//! 连 controller 的那条长连接。
//!
//! 节点用它做这些事：第一次加入时注册（[`enroll`]）；收 netmap 并确认；定期上报；转发信令；
//! 收更新的指令、取更新包（[`Packages`]）；回答"到某个对端现在怎么走"和"手上的骨干矩阵"的查询；
//! 收主动测试的指令、送回测试的结果。
//! 连接断开后带退避重连，重连期间节点按本地最后一份 netmap 继续运行。
//! 被吊销或 controller 明确拒绝本节点（`Rejected`）时不再重连；controller 返回自身临时故障（`TryLater`）时
//! 仍带退避重连，这不代表节点身份被拒绝。
//!
//! 上报里的路由表：每次连上之后的第一次上报是完整的，之后只带变化的条目（延迟的小幅波动不算变化）。
//! 每条路的细节（[`Report::route_kinds`]）跟着它的条目走：条目要报的时候细节也报，细节变了条目也重报。
//! 这件事在这里做，因为只有这里知道一条连接从哪里开始。
//!
//! 无法解析的帧会被跳过，连接仍可使用。常见原因是 controller 发送了当前版本无法识别的消息。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail, ensure};
use i3t_crypto::{NodeKey, tls};
use i3t_model::Netmap;
use i3t_model::control::{
    BackboneRow, DirectStatus, ExitTestResult, Hello, MAX_FRAME_LEN, Report, RouteAnswer, RouteEntry, RouteKind, Signal, TestOrder,
    TestReport, ToController, ToNode,
};
use i3t_model::update::{Platform, SignedManifest, UpdateTiming, Version};
use i3t_proto::NodeId;
use i3t_update::{ChunkRequest, PackageSource, SourceError};
use rustls::pki_types::ServerName;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::state::{ControllerInfo, StateDir};
use crate::texts::{CONNECT_ZH, Connect, texts};

/// 节点协议在 TLS 上的 ALPN。
pub const ALPN: &[u8] = b"i3t-ctl/1";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 信令采用尽力而为投递：队列积压超过此上限说明消费端无法及时处理，新信令直接丢弃，由发起方重试。
const SIGNAL_QUEUE: usize = 64;
/// controller 的更新指令最多排这么多条。它们是一条顶替一条的，正常情况下只有一条在排。
const ORDER_QUEUE: usize = 8;
/// 交给长连接的请求（取包、马上上报）最多排这么多条。
const REQUEST_QUEUE: usize = 16;
/// 等 controller 给一段包最多等多久。到时候按链路中断处理，下载的一方会从同一个位置再要。
const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);
/// 自检时等 controller 关闭探测用的连接最多等多久。
const PROBE_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
/// 路由上的延迟变化不超过这个数（毫秒）、也不超过原来的四分之一时，不算变化，不重新上报。
const RTT_NOISE_MS: u32 = 10;

/// 直连"最近一次尝试是多少秒之前"折算之后差这么多秒以内，算同一次尝试：秒数是取整的，两次上报之间也有几十毫秒的出入。
const ATTEMPT_SLACK_SECS: u64 = 2;

/// 用注册令牌里的一次性密钥加入网络，返回 controller 给这个节点的第一份 netmap。
///
/// # Errors
///
/// 无法连接 controller、controller 公钥不匹配、令牌被拒绝，或应答不符合协议。
pub async fn enroll(controller: &ControllerInfo, key: &NodeKey, secret: &str, hello: Hello) -> anyhow::Result<Netmap> {
    let said = texts();
    let mut stream = connect(controller, key, &said.connect).await?;
    write_message(&mut stream, &ToController::Enroll { token: secret.to_owned(), hello }).await?;
    let first = timeout(CONNECT_TIMEOUT, read_message::<_, ToNode>(&mut stream)).await.context(said.enroll_timeout)??;
    match first {
        Some(ToNode::Snapshot(netmap)) => {
            write_message(&mut stream, &ToController::Ack { version: netmap.version }).await?;
            Ok(*netmap)
        }
        Some(ToNode::Rejected { reason, cause }) => {
            // controller 的原话是中文的；带了原因的代码时按这个程序的语言说。
            let reason = cause.map_or(reason, |cause| (i3t_lang::current().codes().reject_cause)(cause).to_owned());
            bail!((said.enroll_rejected)(&reason))
        }
        Some(ToNode::TryLater { reason }) => bail!((said.enroll_try_later)(&reason)),
        Some(other) => {
            // 消息的种类按它在 JSON 里的 `type` 说：名字只写在 `ToNode` 的 serde 属性里。
            let kind = serde_json::to_value(&other).ok().and_then(|value| value.get("type")?.as_str().map(str::to_owned));
            bail!((said.enroll_unexpected)(&kind.unwrap_or_default()))
        }
        None => bail!(said.enroll_closed),
    }
}

/// 与 controller 完成一次握手后即断开，不上报身份：新版本自检用于确认当前程序能够连接 controller。
///
/// 握手采用双向认证的 TLS：本节点按公钥校验 controller，controller 验证本节点证书。随后不发送 `Hello`，直接正常关闭，
/// 并等待 controller 关闭连接。不上报身份是因为此时旧进程仍在线：上报身份会导致 controller 判定节点重连并断开旧连接。
///
/// # Errors
///
/// 无法连接 controller、controller 公钥不匹配，或 controller 拒绝了本次握手。
pub async fn probe(controller: &ControllerInfo, key: &NodeKey) -> anyhow::Result<()> {
    let said = texts();
    let mut stream = connect(controller, key, &said.connect).await?;
    stream.shutdown().await.context(said.probe_close)?;
    // TLS 1.3 里客户端先完成握手：controller 要是不收本节点的证书，要到这里读的时候才看得到它的拒绝。
    let mut rest = [0; 64];
    match timeout(PROBE_CLOSE_TIMEOUT, stream.read(&mut rest)).await {
        // controller 关了连接（没有发关闭通知就断开也算）：握手是成了的。
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
        Ok(Err(err)) => Err(err).context(said.probe_refused),
        // 握手已经完成，只是 controller 迟迟不关连接。它没有拒绝，算通过。
        Err(_) => Ok(()),
    }
}

/// controller 对更新的指示。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCommand {
    /// 更新到这份清单说的版本。
    Update { manifest: SignedManifest, timing: UpdateTiming },
    /// 上一次要求的更新不要做了。
    Cancel,
}

/// 经长连接从 controller 拉取更新包。可克隆后在多个任务中使用。
///
/// 链路异常（未连接、连接断开、等待 controller 应答超时）均报告为“已中断”，下载方稍后从同一偏移继续请求；
/// 仅当 controller 明确返回不可用时才报告为不可用。
#[derive(Debug, Clone)]
pub struct Packages {
    requests: mpsc::Sender<Request>,
}

impl PackageSource for Packages {
    async fn fetch(&self, request: ChunkRequest<'_>) -> Result<Vec<u8>, SourceError> {
        let (reply, answer) = oneshot::channel();
        let chunk =
            Chunk { version: request.version.clone(), platform: request.platform.clone(), offset: request.offset, len: request.len };
        let interrupted = |reason: &str| SourceError::Interrupted(reason.to_owned());
        self.requests.send(Request::Chunk { chunk, reply }).await.map_err(|_| interrupted("与 controller 的长连接已停止"))?;
        match timeout(CHUNK_TIMEOUT, answer).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(interrupted("与 controller 的连接已断开")),
            Err(_) => Err(interrupted("等待 controller 返回更新包分段超时")),
        }
    }
}

/// 要 controller 给的一段包。
#[derive(Debug)]
struct Chunk {
    version: Version,
    platform: Platform,
    offset: u64,
    len: u32,
}

/// 别的任务交给长连接去做的事。
#[derive(Debug)]
enum Request {
    Chunk {
        chunk: Chunk,
        reply: oneshot::Sender<Result<Vec<u8>, SourceError>>,
    },
    /// 马上上报一次，写出去之后告诉我。
    Report {
        written: oneshot::Sender<()>,
    },
}

impl Request {
    /// 当前未连接 controller，无法立即处理请求：拉取分段的调用方稍后从同一位置重试，等待上报写出的调用方不再等待。
    fn turn_away(self) {
        match self {
            Self::Chunk { reply, .. } => {
                // 调用方已放弃等待时忽略发送失败。
                let _gone = reply.send(Err(SourceError::Interrupted("尚未连接 controller".to_owned())));
            }
            // 丢弃 `written`，通知等待方本次上报未写出。
            Self::Report { .. } => {}
        }
    }
}

/// 这条长连接现在的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// 尚未连接，或断开后正在重连。
    Offline,
    Online,
    /// controller 吊销了这个节点。不再重连。
    Revoked,
    /// controller 拒绝了本节点（例如节点被删除时本节点处于离线状态）。停止重连，需重新加入网络。
    Rejected,
}

/// controller 关于主动测试说的话。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestMessage {
    Order(TestOrder),
    /// 这个测试结束了。
    End(u64),
}

/// 长连接上的几个时间。默认值是协议约定的，测试里会改短。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// 多久上报一次。上报同时是节点一侧的心跳。
    pub report_interval: Duration,
    /// 这么久收不到 controller 的任何消息就认为连接已经死了。controller 空闲时每 20 秒发一次心跳。
    pub idle_timeout: Duration,
    /// 重连的退避从这个值起，每次翻倍，到 `backoff_max` 为止；连上之后重新从头算。
    pub backoff_min: Duration,
    pub backoff_max: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            report_interval: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(90),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
        }
    }
}

/// 启动长连接所需要的东西。
pub struct LinkSetup {
    pub controller: ControllerInfo,
    pub key: Arc<NodeKey>,
    /// 启动时持有的初始 netmap（来自注册或本地持久化副本）。
    pub initial: Arc<Netmap>,
    /// 当前的自我介绍。本地声明变了就往里放一个新值，长连接会把它发给 controller。
    pub hello: watch::Receiver<Hello>,
    /// 每次上报时调用，取当前要报的内容。`routes` 里放完整的路由表：哪些条目要发由长连接自己算。
    pub report: Box<dyn Fn() -> Report + Send + Sync>,
    /// controller 问"到这个对端现在怎么走"时调用。
    pub route: Box<dyn Fn(NodeId) -> RouteAnswer + Send + Sync>,
    /// controller 问"手上的骨干矩阵"时调用。
    pub backbone: Box<dyn Fn() -> Vec<BackboneRow> + Send + Sync>,
    /// 通知它一下，就不等下一次定时上报，马上报一次。
    /// 候选端点或者挂靠的 relay 变了的时候用：对端要靠这些才找得到本节点，晚报十秒就晚通十秒。
    pub report_now: Arc<Notify>,
    /// controller 的主动测试指令交给它。在长连接的任务里调用，不能阻塞。
    pub tests: Box<dyn Fn(TestMessage) + Send + Sync>,
    /// 主动测试结果从此通道取出并发送给 controller。离线期间暂存在队列中，重连后继续发送（controller 不识别的条目会被丢弃）。
    pub test_reports: mpsc::Receiver<TestReport>,
    /// controller 的出口测试交给它：编号、主机、端口。在长连接的任务里调用，不能阻塞。
    pub exit_tests: Box<dyn Fn(u64, String, u16) + Send + Sync>,
    /// 出口测试做完的结果从这里取出来送给 controller。
    pub exit_test_answers: mpsc::Receiver<(u64, ExitTestResult)>,
    /// 收到的 netmap 存到这里，下次启动时用。
    pub state: StateDir,
    pub timing: Timing,
}

/// 一条正在后台运行的长连接。丢弃它就停止。
pub struct ControlLink {
    netmap: watch::Receiver<Arc<Netmap>>,
    state: watch::Receiver<LinkState>,
    signals: mpsc::Receiver<(NodeId, Signal)>,
    outgoing: mpsc::Sender<(NodeId, Signal)>,
    orders: Option<mpsc::Receiver<UpdateCommand>>,
    requests: mpsc::Sender<Request>,
    task: JoinHandle<()>,
}

impl ControlLink {
    #[must_use]
    pub fn spawn(setup: LinkSetup) -> Self {
        let (netmap_tx, netmap) = watch::channel(Arc::clone(&setup.initial));
        let (state_tx, state) = watch::channel(LinkState::Offline);
        let (signals_tx, signals) = mpsc::channel(SIGNAL_QUEUE);
        let (outgoing, outgoing_rx) = mpsc::channel(SIGNAL_QUEUE);
        let (orders_tx, orders) = mpsc::channel(ORDER_QUEUE);
        let (requests, requests_rx) = mpsc::channel(REQUEST_QUEUE);
        let worker = Worker {
            setup,
            netmap: netmap_tx,
            state: state_tx,
            signals: signals_tx,
            outgoing: outgoing_rx,
            orders: orders_tx,
            requests: requests_rx,
        };
        Self { netmap, state, signals, outgoing, orders: Some(orders), requests, task: tokio::spawn(worker.run()) }
    }

    /// controller 对更新的指示从这里出来。只能取走一次，交给管更新的那个任务；没有人取的话指示被丢掉。
    pub fn take_update_commands(&mut self) -> Option<mpsc::Receiver<UpdateCommand>> {
        self.orders.take()
    }

    /// 经这条长连接取更新包的句柄。
    #[must_use]
    pub fn packages(&self) -> Packages {
        Packages { requests: self.requests.clone() }
    }

    /// 马上上报一次，等它写出去；没有连着的话不等，返回 `false`。
    ///
    /// 进程要退出（更新之后重启）之前用它把最后的状态送到 controller：之后就没有机会了。
    pub async fn report_and_wait(&self, limit: Duration) -> bool {
        let (written, done) = oneshot::channel();
        if self.requests.send(Request::Report { written }).await.is_err() {
            return false;
        }
        matches!(timeout(limit, done).await, Ok(Ok(())))
    }

    /// 当前的 netmap，controller 每下发一份就更新一次。
    #[must_use]
    pub fn netmap(&self) -> watch::Receiver<Arc<Netmap>> {
        self.netmap.clone()
    }

    #[must_use]
    pub fn state(&self) -> watch::Receiver<LinkState> {
        self.state.clone()
    }

    /// 往这里放要经 controller 转给别的节点的信令。
    #[must_use]
    pub fn signal_sender(&self) -> mpsc::Sender<(NodeId, Signal)> {
        self.outgoing.clone()
    }

    /// 等下一条别的节点经 controller 转来的信令。长连接停止之后返回 `None`。
    pub async fn next_signal(&mut self) -> Option<(NodeId, Signal)> {
        self.signals.recv().await
    }
}

impl Drop for ControlLink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// 一次会话是怎么结束的。出错的情况走 `Err`，会重连。
enum Ended {
    Revoked,
    Rejected(String),
}

struct Worker {
    setup: LinkSetup,
    netmap: watch::Sender<Arc<Netmap>>,
    state: watch::Sender<LinkState>,
    signals: mpsc::Sender<(NodeId, Signal)>,
    outgoing: mpsc::Receiver<(NodeId, Signal)>,
    orders: mpsc::Sender<UpdateCommand>,
    requests: mpsc::Receiver<Request>,
}

/// 上报过的一条路：条目、它的细节，和什么时候报的（细节里有"多少秒之前"，要按报的时刻比）。
#[derive(Debug, Clone)]
struct ReportedRoute {
    entry: RouteEntry,
    kind: Option<RouteKind>,
    at: Instant,
}

/// 一条连接期间的状态。连接断了就整个丢掉，等回答的人因此知道被打断了。
#[derive(Default)]
struct Session {
    /// 这条连接上报过的路由表和每条路的细节：下一次只报和它不同的条目。
    reported_routes: BTreeMap<NodeId, ReportedRoute>,
    /// 发出去、还在等回答的取包请求。
    chunks: BTreeMap<u64, oneshot::Sender<Result<Vec<u8>, SourceError>>>,
    next_request: u64,
    /// 是不是已经做过这条连接上的第一次上报。
    reported: bool,
}

impl Worker {
    async fn run(mut self) {
        let timing = self.setup.timing;
        let mut backoff = timing.backoff_min;
        loop {
            let mut was_online = false;
            match self.session(&mut was_online).await {
                Ok(Ended::Revoked) => {
                    tracing::warn!("controller 吊销了这个节点，不再连接");
                    self.state.send_replace(LinkState::Revoked);
                    return;
                }
                Ok(Ended::Rejected(reason)) => {
                    tracing::warn!(%reason, "本节点接入请求被 controller 拒绝，已停止重连。请重新加入网络。");
                    self.state.send_replace(LinkState::Rejected);
                    return;
                }
                Err(err) => tracing::warn!("和 controller 的连接断开：{err:#}"),
            }
            self.state.send_replace(LinkState::Offline);
            if was_online {
                backoff = timing.backoff_min;
            }
            self.idle(jittered(backoff)).await;
            backoff = (backoff * 2).min(timing.backoff_max);
        }
    }

    /// 未连接期间等待 `pause`。期间收到的请求不排队等待下次连接，立即通知调用方当前不可处理。
    async fn idle(&mut self, pause: Duration) {
        let resume = tokio::time::sleep(pause);
        tokio::pin!(resume);
        loop {
            tokio::select! {
                () = &mut resume => return,
                Some(request) = self.requests.recv() => request.turn_away(),
            }
        }
    }

    /// 连接 controller。连接建立前收到的请求同样立即通知调用方当前不可处理，避免阻塞至连接超时。
    async fn connect(&mut self) -> anyhow::Result<TlsStream<TcpStream>> {
        // 长连接出的错只进日志，日志是中文的。
        let connecting = connect(&self.setup.controller, &self.setup.key, &CONNECT_ZH);
        tokio::pin!(connecting);
        loop {
            tokio::select! {
                stream = &mut connecting => return stream,
                Some(request) = self.requests.recv() => request.turn_away(),
            }
        }
    }

    async fn session(&mut self, was_online: &mut bool) -> anyhow::Result<Ended> {
        let stream = self.connect().await?;
        let (reader, mut writer) = tokio::io::split(stream);
        let hello = self.setup.hello.borrow_and_update().clone();
        write_message(&mut writer, &ToController::Hello(hello)).await?;
        let mut session = Session::default();
        // 报到之后马上上报一次：完整的路由表，和更新的状态。controller 等这一次到了才会给节点下发更新指令。
        self.report(&mut writer, &mut session).await?;

        // 读一帧不能被打断（长度和内容分两次读），所以交给单独的任务，这里只从队列里取完整的消息。
        let mut inbound = spawn_reader(reader);
        let Timing { report_interval, idle_timeout, .. } = self.setup.timing;
        let mut report_at = tokio::time::interval_at(Instant::now() + report_interval, report_interval);
        let mut last_heard = Instant::now();
        loop {
            tokio::select! {
                message = inbound.messages.recv() => {
                    let message = message.ok_or_else(|| anyhow!("读取任务意外结束"))??;
                    last_heard = Instant::now();
                    match message {
                        ToNode::Snapshot(netmap) => {
                            let version = netmap.version;
                            self.apply(*netmap);
                            write_message(&mut writer, &ToController::Ack { version }).await?;
                            *was_online = true;
                            self.state.send_if_modified(|state| std::mem::replace(state, LinkState::Online) != LinkState::Online);
                        }
                        ToNode::Signal { from, signal } => {
                            if self.signals.try_send((from, signal)).is_err() {
                                tracing::debug!(%from, "信令队列满了，丢掉一条");
                            }
                        }
                        ToNode::Revoked => return Ok(Ended::Revoked),
                        ToNode::Rejected { reason, .. } => return Ok(Ended::Rejected(reason)),
                        // controller 返回自身临时故障，并非拒绝本节点：按连接断开处理，带退避重连。
                        ToNode::TryLater { reason } => bail!("controller 暂时无法处理本节点接入请求，稍后重连：{reason}"),
                        ToNode::Heartbeat => {}
                        ToNode::Update { manifest, timing } => self.pass_on(UpdateCommand::Update { manifest, timing }),
                        ToNode::UpdateCancel => self.pass_on(UpdateCommand::Cancel),
                        ToNode::PackageChunk { request, data } => session.answer(request, Ok(data)),
                        ToNode::PackageUnavailable { request, reason } => session.answer(request, Err(SourceError::Unavailable(reason))),
                        ToNode::RouteQuery { request, peer } => {
                            let answer = (self.setup.route)(peer);
                            tracing::debug!(%peer, route = ?answer.route, "回答 controller 的路由查询");
                            write_message(&mut writer, &ToController::RouteAnswer { request, answer }).await?;
                        }
                        ToNode::BackboneQuery { request } => {
                            let rows = (self.setup.backbone)();
                            tracing::debug!(rows = rows.len(), "回答 controller 的骨干矩阵查询");
                            write_message(&mut writer, &ToController::BackboneAnswer { request, rows }).await?;
                        }
                        ToNode::Test(order) => (self.setup.tests)(TestMessage::Order(*order)),
                        ToNode::TestEnd { test } => (self.setup.tests)(TestMessage::End(test)),
                        ToNode::ExitTest { request, host, port } => (self.setup.exit_tests)(request, host, port),
                    }
                }
                Some(report) = self.setup.test_reports.recv() => {
                    write_message(&mut writer, &ToController::TestReport(Box::new(report))).await?;
                }
                Some((request, result)) = self.setup.exit_test_answers.recv() => {
                    write_message(&mut writer, &ToController::ExitTestAnswer { request, result: Box::new(result) }).await?;
                }
                Some((to, signal)) = self.outgoing.recv() => {
                    write_message(&mut writer, &ToController::Signal { to, signal }).await?;
                }
                Some(request) = self.requests.recv() => match request {
                    Request::Chunk { chunk, reply } => {
                        let request = session.expect(reply);
                        let Chunk { version, platform, offset, len } = chunk;
                        write_message(&mut writer, &ToController::PackageRequest { request, version, platform, offset, len }).await?;
                    }
                    Request::Report { written } => {
                        self.report(&mut writer, &mut session).await?;
                        report_at.reset();
                        // 等的人不等了也无妨。
                        let _gone = written.send(());
                    }
                },
                _ = report_at.tick() => self.report(&mut writer, &mut session).await?,
                () = self.setup.report_now.notified() => {
                    self.report(&mut writer, &mut session).await?;
                    report_at.reset();
                }
                Ok(()) = self.setup.hello.changed() => {
                    let hello = self.setup.hello.borrow_and_update().clone();
                    write_message(&mut writer, &ToController::Hello(hello)).await?;
                }
                () = tokio::time::sleep_until(last_heard + idle_timeout) => {
                    bail!("{} 秒没有收到 controller 的任何消息", idle_timeout.as_secs());
                }
            }
        }
    }

    /// 上报一次。这条连接上的第一次带完整的路由表，之后只带变化的条目。
    async fn report<W: AsyncWrite + Unpin>(&self, writer: &mut W, session: &mut Session) -> anyhow::Result<()> {
        let mut report = (self.setup.report)();
        report.routes_full = !session.reported;
        (report.routes, report.route_kinds) = session.routes_to_report(report.routes, report.route_kinds);
        session.reported = true;
        write_message(writer, &ToController::Report(Box::new(report))).await
    }

    fn pass_on(&self, command: UpdateCommand) {
        if self.orders.try_send(command).is_err() {
            tracing::warn!("更新指令未处理或队列已满，已丢弃一条更新指令");
        }
    }

    fn apply(&self, netmap: Netmap) {
        if let Err(err) = self.setup.state.save_netmap(&netmap) {
            // 持久化失败不影响本次运行，仅导致下次启动时无法加载该版本。
            tracing::warn!("保存 netmap 失败：{err:#}");
        }
        tracing::info!(version = netmap.version, peers = netmap.peers.len(), relays = netmap.relays.len(), "应用新的 netmap");
        self.netmap.send_replace(Arc::new(netmap));
    }
}

impl Session {
    /// 登记一个等待应答的更新包分段请求，返回其请求编号。
    fn expect(&mut self, reply: oneshot::Sender<Result<Vec<u8>, SourceError>>) -> u64 {
        // 清理调用方已放弃等待的请求。
        self.chunks.retain(|_, reply| !reply.is_closed());
        self.next_request += 1;
        self.chunks.insert(self.next_request, reply);
        self.next_request
    }

    fn answer(&mut self, request: u64, outcome: Result<Vec<u8>, SourceError>) {
        match self.chunks.remove(&request) {
            // 调用方已放弃等待时忽略发送失败。
            Some(reply) => drop(reply.send(outcome)),
            None => tracing::debug!(request, "收到无对应等待方的更新包分段应答，已忽略"),
        }
    }

    /// 从完整的路由表和细节里挑出这次要报的条目和它们的细节，并记下报过什么。
    ///
    /// 细节说的对端不在路由表里的不报：controller 只认和条目一起来的细节。
    fn routes_to_report(&mut self, current: Vec<RouteEntry>, kinds: Vec<RouteKind>) -> (Vec<RouteEntry>, Vec<RouteKind>) {
        let mut kinds: BTreeMap<NodeId, RouteKind> = kinds.into_iter().map(|kind| (kind.peer, kind)).collect();
        let current: Vec<(RouteEntry, Option<RouteKind>)> = current
            .into_iter()
            .map(|entry| {
                let kind = kinds.remove(&entry.peer);
                (entry, kind)
            })
            .collect();
        let now = Instant::now();
        let first = !self.reported;
        if first {
            self.reported_routes.clear();
        }
        // 不在表里了的对端不用报：它已经不在 netmap 里，controller 那边自己会去掉。
        self.reported_routes.retain(|peer, _| current.iter().any(|(entry, _)| entry.peer == *peer));
        let changed: Vec<(RouteEntry, Option<RouteKind>)> = current
            .into_iter()
            .filter(|(entry, kind)| {
                first
                    || self
                        .reported_routes
                        .get(&entry.peer)
                        .is_none_or(|before| differs(&before.entry, entry) || kind_differs(before, kind.as_ref(), now))
            })
            .collect();
        self.reported_routes
            .extend(changed.iter().map(|(entry, kind)| (entry.peer, ReportedRoute { entry: entry.clone(), kind: kind.clone(), at: now })));
        let (entries, kinds): (Vec<RouteEntry>, Vec<Option<RouteKind>>) = changed.into_iter().unzip();
        (entries, kinds.into_iter().flatten().collect())
    }
}

/// 一条路由和上次报的比，有没有值得再报一次的变化：路换了，或者延迟变了不少。
fn differs(before: &RouteEntry, now: &RouteEntry) -> bool {
    before.route != now.route || rtt_differs(before.rtt_ms, now.rtt_ms)
}

/// 延迟变了不少：超过 [`RTT_NOISE_MS`]，也超过原来的四分之一。
fn rtt_differs(before: Option<u32>, now: Option<u32>) -> bool {
    match (before, now) {
        (Some(before), Some(now)) => before.abs_diff(now) > RTT_NOISE_MS.max(before / 4),
        (None, None) => false,
        (Some(_), None) | (None, Some(_)) => true,
    }
}

/// 一条路的细节和上次报的比，有没有值得再报一次的变化。直连"最近一次尝试是多少秒之前"随时间自己往上涨，
/// 按报的时刻折算之后差不过 [`ATTEMPT_SLACK_SECS`] 秒的，说的还是同一次尝试，不算变化。
fn kind_differs(before: &ReportedRoute, now_kind: Option<&RouteKind>, now: Instant) -> bool {
    let (Some(before_kind), Some(now_kind)) = (before.kind.as_ref(), now_kind) else {
        return before.kind.is_some() || now_kind.is_some();
    };
    let elapsed = now.saturating_duration_since(before.at).as_secs();
    let attempted = |kind: &RouteKind| kind.direct_status.and_then(|status| status.attempted_secs_ago);
    let same_attempt = match (attempted(before_kind), attempted(now_kind)) {
        (Some(then), Some(ago)) => then.saturating_add(elapsed).abs_diff(ago) <= ATTEMPT_SLACK_SECS,
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    };
    // 另一种模式会选的路：路变了才算，延迟按和路由条目一样的门槛比。
    let alternative_differs = match (&before_kind.alternative, &now_kind.alternative) {
        (Some(before), Some(now)) => before.route != now.route || rtt_differs(before.rtt_ms, now.rtt_ms),
        (None, None) => false,
        (Some(_), None) | (None, Some(_)) => true,
    };
    let rest = |kind: &RouteKind| RouteKind {
        direct_status: kind.direct_status.map(|status| DirectStatus { attempted_secs_ago: None, ..status }),
        alternative: None,
        ..kind.clone()
    };
    !same_attempt || alternative_differs || rest(before_kind) != rest(now_kind)
}

/// 一条连接上的读取任务，以及它读出来的消息。
///
/// 丢弃时任务必须立刻中止：任务常态阻塞在等待对端数据上并持有连接读半部，
/// 若不及时中止，会话结束后连接无法关闭，controller 侧将无法感知节点已断开。
struct Reader {
    messages: mpsc::Receiver<anyhow::Result<ToNode>>,
    task: JoinHandle<()>,
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// 将完整消息逐条送入队列。连接结束或出错时发送错误并退出。
///
/// 完整帧但内容无法解析时不视为连接错误：常见原因是 controller 发送了新版本消息，跳过该帧继续读取。
fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(mut reader: R) -> Reader {
    let (tx, messages) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        loop {
            let message = match read_frame(&mut reader).await {
                Ok(Some(frame)) => match serde_json::from_slice(&frame) {
                    Ok(message) => Ok(message),
                    Err(err) => {
                        tracing::debug!("无法解析 controller 消息，已忽略：{err}");
                        continue;
                    }
                },
                Ok(None) => Err(anyhow!("controller 关闭了连接")),
                Err(err) => Err(err),
            };
            let failed = message.is_err();
            if tx.send(message).await.is_err() || failed {
                return;
            }
        }
    });
    Reader { messages, task }
}

/// 连上 controller 并完成 TLS 握手。`said` 是出错时的说明：交互的命令用当前语言的，长连接用中文的（它只进日志）。
async fn connect(controller: &ControllerInfo, key: &NodeKey, said: &Connect) -> anyhow::Result<TlsStream<TcpStream>> {
    let config = tls::client_config(key, controller.key, ALPN).context(said.tls_config)?;
    // 校验器只比对公钥，不看名字；这里的名字只是 TLS 接口要求有一个。
    let name = ServerName::try_from("i3t").context(said.server_name)?;
    let handshake = async {
        let tcp = i3t_underlay::tcp_mss::connect_host(&controller.address).await.with_context(|| (said.tcp)(&controller.address))?;
        tcp.set_nodelay(true).context(said.nodelay)?;
        TlsConnector::from(Arc::new(config)).connect(name, tcp).await.context(said.handshake)
    };
    timeout(CONNECT_TIMEOUT, handshake).await.with_context(|| (said.timeout)(&controller.address))?
}

/// 发一条消息：4 字节大端长度，后面是 JSON。
///
/// # Errors
///
/// 消息超过长度上限，或者写失败。
pub async fn write_message<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, message: &T) -> anyhow::Result<()> {
    let body = serde_json::to_vec(message).context("序列化消息")?;
    ensure!(body.len() <= MAX_FRAME_LEN, "消息有 {} 字节，超过上限 {MAX_FRAME_LEN}", body.len());
    let len = u32::try_from(body.len()).context("消息长度超出 4 字节表示范围")?;
    let mut frame = Vec::with_capacity(size_of::<u32>() + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    writer.write_all(&frame).await.context("写消息")?;
    writer.flush().await.context("写消息")
}

/// 读一条消息。对端在两条消息之间正常关闭连接时返回 `None`。
///
/// # Errors
///
/// 读失败、长度超过上限，或者内容不是期望的 JSON。
pub async fn read_message<R: AsyncRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> anyhow::Result<Option<T>> {
    match read_frame(reader).await? {
        Some(frame) => serde_json::from_slice(&frame).map(Some).context("解析消息"),
        None => Ok(None),
    }
}

/// 读一帧的内容，不解析。对端在两帧之间正常关闭连接时返回 `None`。
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>> {
    let len = match reader.read_u32().await {
        Ok(len) => usize::try_from(len).context("消息长度超出当前平台地址空间范围")?,
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("读消息长度"),
    };
    ensure!(len <= MAX_FRAME_LEN, "对端声称的消息长度 {len} 超过上限 {MAX_FRAME_LEN}");
    let mut body = vec![0; len];
    reader.read_exact(&mut body).await.context("读消息内容")?;
    Ok(Some(body))
}

/// 退避时间上下浮动一半，免得一批节点在 controller 重启之后同时连回来。
fn jittered(base: Duration) -> Duration {
    base.mul_f64(0.5 + rand::random::<f64>())
}

/// 测试用的假 controller，本 crate 里别的模块的测试也用它。
#[cfg(test)]
pub(crate) mod testing {
    use i3t_proto::PublicKey;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    pub(crate) use tokio_rustls::server::TlsStream as ServerStream;

    use super::*;

    pub(crate) fn netmap(version: u64) -> Netmap {
        serde_json::from_value(serde_json::json!({
            "version": version,
            "network": { "name": "home", "domain": "home.i3t", "cidr": "10.66.0.0/16" },
            "me": { "id": 1, "name": "laptop", "virtual_ip": "10.66.0.1" }
        }))
        .unwrap()
    }

    /// 一个只会接受连接的假 controller。测试里拿到每条连接之后自己决定说什么。
    pub(crate) struct FakeController {
        pub(crate) listener: TcpListener,
        pub(crate) acceptor: TlsAcceptor,
        pub(crate) info: ControllerInfo,
    }

    impl FakeController {
        pub(crate) async fn start() -> Self {
            let key = NodeKey::generate().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let info = ControllerInfo { address: listener.local_addr().unwrap().to_string(), key: key.public() };
            let config = tls::server_config(&key, |_| true, ALPN).unwrap();
            Self { listener, acceptor: TlsAcceptor::from(Arc::new(config)), info }
        }

        /// 接受下一条连接，返回它和节点在握手里出示的公钥。
        pub(crate) async fn accept(&self) -> (ServerStream<TcpStream>, PublicKey) {
            let (tcp, _) = self.listener.accept().await.unwrap();
            let stream = self.acceptor.accept(tcp).await.unwrap();
            let certs = stream.get_ref().1.peer_certificates().unwrap();
            let key = tls::peer_key(&certs[0]).unwrap();
            (stream, key)
        }
    }

    pub(crate) async fn expect<T: DeserializeOwned>(stream: &mut ServerStream<TcpStream>) -> T {
        timeout(Duration::from_secs(5), read_message(stream)).await.expect("等节点的消息超时").unwrap().expect("节点关闭了连接")
    }

    /// 等下一条不是上报的消息。节点随时可能上报（报到之后马上一次，之后定时），不关心上报的测试用它跳过去。
    pub(crate) async fn expect_other(stream: &mut ServerStream<TcpStream>) -> ToController {
        loop {
            match expect(stream).await {
                ToController::Report(_) => {}
                other => return other,
            }
        }
    }

    /// 等下一次上报，跳过别的消息。
    pub(crate) async fn expect_report(stream: &mut ServerStream<TcpStream>) -> Report {
        loop {
            if let ToController::Report(report) = expect(stream).await {
                return *report;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use i3t_model::control::Route;
    use i3t_model::update::{ManifestSignature, UpdateStatus};

    use super::testing::{FakeController, expect, expect_other, expect_report, netmap};
    use super::*;

    const FAST: Timing = Timing {
        report_interval: Duration::from_millis(50),
        idle_timeout: Duration::from_millis(400),
        backoff_min: Duration::from_millis(10),
        backoff_max: Duration::from_millis(40),
    };

    /// 定时上报要很久以后才到：收到的上报只能是报到时的那一次，或者测试自己要的。
    const QUIET: Timing = Timing { report_interval: Duration::from_secs(3600), idle_timeout: Duration::from_secs(3600), ..FAST };

    #[test]
    fn a_route_detail_is_reported_again_only_when_it_says_something_new() {
        use i3t_model::control::{DirectCause, DirectState, RouteAlternative};

        let peer = NodeId::new(2).unwrap();
        let entry = RouteEntry { peer, route: Route::Relay { relays: vec![NodeId::new(9).unwrap()] }, rtt_ms: Some(40) };
        let status = |ago| DirectStatus {
            state: DirectState::Failed,
            kind: None,
            cause: Some(DirectCause::NoAnswer),
            attempted_secs_ago: Some(ago),
        };
        let kind = |ago, rtt| RouteKind {
            peer,
            direct: None,
            relay_leg: None,
            direct_status: Some(status(ago)),
            alternative: Some(RouteAlternative { route: Route::None, rtt_ms: rtt }),
        };
        let reported_at = Instant::now();
        let before = ReportedRoute { entry, kind: Some(kind(10, Some(30))), at: reported_at };
        let later = reported_at + Duration::from_secs(20);
        assert!(!kind_differs(&before, Some(&kind(30, Some(30))), later), "同一次尝试，只是过了 20 秒");
        assert!(kind_differs(&before, Some(&kind(1, Some(30))), later), "又试了一次");
        assert!(!kind_differs(&before, Some(&kind(30, Some(33))), later), "另一种模式的延迟小幅波动不算");
        assert!(kind_differs(&before, Some(&kind(30, Some(80))), later), "延迟变了不少");
        let verified = RouteKind {
            direct_status: Some(DirectStatus { state: DirectState::Verified, cause: None, ..status(30) }),
            ..kind(30, Some(30))
        };
        assert!(kind_differs(&before, Some(&verified), later), "直连通了");
        assert!(kind_differs(&before, None, later), "细节没了");
    }

    fn setup(controller: &FakeController, state: StateDir, timing: Timing) -> (LinkSetup, watch::Sender<Hello>) {
        let hello = Hello { version: "0.1.0".into(), platform: "test".into(), ..Hello::default() };
        let (hello_tx, hello_rx) = watch::channel(hello);
        let setup = LinkSetup {
            controller: controller.info.clone(),
            key: Arc::new(NodeKey::generate().unwrap()),
            initial: Arc::new(netmap(1)),
            hello: hello_rx,
            report: Box::new(|| Report { flows: 3, ..Report::default() }),
            route: Box::new(|peer| RouteAnswer { peer, route: None, rtt_ms: None, since: None, detail: None, connection_rtt_ms: None }),
            backbone: Box::new(Vec::new),
            report_now: Arc::new(Notify::new()),
            tests: Box::new(|_| {}),
            test_reports: mpsc::channel(1).1,
            exit_tests: Box::new(|_, _, _| {}),
            exit_test_answers: mpsc::channel(1).1,
            state,
            timing,
        };
        (setup, hello_tx)
    }

    fn link(controller: &FakeController, state: StateDir) -> (ControlLink, watch::Sender<Hello>) {
        let (setup, hello) = setup(controller, state, FAST);
        (ControlLink::spawn(setup), hello)
    }

    fn temp_state() -> (tempfile::TempDir, StateDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path()).unwrap();
        (dir, state)
    }

    fn peer(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    #[tokio::test]
    async fn enroll_sends_the_secret_and_returns_the_first_netmap() {
        let controller = FakeController::start().await;
        let key = NodeKey::generate().unwrap();
        let public = key.public();
        let info = controller.info.clone();
        let server = tokio::spawn(async move {
            let (mut stream, seen_key) = controller.accept().await;
            assert_eq!(seen_key, public, "controller 从握手里认出节点的公钥");
            let ToController::Enroll { token, hello } = expect(&mut stream).await else { panic!("第一条消息不是 enroll") };
            assert_eq!((token.as_str(), hello.platform.as_str()), ("s3cret", "test"));
            write_message(&mut stream, &ToNode::Snapshot(Box::new(netmap(7)))).await.unwrap();
            assert_eq!(expect::<ToController>(&mut stream).await, ToController::Ack { version: 7 });
        });
        let hello = Hello { platform: "test".into(), ..Hello::default() };
        let received = enroll(&info, &key, "s3cret", hello).await.unwrap();
        assert_eq!(received.version, 7);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn enroll_reports_the_reason_when_rejected() {
        let controller = FakeController::start().await;
        let info = controller.info.clone();
        tokio::spawn(async move {
            let (mut stream, _) = controller.accept().await;
            let _: ToController = expect(&mut stream).await;
            write_message(&mut stream, &ToNode::Rejected { reason: "令牌已经用过".into(), cause: None }).await.unwrap();
        });
        let err = enroll(&info, &NodeKey::generate().unwrap(), "x", Hello::default()).await.unwrap_err();
        assert!(format!("{err:#}").contains("令牌已经用过"), "{err:#}");
    }

    #[tokio::test]
    async fn a_controller_with_another_key_is_not_trusted() {
        let controller = FakeController::start().await;
        let mut info = controller.info.clone();
        info.key = NodeKey::generate().unwrap().public();
        tokio::spawn(async move {
            let (tcp, _) = controller.listener.accept().await.unwrap();
            let _ = controller.acceptor.accept(tcp).await;
        });
        let err = enroll(&info, &NodeKey::generate().unwrap(), "x", Hello::default()).await.unwrap_err();
        assert!(format!("{err:#}").contains("TLS"), "{err:#}");
    }

    #[tokio::test]
    async fn snapshots_are_applied_saved_and_acknowledged() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (link, _hello) = link(&controller, state.clone());
        let mut netmaps = link.netmap();
        assert_eq!(netmaps.borrow().version, 1);

        let (mut stream, _) = controller.accept().await;
        assert!(matches!(expect::<ToController>(&mut stream).await, ToController::Hello(_)));
        write_message(&mut stream, &ToNode::Snapshot(Box::new(netmap(2)))).await.unwrap();
        assert_eq!(expect_other(&mut stream).await, ToController::Ack { version: 2 });

        netmaps.changed().await.unwrap();
        assert_eq!(netmaps.borrow().version, 2);
        assert_eq!(state.netmap().unwrap().unwrap().version, 2);
        assert_eq!(*link.state().borrow(), LinkState::Online);
    }

    #[tokio::test]
    async fn signals_travel_both_ways_and_a_changed_hello_is_resent() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (mut link, hello) = link(&controller, state);
        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;

        let request = Signal::PunchRequest { endpoints: vec!["203.0.113.5:20330".parse().unwrap()] };
        write_message(&mut stream, &ToNode::Signal { from: peer(2), signal: request.clone() }).await.unwrap();
        assert_eq!(link.next_signal().await, Some((peer(2), request)));

        let reply = Signal::PunchReply { endpoints: Vec::new() };
        link.signal_sender().send((peer(2), reply.clone())).await.unwrap();
        assert_eq!(expect_other(&mut stream).await, ToController::Signal { to: peer(2), signal: reply });

        hello.send_modify(|hello| hello.declared.exit = true);
        let ToController::Hello(resent) = expect_other(&mut stream).await else { panic!("声明变了之后应该重发 hello") };
        assert!(resent.declared.exit);
    }

    #[tokio::test]
    async fn the_node_reports_right_after_hello_and_then_periodically() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (_link, _hello) = link(&controller, state);
        let (mut stream, _) = controller.accept().await;
        assert!(matches!(expect::<ToController>(&mut stream).await, ToController::Hello(_)));
        // 不等 controller 说话：报到之后的下一条就是上报。controller 要靠它才知道节点的更新状态。
        let ToController::Report(first) = expect(&mut stream).await else { panic!("报到之后应该马上上报") };
        assert_eq!((first.flows, first.routes_full), (3, true));
        let later = expect_report(&mut stream).await;
        assert!(!later.routes_full, "之后的定时上报只带变化的路由");
    }

    #[tokio::test]
    async fn a_report_can_be_requested_ahead_of_schedule_and_waited_for() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (setup, _hello) = setup(&controller, state, QUIET);
        let report_now = Arc::clone(&setup.report_now);
        let link = ControlLink::spawn(setup);
        assert!(!link.report_and_wait(Duration::from_secs(5)).await, "还没连上：不排着等，马上说没有写出去");

        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;
        assert!(expect_report(&mut stream).await.routes_full);
        report_now.notify_one();
        assert_eq!(expect_report(&mut stream).await.flows, 3);
        assert!(link.report_and_wait(Duration::from_secs(5)).await);
        assert_eq!(expect_report(&mut stream).await.flows, 3);
    }

    #[tokio::test]
    async fn the_first_report_of_every_connection_has_the_whole_route_table_and_later_ones_only_the_changes() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (mut setup, _hello) = setup(&controller, state, QUIET);
        let entry =
            |raw: u32, rtt_ms: u32| RouteEntry { peer: peer(raw), route: Route::Relay { relays: vec![peer(9)] }, rtt_ms: Some(rtt_ms) };
        let table = Arc::new(std::sync::Mutex::new(vec![entry(2, 100), entry(3, 20)]));
        let current = Arc::clone(&table);
        setup.report = Box::new(move || Report { routes: current.lock().unwrap().clone(), ..Report::default() });
        let report_now = Arc::clone(&setup.report_now);
        let _link = ControlLink::spawn(setup);
        let peers = |report: &Report| report.routes.iter().map(|entry| entry.peer.get()).collect::<Vec<_>>();

        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;
        let first = expect_report(&mut stream).await;
        assert_eq!((first.routes_full, peers(&first)), (true, vec![2, 3]));

        // 什么都没变：不带路由。延迟的小幅波动也不算变化。
        *table.lock().unwrap() = vec![entry(2, 110), entry(3, 24)];
        report_now.notify_one();
        let quiet = expect_report(&mut stream).await;
        assert_eq!((quiet.routes_full, peers(&quiet)), (false, vec![]));

        // 一条路换了，一条的延迟变了不少，多了一个对端，少了一个对端。
        let direct = RouteEntry { peer: peer(2), route: Route::Direct { addr: "203.0.113.5:20330".parse().unwrap() }, rtt_ms: Some(100) };
        *table.lock().unwrap() = vec![direct.clone(), entry(4, 50)];
        report_now.notify_one();
        let changed = expect_report(&mut stream).await;
        assert_eq!((changed.routes_full, peers(&changed)), (false, vec![2, 4]));
        assert_eq!(changed.routes[0], direct);
        *table.lock().unwrap() = vec![direct, entry(4, 90)];
        report_now.notify_one();
        assert_eq!(peers(&expect_report(&mut stream).await), vec![4], "延迟从 50 变到 90 值得再报");

        // 重新连上之后的第一次上报又是完整的。
        drop(stream);
        let (mut again, _) = controller.accept().await;
        let _: ToController = expect(&mut again).await;
        let full = expect_report(&mut again).await;
        assert_eq!((full.routes_full, peers(&full)), (true, vec![2, 4]));
    }

    #[tokio::test]
    async fn update_commands_are_passed_on_and_unknown_messages_are_skipped() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (mut link, _hello) = link(&controller, state);
        let mut commands = link.take_update_commands().unwrap();
        assert!(link.take_update_commands().is_none(), "只有一个任务管更新");
        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;

        // 更新版本的 controller 才有的消息：跳过，连接接着用。
        write_message(&mut stream, &serde_json::json!({ "type": "added_in_a_newer_version", "x": 1 })).await.unwrap();
        write_message(&mut stream, &serde_json::json!({ "type": "update", "timing": "some_new_timing", "manifest": {} })).await.unwrap();
        let manifest = SignedManifest { manifest: "{}".to_owned(), signature: ManifestSignature::from_bytes([7; 64]) };
        write_message(&mut stream, &ToNode::Update { manifest: manifest.clone(), timing: UpdateTiming::AfterDrain }).await.unwrap();
        write_message(&mut stream, &ToNode::UpdateCancel).await.unwrap();

        let received = timeout(Duration::from_secs(5), commands.recv()).await.unwrap();
        assert_eq!(received, Some(UpdateCommand::Update { manifest, timing: UpdateTiming::AfterDrain }));
        assert_eq!(timeout(Duration::from_secs(5), commands.recv()).await.unwrap(), Some(UpdateCommand::Cancel));
        assert_eq!(*link.state().borrow(), LinkState::Offline, "还没有收到 netmap；重要的是连接没有因为不认识的消息断开重连");
        assert!(timeout(Duration::from_millis(200), controller.listener.accept()).await.is_err(), "没有重连");
    }

    #[tokio::test]
    async fn a_route_query_is_answered_from_the_assembly() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (mut setup, _hello) = setup(&controller, state, QUIET);
        setup.route = Box::new(|peer| RouteAnswer {
            peer,
            route: Some(Route::None),
            rtt_ms: Some(5),
            since: None,
            detail: None,
            connection_rtt_ms: Some(6),
        });
        let _link = ControlLink::spawn(setup);
        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;
        write_message(&mut stream, &ToNode::RouteQuery { request: 41, peer: peer(7) }).await.unwrap();
        let ToController::RouteAnswer { request, answer } = expect_other(&mut stream).await else { panic!("应该回答路由查询") };
        assert_eq!((request, answer.peer, answer.route, answer.rtt_ms), (41, peer(7), Some(Route::None), Some(5)));
    }

    #[tokio::test]
    async fn a_backbone_query_is_answered_from_the_assembly() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (mut setup, _hello) = setup(&controller, state, QUIET);
        let row = BackboneRow { relay: peer(9), state: Default::default(), load_percent: 7, age_ms: 300, links: Vec::new() };
        let rows = vec![row];
        let expected = rows.clone();
        setup.backbone = Box::new(move || rows.clone());
        let _link = ControlLink::spawn(setup);
        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;
        write_message(&mut stream, &ToNode::BackboneQuery { request: 12 }).await.unwrap();
        assert_eq!(expect_other(&mut stream).await, ToController::BackboneAnswer { request: 12, rows: expected });
    }

    #[tokio::test]
    async fn route_details_travel_with_their_entries_and_a_changed_detail_is_reported_again() {
        use i3t_model::control::DirectKind;

        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (mut setup, _hello) = setup(&controller, state, QUIET);
        let direct = |raw: u32| RouteEntry {
            peer: peer(raw),
            route: Route::Direct { addr: "203.0.113.5:20330".parse().unwrap() },
            rtt_ms: Some(10),
        };
        let kind = |raw: u32, direct: DirectKind| RouteKind {
            peer: peer(raw),
            direct: Some(direct),
            relay_leg: None,
            direct_status: None,
            alternative: None,
        };
        let table = Arc::new(std::sync::Mutex::new((vec![direct(2), direct(3)], vec![kind(2, DirectKind::Lan), kind(7, DirectKind::Lan)])));
        let current = Arc::clone(&table);
        setup.report = Box::new(move || {
            let (routes, route_kinds) = current.lock().unwrap().clone();
            Report { routes, route_kinds, ..Report::default() }
        });
        let report_now = Arc::clone(&setup.report_now);
        let _link = ControlLink::spawn(setup);
        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;

        let first = expect_report(&mut stream).await;
        assert_eq!(first.routes.len(), 2);
        assert_eq!(first.route_kinds, [kind(2, DirectKind::Lan)], "没有条目的对端的细节不报");

        // 路和延迟都没变，只是直连的类型变了：这一条连同细节再报一次。
        table.lock().unwrap().1 = vec![kind(2, DirectKind::Punched)];
        report_now.notify_one();
        let changed = expect_report(&mut stream).await;
        assert_eq!((changed.routes, changed.route_kinds), (vec![direct(2)], vec![kind(2, DirectKind::Punched)]));

        // 细节没了也算变化：controller 要知道原来的那一份不再对。
        table.lock().unwrap().1 = Vec::new();
        report_now.notify_one();
        let gone = expect_report(&mut stream).await;
        assert_eq!((gone.routes, gone.route_kinds), (vec![direct(2)], Vec::new()));
        report_now.notify_one();
        let quiet = expect_report(&mut stream).await;
        assert!(quiet.routes.is_empty() && quiet.route_kinds.is_empty());
    }

    #[tokio::test]
    async fn a_controller_that_cannot_take_the_node_right_now_is_dialled_again() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (link, _hello) = link(&controller, state);
        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;
        write_message(&mut stream, &ToNode::TryLater { reason: "存储暂时不可用".into() }).await.unwrap();
        drop(stream);

        let (mut again, _) =
            timeout(Duration::from_secs(5), controller.accept()).await.expect("controller 自己出错时节点要重连，不能就此停下");
        assert!(matches!(expect::<ToController>(&mut again).await, ToController::Hello(_)));
        assert!(!matches!(*link.state().borrow(), LinkState::Rejected | LinkState::Revoked));
        write_message(&mut again, &ToNode::Snapshot(Box::new(netmap(3)))).await.unwrap();
        let mut states = link.state();
        timeout(Duration::from_secs(5), states.wait_for(|state| *state == LinkState::Online)).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn enrolment_that_the_controller_cannot_handle_right_now_says_to_try_again() {
        let controller = FakeController::start().await;
        let info = controller.info.clone();
        tokio::spawn(async move {
            let (mut stream, _) = controller.accept().await;
            let _: ToController = expect(&mut stream).await;
            write_message(&mut stream, &ToNode::TryLater { reason: "存储暂时不可用".into() }).await.unwrap();
        });
        let err = enroll(&info, &NodeKey::generate().unwrap(), "x", Hello::default()).await.unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains(&(texts().enroll_try_later)("存储暂时不可用")), "{message}");
    }

    /// 取一段包：`version` 的 linux 包里从 `offset` 起的 `len` 字节。
    async fn fetch(packages: &Packages, offset: u64, len: u32) -> Result<Vec<u8>, SourceError> {
        let (version, platform) = (Version::new(0, 2, 0), "linux-x86_64".parse().unwrap());
        packages.fetch(ChunkRequest { version: &version, platform: &platform, offset, len }).await
    }

    #[tokio::test]
    async fn packages_are_fetched_over_the_link_and_a_lost_link_reads_as_interrupted() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (setup, _hello) = setup(&controller, state, QUIET);
        let link = ControlLink::spawn(setup);
        let packages = link.packages();
        assert!(matches!(fetch(&packages, 0, 4).await, Err(SourceError::Interrupted(_))), "还没连上：过一会儿再要，不算失败");

        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;
        let (first, second) = (
            tokio::spawn({
                let packages = packages.clone();
                async move { fetch(&packages, 0, 4).await }
            }),
            {
                let packages = packages.clone();
                tokio::spawn(async move { fetch(&packages, 4, 4).await })
            },
        );
        let mut asked = Vec::new();
        for _ in 0..2 {
            let ToController::PackageRequest { request, version, platform, offset, len } = expect_other(&mut stream).await else {
                panic!("应该收到取包的请求")
            };
            assert_eq!((version.to_string().as_str(), platform.as_str(), len), ("0.2.0", "linux-x86_64", 4));
            asked.push((request, offset));
        }
        // 回答的先后和要的先后不一样也对得上；多余的、没人等的回答被忽略。
        asked.sort_by_key(|&(_, offset)| std::cmp::Reverse(offset));
        write_message(&mut stream, &ToNode::PackageChunk { request: 999, data: vec![9] }).await.unwrap();
        for (request, offset) in &asked {
            let data = if *offset == 0 { b"abcd".to_vec() } else { b"efgh".to_vec() };
            write_message(&mut stream, &ToNode::PackageChunk { request: *request, data }).await.unwrap();
        }
        assert_eq!(first.await.unwrap().unwrap(), b"abcd");
        assert_eq!(second.await.unwrap().unwrap(), b"efgh");

        // controller 明说给不了。
        let refused = tokio::spawn({
            let packages = packages.clone();
            async move { fetch(&packages, 8, 4).await }
        });
        let ToController::PackageRequest { request, .. } = expect_other(&mut stream).await else { panic!("应该收到取包的请求") };
        write_message(&mut stream, &ToNode::PackageUnavailable { request, reason: "没有这个平台的包".into() }).await.unwrap();
        assert_eq!(refused.await.unwrap(), Err(SourceError::Unavailable("没有这个平台的包".into())));

        // 要到一半连接断了：被打断，不是给不了。
        let cut_off = tokio::spawn({
            let packages = packages.clone();
            async move { fetch(&packages, 8, 4).await }
        });
        let _request = expect_other(&mut stream).await;
        drop(stream);
        assert!(matches!(cut_off.await.unwrap(), Err(SourceError::Interrupted(_))));
    }

    #[tokio::test]
    async fn the_self_check_probe_authenticates_both_ways_and_says_nothing() {
        let controller = FakeController::start().await;
        let key = NodeKey::generate().unwrap();
        let (info, public) = (controller.info.clone(), key.public());
        let server = tokio::spawn(async move {
            let (mut stream, seen_key) = controller.accept().await;
            assert_eq!(seen_key, public, "controller 认出了节点的公钥");
            // 节点什么都不发就关了连接：没有 hello，旧程序的连接不会被顶替。
            assert!(read_message::<_, ToController>(&mut stream).await.unwrap().is_none());
        });
        probe(&info, &key).await.unwrap();
        server.await.unwrap();

        // controller 的公钥不对：握手不成，自检不通过。
        let controller = FakeController::start().await;
        let mut wrong = controller.info.clone();
        wrong.key = NodeKey::generate().unwrap().public();
        tokio::spawn(async move {
            let (tcp, _) = controller.listener.accept().await.unwrap();
            let _ = controller.acceptor.accept(tcp).await;
        });
        assert!(probe(&wrong, &key).await.is_err());
        // 连不上。
        let nobody = ControllerInfo { address: "127.0.0.1:1".to_owned(), key: public };
        assert!(probe(&nobody, &key).await.is_err());
    }

    #[tokio::test]
    async fn the_report_carries_whatever_the_assembly_puts_in_it() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (mut setup, _hello) = setup(&controller, state, QUIET);
        setup.report =
            Box::new(|| Report { update: Some(UpdateStatus::WaitingForIdle { version: Version::new(0, 2, 0) }), ..Report::default() });
        let _link = ControlLink::spawn(setup);
        let (mut stream, _) = controller.accept().await;
        let _: ToController = expect(&mut stream).await;
        assert_eq!(expect_report(&mut stream).await.update, Some(UpdateStatus::WaitingForIdle { version: Version::new(0, 2, 0) }));
    }

    #[tokio::test]
    async fn the_link_reconnects_after_the_connection_drops() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (link, _hello) = link(&controller, state);
        let (mut first, _) = controller.accept().await;
        let _: ToController = expect(&mut first).await;
        drop(first);

        let (mut second, _) = controller.accept().await;
        assert!(matches!(expect::<ToController>(&mut second).await, ToController::Hello(_)));
        write_message(&mut second, &ToNode::Snapshot(Box::new(netmap(5)))).await.unwrap();
        let mut netmaps = link.netmap();
        timeout(Duration::from_secs(5), netmaps.wait_for(|netmap| netmap.version == 5)).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_silent_controller_is_dropped_and_dialled_again() {
        let controller = FakeController::start().await;
        let (_dir, state) = temp_state();
        let (_link, _hello) = link(&controller, state);
        // 第一条连接上 controller 一句话都不说，但也不关。
        let (_silent, _) = controller.accept().await;
        let (mut second, _) = timeout(Duration::from_secs(5), controller.accept()).await.expect("空闲超时之后应该重连");
        assert!(matches!(expect::<ToController>(&mut second).await, ToController::Hello(_)));
    }

    #[tokio::test]
    async fn revocation_and_rejection_stop_the_link_for_good() {
        for (message, expected) in [
            (ToNode::Revoked, LinkState::Revoked),
            (ToNode::Rejected { reason: "不认识这个公钥".into(), cause: None }, LinkState::Rejected),
        ] {
            let controller = FakeController::start().await;
            let (_dir, state) = temp_state();
            let (link, _hello) = link(&controller, state);
            let (mut stream, _) = controller.accept().await;
            let _: ToController = expect(&mut stream).await;
            write_message(&mut stream, &message).await.unwrap();
            // 节点这时可能正好在发上报，把它读掉，直到连接被节点关闭。
            while read_message::<_, ToController>(&mut stream).await.is_ok_and(|message| message.is_some()) {}

            let mut states = link.state();
            timeout(Duration::from_secs(5), states.wait_for(|state| *state == expected)).await.unwrap().unwrap();
            // 之后不应该再有新的连接进来。
            assert!(timeout(Duration::from_millis(300), controller.listener.accept()).await.is_err());
        }
    }

    #[tokio::test]
    async fn oversized_and_truncated_frames_are_errors() {
        let mut oversized: &[u8] = &u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_be_bytes();
        assert!(read_message::<_, ToNode>(&mut oversized).await.is_err());
        let mut truncated: &[u8] = &[0, 0, 0, 9, b'{'];
        assert!(read_message::<_, ToNode>(&mut truncated).await.is_err());
        let mut empty: &[u8] = &[];
        assert!(read_message::<_, ToNode>(&mut empty).await.unwrap().is_none());
    }

    #[test]
    fn small_rtt_changes_are_not_worth_reporting() {
        let entry = |rtt_ms| RouteEntry { peer: peer(2), route: Route::None, rtt_ms };
        assert!(!differs(&entry(Some(20)), &entry(Some(29))) && differs(&entry(Some(20)), &entry(Some(31))));
        assert!(!differs(&entry(Some(200)), &entry(Some(249))) && differs(&entry(Some(200)), &entry(Some(251))));
        assert!(differs(&entry(None), &entry(Some(1))) && differs(&entry(Some(1)), &entry(None)) && !differs(&entry(None), &entry(None)));
    }
}
