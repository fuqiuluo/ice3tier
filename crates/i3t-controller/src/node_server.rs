//! 节点协议的服务端：TCP 上的 TLS 1.3，双方按公钥互相认证，上面是分帧的 JSON 消息。
//!
//! 这里只管连接：握手、读写、心跳、超时。每条消息怎么处理在 [`Controller`] 里。
//!
//! 一条连接上的顺序：节点先发 `Enroll` 或 `Hello`；controller 回 `Snapshot`，不认它时回 `Rejected` 然后断开，
//! 自己出了错时回 `TryLater` 然后断开（节点会按退避重连）。之后节点上报、确认、发信令，controller 下发 netmap、转信令。
//!
//! 握手和成员资格核验分别按来源地址记账（[`crate::gate`]）。握手名额满了挤掉老连接，核验名额满了让新来的稍后重试。
//! 连上之后 [`CLIENT_HELLO_TIMEOUT`] 之内要收到 TLS 的 ClientHello，从连上算起 [`Timing::handshake_timeout`] 之内要完成握手并发来第一条消息。
//!
//! [`Timing::handshake_timeout`]: crate::Timing::handshake_timeout

mod verification;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use i3t_crypto::tls;
use i3t_model::control::{MAX_FRAME_LEN, ToController, ToNode};
use i3t_proto::PublicKey;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, sleep, sleep_until, timeout, timeout_at};
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;

use crate::controller::{Admitted, Controller};
use crate::error::{Rejection, error_chain};
use crate::frame::{FrameError, read_frame, write_frame};
use crate::gate::{Gate, Limits, Pass, Throttle};
use crate::server::blocking;
use verification::AdmissionError;
pub(crate) use verification::VerificationQuota;

/// 还没报到的连接上，一帧最长这么多字节。`Enroll` 和 `Hello` 都只有几百字节。
const FIRST_FRAME_LIMIT: usize = 64 * 1024;
/// 握手和核验各用一组名额：每个来源最多 16 条，全部最多 256 条。
///
/// 正常的节点连上来几个往返就报到完了，同一个家用 NAT 后面的节点在 controller 重启之后带着随机的退避陆续连回来，
/// 同时在握手的远到不了 16 条。
pub(crate) const PENDING: Limits = Limits { per_source: 16, total: 256 };
/// 连上之后这么久还没有收到 TLS 的 ClientHello 就断开。正常的节点连上就发；只连不说话的连接不值得等满整个握手时限。
pub const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(3);
/// 接受连接失败（多半是文件描述符用完了）的日志多久最多记一条。
const ACCEPT_ERROR_LOG_EVERY: Duration = Duration::from_secs(10);
/// 每个节点的发送队列有多少格。满了说明节点不读，controller 会断开它。
const OUTBOX_CAPACITY: usize = 64;
/// 报到失败的应答很小，写入和关闭合计最多占用名额这么久。之前的核验耗时另计。
const ADMISSION_REPLY_TIMEOUT: Duration = Duration::from_secs(2);
/// 已报到节点的一帧写这么久还没写完，就认为连接已经死了。
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// 关闭时最多等连接收尾这么久。
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

type Reader = ReadHalf<TlsStream<TcpStream>>;
type Writer = WriteHalf<TlsStream<TcpStream>>;

/// 在 `listener` 上接受节点的连接，直到 `shutdown` 变化。`tls` 来自 [`Controller::tls_config`]。
pub async fn serve(
    controller: Arc<Controller>,
    tls: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) {
    let pending = Gate::new("还没报到的节点连接", PENDING);
    let accept_errors = Throttle::new(ACCEPT_ERROR_LOG_EVERY);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = i3t_underlay::tcp_mss::accept(&listener) => match accepted {
                Ok((stream, remote)) => {
                    let pass = pending.admit(remote.ip());
                    let mut connection = Connection { controller: Arc::clone(&controller), remote, shutdown: shutdown.clone() };
                    let tls = Arc::clone(&tls);
                    connections.spawn(async move {
                        let Some(established) = connection.establish(tls, stream, pass).await else { return };
                        connection.run(established).await;
                    });
                }
                Err(err) => {
                    // 多半是文件描述符用完了。歇一下再接，免得空转。
                    if let Some(suppressed) = accept_errors.allow() {
                        tracing::warn!(suppressed, "接受连接失败：{err}");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            _ = shutdown.changed() => break,
        }
    }
    drop(listener);
    // 每条连接自己也在看 shutdown：它们会把节点记为离线再退出。
    if timeout(SHUTDOWN_GRACE, async { while connections.join_next().await.is_some() {} }).await.is_err() {
        tracing::warn!("有连接没有在 {SHUTDOWN_GRACE:?} 之内结束，不再等它们");
    }
}

struct Connection {
    controller: Arc<Controller>,
    remote: SocketAddr,
    shutdown: watch::Receiver<bool>,
}

/// 一条已经报到的连接。
struct Established {
    session: Admitted,
    reader: Reader,
    writer: Writer,
    outbox: mpsc::Receiver<ToNode>,
}

impl Connection {
    /// 握手，读第一条消息，让 controller 决定认不认这个节点。不认时回 `Rejected`（或者 `TryLater`）并返回 `None`。
    ///
    /// `pass` 在取得核验名额后交还。满额或首帧不合要求时，应答仍受握手名额和时限约束。
    async fn establish(&mut self, tls: Arc<rustls::ServerConfig>, stream: TcpStream, mut pass: Pass) -> Option<Established> {
        let remote = self.remote;
        let deadline = Instant::now() + self.controller.timing().handshake_timeout;
        let handshake = timeout_at(deadline, handshake(tls, stream));
        let outcome = tokio::select! {
            outcome = handshake => outcome,
            () = pass.evicted() => {
                tracing::debug!(%remote, "还没报到的连接太多，这一条被挤掉了");
                return None;
            }
        };
        let (key, first, reader, mut writer) = match outcome {
            Ok(Ok(parts)) => parts,
            Ok(Err(reason)) => {
                tracing::debug!(%remote, %reason, "连接没有完成报到");
                return None;
            }
            Err(_) => {
                tracing::debug!(%remote, "连接没有在限定时间内完成握手并发来第一条消息");
                return None;
            }
        };

        let ip = remote.ip();
        let (hello, token) = match first {
            ToController::Enroll { token, hello } => (hello, Some(token)),
            ToController::Hello(hello) => (hello, None),
            ToController::Report(_)
            | ToController::Ack { .. }
            | ToController::Signal { .. }
            | ToController::Heartbeat
            | ToController::PackageRequest { .. }
            | ToController::RouteAnswer { .. }
            | ToController::BackboneAnswer { .. }
            | ToController::TestReport(_)
            | ToController::ExitTestAnswer { .. } => {
                if let Some(suppressed) = self.controller.refusal_log.allow() {
                    tracing::warn!(key = ?key, remote = %ip, suppressed, "拒绝连接：第一条消息不是 enroll 也不是 hello");
                }
                AdmissionError::UnexpectedFirstMessage(pass).reply(&mut writer, remote, deadline, &mut self.shutdown).await;
                return None;
            }
        };
        let (outbox, inbox) = mpsc::channel(OUTBOX_CAPACITY);
        let check = move |controller: &Controller| match token {
            Some(token) => controller.enroll(key, &token, &hello, ip, outbox),
            None => controller.hello(key, &hello, ip, outbox),
        };
        match self.controller.verify_node(pass, check).await {
            Ok(session) => Some(Established { session, reader, writer, outbox: inbox }),
            Err(error) => {
                error.reply(&mut writer, remote, deadline, &mut self.shutdown).await;
                None
            }
        }
    }

    async fn run(mut self, established: Established) {
        let Established { session, reader, mut writer, mut outbox } = established;
        let timing = self.controller.timing();
        let ip = self.remote.ip();
        let (mut inbound, reader_task) = spawn_reader(reader);
        let mut last_heard = Instant::now();
        let mut last_sent = Instant::now();

        let reason = loop {
            tokio::select! {
                received = inbound.recv() => match received {
                    Some(Ok(message)) => {
                        last_heard = Instant::now();
                        let handled = blocking(&self.controller, move |controller| controller.handle(session, ip, message)).await;
                        if let Err(err) = handled {
                            tracing::error!(node = %session.node, "处理节点的消息时出错：{}", error_chain(&err));
                        }
                    }
                    // 多半是更新版本的节点发来的、这个版本不认识的消息。跳过它，连接接着用。
                    Some(Err(FrameError::Json(err))) => {
                        last_heard = Instant::now();
                        tracing::debug!(node = %session.node, "忽略一条解析不了的消息：{err}");
                    }
                    Some(Err(err)) => break format!("读取失败：{}", error_chain(&err)),
                    None => break "节点关闭了连接".to_owned(),
                },
                outgoing = outbox.recv() => match outgoing {
                    Some(message) => match timeout(WRITE_TIMEOUT, write_frame(&mut writer, &message)).await {
                        Ok(Ok(())) => last_sent = Instant::now(),
                        Ok(Err(err)) => break format!("写入失败：{}", error_chain(&err)),
                        Err(_) => break format!("一条消息 {WRITE_TIMEOUT:?} 没写完"),
                    },
                    // 发送队列的另一头没了：这条连接被同一个节点的新连接顶替，或者节点被删除（Revoked 已经在上面发出去了）。
                    None => break "controller 结束了这条连接".to_owned(),
                },
                () = sleep_until(last_sent + timing.heartbeat_idle) => {
                    match timeout(WRITE_TIMEOUT, write_frame(&mut writer, &ToNode::Heartbeat)).await {
                        Ok(Ok(())) => last_sent = Instant::now(),
                        _ => break "心跳发不出去".to_owned(),
                    }
                }
                () = sleep_until(last_heard + timing.liveness_timeout) => {
                    break format!("{:?} 没有收到节点的任何消息", timing.liveness_timeout);
                }
                _ = self.shutdown.changed() => break "controller 正在关闭".to_owned(),
            }
        };

        tracing::info!(node = %session.node, remote = %self.remote, %reason, "和节点的连接结束");
        reader_task.abort();
        blocking(&self.controller, move |controller| controller.disconnect(session)).await;
        close(&mut writer).await;
    }
}

/// TLS 握手，取出对端的公钥，读第一条消息。失败时返回给日志看的原因。
///
/// ClientHello 要在 [`CLIENT_HELLO_TIMEOUT`] 之内到；整个过程的时限由调用的一方管。
async fn handshake(tls: Arc<rustls::ServerConfig>, stream: TcpStream) -> Result<(PublicKey, ToController, Reader, Writer), String> {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!("设置 TCP_NODELAY 失败：{err}");
    }
    let hello = timeout(CLIENT_HELLO_TIMEOUT, LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream))
        .await
        .map_err(|_| format!("{CLIENT_HELLO_TIMEOUT:?} 之内没有收到 TLS 的 ClientHello"))?
        .map_err(|err| format!("TLS 握手失败：{err}"))?;
    let stream = hello.into_stream(tls).await.map_err(|err| format!("TLS 握手失败：{err}"))?;
    let key = {
        let (_, session) = stream.get_ref();
        let certificate = session.peer_certificates().and_then(|chain| chain.first()).ok_or("对端没有出示证书")?;
        tls::peer_key(certificate).map_err(|err| format!("对端的证书不能用：{err}"))?
    };
    let (mut reader, writer) = tokio::io::split(stream);
    match read_frame(&mut reader, FIRST_FRAME_LIMIT).await {
        Ok(Some(first)) => Ok((key, first, reader, writer)),
        Ok(None) => Err("对端没有发消息就关闭了连接".to_owned()),
        Err(err) => Err(format!("第一条消息读不出来：{}", error_chain(&err))),
    }
}

/// 读取任务：把收到的帧一条条放进队列。读一帧不能被打断（长度和内容分两次读），所以不能直接放在 `select!` 里。
/// 连接断开或者出了解析之外的错，放进最后一个结果然后退出。
fn spawn_reader(mut reader: Reader) -> (mpsc::Receiver<Result<ToController, FrameError>>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        loop {
            let frame = match read_frame(&mut reader, MAX_FRAME_LEN).await {
                Ok(Some(message)) => Ok(message),
                Ok(None) => return,
                Err(err) => Err(err),
            };
            let fatal = matches!(frame, Err(FrameError::Io(_) | FrameError::TooLong { .. }));
            if tx.send(frame).await.is_err() || fatal {
                return;
            }
        }
    });
    (rx, task)
}

impl AdmissionError {
    async fn reply(
        self,
        writer: &mut (impl AsyncWrite + Unpin),
        remote: SocketAddr,
        deadline: Instant,
        shutdown: &mut watch::Receiver<bool>,
    ) {
        let (mut pass, reply) = match self {
            Self::Evicted => {
                tracing::debug!(%remote, "握手名额已被挤掉，跳过成员资格核验");
                return;
            }
            Self::Rejected(reason, _permit) => {
                reply_and_close(writer, reason.reply(), remote, shutdown).await;
                return;
            }
            Self::Busy(pass) => (pass, ToNode::TryLater { reason: "正在核验的节点太多，稍后再试".to_owned() }),
            Self::UnexpectedFirstMessage(pass) => (pass, Rejection::UnexpectedFirstMessage.reply()),
        };
        tokio::select! {
            biased;
            () = pass.evicted() => tracing::debug!(%remote, "发送报到应答时握手名额被挤掉"),
            () = sleep_until(deadline) => tracing::debug!(%remote, "发送报到应答时已到握手时限"),
            () = reply_and_close(writer, reply, remote, shutdown) => {}
        }
    }
}

async fn reply_and_close(writer: &mut (impl AsyncWrite + Unpin), reply: ToNode, remote: SocketAddr, shutdown: &mut watch::Receiver<bool>) {
    let send = async {
        match write_frame(writer, &reply).await {
            Ok(()) => close(writer).await,
            Err(err) => tracing::debug!(%remote, "拒绝的原因没能发给对方：{}", error_chain(&err)),
        }
    };
    tokio::select! {
        biased;
        _ = shutdown.wait_for(|&stopping| stopping) => {}
        () = sleep(ADMISSION_REPLY_TIMEOUT) => tracing::debug!(%remote, "拒绝应答没有在 {ADMISSION_REPLY_TIMEOUT:?} 内写完并关闭连接"),
        () = send => {}
    }
}

/// 尽量体面地关掉连接。对方不配合也不多等。
async fn close(writer: &mut (impl AsyncWrite + Unpin)) {
    // 关不关得干净不影响任何状态：连接反正要丢弃了。
    let _ = timeout(Duration::from_secs(1), writer.shutdown()).await;
}
