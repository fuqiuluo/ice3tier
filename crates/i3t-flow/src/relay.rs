//! 在一条流和一条 TCP 连接之间双向搬运。
//!
//! 两个方向各自独立，各有正常和异常两种结局，搬运要把它们如实传到另一头：
//!
//! | 这一头发生了什么 | 另一头看到什么 |
//! |---|---|
//! | TCP 读到 EOF（对方发了 FIN） | 流的发送方向正常结束 |
//! | 流读到 EOF | TCP 发送 FIN（仅关闭写半部，另一方向继续转发） |
//! | TCP 读写出错（被重置、保活超时） | 流的两个方向都异常结束，带原因码 |
//! | 流被对端重置或叫停、连接断开、搬运被取消 | TCP 被重置（RST），不是 FIN |
//!
//! 被截断的数据不能看起来像正常结束。所以搬运一开始就把 TCP 设成"关闭时发 RST"，只有两个方向都正常结束了才改回去：
//! 中途无论发生错误、任务取消还是进程退出，TCP 对端都会收到重置。macOS 上不能等到此时：socket 双向关闭后
//! 无法再修改该选项，因此会在发送 FIN 时先恢复正常关闭，后续出错时再重新设置（见 `i3t_underlay::tcp_reset`）。
//!
//! 静默不是断开的理由：经端口转发的 SSH 会话、数据库连接池里的空闲连接，一连几个小时不说话都是正当的。
//! 所以流没有"多久没有数据就切断"的时限，而是和 TCP 的保活一样，静默久了去探一探两头还在不在，不在了才断：
//!
//! - 对端节点还在不在：连接层的保活（15 秒一次，30 秒没有回应就判连接断开，上面的流全部出错）；
//! - TCP 那一头还在不在：内核保活（[`keep_alive`]），入口一侧的客户端连接和出口一侧到目标的连接都打开。
//!   探测没有回应时内核报错，搬运把流重置，另一头的节点跟着重置它那一头的 TCP。
//!
//! 任一端无声中断（断电、切换网络、NAT 映射回收）后，两端资源会在数分钟内释放；存活连接会正常响应探测并保持不断开。
//! 活着却一直不说话的流占着的资源，由接受方按发起节点限制同时处理的流数来约束（[`crate::Handler::screen`]）。
//!
//! 流在 ice3proxy（lane）上、并且负载不再加密（用户自己的 TLS 原样过去）时，那个方向在 lane 交出原始的 socket 之后
//! （[`SendStream::take_raw`]、[`RecvStream::wait_raw`]）直接在两条 TCP 之间搬（[`crate::engine`]，Linux 上是 splice），
//! 不再经过流的接口。结局的传法和上表一样：EOF 对 FIN，出错对 RST；计量和配额照样在每一段上记。
//!
//! 发起方选了不再加密（它的首批数据是 TLS 1.3 的 ClientHello）也只是可以：两个方向都要等出口看到目标回了 TLS 1.3 的
//! ServerHello（[`ServerHelloWatch`]）。ServerHello 仍按加密方式发回，此后出口回传方向不再加密，入口侧 lane 收到切换信号
//! 时它的方向跟着切换；目标回了 HelloRetryRequest、用的是 TLS 1.2（证书会明文来回）、或者根本不是 TLS 时，两个方向一直加密。
//! 所以入口一侧两个方向每一段之前都问一下切换了没有。
//!
//! 流往对端节点发数据的优先级跟着服务等级（[`priority_of`]）：同一条连接上，interactive 的流先于 bulk 的流发出。
//! `auto` 的流开始时按 interactive 对待，这一端在它上面发出的数据累计超过 [`AUTO_DEMOTE_AFTER`] 之后降到 bulk 的优先级。
//! 优先级只管本端发出去的方向，所以两端各数各的：下载时降级的是出口那一端，上传时是入口这一端。

use std::fmt;
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use i3t_conn::contract::{Priority, wait_revoked};
use i3t_conn::{Payload, RawRead, RawWrite, RecvStream, SendStream, ServerHelloVerdict, ServerHelloWatch, StreamAborted, StreamCode};
use i3t_proto::flow::{Class, Reason, Reply};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::sync::watch;

use crate::engine::{Gate, PumpError, Splicer};
use crate::meter::{Direction, Meter, Unmetered};
use crate::{FlowError, header};

/// 每个方向一块缓冲区，默认这么大。流的数量可以上万，所以不取更大的。
pub const DEFAULT_BUFFER_LEN: usize = 16 * 1024;

/// 现在的缓冲区大小，见 [`set_buffer_len`]。
static BUFFER_LEN: AtomicUsize = AtomicUsize::new(DEFAULT_BUFFER_LEN);

/// 设每条流每个方向的搬运缓冲区有多大（性能档位的一项）。之后开始搬运的流用它，已经在搬的不变。
///
/// 这块缓冲区在流活着的时候一直占着，所以它乘上流的条数就是搬运本身的内存：本机实验环境里 2000 条开着的流，
/// 16KB 时入口和出口各多用约 45MB；4KB 时少这么多，代价是满速搬运的每 GB CPU 多两成左右。
/// 整个进程一个值，由装配方按档位设；不到 1KB 的按 1KB 算。
pub fn set_buffer_len(len: usize) {
    BUFFER_LEN.store(len.max(1024), Ordering::Relaxed);
}

/// 现在的搬运缓冲区大小。
#[must_use]
pub fn buffer_len() -> usize {
    BUFFER_LEN.load(Ordering::Relaxed)
}

/// 和流对接的 TCP 连接静默多久之后内核开始发保活探测，以及探测的间隔。
///
/// 探测连续没有回应（Linux 默认 9 次）时内核报错，一头消失之后大约四分钟流被重置。活着的连接回应探测，不受影响。
/// 系统默认要静默两小时才开始探测；这里取得短得多，因为出口到目标的连接常常要穿过家用路由器，
/// 静默久了映射会被悄悄回收，而大模型这类请求正好会长时间静默。探测很小，静默的连接每 25 秒一个，代价可以忽略。
pub const KEEPALIVE: Duration = Duration::from_secs(25);

/// 给一条要和流对接的 TCP 连接打开内核保活，参数见 [`KEEPALIVE`]。入口接受的客户端连接、出口连上的目标都要打开：
/// 流本身没有空闲时限，TCP 那一头的死活只靠它判断（模块文档）。
///
/// # Errors
///
/// 系统不让设。连接照样能用，只是那一头悄悄消失时这条流要等到有数据要发才会发现。
pub fn keep_alive(stream: &TcpStream) -> io::Result<()> {
    let keepalive = TcpKeepalive::new().with_time(KEEPALIVE).with_interval(KEEPALIVE);
    SockRef::from(stream).set_tcp_keepalive(&keepalive)
}

/// `auto` 等级的流，这一端在它上面发出多少字节之后降到 bulk 的优先级。
pub(crate) const AUTO_DEMOTE_AFTER: u64 = 1024 * 1024;

/// 一个服务等级的流刚建立时，往对端发数据用什么优先级。
pub(crate) const fn priority_of(class: Class) -> Priority {
    match class {
        Class::Interactive | Class::Auto => Priority::High,
        Class::Reliable => Priority::Normal,
        Class::Bulk => Priority::Low,
    }
}

/// TCP 那一头是谁。决定它出错时告诉对端节点的原因码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpRole {
    /// 入口一侧：TCP 那一头是客户端。
    Client,
    /// 出口一侧：TCP 那一头是目标。
    Target,
}

/// 一条流的两个方向，加上搬运时需要知道的事。
pub(crate) struct Parts<S, R> {
    pub send: S,
    pub recv: R,
    pub role: TcpRole,
    /// 服务等级。发送方向的优先级在建流时已经按它设好了，这里用它判断要不要中途降级。
    pub class: Class,
    /// 首字节时间从这个时刻算起。
    pub started: Instant,
    /// 流上的 REPLY 还没有读（乐观回复）。
    pub reply_pending: bool,
}

/// 一条两边都同意了的流：REPLY 已经发出（接受方）或者已经读到并且是成功（发起方），接下来只剩搬运。
pub struct Flow<S, R> {
    pub(crate) parts: Parts<S, R>,
}

/// 契约没有要求流实现 `Debug`，所以这里不打印它们。
impl<S, R> fmt::Debug for Flow<S, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flow").field("role", &self.parts.role).finish_non_exhaustive()
    }
}

impl<S: SendStream, R: RecvStream> Flow<S, R> {
    pub(crate) fn new(parts: Parts<S, R>) -> Self {
        Self { parts }
    }

    /// 在这条流和 `tcp` 之间搬运，直到两个方向都结束，或者有一头异常结束。
    ///
    /// `tcp` 是入口一侧的客户端连接，或者出口一侧到目标的连接。`cancel` 完成时搬运立刻停止：
    /// 流用它给出的原因码重置，`tcp` 被重置。不需要取消时传 [`std::future::pending`]。
    ///
    /// 返回之后流和 `tcp` 都已经关闭。
    pub async fn relay(self, tcp: TcpStream, cancel: impl Future<Output = Reason>) -> Summary {
        run(self.parts, tcp, cancel, &Unmetered, None).await
    }

    /// 和 [`relay`](Self::relay) 一样，只是每一段数据写出去之前先过 `meter`：它可以计数、让搬运慢下来，或者叫停。
    /// 被叫停时结局是 [`End::Cancelled`]，带着 `meter` 给的原因码。
    pub async fn relay_metered(self, tcp: TcpStream, cancel: impl Future<Output = Reason>, meter: &impl Meter) -> Summary {
        run(self.parts, tcp, cancel, meter, None).await
    }

    /// 与 [`relay_metered`](Self::relay_metered) 类似，但仅将 `tcp` 中由 `framing` 界定的消息片段写入流。
    ///
    /// 适用于单条 TCP 连接上仅有部分数据属于当前流的协议，例如明文 HTTP 代理请求（请求头已随 OPEN 发出，此处仅转发请求体）。
    /// 该片段完整后即停止读取 `tcp`，丢弃多余字节；此时流的发送方向**不**立即正常关闭，而是等待另一方向结束（目标响应发完）
    /// 后再关闭，避免部分服务器将客户端半关闭视为连接中断而丢弃未发完的响应。若片段尚未完整时 `tcp` 即读到 EOF，
    /// 视为数据截断并按 TCP 错误处理（重置流），避免目标误认为请求已完整。
    ///
    /// 流的头之后的字节一直经过这一层（不交给 ice3proxy 直接搬）：要划分就得看得到它们。首批数据是 TLS 握手的流不该用它。
    pub async fn relay_framed(
        self,
        tcp: TcpStream,
        cancel: impl Future<Output = Reason>,
        meter: &impl Meter,
        framing: &mut (dyn Framing + Send),
    ) -> Summary {
        run(self.parts, tcp, cancel, meter, Some(framing)).await
    }

    /// 不搬运了：两个方向都异常结束，带上 `reason`。
    pub fn abort(mut self, reason: Reason) {
        let code = StreamCode(reason.to_wire());
        self.parts.send.reset(code);
        self.parts.recv.stop(code);
    }
}

/// 从 TCP 读到的字节里哪些属于这条流（见 [`Flow::relay_framed`]）。
pub trait Framing {
    /// `bytes` 为刚从 TCP 读取的数据，返回开头属于当前流的字节数。若小于 `bytes.len()`，表示当前消息片段已结束。
    ///
    /// # Errors
    ///
    /// 数据不符合当前分帧格式。流将按返回的原因码重置，TCP 连接也会随之重置。
    fn take(&mut self, bytes: &[u8]) -> Result<usize, Reason>;

    /// 当前消息片段是否已完整。
    fn is_complete(&self) -> bool;
}

/// 一个方向上搬了多少。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Traffic {
    pub bytes: u64,
    /// 从流建立到这个方向上读到第一个字节过了多久；一个字节都没有时是 `None`。
    pub first_byte: Option<Duration>,
}

impl Traffic {
    fn arrived(&mut self, started: Instant) {
        self.first_byte.get_or_insert_with(|| started.elapsed());
    }

    fn delivered(&mut self, len: usize) {
        // usize 不会比 u64 宽，这里不会截断。
        self.bytes += len as u64;
    }
}

/// 一次搬运的结果。
#[derive(Debug)]
pub struct Summary {
    /// 从 TCP 读出来、写进流的。出口一侧这是目标发回来的数据，它的 `first_byte` 就是目标的首字节时间。
    pub from_tcp: Traffic,
    /// 从流读出来、写进 TCP 的。
    pub from_flow: Traffic,
    pub end: End,
}

/// 搬运是怎么结束的。
#[derive(Debug)]
#[non_exhaustive]
pub enum End {
    /// 两个方向都正常结束。
    Clean,
    /// TCP 那一头出错（被重置、保活超时等）。
    Tcp(io::Error),
    /// 对端节点重置或者叫停了这条流，里面有它给的原因码。
    Aborted(StreamAborted),
    /// 流出了别的错：和对端节点的连接断了。
    Lost(io::Error),
    /// 乐观回复时，对端的 REPLY 是拒绝。
    Refused(Reply),
    /// 乐观回复模式下，读取或解析对端 REPLY 失败。
    BadReply(FlowError),
    /// 调用者取消了搬运。
    Cancelled(Reason),
}

impl End {
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }
}

/// 一个方向停下来的原因。
enum Abort {
    Tcp(io::Error),
    Flow(io::Error),
    Refused(Reply),
    BadReply(FlowError),
    Cancelled(Reason),
}

impl Abort {
    /// 流的发送方向被对端叫停了。
    fn is_stop(&self) -> bool {
        matches!(self, Self::Flow(error) if matches!(StreamAborted::of(error), Some(StreamAborted::Stopped(_))))
    }

    /// 这一端结束流时告诉对端节点的原因。
    fn reason(&self, role: TcpRole) -> Reason {
        match self {
            Self::Tcp(error) => match role {
                TcpRole::Client => Reason::ClientReset,
                TcpRole::Target if error.kind() == io::ErrorKind::ConnectionReset => Reason::TargetReset,
                TcpRole::Target => Reason::TargetError,
            },
            Self::BadReply(_) => Reason::ProtocolError,
            // 是对端先结束的，这里只是跟着放弃另一个方向。
            Self::Flow(_) | Self::Refused(_) => Reason::Cancelled,
            Self::Cancelled(reason) => *reason,
        }
    }
}

impl From<Abort> for End {
    fn from(abort: Abort) -> Self {
        match abort {
            Abort::Tcp(error) => Self::Tcp(error),
            Abort::Flow(error) => match StreamAborted::of(&error) {
                Some(aborted) => Self::Aborted(aborted),
                None => Self::Lost(error),
            },
            Abort::Refused(reply) => Self::Refused(reply),
            Abort::BadReply(error) => Self::BadReply(error),
            Abort::Cancelled(reason) => Self::Cancelled(reason),
        }
    }
}

pub(crate) async fn run<S: SendStream, R: RecvStream>(
    parts: Parts<S, R>,
    mut tcp: TcpStream,
    cancel: impl Future<Output = Reason>,
    meter: &impl Meter,
    framing: Option<&mut (dyn Framing + Send)>,
) -> Summary {
    let Parts { mut send, mut recv, role, class, started, reply_pending } = parts;
    // 直接搬的方向已经绕过流接口，仍需要和普通方向一样响应吊销。
    let revocation = recv.revocation();
    let cancel = cancel_on_revocation(cancel, revocation.clone());
    // 先设成"关闭时发 RST"。这个选项只管 close，中途用 shutdown 发的 FIN 不受影响。
    if let Err(error) = tcp.set_zero_linger() {
        tracing::warn!(%error, "设置 SO_LINGER 失败，转发中断时 TCP 侧可能视为正常关闭");
    }

    let mut from_tcp = Traffic::default();
    let mut from_flow = Traffic::default();
    // 流底下的 ice3proxy（交出来直接搬的话）。正常结束时它也要恢复正常关闭。
    let lane = OnceLock::new();
    let framed = framing.is_some();
    let outcome = {
        let (tcp_read, tcp_write) = tcp.split();
        let upstream = async {
            let progress = Progress { started, class, meter };
            match framing {
                Some(framing) => tcp_to_flow_framed(tcp_read, &mut send, &mut from_tcp, progress, framing).await,
                None => match send.take_raw() {
                    Some(raw) => tcp_to_raw(tcp_read, raw, Bytes::new(), &lane, &mut from_tcp, progress).await,
                    None => {
                        // 出口一侧：看目标回的是不是 TLS 1.3，是的话 ServerHello 之后不再加密。入口一侧：出口切换了就跟着。
                        let leave = match role {
                            TcpRole::Target => Leave::AfterServerHello(ServerHelloWatch::new()),
                            TcpRole::Client => Leave::AfterPeer,
                        };
                        tcp_to_flow(tcp_read, &mut send, leave, &lane, &mut from_tcp, progress).await
                    }
                },
            }
        };
        let downstream = flow_to_tcp(&mut recv, tcp_write, &mut from_flow, Progress { started, class, meter }, reply_pending, &lane);
        drive(upstream, downstream, cancel).await
    };
    // 分帧数据发完后发送方向保持开启（见 [`Flow::relay_framed`]），待双向均结束后再正常关闭。
    let outcome = match outcome {
        Ok(()) if framed => send.shutdown().await.map_err(Abort::Flow),
        outcome => outcome,
    };

    // 最后一次搬运和吊销可能并发完成，恢复正常关闭前再核对一次。
    let outcome =
        if revocation.as_ref().is_some_and(|state| *state.borrow()) { Err(Abort::Cancelled(Reason::AccessRevoked)) } else { outcome };

    let end = match outcome {
        Ok(()) => {
            // 两头写的一半都是用 `tcp_reset::shutdown_write` 关的：macOS 上那时已经改回了正常关闭（见 `i3t_underlay::tcp_reset`）。
            if let Err(error) = i3t_underlay::tcp_reset::graceful_close(&tcp) {
                tracing::warn!(%error, "禁用 SO_LINGER 失败，关闭连接时可能发送 RST");
            }
            if let Some(lane) = lane.get()
                && let Err(error) = i3t_underlay::tcp_reset::graceful_close(lane)
            {
                tracing::warn!(%error, "禁用 ice3proxy 的 SO_LINGER 失败，关闭流时可能发送 RST");
            }
            drop(tcp);
            End::Clean
        }
        Err(abort) => {
            let code = StreamCode(abort.reason(role).to_wire());
            send.reset(code);
            recv.stop(code);
            // 交出来直接搬的 ice3proxy 不归流管，上面两句碰不到它。它的一个方向可能已经正常结束过，macOS 上那时改回了
            // 正常关闭：这里重新设成关闭时发 RST，对端才知道流断了。
            // 两边刚写过数据时，macOS 上要留着 socket 等对端确认，见 `i3t_underlay::tcp_reset`。
            if let Some(lane) = lane.into_inner() {
                i3t_underlay::tcp_reset::close(lane);
            }
            i3t_underlay::tcp_reset::close(tcp);
            End::from(abort)
        }
    };
    Summary { from_tcp, from_flow, end }
}

/// 流的身份吊销和调用者取消一起监听。吊销优先于继续搬运。
pub(crate) async fn cancel_on_revocation(cancel: impl Future<Output = Reason>, revocation: Option<watch::Receiver<bool>>) -> Reason {
    let Some(revocation) = revocation else { return cancel.await };
    tokio::select! {
        biased;
        () = wait_revoked(revocation) => Reason::AccessRevoked,
        reason = cancel => reason,
    }
}

/// 同时跑两个方向，决定整次搬运的结局。
///
/// 一个方向正常结束时，另一个方向继续（半关闭）。一个方向异常结束时，整次搬运立刻结束。
/// 例外是 `upstream` 被对端叫停：这只说明对端不再读了，原因在另一个方向上（对端拒绝时那里是 REPLY，
/// 对端异常结束时那里是重置），所以等 `downstream` 给出结局；它要是正常结束，才把"被叫停"当作结局。
async fn drive(
    upstream: impl Future<Output = Result<(), Abort>>,
    downstream: impl Future<Output = Result<(), Abort>>,
    cancel: impl Future<Output = Reason>,
) -> Result<(), Abort> {
    enum Upstream {
        Running,
        Finished,
        Stopped(Abort),
    }

    tokio::pin!(upstream, downstream, cancel);
    let mut up = Upstream::Running;
    let mut down_finished = false;
    loop {
        tokio::select! {
            biased;
            reason = &mut cancel => return Err(Abort::Cancelled(reason)),
            end = &mut downstream, if !down_finished => {
                end?;
                down_finished = true;
            }
            end = &mut upstream, if matches!(up, Upstream::Running) => {
                up = match end {
                    Ok(()) => Upstream::Finished,
                    Err(abort) if abort.is_stop() && !down_finished => Upstream::Stopped(abort),
                    Err(abort) => return Err(abort),
                };
            }
        }
        if down_finished {
            match up {
                Upstream::Running => {}
                Upstream::Finished => return Ok(()),
                Upstream::Stopped(abort) => return Err(abort),
            }
        }
    }
}

/// 一个方向搬运时要知道的事。
struct Progress<'m, M> {
    /// 首字节时间从这个时刻算起。
    started: Instant,
    class: Class,
    meter: &'m M,
}

/// 往对端节点写的这个方向什么时候可能不再加密（流在 ice3proxy 上、发起方选了不再加密时才会）。
enum Leave {
    /// 出口一侧：目标回的 TLS 1.3 ServerHello 一写完就由这一端告诉流（[`SendStream::end_header`]）。
    AfterServerHello(ServerHelloWatch),
    /// 入口一侧：出口先切换，流收到时自己跟着切换（读的那一侧在推进），这里每一段之前问一下（[`SendStream::take_raw`]）。
    AfterPeer,
    /// 不会了。
    Never,
}

/// TCP 读到的写进流。
///
/// 流交得出原始的 socket 时（`leave` 说什么时候），剩下的交给 [`tcp_to_raw`]。流不在 ice3proxy 上、发起方没选不再加密、
/// 目标回的不是 TLS 1.3 时照样写进流。
async fn tcp_to_flow<S: SendStream, M: Meter>(
    mut tcp: ReadHalf<'_>,
    send: &mut S,
    mut leave: Leave,
    lane: &OnceLock<Arc<TcpStream>>,
    traffic: &mut Traffic,
    progress: Progress<'_, M>,
) -> Result<(), Abort> {
    let Progress { started, class, meter } = progress;
    let mut buf = vec![0; buffer_len()];
    let mut demotable = class == Class::Auto;
    loop {
        let len = tcp.read(&mut buf).await.map_err(Abort::Tcp)?;
        if len == 0 {
            return send.shutdown().await.map_err(Abort::Flow);
        }
        traffic.arrived(started);
        if matches!(leave, Leave::AfterPeer)
            && let Some(raw) = send.take_raw()
        {
            let rest = Bytes::copy_from_slice(&buf[..len]);
            // 同下：不能让这块缓冲跟着 `tcp_to_raw` 一直占到连接结束。
            drop(buf);
            return tcp_to_raw(tcp, raw, rest, lane, traffic, Progress { started, class, meter }).await;
        }
        let verdict = match &mut leave {
            Leave::AfterServerHello(watch) => watch.feed(&buf[..len]),
            Leave::AfterPeer | Leave::Never => ServerHelloVerdict::Undecided,
        };
        let switch_at = match verdict {
            ServerHelloVerdict::Undecided => None,
            ServerHelloVerdict::Sealed => {
                leave = Leave::Never;
                None
            }
            ServerHelloVerdict::PassthroughAfter(at) => {
                leave = Leave::Never;
                Some(at)
            }
        };
        let sealed = switch_at.unwrap_or(len);
        deliver(send, meter, traffic, &buf[..sealed]).await?;
        if switch_at.is_some() {
            send.end_header(Payload::Passthrough);
            if let Some(raw) = send.take_raw() {
                let rest = Bytes::copy_from_slice(&buf[sealed..len]);
                // 切换为透传后不再需要此缓冲区，提前释放以避免在 `tcp_to_raw` 期间持续占用内存。
                drop(buf);
                return tcp_to_raw(tcp, raw, rest, lane, traffic, Progress { started, class, meter }).await;
            }
            deliver(send, meter, traffic, &buf[sealed..len]).await?;
        }
        if demotable && traffic.bytes > AUTO_DEMOTE_AFTER {
            // 这条流原来是在传大块的数据：往后让交互的流先走。
            send.set_priority(priority_of(Class::Bulk));
            demotable = false;
        }
    }
}

/// 把从 TCP 读到的一段写进流：先过关卡，写完再记数。
async fn deliver<S: SendStream, M: Meter>(send: &mut S, meter: &M, traffic: &mut Traffic, bytes: &[u8]) -> Result<(), Abort> {
    if bytes.is_empty() {
        return Ok(());
    }
    meter.pass(Direction::FromTcp, bytes.len()).await.map_err(Abort::Cancelled)?;
    send.write_all(bytes).await.map_err(Abort::Flow)?;
    traffic.delivered(bytes.len());
    Ok(())
}

/// 仅将 `framing` 界定的消息片段从 TCP 转发至流。片段完整后即返回，不继续读取 TCP 剩余数据，也不关闭流发送方向（由 [`run`] 在最后关闭）。
async fn tcp_to_flow_framed<S: SendStream, M: Meter>(
    mut tcp: ReadHalf<'_>,
    send: &mut S,
    traffic: &mut Traffic,
    progress: Progress<'_, M>,
    framing: &mut (dyn Framing + Send),
) -> Result<(), Abort> {
    let Progress { started, class, meter } = progress;
    let mut buf = vec![0; buffer_len()];
    let mut demotable = class == Class::Auto;
    while !framing.is_complete() {
        let read = tcp.read(&mut buf).await.map_err(Abort::Tcp)?;
        if read == 0 {
            return Err(Abort::Tcp(io::Error::new(io::ErrorKind::UnexpectedEof, "TCP 连接在当前分帧尚未完整时关闭")));
        }
        traffic.arrived(started);
        let len = framing.take(&buf[..read]).map_err(Abort::Cancelled)?;
        if len == 0 {
            continue;
        }
        meter.pass(Direction::FromTcp, len).await.map_err(Abort::Cancelled)?;
        send.write_all(&buf[..len]).await.map_err(Abort::Flow)?;
        traffic.delivered(len);
        if demotable && traffic.bytes > AUTO_DEMOTE_AFTER {
            send.set_priority(priority_of(Class::Bulk));
            demotable = false;
        }
    }
    Ok(())
}

async fn flow_to_tcp<R: RecvStream, M: Meter>(
    recv: &mut R,
    mut tcp: WriteHalf<'_>,
    traffic: &mut Traffic,
    progress: Progress<'_, M>,
    reply_pending: bool,
    lane: &OnceLock<Arc<TcpStream>>,
) -> Result<(), Abort> {
    let Progress { started, meter, .. } = progress;
    if reply_pending {
        match header::read_reply(recv).await {
            Ok(reply) if reply.status.is_ok() => {}
            Ok(reply) => return Err(Abort::Refused(reply)),
            // 流本身出错（被重置、连接断开）和 REPLY 的内容不对是两回事。
            Err(FlowError::Read(error)) => return Err(Abort::Flow(error)),
            Err(error) => return Err(Abort::BadReply(error)),
        }
    }
    // 初始即透传的方向（出口接收发起方数据）无需缓冲区：先检查切换状态，避免多余分配。
    if let Some(raw) = recv.wait_raw().await {
        return raw_to_tcp(raw, tcp, lane, traffic, progress).await;
    }
    let mut buf = vec![0; buffer_len()];
    loop {
        // 对端可能先加密地送一段、之后才切换（出口要先把目标的 ServerHello 加密地送回来）：每一段之前都问一下。
        if let Some(raw) = recv.wait_raw().await {
            // 切换为透传后不再需要此缓冲区，提前释放以避免在 `raw_to_tcp` 期间持续占用内存。
            drop(buf);
            return raw_to_tcp(raw, tcp, lane, traffic, progress).await;
        }
        let len = recv.read(&mut buf).await.map_err(Abort::Flow)?;
        if len == 0 {
            // 不用 `tcp.shutdown()`：TCP 设着关闭时发 RST，macOS 上要赶在发 FIN 之前改回正常关闭（见 `i3t_underlay::tcp_reset`）。
            return i3t_underlay::tcp_reset::shutdown_write(tcp.as_ref()).map_err(Abort::Tcp);
        }
        traffic.arrived(started);
        meter.pass(Direction::FromFlow, len).await.map_err(Abort::Cancelled)?;
        tcp.write_all(&buf[..len]).await.map_err(Abort::Tcp)?;
        traffic.delivered(len);
    }
}

/// 一个进程一个搬运引擎，管道池在里面。
static ENGINE: LazyLock<Splicer> = LazyLock::new(Splicer::new);

/// 不再加密的 ice3proxy 上的搬运，每一段之前过 [`Meter`]，顺带记首字节时间、告诉底下的传输搬了多少。
struct MeterGate<'a, M> {
    meter: &'a M,
    direction: Direction,
    started: Instant,
    first_byte: &'a mut Option<Duration>,
    counter: Counter<'a>,
}

/// 搬了多少要告诉谁：ice3proxy 的哪一个方向。
enum Counter<'a> {
    Write(&'a RawWrite),
    Read(&'a RawRead),
}

impl<M: Meter> Gate for MeterGate<'_, M> {
    type Stop = Reason;

    async fn pass(&mut self, len: usize) -> Result<(), Reason> {
        let started = self.started;
        self.first_byte.get_or_insert_with(|| started.elapsed());
        self.meter.pass(self.direction, len).await?;
        match self.counter {
            Counter::Write(raw) => raw.moved(len),
            Counter::Read(raw) => raw.moved(len),
        }
        Ok(())
    }
}

/// TCP 读到的，直接写进不再加密的 ice3proxy。`rest` 是已经从 TCP 读出来、还没写出去的用户字节，最先写。
async fn tcp_to_raw<M: Meter>(
    tcp: ReadHalf<'_>,
    raw: RawWrite,
    rest: Bytes,
    lane: &OnceLock<Arc<TcpStream>>,
    traffic: &mut Traffic,
    progress: Progress<'_, M>,
) -> Result<(), Abort> {
    let Progress { started, meter, .. } = progress;
    // 两个方向交出来的是同一条 ice3proxy，另一个方向先记下了的话这里不用再记。
    let _ = lane.set(raw.socket_handle());
    // 开流时还没交给内核的那一截密文不是用户的字节：先原样写出去，不计数、不过关卡。
    write_all(raw.socket(), raw.unsent()).await.map_err(Abort::Flow)?;
    let mut moved = 0;
    let mut gate =
        MeterGate { meter, direction: Direction::FromTcp, started, first_byte: &mut traffic.first_byte, counter: Counter::Write(&raw) };
    let pumped = ENGINE.pump(tcp.as_ref(), raw.socket(), rest, &mut gate, &mut moved).await;
    traffic.bytes += moved;
    pumped.map_err(|error| match error {
        PumpError::Read(error) => Abort::Tcp(error),
        PumpError::Write(error) => Abort::Flow(error),
        PumpError::Stopped(reason) => Abort::Cancelled(reason),
    })
}

/// 不再加密的 ice3proxy 上收到的，直接写进 TCP。
async fn raw_to_tcp<M: Meter>(
    raw: RawRead,
    tcp: WriteHalf<'_>,
    lane: &OnceLock<Arc<TcpStream>>,
    traffic: &mut Traffic,
    progress: Progress<'_, M>,
) -> Result<(), Abort> {
    let Progress { started, meter, .. } = progress;
    // 两个方向交出来的是同一条 ice3proxy，另一个方向先记下了的话这里不用再记。
    let _ = lane.set(raw.socket_handle());
    let received = Bytes::copy_from_slice(raw.received());
    let mut moved = 0;
    let mut gate =
        MeterGate { meter, direction: Direction::FromFlow, started, first_byte: &mut traffic.first_byte, counter: Counter::Read(&raw) };
    let pumped = ENGINE.pump(raw.socket(), tcp.as_ref(), received, &mut gate, &mut moved).await;
    traffic.bytes += moved;
    pumped.map_err(|error| match error {
        PumpError::Read(error) => Abort::Flow(error),
        PumpError::Write(error) => Abort::Tcp(error),
        PumpError::Stopped(reason) => Abort::Cancelled(reason),
    })
}

/// 把 `bytes` 全部写给 `to`。
async fn write_all(to: &TcpStream, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        to.writable().await?;
        match to.try_write(bytes) {
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
