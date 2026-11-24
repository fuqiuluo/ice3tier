//! 一条 lane 上的一条流：[`LaneSend`] 和 [`LaneRecv`]，实现连接层契约里的 [`SendStream`] 和 [`RecvStream`]。
//!
//! # 两种负载方式
//!
//! 每个方向开始时都在 lane 的 TLS 里面（帧见 crate 文档）。发起方在头写完时（[`LaneSend::end_header`]）选定负载方式：
//!
//! - sealed：两个方向一直在 TLS 里，数据是 DATA 帧，正常结束是 close_notify 加 FIN。没有 close_notify 的 FIN 是截断，按异常结束算。
//! - passthrough：每个方向在自己的 SWITCH 所在的记录之后离开 TLS。接受方在 REPLY 之后、确认可以不再加密时调
//!   [`LaneSend::end_header`] 发出它的（流层是在目标的 TLS 1.3 ServerHello 之后）；发起方收到它时回一个，自己的方向跟着离开
//!   （[`Mode::Mutual`]）。若接受方未发送，双向保持在 TLS 内，对端仍可正常解析：当目标返回 HelloRetryRequest、TLS 1.2
//!   或非 TLS 响应时，客户端后续发送的数据（第二个 ClientHello、客户端证书、明文）仍受加密保护（issue #34）。
//!   退出 TLS 后传输用户原始字节，以 FIN 表示正常结束，以 RST 或错误表示异常结束。
//!
//! 对端为未升级节点（lane 协商版本为 `i3t-lane/1`）时，本端发起的流一律采用 sealed 模式：对端不支持等待 SWITCH。
//! 那边发起的 passthrough 流照旧：它的方向在 OPENING 所在的记录之后就离开 TLS（[`Mode::Early`]），只有接受方发 SWITCH。
//!
//! 流层的头（OPEN、REPLY）决定连谁、连上了没有，只能来自认证过的对端，所以它们必须完整地在 TLS 里：
//! 接收方在读完对端流头（[`RecvStream::end_header`]）前，仅交付 TLS 内收到的字节；若对端在流头尚未读完时便退出 TLS，
//! 读取将报错（对端违反协议），不会将后续未经认证的原始字节拼入流头。
//!
//! # 异常结束
//!
//! lane 是一整条只属于这条流的 TCP，所以任何一个方向的异常结束都让整条 lane 异常结束：
//!
//! | 本端做了什么 | 对端看到什么 |
//! |---|---|
//! | [`SendStream::reset`]，这个方向还在 TLS 里 | ABORT 帧（带原因码），随后 FIN；两个方向都丢弃之后等对端关掉再关，那时发 RST |
//! | [`SendStream::reset`]，这个方向已经是原始字节 | RST（Linux 上立刻发，别处在关闭时） |
//! | [`RecvStream::stop`]，本端发送方向仍在 TLS 内 | STOP 帧（带原因码），对端此后的写入、flush 与 shutdown 均失败；lane 不断开，本端发送继续 |
//! | [`RecvStream::stop`]，本端的发送方向已经不在 TLS 里 | RST |
//! | 没有 `shutdown` 就丢弃发送方向 | 同 `reset` |
//!
//! lane 从开流起就设成"关闭时发 RST"，只有两个方向都正常结束才改回去，所以任务被取消、进程退出也一样。
//! macOS 上会在发送方向正常关闭、发送 FIN 时即恢复正常关闭：该平台在双向关闭后无法再修改 `SO_LINGER`（见 `i3t_underlay::tcp_reset`）。
//! 收到的 RST 在读写时是一个不带原因码的连接错误（分不清是对端重置了流，还是路上断了），ABORT 帧是带原因码的
//! [`StreamAborted::Reset`]，STOP 帧让本端此后的写入、flush 与 shutdown 均返回 [`StreamAborted::Stopped`]（ABORT 帧同样如此）：
//! 对端已不再读取，此前写入的数据未必全部送达，不能按正常结束处理，该方向也不再离开 TLS。已正常结束的方向不受影响。
//!
//! 发了 ABORT 帧的一端不在丢弃时马上关：Windows 收到 RST 时把还没读走的数据扔掉，紧跟在 ABORT 后面的 RST
//! 会让对端连 ABORT 和原因码一起丢掉。所以它先发 FIN，把对端还在路上的数据收下扔掉，等对端关掉（最多
//! [`LINGER_AFTER_STOP`]）再关。ABORT 后面的 FIN 不会被当成正常结束：sealed 的方向上正常结束要有 close_notify。
//!
//! # 写不需要 flush
//!
//! 流层是照 QUIC 的流写的，不调 `flush`。所以 [`LaneSend`] 返回"写进去了"之后，密文要么已经交给内核，
//! 要么由一个短命的后台任务等 socket 可写时送出，不会停在缓冲区里等下一次写。

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use i3t_conn::contract::wait_revoked;
use i3t_conn::{Payload, RawRead, RawWrite, RecvStream, SendStream, StreamAborted, StreamCode};
use i3t_proto::NodeId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, watch};

use crate::frame::{Frame, MAX_DATA_LEN, MAX_HEADER_LEN, Mode, data_header};
use crate::lane::{Lane, Version};
use crate::sealed::{Next, Sealed};
use crate::socket;
use crate::status::{Book, Gauge};

/// 发送方向没有正常结束就被丢弃时，对端看到的原因码。和 QUIC 的实现取同一个数。
const DROPPED_SEND: StreamCode = StreamCode(u32::MAX);
/// 接收方向没读完就被丢弃时，对端看到的原因码。同上。
const DROPPED_RECV: StreamCode = StreamCode(0);

/// 一次从 socket 读多少（sealed 的方向）。
const READ_CHUNK: usize = 64 * 1024;

/// 本端叫停了对端、自己这一侧已经正常写完，或者本端发了 ABORT 帧时，关闭之前最多再收多久（收到就扔）：
/// 关闭时接收缓冲里还有没读的数据，内核会发 RST 并丢掉还没发出去的数据，刚写完的 REPLY 可能就此丢了；
/// 对端是 Windows 时，它收到 RST 也会丢掉还没读走的 ABORT。
const LINGER_AFTER_STOP: Duration = Duration::from_secs(5);

/// 这一端在流里是哪一方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

type RevocationWait = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;

/// 一条流的发送方向。实现 [`SendStream`]。
pub struct LaneSend {
    shared: Arc<Shared>,
    wait_revoked: RevocationWait,
}

/// 一条流的接收方向。实现 [`RecvStream`]。
pub struct LaneRecv {
    shared: Arc<Shared>,
    wait_revoked: RevocationWait,
}

impl fmt::Debug for LaneSend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaneSend").field("peer", &self.shared.peer).finish_non_exhaustive()
    }
}

impl fmt::Debug for LaneRecv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaneRecv").field("peer", &self.shared.peer).finish_non_exhaustive()
    }
}

struct Shared {
    socket: Arc<TcpStream>,
    peer: NodeId,
    state: Mutex<State>,
    revoked: watch::Receiver<bool>,
    /// 两个方向都被丢弃了：后台的发送任务不用再等。
    closed: Notify,
    book: Book,
    _in_use: [Gauge; 2],
}

impl Shared {
    fn is_revoked(&self) -> bool {
        *self.revoked.borrow()
    }

    fn check_revoked(&self, wait: &mut RevocationWait, cx: &mut Context<'_>) -> io::Result<()> {
        if self.is_revoked() || wait.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "对端 lane 授权已吊销"));
        }
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("lane stream mutex poisoned")
    }
}

enum SendState {
    /// 发起方还在写头（OPEN 连同首批数据），攒在这里，头写完时作为一个 OPENING 帧发出。
    Header(Vec<u8>),
    Sealed,
    Raw,
    /// 已经开始正常结束：close_notify（sealed 时）已经排进待发的密文，等它们发完再发 FIN。
    Closing,
    Finished,
    Aborted,
    /// 已经用 [`LaneSend::take_raw`] 交出去了。
    Handed,
}

enum RecvState {
    /// 在 TLS 里，里面是收到了、还没交出去的数据。
    Sealed(Bytes),
    /// 对端发送方向已退出 TLS，本端尚未读完对端流头（[`RecvStream::end_header`]）。`sealed` 为 TLS 内已收到但尚未交付的尾部字节，
    /// `raw` 为其后已从 socket 读入的原始字节。此时仅交付 `sealed`：若 `sealed` 耗尽而流头仍未结束，则属于对端违反协议，
    /// 不能使用未经认证的原始字节补全流头。流头读完后合并为 [`RecvState::Raw`]。
    Leaving {
        sealed: Bytes,
        raw: Bytes,
    },
    /// 原始字节，里面是已经从 socket 读进来、还没交出去的部分。
    Raw(Bytes),
    Eof,
    /// 本端叫停了，之后收到的都扔掉。
    Stopped,
    Failed(Failure),
    Handed,
}

/// 接收方向异常结束的原因。`io::Error` 不能复制，这里存够重建它的东西。
#[derive(Debug, Clone)]
enum Failure {
    Reset(StreamCode),
    Protocol(String),
    Truncated,
    Io(io::ErrorKind, String),
}

impl Failure {
    fn to_io(&self) -> io::Error {
        match self {
            Self::Reset(code) => StreamAborted::Reset(*code).into(),
            Self::Protocol(what) => io::Error::new(io::ErrorKind::InvalidData, format!("lane 对端违反协议：{what}")),
            Self::Truncated => io::Error::new(io::ErrorKind::UnexpectedEof, "lane 在收到 close_notify 前关闭，数据被截断"),
            Self::Io(kind, message) => io::Error::new(*kind, message.clone()),
        }
    }

    fn of(error: &io::Error) -> Self {
        Self::Io(error.kind(), error.to_string())
    }
}

struct State {
    role: Role,
    /// 这条流的负载方式。发起方在头写完之前还没定。
    mode: Option<Mode>,
    /// lane 谈定的版本。发起方按它选负载方式。
    version: Version,
    /// 本端发过 SWITCH。接受方要先发过，才收得了发起方的 SWITCH（那是回应）。
    switched: bool,
    /// TLS 状态。两个方向都离开 TLS 之后就扔掉，静默的 passthrough 流不再占它的内存。
    sealed: Option<Sealed>,
    /// 待发的密文。
    out: BytesMut,
    send: SendState,
    recv: RecvState,
    /// 本端已读完对端流头（已调用 [`RecvStream::end_header`] 或移交原始接收方向）：此后接收方向离开 TLS 时可继续读取原始字节。
    header_read: bool,
    /// 对端叫停了本端的发送（STOP），或者异常结束了整条流（ABORT）：本端此后的写入、flush 与 shutdown 均返回它（[`State::check_refused`]）。
    send_refused: Option<StreamAborted>,
    /// 写入、flush 或 shutdown 正在等待的任务。对端叫停时要叫醒它，不然它会一直等一个不会再变得可写的 socket。
    send_waker: Option<Waker>,
    /// 后台送出任务（[`flush_later`]）正在运行：[`push`] 未能将待发密文全部写入内核时不再启动新任务。仅由该任务在持锁确认退出时清除。
    flushing: bool,
    halves: u8,
    raw_taken: bool,
    /// 本端或对端异常结束了这条流：关闭时发 RST。
    aborted: bool,
    /// 本端用 ABORT 帧重置了发送方向，这个帧已经全部交给了内核：关闭之前要等对端读到它（[`close_after_abort`]）。
    abort_sent: bool,
    heard_from_peer: bool,
    /// 向 socket 写入时曾发生错误：连接已断开，通常由对端重置引起。Linux 上一次重置仅上报一次错误，若被写操作消费则读操作只会看到 EOF，
    /// 所以记在这里：之后读到 EOF 时按它异常结束，不当作对端正常结束了（见 [`State::drain_now`]）。
    write_failed: Option<Failure>,
}

impl LaneSend {
    /// 对端节点。
    #[must_use]
    pub fn peer(&self) -> NodeId {
        self.shared.peer
    }
}

impl LaneRecv {
    pub(crate) fn is_revoked(&self) -> bool {
        self.shared.is_revoked()
    }

    /// 这个方向已经离开 TLS 时，把它交出去，让调用方直接读 socket（见 [`RawRead`]）。还在 TLS 里、已经结束或者已经交出去时返回 `None`；
    /// 若本端仍有待发密文尚未写入内核（如刚响应对端 SWITCH），或写操作已检测到连接断开，同样返回 `None`，由调用方继续正常读取。
    /// 不等待；要等对端的切换用 [`RecvStream::wait_raw`]。
    ///
    /// 交出去之后这个 [`LaneRecv`] 不再能读，丢弃它也不会叫停流。
    ///
    /// 已经收到、还没处理的记录先处理掉（不等待）：接受方的 REPLY 和 SWITCH 往往一起到，读完 REPLY 时 SWITCH 已经在缓冲里了。
    ///
    /// 要原始字节说明调用方已经读完了对端的头：交得出来时同时算作 [`RecvStream::end_header`]。
    pub fn take_raw(&mut self) -> Option<RawRead> {
        let shared = &self.shared;
        let mut state = shared.lock();
        if shared.is_revoked() {
            return None;
        }
        while matches!(&state.recv, RecvState::Sealed(data) if data.is_empty()) {
            if !matches!(state.poll_sealed_step(&shared.socket, Read::Now), Poll::Ready(Ok(()))) {
                break;
            }
        }
        if matches!(state.recv, RecvState::Leaving { .. }) {
            state.finish_header();
        }
        if !state.out.is_empty() {
            push(shared, &mut state);
        }
        // 写的时候已经知道连接断了：交出去的话，搬运的一方读到的只是 EOF。留在这里读，读到 EOF 时报那个错误。
        // 待发的密文（比如回应对端的 SWITCH）还没全部交给内核时也不交：之后由后台任务去写（[`flush_later`]），它撞上对端的
        // 重置时拿走的那个错误（Linux 上只报一次）就只记在这里，交出去的接收方向读到的又只是 EOF。排空之后下一次再交。
        if state.write_failed.is_some() || !state.out.is_empty() {
            return None;
        }
        let RecvState::Raw(pending) = &mut state.recv else { return None };
        let received = std::mem::take(pending);
        state.recv = RecvState::Handed;
        state.raw_taken = true;
        state.drop_tls_if_unused();
        Some(RawRead::new(Arc::clone(&shared.socket), received, shared.book.spliced()).with_revocation(shared.revoked.clone()))
    }

    /// 这条流的负载方式。发起方在头写完之前是 `None`。
    #[must_use]
    pub fn payload(&self) -> Option<Payload> {
        self.shared.lock().mode.map(Mode::payload)
    }
}

/// 把一条刚取到的 lane 变成本端发起的一条流。
pub(crate) fn initiate(lane: Lane, book: Book, revoked: watch::Receiver<bool>) -> (LaneSend, LaneRecv) {
    let Lane { socket, mut sealed, out, peer, version, .. } = lane;
    sealed.shrink();
    socket::rst_on_close(&socket);
    socket::set_user_timeout(&socket, socket::OPENING_USER_TIMEOUT);
    let state = State {
        role: Role::Initiator,
        mode: None,
        version,
        switched: false,
        sealed: Some(sealed),
        out,
        send: SendState::Header(Vec::new()),
        recv: RecvState::Sealed(Bytes::new()),
        header_read: false,
        send_refused: None,
        send_waker: None,
        flushing: false,
        halves: 2,
        raw_taken: false,
        aborted: false,
        abort_sent: false,
        heard_from_peer: false,
        write_failed: None,
    };
    split(socket, peer, state, book, revoked)
}

/// 对端在一条 lane 上开过来的流：它的 OPENING 已经读到了，`header` 是里面流的头。
///
/// [`Mode::Early`] 时 OPENING 所在的记录之后就是原始字节，调用方已经确认这条记录在这个帧的末尾结束。
/// 流层的 OPEN 只能从 `header` 中读取，在流头读完前不会继续读取后续原始字节（[`RecvState::Leaving`]）。
pub(crate) fn respond(lane: Lane, mode: Mode, header: &[u8], book: Book, revoked: watch::Receiver<bool>) -> (LaneSend, LaneRecv) {
    let Lane { socket, mut sealed, out, peer, version, .. } = lane;
    socket::rst_on_close(&socket);
    socket::set_user_timeout(&socket, socket::STREAM_USER_TIMEOUT);
    let recv = match mode {
        Mode::Sealed | Mode::Mutual => RecvState::Sealed(compact(header)),
        Mode::Early => RecvState::Leaving { sealed: compact(header), raw: compact(&sealed.take_inbound()) },
    };
    let state = State {
        role: Role::Responder,
        mode: Some(mode),
        version,
        switched: false,
        sealed: Some(sealed),
        out,
        send: SendState::Sealed,
        recv,
        header_read: false,
        send_refused: None,
        send_waker: None,
        flushing: false,
        halves: 2,
        raw_taken: false,
        aborted: false,
        abort_sent: false,
        heard_from_peer: true,
        write_failed: None,
    };
    split(socket, peer, state, book, revoked)
}

fn split(socket: Arc<TcpStream>, peer: NodeId, state: State, book: Book, revoked: watch::Receiver<bool>) -> (LaneSend, LaneRecv) {
    let shared = Arc::new(Shared {
        socket,
        revoked,
        peer,
        state: Mutex::new(state),
        closed: Notify::new(),
        _in_use: book.enter(|tally| &tally.in_use),
        book,
    });
    let send = LaneSend { shared: Arc::clone(&shared), wait_revoked: Box::pin(wait_revoked(shared.revoked.clone())) };
    let recv = LaneRecv { wait_revoked: Box::pin(wait_revoked(shared.revoked.clone())), shared };
    (send, recv)
}

impl State {
    fn end_header(&mut self, payload: Payload) {
        match (&mut self.send, self.role) {
            (SendState::Header(header), Role::Initiator) => {
                let header = Bytes::from(std::mem::take(header));
                // 未升级的接受方不支持等待 SWITCH，其 passthrough 只能在 OPENING 后立即离开 TLS；本端不再采用该模式，见 [`Mode::Early`]。
                let mode = match (payload, self.version) {
                    (Payload::Passthrough, Version::V2) => Mode::Mutual,
                    (Payload::Passthrough, Version::V1) | (Payload::Sealed, _) => Mode::Sealed,
                };
                self.mode = Some(mode);
                let sealed = self.sealed.as_mut().expect("头还没发出去时 TLS 状态一定还在");
                sealed.seal_frame(&Frame::Opening { mode, header });
                sealed.take_output(&mut self.out);
                self.send = SendState::Sealed;
            }
            // 已被对端叫停的方向不再离开 TLS：此后的写入均会失败，切换已无意义。
            (SendState::Sealed, Role::Responder)
                if payload == Payload::Passthrough && self.mode.is_some_and(|mode| mode != Mode::Sealed) && self.send_refused.is_none() =>
            {
                self.switch();
            }
            _ => {}
        }
    }

    /// 发 SWITCH：这个方向在它所在的记录之后离开 TLS。调用方确认过这个方向还在 TLS 里（[`SendState::Sealed`]）。
    fn switch(&mut self) {
        let sealed = self.sealed.as_mut().expect("sealed 的方向一定还有 TLS 状态");
        sealed.seal_frame(&Frame::Switch);
        sealed.take_output(&mut self.out);
        self.send = SendState::Raw;
        self.switched = true;
        self.drop_tls_if_unused();
    }

    /// 现在收到对端的 SWITCH 合不合协议。只有 [`Mode::Mutual`] 的流上会有：接受方的随时可以来（本端发起的流不再用 [`Mode::Early`]），
    /// 发起方的只能是对本端那个的回应。
    fn expects_switch(&self) -> bool {
        self.mode == Some(Mode::Mutual) && (self.role == Role::Initiator || self.switched)
    }

    /// 本端已读完对端流头：此后可从 TLS 缓冲字节无缝衔接读取后续原始字节。
    ///
    /// 发起方此时若已收到接受方的 SWITCH（接受方检查目标响应后先期切换），则回发 SWITCH，使本端发送方向同步退出 TLS。
    /// 必须等待流头读完：接受方在 REPLY 尚未结束时切换属于违反协议，此时不跟随切换，发送方向保持在 TLS 内，以便重置时通过 ABORT 携带原因码。
    /// 已处于关闭或重置流程、或已被对端叫停的方向亦不跟随切换（叫停了本端的接受方不再读取，无须回应）。
    /// 回应帧排入待发密文缓冲区，由调用方随后写出（[`push`]）。
    fn finish_header(&mut self) {
        self.header_read = true;
        if let RecvState::Leaving { sealed, raw } = &mut self.recv {
            let pending = match (sealed.is_empty(), raw.is_empty()) {
                (true, _) => std::mem::take(raw),
                (false, true) => std::mem::take(sealed),
                (false, false) => compact(&[&sealed[..], &raw[..]].concat()),
            };
            self.recv = RecvState::Raw(pending);
            // 发起方的接收方向只会因为接受方的 SWITCH 离开 TLS（[`Mode::Mutual`]）；接受方的（没升级的发起方、或者发起方的回应）不用回。
            if self.role == Role::Initiator && matches!(self.send, SendState::Sealed) && self.send_refused.is_none() {
                self.switch();
            }
        }
    }

    /// 两个方向都不再需要 TLS 时扔掉它。
    fn drop_tls_if_unused(&mut self) {
        let send_needs = matches!(self.send, SendState::Header(_) | SendState::Sealed);
        let recv_needs = matches!(self.recv, RecvState::Sealed(_));
        if !send_needs && !recv_needs {
            self.sealed = None;
        }
    }

    /// 尽量把待发的密文交给内核，不等待。全部交完返回 `true`。
    ///
    /// 写入出错时记录原因（[`State::write_failed`]）：此处写入有时由读侧顺带触发（响应对端 SWITCH）或在后台执行，
    /// 错误没有人接，读的那一侧却要靠它知道连接是被重置的。
    fn drain_now(&mut self, socket: &TcpStream) -> io::Result<bool> {
        while !self.out.is_empty() {
            match socket.try_write(&self.out) {
                Ok(written) => self.out.advance(written),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => {
                    self.write_failed.get_or_insert_with(|| Failure::of(&error));
                    return Err(error);
                }
            }
        }
        if self.out.capacity() > 0 {
            self.out = BytesMut::new();
        }
        Ok(true)
    }

    /// 对端已叫停本端发送方向（[`State::send_refused`]）且该方向尚未正常结束时，返回叫停的原因。
    ///
    /// 已正常结束的方向不受影响：结束前写入的数据均已交给内核，close_notify 与 FIN 也已发出，与其他流实现一致。
    fn check_refused(&self) -> io::Result<()> {
        match self.send_refused {
            Some(refused) if !matches!(self.send, SendState::Finished) => Err(refused.into()),
            _ => Ok(()),
        }
    }

    /// 把待发的密文交给内核，交不完就等 socket 可写。
    ///
    /// 对端叫停本端发送方向后不再等待，直接返回叫停的原因：对端已不再读取，socket 可能不会再变为可写。
    fn poll_drain(&mut self, socket: &TcpStream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            self.check_refused()?;
            if self.drain_now(socket)? {
                return Poll::Ready(Ok(()));
            }
            self.send_waker = Some(cx.waker().clone());
            ready!(socket.poll_write_ready(cx))?;
        }
    }

    /// 第一次听到对端（发起方开流之后）：确认 lane 是活的，换成流里的 `TCP_USER_TIMEOUT`。
    fn heard(&mut self, socket: &TcpStream) {
        if !self.heard_from_peer {
            self.heard_from_peer = true;
            socket::set_user_timeout(socket, socket::STREAM_USER_TIMEOUT);
        }
    }

    fn fail_recv(&mut self, failure: Failure) -> io::Error {
        let error = failure.to_io();
        self.recv = RecvState::Failed(failure);
        self.aborted = true;
        error
    }

    fn wake_sender(&mut self) {
        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }
    }

    /// TLS 处理收到的记录时可能要回点什么（比如更新密钥）。本端的发送方向还在 TLS 里才发，否则扔掉：
    /// 原始字节的方向上不能插进 TLS 的字节。
    fn collect_tls_output(&mut self) {
        let Some(sealed) = self.sealed.as_mut() else { return };
        let in_tls = match self.send {
            SendState::Header(_) | SendState::Sealed => true,
            // 原始字节的方向结束时也经过 Closing（等待发的密文写完再发 FIN）。
            SendState::Closing => !self.switched,
            _ => false,
        };
        if in_tls {
            sealed.take_output(&mut self.out);
        } else {
            sealed.take_output(&mut BytesMut::new());
        }
    }

    /// sealed 的接收方向往前走一步：交出数据、处理一个帧，或者从 socket 读更多。
    fn poll_sealed_step(&mut self, socket: &TcpStream, read: Read<'_, '_>) -> Poll<io::Result<()>> {
        let sealed = self.sealed.as_mut().expect("sealed 的方向一定还有 TLS 状态");
        let next = sealed.next_frame();
        let at_boundary = sealed.at_record_boundary();
        self.collect_tls_output();
        match next {
            Ok(Next::Frame(Frame::Data(data))) => {
                self.heard(socket);
                self.recv = RecvState::Sealed(data);
            }
            Ok(Next::Frame(Frame::Switch)) => {
                if !self.expects_switch() || !at_boundary {
                    return Poll::Ready(Err(self.fail_recv(Failure::Protocol("非预期的 SWITCH 帧".to_owned()))));
                }
                self.heard(socket);
                let leftover = self.sealed.as_mut().map(Sealed::take_inbound).unwrap_or_default();
                // 流层的 REPLY 要在 SWITCH 之前完整地送到：还没读完它时，后面的原始字节先不交出去。
                self.recv = RecvState::Leaving { sealed: Bytes::new(), raw: compact(&leftover) };
                if self.header_read {
                    self.finish_header();
                }
                self.drop_tls_if_unused();
            }
            Ok(Next::Frame(Frame::Stop(code))) => {
                self.heard(socket);
                self.send_refused = Some(StreamAborted::Stopped(StreamCode(code)));
                self.wake_sender();
            }
            Ok(Next::Frame(Frame::Abort(code))) => {
                self.heard(socket);
                self.send_refused = Some(StreamAborted::Stopped(StreamCode(code)));
                self.wake_sender();
                return Poll::Ready(Err(self.fail_recv(Failure::Reset(StreamCode(code)))));
            }
            Ok(Next::Frame(other)) => {
                return Poll::Ready(Err(self.fail_recv(Failure::Protocol(format!("流上收到非预期帧 {other:?}")))));
            }
            Ok(Next::Closed) => {
                self.heard(socket);
                self.recv = RecvState::Eof;
                self.drop_tls_if_unused();
            }
            Ok(Next::More) => {
                let sealed = self.sealed.as_mut().expect("同上");
                sealed.inbound.reserve(READ_CHUNK);
                match socket.try_read_buf(&mut sealed.inbound) {
                    Ok(0) => return Poll::Ready(Err(self.fail_recv(Failure::Truncated))),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        sealed.shrink();
                        let Read::Wait(cx) = read else { return Poll::Pending };
                        ready!(socket.poll_read_ready(cx)).map_err(|error| self.fail_recv(Failure::of(&error)))?;
                    }
                    Err(error) => return Poll::Ready(Err(self.fail_recv(Failure::of(&error)))),
                }
            }
            Err(error) => return Poll::Ready(Err(self.fail_recv(Failure::Protocol(error.to_string())))),
        }
        Poll::Ready(Ok(()))
    }
}

/// 从 `data` 开头取出能放进 `buf` 的字节。取空了就换成一个空的 `Bytes`：
/// 切出来的 `Bytes` 和整块读缓冲共用内存，空着也会让那一整块（几十 KB）一直留着，几千条静默的流就是几百 MB。
fn take_into(data: &mut Bytes, buf: &mut ReadBuf<'_>) -> usize {
    let len = data.len().min(buf.remaining());
    buf.put_slice(&data.split_to(len));
    if data.is_empty() {
        *data = Bytes::new();
    }
    len
}

/// 切换成原始字节时多读进来的那一点，拷进一块大小正好的内存，不留着整块读缓冲。
fn compact(leftover: &[u8]) -> Bytes {
    if leftover.is_empty() { Bytes::new() } else { Bytes::copy_from_slice(leftover) }
}

/// 读取 socket 遇到 `WouldBlock` 时的处理策略。
enum Read<'a, 'b> {
    /// 登记这个任务，等 socket 可读。
    Wait(&'a mut Context<'b>),
    /// 不等，就此返回 `Pending`（不登记任何人）。
    Now,
}

/// 把待发的密文交给内核；交不完时让后台任务等 socket 可写再送，调用方不必再管。
fn push(shared: &Arc<Shared>, state: &mut State) {
    if shared.is_revoked() {
        return;
    }
    match state.drain_now(&shared.socket) {
        Ok(true) => {}
        Ok(false) => {
            if !state.flushing
                && let Ok(runtime) = tokio::runtime::Handle::try_current()
            {
                state.flushing = true;
                drop(runtime.spawn(flush_later(Arc::clone(shared))));
            }
        }
        // 写出错时连接已经坏了：下一次读写会看到错误，这里不用做什么。
        Err(error) => tracing::debug!(peer = %shared.peer, %error, "lane 密文发送失败"),
    }
}

/// 后台送出待发的密文。只在写的一方已经返回、没有人会再来推一把时才需要。
///
/// 退出的判定与清除 [`State::flushing`] 在同一次持锁内完成：若先释放锁再清除，期间 [`push`] 见其仍为真便不再启动新任务，
/// 此时排入的密文（如回应对端的 SWITCH、写入的最后一段数据）在本任务退出后无人送出，流将一直停滞。
async fn flush_later(shared: Arc<Shared>) {
    let revoked = wait_revoked(shared.revoked.clone());
    tokio::pin!(revoked);
    let mut give_up = false;
    loop {
        {
            let mut state = shared.lock();
            if give_up || shared.is_revoked() || state.halves == 0 || !matches!(state.drain_now(&shared.socket), Ok(false)) {
                state.flushing = false;
                state.wake_sender();
                return;
            }
        }
        // 下列任一情况发生时不再送出：流已吊销、两个句柄均已丢弃（此后不会再有 push）、runtime 正在关闭。
        give_up = tokio::select! {
            biased;
            () = &mut revoked => true,
            () = shared.closed.notified() => true,
            ready = shared.socket.writable() => ready.is_err(),
        };
    }
}

impl AsyncRead for LaneRecv {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let shared = &this.shared;
        let mut state = shared.lock();
        shared.check_revoked(&mut this.wait_revoked, cx)?;
        if state.role == Role::Initiator && matches!(state.send, SendState::Header(_)) {
            // 发起方开始等回复了，头一定已经写完。
            state.end_header(Payload::Sealed);
            push(shared, &mut state);
        }
        loop {
            match &mut state.recv {
                RecvState::Failed(failure) => return Poll::Ready(Err(failure.to_io())),
                RecvState::Eof => return Poll::Ready(Ok(())),
                RecvState::Stopped => return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "当前接收方向已中止"))),
                RecvState::Handed => return Poll::Ready(Err(io::Error::other("当前接收方向已移交调用方直接读取"))),
                RecvState::Sealed(data) if !data.is_empty() => {
                    let len = take_into(data, buf);
                    shared.book.add(|tally| &tally.sealed_bytes, len);
                    return Poll::Ready(Ok(()));
                }
                RecvState::Leaving { sealed, .. } if !sealed.is_empty() => {
                    let len = take_into(sealed, buf);
                    shared.book.add(|tally| &tally.sealed_bytes, len);
                    return Poll::Ready(Ok(()));
                }
                // 本端还在读对端的头，TLS 里的字节却已经读完了：头没有完整地在 TLS 里。
                RecvState::Leaving { .. } => {
                    return Poll::Ready(Err(state.fail_recv(Failure::Protocol("流头尚未完整，对端发送方向即离开 TLS".to_owned()))));
                }
                RecvState::Raw(pending) if !pending.is_empty() => {
                    let len = take_into(pending, buf);
                    shared.book.add(|tally| &tally.raw_bytes, len);
                    return Poll::Ready(Ok(()));
                }
                RecvState::Raw(_) => match shared.socket.try_read(buf.initialize_unfilled()) {
                    Ok(0) => {
                        if let Some(failure) = state.write_failed.clone() {
                            return Poll::Ready(Err(state.fail_recv(failure)));
                        }
                        state.recv = RecvState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    Ok(len) => {
                        buf.advance(len);
                        state.heard(&shared.socket);
                        shared.book.add(|tally| &tally.raw_bytes, len);
                        return Poll::Ready(Ok(()));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        ready!(shared.socket.poll_read_ready(cx)).map_err(|error| state.fail_recv(Failure::of(&error)))?;
                    }
                    Err(error) => return Poll::Ready(Err(state.fail_recv(Failure::of(&error)))),
                },
                RecvState::Sealed(_) => {
                    ready!(state.poll_sealed_step(&shared.socket, Read::Wait(cx)))?;
                    if !state.out.is_empty() {
                        push(shared, &mut state);
                    }
                }
            }
        }
    }
}

impl AsyncWrite for LaneSend {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let shared = &this.shared;
        let mut state = shared.lock();
        shared.check_revoked(&mut this.wait_revoked, cx)?;
        state.check_refused()?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match &mut state.send {
                SendState::Header(header) => {
                    if header.len() + data.len() <= MAX_HEADER_LEN {
                        header.extend_from_slice(data);
                        return Poll::Ready(Ok(data.len()));
                    }
                    // 流头不会超过该上限：按 sealed 模式结束流头，后续字节作为普通数据发送。
                    state.end_header(Payload::Sealed);
                }
                SendState::Sealed => {
                    ready!(state.poll_drain(&shared.socket, cx))?;
                    let len = data.len().min(MAX_DATA_LEN);
                    let State { sealed, out, .. } = &mut *state;
                    let sealed = sealed.as_mut().expect("sealed 的方向一定还有 TLS 状态");
                    sealed.seal(&[&data_header(len), &data[..len]]);
                    sealed.take_output(out);
                    shared.book.add(|tally| &tally.sealed_bytes, len);
                    push(shared, &mut state);
                    return Poll::Ready(Ok(len));
                }
                SendState::Raw => {
                    ready!(state.poll_drain(&shared.socket, cx))?;
                    match shared.socket.try_write(data) {
                        Ok(len) => {
                            shared.book.add(|tally| &tally.raw_bytes, len);
                            return Poll::Ready(Ok(len));
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            state.send_waker = Some(cx.waker().clone());
                            ready!(shared.socket.poll_write_ready(cx))?;
                        }
                        Err(error) => {
                            state.write_failed.get_or_insert_with(|| Failure::of(&error));
                            return Poll::Ready(Err(error));
                        }
                    }
                }
                SendState::Closing | SendState::Finished => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "当前发送方向已正常关闭")));
                }
                SendState::Aborted => return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "当前发送方向已重置"))),
                SendState::Handed => return Poll::Ready(Err(io::Error::other("当前发送方向已移交调用方直接写入"))),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let shared = &this.shared;
        let mut state = shared.lock();
        shared.check_revoked(&mut this.wait_revoked, cx)?;
        if matches!(state.send, SendState::Header(_)) {
            state.end_header(Payload::Sealed);
        }
        state.poll_drain(&shared.socket, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let shared = &this.shared;
        let mut state = shared.lock();
        shared.check_revoked(&mut this.wait_revoked, cx)?;
        loop {
            // 被对端叫停的方向不发 close_notify 与 FIN：对端未必收全了之前写入的数据，不能报告正常结束。
            state.check_refused()?;
            match state.send {
                SendState::Header(_) => state.end_header(Payload::Sealed),
                SendState::Sealed => {
                    let State { sealed, out, .. } = &mut *state;
                    let sealed = sealed.as_mut().expect("sealed 的方向一定还有 TLS 状态");
                    sealed.close_notify();
                    sealed.take_output(out);
                    state.send = SendState::Closing;
                }
                SendState::Raw => state.send = SendState::Closing,
                SendState::Closing => {
                    ready!(state.poll_drain(&shared.socket, cx))?;
                    shared.check_revoked(&mut this.wait_revoked, cx)?;
                    socket::finish_write(&shared.socket)?;
                    state.send = SendState::Finished;
                    state.drop_tls_if_unused();
                    return Poll::Ready(Ok(()));
                }
                SendState::Finished => return Poll::Ready(Ok(())),
                SendState::Aborted => return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "当前发送方向已重置"))),
                SendState::Handed => return Poll::Ready(Err(io::Error::other("当前发送方向已移交调用方直接写入"))),
            }
        }
    }
}

impl SendStream for LaneSend {
    fn reset(&mut self, code: StreamCode) {
        let shared = &self.shared;
        let mut state = shared.lock();
        reset(shared, &mut state, code);
    }

    /// 头写完了，或者接受方这个方向可以不再加密了。
    ///
    /// - 发起方：OPEN 连同首批数据写完了。`payload` 选定这条流的负载方式，攒下的头作为一个 OPENING 帧送出。
    ///   选了 [`Payload::Passthrough`] 时这个方向还留在 TLS 里，等接受方的 SWITCH：收到时（在读的那一侧）回一个 SWITCH，
    ///   之后这个方向是原始字节，[`take_raw`](SendStream::take_raw) 交得出来。对端是没升级的节点时按 sealed 送出。
    /// - 接受方：发起方选了 passthrough、并且这里也传 [`Payload::Passthrough`] 时，发一个 SWITCH，之后这个方向是原始字节；
    ///   别的情况（包括这个方向已被对端叫停）什么都不做，这个方向留在 TLS 里。在这之前可以已经发过任意多的数据（流层先加密地送出目标的 ServerHello）。
    ///
    /// 不用等：密文立刻交给内核，交不完的由后台送出。头已经结束之后再调用没有效果。
    ///
    /// 发起方不调它也能用，只是一直是 sealed：开始读（等回复）、`flush`、`shutdown`，或者头超过上限时，
    /// 攒下的头按 sealed 送出。
    fn end_header(&mut self, payload: Payload) {
        let mut state = self.shared.lock();
        if self.shared.is_revoked() {
            return;
        }
        state.end_header(payload);
        push(&self.shared, &mut state);
    }

    /// 这个方向已经离开 TLS 时，把它交出去，让调用方直接写 socket（见 [`RawWrite`]）。还在 TLS 里、已经结束、已被对端叫停或者已经交出去时
    /// 返回 `None`：被叫停的方向交出去之后，写入将绕过这里，叫停的原因随之丢失。
    ///
    /// 交出去之后这个 [`LaneSend`] 不再能写，丢弃它也不会重置流。
    fn take_raw(&mut self) -> Option<RawWrite> {
        let shared = &self.shared;
        let mut state = shared.lock();
        if shared.is_revoked() || !matches!(state.send, SendState::Raw) || state.aborted || state.send_refused.is_some() {
            return None;
        }
        state.send = SendState::Handed;
        state.raw_taken = true;
        let unsent = std::mem::take(&mut state.out).freeze();
        state.drop_tls_if_unused();
        Some(RawWrite::new(Arc::clone(&shared.socket), unsent, shared.book.spliced()).with_revocation(shared.revoked.clone()))
    }
}

fn reset(shared: &Shared, state: &mut State, code: StreamCode) {
    if shared.is_revoked() {
        return;
    }
    let raw = match state.send {
        SendState::Finished | SendState::Aborted | SendState::Handed => return,
        // 头还没发出去：对端还不知道有这条流，重置连接就够了。
        SendState::Header(_) | SendState::Closing => false,
        SendState::Sealed => {
            let sealed = state.sealed.as_mut().expect("sealed 的方向一定还有 TLS 状态");
            sealed.seal_frame(&Frame::Abort(code.0));
            sealed.take_output(&mut state.out);
            // 尽力而为：ABORT 进得了内核就送得到，进不去对端也会看到 RST。
            state.abort_sent = matches!(state.drain_now(&shared.socket), Ok(true));
            false
        }
        SendState::Raw => true,
    };
    state.send = SendState::Aborted;
    state.aborted = true;
    socket::rst_on_close(&shared.socket);
    if raw {
        socket::reset_now(&shared.socket);
    }
}

impl RecvStream for LaneRecv {
    fn stop(&mut self, code: StreamCode) {
        let shared = &self.shared;
        let mut state = shared.lock();
        stop(shared, &mut state, code);
    }

    fn revocation(&self) -> Option<watch::Receiver<bool>> {
        Some(self.shared.revoked.clone())
    }

    /// 读完了对端的头（OPEN 或 REPLY）。在这之前接收方向只交出 TLS 里收到的字节，见 [`RecvState::Leaving`]。
    fn end_header(&mut self) {
        let shared = &self.shared;
        let mut state = shared.lock();
        state.finish_header();
        if !state.out.is_empty() {
            push(shared, &mut state);
        }
    }

    /// 等待确定接收方向的后续模式：若已离开 TLS（对端发送 SWITCH，或未升级的发起方选择了 passthrough），则与
    /// [`take_raw`](Self::take_raw) 相同交出原始句柄；若后续仍为 TLS 数据、或该方向已结束/出错，则返回 `None`，由调用方继续正常读取。
    ///
    /// 发起方在读完 REPLY 后调用该方法：接受方紧随其后发送 SWITCH，可能仍在传输途中。收到后发起方发送方向也会随之切换（见
    /// [`LaneSend::end_header`]）。接受方在它自己的 SWITCH 之后用它等发起方的回应。
    async fn wait_raw(&mut self) -> Option<RawRead> {
        // 一直加密的流，哪个方向都不会离开 TLS：直接返回，不去推进 TLS、也不再为 `take_raw` 拿一次锁。
        // 流层每读一段之前都会问一次（i3t-flow 的 `flow_to_tcp`），这样加密的流上每段只多拿一次锁。
        if self.shared.lock().mode == Some(Mode::Sealed) {
            return None;
        }
        std::future::poll_fn(|cx| {
            let shared = &self.shared;
            let mut state = shared.lock();
            if shared.check_revoked(&mut self.wait_revoked, cx).is_err() {
                return Poll::Ready(());
            }
            loop {
                match &state.recv {
                    RecvState::Raw(_) | RecvState::Leaving { .. } => break,
                    RecvState::Sealed(data) if data.is_empty() => {
                        let step = state.poll_sealed_step(&shared.socket, Read::Wait(cx));
                        if !state.out.is_empty() {
                            push(shared, &mut state);
                        }
                        match step {
                            Poll::Ready(Ok(())) => {}
                            Poll::Ready(Err(_)) => return Poll::Ready(()),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    _ => return Poll::Ready(()),
                }
            }
            Poll::Ready(())
        })
        .await;
        self.take_raw()
    }
}

fn stop(shared: &Arc<Shared>, state: &mut State, code: StreamCode) {
    if shared.is_revoked() || matches!(state.recv, RecvState::Eof | RecvState::Stopped | RecvState::Failed(_) | RecvState::Handed) {
        return;
    }
    state.recv = RecvState::Stopped;
    match state.send {
        SendState::Sealed => {
            let sealed = state.sealed.as_mut().expect("sealed 的方向一定还有 TLS 状态");
            sealed.seal_frame(&Frame::Stop(code.0));
            sealed.take_output(&mut state.out);
            push(shared, state);
        }
        // 对端还不知道有这条流。
        SendState::Header(_) | SendState::Aborted | SendState::Handed => {}
        // 没有办法在流里告诉对端了：只能重置整条 lane。
        SendState::Raw | SendState::Closing | SendState::Finished => {
            state.aborted = true;
            socket::reset_now(&shared.socket);
        }
    }
    state.drop_tls_if_unused();
}

impl Drop for LaneSend {
    fn drop(&mut self) {
        let shared = &self.shared;
        let mut state = shared.lock();
        if !matches!(state.send, SendState::Finished | SendState::Aborted | SendState::Handed) {
            reset(shared, &mut state, DROPPED_SEND);
        }
        release(shared, &mut state);
    }
}

impl Drop for LaneRecv {
    fn drop(&mut self) {
        let shared = &self.shared;
        let mut state = shared.lock();
        stop(shared, &mut state, DROPPED_RECV);
        release(shared, &mut state);
    }
}

/// 一个方向的句柄被丢弃。两个都丢了时决定关闭方式。
fn release(shared: &Arc<Shared>, state: &mut State) {
    state.halves -= 1;
    if state.halves > 0 {
        return;
    }
    shared.closed.notify_one();
    if state.raw_taken {
        // 原始方向的搬运方监听同一个吊销信号，并负责重置 socket。
        return;
    }
    if shared.is_revoked() {
        i3t_underlay::tcp_reset::close(Arc::clone(&shared.socket));
        return;
    }
    let send_clean = matches!(state.send, SendState::Finished);
    match (&state.recv, send_clean, state.aborted) {
        (RecvState::Eof, true, false) => socket::graceful_close(&shared.socket),
        (RecvState::Stopped, true, false) => linger_then_close(shared),
        _ if state.abort_sent => close_after_abort(shared),
        // 异常结束。发送方向可能正常结束过，macOS 上那时已经改回了正常关闭（`socket::finish_write`）：重新设成关闭时发 RST。
        _ => socket::rst_on_close(&shared.socket),
    }
}

/// 本端已经正常写完、但叫停了对端：先把对端还在路上的数据收下扔掉，再正常关闭（见 [`LINGER_AFTER_STOP`]）。
fn linger_then_close(shared: &Arc<Shared>) {
    let socket = Arc::clone(&shared.socket);
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    socket::graceful_close(&socket);
    drop(runtime.spawn(async move {
        let _ = tokio::time::timeout(LINGER_AFTER_STOP, discard(&socket)).await;
    }));
}

/// 本端发了 ABORT 帧、两个方向都丢弃了：发 FIN，把对端还在路上的数据收下扔掉，等对端关掉（最多 [`LINGER_AFTER_STOP`]）再关。
/// socket 还设着"关闭时发 RST"，那时对端看到的是重置。见模块文档的异常结束一节。
///
/// 对端读到 ABORT 之后会关掉它那一头；两头都发了 ABORT 时，各自的 FIN 让对方的等待马上结束。
fn close_after_abort(shared: &Arc<Shared>) {
    let socket = Arc::clone(&shared.socket);
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    if let Err(error) = socket::shutdown_write(&socket) {
        tracing::debug!(%error, "发送 ABORT 后关闭写半部（FIN）失败，对端读取 ABORT 后将等待关闭时的 RST");
    }
    drop(runtime.spawn(async move {
        let _ = tokio::time::timeout(LINGER_AFTER_STOP, discard(&socket)).await;
    }));
}

/// 把收到的都读出来扔掉，直到对端结束或者出错。
async fn discard(socket: &TcpStream) {
    let mut scratch = [0; 4096];
    loop {
        if socket.readable().await.is_err() {
            return;
        }
        match socket.try_read(&mut scratch) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests;
