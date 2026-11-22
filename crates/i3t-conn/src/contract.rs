//! 端到端连接对上层的契约。
//!
//! 一条流是两个独立的方向：[`SendStream`] 和 [`RecvStream`]。每个方向有两种结束方式，上层必须能区分：
//!
//! | | 发送方做了什么 | 接收方看到什么 |
//! |---|---|---|
//! | 正常结束 | `AsyncWriteExt::shutdown`，写入的数据全部送达 | 读到 EOF（`read` 返回 0） |
//! | 异常结束 | [`SendStream::reset`]，或者没有 `shutdown` 就把流丢弃 | 读出错，[`StreamAborted::of`] 能取出原因码 |
//!
//! 被截断的数据不能表现成正常结束，所以**没有 `shutdown` 就丢弃发送方向等同于重置**。
//!
//! 接收方也可以主动叫停（[`RecvStream::stop`]）：发送方之后的写会出错，[`StreamAborted::of`] 同样能取出原因码。
//!
//! # ice3proxy（lane）要上层多做的事
//!
//! 一条流也可能跑在一条只属于它的 TCP 上（`i3t-lane`）。那时上层多做三件事，跑在共用连接上的流全部是空操作：
//!
//! - 写完流的头（发起方的 OPEN 连同首批数据、接受方的 REPLY）时调 [`SendStream::end_header`]，发起方顺便选定
//!   [`Payload`]：首批数据本身就是 TLS 时，头之后的字节可以不再加密；
//! - 搬运之前用 [`SendStream::take_raw`]、[`RecvStream::wait_raw`] 问一下这个方向是不是已经是一条原始的 TCP，
//!   是的话直接在两条 TCP 之间搬（Linux 上用 splice），同时监听流的吊销信号；
//! - 开一条承载 TCP 连接的流用 [`Connector::open_tcp`]：实现可以为它挑独占的 TCP，别的流（数据报上下文等）照常用 [`Connector::open`]。
//!
//! 流之外，一对节点之间还可以互相发数据报（[`Datagrams`]）：一份一份的，每份有长度上限。
//! 走 [`DatagramSender::send_datagram`] 的可能丢、可能乱序、不重传；走 [`DatagramSender::send_reliable`] 的不丢，
//! 但同样不保证先后。数据报只在已经有的连接上发，不会为它去建连接：上层总是先开一条流，再发和这条流有关的数据报。
//!
//! 虚拟网卡上的 IP 包（[`Packets`]）也是不保证送达的数据报，首字节标着它是网络包（`i3t_proto::flow::PacketHeader`），
//! 收的一方交给第三个人。它们和流不一样，没有一条流替它们撑着连接，所以：第一个包之前要先把连接建起来（[`PacketSender::connect`]）；
//! 包在走的时候连接不因为没有流而被当作空闲回收，包停了照常回收。

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use i3t_proto::NodeId;
use i3t_proto::flow::Recipient;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;

/// 流异常结束时带给对端的原因码。各个值的含义由上层定义，这一层只负责送达。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamCode(pub u32);

/// 同一条连接上流与流之间的发送次序：连接一次发不完所有流的数据时，先发优先级高的流，同一级的轮流发。
///
/// 它只管本端往外发的方向，对端怎么排它自己的发送由对端决定。数据报不排在这里面，它们总是先于流的数据发出。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Priority {
    /// 让位：别的流有数据要发时先发它们的。
    Low,
    #[default]
    Normal,
    /// 优先：先于别的流发出。
    High,
}

/// 一条流的发送方向。
pub trait SendStream: AsyncWrite + Unpin + Send + 'static {
    /// 异常结束这个方向。还没送达的数据可能被丢弃，对端的读会出错并拿到 `code`。
    /// 已经正常结束或者已经重置过的流上再调用没有效果。
    fn reset(&mut self, code: StreamCode);

    /// 改这个方向的发送优先级，随时可以改。新开的流是 [`Priority::Normal`]。
    ///
    /// 不分优先级的实现可以不管它，所以有一个什么都不做的默认实现。
    fn set_priority(&mut self, priority: Priority) {
        let _ = priority;
    }

    /// 流的头写完了：发起方是 OPEN 连同首批数据，接受方是 REPLY。
    ///
    /// 发起方用 `payload` 选这条流头之后的负载方式；接受方传 [`Payload::Passthrough`] 表示"发起方选了不加密的话，我这个方向也跟着"。
    /// 跑在共用连接上的流不需要知道头在哪里结束，默认什么都不做。不用等，也不用再 `flush`。
    fn end_header(&mut self, payload: Payload) {
        let _ = payload;
    }

    /// 这个方向底下是不是已经是一条只属于这条流、不再加密的 TCP。是的话交出来（见 [`RawWrite`]），之后这个 [`SendStream`] 不再能写。
    ///
    /// 默认 `None`：照常用 `AsyncWrite` 写。
    fn take_raw(&mut self) -> Option<RawWrite> {
        None
    }
}

/// 一条流的接收方向。
pub trait RecvStream: AsyncRead + Unpin + Send + 'static {
    /// 不再读了，请对端停止发送。对端之后的写会出错并拿到 `code`。
    fn stop(&mut self, code: StreamCode);

    /// 整条流的吊销信号，包括已经交给调用方直接搬运的两个方向。默认由底层连接负责终止读写。
    fn revocation(&self) -> Option<watch::Receiver<bool>> {
        None
    }

    /// 等到知道这个方向接下来是什么：底下已经是一条不再加密的 TCP（见 [`RawRead`]）就交出来，之后这个 [`RecvStream`] 不再能读；
    /// 不是（接下来还是加密的数据、或者已经结束），返回 `None`，照常读。
    ///
    /// 发起方读完 REPLY 之后调：对端在 REPLY 后面紧跟着切换，切换的标记可能还在路上。默认立刻返回 `None`。
    fn wait_raw(&mut self) -> impl Future<Output = Option<RawRead>> + Send {
        std::future::ready(None)
    }
}

/// 等到流被吊销。发送端只在吊销时设为 `true`，直接关闭代表连接管理器退出，存量流可以继续。
pub async fn wait_revoked(mut revocation: watch::Receiver<bool>) {
    if revocation.wait_for(|revoked| *revoked).await.is_err() {
        std::future::pending::<()>().await
    }
}

/// 流的头之后，这个方向上的数据怎么走。只对跑在 ice3proxy 上的流有意义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Payload {
    /// 一直加密。
    #[default]
    Sealed,
    /// 头之后原样传用户的字节，不再加密第二次。只在用户的数据本身就是 TLS 时用。
    Passthrough,
}

impl Payload {
    /// 首批数据是一条完整的 TLS 握手记录、内容是 ClientHello 时选 [`Payload::Passthrough`]，其余选 [`Payload::Sealed`]。
    ///
    /// 只看开头：记录头是握手类型、版本是 3.x、长度在 TLS 允许的范围里并且整条都在，记录里第一条握手消息是 ClientHello。
    /// 不完整的不算，宁可多加密一次，也不能把不是 TLS 的数据明文送出去。
    #[must_use]
    pub fn for_first_data(first: &[u8]) -> Self {
        const HANDSHAKE: u8 = 0x16;
        const CLIENT_HELLO: u8 = 0x01;
        let Some(&[HANDSHAKE, 0x03, _minor, hi, lo, CLIENT_HELLO]) = first.first_chunk::<6>() else { return Self::Sealed };
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        if (4..=1 << 14).contains(&len) && first.len() >= 5 + len { Self::Passthrough } else { Self::Sealed }
    }
}

/// 一个已经不再加密的发送方向：一条只属于这条流的 TCP，交给调用方直接写（例如在两条 TCP 之间 splice）。
///
/// - 先写 [`unsent`](Self::unsent)，再写自己的数据。
/// - 正常结束时发 FIN（`shutdown(Write)`）；异常结束时绝不能发 FIN，而是重置连接。
/// - 搬运时监听 [`revoked`](Self::revoked)。吊销时停止两个方向并按异常结束处理。
/// - socket 处在"关闭时发 RST"的状态。交出去之后底下的传输不再管它怎么关：调用方在整条流两个方向都正常结束时
///   才恢复正常关闭（`SO_LINGER` 关掉），否则保持原样，丢弃时对端看到重置。macOS 上两个方向都关了之后改不了，
///   要在发 FIN 时就改、出错时再设回来（`i3t_underlay::tcp_reset` 的 `shutdown_write`、`graceful_close` 就是这样做的）。
#[derive(Debug)]
pub struct RawWrite {
    socket: Arc<TcpStream>,
    unsent: Bytes,
    counters: Vec<Arc<AtomicU64>>,
    revocation: Option<watch::Receiver<bool>>,
}

impl RawWrite {
    /// 调用方每搬一段就往 `counters` 上各加一次，底下的传输用它们计数。
    #[must_use]
    pub fn new(socket: Arc<TcpStream>, unsent: Bytes, counters: Vec<Arc<AtomicU64>>) -> Self {
        Self { socket, unsent, counters, revocation: None }
    }

    /// 附上整条流的吊销信号。
    #[must_use]
    pub fn with_revocation(mut self, revocation: watch::Receiver<bool>) -> Self {
        self.revocation = Some(revocation);
        self
    }

    /// 复制吊销信号，可在取出 socket 后继续监听。
    #[must_use]
    pub fn revocation(&self) -> Option<watch::Receiver<bool>> {
        self.revocation.clone()
    }

    /// 当前是否已被吊销。
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revocation.as_ref().is_some_and(|revocation| *revocation.borrow())
    }

    /// 被吊销时唤醒搬运任务。没有独立吊销信号时由 socket 自己报告断开。
    pub async fn revoked(&self) {
        if let Some(revocation) = &self.revocation {
            wait_revoked(revocation.clone()).await;
        } else {
            std::future::pending::<()>().await;
        }
    }

    #[must_use]
    pub fn socket(&self) -> &TcpStream {
        &self.socket
    }

    /// 同一条 socket 的又一个句柄：调用方要在搬运结束之后决定怎么关它时留着。
    #[must_use]
    pub fn socket_handle(&self) -> Arc<TcpStream> {
        Arc::clone(&self.socket)
    }

    /// 还没交给内核的那一截（开流时的密文），必须先于任何原始字节写出去。
    #[must_use]
    pub fn unsent(&self) -> &[u8] {
        &self.unsent
    }

    /// 告诉底下的传输又搬了 `bytes` 字节。
    pub fn moved(&self, bytes: usize) {
        for counter in &self.counters {
            // usize 不会比 u64 宽，这里不会截断。
            counter.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    /// 取出 socket 和缓冲的字节。搬运前先取 [`Self::revocation`]，被吊销时停止读写并以重置关闭 socket。
    #[must_use]
    pub fn into_parts(self) -> (Arc<TcpStream>, Bytes) {
        (self.socket, self.unsent)
    }
}

/// 一个已经不再加密的接收方向：先交出 [`received`](Self::received)（已经从 socket 读进来、还没交出去的原始字节），再读 socket。
/// FIN 是正常结束，RST 或者出错是异常结束。搬运时监听 [`revoked`](Self::revoked)，关闭的规矩和 [`RawWrite`] 一样。
#[derive(Debug)]
pub struct RawRead {
    socket: Arc<TcpStream>,
    received: Bytes,
    counters: Vec<Arc<AtomicU64>>,
    revocation: Option<watch::Receiver<bool>>,
}

impl RawRead {
    /// 调用方每搬一段就往 `counters` 上各加一次，底下的传输用它们计数。
    #[must_use]
    pub fn new(socket: Arc<TcpStream>, received: Bytes, counters: Vec<Arc<AtomicU64>>) -> Self {
        Self { socket, received, counters, revocation: None }
    }

    /// 附上整条流的吊销信号。
    #[must_use]
    pub fn with_revocation(mut self, revocation: watch::Receiver<bool>) -> Self {
        self.revocation = Some(revocation);
        self
    }

    /// 复制吊销信号，可在取出 socket 后继续监听。
    #[must_use]
    pub fn revocation(&self) -> Option<watch::Receiver<bool>> {
        self.revocation.clone()
    }

    /// 当前是否已被吊销。
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revocation.as_ref().is_some_and(|revocation| *revocation.borrow())
    }

    /// 被吊销时唤醒搬运任务。没有独立吊销信号时由 socket 自己报告断开。
    pub async fn revoked(&self) {
        if let Some(revocation) = &self.revocation {
            wait_revoked(revocation.clone()).await;
        } else {
            std::future::pending::<()>().await;
        }
    }

    #[must_use]
    pub fn socket(&self) -> &TcpStream {
        &self.socket
    }

    /// 同一条 socket 的又一个句柄：调用方要在搬运结束之后决定怎么关它时留着。
    #[must_use]
    pub fn socket_handle(&self) -> Arc<TcpStream> {
        Arc::clone(&self.socket)
    }

    #[must_use]
    pub fn received(&self) -> &[u8] {
        &self.received
    }

    /// 告诉底下的传输又搬了 `bytes` 字节。
    pub fn moved(&self, bytes: usize) {
        for counter in &self.counters {
            // usize 不会比 u64 宽，这里不会截断。
            counter.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    /// 取出 socket 和缓冲的字节。搬运前先取 [`Self::revocation`]，被吊销时停止读写并以重置关闭 socket。
    #[must_use]
    pub fn into_parts(self) -> (Arc<TcpStream>, Bytes) {
        (self.socket, self.received)
    }
}

/// 流的某个方向被对端异常结束了。它被包在读写返回的 [`io::Error`] 里。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamAborted {
    /// 读的时候发现对端重置了发送方向。
    #[error("对端重置了这条流，原因码 {}", .0.0)]
    Reset(StreamCode),
    /// 写的时候发现对端叫停了接收方向。
    #[error("对端不再接收这条流，原因码 {}", .0.0)]
    Stopped(StreamCode),
}

impl StreamAborted {
    /// 从读写返回的错误里取出"被对端异常结束"这件事；别的错误（连接断开等）返回 `None`。
    #[must_use]
    pub fn of(error: &io::Error) -> Option<Self> {
        error.get_ref()?.downcast_ref::<Self>().copied()
    }

    #[must_use]
    pub const fn code(self) -> StreamCode {
        match self {
            Self::Reset(code) | Self::Stopped(code) => code,
        }
    }
}

impl From<StreamAborted> for io::Error {
    fn from(aborted: StreamAborted) -> Self {
        let kind = match aborted {
            StreamAborted::Reset(_) => io::ErrorKind::ConnectionReset,
            StreamAborted::Stopped(_) => io::ErrorKind::BrokenPipe,
        };
        Self::new(kind, aborted)
    }
}

/// 到对端开流。
pub trait Connector: Send + Sync + 'static {
    type Send: SendStream;
    type Recv: RecvStream;

    /// 到 `peer` 开一条新的流。和它之间还没有连接时先建连接（多一次握手往返）；已经有连接时不需要任何往返。
    fn open(&self, peer: NodeId) -> impl Future<Output = Result<(Self::Send, Self::Recv), OpenError>> + Send;

    /// 到 `peer` 开一条承载一条 TCP 连接、要求走 ice3proxy 的流（选了 ice3proxy 的代理的 CONNECT 和明文 HTTP）。
    ///
    /// 实现可以为这种流挑另一种传输（一对节点之间备着 ice3proxy 时，每条这样的流独占一条 TCP）。默认同 [`open`](Self::open)。
    fn open_tcp(&self, peer: NodeId) -> impl Future<Output = Result<(Self::Send, Self::Recv), OpenError>> + Send {
        self.open(peer)
    }
}

/// 接受对端开过来的流。
pub trait Acceptor: Send + Sync + 'static {
    type Send: SendStream;
    type Recv: RecvStream;

    /// 等下一条对端开过来的流。本端关闭之后返回 `None`。
    ///
    /// 对端是谁由连接的握手确定（按公钥认证），所以 [`Incoming::peer`] 伪造不了。
    fn accept(&self) -> impl Future<Output = Option<Incoming<Self::Send, Self::Recv>>> + Send;
}

/// 对端开过来的一条流。
#[derive(Debug)]
pub struct Incoming<S, R> {
    pub peer: NodeId,
    pub send: S,
    pub recv: R,
}

/// 一对节点之间的数据报。
///
/// 收和发分开：收的一方只有一个（[`recv_datagram`](Self::recv_datagram) 的每个 `recipient` 各有一个人在等），
/// 发的一方可以有很多，所以发送用的是一个可以克隆、可以带进任务里的句柄。
pub trait Datagrams: Send + Sync + 'static {
    type Sender: DatagramSender;

    /// 发数据报用的句柄。
    fn datagram_sender(&self) -> Self::Sender;

    /// 等下一个对端发来的、给 `recipient` 这一侧的数据报。本端关闭之后返回 `None`。
    ///
    /// 这一层不解释数据报的内容，只看首字节里上层写明的"给哪一侧"（[`Recipient::peek`]），看不出来的直接丢掉。
    /// 两侧各有一个有上限的队列：没有人来取、或者取得太慢时，新到的数据报被丢掉。
    /// 同一个 `recipient` 只应该有一个人在等。
    fn recv_datagram(&self, recipient: Recipient) -> impl Future<Output = Option<Datagram>> + Send;
}

/// 往对端发数据报。
pub trait DatagramSender: Clone + Send + Sync + 'static {
    /// 现在往 `peer` 发一个数据报最长可以多少字节。和它之间没有连接、或者它不接收数据报时返回 `None`。
    ///
    /// 这个值跟着连接探测到的路径 MTU 变，每次发之前都要问。它只限制 [`send_datagram`](Self::send_datagram)。
    fn max_datagram_len(&self, peer: NodeId) -> Option<usize>;

    /// 发一个不保证送达的数据报。不等待：连接来不及发时，排在最前面的旧数据报被丢掉，给新的让位。
    ///
    /// # Errors
    ///
    /// 和 `peer` 之间没有连接，或者数据报超过了 [`max_datagram_len`](Self::max_datagram_len)。
    fn send_datagram(&self, peer: NodeId, datagram: Bytes) -> Result<(), DatagramSendError>;

    /// 发一个保证送达的数据报：丢了由连接重传，长度不受 [`max_datagram_len`](Self::max_datagram_len) 限制。
    /// 每个数据报各走各的，一个被重传不耽误别的，所以到达的先后不保证。
    ///
    /// 返回时数据报已经交给连接，还不一定到了对端。对端来不及收时会在这里等，这就是反压。
    ///
    /// # Errors
    ///
    /// 和 `peer` 之间没有连接，或者连接在交出去之前断了。
    fn send_reliable(&self, peer: NodeId, datagram: Bytes) -> impl Future<Output = Result<(), DatagramSendError>> + Send;
}

/// 一对节点之间的网络包（虚拟网卡上的 IP 包）。
///
/// 和 [`Datagrams`] 一样收和发分开。只走共用的连接：ice3proxy 只运流，不运包。
pub trait Packets: Send + Sync + 'static {
    type Sender: PacketSender;

    /// 发网络包用的句柄。
    fn packet_sender(&self) -> Self::Sender;

    /// 等对端发来的网络包帧，一次取走排着的若干个（最多 `limit` 个）放进 `into`，返回取了几个。本端关闭之后返回 0。
    ///
    /// 首字节标着网络包的数据报（`i3t_proto::flow::Channel::Packet`）排在这里，内容这一层不看。队列有上限，
    /// 没有人来取、或者取得太慢时新到的被丢掉，和路由器的队列满了一样。只应该有一个人在等。
    fn recv_packets(&self, into: &mut Vec<Datagram>, limit: usize) -> impl Future<Output = usize> + Send;
}

/// 往对端发网络包。
pub trait PacketSender: Clone + Send + Sync + 'static {
    /// 把一帧（首字节标着网络包）作为一个不保证送达的数据报发给 `peer`，不等待。发出去的包让连接不被当作空闲回收。
    ///
    /// # Errors
    ///
    /// 和 `peer` 之间没有连接（先 [`connect`](Self::connect)），或者这一帧比这条连接现在能发的长
    /// （[`DatagramSendError::TooLarge`] 带着现在的上限：调用方切开再发）。
    fn send_packet(&self, peer: NodeId, frame: Bytes) -> Result<(), DatagramSendError>;

    /// 和 [`send_packet`](Self::send_packet) 一样把一帧交给 `peer`，只是允许实现先攒着，和紧接着交下来的几帧凑成一批一起发
    /// （少几次系统调用）。调用方在这一轮交完、要去等别的事之前必须调用 [`flush`](Self::flush)，不然攒着的发不出去。
    ///
    /// 默认就是 `send_packet`，不攒。
    ///
    /// # Errors
    ///
    /// 和 [`send_packet`](Self::send_packet) 一样，当场就知道。
    fn queue_packet(&self, peer: NodeId, frame: Bytes) -> Result<(), DatagramSendError> {
        self.send_packet(peer, frame)
    }

    /// 把 [`queue_packet`](Self::queue_packet) 攒着的都发出去。
    fn flush(&self) {}

    /// 发给 `peer` 的几个小网络包现在能不能合成一帧发（`i3t_proto::flow::PacketHeader::Bundle`），能的话一帧最长多少字节。
    ///
    /// 能：和它之间有连接，它握手时说过认识这种帧，而且现在包是单独封好了直接发给它的（到它是直连）。经 relay 的路上不合：
    /// 那里包是连接的数据报，排着的几个连接自己会装进一个包里。不认识这种帧的对端收到了只会丢掉。
    ///
    /// 默认是不能。
    fn bundle_capacity(&self, _peer: NodeId) -> Option<usize> {
        None
    }

    /// 和 `peer` 之间还没有连接时建一条；已经有了就立刻返回。
    ///
    /// # Errors
    ///
    /// 和 [`Connector::open`] 建连接时一样：不在 netmap 里、没有路、超时、本端正在关闭。
    fn connect(&self, peer: NodeId) -> impl Future<Output = Result<(), OpenError>> + Send;
}

/// 对端发来的一个数据报。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// 发它的节点。来自连接的握手，伪造不了。
    pub peer: NodeId,
    pub payload: Bytes,
}

/// 数据报没有发出去的原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DatagramSendError {
    #[error("和节点 {0} 之间没有连接")]
    NotConnected(NodeId),
    #[error("节点 {0} 不接收数据报")]
    Unsupported(NodeId),
    #[error("数据报有 {len} 字节，这条连接现在最长只能发 {max} 字节")]
    TooLarge { len: usize, max: usize },
    #[error("和节点 {peer} 的连接断开了：{reason}")]
    ConnectionLost { peer: NodeId, reason: String },
}

/// 开流失败的原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("节点 {0} 不在本节点的 netmap 里")]
    UnknownPeer(NodeId),
    #[error("到节点 {0} 没有可用的路径")]
    NoRoute(NodeId),
    #[error("和节点 {0} 建立连接超时")]
    Timeout(NodeId),
    #[error("和节点 {peer} 的连接断开了：{reason}")]
    ConnectionLost { peer: NodeId, reason: String },
    #[error("本端正在关闭")]
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_the_revocation_sender_does_not_revoke_a_stream() {
        let (sender, receiver) = watch::channel(false);
        drop(sender);
        tokio::select! {
            biased;
            () = wait_revoked(receiver) => panic!("关闭信号不能吊销流"),
            () = std::future::ready(()) => {}
        }

        let (sender, receiver) = watch::channel(false);
        sender.send_replace(true);
        drop(sender);
        tokio::select! {
            biased;
            () = wait_revoked(receiver) => {}
            () = std::future::ready(()) => panic!("已经吊销的流应当立即结束"),
        }
    }

    #[test]
    fn only_a_complete_client_hello_goes_unencrypted() {
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0, 0, 4, 3, 3, 0, 0];
        assert_eq!(Payload::for_first_data(&hello), Payload::Passthrough);
        hello.extend_from_slice(b"more records");
        assert_eq!(Payload::for_first_data(&hello), Payload::Passthrough);
        assert_eq!(Payload::for_first_data(&hello[..12]), Payload::Sealed, "记录不完整");
        assert_eq!(Payload::for_first_data(b"GET / HTTP/1.1\r\n\r\n"), Payload::Sealed);
        assert_eq!(Payload::for_first_data(&[]), Payload::Sealed);
        assert_eq!(Payload::for_first_data(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0, 0, 0]), Payload::Sealed, "ServerHello 不算");
        assert_eq!(Payload::for_first_data(&[0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0, 0, 0]), Payload::Sealed, "应用数据记录不算");
    }

    #[test]
    fn abort_survives_the_trip_through_io_error() {
        let reset: io::Error = StreamAborted::Reset(StreamCode(7)).into();
        assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(StreamAborted::of(&reset), Some(StreamAborted::Reset(StreamCode(7))));

        let stopped: io::Error = StreamAborted::Stopped(StreamCode(9)).into();
        assert_eq!(stopped.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(StreamAborted::of(&stopped).map(StreamAborted::code), Some(StreamCode(9)));

        assert_eq!(StreamAborted::of(&io::Error::other("连接断开")), None);
        assert_eq!(StreamAborted::of(&io::ErrorKind::UnexpectedEof.into()), None);
    }
}
