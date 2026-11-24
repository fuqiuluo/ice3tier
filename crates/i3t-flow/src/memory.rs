//! 内存里的连接层，测试用。
//!
//! [`MemoryMesh`] 是一张假的网：节点 [`join`](MemoryMesh::join) 进来，拿到一个开流的 [`MemoryConnector`] 和一个
//! 收流的 [`MemoryAcceptor`]。它们实现的就是 [`i3t_conn::contract`] 里的契约，行为按契约的文档来：
//!
//! - 正常结束：发送方 `shutdown`，接收方把数据读完之后读到 EOF。
//! - 重置：发送方 [`reset`](SendStream::reset)，或者没有 `shutdown` 就被丢弃（原因码是 `u32::MAX`）。
//!   接收方的读立刻出错，还没读走的数据被丢掉，[`StreamAborted::of`] 取得出原因码。
//! - 叫停：接收方 [`stop`](RecvStream::stop)，或者没读完就被丢弃（原因码是 0）。发送方之后的写出错，原因码同样取得出。
//! - 连接断开：[`MemoryMesh::partition`] 之后，两个节点之间所有的流读写都出错，而且这个错误里没有原因码。
//!
//! 每个方向有一个固定大小的缓冲区，写满了发送方就等，所以反压也是有的。
//!
//! 数据报（[`Datagrams`]）也有：加入了这张网、没有被 [`partition`](MemoryMesh::partition) 隔开的两个节点之间算有连接。
//! 不保证送达的那种有长度上限（[`MemoryMesh::set_max_datagram_len`]），可以让测试挑着丢（[`MemoryMesh::set_datagram_filter`]），
//! 收的一方排满了也丢；保证送达的那种不经过这些，排满了发送方就等。
//!
//! 流的发送优先级没有效果（内存里的流互不争抢），只是记下来，测试用 [`MemoryMesh::send_priorities`] 看设成了什么。

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use i3t_conn::contract::{Datagram, DatagramSendError, DatagramSender, Datagrams, Priority};
use i3t_conn::{Acceptor, Connector, Incoming, OpenError, RecvStream, SendStream, StreamAborted, StreamCode};
use i3t_proto::NodeId;
use i3t_proto::flow::Recipient;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// 一个方向上最多缓冲多少字节。
const PIPE_CAPACITY: usize = 64 * 1024;

/// 一个节点的每一侧，收到了、还没有被取走的数据报最多排多少个。和 QUIC 的实现取同一个数。
const DATAGRAM_BACKLOG: usize = 1024;

/// 不保证送达的数据报默认最长多少字节：真的连接在最小的路径 MTU 下差不多是这个数。
const DEFAULT_MAX_DATAGRAM_LEN: usize = 1200;

/// 发送方向没有正常结束就被丢弃时，对端看到的原因码。契约没有规定这个值，这里和 QUIC 的实现取同一个。
const DROPPED_SEND: StreamCode = StreamCode(u32::MAX);

/// 接收方向没读完就被丢弃时，对端看到的原因码。同样和 QUIC 的实现一致。
const DROPPED_RECV: StreamCode = StreamCode(0);

type IncomingStream = Incoming<MemorySend, MemoryRecv>;

/// 一张内存里的网。克隆出来的是同一张网。
#[derive(Debug, Clone, Default)]
pub struct MemoryMesh {
    state: Arc<Mutex<MeshState>>,
}

#[derive(Debug, Default)]
struct MeshState {
    nodes: HashMap<NodeId, NodeEntry>,
    partitions: HashSet<Link>,
    pipes: Vec<LivePipe>,
    /// 没有值时是 [`DEFAULT_MAX_DATAGRAM_LEN`]。
    max_datagram_len: Option<usize>,
    datagram_filter: Option<InstalledFilter>,
}

/// 一个加入了这张网的节点收东西的入口。
#[derive(Debug)]
struct NodeEntry {
    streams: mpsc::UnboundedSender<IncomingStream>,
    datagrams: Sides<mpsc::Sender<Datagram>>,
}

/// 上下文的两侧各一份的东西。
#[derive(Debug)]
struct Sides<T> {
    acceptor: T,
    initiator: T,
}

impl<T> Sides<T> {
    fn of(&self, recipient: Recipient) -> &T {
        match recipient {
            Recipient::Acceptor => &self.acceptor,
            Recipient::Initiator => &self.initiator,
        }
    }
}

/// 一个节点的两个接收队列。它的 [`MemoryConnector`] 和 [`MemoryAcceptor`] 共用。
type Inbox = Arc<Sides<tokio::sync::Mutex<mpsc::Receiver<Datagram>>>>;

/// 测试给的丢包规则：参数是发送方、接收方和数据报，返回 `false` 的被丢掉。
pub type DatagramFilter = Box<dyn FnMut(NodeId, NodeId, &[u8]) -> bool + Send>;

/// 装着的丢包规则。包这一层只是为了让网的状态还打印得出来。
struct InstalledFilter(DatagramFilter);

impl std::fmt::Debug for InstalledFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatagramFilter")
    }
}

#[derive(Debug)]
struct LivePipe {
    link: Link,
    /// 往这个方向里写的节点。
    sender: NodeId,
    pipe: Weak<Pipe>,
}

/// 一对节点，不分方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Link {
    low: NodeId,
    high: NodeId,
}

impl Link {
    fn between(a: NodeId, b: NodeId) -> Self {
        Self { low: a.min(b), high: a.max(b) }
    }
}

impl MemoryMesh {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 让一个节点加入这张网。同一个编号再加入一次会顶掉原来的：原来的 [`MemoryAcceptor`] 不再收到新的流。
    #[must_use]
    pub fn join(&self, id: NodeId) -> (MemoryConnector, MemoryAcceptor) {
        let (streams, incoming) = mpsc::unbounded_channel();
        let (to_acceptor, for_acceptor) = mpsc::channel(DATAGRAM_BACKLOG);
        let (to_initiator, for_initiator) = mpsc::channel(DATAGRAM_BACKLOG);
        let inbox: Inbox = Arc::new(Sides { acceptor: for_acceptor.into(), initiator: for_initiator.into() });
        self.lock().nodes.insert(id, NodeEntry { streams, datagrams: Sides { acceptor: to_acceptor, initiator: to_initiator } });
        let connector = MemoryConnector { id, mesh: self.clone(), inbox: Arc::clone(&inbox) };
        (connector, MemoryAcceptor { id, mesh: self.clone(), incoming: tokio::sync::Mutex::new(incoming), inbox })
    }

    /// 不保证送达的数据报最长多少字节。调小了可以让上层的分片跑起来。
    pub fn set_max_datagram_len(&self, len: usize) {
        self.lock().max_datagram_len = Some(len);
    }

    /// 装上或者卸掉丢包规则：每个不保证送达的数据报都拿去问，返回 `false` 的被丢掉。保证送达的数据报不经过它。
    pub fn set_datagram_filter(&self, filter: Option<DatagramFilter>) {
        self.lock().datagram_filter = filter.map(InstalledFilter);
    }

    /// `sender` 现在开着的每个流的发送方向各是什么优先级，按开流的先后。
    #[must_use]
    pub fn send_priorities(&self, sender: NodeId) -> Vec<Priority> {
        let state = self.lock();
        let live = state.pipes.iter().filter(|live| live.sender == sender).filter_map(|live| live.pipe.upgrade());
        live.map(|pipe| pipe.lock().priority).collect()
    }

    /// 断开两个节点之间的连接：它们之间已有的流全部出错（不带原因码），之后开流得到 [`OpenError::NoRoute`]。
    pub fn partition(&self, a: NodeId, b: NodeId) {
        let link = Link::between(a, b);
        let mut state = self.lock();
        state.partitions.insert(link);
        state.pipes.retain(|live| match live.pipe.upgrade() {
            Some(pipe) if live.link == link => {
                pipe.abort(Abort::Lost);
                false
            }
            Some(_) => true,
            None => false,
        });
    }

    /// 撤销 [`partition`](Self::partition)：两个节点之间又可以开流。已经断掉的流不会恢复。
    pub fn heal(&self, a: NodeId, b: NodeId) {
        self.lock().partitions.remove(&Link::between(a, b));
    }

    fn lock(&self) -> MutexGuard<'_, MeshState> {
        self.state.lock().expect("mesh mutex poisoned")
    }
}

/// 一个节点开流的那一半。
#[derive(Debug, Clone)]
pub struct MemoryConnector {
    id: NodeId,
    mesh: MemoryMesh,
    inbox: Inbox,
}

impl MemoryConnector {
    /// 这个节点自己的编号。
    #[must_use]
    pub fn id(&self) -> NodeId {
        self.id
    }
}

impl Connector for MemoryConnector {
    type Send = MemorySend;
    type Recv = MemoryRecv;

    async fn open(&self, peer: NodeId) -> Result<(Self::Send, Self::Recv), OpenError> {
        let link = Link::between(self.id, peer);
        let mut state = self.mesh.lock();
        if state.partitions.contains(&link) {
            return Err(OpenError::NoRoute(peer));
        }
        let Some(node) = state.nodes.get(&peer) else { return Err(OpenError::UnknownPeer(peer)) };

        let outbound = Arc::new(Pipe::default());
        let inbound = Arc::new(Pipe::default());
        let incoming =
            Incoming { peer: self.id, send: MemorySend { pipe: Arc::clone(&inbound) }, recv: MemoryRecv { pipe: Arc::clone(&outbound) } };
        if node.streams.send(incoming).is_err() {
            return Err(OpenError::ConnectionLost { peer, reason: "对端已经不接受新的流".to_owned() });
        }
        state.pipes.retain(|live| live.pipe.strong_count() > 0);
        state.pipes.extend([(self.id, &outbound), (peer, &inbound)].map(|(sender, pipe)| LivePipe {
            link,
            sender,
            pipe: Arc::downgrade(pipe),
        }));
        Ok((MemorySend { pipe: outbound }, MemoryRecv { pipe: inbound }))
    }
}

/// 一个节点收流的那一半。
#[derive(Debug)]
pub struct MemoryAcceptor {
    id: NodeId,
    mesh: MemoryMesh,
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<IncomingStream>>,
    inbox: Inbox,
}

impl Acceptor for MemoryAcceptor {
    type Send = MemorySend;
    type Recv = MemoryRecv;

    async fn accept(&self) -> Option<Incoming<Self::Send, Self::Recv>> {
        self.incoming.lock().await.recv().await
    }
}

impl Datagrams for MemoryConnector {
    type Sender = MemoryDatagrams;

    fn datagram_sender(&self) -> MemoryDatagrams {
        MemoryDatagrams { id: self.id, mesh: self.mesh.clone() }
    }

    async fn recv_datagram(&self, recipient: Recipient) -> Option<Datagram> {
        self.inbox.of(recipient).lock().await.recv().await
    }
}

impl Datagrams for MemoryAcceptor {
    type Sender = MemoryDatagrams;

    fn datagram_sender(&self) -> MemoryDatagrams {
        MemoryDatagrams { id: self.id, mesh: self.mesh.clone() }
    }

    async fn recv_datagram(&self, recipient: Recipient) -> Option<Datagram> {
        self.inbox.of(recipient).lock().await.recv().await
    }
}

/// 一个节点发数据报的句柄。
#[derive(Debug, Clone)]
pub struct MemoryDatagrams {
    id: NodeId,
    mesh: MemoryMesh,
}

impl MemoryDatagrams {
    /// 决定 `datagram` 应进入 `peer` 的哪一侧队列。若首字节无法识别目标侧，则与真实连接一致，直接丢弃。
    fn queue(&self, state: &MeshState, peer: NodeId, datagram: &[u8]) -> Result<Option<mpsc::Sender<Datagram>>, DatagramSendError> {
        let node = state.nodes.get(&peer).filter(|_| !state.partitions.contains(&Link::between(self.id, peer)));
        let node = node.ok_or(DatagramSendError::NotConnected(peer))?;
        Ok(Recipient::peek(datagram).map(|recipient| node.datagrams.of(recipient).clone()))
    }
}

impl DatagramSender for MemoryDatagrams {
    fn max_datagram_len(&self, peer: NodeId) -> Option<usize> {
        let state = self.mesh.lock();
        self.queue(&state, peer, &[]).ok().map(|_| state.max_datagram_len.unwrap_or(DEFAULT_MAX_DATAGRAM_LEN))
    }

    fn send_datagram(&self, peer: NodeId, datagram: Bytes) -> Result<(), DatagramSendError> {
        let mut state = self.mesh.lock();
        let queue = self.queue(&state, peer, &datagram)?;
        let max = state.max_datagram_len.unwrap_or(DEFAULT_MAX_DATAGRAM_LEN);
        if datagram.len() > max {
            return Err(DatagramSendError::TooLarge { len: datagram.len(), max });
        }
        let delivered = state.datagram_filter.as_mut().is_none_or(|filter| (filter.0)(self.id, peer, &datagram));
        if let Some(queue) = queue.filter(|_| delivered) {
            // 排满了就丢，和真的连接一样。
            let _full = queue.try_send(Datagram { peer: self.id, payload: datagram });
        }
        Ok(())
    }

    async fn send_reliable(&self, peer: NodeId, datagram: Bytes) -> Result<(), DatagramSendError> {
        let queue = self.queue(&self.mesh.lock(), peer, &datagram)?;
        let Some(queue) = queue else { return Ok(()) };
        let closed = |_| DatagramSendError::ConnectionLost { peer, reason: "对端已离开网络".to_owned() };
        queue.send(Datagram { peer: self.id, payload: datagram }).await.map_err(closed)
    }
}

/// 一个方向异常结束的方式。
#[derive(Debug, Clone, Copy)]
enum Abort {
    Reset(StreamCode),
    Stopped(StreamCode),
    Lost,
}

/// 一条流的一个方向：发送方往里写，接收方从里读。
#[derive(Debug, Default)]
struct Pipe {
    state: Mutex<PipeState>,
}

#[derive(Debug, Default)]
struct PipeState {
    buffer: VecDeque<u8>,
    /// 发送方已经正常结束。
    finished: bool,
    aborted: Option<Abort>,
    /// 发送方给这个方向设的优先级。只是记着，给测试看。
    priority: Priority,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl PipeState {
    fn wake_both(&mut self) {
        for waker in [self.reader.take(), self.writer.take()].into_iter().flatten() {
            waker.wake();
        }
    }
}

impl Pipe {
    fn lock(&self) -> MutexGuard<'_, PipeState> {
        self.state.lock().expect("pipe mutex poisoned")
    }

    /// 异常结束该方向。若此前已异常结束则保持不变，以最先到达的原因生效。
    fn abort(&self, abort: Abort) {
        let mut state = self.lock();
        if state.aborted.is_none() {
            state.aborted = Some(abort);
            state.buffer.clear();
            state.wake_both();
        }
    }
}

fn connection_lost() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "与对端节点的连接已断开")
}

/// 流的发送方向。
#[derive(Debug)]
pub struct MemorySend {
    pipe: Arc<Pipe>,
}

impl MemorySend {
    /// 这个方向现在还能不能写；不能时给出写会得到的错误。
    fn writable(state: &PipeState) -> io::Result<()> {
        match state.aborted {
            Some(Abort::Stopped(code)) => Err(StreamAborted::Stopped(code).into()),
            Some(Abort::Lost) => Err(connection_lost()),
            Some(Abort::Reset(_)) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "当前发送方向已重置")),
            None if state.finished => Err(io::Error::new(io::ErrorKind::BrokenPipe, "当前发送方向已正常关闭")),
            None => Ok(()),
        }
    }
}

impl AsyncWrite for MemorySend {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.pipe.lock();
        Self::writable(&state)?;
        let room = PIPE_CAPACITY.saturating_sub(state.buffer.len());
        if room == 0 && !data.is_empty() {
            state.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let len = data.len().min(room);
        state.buffer.extend(&data[..len]);
        if let Some(reader) = state.reader.take() {
            reader.wake();
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.pipe.lock();
        if !state.finished {
            Self::writable(&state)?;
            state.finished = true;
            if let Some(reader) = state.reader.take() {
                reader.wake();
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl SendStream for MemorySend {
    fn reset(&mut self, code: StreamCode) {
        if !self.pipe.lock().finished {
            self.pipe.abort(Abort::Reset(code));
        }
    }

    fn set_priority(&mut self, priority: Priority) {
        self.pipe.lock().priority = priority;
    }
}

impl Drop for MemorySend {
    fn drop(&mut self) {
        self.reset(DROPPED_SEND);
    }
}

/// 流的接收方向。
#[derive(Debug)]
pub struct MemoryRecv {
    pipe: Arc<Pipe>,
}

impl AsyncRead for MemoryRecv {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.pipe.lock();
        match state.aborted {
            Some(Abort::Reset(code)) => return Poll::Ready(Err(StreamAborted::Reset(code).into())),
            Some(Abort::Lost) => return Poll::Ready(Err(connection_lost())),
            Some(Abort::Stopped(_)) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "当前接收方向已中止")));
            }
            None => {}
        }
        if state.buffer.is_empty() {
            if state.finished || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            state.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let len = state.buffer.len().min(buf.remaining());
        let (front, back) = state.buffer.as_slices();
        let from_front = len.min(front.len());
        buf.put_slice(&front[..from_front]);
        buf.put_slice(&back[..len - from_front]);
        state.buffer.drain(..len);
        if let Some(writer) = state.writer.take() {
            writer.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl RecvStream for MemoryRecv {
    fn stop(&mut self, code: StreamCode) {
        let read_to_the_end = {
            let state = self.pipe.lock();
            state.finished && state.buffer.is_empty()
        };
        if !read_to_the_end {
            self.pipe.abort(Abort::Stopped(code));
        }
    }
}

impl Drop for MemoryRecv {
    fn drop(&mut self) {
        self.stop(DROPPED_RECV);
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    /// 从 1 号节点到 2 号节点开一条流，返回两头。
    async fn stream() -> ((MemorySend, MemoryRecv), IncomingStream) {
        let mesh = MemoryMesh::new();
        let (opener, _) = mesh.join(node(1));
        let (_, acceptor) = mesh.join(node(2));
        let near = opener.open(node(2)).await.unwrap();
        let far = acceptor.accept().await.unwrap();
        (near, far)
    }

    #[tokio::test]
    async fn the_acceptor_learns_who_opened_the_stream() {
        let (_near, far) = stream().await;
        assert_eq!(far.peer, node(1));
    }

    #[tokio::test]
    async fn data_flows_both_ways_and_shutdown_is_a_clean_end() {
        let ((mut send, mut recv), mut far) = stream().await;
        send.write_all(b"ping").await.unwrap();
        send.shutdown().await.unwrap();
        let mut got = Vec::new();
        far.recv.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");

        far.send.write_all(b"pong").await.unwrap();
        far.send.shutdown().await.unwrap();
        got.clear();
        recv.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"pong");
    }

    #[tokio::test]
    async fn reset_reaches_the_reader_with_its_code_even_past_unread_data() {
        let ((mut send, _recv), mut far) = stream().await;
        send.write_all(b"half a response").await.unwrap();
        send.reset(StreamCode(7));
        let error = far.recv.read(&mut [0; 64]).await.unwrap_err();
        assert_eq!(StreamAborted::of(&error), Some(StreamAborted::Reset(StreamCode(7))));
    }

    #[tokio::test]
    async fn dropping_the_sender_without_shutdown_is_a_reset() {
        let ((mut send, _recv), mut far) = stream().await;
        send.write_all(b"truncated").await.unwrap();
        drop(send);
        let error = far.recv.read(&mut [0; 64]).await.unwrap_err();
        assert_eq!(StreamAborted::of(&error), Some(StreamAborted::Reset(StreamCode(u32::MAX))));
    }

    #[tokio::test]
    async fn reset_after_a_clean_end_changes_nothing() {
        let ((mut send, _recv), mut far) = stream().await;
        send.write_all(b"complete").await.unwrap();
        send.shutdown().await.unwrap();
        send.reset(StreamCode(7));
        drop(send);
        let mut got = Vec::new();
        far.recv.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"complete");
    }

    #[tokio::test]
    async fn stop_reaches_the_writer_with_its_code() {
        let ((mut send, _recv), mut far) = stream().await;
        far.recv.stop(StreamCode(9));
        let error = send.write_all(b"unwanted").await.unwrap_err();
        assert_eq!(StreamAborted::of(&error), Some(StreamAborted::Stopped(StreamCode(9))));
        let error = send.shutdown().await.unwrap_err();
        assert_eq!(StreamAborted::of(&error), Some(StreamAborted::Stopped(StreamCode(9))));
    }

    #[tokio::test]
    async fn stop_wakes_a_writer_blocked_on_a_full_pipe() {
        let ((mut send, _recv), mut far) = stream().await;
        let writer = tokio::spawn(async move { send.write_all(&vec![0; 4 * PIPE_CAPACITY]).await });
        tokio::task::yield_now().await;
        far.recv.stop(StreamCode(3));
        let error = writer.await.unwrap().unwrap_err();
        assert_eq!(StreamAborted::of(&error), Some(StreamAborted::Stopped(StreamCode(3))));
    }

    #[tokio::test]
    async fn a_full_pipe_holds_the_writer_back_until_the_reader_catches_up() {
        let ((mut send, _recv), mut far) = stream().await;
        let payload: Vec<u8> = (0..=u8::MAX).cycle().take(4 * PIPE_CAPACITY + 7).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            send.write_all(&payload).await.unwrap();
            send.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        far.recv.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn partition_breaks_streams_without_a_code_and_blocks_new_ones() {
        let mesh = MemoryMesh::new();
        let (opener, _) = mesh.join(node(1));
        let (_, acceptor) = mesh.join(node(2));
        let (mut send, mut recv) = opener.open(node(2)).await.unwrap();
        let mut far = acceptor.accept().await.unwrap();

        mesh.partition(node(2), node(1));
        for error in [
            send.write_all(b"x").await.unwrap_err(),
            recv.read(&mut [0; 8]).await.unwrap_err(),
            far.send.write_all(b"x").await.unwrap_err(),
            far.recv.read(&mut [0; 8]).await.unwrap_err(),
        ] {
            assert_eq!(StreamAborted::of(&error), None, "连接断开不是对端主动结束");
        }
        assert_eq!(opener.open(node(2)).await.unwrap_err(), OpenError::NoRoute(node(2)));

        mesh.heal(node(1), node(2));
        assert!(opener.open(node(2)).await.is_ok());
    }

    #[tokio::test]
    async fn opening_to_a_node_that_never_joined_fails() {
        let mesh = MemoryMesh::new();
        let (opener, _) = mesh.join(node(1));
        assert_eq!(opener.open(node(9)).await.unwrap_err(), OpenError::UnknownPeer(node(9)));
    }
}
