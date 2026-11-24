//! 共用的连接和 ice3proxy 装在一起：上层还是只看到一个 [`Connector`]、一个 [`Acceptor`]。
//!
//! - [`LaneConnector`]：[`Connector::open_tcp`]（承载 TCP 连接的流）在调用方选择函数指示该对端使用 lane
//!   且当前可成功获取 lane 时走 lane；获取失败（池耗尽超时、控制 lane 未建立、对端正在排空、拨号失败）时静默回退到共用连接
//!   并计入一次回退。此时开流请求尚未发送任何字节，切换传输不会导致重复执行。
//!   别的流（[`Connector::open`]，例如数据报上下文）和数据报一律走共用的连接。
//! - [`LaneAcceptor`]：两边开过来的流排在同一个接受队列里，交给同一个 `serve`，接受方的筛选、
//!   每个对端同时处理的流数、访问规则、排空对两种流一视同仁。
//!
//! 已经在跑的流不会换传输。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use i3t_conn::contract::{Datagram, Datagrams, Priority};
use i3t_conn::{Acceptor, Connector, Incoming, OpenError, Payload, RawRead, RawWrite, RecvStream, SendStream, StreamCode};
use i3t_proto::NodeId;
use i3t_proto::flow::Recipient;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::endpoint::Lanes;
use crate::stream::{LaneRecv, LaneSend};

/// 调用方决定到一个对端、要求走 ice3proxy 的流（`open_tcp`）现在该不该走 lane：和它之间备没备着，
/// 以及（"UDP 不通时用"时）现在共用连接的路有没有 UDP。
pub type Choose = Arc<dyn Fn(NodeId) -> bool + Send + Sync>;

/// 开流：承载 TCP 连接的流按选择走 lane，其余的走共用的连接 `C`。
pub struct LaneConnector<C> {
    shared: Arc<C>,
    lanes: Arc<Lanes>,
    choose: Choose,
}

impl<C> LaneConnector<C> {
    #[must_use]
    pub fn new(shared: Arc<C>, lanes: Arc<Lanes>, choose: Choose) -> Self {
        Self { shared, lanes, choose }
    }

    /// 共用的连接。
    #[must_use]
    pub fn shared(&self) -> &Arc<C> {
        &self.shared
    }
}

impl<C> std::fmt::Debug for LaneConnector<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneConnector").finish_non_exhaustive()
    }
}

impl<C: Connector> Connector for LaneConnector<C> {
    type Send = EitherSend<C::Send>;
    type Recv = EitherRecv<C::Recv>;

    async fn open(&self, peer: NodeId) -> Result<(Self::Send, Self::Recv), OpenError> {
        let (send, recv) = self.shared.open(peer).await?;
        Ok((EitherSend::Shared(send), EitherRecv::Shared(recv)))
    }

    async fn open_tcp(&self, peer: NodeId) -> Result<(Self::Send, Self::Recv), OpenError> {
        if (self.choose)(peer) {
            match self.lanes.open_stream(peer).await {
                Ok((send, recv)) => return Ok((EitherSend::Lane(send), EitherRecv::Lane(recv))),
                Err(error) => {
                    // 每条回退流记录一条 debug 日志（池耗尽期间可能短时产生大量日志），累计次数可在状态中查看。
                    tracing::debug!(%peer, %error, "开启 lane 失败，该流回退至共用连接");
                    self.lanes.note_fallback(peer);
                }
            }
        }
        let (send, recv) = self.shared.open_tcp(peer).await?;
        Ok((EitherSend::Shared(send), EitherRecv::Shared(recv)))
    }
}

impl<C: Datagrams> Datagrams for LaneConnector<C> {
    type Sender = C::Sender;

    fn datagram_sender(&self) -> C::Sender {
        self.shared.datagram_sender()
    }

    fn recv_datagram(&self, recipient: Recipient) -> impl Future<Output = Option<Datagram>> + Send {
        self.shared.recv_datagram(recipient)
    }
}

/// 接受流：共用的连接 `A` 和 lane 开过来的都从这里出来。
pub struct LaneAcceptor<A> {
    shared: Arc<A>,
    lanes: Arc<Lanes>,
}

impl<A> LaneAcceptor<A> {
    #[must_use]
    pub fn new(shared: Arc<A>, lanes: Arc<Lanes>) -> Self {
        Self { shared, lanes }
    }
}

impl<A> std::fmt::Debug for LaneAcceptor<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneAcceptor").finish_non_exhaustive()
    }
}

impl<A: Acceptor> Acceptor for LaneAcceptor<A> {
    type Send = EitherSend<A::Send>;
    type Recv = EitherRecv<A::Recv>;

    /// 共用的连接关闭（节点在关闭）时返回 `None`。
    async fn accept(&self) -> Option<Incoming<Self::Send, Self::Recv>> {
        // 两边的 accept 都可以取消：被丢掉的那一个没有拿走任何东西。
        tokio::select! {
            incoming = self.shared.accept() => {
                let Incoming { peer, send, recv } = incoming?;
                Some(Incoming { peer, send: EitherSend::Shared(send), recv: EitherRecv::Shared(recv) })
            }
            Some(incoming) = self.lanes.accept() => {
                let Incoming { peer, send, recv } = incoming;
                Some(Incoming { peer, send: EitherSend::Lane(send), recv: EitherRecv::Lane(recv) })
            }
        }
    }
}

impl<A: Datagrams> Datagrams for LaneAcceptor<A> {
    type Sender = A::Sender;

    fn datagram_sender(&self) -> A::Sender {
        self.shared.datagram_sender()
    }

    fn recv_datagram(&self, recipient: Recipient) -> impl Future<Output = Option<Datagram>> + Send {
        self.shared.recv_datagram(recipient)
    }
}

/// 一条流的发送方向：在共用的连接上，或者在一条 lane 上。
#[derive(Debug)]
pub enum EitherSend<S> {
    Shared(S),
    Lane(LaneSend),
}

/// 一条流的接收方向：在共用的连接上，或者在一条 lane 上。
#[derive(Debug)]
pub enum EitherRecv<R> {
    Shared(R),
    Lane(LaneRecv),
}

impl<S> EitherSend<S> {
    /// 这条流是不是在 lane 上。
    #[must_use]
    pub const fn is_lane(&self) -> bool {
        matches!(self, Self::Lane(_))
    }
}

impl<S: SendStream> AsyncWrite for EitherSend<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Shared(send) => Pin::new(send).poll_write(cx, buf),
            Self::Lane(send) => Pin::new(send).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Shared(send) => Pin::new(send).poll_flush(cx),
            Self::Lane(send) => Pin::new(send).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Shared(send) => Pin::new(send).poll_shutdown(cx),
            Self::Lane(send) => Pin::new(send).poll_shutdown(cx),
        }
    }
}

impl<S: SendStream> SendStream for EitherSend<S> {
    fn reset(&mut self, code: StreamCode) {
        match self {
            Self::Shared(send) => send.reset(code),
            Self::Lane(send) => send.reset(code),
        }
    }

    fn set_priority(&mut self, priority: Priority) {
        match self {
            Self::Shared(send) => send.set_priority(priority),
            Self::Lane(send) => send.set_priority(priority),
        }
    }

    fn end_header(&mut self, payload: Payload) {
        match self {
            Self::Shared(send) => send.end_header(payload),
            Self::Lane(send) => send.end_header(payload),
        }
    }

    fn take_raw(&mut self) -> Option<RawWrite> {
        match self {
            Self::Shared(send) => send.take_raw(),
            Self::Lane(send) => send.take_raw(),
        }
    }
}

impl<R: RecvStream> AsyncRead for EitherRecv<R> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Shared(recv) => Pin::new(recv).poll_read(cx, buf),
            Self::Lane(recv) => Pin::new(recv).poll_read(cx, buf),
        }
    }
}

impl<R: RecvStream> RecvStream for EitherRecv<R> {
    fn stop(&mut self, code: StreamCode) {
        match self {
            Self::Shared(recv) => recv.stop(code),
            Self::Lane(recv) => recv.stop(code),
        }
    }

    fn revocation(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        match self {
            Self::Shared(recv) => recv.revocation(),
            Self::Lane(recv) => recv.revocation(),
        }
    }

    fn end_header(&mut self) {
        match self {
            Self::Shared(recv) => recv.end_header(),
            Self::Lane(recv) => recv.end_header(),
        }
    }

    async fn wait_raw(&mut self) -> Option<RawRead> {
        match self {
            Self::Shared(recv) => recv.wait_raw().await,
            Self::Lane(recv) => recv.wait_raw().await,
        }
    }
}
