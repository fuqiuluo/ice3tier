//! 数据报上下文：UDP 应用的数据怎么过一对节点。
//!
//! 一个上下文是两个节点之间的一条"UDP 通道"。发起方在一条流上发一个数据报上下文的 OPEN，对端回 REPLY；
//! 之后两边在这个上下文里互相发数据报，每个数据报带着它要去的目标（或者它的来源）。格式在 [`i3t_proto::flow`]。
//!
//! | 谁用 | 入口 | 做什么 |
//! |---|---|---|
//! | 发起方（入口模块） | [`Opener`] | 开上下文：开流、发 OPEN、等 REPLY |
//! | 接受方（出口模块） | [`Request`]，由 [`crate::serve`] 交给 [`crate::Handler::handle_datagrams`] | 接受或者拒绝一个上下文 |
//! | 两边 | [`Context`]、[`ContextSender`] | 收数据报、知道上下文什么时候结束；发数据报 |
//!
//! 那条流在 REPLY 之后不再有数据，它只是上下文的寿命：任何一方正常结束它（[`Context::close`]）、重置它
//! （[`Context::abort`]，或者直接丢弃 [`Context`]），或者连接断了，对面的 [`Context::recv`] 就报告上下文结束。
//!
//! 数据报怎么送看上下文的服务等级（[`Class::keeps_every_datagram`]）：
//!
//! - `auto`、`reliable`、`bulk`：每个数据报单独走一条单向流。不会丢，互相不阻塞，先后不保证；连接来不及发时发送方等着。
//! - `interactive`：走连接上不可靠的数据报通道。连接来不及发时丢最旧的，路上丢了不重传，换来最低的延迟。
//!   比连接一次能发的长的数据报在这里切成几片，对面拼回去；丢了一片，整个报文就没了。
//!
//! 收的一方每个上下文有一个有上限的队列（256 个、半兆字节），取得慢了丢新来的。不丢包的等级也一样：
//! 它们保证的是路上不丢，不是对面的应用来不及收时也不丢。

mod mux;
mod reassembly;
mod socket;

use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use bytes::Bytes;
use i3t_conn::contract::{DatagramSendError, DatagramSender, Datagrams};
use i3t_conn::{Connector, RecvStream, SendStream, StreamAborted, StreamCode};
use i3t_proto::NodeId;
use i3t_proto::flow::{Class, Decoded, Frames, OpenDatagrams, Origin, Reason, Recipient, Reply, SplitError, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time;

pub(crate) use self::mux::Mux;
use self::mux::Registration;
pub use self::socket::OutboundSocket;
use crate::{FlowError, acceptor, header};

/// 发起方等对端的 REPLY 最多等多久。对端只是查一下访问规则、绑一个端口，正常情况下立刻就回。
const REPLY_DEADLINE: Duration = Duration::from_secs(10);

/// 发起方一侧：一个节点自己开的全部数据报上下文。
///
/// 一个节点只应该有一个，并且要让 [`run`](Self::run) 一直跑着：对端发回来的数据报是它分给各个上下文的。
pub struct Opener<C: Datagrams> {
    connector: Arc<C>,
    transport: C::Sender,
    mux: Arc<Mux>,
}

impl<C: Datagrams> fmt::Debug for Opener<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opener").finish_non_exhaustive()
    }
}

impl<C: Connector + Datagrams> Opener<C> {
    pub fn new(connector: Arc<C>) -> Self {
        let transport = connector.datagram_sender();
        Self { connector, transport, mux: Mux::new(Recipient::Initiator) }
    }

    /// 把对端发回来的数据报分给各个上下文，直到连接层关闭。只应该有一个在跑。
    pub async fn run(&self) {
        self.mux.pump(&*self.connector).await;
    }

    /// 到 `peer` 开一个数据报上下文，等它答应。
    ///
    /// 要等到 REPLY 才返回：那时对端已经认得这个上下文，发过去的数据报才有人收。
    /// 和 `peer` 之间还没有连接时先建连接。
    ///
    /// # Errors
    ///
    /// 开流失败返回 [`FlowError::Connect`]；对端拒绝时返回 [`FlowError::Refused`]，里面是它给的状态和说明；
    /// REPLY 迟迟不来返回 [`FlowError::Deadline`]。出错时那条流已经被放弃。
    pub async fn open(&self, peer: NodeId, class: Class, origin: Origin) -> Result<Context<C::Send, C::Recv, C::Sender>, FlowError> {
        let (mut send, mut recv) = self.connector.open(peer).await?;
        // 先登记再发 OPEN：对端一答应就可能发数据报过来。
        let registration = self.mux.allocate(peer);
        let request = OpenDatagrams { context: registration.context(), class, origin };
        let mut bytes = Vec::with_capacity(OpenDatagrams::MAX_LEN);
        request.encode(&mut bytes);
        send.write_all(&bytes).await.map_err(FlowError::Write)?;

        let reply = time::timeout(REPLY_DEADLINE, header::read_reply(&mut recv)).await;
        let failure = match reply.unwrap_or(Err(FlowError::Deadline(REPLY_DEADLINE))) {
            Ok(reply) if reply.status.is_ok() => {
                let sender = ContextSender::new(self.transport.clone(), peer, &request, Recipient::Acceptor);
                return Ok(Context { send, recv, sender, registration });
            }
            Ok(reply) => FlowError::Refused(reply),
            Err(error) => error,
        };
        let reason = failure.reset_reason();
        send.reset(StreamCode(reason.to_wire()));
        recv.stop(StreamCode(reason.to_wire()));
        Err(failure)
    }
}

/// 对端要建立的一个数据报上下文，还没有应答。
///
/// 处理者要么 [`accept`](Self::accept)，要么 [`refuse`](Self::refuse)。什么都不做就丢弃，对端看到的是流被重置。
pub struct Request<S, R, T> {
    peer: NodeId,
    open: OpenDatagrams,
    send: S,
    recv: R,
    mux: Arc<Mux>,
    transport: T,
}

/// 契约没有要求流实现 `Debug`，所以这里不打印它们。
impl<S, R, T> fmt::Debug for Request<S, R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request").field("peer", &self.peer).field("open", &self.open).finish_non_exhaustive()
    }
}

impl<S: SendStream, R: RecvStream, T: DatagramSender> Request<S, R, T> {
    pub(crate) fn new(arrival: acceptor::DatagramArrival<S, R>, mux: Arc<Mux>, transport: T) -> Self {
        let acceptor::DatagramArrival { peer, open, send, recv } = arrival;
        Self { peer, open, send, recv, mux, transport }
    }

    /// 请求建立该上下文的节点，来源经连接握手认证，不可伪造。
    #[must_use]
    pub fn peer(&self) -> NodeId {
        self.peer
    }

    #[must_use]
    pub fn open(&self) -> &OpenDatagrams {
        &self.open
    }

    /// 答应：登记这个上下文，回一个成功的 REPLY。之后对端发来的数据报从返回的 [`Context`] 里出来。
    ///
    /// # Errors
    ///
    /// 对端给的上下文号还在用（[`FlowError::ContextInUse`]，流被重置），或者 REPLY 没有写出去。
    pub async fn accept(mut self) -> Result<Context<S, R, T>, FlowError> {
        // 先登记再回 REPLY：对端读到 REPLY 就会开始发数据报。
        let Some(registration) = self.mux.register(self.peer, self.open.context) else {
            let code = StreamCode(Reason::ProtocolError.to_wire());
            self.send.reset(code);
            self.recv.stop(code);
            return Err(FlowError::ContextInUse(self.open.context));
        };
        let mut bytes = Vec::with_capacity(Reply::MAX_LEN);
        Reply::ok().encode(&mut bytes);
        self.send.write_all(&bytes).await.map_err(FlowError::Write)?;
        let sender = ContextSender::new(self.transport, self.peer, &self.open, Recipient::Initiator);
        Ok(Context { send: self.send, recv: self.recv, sender, registration })
    }

    /// 拒绝：把 `reply` 发回去，然后结束这条流。
    pub async fn refuse(mut self, reply: &Reply) {
        acceptor::refuse(self.peer, &mut self.send, &mut self.recv, reply).await;
    }
}

/// 一个已经建立的数据报上下文的一端。
///
/// 收数据报和知道上下文什么时候结束都在 [`recv`](Self::recv)。发数据报用 [`sender`](Self::sender) 给的句柄：
/// 它可以克隆、可以带进别的任务，也可以在等 `recv` 的同一个 `select!` 里用。
///
/// 没有 [`close`](Self::close) 就丢弃等同于重置：对端看到的是异常结束。
pub struct Context<S, R, T> {
    send: S,
    recv: R,
    sender: ContextSender<T>,
    registration: Registration,
}

/// 契约没有要求流实现 `Debug`，所以这里不打印它们。
impl<S, R, T> fmt::Debug for Context<S, R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context").field("peer", &self.sender.peer).field("context", &self.sender.context).finish_non_exhaustive()
    }
}

impl<S: SendStream, R: RecvStream, T: DatagramSender> Context<S, R, T> {
    /// 上下文另一端的节点。
    #[must_use]
    pub fn peer(&self) -> NodeId {
        self.sender.peer
    }

    /// 这个上下文的服务等级，OPEN 里写的。
    #[must_use]
    pub fn class(&self) -> Class {
        self.sender.class
    }

    /// 发数据报用的句柄，可以克隆、带进别的任务。上下文结束之后用它发的数据报没有人收。
    #[must_use]
    pub fn sender(&self) -> ContextSender<T> {
        self.sender.clone()
    }

    /// 等对端发来的下一个数据报。可以放在 `select!` 里：被取消时不会丢数据报。
    ///
    /// 无法解析内容的数据报会被跳过。上下文结束后，已到达的数据报仍会先交付完毕。
    ///
    /// # Errors
    ///
    /// 上下文结束了：对端正常结束或者重置了那条流，或者连接断了。
    pub async fn recv(&mut self) -> Result<Received, ContextEnd> {
        loop {
            tokio::select! {
                biased;
                Some(body) = self.registration.recv() => match Target::decode(&body) {
                    Ok(Decoded::Complete { value: target, len }) => return Ok(Received { target, payload: body.slice(len..) }),
                    Ok(Decoded::Incomplete { .. }) | Err(_) => {
                        tracing::debug!(peer = %self.sender.peer, "丢弃数据报：载荷开头不是有效的目标地址");
                    }
                },
                end = stream_end(&mut self.recv) => return Err(end),
            }
        }
    }

    /// 正常结束这个上下文。对端的 [`recv`](Self::recv) 报告 [`ContextEnd::Finished`]。
    pub async fn close(mut self) {
        if let Err(error) = self.send.shutdown().await {
            tracing::debug!(peer = %self.sender.peer, %error, "关闭数据报上下文时流已断开");
        }
    }

    /// 异常结束这个上下文，带上 `reason`。对端的 [`recv`](Self::recv) 报告 [`ContextEnd::Aborted`]。
    pub fn abort(mut self, reason: Reason) {
        let code = StreamCode(reason.to_wire());
        self.send.reset(code);
        self.recv.stop(code);
    }
}

/// 等上下文的那条流结束。REPLY 之后流上不该再有数据，有也不看。
async fn stream_end(recv: &mut (impl RecvStream + ?Sized)) -> ContextEnd {
    let mut ignored = [0; 64];
    loop {
        match recv.read(&mut ignored).await {
            Ok(0) => return ContextEnd::Finished,
            Ok(_) => {}
            Err(error) => {
                return match StreamAborted::of(&error) {
                    Some(aborted) => ContextEnd::Aborted(aborted),
                    None => ContextEnd::Lost(error),
                };
            }
        }
    }
}

/// 对端在上下文里发来的一个数据报。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// 发起方发来的：这个数据报要去哪里。接受方发来的：它是从哪里来的。
    pub target: Target,
    pub payload: Bytes,
}

/// 一个上下文是怎么结束的。
#[derive(Debug)]
#[non_exhaustive]
pub enum ContextEnd {
    /// 对端正常结束了它：不再需要，或者它那边空闲太久被回收了。
    Finished,
    /// 对端重置或者叫停了上下文的那条流，里面有它给的原因码。
    Aborted(StreamAborted),
    /// 和对端节点的连接断了。
    Lost(io::Error),
}

/// 往一个上下文里发数据报的句柄。克隆出来的是同一个上下文。
#[derive(Debug, Clone)]
pub struct ContextSender<T> {
    transport: T,
    peer: NodeId,
    context: u32,
    /// 发出去的数据报是给上下文的哪一侧的：对面那一侧。
    to: Recipient,
    class: Class,
    /// 下一个要分片的报文用的报文号。
    next_message: Arc<AtomicU16>,
}

impl<T: DatagramSender> ContextSender<T> {
    fn new(transport: T, peer: NodeId, open: &OpenDatagrams, to: Recipient) -> Self {
        Self { transport, peer, context: open.context, to, class: open.class, next_message: Arc::default() }
    }

    /// 上下文另一端的节点。
    #[must_use]
    pub fn peer(&self) -> NodeId {
        self.peer
    }

    /// 发一个数据报。发起方给的 `target` 是它要去哪里，接受方给的是它从哪里来。
    ///
    /// 默认一个都不丢（[`Class::keeps_every_datagram`]）：这里会等到连接收下这个数据报，对端来不及收时就是在这里等。
    /// 等级是 `interactive` 的上下文不等待，连接来不及发时丢的是排在最前面的旧数据报。
    ///
    /// # Errors
    ///
    /// 数据报太长（[`SendError::Split`]），或者和对端之间的连接不在了（[`SendError::Transport`]）。
    /// 后一种情况下上下文也已经结束了，[`Context::recv`] 会报告。
    pub async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), SendError> {
        let mut body = Vec::with_capacity(Target::MAX_LEN + payload.len());
        target.encode(&mut body);
        body.extend_from_slice(payload);

        if self.class.keeps_every_datagram() {
            // 流没有长度限制，整个内容就是一帧。
            for frame in Frames::split(self.to, self.context, 0, &body, usize::MAX)? {
                self.transport.send_reliable(self.peer, frame.into()).await?;
            }
            return Ok(());
        }
        let max_len = self.transport.max_datagram_len(self.peer).ok_or(DatagramSendError::NotConnected(self.peer))?;
        let message = self.next_message.fetch_add(1, Ordering::Relaxed);
        for frame in Frames::split(self.to, self.context, message, &body, max_len)? {
            self.transport.send_datagram(self.peer, frame.into())?;
        }
        Ok(())
    }
}

/// 数据报发送失败的原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    #[error("数据报无法分片发送")]
    Split(#[from] SplitError),
    #[error("连接未能发送数据报")]
    Transport(#[from] DatagramSendError),
}
