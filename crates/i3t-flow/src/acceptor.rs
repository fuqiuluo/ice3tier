//! 接受方：读 OPEN，交给处理者，回 REPLY。

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use i3t_conn::contract::{DatagramSender, Datagrams};
use i3t_conn::{Acceptor, Incoming, RecvStream, SendStream, StreamCode};
use i3t_proto::NodeId;
use i3t_proto::flow::{Open, OpenDatagrams, Opening, Reason, Recipient, Reply, Status};
use tokio::io::AsyncWriteExt;
use tokio::time;

use crate::datagram::{self, Mux};
use crate::measure::MeasureRequest;
use crate::relay::{self, Flow, Parts, TcpRole};
use crate::{FlowError, header};

/// [`serve`] 等一条流的 OPEN 等多久。OPEN 是和流一起到的，正常情况下不用等；这个时限只是不让空流一直占着。
pub const OPEN_DEADLINE: Duration = Duration::from_secs(10);

/// 拒绝时 REPLY 最多花多久送出去。REPLY 很短，送不出去说明发起方不收（不给流量控制的额度），不为它一直占着这条流。
const REFUSE_DEADLINE: Duration = Duration::from_secs(5);

/// 一条已经读出 OPEN、还没有应答的流。
///
/// 处理者要么 [`accept`](Self::accept)，要么 [`refuse`](Self::refuse)。什么都不做就丢弃，对端看到的是流被重置。
pub struct Request<S, R> {
    peer: NodeId,
    open: Open,
    send: S,
    recv: R,
    received: Instant,
}

/// 契约没有要求流实现 `Debug`，所以这里不打印它们。
impl<S, R> fmt::Debug for Request<S, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request").field("peer", &self.peer).field("open", &self.open).finish_non_exhaustive()
    }
}

/// 对端开过来的一条流上读出来的 OPEN：它要一条流、一个数据报上下文、一条测量流，还是只量一个往返。
pub(crate) enum Arrival<S, R> {
    Stream(Request<S, R>),
    Datagrams(DatagramArrival<S, R>),
    Measure(MeasureRequest<S, R>),
    Ping { peer: NodeId, send: S, recv: R },
}

/// 一条读出了数据报上下文的 OPEN 的流。
pub(crate) struct DatagramArrival<S, R> {
    pub peer: NodeId,
    pub open: OpenDatagrams,
    pub send: S,
    pub recv: R,
}

impl<S: SendStream, R: RecvStream> Arrival<S, R> {
    /// 从对端开过来的流上读 OPEN，最多等 `deadline`。出错时流已经被重置，原因码是 [`Reason::ProtocolError`]。
    pub(crate) async fn read(incoming: Incoming<S, R>, deadline: Duration) -> Result<Self, FlowError> {
        let Incoming { peer, mut send, mut recv } = incoming;
        let outcome = time::timeout(deadline, header::read_open(&mut recv)).await;
        match outcome.unwrap_or(Err(FlowError::Deadline(deadline))) {
            Ok(Opening::Stream(open)) => Ok(Self::Stream(Request { peer, open, send, recv, received: Instant::now() })),
            Ok(Opening::Datagrams(open)) => Ok(Self::Datagrams(DatagramArrival { peer, open, send, recv })),
            Ok(Opening::Measure(open)) => Ok(Self::Measure(MeasureRequest { peer, open, send, recv })),
            Ok(Opening::Ping(_)) => Ok(Self::Ping { peer, send, recv }),
            Err(error) => {
                let code = StreamCode(Reason::ProtocolError.to_wire());
                send.reset(code);
                recv.stop(code);
                Err(error)
            }
        }
    }
}

impl<S: SendStream, R: RecvStream> Request<S, R> {
    /// 从对端开过来的流上读 OPEN，最多等 `deadline`。
    ///
    /// # Errors
    ///
    /// OPEN 没有按时到、不合法，或者流先出了错；对端要的是数据报上下文时是 [`FlowError::NotAStream`]
    /// （要两种都接受的话用 [`serve`]）。这时流已经被重置，原因码是 [`Reason::ProtocolError`]。
    pub async fn read(incoming: Incoming<S, R>, deadline: Duration) -> Result<Self, FlowError> {
        match Arrival::read(incoming, deadline).await? {
            Arrival::Stream(request) => Ok(request),
            Arrival::Datagrams(DatagramArrival { mut send, mut recv, .. })
            | Arrival::Measure(MeasureRequest { mut send, mut recv, .. })
            | Arrival::Ping { mut send, mut recv, .. } => {
                let code = StreamCode(Reason::ProtocolError.to_wire());
                send.reset(code);
                recv.stop(code);
                Err(FlowError::NotAStream)
            }
        }
    }

    /// 发起该流的节点，来源经连接握手认证，不可伪造。
    #[must_use]
    pub fn peer(&self) -> NodeId {
        self.peer
    }

    #[must_use]
    pub fn open(&self) -> &Open {
        &self.open
    }

    /// OPEN 读完的时刻。[`Flow::relay`] 报告的首字节时间从这里算起，所以包含了连接目标花的时间。
    #[must_use]
    pub fn received(&self) -> Instant {
        self.received
    }

    /// 目标已经连上：回一个成功的 REPLY，之后可以搬运。
    ///
    /// 这一端往发起方发数据的优先级从这里起按 OPEN 里的服务等级来。
    ///
    /// 发起方选了不再加密（它的首批数据是 TLS 1.3 的 ClientHello）时，这个方向不在这里切换：目标会怎么回还不知道。
    /// 搬运时看到目标回了 TLS 1.3 的 ServerHello 才切换（[`i3t_conn::ServerHelloWatch`]），发起方的方向再跟着它。
    ///
    /// # Errors
    ///
    /// REPLY 没有写出去（发起方已经放弃了这条流，或者连接断了）。
    pub async fn accept(mut self) -> Result<Flow<S, R>, FlowError> {
        let class = self.open.class;
        self.send.set_priority(relay::priority_of(class));
        let mut bytes = Vec::with_capacity(Reply::MAX_LEN);
        Reply::ok().encode(&mut bytes);
        self.send.write_all(&bytes).await.map_err(FlowError::Write)?;
        let (send, recv) = (self.send, self.recv);
        Ok(Flow::new(Parts { send, recv, role: TcpRole::Target, class, started: self.received, reply_pending: false }))
    }

    /// 拒绝：把 `reply` 发回去，然后结束这条流。
    ///
    /// 发送方向是正常结束的，这样 REPLY 一定送得到；接收方向叫停，让发起方别再发数据。
    /// 若发起方已断开，REPLY 无法送达且已无必要，因此此处不返回错误。
    pub async fn refuse(mut self, reply: &Reply) {
        refuse(self.peer, &mut self.send, &mut self.recv, reply).await;
    }
}

/// 把拒绝的 `reply` 发回去，然后结束这条流。流和数据报上下文的拒绝是同一个做法。
///
/// 先叫停接收方向：发起方别再发数据，已经到了、还没读的数据随之丢掉，不再占本端的内存。
/// 发送方向是正常结束的，这样 REPLY 一定送得到；[`REFUSE_DEADLINE`] 之内送不出去就重置。
pub(crate) async fn refuse(peer: NodeId, send: &mut impl SendStream, recv: &mut impl RecvStream, reply: &Reply) {
    debug_assert!(!reply.status.is_ok(), "拒绝时不能回成功的状态");
    let code = StreamCode(Reason::Cancelled.to_wire());
    recv.stop(code);
    let mut bytes = Vec::with_capacity(Reply::MAX_LEN);
    reply.encode(&mut bytes);
    let sent = async {
        send.write_all(&bytes).await?;
        send.shutdown().await
    };
    match time::timeout(REFUSE_DEADLINE, sent).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(%peer, %error, "发送拒绝 REPLY 失败"),
        Err(_) => {
            tracing::debug!(%peer, "拒绝 REPLY 在 {REFUSE_DEADLINE:?} 内未发送完成，重置流");
            send.reset(code);
        }
    }
}

/// 回答一个往返测量（`i3t ping`）：一个成功的 REPLY，然后正常结束这条流。
///
/// 能走到这里的对端已经过了 [`Handler::screen`]（访问规则、每个对端的流数上限），所以不再查别的。
/// REPLY 只有两个字节，不比对端发来的 OPEN 长，没有放大。
async fn answer_ping(peer: NodeId, mut send: impl SendStream, mut recv: impl RecvStream) {
    recv.stop(StreamCode(Reason::Cancelled.to_wire()));
    let mut bytes = Vec::with_capacity(Reply::MAX_LEN);
    Reply::ok().encode(&mut bytes);
    let answered = async {
        send.write_all(&bytes).await?;
        send.shutdown().await
    };
    match time::timeout(REFUSE_DEADLINE, answered).await {
        Ok(Ok(())) => tracing::trace!(%peer, "已响应往返测量请求"),
        Ok(Err(error)) => tracing::debug!(%peer, %error, "发送往返测量响应失败"),
        Err(_) => send.reset(StreamCode(Reason::Cancelled.to_wire())),
    }
}

/// 对端开过来的一条流在读 OPEN 之前怎么处理，由 [`Handler::screen`] 决定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screening {
    /// 读它的 OPEN，交给处理者。
    Admit,
    /// 它发来的东西一个字节也不读，回这个拒绝。
    Refuse(Reply),
    /// 不读也不回，两个方向带着这个原因码立刻重置。
    Reset(Reason),
}

/// [`serve`] 手上每个对端各有多少条流：还在读 OPEN 的，和处理者还没处理完的。
#[derive(Debug, Default)]
struct InProgress {
    counts: Mutex<HashMap<NodeId, usize>>,
}

impl InProgress {
    fn of(&self, peer: NodeId) -> usize {
        self.counts.lock().expect("in-progress mutex poisoned").get(&peer).copied().unwrap_or(0)
    }

    /// 给 `peer` 记上一条。返回的守卫被丢弃时减回去。
    fn enter(self: &Arc<Self>, peer: NodeId) -> InProgressEntry {
        *self.counts.lock().expect("in-progress mutex poisoned").entry(peer).or_insert(0) += 1;
        InProgressEntry { tally: Arc::clone(self), peer }
    }
}

/// 一条流在 [`InProgress`] 里占着的那一个数。
struct InProgressEntry {
    tally: Arc<InProgress>,
    peer: NodeId,
}

impl Drop for InProgressEntry {
    fn drop(&mut self) {
        let mut counts = self.tally.counts.lock().expect("in-progress mutex poisoned");
        if let Some(count) = counts.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.peer);
            }
        }
    }
}

/// 处理对端开过来的流。出口模块实现它。
pub trait Handler: Send + Sync + 'static {
    /// 对端开过来一条流、还没有读它的 OPEN 时问一次：这时就能下结论的拒绝在这里给出，被拒绝的流一个字节也不读。
    ///
    /// `in_progress` 是 [`serve`] 手上这个对端已经有多少条流（还在读 OPEN 的、处理者还没处理完的、数据报上下文都算），
    /// 不含这一条。这里不能等待：每条流都要经过它，它慢了所有对端的流都跟着慢。
    ///
    /// 默认一律放行。
    fn screen(&self, peer: NodeId, in_progress: usize) -> Screening {
        let _ = (peer, in_progress);
        Screening::Admit
    }

    /// 处理一条流直到它结束。每条流在自己的任务里调用，互不阻塞。
    fn handle<S: SendStream, R: RecvStream>(&self, request: Request<S, R>) -> impl Future<Output = ()> + Send;

    /// 处理对端要建立的一个数据报上下文，直到它结束。每个上下文在自己的任务里调用。
    ///
    /// 不处理数据报的实现不用写它：默认拒绝。
    fn handle_datagrams<S: SendStream, R: RecvStream, T: DatagramSender>(
        &self,
        request: datagram::Request<S, R, T>,
    ) -> impl Future<Output = ()> + Send {
        async move { request.refuse(&Reply::new(Status::NotEnabled, "当前节点不接受数据报上下文")).await }
    }

    /// 处理对端开过来的一条测量流（主动测试量吞吐用，见 [`crate::measure`]），直到它结束。每条在自己的任务里调用。
    ///
    /// 不提供测量服务的实现不用写它：默认拒绝。
    fn handle_measure<S: SendStream, R: RecvStream>(&self, request: MeasureRequest<S, R>) -> impl Future<Output = ()> + Send {
        async move { request.refuse(&Reply::new(Status::NotEnabled, "当前节点不提供测量服务")).await }
    }
}

/// 接受对端开过来的流，读出 OPEN 之后交给 `handler`，直到 `acceptor` 关闭。
///
/// 每条流先过 [`Handler::screen`]，被拒绝的不读 OPEN。放行的流交给 [`Handler::handle`]，
/// 数据报上下文交给 [`Handler::handle_datagrams`]，各自一个任务。
/// 对端在上下文里发来的数据报也是在这里分给各个上下文的，所以同一个 `acceptor` 上只应该有一个 `serve` 在跑。
/// 这个函数返回之后，已经在处理的流不受影响，继续跑到自己结束；数据报上下文收不到新的数据报。
pub async fn serve<A: Acceptor + Datagrams, H: Handler>(acceptor: &A, handler: Arc<H>) {
    let mux = Mux::new(Recipient::Acceptor);
    let transport = acceptor.datagram_sender();
    let in_progress = Arc::new(InProgress::default());
    let pump = mux.pump(acceptor);
    tokio::pin!(pump);
    let mut pumping = true;
    loop {
        let incoming = tokio::select! {
            incoming = acceptor.accept() => incoming,
            // 数据报接收端先结束时，仍继续接受流直至 `acceptor` 关闭。
            () = &mut pump, if pumping => {
                pumping = false;
                continue;
            }
        };
        let Some(mut incoming) = incoming else { return };
        let peer = incoming.peer;
        match handler.screen(peer, in_progress.of(peer)) {
            Screening::Admit => {}
            Screening::Reset(reason) => {
                let code = StreamCode(reason.to_wire());
                incoming.send.reset(code);
                incoming.recv.stop(code);
                continue;
            }
            Screening::Refuse(reply) => {
                drop(tokio::spawn(async move {
                    let Incoming { peer, mut send, mut recv } = incoming;
                    refuse(peer, &mut send, &mut recv, &reply).await;
                }));
                continue;
            }
        }
        let entry = in_progress.enter(peer);
        let (handler, mux, transport) = (Arc::clone(&handler), Arc::clone(&mux), transport.clone());
        tokio::spawn(async move {
            let _entry = entry;
            match Arrival::read(incoming, OPEN_DEADLINE).await {
                Ok(Arrival::Stream(request)) => handler.handle(request).await,
                Ok(Arrival::Datagrams(arrival)) => handler.handle_datagrams(datagram::Request::new(arrival, mux, transport)).await,
                Ok(Arrival::Measure(request)) => handler.handle_measure(request).await,
                Ok(Arrival::Ping { peer, send, recv }) => answer_ping(peer, send, recv).await,
                // 对端每开一条这样的流就是一行，不记成 info：不然它能拿日志刷屏。
                Err(error) => tracing::debug!(%peer, ?error, "未读取到合法的 OPEN，已重置流"),
            }
        });
    }
}
