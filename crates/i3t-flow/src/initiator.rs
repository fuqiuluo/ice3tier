//! 发起方：开流、发 OPEN、等 REPLY。

use std::fmt;
use std::future::{self, Future};
use std::time::Instant;

use i3t_conn::{Connector, Payload, RecvStream, SendStream, StreamCode};
use i3t_proto::NodeId;
use i3t_proto::flow::{Class, Open, OpenPing, Reason};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::meter::{Meter, Unmetered};
use crate::relay::{self, Flow, Parts, Summary, TcpRole};
use crate::{FlowError, header};

/// 一条承载 TCP 连接的流可以怎么走（ice3proxy 只归选了它的代理）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carriage {
    /// 仅走节点对之间的共用连接（[`Connector::open`]）：包括端口转发（监听侧及中间节点到目标节点段）、
    /// 本机配置文件中的组网入口，以及未启用 ice3proxy 的代理。即使对端间已预备 ice3proxy 也不使用。
    Shared,
    /// 对端间已预备 ice3proxy 且可开启 lane 时走 lane，否则回退到共用连接（[`Connector::open_tcp`]，由连接层决定）。
    /// 用于启用 ice3proxy 的代理流。
    Lane,
}

/// 到 `peer` 开一条承载 TCP 连接的流，把 OPEN 和调用者的首批数据一次写出去。`carriage` 说它能不能走 ice3proxy。
///
/// 和 `peer` 之间已经有连接时不加任何往返：OPEN 和首批数据在同一次写里。
/// 这一端往对端发数据的优先级按 OPEN 里的服务等级来，首批数据也是。
///
/// 失败之后不会自己重试，调用者也不应该原样重放：OPEN 一旦发出，连接断了就无从知道对端有没有把首批数据交给目标，
/// 重放可能让一个非幂等的请求被执行两次。
///
/// # Errors
///
/// 开流失败（对端不可达、连接断开）返回 [`FlowError::Connect`]，头没有写出去返回 [`FlowError::Write`]。
pub async fn open<C: Connector>(
    connector: &C,
    peer: NodeId,
    request: &Open,
    first_data: &[u8],
    carriage: Carriage,
) -> Result<Pending<C::Send, C::Recv>, FlowError> {
    let started = Instant::now();
    let (mut send, recv) = match carriage {
        Carriage::Shared => connector.open(peer).await?,
        Carriage::Lane => connector.open_tcp(peer).await?,
    };
    send.set_priority(relay::priority_of(request.class));
    let mut bytes = Vec::with_capacity(Open::MAX_LEN + first_data.len());
    request.encode(&mut bytes);
    bytes.extend_from_slice(first_data);
    send.write_all(&bytes).await.map_err(FlowError::Write)?;
    // 首批数据本身就是 TLS 时，跑在 ice3proxy 上的流之后不再加密第二次。
    send.end_header(Payload::for_first_data(first_data));
    Ok(Pending { send, recv, class: request.class, started })
}

/// 在和 `peer` 的连接上量一个往返（`i3t ping`）：开一条流（不走 ice3proxy），写一个往返测量的 OPEN，等对端的 REPLY。
/// 返回从写出 OPEN 到读到 REPLY 用了多久。
///
/// 和 `peer` 之间还没有连接时，这一次包括建立连接的时间；要量连接本身的往返，先调一次把连接建起来。
///
/// # Errors
///
/// 开流失败返回 [`FlowError::Connect`]；对端的访问规则不允许本节点访问它时是 [`FlowError::Refused`]（状态是
/// [`Status::AccessDenied`](i3t_proto::flow::Status::AccessDenied)）；若对端版本过旧无法识别此类 OPEN，会以
/// [`Reason::ProtocolError`] 重置流，此处表现为 [`FlowError::Read`]。
pub async fn ping<C: Connector>(connector: &C, peer: NodeId) -> Result<std::time::Duration, FlowError> {
    let (mut send, mut recv) = connector.open(peer).await?;
    send.set_priority(relay::priority_of(Class::Interactive));
    let mut bytes = Vec::with_capacity(OpenPing::LEN);
    OpenPing.encode(&mut bytes);
    let started = Instant::now();
    send.write_all(&bytes).await.map_err(FlowError::Write)?;
    let reply = header::read_reply(&mut recv).await;
    let elapsed = started.elapsed();
    // 回答之后对端就结束了它那个方向；这一端也正常结束，读不读到 EOF 都无所谓。
    let _ = send.shutdown().await;
    match reply {
        Ok(reply) if reply.status.is_ok() => Ok(elapsed),
        Ok(reply) => Err(FlowError::Refused(reply)),
        Err(error) => Err(error),
    }
}

/// 已经发出 OPEN、还没有读 REPLY 的流。
///
/// 接下来二选一：[`established`](Self::established) 等对端说连上了再往下走，客户端能拿到准确的错误；
/// [`relay`](Self::relay) 不等，省一个全程往返，代价是失败只能表现为连接被重置（乐观回复）。
pub struct Pending<S, R> {
    send: S,
    recv: R,
    class: Class,
    started: Instant,
}

/// 契约没有要求流实现 `Debug`，所以这里不打印它们。
impl<S, R> fmt::Debug for Pending<S, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending").field("started", &self.started).finish_non_exhaustive()
    }
}

impl<S: SendStream, R: RecvStream> Pending<S, R> {
    /// 等对端的 REPLY。
    ///
    /// 这里不设时限：对端连接目标有它自己的时限，连接断开时流会出错。
    ///
    /// # Errors
    ///
    /// 对端拒绝时返回 [`FlowError::Refused`]，里面是它给的状态和说明（对端没读 OPEN 就以访问规则为由重置了流时，
    /// 状态为 [`Status::AccessDenied`](i3t_proto::flow::Status::AccessDenied)）；读取 REPLY 失败或其格式不合法时返回对应错误。
    /// 出错时这条流已经被放弃。
    pub async fn established(mut self) -> Result<Flow<S, R>, FlowError> {
        let failure = match header::read_reply(&mut self.recv).await {
            Ok(reply) if reply.status.is_ok() => return Ok(Flow::new(self.parts(false))),
            Ok(reply) => FlowError::Refused(reply),
            Err(error) => error,
        };
        let reason = failure.reset_reason();
        self.send.reset(StreamCode(reason.to_wire()));
        self.recv.stop(StreamCode(reason.to_wire()));
        Err(failure)
    }

    /// 不等 REPLY，直接在这条流和客户端的连接之间搬运。
    ///
    /// REPLY 在往客户端搬运的那个方向上读：对端拒绝了，或者流出了别的问题，客户端的连接被重置（RST），
    /// 结果在 [`Summary::end`] 里。
    pub async fn relay(self, client: TcpStream) -> Summary {
        relay::run(self.parts(true), client, future::pending(), &Unmetered, None).await
    }

    /// 和 [`relay`](Self::relay) 一样，只是可以取消（`cancel` 完成时用它给的原因码结束），每一段数据写出去之前先过 `meter`。
    pub async fn relay_metered(self, client: TcpStream, cancel: impl Future<Output = Reason>, meter: &impl Meter) -> Summary {
        relay::run(self.parts(true), client, cancel, meter, None).await
    }

    fn parts(self, reply_pending: bool) -> Parts<S, R> {
        Parts { send: self.send, recv: self.recv, role: TcpRole::Client, class: self.class, started: self.started, reply_pending }
    }
}
