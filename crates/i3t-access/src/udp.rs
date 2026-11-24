//! UDP 的入口：SOCKS5 的 UDP ASSOCIATE（[`association`]）和 UDP 的端口转发（[`forward`]）。
//!
//! 两者到对端节点走的都是数据报上下文（[`i3t_flow::datagram`]）。上下文是用到的时候才开的，开的时候要等对端答应，
//! 所以每个上下文有一个自己的任务：它去开上下文，开好之前到的报文在它的队列里等着，队列满了丢新来的。
//! 因此收包循环不会阻塞等待，单个不可达对端不会拖慢发往其他对端的报文。

pub(crate) mod association;
pub(crate) mod forward;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use i3t_conn::Connector;
use i3t_conn::contract::Datagrams;
use i3t_flow::FlowError;
use i3t_flow::datagram::Context;
use i3t_proto::NodeId;
use i3t_proto::flow::{Class, Origin};
use tokio::sync::mpsc;
use tokio::time;

use crate::session::Shared;

/// 一个上下文里排着等发的报文最多多少个。上下文还在开的时候，后到的报文在这里等。
const OUTGOING_BACKLOG: usize = 64;

/// 开上下文失败之后，多久之内发往那个对端的报文直接丢掉。
/// 若无该冷却时间，对端不可达（或拒绝）时每个报文都会反复尝试建立流。
const RETRY_PAUSE: Duration = Duration::from_secs(5);

/// 一个 UDP 报文最长这么多，收的缓冲区按它开。
const MAX_UDP_PAYLOAD: usize = 65_535;

/// 到对端节点的一个数据报上下文，流的类型跟着连接层走。
type MeshContext<C> = Context<<C as Connector>::Send, <C as Connector>::Recv, <C as Datagrams>::Sender>;

/// 到 `peer` 开一个上下文。失败时记一行日志，把这段时间里排进 `queue` 的报文都丢掉，然后返回错误。
async fn open_context<C: Connector + Datagrams, T>(
    shared: &Arc<Shared<C>>,
    peer: NodeId,
    class: Class,
    origin: Origin,
    queue: &mut mpsc::Receiver<T>,
) -> Result<MeshContext<C>, FlowError> {
    match shared.opener.open(peer, class, origin).await {
        Ok(context) => Ok(context),
        Err(error) => {
            tracing::info!(%peer, ?error, "到对端节点建立数据报上下文失败，{RETRY_PAUSE:?} 内发往该节点的 UDP 报文将被丢弃");
            let discard = async { while queue.recv().await.is_some() {} };
            // 到时间了，或者发报文的一方已经不在了，都是不用再等。
            let _ = time::timeout(RETRY_PAUSE, discard).await;
            Err(error)
        }
    }
}

/// 把一个报文复制出来，交给上下文的任务。
fn owned(payload: &[u8]) -> Bytes {
    Bytes::copy_from_slice(payload)
}
