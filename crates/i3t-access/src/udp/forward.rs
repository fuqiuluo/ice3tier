//! UDP 的端口转发：监听一个 UDP 端口，每个客户端地址是一个会话，会话的报文走到目标节点的一个数据报上下文。
//!
//! - 会话按客户端的地址（IP 加端口）分。一个会话没有报文往来超过空闲时限（默认 60 秒）就回收，客户端再发报文时重新建。
//! - 一条转发同时最多 [`MAX_SESSIONS`] 个会话。UDP 的来源地址可以随便伪造，没有这个上限的话，
//!   往监听端口上乱发报文就能让本节点和目标节点开出无数个上下文。到了上限，新来的客户端要等旧的会话回收。
//!   这个数是目标节点给本节点的上下文名额（`i3t_exit` 里每个对端 128 个）的一半：一条对外开放的转发被人占满时，
//!   本节点到那个节点的别的 UDP（SOCKS5 的 UDP 关联、别的转发）还有名额。
//! - 回环以外的同一个来源（IPv4 的一个地址、IPv6 的一个 /64）在一条转发上最多 [`MAX_SESSIONS_PER_HOST`] 个会话：
//!   互联网上的单台主机即使不断更换源端口，也无法耗尽整条转发的会话配额，其他客户端仍可正常使用。回环来源属于本机程序，不受单来源上限限制：
//!   本机 DNS 解析器等程序通常为每个请求更换源端口，限制过严会导致其无法正常工作。该限制无法防御伪造源地址，需要防护时应配置来源白名单。
//! - 目标节点按转发编号找到要发往的地址；它回来的报文从监听端口发回那个客户端。
//! - 来源白名单逐个报文检查。UDP 没有地方回错误，不通过的报文只是丢掉。监听在本节点虚拟 IP 上的转发另外只收经虚拟网卡来的和本机的
//!   （[`crate::manager::virtual_ip_admits`]）。

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use i3t_conn::Connector;
use i3t_conn::contract::Datagrams;
use i3t_flow::FlowError;
use i3t_model::netmap::{Forward, ForwardProtocol};
use i3t_proto::flow::{Class, Origin, Target};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;
use tracing::Instrument;

use super::{MAX_UDP_PAYLOAD, OUTGOING_BACKLOG, open_context, owned};
use crate::forward_health::TargetCause;
use crate::manager::{Counters, allowed, virtual_ip_admits};
use crate::session::{Shared, origin_address};
use crate::source::SourceHost;
use crate::usage::Tally;

/// 一条转发同时最多多少个会话。
pub(crate) const MAX_SESSIONS: usize = 64;

/// 回环以外的同一个来源在一条转发上同时最多多少个会话。
pub(crate) const MAX_SESSIONS_PER_HOST: usize = 16;

/// 最多为多少个被拒绝的来源地址各记一行日志。
const MAX_LOGGED_REFUSALS: usize = 64;

/// 在 `socket` 上收报文，按客户端地址分给各个会话，直到任务被取消（监听被关掉）。
///
/// `counters` 记这条转发现在有多少个会话、搬了多少字节。转发的设置每个报文都从当前的 netmap 里取，所以改白名单不用重新绑定。
/// `bind` 是配置里写的地址（端口可能是 0），用它在 netmap 里认出这条转发。
pub(crate) async fn serve<C: Connector + Datagrams>(
    shared: Arc<Shared<C>>,
    id: u32,
    bind: SocketAddr,
    socket: UdpSocket,
    counters: Counters,
) {
    let socket = Arc::new(socket);
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<Bytes>> = HashMap::new();
    let mut refused: HashSet<IpAddr> = HashSet::new();
    let mut buf = vec![0; MAX_UDP_PAYLOAD];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(error) => {
                // 有的系统把上一次发送引起的"端口不可达"报在这里。它不影响这个端口继续用。
                tracing::debug!(%error, "端口转发的 UDP 端口收报文时出错");
                continue;
            }
        };
        let netmap = Arc::clone(&shared.netmap.borrow());
        let current = netmap.me.forwards.iter().find(|forward| forward.id == id && forward.bind == bind);
        // 未找到说明该转发刚从 netmap 中移除，监听器即将关闭。
        let Some(forward) = current.filter(|forward| forward.protocol == ForwardProtocol::Udp) else { continue };
        if !allowed(&forward.allow_from, from) {
            if refused.len() < MAX_LOGGED_REFUSALS && refused.insert(from.ip()) {
                tracing::info!(%from, "已丢弃 UDP 报文：来源地址不在该端口转发的白名单中（同一来源后续不再重复记录）");
            }
            continue;
        }
        if !virtual_ip_admits(&netmap, forward.bind, from) {
            if refused.len() < MAX_LOGGED_REFUSALS && refused.insert(from.ip()) {
                tracing::info!(%from, "已丢弃 UDP 报文：该端口监听在本节点虚拟 IP 上，来源既非本机，也非有权访问本节点的对端节点（同一来源后续不再重复记录）");
            }
            continue;
        }

        if sessions.get(&from).is_none_or(mpsc::Sender::is_closed) {
            sessions.retain(|_, queue| !queue.is_closed());
            if sessions.len() >= MAX_SESSIONS {
                tracing::debug!(%from, "已丢弃 UDP 报文：该端口转发的会话数已达上限（{MAX_SESSIONS} 个），等待旧会话空闲回收");
                continue;
            }
            let host = SourceHost::of(from);
            if host.is_some() && sessions.keys().filter(|client| SourceHost::of(**client) == host).count() >= MAX_SESSIONS_PER_HOST {
                tracing::debug!(%from, "已丢弃 UDP 报文：该来源在此端口转发上的会话数已达上限（{MAX_SESSIONS_PER_HOST} 个）");
                continue;
            }
            if !netmap.peer(forward.target).is_some_and(|peer| peer.outbound) {
                tracing::debug!(target = %forward.target, "已丢弃 UDP 报文：目标节点不在 netmap 中，或访问规则不允许本节点访问");
                continue;
            }
            if shared.refuse_while_draining("UDP 端口转发的新会话") {
                continue;
            }
            let (queue, outgoing) = mpsc::channel(OUTGOING_BACKLOG);
            let class = forward.class.or(netmap.network.class).unwrap_or_default();
            let session = Session {
                socket: Arc::clone(&socket),
                client: from,
                class,
                active: Active::enter(&counters.active),
                traffic: Arc::clone(&counters.traffic),
            };
            let span = tracing::info_span!("udp-session", client = %from);
            tokio::spawn(session.run(Arc::clone(&shared), forward.clone(), outgoing).instrument(span));
            sessions.insert(from, queue);
        }
        let queued = sessions.get(&from).is_some_and(|queue| queue.try_send(owned(&buf[..len])).is_ok());
        if !queued {
            tracing::trace!(%from, "已丢弃 UDP 报文：到目标节点的数据报上下文尚未就绪或发送队列已满");
        }
    }
}

/// 一个会话占着的计数，会话的任务结束时减回去。
struct Active(Arc<AtomicUsize>);

impl Active {
    fn enter(active: &Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(active))
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 一个客户端地址的会话。
struct Session {
    /// 监听的那个端口：回客户端的报文也从它发，客户端才认得。
    socket: Arc<UdpSocket>,
    client: SocketAddr,
    class: Class,
    active: Active,
    traffic: Arc<Tally>,
}

impl Session {
    /// 开到目标节点的上下文，然后在客户端和上下文之间搬运，直到空闲太久或者上下文结束。
    async fn run<C: Connector + Datagrams>(self, shared: Arc<Shared<C>>, forward: Forward, mut outgoing: mpsc::Receiver<Bytes>) {
        let _active = self.active;
        let origin = Origin { credential: None, client: origin_address(self.client) };
        // 会话能否建立是 UDP 转发唯一可观测的“目标连通性”信号：报文发出后目标是否收到，UDP 协议本身无法反馈。
        let mut context = match open_context(&shared, forward.target, self.class, origin, &mut outgoing).await {
            Ok(context) => {
                shared.forward_health.record(forward.id, Ok(()));
                context
            }
            Err(error) => {
                let cause = match error {
                    FlowError::Refused(reply) => TargetCause::of(reply.status).unwrap_or(TargetCause::Other),
                    _ => TargetCause::NodeUnreachable,
                };
                return shared.forward_health.record(forward.id, Err(cause));
            }
        };
        let sender = context.sender();
        let target = Target::Forward { id: forward.id };
        tracing::debug!(target = %forward.target, "UDP 端口转发的会话建立");

        let idle = time::sleep(shared.udp_idle_timeout);
        tokio::pin!(idle);
        let (mut sent, mut received) = (0u64, 0u64);
        let end = loop {
            tokio::select! {
                queued = outgoing.recv() => match queued {
                    Some(payload) => match sender.send(&target, &payload).await {
                        Ok(()) => {
                            sent += 1;
                            self.traffic.add(true, payload.len());
                        }
                        Err(error) => tracing::debug!(%error, "向目标节点发送 UDP 报文失败"),
                    },
                    // 监听被关掉了。
                    None => break "监听关闭".to_owned(),
                },
                arrived = context.recv() => match arrived {
                    Ok(datagram) => match self.socket.send_to(&datagram.payload, self.client).await {
                        Ok(_) => {
                            received += 1;
                            self.traffic.add(false, datagram.payload.len());
                        }
                        Err(error) => tracing::debug!(%error, "向客户端返回 UDP 报文失败"),
                    },
                    Err(end) => {
                        tracing::info!(target = %forward.target, sent, received, ?end, "UDP 端口转发会话结束：到目标节点的数据报上下文已结束");
                        return;
                    }
                },
                () = &mut idle => break format!("{:?} 没有报文往来", shared.udp_idle_timeout),
            }
            idle.as_mut().reset(time::Instant::now() + shared.udp_idle_timeout);
        };
        context.close().await;
        tracing::info!(target = %forward.target, sent, received, end, "UDP 端口转发的会话结束");
    }
}
