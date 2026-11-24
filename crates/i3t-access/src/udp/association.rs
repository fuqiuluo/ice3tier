//! SOCKS5 的 UDP ASSOCIATE（RFC 1928 §7）。
//!
//! 客户端在一条 TCP 连接上请求之后，入口给它开一个 UDP 中继端口。客户端把报文发到这个端口，每个报文前面带着目标；
//! 目标回来的报文从同一个端口发回客户端，前面带着来源。这条 TCP 连接不传数据，它活着关联就在，它一断关联就结束。
//!
//! - 中继端口绑在客户端连过来的那个本机地址上（所以和监听器是同一个地址族），端口由系统挑。
//! - 只收建立关联的那个客户端发来的报文：来源 IP 必须是 TCP 连接的对端；端口以它发来的第一个报文为准，之后不变。
//!   请求里写了自己的地址和端口、而且地址和 TCP 连接的对端一致的客户端，从一开始就只认那个端口。
//! - 不支持分片：分片号不是 0 的报文直接丢掉，RFC 允许这样。
//! - 每个报文往哪里去，判断和 CONNECT 完全一样（[`crate::route`]）：用户名指定出口，组网地址是那个节点自己的服务，
//!   其余按监听器的默认动作。同一个关联里发往不同节点的报文各走各的上下文，每个节点一个，用到时才开。
//! - UDP 没有地方回错误：被拒绝的目标只记日志（每个目标一行），报文丢掉。

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use i3t_conn::Connector;
use i3t_conn::contract::Datagrams;
use i3t_flow::datagram::Received;
use i3t_model::Netmap;
use i3t_proto::NodeId;
use i3t_proto::flow::{Class, Host, Origin, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::Instrument;

use super::{MAX_UDP_PAYLOAD, OUTGOING_BACKLOG, open_context, owned};
use crate::entry::Entry;
use crate::route::{self, Route};
use crate::session::Shared;
use crate::socks5::{self, UdpPacket};
use crate::usage::{ExitTally, IngressMeter};

/// 各个上下文收到的、等着发回客户端的报文最多排多少个。排满了上下文的任务就等，再往前是上下文自己的有上限的队列。
const RETURN_BACKLOG: usize = 64;

/// 一个关联最多为多少个被拒绝的目标各记一行日志。再多的照样丢，只是不再记。
const MAX_LOGGED_REFUSALS: usize = 64;

/// 发往对端节点的一个报文。
struct Outgoing {
    target: Target,
    payload: Bytes,
}

/// 对端节点送回来的一个报文。
struct Return {
    peer: NodeId,
    source: Target,
    payload: Bytes,
}

/// 关联的客户端是谁。
struct Client {
    /// TCP 连接对端的地址，IPv4 映射的地址已经还原。
    ip: IpAddr,
    /// 认定的来源端口。没有值时以第一个报文为准。
    port: Option<u16>,
    /// 往回发报文用的地址，就是它上一个报文的来源，原样留着。
    reply_to: Option<SocketAddr>,
}

impl Client {
    /// `declared` 是 UDP ASSOCIATE 请求里客户端写的"我会从这里发"。
    fn new(tcp_peer: SocketAddr, declared: &Host, declared_port: u16) -> Self {
        let ip = tcp_peer.ip().to_canonical();
        // 写的地址和我们看到的一致，说明中间没有地址转换，它写的端口就是我们会看到的端口。
        let known = matches!(declared, Host::Ip(declared) if declared.to_canonical() == ip) && declared_port != 0;
        Self { ip, port: known.then_some(declared_port), reply_to: None }
    }

    /// 这个报文是不是关联的客户端发来的。是的话记下往回发的地址。
    fn admits(&mut self, from: SocketAddr) -> bool {
        if from.ip().to_canonical() != self.ip || self.port.is_some_and(|port| port != from.port()) {
            return false;
        }
        self.port = Some(from.port());
        self.reply_to = Some(from);
        true
    }
}

/// 一个关联里来往了多少报文。
#[derive(Debug, Default)]
struct Tally {
    from_client: u64,
    to_client: u64,
    /// 客户端发来、没有送出去的：不是它发的、格式不对、目标被拒绝。
    dropped: u64,
}

struct Association<'a, C: Datagrams> {
    shared: &'a Arc<Shared<C>>,
    /// 关联建立那一刻这个端口的设置。
    entry: Entry,
    origin: Origin,
    /// 报文的字节数记到这个代理上。
    meter: IngressMeter<'a>,
    /// 经出口出去的报文，发起这一侧看到的计数。
    exits: HashMap<NodeId, Arc<ExitTally>>,
    relay: UdpSocket,
    client: Client,
    /// 到每个对端节点的上下文的队列。任务结束（上下文没开成、被对端回收）之后队列是关着的，下一个报文会重新开。
    peers: HashMap<NodeId, mpsc::Sender<Outgoing>>,
    returns: mpsc::Sender<Return>,
    logged_refusals: HashSet<(Host, u16)>,
    tally: Tally,
}

/// 一个 UDP ASSOCIATE 请求里说了什么，和它的报文记到哪里。
pub(crate) struct Ask<'a> {
    /// 请求里客户端写的"我会从这里发"。
    pub(crate) declared: (Host, u16),
    pub(crate) origin: Origin,
    pub(crate) meter: IngressMeter<'a>,
}

/// 处理一个 UDP ASSOCIATE 请求，直到那条 TCP 连接结束。
///
/// `control` 是客户端的 TCP 连接，请求已经读走、还没有应答。
pub(crate) async fn run<C: Connector + Datagrams>(
    shared: &Arc<Shared<C>>,
    entry: Entry,
    mut control: TcpStream,
    tcp_peer: SocketAddr,
    ask: Ask<'_>,
) {
    let Ask { declared, origin, meter } = ask;
    let bound = async {
        let relay = UdpSocket::bind((control.local_addr()?.ip(), 0)).await?;
        let addr = relay.local_addr()?;
        io::Result::Ok((relay, addr))
    };
    let (relay, relay_addr) = match bound.await {
        Ok(bound) => bound,
        Err(error) => {
            tracing::warn!(%error, "已拒绝 UDP ASSOCIATE 请求：绑定中继端口失败");
            // 写入失败说明客户端已断开。
            let _ = control.write_all(&socks5::reply(socks5::ReplyCode::GeneralFailure)).await;
            return;
        }
    };
    if let Err(error) = control.write_all(&socks5::associated(relay_addr)).await {
        return tracing::debug!(%error, "客户端在写入应答前已断开");
    }
    tracing::debug!(relay = %relay_addr, "UDP 关联建立");

    let (returns, mut returned) = mpsc::channel(RETURN_BACKLOG);
    let mut association = Association {
        shared,
        entry,
        origin,
        meter,
        exits: HashMap::new(),
        relay,
        client: Client::new(tcp_peer, &declared.0, declared.1),
        peers: HashMap::new(),
        returns,
        logged_refusals: HashSet::new(),
        tally: Tally::default(),
    };
    let mut datagram = vec![0; MAX_UDP_PAYLOAD];
    let mut ignored = [0; 64];
    let end = loop {
        tokio::select! {
            // TCP 连接上不该再有数据，有也不看；它一结束，关联就结束。
            read = control.read(&mut ignored) => match read {
                Ok(0) => break "客户端关闭了 TCP 连接".to_owned(),
                Ok(_) => {}
                Err(error) => break format!("TCP 连接出错：{error}"),
            },
            received = association.relay.recv_from(&mut datagram) => match received {
                Ok((len, from)) => association.on_client_datagram(from, &datagram[..len]).await,
                Err(error) => tracing::debug!(%error, "UDP 中继端口收报文时出错"),
            },
            Some(Return { peer, source, payload }) = returned.recv() => {
                let netmap = Arc::clone(&shared.netmap.borrow());
                if source.needs_exit() {
                    association.exit(peer).traffic().add(false, payload.len());
                }
                match source_address(&netmap, peer, source) {
                    Some((host, port)) => association.deliver_to_client(host, port, &payload).await,
                    None => tracing::debug!(%peer, "已丢弃对端节点返回的报文：来源地址无法以 SOCKS5 格式编码"),
                }
            }
        }
    };
    let Tally { from_client, to_client, dropped } = association.tally;
    tracing::info!(from_client, to_client, dropped, end, "UDP 关联结束");
    // 这里丢弃 `association`：各个上下文的队列随之关闭，它们的任务各自把上下文正常结束。
}

impl<C: Connector + Datagrams> Association<'_, C> {
    /// 处理中继端口上收到的一个报文。
    async fn on_client_datagram(&mut self, from: SocketAddr, datagram: &[u8]) {
        if !self.client.admits(from) {
            self.tally.dropped += 1;
            return tracing::debug!(%from, "已丢弃 UDP 中继端口收到的报文：来源非当前关联的客户端");
        }
        let packet = match UdpPacket::parse(datagram) {
            Ok(packet) => packet,
            Err(error) => {
                self.tally.dropped += 1;
                return tracing::debug!(%error, "丢掉客户端发来的一个 UDP 报文");
            }
        };
        // 每个报文都按当时的 netmap 判断，和每条 CONNECT 一样。
        let netmap = Arc::clone(&self.shared.netmap.borrow());
        match route::decide(&netmap, self.entry.exit, &packet.host, packet.port) {
            Ok(route) => {
                let class = route::class_for(&netmap, self.entry.class, &route);
                let Route { peer, target, .. } = route;
                self.forward_to_peer(peer, target, class, packet.data);
            }
            Err(reason) => {
                self.tally.dropped += 1;
                if self.first_refusal(&packet) {
                    tracing::info!(%reason, "拒绝了客户端发往一个目标的 UDP 报文，之后发往它的都直接丢掉");
                }
            }
        }
    }

    /// 发起这一侧经出口 `peer` 出去的报文记在哪里。
    fn exit(&mut self, peer: NodeId) -> &ExitTally {
        self.exits.entry(peer).or_insert_with(|| self.shared.usage.exit(peer))
    }

    /// 把一个报文交给到 `peer` 的上下文。上下文还没有（或者上一个已经结束了）就新开一个，等级按这个报文的算。
    fn forward_to_peer(&mut self, peer: NodeId, target: Target, class: Class, data: &[u8]) {
        let via_exit = target.needs_exit();
        if self.peers.get(&peer).is_none_or(mpsc::Sender::is_closed) {
            let (queue, outgoing) = mpsc::channel(OUTGOING_BACKLOG);
            let session = serve_peer(Arc::clone(self.shared), peer, class, self.origin.clone(), outgoing, self.returns.clone());
            tokio::spawn(session.in_current_span());
            self.peers.insert(peer, queue);
            if via_exit {
                self.exit(peer).started();
            }
        }
        let queued = self.peers.get(&peer).is_some_and(|queue| queue.try_send(Outgoing { target, payload: owned(data) }).is_ok());
        if queued {
            self.tally.from_client += 1;
            self.meter.record(true, data.len());
            if via_exit {
                self.exit(peer).traffic().add(true, data.len());
            }
        } else {
            self.tally.dropped += 1;
            tracing::trace!(%peer, "已丢弃客户端发送的 UDP 报文：到对端节点的数据报上下文尚未就绪或发送队列已满");
        }
    }

    /// 把一个报文发回客户端，前面带着它的来源。
    async fn deliver_to_client(&mut self, host: Host, port: u16, data: &[u8]) {
        // 客户端还没有发过报文的话，不知道往哪里回。
        let Some(client) = self.client.reply_to else { return };
        let datagram = UdpPacket { host, port, data }.encode();
        match self.relay.send_to(&datagram, client).await {
            Ok(_) => {
                self.tally.to_client += 1;
                self.meter.record(false, data.len());
            }
            Err(error) => tracing::debug!(%error, "向客户端返回 UDP 报文失败"),
        }
    }

    /// 这个目标是不是第一次被拒绝（要不要记日志）。
    fn first_refusal(&mut self, packet: &UdpPacket<'_>) -> bool {
        self.logged_refusals.len() < MAX_LOGGED_REFUSALS && self.logged_refusals.insert((packet.host.clone(), packet.port))
    }
}

/// 对端节点送回来的报文的来源，在 SOCKS5 里写成什么地址。
fn source_address(netmap: &Netmap, peer: NodeId, source: Target) -> Option<(Host, u16)> {
    match source {
        Target::Internet { host, port } => Some((host, port)),
        Target::Lan { addr } => Some((Host::Ip(addr.ip()), addr.port())),
        // 那个节点自己的服务：客户端当初是发往它的虚拟 IP 的，回来的也报成从那里来。
        Target::Node { port } => netmap.peer(peer).map(|peer| (Host::Ip(IpAddr::V4(peer.virtual_ip)), port)),
        Target::Forward { .. } => None,
    }
}

/// 一个关联到一个对端节点的上下文：开上下文，然后在队列和上下文之间搬运，直到关联结束或者上下文结束。
async fn serve_peer<C: Connector + Datagrams>(
    shared: Arc<Shared<C>>,
    peer: NodeId,
    class: Class,
    origin: Origin,
    mut outgoing: mpsc::Receiver<Outgoing>,
    returns: mpsc::Sender<Return>,
) {
    let Ok(mut context) = open_context(&shared, peer, class, origin, &mut outgoing).await else { return };
    let sender = context.sender();
    tracing::debug!(%peer, ?class, "到对端节点的数据报上下文建立");
    loop {
        tokio::select! {
            queued = outgoing.recv() => match queued {
                Some(Outgoing { target, payload }) => {
                    if let Err(error) = sender.send(&target, &payload).await {
                        tracing::debug!(%peer, %error, "向对端节点发送 UDP 报文失败");
                    }
                }
                // 关联结束了。
                None => return context.close().await,
            },
            received = context.recv() => match received {
                Ok(Received { target: source, payload }) => {
                    if returns.send(Return { peer, source, payload }).await.is_err() {
                        return context.close().await;
                    }
                }
                Err(end) => return tracing::debug!(%peer, ?end, "到对端节点的数据报上下文已结束，后续收到报文时将重新建立"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn unspecified() -> Host {
        Host::Ip("0.0.0.0".parse().unwrap())
    }

    #[test]
    fn only_the_tcp_peers_address_is_admitted_and_its_first_port_sticks() {
        let mut client = Client::new(addr("192.0.2.9:40000"), &unspecified(), 0);
        assert!(!client.admits(addr("192.0.2.10:5000")), "别的地址");
        assert_eq!(client.reply_to, None);
        assert!(client.admits(addr("192.0.2.9:5000")), "端口以第一个报文为准");
        assert!(client.admits(addr("192.0.2.9:5000")));
        assert!(!client.admits(addr("192.0.2.9:5001")), "之后换了端口的不认");
        assert_eq!(client.reply_to, Some(addr("192.0.2.9:5000")));
    }

    #[test]
    fn a_declared_port_is_enforced_from_the_start_when_the_declared_address_is_the_one_we_see() {
        let declared = Host::Ip("192.0.2.9".parse().unwrap());
        let mut client = Client::new(addr("192.0.2.9:40000"), &declared, 5000);
        assert!(!client.admits(addr("192.0.2.9:5001")), "抢在客户端前面发的也不认");
        assert!(client.admits(addr("192.0.2.9:5000")));

        // 写的地址和看到的不一样（中间有地址转换）、或者没写：写的端口不作数。
        for declared in [Host::Ip("10.0.0.7".parse().unwrap()), unspecified(), "client.example".parse().unwrap()] {
            let mut client = Client::new(addr("192.0.2.9:40000"), &declared, 5000);
            assert!(client.admits(addr("192.0.2.9:61000")), "{declared}");
        }
    }

    #[test]
    fn a_client_on_a_dual_stack_port_is_recognised_by_its_ipv4_address_and_answered_as_it_came() {
        let mut client = Client::new(addr("[::ffff:192.0.2.9]:40000"), &unspecified(), 0);
        assert!(client.admits(addr("[::ffff:192.0.2.9]:5000")));
        assert_eq!(client.reply_to, Some(addr("[::ffff:192.0.2.9]:5000")), "往回发要用收到时的写法");
        assert!(client.admits(addr("192.0.2.9:5000")));
    }
}
