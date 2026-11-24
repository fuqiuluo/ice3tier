//! 一个节点的数据面：把 UDP 端口、路径层、relay 角色和 QUIC 装在一起。

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use i3t_crypto::NodeKey;
use i3t_model::Netmap;
use i3t_model::control::{RouteEntry, Signal};
use i3t_model::netmap::{Attachment, Congestion};
use i3t_path::{
    BackboneRow, DirectAttempt, HopReport, PathConfig, PathReport, Paths, RouteChange, RouteDecision, RoutePin, Side, TestGuard, TestPath,
    TestSpec, TrainError, TrainReport, TrainSpec,
};
use i3t_proto::NodeId;
use i3t_proto::flow::Recipient;
use i3t_relay::{Relay, RelayCounters};
use i3t_underlay::{PacketFilter, UdpPort};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;

use crate::contract::{Acceptor, Connector, Datagram, Datagrams, Incoming, OpenError, Packets};
use crate::manager::{ConnectionReport, DATAGRAM_BACKLOG, DatagramHandle, DatagramQueues, Manager, PACKET_BACKLOG, PacketRoute};
use crate::quic::{self, QuicConfigError};
use crate::sealed::{Inbox, PacketTransport};
use crate::socket::PathSocket;
use crate::stream::{RecvHalf, SendHalf};
use crate::tuning::Tuning;

/// relay 宣布自己要停之后，还继续转发多久。挂靠它的节点收到通知就会换路，这段时间是留给它们换的。
const RELAY_LEAVE_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// 对端开过来、上层还没有取走的流最多排多少条。满了之后那条连接上新的流先不接，压力传回对端。
const INCOMING_BACKLOG: usize = 256;

/// 建一个 [`Endpoint`] 要的东西。
#[derive(Debug)]
pub struct EndpointConfig {
    /// 节点密钥。
    pub key: Arc<NodeKey>,
    /// UDP 端口绑定在哪里。本节点启用为 relay 时，同一个地址和端口号上还会监听 TCP。
    pub bind: SocketAddr,
    /// 节点的配置。随时可以换成新的一份，立即生效。
    pub netmap: watch::Receiver<Arc<Netmap>>,
    /// 地址查询的服务器（通常是 controller 的那个 UDP 端口）。可以为空：有 relay 时反射地址也能从 relay 得到。
    pub addr_servers: Vec<SocketAddr>,
}

type SignalHook = Arc<dyn Fn(NodeId, &Signal) + Send + Sync>;

/// 到一个对端的共用连接现在走的路上，本节点看得见多少 UDP（[`Endpoint::udp_path`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSeen {
    /// 直连：两个节点之间没有别人，整条路都是 UDP。
    WholePath,
    /// 经 relay 转发，本节点到 relay 段走 UDP；对端到 relay 段的传输方式本节点不可见。
    OwnLeg,
    /// 经 relay 转发，本节点到 relay 段走 TCP。
    NoUdp,
}

/// 一个节点的数据面。
///
/// 它实现 [`Connector`] 和 [`Acceptor`]：到某个节点开一条流，接受某个节点开过来的流。包走直连还是经 relay、
/// 什么时候换路、和对端之间有没有连接，上层都不用管。本节点在 netmap 里被启用为 relay 时，它同时转发别人的包。
/// 它也实现 [`Datagrams`]：在已经有的连接上和对端互相发数据报（QUIC 的 DATAGRAM 帧，要保证送达的走单向流）；
/// 和 [`Packets`]：虚拟网卡上的 IP 包，一个包一个不保证送达的数据报，走和流同一条连接。
///
/// 谁能访问谁（netmap 里的 `inbound`）不在这一层检查：netmap 里有的对端都能连进来、开流，
/// 上层收到流之后按发起节点自己查。
///
/// 丢弃这个值会关掉所有连接、中转会话和后台任务。
pub struct Endpoint {
    port: Arc<UdpPort>,
    paths: Arc<Paths>,
    relay: Arc<Relay>,
    manager: Arc<Manager>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<Incoming<SendHalf, RecvHalf>>>,
    datagrams: DatagramInbox,
    /// 装配方提供的信令出口。
    signal_hook: Arc<RwLock<Option<SignalHook>>>,
    tasks: [JoinHandle<()>; 2],
}

impl Endpoint {
    /// 绑定端口并启动。要在 tokio 运行时里调用。
    ///
    /// 虚拟网卡的包怎么走按环境变量来（[`PacketTransport::from_env`]），没有设置时用默认的。
    ///
    /// # Errors
    ///
    /// UDP 端口绑定失败，或 QUIC 配置构建失败（如节点密钥无效）。
    pub fn bind(config: EndpointConfig) -> Result<Self, EndpointError> {
        Self::bind_with(config, PacketTransport::from_env())
    }

    /// 和 [`bind`](Self::bind) 一样，只是指定虚拟网卡的包怎么走，不看环境变量。
    ///
    /// # Errors
    ///
    /// UDP 端口绑定失败，或 QUIC 配置构建失败（如节点密钥无效）。
    pub fn bind_with(config: EndpointConfig, packets: PacketTransport) -> Result<Self, EndpointError> {
        let EndpointConfig { key, bind, netmap, addr_servers } = config;
        let me = netmap.borrow().me.id;
        let port = Arc::new(UdpPort::bind(bind).map_err(|source| EndpointError::Bind { addr: bind, source })?);
        let paths =
            Arc::new(Paths::new(PathConfig { key: Arc::clone(&key), port: Arc::clone(&port), netmap: netmap.clone(), addr_servers }));

        let relay = Arc::new(Relay::new(Arc::clone(&key), Arc::clone(&port), netmap.clone()));
        paths.set_local_relay(Arc::clone(&relay) as Arc<dyn i3t_path::LocalRelay>);
        relay.set_backbone_inbox(paths.backbone_inbox());
        // relay 仅持有路径层的弱引用，避免与路径层持有的 relay 强引用形成循环引用导致无法释放。
        let weak_paths = Arc::downgrade(&paths);
        relay.set_local_delivery(move |src, packet| {
            if let Some(paths) = weak_paths.upgrade() {
                paths.deliver_local(src, packet);
            }
        });

        // 接受连接时按每次握手时的当前 netmap 校验对端公钥是否受信任。
        let allowed = netmap.clone();
        let server = quic::server(&key, move |key| allowed.borrow().peers.iter().any(|peer| peer.key == *key), packets)?;

        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_BACKLOG);
        let (to_acceptor, for_acceptor) = mpsc::channel(DATAGRAM_BACKLOG);
        let (to_initiator, for_initiator) = mpsc::channel(DATAGRAM_BACKLOG);
        let (to_packets, for_packets) = mpsc::channel(PACKET_BACKLOG);
        // 封好的网络包不经 QUIC 库：socket 收到就交给它，解开之后和走数据报来的网络包排进同一个队列。
        let inbox = Inbox::new(to_packets.clone());
        let socket = PathSocket::new(Arc::clone(&paths), me, Arc::clone(&inbox));
        let quic =
            quinn::Endpoint::new_with_abstract_socket(quic::endpoint(&key)?, Some(server.clone()), socket, Arc::new(quinn::TokioRuntime))
                .map_err(EndpointError::Quic)?;
        let queues = DatagramQueues { acceptor: to_acceptor, initiator: to_initiator, packets: to_packets };
        let datagrams = DatagramInbox { acceptor: for_acceptor.into(), initiator: for_initiator.into(), packets: for_packets.into() };
        let route = PacketRoute { transport: packets, inbox };
        let manager = Manager::new(key, (quic, server), Arc::clone(&paths), netmap, incoming_tx, queues, route);

        // 信令两条路都走：已经有连接的话在连接里送（有 relay 的网络因此不依赖 controller），同时交给装配方的钩子。
        let signal_hook: Arc<RwLock<Option<SignalHook>>> = Arc::default();
        let (in_band, external) = (Arc::downgrade(&manager), Arc::clone(&signal_hook));
        paths.set_signal_hook(move |to, signal| {
            if let Some(manager) = in_band.upgrade() {
                manager.send_signal(to, signal);
            }
            let hook = external.read().expect("signal hook lock poisoned").clone();
            if let Some(hook) = hook {
                hook(to, signal);
            }
        });

        let tasks = [tokio::spawn(Arc::clone(&manager).accept_loop()), tokio::spawn(Arc::clone(&manager).follow_netmap())];
        tracing::info!(node = %me, addr = %port.local_addr(), "数据面启动");
        Ok(Self { port, paths, relay, manager, incoming: tokio::sync::Mutex::new(incoming_rx), datagrams, signal_hook, tasks })
    }

    /// 换上性能档位的连接设置（见 [`Tuning`]）。刚绑定好的端点用的是 [`Tuning::default`]。
    ///
    /// 窗口对之后建立的连接生效，两个方向（本端拨出的、对端连进来的）都是；已有的连接保持原样。空闲回收的时间立刻生效。
    pub fn tune(&self, tuning: Tuning) {
        self.manager.tune(tuning);
        tracing::info!(?tuning, "连接层性能档位配置已更新");
    }

    /// 更新 controller 的在线状态。装配层在长连接状态变化时调用；未曾通知时默认视为在线。
    ///
    /// 当 controller 不可达且到某对端无经 relay 路径时，暂缓回收其空闲连接，避免关闭后因打洞信令无路可走而无法重建。
    /// 恢复在线后，下一次周期检查（1 秒内）将恢复正常回收。
    pub fn set_controller_online(&self, online: bool) {
        self.manager.set_controller_online(online);
    }

    /// UDP 端口实际绑定的地址。
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.port.local_addr()
    }

    /// 到每个对端现在走哪条路，延迟多少。
    #[must_use]
    pub fn routes(&self) -> Vec<RouteEntry> {
        self.paths.routes()
    }

    /// 本节点的候选端点，上报给 controller 用。
    #[must_use]
    pub fn endpoints(&self) -> Vec<SocketAddr> {
        self.paths.endpoints()
    }

    /// 别人看到的本节点地址：relay 和地址查询服务器看到的，以及路由器上映射出来的。
    /// 和 [`endpoints`](Self::endpoints) 不同，不向对端公布自己地址的节点（只经 relay 的）这里也有。
    /// 出口靠它知道哪些公网地址其实是自己，不替别人去连。
    #[must_use]
    pub fn public_addresses(&self) -> Vec<SocketAddr> {
        self.paths.public_addresses()
    }

    /// 映射出来的端口是不是随对端变化。要有两个以上的观察点才知道。
    #[must_use]
    pub fn mapping_varies(&self) -> Option<bool> {
        self.paths.mapping_varies()
    }

    /// 本节点挂靠的 relay 和到它们的延迟，按延迟从低到高。上报给 controller 用。
    #[must_use]
    pub fn attached(&self) -> Vec<Attachment> {
        self.paths.attached()
    }

    /// 到 `peer` 的连接自己量的往返时间（QUIC 的平滑 RTT）。没有连接时是 `None`。
    ///
    /// 路由层按各段的探测推算一条路的延迟（[`routes`](Self::routes) 里的 `rtt_ms`）；这个是真实的数据走完全程量出来的，
    /// 两个对着看能发现测量失真。只读，不影响选路。
    #[must_use]
    pub fn connection_rtt(&self, peer: NodeId) -> Option<std::time::Duration> {
        self.manager.connection_rtt(peer)
    }

    /// 到 `peer` 的连接现在的状况：往返时间、拥塞窗口、包长和累计的收发、丢包。没有连接时是 `None`。给两个节点之间的诊断用。
    #[must_use]
    pub fn connection_report(&self, peer: NodeId) -> Option<ConnectionReport> {
        self.manager.connection_report(peer)
    }

    /// 和各个对端之间的共用连接上现在开着几条流、本节点启动以来两个方向各走了多少字节（线上的，关掉的连接也算），
    /// 只有现在有连接的对端，流量大的在前，最多 [`MAX_PEER_USE`](i3t_model::control::MAX_PEER_USE) 个。给路由视图用。
    #[must_use]
    pub fn peer_use(&self) -> Vec<i3t_model::control::PeerUse> {
        self.manager.peer_use(i3t_model::control::MAX_PEER_USE)
    }

    /// 本节点是 relay 时：谁在用它，见 [`Relay::users`]。
    #[must_use]
    pub fn relay_use(&self) -> Option<i3t_model::control::RelayUse> {
        self.relay.users()
    }

    /// 本节点试过的各个 relay 连没连上、它们看到的本节点 IP。上报给 controller 用，见 [`Paths::relay_tries`]。
    #[must_use]
    pub fn relay_tries(&self) -> Vec<i3t_model::control::RelayTry> {
        self.paths.relay_tries()
    }

    /// 到每个对端考虑过哪些路径、各自测到的代价，以及为什么选了现在这条。给路由视图和路径诊断用。
    #[must_use]
    pub fn path_reports(&self) -> Vec<PathReport> {
        self.paths.path_reports()
    }

    /// 同 [`path_reports`](Self::path_reports)，只取一个对端的；这个对端不在 netmap 里时是 `None`。
    #[must_use]
    pub fn path_report(&self, peer: NodeId) -> Option<PathReport> {
        self.paths.path_report(peer)
    }

    /// 本节点手上的 relay 骨干延迟矩阵，每个 relay 一行。
    #[must_use]
    pub fn backbone(&self) -> Vec<BackboneRow> {
        self.paths.backbone()
    }

    /// 订阅换路事件。每一次换路都有一条，带着给人看的原因。
    #[must_use]
    pub fn route_changes(&self) -> broadcast::Receiver<RouteChange> {
        self.paths.subscribe()
    }

    /// 返回到 `peer` 的共用连接当前路径上本节点可见的 UDP 使用情况（见 [`UdpSeen`]）：直连时整条路径为 UDP；经 relay 时仅可见
    /// 本节点到 relay 段；本节点自身作为 relay 时，检查对端在本节点上的中转会话是否为 UDP。
    /// 无可用路径（对端不在 netmap、尚未选路或不可达）时返回 `None`：无路径不代表“无 UDP 路径”，不能据此决定启用 ice3proxy。
    ///
    /// "UDP 不通时才用 ice3proxy"按它来判断。
    #[must_use]
    pub fn udp_path(&self, peer: NodeId) -> Option<UdpSeen> {
        let own_leg = |udp: bool| if udp { UdpSeen::OwnLeg } else { UdpSeen::NoUdp };
        let report = self.paths.path_report(peer)?;
        match (&report.route, report.relay_leg) {
            (i3t_model::control::Route::Direct { .. }, _) => Some(UdpSeen::WholePath),
            (i3t_model::control::Route::Relay { .. }, Some(leg)) => Some(own_leg(leg == i3t_path::RelayLeg::Udp)),
            // 经本节点自己的 relay：最后一段是对端在本节点上的会话。
            (i3t_model::control::Route::Relay { .. }, None) => Some(own_leg(self.relay.has_udp_session(peer))),
            (i3t_model::control::Route::None, _) => None,
        }
    }

    /// 主动测试：打开一个测试的时间窗，见 [`Paths::open_test`]。丢弃返回的值就关掉。
    #[must_use]
    pub fn open_test(&self, spec: TestSpec) -> TestGuard {
        self.paths.open_test(spec)
    }

    /// 主动测试：在一条路径上发一列探测，见 [`Paths::train`]。
    ///
    /// # Errors
    ///
    /// 同 [`Paths::train`]。
    pub async fn test_train(&self, spec: TrainSpec) -> Result<TrainReport, TrainError> {
        self.paths.train(spec).await
    }

    /// 主动测试：把到 `peer` 的共用连接暂时固定在 `path` 上，见 [`Paths::pin`]。丢弃返回的值就解除。
    #[must_use]
    pub fn pin_route(&self, peer: NodeId, path: TestPath, limit: std::time::Duration) -> RoutePin {
        self.paths.pin(peer, path, limit)
    }

    /// 主动测试：试一次直连（带头或者跟随），见 [`Paths::attempt_direct`]。
    pub async fn attempt_direct(&self, peer: NodeId, side: Side, limit: std::time::Duration) -> DirectAttempt {
        self.paths.attempt_direct(peer, side, limit).await
    }

    /// 主动测试：两种选路模式此刻各会选哪条路，见 [`Paths::decide`]。
    pub async fn route_decision(&self, peer: NodeId) -> Option<RouteDecision> {
        self.paths.decide(peer).await
    }

    /// 主动测试：一条路径上各段此刻的测量值，见 [`Paths::hops`]。
    pub async fn path_hops(&self, peer: NodeId, path: TestPath) -> Vec<HopReport> {
        self.paths.hops(peer, path).await
    }

    /// 到 `peer` 的连接用的拥塞控制。还没有连接时是新建的连接会用的那一种（节点对的设置，
    /// 没有设置时是节点的默认）。吞吐测试的结果要说明它是在哪一种下面量的。
    #[must_use]
    pub fn congestion(&self, peer: NodeId) -> Congestion {
        Congestion::from(self.manager.congestion(peer))
    }

    /// 本节点启用为 relay 时，它在 UDP 端口的同一个端口号上听 TCP。开头是 TLS 握手记录的连接（ice3proxy）交给 `handoff`，
    /// 其余连接仍按中转处理。为 `None` 时该端口仅提供中转服务。见 [`i3t_relay::Relay::set_tcp_handoff`]。
    pub fn set_lane_handoff(&self, handoff: Option<i3t_relay::TcpHandoff>) {
        self.relay.set_tcp_handoff(handoff);
    }

    /// 本节点作为 relay 的计数。没有启用 relay 时除了"因为没启用而丢掉"的那一项都是 0。
    #[must_use]
    pub fn relay_counters(&self) -> RelayCounters {
        self.relay.counters()
    }

    /// 打洞信令从哪里送出去：`hook(收信令的节点, 信令)`，装配方把它经 controller 的通道转给那个节点。
    /// 钩子在后台任务里被调用，不能阻塞。
    ///
    /// # Panics
    ///
    /// 之前设的钩子自己 panic 过（锁中毒）。
    pub fn set_signal_hook(&self, hook: impl Fn(NodeId, &Signal) + Send + Sync + 'static) {
        *self.signal_hook.write().expect("signal hook lock poisoned") = Some(Arc::new(hook));
    }

    /// controller 转来了节点 `from` 发的一条信令。
    pub fn deliver_signal(&self, from: NodeId, signal: Signal) {
        self.paths.handle_signal(from, signal);
    }

    /// 装上或者卸掉 UDP 端口上的丢包过滤器。只给测试用，用来模拟某条路不通。
    pub fn set_packet_filter(&self, filter: Option<PacketFilter>) {
        self.port.set_filter(filter);
    }

    /// 关闭：所有连接带着关闭帧结束，[`Acceptor::accept`] 返回 `None`，之后的 [`Connector::open`] 失败。
    pub async fn close(&self) {
        if self.relay.is_enabled() {
            // 先告诉挂靠在本节点上的节点"我要停了"，再继续转发一小会儿，让它们把路换到别的 relay 上。
            self.relay.announce_shutdown();
            tokio::time::sleep(RELAY_LEAVE_GRACE).await;
        }
        self.manager.close().await;
        // 最后关闭路径层，以便清理向路由器自动申请的端口映射。
        self.paths.shutdown().await;
    }
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint").field("local_addr", &self.port.local_addr()).finish_non_exhaustive()
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.manager.abort();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Connector for Endpoint {
    type Send = SendHalf;
    type Recv = RecvHalf;

    async fn open(&self, peer: NodeId) -> Result<(SendHalf, RecvHalf), OpenError> {
        self.manager.open(peer).await
    }
}

impl Acceptor for Endpoint {
    type Send = SendHalf;
    type Recv = RecvHalf;

    async fn accept(&self) -> Option<Incoming<SendHalf, RecvHalf>> {
        let mut closed = self.manager.subscribe_closed();
        let mut incoming = self.incoming.lock().await;
        tokio::select! {
            biased;
            stream = incoming.recv() => stream,
            _ = closed.wait_for(|closed| *closed) => None,
        }
    }
}

impl Datagrams for Endpoint {
    type Sender = DatagramHandle;

    fn datagram_sender(&self) -> DatagramHandle {
        self.manager.datagram_handle()
    }

    async fn recv_datagram(&self, recipient: Recipient) -> Option<Datagram> {
        let mut closed = self.manager.subscribe_closed();
        let mut inbox = self.datagrams.of(recipient).lock().await;
        tokio::select! {
            biased;
            datagram = inbox.recv() => datagram,
            _ = closed.wait_for(|closed| *closed) => None,
        }
    }
}

impl Packets for Endpoint {
    type Sender = DatagramHandle;

    fn packet_sender(&self) -> DatagramHandle {
        self.manager.datagram_handle()
    }

    async fn recv_packets(&self, into: &mut Vec<Datagram>, limit: usize) -> usize {
        let mut closed = self.manager.subscribe_closed();
        let mut inbox = self.datagrams.packets.lock().await;
        tokio::select! {
            biased;
            taken = inbox.recv_many(into, limit) => taken,
            _ = closed.wait_for(|closed| *closed) => 0,
        }
    }
}

/// 对端发来、上层还没有取走的数据报，两侧各一个队列，网络包一个。
struct DatagramInbox {
    acceptor: tokio::sync::Mutex<mpsc::Receiver<Datagram>>,
    initiator: tokio::sync::Mutex<mpsc::Receiver<Datagram>>,
    packets: tokio::sync::Mutex<mpsc::Receiver<Datagram>>,
}

impl DatagramInbox {
    fn of(&self, recipient: Recipient) -> &tokio::sync::Mutex<mpsc::Receiver<Datagram>> {
        match recipient {
            Recipient::Acceptor => &self.acceptor,
            Recipient::Initiator => &self.initiator,
        }
    }
}

/// [`Endpoint::bind`] 失败的原因。
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("绑定 UDP {addr} 失败")]
    Bind { addr: SocketAddr, source: io::Error },
    #[error("构建连接层配置失败")]
    Config(#[from] QuicConfigError),
    #[error("启动连接层失败")]
    Quic(#[source] io::Error),
}
