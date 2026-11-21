//! 路径层对外的入口：连接层通过它收发包，装配的一方通过它查状态、接信令。

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use bytes::Bytes;
use i3t_crypto::NodeKey;
use i3t_model::Netmap;
use i3t_model::control::{Route, RouteEntry, Signal};
use i3t_model::netmap::Attachment;
use i3t_proto::datagram::{RelayHeader, RouteHeader};
use i3t_proto::probe::{TestId, TestPing, TestPong};
use i3t_proto::session::{self, Refused};
use i3t_proto::{Datagram, NodeId, PublicKey, probe};
use i3t_underlay::lan::{LanConfig, LanDiscovery};
use i3t_underlay::portmap::PortMapConfig;
use i3t_underlay::{BATCH_SIZE, Ecn, RecvMeta, UdpPort};
use tokio::sync::{Notify, broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::control::{Control, Ctrl, Inbound, Queues};
use crate::diag::{
    DirectAttempt, DirectFailure, HopReport, Pin, RouteDecision, Side, TestPath, TestSpec, TrainError, TrainReport, TrainSpec,
};
use crate::report::{BackboneRow, PathReport};
use crate::table::{Clock, Packets, PeerSlot, Shared, Table, Unsent};
use crate::{LocalRelay, RouteChange, Status};

/// 交给控制任务的内部事件最多攒多少。
const CTRL_QUEUE: usize = 1024;
/// 收包路径交给控制任务的帧最多攒多少，relay 来的和别的各一个队列。满了就丢：它们都是有重试的握手和探测，
/// 而且这样陌生人灌不爆内存。
const FRAME_QUEUE: usize = 512;
/// 不走 UDP 缓冲区直达的包（TCP 中转来的等）最多攒多少。满了之后 TCP 那边停下来等。
const INBOUND_QUEUE: usize = 1024;
/// 换路事件的订阅者最多落后多少条。
const CHANGE_BACKLOG: usize = 256;

/// 建路径层要的东西。
#[derive(Debug)]
pub struct PathConfig {
    pub key: Arc<NodeKey>,
    pub port: Arc<UdpPort>,
    pub netmap: watch::Receiver<Arc<Netmap>>,
    /// 地址查询的服务器（通常是 controller 的那个 UDP 端口）。
    pub addr_servers: Vec<SocketAddr>,
}

/// 收到的一批包是谁发来的、有多长。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    /// 发这些包的对端。直连时由来源地址认出来，经 relay 时取自中转头（relay 保证它是真的）。
    pub peer: NodeId,
    /// 缓冲区里有多少字节。
    pub len: usize,
    /// 每个包的长度；`len` 比它大时缓冲区里是同一个对端的多个包，每 `stride` 字节一个，最后一个可以短。
    pub stride: usize,
    pub ecn: Option<Ecn>,
}

/// 一个节点的路径层。
///
/// 它管着那个唯一的 UDP 端口上的全部收发：连接层的包走哪条路由它定，路径层自己的帧（中转会话、探测）它自己处理，
/// 归 relay 的交给 [`LocalRelay`]。连接层只说"发给哪个节点"，只看到"哪个节点发来的"，物理地址不出这一层，
/// 所以换路时连接不知道。
///
/// 丢弃这个值会停掉后台任务，关掉所有的中转会话。
#[derive(Debug)]
pub struct Paths {
    shared: Arc<Shared>,
    control: JoinHandle<()>,
    /// 本节点的公钥：局域网信标里的标签是拿它算的。
    public: PublicKey,
    /// 给固定路编号用：解除时靠它认出是哪一次，免得解除了别人后来的固定。
    next_pin: AtomicU64,
}

impl Paths {
    /// 要在 tokio 运行时里调用：它会启动控制任务。
    #[must_use]
    pub fn new(config: PathConfig) -> Self {
        let PathConfig { key, port, mut netmap, addr_servers } = config;
        let (ctrl, ctrl_rx) = mpsc::channel(CTRL_QUEUE);
        let (from_relays, from_relays_rx) = mpsc::channel(FRAME_QUEUE);
        let (from_peers, from_peers_rx) = mpsc::channel(FRAME_QUEUE);
        let (inbound, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let current = Arc::clone(&netmap.borrow_and_update());
        let shared = Arc::new(Shared {
            me: current.me.id,
            port,
            clock: Clock::new(),
            table: RwLock::new(Table::default()),
            ctrl,
            from_relays,
            from_peers,
            inbound,
            inbound_rx: Mutex::new(inbound_rx),
            local_relay: OnceLock::new(),
            gates: Arc::default(),
            signal_hook: RwLock::new(None),
            changes: broadcast::Sender::new(CHANGE_BACKLOG),
            route_changed: Notify::new(),
            status: Mutex::new(Status::default()),
            lan: Mutex::new(None),
            open_tests: RwLock::default(),
        });
        let public = key.public();
        let control = Control::new(Arc::clone(&shared), key, current, addr_servers);
        let queues = Queues { ctrl: ctrl_rx, from_relays: from_relays_rx, from_peers: from_peers_rx };
        let control = tokio::spawn(control.run(queues, netmap));
        let paths = Self { shared, control, public, next_pin: AtomicU64::new(1) };
        // 端口绑在未指定地址上的才是真的节点：只有它们自动在本地网段上找对端。绑在具体地址上的（测试）要自己明确打开。
        if paths.shared.port.local_addr().ip().is_unspecified()
            && let Err(error) = paths.start_lan_discovery(LanConfig::default())
        {
            tracing::debug!(%error, "局域网发现启动不了，同一个局域网里的对端只能靠上报的地址去找");
        }
        paths
    }

    /// 开始在本地网段上发信标、听对端的信标。看到的对端成为直连的候选地址，照样要验证过才用。
    ///
    /// 端口绑在未指定地址上时 [`new`](Self::new) 已经用默认参数调用过它；再调用会换成新的参数。要在 tokio 运行时里调用。
    ///
    /// # Errors
    ///
    /// 组播的 socket 建不起来（端口被不肯共用的程序占着，或者系统不让用组播）。
    ///
    /// # Panics
    ///
    /// 之前的调用 panic 过（锁中毒）。
    pub fn start_lan_discovery(&self, config: LanConfig) -> io::Result<()> {
        let queue = self.shared.from_peers.clone();
        let port = self.shared.port.local_addr().port();
        let discovery = LanDiscovery::start(config, self.public, port, move |sighting| {
            // 信标每隔几秒就来一个，控制任务忙的时候丢掉这一个没有关系。
            let _queued = queue.try_send(Ctrl::Lan(sighting));
        })?;
        *self.shared.lan.lock().expect("lan discovery mutex poisoned") = Some(discovery);
        let _queued = self.shared.ctrl.try_send(Ctrl::LanStarted);
        Ok(())
    }

    /// 向网关申请端口映射（PCP、NAT-PMP、UPnP），映射出来的地址会出现在 [`endpoints`](Self::endpoints) 里。
    ///
    /// 端口绑在未指定地址上时 [`new`](Self::new) 已经按默认网关启动过；这个方法用给定的参数重新来，
    /// 测试靠它把请求指向假的网关。
    pub fn start_port_mapping(&self, config: PortMapConfig) {
        if self.shared.ctrl.try_send(Ctrl::PortMap(config)).is_err() {
            tracing::warn!("控制任务忙不过来，端口映射没有启动");
        }
    }

    /// 节点要停了：把在路由器上申请的端口映射删掉，然后停止维护路径。最多等一两秒。
    ///
    /// 本节点同时是 relay 时，先调用 relay 的 `announce_shutdown`，再调用这个。之后这个值不再换路，只能丢弃。
    pub async fn shutdown(&self) {
        let (done, finished) = oneshot::channel();
        if self.shared.ctrl.send(Ctrl::Shutdown(done)).await.is_ok() {
            // 控制任务已经没了的话也就没有映射要删了。
            let _stopped = finished.await;
        }
    }

    /// 本节点的 relay 角色。归 relay 处理的数据报从此交给它；对端挂在本节点自己的 relay 上时，包也经它送。
    /// 只能设一次。
    pub fn set_local_relay(&self, relay: Arc<dyn LocalRelay>) {
        if self.shared.local_relay.set(relay).is_err() {
            tracing::warn!("路径层的本地 relay 已经设过了，忽略这一次");
        }
    }

    /// 给本节点的 relay 的入口：别的 relay 拨进来的骨干 TCP 上归路径层的事从这里交进来，骨干走着 TCP 的那几段的情况从这里问
    /// （[`crate::backbone`]），交给 relay 的 `set_backbone_inbox`。它只拿着控制任务的队列和那张表，relay 拿着它不会让路径层释放不掉。
    #[must_use]
    pub fn backbone_inbox(&self) -> crate::BackboneInbox {
        crate::BackboneInbox { ctrl: self.shared.ctrl.clone(), gates: Arc::clone(&self.shared.gates) }
    }

    /// 信令从哪里送出去（`to` 是收信令的节点）。钩子在控制任务里被调用，不能阻塞。
    ///
    /// # Panics
    ///
    /// 之前设的钩子自己 panic 过（锁中毒）。
    pub fn set_signal_hook(&self, hook: impl Fn(NodeId, &Signal) + Send + Sync + 'static) {
        *self.shared.signal_hook.write().expect("signal hook lock poisoned") = Some(Arc::new(hook));
    }

    /// 对端 `from` 发来了一条信令。来源必须是可信的：controller 转来的，或者和 `from` 的已认证连接里收到的。
    pub fn handle_signal(&self, from: NodeId, signal: Signal) {
        if self.shared.ctrl.try_send(Ctrl::Signal { from, signal }).is_err() {
            tracing::debug!(peer = %from, "控制任务忙不过来，丢掉一条信令");
        }
    }

    /// 接下来要和 `peer` 通信了：立刻开始为它找路（建临时的中转会话、探测直连），不等第一个包。
    pub fn activate(&self, peer: NodeId) {
        if let Some(slot) = self.shared.table().peers.get(&peer) {
            slot.last_demand.touch(&self.shared.clock);
        }
        // 满了说明控制任务本来就有事要做，做完会重新选路。
        let _queued = self.shared.ctrl.try_send(Ctrl::Wake);
    }

    /// 到 `peer` 现在有没有路。
    #[must_use]
    pub fn has_route(&self, peer: NodeId) -> bool {
        self.shared.table().peers.get(&peer).is_some_and(|slot| slot.has_hop())
    }

    /// 等到 `peer` 有路为止，最多等 `limit`。返回等到了没有。等的时候不断把 `peer` 标记为活跃，找路不会停。
    pub async fn wait_for_route(&self, peer: NodeId, limit: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            // 先登记再检查，这样两步之间发生的换路不会漏掉。
            let changed = self.shared.route_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.activate(peer);
            if self.has_route(peer) {
                return true;
            }
            // 隔一小会儿就重新标记一次：netmap 刚换、对端还没进表的时候，头一次标记会落空。
            let recheck = tokio::time::Instant::now() + Duration::from_millis(100);
            if tokio::time::timeout_at(deadline.min(recheck), changed).await.is_err() && tokio::time::Instant::now() >= deadline {
                return self.has_route(peer);
            }
        }
    }

    /// 把一批包发给 `peer`。没有路时包被悄悄丢掉，连接自己会在空闲超时之内等路恢复。
    ///
    /// # Errors
    ///
    /// 只会返回 [`io::ErrorKind::WouldBlock`]：现在发不了，等 [`writable`](Self::writable) 之后再试。
    pub fn try_send(&self, peer: NodeId, packets: &Packets<'_>) -> io::Result<()> {
        let table = self.shared.table();
        match table.peers.get(&peer) {
            Some(slot) => slot.send(&self.shared, packets),
            None => Ok(()),
        }
    }

    /// 把一批丢了也没关系的包发给 `peer`，不等：端口忙着、经 TCP 中转时队列满了，或者没有路，发不出去的就丢掉。
    /// 返回没有发出去的那一部分。
    ///
    /// 不等 [`writable`](Self::writable) 的调用方用这个，不用 [`try_send`](Self::try_send)：那个入口说过一次"现在发不了"之后，
    /// 要等到有人等来了可写才会再去问内核。
    pub fn send_or_drop(&self, peer: NodeId, packets: &Packets<'_>) -> Unsent {
        let table = self.shared.table();
        match table.peers.get(&peer) {
            Some(slot) => slot.send_or_drop(&self.shared, packets),
            None => Unsent::all(packets),
        }
    }

    /// 到 `peer` 的包现在是不是装在一条 TCP 里走：本节点到 relay 的那一段是 TCP，或者本节点自己是 relay、对端经 TCP 挂在上面。
    /// 不认识这个对端、没有路时是 `false`。
    ///
    /// 那一段是一条可靠的流，有它自己的重传和拥塞控制。没有人管量的包（[`send_or_drop`](Self::send_or_drop) 发的那种）
    /// 把它灌满之后，同一条流上的东西都跟着晚到；量要有人管着才不会这样，所以连接层这时不该用那个入口发大量的包。
    #[must_use]
    pub fn carried_in_tcp(&self, peer: NodeId) -> bool {
        self.shared.table().peers.get(&peer).is_some_and(|slot| slot.carried_in_tcp(&self.shared))
    }

    /// 等到可以再发。可以有多个任务同时等。
    ///
    /// # Errors
    ///
    /// socket 本身出错。
    pub async fn writable(&self) -> io::Result<()> {
        self.shared.port.writable().await
    }

    /// 收一批发给本节点的连接包。返回填了前几个缓冲区，对应的 `metas` 说明每个缓冲区里是谁的包。
    ///
    /// 那个 UDP 端口上的所有数据报都从这里过：连接包留给调用方，其余的在这里分给路径层自己和本地的 relay。
    /// 所以必须有人一直在调用它，路径层和 relay 才会工作。每个缓冲区要装得下
    /// "[`max_datagram_len`](Self::max_datagram_len) × [`max_receive_segments`](Self::max_receive_segments)" 字节。
    ///
    /// # Errors
    ///
    /// socket 本身出错。
    pub fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], metas: &mut [PacketMeta]) -> Poll<io::Result<usize>> {
        let limit = bufs.len().min(metas.len());
        let queued = self.drain_inbound(cx, &mut bufs[..limit], metas);
        if queued > 0 {
            return Poll::Ready(Ok(queued));
        }
        let mut raw = [RecvMeta::default(); BATCH_SIZE];
        let limit = limit.min(BATCH_SIZE);
        loop {
            let count = ready!(self.shared.port.poll_recv(cx, &mut bufs[..limit], &mut raw[..limit]))?;
            let mut kept = 0;
            {
                let table = self.shared.table();
                for index in 0..count {
                    if let Some(meta) = self.demux(&table, &raw[index], &mut bufs[index]) {
                        bufs.swap(kept, index);
                        metas[kept] = meta;
                        kept += 1;
                    }
                }
            }
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
            // 这一批里没有能直接留在缓冲区里的，但可能有放进了队列的。
            let queued = self.drain_inbound(cx, &mut bufs[..limit], metas);
            if queued > 0 {
                return Poll::Ready(Ok(queued));
            }
        }
    }

    /// 这个端口上一个数据报最长多少字节：连接包的上限加上最长的中转头（经 4 个 relay 时的）。
    #[must_use]
    pub const fn max_datagram_len() -> usize {
        i3t_proto::MAX_CONN_PACKET_LEN as usize + RouteHeader::MAX_LEN
    }

    /// 一次发送最多能带几个包。
    #[must_use]
    pub fn max_transmit_segments(&self) -> usize {
        self.shared.port.max_gso_segments()
    }

    /// 一个接收缓冲区里最多会有几个包。
    #[must_use]
    pub fn max_receive_segments(&self) -> usize {
        self.shared.port.gro_segments()
    }

    /// 发出去的包在路上会不会被 IP 层分片。
    #[must_use]
    pub fn may_fragment(&self) -> bool {
        self.shared.port.may_fragment()
    }

    /// 本地的 relay 收到了发给本节点的中转帧（从它的 TCP 中转腿上）：`packet` 是去掉中转头之后的连接包。
    pub fn deliver_local(&self, src: NodeId, packet: Bytes) {
        if self.shared.inbound.try_send((src, packet)).is_err() {
            tracing::trace!(peer = %src, "连接层来不及收，丢掉一个包");
        }
    }

    /// 到每个对端现在走哪条路，延迟多少。
    ///
    /// # Panics
    ///
    /// 控制任务 panic 过（锁中毒）。
    #[must_use]
    pub fn routes(&self) -> Vec<RouteEntry> {
        self.status().routes.clone()
    }

    /// 本节点的候选端点：网卡地址，加上 relay 和地址查询服务器看到的地址。不建立直连的节点返回空表。
    #[must_use]
    pub fn endpoints(&self) -> Vec<SocketAddr> {
        self.status().endpoints.clone()
    }

    /// 别人看到的本节点地址：relay（以及地址查询服务器）看到的来源地址，和路由器上映射出来的外部地址（UDP 和 TCP）。
    ///
    /// 和 [`endpoints`](Self::endpoints) 不同，不管本节点用不用直连都照样给出：不建立直连的节点不向对端公布自己的地址，
    /// 但本节点自己还是要知道它们（比如出口不替人去连本节点自己的公网地址）。地址查询服务器只在可以直连时才去问，
    /// 所以只经 relay 的节点这里只有 relay 看到的和映射出来的。端口照实给出，只关心 IP 的调用方自己去掉。
    #[must_use]
    pub fn public_addresses(&self) -> Vec<SocketAddr> {
        self.status().public_addresses.clone()
    }

    /// 映射出来的端口是不是随对端变化。要有两个以上的观察点才知道；是的话这台机器所在的网络基本打不了洞。
    #[must_use]
    pub fn mapping_varies(&self) -> Option<bool> {
        self.status().mapping_varies
    }

    /// 本节点挂靠的 relay（会话已经建好的）和到它们的延迟，按延迟从低到高。
    #[must_use]
    pub fn attached(&self) -> Vec<Attachment> {
        self.status().attached.clone()
    }

    /// 本节点试过的各个 relay 连没连上、它们看到的本节点 IP，报给 controller 用。
    ///
    /// 试的是 netmap 里的每个 relay：挂靠的、经过的用会话（UDP 和 TCP 一起），别的每分钟用 UDP 问一次延迟，问不到的每十分钟
    /// 用会话试一次（同一时刻只试一个）。有会话的排在前面，最多 [`i3t_model::control::MAX_RELAY_TRIES`] 个。
    #[must_use]
    pub fn relay_tries(&self) -> Vec<i3t_model::control::RelayTry> {
        self.status().relay_tries.clone()
    }

    /// 订阅换路事件。每一次换路都有一条，带着给人看的原因。
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<RouteChange> {
        self.shared.changes.subscribe()
    }

    /// 到每个对端的选路情况：考虑过的候选路径和各自测出来的代价、现在走的是哪一条、为什么。
    /// 没有连接的对端也在里面，候选是按手上现有的测量值算的。
    #[must_use]
    pub fn path_reports(&self) -> Vec<PathReport> {
        self.status().reports.clone()
    }

    /// 到 `peer` 的选路情况；它不在 netmap 里时返回 `None`。
    #[must_use]
    pub fn path_report(&self, peer: NodeId) -> Option<PathReport> {
        self.status().reports.iter().find(|report| report.peer == peer).cloned()
    }

    /// 到 `peer` 有没有经 relay 的路：现在就走着，或者最近一次算的候选里有（本节点有会话的 relay 接得上对端挂靠的 relay）。
    ///
    /// 连接层靠它判断一条空闲的连接关掉之后还建不建得回来：直连要靠信令重新打洞，经 relay 的不用。
    #[must_use]
    pub fn has_relay_path(&self, peer: NodeId) -> bool {
        let relayed = |route: &Route| matches!(route, Route::Relay { .. });
        self.status()
            .reports
            .iter()
            .find(|report| report.peer == peer)
            .is_some_and(|report| relayed(&report.route) || report.candidates.iter().any(|candidate| relayed(&candidate.route)))
    }

    /// 本节点手上的骨干矩阵：每个 relay 最新的一行（它的状态、负载、到别的 relay 的延迟），过期的不在里面。
    #[must_use]
    pub fn backbone(&self) -> Vec<BackboneRow> {
        self.status().backbone.clone()
    }

    /// 打开一个主动测试的时间窗：在窗内回答对端带着这个编号的测试探测，和指定的 relay 保持会话，
    /// 对端算作活跃的。丢弃返回的值就关掉它；不丢也会在时间窗到了时自己关掉。
    #[must_use]
    pub fn open_test(&self, spec: TestSpec) -> TestGuard {
        let test = spec.test;
        if self.shared.ctrl.try_send(Ctrl::OpenTest(spec)).is_err() {
            tracing::warn!(test, "控制任务忙不过来，主动测试的时间窗没有打开");
        }
        TestGuard { ctrl: self.shared.ctrl.clone(), test }
    }

    /// 在一条路径上发一列测试探测，等它们的回答。要先打开这个测试（[`open_test`](Self::open_test)）。
    ///
    /// # Errors
    ///
    /// 测试没有打开、对端不在 netmap 里、此刻走不了这条路径，或者本节点的路径限制不允许。
    pub async fn train(&self, spec: TrainSpec) -> Result<TrainReport, TrainError> {
        let (reply, answer) = oneshot::channel();
        self.shared.ctrl.send(Ctrl::Train { spec, reply }).await.map_err(|_| TrainError::Stopped)?;
        answer.await.map_err(|_| TrainError::Stopped)?
    }

    /// 把到 `peer` 的路暂时固定在 `path` 上，最多 `limit`（不超过 [`crate::diag::MAX_PIN`]）。
    /// 丢弃返回的值就解除；到期也会自己解除。这条路此刻走不了时照常按选路规则走，路通了再换过去。
    #[must_use]
    pub fn pin(&self, peer: NodeId, path: TestPath, limit: Duration) -> RoutePin {
        let id = self.next_pin.fetch_add(1, Ordering::Relaxed);
        let pin = Pin { id, path, until: Instant::now() + limit };
        if self.shared.ctrl.try_send(Ctrl::Pin { peer, pin }).is_err() {
            tracing::warn!(%peer, "控制任务忙不过来，没有固定到对端的路");
        }
        // 固定之后马上重新选路，不等下一个定时器。
        let _queued = self.shared.ctrl.try_send(Ctrl::Wake);
        RoutePin { ctrl: self.shared.ctrl.clone(), peer, id }
    }

    /// 试一次到 `peer` 的直连，最多等 `limit`。已经有可用的直连时马上回答。`side` 是带头（现在就试，不等退避）
    /// 还是跟随（等对端来试，见 [`Side`]）。
    pub async fn attempt_direct(&self, peer: NodeId, side: Side, limit: Duration) -> DirectAttempt {
        let stopped = DirectAttempt {
            ok: false,
            already: false,
            kind: None,
            elapsed: None,
            failure: Some(DirectFailure::NotPeer),
            udp: None,
            mapping_varies: None,
            candidates: 0,
        };
        let (reply, answer) = oneshot::channel();
        if self.shared.ctrl.send(Ctrl::AttemptDirect { peer, side, limit, reply }).await.is_err() {
            return stopped;
        }
        answer.await.unwrap_or(stopped)
    }

    /// 两种选路模式此刻各会选哪条路；对端不在 netmap 里时是 `None`。
    pub async fn decide(&self, peer: NodeId) -> Option<RouteDecision> {
        let (reply, answer) = oneshot::channel();
        self.shared.ctrl.send(Ctrl::Decide { peer, reply }).await.ok()?;
        answer.await.ok().flatten()
    }

    /// 一条到 `peer` 的路径上各段此刻的测量值。
    pub async fn hops(&self, peer: NodeId, path: TestPath) -> Vec<HopReport> {
        let (reply, answer) = oneshot::channel();
        if self.shared.ctrl.send(Ctrl::Hops { peer, path, reply }).await.is_err() {
            return Vec::new();
        }
        answer.await.unwrap_or_default()
    }

    fn status(&self) -> std::sync::MutexGuard<'_, Status> {
        self.shared.status.lock().expect("path status mutex poisoned")
    }

    /// 把队列里的包拷进连接层的缓冲区，一个缓冲区一个。
    fn drain_inbound(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], metas: &mut [PacketMeta]) -> usize {
        let mut queue = self.shared.inbound_rx.lock().expect("inbound queue mutex poisoned");
        let mut filled = 0;
        while filled < bufs.len() {
            let Poll::Ready(Some((peer, packet))) = queue.poll_recv(cx) else { break };
            // TCP 中转来的、本节点的 relay 交过来的包里也可能夹着对端的路径探测和测试探测。
            if let Some(frame) = path_probe(&packet) {
                let queued =
                    self.relayed_probe(peer, frame).is_some_and(|inbound| self.shared.queue_frame(self.shared.port.local_addr(), inbound));
                if !queued {
                    tracing::trace!(%peer, "丢掉一个经 relay 来的探测：控制任务忙不过来，或者它不属于任何打开着的测试");
                }
                continue;
            }
            let buf = &mut bufs[filled];
            match self.shared.table().peers.get(&peer) {
                Some(slot) if packet.len() <= buf.len() => slot.received(&self.shared),
                Some(_) | None => continue,
            }
            buf[..packet.len()].copy_from_slice(&packet);
            metas[filled] = PacketMeta { peer, len: packet.len(), stride: packet.len(), ecn: None };
            filled += 1;
        }
        filled
    }

    /// 处理一个接收缓冲区。里面可能是来自同一个地址的多个数据报，种类和去向各不相同，逐个看：
    /// 连接包就地挪到缓冲区开头留给连接层，别的当场分发。返回留下来的那一段。
    fn demux(&self, table: &Table, raw: &RecvMeta, buf: &mut [u8]) -> Option<PacketMeta> {
        let data = &mut buf[..raw.len];
        let stride = raw.stride.max(1);
        let mut kept: Option<Kept<'_>> = None;
        // 连续的、归本地 relay 处理的数据报攒成一段再交给它，这样它还能成批地转发。
        let mut for_relay: Option<Range<usize>> = None;
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + stride).min(data.len());
            let verdict = self.classify(table, raw.addr, &data[offset..end]);
            if !matches!(verdict, Verdict::Relay)
                && let Some(span) = for_relay.take()
            {
                self.hand_to_local_relay(raw, &data[span], stride);
            }
            match verdict {
                Verdict::Packet { slot, skip } => {
                    let packet = offset + skip..end;
                    match &mut kept {
                        None => {
                            data.copy_within(packet.clone(), 0);
                            kept = Some(Kept { slot, stride: packet.len(), len: packet.len(), open: true });
                        }
                        // 同一个对端、长度也接得上的，接在后面；不然就拷出去走队列。
                        Some(run) if run.open && Arc::ptr_eq(run.slot, slot) && packet.len() <= run.stride => {
                            data.copy_within(packet.clone(), run.len);
                            run.len += packet.len();
                            run.open = packet.len() == run.stride;
                        }
                        Some(_) => {
                            if self.shared.inbound.try_send((slot.id, Bytes::copy_from_slice(&data[packet]))).is_err() {
                                tracing::trace!(peer = %slot.id, "连接层来不及收，丢掉一个包");
                            }
                        }
                    }
                }
                Verdict::Relay => for_relay = Some(for_relay.map_or(offset..end, |span| span.start..end)),
                Verdict::Control(frame) => {
                    if !self.shared.queue_frame(raw.addr, frame) {
                        tracing::trace!(from = %raw.addr, "控制任务忙不过来，丢掉一帧");
                    }
                }
                Verdict::Drop => {}
            }
            offset = end;
        }
        if let Some(span) = for_relay {
            self.hand_to_local_relay(raw, &data[span], stride);
        }
        kept.map(|run| PacketMeta { peer: run.slot.id, len: run.len, stride: run.stride, ecn: raw.ecn })
    }

    fn hand_to_local_relay(&self, raw: &RecvMeta, data: &[u8], stride: usize) {
        if let Some(relay) = self.shared.local_relay.get() {
            relay.handle_udp(raw.addr, raw.ecn, data, stride);
        }
    }

    /// 一个数据报归谁。
    fn classify<'t>(&self, table: &'t Table, from: SocketAddr, datagram: &[u8]) -> Verdict<'t> {
        let clock = &self.shared.clock;
        match Datagram::parse(datagram) {
            // 直连的连接包，或者封好的网络包（它和连接包走同一条路，一样交给连接层）：
            // 来源地址不是任何对端已验证的直连地址时丢掉。
            Ok(Datagram::Conn(_) | Datagram::Sealed(_)) => match table.direct.get(&from) {
                Some(slot) => {
                    slot.last_rx_direct.touch(clock);
                    slot.received(&self.shared);
                    Verdict::Packet { slot, skip: 0 }
                }
                None => Verdict::Drop,
            },
            Ok(Datagram::Relayed { header, packet }) if header.dst == self.shared.me => {
                // 发给本节点的中转帧只认两种来源：netmap 里的 relay；或者挂在本节点自己的 relay 上的节点，
                // 并且帧里的来源节点就是那个会话的主人。
                let vouched = match table.relays.get(&from) {
                    Some(relay) => {
                        relay.last_rx.touch(clock);
                        true
                    }
                    None => self.shared.local_relay.get().is_some_and(|relay| relay.session_at(header.src, from)),
                };
                match (table.peers.get(&header.src), path_probe(packet)) {
                    (Some(_), Some(frame)) if vouched => self.relayed_probe(header.src, frame).map_or(Verdict::Drop, Verdict::Control),
                    // 空的连接包不交上去：它会成为一个长度为 0 的包，连接层没有理由收到这种东西。
                    (Some(slot), None) if vouched && !packet.is_empty() => {
                        slot.received(&self.shared);
                        Verdict::Packet { slot, skip: RelayHeader::LEN }
                    }
                    (Some(_) | None, _) => Verdict::Drop,
                }
            }
            // 多级中转的包，本节点是目的节点、又不在它的路径上：只认路径上最后一个 relay 发来的，而且它得是 netmap 里的 relay。
            Ok(Datagram::Routed { header, packet }) if header.dst == self.shared.me && header.relays.around(self.shared.me).is_none() => {
                match (table.relays.get(&from), table.peers.get(&header.src)) {
                    (Some(relay), Some(slot)) if relay.id == header.relays.last() => {
                        relay.last_rx.touch(clock);
                        match path_probe(packet) {
                            Some(frame) => self.relayed_probe(header.src, frame).map_or(Verdict::Drop, Verdict::Control),
                            None if packet.is_empty() => Verdict::Drop,
                            None => {
                                slot.received(&self.shared);
                                Verdict::Packet { slot, skip: header.encoded_len() }
                            }
                        }
                    }
                    _ => Verdict::Drop,
                }
            }
            // 发给别人的中转帧、路径上有本节点的多级中转帧、节点发来的会话帧、地址查询：本节点是 relay 时由它处理，不是就没有人理。
            Ok(Datagram::Relayed { .. } | Datagram::Routed { .. } | Datagram::AddrQuery(_)) => Verdict::Relay,
            Ok(Datagram::Session(frame)) if frame.is_request() => Verdict::Relay,
            // relay 的应答只认从 netmap 里 relay 的地址来的：别的地址来的没有人在等，不值得进控制任务的队列。
            Ok(Datagram::Session(frame)) => match table.relays.get(&from) {
                Some(relay) => {
                    relay.last_rx.touch(clock);
                    match (frame, Refused::echo(datagram)) {
                        (session::Frame::Error(refused), Some(echo)) => Verdict::Control(Inbound::Refusal(refused, echo)),
                        (frame, _) => Verdict::Control(Inbound::Session(frame)),
                    }
                }
                None => Verdict::Drop,
            },
            // 矩阵行只认从 netmap 里的 relay 地址来的；是不是有会话、签名对不对由控制任务去查。
            Ok(Datagram::Row(frame)) => match table.relays.get(&from) {
                Some(relay) => {
                    relay.last_rx.touch(clock);
                    Verdict::Control(Inbound::Row(Bytes::copy_from_slice(frame)))
                }
                None => Verdict::Drop,
            },
            // 探测只收发给本节点的、自称来自 netmap 里的对端的：别的不可能验得过签名，不值得进控制任务的队列。
            Ok(Datagram::Probe(frame)) => {
                let probe::Ends { src, dst } = frame.ends();
                if dst != self.shared.me || !table.peers.contains_key(&src) {
                    return Verdict::Drop;
                }
                match frame {
                    probe::Frame::Ping(_) | probe::Frame::Pong(_) => Verdict::Control(Inbound::Probe(frame)),
                    probe::Frame::TestPing(TestPing { test, .. }) | probe::Frame::TestPong(TestPong { test, .. })
                        if self.shared.expects_test(test, src) =>
                    {
                        Verdict::Control(Inbound::Test { frame, at: Instant::now(), relayed: false })
                    }
                    probe::Frame::TestPing(_) | probe::Frame::TestPong(_) => Verdict::Drop,
                }
            }
            Ok(Datagram::AddrReply(reply)) => Verdict::Control(Inbound::AddrReply(reply)),
            Err(_) => Verdict::Drop,
        }
    }
}

impl Drop for Paths {
    fn drop(&mut self) {
        self.control.abort();
    }
}

impl Paths {
    /// 经 relay 送到的包里夹着的探测帧（`peer` 是中转头里的来源）该交给控制任务的哪一处。
    /// 测试探测只有属于一个打开着的、和 `peer` 之间的测试时才交，帧里写的来源也要就是 `peer`。
    fn relayed_probe(&self, peer: NodeId, frame: probe::Frame) -> Option<Inbound> {
        match frame {
            probe::Frame::Ping(_) | probe::Frame::Pong(_) => Some(Inbound::PathProbe { peer, frame }),
            probe::Frame::TestPing(TestPing { test, src, .. }) | probe::Frame::TestPong(TestPong { test, src, .. }) => {
                (src == peer && self.shared.expects_test(test, peer)).then(|| Inbound::Test { frame, at: Instant::now(), relayed: true })
            }
        }
    }
}

/// 一个打开着的主动测试。丢弃它就关掉这个测试的时间窗。
#[derive(Debug)]
pub struct TestGuard {
    ctrl: mpsc::Sender<Ctrl>,
    test: TestId,
}

impl Drop for TestGuard {
    fn drop(&mut self) {
        // 队列满了也没有关系：时间窗到了控制任务自己会关。
        let _queued = self.ctrl.try_send(Ctrl::CloseTest(self.test));
    }
}

/// 一次暂时固定的路。丢弃它就解除固定。
#[derive(Debug)]
pub struct RoutePin {
    ctrl: mpsc::Sender<Ctrl>,
    peer: NodeId,
    id: u64,
}

impl Drop for RoutePin {
    fn drop(&mut self) {
        // 队列满了也没有关系：固定有期限，到了控制任务自己会解除。
        if self.ctrl.try_send(Ctrl::Unpin { peer: self.peer, id: self.id }).is_err() {
            tracing::debug!(peer = %self.peer, "控制任务忙不过来，固定的路等到期自己解除");
        }
        let _queued = self.ctrl.try_send(Ctrl::Wake);
    }
}

/// 经 relay 送到的包如果不是连接包而是一个探测帧，那是对端发来的端到端路径探测（或者对它的回答）。
/// 连接包的首字节一定带着 QUIC 的那一位，所以两者不会混淆。
fn path_probe(packet: &[u8]) -> Option<probe::Frame> {
    match Datagram::parse(packet) {
        Ok(Datagram::Probe(frame)) => Some(frame),
        _ => None,
    }
}

/// 一个数据报的去向。
enum Verdict<'t> {
    /// 连接包，是 `slot` 这个对端发来的；前 `skip` 个字节是中转头，要去掉。
    Packet {
        slot: &'t Arc<PeerSlot>,
        skip: usize,
    },
    /// 归本地的 relay。
    Relay,
    /// 归控制任务。
    Control(Inbound),
    Drop,
}

/// 一个接收缓冲区里留给连接层的那一段：都来自同一个对端，除了最后一个都一样长。
struct Kept<'t> {
    slot: &'t Arc<PeerSlot>,
    stride: usize,
    len: usize,
    /// 还能不能往后接：接上一个短的之后就不能了。
    open: bool,
}

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use i3t_proto::session::{Init, Pong};

    use super::*;

    const ME: u32 = 1;
    const RELAY_ADDR: &str = "198.51.100.9:20330";

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// 一个路径层：对端是 2 和 3，netmap 里有一个 relay（编号 9）。没有人去读它的 UDP 端口，测试直接把缓冲区交给 `demux`。
    fn paths() -> (Paths, watch::Sender<Arc<Netmap>>) {
        let key = |seed: u8| i3t_proto::PublicKey::from_bytes([seed; 32]);
        let peer = |id: u32| serde_json::json!({ "id": id, "key": key(2), "name": format!("n{id}"), "virtual_ip": format!("10.66.0.{id}"), "inbound": true, "outbound": true });
        let netmap = serde_json::json!({
            "version": 1,
            "network": { "name": "test", "domain": "test.i3t", "cidr": "10.66.0.0/16" },
            "me": { "id": ME, "name": "me", "virtual_ip": "10.66.0.1" },
            "peers": [peer(2), peer(3)],
            "relays": [{ "id": 9, "key": key(9), "name": "relay", "udp": [RELAY_ADDR] }],
        });
        let (sender, netmap) = watch::channel(Arc::new(serde_json::from_value(netmap).unwrap()));
        let port = Arc::new(UdpPort::bind(addr("127.0.0.1:0")).unwrap());
        let key = Arc::new(NodeKey::generate().unwrap());
        (Paths::new(PathConfig { key, port, netmap, addr_servers: Vec::new() }), sender)
    }

    fn relayed(dst: u32, src: u32, packet: &[u8]) -> Vec<u8> {
        let mut datagram = RelayHeader { dst: node(dst), src: node(src) }.to_bytes().to_vec();
        datagram.extend_from_slice(packet);
        datagram
    }

    /// 把一批数据报当作内核合并接收交上来的一个缓冲区，过一遍 `demux`。返回留给连接层的那一段。
    fn demux(paths: &Paths, from: &str, datagrams: &[Vec<u8>]) -> Option<(PacketMeta, Vec<u8>)> {
        let stride = datagrams[0].len();
        assert!(datagrams[..datagrams.len() - 1].iter().all(|datagram| datagram.len() == stride), "除了最后一个都要一样长");
        let mut buf = datagrams.concat();
        let raw = RecvMeta { addr: addr(from), len: buf.len(), stride, ecn: Some(Ecn::Ect0) };
        let table = paths.shared.table();
        let meta = paths.demux(&table, &raw, &mut buf)?;
        Some((meta, buf[..meta.len].to_vec()))
    }

    /// 走队列的那些包。
    fn queued(paths: &Paths) -> Vec<(NodeId, Vec<u8>)> {
        let mut storage = vec![0u8; 8 * 2048];
        let mut bufs: Vec<IoSliceMut<'_>> = storage.chunks_mut(2048).map(IoSliceMut::new).collect();
        let mut metas = [PacketMeta { peer: node(ME), len: 0, stride: 0, ecn: None }; 8];
        let filled = paths.drain_inbound(&mut Context::from_waker(Waker::noop()), &mut bufs, &mut metas);
        metas[..filled].iter().zip(&bufs).map(|(meta, buf)| (meta.peer, buf[..meta.len].to_vec())).collect()
    }

    #[derive(Default)]
    struct RecordingRelay {
        handled: Mutex<Vec<(SocketAddr, usize, Vec<u8>)>>,
        clients: Vec<(NodeId, SocketAddr)>,
    }

    impl LocalRelay for RecordingRelay {
        fn handle_udp(&self, from: SocketAddr, _ecn: Option<Ecn>, data: &[u8], stride: usize) {
            self.handled.lock().unwrap().push((from, stride, data.to_vec()));
        }

        fn has_session(&self, client: NodeId) -> bool {
            self.clients.iter().any(|(id, _)| *id == client)
        }

        fn session_reopened(&self, _client: NodeId) -> Option<Duration> {
            None
        }

        fn session_at(&self, client: NodeId, from: SocketAddr) -> bool {
            self.clients.contains(&(client, from))
        }

        fn send_to_client(&self, _client: NodeId, _contents: &[u8], _segment_size: Option<usize>, _ecn: Option<Ecn>) -> bool {
            false
        }

        fn session_leg(&self, client: NodeId) -> Option<crate::SessionLeg> {
            self.has_session(client).then_some(crate::SessionLeg::Udp)
        }

        fn handle_leg_frame(&self, _conn: u64, _addr: SocketAddr, _sender: &i3t_underlay::tcp_leg::FrameSender, _frame: &[u8]) {}

        fn leg_closed(&self, _conn: u64) {}

        fn status(&self) -> Option<crate::RelayStatus> {
            None
        }

        fn publish_row(&self, _links: &[i3t_proto::backbone::Link]) {}

        fn broadcast(&self, _frame: &[u8]) {}
    }

    #[tokio::test]
    async fn relayed_packets_from_one_peer_stay_in_the_buffer_with_their_headers_removed() {
        let (paths, _netmap) = paths();
        let batch = [relayed(ME, 2, &[0xc1; 1200]), relayed(ME, 2, &[0xc2; 1200]), relayed(ME, 2, &[0xc3; 700])];
        let (meta, kept) = demux(&paths, RELAY_ADDR, &batch).expect("这些包都是给连接层的");
        assert_eq!(meta, PacketMeta { peer: node(2), len: 3100, stride: 1200, ecn: Some(Ecn::Ect0) });
        assert_eq!(kept, [vec![0xc1; 1200], vec![0xc2; 1200], vec![0xc3; 700]].concat());
        assert!(queued(&paths).is_empty());
    }

    #[tokio::test]
    async fn a_batch_mixing_peers_keeps_one_peer_in_place_and_queues_the_rest_in_order() {
        let (paths, _netmap) = paths();
        // 同一个 relay 转来的、两个对端的包交错在一批里；最后一个短一些。
        let batch = [
            relayed(ME, 2, &[0xc1; 1000]),
            relayed(ME, 3, &[0xd1; 1000]),
            relayed(ME, 2, &[0xc2; 1000]),
            relayed(ME, 3, &[0xd2; 1000]),
            relayed(ME, 2, &[0xc3; 400]),
        ];
        let (meta, kept) = demux(&paths, RELAY_ADDR, &batch).expect("对端 2 的包留在缓冲区里");
        assert_eq!(meta, PacketMeta { peer: node(2), len: 2400, stride: 1000, ecn: Some(Ecn::Ect0) });
        assert_eq!(kept, [vec![0xc1; 1000], vec![0xc2; 1000], vec![0xc3; 400]].concat());
        assert_eq!(queued(&paths), [(node(3), vec![0xd1; 1000]), (node(3), vec![0xd2; 1000])], "另一个对端的包走队列，顺序不变");

        // 留在缓冲区里的那一段只有最后一个可以短。短的接上之后，同一个对端后面的包也只能走队列。
        let batch = [relayed(ME, 3, &[0xd1; 600]), relayed(ME, 2, &[0xc1; 600]), relayed(ME, 3, &[0xd2; 100])];
        let (meta, _kept) = demux(&paths, RELAY_ADDR, &batch).unwrap();
        assert_eq!(meta, PacketMeta { peer: node(3), len: 700, stride: 600, ecn: Some(Ecn::Ect0) });
        assert_eq!(queued(&paths), [(node(2), vec![0xc1; 600])]);
    }

    #[tokio::test]
    async fn only_packets_vouched_for_by_a_relay_or_a_verified_address_reach_the_connection_layer() {
        let (paths, _netmap) = paths();
        let quic = vec![0xc0u8; 1200];

        // 中转帧：来源不是 relay 的地址；或者帧里的来源节点不是对端。
        assert!(demux(&paths, "203.0.113.50:1", &[relayed(ME, 2, &quic)]).is_none());
        assert!(demux(&paths, RELAY_ADDR, &[relayed(ME, 77, &quic)]).is_none());
        assert!(demux(&paths, RELAY_ADDR, &[relayed(ME, 2, &quic)]).is_some());

        // 直连的连接包：来源地址没有验证过时丢掉；验证过之后算作那个对端的。
        let direct = "203.0.113.7:4000";
        assert!(demux(&paths, direct, std::slice::from_ref(&quic)).is_none());
        {
            let mut table = paths.shared.table_mut();
            let slot = Arc::clone(&table.peers[&node(3)]);
            table.direct.insert(addr(direct), slot);
        }
        let (meta, kept) = demux(&paths, direct, &[quic.clone(), quic.clone()]).unwrap();
        assert_eq!(meta, PacketMeta { peer: node(3), len: 2400, stride: 1200, ecn: Some(Ecn::Ect0) });
        assert_eq!(kept.len(), 2400);

        // 不认识的、残缺的：丢掉。
        assert!(demux(&paths, direct, &[vec![0x3f; 100]]).is_none());
        assert!(demux(&paths, RELAY_ADDR, &[vec![0x01, 0, 0]]).is_none());
        assert!(queued(&paths).is_empty());
    }

    #[tokio::test]
    async fn frames_for_the_local_relay_are_handed_over_in_contiguous_runs() {
        let (paths, _netmap) = paths();
        let client = addr("203.0.113.60:5000");
        let relay = Arc::new(RecordingRelay { handled: Mutex::default(), clients: vec![(node(2), client)] });
        paths.set_local_relay(Arc::clone(&relay) as Arc<dyn LocalRelay>);

        // 同一个来源的一批：两个要转发给别人的、一个发给本节点的、又两个要转发的。
        let stride = RelayHeader::LEN + 500;
        let batch = [
            relayed(3, 2, &[1; 500]),
            relayed(8, 2, &[2; 500]),
            relayed(ME, 2, &[0xc3; 500]),
            relayed(3, 2, &[4; 500]),
            relayed(3, 2, &[5; 100]),
        ];
        let (meta, kept) = demux(&paths, "203.0.113.60:5000", &batch).expect("中间那个是给本节点的");
        // 发给本节点的那个：来源节点在本地 relay 上的会话就绑定在这个地址上，所以收下。
        assert_eq!(meta, PacketMeta { peer: node(2), len: 500, stride: 500, ecn: Some(Ecn::Ect0) });
        assert_eq!(kept, vec![0xc3; 500]);
        let handled = relay.handled.lock().unwrap().clone();
        assert_eq!(handled.len(), 2, "被发给本节点的那个隔开，成了两段");
        assert_eq!(handled[0], (client, stride, [batch[0].clone(), batch[1].clone()].concat()));
        assert_eq!(handled[1], (client, stride, [batch[3].clone(), batch[4].clone()].concat()), "原样交过去，一个字节都不改");

        // 节点发给 relay 的会话帧也交给它；relay 的应答不交。
        relay.handled.lock().unwrap().clear();
        let init = Init { node: node(2), nonce: [1; 8] }.to_bytes().to_vec();
        assert!(demux(&paths, "203.0.113.60:5000", std::slice::from_ref(&init)).is_none());
        assert!(demux(&paths, RELAY_ADDR, &[Pong { nonce: [1; 8], observed: client }.to_bytes()]).is_none());
        assert_eq!(*relay.handled.lock().unwrap(), [(client, init.len(), init)]);

        // 别的地址冒充那个节点发给本节点的帧：本地 relay 不认，丢掉。
        assert!(demux(&paths, "203.0.113.61:5000", &[relayed(ME, 2, &[0xc3; 500])]).is_none());
    }

    #[tokio::test]
    async fn frames_nobody_is_waiting_for_never_reach_the_control_task() {
        let (paths, _netmap) = paths();
        let table = paths.shared.table();
        let stranger = addr("203.0.113.50:1");
        let control = |from: SocketAddr, datagram: &[u8]| matches!(paths.classify(&table, from, datagram), Verdict::Control(_));
        let ping = |src: u32, dst: u32| probe::Ping { src: node(src), dst: node(dst), nonce: [1; 8], signature: [0; 64] }.to_bytes();

        // 探测：只有发给本节点、自称来自 netmap 里的对端的才交给控制任务去验签名。
        assert!(control(stranger, &ping(2, ME)));
        assert!(!control(stranger, &ping(2, 77)), "不是发给本节点的");
        assert!(!control(stranger, &ping(77, ME)), "自称的来源不是对端");
        let pong = probe::Pong { src: node(77), dst: node(ME), nonce: [1; 8], observed: stranger, signature: [0; 64] };
        assert!(!control(stranger, &pong.to_bytes()));

        // relay 的应答只认 netmap 里 relay 的地址。错误帧连同它回显的字节一起交过去。
        let error = Refused { reason: i3t_proto::session::RefusalReason::NoSession, node: node(ME) }.to_bytes_echoing(&[7; 8]);
        assert!(!control(stranger, &Pong { nonce: [1; 8], observed: stranger }.to_bytes()));
        assert!(!control(stranger, &error));
        assert!(matches!(
            paths.classify(&table, addr(RELAY_ADDR), &error),
            Verdict::Control(Inbound::Refusal(_, [7, 7, 7, 7, 7, 7, 7, 7]))
        ));
        assert!(control(addr(RELAY_ADDR), &Pong { nonce: [1; 8], observed: stranger }.to_bytes()));

        // 空的连接包不交给连接层。
        assert!(matches!(paths.classify(&table, addr(RELAY_ADDR), &relayed(ME, 2, &[])), Verdict::Drop));
    }

    #[tokio::test]
    async fn a_pin_is_released_when_its_holder_drops_it_even_if_the_holding_task_is_aborted() {
        let (ctrl, mut queue) = mpsc::channel(8);
        let holder = tokio::spawn(async move {
            let _pin = RoutePin { ctrl, peer: node(2), id: 5 };
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        holder.abort();
        assert!(holder.await.unwrap_err().is_cancelled());
        assert!(matches!(queue.recv().await, Some(Ctrl::Unpin { peer, id: 5 }) if peer == node(2)), "任务被取消，固定照样解除");

        let (ctrl, mut queue) = mpsc::channel(8);
        drop(TestGuard { ctrl, test: 7 });
        assert!(matches!(queue.recv().await, Some(Ctrl::CloseTest(7))));
    }

    #[tokio::test]
    async fn test_probes_reach_the_control_task_only_for_an_open_test_with_the_peer_that_sent_them() {
        let (paths, _netmap) = paths();
        let ping = |src: u32, test: u64| {
            probe::TestPing { src: node(src), dst: node(ME), test, seq: 0, path: None, signature: [0; 64] }.to_bytes().to_vec()
        };
        let table = paths.shared.table();
        let control =
            |datagram: &[u8]| matches!(paths.classify(&table, addr("203.0.113.50:1"), datagram), Verdict::Control(Inbound::Test { .. }));
        assert!(!control(&ping(2, 7)), "没有打开的测试");
        paths.shared.open_tests.write().unwrap().insert((7, node(2)));
        assert!(control(&ping(2, 7)));
        assert!(!control(&ping(3, 7)), "别的对端");
        assert!(!control(&ping(2, 8)), "别的测试");
        // 经 relay 来的：帧里写的来源要就是中转头里的来源。
        drop(table);
        assert!(paths.relayed_probe(node(2), probe::Frame::parse(&ping(2, 7)).unwrap()).is_some());
        assert!(paths.relayed_probe(node(3), probe::Frame::parse(&ping(2, 7)).unwrap()).is_none());
    }

    #[tokio::test]
    async fn packets_for_unknown_peers_are_dropped_and_sending_to_them_is_a_silent_no_op() {
        let (paths, netmap) = paths();
        paths.deliver_local(node(2), Bytes::from_static(b"from a tcp leg"));
        paths.deliver_local(node(77), Bytes::from_static(b"not a peer"));
        assert_eq!(queued(&paths), [(node(2), b"from a tcp leg".to_vec())]);

        let packets = Packets { contents: &[0xc0; 1200], segment_size: None, ecn: None };
        assert!(paths.try_send(node(77), &packets).is_ok());
        // 没有路的对端：包被悄悄丢掉。
        assert!(!paths.has_route(node(2)));
        assert!(paths.try_send(node(2), &packets).is_ok());
        assert!(!paths.wait_for_route(node(2), Duration::from_millis(100)).await);
        assert_eq!(paths.routes().len(), 2);
        drop(netmap);
    }
}
