//! relay 本体：握手、保活、转发。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use i3t_crypto::{NodeKey, Signature};
use i3t_model::Netmap;
use i3t_model::control::RelayUse;
use i3t_path::{BackboneInbox, RelayStatus, SessionLeg};
use i3t_proto::backbone::{Link, RelayState, Row};
use i3t_proto::datagram::{self, MAX_RELAY_HOPS, RelayHeader, RouteHeader};
use i3t_proto::session::{self, Accepted, Auth, Challenge, Echo, Frame, Nonce, Pong, RefusalReason, Refused};
use i3t_proto::{Datagram, MAX_CONN_PACKET_LEN, NodeId, PublicKey};
use i3t_underlay::tcp_leg::FrameSender;
use i3t_underlay::{Ecn, Transmit, UdpPort, addr_query};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::cookie::CookieJar;
use crate::counters::{Counters, DropReason, RelayCounters};
use crate::leg;
use crate::limit::{Bandwidth, HandshakeLimiter, RefusalLimiter};
use crate::session::{Binding, Origin, SESSION_TTL, Sessions, TcpConn};
use crate::users::Users;

/// 一个中转帧最长多少字节。再长的不是正常节点发的。
const MAX_RELAYED_LEN: usize = RouteHeader::MAX_LEN + MAX_CONN_PACKET_LEN as usize;
/// 多久清理一次过期的会话。TCP 监听不起来时也是隔这么久再试。
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// 目的就是本节点的中转帧交给谁。参数是来源节点和去掉中转头之后的包。
type LocalDelivery = Box<dyn Fn(NodeId, Bytes) + Send + Sync>;

/// 一个节点的 relay 角色。
///
/// 只有 netmap 里 `me.relay` 有值时它才工作；没有值时交给它的东西一律丢掉，不回应。netmap 可以随时变：
/// 启用、停用、允许的节点名单变化都立即生效，被去掉的节点、换了公钥的节点的会话当场删除。
///
/// UDP 上的数据报由收包的一方（路径层）交进来（[`handle_udp`](Self::handle_udp)）；同一个端口号上的 TCP 由它自己监听。
///
/// # 多级中转
///
/// 包头里写着要经过的全部 relay（[`i3t_proto::datagram`]）。本节点在路径上排第一时，只认来源节点自己的会话发来的；
/// 排在后面时，只认路径上前一个 relay 发来的：它必须是 netmap 里的 relay，并且包就是从它在本节点上的会话绑定的地方来的
/// （那个 UDP 地址，或者那条 TCP）。往后送也是送到下一个 relay 在本节点上的会话。所以两个 relay 之间互相都有会话才转发得过去，
/// 这就是骨干上的一条连接。路径比网络设的最大中转级数长的不转发。
///
/// 两个 relay 之间 UDP 不通时，两个会话在同一条 TCP 上（[`i3t_path::backbone`]）：对方拨进来的，由这里的 TCP 监听接住，
/// 上面属于路径层的帧交给 [`set_backbone_inbox`](Self::set_backbone_inbox) 给的入口；本节点的路径层拨出去的，
/// 对方在上面建会话、要转发的帧由路径层交进来（[`handle_leg_frame`](Self::handle_leg_frame)）。骨干上的一段走着 TCP 时，
/// 对方经 UDP 来的 AUTH 要那个入口同意才把它的会话搬到 UDP 上（[`BackboneInbox::admits_udp`]），不同意时不回答，只告诉路径层。
///
/// # 下线
///
/// 节点要停下之前调用 [`announce_shutdown`](Self::announce_shutdown)：所有会话立刻收到一行"即将下线"的通知，
/// 节点把路径和挂靠换到别处。被丢弃、或者在 netmap 里被停用时也会发同样的通知。
/// 丢弃这个值会停掉后台任务和所有的 TCP 中转。
#[derive(Debug)]
pub struct Relay {
    inner: Arc<Inner>,
    maintenance: JoinHandle<()>,
}

pub(crate) struct Inner {
    key: Arc<NodeKey>,
    pub(crate) port: Arc<UdpPort>,
    cookies: CookieJar,
    state: RwLock<State>,
    /// 带宽上限单独一把锁：转发时只读会话表，但要改令牌桶。
    bandwidth: Mutex<Option<Bandwidth>>,
    /// 给中转帧回错误帧的限速。
    refusals: Mutex<RefusalLimiter>,
    /// 给 PING 回错误帧的限速。和上面分开：节点收到中转帧引出的错误帧之后会立刻发一个 PING 来核实（见
    /// [`i3t_proto::session`] 的"ERROR 的回显"），对它的回答不能因为刚回过一个错误帧就被压下去。
    keepalive_refusals: Mutex<RefusalLimiter>,
    handshakes: Mutex<HandshakeLimiter>,
    counters: Counters,
    /// 谁在用这个 relay：按节点对数的转发量（[`crate::users`]）。
    users: Mutex<Users>,
    local: OnceLock<LocalDelivery>,
    /// TCP 中转腿靠它知道 relay 被停用了。
    enabled: watch::Sender<bool>,
    next_conn: AtomicU64,
    /// 已经宣布过即将下线。
    draining: AtomicBool,
    /// 上一次发出去的矩阵行的序号。
    row_seq: AtomicU64,
    /// 同一个 TCP 端口上别的协议（ice3proxy）：开头字节认出来是它的连接交给这里。没有设时 TCP 端口上只有中转。
    pub(crate) tcp_handoff: RwLock<Option<TcpHandoff>>,
    /// 别的 relay 拨进来的骨干 TCP 上归路径层的帧交给谁。没有设时这些帧丢掉，对方的会话照常。
    inbox: OnceLock<BackboneInbox>,
}

/// 接过一条 TCP 连接：开头字节已经用 `peek` 看过，没有读走。
pub type TcpHandoff = Arc<dyn Fn(tokio::net::TcpStream, SocketAddr) + Send + Sync>;

struct State {
    me: NodeId,
    enabled: bool,
    /// 允许建会话的节点和它们的公钥：netmap 里列出的节点，加上别的 relay。
    clients: HashMap<NodeId, PublicKey>,
    /// 网络里别的 relay。只有它们可以当骨干上的邻居。
    relays: HashSet<NodeId>,
    /// 一条路径最多经过几个 relay（netmap 里网络的设置，不超过协议的上限）。
    max_relay_hops: usize,
    sessions: Sessions,
    bandwidth_mbps: Option<u32>,
}

/// 一个帧是从哪里来的，回话往哪里送。
pub(crate) struct Source<'a> {
    /// UDP 的来源地址，或者那条 TCP 的对端地址。cookie 和"relay 看到的地址"都用它。
    pub(crate) addr: SocketAddr,
    pub(crate) via: Via<'a>,
}

pub(crate) enum Via<'a> {
    Udp,
    Tcp { conn: TcpConn, sender: &'a FrameSender },
}

impl Source<'_> {
    fn origin(&self) -> Origin {
        match self.via {
            Via::Udp => Origin::Udp(self.addr),
            Via::Tcp { conn, .. } => Origin::Tcp(conn),
        }
    }

    fn binding(&self) -> Binding {
        match self.via {
            Via::Udp => Binding::Udp(self.addr),
            Via::Tcp { conn, sender } => Binding::Tcp { conn, sender: sender.clone() },
        }
    }
}

enum NextHop {
    /// 目的就是本节点。
    Local,
    /// 送到这个会话上：目的节点的，或者路径上下一个 relay 的。
    Session(Binding),
}

/// 一段数据报不转发的原因，以及要不要告诉发来的一方（错误帧的内容和它回显的字节）。
struct Refusal {
    reason: DropReason,
    reply: Option<(Refused, Echo)>,
}

impl Refusal {
    const fn silent(reason: DropReason) -> Self {
        Self { reason, reply: None }
    }
}

impl Relay {
    /// 要在 tokio 运行时里调用：它会启动一个后台任务来跟随 netmap、清理过期会话、监听 TCP。
    #[must_use]
    pub fn new(key: Arc<NodeKey>, port: Arc<UdpPort>, netmap: watch::Receiver<Arc<Netmap>>) -> Self {
        let now = Instant::now();
        let state = State {
            me: netmap.borrow().me.id,
            enabled: false,
            clients: HashMap::new(),
            relays: HashSet::new(),
            max_relay_hops: MAX_RELAY_HOPS,
            sessions: Sessions::default(),
            bandwidth_mbps: None,
        };
        let inner = Arc::new(Inner {
            key,
            port,
            cookies: CookieJar::new(now),
            state: RwLock::new(state),
            bandwidth: Mutex::new(None),
            refusals: Mutex::new(RefusalLimiter::default()),
            keepalive_refusals: Mutex::new(RefusalLimiter::default()),
            handshakes: Mutex::new(HandshakeLimiter::new(now)),
            counters: Counters::default(),
            users: Mutex::new(Users::new(now)),
            local: OnceLock::new(),
            enabled: watch::Sender::new(false),
            next_conn: AtomicU64::new(1),
            draining: AtomicBool::new(false),
            row_seq: AtomicU64::new(0),
            tcp_handoff: RwLock::new(None),
            inbox: OnceLock::new(),
        });
        inner.apply(&netmap.borrow());
        let maintenance = tokio::spawn(maintain(Arc::clone(&inner), netmap));
        Self { inner, maintenance }
    }

    /// 同一个 TCP 端口上还接 ice3proxy（lane）：开头是 TLS 握手记录（`0x16`）的连接交给 `handoff`，
    /// 别的照常当作中转。`handoff` 不能阻塞。
    ///
    /// 没有设的时候（没有为任何对端打开 ice3proxy）连接一接受就按中转处理，和原来完全一样；设了之后每条连接先等它的第一个字节
    /// （最多 [`leg::CLASSIFY_TIMEOUT`]），这段时间里同一来源、以及全部来源还没认出来的连接数另有上限。
    /// 认出来是中转的连接之后照常受中转的全部限制。
    ///
    /// # Panics
    ///
    /// 锁中毒（之前持锁的地方 panic 过）。
    pub fn set_tcp_handoff(&self, handoff: Option<TcpHandoff>) {
        *self.inner.tcp_handoff.write().expect("relay tcp handoff lock poisoned") = handoff;
    }

    /// 本节点现在是不是 relay。
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        *self.inner.enabled.borrow()
    }

    /// 处理 UDP 上收到的、归 relay 管的数据：节点发来的中转会话帧、要转发的中转帧、地址查询。
    ///
    /// `data` 是一个接收缓冲区里连续的若干个数据报，每 `stride` 字节一个（最后一个可以短），都来自 `from`。
    /// 它们可以发往不同的节点，这里逐个决定去向；发往同一个节点的相邻数据报合成一次发送。
    pub fn handle_udp(&self, from: SocketAddr, ecn: Option<Ecn>, data: &[u8], stride: usize) {
        let source = Source { addr: from, via: Via::Udp };
        let stride = stride.max(1);
        let mut rest = data;
        while !rest.is_empty() {
            let first = &rest[..stride.min(rest.len())];
            let taken = if let Some(header_len) = datagram::forwarding_header_len(first) {
                let run = same_route_run(rest, stride, header_len, self.inner.port.max_gso_segments());
                self.inner.forward(&source, ecn, &rest[..run], stride);
                run
            } else {
                self.inner.handle_control(&source, first);
                first.len()
            };
            rest = &rest[taken..];
        }
    }

    /// `client` 现在在本 relay 上有没有会话。
    #[must_use]
    pub fn has_session(&self, client: NodeId) -> bool {
        self.inner.read().sessions.binding(client, Instant::now()).is_some()
    }

    /// `client` 现在的会话如果是它上一个会话断掉之后重新建的，返回重新建立以来过了多久。
    /// 没有会话，或者这是它头一次建立的会话，返回 `None`。
    #[must_use]
    pub fn session_reopened(&self, client: NodeId) -> Option<Duration> {
        let now = Instant::now();
        self.inner.read().sessions.reopened(client, now).map(|at| now.saturating_duration_since(at))
    }

    /// `client` 的会话是不是绑定在 UDP 地址 `from` 上。
    /// 收包的一方用它判断"发给本节点的中转帧"是不是真的来自它自称的那个节点。
    #[must_use]
    pub fn session_at(&self, client: NodeId, from: SocketAddr) -> bool {
        let state = self.inner.read();
        state.enabled && state.sessions.owned_by(client, Origin::Udp(from), Instant::now())
    }

    /// 本节点自己有包要发给挂在本 relay 上的 `client`。`contents` 是带着中转头的数据报，
    /// 可以是若干个等长的首尾相接，这时 `segment_size` 是每个的长度。返回有没有送出去。
    ///
    /// 这是本节点自己的流量，不算转发，也不受带宽上限限制。
    pub fn send_to_client(&self, client: NodeId, contents: &[u8], segment_size: Option<usize>, ecn: Option<Ecn>) -> bool {
        let Some(binding) = self.inner.read().sessions.binding(client, Instant::now()).cloned() else { return false };
        match binding {
            Binding::Udp(destination) => self.inner.port.send_or_drop(&Transmit { destination, contents, segment_size, ecn }),
            Binding::Tcp { sender, .. } => {
                let stride = segment_size.unwrap_or(contents.len()).max(1);
                // 队列满了也接着试后面的：中间可能正好腾出了位置。
                let mut all_sent = true;
                for datagram in contents.chunks(stride) {
                    all_sent &= sender.try_send(Bytes::copy_from_slice(datagram));
                }
                all_sent
            }
        }
    }

    /// 目的就是本节点的中转帧交给谁（路径层的入口）。只能设一次，再设没有效果。
    pub fn set_local_delivery(&self, deliver: impl Fn(NodeId, Bytes) + Send + Sync + 'static) {
        if self.inner.local.set(Box::new(deliver)).is_err() {
            tracing::warn!("relay 的本地投递入口已经设过了，忽略这一次");
        }
    }

    /// 谁在用它：上一个统计时段（10 秒）里替哪些节点对转发了多少，最多的十几对，其余的合成一个数。
    /// 本节点没有启用 relay 时是 `None`。
    ///
    /// # Panics
    ///
    /// 锁中毒（之前持锁的地方 panic 过）。
    #[must_use]
    pub fn users(&self) -> Option<RelayUse> {
        let enabled = self.inner.read().enabled;
        enabled.then(|| self.inner.users.lock().expect("relay users mutex poisoned").last(Instant::now()))
    }

    /// 现在的计数。
    #[must_use]
    pub fn counters(&self) -> RelayCounters {
        self.inner.counters.snapshot(self.inner.read().sessions.len())
    }

    /// `client` 在本 relay 上的会话绑定在哪里；没有会话是 `None`。两个 relay 之间互相都有会话、而且在同一种传输上，骨干上才转发得过去。
    #[must_use]
    pub fn session_leg(&self, client: NodeId) -> Option<SessionLeg> {
        Some(match self.inner.read().sessions.binding(client, Instant::now())? {
            Binding::Udp(_) => SessionLeg::Udp,
            Binding::Tcp { conn: TcpConn::Accepted(conn), .. } => SessionLeg::Accepted(*conn),
            Binding::Tcp { conn: TcpConn::Dialled(conn), .. } => SessionLeg::Dialled(*conn),
        })
    }

    /// `client` 在本 relay 上是不是有走 UDP 的会话。
    #[must_use]
    pub fn has_udp_session(&self, client: NodeId) -> bool {
        self.session_leg(client) == Some(SessionLeg::Udp)
    }

    /// 别的 relay 拨进来的骨干 TCP 上，归路径层的帧（会话的应答、错误帧、矩阵行）和"它在上面建好了会话"交给 `inbox`。
    /// 只能设一次，再设没有效果。
    pub fn set_backbone_inbox(&self, inbox: BackboneInbox) {
        if self.inner.inbox.set(inbox).is_err() {
            tracing::warn!("relay 的骨干入口已经设过了，忽略这一次");
        }
    }

    /// 本节点的路径层拨向另一个 relay 的第 `conn` 条 TCP 上，来了一帧归 relay 管的：那个 relay 反过来建会话的握手和保活，
    /// 或者要本节点往下转的包。这条 TCP 的对端是 `addr`，回话写进 `sender`。规矩和 UDP、和接进来的 TCP 上一样。
    pub fn handle_leg_frame(&self, conn: u64, addr: SocketAddr, sender: &FrameSender, frame: &[u8]) {
        let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
        let source = Source { addr, via: Via::Tcp { conn: TcpConn::Dialled(conn), sender } };
        self.inner.handle_tcp_frame(&source, frame);
    }

    /// 本节点的路径层拨出去的第 `conn` 条 TCP 没了：绑在上面的会话跟着关闭。
    pub fn leg_closed(&self, conn: u64) {
        self.inner.close_tcp(TcpConn::Dialled(conn));
    }

    /// 现在的状态和负载。本节点没有启用 relay 时返回 `None`。
    #[must_use]
    pub fn status(&self) -> Option<RelayStatus> {
        self.is_enabled().then(|| self.inner.status(Instant::now()))
    }

    /// 把本节点测到的骨干链路签成矩阵的一行，发给所有会话（挂靠的节点和别的 relay）。没有启用 relay 时什么都不做。
    pub fn publish_row(&self, links: &[Link]) {
        if self.is_enabled() {
            self.inner.publish_row(links);
        }
    }

    /// 把一帧原样发给所有会话。用来把别的 relay 的矩阵行传下去。没有启用 relay 时什么都不做。
    pub fn broadcast(&self, frame: &[u8]) {
        if self.is_enabled() {
            let bindings = self.inner.read().sessions.bindings(Instant::now());
            self.inner.send_to_all(&bindings, frame);
        }
    }

    /// 本节点即将下线（关机、升级）：立刻通知所有会话，让它们把路径和挂靠换到别处。之后照常转发，直到进程退出。
    ///
    /// 节点停下之前调用一次；多调用几次也只通知一次。
    pub fn announce_shutdown(&self) {
        self.inner.announce_shutdown("节点即将停止");
    }
}

impl i3t_path::LocalRelay for Relay {
    fn handle_udp(&self, from: SocketAddr, ecn: Option<Ecn>, data: &[u8], stride: usize) {
        Self::handle_udp(self, from, ecn, data, stride);
    }

    fn has_session(&self, client: NodeId) -> bool {
        Self::has_session(self, client)
    }

    fn session_reopened(&self, client: NodeId) -> Option<Duration> {
        Self::session_reopened(self, client)
    }

    fn session_at(&self, client: NodeId, from: SocketAddr) -> bool {
        Self::session_at(self, client, from)
    }

    fn send_to_client(&self, client: NodeId, contents: &[u8], segment_size: Option<usize>, ecn: Option<Ecn>) -> bool {
        Self::send_to_client(self, client, contents, segment_size, ecn)
    }

    fn session_leg(&self, client: NodeId) -> Option<SessionLeg> {
        Self::session_leg(self, client)
    }

    fn handle_leg_frame(&self, conn: u64, addr: SocketAddr, sender: &FrameSender, frame: &[u8]) {
        Self::handle_leg_frame(self, conn, addr, sender, frame);
    }

    fn leg_closed(&self, conn: u64) {
        Self::leg_closed(self, conn);
    }

    fn status(&self) -> Option<RelayStatus> {
        Self::status(self)
    }

    fn publish_row(&self, links: &[Link]) {
        Self::publish_row(self, links);
    }

    fn broadcast(&self, frame: &[u8]) {
        Self::broadcast(self, frame);
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // 没有人显式通知过的话，这里是最后的机会。发通知只是几次不等待的 UDP 发送。
        self.inner.announce_shutdown("relay 被丢弃");
        self.maintenance.abort();
        // 让还开着的 TCP 中转腿自己结束。
        self.inner.enabled.send_replace(false);
    }
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay").field("port", &self.port.local_addr()).finish_non_exhaustive()
    }
}

impl Inner {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state.read().expect("relay state lock poisoned")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, State> {
        self.state.write().expect("relay state lock poisoned")
    }

    pub(crate) fn subscribe_enabled(&self) -> watch::Receiver<bool> {
        self.enabled.subscribe()
    }

    pub(crate) fn next_conn(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// 按新的 netmap 更新：是否启用、允许哪些节点、别的 relay 是谁、最大中转级数、带宽上限。
    fn apply(&self, netmap: &Netmap) {
        let now = Instant::now();
        let role = netmap.me.relay.as_ref();
        if role.is_none() && self.read().enabled {
            // 被停用：趁会话还在，先告诉它们。
            self.announce_shutdown("本节点在 netmap 里不再是 relay");
        }
        let mut state = self.write();
        state.me = netmap.me.id;
        let others = netmap.relays.iter().filter(|relay| relay.id != netmap.me.id);
        state.relays = others.clone().map(|relay| relay.id).collect();
        // 别的 relay 要在本节点上建会话才有骨干，所以它们总是允许的，不管节点名单里有没有。
        state.clients =
            netmap.relay_clients.iter().map(|client| (client.id, client.key)).chain(others.map(|relay| (relay.id, relay.key))).collect();
        state.max_relay_hops = usize::from(netmap.network.max_relay_hops).clamp(1, MAX_RELAY_HOPS);
        if state.enabled != role.is_some() {
            state.enabled = role.is_some();
            if state.enabled {
                // 重新启用之后是一个正常服务的 relay。
                self.draining.store(false, Ordering::Relaxed);
                tracing::info!(clients = state.clients.len(), relays = state.relays.len(), "本节点启用为 relay");
            } else {
                tracing::info!(sessions = state.sessions.len(), "本节点不再是 relay，全部中转会话关闭");
                state.sessions.clear();
            }
        }
        let State { clients, sessions, .. } = &mut *state;
        for node in sessions.retain_clients(|node| clients.get(&node).copied()) {
            tracing::info!(%node, "节点不在允许的名单里了，或者换了公钥：它的中转会话关闭");
        }
        let bandwidth_mbps = role.and_then(|role| role.bandwidth_mbps);
        if state.bandwidth_mbps != bandwidth_mbps {
            state.bandwidth_mbps = bandwidth_mbps;
            *self.bandwidth.lock().expect("relay bandwidth mutex poisoned") = bandwidth_mbps.map(|mbps| Bandwidth::new(mbps, now));
        }
        let enabled = state.enabled;
        drop(state);
        self.enabled.send_if_modified(|current| std::mem::replace(current, enabled) != enabled);
    }

    /// 现在的状态和负载。没有设带宽上限的 relay 不知道自己的容量，负载报 0。
    fn status(&self, now: Instant) -> RelayStatus {
        let load = self.bandwidth.lock().expect("relay bandwidth mutex poisoned").as_mut().map(|bandwidth| bandwidth.load(now));
        let state = if self.draining.load(Ordering::Relaxed) {
            RelayState::Draining
        } else if load.is_some_and(|load| load.overloaded) {
            RelayState::Overloaded
        } else {
            RelayState::Serving
        };
        // 负载是 0 到几的一个比例，换成百分数之后封顶在一个字节能装下的范围里。浮点数到整数没有不会悄悄截断的现成转换，
        // 所以从大到小找第一个不超过它的整数；一共 256 个值，而且只在发通知和路径层问状态时才算。
        let percent = load.map_or(0.0, |load| (load.utilisation * 100.0).clamp(0.0, f64::from(u8::MAX)));
        let load_percent = (0..=u8::MAX).rev().find(|step| f64::from(*step) <= percent).unwrap_or(0);
        RelayStatus { state, load_percent, sessions_opened: self.counters.sessions_opened() }
    }

    /// 签一行发给所有会话。
    fn publish_row(&self, links: &[Link]) {
        let now = Instant::now();
        let (me, bindings) = {
            let state = self.read();
            (state.me, state.sessions.bindings(now))
        };
        if bindings.is_empty() {
            return;
        }
        let RelayStatus { state, load_percent, .. } = self.status(now);
        let row = Row { origin: me, seq: self.next_row_seq(), state, load_percent, links: links.to_vec() };
        let unsigned = row.to_unsigned_bytes();
        let signature = self.key.sign(Row::PURPOSE, &unsigned);
        self.send_to_all(&bindings, &row.to_bytes(signature.as_bytes()));
    }

    /// 序号用毫秒时间戳：进程重启之后也比以前发过的大。同一毫秒里发两行、或者系统时间往回跳的时候，至少比上一个大 1。
    fn next_row_seq(&self) -> u64 {
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX));
        let mut last = self.row_seq.load(Ordering::Relaxed);
        loop {
            let next = wall.max(last.saturating_add(1));
            match self.row_seq.compare_exchange_weak(last, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return next,
                Err(actual) => last = actual,
            }
        }
    }

    fn send_to_all(&self, bindings: &[Binding], frame: &[u8]) {
        for binding in bindings {
            match binding {
                Binding::Udp(addr) => self.port.send_datagram(frame, *addr),
                // 通知也走那条有上限的队列；满了就丢，下一轮还会再发。
                Binding::Tcp { sender, .. } => drop(sender.try_send(Bytes::copy_from_slice(frame))),
            }
        }
    }

    /// 宣布即将下线：发一行状态是"即将下线"、不带链路的。只在第一次调用时发。
    fn announce_shutdown(&self, why: &'static str) {
        if !self.read().enabled || self.draining.swap(true, Ordering::Relaxed) {
            return;
        }
        let sessions = self.read().sessions.len();
        tracing::info!(sessions, why, "relay 即将下线，通知所有会话换到别处");
        self.publish_row(&[]);
    }

    fn sweep(&self, now: Instant) {
        for node in self.write().sessions.sweep(now) {
            tracing::info!(%node, "中转会话过期：{} 秒没有收到保活", SESSION_TTL.as_secs());
        }
        self.refusals.lock().expect("relay refusal mutex poisoned").sweep(now);
        self.keepalive_refusals.lock().expect("relay refusal mutex poisoned").sweep(now);
        self.handshakes.lock().expect("relay handshake mutex poisoned").sweep(now);
    }

    /// 一条 TCP 断了，绑定在它上面的会话跟着关闭。
    pub(crate) fn close_tcp(&self, conn: TcpConn) {
        for node in self.write().sessions.close_tcp(conn) {
            tracing::info!(%node, "TCP 中转断开，中转会话关闭");
        }
    }

    pub(crate) fn tcp_session_alive(&self, node: NodeId, conn: TcpConn) -> bool {
        self.read().sessions.owned_by(node, Origin::Tcp(conn), Instant::now())
    }

    /// `node` 是 netmap 里别的 relay。
    pub(crate) fn is_relay(&self, node: NodeId) -> bool {
        self.read().relays.contains(&node)
    }

    pub(crate) fn inbox(&self) -> Option<&BackboneInbox> {
        self.inbox.get()
    }

    /// 别的 relay 拨进来的骨干 TCP（第 `conn` 条，`neighbour` 在上面有会话）上的一帧，属于本节点自己的那些：
    /// 本节点在对方那里的会话的应答和矩阵行交给路径层；对方送给本节点的包交给连接层（它替来源节点担保，
    /// 和 UDP 上 relay 的地址来的包一样）。返回这一帧是不是就此处理完了；别的（对方的握手和保活、要往下转的包）照常由 relay 处理。
    pub(crate) fn neighbour_frame(&self, neighbour: NodeId, conn: u64, frame: &Bytes) -> bool {
        let me = self.read().me;
        match Datagram::parse(frame) {
            Ok(Datagram::Session(session)) if !session.is_request() => {
                self.deliver_to_inbox(neighbour, conn, frame);
                true
            }
            Ok(Datagram::Row(_)) => {
                self.deliver_to_inbox(neighbour, conn, frame);
                true
            }
            Ok(Datagram::Relayed { header, .. }) if header.dst == me => {
                self.deliver_locally(header.src, frame, frame.len(), RelayHeader::LEN);
                true
            }
            Ok(Datagram::Routed { header, .. })
                if header.dst == me && header.relays.around(me).is_none() && header.relays.last() == neighbour =>
            {
                self.deliver_locally(header.src, frame, frame.len(), header.encoded_len());
                true
            }
            _ => false,
        }
    }

    /// 交给路径层的骨干收件箱。路径层还没接上收件箱时丢掉：这帧本来就是给它的，别人也用不上。
    fn deliver_to_inbox(&self, neighbour: NodeId, conn: u64, frame: &Bytes) {
        if let Some(inbox) = self.inbox.get() {
            inbox.frame(neighbour, conn, frame.clone());
        }
    }

    /// TCP 上读出来的一帧。握手成功时返回建了会话的节点。
    pub(crate) fn handle_tcp_frame(&self, source: &Source<'_>, frame: &[u8]) -> Option<NodeId> {
        if datagram::forwarding_header_len(frame).is_some() {
            self.forward(source, None, frame, frame.len());
            return None;
        }
        self.handle_control(source, frame)
    }

    /// 不是中转帧的一个数据报：会话帧或者地址查询。握手成功时返回建了会话的节点。
    fn handle_control(&self, source: &Source<'_>, datagram: &[u8]) -> Option<NodeId> {
        if !self.read().enabled {
            self.counters.dropped(DropReason::Disabled, 1);
            return None;
        }
        match Datagram::parse(datagram) {
            Ok(Datagram::Session(frame)) if frame.is_request() => self.handle_request(source, frame),
            Ok(Datagram::AddrQuery(query)) => {
                self.reply(source, &addr_query::answer(&query, source.addr));
                None
            }
            // 别的都不归 relay 管，或者解析不了：丢掉，不回应。
            Ok(
                Datagram::Session(_)
                | Datagram::Conn(_)
                | Datagram::Sealed(_)
                | Datagram::Relayed { .. }
                | Datagram::Routed { .. }
                | Datagram::Row(_)
                | Datagram::Probe(_)
                | Datagram::AddrReply(_),
            )
            | Err(_) => {
                self.counters.dropped(DropReason::Malformed, 1);
                None
            }
        }
    }

    fn handle_request(&self, source: &Source<'_>, frame: Frame) -> Option<NodeId> {
        let now = Instant::now();
        match frame {
            Frame::Init(init) => {
                if !self.read().clients.contains_key(&init.node) {
                    self.counters.dropped(DropReason::UnknownClient, 1);
                    tracing::debug!(node = %init.node, from = %source.addr, "握手被忽略：节点不在允许的名单里");
                    return None;
                }
                let cookie = self.cookies.issue(source.addr, init.node, now);
                self.reply(source, &Challenge { nonce: init.nonce, cookie }.to_bytes());
                None
            }
            Frame::Auth(auth) => self.authenticate(source, &auth, now),
            Frame::Ping(ping) => {
                if self.write().sessions.refresh(ping.node, source.origin(), now) {
                    self.reply(source, &Pong { nonce: ping.nonce, observed: source.addr }.to_bytes());
                } else {
                    self.counters.dropped(DropReason::NoSession, 1);
                    let refused = Refused { reason: RefusalReason::NoSession, node: ping.node };
                    self.refuse(source, &self.keepalive_refusals, (refused, ping.nonce), session::Ping::LEN, now);
                }
                None
            }
            Frame::Challenge(_) | Frame::Ok(_) | Frame::Pong(_) | Frame::Error(_) => {
                self.counters.dropped(DropReason::Malformed, 1);
                None
            }
        }
    }

    /// AUTH：先验 cookie（便宜，证明来源地址是真的），再按来源限速，再验签名（贵），都过了才建会话。
    ///
    /// 别的 relay 经 UDP 来的，还要路径层同意它把会话搬到 UDP 上（[`BackboneInbox::admits_udp`]）：骨干上到它的那一段走着 TCP、
    /// 本节点又不知道自己的 UDP 到不到得了它时不建会话、不回答，只告诉路径层它敲了门。
    fn authenticate(&self, source: &Source<'_>, auth: &Auth, now: Instant) -> Option<NodeId> {
        let key = self.check_auth(source, auth, now)?;
        self.open_session(source, auth, key, now)
    }

    /// 握手的前一半：这个 AUTH 该不该建会话。该的话返回它的签名是照哪把公钥验过的。
    ///
    /// 验签名的时候不拿着状态的锁（它是收包的路径上最贵的一步），所以这里看到的名单到建会话时可能已经换了：
    /// 后一半（[`open_session`](Self::open_session)）要照这把公钥再核对一次。
    fn check_auth(&self, source: &Source<'_>, auth: &Auth, now: Instant) -> Option<PublicKey> {
        let node = auth.node;
        let (me, client_key, neighbour) = {
            let state = self.read();
            (state.me, state.clients.get(&node).copied(), state.relays.contains(&node))
        };
        let Some(client_key) = client_key else {
            self.counters.dropped(DropReason::UnknownClient, 1);
            tracing::debug!(%node, from = %source.addr, "握手被忽略：节点不在允许的名单里");
            return None;
        };
        if !self.cookies.verify(&auth.cookie, source.addr, node, now) {
            self.counters.dropped(DropReason::BadCookie, 1);
            tracing::debug!(%node, from = %source.addr, "握手被忽略：cookie 不是发给这个地址的，或者已经过期");
            return None;
        }
        if !self.handshakes.lock().expect("relay handshake mutex poisoned").allow(source.addr.ip(), now) {
            self.counters.dropped(DropReason::TooManyHandshakes, 1);
            tracing::debug!(%node, from = %source.addr, "握手被忽略：这个来源这一阵发来的 AUTH 太多，不再为它验签名");
            return None;
        }
        let message = Auth::signed_message(me, node, &auth.nonce, &auth.cookie);
        if i3t_crypto::verify(&client_key, Auth::PURPOSE, &message, &Signature::from_bytes(auth.signature)).is_err() {
            self.counters.dropped(DropReason::BadSignature, 1);
            // 不用 warn：拿到 cookie 的人可以照着限速不停地发，每次一条 warn 就是刷屏。计数器里看得到。
            tracing::debug!(%node, from = %source.addr, "握手被忽略：签名不对");
            return None;
        }
        if neighbour
            && matches!(source.via, Via::Udp)
            && let Some(inbox) = self.inbox.get()
            && !inbox.admits_udp(node, now)
        {
            // 不算进丢弃的计数：对方没有做错什么。本节点的路径层被敲了门，马上自己经 UDP 试一次，通的话对方的下一个 AUTH 就能过。
            tracing::debug!(
                %node,
                from = %source.addr,
                "握手先搁下：骨干上到这个 relay 的一段走着 TCP，本节点还不知道自己的 UDP 到不到得了它，不把它的会话搬到 UDP 上；请路径层自己经 UDP 试一次"
            );
            inbox.knocked(node);
            return None;
        }
        Some(client_key)
    }

    /// 握手的后一半：给签名照 `key` 验过的 AUTH（[`check_auth`](Self::check_auth)）建会话、回 OK。
    ///
    /// 验签名的那段时间里 netmap 可能变了，所以拿着写锁再看一次：relay 还启用着，这个节点在名单里的公钥还是 `key`。
    /// 节点被去掉了，或者换了公钥（那签名就是照一把已经不作数的公钥验的），都不建会话。
    fn open_session(&self, source: &Source<'_>, auth: &Auth, key: PublicKey, now: Instant) -> Option<NodeId> {
        let node = auth.node;
        let me = {
            let mut state = self.write();
            if !state.enabled || state.clients.get(&node) != Some(&key) {
                return None;
            }
            state.sessions.open(node, key, source.binding(), auth.nonce, now);
            state.me
        };
        self.counters.session_opened();
        let valid_for = u16::try_from(SESSION_TTL.as_secs()).unwrap_or(u16::MAX);
        let message = Accepted::signed_message(me, node, &auth.nonce, valid_for, source.addr);
        let signature = *self.key.sign(Accepted::PURPOSE, &message).as_bytes();
        self.reply(source, &Accepted { nonce: auth.nonce, valid_for, observed: source.addr, signature }.to_bytes());
        let via = match source.via {
            Via::Udp => "UDP",
            Via::Tcp { .. } => "TCP",
        };
        tracing::info!(%node, from = %source.addr, via, "中转会话建立");
        Some(node)
    }

    /// 转发一段中转头完全相同（同一个来源节点、同一个目的节点、同一条路径）的数据报。数据报原样转出去，一个字节都不改。
    fn forward(&self, source: &Source<'_>, ecn: Option<Ecn>, run: &[u8], stride: usize) {
        let packets = run.len().div_ceil(stride);
        let first = &run[..stride.min(run.len())];
        if stride > MAX_RELAYED_LEN {
            self.counters.dropped(DropReason::Malformed, packets);
            return;
        }
        let now = Instant::now();
        let (hop, src, dst, header_len) = match Datagram::parse(first) {
            Ok(Datagram::Relayed { header, packet }) => {
                (self.next_hop(source, header, &session::payload_echo(packet), now), header.src, header.dst, RelayHeader::LEN)
            }
            Ok(Datagram::Routed { header, packet }) => {
                let hop = self.next_hop_on_route(source, &header, &session::payload_echo(packet), now);
                (hop, header.src, header.dst, header.encoded_len())
            }
            _ => {
                self.counters.dropped(DropReason::Malformed, packets);
                return;
            }
        };
        match hop {
            Ok(NextHop::Local) => self.deliver_locally(src, run, stride, header_len),
            Ok(NextHop::Session(binding)) => {
                if self.admit(src, run.len(), now) {
                    let sent = self.send(&binding, ecn, run, stride);
                    if sent > 0 {
                        self.users.lock().expect("relay users mutex poisoned").forwarded(src, dst, sent, now);
                    }
                } else {
                    self.counters.dropped(DropReason::RateLimited, packets);
                }
            }
            Err(Refusal { reason, reply }) => {
                self.counters.dropped(reason, packets);
                if let Some(reply) = reply {
                    self.refuse(source, &self.refusals, reply, first.len(), now);
                }
            }
        }
    }

    /// 核对：来源节点有会话，并且数据报就是从会话绑定的地方来的；目的节点也有会话。
    ///
    /// `payload` 是这个数据报去掉中转头之后的前几个字节，来源没有会话时错误帧回显它；有会话时回显会话握手的随机数。
    fn next_hop(&self, source: &Source<'_>, header: RelayHeader, payload: &Echo, now: Instant) -> Result<NextHop, Refusal> {
        let state = self.read();
        if !state.enabled {
            return Err(Refusal::silent(DropReason::Disabled));
        }
        let Some(nonce) = state.sessions.owned_nonce(header.src, source.origin(), now) else {
            let reply = Refused { reason: RefusalReason::NoSession, node: header.src };
            return Err(Refusal { reason: DropReason::NoSession, reply: Some((reply, *payload)) });
        };
        if header.dst == state.me {
            return Ok(NextHop::Local);
        }
        let unattached = Refusal {
            reason: DropReason::PeerUnattached,
            reply: Some((Refused { reason: RefusalReason::PeerUnattached, node: header.dst }, nonce)),
        };
        state.sessions.binding(header.dst, now).cloned().map(NextHop::Session).ok_or(unattached)
    }

    /// 多级中转的包往哪里送。先核对它是从该来的地方来的，再看路径本身，最后找下一站。
    ///
    /// 只有排第一的 relay 会回错误帧：那时发来的一方就是来源节点，而且它的会话已经核对过（错误帧回显那个会话握手的随机数）。
    /// 排在后面的 relay 不知道来源节点在哪里，不照办就只是丢掉。
    fn next_hop_on_route(&self, source: &Source<'_>, header: &RouteHeader, payload: &Echo, now: Instant) -> Result<NextHop, Refusal> {
        let state = self.read();
        if !state.enabled {
            return Err(Refusal::silent(DropReason::Disabled));
        }
        let Some(around) = header.relays.around(state.me) else { return Err(Refusal::silent(DropReason::NotOnRoute)) };
        // 排第一时是来源节点的会话握手的随机数；排在后面时是 `None`，不回错误帧。
        let session_nonce: Option<Nonce> = match around.previous {
            None => match state.sessions.owned_nonce(header.src, source.origin(), now) {
                Some(nonce) => Some(nonce),
                None => {
                    let reply = Refused { reason: RefusalReason::NoSession, node: header.src };
                    return Err(Refusal { reason: DropReason::NoSession, reply: Some((reply, *payload)) });
                }
            },
            // 前一个 relay 的会话必须就绑定在帧来的地方：那个 UDP 地址，或者那条 TCP（两个 relay 之间 UDP 不通时骨干走 TCP）。
            Some(previous) => {
                let from_neighbour = state.relays.contains(&previous) && state.sessions.owned_by(previous, source.origin(), now);
                if !from_neighbour {
                    return Err(Refusal::silent(DropReason::NoBackbone));
                }
                None
            }
        };
        let refusal = |reason: DropReason, refused: RefusalReason, node: NodeId| Refusal {
            reason,
            reply: session_nonce.map(|nonce| (Refused { reason: refused, node }, nonce)),
        };
        let relays = header.relays.as_slice();
        if relays.len() > state.max_relay_hops {
            return Err(refusal(DropReason::HopLimit, RefusalReason::RouteUnavailable, state.me));
        }
        // 目的节点只能出现在路径的末尾（它自己就是最后一个 relay）；写在中间的话，包到了它那里还要往外转，没有意义。
        if relays[..relays.len() - 1].contains(&header.dst) {
            return Err(Refusal::silent(DropReason::NotOnRoute));
        }
        match around.next {
            None if header.dst == state.me => Ok(NextHop::Local),
            None => state
                .sessions
                .binding(header.dst, now)
                .cloned()
                .map(NextHop::Session)
                .ok_or_else(|| refusal(DropReason::PeerUnattached, RefusalReason::PeerUnattached, header.dst)),
            Some(next) => match state.sessions.binding(next, now) {
                Some(binding) if state.relays.contains(&next) => Ok(NextHop::Session(binding.clone())),
                Some(_) | None => Err(refusal(DropReason::NoBackbone, RefusalReason::RouteUnavailable, next)),
            },
        }
    }

    fn admit(&self, src: NodeId, bytes: usize, now: Instant) -> bool {
        self.bandwidth.lock().expect("relay bandwidth mutex poisoned").as_mut().is_none_or(|bandwidth| bandwidth.admit(src, bytes, now))
    }

    /// 把一串数据报送到会话上，返回送出去了多少字节。
    fn send(&self, binding: &Binding, ecn: Option<Ecn>, run: &[u8], stride: usize) -> usize {
        match binding {
            Binding::Udp(destination) => {
                let packets = run.len().div_ceil(stride);
                let segment_size = (run.len() > stride).then_some(stride);
                if self.port.send_or_drop(&Transmit { destination: *destination, contents: run, segment_size, ecn }) {
                    self.counters.forwarded(packets, run.len());
                    run.len()
                } else {
                    self.counters.dropped(DropReason::SendBufferFull, packets);
                    0
                }
            }
            Binding::Tcp { sender, .. } => {
                let mut sent = 0;
                for datagram in run.chunks(stride) {
                    if sender.try_send(Bytes::copy_from_slice(datagram)) {
                        self.counters.forwarded(1, datagram.len());
                        sent += datagram.len();
                    } else {
                        self.counters.dropped(DropReason::QueueFull, 1);
                    }
                }
                sent
            }
        }
    }

    fn deliver_locally(&self, src: NodeId, run: &[u8], stride: usize, header_len: usize) {
        let Some(deliver) = self.local.get() else {
            self.counters.dropped(DropReason::PeerUnattached, run.len().div_ceil(stride));
            return;
        };
        let packets = run.chunks(stride).filter_map(|datagram| datagram.get(header_len..));
        for packet in packets {
            deliver(src, Bytes::copy_from_slice(packet));
        }
    }

    fn reply(&self, source: &Source<'_>, frame: &[u8]) {
        match source.via {
            Via::Udp => self.port.send_datagram(frame, source.addr),
            // 握手和保活的应答也走那条有上限的队列；满了就丢，节点会重试。
            Via::Tcp { sender, .. } => drop(sender.try_send(Bytes::copy_from_slice(frame))),
        }
    }

    /// 回一个回显 `echo` 的错误帧，按来源地址用 `limiter` 限速。引出它的请求有 `request_len` 字节：比错误帧短就不回，
    /// 应答不能比请求大。
    fn refuse(
        &self,
        source: &Source<'_>,
        limiter: &Mutex<RefusalLimiter>,
        (refused, echo): (Refused, Echo),
        request_len: usize,
        now: Instant,
    ) {
        if request_len < Refused::LEN || !limiter.lock().expect("relay refusal mutex poisoned").allow(source.addr, now) {
            return;
        }
        tracing::debug!(from = %source.addr, node = %refused.node, reason = ?refused.reason, "拒绝转发，回一个错误帧");
        self.reply(source, &refused.to_bytes_echoing(&echo));
    }
}

/// 从 `data` 开头起，连续多少字节的数据报带着同一个中转头（最多 `max_segments` 个数据报）。`header_len` 是第一个数据报的头的长度。
///
/// 内核一次交上来的一批数据报可能发往不同的节点（实测时见到过），所以要逐个看。
/// 中转头相同的一段可以用一次带分段卸载的发送转出去，不用逐个调内核。
fn same_route_run(data: &[u8], stride: usize, header_len: usize, max_segments: usize) -> usize {
    let header = data.get(..header_len);
    let segments = data
        .chunks(stride)
        .take(max_segments.max(1))
        .take_while(|datagram| header.is_some() && datagram.get(..header_len) == header)
        .count()
        .max(1);
    (segments * stride).min(data.len())
}

/// 后台任务：跟随 netmap，清理过期会话，relay 启用期间监听 TCP。
async fn maintain(inner: Arc<Inner>, mut netmap: watch::Receiver<Arc<Netmap>>) {
    let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut listener: Option<JoinHandle<()>> = None;
    // 上一次监听是不是失败了。只在失败和恢复的那一刻各记一条日志，重试期间不刷屏。
    let mut listen_failed = false;
    let mut netmap_open = true;
    loop {
        tokio::select! {
            changed = netmap.changed(), if netmap_open => match changed {
                Ok(()) => inner.apply(&netmap.borrow_and_update()),
                // 发 netmap 的一方没了（节点在退出）：按最后一份继续。
                Err(_) => netmap_open = false,
            },
            _ = sweep.tick() => inner.sweep(Instant::now()),
        }
        // 监听任务自己会在 relay 停用时结束。
        if !*inner.enabled.borrow() {
            listener = None;
            listen_failed = false;
        } else if listener.as_ref().is_none_or(JoinHandle::is_finished) {
            // 绑不上（端口被别的程序占着）时，下一轮（一秒之后）再试。
            match leg::listen(&inner) {
                Ok(task) => {
                    listener = Some(task);
                    listen_failed = false;
                }
                Err(error) if !listen_failed => {
                    listen_failed = true;
                    let addr = inner.port.local_addr();
                    tracing::warn!(%addr, %error, "relay 监听不了 TCP，UDP 用不了的节点暂时连不上来；会一直重试");
                }
                Err(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(dst: u32, src: u32, payload_len: usize) -> Vec<u8> {
        let header = RelayHeader { dst: NodeId::new(dst).unwrap(), src: NodeId::new(src).unwrap() };
        let mut datagram = header.to_bytes().to_vec();
        datagram.resize(RelayHeader::LEN + payload_len, 0xab);
        datagram
    }

    #[test]
    fn a_run_stops_where_the_destination_or_the_source_changes() {
        let stride = frame(2, 1, 100).len();
        let data = [frame(2, 1, 100), frame(2, 1, 100), frame(3, 1, 100), frame(3, 4, 100), frame(2, 1, 40)].concat();
        const LEN: usize = RelayHeader::LEN;
        assert_eq!(same_route_run(&data, stride, LEN, 64), 2 * stride);
        assert_eq!(same_route_run(&data[2 * stride..], stride, LEN, 64), stride, "目的变了");
        assert_eq!(same_route_run(&data[3 * stride..], stride, LEN, 64), stride, "来源变了");
        assert_eq!(same_route_run(&data[4 * stride..], stride, LEN, 64), data.len() - 4 * stride, "最后一个可以短");
    }

    #[test]
    fn a_run_is_capped_by_the_segment_limit() {
        let stride = frame(2, 1, 100).len();
        let data = [frame(2, 1, 100), frame(2, 1, 100), frame(2, 1, 100)].concat();
        assert_eq!(same_route_run(&data, stride, RelayHeader::LEN, 1), stride);
        assert_eq!(same_route_run(&data, stride, RelayHeader::LEN, 2), 2 * stride);
        assert_eq!(same_route_run(&data, stride, RelayHeader::LEN, 0), stride, "限制是 0 也至少往前走一个");
    }

    #[test]
    fn a_truncated_header_still_advances_by_one_datagram() {
        assert_eq!(same_route_run(&[1, 0, 0], 1400, RelayHeader::LEN, 64), 3);
        let data = [frame(2, 1, 0), vec![1, 0, 0]].concat();
        assert_eq!(same_route_run(&data, RelayHeader::LEN, RelayHeader::LEN, 64), RelayHeader::LEN);
    }

    #[test]
    fn a_run_of_routed_frames_stops_where_the_path_changes() {
        let routed = |relays: &[u32]| {
            let relays: Vec<NodeId> = relays.iter().map(|&relay| NodeId::new(relay).unwrap()).collect();
            let header = RouteHeader {
                dst: NodeId::new(2).unwrap(),
                src: NodeId::new(1).unwrap(),
                relays: datagram::RelayPath::new(&relays).unwrap(),
            };
            let mut datagram = header.to_bytes();
            datagram.resize(header.encoded_len() + 100, 0xab);
            datagram
        };
        let data = [routed(&[8, 9]), routed(&[8, 9]), routed(&[9, 8])].concat();
        let stride = routed(&[8, 9]).len();
        let header_len = datagram::forwarding_header_len(&data).unwrap();
        assert_eq!(header_len, 18);
        assert_eq!(same_route_run(&data, stride, header_len, 64), 2 * stride, "同样的两个 relay 换了顺序就是另一条路径");
    }

    /// 本节点是 relay（编号 100）的 netmap，允许 `clients` 里的节点。
    fn netmap(clients: &[(NodeId, PublicKey)]) -> Netmap {
        let clients: Vec<_> = clients.iter().map(|(id, key)| serde_json::json!({ "id": id, "key": key })).collect();
        let netmap = serde_json::json!({
            "version": 1,
            "network": { "name": "test", "domain": "test.i3t", "cidr": "10.66.0.0/16", "max_relay_hops": 2 },
            "me": { "id": 100, "name": "relay", "virtual_ip": "10.66.0.100", "relay": {} },
            "relays": [],
            "relay_clients": clients,
        });
        serde_json::from_value(netmap).unwrap()
    }

    #[tokio::test]
    async fn an_auth_checked_against_a_key_the_netmap_has_since_replaced_opens_no_session() {
        let node = NodeId::new(1).unwrap();
        let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        let port = Arc::new(UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let (_netmap, updates) = watch::channel(Arc::new(netmap(&[(node, old.public())])));
        let relay = Relay::new(Arc::new(NodeKey::generate().unwrap()), port, updates);
        let me = relay.inner.read().me;

        // 一个样样都对的 AUTH：cookie 是发给这个地址的，签名是 netmap 里现在这把公钥的主人签的。
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = Source { addr: client.local_addr().unwrap(), via: Via::Udp };
        let (now, nonce) = (Instant::now(), [7; 8]);
        let cookie = relay.inner.cookies.issue(source.addr, node, now);
        let signature = *old.sign(Auth::PURPOSE, &Auth::signed_message(me, node, &nonce, &cookie)).as_bytes();
        let auth = Auth { node, nonce, cookie, signature };

        // 握手的前一半验过了签名，后一半还没有开始：这期间 netmap 里这个节点换了公钥。
        assert_eq!(relay.inner.check_auth(&source, &auth, now), Some(old.public()));
        relay.inner.apply(&netmap(&[(node, new.public())]));
        assert_eq!(relay.inner.open_session(&source, &auth, old.public(), now), None, "签名是照已经换掉的公钥验的，不该建会话");
        assert!(!relay.has_session(node));
        assert_eq!(relay.counters().sessions_opened, 0);

        // 名单里还是那把公钥的话，同样的后一半是建得了会话的。
        relay.inner.apply(&netmap(&[(node, old.public())]));
        assert_eq!(relay.inner.open_session(&source, &auth, old.public(), now), Some(node));
        assert!(relay.has_session(node));
    }
}
