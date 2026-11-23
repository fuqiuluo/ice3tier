//! 监听的管理：按 netmap 开关代理和端口转发的监听，加上本机配置文件里的组网入口。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use i3t_conn::Connector;
use i3t_conn::contract::Datagrams;
use i3t_flow::datagram::Opener;
use i3t_model::Netmap;
use i3t_model::netmap::{ForwardProtocol, ListenerProtocol};
use ipnet::IpNet;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::Instrument;

use crate::admission::{HandshakeLimits, Handshakes, Pass, RefusalLog};
use crate::entry::{Entry, LocalEntry};
use crate::forward_health::{ForwardHealth, TargetFailure};
use crate::routes::{NoRoutes, SharedRoutes};
use crate::session::{self, Shared};
use crate::udp;
use crate::usage::{ExitSnapshot, Tally, Usage};

/// 绑定失败的监听隔多久重试一次。端口被别的程序占着时不去抢，等它让出来。
const RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// `accept` 出错之后歇多久再试。文件描述符用完这类错误不歇一下会空转。
pub(crate) const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// UDP 端口转发的会话没有报文往来多久之后回收。
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 端口写 0 的端口转发挑定的端口记在哪里（挑定之后固定下来，重启不变）。
///
/// 装配层把它存在节点的状态目录里。记着的端口下次启动时被别的程序占了，这条转发处于"端口被占用"的状态，
/// 不会换一个端口：换了的话，用它的人手里的端口号就悄悄失效了。
pub trait PortBook: Send + Sync + 'static {
    /// 这条转发上次挑定的端口。
    fn port(&self, forward: u32) -> Option<u16>;
    /// 这条转发挑定了 `port`。
    fn remember(&self, forward: u32, port: u16);
}

/// 不记：每次都让系统重新挑。静态模式和测试用。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPortBook;

impl PortBook for NoPortBook {
    fn port(&self, _forward: u32) -> Option<u16> {
        None
    }

    fn remember(&self, _forward: u32, _port: u16) {}
}

/// 一个节点的入口：代理、本机的组网入口和端口转发。
///
/// 代理和端口转发的监听由 netmap 决定（`me.proxies` 和 `me.forwards`），组网入口在构造时给定（[`Access::with_local_entries`]）。
/// netmap 变了，只动变了的那几个监听；已经建立的连接各自跑在自己的任务里，监听被关掉也不受影响。
/// 一个组网入口和某个代理绑同一个地址时让给代理。
///
/// UDP 也从这里进来：SOCKS5 上的 UDP ASSOCIATE，以及协议是 UDP 的端口转发。它们到对端节点走数据报上下文，
/// 所以 `C` 除了能开流，还要能收发数据报。
///
/// 节点排空时（[`Access::set_draining`]）监听照常开着，新的请求得到明确的拒绝：代理回 SOCKS5 的 0x01、
/// HTTP 的 503；端口转发没有地方回错误，TCP 的连接被重置，UDP 不建新的会话。已经建立的连接照常跑完。
pub struct Access<C: Datagrams> {
    pub(crate) shared: Arc<Shared<C>>,
    published: Mutex<AccessStatus>,
}

impl<C: Connector + Datagrams> Access<C> {
    /// `connector` 用来到对端节点开流和数据报上下文。这里还不开始监听，要调用 [`run`](Self::run)。
    ///
    /// `connector` 收的是 `Arc`：连接层的同一个端点通常既是开流的一方、又是接受流的一方，要和出口那一侧共用。
    pub fn new(connector: Arc<C>, netmap: watch::Receiver<Arc<Netmap>>) -> Self {
        let opener = Arc::new(Opener::new(Arc::clone(&connector)));
        let shared = Shared {
            connector,
            opener,
            netmap,
            local: Vec::new(),
            usage: Usage::default(),
            ports: Arc::new(NoPortBook),
            draining: Mutex::new(None),
            drained: AtomicU64::new(0),
            udp_idle_timeout: UDP_IDLE_TIMEOUT,
            forward_health: ForwardHealth::default(),
            routes: Arc::new(NoRoutes),
            handshakes: Handshakes::new(HandshakeLimits::default()),
        };
        Self { shared: Arc::new(shared), published: Mutex::default() }
    }

    /// UDP 端口转发的会话没有报文往来多久之后回收。默认 60 秒；测试里调短，不用真的等一分钟。
    ///
    /// # Panics
    ///
    /// 在 [`run`](Self::run) 已经开始之后调用。
    #[must_use]
    pub fn with_udp_idle_timeout(mut self, timeout: Duration) -> Self {
        self.shared_mut("with_udp_idle_timeout").udp_idle_timeout = timeout;
        self
    }

    /// 同时最多有多少条代理连接还没完成握手。默认的（[`HandshakeLimits::default`]）够个人用；测试里调小，不用真的开上千条连接。
    ///
    /// # Panics
    ///
    /// 在 [`run`](Self::run) 已经开始之后调用。
    #[must_use]
    pub fn with_handshake_limits(mut self, limits: HandshakeLimits) -> Self {
        self.shared_mut("with_handshake_limits").handshakes = Handshakes::new(limits);
        self
    }

    /// 本机配置文件里的组网入口：不认证、只通到组网里的节点（[`LocalEntry`]）。不设时没有。
    ///
    /// # Panics
    ///
    /// 在 [`run`](Self::run) 已经开始之后调用。
    #[must_use]
    pub fn with_local_entries(mut self, entries: Vec<LocalEntry>) -> Self {
        self.shared_mut("with_local_entries").local = entries;
        self
    }

    /// 端口写 0 的端口转发挑定的端口记在哪里。不设时每次启动都重新挑。
    ///
    /// # Panics
    ///
    /// 在 [`run`](Self::run) 已经开始之后调用。
    #[must_use]
    pub fn with_port_book(mut self, ports: Arc<dyn PortBook>) -> Self {
        self.shared_mut("with_port_book").ports = ports;
        self
    }

    /// 到各个对端现在走哪条路从哪里问：每条流结束时的摘要里写它。不设时摘要里的路是"不知道"。
    ///
    /// # Panics
    ///
    /// 在 [`run`](Self::run) 已经开始之后调用。
    #[must_use]
    pub fn with_routes(mut self, routes: SharedRoutes) -> Self {
        self.shared_mut("with_routes").routes = routes;
        self
    }

    /// 本节点开数据报上下文用的那一个。一个节点只该有一个（对端发回来的数据报由它分发，见 [`run`](Self::run)），
    /// 出口那一侧接力 UDP 端口转发时要用同一个。
    #[must_use]
    pub fn datagram_opener(&self) -> Arc<Opener<C>> {
        Arc::clone(&self.shared.opener)
    }

    fn shared_mut(&mut self, what: &str) -> &mut Shared<C> {
        Arc::get_mut(&mut self.shared).unwrap_or_else(|| panic!("{what}() 要在 run() 之前调用：那时还没有监听拿着这些设置"))
    }

    /// 按 netmap 维护监听，直到 netmap 的发送端被丢弃（节点在关闭）。
    ///
    /// 只应该有一个在跑。这个 future 结束或者被丢弃时，所有监听都关掉；已经建立的连接继续跑到自己结束。
    /// 对端节点在数据报上下文里发回来的数据报也是在这里面分发的。
    pub async fn run(&self) {
        let mut netmap = self.shared.netmap.clone();
        let mut bound: Vec<Bound> = Vec::new();
        let datagrams = self.shared.opener.run();
        tokio::pin!(datagrams);
        let mut pumping = true;
        loop {
            let current = Arc::clone(&netmap.borrow_and_update());
            self.reconcile(&current, &mut bound).await;
            let any_failed = bound
                .iter()
                .any(|bound| bound.awaiting_address || matches!(bound.state, ListenState::Failed { .. } | ListenState::PortInUse { .. }));
            // 等到下一次要调整监听的时候；这期间一直在分发数据报。
            loop {
                tokio::select! {
                    changed = netmap.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        break;
                    }
                    () = time::sleep(RETRY_INTERVAL), if any_failed => break,
                    // 连接层关掉了：数据报不会再来，监听照常维护到节点关闭。
                    () = &mut datagrams, if pumping => pumping = false,
                }
            }
        }
    }

    /// 每个代理、组网入口和端口转发现在的状态。
    #[must_use]
    pub fn status(&self) -> AccessStatus {
        let mut status = self.published.lock().expect("access status mutex poisoned").clone();
        for forward in &mut status.forwards {
            forward.target_failure = self.shared.forward_health.last_failure(forward.id);
        }
        status
    }

    /// 端口转发的目标最近连不上的记录。出口模块接住监听在虚拟 IP 上的转发时记到同一份里。
    #[must_use]
    pub fn forward_health(&self) -> ForwardHealth {
        self.shared.forward_health.clone()
    }

    /// 入口现在真的在监听的地址：代理、组网入口和端口转发里绑上了的那些。
    #[must_use]
    pub fn own_listeners(&self) -> Vec<OwnListener> {
        let status = self.published.lock().expect("access status mutex poisoned");
        let listening = |state: &ListenState, protocol, forward| match state {
            ListenState::Listening { local } => Some(OwnListener { protocol, local: *local, forward }),
            ListenState::PortInUse { .. } | ListenState::Failed { .. } | ListenState::Virtual | ListenState::Unsupported { .. } => None,
        };
        let proxies = status.proxies.iter().filter_map(|proxy| listening(&proxy.state, ForwardProtocol::Tcp, None));
        let local = status.local.iter().filter_map(|entry| listening(&entry.state, ForwardProtocol::Tcp, None));
        let forwards = status.forwards.iter().filter_map(|forward| listening(&forward.state, forward.protocol, Some(forward.id)));
        proxies.chain(local).chain(forwards).collect()
    }

    /// 开始或者结束排空。`Some(说明)` 时新的连接得到拒绝（见类型的文档），说明写进日志。
    pub fn set_draining(&self, draining: Option<String>) {
        *self.shared.draining.lock().expect("draining mutex poisoned") = draining;
    }

    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.shared.draining.lock().expect("draining mutex poisoned").is_some()
    }

    /// 启动以来因为排空而拒绝的连接（和 UDP 会话）。
    #[must_use]
    pub fn drained(&self) -> u64 {
        self.shared.drained.load(Ordering::Relaxed)
    }

    /// 这次运行以来经各个出口出去的流，本节点作为发起方看到的。
    #[must_use]
    pub fn exit_usage(&self) -> Vec<ExitSnapshot> {
        self.shared.usage.exits()
    }

    /// 让 `bound` 和 `netmap` 要求的监听一致：关掉不再需要的，绑定新增的，重试上次没绑上的。
    async fn reconcile(&self, netmap: &Netmap, bound: &mut Vec<Bound>) {
        let wanted = wanted(netmap, &self.shared.local);

        // 先关后开：代理换了编号但地址没变时，新的要等旧的让出端口才绑得上。
        let mut kept = Vec::with_capacity(wanted.len());
        for existing in bound.drain(..) {
            if wanted.iter().any(|(key, _)| *key == existing.key) {
                kept.push(existing);
            } else {
                tracing::info!(listen = %existing.key, "netmap 里不再有这个监听，关掉它（已经建立的连接不受影响）");
                existing.close().await;
            }
        }

        for (key, plan) in wanted {
            match kept.iter_mut().find(|existing| existing.key == key) {
                Some(existing) => {
                    if let Some(previous) = existing.state.failure().map(str::to_owned) {
                        (existing.state, existing.task) = self.listen(&key, &existing.counters, Some(&previous)).await;
                    } else if existing.awaiting_address {
                        (existing.state, existing.task, existing.awaiting_address) = self.listen_virtual(&key, &existing.counters).await;
                    }
                }
                None => {
                    let counters = Counters::default();
                    let mut awaiting_address = false;
                    let (state, task) = match plan {
                        Plan::Bind => self.listen(&key, &counters, None).await,
                        Plan::Virtual { listener: true } => {
                            let (state, task, awaiting) = self.listen_virtual(&key, &counters).await;
                            awaiting_address = awaiting;
                            (state, task)
                        }
                        Plan::Virtual { listener: false } => {
                            tracing::info!(listen = %key, "这条 UDP 端口转发监听在本节点的虚拟 IP 上、目标是本节点自己：只经流来访问，不占用操作系统的端口");
                            (ListenState::Virtual, None)
                        }
                        Plan::Unsupported { reason, cause } => {
                            tracing::warn!(listen = %key, reason, "这条端口转发不能用");
                            (ListenState::Unsupported { reason: reason.to_owned(), cause }, None)
                        }
                    };
                    kept.push(Bound { key, state, counters, task, awaiting_address });
                }
            }
        }
        *bound = kept;

        let mut status = AccessStatus { version: netmap.version, proxies: Vec::new(), local: Vec::new(), forwards: Vec::new() };
        for entry in bound.iter() {
            let (state, active, traffic) =
                (entry.state.clone(), Active(Arc::clone(&entry.counters.active)), Traffic(Arc::clone(&entry.counters.traffic)));
            match &entry.key {
                Key::Proxy { id, bind } => {
                    status.proxies.push(ProxyStatus { id: *id, bind: *bind, state, active, traffic });
                }
                Key::Local { name, bind, protocol } => {
                    status.local.push(ListenerStatus { name: name.clone(), bind: *bind, protocol: *protocol, state, active, traffic });
                }
                Key::Forward { id, bind, protocol } => {
                    let forward = ForwardStatus { id: *id, bind: *bind, protocol: *protocol, state, active, traffic, target_failure: None };
                    status.forwards.push(forward);
                }
            }
        }
        self.shared.forward_health.retain(|id| netmap.me.forwards.iter().any(|forward| forward.id == id));
        *self.published.lock().expect("access status mutex poisoned") = status;
    }

    /// 绑定 `key` 的地址并开始接受连接。绑不上时不是错误，而是一个要报告的状态。
    ///
    /// `previous_failure` 是上一次失败的原因：重试时原因没变就不再记日志。
    /// 监听在本节点虚拟 IP 上的端口转发：别的节点经虚拟网卡来连，所以在虚拟 IP 上真的监听。经流来的
    /// （本机的 SOCKS5 入口、没有网卡的节点）照旧由出口模块接住。
    ///
    /// Linux 上用 `IP_FREEBIND`：地址还不在网卡上（网卡还没装好、或者装不了）也绑得上，网卡装好的那一刻就收得到连接。
    /// 别的平台没有它：地址不在本机时（第三项是真）状态是 [`ListenState::Virtual`]，之后隔一阵再试，网卡装好之后就绑上了。
    async fn listen_virtual(&self, key: &Key, counters: &Counters) -> (ListenState, Option<JoinHandle<()>>, bool) {
        match self.listen(key, counters, None).await {
            (ListenState::Failed { cause: ListenCause::AddressNotAvailable, .. }, None) => {
                tracing::info!(listen = %key, "这条端口转发监听在本节点的虚拟 IP 上，虚拟网卡还没有装上：先只经流来访问，网卡装上之后再监听");
                (ListenState::Virtual, None, true)
            }
            (state, task) => (state, task, false),
        }
    }

    async fn listen(&self, key: &Key, counters: &Counters, previous_failure: Option<&str>) -> (ListenState, Option<JoinHandle<()>>) {
        let configured = key.bind();
        // 端口写 0 的端口转发：用上次挑定的端口；还没挑过就让系统挑一个，记下来。
        let (bind, chosen_now) = match key {
            Key::Forward { id, .. } if configured.port() == 0 => match self.shared.ports.port(*id) {
                Some(port) => (SocketAddr::new(configured.ip(), port), false),
                None => (configured, true),
            },
            Key::Forward { .. } | Key::Proxy { .. } | Key::Local { .. } => (configured, false),
        };
        // 本节点的虚拟 IP 在虚拟网卡上，网卡可能还没装好。
        let free = bind.ip() == self.shared.netmap.borrow().me.virtual_ip;
        let started = match key {
            Key::Forward { id, protocol: ForwardProtocol::Udp, .. } => udp_socket(bind, free).map(|socket| {
                let local = socket.local_addr().unwrap_or(bind);
                let span = tracing::info_span!("access", listen = %key);
                let sessions = udp::forward::serve(Arc::clone(&self.shared), *id, configured, socket, counters.clone());
                (local, tokio::spawn(sessions.instrument(span)))
            }),
            Key::Forward { protocol: ForwardProtocol::Tcp, .. } | Key::Proxy { .. } | Key::Local { .. } => {
                tcp_listener(bind, free).map(|listener| {
                    let local = listener.local_addr().unwrap_or(bind);
                    (local, tokio::spawn(accept_loop(Arc::clone(&self.shared), key.clone(), listener, counters.clone())))
                })
            }
        };
        match started {
            Ok((local, task)) => {
                if let (true, Key::Forward { id, .. }) = (chosen_now, key) {
                    tracing::info!(listen = %key, port = local.port(), "端口转发的端口写的是 0，挑定了这个端口，之后重启也用它");
                    self.shared.ports.remember(*id, local.port());
                }
                tracing::info!(listen = %key, %local, "开始监听");
                (ListenState::Listening { local }, Some(task))
            }
            Err(error) => {
                let reason = error.to_string();
                if previous_failure != Some(reason.as_str()) {
                    tracing::warn!(listen = %key, %bind, %reason, "绑定失败，这个监听处于失败状态，之后会重试");
                }
                let state = match ListenCause::from(error.kind()) {
                    ListenCause::AddressInUse => ListenState::PortInUse { reason },
                    cause => ListenState::Failed { reason, cause },
                };
                (state, None)
            }
        }
    }
}

/// 全部监听的状态，对应某一版 netmap。
#[derive(Debug, Clone, Default)]
pub struct AccessStatus {
    /// 这些状态是按哪一版 netmap 算的。
    pub version: u64,
    pub proxies: Vec<ProxyStatus>,
    /// 本机配置文件里的组网入口。
    pub local: Vec<ListenerStatus>,
    pub forwards: Vec<ForwardStatus>,
}

/// 一个代理的状态。
#[derive(Debug, Clone)]
pub struct ProxyStatus {
    /// netmap 里的编号（[`i3t_model::netmap::Proxy::id`]）。
    pub id: u32,
    /// 配置里写的绑定地址。
    pub bind: SocketAddr,
    pub state: ListenState,
    pub active: Active,
    pub traffic: Traffic,
}

/// 一个组网入口的状态。
#[derive(Debug, Clone)]
pub struct ListenerStatus {
    pub name: String,
    /// 配置里写的绑定地址。
    pub bind: SocketAddr,
    pub protocol: ListenerProtocol,
    pub state: ListenState,
    pub active: Active,
    pub traffic: Traffic,
}

/// 一条端口转发（监听一侧）的状态。
#[derive(Debug, Clone)]
pub struct ForwardStatus {
    pub id: u32,
    /// 配置里写的监听地址。端口写 0 时实际的端口在 [`ListenState::Listening`] 里。
    pub bind: SocketAddr,
    pub protocol: ForwardProtocol,
    pub state: ListenState,
    pub active: Active,
    pub traffic: Traffic,
    /// 最近一次这条转发的流在目标那里失败；之后成功过就是 `None`（[`crate::ForwardHealth`]）。
    pub target_failure: Option<TargetFailure>,
}

/// 本节点的程序自己在监听的一个地址：入口的代理、组网入口、端口转发（[`Access::own_listeners`]），
/// 装配层还可以把程序里别处的监听也算进来（虚拟网卡的名字服务）。
///
/// 出口模块凭它认出"本节点的端口"里哪些其实是程序自己的监听。别的节点要访问本节点的一个端口时，出口用本机的地址去连本机的服务，
/// 那条连接的来源是本机自己的地址；连到程序自己的监听上，监听按来源做的检查（来源白名单、只收本机和对端的虚拟 IP）
/// 看到的就是本机，而不是真正来访问的那个节点。所以这些地址出口不去连。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnListener {
    /// TCP 的监听还是 UDP 的端口。
    pub protocol: ForwardProtocol,
    /// 实际绑定的地址：配置里端口写 0 的，这里是挑定的端口。
    pub local: SocketAddr,
    /// 是端口转发的监听时，它的编号。
    pub forward: Option<u32>,
}

impl OwnListener {
    /// 发往 `addr` 的连接（`protocol` 是 UDP 时是报文）是不是落在这个监听上。
    ///
    /// 监听在全部地址上的，哪个地址上的这个端口都算它的：`[::]` 在有的系统上不收 IPv4 的，这里也按收算，
    /// 宁可少连一个地址，不把来源洗成本机。
    #[must_use]
    pub fn receives(&self, protocol: ForwardProtocol, addr: SocketAddr) -> bool {
        let covers = match self.local.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => addr.ip().to_canonical().is_ipv4(),
            IpAddr::V6(ip) if ip.is_unspecified() => true,
            ip => ip.to_canonical() == addr.ip().to_canonical(),
        };
        self.protocol == protocol && self.local.port() == addr.port() && covers
    }
}

/// 一个监听现在的状态。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenState {
    /// 正在监听。`local` 是实际绑定的地址：配置里端口写 0 时，这里是挑定的端口。
    Listening { local: SocketAddr },
    /// 端口已经被别的程序占用（原因的种类就是 [`ListenCause::AddressInUse`]）。不去抢，每隔一段时间和每次 netmap 变化时重试。
    PortInUse { reason: String },
    /// 别的原因没有绑上，`reason` 是系统给的原话，`cause` 是它的种类。同样会重试。
    Failed { reason: String, cause: ListenCause },
    /// 监听在本节点的虚拟 IP 上的端口转发，现在没有真的监听（虚拟网卡没装上，或者是目标在本节点的 UDP 转发）：
    /// 别的节点经流来访问时由出口模块接住。虚拟网卡装着时它是 [`ListenState::Listening`]。
    Virtual,
    /// 这种配置节点不支持，`reason` 说明为什么，`cause` 是哪一种。不重试，配置改了才重新判断。
    Unsupported { reason: String, cause: ListenCause },
}

impl ListenState {
    /// 绑定失败（会重试）时的原因。
    fn failure(&self) -> Option<&str> {
        match self {
            Self::PortInUse { reason } | Self::Failed { reason, .. } => Some(reason),
            Self::Listening { .. } | Self::Virtual | Self::Unsupported { .. } => None,
        }
    }
}

/// 一个监听没有开起来的原因是哪一种，和 [`ListenState`] 里给人看的那句话放在一起：上层按它归类，不用去读那句话。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenCause {
    /// 端口被别的程序占着。
    AddressInUse,
    /// 没有权限（比如普通用户绑 1024 以下的端口）。
    PermissionDenied,
    /// 地址不在这台机器上。
    AddressNotAvailable,
    /// 别的系统错误，见那句话。
    Other,
    /// 不是系统的错误：监听在本节点虚拟 IP 上的端口转发没有写端口号。
    VirtualPortZero,
}

/// 绑定失败时系统错误的种类。
impl From<io::ErrorKind> for ListenCause {
    fn from(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::AddrInUse => Self::AddressInUse,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::AddrNotAvailable => Self::AddressNotAvailable,
            _ => Self::Other,
        }
    }
}

/// 一个监听上现在有多少条连接（UDP 的端口转发是多少个会话）。读到的是调用那一刻的值，不是状态生成时的。
#[derive(Debug, Clone)]
pub struct Active(pub(crate) Arc<AtomicUsize>);

impl Active {
    #[must_use]
    pub fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// 一个监听上这次运行以来的流量。读到的是调用那一刻的值。
#[derive(Debug, Clone)]
pub struct Traffic(pub(crate) Arc<Tally>);

impl Traffic {
    /// 客户端发进来的字节数。
    #[must_use]
    pub fn up(&self) -> u64 {
        self.0.up()
    }

    /// 发回给客户端的字节数。
    #[must_use]
    pub fn down(&self) -> u64 {
        self.0.down()
    }
}

/// 一个监听上的计数：连接数和流量。监听重新绑定时沿用，所以流量是这次运行以来的。
#[derive(Debug, Clone, Default)]
pub(crate) struct Counters {
    pub(crate) active: Arc<AtomicUsize>,
    pub(crate) traffic: Arc<Tally>,
}

/// 一个监听是谁。地址变了（端口转发是协议变了也算）就是另一个监听，要重新绑定；别的设置变了还是同一个，
/// 新的连接按新的设置处理，所以代理改协议、出口、用户名密码都不用重新绑定。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    Proxy { id: u32, bind: SocketAddr },
    Local { name: String, bind: SocketAddr, protocol: ListenerProtocol },
    Forward { id: u32, bind: SocketAddr, protocol: ForwardProtocol },
}

impl Key {
    const fn bind(&self) -> SocketAddr {
        match self {
            Self::Proxy { bind, .. } | Self::Local { bind, .. } | Self::Forward { bind, .. } => *bind,
        }
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proxy { id, bind } => write!(f, "代理 {id}（{bind}）"),
            Self::Local { name, bind, protocol } => write!(f, "组网入口 {name}（{protocol}，{bind}）"),
            Self::Forward { id, bind, protocol } => write!(f, "端口转发 {id}（{protocol:?}，{bind}）"),
        }
    }
}

/// netmap 要求的一个监听怎么落实。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    Bind,
    /// 监听在本节点的虚拟 IP 上。`listener` 是假的时候不在操作系统里监听：目标是本节点自己的 UDP 转发，
    /// 本节点到不了自己的数据报上下文，只经流来访问（出口模块接住）。
    Virtual {
        listener: bool,
    },
    Unsupported {
        reason: &'static str,
        cause: ListenCause,
    },
}

fn wanted(netmap: &Netmap, local: &[LocalEntry]) -> Vec<(Key, Plan)> {
    let proxies = netmap.me.proxies.iter().map(|proxy| (Key::Proxy { id: proxy.id, bind: proxy.bind }, Plan::Bind));
    // controller 也可以给同一个地址配一个代理，那时以 controller 的为准。
    let local = local
        .iter()
        .filter(|entry| !netmap.me.proxies.iter().any(|proxy| proxy.bind == entry.bind))
        .map(|entry| (Key::Local { name: entry.name.clone(), bind: entry.bind, protocol: entry.protocol }, Plan::Bind));
    let forwards = netmap.me.forwards.iter().map(|forward| {
        let plan = if forward.bind.ip() != netmap.me.virtual_ip {
            Plan::Bind
        } else if forward.bind.port() == 0 {
            Plan::Unsupported { reason: "监听在虚拟 IP 上的端口转发要写明端口号", cause: ListenCause::VirtualPortZero }
        } else {
            Plan::Virtual { listener: !(forward.protocol == ForwardProtocol::Udp && forward.target == netmap.me.id) }
        };
        (Key::Forward { id: forward.id, bind: forward.bind, protocol: forward.protocol }, plan)
    });
    let mut wanted: Vec<(Key, Plan)> = Vec::new();
    // 配置里重复的条目只留第一个：同一个地址本来也只能绑一次。
    for entry in proxies.chain(local).chain(forwards) {
        if !wanted.iter().any(|(key, _)| *key == entry.0) {
            wanted.push(entry);
        }
    }
    wanted
}

/// 一个已经落实（或者落实失败）的监听。
struct Bound {
    key: Key,
    state: ListenState,
    counters: Counters,
    /// 接受连接的任务，监听的 socket 在它手里。
    task: Option<JoinHandle<()>>,
    /// 监听在虚拟 IP 上、这个地址还不在本机（虚拟网卡没装上，没有 `IP_FREEBIND` 的平台上）：隔一阵再试。
    awaiting_address: bool,
}

impl Bound {
    /// 关掉监听，等到 socket 真的关上再返回，这样紧接着绑同一个地址不会撞上自己。
    async fn close(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            // 任务是被取消的，它的结果只会是"已取消"。
            let _ = task.await;
        }
    }
}

impl Drop for Bound {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// TCP 的监听。`free` 时（地址是本节点的虚拟 IP）地址还不在网卡上也绑得上（[`free_bind`]）。
fn tcp_listener(bind: SocketAddr, free: bool) -> io::Result<TcpListener> {
    if !free {
        return i3t_underlay::tcp_mss::listen(bind);
    }
    let socket = if bind.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    free_bind(&socket2::SockRef::from(&socket))?;
    i3t_underlay::tcp_mss::clamp(&socket);
    socket.bind(bind)?;
    socket.listen(1024)
}

/// UDP 的监听，`free` 同上。
fn udp_socket(bind: SocketAddr, free: bool) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(bind), socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if free {
        free_bind(&socket2::SockRef::from(&socket))?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    UdpSocket::from_std(socket.into())
}

/// Linux 上的 `IP_FREEBIND`：绑一个现在还不在本机网卡上的地址。别的平台上什么都不做，地址不在时绑定失败、之后再试。
#[cfg(target_os = "linux")]
fn free_bind(socket: &socket2::SockRef<'_>) -> io::Result<()> {
    socket.set_freebind_v4(true)
}

#[cfg(not(target_os = "linux"))]
fn free_bind(_socket: &socket2::SockRef<'_>) -> io::Result<()> {
    Ok(())
}

async fn accept_loop<C: Connector + Datagrams>(shared: Arc<Shared<C>>, key: Key, listener: TcpListener, counters: Counters) {
    // 来源不在白名单里的拒绝日志：有人一直往这个监听上连的时候不刷屏。
    let mut refusals = RefusalLog::default();
    loop {
        match i3t_underlay::tcp_mss::accept(&listener).await {
            Ok((stream, from)) => {
                // 先查来源，再领握手的名额、开任务：被拒绝的来源什么都不占。拒绝一律发 RST，内核也不用替这条连接收尾。
                let netmap = Arc::clone(&shared.netmap.borrow());
                if let Err(refusal) = key.admits(&netmap, &shared.local, from) {
                    session::reset(stream);
                    match refusal {
                        // 防火墙开关关着时，局域网里一次端口扫描就是一串这样的连接：只记在 debug 里。
                        Refusal::VirtualIp => tracing::debug!(
                            listen = %key,
                            %from,
                            "拒绝了一条连接：监听在本节点的虚拟 IP 上，来源既不是本机，也不是可以访问本节点的节点（多半是从别的网卡进来的）"
                        ),
                        Refusal::AllowList => {
                            if let Some(more) = refusals.due(time::Instant::now()) {
                                tracing::info!(listen = %key, %from, more, "拒绝了一条连接：来源不在白名单里");
                            }
                        }
                        Refusal::Gone => {}
                    }
                    continue;
                }
                // 代理和组网入口的连接要领握手的名额，领不到的在这里就关掉，不开任务。端口转发没有握手，不领。
                let pass = match key {
                    Key::Proxy { .. } | Key::Local { .. } => match shared.handshakes.admit(from) {
                        Ok(pass) => Some(pass),
                        Err(full) => {
                            session::reset(stream);
                            shared.handshakes.refused(&key, from, full);
                            continue;
                        }
                    },
                    Key::Forward { .. } => None,
                };
                let connection = Connection::enter(&counters);
                let span = tracing::info_span!("access", listen = %key, %from);
                tokio::spawn(serve(Arc::clone(&shared), key.clone(), netmap, stream, from, connection, pass).instrument(span));
            }
            Err(error) => {
                tracing::warn!(listen = %key, %error, "接受连接出错");
                time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
}

/// 一条连接占着的计数，连接的任务结束时减回去。它也带着这个监听的流量计数，搬运时往里记。
pub(crate) struct Connection {
    active: Arc<AtomicUsize>,
    pub(crate) traffic: Arc<Tally>,
}

impl Connection {
    pub(crate) fn enter(counters: &Counters) -> Self {
        counters.active.fetch_add(1, Ordering::Relaxed);
        Self { active: Arc::clone(&counters.active), traffic: Arc::clone(&counters.traffic) }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 处理一条刚接受、来源已经查过的连接。
///
/// 每条连接按接受它那一刻的 netmap（`netmap`，查来源用的也是这一份）里的设置处理，所以改设置不需要重新绑定。
/// `pass` 是代理和组网入口的连接领到的握手名额。
async fn serve<C: Connector + Datagrams>(
    shared: Arc<Shared<C>>,
    key: Key,
    netmap: Arc<Netmap>,
    stream: TcpStream,
    from: SocketAddr,
    connection: Connection,
    pass: Option<Pass>,
) {
    if let Err(error) = stream.set_nodelay(true) {
        tracing::debug!(%error, "设置不了 TCP_NODELAY");
    }
    // 流没有空闲时限，客户端悄悄消失（断电、换了网络）时靠内核保活发现，这条连接经过的流和出口上的连接才会释放。
    if let Err(error) = i3t_flow::keep_alive(&stream) {
        tracing::debug!(%error, "客户端连接打不开内核保活，客户端悄悄消失时这条连接要等到有数据要发才会发现");
    }
    // 下面都找得到：接受连接时在同一份 netmap 里找过（[`Key::admits`]）。
    match key {
        Key::Proxy { id, bind } => {
            let Some(proxy) = netmap.me.proxies.iter().find(|proxy| proxy.id == id && proxy.bind == bind) else { return };
            session::proxy(&shared, &netmap, Entry::proxy(proxy), stream, from, &connection, pass).await;
        }
        Key::Local { name, .. } => {
            let Some(local) = shared.local.iter().find(|entry| entry.name == name) else { return };
            let entry = Entry::local(local);
            session::proxy(&shared, &netmap, entry, stream, from, &connection, pass).await;
        }
        Key::Forward { id, bind, .. } => {
            let Some(forward) = netmap.me.forwards.iter().find(|forward| forward.id == id && forward.bind == bind) else { return };
            session::forward(&shared, &netmap, forward, stream, from, &connection).await;
        }
    }
}

/// 一条刚接受的连接为什么不能进来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// 监听在本节点的虚拟 IP 上，来源既不是本机，也不是可以访问本节点的节点（[`virtual_ip_admits`]）。
    VirtualIp,
    /// 来源不在这个代理或者这条端口转发的白名单里（[`allowed`]）。
    AllowList,
    /// 这个代理、组网入口或者端口转发刚从设置里删掉，监听马上就会关。
    Gone,
}

impl Key {
    /// 来自 `from` 的连接能不能进这个监听：它还在 `netmap`（组网入口是 `local`）里，来源过得了虚拟 IP 的限制和白名单。
    fn admits(&self, netmap: &Netmap, local: &[LocalEntry], from: SocketAddr) -> Result<(), Refusal> {
        if !virtual_ip_admits(netmap, self.bind(), from) {
            return Err(Refusal::VirtualIp);
        }
        let allow_from = match self {
            Self::Proxy { id, bind } => {
                netmap.me.proxies.iter().find(|proxy| proxy.id == *id && proxy.bind == *bind).map(|proxy| proxy.allow_from.as_slice())
            }
            Self::Forward { id, bind, .. } => netmap
                .me
                .forwards
                .iter()
                .find(|forward| forward.id == *id && forward.bind == *bind)
                .map(|forward| forward.allow_from.as_slice()),
            // 组网入口没有白名单：它只在回环地址上。
            Self::Local { name, .. } => local.iter().any(|entry| entry.name == *name).then_some(&[][..]),
        };
        match allow_from {
            None => Err(Refusal::Gone),
            Some(allow_from) if !allowed(allow_from, from) => Err(Refusal::AllowList),
            Some(_) => Ok(()),
        }
    }
}

/// 监听在本节点虚拟 IP 上的（端口转发、代理、组网入口）只收经虚拟网卡来的和本机自己的：来源是可以访问本节点的节点的虚拟 IP、
/// 本节点的虚拟 IP 或者回环。监听在别的地址上的不管。和来源白名单（[`allowed`]）都要过。
///
/// 经虚拟网卡进来的包，来源核对过是那个节点的虚拟 IP，访问规则不允许它访问本节点时它开不了会话。可 Linux 按"弱主机模型"收包：
/// 发往虚拟 IP 的包从别的网卡进来也收，同一个局域网里的机器（或者上游的路由器）把虚拟 IP 指到这台机器，就能用它自己的真实地址
/// 连上这里，访问规则管不到它。虚拟网卡的防火墙规则挡在前面；这里再挡一道：防火墙的开关关着、规则装不上、别的系统打开了转发时
/// 也挡得住。Docker 桥接网络里的容器连宿主机的虚拟 IP 也因此不行（它们和局域网里的机器分不开）。
pub(crate) fn virtual_ip_admits(netmap: &Netmap, bind: SocketAddr, from: SocketAddr) -> bool {
    let own = netmap.me.virtual_ip;
    if bind.ip().to_canonical() != IpAddr::V4(own) {
        return true;
    }
    match from.ip().to_canonical() {
        IpAddr::V4(ip) => ip.is_loopback() || ip == own || netmap.peer_by_ip(ip).is_some_and(|peer| peer.inbound),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

/// 来源白名单。空的表示不限制。
pub(crate) fn allowed(allow_from: &[IpNet], from: SocketAddr) -> bool {
    let ip = from.ip().to_canonical();
    allow_from.is_empty() || allow_from.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bind_failure_carries_the_kind_of_the_system_error() {
        // 真的去绑绑不上的地址：错误的种类是这个平台给的。
        let elsewhere = std::net::TcpListener::bind("192.0.2.1:0").unwrap_err();
        assert_eq!(ListenCause::from(elsewhere.kind()), ListenCause::AddressNotAvailable, "{elsewhere}");
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let again = std::net::TcpListener::bind(taken.local_addr().unwrap()).unwrap_err();
        assert_eq!(ListenCause::from(again.kind()), ListenCause::AddressInUse, "{again}");
        assert_eq!(ListenCause::from(io::ErrorKind::PermissionDenied), ListenCause::PermissionDenied);
        assert_eq!(ListenCause::from(io::ErrorKind::InvalidInput), ListenCause::Other);
    }

    #[test]
    fn a_listener_takes_what_is_sent_to_its_own_address_and_port_or_to_any_address_when_bound_to_all() {
        let at = |text: &str| text.parse::<SocketAddr>().unwrap();
        let listener = |local: &str| OwnListener { protocol: ForwardProtocol::Tcp, local: at(local), forward: None };
        let tcp = |listener: OwnListener, addr: &str| listener.receives(ForwardProtocol::Tcp, at(addr));

        let on_lan = listener("192.168.1.5:8080");
        assert!(tcp(on_lan, "192.168.1.5:8080") && tcp(on_lan, "[::ffff:192.168.1.5]:8080"));
        assert!(!tcp(on_lan, "10.66.0.1:8080") && !tcp(on_lan, "192.168.1.5:8081") && !tcp(on_lan, "[2001:db8::5]:8080"));
        assert!(!on_lan.receives(ForwardProtocol::Udp, at("192.168.1.5:8080")), "UDP 的同一个端口是另一回事");

        let all_v4 = listener("0.0.0.0:8080");
        assert!(tcp(all_v4, "192.168.1.5:8080") && tcp(all_v4, "10.66.0.1:8080"));
        assert!(!tcp(all_v4, "[2001:db8::5]:8080") && !tcp(all_v4, "192.168.1.5:8081"));

        let all = listener("[::]:8080");
        assert!(tcp(all, "[2001:db8::5]:8080") && tcp(all, "192.168.1.5:8080"));
        assert!(!tcp(all, "192.168.1.5:8081"));
    }

    #[test]
    fn on_our_virtual_ip_only_nodes_that_may_reach_us_and_this_machine_get_in() {
        let mut netmap = crate::route::tests::netmap();
        netmap.peers[1].inbound = false;
        let at = |text: &str| text.parse::<SocketAddr>().unwrap();
        let ours = at("10.66.0.1:8080");
        assert!(virtual_ip_admits(&netmap, ours, at("10.66.0.2:40000")), "可以访问本节点的节点");
        assert!(!virtual_ip_admits(&netmap, ours, at("10.66.0.3:40000")), "不能访问本节点的节点");
        assert!(!virtual_ip_admits(&netmap, ours, at("10.66.0.9:40000")), "地址段里不是节点的地址");
        assert!(virtual_ip_admits(&netmap, ours, at("10.66.0.1:40000")), "本机的程序连虚拟 IP");
        assert!(virtual_ip_admits(&netmap, ours, at("127.0.0.1:40000")));
        assert!(virtual_ip_admits(&netmap, ours, at("[::ffff:10.66.0.2]:40000")), "双栈 socket 上的 IPv4 来源按 IPv4 比对");
        assert!(!virtual_ip_admits(&netmap, ours, at("192.168.1.99:40000")), "局域网里的机器用它自己的地址连进来");
        assert!(!virtual_ip_admits(&netmap, ours, at("172.17.0.2:40000")), "Docker 桥接网络里的容器");
        assert!(!virtual_ip_admits(&netmap, ours, at("[2001:db8::1]:40000")));
        for elsewhere in ["0.0.0.0:8080", "127.0.0.1:8080", "192.168.1.5:8080", "10.66.0.7:8080"] {
            assert!(virtual_ip_admits(&netmap, at(elsewhere), at("192.168.1.99:40000")), "监听在 {elsewhere} 上的不管");
        }
    }

    #[test]
    fn an_empty_allow_list_admits_everyone_and_a_filled_one_only_its_networks() {
        let from = |text: &str| text.parse::<SocketAddr>().unwrap();
        assert!(allowed(&[], from("203.0.113.9:1")));

        let list: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap(), "127.0.0.1/32".parse().unwrap(), "fd00::/8".parse().unwrap()];
        assert!(allowed(&list, from("192.168.1.77:1")));
        assert!(allowed(&list, from("127.0.0.1:1")));
        assert!(allowed(&list, from("[fd00::7]:1")));
        assert!(allowed(&list, from("[::ffff:192.168.1.77]:1")), "双栈 socket 上的 IPv4 客户端按 IPv4 比对");
        assert!(!allowed(&list, from("192.168.2.1:1")));
        assert!(!allowed(&list, from("127.0.0.2:1")));
        assert!(!allowed(&list, from("[2001:db8::1]:1")));
    }
}
