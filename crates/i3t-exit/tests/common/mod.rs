//! 端到端测试的搭建：几个节点跑在一张内存里的网上，每个节点都有完整的入口和出口。
//!
//! ```text
//! 测试扮演的客户端 ──TCP──▶ 入口（Access）──内存里的连接──▶ 出口（Exit）──TCP──▶ 测试扮演的目标
//! ```
//!
//! 出口和操作系统之间换成了 [`FakeSystem`]：网卡、域名解析由测试给出，"公网地址"被引到本机的测试服务上。
//! 出站策略的检查在它之上，照常进行。
//!
//! 用 `i3t_lane::on_both_transports!` 写的测试各跑两遍：一遍所有的流都在内存里的连接上，一遍承载 TCP 连接的流
//! 走回环上真的 lane（ice3proxy），数据报和别的流仍然在内存里的连接上。两遍的期望完全一样。

// 每个测试文件各用到这里的一部分，没用到的在那个文件里会被报成死代码。
#![allow(dead_code)]
// clippy.toml 里的 allow-unwrap-in-tests 只管 #[test] 函数，管不到这些辅助函数。这里 unwrap 失败就是测试失败。
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use i3t_access::{Access, AccessStatus, ListenState};
use i3t_exit::{Exit, Os, Outbound, ResolveError, System};
use i3t_flow::memory::{MemoryAcceptor, MemoryConnector, MemoryMesh};
use i3t_lane::testing::LaneMesh;
use i3t_lane::{LaneAcceptor, LaneConnector, Lanes};
use i3t_model::Netmap;
use i3t_model::netmap::{ExitRole, LaneMode, ListenerProtocol, LocalNode, Network, Peer, PeerExit, Proxy, Verifier};
use i3t_proto::{NodeId, PublicKey};
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

/// 入口所在的节点。
pub const LAPTOP: u32 = 1;
/// 出口节点。
pub const GW: u32 = 2;
/// 一个不是出口的节点，上面有服务。
pub const NAS: u32 = 3;

/// 测试里等一件事发生最多等多久。
pub const PATIENCE: Duration = Duration::from_secs(5);

/// 一个"公网地址"：它过得了出站策略，测试把它引到本机的测试服务上。
pub const PUBLIC_IP: &str = "93.184.216.34";

pub fn node(raw: u32) -> NodeId {
    NodeId::new(raw).unwrap()
}

/// 节点的虚拟 IP：`10.66.0.<编号>`。
pub fn virtual_ip(raw: u32) -> Ipv4Addr {
    Ipv4Addr::new(10, 66, 0, u8::try_from(raw).unwrap())
}

pub fn name_of(raw: u32) -> &'static str {
    match raw {
        LAPTOP => "laptop",
        GW => "gw",
        NAS => "nas",
        other => panic!("测试里没有 {other} 号节点"),
    }
}

/// 一个互相都能访问的对端。
pub fn peer(raw: u32, exit: Option<PeerExit>) -> Peer {
    Peer {
        id: node(raw),
        key: PublicKey::from_bytes([u8::try_from(raw).unwrap(); 32]),
        name: name_of(raw).into(),
        virtual_ip: virtual_ip(raw),
        inbound: true,
        outbound: true,
        endpoints: Vec::new(),
        attached: Vec::new(),
        exit,
        dial_out_only: false,
        keep_alive: false,
        lane: LaneMode::Off,
        congestion: None,
        no_udp: false,
    }
}

/// `me` 号节点的 netmap：另外两个节点都是它的对端，互相都能访问。gw 是出口（局域网开关关着），默认只放行 80 和 443。
pub fn netmap(me: u32) -> Netmap {
    let exit_of = |raw: u32| (raw == GW).then_some(PeerExit { lan: false, class: None, optimistic: None });
    Netmap {
        version: 1,
        network: Network {
            name: "home".into(),
            domain: "home.i3t".into(),
            cidr: "10.66.0.0/16".parse().unwrap(),
            routing: Default::default(),
            max_relay_hops: 2,
            reach: Default::default(),
            class: None,
            ack_eliciting_threshold: 3,
            max_ack_delay_ms: 2,
            bundle_small_packets: true,
            vnet_offload: true,
            vnet_mtu: 1280,
        },
        me: LocalNode {
            id: node(me),
            name: name_of(me).into(),
            virtual_ip: virtual_ip(me),
            routing: None,
            reach: None,
            dial_out_only: false,
            relay: None,
            exit: (me == GW).then(ExitRole::default),
            proxies: Vec::new(),
            forwards: Vec::new(),
            forward_targets: Vec::new(),
            pinned_relays: Vec::new(),
            profile: None,
            shared_relays: Vec::new(),
        },
        peers: [LAPTOP, GW, NAS].into_iter().filter(|&raw| raw != me).map(|raw| peer(raw, exit_of(raw))).collect(),
        relays: Vec::new(),
        relay_clients: Vec::new(),
        no_vnet: Vec::new(),
    }
}

/// laptop 上 [`World`] 一开始就有的代理：1、2 经 gw 出去，3、4 经 nas（nas 默认不是出口），各一个 SOCKS5 和一个 HTTP。
pub const SOCKS_VIA_GW: u32 = 1;
pub const HTTP_VIA_GW: u32 = 2;
pub const SOCKS_VIA_NAS: u32 = 3;
pub const HTTP_VIA_NAS: u32 = 4;

/// 经 `exit` 号节点出去、不认证的代理。
pub fn proxy(id: u32, protocol: ListenerProtocol, bind: &str, exit: u32) -> Proxy {
    Proxy {
        id,
        name: format!("p{id}"),
        bind: bind.parse().unwrap(),
        protocol,
        exit: node(exit),
        auth: None,
        allow_from: Vec::new(),
        class: None,
        optimistic: None,
        // 跑在 lane 上的那一遍，代理选了 ice3proxy：只有这样的代理的流才走 lane。
        lane: i3t_lane::testing::transport() == i3t_lane::testing::Transport::Lanes,
    }
}

/// `username` 和 `password` 的校验值，代理的 `auth` 用它。
pub fn verifier(username: &str, password: &str) -> Verifier {
    Verifier::derive([7; 16], username.as_bytes(), password.as_bytes())
}

/// 找到 netmap 里的一个对端来改。
pub fn peer_mut(netmap: &mut Netmap, raw: u32) -> &mut Peer {
    netmap.peers.iter_mut().find(|peer| peer.id == node(raw)).unwrap()
}

/// 假的操作系统。克隆出来的是同一个。
#[derive(Clone)]
pub struct FakeSystem {
    state: Arc<Mutex<FakeState>>,
}

struct FakeState {
    interfaces: Vec<IpNet>,
    names: HashMap<String, Result<Vec<IpAddr>, ResolveError>>,
    redirects: HashMap<SocketAddr, SocketAddr>,
    resolved: Vec<String>,
    connected: Vec<SocketAddr>,
    udp_destinations: Vec<SocketAddr>,
}

impl Default for FakeSystem {
    /// 默认有一块回环网卡和一块局域网网卡 `192.168.77.5/24`。
    fn default() -> Self {
        let interfaces = vec!["127.0.0.1/8".parse().unwrap(), "192.168.77.5/24".parse().unwrap()];
        let state = FakeState {
            interfaces,
            names: HashMap::new(),
            redirects: HashMap::new(),
            resolved: Vec::new(),
            connected: Vec::new(),
            udp_destinations: Vec::new(),
        };
        Self { state: Arc::new(Mutex::new(state)) }
    }
}

impl FakeSystem {
    /// 换掉网卡的地址。连接照样只看地址是不是这台机器真的有：要测"本节点自己的服务"时，放进去一个真的非回环地址。
    pub fn set_interfaces(&self, interfaces: &[&str]) {
        self.state.lock().unwrap().interfaces = interfaces.iter().map(|net| net.parse().unwrap()).collect();
    }

    /// 让 `name` 解析成这些地址。没有安排过的域名一律"不存在"。
    pub fn name(&self, name: &str, addrs: &[&str]) {
        let addrs = addrs.iter().map(|ip| ip.parse().unwrap()).collect();
        self.state.lock().unwrap().names.insert(name.into(), Ok(addrs));
    }

    pub fn name_fails(&self, name: &str, error: ResolveError) {
        self.state.lock().unwrap().names.insert(name.into(), Err(error));
    }

    /// 出口到现在为止决定往哪些地址发 UDP 报文（引到别处之前的），每个目标通过检查时记一次。
    pub fn udp_destinations(&self) -> Vec<SocketAddr> {
        self.state.lock().unwrap().udp_destinations.clone()
    }

    /// 把去 `target` 的连接（和 UDP 报文）引到本机的 `real` 上。
    pub fn redirect(&self, target: &str, real: SocketAddr) {
        self.state.lock().unwrap().redirects.insert(target.parse().unwrap(), real);
    }

    /// 出口到现在为止试着连过哪些地址（引到别处之前的）。
    pub fn connected(&self) -> Vec<SocketAddr> {
        self.state.lock().unwrap().connected.clone()
    }

    /// 出口到现在为止问过解析器哪些域名。
    pub fn resolved(&self) -> Vec<String> {
        self.state.lock().unwrap().resolved.clone()
    }
}

impl System for FakeSystem {
    fn interfaces(&self) -> io::Result<Vec<IpNet>> {
        Ok(self.state.lock().unwrap().interfaces.clone())
    }

    async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let mut state = self.state.lock().unwrap();
        state.resolved.push(name.to_owned());
        state.names.get(name).cloned().unwrap_or(Err(ResolveError::NotFound))
    }

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let redirect = {
            let mut state = self.state.lock().unwrap();
            state.connected.push(addr);
            state.redirects.get(&addr).copied()
        };
        let real = match redirect {
            Some(real) => real,
            None if is_this_machine(addr.ip()) => addr,
            // 没有安排过的地址绝不真的去连：测试不应该碰到外面的网络。
            None => return Err(io::Error::new(io::ErrorKind::NetworkUnreachable, "测试里没有安排这个地址")),
        };
        TcpStream::connect(real).await
    }

    fn udp_route(&self, addr: SocketAddr) -> SocketAddr {
        let mut state = self.state.lock().unwrap();
        state.udp_destinations.push(addr);
        match state.redirects.get(&addr) {
            Some(real) => *real,
            None if is_this_machine(addr.ip()) => addr,
            // 没有安排过的地址绝不真的去发：引到本机一个没有人收的端口上，报文就此消失。
            None => SocketAddr::from(([127, 0, 0, 1], 9)),
        }
    }
}

fn is_this_machine(ip: IpAddr) -> bool {
    ip.is_loopback() || Os.interfaces().unwrap().iter().any(|net| net.addr() == ip)
}

/// 这台机器的一个非回环 IPv4 地址；没有（只有回环网卡的环境）时是 `None`。
pub fn non_loopback_address() -> Option<IpAddr> {
    let interfaces = Os.interfaces().unwrap();
    interfaces.iter().map(IpNet::addr).find(|ip| ip.is_ipv4() && !ip.is_loopback() && !matches!(ip, IpAddr::V4(v4) if v4.is_link_local()))
}

/// 一个跑着的节点。
pub struct Node {
    pub id: NodeId,
    pub system: FakeSystem,
    /// 数据面报出来的本节点的候选端点（反射地址、端口映射拿到的地址）。测试往里放什么，出口就认为自己对外是什么地址。
    pub own_endpoints: Arc<Mutex<Vec<SocketAddr>>>,
    pub access: Arc<Access<LaneConnector<MemoryConnector>>>,
    pub exit: Arc<Exit<FakeSystem, LaneConnector<MemoryConnector>>>,
    /// 本节点的 lane：看和哪个对端之间经过了多少字节。
    pub lanes: Arc<Lanes>,
    netmap: watch::Sender<Arc<Netmap>>,
}

impl Node {
    pub async fn start(mesh: &MemoryMesh, lanes: &LaneMesh, netmap: Netmap) -> Self {
        Self::start_with_udp_idle(mesh, lanes, netmap, None).await
    }

    /// 同 [`Node::start`]。`udp_idle` 有值时，数据报上下文和 UDP 端口转发的会话空闲这么久就回收，而不是默认的 60 秒。
    pub async fn start_with_udp_idle(mesh: &MemoryMesh, lane_mesh: &LaneMesh, netmap: Netmap, udp_idle: Option<Duration>) -> Self {
        let id = netmap.me.id;
        let (connector, acceptor) = mesh.join(id);
        let lanes = lane_mesh.join(id).await;
        let connector = Arc::new(LaneConnector::new(Arc::new(connector), Arc::clone(&lanes), lane_mesh.choose()));
        let acceptor: LaneAcceptor<MemoryAcceptor> = LaneAcceptor::new(Arc::new(acceptor), Arc::clone(&lanes));
        let (sender, receiver) = watch::channel(Arc::new(netmap));
        let system = FakeSystem::default();
        let own_endpoints: Arc<Mutex<Vec<SocketAddr>>> = Arc::default();
        let outbound = Outbound::new(receiver.clone(), system.clone()).with_own_endpoints({
            let own_endpoints = Arc::clone(&own_endpoints);
            move || own_endpoints.lock().unwrap().clone()
        });
        let mut access = Access::new(Arc::clone(&connector), receiver.clone());
        let mut exit =
            Exit::new(receiver, outbound, connector).with_opener(access.datagram_opener()).with_forward_health(access.forward_health());
        if let Some(udp_idle) = udp_idle {
            exit = exit.with_datagram_idle_timeout(udp_idle);
            access = access.with_udp_idle_timeout(udp_idle);
        }
        let (exit, access) = (Arc::new(exit), Arc::new(access));
        tokio::spawn({
            let access = Arc::clone(&access);
            async move { access.run().await }
        });
        tokio::spawn({
            let exit = Arc::clone(&exit);
            async move { i3t_flow::serve(&acceptor, exit).await }
        });
        Self { id, system, own_endpoints, access, exit, lanes, netmap: sender }
    }

    /// 改这个节点的 netmap 并下发（版本号加一），等入口把监听调整完。
    pub async fn update(&self, change: impl FnOnce(&mut Netmap)) -> AccessStatus {
        let mut netmap = Netmap::clone(&self.netmap.borrow());
        change(&mut netmap);
        netmap.version += 1;
        self.netmap.send(Arc::new(netmap)).unwrap();
        self.settled().await
    }

    /// 等入口应用完当前这一版 netmap，返回它的监听状态。
    pub async fn settled(&self) -> AccessStatus {
        let version = self.netmap.borrow().version;
        timeout(PATIENCE, async {
            loop {
                let status = self.access.status();
                if status.version == version {
                    return status;
                }
                sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("入口应该很快应用完新的 netmap")
    }

    /// 一个代理实际监听的地址。
    pub async fn proxy(&self, id: u32) -> SocketAddr {
        let status = self.settled().await;
        let proxy = status.proxies.iter().find(|proxy| proxy.id == id).unwrap_or_else(|| panic!("没有 {id} 号代理"));
        local_addr(&proxy.state)
    }

    /// 一条端口转发实际监听的地址。
    pub async fn forward(&self, id: u32) -> SocketAddr {
        let status = self.settled().await;
        local_addr(&status.forwards.iter().find(|forward| forward.id == id).unwrap_or_else(|| panic!("没有 {id} 号端口转发")).state)
    }
}

fn local_addr(state: &ListenState) -> SocketAddr {
    match state {
        // 监听在 0.0.0.0 上时从回环连过去。
        ListenState::Listening { local } if local.ip().is_unspecified() => SocketAddr::new(Ipv4Addr::LOCALHOST.into(), local.port()),
        ListenState::Listening { local } => *local,
        other => panic!("监听没有起来：{other:?}"),
    }
}

/// 三个节点。laptop 上有经 gw 和经 nas 出去的 SOCKS5 和 HTTP 代理（[`SOCKS_VIA_GW`] 等），都在回环上、不认证。
pub struct World {
    pub mesh: MemoryMesh,
    pub lanes: LaneMesh,
    pub laptop: Node,
    pub gw: Node,
    pub nas: Node,
}

impl World {
    pub async fn new() -> Self {
        Self::start(None).await
    }

    /// 同 [`World::new`]，但数据报上下文和 UDP 端口转发的会话空闲 `udp_idle` 就回收。
    pub async fn with_udp_idle(udp_idle: Duration) -> Self {
        Self::start(Some(udp_idle)).await
    }

    async fn start(udp_idle: Option<Duration>) -> Self {
        let mesh = MemoryMesh::new();
        let lanes = LaneMesh::for_current_test();
        let mut laptop = netmap(LAPTOP);
        laptop.me.proxies = vec![
            proxy(SOCKS_VIA_GW, ListenerProtocol::Socks5, "127.0.0.1:0", GW),
            proxy(HTTP_VIA_GW, ListenerProtocol::Http, "127.0.0.1:0", GW),
            proxy(SOCKS_VIA_NAS, ListenerProtocol::Socks5, "127.0.0.1:0", NAS),
            proxy(HTTP_VIA_NAS, ListenerProtocol::Http, "127.0.0.1:0", NAS),
        ];
        let laptop = Node::start_with_udp_idle(&mesh, &lanes, laptop, udp_idle).await;
        let gw = Node::start_with_udp_idle(&mesh, &lanes, netmap(GW), udp_idle).await;
        let nas = Node::start_with_udp_idle(&mesh, &lanes, netmap(NAS), udp_idle).await;
        let world = Self { laptop, gw, nas, mesh: mesh.clone(), lanes };
        world.laptop.settled().await;
        world
    }

    /// laptop 上经 gw 出去的 SOCKS5 代理。
    pub async fn socks(&self) -> SocketAddr {
        self.laptop.proxy(SOCKS_VIA_GW).await
    }

    /// laptop 上经 gw 出去的 HTTP 代理。
    pub async fn http(&self) -> SocketAddr {
        self.laptop.proxy(HTTP_VIA_GW).await
    }

    /// laptop 上经 nas 出去的 SOCKS5 代理。
    pub async fn socks_via_nas(&self) -> SocketAddr {
        self.laptop.proxy(SOCKS_VIA_NAS).await
    }

    /// laptop 上经 nas 出去的 HTTP 代理。
    pub async fn http_via_nas(&self) -> SocketAddr {
        self.laptop.proxy(HTTP_VIA_NAS).await
    }
}

/// 测试扮演的目标：一个监听着的端口，测试从它接到出口连过来的连接。
pub struct Target {
    listener: TcpListener,
}

impl Target {
    pub async fn bind(ip: &str) -> Self {
        Self { listener: TcpListener::bind((ip.parse::<IpAddr>().unwrap(), 0)).await.unwrap() }
    }

    pub fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub async fn accept(&self) -> TcpStream {
        timeout(PATIENCE, self.listener.accept()).await.expect("应该有连接连到目标").unwrap().0
    }

    /// 在 `within` 之内没有任何连接连过来。
    pub async fn assert_untouched(&self, within: Duration) {
        assert!(timeout(within, self.listener.accept()).await.is_err(), "不应该有连接连到这个目标");
    }

    /// 之后每条连接都原样回显，直到对方关掉发送方向。
    pub fn echo(self) -> SocketAddr {
        let addr = self.addr();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = self.listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        addr
    }
}

/// 在本机回环上起一个回显服务。
pub async fn echo_server() -> SocketAddr {
    Target::bind("127.0.0.1").await.echo()
}

/// 一个没有人监听、连过去被拒绝的本机端口，在这个测试进程结束之前一直如此。
///
/// 端口由一条本机连接的发起那一头占着：连接一直开着，别的 socket 绑不到这个端口；发到这个端口的新连接找不到监听，
/// 三个系统的内核都回 RST（Windows 要重试两秒左右才报出来）。不用只绑定、不监听的 socket 占着：Linux 和 Windows
/// 对它回 RST，macOS 却把 SYN 悄悄丢掉，连接一直等到超时。也不能绑一下就放掉：跑满整个工作区的测试时偶尔有别的测试的
/// 监听正好拿到这个端口，连过去就连上了，客户端看到的是正常结束而不是"被拒绝"之后的重置。
/// 两头的 socket 故意不关：几个文件描述符，换来端口不会被别人拿走。用阻塞的 socket：回环上建连当场完成。
pub async fn closed_port() -> SocketAddr {
    closed_port_on(Ipv4Addr::LOCALHOST.into())
}

/// 和 [`closed_port`] 一样，端口在本机的 `ip` 这个地址上。
fn closed_port_on(ip: IpAddr) -> SocketAddr {
    let listener = std::net::TcpListener::bind((ip, 0)).unwrap();
    let holder = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let addr = holder.local_addr().unwrap();
    std::mem::forget((holder, accepted));
    addr
}

/// 一个只在 127.0.0.1 上监听的回显服务，同一个端口号在本机的 `other` 这个地址上连过去被拒绝，
/// 在这个测试进程结束之前一直如此。
///
/// 并行的测试各自让系统挑端口，同一个号可以同时分给 127.0.0.1 和别的地址：只起回环上的服务的话，偶尔有别的测试的监听
/// 正好在 `other` 上拿到这个号，连过去就连上了。所以先把 `other` 上的这个号占住（占法见 [`closed_port`]），
/// 再在回环上用同一个号起服务；回环上这个号已经有人用了就换一个。
pub async fn echo_server_on_loopback_only(other: IpAddr) -> SocketAddr {
    loop {
        let port = closed_port_on(other).port();
        if let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            return Target { listener }.echo();
        }
    }
}

/// [`assert_echo`] 每次发出去多少字节。
pub const ECHO_LEN: u64 = 50;

/// 发一段数据过去，确认原样回来。
///
/// 这段数据长得像一条完整的 TLS 握手记录，所以经过代理入口时，它会被当作首批数据随建流请求一起发出去。
pub async fn assert_echo(stream: &mut TcpStream) {
    let mut message = vec![0x16, 0x03, 0x01, 0x00, 45];
    message.extend(b"client hello ".iter().cycle().take(45));
    assert_eq!(u64::try_from(message.len()).unwrap(), ECHO_LEN);
    stream.write_all(&message).await.unwrap();
    let mut back = vec![0; message.len()];
    timeout(PATIENCE, stream.read_exact(&mut back)).await.expect("回显应该回来").unwrap();
    assert_eq!(back, message);
}

/// 把连接读到结束，返回读到的数据和结束的方式。
pub async fn drain(stream: &mut TcpStream) -> (Vec<u8>, io::Result<()>) {
    let mut data = Vec::new();
    let end = timeout(PATIENCE, stream.read_to_end(&mut data)).await.expect("连接应该结束");
    (data, end.map(drop))
}

pub fn assert_reset(end: &io::Result<()>) {
    let kind = end.as_ref().expect_err("连接应该是被重置的，而不是正常结束").kind();
    assert_eq!(kind, io::ErrorKind::ConnectionReset);
}

/// SOCKS5 握手的结果。
#[derive(Debug)]
pub enum Socks5 {
    /// 代理说连上了。
    Connected(TcpStream),
    /// 代理对 CONNECT 回了一个失败的应答码。
    Failed(u8),
    /// 用户名密码认证没有通过。
    AuthRejected,
    /// 代理不接受客户端提供的认证方法。
    NoAcceptableMethod,
}

impl Socks5 {
    pub fn connected(self) -> TcpStream {
        match self {
            Self::Connected(stream) => stream,
            other => panic!("代理应该说连上了，实际是 {other:?}"),
        }
    }

    pub fn failed(self) -> u8 {
        match self {
            Self::Failed(code) => code,
            other => panic!("代理应该回一个失败的应答码，实际是 {other:?}"),
        }
    }
}

/// 做一次 SOCKS5 握手。`auth` 是用户名和密码，这时客户端只提供用户名密码认证；没有时只提供"不认证"。
pub async fn socks5(proxy: SocketAddr, auth: Option<(&str, &str)>, host: &str, port: u16) -> Socks5 {
    timeout(PATIENCE, async {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(if auth.is_some() { &[5, 1, 2] } else { &[5, 1, 0] }).await.unwrap();
        let mut selection = [0; 2];
        stream.read_exact(&mut selection).await.unwrap();
        match (selection, auth) {
            ([5, 0xff], _) => return Socks5::NoAcceptableMethod,
            ([5, 2], Some((username, password))) => {
                let mut message = vec![1, u8::try_from(username.len()).unwrap()];
                message.extend_from_slice(username.as_bytes());
                message.push(u8::try_from(password.len()).unwrap());
                message.extend_from_slice(password.as_bytes());
                stream.write_all(&message).await.unwrap();
                let mut status = [0; 2];
                stream.read_exact(&mut status).await.unwrap();
                if status != [1, 0] {
                    return Socks5::AuthRejected;
                }
            }
            ([5, 0], _) => {}
            other => panic!("代理选的认证方法不对：{other:?}"),
        }

        let mut request = vec![5, 1, 0];
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
            Err(_) => {
                request.push(3);
                request.push(u8::try_from(host.len()).unwrap());
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();

        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!((reply[0], reply[2], &reply[3..]), (5, 0, &[1, 0, 0, 0, 0, 0, 0][..]), "应答的格式不对");
        match reply[1] {
            0 => Socks5::Connected(stream),
            code => Socks5::Failed(code),
        }
    })
    .await
    .expect("SOCKS5 握手应该很快完成")
}

/// 发一个 HTTP CONNECT，返回状态码和连接。`auth` 是 Basic 认证的用户名和密码。
pub async fn http_connect(proxy: SocketAddr, authority: &str, auth: Option<(&str, &str)>) -> (u16, TcpStream) {
    timeout(PATIENCE, async {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some((username, password)) = auth {
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", STANDARD.encode(format!("{username}:{password}"))));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();

        // 一个字节一个字节读到空行为止，不碰后面的隧道数据。
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        let head = String::from_utf8(head).unwrap();
        let status = head.strip_prefix("HTTP/1.1 ").and_then(|rest| rest.get(..3)).unwrap_or_else(|| panic!("不是 HTTP 应答：{head:?}"));
        (status.parse().unwrap(), stream)
    })
    .await
    .expect("HTTP CONNECT 应该很快得到应答")
}

/// 等一个条件成立。用在"另一头的任务很快就会做完某件事"的地方。
pub async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let waited = timeout(PATIENCE, async {
        while !condition() {
            sleep(Duration::from_millis(2)).await;
        }
    });
    waited.await.unwrap_or_else(|_| panic!("等了 {PATIENCE:?} 也没有等到：{what}"));
}

/// 测试扮演的 UDP 目标：一个绑好的端口，测试从它收出口发过来的报文。
pub struct UdpTarget {
    socket: UdpSocket,
}

impl UdpTarget {
    pub async fn bind(ip: &str) -> Self {
        Self { socket: UdpSocket::bind((ip.parse::<IpAddr>().unwrap(), 0)).await.unwrap() }
    }

    pub fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    /// 等下一个报文，返回它的内容和来源。
    pub async fn recv(&self) -> (Vec<u8>, SocketAddr) {
        let mut buf = vec![0; 65_535];
        let (len, from) = timeout(PATIENCE, self.socket.recv_from(&mut buf)).await.expect("应该有报文发到目标").unwrap();
        buf.truncate(len);
        (buf, from)
    }

    pub async fn send(&self, data: &[u8], to: SocketAddr) {
        self.socket.send_to(data, to).await.unwrap();
    }

    /// 在 `within` 之内没有任何报文发过来。
    pub async fn assert_untouched(&self, within: Duration) {
        let mut buf = [0; 16];
        assert!(timeout(within, self.socket.recv_from(&mut buf)).await.is_err(), "不应该有报文发到这个目标");
    }

    /// 之后每个报文都原样发回它的来源。
    pub fn echo(self) -> SocketAddr {
        let addr = self.addr();
        tokio::spawn(async move {
            let mut buf = vec![0; 65_535];
            while let Ok((len, from)) = self.socket.recv_from(&mut buf).await {
                let _ = self.socket.send_to(&buf[..len], from).await;
            }
        });
        addr
    }
}

/// 在本机回环上起一个 UDP 回显服务。
pub async fn udp_echo_server() -> SocketAddr {
    UdpTarget::bind("127.0.0.1").await.echo()
}

/// 一个 SOCKS5 的 UDP 关联，测试扮演客户端。
pub struct UdpAssociation {
    /// 那条 TCP 连接。它一关，关联就结束。
    pub control: TcpStream,
    /// 客户端发报文用的端口。
    pub socket: UdpSocket,
    /// 代理给的 UDP 中继端口。
    pub relay: SocketAddr,
}

/// 做一次 SOCKS5 握手，请求 UDP ASSOCIATE。`auth` 是用户名和密码；没有时客户端只提供"不认证"。
/// 请求里客户端的地址写全 0：大多数客户端都这样。
pub async fn udp_associate(proxy: SocketAddr, auth: Option<(&str, &str)>) -> UdpAssociation {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_associate_from(proxy, auth, socket, [0; 6]).await
}

/// 同 [`udp_associate`]，用给定的端口发报文，并且在请求里写上 `declared`（IPv4 地址 4 字节加端口 2 字节）。
pub async fn udp_associate_from(proxy: SocketAddr, auth: Option<(&str, &str)>, socket: UdpSocket, declared: [u8; 6]) -> UdpAssociation {
    timeout(PATIENCE, async {
        let mut control = TcpStream::connect(proxy).await.unwrap();
        control.write_all(if auth.is_some() { &[5, 1, 2] } else { &[5, 1, 0] }).await.unwrap();
        let mut selection = [0; 2];
        control.read_exact(&mut selection).await.unwrap();
        if let Some((username, password)) = auth {
            assert_eq!(selection, [5, 2]);
            let mut message = vec![1, u8::try_from(username.len()).unwrap()];
            message.extend_from_slice(username.as_bytes());
            message.push(u8::try_from(password.len()).unwrap());
            message.extend_from_slice(password.as_bytes());
            control.write_all(&message).await.unwrap();
            let mut status = [0; 2];
            control.read_exact(&mut status).await.unwrap();
            assert_eq!(status, [1, 0], "用户名密码认证应该通过");
        } else {
            assert_eq!(selection, [5, 0]);
        }

        control.write_all(&[&[5, 3, 0, 1][..], &declared].concat()).await.unwrap();
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[..4], [5, 0, 0, 1], "代理应该答应 UDP ASSOCIATE，并给出一个 IPv4 的中继地址");
        let relay = SocketAddr::from(([reply[4], reply[5], reply[6], reply[7]], u16::from_be_bytes([reply[8], reply[9]])));
        UdpAssociation { control, socket, relay }
    })
    .await
    .expect("SOCKS5 握手应该很快完成")
}

/// 一个 SOCKS5 UDP 报文：头加数据。`host` 写成地址就按地址发，否则按域名发。
pub fn socks5_udp_packet(host: &str, port: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            packet.push(4);
            packet.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            packet.push(3);
            packet.push(u8::try_from(host.len()).unwrap());
            packet.extend_from_slice(host.as_bytes());
        }
    }
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

impl UdpAssociation {
    /// 经中继端口发一个报文给 `host:port`。
    pub async fn send(&self, host: &str, port: u16, data: &[u8]) {
        self.socket.send_to(&socks5_udp_packet(host, port, data), self.relay).await.unwrap();
    }

    /// 等中继端口发回来的下一个报文，返回它的来源（写成 `地址:端口`）和数据。
    pub async fn recv(&self) -> (String, Vec<u8>) {
        let mut buf = vec![0; 65_535];
        let (len, from) = timeout(PATIENCE, self.socket.recv_from(&mut buf)).await.expect("中继端口应该发回一个报文").unwrap();
        assert_eq!(from, self.relay, "报文应该是从中继端口发回来的");
        assert_eq!(buf[..3], [0, 0, 0], "保留字节和分片号都是 0");
        let (source, header_len) = match buf[3] {
            1 => (SocketAddr::from(([buf[4], buf[5], buf[6], buf[7]], u16::from_be_bytes([buf[8], buf[9]]))).to_string(), 10),
            4 => {
                let ip: [u8; 16] = buf[4..20].try_into().unwrap();
                (SocketAddr::from((ip, u16::from_be_bytes([buf[20], buf[21]]))).to_string(), 22)
            }
            3 => {
                let name_end = 5 + usize::from(buf[4]);
                let name = std::str::from_utf8(&buf[5..name_end]).unwrap();
                (format!("{name}:{}", u16::from_be_bytes([buf[name_end], buf[name_end + 1]])), name_end + 2)
            }
            other => panic!("不认识的地址类型 {other}"),
        };
        (source, buf[header_len..len].to_vec())
    }

    /// 在 `within` 之内中继端口什么都没有发回来。
    pub async fn assert_silent(&self, within: Duration) {
        let mut buf = [0; 16];
        assert!(timeout(within, self.socket.recv_from(&mut buf)).await.is_err(), "中继端口不应该发回报文");
    }
}
