//! 入口在真的 socket 上的行为。对端节点是一个记下建流请求、然后原样回显的替身。
//!
//! 入口加真的出口的端到端测试在 `i3t-exit` 的 `tests/` 里。

// clippy.toml 里的 allow-unwrap-in-tests 只管 #[test] 函数，管不到集成测试里的辅助函数。这里 unwrap 失败就是测试失败。
#![allow(clippy::unwrap_used)]

use std::future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use i3t_access::{Access, AccessStatus, ListenCause, ListenState, LocalEntry, PortBook, TargetCause};
use i3t_conn::{RecvStream, SendStream};
use i3t_flow::memory::{MemoryAcceptor, MemoryConnector, MemoryMesh};
use i3t_flow::{Handler, Request};
use i3t_lane::testing::LaneMesh;
use i3t_lane::{LaneAcceptor, LaneConnector, Lanes};
use i3t_model::Netmap;
use i3t_model::netmap::{Forward, ForwardProtocol, LaneMode, ListenerProtocol, LocalNode, Network, Peer, PeerExit, Proxy, Verifier};
use i3t_proto::flow::{Class, Open, Origin, Reply, Status, Target};
use i3t_proto::{NodeId, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const ME: u32 = 1;
const GW: u32 = 2;
const PATIENCE: Duration = Duration::from_secs(5);

fn node(raw: u32) -> NodeId {
    NodeId::new(raw).unwrap()
}

/// 本节点是 1 号，对端只有 2 号 `gw`：可以访问，是出口，开了局域网。
fn netmap() -> Netmap {
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
            ack_eliciting_threshold: 10,
            max_ack_delay_ms: 2,
        },
        me: LocalNode {
            id: node(ME),
            name: "laptop".into(),
            virtual_ip: [10, 66, 0, 1].into(),
            routing: None,
            reach: None,
            dial_out_only: false,
            relay: None,
            exit: None,
            proxies: Vec::new(),
            forwards: Vec::new(),
            forward_targets: Vec::new(),
            pinned_relays: Vec::new(),
            profile: None,
            shared_relays: Vec::new(),
        },
        peers: vec![Peer {
            id: node(GW),
            key: PublicKey::from_bytes([2; 32]),
            name: "gw".into(),
            virtual_ip: [10, 66, 0, 2].into(),
            inbound: true,
            outbound: true,
            endpoints: Vec::new(),
            attached: Vec::new(),
            exit: Some(PeerExit { lan: true, class: None, optimistic: None }),
            dial_out_only: false,
            keep_alive: false,
            lane: LaneMode::Off,
            congestion: None,
            no_udp: false,
        }],
        relays: Vec::new(),
        relay_clients: Vec::new(),
        no_vnet: Vec::new(),
    }
}

/// 经 `gw` 出去、不认证的代理。
fn proxy(id: u32, protocol: ListenerProtocol, bind: &str) -> Proxy {
    Proxy {
        id,
        name: format!("p{id}"),
        bind: bind.parse().unwrap(),
        protocol,
        exit: node(GW),
        auth: None,
        allow_from: Vec::new(),
        class: None,
        optimistic: None,
        // 跑在 lane 上的那一遍，代理选了 ice3proxy：只有这样的代理的流才走 lane。
        lane: i3t_lane::testing::transport() == i3t_lane::testing::Transport::Lanes,
    }
}

/// 同 [`proxy`]，认这一对用户名和密码。
fn guarded(id: u32, protocol: ListenerProtocol, bind: &str, username: &str, password: &str) -> Proxy {
    Proxy { auth: Some(Verifier::derive([id.to_le_bytes()[0]; 16], username.as_bytes(), password.as_bytes())), ..proxy(id, protocol, bind) }
}

fn forward(id: u32, protocol: ForwardProtocol, bind: &str) -> Forward {
    Forward { id, protocol, bind: bind.parse().unwrap(), target: node(GW), allow_from: Vec::new(), class: None }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    addr
}

/// 一个最小的 HTTP 服务：读完一个请求（`Content-Length` 或者 chunked 的请求体，请求头里有 `Expect: 100-continue` 时先回 100），
/// 把收到的整个请求原样作为应答的正文发回去，然后关连接。
async fn origin_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0; 4096];
                let head_end = loop {
                    if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                        break end + 4;
                    }
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(read, 0, "请求头还没完就结束了");
                    request.extend_from_slice(&chunk[..read]);
                };
                let head = String::from_utf8_lossy(&request[..head_end]).to_ascii_lowercase();
                if head.contains("\r\nexpect: 100-continue\r\n") {
                    stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.unwrap();
                }
                let length = head.split("\r\n").find_map(|line| line.strip_prefix("content-length: ")).map(|n| n.parse::<usize>().unwrap());
                let complete = |request: &[u8]| match length {
                    Some(length) => request.len() >= head_end + length,
                    // 测试里的 chunked 请求体最后一块之前总有别的块。
                    None if head.contains("transfer-encoding: chunked") => {
                        let body = &request[head_end..];
                        body.windows(5).any(|window| window == b"\r\n0\r\n") && body.ends_with(b"\r\n\r\n")
                    }
                    None => true,
                };
                while !complete(&request) {
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(read, 0, "请求体还没完就结束了");
                    request.extend_from_slice(&chunk[..read]);
                }
                let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", request.len());
                stream.write_all(&[answer.as_bytes(), &request].concat()).await.unwrap();
            });
        }
    });
    addr
}

/// 对端节点的替身：记下每个建流请求，接受它，然后把流接到一个回显服务上；去 80 端口的接到 [`origin_server`]。
struct EchoPeer {
    opens: mpsc::UnboundedSender<Open>,
    echo: SocketAddr,
    origin: SocketAddr,
}

impl Handler for EchoPeer {
    async fn handle<S: SendStream, R: RecvStream>(&self, request: Request<S, R>) {
        assert_eq!(request.peer(), node(ME));
        self.opens.send(request.open().clone()).unwrap();
        // 端口 9（和 9 号端口转发）当作"目标拒绝连接"，测拒绝怎么告诉客户端。
        if matches!(request.open().target, Target::Internet { port: 9, .. } | Target::Forward { id: 9 }) {
            return request.refuse(&Reply::new(Status::ConnectionRefused, "端口没开")).await;
        }
        let to = match request.open().target {
            Target::Internet { port: 80, .. } | Target::Node { port: 80 } => self.origin,
            _ => self.echo,
        };
        let target = TcpStream::connect(to).await.unwrap();
        let flow = request.accept().await.unwrap();
        flow.relay(target, future::pending()).await;
    }
}

/// 一个跑着的入口，对面是 [`EchoPeer`]。
struct World {
    netmap: watch::Sender<Arc<Netmap>>,
    access: Arc<Access<LaneConnector<MemoryConnector>>>,
    /// 对端收到的建流请求，按到达的顺序。
    opens: mpsc::UnboundedReceiver<Open>,
    manager: JoinHandle<()>,
    /// 本节点的 lane：看有多少字节经过了它。
    lanes: Arc<Lanes>,
}

impl World {
    async fn start(netmap: Netmap) -> Self {
        Self::start_with(netmap, |access| access).await
    }

    /// 同 [`World::start`]，入口在开始之前先交给 `prepare` 加上别的设置。
    async fn start_with(
        netmap: Netmap,
        prepare: impl FnOnce(Access<LaneConnector<MemoryConnector>>) -> Access<LaneConnector<MemoryConnector>>,
    ) -> Self {
        let mesh = MemoryMesh::new();
        let lane_mesh = LaneMesh::for_current_test();
        let (connector, _) = mesh.join(node(ME));
        let (_, acceptor) = mesh.join(node(GW));
        let my_lanes = lane_mesh.join(node(ME)).await;
        let peer_lanes = lane_mesh.join(node(GW)).await;
        let connector = LaneConnector::new(Arc::new(connector), Arc::clone(&my_lanes), lane_mesh.choose());
        let acceptor = LaneAcceptor::<MemoryAcceptor>::new(Arc::new(acceptor), peer_lanes);
        let (opens_sender, opens) = mpsc::unbounded_channel();
        let peer = Arc::new(EchoPeer { opens: opens_sender, echo: echo_server().await, origin: origin_server().await });
        tokio::spawn(async move { i3t_flow::serve(&acceptor, peer).await });

        let (sender, receiver) = watch::channel(Arc::new(netmap));
        let access = Arc::new(prepare(Access::new(Arc::new(connector), receiver)));
        let manager = tokio::spawn({
            let access = Arc::clone(&access);
            async move { access.run().await }
        });
        let world = Self { netmap: sender, access, opens, manager, lanes: my_lanes };
        world.settled().await;
        world
    }

    async fn update(&self, change: impl FnOnce(&mut Netmap)) -> AccessStatus {
        let mut netmap = Netmap::clone(&self.netmap.borrow());
        change(&mut netmap);
        netmap.version += 1;
        self.netmap.send(Arc::new(netmap)).unwrap();
        self.settled().await
    }

    async fn settled(&self) -> AccessStatus {
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

    /// 一个代理实际监听的地址（监听在 0.0.0.0 上时给回环地址）。
    async fn proxy(&self, id: u32) -> SocketAddr {
        let status = self.settled().await;
        local(&status.proxies.iter().find(|proxy| proxy.id == id).unwrap().state)
    }

    /// 一个组网入口实际监听的地址。
    async fn local_entry(&self, name: &str) -> SocketAddr {
        let status = self.settled().await;
        local(&status.local.iter().find(|entry| entry.name == name).unwrap().state)
    }

    async fn forward(&self, id: u32) -> SocketAddr {
        let status = self.settled().await;
        local(&status.forwards.iter().find(|forward| forward.id == id).unwrap().state)
    }

    async fn next_open(&mut self) -> Open {
        timeout(PATIENCE, self.opens.recv()).await.expect("对端应该收到一个建流请求").unwrap()
    }

    fn assert_no_open(&mut self) {
        assert!(self.opens.try_recv().is_err(), "对端不应该收到建流请求");
    }
}

fn local(state: &ListenState) -> SocketAddr {
    match state {
        ListenState::Listening { local } if local.ip().is_unspecified() => SocketAddr::new([127, 0, 0, 1].into(), local.port()),
        ListenState::Listening { local } => *local,
        other => panic!("监听没有起来：{other:?}"),
    }
}

async fn assert_echo(stream: &mut TcpStream) {
    stream.write_all(b"ping through the mesh").await.unwrap();
    let mut back = [0; 21];
    timeout(PATIENCE, stream.read_exact(&mut back)).await.expect("回显应该回来").unwrap();
    assert_eq!(&back, b"ping through the mesh");
}

/// 把 `request` 发给代理，读回 `expected.len()` 字节，确认和 `expected` 一样。
async fn exchange(stream: &mut TcpStream, request: &[u8], expected: &[u8]) {
    stream.write_all(request).await.unwrap();
    let mut answer = vec![0; expected.len()];
    timeout(PATIENCE, stream.read_exact(&mut answer)).await.expect("代理应该应答").unwrap();
    assert_eq!(answer, expected, "发的是 {request:02x?}");
}

/// 代理接下来是关连接（正常关或者重置都算），而不是再发数据。
async fn assert_closed(stream: &mut TcpStream) {
    let mut rest = Vec::new();
    let _ = timeout(PATIENCE, stream.read_to_end(&mut rest)).await.expect("代理应该关掉连接");
    assert!(rest.is_empty(), "代理不应该再发东西：{rest:02x?}");
}

/// 不认证的 SOCKS5 握手，一直做到 CONNECT 一个域名，返回应答码。
async fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> (u8, TcpStream) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    exchange(&mut stream, &[5, 1, 0], &[5, 0]).await;
    socks5_request(stream, host, port).await
}

/// 用户名密码认证的 SOCKS5 握手。认证通过时接着 CONNECT 一个域名，返回应答码；没通过时返回 `None`（代理随后关掉连接）。
async fn socks5_login(proxy: SocketAddr, username: &str, password: &str, host: &str, port: u16) -> Option<(u8, TcpStream)> {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    exchange(&mut stream, &[5, 1, 2], &[5, 2]).await;
    let auth = [
        &[1, u8::try_from(username.len()).unwrap()][..],
        username.as_bytes(),
        &[u8::try_from(password.len()).unwrap()],
        password.as_bytes(),
    ]
    .concat();
    stream.write_all(&auth).await.unwrap();
    let mut status = [0; 2];
    timeout(PATIENCE, stream.read_exact(&mut status)).await.expect("代理应该回答认证").unwrap();
    if status != [1, 0] {
        assert_eq!(status, [1, 1], "认证没通过的应答");
        assert_closed(&mut stream).await;
        return None;
    }
    Some(socks5_request(stream, host, port).await)
}

async fn socks5_request(mut stream: TcpStream, host: &str, port: u16) -> (u8, TcpStream) {
    let request = [&[5, 1, 0, 3, u8::try_from(host.len()).unwrap()][..], host.as_bytes(), &port.to_be_bytes()].concat();
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    timeout(PATIENCE, stream.read_exact(&mut reply)).await.expect("代理应该应答").unwrap();
    (reply[1], stream)
}

fn internet(host: &str, port: u16) -> Target {
    Target::Internet { host: host.parse().unwrap(), port }
}

i3t_lane::on_both_transports! {
    async fn proxy_requests_become_flows_carrying_target_class_and_origin() {
        let mut netmap = netmap();
        let mut http = proxy(2, ListenerProtocol::Http, "127.0.0.1:0");
        http.class = Some(Class::Bulk);
        netmap.me.proxies = vec![proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0"), http];
        let mut world = World::start(netmap).await;
        let socks = world.proxy(1).await;

        // 域名原样交给代理的出口去解析。
        let (code, mut stream) = socks5_connect(socks, "example.com", 443).await;
        assert_eq!(code, 0);
        assert_echo(&mut stream).await;
        let open = world.next_open().await;
        assert_eq!(open, Open { target: internet("example.com", 443), class: Class::Auto, origin: Origin::default() });

        // 私有地址按"出口的局域网"发。
        let (code, mut stream) = socks5_connect(socks, "192.168.1.10", 8080).await;
        assert_eq!(code, 0);
        assert_echo(&mut stream).await;
        assert_eq!(world.next_open().await.target, Target::Lan { addr: "192.168.1.10:8080".parse().unwrap() });

        // 组网地址是那个节点自己的端口，不经出口。
        let mut stream = TcpStream::connect(socks).await.unwrap();
        exchange(&mut stream, &[5, 1, 0], &[5, 0]).await;
        exchange(&mut stream, &[5, 1, 0, 1, 10, 66, 0, 2, 0, 22], &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        assert_echo(&mut stream).await;
        assert_eq!(world.next_open().await, Open { target: Target::Node { port: 22 }, class: Class::Auto, origin: Origin::default() });

        // HTTP 代理一样；QoS 是这个代理自己设的。用户名里写什么都不再有意思。
        let mut stream = TcpStream::connect(world.proxy(2).await).await.unwrap();
        let request = format!("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", STANDARD.encode("gw+c-i:"));
        exchange(&mut stream, request.as_bytes(), b"HTTP/1.1 200 Connection established\r\n\r\n").await;
        assert_echo(&mut stream).await;
        assert_eq!(world.next_open().await, Open { target: internet("example.com", 443), class: Class::Bulk, origin: Origin::default() });
    }
}

i3t_lane::on_both_transports! {
    async fn a_proxy_off_loopback_needs_its_user_name_and_password_and_the_client_address_travels_in_the_origin() {
        let mut netmap = netmap();
        netmap.me.proxies = vec![guarded(1, ListenerProtocol::Socks5, "0.0.0.0:0", "alice", "s3cret"), proxy(2, ListenerProtocol::Socks5, "0.0.0.0:0")];
        let mut world = World::start(netmap).await;
        let port = world.proxy(1).await.port();
        let loopback = SocketAddr::new([127, 0, 0, 1].into(), port);

        // 对的用户名和密码：从回环连过去时不写来源地址。
        let (code, _stream) = socks5_login(loopback, "alice", "s3cret", "example.com", 443).await.unwrap();
        assert_eq!(code, 0);
        assert_eq!(world.next_open().await.origin, Origin { credential: None, client: None });

        // 错的、少一个的：认证就不过。
        for (username, password) in [("alice", "wrong"), ("bob", "s3cret"), ("alice", ""), ("", "")] {
            assert!(socks5_login(loopback, username, password, "example.com", 443).await.is_none(), "{username}:{password}");
        }
        // 不提用户名密码：没有可用的认证方法。
        let mut stream = TcpStream::connect(loopback).await.unwrap();
        exchange(&mut stream, &[5, 1, 0], &[5, 0xff]).await;
        assert_closed(&mut stream).await;
        // 不在回环上、又没有用户名和密码的代理谁都不让用（controller 不下发这样的，静态的 netmap 可能这样写）。
        let open = SocketAddr::new([127, 0, 0, 1].into(), world.proxy(2).await.port());
        assert!(socks5_login(open, "", "", "example.com", 443).await.is_none());
        world.assert_no_open();

        // 从这台机器的局域网地址连过去（有的话）：入口看到的客户端地址带上。
        let Some(lan_ip) = non_loopback_address() else {
            eprintln!("跳过后半段：这台机器只有回环网卡");
            return;
        };
        let (code, stream) = socks5_login(SocketAddr::new(lan_ip, port), "alice", "s3cret", "example.com", 443).await.unwrap();
        assert_eq!(code, 0);
        let origin = world.next_open().await.origin;
        assert_eq!(origin, Origin { credential: None, client: Some(stream.local_addr().unwrap()) });
    }
}

/// 这台机器的一个非回环 IPv4 地址：往外"连"一个 UDP socket（不发任何包），看系统给它挑的本地地址。
fn non_loopback_address() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip()).filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
}

#[tokio::test]
async fn a_port_forward_turns_each_connection_into_a_flow_for_its_id() {
    let mut netmap = netmap();
    netmap.me.forwards = vec![forward(7, ForwardProtocol::Tcp, "127.0.0.1:0")];
    let mut world = World::start(netmap).await;

    let mut stream = TcpStream::connect(world.forward(7).await).await.unwrap();
    assert_echo(&mut stream).await;
    assert_eq!(world.next_open().await, Open { target: Target::Forward { id: 7 }, class: Class::Auto, origin: Origin::default() });
    assert_eq!(world.settled().await.forwards[0].active.get(), 1);
    drop(stream);
    let active = world.settled().await.forwards[0].active.clone();
    timeout(PATIENCE, async {
        while active.get() != 0 {
            sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("连接结束之后计数应该归零");
}

/// 和对端之间备着 ice3proxy 时，只有选了它的代理的流走 lane：端口转发、本机的组网入口、
/// 没有选它的代理都走共用的连接。
#[tokio::test]
async fn on_a_pair_with_lanes_only_a_proxy_that_chose_ice3proxy_takes_one() {
    i3t_lane::testing::run(i3t_lane::testing::Transport::Lanes, async {
        let mut with_lanes = netmap();
        with_lanes.peers[0].lane = LaneMode::Always;
        let carried = |world: &World| {
            let total = world.lanes.status().total;
            total.sealed_bytes + total.passthrough_bytes + total.spliced_bytes
        };

        // 本机的组网入口单独一个入口：和代理绑在同一个地址上时它让给代理。
        let local =
            LocalEntry { name: "local-socks5".to_owned(), bind: "127.0.0.1:0".parse().unwrap(), protocol: ListenerProtocol::Socks5 };
        let mut entries = World::start_with(with_lanes.clone(), |access| access.with_local_entries(vec![local])).await;
        let (code, mut through_local) = socks5_connect(entries.local_entry("local-socks5").await, "gw.home.i3t", 22).await;
        assert_eq!(code, 0);
        assert_echo(&mut through_local).await;
        assert_eq!(entries.next_open().await.target, Target::Node { port: 22 });
        assert_eq!(carried(&entries), 0, "本机的组网入口不走 lane");

        let mut netmap = with_lanes;
        let plain = Proxy { lane: false, ..proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0") };
        let chosen = Proxy { lane: true, ..proxy(2, ListenerProtocol::Socks5, "127.0.0.1:0") };
        netmap.me.proxies = vec![plain, chosen];
        netmap.me.forwards = vec![forward(7, ForwardProtocol::Tcp, "127.0.0.1:0")];
        let mut world = World::start(netmap).await;
        let mut forwarded = TcpStream::connect(world.forward(7).await).await.unwrap();
        assert_echo(&mut forwarded).await;
        assert_eq!(world.next_open().await.target, Target::Forward { id: 7 });
        let (code, mut proxied) = socks5_connect(world.proxy(1).await, "example.com", 443).await;
        assert_eq!(code, 0);
        assert_echo(&mut proxied).await;
        assert_eq!(world.next_open().await.target, internet("example.com", 443));
        assert_eq!(carried(&world), 0, "端口转发和没选 ice3proxy 的代理不走 lane");

        let (code, mut chosen) = socks5_connect(world.proxy(2).await, "example.com", 443).await;
        assert_eq!(code, 0);
        assert_echo(&mut chosen).await;
        assert!(carried(&world) > 0, "选了 ice3proxy 的代理的流走 lane");
    })
    .await;
}

#[tokio::test]
async fn a_forward_says_why_its_target_cannot_be_reached_until_a_stream_gets_through() {
    let mut netmap = netmap();
    let mut offline = netmap.peers[0].clone();
    (offline.id, offline.name, offline.virtual_ip, offline.key) =
        (node(3), "nas".into(), [10, 66, 0, 3].into(), PublicKey::from_bytes([3; 32]));
    netmap.peers.push(offline);
    let mut to_offline = forward(8, ForwardProtocol::Tcp, "127.0.0.1:0");
    to_offline.target = node(3);
    netmap.me.forwards = vec![forward(7, ForwardProtocol::Tcp, "127.0.0.1:0"), forward(9, ForwardProtocol::Tcp, "127.0.0.1:0"), to_offline];
    let mut world = World::start(netmap).await;
    let cause = |world: &World, id: u32| {
        world.access.status().forwards.iter().find(|forward| forward.id == id).unwrap().target_failure.map(|failure| failure.cause)
    };
    let eventually = async |world: &World, id: u32, expected: Option<TargetCause>| {
        timeout(PATIENCE, async {
            while cause(world, id) != expected {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("转发 {id} 应该是 {expected:?}，现在是 {:?}", cause(world, id)));
    };

    let mut stream = TcpStream::connect(world.forward(7).await).await.unwrap();
    assert_echo(&mut stream).await;
    drop(stream);
    let _ = world.next_open().await;

    // 目标拒绝：客户端的连接被重置，转发记下原因。
    let mut refused = TcpStream::connect(world.forward(9).await).await.unwrap();
    refused.write_all(b"hello").await.unwrap();
    let _ = timeout(PATIENCE, refused.read_to_end(&mut Vec::new())).await.unwrap();
    assert_eq!(world.next_open().await.target, Target::Forward { id: 9 });
    eventually(&world, 9, Some(TargetCause::Refused)).await;

    // 目标节点开不出流。
    let mut unreachable = TcpStream::connect(world.forward(8).await).await.unwrap();
    let _ = timeout(PATIENCE, unreachable.read_to_end(&mut Vec::new())).await.unwrap();
    eventually(&world, 8, Some(TargetCause::NodeUnreachable)).await;
    assert_eq!(cause(&world, 7), None, "通着的转发没有记录");

    // 那条转发改成指向一个通着的目标之后，一条流成功了，记录就清掉。
    world.update(|netmap| netmap.me.forwards[2].target = node(GW)).await;
    let mut stream = TcpStream::connect(world.forward(8).await).await.unwrap();
    assert_echo(&mut stream).await;
    drop(stream);
    eventually(&world, 8, None).await;
}

/// 本进程里一条 TCP 连接（按本端和对端的端口找）的保活计时器还有多久到；没有在走的保活计时器时是 `None`。
/// 读的是 `/proc/net/tcp`，所以只有 Linux 上有。
#[cfg(target_os = "linux")]
fn keepalive_timer(local: SocketAddr, remote: SocketAddr) -> Option<Duration> {
    let table = std::fs::read_to_string("/proc/net/tcp").unwrap();
    let port = |field: &str| u16::from_str_radix(field.rsplit(':').next().unwrap(), 16).unwrap();
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if port(fields[1]) != local.port() || port(fields[2]) != remote.port() {
            return None;
        }
        // 第 6 列是"计时器种类:还有多久"，种类 2 是保活，时间的单位是 1/100 秒。
        let (kind, when) = fields[5].split_once(':').unwrap();
        (kind == "02").then(|| Duration::from_millis(u64::from_str_radix(when, 16).unwrap() * 10))
    })
}

/// 流没有空闲时限，客户端悄悄消失时只能靠内核保活发现：入口接受的每条客户端连接都要打开它。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn accepted_client_connections_probe_an_idle_client_with_keepalives() {
    let mut netmap = netmap();
    netmap.me.proxies = vec![proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0")];
    netmap.me.forwards = vec![forward(7, ForwardProtocol::Tcp, "127.0.0.1:0")];
    let world = World::start(netmap).await;

    for server in [world.proxy(1).await, world.forward(7).await] {
        // 客户端连上之后什么都不发：这正是要靠保活判断死活的静默连接。
        let client = TcpStream::connect(server).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let timer = timeout(PATIENCE, async {
            loop {
                if let Some(timer) = keepalive_timer(server, client_addr) {
                    return timer;
                }
                sleep(Duration::from_millis(5)).await;
            }
        });
        let timer = timer.await.unwrap_or_else(|_| panic!("入口接受的 {server} 上的连接没有打开保活"));
        assert!(timer <= i3t_flow::KEEPALIVE, "静默 {:?} 之后就开始探测，现在还要等 {timer:?}", i3t_flow::KEEPALIVE);
    }
}

/// 监听在本节点虚拟 IP 上的端口转发：别的节点经虚拟网卡来连，所以在那个地址上真的监听。Linux 上地址还不在本机也绑得上
/// （`IP_FREEBIND`，这里的测试机器上就没有这个地址）；别的平台上绑不上，先报 `Virtual`、只经流来访问，网卡装上之后再绑。
/// 目标是本节点自己的 UDP 转发不监听（本节点到不了自己的数据报上下文）。
#[tokio::test]
async fn forwards_on_our_virtual_ip_listen_there_or_wait_for_the_address() {
    let mut netmap = netmap();
    let mut to_myself = forward(1, ForwardProtocol::Udp, "10.66.0.1:5353");
    to_myself.target = node(ME);
    netmap.me.forwards = vec![
        to_myself,
        forward(2, ForwardProtocol::Tcp, "10.66.0.1:8080"),
        forward(3, ForwardProtocol::Tcp, "127.0.0.1:0"),
        forward(4, ForwardProtocol::Udp, "127.0.0.1:0"),
        forward(5, ForwardProtocol::Udp, "10.66.0.1:5354"),
        forward(6, ForwardProtocol::Tcp, "10.66.0.1:0"),
    ];
    let world = World::start(netmap).await;
    let status = world.settled().await;
    assert_eq!(status.forwards.iter().map(|forward| forward.id).collect::<Vec<u32>>(), [1, 2, 3, 4, 5, 6]);
    assert_eq!(status.forwards[0].state, ListenState::Virtual, "目标是本节点自己的 UDP 转发只经流");
    for (at, port) in [(1, 8080), (4, 5354)] {
        let expected = if cfg!(target_os = "linux") {
            ListenState::Listening { local: SocketAddr::from(([10, 66, 0, 1], port)) }
        } else {
            ListenState::Virtual
        };
        assert_eq!(status.forwards[at].state, expected, "虚拟 IP 上的 {port}");
    }
    assert!(matches!(status.forwards[2].state, ListenState::Listening { .. }));
    assert!(matches!(status.forwards[3].state, ListenState::Listening { .. }), "UDP 的端口转发和 TCP 的一样监听");
    assert!(
        matches!(&status.forwards[5].state, ListenState::Unsupported { reason, cause: ListenCause::VirtualPortZero } if reason.contains("端口")),
        "{:?}",
        status.forwards[5].state
    );
}

i3t_lane::on_both_transports! {
    async fn the_source_allow_list_is_checked_before_anything_else() {
        let mut netmap = netmap();
        let mut guarded = proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0");
        guarded.allow_from = vec!["10.0.0.0/8".parse().unwrap()];
        netmap.me.proxies = vec![guarded];
        let mut guarded_forward = forward(7, ForwardProtocol::Tcp, "127.0.0.1:0");
        guarded_forward.allow_from = vec!["192.168.0.0/16".parse().unwrap()];
        netmap.me.forwards = vec![guarded_forward];
        let mut world = World::start(netmap).await;
        let (socks, forwarded) = (world.proxy(1).await, world.forward(7).await);

        // 来源（127.0.0.1）不在白名单里：连接直接被关掉，连握手都不做。
        let mut stream = TcpStream::connect(socks).await.unwrap();
        let _ = stream.write_all(&[5, 1, 0]).await;
        assert_closed(&mut stream).await;
        let mut stream = TcpStream::connect(forwarded).await.unwrap();
        assert_closed(&mut stream).await;
        world.assert_no_open();

        // 白名单改了之后新的连接就按新的来，不需要重新绑定。
        world
            .update(|netmap| {
                netmap.me.proxies[0].allow_from.push("127.0.0.0/8".parse().unwrap());
                netmap.me.forwards[0].allow_from.push("127.0.0.1/32".parse().unwrap());
            })
            .await;
        assert_eq!((world.proxy(1).await, world.forward(7).await), (socks, forwarded));
        let (code, mut proxied) = socks5_connect(socks, "example.com", 443).await;
        assert_eq!(code, 0);
        assert_echo(&mut proxied).await;
        let mut stream = TcpStream::connect(forwarded).await.unwrap();
        assert_echo(&mut stream).await;
    }
}

#[tokio::test]
async fn unsupported_and_malformed_socks5_requests_get_the_right_answer() {
    let mut netmap = netmap();
    let mut unknown_exit = proxy(2, ListenerProtocol::Socks5, "127.0.0.1:0");
    unknown_exit.exit = node(9);
    netmap.me.proxies = vec![proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0"), unknown_exit];
    let mut world = World::start(netmap).await;
    let socks = world.proxy(1).await;

    let after_greeting: [(&[u8], u8); 5] = [
        // BIND
        (&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80], 7),
        // 不认识的地址类型
        (&[5, 1, 0, 2, 1, 2, 3, 4, 0, 80], 8),
        // 保留字节不是 0
        (&[5, 1, 7, 1, 1, 2, 3, 4, 0, 80], 1),
        // 域名里有空格
        (&[5, 1, 0, 3, 3, b'a', b' ', b'b', 0, 80], 1),
        // 空域名
        (&[5, 1, 0, 3, 0, 0, 80], 1),
    ];
    for (request, code) in after_greeting {
        let mut stream = TcpStream::connect(socks).await.unwrap();
        exchange(&mut stream, &[5, 1, 0], &[5, 0]).await;
        exchange(&mut stream, request, &[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        assert_closed(&mut stream).await;
    }

    // 客户端只会 GSSAPI：没有可用的认证方法。
    let mut stream = TcpStream::connect(socks).await.unwrap();
    exchange(&mut stream, &[5, 1, 1], &[5, 0xff]).await;
    assert_closed(&mut stream).await;

    // 根本不是 SOCKS5：什么都不回。
    for garbage in [&[4, 1, 0, 80, 1, 2, 3, 4, 0][..], b"GET / HTTP/1.1\r\n\r\n", &[5, 0]] {
        let mut stream = TcpStream::connect(socks).await.unwrap();
        stream.write_all(garbage).await.unwrap();
        assert_closed(&mut stream).await;
    }

    // 代理的出口不在 netmap 里：0x02，和访问规则不允许是同一个应答。组网目标照样能去。
    let elsewhere = world.proxy(2).await;
    assert_eq!(socks5_connect(elsewhere, "example.com", 443).await.0, 2);
    world.assert_no_open();
    assert_eq!(socks5_connect(elsewhere, "gw.home.i3t", 22).await.0, 0, "组网目标不经出口");
    assert_eq!(world.next_open().await.target, Target::Node { port: 22 });
}

#[tokio::test]
async fn unsupported_and_malformed_http_requests_get_the_right_status() {
    let mut netmap = netmap();
    let mut not_an_exit = proxy(2, ListenerProtocol::Http, "127.0.0.1:0");
    not_an_exit.exit = node(9);
    netmap.me.proxies = vec![proxy(1, ListenerProtocol::Http, "127.0.0.1:0"), not_an_exit];
    let mut world = World::start(netmap).await;
    let (http, elsewhere) = (world.proxy(1).await, world.proxy(2).await);

    let oversized = format!("CONNECT example.com:443 HTTP/1.1\r\nX-Padding: {}\r\n\r\n", "a".repeat(40_000));
    let cases = [
        ("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "400 Bad Request"),
        ("GET https://example.com/ HTTP/1.1\r\n\r\n", "501 Not Implemented"),
        ("POST http://example.com/ HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n", "400 Bad Request"),
        ("POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", "400 Bad Request"),
        ("CONNECT example.com HTTP/1.1\r\n\r\n", "400 Bad Request"),
        ("CONNECT example.com:443 HTTP/3\r\n\r\n", "400 Bad Request"),
        ("\x05\x01\x00 this is not http\r\n\r\n", "400 Bad Request"),
        (oversized.as_str(), "431 Request Header Fields Too Large"),
    ];
    // 代理的出口节点不在 netmap 里。
    let refused = [("CONNECT example.com:443 HTTP/1.1\r\n\r\n", "403 Forbidden")];
    for (proxy, (request, status)) in cases.into_iter().map(|case| (http, case)).chain(refused.into_iter().map(|case| (elsewhere, case))) {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        // 超长的请求头写到一半代理就可能已经应答并关掉连接了。
        let _ = stream.write_all(request.as_bytes()).await;
        let mut answer = Vec::new();
        let _ = timeout(PATIENCE, stream.read_to_end(&mut answer)).await.expect("代理应该应答并关掉连接");
        let answer = String::from_utf8(answer).unwrap();
        assert!(answer.starts_with(&format!("HTTP/1.1 {status}\r\n")), "{request:?} → {answer:?}");
    }
    world.assert_no_open();
}

#[tokio::test]
async fn the_local_mesh_entry_reaches_only_nodes_and_asks_for_no_password() {
    let local = |name: &str, protocol| LocalEntry { name: name.to_owned(), bind: "127.0.0.1:0".parse().unwrap(), protocol };
    let entries = vec![local("local-socks5", ListenerProtocol::Socks5), local("local-http", ListenerProtocol::Http)];
    let mut world = World::start_with(netmap(), |access| access.with_local_entries(entries)).await;
    let (socks, http) = (world.local_entry("local-socks5").await, world.local_entry("local-http").await);

    // 组网里的节点：握手、首批数据和应答一次写出去，多读进来的数据不能丢。
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream.write_all(&[5, 1, 0, 5, 1, 0, 1, 10, 66, 0, 2, 0, 22]).await.unwrap();
    let mut answer = [0; 12];
    timeout(PATIENCE, stream.read_exact(&mut answer)).await.unwrap().unwrap();
    assert_eq!(answer, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_echo(&mut stream).await;
    assert_eq!(world.next_open().await.target, Target::Node { port: 22 });
    let answer = plain_http(http, b"GET http://gw.home.i3t/x HTTP/1.1\r\n\r\n").await;
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n") && answer.contains("GET /x HTTP/1.1\r\nHost: gw.home.i3t\r\n"), "{answer:?}");
    assert_eq!(world.next_open().await.target, Target::Node { port: 80 });

    // 不在组网里的目标：没有出口，拒绝。用户名里写出口也不行。
    assert_eq!(socks5_connect(socks, "example.com", 443).await.0, 2);
    assert_eq!(socks5_login(socks, "gw", "", "192.168.1.10", 80).await.unwrap().0, 2);
    let answer = plain_http(http, b"GET http://example.com/ HTTP/1.1\r\n\r\n").await;
    assert!(answer.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{answer:?}");
    world.assert_no_open();
    let status = world.settled().await;
    assert!(status.proxies.is_empty());
    assert_eq!(status.local.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>(), ["local-socks5", "local-http"]);
}

i3t_lane::on_both_transports! {
    async fn stopping_the_manager_closes_the_listeners_and_leaves_connections_alone() {
        let mut netmap = netmap();
        netmap.me.proxies = vec![proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0")];
        let world = World::start(netmap).await;
        let socks = world.proxy(1).await;
        let (code, mut established) = socks5_connect(socks, "example.com", 443).await;
        assert_eq!(code, 0);
        assert_echo(&mut established).await;

        let manager = world.manager;
        manager.abort();
        // 任务是被取消的，它的结果只会是"已取消"。
        let _ = manager.await;

        // 接受连接的任务随后被取消，监听的 socket 跟着关掉。
        let refused = timeout(PATIENCE, async {
            loop {
                match TcpStream::connect(socks).await {
                    Ok(_) => sleep(Duration::from_millis(2)).await,
                    Err(error) => break error,
                }
            }
        })
        .await
        .expect("监听应该很快关掉");
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
        assert_echo(&mut established).await;
    }
}

/// 一个记在内存里的端口簿，代替装配层存在状态目录里的那一份。克隆出来的是同一本。
#[derive(Clone, Default)]
struct MemoryPortBook {
    ports: Arc<Mutex<std::collections::HashMap<u32, u16>>>,
}

impl PortBook for MemoryPortBook {
    fn port(&self, forward: u32) -> Option<u16> {
        self.ports.lock().unwrap().get(&forward).copied()
    }

    fn remember(&self, forward: u32, port: u16) {
        self.ports.lock().unwrap().insert(forward, port);
    }
}

/// 别的程序占着一个端口最多等多久。占着的通常是同一台机器上并行跑的别的测试，它结束了就让出来；
/// 机器很忙时一个测试要跑十几秒。
const HELD_ELSEWHERE: Duration = Duration::from_secs(30);

impl World {
    /// 等端口转发 `id` 监听在 `expected` 上。
    ///
    /// 挑定的端口空着的那一会儿（重启的间隙），别的程序可能正好绑上它：同一台机器上并行跑的测试一直在让系统挑端口，
    /// 挑中刚空出来的这一个并不稀奇。入口答应的是这时报"端口被占用"、不换端口，等它让出来再绑回去，
    /// 所以这期间只许看到这两种状态。入口每 10 秒重试一次绑不上的监听；这里看到"端口被占用"就把 netmap 的版本加一，
    /// 让它马上重试，不用干等。
    async fn listening_again(&self, id: u32, expected: SocketAddr) {
        timeout(HELD_ELSEWHERE, async {
            loop {
                let status = self.settled().await;
                match &status.forwards.iter().find(|forward| forward.id == id).unwrap().state {
                    ListenState::Listening { local } => {
                        assert_eq!(*local, expected, "端口转发 {id} 换了端口");
                        return;
                    }
                    ListenState::PortInUse { .. } => {
                        sleep(Duration::from_millis(20)).await;
                        self.update(|_| {}).await;
                    }
                    other => panic!("端口转发 {id} 应该监听在 {expected}，或者在等别人让出这个端口：{other:?}"),
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("端口 {expected} 一直被别的程序占着"));
    }
}

/// 替"别的程序"占住 `addr`。刚空出来的端口可能正被别人占着（见 [`World::listening_again`]），那就等它让出来。
async fn squat(addr: SocketAddr) -> TcpListener {
    timeout(HELD_ELSEWHERE, async {
        loop {
            match TcpListener::bind(addr).await {
                Ok(listener) => break listener,
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => sleep(Duration::from_millis(20)).await,
                Err(error) => panic!("占不了 {addr}：{error}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("端口 {addr} 一直被别的程序占着"))
}

#[tokio::test]
async fn a_forward_on_port_zero_gets_a_port_that_survives_a_restart() {
    let book = MemoryPortBook::default();
    let mut map = netmap();
    map.me.forwards = vec![forward(7, ForwardProtocol::Tcp, "127.0.0.1:0"), forward(8, ForwardProtocol::Udp, "127.0.0.1:0")];
    let first = World::start_with(map.clone(), |access| access.with_port_book(Arc::new(book.clone()))).await;
    let (tcp, udp) = (first.forward(7).await, first.forward(8).await);
    assert_ne!(tcp.port(), 0);
    assert_eq!(book.port(7), Some(tcp.port()), "挑定的端口记下来了");
    assert_eq!(book.port(8), Some(udp.port()));
    let mut stream = TcpStream::connect(tcp).await.unwrap();
    assert_echo(&mut stream).await;
    drop(stream);
    first.manager.abort();
    let _ = first.manager.await;

    // 像重启那样从头开一个入口：还是同一个端口。
    let second = World::start_with(map.clone(), |access| access.with_port_book(Arc::new(book.clone()))).await;
    second.listening_again(7, tcp).await;
    second.listening_again(8, udp).await;
    second.manager.abort();
    let _ = second.manager.await;

    // 记着的端口被别的程序占了：不换端口，照实报"端口被占用"；让出来之后绑回同一个端口。
    let squatter = squat(tcp).await;
    let third = World::start_with(map, |access| access.with_port_book(Arc::new(book.clone()))).await;
    let status = third.settled().await;
    assert!(matches!(&status.forwards[0].state, ListenState::PortInUse { .. }), "{:?}", status.forwards[0].state);
    drop(squatter);
    third.listening_again(7, tcp).await;
}

#[tokio::test]
async fn a_port_already_taken_by_another_program_is_reported_as_in_use() {
    let squatter = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taken = squatter.local_addr().unwrap();
    let mut map = netmap();
    map.me.forwards = vec![forward(7, ForwardProtocol::Tcp, &taken.to_string())];
    map.me.proxies = vec![proxy(1, ListenerProtocol::Mixed, &taken.to_string())];
    let world = World::start(map).await;
    let status = world.settled().await;
    assert!(matches!(&status.forwards[0].state, ListenState::PortInUse { reason } if !reason.is_empty()), "{:?}", status.forwards[0].state);
    assert!(matches!(&status.proxies[0].state, ListenState::PortInUse { .. }), "{:?}", status.proxies[0].state);
    drop(squatter);
}

#[tokio::test]
async fn an_address_not_on_this_machine_is_reported_with_its_kind() {
    let mut map = netmap();
    // 192.0.2.0/24 是文档用的地址段，不会在测试机的网卡上。
    map.me.proxies = vec![proxy(1, ListenerProtocol::Socks5, "192.0.2.1:1080")];
    let world = World::start(map).await;
    let status = world.settled().await;
    assert!(
        matches!(&status.proxies[0].state, ListenState::Failed { reason, cause: ListenCause::AddressNotAvailable } if !reason.is_empty()),
        "{:?}",
        status.proxies[0].state
    );
}

i3t_lane::on_both_transports! {
    async fn while_draining_proxies_answer_with_a_proxy_error_forwards_are_reset_and_listeners_stay_open() {
        let mut map = netmap();
        map.me.proxies = vec![proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0"), proxy(2, ListenerProtocol::Http, "127.0.0.1:0")];
        map.me.forwards = vec![forward(7, ForwardProtocol::Tcp, "127.0.0.1:0")];
        let mut world = World::start(map).await;
        let (socks, http, forwarded) = (world.proxy(1).await, world.proxy(2).await, world.forward(7).await);
        let (code, mut established) = socks5_connect(socks, "example.com", 443).await;
        assert_eq!(code, 0);
        world.next_open().await;

        world.access.set_draining(Some("准备更新到 0.2.0".to_owned()));
        assert!(world.access.is_draining());
        assert_eq!(socks5_connect(socks, "example.com", 443).await.0, 1, "SOCKS5 回 0x01：一般性失败，换一个或者稍后再试");
        let mut stream = TcpStream::connect(http).await.unwrap();
        stream.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic Z3c6\r\n\r\n").await.unwrap();
        let mut answer = Vec::new();
        let _ = timeout(PATIENCE, stream.read_to_end(&mut answer)).await.unwrap();
        let answer = String::from_utf8(answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 503 Service Unavailable\r\n") && answer.contains("Retry-After: "), "{answer:?}");
        let mut forwarded_stream = TcpStream::connect(forwarded).await.unwrap();
        let end = timeout(PATIENCE, forwarded_stream.read_to_end(&mut Vec::new())).await.unwrap();
        assert_eq!(end.unwrap_err().kind(), io::ErrorKind::ConnectionReset, "端口转发没有地方回错误，连接被重置");
        world.assert_no_open();
        assert_eq!(world.access.drained(), 3);
        let status = world.settled().await;
        assert!(matches!(status.proxies[0].state, ListenState::Listening { .. }), "排空不关监听");
        assert_echo(&mut established).await;

        world.access.set_draining(None);
        assert_eq!(socks5_connect(socks, "example.com", 443).await.0, 0, "撤回之后照常接");
    }
}

i3t_lane::on_both_transports! {
    async fn a_mixed_port_tells_socks5_from_http_by_the_first_byte_and_checks_the_password_on_both() {
        let mut map = netmap();
        map.me.proxies = vec![guarded(1, ListenerProtocol::Mixed, "127.0.0.1:0", "alice", "s3cret")];
        let mut world = World::start(map).await;
        let mixed = world.proxy(1).await;

        let (code, mut stream) = socks5_login(mixed, "alice", "s3cret", "example.com", 443).await.unwrap();
        assert_eq!(code, 0);
        assert_echo(&mut stream).await;
        drop(stream);
        world.next_open().await;

        let connect = |auth: &str| format!("CONNECT example.com:443 HTTP/1.1\r\n{auth}\r\n");
        let mut stream = TcpStream::connect(mixed).await.unwrap();
        exchange(&mut stream, connect(&basic("alice:s3cret")).as_bytes(), b"HTTP/1.1 200 Connection established\r\n\r\n").await;
        assert_echo(&mut stream).await;
        drop(stream);
        world.next_open().await;
        let answer = plain_http(mixed, format!("GET http://example.com/x HTTP/1.1\r\n{}\r\n", basic("alice:s3cret")).as_bytes()).await;
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer:?}");
        assert_eq!(world.next_open().await.target, internet("example.com", 80));

        // 错的和没有带的：HTTP 回 407，SOCKS5 认证不过。
        for auth in [basic("alice:wrong"), basic("alice"), String::new()] {
            let answer = plain_http(mixed, connect(&auth).as_bytes()).await;
            assert!(answer.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic"), "{auth:?} → {answer:?}");
        }
        assert!(socks5_login(mixed, "alice", "wrong", "example.com", 443).await.is_none());
        world.assert_no_open();

        // 流量和连接数按代理记。
        let status = world.settled().await;
        let traffic = &status.proxies[0].traffic;
        assert!(traffic.up() >= 42 && traffic.down() >= 42, "{} {}", traffic.up(), traffic.down());
        timeout(PATIENCE, async {
            while world.access.status().proxies[0].active.get() != 0 {
                sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("连接都结束了");
    }
}

i3t_lane::on_both_transports! {
    async fn classes_come_from_the_proxy_the_exit_and_the_network_in_that_order() {
        let mut map = netmap();
        let mut socks = proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0");
        socks.class = Some(Class::Reliable);
        map.me.proxies = vec![socks, proxy(2, ListenerProtocol::Socks5, "127.0.0.1:0")];
        let mut tagged = forward(7, ForwardProtocol::Tcp, "127.0.0.1:0");
        tagged.class = Some(Class::Interactive);
        map.me.forwards = vec![tagged, forward(8, ForwardProtocol::Tcp, "127.0.0.1:0")];
        map.peers[0].exit = Some(PeerExit { lan: true, class: Some(Class::Bulk), optimistic: None });
        map.network.class = Some(Class::Interactive);
        let mut world = World::start(map).await;
        let (socks, plain) = (world.proxy(1).await, world.proxy(2).await);

        async fn class_of(world: &mut World, proxy: SocketAddr, host: &str) -> Class {
            let (_code, _stream) = socks5_connect(proxy, host, 443).await;
            world.next_open().await.class
        }
        assert_eq!(class_of(&mut world, socks, "example.com").await, Class::Reliable, "先看代理");
        assert_eq!(class_of(&mut world, socks, "10.66.0.2").await, Class::Reliable, "不经出口的流也看代理");
        assert_eq!(class_of(&mut world, plain, "example.com").await, Class::Bulk, "再看出口的默认值");
        assert_eq!(class_of(&mut world, plain, "10.66.0.2").await, Class::Interactive, "不经出口时是网络的默认值");

        let mut stream = TcpStream::connect(world.forward(7).await).await.unwrap();
        assert_echo(&mut stream).await;
        assert_eq!(world.next_open().await.class, Class::Interactive, "端口转发自己的设置");
        world.update(|netmap| netmap.network.class = Some(Class::Reliable)).await;
        let mut stream = TcpStream::connect(world.forward(8).await).await.unwrap();
        assert_echo(&mut stream).await;
        assert_eq!(world.next_open().await.class, Class::Reliable, "端口转发没有设置时用网络的默认值");
    }
}

i3t_lane::on_both_transports! {
    async fn a_proxy_can_turn_the_optimistic_reply_off_so_clients_see_precise_errors() {
        let mut map = netmap();
        let mut careful = proxy(2, ListenerProtocol::Socks5, "127.0.0.1:0");
        careful.optimistic = Some(false);
        map.me.proxies = vec![proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0"), careful];
        let mut world = World::start(map).await;
        let (socks, careful) = (world.proxy(1).await, world.proxy(2).await);

        let (code, mut stream) = socks5_connect(socks, "example.com", 9).await;
        assert_eq!(code, 0, "互联网目标默认不等应答：先说连上了");
        world.next_open().await;
        let end = timeout(PATIENCE, stream.read_to_end(&mut Vec::new())).await.unwrap();
        assert_eq!(end.unwrap_err().kind(), io::ErrorKind::ConnectionReset, "之后的失败只能表现为被重置");

        let (code, _stream) = socks5_connect(careful, "example.com", 9).await;
        assert_eq!(code, 5, "关掉乐观回复之后客户端拿到准确的 0x05（连接被拒绝）");
        world.next_open().await;

        let usage = world.access.exit_usage();
        assert_eq!(usage.len(), 1);
        assert_eq!((usage[0].exit, usage[0].flows, usage[0].failed_by_target), (node(GW), 2, 2), "两次都是目标的问题");

        // 出口也可以关掉乐观回复；代理自己设了的以代理为准。
        world.update(|netmap| netmap.peers[0].exit.as_mut().unwrap().optimistic = Some(false)).await;
        let (code, _stream) = socks5_connect(socks, "example.com", 9).await;
        assert_eq!(code, 5, "出口关掉了乐观回复：这个没有设的代理也等应答");
        world.next_open().await;
        world.update(|netmap| netmap.me.proxies[1].optimistic = Some(true)).await;
        let (code, _stream) = socks5_connect(world.proxy(2).await, "example.com", 9).await;
        assert_eq!(code, 0, "代理打开了乐观回复，盖过出口的");
        world.next_open().await;
    }
}

i3t_lane::on_both_transports! {
    async fn a_proxy_closes_active_flows_when_the_peer_identity_is_revoked() {
        for remove_peer in [false, true] {
            let mut map = netmap();
            map.peers[0].lane = LaneMode::Always;
            let mut careful = proxy(2, ListenerProtocol::Socks5, "127.0.0.1:0");
            careful.optimistic = Some(false);
            map.me.proxies = vec![proxy(1, ListenerProtocol::Socks5, "127.0.0.1:0"), careful];
            let world = World::start(map).await;
            let (optimistic_code, mut optimistic) = socks5_connect(world.proxy(1).await, "example.com", 443).await;
            let (careful_code, mut careful) = socks5_connect(world.proxy(2).await, "example.com", 443).await;
            assert_eq!((optimistic_code, careful_code), (0, 0));
            assert_echo(&mut optimistic).await;
            assert_echo(&mut careful).await;

            world.update(|map| map.peers[0].lane = LaneMode::Off).await;
            assert_echo(&mut optimistic).await;
            assert_echo(&mut careful).await;

            world
                .update(|map| {
                    if remove_peer {
                        map.peers.clear();
                    } else {
                        map.peers[0].key = PublicKey::from_bytes([3; 32]);
                    }
                })
                .await;
            assert_closed(&mut optimistic).await;
            assert_closed(&mut careful).await;
        }
    }
}

/// 把一个明文 HTTP 请求发给代理，读到连接结束，返回读到的全部。
async fn plain_http(proxy: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut answer = Vec::new();
    // 代理在应答之后关连接，正常关和重置都算结束。
    let _ = timeout(PATIENCE, stream.read_to_end(&mut answer)).await.expect("代理应该回完应答并关掉连接");
    String::from_utf8(answer).unwrap()
}

fn basic(credentials: &str) -> String {
    format!("Proxy-Authorization: Basic {}\r\n", STANDARD.encode(credentials))
}

i3t_lane::on_both_transports! {
    async fn a_plain_http_request_is_forwarded_with_a_clean_head_and_nothing_after_it() {
        let mut netmap = netmap();
        netmap.me.proxies = vec![proxy(1, ListenerProtocol::Http, "127.0.0.1:0")];
        netmap.me.proxies[0].class = Some(Class::Interactive);
        let mut world = World::start(netmap).await;
        let http = world.proxy(1).await;

        // 流水线里排在后面的请求（带着别的用户名和密码）不能到目标那里去。
        let request = format!(
            "GET http://example.com/index.html?q=1 HTTP/1.1\r\nHost: example.com\r\n{}Proxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n\
             GET http://example.com/second HTTP/1.1\r\n{}\r\n",
            basic("someone:"),
            basic("gw:other")
        );
        let answer = plain_http(http, request.as_bytes()).await;
        let expected = "GET /index.html?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        assert_eq!(answer, format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{expected}", expected.len()));
        assert_eq!(world.next_open().await, Open { target: internet("example.com", 80), class: Class::Interactive, origin: Origin::default() });
        world.assert_no_open();
    }
}

i3t_lane::on_both_transports! {
    async fn plain_http_bodies_arrive_whole_by_length_by_chunks_and_after_100_continue() {
        let mut netmap = netmap();
        netmap.me.proxies = vec![guarded(1, ListenerProtocol::Mixed, "127.0.0.1:0", "u", "p")];
        let mut world = World::start(netmap).await;
        let http = world.proxy(1).await;
        let auth = basic("u:p");

        let answer = plain_http(http, format!("POST http://example.com/form HTTP/1.1\r\n{auth}Content-Length: 11\r\n\r\nhello worldEXTRA").as_bytes()).await;
        assert!(answer.ends_with("Content-Length: 11\r\nConnection: close\r\n\r\nhello world"), "{answer:?}");

        let chunks = "4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\nX-Sum: 9\r\n\r\n";
        let answer = plain_http(http, format!("PUT http://example.com/ HTTP/1.1\r\n{auth}Transfer-Encoding: chunked\r\n\r\n{chunks}").as_bytes()).await;
        assert!(answer.ends_with(&format!("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{chunks}")), "{answer:?}");

        // 客户端等到 100 才发请求体。
        let mut stream = TcpStream::connect(http).await.unwrap();
        let head = format!("POST http://example.com/big HTTP/1.1\r\n{auth}Content-Length: 70000\r\nExpect: 100-continue\r\n\r\n");
        exchange(&mut stream, head.as_bytes(), b"HTTP/1.1 100 Continue\r\n\r\n").await;
        let body = vec![b'b'; 70_000];
        for part in body.chunks(7000) {
            stream.write_all(part).await.unwrap();
        }
        let mut answer = Vec::new();
        timeout(PATIENCE, stream.read_to_end(&mut answer)).await.expect("应答应该回来").unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 200 OK\r\n") && answer.ends_with(&body), "{:?}", String::from_utf8_lossy(&answer[..200]));

        for _ in 0..3 {
            assert_eq!(world.next_open().await.target, internet("example.com", 80));
        }
    }
}

#[tokio::test]
async fn a_refused_plain_http_request_gets_a_status_code() {
    let mut netmap = netmap();
    let mut elsewhere = proxy(2, ListenerProtocol::Http, "127.0.0.1:0");
    elsewhere.exit = node(9);
    netmap.me.proxies = vec![proxy(1, ListenerProtocol::Http, "127.0.0.1:0"), elsewhere];
    // 就算代理要求乐观回复，明文 HTTP 也等对端的 REPLY：客户端拿到的是状态码，不是断开。
    netmap.me.proxies[0].optimistic = Some(true);
    let mut world = World::start(netmap).await;

    let answer = plain_http(world.proxy(1).await, b"GET http://example.com:9/ HTTP/1.1\r\n\r\n").await;
    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{answer:?}");
    assert_eq!(world.next_open().await.target, internet("example.com", 9));

    // 代理的出口不在 netmap 里。
    let answer = plain_http(world.proxy(2).await, b"GET http://example.com/ HTTP/1.1\r\n\r\n").await;
    assert!(answer.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{answer:?}");
    world.assert_no_open();
}
