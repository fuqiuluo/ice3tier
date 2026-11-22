//! UDP 的入口在真的 socket 上的行为。对端节点是一个记下它收到了什么、然后原样回显的替身。
//!
//! 入口加真的出口的端到端测试在 `i3t-exit` 的 `tests/datagrams.rs` 里。

// clippy.toml 里的 allow-unwrap-in-tests 只管 #[test] 函数，管不到集成测试里的辅助函数。这里 unwrap 失败就是测试失败。
#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use i3t_access::{Access, ListenState, LocalEntry};
use i3t_conn::contract::DatagramSender;
use i3t_conn::{RecvStream, SendStream};
use i3t_flow::memory::{MemoryConnector, MemoryMesh};
use i3t_flow::{Handler, Request, datagram};
use i3t_model::Netmap;
use i3t_model::netmap::{Forward, ForwardProtocol, LaneMode, ListenerProtocol, LocalNode, Network, Peer, PeerExit, Proxy, Verifier};
use i3t_proto::flow::{Class, OpenDatagrams, Reply, Status, Target};
use i3t_proto::{NodeId, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};

const ME: u32 = 1;
const GW: u32 = 2;
const PATIENCE: Duration = Duration::from_secs(5);
/// 断言"这件事不会发生"时观察多久。
const QUIET: Duration = Duration::from_millis(200);

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
            ack_eliciting_threshold: 3,
            max_ack_delay_ms: 2,
            bundle_small_packets: true,
            vnet_offload: true,
            vnet_mtu: 1280,
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

/// 经 `gw` 出去、不认证的 SOCKS5 代理。
fn socks(id: u32) -> Proxy {
    Proxy {
        id,
        name: format!("p{id}"),
        bind: "127.0.0.1:0".parse().unwrap(),
        protocol: ListenerProtocol::Socks5,
        exit: node(GW),
        auth: None,
        allow_from: Vec::new(),
        class: None,
        optimistic: None,
        lane: false,
    }
}

/// 对端节点的替身：答应每个数据报上下文，记下 OPEN 和每个数据报的目标，把数据报原样发回去（来源就写它的目标）。
struct EchoPeer {
    opens: mpsc::UnboundedSender<OpenDatagrams>,
    targets: mpsc::UnboundedSender<Target>,
}

impl Handler for EchoPeer {
    async fn handle<S: SendStream, R: RecvStream>(&self, request: Request<S, R>) {
        request.refuse(&Reply::new(Status::InternalError, "这个替身只接受数据报上下文")).await;
    }

    async fn handle_datagrams<S: SendStream, R: RecvStream, T: DatagramSender>(&self, request: datagram::Request<S, R, T>) {
        assert_eq!(request.peer(), node(ME));
        self.opens.send(request.open().clone()).unwrap();
        let mut context = request.accept().await.unwrap();
        let sender = context.sender();
        while let Ok(received) = context.recv().await {
            self.targets.send(received.target.clone()).unwrap();
            sender.send(&received.target, &received.payload).await.unwrap();
        }
    }
}

/// 一个跑着的入口，对面是 [`EchoPeer`]。
struct World {
    netmap: watch::Sender<Arc<Netmap>>,
    access: Arc<Access<MemoryConnector>>,
    /// 对端收到的数据报上下文的 OPEN，按到达的顺序。
    opens: mpsc::UnboundedReceiver<OpenDatagrams>,
    /// 对端收到的每个数据报的目标，按到达的顺序。
    targets: mpsc::UnboundedReceiver<Target>,
}

impl World {
    /// UDP 端口转发的会话空闲 0.3 秒就回收，测试不用真的等一分钟。
    async fn start(netmap: Netmap) -> Self {
        Self::start_with(netmap, Duration::from_millis(300), Vec::new()).await
    }

    async fn start_with(netmap: Netmap, udp_idle: Duration, local: Vec<LocalEntry>) -> Self {
        let mesh = MemoryMesh::new();
        let (connector, _) = mesh.join(node(ME));
        let (_, acceptor) = mesh.join(node(GW));
        let (opens_sender, opens) = mpsc::unbounded_channel();
        let (targets_sender, targets) = mpsc::unbounded_channel();
        let peer = Arc::new(EchoPeer { opens: opens_sender, targets: targets_sender });
        tokio::spawn(async move { i3t_flow::serve(&acceptor, peer).await });

        let (sender, receiver) = watch::channel(Arc::new(netmap));
        let access = Arc::new(Access::new(Arc::new(connector), receiver).with_udp_idle_timeout(udp_idle).with_local_entries(local));
        tokio::spawn({
            let access = Arc::clone(&access);
            async move { access.run().await }
        });
        let world = Self { netmap: sender, access, opens, targets };
        world.settled().await;
        world
    }

    async fn settled(&self) {
        let version = self.netmap.borrow().version;
        timeout(PATIENCE, async {
            while self.access.status().version != version {
                sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("入口应该很快应用完新的 netmap");
    }

    fn proxy(&self, id: u32) -> SocketAddr {
        local(&self.access.status().proxies.iter().find(|proxy| proxy.id == id).unwrap().state)
    }

    fn forward(&self, id: u32) -> SocketAddr {
        local(&self.access.status().forwards.iter().find(|forward| forward.id == id).unwrap().state)
    }

    fn sessions(&self, id: u32) -> usize {
        self.access.status().forwards.iter().find(|forward| forward.id == id).unwrap().active.get()
    }

    async fn next_open(&mut self) -> OpenDatagrams {
        timeout(PATIENCE, self.opens.recv()).await.expect("对端应该收到一个数据报上下文的 OPEN").unwrap()
    }

    async fn next_target(&mut self) -> Target {
        timeout(PATIENCE, self.targets.recv()).await.expect("对端应该收到一个数据报").unwrap()
    }
}

fn local(state: &ListenState) -> SocketAddr {
    match state {
        ListenState::Listening { local } => *local,
        other => panic!("监听没有起来：{other:?}"),
    }
}

/// 一个 SOCKS5 的 UDP 关联，测试扮演客户端。
struct Association {
    /// 那条 TCP 连接，留着它关联才在。
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

/// SOCKS5 握手（给了 `login` 时用户名密码认证，否则不认证）加 UDP ASSOCIATE。
async fn associate(proxy: SocketAddr, login: Option<(&str, &str)>) -> Association {
    let mut control = TcpStream::connect(proxy).await.unwrap();
    let (greeting, expected): (Vec<u8>, &[u8]) = match login {
        Some((username, password)) => {
            let auth = [
                &[5, 1, 2, 1, u8::try_from(username.len()).unwrap()][..],
                username.as_bytes(),
                &[u8::try_from(password.len()).unwrap()],
                password.as_bytes(),
            ];
            (auth.concat(), &[5, 2, 1, 0])
        }
        None => (vec![5, 1, 0], &[5, 0]),
    };
    control.write_all(&[&greeting[..], &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]].concat()).await.unwrap();
    let mut answer = vec![0; expected.len() + 10];
    timeout(PATIENCE, control.read_exact(&mut answer)).await.expect("代理应该应答").unwrap();
    let (head, reply) = answer.split_at(expected.len());
    assert_eq!((head, &reply[..4]), (expected, &[5, 0, 0, 1][..]), "认证通过，答应 UDP ASSOCIATE");
    let relay = SocketAddr::from(([reply[4], reply[5], reply[6], reply[7]], u16::from_be_bytes([reply[8], reply[9]])));
    Association { _control: control, socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(), relay }
}

impl Association {
    /// 发一个报文。`address` 是 SOCKS5 头里"地址类型、地址、端口"那一段。
    async fn send(&self, address: &[u8], data: &[u8]) {
        self.socket.send_to(&[&[0, 0, 0][..], address, data].concat(), self.relay).await.unwrap();
    }

    /// 等中继端口发回来的下一个报文：头里"地址类型、地址、端口"那一段有 `address_len` 字节，返回它和数据。
    async fn recv(&self, address_len: usize) -> (Vec<u8>, Vec<u8>) {
        let mut buf = vec![0; 2048];
        let (len, from) = timeout(PATIENCE, self.socket.recv_from(&mut buf)).await.expect("中继端口应该发回一个报文").unwrap();
        assert_eq!((from, &buf[..3]), (self.relay, &[0, 0, 0][..]));
        (buf[3..3 + address_len].to_vec(), buf[3 + address_len..len].to_vec())
    }

    async fn assert_silent(&self) {
        let mut buf = [0; 16];
        assert!(timeout(QUIET, self.socket.recv_from(&mut buf)).await.is_err(), "中继端口不应该发回报文");
    }
}

fn domain(name: &str, port: u16) -> Vec<u8> {
    [&[3, u8::try_from(name.len()).unwrap()][..], name.as_bytes(), &port.to_be_bytes()].concat()
}

#[tokio::test]
async fn an_association_is_one_context_per_peer_carrying_the_class_the_origin_and_each_datagrams_own_target() {
    let mut netmap = netmap();
    let mut proxy = socks(1);
    proxy.auth = Some(Verifier::derive([1; 16], b"alice", b"s3cret"));
    proxy.class = Some(Class::Reliable);
    netmap.me.proxies = vec![proxy];
    let mut world = World::start(netmap).await;
    let client = associate(world.proxy(1), Some(("alice", "s3cret"))).await;

    // 四种目标：公网地址、域名、出口背后局域网里的地址、节点自己的服务（组网地址）。
    let public = [1, 93, 184, 216, 34, 0x01, 0xbb];
    let name = domain("example.com", 53);
    let lan = [1, 192, 168, 1, 10, 0, 161];
    let service = [1, 10, 66, 0, 2, 0x14, 0xe9];
    for address in [&public[..], &name, &lan, &service] {
        client.send(address, b"payload").await;
        // 回来的报文带着同样的地址：替身把目标当来源回显，节点自己的服务报成它的虚拟 IP。
        assert_eq!(client.recv(address.len()).await, (address.to_vec(), b"payload".to_vec()));
    }
    let expected = [
        Target::Internet { host: "93.184.216.34".parse().unwrap(), port: 443 },
        Target::Internet { host: "example.com".parse().unwrap(), port: 53 },
        Target::Lan { addr: "192.168.1.10:161".parse().unwrap() },
        Target::Node { port: 5353 },
    ];
    for target in expected {
        assert_eq!(world.next_target().await, target);
    }

    // 都在同一个上下文里：等级来自代理的设置；客户端在回环上，它的地址不带。
    let open = world.next_open().await;
    assert_eq!((open.class, open.origin.credential.as_deref(), open.origin.client), (Class::Reliable, None, None));
    assert!(world.opens.try_recv().is_err(), "到同一个对端只开一个上下文");
}

#[tokio::test]
async fn where_a_datagram_goes_is_decided_like_a_connect_request() {
    let mut netmap = netmap();
    let mut elsewhere = socks(1);
    elsewhere.exit = node(9);
    netmap.me.proxies = vec![elsewhere, socks(2)];
    let mut world = World::start(netmap).await;
    let public = [1, 93, 184, 216, 34, 0x01, 0xbb];

    // 代理的出口不在 netmap 里：报文被丢掉，连上下文都不开。发往本节点自己的组网地址的也一样。
    let client = associate(world.proxy(1), None).await;
    client.send(&public, b"no such exit").await;
    client.send(&[1, 10, 66, 0, 1, 0, 53], b"myself").await;
    client.assert_silent().await;
    assert!(world.opens.try_recv().is_err());
    // 组网地址不经出口。
    client.send(&[1, 10, 66, 0, 2, 0, 53], b"a mesh service").await;
    assert_eq!(world.next_target().await, Target::Node { port: 53 });
    assert_eq!(world.next_open().await.class, Class::Auto);

    // 出口在的代理：从它出去。
    let client = associate(world.proxy(2), None).await;
    client.send(&public, b"via the exit").await;
    assert_eq!(world.next_target().await, Target::Internet { host: "93.184.216.34".parse().unwrap(), port: 443 });
    assert_eq!(client.recv(public.len()).await.1, b"via the exit");
}

#[tokio::test]
async fn the_local_mesh_entry_carries_datagrams_to_nodes_only() {
    let entry = LocalEntry { name: "local-socks5".into(), bind: "127.0.0.1:0".parse().unwrap(), protocol: ListenerProtocol::Socks5 };
    let mut world = World::start_with(netmap(), Duration::from_millis(300), vec![entry]).await;
    let status = world.access.status();
    let client = associate(local(&status.local[0].state), None).await;
    client.send(&[1, 93, 184, 216, 34, 0x01, 0xbb], b"outside the mesh").await;
    client.send(&domain("example.com", 53), b"outside the mesh").await;
    client.assert_silent().await;
    assert!(world.opens.try_recv().is_err(), "没有出口：不在组网里的目标一个上下文都不开");
    client.send(&[1, 10, 66, 0, 2, 0, 53], b"a mesh service").await;
    assert_eq!(world.next_target().await, Target::Node { port: 53 });
    assert_eq!(client.recv(7).await, (vec![1, 10, 66, 0, 2, 0, 53], b"a mesh service".to_vec()));
}

fn udp_forward(id: u32) -> Forward {
    Forward {
        id,
        protocol: ForwardProtocol::Udp,
        bind: "127.0.0.1:0".parse().unwrap(),
        target: node(GW),
        allow_from: Vec::new(),
        class: None,
    }
}

#[tokio::test]
async fn a_udp_forward_is_one_context_per_client_address_tagged_with_the_forward_id_and_expires_when_idle() {
    let mut netmap = netmap();
    netmap.me.forwards = vec![udp_forward(7)];
    let mut world = World::start(netmap).await;
    let listening = world.forward(7);
    let (first, second) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let mut buf = [0; 64];
    for (client, data) in [(&first, &b"one"[..]), (&second, b"two"), (&first, b"three")] {
        client.send_to(data, listening).await.unwrap();
        assert_eq!(world.next_target().await, Target::Forward { id: 7 });
        // 回来的报文是从监听的端口发回这个客户端的。
        let (len, from) = timeout(PATIENCE, client.recv_from(&mut buf)).await.expect("回显应该回到客户端").unwrap();
        assert_eq!((&buf[..len], from), (data, listening));
    }
    // 两个客户端地址，两个上下文；同一个客户端的第二个报文用的还是它的那一个。
    for _ in 0..2 {
        let open = world.next_open().await;
        assert_eq!((open.class, open.origin.client), (Class::Auto, None));
    }
    assert!(world.opens.try_recv().is_err());
    assert_eq!(world.sessions(7), 2);

    // 没有报文往来超过时限（测试里调成了 0.3 秒）：会话回收。之后再来的报文开一个新的上下文。
    timeout(PATIENCE, async {
        while world.sessions(7) != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("空闲的会话应该被回收");
    first.send_to(b"again", listening).await.unwrap();
    world.next_open().await;
    assert_eq!(world.next_target().await, Target::Forward { id: 7 });
}

#[tokio::test]
async fn a_udp_forward_refuses_sources_outside_its_allow_list_and_targets_it_may_not_reach() {
    let mut netmap = netmap();
    let mut guarded = udp_forward(8);
    guarded.allow_from = vec!["192.168.0.0/16".parse().unwrap()];
    let mut unreachable = udp_forward(9);
    unreachable.target = node(5);
    netmap.me.forwards = vec![guarded, unreachable];
    let mut world = World::start(netmap).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 来源（127.0.0.1）不在白名单里；目标节点不在 netmap 里。两种都是丢掉报文，不建会话。
    for id in [8, 9] {
        client.send_to(b"dropped", world.forward(id)).await.unwrap();
    }
    sleep(QUIET).await;
    assert!(world.opens.try_recv().is_err());
    assert_eq!((world.sessions(8), world.sessions(9)), (0, 0));

    // 白名单改了之后马上生效，不用重新绑定：监听的还是原来那个端口。
    let before = world.forward(8);
    let mut changed = Netmap::clone(&world.netmap.borrow());
    changed.me.forwards[0].allow_from = vec!["127.0.0.0/8".parse().unwrap()];
    changed.version += 1;
    world.netmap.send(Arc::new(changed)).unwrap();
    world.settled().await;
    assert_eq!(world.forward(8), before);
    client.send_to(b"now allowed", before).await.unwrap();
    assert_eq!(world.next_target().await, Target::Forward { id: 8 });
}

/// 一条转发同时最多这么多个会话，是目标节点给本节点的上下文名额（128）的一半。
const MAX_SESSIONS: usize = 64;

/// 回环以外的同一个来源在一条转发上最多这么多个会话。
const MAX_SESSIONS_PER_HOST: usize = 16;

/// 从 `ip` 上的 `count` 个不同端口各往 `to` 发一个报文，返回这些 socket（留着它们，会话才有人回）。
async fn clients_from(ip: IpAddr, count: usize, to: SocketAddr) -> Vec<UdpSocket> {
    let mut clients = Vec::new();
    for _ in 0..count {
        let client = UdpSocket::bind((ip, 0)).await.unwrap();
        client.send_to(b"x", to).await.unwrap();
        clients.push(client);
    }
    clients
}

/// 数一数对端又收到了几个数据报上下文的 OPEN，直到一阵子没有新的。
async fn count_opens(world: &mut World) -> usize {
    let mut opened = 0;
    while timeout(QUIET, world.opens.recv()).await.is_ok() {
        opened += 1;
    }
    opened
}

#[tokio::test]
async fn a_udp_forward_holds_a_bounded_number_of_sessions() {
    let mut netmap = netmap();
    netmap.me.forwards = vec![udp_forward(7)];
    // 空闲时限留成默认的 60 秒：这个测试里会话不能自己过期。
    let mut world = World::start_with(netmap, Duration::from_secs(60), Vec::new()).await;
    let listening = world.forward(7);

    // 回环上的来源不按来源限制：本机的程序每个请求换一个端口也照样用得上，直到整条转发的上限。
    let _clients = clients_from(IpAddr::from([127, 0, 0, 1]), MAX_SESSIONS + 1, listening).await;
    assert_eq!((count_opens(&mut world).await, world.sessions(7)), (MAX_SESSIONS, MAX_SESSIONS), "到了上限之后新的来源不再建会话");
}

#[tokio::test]
async fn one_host_on_the_network_cannot_take_a_whole_udp_forward() {
    let Some(lan) = non_loopback_address() else {
        eprintln!("这台机器没有非回环的地址，跳过");
        return;
    };
    let mut netmap = netmap();
    netmap.me.forwards = vec![Forward { bind: "0.0.0.0:0".parse().unwrap(), ..udp_forward(7) }];
    let mut world = World::start_with(netmap, Duration::from_secs(60), Vec::new()).await;
    let listening = SocketAddr::new(lan, world.forward(7).port());

    // 同一台主机换着来源端口发：只占得到它的那一份。
    let _from_one_host = clients_from(lan, MAX_SESSIONS_PER_HOST + 4, listening).await;
    assert_eq!(count_opens(&mut world).await, MAX_SESSIONS_PER_HOST);

    // 转发还有空位，别的来源照样建得起会话。
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    other.send_to(b"still room", SocketAddr::new([127, 0, 0, 1].into(), listening.port())).await.unwrap();
    assert_eq!(count_opens(&mut world).await, 1);
    assert_eq!(world.sessions(7), MAX_SESSIONS_PER_HOST + 1);
}

/// 这台机器的一个非回环 IPv4 地址；没有（只有回环网卡的环境）时是 `None`。
fn non_loopback_address() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // 不真的发包：connect 一个 UDP socket 只是让系统选出一个出口地址。
    socket.connect("192.0.2.1:9").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip()).filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
}
