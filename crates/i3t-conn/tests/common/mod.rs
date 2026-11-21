//! 数据面集成测试的公共部分：在一个进程里起几个节点，都绑在回环地址上，netmap 由测试直接给。

// 这个文件里全是测试用的辅助代码。clippy.toml 的 allow-unwrap-in-tests 只管 #[test] 函数本身，管不到它们调用的辅助函数。
#![allow(clippy::unwrap_used)]
// 每个测试文件各自编译这个模块，各用其中的一部分。
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use i3t_conn::{Acceptor, Connector, Direction, Endpoint, EndpointConfig, PacketFilter, PacketTransport, RecvHalf, SendHalf};
use i3t_crypto::NodeKey;
use i3t_model::Netmap;
use i3t_model::control::Route;
use i3t_proto::NodeId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// 等一件"应该很快发生"的事最多等多久。
pub const SOON: Duration = Duration::from_secs(10);

/// 设置环境变量 `I3T_TEST_LOG=debug`（或别的级别）可以看到节点的日志。
pub fn init_logging() {
    let Ok(level) = std::env::var("I3T_TEST_LOG") else { return };
    let level = level.parse().unwrap_or(tracing_subscriber::filter::LevelFilter::DEBUG);
    let _already_set = tracing_subscriber::fmt().with_max_level(level).with_test_writer().try_init();
}

/// 一个测试节点。
pub struct Node {
    pub id: NodeId,
    pub key: Arc<NodeKey>,
    pub endpoint: Arc<Endpoint>,
    netmap: watch::Sender<Arc<Netmap>>,
}

/// 某个节点的 netmap 里怎么写一个对端。
#[derive(Clone, Copy)]
pub struct Peer<'a> {
    pub node: &'a Node,
    /// 把对端真实的地址写进它的候选端点。不写的话只能靠信令或者对端先来探测才知道它在哪里。
    pub endpoints: bool,
    /// 对端挂靠的 relay。
    pub attached: &'a [&'a Node],
    pub keep_alive: bool,
    pub dial_out_only: bool,
    /// 这一对节点的拥塞控制（`"bbr"`、`"cubic"`）；不写就是节点的默认。
    pub congestion: Option<&'static str>,
}

impl<'a> Peer<'a> {
    /// 知道地址、没有挂靠任何 relay 的对端。
    pub fn direct(node: &'a Node) -> Self {
        Self { node, endpoints: true, attached: &[], keep_alive: false, dial_out_only: false, congestion: None }
    }

    /// 不知道地址、挂靠在 `relays` 上的对端。
    pub fn via(node: &'a Node, relays: &'a [&'a Node]) -> Self {
        Self { node, endpoints: false, attached: relays, keep_alive: false, dial_out_only: false, congestion: None }
    }

    /// 知道地址、也挂靠在 `relays` 上的对端。
    pub fn both(node: &'a Node, relays: &'a [&'a Node]) -> Self {
        Self { node, endpoints: true, attached: relays, keep_alive: false, dial_out_only: false, congestion: None }
    }
}

/// 一个节点的 netmap 里除了它自己之外的内容。
#[derive(Clone, Copy, Default)]
pub struct View<'a> {
    pub peers: &'a [Peer<'a>],
    /// 网络里的 relay。
    pub relays: &'a [&'a Node],
    /// 有值时本节点启用为 relay，值是允许建中转会话的节点。
    pub relay_clients: Option<&'a [&'a Node]>,
    /// 网络的 `reach` 设置：`"direct_only"`、`"relay_only"`，不写就是都可以。
    pub reach: Option<&'static str>,
    pub dial_out_only: bool,
    /// 网络的确认设置：对端攒到多于几个包才单独发确认，没攒够时最多等几毫秒。不写就是默认值。
    pub ack: Option<(u32, u32)>,
}

impl Node {
    /// 起一个节点，绑在回环地址的一个空闲端口上。一开始它的 netmap 里只有自己。
    pub fn start(id: u32) -> Self {
        Self::start_with(id, &[])
    }

    /// 同 [`Node::start`]，另外给它几个地址查询的服务器。
    pub fn start_with(id: u32, addr_servers: &[SocketAddr]) -> Self {
        Self::start_inner(id, Arc::new(NodeKey::generate().unwrap()), addr_servers, PacketTransport::Sealed)
    }

    /// 用一把已有的密钥起一个节点：同一个节点重启之后的样子（端口换了，身份还是它）。
    pub fn start_with_key(id: u32, key: Arc<NodeKey>) -> Self {
        Self::start_inner(id, key, &[], PacketTransport::Sealed)
    }

    /// 同 [`Node::start`]，只是网络包一律走连接的数据报：不认识封好的包的旧节点就是这样。
    pub fn start_datagram_only(id: u32) -> Self {
        Self::start_inner(id, Arc::new(NodeKey::generate().unwrap()), &[], PacketTransport::Datagram)
    }

    // 网络包怎么走写明在这里，不看环境变量：测试的结果不该跟着跑测试的环境变。
    fn start_inner(id: u32, key: Arc<NodeKey>, addr_servers: &[SocketAddr], packets: PacketTransport) -> Self {
        init_logging();
        let id = NodeId::new(id).unwrap();
        let (netmap, netmap_rx) = watch::channel(build_netmap(id, &View::default()));
        let config = |bind| EndpointConfig { key: Arc::clone(&key), bind, netmap: netmap_rx.clone(), addr_servers: addr_servers.to_vec() };
        // 节点启用为 relay 时要在同一个端口号上监听 TCP，所以挑一个 TCP 和 UDP 都空着的端口。两种挑法轮着来：
        // 系统分一个空闲的 TCP 端口、去绑同号的 UDP；或者系统分一个空闲的 UDP 端口、看同号的 TCP 绑不绑得上。
        // 只用前一种，Windows 上曾经一连 50 次都不成：那里 UDP 和 TCP 各有一些成段保留、不让绑的端口（`netsh int ipv4
        // show excludedportrange protocol=udp`，Hyper-V、WinNAT 占的），系统分给 TCP 的端口号可能接连落在 UDP 保留的那一段里。
        // 每一边的分配器都躲开自己那边保留的端口，轮着来就不会一直卡在同一段上。
        let mut last_error = String::new();
        for attempt in 0..100 {
            let bound = if attempt % 2 == 0 {
                let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                Endpoint::bind_with(config(probe.local_addr().unwrap()), packets).map_err(|error| format!("{error:?}"))
            } else {
                Endpoint::bind_with(config("127.0.0.1:0".parse().unwrap()), packets).map_err(|error| format!("{error:?}")).and_then(
                    |endpoint| match std::net::TcpListener::bind(endpoint.local_addr()) {
                        Ok(_) => Ok(endpoint),
                        Err(error) => Err(format!("TCP {}：{error}", endpoint.local_addr())),
                    },
                )
            };
            match bound {
                Ok(endpoint) => return Self { id, key, endpoint: Arc::new(endpoint), netmap },
                Err(error) => last_error = error,
            }
        }
        panic!("找不到 TCP 和 UDP 都空闲的端口，最后一次失败：{last_error}");
    }

    pub fn addr(&self) -> SocketAddr {
        self.endpoint.local_addr()
    }

    /// 给这个节点换一份 netmap。
    pub fn apply(&self, view: &View<'_>) {
        self.netmap.send(build_netmap(self.id, view)).unwrap();
    }

    /// 到 `peer` 现在走哪条路。
    pub fn route_to(&self, peer: &Node) -> Route {
        self.endpoint.routes().into_iter().find(|entry| entry.peer == peer.id).map_or(Route::None, |entry| entry.route)
    }

    /// 等到 `peer` 的路满足 `wanted` 为止。
    pub async fn wait_route(&self, peer: &Node, what: &str, wanted: impl Fn(&Route) -> bool) -> Route {
        let deadline = Instant::now() + 3 * SOON;
        loop {
            let route = self.route_to(peer);
            if wanted(&route) {
                return route;
            }
            assert!(Instant::now() < deadline, "节点 {} 到节点 {} 的路一直没有变成{what}，现在是 {route:?}", self.id, peer.id);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// 等这个节点的路径层知道 `peer`。netmap 是异步生效的；直接往端口上发原始的帧之前要等它。
    pub async fn wait_knows(&self, peer: &Node) {
        let deadline = Instant::now() + SOON;
        while !self.endpoint.routes().iter().any(|entry| entry.peer == peer.id) {
            assert!(Instant::now() < deadline, "节点 {} 的 netmap 一直没有生效", self.id);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// 等这个节点的 relay 角色把 TCP 监听起来。netmap 是异步生效的，UDP 用不了的节点要等它好了才连得上。
    pub async fn wait_tcp_listening(&self) {
        let deadline = Instant::now() + SOON;
        while tokio::net::TcpStream::connect(self.addr()).await.is_err() {
            assert!(Instant::now() < deadline, "节点 {} 一直没有监听 TCP", self.id);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// 丢掉这个节点和 `others` 之间所有的 UDP 包（两个方向），模拟它们之间的路不通。
    pub fn block(&self, others: &[&Node]) {
        let blocked: Vec<SocketAddr> = others.iter().map(|node| node.addr()).collect();
        self.set_filter(Some(Arc::new(move |_, peer, _| !blocked.contains(&peer))));
    }

    /// 丢掉这个节点的所有 UDP 包。
    pub fn block_all(&self) {
        self.set_filter(Some(Arc::new(|_: Direction, _, _: &[u8]| false)));
    }

    pub fn unblock(&self) {
        self.set_filter(None);
    }

    pub fn set_filter(&self, filter: Option<PacketFilter>) {
        self.endpoint.set_packet_filter(filter);
    }

    /// 起一个回声服务：对端开过来的每条流，读到什么写回什么，对端结束时也跟着正常结束。
    pub fn spawn_echo(&self) -> JoinHandle<()> {
        let endpoint = Arc::clone(&self.endpoint);
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(echo(incoming.send, incoming.recv));
            }
        })
    }
}

async fn echo(mut send: SendHalf, mut recv: RecvHalf) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match recv.read(&mut buf).await {
            Ok(0) => break,
            Ok(len) => {
                if send.write_all(&buf[..len]).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    let _finished = send.shutdown().await;
}

pub fn is_direct(route: &Route) -> bool {
    matches!(route, Route::Direct { .. })
}

pub fn is_relay(route: &Route) -> bool {
    matches!(route, Route::Relay { .. })
}

pub fn is_none(route: &Route) -> bool {
    matches!(route, Route::None)
}

fn build_netmap(me: NodeId, view: &View<'_>) -> Arc<Netmap> {
    let virtual_ip = |id: NodeId| format!("10.66.{}.{}", id.get() / 256 % 256, id.get() % 256);
    let attachments = |relays: &[&Node]| {
        relays.iter().enumerate().map(|(index, relay)| serde_json::json!({ "relay": relay.id, "rtt_ms": index + 1 })).collect::<Vec<_>>()
    };
    let peers: Vec<_> = view
        .peers
        .iter()
        .map(|peer| {
            serde_json::json!({
                "id": peer.node.id,
                "key": peer.node.key.public(),
                "name": format!("node-{}", peer.node.id),
                "virtual_ip": virtual_ip(peer.node.id),
                "inbound": true,
                "outbound": true,
                "endpoints": if peer.endpoints { vec![peer.node.addr()] } else { Vec::new() },
                "attached": attachments(peer.attached),
                "keep_alive": peer.keep_alive,
                "dial_out_only": peer.dial_out_only,
                "congestion": peer.congestion,
            })
        })
        .collect();
    let relays: Vec<_> = view
        .relays
        .iter()
        .map(|relay| {
            serde_json::json!({
                "id": relay.id,
                "key": relay.key.public(),
                "name": format!("relay-{}", relay.id),
                "udp": [relay.addr()],
                "tcp": [relay.addr()],
            })
        })
        .collect();
    let relay_clients: Vec<_> = view
        .relay_clients
        .unwrap_or_default()
        .iter()
        .map(|client| serde_json::json!({ "id": client.id, "key": client.key.public() }))
        .collect();
    let mut network = serde_json::json!({ "name": "test", "domain": "test.i3t", "cidr": "10.66.0.0/16" });
    if let Some(reach) = view.reach {
        network["reach"] = reach.into();
    }
    if let Some((eliciting_threshold, max_delay_ms)) = view.ack {
        network["ack_eliciting_threshold"] = eliciting_threshold.into();
        network["max_ack_delay_ms"] = max_delay_ms.into();
    }
    let netmap = serde_json::json!({
        "version": 1,
        "network": network,
        "me": {
            "id": me,
            "name": format!("node-{me}"),
            "virtual_ip": virtual_ip(me),
            "relay": view.relay_clients.map(|_| serde_json::json!({})),
            "dial_out_only": view.dial_out_only,
        },
        "peers": peers,
        "relays": relays,
        "relay_clients": relay_clients,
    });
    Arc::new(serde_json::from_value(netmap).unwrap())
}

/// 在一条流上开一次回声往返，核对内容。
pub async fn echo_once(from: &Node, to: &Node, payload: &[u8]) {
    let (mut send, mut recv) = tokio::time::timeout(SOON, from.endpoint.open(to.id)).await.expect("开流超时").expect("开流失败");
    send.write_all(payload).await.unwrap();
    send.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    tokio::time::timeout(SOON, recv.read_to_end(&mut echoed)).await.expect("等回声超时").expect("读回声失败");
    assert_eq!(echoed.len(), payload.len());
    assert!(echoed == payload, "回声的内容和发出去的不一样");
}

/// 每一块的长度。块里是它的序号反复写，所以丢了、重了、乱了都看得出来。
const BLOCK: usize = 1024;

/// 一条一直在传数据的回声流：一头不停地写编了号的块，另一头核对回来的块一个不少、一个不乱。
pub struct Transfer {
    verified: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    writer: JoinHandle<u64>,
    reader: JoinHandle<Result<u64, String>>,
}

impl Transfer {
    /// 在 `from` 到 `to` 的一条新流上开始传。`to` 上要有回声服务。每秒大约传 `blocks_per_sec` 块。
    pub async fn start(from: &Node, to: &Node, blocks_per_sec: u32) -> Self {
        let (mut send, mut recv) = tokio::time::timeout(SOON, from.endpoint.open(to.id)).await.expect("开流超时").expect("开流失败");
        let verified = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let stopping = Arc::clone(&stop);
        let writer = tokio::spawn(async move {
            let mut pace = tokio::time::interval(Duration::from_secs(1) / blocks_per_sec);
            let mut index = 0u64;
            while !stopping.load(Ordering::Relaxed) {
                pace.tick().await;
                send.write_all(&block(index)).await.expect("写流失败");
                index += 1;
            }
            send.shutdown().await.expect("正常结束流失败");
            index
        });

        let progress = Arc::clone(&verified);
        let reader = tokio::spawn(async move {
            let mut received = [0u8; BLOCK];
            let mut index = 0u64;
            loop {
                match recv.read_exact(&mut received).await {
                    Ok(_) if received == block(index) => {
                        index += 1;
                        progress.store(index, Ordering::Relaxed);
                    }
                    Ok(_) => return Err(format!("第 {index} 块的内容不对：数据丢了、重了或者乱了")),
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(index),
                    Err(error) => return Err(format!("读第 {index} 块时出错：{error}")),
                }
            }
        });
        Self { verified, stop, writer, reader }
    }

    /// 已经核对过多少块。
    pub fn verified(&self) -> u64 {
        self.verified.load(Ordering::Relaxed)
    }

    /// 等到又核对了 `more` 块为止，返回等了多久。数据不再流动的话会在这里超时失败。
    pub async fn expect_progress(&self, more: u64) -> Duration {
        let started = Instant::now();
        let target = self.verified() + more;
        while self.verified() < target {
            assert!(!self.reader.is_finished(), "流提前结束了");
            assert!(
                started.elapsed() < 3 * SOON,
                "数据不再流动：{} 秒里只核对到第 {} 块，要到第 {target} 块",
                started.elapsed().as_secs(),
                self.verified()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        started.elapsed()
    }

    /// 正常结束这条流，核对发出去的每一块都原样回来了。返回一共传了多少块。
    pub async fn finish(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        let sent = tokio::time::timeout(3 * SOON, self.writer).await.expect("写的一头迟迟不结束").unwrap();
        let received = tokio::time::timeout(3 * SOON, self.reader).await.expect("读的一头迟迟不结束").unwrap().unwrap();
        assert_eq!(received, sent, "发出去 {sent} 块，回来 {received} 块");
        sent
    }
}

fn block(index: u64) -> [u8; BLOCK] {
    let mut bytes = [0u8; BLOCK];
    for chunk in bytes.as_chunks_mut::<8>().0 {
        *chunk = index.to_be_bytes();
    }
    bytes
}

/// 订阅之后到 `peer` 的换路原因，按发生的顺序。
pub fn drain_reasons(changes: &mut tokio::sync::broadcast::Receiver<i3t_conn::RouteChange>, peer: &Node) -> Vec<String> {
    let mut reasons = Vec::new();
    while let Ok(change) = changes.try_recv() {
        if change.peer == peer.id {
            reasons.push(change.reason);
        }
    }
    reasons
}
