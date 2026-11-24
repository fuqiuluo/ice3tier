//! `i3t ping <节点>`：在本节点和另一个节点之间的那条连接上量几个往返，不是 ICMP。
//!
//! 每个往返是连接上新开的一条流：写一个往返测量的 OPEN，对端读到就回一个成功的 REPLY（`i3t_flow::ping`）。
//! 对端先按它的访问规则和每个对端的流数上限筛过，所以访问规则不允许时拿到的是明确的拒绝。到对端还没有连接时，
//! 第一个往返先把连接建起来，它不算在结果里，可以等到连接层自己建连接的时限（[`FIRST`]）：慢的路上（只有 TCP、隔着
//! 几百毫秒、经 relay）建连接要几秒。那时还没有建起来，说的是"没有及时建起来"，不是"不在线"。
//! 连接建立后（或原本已存在），若首次探测未及时返回，则问题在往返而非建连：最多再等待 [`EACH`]，
//! 随后继续常规测量，未返回的探测记为丢包。
//! 结果包含测量开始与结束时该对节点连接所使用的路径，以及路径上各 relay 的名称。
//!
//! 只能由本机问（本机状态接口要令牌），一次只做一个，最多 [`MAX_COUNT`] 个往返、[`DEADLINE`] 之内做完；
//! 只能问本节点配置里的节点，所以它不能拿来扫描别的地址。

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use i3t_access::RouteAtStart;
use i3t_conn::{Connector, OpenError, StreamAborted, StreamCode};
use i3t_flow::FlowError;
use i3t_model::Netmap;
use i3t_model::control::Route;
use i3t_proto::NodeId;
use i3t_proto::flow::Reason;
use serde::{Deserialize, Serialize};
use tokio::time::{self, Instant};

use crate::route_detail::EndpointRoutes;
use crate::runtime::Runtime;

/// 不说要几个时量几个往返。
pub const DEFAULT_COUNT: u32 = 5;
/// 最多量几个。
pub const MAX_COUNT: u32 = 10;
/// 两个往返之间隔多久。
const INTERVAL: Duration = Duration::from_millis(200);
/// 单次往返的最长等待时间，超时计为丢包。
const EACH: Duration = Duration::from_secs(1);
/// 第一个往返（可能要先建连接）最多等多久：连接层建一条连接的时限，加上建好之后的那一个往返。
const FIRST: Duration = i3t_conn::DIAL_TIMEOUT.saturating_add(EACH);
/// 等第一个往返的时候多久看一次连接建起来了没有。
const CONNECTED_CHECK: Duration = Duration::from_millis(50);
/// 整个过程最多多久：本机状态接口的一次问答不超过 10 秒。
pub const DEADLINE: Duration = Duration::from_secs(8);

const _: () = assert!(FIRST.as_millis() < DEADLINE.as_millis(), "第一个往返等满之后，整个过程还得在时限之内");

/// 同一时间只做一个。
static RUNNING: AtomicBool = AtomicBool::new(false);

/// 本机状态接口对 `/ping` 的回答，也就是 `i3t ping` 显示的东西。字段都有默认值：问的和答的可能不是同一个版本。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PingReport {
    /// 探测目标节点；无法识别时为 `None`。
    pub peer: Option<PingPeer>,
    pub outcome: PingOutcome,
    /// 已发送与已返回的往返次数，未返回计为丢包。
    pub sent: u32,
    pub received: u32,
    /// 已返回探测的往返耗时（微秒），按发送顺序排列。
    pub rtts_us: Vec<u64>,
    /// 测量开始和结束时该对节点连接所使用的路径；未知时为 `None`。仅首尾不同视为切换路径：中途切换后又恢复的不计入，
    /// 那种来回只在流日志里记（`route_changed`）。
    pub route_start: Option<Route>,
    pub route_end: Option<Route>,
    /// 上面两条路经过的 relay 的名字，按出现的先后，不重复。旧版本的节点不给，那时只写编号。
    pub relays: Vec<RelayName>,
}

/// 一个 relay 的编号和名字。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayName {
    pub id: u32,
    pub name: String,
}

/// 被问的节点。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingPeer {
    pub id: u32,
    pub name: String,
    pub virtual_ip: Ipv4Addr,
}

/// 量成了没有；没有的话为什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PingOutcome {
    /// 量了（丢没丢看 `sent` 和 `received`）。
    #[default]
    Done,
    /// 本节点的配置里没有这个节点：没有这个节点，或者访问规则没有把它和本节点连起来。
    UnknownNode,
    /// 是本节点自己。
    Myself,
    /// 本节点的访问规则不允许本节点访问它（只允许它访问本节点）。
    NotAllowed,
    /// 对端拒绝了：它那边的访问规则不允许本节点访问它。
    Refused,
    /// 无法向对端建立流：对端可能离线或无可用路径。
    Unreachable,
    /// 未能在时限（[`FIRST`]）内建立连接：对端未必离线，慢速链路建连可能需要数秒。
    ConnectTimeout,
    /// 对端版本过旧，不支持往返测量。
    Unsupported,
    /// 本节点上已有另一个 ping 正在执行。
    Busy,
    /// 来自较新版本节点、当前版本无法识别的结果状态。
    #[serde(other)]
    Unknown,
}

/// 在 [`RUNNING`] 上占着的名额，丢弃时还回去。
struct Running;

impl Running {
    fn enter() -> Option<Self> {
        (!RUNNING.swap(true, Ordering::AcqRel)).then_some(Self)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

/// 在到 `target`（节点名、全名或者虚拟 IP）的连接上量 `count` 个往返（1 到 [`MAX_COUNT`]）。
pub(crate) async fn ping(runtime: &Runtime, target: &str, count: u32) -> PingReport {
    let netmap = Arc::clone(&runtime.netmap.borrow());
    let peer = match find(&netmap, target) {
        Ok(peer) => peer,
        Err(outcome) => return PingReport { outcome, ..PingReport::default() },
    };
    let mut report = PingReport {
        peer: Some(PingPeer { id: peer.id.get(), name: peer.name.clone(), virtual_ip: peer.virtual_ip }),
        ..PingReport::default()
    };
    if !peer.outbound {
        report.outcome = PingOutcome::NotAllowed;
        return report;
    }
    let Some(_running) = Running::enter() else {
        report.outcome = PingOutcome::Busy;
        return report;
    };
    let (id, endpoint) = (peer.id, &*runtime.endpoint);
    let routes = EndpointRoutes(Arc::clone(&runtime.endpoint));
    let mut route = RouteAtStart::now(&routes, id);
    let deadline = Instant::now() + DEADLINE;

    let connected = || runtime.endpoint.connection_rtt(id).is_some();
    match bring_up(endpoint, id, connected).await {
        Err(outcome) => report.outcome = outcome,
        Ok(()) => {
            // 开始时的路从连接建起来之后算，不然第一次联系时总是"不可达 → 直连"。
            route = RouteAtStart::now(&routes, id);
            measure(endpoint, id, count, deadline, &mut report).await;
        }
    }
    let span = route.ended(&routes);
    let on_routes = [span.start.as_ref(), span.end.as_ref()].into_iter().flatten().flat_map(|route| route.relays().iter().copied());
    report.relays = relay_names(&netmap, on_routes);
    (report.route_start, report.route_end) = (span.start, span.end);
    tracing::info!(peer = %id, outcome = ?report.outcome, sent = report.sent, received = report.received, "ping 测量完成");
    report
}

/// 首次往返：用于建立到 `peer` 的连接，不计入测量结果。`connected` 表示当前是否已与 `peer` 建立连接。
///
/// 连接建立前最多等待 [`FIRST`]，超时仍未建立连接则判定为连接建立超时。连接已建立（或原本已存在）后，本次探测
/// 最多再等待 [`EACH`]（且不超过 [`FIRST`]）：超时不能说明连接未建立或对端离线，因此不视为失败，继续后续测量，
/// 未返回的探测计为丢包。建流或读取应答出错（被拒绝、无可用路径、连接断开、对端版本过旧）仍视为失败。
async fn bring_up<C: Connector>(connector: &C, peer: NodeId, connected: impl Fn() -> bool) -> Result<(), PingOutcome> {
    let started = Instant::now();
    let warm_up = i3t_flow::ping(connector, peer);
    tokio::pin!(warm_up);
    let mut up_at = connected().then_some(started);
    let mut check = time::interval(CONNECTED_CHECK);
    loop {
        let limit = up_at.map_or(started + FIRST, |at| (at + EACH).min(started + FIRST));
        tokio::select! {
            done = &mut warm_up => {
                let outcome = match done {
                    Ok(_) => return Ok(()),
                    Err(error) => outcome_of(&error),
                };
                tracing::info!(%peer, ?outcome, waited_ms = started.elapsed().as_millis(), "ping：首次往返测量失败");
                return Err(outcome);
            }
            () = time::sleep_until(limit) => break,
            _ = check.tick(), if up_at.is_none() => {
                if connected() {
                    up_at = Some(Instant::now());
                }
            }
        }
    }
    let waited_ms = started.elapsed().as_millis();
    match up_at {
        Some(at) => {
            let up_ms = at.saturating_duration_since(started).as_millis();
            tracing::info!(%peer, up_ms, waited_ms, "ping：已建立连接，首次探测未在时限内返回，继续测量");
            Ok(())
        }
        None => {
            tracing::info!(%peer, outcome = ?PingOutcome::ConnectTimeout, waited_ms, "ping：首次往返测量失败");
            Err(PingOutcome::ConnectTimeout)
        }
    }
}

/// 连接建立后，最多测量 `count` 次往返（次数限制在 1 至 [`MAX_COUNT`]）。仅在 `deadline` 前发起探测，结果写入 `report`。
async fn measure<C: Connector>(connector: &C, peer: NodeId, count: u32, deadline: Instant, report: &mut PingReport) {
    for index in 0..count.clamp(1, MAX_COUNT) {
        if index > 0 {
            time::sleep(INTERVAL).await;
        }
        let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()) else { break };
        report.sent += 1;
        if let Ok(Ok(rtt)) = time::timeout(EACH.min(left), i3t_flow::ping(connector, peer)).await {
            report.received += 1;
            report.rtts_us.push(u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX));
        }
    }
}

/// 按名字（短名或者全名）或者虚拟 IP 在配置里找节点。
fn find<'a>(netmap: &'a Netmap, target: &str) -> Result<&'a i3t_model::netmap::Peer, PingOutcome> {
    let target = target.trim();
    let mine = match target.parse::<Ipv4Addr>() {
        Ok(ip) => ip == netmap.me.virtual_ip,
        Err(_) => {
            let full = target.strip_suffix('.').unwrap_or(target);
            netmap.network.short_name(full).eq_ignore_ascii_case(&netmap.me.name)
        }
    };
    if mine {
        return Err(PingOutcome::Myself);
    }
    let found = match target.parse::<Ipv4Addr>() {
        Ok(ip) => netmap.peer_by_ip(ip),
        Err(_) => netmap.peer_by_name(target),
    };
    found.ok_or(PingOutcome::UnknownNode)
}

/// 这些 relay 的名称，按出现顺序去重。名称通过 [`Netmap::node_name`] 查找（relay 列表、对端、本节点自身），
/// 与 `i3t routes`、`i3t status` 及流结束日志采用相同方式；均未找到时省略名称，展示时退回节点编号。
pub(crate) fn relay_names(netmap: &Netmap, relays: impl IntoIterator<Item = NodeId>) -> Vec<RelayName> {
    let mut names: Vec<RelayName> = Vec::new();
    for id in relays {
        if names.iter().any(|known| known.id == id.get()) {
            continue;
        }
        if let Some(name) = netmap.node_name(id) {
            names.push(RelayName { id: id.get(), name: name.to_owned() });
        }
    }
    names
}

/// 将失败的往返探测映射为结果分类。连接层建连超时与此处等待超时语义一致，均表示未在时限内建立连接；
/// 无可用路径或连接中断则归类为不可达（对端离线或无路径）。
fn outcome_of(error: &FlowError) -> PingOutcome {
    match error {
        FlowError::Refused(_) => PingOutcome::Refused,
        FlowError::Connect(OpenError::Timeout(_)) => PingOutcome::ConnectTimeout,
        FlowError::Read(error) if StreamAborted::of(error) == Some(StreamAborted::Reset(StreamCode(Reason::ProtocolError.to_wire()))) => {
            PingOutcome::Unsupported
        }
        _ => PingOutcome::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::atomic::AtomicU32;

    use i3t_flow::memory::{MemoryConnector, MemoryMesh, MemoryRecv, MemorySend};
    use i3t_flow::{Handler, Request, Screening};
    use i3t_model::netmap::{LaneMode, LocalNode, Network, Peer, Relay};
    use i3t_proto::PublicKey;
    use i3t_proto::flow::{Reply, Status};

    use super::*;

    /// 对端：往返测量照常回答，别的流一律拒绝。
    struct Answers;

    impl Handler for Answers {
        fn screen(&self, _peer: NodeId, _in_progress: usize) -> Screening {
            Screening::Admit
        }

        async fn handle<S: i3t_conn::SendStream, R: i3t_conn::RecvStream>(&self, request: Request<S, R>) {
            request.refuse(&Reply::new(Status::NotEnabled, "只回答往返测量")).await;
        }
    }

    /// 一条慢的路：前 `slow_opens` 次开流各要等 `dial` 才开得出来（像是先要建连接），之后和内存里的连接一样快。
    /// `dial` 是 `None` 时那几次一直开不出来。开出过一条流之后 `up` 为真：连接建起来了。
    /// `unanswered` 次开流开得出来，对端却一直不回答（第一条流在刚建好的连接上卡住）。
    struct SlowPath {
        inner: MemoryConnector,
        silent: MemoryConnector,
        dial: Option<Duration>,
        slow_opens: AtomicU32,
        unanswered: AtomicU32,
        up: AtomicBool,
    }

    impl SlowPath {
        fn connected(&self) -> bool {
            self.up.load(Ordering::Acquire)
        }
    }

    impl Connector for SlowPath {
        type Send = MemorySend;
        type Recv = MemoryRecv;

        fn open(&self, peer: NodeId) -> impl Future<Output = Result<(MemorySend, MemoryRecv), OpenError>> + Send {
            // 还有余额就减一。不用 `fetch_update`：新的 clippy 说它已经过时，换上的 `try_update` 老一点的工具链又没有。
            let take = |left: &AtomicU32| {
                let mut current = left.load(Ordering::Acquire);
                while let Some(next) = current.checked_sub(1) {
                    match left.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => return true,
                        Err(actual) => current = actual,
                    }
                }
                false
            };
            let slow = take(&self.slow_opens);
            let unanswered = take(&self.unanswered);
            let dial = self.dial;
            async move {
                match (slow, dial) {
                    (false, _) => {}
                    (true, Some(dial)) => time::sleep(dial).await,
                    (true, None) => std::future::pending().await,
                }
                let opened = if unanswered { self.silent.open(peer).await } else { self.inner.open(peer).await };
                self.up.store(opened.is_ok(), Ordering::Release);
                opened
            }
        }
    }

    const NAS: u32 = 2;

    fn slow_path(dial: Option<Duration>) -> SlowPath {
        stuck_path(dial, 0)
    }

    /// 同 [`slow_path`]，另外开头 `unanswered` 条流对端不回答（它在另一个对端不读流的网里）。
    fn stuck_path(dial: Option<Duration>, unanswered: u32) -> SlowPath {
        let mesh = MemoryMesh::new();
        let (_, acceptor) = mesh.join(NodeId::new(NAS).unwrap());
        tokio::spawn(async move { i3t_flow::serve(&acceptor, Arc::new(Answers)).await });
        let (inner, _) = mesh.join(NodeId::new(1).unwrap());
        let deaf = MemoryMesh::new();
        let (_, never_read) = deaf.join(NodeId::new(NAS).unwrap());
        // 接受方一直在，只是从来不读：开得出流，却等不到回答。
        tokio::spawn(async move {
            let _held = never_read;
            std::future::pending::<()>().await;
        });
        let (silent, _) = deaf.join(NodeId::new(1).unwrap());
        SlowPath { inner, silent, dial, slow_opens: AtomicU32::new(1), unanswered: AtomicU32::new(unanswered), up: AtomicBool::new(false) }
    }

    fn netmap() -> Netmap {
        let peer = |raw: u32, name: &str, outbound: bool| Peer {
            id: NodeId::new(raw).unwrap(),
            key: PublicKey::from_bytes([u8::try_from(raw).unwrap(); 32]),
            name: name.into(),
            virtual_ip: Ipv4Addr::new(10, 66, 0, u8::try_from(raw).unwrap()),
            inbound: true,
            outbound,
            endpoints: Vec::new(),
            attached: Vec::new(),
            exit: None,
            dial_out_only: false,
            keep_alive: false,
            lane: LaneMode::Off,
            congestion: None,
            no_udp: false,
        };
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
                id: NodeId::new(1).unwrap(),
                name: "laptop".into(),
                virtual_ip: Ipv4Addr::new(10, 66, 0, 1),
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
            peers: vec![peer(2, "nas", true), peer(3, "phone", false)],
            relays: Vec::new(),
            relay_clients: Vec::new(),
            no_vnet: Vec::new(),
        }
    }

    #[test]
    fn a_peer_is_found_by_name_full_name_or_virtual_ip_and_never_ourselves() {
        let netmap = netmap();
        for target in ["nas", "NAS", "nas.home.i3t", "10.66.0.2"] {
            assert_eq!(find(&netmap, target).map(|peer| peer.id.get()), Ok(2), "{target}");
        }
        for target in ["laptop", "laptop.home.i3t", "10.66.0.1"] {
            assert_eq!(find(&netmap, target).map(|peer| peer.id.get()), Err(PingOutcome::Myself), "{target}");
        }
        assert_eq!(find(&netmap, "printer").map(|peer| peer.id.get()), Err(PingOutcome::UnknownNode));
        assert!(!find(&netmap, "phone").unwrap().outbound, "只能被它访问的节点找得到，由调用方说不允许");
    }

    #[test]
    fn relays_on_the_routes_are_named_once_from_the_netmap() {
        let mut netmap = netmap();
        let hk =
            Relay { id: NodeId::new(9).unwrap(), key: PublicKey::from_bytes([9; 32]), name: "hk".into(), udp: Vec::new(), tcp: Vec::new() };
        netmap.relays.push(hk);
        let ids = [9, 2, 9, 1, 7].map(|id| NodeId::new(id).unwrap());
        let names = relay_names(&netmap, ids);
        let names: Vec<(u32, &str)> = names.iter().map(|relay| (relay.id, relay.name.as_str())).collect();
        assert_eq!(names, [(9, "hk"), (2, "nas"), (1, "laptop")], "对端自己、本节点自己也认得出来；哪里都没有的 7 不给");
        let direct = Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() };
        assert!(direct.relays().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_takes_most_of_the_dial_timeout_to_come_up_is_still_measured() {
        // 比以前的 3 秒长，比连接层建连接的时限短：只有 TCP、隔着 250 毫秒、经 relay 的那种路。
        let dial = i3t_conn::DIAL_TIMEOUT - Duration::from_millis(500);
        let path = slow_path(Some(dial));
        let started = Instant::now();
        assert_eq!(bring_up(&path, NodeId::new(NAS).unwrap(), || path.connected()).await, Ok(()));
        assert!(started.elapsed() >= dial, "第一个往返确实等了建连接的那几秒：{:?}", started.elapsed());

        let mut report = PingReport::default();
        measure(&path, NodeId::new(NAS).unwrap(), 3, started + DEADLINE, &mut report).await;
        assert_eq!((report.sent, report.received, report.rtts_us.len()), (3, 3, 3), "建好之后量的往返都在");
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_does_not_come_up_is_reported_as_not_up_in_time_after_the_dial_timeout() {
        let path = slow_path(None);
        let started = Instant::now();
        let outcome = bring_up(&path, NodeId::new(NAS).unwrap(), || path.connected()).await;
        assert_eq!(outcome, Err(PingOutcome::ConnectTimeout), "不是说它不在线");
        let waited = started.elapsed();
        assert!(waited >= i3t_conn::DIAL_TIMEOUT && waited <= FIRST, "等满连接层建连接的时限才放弃：{waited:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_round_trip_that_stalls_on_a_connection_that_is_up_is_counted_as_lost_not_as_a_connection_that_did_not_come_up() {
        // 连接 250 毫秒就建起来了，第一条流却一直等不到回答（实际网络上见过：之后 5.7 秒都没有回来）。
        let path = stuck_path(Some(Duration::from_millis(250)), 1);
        let started = Instant::now();
        assert_eq!(bring_up(&path, NodeId::new(NAS).unwrap(), || path.connected()).await, Ok(()), "不能说连接没有建起来");
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(250) + EACH && waited < Duration::from_millis(250) + EACH + CONNECTED_CHECK * 2,
            "连接建起来之后只再等一个往返的时限：{waited:?}"
        );

        let mut report = PingReport::default();
        measure(&path, NodeId::new(NAS).unwrap(), 3, started + DEADLINE, &mut report).await;
        assert_eq!((report.sent, report.received), (3, 3), "之后的往返照常量");
        // 量的往返本身也回不来时，是丢了：结论还是"量了"，由发出和回来的个数说话。
        let path = stuck_path(Some(Duration::from_millis(250)), 4);
        let started = Instant::now();
        assert_eq!(bring_up(&path, NodeId::new(NAS).unwrap(), || path.connected()).await, Ok(()));
        let mut report = PingReport::default();
        measure(&path, NodeId::new(NAS).unwrap(), 5, started + DEADLINE, &mut report).await;
        assert_eq!((report.outcome, report.received), (PingOutcome::Done, 2), "前三个丢了，后两个回来了：{report:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_round_trip_that_stalls_on_an_existing_connection_waits_one_round_trip_limit_not_the_dial_timeout() {
        let path = stuck_path(Some(Duration::ZERO), 1);
        path.up.store(true, Ordering::Release);
        let started = Instant::now();
        assert_eq!(bring_up(&path, NodeId::new(NAS).unwrap(), || path.connected()).await, Ok(()));
        assert_eq!(started.elapsed(), EACH, "本来就有连接：不等建连接的时限");
    }

    #[tokio::test(start_paused = true)]
    async fn a_measurement_stops_at_the_deadline() {
        let path = slow_path(Some(Duration::ZERO));
        let started = Instant::now();
        bring_up(&path, NodeId::new(NAS).unwrap(), || path.connected()).await.unwrap();
        let mut report = PingReport::default();
        measure(&path, NodeId::new(NAS).unwrap(), MAX_COUNT, started + INTERVAL * 2 + Duration::from_millis(1), &mut report).await;
        assert_eq!(report.sent, 3, "第一个立刻发，之后每隔一段发一个，过了时限就不再发");
    }

    #[test]
    fn failures_are_told_apart() {
        let refused = FlowError::Refused(i3t_proto::flow::Reply::new(i3t_proto::flow::Status::AccessDenied, ""));
        assert_eq!(outcome_of(&refused), PingOutcome::Refused);
        let old = FlowError::Read(StreamAborted::Reset(StreamCode(Reason::ProtocolError.to_wire())).into());
        assert_eq!(outcome_of(&old), PingOutcome::Unsupported);
        assert_eq!(outcome_of(&FlowError::Connect(OpenError::NoRoute(NodeId::new(2).unwrap()))), PingOutcome::Unreachable);
        assert_eq!(
            outcome_of(&FlowError::Connect(OpenError::Timeout(NodeId::new(2).unwrap()))),
            PingOutcome::ConnectTimeout,
            "连接层自己建连接超时：没有及时建起来，不是不在线"
        );
        let newer: PingReport = serde_json::from_value(serde_json::json!({ "outcome": "later", "extra": 1 })).unwrap();
        assert_eq!(newer.outcome, PingOutcome::Unknown);
    }
}
