//! 主动测试在节点里的部分：收 controller 的指令，按自己的规矩决定做不做，发起方量、接受方配合，各自上报。
//!
//! 节点本地约束（即使 controller 被攻破，也不允许节点执行本地禁止的操作）：
//!
//! - **只执行 controller 下发的测试。** 仅响应已开启测试的探测（路径层），测量流仅接受指令指定的对端、在时间窗内、
//!   且指令包含吞吐项的测试连接。对端无法自行发起测试。
//! - **遵循路径限制。** 仅经 relay 的节点不参与直连测试项（不尝试直连、不响应直连探测），不向对端暴露地址；
//!   只用直连的节点不测经 relay 的路径。
//! - **本机的开关。** 配置文件里关掉了吞吐测试（`[tests] throughput = false`）就一律拒绝测量流。
//! - **上限在本机。** 同时最多 [`MAX_TESTS`] 个测试；和同一个对端的测试至少隔 [`MIN_INTERVAL`]，吞吐至少隔 [`THROUGHPUT_INTERVAL`]；
//!   时间窗最长 [`MAX_WINDOW`]；每条测量流每个方向最多 [`THROUGHPUT_BYTES`]、[`THROUGHPUT_TIME`]，一个测试最多 [`MAX_STREAMS`] 条、
//!   同时一条；探测的个数和速率有路径层的上限。
//! - **测量流不碰 ice3proxy。** 发起方直接在共用的连接上开（[`Endpoint`] 本身，不是入口用的连接层）。
//!   接受方吞吐期间把自己发回去的方向固定在同一条路径上，流结束（包括被取消）就解除。

mod host;
mod run;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use i3t_conn::{Endpoint, RecvStream, SendStream, Side, TestPath, TestSpec};
use i3t_flow::datagram;
use i3t_flow::measure::{MeasureLimits, MeasureRequest};
use i3t_flow::{Handler, Request, Screening};
use i3t_model::Netmap;
use i3t_model::control::diag::{TestCode, TestItems, TestProblem, TestRole};
use i3t_model::control::{TestOrder, TestReport};
use i3t_model::netmap::Reach;
use i3t_proto::NodeId;
use i3t_proto::flow::{Reason, Reply, Status};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::lanes::NodeLanes;
use crate::runtime::NodeExit;

/// 节点同时最多进行几个测试。全网矩阵分批跑，一个节点会同时出现在几对里。
const MAX_TESTS: usize = 8;
/// 和同一个对端的两次测试至少隔多久。controller 那边也守着这一条（10 秒），这里短一点，免得两边差一点就互相打架；
/// 放在节点上是为了 controller 被攻破时节点自己也守得住。
const MIN_INTERVAL: Duration = Duration::from_secs(8);
/// 和同一个对端的两次吞吐测试至少隔多久。
const THROUGHPUT_INTERVAL: Duration = Duration::from_secs(25);
/// 时间窗最长多久，不管指令里写多少。
const MAX_WINDOW: Duration = Duration::from_secs(150);
/// 吞吐测试每个方向的上限，先到为止。
pub(crate) const THROUGHPUT_BYTES: u64 = 20_000_000;
pub(crate) const THROUGHPUT_TIME: Duration = Duration::from_secs(5);
/// 一个测试最多接受几条测量流：每条路径上行下行各一条，最多三条路径（直连，加上两条经 relay 的）。
/// 所以一个测试里本节点最多发出或者收下 6 × 20MB，和同一个对端的吞吐测试又至少隔 [`THROUGHPUT_INTERVAL`]。
const MAX_STREAMS: u32 = 6;
/// 一列探测发多少个、隔多久：两秒，丢包的分辨率是百分之一。
pub(crate) const TRAIN_PROBES: u32 = 100;
pub(crate) const TRAIN_INTERVAL: Duration = Duration::from_millis(20);
/// 一个测试里本节点最多回答多少个探测：每条路径一列，最多五条。
const MAX_PROBES: u32 = TRAIN_PROBES * 5;
/// 访问规则不允许访问本节点的对端，在和本节点做吞吐测试期间同时最多有几条流被读 OPEN。
/// 测量流一次一条，前一条收尾时和后一条会重叠一下，所以不是一。
const EXEMPT_STREAMS: usize = 4;
/// 同一个测试的上一条测量流还占着"正在测"时，新来的一条最多等它多久（见 [`Diag::admit_after_previous`]）。
/// 等待的仅是前一条流任务执行收尾步骤，高负载主机上通常也仅需数十毫秒。
const PREVIOUS_STREAM_WAIT: Duration = Duration::from_secs(1);

/// 一个节点上的主动测试。
pub(crate) struct Diag {
    endpoint: Arc<Endpoint>,
    netmap: watch::Receiver<Arc<Netmap>>,
    /// 本机接不接受吞吐测试。
    throughput: bool,
    reports: mpsc::Sender<TestReport>,
    state: Mutex<State>,
    /// 一条测量流放开"正在测"时叫醒等着的下一条。
    released: Notify,
    /// 节点启动的时刻（这个值是节点启动时建的）。
    started: Instant,
    /// ice3proxy 的状况，测试项 `host` 报连接数时用。没有给时那两个数是 0。
    lanes: Option<Arc<NodeLanes>>,
}

#[derive(Default)]
struct State {
    tests: HashMap<u64, Session>,
    /// 和每个对端最近一次测试开始的时刻，和最近一次带吞吐的测试开始的时刻。
    recent: HashMap<NodeId, (Instant, Option<Instant>)>,
}

/// 一个进行中的测试。
struct Session {
    peer: NodeId,
    role: TestRole,
    items: TestItems,
    until: Instant,
    task: JoinHandle<()>,
    /// 接受方：测试结束（controller 说的）时叫它报最后的结果。
    end: Option<oneshot::Sender<()>>,
    /// 接受过几条测量流，现在有没有一条在进行。
    streams: u32,
    measuring: bool,
}

impl Diag {
    pub(crate) fn new(
        endpoint: Arc<Endpoint>,
        netmap: watch::Receiver<Arc<Netmap>>,
        throughput: bool,
        reports: mpsc::Sender<TestReport>,
    ) -> Self {
        Self {
            endpoint,
            netmap,
            throughput,
            reports,
            state: Mutex::default(),
            released: Notify::new(),
            started: Instant::now(),
            lanes: None,
        }
    }

    #[must_use]
    pub(crate) fn with_lanes(mut self, lanes: Arc<NodeLanes>) -> Self {
        self.lanes = Some(lanes);
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("diag state mutex poisoned")
    }

    fn me(&self) -> NodeId {
        self.netmap.borrow().me.id
    }

    /// 本节点的路径限制：节点自己的，没有就用网络的。
    fn reach(&self) -> Reach {
        let netmap = self.netmap.borrow();
        netmap.me.reach.unwrap_or(netmap.network.reach)
    }

    fn report(&self, report: TestReport) {
        if self.reports.try_send(report).is_err() {
            tracing::warn!("主动测试结果发送失败：与 controller 的上报通道已满或已关闭");
        }
    }

    /// controller 的测试指令。按本机约束决定是否执行，若执行则在后台运行，不在此阻塞。
    pub(crate) fn order(self: &Arc<Self>, order: TestOrder) {
        let (test, peer, role) = (order.test, order.peer, order.role);
        match self.admit(&order) {
            Ok(()) => {}
            Err(problem) => {
                tracing::info!(test, %peer, ?role, code = ?problem.code, "已拒绝执行主动测试");
                return self.report(TestReport { test, role: Some(role), last: true, refused: Some(problem), ..TestReport::default() });
            }
        }
        let window = Duration::from_secs(u64::from(order.window_secs)).min(MAX_WINDOW);
        let until = Instant::now() + window;
        // 本节点这一头的第一个 relay：指定的路径上它可能平时不连，测试期间要保持会话。
        let first_hops = order.paths.iter().filter_map(|path| if role == TestRole::Initiator { path.first() } else { path.last() });
        // 发起方带头：马上试直连、测试期间把对端当作活跃的；接受方跟随（见 `Side`）。
        let side = if role == TestRole::Initiator { Side::Lead } else { Side::Follow };
        let spec = TestSpec { test, peer, side, window, max_probes: MAX_PROBES, relays: first_hops.copied().collect() };
        let guard = self.endpoint.open_test(spec);
        tracing::info!(test, %peer, ?role, items = ?order.items, paths = ?order.paths, window_secs = window.as_secs(), "开始主动测试");
        let (end, ended) = oneshot::channel();
        let items = order.items;
        let task = tokio::spawn({
            let diag = Arc::clone(self);
            async move {
                let host = order.items.host.then(|| host::Watch::start(&diag.endpoint, order.peer));
                let mut report = match role {
                    TestRole::Initiator => run::initiate(&diag, &order).await,
                    TestRole::Responder => run::respond(&diag, &order, until, ended).await,
                };
                if let Some(host) = host {
                    report.host = Some(host.finish(&diag, order.peer).await);
                }
                drop(guard);
                diag.report(report);
                diag.lock().tests.remove(&order.test);
                tracing::info!(test = order.test, peer = %order.peer, "主动测试结束");
            }
        });
        let end = (role == TestRole::Responder).then_some(end);
        self.lock().tests.insert(test, Session { peer, role, items, until, task, end, streams: 0, measuring: false });
    }

    /// 检查一个指令能不能做：对端在不在 netmap 里，同时的测试多不多，和这个对端是不是刚测过。能做的话记下这一次。
    fn admit(&self, order: &TestOrder) -> Result<(), TestProblem> {
        let me = self.me();
        if self.netmap.borrow().peer(order.peer).is_none() {
            return Err(TestProblem::new(TestCode::NotConnected, Some(me)));
        }
        let now = Instant::now();
        let mut state = self.lock();
        state.tests.retain(|_, session| !session.task.is_finished());
        if state.tests.contains_key(&order.test) {
            return Err(TestProblem::new(TestCode::Busy, Some(me)));
        }
        if state.tests.len() >= MAX_TESTS {
            return Err(TestProblem::new(TestCode::Busy, Some(me)));
        }
        let recent = state.recent.get(&order.peer).copied();
        let too_soon = recent.is_some_and(|(started, _)| now.saturating_duration_since(started) < MIN_INTERVAL);
        let throughput_too_soon = order.items.throughput
            && recent.and_then(|(_, throughput)| throughput).is_some_and(|at| now.saturating_duration_since(at) < THROUGHPUT_INTERVAL);
        if too_soon || throughput_too_soon {
            return Err(TestProblem::new(TestCode::TooSoon, Some(me)));
        }
        let throughput = if order.items.throughput { Some(now) } else { recent.and_then(|(_, throughput)| throughput) };
        state.recent.insert(order.peer, (now, throughput));
        state.recent.retain(|_, (started, _)| now.saturating_duration_since(*started) < THROUGHPUT_INTERVAL.max(MIN_INTERVAL));
        Ok(())
    }

    /// controller 说这个测试结束了：发起方停下（结果 controller 已经有了，或者测试被取消了），接受方报最后的结果。
    pub(crate) fn end(&self, test: u64) {
        let mut state = self.lock();
        let Some(session) = state.tests.get_mut(&test) else { return };
        match session.role {
            TestRole::Initiator => {
                session.task.abort();
                state.tests.remove(&test);
                tracing::info!(test, "controller 已结束该主动测试，停止执行");
            }
            TestRole::Responder => {
                if let Some(end) = session.end.take() {
                    // 接受方的任务已经结束的话没有人听，那也没有关系。
                    let _listening = end.send(());
                }
            }
        }
    }

    /// 对端开过来的流在读 OPEN 之前：它在和本节点做一个要量吞吐的测试时，测量流不受访问规则限制。
    fn expects_stream(&self, peer: NodeId) -> bool {
        let now = Instant::now();
        self.lock()
            .tests
            .values()
            .any(|session| session.role == TestRole::Responder && session.peer == peer && session.items.throughput && now < session.until)
    }

    /// 出口对一条流的筛选结果 `exit`，算上主动测试之后是什么。
    ///
    /// 访问规则不允许对端访问本节点，但它正在和本节点做一个要量吞吐的测试：读它的 OPEN。不是测量流的话，
    /// 出口读了 OPEN 之后照样按访问规则拒绝。只放过"访问规则不允许"这一种重置，而且只放过几条：
    /// 出口在这种对端身上不数它开了多少条流，不设上限的话测试期间它能让本节点同时读任意多个 OPEN。
    fn screening(&self, peer: NodeId, in_progress: usize, exit: Screening) -> Screening {
        match exit {
            Screening::Reset(Reason::AccessRevoked) if in_progress < EXEMPT_STREAMS && self.expects_stream(peer) => Screening::Admit,
            other => other,
        }
    }

    /// 测量服务：对端开来的一条测量流。
    async fn serve(&self, request: MeasureRequest<impl SendStream, impl RecvStream>) {
        let (peer, open) = (request.peer(), *request.open());
        if let Err(code) = self.admit_after_previous(peer, &open).await {
            tracing::info!(test = open.test, %peer, ?code, "拒绝了一条测量流");
            return request.refuse(&Reply::new(Status::NotEnabled, code.text())).await;
        }
        let _slot = StreamSlot { diag: self, test: open.test };
        // 本节点发回去的方向固定在同一条路径上，两个方向量的才是同一条路。流结束（包括被取消）时 `_pin` 被丢掉，固定随之解除。
        let reverse = TestPath::from_relays(open.path).reversed();
        let _pin = self.endpoint.pin_route(peer, reverse, THROUGHPUT_TIME + Duration::from_secs(5));
        let limits = MeasureLimits { bytes: THROUGHPUT_BYTES, duration: THROUGHPUT_TIME };
        let served = request.serve(limits).await;
        tracing::info!(test = open.test, %peer, mode = ?open.mode, bytes = served.bytes, ms = served.elapsed.as_millis(), end = ?served.end, "测量流结束");
    }

    /// 同 [`admit_stream`](Self::admit_stream)，只是同一个测试的上一条测量流还占着"正在测"时，先等它放开。
    ///
    /// 发起方读到上一条的结果就开下一条（量完上行量下行），而这一头的那条流把结果写出去之后，它的任务还要再跑几步
    /// 才放开"正在测"：机器忙的时候，下一条的 OPEN 会先到。那不是同时开了两条，拒绝的话下行就量不成了。
    /// 最多等 [`PREVIOUS_STREAM_WAIT`]，真正同时开的两条照旧只接一条。
    async fn admit_after_previous(&self, peer: NodeId, open: &i3t_proto::flow::OpenMeasure) -> Result<(), TestCode> {
        let deadline = tokio::time::Instant::now() + PREVIOUS_STREAM_WAIT;
        loop {
            // 在看状态之前就开始听：中间放开的那一下也收得到。
            let released = self.released.notified();
            match self.admit_stream(peer, open) {
                Err(TestCode::Busy) if self.lock().tests.get(&open.test).is_some_and(|session| session.measuring) => {
                    if tokio::time::timeout_at(deadline, released).await.is_err() {
                        return Err(TestCode::Busy);
                    }
                }
                admitted => return admitted,
            }
        }
    }

    /// 能不能接这条测量流。能的话记下"正在测"。
    fn admit_stream(&self, peer: NodeId, open: &i3t_proto::flow::OpenMeasure) -> Result<(), TestCode> {
        if !self.throughput {
            return Err(TestCode::ThroughputOff);
        }
        let netmap = Arc::clone(&self.netmap.borrow());
        let reach = netmap.me.reach.unwrap_or(netmap.network.reach);
        match open.path {
            None if reach == Reach::RelayOnly => return Err(TestCode::RelayOnly),
            Some(_) if reach == Reach::DirectOnly => return Err(TestCode::DirectOnly),
            Some(path) if path.as_slice().iter().any(|relay| netmap.relay(*relay).is_none() && *relay != netmap.me.id) => {
                return Err(TestCode::InvalidPath);
            }
            None | Some(_) => {}
        }
        let now = Instant::now();
        let mut state = self.lock();
        let session = state.tests.get_mut(&open.test).filter(|session| session.role == TestRole::Responder && session.peer == peer);
        let Some(session) = session.filter(|session| now < session.until) else { return Err(TestCode::Refused) };
        if !session.items.throughput {
            return Err(TestCode::Refused);
        }
        if session.measuring || session.streams >= MAX_STREAMS {
            return Err(TestCode::Busy);
        }
        session.measuring = true;
        session.streams += 1;
        Ok(())
    }
}

/// 一条测量流占着的"正在测"。丢掉时（流结束、任务被取消）放开。
struct StreamSlot<'a> {
    diag: &'a Diag,
    test: u64,
}

impl Drop for StreamSlot<'_> {
    fn drop(&mut self) {
        if let Some(session) = self.diag.lock().tests.get_mut(&self.test) {
            session.measuring = false;
        }
        self.diag.released.notify_waiters();
    }
}

/// 节点接受流的那一侧：出口，加上测量服务。
pub(crate) struct NodeHandler {
    pub(crate) exit: Arc<NodeExit>,
    pub(crate) diag: Arc<Diag>,
}

impl Handler for NodeHandler {
    fn screen(&self, peer: NodeId, in_progress: usize) -> Screening {
        self.diag.screening(peer, in_progress, self.exit.screen(peer, in_progress))
    }

    async fn handle<S: SendStream, R: RecvStream>(&self, request: Request<S, R>) {
        self.exit.handle(request).await;
    }

    async fn handle_datagrams<S: SendStream, R: RecvStream, T: i3t_conn::DatagramSender>(&self, request: datagram::Request<S, R, T>) {
        self.exit.handle_datagrams(request).await;
    }

    async fn handle_measure<S: SendStream, R: RecvStream>(&self, request: MeasureRequest<S, R>) {
        self.diag.serve(request).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use i3t_conn::EndpointConfig;
    use i3t_crypto::NodeKey;
    use i3t_model::control::diag::{TestItems, Transfer, TransferEnd};
    use i3t_proto::datagram::RelayPath;
    use i3t_proto::flow::{MeasureMode, OpenMeasure};

    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    /// 本节点是 `me`，对端是 `peers`（编号、公钥、地址）。`reach` 是本节点的路径限制。
    fn netmap(me: u32, peers: &[(u32, i3t_proto::PublicKey, Option<SocketAddr>)], reach: &str) -> Netmap {
        let peers: Vec<serde_json::Value> = peers
            .iter()
            .map(|(id, key, addr)| {
                serde_json::json!({
                    "id": id, "key": key, "name": format!("n{id}"), "virtual_ip": format!("10.66.0.{id}"),
                    "inbound": true, "outbound": true, "endpoints": addr.iter().collect::<Vec<_>>(),
                })
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "network": { "name": "test", "domain": "test.i3t", "cidr": "10.66.0.0/16" },
            "me": { "id": me, "name": format!("n{me}"), "virtual_ip": format!("10.66.0.{me}"), "reach": reach },
            "peers": peers,
            "relays": [{ "id": 9, "key": i3t_proto::PublicKey::from_bytes([9; 32]), "name": "relay", "udp": ["127.0.0.1:9"] }],
        }))
        .unwrap()
    }

    struct TestNode {
        endpoint: Arc<Endpoint>,
        diag: Arc<Diag>,
        reports: mpsc::Receiver<TestReport>,
        netmap: watch::Sender<Arc<Netmap>>,
    }

    fn test_node(key: Arc<NodeKey>, netmap: Netmap, throughput: bool) -> TestNode {
        let (sender, receiver) = watch::channel(Arc::new(netmap));
        let endpoint = Arc::new(
            Endpoint::bind(EndpointConfig {
                key,
                bind: "127.0.0.1:0".parse().unwrap(),
                netmap: receiver.clone(),
                addr_servers: Vec::new(),
            })
            .unwrap(),
        );
        let (reports_tx, reports) = mpsc::channel(32);
        let diag = Arc::new(Diag::new(Arc::clone(&endpoint), receiver, throughput, reports_tx));
        TestNode { endpoint, diag, reports, netmap: sender }
    }

    fn order(test: u64, peer: u32, role: TestRole, items: TestItems) -> TestOrder {
        TestOrder { test, peer: node(peer), role, items, paths: Vec::new(), window_secs: 30 }
    }

    async fn next_report(reports: &mut mpsc::Receiver<TestReport>) -> TestReport {
        tokio::time::timeout(Duration::from_secs(60), reports.recv()).await.unwrap().unwrap()
    }

    fn peers(ids: std::ops::RangeInclusive<u32>) -> Vec<(u32, i3t_proto::PublicKey, Option<SocketAddr>)> {
        ids.map(|id| (id, i3t_proto::PublicKey::from_bytes([u8::try_from(id).unwrap(); 32]), None)).collect()
    }

    #[tokio::test]
    async fn an_order_is_refused_for_a_stranger_too_soon_after_the_last_one_or_beyond_the_concurrency_limit() {
        let mut tested = test_node(Arc::new(NodeKey::generate().unwrap()), netmap(1, &peers(2..=11), "any"), true);
        let quiet = TestItems::default();
        tested.diag.order(order(1, 99, TestRole::Initiator, quiet));
        let refused = next_report(&mut tested.reports).await;
        assert_eq!(refused.refused.map(|problem| (problem.code, problem.node)), Some((TestCode::NotConnected, Some(node(1)))));

        // 接受方的测试一直开着，直到结束或者时间窗到了。
        for peer in 2..=9 {
            tested.diag.order(order(u64::from(peer), peer, TestRole::Responder, quiet));
            assert!(next_report(&mut tested.reports).await.refused.is_none(), "第一次上报不是拒绝");
        }
        tested.diag.order(order(20, 10, TestRole::Responder, quiet));
        assert_eq!(next_report(&mut tested.reports).await.refused.map(|problem| problem.code), Some(TestCode::Busy), "同时最多 8 个");
        tested.diag.end(2);
        let last = next_report(&mut tested.reports).await;
        assert!(last.last && last.test == 2, "结束之后接受方报最后一次");
        tokio::time::sleep(Duration::from_millis(50)).await;
        tested.diag.order(order(21, 2, TestRole::Responder, quiet));
        assert_eq!(next_report(&mut tested.reports).await.refused.map(|problem| problem.code), Some(TestCode::TooSoon), "刚和 2 测过");
        tested.diag.order(order(22, 11, TestRole::Responder, quiet));
        assert!(next_report(&mut tested.reports).await.refused.is_none(), "腾出了一个位置，别的对端可以");
        drop(tested.netmap);
    }

    fn open(test: u64, path: Option<RelayPath>) -> OpenMeasure {
        OpenMeasure { test, mode: MeasureMode::Sink, path, bytes: 1000, millis: 1000 }
    }

    #[tokio::test]
    async fn a_measurement_stream_needs_a_responder_test_with_throughput_from_its_own_peer_and_runs_one_at_a_time() {
        let mut tested = test_node(Arc::new(NodeKey::generate().unwrap()), netmap(1, &peers(2..=3), "any"), true);
        let items = TestItems { throughput: true, ..TestItems::default() };
        tested.diag.order(order(5, 2, TestRole::Responder, items));
        tested.diag.order(order(6, 3, TestRole::Responder, TestItems::default()));
        next_report(&mut tested.reports).await;
        next_report(&mut tested.reports).await;

        assert!(tested.diag.expects_stream(node(2)) && !tested.diag.expects_stream(node(3)), "只有要吞吐的测试的对端");
        let denied = || Screening::Reset(Reason::AccessRevoked);
        assert_eq!(tested.diag.screening(node(2), 0, denied()), Screening::Admit, "测试期间读它的 OPEN");
        assert_eq!(tested.diag.screening(node(2), EXEMPT_STREAMS, denied()), denied(), "只放过几条");
        assert_eq!(tested.diag.screening(node(3), 0, denied()), denied(), "没有要吞吐的测试的对端照旧");
        let shutting_down = Screening::Reset(Reason::ShuttingDown);
        assert_eq!(tested.diag.screening(node(2), 0, shutting_down.clone()), shutting_down, "别的原因的重置不放过");
        let busy = Screening::Refuse(Reply::new(Status::NotEnabled, "忙"));
        assert_eq!(tested.diag.screening(node(2), 0, busy.clone()), busy);
        assert_eq!(tested.diag.admit_stream(node(3), &open(5, None)), Err(TestCode::Refused), "别的对端拿着这个编号");
        assert_eq!(tested.diag.admit_stream(node(2), &open(7, None)), Err(TestCode::Refused), "不认识的测试");
        assert_eq!(tested.diag.admit_stream(node(3), &open(6, None)), Err(TestCode::Refused), "这个测试没有要吞吐");
        let stranger = RelayPath::new(&[node(77)]).ok();
        assert_eq!(tested.diag.admit_stream(node(2), &open(5, stranger)), Err(TestCode::InvalidPath));
        assert_eq!(tested.diag.admit_stream(node(2), &open(5, RelayPath::new(&[node(9)]).ok())), Ok(()));
        assert_eq!(tested.diag.admit_stream(node(2), &open(5, None)), Err(TestCode::Busy), "同时一条");
        for _ in 1..MAX_STREAMS {
            drop(StreamSlot { diag: &tested.diag, test: 5 });
            assert_eq!(tested.diag.admit_stream(node(2), &open(5, None)), Ok(()));
        }
        drop(StreamSlot { diag: &tested.diag, test: 5 });
        assert_eq!(tested.diag.admit_stream(node(2), &open(5, None)), Err(TestCode::Busy), "一个测试最多 {MAX_STREAMS} 条");

        let switched_off = test_node(Arc::new(NodeKey::generate().unwrap()), netmap(1, &peers(2..=2), "any"), false);
        assert_eq!(switched_off.diag.admit_stream(node(2), &open(5, None)), Err(TestCode::ThroughputOff), "本机关掉了吞吐测试");
        let relay_only = test_node(Arc::new(NodeKey::generate().unwrap()), netmap(1, &peers(2..=2), "relay_only"), true);
        assert_eq!(relay_only.diag.admit_stream(node(2), &open(5, None)), Err(TestCode::RelayOnly));
    }

    #[tokio::test]
    async fn the_next_measurement_stream_waits_for_the_previous_one_to_finish_instead_of_being_refused() {
        let mut tested = test_node(Arc::new(NodeKey::generate().unwrap()), netmap(1, &peers(2..=2), "any"), true);
        tested.diag.order(order(5, 2, TestRole::Responder, TestItems { throughput: true, ..TestItems::default() }));
        next_report(&mut tested.reports).await;
        let stream = open(5, None);
        assert_eq!(tested.diag.admit_after_previous(node(2), &stream).await, Ok(()));

        // 上行那一条的结果已经发出去，发起方开来了下行那一条，这一头那条流的任务还没放开"正在测"。
        let finishing = StreamSlot { diag: &tested.diag, test: 5 };
        let (admitted, ()) = tokio::join!(tested.diag.admit_after_previous(node(2), &stream), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(finishing);
        });
        assert_eq!(admitted, Ok(()), "等上一条收完尾，不拒绝");

        // 真正同时开的两条照旧只接一条。
        let _measuring = StreamSlot { diag: &tested.diag, test: 5 };
        assert_eq!(tested.diag.admit_after_previous(node(2), &stream).await, Err(TestCode::Busy), "同时一条");
    }

    /// 只提供测量服务的处理者：两个节点之间不用出口。
    struct MeasureOnly(Arc<Diag>);

    impl Handler for MeasureOnly {
        async fn handle<S: SendStream, R: RecvStream>(&self, request: Request<S, R>) {
            request.refuse(&Reply::new(Status::NotEnabled, "只测量")).await;
        }

        async fn handle_measure<S: SendStream, R: RecvStream>(&self, request: MeasureRequest<S, R>) {
            self.0.serve(request).await;
        }
    }

    /// 两个互相知道地址的节点 1 和 2，节点 2 提供测量服务。`settings` 在各自的 netmap 交出去之前改网络的设置。
    fn measuring_pair(settings: impl Fn(&mut i3t_model::netmap::Network)) -> (TestNode, TestNode, tokio::task::JoinHandle<()>) {
        let keys = [Arc::new(NodeKey::generate().unwrap()), Arc::new(NodeKey::generate().unwrap())];
        let of = |me: u32, peer: u32, addr: Option<SocketAddr>| {
            let mut netmap = netmap(me, &[(peer, keys[usize::try_from(peer - 1).unwrap()].public(), addr)], "any");
            settings(&mut netmap.network);
            netmap
        };
        let a = test_node(Arc::clone(&keys[0]), of(1, 2, None), true);
        let b = test_node(Arc::clone(&keys[1]), of(2, 1, None), true);
        a.netmap.send_replace(Arc::new(of(1, 2, Some(b.endpoint.local_addr()))));
        b.netmap.send_replace(Arc::new(of(2, 1, Some(a.endpoint.local_addr()))));
        let serving = tokio::spawn({
            let (endpoint, handler) = (Arc::clone(&b.endpoint), Arc::new(MeasureOnly(Arc::clone(&b.diag))));
            async move { i3t_flow::serve(&*endpoint, handler).await }
        });
        (a, b, serving)
    }

    /// 全套的主动测试：直连、延迟、选路、吞吐、主机的状况。
    const EVERYTHING: TestItems =
        TestItems { direct: true, direct_quality: true, relay_quality: false, route: true, throughput: true, host: true };

    /// 在一对新的节点之间做一次全套的主动测试，返回吞吐的两个方向（上行、下行）。`settings` 改网络的设置。
    async fn measured_throughput(settings: impl Fn(&mut i3t_model::netmap::Network)) -> (Transfer, Transfer) {
        let (mut a, b, serving) = measuring_pair(settings);
        b.diag.order(order(41, 1, TestRole::Responder, EVERYTHING));
        a.diag.order(order(41, 2, TestRole::Initiator, EVERYTHING));
        let report = next_report(&mut a.reports).await;
        serving.abort();
        let throughput = report.paths[0].throughput.as_ref().unwrap();
        (throughput.up.unwrap(), throughput.down.unwrap())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_throughput_of_a_connection_does_not_hang_on_the_peers_acknowledgement_timer() {
        // 网络默认的确认阈值下，对端等确认的定时器再慢，吞吐也不受影响：窗口里总有够数的包，对端不等定时器就确认。
        // 这里把等待调到最长，代替定时器不准的对端：Windows 默认的粒度是十几毫秒，说好等 2 毫秒，实际等的是这个数。
        //
        // 快慢和同一次运行里默认等待的那一对比，不和钟表比：这二十兆在回环上要多久看机器，
        // 开发机上不到 0.2 秒，CI 上跑调试构建的 macOS 要一两秒，有一次用了 2.8 秒。
        let usual = measured_throughput(|_| {}).await;
        let patient = measured_throughput(|network| network.max_ack_delay_ms = 25).await;
        for (patient, usual) in [(patient.0, usual.0), (patient.1, usual.1)] {
            assert_eq!((usual.bytes, usual.stopped_by), (THROUGHPUT_BYTES, TransferEnd::Bytes), "{usual:?}");
            assert_eq!((patient.bytes, patient.stopped_by), (THROUGHPUT_BYTES, TransferEnd::Bytes), "{patient:?}");
            // 阈值比拥塞控制的最小窗口大的时候（默认值曾经是 10），不是每次都传不完，更多的时候是慢十倍上下：
            // 开发机上十次里有七八次至少一个方向要 1.4 到 5 秒。慢的机器上那就是传不完，上面一句已经管了。
            let unhurried = u64::from(usual.ms) * 4 + 500;
            assert!(u64::from(patient.ms) < unhurried, "对端等得久，传得就慢了：{patient:?}，平时是 {usual:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_nodes_find_their_direct_path_and_measure_its_latency_and_throughput_end_to_end() {
        let (mut a, mut b, serving) = measuring_pair(|_| {});
        let items = EVERYTHING;
        b.diag.order(order(40, 1, TestRole::Responder, items));
        a.diag.order(order(40, 2, TestRole::Initiator, items));
        let report = next_report(&mut a.reports).await;
        assert!(report.last && report.refused.is_none(), "{report:?}");
        let direct = report.direct.as_ref().unwrap();
        assert!(direct.ok && direct.kind.is_some(), "{direct:?}");
        let path = &report.paths[0];
        assert!(matches!(path.route, i3t_model::control::Route::Direct { .. }), "{path:?}");
        let latency = path.latency.unwrap();
        assert_eq!((latency.probes, latency.answered, latency.same_path), (TRAIN_PROBES, TRAIN_PROBES, TRAIN_PROBES), "{latency:?}");
        assert!(path.hops.len() == 1 && path.cost_us.is_some());
        let throughput = path.throughput.as_ref().unwrap();
        assert_eq!(throughput.failure, None, "{throughput:?}");
        let (up, down) = (throughput.up.unwrap(), throughput.down.unwrap());
        // 回环上很快：两个方向都在字节上限处停下。
        assert_eq!((up.bytes, up.stopped_by), (THROUGHPUT_BYTES, TransferEnd::Bytes), "{up:?}");
        assert_eq!((down.bytes, down.stopped_by), (THROUGHPUT_BYTES, TransferEnd::Bytes), "{down:?}");
        assert!(up.bits_per_second.is_some() && throughput.pinned, "{throughput:?}");
        assert_eq!((throughput.transport.as_str(), throughput.limit_bytes), ("quic", THROUGHPUT_BYTES));
        assert!(report.decision.is_some());
        // 主机的状况：到对端的那条连接是这个测试建起来的，计数里有量吞吐时两个方向的那些字节。
        let host = report.host.as_ref().expect("要了 host，发起方最后的上报里带着");
        let to_peer = host.to_peer.as_ref().expect("量过吞吐，连接在");
        assert!(matches!(to_peer.route, i3t_model::control::Route::Direct { .. }), "{to_peer:?}");
        assert!(to_peer.bytes_sent >= THROUGHPUT_BYTES && to_peer.bytes_received >= THROUGHPUT_BYTES, "{to_peer:?}");
        assert!(to_peer.sent_packets > 0 && to_peer.mtu >= 1200 && to_peer.rtt_us > 0 && !to_peer.congestion.is_empty(), "{to_peer:?}");
        let connections = host.connections.unwrap();
        assert_eq!((connections.peers, connections.relays, connections.relay_clients), (1, 0, None), "{connections:?}");
        let system = host.system.as_ref().unwrap();
        assert!(system.cores >= 1 && !system.arch.is_empty(), "{system:?}");
        if cfg!(target_os = "linux") {
            // 量了十秒左右的吞吐：头一秒和最忙的一秒都有，最忙的不比头一秒闲。
            let (first, peak) = (host.cpu.expect("Linux 上读得到 CPU"), host.cpu_peak.unwrap());
            assert!(peak.process_percent >= first.process_percent && peak.system_percent >= first.system_percent, "{first:?} {peak:?}");
            assert!(
                host.memory.is_some_and(|memory| memory.process_rss_bytes > 0 && memory.available_bytes <= memory.total_bytes),
                "{host:?}"
            );
            assert!(host.load_x100.is_some() && system.kernel.is_some() && system.uptime_secs.is_some(), "{host:?}");
            assert!(host.process.is_some_and(|process| process.threads.is_some_and(|threads| threads >= 1)), "{host:?}");
        }

        let first = next_report(&mut b.reports).await;
        assert!(!first.last && first.direct.as_ref().is_some_and(|direct| direct.ok), "{first:?}");
        assert!(first.host.is_none(), "只在最后一次上报里带");
        b.diag.end(40);
        let last = next_report(&mut b.reports).await;
        assert!(last.last && last.decision.is_some(), "{last:?}");
        assert!(last.host.as_ref().is_some_and(|host| host.to_peer.is_some() && host.connections.is_some()), "{last:?}");
        serving.abort();
    }
}
