//! 主动测试在 controller 这一侧：管理员发起测试，controller 检查、给两端下发同一个编号和参数，
//! 两端各自上报，controller 合成结果、存下来（每对节点留最近的 [`crate::store::KEEP_PER_PAIR`] 个），以及全网矩阵（`matrix`）。
//!
//! 规矩：
//!
//! - 同一对节点两次测试至少隔 [`MIN_INTERVAL`]，带吞吐的至少隔 [`THROUGHPUT_INTERVAL`]；同一对节点同时只有一个测试。
//!   节点自己也守着差不多的间隔，controller 被攻破时节点照样守得住。
//! - 指令发出之前就知道做不了的不发：节点不在线、版本太旧（[`TEST_REVISION`] 之前）、访问规则没有连通，整个测试直接失败，
//!   原因里说是哪个节点；只经 relay 的节点不参加直连的两项，只用直连的节点不参加 relay 的那项，在本地关掉了吞吐测试的不量吞吐，
//!   这些项标成"没有做"并说明原因。
//! - 发起方报完最后的结果之后，controller 告诉两端测试结束（`TestEnd`），接受方随即报它最后的那一份（它那个方向上两种模式的选择）。
//!   接受方 [`RESPONDER_GRACE`] 之内没有报，或者整个测试过了时间窗还没有报完，就按手上有的结束，缺的那一端在结果里写明。
//! - 节点掉线时，它参与的测试按手上有的结束。管理员可以取消进行中的测试，已经有的结果照样留着。
//! - 定时重复测试不做：这是个人用的工具，管理员需要时再点一次；历史结果留着可以对比。

mod matrix;
mod merge;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use i3t_model::admin::diag::{CreateTest, ItemState, TestItem, TestQuery, TestRequest, TestState, TestView};
use i3t_model::admin::{LogRef, NetworkId, action};
use i3t_model::control::diag::{TestCode, TestItems, TestProblem, TestRole};
use i3t_model::control::{TEST_REVISION, TestOrder, TestReport, ToNode};
use i3t_model::netmap::Reach;
use i3t_proto::NodeId;

pub(crate) use self::matrix::Matrix;
use self::merge::{Inputs, Skips, final_state, merge};
use serde_json::json;

use super::{Controller, Inner};
use crate::error::{Entity, Error, InField};
use crate::store::{NetworkRecord, NodeRecord, Store};

/// 同一对节点两次测试至少隔多久，带吞吐的至少隔多久。
const MIN_INTERVAL: Duration = Duration::from_secs(10);
const THROUGHPUT_INTERVAL: Duration = Duration::from_secs(30);
/// 发起方报完之后等接受方的最后一份最多等多久。
const RESPONDER_GRACE: Duration = Duration::from_secs(5);
/// 时间窗之外再给上报留的余量。
const REPORT_GRACE: Duration = Duration::from_secs(15);
/// 节点那边时间窗的上限是 150 秒，这里算出来的不超过它。
const MAX_WINDOW_SECS: u32 = 150;
/// 列测试时默认和最多给几个。
const DEFAULT_LIST: u32 = 20;
const MAX_LIST: u32 = 200;
/// 一个测试最多指定几条 relay 路径：和默认测的条数一样，加上直连，一个带吞吐的测试最多量三条路径、六条测量流。
const MAX_VIA: usize = 2;
/// 测试的结果、矩阵的下一对写不进存储时，隔多久再试。节点的每条消息都会叫醒后台任务，
/// 不隔开的话数据库出错期间每来一条消息就试一次、记一遍日志。
const STORE_RETRY: Duration = Duration::from_secs(5);

/// 进行中的测试和全网矩阵，只在内存里：controller 重启之后，进行中的测试在存储里显示成失败。
#[derive(Default)]
pub(crate) struct Diag {
    running: BTreeMap<u64, Running>,
    matrices: BTreeMap<NetworkId, Matrix>,
    next_matrix: u64,
    /// 每一对节点（编号小的在前）最近一次测试开始的时刻，和最近一次带吞吐的测试开始的时刻。
    last: BTreeMap<(NodeId, NodeId), (Instant, Option<Instant>)>,
}

impl Diag {
    /// 没有进行中的测试和矩阵：后台任务不用为它们醒来。
    pub(crate) fn is_idle(&self) -> bool {
        self.running.is_empty() && self.matrices.values().all(Matrix::is_finished)
    }
}

/// 一个进行中的测试。
struct Running {
    /// 结果的骨架：请求、两个节点、指令发出前就知道做不了的项。
    base: TestView,
    skips: Skips,
    initiator: Option<TestReport>,
    responder: Option<TestReport>,
    /// 到这个时刻还没报完就按手上有的结束。结果定下了、还没存下来时，是下一次再存的时刻。
    deadline: Instant,
    /// 发起方报完、controller 发出结束的时刻。
    ended: Option<Instant>,
    /// 第一次结束时定下的结果，连同结束的时刻。存不下来时它还留在进行中，后台任务原样再存，这期间来的上报不算数。
    outcome: Option<TestView>,
}

impl Running {
    fn view(&self, finished: bool) -> TestView {
        merge(&Inputs {
            base: &self.base,
            skips: &self.skips,
            initiator: self.initiator.as_ref(),
            responder: self.responder.as_ref(),
            finished,
        })
    }

    /// 给人看的样子：结束了的是定下的结果（还没存下来也一样），没结束的是到现在为止的。
    fn current(&self) -> TestView {
        self.outcome.clone().unwrap_or_else(|| self.view(false))
    }

    /// 后台任务什么时候要为它回来：结束它，或者再存一次定下的结果。
    fn due_at(&self) -> Instant {
        match (&self.outcome, self.ended) {
            (None, Some(ended)) => (ended + RESPONDER_GRACE).min(self.deadline),
            _ => self.deadline,
        }
    }
}

fn pair(a: NodeId, b: NodeId) -> (NodeId, NodeId) {
    (a.min(b), a.max(b))
}

impl Controller {
    /// 发起一个测试。做不了的测试也会建起来（状态是失败，原因里说是哪个节点），这样历史里看得到。
    ///
    /// # Errors
    ///
    /// 节点不在这个网络里（`not_found`）；请求不合法（`invalid_request`）；这一对节点刚测过或者正在测（`too_soon`、`busy`）。
    pub fn start_test(&self, network: NetworkId, input: &CreateTest) -> Result<TestView, Error> {
        let mut inner = self.lock();
        let record = inner.require_network(network)?;
        let (a, b) = (inner.require_node(network, input.a)?, inner.require_node(network, input.b)?);
        let request = inner.test_request(&record, input)?;
        inner.check_interval(a.id, b.id, request.throughput)?;
        let view = inner.begin_test(&record, &a, &b, request, None)?;
        self.wake_if_needed(&inner);
        Ok(view)
    }

    /// 一个测试：进行中的现在的样子，结束了的存下来的结果。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个测试。
    pub fn test(&self, network: NetworkId, id: u64) -> Result<TestView, Error> {
        let inner = self.lock();
        inner.require_network(network)?;
        if let Some(running) = inner.diag.running.get(&id).filter(|running| running.base.network == network) {
            return Ok(running.current());
        }
        inner.store.test(network, id)?.map(|view| inner.settled(view)).ok_or(Error::NotFound(Entity::Test))
    }

    /// 最近的测试，新的在前。写了 `a` 和 `b` 时只要这一对的。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者只写了 `a`、`b` 中的一个。
    pub fn tests(&self, network: NetworkId, query: &TestQuery) -> Result<Vec<TestView>, Error> {
        let inner = self.lock();
        inner.require_network(network)?;
        let pair = match (query.a, query.b) {
            (Some(a), Some(b)) => Some((a, b)),
            (None, None) => None,
            (Some(_), None) => return Err(Error::invalid_field("b", "missing", "要看一对节点的测试时 a 和 b 都要写")),
            (None, Some(_)) => return Err(Error::invalid_field("a", "missing", "要看一对节点的测试时 a 和 b 都要写")),
        };
        let limit = query.limit.unwrap_or(DEFAULT_LIST).clamp(1, MAX_LIST);
        let stored = inner.store.tests(network, pair, limit)?;
        Ok(stored
            .into_iter()
            .map(|view| match inner.diag.running.get(&view.id) {
                Some(running) => running.current(),
                None => inner.settled(view),
            })
            .collect())
    }

    /// 取消一个进行中的测试。已经有的结果照样留着。
    ///
    /// 操作记录和取消的结果在一个事务里存下来，存不下来时什么都没有变，可以再试。
    /// 随矩阵一起取消了、结果还没存下来的，再取消一次就是接着存。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个测试（`not_found`）；它已经结束了（`busy`）；读写存储失败。
    pub fn cancel_test(&self, network: NetworkId, id: u64) -> Result<TestView, Error> {
        let mut inner = self.lock();
        inner.require_network(network)?;
        let Some(running) = inner.diag.running.get(&id).filter(|running| running.base.network == network) else {
            return match inner.store.test(network, id)? {
                Some(_) => Err(Error::Busy(format!("测试 #{id} 已经结束了"))),
                None => Err(Error::NotFound(Entity::Test)),
            };
        };
        let finished = match running.outcome.as_ref().map(|outcome| outcome.state) {
            // 随矩阵一起取消了，结果还没存下来：接着存。
            Some(TestState::Cancelled) => inner.finish_test(id, true),
            // 已经因为别的原因结束了，只是结果还没存下来。
            Some(_) => return Err(Error::Busy(format!("测试 #{id} 已经结束了"))),
            None => {
                let (a, b) = (running.base.a.clone(), running.base.b.clone());
                let detail = format!("取消了节点 {} 和 {} 之间的主动测试 #{id}", a.name, b.name);
                let refs = [LogRef::node(a.id), LogRef::node(b.id)];
                let params = json!({ "test": id, "a": a.id, "a_name": a.name, "b": b.id, "b_name": b.name });
                let view = inner.outcome(id, true).ok_or(Error::NotFound(Entity::Test))?;
                let at = view.finished_at.unwrap_or_default();
                inner.store.atomically(|store| {
                    store.log_refs(at, Some(network), action::TEST_CANCEL, &detail, &refs, params)?;
                    store.update_test(&view)
                })?;
                inner.test_stored(&view);
                Ok(view)
            }
        };
        self.wake_if_needed(&inner);
        finished
    }
}

impl Inner {
    /// 把请求规整一遍：测试项去重排好，指定的路径要是这个网络里启用了的 relay、不超过最大中转级数。
    fn test_request(&self, network: &NetworkRecord, input: &CreateTest) -> Result<TestRequest, Error> {
        if input.a == input.b {
            return Err(Error::invalid_field("b", "same_node", "要测的是两个不同的节点"));
        }
        let mut items: Vec<TestItem> = input.items.clone().unwrap_or_else(|| TestItem::ALL.to_vec());
        if !input.via.is_empty() && !items.contains(&TestItem::RelayQuality) {
            items.push(TestItem::RelayQuality);
        }
        items.sort_unstable();
        items.dedup();
        if items.is_empty() {
            return Err(Error::invalid_field("items", "empty", "至少要做一项测试"));
        }
        if input.throughput && !items.iter().any(|item| matches!(item, TestItem::DirectQuality | TestItem::RelayQuality)) {
            return Err(Error::invalid_field("throughput", "needs_quality", "吞吐是在测质量的路径上量的：要同时测直连质量或者中继质量"));
        }
        if input.via.len() > MAX_VIA {
            return Err(Error::invalid_field("via", "too_many", format!("最多指定 {MAX_VIA} 条路径")));
        }
        for path in &input.via {
            if path.is_empty() || path.len() > usize::from(network.max_relay_hops) {
                return Err(Error::invalid_field(
                    "via",
                    "out_of_range",
                    format!("一条路径经过 1 到 {} 个中继（网络的最大中转级数）", network.max_relay_hops),
                ));
            }
            if path.iter().enumerate().any(|(index, relay)| path[..index].contains(relay)) {
                return Err(Error::invalid_field("via", "duplicate", "一条路径里同一个中继不能出现两次"));
            }
            for relay in path {
                let node = self.require_node(network.id, *relay).in_field("via")?;
                if node.relay.is_none() {
                    return Err(Error::invalid_field("via", "not_relay", format!("节点 {} 没有启用为中继，不能出现在路径里", node.name)));
                }
            }
        }
        Ok(TestRequest { items, throughput: input.throughput, via: input.via.clone() })
    }

    /// 这一对节点能不能现在测：没有正在进行的测试，离上一次足够久。
    fn check_interval(&self, a: NodeId, b: NodeId, throughput: bool) -> Result<(), Error> {
        let key = pair(a, b);
        if self.diag.running.values().any(|running| pair(running.base.a.id, running.base.b.id) == key) {
            return Err(Error::Busy("这一对节点正在测试，等它结束或者取消它".to_owned()));
        }
        let now = Instant::now();
        let Some(&(started, with_throughput)) = self.diag.last.get(&key) else { return Ok(()) };
        let wait = MIN_INTERVAL.saturating_sub(now.saturating_duration_since(started));
        let wait = match with_throughput.filter(|_| throughput) {
            Some(at) => wait.max(THROUGHPUT_INTERVAL.saturating_sub(now.saturating_duration_since(at))),
            None => wait,
        };
        if wait.is_zero() {
            return Ok(());
        }
        Err(Error::TooSoon(format!("这一对节点刚测过，{} 秒之后再试", wait.as_secs().max(1))))
    }

    /// 整个测试做不了的原因：有一端不在线、版本太旧，或者访问规则没有把它们连通。
    fn test_blocker(&self, a: &NodeRecord, b: &NodeRecord) -> Option<TestProblem> {
        for node in [a, b] {
            match self.live.get(&node.id) {
                None => return Some(TestProblem::new(TestCode::NodeOffline, Some(node.id))),
                Some(live) if live.protocol < TEST_REVISION => return Some(TestProblem::new(TestCode::NotSupported, Some(node.id))),
                Some(_) => {}
            }
        }
        let knows = |from: &NodeRecord, to: &NodeRecord| self.sync.get(&from.id).is_some_and(|sync| sync.knows(to.id));
        (!knows(a, b) || !knows(b, a)).then(|| TestProblem::new(TestCode::NotConnected, None))
    }

    /// 指令发出前就知道做不了的项。
    fn test_skips(&self, network: &NetworkRecord, a: &NodeRecord, b: &NodeRecord, request: &TestRequest) -> Result<Skips, Error> {
        let reach = |node: &NodeRecord| node.reach.unwrap_or(network.reach);
        let blamed = |wanted: Reach, code: TestCode| {
            [a, b].into_iter().find(|node| reach(node) == wanted).map(|node| TestProblem::new(code, Some(node.id)))
        };
        let has_relay = self.store.nodes(network.id)?.iter().any(|node| node.relay.is_some());
        let relay = blamed(Reach::DirectOnly, TestCode::DirectOnly)
            .or_else(|| (request.via.is_empty() && !has_relay).then(|| TestProblem::new(TestCode::NoRelay, None)));
        let throughput = [a, b]
            .into_iter()
            .find(|node| self.live.get(&node.id).is_some_and(|live| !live.throughput_tests))
            .map(|node| TestProblem::new(TestCode::ThroughputOff, Some(node.id)));
        Ok(Skips { direct: blamed(Reach::RelayOnly, TestCode::RelayOnly), relay, throughput })
    }

    /// 建起一个测试并下发指令。调用前已经查过间隔。
    ///
    /// 出错时什么都没有变：存储里没有这个测试，没有指令发出去，可以原样再试。
    pub(super) fn begin_test(
        &mut self,
        network: &NetworkRecord,
        a: &NodeRecord,
        b: &NodeRecord,
        request: TestRequest,
        matrix: Option<u64>,
    ) -> Result<TestView, Error> {
        let started_at = self.clock.now();
        let mut view = TestView {
            id: 0,
            network: network.id,
            a: a.to_ref(),
            b: b.to_ref(),
            state: TestState::Running,
            request,
            started_at,
            finished_at: None,
            matrix,
            error: None,
            direct: None,
            direct_quality: None,
            relay_quality: Vec::new(),
            route: None,
            hosts: None,
            notes: Vec::new(),
        };
        let wants = |item| view.request.items.contains(&item);
        let skips = self.test_skips(network, a, b, &view.request)?;
        let items = TestItems {
            direct: wants(TestItem::Direct) && skips.direct.is_none(),
            direct_quality: wants(TestItem::DirectQuality) && skips.direct.is_none(),
            relay_quality: wants(TestItem::RelayQuality) && skips.relay.is_none(),
            route: wants(TestItem::Route),
            throughput: false,
            host: wants(TestItem::Host),
        };
        let items = TestItems {
            throughput: view.request.throughput && skips.throughput.is_none() && (items.direct_quality || items.relay_quality),
            ..items
        };
        let blocker = self.test_blocker(a, b);
        let nothing_to_do = !(items.direct || items.direct_quality || items.relay_quality || items.route || items.host);
        if blocker.is_some() || nothing_to_do {
            // 指令不用发：要么做不了，要么每一项都事先知道做不了。
            view.state = if blocker.is_some() { TestState::Failed } else { TestState::Done };
            view.error.clone_from(&blocker);
            view.finished_at = Some(started_at);
            // 整个测试做不了时，每一项都是"没有做"，原因就是那一条。
            let skips = match &blocker {
                Some(problem) => Skips { direct: Some(problem.clone()), relay: Some(problem.clone()), throughput: Some(problem.clone()) },
                None => skips,
            };
            let running = Running {
                base: view.clone(),
                skips,
                initiator: None,
                responder: None,
                deadline: Instant::now(),
                ended: None,
                outcome: None,
            };
            let mut view = TestView { state: view.state, error: view.error.clone(), finished_at: view.finished_at, ..running.view(false) };
            if let Some(route) = view.route.as_mut().filter(|route| route.state == ItemState::Pending) {
                route.state = ItemState::Skipped;
                route.problem.clone_from(&blocker);
            }
            for host in view.hosts.iter_mut().flatten().filter(|host| host.state == ItemState::Pending) {
                host.state = ItemState::Skipped;
                host.problem.clone_from(&blocker);
            }
            // 编号要等插进去才有，所以插完再改一次。几笔写在一个事务里，出错时什么都没有留下。
            self.store.atomically(|store| {
                view.id = store.insert_test(&view)?;
                store.update_test(&view)?;
                Self::log_test(store, &view)
            })?;
            return Ok(view);
        }
        // 插进去的这一行和操作记录在一个事务里：出错时存储里没有这个测试，矩阵再排这一对时不会多出一条"没做完"的。
        self.store.atomically(|store| {
            view.id = store.insert_test(&view)?;
            Self::log_test(store, &view)
        })?;
        let window = window_secs(&items, &view.request);
        let (id, paths) = (view.id, view.request.via.clone());
        let order = |peer: NodeId, role| TestOrder { test: id, peer, role, items, paths: paths.clone(), window_secs: window };
        tracing::info!(test = view.id, a = %a.id, b = %b.id, ?items, window_secs = window, "开始主动测试");
        let now = Instant::now();
        self.diag.last.insert(pair(a.id, b.id), (now, items.throughput.then_some(now)));
        // 接受方先拿到指令：发起方的第一个探测到的时候，它的时间窗已经开着了。
        let sent = self.send(b.id, ToNode::Test(Box::new(order(a.id, TestRole::Responder))))
            && self.send(a.id, ToNode::Test(Box::new(order(b.id, TestRole::Initiator))));
        // 发送失败会把那个节点记为离线。测试发完了才算进行中，所以不会在发的时候就被掉线结束掉，返回一个已经不在的"进行中"；
        // 发不出去的测试下面就结束它。
        let deadline = now + Duration::from_secs(u64::from(window)) + REPORT_GRACE;
        let running = Running { base: view, skips, initiator: None, responder: None, deadline, ended: None, outcome: None };
        let started = running.view(false);
        self.diag.running.insert(id, running);
        if sent {
            return Ok(started);
        }
        match self.finish_test(id, false) {
            Ok(view) => Ok(view),
            // 测试已经建起来了，不算开始失败：结果定下了，后台任务接着存。
            Err(error) => {
                tracing::warn!(test = id, "存发不出去的主动测试的结果时出错，{} 秒后再试：{error}", STORE_RETRY.as_secs());
                Ok(self.diag.running.get(&id).map_or(started, Running::current))
            }
        }
    }

    fn log_test(store: &Store, view: &TestView) -> Result<(), Error> {
        let items: Vec<&str> = view
            .request
            .items
            .iter()
            .map(|item| match item {
                TestItem::Direct => "直连能力",
                TestItem::DirectQuality => "直连质量",
                TestItem::RelayQuality => "中继质量",
                TestItem::Route => "选路",
                TestItem::Host => "主机和连接",
            })
            .collect();
        let throughput = if view.request.throughput { "，含吞吐" } else { "" };
        let detail = format!("节点 {} 和 {} 之间的主动测试 #{}：{}{throughput}", view.a.name, view.b.name, view.id, items.join("、"));
        let refs = [LogRef::node(view.a.id), LogRef::node(view.b.id)];
        let params = json!({
            "test": view.id,
            "a": view.a.id,
            "a_name": view.a.name,
            "b": view.b.id,
            "b_name": view.b.name,
            "items": view.request.items,
            "throughput": view.request.throughput,
            "matrix": view.matrix,
        });
        store.log_refs(view.started_at, Some(view.network), action::TEST_START, &detail, &refs, params)?;
        Ok(())
    }

    /// 节点报来一个测试的结果。不是这个测试的两端、或者角色不对的不算数。
    pub(super) fn test_reported(&mut self, node: NodeId, report: TestReport) -> Result<(), Error> {
        let id = report.test;
        let Some(running) = self.diag.running.get_mut(&id) else {
            tracing::debug!(%node, test = id, "丢掉一份测试结果：没有在进行这个测试（多半已经结束了）");
            return Ok(());
        };
        if running.outcome.is_some() {
            tracing::debug!(%node, test = id, "丢掉一份测试结果：这个测试已经结束了，结果在等着存下来");
            return Ok(());
        }
        let role = if node == running.base.a.id {
            TestRole::Initiator
        } else if node == running.base.b.id {
            TestRole::Responder
        } else {
            tracing::debug!(%node, test = id, "丢掉一份测试结果：报的节点不是这个测试的两端");
            return Ok(());
        };
        if report.role.is_some_and(|reported| reported != role) {
            tracing::debug!(%node, test = id, "丢掉一份测试结果：角色对不上");
            return Ok(());
        }
        let refused = report.refused.is_some();
        let last = report.last;
        match role {
            TestRole::Initiator => running.initiator = Some(report),
            // 接受方的最后一份之后再来的（不该有）不覆盖它。
            TestRole::Responder if running.responder.as_ref().is_none_or(|known| !known.last) => running.responder = Some(report),
            TestRole::Responder => {}
        }
        let initiator_done = running.initiator.as_ref().is_some_and(|report| report.last);
        let responder_done = running.responder.as_ref().is_some_and(|report| report.last);
        tracing::info!(test = id, %node, ?role, last, refused, "收到主动测试的结果");
        if refused || (initiator_done && responder_done) {
            self.finish_test(id, false)?;
        } else if initiator_done && running.ended.is_none() {
            // 发起方量完了：告诉接受方结束，它随即报最后的一份。
            running.ended = Some(Instant::now());
            let responder = running.base.b.id;
            self.send(responder, ToNode::TestEnd { test: id });
        } else {
            self.store_progress(id)?;
        }
        Ok(())
    }

    /// 进行中的测试的中间结果也存一份：界面轮询的是内存里的，存储里的只是为了 controller 意外退出时少丢一点。
    fn store_progress(&self, id: u64) -> Result<(), Error> {
        if let Some(running) = self.diag.running.get(&id) {
            self.store.update_test(&running.view(false))?;
        }
        Ok(())
    }

    /// 结束一个测试：合成最后的结果、存下来、告诉两端结束。`cancelled` 是管理员取消的。
    ///
    /// 结果在第一次结束时定下来，连同结束的时刻；之后再调用只是把它再存一次，`cancelled` 不再起作用。
    /// 存不下来时别的都没有变：它还在进行中，过 [`STORE_RETRY`] 后台任务再存，这期间来的上报不算数。
    pub(super) fn finish_test(&mut self, id: u64, cancelled: bool) -> Result<TestView, Error> {
        let view = self.fix_outcome(id, cancelled).ok_or(Error::NotFound(Entity::Test))?;
        if let Err(error) = self.store.update_test(&view) {
            if let Some(running) = self.diag.running.get_mut(&id) {
                running.deadline = Instant::now() + STORE_RETRY;
            }
            return Err(error.into());
        }
        self.test_stored(&view);
        Ok(view)
    }

    /// 测试现在结束的话是什么结果：合成到现在为止的上报，结束的时刻是现在。
    fn outcome(&self, id: u64, cancelled: bool) -> Option<TestView> {
        let running = self.diag.running.get(&id)?;
        let (state, error) = final_state(cancelled, running.initiator.as_ref(), running.responder.as_ref());
        let error = error.or_else(|| (state == TestState::Failed).then(|| TestProblem::new(TestCode::NoReport, Some(running.base.a.id))));
        Some(TestView { state, error, finished_at: Some(self.clock.now()), ..running.view(true) })
    }

    /// 把测试的结果定下来，已经定下的不变。
    pub(super) fn fix_outcome(&mut self, id: u64, cancelled: bool) -> Option<TestView> {
        if let Some(outcome) = &self.diag.running.get(&id)?.outcome {
            return Some(outcome.clone());
        }
        let outcome = self.outcome(id, cancelled)?;
        self.diag.running.get_mut(&id)?.outcome = Some(outcome.clone());
        Some(outcome)
    }

    /// 测试的结果存下来了：从进行中拿掉，告诉两端结束，记进矩阵。
    fn test_stored(&mut self, view: &TestView) {
        let id = view.id;
        self.diag.running.remove(&id);
        tracing::info!(test = id, state = ?view.state, "主动测试结束");
        for node in [view.a.id, view.b.id] {
            if self.live.contains_key(&node) {
                self.send(node, ToNode::TestEnd { test: id });
            }
        }
        if let Some(matrix) = view.matrix {
            self.matrix_test_finished(view.network, matrix, view);
        }
    }

    /// 存储里的一个测试：进行中的却不在内存里，是 controller 重启前没做完的，显示成失败。
    fn settled(&self, view: TestView) -> TestView {
        if view.state != TestState::Running {
            return view;
        }
        let problem =
            TestProblem { code: TestCode::Internal, node: None, message: "controller 重启过，这个测试没有做完".to_owned() };
        TestView { state: TestState::Failed, error: Some(problem), ..view }
    }

    /// 到点了的：过了时间窗还没报完的测试按手上有的结束；接受方迟迟不报最后一份的也结束；结果没存下来的再存；
    /// 矩阵里排着的接着开始。返回下一次最晚什么时候再来看。
    ///
    /// 存储出错不算这里出错：记下日志，存不下来的测试、开始不了的矩阵各自隔 [`STORE_RETRY`] 再试，
    /// 一个出错不耽误别的，也不让后台任务丢掉别的工作要它回来的时刻。
    pub(super) fn tests_tick(&mut self, now: Instant) -> Option<Instant> {
        for id in self.time_out_tests(now) {
            // 前面结束的测试给节点发结束时，节点可能掉线，连带结束了这一个。
            if !self.diag.running.contains_key(&id) {
                continue;
            }
            if let Err(error) = self.finish_test(id, false) {
                tracing::warn!(test = id, "存主动测试的结果时出错，{} 秒后再试：{error}", STORE_RETRY.as_secs());
            }
        }
        self.schedule_matrices(now);
        let next = self.diag.running.values().map(Running::due_at).min();
        let cooling = self.matrix_wake(now);
        [next, cooling].into_iter().flatten().min()
    }

    /// 到点了的测试里还没结束的，按手上的结果定下来，返回到点了的测试。只改内存、不碰存储：
    /// 整个数据库都读写不了、后台任务这一轮不存测试结果时也要做，定下之后来的上报就不算数了（见 [`Inner::test_reported`]），
    /// 不然一个已经超时、本该算失败的测试，会被迟到的上报记成做完了。结果等能存了再存。
    pub(super) fn time_out_tests(&mut self, now: Instant) -> Vec<u64> {
        let due: Vec<u64> = self.diag.running.iter().filter(|(_, running)| now >= running.due_at()).map(|(id, _)| *id).collect();
        for &id in &due {
            if self.diag.running.get(&id).is_some_and(|running| running.outcome.is_none()) {
                tracing::info!(test = id, "主动测试到时间了，按手上的结果结束");
                self.fix_outcome(id, false);
                // 定下之后它只看 `deadline`（见 `Running::due_at`）。因为接受方过了宽限期才结束的，原来的时间窗可能还早：
                // 收到现在，能存了马上就存，不用等到时间窗结束才放开这一对节点。
                if let Some(running) = self.diag.running.get_mut(&id) {
                    running.deadline = running.deadline.min(now);
                }
            }
        }
        due
    }

    /// 节点掉线了：它参与的测试不会再有它的结果，按手上有的结束。
    pub(crate) fn tests_node_gone(&mut self, node: NodeId) {
        let involved: Vec<u64> = self
            .diag
            .running
            .iter()
            .filter(|(_, running)| running.base.a.id == node || running.base.b.id == node)
            .map(|(id, _)| *id)
            .collect();
        for id in involved {
            // 前面结束的测试给另一端发结束时，那一端也可能掉线，连带结束了这一个。
            if !self.diag.running.contains_key(&id) {
                continue;
            }
            tracing::info!(test = id, %node, "节点掉线，主动测试按手上的结果结束");
            if let Err(error) = self.finish_test(id, false) {
                tracing::warn!(test = id, "存主动测试的结果时出错，{} 秒后再试：{error}", STORE_RETRY.as_secs());
            }
        }
    }
}

/// 给节点的时间窗多长：每一项大概要多久，加起来，不超过节点的上限。
fn window_secs(items: &TestItems, request: &TestRequest) -> u32 {
    // 直连尝试 8 秒；一列探测 2 秒，等路径就绪最多 6 秒；吞吐上下行各 5 秒加收尾。
    let throughput = if items.throughput { 20 } else { 0 };
    let paths = if request.via.is_empty() { 2 } else { u32::try_from(request.via.len()).unwrap_or(4) };
    let mut window = 10;
    if items.direct || items.direct_quality {
        window += 10;
    }
    if items.direct_quality {
        window += 4 + throughput;
    }
    if items.relay_quality {
        window += 6 + paths * (4 + throughput);
    }
    if items.route {
        window += 2;
    }
    window.min(MAX_WINDOW_SECS)
}

#[cfg(test)]
mod tests {
    use i3t_model::admin::UpdateNode;
    use i3t_model::admin::diag::{CellState, ItemState, MatrixState, TestItem};
    use i3t_model::control::diag::{Choice, ChoiceCode, CpuUse, Decision, DirectSide, HostReport, Latency, PathMeasure, PathPick};
    use i3t_model::control::{Declared, DirectKind, Hello, Route, ToController};

    use super::*;
    use crate::controller::testing::{Lab, Member, REMOTE, hello, modern_hello};

    fn two_nodes() -> (Lab, NetworkId, Member, Member) {
        let mut lab = Lab::new();
        let network = lab.network("home").id;
        let mut a = lab.join_as(network, &modern_hello("0.2.0"));
        let mut b = lab.join_as(network, &modern_hello("0.2.0"));
        lab.settle(&mut [&mut a, &mut b]);
        (lab, network, a, b)
    }

    fn request(a: &Member, b: &Member) -> CreateTest {
        CreateTest { a: a.id, b: b.id, items: None, throughput: false, via: Vec::new() }
    }

    fn decision() -> Decision {
        let choice = Choice {
            route: Some(Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() }),
            reason: ChoiceCode::Direct,
            cost_us: Some(12_000),
            cheaper: None,
        };
        Decision { mode: None, current: None, direct_first: choice.clone(), lowest_cost: choice, candidates: Vec::new() }
    }

    fn initiator_report(test: u64) -> TestReport {
        let side = DirectSide { ok: true, kind: Some(DirectKind::Punched), elapsed_ms: Some(640), ..DirectSide::default() };
        let path = PathMeasure {
            route: Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() },
            picked_by: vec![PathPick::Direct],
            failure: None,
            latency: Some(Latency { probes: 100, answered: 100, avg_us: Some(12_000), ..Latency::default() }),
            cost_us: Some(12_000),
            hops: Vec::new(),
            relay_leg: None,
            throughput: None,
        };
        TestReport {
            test,
            role: Some(TestRole::Initiator),
            last: true,
            direct: Some(side),
            paths: vec![path],
            decision: Some(decision()),
            ..TestReport::default()
        }
    }

    fn responder_report(test: u64, last: bool) -> TestReport {
        let side = DirectSide { ok: true, kind: Some(DirectKind::Punched), ..DirectSide::default() };
        TestReport {
            test,
            role: Some(TestRole::Responder),
            last,
            direct: Some(side),
            decision: last.then(decision),
            ..TestReport::default()
        }
    }

    fn send(lab: &Lab, member: &Member, report: TestReport) {
        member.send(&lab.controller, ToController::TestReport(Box::new(report)));
    }

    #[test]
    fn each_end_s_host_report_fills_its_entry_and_an_end_without_one_is_not_supported() {
        let (lab, network, mut a, mut b) = two_nodes();
        let only_host = CreateTest { items: Some(vec![TestItem::Host]), ..request(&a, &b) };
        let view = lab.controller.start_test(network, &only_host).unwrap();
        let states = |view: &TestView| view.hosts.iter().flatten().map(|host| (host.node, host.state)).collect::<Vec<_>>();
        assert_eq!(states(&view), [(a.id, ItemState::Pending), (b.id, ItemState::Pending)], "a 在前");
        a.receive();
        b.receive();
        let order = a.tests[0].items;
        assert!(order.host && !order.direct && !order.direct_quality && !order.relay_quality && !order.route, "{order:?}");
        assert_eq!(b.tests[0].items, order);

        let host = HostReport { cpu_peak: Some(CpuUse { system_percent: 61, process_percent: 98 }), ..HostReport::default() };
        let last = |role, host| TestReport { test: view.id, role: Some(role), last: true, host, ..TestReport::default() };
        send(&lab, &a, last(TestRole::Initiator, Some(host.clone())));
        assert_eq!(states(&lab.controller.test(network, view.id).unwrap()), [(a.id, ItemState::Done), (b.id, ItemState::Pending)]);
        // b 是没有这一项的旧版本：它最后的一次上报里什么都没带。
        send(&lab, &b, last(TestRole::Responder, None));
        let done = lab.controller.test(network, view.id).unwrap();
        assert_eq!(done.state, TestState::Done);
        let hosts = done.hosts.unwrap();
        assert_eq!((hosts[0].state, &hosts[0].problem, &hosts[0].report), (ItemState::Done, &None, &host));
        assert_eq!(hosts[1].state, ItemState::Skipped);
        assert_eq!(hosts[1].problem.as_ref().map(|problem| (problem.code, problem.node)), Some((TestCode::NotSupported, Some(b.id))));
        assert_eq!(hosts[1].report, HostReport::default());
    }

    #[test]
    fn a_test_gives_both_ends_the_same_id_and_merges_what_they_report() {
        let (lab, network, mut a, mut b) = two_nodes();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        assert_eq!((view.state, view.request.items.len()), (TestState::Running, 5));
        assert_eq!(view.direct.as_ref().map(|direct| direct.state), Some(ItemState::Pending));
        a.receive();
        b.receive();
        let (to_a, to_b) = (&a.tests[0], &b.tests[0]);
        assert_eq!((to_a.test, to_a.peer, to_a.role), (view.id, b.id, TestRole::Initiator));
        assert_eq!((to_b.test, to_b.peer, to_b.role), (view.id, a.id, TestRole::Responder));
        assert_eq!(to_a.items, to_b.items);
        assert!(to_a.items.direct && to_a.items.route && !to_a.items.throughput);

        send(&lab, &b, responder_report(view.id, false));
        assert_eq!(lab.controller.test(network, view.id).unwrap().state, TestState::Running);
        send(&lab, &a, initiator_report(view.id));
        b.receive();
        assert_eq!(b.test_ends, [view.id], "发起方报完之后接受方被告知结束");
        send(&lab, &b, responder_report(view.id, true));
        let done = lab.controller.test(network, view.id).unwrap();
        assert_eq!(done.state, TestState::Done);
        assert!(done.finished_at.is_some());
        let direct = done.direct.unwrap();
        assert!(direct.ok && direct.kind == Some(DirectKind::Punched) && direct.elapsed_ms == Some(640));
        assert_eq!(done.direct_quality.unwrap().latency.and_then(|latency| latency.avg_us), Some(12_000));
        let route = done.route.unwrap();
        assert!(route.forward.is_some() && route.reverse.is_some());
        a.receive();
        assert_eq!(a.test_ends, [view.id]);

        let listed = lab.controller.tests(network, &TestQuery { a: Some(b.id), b: Some(a.id), limit: None }).unwrap();
        assert_eq!(listed.iter().map(|view| view.id).collect::<Vec<_>>(), [view.id], "先后无所谓");
        let log = lab.controller.oplog(5).unwrap();
        assert!(log.iter().any(|entry| entry.action == "test.start"), "{log:?}");
        // 别人冒充着报的、报错了测试的，都不算数。
        send(&lab, &a, initiator_report(view.id));
        assert_eq!(lab.controller.test(network, view.id).unwrap().direct_quality.unwrap().state, ItemState::Done);
    }

    #[test]
    fn a_test_that_cannot_run_fails_at_once_and_says_which_node() {
        let (mut lab, network, a, b) = two_nodes();
        let mut old = lab.join_as(network, &hello(Declared::default()));
        lab.settle(&mut [&mut old]);
        let view = lab.controller.start_test(network, &CreateTest { b: old.id, ..request(&a, &b) }).unwrap();
        assert_eq!(view.direct.as_ref().map(|direct| direct.state), Some(ItemState::Skipped), "每一项都没有做，原因同上");
        assert_eq!(view.route.as_ref().and_then(|route| route.problem.as_ref()).map(|problem| problem.code), Some(TestCode::NotSupported));
        assert_eq!(
            (view.state, view.error.map(|problem| (problem.code, problem.node))),
            (TestState::Failed, Some((TestCode::NotSupported, Some(old.id))))
        );
        old.receive();
        assert!(old.tests.is_empty(), "旧节点不懂这条消息，不发给它");

        let offline = lab.join_offline(network, &[], Declared::default());
        let view = lab.controller.start_test(network, &CreateTest { b: offline, ..request(&a, &b) }).unwrap();
        assert_eq!(view.error.map(|problem| (problem.code, problem.node)), Some((TestCode::NodeOffline, Some(offline))));
        assert!(view.finished_at.is_some());
    }

    #[test]
    fn nodes_the_access_rules_keep_apart_are_not_tested() {
        let (lab, network, mut a, mut b) = two_nodes();
        for rule in lab.controller.rules(network).unwrap() {
            lab.controller.delete_rule(network, rule.id).unwrap();
        }
        lab.settle(&mut [&mut a, &mut b]);
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        assert_eq!(view.error.map(|problem| problem.code), Some(TestCode::NotConnected));
    }

    #[test]
    fn items_a_node_would_refuse_are_skipped_with_the_reason_and_left_out_of_the_order() {
        let mut lab = Lab::new();
        let network = lab.network("home").id;
        let mut a = lab.join_as(network, &modern_hello("0.2.0"));
        let mut b = lab.join_as(network, &Hello { throughput_tests: false, ..modern_hello("0.2.0") });
        lab.settle(&mut [&mut a, &mut b]);
        lab.controller.update_node(network, b.id, &UpdateNode { reach: Some(Some(Reach::RelayOnly)), ..UpdateNode::default() }).unwrap();
        lab.settle(&mut [&mut a, &mut b]);
        let view = lab.controller.start_test(network, &CreateTest { throughput: true, ..request(&a, &b) }).unwrap();
        let direct = view.direct.unwrap();
        assert_eq!(
            (direct.state, direct.problem.map(|problem| (problem.code, problem.node))),
            (ItemState::Skipped, Some((TestCode::RelayOnly, Some(b.id))))
        );
        assert_eq!(view.relay_quality[0].problem.as_ref().map(|problem| problem.code), Some(TestCode::NoRelay), "网络里没有 relay");
        a.receive();
        let order = &a.tests[0].items;
        assert!(!order.direct && !order.direct_quality && !order.relay_quality && order.route && !order.throughput, "{order:?}");
        let skips = lab.controller.lock().diag.running[&view.id].skips.clone();
        assert_eq!(skips.throughput.map(|problem| (problem.code, problem.node)), Some((TestCode::ThroughputOff, Some(b.id))));
    }

    #[test]
    fn the_same_pair_waits_between_tests_and_a_running_test_blocks_another() {
        let (lab, network, a, b) = two_nodes();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        assert!(matches!(lab.controller.start_test(network, &request(&b, &a)), Err(Error::Busy(_))));
        lab.controller.cancel_test(network, view.id).unwrap();
        assert!(matches!(lab.controller.start_test(network, &request(&a, &b)), Err(Error::TooSoon(_))));
        // 十秒之后可以了；带吞吐的要三十秒。
        let earlier = Instant::now().checked_sub(Duration::from_secs(11)).unwrap();
        lab.controller.lock().diag.last.insert(pair(a.id, b.id), (earlier, Some(earlier)));
        assert!(matches!(lab.controller.start_test(network, &CreateTest { throughput: true, ..request(&a, &b) }), Err(Error::TooSoon(_))));
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        assert_eq!(view.state, TestState::Running);
        assert!(matches!(
            lab.controller.start_test(network, &CreateTest { a: a.id, b: a.id, ..request(&a, &b) }),
            Err(Error::InField { .. })
        ));
    }

    #[test]
    fn a_test_ends_with_what_it_has_when_time_runs_out_a_node_goes_away_or_it_is_cancelled() {
        let (mut lab, network, mut a, b) = two_nodes();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        send(&lab, &a, initiator_report(view.id));
        // 接受方一直不报最后一份：过了宽限就按手上有的结束，结果里写明缺了谁。
        let past = Instant::now().checked_sub(RESPONDER_GRACE).unwrap();
        lab.controller.lock().diag.running.get_mut(&view.id).unwrap().ended = Some(past);
        lab.controller.tick().unwrap();
        let done = lab.controller.test(network, view.id).unwrap();
        assert_eq!(done.state, TestState::Done);
        assert_eq!(done.notes.iter().map(|note| (note.code, note.node)).collect::<Vec<_>>(), [(TestCode::NoReport, Some(b.id))]);

        lab.controller.lock().diag.last.clear();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        lab.controller.disconnect(b.session);
        let gone = lab.controller.test(network, view.id).unwrap();
        assert_eq!((gone.state, gone.error.map(|problem| problem.code)), (TestState::Failed, Some(TestCode::NoReport)), "发起方什么都没报");

        let b = lab.connect_as(b.key, &modern_hello("0.2.0")).unwrap();
        lab.controller.lock().diag.last.clear();
        a.receive();
        let started = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        let cancelled = lab.controller.cancel_test(network, started.id).unwrap();
        assert_eq!(cancelled.state, TestState::Cancelled);
        a.receive();
        assert!(a.test_ends.contains(&started.id), "取消时两端都被告知结束");
        assert!(matches!(lab.controller.cancel_test(network, started.id), Err(Error::Busy(_))), "已经结束了");
        assert!(matches!(lab.controller.cancel_test(network, 9999), Err(Error::NotFound(Entity::Test))));
    }

    #[test]
    fn the_matrix_tests_every_reachable_pair_never_more_than_four_at_a_time() {
        let mut lab = Lab::new();
        let network = lab.network("home").id;
        let mut members: Vec<Member> = (0..6).map(|_| lab.join_as(network, &modern_hello("0.2.0"))).collect();
        let offline = lab.join_offline(network, &[], Declared::default());
        lab.settle(&mut members.iter_mut().collect::<Vec<_>>());
        let run = lab.controller.start_matrix(network).unwrap();
        assert_eq!((run.total, run.concurrency), (21, 4), "七个节点二十一对");
        let skipped: Vec<&i3t_model::admin::diag::MatrixCell> = run.cells.iter().filter(|cell| cell.state == CellState::Skipped).collect();
        assert_eq!(skipped.len(), 6, "不在线的节点那六对不测");
        assert!(skipped.iter().all(|cell| cell.problem.as_ref().is_some_and(|problem| problem.node == Some(offline))));
        assert!(matches!(lab.controller.start_matrix(network), Err(Error::Busy(_))));

        let mut rounds = 0;
        loop {
            let running: Vec<u64> = lab.controller.lock().diag.running.keys().copied().collect();
            assert!(running.len() <= 4, "同时最多四个：{}", running.len());
            if running.is_empty() {
                break;
            }
            for test in running {
                let view = lab.controller.test(network, test).unwrap();
                assert_eq!(view.matrix, Some(run.id));
                assert!(!view.request.throughput && !view.request.items.contains(&TestItem::Route), "矩阵不量吞吐");
                let initiator = members.iter().find(|member| member.id == view.a.id).unwrap();
                let responder = members.iter().find(|member| member.id == view.b.id).unwrap();
                send(&lab, responder, responder_report(test, false));
                send(&lab, initiator, initiator_report(test));
                send(&lab, responder, responder_report(test, true));
            }
            rounds += 1;
            // 刚测过的对要等间隔：测试里把它拨过去。
            let earlier = Instant::now().checked_sub(MIN_INTERVAL).unwrap();
            lab.controller.lock().diag.last.values_mut().for_each(|(started, _)| *started = earlier);
            lab.controller.tick().unwrap();
        }
        let run = lab.controller.matrix(network).unwrap();
        assert_eq!((run.state, run.finished, rounds), (MatrixState::Done, 21, 4), "十五对、每批四对");
        let done: Vec<_> = run.cells.iter().filter(|cell| cell.state == CellState::Done).collect();
        assert_eq!(done.len(), 15);
        assert!(
            done.iter()
                .all(|cell| cell.direct_ok == Some(true) && cell.latency.is_some() && matches!(cell.route, Some(Route::Direct { .. })))
        );
        assert!(matches!(lab.controller.start_matrix(network), Err(Error::TooSoon(_))));
        assert!(matches!(lab.controller.cancel_matrix(network), Err(Error::Busy(_))));
    }

    #[test]
    fn a_cancelled_matrix_stops_its_tests_and_starts_no_more() {
        let mut lab = Lab::new();
        let network = lab.network("home").id;
        let mut members: Vec<Member> = (0..4).map(|_| lab.join_as(network, &modern_hello("0.2.0"))).collect();
        lab.settle(&mut members.iter_mut().collect::<Vec<_>>());
        lab.controller.start_matrix(network).unwrap();
        let cancelled = lab.controller.cancel_matrix(network).unwrap();
        assert_eq!(cancelled.state, MatrixState::Cancelled);
        assert!(cancelled.cells.iter().all(|cell| cell.state == CellState::Cancelled), "{:?}", cancelled.cells);
        assert!(lab.controller.lock().diag.running.is_empty());
        lab.controller.tick().unwrap();
        assert!(lab.controller.lock().diag.running.is_empty(), "取消之后不再开始新的");
    }

    /// 报一份结果，controller 处理时出的错原样返回（存储写不进去时会出错）。
    fn try_send(lab: &Lab, member: &Member, report: TestReport) -> Result<(), Error> {
        lab.controller.handle(member.session, REMOTE, ToController::TestReport(Box::new(report)))
    }

    /// 过了 `times` 次再存、再排的间隔之后。
    fn later(times: u32) -> Instant {
        Instant::now() + STORE_RETRY * times
    }

    /// 这几个节点里，`test` 的发起方和接受方。
    fn ends<'a>(lab: &Lab, network: NetworkId, test: u64, members: &[&'a Member]) -> (&'a Member, &'a Member) {
        let view = lab.controller.test(network, test).unwrap();
        let member = |id| members.iter().copied().find(|member| member.id == id).unwrap();
        (member(view.a.id), member(view.b.id))
    }

    #[test]
    fn a_test_whose_end_cannot_be_stored_keeps_running_and_ends_once_the_store_can_write() {
        let (lab, network, mut a, mut b) = two_nodes();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        send(&lab, &a, initiator_report(view.id));
        // 接受方一直不报最后一份，过了宽限要按手上有的结束，这时数据库写不进去。
        let past = Instant::now().checked_sub(RESPONDER_GRACE).unwrap();
        {
            let mut inner = lab.controller.lock();
            inner.diag.running.get_mut(&view.id).unwrap().ended = Some(past);
            inner.store.set_read_only(true);
            inner.tests_tick(Instant::now());
            assert!(inner.diag.running.contains_key(&view.id), "结果没存下来：还在进行中，下次接着存");
            // 后台任务被叫醒得再勤，没到再存的时刻也不去存。
            inner.store.set_read_only(false);
            let next = inner.tests_tick(Instant::now());
            assert!(inner.diag.running.contains_key(&view.id), "还没到再存的时刻");
            assert!(next.is_some_and(|at| at > Instant::now()), "到那时再来");
        }
        a.receive();
        assert!(a.test_ends.is_empty(), "存下来之前不告诉两端结束");

        lab.controller.lock().tests_tick(later(1));
        assert!(lab.controller.lock().diag.running.is_empty());
        let stored = lab.controller.lock().store.test(network, view.id).unwrap().unwrap();
        assert_eq!((stored.state, stored.finished_at.is_some()), (TestState::Done, true));
        a.receive();
        b.receive();
        assert_eq!(a.test_ends, [view.id]);
        assert_eq!(b.test_ends, [view.id, view.id], "发起方报完时一次，结束时一次");
    }

    #[test]
    fn a_matrix_test_whose_result_cannot_be_stored_keeps_its_place_and_the_matrix_still_finishes() {
        let (lab, network, a, b) = two_nodes();
        let run = lab.controller.start_matrix(network).unwrap();
        let test = run.cells[0].test.unwrap();
        let (initiator, responder) = ends(&lab, network, test, &[&a, &b]);
        lab.controller.lock().store.set_read_only(true);
        try_send(&lab, initiator, initiator_report(test)).unwrap();
        assert!(try_send(&lab, responder, responder_report(test, true)).is_err(), "两端都报完了，结果存不下来");
        {
            let mut inner = lab.controller.lock();
            assert!(inner.diag.running.contains_key(&test), "还在进行中");
            inner.tests_tick(later(1));
            assert!(inner.diag.running.contains_key(&test), "后台任务到点再存，还是存不下来");
            inner.store.set_read_only(false);
            inner.tests_tick(later(2));
        }
        assert_eq!(lab.controller.test(network, test).unwrap().state, TestState::Done);
        let run = lab.controller.matrix(network).unwrap();
        assert_eq!((run.state, run.finished, run.cells[0].state), (MatrixState::Done, 1, CellState::Done));
    }

    #[test]
    fn a_matrix_pair_that_cannot_start_stays_queued_and_starts_once_the_store_can_write() {
        let (lab, network, a, b) = two_nodes();
        // 这一对刚单独测过：矩阵开始时它排着，等间隔过去。
        lab.controller.lock().diag.last.insert(pair(a.id, b.id), (Instant::now(), None));
        lab.controller.start_matrix(network).unwrap();
        {
            let mut inner = lab.controller.lock();
            inner.diag.last.clear();
            inner.store.set_read_only(true);
            inner.tests_tick(Instant::now());
            assert!(inner.diag.running.is_empty(), "开始一个测试要写数据库");
            inner.store.set_read_only(false);
            let next = inner.tests_tick(Instant::now());
            assert!(inner.diag.running.is_empty(), "隔一会儿再排");
            assert!(next.is_some_and(|at| at > Instant::now() + Duration::from_secs(2)), "到再排的时刻再来");
            inner.tests_tick(later(1));
        }
        let cell = lab.controller.matrix(network).unwrap().cells[0].clone();
        assert_eq!(cell.state, CellState::Running, "写得进去之后这一对照样开始");
        let test = cell.test.unwrap();
        let (initiator, responder) = ends(&lab, network, test, &[&a, &b]);
        send(&lab, initiator, initiator_report(test));
        send(&lab, responder, responder_report(test, true));
        let run = lab.controller.matrix(network).unwrap();
        assert_eq!((run.state, run.finished, run.cells[0].state), (MatrixState::Done, 1, CellState::Done));
    }

    #[test]
    fn a_test_whose_start_cannot_be_logged_leaves_nothing_behind() {
        let (mut lab, network, a, b) = two_nodes();
        let offline = lab.join_offline(network, &[], Declared::default());
        // 测试那一行写得进去，操作记录写不进去。
        lab.controller.lock().store.block("no_log", "INSERT ON oplog", None);
        assert!(lab.controller.start_test(network, &request(&a, &b)).is_err());
        assert!(lab.controller.start_test(network, &CreateTest { b: offline, ..request(&a, &b) }).is_err(), "做不了的测试也一样");
        assert!(lab.controller.tests(network, &TestQuery::default()).unwrap().is_empty(), "开始不了的测试不留一行");
        assert!(lab.controller.lock().diag.running.is_empty());

        lab.controller.lock().store.unblock("no_log", "oplog");
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        assert_eq!(view.state, TestState::Running, "马上可以再试，不用等间隔");
    }

    #[test]
    fn a_matrix_test_whose_order_cannot_be_delivered_ends_at_once_and_frees_its_place() {
        let mut lab = Lab::new();
        let network = lab.network("home").id;
        let mut members: Vec<Member> = (0..3).map(|_| lab.join_as(network, &modern_hello("0.2.0"))).collect();
        lab.settle(&mut members.iter_mut().collect::<Vec<_>>());
        // 最后一个节点的连接已经断了，controller 还不知道：发给它的指令发不出去，它随之被记为离线。
        let gone = members.pop().unwrap().id;
        lab.controller.start_matrix(network).unwrap();
        let running: Vec<u64> = lab.controller.lock().diag.running.keys().copied().collect();
        assert_eq!(running.len(), 1, "只有两个在线的节点那一对在测");
        let (initiator, responder) = ends(&lab, network, running[0], &[&members[0], &members[1]]);
        send(&lab, initiator, initiator_report(running[0]));
        send(&lab, responder, responder_report(running[0], true));
        let run = lab.controller.matrix(network).unwrap();
        assert_eq!((run.state, run.finished), (MatrixState::Done, 3), "{:?}", run.cells);
        for cell in &run.cells {
            let expected = if cell.a == gone || cell.b == gone { CellState::Failed } else { CellState::Done };
            assert_eq!(cell.state, expected, "{cell:?}");
        }
    }

    #[test]
    fn what_already_happened_does_not_fail_because_the_next_matrix_pair_cannot_start() {
        let mut lab = Lab::new();
        let network = lab.network("home").id;
        let mut members: Vec<Member> = (0..3).map(|_| lab.join_as(network, &modern_hello("0.2.0"))).collect();
        lab.settle(&mut members.iter_mut().collect::<Vec<_>>());
        // 结果照样更新得进去，新的测试插不进去。
        let block = |lab: &Lab| lab.controller.lock().store.block("no_new_test", "INSERT ON tests", None);
        let unblock = |lab: &Lab| lab.controller.lock().store.unblock("no_new_test", "tests");
        block(&lab);
        let run = lab.controller.start_matrix(network).unwrap();
        assert!(run.cells.iter().all(|cell| cell.state == CellState::Pending), "矩阵开始了，一对都还没开始：{:?}", run.cells);

        // 最后一对刚单独测过，先开始另外两对。
        let last = pair(members[1].id, members[2].id);
        lab.controller.lock().diag.last.insert(last, (Instant::now(), None));
        unblock(&lab);
        lab.controller.lock().tests_tick(later(1));
        let running: Vec<u64> = lab.controller.lock().diag.running.keys().copied().collect();
        assert_eq!(running.len(), 2);

        lab.controller.lock().diag.last.clear();
        block(&lab);
        let test = running[0];
        let (initiator, responder) = ends(&lab, network, test, &members.iter().collect::<Vec<_>>());
        send(&lab, initiator, initiator_report(test));
        send(&lab, responder, responder_report(test, true));
        assert_eq!(lab.controller.test(network, test).unwrap().state, TestState::Done, "测试照常结束，下一对开始不了不算它的错");
        let queued = |lab: &Lab| lab.controller.matrix(network).unwrap().cells.into_iter().find(|cell| (cell.a, cell.b) == last).unwrap();
        assert_eq!(queued(&lab).state, CellState::Pending);

        unblock(&lab);
        lab.controller.lock().tests_tick(later(1));
        assert_eq!(queued(&lab).state, CellState::Running, "后台任务接着排");
    }

    /// 三个在线节点的网络，全网矩阵三对都在测。
    fn three_testing(lab: &mut Lab, name: &str) -> (NetworkId, Vec<Member>) {
        let network = lab.network(name).id;
        let mut members: Vec<Member> = (0..3).map(|_| lab.join_as(network, &modern_hello("0.2.0"))).collect();
        lab.settle(&mut members.iter_mut().collect::<Vec<_>>());
        lab.controller.start_matrix(network).unwrap();
        assert_eq!(lab.controller.lock().diag.running.len(), 3);
        (network, members)
    }

    /// 让这几个测试的结果写不进去，别的照常。
    fn stick(lab: &Lab, tests: &[u64]) {
        let ids = tests.iter().map(u64::to_string).collect::<Vec<_>>().join(", ");
        lab.controller.lock().store.block("stuck", "UPDATE ON tests", Some(&format!("OLD.id IN ({ids})")));
    }

    fn unstick(lab: &Lab) {
        lab.controller.lock().store.unblock("stuck", "tests");
    }

    #[test]
    fn a_matrix_cancel_that_cannot_be_logged_changes_nothing_and_can_be_tried_again() {
        let (lab, network, _a, _b) = two_nodes();
        lab.controller.start_matrix(network).unwrap();
        lab.controller.lock().store.set_read_only(true);
        assert!(lab.controller.cancel_matrix(network).is_err());
        let run = lab.controller.matrix(network).unwrap();
        assert_eq!((run.state, run.cells[0].state), (MatrixState::Running, CellState::Running), "什么都没有变");

        lab.controller.lock().store.set_read_only(false);
        let run = lab.controller.cancel_matrix(network).unwrap();
        assert_eq!((run.state, run.cells[0].state), (MatrixState::Cancelled, CellState::Cancelled));
    }

    #[test]
    fn a_matrix_is_cancelled_only_once_every_test_s_cancellation_is_stored() {
        let mut lab = Lab::new();
        let (network, _members) = three_testing(&mut lab, "home");
        let tests: Vec<u64> = lab.controller.lock().diag.running.keys().copied().collect();
        stick(&lab, &tests[..2]);
        assert!(lab.controller.cancel_matrix(network).is_err(), "两个测试的结果存不下来");
        let state = |lab: &Lab, test: u64| lab.controller.test(network, test).unwrap().state;
        assert_eq!(state(&lab, tests[2]), TestState::Cancelled, "存得下来的照样取消");
        assert_eq!(state(&lab, tests[0]), TestState::Cancelled, "存不下来的结果也已经定成取消");
        let run = lab.controller.matrix(network).unwrap();
        assert_eq!((run.state, run.finished_at), (MatrixState::Running, None), "还没取消完");
        assert!(matches!(lab.controller.start_matrix(network), Err(Error::Busy(_))), "取消完之前不能开始下一次");
        assert!(lab.controller.cancel_matrix(network).is_err(), "可以再取消一次，还是存不下来");

        // 后台任务接着存：一个存得下来了，另一个还存不下来。
        unstick(&lab);
        stick(&lab, &tests[1..2]);
        lab.controller.lock().tests_tick(later(1));
        let stored = lab.controller.lock().store.test(network, tests[0]).unwrap().unwrap();
        assert_eq!(stored.state, TestState::Cancelled, "存下来的是取消，不是照常做完");
        assert_eq!(lab.controller.matrix(network).unwrap().state, MatrixState::Running);
        // 单独再取消剩下的那个，这次存得下来，矩阵取消完了。
        unstick(&lab);
        assert_eq!(lab.controller.cancel_test(network, tests[1]).unwrap().state, TestState::Cancelled);
        let run = lab.controller.matrix(network).unwrap();
        assert_eq!((run.state, run.finished, run.finished_at.is_some()), (MatrixState::Cancelled, 3, true));
        assert!(run.cells.iter().all(|cell| cell.state == CellState::Cancelled), "{:?}", run.cells);
        assert!(lab.controller.lock().diag.running.is_empty());
        assert!(matches!(lab.controller.cancel_matrix(network), Err(Error::Busy(_))), "取消完了");
        let logged = |action: &str| lab.controller.oplog(50).unwrap().into_iter().filter(|entry| entry.action == action).count();
        assert_eq!((logged(action::TEST_MATRIX_CANCEL), logged(action::TEST_CANCEL)), (1, 0), "再取消一次不重复记");
    }

    #[test]
    fn a_network_can_start_another_matrix_once_one_was_cancelled() {
        let (lab, network, _a, _b) = two_nodes();
        lab.controller.start_matrix(network).unwrap();
        lab.controller.cancel_matrix(network).unwrap();
        assert!(matches!(lab.controller.start_matrix(network), Err(Error::TooSoon(_))), "和做完了的一样，只等间隔");
        lab.controller.lock().diag.matrices.get_mut(&network).unwrap().interval_passed();
        assert_eq!(lab.controller.start_matrix(network).unwrap().state, MatrixState::Running);
    }

    #[test]
    fn a_matrix_cancel_cancels_every_test_even_when_telling_a_node_finds_it_gone() {
        let mut lab = Lab::new();
        let (network, mut members) = three_testing(&mut lab, "home");
        let tests: Vec<u64> = lab.controller.lock().diag.running.keys().copied().collect();
        // 第一个节点的连接已经断了，controller 还不知道：告诉它第一个测试结束时它被记为离线，
        // 它参与的另一个测试随之按掉线结束。
        drop(members.remove(0));
        assert_eq!(lab.controller.cancel_matrix(network).unwrap().state, MatrixState::Cancelled);
        for test in tests {
            assert_eq!(lab.controller.lock().store.test(network, test).unwrap().unwrap().state, TestState::Cancelled, "测试 #{test}");
        }
    }

    #[test]
    fn a_matrix_cell_shows_its_test_as_running_until_the_result_is_stored() {
        let (lab, network, _a, b) = two_nodes();
        // 接受方的连接已经断了，指令发不出去；测试的结果也写不进去。
        drop(b);
        lab.controller.lock().store.block("stuck", "UPDATE ON tests", None);
        let run = lab.controller.start_matrix(network).unwrap();
        assert_eq!((run.state, run.finished, run.cells[0].state), (MatrixState::Running, 0, CellState::Running), "{:?}", run.cells);
        let test = run.cells[0].test.unwrap();
        assert_eq!(lab.controller.test(network, test).unwrap().state, TestState::Failed, "测试本身的结果已经定下了");

        unstick(&lab);
        lab.controller.lock().tests_tick(later(1));
        let run = lab.controller.matrix(network).unwrap();
        assert_eq!((run.state, run.finished, run.cells[0].state), (MatrixState::Done, 1, CellState::Failed));
    }

    #[test]
    fn a_matrix_with_nothing_running_is_cancelled_at_once() {
        let (lab, network, a, b) = two_nodes();
        lab.controller.lock().diag.last.insert(pair(a.id, b.id), (Instant::now(), None));
        lab.controller.start_matrix(network).unwrap();
        let run = lab.controller.cancel_matrix(network).unwrap();
        assert_eq!((run.state, run.cells[0].state, run.finished_at.is_some()), (MatrixState::Cancelled, CellState::Cancelled, true));
    }

    #[test]
    fn a_test_cancel_that_cannot_be_stored_changes_nothing_and_can_be_tried_again() {
        let (lab, network, a, mut b) = two_nodes();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        stick(&lab, &[view.id]);
        assert!(lab.controller.cancel_test(network, view.id).is_err());
        assert_eq!(lab.controller.test(network, view.id).unwrap().state, TestState::Running, "什么都没有变");
        let logged = |lab: &Lab| lab.controller.oplog(50).unwrap().into_iter().filter(|entry| entry.action == action::TEST_CANCEL).count();
        assert_eq!(logged(&lab), 0, "操作记录和结果一起没写进去");

        unstick(&lab);
        assert_eq!(lab.controller.cancel_test(network, view.id).unwrap().state, TestState::Cancelled);
        assert!(matches!(lab.controller.cancel_test(network, view.id), Err(Error::Busy(_))));
        assert_eq!(logged(&lab), 1);
        b.receive();
        assert_eq!(b.test_ends, [view.id]);
    }

    #[test]
    fn a_test_that_ended_before_its_result_could_be_stored_takes_no_more_reports() {
        let (lab, network, a, mut b) = two_nodes();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        // 时间窗过了，什么都没报，结果存不下来。
        stick(&lab, &[view.id]);
        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        lab.controller.lock().diag.running.get_mut(&view.id).unwrap().deadline = past;
        lab.controller.lock().tests_tick(Instant::now());
        assert_eq!(lab.controller.test(network, view.id).unwrap().state, TestState::Failed, "结果已经定下了");
        // 发起方的最后一份这时才到：不算数，也不因此告诉接受方结束。
        try_send(&lab, &a, initiator_report(view.id)).unwrap();
        b.receive();
        assert!(b.test_ends.is_empty(), "存下来之前不告诉两端结束");
        assert!(matches!(lab.controller.cancel_test(network, view.id), Err(Error::Busy(_))), "已经结束了");

        unstick(&lab);
        lab.controller.lock().tests_tick(later(1));
        assert_eq!(lab.controller.lock().store.test(network, view.id).unwrap().unwrap().state, TestState::Failed);
        b.receive();
        assert_eq!(b.test_ends, [view.id]);
    }

    #[test]
    fn a_test_that_times_out_while_the_whole_store_is_unusable_takes_no_late_reports() {
        let (lab, network, a, b) = two_nodes();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        // 时间窗过了，什么都没报。这时整个数据库都写不进去（清理过期的记录时发现的），后台任务这一轮不存测试结果。
        {
            let mut inner = lab.controller.lock();
            inner.diag.running.get_mut(&view.id).unwrap().deadline = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
            inner.store.set_read_only(true);
            inner.last_purge = None;
            let wall = inner.clock.now();
            assert!(inner.tick_work(Instant::now(), wall).unwrap_err().is_database_wide());
            inner.store.set_read_only(false);
        }
        assert_eq!(lab.controller.test(network, view.id).unwrap().state, TestState::Failed, "结果照样定下了");

        // 两端的最后一份在这之后才到：不算数，不然超时的测试被记成做完了。
        try_send(&lab, &a, initiator_report(view.id)).unwrap();
        try_send(&lab, &b, responder_report(view.id, true)).unwrap();
        lab.controller.lock().tests_tick(later(1));
        let stored = lab.controller.lock().store.test(network, view.id).unwrap().unwrap();
        assert_eq!((stored.state, stored.error.map(|problem| problem.code)), (TestState::Failed, Some(TestCode::NoReport)));
    }

    #[test]
    fn a_test_whose_responder_ran_late_while_the_whole_store_was_unusable_is_stored_as_soon_as_it_can_be() {
        let (lab, network, a, b) = two_nodes();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        // 发起方报完了，controller 叫接受方结束；接受方过了宽限期还没报最后一份，离时间窗结束还早。
        try_send(&lab, &a, initiator_report(view.id)).unwrap();
        let late = Instant::now() + RESPONDER_GRACE + Duration::from_secs(1);
        assert!(late < lab.controller.lock().diag.running[&view.id].deadline);
        // 这时整个数据库都写不进去：结果先定下来，不存。
        {
            let mut inner = lab.controller.lock();
            inner.store.set_read_only(true);
            inner.last_purge = None;
            let wall = inner.clock.now();
            assert!(inner.tick_work(late, wall).unwrap_err().is_database_wide());
            inner.store.set_read_only(false);
        }
        let fixed = lab.controller.test(network, view.id).unwrap();
        assert!(fixed.finished_at.is_some(), "结果定下了");

        // 能写了：马上存下来，放开这一对节点，不用等到原来的时间窗结束。
        lab.controller.lock().tests_tick(late);
        assert!(!lab.controller.lock().diag.running.contains_key(&view.id));
        assert_eq!(lab.controller.lock().store.test(network, view.id).unwrap().unwrap(), fixed);
    }

    #[test]
    fn a_report_that_comes_after_a_test_ended_does_not_change_the_result_waiting_to_be_stored() {
        let (lab, network, a, b) = two_nodes();
        let view = lab.controller.start_test(network, &request(&a, &b)).unwrap();
        lab.controller.lock().store.set_read_only(true);
        // 接受方掉线：发起方还什么都没报，测试按手上有的结束，是失败。结果存不下来。
        lab.controller.disconnect(b.session);
        let ended = lab.controller.test(network, view.id).unwrap();
        assert_eq!((ended.state, ended.finished_at.is_some()), (TestState::Failed, true), "结果已经定下了");
        // 发起方的结果这时才到。
        try_send(&lab, &a, initiator_report(view.id)).unwrap();
        assert_eq!(lab.controller.test(network, view.id).unwrap(), ended, "不算数");

        lab.controller.advance_clock(30);
        lab.controller.lock().store.set_read_only(false);
        lab.controller.lock().tests_tick(later(1));
        let stored = lab.controller.lock().store.test(network, view.id).unwrap().unwrap();
        assert_eq!((stored.state, stored.finished_at), (TestState::Failed, ended.finished_at), "存下来的是当时定下的结果和时刻");
    }

    #[test]
    fn an_operation_whose_log_entry_cannot_be_written_in_full_changes_nothing() {
        let (mut lab, network, _a, _b) = two_nodes();
        let other = lab.network("lab").id;
        let mut c = lab.join_as(other, &modern_hello("0.2.0"));
        let mut d = lab.join_as(other, &modern_hello("0.2.0"));
        lab.settle(&mut [&mut c, &mut d]);
        let test = lab.controller.start_matrix(network).unwrap().cells[0].test.unwrap();
        // 操作记录满了：记一条要顺带清掉最老的，清不掉。
        lab.controller.lock().store.execute_batch(
            "INSERT INTO oplog (at, network_id, action, detail, refs, params) \
             SELECT 0, NULL, 'filler', '', '[]', '{}' FROM generate_series(1, 10000)",
        );
        lab.controller.lock().store.block("no_trim", "DELETE ON oplog", None);
        assert!(lab.controller.start_matrix(other).is_err());
        assert!(matches!(lab.controller.matrix(other), Err(Error::NotFound(_))), "矩阵没有开始");
        assert!(lab.controller.cancel_matrix(network).is_err());
        assert_eq!(lab.controller.matrix(network).unwrap().cells[0].state, CellState::Running, "矩阵没有取消");
        assert!(lab.controller.cancel_test(network, test).is_err());
        assert_eq!(lab.controller.test(network, test).unwrap().state, TestState::Running, "测试没有取消");
        let logged = |lab: &Lab| lab.controller.oplog(10).unwrap().into_iter().filter(|entry| entry.action != "filler").count();
        assert_eq!(logged(&lab), 0, "操作记录里也没有");

        lab.controller.lock().store.unblock("no_trim", "oplog");
        assert_eq!(lab.controller.cancel_matrix(network).unwrap().state, MatrixState::Cancelled);
        assert_eq!(logged(&lab), 1);
    }

    #[test]
    fn one_test_that_cannot_be_stored_does_not_hold_up_the_rest_of_the_background_work() {
        let mut lab = Lab::new();
        let (_network, _members) = three_testing(&mut lab, "home");
        // 另一个网络的矩阵有一对排着，这一轮该开始了。
        let other = lab.network("lab").id;
        let mut a = lab.join_as(other, &modern_hello("0.2.0"));
        let mut b = lab.join_as(other, &modern_hello("0.2.0"));
        lab.settle(&mut [&mut a, &mut b]);
        lab.controller.lock().diag.last.insert(pair(a.id, b.id), (Instant::now(), None));
        lab.controller.start_matrix(other).unwrap();
        lab.controller.lock().diag.last.remove(&pair(a.id, b.id));

        let tests: Vec<u64> = lab.controller.lock().diag.running.keys().copied().collect();
        stick(&lab, &tests[..1]);
        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        lab.controller.lock().diag.running.values_mut().for_each(|running| running.deadline = past);
        // 整个后台任务照常做完，不因为第一个存不下来出错、丢掉别的工作要它回来的时刻。
        assert!(lab.controller.tick().is_ok());
        let running: Vec<u64> = lab.controller.lock().diag.running.keys().copied().collect();
        assert_eq!(running.len(), 2, "到点的另外两个照样结束了，另一个网络的那一对照样开始了：{running:?}");
        assert_eq!(running[0], tests[0]);
        assert_eq!(lab.controller.matrix(other).unwrap().cells[0].state, CellState::Running);
    }

    #[test]
    fn a_matrix_pair_that_keeps_failing_to_start_does_not_hold_up_the_pairs_behind_it() {
        let mut lab = Lab::new();
        let network = lab.network("home").id;
        let mut members: Vec<Member> = (0..3).map(|_| lab.join_as(network, &modern_hello("0.2.0"))).collect();
        lab.settle(&mut members.iter_mut().collect::<Vec<_>>());
        // 后建的网络也有一个矩阵，它那一对排着，这一轮该开始了。
        let other = lab.network("lab").id;
        let mut a = lab.join_as(other, &modern_hello("0.2.0"));
        let mut b = lab.join_as(other, &modern_hello("0.2.0"));
        lab.settle(&mut [&mut a, &mut b]);
        // 前一个网络排在最前面的那一对一直插不进去。
        let (first, second) = (members[0].id.get(), members[1].id.get());
        let stuck = format!("NEW.node_a = {first} AND NEW.node_b = {second}");
        lab.controller.lock().store.block("stuck", "INSERT ON tests", Some(&stuck));
        lab.controller.start_matrix(network).unwrap();
        lab.controller.lock().diag.last.insert(pair(a.id, b.id), (Instant::now(), None));
        lab.controller.start_matrix(other).unwrap();
        lab.controller.lock().diag.last.remove(&pair(a.id, b.id));

        lab.controller.lock().tests_tick(later(1));
        let states = |lab: &Lab| lab.controller.matrix(network).unwrap().cells.iter().map(|cell| cell.state).collect::<Vec<_>>();
        assert_eq!(states(&lab), [CellState::Pending, CellState::Running, CellState::Running], "后面的两对照样开始");
        assert_eq!(lab.controller.matrix(other).unwrap().cells[0].state, CellState::Running, "别的网络也照样排");

        lab.controller.lock().store.unblock("stuck", "tests");
        lab.controller.lock().tests_tick(later(2));
        assert_eq!(states(&lab), [CellState::Running; 3]);
    }
}
