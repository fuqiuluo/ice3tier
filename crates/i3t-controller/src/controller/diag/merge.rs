//! 把两端各自的上报合成管理 API 里的一个测试结果。纯函数，不碰存储和连接。

use i3t_model::admin::diag::{
    DecisionView, DirectResult, DirectSideView, HostResult, ItemState, PathResult, RouteResult, TestItem, TestState, TestView,
    ThroughputResult,
};
use i3t_model::control::diag::{Decision, HostReport, PathMeasure, PathPick, TestCode, TestProblem, Throughput};
use i3t_model::control::{Route, TestReport};
use i3t_proto::NodeId;

/// 下发指令前即可确定无法执行的测试项及其原因。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Skips {
    /// 直连能力和直连质量（有一端只经 relay）。
    pub(crate) direct: Option<TestProblem>,
    /// relay 质量（有一端只用直连，或者网络里没有 relay）。
    pub(crate) relay: Option<TestProblem>,
    /// 吞吐（有一端关掉了吞吐测试）。
    pub(crate) throughput: Option<TestProblem>,
}

/// 合成结果要的东西。
pub(crate) struct Inputs<'a> {
    pub(crate) base: &'a TestView,
    pub(crate) skips: &'a Skips,
    pub(crate) initiator: Option<&'a TestReport>,
    /// 接受方最新的一次上报（最后一次优先）。
    pub(crate) responder: Option<&'a TestReport>,
    /// 测试已经结束：还没有的结果不会再来了。
    pub(crate) finished: bool,
}

/// 合成一个测试现在的样子。`state`、`finished_at`、`error` 由调用方定。
pub(crate) fn merge(inputs: &Inputs<'_>) -> TestView {
    let Inputs { base, skips, initiator, responder, finished, .. } = *inputs;
    let (a, b) = (base.a.id, base.b.id);
    let requested = |item| base.request.items.contains(&item);
    let missing = |node| {
        if finished { (ItemState::Failed, Some(TestProblem::new(TestCode::NoReport, Some(node)))) } else { (ItemState::Pending, None) }
    };
    let b_refused_throughput = responder.and_then(|report| report.throughput_refused.clone());
    let throughput_wanted = base.request.throughput;
    let shape = |measure: &PathMeasure| {
        path_result(measure, a, b, throughput_wanted.then_some(skips.throughput.as_ref()), b_refused_throughput.as_ref())
    };

    let direct = requested(TestItem::Direct).then(|| match (&skips.direct, initiator.and_then(|report| report.direct.as_ref())) {
        (Some(problem), _) => DirectResult {
            state: ItemState::Skipped,
            ok: false,
            kind: None,
            elapsed_ms: None,
            already: false,
            problem: Some(problem.clone()),
            sides: Vec::new(),
        },
        (None, None) => {
            let (state, problem) = missing(a);
            DirectResult { state, ok: false, kind: None, elapsed_ms: None, already: false, problem, sides: Vec::new() }
        }
        (None, Some(mine)) => {
            let theirs = responder.and_then(|report| report.direct.as_ref());
            let ok = mine.ok && theirs.is_none_or(|side| side.ok);
            let mut sides = vec![DirectSideView { node: a, side: mine.clone() }];
            sides.extend(theirs.map(|side| DirectSideView { node: b, side: side.clone() }));
            let problem = (!ok).then(|| direct_problem(&sides));
            DirectResult {
                state: ItemState::Done,
                ok,
                kind: mine.kind.or_else(|| theirs.and_then(|side| side.kind)),
                elapsed_ms: mine.elapsed_ms,
                already: mine.already,
                problem,
                sides,
            }
        }
    });

    let direct_measure = initiator.and_then(|report| report.paths.iter().find(|path| path.picked_by.contains(&PathPick::Direct)));
    let direct_quality = requested(TestItem::DirectQuality).then(|| match (&skips.direct, direct_measure) {
        (Some(problem), _) => skipped(problem.clone()),
        (None, Some(measure)) => shape(measure),
        (None, None) => {
            let (state, problem) = missing(a);
            PathResult { state, ..skipped_fields(problem) }
        }
    });

    let relay_quality = if !requested(TestItem::RelayQuality) {
        Vec::new()
    } else if let Some(problem) = &skips.relay {
        vec![skipped(problem.clone())]
    } else {
        let measured: Vec<PathResult> = initiator
            .map(|report| report.paths.iter().filter(|path| !path.picked_by.contains(&PathPick::Direct)).map(shape).collect())
            .unwrap_or_default();
        if measured.is_empty() {
            let (state, problem) = missing(a);
            // 指定了路径的，还没有结果时也先列出来，界面可以先画出要测哪几条。
            if base.request.via.is_empty() {
                vec![PathResult { state, ..skipped_fields(problem) }]
            } else {
                base.request
                    .via
                    .iter()
                    .map(|relays| PathResult {
                        state,
                        route: Some(Route::Relay { relays: relays.clone() }),
                        picked_by: vec![PathPick::Admin],
                        ..skipped_fields(problem.clone())
                    })
                    .collect()
            }
        } else {
            measured
        }
    };

    let route = requested(TestItem::Route).then(|| {
        let forward = initiator.and_then(|report| report.decision.as_ref()).map(|decision| decision_view(decision, a, b));
        let reverse = responder
            .filter(|report| report.last)
            .and_then(|report| report.decision.as_ref())
            .map(|decision| decision_view(decision, b, a));
        let (state, problem) = match (&forward, &reverse) {
            (Some(_), Some(_)) => (ItemState::Done, None),
            (Some(_), None) if finished => (ItemState::Done, Some(TestProblem::new(TestCode::NoReport, Some(b)))),
            (None, _) if finished => (ItemState::Failed, Some(TestProblem::new(TestCode::NoReport, Some(a)))),
            (Some(_) | None, _) => (ItemState::Pending, None),
        };
        RouteResult { state, problem, forward, reverse }
    });

    // 主机的状况在每一端最后的那次上报里。
    let hosts = requested(TestItem::Host)
        .then(|| vec![host_result(a, initiator, finished), host_result(b, responder.filter(|report| report.last), finished)]);

    let mut notes = Vec::new();
    if finished && responder.is_none_or(|report| !report.last) && initiator.is_some() {
        notes.push(TestProblem::new(TestCode::NoReport, Some(b)));
    }
    TestView { direct, direct_quality, relay_quality, route, hosts, notes, ..base.clone() }
}

/// 一端的主机状况。`last` 是它最后的那次上报：到了却没有带，就是这个节点的版本没有这一项。
fn host_result(node: NodeId, last: Option<&TestReport>, finished: bool) -> HostResult {
    let (state, problem, report) = match last {
        Some(TestReport { host: Some(host), .. }) => (ItemState::Done, None, host.clone()),
        Some(_) => (ItemState::Skipped, Some(TestProblem::new(TestCode::NotSupported, Some(node))), HostReport::default()),
        None if finished => (ItemState::Failed, Some(TestProblem::new(TestCode::NoReport, Some(node))), HostReport::default()),
        None => (ItemState::Pending, None, HostReport::default()),
    };
    HostResult { node, state, problem, report }
}

/// 直连失败时最具诊断价值的根因：可定位到具体节点的原因（如 UDP 不通、端口映射随对端变化）优先于「超时」。
fn direct_problem(sides: &[DirectSideView]) -> TestProblem {
    const ORDER: [TestCode; 7] = [
        TestCode::UdpBlocked,
        TestCode::MappingVaries,
        TestCode::DialOutOnly,
        TestCode::RelayOnly,
        TestCode::NotConnected,
        TestCode::NoCandidates,
        TestCode::Timeout,
    ];
    let found = ORDER.iter().find_map(|code| sides.iter().find(|side| side.side.failure == Some(*code)).map(|side| (*code, side.node)));
    match found {
        Some((code, node)) => TestProblem::new(code, Some(node)),
        // 一边成了、另一边没成又没说原因：只能说是那一边超时了。
        None => TestProblem::new(TestCode::Timeout, sides.iter().find(|side| !side.side.ok).map(|side| side.node)),
    }
}

fn skipped(problem: TestProblem) -> PathResult {
    PathResult { state: ItemState::Skipped, ..skipped_fields(Some(problem)) }
}

fn skipped_fields(problem: Option<TestProblem>) -> PathResult {
    PathResult {
        state: ItemState::Skipped,
        route: None,
        picked_by: Vec::new(),
        problem,
        latency: None,
        cost_us: None,
        hops: Vec::new(),
        relay_leg: None,
        throughput: None,
    }
}

/// 发起方量过的一条路径。`throughput_skip` 是 `None` 表示没要吞吐，`Some(None)` 表示要了、指令发出前没有理由不做。
fn path_result(
    measure: &PathMeasure,
    a: NodeId,
    b: NodeId,
    throughput_skip: Option<Option<&TestProblem>>,
    b_refused: Option<&TestProblem>,
) -> PathResult {
    let problem = measure.failure.map(|code| {
        // 发起方报的路径限制说的是它自己；别的原因（路径断了、对端没回答……）说的是这条路，不怪哪一个节点，以后新加的原因也这样。
        let node = matches!(code, TestCode::RelayOnly | TestCode::DirectOnly).then_some(a);
        TestProblem::new(code, node)
    });
    let throughput = throughput_skip.map(|skip| match (skip, &measure.throughput, &problem) {
        (Some(skip), _, _) => ThroughputResult {
            state: ItemState::Skipped,
            problem: Some(skip.clone()),
            measured: empty_throughput(),
            shared_connection: true,
        },
        (None, Some(measured), _) => {
            let problem = measured.failure.map(|code| match code {
                // 接受方拒绝测量流时，它自己报的原因（关掉了吞吐测试）比"被拒绝"说得清楚。
                TestCode::Refused => b_refused.cloned().unwrap_or_else(|| TestProblem::new(TestCode::Refused, Some(b))),
                TestCode::ThroughputOff => TestProblem::new(code, Some(a)),
                code => TestProblem::new(code, None),
            });
            let state = match problem.as_ref().map(|problem| problem.code) {
                None => ItemState::Done,
                Some(TestCode::ThroughputOff) => ItemState::Skipped,
                Some(_) => ItemState::Failed,
            };
            ThroughputResult { state, problem, measured: measured.clone(), shared_connection: true }
        }
        (None, None, path_problem) => ThroughputResult {
            state: ItemState::Skipped,
            problem: path_problem.clone().or_else(|| Some(TestProblem::new(TestCode::Unreachable, None))),
            measured: empty_throughput(),
            shared_connection: true,
        },
    });
    PathResult {
        state: if problem.is_some() { ItemState::Failed } else { ItemState::Done },
        route: (measure.route != Route::None).then(|| measure.route.clone()),
        picked_by: measure.picked_by.clone(),
        problem,
        latency: measure.latency,
        cost_us: measure.cost_us,
        hops: measure.hops.clone(),
        relay_leg: measure.relay_leg,
        throughput,
    }
}

fn empty_throughput() -> Throughput {
    Throughput {
        up: None,
        down: None,
        failure: None,
        transport: "quic".to_owned(),
        congestion: String::new(),
        limit_bytes: 0,
        limit_ms: 0,
        pinned: false,
    }
}

fn decision_view(decision: &Decision, from: NodeId, to: NodeId) -> DecisionView {
    DecisionView {
        from,
        to,
        mode: decision.mode,
        current: decision.current.clone(),
        direct_first: decision.direct_first.clone(),
        lowest_cost: decision.lowest_cost.clone(),
        candidates: decision.candidates.clone(),
    }
}

/// 测试结束时的最终状态：被取消时为取消；任一端整体拒绝或发起方无任何上报时为失败；其余情况为已完成。
pub(crate) fn final_state(
    cancelled: bool,
    initiator: Option<&TestReport>,
    responder: Option<&TestReport>,
) -> (TestState, Option<TestProblem>) {
    if cancelled {
        return (TestState::Cancelled, None);
    }
    if let Some(problem) =
        initiator.and_then(|report| report.refused.clone()).or_else(|| responder.and_then(|report| report.refused.clone()))
    {
        return (TestState::Failed, Some(problem));
    }
    match initiator {
        Some(_) => (TestState::Done, None),
        None => (TestState::Failed, None),
    }
}

#[cfg(test)]
mod tests {
    use i3t_model::admin::diag::TestRequest;
    use i3t_model::admin::{NetworkId, NodeRef};
    use i3t_model::control::DirectKind;
    use i3t_model::control::diag::{Choice, ChoiceCode, DirectSide, Latency, TestRole, Transfer, TransferEnd};

    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn base(items: &[TestItem], throughput: bool) -> TestView {
        let reference = |id: u32| NodeRef { id: node(id), name: format!("n{id}"), virtual_ip: format!("10.66.0.{id}").parse().unwrap() };
        TestView {
            id: 7,
            network: NetworkId(1),
            a: reference(1),
            b: reference(2),
            state: TestState::Running,
            request: TestRequest { items: items.to_vec(), throughput, via: Vec::new() },
            started_at: 100,
            finished_at: None,
            matrix: None,
            error: None,
            direct: None,
            direct_quality: None,
            relay_quality: Vec::new(),
            route: None,
            hosts: None,
            notes: Vec::new(),
        }
    }

    fn side(ok: bool, failure: Option<TestCode>) -> DirectSide {
        DirectSide { ok, kind: ok.then_some(DirectKind::Punched), elapsed_ms: ok.then_some(640), failure, ..DirectSide::default() }
    }

    fn measured(pick: PathPick, route: Route, throughput: Option<Throughput>) -> PathMeasure {
        PathMeasure {
            route,
            picked_by: vec![pick],
            failure: None,
            latency: Some(Latency { probes: 100, answered: 100, avg_us: Some(20_000), ..Latency::default() }),
            cost_us: Some(21_000),
            hops: Vec::new(),
            relay_leg: None,
            throughput,
        }
    }

    fn choice() -> Choice {
        Choice { route: Some(Route::Relay { relays: vec![node(9)] }), reason: ChoiceCode::PeerRelay, cost_us: Some(30_000), cheaper: None }
    }

    fn decision() -> Decision {
        Decision { mode: None, current: None, direct_first: choice(), lowest_cost: choice(), candidates: Vec::new() }
    }

    #[test]
    fn the_two_ends_are_merged_into_one_result_with_the_failure_blamed_on_the_node_that_has_it() {
        let items = [TestItem::Direct, TestItem::Route];
        let view = base(&items, false);
        let initiator = TestReport {
            test: 7,
            role: Some(TestRole::Initiator),
            last: true,
            direct: Some(side(false, Some(TestCode::Timeout))),
            decision: Some(decision()),
            ..TestReport::default()
        };
        let responder = TestReport {
            test: 7,
            role: Some(TestRole::Responder),
            last: true,
            direct: Some(side(false, Some(TestCode::UdpBlocked))),
            decision: Some(decision()),
            ..TestReport::default()
        };
        let skips = Skips::default();
        let merged =
            merge(&Inputs { base: &view, skips: &skips, initiator: Some(&initiator), responder: Some(&responder), finished: true });
        let direct = merged.direct.unwrap();
        assert_eq!((direct.state, direct.ok), (ItemState::Done, false));
        assert_eq!(
            direct.problem.map(|problem| (problem.code, problem.node)),
            Some((TestCode::UdpBlocked, Some(node(2)))),
            "UDP 不通比超时说得清楚"
        );
        assert_eq!(direct.sides.iter().map(|side| side.node).collect::<Vec<_>>(), [node(1), node(2)]);
        let route = merged.route.unwrap();
        assert_eq!(
            (route.state, route.forward.map(|view| (view.from, view.to)), route.reverse.map(|view| (view.from, view.to))),
            (ItemState::Done, Some((node(1), node(2))), Some((node(2), node(1))))
        );
        assert!(merged.notes.is_empty());
    }

    #[test]
    fn a_refused_throughput_carries_the_reason_the_peer_gave_and_missing_reports_are_named() {
        let view = base(&[TestItem::Direct, TestItem::DirectQuality, TestItem::RelayQuality], true);
        let refused = Throughput {
            up: None,
            down: None,
            failure: Some(TestCode::Refused),
            transport: "quic".to_owned(),
            congestion: "bbr".to_owned(),
            limit_bytes: 1,
            limit_ms: 1,
            pinned: false,
        };
        let fine = Throughput {
            up: Some(Transfer { bytes: 10, ms: 1, bits_per_second: Some(80_000), stopped_by: TransferEnd::Bytes }),
            failure: None,
            ..refused.clone()
        };
        let initiator = TestReport {
            test: 7,
            last: true,
            direct: Some(side(true, None)),
            paths: vec![
                measured(PathPick::Direct, Route::Direct { addr: "1.2.3.4:5".parse().unwrap() }, Some(refused)),
                measured(PathPick::DirectFirst, Route::Relay { relays: vec![node(9)] }, Some(fine)),
            ],
            ..TestReport::default()
        };
        let off = TestProblem::new(TestCode::ThroughputOff, Some(node(2)));
        let responder =
            TestReport { test: 7, throughput_refused: Some(off.clone()), direct: Some(side(true, None)), ..TestReport::default() };
        let skips = Skips::default();
        let running =
            merge(&Inputs { base: &view, skips: &skips, initiator: Some(&initiator), responder: Some(&responder), finished: false });
        let direct_throughput = running.direct_quality.unwrap().throughput.unwrap();
        assert_eq!((direct_throughput.state, direct_throughput.problem), (ItemState::Skipped, Some(off)), "对端说它关掉了吞吐测试：没有量");
        let relayed = &running.relay_quality[0];
        assert_eq!(
            (relayed.state, relayed.throughput.as_ref().map(|throughput| throughput.state)),
            (ItemState::Done, Some(ItemState::Done))
        );
        assert!(running.direct.unwrap().ok);
        assert!(running.notes.is_empty(), "测试还没结束，接受方的最后一次上报还会来");

        let finished =
            merge(&Inputs { base: &view, skips: &skips, initiator: Some(&initiator), responder: Some(&responder), finished: true });
        assert_eq!(finished.notes, [TestProblem::new(TestCode::NoReport, Some(node(2)))]);
        let nothing = merge(&Inputs { base: &view, skips: &skips, initiator: None, responder: None, finished: true });
        assert_eq!(nothing.direct.unwrap().problem, Some(TestProblem::new(TestCode::NoReport, Some(node(1)))));
    }

    #[test]
    fn items_known_to_be_impossible_are_skipped_with_their_reason() {
        let view = base(&[TestItem::Direct, TestItem::DirectQuality, TestItem::RelayQuality], true);
        let skips = Skips {
            direct: Some(TestProblem::new(TestCode::RelayOnly, Some(node(2)))),
            relay: Some(TestProblem::new(TestCode::NoRelay, None)),
            throughput: None,
        };
        let merged = merge(&Inputs { base: &view, skips: &skips, initiator: None, responder: None, finished: false });
        assert_eq!(merged.direct.unwrap().state, ItemState::Skipped);
        assert_eq!(merged.direct_quality.unwrap().problem.map(|problem| problem.code), Some(TestCode::RelayOnly));
        assert_eq!(merged.relay_quality[0].problem.as_ref().map(|problem| problem.code), Some(TestCode::NoRelay));
    }

    #[test]
    fn the_final_state_follows_cancellation_refusal_and_the_initiators_report() {
        let refused = TestReport { refused: Some(TestProblem::new(TestCode::Busy, Some(node(2)))), ..TestReport::default() };
        assert_eq!(final_state(true, None, None), (TestState::Cancelled, None));
        assert_eq!(final_state(false, Some(&TestReport::default()), Some(&refused)).0, TestState::Failed);
        assert_eq!(final_state(false, Some(&TestReport::default()), None), (TestState::Done, None));
        assert_eq!(final_state(false, None, None).0, TestState::Failed);
    }
}
