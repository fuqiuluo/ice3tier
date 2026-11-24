//! 一个测试在两端各做什么。
//!
//! - 发起方：试直连 → 在直连上发一列探测（要吞吐时再量上下行）→ 在经 relay 的路径上做同样的事（指定的路径，或者两种模式默认会选的）
//!   → 算两种模式的选择 → 一次报上去。
//! - 接受方：尝试直连（确认本侧直连可达性）→ 首次上报 → 等待测试结束或时间窗到期 → 计算本方向两种模式选路结果 → 最终上报。
//!   探测由路径层回答，测量流由测量服务接，都不在这里。

use std::time::{Duration, Instant};

use i3t_conn::{
    ChoiceReason, DirectAttempt, DirectFailure, Endpoint, HopReport, HopSource as PathHopSource, RouteDecision, Side, TestPath, TrainError,
    TrainReport, TrainSpec,
};
use i3t_flow::FlowError;
use i3t_flow::measure::{Measured, measure};
use i3t_model::control::diag::{
    CheaperPath, Choice, ChoiceCode, Decision, DirectSide, Hop, HopSource, Latency, PathMeasure, PathPick, TestCode, TestRole, Throughput,
    Transfer, TransferEnd,
};
use i3t_model::control::{Route, TestOrder, TestReport};
use i3t_model::netmap::{Congestion, Reach};
use i3t_proto::NodeId;
use i3t_proto::datagram::RelayPath;
use i3t_proto::flow::{MeasureEnd, MeasureMode, OpenMeasure};
use tokio::sync::oneshot;

use super::{Diag, THROUGHPUT_BYTES, THROUGHPUT_TIME, TRAIN_INTERVAL, TRAIN_PROBES};
use crate::route_detail::{candidate, direct_kind_of, leg_transport, micros, permille};

/// 直连尝试最多等多久：打洞的头三次尝试（0、2.5、5 秒开始）都来得及。
const DIRECT_LIMIT: Duration = Duration::from_secs(8);
/// 指定的路径要先建好到第一个 relay 的会话：最多等这么久。
const PATH_READY: Duration = Duration::from_secs(6);
/// 固定路之后等连接真的换到被测的路径上，最多等这么久。
const PIN_SETTLE: Duration = Duration::from_secs(3);

/// 发起方：按指令量完，返回要报的结果。
pub(super) async fn initiate(diag: &Diag, order: &TestOrder) -> TestReport {
    let (endpoint, peer, me) = (&*diag.endpoint, order.peer, diag.me());
    let reach = diag.reach();
    let mut report = TestReport { test: order.test, role: Some(TestRole::Initiator), last: true, ..TestReport::default() };
    // 本机关掉了吞吐测试的话，自己发起的测试也不量吞吐。
    let throughput = order.items.throughput.then_some(()).filter(|()| diag.throughput).map(|()| endpoint.congestion(order.peer));
    let throughput_off = order.items.throughput && !diag.throughput;

    let mut direct = None;
    if order.items.direct || order.items.direct_quality {
        let attempt = if reach == Reach::RelayOnly { None } else { Some(endpoint.attempt_direct(peer, Side::Lead, DIRECT_LIMIT).await) };
        direct = Some(direct_side(attempt.as_ref()));
    }
    if order.items.direct {
        report.direct.clone_from(&direct);
    }
    if order.items.direct_quality {
        let picked = vec![PathPick::Direct];
        let measured = match direct.as_ref() {
            _ if reach == Reach::RelayOnly => failed(Route::None, picked, TestCode::RelayOnly),
            Some(side) if side.ok => measure_path(diag, order, TestPath::Direct, picked, throughput, throughput_off).await,
            Some(_) | None => failed(Route::None, picked, TestCode::NoDirect),
        };
        report.paths.push(measured);
    }
    if order.items.relay_quality {
        if reach == Reach::DirectOnly {
            report.paths.push(failed(Route::None, Vec::new(), TestCode::DirectOnly));
        } else {
            for Planned { path, picked } in relay_paths(diag, order).await {
                let measured = match path {
                    Ok(path) => measure_path(diag, order, TestPath::Relays(path), picked, throughput, throughput_off).await,
                    Err((route, code)) => failed(route, picked, code),
                };
                report.paths.push(measured);
            }
        }
    }
    if order.items.route {
        report.decision = endpoint.route_decision(peer).await.as_ref().map(decision);
    }
    tracing::debug!(test = order.test, %me, %peer, paths = report.paths.len(), "主动测试测量完成");
    report
}

/// 接受方：配合发起方，报自己这一侧看到的。
pub(super) async fn respond(diag: &Diag, order: &TestOrder, until: Instant, ended: oneshot::Receiver<()>) -> TestReport {
    let (endpoint, peer, me) = (&*diag.endpoint, order.peer, diag.me());
    let mut report = TestReport { test: order.test, role: Some(TestRole::Responder), ..TestReport::default() };
    if order.items.throughput && !diag.throughput {
        report.throughput_refused = Some(i3t_model::control::diag::TestProblem::new(TestCode::ThroughputOff, Some(me)));
    }
    if order.items.direct || order.items.direct_quality {
        // 接受方跟随，等发起方来试；只主动连接的节点不理对端主动找上来的探测，只能自己也去试。
        let side = if diag.netmap.borrow().me.dial_out_only { Side::Lead } else { Side::Follow };
        let attempt = if diag.reach() == Reach::RelayOnly { None } else { Some(endpoint.attempt_direct(peer, side, DIRECT_LIMIT).await) };
        report.direct = Some(direct_side(attempt.as_ref()));
    }
    diag.report(report.clone());
    // 等发起方量完（controller 发来结束），或者时间窗到了。
    let _ended = tokio::time::timeout_at(tokio::time::Instant::from_std(until), ended).await;
    if order.items.route {
        report.decision = endpoint.route_decision(peer).await.as_ref().map(decision);
    }
    report.last = true;
    report
}

/// 一端看到的直连能力。`attempt` 是 `None` 表示本节点只经 relay、根本不试。
fn direct_side(attempt: Option<&DirectAttempt>) -> DirectSide {
    let Some(attempt) = attempt else {
        return DirectSide { ok: false, failure: Some(TestCode::RelayOnly), ..DirectSide::default() };
    };
    DirectSide {
        ok: attempt.ok,
        already: attempt.already,
        kind: attempt.kind.map(direct_kind_of),
        elapsed_ms: attempt.elapsed.map(|elapsed| u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX)),
        failure: attempt.failure.map(failure_code),
        udp: attempt.udp,
        mapping_varies: attempt.mapping_varies,
        candidates: u32::try_from(attempt.candidates).unwrap_or(u32::MAX),
    }
}

const fn failure_code(failure: DirectFailure) -> TestCode {
    match failure {
        DirectFailure::RelayOnly => TestCode::RelayOnly,
        DirectFailure::NotPeer => TestCode::NotConnected,
        DirectFailure::DialOutOnly => TestCode::DialOutOnly,
        DirectFailure::NoCandidates => TestCode::NoCandidates,
        DirectFailure::UdpUnavailable => TestCode::UdpBlocked,
        DirectFailure::MappingVaries => TestCode::MappingVaries,
        DirectFailure::Timeout => TestCode::Timeout,
    }
}

fn failed(route: Route, picked_by: Vec<PathPick>, code: TestCode) -> PathMeasure {
    PathMeasure { route, picked_by, failure: Some(code), latency: None, cost_us: None, hops: Vec::new(), relay_leg: None, throughput: None }
}

/// relay 质量要测的一条路径，和为什么测它。路径不能用时是它的写法和原因。
struct Planned {
    path: Result<RelayPath, (Route, TestCode)>,
    picked: Vec<PathPick>,
}

/// relay 质量要测的路径：指定的，或者两种模式默认会选的（相同的只测一次）。
async fn relay_paths(diag: &Diag, order: &TestOrder) -> Vec<Planned> {
    let netmap = std::sync::Arc::clone(&diag.netmap.borrow());
    if !order.paths.is_empty() {
        return order
            .paths
            .iter()
            .map(|relays| {
                let usable = relays.iter().all(|relay| netmap.relay(*relay).is_some() || *relay == netmap.me.id);
                let path =
                    RelayPath::new(relays).ok().filter(|_| usable).ok_or((Route::Relay { relays: relays.clone() }, TestCode::InvalidPath));
                Planned { path, picked: vec![PathPick::Admin] }
            })
            .collect();
    }
    // 默认的两条看路径层手上的会话和测量值：测试刚开始时到对端挂靠的 relay 可能还没有会话，等一小会儿。
    let deadline = Instant::now() + PATH_READY;
    let decision = loop {
        let decision = diag.endpoint.route_decision(order.peer).await;
        let found = decision.as_ref().is_some_and(|decision| decision.default_relay.is_some() || decision.cheapest_relay.is_some());
        if found || Instant::now() >= deadline {
            break decision;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    let mut paths: Vec<Planned> = Vec::new();
    let picks = decision.iter().flat_map(|decision| {
        [(decision.default_relay, PathPick::DirectFirst), (decision.cheapest_relay, PathPick::LowestCost)].into_iter()
    });
    for (path, pick) in picks {
        let Some(path) = path else { continue };
        match paths.iter_mut().find(|planned| planned.path.as_ref().ok() == Some(&path)) {
            Some(planned) => planned.picked.push(pick),
            None => paths.push(Planned { path: Ok(path), picked: vec![pick] }),
        }
    }
    if paths.is_empty() {
        paths.push(Planned { path: Err((Route::None, TestCode::NoRelay)), picked: vec![PathPick::DirectFirst, PathPick::LowestCost] });
    }
    paths
}

/// 在一条路径上发一列探测、取各段的测量值，要吞吐时再量上下行。
async fn measure_path(
    diag: &Diag,
    order: &TestOrder,
    path: TestPath,
    picked_by: Vec<PathPick>,
    congestion: Option<Congestion>,
    throughput_off: bool,
) -> PathMeasure {
    let (endpoint, peer) = (&*diag.endpoint, order.peer);
    let relays = path.relays().map_or(0, |relays| relays.as_slice().len());
    let spec = TrainSpec { test: order.test, peer, path, count: TRAIN_PROBES, interval: TRAIN_INTERVAL };
    let train = train_when_ready(endpoint, spec).await;
    let route = match (&train, path) {
        (Ok(report), TestPath::Direct) => report.peer_addr.map_or(Route::None, |addr| Route::Direct { addr }),
        (Err(_), TestPath::Direct) => Route::None,
        (_, TestPath::Relays(relays)) => Route::Relay { relays: relays.as_slice().to_vec() },
    };
    let report = match train {
        Ok(report) => report,
        Err(error) => {
            tracing::info!(test = order.test, %peer, ?path, %error, "路径探测失败");
            return failed(route, picked_by, TestCode::Unreachable);
        }
    };
    let summary = report.summary();
    let latency = latency(&report);
    let hops = endpoint.path_hops(peer, path).await.iter().map(hop).collect();
    let throughput = match (congestion, throughput_off) {
        (Some(congestion), _) => Some(throughput(endpoint, order, path, congestion).await),
        (None, true) => Some(Throughput {
            up: None,
            down: None,
            failure: Some(TestCode::ThroughputOff),
            transport: "quic".to_owned(),
            congestion: endpoint.congestion(order.peer).to_string(),
            limit_bytes: THROUGHPUT_BYTES,
            limit_ms: millis(THROUGHPUT_TIME),
            pinned: false,
        }),
        (None, false) => None,
    };
    PathMeasure {
        route,
        picked_by,
        failure: None,
        latency: Some(latency),
        cost_us: summary.cost_ms(relays).map(|cost| u64::from(micros(cost))),
        hops,
        relay_leg: report.relay_leg.map(leg_transport),
        throughput,
    }
}

/// 发送一列探测；若指定路径尚未建立会话导致暂不可达，则等待后重试。
async fn train_when_ready(endpoint: &Endpoint, spec: TrainSpec) -> Result<TrainReport, TrainError> {
    let deadline = Instant::now() + PATH_READY;
    loop {
        match endpoint.test_train(spec).await {
            Err(TrainError::Unreachable) if Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(300)).await,
            outcome => return outcome,
        }
    }
}

fn latency(report: &TrainReport) -> Latency {
    let summary = report.summary();
    Latency {
        probes: summary.sent,
        answered: summary.answered,
        min_us: summary.min_us,
        avg_us: summary.avg_us,
        p95_us: summary.p95_us,
        jitter_us: summary.jitter_us,
        loss_permille: summary.loss_permille,
        loss_up_permille: summary.loss_up_permille,
        loss_down_permille: summary.loss_down_permille,
        same_path: report.same_path,
        interval_ms: millis(report.interval),
        duration_ms: millis(report.duration),
    }
}

fn hop(hop: &HopReport) -> Hop {
    Hop {
        from: hop.from,
        to: hop.to,
        rtt_us: hop.rtt_ms.map(micros),
        jitter_us: hop.jitter_ms.map(micros),
        loss_permille: hop.loss.map(permille),
        source: match hop.source {
            PathHopSource::Measured => HopSource::Measured,
            PathHopSource::Backbone => HopSource::Backbone,
            PathHopSource::Reported => HopSource::Reported,
            PathHopSource::Unknown => HopSource::Unknown,
        },
    }
}

/// 在 `path` 上量上下行的吞吐：先把到对端的连接固定在这条路径上，量完（包括中途出错）就解除。
async fn throughput(endpoint: &Endpoint, order: &TestOrder, path: TestPath, congestion: Congestion) -> Throughput {
    let peer = order.peer;
    let limit = (THROUGHPUT_TIME + Duration::from_secs(4)) * 2;
    let pin = endpoint.pin_route(peer, path, limit);
    let settled = on_path(endpoint, peer, path, PIN_SETTLE).await;
    let open = |mode| OpenMeasure { test: order.test, mode, path: path.relays(), bytes: THROUGHPUT_BYTES, millis: millis(THROUGHPUT_TIME) };
    let up = measure(endpoint, peer, &open(MeasureMode::Sink)).await;
    let down = match &up {
        // 对端拒绝了测量流（如已关闭吞吐测试或不识别该测试），无需再测试下行。
        Err(FlowError::Refused(_)) => None,
        _ => Some(measure(endpoint, peer, &open(MeasureMode::Source)).await),
    };
    let held = settled && on_path(endpoint, peer, path, Duration::ZERO).await;
    drop(pin);
    let failure = throughput_failure(&up, down.as_ref());
    tracing::info!(test = order.test, %peer, ?path, up = ?up.as_ref().ok(), down = ?down.as_ref().and_then(|down| down.as_ref().ok()), held, "吞吐测试完成");
    Throughput {
        up: up.ok().map(transfer),
        down: down.and_then(Result::ok).map(transfer),
        failure,
        transport: "quic".to_owned(),
        congestion: congestion.to_string(),
        limit_bytes: THROUGHPUT_BYTES,
        limit_ms: millis(THROUGHPUT_TIME),
        pinned: held,
    }
}

/// 两个方向的测量流合起来算哪一种失败。哪个方向被对端拒绝了都是"拒绝"，不是流中途断了。
fn throughput_failure(up: &Result<Measured, FlowError>, down: Option<&Result<Measured, FlowError>>) -> Option<TestCode> {
    match (up, down) {
        (Err(FlowError::Refused(_)), _) | (_, Some(Err(FlowError::Refused(_)))) => Some(TestCode::Refused),
        (Err(_), _) | (_, Some(Err(_))) => Some(TestCode::StreamFailed),
        (Ok(_), Some(Ok(_)) | None) => None,
    }
}

/// 到 `peer` 的连接现在是不是走在 `path` 上；最多等 `wait`。
async fn on_path(endpoint: &Endpoint, peer: NodeId, path: TestPath, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        let current = endpoint.path_report(peer).map(|report| report.route);
        let matches = match (path, current) {
            (TestPath::Direct, Some(Route::Direct { .. })) => true,
            (TestPath::Relays(relays), Some(Route::Relay { relays: current })) => current == relays.as_slice(),
            (TestPath::Direct | TestPath::Relays(_), _) => false,
        };
        if matches || Instant::now() >= deadline {
            return matches;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn transfer(measured: Measured) -> Transfer {
    Transfer {
        bytes: measured.bytes,
        ms: millis(measured.elapsed),
        bits_per_second: measured.bits_per_second().and_then(|rate| {
            // 每秒的比特数是有限的正数，放得进 u64；借 Duration 换成整数，不用 `as`。
            Duration::try_from_secs_f64(rate).ok().map(|whole| whole.as_secs())
        }),
        stopped_by: match measured.end {
            MeasureEnd::Finished => TransferEnd::Finished,
            MeasureEnd::Bytes => TransferEnd::Bytes,
            MeasureEnd::Time => TransferEnd::Time,
        },
    }
}

fn millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

fn decision(decision: &RouteDecision) -> Decision {
    let choice = |choice: &i3t_conn::ModeChoice| Choice {
        route: (!matches!(choice.route, Route::None)).then(|| choice.route.clone()),
        reason: match choice.reason {
            ChoiceReason::Lan => ChoiceCode::Lan,
            ChoiceReason::Direct => ChoiceCode::Direct,
            ChoiceReason::PeerIsRelay => ChoiceCode::PeerIsRelay,
            ChoiceReason::OwnRelay => ChoiceCode::OwnRelay,
            ChoiceReason::PeerRelay => ChoiceCode::PeerRelay,
            ChoiceReason::NoSharedRelay => ChoiceCode::NoSharedRelay,
            ChoiceReason::LowestCost => ChoiceCode::LowestCost,
            ChoiceReason::WithinMargin => ChoiceCode::WithinMargin,
            ChoiceReason::NoPath => ChoiceCode::NoPath,
        },
        cost_us: choice.cost_ms.map(|cost| u64::from(micros(cost))),
        cheaper: choice
            .cheaper
            .as_ref()
            .map(|cheaper| CheaperPath { route: cheaper.route.clone(), cost_us: u64::from(micros(cheaper.cost_ms)) }),
    };
    Decision {
        mode: Some(decision.mode),
        current: Some(decision.current.clone()),
        direct_first: choice(&decision.direct_first),
        lowest_cost: choice(&decision.lowest_cost),
        candidates: decision.candidates.iter().map(candidate).collect(),
    }
}

#[cfg(test)]
mod tests {
    use i3t_flow::measure::Steady;
    use i3t_proto::flow::{Reply, Status};

    use super::*;

    #[test]
    fn a_transfer_reports_its_rate_in_whole_bits_per_second() {
        let measured = Measured { bytes: 1_000_000, elapsed: Duration::from_millis(800), end: MeasureEnd::Bytes, steady: None };
        let whole = transfer(measured);
        assert_eq!(
            (whole.bytes, whole.ms, whole.bits_per_second, whole.stopped_by),
            (1_000_000, 800, Some(10_000_000), TransferEnd::Bytes)
        );
        // 有起步之后的那一段时速率按它算；字节数和用时仍然是整次搬运的。
        let steady = Steady { bytes: 750_000, elapsed: Duration::from_millis(300) };
        let warmed = transfer(Measured { steady: Some(steady), ..measured });
        assert_eq!((warmed.bytes, warmed.ms, warmed.bits_per_second), (1_000_000, 800, Some(20_000_000)));
        let instant = Measured { bytes: 10, elapsed: Duration::ZERO, end: MeasureEnd::Finished, steady: None };
        assert_eq!(super::transfer(instant).bits_per_second, None, "用时太短算不出速率");
    }

    #[test]
    fn a_refused_measurement_stream_is_reported_as_refused_in_either_direction() {
        let moved = || Ok(Measured { bytes: 10, elapsed: Duration::from_millis(5), end: MeasureEnd::Bytes, steady: None });
        let refused = || Err(FlowError::Refused(Reply::new(Status::NotEnabled, "忙")));
        let broken = || Err(FlowError::Truncated);
        assert_eq!(throughput_failure(&moved(), Some(&moved())), None);
        assert_eq!(throughput_failure(&refused(), None), Some(TestCode::Refused));
        assert_eq!(throughput_failure(&moved(), Some(&refused())), Some(TestCode::Refused), "只有下行被拒绝");
        assert_eq!(throughput_failure(&moved(), Some(&broken())), Some(TestCode::StreamFailed));
        assert_eq!(throughput_failure(&broken(), Some(&moved())), Some(TestCode::StreamFailed));
    }

    #[test]
    fn a_node_that_does_not_try_reports_why() {
        assert_eq!(direct_side(None).failure, Some(TestCode::RelayOnly));
        let attempt = DirectAttempt {
            ok: false,
            already: false,
            kind: None,
            elapsed: None,
            failure: Some(DirectFailure::UdpUnavailable),
            udp: Some(false),
            mapping_varies: None,
            candidates: 2,
        };
        let side = direct_side(Some(&attempt));
        assert_eq!((side.failure, side.udp, side.candidates), (Some(TestCode::UdpBlocked), Some(false), 2));
    }
}
