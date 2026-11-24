//! 把路由层给人看的选路情况写成节点协议里的样子，交给 controller：
//! 上报里每条路的细节（[`kinds`]），现问时的候选路径和代价（[`detail`]），以及骨干矩阵（[`backbone`]）。
//!
//! 路由层用的是浮点数的毫秒和 0 到 1 的丢包率；协议里换成整数（微秒、千分之几），消息因此可以直接比较相等。

use std::sync::Arc;
use std::time::Duration;

use i3t_access::{CurrentRoute, Routes};

use i3t_conn::{
    BackboneRow, CandidateReport, DirectFailureCause, DirectKind, DirectState, DirectStatus, Endpoint, LegReport, PathReport, RelayLeg,
};
use i3t_model::control::{self, PathCandidate, PathDetail, PathSegment, Route, RouteKind};
use i3t_proto::NodeId;
use i3t_proto::backbone::RelayState;

/// 当前路径详情：直连建立方式，或经 relay 时首段使用的传输协议（UDP/TCP）；以及当前直连阶段状态（无论当前是否走直连）。
/// 路由层可为每个对端提供直连状态，因此每个对端均有此字段。
pub(crate) fn kind(report: &PathReport) -> RouteKind {
    let (direct, relay_leg) = (direct_kind(report), report.relay_leg.map(leg_transport));
    let alternative =
        report.alternative.as_ref().map(|other| control::RouteAlternative { route: other.route.clone(), rtt_ms: other.rtt_ms });
    RouteKind { peer: report.peer, direct, relay_leg, direct_status: Some(direct_status(&report.direct_status)), alternative }
}

/// 路由层说的直连在哪一步写成协议里的样子。
pub(crate) fn direct_status(status: &DirectStatus) -> control::DirectStatus {
    control::DirectStatus {
        state: match status.state {
            DirectState::NotTried => control::DirectState::NotTried,
            DirectState::Trying => control::DirectState::Trying,
            DirectState::Verified => control::DirectState::Verified,
            DirectState::Failed => control::DirectState::Failed,
        },
        kind: status.kind.map(direct_kind_of),
        cause: status.failure.map(|failure| match failure {
            DirectFailureCause::NoAnswer => control::DirectCause::NoAnswer,
            DirectFailureCause::NoCandidates => control::DirectCause::NoCandidates,
            DirectFailureCause::Timeouts => control::DirectCause::Timeouts,
            DirectFailureCause::Loss => control::DirectCause::Loss,
            DirectFailureCause::Stale => control::DirectCause::Stale,
        }),
        // 不足一秒的算 0：刚开始的尝试是"0 秒之前"。
        attempted_secs_ago: status.attempted_ms.map(|ms| ms / 1000),
    }
}

pub(crate) const fn leg_transport(leg: RelayLeg) -> control::LegTransport {
    match leg {
        RelayLeg::Udp => control::LegTransport::Udp,
        RelayLeg::Tcp => control::LegTransport::Tcp,
    }
}

/// 到这个对端的选路情况：模式、为什么是现在这条、考虑过的候选路径。
pub(crate) fn detail(report: &PathReport) -> PathDetail {
    PathDetail {
        mode: Some(report.mode),
        direct: direct_kind(report),
        relay_leg: report.relay_leg.map(leg_transport),
        reason: report.reason.clone(),
        cause: report.cause.clone(),
        candidates: report.candidates.iter().map(candidate).collect(),
    }
}

/// 入口和出口写每条流的摘要时问"到这个对端现在走哪条路"，答的是路由层手上现成的结论。
pub(crate) struct EndpointRoutes(pub(crate) Arc<Endpoint>);

impl Routes for EndpointRoutes {
    fn current(&self, peer: NodeId) -> Option<CurrentRoute> {
        let report = self.0.path_report(peer)?;
        Some(CurrentRoute { route: report.route, since_switch: report.since_switch_ms.map(Duration::from_millis) })
    }
}

/// 本节点手上的骨干矩阵。
pub(crate) fn backbone(rows: &[BackboneRow]) -> Vec<control::BackboneRow> {
    rows.iter()
        .map(|row| control::BackboneRow {
            relay: row.relay,
            state: match row.state {
                RelayState::Serving => control::RelayState::Serving,
                RelayState::Overloaded => control::RelayState::Overloaded,
                RelayState::Draining => control::RelayState::Draining,
            },
            load_percent: row.load_percent,
            age_ms: row.age_ms,
            links: row
                .links
                .iter()
                .map(|link| control::BackboneLink {
                    to: link.to,
                    rtt_ms: link.rtt_ms.map(u32::from),
                    jitter_ms: u32::from(link.jitter_ms),
                    loss_permille: permille(link.loss),
                })
                .collect(),
        })
        .collect()
}

/// 直连的类型，只在现在走的就是直连时才有。
fn direct_kind(report: &PathReport) -> Option<control::DirectKind> {
    if !matches!(report.route, Route::Direct { .. }) {
        return None;
    }
    report.direct.map(direct_kind_of)
}

/// 路由层说的直连类型写成协议里的样子。
pub(crate) const fn direct_kind_of(kind: DirectKind) -> control::DirectKind {
    match kind {
        DirectKind::Lan => control::DirectKind::Lan,
        DirectKind::Ipv6 => control::DirectKind::Ipv6,
        DirectKind::Reachable => control::DirectKind::Reachable,
        DirectKind::Punched => control::DirectKind::Punched,
    }
}

pub(crate) fn candidate(candidate: &CandidateReport) -> PathCandidate {
    PathCandidate {
        route: candidate.route.clone(),
        cost_us: u64::from(micros(candidate.cost_ms)),
        legs: candidate.legs.iter().map(segment).collect(),
        load_percent: candidate.load_percent,
        current: candidate.current,
    }
}

fn segment(leg: &LegReport) -> PathSegment {
    PathSegment {
        from: leg.from,
        to: leg.to,
        rtt_us: micros(leg.rtt_ms),
        jitter_us: micros(leg.jitter_ms),
        loss_permille: permille(leg.loss),
    }
}

/// 将毫秒转换为微秒并四舍五入。借助 `Duration` 换算而非使用 `as`：负数和 NaN 返回 0，超出范围时饱和为最大值。
pub(crate) fn micros(ms: f64) -> u32 {
    match Duration::try_from_secs_f64(ms / 1000.0) {
        Ok(duration) => u32::try_from(rounded_thousandths(duration)).unwrap_or(u32::MAX),
        Err(_) if ms > 0.0 => u32::MAX,
        Err(_) => 0,
    }
}

/// 0 到 1 的比例换成千分之几，四舍五入，超出范围的取边界。和 [`micros`] 一样借 `Duration` 来换：比例当成秒数，
/// 毫秒数就是千分之几。
pub(crate) fn permille(fraction: f64) -> u16 {
    let clamped = if fraction.is_nan() { 0.0 } else { fraction.clamp(0.0, 1.0) };
    Duration::try_from_secs_f64(clamped).map_or(0, |duration| u16::try_from((rounded_thousandths(duration) + 500) / 1000).unwrap_or(1000))
}

/// 一段时间有多少微秒，四舍五入：浮点数换算时 20.4 毫秒会变成 20.399999…，直接截断就少了 1。
fn rounded_thousandths(duration: Duration) -> u128 {
    (duration.as_nanos() + 500) / 1000
}

#[cfg(test)]
mod tests {
    use i3t_conn::BackboneLink;
    use i3t_model::netmap::RoutingMode;
    use i3t_proto::NodeId;

    use super::*;

    fn id(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn report(route: Route, direct: Option<DirectKind>) -> PathReport {
        PathReport {
            peer: id(4),
            mode: RoutingMode::LowestCost,
            route,
            direct,
            relay_leg: None,
            reason: "直连代价最低".to_owned(),
            cause: Some(control::RouteCause::Lan),
            since_switch_ms: Some(1500),
            direct_status: DirectStatus {
                state: DirectState::Failed,
                kind: None,
                failure: Some(DirectFailureCause::NoAnswer),
                attempted_ms: Some(2600),
            },
            alternative: None,
            candidates: vec![CandidateReport {
                route: Route::Relay { relays: vec![id(9)] },
                cost_ms: 41.25,
                legs: vec![LegReport { from: id(1), to: id(9), rtt_ms: 20.4, jitter_ms: 0.5, loss: 0.012 }],
                load_percent: 30,
                current: false,
                relay_leg: Some(RelayLeg::Udp),
            }],
        }
    }

    #[test]
    fn a_path_report_becomes_integer_microseconds_and_permille() {
        let direct = Route::Direct { addr: "192.168.1.5:20330".parse().unwrap() };
        let detail = detail(&report(direct.clone(), Some(DirectKind::Lan)));
        assert_eq!(
            (detail.mode, detail.direct, detail.reason.as_str()),
            (Some(RoutingMode::LowestCost), Some(control::DirectKind::Lan), "直连代价最低")
        );
        assert_eq!(detail.cause, Some(control::RouteCause::Lan), "原因的代码原样上报");
        let candidate = &detail.candidates[0];
        assert_eq!((candidate.cost_us, candidate.load_percent, candidate.current), (41_250, 30, false));
        assert_eq!(candidate.legs[0], PathSegment { from: id(1), to: id(9), rtt_us: 20_400, jitter_us: 500, loss_permille: 12 });
        assert_eq!(kind(&report(direct, Some(DirectKind::Punched))).direct, Some(control::DirectKind::Punched));
    }

    #[test]
    fn a_relayed_path_has_no_direct_kind_but_says_where_the_direct_path_stands() {
        let relayed = report(Route::Relay { relays: vec![id(9)] }, Some(DirectKind::Reachable));
        assert_eq!(detail(&relayed).direct, None, "直连的类型只说现在走的直连");
        let failed = control::DirectStatus {
            state: control::DirectState::Failed,
            kind: None,
            cause: Some(control::DirectCause::NoAnswer),
            attempted_secs_ago: Some(2),
        };
        assert_eq!(
            kind(&relayed),
            RouteKind { peer: id(4), direct: None, relay_leg: None, direct_status: Some(failed), alternative: None }
        );

        // 经 relay 时报的是到第一个 relay 那一段走的传输。
        let over_tcp = PathReport { relay_leg: Some(RelayLeg::Tcp), ..relayed };
        assert_eq!(detail(&over_tcp).relay_leg, Some(control::LegTransport::Tcp));
        assert_eq!(kind(&over_tcp).relay_leg, Some(control::LegTransport::Tcp));
    }

    #[test]
    fn odd_measurements_are_clamped_instead_of_wrapping() {
        assert_eq!((micros(-1.0), micros(f64::NAN), micros(1e30), micros(0.0004)), (0, 0, u32::MAX, 0));
        assert_eq!((permille(-0.5), permille(2.0), permille(f64::NAN), permille(0.5), permille(0.0126)), (0, 1000, 0, 500, 13));
    }

    #[test]
    fn backbone_rows_keep_unreachable_links_as_null() {
        let rows = [BackboneRow {
            relay: id(9),
            state: RelayState::Draining,
            load_percent: 80,
            age_ms: 2500,
            links: vec![
                BackboneLink { to: id(3), rtt_ms: None, jitter_ms: 0, loss: 1.0 },
                BackboneLink { to: id(5), rtt_ms: Some(42), jitter_ms: 3, loss: 0.005 },
            ],
        }];
        let converted = backbone(&rows);
        assert_eq!((converted[0].state, converted[0].load_percent, converted[0].age_ms), (control::RelayState::Draining, 80, 2500));
        let links: Vec<_> = converted[0].links.iter().map(|link| (link.to, link.rtt_ms, link.jitter_ms, link.loss_permille)).collect();
        assert_eq!(links, [(id(3), None, 0, 1000), (id(5), Some(42), 3, 5)]);
    }
}
