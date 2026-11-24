//! 对外公布的状态：路由表、挂靠、给界面的路径报告、骨干矩阵、试过的 relay。

use std::time::{Duration, Instant};

use i3t_model::control::{MAX_RELAY_TRIES, RelayTry, Route, RouteEntry};
use i3t_model::netmap::Attachment;
use i3t_proto::NodeId;
use i3t_proto::backbone::LinkQuality;

use super::route::{RouteKey, Via};
use super::{Control, MAX_REPORTED_CANDIDATES, PeerState};
use crate::Status;
use crate::relays::Leg;
use crate::report::{Alternative, BackboneLink, BackboneRow, CandidateReport, LegReport, PathReport, RelayLeg};
use crate::routing::PathId;
use crate::timing::Rtt;

impl Control {
    /// 汇总本节点探测过的各 relay 可达状态并上报给 controller。按已建立会话、可达、不可达排序，最多返回 [`MAX_RELAY_TRIES`] 条。
    pub(super) fn relay_tries(&self, now: Instant) -> Vec<RelayTry> {
        let mut tries: Vec<(bool, RelayTry)> = self
            .relays
            .iter()
            .filter_map(|(&relay, entry)| {
                let (outcome, at) = entry.link.last_try(now)?;
                let age_secs = u32::try_from(now.saturating_duration_since(at).as_secs()).unwrap_or(u32::MAX);
                let seen_as = entry.link.seen_as(now);
                Some((entry.link.leg().is_some(), RelayTry { relay, outcome, age_secs, seen_as }))
            })
            .collect();
        tries.sort_unstable_by_key(|(session, entry)| (!session, !entry.outcome.reached(), entry.age_secs, entry.relay));
        tries.into_iter().take(MAX_RELAY_TRIES).map(|(_, entry)| entry).collect()
    }

    pub(super) fn publish_status(&mut self, now: Instant) {
        self.status_refreshed = Some(now);
        self.published_attachments = self.attachment_ids();
        let mut routes: Vec<RouteEntry> = self
            .peers
            .iter()
            .map(|(&id, peer)| RouteEntry { peer: id, route: peer.route.to_route(), rtt_ms: self.route_rtt_ms(id, peer) })
            .collect();
        routes.sort_unstable_by_key(|entry| entry.peer);
        let own = self.attached.iter().map(|id| (id, false));
        let shared = self.shared_relays.iter().map(|id| (id, true));
        let mut attached: Vec<Attachment> = own
            .chain(shared)
            .filter_map(|(id, shared)| {
                Some(Attachment { relay: *id, rtt_ms: self.relays.get(id)?.link.reported_rtt(now)?.millis(), shared })
            })
            .collect();
        attached.sort_by_key(|attachment| attachment.rtt_ms);

        let mut reports: Vec<PathReport> = self.peers.iter().map(|(&id, peer)| self.report(id, peer, now)).collect();
        reports.sort_unstable_by_key(|report| report.peer);
        let mut backbone: Vec<BackboneRow> = self
            .matrix
            .rows(now)
            .map(|(row, age)| BackboneRow {
                relay: row.origin,
                state: row.state,
                load_percent: row.load_percent,
                age_ms: u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
                links: row
                    .links
                    .iter()
                    .map(|link| BackboneLink {
                        to: link.relay,
                        rtt_ms: link.quality.map(|quality| quality.rtt_ms),
                        jitter_ms: link.quality.map_or(0, |quality| quality.jitter_ms),
                        loss: link.quality.map_or(0.0, LinkQuality::loss),
                    })
                    .collect(),
            })
            .collect();
        backbone.sort_unstable_by_key(|row| row.relay);
        let status = Status {
            routes,
            endpoints: self.endpoints.clone(),
            public_addresses: self.public_addresses.clone(),
            mapping_varies: self.mapping_varies,
            attached,
            reports,
            backbone,
            relay_tries: self.relay_tries(now),
        };
        *self.shared.status.lock().expect("path status mutex poisoned") = status;
    }

    /// 现在这条路上的往返延迟。
    pub(super) fn route_rtt_ms(&self, id: NodeId, peer: &PeerState) -> Option<u32> {
        self.path_rtt_ms(id, peer, peer.route.path()?)
    }

    /// 一条路径上的往返延迟，和路由表里现在这条路的算法一样。
    pub(super) fn path_rtt_ms(&self, id: NodeId, peer: &PeerState, path: PathId) -> Option<u32> {
        match path {
            PathId::Direct(_) => peer.direct.active().map(|(_, rtt)| rtt.millis()),
            PathId::Relays(path) => match *path.as_slice() {
                // 经一个 relay 的延迟是两段之和：本节点到 relay 是自己测的，relay 到对端是对端上报的。
                [relay] => {
                    let near = self.relays.get(&relay).and_then(|entry| entry.link.rtt()).map(|rtt| rtt.millis());
                    let far = peer.attached.iter().find(|attachment| attachment.relay == relay).map(|attachment| attachment.rtt_ms);
                    match (near, far) {
                        // relay 就是对端自己：只有一段。
                        (near, None) if relay == id => near,
                        (near, Some(far)) => Some(near.unwrap_or(0).saturating_add(far)),
                        (_, None) => None,
                    }
                }
                // 多级路径：各段相加，取最近一次算候选时的测量值。
                _ => {
                    let chosen = peer.candidates.iter().find(|candidate| candidate.path == PathId::Relays(path))?;
                    let total: f64 = chosen.legs.iter().map(|leg| leg.segment.rtt_ms).sum();
                    Some(Rtt::new(Duration::try_from_secs_f64(total / 1000.0).ok()?).millis())
                }
            },
        }
    }

    /// 给界面看的：到这个对端考虑过哪些路、现在走哪条、为什么。
    pub(super) fn report(&self, id: NodeId, peer: &PeerState, now: Instant) -> PathReport {
        let current = peer.route.path();
        let candidates = peer
            .candidates
            .iter()
            .take(MAX_REPORTED_CANDIDATES)
            .map(|candidate| CandidateReport {
                route: candidate.path.to_route(),
                cost_ms: candidate.cost_ms,
                legs: candidate
                    .legs
                    .iter()
                    .map(|leg| LegReport {
                        from: leg.from,
                        to: leg.to,
                        rtt_ms: leg.segment.rtt_ms,
                        jitter_ms: leg.segment.jitter_ms,
                        loss: leg.segment.loss,
                    })
                    .collect(),
                load_percent: candidate.load_percent,
                current: Some(candidate.path) == current,
                relay_leg: match candidate.path {
                    PathId::Direct(_) => None,
                    PathId::Relays(path) => self.relays.get(&path.first()).and_then(|entry| entry.link.leg()).map(|leg| match leg {
                        Leg::Udp(_) => RelayLeg::Udp,
                        Leg::Tcp => RelayLeg::Tcp,
                    }),
                },
            })
            .collect();
        PathReport {
            peer: id,
            mode: self.mode,
            route: peer.route.to_route(),
            direct: matches!(peer.route, RouteKey::Direct(_)).then(|| peer.direct.kind()).flatten(),
            relay_leg: match peer.route {
                RouteKey::Relay { via: Via::Udp(_), .. } => Some(RelayLeg::Udp),
                RouteKey::Relay { via: Via::Tcp(_), .. } => Some(RelayLeg::Tcp),
                RouteKey::Relay { via: Via::Local, .. } | RouteKey::Direct(_) | RouteKey::None => None,
            },
            reason: peer.reason.text.clone(),
            cause: Some(peer.reason.cause.clone()),
            since_switch_ms: peer.switched.map(|at| u64::try_from(now.saturating_duration_since(at).as_millis()).unwrap_or(u64::MAX)),
            direct_status: peer.direct.status(now),
            alternative: peer.other_mode.filter(|other| *other != current).map(|other| Alternative {
                route: other.map_or(Route::None, PathId::to_route),
                rtt_ms: other.and_then(|path| self.path_rtt_ms(id, peer, path)),
            }),
            candidates,
        }
    }
}
