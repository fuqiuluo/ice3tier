//! 到 relay 的会话和挂靠：按地址认 relay、交给它的帧和 TCP 事件、relay 的抱怨和状态通知、挂靠谁、和谁保持会话。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use i3t_model::control::RouteHint;
use i3t_model::netmap::{MAX_SHARED_RELAYS, RoutingMode};
use i3t_proto::backbone::RelayState;
use i3t_proto::session::{Echo, Refused};
use i3t_proto::{NodeId, session};

use super::route::{RouteKey, relay_candidates};
use super::{
    ATTACH_REVIEW, Control, DRAIN_HOLD, InboundLeg, LinkWire, OVERLOAD_HOLD, PROBE_AGAIN, PROBE_LIMIT, PeerState, RelayEntry,
    UNATTACHED_HOLD,
};
use crate::backbone::{Accepted, Gate};
use crate::relays::{self, Backbone, Complaint, Identity, Standing};
use crate::routing::Entry;
use crate::table::{self, RelaySlot};
use crate::tcp::TcpEvent;
use crate::timing::{BACKBONE_PROBE_INTERVAL, ENTRY_RELAYS, PROBE_INTERVAL};

impl Control {
    /// 重建按来源地址认 relay 的两张表。同一个地址是几个 relay 的时，收包路径那张表里给正在用它的那个。
    pub(super) fn relay_addresses(&mut self) -> HashMap<SocketAddr, Arc<RelaySlot>> {
        let mut by_addr: HashMap<SocketAddr, Vec<NodeId>> = HashMap::new();
        for (&id, entry) in &self.relays {
            for addr in entry.link.dispatch_addrs() {
                by_addr.entry(addr).or_default().push(id);
            }
        }
        let mut slots = HashMap::with_capacity(by_addr.len());
        for (addr, ids) in &mut by_addr {
            ids.sort_unstable();
            let using = ids.iter().copied().find(|id| self.relays.get(id).is_some_and(|entry| entry.link.udp_target() == Some(*addr)));
            if let Some(entry) = using.or_else(|| ids.first().copied()).and_then(|id| self.relays.get(&id)) {
                slots.insert(*addr, Arc::clone(&entry.slot));
            }
        }
        self.relay_by_addr = by_addr;
        slots
    }

    /// 有 relay 换了在用的地址：重建按地址认 relay 的表。
    pub(super) fn sync_relay_targets(&mut self) {
        let changed = self.relays.values_mut().fold(false, |changed, entry| entry.link.take_target_changed() | changed);
        if changed {
            let slots = self.relay_addresses();
            self.shared.table_mut().relays = slots;
        }
    }

    /// 从 `from` 来的帧是哪些 relay 的。几个 relay 都有这个地址时，正在用它的那个排在前面。
    pub(super) fn relays_at(&self, from: SocketAddr) -> Vec<NodeId> {
        let mut ids = self.relay_by_addr.get(&from).cloned().unwrap_or_default();
        ids.sort_by_key(|id| self.relays.get(id).is_none_or(|entry| entry.link.udp_target() != Some(from)));
        ids
    }

    pub(super) fn on_relay_frame(&mut self, from: SocketAddr, frame: &session::Frame, now: Instant) {
        let relays_at = self.relays_at(from);
        if relays_at.is_empty() {
            tracing::trace!(%from, "中转会话帧来源不属于 netmap 中的 relay 地址，已丢弃");
            return;
        }
        // 交给有这个地址的每一个 relay：只有在等这个随机数的那个会认它（OK 还要验签名）。
        let Self { shared, key, relays, legs, inbound, next_conn, .. } = self;
        let who = Identity { me: shared.me, key };
        for relay in relays_at {
            let Some(entry) = relays.get_mut(&relay) else { continue };
            let mut wire = LinkWire { shared, slot: &entry.slot, legs, inbound, next_conn };
            entry.link.on_udp_frame(from, frame, now, who, &mut wire);
        }
        self.sync_relay_targets();
        // CHALLENGE 提供了本节点 UDP 可达证据，OK 将骨干切回 UDP：立即更新本节点 relay 门控，以便接收对端随后发来的 AUTH。
        self.sync_gates();
    }

    pub(super) fn on_relay_refusal(&mut self, from: SocketAddr, refused: &Refused, echo: &Echo, now: Instant) {
        // 若已有 relay 正在使用该地址则仅投递给它；否则投递给所有匹配的候选 relay（回显不匹配者会被忽略，见 `RelayLink::on_udp_refusal`）。
        let mut relays_at = self.relays_at(from);
        if let Some(&first) = relays_at.first()
            && self.relays.get(&first).is_some_and(|entry| entry.link.udp_target() == Some(from))
        {
            relays_at.truncate(1);
        }
        let mut complaints = Vec::new();
        let Self { shared, key, relays, legs, inbound, next_conn, .. } = self;
        let who = Identity { me: shared.me, key };
        for relay in relays_at {
            let Some(entry) = relays.get_mut(&relay) else { continue };
            let mut wire = LinkWire { shared, slot: &entry.slot, legs, inbound, next_conn };
            if let Some(complaint) = entry.link.on_udp_refusal(refused, echo, now, who, &mut wire) {
                complaints.push((relay, complaint));
            }
        }
        for (relay, complaint) in complaints {
            self.on_complaint(relay, complaint, now);
        }
        self.sync_relay_targets();
    }

    pub(super) fn on_tcp(&mut self, relay: NodeId, conn: u64, event: &TcpEvent, now: Instant) {
        // 同一个 relay 可能先后连过几次，只认现在这一条上的事件。
        if self.legs.get(&relay).is_none_or(|leg| leg.conn != conn) {
            return;
        }
        if let TcpEvent::Row(frame) = event {
            self.on_row(relay, frame, now);
            return;
        }
        let Self { shared, key, relays, legs, inbound, next_conn, .. } = self;
        let Some(entry) = relays.get_mut(&relay) else { return };
        let who = Identity { me: shared.me, key };
        let complaint = match event {
            TcpEvent::Connected(addr) => {
                let mut wire = LinkWire { shared, slot: &entry.slot, legs, inbound, next_conn };
                entry.link.on_tcp_connected(*addr, now, who, &mut wire);
                None
            }
            TcpEvent::Frame(frame) => {
                let mut wire = LinkWire { shared, slot: &entry.slot, legs, inbound, next_conn };
                entry.link.on_tcp_frame(frame, now, who, &mut wire);
                None
            }
            TcpEvent::Refusal(refused, echo) => {
                let mut wire = LinkWire { shared, slot: &entry.slot, legs, inbound, next_conn };
                entry.link.on_tcp_refusal(refused, echo, now, who, &mut wire)
            }
            TcpEvent::Closed => {
                legs.remove(&relay);
                entry.link.on_tcp_closed(now);
                None
            }
            TcpEvent::Row(_) => None,
        };
        if let Some(complaint) = complaint {
            self.on_complaint(relay, complaint, now);
        }
    }

    /// relay `relay` 经 UDP 敲了门（本节点的 relay 挡下了它的 AUTH，见 [`crate::BackboneInbox::knocked`]）。
    pub(super) fn on_knock(&mut self, relay: NodeId, now: Instant) {
        let Self { shared, key, relays, legs, inbound, next_conn, .. } = self;
        let Some(entry) = relays.get_mut(&relay) else { return };
        let who = Identity { me: shared.me, key };
        let mut wire = LinkWire { shared, slot: &entry.slot, legs, inbound, next_conn };
        entry.link.on_knock(now, who, &mut wire);
        self.sync_relay_targets();
    }

    /// 把骨干上走着 TCP 的那几段和它们的 [`Gate`] 交给本节点的 relay（[`crate::backbone::Gates`]），变了才写。
    pub(super) fn sync_gates(&mut self) {
        let gates: HashMap<NodeId, Gate> = self.relays.iter().filter_map(|(&id, entry)| Some((id, entry.link.udp_gate()?))).collect();
        if gates != self.gates {
            self.shared.gates.set(gates.clone());
            self.gates = gates;
        }
    }

    /// relay `relay` 拨进来的第 `conn` 条 TCP 上的事（本节点的 relay 交来的，见 [`crate::backbone`]）。
    pub(super) fn on_accepted(&mut self, relay: NodeId, conn: u64, event: Accepted, now: Instant) {
        let borrowed = self.legs.get(&relay).filter(|leg| leg.accepted() == Some(conn)).map(|leg| leg.conn);
        match event {
            Accepted::Opened { addr, sender } => {
                if self.relays.contains_key(&relay) && borrowed.is_none() {
                    tracing::debug!(%relay, %addr, conn, "该 relay 拨入的 TCP 连接已建立会话，可供骨干链路复用");
                    self.inbound.insert(relay, InboundLeg { accepted: conn, addr, sender });
                }
            }
            Accepted::Event(event) => match (borrowed, event) {
                (Some(leg), event) => self.on_tcp(relay, leg, &event, now),
                // 还没借来用的那条上来的矩阵行照样收：有没有会话、签名对不对 `on_row` 自己查。
                (None, TcpEvent::Row(frame)) => self.on_row(relay, &frame, now),
                (None, _) => {}
            },
            Accepted::Closed => {
                if self.inbound.get(&relay).is_some_and(|leg| leg.accepted == conn) {
                    self.inbound.remove(&relay);
                }
                if let Some(leg) = borrowed {
                    self.on_tcp(relay, leg, &TcpEvent::Closed, now);
                }
            }
        }
    }

    pub(super) fn on_complaint(&mut self, relay: NodeId, complaint: Complaint, now: Instant) {
        match complaint {
            Complaint::PeerUnattached(peer) => self.mark_unattached(relay, peer, now),
            Complaint::RouteUnavailable(next) => {
                // 仅采信与本节点当前多级路径匹配的报告：首跳为 `relay` 且下一跳为 `next`（若 `next == relay` 表示其拒绝转发多级路径）。
                // 由此限制该表上限不超过 relay 两两组合数。
                let on_route = |peer: &PeerState| {
                    matches!(peer.route, RouteKey::Relay { path, .. }
                        if path.first() == relay && path.as_slice().len() > 1 && (next == relay || path.as_slice().get(1) == Some(&next)))
                };
                if !self.peers.values().any(on_route) {
                    tracing::debug!(%relay, %next, "relay 报告多级路径不可达，但本节点当前未使用该段，已忽略");
                    return;
                }
                let until = now + UNATTACHED_HOLD;
                if let Some(held) = self.broken.iter_mut().find(|(from, to, _)| (*from, *to) == (relay, next)) {
                    held.2 = until;
                    return;
                }
                tracing::info!(%relay, %next, "relay 报告多级路径不可达，暂停使用该骨干链路");
                self.broken.push((relay, next, until));
                for peer in self.peers.values_mut().filter(|peer| on_route(peer)) {
                    peer.hint = Some(RouteHint::RelayPathBroken);
                }
            }
        }
    }

    /// relay 说 `peer` 没有挂在它上面：一段时间里先经对端挂靠的别的 relay 去找它。
    pub(super) fn mark_unattached(&mut self, relay: NodeId, peer: NodeId, now: Instant) {
        let Some(state) = self.peers.get_mut(&peer) else { return };
        state.unattached.retain(|(id, _)| *id != relay);
        state.unattached.push((relay, now + UNATTACHED_HOLD));
        state.hint = Some(RouteHint::PeerNotAttached);
    }

    /// 按矩阵里各个 relay 最新的通知更新它们的状态。
    pub(super) fn sync_standing(&mut self, now: Instant) {
        let Self { relays, matrix, attach_reviewed, peers, .. } = self;
        for (&id, entry) in relays.iter_mut() {
            let state = match matrix.state(id, now) {
                // 下线的通知只管一小段时间，见 [`DRAIN_HOLD`]。
                RelayState::Draining if matrix.age(id, now).is_some_and(|age| age >= DRAIN_HOLD) => RelayState::Serving,
                RelayState::Overloaded => {
                    // 每个节点各自多等一段随机的时间再回去。大家一走它就不过载了；要是一看到"恢复"又一起回去，
                    // 它马上又过载，这样来回就是群体震荡。
                    if entry.state != RelayState::Overloaded {
                        entry.cooling_until = Some(now + OVERLOAD_HOLD + relays::jitter(OVERLOAD_HOLD));
                    }
                    RelayState::Overloaded
                }
                RelayState::Serving if entry.cooling_until.is_some_and(|until| now < until) => RelayState::Overloaded,
                state => state,
            };
            if state == entry.state {
                continue;
            }
            let notice = match state {
                RelayState::Draining => {
                    tracing::info!(relay = %id, "relay 通知即将下线，若有其他可用路径将立即迁移相关路由与挂靠");
                    Some(RouteHint::RelayDraining)
                }
                RelayState::Overloaded => {
                    tracing::info!(relay = %id, "relay 通知过载，若有其他可用 relay 将暂时切换并等待恢复");
                    Some(RouteHint::RelayOverloaded)
                }
                RelayState::Serving => {
                    tracing::info!(relay = %id, "relay 已恢复正常服务");
                    None
                }
            };
            // 正经过它的路马上要换：把原因记下来，换路的日志里说得清是为什么。
            for peer in peers.values_mut() {
                if notice.is_some() && matches!(peer.route, RouteKey::Relay { path, .. } if path.as_slice().contains(&id)) {
                    peer.hint = notice;
                }
            }
            entry.state = state;
            *attach_reviewed = None;
        }
    }

    /// 重新评估挂靠的 relay 集合。
    pub(super) fn review_attachments(&mut self, now: Instant) {
        if self.attach_reviewed.is_some_and(|at| now.saturating_duration_since(at) < ATTACH_REVIEW) {
            return;
        }
        self.attach_reviewed = Some(now);
        // 按 netmap 顺序列出候选：延迟尚未测出时按该顺序使用。将已通知即将下线或过载的 relay 视为不可用：
        // 若存在替代者则立即替换，否则保留（仅剩唯一 relay 时继续保留以等待恢复）。
        let standings: Vec<Standing> = self
            .netmap
            .relays
            .iter()
            .filter_map(|relay| Some((relay.id, self.relays.get(&relay.id)?)))
            .map(|(id, entry)| Standing {
                id,
                rtt: entry.link.estimate(now),
                failing: entry.state != RelayState::Serving || (self.attached.contains(&id) && entry.link.is_failing(now)),
            })
            .collect();
        let chosen =
            if self.allow_relay { relays::choose_attached(&self.attached, &standings, &self.netmap.me.pinned_relays) } else { Vec::new() };
        // controller 为保障其他节点可达本节点而下发的额外共享 relay。即使当前无法连接也保留尝试，以便将失败结果上报给 controller 进行调整。
        let shared: Vec<NodeId> = if self.allow_relay {
            let extra = self.netmap.me.shared_relays.iter().copied();
            extra.filter(|id| self.relays.contains_key(id) && !chosen.contains(id)).take(MAX_SHARED_RELAYS).collect()
        } else {
            Vec::new()
        };
        if shared != self.shared_relays {
            tracing::info!(from = ?self.shared_relays, to = ?shared, "额外挂靠的共享 relay 已变更（按 controller 下发配置，用于保障无法连接本节点常规 relay 的对端可达）");
            self.shared_relays = shared;
        }
        if chosen != self.attached {
            let avoided = |id: &NodeId| self.relays.get(id).is_some_and(|entry| entry.state != RelayState::Serving);
            let reason = if !self.allow_relay {
                "本节点不使用 relay"
            } else if !self.netmap.me.pinned_relays.is_empty() {
                "管理员固定了挂靠的 relay"
            } else if self.attached.iter().any(avoided) {
                "原挂靠的 relay 通知即将下线或过载"
            } else {
                "按到各个 relay 的延迟选择"
            };
            tracing::info!(from = ?self.attached, to = ?chosen, reason, "挂靠的 relay 列表已变更");
            self.attached = chosen;
        }
    }

    /// 决定和哪些 relay 保持会话，并推进到每个 relay 的状态机。
    pub(super) fn poll_relays(&mut self, now: Instant, active: &HashSet<NodeId>) {
        let serving = self.shared.local_relay.get().is_some_and(|local| local.status().is_some());
        let lowest_cost = self.mode == RoutingMode::LowestCost && self.allow_relay && !active.is_empty();
        let mut wanted: HashSet<NodeId> = self.attached.iter().chain(&self.shared_relays).copied().collect();
        if self.allow_relay {
            // 能通到活跃对端的 relay 都连着（对端自己是 relay 的话也包括它）：走 relay 时要经它们，走直连时它们是随时能退回去的备用路。
            for (&id, peer) in self.peers.iter().filter(|(id, _)| active.contains(id)) {
                wanted.extend(relay_candidates(self.shared.me, id, peer, None));
            }
        }
        if lowest_cost {
            // 延迟优先：多级路径从离本节点最近的几个 relay 进。只连这几个，探测量才有上限。
            let mut nearest: Vec<(Duration, NodeId)> =
                self.relays.iter().filter_map(|(&id, entry)| Some((entry.link.estimate(now)?, id))).collect();
            nearest.sort_unstable();
            wanted.extend(nearest.into_iter().take(ENTRY_RELAYS).map(|(_, id)| id));
        }
        if serving {
            // 本节点作为 relay：与其他可达 relay 保持会话以构成骨干网络。
            wanted.extend(self.relays.keys().copied());
        }
        if self.allow_relay {
            // 主动测试指定的路径上，本节点这一头的第一个 relay：测试期间保持会话，平时可能不连它。
            wanted.extend(self.windows.values().filter(|window| window.is_open(now)).flat_map(|window| window.relays.iter().copied()));
        }
        if let Some(relay) = self.probe(now, &wanted) {
            wanted.insert(relay);
        }
        let survey = self.allow_relay && self.netmap.me.pinned_relays.is_empty();
        let Self { shared, key, relays, legs, inbound, next_conn, .. } = self;
        let who = Identity { me: shared.me, key };
        let local = shared.local_relay.get().filter(|_| serving);
        for (id, entry) in relays.iter_mut() {
            // 本节点作为 relay 时，该段亦属骨干链路：根据对端在本节点 relay 上的会话及入站 TCP 情况决定走 UDP 或 TCP。
            let backbone = local.map(|local| Backbone { theirs: local.session_leg(*id), offered: inbound.get(id).map(|leg| leg.accepted) });
            let mut wire = LinkWire { shared, slot: &entry.slot, legs, inbound, next_conn };
            let want = wanted.contains(id);
            entry.link.set_probe_interval(if serving { BACKBONE_PROBE_INTERVAL } else { PROBE_INTERVAL });
            // 延迟优先模式下，会话在用的 relay 都可能是候选路径的第一段：定期发探测包列，丢包率才估得出来。
            entry.link.set_training(lowest_cost && want);
            if want != entry.link.is_wanted() {
                tracing::debug!(relay = %id, want, "与该 relay 的中转会话保持状态已变更");
                entry.link.set_wanted(want, now, &mut wire);
            }
            let urgent = table::unanswered(&shared.clock, &entry.slot.last_tx, &entry.slot.last_rx);
            entry.link.poll(now, who, urgent, survey, backbone, &mut wire);
        }
        self.sync_relay_targets();
        self.sync_gates();
    }

    /// 通过一次临时会话检测对 UDP 探测无响应的 relay（见 [`PROBE_AGAIN`]），返回当前正在检测的目标。
    ///
    /// 每分钟的常规探测仅使用 UDP，无响应的 relay 可能仅支持 TCP 可达。通过会话（并发尝试 UDP 与 TCP）检测一次后即可确定准确结果，
    /// 从而向 controller 上报精确的可达状态。检测完成后即释放会话，同一时刻仅检测一个。
    pub(super) fn probe(&mut self, now: Instant, wanted: &HashSet<NodeId>) -> Option<NodeId> {
        if let Some((relay, started)) = self.probing {
            let finished = self.relays.get(&relay).is_none_or(|entry| {
                let tried_since = entry.link.last_try(now).is_some_and(|(_, at)| at >= started);
                tried_since || now.saturating_duration_since(started) >= PROBE_LIMIT
            });
            if !finished {
                return Some(relay);
            }
            let outcome = self.relays.get(&relay).and_then(|entry| entry.link.last_try(now)).map(|(outcome, _)| outcome);
            tracing::debug!(%relay, ?outcome, "已完成对 UDP 探测无响应 relay 的会话可达性检测");
            self.probing = None;
        }
        if !self.allow_relay {
            return None;
        }
        let due = |entry: &RelayEntry| entry.link.last_try(now).is_none_or(|(_, at)| now.saturating_duration_since(at) >= PROBE_AGAIN);
        let (relay, _) = self
            .relays
            .iter()
            .filter(|(id, entry)| !wanted.contains(id) && entry.link.survey_silent(now) && due(entry))
            .min_by_key(|(id, entry)| (entry.link.last_try(now).map(|(_, at)| at), **id))?;
        let relay = *relay;
        tracing::debug!(%relay, "该 relay 的 UDP 探测无响应，开始发起 UDP/TCP 会话可达性检测");
        self.probing = Some((relay, now));
        Some(relay)
    }

    /// 现在挂靠着、会话通着的 relay（自己挑的和另外挂的），按编号排。对外公布的挂靠就是它们。
    pub(super) fn attachment_ids(&self) -> Vec<NodeId> {
        let mut ids: Vec<NodeId> = self
            .attached
            .iter()
            .chain(&self.shared_relays)
            .copied()
            .filter(|id| self.relays.get(id).is_some_and(|entry| entry.link.rtt().is_some()))
            .collect();
        ids.sort_unstable();
        ids
    }

    /// 本节点现在能把包交给它的 relay：会话是通的、延迟测出来了。
    pub(super) fn entries(&self, now: Instant) -> Vec<Entry> {
        let mut entries: Vec<Entry> = self
            .relays
            .iter()
            .filter(|(_, entry)| entry.link.leg().is_some())
            .filter_map(|(&relay, entry)| {
                Some(Entry { relay, segment: entry.link.quality(now)?.segment(), settled: entry.link.is_settled(now) })
            })
            .collect();
        entries.sort_unstable_by_key(|entry| entry.relay);
        entries
    }
}
