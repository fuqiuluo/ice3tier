//! 控制任务里主动测试的部分：时间窗、回答和发出测试的探测、暂时固定路、直连尝试、两种模式的选择。
//! 规矩见 [`crate::diag`]。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use i3t_crypto::Signature;
use i3t_proto::NodeId;
use i3t_proto::probe::{TestId, TestPing, TestPong};
use tokio::sync::oneshot;

use super::route::{RouteKey, View};
use super::{Attempt, Control, PeerState};
use crate::diag::{
    Admission, CheaperPath, ChoiceReason, DirectAttempt, DirectFailure, HopReport, HopSource, MAX_PIN, ModeChoice, Pin, RouteDecision,
    Side, TestPath, TestSpec, TrainError, TrainReport, TrainRun, TrainSpec, Window,
};
use crate::relays::Leg;
use crate::report::{CandidateReport, RelayLeg};
pub(super) use crate::routing::lowest_cost_path;
use crate::routing::{Candidate, PathId};
use crate::table::{Hop, send_frame_via};

impl Control {
    /// 选路时看到的此刻的状态。`entries` 是 [`Control::entries`] 算出来的；只用来把路径落实成收发做法的时候可以是空的。
    fn view<'a>(&'a self, entries: &'a [crate::routing::Entry], now: Instant) -> View<'a> {
        View {
            shared: &self.shared,
            relays: &self.relays,
            legs: &self.legs,
            matrix: &self.matrix,
            broken: &self.broken,
            entries,
            allow_direct: self.allow_direct,
            allow_relay: self.allow_relay,
            max_hops: self.max_hops,
            now,
        }
    }

    pub(super) fn open_test(&mut self, spec: &TestSpec, now: Instant) {
        if !self.peers.contains_key(&spec.peer) {
            tracing::info!(test = spec.test, peer = %spec.peer, "未开启主动测试：对端不在 netmap 中");
            return;
        }
        let window = Window::new(spec, now);
        tracing::info!(test = spec.test, peer = %spec.peer, window_secs = window.until.saturating_duration_since(now).as_secs(), relays = ?spec.relays, "已开启主动测试时间窗");
        self.windows.insert(spec.test, window);
        self.sync_open_tests();
    }

    pub(super) fn close_test(&mut self, test: TestId, why: &'static str) {
        if self.windows.remove(&test).is_none() {
            return;
        }
        tracing::info!(test, why, "已关闭主动测试时间窗");
        self.sync_open_tests();
        // 测试没了，它的探测包列也就到此为止：已经发出去的照样算，没发的不发了。
        let now = Instant::now();
        let (ended, running): (Vec<TrainRun>, Vec<TrainRun>) =
            std::mem::take(&mut self.trains).into_iter().partition(|train| train.spec.test == test);
        self.trains = running;
        for mut train in ended {
            if let Some(reply) = train.reply.take() {
                let _waiting = reply.send(Ok(train.report(now)));
            }
        }
    }

    fn sync_open_tests(&self) {
        let open = self.windows.iter().map(|(test, window)| (*test, window.peer)).collect();
        *self.shared.open_tests.write().expect("open tests lock poisoned") = open;
    }

    /// 定期推进主动测试状态：关闭到期时间窗；发起方在测试期间将对端保持为活跃状态（常规寻路、直连探测与中转会话维持正常进行）；
    /// 直连尝试得出结果后即刻返回应答。
    pub(super) fn poll_tests(&mut self, now: Instant) {
        let expired: Vec<TestId> = self.windows.iter().filter(|(_, window)| !window.is_open(now)).map(|(test, _)| *test).collect();
        for test in expired {
            self.close_test(test, "时间窗到期");
        }
        let clock = &self.shared.clock;
        for window in self.windows.values().filter(|window| window.side == Side::Lead) {
            if let Some(peer) = self.peers.get(&window.peer) {
                peer.slot.last_demand.touch(clock);
            }
        }
        let attempts = std::mem::take(&mut self.attempts);
        for attempt in attempts {
            let Some(peer) = self.peers.get(&attempt.peer) else {
                let _waiting = attempt.reply.send(self.failed_attempt(None, DirectFailure::NotPeer));
                continue;
            };
            if let Some(established) = peer.direct.established_at().filter(|_| peer.direct.active().is_some()) {
                let elapsed = established.saturating_duration_since(attempt.started);
                tracing::info!(peer = %attempt.peer, elapsed_ms = elapsed.as_millis(), kind = ?peer.direct.kind(), "主动测试直连尝试成功");
                let result = DirectAttempt {
                    ok: true,
                    already: false,
                    kind: peer.direct.kind(),
                    elapsed: Some(elapsed),
                    failure: None,
                    udp: self.udp_state(now),
                    mapping_varies: self.mapping_varies,
                    candidates: peer.direct.candidate_count(),
                };
                let _waiting = attempt.reply.send(result);
            } else if now >= attempt.deadline || attempt.reply.is_closed() {
                let failure = self.direct_failure(peer, now);
                tracing::info!(peer = %attempt.peer, ?failure, "主动测试直连尝试失败");
                let _waiting = attempt.reply.send(self.failed_attempt(Some(peer), failure));
            } else {
                if attempt.side == Side::Lead {
                    peer.slot.last_demand.touch(clock);
                }
                self.attempts.push(attempt);
            }
        }
    }

    fn failed_attempt(&self, peer: Option<&PeerState>, failure: DirectFailure) -> DirectAttempt {
        DirectAttempt {
            ok: false,
            already: false,
            kind: None,
            elapsed: None,
            failure: Some(failure),
            udp: self.udp_state(Instant::now()),
            mapping_varies: self.mapping_varies,
            candidates: peer.map_or(0, |peer| peer.direct.candidate_count()),
        }
    }

    /// 本节点的 UDP 通不通：到某个 relay 走着 UDP、或者地址查询有回答就是通的；到 relay 都只能走 TCP 就是不通的；
    /// 两样都没有时不知道。
    fn udp_state(&self, now: Instant) -> Option<bool> {
        let legs: Vec<Leg> = self.relays.values().filter_map(|entry| entry.link.leg()).collect();
        if legs.iter().any(|leg| matches!(leg, Leg::Udp(_))) || self.addr_query.observations(now).next().is_some() {
            return Some(true);
        }
        (!legs.is_empty()).then_some(false)
    }

    /// 直连没有建起来，从本节点这一侧看最可能的原因。
    fn direct_failure(&self, peer: &PeerState, now: Instant) -> DirectFailure {
        if self.dial_out_only && peer.dial_out_only {
            DirectFailure::DialOutOnly
        } else if self.udp_state(now) == Some(false) {
            DirectFailure::UdpUnavailable
        } else if self.mapping_varies == Some(true) {
            DirectFailure::MappingVaries
        } else if peer.direct.candidate_count() == 0 {
            DirectFailure::NoCandidates
        } else {
            DirectFailure::Timeout
        }
    }

    /// 试一次直连，最多等 `limit`；已经有了就当场回答。带头时没有可用的直连就不等退避、从头尝试，并把对端当作活跃的；
    /// 跟随时只是等着看对端的尝试有没有让直连通起来（见 [`Side`]）。
    pub(super) fn attempt_direct(&mut self, id: NodeId, side: Side, limit: Duration, reply: oneshot::Sender<DirectAttempt>, now: Instant) {
        if !self.allow_direct {
            tracing::info!(peer = %id, "跳过直连尝试：本节点路径策略为仅经 relay");
            let _waiting = reply.send(self.failed_attempt(None, DirectFailure::RelayOnly));
            return;
        }
        let Some(peer) = self.peers.get_mut(&id) else {
            let _waiting = reply.send(self.failed_attempt(None, DirectFailure::NotPeer));
            return;
        };
        if side == Side::Lead {
            peer.slot.last_demand.touch(&self.shared.clock);
        }
        if peer.direct.active().is_some() {
            let result = DirectAttempt {
                ok: true,
                already: true,
                kind: peer.direct.kind(),
                elapsed: None,
                failure: None,
                udp: None,
                mapping_varies: self.mapping_varies,
                candidates: peer.direct.candidate_count(),
            };
            let result = DirectAttempt { udp: self.udp_state(now), ..result };
            tracing::info!(peer = %id, kind = ?result.kind, "主动测试直连尝试：当前已有可用直连");
            let _waiting = reply.send(result);
            return;
        }
        match side {
            Side::Lead => {
                tracing::info!(peer = %id, limit_ms = limit.as_millis(), "主动测试：立即发起直连尝试，跳过退避等待");
                peer.direct.retry_now();
            }
            Side::Follow => tracing::info!(peer = %id, limit_ms = limit.as_millis(), "主动测试：等待对端发起直连尝试"),
        }
        self.attempts.push(Attempt { peer: id, side, started: now, deadline: now + limit, reply });
    }

    pub(super) fn pin(&mut self, id: NodeId, pin: Pin, now: Instant) {
        let Some(peer) = self.peers.get_mut(&id) else { return };
        let pin = Pin { until: pin.until.min(now + MAX_PIN), ..pin };
        tracing::info!(peer = %id, path = ?pin.path, secs = pin.until.saturating_duration_since(now).as_secs_f32(), "主动测试已临时固定到对端的路由");
        peer.pin = Some(pin);
    }

    pub(super) fn unpin(&mut self, id: NodeId, pin: u64) {
        let Some(peer) = self.peers.get_mut(&id) else { return };
        if peer.pin.is_some_and(|current| current.id == pin) {
            tracing::info!(peer = %id, "主动测试解除固定的路");
            peer.pin = None;
        }
    }

    /// 解析向 `id` 沿 `path` 发送测试探测所使用的转发目标；当前不可达时返回 `None`。
    fn test_hop(&self, id: NodeId, path: TestPath, now: Instant) -> Option<Hop> {
        let peer = self.peers.get(&id)?;
        match path {
            TestPath::Direct => self.allow_direct.then(|| peer.direct.active()).flatten().map(|(addr, _)| Hop::Direct(addr)),
            TestPath::Relays(relays) => self.view(&[], now).resolve(id, peer, PathId::Relays(relays)).map(|(_, hop)| hop),
        }
    }

    /// 处理对端的测试探测：先执行低开销校验再验签，随后沿反向路径返回应答。
    pub(super) fn on_test_ping(&mut self, from: SocketAddr, ping: &TestPing, at: Instant, relayed: bool, now: Instant) {
        if ping.dst != self.shared.me {
            return;
        }
        let path = TestPath::from_relays(ping.path);
        let Some(window) = self.windows.get(&ping.test) else { return };
        if let Err(why) = window.screen(ping.src, ping.seq, path, now) {
            tracing::debug!(test = ping.test, peer = %ping.src, seq = ping.seq, why, "忽略该测试探测");
            return;
        }
        // 声明为直连的探测必须经直连到达，反之亦然；本节点未启用直连时不响应直连探测，避免暴露地址。
        if (path == TestPath::Direct) == relayed || (path == TestPath::Direct && !self.allow_direct) {
            tracing::debug!(test = ping.test, peer = %ping.src, relayed, "忽略该测试探测：实际到达路径与声明路径不一致，或本节点未启用直连");
            return;
        }
        let Some(peer) = self.peers.get(&ping.src) else { return };
        if i3t_crypto::verify(&peer.key, TestPing::PURPOSE, &ping.signed_message(), &Signature::from_bytes(ping.signature)).is_err() {
            tracing::debug!(test = ping.test, peer = %ping.src, "测试探测签名校验失败，已丢弃");
            return;
        }
        let hop = match path {
            TestPath::Direct => Some(Hop::Direct(from)),
            TestPath::Relays(_) => self.test_hop(ping.src, path.reversed(), now),
        };
        let Some(window) = self.windows.get_mut(&ping.test) else { return };
        let Admission::Answer { received } = window.admit(ping.seq, path) else { return };
        let held = Instant::now().saturating_duration_since(at);
        let mut pong = TestPong {
            src: self.shared.me,
            dst: ping.src,
            test: ping.test,
            seq: ping.seq,
            held_us: u32::try_from(held.as_micros()).unwrap_or(u32::MAX),
            received,
            same_path: hop.is_some(),
            signature: [0; 64],
        };
        pong.signature = *self.key.sign(TestPong::PURPOSE, &pong.signed_message()).as_bytes();
        let bytes = pong.to_bytes();
        match hop {
            Some(hop) => send_frame_via(&self.shared, ping.src, &hop, &bytes),
            // 反向路径当前不可达：改沿本节点当前路由返回应答，并在应答字段中标记。
            None => peer.slot.send_frame(&self.shared, &bytes),
        }
    }

    /// 处理本节点测试探测包列的应答。
    pub(super) fn on_test_pong(&mut self, pong: &TestPong, at: Instant) {
        if pong.dst != self.shared.me {
            return;
        }
        let Some(train) = self.trains.iter().position(|train| train.spec.test == pong.test && train.spec.peer == pong.src) else { return };
        let Some(index) = self.trains[train].index_of(pong.seq) else { return };
        let Some(peer) = self.peers.get(&pong.src) else { return };
        if i3t_crypto::verify(&peer.key, TestPong::PURPOSE, &pong.signed_message(), &Signature::from_bytes(pong.signature)).is_err() {
            tracing::debug!(test = pong.test, peer = %pong.src, "测试探测应答签名校验失败，已丢弃");
            return;
        }
        let held = Duration::from_micros(u64::from(pong.held_us));
        self.trains[train].answered(index, at, held, pong.received, pong.same_path);
    }

    pub(super) fn start_train(&mut self, spec: TrainSpec, reply: oneshot::Sender<Result<TrainReport, TrainError>>, now: Instant) {
        let refused = if !self.peers.contains_key(&spec.peer) {
            Some(TrainError::NotPeer)
        } else if !self.windows.get(&spec.test).is_some_and(|window| window.is_open(now) && window.peer == spec.peer) {
            Some(TrainError::NoWindow)
        } else if spec.path == TestPath::Direct && !self.allow_direct {
            Some(TrainError::DirectDisabled)
        } else if spec.path != TestPath::Direct && !self.allow_relay {
            Some(TrainError::RelayDisabled)
        } else if self.test_hop(spec.peer, spec.path, now).is_none() {
            Some(TrainError::Unreachable)
        } else {
            None
        };
        if let Some(error) = refused {
            tracing::info!(test = spec.test, peer = %spec.peer, path = ?spec.path, %error, "拒绝发送测试探测包列");
            let _waiting = reply.send(Err(error));
            return;
        }
        let first_seq = self.windows.get_mut(&spec.test).map_or(0, |window| window.take_seqs(spec.count));
        let mut train = TrainRun::new(spec, first_seq, now, reply);
        train.relay_leg = match spec.path {
            TestPath::Direct => None,
            TestPath::Relays(relays) => self.relays.get(&relays.first()).and_then(|entry| entry.link.leg()).map(|leg| match leg {
                Leg::Udp(_) => RelayLeg::Udp,
                Leg::Tcp => RelayLeg::Tcp,
            }),
        };
        train.peer_addr = self
            .peers
            .get(&spec.peer)
            .and_then(|peer| peer.direct.active())
            .map(|(addr, _)| addr)
            .filter(|_| spec.path == TestPath::Direct);
        tracing::info!(test = spec.test, peer = %spec.peer, path = ?spec.path, count = train.spec.count, interval_ms = train.spec.interval.as_millis(), "开始发送测试探测包列");
        self.trains.push(train);
        self.poll_trains(now);
    }

    /// 发送到达计划时刻的测试探测，并汇总已完成包列的测试报告。
    pub(super) fn poll_trains(&mut self, now: Instant) {
        let mut trains = std::mem::take(&mut self.trains);
        for train in &mut trains {
            while let Some((index, _)) = train.next_due().filter(|(_, due)| *due <= now) {
                let seq = train.first_seq.saturating_add(u32::try_from(index).unwrap_or(u32::MAX));
                let (test, peer, path) = (train.spec.test, train.spec.peer, train.spec.path);
                // 即使发送时刻路径刚断开而不可达，也记录为已发送：由此计入丢包，以反映测试期间的真实中断。
                if let Some(hop) = self.test_hop(peer, path, now) {
                    let mut ping = TestPing { src: self.shared.me, dst: peer, test, seq, path: path.relays(), signature: [0; 64] };
                    ping.signature = *self.key.sign(TestPing::PURPOSE, &ping.signed_message()).as_bytes();
                    let bytes = ping.to_bytes();
                    let sent = Instant::now();
                    send_frame_via(&self.shared, peer, &hop, &bytes);
                    train.sent_at[index] = Some(sent);
                } else {
                    train.sent_at[index] = Some(now);
                }
            }
        }
        for mut train in trains {
            if train.is_finished(now) || train.reply.as_ref().is_none_or(oneshot::Sender::is_closed) {
                let report = train.report(now);
                let summary = report.summary();
                tracing::info!(
                    test = train.spec.test,
                    peer = %train.spec.peer,
                    path = ?train.spec.path,
                    sent = summary.sent,
                    answered = summary.answered,
                    avg_us = summary.avg_us,
                    "测试探测包列完成"
                );
                if let Some(reply) = train.reply.take() {
                    let _waiting = reply.send(Ok(report));
                }
            } else {
                self.trains.push(train);
            }
        }
    }

    /// 两种选路模式此刻各会选哪条路，以及 relay 质量默认要测的两条路径。对端不在 netmap 里时是 `None`。
    pub(super) fn decide(&self, id: NodeId, now: Instant) -> Option<RouteDecision> {
        let peer = self.peers.get(&id)?;
        let entries = self.entries(now);
        let view = self.view(&entries, now);
        let mut candidates = view.candidates(id, peer);
        candidates.retain(|candidate| view.resolve(id, peer, candidate.path).is_some());
        let cost_of = |path: PathId| candidates.iter().find(|candidate| candidate.path == path).map(|candidate| candidate.cost_ms);
        let me = self.shared.me;

        let current_chain = peer.policy_route.path().filter(|path| matches!(path, PathId::Relays(relays) if relays.as_slice().len() > 1));
        let direct_first = match view.default_route(id, peer, &candidates, current_chain) {
            Some(path @ PathId::Direct(_)) => {
                let reason = if peer.direct.is_lan_active() { ChoiceReason::Lan } else { ChoiceReason::Direct };
                ModeChoice { route: path.to_route(), reason, cost_ms: cost_of(path), cheaper: None }
            }
            Some(path @ PathId::Relays(relays)) => {
                let reason = match relays.first() {
                    _ if relays.as_slice().len() > 1 => ChoiceReason::NoSharedRelay,
                    first if first == id => ChoiceReason::PeerIsRelay,
                    first if first == me => ChoiceReason::OwnRelay,
                    _ => ChoiceReason::PeerRelay,
                };
                ModeChoice { route: path.to_route(), reason, cost_ms: cost_of(path), cheaper: None }
            }
            None => ModeChoice::none(),
        };
        let current = peer.policy_route.path().and_then(|path| candidates.iter().find(|candidate| candidate.path == path));
        let lowest_cost = lowest_cost_choice(&candidates, current);
        // 不算直连时默认模式会经的 relay：同一套规则，只是假装直连不可用。
        let without_direct = View { allow_direct: false, ..self.view(&entries, now) };
        let default_relay = match without_direct.default_route(id, peer, &candidates, current_chain) {
            Some(PathId::Relays(relays)) => Some(relays),
            Some(PathId::Direct(_)) | None => None,
        };
        let cheapest_relay = candidates.iter().find_map(|candidate| match candidate.path {
            PathId::Relays(relays) => Some(relays),
            PathId::Direct(_) => None,
        });
        // "现在走的路"是选路规则选的那一条：测试自己为了量吞吐暂时固定的路不算，不然测完的结果里写的是测试的路。
        Some(RouteDecision {
            mode: self.mode,
            current: peer.policy_route.to_route(),
            direct_first,
            lowest_cost,
            default_relay,
            cheapest_relay,
            candidates: candidates.iter().map(|candidate| candidate_report(candidate, peer.policy_route)).collect(),
        })
    }

    /// 一条路径上各段的测量值：本节点到第一个 relay 是自己测的，relay 之间来自骨干矩阵，最后一个 relay 到对端是对端上报的。
    pub(super) fn hops(&self, id: NodeId, path: TestPath, now: Instant) -> Vec<HopReport> {
        let me = self.shared.me;
        let Some(peer) = self.peers.get(&id) else { return Vec::new() };
        let unknown = |from, to| HopReport { from, to, rtt_ms: None, jitter_ms: None, loss: None, source: HopSource::Unknown };
        let measured = |from, to, quality: Option<crate::estimate::Quality>| match quality {
            Some(quality) => {
                let segment = quality.segment();
                let loss = (quality.probes > 0).then_some(segment.loss);
                HopReport { from, to, rtt_ms: Some(segment.rtt_ms), jitter_ms: Some(segment.jitter_ms), loss, source: HopSource::Measured }
            }
            None => unknown(from, to),
        };
        let relays = match path {
            TestPath::Direct => return vec![measured(me, id, peer.direct.quality(now))],
            TestPath::Relays(relays) => relays,
        };
        let list = relays.as_slice();
        let mut hops = Vec::with_capacity(list.len() + 1);
        if let Some(&first) = list.first().filter(|first| **first != me) {
            hops.push(measured(me, first, self.relays.get(&first).and_then(|entry| entry.link.quality(now))));
        }
        for pair in list.windows(2) {
            let (from, to) = (pair[0], pair[1]);
            let link = self.matrix.links_from(from, now).find(|(next, _)| *next == to).map(|(_, quality)| quality);
            hops.push(match link {
                Some(quality) => HopReport {
                    from,
                    to,
                    rtt_ms: Some(f64::from(quality.rtt_ms)),
                    jitter_ms: Some(f64::from(quality.jitter_ms)),
                    loss: Some(quality.loss()),
                    source: HopSource::Backbone,
                },
                None => unknown(from, to),
            });
        }
        if list.last() == Some(&me) {
            // 本节点自身 relay：该段为对端挂靠于本节点上的会话，测量值与选路共享同一来源（见 `View::local_leg`）。
            let leg = self.view(&[], now).local_leg(id, peer);
            hops.push(leg.map_or_else(
                || unknown(me, id),
                |(segment, source)| {
                    let measured = source == HopSource::Measured;
                    HopReport {
                        from: me,
                        to: id,
                        rtt_ms: Some(segment.rtt_ms),
                        jitter_ms: measured.then_some(segment.jitter_ms),
                        loss: measured.then_some(segment.loss),
                        source,
                    }
                },
            ));
        } else if let Some(&last) = list.last().filter(|last| **last != id) {
            let reported = peer.attached.iter().find(|attachment| attachment.relay == last);
            hops.push(match reported {
                Some(attachment) => HopReport {
                    from: last,
                    to: id,
                    rtt_ms: Some(f64::from(attachment.rtt_ms)),
                    jitter_ms: None,
                    loss: None,
                    source: HopSource::Reported,
                },
                None => unknown(last, id),
            });
        }
        hops
    }
}

/// 延迟优先模式从这一对现在走的路（`current`，它在候选里时）出发会选哪条：局域网直连无条件优先；
/// 代价最低的候选比现在的路便宜得够选路器换过去（[`routing::beats_by_margin`]）就是它，不够就还是现在的路，
/// 并带上那条更便宜的。现在的路不在候选里（没有路、断了）时选路器立刻换到最低的，不看差距。
///
/// 仅比较代价差距：连续评估窗口数、切换后停留期以及刚重连 relay 的稳定等待期属于时间维度条件，单次快照中无法体现。
fn lowest_cost_choice(candidates: &[Candidate], current: Option<&Candidate>) -> ModeChoice {
    let chosen = |candidate: &Candidate, reason| ModeChoice {
        route: candidate.path.to_route(),
        reason,
        cost_ms: Some(candidate.cost_ms),
        cheaper: None,
    };
    let usable: Vec<&Candidate> = candidates.iter().collect();
    let Some(path) = lowest_cost_path(&usable, current.map(|current| current.path)) else { return ModeChoice::none() };
    let Some(picked) = candidates.iter().find(|candidate| candidate.path == path) else { return ModeChoice::none() };
    match candidates.first() {
        _ if picked.lan => chosen(picked, ChoiceReason::Lan),
        Some(cheapest) if cheapest.path != path => ModeChoice {
            cheaper: Some(CheaperPath { route: cheapest.path.to_route(), cost_ms: cheapest.cost_ms }),
            ..chosen(picked, ChoiceReason::WithinMargin)
        },
        Some(_) | None => chosen(picked, ChoiceReason::LowestCost),
    }
}

fn candidate_report(candidate: &Candidate, current: RouteKey) -> CandidateReport {
    let current = current.path();
    CandidateReport {
        route: candidate.path.to_route(),
        cost_ms: candidate.cost_ms,
        legs: candidate
            .legs
            .iter()
            .map(|leg| crate::report::LegReport {
                from: leg.from,
                to: leg.to,
                rtt_ms: leg.segment.rtt_ms,
                jitter_ms: leg.segment.jitter_ms,
                loss: leg.segment.loss,
            })
            .collect(),
        load_percent: candidate.load_percent,
        current: Some(candidate.path) == current,
        relay_leg: None,
    }
}

#[cfg(test)]
mod tests {
    use i3t_model::control::Route;
    use i3t_proto::datagram::RelayPath;

    use super::*;

    fn direct(cost_ms: f64) -> Candidate {
        let addr: SocketAddr = "203.0.113.7:20330".parse().unwrap();
        Candidate { path: PathId::Direct(addr), legs: Vec::new(), cost_ms, load_percent: 0, lan: false, settled: true }
    }

    fn via(relay: u32, cost_ms: f64) -> Candidate {
        let path = PathId::Relays(RelayPath::new(&[NodeId::new(relay).unwrap()]).unwrap());
        Candidate { path, legs: Vec::new(), cost_ms, load_percent: 0, lan: false, settled: true }
    }

    fn relay_route(relay: u32) -> Route {
        Route::Relay { relays: vec![NodeId::new(relay).unwrap()] }
    }

    #[test]
    fn the_lowest_cost_pick_for_the_route_table_follows_the_same_rule() {
        let (on_direct, near, far) = (direct(74.3), via(3, 74.1), via(4, 20.0));
        let path = |candidate: &Candidate| candidate.path;
        assert_eq!(lowest_cost_path(&[&near, &on_direct], Some(path(&on_direct))), Some(path(&on_direct)), "便宜得不够：还是现在的路");
        assert_eq!(lowest_cost_path(&[&far, &on_direct], Some(path(&on_direct))), Some(path(&far)), "便宜得够：换过去");
        assert_eq!(lowest_cost_path(&[&near, &on_direct], None), Some(path(&near)), "现在没有路：直接取最低的");
        let lan = Candidate { lan: true, ..direct(90.0) };
        assert_eq!(lowest_cost_path(&[&far, &lan], Some(path(&far))), Some(path(&lan)), "局域网直连无条件优先");
        assert_eq!(lowest_cost_path(&[], Some(path(&far))), None, "没有候选就没有路");
    }

    #[test]
    fn a_slightly_cheaper_relay_does_not_move_a_pair_off_its_current_path() {
        let (on_direct, relay) = (direct(74.3), via(3, 74.1));
        let choice = lowest_cost_choice(&[relay.clone(), on_direct.clone()], Some(&on_direct));
        assert_eq!((choice.reason, choice.cost_ms), (ChoiceReason::WithinMargin, Some(74.3)), "{choice:?}");
        assert!(matches!(choice.route, Route::Direct { .. }), "还是现在的直连：{choice:?}");
        assert_eq!(choice.cheaper, Some(CheaperPath { route: relay_route(3), cost_ms: 74.1 }), "更便宜的那条和它的代价也在");
    }

    #[test]
    fn a_candidate_cheaper_by_the_selectors_margin_is_the_choice() {
        let current = direct(74.3);
        let choice = lowest_cost_choice(&[via(3, 60.0), current.clone()], Some(&current));
        assert_eq!((choice.route, choice.reason, choice.cheaper), (relay_route(3), ChoiceReason::LowestCost, None));
        // 代价高的时候差距按比例算：200ms 的路，181ms 的不够，180ms 的够。
        let current = direct(200.0);
        assert_eq!(lowest_cost_choice(&[via(3, 181.0), current.clone()], Some(&current)).reason, ChoiceReason::WithinMargin);
        assert_eq!(lowest_cost_choice(&[via(3, 180.0), current.clone()], Some(&current)).reason, ChoiceReason::LowestCost);
    }

    #[test]
    fn without_a_usable_current_path_the_cheapest_is_taken_at_once_and_a_lan_path_always_wins() {
        let candidates = [via(3, 30.0), via(4, 31.0)];
        let choice = lowest_cost_choice(&candidates, None);
        assert_eq!((choice.route, choice.reason), (relay_route(3), ChoiceReason::LowestCost), "没有路时不看差距");
        let on_cheapest = lowest_cost_choice(&candidates, Some(&candidates[0]));
        assert_eq!((on_cheapest.route, on_cheapest.reason, on_cheapest.cheaper), (relay_route(3), ChoiceReason::LowestCost, None));
        let lan = Candidate { lan: true, ..direct(40.0) };
        assert_eq!(lowest_cost_choice(&[via(3, 30.0), lan], Some(&candidates[0])).reason, ChoiceReason::Lan);
        assert_eq!(lowest_cost_choice(&[], None), ModeChoice::none());
    }
}
