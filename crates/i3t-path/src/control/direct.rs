//! 直连和端到端的路径探测：打洞信令、PING / PONG、局域网信标，推进直连的状态机。

use std::net::SocketAddr;
use std::time::Instant;

use i3t_crypto::Signature;
use i3t_model::control::{RouteHint, Signal};
use i3t_proto::{NodeId, PublicKey, probe};
use i3t_underlay::lan::Sighting;

use super::{Control, PATH_PING_MIN_GAP, direct_policy, observed_is_mine};
use crate::direct::{Action, Change};

impl Control {
    /// 把要认的对端和"发不发信标"告诉局域网发现。
    pub(super) fn sync_lan(&self) {
        let lan = self.shared.lan.lock().expect("lan discovery mutex poisoned");
        let Some(lan) = lan.as_ref() else { return };
        // 不建立直连的节点既不找人也不让人找；只主动连接的节点照样听，但自己不出声。
        let keys: Vec<PublicKey> = if self.allow_direct { self.peers.values().map(|peer| peer.key).collect() } else { Vec::new() };
        lan.set_peers(&keys);
        lan.set_announcing(self.allow_direct && !self.dial_out_only);
    }

    pub(super) fn on_signal(&mut self, from: NodeId, signal: &Signal, now: Instant) {
        if !self.allow_direct {
            tracing::debug!(peer = %from, "本节点未启用直连，已忽略打洞信令");
            return;
        }
        let Some(peer) = self.peers.get_mut(&from) else {
            tracing::debug!(peer = %from, "收到非 netmap 节点的信令，已忽略");
            return;
        };
        let policy = direct_policy(&self.shared, self.allow_direct, self.dial_out_only, self.mode, &self.endpoints, peer, now);
        if !policy.signal {
            tracing::debug!(peer = %from, "本节点或对端仅允许主动外连，不参与打洞，已忽略信令");
            return;
        }
        // 信令是经 controller 或者已经认证的连接送来的，对端确实想和本端建立直连：记下来，后面几轮探测才会跟上。
        // 不把它当成有流量（见 `direct_policy`）：不为它建中转会话，也不动到它的路。
        peer.signalled = Some(now);
        let actions = peer.direct.on_signal(signal, now, &policy);
        self.perform(from, actions);
    }

    /// 对端的 PING：验签名，回 PONG，并且反过来验证它的来源地址。
    pub(super) fn on_ping(&mut self, from: SocketAddr, ping: &probe::Ping, now: Instant) {
        let me = self.shared.me;
        if ping.dst != me || !self.allow_direct {
            return;
        }
        let Some(peer) = self.peers.get_mut(&ping.src) else {
            tracing::trace!(%from, src = %ping.src, "收到来源节点不在 netmap 中的 PING，已丢弃");
            return;
        };
        if self.dial_out_only && !peer.slot.is_active(&self.shared.clock) {
            // 只主动连接的节点不理别人主动找上来的探测，只有它自己正在连的对端除外。
            return;
        }
        // 对端的候选地址来的用那个地址自己的额度；陌生地址来的先用这个对端的、再用全体的。不管签名对不对都要扣：
        // 不验就不知道对不对。
        let budgeted = match peer.direct.charge(from, now) {
            Some(granted) => granted,
            None => peer.stranger_budget.take(now) && self.verify_budget.take(now),
        };
        if !budgeted {
            tracing::debug!(%from, src = %ping.src, "该地址发送的 PING 速率超限，跳过验签并丢弃");
            return;
        }
        let message = probe::Ping::signed_message(ping.src, ping.dst, &ping.nonce);
        if i3t_crypto::verify(&peer.key, probe::Ping::PURPOSE, &message, &Signature::from_bytes(ping.signature)).is_err() {
            tracing::debug!(%from, src = %ping.src, "PING 签名校验失败，已丢弃");
            return;
        }
        if peer.direct.active().is_some_and(|(addr, _)| addr == from) {
            peer.slot.last_rx_direct.touch(&self.shared.clock);
        }
        let message = probe::Pong::signed_message(me, ping.src, &ping.nonce, from);
        let signature = *self.key.sign(probe::Pong::PURPOSE, &message).as_bytes();
        let pong = probe::Pong { src: me, dst: ping.src, nonce: ping.nonce, observed: from, signature };
        self.shared.port.send_datagram(&pong.to_bytes(), from);
        let reverse = peer.direct.on_ping(from, now);
        self.perform(ping.src, reverse);
    }

    pub(super) fn on_pong(&mut self, from: SocketAddr, pong: &probe::Pong, now: Instant) {
        if pong.dst != self.shared.me || !self.allow_direct {
            return;
        }
        let Some(peer) = self.peers.get_mut(&pong.src) else { return };
        // 对端从直连回答了本端经 relay 发的路径探测（它那个方向走的是直连）。
        if peer.probe.pending.is_some_and(|(nonce, _)| nonce == pong.nonce) || peer.local_leg.expects(&pong.nonce) {
            self.on_path_pong(pong.src, pong, now);
            return;
        }
        // 先看它是不是在回答本端发过的 PING，是才值得验签名。
        if !peer.direct.expects_pong(from, &pong.nonce) {
            return;
        }
        let message = probe::Pong::signed_message(pong.src, pong.dst, &pong.nonce, pong.observed);
        if i3t_crypto::verify(&peer.key, probe::Pong::PURPOSE, &message, &Signature::from_bytes(pong.signature)).is_err() {
            tracing::debug!(%from, src = %pong.src, "PONG 签名校验失败，已丢弃");
            return;
        }
        let local_network = peer.direct.is_local_network(from);
        if !observed_is_mine(pong.observed, local_network, &self.local_candidates, &self.endpoints) {
            tracing::debug!(%from, src = %pong.src, observed = %pong.observed, "对端上报的观测地址不属于本节点，可能存在中间转发，已忽略该 PONG");
            return;
        }
        if peer.direct.active().is_some_and(|(addr, _)| addr == from) {
            peer.slot.last_rx_direct.touch(&self.shared.clock);
        }
        if let Some(Change::Up { addr }) = peer.direct.on_pong(from, &pong.nonce, now) {
            tracing::debug!(peer = %pong.src, %addr, "直连地址验证通过");
        }
    }

    /// 对端经 relay 发来的端到端路径探测：验签名，然后从本节点到它的那条路回答。
    ///
    /// 回答走的是本节点自己选的路，不是探测来的那条路（每个节点只为自己发出的包选路），所以回答到了只说明对端的路是通的。
    pub(super) fn on_path_ping(&mut self, from: NodeId, ping: &probe::Ping, now: Instant) {
        let me = self.shared.me;
        let Some(peer) = self.peers.get_mut(&from) else { return };
        if ping.src != from || ping.dst != me {
            return;
        }
        if peer.probe.answered.is_some_and(|at| now.saturating_duration_since(at) < PATH_PING_MIN_GAP) {
            return;
        }
        // 验签名之前就记下：这个间隔限的是验签名的次数，签名不对的也算一次。
        peer.probe.answered = Some(now);
        let message = probe::Ping::signed_message(ping.src, ping.dst, &ping.nonce);
        if i3t_crypto::verify(&peer.key, probe::Ping::PURPOSE, &message, &Signature::from_bytes(ping.signature)).is_err() {
            tracing::debug!(peer = %from, "路径探测签名校验失败，已丢弃");
            return;
        }
        // 探测是经 relay 来的，没有"看到的来源地址"可报。
        let observed = SocketAddr::from(([0, 0, 0, 0], 0));
        let message = probe::Pong::signed_message(me, from, &ping.nonce, observed);
        let signature = *self.key.sign(probe::Pong::PURPOSE, &message).as_bytes();
        let pong = probe::Pong { src: me, dst: from, nonce: ping.nonce, observed, signature };
        peer.slot.send_frame(&self.shared, &pong.to_bytes());
    }

    /// 处理对端返回的路径探测应答：确认当前多级路径可达；若属于测量“本节点 relay → 对端”链路的探测（`View::local_leg`），则记录往返耗时。
    pub(super) fn on_path_pong(&mut self, from: NodeId, pong: &probe::Pong, now: Instant) {
        let Some(peer) = self.peers.get_mut(&from) else { return };
        let path_probe = peer.probe.pending.is_some_and(|(nonce, _)| nonce == pong.nonce);
        if pong.src != from || pong.dst != self.shared.me || !(path_probe || peer.local_leg.expects(&pong.nonce)) {
            return;
        }
        let message = probe::Pong::signed_message(pong.src, pong.dst, &pong.nonce, pong.observed);
        if i3t_crypto::verify(&peer.key, probe::Pong::PURPOSE, &message, &Signature::from_bytes(pong.signature)).is_err() {
            tracing::debug!(peer = %from, "路径探测应答签名校验失败，已丢弃");
            return;
        }
        if path_probe {
            peer.probe.pending = None;
            peer.probe.missed = 0;
            // 路径已恢复可达：清除此前因探测持续无响应且无备选路径时遗留的起因，避免后续常规切换误报为探测超时。
            if peer.hint == Some(RouteHint::PathProbeSilent) {
                peer.hint = None;
            }
        } else {
            peer.local_leg.on_reply(&pong.nonce, now);
        }
    }

    /// 在本地网段上看到了一个对端的信标：它的来源地址成为一个直连候选，照样要用带签名的探测验证过才用。
    /// 信标造得出来，所以它最多引出一个探测，别的都不动（见 [`DirectPath::on_lan_sighting`](crate::direct::DirectPath::on_lan_sighting)）。
    pub(super) fn on_lan(&mut self, sighting: Sighting, now: Instant) {
        if !self.allow_direct {
            return;
        }
        let Some((&id, peer)) = self.peers.iter_mut().find(|(_, peer)| peer.key == sighting.key) else { return };
        tracing::debug!(peer = %id, addr = %sighting.addr, "在局域网里看到了对端的信标");
        let policy = direct_policy(&self.shared, self.allow_direct, self.dial_out_only, self.mode, &self.endpoints, peer, now);
        let probe = peer.direct.on_lan_sighting(sighting.addr, now, &policy);
        self.perform(id, probe);
    }

    /// 把直连状态机要做的事做掉：给 PING 签名发出去，把信令交给钩子。
    pub(super) fn perform(&self, peer: NodeId, actions: impl IntoIterator<Item = Action>) {
        for action in actions {
            match action {
                Action::Ping { to, nonce } => {
                    let message = probe::Ping::signed_message(self.shared.me, peer, &nonce);
                    let signature = *self.key.sign(probe::Ping::PURPOSE, &message).as_bytes();
                    let ping = probe::Ping { src: self.shared.me, dst: peer, nonce, signature };
                    self.shared.port.send_datagram(&ping.to_bytes(), to);
                }
                Action::Signal(signal) => self.shared.send_signal(peer, &signal),
            }
        }
    }

    pub(super) fn poll_directs(&mut self, now: Instant) {
        let mut todo = Vec::new();
        for (&id, peer) in &mut self.peers {
            let policy = direct_policy(&self.shared, self.allow_direct, self.dial_out_only, self.mode, &self.endpoints, peer, now);
            let step = peer.direct.poll(now, &policy);
            if let Some(Change::Down { reason }) = step.change {
                peer.hint = Some(reason.hint());
            }
            if !step.actions.is_empty() {
                todo.push((id, step.actions));
            }
        }
        for (id, actions) in todo {
            self.perform(id, actions);
        }
    }
}
