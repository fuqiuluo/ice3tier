//! 骨干矩阵的行：收别的 relay 的行，本节点是 relay 时发自己的。

use std::time::Instant;

use bytes::Bytes;
use i3t_crypto::Signature;
use i3t_proto::NodeId;
use i3t_proto::backbone::{Link, LinkQuality, Row};

use super::{Control, NEWCOMER_BATCH, RelayEntry, RowGate};
use crate::relays::Leg;
use crate::timing::ROW_INTERVAL;
use crate::{LocalRelay, SessionLeg};

impl Control {
    /// 骨干矩阵的一行，是从 `via` 这个 relay 的会话上收到的（它自己的，或者它转来的别的 relay 的）。
    pub(super) fn on_row(&mut self, via: NodeId, frame: &Bytes, now: Instant) {
        // 只认现在有会话的 relay 发来的：没有会话就没有核对过它的地址。
        if self.relays.get(&via).is_none_or(|entry| entry.link.leg().is_none()) {
            return;
        }
        let Some((origin, seq)) = Row::peek(frame) else { return };
        let Some(origin_key) = self.netmap.relay(origin).map(|relay| relay.key).filter(|_| origin != self.shared.me) else { return };
        // 不比手上的新就不用往下看了：验签名是这里唯一花钱的事。来源地址是可以伪造的，所以验的次数也有上限，
        // 按行的主人分开算：一个 relay 不停地发新的行，花掉的只是它自己的额度。正常情况下每个 relay 几秒才有一行新的。
        if !self.matrix.is_news(origin, seq, now) {
            return;
        }
        let gate = self.row_gates.entry(origin).or_insert_with(|| RowGate::new(now));
        if !gate.budget.take(now) {
            tracing::debug!(%via, %origin, "该 relay 矩阵行接收速率超限，跳过验签并丢弃");
            return;
        }
        let (Some((row, signature)), Some(signed)) = (Row::parse(frame), Row::signed_part(frame)) else { return };
        if i3t_crypto::verify(&origin_key, Row::PURPOSE, signed, &Signature::from_bytes(signature)).is_err() {
            tracing::debug!(%via, %origin, "骨干矩阵行签名校验失败，已丢弃");
            return;
        }
        let state = row.state;
        let brings_up = self.matrix.brings_up_links(&row, now);
        let state_changed = self.matrix.insert(row, frame.clone(), now);
        if state_changed {
            tracing::info!(relay = %origin, ?state, %via, "relay 状态已变更");
        }
        // 状态变更或骨干链路恢复的行不等下一轮即广播给本节点 relay 上的会话，使下游节点尽快感知。
        // 后者用于修正骨干由 TCP 切回 UDP 时的矩阵行（见 `publish_rows`），避免多级路径中断数秒。
        // 同一 relay 的即时转发受速率限制，防止状态或连通性频繁抖动的行被本节点放大。
        if (state_changed || brings_up)
            && let Some(local) = self.shared.local_relay.get()
            && gate.forward(now)
        {
            local.broadcast(frame);
        }
    }

    /// 本节点作为 relay 时，向会话发布自身测得的骨干链路与其他 relay 的矩阵行（周期性发布，状态变更或骨干链路恢复时立即发布）。
    pub(super) fn publish_rows(&mut self, now: Instant) {
        let Some(local) = self.shared.local_relay.get() else { return };
        let Some(status) = local.status() else {
            self.own_state = None;
            return;
        };
        let state_changed = self.own_state != Some(status.state);
        let since_sent = self.rows_sent.map(|at| now.saturating_duration_since(at));
        let due = since_sent.is_none_or(|since| since >= ROW_INTERVAL);
        // 有新的会话：让它马上拿到矩阵。一批节点同时挂上来时合成一次发，不是每来一个发一轮。
        let newcomers = self.sessions_seen != status.sessions_opened && since_sent.is_none_or(|since| since >= NEWCOMER_BATCH);
        let links = self.own_links(local.as_ref(), now);
        // 若上一行中处于断开状态的骨干链路现已恢复，则立即发布更新。骨干由 TCP 切回 UDP 时双向会话依次迁移，
        // 首个会话迁入触发新会话广播时该链路仍显示断开；若等到下一周期（ROW_INTERVAL）再更正，期间多级路径将无法使用该链路。
        // 此类补发行不会连续触发：其前必然存在一条标注该链路断开的矩阵行，而断开行仅按常规周期或新会话节奏发布。
        let came_up = links.iter().any(|link| link.quality.is_some() && !self.rows_linked.contains(&link.relay));
        if !due && !state_changed && !newcomers && !came_up {
            return;
        }
        self.own_state = Some(status.state);
        self.rows_linked = links.iter().filter(|link| link.quality.is_some()).map(|link| link.relay).collect();
        local.publish_row(&links);
        // 仅额外发布本节点单行（状态变更或链路恢复）不重置全表周期：新接入会话仍需整张矩阵，周期广播亦保持原定节奏，
        // 避免骨干链路陆续恢复期间反复推迟整表广播，导致新接入节点迟迟无法收到其他 relay 的矩阵行。
        if due || newcomers {
            self.sessions_seen = status.sessions_opened;
            self.rows_sent = Some(now);
            for frame in self.matrix.frames(now) {
                local.broadcast(frame);
            }
        }
    }

    /// 本节点测到的到每个别的 relay 的骨干链路：两个会话不在同一处的是断的。
    fn own_links(&self, local: &dyn LocalRelay, now: Instant) -> Vec<Link> {
        let me = self.shared.me;
        self.netmap
            .relays
            .iter()
            .filter(|relay| relay.id != me)
            .map(|relay| {
                // 一条骨干连接算通，要本节点在对方那里有会话（包从那里送过去），对方在本节点这里也有（它据此认本节点发的包），
                // 两个会话还要在同一处：都走 UDP，或者都在同一条 TCP 上（见 [`crate::backbone`]）。
                let theirs = local.session_leg(relay.id);
                let paired = |entry: &&RelayEntry| match (entry.link.leg(), theirs) {
                    (Some(Leg::Udp(_)), Some(SessionLeg::Udp)) => true,
                    (Some(Leg::Tcp), Some(theirs)) => self.legs.get(&relay.id).is_some_and(|leg| leg.carries(theirs)),
                    (Some(Leg::Udp(_) | Leg::Tcp) | None, _) => false,
                };
                let quality = self
                    .relays
                    .get(&relay.id)
                    .filter(paired)
                    .and_then(|entry| entry.link.quality(now))
                    .map(|quality| LinkQuality::from_measured(quality.rtt, quality.jitter, quality.lost, quality.probes));
                Link { relay: relay.id, quality }
            })
            .collect()
    }
}
