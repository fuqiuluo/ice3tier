//! 发送端小包聚合：将短时间内发往同一对端的多个小包合并为单个聚合帧（[`PacketHeader::Bundle`]）。
//!
//! # 背景
//!
//! 下载流量在回程方向会产生大量小包（如 50–60 字节的 TCP ACK，每收到两个数据包发送一次）。若逐包发送，
//! 回程包速率将达到数据方向的一半。在按包速率（PPS）限速的链路上，大量小包会耗尽额度导致吞吐受阻，
//! 并波及同方向的其他数据包（如 ping 与路径探测包）。将数十个确认包合并发送可将回程包数降低至原来的几分之一。
//!
//! # 聚合与等待策略
//!
//! 仅聚合小包（长度不超过 [`SMALL_PACKET`] 字节）。大包不等待也不聚合，按原方式直接发送；
//! 若发往同一对端时存在已缓存小包，则先发出已缓存帧以保持数据包顺序。
//!
//! - 同一轮从虚拟网卡批量读取的小包直接合并为一帧，本轮读取结束后立即发送，不额外等待。
//! - 稀疏小包（与上一小包间隔不少于 [`DENSE_GAP`]，如 ping 或游戏数据包）到达后立即发送，不引入额外延迟。
//! - 密集小包（与上一小包间隔小于 [`DENSE_GAP`]，如持续下载的 TCP ACK）会缓存至装满一帧或到达 [`WINDOW`] 时限后发出，
//!   单个小包最多额外等待 1–2 毫秒。
//!
//! 聚合等待依赖定时器。部分平台默认定时器粒度较粗（如 Windows 默认约 15 毫秒），等待 1 毫秒可能实际延迟十余毫秒。
//! 因此每次定时器唤醒都会检查延迟幅度：若连续多次严重延迟，则在 [`COARSE_PAUSE`] 期间暂停等待，仅合并同批读取的数据包。
//!
//! 是否允许聚合由连接层决定（[`i3t_conn::contract::PacketSender::bundle_capacity`]）：需满足对端握手声明支持聚合帧且当前为直连路径。
//! 本模块仅负责小包缓存与发送时机判定。

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use i3t_proto::NodeId;
use i3t_proto::flow::{Bundled, PacketHeader};
use tokio::time::Instant;

/// 小包长度上限（字节）。涵盖 TCP ACK（含时间戳与若干 SACK 块仍不足 100 字节）、DNS 查询/应答及常见游戏状态包。
pub(crate) const SMALL_PACKET: usize = 256;
/// 判定小包为密集到达的最大时间间隔。
const DENSE_GAP: Duration = Duration::from_millis(2);
/// 密集到达时单帧自首包入队起的最长等待窗口。受 1 毫秒定时器刻度影响，实际延迟约为 1–2 毫秒。
const WINDOW: Duration = Duration::from_millis(1);
/// 判定为定时器严重延迟的超出阈值。
const LATE: Duration = Duration::from_millis(4);
/// 判定当前平台定时器粒度过粗所需的连续严重延迟次数（偶发系统繁忙不触发）。
const LATE_STREAK: u8 = 3;
/// 判定定时器粒度过粗后暂停等待的时长。到期后会重新尝试，以适应系统定时器精度动态变化。
const COARSE_PAUSE: Duration = Duration::from_secs(10);
/// 连接层表示某对端当前不支持聚合后，暂缓重复查询的冷却时间，避免经 relay 转发时每个小包反复查询。
const ASK_AGAIN: Duration = Duration::from_millis(200);
/// 触发清理空闲对端槽位的条目数阈值。
const SLOTS_BEFORE_PRUNE: usize = 64;
/// 空闲对端槽位被清理前的无小包持续时长。
const IDLE_SLOT: Duration = Duration::from_secs(30);

/// [`Bundler::push`] 的返回结果。
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Pushed {
    /// 需要先行发出的已满聚合帧（因该对端原有缓冲帧无法继续容纳新包）。
    pub(crate) emit: Option<Bytes>,
    /// 当前数据包是否已被吸收进聚合缓冲；若为 `false`，调用方应在发出 `emit` 后按普通单包发送。
    pub(crate) taken: bool,
}

/// 各对端待聚合的小包状态表。
#[derive(Debug, Default)]
pub(crate) struct Bundler {
    peers: HashMap<NodeId, Slot>,
    /// 当前存在未发出聚合帧的对端数量。为 0 时可快速跳过遍历。
    pending: usize,
    late_streak: u8,
    /// 定时器过粗冷却截止时刻：在此之前暂停小包聚合等待。
    coarse_until: Option<Instant>,
}

#[derive(Debug)]
struct Slot {
    /// 上一个小包的到达时刻。
    last_small: Instant,
    /// 连接层拒绝聚合后的查询冷却截止时刻：在此之前不再重复查询容量。
    refused_until: Option<Instant>,
    /// 正在构建的聚合帧缓冲区（含帧头与已追加的数据包）；为空表示当前无待发帧。
    frame: Vec<u8>,
    packets: usize,
    /// 当前聚合帧的最大字节容量。
    capacity: usize,
    /// 当前缓冲帧中首个小包的入队时刻。
    since: Instant,
    /// 起始构建当前帧时是否处于密集到达模式：为 `true` 时允许短暂等待。
    dense: bool,
}

impl Slot {
    /// 封装并返回当前缓存的数据帧。若仅包含一个数据包，则编码为普通单包帧以保持线格式一致。
    fn finish(&mut self) -> Bytes {
        let frame = if self.packets == 1 {
            let packet = &self.frame[PacketHeader::BUNDLE_LEN + Bundled::PREFIX_LEN..];
            let mut whole = Vec::with_capacity(PacketHeader::WHOLE_LEN + packet.len());
            PacketHeader::Whole.encode(&mut whole);
            whole.extend_from_slice(packet);
            Bytes::from(whole)
        } else {
            Bytes::copy_from_slice(&self.frame)
        };
        self.frame.clear();
        self.packets = 0;
        frame
    }
}

impl Bundler {
    /// 将发往 `peer` 的小包（长度不超过 [`SMALL_PACKET`] 的 IP 包）尝试加入其聚合缓冲帧。
    ///
    /// 仅在需要新建缓冲帧时调用 `capacity` 查询连接层是否允许聚合及单帧上限。
    pub(crate) fn push(&mut self, peer: NodeId, packet: &[u8], capacity: impl FnOnce() -> Option<usize>, now: Instant) -> Pushed {
        if self.peers.len() > SLOTS_BEFORE_PRUNE {
            self.peers.retain(|_, slot| !slot.frame.is_empty() || now.saturating_duration_since(slot.last_small) < IDLE_SLOT);
        }
        let slot = self.peers.entry(peer).or_insert_with(|| Slot {
            // 首个小包无前驱参考，不视为密集到达。
            last_small: now.checked_sub(DENSE_GAP).unwrap_or(now),
            refused_until: None,
            frame: Vec::new(),
            packets: 0,
            capacity: 0,
            since: now,
            dense: false,
        });
        let dense = now.saturating_duration_since(slot.last_small) < DENSE_GAP;
        slot.last_small = now;
        let need = Bundled::PREFIX_LEN + packet.len();
        let mut emit = None;
        if !slot.frame.is_empty() {
            if slot.frame.len() + need <= slot.capacity && Bundled::push(&mut slot.frame, packet).is_ok() {
                slot.packets += 1;
                return Pushed { emit: None, taken: true };
            }
            // 当前缓冲帧剩余空间不足：先输出已有帧，再为当前数据包开启新帧。
            emit = Some(slot.finish());
            self.pending -= 1;
        }
        if slot.refused_until.is_some_and(|until| now < until) {
            return Pushed { emit, taken: false };
        }
        let Some(capacity) = capacity().filter(|capacity| PacketHeader::BUNDLE_LEN + need <= *capacity) else {
            slot.refused_until = Some(now + ASK_AGAIN);
            return Pushed { emit, taken: false };
        };
        slot.refused_until = None;
        PacketHeader::Bundle.encode(&mut slot.frame);
        if Bundled::push(&mut slot.frame, packet).is_err() {
            // 正常情况下调用方只传入非空 IP 包；此处做防御性清理，避免残留不完整帧头。
            slot.frame.clear();
            return Pushed { emit, taken: false };
        }
        (slot.packets, slot.capacity, slot.since, slot.dense) = (1, capacity, now, dense);
        self.pending += 1;
        Pushed { emit, taken: true }
    }

    /// 取出 `peer` 当前缓存的聚合帧：当有不参与聚合的大包发往同一对端时，先发出已缓存小包以保序。
    pub(crate) fn take(&mut self, peer: NodeId) -> Option<Bytes> {
        if self.pending == 0 {
            return None;
        }
        let slot = self.peers.get_mut(&peer).filter(|slot| !slot.frame.is_empty())?;
        self.pending -= 1;
        Some(slot.finish())
    }

    /// 取出本轮读取结束后已到达发送条件的聚合帧。`hold` 表示是否允许密集小包继续等待（受网络开关控制）；
    /// 为 `false` 时立即返回所有缓存帧。剩余仍在等待的帧中最早到期时刻可通过 [`deadline`](Self::deadline) 获取。
    pub(crate) fn due(&mut self, now: Instant, hold: bool) -> Vec<(NodeId, Bytes)> {
        if self.pending == 0 {
            return Vec::new();
        }
        let hold = hold && self.coarse_until.is_none_or(|until| now >= until);
        let mut due = Vec::new();
        for (&peer, slot) in &mut self.peers {
            let waiting = hold && slot.dense && now < slot.since + WINDOW;
            if !slot.frame.is_empty() && !waiting {
                due.push((peer, slot.finish()));
            }
        }
        self.pending -= due.len();
        due
    }

    /// 返回仍在等待的聚合帧中最早的截止时刻；无等待帧时返回 `None`。
    pub(crate) fn deadline(&self) -> Option<Instant> {
        if self.pending == 0 {
            return None;
        }
        self.peers.values().filter(|slot| !slot.frame.is_empty()).map(|slot| slot.since + WINDOW).min()
    }

    /// 在聚合定时器唤醒后记录实际延迟（预期唤醒时刻为 `deadline`）。若连续多次严重延迟，则判定当前系统定时器粒度过粗并暂时停用等待。
    pub(crate) fn woke(&mut self, deadline: Instant, now: Instant) {
        if now.saturating_duration_since(deadline) < LATE {
            self.late_streak = 0;
            return;
        }
        self.late_streak += 1;
        if self.late_streak >= LATE_STREAK {
            self.late_streak = 0;
            self.coarse_until = Some(now + COARSE_PAUSE);
            tracing::debug!(late = ?now.saturating_duration_since(deadline), "定时器唤醒严重延迟，将暂时停止小包聚合等待，仅合并同批读取的数据包");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn peer(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn ack(fill: u8) -> Vec<u8> {
        vec![fill; 52]
    }

    fn whole(packet: &[u8]) -> Bytes {
        let mut frame = Vec::new();
        PacketHeader::Whole.encode(&mut frame);
        frame.extend_from_slice(packet);
        frame.into()
    }

    fn bundle(packets: &[Vec<u8>]) -> Bytes {
        let mut frame = Vec::new();
        PacketHeader::Bundle.encode(&mut frame);
        for packet in packets {
            Bundled::push(&mut frame, packet).unwrap();
        }
        frame.into()
    }

    const TAKEN: Pushed = Pushed { emit: None, taken: true };

    #[test]
    fn packets_read_in_the_same_round_leave_together_at_once_and_a_lone_one_looks_as_it_always_did() {
        let mut bundler = Bundler::default();
        let now = Instant::now();
        // 稀的：一个小包，这一轮读完就走，就是普通的一帧。
        assert_eq!(bundler.push(peer(2), &ack(1), || Some(1200), now), TAKEN);
        assert_eq!(bundler.due(now, true), [(peer(2), whole(&ack(1)))]);
        assert_eq!(bundler.deadline(), None);

        // 很久之后同一轮里来了三个（给两个对端）：各合各的，不等。
        let later = now + 50 * MS;
        for (to, fill) in [(2, 2), (3, 9), (2, 3)] {
            assert_eq!(bundler.push(peer(to), &ack(fill), || Some(1200), later), TAKEN);
        }
        let mut due = bundler.due(later, true);
        due.sort_by_key(|(peer, _)| *peer);
        assert_eq!(due, [(peer(2), bundle(&[ack(2), ack(3)])), (peer(3), whole(&ack(9)))]);
        assert_eq!(bundler.deadline(), None, "同一轮里的不等");
    }

    #[test]
    fn packets_that_come_thick_wait_for_the_window_and_sparse_ones_never_do() {
        let mut bundler = Bundler::default();
        let start = Instant::now();
        // 一条下载的确认，每 0.4 毫秒一个。头一个不等。
        bundler.push(peer(2), &ack(0), || Some(1200), start);
        assert_eq!(bundler.due(start, true).len(), 1);
        // 第二个离上一个不到 2 毫秒：攒着，等到它来了之后 1 毫秒。
        let second = start + 400 * Duration::from_micros(1);
        bundler.push(peer(2), &ack(1), || Some(1200), second);
        assert_eq!(bundler.due(second, true), []);
        assert_eq!(bundler.deadline(), Some(second + WINDOW));
        bundler.push(peer(2), &ack(2), || Some(1200), second + 400 * Duration::from_micros(1));
        assert_eq!(bundler.due(second + 800 * Duration::from_micros(1), true), [], "窗口还没到");
        assert_eq!(bundler.due(second + WINDOW, true), [(peer(2), bundle(&[ack(1), ack(2)]))]);
        assert_eq!(bundler.deadline(), None);

        // 每 50 毫秒一个的（游戏的包）：个个到了就走。
        let mut now = second + 100 * MS;
        for fill in 3..6 {
            bundler.push(peer(2), &ack(fill), || Some(1200), now);
            assert_eq!(bundler.due(now, true), [(peer(2), whole(&ack(fill)))]);
            now += 50 * MS;
        }
    }

    #[test]
    fn a_frame_that_is_full_leaves_and_the_next_packet_starts_another() {
        let mut bundler = Bundler::default();
        let now = Instant::now();
        // 一帧 120 字节：头 1 个，每个包 2 + 52，装得下两个。
        assert_eq!(bundler.push(peer(2), &ack(1), || Some(120), now), TAKEN);
        assert_eq!(bundler.push(peer(2), &ack(2), || panic!("已经在攒了，不用再问"), now), TAKEN);
        let third = bundler.push(peer(2), &ack(3), || Some(120), now);
        assert_eq!(third, Pushed { emit: Some(bundle(&[ack(1), ack(2)])), taken: true });
        assert_eq!(bundler.take(peer(2)), Some(whole(&ack(3))), "有大包要发给它：攒着的先交出来");
        assert_eq!(bundler.take(peer(2)), None);
        assert_eq!(bundler.due(now, true), []);
    }

    #[test]
    fn nothing_is_kept_for_a_peer_that_cannot_take_bundles_and_it_is_not_asked_again_at_once() {
        let mut bundler = Bundler::default();
        let now = Instant::now();
        assert_eq!(bundler.push(peer(2), &ack(1), || None, now), Pushed { emit: None, taken: false });
        assert_eq!(bundler.push(peer(2), &ack(2), || panic!("刚问过"), now + MS), Pushed::default());
        // 过一阵再问；这回能合了（路换成了直连）。
        assert_eq!(bundler.push(peer(2), &ack(3), || Some(1200), now + ASK_AGAIN), TAKEN);
        // 一帧连一个包都装不下的也算不能合。
        assert_eq!(bundler.push(peer(3), &ack(4), || Some(40), now), Pushed::default());
        assert_eq!(bundler.due(now + ASK_AGAIN, true).len(), 1);
    }

    #[test]
    fn with_the_switch_off_nothing_waits() {
        let mut bundler = Bundler::default();
        let start = Instant::now();
        bundler.push(peer(2), &ack(0), || Some(1200), start);
        bundler.due(start, true);
        bundler.push(peer(2), &ack(1), || Some(1200), start + MS);
        assert_eq!(bundler.due(start + MS, true), [], "来得密：等着");
        assert_eq!(bundler.due(start + MS, false), [(peer(2), whole(&ack(1)))], "开关关了：攒着的马上交出来");
    }

    #[test]
    fn a_timer_that_keeps_firing_late_stops_the_waiting_for_a_while() {
        let mut bundler = Bundler::default();
        let start = Instant::now();
        // 两个小包隔半毫秒，各在各的一轮里：头一个到了就走，第二个来得密。返回第二个那一轮当场交出来的。
        let thick = |bundler: &mut Bundler, at: Instant| {
            bundler.push(peer(2), &ack(0), || Some(1200), at);
            assert_eq!(bundler.due(at, true).len(), 1);
            bundler.push(peer(2), &ack(1), || Some(1200), at + MS / 2);
            bundler.due(at + MS / 2, true)
        };
        // 忙的时候偶尔晚一次，中间有准的：不算。
        for round in 0..6 {
            let at = start + 20 * MS * round;
            assert_eq!(thick(&mut bundler, at), [], "来得密：等着");
            let deadline = at + MS / 2 + WINDOW;
            assert_eq!(bundler.deadline(), Some(deadline));
            let woken = deadline + if round % 2 == 0 { 15 * MS } else { MS };
            bundler.woke(deadline, woken);
            assert_eq!(bundler.due(woken, true).len(), 1);
        }
        // 接连三次都晚了十几毫秒（Windows 默认的定时器）：之后不再等。
        let mut at = start + 200 * MS;
        for _ in 0..LATE_STREAK {
            assert_eq!(thick(&mut bundler, at), []);
            let deadline = at + MS / 2 + WINDOW;
            bundler.woke(deadline, deadline + 15 * MS);
            assert_eq!(bundler.due(deadline + 15 * MS, true).len(), 1);
            at += 20 * MS;
        }
        assert_eq!(thick(&mut bundler, at).len(), 1, "来得密也不等了，这一轮读完就发");
        // 过了一阵再试。
        assert_eq!(thick(&mut bundler, at + COARSE_PAUSE + 20 * MS), [], "又肯等了");
    }
}
