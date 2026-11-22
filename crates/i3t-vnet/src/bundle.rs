//! 发的一方把同一时刻要发给同一个对端的几个小包合成一帧（[`PacketHeader::Bundle`]）。
//!
//! # 为什么
//!
//! 一条下载在回程方向上全是小包：TCP 的确认，五六十个字节一个，每收到两个数据包就有一个。一个包一个地发，回程的包数是
//! 数据方向的一半。线路按包数限速的方向上（实测有一条每秒只放行一千两百多个包），这些小包先把额度用完，下载就卡在那里，
//! 同一个方向上别的包（ping、路径层的探测）也跟着丢。二十来个确认装得进一个包：合起来发，回程的包数少到几分之一。
//!
//! # 什么时候合，等不等
//!
//! 只合小包（不超过 [`SMALL_PACKET`] 字节）。大包不等也不合，照旧走；有大包要发给同一个对端时，攒着的小包先走，顺序不变。
//!
//! - 同一轮从网卡上读出来的小包本来就同时在手上：合成一帧，这一轮读完就发，一点不等。
//! - 小包来得稀的时候（离上一个 [`DENSE_GAP`] 以上：ping、游戏的包），到了就发，和不合的时候一样。
//! - 小包来得密的时候（离上一个不到 [`DENSE_GAP`]：一条跑着的下载的确认），攒到一帧装满或者 [`WINDOW`] 到了再发。
//!   一个小包因此最多多等一两毫秒。
//!
//! 等要靠定时器。有的系统上定时器粗得多（Windows 默认十几毫秒一跳），那里说等一毫秒会等上十几毫秒。所以每次被定时器叫醒
//! 都看晚了多少：接连几次晚得多，就一阵子不再等（[`COARSE_PAUSE`]），只合同时在手上的。
//!
//! 合不合由连接层说了算（[`i3t_conn::contract::PacketSender::bundle_capacity`]）：对端握手时说过认识这种帧，而且到它是直连。
//! 这里只管攒和什么时候放。

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use i3t_proto::NodeId;
use i3t_proto::flow::{Bundled, PacketHeader};
use tokio::time::Instant;

/// 不超过这么多字节的 IP 包算小包。TCP 的确认（带时间戳和几段 SACK 也不到一百字节）、DNS 的问答、游戏的状态包都在里面。
pub(crate) const SMALL_PACKET: usize = 256;
/// 一个小包离上一个不到这么久，就算来得密。
const DENSE_GAP: Duration = Duration::from_millis(2);
/// 来得密的时候，一帧从放进第一个包起最多攒这么久。定时器的刻度是一毫秒，实际是一到两毫秒。
const WINDOW: Duration = Duration::from_millis(1);
/// 定时器比说好的晚这么多，算一次"晚得多"。
const LATE: Duration = Duration::from_millis(4);
/// 接连几次晚得多，就认定这里的定时器粗。忙的时候偶尔晚一次不算。
const LATE_STREAK: u8 = 3;
/// 认定定时器粗之后，这么久不再让包等。过后再试，系统的定时器是可以变细的。
const COARSE_PAUSE: Duration = Duration::from_secs(10);
/// 连接层说过"这个对端现在合不了"之后，这么久不再问：经 relay 的路上每个小包都去问一遍不值得。
const ASK_AGAIN: Duration = Duration::from_millis(200);
/// 记着的对端超过这么多个时，把很久没有小包的清掉。
const SLOTS_BEFORE_PRUNE: usize = 64;
/// 多久没有小包的对端可以清掉。
const IDLE_SLOT: Duration = Duration::from_secs(30);

/// [`Bundler::push`] 的结果。
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Pushed {
    /// 这时该先发出去的一帧：这个对端原来攒着的那一帧装不下新来的包了。
    pub(crate) emit: Option<Bytes>,
    /// 这个包放进去了没有。没有的话调用方照常单独发它（在 `emit` 之后）。
    pub(crate) taken: bool,
}

/// 各个对端名下攒着的小包。
#[derive(Debug, Default)]
pub(crate) struct Bundler {
    peers: HashMap<NodeId, Slot>,
    /// 有几个对端名下正攒着东西。大多数时候是 0，那时什么都不用看。
    pending: usize,
    late_streak: u8,
    /// 认定定时器粗了：到这个时刻之前不让包等。
    coarse_until: Option<Instant>,
}

#[derive(Debug)]
struct Slot {
    /// 最近一个小包是什么时候来的。
    last_small: Instant,
    /// 连接层说过合不了：到这个时刻之前不再问。
    refused_until: Option<Instant>,
    /// 正攒着的一帧：头和放进去的包。空着是没有在攒。
    frame: Vec<u8>,
    packets: usize,
    /// 这一帧最长多少字节。
    capacity: usize,
    /// 攒着的第一个包是什么时候来的。
    since: Instant,
    /// 开始攒这一帧的时候小包来得密：可以等一会儿再发。
    dense: bool,
}

impl Slot {
    /// 把攒着的做成一帧交出去。只有一个包的就是普通的一帧，线上和不合的时候一模一样。
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
    /// 发给 `peer` 的一个小包（不超过 [`SMALL_PACKET`] 字节的 IP 包）来了：放进它名下那一帧。
    ///
    /// `capacity` 去问连接层现在能不能合、一帧最长多少（只在要新开一帧的时候问）。
    pub(crate) fn push(&mut self, peer: NodeId, packet: &[u8], capacity: impl FnOnce() -> Option<usize>, now: Instant) -> Pushed {
        if self.peers.len() > SLOTS_BEFORE_PRUNE {
            self.peers.retain(|_, slot| !slot.frame.is_empty() || now.saturating_duration_since(slot.last_small) < IDLE_SLOT);
        }
        let slot = self.peers.entry(peer).or_insert_with(|| Slot {
            // 头一个小包：之前没有，不算密。
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
            // 装不下了：原来那一帧该走了，这个包另起一帧。
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
            // 空的包：进不来这里（调用方只交 IP 包），进来了也不留半截。
            slot.frame.clear();
            return Pushed { emit, taken: false };
        }
        (slot.packets, slot.capacity, slot.since, slot.dense) = (1, capacity, now, dense);
        self.pending += 1;
        Pushed { emit, taken: true }
    }

    /// 取走 `peer` 名下攒着的那一帧：有不合的包（大包）要发给它，攒着的先走，顺序不变。
    pub(crate) fn take(&mut self, peer: NodeId) -> Option<Bytes> {
        if self.pending == 0 {
            return None;
        }
        let slot = self.peers.get_mut(&peer).filter(|slot| !slot.frame.is_empty())?;
        self.pending -= 1;
        Some(slot.finish())
    }

    /// 这一轮读完了：现在该发的各帧。`hold` 是让不让包等（网络的开关开着）；不让的话攒着的全交出来。
    /// 留下的都是还在等的，[`deadline`](Self::deadline) 是它们里最早到点的时刻。
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

    /// 还在等的各帧里最早什么时候到点；没有在等的是 `None`。
    pub(crate) fn deadline(&self) -> Option<Instant> {
        if self.pending == 0 {
            return None;
        }
        self.peers.values().filter(|slot| !slot.frame.is_empty()).map(|slot| slot.since + WINDOW).min()
    }

    /// 定时器把调用方叫醒了，说好的时刻是 `deadline`。晚得多的次数接连够了，就认定这里的定时器粗，一阵子不再让包等。
    pub(crate) fn woke(&mut self, deadline: Instant, now: Instant) {
        if now.saturating_duration_since(deadline) < LATE {
            self.late_streak = 0;
            return;
        }
        self.late_streak += 1;
        if self.late_streak >= LATE_STREAK {
            self.late_streak = 0;
            self.coarse_until = Some(now + COARSE_PAUSE);
            tracing::debug!(late = ?now.saturating_duration_since(deadline), "定时器比说好的晚得多：一阵子不让小包等，只合同时在手上的");
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
