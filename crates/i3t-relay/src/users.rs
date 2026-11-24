//! 谁在用这个 relay：按"从哪个节点、发往哪个节点"数转发的字节，每 [`WINDOW`] 一个时段。
//!
//! # Invariants
//! - 单个统计窗口内最多追踪 [`MAX_PAIRS`] 个节点对，超出的归入“其余”，以限制转发路径内存占用并防止伪造无限节点对
//!   （来源节点要有会话，节点对本来也只在网络里的节点之间）。
//! - 给出去的是上一个完整的时段里最多的 [`MAX_RELAY_USERS`] 对，其余的合成一个数。
//!
//! # Performance
//! - 转发是按"中转头相同的一串数据报"做的，这里每串记一次，和带宽上限的那把锁一样，不是每个包一次。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use i3t_model::control::{MAX_RELAY_USERS, RelayPairUse, RelayUse};
use i3t_proto::NodeId;

/// 单个统计窗口的时长，与节点上报周期一致：每次上报携带刚结束的完整窗口数据。
pub(crate) const WINDOW: Duration = Duration::from_secs(10);
/// 一个时段里最多单独数多少个节点对。
pub(crate) const MAX_PAIRS: usize = 1024;

/// 正在数的时段，和上一个数完的时段。
#[derive(Debug)]
pub(crate) struct Users {
    started: Instant,
    pairs: HashMap<(NodeId, NodeId), u64>,
    other: u64,
    finished: RelayUse,
}

impl Users {
    pub(crate) fn new(now: Instant) -> Self {
        Self { started: now, pairs: HashMap::new(), other: 0, finished: empty() }
    }

    /// 记下 `from` 发往 `to` 的一串数据报转发出去了，一共 `bytes` 字节（含中转头）。
    pub(crate) fn forwarded(&mut self, from: NodeId, to: NodeId, bytes: usize, now: Instant) {
        self.roll(now);
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let full = self.pairs.len() >= MAX_PAIRS;
        match self.pairs.get_mut(&(from, to)) {
            Some(counted) => *counted = counted.saturating_add(bytes),
            None if full => self.other = self.other.saturating_add(bytes),
            None => drop(self.pairs.insert((from, to), bytes)),
        }
    }

    /// 上一个完整的时段里转发得最多的节点对。很久没有转发过时是空的。
    pub(crate) fn last(&mut self, now: Instant) -> RelayUse {
        self.roll(now);
        self.finished.clone()
    }

    /// 正在数的时段过完了的话，把它定下来，开始新的一段。过去了不止一段（中间没有转发）时，上一段是空的。
    fn roll(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.started);
        if elapsed < WINDOW {
            return;
        }
        let pairs = std::mem::take(&mut self.pairs);
        let other = std::mem::take(&mut self.other);
        self.finished = if elapsed < 2 * WINDOW { summarize(pairs, other) } else { empty() };
        self.started = if elapsed < 2 * WINDOW { self.started + WINDOW } else { now };
    }
}

fn empty() -> RelayUse {
    RelayUse { window_secs: window_secs(), pairs: Vec::new(), other_bytes: 0 }
}

fn window_secs() -> u32 {
    u32::try_from(WINDOW.as_secs()).expect("统计窗口秒数应可转换为 u32")
}

/// 一个时段数完了：最多的几对，其余的合成一个数。
fn summarize(pairs: HashMap<(NodeId, NodeId), u64>, other: u64) -> RelayUse {
    let mut ranked: Vec<RelayPairUse> = pairs.into_iter().map(|((from, to), bytes)| RelayPairUse { from, to, bytes }).collect();
    ranked.sort_unstable_by_key(|pair| (std::cmp::Reverse(pair.bytes), pair.from, pair.to));
    let rest: u64 = ranked.iter().skip(MAX_RELAY_USERS).map(|pair| pair.bytes).fold(other, u64::saturating_add);
    ranked.truncate(MAX_RELAY_USERS);
    RelayUse { window_secs: window_secs(), pairs: ranked, other_bytes: rest }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    #[test]
    fn the_last_finished_window_is_given_with_the_busiest_pairs_first() {
        let start = Instant::now();
        let mut users = Users::new(start);
        users.forwarded(node(1), node(2), 1000, start);
        users.forwarded(node(1), node(2), 500, start + Duration::from_secs(1));
        users.forwarded(node(2), node(1), 4000, start + Duration::from_secs(2));
        assert!(users.last(start + Duration::from_secs(3)).pairs.is_empty(), "这一段还没数完");

        let last = users.last(start + WINDOW + Duration::from_secs(1));
        assert_eq!(last.window_secs, 10);
        assert_eq!(
            last.pairs,
            [RelayPairUse { from: node(2), to: node(1), bytes: 4000 }, RelayPairUse { from: node(1), to: node(2), bytes: 1500 }]
        );
        assert_eq!(last.other_bytes, 0);
        assert!(users.last(start + 3 * WINDOW).pairs.is_empty(), "之后没有转发过");
    }

    #[test]
    fn pairs_beyond_the_limits_are_summed_up_as_the_rest() {
        let start = Instant::now();
        let mut users = Users::new(start);
        let count = u32::try_from(MAX_PAIRS).unwrap() + 10;
        for raw in 1..=count {
            users.forwarded(node(raw), node(raw + 100_000), 10, start);
        }
        assert_eq!(users.pairs.len(), MAX_PAIRS, "一个时段里单独数的节点对有上限");
        let last = users.last(start + WINDOW);
        assert_eq!(last.pairs.len(), MAX_RELAY_USERS);
        let total: u64 = last.pairs.iter().map(|pair| pair.bytes).sum::<u64>() + last.other_bytes;
        assert_eq!(total, u64::from(count) * 10, "一个字节也不少");
    }
}
