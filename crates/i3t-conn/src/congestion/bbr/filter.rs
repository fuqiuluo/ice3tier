//! 两个滑动窗口：按往返轮数算的最大值，和按时间算的最小往返时间。
//!
//! 两者都会让旧的样本过期。带宽估计因此能跟着路径变慢，往返时间的下限因此能跟着路径变长。

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// 最近若干轮里的最大值。
#[derive(Debug, Clone)]
pub(super) struct WindowedMax {
    /// 一个样本从记下的那一轮起，一共在这么多轮里有效。
    window: u64,
    /// 轮数递增、值递减。队首是窗口里的最大值，后面的是"队首过期之后轮到谁"。同一轮最多留一项。
    entries: VecDeque<Entry>,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    round: u64,
    value: u64,
}

impl WindowedMax {
    pub(super) fn new(window: u64) -> Self {
        Self { window, entries: VecDeque::new() }
    }

    pub(super) fn get(&self) -> Option<u64> {
        self.entries.front().map(|entry| entry.value)
    }

    /// 记下第 `round` 轮的一个样本，并让过期的样本出局。
    ///
    /// 过期只在这里发生：一直没有新样本时估计值保持不变。应用发得少的那些时候，调用方不把样本送进来，
    /// 估计值就不会被拉低。
    pub(super) fn update(&mut self, round: u64, value: u64) {
        while self.entries.back().is_some_and(|entry| entry.value <= value) {
            self.entries.pop_back();
        }
        // 走到这里，队尾（如果有）的值比新样本大。它要是也在这一轮，新样本就永远轮不到。
        if self.entries.back().is_none_or(|entry| entry.round < round) {
            self.entries.push_back(Entry { round, value });
        }
        while self.entries.front().is_some_and(|entry| entry.round.saturating_add(self.window) <= round) {
            self.entries.pop_front();
        }
    }

    /// 忘掉第 `round` 轮之前的样本。至少留下最新的一个。
    pub(super) fn forget_before(&mut self, round: u64) {
        while self.entries.len() > 1 && self.entries.front().is_some_and(|entry| entry.round < round) {
            self.entries.pop_front();
        }
    }
}

/// 一段时间里见过的最小往返时间，也就是路径上没有排队时的往返时间。
#[derive(Debug, Clone)]
pub(super) struct MinRtt {
    window: Duration,
    /// 下限刚被大幅抬高之后，过多久要复核。
    recheck: Duration,
    value: Option<Duration>,
    /// 上一个样本比下限低出一截，还没有被之后的样本证实。记着它的值和到达的时刻。
    candidate: Option<(Duration, Instant)>,
    /// 最近一次看到"和下限差不多"的样本是什么时候。
    confirmed: Instant,
    /// 下限刚被大幅抬高过，还没有复核。抬高它的可能是路径变长，也可能只是别的连接这时正排着队；
    /// 是后者的话，几条连接各自把对方的排队当成路径的一部分，队列就一直排在那里。
    provisional: bool,
}

/// 一次更新之后，往返时间下限的情况。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Floor {
    /// 窗口之内见过和下限差不多的样本。
    Fresh,
    /// 整个窗口里都没有再见到过下限附近的样本。下限的值没有动：眼下的样本里可能有自己造成的排队，
    /// 要由调用方把在途量降下来之后用 [`MinRtt::replace`] 换成量到的值。
    Expired,
}

impl MinRtt {
    pub(super) fn new(now: Instant, window: Duration, recheck: Duration) -> Self {
        Self { window, recheck, value: None, candidate: None, confirmed: now, provisional: false }
    }

    pub(super) fn get(&self) -> Option<Duration> {
        self.value
    }

    pub(super) fn update(&mut self, now: Instant, sample: Duration) -> Floor {
        let Some(floor) = self.value else {
            self.value = Some(sample);
            self.confirmed = now;
            return Floor::Fresh;
        };
        let tolerance = Self::tolerance(floor);
        let floor = if sample + tolerance >= floor {
            self.candidate = None;
            floor.min(sample)
        } else {
            // 样本比下限低出一截。先记着，等之后另一个时刻到的样本也这样才认，认的时候取两个里较高的那个，
            // 余下的差距后面的样本会补上。窗口只控制在途量，下限被偶然的样本压低多少，吞吐就跟着少多少，
            // 而且要等整个窗口过去才纠正得回来。偶然偏低的样本确实有：进程被挂起几毫秒之后一口气处理积压的确认，
            // 它们的到达时刻都按挂起之前算，往返时间就都短了几毫秒。这样的一批时刻相同，互相不能作证。
            match self.candidate {
                Some((candidate, at)) if at < now => {
                    self.candidate = None;
                    sample.max(candidate)
                }
                Some((candidate, at)) => {
                    self.candidate = Some((sample.max(candidate), at));
                    floor
                }
                None => {
                    self.candidate = Some((sample, now));
                    floor
                }
            }
        };
        self.value = Some(floor);
        // 样本贴着下限，说明下限还成立，不需要专门降低在途量去重新量。暂定的下限不这样续期，到时间一定复核。
        if !self.provisional && sample <= floor + tolerance {
            self.confirmed = now;
        }
        let window = if self.provisional { self.recheck } else { self.window };
        if now.saturating_duration_since(self.confirmed) <= window { Floor::Fresh } else { Floor::Expired }
    }

    /// 样本和下限相差多少以内算"差不多"。收发两端的调度本身就有不到一毫秒的抖动。
    fn tolerance(floor: Duration) -> Duration {
        (floor / 32).max(Duration::from_millis(1))
    }

    /// 把下限换成 `sample`，不管它比原来的高还是低。在途量降下来之后量到的值、或者应用本来就发得很少时的样本，
    /// 不含自身造成的排队延迟。若较原值升高超过四分之一，则将新下限标记为暂定并返回 `true`（通常意味着切换到了更长路径）。
    pub(super) fn replace(&mut self, now: Instant, sample: Duration) -> bool {
        self.provisional = self.value.is_some_and(|old| sample * 4 > old * 5);
        self.value = Some(sample);
        self.candidate = None;
        self.confirmed = now;
        self.provisional
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_follows_the_largest_sample_in_the_window() {
        let mut max = WindowedMax::new(10);
        assert_eq!(max.get(), None);
        max.update(1, 100);
        max.update(2, 300);
        max.update(3, 200);
        assert_eq!(max.get(), Some(300));
    }

    #[test]
    fn max_expires_old_samples_and_falls_back_to_the_next_largest() {
        let mut max = WindowedMax::new(10);
        max.update(1, 300);
        max.update(5, 200);
        max.update(8, 100);
        // 第 1 轮的样本在第 1～10 轮有效。
        max.update(10, 50);
        assert_eq!(max.get(), Some(300));
        max.update(11, 50);
        assert_eq!(max.get(), Some(200));
        max.update(15, 50);
        assert_eq!(max.get(), Some(100));
        max.update(18, 50);
        assert_eq!(max.get(), Some(50));
    }

    #[test]
    fn max_keeps_its_value_while_no_samples_arrive() {
        let mut max = WindowedMax::new(10);
        max.update(1, 300);
        // 中间一百轮没有样本（应用没怎么发数据），估计值不变；下一个样本进来时旧的才过期。
        assert_eq!(max.get(), Some(300));
        max.update(100, 40);
        assert_eq!(max.get(), Some(40));
    }

    #[test]
    fn max_keeps_one_entry_per_round() {
        let mut max = WindowedMax::new(10);
        for value in [50, 40, 30, 20, 10] {
            max.update(1, value);
        }
        assert_eq!(max.entries.len(), 1);
        assert_eq!(max.get(), Some(50));
    }

    #[test]
    fn max_can_forget_everything_before_a_round() {
        let mut max = WindowedMax::new(10);
        max.update(1, 300);
        max.update(4, 200);
        max.update(6, 100);
        max.forget_before(4);
        assert_eq!(max.get(), Some(200));
        max.forget_before(100);
        assert_eq!(max.get(), Some(100), "最新的一个样本要留下");
    }

    const WINDOW: Duration = Duration::from_secs(5);
    const RECHECK: Duration = Duration::from_secs(2);
    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn min_rtt_takes_slightly_lower_samples_at_once() {
        let start = Instant::now();
        let mut min = MinRtt::new(start, WINDOW, RECHECK);
        assert_eq!(min.update(start, 100 * MS), Floor::Fresh);
        assert_eq!(min.update(start + 10 * MS, 98 * MS), Floor::Fresh);
        assert_eq!(min.get(), Some(98 * MS));
    }

    #[test]
    fn min_rtt_takes_a_much_lower_sample_once_the_next_one_confirms_it() {
        let start = Instant::now();
        let mut min = MinRtt::new(start, WINDOW, RECHECK);
        min.update(start, 100 * MS);
        // 换到了一条 30ms 的路。头一个样本先不认，第二个到了才认，先取两个里较高的。
        min.update(start + 10 * MS, 31 * MS);
        assert_eq!(min.get(), Some(100 * MS));
        min.update(start + 12 * MS, 30 * MS);
        assert_eq!(min.get(), Some(31 * MS));
        min.update(start + 14 * MS, 30 * MS);
        assert_eq!(min.get(), Some(30 * MS));
    }

    #[test]
    fn min_rtt_ignores_low_samples_that_arrive_at_the_same_instant() {
        let start = Instant::now();
        let mut min = MinRtt::new(start, WINDOW, RECHECK);
        min.update(start, 30 * MS);
        // 进程被挂起之后一口气处理的几个确认：到达时刻相同，量出来的往返时间都偏短。
        for sample in [27, 26, 25] {
            min.update(start + 10 * MS, sample * MS);
        }
        min.update(start + 12 * MS, 30 * MS);
        assert_eq!(min.get(), Some(30 * MS));
        // 之后真的变短了：另一个时刻的样本可以作证，取的是这一批里最高的那个。
        for sample in [27, 26] {
            min.update(start + 20 * MS, sample * MS);
        }
        min.update(start + 22 * MS, 26 * MS);
        assert_eq!(min.get(), Some(27 * MS));
    }

    #[test]
    fn min_rtt_ignores_a_single_low_outlier() {
        let start = Instant::now();
        let mut min = MinRtt::new(start, WINDOW, RECHECK);
        min.update(start, 30 * MS);
        min.update(start + 10 * MS, 27 * MS);
        min.update(start + 12 * MS, 30 * MS);
        min.update(start + 14 * MS, 27 * MS);
        min.update(start + 16 * MS, 31 * MS);
        assert_eq!(min.get(), Some(30 * MS), "两个偏低的样本不相邻，都不算数");
    }

    #[test]
    fn min_rtt_expires_when_the_floor_is_not_seen_for_a_whole_window() {
        let start = Instant::now();
        let mut min = MinRtt::new(start, WINDOW, RECHECK);
        min.update(start, 30 * MS);
        // 往返时间变成了 100ms：窗口之内不说话，窗口一过就报告过期。值不动，等调用方量过之后来换。
        assert_eq!(min.update(start + WINDOW, 100 * MS), Floor::Fresh);
        assert_eq!(min.update(start + WINDOW + MS, 100 * MS), Floor::Expired);
        assert_eq!(min.get(), Some(30 * MS));
        min.replace(start + WINDOW + 300 * MS, 100 * MS);
        assert_eq!(min.get(), Some(100 * MS));
        assert_eq!(min.update(start + WINDOW + 301 * MS, 100 * MS), Floor::Fresh);
    }

    #[test]
    fn min_rtt_stays_fresh_while_samples_touch_the_floor() {
        let start = Instant::now();
        let mut min = MinRtt::new(start, WINDOW, RECHECK);
        min.update(start, 100 * MS);
        for second in 1..=20 {
            // 比下限高 2ms，在容差（100ms 的 1/32）之内。
            assert_eq!(min.update(start + Duration::from_secs(second), 102 * MS), Floor::Fresh);
        }
        assert_eq!(min.get(), Some(100 * MS), "容差只用来确认下限，不抬高它");
    }

    #[test]
    fn a_floor_that_was_raised_a_lot_is_rechecked_soon() {
        let start = Instant::now();
        let mut min = MinRtt::new(start, WINDOW, RECHECK);
        min.update(start, 30 * MS);
        min.replace(start + MS, 100 * MS);
        // 样本一直贴着新的下限，也不算数：2 秒之后要复核。
        assert_eq!(min.update(start + RECHECK, 100 * MS), Floor::Fresh);
        assert_eq!(min.update(start + RECHECK + 2 * MS, 100 * MS), Floor::Expired);
        // 复核的结果差不多，之后按正常的窗口走。
        min.replace(start + 3 * RECHECK / 2, 104 * MS);
        assert_eq!(min.update(start + 3 * RECHECK / 2 + WINDOW, 200 * MS), Floor::Fresh);
    }

    #[test]
    fn a_floor_that_was_lowered_or_barely_raised_is_not_provisional() {
        let start = Instant::now();
        let mut min = MinRtt::new(start, WINDOW, RECHECK);
        min.update(start, 100 * MS);
        min.replace(start + MS, 120 * MS);
        assert_eq!(min.update(start + RECHECK + WINDOW / 2, 200 * MS), Floor::Fresh);
        min.replace(start + WINDOW, 40 * MS);
        assert_eq!(min.update(start + WINDOW + RECHECK + MS, 200 * MS), Floor::Fresh);
    }
}
