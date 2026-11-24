//! 池该备多少条空闲的 lane：跟着新流的速率走。
//!
//! 目标 = clamp(⌈速率 × 补拨时间 × 1.5⌉ + 最小值, 最小值, [`MAX_IDLE_TARGET`])。
//! 补拨时间是"取走一条到补上一条"要多久，约三个往返（通知、建连、握手）。
//!
//! 速率是一个涨得快、落得慢的指数平均：比上一次的估计高时时间常数 1 秒，低时 5 秒。
//! 上升过慢会导致突发流量到来时池尚未就绪；下降过快则会导致刚补充的 lane 立即被当作冗余关闭。
//!
//! 这里不碰时钟：时刻由调用方传进来，测试可以用假的时钟跑各种到达的模式。

use std::time::{Duration, Instant};

/// 空闲 lane 的目标最多这么多条。
pub(crate) const MAX_IDLE_TARGET: usize = 64;

const RISE: Duration = Duration::from_secs(1);
const FALL: Duration = Duration::from_secs(5);

/// 目标比"速率 × 补拨时间"多备的比例。
const HEADROOM: f64 = 1.5;

/// 低于该阈值的需求不予预备。指数移动平均衰减不会真正归零，若无此阈值，突发流量消退很久后仍会多保留一条空闲 lane。
const NEGLIGIBLE: f64 = 0.1;

#[derive(Debug, Clone)]
pub(crate) struct Demand {
    /// 每秒新流数的估计。
    rate: f64,
    /// 上一次更新之后又来了几条。
    arrived: u32,
    updated: Instant,
}

impl Demand {
    pub(crate) fn new(now: Instant) -> Self {
        Self { rate: 0.0, arrived: 0, updated: now }
    }

    /// 来了一条新流。
    pub(crate) fn record(&mut self) {
        self.arrived = self.arrived.saturating_add(1);
    }

    /// 把上一次更新以来到达的流折进速率的估计。调用方定期调（例如每 100 毫秒），间隔不必相等。
    pub(crate) fn update(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let sample = f64::from(self.arrived) / elapsed;
        let tau = if sample > self.rate { RISE } else { FALL };
        let alpha = 1.0 - (-elapsed / tau.as_secs_f64()).exp();
        self.rate += alpha * (sample - self.rate);
        self.arrived = 0;
        self.updated = now;
    }

    #[cfg(test)]
    pub(crate) fn rate(&self) -> f64 {
        self.rate
    }

    /// 现在该备多少条空闲的 lane。
    pub(crate) fn target(&self, refill: Duration, min_idle: usize) -> usize {
        let min_idle = min_idle.min(MAX_IDLE_TARGET);
        let wanted = self.rate * refill.as_secs_f64() * HEADROOM - NEGLIGIBLE;
        // 向上取整：找最小的、不小于它的整数。最多试 64 次，比做浮点到整数的转换更不容易出错。
        let extra = (0..=MAX_IDLE_TARGET).find(|&n| u32::try_from(n).is_ok_and(|n| f64::from(n) >= wanted)).unwrap_or(MAX_IDLE_TARGET);
        (extra + min_idle).clamp(min_idle, MAX_IDLE_TARGET)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TICK: Duration = Duration::from_millis(100);

    /// 按 `per_tick` 给出的每个 100 毫秒到达几条，跑一段假的时间，返回结束时的估计。
    fn run(demand: &mut Demand, now: &mut Instant, per_tick: impl IntoIterator<Item = u32>) {
        for arrivals in per_tick {
            for _ in 0..arrivals {
                demand.record();
            }
            *now += TICK;
            demand.update(*now);
        }
    }

    #[test]
    fn a_steady_rate_is_learned_within_a_few_seconds() {
        let mut now = Instant::now();
        let mut demand = Demand::new(now);
        run(&mut demand, &mut now, std::iter::repeat_n(10, 50));
        assert!((demand.rate() - 100.0).abs() < 2.0, "每秒 100 条跑 5 秒之后估计是 {}", demand.rate());
    }

    #[test]
    fn the_estimate_rises_in_about_a_second_and_falls_in_about_five() {
        let mut now = Instant::now();
        let mut demand = Demand::new(now);
        run(&mut demand, &mut now, std::iter::repeat_n(10, 10));
        let after_one_second = demand.rate();
        assert!((55.0..75.0).contains(&after_one_second), "上升一个时间常数应该到六成多，实际 {after_one_second}");

        run(&mut demand, &mut now, std::iter::repeat_n(10, 100));
        run(&mut demand, &mut now, std::iter::repeat_n(0, 50));
        let after_five_quiet_seconds = demand.rate();
        assert!((30.0..45.0).contains(&after_five_quiet_seconds), "静默一个下降时间常数应该剩三成多，实际 {after_five_quiet_seconds}");
    }

    #[test]
    fn a_single_burst_does_not_inflate_the_pool_for_long_but_is_noticed() {
        let mut now = Instant::now();
        let mut demand = Demand::new(now);
        // 一下子来 200 条，之后什么都没有。
        run(&mut demand, &mut now, [200]);
        let refill = Duration::from_millis(300);
        let right_after = demand.target(refill, 4);
        assert!(right_after > 4, "突发之后应该多备一些，实际 {right_after}");
        run(&mut demand, &mut now, std::iter::repeat_n(0, 150));
        assert!(demand.target(refill, 4) < right_after, "静默十五秒之后少备一些");
        run(&mut demand, &mut now, std::iter::repeat_n(0, 450));
        assert_eq!(demand.target(refill, 4), 4, "静默一分钟之后回到最小值");
    }

    #[test]
    fn target_follows_rate_times_refill_time_with_headroom_and_bounds() {
        let now = Instant::now();
        let mut demand = Demand::new(now);
        let refill = Duration::from_millis(300);
        assert_eq!(demand.target(refill, 4), 4, "没有流时就是最小值");
        demand.rate = 100.0;
        assert_eq!(demand.target(refill, 4), 45 + 4, "⌈100 × 0.3 × 1.5⌉ + 4");
        demand.rate = 10_000.0;
        assert_eq!(demand.target(refill, 4), MAX_IDLE_TARGET);
        demand.rate = 1.0;
        assert_eq!(demand.target(refill, 0), 1, "每秒一条也要备一条");
        demand.rate = 0.1;
        assert_eq!(demand.target(refill, 0), 0, "补拨期间平均不到十分之一条，不备");
        assert_eq!(demand.target(refill, 100), MAX_IDLE_TARGET, "最小值本身也受上限约束");
    }

    #[test]
    fn the_target_follows_a_day_of_traffic() {
        // 补拨时间 300 毫秒（往返 100 毫秒），最小值 4。依次：静默、每秒 20 条、每秒 200 条、一下子 300 条、又静默。
        let refill = Duration::from_millis(300);
        let mut now = Instant::now();
        let mut demand = Demand::new(now);
        let target_after = |demand: &mut Demand, now: &mut Instant, per_tick: u32, ticks: usize| {
            run(demand, now, std::iter::repeat_n(per_tick, ticks));
            demand.target(refill, 4)
        };
        assert_eq!(target_after(&mut demand, &mut now, 0, 50), 4);
        assert_eq!(target_after(&mut demand, &mut now, 2, 100), 4 + 9, "每秒 20 条：⌈20 × 0.3 × 1.5 − 0.1⌉ = 9");
        assert_eq!(target_after(&mut demand, &mut now, 20, 100), MAX_IDLE_TARGET, "每秒 200 条要 90 条，到了上限");
        let peak = target_after(&mut demand, &mut now, 300, 1);
        assert_eq!(peak, MAX_IDLE_TARGET);
        // 回落是慢的：一秒之后还在上限附近；那一下突发把估计推到每秒四百多条，四十秒之后才回到最小值。
        assert!(target_after(&mut demand, &mut now, 0, 10) > 50);
        assert!(target_after(&mut demand, &mut now, 0, 190) > 4, "二十秒时还多备几条");
        assert_eq!(target_after(&mut demand, &mut now, 0, 200), 4);
    }

    #[test]
    fn irregular_update_intervals_give_the_same_answer() {
        let start = Instant::now();
        let mut even = Demand::new(start);
        let mut uneven = Demand::new(start);
        let mut now = start;
        run(&mut even, &mut now, std::iter::repeat_n(5, 40));
        // 同样的到达，只是每 400 毫秒更新一次。
        let mut later = start;
        for _ in 0..10 {
            for _ in 0..20 {
                uneven.record();
            }
            later += TICK * 4;
            uneven.update(later);
        }
        assert!((even.rate() - uneven.rate()).abs() < 5.0, "{} 和 {}", even.rate(), uneven.rate());
    }
}
