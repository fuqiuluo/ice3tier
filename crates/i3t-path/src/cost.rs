//! 路径的代价。延迟优先模式拿它比较全部候选路径，单位是毫秒，越小越好：
//!
//! ```text
//! cost(path) = Σ 各段延迟 + α × 抖动                延迟与抖动
//!            + β × 全程丢包率 × 1.5 × 全程延迟       丢包的延迟代价
//!            + γ × relay 数                          每经一个 relay 的固定偏置
//!            + Σ load(relay)                         relay 负载惩罚
//! ```
//!
//! - 全程丢包率由各段的丢包率合成（各段独立：`1 - Π(1 - 丢包率)`）。丢的包由两端重传，
//!   恢复一次丢包的耗时按全程往返延迟的 1.5 倍算。
//! - 全程的抖动取各段抖动之和。设计里没有规定怎么合成；各段的抖动互不相关时这是偏保守的上界，而且不用假设分布。
//! - 负载惩罚：relay 上报的带宽占用不超过 80% 时是 0，之后线性上升，到 100% 时是 [`LOAD_PENALTY_AT_FULL_MS`]，
//!   超过 100% 继续按同样的斜率涨。设计里只说"超过 80% 后线性上升"，斜率是这里定的初值。
//!
//! 几个系数都是设计时定的初值，等有了真实链路的数据再校准。

use serde::Serialize;

/// α：抖动的权重。
const JITTER_WEIGHT: f64 = 4.0;
/// β：丢包代价的权重。
const LOSS_WEIGHT: f64 = 1.0;
/// γ：每经一个 relay 加多少毫秒。
const RELAY_BIAS_MS: f64 = 1.0;
/// 恢复一次丢包要几个全程往返。
const LOSS_RECOVERY_RTTS: f64 = 1.5;
/// 带宽占用不超过这个百分比的 relay 没有负载惩罚。
const LOAD_FREE_PERCENT: u8 = 80;
/// 带宽占满（100%）的 relay 的负载惩罚，毫秒。
const LOAD_PENALTY_AT_FULL_MS: f64 = 50.0;

/// 路径上一段的测量值。
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Segment {
    /// 往返延迟，毫秒。
    pub rtt_ms: f64,
    /// 抖动，毫秒。
    pub jitter_ms: f64,
    /// 丢包率，0 到 1 之间。
    pub loss: f64,
}

impl Segment {
    /// 仅已知延迟的链路段（抖动与丢包率按 0 处理），例如目的节点至其挂靠 relay 的末段（netmap 仅提供延迟）。
    #[must_use]
    pub const fn from_rtt_ms(rtt_ms: f64) -> Self {
        Self { rtt_ms, jitter_ms: 0.0, loss: 0.0 }
    }
}

/// 一条路径的代价，毫秒。`segments` 是按顺序经过的各段，`relays` 是经过的 relay 数（直连是 0），
/// `load_ms` 是路径上各个 relay 的负载惩罚之和。
#[must_use]
pub(crate) fn path_cost(segments: &[Segment], relays: usize, load_ms: f64) -> f64 {
    let rtt: f64 = segments.iter().map(|segment| segment.rtt_ms).sum();
    let jitter: f64 = segments.iter().map(|segment| segment.jitter_ms).sum();
    let delivered: f64 = segments.iter().map(|segment| 1.0 - segment.loss.clamp(0.0, 1.0)).product();
    let loss = 1.0 - delivered;
    // 经过的 relay 最多 4 个，换成浮点数没有精度问题。
    let relay_count = u8::try_from(relays).map_or(f64::from(u8::MAX), f64::from);
    rtt + JITTER_WEIGHT * jitter + LOSS_WEIGHT * loss * LOSS_RECOVERY_RTTS * rtt + RELAY_BIAS_MS * relay_count + load_ms
}

/// 一个 relay 的负载惩罚，毫秒。`load_percent` 是它上报的带宽占用百分比。
#[must_use]
pub(crate) fn load_penalty_ms(load_percent: u8) -> f64 {
    let over = f64::from(load_percent.saturating_sub(LOAD_FREE_PERCENT));
    over / f64::from(100 - LOAD_FREE_PERCENT) * LOAD_PENALTY_AT_FULL_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(rtt_ms: f64, loss_percent: f64) -> Segment {
        Segment { rtt_ms, jitter_ms: 0.0, loss: loss_percent / 100.0 }
    }

    /// 一个算例：A 是上海家宽，B 是香港的 relay，C 是洛杉矶的 relay，D 是洛杉矶家宽，晚高峰。
    #[test]
    fn the_worked_example_gives_the_four_costs_in_the_design() {
        let direct = segment(190.0, 4.0);
        let (a_b, a_c) = (segment(35.0, 0.2), segment(200.0, 3.0));
        let b_c = segment(140.0, 0.1);
        let (b_d, c_d) = (segment(170.0, 0.5), segment(8.0, 0.0));

        let costs = [
            path_cost(&[direct], 0, 0.0),
            path_cost(&[a_c, c_d], 1, 0.0),
            path_cost(&[a_b, b_d], 1, 0.0),
            path_cost(&[a_b, b_c, c_d], 2, 0.0),
        ];
        let rounded: Vec<f64> = costs.iter().map(|cost| cost.round()).collect();
        assert_eq!(rounded, [201.0, 218.0, 208.0, 186.0], "直连约 201，A→C→D 约 218，A→B→D 约 208，A→B→C→D 约 186：{costs:?}");
    }

    #[test]
    fn a_direct_path_has_no_bias_and_each_relay_adds_one_millisecond() {
        let clean = Segment::from_rtt_ms(50.0);
        assert!((path_cost(&[clean], 0, 0.0) - 50.0).abs() < 1e-9);
        assert!((path_cost(&[clean, clean], 1, 0.0) - 101.0).abs() < 1e-9);
        assert!((path_cost(&[clean, clean, clean], 2, 0.0) - 152.0).abs() < 1e-9);
    }

    #[test]
    fn jitter_counts_four_times_and_adds_up_along_the_path() {
        let shaky = Segment { rtt_ms: 40.0, jitter_ms: 5.0, loss: 0.0 };
        assert!((path_cost(&[shaky], 0, 0.0) - 60.0).abs() < 1e-9);
        assert!((path_cost(&[shaky, shaky], 1, 0.0) - 121.0).abs() < 1e-9);
    }

    #[test]
    fn loss_is_combined_across_segments_and_priced_at_one_and_a_half_round_trips() {
        // 两段各丢 10%：全程丢 19%，全程往返 200ms，代价是 0.19 × 1.5 × 200 = 57。
        let lossy = segment(100.0, 10.0);
        assert!((path_cost(&[lossy, lossy], 0, 0.0) - 257.0).abs() < 1e-9);
        // 丢包率写错了（超出 0～1）也不会算出离谱的数。
        let broken = Segment { rtt_ms: 100.0, jitter_ms: 0.0, loss: 7.0 };
        assert!((path_cost(&[broken], 0, 0.0) - 250.0).abs() < 1e-9);
    }

    #[test]
    fn relay_load_costs_nothing_up_to_eighty_percent_and_rises_linearly_after() {
        assert_eq!(load_penalty_ms(0), 0.0);
        assert_eq!(load_penalty_ms(80), 0.0);
        assert!((load_penalty_ms(90) - 25.0).abs() < 1e-9);
        assert!((load_penalty_ms(100) - 50.0).abs() < 1e-9);
        assert!((load_penalty_ms(120) - 100.0).abs() < 1e-9);
        let clean = Segment::from_rtt_ms(50.0);
        assert!((path_cost(&[clean, clean], 1, load_penalty_ms(90)) - 126.0).abs() < 1e-9);
    }
}
