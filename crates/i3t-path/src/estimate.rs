//! 单段链路的质量估计：延迟、抖动与丢包率。
//!
//! 本节点主动测量的各段链路均使用本模块：到 relay 的中转会话及到对端的直连。样本来源包括常规保活探测，
//! 以及面向待评估候选路径发送的探测包列（[`Train`]）——仅依赖低频保活难以测出个位数百分比的丢包率。
//!
//! 估计值带有时间戳，长时间未收到新应答时自动失效，不会沿用过期结果。
//!
//! # 迟到的应答
//!
//! 超时未获应答的探测记为丢失；若其应答随后迟到，仅补充一个延迟样本（不撤销已记录的丢包）。
//! UDP 链路依据平滑延迟、抖动与丢包率计算路径代价（[`Estimate::quality`]）。
//!
//! # TCP 链路
//!
//! TCP 链路的底层丢包会由 TCP 协议栈自动重传，探测帧不会真正丢失，只会因队头阻塞而在停顿后延迟到达，因此节点仅能观测到延迟与停顿。
//! 将 UDP 估算方法直接套用于 TCP 链路会产生双向偏差（实测于 250～350 ms、丢包 5～8% 的链路）：
//! 稀疏探测多落于停顿间隙，少数触发重传的样本会导致平滑延迟偏低而抖动（RTTVAR）被拉升至一两百毫秒，
//! 乘以抖动权重后代价虚高且单次样本即可引发数百毫秒波动、导致选路反复震荡；同时对端仅上报平滑延迟，又显著偏低。
//! 实际流量在 TCP 链路中承受的是队头阻塞停顿本身。因此 TCP 链路按最近 4 分钟内全部样本的均值延迟评估（[`Estimate::over_tcp`]）：
//! 停顿样本按实际耗时计入均值，停顿时长与频率均已体现在延迟中，不再叠加抖动与丢包权重以避免重复计算。
//! 当保活持续无应答并导致会话关闭时，将最早未应答探测的等待时长也记入样本（[`Estimate::stalled`]），避免频繁卡死重连的 TCP
//! 窗口内仅残留重连初期的优良样本。
//!
//! 该均值对应轻负载探测条件下的等待时间，高负载时碰撞停顿的概率更高（实测 250 ms、5% 丢包 TCP 在每秒 50 包下均值高约四成），
//! 虽偏乐观，但各条 TCP 链路采用统一标尺且单次停顿仅产生小幅扰动；高分位数或相邻样本差值虽贴近满载，但仍会出现剧烈跳变。
//!
//! 窗口按时间而非样本数划分：待评估候选链路每 30 秒额外发送一组探测包列，样本密度为纯保活链路的四倍，按数量统计会导致覆盖时长不一致。
//! 4 分钟为实测折中值（基于 250 ms、5% 丢包 TCP 样本模拟两条等价链路对比）：窗口过短时，单次停顿影响衰减不足，
//! 等价链路每 10 分钟切换两三次；4 分钟窗口下每 10 分钟不足一次，且在链路真实劣化四成后约 50 秒内即可完成切换。

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use i3t_proto::session::Nonce;

use crate::cost::Segment;
use crate::timing::{ESTIMATE_TTL, Rtt, TRAIN_INTERVAL, TRAIN_PROBES};

/// 丢包率按最近这么多个探测算。一组探测包列是 10 个，所以大约是最近四组。
const LOSS_WINDOW: usize = 40;
/// 走 TCP 的一段的平均延迟按这么久之内的样本算（见模块文档）。
const TCP_WINDOW: Duration = Duration::from_secs(240);
/// 这个窗口里最多留多少个样本：在评估的候选上的一段 4 分钟大约 130 个，多出来的（有流量时提前的保活）挤掉最老的。
const TCP_SAMPLES: usize = 160;
/// 探测不到这么多个时不报丢包率：样本太少，丢一个就是百分之十几。
const MIN_LOSS_SAMPLES: usize = 10;
/// 超时的探测最多记多少个、记多久，等它们迟到的回答。再晚的回答就不当样本了：那样的停顿早就让会话判为断开。
const OVERDUE_KEPT: usize = 8;
const OVERDUE_LIMIT: Duration = Duration::from_secs(10);

/// 一段链路的估计。
#[derive(Debug, Clone)]
pub(crate) struct Estimate {
    rtt: Option<Rtt>,
    /// 延迟样本和平滑值之差的平滑值，和 TCP 的 RTTVAR 是同一种算法。
    jitter: Duration,
    /// 最近的探测是不是丢了。
    outcomes: VecDeque<bool>,
    /// 最近 [`TCP_WINDOW`] 里的延迟样本和它们的时刻，迟到的回答按它真正用的时间算。走 TCP 的一段按它们算（见模块文档）。
    recent: VecDeque<(Instant, Duration)>,
    /// 最近一次得到回答的时刻。
    answered: Option<Instant>,
}

/// 某一时刻读出来的估计值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Quality {
    pub(crate) rtt: Duration,
    pub(crate) jitter: Duration,
    /// 最近 `probes` 个探测里丢了 `lost` 个。样本不够时两个都是 0。
    pub(crate) lost: usize,
    pub(crate) probes: usize,
}

impl Quality {
    /// 换成算代价用的形式。
    pub(crate) fn segment(&self) -> Segment {
        let millis = |value: Duration| value.as_secs_f64() * 1000.0;
        // 两个计数都不超过窗口的长度（40），换成浮点数没有精度问题。
        let ratio = |count: usize| u8::try_from(count).map_or(f64::from(u8::MAX), f64::from);
        let loss = if self.probes == 0 { 0.0 } else { ratio(self.lost) / ratio(self.probes) };
        Segment { rtt_ms: millis(self.rtt), jitter_ms: millis(self.jitter), loss }
    }
}

impl Estimate {
    pub(crate) const fn new() -> Self {
        Self { rtt: None, jitter: Duration::ZERO, outcomes: VecDeque::new(), recent: VecDeque::new(), answered: None }
    }

    /// 一个探测得到了回答，往返用了 `rtt`。
    pub(crate) fn sample(&mut self, rtt: Duration, now: Instant) {
        self.measure(rtt, now);
        self.record(false);
    }

    /// 一个探测没有等到回答。
    pub(crate) fn lost(&mut self) {
        self.record(true);
    }

    /// 一个已经记成丢失的探测，回答在 `rtt` 之后迟到了：只更新延迟和抖动，不改丢包的记录（见模块文档）。
    pub(crate) fn late_answer(&mut self, rtt: Duration, now: Instant) {
        self.measure(rtt, now);
    }

    /// TCP 链路发生停顿：某探测等待 `waited` 仍无应答并导致会话关闭，后续不会再收到其应答。
    /// 仅写入 TCP 均值窗口（见模块文档），不更新平滑延迟（用于计算探测超时），也不视为有效应答。
    pub(crate) fn stalled(&mut self, waited: Duration, now: Instant) {
        self.remember(waited, now);
    }

    fn measure(&mut self, rtt: Duration, now: Instant) {
        match &mut self.rtt {
            Some(smoothed) => {
                let deviation = smoothed.get().abs_diff(rtt);
                self.jitter = (self.jitter * 3 + deviation) / 4;
                smoothed.update(rtt);
            }
            None => self.rtt = Some(Rtt::new(rtt)),
        }
        self.remember(rtt, now);
        self.answered = Some(now);
    }

    fn remember(&mut self, rtt: Duration, now: Instant) {
        while self.recent.front().is_some_and(|(at, _)| now.saturating_duration_since(*at) >= TCP_WINDOW)
            || self.recent.len() >= TCP_SAMPLES
        {
            self.recent.pop_front();
        }
        self.recent.push_back((now, rtt));
    }

    fn record(&mut self, lost: bool) {
        if self.outcomes.len() == LOSS_WINDOW {
            self.outcomes.pop_front();
        }
        self.outcomes.push_back(lost);
    }

    /// 平滑之后的往返延迟，不管新旧。用来定探测的超时。
    pub(crate) const fn rtt(&self) -> Option<Rtt> {
        self.rtt
    }

    /// 现在的估计。从来没有得到过回答，或者最近一次回答已经过期了，返回 `None`。
    pub(crate) fn quality(&self, now: Instant) -> Option<Quality> {
        let fresh = self.answered.is_some_and(|at| now.saturating_duration_since(at) < ESTIMATE_TTL);
        let rtt = self.rtt.filter(|_| fresh)?.get();
        let probes = self.outcomes.len();
        let (lost, probes) = if probes < MIN_LOSS_SAMPLES { (0, 0) } else { (self.outcomes.iter().filter(|&&lost| lost).count(), probes) };
        Some(Quality { rtt, jitter: self.jitter, lost, probes })
    }

    /// TCP 链路的质量估计：延迟取最近 [`TCP_WINDOW`] 内所有样本的均值（停顿按实际耗时计入）；
    /// 抖动与丢包记为 0，因其影响已折算入均值延迟（见模块文档）。与 [`quality`](Self::quality) 一致，
    /// 从未收到应答或最近应答已过期时返回 `None`。
    pub(crate) fn over_tcp(&self, now: Instant) -> Option<Quality> {
        let fresh = self.answered.is_some_and(|at| now.saturating_duration_since(at) < ESTIMATE_TTL);
        let window: Vec<Duration> =
            self.recent.iter().filter(|(at, _)| now.saturating_duration_since(*at) < TCP_WINDOW).map(|(_, rtt)| *rtt).collect();
        // 窗口里最多 [`TCP_SAMPLES`] 个，个数换成 u32 不会失败。
        let count = u32::try_from(window.len()).ok().filter(|count| fresh && *count > 0)?;
        let rtt = window.iter().sum::<Duration>() / count;
        Some(Quality { rtt, jitter: Duration::ZERO, lost: 0, probes: 0 })
    }
}

/// 探测包列：每隔一段时间连着发一组探测，专门用来估丢包率（默认每 30 秒一组 10 个）。
///
/// 它只管节奏和对账：外面每隔一小段时间问一次"现在要不要发一个"，把回答交回来；没有等到回答的记成丢失，
/// 回答迟到的再记一个延迟样本（见模块文档）。同一段链路上保活用的探测超时了也交给它等迟到的回答（[`overdue`](Self::overdue)）。
#[derive(Debug)]
pub(crate) struct Train {
    pending: Vec<(Nonce, Instant)>,
    /// 已经记成丢失、还在等迟到的回答的探测，最老的在前面。
    overdue: VecDeque<(Nonce, Instant)>,
    /// 这一组还要发几个。
    remaining: u8,
    /// 下一组什么时候开始。
    next_round: Option<Instant>,
}

impl Train {
    pub(crate) const fn new() -> Self {
        Self { pending: Vec::new(), overdue: VecDeque::new(), remaining: 0, next_round: None }
    }

    /// 推进一步。`wanted`：这段链路是不是在正在评估的候选路径上；不是就不发新的。
    /// 等了超过 `timeout` 的探测记成丢失。返回值是现在要发的一个探测的随机数；每次调用最多发一个，
    /// 所以一组探测自然地按调用的间隔散开，不会挤成一个突发。
    pub(crate) fn poll(&mut self, now: Instant, wanted: bool, timeout: Duration, estimate: &mut Estimate) -> Option<Nonce> {
        let (waiting, expired): (Vec<_>, Vec<_>) =
            self.pending.drain(..).partition(|(_, sent)| now.saturating_duration_since(*sent) < timeout);
        self.pending = waiting;
        for (nonce, sent) in expired {
            estimate.lost();
            self.overdue(nonce, sent);
        }
        self.overdue.retain(|(_, sent)| now.saturating_duration_since(*sent) < OVERDUE_LIMIT);
        if !wanted {
            self.remaining = 0;
            return None;
        }
        if self.remaining == 0 && self.next_round.is_none_or(|at| now >= at) {
            self.remaining = TRAIN_PROBES;
            self.next_round = Some(now + TRAIN_INTERVAL);
        }
        self.remaining = self.remaining.checked_sub(1)?;
        let nonce: Nonce = i3t_underlay::random_bytes();
        self.pending.push((nonce, now));
        Some(nonce)
    }

    /// 一个已经记成丢失的探测（`sent` 时发的），它的回答要是迟到了，仍然记一个延迟样本。
    pub(crate) fn overdue(&mut self, nonce: Nonce, sent: Instant) {
        if self.overdue.len() == OVERDUE_KEPT {
            self.overdue.pop_front();
        }
        self.overdue.push_back((nonce, sent));
    }

    /// 一个回答到了。它回答的是这一列里的探测（或者一个超时了的探测）时记一个样本，返回 `true`。
    pub(crate) fn on_reply(&mut self, nonce: &Nonce, now: Instant, estimate: &mut Estimate) -> bool {
        if let Some(index) = self.pending.iter().position(|(pending, _)| pending == nonce) {
            let (_, sent) = self.pending.swap_remove(index);
            estimate.sample(now.saturating_duration_since(sent), now);
            return true;
        }
        let Some(index) = self.overdue.iter().position(|(overdue, _)| overdue == nonce) else { return false };
        let Some((_, sent)) = self.overdue.remove(index) else { return false };
        let delay = now.saturating_duration_since(sent);
        if delay < OVERDUE_LIMIT {
            estimate.late_answer(delay, now);
        }
        true
    }

    /// 是不是发过带这个随机数的探测、还在等回答（包括迟到的）。
    pub(crate) fn expects(&self, nonce: &Nonce) -> bool {
        self.pending.iter().chain(&self.overdue).any(|(pending, _)| pending == nonce)
    }

    /// 链路已断开：清除所有待应答与迟到追踪记录。
    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.overdue.clear();
        self.remaining = 0;
    }

    /// 等着迟到的回答的探测里最早发出的那个是什么时候发的。
    pub(crate) fn oldest_overdue(&self) -> Option<Instant> {
        self.overdue.iter().map(|(_, sent)| *sent).min()
    }
}

/// 串行发送的端到端探测采样器：同一时刻最多允许一个待应答探测，前次发出间隔 `interval` 后再发下一个。
///
/// 用于本节点会话无法直接测得、只能端到端采样的链路：对端挂靠在本节点 relay 上且未将本节点上报至挂靠表时的
/// “本节点 relay → 对端”链路（见 `control::route`）。因对端对该类探测存在频率限制（同一对端每 200 毫秒一次），
/// 不宜如 [`Train`] 连续发送；未收到应答亦不计为丢包（可能被对端限频丢弃），迟到应答仍计入延迟样本。
#[derive(Debug)]
pub(crate) struct Sampler {
    estimate: Estimate,
    pending: Option<(Nonce, Instant)>,
    /// 超时了、还在等迟到的回答的那些，借 [`Train`] 的记账。
    late: Train,
    sent: Option<Instant>,
}

impl Sampler {
    pub(crate) const fn new() -> Self {
        Self { estimate: Estimate::new(), pending: None, late: Train::new(), sent: None }
    }

    pub(crate) const fn measured(&self) -> &Estimate {
        &self.estimate
    }

    /// 推进一步：在等的那个超时了就转去等它迟到的回答；该发下一个了就返回它的随机数。`wanted` 为假时不发新的。
    pub(crate) fn poll(&mut self, now: Instant, wanted: bool, interval: Duration) -> Option<Nonce> {
        let timeout = self.estimate.rtt().map_or(crate::timing::PROBE_TIMEOUT_MAX, Rtt::probe_timeout);
        if let Some((nonce, sent)) = self.pending.filter(|(_, sent)| now.saturating_duration_since(*sent) >= timeout) {
            self.late.overdue(nonce, sent);
            self.pending = None;
        }
        // 只为了扔掉等得太久的那些；它不在列里，不会发新的。
        self.late.poll(now, false, timeout, &mut self.estimate);
        let due = self.pending.is_none() && self.sent.is_none_or(|at| now.saturating_duration_since(at) >= interval);
        if !wanted || !due {
            return None;
        }
        let nonce: Nonce = i3t_underlay::random_bytes();
        self.pending = Some((nonce, now));
        self.sent = Some(now);
        Some(nonce)
    }

    /// 是不是在等这个随机数的回答（包括迟到的）。
    pub(crate) fn expects(&self, nonce: &Nonce) -> bool {
        self.pending.is_some_and(|(pending, _)| pending == *nonce) || self.late.expects(nonce)
    }

    /// 一个回答到了。是在回答本 sampler 发的探测时记一个样本，返回 `true`。
    pub(crate) fn on_reply(&mut self, nonce: &Nonce, now: Instant) -> bool {
        if let Some((_, sent)) = self.pending.filter(|(pending, _)| pending == nonce) {
            self.pending = None;
            self.estimate.measure(now.saturating_duration_since(sent), now);
            return true;
        }
        self.late.on_reply(nonce, now, &mut self.estimate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn nothing_is_known_before_the_first_answer() {
        let now = Instant::now();
        let mut estimate = Estimate::new();
        assert_eq!(estimate.quality(now), None);
        estimate.lost();
        assert_eq!(estimate.quality(now), None, "只有丢失、从来没有回答：还是不知道");
        assert_eq!(estimate.rtt(), None);
    }

    #[test]
    fn rtt_is_smoothed_and_jitter_follows_the_deviation() {
        let now = Instant::now();
        let mut estimate = Estimate::new();
        estimate.sample(80 * MS, now);
        let first = estimate.quality(now).unwrap();
        assert_eq!((first.rtt, first.jitter), (80 * MS, Duration::ZERO));

        // 样本偏了 40ms：延迟向它走八分之一，抖动记下四分之一的偏差。
        estimate.sample(120 * MS, now);
        let second = estimate.quality(now).unwrap();
        assert_eq!((second.rtt, second.jitter), (85 * MS, 10 * MS));

        // 之后的样本都落在平滑值上：抖动慢慢退回去。
        for _ in 0..40 {
            estimate.sample(estimate.rtt().unwrap().get(), now);
        }
        assert!(estimate.quality(now).unwrap().jitter < MS);
    }

    #[test]
    fn loss_is_not_reported_until_there_are_enough_probes() {
        let now = Instant::now();
        let mut estimate = Estimate::new();
        estimate.sample(50 * MS, now);
        estimate.lost();
        let few = estimate.quality(now).unwrap();
        assert_eq!((few.lost, few.probes), (0, 0), "两个探测丢一个不能说丢包率是一半");
        assert_eq!(few.segment().loss, 0.0);

        for _ in 0..8 {
            estimate.sample(50 * MS, now);
        }
        let enough = estimate.quality(now).unwrap();
        assert_eq!((enough.lost, enough.probes), (1, 10));
        assert!((enough.segment().loss - 0.1).abs() < 1e-9);
        assert!((enough.segment().rtt_ms - 50.0).abs() < 1e-9);
    }

    #[test]
    fn loss_is_measured_over_the_most_recent_window_only() {
        let now = Instant::now();
        let mut estimate = Estimate::new();
        for _ in 0..LOSS_WINDOW {
            estimate.lost();
        }
        for _ in 0..LOSS_WINDOW {
            estimate.sample(50 * MS, now);
        }
        let quality = estimate.quality(now).unwrap();
        assert_eq!((quality.lost, quality.probes), (0, LOSS_WINDOW), "早先丢的那些已经滑出窗口了");
    }

    #[test]
    fn an_estimate_expires_when_no_answer_arrives_for_two_minutes() {
        let start = Instant::now();
        let mut estimate = Estimate::new();
        estimate.sample(50 * MS, start);
        assert!(estimate.quality(start + ESTIMATE_TTL - MS).is_some());
        assert_eq!(estimate.quality(start + ESTIMATE_TTL), None, "过期作废");
        // 期间只有丢失、没有回答，不能让它续命。
        estimate.lost();
        assert_eq!(estimate.quality(start + ESTIMATE_TTL), None);
        assert!(estimate.rtt().is_some(), "定超时用的延迟不受过期影响");
        estimate.sample(60 * MS, start + ESTIMATE_TTL);
        assert!(estimate.quality(start + ESTIMATE_TTL).is_some());
    }

    #[test]
    fn a_train_sends_ten_probes_one_per_step_every_thirty_seconds() {
        let start = Instant::now();
        let mut estimate = Estimate::new();
        let mut train = Train::new();
        let timeout = 300 * MS;
        let mut sent = Vec::new();
        // 每 50ms 推进一步，所有探测都在 20ms 之后得到回答。
        for step in 0..1400u32 {
            let now = start + 50 * MS * step;
            for (nonce, at) in std::mem::take(&mut sent) {
                assert!(train.on_reply(&nonce, at + 20 * MS, &mut estimate));
            }
            if let Some(nonce) = train.poll(now, true, timeout, &mut estimate) {
                sent.push((nonce, now));
            }
        }
        // 70 秒里是三组：0 秒、30 秒、60 秒各开始一组。
        let quality = estimate.quality(start + Duration::from_secs(70)).unwrap();
        assert_eq!((quality.lost, quality.probes), (0, 30));
        assert_eq!(quality.rtt, 20 * MS);
        assert!(!train.on_reply(&[0; 8], start, &mut estimate), "不是这一列里的探测");
    }

    #[test]
    fn unanswered_train_probes_count_as_lost_and_an_unwanted_train_stops() {
        let start = Instant::now();
        let mut estimate = Estimate::new();
        estimate.sample(20 * MS, start);
        let mut train = Train::new();
        let timeout = 300 * MS;
        let mut answered = 0;
        for step in 0..20u32 {
            let now = start + 50 * MS * step;
            // 每三个探测回答两个。
            if let Some(nonce) = train.poll(now, true, timeout, &mut estimate)
                && step % 3 != 0
            {
                assert!(train.on_reply(&nonce, now + 20 * MS, &mut estimate));
                answered += 1;
            }
        }
        // 等所有没回答的都超时。
        train.poll(start + Duration::from_secs(2), false, timeout, &mut estimate);
        let quality = estimate.quality(start + Duration::from_secs(2)).unwrap();
        assert_eq!((answered, quality.probes, quality.lost), (6, 11, 4), "十个探测丢了四个，加上最开始的一个样本");

        // 不再需要之后不发新的；重新需要时要等到下一组的时刻。
        assert_eq!(train.poll(start + Duration::from_secs(3), false, timeout, &mut estimate), None);
        assert_eq!(train.poll(start + Duration::from_secs(4), true, timeout, &mut estimate), None);
        assert!(train.poll(start + TRAIN_INTERVAL, true, timeout, &mut estimate).is_some());
        train.clear();
        assert_eq!(train.poll(start + TRAIN_INTERVAL + MS, true, timeout, &mut estimate), None);
    }

    #[test]
    fn a_late_answer_stays_a_loss_but_raises_the_delay_and_the_jitter() {
        let start = Instant::now();
        let mut estimate = Estimate::new();
        for _ in 0..10 {
            estimate.sample(20 * MS, start);
        }
        let mut train = Train::new();
        let timeout = 300 * MS;
        let nonce = train.poll(start, true, timeout, &mut estimate).unwrap();
        // 300ms 没有回答：记成丢失。
        train.poll(start + timeout, true, timeout, &mut estimate);
        assert_eq!(estimate.quality(start + timeout).unwrap().lost, 1);
        // 回答在 900ms 之后才到（TCP 重传完了）：认得出来，丢失不撤销，延迟和抖动跟着涨。
        assert!(train.expects(&nonce));
        assert!(train.on_reply(&nonce, start + 900 * MS, &mut estimate));
        let quality = estimate.quality(start + 900 * MS).unwrap();
        assert_eq!((quality.lost, quality.probes), (1, 11), "一次停顿只算一次");
        assert_eq!(quality.rtt, 20 * MS + (900 * MS - 20 * MS) / 8);
        assert_eq!(quality.jitter, (900 * MS - 20 * MS) / 4);
        assert!(!train.on_reply(&nonce, start + 950 * MS, &mut estimate), "同一个回答只算一次");

        // 再晚的回答不当样本，也不再等。
        let late = train.poll(start + TRAIN_INTERVAL, true, timeout, &mut estimate).unwrap();
        train.poll(start + TRAIN_INTERVAL + timeout, true, timeout, &mut estimate);
        train.poll(start + TRAIN_INTERVAL + OVERDUE_LIMIT, true, timeout, &mut estimate);
        assert!(!train.expects(&late));
    }

    #[test]
    fn a_timed_out_keepalive_handed_to_the_train_is_matched_when_its_answer_arrives() {
        let start = Instant::now();
        let mut estimate = Estimate::new();
        estimate.sample(20 * MS, start);
        let mut train = Train::new();
        let nonces: Vec<Nonce> = (0..=OVERDUE_KEPT).map(|index| [u8::try_from(index).unwrap(); 8]).collect();
        for nonce in &nonces {
            train.overdue(*nonce, start);
        }
        assert!(!train.expects(&nonces[0]), "最多等 {OVERDUE_KEPT} 个，最老的先放弃");
        assert!(train.on_reply(&nonces[OVERDUE_KEPT], start + 500 * MS, &mut estimate));
        assert!(estimate.rtt().unwrap().get() > 20 * MS);
    }

    /// 实验环境里量到的一条 250 ms、两个方向各丢 5% 的 TCP 上探测的样子：多数回答就是 250 ms，撞上一次重传的要多等 400～600 ms。
    /// 第 `index` 个样本。
    fn lossy_tcp(index: u32) -> Duration {
        if index % 7 == 3 { 750 * MS } else { 250 * MS }
    }

    #[test]
    fn a_tcp_leg_costs_the_mean_delay_of_its_recent_probes_with_stalls_at_their_full_length() {
        let now = Instant::now();
        let mut estimate = Estimate::new();
        for _ in 0..9 {
            estimate.sample(250 * MS, now);
        }
        // 一个探测撞上了重传，超时之后 900 ms 才回答：按 900 ms 算进平均。
        estimate.lost();
        estimate.late_answer(900 * MS, now);
        let tcp = estimate.over_tcp(now).unwrap();
        assert_eq!(tcp, Quality { rtt: 315 * MS, jitter: Duration::ZERO, lost: 0, probes: 0 }, "停顿已经在平均里，不再按抖动和丢包加一遍");
        assert!((tcp.segment().rtt_ms - 315.0).abs() < 1e-9 && tcp.segment().loss == 0.0);
        assert_eq!(Estimate::new().over_tcp(now), None, "没有样本就是不知道");
    }

    #[test]
    fn on_a_lossy_tcp_the_old_reading_costs_far_more_than_the_mean_and_one_stall_swings_it_by_hundreds_of_milliseconds() {
        let start = Instant::now();
        let every = Duration::from_secs(2);
        let mut estimate = Estimate::new();
        for index in 0..240 {
            estimate.sample(lossy_tcp(index), start + every * index);
        }
        let now = start + every * 239;
        let udp_cost = |estimate: &Estimate, now| crate::cost::path_cost(&[estimate.quality(now).unwrap().segment()], 0, 0.0);
        let tcp_cost = |estimate: &Estimate, now| crate::cost::path_cost(&[estimate.over_tcp(now).unwrap().segment()], 0, 0.0);
        let (old, new) = (udp_cost(&estimate, now), tcp_cost(&estimate, now));
        // 4 分钟里的 120 个样本（第 120 到 239 个）的平均，就是一个探测平均要等的时间。
        let mean = (120..240).map(|index| lossy_tcp(index).as_secs_f64() * 1000.0).sum::<f64>() / 120.0;
        assert!((new - mean).abs() < 1e-6, "{new} 对 {mean}");
        assert!(old > 1.5 * new, "平滑延迟加四倍的偏差：{old:.0} 对 {new:.0}");

        // 再来一个停顿：新的读数挪 500/120 ms，旧的一下子涨好几百毫秒，选路跟着它来回换。
        let later = now + every;
        estimate.sample(750 * MS, later);
        let (old_after, new_after) = (udp_cost(&estimate, later), tcp_cost(&estimate, later));
        assert!(new_after - new < 5.0, "{new} → {new_after}");
        assert!(old_after - old > 300.0, "{old} → {old_after}");
    }

    #[test]
    fn a_tcp_leg_averages_the_last_four_minutes_and_a_fatal_stall_counts_without_refreshing_it() {
        let start = Instant::now();
        let mut estimate = Estimate::new();
        for _ in 0..LOSS_WINDOW {
            estimate.sample(900 * MS, start);
        }
        let later = start + TCP_WINDOW;
        for _ in 0..9 {
            estimate.sample(250 * MS, later);
        }
        assert_eq!(estimate.over_tcp(later).unwrap().rtt, 250 * MS, "4 分钟以前的那一阵不算了，不管当时有多少个样本");

        // 保活一直没有回答、会话拆掉了：最早那个探测等了 4 秒，记一个样本。平滑延迟（定超时用）不动，也不算一次回答。
        let srtt = estimate.rtt();
        estimate.stalled(Duration::from_secs(4), later);
        assert_eq!(estimate.over_tcp(later).unwrap().rtt, (250 * MS * 9 + Duration::from_secs(4)) / 10);
        assert_eq!(estimate.rtt(), srtt);
        assert_eq!(estimate.over_tcp(later + ESTIMATE_TTL), None, "只有停顿、没有新的回答：照样过期");

        // 样本再密也只留最近的 [`TCP_SAMPLES`] 个。
        for _ in 0..2 * TCP_SAMPLES {
            estimate.sample(100 * MS, later);
        }
        assert_eq!(estimate.recent.len(), TCP_SAMPLES);
        assert_eq!(estimate.over_tcp(later).unwrap().rtt, 100 * MS);
    }

    #[test]
    fn the_sampler_keeps_one_probe_in_flight_and_sends_the_next_after_the_interval() {
        let start = Instant::now();
        let interval = Duration::from_secs(5);
        let mut sampler = Sampler::new();
        assert_eq!(sampler.poll(start, false, interval), None, "不需要的时候不发");
        let first = sampler.poll(start, true, interval).unwrap();
        assert!(sampler.expects(&first));
        assert_eq!(sampler.poll(start + 100 * MS, true, interval), None, "一次只有一个在等回答");
        assert!(sampler.on_reply(&first, start + 260 * MS));
        assert!(!sampler.on_reply(&first, start + 270 * MS), "同一个回答只算一次");
        assert_eq!(sampler.poll(start + 300 * MS, true, interval), None, "间隔没到");
        assert!(sampler.poll(start + interval, true, interval).is_some());
        let quality = sampler.measured().over_tcp(start + interval).unwrap();
        assert_eq!(quality.rtt, 260 * MS);
        assert!(!sampler.on_reply(&[0; 8], start + interval), "不是它发的");
    }

    #[test]
    fn an_unanswered_sampler_probe_is_not_a_loss_and_its_late_answer_still_counts() {
        let start = Instant::now();
        let interval = Duration::from_secs(5);
        let mut sampler = Sampler::new();
        let first = sampler.poll(start, true, interval).unwrap();
        sampler.on_reply(&first, start + 250 * MS);
        let stalled = sampler.poll(start + interval, true, interval).unwrap();
        // 等了超时（这里是延迟的 4 倍，1 秒）还没有回答：转去等它迟到的回答。下一个照样按间隔发。
        assert_eq!(sampler.poll(start + interval + Duration::from_secs(1), true, interval), None);
        assert!(sampler.expects(&stalled));
        let next = sampler.poll(start + interval * 2, true, interval).unwrap();
        // 迟到 1.2 秒的回答记一个样本；对端频率上限挡掉的那种永远不来，也不算丢包。
        assert!(sampler.on_reply(&stalled, start + interval + 1200 * MS));
        let measured = sampler.measured();
        assert_eq!(measured.over_tcp(start + interval * 2).unwrap().rtt, (250 * MS + 1200 * MS) / 2);
        assert_eq!(measured.quality(start + interval * 2).map(|quality| (quality.lost, quality.probes)), Some((0, 0)));
        assert!(sampler.expects(&next));
    }
}
