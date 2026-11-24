//! 丢包账本：把丢掉的和送达的字节记回"它们是哪一段时间发出去的"，判断丢包是不是发得太多造成的。
//!
//! 丢包通常需经过约一个往返时间才能检测到，届时控制器可能已切换阶段。因此统计不按“发现丢包的时刻”归属，
//! 而是按数据包发送时刻归入对应周期段：每完成一轮或切换一次阶段开启一个新段。
//!
//! 丢包率超过门限，就认为那时的在途量超过了路径装得下的量。门限是 2% 加上这条路径的背景丢包率。
//! 背景丢包率取自"故意把在途量压到估计值以下"的那些段：那时瓶颈处没有自己造成的排队，还在丢的就和发多少无关。
//!
//! 丢包率是从有限的几百个包里量出来的，而且丢包常常成片（一片就是十来个包），单独一段的数字出入很大。
//! 因此判定时预留两倍标准差容限，并将相邻同类型周期段合并统计：突发超标可在单段内检出，
//! 持续小幅超标也可在合并多段后检出。

use std::collections::VecDeque;
use std::time::Instant;

/// 丢掉的字节超过这个比例（千分比）算丢包过多。和 BBRv2 的取值相同。
const LOSS_THRESHOLD_PERMILLE: u64 = 20;
/// 触发丢包过量判定的最小丢包数。在途仅有几十个包时，丢弃单个包即达百分之几，不具备统计显著性。
const MIN_LOST_PACKETS: u64 = 3;
/// 相邻的段最多并到这么多个包。再多的话，早先的情况已经和现在无关了。
const POOL_PACKETS: u64 = 4000;
/// 估计"一片丢多少"时，一次丢包最多按这么多个包算。拥塞时一次能丢掉几百个包，不能让它把余地撑得太大。
const MAX_BURST_PACKETS: u64 = 32;
/// 背景丢包率的一个样本至少要攒够这么多个包；
const BASELINE_MIN_PACKETS: u64 = 200;
/// 并且要么见过这么多次丢包，要么攒够了下面这么多个包（丢包很少，或者根本没有）。次数太少的话量出来的比例不可信。
const BASELINE_MIN_EVENTS: u64 = 8;
const BASELINE_MAX_PACKETS: u64 = 2000;
/// 背景丢包率取最近这么多个样本里最小的。路径突然变窄时，压低之后仍然在丢的那一两段不会把它抬高。
const BASELINE_SAMPLES: usize = 3;
/// 背景丢包率最多认到这个数（千分比）。再高的话宁可降速：分不清它是不是好几条连接一起挤出来的。
const BASELINE_CAP_PERMILLE: u64 = 100;

/// 周期段内控制器所处的行为模式，决定该段丢包统计的用途。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EpochKind {
    /// 在试探更大的在途量。这时丢包过多，说明试探到头了。
    Probing,
    /// 故意把在途量压在估计值以下。这时的丢包率当作路径的背景丢包率，不算发得太多。
    Draining,
    /// 其余：维持在估计值上。
    Steady,
}

#[derive(Debug, Clone)]
struct Epoch {
    start: Instant,
    kind: EpochKind,
    /// 该周期段允许的在途字节数上限。
    window: u64,
    sent: u64,
    acked: u64,
    lost: u64,
    /// 丢包是分几次报告的。
    loss_events: u64,
    alarmed: bool,
}

impl Epoch {
    fn new(start: Instant, kind: EpochKind, window: u64) -> Self {
        Self { start, kind, window, sent: 0, acked: 0, lost: 0, loss_events: 0, alarmed: false }
    }

    fn is_empty(&self) -> bool {
        self.sent == 0 && self.acked == 0 && self.lost == 0
    }

    /// 计算丢包率的分母，取已发送量与窗口上限的较大值：在应用发送量较少的周期段，少量丢包并不代表路径容量不足。
    fn base(&self) -> u64 {
        self.sent.max(self.window)
    }
}

/// 一段结清之后的结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Verdict {
    pub(super) kind: EpochKind,
    pub(super) window: u64,
    pub(super) sent: u64,
    /// 单轮等效丢包字节数：取当前段自身丢包量与合并多段平均值的较大值。
    pub(super) lost: u64,
    pub(super) too_high: bool,
}

/// 并在一起看的相邻几段。
#[derive(Debug, Clone, Copy)]
struct Pool {
    kind: EpochKind,
    epochs: u64,
    base: u64,
    lost: u64,
}

#[derive(Debug, Clone)]
pub(super) struct Ledger {
    /// 按起始时刻递增排列，末尾元素为当前活跃周期段。
    epochs: VecDeque<Epoch>,
    /// 已确认的包里最晚的发送时刻。
    acked_through: Instant,
    /// 上一次结算时的 `acked_through`。在它之前结束的段，包都有了下落：要么确认了，要么在那之后的丢包检测里判了丢失。
    settled_through: Instant,
    pool: Option<Pool>,
    /// 一次丢包通常丢多少字节，取最近若干次的滑动平均。还没有丢过时是 0，用的时候按一个包算。
    burst: u64,
    baseline: Baseline,
}

impl Ledger {
    pub(super) fn new(now: Instant, window: u64) -> Self {
        Self {
            epochs: VecDeque::from([Epoch::new(now, EpochKind::Probing, window)]),
            acked_through: now,
            settled_through: now,
            pool: None,
            burst: 0,
            baseline: Baseline::default(),
        }
    }

    /// 从 `now` 起开新的一段。
    pub(super) fn begin(&mut self, now: Instant, kind: EpochKind, window: u64) {
        match self.epochs.back_mut() {
            // 若上一段为空（同一时刻连续切换阶段），直接覆写而不保留空段。
            Some(last) if last.is_empty() => *last = Epoch::new(last.start, kind, window),
            _ => self.epochs.push_back(Epoch::new(now, kind, window)),
        }
    }

    pub(super) fn on_sent(&mut self, bytes: u64) {
        if let Some(current) = self.epochs.back_mut() {
            current.sent += bytes;
        }
    }

    pub(super) fn on_ack(&mut self, sent: Instant, bytes: u64) {
        self.acked_through = self.acked_through.max(sent);
        if let Some(epoch) = self.epoch_of(sent) {
            epoch.acked += bytes;
        }
    }

    /// 路断过（在途的包很久没有任何回音）：断之前和断的时候发出的包，之后报告的丢失都和发多少无关，一律不记，
    /// 从 `now` 起重新记账。背景丢包率留着，它是路径的性质，和这一次断路无关。
    pub(super) fn restart(&mut self, now: Instant, kind: EpochKind, window: u64) {
        self.epochs = VecDeque::from([Epoch::new(now, kind, window)]);
        self.pool = None;
    }

    /// 记录一次丢包。当探测周期段的丢包首次超过阈值时返回 `true`，调用方可立即停止探测而不必等待该段结算。
    pub(super) fn on_lost(&mut self, sent: Instant, bytes: u64, mtu: u64) -> bool {
        // 不属于任何在保留周期段的丢包（该段已结算或属于链路中断前发出）不予计入，也不用于估算单次突发丢包量。
        if self.epoch_of(sent).is_none() {
            return false;
        }
        let seen = bytes.clamp(mtu, MAX_BURST_PACKETS * mtu);
        self.burst = if self.burst == 0 { seen } else { (7 * self.burst + seen) / 8 };
        let (threshold, burst) = (self.threshold_permille(), self.burst);
        let Some(epoch) = self.epoch_of(sent) else { return false };
        epoch.lost += bytes;
        epoch.loss_events += 1;
        if epoch.alarmed || epoch.kind != EpochKind::Probing || !exceeds(epoch.lost, epoch.base(), threshold, burst, mtu) {
            return false;
        }
        epoch.alarmed = true;
        true
    }

    /// 结清一段包都有了下落的时间，没有可结的返回 `None`。每处理完一批确认调用到返回 `None` 为止。
    pub(super) fn settle(&mut self, mtu: u64) -> Option<Verdict> {
        let complete = self.epochs.get(1).is_some_and(|next| next.start <= self.settled_through);
        if !complete {
            // 本批确认处理后 QUIC 库会执行丢包检测；至下次调用时，本批之前的发包才全部确定确认或丢失状态。
            self.settled_through = self.acked_through;
            return None;
        }
        let epoch = self.epochs.pop_front()?;
        let mut verdict = Verdict { kind: epoch.kind, window: epoch.window, sent: epoch.sent, lost: epoch.lost, too_high: false };
        if epoch.kind == EpochKind::Draining {
            self.baseline.record(&epoch, mtu);
            self.pool = None;
            return Some(verdict);
        }

        let mut pool = self.pool.filter(|pool| pool.kind == epoch.kind).unwrap_or(Pool { kind: epoch.kind, epochs: 0, base: 0, lost: 0 });
        pool.epochs += 1;
        pool.base += epoch.base();
        pool.lost += epoch.lost;
        verdict.lost = epoch.lost.max(pool.lost / pool.epochs);
        verdict.too_high = exceeds(pool.lost, pool.base, self.threshold_permille(), self.burst, mtu);
        // 下了"过多"的结论就从头再看；并够了也从头再看。
        self.pool = (!verdict.too_high && pool.base < POOL_PACKETS * mtu).then_some(pool);
        Some(verdict)
    }

    /// 一共量出过多少个背景丢包率的样本。
    pub(super) fn baseline_samples(&self) -> usize {
        self.baseline.recorded
    }

    fn threshold_permille(&self) -> u64 {
        LOSS_THRESHOLD_PERMILLE + self.baseline.permille()
    }

    /// 查找发送时刻 `sent` 所属的周期段。早于所有保留段的包不予归属：其原周期段已结算，归入后续段会造成误判。
    fn epoch_of(&mut self, sent: Instant) -> Option<&mut Epoch> {
        let index = self.epochs.iter().rposition(|epoch| epoch.start <= sent)?;
        self.epochs.get_mut(index)
    }
}

/// `base` 字节里丢了 `lost` 字节，是不是超过了门限。
///
/// 按门限该丢 `allowed` 字节、每次丢包丢一片 `burst` 字节时，随机丢包下实际丢掉的字节数的标准差大约是
/// `√(allowed × burst)`。超出门限两倍标准差以上才算超过，否则路径上原本就有的丢包会被一次次当成自己造成的。
fn exceeds(lost: u64, base: u64, threshold_permille: u64, burst: u64, mtu: u64) -> bool {
    let allowed = super::mul_div(base, threshold_permille, 1000);
    let noise = 2 * allowed.saturating_mul(burst.max(mtu)).isqrt();
    lost >= MIN_LOST_PACKETS * mtu && lost > allowed + noise
}

/// 路径的背景丢包率：和发多少无关的那部分丢包。
#[derive(Debug, Clone, Default)]
struct Baseline {
    pending_acked: u64,
    pending_lost: u64,
    pending_events: u64,
    /// 最近的几个样本（千分比），循环覆盖。
    samples: [u64; BASELINE_SAMPLES],
    recorded: usize,
}

impl Baseline {
    fn record(&mut self, epoch: &Epoch, mtu: u64) {
        self.pending_acked += epoch.acked;
        self.pending_lost += epoch.lost;
        self.pending_events += epoch.loss_events;
        let total = self.pending_acked + self.pending_lost;
        let enough_loss = self.pending_events >= BASELINE_MIN_EVENTS || total >= BASELINE_MAX_PACKETS * mtu;
        if total < BASELINE_MIN_PACKETS * mtu || !enough_loss {
            return;
        }
        self.samples[self.recorded % BASELINE_SAMPLES] = super::mul_div(self.pending_lost, 1000, total);
        self.recorded += 1;
        self.pending_acked = 0;
        self.pending_lost = 0;
        self.pending_events = 0;
    }

    fn permille(&self) -> u64 {
        let filled = self.recorded.min(BASELINE_SAMPLES);
        self.samples[..filled].iter().copied().min().unwrap_or(0).min(BASELINE_CAP_PERMILLE)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const MTU: u64 = 1000;
    const MS: Duration = Duration::from_millis(1);

    /// 一段的经过：发了多少，其中丢了多少、分几次报告。
    #[derive(Clone, Copy)]
    struct Run {
        kind: EpochKind,
        sent: u64,
        lost: u64,
        events: u64,
    }

    impl Run {
        fn new(kind: EpochKind, sent: u64, lost: u64) -> Self {
            // 不特别说明时，每次丢一个包。
            Self { kind, sent, lost, events: lost / MTU }
        }

        fn in_bursts_of(self, packets: u64) -> Self {
            Self { events: self.lost / (packets * MTU), ..self }
        }
    }

    /// 让 `ledger` 经历一段 `run`，返回这一段结清后的结论。每一段占 100ms，`at` 是这一段的开始。
    fn play(ledger: &mut Ledger, at: Instant, run: Run) -> Verdict {
        ledger.begin(at, run.kind, run.sent);
        ledger.on_sent(run.sent);
        ledger.begin(at + 50 * MS, EpochKind::Steady, run.sent);
        ledger.on_ack(at + 10 * MS, run.sent - run.lost);
        for _ in 0..run.events {
            ledger.on_lost(at + 10 * MS, run.lost / run.events, MTU);
        }
        // 下一段发出的包被确认，说明这一段的包都有了下落。
        ledger.on_ack(at + 50 * MS, 0);
        assert_eq!(ledger.settle(MTU), None, "同一批确认之后的丢包检测还没有做");
        let verdict = ledger.settle(MTU).expect("这一段应该结清了");
        assert_eq!(ledger.settle(MTU), None);
        verdict
    }

    /// 连着经历几段，返回每一段的结论里"丢包过多"的那一项。
    fn play_all(ledger: &mut Ledger, start: Instant, runs: &[Run]) -> Vec<bool> {
        runs.iter().zip(0..).map(|(&run, index)| play(ledger, start + index * 100 * MS, run).too_high).collect()
    }

    #[test]
    fn loss_is_charged_to_the_epoch_the_packets_were_sent_in() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 100_000);
        ledger.on_sent(100_000);
        ledger.begin(start + 50 * MS, EpochKind::Steady, 100_000);
        ledger.on_sent(100_000);
        // 第一段发的包里丢了 10 个（10%），是在第二段进行当中陆续发现的。丢到第 5 个时超过了门限。
        let alarms: Vec<bool> = (0..10).map(|_| ledger.on_lost(start + 20 * MS, 1_000, MTU)).collect();
        assert_eq!(alarms, [false, false, false, false, true, false, false, false, false, false]);
        ledger.on_ack(start + 20 * MS, 90_000);
        ledger.on_ack(start + 60 * MS, 1_000);
        assert_eq!(ledger.settle(MTU), None);
        let verdict = ledger.settle(MTU).unwrap();
        assert_eq!(verdict, Verdict { kind: EpochKind::Probing, window: 100_000, sent: 100_000, lost: 10_000, too_high: true });
        assert_eq!(ledger.settle(MTU), None, "第二段还没有结束");
    }

    #[test]
    fn loss_of_packets_from_an_already_settled_epoch_is_not_charged_to_a_later_one() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 100_000);
        play(&mut ledger, start, Run::new(EpochKind::Steady, 100_000, 0));
        ledger.begin(start + 100 * MS, EpochKind::Probing, 100_000);
        ledger.on_sent(100_000);
        // 很久以前发的包现在才判为丢失（比如靠探测超时才发现的）。
        assert!(!ledger.on_lost(start + MS, 50_000, MTU));
        assert!(ledger.epochs.iter().all(|epoch| epoch.lost == 0));
    }

    #[test]
    fn loss_must_exceed_the_threshold_by_twice_its_noise() {
        let start = Instant::now();
        // 一千个包、门限 2%：该丢 20 个，随机丢包下的出入大约是 √20 ≈ 4.5 个，所以丢 28 个不算超过，30 个算。
        for (lost, too_high) in [(28_000, false), (30_000, true)] {
            let mut ledger = Ledger::new(start, 0);
            assert_eq!(play(&mut ledger, start, Run::new(EpochKind::Steady, 1_000_000, lost)).too_high, too_high);
        }
    }

    #[test]
    fn bursty_loss_gets_more_room() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 0);
        // 同样丢 40 个包：一个一个丢的话是超过了；十个一片地丢，只是多丢了两片，还在出入的范围里。
        assert!(play(&mut ledger, start, Run::new(EpochKind::Steady, 1_000_000, 40_000)).too_high);
        let mut ledger = Ledger::new(start, 0);
        assert!(!play(&mut ledger, start, Run::new(EpochKind::Steady, 1_000_000, 40_000).in_bursts_of(10)).too_high);
        assert!(play(&mut ledger, start + 100 * MS, Run::new(EpochKind::Steady, 1_000_000, 100_000).in_bursts_of(10)).too_high);
    }

    #[test]
    fn a_couple_of_lost_packets_prove_nothing() {
        let start = Instant::now();
        // 20 个包丢 2 个是 10%，但只有两个包。
        for (lost, too_high) in [(2_000, false), (3_000, true)] {
            let mut ledger = Ledger::new(start, 0);
            assert_eq!(play(&mut ledger, start, Run::new(EpochKind::Steady, 20_000, lost)).too_high, too_high);
        }
    }

    #[test]
    fn a_small_excess_shows_up_once_enough_epochs_are_pooled() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 0);
        // 每一段都丢 2.6%，单看哪一段都在出入的范围里；并到第三段就看得出一直在超。
        let run = Run::new(EpochKind::Steady, 1_000_000, 26_000);
        assert_eq!(play_all(&mut ledger, start, &[run; 4]), [false, false, true, false], "下了结论之后从头再看");
    }

    #[test]
    fn pooling_stops_at_a_few_thousand_packets_and_at_a_change_of_kind() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 0);
        // 丢 2.4%：并到四千个包还看不出来，之后重新开始并。一直并下去的话，到第六段会算超过。
        let run = Run::new(EpochKind::Steady, 1_000_000, 24_000);
        assert_eq!(play_all(&mut ledger, start, &[run; 8]), [false; 8]);
        // 巡航和试探不并在一起。
        let mut ledger = Ledger::new(start, 0);
        let runs = [
            Run::new(EpochKind::Steady, 1_000_000, 26_000),
            Run::new(EpochKind::Steady, 1_000_000, 26_000),
            Run::new(EpochKind::Probing, 1_000_000, 26_000),
        ];
        assert_eq!(play_all(&mut ledger, start, &runs), [false; 3]);
    }

    #[test]
    fn only_a_probing_epoch_raises_the_alarm_and_only_once() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 100_000);
        ledger.on_sent(100_000);
        // 100 个包：该丢 2 个，出入不到 3 个，丢到第 5 个算超过。
        let alarms: Vec<bool> = (0..7).map(|_| ledger.on_lost(start, 1_000, MTU)).collect();
        assert_eq!(alarms, [false, false, false, false, true, false, false]);

        ledger.begin(start + 50 * MS, EpochKind::Steady, 100_000);
        ledger.on_sent(100_000);
        assert!(!ledger.on_lost(start + 50 * MS, 50_000, MTU));
    }

    #[test]
    fn loss_in_a_mostly_idle_epoch_is_measured_against_the_window() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 1_000_000);
        // 允许在途 1MB，应用只发了 30KB，丢了 4 个包。
        ledger.on_sent(30_000);
        assert!(!ledger.on_lost(start, 4_000, MTU));
    }

    #[test]
    fn loss_while_draining_is_background_and_raises_the_threshold() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 0);
        // 路径本身丢 3%：没有量出背景丢包率之前算超过。
        assert!(play(&mut ledger, start, Run::new(EpochKind::Steady, 1_000_000, 40_000)).too_high);
        // 压低在途量的那一段照样丢 3%。这一段本身不算超过，它量出来的就是背景丢包率。
        assert!(!play(&mut ledger, start + 100 * MS, Run::new(EpochKind::Draining, 1_000_000, 30_000)).too_high);
        assert_eq!(ledger.baseline.permille(), 30);
        // 之后门限是 5%：丢 4% 不算超过，丢 9% 算。
        let runs = [Run::new(EpochKind::Steady, 1_000_000, 40_000), Run::new(EpochKind::Steady, 1_000_000, 90_000)];
        assert_eq!(play_all(&mut ledger, start + 200 * MS, &runs), [false, true]);
    }

    fn drained(acked: u64, lost: u64, loss_events: u64) -> Epoch {
        Epoch { acked, lost, loss_events, ..Epoch::new(Instant::now(), EpochKind::Draining, 0) }
    }

    #[test]
    fn background_loss_is_the_smallest_recent_sample_and_is_capped() {
        let mut baseline = Baseline::default();
        baseline.record(&drained(990_000, 10_000, 10), MTU);
        assert_eq!(baseline.permille(), 10);
        baseline.record(&drained(500_000, 500_000, 10), MTU);
        baseline.record(&drained(500_000, 500_000, 10), MTU);
        assert_eq!(baseline.permille(), 10, "取最小的：路径变窄时的那两段不算背景");
        baseline.record(&drained(500_000, 500_000, 10), MTU);
        assert_eq!(baseline.permille(), BASELINE_CAP_PERMILLE);
    }

    #[test]
    fn a_background_sample_waits_for_enough_packets_and_enough_loss_events() {
        let mut baseline = Baseline::default();
        // 150 个包，丢包的次数够了，包不够。
        baseline.record(&drained(140_000, 10_000, 10), MTU);
        assert_eq!(baseline.recorded, 0);
        baseline.record(&drained(140_000, 10_000, 10), MTU);
        assert_eq!((baseline.recorded, baseline.samples[0]), (1, 66));

        // 1500 个包里只有两片丢包：再丢一片比例就差出一半，不可信，接着攒。
        baseline.record(&drained(1_480_000, 20_000, 2), MTU);
        assert_eq!(baseline.recorded, 1);
        // 攒到 2000 个包还是只有这么几次，说明丢包确实少，就按量到的算。
        baseline.record(&drained(500_000, 0, 0), MTU);
        assert_eq!((baseline.recorded, baseline.samples[1]), (2, 10));
    }

    #[test]
    fn after_an_outage_losses_of_earlier_packets_are_not_charged() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 100_000);
        ledger.on_sent(100_000);
        // 路断了，100ms 时恢复。之前发的包这时才陆续判为丢失。
        ledger.restart(start + 100 * MS, EpochKind::Steady, 100_000);
        assert!(!ledger.on_lost(start + 10 * MS, 50_000, MTU));
        assert_eq!(ledger.burst, 0, "也不拿来估计一片丢多少");
        assert_eq!((ledger.epochs.len(), ledger.epochs[0].lost), (1, 0));
        // 恢复之后发的包照常记账。
        ledger.on_sent(10_000);
        assert!(!ledger.on_lost(start + 120 * MS, 1_000, MTU));
        assert_eq!(ledger.epochs[0].lost, 1_000);
    }

    #[test]
    fn an_empty_epoch_is_replaced_instead_of_kept() {
        let start = Instant::now();
        let mut ledger = Ledger::new(start, 1000);
        ledger.begin(start, EpochKind::Steady, 2000);
        ledger.begin(start, EpochKind::Draining, 3000);
        assert_eq!(ledger.epochs.len(), 1);
        assert_eq!((ledger.epochs[0].kind, ledger.epochs[0].window), (EpochKind::Draining, 3000));
    }
}
