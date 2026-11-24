//! BBR 一族的拥塞控制：估计瓶颈带宽和不排队时的往返时间，让在途的数据量维持在两者的乘积附近。
//!
//! # 是哪一种
//!
//! 状态机和两个滤波器是 BBRv1 的（启动、排空、带宽探测的增益循环、往返时间探测；带宽取最近 10 轮送达速率的最大值，
//! 往返时间下限取一个时间窗口里的最小值），再加上 BBRv2 对丢包的处理中的在途量上限（inflight_hi）：一轮里丢包率
//! 超过门限，就把上限缩到"这一轮的窗口减去丢掉的"，一次最多缩到 0.7 倍；之后只在向上试探时抬高它，每轮的步子翻倍。
//! BBRv2 的另一半（inflight_lo、bw_lo：非试探阶段一有丢包就压低的短期下限）没有做：它在随机丢包的路径上会一直往下压。
//! v1 完全不看丢包，在缓冲浅的窄带宽上会成倍超发；v2 的固定 2% 门限在随机丢包高于 2% 的路径上又会一路降速。
//! 这里的门限是 2% 加上这条路径的背景丢包率（见 [`loss`]）。
//!
//! 在途的数据很久（至少 1 秒、并且至少四个往返时间下限）没有任何回音时，算路断过一次，断的时候发出的包的丢失不算账：
//! 那是路径层在换路或者等路恢复，和发多少无关。
//!
//! # 和标准 BBR 的差别：只控制在途量
//!
//! 标准的 BBR 主要靠发送速率控制，拥塞窗口只是保险。QUIC 库的拥塞控制接口只有 [`Controller::window`] 一个输出，
//! 其内置发送节奏固定为“窗口 ÷ 平滑往返时间 × 1.25”，控制器无法直接指定速率，因此将各阶段增益统一作用于窗口：
//!
//! | 阶段 | 允许的在途量 |
//! |---|---|
//! | 启动 | 2 × BDP，每轮送达速率翻倍 |
//! | 排空、巡航 | 1 × BDP + 一批确认的量 |
//! | 向上试探 | 1.25 × BDP + 一批确认的量；被在途量上限挡住时，每轮只多放一小步 |
//! | 向下 | 0.9 × BDP |
//! | 往返时间探测 | 0.5 × 最近一轮的送达速率 × 往返时间下限 |
//!
//! BDP 是带宽估计 × 往返时间。向下和往返时间探测用往返时间的下限；其余阶段用"向下的那一轮里量到的往返时间"，
//! 它比下限多出来的部分是别的连接在瓶颈处排的队，最多按下限的两倍算。这样做的后果：
//!
//! - 自己造成的排队不超过"窗口 − 路径装得下的量"，估计准确时巡航阶段基本不排队。路径变慢而带宽估计还没降下来时，
//!   排队也以旧的窗口为限，不会无限增长。丢包被藏起来、只看得到延迟变大的路径（比如经 TCP 中转）上也是如此。
//! - 往返时间下限偏小时，标准 BBR 仍按估计的速率发，这里则会发得不够，带宽估计跟着一路降下去。所以多了两条规则。
//!   一是下限不会被单独一个偏低的样本压下去。二是实际的往返时间连续几轮远高于"按窗口和带宽估计算出来该有的值"，
//!   就提前做一次往返时间探测：把在途量降下来之后量到的往返时间如果仍然那么高，是路径变长了，下限换成新的，
//!   按原来那条路定下的在途量上限也作废；如果回落了，是带宽估计偏高，旧的带宽样本作废。
//! - 和把缓冲填满的连接（Cubic 之类）共用瓶颈时，拿到的份额比标准 BBR 少：往返时间超过下限两倍之后，
//!   在途量不再跟着放大。
//!
//! # QUIC 库的接口带来的其他限制
//!
//! - 确认时库只给"这个包是什么时候发的"，不给包号；发送时也只说"这一批在什么时刻发出"。送达速率的记录因此按
//!   发送时刻对上，同一时刻发出的一批共用一条（见 [`sampler`]）。
//! - "应用没有数据可发"不是按包标记的：库只在确认到达时告诉控制器，上一次组包时是不是既没发出东西、也没被窗口挡住。
//!   流的接收窗口挡住发送时也算没有数据可发，所以单条流被接收窗口限速时，样本都带着应用受限的标记，只能抬高带宽估计。
//! - 一次丢包检测里判丢的包一起报告，只带其中最晚的那个的发送时刻，丢包就按这个时刻记账（见 [`loss`]）。
//! - 换路发生在库的下面，库和控制器都得不到通知，只能从往返时间和送达速率的变化自己发现（上一节）。
//! - 链路中断恢复后，QUIC 库的平滑往返时间会被旧包确认抬高，导致其发送节奏远慢于窗口允许值，此阶段的送达速率不用于拉低带宽估计
//!   （见 [`PACER_LAG`]）。
//!
//! # 没有做的
//!
//! - 不看 ECN 的拥塞标记。库把它和丢包用同一个回调通知，但不带字节数，这里忽略。
//! - 多条连接共用一个缓冲很浅的瓶颈时，彼此造成的丢包会被当成背景丢包容忍下来，上限是 10%。
//! - 当瓶颈缓冲区小于 QUIC 库单次突发发送量（10 个包）时，丢包源于库自身的发送节奏，拥塞窗口无法消除。
//!
//! # 依据
//!
//! - draft-ietf-ccwg-bbr（BBRv3 草案）和 draft-cardwell-iccrg-bbr-congestion-control（BBRv1/v2）
//! - draft-cheng-iccrg-delivery-rate-estimation（送达速率估计）
//! - RFC 9002（丢包检测与拥塞控制的接口）

mod filter;
mod loss;
mod sampler;
#[cfg(test)]
mod sim;

use std::any::Any;
use std::hash::{BuildHasher, Hasher};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;

use self::filter::{Floor, MinRtt, WindowedMax};
use self::loss::{EpochKind, Ledger, Verdict};
use self::sampler::{AckSample, Sampler};

/// 带宽估计看最近多少轮。
const FILTER_ROUNDS: u64 = 10;
/// 往返时间下限多久没有被再次看到就要重新量。
const MIN_RTT_WINDOW: Duration = Duration::from_secs(5);
/// 往返时间下限被大幅抬高之后，过多久复核一次。
const MIN_RTT_RECHECK: Duration = Duration::from_secs(2);
/// 往返时间探测时，在途量降到位之后保持多久。要长过对端攒确认的时间，也给别的连接留出看到空队列的机会。
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
/// 别的连接在瓶颈处排着队时，在途量跟着实际的往返时间放大，最多按往返时间下限的这么多倍算（和 BBR 的窗口增益相同）。
const QUEUE_RTT_GAIN: u32 = 2;
/// 启动阶段连续这么多轮带宽涨不到 25%，就认为到了瓶颈带宽。
const STARTUP_FULL_ROUNDS: u32 = 3;
/// 向上试探至少持续几轮。第一轮发出去的包第二轮才被确认，所以两轮之后才看得到试探的效果。
const UP_MIN_ROUNDS: u32 = 2;
/// 巡航几轮之后再向上试探，每次在这个范围里随机取，免得几条连接同时试探。
/// 整个循环不能长过带宽滤波器的窗口，否则上一次试探量到的带宽会在下一次试探之前过期。
const CRUISE_ROUNDS: RangeInclusive<u32> = 3..=6;
/// 向上试探以丢包过多收场时，下一次巡航的轮数翻倍，最多翻这么多次；试探没有造成丢包就恢复原样。
/// 缓冲很浅的路径上每试探一次都要丢一些包，试探得越勤丢得越多；和怕丢包的连接共用瓶颈时也给它们留出恢复的时间。
const MAX_PROBE_BACKOFF: u32 = 3;
/// 为了量背景丢包率，向下的阶段最多持续这么多轮。在途量小、丢包又成片的时候，一两轮里见不到几次丢包。
const BASELINE_DOWN_ROUNDS: u32 = 40;
/// 启动阶段带宽连续这么多轮不涨、同时试探的丢包过多，就不再等，直接结束启动。
const STARTUP_LOSS_ROUNDS: u32 = 2;
/// 丢包过多时在途量上限一次最多缩到原来的多少（百分比）。和 BBRv2 的取值相同。
const BETA_PERCENT: u64 = 70;
/// 窗口不小于这么多个包。再小的话一次丢包就要靠超时才能恢复。
const MIN_WINDOW_PACKETS: u64 = 4;
/// 一轮里最小的往返时间超过"该有的值"的这么多（百分比），算这一轮在排队。
/// 自己向上试探时最多造成 25% 的排队，留出余量。
const INFLATION_PERCENT: u128 = 150;
/// 连续这么多轮都在排队，就提前做往返时间探测。
const INFLATED_ROUNDS: u32 = 3;
/// 两次因为排队提前做的往返时间探测至少隔这么久。往返时间本身抖动很大的路径上，不让它反复触发。
const INFLATION_HOLDOFF: Duration = Duration::from_secs(2);
/// 算 BDP 时往返时间下限至少按这么长算，一轮也至少这么长。往返时间只有几十微秒到一毫秒的路径（同一台机器、
/// 局域网）上，收发两端一批一批处理包、定时器唤醒的间隔都比往返时间长，在途量只有"带宽 × 往返时间"的话连一批
/// 都装不下，窗口就成了瓶颈。库自己的发送节奏是 2ms 一批，取相同的值。代价是这类路径上最多多排 2ms 的队。
const MIN_RTT_FLOOR: Duration = Duration::from_millis(2);

/// 在途有数据、却至少这么久（并且至少四个往返时间下限）没有收到任何确认，算路断过一次。
/// 正常的尾部丢包靠探测超时恢复，安静的时间是两三个往返时间；拥塞时确认照样一直在来，只是来得晚。
const OUTAGE: Duration = Duration::from_secs(1);

/// 库的平滑往返时间比这一批量到的往返时间高出这么多倍时，这一批的送达速率只能用来抬高带宽估计。
///
/// 库按"窗口 ÷ 它的平滑往返时间 × 1.25"定发送节奏。断路之后第一批确认里有断路之前发的包（路径层补发的、对端补发的
/// 旧确认），库从它们得到几秒的往返时间样本，平滑值一下子到几百毫秒，而实际的往返时间只有几毫秒。这时送达速率量的是
/// 库的发送节奏，不是路径，和应用没有数据可发时一样；拿它拉低带宽估计的话，窗口跟着落到最小，节奏更慢，平滑值要好几秒
/// 才降得下来。平时一个样本比平滑值低一些是常事，所以要高出几倍才算。
const PACER_LAG: u32 = 4;

/// 日志里每隔多久记一次估计值。
const REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// 建 [`Bbr`] 的工厂，交给 QUIC 库的传输配置。
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BbrConfig;

impl ControllerFactory for BbrConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        // 标准库的哈希种子每次取都不同，用它当随机数种子，不用为此引入依赖。
        let seed = std::collections::hash_map::RandomState::new().build_hasher().finish();
        Box::new(Bbr::new(now, current_mtu, seed))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// 每轮把在途量翻倍，直到送达速率不再涨。
    Startup,
    /// 启动阶段多发出去的那部分排在瓶颈处，等它排空。
    Drain,
    ProbeBw(Phase),
    ProbeRtt(ProbeRtt),
}

/// 带宽探测阶段里的一步。顺序是巡航 → 向上 → 向下 → 巡航。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// 维持在估计的 BDP 上。
    Cruise { rounds_left: u32 },
    /// 多发 25%，看送达速率涨不涨。涨就继续，不涨说明已经到了瓶颈带宽。
    Up { rounds: u32, base_bw: u64 },
    /// 压到估计值以下：排空试探时造成的排队，顺便量背景丢包率和没有自己排队时的往返时间。
    /// 通常只一轮；因为巡航时丢包过多而进来的，留到量出一个新的背景丢包率样本为止（`samples_before` 是进来时已有的样本数）。
    Down { rounds_left: u32, samples_before: usize },
}

/// 往返时间探测：把在途量降下来，量没有自己排队时的往返时间。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeRtt {
    /// 探测期间允许的在途量，进入时定下。
    window: u64,
    stage: ProbeStage,
    /// 这次探测是因为连续几轮排队而提前做的。
    inflation: Option<Inflation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeStage {
    /// 等在途量降到位。
    Draining,
    /// 在途量在 `since` 降到位了。那之后发出的包被确认时，量到的才是没有自己排队的往返时间。
    Settling { since: Instant },
    /// 下限已经换成了降到位之后量到的值，继续量到 `until`。
    Measuring { until: Instant },
}

/// 向下的一轮里发出的包量到的往返时间。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueueProbe {
    since: Instant,
    /// 向下的一轮什么时候结束的。还没有结束时是 `None`。
    until: Option<Instant>,
    rtt: Option<Duration>,
}

/// 提前做往返时间探测之前看到的排队。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Inflation {
    /// 排队的那几轮里，最后一轮的最小往返时间。
    rtt: Duration,
    /// 从哪一轮开始排队的。
    since_round: u64,
}

/// 一条连接的拥塞控制状态。
#[derive(Debug, Clone)]
pub(crate) struct Bbr {
    mtu: u64,
    /// 还没有带宽估计时用的窗口。
    base_window: u64,
    window: u64,
    state: State,
    /// 状态或者轮次变了，丢包账本要开新的一段。
    epoch_stale: bool,
    sampler: Sampler,
    /// 瓶颈带宽的估计，字节每秒。
    bw: WindowedMax,
    /// 正在进行的这一轮、和刚结束的那一轮里量到的最大送达速率。
    round_bw: Option<u64>,
    latest_bw: Option<u64>,
    min_rtt: MinRtt,
    /// 最近一次把在途量压到估计值以下时量到的往返时间：那时自己没有多排队，比下限高出来的部分是别人排的队。
    /// 巡航和向上试探按它算在途量。只按下限算的话，别人的队排得越长，同样的在途量换来的速率越低，
    /// 带宽估计跟着降，在途量再跟着降，最后被挤到几乎没有。
    queue_rtt: Option<Duration>,
    /// 正在量上面这个值：向下的那一轮里发出的包还没有都被确认。
    queue_probe: Option<QueueProbe>,
    ledger: Ledger,
    /// 在途量的上限：超过它曾经造成过多的丢包。没有丢过就没有上限。
    inflight_hi: Option<u64>,
    /// 启动阶段：上一次明显增长之后的带宽，和之后没有明显增长的轮数。
    full_bw: u64,
    full_bw_rounds: u32,
    /// 启动阶段已经结束（到过瓶颈带宽）。
    filled_pipe: bool,
    /// 最近连续几次向上试探是以丢包过多收场的。
    probe_backoff: u32,
    /// 确认是一批一批到的，这两个数是每批字节数的平方、和每批字节数的滑动累计，相除得到"一个字节通常和多少字节一起被确认"。
    batch_squares: u128,
    batch_bytes: u128,
    /// 这一轮里最小的往返时间，和这一轮里用过的最大窗口。
    round_min_rtt: Option<Duration>,
    round_max_window: u64,
    /// 连续多少轮在排队，以及其中最近一轮里最小的往返时间。
    inflated_rounds: u32,
    inflated_rtt: Option<Duration>,
    last_inflation_probe: Option<Instant>,
    in_flight: u64,
    /// 上一批确认之后第一次发送的时刻。从那时起发出去的数据还没有任何回音。
    unanswered_since: Option<Instant>,
    /// 最近一次断路结束的时刻：断了之后第一批确认到达的时候。
    outage_ended: Option<Instant>,
    /// 库自己的平滑往返时间，它的发送节奏按这个算（见 [`PACER_LAG`]）。
    pacing_rtt: Option<Duration>,
    next_report: Instant,
    rng: XorShift,
}

impl Bbr {
    pub(crate) fn new(now: Instant, mtu: u16, seed: u64) -> Self {
        let mtu = u64::from(mtu);
        let base_window = initial_window(mtu);
        Self {
            mtu,
            base_window,
            window: base_window,
            state: State::Startup,
            epoch_stale: false,
            sampler: Sampler::new(now, MIN_RTT_FLOOR),
            bw: WindowedMax::new(FILTER_ROUNDS),
            round_bw: None,
            latest_bw: None,
            min_rtt: MinRtt::new(now, MIN_RTT_WINDOW, MIN_RTT_RECHECK),
            queue_rtt: None,
            queue_probe: None,
            ledger: Ledger::new(now, base_window),
            inflight_hi: None,
            full_bw: 0,
            full_bw_rounds: 0,
            filled_pipe: false,
            probe_backoff: 0,
            batch_squares: 0,
            batch_bytes: 0,
            round_min_rtt: None,
            round_max_window: base_window,
            inflated_rounds: 0,
            inflated_rtt: None,
            last_inflation_probe: None,
            in_flight: 0,
            unanswered_since: None,
            outage_ended: None,
            pacing_rtt: None,
            next_report: now + REPORT_INTERVAL,
            rng: XorShift::new(seed),
        }
    }

    /// 排查某条连接为什么慢时要看的就是这几个估计值。这一秒里没有收到确认就不记。
    fn report(&self) {
        tracing::debug!(
            state = ?self.state,
            bw = self.bw.get(),
            min_rtt = ?self.min_rtt.get(),
            extra = self.extra(),
            inflight_hi = self.inflight_hi,
            window = self.window,
            in_flight = self.in_flight,
            round = self.sampler.round(),
            "拥塞控制估计值"
        );
    }

    fn sent(&mut self, now: Instant, bytes: u64) {
        self.unanswered_since.get_or_insert(now);
        self.sampler.on_sent(now);
        self.ledger.on_sent(bytes);
    }

    fn acked(&mut self, now: Instant, sent: Instant, bytes: u64) {
        self.sampler.on_ack(now, sent, bytes);
        self.ledger.on_ack(sent, bytes);
    }

    fn end_acks(&mut self, now: Instant, in_flight: u64, app_limited: bool) {
        self.in_flight = in_flight;
        let silence = self.take_silence(now);
        let outage = silence > self.outage_after();
        if outage {
            // 路断了，或者路径层换了一条路。断的时候发出去的包会在这批确认之后被判丢失，那不是发得太多。
            tracing::debug!(?silence, "在途数据长时间未收到确认，判定发生链路中断，此前发包的丢包不计为拥塞");
            self.ledger.restart(now, self.epoch_kind(), self.window);
            self.epoch_stale = false;
            self.outage_ended = Some(now);
        }
        while let Some(verdict) = self.ledger.settle(self.mtu) {
            self.apply_verdict(verdict);
        }

        // 往返时间探测期间是自己故意少发，量出来的速率和应用没数据可发时一样，不能用来拉低带宽估计。
        let self_limited = app_limited || matches!(self.state, State::ProbeRtt(_));
        if let Some(mut sample) = self.sampler.finish(now, in_flight, self_limited, self.min_rtt.get()) {
            // 库的发送节奏还按断路时抬高的往返时间走，见 [`PACER_LAG`]。
            if self.pacing_rtt.is_some_and(|srtt| srtt > sample.rtt.max(MIN_RTT_FLOOR) * PACER_LAG) {
                sample.app_limited = true;
            }
            let floor = self.min_rtt.update(now, sample.rtt);
            if let Some(rate) = sample.rate {
                self.round_bw = self.round_bw.max(Some(rate));
                if !sample.app_limited || self.bw.get().is_none_or(|bw| rate > bw) {
                    self.bw.update(self.sampler.round(), rate);
                }
            }
            // 断路之后的第一批确认是攒了很久的一大批，不是平时确认成批到达的样子。
            if !outage {
                self.batch_squares = self.batch_squares * 7 / 8 + u128::from(sample.acked) * u128::from(sample.acked);
                self.batch_bytes = self.batch_bytes * 7 / 8 + u128::from(sample.acked);
            }
            self.round_min_rtt = Some(self.round_min_rtt.map_or(sample.rtt, |rtt| rtt.min(sample.rtt)));
            self.update_queue_rtt(now, &sample);
            if sample.round_ended {
                self.on_round_end(&sample);
            }
            self.advance(now, &sample, floor);
            if now >= self.next_report {
                self.next_report = now + REPORT_INTERVAL;
                self.report();
            }
        }

        self.update_window();
        if self.epoch_stale {
            self.epoch_stale = false;
            self.ledger.begin(now, self.epoch_kind(), self.window);
        }
    }

    fn lost(&mut self, now: Instant, sent: Instant, is_persistent: bool, lost_bytes: u64) {
        if lost_bytes == 0 {
            return;
        }
        // QUIC 栈判定"持续拥塞"的依据是较长时间段内发出的包全部丢失。若这些包发出于断路期间，对应区间已按断路处理
        // （见 `end_acks`，QUIC 栈总是先上报该批确认再上报丢包），与发送量无关，不触发重启。若重启，窗口将回落至最小值，
        // 而发送节奏仍受断路期间抬高的往返时间约束（见 [`PACER_LAG`]），导致恢复后 1～2 秒内速率难以回升。
        if is_persistent && self.outage_ended.is_some_and(|ended| sent < ended) {
            return;
        }
        if is_persistent {
            self.restart(now);
            return;
        }
        if self.ledger.on_lost(sent, lost_bytes, self.mtu) {
            // 探测引起的丢包过多：立即停止探测。上限缩减幅度待当前周期结算、确定实际送达量后再定。
            self.stop_probing("探测阶段丢包过多");
            self.update_window();
        }
    }

    /// 一长段时间里发出去的包全丢了：原来的路径多半已经不在，之前的估计都不可信，从最小的窗口重新开始。
    fn restart(&mut self, now: Instant) {
        tracing::debug!(window = self.window, "持续丢包，重置拥塞控制状态");
        self.base_window = MIN_WINDOW_PACKETS * self.mtu;
        self.window = self.base_window;
        self.state = State::Startup;
        self.epoch_stale = false;
        self.bw = WindowedMax::new(FILTER_ROUNDS);
        self.round_bw = None;
        self.latest_bw = None;
        self.min_rtt = MinRtt::new(now, MIN_RTT_WINDOW, MIN_RTT_RECHECK);
        self.queue_rtt = None;
        self.queue_probe = None;
        self.ledger = Ledger::new(now, self.window);
        self.inflight_hi = None;
        self.full_bw = 0;
        self.full_bw_rounds = 0;
        self.filled_pipe = false;
        self.probe_backoff = 0;
        self.round_min_rtt = None;
        self.round_max_window = self.window;
        self.inflated_rounds = 0;
        self.inflated_rtt = None;
    }

    fn enter(&mut self, state: State, why: &'static str) {
        tracing::trace!(from = ?self.state, to = ?state, why, bw = self.bw.get(), min_rtt = ?self.min_rtt.get(), "拥塞控制切换阶段");
        self.state = state;
        self.epoch_stale = true;
    }

    fn enter_cruise(&mut self, why: &'static str) {
        let rounds_left = self.rng.pick(CRUISE_ROUNDS) << self.probe_backoff;
        self.enter(State::ProbeBw(Phase::Cruise { rounds_left }), why);
    }

    fn enter_down(&mut self, rounds: u32, why: &'static str) {
        let down = Phase::Down { rounds_left: rounds, samples_before: self.ledger.baseline_samples() };
        self.enter(State::ProbeBw(down), why);
    }

    /// 启动阶段只在带宽不再涨的时候才把丢包当作"到头了"：带宽还在翻倍，说明丢的不是装不下的那部分。
    /// 随机丢包会让个别的一轮涨不上去，所以要连着两轮。
    fn is_startup_growing(&self) -> bool {
        self.state == State::Startup && self.full_bw_rounds < STARTUP_LOSS_ROUNDS
    }

    fn stop_probing(&mut self, why: &'static str) {
        match self.state {
            State::Startup if self.is_startup_growing() => {}
            State::Startup => {
                self.filled_pipe = true;
                self.enter(State::Drain, why);
            }
            State::ProbeBw(Phase::Up { .. }) => {
                self.probe_backoff = (self.probe_backoff + 1).min(MAX_PROBE_BACKOFF);
                self.enter_down(1, why);
            }
            State::Drain | State::ProbeBw(Phase::Cruise { .. } | Phase::Down { .. }) | State::ProbeRtt(_) => {}
        }
    }

    fn apply_verdict(&mut self, verdict: Verdict) {
        if verdict.too_high {
            if self.is_startup_growing() {
                return;
            }
            // 一段不超过一轮。窗口比路径装得下的量多出多少，一轮里就丢多少，所以装得下的量大约是窗口减去丢掉的。
            // 一次最多缩到原来的 70%：单独一段丢得多可能是偶然的。
            let fits = verdict.window.saturating_sub(verdict.lost);
            let ceiling = self.inflight_hi.map_or(verdict.window, |hi| hi.min(verdict.window));
            let floor = MIN_WINDOW_PACKETS * self.mtu;
            self.inflight_hi = Some(fits.max(mul_div(ceiling, BETA_PERCENT, 100)).max(floor));
            if verdict.kind == EpochKind::Probing {
                self.stop_probing("探测阶段丢包过多");
            } else if matches!(self.state, State::ProbeBw(Phase::Cruise { .. })) {
                // 没有在试探也丢得多。把在途量压低看看：还照样丢的话，这些丢包和发多少无关，之后就不再为它降速。
                self.enter_down(BASELINE_DOWN_ROUNDS, "巡航阶段丢包过多");
            }
        } else if verdict.kind == EpochKind::Probing
            && let Some(hi) = self.inflight_hi
            && verdict.window > hi
            && verdict.sent >= verdict.window / 4 * 3
        {
            // 超过上限试探了一段，窗口也确实用上了，没有丢得过多：上限抬到这一段的窗口。
            self.inflight_hi = Some(verdict.window);
        }
    }

    fn on_round_end(&mut self, sample: &AckSample) {
        self.epoch_stale = true;
        self.latest_bw = self.round_bw.take().or(self.latest_bw);
        let bw = self.bw.get().unwrap_or(0);
        match self.state {
            State::Startup => {
                // 应用没有填满连接的那些轮，带宽不涨不说明到了瓶颈。但在途量已经够一个 BDP 时例外：
                // 管道是满的，带宽还不涨就是到头了。流的接收窗口正好卡在一到两个 BDP 之间时就是这种情况，
                // 不这样判断的话会一直停在启动阶段，多出来的那部分一直排在瓶颈处。
                let is_pipe_full = self.bdp().is_some_and(|bdp| self.in_flight >= bdp);
                if !sample.app_limited || is_pipe_full {
                    if bw >= mul_div(self.full_bw, 5, 4) {
                        self.full_bw = bw;
                        self.full_bw_rounds = 0;
                    } else {
                        self.full_bw_rounds += 1;
                        if self.full_bw_rounds >= STARTUP_FULL_ROUNDS {
                            self.filled_pipe = true;
                            self.enter(State::Drain, "带宽连续几轮不再增长");
                        }
                    }
                }
            }
            State::ProbeBw(Phase::Cruise { rounds_left }) => {
                let next = match rounds_left.saturating_sub(1) {
                    0 => Phase::Up { rounds: 0, base_bw: bw },
                    rounds_left => Phase::Cruise { rounds_left },
                };
                self.state = State::ProbeBw(next);
            }
            State::ProbeBw(Phase::Up { rounds, base_bw }) => {
                let rounds = rounds + 1;
                if rounds < UP_MIN_ROUNDS {
                    self.state = State::ProbeBw(Phase::Up { rounds, base_bw });
                } else if bw >= mul_div(base_bw, 9, 8) {
                    self.state = State::ProbeBw(Phase::Up { rounds, base_bw: bw });
                } else if self.is_bound_by_inflight_hi(rounds) {
                    // 还没试探到 1.25 倍就被上限挡住了：继续，每轮把试探的步子翻倍。
                    self.state = State::ProbeBw(Phase::Up { rounds, base_bw });
                } else {
                    self.probe_backoff = 0;
                    self.enter_down(1, "探测增发后送达速率未增长");
                }
            }
            State::ProbeBw(Phase::Down { rounds_left, samples_before }) => {
                if rounds_left <= 1 || self.ledger.baseline_samples() != samples_before {
                    self.enter_cruise("回落阶段结束");
                } else {
                    self.state = State::ProbeBw(Phase::Down { rounds_left: rounds_left - 1, samples_before });
                }
            }
            State::Drain | State::ProbeRtt(_) => {}
        }

        let queueing = self
            .round_min_rtt
            .zip(self.expected_rtt())
            .filter(|_| matches!(self.state, State::ProbeBw(_)))
            .filter(|(rtt, expected)| rtt.as_nanos() * 100 > expected.as_nanos() * INFLATION_PERCENT);
        match queueing {
            Some((rtt, _)) => {
                self.inflated_rounds += 1;
                self.inflated_rtt = Some(rtt);
            }
            None => {
                self.inflated_rounds = 0;
                self.inflated_rtt = None;
            }
        }
        self.round_min_rtt = None;
        self.round_max_window = self.window;
    }

    /// 向下的那一轮里发出的包被确认时记下往返时间；它们都确认完了，就用其中最小的更新 [`Self::queue_rtt`]。
    fn update_queue_rtt(&mut self, now: Instant, sample: &AckSample) {
        let is_down = matches!(self.state, State::ProbeBw(Phase::Down { .. }));
        let Some(probe) = &mut self.queue_probe else {
            if is_down {
                self.queue_probe = Some(QueueProbe { since: now, until: None, rtt: None });
            }
            return;
        };
        if !is_down && probe.until.is_none() {
            probe.until = Some(now);
        }
        if sample.sent < probe.since {
            return;
        }
        if probe.until.is_none_or(|until| sample.sent < until) {
            probe.rtt = Some(probe.rtt.map_or(sample.rtt, |rtt| rtt.min(sample.rtt)));
            return;
        }
        // 一次最多抬高四分之一：别人的队是慢慢排起来的；一下子高出很多是路径变了或者带宽估计过高，那要靠往返时间探测去分辨。
        let ceiling = self.queue_rtt.or(self.min_rtt.get()).map(|previous| previous * 5 / 4);
        self.queue_rtt = probe.rtt.zip(ceiling).map(|(rtt, ceiling)| rtt.min(ceiling));
        self.queue_probe = None;
    }

    /// 不按轮次发生的状态变化：排空结束、往返时间探测的开始和进展。
    fn advance(&mut self, now: Instant, sample: &AckSample, floor: Floor) {
        match self.state {
            State::Drain => {
                if self.in_flight <= self.target_window(State::ProbeBw(Phase::Cruise { rounds_left: 0 })) {
                    self.enter_cruise("启动阶段超发数据已排空");
                }
            }
            State::ProbeRtt(probe) => {
                self.advance_probe_rtt(now, probe, sample);
                return;
            }
            State::Startup | State::ProbeBw(_) => {}
        }
        let (Some(bw), Some(min_rtt)) = (self.latest_bw.or(self.bw.get()), self.min_rtt.get()) else { return };

        let holdoff_passed = self.last_inflation_probe.is_none_or(|at| now.saturating_duration_since(at) >= INFLATION_HOLDOFF);
        let inflation = self
            .inflated_rtt
            .filter(|_| self.inflated_rounds >= INFLATED_ROUNDS && holdoff_passed)
            .map(|rtt| Inflation { rtt, since_round: self.sampler.round().saturating_sub(u64::from(self.inflated_rounds)) });
        if inflation.is_none() && floor == Floor::Fresh {
            return;
        }
        self.inflated_rounds = 0;
        self.inflated_rtt = None;
        if inflation.is_some() {
            self.last_inflation_probe = Some(now);
        }
        // 探测期间的在途量按最近一轮实际的送达速率算，不按带宽估计：带宽估计偏高时，按它算出来的一半未必排得空队列。
        let window = self.bounded_by_inflight_hi(bytes_in(bw, min_rtt.max(MIN_RTT_FLOOR)) / 2).max(MIN_WINDOW_PACKETS * self.mtu);
        if sample.app_limited && self.in_flight <= window {
            // 应用发送量较低，当前在途字节数已不高于探测目标窗口，样本不含自身引入的排队时延，无需进入探测。
            self.replace_floor(now, sample.rtt);
            return;
        }
        let why = if inflation.is_some() { "往返时间连续多轮高于预期值" } else { "往返时间下限长时间未刷新" };
        self.enter(State::ProbeRtt(ProbeRtt { window, stage: ProbeStage::Draining, inflation }), why);
    }

    fn advance_probe_rtt(&mut self, now: Instant, probe: ProbeRtt, sample: &AckSample) {
        // 这期间发出的包都带上"自己少发"的标记。
        self.sampler.mark_app_limited(self.in_flight);
        let stage = match probe.stage {
            ProbeStage::Draining if self.in_flight <= probe.window => ProbeStage::Settling { since: now },
            ProbeStage::Settling { since } if sample.sent >= since => {
                self.replace_floor(now, sample.rtt);
                ProbeStage::Measuring { until: now + PROBE_RTT_DURATION }
            }
            ProbeStage::Measuring { until } if now >= until => {
                self.finish_probe_rtt(probe);
                return;
            }
            stage @ (ProbeStage::Draining | ProbeStage::Settling { .. } | ProbeStage::Measuring { .. }) => stage,
        };
        self.state = State::ProbeRtt(ProbeRtt { stage, ..probe });
    }

    fn finish_probe_rtt(&mut self, probe: ProbeRtt) {
        if let Some(inflation) = probe.inflation
            && self.min_rtt.get().is_some_and(|floor| inflation.rtt * 4 > floor * 5)
        {
            // 把在途量降下来之后量到的往返时间，比之前那几轮低得多：之前是在排队，带宽估计偏高。
            // 只留排队那几轮量到的送达速率，那时瓶颈是满的，量到的就是现在的带宽。
            self.bw.forget_before(inflation.since_round);
        }
        // 刚量过没有自己排队时的往返时间，之前量的作废。
        self.queue_rtt = None;
        self.queue_probe = None;
        if self.filled_pipe {
            self.enter_cruise("往返时间探测结束");
        } else {
            self.enter(State::Startup, "往返时间探测结束");
        }
    }

    /// 用一个里面没有自己排队的样本换掉往返时间的下限。
    ///
    /// 下限被大幅抬高，多半是换了一条更长的路。在途量上限是在原来那条路上按丢包定下的字节数，路变长之后它会把窗口
    /// 卡在新的 BDP 之下很多；被卡住时量到的送达速率又会把带宽估计拉低，要好几秒才试探得回来。所以这时作废它，
    /// 新的路上发得太多的话会重新丢包、重新定下来。
    fn replace_floor(&mut self, now: Instant, rtt: Duration) {
        if self.min_rtt.replace(now, rtt)
            && let Some(hi) = self.inflight_hi.take()
        {
            tracing::debug!(inflight_hi = hi, ?rtt, "往返时间下限大幅抬升，可能已切换路径，清除旧路径对应的在途量上限");
        }
    }

    /// 发出去的数据等了多久才有回音，并且从这一批确认起重新计时。
    ///
    /// 从上一批确认之后第一次发送算起，而不是从上一批确认算起：应用没有数据可发的那段时间不算在里面。
    fn take_silence(&mut self, now: Instant) -> Duration {
        self.unanswered_since.take().map_or(Duration::ZERO, |since| now.saturating_duration_since(since))
    }

    /// 在途的数据多久没有回音算路断过一次。
    fn outage_after(&self) -> Duration {
        self.min_rtt.get().map_or(OUTAGE, |floor| OUTAGE.max(floor * 4))
    }

    /// 按往返时间下限算的 BDP：路径上只有自己时装得下的量。
    fn floor_bdp(&self) -> Option<u64> {
        Some(bytes_in(self.bw.get()?, self.min_rtt.get()?.max(MIN_RTT_FLOOR)))
    }

    /// 巡航时用的 BDP：别的连接排着队时，按含着那段排队的往返时间算。
    fn bdp(&self) -> Option<u64> {
        let floor = self.min_rtt.get()?;
        let rtt = self.queue_rtt.map_or(floor, |rtt| rtt.clamp(floor, floor * QUEUE_RTT_GAIN));
        Some(bytes_in(self.bw.get()?, rtt.max(MIN_RTT_FLOOR)))
    }

    /// 给确认聚合留的余量：一批确认通常确认多少字节，最多一个 BDP。
    ///
    /// 一批确认到达的那一刻，在途量一下子少掉一批，新发出去的这一批要过一会儿才到瓶颈；瓶颈处得有差不多一批的包垫着，
    /// 链路才不会空下来。BBR 草案里的估计方法是拿带宽估计当基准，看确认比"该到的"多出多少；带宽估计一时偏低
    /// （带宽刚变大、别的连接刚让出带宽）的时候，它会把"送得比估计快"也算成聚合，在只控制在途量的做法里这直接变成排队。
    /// 所以这里直接量每批的大小，按字节加权取平均：大批和小批交替时，要垫的是大批的量。
    fn extra(&self) -> u64 {
        let batch = u64::try_from(self.batch_squares.checked_div(self.batch_bytes).unwrap_or(0)).unwrap_or(u64::MAX);
        batch.min(self.bdp().unwrap_or(0))
    }

    /// 向上试探到第 `rounds` 轮时，在途量上限允许超出多少：每轮翻倍。
    fn probe_step(&self, rounds: u32) -> u64 {
        self.mtu << rounds.min(20)
    }

    fn is_bound_by_inflight_hi(&self, rounds: u32) -> bool {
        let (Some(hi), Some(bdp)) = (self.inflight_hi, self.bdp()) else { return false };
        hi.saturating_add(self.probe_step(rounds)) < mul_div(bdp, 5, 4) + self.extra()
    }

    fn bounded_by_inflight_hi(&self, window: u64) -> u64 {
        self.inflight_hi.map_or(window, |hi| window.min(hi))
    }

    /// 按窗口和带宽估计，这一轮的往返时间该是多少：在途的数据按估计的带宽送完要这么久。
    fn expected_rtt(&self) -> Option<Duration> {
        let (bw, min_rtt) = (self.bw.get()?, self.min_rtt.get()?);
        (bw > 0).then(|| min_rtt.max(Duration::from_nanos(mul_div(self.round_max_window, NANOS_PER_SEC, bw))))
    }

    fn target_window(&self, state: State) -> u64 {
        let Some(bdp) = self.bdp() else { return self.base_window };
        let extra = self.extra();
        match state {
            State::Startup => (bdp.saturating_mul(2).saturating_add(extra)).max(self.base_window),
            State::Drain | State::ProbeBw(Phase::Cruise { .. }) => self.bounded_by_inflight_hi(bdp + extra),
            State::ProbeBw(Phase::Up { rounds, .. }) => {
                let window = mul_div(bdp, 5, 4) + extra;
                self.inflight_hi.map_or(window, |hi| window.min(hi.saturating_add(self.probe_step(rounds))))
            }
            State::ProbeBw(Phase::Down { .. }) => self.bounded_by_inflight_hi(mul_div(self.floor_bdp().unwrap_or(bdp), 9, 10)),
            State::ProbeRtt(probe) => probe.window,
        }
    }

    fn update_window(&mut self) {
        self.window = self.target_window(self.state).max(MIN_WINDOW_PACKETS * self.mtu);
        self.round_max_window = self.round_max_window.max(self.window);
    }

    fn epoch_kind(&self) -> EpochKind {
        match self.state {
            State::Startup | State::ProbeBw(Phase::Up { .. }) => EpochKind::Probing,
            State::ProbeBw(Phase::Down { .. }) | State::ProbeRtt(_) => EpochKind::Draining,
            State::Drain | State::ProbeBw(Phase::Cruise { .. }) => EpochKind::Steady,
        }
    }
}

impl Controller for Bbr {
    fn on_sent(&mut self, now: Instant, bytes: u64, _last_packet_number: u64) {
        self.sent(now, bytes);
    }

    // 往返时间的样本由发送时刻自己算。库的估计只用来看它的发送节奏是不是还按断路时的值走。
    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, _app_limited: bool, rtt: &RttEstimator) {
        self.pacing_rtt = Some(rtt.get());
        self.acked(now, sent, bytes);
    }

    fn on_end_acks(&mut self, now: Instant, in_flight: u64, app_limited: bool, _largest_packet_num_acked: Option<u64>) {
        self.end_acks(now, in_flight, app_limited);
    }

    fn on_congestion_event(&mut self, now: Instant, sent: Instant, is_persistent_congestion: bool, lost_bytes: u64) {
        self.lost(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu);
        self.update_window();
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        initial_window(self.mtu)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// RFC 9002 §7.2 的初始窗口。
fn initial_window(mtu: u64) -> u64 {
    (10 * mtu).min((2 * mtu).max(14_720))
}

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// `value × num ÷ den`。中间结果用 128 位，最后封顶到 `u64::MAX`。
fn mul_div(value: u64, num: u64, den: u64) -> u64 {
    u64::try_from(u128::from(value) * u128::from(num) / u128::from(den.max(1))).unwrap_or(u64::MAX)
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// `interval` 里送达了 `bytes` 字节，速率是多少字节每秒。
fn bytes_per_sec(bytes: u64, interval: Duration) -> u64 {
    mul_div(bytes, NANOS_PER_SEC, nanos(interval))
}

/// 按 `rate` 字节每秒，`duration` 里能送多少字节。
fn bytes_in(rate: u64, duration: Duration) -> u64 {
    mul_div(rate, nanos(duration), NANOS_PER_SEC)
}

/// 很小的伪随机数发生器，只用来错开各条连接试探的时机。
#[derive(Debug, Clone)]
struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        // 状态不能是 0。
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick(&mut self, range: RangeInclusive<u32>) -> u32 {
        let span = u64::from(range.end() - range.start()) + 1;
        let offset = u32::try_from(self.next() % span).expect("余数小于 span，而 span 不超过 u32 的范围");
        range.start() + offset
    }
}

#[cfg(test)]
mod tests;
