//! 路径层用到的时间参数，集中在一处，改的时候看得到彼此的关系。

use std::time::Duration;

/// 往返延迟的平滑估计，算法和 TCP 的 SRTT 一样：新样本占八分之一。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rtt(Duration);

impl Rtt {
    pub(crate) const fn new(sample: Duration) -> Self {
        Self(sample)
    }

    pub(crate) fn update(&mut self, sample: Duration) {
        self.0 = (self.0 * 7 + sample) / 8;
    }

    pub(crate) const fn get(self) -> Duration {
        self.0
    }

    /// 四舍五入到毫秒；不到 1 毫秒的报 1，免得和"没有测到"混淆。
    pub(crate) fn millis(self) -> u32 {
        u32::try_from((self.0.as_micros() + 500) / 1000).unwrap_or(u32::MAX).max(1)
    }

    /// 等一个探测的回答等多久算超时：延迟的 4 倍，夹在 [`PROBE_TIMEOUT_MIN`] 和 [`PROBE_TIMEOUT_MAX`] 之间。
    pub(crate) fn probe_timeout(self) -> Duration {
        (self.0 * 4).clamp(PROBE_TIMEOUT_MIN, PROBE_TIMEOUT_MAX)
    }
}

pub(crate) const PROBE_TIMEOUT_MIN: Duration = Duration::from_millis(300);
pub(crate) const PROBE_TIMEOUT_MAX: Duration = Duration::from_millis(1500);

/// 控制任务多久把所有的定时器过一遍。各种超时的精度就是这么多。
pub(crate) const TICK: Duration = Duration::from_millis(50);

/// 在用的直连地址、挂靠的 relay 多久探测一次。
pub(crate) const PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// 探测连续几次没有回答就判为不可用。
pub(crate) const MAX_TIMEOUTS: u8 = 3;
/// 有包发出去、却这么久没有从这条路上收到任何东西时，不等探测间隔，立刻探测。
pub(crate) const SILENCE: Duration = Duration::from_secs(1);
/// 判定“发送后无响应”时纳入统计的最近发送时间窗口。
pub(crate) const UNANSWERED_WINDOW: Duration = Duration::from_secs(6);

/// 一个对端多久没有包要发就算不活跃：停止探测它的直连，为它临时建的中转会话可以回收。
/// 连接层每 15 秒保活一次，所以有连接的对端始终是活跃的。
pub(crate) const PEER_ACTIVE: Duration = Duration::from_secs(45);

/// 没有路或者路可疑时留着的最后几个包，最多放这么久。再旧的重放出去只会让对面算出离谱的延迟。
pub(crate) const STASH_MAX_AGE: Duration = Duration::from_secs(20);

/// 打洞失败之后隔多久再试。
pub(crate) const PUNCH_BACKOFF: [Duration; 8] = [
    Duration::from_secs(1),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(8),
    Duration::from_secs(16),
];
/// 上面那一轮都不成之后：连接还在走 relay 并且有流量时，每隔这么久再试一次。
pub(crate) const PUNCH_IDLE_RETRY: Duration = Duration::from_secs(60);
/// 单次打洞尝试中，自起始时刻起向全部候选地址发送探测的各轮偏移时刻。
/// 首轮探测通常会被对端 NAT 拦截（此时对端尚未向外发包），后续两轮用于完成双向穿透。
pub(crate) const PUNCH_VOLLEYS: [Duration; 3] = [Duration::ZERO, Duration::from_millis(300), Duration::from_millis(600)];
/// 一次打洞尝试从开始到判为失败的时间。
pub(crate) const PUNCH_ATTEMPT: Duration = Duration::from_millis(1500);

/// 中转会话握手的每一步等多久重发，一共发几次。
pub(crate) const HANDSHAKE_RETRY: Duration = Duration::from_millis(500);
pub(crate) const HANDSHAKE_TRIES: u8 = 4;
/// 走在 TCP 里的握手，每一步等回答等多久。TCP 里的帧不会丢、只会迟到，所以不重发，只是等得久一些：
/// 丢包的链路上一次重传就是一两秒，按 UDP 的节奏（半秒一次、两秒放弃）会在链路只是慢的时候白白放弃。
/// 两步加起来要比 relay 给握手留的时间（10 秒）短。
///
/// 保活无响应时不采用此长等待，仍尽快关闭重建。实测（晚高峰、20% 丢包链路）：约三分之二卡死的 TCP 连接
/// 等待 20 秒仍无法恢复，而新建连接通常在 1 秒内即可完成握手；可自行恢复的三分之一也并不比重连更快。
pub(crate) const TCP_HANDSHAKE_STEP: Duration = Duration::from_secs(4);
/// 到 relay 的 TCP 连接上，已发送数据超过该时长仍未获确认时，内核将终止连接（`TCP_USER_TIMEOUT`，与重传上限配合设置，
/// 见 `i3t_underlay::tcp_recovery`）。
///
/// 上层自行判定该 TCP 连接存活：会话建立后保活连续 3 次无响应（约 4.5 秒内）即关闭重连，握手阶段每步等待
/// [`TCP_HANDSHAKE_STEP`]。此处取 10 秒可确保长于上层全部等待阈值，避免内核抢先终止连接，同时限制已关闭 socket 在内核中的最长残留时间。
pub(crate) const TCP_LEG_GIVE_UP: Duration = Duration::from_secs(10);
/// UDP 与 TCP 并发连接时，预留给 UDP 握手的先行时间窗口，超时未完成则放行 TCP 握手。
pub(crate) const UDP_HEAD_START: Duration = Duration::from_secs(1);
/// 使用 TCP 中继的节点定期重试 UDP 的间隔。
pub(crate) const UDP_RETRY: Duration = Duration::from_secs(30);
/// 不可达 relay 的指数退避重试上限（从 1 秒起逐次翻倍直至该上限）。
/// 单次重试开销仅为一个 TCP 连接与若干 UDP 包，而无法连接任何 relay 的节点处于孤立状态，因此上限不宜过长。
pub(crate) const RELAY_RETRY_MAX: Duration = Duration::from_secs(10);
/// 非挂靠 relay 的周期性延迟探测间隔。
pub(crate) const RELAY_SURVEY: Duration = Duration::from_secs(60);
/// 测量结果的有效期，过期作废。
pub(crate) const ESTIMATE_TTL: Duration = Duration::from_secs(120);

/// relay 间骨干链路的 UDP 保活探测间隔；骨干切换为 TCP 时沿用 [`PROBE_INTERVAL`]（见 `crate::relays`）。
pub(crate) const BACKBONE_PROBE_INTERVAL: Duration = Duration::from_secs(2);
/// 骨干链路单向可达宽限期：到对方的 UDP 会话已建立，但对方超过该时长仍未通过 UDP 在本节点建立会话时，
/// 判定对方无法直达本节点，切换为由本节点主动拨出的 TCP 连接。该时长足以覆盖对方 netmap 延迟与握手重试，避免对方重启时误判。
pub(crate) const ONE_SIDED_GRACE: Duration = Duration::from_secs(10);
/// 骨干链路采用 TCP 且按节点 ID 规则不由本节点优先拨号时，等待对方拨入的最大时长，超时后由本节点主动拨号（对方可能无法连入）。
/// 对方发起拨号需经历自身 UDP 握手超时（2 秒）及 TCP 建连与握手（单个不可达地址最多 4 秒）。
pub(crate) const DIAL_DEFER: Duration = Duration::from_secs(10);
/// 复用的入站 TCP 连接未能建立会话（例如对方为不支持反向复用的旧版本）后，不再复用同一连接的冷却时长。
pub(crate) const OFFER_RETRY: Duration = Duration::from_secs(60);
/// 骨干链路从 TCP 切回 UDP 后的稳定观察期：若在该时长内再次退回 TCP，则视为切回失败并加倍后台 UDP 重试间隔（见 `crate::relays`）。
/// 各类切回失败场景均会在此窗口内暴露（单向不可达需 [`ONE_SIDED_GRACE`]、对方 UDP 握手失败 2 秒、
/// 加之 TCP 拨号等待 [`DIAL_DEFER`]，合计约 20 余秒，预留余量应对高负载）；稳定超过该时长则重置重试间隔。
pub(crate) const RETURN_PROBATION: Duration = Duration::from_secs(60);
/// 骨干链路后台尝试 UDP 的最大退避间隔。若对端为不支持双向探测的旧版 relay 且仅单向 UDP 可达，
/// 每次切回 UDP 都会引发数秒至十余秒中断（见 `crate::relays`），因此将频率限制为最多每小时一次。
pub(crate) const BACKBONE_RETRY_MAX: Duration = Duration::from_secs(3600);
/// 骨干走着 TCP 时，对方经 UDP 敲门（它的 AUTH 被本节点的 relay 挡下了）引出的 UDP 尝试至少隔这么久才再来一次。
/// 比一次没有回答的 UDP 握手（[`HANDSHAKE_TRIES`] × [`HANDSHAKE_RETRY`]，两秒）长：对方一次尝试里的几个 AUTH 只引出一次，
/// 一个不停敲门的 relay（或者有人重放它的 AUTH）也只能让本节点每 5 秒多握一次手。对方正常的尝试隔得比这久得多。
pub(crate) const KNOCK_GAP: Duration = Duration::from_secs(5);
/// 测试用的开关：环境变量 `I3T_TEST_BACKBONE_UDP_RETRY`（秒）改骨干走 TCP 时在后台试 UDP 的间隔（[`backbone_udp_retry`]），
/// 集成测试里不用一等就是半分钟。
const BACKBONE_RETRY_TEST_SWITCH: &str = "I3T_TEST_BACKBONE_UDP_RETRY";
/// 给正在评估的候选路径发探测包列：多久一组，一组几个。
pub(crate) const TRAIN_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const TRAIN_PROBES: u8 = 10;
/// 延迟优先模式多久比较一次候选路径的代价（评估窗口）。
pub(crate) const EVAL_WINDOW: Duration = Duration::from_secs(5);
/// 新的路要连续几个评估窗口都更优才换过去。
pub(crate) const SWITCH_WINDOWS: u8 = 3;
/// 因为代价换过一次路之后至少停留多久。
pub(crate) const MIN_DWELL: Duration = Duration::from_secs(30);
/// 两条路来回换的时候停留期每次加倍，最长到这么久。
pub(crate) const MAX_DWELL: Duration = Duration::from_secs(480);
/// 到一个 relay 的会话断了重连之后要保持这么久，流量才会再换到经它的路上（原来的路断了的时候除外）。
pub(crate) const SETTLE: Duration = MIN_DWELL;
/// relay 多久把骨干矩阵发给它的会话一次。状态变了的时候不等这个间隔。
pub(crate) const ROW_INTERVAL: Duration = Duration::from_secs(5);
/// 延迟优先模式下，入口 relay 只在离本节点最近的这么多个里选，为的是限制探测量。
pub(crate) const ENTRY_RELAYS: usize = 3;

/// 骨干走着 TCP 时多久在后台试一次 UDP：从 [`UDP_RETRY`] 起，回到 UDP 没有回成时加倍（见 `crate::relays`）。
/// 测试可以用 [`BACKBONE_RETRY_TEST_SWITCH`] 改。
pub(crate) fn backbone_udp_retry() -> Duration {
    static RETRY: std::sync::LazyLock<Duration> = std::sync::LazyLock::new(|| {
        let seconds = std::env::var(BACKBONE_RETRY_TEST_SWITCH).ok().and_then(|value| value.parse().ok()).filter(|seconds| *seconds > 0);
        seconds.map_or(UDP_RETRY, Duration::from_secs)
    });
    *RETRY
}

/// “本节点 UDP 可达该 relay”（对方应答了本节点经 UDP 发送的 INIT）这一可达证据的有效期：两个 [`backbone_udp_retry`] 周期另加 5 秒。
///
/// 骨干链路使用 TCP 期间，本节点按该周期在后台试探 UDP，UDP 正常时每次均会刷新证据；即使偶发单次丢包未响应，证据仍保持有效，
/// 附加的 5 秒涵盖一次完整握手耗时（2 秒）及余量。有效期不宜更长，否则已失效的 UDP 会被误判为可达并导致迁移中断。
pub(crate) fn udp_evidence_ttl() -> Duration {
    backbone_udp_retry() * 2 + Duration::from_secs(5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_moves_an_eighth_of_the_way_towards_each_sample() {
        let mut rtt = Rtt::new(Duration::from_millis(80));
        rtt.update(Duration::from_millis(160));
        assert_eq!(rtt.get(), Duration::from_millis(90));
        assert_eq!(rtt.millis(), 90);
        assert_eq!(Rtt::new(Duration::from_micros(40)).millis(), 1);
        assert_eq!(Rtt::new(Duration::from_micros(1500)).millis(), 2);
    }

    #[test]
    fn probe_timeout_follows_the_rtt_within_bounds() {
        assert_eq!(Rtt::new(Duration::from_millis(1)).probe_timeout(), PROBE_TIMEOUT_MIN);
        assert_eq!(Rtt::new(Duration::from_millis(200)).probe_timeout(), Duration::from_millis(800));
        assert_eq!(Rtt::new(Duration::from_secs(2)).probe_timeout(), PROBE_TIMEOUT_MAX);
    }

    #[test]
    fn the_punch_schedule_is_the_one_in_the_design() {
        let seconds: Vec<u64> = PUNCH_BACKOFF.iter().map(Duration::as_secs).collect();
        assert_eq!(seconds, [1, 1, 2, 4, 4, 8, 8, 16]);
        assert!(PUNCH_VOLLEYS.iter().all(|&at| at < PUNCH_ATTEMPT));
    }
}
