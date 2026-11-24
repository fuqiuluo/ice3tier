//! 主动测试在路径层的部分：测试的时间窗、探测包列、把到一个对端的路暂时固定住，以及它们给出的结果。
//!
//! 这里只有状态和算法，收发都在控制任务里（[`crate::control`]）。几条规矩：
//!
//! - **仅响应已知测试。** 测试由装配方按 controller 指令开启（[`crate::Paths::open_test`]），并指定对端、
//!   截止时间与响应探测数上限。超出时间窗、非目标对端、超出上限或重复序号的请求一律忽略，签名验证仅在这些低开销校验通过后执行。
//!   因此对端无法自行开启测试，即使 controller 被攻破也只能在节点本地上限内触发响应。
//! - **探测沿指定路径传输。** 发起方在探测帧中携带路径（[`i3t_proto::probe::TestPing`]），响应方优先沿逆向路径返回，
//!   以测量该路径双向 RTT；若逆向路径不可用，则通过本节点当前路由返回并在响应中注明。
//! - **路径固定有时限。** 吞吐测试需确保连接实际经过被测路径，因此临时固定到对端的路由
//!   （[`crate::Paths::pin`]）。固定时长受 [`MAX_PIN`] 限制，到期后由控制任务自动解除；持有者释放句柄（含任务取消或 panic）
//!   时也会立即解除。解除后恢复为选路策略决定的路由，选路内部状态（迟滞、停留期、会话稳定期）在固定期间继续正常推进。

use std::collections::HashSet;
use std::time::{Duration, Instant};

use i3t_model::control::Route;
use i3t_model::netmap::RoutingMode;
use i3t_proto::NodeId;
use i3t_proto::datagram::RelayPath;
use i3t_proto::probe::TestId;
use tokio::sync::oneshot;

use crate::cost::{self, Segment};
use crate::report::{CandidateReport, DirectKind, RelayLeg};
use crate::routing::PathId;

/// 一个测试最多同时有几条路径在测（直连和指定的 relay 路径都算）。
pub const MAX_TEST_PATHS: usize = 5;
/// 一个测试里回答的一方最多回答多少个探测。默认的测试每条路径 100 个。
pub const MAX_TEST_PROBES: u32 = 600;
/// 一个测试的时间窗最长多久。
pub const MAX_TEST_WINDOW: Duration = Duration::from_secs(180);
/// 一次固定路最长多久，不管调用方要多久。
pub const MAX_PIN: Duration = Duration::from_secs(30);
/// 探测包列里两个探测之间最短隔多久：每个探测都要签名和验签，太密了是在拿测试当负载。
pub const MIN_TRAIN_INTERVAL: Duration = Duration::from_millis(5);
/// 一列最多多少个探测。
pub const MAX_TRAIN_PROBES: u32 = 200;
/// 最后一个探测发出之后等回答等多久。
pub(crate) const TRAIN_WAIT: Duration = Duration::from_secs(2);

/// 测的是哪一条路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestPath {
    /// 直连。
    Direct,
    /// 按顺序经过这些 relay。
    Relays(RelayPath),
}

impl TestPath {
    /// 探测里写的路径。
    #[must_use]
    pub const fn relays(self) -> Option<RelayPath> {
        match self {
            Self::Direct => None,
            Self::Relays(path) => Some(path),
        }
    }

    #[must_use]
    pub const fn from_relays(path: Option<RelayPath>) -> Self {
        match path {
            None => Self::Direct,
            Some(path) => Self::Relays(path),
        }
    }

    /// 从另一头看的同一条路径：relay 倒过来。
    #[must_use]
    pub fn reversed(self) -> Self {
        match self {
            Self::Direct => Self::Direct,
            Self::Relays(path) => {
                let mut relays = path.as_slice().to_vec();
                relays.reverse();
                Self::Relays(RelayPath::new(&relays).expect("倒过来的路径和原来的一样长、一样没有重复"))
            }
        }
    }

    /// 管理接口里的写法。直连要写出对端的地址，`peer_addr` 没有时是 [`Route::None`]。
    #[must_use]
    pub fn to_route(self, peer_addr: Option<std::net::SocketAddr>) -> Route {
        let path = match (self, peer_addr) {
            (Self::Direct, Some(addr)) => Some(PathId::Direct(addr)),
            (Self::Direct, None) => None,
            (Self::Relays(path), _) => Some(PathId::Relays(path)),
        };
        path.map_or(Route::None, PathId::to_route)
    }
}

/// 本节点在测试里带头还是跟随。
///
/// 若两端同时发起直连探测，先发次序取决于时机，会导致直达地址被误判为打洞成功，或反之。
/// 因此由发起方主导（立即尝试并在测试期间将对端视为活跃），接收方仅跟随：正常响应探测与打洞信令，不主动发起探测。
/// 平时有流量时也是一方先发包、另一方跟着，这样量到的就是平时会发生的事。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    Lead,
    Follow,
}

/// 打开一个测试要说清楚的东西。
#[derive(Debug, Clone)]
pub struct TestSpec {
    pub test: TestId,
    pub peer: NodeId,
    /// 带头的一方在时间窗里把对端当作活跃的；跟随的一方不。
    pub side: Side,
    /// 时间窗多长，超过 [`MAX_TEST_WINDOW`] 的按它算。
    pub window: Duration,
    /// 这个测试里本节点最多回答多少个探测，超过 [`MAX_TEST_PROBES`] 的按它算。
    pub max_probes: u32,
    /// 本节点这一头要经过的第一个 relay：时间窗里和它们保持中转会话。指定的路径上的 relay 本节点平时可能不连。
    pub relays: Vec<NodeId>,
}

/// 一个打开着的测试。
#[derive(Debug)]
pub(crate) struct Window {
    pub(crate) peer: NodeId,
    pub(crate) side: Side,
    pub(crate) until: Instant,
    pub(crate) max_probes: u32,
    pub(crate) relays: Vec<NodeId>,
    /// 已响应的探测总数及序号集合，用于去重并避免重复响应重放探测。
    answered: u32,
    seen: HashSet<u32>,
    /// 对端经各条路径发来的探测，每条收到了几个。
    paths: Vec<(TestPath, u32)>,
    /// 本节点发探测时给它们编号用的下一个序号。
    next_seq: u32,
}

/// 收到的一个探测能不能回答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// 能，这是它所在路径上收到的第几个（含它）。
    Answer { received: u32 },
    /// 不能，原因写进日志。
    Refuse(&'static str),
}

impl Window {
    pub(crate) fn new(spec: &TestSpec, now: Instant) -> Self {
        Self {
            peer: spec.peer,
            side: spec.side,
            until: now + spec.window.min(MAX_TEST_WINDOW),
            max_probes: spec.max_probes.min(MAX_TEST_PROBES),
            relays: spec.relays.clone(),
            answered: 0,
            seen: HashSet::new(),
            paths: Vec::new(),
            next_seq: 0,
        }
    }

    pub(crate) fn is_open(&self, now: Instant) -> bool {
        now < self.until
    }

    /// 便宜的检查，在验签名之前做：时间窗、对端、个数、序号。
    pub(crate) fn screen(&self, from: NodeId, seq: u32, path: TestPath, now: Instant) -> Result<(), &'static str> {
        if !self.is_open(now) {
            return Err("测试时间窗已过期");
        }
        if from != self.peer {
            return Err("来源节点非该测试的目标对端");
        }
        if self.answered >= self.max_probes {
            return Err("该测试已达到最大响应探测数上限");
        }
        if self.seen.contains(&seq) {
            return Err("该探测序号已响应");
        }
        if !self.paths.iter().any(|(known, _)| *known == path) && self.paths.len() >= MAX_TEST_PATHS {
            return Err("该测试的路径数量已达上限");
        }
        Ok(())
    }

    /// 签名验过了：记下这个探测，返回它所在路径上收到的个数。调用前要先过 [`screen`](Self::screen)。
    pub(crate) fn admit(&mut self, seq: u32, path: TestPath) -> Admission {
        if !self.seen.insert(seq) {
            return Admission::Refuse("该探测序号已响应");
        }
        self.answered += 1;
        let received = match self.paths.iter_mut().find(|(known, _)| *known == path) {
            Some((_, count)) => {
                *count += 1;
                *count
            }
            None => {
                self.paths.push((path, 1));
                1
            }
        };
        Admission::Answer { received }
    }

    /// 本节点发一列探测要用的 `count` 个序号的起点。
    pub(crate) fn take_seqs(&mut self, count: u32) -> u32 {
        let start = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(count);
        start
    }
}

/// 发一列探测要说清楚的东西。
#[derive(Debug, Clone, Copy)]
pub struct TrainSpec {
    pub test: TestId,
    pub peer: NodeId,
    pub path: TestPath,
    /// 发几个，超过 [`MAX_TRAIN_PROBES`] 的按它算。
    pub count: u32,
    /// 隔多久发一个，不短于 [`MIN_TRAIN_INTERVAL`]。
    pub interval: Duration,
}

/// 一列探测的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainReport {
    pub path: TestPath,
    /// 发出去的个数。
    pub sent: u32,
    /// 每个探测的往返时间（减掉了对端的停留），按发出的顺序；没有回答的是 `None`。
    pub rtts: Vec<Option<Duration>>,
    /// 最后一个得到回答的探测，回答里说对端在这条路径上一共收到了几个。
    pub peer_received: Option<u32>,
    /// 回答里有几个是从同一条路径倒着回来的。
    pub same_path: u32,
    pub interval: Duration,
    /// 从第一个探测发出到等完最后一个回答。
    pub duration: Duration,
    /// 经 relay 传输时，测试开始阶段本节点至首个 relay 所使用的传输协议（UDP 或 TCP）。
    pub relay_leg: Option<RelayLeg>,
    /// 直连时用的对端地址。
    pub peer_addr: Option<std::net::SocketAddr>,
}

/// 一列探测为什么没有发成。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrainError {
    #[error("对端不在 netmap 中")]
    NotPeer,
    #[error("测试未开启或时间窗已过期")]
    NoWindow,
    #[error("当前路径不可用：缺少已验证的直连，或与首个 relay 尚未建立会话")]
    Unreachable,
    #[error("本节点不建立直连")]
    DirectDisabled,
    #[error("本节点不使用 relay")]
    RelayDisabled,
    #[error("路径层已停止")]
    Stopped,
}

/// 一列探测的延迟和丢包，算好的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencySummary {
    pub sent: u32,
    pub answered: u32,
    pub min_us: Option<u32>,
    pub avg_us: Option<u32>,
    pub p95_us: Option<u32>,
    /// 相邻两个往返时间之差的绝对值的平均，微秒。没有两个以上的回答时是 `None`。
    pub jitter_us: Option<u32>,
    /// 往返的丢包，千分之几。
    pub loss_permille: u16,
    /// 去程与回程各自丢包率（千分比），依据对端回报的接收计数拆分；若无任何响应则无法区分，返回 `None`。
    pub loss_up_permille: Option<u16>,
    pub loss_down_permille: Option<u16>,
}

impl TrainReport {
    /// 算出最小、平均、p95、抖动和丢包。
    ///
    /// 抖动取相邻两个往返时间之差的绝对值的平均（RFC 3550 那种按单程时间戳算的抖动要两边的钟对得上，这里没有）。
    /// 去程丢包按最后一个得到回答的探测算：它之前发出的有几个，对端说收到了几个；之后发出的那几个对端收没收到不知道，不算。
    #[must_use]
    pub fn summary(&self) -> LatencySummary {
        let answered: Vec<u32> = self.rtts.iter().flatten().map(|rtt| micros(*rtt)).collect();
        let count = u32::try_from(answered.len()).unwrap_or(u32::MAX);
        let mut sorted = answered.clone();
        sorted.sort_unstable();
        let total: u64 = answered.iter().map(|&us| u64::from(us)).sum();
        let avg = (count > 0).then(|| u32::try_from(total / u64::from(count)).unwrap_or(u32::MAX));
        let p95 = (!sorted.is_empty()).then(|| {
            // 最近秩法：第 ⌈0.95 n⌉ 个。
            let rank = (sorted.len() * 95).div_ceil(100).max(1);
            sorted[rank - 1]
        });
        let jitter = (answered.len() >= 2).then(|| {
            let diffs: u64 = answered.windows(2).map(|pair| u64::from(pair[0].abs_diff(pair[1]))).sum();
            let pairs = u64::try_from(answered.len() - 1).unwrap_or(u64::MAX);
            u32::try_from(diffs / pairs).unwrap_or(u32::MAX)
        });
        let (up, down) = match (self.rtts.iter().rposition(Option::is_some), self.peer_received) {
            (Some(last), Some(received)) if received > 0 => {
                let before = u32::try_from(last + 1).unwrap_or(u32::MAX);
                (
                    Some(permille(before.saturating_sub(received.min(before)), before)),
                    Some(permille(received.saturating_sub(count), received)),
                )
            }
            _ => (None, None),
        };
        LatencySummary {
            sent: self.sent,
            answered: count,
            min_us: sorted.first().copied(),
            avg_us: avg,
            p95_us: p95,
            jitter_us: jitter,
            loss_permille: permille(self.sent.saturating_sub(count), self.sent),
            loss_up_permille: up,
            loss_down_permille: down,
        }
    }
}

impl LatencySummary {
    /// 按代价公式（`crate::cost`）用这次测到的值算出来的代价，毫秒。`relays` 是路径上的 relay 数。没有回答时是 `None`。
    #[must_use]
    pub fn cost_ms(&self, relays: usize) -> Option<f64> {
        let rtt_ms = f64::from(self.avg_us?) / 1000.0;
        let jitter_ms = f64::from(self.jitter_us.unwrap_or(0)) / 1000.0;
        let segment = Segment { rtt_ms, jitter_ms, loss: f64::from(self.loss_permille) / 1000.0 };
        Some(cost::path_cost(&[segment], relays, 0.0))
    }
}

fn micros(duration: Duration) -> u32 {
    u32::try_from(duration.as_micros()).unwrap_or(u32::MAX)
}

/// `part / whole` 的千分之几，四舍五入。`whole` 是 0 时是 0。
fn permille(part: u32, whole: u32) -> u16 {
    if whole == 0 {
        return 0;
    }
    let value = (u64::from(part) * 1000 + u64::from(whole) / 2) / u64::from(whole);
    u16::try_from(value.min(1000)).unwrap_or(1000)
}

/// 控制任务里一列正在发的探测。
#[derive(Debug)]
pub(crate) struct TrainRun {
    pub(crate) spec: TrainSpec,
    pub(crate) first_seq: u32,
    pub(crate) started: Instant,
    /// 每个探测发出的时刻；还没发的是 `None`。
    pub(crate) sent_at: Vec<Option<Instant>>,
    pub(crate) rtts: Vec<Option<Duration>>,
    pub(crate) peer_received: Option<u32>,
    pub(crate) same_path: u32,
    pub(crate) relay_leg: Option<RelayLeg>,
    pub(crate) peer_addr: Option<std::net::SocketAddr>,
    pub(crate) reply: Option<oneshot::Sender<Result<TrainReport, TrainError>>>,
}

impl TrainRun {
    pub(crate) fn new(spec: TrainSpec, first_seq: u32, now: Instant, reply: oneshot::Sender<Result<TrainReport, TrainError>>) -> Self {
        let count = usize::try_from(spec.count.min(MAX_TRAIN_PROBES)).unwrap_or(0);
        let spec = TrainSpec { count: spec.count.min(MAX_TRAIN_PROBES), interval: spec.interval.max(MIN_TRAIN_INTERVAL), ..spec };
        Self {
            spec,
            first_seq,
            started: now,
            sent_at: vec![None; count],
            rtts: vec![None; count],
            peer_received: None,
            same_path: 0,
            relay_leg: None,
            peer_addr: None,
            reply: Some(reply),
        }
    }

    /// 下一个该发的探测：它在列里的位置和该发的时刻。都发完了是 `None`。
    pub(crate) fn next_due(&self) -> Option<(usize, Instant)> {
        let index = self.sent_at.iter().position(Option::is_none)?;
        let offset = self.spec.interval.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX));
        Some((index, self.started + offset))
    }

    /// 什么时候该醒来：发下一个探测，或者等完最后一个回答。
    pub(crate) fn wake_at(&self) -> Instant {
        self.next_due().map_or_else(|| self.last_sent().unwrap_or(self.started) + TRAIN_WAIT, |(_, at)| at)
    }

    fn last_sent(&self) -> Option<Instant> {
        self.sent_at.iter().flatten().max().copied()
    }

    /// 都发完了，并且都有了回答或者等够了。
    pub(crate) fn is_finished(&self, now: Instant) -> bool {
        self.next_due().is_none()
            && (self.rtts.iter().all(Option::is_some)
                || self.last_sent().is_none_or(|last| now.saturating_duration_since(last) >= TRAIN_WAIT))
    }

    /// 序号 `seq` 是不是这一列的。是的话返回它在列里的位置。
    pub(crate) fn index_of(&self, seq: u32) -> Option<usize> {
        let index = usize::try_from(seq.checked_sub(self.first_seq)?).ok()?;
        (index < self.sent_at.len()).then_some(index)
    }

    /// 记下一个回答。`arrived` 是收包路径看到它的时刻，`held` 是对端说它停留的时间。重复的回答不算。
    pub(crate) fn answered(&mut self, index: usize, arrived: Instant, held: Duration, received: u32, same_path: bool) {
        let (Some(Some(sent)), Some(slot)) = (self.sent_at.get(index).copied(), self.rtts.get_mut(index)) else { return };
        if slot.is_some() {
            return;
        }
        *slot = Some(arrived.saturating_duration_since(sent).saturating_sub(held));
        if same_path {
            self.same_path += 1;
        }
        // 回答可能乱序到：取序号最大的那个回答里说的数。
        let latest = self.rtts.iter().rposition(Option::is_some).is_some_and(|last| last == index);
        if latest {
            self.peer_received = Some(received);
        }
    }

    pub(crate) fn report(&self, now: Instant) -> TrainReport {
        TrainReport {
            path: self.spec.path,
            sent: u32::try_from(self.sent_at.iter().flatten().count()).unwrap_or(u32::MAX),
            rtts: self.rtts.clone(),
            peer_received: self.peer_received,
            same_path: self.same_path,
            interval: self.spec.interval,
            duration: now.saturating_duration_since(self.started),
            relay_leg: self.relay_leg,
            peer_addr: self.peer_addr,
        }
    }
}

/// 到一个对端的路被测试暂时固定在哪里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pin {
    pub(crate) id: u64,
    pub(crate) path: TestPath,
    pub(crate) until: Instant,
}

/// 一次直连尝试的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectAttempt {
    /// 直连可用了。
    pub ok: bool,
    /// 开始时就已经有可用的直连（这时没有新建，也就没有耗时）。
    pub already: bool,
    pub kind: Option<DirectKind>,
    /// 从开始尝试到验证通过。
    pub elapsed: Option<Duration>,
    /// 尝试失败时本节点侧记录的失败原因。
    pub failure: Option<DirectFailure>,
    /// 本节点的 UDP 通不通：到某个 relay 走的是 UDP 就是通的，到 relay 都只能走 TCP 就是不通的，没有 relay 时不知道。
    pub udp: Option<bool>,
    /// 本节点 NAT 映射端口是否随对端地址变化（若为真通常无法完成 UDP 打洞）。
    pub mapping_varies: Option<bool>,
    /// 尝试时手上有几个对端的候选地址。
    pub candidates: usize,
}

/// 直连没有建起来的原因，从本节点这一侧看。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirectFailure {
    /// 本节点的路径限制是只经 relay：不建立直连，也不向对端暴露地址。
    RelayOnly,
    /// 对端不在 netmap 里。
    NotPeer,
    /// 两边都是只主动连接的：谁也不接受对方主动发来的探测。
    DialOutOnly,
    /// 手上没有对端的任何候选地址。
    NoCandidates,
    /// 本节点的 UDP 不通。
    UdpUnavailable,
    /// 本节点 NAT 映射端口随对端变化（对称型 NAT），无法完成打洞。
    MappingVaries,
    /// 试过了，在时限之内没有得到回答。
    Timeout,
}

/// 两种选路模式各会选哪条路。
#[derive(Debug, Clone, PartialEq)]
pub struct RouteDecision {
    /// 本节点现在用的模式。
    pub mode: RoutingMode,
    /// 选路规则现在选的路。主动测试暂时固定的路不算。
    pub current: Route,
    pub direct_first: ModeChoice,
    pub lowest_cost: ModeChoice,
    /// 不算直连时默认模式会经的 relay 路径：relay 质量默认测它。
    pub default_relay: Option<RelayPath>,
    /// 经 relay 的候选里代价最低的路径：relay 质量默认也测它。
    pub cheapest_relay: Option<RelayPath>,
    /// 考虑过的候选路径和代价，按代价从低到高。
    pub candidates: Vec<CandidateReport>,
}

/// 一种模式的选择。
#[derive(Debug, Clone, PartialEq)]
pub struct ModeChoice {
    pub route: Route,
    pub reason: ChoiceReason,
    /// 这条路的代价，毫秒；候选里没有它（没有测量值）时是 `None`。
    pub cost_ms: Option<f64>,
    /// [`ChoiceReason::WithinMargin`] 时：比选的这条（现在的路）便宜、却没有便宜到要换的那条候选。别的时候是 `None`。
    pub cheaper: Option<CheaperPath>,
}

impl ModeChoice {
    /// 没有能走的路。
    pub(crate) fn none() -> Self {
        Self { route: Route::None, reason: ChoiceReason::NoPath, cost_ms: None, cheaper: None }
    }
}

/// 更便宜、但不够换过去的一条候选路径。
#[derive(Debug, Clone, PartialEq)]
pub struct CheaperPath {
    pub route: Route,
    /// 毫秒。
    pub cost_ms: f64,
}

/// 为什么选这条路。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChoiceReason {
    /// 对端在同一个局域网里，局域网直连无条件优先。
    Lan,
    /// 默认模式：直连可用就走直连。
    Direct,
    /// 对端自己就是 relay，两个节点之间有直接的中转会话。
    PeerIsRelay,
    /// 对端挂在本节点自己的 relay 上。
    OwnRelay,
    /// 对端挂靠的 relay（按对端报的延迟排第一个能用的）。
    PeerRelay,
    /// 默认模式：两端无共同可达的单个 relay，改经候选中代价最低的多级 relay 路径。
    NoSharedRelay,
    /// 延迟优先：候选里代价最低的。
    LowestCost,
    /// 延迟优先：留在现在的路上。有更便宜的候选，但没有便宜到选路器换路要的差距（`max(5ms, 10%)`）。
    WithinMargin,
    /// 没有能走的路。
    NoPath,
}

/// 路径上的一段，以及它的测量值从哪里来。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HopReport {
    pub from: NodeId,
    pub to: NodeId,
    /// 往返延迟，毫秒；不知道时是 `None`。
    pub rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    /// 丢包率，0 到 1；不知道时是 `None`。
    pub loss: Option<f64>,
    pub source: HopSource,
}

/// 一段的测量值从哪里来。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HopSource {
    /// 本节点自己测的（到第一个 relay 的会话，或者直连）。
    Measured,
    /// relay 之间的骨干矩阵。
    Backbone,
    /// 对端上报的它到 relay 的延迟（只有延迟）。
    Reported,
    /// 没有数据。
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn spec(window: Duration, max_probes: u32) -> TestSpec {
        TestSpec { test: 7, peer: node(2), side: Side::Lead, window, max_probes, relays: Vec::new() }
    }

    #[test]
    fn a_window_answers_only_its_peer_inside_its_time_and_count_and_never_the_same_sequence_twice() {
        let now = Instant::now();
        let mut window = Window::new(&spec(Duration::from_secs(10), 3), now);
        assert_eq!(window.screen(node(3), 1, TestPath::Direct, now), Err("来源节点非该测试的目标对端"));
        assert_eq!(window.screen(node(2), 1, TestPath::Direct, now), Ok(()));
        assert_eq!(window.admit(1, TestPath::Direct), Admission::Answer { received: 1 });
        assert_eq!(window.screen(node(2), 1, TestPath::Direct, now), Err("该探测序号已响应"), "重放的探测不回答第二次");
        assert_eq!(window.admit(1, TestPath::Direct), Admission::Refuse("该探测序号已响应"));
        assert_eq!(window.admit(2, TestPath::Direct), Admission::Answer { received: 2 });
        let relayed = TestPath::Relays(RelayPath::new(&[node(9)]).unwrap());
        assert_eq!(window.admit(3, relayed), Admission::Answer { received: 1 }, "每条路径各自数");
        assert_eq!(window.screen(node(2), 4, TestPath::Direct, now), Err("该测试已达到最大响应探测数上限"));
        assert_eq!(window.screen(node(2), 9, TestPath::Direct, now + Duration::from_secs(10)), Err("测试时间窗已过期"));
    }

    #[test]
    fn a_window_is_held_to_the_node_limits_whatever_was_asked() {
        let now = Instant::now();
        let window = Window::new(&spec(Duration::from_secs(3600), u32::MAX), now);
        assert_eq!(window.until, now + MAX_TEST_WINDOW);
        assert_eq!(window.max_probes, MAX_TEST_PROBES);
    }

    #[test]
    fn a_window_takes_only_a_bounded_number_of_paths() {
        let now = Instant::now();
        let mut window = Window::new(&spec(Duration::from_secs(10), 100), now);
        for (seq, relay) in (0..u32::try_from(MAX_TEST_PATHS).unwrap()).zip(10..) {
            let path = TestPath::Relays(RelayPath::new(&[node(relay)]).unwrap());
            assert_eq!(window.screen(node(2), seq, path, now), Ok(()));
            window.admit(seq, path);
        }
        let one_more = TestPath::Relays(RelayPath::new(&[node(99)]).unwrap());
        assert_eq!(window.screen(node(2), 50, one_more, now), Err("该测试的路径数量已达上限"));
        assert_eq!(window.screen(node(2), 50, TestPath::Relays(RelayPath::new(&[node(10)]).unwrap()), now), Ok(()), "已经有的路径照样收");
    }

    #[test]
    fn a_path_reversed_lists_its_relays_backwards() {
        let path = TestPath::Relays(RelayPath::new(&[node(8), node(9)]).unwrap());
        assert_eq!(path.reversed(), TestPath::Relays(RelayPath::new(&[node(9), node(8)]).unwrap()));
        assert_eq!(TestPath::Direct.reversed(), TestPath::Direct);
        assert_eq!(TestPath::from_relays(path.relays()), path);
    }

    fn report(rtts: &[Option<u64>], peer_received: Option<u32>) -> TrainReport {
        TrainReport {
            path: TestPath::Direct,
            sent: u32::try_from(rtts.len()).unwrap(),
            rtts: rtts.iter().map(|rtt| rtt.map(Duration::from_millis)).collect(),
            peer_received,
            same_path: 0,
            interval: 20 * MS,
            duration: Duration::from_secs(2),
            relay_leg: None,
            peer_addr: None,
        }
    }

    #[test]
    fn a_summary_gives_min_average_p95_jitter_and_loss_split_by_direction() {
        // 十个探测：第 3 个去程丢了（对端没收到），第 7 个回程丢了（对端收到了，回答没到）。
        let rtts = [Some(10), Some(12), None, Some(10), Some(14), Some(10), None, Some(10), Some(10), Some(30)];
        let summary = report(&rtts, Some(9)).summary();
        assert_eq!((summary.sent, summary.answered), (10, 8));
        assert_eq!(summary.min_us, Some(10_000));
        assert_eq!(summary.avg_us, Some(13_250));
        assert_eq!(summary.p95_us, Some(30_000), "八个样本的 p95 是最大的那个");
        // 相邻差：2、2、4、4、0、0、20，平均 32/7。
        assert_eq!(summary.jitter_us, Some(4571));
        assert_eq!(summary.loss_permille, 200);
        assert_eq!(summary.loss_up_permille, Some(100), "十个里对端收到九个");
        assert_eq!(summary.loss_down_permille, Some(111), "九个里回来八个");
        assert!(summary.cost_ms(1).unwrap() > 13.25);
    }

    #[test]
    fn a_summary_of_nothing_answered_has_no_numbers_but_full_loss() {
        let summary = report(&[None, None, None], None).summary();
        assert_eq!((summary.answered, summary.min_us, summary.avg_us, summary.p95_us, summary.jitter_us), (0, None, None, None, None));
        assert_eq!((summary.loss_permille, summary.loss_up_permille, summary.loss_down_permille), (1000, None, None));
        assert_eq!(summary.cost_ms(0), None);
        assert_eq!(report(&[], None).summary().loss_permille, 0);
    }

    #[test]
    fn a_train_sends_on_its_schedule_matches_answers_by_sequence_and_waits_for_late_ones() {
        let start = Instant::now();
        let (reply, _answer) = oneshot::channel();
        let spec = TrainSpec { test: 7, peer: node(2), path: TestPath::Direct, count: 3, interval: 20 * MS };
        let mut train = TrainRun::new(spec, 100, start, reply);
        assert_eq!(train.next_due(), Some((0, start)));
        train.sent_at[0] = Some(start);
        assert_eq!(train.next_due(), Some((1, start + 20 * MS)));
        assert_eq!(train.index_of(101), Some(1));
        assert_eq!((train.index_of(99), train.index_of(103)), (None, None), "别的列的序号");
        train.answered(1, start + 30 * MS, MS, 1, true);
        assert_eq!(train.rtts[1], None, "还没发出的探测不会有回答");
        train.sent_at[1] = Some(start + 20 * MS);
        train.sent_at[2] = Some(start + 40 * MS);
        train.answered(1, start + 50 * MS, 2 * MS, 2, true);
        train.answered(1, start + 90 * MS, Duration::ZERO, 2, true);
        assert_eq!(train.rtts[1], Some(28 * MS), "减掉对端的停留；重复的回答不算");
        assert!(!train.is_finished(start + 100 * MS));
        assert_eq!(train.wake_at(), start + 40 * MS + TRAIN_WAIT);
        assert!(train.is_finished(start + 40 * MS + TRAIN_WAIT));
        let report = train.report(start + 40 * MS + TRAIN_WAIT);
        assert_eq!((report.sent, report.same_path, report.peer_received), (3, 1, Some(2)));
    }

    #[test]
    fn a_train_is_held_to_its_limits() {
        let (reply, _answer) = oneshot::channel();
        let spec = TrainSpec { test: 7, peer: node(2), path: TestPath::Direct, count: 10_000, interval: Duration::ZERO };
        let train = TrainRun::new(spec, 0, Instant::now(), reply);
        assert_eq!((train.sent_at.len(), train.spec.interval), (usize::try_from(MAX_TRAIN_PROBES).unwrap(), MIN_TRAIN_INTERVAL));
    }
}
