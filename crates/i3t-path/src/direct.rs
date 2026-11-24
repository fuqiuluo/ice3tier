//! 到一个对端的直连：候选地址、验证、打洞的重试、在用地址的保活。
//!
//! 这里是一台不做 I/O 的状态机：外面告诉它时间和收到了什么，它回答该发什么、直连现在可不可用。
//! 签名和验签都在外面做，交进来的 PING / PONG 都是已经验过签名的。
//!
//! 一个地址要先验证才能用：向它发 PING，收到带着同一个随机数的 PONG。验证过的地址每 5 秒再探测一次，
//! 连续超时或者丢得太多就判为不可用。没有可用地址时按固定的节奏重试：每次尝试向所有候选地址发几轮 PING，
//! 并且发信令请对端同时向本端发，这就是打洞。
//!
//! # 别人能让它做什么
//!
//! - PING 可以被人截下来、从别的地址重放，签名照样是对的。所以只凭收到过 PING 的地址只认很短的一阵
//!   （[`PINGED_TTL`]），本端自己的 PING 在那里得到回答才算真正验证过。
//! - 对端的候选地址来自它自己（netmap 里上报的、信令里带来的），它可以写任何地址。没法发、不该发的地址不记
//!   （回环、组播、广播、链路本地；本节点自己绑在回环上的测试除外），信令引出的探测最多每 [`PUNCH_ATTEMPT`] 一轮，
//!   重试的退避照常推进，所以对端不能让本节点不停地向随便什么地址发探测。
//! - 每个候选地址来的 PING 有自己的验签额度，伪造的 PING 花不掉别的地址的额度。
//! - 局域网信标谁知道对端的公钥都造得出来，所以信标带来的地址只是一个线索（[`DirectPath::on_lan_sighting`]）：
//!   它另占几个名额（[`MAX_SIGHTED`]），挤不掉别处学来的候选；一个信标最多引出一个探测，探测有额度；
//!   重试的节奏、退避和搁置不因为它重来，也不为它发信令；别处也说到这个地址之前，它来的 PING 用不上候选地址自己的验签额度。
//!   公网 IPv4 地址不会因为信标被当成本地网络里的，信标停了一阵之后别的地址也不再算。

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use i3t_model::control::{RouteHint, Signal};
use i3t_proto::session::Nonce;
use i3t_underlay::ifaddr;

use crate::budget::Budget;
use crate::estimate::{Estimate, Quality, Train};
use crate::report::{DirectFailureCause, DirectKind, DirectState, DirectStatus};
use crate::timing::{MAX_TIMEOUTS, PROBE_INTERVAL, PUNCH_ATTEMPT, PUNCH_BACKOFF, PUNCH_IDLE_RETRY, PUNCH_VOLLEYS, Rtt, SILENCE};

/// 一个对端最多记多少个候选地址。对端上报的、信令里带来的、探测里看到的都算。
const MAX_CANDIDATES: usize = 16;
/// 一条信令里最多取多少个端点，多出来的不要。
const MAX_SIGNALLED: usize = 8;
/// 不是对端上报的候选地址多久没有再出现就忘掉；验证过的地址多久没有新的证明就不再认它发来的包。
const CANDIDATE_TTL: Duration = Duration::from_secs(120);
/// 只是收到过对端 PING 的地址，多久之内认它发来的连接包。对端在用这个地址时每 5 秒就有一个保活 PING，
/// 三个间隔够了；别人重放一个旧的 PING，也只能让这个地址被认这么久。
const PINGED_TTL: Duration = Duration::from_secs(15);
/// 一个候选地址来的 PING 每秒最多验多少个签名，最多攒多少个。对端打洞时一轮向本端的每个候选地址各发一个，
/// 三轮在 600ms 里发完，这些都从它的同一个地址来。
const CANDIDATE_VERIFIES_PER_SEC: f64 = 25.0;
const CANDIDATE_VERIFY_BURST: f64 = 50.0;
/// 只在局域网信标里见过的候选地址最多记多少个。对端在本节点的网段上一般只有一两个地址（每块网卡上 IPv4、IPv6 各一个）。
/// 信标造得再多，也只在这几个名额里互相挤。
const MAX_SIGHTED: usize = 4;
/// 多久没有再看到信标，一个地址就不再算是在本地网段上看到的。信标每 10 秒一个。
const SIGHTING_TTL: Duration = Duration::from_secs(60);
/// 信标引出的探测，一个对端每秒最多几个、最多攒几个。对端的每个地址每 10 秒才有一个信标。
const SIGHTING_PROBES_PER_SEC: f64 = 1.0;
const SIGHTING_PROBE_BURST: f64 = 4.0;
/// 发出去的 PING 等多久还没有回答就不再等。比一次打洞尝试长，晚到的 PONG 照样算数。
const PENDING_TTL: Duration = Duration::from_secs(5);
const MAX_PENDING: usize = 64;
/// 丢包率按最近这么多次保活探测算。原来是 10 次，丢 3 个就下结论：真实链路上量过，一条丢包 3%～5%、成串地丢的直连，
/// 一小时里被判成"丢包超过 20%"19 回。
const LOSS_WINDOW: usize = 30;
/// 窗口里丢的超过这么多个（20%）就判为不可用。不等窗口填满：丢得多的路几十秒里就够数了。
const MAX_LOSSES: usize = LOSS_WINDOW / 5;
/// 同一个地址上，对端的 PING 引出的反向验证最多这么频繁。重放一个旧的 PING 没法让本端发得更多。
const REVERSE_PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// 两条信令通道（controller、连接里）会把同一个打洞请求各送来一份，这么短的时间里的第二份不再处理。
const REQUEST_DEDUP: Duration = Duration::from_millis(300);
/// 对端不活跃时，验证过的地址多久没有新的证明就丢掉。
const STALE: Duration = Duration::from_secs(30);

/// 外面决定的、这个对端此刻适用的限制。
#[derive(Debug, Clone, Copy)]
pub(crate) struct Policy<'a> {
    /// 现在需要到这个对端的直连：它是活跃的（或者网络小，不等流量就试，见 `crate::control` 的 `EAGER_DIRECT_PEERS`），
    /// 并且没有禁用直连。
    pub(crate) wanted: bool,
    /// 可以由本端主动去探测它的候选地址。对端是只主动连接的节点时不行：它不理陌生的探测，只能等它来找本端。
    pub(crate) initiate: bool,
    /// 可以和它互发打洞信令。任何一方只主动连接时不行。
    pub(crate) signal: bool,
    /// 有包发给它，却有一阵没有从直连上收到它的包了。
    pub(crate) silent: bool,
    /// 本节点自己的候选端点，放进信令里告诉对端。
    pub(crate) local: &'a [SocketAddr],
    /// 直连是正在评估的候选路径（延迟优先模式）：给在用的地址定期发探测包列来估丢包。
    pub(crate) train: bool,
}

/// 要外面去做的事。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// 向 `to` 发一个带这个随机数的 PING。
    Ping { to: SocketAddr, nonce: Nonce },
    /// 把这条信令送给对端。
    Signal(Signal),
}

/// 直连的可用状态变了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Change {
    /// `addr` 验证通过，从现在起可以往它发连接的包。也可能是从一个已验证的地址换到了另一个。
    Up {
        addr: SocketAddr,
    },
    Down {
        reason: DownReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownReason {
    /// 探测连续超时。
    Timeouts,
    /// 最近的探测丢了超过 20%。
    Loss,
    /// 对端不活跃了，地址也很久没有验证过。
    Stale,
}

impl DownReason {
    /// 直连因此断了时，换路的起因。
    pub(crate) const fn hint(self) -> RouteHint {
        match self {
            Self::Timeouts => RouteHint::DirectTimeouts,
            Self::Loss => RouteHint::DirectLoss,
            Self::Stale => RouteHint::DirectStale,
        }
    }

    /// 给界面看的"直连上一次为什么没有成"。
    const fn failure(self) -> DirectFailureCause {
        match self {
            Self::Timeouts => DirectFailureCause::Timeouts,
            Self::Loss => DirectFailureCause::Loss,
            Self::Stale => DirectFailureCause::Stale,
        }
    }
}

/// [`DirectPath::poll`] 的结果。
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) actions: Vec<Action>,
    pub(crate) change: Option<Change>,
}

#[derive(Debug)]
struct Candidate {
    addr: SocketAddr,
    /// 在对端上报的端点里（netmap）。
    reported: bool,
    /// 最近一次从任何来源得知这个地址。
    refreshed: Instant,
    /// 最近一次本端发往这个地址的 PING 得到了对端签了名的回答。
    proven: Option<Instant>,
    /// 最近一次从这个地址收到对端签了名的 PING。
    pinged: Option<Instant>,
    /// 最近一次在本地网段上看到对端从这个地址发的信标。[`SIGHTING_TTL`] 里没有再看到就清掉。
    sighted: Option<Instant>,
    /// 只在信标里见过：对端没有上报它，信令里没有它，也没有从它收到过对端签了名的探测或者回答。
    sighted_only: bool,
    /// 最近一次本端往这个地址发探测。
    probed: Option<Instant>,
    /// 最近一次因为收到对端从这个地址来的 PING 而反过来验证它（每个地址最多每 [`REVERSE_PROBE_INTERVAL`] 一次）。
    reverse_probed: Option<Instant>,
    /// 最近一次对端从这个地址"不请自来"地探测本端：那时本端没有往这个地址发过东西，也没有在打洞的那一轮里。
    /// 这说明本端的地址本来就连得上，这条路不用打洞也建得起来（见 [`DirectPath::kind`]）。
    unsolicited: Option<Instant>,
    /// 这个地址来的 PING 的验签额度。
    budget: Budget,
}

impl Candidate {
    fn new(addr: SocketAddr, sighted_only: bool, now: Instant) -> Self {
        Self {
            addr,
            reported: false,
            refreshed: now,
            proven: None,
            pinged: None,
            sighted: None,
            sighted_only,
            probed: None,
            reverse_probed: None,
            unsolicited: None,
            budget: Budget::new(CANDIDATE_VERIFIES_PER_SEC, CANDIDATE_VERIFY_BURST, now),
        }
    }
}

#[derive(Debug)]
struct Pending {
    nonce: Nonce,
    addr: SocketAddr,
    sent: Instant,
    /// 发这个探测的时候，正在打洞的那一轮里：刚从对端收到过打洞信令。它得到回答的话，这条直连算是打洞打通的
    /// （除非对端先不请自来地探测过本端，见 [`Candidate::unsolicited`]）；不然就是对端的地址本来就连得上。
    coordinated: bool,
}

#[derive(Debug)]
struct Active {
    addr: SocketAddr,
    rtt: Rtt,
    /// 最近一次得到回答。
    confirmed: Instant,
    last_probe: Instant,
    /// 在等回答的那个保活探测是什么时候发的。
    awaiting: Option<Instant>,
    timeouts: u8,
    /// 最近几次保活探测是不是丢了。
    history: VecDeque<bool>,
    /// 给选路用的延迟、抖动和丢包估计。保活和探测包列的结果都记在这里。
    estimate: Estimate,
    train: Train,
    /// 这个地址是和对端协调之后才打通的。
    punched: bool,
    /// 这个地址验证通过的时刻。
    since: Instant,
}

impl Active {
    fn new(addr: SocketAddr, sample: Duration, punched: bool, now: Instant) -> Self {
        let mut estimate = Estimate::new();
        estimate.sample(sample, now);
        Self {
            addr,
            rtt: Rtt::new(sample),
            confirmed: now,
            last_probe: now,
            awaiting: None,
            timeouts: 0,
            history: VecDeque::new(),
            estimate,
            train: Train::new(),
            punched,
            since: now,
        }
    }

    fn record(&mut self, lost: bool) {
        if self.history.len() == LOSS_WINDOW {
            self.history.pop_front();
        }
        self.history.push_back(lost);
    }

    fn too_lossy(&self) -> bool {
        self.history.iter().filter(|&&lost| lost).count() > MAX_LOSSES
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Punch {
    /// 下一次 `poll` 就开始第一次尝试。
    Idle,
    /// 第 `round` 次重试（0 是头一次）正在进行，已经发了 `volleys` 轮探测。
    Attempt { round: usize, started: Instant, volleys: usize },
    /// 第 `round` 次尝试失败了，等到 `until` 再试。
    Backoff { round: usize, until: Instant },
    /// 一整轮都失败了。之后候选地址有变化就立刻重来，否则到 `retry_at` 再试一次。
    Exhausted { retry_at: Instant },
    /// 在用的地址 `addr` 丢包太多，被判为不可用。它多半一直答得上来，所以到 `until` 之前它再有回答也不用它，
    /// 之后才再试一次；候选地址有变化照样立刻重来，别的地址这期间验证通过了照样用。
    Shunned { addr: SocketAddr, until: Instant },
}

/// 到一个对端的直连状态。
#[derive(Debug)]
pub(crate) struct DirectPath {
    candidates: Vec<Candidate>,
    pending: VecDeque<Pending>,
    active: Option<Active>,
    punch: Punch,
    last_request: Option<Instant>,
    /// 最近一次从对端收到打洞信令。
    signalled: Option<Instant>,
    /// 最近一次本端发打洞请求。
    requested: Option<Instant>,
    /// 两边的公网地址相同：对端的私有地址多半和本节点在同一个局域网里。
    same_nat: bool,
    /// 上一次因为信令立刻发一轮探测的时刻。
    signal_volley: Option<Instant>,
    /// 信标引出的探测的额度。看到头一个信标时才有。
    sighting_probes: Option<Budget>,
    /// 回环地址可以当候选：本节点自己就绑在回环上（测试里几个节点在同一台机器上）。
    loopback: bool,
    /// 最近一次尝试开始的时刻，和最近一次失败的原因：只记下来给界面看（[`DirectPath::status`]），不影响什么时候去试。
    attempted: Option<Instant>,
    failure: Option<DirectFailureCause>,
}

impl DirectPath {
    pub(crate) const fn new() -> Self {
        Self {
            candidates: Vec::new(),
            pending: VecDeque::new(),
            active: None,
            punch: Punch::Idle,
            last_request: None,
            signalled: None,
            requested: None,
            same_nat: false,
            signal_volley: None,
            sighting_probes: None,
            loopback: false,
            attempted: None,
            failure: None,
        }
    }

    /// 本节点的端口绑在 `local` 上时用的。绑在回环上时，对端的回环地址也可以当候选；否则那是本节点自己的回环，不该往那里发。
    pub(crate) fn for_port(local: SocketAddr) -> Self {
        Self { loopback: local.ip().is_loopback(), ..Self::new() }
    }

    /// 在用的地址上测到的延迟、抖动和丢包。没有在用的地址，或者估计过期了，是 `None`。
    pub(crate) fn quality(&self, now: Instant) -> Option<Quality> {
        self.active.as_ref().and_then(|active| active.estimate.quality(now))
    }

    /// 在用的直连是怎么建立起来的。
    ///
    /// `Punched` 说的是这条路要两边在打洞的那一轮里同时发才通，`Reachable` 是不用：本端的探测在打洞之前就得到了回答
    /// （对端的地址本来就连得上），或者对端在打洞之前就探测到了本端（本端的地址本来就连得上）。两端各自按自己看到的判断，
    /// 一边先探测到另一边时两端说的都是 `Reachable`。还会不一样的情形只有一种：打洞信令比对端的探测先到，本端已经在那一轮里
    /// 发了探测，这时本端说 `Punched`；它只说明两边是在同一轮里碰上的，不说明谁的地址连不上。
    pub(crate) fn kind(&self) -> Option<DirectKind> {
        let active = self.active.as_ref()?;
        Some(if self.is_lan(active.addr) {
            DirectKind::Lan
        } else if active.addr.ip().to_canonical().is_ipv6() {
            DirectKind::Ipv6
        } else if active.punched {
            DirectKind::Punched
        } else {
            DirectKind::Reachable
        })
    }

    /// 直连现在在哪一步，给界面看：读的是尝试和退避的状态，不改它们。
    pub(crate) fn status(&self, now: Instant) -> DirectStatus {
        let state = match (self.kind(), self.punch, self.failure) {
            (Some(_), _, _) => DirectState::Verified,
            (None, Punch::Attempt { .. }, _) => DirectState::Trying,
            (None, Punch::Idle | Punch::Backoff { .. } | Punch::Exhausted { .. } | Punch::Shunned { .. }, Some(_)) => DirectState::Failed,
            (None, Punch::Idle | Punch::Backoff { .. } | Punch::Exhausted { .. } | Punch::Shunned { .. }, None) => DirectState::NotTried,
        };
        let attempted_ms = self.attempted.map(|at| u64::try_from(now.saturating_duration_since(at).as_millis()).unwrap_or(u64::MAX));
        let failure = if state == DirectState::Verified { None } else { self.failure };
        DirectStatus { state, kind: self.kind(), failure, attempted_ms }
    }

    /// 在用的直连是不是局域网直连。两种模式下它都无条件优先。
    pub(crate) fn is_lan_active(&self) -> bool {
        self.active.as_ref().is_some_and(|active| self.is_lan(active.addr))
    }

    /// `addr` 是不是对端在本节点所在局域网里的地址：它是私有地址，并且要么对端的信标就是在本地网段上从它发来的，
    /// 要么两边的公网地址相同。只凭"是私有地址"不算：两个不相干的网络可以用同一个私有网段。
    fn is_lan(&self, addr: SocketAddr) -> bool {
        ifaddr::is_private(addr.ip()) && (self.same_nat || self.came_from_beacon(addr))
    }

    fn came_from_beacon(&self, addr: SocketAddr) -> bool {
        self.candidates.iter().any(|candidate| candidate.addr == addr && candidate.sighted.is_some())
    }

    /// 到 `addr` 的包是不是不经过地址转换：它是私有地址，或者是从局域网信标里得知的（公网 IPv4 地址不会是，
    /// 见 [`on_lan_sighting`](Self::on_lan_sighting)）。这样的地址上的对端看到的本节点地址，应该就是本节点网卡上的地址。
    pub(crate) fn is_local_network(&self, addr: SocketAddr) -> bool {
        ifaddr::is_private(addr.ip()) || self.came_from_beacon(addr)
    }

    /// `from` 是这个对端的候选地址时，从它的验签额度里扣一次，返回扣没扣到；不是候选地址返回 `None`。
    /// 只在信标里见过的地址不算候选地址：信标谁都造得出来，凭它拿不到一份自己的额度。
    pub(crate) fn charge(&mut self, from: SocketAddr, now: Instant) -> Option<bool> {
        self.candidate_mut(from).filter(|candidate| !candidate.sighted_only).map(|candidate| candidate.budget.take(now))
    }

    /// 本节点和对端是不是在同一个 NAT 后面（两边上报的公网地址里有相同的 IP）。
    pub(crate) const fn set_same_nat(&mut self, same_nat: bool) {
        self.same_nat = same_nat;
    }

    /// 在本地网段上看到了对端的信标，来源是 `addr`。它成为一个候选地址，照样要验证过才用。返回要不要马上向它发一个探测。
    ///
    /// 信标谁知道对端的公钥都造得出来，所以它能引起的只有这些：占信标自己的一个名额
    /// （[`learn_sighted`](Self::learn_sighted)），引出最多一个探测（有额度），让这个地址在 [`SIGHTING_TTL`] 里算作本地网段上的。
    /// 重试的节奏不因为它重来，也不为它发信令：局域网里不用打洞，两边各自看到对方的信标、各发一个探测就通了；
    /// 没有通的话，这个地址也在之后每一次尝试的那几轮探测里。
    pub(crate) fn on_lan_sighting(&mut self, addr: SocketAddr, now: Instant, policy: &Policy<'_>) -> Option<Action> {
        // IPv4 的信标只从私有地址发。公网 IPv4 地址不能因为一个信标就被当成不经过地址转换的：在地址转换后面的节点，
        // 对端看到的是它的公网地址，那样一来对端的回答就再也对不上了。
        let ip = addr.ip().to_canonical();
        if ip.is_ipv4() && !ifaddr::is_private(ip) {
            return None;
        }
        if !self.learn_sighted(addr, now) {
            return None;
        }
        self.candidate_mut(addr)?.sighted = Some(now);
        // 有地址在用时不为它另发。还没有开始试的也不用：下一次推进就从头尝试，那一轮探测里有它。
        let due = policy.wanted && policy.initiate && self.active.is_none() && self.punch != Punch::Idle;
        if !due || self.is_shunned(addr, now) {
            return None;
        }
        let budget = self.sighting_probes.get_or_insert_with(|| Budget::new(SIGHTING_PROBES_PER_SEC, SIGHTING_PROBE_BURST, now));
        if !budget.take(now) {
            return None;
        }
        let coordinated = self.signalled_recently(now);
        Some(self.probe(addr, coordinated, now))
    }

    /// 在用的直连地址和到它的延迟。
    pub(crate) fn active(&self) -> Option<(SocketAddr, Rtt)> {
        self.active.as_ref().map(|active| (active.addr, active.rtt))
    }

    /// 在用的直连是什么时候验证通过的。
    pub(crate) fn established_at(&self) -> Option<Instant> {
        self.active.as_ref().map(|active| active.since)
    }

    /// 手上有几个对端的候选地址。
    pub(crate) fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// 主动测试要试一次直连：没有可用的直连时不等退避，下一次推进就从头尝试。
    /// 和候选地址变了时的做法一样，之前的失败记录不再算数。
    pub(crate) fn retry_now(&mut self) {
        self.candidates_changed();
    }

    /// 在用的地址是不是可疑：有保活探测没有得到回答。
    pub(crate) fn in_doubt(&self) -> bool {
        self.active.as_ref().is_some_and(|active| active.timeouts > 0)
    }

    /// 可以认作"这个对端发来的连接包"的来源地址：本端验证过的，加上刚收到过对端签了名的 PING 的。
    ///
    /// 后一种是为了对端先验证完、先改走直连的时候：它的包会比本端的反向验证早到一步。PING 可以被人重放，
    /// 所以这种地址只认 [`PINGED_TTL`] 那么久；同一个地址还被别的对端认领时谁优先，由收包表那边决定。
    pub(crate) fn sources(&self, now: Instant) -> impl Iterator<Item = SocketAddr> + '_ {
        let within = move |at: Option<Instant>, ttl: Duration| at.is_some_and(|at| now.saturating_duration_since(at) < ttl);
        let fresh = move |candidate: &&Candidate| within(candidate.proven, CANDIDATE_TTL) || within(candidate.pinged, PINGED_TTL);
        self.candidates.iter().filter(fresh).map(|candidate| candidate.addr)
    }

    /// netmap 里对端上报的端点。每次 netmap 更新都调用。返回里面有没有新的候选地址。
    pub(crate) fn set_reported(&mut self, endpoints: &[SocketAddr], now: Instant) -> bool {
        for candidate in &mut self.candidates {
            candidate.reported = endpoints.contains(&candidate.addr);
        }
        let mut appeared = false;
        for &addr in endpoints.iter().take(MAX_CANDIDATES) {
            appeared |= self.learn(addr, now);
            if let Some(candidate) = self.candidate_mut(addr) {
                candidate.reported = true;
            }
        }
        if appeared {
            self.candidates_changed();
        }
        appeared
    }

    /// 本节点自己的候选端点变了（换了网络、拿到了新的反射地址）。
    pub(crate) fn local_changed(&mut self) {
        self.candidates_changed();
    }

    /// 对端发来打洞信令。返回要发的东西：对请求的回答，以及立刻向它的候选地址发的一轮探测。
    pub(crate) fn on_signal(&mut self, signal: &Signal, now: Instant, policy: &Policy<'_>) -> Vec<Action> {
        if !policy.signal {
            return Vec::new();
        }
        let (endpoints, is_request) = match signal {
            Signal::PunchRequest { endpoints } => (endpoints, true),
            Signal::PunchReply { endpoints } => (endpoints, false),
        };
        if is_request {
            if self.last_request.is_some_and(|last| now.saturating_duration_since(last) < REQUEST_DEDUP) {
                return Vec::new();
            }
            self.last_request = Some(now);
        }
        for &addr in endpoints.iter().take(MAX_SIGNALLED) {
            self.learn(addr, now);
        }
        self.signalled = Some(now);
        let mut actions = Vec::new();
        if is_request {
            actions.push(Action::Signal(Signal::PunchReply { endpoints: policy.local.to_vec() }));
        }
        // 信令引出的探测最多每 `PUNCH_ATTEMPT` 一轮：对端发多少信令，本节点也只按一次尝试的节奏发。
        let volley_due = self.signal_volley.is_none_or(|at| now.saturating_duration_since(at) >= PUNCH_ATTEMPT);
        // 丢包太多、正搁着不用的那一阵里不跟着对端的信令去试：那个地址试通了也不用。对端换了地址的话，
        // 它的探测会从新地址来，照样引出反向验证（见 `on_ping`）。
        let shunning = matches!(self.punch, Punch::Shunned { until, .. } if now < until);
        if self.active.is_none() && volley_due && !shunning {
            // 对端此刻正在向本端发探测。本端也立刻发，并把这一次尝试的节奏对齐到现在，后面两轮跟着来。
            let round = match self.punch {
                Punch::Idle => 0,
                Punch::Attempt { round, started, .. } if now.saturating_duration_since(started) < PUNCH_ATTEMPT => round,
                // 上一次已经失败了（或者正好到了判为失败的时候），这是下一次：退避照常推进，
                // 信令不会让本节点一直停在同一档上。
                Punch::Attempt { round, .. } | Punch::Backoff { round, .. } => round + 1,
                Punch::Exhausted { .. } | Punch::Shunned { .. } => PUNCH_BACKOFF.len(),
            };
            self.signal_volley = Some(now);
            self.punch = Punch::Attempt { round, started: now, volleys: 1 };
            self.attempted = Some(now);
            actions.extend(self.volley(now));
        }
        actions
    }

    /// 从 `from` 收到了对端的 PING（签名已经验过，PONG 由外面去回）。返回要不要向 `from` 发一个反方向的 PING。
    pub(crate) fn on_ping(&mut self, from: SocketAddr, now: Instant) -> Option<Action> {
        self.learn(from, now);
        let quiet = |at: Option<Instant>| at.is_none_or(|at| now.saturating_duration_since(at) >= PENDING_TTL);
        let in_round = !quiet(self.signalled);
        // 反向验证得到回答，靠的是对端刚从这个地址往本端发过探测。本端发过打洞请求的话，那个探测多半就是对端照着请求发的：
        // 这样打通的路算打洞打通的，和收到过对端的信令一样（见 [`Pending::coordinated`]）。
        let coordinated = in_round || !quiet(self.requested);
        let in_use = self.active.as_ref().is_some_and(|active| active.addr == from);
        let shunned = self.is_shunned(from, now);
        // 没法发、不该发的地址，或者候选记满了挤不进来的地址，不反过来验证：本端只认候选地址来的连接包，
        // 那里验证通过了也用不上。反向验证的时刻记在候选地址上，要记的东西也就有上限。
        let candidate = self.candidate_mut(from)?;
        candidate.pinged = Some(now);
        if !in_round && quiet(candidate.probed) {
            candidate.unsolicited = Some(now);
        }
        if in_use {
            return None;
        }
        // 这个地址正因为丢包搁着不用：验证通过了也不会用，不白发。它发来的包照样认（上面记了 `pinged`）。
        if shunned {
            return None;
        }
        // 按地址记上一次反向验证的时刻，不看在等回答的探测：回答一到那条记录就没了，两边之间通着两个地址时，
        // 不在用的那个地址上会你一个我一个地一直互相验证下去。本端自己发起的探测也不算：它可能已经丢了
        // （对端那时还不认识本端，或者被它的 NAT 挡掉），等它的下一轮要 300ms。这期间对端先验证通过、先拨号，
        // 它的握手要等到本端也有路才得到应答，那条连接从一开头就把往返时间量成几百毫秒。
        if candidate.reverse_probed.is_some_and(|at| now.saturating_duration_since(at) < REVERSE_PROBE_INTERVAL) {
            return None;
        }
        candidate.reverse_probed = Some(now);
        Some(self.probe(from, coordinated, now))
    }

    /// 是不是向 `from` 发过带这个随机数的 PING、还在等回答。验 PONG 的签名之前先问这个，不花冤枉的计算。
    pub(crate) fn expects_pong(&self, from: SocketAddr, nonce: &Nonce) -> bool {
        self.pending.iter().any(|pending| pending.nonce == *nonce && pending.addr == from)
            || self.active.as_ref().is_some_and(|active| active.addr == from && active.train.expects(nonce))
    }

    /// 从 `from` 收到了对端的 PONG（签名已经验过）。随机数对不上发往 `from` 的任何一个 PING 时不算数。
    pub(crate) fn on_pong(&mut self, from: SocketAddr, nonce: &Nonce, now: Instant) -> Option<Change> {
        // 探测包列里的回答只用来估丢包和延迟，也算这个地址还活着的证明。
        if let Some(active) = &mut self.active
            && active.addr == from
            && active.train.on_reply(nonce, now, &mut active.estimate)
        {
            active.confirmed = now;
            self.prove(from, now);
            return None;
        }
        let index = self.pending.iter().position(|pending| pending.nonce == *nonce && pending.addr == from)?;
        let answered = self.pending.remove(index)?;
        let sample = now.saturating_duration_since(answered.sent);
        // 探测发出去之后，这个地址可能被别的候选挤掉了。对端签了名的回答是它最硬的证明，重新记上；
        // 记不上（表里全是对端上报的地址）就不用它：收包只认候选地址来的。
        self.learn(from, now);
        self.candidate_mut(from)?.proven = Some(now);
        let shunned = self.is_shunned(from, now);
        match &mut self.active {
            Some(active) if active.addr == from => {
                active.rtt.update(sample);
                active.estimate.sample(sample, now);
                active.confirmed = now;
                active.timeouts = 0;
                if active.awaiting.take().is_some() {
                    active.record(false);
                }
                None
            }
            // 局域网直连无条件优先：已经在用公网地址时，局域网地址验证通过就换过去。别的情况先到先得。
            Some(active) if !ifaddr::is_private(from.ip()) || ifaddr::is_private(active.addr.ip()) => None,
            // 丢包太多刚搁下的地址：搁下之前发出去的探测这时才答回来，不算数。
            None if shunned => None,
            Some(_) | None => {
                let unsolicited = self.candidates.iter().any(|candidate| {
                    candidate.addr == from && candidate.unsolicited.is_some_and(|at| now.saturating_duration_since(at) < PENDING_TTL)
                });
                self.active = Some(Active::new(from, sample, answered.coordinated && !unsolicited, now));
                self.punch = Punch::Idle;
                self.failure = None;
                Some(Change::Up { addr: from })
            }
        }
    }

    /// 推进定时器。隔一小段时间调用一次。
    pub(crate) fn poll(&mut self, now: Instant, policy: &Policy<'_>) -> Step {
        let mut step = Step::default();
        self.expire(now);
        if !policy.wanted {
            self.punch = Punch::Idle;
            if self.active.as_ref().is_some_and(|active| now.saturating_duration_since(active.confirmed) > STALE) {
                self.active = None;
                self.failure = Some(DownReason::Stale.failure());
                step.change = Some(Change::Down { reason: DownReason::Stale });
            }
            return step;
        }
        if self.active.is_some() {
            self.maintain(now, policy, &mut step);
        }
        if self.active.is_none() && policy.initiate {
            self.punch(now, policy, &mut step);
        }
        step
    }

    /// 给在用的地址保活，判断它还能不能用。
    fn maintain(&mut self, now: Instant, policy: &Policy<'_>, step: &mut Step) {
        let Some(active) = &mut self.active else { return };
        let since_probe = now.saturating_duration_since(active.last_probe);
        let due = match active.awaiting {
            Some(sent) if now.saturating_duration_since(sent) < active.rtt.probe_timeout() => false,
            Some(_) => {
                active.awaiting = None;
                active.timeouts += 1;
                active.record(true);
                active.estimate.lost();
                let verdict = if active.timeouts >= MAX_TIMEOUTS {
                    Some(DownReason::Timeouts)
                } else if active.too_lossy() {
                    Some(DownReason::Loss)
                } else {
                    None
                };
                if let Some(reason) = verdict {
                    let addr = active.addr;
                    self.active = None;
                    self.failure = Some(reason.failure());
                    // 路是断了的话马上从头重试；只是丢包多的话它多半还能验证通过，立刻重试只会来回切，所以搁一阵再说。
                    // 搁着的时候它有回答也不用：对端的直连多半还在，它每 5 秒一个保活 PING 引出本端的反向验证，
                    // 真实链路上就是这样把刚判掉的直连两三秒之后又拉了回来。
                    self.punch = match reason {
                        DownReason::Loss => Punch::Shunned { addr, until: now + PUNCH_IDLE_RETRY },
                        DownReason::Timeouts | DownReason::Stale => Punch::Idle,
                    };
                    step.change = Some(Change::Down { reason });
                    return;
                }
                // 超时之后不等下一个探测间隔，立刻再问。
                true
            }
            None => since_probe >= PROBE_INTERVAL || (policy.silent && since_probe >= SILENCE),
        };
        if due {
            let addr = active.addr;
            active.awaiting = Some(now);
            active.last_probe = now;
            let coordinated = self.signalled_recently(now);
            step.actions.push(self.probe(addr, coordinated, now));
        } else if let Some(nonce) = active.train.poll(now, policy.train, active.rtt.probe_timeout(), &mut active.estimate) {
            step.actions.push(Action::Ping { to: active.addr, nonce });
        }
    }

    /// 没有可用地址时按节奏重试。
    fn punch(&mut self, now: Instant, policy: &Policy<'_>, step: &mut Step) {
        self.punch = match self.punch {
            Punch::Idle => Punch::Attempt { round: 0, started: now, volleys: 0 },
            Punch::Backoff { round, until } if now >= until => Punch::Attempt { round: round + 1, started: now, volleys: 0 },
            Punch::Exhausted { retry_at } if now >= retry_at => Punch::Attempt { round: PUNCH_BACKOFF.len(), started: now, volleys: 0 },
            Punch::Shunned { until, .. } if now >= until => Punch::Attempt { round: PUNCH_BACKOFF.len(), started: now, volleys: 0 },
            waiting @ (Punch::Attempt { .. } | Punch::Backoff { .. } | Punch::Exhausted { .. } | Punch::Shunned { .. }) => waiting,
        };
        let Punch::Attempt { round, started, volleys } = self.punch else { return };
        if started == now && volleys == 0 {
            // 这一次尝试是刚才开始的（从空闲、退避或者整轮失败里出来）。
            self.attempted = Some(now);
        }
        let elapsed = now.saturating_duration_since(started);
        if PUNCH_VOLLEYS.get(volleys).is_some_and(|&at| elapsed >= at) {
            if volleys == 0 && policy.signal {
                self.requested = Some(now);
                step.actions.push(Action::Signal(Signal::PunchRequest { endpoints: policy.local.to_vec() }));
            }
            step.actions.extend(self.volley(now));
            self.punch = Punch::Attempt { round, started, volleys: volleys + 1 };
        }
        if elapsed >= PUNCH_ATTEMPT {
            self.failure = Some(if self.candidates.is_empty() { DirectFailureCause::NoCandidates } else { DirectFailureCause::NoAnswer });
            self.punch = match PUNCH_BACKOFF.get(round) {
                Some(&wait) => Punch::Backoff { round, until: now + wait },
                None => Punch::Exhausted { retry_at: now + PUNCH_IDLE_RETRY },
            };
        }
    }

    /// 向每个候选地址发一个 PING。
    fn volley(&mut self, now: Instant) -> Vec<Action> {
        let targets: Vec<SocketAddr> = self.candidates.iter().map(|candidate| candidate.addr).collect();
        let coordinated = self.signalled_recently(now);
        targets.into_iter().map(|addr| self.probe(addr, coordinated, now)).collect()
    }

    /// 刚从对端收到过打洞信令：现在发的探测在打洞的那一轮里。
    fn signalled_recently(&self, now: Instant) -> bool {
        self.signalled.is_some_and(|signalled| now.saturating_duration_since(signalled) < PENDING_TTL)
    }

    fn probe(&mut self, to: SocketAddr, coordinated: bool, now: Instant) -> Action {
        let nonce: Nonce = i3t_underlay::random_bytes();
        if self.pending.len() == MAX_PENDING {
            self.pending.pop_front();
        }
        if let Some(candidate) = self.candidate_mut(to) {
            candidate.probed = Some(now);
        }
        self.pending.push_back(Pending { nonce, addr: to, sent: now, coordinated });
        Action::Ping { to, nonce }
    }

    /// 能不能往 `addr` 发探测。对端可以在上报的端点和信令里写任何地址，没法发、不该发的不记。
    ///
    /// 私有地址照样收：两个节点可能在同一个局域网里，也可能经站点之间的隧道用私有地址互通，这里分不出来。
    fn can_probe(&self, addr: SocketAddr) -> bool {
        let ip = addr.ip().to_canonical();
        let unusable = match ip {
            IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_link_local(),
            IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_unicast_link_local(),
        };
        addr.port() != 0 && !unusable && (self.loopback || !ip.is_loopback())
    }

    /// 记下一个候选地址。返回它是不是新的：原来没有，或者原来只在信标里见过。
    fn learn(&mut self, addr: SocketAddr, now: Instant) -> bool {
        if !self.can_probe(addr) {
            return false;
        }
        if let Some(candidate) = self.candidate_mut(addr) {
            candidate.refreshed = now;
            // 别处也说到了它，不再只是信标里的线索。头一次这样说到时，和新来的一个候选一样算：
            // 信标先到一步，不该让对端上报这个地址时少了"候选变了、立刻重试"的那一下。
            return std::mem::replace(&mut candidate.sighted_only, false);
        }
        if self.candidates.len() >= MAX_CANDIDATES {
            // 满了就挤掉一个：先挤只在信标里见过的，没有了再挤最久没有出现的；对端上报的和在用的不动。
            let active = self.active.as_ref().map(|active| active.addr);
            let evictable =
                self.candidates.iter().enumerate().filter(|(_, candidate)| !candidate.reported && Some(candidate.addr) != active);
            let Some((oldest, _)) = evictable.min_by_key(|(_, candidate)| (!candidate.sighted_only, candidate.refreshed)) else {
                return false;
            };
            self.candidates.swap_remove(oldest);
        }
        self.candidates.push(Candidate::new(addr, false, now));
        true
    }

    /// 记下信标里来的地址。返回记没记下，本来就有也算。
    ///
    /// 新的地址只占信标自己的名额：名额满了、或者整张表满了，挤掉的也只是另一个只在信标里见过的地址（最久没有出现的那个），
    /// 没有可挤的就不记。对端上报的、信令和探测里来的候选不会被它挤掉。
    fn learn_sighted(&mut self, addr: SocketAddr, now: Instant) -> bool {
        if !self.can_probe(addr) {
            return false;
        }
        if let Some(candidate) = self.candidate_mut(addr) {
            candidate.refreshed = now;
            return true;
        }
        let sighted_only = self.candidates.iter().filter(|candidate| candidate.sighted_only).count();
        if sighted_only >= MAX_SIGHTED || self.candidates.len() >= MAX_CANDIDATES {
            let active = self.active.as_ref().map(|active| active.addr);
            let evictable =
                self.candidates.iter().enumerate().filter(|(_, candidate)| candidate.sighted_only && Some(candidate.addr) != active);
            let Some((oldest, _)) = evictable.min_by_key(|(_, candidate)| candidate.refreshed) else { return false };
            self.candidates.swap_remove(oldest);
        }
        self.candidates.push(Candidate::new(addr, true, now));
        true
    }

    fn prove(&mut self, addr: SocketAddr, now: Instant) {
        if let Some(candidate) = self.candidate_mut(addr) {
            candidate.proven = Some(now);
        }
    }

    fn candidate_mut(&mut self, addr: SocketAddr) -> Option<&mut Candidate> {
        self.candidates.iter_mut().find(|candidate| candidate.addr == addr)
    }

    /// `addr` 是不是因为丢包太多正搁着不用（见 [`Punch::Shunned`]）。
    fn is_shunned(&self, addr: SocketAddr, now: Instant) -> bool {
        matches!(self.punch, Punch::Shunned { addr: shunned, until } if shunned == addr && now < until)
    }

    /// 任何一方的候选端点变了：之前的失败记录清掉，立刻重新尝试。
    fn candidates_changed(&mut self) {
        if self.active.is_none() {
            self.punch = Punch::Idle;
        }
    }

    fn expire(&mut self, now: Instant) {
        while self.pending.front().is_some_and(|pending| now.saturating_duration_since(pending.sent) > PENDING_TTL) {
            self.pending.pop_front();
        }
        let active = self.active.as_ref().map(|active| active.addr);
        self.candidates.retain(|candidate| {
            candidate.reported || Some(candidate.addr) == active || now.saturating_duration_since(candidate.refreshed) < CANDIDATE_TTL
        });
        for candidate in &mut self.candidates {
            if candidate.sighted.is_some_and(|at| now.saturating_duration_since(at) >= SIGHTING_TTL) {
                candidate.sighted = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn policy(local: &[SocketAddr]) -> Policy<'_> {
        Policy { wanted: true, initiate: true, signal: true, silent: false, local, train: false }
    }

    fn pings(actions: &[Action]) -> Vec<(SocketAddr, Nonce)> {
        actions.iter().filter_map(|action| if let Action::Ping { to, nonce } = action { Some((*to, *nonce)) } else { None }).collect()
    }

    fn signals(actions: &[Action]) -> Vec<&Signal> {
        actions.iter().filter_map(|action| if let Action::Signal(signal) = action { Some(signal) } else { None }).collect()
    }

    /// 一条已经验证通过的直连，返回它和验证通过的时刻。
    fn established(peer: SocketAddr) -> (DirectPath, Instant) {
        let start = Instant::now();
        let mut path = DirectPath::new();
        path.set_reported(&[peer], start);
        let step = path.poll(start, &policy(&[]));
        let (to, nonce) = pings(&step.actions)[0];
        let up = start + 20 * MS;
        assert_eq!(path.on_pong(to, &nonce, up), Some(Change::Up { addr: peer }));
        (path, up)
    }

    #[test]
    fn the_status_tells_not_tried_from_trying_from_failed_without_changing_when_it_tries() {
        let start = Instant::now();
        let peer = addr("203.0.113.7:20330");
        let mut path = DirectPath::new();
        path.set_reported(&[peer], start);
        // 这一对节点还没有用过：不去试，也就说"还没有试过"。
        let idle = Policy { wanted: false, ..policy(&[]) };
        assert!(path.poll(start, &idle).actions.is_empty());
        let status = path.status(start);
        assert_eq!((status.state, status.failure, status.attempted_ms), (DirectState::NotTried, None, None));

        // 用到了：开始试。
        let step = path.poll(start, &policy(&[]));
        assert!(!pings(&step.actions).is_empty());
        assert_eq!(path.status(start + 100 * MS).state, DirectState::Trying);
        assert_eq!(path.status(start + 100 * MS).attempted_ms, Some(100));

        // 一次尝试的时限里没有回答：失败，原因是没有回答；退避照旧。
        let mut now = start;
        while now < start + PUNCH_ATTEMPT {
            now += 100 * MS;
            path.poll(now, &policy(&[]));
        }
        assert!(matches!(path.punch, Punch::Backoff { round: 0, .. }), "{:?}", path.punch);
        let failed = path.status(now);
        assert_eq!((failed.state, failed.failure, failed.kind), (DirectState::Failed, Some(DirectFailureCause::NoAnswer), None));
        assert_eq!(failed.attempted_ms, Some(u64::try_from((now - start).as_millis()).unwrap()), "最近一次尝试是开始时那一次");

        // 对端不再活跃：失败的记录还在，不会变回"没有试过"。
        path.poll(now + 10 * MS, &idle);
        assert_eq!(path.status(now + 10 * MS).state, DirectState::Failed);
    }

    #[test]
    fn a_verified_path_reports_its_kind_and_a_lost_one_why_it_went() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, up) = established(peer);
        let status = path.status(up);
        assert_eq!((status.state, status.kind, status.failure), (DirectState::Verified, Some(DirectKind::Reachable), None));

        // 闲着太久，放下了。
        let idle = Policy { wanted: false, ..policy(&[]) };
        let later = up + STALE + MS;
        assert_eq!(path.poll(later, &idle).change, Some(Change::Down { reason: DownReason::Stale }));
        let status = path.status(later);
        assert_eq!((status.state, status.failure), (DirectState::Failed, Some(DirectFailureCause::Stale)));
    }

    #[test]
    fn with_no_candidate_to_try_the_failure_says_so() {
        let start = Instant::now();
        let mut path = DirectPath::new();
        let mut now = start;
        path.poll(now, &policy(&[]));
        while now <= start + PUNCH_ATTEMPT {
            now += 100 * MS;
            path.poll(now, &policy(&[]));
        }
        assert_eq!(path.status(now).failure, Some(DirectFailureCause::NoCandidates));
    }

    #[test]
    fn a_candidate_becomes_usable_only_after_a_matching_pong() {
        let start = Instant::now();
        let peer = addr("203.0.113.7:20330");
        let local = [addr("198.51.100.1:20330")];
        let mut path = DirectPath::new();
        path.set_reported(&[peer], start);
        assert_eq!(path.active(), None);

        let step = path.poll(start, &policy(&local));
        assert_eq!(signals(&step.actions), [&Signal::PunchRequest { endpoints: local.to_vec() }], "尝试开始时请对端同时发");
        let [(to, nonce)] = pings(&step.actions)[..] else { panic!("应该向唯一的候选发一个 PING：{step:?}") };
        assert_eq!(to, peer);
        assert_eq!(path.active(), None, "发了 PING 还不算验证过");

        assert_eq!(path.on_pong(peer, &[0; 8], start + 10 * MS), None, "随机数不对");
        assert_eq!(path.on_pong(addr("203.0.113.8:20330"), &nonce, start + 10 * MS), None, "不是从被问的地址来的");
        assert_eq!(path.active(), None);

        assert_eq!(path.on_pong(peer, &nonce, start + 30 * MS), Some(Change::Up { addr: peer }));
        let (active, rtt) = path.active().unwrap();
        assert_eq!((active, rtt.get()), (peer, 30 * MS));
        assert_eq!(path.on_pong(peer, &nonce, start + 40 * MS), None, "同一个 PONG 不能用两次");
    }

    #[test]
    fn an_attempt_sends_three_volleys_and_then_backs_off_on_the_documented_schedule() {
        let start = Instant::now();
        let peer = addr("203.0.113.7:20330");
        let mut path = DirectPath::new();
        path.set_reported(&[peer], start);
        let policy = policy(&[]);

        // 每 10ms 推进一次，记下每个 PING 和每条信令发出的时刻。
        let mut ping_times = Vec::new();
        let mut request_times = Vec::new();
        for tick in 0..=6_000u32 {
            let now = start + 10 * MS * tick;
            let step = path.poll(now, &policy);
            assert_eq!(step.change, None);
            if !pings(&step.actions).is_empty() {
                ping_times.push(tick * 10);
            }
            if !signals(&step.actions).is_empty() {
                request_times.push(tick * 10);
            }
        }
        // 一次尝试 1.5 秒，然后等 1、1、2、4、4、8、8、16 秒。
        let expected: Vec<u32> = [0u32, 2500, 5000, 8500, 14000, 19500, 29000, 38500, 56000].to_vec();
        assert_eq!(request_times, expected, "每次尝试开始时发一条信令");
        let first_volleys: Vec<u32> = expected.iter().flat_map(|&at| [at, at + 300, at + 600]).collect();
        assert_eq!(ping_times, first_volleys, "每次尝试三轮探测");
    }

    #[test]
    fn after_the_schedule_is_exhausted_it_retries_once_a_minute_or_at_once_when_candidates_change() {
        let start = Instant::now();
        let peer = addr("203.0.113.7:20330");
        let mut path = DirectPath::new();
        path.set_reported(&[peer], start);
        let policy = policy(&[]);
        let exhausted_at = (0..).map(|tick| start + 100 * MS * tick).find(|&now| {
            path.poll(now, &policy);
            matches!(path.punch, Punch::Exhausted { .. })
        });
        let exhausted_at = exhausted_at.unwrap();

        assert!(path.poll(exhausted_at + Duration::from_secs(59), &policy).actions.is_empty());
        let retry = path.poll(exhausted_at + Duration::from_secs(60), &policy);
        assert_eq!(pings(&retry.actions).len(), 1, "一分钟之后再试一次");
        let failed = exhausted_at + Duration::from_secs(60) + PUNCH_ATTEMPT;
        path.poll(failed, &policy);
        assert!(matches!(path.punch, Punch::Exhausted { .. }), "再失败还是每分钟一次，不重走整个退避表");

        // 对端上报了新的端点：立刻重试，之前的失败记录清掉。
        let moved = addr("203.0.113.9:4000");
        path.set_reported(&[peer, moved], failed + 5 * MS);
        let step = path.poll(failed + 5 * MS, &policy);
        assert_eq!(pings(&step.actions).iter().map(|(to, _)| *to).collect::<Vec<_>>(), [peer, moved]);
        assert!(matches!(path.punch, Punch::Attempt { round: 0, .. }));

        // 本端的端点变了也一样。
        path.poll(failed + 5 * MS + PUNCH_ATTEMPT, &policy);
        assert!(matches!(path.punch, Punch::Backoff { round: 0, .. }));
        path.local_changed();
        assert_eq!(path.punch, Punch::Idle);
    }

    #[test]
    fn the_active_address_is_probed_every_five_seconds() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, up) = established(peer);
        let policy = policy(&[]);
        assert!(path.poll(up + PROBE_INTERVAL - MS, &policy).actions.is_empty());
        let step = path.poll(up + PROBE_INTERVAL, &policy);
        let [(to, nonce)] = pings(&step.actions)[..] else { panic!("该发保活探测了：{step:?}") };
        assert_eq!(to, peer);
        assert!(signals(&step.actions).is_empty(), "保活不发信令");
        assert_eq!(path.on_pong(peer, &nonce, up + PROBE_INTERVAL + 10 * MS), None);
        assert!(!path.in_doubt());
        assert!(path.poll(up + PROBE_INTERVAL + 20 * MS, &policy).actions.is_empty());
    }

    #[test]
    fn three_consecutive_timeouts_take_the_path_down_and_restart_punching_at_once() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, up) = established(peer);
        let policy = policy(&[]);
        let timeout = path.active().unwrap().1.probe_timeout();

        let mut now = up + PROBE_INTERVAL;
        assert_eq!(pings(&path.poll(now, &policy).actions).len(), 1);
        for expected_timeouts in 1..MAX_TIMEOUTS {
            now += timeout;
            let step = path.poll(now, &policy);
            assert_eq!(step.change, None);
            assert_eq!(pings(&step.actions).len(), 1, "超时之后立刻再问，不等 5 秒");
            assert!(path.in_doubt());
            assert_eq!(path.active.as_ref().unwrap().timeouts, expected_timeouts);
        }
        now += timeout;
        let step = path.poll(now, &policy);
        assert_eq!(step.change, Some(Change::Down { reason: DownReason::Timeouts }));
        assert_eq!(path.active(), None);
        assert_eq!(pings(&step.actions).len(), 1, "同一步里就开始重新验证");
        assert!(matches!(path.punch, Punch::Attempt { round: 0, .. }));
    }

    #[test]
    fn an_answer_in_time_clears_the_timeout_count() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, up) = established(peer);
        let policy = policy(&[]);
        let timeout = path.active().unwrap().1.probe_timeout();
        let mut now = up + PROBE_INTERVAL;
        path.poll(now, &policy);
        now += timeout;
        let retry = path.poll(now, &policy);
        let (_, nonce) = pings(&retry.actions)[0];
        assert!(path.in_doubt());
        assert_eq!(path.on_pong(peer, &nonce, now + 5 * MS), None);
        assert!(!path.in_doubt());
        assert_eq!(path.active().map(|(addr, _)| addr), Some(peer));
    }

    /// 一条因为丢包太多刚被判掉的直连：每三个探测丢一个，从不连续超时三次，但丢包率是三分之一。
    /// 返回它、判掉的时刻，和判掉之前最后发出去、没有等到回答的那个探测的随机数。
    fn taken_down_for_loss(peer: SocketAddr) -> (DirectPath, Instant, Nonce) {
        let (mut path, up) = established(peer);
        let policy = policy(&[]);
        let mut now = up;
        for round in 0..60 {
            now += PROBE_INTERVAL;
            let step = path.poll(now, &policy);
            let (_, nonce) = pings(&step.actions)[0];
            if round % 2 == 0 {
                path.on_pong(peer, &nonce, now + 5 * MS);
                continue;
            }
            now += path.active().unwrap().1.probe_timeout();
            let step = path.poll(now, &policy);
            if let Some(change) = step.change {
                assert_eq!(change, Change::Down { reason: DownReason::Loss });
                assert!(step.actions.is_empty(), "丢包多的路不立刻重试，免得来回切");
                return (path, now, nonce);
            }
            let (_, nonce) = pings(&step.actions)[0];
            path.on_pong(peer, &nonce, now + 5 * MS);
        }
        panic!("三分之一的丢包率早该判掉了");
    }

    #[test]
    fn losing_more_than_a_fifth_of_recent_probes_takes_the_path_down_and_waits_before_retrying() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, down, _) = taken_down_for_loss(peer);
        let policy = policy(&[]);
        assert_eq!(path.active(), None);
        assert!(path.poll(down + Duration::from_secs(59), &policy).actions.is_empty());
        assert!(!path.poll(down + PUNCH_IDLE_RETRY, &policy).actions.is_empty());
    }

    #[test]
    fn a_few_losses_close_together_do_not_take_a_low_loss_path_down() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, up) = established(peer);
        let policy = policy(&[]);
        let mut now = up;
        // 四十个保活里丢三个，三个挨得很近，其余都有回答。按最近 10 个探测算的时候，这样就判掉了。
        for round in 0..40 {
            now += PROBE_INTERVAL;
            let step = path.poll(now, &policy);
            let (_, mut nonce) = pings(&step.actions)[0];
            if matches!(round, 10 | 12 | 14) {
                now += path.active().unwrap().1.probe_timeout();
                let step = path.poll(now, &policy);
                assert_eq!(step.change, None);
                nonce = pings(&step.actions)[0].1;
            }
            path.on_pong(peer, &nonce, now + 5 * MS);
        }
        assert_eq!(path.active().map(|(addr, _)| addr), Some(peer));
    }

    #[test]
    fn a_path_taken_down_for_loss_is_not_brought_back_by_answers_until_the_wait_is_over() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, down, unanswered) = taken_down_for_loss(peer);
        let policy = policy(&[]);

        // 判掉之前发的探测这时才答回来。
        assert_eq!(path.on_pong(peer, &unanswered, down + 10 * MS), None);
        // 对端的直连还在，它的保活 PING 照常来：不引出反向验证，它发来的包照样认。
        let later = down + Duration::from_secs(1);
        assert_eq!(path.on_ping(peer, later), None);
        assert_eq!(path.sources(later).collect::<Vec<_>>(), [peer]);
        // 对端请本端一起打洞：回答它，但不跟着去试。
        let actions = path.on_signal(&Signal::PunchRequest { endpoints: vec![peer] }, later, &policy);
        assert!(matches!(signals(&actions)[..], [Signal::PunchReply { .. }]), "{actions:?}");
        assert!(pings(&actions).is_empty(), "{actions:?}");
        assert_eq!(path.active(), None);
        assert_eq!(path.status(later).failure, Some(DirectFailureCause::Loss));

        // 等够了再试一次，这一次的回答算数。
        let retry = down + PUNCH_IDLE_RETRY;
        let step = path.poll(retry, &policy);
        let (to, nonce) = pings(&step.actions)[0];
        assert_eq!(path.on_pong(to, &nonce, retry + 20 * MS), Some(Change::Up { addr: peer }));
    }

    #[test]
    fn another_address_of_the_peer_can_still_come_up_while_the_lossy_one_waits() {
        let peer = addr("203.0.113.7:20330");
        let moved = addr("203.0.113.7:40000");
        let (mut path, down, _) = taken_down_for_loss(peer);
        let at = down + Duration::from_secs(3);
        let Some(Action::Ping { to, nonce }) = path.on_ping(moved, at) else {
            panic!("对端从新地址来的探测应该引出反向验证")
        };
        assert_eq!(to, moved);
        assert_eq!(path.on_pong(moved, &nonce, at + 20 * MS), Some(Change::Up { addr: moved }));
    }

    #[test]
    fn a_new_candidate_ends_the_wait_after_loss_at_once() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, down, _) = taken_down_for_loss(peer);
        let policy = policy(&[]);
        let at = down + Duration::from_secs(3);
        assert!(path.set_reported(&[peer, addr("203.0.113.8:20330")], at));
        let step = path.poll(at, &policy);
        let (_, nonce) = pings(&step.actions).into_iter().find(|(to, _)| *to == peer).expect("两个候选都该探测");
        assert_eq!(path.on_pong(peer, &nonce, at + 20 * MS), Some(Change::Up { addr: peer }), "候选变了就从头来，原来那个地址也算数");
    }

    #[test]
    fn silence_on_a_busy_path_triggers_an_early_probe() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, up) = established(peer);
        let silent = Policy { silent: true, ..policy(&[]) };
        assert!(path.poll(up + SILENCE - MS, &silent).actions.is_empty());
        assert_eq!(pings(&path.poll(up + SILENCE, &silent).actions).len(), 1);
    }

    #[test]
    fn a_ping_from_the_peer_triggers_one_reverse_probe_per_second_per_address() {
        let start = Instant::now();
        let from = addr("203.0.113.7:4000");
        let mut path = DirectPath::new();
        assert_eq!(path.sources(start).count(), 0);

        let Some(Action::Ping { to, nonce }) = path.on_ping(from, start) else { panic!("应该反过来验证这个地址") };
        assert_eq!(to, from);
        assert_eq!(path.sources(start).collect::<Vec<_>>(), [from], "收到过签了名的 PING 的地址，可以认它发来的连接包");
        assert_eq!(path.active(), None, "但还不能往它发");
        assert_eq!(path.on_ping(from, start + 500 * MS), None, "重放同一个 PING 不会让本端多发");
        assert!(path.on_ping(from, start + REVERSE_PROBE_INTERVAL).is_some());

        assert_eq!(path.on_pong(from, &nonce, start + 30 * MS), Some(Change::Up { addr: from }));
        assert_eq!(path.on_ping(from, start + 5 * REVERSE_PROBE_INTERVAL), None, "已经在用的地址有自己的保活");
    }

    #[test]
    fn a_ping_from_the_peer_is_probed_back_even_while_our_own_probe_to_it_is_unanswered() {
        let start = Instant::now();
        let peer = addr("203.0.113.7:20330");
        let mut path = DirectPath::new();
        path.set_reported(&[peer], start);
        // 本端先探测了对端，这个探测没有回音：对端那时还不认识本端，丢掉了。
        assert_eq!(pings(&path.poll(start, &policy(&[])).actions).len(), 1);

        // 对端随后探测本端：不等本端的下一轮（300ms 之后），马上反过来验证，两边差不多同时改走直连。
        let Some(Action::Ping { to, nonce }) = path.on_ping(peer, start + 5 * MS) else { panic!("应该反过来验证这个地址") };
        assert_eq!(to, peer);
        assert_eq!(path.on_pong(peer, &nonce, start + 6 * MS), Some(Change::Up { addr: peer }));

        // 反向验证本身还是每秒最多一次：重放对端的 PING 不会让本端多发。
        let mut path = DirectPath::new();
        path.set_reported(&[peer], start);
        path.poll(start, &policy(&[]));
        assert!(path.on_ping(peer, start + 5 * MS).is_some());
        assert_eq!(path.on_ping(peer, start + 500 * MS), None);
    }

    #[test]
    fn an_answered_reverse_probe_still_counts_against_the_once_a_second_limit() {
        // 两边之间通着两个地址，已经在用其中一个。对端从另一个地址探测本端，本端反过来验证、得到了回答：
        // 对端紧接着从那里来的 PING（多半就是被本端的反向验证引出来的）不能再引出一个，不然两边一来一回停不下来。
        let (primary, spare) = (addr("203.0.113.7:20330"), addr("198.51.100.4:20330"));
        let (mut path, up) = established(primary);
        let Some(Action::Ping { to, nonce }) = path.on_ping(spare, up) else { panic!("应该反过来验证这个地址") };
        assert_eq!(to, spare);
        assert_eq!(path.on_pong(spare, &nonce, up + MS), None, "已经有在用的地址，不换");
        assert_eq!(path.on_ping(spare, up + 2 * MS), None, "一秒之内这个地址已经反向验证过了");
        assert!(path.on_ping(spare, up + REVERSE_PROBE_INTERVAL).is_some());
        assert_eq!(path.active().map(|(addr, _)| addr), Some(primary));
    }

    #[test]
    fn a_ping_from_an_address_that_cannot_be_a_candidate_is_not_probed_back() {
        // 没法发、不该发的地址（这里是链路本地地址）不记成候选，也就不反过来验证：那里的直连本来就用不了。
        let start = Instant::now();
        let mut path = DirectPath::new();
        assert_eq!(path.on_ping(addr("169.254.1.2:20330"), start), None);

        // 候选地址记满了、又都挤不掉（对端上报的）：新来的地址也不反过来验证，每个来源地址的频率限制就不用另外记。
        let mut full = DirectPath::new();
        let reported: Vec<SocketAddr> =
            (0..MAX_CANDIDATES).map(|index| SocketAddr::from(([203, 0, 113, 1], 20330 + u16::try_from(index).unwrap()))).collect();
        full.set_reported(&reported, start);
        assert_eq!(full.candidates.len(), MAX_CANDIDATES);
        assert_eq!(full.on_ping(addr("198.51.100.4:20330"), start), None);
        assert!(full.on_ping(reported[0], start).is_some(), "记着的地址照常反过来验证");
    }

    #[test]
    fn a_punch_both_sides_signalled_for_is_punched_whichever_answer_brings_it_up() {
        // 两边都在 NAT 后面，A 发起：A 发打洞请求、向 B 发头一轮探测（被 B 的 NAT 挡掉）。B 收到请求后探测 A，
        // 这个探测穿过 A 的 NAT（A 刚往 B 发过）。A 收到它时自己的探测还没有回音，就反过来验证。之后哪个回答先到都行：
        // A 的反向验证的、A 收到回应信令之后那一轮的；B 那边也一样。两边都要说是打洞打通的。
        let start = Instant::now();
        let (pa, pb) = (addr("198.51.100.1:20330"), addr("203.0.113.7:20330"));
        let begin = || {
            let mut a = DirectPath::new();
            a.set_reported(&[pb], start);
            let first = a.poll(start, &policy(&[pa])).actions;
            assert!(matches!(signals(&first)[..], [Signal::PunchRequest { .. }]), "{first:?}");
            let mut b = DirectPath::new();
            let answer = b.on_signal(&Signal::PunchRequest { endpoints: vec![pa] }, start + 40 * MS, &policy(&[pb]));
            let (_, b_probe) = pings(&answer)[0];
            let Some(Action::Ping { nonce: a_reverse, .. }) = a.on_ping(pb, start + 41 * MS) else { panic!("A 应该反过来验证 B") };
            (a, b, b_probe, a_reverse)
        };
        let reply = Signal::PunchReply { endpoints: vec![pb] };

        // A 的反向验证先得到回答，回应信令还没到。
        let (mut a, _, _, a_reverse) = begin();
        assert_eq!(a.on_pong(pb, &a_reverse, start + 42 * MS), Some(Change::Up { addr: pb }));
        assert_eq!(a.kind(), Some(DirectKind::Punched), "反向验证先到");

        // 回应信令先到，A 跟着发一轮；反向验证的回答先到，或者那一轮的回答先到。
        for volley_first in [false, true] {
            let (mut a, _, _, a_reverse) = begin();
            let (_, a_volley) = pings(&a.on_signal(&reply, start + 45 * MS, &policy(&[pa])))[0];
            let first = if volley_first { a_volley } else { a_reverse };
            assert_eq!(a.on_pong(pb, &first, start + 46 * MS), Some(Change::Up { addr: pb }));
            assert_eq!(a.kind(), Some(DirectKind::Punched), "回应信令之后，那一轮的回答先到：{volley_first}");
        }

        // B 这边：A 的反向验证的 PING 先到（B 自己的探测还没有回音），之后哪个回答先到都一样。
        for own_first in [false, true] {
            let (_, mut b, b_probe, _) = begin();
            let Some(Action::Ping { nonce: b_reverse, .. }) = b.on_ping(pa, start + 42 * MS) else { panic!("B 应该反过来验证 A") };
            let first = if own_first { b_probe } else { b_reverse };
            assert_eq!(b.on_pong(pa, &first, start + 43 * MS), Some(Change::Up { addr: pa }));
            assert_eq!(b.kind(), Some(DirectKind::Punched), "B 自己那一轮的回答先到：{own_first}");
        }

        // 对照：B 的地址本来就连得上，A 头一轮的探测直接得到了回答，B 还没来得及做什么：这是"本来就连得上"。
        let mut reachable = DirectPath::new();
        reachable.set_reported(&[pb], start);
        let (_, first) = pings(&reachable.poll(start, &policy(&[pa])).actions)[0];
        assert_eq!(reachable.on_pong(pb, &first, start + 5 * MS), Some(Change::Up { addr: pb }));
        assert_eq!(reachable.kind(), Some(DirectKind::Reachable));
    }

    #[test]
    fn a_ping_alone_vouches_for_its_source_only_briefly_unless_the_reverse_probe_is_answered() {
        let start = Instant::now();
        // 别人截下对端的一个 PING，从 `spoofed` 重放过来：签名是对的，但对端并不在那里。
        let spoofed = addr("203.0.113.7:4000");
        let mut path = DirectPath::new();
        let Some(Action::Ping { nonce, .. }) = path.on_ping(spoofed, start) else { panic!("应该反过来验证这个地址") };
        assert_eq!(path.sources(start).collect::<Vec<_>>(), [spoofed], "对端可能已经先改走直连了，它的包先认着");
        assert_eq!(path.sources(start + PINGED_TTL).count(), 0, "反向的验证一直没有回答：过一阵就不认了");

        // 对端确实在那里：反向的验证有了回答，这个地址就按验证过的地址认。
        let mut path = DirectPath::new();
        let Some(Action::Ping { nonce: reverse, .. }) = path.on_ping(spoofed, start) else { panic!("应该反过来验证这个地址") };
        path.on_pong(spoofed, &reverse, start + 20 * MS);
        assert_eq!(path.sources(start + PINGED_TTL).collect::<Vec<_>>(), [spoofed]);
        assert_ne!(nonce, reverse);
    }

    #[test]
    fn each_candidate_address_has_its_own_budget_for_signature_checks() {
        let start = Instant::now();
        let (reported, other) = (addr("203.0.113.7:20330"), addr("198.51.100.4:20330"));
        let mut path = DirectPath::new();
        path.set_reported(&[reported, other], start);
        assert_eq!(path.charge(addr("192.0.2.1:9"), start), None, "不是候选地址：交给陌生地址的额度");
        let spent = (0..1000).take_while(|_| path.charge(reported, start) == Some(true)).count();
        assert_eq!(spent, 50);
        assert_eq!(path.charge(reported, start), Some(false));
        assert_eq!(path.charge(other, start), Some(true), "一个地址的额度用完了，不影响别的地址");
        assert_eq!(path.charge(reported, start + Duration::from_millis(40)), Some(true), "之后每秒 25 个");
    }

    #[test]
    fn a_peer_flooding_punch_signals_gets_one_volley_per_attempt_and_the_backoff_still_advances() {
        let start = Instant::now();
        let mut path = DirectPath::new();
        let local = [addr("198.51.100.1:20330")];
        let theirs: Vec<SocketAddr> = (1..=8u16).map(|port| SocketAddr::from(([203, 0, 113, 7], port))).collect();
        let reply = Signal::PunchReply { endpoints: theirs.clone() };
        // 对端每 100ms 发一条回应信令，一共 15 秒。
        let mut volleys = 0;
        let mut pinged = 0;
        for tick in 0..150u32 {
            let now = start + 100 * MS * tick;
            let actions = path.on_signal(&reply, now, &policy(&local));
            volleys += usize::from(!pings(&actions).is_empty());
            pinged += pings(&actions).len() + pings(&path.poll(now, &policy(&local)).actions).len();
        }
        assert!(volleys <= 10, "15 秒里信令引出的探测最多每 1.5 秒一轮：{volleys}");
        // 每一次尝试三轮，每轮向 8 个候选各发一个；不比按退避表自己重试多多少。
        assert!(pinged <= 10 * 3 * theirs.len(), "{pinged}");
        let advanced = match path.punch {
            Punch::Attempt { round, .. } | Punch::Backoff { round, .. } => round >= 2,
            Punch::Exhausted { .. } => true,
            Punch::Idle | Punch::Shunned { .. } => false,
        };
        assert!(advanced, "退避在往前走：{:?}", path.punch);
    }

    #[test]
    fn addresses_that_cannot_or_should_not_be_probed_never_become_candidates() {
        let start = Instant::now();
        let refused = [
            "127.0.0.1:20330",
            "[::1]:20330",
            "224.0.0.251:5353",
            "[ff02::1]:20330",
            "255.255.255.255:20330",
            "169.254.1.2:20330",
            "[fe80::1]:20330",
            "0.0.0.0:20330",
            "203.0.113.7:0",
        ];
        let mut path = DirectPath::new();
        path.set_reported(&refused.map(addr), start);
        let signal = Signal::PunchRequest { endpoints: refused[..8].iter().map(|text| addr(text)).collect() };
        path.on_signal(&signal, start, &policy(&[]));
        assert!(path.candidates.is_empty(), "{:?}", path.candidates);
        // 私有地址照样收：可能就在同一个局域网里。
        path.set_reported(&[addr("192.168.1.5:20330"), addr("[fd00::5]:20330")], start);
        assert_eq!(path.candidates.len(), 2);
        // 本节点自己绑在回环上（测试）时，对端的回环地址就是它真的地址。
        let mut on_loopback = DirectPath::for_port(addr("127.0.0.1:4000"));
        on_loopback.set_reported(&[addr("127.0.0.1:20330")], start);
        assert_eq!(on_loopback.candidates.len(), 1);
    }

    #[test]
    fn a_punch_request_is_answered_and_both_sides_probe_at_once() {
        let start = Instant::now();
        let local = [addr("198.51.100.1:20330")];
        let theirs = vec![addr("203.0.113.7:4000"), addr("192.168.1.5:20330")];
        let mut path = DirectPath::new();
        let request = Signal::PunchRequest { endpoints: theirs.clone() };

        let actions = path.on_signal(&request, start, &policy(&local));
        assert_eq!(signals(&actions), [&Signal::PunchReply { endpoints: local.to_vec() }]);
        assert_eq!(pings(&actions).iter().map(|(to, _)| *to).collect::<Vec<_>>(), theirs);
        assert!(path.on_signal(&request, start + 50 * MS, &policy(&local)).is_empty(), "另一条通道送来的同一个请求");

        // 后面两轮探测跟着这次请求的时刻走，并且不再发自己的请求。
        let step = path.poll(start + 300 * MS, &policy(&local));
        assert_eq!(pings(&step.actions).len(), 2);
        assert!(signals(&step.actions).is_empty());

        // 回答只带来候选和一轮探测，不再回信令。
        let mut requester = DirectPath::new();
        let actions = requester.on_signal(&Signal::PunchReply { endpoints: theirs.clone() }, start, &policy(&local));
        assert!(signals(&actions).is_empty());
        assert_eq!(pings(&actions).len(), 2);
    }

    #[test]
    fn signals_are_ignored_when_punching_is_not_allowed() {
        let start = Instant::now();
        let mut path = DirectPath::new();
        let no_signal = Policy { signal: false, ..policy(&[]) };
        let request = Signal::PunchRequest { endpoints: vec![addr("203.0.113.7:4000")] };
        assert!(path.on_signal(&request, start, &no_signal).is_empty());
        assert!(path.candidates.is_empty());

        // 不许发信令时，尝试照常进行，只是不带信令。
        path.set_reported(&[addr("203.0.113.7:20330")], start);
        let step = path.poll(start, &no_signal);
        assert!(signals(&step.actions).is_empty());
        assert_eq!(pings(&step.actions).len(), 1);
    }

    #[test]
    fn nothing_is_initiated_towards_a_peer_that_only_dials_out() {
        let start = Instant::now();
        let mut path = DirectPath::new();
        path.set_reported(&[addr("203.0.113.7:20330")], start);
        let passive = Policy { initiate: false, signal: false, ..policy(&[]) };
        assert_eq!(path.poll(start, &passive), Step::default());
        // 它来找本端时照样反向验证，验证过的地址照样保活。
        let from = addr("203.0.113.7:5555");
        let Some(Action::Ping { nonce, .. }) = path.on_ping(from, start) else { panic!("应该反向验证") };
        assert_eq!(path.on_pong(from, &nonce, start + 10 * MS), Some(Change::Up { addr: from }));
        assert_eq!(pings(&path.poll(start + PROBE_INTERVAL + 10 * MS, &passive).actions).len(), 1);
    }

    #[test]
    fn an_inactive_peer_is_not_probed_and_its_address_goes_stale() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, up) = established(peer);
        let idle = Policy { wanted: false, ..policy(&[]) };
        assert_eq!(path.poll(up + PROBE_INTERVAL, &idle), Step::default());
        assert!(path.active().is_some(), "刚不活跃时地址还留着，马上又有流量的话不用重新验证");
        let step = path.poll(up + STALE + MS, &idle);
        assert_eq!(step, Step { actions: Vec::new(), change: Some(Change::Down { reason: DownReason::Stale }) });

        // 重新活跃之后从头开始。
        let step = path.poll(up + STALE + 2 * MS, &policy(&[]));
        assert_eq!(pings(&step.actions).len(), 1);
    }

    #[test]
    fn an_address_that_was_idle_is_probed_as_soon_as_the_peer_is_wanted_again() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, up) = established(peer);
        let idle = Policy { wanted: false, ..policy(&[]) };
        path.poll(up + 2 * PROBE_INTERVAL, &idle);
        let step = path.poll(up + 2 * PROBE_INTERVAL + MS, &policy(&[]));
        assert_eq!(pings(&step.actions).len(), 1, "隔了超过一个探测间隔，先确认它还在");
    }

    #[test]
    fn a_lan_address_replaces_a_public_one_but_not_the_other_way_round() {
        let start = Instant::now();
        let (public, lan) = (addr("203.0.113.7:4000"), addr("192.168.1.5:20330"));
        let mut path = DirectPath::new();
        path.set_reported(&[public, lan], start);
        let step = path.poll(start, &policy(&[]));
        let probes = pings(&step.actions);
        let nonce_of = |target: SocketAddr| probes.iter().find(|(to, _)| *to == target).unwrap().1;

        assert_eq!(path.on_pong(public, &nonce_of(public), start + 30 * MS), Some(Change::Up { addr: public }));
        assert_eq!(path.on_pong(lan, &nonce_of(lan), start + 40 * MS), Some(Change::Up { addr: lan }), "局域网地址优先");

        let mut path = DirectPath::new();
        path.set_reported(&[public, lan], start);
        let probes = pings(&path.poll(start, &policy(&[])).actions);
        let nonce_of = |target: SocketAddr| probes.iter().find(|(to, _)| *to == target).unwrap().1;
        assert_eq!(path.on_pong(lan, &nonce_of(lan), start + 30 * MS), Some(Change::Up { addr: lan }));
        assert_eq!(path.on_pong(public, &nonce_of(public), start + 40 * MS), None, "已经在用局域网地址就不换");
        assert_eq!(path.sources(start + 40 * MS).count(), 2, "两个地址来的包都认");
    }

    /// 让一条通着的直连一直通到 `until`：每秒推进一次，保活探测都有回答。
    fn kept_alive(path: &mut DirectPath, from: Instant, until: Instant) {
        let mut now = from;
        while now < until {
            now = (now + Duration::from_secs(1)).min(until);
            for (to, nonce) in pings(&path.poll(now, &policy(&[])).actions) {
                path.on_pong(to, &nonce, now);
            }
        }
    }

    #[test]
    fn a_peer_seen_through_a_lan_beacon_becomes_a_candidate_that_still_has_to_be_validated() {
        let start = Instant::now();
        let lan = addr("192.168.1.7:20330");
        let mut path = DirectPath::new();
        // 对端没有上报任何端点；信标是唯一的线索。
        assert!(path.poll(start, &policy(&[])).actions.iter().all(|action| !matches!(action, Action::Ping { .. })));
        let probe = path.on_lan_sighting(lan, start + 10 * MS, &policy(&[]));
        let Some(Action::Ping { to, nonce }) = probe else { panic!("应该立刻去探测信标里的地址：{probe:?}") };
        assert_eq!(to, lan);
        assert_eq!(path.active(), None, "看到信标不等于验证过");
        assert_eq!(path.on_pong(lan, &nonce, start + 12 * MS), Some(Change::Up { addr: lan }));
        assert_eq!(path.kind(), Some(DirectKind::Lan));
        assert!(path.is_lan_active());

        // 还没有开始试的不另发：下一次推进就从头尝试，那一轮探测里有它。
        let mut fresh = DirectPath::new();
        assert_eq!(fresh.on_lan_sighting(lan, start, &policy(&[])), None);
        let step = fresh.poll(start, &policy(&[]));
        assert_eq!(pings(&step.actions).iter().map(|(to, _)| *to).collect::<Vec<_>>(), [lan]);

        // 用不到这个对端时只是记下，不探测；只主动连接的对端也不由本端去探测。
        let idle = Policy { wanted: false, ..policy(&[]) };
        let dial_out_only = Policy { initiate: false, ..policy(&[]) };
        for unwanted in [idle, dial_out_only] {
            let mut path = DirectPath::new();
            path.poll(start, &unwanted);
            assert_eq!(path.on_lan_sighting(lan, start, &unwanted), None);
            assert!(pings(&path.poll(start, &unwanted).actions).is_empty());
            assert_eq!(path.candidate_count(), 1);
        }
    }

    #[test]
    fn repeated_beacons_refresh_the_candidate_without_restarting_the_retry_schedule() {
        let start = Instant::now();
        let lan = addr("192.168.1.7:20330");
        let mut path = DirectPath::new();
        path.on_lan_sighting(lan, start, &policy(&[]));
        path.poll(start, &policy(&[]));
        // 这一次尝试失败之后进入退避。信标每隔几秒再来一个，不该每次都把退避清掉重来。
        path.poll(start + PUNCH_ATTEMPT, &policy(&[]));
        assert!(matches!(path.punch, Punch::Backoff { round: 0, .. }));
        path.on_lan_sighting(lan, start + PUNCH_ATTEMPT + 10 * MS, &policy(&[]));
        assert!(matches!(path.punch, Punch::Backoff { round: 0, .. }));
        // 信标一直在来，这个候选就一直留着（不是对端上报的候选本来两分钟不出现就忘掉）。
        let later = start + CANDIDATE_TTL + Duration::from_secs(1);
        path.on_lan_sighting(lan, later - Duration::from_secs(5), &policy(&[]));
        path.poll(later, &Policy { wanted: false, ..policy(&[]) });
        assert_eq!(path.candidates.len(), 1);
    }

    #[test]
    fn forged_beacons_neither_restart_the_retry_schedule_nor_crowd_out_other_candidates() {
        let start = Instant::now();
        let local = [addr("198.51.100.1:20330")];
        let policy = policy(&local);
        let (reported, signalled, pinged) = (addr("203.0.113.7:20330"), addr("203.0.113.7:4000"), addr("203.0.113.7:4001"));
        let mut path = DirectPath::new();
        path.set_reported(&[reported], start);
        path.on_signal(&Signal::PunchReply { endpoints: vec![signalled] }, start, &policy);
        path.on_ping(pinged, start);
        // 一整轮都没有打通，之后每分钟才再试一次。
        let mut now = start;
        while !matches!(path.punch, Punch::Exhausted { .. }) {
            now += 100 * MS;
            path.poll(now, &policy);
        }
        let exhausted = path.punch;
        let known = |path: &DirectPath| {
            [reported, signalled, pinged].iter().all(|addr| path.candidates.iter().any(|candidate| candidate.addr == *addr))
        };
        assert!(known(&path));

        // 知道对端公钥的人在网段上灌信标，每个的来源都不一样：每秒 50 个，灌 20 秒。
        let mut probes = Vec::new();
        for forged in 0..1000u16 {
            now += 20 * MS;
            let from = SocketAddr::from(([192, 168, 1, 66], 1000 + forged));
            if let Some(action) = path.on_lan_sighting(from, now, &policy) {
                let Action::Ping { to, .. } = action else { panic!("信标只会引出探测：{action:?}") };
                assert_eq!(to, from, "只探测信标里的那个地址");
                probes.push(now);
            }
            assert!(path.poll(now, &policy).actions.is_empty(), "不为它另发一轮探测，也不发信令");
            assert_eq!(path.punch, exhausted, "重试的节奏不因为它重来");
            assert!(path.candidates.iter().filter(|candidate| candidate.sighted_only).count() <= MAX_SIGHTED);
        }
        // 攒着的 4 个，加上 20 秒里每秒补的一个。
        assert!((20..=24).contains(&probes.len()), "{}", probes.len());
        assert!(known(&path), "别处学来的候选没有被挤掉");
        assert!(path.candidates.len() <= 3 + MAX_SIGHTED);

        // 到了该再试的时候照常再试。
        let Punch::Exhausted { retry_at } = exhausted else { unreachable!() };
        let step = path.poll(retry_at, &policy);
        assert_eq!(signals(&step.actions).len(), 1);
        assert_eq!(pings(&step.actions).len(), path.candidates.len());
    }

    #[test]
    fn beacons_do_not_bring_back_an_address_put_aside_for_loss() {
        let peer = addr("192.168.1.7:20330");
        let (mut path, down, _) = taken_down_for_loss(peer);
        let policy = policy(&[]);
        let shunned = path.punch;
        assert!(matches!(shunned, Punch::Shunned { .. }));
        // 对端的信标照常每 10 秒一个：搁着的那个地址不因为它提前再试。
        for seconds in [1, 11, 21, 31, 41, 51] {
            let now = down + Duration::from_secs(seconds);
            assert_eq!(path.on_lan_sighting(peer, now, &policy), None);
            assert!(path.poll(now, &policy).actions.is_empty());
            assert_eq!(path.punch, shunned);
        }
        // 别的地址上看到了它：只探测那一个，搁着的照旧搁着。
        let other = addr("192.168.1.8:20330");
        let now = down + Duration::from_secs(52);
        let probe = path.on_lan_sighting(other, now, &policy);
        let Some(Action::Ping { to, nonce }) = probe else { panic!("别的地址照样探测：{probe:?}") };
        assert_eq!((to, path.punch), (other, shunned));
        assert_eq!(path.on_pong(other, &nonce, now + MS), Some(Change::Up { addr: other }), "别的地址验证通过了照样用");
    }

    #[test]
    fn a_beacon_cannot_make_a_public_address_count_as_the_local_network() {
        let public = addr("203.0.113.7:20330");
        let (mut path, up) = established(public);
        assert!(!path.is_local_network(public));
        // 有人造了一个来源是对端公网地址的信标。本节点在地址转换后面的话，对端看到的是本节点的公网地址：
        // 把这个地址当成本地网络里的，对端的回答就再也对不上，直连断了也回不来。
        assert_eq!(path.on_lan_sighting(public, up, &policy(&[])), None);
        assert!(!path.is_local_network(public));
        assert_eq!(path.kind(), Some(DirectKind::Reachable));
        // 没有听说过的公网地址也不因为信标成为候选。
        let unknown = addr("198.51.100.3:9");
        let mut idle = DirectPath::new();
        idle.poll(up, &policy(&[]));
        assert_eq!(idle.on_lan_sighting(unknown, up, &policy(&[])), None);
        assert_eq!(idle.candidate_count(), 0);
    }

    #[test]
    fn an_address_stops_counting_as_seen_on_the_lan_once_the_beacons_stop() {
        // 对端上报的地址不会过期，信标给它的记号会。
        for peer in ["192.168.1.7:20330", "[2001:db8::7]:20330"].map(addr) {
            let (mut path, up) = established(peer);
            let private = ifaddr::is_private(peer.ip());
            assert_eq!(path.is_local_network(peer), private);
            path.on_lan_sighting(peer, up, &policy(&[]));
            assert!(path.is_local_network(peer));
            assert_eq!(path.is_lan_active(), private, "公网的 IPv6 地址在同一个网段上也不叫局域网直连");

            // 信标还在来的时候一直算。
            let seen_again = up + SIGHTING_TTL - Duration::from_secs(1);
            kept_alive(&mut path, up, seen_again);
            path.on_lan_sighting(peer, seen_again, &policy(&[]));
            let almost = seen_again + SIGHTING_TTL - Duration::from_secs(1);
            kept_alive(&mut path, seen_again, almost);
            assert!(path.is_local_network(peer));
            // 信标停了。
            kept_alive(&mut path, almost, seen_again + SIGHTING_TTL);
            assert_eq!(path.active().map(|(addr, _)| addr), Some(peer), "直连本身不受影响");
            assert_eq!(path.is_local_network(peer), private);
            assert!(!path.is_lan_active());
        }
    }

    #[test]
    fn an_address_known_only_from_a_beacon_has_no_verify_budget_of_its_own() {
        let start = Instant::now();
        let (lan, reported, signalled) = (addr("192.168.1.7:20330"), addr("192.168.1.8:20330"), addr("203.0.113.7:4000"));
        let mut path = DirectPath::new();
        path.set_reported(&[reported], start);
        path.on_signal(&Signal::PunchReply { endpoints: vec![signalled] }, start, &policy(&[]));
        path.on_lan_sighting(lan, start, &policy(&[]));
        path.on_lan_sighting(reported, start, &policy(&[]));
        // 对端上报的、信令里的地址来的 PING 用那个地址自己的额度，信标里也看到了它不改变这一点。
        assert_eq!((path.charge(reported, start), path.charge(signalled, start)), (Some(true), Some(true)));
        // 只在信标里见过的照陌生地址算：造几个信标换不来几份额度。
        assert_eq!(path.charge(lan, start), None);
        // 对端签了名的探测从这个地址来过之后，它就是一个普通的候选了。
        path.on_ping(lan, start + MS);
        assert_eq!(path.charge(lan, start + MS), Some(true));
    }

    #[test]
    fn a_full_table_gives_up_addresses_known_only_from_beacons_first() {
        let start = Instant::now();
        let reported = addr("203.0.113.7:20330");
        let mut path = DirectPath::new();
        path.set_reported(&[reported], start);
        // 探测里来的 11 个，然后是信标里来的 4 个：表满了，信标里的那几个最新。
        let pinged: Vec<SocketAddr> = (1..=11u16).map(|port| SocketAddr::from(([198, 51, 100, 1], port))).collect();
        for from in &pinged {
            path.on_ping(*from, start + MS * u32::from(from.port()));
        }
        for port in 1..=4 {
            path.on_lan_sighting(SocketAddr::from(([192, 168, 1, 66], port)), start + Duration::from_secs(1), &policy(&[]));
        }
        assert_eq!(path.candidates.len(), MAX_CANDIDATES);
        let has = |path: &DirectPath, addr: SocketAddr| path.candidates.iter().any(|candidate| candidate.addr == addr);
        let sighted_only = |path: &DirectPath| path.candidates.iter().filter(|candidate| candidate.sighted_only).count();

        // 又有一个地址来了对端的探测：让出位置的是信标里的线索，不是更早从探测里得知的地址。
        let newcomer = addr("198.51.100.2:9");
        path.on_ping(newcomer, start + Duration::from_secs(2));
        assert!(has(&path, newcomer) && has(&path, reported));
        assert!(pinged.iter().all(|from| has(&path, *from)), "别处学来的候选一个都没有少");
        assert_eq!(sighted_only(&path), 3);

        // 信标里的挤完了，才轮到最久没有出现的那个。
        for port in 10..=13 {
            path.on_ping(SocketAddr::from(([198, 51, 100, 2], port)), start + Duration::from_secs(3));
        }
        assert_eq!((sighted_only(&path), path.candidates.len()), (0, MAX_CANDIDATES));
        assert!(!has(&path, pinged[0]) && has(&path, pinged[1]) && has(&path, reported));
    }

    #[test]
    fn an_address_first_seen_in_a_beacon_still_counts_as_new_when_the_peer_reports_it() {
        let start = Instant::now();
        let lan = addr("192.168.1.7:20330");
        let mut path = DirectPath::new();
        path.poll(start, &policy(&[]));
        assert!(path.on_lan_sighting(lan, start + MS, &policy(&[])).is_some());
        // 探测没有得到回答，这一次尝试失败了，正在退避。
        path.poll(start + PUNCH_ATTEMPT, &policy(&[]));
        assert!(matches!(path.punch, Punch::Backoff { round: 0, .. }));

        // 对端自己上报了这个地址：候选端点变了，立刻从头试，和信标没有先到一步时一样。
        let reported = start + PUNCH_ATTEMPT + 10 * MS;
        assert!(path.set_reported(&[lan], reported), "要算作新的地址");
        let step = path.poll(reported, &policy(&[]));
        assert_eq!((signals(&step.actions).len(), pings(&step.actions).len()), (1, 1), "{step:?}");
        // 同一份 netmap 再来一次不算，正在进行的尝试不被打断。
        let attempt = path.punch;
        assert!(!path.set_reported(&[lan], reported + MS));
        assert_eq!(path.punch, attempt);
        // 信标再来也不让它变回"只在信标里见过"。
        path.on_lan_sighting(lan, reported + 2 * MS, &policy(&[]));
        assert!(!path.set_reported(&[lan], reported + 3 * MS));
    }

    #[test]
    fn an_answer_from_an_address_crowded_out_meanwhile_puts_it_back_among_the_candidates() {
        let start = Instant::now();
        let lan = addr("192.168.1.7:20330");
        let mut path = DirectPath::new();
        path.poll(start, &policy(&[]));
        let probe = path.on_lan_sighting(lan, start + MS, &policy(&[]));
        let Some(Action::Ping { to, nonce }) = probe else { panic!("应该探测信标里的地址：{probe:?}") };
        // 回答还在路上，造出来的信标把它从信标的名额里挤了出去。
        for port in 1..=4 {
            path.on_lan_sighting(SocketAddr::from(([192, 168, 1, 66], port)), start + 2 * MS, &policy(&[]));
        }
        assert!(path.candidates.iter().all(|candidate| candidate.addr != lan));
        assert_eq!(path.on_pong(to, &nonce, start + 3 * MS), Some(Change::Up { addr: lan }));
        assert!(path.sources(start + 3 * MS).any(|source| source == lan), "它发来的连接包要认得出来");
        assert_eq!(path.charge(lan, start + 3 * MS), Some(true));
        // 在用的地址不会再被挤掉。
        for port in 5..=20 {
            path.on_lan_sighting(SocketAddr::from(([192, 168, 1, 66], port)), start + 4 * MS, &policy(&[]));
        }
        assert!(path.sources(start + 4 * MS).any(|source| source == lan));
    }

    #[test]
    fn a_private_address_counts_as_lan_only_with_a_beacon_or_a_shared_public_address() {
        let start = Instant::now();
        let private = addr("192.168.1.7:20330");
        let (mut path, _up) = established(private);
        // 两个不相干的网络可以用同一个私有网段（比如经站点之间的隧道连得上）：只凭地址是私有的不算局域网。
        assert_eq!(path.kind(), Some(DirectKind::Reachable));
        assert!(!path.is_lan_active());
        // 两边的公网地址相同，说明在同一个 NAT 后面。
        path.set_same_nat(true);
        assert_eq!(path.kind(), Some(DirectKind::Lan));
        path.set_same_nat(false);
        // 或者对端的信标就是从这个地址发来的。
        path.on_lan_sighting(private, start + Duration::from_secs(1), &policy(&[]));
        assert_eq!(path.kind(), Some(DirectKind::Lan));

        // 公网地址不管怎样都不是局域网。
        let (mut public, _up) = established(addr("203.0.113.7:20330"));
        public.set_same_nat(true);
        assert_eq!(public.kind(), Some(DirectKind::Reachable));
        assert_eq!(DirectPath::new().kind(), None);
    }

    #[test]
    fn the_kind_of_a_direct_path_tells_reachable_punched_and_ipv6_apart() {
        let start = Instant::now();
        let local = [addr("198.51.100.1:20330")];
        // 对端的地址本来就连得上：头一个探测就得到了回答，那时还没有从对端收到过任何东西。
        let (reachable, _up) = established(addr("203.0.113.7:20330"));
        assert_eq!(reachable.kind(), Some(DirectKind::Reachable));

        // 打洞：头一轮探测被对面的 NAT 挡掉，收到对端的回应信令之后发的那一轮才通。
        let peer = addr("203.0.113.7:4000");
        let mut punched = DirectPath::new();
        punched.set_reported(&[peer], start);
        punched.poll(start, &policy(&local));
        let actions = punched.on_signal(&Signal::PunchReply { endpoints: vec![peer] }, start + 100 * MS, &policy(&local));
        let (to, nonce) = pings(&actions)[0];
        assert_eq!(punched.on_pong(to, &nonce, start + 130 * MS), Some(Change::Up { addr: peer }));
        assert_eq!(punched.kind(), Some(DirectKind::Punched));

        // 对端在打洞之前就探测到了本端，本端反过来验证通过：本端的地址本来就连得上，这条路不用打洞，
        // 和对端那边（它的探测头一次就得到了回答）说的一样。
        let mut dialled = DirectPath::new();
        let Some(Action::Ping { to, nonce }) = dialled.on_ping(peer, start) else { panic!("应该反向验证") };
        dialled.on_pong(to, &nonce, start + 20 * MS);
        assert_eq!(dialled.kind(), Some(DirectKind::Reachable));

        // 打洞信令先到，本端已经在那一轮里往对端发了探测，对端的探测才到：两边是在同一轮里碰上的。
        let mut met = DirectPath::new();
        met.set_reported(&[peer], start);
        let volley = met.on_signal(&Signal::PunchRequest { endpoints: vec![peer] }, start, &policy(&local));
        assert!(!pings(&volley).is_empty());
        assert!(met.on_ping(peer, start + 10 * MS).is_some(), "本端那一轮的探测可能被对面挡掉了，照样反向验证");
        let (to, nonce) = pings(&volley)[0];
        met.on_pong(to, &nonce, start + 30 * MS);
        assert_eq!(met.kind(), Some(DirectKind::Punched));

        let (v6, _up) = established(addr("[2001:db8::7]:20330"));
        assert_eq!(v6.kind(), Some(DirectKind::Ipv6));
    }

    #[test]
    fn a_probe_train_on_the_active_address_measures_loss_for_the_cost_comparison() {
        let peer = addr("203.0.113.7:20330");
        let (mut path, up) = established(peer);
        let training = Policy { train: true, ..policy(&[]) };
        let mut sent = 0;
        // 一秒里每 50ms 推进一步：探测包列发出 10 个，每五个丢一个。
        for step in 1..20u32 {
            let now = up + 50 * MS * step;
            for (to, nonce) in pings(&path.poll(now, &training).actions) {
                assert_eq!(to, peer);
                sent += 1;
                assert!(path.expects_pong(peer, &nonce));
                if sent % 5 != 0 {
                    assert_eq!(path.on_pong(peer, &nonce, now + 20 * MS), None);
                }
            }
        }
        assert_eq!(sent, 10);
        // 等没有回答的那两个超时。
        path.poll(up + Duration::from_secs(3), &training);
        let quality = path.quality(up + Duration::from_secs(3)).unwrap();
        assert_eq!((quality.lost, quality.probes), (2, 11), "验证时的一个样本，加上 10 个探测里丢的 2 个");
        assert!(!path.in_doubt(), "探测包列丢了回答不算保活超时");

        // 默认模式不比代价，不发探测包列。
        let (mut quiet, up) = established(peer);
        assert!((1..20u32).all(|step| quiet.poll(up + 50 * MS * step, &policy(&[])).actions.is_empty()));
        assert_eq!(quiet.quality(up).map(|quality| quality.probes), Some(0), "样本不够时不报丢包率");
    }

    #[test]
    fn the_candidate_list_is_bounded_and_forgets_what_is_no_longer_seen() {
        let start = Instant::now();
        let mut path = DirectPath::new();
        let reported = addr("203.0.113.7:20330");
        path.set_reported(&[reported], start);
        for port in 1..=100u16 {
            path.on_ping(SocketAddr::from(([198, 51, 100, 1], port)), start + MS * u32::from(port));
        }
        assert_eq!(path.candidates.len(), MAX_CANDIDATES);
        assert!(path.candidates.iter().any(|candidate| candidate.addr == reported), "对端上报的不会被挤掉");
        assert!(path.pending.len() <= MAX_PENDING);

        path.poll(start + CANDIDATE_TTL + Duration::from_secs(1), &Policy { wanted: false, ..policy(&[]) });
        assert_eq!(path.candidates.iter().map(|candidate| candidate.addr).collect::<Vec<_>>(), [reported]);
        assert!(path.pending.is_empty());

        // 上报的端点换了，旧的也跟着过期。
        let later = start + 2 * CANDIDATE_TTL + Duration::from_secs(2);
        path.set_reported(&[], later);
        path.poll(later, &Policy { wanted: false, ..policy(&[]) });
        assert!(path.candidates.is_empty());
        assert!(!path.learn(addr("0.0.0.0:5"), later) && !path.learn(addr("203.0.113.7:0"), later), "没法发的地址不记");
    }
}
