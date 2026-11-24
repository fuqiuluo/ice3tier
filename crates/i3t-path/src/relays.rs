//! 节点一侧到各个 relay 的联系：UDP 和 TCP 同时试、优先 UDP、掉线重连，以及挂靠哪几个 relay 的选择。
//!
//! 一个 [`RelayLink`] 管到一个 relay 的全部事情。它不直接碰 socket：要发的东西交给 [`Wire`]，
//! 所以整套"先试谁、什么时候换"的规则可以脱离网络来测。
//!
//! 单个 relay 可能拥有多个候选地址（由 controller 收集），其中部分可能不可达。UDP 握手会同时向所有候选地址发送 INIT，
//! 采用最先返回 CHALLENGE 的地址进行后续握手与保活；会话断开后下次重连仍会并发探测全部地址，避免在不可达地址上耗时。
//! 对已返回 CHALLENGE 但未完成握手的地址（如地址冲突、实际应答者为其他节点），本轮不再重试，立即尝试其余候选地址。
//! TCP 则按错峰策略依次并发连接（见 [`crate::tcp`]），上次握手成功的地址排在最前，失败的地址排在最后。
//!
//! # 骨干
//!
//! 当本节点自身作为 relay 时，与其他 relay 的连接同时构成骨干链路：双方需互相建立会话并采用相同的传输协议（[`crate::backbone`]）。
//! UDP 可达时与普通节点一样使用 UDP（此时不并发尝试 TCP）。以下情况下该骨干链路切换为单条 TCP 连接，双向会话共用该连接：
//!
//! - 本节点到对端 relay 的 UDP 握手未完成；
//! - 本节点到对端 relay 的 UDP 会话已建立，但经过 [`ONE_SIDED_GRACE`] 仍未收到对方在本节点 relay 上建立的会话（表明对方无法通过 UDP 到达本节点）；
//! - 对方主动拨入 TCP 连接（由本节点 relay 接受并通知路径层），且本节点尚无活跃 UDP 会话，或对方的会话已迁移至该 TCP 连接。
//!
//! 拨号方协商规则：节点 ID 较小的一方优先主动拨号；若拨号失败（对方不可直连），另一方等待 [`DIAL_DEFER`] 后仍未收到入站连接则主动拨出。
//! 在第二种单向可达场景下，本节点已知对方无法连入自身，因此立即主动拨号。若双方同时拨通，ID 较小的一方保留自建连接，另一方切换复用该连接并关闭自建连接。
//!
//! 切换为 TCP 后，该连接断开时仍按 TCP 重连（与普通节点的 TCP 回退策略相同）。若一端单方面切回 UDP 而另一端仍停留在 TCP，
//! 双向会话分处不同传输通道将导致骨干转发中断；在仅单向 UDP 可达（受防火墙或端口映射限制）的环境下，单方反复切回会导致链路周期性中断十余秒。
//! 因此切回 UDP 需要双向可达证据，并在接收方汇聚确认：
//!
//! - 使用 TCP 期间（无论当前 TCP 是否已连通），每隔 [`backbone_udp_retry`] 在后台尝试一次 UDP 握手，不影响现有 TCP 使用。握手未完成时不改变任何状态：
//!   不计入失败次数，不触发退避，也不修改上报结果。
//! - 后台握手收到对方的 CHALLENGE 时，记录“本节点 UDP 可达对方”，有效期为 [`udp_evidence_ttl`]。
//! - 对方经 UDP 发来的 AUTH 本身可证明对方 UDP 可达本节点。本节点 relay 仅在持有上述双向证据或本节点到对方的 UDP 会话已建立时，
//!   才允许对方将会话迁移至 UDP；否则不建立会话、不应答，并通知路径层对方发起试探（[`crate::BackboneInbox`]），路径层随即主动试探一次（受 [`KNOCK_GAP`] 限制）。
//!   若对方为新版本，其此次请求即构成反向可达证据，因此不受下方退避间隔约束。
//! - 后台握手成功后（对方允许本节点迁回 UDP），本节点退出 TCP 模式，恢复常规 UDP 骨干。在对方跟随切换前，其会话仍停留在该 TCP 连接上：
//!   自建连接需等待对方会话离开后再关闭（过早关闭会导致对方在本节点无会话，进而使转发包被拒绝），
//!   复用连接则在短时间内不再复用（避免被误判为“对方迁至自建 TCP”而再次切回）。
//!   对方发现本节点会话已切至 UDP 后按下一条规则跟随；本端因已有活跃 UDP 会话而接受其 AUTH。
//! - 当对方经 UDP 在本节点建立会话（表明对方处于 UDP 且可达本节点），且本节点近期亦验证 UDP 可达对方时，本节点切回 UDP 重试。
//!   仅满足前半条件不足以触发切换：UDP 完全中断后，对方原有 UDP 会话需等待超时（30 秒）才会过期清除。
//!
//! 早于本次改动的旧版 relay 会接受所有 AUTH 且不在 TCP 上探测 UDP。若仅本节点 UDP 可达对方而反向不可达，本节点每次切回 UDP
//! 都需等待既有规则将双方带回 TCP（耗时数秒至十余秒）。因此，若切回 UDP 后在 [`RETURN_PROBATION`] 内再次退回 TCP，
//! 下次后台尝试 UDP 的间隔将加倍，上限为 [`BACKBONE_RETRY_MAX`]；若切回后保持稳定，则恢复初始间隔。

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use i3t_crypto::{NodeKey, Signature};
use i3t_model::control::TryOutcome;
use i3t_model::netmap::Relay;
use i3t_proto::session::{Accepted, Auth, Echo, Frame, Init, Nonce, Ping, RefusalReason, Refused};
use i3t_proto::{NodeId, PublicKey};

use crate::SessionLeg;
use crate::attach::{Event, Send, Session, Step};
use crate::backbone::Gate;
use crate::estimate::{Estimate, Quality};
use crate::timing::{
    BACKBONE_RETRY_MAX, DIAL_DEFER, ESTIMATE_TTL, KNOCK_GAP, OFFER_RETRY, ONE_SIDED_GRACE, PROBE_INTERVAL, RELAY_RETRY_MAX, RELAY_SURVEY,
    RETURN_PROBATION, Rtt, SETTLE, UDP_HEAD_START, UDP_RETRY, backbone_udp_retry, udp_evidence_ttl,
};

/// 挂靠几个 relay。
pub(crate) const ATTACH_COUNT: usize = 2;
/// 挂靠的 relay 持续无法连接超过该时长后，可被其他 relay 替换。
const FAILING_AFTER: Duration = Duration::from_secs(10);
/// TCP 连接超时阈值。
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 不保持会话的 relay 每分钟问一次延迟（INIT / CHALLENGE），这么久没有回答就算这一次没问到。
const SURVEY_SILENCE: Duration = Duration::from_secs(3);

/// 本节点是谁，用来填帧和签名。
#[derive(Debug, Clone, Copy)]
pub(crate) struct Identity<'a> {
    pub(crate) me: NodeId,
    pub(crate) key: &'a NodeKey,
}

/// [`RelayLink`] 往外发东西的出口。
pub(crate) trait Wire {
    /// 向 relay 的 UDP 地址发一帧。
    fn udp(&mut self, to: SocketAddr, frame: &[u8]);
    /// 往到这个 relay 的 TCP 里发一帧。
    fn tcp(&mut self, frame: &[u8]);
    /// 开始连 relay 的 TCP。连上、断开、收到帧都会回到 [`RelayLink`] 对应的方法上。
    fn tcp_connect(&mut self, addrs: &[SocketAddr]);
    /// 改用这个 relay 拨进来、本节点的 relay 接住的那条 TCP（骨干，见模块文档）。之后往里写、从里收和自己拨的一样。
    /// 返回它的对端地址和 relay 给它的编号；没有这样一条时是 `None`。
    fn tcp_adopt(&mut self) -> Option<(SocketAddr, u64)>;
    /// 关掉到这个 relay 的 TCP。借来的那条只是不再用，它归本节点的 relay。
    fn tcp_close(&mut self);
}

/// 本节点是 relay 时，选路一方告诉 [`RelayLink`] 的骨干上的情况（见模块文档）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Backbone {
    /// 它在本节点的 relay 上的会话绑定在哪里。
    pub(crate) theirs: Option<SessionLeg>,
    /// 它拨进来、等着本节点用的那条 TCP 在 relay 那边的编号。
    pub(crate) offered: Option<u64>,
}

/// 骨干链路通过单条 TCP 连接承载（见模块文档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpLink {
    since: Instant,
    /// 本节点已知对方无法连入，因此不等待对方拨入，由本节点主动拨号。
    must_dial: bool,
    /// 下次在后台尝试 UDP 握手的时刻。
    next_try: Instant,
}

/// relay 拒绝转发请求，原因在于目标路径而非会话本身。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Complaint {
    /// 目标对端未挂靠于该 relay。
    PeerUnattached(NodeId),
    /// 多级中转路径不可达：该 relay 与指定下一跳之间无骨干连接；若为自身节点 ID，表示路径超出网络允许的最大跳数。
    RouteUnavailable(NodeId),
}

/// 现在经这个 relay 收发包走的是哪一种传输。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Leg {
    Udp(SocketAddr),
    Tcp,
}

#[derive(Debug)]
struct TcpLeg {
    session: Session,
    connected: bool,
    started: Instant,
    /// 连上的是哪个地址。
    addr: Option<SocketAddr>,
    /// 这条 TCP 上的会话建起来过。
    established: bool,
    /// 这是别的 relay 拨进来、借来用的那一条，值是 relay 给它的编号（骨干）。
    adopted: Option<u64>,
}

/// 到一个 relay 的联系。
#[derive(Debug)]
pub(crate) struct RelayLink {
    id: NodeId,
    key: PublicKey,
    udp_addrs: Vec<SocketAddr>,
    tcp_addrs: Vec<SocketAddr>,
    /// 本节点自己的地址。relay 的地址里有它们的话不去试：发出去的包会回到本节点自己这里。
    own: Vec<SocketAddr>,
    /// 要不要和它保持会话：它是挂靠的 relay，或者有活跃的对端要经它到达。
    wanted: bool,
    wanted_since: Option<Instant>,
    udp: Session,
    /// UDP 的握手和会话用的地址：回答了这一次握手的 CHALLENGE 的那个。还没有谁回答时是 `None`，INIT 发给每个地址。
    udp_target: Option<SocketAddr>,
    /// UDP 的会话建起来过（之后再断就是"会话没了"，不是"握手失败"）。
    udp_established: bool,
    /// 这一轮里回答了 CHALLENGE、握手却没有走完的地址。这一轮剩下的时间里不再试。
    udp_shunned: Vec<SocketAddr>,
    /// `udp_target` 变过，收包时按地址认 relay 的表要重建（见 [`take_target_changed`](Self::take_target_changed)）。
    target_changed: bool,
    tcp: Option<TcpLeg>,
    /// 最近一次 TCP 上握手成功的地址，下一次先连它；握手失败的地址下一次排最后。
    tcp_good: Option<SocketAddr>,
    tcp_bad: Option<SocketAddr>,
    /// 上一个 TCP 会话保留的链路测量值。断线重连仍属于同一链路，新会话继续沿用：
    /// 否则频繁中断的链路每次重连后都显得质量良好，会导致延迟优先选路反复切回。
    tcp_measured: Estimate,
    /// 最近一次因 UDP 握手未完成而回退至 TCP 建立会话。此类会话断开重连时直接尝试 TCP，不再预留 1 秒 UDP 先行窗口，
    /// 避免重复无效等待；连上后仍定期尝试切回 UDP。
    fell_back: bool,
    /// 会话断没断过，见 [`is_settled`](Self::is_settled)。
    steadiness: Steadiness,
    /// 这一轮连接尝试（UDP 和 TCP 同时）是什么时候开始的。
    attempt: Option<Instant>,
    retry_at: Instant,
    failures: u32,
    /// 走着 TCP 的时候，下一次试 UDP 的时刻。
    udp_retry_at: Instant,
    /// relay 看到的本节点 UDP 地址。
    observed: Option<(SocketAddr, Instant)>,
    /// 不保持会话的 relay 靠一个 INIT / CHALLENGE 的往返测延迟：relay 那边不留任何状态。
    survey: Option<(Nonce, Instant)>,
    surveyed: Option<(Duration, Instant)>,
    next_survey: Instant,
    /// 会话保活的间隔，见 [`set_probe_interval`](Self::set_probe_interval)。
    probe_interval: Duration,
    /// 要不要给这段链路发探测包列。
    training: bool,
    /// 最近一次试的结果和时刻（见 [`last_try`](Self::last_try)）。
    tried: Option<(TryOutcome, Instant)>,
    /// 它最近看到的本节点的 IP：UDP 和 TCP 上的会话应答里都有。TCP 上的那个不能当直连的候选端点，但出口地址就是它。
    seen: Option<(IpAddr, Instant)>,
    /// 本节点是 relay 时最近一次 [`poll`](Self::poll) 交进来的骨干上的情况；不是时是 `None`。
    backbone: Option<Backbone>,
    /// 骨干链路已切换为 TCP 模式。
    tcp_link: Option<TcpLink>,
    /// 到对端的 UDP 会话已建立、但对方尚未经 UDP 在本节点 relay 建立会话的起始时刻。
    one_sided_since: Option<Instant>,
    /// 曾复用但失败的连接（握手未完成或会话中断），或切回 UDP 时释放的连接及对应时刻：[`OFFER_RETRY`] 内不再复用。
    spoiled_offer: Option<(u64, Instant)>,
    /// 本节点经 UDP 发送的 INIT 最近一次收到对方 CHALLENGE 的时刻（证明双向 UDP 可达）。
    /// 切换为 TCP 模式时清除，避免使用过期证据。
    udp_reached: Option<Instant>,
    /// 骨干链路最近一次从 TCP 切回 UDP 的时刻；若短时间内再次退回 TCP，用于退避判断。
    returned: Option<Instant>,
    /// 走着 TCP 时多久在后台试一次 UDP（见模块文档的退避）。
    backbone_retry: Duration,
    /// 最近一次因为它敲门而试 UDP 的时刻。
    knock_answered: Option<Instant>,
    /// 回到 UDP 时放下、还没有关的那条本节点拨的 TCP，和放下它的时刻（见 [`linger`](Self::linger)）。它还在 [`Wire`] 那里。
    lingering: Option<Instant>,
}

impl RelayLink {
    pub(crate) fn new(relay: &Relay, now: Instant) -> Self {
        Self {
            id: relay.id,
            key: relay.key,
            udp_addrs: relay.udp.clone(),
            tcp_addrs: relay.tcp.clone(),
            own: Vec::new(),
            wanted: false,
            wanted_since: None,
            udp: Session::new(),
            udp_target: None,
            udp_established: false,
            udp_shunned: Vec::new(),
            target_changed: false,
            tcp: None,
            tcp_good: None,
            tcp_bad: None,
            tcp_measured: Estimate::new(),
            fell_back: false,
            steadiness: Steadiness::Unbroken,
            attempt: None,
            retry_at: now,
            failures: 0,
            udp_retry_at: now,
            observed: None,
            survey: None,
            surveyed: None,
            next_survey: now,
            probe_interval: PROBE_INTERVAL,
            training: false,
            tried: None,
            seen: None,
            backbone: None,
            tcp_link: None,
            one_sided_since: None,
            spoiled_offer: None,
            udp_reached: None,
            returned: None,
            backbone_retry: backbone_udp_retry(),
            knock_answered: None,
            lingering: None,
        }
    }

    /// UDP 上的会话多久保活一次。本节点是 relay 时，到别的 relay 的会话就是骨干上的连接，探测得更勤。
    ///
    /// TCP 上的会话不跟着变，骨干改走 TCP 时也一样：TCP 不丢帧，探测得再勤也只多测出几个延迟样本，
    /// 反倒让一条丢包的 TCP 更容易被判为断开（一个探测卡在重传里，后面的全跟着超时）。所以走 TCP 的骨干每 5 秒测一次。
    pub(crate) fn set_probe_interval(&mut self, interval: Duration) {
        self.probe_interval = interval;
        self.udp.set_interval(interval);
    }

    /// 这段链路是不是在正在评估的候选路径上：是的话定期发探测包列来估丢包。
    pub(crate) fn set_training(&mut self, training: bool) {
        self.training = training;
        self.udp.set_training(training);
        if let Some(tcp) = &mut self.tcp {
            tcp.session.set_training(training);
        }
    }

    /// 根据 netmap 更新该 relay 的信息。当前活跃地址即使不在新列表中也继续沿用，待会话断开后再仅尝试新地址。
    pub(crate) fn update(&mut self, relay: &Relay) {
        self.key = relay.key;
        if self.udp_addrs != relay.udp || self.tcp_addrs != relay.tcp {
            self.udp_addrs.clone_from(&relay.udp);
            self.tcp_addrs.clone_from(&relay.tcp);
            self.udp_shunned.retain(|addr| relay.udp.contains(addr));
        }
    }

    /// 本节点自己的地址变了。
    pub(crate) fn set_own(&mut self, own: &[SocketAddr]) {
        own.clone_into(&mut self.own);
    }

    /// 要按来源地址认出这个 relay 的那些地址：netmap 里的，加上正在用的那个（它可能已经不在 netmap 里了）。
    pub(crate) fn dispatch_addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.udp_addrs.iter().copied().chain(self.udp_target.filter(|target| !self.udp_addrs.contains(target)))
    }

    /// UDP 的握手和会话现在用的地址；还没有哪个地址回答时是 `None`。
    pub(crate) const fn udp_target(&self) -> Option<SocketAddr> {
        self.udp_target
    }

    /// `udp_target` 自上次问过之后变过没有。
    pub(crate) fn take_target_changed(&mut self) -> bool {
        std::mem::take(&mut self.target_changed)
    }

    fn set_target(&mut self, target: Option<SocketAddr>) {
        if self.udp_target != target {
            self.udp_target = target;
            self.target_changed = true;
        }
    }

    /// 这一轮还可以试的 UDP 地址。
    fn udp_candidates(&self) -> Vec<SocketAddr> {
        self.udp_addrs.iter().copied().filter(|addr| !self.own.contains(addr) && !self.udp_shunned.contains(addr)).collect()
    }

    fn has_udp(&self) -> bool {
        self.udp_addrs.iter().any(|addr| !self.own.contains(addr) && !self.udp_shunned.contains(addr))
    }

    /// 去连 TCP 的顺序：上一次握手成功的在最前，失败的在最后，别的照 netmap 里的顺序。
    fn tcp_candidates(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = self.tcp_addrs.iter().copied().filter(|addr| !self.own.contains(addr)).collect();
        addrs.sort_by_key(|addr| match Some(*addr) {
            good if good == self.tcp_good => 0,
            bad if bad == self.tcp_bad => 2,
            _ => 1,
        });
        addrs
    }

    pub(crate) const fn is_wanted(&self) -> bool {
        self.wanted
    }

    /// 要不要和这个 relay 保持会话。不要了就立刻放手：停止保活、关掉 TCP，relay 那边的会话会自己过期。
    pub(crate) fn set_wanted(&mut self, wanted: bool, now: Instant, wire: &mut dyn Wire) {
        if self.wanted == wanted {
            return;
        }
        self.wanted = wanted;
        self.wanted_since = wanted.then_some(now);
        if wanted {
            self.retry_at = now;
            self.failures = 0;
        } else {
            self.udp.stop();
            self.udp_established = false;
            self.set_target(None);
            let lingering = self.lingering.take().is_some();
            if self.retire_tcp().is_some() || lingering {
                wire.tcp_close();
            }
            self.attempt = None;
            self.steadiness = Steadiness::Unbroken;
            self.tcp_link = None;
            self.one_sided_since = None;
        }
    }

    /// 放下 TCP 那条腿，把它测到的东西留下。
    fn retire_tcp(&mut self) -> Option<TcpLeg> {
        let tcp = self.tcp.take()?;
        self.tcp_measured = tcp.session.measured().clone();
        Some(tcp)
    }

    /// 到它的会话信得过：建立之后没有断过，或者断过、重新连上之后又保持了 [`SETTLE`] 那么久。
    ///
    /// 一条时好时坏的链路，会话断了重连之后头几秒看起来总是好的。等它保持够久再把流量换过去，
    /// 免得流量跟着它一断一连地来回换。
    pub(crate) fn is_settled(&self, now: Instant) -> bool {
        self.leg().is_some()
            && match self.steadiness {
                Steadiness::Unbroken => true,
                Steadiness::Down => false,
                Steadiness::Recovered(at) => now.saturating_duration_since(at) >= SETTLE,
            }
    }

    /// 建立好的会话没了。
    fn session_lost(&mut self) {
        self.steadiness = Steadiness::Down;
    }

    /// 会话已建立。从 TCP 切回 UDP 时会话未曾中断，不视为断线重连。
    fn session_up(&mut self, now: Instant) {
        if self.steadiness == Steadiness::Down {
            self.steadiness = Steadiness::Recovered(now);
        }
    }

    /// 现在能经它收发包的传输。UDP 和 TCP 都通时用 UDP。
    pub(crate) fn leg(&self) -> Option<Leg> {
        if self.udp.is_up() {
            return self.udp_target.map(Leg::Udp);
        }
        self.tcp.as_ref().filter(|tcp| tcp.session.is_up()).map(|_| Leg::Tcp)
    }

    /// 到它的延迟：有会话时是会话上测的。
    pub(crate) fn rtt(&self) -> Option<Rtt> {
        match self.leg()? {
            Leg::Udp(_) => self.udp.rtt(),
            Leg::Tcp => self.tcp.as_ref().and_then(|tcp| tcp.session.rtt()),
        }
    }

    /// 报给别的节点的延迟（挂靠表里的那个数）：它们拿它当"经这个 relay 到本节点"的最后一段。
    ///
    /// 使用 UDP 时上报平滑延迟；使用 TCP 时上报与本节点计算路径代价相同的指标（最近数分钟的均值，包含停顿与卡死时长，
    /// 见 `crate::estimate`）：避免同一 TCP 链路两端衡量标准不一致，导致对端上报的平滑延迟偏低而使该路径显得优于实际质量。
    /// 实际网络中曾出现频繁断连的 TCP 会话持续上报最低延迟，致使选路反复切换并在半分钟后再次因断连切走。估计过期时回退至平滑延迟。
    pub(crate) fn reported_rtt(&self, now: Instant) -> Option<Rtt> {
        match self.leg()? {
            Leg::Udp(_) => self.udp.rtt(),
            Leg::Tcp => {
                let session = &self.tcp.as_ref()?.session;
                session.quality(now).map(|quality| Rtt::new(quality.rtt)).or_else(|| session.rtt())
            }
        }
    }

    /// 现在在用的那个会话上测到的延迟、抖动和丢包。没有会话，或者估计过期了，是 `None`。
    pub(crate) fn quality(&self, now: Instant) -> Option<Quality> {
        match self.leg()? {
            Leg::Udp(_) => self.udp.quality(now),
            Leg::Tcp => self.tcp.as_ref().and_then(|tcp| tcp.session.quality(now)),
        }
    }

    /// 选挂靠对象时用的延迟估计：有会话的用会话上测的，没有的用最近一次单独测的；都没有或者过期了就是 `None`。
    ///
    /// 会话上测的和报给别的节点的是同一个数（[`reported_rtt`](Self::reported_rtt)）：走 TCP 时是最近几分钟的平均，
    /// 不是平滑延迟。平滑延迟撞上一次停顿就高出几成，半分钟才落回去；真实链路上一个只有 TCP 的节点到两个延迟相近的
    /// relay，挂靠就这样一小时来回换了三十来次。
    pub(crate) fn estimate(&self, now: Instant) -> Option<Duration> {
        let surveyed = self.surveyed.filter(|(_, at)| now.saturating_duration_since(*at) < ESTIMATE_TTL).map(|(rtt, _)| rtt);
        self.reported_rtt(now).map(Rtt::get).or(surveyed)
    }

    /// 需要连接该 relay 但持续未建立会话。
    pub(crate) fn is_failing(&self, now: Instant) -> bool {
        self.leg().is_none() && self.wanted_since.is_some_and(|since| now.saturating_duration_since(since) > FAILING_AFTER)
    }

    /// 在用的会话可疑：有保活没有得到回答。
    pub(crate) fn in_doubt(&self) -> bool {
        match self.leg() {
            Some(Leg::Udp(_)) => self.udp.in_doubt(),
            Some(Leg::Tcp) => self.tcp.as_ref().is_some_and(|tcp| tcp.session.in_doubt()),
            None => false,
        }
    }

    /// relay 看到的本节点 UDP 地址，只有 UDP 会话上得到的才算。
    pub(crate) fn observed(&self, now: Instant) -> Option<SocketAddr> {
        self.observed.filter(|(_, at)| now.saturating_duration_since(*at) < ESTIMATE_TTL).map(|(addr, _)| addr)
    }

    /// 最近一次试它的结果和时刻。现在有会话的就是现在、会话走的传输；不然是最近一次会话的尝试（UDP 和 TCP 一起试的）
    /// 或者每分钟一次的 UDP 询问得到了回答。只有 UDP 询问没有回答、还没用会话试过的，没有结果（见 [`survey_silent`](Self::survey_silent)）。
    pub(crate) fn last_try(&self, now: Instant) -> Option<(TryOutcome, Instant)> {
        match self.leg() {
            Some(Leg::Udp(_)) => Some((TryOutcome::Udp, now)),
            Some(Leg::Tcp) => Some((TryOutcome::Tcp, now)),
            None => self.tried,
        }
    }

    /// 它最近看到的本节点的 IP。有会话时随保活的应答刷新；会话没了之后照旧是最后看到的那个，过了估计的有效期就不算。
    pub(crate) fn seen_as(&self, now: Instant) -> Option<IpAddr> {
        self.seen.filter(|(_, at)| now.saturating_duration_since(*at) < ESTIMATE_TTL).map(|(ip, _)| ip)
    }

    /// 未保持会话时每分钟一次的 UDP 探测本次未收到响应（UDP 不可达，TCP 尚未尝试）。
    pub(crate) fn survey_silent(&self, now: Instant) -> bool {
        !self.wanted && self.survey.is_some_and(|(_, sent)| now.saturating_duration_since(sent) >= SURVEY_SILENCE)
    }

    /// 推进定时器。`urgent` 表示当前有数据包经该 relay 发出，但已有一段时间未收到其任何响应。
    /// `survey`：未保持会话时是否定期探测延迟。`backbone`：本节点作为 relay 时的骨干状态（见模块文档），非 relay 时为 `None`。
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        who: Identity<'_>,
        urgent: bool,
        survey: bool,
        backbone: Option<Backbone>,
        wire: &mut dyn Wire,
    ) {
        if !self.wanted {
            if survey {
                self.survey(now, who, wire);
            }
            return;
        }
        if backbone.is_none() && self.tcp_link.take().is_some() {
            // 本节点不再作为 relay：该链路不再属于骨干，恢复普通节点策略（优先尝试 UDP，TCP 作为回退）。
            self.one_sided_since = None;
        }
        if backbone.is_none() && self.lingering.take().is_some() && self.tcp.is_none() {
            wire.tcp_close();
        }
        self.backbone = backbone;
        if let Some(backbone) = backbone {
            self.review_backbone(now, who, backbone, wire);
        }
        let step = self.udp.poll(now, urgent);
        self.apply_udp(step, now, who, wire);
        self.poll_tcp(now, who, urgent, wire);

        if self.udp.is_up() {
            if self.retire_tcp().is_some() {
                tracing::info!(relay = %self.id, "到 relay 的 UDP 会话已建立，关闭 TCP 回退连接");
                wire.tcp_close();
            }
            return;
        }
        self.try_udp_beside_tcp(now, who, wire);
        if self.tcp.as_ref().is_some_and(|tcp| tcp.session.is_up()) {
            // 当前使用 TCP：定期重试 UDP，成功则切回；骨干 TCP 模式则按骨干规则在后台试探（见上一步及模块文档）。
            if self.tcp_link.is_none() && self.udp.is_idle() && now >= self.udp_retry_at && self.has_udp() {
                self.udp_retry_at = now + UDP_RETRY;
                self.start_udp(now, who, wire);
            }
            return;
        }
        match self.attempt {
            None if now >= self.retry_at => self.begin_attempt(now, who, wire),
            None => {}
            Some(started) => {
                // 先给 UDP 预留先行时间窗口；超时仍未完成握手时，放行暂停在 cookie 阶段的 TCP 握手继续执行。
                // 若上一轮已确认 UDP 握手未完成，本轮不再预留先行窗口。
                let head_start = if self.failures == 0 { UDP_HEAD_START } else { Duration::ZERO };
                let head_start_over = now.saturating_duration_since(started) >= head_start || self.udp.is_idle();
                if head_start_over
                    && let Some(tcp) = &mut self.tcp
                    && let Some(send) = tcp.session.release(now)
                {
                    if self.fell_back {
                        tracing::info!(relay = %self.id, "上一次与 relay 的 UDP 握手未完成，本次直接通过 TCP 建立会话");
                    } else {
                        tracing::info!(relay = %self.id, "与 relay 的 UDP 握手未完成，继续通过 TCP 建立会话");
                    }
                    self.send_tcp(send, who, wire);
                }
                // 骨干切换为 TCP 时本轮仅尝试 TCP：后台 UDP 试探独立运行，无需等待。
                if self.tcp.is_none() && (self.tcp_link.is_some() || self.udp.is_idle()) {
                    self.attempt_failed(now);
                }
            }
        }
    }

    fn poll_tcp(&mut self, now: Instant, who: Identity<'_>, urgent: bool, wire: &mut dyn Wire) {
        let Some(tcp) = &mut self.tcp else { return };
        if !tcp.connected {
            if now.saturating_duration_since(tcp.started) >= TCP_CONNECT_TIMEOUT {
                tracing::debug!(relay = %self.id, "到 relay 的 TCP 连接超时");
                self.retire_tcp();
                wire.tcp_close();
            }
            return;
        }
        let step = tcp.session.poll(now, urgent);
        self.apply_tcp(step, now, who, wire);
    }

    /// 评估骨干链路是否及如何切换为 TCP（见模块文档）。本节点为 relay 时每轮调用。
    fn review_backbone(&mut self, now: Instant, who: Identity<'_>, backbone: Backbone, wire: &mut dyn Wire) {
        self.linger(now, backbone.theirs, wire);
        let offered =
            backbone.offered.filter(|offer| self.spoiled_offer.is_none_or(|(spoiled, at)| spoiled != *offer || now >= at + OFFER_RETRY));
        let using = self.tcp.as_ref().and_then(|tcp| tcp.adopted);
        // 即使本节点到对方的 UDP 会话仍通，只要对方的会话已迁至该 TCP 连接（其侧 UDP 不可达），双方均需统一使用该 TCP 连接。
        let moved = |offer: u64| backbone.theirs == Some(SessionLeg::Accepted(offer));
        if let Some(offer) = offered.filter(|offer| using != Some(*offer) && (!self.udp.is_up() || moved(*offer))) {
            // 自己拨的那条已经通了、按编号又该本节点拨的话留着它：对方看到本节点的会话从它接的那条上来，会放下它自己拨的。
            let own_wins = who.me < self.id && self.tcp.as_ref().is_some_and(|tcp| tcp.adopted.is_none() && tcp.session.is_up());
            if !own_wins {
                self.adopt(offer, now, who, wire);
                return;
            }
        }
        if self.tcp_link.is_none() && !self.udp.is_up() && self.tcp.as_ref().is_some_and(|tcp| tcp.session.is_up()) {
            // 本节点启用 relay 角色前已按普通节点策略回退至 TCP：该链路已在 TCP 上，转按骨干 TCP 规则沿用。
            tracing::info!(relay = %self.id, "本节点启用 relay 角色前已通过 TCP 连接到该 relay，骨干链路沿用该 TCP 连接");
            self.enter_tcp_link(now, false);
        }
        if self.tcp_link.is_some() {
            // 对方已通过 UDP 在本节点建立会话且本节点近期验证 UDP 可达对方：切回 UDP 重试，若失败则重新切回 TCP。
            // 缺少后一项证据时不可切回：UDP 完全中断后，对方原有的 UDP 会话需等待 30 秒超时才会清除，
            // 若据此切回会导致反复握手失败，既无法恢复 UDP 也无法建立 TCP。后台 UDP 试探收到回应后即产生该证据。
            if backbone.theirs == Some(SessionLeg::Udp) && self.udp_reaches(now) {
                tracing::info!(relay = %self.id, "对端 relay 已通过 UDP 与本节点建立会话且本节点 UDP 可达，骨干链路切回 UDP 重试");
                // 对方会话已迁离，该 TCP 连接不再需要。
                if self.leave_tcp_link(now).is_some() {
                    wire.tcp_close();
                }
                self.retry_at = now;
            }
            return;
        }
        match (self.udp.is_up(), backbone.theirs) {
            (true, Some(SessionLeg::Udp)) | (false, _) => self.one_sided_since = None,
            (true, Some(SessionLeg::Accepted(_) | SessionLeg::Dialled(_)) | None) => {
                let since = *self.one_sided_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= ONE_SIDED_GRACE {
                    tracing::info!(relay = %self.id, "到该 relay 的 UDP 会话已建立，但对方持续未通过 UDP 与本节点建立会话，骨干链路改由本节点主动拨出 TCP");
                    self.enter_tcp_link(now, true);
                }
            }
        }
    }

    /// 骨干链路切换为 TCP 模式：停止 UDP 会话并立即按 TCP 规则重连。若上次切回 UDP 后短时间内再次退回，后台 UDP 重试间隔加倍（见模块文档）。
    fn enter_tcp_link(&mut self, now: Instant, must_dial: bool) {
        self.backbone_retry = Self::next_backbone_retry(self.backbone_retry, self.returned.take(), now);
        if self.backbone_retry > backbone_udp_retry() {
            tracing::info!(
                relay = %self.id,
                wait = self.backbone_retry.as_secs(),
                "骨干链路切回 UDP 后短时间内再次退回 TCP，后台 UDP 重试间隔已加倍（秒）"
            );
        }
        self.tcp_link = Some(TcpLink { since: now, must_dial, next_try: now + self.backbone_retry });
        self.udp_reached = None;
        self.one_sided_since = None;
        self.udp.stop();
        self.udp_established = false;
        self.udp_shunned.clear();
        self.set_target(None);
        self.attempt = None;
        self.retry_at = now;
    }

    /// 改走 TCP 时，之后在后台试 UDP 的间隔：上一次回到 UDP（`returned`）不到 [`RETURN_PROBATION`] 的话是现在的两倍，
    /// 最多 [`BACKBONE_RETRY_MAX`]；回去之后保持住了、或者从来没有回去过的，从 [`backbone_udp_retry`] 起。
    fn next_backbone_retry(current: Duration, returned: Option<Instant>, now: Instant) -> Duration {
        match returned {
            Some(at) if now.saturating_duration_since(at) < RETURN_PROBATION => current.saturating_mul(2).min(BACKBONE_RETRY_MAX),
            Some(_) | None => backbone_udp_retry(),
        }
    }

    /// 骨干链路退出 TCP 模式、切回 UDP：本节点会话不再使用该 TCP 连接。返回释放的连接，是否关闭由调用方决定
    /// （复用连接仅停止使用，关闭由 relay 侧管理）。
    ///
    /// 复用连接释放后在 [`OFFER_RETRY`] 内不再复用：在对方跟随切回前，其会话仍停留在该 TCP 连接上，
    /// 若立即复用会被误判为“对方迁至自建 TCP”（[`review_backbone`](Self::review_backbone)）。
    /// 若切回 UDP 确实失败，对方将拨入新连接，或由本节点按单向可达规则主动拨号。
    fn leave_tcp_link(&mut self, now: Instant) -> Option<TcpLeg> {
        self.tcp_link = None;
        self.returned = Some(now);
        self.attempt = None;
        let tcp = self.retire_tcp()?;
        if let Some(offer) = tcp.adopted {
            self.spoiled_offer = Some((offer, now));
        }
        Some(tcp)
    }

    /// 当本节点先行切回 UDP 且释放的是自建 TCP 连接时暂不立即关闭：对方尚未跟随切换，其在本节点 relay 上的会话仍绑定在该 TCP 连接上，
    /// 立即关闭会导致该会话中断、期间转发的数据报被拒绝，使源节点避开该链路十余秒；暂缓关闭则仅静默丢包。
    /// 待对方会话迁移离开（转至 UDP 或断开）后再关闭，最长等待 [`ONE_SIDED_GRACE`]，超时后按常规规则重建。
    fn linger(&mut self, now: Instant, theirs: Option<SessionLeg>, wire: &mut dyn Wire) {
        let Some(since) = self.lingering else { return };
        if matches!(theirs, Some(SessionLeg::Dialled(_))) && now.saturating_duration_since(since) < ONE_SIDED_GRACE {
            return;
        }
        self.lingering = None;
        if self.tcp.is_none() {
            wire.tcp_close();
        }
    }

    /// 骨干链路使用 TCP 时，到期后在后台尝试一次 UDP 握手（见模块文档）。现有 TCP 正常使用；握手未完成时不改变状态（见 [`apply_udp`](Self::apply_udp)）。
    fn try_udp_beside_tcp(&mut self, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        let Some(link) = &mut self.tcp_link else { return };
        if now < link.next_try {
            return;
        }
        link.next_try = now + self.backbone_retry;
        // 若由对方请求触发的试探尚未结束，则复用该次尝试。
        if self.udp.is_idle() && self.has_udp() {
            tracing::debug!(relay = %self.id, "骨干链路当前使用 TCP，开始在后台尝试 UDP 握手");
            self.start_udp(now, who, wire);
        }
    }

    /// 收到对端 relay 经 UDP 发来的试探请求：本节点 relay 因缺乏反向 UDP 可达证据而拦截了其 AUTH（[`crate::BackboneInbox::knocked`]）。
    ///
    /// 若骨干链路当前使用 TCP，则立即发起一次 UDP 尝试，不受后台退避间隔限制（对方为新版本且已证明其方向可达）。
    /// 若当前正在尝试或在 [`KNOCK_GAP`] 内已响应过，则忽略；未处于 TCP 模式时忽略（本节点 relay 的门控状态尚未同步）。
    pub(crate) fn on_knock(&mut self, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        let answered_lately = self.knock_answered.is_some_and(|at| now.saturating_duration_since(at) < KNOCK_GAP);
        if self.tcp_link.is_none() || answered_lately || !self.udp.is_idle() || !self.has_udp() {
            return;
        }
        self.knock_answered = Some(now);
        tracing::debug!(relay = %self.id, "收到对端 relay 的 UDP 握手请求，当前骨干链路使用 TCP，立即发起 UDP 尝试");
        self.start_udp(now, who, wire);
    }

    /// 控制本节点 relay 是否允许该对端经 UDP 迁移会话（[`crate::BackboneInbox::admits_udp`]）。
    /// 当骨干链路未使用 TCP 或本节点到对方的 UDP 会话已建立时返回 `None`（直接允许，沿用常规行为）。
    pub(crate) fn udp_gate(&self) -> Option<Gate> {
        if self.tcp_link.is_none() || self.udp.is_up() {
            return None;
        }
        Some(self.udp_reached.map_or(Gate::Closed, |at| Gate::OpenUntil(at + udp_evidence_ttl())))
    }

    /// 本节点近期验证过 UDP 可达对方（`udp_reached`），且该证据仍在有效期内。
    fn udp_reaches(&self, now: Instant) -> bool {
        self.udp_reached.is_some_and(|at| now < at + udp_evidence_ttl())
    }

    /// 改用对方拨进来的第 `offer` 条 TCP，在上面建本节点的会话。自己拨的那条（有的话）放下。
    fn adopt(&mut self, offer: u64, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        if self.tcp_link.is_none() {
            self.enter_tcp_link(now, false);
        }
        if self.retire_tcp().is_some() {
            wire.tcp_close();
        }
        let Some((addr, accepted)) = wire.tcp_adopt() else { return };
        tracing::info!(relay = %self.id, %addr, conn = accepted, "对端 relay 已拨入 TCP 连接，骨干链路两端会话复用该连接");
        let mut session = Session::over_tcp(self.tcp_measured.clone());
        session.set_training(self.training);
        let send = session.start(now, false);
        self.lingering = None;
        self.tcp = Some(TcpLeg { session, connected: true, started: now, addr: Some(addr), established: false, adopted: Some(offer) });
        self.attempt = Some(now);
        self.send_tcp(send, who, wire);
    }

    /// 判断骨干走 TCP 时本节点当前是否应主动拨号：节点 ID 较小的一方先拨，另一方延迟后拨（见模块文档）。
    fn may_dial(&self, link: TcpLink, now: Instant, who: Identity<'_>) -> bool {
        link.must_dial || who.me < self.id || now.saturating_duration_since(link.since) >= DIAL_DEFER
    }

    fn begin_attempt(&mut self, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        if self.backbone.is_some() {
            return self.begin_backbone_attempt(now, who, wire);
        }
        self.attempt = Some(now);
        let tcp_addrs = self.tcp_candidates();
        let tcp_only = self.fell_back && !tcp_addrs.is_empty();
        if tcp_only {
            // 定期试 UDP 的握手要是正好进行到一半，放下它：relay 上一个节点只有一个会话，两边一起握手会互相顶掉。
            self.udp.stop();
            self.set_target(None);
        } else if self.has_udp() {
            self.start_udp(now, who, wire);
        }
        if !tcp_addrs.is_empty() {
            let mut session = Session::over_tcp(self.tcp_measured.clone());
            session.set_training(self.training);
            self.lingering = None;
            self.tcp = Some(TcpLeg { session, connected: false, started: now, addr: None, established: false, adopted: None });
            wire.tcp_connect(&tcp_addrs);
        }
        if !self.has_udp() && tcp_addrs.is_empty() {
            tracing::warn!(relay = %self.id, "netmap 中该 relay 无可用地址，无法建立连接");
            self.attempt_failed(now);
        }
    }

    /// 骨干上的一次尝试：还没改走 TCP 时只试 UDP；改走了 TCP 时用对方拨进来的那条，没有的话轮到本节点拨就拨。
    fn begin_backbone_attempt(&mut self, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        let Some(link) = self.tcp_link else {
            if self.has_udp() {
                self.attempt = Some(now);
                self.start_udp(now, who, wire);
            } else {
                // netmap 里没有能试的 UDP 地址：直接走 TCP。
                self.enter_tcp_link(now, false);
            }
            return;
        };
        let tcp_addrs = self.tcp_candidates();
        if !self.may_dial(link, now, who) {
            // 等对方拨进来（它拨进来时 `review_backbone` 马上就用）；等不到的话到时候自己拨。
            self.retry_at = link.since + DIAL_DEFER;
            return;
        }
        if tcp_addrs.is_empty() {
            tracing::warn!(relay = %self.id, "到该 relay 的 UDP 不可达且 netmap 中无其 TCP 地址，等待对方主动拨入");
            self.attempt = Some(now);
            self.attempt_failed(now);
            return;
        }
        tracing::info!(relay = %self.id, "到该 relay 的骨干链路使用 TCP，由本节点主动拨号");
        self.attempt = Some(now);
        let mut session = Session::over_tcp(self.tcp_measured.clone());
        session.set_training(self.training);
        self.lingering = None;
        self.tcp = Some(TcpLeg { session, connected: false, started: now, addr: None, established: false, adopted: None });
        wire.tcp_connect(&tcp_addrs);
    }

    fn attempt_failed(&mut self, now: Instant) {
        self.tried = Some((TryOutcome::Unreached, now));
        self.attempt = None;
        self.fell_back = false;
        self.failures = self.failures.saturating_add(1);
        self.udp_shunned.clear();
        if self.backbone.is_some() && self.tcp_link.is_none() {
            // 骨干链路 UDP 握手未完成：立即切换为 TCP，不进入退避等待。
            tracing::info!(relay = %self.id, "与该 relay 的 UDP 握手未完成，骨干链路切换为 TCP");
            self.enter_tcp_link(now, false);
            return;
        }
        let wait = retry_delay(self.failures);
        self.retry_at = now + wait;
        tracing::info!(relay = %self.id, failures = self.failures, "无法连接 relay，{} 秒后重试", wait.as_secs());
    }

    /// 在用的会话没了：马上重连。同一个 relay 掉线时挂靠它的节点会同时重连，所以带一点随机的延迟错开。
    fn reconnect_soon(&mut self, now: Instant) {
        self.session_lost();
        self.attempt = None;
        self.failures = 0;
        self.udp_shunned.clear();
        self.retry_at = now + jitter(Duration::from_millis(300));
    }

    /// 开始一次 UDP 握手：INIT 发给每个还可以试的地址。
    fn start_udp(&mut self, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        self.set_target(None);
        self.udp_established = false;
        let send = self.udp.start(now, false);
        self.send_udp(send, who, wire);
    }

    /// 握手还没有地址回答时 INIT（和它的重发）发给每个地址；之后只发给回答了的那个。
    fn send_udp(&mut self, send: Send, who: Identity<'_>, wire: &mut dyn Wire) {
        let frame = self.encode(send, who);
        match (send, self.udp_target) {
            (_, Some(to)) => wire.udp(to, &frame),
            (Send::Init { .. }, None) => {
                for to in self.udp_candidates() {
                    wire.udp(to, &frame);
                }
            }
            // AUTH 和 PING 只在有地址回答过之后才会发。
            (Send::Auth { .. } | Send::Ping { .. }, None) => {}
        }
    }

    fn send_tcp(&mut self, send: Send, who: Identity<'_>, wire: &mut dyn Wire) {
        wire.tcp(&self.encode(send, who));
    }

    fn encode(&self, send: Send, who: Identity<'_>) -> Vec<u8> {
        match send {
            Send::Init { nonce } => Init { node: who.me, nonce }.to_bytes().to_vec(),
            Send::Auth { nonce, cookie } => {
                let message = Auth::signed_message(self.id, who.me, &nonce, &cookie);
                let signature = *who.key.sign(Auth::PURPOSE, &message).as_bytes();
                Auth { node: who.me, nonce, cookie, signature }.to_bytes().to_vec()
            }
            Send::Ping { nonce } => Ping { node: who.me, nonce }.to_bytes().to_vec(),
        }
    }

    fn apply_udp(&mut self, step: Step, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        if let Some(send) = step.send {
            self.send_udp(send, who, wire);
        }
        match step.event {
            Some(Event::Up { observed }) => {
                self.observed = Some((observed, now));
                self.seen = Some((observed.ip().to_canonical(), now));
                self.tried = Some((TryOutcome::Udp, now));
                self.attempt = None;
                self.failures = 0;
                self.fell_back = false;
                self.udp_established = true;
                self.udp_shunned.clear();
                self.session_up(now);
                let via = self.udp_target.map(|addr| addr.to_string()).unwrap_or_default();
                tracing::info!(relay = %self.id, %observed, %via, "到 relay 的中转会话建立（UDP）");
                if self.tcp_link.is_some() {
                    // 对方允许本节点迁回 UDP（表明其侧确认 UDP 可达）：该链路切回 UDP，对方观测到后随之切回。
                    tracing::info!(relay = %self.id, "骨干链路后台 UDP 握手已完成，由 TCP 切回 UDP");
                    match self.leave_tcp_link(now) {
                        Some(TcpLeg { adopted: None, connected: true, .. }) => self.lingering = Some(now),
                        Some(_) => wire.tcp_close(),
                        None => {}
                    }
                }
            }
            Some(Event::Down { reason }) => {
                let target = self.udp_target;
                let established = std::mem::take(&mut self.udp_established);
                self.set_target(None);
                if self.tcp_link.is_some() && !established {
                    // 骨干链路使用 TCP 时后台尝试的 UDP 握手未完成：保持现状。未收到 AUTH 应答通常是因为对方尚缺乏反向 UDP 可达证据，
                    // 对方在被触发试探后会主动发起探测，因此不将该地址标记为握手异常。
                    tracing::debug!(relay = %self.id, reason, "骨干链路后台 UDP 握手未完成，保持 TCP 连接");
                    return;
                }
                if !established
                    && self.wanted
                    && let Some(addr) = target
                {
                    // 已返回 CHALLENGE 但未完成握手：本轮不再重试该地址，立即尝试其余候选地址。
                    self.udp_shunned.push(addr);
                    if self.has_udp() {
                        tracing::info!(relay = %self.id, %addr, reason, "该 relay 地址握手未完成，切换至其他候选地址重试");
                        self.start_udp(now, who, wire);
                        return;
                    }
                }
                // 握手失败留给这一轮尝试去收尾；已经建好的会话掉了才需要马上重连。
                if self.attempt.is_none() && !self.tcp.as_ref().is_some_and(|tcp| tcp.session.is_up()) {
                    tracing::info!(relay = %self.id, reason, "到 relay 的中转会话断开（UDP）");
                    self.reconnect_soon(now);
                } else {
                    tracing::debug!(relay = %self.id, reason, "到 relay 的 UDP 握手失败");
                }
            }
            Some(Event::Held) | None => {}
        }
    }

    fn apply_tcp(&mut self, step: Step, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        if let Some(send) = step.send {
            self.send_tcp(send, who, wire);
        }
        match step.event {
            Some(Event::Up { observed }) => {
                self.seen = Some((observed.ip().to_canonical(), now));
                if !self.udp.is_up() {
                    self.tried = Some((TryOutcome::Tcp, now));
                }
                self.attempt = None;
                self.failures = 0;
                // 这一轮没有同时试 UDP 的话（见 `fell_back`），连上之后马上在后台试一次：UDP 要是恢复了，不用等半分钟。
                self.udp_retry_at = if self.fell_back { now } else { now + UDP_RETRY };
                self.fell_back = true;
                self.session_up(now);
                let via = self.tcp.as_mut().and_then(|tcp| {
                    tcp.established = true;
                    tcp.addr
                });
                self.tcp_good = via;
                if self.tcp_bad == via {
                    self.tcp_bad = None;
                }
                let via = via.map(|addr| addr.to_string()).unwrap_or_default();
                tracing::info!(relay = %self.id, %via, "到 relay 的中转会话建立（TCP）");
            }
            Some(Event::Down { reason }) => {
                tracing::info!(relay = %self.id, reason, "到 relay 的 TCP 中转不可用");
                match self.tcp {
                    // 复用的入站 TCP 连接未能建立会话：短时间内不再复用，改由本节点主动拨号（对方可能是不支持反向复用的旧版本）。
                    Some(TcpLeg { adopted: Some(offer), .. }) => self.spoiled_offer = Some((offer, now)),
                    // 已建立 TCP 连接但握手未完成的地址，下次排在末尾（可能对应其他主机）。
                    Some(TcpLeg { addr: Some(addr), established: false, .. }) => self.tcp_bad = Some(addr),
                    Some(_) | None => {}
                }
                self.retire_tcp();
                wire.tcp_close();
                // 握手失败时这一轮尝试还没结束（`attempt` 还在）；建好的会话掉了才算"断过"。
                if self.attempt.is_none() && self.leg().is_none() {
                    self.session_lost();
                }
            }
            Some(Event::Held) | None => {}
        }
    }

    /// relay 的地址 `from` 发来的会话帧。错误帧走 [`on_udp_refusal`](Self::on_udp_refusal)。
    ///
    /// 同一个地址可能是好几个 relay 的（不同局域网里的内网地址会撞），所以收包的一方会把帧交给每一个：
    /// 这里只认在回答本节点发出去的随机数的帧，OK 还要验过签名。
    pub(crate) fn on_udp_frame(&mut self, from: SocketAddr, frame: &Frame, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        match frame {
            Frame::Challenge(challenge) => {
                if let Some((_, sent)) = self.survey.take_if(|(nonce, _)| *nonce == challenge.nonce) {
                    self.surveyed = Some((now.saturating_duration_since(sent), now));
                    self.tried = Some((TryOutcome::Udp, now));
                    self.next_survey = now + RELAY_SURVEY;
                } else if self.udp_target.is_none_or(|target| target == from) && self.udp_candidates().contains(&from) {
                    let step = self.udp.on_challenge(challenge, now);
                    if matches!(step.send, Some(Send::Auth { .. })) {
                        self.set_target(Some(from));
                        self.udp_reached = Some(now);
                    }
                    self.apply_udp(step, now, who, wire);
                }
            }
            Frame::Ok(ok) if self.udp_target == Some(from) && self.udp.expects_ok(ok) => {
                if self.ok_is_genuine(ok, who) {
                    let step = self.udp.on_ok(ok, now);
                    self.apply_udp(step, now, who, wire);
                }
            }
            Frame::Pong(_) if self.udp_target != Some(from) => {}
            Frame::Pong(pong) => {
                if let Some(observed) = self.udp.on_pong(pong, now) {
                    self.observed = Some((observed, now));
                    self.seen = Some((observed.ip().to_canonical(), now));
                }
            }
            // 错误帧要和它回显的字节一起看，见 [`on_udp_refusal`](Self::on_udp_refusal)。
            // 别的会话帧是节点发给 relay 的，不该从 relay 来。
            Frame::Error(_) | Frame::Ok(_) | Frame::Init(_) | Frame::Auth(_) | Frame::Ping(_) => {}
        }
    }

    /// 处理来自 relay UDP 地址的错误帧，回显内容为 `echo`。返回 relay 报告的路径问题（仅当回显匹配当前会话时有效）。
    pub(crate) fn on_udp_refusal(
        &mut self,
        refused: &Refused,
        echo: &Echo,
        now: Instant,
        who: Identity<'_>,
        wire: &mut dyn Wire,
    ) -> Option<Complaint> {
        let (step, complaint) = Self::refusal(&mut self.udp, self.id, refused, echo, now, who);
        self.apply_udp(step, now, who, wire);
        complaint
    }

    /// 处理会话收到的错误帧：涉及本节点无会话的错误交由会话自身校验；涉及路径不可达的错误仅在回显匹配本次握手随机数时采信。
    fn refusal(
        session: &mut Session,
        relay: NodeId,
        refused: &Refused,
        echo: &Echo,
        now: Instant,
        who: Identity<'_>,
    ) -> (Step, Option<Complaint>) {
        let complaint = match refused.reason {
            RefusalReason::NoSession if refused.node == who.me => return (session.on_no_session(echo, now), None),
            RefusalReason::NoSession => return (Step::default(), None),
            RefusalReason::PeerUnattached => Complaint::PeerUnattached(refused.node),
            RefusalReason::RouteUnavailable => Complaint::RouteUnavailable(refused.node),
        };
        if !session.is_session_echo(echo) {
            tracing::debug!(%relay, reason = ?refused.reason, "relay 错误帧回显与当前会话不匹配，已忽略");
            return (Step::default(), None);
        }
        (Step::default(), Some(complaint))
    }

    /// 到这个 relay 的 TCP 连上了（`addr` 是连上的那个地址）：在里面开始握手，先停在 cookie 那一步。
    pub(crate) fn on_tcp_connected(&mut self, addr: SocketAddr, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        let Some(tcp) = &mut self.tcp else { return };
        tcp.connected = true;
        tcp.addr = Some(addr);
        // 骨干改走了 TCP 的话 UDP 不会再来，不用停在 cookie 那一步等它。
        let send = tcp.session.start(now, self.tcp_link.is_none());
        self.send_tcp(send, who, wire);
    }

    /// 到这个 relay 的 TCP 里收到的会话帧。错误帧走 [`on_tcp_refusal`](Self::on_tcp_refusal)。
    pub(crate) fn on_tcp_frame(&mut self, frame: &Frame, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        let genuine = matches!(frame, Frame::Ok(ok) if self.ok_is_genuine(ok, who));
        let Some(tcp) = self.tcp.as_mut() else { return };
        let step = match frame {
            Frame::Challenge(challenge) => tcp.session.on_challenge(challenge, now),
            Frame::Ok(ok) if genuine => tcp.session.on_ok(ok, now),
            Frame::Pong(pong) => {
                // TCP 上看到的地址是那条 TCP 的，不是 UDP 的候选端点，不记成 `observed`；出口地址照样是它。
                if let Some(observed) = tcp.session.on_pong(pong, now) {
                    self.seen = Some((observed.ip().to_canonical(), now));
                }
                Step::default()
            }
            Frame::Error(_) | Frame::Ok(_) | Frame::Init(_) | Frame::Auth(_) | Frame::Ping(_) => Step::default(),
        };
        self.apply_tcp(step, now, who, wire);
    }

    /// 处理经该 relay TCP 连接收到的错误帧。校验规则与 UDP 一致（[`on_udp_refusal`](Self::on_udp_refusal)）：
    /// 尽管路径外攻击者难以伪造 TCP 帧，保持两端规则一致仅会在无会话时多一次往返探测。
    pub(crate) fn on_tcp_refusal(
        &mut self,
        refused: &Refused,
        echo: &Echo,
        now: Instant,
        who: Identity<'_>,
        wire: &mut dyn Wire,
    ) -> Option<Complaint> {
        let tcp = self.tcp.as_mut()?;
        let (step, complaint) = Self::refusal(&mut tcp.session, self.id, refused, echo, now, who);
        self.apply_tcp(step, now, who, wire);
        complaint
    }

    /// 到该 relay 的 TCP 连接已断开或连接失败。
    pub(crate) fn on_tcp_closed(&mut self, now: Instant) {
        let Some(tcp) = self.retire_tcp() else { return };
        if tcp.session.is_up() {
            tracing::info!(relay = %self.id, "到 relay 的 TCP 连接已断开，中转会话终止");
            if !self.udp.is_up() {
                self.reconnect_soon(now);
            }
        } else {
            tracing::debug!(relay = %self.id, "到 relay 的 TCP 连接失败或在握手阶段断开");
        }
    }

    fn ok_is_genuine(&self, ok: &Accepted, who: Identity<'_>) -> bool {
        let message = Accepted::signed_message(self.id, who.me, &ok.nonce, ok.valid_for, ok.observed);
        let genuine = i3t_crypto::verify(&self.key, Accepted::PURPOSE, &message, &Signature::from_bytes(ok.signature)).is_ok();
        if !genuine {
            tracing::warn!(relay = %self.id, "relay 握手应答签名校验失败，已忽略");
        }
        genuine
    }

    fn survey(&mut self, now: Instant, who: Identity<'_>, wire: &mut dyn Wire) {
        if now < self.next_survey {
            return;
        }
        let candidates = self.udp_candidates();
        if candidates.is_empty() {
            return;
        }
        // 未收到响应时较快重试以尽早确认可达性；收到响应后则按完整周期继续探测。
        self.next_survey = now + RELAY_SURVEY / 6;
        let nonce: Nonce = i3t_underlay::random_bytes();
        self.survey = Some((nonce, now));
        // 向所有候选地址并发发送探测，以最先返回的结果作为延迟样本。
        let init = Init { node: who.me, nonce }.to_bytes();
        for to in candidates {
            wire.udp(to, &init);
        }
    }
}

/// 到一个 relay 的会话断没断过。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Steadiness {
    /// 建立之后没有断过（或者还没有建立过）。
    Unbroken,
    /// 断了，还没有重新连上。
    Down,
    /// 断过，在这个时刻重新连上的。
    Recovered(Instant),
}

/// 连接失败后的指数退避重试间隔：从 1 秒起逐次翻倍直至上限，并附加最多 20% 的随机抖动。
fn retry_delay(failures: u32) -> Duration {
    let base = Duration::from_secs(1).saturating_mul(1u32.checked_shl(failures.saturating_sub(1)).unwrap_or(u32::MAX)).min(RELAY_RETRY_MAX);
    base + jitter(base / 5)
}

/// 0 到 `max` 之间的一个随机时长。
pub(crate) fn jitter(max: Duration) -> Duration {
    let [byte]: [u8; 1] = i3t_underlay::random_bytes();
    max * u32::from(byte) / 255
}

/// 选挂靠对象时一个 relay 的情况。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Standing {
    pub(crate) id: NodeId,
    /// 到它的延迟；不知道时是 `None`。
    pub(crate) rtt: Option<Duration>,
    /// 已选为挂靠目标但持续连接失败。
    pub(crate) failing: bool,
}

/// 决定挂靠哪几个 relay。
///
/// - 管理员固定了的话就是固定的那几个。
/// - 否则保留现在挂靠的，不足 [`ATTACH_COUNT`] 个时补上延迟最低的；延迟还不知道的按 netmap 里的顺序排在后面，
///   这样刚启动时不用等测量就有 relay 可用。
/// - 若存在明显更优的外部候选（延迟降低超过 `max(10ms, 20%)`，或当前挂靠的 relay 持续连接失败），则替换最差的一个；
///   每次仅替换一个并带迟滞，避免在延迟相近的 relay 之间频繁抖动。
pub(crate) fn choose_attached(current: &[NodeId], relays: &[Standing], pinned: &[NodeId]) -> Vec<NodeId> {
    let known = |id: &NodeId| relays.iter().any(|relay| relay.id == *id);
    if !pinned.is_empty() {
        return pinned.iter().copied().filter(known).collect();
    }
    // 延迟未知的排在已知的后面；`sort_by_key` 是稳定的，所以同样未知的保持 netmap 里的顺序。
    let rank = |relay: &Standing| (relay.failing, relay.rtt.is_none(), relay.rtt);
    let mut chosen: Vec<NodeId> = current.iter().copied().filter(known).take(ATTACH_COUNT).collect();
    let mut outside: Vec<Standing> = relays.iter().copied().filter(|relay| !chosen.contains(&relay.id)).collect();
    outside.sort_by_key(rank);
    let mut outside = outside.into_iter();
    while chosen.len() < ATTACH_COUNT {
        let Some(next) = outside.next() else { return chosen };
        chosen.push(next.id);
    }
    let standing = |id: &NodeId| relays.iter().find(|relay| relay.id == *id).copied();
    let worst = chosen.iter().filter_map(standing).max_by_key(rank);
    if let (Some(worst), Some(best)) = (worst, outside.next())
        && let Some(best_rtt) = best.rtt
        && !best.failing
    {
        let better = match worst.rtt {
            _ if worst.failing => true,
            Some(worst_rtt) => best_rtt + (worst_rtt / 5).max(Duration::from_millis(10)) < worst_rtt,
            // 现在挂靠的那个延迟还没测出来：先不动，等它有了数再比。
            None => false,
        };
        if better && let Some(slot) = chosen.iter_mut().find(|id| **id == worst.id) {
            *slot = best.id;
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use i3t_proto::session::{Challenge, Pong, Refused};

    use super::*;
    use crate::timing::{DIAL_DEFER, ONE_SIDED_GRACE};

    const MS: Duration = Duration::from_millis(1);

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// 记下 [`RelayLink`] 想发什么。
    #[derive(Debug, Default)]
    struct Recorder {
        udp: Vec<(SocketAddr, Frame)>,
        tcp: Vec<Frame>,
        tcp_connects: usize,
        /// 每次去连 TCP 时给的地址，按顺序。
        tcp_targets: Vec<Vec<SocketAddr>>,
        tcp_closes: usize,
        /// 对方拨进来、可以借来用的那条：对端地址和编号。借走之后清掉。
        offered: Option<(SocketAddr, u64)>,
        /// 借来用过的，按顺序。
        adopted: Vec<u64>,
    }

    impl Wire for Recorder {
        fn udp(&mut self, to: SocketAddr, frame: &[u8]) {
            self.udp.push((to, Frame::parse(frame).expect("发出去的应该是合法的会话帧")));
        }

        fn tcp(&mut self, frame: &[u8]) {
            self.tcp.push(Frame::parse(frame).expect("发出去的应该是合法的会话帧"));
        }

        fn tcp_connect(&mut self, addrs: &[SocketAddr]) {
            self.tcp_connects += 1;
            self.tcp_targets.push(addrs.to_vec());
        }

        fn tcp_adopt(&mut self) -> Option<(SocketAddr, u64)> {
            let offered = self.offered.take()?;
            self.adopted.push(offered.1);
            Some(offered)
        }

        fn tcp_close(&mut self) {
            self.tcp_closes += 1;
        }
    }

    struct Setup {
        me: NodeId,
        link: RelayLink,
        wire: Recorder,
        node_key: NodeKey,
        relay_key: NodeKey,
        start: Instant,
    }

    const ME: u32 = 1;
    const RELAY: u32 = 9;

    impl Setup {
        fn new(udp: &[&str], tcp: &[&str]) -> Self {
            Self::as_node(ME, udp, tcp)
        }

        /// 本节点的编号是 `me`（relay 是 9）：骨干上谁先拨号按编号定。
        fn as_node(me: u32, udp: &[&str], tcp: &[&str]) -> Self {
            let relay_key = NodeKey::generate().unwrap();
            let relay = Relay {
                id: node(RELAY),
                key: relay_key.public(),
                name: "relay".to_owned(),
                udp: udp.iter().map(|text| addr(text)).collect(),
                tcp: tcp.iter().map(|text| addr(text)).collect(),
            };
            let start = Instant::now();
            let mut setup = Self {
                me: node(me),
                link: RelayLink::new(&relay, start),
                wire: Recorder::default(),
                node_key: NodeKey::generate().unwrap(),
                relay_key,
                start,
            };
            setup.link.set_wanted(true, start, &mut setup.wire);
            setup
        }

        fn poll(&mut self, at: Duration) {
            let who = Identity { me: self.me, key: &self.node_key };
            self.link.poll(self.start + at, who, false, false, None, &mut self.wire);
        }

        /// relay 从本节点最近一次发往的那个地址回答。
        fn udp_frame(&mut self, frame: Frame, at: Duration) {
            let from = self.wire.udp.last().expect("relay 只回答发给它的东西").0;
            self.udp_frame_from(from, frame, at);
        }

        fn udp_frame_from(&mut self, from: SocketAddr, frame: Frame, at: Duration) {
            let who = Identity { me: self.me, key: &self.node_key };
            self.link.on_udp_frame(from, &frame, self.start + at, who, &mut self.wire);
        }

        fn tcp_frame(&mut self, frame: Frame, at: Duration) {
            let who = Identity { me: self.me, key: &self.node_key };
            self.link.on_tcp_frame(&frame, self.start + at, who, &mut self.wire);
        }

        fn udp_refusal(&mut self, reason: RefusalReason, node: NodeId, echo: Echo, at: Duration) -> Option<Complaint> {
            let who = Identity { me: self.me, key: &self.node_key };
            self.link.on_udp_refusal(&Refused { reason, node }, &echo, self.start + at, who, &mut self.wire)
        }

        fn tcp_refusal(&mut self, reason: RefusalReason, node: NodeId, echo: Echo, at: Duration) -> Option<Complaint> {
            let who = Identity { me: self.me, key: &self.node_key };
            self.link.on_tcp_refusal(&Refused { reason, node }, &echo, self.start + at, who, &mut self.wire)
        }

        /// TCP 连上了，连上的是最近一次去连的地址里的第一个。
        fn tcp_connected(&mut self, at: Duration) {
            let to = self.wire.tcp_targets.last().and_then(|addrs| addrs.first()).copied().expect("应该去连过 TCP");
            self.tcp_connected_to(to, at);
        }

        fn tcp_connected_to(&mut self, to: SocketAddr, at: Duration) {
            let who = Identity { me: self.me, key: &self.node_key };
            self.link.on_tcp_connected(to, self.start + at, who, &mut self.wire);
        }

        /// relay 对一个 AUTH 的回答，签名是真的。
        fn ok_for(&self, auth: &Auth, observed: &str) -> Frame {
            let observed = addr(observed);
            let message = Accepted::signed_message(node(RELAY), self.me, &auth.nonce, 30, observed);
            let signature = *self.relay_key.sign(Accepted::PURPOSE, &message).as_bytes();
            Frame::Ok(Accepted { nonce: auth.nonce, valid_for: 30, observed, signature })
        }

        fn last_udp(&self) -> Frame {
            self.wire.udp.last().expect("应该发过 UDP 帧").1
        }

        fn last_tcp(&self) -> Frame {
            *self.wire.tcp.last().expect("应该发过 TCP 帧")
        }

        /// 把 UDP 握手走完。返回会话握手时的随机数。
        fn complete_udp(&mut self, at: Duration) -> Nonce {
            let Frame::Init(init) = self.last_udp() else { panic!("UDP 上最后发的应该是 INIT：{:?}", self.wire.udp) };
            self.udp_frame(Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), at);
            let Frame::Auth(auth) = self.last_udp() else { panic!("收到 CHALLENGE 之后应该发 AUTH") };
            let ok = self.ok_for(&auth, "203.0.113.7:4000");
            self.udp_frame(ok, at);
            auth.nonce
        }

        /// 把 TCP 握手从 INIT 走到拿到 cookie。
        fn challenge_tcp(&mut self, at: Duration) {
            let Frame::Init(init) = self.last_tcp() else { panic!("TCP 上最后发的应该是 INIT：{:?}", self.wire.tcp) };
            self.tcp_frame(Frame::Challenge(Challenge { nonce: init.nonce, cookie: [4; 16] }), at);
        }

        /// 返回会话握手时的随机数。
        fn complete_tcp(&mut self, at: Duration) -> Nonce {
            let Frame::Auth(auth) = self.last_tcp() else { panic!("TCP 上最后发的应该是 AUTH：{:?}", self.wire.tcp) };
            let ok = self.ok_for(&auth, "203.0.113.7:5555");
            self.tcp_frame(ok, at);
            auth.nonce
        }

        /// UDP 一直没有回音，靠 TCP 把会话建起来。返回建好的时刻。
        fn fall_back_to_tcp(&mut self) -> Duration {
            self.poll(Duration::ZERO);
            self.tcp_connected(10 * MS);
            self.challenge_tcp(20 * MS);
            self.poll(UDP_HEAD_START);
            self.complete_tcp(UDP_HEAD_START + 20 * MS);
            assert_eq!(self.link.leg(), Some(Leg::Tcp));
            UDP_HEAD_START + 20 * MS
        }

        /// 从 `from` 到 `to` 每 50ms 推进一次，relay 照常回答 TCP 上的保活。
        fn keep_tcp_alive(&mut self, from: Duration, to: Duration) {
            let mut at = from;
            let mut seen = self.wire.tcp.len();
            while at < to {
                at += 50 * MS;
                self.poll(at);
                let pings: Vec<Ping> = self.wire.tcp[seen..]
                    .iter()
                    .filter_map(|frame| if let Frame::Ping(ping) = frame { Some(*ping) } else { None })
                    .collect();
                seen = self.wire.tcp.len();
                for ping in pings {
                    self.tcp_frame(Frame::Pong(Pong { nonce: ping.nonce, observed: addr("203.0.113.7:5555") }), at + 20 * MS);
                }
            }
        }

        /// 从 `from` 起 relay 在 TCP 上什么也不回答了（链路卡住了）。每 50ms 推进一次，返回会话被判为断开的时刻。
        fn stall_tcp(&mut self, from: Duration) -> Duration {
            let mut at = from;
            while self.link.leg().is_some() {
                at += 50 * MS;
                assert!(at < from + Duration::from_secs(30), "保活没有回答，会话早该断了");
                self.poll(at);
            }
            at
        }

        /// 从 `from` 起 relay 在 UDP 上什么也不回答了。每 50ms 推进一次，返回会话被判为断开的时刻。
        fn stall_udp(&mut self, from: Duration) -> Duration {
            let mut at = from;
            while self.link.leg().is_some() {
                at += 50 * MS;
                assert!(at < from + Duration::from_secs(30), "保活没有回答，会话早该断了");
                self.poll(at);
            }
            at
        }

        /// 重连的 TCP 连上之后把握手走完。返回建好的时刻。
        fn reconnect_tcp(&mut self, at: Duration) -> Duration {
            self.tcp_connected(at + 10 * MS);
            self.challenge_tcp(at + 20 * MS);
            self.poll(at + 50 * MS);
            self.complete_tcp(at + 70 * MS);
            assert_eq!(self.link.leg(), Some(Leg::Tcp));
            at + 70 * MS
        }

        /// 本节点是 relay：带着骨干上的情况推进。
        fn poll_as_relay(&mut self, at: Duration, backbone: Backbone) {
            let who = Identity { me: self.me, key: &self.node_key };
            self.link.poll(self.start + at, who, false, false, Some(backbone), &mut self.wire);
        }

        /// 本节点是 relay：从 `from` 到 `to` 每 50ms 推进一次，relay 照常回答 UDP 和 TCP 上的保活。返回最后推进到的时刻。
        fn relay_until(&mut self, from: Duration, to: Duration, backbone: Backbone) -> Duration {
            let (mut at, mut udp_seen, mut tcp_seen) = (from, self.wire.udp.len(), self.wire.tcp.len());
            while at < to {
                at += 50 * MS;
                self.poll_as_relay(at, backbone);
                let udp_pings: Vec<(SocketAddr, Ping)> = self.wire.udp[udp_seen..]
                    .iter()
                    .filter_map(|(to, frame)| if let Frame::Ping(ping) = frame { Some((*to, *ping)) } else { None })
                    .collect();
                let tcp_pings: Vec<Ping> = self.wire.tcp[tcp_seen..]
                    .iter()
                    .filter_map(|frame| if let Frame::Ping(ping) = frame { Some(*ping) } else { None })
                    .collect();
                (udp_seen, tcp_seen) = (self.wire.udp.len(), self.wire.tcp.len());
                for (to, ping) in udp_pings {
                    self.udp_frame_from(to, Frame::Pong(Pong { nonce: ping.nonce, observed: addr("203.0.113.7:4000") }), at + 10 * MS);
                }
                for ping in tcp_pings {
                    self.tcp_frame(Frame::Pong(Pong { nonce: ping.nonce, observed: addr("203.0.113.7:5555") }), at + 10 * MS);
                }
            }
            at
        }

        fn udp_inits(&self) -> usize {
            self.wire.udp.iter().filter(|(_, frame)| matches!(frame, Frame::Init(_))).count()
        }

        /// 这个 relay 经 UDP 敲了门。
        fn knock(&mut self, at: Duration) {
            let who = Identity { me: self.me, key: &self.node_key };
            self.link.on_knock(self.start + at, who, &mut self.wire);
        }

        /// 本节点是编号小的 relay：到它的 UDP 握不上手，骨干改走本节点马上拨的 TCP，两个会话都在上面。返回 TCP 上的会话建好的时刻。
        fn backbone_on_tcp(&mut self) -> Duration {
            assert!(self.me < node(RELAY), "编号小的一方马上拨");
            let at = self.relay_until(Duration::ZERO, UDP_GIVEN_UP, backbone(None, None));
            self.tcp_connected(at + 10 * MS);
            self.challenge_tcp(at + 20 * MS);
            self.complete_tcp(at + 30 * MS);
            assert_eq!((self.link.leg(), self.wire.tcp_connects), (Some(Leg::Tcp), 1));
            at + 30 * MS
        }

        /// 骨干走着 TCP：从 `from` 起照常回答保活，直到经 UDP 发出一个 INIT 为止。返回发出它的那一轮的时刻。
        fn until_udp_try(&mut self, from: Duration, backbone: Backbone) -> Duration {
            let inits = self.udp_inits();
            let mut at = from;
            while self.udp_inits() == inits {
                at = self.relay_until(at, at + 50 * MS, backbone);
                assert!(at < from + Duration::from_secs(300), "该在后台试 UDP 了");
            }
            at
        }

        /// 骨干改走 TCP 的时刻。
        fn tcp_since(&self) -> Duration {
            self.link.tcp_link.expect("骨干走着 TCP").since - self.start
        }

        /// 骨干走着 TCP 时不该被后台试的 UDP 碰到的那些：失败次数、下一次尝试的时刻、报上去的结果、TCP 的连和关。
        fn bookkeeping(&self) -> (u32, Instant, Option<(TryOutcome, Instant)>, usize, usize) {
            (self.link.failures, self.link.retry_at, self.link.tried, self.wire.tcp_connects, self.wire.tcp_closes)
        }
    }

    #[test]
    fn udp_and_tcp_are_tried_together_and_udp_wins_when_it_works() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        setup.poll(Duration::ZERO);
        assert!(matches!(setup.wire.udp[..], [(to, Frame::Init(init))] if to == addr("198.51.100.9:20330") && init.node == node(ME)));
        assert_eq!(setup.wire.tcp_connects, 1, "同时去连 TCP");

        // TCP 连上了，握手走到 cookie 就停下：AUTH 先不发。
        setup.tcp_connected(10 * MS);
        setup.challenge_tcp(20 * MS);
        assert!(matches!(setup.wire.tcp[..], [Frame::Init(_)]), "{:?}", setup.wire.tcp);

        setup.complete_udp(30 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Udp(addr("198.51.100.9:20330"))));
        assert_eq!(setup.link.observed(setup.start + 30 * MS), Some(addr("203.0.113.7:4000")));
        setup.poll(40 * MS);
        assert_eq!(setup.wire.tcp_closes, 1, "UDP 通了，TCP 不要了");
        assert!(matches!(setup.wire.tcp[..], [Frame::Init(_)]), "TCP 上始终没有发过 AUTH，relay 那边没有绑过它");
    }

    #[test]
    fn tcp_takes_over_when_udp_stays_silent_past_its_head_start() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        setup.poll(Duration::ZERO);
        setup.tcp_connected(10 * MS);
        setup.challenge_tcp(20 * MS);
        setup.poll(UDP_HEAD_START - MS);
        assert!(matches!(setup.wire.tcp[..], [Frame::Init(_)]), "还在给 UDP 留时间");

        setup.poll(UDP_HEAD_START);
        assert!(matches!(setup.last_tcp(), Frame::Auth(_)));
        setup.complete_tcp(UDP_HEAD_START + 20 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));
        assert_eq!(setup.link.observed(setup.start + UDP_HEAD_START + 20 * MS), None, "TCP 上看到的地址不是 UDP 的候选端点");
        assert!(setup.link.rtt().is_some());
    }

    #[test]
    fn a_node_on_tcp_keeps_retrying_udp_and_switches_back() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        setup.poll(Duration::ZERO);
        setup.tcp_connected(10 * MS);
        setup.challenge_tcp(20 * MS);
        setup.poll(UDP_HEAD_START);
        setup.complete_tcp(UDP_HEAD_START + 20 * MS);

        // 头一次 UDP 握手耗尽重试之后，隔一段时间再来一次。停在第二次握手进行到一半的时候。
        // 这期间 relay 照常回答 TCP 上的保活。
        let mut at = UDP_HEAD_START;
        let mut answered = setup.wire.tcp.len();
        while at < UDP_RETRY + Duration::from_secs(2) {
            at += 100 * MS;
            setup.poll(at);
            let pings: Vec<Ping> = setup.wire.tcp[answered..]
                .iter()
                .filter_map(|frame| if let Frame::Ping(ping) = frame { Some(*ping) } else { None })
                .collect();
            answered = setup.wire.tcp.len();
            for ping in pings {
                setup.tcp_frame(Frame::Pong(Pong { nonce: ping.nonce, observed: addr("203.0.113.7:5555") }), at);
            }
        }
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));
        let inits = setup.wire.udp.iter().filter(|(_, frame)| matches!(frame, Frame::Init(_))).count();
        assert!(inits > usize::from(crate::timing::HANDSHAKE_TRIES), "走着 TCP 的时候又试了 UDP：{inits} 个 INIT");
        assert_eq!(setup.wire.tcp_closes, 0);

        // 这一次 UDP 通了：换回 UDP，关掉 TCP。
        setup.complete_udp(at + 10 * MS);
        setup.poll(at + 20 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Udp(addr("198.51.100.9:20330"))));
        assert_eq!(setup.wire.tcp_closes, 1);
    }

    #[test]
    fn a_tcp_session_that_dies_is_rebuilt_over_tcp_alone_without_waiting_for_udp() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        let up = setup.fall_back_to_tcp();
        let died = setup.stall_tcp(up);
        assert_eq!(setup.wire.tcp_connects, 2, "断开的那一刻就开始重连");
        let inits = setup.udp_inits();

        setup.tcp_connected(died + 10 * MS);
        setup.challenge_tcp(died + 20 * MS);
        setup.poll(died + 50 * MS);
        assert!(matches!(setup.last_tcp(), Frame::Auth(_)), "上一次就是 UDP 握不上手才用的 TCP，这一次不再等它一秒");
        setup.complete_tcp(died + 70 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));
        assert_eq!(setup.udp_inits(), inits, "重连时没有同时去试 UDP");

        // UDP 并没有被放弃：TCP 连上之后马上在后台试一次，之后照常定期试，通了就换回去。
        setup.keep_tcp_alive(died + 70 * MS, died + 200 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));
        assert_eq!(setup.udp_inits(), inits + 1, "TCP 一连上就试了 UDP");
        setup.complete_udp(died + 250 * MS);
        setup.poll(died + 300 * MS);
        assert!(matches!(setup.link.leg(), Some(Leg::Udp(_))), "UDP 恢复了的话立刻换回去");
    }

    #[test]
    fn a_reconnect_over_tcp_does_not_wait_for_a_udp_attempt_that_happens_to_be_under_way() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        let up = setup.fall_back_to_tcp();
        // 走着 TCP 时定期试 UDP。TCP 在那之前不久卡住，于是会话断开的时候 UDP 的握手正进行到一半。
        let inits = setup.udp_inits();
        let stalled = up + UDP_RETRY - PROBE_INTERVAL + 100 * MS;
        setup.keep_tcp_alive(up, stalled);
        let died = setup.stall_tcp(stalled);
        let under_way = setup.udp_inits();
        assert!(under_way > inits && died < up + UDP_RETRY + Duration::from_secs(2), "UDP 的握手应该正在进行");

        let again = setup.reconnect_tcp(died);
        assert!(again < died + UDP_HEAD_START, "不等那次 UDP 握手");
        assert_eq!(setup.udp_inits(), under_way, "那次 UDP 握手放下了，不会和 TCP 的握手互相顶掉");
    }

    #[test]
    fn a_handshake_over_tcp_waits_for_a_slow_answer_instead_of_resending() {
        let mut setup = Setup::new(&[], &["198.51.100.9:20330"]);
        setup.poll(Duration::ZERO);
        setup.tcp_connected(10 * MS);
        // 回答 3 秒之后才到（TCP 在重传）。这期间不重发，也不放弃。
        for step in 1..=60u32 {
            setup.poll(10 * MS + 50 * MS * step);
        }
        assert!(matches!(setup.wire.tcp[..], [Frame::Init(_)]), "TCP 里的帧不会丢，重发只是多排一个：{:?}", setup.wire.tcp);
        assert_eq!(setup.wire.tcp_closes, 0);
        let up = setup.reconnect_tcp(Duration::from_secs(3) - 10 * MS);
        assert!(setup.link.is_settled(setup.start + up));

        // 一直没有回答的话，等够了时间就放弃这条连接，换一条再试。
        let mut silent = Setup::new(&[], &["198.51.100.9:20330"]);
        silent.poll(Duration::ZERO);
        silent.tcp_connected(10 * MS);
        let mut at = 10 * MS;
        while silent.wire.tcp_closes == 0 {
            at += 50 * MS;
            assert!(at < Duration::from_secs(10), "握手没有回答，该放弃了");
            silent.poll(at);
        }
        assert!(at >= crate::timing::TCP_HANDSHAKE_STEP, "放弃得太早：{at:?}");
    }

    #[test]
    fn a_relay_that_cannot_be_reached_over_tcp_either_gets_both_transports_tried_again() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        let up = setup.fall_back_to_tcp();
        let died = setup.stall_tcp(up);
        let inits = setup.udp_inits();
        // 重连的 TCP 一直连不上：这一轮算失败，下一轮 UDP 和 TCP 又一起试。
        let mut at = died;
        while setup.udp_inits() == inits {
            at += 100 * MS;
            assert!(at < died + Duration::from_secs(30), "该重新试 UDP 了");
            setup.poll(at);
        }
        assert!(setup.wire.tcp_connects >= 3);
    }

    #[test]
    fn what_a_tcp_leg_measured_is_kept_when_it_reconnects() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        let up = setup.fall_back_to_tcp();
        // 好好的 40 秒（8 个保活都有回答），然后卡住：3 个保活没有回答，会话断开。
        let stalled = up + PROBE_INTERVAL * 8 + Duration::from_secs(1);
        setup.keep_tcp_alive(up, stalled);
        let died = setup.stall_tcp(stalled);
        let again = setup.reconnect_tcp(died);

        let quality = setup.link.quality(setup.start + again).expect("重连之后马上就有估计");
        // 走 TCP 的一段按最近的样本的平均延迟算（`crate::estimate`）。断开之前的十几个样本都是 20ms 左右；卡住的那一次按最早那个
        // 没有回答的保活等了多久算（三次超时，0.9 秒多），也在里面：重连之后不是只剩握手那两个漂亮的样本。
        assert!(quality.rtt > 70 * MS && quality.rtt < 120 * MS, "断开之前的样本和那一次停顿都还在：{quality:?}");
        assert_eq!((quality.jitter, quality.lost, quality.probes), (Duration::ZERO, 0, 0), "停顿已经算在延迟里了：{quality:?}");
        // 报给别的节点的也是这个数，不是平滑延迟：那个数里看不出这条 TCP 刚卡死过。
        let smoothed = setup.link.rtt().expect("有会话").get();
        let reported = setup.link.reported_rtt(setup.start + again).expect("有会话").get();
        assert!(smoothed < 40 * MS, "平滑延迟还是握手和保活那二十来毫秒：{smoothed:?}");
        assert_eq!(reported, quality.rtt, "两头用同一把尺子");
        assert_eq!(setup.link.estimate(setup.start + again), Some(quality.rtt), "选挂靠谁也用它：一次停顿不会让平滑延迟带着挂靠来回换");
    }

    #[test]
    fn a_leg_over_udp_reports_its_smoothed_round_trip() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        setup.poll(Duration::ZERO);
        setup.complete_udp(30 * MS);
        let now = setup.start + 30 * MS;
        assert!(matches!(setup.link.leg(), Some(Leg::Udp(_))));
        assert_eq!(setup.link.reported_rtt(now), setup.link.rtt(), "走 UDP 的一段照旧");
        assert!(setup.link.reported_rtt(now).is_some());
    }

    #[test]
    fn a_session_over_tcp_is_probed_at_the_ordinary_pace_even_towards_another_relay() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        // 本节点自己是 relay：到别的 relay 的 UDP 会话是骨干连接，2 秒探测一次。TCP 上的不跟着变。
        setup.link.set_probe_interval(crate::timing::BACKBONE_PROBE_INTERVAL);
        let up = setup.fall_back_to_tcp();
        let pings = |setup: &Setup| setup.wire.tcp.iter().filter(|frame| matches!(frame, Frame::Ping(_))).count();
        setup.keep_tcp_alive(up, up + PROBE_INTERVAL - 200 * MS);
        assert_eq!(pings(&setup), 0, "不到 5 秒不发保活");
        setup.keep_tcp_alive(up + PROBE_INTERVAL - 200 * MS, up + PROBE_INTERVAL + 200 * MS);
        assert_eq!(pings(&setup), 1);
    }

    #[test]
    fn a_session_that_never_broke_is_settled_at_once_and_one_that_reconnected_only_after_it_has_held() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        assert!(!setup.link.is_settled(setup.start), "还没有会话");
        let up = setup.fall_back_to_tcp();
        assert!(setup.link.is_settled(setup.start + up), "头一次连上，没有理由不信它");

        // 断了一次：重连上来之后要保持够久才算数。
        setup.keep_tcp_alive(up, up + Duration::from_secs(20));
        let died = setup.stall_tcp(up + Duration::from_secs(20));
        assert!(!setup.link.is_settled(setup.start + died));
        let again = setup.reconnect_tcp(died);
        assert!(!setup.link.is_settled(setup.start + again + SETTLE - MS));
        assert!(setup.link.is_settled(setup.start + again + SETTLE));
    }

    #[test]
    fn a_handshake_that_fails_before_any_session_existed_does_not_count_as_a_broken_session() {
        let mut setup = Setup::new(&[], &["198.51.100.9:20330"]);
        // 头一次 TCP 连上了，但握手的最后一步一直没有回应；下一轮才成功。
        setup.poll(Duration::ZERO);
        setup.tcp_connected(10 * MS);
        setup.challenge_tcp(20 * MS);
        let mut at = 20 * MS;
        while setup.wire.tcp_connects < 2 {
            at += 100 * MS;
            assert!(at < Duration::from_secs(30), "握手失败之后应该重试");
            setup.poll(at);
        }
        let up = setup.reconnect_tcp(at);
        assert!(setup.link.is_settled(setup.start + up), "从来没有建立过会话，谈不上断过");
    }

    #[test]
    fn switching_from_tcp_back_to_udp_does_not_restart_the_settling_time() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        let up = setup.fall_back_to_tcp();
        let died = setup.stall_tcp(up);
        let again = setup.reconnect_tcp(died);
        // 重连之后走着 TCP，直到下一次试 UDP 的握手发出去；这一次 UDP 通了。
        let at = again + UDP_RETRY + 100 * MS;
        setup.keep_tcp_alive(again, at);
        setup.complete_udp(at + 60 * MS);
        setup.poll(at + 100 * MS);
        assert!(matches!(setup.link.leg(), Some(Leg::Udp(_))));
        assert!(setup.link.is_settled(setup.start + at + 100 * MS), "从重连上 TCP 算起已经保持够久了，换到 UDP 不重新算");
    }

    #[test]
    fn a_forged_ok_is_ignored() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &[]);
        setup.poll(Duration::ZERO);
        let Frame::Init(init) = setup.last_udp() else { panic!("先发 INIT") };
        setup.udp_frame(Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), 10 * MS);
        let Frame::Auth(auth) = setup.last_udp() else { panic!("再发 AUTH") };

        let forged = Accepted { nonce: auth.nonce, valid_for: 30, observed: addr("203.0.113.7:4000"), signature: [0; 64] };
        setup.udp_frame(Frame::Ok(forged), 20 * MS);
        assert_eq!(setup.link.leg(), None);
        // 签名对，但签的是另一个观察到的地址。
        let Frame::Ok(genuine) = setup.ok_for(&auth, "203.0.113.7:4000") else { unreachable!("ok_for 返回的就是 OK") };
        let tampered = Accepted { observed: addr("203.0.113.99:4000"), ..genuine };
        setup.udp_frame(Frame::Ok(tampered), 20 * MS);
        assert_eq!(setup.link.leg(), None);
        setup.udp_frame(Frame::Ok(genuine), 20 * MS);
        assert!(setup.link.leg().is_some());
    }

    #[test]
    fn the_auth_frame_carries_a_signature_the_relay_can_verify() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &[]);
        setup.poll(Duration::ZERO);
        let Frame::Init(init) = setup.last_udp() else { panic!("先发 INIT") };
        setup.udp_frame(Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), 10 * MS);
        let Frame::Auth(auth) = setup.last_udp() else { panic!("再发 AUTH") };
        let message = Auth::signed_message(node(RELAY), node(ME), &auth.nonce, &auth.cookie);
        i3t_crypto::verify(&setup.node_key.public(), Auth::PURPOSE, &message, &Signature::from_bytes(auth.signature)).unwrap();
        assert_eq!((auth.node, auth.cookie), (node(ME), [3; 16]));
    }

    #[test]
    fn a_lost_session_is_rebuilt_at_once_and_an_unreachable_relay_is_retried_with_backoff() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &[]);
        setup.poll(Duration::ZERO);
        setup.complete_udp(10 * MS);
        assert!(setup.link.leg().is_some());

        // relay 重启了，它说本节点没有会话。这个错误帧回答的是一个中转帧，回显的东西本节点核对不了：先发一个 PING 去问。
        setup.udp_refusal(RefusalReason::NoSession, node(ME), [0x41; 8], Duration::from_secs(1));
        assert!(setup.link.leg().is_some(), "一个核对不了的错误帧不拆会话");
        let Frame::Ping(ping) = setup.last_udp() else { panic!("应该马上发 PING 去问：{:?}", setup.wire.udp) };
        // relay 对这个 PING 的回答回显了它的随机数：会话确实没了，马上重新握手。
        let sent_before = setup.wire.udp.len();
        setup.udp_refusal(RefusalReason::NoSession, node(ME), ping.nonce, Duration::from_secs(1) + 20 * MS);
        assert_eq!(setup.link.leg(), None);
        setup.poll(Duration::from_secs(1) + 400 * MS);
        assert!(matches!(setup.wire.udp[sent_before..], [(_, Frame::Init(_))]), "{:?}", &setup.wire.udp[sent_before..]);

        // 这回一直没有回答：尝试失败，过一阵再试，间隔越来越长。
        let mut attempts = Vec::new();
        let mut at = Duration::from_secs(1) + 400 * MS;
        let mut seen = setup.wire.udp.len();
        let mut last_nonce = None;
        while at < Duration::from_secs(40) {
            at += 100 * MS;
            setup.poll(at);
            for (_, frame) in &setup.wire.udp[seen..] {
                if let Frame::Init(init) = frame
                    && last_nonce.replace(init.nonce) != Some(init.nonce)
                {
                    attempts.push(at);
                }
            }
            seen = setup.wire.udp.len();
        }
        assert!((4..=7).contains(&attempts.len()), "40 秒里大约试 5 次：{attempts:?}");
        let gaps: Vec<Duration> = attempts.windows(2).map(|pair| pair[1] - pair[0]).collect();
        assert!(gaps.windows(2).all(|pair| pair[1] > pair[0]), "间隔应该越来越长：{gaps:?}");
        assert!(setup.link.is_failing(setup.start + at));
    }

    #[test]
    fn a_refusal_meant_for_another_node_or_about_a_peer_does_not_touch_the_session() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &[]);
        setup.poll(Duration::ZERO);
        let session = setup.complete_udp(10 * MS);
        let sent = setup.wire.udp.len();
        assert_eq!(setup.udp_refusal(RefusalReason::NoSession, node(77), session, 20 * MS), None);
        assert!(setup.link.leg().is_some() && setup.wire.udp.len() == sent, "说的是别的节点");
        let unattached = setup.udp_refusal(RefusalReason::PeerUnattached, node(5), session, 20 * MS);
        assert_eq!(unattached, Some(Complaint::PeerUnattached(node(5))), "对端没挂在这个 relay 上：交给选路去换");
        let unroutable = setup.udp_refusal(RefusalReason::RouteUnavailable, node(8), session, 20 * MS);
        assert_eq!(unroutable, Some(Complaint::RouteUnavailable(node(8))), "多级路径走不下去：也交给选路去换");
        assert!(setup.link.leg().is_some());
    }

    #[test]
    fn a_complaint_that_does_not_echo_the_session_is_ignored() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        let tcp_session = setup.fall_back_to_tcp();
        let tcp_nonce = {
            let Some(Frame::Auth(auth)) = setup.wire.tcp.iter().rev().find(|frame| matches!(frame, Frame::Auth(_))).copied() else {
                panic!("TCP 上发过 AUTH")
            };
            auth.nonce
        };
        // 伪造来源地址的人冒充 relay：它不知道会话握手的随机数。
        for reason in [RefusalReason::PeerUnattached, RefusalReason::RouteUnavailable] {
            assert_eq!(setup.tcp_refusal(reason, node(5), [0; 8], tcp_session), None);
            assert_eq!(setup.udp_refusal(reason, node(5), tcp_nonce, tcp_session), None, "UDP 上没有会话，回显什么都不算");
        }
        assert_eq!(
            setup.tcp_refusal(RefusalReason::PeerUnattached, node(5), tcp_nonce, tcp_session),
            Some(Complaint::PeerUnattached(node(5)))
        );
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));
    }

    #[test]
    fn pong_refreshes_the_observed_address() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &[]);
        setup.poll(Duration::ZERO);
        setup.complete_udp(10 * MS);
        setup.poll(crate::timing::PROBE_INTERVAL + 10 * MS);
        let Frame::Ping(ping) = setup.last_udp() else { panic!("该发保活了：{:?}", setup.wire.udp) };
        assert_eq!(ping.node, node(ME));
        let moved = addr("203.0.113.7:4999");
        setup.udp_frame(Frame::Pong(Pong { nonce: ping.nonce, observed: moved }), crate::timing::PROBE_INTERVAL + 30 * MS);
        assert_eq!(setup.link.observed(setup.start + crate::timing::PROBE_INTERVAL + 30 * MS), Some(moved));
    }

    #[test]
    fn letting_go_of_a_relay_stops_everything() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        setup.poll(Duration::ZERO);
        setup.tcp_connected(10 * MS);
        setup.link.set_wanted(false, setup.start + 20 * MS, &mut setup.wire);
        assert_eq!(setup.wire.tcp_closes, 1);
        assert_eq!(setup.link.leg(), None);
        let sent = setup.wire.udp.len();
        setup.poll(Duration::from_secs(30));
        assert_eq!(setup.wire.udp.len(), sent, "不要了的 relay 不再握手也不再保活");
    }

    #[test]
    fn an_unattached_relay_is_surveyed_with_a_stateless_round_trip() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &[]);
        setup.link.set_wanted(false, setup.start, &mut setup.wire);
        let who_key = NodeKey::generate().unwrap();
        let who = Identity { me: node(ME), key: &who_key };
        setup.link.poll(setup.start, who, false, true, None, &mut setup.wire);
        let Frame::Init(init) = setup.last_udp() else { panic!("测延迟用的是 INIT") };
        assert_eq!(setup.link.estimate(setup.start), None);

        setup.udp_frame(Frame::Challenge(Challenge { nonce: init.nonce, cookie: [0; 16] }), 35 * MS);
        assert_eq!(setup.link.estimate(setup.start + 35 * MS), Some(35 * MS));
        assert_eq!(setup.wire.udp.len(), 1, "只量一个往返，不接着握手");
        assert_eq!(setup.link.leg(), None);
        assert_eq!(setup.link.estimate(setup.start + ESTIMATE_TTL + 36 * MS), None, "过期作废");

        // 一分钟之后再量。
        setup.link.poll(setup.start + 35 * MS + RELAY_SURVEY - MS, who, false, true, None, &mut setup.wire);
        assert_eq!(setup.wire.udp.len(), 1);
        setup.link.poll(setup.start + 35 * MS + RELAY_SURVEY, who, false, true, None, &mut setup.wire);
        assert_eq!(setup.wire.udp.len(), 2);

        // 没有回答的话十秒之后就再问。
        setup.link.poll(setup.start + 35 * MS + RELAY_SURVEY + RELAY_SURVEY / 6, who, false, true, None, &mut setup.wire);
        assert_eq!(setup.wire.udp.len(), 3);
    }

    #[test]
    fn a_try_is_remembered_as_udp_tcp_only_or_unreached_together_with_the_address_the_relay_saw() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        assert_eq!(setup.link.last_try(setup.start), None, "还没试过");
        setup.poll(Duration::ZERO);
        setup.complete_udp(10 * MS);
        let now = setup.start + 20 * MS;
        assert_eq!(setup.link.last_try(now), Some((TryOutcome::Udp, now)), "有会话时就是现在");
        assert_eq!(setup.link.seen_as(now), Some(ip("203.0.113.7")));

        // UDP 一直没有回音，经 TCP 连上：只有 TCP 连得上。TCP 上看到的地址照样是出口地址。
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        let up = setup.start + setup.fall_back_to_tcp();
        assert_eq!(setup.link.last_try(up).map(|(outcome, _)| outcome), Some(TryOutcome::Tcp));
        assert_eq!(setup.link.seen_as(up), Some(ip("203.0.113.7")));

        // 两种都连不上：这一轮失败，记成连不上。
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        let mut at = Duration::ZERO;
        while setup.link.last_try(setup.start + at).is_none() {
            setup.poll(at);
            at += 100 * MS;
            assert!(at < Duration::from_secs(30), "该算这一轮失败了");
        }
        assert_eq!(setup.link.last_try(setup.start + at).map(|(outcome, _)| outcome), Some(TryOutcome::Unreached));
    }

    #[test]
    fn an_unanswered_survey_says_udp_does_not_get_through_and_an_answered_one_counts_as_reached() {
        let mut setup = Setup::new(&["198.51.100.9:20330"], &["198.51.100.9:20330"]);
        setup.link.set_wanted(false, setup.start, &mut setup.wire);
        let key = NodeKey::generate().unwrap();
        let who = Identity { me: node(ME), key: &key };
        setup.link.poll(setup.start, who, false, true, None, &mut setup.wire);
        assert!(!setup.link.survey_silent(setup.start + MS), "刚问");
        assert!(setup.link.survey_silent(setup.start + SURVEY_SILENCE), "问了没有回答");
        assert_eq!(setup.link.last_try(setup.start + SURVEY_SILENCE), None, "只试了 UDP，还说不上连不连得上");

        let Frame::Init(init) = setup.last_udp() else { panic!("询问用的是 INIT") };
        setup.udp_frame(Frame::Challenge(Challenge { nonce: init.nonce, cookie: [0; 16] }), 40 * MS);
        assert!(!setup.link.survey_silent(setup.start + SURVEY_SILENCE));
        assert_eq!(setup.link.last_try(setup.start + SECOND), Some((TryOutcome::Udp, setup.start + 40 * MS)));
    }

    const SECOND: Duration = Duration::from_secs(1);
    const DEAD: &str = "198.51.100.9:20330";
    const LAN: &str = "192.168.1.5:20330";
    const MAPPED: &str = "203.0.113.9:40330";

    /// 发出去的 INIT 都发给了哪些地址（按发出的顺序）。
    fn init_targets(wire: &Recorder, from: usize) -> Vec<SocketAddr> {
        wire.udp[from..].iter().filter(|(_, frame)| matches!(frame, Frame::Init(_))).map(|(to, _)| *to).collect()
    }

    #[test]
    fn every_address_gets_the_init_and_the_first_to_answer_carries_the_session() {
        let mut setup = Setup::new(&[DEAD, LAN, MAPPED], &[DEAD, LAN, MAPPED]);
        setup.poll(Duration::ZERO);
        assert_eq!(init_targets(&setup.wire, 0), [addr(DEAD), addr(LAN), addr(MAPPED)], "同时问每个地址，第一个连不上不耽误别的");
        let nonces: Vec<Nonce> =
            setup.wire.udp.iter().filter_map(|(_, frame)| if let Frame::Init(init) = frame { Some(init.nonce) } else { None }).collect();
        assert!(nonces.windows(2).all(|pair| pair[0] == pair[1]), "是同一次握手");

        // 局域网里的地址先回答：和只有这一个地址时一样快。
        setup.udp_frame_from(addr(LAN), Frame::Challenge(Challenge { nonce: nonces[0], cookie: [3; 16] }), 2 * MS);
        assert!(matches!(setup.wire.udp.last(), Some((to, Frame::Auth(_))) if *to == addr(LAN)), "AUTH 只发给回答了的地址");
        // 另一个地址后来也回答了（经路由器绕了一圈）：不理，不能让 relay 那边的会话换来换去。
        let sent = setup.wire.udp.len();
        setup.udp_frame_from(addr(MAPPED), Frame::Challenge(Challenge { nonce: nonces[0], cookie: [5; 16] }), 4 * MS);
        assert_eq!(setup.wire.udp.len(), sent);
        let Frame::Auth(auth) = setup.last_udp() else { panic!("应该发了 AUTH") };
        let ok = setup.ok_for(&auth, "192.168.1.20:20330");
        setup.udp_frame_from(addr(MAPPED), ok, 5 * MS);
        assert_eq!(setup.link.leg(), None, "OK 要从握手的那个地址来");
        setup.udp_frame_from(addr(LAN), ok, 5 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Udp(addr(LAN))));
        assert!(setup.link.take_target_changed());

        setup.poll(PROBE_INTERVAL + 10 * MS);
        assert!(matches!(setup.wire.udp.last(), Some((to, Frame::Ping(_))) if *to == addr(LAN)), "保活只走在用的地址");
        setup.poll(UDP_HEAD_START + 50 * MS);
        assert!(setup.wire.tcp.iter().all(|frame| !matches!(frame, Frame::Auth(_))), "UDP 通了，TCP 从来没有走到 AUTH");
    }

    #[test]
    fn when_the_address_in_use_stops_answering_every_address_is_tried_again() {
        let mut setup = Setup::new(&[DEAD, LAN, MAPPED], &[]);
        setup.poll(Duration::ZERO);
        let Frame::Init(init) = setup.last_udp() else { panic!() };
        setup.udp_frame_from(addr(LAN), Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), 2 * MS);
        let Frame::Auth(auth) = setup.last_udp() else { panic!() };
        let ok = setup.ok_for(&auth, "192.168.1.20:20330");
        setup.udp_frame_from(addr(LAN), ok, 3 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Udp(addr(LAN))));

        // 换了个局域网：原来的地址不再回答，保活连续没有回音，会话断开，马上重新问每个地址。
        let sent = setup.wire.udp.len();
        let died = setup.stall_udp(10 * MS);
        setup.poll(died + 400 * MS);
        assert_eq!(
            init_targets(&setup.wire, sent).iter().rev().take(3).rev().copied().collect::<Vec<_>>(),
            [addr(DEAD), addr(LAN), addr(MAPPED)]
        );
        let Frame::Init(init) = setup.last_udp() else { panic!() };
        setup.udp_frame_from(addr(MAPPED), Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), died + 420 * MS);
        let Frame::Auth(auth) = setup.last_udp() else { panic!() };
        let ok = setup.ok_for(&auth, "198.51.100.30:20330");
        setup.udp_frame_from(addr(MAPPED), ok, died + 440 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Udp(addr(MAPPED))), "这回用的是现在连得上的那个");
    }

    #[test]
    fn an_address_that_answers_but_cannot_finish_the_handshake_is_left_out_for_the_rest_of_the_round() {
        // 第一个地址上回答的是另一台机器（和别的 relay 撞了地址）：它给 cookie，却不认本节点的 AUTH。
        let mut setup = Setup::new(&[LAN, MAPPED], &[]);
        setup.poll(Duration::ZERO);
        let Frame::Init(init) = setup.last_udp() else { panic!() };
        setup.udp_frame_from(addr(LAN), Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), MS);
        let sent = setup.wire.udp.len();
        let mut at = MS;
        while setup.link.udp_target() == Some(addr(LAN)) {
            at += 50 * MS;
            assert!(at < Duration::from_secs(5), "握手走不完总该放弃");
            setup.poll(at);
        }
        assert_eq!(init_targets(&setup.wire, sent), [addr(MAPPED)], "马上接着试剩下的地址，不等这一轮结束");
        assert!(at < Duration::from_secs(3), "{at:?}");
        let Frame::Init(init) = setup.last_udp() else { panic!() };
        setup.udp_frame_from(addr(LAN), Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), at + MS);
        assert!(!matches!(setup.last_udp(), Frame::Auth(_)), "这一轮里不再理它");
        setup.udp_frame_from(addr(MAPPED), Frame::Challenge(Challenge { nonce: init.nonce, cookie: [4; 16] }), at + 2 * MS);
        let Frame::Auth(auth) = setup.last_udp() else { panic!() };
        let ok = setup.ok_for(&auth, "198.51.100.30:20330");
        setup.udp_frame_from(addr(MAPPED), ok, at + 3 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Udp(addr(MAPPED))));
    }

    #[test]
    fn the_nodes_own_addresses_are_never_tried() {
        let mut setup = Setup::new(&[LAN, MAPPED], &[LAN, MAPPED]);
        setup.link.set_own(&[addr(LAN)]);
        setup.poll(Duration::ZERO);
        assert_eq!(init_targets(&setup.wire, 0), [addr(MAPPED)]);
        assert_eq!(setup.wire.tcp_targets, [vec![addr(MAPPED)]]);
    }

    #[test]
    fn a_relay_whose_udp_never_gets_through_works_over_tcp_on_the_same_addresses() {
        let mut setup = Setup::new(&[DEAD, MAPPED], &[DEAD, MAPPED]);
        setup.poll(Duration::ZERO);
        assert_eq!(setup.wire.tcp_targets, [vec![addr(DEAD), addr(MAPPED)]]);
        setup.tcp_connected_to(addr(MAPPED), 300 * MS);
        setup.challenge_tcp(310 * MS);
        setup.poll(UDP_HEAD_START);
        setup.complete_tcp(UDP_HEAD_START + 20 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Tcp), "没有人说过这个 relay 只能用 TCP");

        // 下一次连 TCP 时，上一次握手成功的地址排在最前。
        let died = setup.stall_tcp(UDP_HEAD_START + 20 * MS);
        assert_eq!(setup.wire.tcp_targets.last(), Some(&vec![addr(MAPPED), addr(DEAD)]), "断开于 {died:?}");
    }

    #[test]
    fn a_tcp_address_that_connects_but_cannot_finish_the_handshake_goes_last_next_time() {
        let mut setup = Setup::new(&[], &[LAN, MAPPED]);
        setup.poll(Duration::ZERO);
        setup.tcp_connected_to(addr(LAN), 10 * MS);
        // 连上的是另一台机器：它回了 cookie，AUTH 却等不到回答。
        setup.challenge_tcp(20 * MS);
        let mut at = 20 * MS;
        while setup.wire.tcp_targets.len() < 2 {
            at += 100 * MS;
            assert!(at < Duration::from_secs(30), "握手走不完总该重连");
            setup.poll(at);
        }
        assert_eq!(setup.wire.tcp_targets[1], [addr(MAPPED), addr(LAN)]);
    }

    fn standing(id: u32, rtt_ms: Option<u64>) -> Standing {
        Standing { id: node(id), rtt: rtt_ms.map(Duration::from_millis), failing: false }
    }

    #[test]
    fn pinned_relays_are_used_as_given() {
        let relays = [standing(1, Some(5)), standing(2, Some(50)), standing(3, Some(500))];
        assert_eq!(
            choose_attached(&[node(1)], &relays, &[node(3), node(2), node(9)]),
            [node(3), node(2)],
            "固定的照用，不在 netmap 里的去掉"
        );
    }

    #[test]
    fn the_two_lowest_latency_relays_are_attached() {
        let relays = [standing(1, Some(80)), standing(2, Some(20)), standing(3, Some(40)), standing(4, None)];
        assert_eq!(choose_attached(&[], &relays, &[]), [node(2), node(3)]);
        assert_eq!(choose_attached(&[], &relays[..1], &[]), [node(1)], "只有一个就挂一个");
        assert_eq!(choose_attached(&[], &[], &[]), []);
    }

    #[test]
    fn before_anything_is_measured_the_first_relays_in_the_netmap_are_used() {
        let relays = [standing(7, None), standing(3, None), standing(5, None)];
        assert_eq!(choose_attached(&[], &relays, &[]), [node(7), node(3)]);
    }

    #[test]
    fn a_clearly_better_relay_replaces_the_worst_attached_one_but_a_marginal_one_does_not() {
        let relays = [standing(1, Some(100)), standing(2, Some(30)), standing(3, Some(85)), standing(4, Some(20))];
        // 4 比 1 好得多：换掉 1。
        assert_eq!(choose_attached(&[node(1), node(2)], &relays, &[]), [node(4), node(2)]);
        // 3 只比 1 好 15%：不换。
        assert_eq!(choose_attached(&[node(1), node(2)], &relays[..3], &[]), [node(1), node(2)]);
        // 延迟很低时用 10ms 的门槛：12ms 和 8ms 之间不换。
        let close = [standing(1, Some(12)), standing(2, Some(5)), standing(3, Some(8))];
        assert_eq!(choose_attached(&[node(1), node(2)], &close, &[]), [node(1), node(2)]);
    }

    #[test]
    fn an_attached_relay_that_cannot_be_reached_gives_way_to_one_that_can() {
        let relays = [Standing { failing: true, ..standing(1, None) }, standing(2, Some(30)), standing(3, Some(300))];
        assert_eq!(choose_attached(&[node(1), node(2)], &relays, &[]), [node(3), node(2)]);
        // 外面那个没有量出延迟（多半也连不上）：不换。
        let unknown = [Standing { failing: true, ..standing(1, None) }, standing(2, Some(30)), standing(3, None)];
        assert_eq!(choose_attached(&[node(1), node(2)], &unknown, &[]), [node(1), node(2)]);
    }

    #[test]
    fn relays_removed_from_the_netmap_are_dropped_and_replaced() {
        let relays = [standing(2, Some(30)), standing(3, Some(300))];
        assert_eq!(choose_attached(&[node(1), node(2)], &relays, &[]), [node(2), node(3)]);
    }

    const RELAY_ADDR: &str = "198.51.100.9:20330";

    /// 骨干：本节点是 relay，`theirs` 是对方在本节点的 relay 上的会话，`offered` 是它拨进来、可以借来用的那一条。
    fn backbone(theirs: Option<SessionLeg>, offered: Option<u64>) -> Backbone {
        Backbone { theirs, offered }
    }

    /// UDP 握手的四次重发都没有回音之后的时刻（再多一点余量）。
    const UDP_GIVEN_UP: Duration = Duration::from_millis(2500);
    /// 骨干走着本节点拨的那条 TCP（本节点给它的编号是 1），对方的会话也在上面。
    const ON_TCP: Backbone = Backbone { theirs: Some(SessionLeg::Dialled(1)), offered: None };

    #[test]
    fn between_relays_udp_is_tried_alone_and_when_it_fails_the_relay_with_the_lower_id_dials_tcp_at_once() {
        let mut setup = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        setup.poll_as_relay(Duration::ZERO, backbone(None, None));
        assert!(matches!(setup.wire.udp[..], [(_, Frame::Init(_))]));
        assert_eq!(setup.wire.tcp_connects, 0, "两个 relay 之间不像节点那样同时去连 TCP：UDP 通的话两个会话都在 UDP 上");

        let at = setup.relay_until(Duration::ZERO, UDP_GIVEN_UP, backbone(None, None));
        assert_eq!(setup.wire.tcp_connects, 1, "UDP 握不上手，编号小的这一方马上拨");
        setup.tcp_connected(at + 10 * MS);
        setup.challenge_tcp(at + 20 * MS);
        assert!(matches!(setup.last_tcp(), Frame::Auth(_)), "不停在 cookie 那一步等 UDP：它不会再来了");
        setup.complete_tcp(at + 30 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));

        // 之后一直用这条 TCP；在后台试的 UDP 没有回答也不碰它（见 `a_backbone_link_on_tcp_tries_udp_in_the_background_…`）。
        setup.relay_until(at + 30 * MS, at + UDP_RETRY + Duration::from_secs(5), ON_TCP);
        assert_eq!((setup.link.leg(), setup.wire.tcp_closes, setup.wire.tcp_connects), (Some(Leg::Tcp), 0, 1));
    }

    #[test]
    fn the_relay_with_the_higher_id_waits_for_the_other_to_dial_and_borrows_the_connection_it_opens() {
        let mut setup = Setup::as_node(20, &[RELAY_ADDR], &[RELAY_ADDR]);
        let at = setup.relay_until(Duration::ZERO, UDP_GIVEN_UP + DIAL_DEFER - Duration::from_secs(1), backbone(None, None));
        assert_eq!(setup.wire.tcp_connects, 0, "编号大的一方先等对方拨");

        // 对方拨进来了：本节点在同一条 TCP 上建自己的会话。
        setup.wire.offered = Some((addr("198.51.100.9:44000"), 77));
        setup.poll_as_relay(at + 10 * MS, backbone(Some(SessionLeg::Accepted(77)), Some(77)));
        assert_eq!(setup.wire.adopted, [77]);
        setup.challenge_tcp(at + 20 * MS);
        setup.complete_tcp(at + 30 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));
        setup.relay_until(at + 30 * MS, at + DIAL_DEFER * 2, backbone(Some(SessionLeg::Accepted(77)), Some(77)));
        assert_eq!((setup.wire.tcp_connects, setup.wire.adopted.len()), (0, 1), "借来的那条一直用着，自己不拨");

        // 对方一直没有拨进来（它连不进本节点）：等够了自己拨。
        let mut alone = Setup::as_node(20, &[RELAY_ADDR], &[RELAY_ADDR]);
        let at = alone.relay_until(Duration::ZERO, UDP_GIVEN_UP + DIAL_DEFER, backbone(None, None));
        assert_eq!(alone.wire.tcp_connects, 1, "等到 {at:?} 还没有人拨进来，自己拨");
    }

    #[test]
    fn a_relay_that_cannot_reach_this_one_makes_it_carry_both_sessions_over_a_tcp_connection_it_dials() {
        // 本节点到它的 UDP 会话通着，它在本节点上也有 UDP 的会话：骨干就在 UDP 上，一直不动。
        let mut setup = Setup::as_node(20, &[RELAY_ADDR], &[RELAY_ADDR]);
        setup.poll_as_relay(Duration::ZERO, backbone(None, None));
        setup.complete_udp(10 * MS);
        let at = setup.relay_until(10 * MS, ONE_SIDED_GRACE * 2, backbone(Some(SessionLeg::Udp), None));
        assert_eq!((setup.link.leg(), setup.wire.tcp_connects), (Some(Leg::Udp(addr(RELAY_ADDR))), 0));

        // 它一直没在本节点上建会话：它连不上本节点。本节点放下 UDP，自己拨 TCP，不管编号。
        let start = setup.relay_until(at, at + ONE_SIDED_GRACE - Duration::from_secs(1), backbone(None, None));
        assert_eq!(setup.wire.tcp_connects, 0, "还在等它的会话");
        let at = setup.relay_until(start, start + Duration::from_secs(2), backbone(None, None));
        assert_eq!(setup.wire.tcp_connects, 1);
        assert_eq!(setup.link.leg(), None, "UDP 的会话放下了：两个会话要在同一条 TCP 上");
        setup.tcp_connected(at + 10 * MS);
        setup.challenge_tcp(at + 20 * MS);
        setup.complete_tcp(at + 30 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));
    }

    #[test]
    fn a_relay_whose_session_moved_onto_the_connection_it_dialled_is_followed_there_at_once() {
        // 本节点到它的 UDP 通着，它那边的 UDP 却不通：它拨了 TCP，会话搬了上去。不等 `ONE_SIDED_GRACE`，马上跟过去。
        let mut setup = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        setup.poll_as_relay(Duration::ZERO, backbone(None, None));
        setup.complete_udp(10 * MS);
        setup.wire.offered = Some((addr("198.51.100.9:44000"), 5));
        setup.poll_as_relay(100 * MS, backbone(Some(SessionLeg::Accepted(5)), Some(5)));
        assert_eq!(setup.wire.adopted, [5]);
        assert_eq!(setup.link.leg(), None, "UDP 的会话放下了，在借来的那条上握手");
        setup.challenge_tcp(120 * MS);
        setup.complete_tcp(130 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));
    }

    #[test]
    fn when_both_relays_dial_the_one_with_the_lower_id_keeps_its_own_connection() {
        let mut first = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        let at = first.relay_until(Duration::ZERO, UDP_GIVEN_UP, backbone(None, None));
        first.tcp_connected(at);
        first.challenge_tcp(at + 10 * MS);
        first.complete_tcp(at + 20 * MS);
        first.wire.offered = Some((addr("198.51.100.9:44000"), 5));
        first.relay_until(at + 20 * MS, at + Duration::from_secs(2), backbone(Some(SessionLeg::Accepted(5)), Some(5)));
        assert_eq!((first.wire.adopted.len(), first.wire.tcp_closes, first.link.leg()), (0, 0, Some(Leg::Tcp)), "留着自己拨的");

        let mut second = Setup::as_node(20, &[RELAY_ADDR], &[RELAY_ADDR]);
        let at = second.relay_until(Duration::ZERO, UDP_GIVEN_UP + DIAL_DEFER, backbone(None, None));
        second.tcp_connected(at);
        second.challenge_tcp(at + 10 * MS);
        second.complete_tcp(at + 20 * MS);
        second.wire.offered = Some((addr("198.51.100.9:44000"), 5));
        second.poll_as_relay(at + 30 * MS, backbone(Some(SessionLeg::Accepted(5)), Some(5)));
        assert_eq!(second.wire.adopted, [5], "编号大的一方改用对方拨的那条");
        assert!(matches!(second.last_tcp(), Frame::Init(_)), "在借来的那条上从头握手");
    }

    #[test]
    fn a_relay_on_tcp_follows_the_other_relay_back_to_udp_once_its_own_udp_reaches_it_too() {
        let mut setup = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        let up = setup.backbone_on_tcp();
        // 它在本节点上还有一个 UDP 的会话（UDP 整个断掉之前留下的，还没有过期）：本节点不知道自己的 UDP 到不到得了它，接着用 TCP。
        let stale = backbone(Some(SessionLeg::Udp), None);
        let at = setup.relay_until(up, up + Duration::from_secs(5), stale);
        assert_eq!((setup.link.leg(), setup.wire.tcp_closes), (Some(Leg::Tcp), 0), "不照一个可能早已不通的会话回去");

        // 后台试的 UDP 得到了它的回答（AUTH 它还没有回答）：两个方向都有了证据，回到 UDP 再试。
        let tried = setup.until_udp_try(at, ON_TCP);
        let Frame::Init(init) = setup.last_udp() else { panic!("后台试 UDP 从 INIT 开始") };
        setup.udp_frame(Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), tried + 10 * MS);
        let inits = setup.udp_inits();
        setup.relay_until(tried + 10 * MS, tried + Duration::from_secs(1), backbone(Some(SessionLeg::Udp), None));
        assert_eq!(setup.wire.tcp_closes, 1, "它在 UDP 上、连得上本节点，本节点的 UDP 也到得了它：回到 UDP 再试");
        assert!(setup.udp_inits() > inits);
        assert_eq!(setup.link.udp_gate(), None);
    }

    #[test]
    fn a_borrowed_connection_that_yields_no_session_is_not_borrowed_again_for_a_while() {
        let mut setup = Setup::as_node(20, &[RELAY_ADDR], &[RELAY_ADDR]);
        let at = setup.relay_until(Duration::ZERO, UDP_GIVEN_UP, backbone(None, None));
        setup.wire.offered = Some((addr("198.51.100.9:44000"), 5));
        // 对方是不在这条 TCP 上回答的旧版本：本节点的握手等够了就放弃。
        let at = setup.relay_until(at, at + crate::timing::TCP_HANDSHAKE_STEP + Duration::from_secs(1), backbone(None, Some(5)));
        assert_eq!(setup.wire.adopted, [5]);
        setup.wire.offered = Some((addr("198.51.100.9:44000"), 5));
        let at = setup.relay_until(at, at + Duration::from_secs(5), backbone(None, Some(5)));
        assert_eq!(setup.wire.adopted, [5], "同一条不再借");
        setup.wire.offered = Some((addr("198.51.100.9:44001"), 6));
        setup.poll_as_relay(at + 10 * MS, backbone(None, Some(6)));
        assert_eq!(setup.wire.adopted, [5, 6], "新拨进来的那条照样借");
    }

    #[test]
    fn a_backbone_link_on_tcp_tries_udp_in_the_background_and_a_try_that_fails_changes_nothing() {
        let mut setup = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        let up = setup.backbone_on_tcp();
        let due = setup.tcp_since() + UDP_RETRY;
        let (inits, before) = (setup.udp_inits(), setup.bookkeeping());
        let at = setup.relay_until(up, due - 100 * MS, ON_TCP);
        assert_eq!(setup.udp_inits(), inits, "改走 TCP 之后 {UDP_RETRY:?} 才试");

        // 对方一点回音都没有：握手两秒之后放弃，什么都不变，TCP 一直用着。
        let tried = setup.until_udp_try(at, ON_TCP);
        assert!(tried <= due + 50 * MS, "{tried:?}");
        let at = setup.relay_until(tried, tried + UDP_GIVEN_UP, ON_TCP);
        assert!(setup.link.udp.is_idle());
        assert_eq!(setup.bookkeeping(), before, "没有握上手：不算一次失败，不动退避，也不改报上去的结果");
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));

        // 下一次对方回答了 INIT，却不回答 AUTH（它还不知道自己的 UDP 到不到得了本节点）：同样什么都不变，这个地址也照样再试。
        let tried = setup.until_udp_try(at, ON_TCP);
        assert!(tried <= due + UDP_RETRY + 100 * MS, "每 {UDP_RETRY:?} 试一次：{tried:?}");
        let Frame::Init(init) = setup.last_udp() else { panic!("后台试 UDP 从 INIT 开始") };
        setup.udp_frame(Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), tried + 10 * MS);
        assert!(matches!(setup.last_udp(), Frame::Auth(_)));
        let at = setup.relay_until(tried + 10 * MS, tried + 10 * MS + UDP_GIVEN_UP, ON_TCP);
        assert!(setup.link.udp.is_idle());
        assert_eq!(setup.bookkeeping(), before);
        assert_eq!((setup.link.leg(), setup.link.udp_target()), (Some(Leg::Tcp), None));
        setup.until_udp_try(at, ON_TCP);
        assert_eq!(init_targets(&setup.wire, setup.wire.udp.len() - 1), [addr(RELAY_ADDR)], "这个地址没有被记成握不完手的");
    }

    #[test]
    fn an_answered_udp_init_lets_the_other_relay_move_here_for_two_retry_periods_but_one_from_before_tcp_does_not() {
        // 本节点的 UDP 到得了它（握手一路走通），它却一直没有经 UDP 在本节点上建会话：改走本节点拨的 TCP。
        let mut setup = Setup::as_node(20, &[RELAY_ADDR], &[RELAY_ADDR]);
        setup.poll_as_relay(Duration::ZERO, backbone(None, None));
        setup.complete_udp(10 * MS);
        assert_eq!(setup.link.udp_gate(), None, "没有走 TCP：都让，和以前一样");
        let at = setup.relay_until(10 * MS, ONE_SIDED_GRACE + SECOND, backbone(None, None));
        assert_eq!(setup.link.udp_gate(), Some(Gate::Closed), "改走 TCP 之前的回答不算：它说明不了现在");
        setup.tcp_connected(at + 10 * MS);
        setup.challenge_tcp(at + 20 * MS);
        setup.complete_tcp(at + 30 * MS);

        // 后台试的 UDP 得到了回答：从这一刻起两个重试周期多一点，对方可以经 UDP 把会话搬过来。
        let tried = setup.until_udp_try(at + 30 * MS, ON_TCP);
        let Frame::Init(init) = setup.last_udp() else { panic!("后台试 UDP 从 INIT 开始") };
        let answered = tried + 20 * MS;
        setup.udp_frame(Frame::Challenge(Challenge { nonce: init.nonce, cookie: [3; 16] }), answered);
        assert_eq!(udp_evidence_ttl(), UDP_RETRY * 2 + Duration::from_secs(5));
        let until = setup.start + answered + udp_evidence_ttl();
        assert_eq!(setup.link.udp_gate(), Some(Gate::OpenUntil(until)));

        // 下一次一点回音都没有（丢了几个包）：上一次的回答还算数，到点作废。
        let next = setup.until_udp_try(answered, ON_TCP);
        setup.relay_until(next, next + UDP_GIVEN_UP, ON_TCP);
        let gate = setup.link.udp_gate().expect("还走着 TCP");
        assert_eq!(gate, Gate::OpenUntil(until));
        assert!(gate.admits(until - MS) && !gate.admits(until));
        assert_eq!(setup.link.leg(), Some(Leg::Tcp));
    }

    #[test]
    fn when_a_background_try_comes_up_the_link_leaves_tcp_and_stays_on_udp_once_the_other_relay_follows() {
        let mut setup = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        let up = setup.backbone_on_tcp();
        let tried = setup.until_udp_try(up, ON_TCP);
        // 对方让本节点搬了过去（它知道自己的 UDP 到得了本节点）：又是一段普通的 UDP 骨干。
        setup.complete_udp(tried + 10 * MS);
        assert_eq!((setup.link.leg(), setup.link.udp_gate()), (Some(Leg::Udp(addr(RELAY_ADDR))), None));
        assert_eq!(setup.link.last_try(setup.start + tried + 10 * MS).map(|(outcome, _)| outcome), Some(TryOutcome::Udp));
        // 自己拨的那条先留着：对方还没有跟过来，它的会话还绑在上面，关了它就没有会话了。
        let at = setup.relay_until(tried + 10 * MS, tried + SECOND, ON_TCP);
        assert_eq!(setup.wire.tcp_closes, 0, "对方的会话还在这条 TCP 上");

        // 对方照旧有的规则跟了过来：这条 TCP 关掉，之后一直在 UDP 上，不再拨 TCP。
        setup.relay_until(at, tried + ONE_SIDED_GRACE * 2, backbone(Some(SessionLeg::Udp), None));
        assert_eq!(setup.wire.tcp_closes, 1);
        assert_eq!((setup.link.leg(), setup.wire.tcp_connects), (Some(Leg::Udp(addr(RELAY_ADDR))), 1));

        // 对方一直不跟过来的话，最多留 ONE_SIDED_GRACE。
        let mut stuck = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        let up = stuck.backbone_on_tcp();
        let tried = stuck.until_udp_try(up, ON_TCP);
        stuck.complete_udp(tried + 10 * MS);
        stuck.relay_until(tried + 10 * MS, tried + ONE_SIDED_GRACE - SECOND, ON_TCP);
        assert_eq!(stuck.wire.tcp_closes, 0);
        stuck.relay_until(tried + ONE_SIDED_GRACE - SECOND, tried + ONE_SIDED_GRACE + SECOND, ON_TCP);
        assert_eq!(stuck.wire.tcp_closes, 1);
    }

    #[test]
    fn a_link_back_on_udp_does_not_borrow_again_the_connection_it_let_go_while_the_other_relay_follows() {
        // 编号大的一方：骨干走的是对方拨进来、本节点借来的第 77 条。
        let mut setup = Setup::as_node(20, &[RELAY_ADDR], &[RELAY_ADDR]);
        let at = setup.relay_until(Duration::ZERO, UDP_GIVEN_UP + SECOND, backbone(None, None));
        let borrowed = backbone(Some(SessionLeg::Accepted(77)), Some(77));
        setup.wire.offered = Some((addr("198.51.100.9:44000"), 77));
        setup.poll_as_relay(at + 10 * MS, borrowed);
        setup.challenge_tcp(at + 20 * MS);
        setup.complete_tcp(at + 30 * MS);
        assert_eq!((setup.link.leg(), &setup.wire.adopted[..]), (Some(Leg::Tcp), &[77][..]));

        // 后台试的 UDP 握上了手。对方还没有跟过来：它的会话还在这条 TCP 上，这条 TCP 也还等着借。本节点不借回去，留在 UDP 上等它。
        let tried = setup.until_udp_try(at + 30 * MS, borrowed);
        setup.complete_udp(tried + 10 * MS);
        setup.wire.offered = Some((addr("198.51.100.9:44000"), 77));
        let at = setup.relay_until(tried + 10 * MS, tried + 3 * SECOND, borrowed);
        assert_eq!((setup.link.leg(), &setup.wire.adopted[..]), (Some(Leg::Udp(addr(RELAY_ADDR))), &[77][..]));
        setup.relay_until(at, at + ONE_SIDED_GRACE * 2, backbone(Some(SessionLeg::Udp), None));
        assert_eq!((setup.link.leg(), setup.wire.tcp_connects), (Some(Leg::Udp(addr(RELAY_ADDR))), 0), "它跟了过来");
    }

    #[test]
    fn a_backbone_link_whose_tcp_cannot_connect_comes_back_over_udp_and_stops_dialling() {
        let mut setup = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        let up = setup.backbone_on_tcp();
        // 这条 TCP 卡死了，会话断开；之后怎么拨都连不上。
        let mut at = up;
        while setup.link.leg().is_some() {
            at += 50 * MS;
            assert!(at < up + Duration::from_secs(30), "保活没有回答，会话早该断了");
            setup.poll_as_relay(at, ON_TCP);
        }
        let inits = setup.udp_inits();
        while setup.udp_inits() == inits {
            at += 50 * MS;
            assert!(at < up + UDP_RETRY + Duration::from_secs(5), "TCP 不通也照样在后台试 UDP");
            setup.poll_as_relay(at, backbone(None, None));
        }
        assert!(setup.wire.tcp_connects >= 3, "一直在重拨：{}", setup.wire.tcp_connects);
        setup.complete_udp(at + 10 * MS);
        assert_eq!(setup.link.leg(), Some(Leg::Udp(addr(RELAY_ADDR))));
        let connects = setup.wire.tcp_connects;
        setup.relay_until(at + 10 * MS, at + Duration::from_secs(30), backbone(Some(SessionLeg::Udp), None));
        assert_eq!((setup.link.leg(), setup.wire.tcp_connects), (Some(Leg::Udp(addr(RELAY_ADDR))), connects), "回到了 UDP，不再拨");
    }

    #[test]
    fn a_knock_makes_a_backbone_link_on_tcp_try_udp_at_once_but_not_more_often_than_the_gap() {
        let mut udp = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        udp.poll_as_relay(Duration::ZERO, backbone(None, None));
        udp.complete_udp(10 * MS);
        let inits = udp.udp_inits();
        udp.knock(20 * MS);
        assert_eq!(udp.udp_inits(), inits, "没有走 TCP：不理");

        let mut setup = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        let up = setup.backbone_on_tcp();
        let inits = setup.udp_inits();
        let knocked = up + SECOND;
        setup.knock(knocked);
        assert_eq!(setup.udp_inits(), inits + 1, "马上自己经 UDP 试一次，不等后台试的时候");
        setup.knock(knocked + 100 * MS);
        assert_eq!(setup.udp_inits(), inits + 1, "正在试着");
        let at = setup.relay_until(knocked, knocked + UDP_GIVEN_UP, ON_TCP);
        assert!(setup.link.udp.is_idle() && at < knocked + KNOCK_GAP);
        let sent = setup.udp_inits();
        setup.knock(at);
        assert_eq!(setup.udp_inits(), sent, "两次因为敲门的尝试之间至少隔 {KNOCK_GAP:?}");
        setup.knock(knocked + KNOCK_GAP);
        assert_eq!(setup.udp_inits(), sent + 1);
        assert_eq!((setup.link.leg(), setup.wire.tcp_closes), (Some(Leg::Tcp), 0));
    }

    #[test]
    fn a_return_that_does_not_last_doubles_the_wait_for_the_next_try_and_one_that_lasts_resets_it() {
        let mut setup = Setup::as_node(1, &[RELAY_ADDR], &[RELAY_ADDR]);
        let up = setup.backbone_on_tcp();
        let tried = setup.until_udp_try(up, ON_TCP);
        setup.complete_udp(tried + 10 * MS);

        // 对方（比如比这个改动旧的 relay，它的 UDP 到不了本节点）一直没有跟过来：既有的规则把这一段带回 TCP。
        let at = setup.relay_until(tried + 10 * MS, tried + ONE_SIDED_GRACE + SECOND, backbone(None, None));
        assert!(setup.link.tcp_link.is_some(), "又改走了 TCP");
        setup.tcp_connected(at + 10 * MS);
        setup.challenge_tcp(at + 20 * MS);
        setup.complete_tcp(at + 30 * MS);
        let since = setup.tcp_since();
        // 敲门照样马上有回应，不管退避。
        setup.knock(since + SECOND);
        let at = setup.relay_until(since + SECOND, since + SECOND + UDP_GIVEN_UP, ON_TCP);
        let tried = setup.until_udp_try(at, ON_TCP);
        let wait = tried - since;
        assert!(wait >= UDP_RETRY * 2 && wait <= UDP_RETRY * 2 + 50 * MS, "回到 UDP 没有回成：下一次多等一倍，{wait:?}");

        // 这一次对方跟了过来，回到的 UDP 保持了 RETURN_PROBATION 以上；之后 UDP 断了，改走 TCP：间隔复原。
        setup.complete_udp(tried + 10 * MS);
        let at = setup.relay_until(tried + 10 * MS, tried + RETURN_PROBATION + SECOND, backbone(Some(SessionLeg::Udp), None));
        assert_eq!(setup.link.leg(), Some(Leg::Udp(addr(RELAY_ADDR))));
        let mut at = at;
        while setup.link.tcp_link.is_none() {
            at += 50 * MS;
            assert!(at < tried + RETURN_PROBATION + Duration::from_secs(30), "UDP 断了，该改走 TCP 了");
            setup.poll_as_relay(at, backbone(None, None));
        }
        let since = setup.tcp_since();
        let connects = setup.wire.tcp_connects;
        let at = setup.relay_until(at, at + 50 * MS, backbone(None, None));
        assert_eq!(setup.wire.tcp_connects, connects + 1, "编号小的一方马上拨");
        setup.tcp_connected(at + 10 * MS);
        setup.challenge_tcp(at + 20 * MS);
        setup.complete_tcp(at + 30 * MS);
        let wait = setup.until_udp_try(at + 30 * MS, ON_TCP) - since;
        assert!(wait >= UDP_RETRY && wait <= UDP_RETRY + 50 * MS, "上一次回去保持住了：间隔复原，{wait:?}");
    }

    #[test]
    fn the_wait_between_background_tries_doubles_up_to_an_hour() {
        let start = Instant::now();
        let next = |current: Duration, returned: Option<Instant>, after: Duration| {
            RelayLink::next_backbone_retry(current, returned, start + after)
        };
        assert_eq!(next(UDP_RETRY, None, Duration::ZERO), UDP_RETRY, "从来没有回去过");
        assert_eq!(next(UDP_RETRY, Some(start), RETURN_PROBATION - MS), UDP_RETRY * 2);
        assert_eq!(next(UDP_RETRY * 8, Some(start), RETURN_PROBATION), UDP_RETRY, "回去之后保持住了：复原");
        let capped = (0..10).fold(UDP_RETRY, |wait, _| next(wait, Some(start), SECOND));
        assert_eq!(capped, BACKBONE_RETRY_MAX);
    }

    #[test]
    fn retry_delays_double_up_to_the_cap() {
        let delay = |failures| retry_delay(failures).as_secs_f64();
        assert!((1.0..=1.2).contains(&delay(1)));
        assert!((2.0..=2.4).contains(&delay(2)));
        assert!((8.0..=9.6).contains(&delay(4)));
        assert!((10.0..=12.0).contains(&delay(5)));
        assert!((10.0..=12.0).contains(&delay(60)));
        assert!(jitter(Duration::from_millis(300)) <= Duration::from_millis(300));
    }
}
