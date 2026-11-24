//! ice3proxy（lane）在节点里的接法。
//!
//! - 入口和出口用的连接层是共用的连接（[`Endpoint`]）和 lane 装在一起的（[`LaneConnector`]、[`LaneAcceptor`]）：
//!   要求走 ice3proxy 的流（选了它的代理的 TCP 流，见 `i3t_flow::Carriage`）在和对端之间备着 lane 时走 lane，
//!   别的流（端口转发、本机的组网入口、没选它的代理）和数据报一律走共用的连接；两种流进同一个 `serve`，
//!   计量、配额、带宽、凭据、每个对端的上限、访问规则和排空对它们一视同仁。
//! - 跟着 netmap：用 [`Lanes::set_peers_with_identities`] 更新 lane 的对端和仍有效的节点公钥。controller 只给有选了 ice3proxy 的
//!   代理的一对（代理监听的节点和它的出口）下发 `always`，别的是 `off`。本节点能拨的是 netmap 里启用了 relay、
//!   有 TCP 地址的对端（relay 在节点端口上听 TCP）；本节点自己是 relay 时，relay 的 TCP 端口把以 TLS 握手开头的连接交给 lane。
//!   双方均无法接受拨号的对端组合按 `off` 处理：无法建立 lane 的流不应计为“回退到共用连接”。
//! - 两个节点都能拨对方时，各自用自己拨的 lane 开流：补 lane 是本地的事，不用经过对方的 POOL 往返，
//!   每边的池跟着它自己开流的速率走；代价是两边各有一条控制 lane。
//! - `always`：能拨的对端一直拨着（控制 lane 和几条空闲的）。
//! - `udp_fallback`（controller 不再下发，旧的 controller 和静态的 netmap 还会写）：按需拨。到对端有路、并且路上没有 UDP 连续 [`SETTLE`] 才拨；
//!   UDP 回来了（或者没有路了）满 [`HOLD`] 才放手，之后什么都不连。没有路不算没有 UDP：对端离线时不去拨它。
//!   “路径无 UDP”指：本节点侧无 UDP，或经 relay 且 controller 标记对端不支持 UDP（netmap 中的 `no_udp`）。
//!   后者是因为经 relay 时节点仅能观测本节点侧：经 UDP 中继转发至无 UDP 能力的中继时，本节点侧虽为 UDP，整条路径仍包含 TCP 段。
//!   当前走直连时不参考该标记：直连整条路径均为 UDP，默认走共用连接。被标记为不支持 UDP 的节点仍可能与个别对端
//!   直连成功（其出站 UDP 经 NAT 可达对端）；是否走直连由路由选择决定（默认直连优先，延迟优先时比较路径代价）。
//!   开流的一方按同样的判断：路上没有 UDP、并且和对端之间的 lane 建着（控制 lane 在）时新的 TCP 流走 lane；
//!   lane 没建着（对方还没拨上来，或者本节点刚开始拨）就直接走共用的连接，不等，也不记作改走。
//!   剩下看不见的：两边都有 UDP、只是这条路经过的某一段（比如两个中继之间）是 TCP。
//! - 本节点的公网地址变了（家宽重拨）：拨出去的 lane 换新的 epoch 重拨（[`Lanes::address_changed`]）。
//! - 排空：告诉对端不再在和本节点之间的 lane 上开流（[`Lanes::go_away`]）；排空撤销了就恢复（[`Lanes::come_back`]）。

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use i3t_conn::{Endpoint, UdpSeen};
use i3t_crypto::NodeKey;
use i3t_lane::{Choose, LaneAcceptor, LaneConfig, LaneConnector, LanePeer, LaneStatus, Lanes, PeerLaneStatus};
use i3t_model::Netmap;
use i3t_model::control::{LaneCounts, LaneHandshakeFailures, LaneReport, PeerLanes};
use i3t_model::netmap::LaneMode;
use i3t_proto::{NodeId, PublicKey};
use tokio::sync::watch;

/// 入口和出口用的连接层。
pub(crate) type Connector = LaneConnector<Endpoint>;
/// 接受流的连接层。
pub(crate) type Acceptor = LaneAcceptor<Endpoint>;

/// 多久看一次本节点的公网地址变了没有、到按需拨号的对端的路上有没有 UDP。
const CHECK: Duration = Duration::from_secs(1);

/// `udp_fallback` 模式下，本节点侧须连续保持无 UDP 状态达到此时长后才开始拨号。
///
/// 支持 UDP 的节点也可能短暂缺少 UDP 路径：到 relay 的会话先尝试 UDP 1 秒，握手未成功时会先使用 TCP（丢包线路上常见），
/// 30 秒后再次尝试 UDP（路径层的 `UDP_RETRY`）；直连也需数秒完成验证。若此时立即拨号，将白白维持整个保持期（[`HOLD`]），
/// 与“双方均支持 UDP 时不产生额外开销”的设计目标不符。取值略高于 30 秒：UDP 重试仍失败才视为无 UDP。确实无 UDP 的节点，
/// 初期的新流走共用连接。无可用路径不计为有 UDP，也不重置计时：避免对端会话短暂重连打断等待。
const SETTLE: Duration = Duration::from_secs(40);

/// `udp_fallback` 模式下，UDP 恢复（或无可用路径）后仍维持拨号的保持时长。
///
/// 弱网环境下路径可能每数分钟切换一次（路径层双向切换时停留期逐次翻倍，最长 8 分钟），UDP 间歇恢复很常见：释放过早
/// 会导致每次切换都需重新拨号，且切回 TCP 初期的新流只能走共用连接。维持拨号的开销仅为一条控制 lane 加若干空闲 TCP（控制 lane 每 10 秒保活一次）。
/// 取略高于路径层最长停留期的 10 分钟：间歇性 UDP 不会导致 lane 反复拆除与重拨，UDP 真正稳定恢复后也仅多维持此时长。
const HOLD: Duration = Duration::from_secs(600);
/// 测试用的开关：环境变量 `I3T_TEST_LANE_HOLD` 改上面这个时间（秒），实验环境里不用等 10 分钟。
const HOLD_TEST_SWITCH: &str = "I3T_TEST_LANE_HOLD";

/// 一个节点上的 lane 和它们的设置。
pub(crate) struct NodeLanes {
    lanes: Arc<Lanes>,
    endpoint: Arc<Endpoint>,
    /// 每个打开了 lane、并且至少一边能被拨的对端的设置。要求走 ice3proxy 的流开流时按它选。
    settings: Arc<RwLock<HashMap<NodeId, Setting>>>,
    /// netmap 给的计划，和现在拨着谁。
    dialling: Mutex<Dialling>,
    timing: Timing,
}

/// netmap 里和一个对端之间的 ice3proxy 的设置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Setting {
    mode: LaneMode,
    /// controller 标记对端不支持 UDP（[`i3t_model::netmap::Peer::no_udp`]）。
    no_udp: bool,
}

impl Setting {
    /// 按 `udp_fallback` 策略判断到对端的路径是否存在 UDP。`seen` 是本节点观测到的状态（[`Endpoint::udp_path`]）：
    /// 直连时整条路径均为 UDP，不受 controller 对端标记影响；经 relay 时须同时满足本节点侧有 UDP 且对端未被标记为不支持 UDP。
    /// 无可用路径时返回 `None`，不视为无 UDP。
    fn udp_path(self, seen: Option<UdpSeen>) -> Option<bool> {
        seen.map(|seen| match seen {
            UdpSeen::WholePath => true,
            UdpSeen::OwnLeg => !self.no_udp,
            UdpSeen::NoUdp => false,
        })
    }
}

/// 按 netmap 要开 lane 的对端，和现在拨着谁。
#[derive(Debug, Default)]
struct Dialling {
    /// 要开 lane 的对端和它们的设置。本节点能拨的带着它的地址，不管现在拨不拨。
    plan: Vec<(LanePeer, Setting)>,
    /// netmap 里仍有效的对端公钥，包含已经关闭 lane、但可能还有存量流的对端。
    identities: Vec<(NodeId, PublicKey)>,
    on_demand: OnDemand,
    /// 上一次更新 lane 设置时拨着的对端。
    dialled: BTreeSet<NodeId>,
    /// relay 的 TCP 端口现在是不是把 lane 交过来。
    handoff: bool,
}

impl NodeLanes {
    /// # Errors
    ///
    /// 用节点密钥签 lane 的证书失败。
    pub(crate) fn new(key: &NodeKey, endpoint: Arc<Endpoint>) -> anyhow::Result<Self> {
        let lanes = Lanes::new(key, LaneConfig::default()).context("用节点密钥给 ice3proxy 签证书")?;
        let timing = Timing { settle: SETTLE, hold: hold() };
        Ok(Self { lanes: Arc::new(lanes), endpoint, settings: Arc::default(), dialling: Mutex::default(), timing })
    }

    /// 入口和出口开流用的连接层。
    pub(crate) fn connector(&self) -> Arc<Connector> {
        Arc::new(LaneConnector::new(Arc::clone(&self.endpoint), Arc::clone(&self.lanes), self.choose()))
    }

    /// 接受流用的连接层。
    pub(crate) fn acceptor(&self) -> Arc<Acceptor> {
        Arc::new(LaneAcceptor::new(Arc::clone(&self.endpoint), Arc::clone(&self.lanes)))
    }

    /// 一条要求走 ice3proxy 的、到 `peer` 的 TCP 流该不该走 lane（别的流不问它，直接走共用的连接）。
    fn choose(&self) -> Choose {
        let (settings, endpoint, lanes) = (Arc::clone(&self.settings), Arc::clone(&self.endpoint), Arc::clone(&self.lanes));
        Arc::new(move |peer| {
            let setting = settings.read().expect("lane settings lock poisoned").get(&peer).copied();
            takes_lane(
                setting.map(|setting| setting.mode),
                || setting.and_then(|setting| setting.udp_path(endpoint.udp_path(peer))),
                || lanes.can_open(peer),
            )
        })
    }

    /// 按 netmap 设置要开 lane 的对端、本节点拨谁，以及 relay 的 TCP 端口交不交 lane。
    pub(crate) fn apply(&self, netmap: &Netmap) {
        let plan = plan(netmap);
        // 只在本节点是 relay、并且真有对端要拨过来时才让 relay 分辨：不用 lane 的节点上 relay 的 TCP 端口和原来一模一样。
        let handoff = netmap.me.relay.is_some() && !plan.is_empty();
        let mut dialling = self.dialling.lock().expect("lane dialling mutex poisoned");
        let settings: HashMap<NodeId, Setting> = plan.iter().map(|(peer, setting)| (peer.id, *setting)).collect();
        dialling.on_demand.retain(|peer| settings.get(&peer).is_some_and(|setting| setting.mode == LaneMode::UdpFallback));
        dialling.plan = plan;
        dialling.identities = netmap.peers.iter().map(|peer| (peer.id, peer.key)).collect();
        if !self.dial(&mut dialling, Instant::now(), true) {
            return;
        }
        *self.settings.write().expect("lane settings lock poisoned") = settings;
        if dialling.handoff != handoff {
            dialling.handoff = handoff;
            self.endpoint.set_lane_handoff(handoff.then(|| {
                let lanes = Arc::clone(&self.lanes);
                Arc::new(move |stream, from| lanes.accept_tcp(stream, from, &[])) as i3t_conn::TcpHandoff
            }));
        }
    }

    /// 看一眼到 `udp_fallback` 的对端的路，按需开始拨或者放手。
    fn check_paths(&self) {
        let mut dialling = self.dialling.lock().expect("lane dialling mutex poisoned");
        self.dial(&mut dialling, Instant::now(), false);
    }

    /// 算出现在拨谁，有变化（或者 `changed`：计划本身变了）时交给 lane。交不出去时返回 `false`，原来的设置留着。
    fn dial(&self, dialling: &mut Dialling, now: Instant, changed: bool) -> bool {
        let Dialling { plan, identities, on_demand, dialled, .. } = dialling;
        let wanted: BTreeSet<NodeId> = plan
            .iter()
            .filter(|(peer, setting)| {
                !peer.dial.is_empty()
                    && match setting.mode {
                        LaneMode::Always => true,
                        LaneMode::UdpFallback => {
                            on_demand.wants(peer.id, setting.udp_path(self.endpoint.udp_path(peer.id)), now, self.timing)
                        }
                        LaneMode::Off => false,
                    }
            })
            .map(|(peer, _)| peer.id)
            .collect();
        if !changed && wanted == *dialled {
            return true;
        }
        let peers = plan
            .iter()
            .map(|(peer, _)| LanePeer { dial: if wanted.contains(&peer.id) { peer.dial.clone() } else { Vec::new() }, ..peer.clone() });
        if let Err(error) = self.lanes.set_peers_with_identities(peers, identities.iter().copied()) {
            // 生成 TLS 配置失败属于本机错误，重试不会恢复；保留原有配置，流继续走共用连接。
            tracing::error!(%error, "ice3proxy 配置未能生效");
            return false;
        }
        let on_demand = |id: &NodeId| plan.iter().find(|(peer, setting)| peer.id == *id && setting.mode == LaneMode::UdpFallback);
        for (peer, _) in wanted.difference(dialled).filter_map(&on_demand) {
            // 本节点侧有 UDP 仍触发拨号，原因只可能来自对端。
            let why = if self.endpoint.udp_path(peer.id) == Some(UdpSeen::OwnLeg) {
                "经中继转发，controller 标记对端不支持 UDP"
            } else {
                "本节点侧当前无 UDP 路径"
            };
            tracing::info!(peer = %peer.id, settle = ?self.timing.settle, why, "到该对端的路径持续无 UDP 已达阈值，开始拨号建立 ice3proxy");
        }
        for peer in dialled.difference(&wanted).filter(|id| on_demand(id).is_some()) {
            tracing::info!(%peer, hold = ?self.timing.hold, "到该对端的共用连接持续具备 UDP 路径（或无可用路径）已达保持期，停止拨号 ice3proxy");
        }
        *dialled = wanted;
        true
    }

    /// 跟着 netmap 改设置，盯着本节点的公网地址和到各个对端的路，直到 netmap 没有人再发。
    pub(crate) async fn follow(self: Arc<Self>, mut netmap: watch::Receiver<Arc<Netmap>>) {
        let first = Arc::clone(&netmap.borrow_and_update());
        self.apply(&first);
        let mut addresses = PublicAddresses::default();
        let mut tick = tokio::time::interval(CHECK);
        loop {
            tokio::select! {
                changed = netmap.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let current = Arc::clone(&netmap.borrow_and_update());
                    self.apply(&current);
                }
                _ = tick.tick() => {
                    if addresses.changed(&self.endpoint) {
                        self.lanes.address_changed();
                    }
                    self.check_paths();
                }
            }
        }
    }

    /// 排空开始或者撤销。
    pub(crate) fn set_draining(&self, draining: bool) {
        if draining {
            self.lanes.go_away();
        } else {
            self.lanes.come_back();
        }
    }

    /// 全部打开了 lane 的对端的状况。
    pub(crate) fn status(&self) -> LaneStatus {
        self.lanes.status()
    }

    /// 给人看、往上报的状况：只列值得看的对端（见 [`listed`]），全节点的合计照旧。
    pub(crate) fn listed_status(&self) -> LaneStatus {
        let mut status = self.lanes.status();
        status.peers.retain(|peer| {
            let setting = self.setting(peer.peer);
            listed(peer, setting.map(|setting| setting.mode), || self.udp_path(peer.peer))
        });
        status
    }

    /// lane 的状况写成上报的样子，带上到每个对端的路上有没有 UDP（`udp_fallback` 按它决定开流走不走 lane、拨不拨）。
    pub(crate) fn report(&self) -> LaneReport {
        report(&self.listed_status(), |peer| self.udp_path(peer))
    }

    fn setting(&self, peer: NodeId) -> Option<Setting> {
        self.settings.read().expect("lane settings lock poisoned").get(&peer).copied()
    }

    /// 按 `udp_fallback` 的算法，到 `peer` 的路上有没有 UDP（见 [`Setting::udp_path`]）。
    fn udp_path(&self, peer: NodeId) -> Option<bool> {
        let seen = self.endpoint.udp_path(peer);
        match self.setting(peer) {
            Some(setting) => setting.udp_path(seen),
            None => seen.map(|seen| seen != UdpSeen::NoUdp),
        }
    }
}

/// 一条到对端的 TCP 流走不走 lane。`udp_path`（到对端的路上有没有 UDP，见 [`Setting::udp_path`]）和 `lanes_up`
/// （和对端之间的控制 lane 在）只在 `udp_fallback` 时才问。
///
/// `udp_fallback` 模式下 lane 未建立时不尝试获取：拨号方按需拨号，对端尚未建立连接属于常态而非失败，
/// 即使尝试也只会立即回退到共用连接，还会额外增加回退计数。`always` 模式仍会尝试，获取失败时再回退并计数。
fn takes_lane(mode: Option<LaneMode>, udp_path: impl FnOnce() -> Option<bool>, lanes_up: impl FnOnce() -> bool) -> bool {
    match mode {
        Some(LaneMode::Always) => true,
        Some(LaneMode::UdpFallback) => udp_path() == Some(false) && lanes_up(),
        Some(LaneMode::Off) | None => false,
    }
}

/// 判断对端是否需要在上报、`i3t status` 和本机 `/metrics` 中展示。`always` 全部展示；`udp_fallback` 仅展示当前需要或正在使用的对端：
/// 正在拨号、控制 lane 在线、存在空闲/使用中/拨号中的 lane，或到该对端的路径无 UDP。
///
/// 旧版 controller 会为未配置的对端组合默认下发 `udp_fallback`，导致每个 relay 都与其他节点开启了 ice3proxy；双方均支持 UDP 时
/// 并未建立任何连接，展示出来全是零值。累计计数不因此保留单对端条目，均已计入全节点汇总。
fn listed(peer: &PeerLaneStatus, mode: Option<LaneMode>, udp_path: impl FnOnce() -> Option<bool>) -> bool {
    let live = peer.dials
        || peer.control
        || peer.idle + peer.ready + peer.parked_at_peer > 0
        || peer.counts.in_use > 0
        || peer.counts.dialling > 0;
    match mode {
        Some(LaneMode::UdpFallback) => live || udp_path() == Some(false),
        Some(LaneMode::Always | LaneMode::Off) | None => true,
    }
}

/// [`HOLD`]，测试可以用环境变量改。
fn hold() -> Duration {
    std::env::var(HOLD_TEST_SWITCH).ok().and_then(|value| value.parse().ok()).map_or(HOLD, Duration::from_secs)
}

/// `udp_fallback` 的按需拨号：本节点能拨的对端里，最近没有 UDP 的路的那些。
#[derive(Debug, Default)]
struct OnDemand {
    watched: HashMap<NodeId, Watch>,
}

/// 一个没有 UDP 的路的对端。
#[derive(Debug, Clone, Copy)]
struct Watch {
    /// 从什么时候起一直没有 UDP（中间没看到过 UDP）。
    since: Instant,
    /// 最近一次观测到存在路径且本节点侧无 UDP 的时刻。
    last: Instant,
    dialling: bool,
}

/// 按需拨号的两个时长阈值：开始拨号前等待时长（[`SETTLE`]），UDP 恢复后维持拨号时长（[`HOLD`]）。
#[derive(Debug, Clone, Copy)]
struct Timing {
    settle: Duration,
    hold: Duration,
}

impl OnDemand {
    /// 根据到 `peer` 的路径状态（`udp_path`，见 [`Endpoint::udp_path`]），返回当前是否应拨号。
    ///
    /// 未拨号时：存在路径且本节点侧无 UDP 连续满 `settle` 后开始拨号；观测到 UDP 则重新计时。
    /// 拨号中时：自最后一次观测到无 UDP 起满 `hold` 才停止，期间 UDP 短暂恢复仍保持拨号。
    /// 无可用路径（`None`）既不视为无 UDP 也不视为有 UDP：既不触发拨号，也不重置等待计时。
    fn wants(&mut self, peer: NodeId, udp_path: Option<bool>, now: Instant, timing: Timing) -> bool {
        if udp_path == Some(false) {
            self.watched.entry(peer).or_insert(Watch { since: now, last: now, dialling: false }).last = now;
        }
        let Some(watch) = self.watched.get_mut(&peer) else { return false };
        let keep = if watch.dialling {
            watch.dialling = now.saturating_duration_since(watch.last) < timing.hold;
            watch.dialling
        } else {
            watch.dialling = udp_path == Some(false) && now.saturating_duration_since(watch.since) >= timing.settle;
            udp_path != Some(true)
        };
        let dialling = watch.dialling;
        if !keep {
            self.watched.remove(&peer);
        }
        dialling
    }

    /// 只留下 `keep` 说还要按需拨的对端。
    fn retain(&mut self, keep: impl Fn(NodeId) -> bool) {
        self.watched.retain(|peer, _| keep(*peer));
    }
}

/// 要开 lane 的对端和它们的设置。两边都不能被拨的对端不在里面。
fn plan(netmap: &Netmap) -> Vec<(LanePeer, Setting)> {
    let me_relay = netmap.me.relay.is_some();
    let wanted = netmap.peers.iter().filter(|peer| peer.lane != LaneMode::Off);
    wanted
        .filter_map(|peer| {
            let dial: Vec<_> = netmap.relays.iter().find(|relay| relay.id == peer.id).map(|relay| relay.tcp.clone()).unwrap_or_default();
            let setting = Setting { mode: peer.lane, no_udp: peer.no_udp };
            (me_relay || !dial.is_empty()).then_some((LanePeer { id: peer.id, key: peer.key, dial }, setting))
        })
        .collect()
}

/// 本节点的公网 IP（端口不算：TCP 的源端口每条连接都不一样）。换了一批才算变了，暂时一个都不知道不算。
#[derive(Debug, Default)]
struct PublicAddresses {
    known: BTreeSet<IpAddr>,
}

impl PublicAddresses {
    fn changed(&mut self, endpoint: &Endpoint) -> bool {
        let now: BTreeSet<IpAddr> = endpoint.public_addresses().iter().map(|addr| addr.ip().to_canonical()).collect();
        if now.is_empty() || now == self.known {
            return false;
        }
        let first = self.known.is_empty();
        self.known = now;
        !first
    }
}

/// lane 的状况写成上报的样子。`udp_path` 说到一个对端的共用连接现在有没有 UDP 的路，不知道（没有路）时是 `None`。
pub(crate) fn report(status: &LaneStatus, udp_path: impl Fn(NodeId) -> Option<bool>) -> LaneReport {
    let failures = &status.handshake_failures;
    LaneReport {
        total: counts(&status.total),
        handshake_failures: LaneHandshakeFailures {
            deadline: failures.deadline,
            unknown_key: failures.unknown_key,
            tls: failures.tls,
            protocol: failures.protocol,
            busy: failures.busy,
        },
        peers: status
            .peers
            .iter()
            .map(|peer| PeerLanes {
                peer: peer.peer,
                dials: peer.dials,
                control: peer.control,
                idle: peer.idle,
                ready: peer.ready,
                parked_at_peer: peer.parked_at_peer,
                udp_path: udp_path(peer.peer),
                counts: counts(&peer.counts),
            })
            .collect(),
    }
}

fn counts(counts: &i3t_lane::LaneCounts) -> LaneCounts {
    LaneCounts {
        in_use: counts.in_use,
        dialling: counts.dialling,
        claims: counts.claims,
        claims_waited: counts.claims_waited,
        claim_wait_ms: u64::try_from(counts.claim_wait.as_millis()).unwrap_or(u64::MAX),
        claims_failed: counts.claims_failed,
        fallbacks: counts.fallbacks,
        dial_failures: counts.dial_failures,
        refused: counts.refused,
        sealed_bytes: counts.sealed_bytes,
        passthrough_bytes: counts.passthrough_bytes,
        spliced_bytes: counts.spliced_bytes,
    }
}

#[cfg(test)]
mod tests {
    use i3t_conn::{Acceptor as _, EndpointConfig, SendStream as _};
    use i3t_lane::Payload;
    use i3t_model::netmap::{Peer, Relay, RelayRole};
    use i3t_proto::PublicKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::control::testing::netmap;

    fn with_peer(netmap: &mut Netmap, raw: u8, lane: LaneMode) -> NodeId {
        let id = NodeId::new(u32::from(raw)).unwrap();
        netmap.peers.push(Peer {
            id,
            key: PublicKey::from_bytes([raw; 32]),
            name: format!("node-{raw}"),
            virtual_ip: std::net::Ipv4Addr::new(10, 66, 0, raw),
            inbound: true,
            outbound: true,
            endpoints: Vec::new(),
            attached: Vec::new(),
            exit: None,
            dial_out_only: false,
            keep_alive: false,
            lane,
            congestion: None,
            no_udp: false,
        });
        id
    }

    fn relay(netmap: &mut Netmap, id: NodeId, tcp: &[&str]) {
        netmap.relays.push(Relay {
            id,
            key: PublicKey::from_bytes([9; 32]),
            name: format!("relay-{id}"),
            udp: Vec::new(),
            tcp: tcp.iter().map(|addr| addr.parse().unwrap()).collect(),
        });
    }

    #[test]
    fn only_peers_with_lanes_on_that_one_side_can_dial_are_planned() {
        let mut map = netmap(1);
        let off = with_peer(&mut map, 2, LaneMode::Off);
        let public = with_peer(&mut map, 3, LaneMode::Always);
        let nobody = with_peer(&mut map, 4, LaneMode::UdpFallback);
        let relay_without_tcp = with_peer(&mut map, 5, LaneMode::Always);
        // udp_fallback（旧的 controller、静态的 netmap）和别的一样计划：能拨就记下地址，拨不拨按需。
        let by_default = with_peer(&mut map, 6, LaneMode::UdpFallback);
        relay(&mut map, off, &["203.0.113.2:20330"]);
        relay(&mut map, public, &["203.0.113.3:20330"]);
        relay(&mut map, relay_without_tcp, &[]);
        relay(&mut map, by_default, &["203.0.113.6:20330"]);

        let planned: Vec<_> = plan(&map).into_iter().map(|(peer, setting)| (peer.id, peer.dial.len(), setting.mode)).collect();
        assert_eq!(planned, vec![(public, 1, LaneMode::Always), (by_default, 1, LaneMode::UdpFallback)], "两边都不能被拨的对端当作 off");

        // 本节点自己是 relay：别人拨过来，不能被拨的对端也要登记（只接受它拨来的）。
        map.me.relay = Some(RelayRole::default());
        let planned: Vec<_> = plan(&map).into_iter().map(|(peer, setting)| (peer.id, peer.dial.len(), setting.mode)).collect();
        assert_eq!(
            planned,
            vec![
                (public, 1, LaneMode::Always),
                (nobody, 0, LaneMode::UdpFallback),
                (relay_without_tcp, 0, LaneMode::Always),
                (by_default, 1, LaneMode::UdpFallback)
            ]
        );
    }

    #[test]
    fn on_demand_dials_after_its_own_leg_has_had_no_udp_for_a_while_and_lets_go_after_the_hold() {
        let peer = NodeId::new(2).unwrap();
        let timing = Timing { settle: Duration::from_secs(40), hold: Duration::from_secs(600) };
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut demand = OnDemand::default();
        let mut wants = |udp_path, secs| demand.wants(peer, udp_path, at(secs), timing);

        assert!(!wants(Some(true), 0), "有 UDP 的路：不拨");
        assert!(!wants(None, 1), "没有路不算没有 UDP：对端离线时不去拨它");
        // 会话的 UDP 没抢过 TCP、30 秒后重试成功：这一阵不拨。
        assert!(!wants(Some(false), 2));
        assert!(!wants(Some(false), 33));
        assert!(!wants(Some(true), 34), "UDP 回来了：没拨过，什么都不花");
        assert!(!wants(Some(false), 35), "又没了：从头等");
        assert!(!wants(None, 60), "中间没有路：不拨，也不从头算");
        assert!(!wants(Some(false), 74));
        assert!(wants(Some(false), 75), "连续 40 秒没有 UDP：拨");
        assert!(wants(Some(false), 100));
        // UDP 回来了：还拨着，从最后一次看到没有 UDP 算起满 hold 才放手。
        assert!(wants(Some(true), 101));
        assert!(wants(None, 300), "中间没有路也一样等满");
        assert!(wants(Some(true), 699));
        assert!(!wants(Some(true), 700), "满 hold：放手");
        assert!(!wants(Some(true), 701));
        // UDP 又没了：再等 40 秒才拨。
        assert!(!wants(Some(false), 800));
        assert!(wants(Some(false), 840));
        // UDP 在 hold 之内来了又走：一直拨着，从最后一次没有 UDP 重新算。
        assert!(wants(Some(true), 1000));
        assert!(wants(Some(false), 1300));
        assert!(wants(Some(true), 1899));
        assert!(!wants(Some(true), 1900));
        assert!(demand.watched.is_empty(), "放手之后不再记着它");

        demand.wants(peer, Some(false), at(2000), timing);
        demand.retain(|_| false);
        assert!(demand.watched.is_empty(), "设置不再是 udp_fallback 的对端忘掉");
    }

    #[test]
    fn a_peer_known_to_have_no_udp_makes_a_relayed_path_count_as_without_udp_but_not_a_direct_one() {
        let plain = Setting { mode: LaneMode::UdpFallback, no_udp: false };
        let without = Setting { no_udp: true, ..plain };
        let seen = [Some(UdpSeen::WholePath), Some(UdpSeen::OwnLeg), Some(UdpSeen::NoUdp), None];
        assert_eq!(seen.map(|seen| plain.udp_path(seen)), [Some(true), Some(true), Some(false), None]);
        assert_eq!(
            seen.map(|seen| without.udp_path(seen)),
            [Some(true), Some(false), Some(false), None],
            "直连的整条路都是 UDP，照常走共用的连接；经中继时本节点这一段有 UDP 也不算：路上总有对端的那一段 TCP；没有路照旧不算没有 UDP"
        );

        // 它从 netmap 来：对端那一项的 no_udp。
        let mut map = netmap(1);
        let relay_without_udp = with_peer(&mut map, 2, LaneMode::UdpFallback);
        map.peers[0].no_udp = true;
        relay(&mut map, relay_without_udp, &["203.0.113.2:20330"]);
        let planned: Vec<_> = plan(&map).into_iter().map(|(peer, setting)| (peer.id, setting)).collect();
        assert_eq!(planned, vec![(relay_without_udp, without)]);
    }

    #[test]
    fn a_tcp_stream_takes_a_lane_by_the_setting_its_own_leg_and_whether_lanes_are_up() {
        let asked = |mode: Option<LaneMode>, udp_path: Option<bool>, up: bool| {
            let questions = std::cell::Cell::new(0);
            let taken = takes_lane(
                mode,
                || {
                    questions.set(questions.get() + 1);
                    udp_path
                },
                || {
                    questions.set(questions.get() + 1);
                    up
                },
            );
            (taken, questions.get())
        };
        assert_eq!(asked(Some(LaneMode::Always), Some(true), false), (true, 0), "always 不看路，取不到才改走");
        assert_eq!(asked(Some(LaneMode::Off), Some(false), true), (false, 0));
        assert_eq!(asked(None, Some(false), true), (false, 0), "没有为它打开 lane");
        let fallback = Some(LaneMode::UdpFallback);
        assert!(asked(fallback, Some(false), true).0, "没有 UDP、lane 建着：走 lane");
        assert!(!asked(fallback, Some(true), true).0, "有 UDP：走共用的连接");
        assert!(!asked(fallback, None, true).0, "没有路：交给共用的连接去建");
        assert!(!asked(fallback, Some(false), false).0, "lane 没建着（对方还没拨上来）：直接走共用的连接，不等");
    }

    #[test]
    fn only_peers_whose_lanes_are_wanted_or_live_are_listed() {
        let peer = |configure: &dyn Fn(&mut PeerLaneStatus)| {
            let mut peer = test_status(NodeId::new(2).unwrap());
            configure(&mut peer);
            peer
        };
        let idle = peer(&|_| {});
        let fallback = Some(LaneMode::UdpFallback);
        assert!(!listed(&idle, fallback, || Some(true)), "有 UDP、什么都没连：不列");
        assert!(!listed(&idle, fallback, || None), "没有路：不列");
        assert!(listed(&idle, fallback, || Some(false)), "本节点这一段没有 UDP：要用，列出来（看得到控制 lane 在不在）");
        assert!(listed(&idle, Some(LaneMode::Always), || Some(true)), "always 照旧都列");
        let used_before = peer(&|status| status.counts.claims = 9);
        assert!(!listed(&used_before, fallback, || Some(true)), "累计的计数不让它留着");
        for live in [
            peer(&|status| status.dials = true),
            peer(&|status| status.control = true),
            peer(&|status| status.idle = 1),
            peer(&|status| status.parked_at_peer = 1),
            peer(&|status| status.counts.in_use = 1),
            peer(&|status| status.counts.dialling = 1),
        ] {
            assert!(listed(&live, fallback, || Some(true)), "拨着、连着、用着的都列：{live:?}");
        }
    }

    #[tokio::test]
    async fn netmap_revokes_a_lane_that_was_already_draining() {
        for rotated in [None, Some(NodeKey::generate().unwrap().public())] {
            timeout(Duration::from_secs(10), async {
                let key = Arc::new(NodeKey::generate().unwrap());
                let peer_key = NodeKey::generate().unwrap();
                let mut map = netmap(1);
                let me = map.me.id;
                map.me.relay = Some(RelayRole::default());
                let peer_id = with_peer(&mut map, 2, LaneMode::Always);
                map.peers[0].key = peer_key.public();
                let (netmap_tx, netmap_rx) = watch::channel(Arc::new(map));
                let endpoint = Arc::new(
                    Endpoint::bind(EndpointConfig {
                        key: Arc::clone(&key),
                        bind: "127.0.0.1:0".parse().unwrap(),
                        netmap: netmap_rx.clone(),
                        addr_servers: Vec::new(),
                    })
                    .unwrap(),
                );
                let lanes = Arc::new(NodeLanes::new(&key, Arc::clone(&endpoint)).unwrap());
                let acceptor = lanes.acceptor();
                let follow = tokio::spawn(Arc::clone(&lanes).follow(netmap_rx));
                let peer = Lanes::new(&peer_key, LaneConfig::default()).unwrap();
                peer.set_peers([LanePeer { id: me, key: key.public(), dial: vec![endpoint.local_addr()] }]).unwrap();
                while !peer.can_open(me) {
                    sleep(Duration::from_millis(10)).await;
                }

                let (mut send, mut recv) = peer.open_stream(me).await.unwrap();
                send.write_u8(1).await.unwrap();
                send.end_header(Payload::Sealed);
                let incoming = acceptor.accept().await.unwrap();
                assert_eq!(incoming.peer, peer_id);
                assert!(incoming.send.is_lane());
                let (mut local_send, mut local_recv) = (incoming.send, incoming.recv);
                assert_eq!(local_recv.read_u8().await.unwrap(), 1);

                netmap_tx.send_modify(|map| Arc::make_mut(map).peers[0].lane = LaneMode::Off);
                while lanes.setting(peer_id).is_some() {
                    sleep(Duration::from_millis(10)).await;
                }
                send.write_u8(2).await.unwrap();
                send.flush().await.unwrap();
                assert_eq!(local_recv.read_u8().await.unwrap(), 2);
                local_send.write_u8(3).await.unwrap();
                local_send.flush().await.unwrap();
                assert_eq!(recv.read_u8().await.unwrap(), 3);

                netmap_tx.send_modify(|map| {
                    let map = Arc::make_mut(map);
                    if let Some(key) = rotated {
                        map.peers[0].key = key;
                    } else {
                        map.peers.clear();
                    }
                });
                assert!(local_recv.read(&mut [0]).await.is_err(), "授权吊销时应中断本端的读");
                drop((local_send, local_recv));
                assert!(recv.read(&mut [0]).await.is_err(), "对端也应看到异常结束");
                drop(netmap_tx);
                follow.await.unwrap();
            })
            .await
            .expect("lane 应当在身份吊销时结束");
        }
    }

    /// 一个对端的空状况。`PeerLaneStatus` 在别的 crate 里、不能直接写出来，借 `Lanes` 造一个。
    fn test_status(id: NodeId) -> PeerLaneStatus {
        let key = NodeKey::generate().unwrap();
        let lanes = Lanes::new(&key, LaneConfig::default()).unwrap();
        let peer = LanePeer { id, key: NodeKey::generate().unwrap().public(), dial: Vec::new() };
        // 不拨它（地址是空的），不用起任务，也就不需要运行时。
        lanes.set_peers([peer]).unwrap();
        lanes.status().peers.remove(0)
    }
}
