//! 一条路在控制任务里的样子，以及怎么从这一刻的状态里选出它。
//!
//! [`View`] 是选路时能看到的全部东西的只读快照；[`RouteKey`] 是选出来的结果；剩下的是把结果写成给人看的话。

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use i3t_model::control::{LegTransport, Route, RouteCause, RouteHint};
use i3t_proto::NodeId;
use i3t_proto::backbone::RelayState;
use i3t_proto::datagram::{RelayHeader, RelayPath, RouteHeader};

use super::{PeerState, RelayEntry};
use crate::SessionLeg;
use crate::cost::Segment;
use crate::diag::HopSource;
use crate::matrix::Matrix;
use crate::relays::Leg;
use crate::routing::{self, Candidate, Destination, DirectLink, Entry, Graph, PathId, Why};
use crate::table::{FrameHeader, Hop, Shared};
use crate::tcp::TcpLegHandle;
use crate::timing::{PROBE_TIMEOUT_MAX, SETTLE, SWITCH_WINDOWS};

/// 从没有路变成有路之后多久之内，选中的 relay 还不算"在用"，见 [`relay_in_use`]。
const FIRST_ROUTE_GRACE: Duration = Duration::from_secs(1);

/// 到路径上首个 relay 的传输方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Via {
    Udp(SocketAddr),
    /// TCP 连接编号：重连后编号变更，发送队列也随之更新。
    Tcp(u64),
    /// relay 就是本节点自己。
    Local,
}

/// 到一个对端现在走哪条路。和收发路径上的 [`Hop`] 一一对应，多出来的用处是能比较"变没变"。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RouteKey {
    None,
    Direct(SocketAddr),
    Relay { path: RelayPath, via: Via },
}

impl RouteKey {
    /// 走的是哪条路径；没有路时是 `None`。
    pub(super) const fn path(self) -> Option<PathId> {
        match self {
            Self::None => None,
            Self::Direct(addr) => Some(PathId::Direct(addr)),
            Self::Relay { path, .. } => Some(PathId::Relays(path)),
        }
    }

    /// 上报和管理接口里的写法。
    pub(super) fn to_route(self) -> Route {
        self.path().map_or(Route::None, PathId::to_route)
    }
}

/// 一条路写给人看，日志和测试都靠它认路。
impl fmt::Display for RouteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("没有路"),
            Self::Direct(addr) => write!(f, "直连 {addr}"),
            Self::Relay { path, .. } => write!(f, "经 {}", relays_text(*path)),
        }
    }
}

/// 选路时看到的、这一刻的全部状态。
pub(super) struct View<'a> {
    pub(super) shared: &'a Arc<Shared>,
    pub(super) relays: &'a HashMap<NodeId, RelayEntry>,
    pub(super) legs: &'a HashMap<NodeId, TcpLegHandle>,
    pub(super) matrix: &'a Matrix,
    pub(super) broken: &'a [(NodeId, NodeId, Instant)],
    /// 本节点现在能把包交给它的 relay（会话是通的、延迟测出来了）。
    pub(super) entries: &'a [Entry],
    pub(super) allow_direct: bool,
    pub(super) allow_relay: bool,
    pub(super) max_hops: usize,
    pub(super) now: Instant,
}

impl View<'_> {
    /// 这个 relay 通知过自己不是正常服务的状态。
    fn avoided(&self, relay: NodeId) -> bool {
        self.relays.get(&relay).is_some_and(|entry| entry.state != RelayState::Serving)
    }

    fn draining(&self, relay: NodeId) -> bool {
        self.relays.get(&relay).is_some_and(|entry| entry.state == RelayState::Draining)
    }

    /// 对端在本节点自己的 relay 上有没有会话。
    fn local_session(&self, peer: NodeId) -> bool {
        self.shared.local_relay.get().is_some_and(|local| local.has_session(peer))
    }

    /// 对端挂靠在本节点自身 relay 上时，“本节点 relay → 对端”链路当前的测量值及其来源。
    /// 本节点侧无传输延迟（数据包直接交由对端会话），该段质量完全取决于对端会话链路：
    ///
    /// 1. 对端为 relay 且其会话位于双方之间的骨干 TCP 连接上（[`crate::backbone`]）：本节点自身会话也在同一条 TCP 上，
    ///    持续进行测量，因此直接采用本端测量值（按 TCP 估算规则，见 `crate::estimate`），使该路径与经对端 relay 的路径代价一致。
    /// 2. 对端在挂靠列表中上报了本节点：采用其上报的延迟（对端在该会话上测得）。
    /// 3. 均不可用时：采用本节点经该会话向对端发送的端到端探测（[`crate::estimate::Sampler`]，对端沿自身路由应答）。
    ///
    /// 尚未测得时返回 `None`。此前按 1 毫秒估算会导致该路径总代价低至 2 毫秒而异常优先。
    pub(super) fn local_leg(&self, id: NodeId, peer: &PeerState) -> Option<(Segment, HopSource)> {
        let theirs = self.shared.local_relay.get()?.session_leg(id)?;
        self.known_local_leg(id, peer, theirs).or_else(|| {
            let measured = peer.local_leg.measured();
            let quality = if theirs == SessionLeg::Udp { measured.quality(self.now) } else { measured.over_tcp(self.now) };
            quality.map(|quality| (quality.segment(), HopSource::Measured))
        })
    }

    /// [`local_leg`](Self::local_leg) 里不用另外探测就知道的那两种（1 和 2）。都没有时本节点要自己去量。
    pub(super) fn needs_local_probe(&self, id: NodeId, peer: &PeerState) -> bool {
        let theirs = self.shared.local_relay.get().and_then(|local| local.session_leg(id));
        theirs.is_some_and(|theirs| self.known_local_leg(id, peer, theirs).is_none())
    }

    fn known_local_leg(&self, id: NodeId, peer: &PeerState, theirs: SessionLeg) -> Option<(Segment, HopSource)> {
        let shared_tcp = theirs != SessionLeg::Udp && self.legs.get(&id).is_some_and(|leg| leg.carries(theirs));
        let own = self.relays.get(&id).filter(|_| shared_tcp).and_then(|entry| entry.link.quality(self.now));
        if let Some(quality) = own {
            return Some((quality.segment(), HopSource::Measured));
        }
        let me = self.shared.me;
        let reported = peer.attached.iter().find(|attachment| attachment.relay == me);
        reported.map(|attachment| (Segment::from_rtt_ms(f64::from(attachment.rtt_ms)), HopSource::Reported))
    }

    /// 经 `relay` 到 `peer` 的那个会话信得过，可以把流量换过去。
    ///
    /// 会话没有断过，或者断了重连之后已经保持了 [`SETTLE`] 那么久，才信得过。`relay` 是别的节点时看的是
    /// 本节点到它的会话；是本节点自己时看的是对端在本节点的 relay 上的会话。
    ///
    /// 一条时好时坏的链路，会话断了重连之后头几秒看起来总是好的；等它保持够久再把流量换过去，
    /// 免得流量跟着它一断一连地来回换。原来的路断了、只剩它能走的时候不管这一条。
    fn settled(&self, peer: NodeId, relay: NodeId) -> bool {
        if relay == self.shared.me {
            let Some(local) = self.shared.local_relay.get() else { return false };
            return local.has_session(peer) && local.session_reopened(peer).is_none_or(|held| held >= SETTLE);
        }
        self.relays.get(&relay).is_some_and(|entry| entry.link.is_settled(self.now))
    }

    fn is_broken(&self, from: NodeId, to: NodeId) -> bool {
        // 两个节点 ID 相同表示 `from` 拒绝转发任何多级路径。
        self.broken.iter().any(|&(first, next, _)| first == from && (next == to || next == first))
    }

    /// 现在能不能把发给 `peer` 的包交给 `relay`。
    fn usable(&self, peer: NodeId, relay: NodeId) -> bool {
        if relay == self.shared.me {
            return self.local_session(peer);
        }
        // 对端不是 relay 时，“对端自身”候选在 relay 表中不存在，自然忽略。
        match self.relays.get(&relay).and_then(|entry| entry.link.leg()) {
            Some(Leg::Udp(_)) => true,
            Some(Leg::Tcp) => self.legs.contains_key(&relay),
            None => false,
        }
    }

    /// 默认模式的选择：直连可用就走直连；否则经一个 relay，按 [`relay_candidates`] 的顺序取第一个现在能用的。
    pub(super) fn direct_first(&self, id: NodeId, peer: &PeerState) -> Option<PathId> {
        let direct = if self.allow_direct { peer.direct.active().map(|(addr, _)| addr) } else { None };
        if !self.allow_relay {
            return direct.map(PathId::Direct);
        }
        let current = relay_in_use(peer, self.now);
        // 通知过下线或者过载的 relay、刚说过"对端没挂在我这里"的 relay 排到后面，但不是完全不用：
        // 只有它一个可走时，对端可能只是还没来得及挂上去。
        let refused = |relay: NodeId| peer.unattached.iter().any(|(held, _)| *held == relay);
        let order = rank_relays(relay_candidates(self.shared.me, id, peer, current).collect(), current, |relay| RelayStanding {
            avoided: self.avoided(relay),
            refused: refused(relay),
            settled: self.settled(id, relay),
        });
        routing::direct_first(direct, order, |relay| self.usable(id, relay))
    }

    /// 默认模式在直连与单跳 relay 均不可达时回退使用的多级 relay 路径（按“各自可达的 relay”拼接）：
    /// 从 `candidates`（与延迟优先模式共用的候选集，经 2 至最大跳数个 relay）中选取当前可达且代价最低的一条。
    /// 若当前正在使用的多级路径（`current`）仍可达，且不存在代价低 `max(5ms, 10%)` 以上的其他多级路径，则保持不变
    /// （与主动测试判断延迟优先决策的规则一致，见 [`super::active::lowest_cost_path`]），避免随测量波动频繁切换。
    pub(super) fn chain(&self, id: NodeId, peer: &PeerState, candidates: &[Candidate], current: Option<PathId>) -> Option<PathId> {
        let usable: Vec<&Candidate> = candidates.iter().filter(|candidate| self.resolve(id, peer, candidate.path).is_some()).collect();
        routing::fallback_chain(&usable, current)
    }

    /// 默认模式此刻会选的路：直连，一个 relay，都没有的话一串 relay（[`chain`](Self::chain)）。`candidates` 是候选路径，
    /// `current` 是现在走着的那一串（不是一串时是 `None`）。
    pub(super) fn default_route(&self, id: NodeId, peer: &PeerState, candidates: &[Candidate], current: Option<PathId>) -> Option<PathId> {
        let single = self.direct_first(id, peer);
        if single.is_some() {
            return single;
        }
        self.chain(id, peer, candidates, current)
    }

    /// 到这个对端的全部候选路径和它们的代价，按代价从低到高。
    pub(super) fn candidates(&self, id: NodeId, peer: &PeerState) -> Vec<Candidate> {
        let me = self.shared.me;
        let direct = peer.direct.active().filter(|_| self.allow_direct).map(|(addr, rtt)| DirectLink {
            addr,
            segment: peer
                .direct
                .quality(self.now)
                .map_or_else(|| Segment::from_rtt_ms(rtt.get().as_secs_f64() * 1000.0), |quality| quality.segment()),
            lan: peer.direct.is_lan_active(),
        });
        let mut entries: Vec<Entry> = Vec::new();
        let mut exits: Vec<(NodeId, Option<Segment>)> = Vec::new();
        if self.allow_relay {
            entries.extend_from_slice(self.entries);
            if self.local_session(id) {
                // 对端挂靠在本节点自身 relay 上：数据包直接交给其会话，本节点侧无延迟，后半段质量见 `local_leg`。
                // 尚未测得时按探测超时上限（1.5 秒）估算：通常高于已测路径代价，仅在无其他路径时选用，也不会因低代价触发切换。
                // WebUI 认这个数：经本节点自己的 relay、代价不低于 1.5 秒的候选显示成「未测」。改这个上限或者这里的算法时要告诉前端。
                let leg = self.local_leg(id, peer).map(|(segment, _)| segment);
                let unmeasured = Segment::from_rtt_ms(PROBE_TIMEOUT_MAX.as_secs_f64() * 1000.0);
                entries.push(Entry { relay: me, segment: Segment::from_rtt_ms(0.0), settled: leg.is_some() && self.settled(id, me) });
                exits.push((me, Some(leg.unwrap_or(unmeasured))));
            }
            for attachment in peer.attached.iter().filter(|attachment| attachment.relay != id && attachment.relay != me) {
                exits.push((attachment.relay, Some(Segment::from_rtt_ms(f64::from(attachment.rtt_ms)))));
            }
            if peer.is_relay {
                exits.push((id, None));
            }
        }
        let broken = |from: NodeId, to: NodeId| self.is_broken(from, to);
        let enumerate = |avoid: &dyn Fn(NodeId) -> bool| {
            let graph =
                Graph { me, max_hops: self.max_hops, entries: &entries, matrix: self.matrix, now: self.now, avoid, broken: &broken };
            routing::candidates(&graph, &Destination { id, exits: &exits, direct })
        };
        let is_relayed = |candidate: &Candidate| matches!(candidate.path, PathId::Relays(_));
        // 通知过过载的 relay 只在没有别的 relay 可走时才用，通知过即将下线的更靠后：只有它一个 relay 可走时，
        // 它退出之前（或者很快回来之后）还能送到，比没有路强。
        let mut found = enumerate(&|relay| self.avoided(relay));
        if !found.iter().any(is_relayed) {
            found = enumerate(&|relay| self.draining(relay));
        }
        if !found.iter().any(is_relayed) {
            found = enumerate(&|_| false);
        }
        // 刚被报告或怀疑不可达的路径暂不使用，除非排除后无任何经 relay 的可用路径。
        let doubtful = |candidate: &Candidate| match candidate.path {
            PathId::Direct(_) => false,
            PathId::Relays(path) => {
                peer.suspect.iter().any(|(suspect, _)| *suspect == path) || peer.unattached.iter().any(|(relay, _)| *relay == path.last())
            }
        };
        if found.iter().any(|candidate| is_relayed(candidate) && !doubtful(candidate)) {
            found.retain(|candidate| !doubtful(candidate));
        }
        found.sort_by(|a, b| a.cost_ms.total_cmp(&b.cost_ms));
        found
    }

    /// 将逻辑路径解析为收发路径使用的转发条目。若当前不可达（直连未验证或到首个 relay 无会话）则返回 `None`。
    pub(super) fn resolve(&self, id: NodeId, peer: &PeerState, path: PathId) -> Option<(RouteKey, Hop)> {
        let me = self.shared.me;
        let path = match path {
            PathId::Direct(addr) => {
                let active = self.allow_direct && peer.direct.active().is_some_and(|(active, _)| active == addr);
                return active.then_some((RouteKey::Direct(addr), Hop::Direct(addr)));
            }
            PathId::Relays(path) => path,
        };
        if !self.allow_relay {
            return None;
        }
        let first = path.first();
        if first == me {
            // 本节点自己的 relay 只用来把包交给挂在它上面的对端。
            let local = path.as_slice().len() == 1 && self.local_session(id);
            return local.then_some((RouteKey::Relay { path, via: Via::Local }, Hop::Local));
        }
        let entry = self.relays.get(&first)?;
        let header = match *path.as_slice() {
            // 只经一个 relay 时用老的 9 字节的头。
            [_] => FrameHeader::single(RelayHeader { dst: id, src: me }),
            _ => FrameHeader::routed(&RouteHeader { dst: id, src: me, relays: path }),
        };
        let relay = Arc::clone(&entry.slot);
        match entry.link.leg()? {
            Leg::Udp(addr) => Some((RouteKey::Relay { path, via: Via::Udp(addr) }, Hop::RelayUdp { relay, addr, header })),
            Leg::Tcp => {
                let leg = self.legs.get(&first)?;
                Some((RouteKey::Relay { path, via: Via::Tcp(leg.conn) }, Hop::RelayTcp { relay, sender: leg.sender.clone(), header }))
            }
        }
    }

    /// 延迟优先模式下，现在选定的路是不是还能走。不能走了要立刻重新选，不等评估窗口。
    pub(super) fn alive(&self, id: NodeId, peer: &PeerState, path: PathId) -> bool {
        if self.resolve(id, peer, path).is_none() {
            return false;
        }
        let PathId::Relays(path) = path else { return true };
        let relays = path.as_slice();
        !relays.iter().any(|relay| self.avoided(*relay))
            && !relays.windows(2).any(|pair| self.is_broken(pair[0], pair[1]))
            && !peer.suspect.iter().any(|(suspect, _)| *suspect == path)
            && !peer.unattached.iter().any(|(relay, _)| *relay == path.last())
    }
}

/// 默认模式下现在走着的 relay（默认模式只经一个）。它在对端的挂靠表里排在前面，不因为刚连上往后排，免得来回换。
///
/// 刚从没有路变成有路的头 [`FIRST_ROUTE_GRACE`] 里不算：启动时到几个 relay 的会话往往前后脚建立，相差不到一毫秒，
/// 先建好的那个只是碰巧先到，不该因此一直占着、把对端排在前面的 relay 挡在后面。
///
/// 看的是选路规则选的路（[`PeerState::policy_route`]），不是主动测试暂时固定出来的路：测试结束之后要回到原来那条。
pub(super) fn relay_in_use(peer: &PeerState, now: Instant) -> Option<NodeId> {
    let just_picked = peer.first_route.is_some_and(|at| now.saturating_duration_since(at) < FIRST_ROUTE_GRACE);
    match peer.policy_route {
        RouteKey::Relay { path, .. } if !just_picked => Some(path.first()),
        RouteKey::Relay { .. } | RouteKey::Direct(_) | RouteKey::None => None,
    }
}

/// 默认模式下经哪些 relay 能到这个对端，按优先顺序。本节点会和其中是 relay 的那些保持会话。
///
/// 1. **对端自己。** 对端本身是启用了的 relay 时，在它那里建一个会话，把中转帧直接发给它，它收到目的是自己的帧就地收下。
///    相当于对端“挂靠于自身、延迟为 0”：数据包仅经由本节点至对端一段，不绕行第三节点。完全无法使用 UDP 的节点
///    即通过一条 TCP 连接直达具备公网端口的对端。
/// 2. **本节点自身。** 当本节点为 relay 且对端在其上有会话时，经该会话直接转发，同样无需绕路。
///    即便对端挂靠列表中其他 relay 排在更前，也应优先采用该会话。
/// 3. **对端挂靠的 relay**，按其上报延迟升序排列。仅在前两类均不可达时使用。
///    `current` 是现在走着的 relay：它还在对端的挂靠表里、延迟又没有明显高过表里最低的那个时，排在这一组的最前面。
///    对端到两个 relay 的延迟相近时，它上报的顺序会随着测量的起伏来回变，不该让路跟着变。
///
/// 前两个候选不适用时（对端不是 relay、本节点不是 relay 或者对端没挂在它上面）在选路时自然落空。
pub(super) fn relay_candidates(me: NodeId, id: NodeId, peer: &PeerState, current: Option<NodeId>) -> impl Iterator<Item = NodeId> + '_ {
    let listed = || peer.attached.iter().filter(move |attachment| attachment.relay != id && attachment.relay != me);
    let lowest = listed().map(|attachment| attachment.rtt_ms).min();
    // "明显更高"的标准和换挂靠对象时一样：高出 max(10ms, 20%)。
    let close_enough = |rtt_ms: u32| lowest.is_some_and(|lowest| rtt_ms <= lowest.saturating_add((lowest / 5).max(10)));
    let kept =
        listed().find(|attachment| Some(attachment.relay) == current && close_enough(attachment.rtt_ms)).map(|attachment| attachment.relay);
    let others = listed().map(|attachment| attachment.relay).filter(move |relay| Some(*relay) != kept);
    [id, me].into_iter().chain(kept).chain(others)
}

/// 默认模式下一个候选 relay 此刻的情况，决定它往后排多少。
#[derive(Debug, Clone, Copy)]
pub(super) struct RelayStanding {
    /// 它通知过即将下线或者过载。
    pub(super) avoided: bool,
    /// 它刚说过对端没挂在它上面。
    pub(super) refused: bool,
    /// 经它的那个会话已经保持了一段时间（见 [`View::settled`]）。
    pub(super) settled: bool,
}

/// 把默认模式的候选 relay 排成该先试哪个。`order` 是 [`relay_candidates`] 给的优先顺序，`current` 是现在走着的。
///
/// 有毛病的往后排，但不去掉：只剩它能走的时候还得用。先看 `avoided`，再看 `refused`，最后是会话刚连上的；
/// 现在走着的那个不因为"刚连上"往后排（已经在它上面了，没有"换过去"的问题）。排序是稳定的，同一档里顺序不变。
pub(super) fn rank_relays(mut order: Vec<NodeId>, current: Option<NodeId>, standing: impl Fn(NodeId) -> RelayStanding) -> Vec<NodeId> {
    order.sort_by_key(|&relay| {
        let RelayStanding { avoided, refused, settled } = standing(relay);
        (avoided, refused, Some(relay) != current && !settled)
    });
    order
}

/// 为什么走现在这条路：给人看的一句话（日志、旧的客户端），和它的代码（界面按自己的语言写）。两样说的是同一件事。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reason {
    pub(crate) text: String,
    pub(crate) cause: RouteCause,
}

impl Reason {
    pub(crate) fn new(text: impl Into<String>, cause: RouteCause) -> Self {
        Self { text: text.into(), cause }
    }

    /// 到这个对端还没有过路。
    pub(crate) fn no_route_yet() -> Self {
        Self::new("还没有可用的路径", RouteCause::NoRouteYet)
    }
}

/// 换路的直接起因写给人看。
pub(crate) const fn hint_text(hint: RouteHint) -> &'static str {
    match hint {
        RouteHint::DirectTimeouts => "直连探测连续超时",
        RouteHint::DirectLoss => "直连探测丢失超过 20%",
        RouteHint::DirectStale => "对端不活跃，直连地址过期",
        RouteHint::DirectUnavailable => "直连不可用",
        RouteHint::RelayDraining => "relay 通知即将下线",
        RouteHint::RelayOverloaded => "relay 通知过载",
        RouteHint::RelayPathBroken => "relay 报告多级路径不可达",
        RouteHint::PeerNotAttached => "relay 报告对端未挂靠",
        RouteHint::PathProbeSilent => "经多级 relay 路径的端到端探测持续无响应",
        RouteHint::PreferredRelayReady => "首次建路时先连上了非首选 relay，现对端首选 relay 会话已就绪",
        RouteHint::Shortcut => "已建立更短路径的中转会话",
        RouteHint::RelayUnavailable => "原来的 relay 不可用",
        RouteHint::RelayLost => "中转会话断开，无其他可用路径",
        RouteHint::RouteFailed => "原路径不可用",
        RouteHint::NoPath => "没有任何可用的路径",
        RouteHint::Unknown => "原因不明",
    }
}

/// 代价的毫秒数换成微秒，原因的代码里用。不是数（没找到这条候选）或者是负数时没有。借 `Duration` 来换，不用 `as`。
fn micros(ms: f64) -> Option<u64> {
    let duration = std::time::Duration::try_from_secs_f64(ms / 1000.0).ok()?;
    Some(u64::try_from(duration.as_micros()).unwrap_or(u64::MAX))
}

/// 一条路径写给人看：`relay 8 → 9`。
fn relays_text(path: RelayPath) -> String {
    let hops: Vec<String> = path.as_slice().iter().map(NodeId::to_string).collect();
    format!("relay {}", hops.join(" → "))
}

/// 延迟优先模式换路的原因。`candidates` 是做决定时的候选，用来写出代价。
pub(super) fn explain(why: Why, to: RouteKey, from: RouteKey, candidates: &[Candidate], hint: Option<RouteHint>) -> Reason {
    let chosen = to.path();
    let cost = candidates.iter().find(|candidate| Some(candidate.path) == chosen).map_or(f64::NAN, |candidate| candidate.cost_ms);
    let count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
    match why {
        Why::Lan => Reason::new(format!("对端在同一个局域网里，局域网直连无条件优先，改走{to}"), RouteCause::Lan),
        Why::First => Reason::new(
            format!("延迟优先：{} 条候选里{to}的代价最低（{cost:.0}ms）", candidates.len()),
            RouteCause::LowestCost { candidates: count, cost_us: micros(cost) },
        ),
        Why::Failover => {
            let hint = hint.unwrap_or(RouteHint::RouteFailed);
            Reason::new(
                format!("{}，不等迟滞，立刻换到剩下的 {} 条候选里代价最低的{to}（{cost:.0}ms）", hint_text(hint), candidates.len()),
                RouteCause::Failover { hint, candidates: count, cost_us: micros(cost) },
            )
        }
        Why::Cheaper { from_ms, to_ms } => Reason::new(
            format!(
                "延迟优先：{to}的代价（{to_ms:.0}ms）连续 {SWITCH_WINDOWS} 个评估窗口都比原来的{from}（{from_ms:.0}ms）低至少 max(5ms, 10%)，切换"
            ),
            RouteCause::Cheaper {
                previous: from.to_route(),
                previous_cost_us: micros(from_ms).unwrap_or_default(),
                cost_us: micros(to_ms).unwrap_or_default(),
                windows: u32::from(SWITCH_WINDOWS),
            },
        ),
        Why::NoPath => {
            let hint = hint.unwrap_or(RouteHint::NoPath);
            Reason::new(hint_text(hint), RouteCause::Unreachable { hint })
        }
    }
}

/// 默认模式换路的原因。`peer` 是这条路通向的对端。延迟优先模式下路径没变、只是到 relay 的会话换了传输时也用它。
pub(super) fn describe(peer: NodeId, from: RouteKey, to: RouteKey, hint: Option<RouteHint>) -> Reason {
    let transport = |via: Via| match via {
        Via::Udp(_) => "UDP",
        Via::Tcp(_) => "TCP",
        Via::Local => "本节点的 relay",
    };
    // 为什么是这个 relay。
    let relay_choice = |path: RelayPath, via: Via| match (path.as_slice(), via) {
        (_, Via::Local) => "本节点自己的 relay（对端在它上面有会话，不用绕别的 relay）".to_owned(),
        (&[relay], Via::Udp(_) | Via::Tcp(_)) if relay == peer => {
            format!("对端自己的 relay（它本身就是 relay，会话走 {}，不用绕别的 relay）", transport(via))
        }
        (&[relay], Via::Udp(_) | Via::Tcp(_)) => format!("对端挂靠的 relay {relay}（会话走 {}）", transport(via)),
        (_, Via::Udp(_) | Via::Tcp(_)) => format!("{}（到第一个 relay 的会话走 {}）", relays_text(path), transport(via)),
    };
    // 新的路是不是两个节点之间直接的中转会话。
    let is_shortcut = |path: RelayPath, via: Via| via == Via::Local || *path.as_slice() == [peer];
    // 默认模式经多级 relay：仅在无两端共同可达的单个 relay 时使用（见 `View::chain`）。
    let chain = |path: RelayPath, via: Via, hint: Option<RouteHint>| {
        let because = hint.map(|hint| format!("{}；", hint_text(hint))).unwrap_or_default();
        Reason::new(
            format!("{because}无两端共同可达的单个 relay，经 {}（到首个 relay 的会话使用 {}）", relays_text(path), transport(via)),
            RouteCause::NoSharedRelay { hint },
        )
    };
    let is_chain = |path: RelayPath| path.as_slice().len() > 1;
    match (from, to) {
        (_, RouteKey::Direct(addr)) => Reason::new(format!("直连地址 {addr} 验证通过，改走直连"), RouteCause::DirectVerified),
        (RouteKey::None, RouteKey::Relay { path, via }) if is_chain(path) => chain(path, via, None),
        (RouteKey::Direct(_), RouteKey::Relay { path, via }) if is_chain(path) => {
            chain(path, via, Some(hint.unwrap_or(RouteHint::DirectUnavailable)))
        }
        (RouteKey::Relay { path: old, .. }, RouteKey::Relay { path, via }) if old != path && is_chain(path) => {
            chain(path, via, Some(hint.unwrap_or(RouteHint::RelayUnavailable)))
        }
        (RouteKey::Direct(_), RouteKey::Relay { path, via }) => {
            let hint = hint.unwrap_or(RouteHint::DirectUnavailable);
            Reason::new(format!("{}，退回{}", hint_text(hint), relay_choice(path, via)), RouteCause::DirectLost { hint })
        }
        (RouteKey::None, RouteKey::Relay { path, via }) => {
            Reason::new(format!("中转会话可用，经{}", relay_choice(path, via)), RouteCause::RelayReady)
        }
        (RouteKey::Relay { path: old, .. }, RouteKey::Relay { path, via }) if old == path => {
            let leg = match via {
                Via::Udp(_) => Some(LegTransport::Udp),
                Via::Tcp(_) => Some(LegTransport::Tcp),
                Via::Local => None,
            };
            Reason::new(format!("到 relay {} 的会话改走 {}", path.first(), transport(via)), RouteCause::LegChanged { transport: leg })
        }
        (RouteKey::Relay { path: old, .. }, RouteKey::Relay { path, via }) => {
            // 从一串 relay 换到一个 relay 也是少绕了路。
            let shorter = is_shortcut(path, via) || old.as_slice().len() > path.as_slice().len();
            let hint = hint.unwrap_or(if shorter { RouteHint::Shortcut } else { RouteHint::RelayUnavailable });
            Reason::new(
                format!("{}，从 {} 换到{}", hint_text(hint), relays_text(old), relay_choice(path, via)),
                RouteCause::RelayChanged { hint, previous: old.as_slice().to_vec() },
            )
        }
        (RouteKey::Direct(_), RouteKey::None) => {
            let hint = hint.unwrap_or(RouteHint::DirectUnavailable);
            Reason::new(format!("{}，也没有 relay 可走", hint_text(hint)), RouteCause::Unreachable { hint })
        }
        (_, RouteKey::None) => {
            let hint = hint.unwrap_or(RouteHint::RelayLost);
            Reason::new(hint_text(hint), RouteCause::Unreachable { hint })
        }
    }
}

#[cfg(test)]
mod tests {
    use i3t_model::netmap::Attachment;
    use i3t_proto::PublicKey;

    use super::*;
    use crate::direct::DirectPath;
    use crate::routing::Selector;
    use crate::table::PeerSlot;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn path(relays: &[u32]) -> RelayPath {
        RelayPath::new(&relays.iter().map(|&relay| node(relay)).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn every_switch_is_described_with_its_reason() {
        let peer = node(2);
        let direct = RouteKey::Direct(addr("203.0.113.7:4000"));
        let via_udp = RouteKey::Relay { path: path(&[9]), via: Via::Udp(addr("198.51.100.9:20330")) };
        let via_tcp = RouteKey::Relay { path: path(&[9]), via: Via::Tcp(1) };
        let other = RouteKey::Relay { path: path(&[8]), via: Via::Udp(addr("198.51.100.8:20330")) };
        let itself = RouteKey::Relay { path: path(&[2]), via: Via::Tcp(2) };
        let local = RouteKey::Relay { path: path(&[1]), via: Via::Local };

        assert_eq!(describe(peer, via_udp, direct, None).text, "直连地址 203.0.113.7:4000 验证通过，改走直连");
        assert_eq!(
            describe(peer, direct, via_udp, Some(RouteHint::DirectTimeouts)).text,
            "直连探测连续超时，退回对端挂靠的 relay 9（会话走 UDP）"
        );
        assert_eq!(describe(peer, RouteKey::None, via_tcp, None).text, "中转会话可用，经对端挂靠的 relay 9（会话走 TCP）");
        assert_eq!(describe(peer, via_tcp, via_udp, None).text, "到 relay 9 的会话改走 UDP");
        assert_eq!(
            describe(peer, via_udp, other, Some(RouteHint::PeerNotAttached)).text,
            "relay 报告对端未挂靠，从 relay 9 换到对端挂靠的 relay 8（会话走 UDP）"
        );
        assert_eq!(describe(peer, via_udp, other, None).text, "原来的 relay 不可用，从 relay 9 换到对端挂靠的 relay 8（会话走 UDP）");
        assert_eq!(describe(peer, direct, RouteKey::None, None).text, "直连不可用，也没有 relay 可走");
        assert_eq!(describe(peer, via_udp, RouteKey::None, None).text, "中转会话断开，无其他可用路径");

        // 两个节点之间直接的中转会话：说明为什么不走对端挂靠表里排在前面的 relay。
        assert_eq!(
            describe(peer, RouteKey::None, itself, None).text,
            "中转会话可用，经对端自己的 relay（它本身就是 relay，会话走 TCP，不用绕别的 relay）"
        );
        assert_eq!(
            describe(peer, via_udp, itself, None).text,
            "已建立更短路径的中转会话，从 relay 9 换到对端自己的 relay（它本身就是 relay，会话走 TCP，不用绕别的 relay）"
        );
        assert_eq!(
            describe(peer, via_udp, local, None).text,
            "已建立更短路径的中转会话，从 relay 9 换到本节点自己的 relay（对端在它上面有会话，不用绕别的 relay）"
        );

        // 默认模式在无两端共同可达的单个 relay 时经多级 relay，出现可用的单跳 relay 后立即切换以缩短路径。
        let two_hops = RouteKey::Relay { path: path(&[8, 9]), via: Via::Udp(addr("198.51.100.8:20330")) };
        assert_eq!(
            describe(peer, RouteKey::None, two_hops, None).text,
            "无两端共同可达的单个 relay，经 relay 8 → 9（到首个 relay 的会话使用 UDP）"
        );
        assert_eq!(
            describe(peer, direct, two_hops, Some(RouteHint::DirectTimeouts)).text,
            "直连探测连续超时；无两端共同可达的单个 relay，经 relay 8 → 9（到首个 relay 的会话使用 UDP）"
        );
        assert_eq!(
            describe(peer, via_udp, two_hops, None).text,
            "原来的 relay 不可用；无两端共同可达的单个 relay，经 relay 8 → 9（到首个 relay 的会话使用 UDP）"
        );
        assert_eq!(
            describe(peer, two_hops, via_udp, None).text,
            "已建立更短路径的中转会话，从 relay 8 → 9 换到对端挂靠的 relay 9（会话走 UDP）"
        );
        let two_hops_tcp = RouteKey::Relay { path: path(&[8, 9]), via: Via::Tcp(4) };
        assert_eq!(describe(peer, two_hops, two_hops_tcp, None).text, "到 relay 8 的会话改走 TCP");

        assert_eq!(direct.to_route(), Route::Direct { addr: addr("203.0.113.7:4000") });
        assert_eq!(via_udp.to_route(), Route::Relay { relays: vec![node(9)] });
        assert_eq!(two_hops.to_route(), Route::Relay { relays: vec![node(8), node(9)] });
        assert_eq!(RouteKey::None.to_route(), Route::None);
        assert_eq!(
            (direct.to_string(), two_hops.to_string(), RouteKey::None.to_string()),
            ("直连 203.0.113.7:4000".to_owned(), "经 relay 8 → 9".to_owned(), "没有路".to_owned())
        );
    }

    #[test]
    fn every_reason_carries_a_code_with_the_values_it_names() {
        let peer = node(2);
        let direct = RouteKey::Direct(addr("203.0.113.7:4000"));
        let via_udp = RouteKey::Relay { path: path(&[9]), via: Via::Udp(addr("198.51.100.9:20330")) };
        let via_tcp = RouteKey::Relay { path: path(&[9]), via: Via::Tcp(1) };
        let other = RouteKey::Relay { path: path(&[8]), via: Via::Udp(addr("198.51.100.8:20330")) };
        let itself = RouteKey::Relay { path: path(&[2]), via: Via::Tcp(2) };
        let cause = |from, to, hint| describe(peer, from, to, hint).cause;

        assert_eq!(cause(via_udp, direct, None), RouteCause::DirectVerified);
        assert_eq!(cause(direct, via_udp, Some(RouteHint::DirectLoss)), RouteCause::DirectLost { hint: RouteHint::DirectLoss });
        assert_eq!(cause(direct, via_udp, None), RouteCause::DirectLost { hint: RouteHint::DirectUnavailable }, "说不出起因时是默认的");
        assert_eq!(cause(RouteKey::None, via_tcp, None), RouteCause::RelayReady);
        assert_eq!(cause(via_udp, via_tcp, None), RouteCause::LegChanged { transport: Some(LegTransport::Tcp) });
        assert_eq!(
            cause(other, via_udp, Some(RouteHint::RelayDraining)),
            RouteCause::RelayChanged { hint: RouteHint::RelayDraining, previous: vec![node(8)] }
        );
        assert_eq!(cause(via_udp, itself, None), RouteCause::RelayChanged { hint: RouteHint::Shortcut, previous: vec![node(9)] });
        let two_hops = RouteKey::Relay { path: path(&[8, 9]), via: Via::Tcp(3) };
        assert_eq!(cause(RouteKey::None, two_hops, None), RouteCause::NoSharedRelay { hint: None });
        assert_eq!(cause(direct, two_hops, None), RouteCause::NoSharedRelay { hint: Some(RouteHint::DirectUnavailable) });
        assert_eq!(
            cause(via_udp, two_hops, Some(RouteHint::PeerNotAttached)),
            RouteCause::NoSharedRelay { hint: Some(RouteHint::PeerNotAttached) }
        );
        assert_eq!(
            cause(two_hops, via_udp, None),
            RouteCause::RelayChanged { hint: RouteHint::Shortcut, previous: vec![node(8), node(9)] }
        );
        assert_eq!(cause(two_hops, direct, None), RouteCause::DirectVerified, "直连一通就换过去");
        assert_eq!(cause(direct, RouteKey::None, None), RouteCause::Unreachable { hint: RouteHint::DirectUnavailable });
        assert_eq!(cause(via_udp, RouteKey::None, None), RouteCause::Unreachable { hint: RouteHint::RelayLost });

        let candidate =
            |path: PathId, cost_ms: f64| Candidate { path, legs: Vec::new(), cost_ms, load_percent: 0, lan: false, settled: true };
        let candidates = [candidate(PathId::Direct(addr("203.0.113.7:4000")), 12.5)];
        assert_eq!(
            explain(Why::First, direct, RouteKey::None, &candidates, None).cause,
            RouteCause::LowestCost { candidates: 1, cost_us: Some(12_500) }
        );
        assert_eq!(
            explain(Why::Cheaper { from_ms: 20.0, to_ms: 12.5 }, direct, via_udp, &candidates, None).cause,
            RouteCause::Cheaper { previous: via_udp.to_route(), previous_cost_us: 20_000, cost_us: 12_500, windows: 3 }
        );
        assert_eq!(
            explain(Why::Failover, via_udp, direct, &[], Some(RouteHint::DirectStale)).cause,
            RouteCause::Failover { hint: RouteHint::DirectStale, candidates: 0, cost_us: None },
            "候选里没有它时说不出代价"
        );
        assert_eq!(explain(Why::Lan, direct, via_udp, &candidates, None).cause, RouteCause::Lan);
        assert_eq!(explain(Why::NoPath, RouteKey::None, direct, &[], None).cause, RouteCause::Unreachable { hint: RouteHint::NoPath });
    }

    #[test]
    fn every_cost_based_decision_is_explained_with_the_numbers_behind_it() {
        let direct = RouteKey::Direct(addr("203.0.113.7:4000"));
        let two_hops = RouteKey::Relay { path: path(&[8, 9]), via: Via::Udp(addr("198.51.100.8:20330")) };
        let candidate =
            |path: PathId, cost_ms: f64| Candidate { path, legs: Vec::new(), cost_ms, load_percent: 0, lan: false, settled: true };
        let candidates = [candidate(PathId::Relays(path(&[8, 9])), 185.8), candidate(PathId::Direct(addr("203.0.113.7:4000")), 201.4)];

        assert_eq!(
            explain(Why::First, two_hops, RouteKey::None, &candidates, None).text,
            "延迟优先：2 条候选里经 relay 8 → 9的代价最低（186ms）"
        );
        assert_eq!(
            explain(Why::Cheaper { from_ms: 201.4, to_ms: 185.8 }, two_hops, direct, &candidates, None).text,
            "延迟优先：经 relay 8 → 9的代价（186ms）连续 3 个评估窗口都比原来的直连 203.0.113.7:4000（201ms）低至少 max(5ms, 10%)，切换"
        );
        assert_eq!(
            explain(Why::Failover, direct, two_hops, &candidates[1..], Some(RouteHint::RelayPathBroken)).text,
            "relay 报告多级路径不可达，不等迟滞，立刻换到剩下的 1 条候选里代价最低的直连 203.0.113.7:4000（201ms）"
        );
        assert_eq!(
            explain(Why::Failover, direct, two_hops, &candidates[1..], None).text,
            "原路径不可用，不等迟滞，立刻换到剩下的 1 条候选里代价最低的直连 203.0.113.7:4000（201ms）"
        );
        assert_eq!(
            explain(Why::Lan, direct, two_hops, &candidates, None).text,
            "对端在同一个局域网里，局域网直连无条件优先，改走直连 203.0.113.7:4000"
        );
        assert_eq!(explain(Why::NoPath, RouteKey::None, direct, &[], None).text, "没有任何可用的路径");
        assert_eq!(explain(Why::NoPath, RouteKey::None, direct, &[], Some(RouteHint::DirectTimeouts)).text, "直连探测连续超时");
    }

    fn peer_attached_to(relays: &[u32]) -> PeerState {
        PeerState {
            key: PublicKey::from_bytes([2; 32]),
            attached: relays.iter().zip(1..).map(|(&relay, rtt_ms)| Attachment { relay: node(relay), rtt_ms, shared: false }).collect(),
            endpoints: Vec::new(),
            is_relay: false,
            dial_out_only: false,
            direct: DirectPath::new(),
            slot: PeerSlot::new(node(2)),
            route: RouteKey::None,
            doubt: true,
            sources: Vec::new(),
            active_source: None,
            stranger_budget: crate::budget::Budget::new(1.0, 1.0, Instant::now()),
            hint: None,
            unattached: Vec::new(),
            suspect: Vec::new(),
            probe: crate::control::PathProbe::default(),
            selector: Selector::default(),
            candidates: Vec::new(),
            reason: Reason::no_route_yet(),
            switched: None,
            first_route: None,
            pin: None,
            pinned: false,
            policy_route: RouteKey::None,
            other_mode: None,
            eager_from: None,
            local_leg: crate::estimate::Sampler::new(),
            signalled: None,
        }
    }

    #[test]
    fn a_relay_picked_the_moment_a_route_first_appeared_does_not_count_as_in_use_yet() {
        let now = Instant::now();
        let mut peer = peer_attached_to(&[8, 9]);
        peer.route = RouteKey::Relay { path: path(&[9]), via: Via::Udp(addr("198.51.100.9:20330")) };
        peer.policy_route = peer.route;
        peer.first_route = Some(now);
        assert_eq!(relay_in_use(&peer, now + Duration::from_millis(1)), None, "到 8 的会话晚到一点点，照样按对端的顺序排");
        assert_eq!(relay_in_use(&peer, now + FIRST_ROUTE_GRACE), Some(node(9)), "之后就是在用的 relay");
        peer.first_route = None;
        assert_eq!(relay_in_use(&peer, now), Some(node(9)));
        peer.policy_route = RouteKey::Direct(addr("203.0.113.7:4000"));
        assert_eq!(relay_in_use(&peer, now), None);
        // 主动测试把路固定在 relay 9 上时，"现在走着的 relay"仍然按选路规则选的那条算。
        peer.route = RouteKey::Relay { path: path(&[9]), via: Via::Udp(addr("198.51.100.9:20330")) };
        assert_eq!(relay_in_use(&peer, now), None);
    }

    #[test]
    fn a_relay_whose_session_just_connected_is_tried_after_the_ones_that_have_held() {
        let (itself, mine, listed) = (node(4), node(1), node(8));
        let order = vec![itself, mine, listed];
        let healthy = RelayStanding { avoided: false, refused: false, settled: true };
        let fresh = RelayStanding { settled: false, ..healthy };
        let ranked = |current: Option<NodeId>, fresh_ones: &[NodeId]| {
            rank_relays(order.clone(), current, |relay| if fresh_ones.contains(&relay) { fresh } else { healthy })
        };

        // 到对端自己（它是 relay）的会话刚重连上：先不换回去，留在对端挂靠的 relay 上。
        assert_eq!(ranked(Some(listed), &[itself]), [mine, listed, itself]);
        // 它保持够久之后回到最前面。
        assert_eq!(ranked(Some(listed), &[]), [itself, mine, listed]);
        // 已经走着的那个不因为刚连上往后排：刚启动时所有会话都是新的，选中的第一个不该马上又被换掉。
        assert_eq!(ranked(Some(itself), &[itself, mine, listed]), [itself, mine, listed]);
        assert_eq!(ranked(None, &[itself, mine, listed]), [itself, mine, listed], "全都是新的：按原来的优先顺序");
        // 通知过下线的排得比刚连上的还靠后。
        let standing = |relay| {
            if relay == itself {
                RelayStanding { avoided: true, ..healthy }
            } else if relay == mine {
                fresh
            } else {
                healthy
            }
        };
        assert_eq!(rank_relays(order.clone(), None, standing), [listed, mine, itself]);
    }

    #[test]
    fn the_relay_in_use_stays_first_among_the_peers_relays_unless_it_became_clearly_slower() {
        let (me, peer) = (node(1), node(2));
        let listed = |rtts: &[(u32, u32)], current: u32| {
            let mut state = peer_attached_to(&[]);
            state.attached = rtts.iter().map(|&(relay, rtt_ms)| Attachment { relay: node(relay), rtt_ms, shared: false }).collect();
            relay_candidates(me, peer, &state, Some(node(current))).skip(2).collect::<Vec<_>>()
        };
        // 对端到两个 relay 的延迟差不多，这一次上报把顺序换了：现在走着的 9 还是排在前面。
        assert_eq!(listed(&[(8, 340), (9, 350)], 9), [node(9), node(8)]);
        assert_eq!(listed(&[(8, 3), (9, 12)], 9), [node(9), node(8)], "差不到 10ms 也不算明显");
        // 9 明显变慢了（高出 20% 以上）：按对端上报的顺序来。
        assert_eq!(listed(&[(8, 340), (9, 440)], 9), [node(8), node(9)]);
        // 现在走着的 relay 已经不在对端的挂靠表里了：同样按上报的顺序。
        assert_eq!(listed(&[(8, 340), (7, 350)], 9), [node(8), node(7)]);
    }

    #[test]
    fn the_peer_itself_and_this_nodes_own_relay_come_before_the_relays_the_peer_lists() {
        let (me, peer) = (node(1), node(2));
        let order = |attached: &[u32]| relay_candidates(me, peer, &peer_attached_to(attached), None).collect::<Vec<_>>();
        // 对端只列了别的 relay：它自己和本节点仍然排在前面。
        assert_eq!(order(&[8, 9]), [peer, me, node(8), node(9)]);
        // 对端把本节点（或者它自己）列在后面也一样，而且不重复出现。
        assert_eq!(order(&[8, 1]), [peer, me, node(8)]);
        assert_eq!(order(&[8, 2, 1, 9]), [peer, me, node(8), node(9)]);
        assert_eq!(order(&[]), [peer, me]);
    }
}
