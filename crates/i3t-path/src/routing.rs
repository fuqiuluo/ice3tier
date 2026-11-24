//! 候选路径和选路。
//!
//! 这里没有 I/O，也不碰会话：外面把此刻的测量值整理成一张图交进来（本节点到各个 relay、骨干矩阵、
//! 目的节点挂靠的 relay、直连），这里列出全部候选路径、算出代价，再按选路模式挑一条。
//!
//! 延迟优先模式的规则：
//!
//! 1. 局域网直连存在就用它，不参与比较。
//! 2. 现在没有路，或者现在的路不在候选里了（断了、relay 要下线）：立刻换到代价最低的候选，不等迟滞。
//! 3. 否则每个评估窗口比一次：有候选比现在的路便宜至少 `max(5ms, 10%)`，并且连续 3 个窗口都是这样，才换过去。
//!    从一条路换到另一条路之后（不管是因为代价还是因为原来的路断了）至少停留 30 秒，才会再因为代价换路；
//!    头一次有路不算换路，所以连接刚建立时不用白等。
//! 4. 挑"最低的"时，代价相差在 5% 以内的候选之间随机取两个，用路径上 relay 负载低的那个。
//!    这样大家不会同时挤到同一个"最优"的 relay 上，又比纯随机更偏向空闲的。
//!
//! 以下两条规则基于真实链路问题补充：当仅支持 TCP 的节点到两个 relay 的链路均不稳定时，
//! 劣化阶段会话每隔十余秒断开一次，但每次重连初期的几个延迟样本偏低。若仅按上述规则，流量会每半分钟切向刚重连的链路，
//! 数秒后再次断开并切回，导致反复震荡。
//!
//! 5. 因为代价换路时，不换到入口 relay 的会话刚断过又连上的路上：要等它重新连上之后保持满一段时间
//!    （[`SETTLE`](crate::timing::SETTLE)）。从没断过的会话不用等。原来的路断了要立刻换的时候不管这一条：有路总比没有强。
//! 6. 换路之后没停留多久（不到停留期的两倍）又换，说明这两条路比不出高下：停留期加倍，最长 8 分钟。
//!    在一条路上留满了停留期的两倍，下一次换路之后停留期回到 30 秒。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use i3t_model::control::Route;
use i3t_proto::NodeId;
use i3t_proto::backbone::LinkQuality;
use i3t_proto::datagram::RelayPath;

use crate::cost::{self, Segment};
use crate::matrix::Matrix;
use crate::timing::{MAX_DWELL, MIN_DWELL, SWITCH_WINDOWS};

/// 新的路至少要便宜这么多毫秒……
const SWITCH_MARGIN_MS: f64 = 5.0;
/// ……并且至少是现在这条路的代价的这个比例，取两者里大的。
const SWITCH_MARGIN_RATIO: f64 = 0.10;
/// 代价和最低的相差在这个比例以内的候选算"差不多"，在它们之间按负载二选一。
const NEAR_EQUAL_RATIO: f64 = 0.05;

/// 一条路径是哪一条。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PathId {
    /// 直连对端的这个地址。
    Direct(SocketAddr),
    /// 按顺序经过这些 relay。
    Relays(RelayPath),
}

impl PathId {
    /// 上报和管理接口里的写法。
    pub(crate) fn to_route(self) -> Route {
        match self {
            Self::Direct(addr) => Route::Direct { addr },
            Self::Relays(relays) => Route::Relay { relays: relays.as_slice().to_vec() },
        }
    }
}

/// 路径上的一段：从谁到谁，测出来是多少。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Leg {
    pub(crate) from: NodeId,
    pub(crate) to: NodeId,
    pub(crate) segment: Segment,
}

/// 一条候选路径和它的代价。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Candidate {
    pub(crate) path: PathId,
    pub(crate) legs: Vec<Leg>,
    pub(crate) cost_ms: f64,
    /// 路径上负载最高的那个 relay 的带宽占用百分比；直连是 0。
    pub(crate) load_percent: u8,
    /// 是局域网直连。
    pub(crate) lan: bool,
    /// 可以因为代价换到这条路上：到它的入口 relay 的会话不是刚断过又连上的（见模块文档第 5 条）。直连总是 `true`。
    pub(crate) settled: bool,
}

/// 本节点现在能把包交给它的一个 relay：到它的会话是通的。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Entry {
    pub(crate) relay: NodeId,
    /// 到它的链路质量。
    pub(crate) segment: Segment,
    /// 到它的会话信得过：没有断过，或者断了重连之后已经保持了 [`SETTLE`](crate::timing::SETTLE) 那么久。
    pub(crate) settled: bool,
}

/// 到一个对端的直连，已经验证过、现在能用的。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct DirectLink {
    pub(crate) addr: SocketAddr,
    pub(crate) segment: Segment,
    pub(crate) lan: bool,
}

/// 本节点视角下的当前网络拓扑图，仅包含已确认可达的边。
pub(crate) struct Graph<'a> {
    pub(crate) me: NodeId,
    /// 一条路径最多经过几个 relay。
    pub(crate) max_hops: usize,
    /// 本节点现在能把包交给它的 relay。
    pub(crate) entries: &'a [Entry],
    pub(crate) matrix: &'a Matrix,
    pub(crate) now: Instant,
    /// 需避开的 relay（即将下线或过载）。
    pub(crate) avoid: &'a dyn Fn(NodeId) -> bool,
    /// 近期被报告不可达的骨干链路（前驱至后继节点）。
    pub(crate) broken: &'a dyn Fn(NodeId, NodeId) -> bool,
}

/// 目标对端信息。
pub(crate) struct Destination<'a> {
    pub(crate) id: NodeId,
    /// 可将数据包送达对端的出口 relay 及对端至该 relay 的链路质量；若对端自身为 relay 则亦包含在内且质量为 `None`（无末跳链路）。
    pub(crate) exits: &'a [(NodeId, Option<Segment>)],
    pub(crate) direct: Option<DirectLink>,
}

/// 枚举到 `dest` 的全部可达候选路径：直连（若可用），以及经 1 至 `max_hops` 个 relay 的每条可达路径。
///
/// 由于 relay 数量通常为个位数且最大跳数不超过 4，直接穷举即可；同时代价公式中的丢包项并非各段线性相加，无法直接使用常规最短路算法。
pub(crate) fn candidates(graph: &Graph<'_>, dest: &Destination<'_>) -> Vec<Candidate> {
    let mut found = Vec::new();
    if let Some(direct) = dest.direct {
        found.push(Candidate {
            path: PathId::Direct(direct.addr),
            legs: vec![Leg { from: graph.me, to: dest.id, segment: direct.segment }],
            cost_ms: cost::path_cost(&[direct.segment], 0, 0.0),
            load_percent: 0,
            lan: direct.lan,
            settled: true,
        });
    }
    for entry in graph.entries {
        if (graph.avoid)(entry.relay) {
            continue;
        }
        let first = Leg { from: graph.me, to: entry.relay, segment: entry.segment };
        let mut walk = Walk { relays: vec![entry.relay], legs: vec![first], settled: entry.settled };
        walk.extend(graph, dest, &mut found);
    }
    found
}

/// 穷举时走到一半的路径。
struct Walk {
    relays: Vec<NodeId>,
    legs: Vec<Leg>,
    /// 入口 relay 的会话是不是已经稳定了。
    settled: bool,
}

impl Walk {
    fn extend(&mut self, graph: &Graph<'_>, dest: &Destination<'_>, found: &mut Vec<Candidate>) {
        let Some(&last) = self.relays.last() else { return };
        if let Some((_, exit)) = dest.exits.iter().find(|(relay, _)| *relay == last)
            && let Ok(path) = RelayPath::new(&self.relays)
        {
            let mut legs = self.legs.clone();
            legs.extend(exit.map(|segment| Leg { from: last, to: dest.id, segment }));
            let segments: Vec<Segment> = legs.iter().map(|leg| leg.segment).collect();
            let loads = self.relays.iter().map(|relay| graph.matrix.load_percent(*relay, graph.now));
            let load_ms: f64 = loads.clone().map(cost::load_penalty_ms).sum();
            found.push(Candidate {
                path: PathId::Relays(path),
                cost_ms: cost::path_cost(&segments, self.relays.len(), load_ms),
                legs,
                load_percent: loads.max().unwrap_or(0),
                lan: false,
                settled: self.settled,
            });
        }
        // 到了对端自己（它是 relay）就不再往前；本节点自己的 relay 只用来把包交给挂在它上面的对端，不从它再绕骨干。
        if self.relays.len() >= graph.max_hops || last == dest.id || last == graph.me {
            return;
        }
        let onward: Vec<(NodeId, LinkQuality)> = graph.matrix.links_from(last, graph.now).collect();
        for (next, quality) in onward {
            if next == graph.me || self.relays.contains(&next) || (graph.avoid)(next) || (graph.broken)(last, next) {
                continue;
            }
            self.relays.push(next);
            self.legs.push(Leg { from: last, to: next, segment: segment_of(quality) });
            self.extend(graph, dest, found);
            self.relays.pop();
            self.legs.pop();
        }
    }
}

fn segment_of(quality: LinkQuality) -> Segment {
    Segment { rtt_ms: f64::from(quality.rtt_ms), jitter_ms: f64::from(quality.jitter_ms), loss: quality.loss() }
}

/// 默认模式的选择：直连可用就走直连，不和 relay 比较；否则只经一个 relay，
/// 按 `relays` 给的顺序取第一个现在能用的。
pub(crate) fn direct_first(
    direct: Option<SocketAddr>,
    relays: impl IntoIterator<Item = NodeId>,
    usable: impl Fn(NodeId) -> bool,
) -> Option<PathId> {
    direct.map(PathId::Direct).or_else(|| {
        let relay = relays.into_iter().find(|relay| usable(*relay))?;
        RelayPath::new(&[relay]).ok().map(PathId::Relays)
    })
}

/// 默认模式在直连与单跳 relay 均不可达时选用的多级 relay 路径：从 `candidates`（当前可达、按代价升序排列的候选集）中
/// 筛选经两个及以上 relay 的路径并取最优者；若当前多级路径（`current`）未被其他路径超出阈值（`max(5ms, 10%)`，见 [`lowest_cost_path`]），
/// 则维持不变。跳数上限已在候选枚举阶段约束；无符合条件候选时返回 `None`。
pub(crate) fn fallback_chain(candidates: &[&Candidate], current: Option<PathId>) -> Option<PathId> {
    let chains: Vec<&Candidate> = candidates
        .iter()
        .copied()
        .filter(|candidate| matches!(candidate.path, PathId::Relays(path) if path.as_slice().len() > 1))
        .collect();
    lowest_cost_path(&chains, current)
}

/// 延迟优先模式基于当前路径 `current` 在可达候选集 `candidates`（按代价升序）中的即时选择：
/// 局域网直连无条件优先；若最低代价候选优于当前路径且超出切换阈值（[`beats_by_margin`]）则选中之，否则保持当前路径；无候选时返回 `None`。
/// 仅比较代价差距：连续评估窗口数与切换停留期属于时间维度条件，单次快照中无法体现。
pub(crate) fn lowest_cost_path(candidates: &[&Candidate], current: Option<PathId>) -> Option<PathId> {
    if let Some(lan) = candidates.iter().find(|candidate| candidate.lan) {
        return Some(lan.path);
    }
    let cheapest = candidates.first()?;
    match current.and_then(|path| candidates.iter().find(|candidate| candidate.path == path)) {
        Some(current) if current.path != cheapest.path && !beats_by_margin(current.cost_ms, cheapest.cost_ms) => Some(current.path),
        Some(_) | None => Some(cheapest.path),
    }
}

/// 代价是 `challenger_ms` 的路比代价是 `current_ms` 的现在的路便宜得够不够换过去：至少 `max(5ms, 10%)`（模块文档第 3 条）。
/// 选路器和主动测试的路由决定（"延迟优先会怎么做"）用的都是它。
pub(crate) fn beats_by_margin(current_ms: f64, challenger_ms: f64) -> bool {
    current_ms - challenger_ms >= (current_ms * SWITCH_MARGIN_RATIO).max(SWITCH_MARGIN_MS)
}

/// 换路的原因。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Why {
    /// 局域网直连无条件优先。
    Lan,
    /// 之前没有路，现在有了。
    First,
    /// 原来的路不能用了，立刻换到次优的。
    Failover,
    /// 新的路连续几个评估窗口都明显更便宜。两个数是原来的路和新的路此刻的代价。
    Cheaper { from_ms: f64, to_ms: f64 },
    /// 一条能用的路都没有了。
    NoPath,
}

/// 延迟优先模式下，到一个对端的选路状态。
#[derive(Debug, Default)]
pub(crate) struct Selector {
    current: Option<PathId>,
    /// 上一次从一条路换到另一条路的时刻。
    switched: Option<Instant>,
    /// 那一次换路之后要停留多久；来回换的时候会加倍（见模块文档第 6 条）。
    dwell: Duration,
    /// 正在考察的更便宜的路，和它已经连续赢了几个窗口。
    challenger: Option<(PathId, u8)>,
}

impl Selector {
    /// 现在选定的路。
    pub(crate) const fn current(&self) -> Option<PathId> {
        self.current
    }

    /// 按此刻的候选重新考虑。`window` 为真表示这一次调用是一个评估窗口的边界：只有这时才数"连续几个窗口更优"；
    /// 别的时候只处理"现在的路没了"和局域网直连。`pick(n)` 返回 0 到 n-1 之间的一个随机数。
    ///
    /// 路换了的时候返回原因。
    pub(crate) fn choose(
        &mut self,
        now: Instant,
        candidates: &[Candidate],
        window: bool,
        pick: &mut dyn FnMut(usize) -> usize,
    ) -> Option<Why> {
        if let Some(lan) = candidates.iter().find(|candidate| candidate.lan) {
            self.challenger = None;
            return self.switch_to(Some(lan.path), Why::Lan, now);
        }
        let Some(current) = self.current.and_then(|path| candidates.iter().find(|candidate| candidate.path == path)) else {
            self.challenger = None;
            let all: Vec<&Candidate> = candidates.iter().collect();
            let chosen = two_choice(&near_best(&all), pick).map(|candidate| candidate.path);
            let why = match (self.current, chosen) {
                (_, None) => Why::NoPath,
                (Some(_), Some(_)) => Why::Failover,
                (None, Some(_)) => Why::First,
            };
            return self.switch_to(chosen, why, now);
        };
        if !window {
            return None;
        }
        let cheaper: Vec<&Candidate> = candidates
            .iter()
            .filter(|candidate| candidate.settled && candidate.path != current.path && beats_by_margin(current.cost_ms, candidate.cost_ms))
            .collect();
        let near = near_best(&cheaper);
        // 若上一评估窗口考察的候选路径仍位于“显著更优”集合中则继续累加计数，否则重新挑选并从 1 计数。
        let (path, wins) = match self.challenger {
            Some((path, wins)) if near.iter().any(|candidate| candidate.path == path) => (path, wins.saturating_add(1)),
            Some(_) | None => match two_choice(&near, pick) {
                Some(chosen) => (chosen.path, 1),
                None => {
                    self.challenger = None;
                    return None;
                }
            },
        };
        self.challenger = Some((path, wins));
        let dwelled = self.switched.is_none_or(|at| now.saturating_duration_since(at) >= self.dwell);
        let to_ms = near.iter().find(|candidate| candidate.path == path)?.cost_ms;
        if wins < SWITCH_WINDOWS || !dwelled {
            return None;
        }
        self.challenger = None;
        let from_ms = current.cost_ms;
        self.switch_to(Some(path), Why::Cheaper { from_ms, to_ms }, now)
    }

    fn switch_to(&mut self, path: Option<PathId>, why: Why, now: Instant) -> Option<Why> {
        if self.current == path {
            return None;
        }
        if self.current.is_some() && path.is_some() {
            let again_soon = self.switched.is_some_and(|at| now.saturating_duration_since(at) < self.dwell * 2);
            self.dwell = if again_soon { (self.dwell * 2).min(MAX_DWELL) } else { MIN_DWELL };
            self.switched = Some(now);
        }
        self.current = path;
        Some(why)
    }
}

/// `candidates` 里代价和最低的相差在 5% 以内的那些。
fn near_best<'a>(candidates: &[&'a Candidate]) -> Vec<&'a Candidate> {
    let Some(best) = candidates.iter().map(|candidate| candidate.cost_ms).min_by(f64::total_cmp) else { return Vec::new() };
    candidates.iter().copied().filter(|candidate| candidate.cost_ms <= best * (1.0 + NEAR_EQUAL_RATIO)).collect()
}

/// 在差不多的候选之间随机取两个，用负载低的；负载一样就用先取到的那个（也就是随机的）。
fn two_choice<'a>(near: &[&'a Candidate], pick: &mut dyn FnMut(usize) -> usize) -> Option<&'a Candidate> {
    match *near {
        [] => None,
        [only] => Some(only),
        _ => {
            let first = pick(near.len()) % near.len();
            // 第二个从剩下的里面取，保证和第一个不是同一个。
            let second = (first + 1 + pick(near.len() - 1) % (near.len() - 1)) % near.len();
            let (first, second) = (near[first], near[second]);
            Some(if second.load_percent < first.load_percent { second } else { first })
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use i3t_proto::backbone::{Link, RelayState, Row};

    use super::*;
    use crate::timing::EVAL_WINDOW;

    const A: u32 = 1;
    const B: u32 = 8;
    const C: u32 = 9;
    const D: u32 = 2;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn addr() -> SocketAddr {
        "203.0.113.7:20330".parse().unwrap()
    }

    fn segment(rtt_ms: f64, loss_percent: f64) -> Segment {
        Segment { rtt_ms, jitter_ms: 0.0, loss: loss_percent / 100.0 }
    }

    fn relays(ids: &[u32]) -> PathId {
        PathId::Relays(RelayPath::new(&ids.iter().map(|&id| node(id)).collect::<Vec<_>>()).unwrap())
    }

    /// 一行矩阵：`origin` 到 `links` 里各个 relay 的延迟（毫秒）和丢包（单位 0.5%）。
    fn row(matrix: &mut Matrix, origin: u32, load_percent: u8, links: &[(u32, u16, u8)], now: Instant) {
        let links = links
            .iter()
            .map(|&(relay, rtt_ms, loss_half_percent)| Link {
                relay: node(relay),
                quality: Some(LinkQuality { rtt_ms, jitter_ms: 0, loss_half_percent }),
            })
            .collect();
        let row = Row { origin: node(origin), seq: 1, state: RelayState::Serving, load_percent, links };
        let frame = Bytes::from(row.to_bytes(&[0; 64]));
        matrix.insert(row, frame, now);
    }

    /// 和 `crate::cost` 测试里同一个算例。骨干 B—C 的丢包是 0.1%，矩阵的刻度是 0.5%，所以这里写成 0：代价差不到 0.3ms，四舍五入之后一样。
    struct Example {
        matrix: Matrix,
        now: Instant,
        entries: Vec<Entry>,
        exits: Vec<(NodeId, Option<Segment>)>,
    }

    fn entry(relay: u32, segment: Segment) -> Entry {
        Entry { relay: node(relay), segment, settled: true }
    }

    impl Example {
        fn new() -> Self {
            let now = Instant::now();
            let mut matrix = Matrix::default();
            row(&mut matrix, B, 0, &[(C, 140, 0)], now);
            row(&mut matrix, C, 0, &[(B, 140, 0)], now);
            Self {
                matrix,
                now,
                entries: vec![entry(B, segment(35.0, 0.2)), entry(C, segment(200.0, 3.0))],
                exits: vec![(node(C), Some(segment(8.0, 0.0))), (node(B), Some(segment(170.0, 0.5)))],
            }
        }

        fn candidates(&self, max_hops: usize, direct: bool) -> Vec<Candidate> {
            let graph = Graph {
                me: node(A),
                max_hops,
                entries: &self.entries,
                matrix: &self.matrix,
                now: self.now,
                avoid: &|_| false,
                broken: &|_, _| false,
            };
            let direct = direct.then(|| DirectLink { addr: addr(), segment: segment(190.0, 4.0), lan: false });
            candidates(&graph, &Destination { id: node(D), exits: &self.exits, direct })
        }
    }

    fn cost_of(candidates: &[Candidate], path: PathId) -> f64 {
        candidates.iter().find(|candidate| candidate.path == path).unwrap_or_else(|| panic!("候选里应该有 {path:?}")).cost_ms.round()
    }

    /// 不随机：总是取第一个。
    fn first(_: usize) -> usize {
        0
    }

    #[test]
    fn the_worked_example_lists_the_four_candidates_with_the_costs_in_the_design() {
        let example = Example::new();
        let found = example.candidates(2, true);
        assert_eq!(cost_of(&found, PathId::Direct(addr())), 201.0);
        assert_eq!(cost_of(&found, relays(&[C])), 218.0);
        assert_eq!(cost_of(&found, relays(&[B])), 208.0);
        assert_eq!(cost_of(&found, relays(&[B, C])), 186.0);
        // 还有一条绕远的 A→C→B→D，它也是走得通的候选，只是代价高得多。
        assert_eq!(found.len(), 5);
        assert!(cost_of(&found, relays(&[C, B])) > 500.0);

        let two_hop = found.iter().find(|candidate| candidate.path == relays(&[B, C])).unwrap();
        let hops: Vec<(NodeId, NodeId)> = two_hop.legs.iter().map(|leg| (leg.from, leg.to)).collect();
        assert_eq!(hops, [(node(A), node(B)), (node(B), node(C)), (node(C), node(D))], "每一段从谁到谁都记着，给界面用");
    }

    #[test]
    fn each_mode_picks_the_path_the_design_says() {
        let example = Example::new();
        let now = example.now;

        // 延迟优先，最大级数 2：走 A→B→C→D。
        let mut selector = Selector::default();
        assert_eq!(selector.choose(now, &example.candidates(2, true), true, &mut first), Some(Why::First));
        assert_eq!(selector.current(), Some(relays(&[B, C])));

        // 延迟优先，最大级数 1：不考虑两级路径，剩下的候选里直连最低。
        let mut selector = Selector::default();
        let one_hop = example.candidates(1, true);
        assert_eq!(one_hop.len(), 3);
        selector.choose(now, &one_hop, true, &mut first);
        assert_eq!(selector.current(), Some(PathId::Direct(addr())));

        // 默认模式：直连可用就走直连，不比较。
        let attached = [node(C), node(B)];
        assert_eq!(direct_first(Some(addr()), attached, |_| true), Some(PathId::Direct(addr())));
        // 直连建不起来时只用一个 relay：离 D 最近的 C，约 208ms（200 + 8，默认模式不算代价）。
        assert_eq!(direct_first(None, attached, |_| true), Some(relays(&[C])));
        // 首选不可用时用 D 的下一个。
        assert_eq!(direct_first(None, attached, |relay| relay != node(C)), Some(relays(&[B])));
        assert_eq!(direct_first(None, attached, |_| false), None);
    }

    #[test]
    fn only_edges_that_really_connect_are_walked() {
        let mut example = Example::new();
        // B 的行里没有 C 了（连不上）：只有 C 一头说连得上不算，两个方向的两级路径都不存在。
        example.matrix = Matrix::default();
        row(&mut example.matrix, B, 0, &[], example.now);
        row(&mut example.matrix, C, 0, &[(B, 140, 0)], example.now);
        let found = example.candidates(2, false);
        let paths: Vec<PathId> = found.iter().map(|candidate| candidate.path).collect();
        assert_eq!(paths, [relays(&[B]), relays(&[C])]);

        // 没有直连、没有能进去的 relay：没有候选。
        example.entries.clear();
        assert!(example.candidates(4, false).is_empty());
    }

    #[test]
    fn relays_to_avoid_and_broken_links_are_left_out() {
        let example = Example::new();
        let graph = |avoid: &dyn Fn(NodeId) -> bool, broken: &dyn Fn(NodeId, NodeId) -> bool| {
            let graph =
                Graph { me: node(A), max_hops: 2, entries: &example.entries, matrix: &example.matrix, now: example.now, avoid, broken };
            let found = candidates(&graph, &Destination { id: node(D), exits: &example.exits, direct: None });
            found.iter().map(|candidate| candidate.path).collect::<Vec<_>>()
        };
        // C 即将下线：经过它的每一条路径都不是候选，不管它排在第几个。
        assert_eq!(graph(&|relay| relay == node(C), &|_, _| false), [relays(&[B])]);
        // B 说它到 C 没有骨干连接：只少了 A→B→C→D。
        assert_eq!(graph(&|_| false, &|from, to| (from, to) == (node(B), node(C))), [relays(&[B]), relays(&[C]), relays(&[C, B])]);
    }

    #[test]
    fn a_path_never_visits_a_relay_twice_and_respects_the_hop_limit() {
        let now = Instant::now();
        let mut matrix = Matrix::default();
        // 五个 relay 两两相通。
        let ids = [11, 12, 13, 14, 15];
        for origin in ids {
            let links: Vec<(u32, u16, u8)> = ids.iter().filter(|&&other| other != origin).map(|&other| (other, 10, 0)).collect();
            row(&mut matrix, origin, 0, &links, now);
        }
        let entries = [entry(11, segment(5.0, 0.0))];
        let exits = [(node(15), Some(segment(5.0, 0.0)))];
        let count = |max_hops| {
            let graph = Graph { me: node(A), max_hops, entries: &entries, matrix: &matrix, now, avoid: &|_| false, broken: &|_, _| false };
            let found = candidates(&graph, &Destination { id: node(D), exits: &exits, direct: None });
            for candidate in &found {
                let PathId::Relays(path) = candidate.path else { panic!("没有直连") };
                assert!(path.as_slice().len() <= max_hops);
                assert_eq!((path.first(), path.last()), (node(11), node(15)));
            }
            found.len()
        };
        // 11 → 15；中间再插 1 个（3 种）；再插 2 个（3×2 种）。
        assert_eq!((count(1), count(2), count(3), count(4)), (0, 1, 4, 10));
    }

    #[test]
    fn a_destination_that_is_itself_a_relay_ends_the_path_and_this_nodes_own_relay_is_not_a_transit() {
        let now = Instant::now();
        let mut matrix = Matrix::default();
        row(&mut matrix, B, 0, &[(D, 30, 0), (C, 10, 0), (A, 5, 0)], now);
        row(&mut matrix, D, 0, &[(C, 10, 0), (B, 30, 0)], now);
        row(&mut matrix, A, 0, &[(B, 5, 0)], now);
        // 对端 D 自己是 relay；本节点 A 也是 relay，D 在 A 上有会话。
        let entries = [entry(B, segment(20.0, 0.0)), entry(D, segment(60.0, 0.0)), entry(A, segment(0.0, 0.0))];
        let exits = [(node(D), None), (node(A), Some(segment(60.0, 0.0)))];
        let graph = Graph { me: node(A), max_hops: 3, entries: &entries, matrix: &matrix, now, avoid: &|_| false, broken: &|_, _| false };
        let found = candidates(&graph, &Destination { id: node(D), exits: &exits, direct: None });
        let paths: Vec<PathId> = found.iter().map(|candidate| candidate.path).collect();
        assert_eq!(paths, [relays(&[B, D]), relays(&[D]), relays(&[A])], "到了 D 就停；A 自己的 relay 不再往骨干上绕");
        assert_eq!(found[0].legs.len(), 2, "对端自己是最后一个 relay，没有再往后的一段");
        assert!((found[0].cost_ms - 52.0).abs() < 1e-9);
    }

    /// 两个岛：本节点 A 只够得着 B（自己局域网里的 relay），对端 D 只挂在 C 上（它那边的 relay），B 和 C 之间有骨干，还有一条绕 E 的远路。
    fn islands() -> Example {
        const E: u32 = 10;
        let now = Instant::now();
        let mut matrix = Matrix::default();
        row(&mut matrix, B, 0, &[(C, 40, 0), (E, 10, 0)], now);
        row(&mut matrix, C, 0, &[(B, 40, 0), (E, 10, 0)], now);
        row(&mut matrix, E, 0, &[(B, 10, 0), (C, 10, 0)], now);
        Example { matrix, now, entries: vec![entry(B, segment(5.0, 0.0))], exits: vec![(node(C), Some(segment(5.0, 0.0)))] }
    }

    #[test]
    fn with_no_direct_path_and_no_single_relay_the_default_mode_takes_the_cheapest_chain_within_the_hop_limit() {
        let islands = islands();
        let found = |max_hops| {
            let mut found = islands.candidates(max_hops, false);
            found.sort_by(|a, b| a.cost_ms.total_cmp(&b.cost_ms));
            found
        };
        let three = found(3);
        let usable: Vec<&Candidate> = three.iter().collect();
        // 经 E 的那一串更便宜（10 + 10 对 40），三级以内的都算。
        assert_eq!(fallback_chain(&usable, None), Some(relays(&[B, 10, C])));
        let two = found(2);
        let usable: Vec<&Candidate> = two.iter().collect();
        assert_eq!(fallback_chain(&usable, None), Some(relays(&[B, C])), "网络只允许两级时就是 B → C");
        assert_eq!(fallback_chain(&[], None), None, "没有候选就没有路");
        // 一个 relay 的候选不算一串：它要是走得了，默认模式在这之前就选了它。
        let single = candidate(relays(&[B]), 10.0);
        assert_eq!(fallback_chain(&[&single], None), None);
    }

    #[test]
    fn the_default_mode_keeps_its_chain_unless_another_is_cheaper_by_the_selectors_margin() {
        let (current, close, far_cheaper) = (relays(&[B, C]), relays(&[B, 10, C]), relays(&[11, C]));
        let options = [candidate(close, 95.0), candidate(current, 100.0)];
        let usable: Vec<&Candidate> = options.iter().collect();
        assert_eq!(fallback_chain(&usable, Some(current)), Some(current), "便宜 5ms 不够 10%：不跟着测量的起伏换");
        let options = [candidate(far_cheaper, 80.0), candidate(current, 100.0)];
        let usable: Vec<&Candidate> = options.iter().collect();
        assert_eq!(fallback_chain(&usable, Some(current)), Some(far_cheaper));
        // 现在那一串走不了了（不在候选里）：换到剩下的里面最便宜的。
        let options = [candidate(close, 95.0)];
        let usable: Vec<&Candidate> = options.iter().collect();
        assert_eq!(fallback_chain(&usable, Some(current)), Some(close));
    }

    fn candidate(path: PathId, cost_ms: f64) -> Candidate {
        Candidate { path, legs: Vec::new(), cost_ms, load_percent: 0, lan: false, settled: true }
    }

    /// 从 `start` 起每个评估窗口调用一次，返回第几个窗口（从 1 数）换了路。
    fn windows_until_switch(selector: &mut Selector, start: Instant, candidates: &[Candidate], limit: u32) -> Option<u32> {
        (1..=limit).find(|&window| selector.choose(start + EVAL_WINDOW * window, candidates, true, &mut first).is_some())
    }

    #[test]
    fn a_cheaper_path_must_win_three_consecutive_windows_before_the_switch() {
        let start = Instant::now();
        let (old, new) = (relays(&[B]), relays(&[C]));
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(old, 100.0)], true, &mut first);

        let better = [candidate(old, 100.0), candidate(new, 80.0)];
        assert_eq!(selector.choose(start + EVAL_WINDOW, &better, true, &mut first), None);
        assert_eq!(selector.choose(start + EVAL_WINDOW * 2, &better, true, &mut first), None);
        // 窗口之间的调用不算数：多调用几次也不会提前。
        assert_eq!(selector.choose(start + EVAL_WINDOW * 2 + Duration::from_millis(50), &better, false, &mut first), None);
        assert_eq!(selector.current(), Some(old));
        assert_eq!(selector.choose(start + EVAL_WINDOW * 3, &better, true, &mut first), Some(Why::Cheaper { from_ms: 100.0, to_ms: 80.0 }));
        assert_eq!(selector.current(), Some(new));

        // 中间有一个窗口不够好，就要重新数三个。
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(old, 100.0)], true, &mut first);
        let barely = [candidate(old, 100.0), candidate(new, 95.0)];
        selector.choose(start + EVAL_WINDOW, &better, true, &mut first);
        selector.choose(start + EVAL_WINDOW * 2, &better, true, &mut first);
        assert_eq!(selector.choose(start + EVAL_WINDOW * 3, &barely, true, &mut first), None);
        assert_eq!(windows_until_switch(&mut selector, start + EVAL_WINDOW * 3, &better, 10), Some(3));
    }

    #[test]
    fn the_margin_is_five_milliseconds_or_ten_percent_whichever_is_larger() {
        let start = Instant::now();
        let (old, new) = (relays(&[B]), relays(&[C]));
        let switches = |old_ms: f64, new_ms: f64| {
            let mut selector = Selector::default();
            selector.choose(start, &[candidate(old, old_ms)], true, &mut first);
            windows_until_switch(&mut selector, start, &[candidate(old, old_ms), candidate(new, new_ms)], 10).is_some()
        };
        // 低延迟：10% 不到 5ms，按 5ms 算。
        assert!(!switches(20.0, 15.5));
        assert!(switches(20.0, 15.0));
        // 高延迟：按 10% 算。
        assert!(!switches(200.0, 181.0));
        assert!(switches(200.0, 180.0));
    }

    #[test]
    fn a_failover_also_starts_the_dwell_but_the_first_route_does_not() {
        let start = Instant::now();
        let (one, two) = (relays(&[B]), relays(&[C]));
        // 头一次有路：不算换路，更便宜的候选连续赢三个窗口就换，不用等 30 秒。
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(one, 100.0)], true, &mut first);
        assert_eq!(windows_until_switch(&mut selector, start, &[candidate(one, 100.0), candidate(two, 50.0)], 10), Some(3));

        // 原来的路断了，立刻换到另一条；断的那条马上又好了，而且便宜得多：也要在新的路上停满 30 秒。
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(one, 50.0), candidate(two, 100.0)], true, &mut first);
        assert_eq!(selector.choose(start + EVAL_WINDOW, &[candidate(two, 100.0)], false, &mut first), Some(Why::Failover));
        let recovered = [candidate(one, 50.0), candidate(two, 100.0)];
        let back = windows_until_switch(&mut selector, start + EVAL_WINDOW, &recovered, 20).unwrap();
        assert_eq!(EVAL_WINDOW * back, MIN_DWELL, "断了又好的路不会让连接每隔十几秒来回换一次");
    }

    #[test]
    fn after_a_cost_based_switch_the_route_stays_for_thirty_seconds() {
        let start = Instant::now();
        let (first_path, second_path) = (relays(&[B]), relays(&[C]));
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(first_path, 100.0)], true, &mut first);
        let towards_second = [candidate(first_path, 100.0), candidate(second_path, 50.0)];
        assert_eq!(windows_until_switch(&mut selector, start, &towards_second, 10), Some(3));
        let switched = start + EVAL_WINDOW * 3;

        // 条件马上反过来：三个窗口之后还不到 30 秒，继续等；满 30 秒的那个窗口才换回去。
        let towards_first = [candidate(first_path, 50.0), candidate(second_path, 100.0)];
        let back = windows_until_switch(&mut selector, switched, &towards_first, 20).unwrap();
        assert_eq!(EVAL_WINDOW * back, MIN_DWELL, "换回去发生在停留满 30 秒的时候，而不是 15 秒");
        assert_eq!(selector.current(), Some(first_path));
    }

    /// 两条路轮流显得更便宜：在哪条上，另一条就便宜一半。从 `start` 起每个评估窗口调用一次，
    /// 返回头 `count` 次换路各自离上一次换路（头一次是离 `start`）多久。
    fn gaps_between_switches(selector: &mut Selector, start: Instant, count: usize) -> Vec<Duration> {
        let (one, two) = (relays(&[B]), relays(&[C]));
        let mut last = start;
        let mut gaps = Vec::new();
        for window in 1u32.. {
            let now = start + EVAL_WINDOW * window;
            let cost = |path| if selector.current() == Some(path) { 200.0 } else { 100.0 };
            let options = [candidate(one, cost(one)), candidate(two, cost(two))];
            if selector.choose(now, &options, true, &mut first).is_some() {
                gaps.push(now.saturating_duration_since(last));
                last = now;
            }
            if gaps.len() == count {
                break;
            }
        }
        gaps
    }

    #[test]
    fn two_paths_that_keep_trading_places_are_switched_between_less_and_less_often() {
        let start = Instant::now();
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(relays(&[B]), 100.0)], true, &mut first);

        let seconds: Vec<u64> = gaps_between_switches(&mut selector, start, 7).iter().map(Duration::as_secs).collect();
        // 头一次换路只等三个评估窗口；之后每一次都紧跟着停留期满，所以停留期一路加倍到上限。
        assert_eq!(seconds, [15, 30, 60, 120, 240, 480, 480]);
    }

    #[test]
    fn keeping_a_route_for_twice_its_dwell_brings_the_dwell_back_to_thirty_seconds() {
        let start = Instant::now();
        let (one, two) = (relays(&[B]), relays(&[C]));
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(one, 100.0)], true, &mut first);
        let gaps = gaps_between_switches(&mut selector, start, 3);
        assert_eq!(gaps[2], MIN_DWELL * 2, "来回换了几次，停留期已经是 60 秒");
        let switched = start + gaps.iter().sum::<Duration>();
        let on = selector.current().unwrap();
        let off = if on == one { two } else { one };

        // 这一次两条路一样好，安安稳稳留了很久（超过停留期的两倍）……
        let quiet = switched + MIN_DWELL * 8;
        let level = [candidate(on, 100.0), candidate(off, 100.0)];
        assert_eq!(windows_until_switch(&mut selector, switched, &level, 48), None);
        // ……之后另一条路真的变好了：换过去，并且这一次换路之后的停留期是从头算的 30 秒。
        let better = [candidate(on, 200.0), candidate(off, 100.0)];
        assert_eq!(windows_until_switch(&mut selector, quiet, &better, 10), Some(3));
        let there = quiet + EVAL_WINDOW * 3;
        let back = [candidate(on, 100.0), candidate(off, 200.0)];
        assert_eq!(windows_until_switch(&mut selector, there, &back, 40).map(|windows| EVAL_WINDOW * windows), Some(MIN_DWELL));
    }

    #[test]
    fn a_path_through_a_relay_that_just_connected_is_not_switched_to_on_cost() {
        let start = Instant::now();
        let (steady, fresh) = (relays(&[B]), relays(&[C]));
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(steady, 500.0)], true, &mut first);

        // 刚重连的 relay 头几个测量值很漂亮，但它还没有证明自己稳得住：便宜再多也不换。
        let unsettled = [candidate(steady, 500.0), Candidate { settled: false, ..candidate(fresh, 50.0) }];
        assert_eq!(windows_until_switch(&mut selector, start, &unsettled, 20), None);
        // 会话保持够久之后和别的候选一样比，而且要从这时起连续赢三个窗口。
        let later = start + EVAL_WINDOW * 20;
        assert_eq!(windows_until_switch(&mut selector, later, &[candidate(steady, 500.0), candidate(fresh, 50.0)], 10), Some(3));
    }

    #[test]
    fn a_path_through_a_relay_that_just_connected_is_still_taken_when_the_current_one_dies() {
        let start = Instant::now();
        let (steady, fresh) = (relays(&[B]), relays(&[C]));
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(steady, 500.0)], true, &mut first);
        let only_fresh = [Candidate { settled: false, ..candidate(fresh, 50.0) }];
        assert_eq!(selector.choose(start + Duration::from_millis(50), &only_fresh, false, &mut first), Some(Why::Failover));
        assert_eq!(selector.current(), Some(fresh));
    }

    #[test]
    fn a_route_that_dies_right_after_being_chosen_is_not_returned_to_for_twice_as_long() {
        let start = Instant::now();
        let (steady, flaky) = (relays(&[B]), relays(&[C]));
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(steady, 200.0)], true, &mut first);
        let both = [candidate(steady, 200.0), candidate(flaky, 100.0)];
        assert_eq!(windows_until_switch(&mut selector, start, &both, 10), Some(3));
        // 换过去 3 秒它就断了：立刻换回来。
        let died = start + EVAL_WINDOW * 3 + Duration::from_secs(3);
        assert_eq!(selector.choose(died, &[candidate(steady, 200.0)], false, &mut first), Some(Why::Failover));
        // 它重连之后又显得更便宜。这一回要等 60 秒而不是 30 秒才会再换过去。
        let back = windows_until_switch(&mut selector, died, &both, 40).unwrap();
        assert_eq!(EVAL_WINDOW * back, MIN_DWELL * 2);
    }

    #[test]
    fn a_dead_path_is_left_at_once_without_waiting_for_windows_or_dwell() {
        let start = Instant::now();
        let (old, new, worse) = (relays(&[B]), relays(&[C]), relays(&[B, C]));
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(old, 100.0), candidate(new, 120.0), candidate(worse, 300.0)], true, &mut first);
        assert_eq!(selector.current(), Some(old));

        // 原来的路不在候选里了（它的 relay 断了，或者宣布要下线）。不是评估窗口的边界也立刻换到次优的。
        let without_old = [candidate(new, 120.0), candidate(worse, 300.0)];
        assert_eq!(selector.choose(start + Duration::from_millis(50), &without_old, false, &mut first), Some(Why::Failover));
        assert_eq!(selector.current(), Some(new));

        // 一条都没有了：没有路。恢复之后是"有路了"，同样不等。
        assert_eq!(selector.choose(start + Duration::from_millis(100), &[], false, &mut first), Some(Why::NoPath));
        assert_eq!(selector.current(), None);
        assert_eq!(selector.choose(start + Duration::from_millis(150), &[], false, &mut first), None);
        assert_eq!(selector.choose(start + Duration::from_millis(200), &without_old, false, &mut first), Some(Why::First));
    }

    #[test]
    fn a_lan_path_wins_unconditionally_and_immediately() {
        let start = Instant::now();
        let relay = relays(&[B]);
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(relay, 10.0)], true, &mut first);
        // 局域网直连的代价更高（比如无线信号差）也照样用它，不等窗口。
        let lan = Candidate { lan: true, ..candidate(PathId::Direct(addr()), 40.0) };
        assert_eq!(
            selector.choose(start + Duration::from_millis(50), &[candidate(relay, 10.0), lan.clone()], false, &mut first),
            Some(Why::Lan)
        );
        assert_eq!(selector.current(), Some(PathId::Direct(addr())));
        assert_eq!(selector.choose(start + EVAL_WINDOW, &[candidate(relay, 10.0), lan], true, &mut first), None, "之后一直留在它上面");
        // 不是局域网的直连没有这个待遇：要按代价比。
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(relay, 10.0)], true, &mut first);
        let wan = candidate(PathId::Direct(addr()), 40.0);
        assert_eq!(selector.choose(start + EVAL_WINDOW, &[candidate(relay, 10.0), wan], true, &mut first), None);
        assert_eq!(selector.current(), Some(relay));
    }

    /// 一个可以重现的随机数序列（SplitMix64）：相邻的种子给出的序列互不相关，可以拿种子当"第几个节点"用。
    fn sequence(seed: u64) -> impl FnMut(usize) -> usize {
        let mut state = seed;
        move |bound| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            mixed ^= mixed >> 31;
            usize::try_from(mixed % u64::try_from(bound).unwrap()).unwrap()
        }
    }

    #[test]
    fn near_equal_relays_share_the_nodes_instead_of_all_taking_the_single_best() {
        let start = Instant::now();
        // 三个 relay 的代价相差不到 5%，第四个差得远。
        let paths = [relays(&[11]), relays(&[12]), relays(&[13]), relays(&[14])];
        let options = [candidate(paths[0], 100.0), candidate(paths[1], 102.0), candidate(paths[2], 104.0), candidate(paths[3], 130.0)];
        let mut chosen = [0u32; 4];
        for node_seed in 0..300 {
            let mut selector = Selector::default();
            selector.choose(start, &options, true, &mut sequence(node_seed));
            let index = paths.iter().position(|path| Some(*path) == selector.current()).unwrap();
            chosen[index] += 1;
        }
        assert_eq!(chosen[3], 0, "差得远的那个没有人选");
        assert!(chosen[..3].iter().all(|&count| count > 60), "差不多的三个各分到一批节点，而不是全挤在最便宜的那个上：{chosen:?}");
    }

    #[test]
    fn between_two_near_equal_relays_the_less_loaded_one_is_preferred() {
        let start = Instant::now();
        let (busy, idle, other) = (relays(&[11]), relays(&[12]), relays(&[13]));
        let options = [
            Candidate { load_percent: 70, ..candidate(busy, 100.0) },
            Candidate { load_percent: 10, ..candidate(idle, 103.0) },
            Candidate { load_percent: 40, ..candidate(other, 104.0) },
        ];
        let mut chosen = [0u32; 3];
        for node_seed in 0..300 {
            let mut selector = Selector::default();
            selector.choose(start, &options, true, &mut sequence(node_seed));
            let index = [busy, idle, other].iter().position(|path| Some(*path) == selector.current()).unwrap();
            chosen[index] += 1;
        }
        // 随机取两个、用负载低的：最闲的那个只要被取到就赢（三分之二），最忙的那个只要被取到就输。
        assert_eq!(chosen[0], 0, "{chosen:?}");
        assert!(chosen[1] > chosen[2] && chosen[2] > 60, "{chosen:?}");
    }

    #[test]
    fn the_challenger_is_not_re_drawn_every_window() {
        let start = Instant::now();
        let (old, one, two) = (relays(&[B]), relays(&[11]), relays(&[12]));
        let mut selector = Selector::default();
        selector.choose(start, &[candidate(old, 200.0)], true, &mut first);
        // 两条差不多便宜的新路。每个窗口都重新随机的话，很难连续三次抽到同一条，路就永远换不过去。
        let options = [candidate(old, 200.0), candidate(one, 100.0), candidate(two, 101.0)];
        let mut random = sequence(7);
        let switched =
            (1..=3).find_map(|window| selector.choose(start + EVAL_WINDOW * window, &options, true, &mut random).map(|_| window));
        assert_eq!(switched, Some(3), "第一个窗口抽中的那条连续赢三个窗口就换");
    }

    #[test]
    fn relay_load_is_part_of_the_cost_and_the_busiest_relay_on_the_path_is_reported() {
        let mut example = Example::new();
        example.matrix = Matrix::default();
        row(&mut example.matrix, B, 90, &[(C, 140, 0)], example.now);
        row(&mut example.matrix, C, 30, &[(B, 140, 0)], example.now);
        let found = example.candidates(2, false);
        // B 的占用到了 90%：经过它的路径各加 25ms。
        assert_eq!(cost_of(&found, relays(&[B])), 233.0);
        assert_eq!(cost_of(&found, relays(&[B, C])), 211.0);
        assert_eq!(cost_of(&found, relays(&[C])), 218.0);
        let load = |path: PathId| found.iter().find(|candidate| candidate.path == path).unwrap().load_percent;
        assert_eq!((load(relays(&[B, C])), load(relays(&[C]))), (90, 30));
    }
}
