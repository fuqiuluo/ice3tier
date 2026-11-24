//! controller 侧对节点上报的 relay 连通性记录的处理。
//!
//! # Responsibilities
//! - 将节点每次上报的结果合并到持久化记录中（每个节点对每个 relay 仅保留最近一次结果）。
//! - 统计每个 relay 当前可被多少在线节点连通；若没有任何已探测的在线节点可连通，则生成相应提醒。
//! - 当两个节点之间缺少共同可达的 relay 时，选定一个共同 relay 要求双方同时挂靠（[`shared_relays`]）。
//! - 定节点的出口地址（[`egress_ip`]）。
//!
//! # Invariants
//! - 每个节点存的结果不超过 [`MAX_RELAY_TRIES`] 项，只有它所在网络里启用着的 relay。
//! - 仅对部分节点可达的 relay 属于正常情况，不触发告警；仅当已探测该 relay 的在线节点均无法连通时才生成提醒。

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use i3t_model::admin::{NodeWarning, ReachEntry, RelayReach, Timestamp};
use i3t_model::control::{MAX_RELAY_TRIES, RelayTry, TryOutcome};
use i3t_model::netmap::MAX_SHARED_RELAYS;
use i3t_proto::NodeId;

use crate::store::{NodeRecord, ReachRecord};

/// 结果没有变时，试的时刻最多隔多久记一次（秒）。有会话的 relay 每次上报都是"刚刚"，每次都记的话每个节点每 10 秒写一次存储。
const AT_RESOLUTION: Timestamp = 300;

/// 并好的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Merged {
    pub(crate) records: Vec<ReachRecord>,
    /// 存在 relay 的可达状态变化（可达与不可达互转）或新增记录：节点间是否缺少共同可达 relay 可能随之变化，需要重算 netmap。
    pub(crate) reach_changed: bool,
}

/// 把节点 `node` 这一次上报的结果并进存着的那一份。没有任何要记的变化时返回 `None`。
///
/// 仅接受属于 `relays`（所在网络已启用的 relay）且非节点自身的条目；忽略未知结果。若连通结果和观测到的 IP 均未变化，
/// 时刻最多每 [`AT_RESOLUTION`] 秒更新一次。不再是 relay 的项去掉；超过 [`MAX_RELAY_TRIES`] 项时留最近试的那些。
pub(crate) fn merge(
    stored: &[ReachRecord],
    reported: &[RelayTry],
    node: NodeId,
    relays: &BTreeSet<NodeId>,
    now: Timestamp,
) -> Option<Merged> {
    let mut records: Vec<ReachRecord> = stored.iter().copied().filter(|record| relays.contains(&record.relay)).collect();
    let mut changed = records.len() != stored.len();
    let mut reach_changed = changed;
    let valid = |entry: &&RelayTry| entry.relay != node && relays.contains(&entry.relay) && entry.outcome != TryOutcome::Unknown;
    for entry in reported.iter().take(MAX_RELAY_TRIES).filter(valid) {
        let fresh = ReachRecord {
            relay: entry.relay,
            outcome: entry.outcome,
            at: now.saturating_sub(entry.age_secs.into()),
            seen_as: entry.seen_as,
        };
        match records.iter_mut().find(|record| record.relay == entry.relay) {
            Some(record) if (record.outcome, record.seen_as) != (fresh.outcome, fresh.seen_as) => {
                reach_changed |= record.outcome.reached() != fresh.outcome.reached();
                *record = fresh;
                changed = true;
            }
            Some(record) if fresh.at >= record.at.saturating_add(AT_RESOLUTION) => {
                record.at = fresh.at;
                changed = true;
            }
            Some(_) => {}
            None => {
                records.push(fresh);
                changed = true;
                reach_changed = true;
            }
        }
    }
    if records.len() > MAX_RELAY_TRIES {
        records.sort_by_key(|record| Reverse(record.at));
        records.truncate(MAX_RELAY_TRIES);
    }
    records.sort_by_key(|record| record.relay);
    changed.then_some(Merged { records, reach_changed })
}

/// 节点的出口地址：它发往互联网的流量出去时，互联网看到的公网地址。不查任何外部的服务，只用手上现成的：
///
/// 1. controller 看到的来源地址（`observed`，走回环连过来的已经换成 controller 对外的地址）是公网地址时就是它。
/// 2. 否则（节点在 controller 所在的局域网里，或者走的是内网）用 relay 看到的公网地址。几个 relay 看到的不一样时
///    （多出口的网络、或者有的 relay 在内网里）取看到它的 relay 最多的那个；一样多时取最近一次看到的，再一样取小的。
/// 3. 只从内网地址被看到过：没有出口地址。
///
/// 出口配了上游代理时，经它替别人访问的流量其实是从代理那里出去的，这里不知道，也不去外面探。
pub(crate) fn egress_ip(record: &NodeRecord) -> Option<IpAddr> {
    if let Some(ip) = record.observed.map(|address| address.ip().to_canonical()).filter(|ip| is_public(*ip)) {
        return Some(ip);
    }
    let mut votes: BTreeMap<IpAddr, (u32, Timestamp)> = BTreeMap::new();
    for record in &record.relay_reach {
        if let Some(ip) = record.seen_as.map(|ip| ip.to_canonical()).filter(|ip| is_public(*ip)) {
            let vote = votes.entry(ip).or_default();
            vote.0 += 1;
            vote.1 = vote.1.max(record.at);
        }
    }
    votes.into_iter().max_by_key(|&(ip, (count, at))| (count, at, Reverse(ip))).map(|(ip, _)| ip)
}

/// 互联网上看得到的地址：不是私有、回环、链路本地、运营商级 NAT、组播、未指定的地址。
fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let carrier_nat = ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64;
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || carrier_nat)
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_unique_local() || ip.is_unicast_link_local())
        }
    }
}

/// 根据上报记录筛选疑似不可用 UDP 的节点：在其所有可达 relay 中没有任何一个经 UDP 连通，且至少存在一个它仅经 TCP 连通、
/// 而其他节点可经 UDP 连通的 relay。`nodes` 为网络内的全部节点（包括在线与离线节点：离线节点此前上报的记录仍可作为依据）。
///
/// 仅经 TCP 连上一个本身不支持 UDP 的 relay 并不能证明该节点不可用 UDP，因为所有节点都只能经 TCP 连接该 relay；因此必须以其他节点经 UDP
/// 可达的 relay 作为对照。若网络中只有一个 relay，或所有 relay 均不支持 UDP，则无法做出此判定（此类路径本身必然经过 TCP，
/// 节点在自身这一段即可感知）。返回值仅表示当前时刻的依据，何时生效见 `controller::no_udp`。
pub(crate) fn without_udp<'a>(nodes: impl IntoIterator<Item = &'a NodeRecord>) -> BTreeSet<NodeId> {
    let nodes: Vec<&NodeRecord> = nodes.into_iter().collect();
    let udp_relays: BTreeSet<NodeId> = nodes
        .iter()
        .flat_map(|node| relays_tried(node))
        .filter(|record| record.outcome == TryOutcome::Udp)
        .map(|record| record.relay)
        .collect();
    nodes
        .iter()
        .filter(|node| {
            relays_tried(node).all(|record| record.outcome != TryOutcome::Udp)
                && relays_tried(node).any(|record| record.outcome == TryOutcome::Tcp && udp_relays.contains(&record.relay))
        })
        .map(|node| node.id)
        .collect()
}

/// 节点试过的 relay，不算它自己。
fn relays_tried(node: &NodeRecord) -> impl Iterator<Item = &ReachRecord> {
    node.relay_reach.iter().filter(move |record| record.relay != node.id)
}

/// 一个网络里每个 relay 被在线的节点连上的情况，一次请求数一遍。
#[derive(Debug, Clone, Default)]
pub(crate) struct ReachIndex {
    counts: BTreeMap<NodeId, RelayReach>,
}

impl ReachIndex {
    /// `nodes` 是网络里的全部节点。只数在线的（`online`）、不是那个 relay 自己的节点。
    pub(crate) fn new<'a>(nodes: impl IntoIterator<Item = &'a NodeRecord>, online: impl Fn(NodeId) -> bool) -> Self {
        let nodes: Vec<&NodeRecord> = nodes.into_iter().collect();
        let relays: BTreeSet<NodeId> = nodes.iter().filter(|node| node.relay.is_some()).map(|node| node.id).collect();
        let mut counts: BTreeMap<NodeId, RelayReach> = relays.iter().map(|relay| (*relay, RelayReach::default())).collect();
        let online_nodes: Vec<&&NodeRecord> = nodes.iter().filter(|node| online(node.id)).collect();
        for node in &online_nodes {
            for record in node.relay_reach.iter().filter(|record| record.relay != node.id) {
                let Some(count) = counts.get_mut(&record.relay) else { continue };
                match record.outcome {
                    TryOutcome::Udp | TryOutcome::Tcp => count.reached += 1,
                    TryOutcome::Unreached => count.unreached += 1,
                    TryOutcome::Unknown => {}
                }
            }
        }
        let total = u32::try_from(online_nodes.len()).unwrap_or(u32::MAX);
        for (relay, count) in &mut counts {
            let others = total.saturating_sub(u32::from(online(*relay)));
            count.unknown = others.saturating_sub(count.reached + count.unreached);
        }
        Self { counts }
    }

    pub(crate) fn of(&self, relay: NodeId) -> RelayReach {
        self.counts.get(&relay).copied().unwrap_or_default()
    }

    /// 对已启用的 relay，若探测过它的在线节点均无法连通，则返回不可达提醒；只要有至少一个在线节点可连通即不告警。
    pub(crate) fn warning(&self, relay: NodeId) -> Option<NodeWarning> {
        let count = self.counts.get(&relay)?;
        (count.reached == 0 && count.unreached > 0).then_some(NodeWarning::RelayUnreached { tried: count.unreached })
    }
}

/// 报过试 `relay` 的结果的每个节点（不算它自己），按节点编号排。
pub(crate) fn reached_by<'a>(
    nodes: impl IntoIterator<Item = &'a NodeRecord>,
    relay: NodeId,
    online: impl Fn(NodeId) -> bool,
) -> Vec<ReachEntry> {
    let mut entries: Vec<ReachEntry> = nodes
        .into_iter()
        .filter(|node| node.id != relay)
        .filter_map(|node| {
            let record = node.relay_reach.iter().find(|record| record.relay == relay)?;
            Some(ReachEntry { node: node.to_ref(), online: online(node.id), outcome: record.outcome, at: record.at })
        })
        .collect();
    entries.sort_by_key(|entry| entry.node.id);
    entries
}

/// 一个节点在"缺不缺共同的 relay"这件事上的样子。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Side {
    pub(crate) id: NodeId,
    /// 它自己是启用着的 relay。
    pub(crate) is_relay: bool,
    /// 它自己挑的挂靠对象（不算 controller 要它另外挂的）。
    pub(crate) own: BTreeSet<NodeId>,
    /// 节点上报的可达 relay 集合。
    pub(crate) reached: BTreeSet<NodeId>,
}

impl Side {
    pub(crate) fn of(node: &NodeRecord, relays: &BTreeSet<NodeId>) -> Self {
        Self {
            id: node.id,
            is_relay: relays.contains(&node.id),
            own: node
                .attached
                .iter()
                .filter(|attachment| !attachment.shared && relays.contains(&attachment.relay))
                .map(|a| a.relay)
                .collect(),
            reached: node.relay_reach.iter().filter(|record| record.outcome.reached()).map(|record| record.relay).collect(),
        }
    }
}

/// `a` 和 `b` 之间要不要另找一个共同的 relay，要的话是哪一个。
///
/// 默认模式下，`a` 经 relay 到 `b` 可通过：`b` 自身（`b` 是 relay 且 `a` 可达），`a` 自身（`a` 是 relay 且 `b` 可达），
/// 或 `b` 挂靠的某个 `a` 可达的 relay；反方向同理。当双向均已有可达路径时无需额外指定。
///
/// 需要指定时，在双方共同可达的 relay 中选择：优先选择双方已挂靠的（尽量减少新增挂靠），相同时取节点编号较小者。双方计算结果一致，
/// 因此各自挂靠后可在同一 relay 会合。计算时仅考虑节点自主选择的挂靠（不计 controller 分配的共享挂靠），避免挂靠生效后结果抖动。
/// 若双方无共同可达的 relay 则返回 `None`：延迟优先模式下可能仍存在多跳 relay 路径，此处不处理。
pub(crate) fn meeting_relay(a: &Side, b: &Side, relays: &BTreeSet<NodeId>) -> Option<NodeId> {
    let through_each_other = (b.is_relay && a.reached.contains(&b.id)) || (a.is_relay && b.reached.contains(&a.id));
    let a_to_b = b.own.iter().any(|relay| a.reached.contains(relay));
    let b_to_a = a.own.iter().any(|relay| b.reached.contains(relay));
    if through_each_other || (a_to_b && b_to_a) {
        return None;
    }
    let extra = |relay: &NodeId| u8::from(!a.own.contains(relay)) + u8::from(!b.own.contains(relay));
    relays
        .iter()
        .filter(|relay| **relay != a.id && **relay != b.id && a.reached.contains(relay) && b.reached.contains(relay))
        .min_by_key(|relay| (extra(relay), **relay))
        .copied()
}

/// `me` 除了自己挑的之外还要挂靠的 relay：和每个对端算一次 [`meeting_relay`]，自己还没挂着的那些，
/// 为越多对端需要的越先，最多 [`MAX_SHARED_RELAYS`] 个，按编号排。
pub(crate) fn shared_relays<'a>(
    me: &NodeRecord,
    peers: impl IntoIterator<Item = &'a NodeRecord>,
    relays: &BTreeSet<NodeId>,
) -> Vec<NodeId> {
    let mine = Side::of(me, relays);
    let mut needed: BTreeMap<NodeId, usize> = BTreeMap::new();
    for peer in peers {
        let theirs = Side::of(peer, relays);
        if let Some(relay) = meeting_relay(&mine, &theirs, relays).filter(|relay| !mine.own.contains(relay)) {
            *needed.entry(relay).or_default() += 1;
        }
    }
    let mut ranked: Vec<(NodeId, usize)> = needed.into_iter().collect();
    ranked.sort_by_key(|&(relay, count)| (Reverse(count), relay));
    let mut chosen: Vec<NodeId> = ranked.into_iter().take(MAX_SHARED_RELAYS).map(|(relay, _)| relay).collect();
    chosen.sort_unstable();
    chosen
}

#[cfg(test)]
mod tests {
    use i3t_model::admin::RelaySettings;
    use i3t_model::netmap::Attachment;

    use super::*;
    use crate::store::fixtures::record;

    fn id(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn tried(relay: u32, outcome: TryOutcome, age_secs: u32, seen_as: Option<&str>) -> RelayTry {
        RelayTry { relay: id(relay), outcome, age_secs, seen_as: seen_as.map(|ip| ip.parse().unwrap()) }
    }

    fn reach(relay: u32, outcome: TryOutcome, at: Timestamp, seen_as: Option<&str>) -> ReachRecord {
        ReachRecord { relay: id(relay), outcome, at, seen_as: seen_as.map(|ip| ip.parse().unwrap()) }
    }

    fn relays(ids: &[u32]) -> BTreeSet<NodeId> {
        ids.iter().map(|raw| id(*raw)).collect()
    }

    /// 一个节点：自己挑的挂靠对象、另外挂的、连得上的 relay。
    fn node(seed: u8, own: &[u32], shared: &[u32], reached: &[u32]) -> NodeRecord {
        let attach = |relay: &u32, shared| Attachment { relay: id(*relay), rtt_ms: 10, shared };
        NodeRecord {
            attached: own.iter().map(|relay| attach(relay, false)).chain(shared.iter().map(|relay| attach(relay, true))).collect(),
            relay_reach: reached.iter().map(|relay| reach(*relay, TryOutcome::Udp, 1_000, None)).collect(),
            ..record(seed)
        }
    }

    #[test]
    fn a_node_counts_as_without_udp_only_against_a_relay_others_reach_over_udp() {
        let with = |seed: u8, records: Vec<ReachRecord>| NodeRecord { relay_reach: records, ..record(seed) };
        let (udp, tcp, gone) = (TryOutcome::Udp, TryOutcome::Tcp, TryOutcome::Unreached);
        // 节点 1、2 是 relay；3 只经 TCP 连上 1，1 别人经 UDP 连得上：3 用不了 UDP。
        let nodes = [
            with(1, vec![reach(2, tcp, 0, None)]),
            with(2, vec![reach(1, udp, 0, None)]),
            with(3, vec![reach(1, tcp, 0, None), reach(2, gone, 0, None)]),
            with(4, vec![reach(1, udp, 0, None), reach(2, tcp, 0, None)]),
            with(5, vec![reach(2, tcp, 0, None)]),
            with(6, Vec::new()),
        ];
        let found = without_udp(&nodes);
        assert_eq!(found, relays(&[3]), "4 经 UDP 连得上 1；1、5 只连上了没有 UDP 的 2（谁都只能经 TCP 连它），说明不了它们；6 还没报过");
        // relay 2 自己也用不了 UDP：它只经 TCP 连上了 1，而 1 别人经 UDP 连得上。
        let nodes = [with(2, vec![reach(1, tcp, 0, None), reach(2, udp, 0, None)]), with(4, vec![reach(1, udp, 0, None)])];
        assert_eq!(without_udp(&nodes), relays(&[2]), "自己那一项不算");
    }

    #[test]
    fn a_report_is_merged_by_relay_and_unchanged_results_are_written_at_most_every_five_minutes() {
        let all = relays(&[7, 8, 9]);
        let first = merge(
            &[],
            &[tried(7, TryOutcome::Udp, 0, Some("203.0.113.5")), tried(8, TryOutcome::Unreached, 30, None)],
            id(1),
            &all,
            10_000,
        )
        .expect("头一次报的全是新的");
        assert!(first.reach_changed);
        assert_eq!(first.records, [reach(7, TryOutcome::Udp, 10_000, Some("203.0.113.5")), reach(8, TryOutcome::Unreached, 9_970, None)]);

        let same = [tried(7, TryOutcome::Udp, 0, Some("203.0.113.5")), tried(8, TryOutcome::Unreached, 30, None)];
        assert_eq!(merge(&first.records, &same, id(1), &all, 10_010), None, "结果没变、时刻只过了十秒：不写");
        let later = merge(&first.records, &same, id(1), &all, 10_300).expect("过了五分钟，时刻要更新");
        assert!(!later.reach_changed, "只是时刻变了");
        assert_eq!(later.records[0].at, 10_300);

        let tcp = merge(&first.records, &[tried(8, TryOutcome::Tcp, 0, Some("203.0.113.5"))], id(1), &all, 10_020).unwrap();
        assert!(tcp.reach_changed, "连不上变成连得上");
        assert_eq!(tcp.records[1], reach(8, TryOutcome::Tcp, 10_020, Some("203.0.113.5")));
        let moved = merge(&tcp.records, &[tried(8, TryOutcome::Udp, 0, Some("203.0.113.5"))], id(1), &all, 10_030).unwrap();
        assert!(!moved.reach_changed, "TCP 换成 UDP 还是连得上");
    }

    #[test]
    fn only_enabled_relays_other_than_the_node_itself_are_kept_and_the_list_is_bounded() {
        let all = relays(&[1, 7]);
        let merged = merge(
            &[reach(9, TryOutcome::Udp, 5, None)],
            &[tried(1, TryOutcome::Udp, 0, None), tried(7, TryOutcome::Unknown, 0, None), tried(42, TryOutcome::Udp, 0, None)],
            id(1),
            &all,
            100,
        )
        .expect("停用了的 relay 的那一项要去掉");
        assert!(merged.records.is_empty(), "{:?}", merged.records);

        let many: BTreeSet<NodeId> = (2..=60).map(id).collect();
        let stored: Vec<ReachRecord> = (2..=40).map(|relay| reach(relay, TryOutcome::Udp, u64::from(relay), None)).collect();
        let reported: Vec<RelayTry> = (41..=60).map(|relay| tried(relay, TryOutcome::Udp, 0, None)).collect();
        let merged = merge(&stored, &reported, id(1), &many, 1_000).unwrap();
        assert_eq!(merged.records.len(), MAX_RELAY_TRIES);
        assert!(merged.records.iter().all(|record| record.at >= 21), "留下的是最近试的");
    }

    #[test]
    fn the_egress_address_is_the_controllers_view_when_public_and_otherwise_what_most_relays_saw() {
        let public_view = NodeRecord { observed: Some("198.51.100.7:20330".parse().unwrap()), ..record(1) };
        assert_eq!(egress_ip(&public_view), Some("198.51.100.7".parse().unwrap()));

        let behind = NodeRecord {
            observed: Some("192.168.1.20:20330".parse().unwrap()),
            relay_reach: vec![
                reach(7, TryOutcome::Udp, 100, Some("203.0.113.9")),
                reach(8, TryOutcome::Tcp, 50, Some("203.0.113.9")),
                reach(9, TryOutcome::Udp, 200, Some("198.51.100.1")),
                reach(10, TryOutcome::Udp, 300, Some("10.0.0.5")),
            ],
            ..record(1)
        };
        assert_eq!(egress_ip(&behind), Some("203.0.113.9".parse().unwrap()), "两个 relay 看到的比一个看到的多");

        let tie = NodeRecord {
            relay_reach: vec![reach(7, TryOutcome::Udp, 100, Some("203.0.113.9")), reach(9, TryOutcome::Udp, 200, Some("198.51.100.1"))],
            ..behind.clone()
        };
        assert_eq!(egress_ip(&tie), Some("198.51.100.1".parse().unwrap()), "一样多时取最近看到的");

        let private_only = NodeRecord {
            relay_reach: vec![reach(10, TryOutcome::Udp, 300, Some("10.0.0.5")), reach(11, TryOutcome::Udp, 300, Some("100.64.3.2"))],
            ..behind
        };
        assert_eq!(egress_ip(&private_only), None, "只从内网地址被看到过");
        assert_eq!(egress_ip(&record(1)), None);
    }

    #[test]
    fn relays_are_counted_over_online_nodes_and_only_a_relay_nobody_reaches_gets_a_note() {
        let relay = |seed: u8| NodeRecord { relay: Some(RelaySettings::default()), ..record(seed) };
        let with = |seed: u8, records: Vec<ReachRecord>| NodeRecord { relay_reach: records, ..record(seed) };
        let nodes = [
            relay(7),
            relay(8),
            with(1, vec![reach(7, TryOutcome::Udp, 1, None), reach(8, TryOutcome::Unreached, 1, None)]),
            with(2, vec![reach(7, TryOutcome::Unreached, 1, None), reach(8, TryOutcome::Unreached, 1, None)]),
            with(3, Vec::new()),
            with(4, vec![reach(8, TryOutcome::Udp, 1, None)]),
        ];
        let online = |node: NodeId| node != id(4);
        let index = ReachIndex::new(&nodes, online);
        assert_eq!(index.of(id(7)), RelayReach { reached: 1, unreached: 1, unknown: 2 }, "8 在线、没报过 7；3 也没报过");
        assert_eq!(index.of(id(8)), RelayReach { reached: 0, unreached: 2, unknown: 2 }, "离线的 4 不算");
        assert_eq!(index.warning(id(7)), None, "有一个连得上，它就是那个节点的 relay");
        assert_eq!(index.warning(id(8)), Some(NodeWarning::RelayUnreached { tried: 2 }));

        let listed = reached_by(&nodes, id(8), online);
        assert_eq!(
            listed.iter().map(|entry| (entry.node.id, entry.online, entry.outcome)).collect::<Vec<_>>(),
            [(id(1), true, TryOutcome::Unreached), (id(2), true, TryOutcome::Unreached), (id(4), false, TryOutcome::Udp)]
        );
    }

    #[test]
    fn two_nodes_that_reach_each_others_relays_need_nothing_more() {
        let all = relays(&[7, 8, 9]);
        let a = node(1, &[7], &[], &[7, 8]);
        let b = node(2, &[8], &[], &[8, 7]);
        assert_eq!(meeting_relay(&Side::of(&a, &all), &Side::of(&b, &all), &all), None);
    }

    #[test]
    fn a_node_whose_relays_are_reachable_only_at_home_meets_a_peer_abroad_on_a_relay_both_reach() {
        // a 在国内，挑的两个最近的 relay（7、8）只有国内连得上；b 在国外，挂在 9、10 上，连不上 7、8。
        // 两边都连得上的只有 11（比如一台香港的服务器）：两边都要挂上去。
        let all = relays(&[7, 8, 9, 10, 11]);
        let a = node(1, &[7, 8], &[], &[7, 8, 11]);
        let b = node(2, &[9, 10], &[], &[9, 10, 11]);
        assert_eq!(meeting_relay(&Side::of(&a, &all), &Side::of(&b, &all), &all), Some(id(11)));
        assert_eq!(meeting_relay(&Side::of(&b, &all), &Side::of(&a, &all), &all), Some(id(11)), "两边算出来的是同一个");
        assert_eq!(shared_relays(&a, [&b], &all), [id(11)]);
        assert_eq!(shared_relays(&b, [&a], &all), [id(11)]);

        // a 连得上 b 挂着的 9：a 挂上 9 就够了，b 不用多挂。
        let a = node(1, &[7, 8], &[], &[7, 8, 9, 11]);
        assert_eq!(shared_relays(&a, [&b], &all), [id(9)]);
        assert!(shared_relays(&b, [&a], &all).is_empty());

        // 挂上去之后（报上来的挂靠里多了一个另外挂的）结果不变，不会来回换。
        let a_after = node(1, &[7, 8], &[9], &[7, 8, 9, 11]);
        assert_eq!(shared_relays(&a_after, [&b], &all), [id(9)]);
        assert!(shared_relays(&b, [&a_after], &all).is_empty());
    }

    #[test]
    fn a_peer_that_is_a_relay_itself_and_reachable_needs_no_third_relay_and_no_common_relay_means_nothing_to_do() {
        let all = relays(&[2, 7, 9]);
        let a = node(1, &[7], &[], &[7, 2]);
        let b = NodeRecord { relay: Some(RelaySettings::default()), ..node(2, &[9], &[], &[9]) };
        assert_eq!(meeting_relay(&Side::of(&a, &all), &Side::of(&b, &all), &all), None, "a 直接把包交给 relay b");

        let c = node(3, &[9], &[], &[9]);
        assert_eq!(meeting_relay(&Side::of(&a, &all), &Side::of(&c, &all), &all), None, "没有两边都连得上的 relay");
    }

    #[test]
    fn shared_relays_are_bounded_and_the_most_needed_come_first() {
        let all: BTreeSet<NodeId> = (10..=20).map(id).collect();
        let me = node(1, &[10], &[], &(10..=20).collect::<Vec<_>>());
        // 每个对端只连得上自己挂着的那一个 relay，各不相同；12 被两个对端需要。
        let peers: Vec<NodeRecord> =
            [11, 12, 12, 13, 14, 15, 16].iter().zip(2..).map(|(&relay, seed)| node(seed, &[relay], &[], &[relay])).collect();
        let shared = shared_relays(&me, &peers, &all);
        assert_eq!(shared.len(), MAX_SHARED_RELAYS);
        assert!(shared.contains(&id(12)), "两个对端需要的先挑：{shared:?}");
    }
}
