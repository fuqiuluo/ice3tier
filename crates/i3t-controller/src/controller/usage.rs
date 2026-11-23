//! 节点报上来的用量和状态在 controller 这一侧：
//!
//! - **出口**：出口报它自己的计数（按归因分的失败、配额、是不是在排空）；用它的节点各自报它们看到的。两份都留着给界面交叉核对。
//!   健康只看出口自己报的、归因于它自己的失败，取最近 5 分钟。
//! - **监听**：每个节点报它的代理、本机的组网入口和端口转发的监听状态、连接数和流量，界面直接显示。
//!
//! 这些都只在内存里：节点离线之后留着它最后报的那一份，controller 重启就没有了，等节点重新上报。

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use i3t_model::admin::{
    ExitHealth, ExitObserved, ExitView, ForwardFailure, ListenStatus, NetworkId, NodeForwardListen, NodeListener, NodeListeners,
};
use i3t_model::control::{ExitObservation, ExitReport, ForwardReport, ListenerReport, ProxyReport};
use i3t_proto::NodeId;

use super::{Controller, Inner};
use crate::access::AccessMap;
use crate::error::{Entity, Error, error_chain};
use crate::netmap::NetworkView;
use crate::store::NodeRecord;

/// 健康看最近这么久。
const HEALTH_WINDOW: Duration = Duration::from_secs(5 * 60);
/// 归因于出口自己的失败至少这么多次、并且每这么多个请求里至少有一次（一成），才算不健康。偶尔一次解析器超时不算。
const DEGRADED_MIN_FAILURES: u64 = 3;
const DEGRADED_ONE_IN: u64 = 10;
/// 一个节点最多报这么多个监听。乱报的节点占不了太多内存。
const MAX_LISTENS: usize = 256;
/// 一次上报里最多看这么多项出口的观测。观测是一次次报上来累积的，跨多次上报也替一个节点最多留这么多个出口的。
const MAX_EXITS: usize = 256;

/// 出口和用出口的节点报的计数。
#[derive(Debug, Default)]
pub(crate) struct Usage {
    exits: BTreeMap<NodeId, ExitSeen>,
    /// （出口，发起节点）→ 发起节点看到的。按出口排，看一个出口的只扫它自己的那一段。
    observed: BTreeMap<(NodeId, NodeId), Observed>,
    /// 发起节点 → 它的观测留在 `observed` 里的那些出口。和 `observed` 的键一一对应。
    observers: BTreeMap<NodeId, BTreeSet<NodeId>>,
}

/// `observed` 里关于 `exit` 的那一段。
fn about(exit: NodeId) -> RangeInclusive<(NodeId, NodeId)> {
    const FIRST: NodeId = NodeId::new(1).unwrap();
    const LAST: NodeId = NodeId::new(u32::MAX).unwrap();
    (exit, FIRST)..=(exit, LAST)
}

/// 一个出口最近报的计数，和最近几分钟的样本。
#[derive(Debug)]
struct ExitSeen {
    report: ExitReport,
    at: Instant,
    run: u64,
    /// 每次上报时的累计请求数和累计的出口自己的失败数，最老的一个在窗口之外，作为起点。
    samples: VecDeque<Sample>,
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    at: Instant,
    total: u64,
    failed_by_exit: u64,
}

#[derive(Debug)]
struct Observed {
    counts: ExitObservation,
    at: Instant,
}

impl ExitSeen {
    /// 最近 5 分钟里的请求数和出口自己的失败数。
    fn recent(&self) -> (u64, u64) {
        match (self.samples.front(), self.samples.back()) {
            (Some(first), Some(last)) => (last.total.saturating_sub(first.total), last.failed_by_exit.saturating_sub(first.failed_by_exit)),
            _ => (0, 0),
        }
    }
}

impl Usage {
    fn exit_reported(&mut self, exit: NodeId, run: u64, report: ExitReport, now: Instant) {
        let sample = Sample { at: now, total: report.total, failed_by_exit: report.failed_by_exit };
        let seen = self.exits.entry(exit).or_insert_with(|| ExitSeen { report: report.clone(), at: now, run, samples: VecDeque::new() });
        // 出口重启了，累计的数从头开始：之前的样本不能和之后的相减。
        if seen.run != run {
            seen.samples.clear();
            seen.run = run;
        }
        seen.report = report;
        seen.at = now;
        seen.samples.push_back(sample);
        while seen.samples.len() > 2 && seen.samples.get(1).is_some_and(|second| now.saturating_duration_since(second.at) >= HEALTH_WINDOW)
        {
            seen.samples.pop_front();
        }
    }

    /// 记下 `by` 这次报的观测，最多 [`MAX_EXITS`] 个。要不要收（出口在不在它的网络里）由调用的一方先筛过。
    ///
    /// 之前报过、这次没报的留着，离线之后也能看。替它留的出口超过 [`MAX_EXITS`] 个时，
    /// 这次报的都留下，别的从最久没有更新的去掉。
    fn observed(&mut self, by: NodeId, observations: impl IntoIterator<Item = ExitObservation>, now: Instant) {
        let mut fresh = BTreeSet::new();
        for counts in observations.into_iter().take(MAX_EXITS) {
            fresh.insert(counts.exit);
            self.observed.insert((counts.exit, by), Observed { counts, at: now });
        }
        if fresh.is_empty() {
            return;
        }
        let mine = self.observers.entry(by).or_default();
        mine.extend(&fresh);
        let excess = mine.len().saturating_sub(MAX_EXITS);
        if excess > 0 {
            let mut stale: Vec<(Instant, NodeId)> =
                mine.difference(&fresh).filter_map(|&exit| Some((self.observed.get(&(exit, by))?.at, exit))).collect();
            stale.sort_unstable();
            for (_, exit) in stale.into_iter().take(excess) {
                self.remove_observed(exit, by);
            }
        }
    }

    /// 去掉一条观测。`observed` 和 `observers` 一起改，只在这里、[`Usage::observed`] 和 [`Usage::forget`] 里改。
    fn remove_observed(&mut self, exit: NodeId, by: NodeId) {
        self.observed.remove(&(exit, by));
        if let Some(mine) = self.observers.get_mut(&by) {
            mine.remove(&exit);
            if mine.is_empty() {
                self.observers.remove(&by);
            }
        }
    }

    /// `exit` 不再是出口了（停用了，或者节点撤回了声明）：controller 这边留着的经它出去的观测都丢掉，
    /// 不再占地方，已经离线、重启过的发起节点的旧数也不再留着。
    ///
    /// 这不等于再启用时从零算起：发起节点报的是它这次运行以来的累计，停用期间照报（只是不收），
    /// 再启用之后，还在线、没重启过的发起节点下一次上报就带着停用之前的数回来。
    pub(crate) fn exit_disabled(&mut self, exit: NodeId) {
        let observers: Vec<NodeId> = self.observed.range(about(exit)).map(|(&(_, by), _)| by).collect();
        for by in observers {
            self.remove_observed(exit, by);
        }
    }

    /// 发起节点各自看到的经 `exit` 出去的流。
    fn observed_about(&self, exit: NodeId) -> impl Iterator<Item = (NodeId, &Observed)> {
        self.observed.range(about(exit)).map(|(&(_, by), observed)| (by, observed))
    }

    /// 留着的观测的键：（出口，发起节点）。
    #[cfg(test)]
    pub(crate) fn observed_keys(&self) -> Vec<(NodeId, NodeId)> {
        self.observed.keys().copied().collect()
    }

    pub(crate) fn forget(&mut self, node: NodeId) {
        self.exits.remove(&node);
        self.exit_disabled(node);
        for exit in self.observers.remove(&node).unwrap_or_default() {
            self.observed.remove(&(exit, node));
        }
    }
}

/// 一个出口最近 5 分钟的健康。
///
/// 计数是节点报的，多大都有可能。门槛（请求数的一成，向上取整）用除法算，不拿计数去乘：报什么数都不会溢出。
fn health(online: bool, (requests, failures): (u64, u64)) -> ExitHealth {
    if !online || requests == 0 {
        ExitHealth::Unknown
    } else if failures >= DEGRADED_MIN_FAILURES.max(requests.div_ceil(DEGRADED_ONE_IN)) {
        ExitHealth::Degraded
    } else {
        ExitHealth::Ok
    }
}

impl Controller {
    /// 一个网络里启用了的出口：设置、它自己报的计数、健康，以及用它的节点各自看到的。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn exits(&self, network: NetworkId) -> Result<Vec<ExitView>, Error> {
        let inner = self.lock();
        let view = NetworkView::load(&inner.store, network)?.ok_or(Error::NotFound(Entity::Network))?;
        let access = view.access();
        Ok(view.nodes.values().filter_map(|node| inner.exit_view(&view, &access, node)).collect())
    }

    /// 一个出口。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个节点，或者它没有启用出口。
    pub fn exit(&self, network: NetworkId, id: NodeId) -> Result<ExitView, Error> {
        let inner = self.lock();
        inner.require_node(network, id)?;
        let view = NetworkView::load(&inner.store, network)?.ok_or(Error::NotFound(Entity::Network))?;
        let node = view.nodes.get(&id).ok_or(Error::NotFound(Entity::Node))?;
        inner.exit_view(&view, &view.access(), node).ok_or(Error::NotFound(Entity::Exit))
    }

    /// 一个节点上的全部监听：controller 下发的代理、节点按本机配置开的组网入口、端口转发的监听一侧，取自它最近的上报。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个节点，或者读存储失败。
    pub fn node_listeners(&self, network: NetworkId, id: NodeId) -> Result<NodeListeners, Error> {
        let inner = self.lock();
        let record = inner.require_node(network, id)?;
        let configured = inner.store.proxies(network)?;
        let live = inner.live.get(&id);
        let proxies = live.map(|live| &live.proxies[..]).unwrap_or_default().iter().filter_map(|report| {
            // 刚删掉的代理节点还在报，不列。
            let proxy = configured.iter().find(|proxy| proxy.id == report.id && proxy.node == id)?;
            Some(NodeListener {
                id: Some(proxy.id),
                builtin: false,
                name: proxy.name.clone(),
                bind: report.bind,
                protocol: proxy.protocol,
                status: ListenStatus { state: report.state.clone(), traffic: report.traffic },
            })
        });
        // 比代理旧的节点在这里也报 controller 下发的监听器，那些已经不存在了，不列。
        let local =
            live.map(|live| &live.listeners[..]).unwrap_or_default().iter().filter(|report| report.builtin).map(|report| NodeListener {
                id: None,
                builtin: true,
                name: report.name.clone(),
                bind: report.bind,
                protocol: report.protocol,
                status: ListenStatus { state: report.state.clone(), traffic: report.traffic },
            });
        let listeners = proxies.chain(local);
        let forwards = live.map(|live| &live.forwards[..]).unwrap_or_default().iter().map(|report| NodeForwardListen {
            id: report.id,
            bind: report.bind,
            protocol: report.protocol,
            status: ListenStatus { state: report.state.clone(), traffic: report.traffic },
        });
        Ok(NodeListeners {
            node: record.to_ref(),
            online: live.is_some(),
            reported_secs_ago: live.and_then(|live| live.reported_at).map(|at| at.elapsed().as_secs()),
            listeners: listeners.collect(),
            forwards: forwards.collect(),
        })
    }
}

impl Inner {
    fn exit_view(&self, view: &NetworkView, access: &AccessMap<'_>, node: &NodeRecord) -> Option<ExitView> {
        let settings = node.exit.clone()?;
        let online = self.is_online(node.id);
        let seen = self.usage.exits.get(&node.id);
        let recent = seen.map(ExitSeen::recent).unwrap_or_default();
        let observed = self.usage.observed_about(node.id).filter_map(|(by, observed)| {
            let by = view.nodes.get(&by)?;
            Some(ExitObserved { by: by.to_ref(), counts: observed.counts.clone(), reported_secs_ago: observed.at.elapsed().as_secs() })
        });
        Some(ExitView {
            node: node.to_ref(),
            online,
            settings,
            health: health(online, recent),
            recent_requests: recent.0,
            recent_failures: recent.1,
            usage: seen.map(|seen| seen.report.clone()),
            reported_secs_ago: seen.map(|seen| seen.at.elapsed().as_secs()),
            observed: observed.collect(),
            proxies: view
                .proxies
                .iter()
                .filter(|proxy| proxy.exit == Some(node.id))
                .map(|proxy| self.proxy_view(view, access, proxy))
                .collect(),
        })
    }

    /// 一条端口转发的监听一侧最近一次报的状态。
    pub(crate) fn forward_listen_status(&self, node: NodeId, id: u32) -> Option<ListenStatus> {
        let report = self.live.get(&node)?.forwards.iter().find(|report| report.id == id)?;
        Some(ListenStatus { state: report.state.clone(), traffic: report.traffic })
    }

    /// 一条端口转发的流最近一次在目标那里失败，监听节点报的。时间换算成 controller 的时钟。
    pub(crate) fn forward_target_failure(&self, node: NodeId, id: u32) -> Option<ForwardFailure> {
        let live = self.live.get(&node)?;
        let failure = live.forwards.iter().find(|report| report.id == id)?.target_failure?;
        let since_report = live.reported_at.map_or(0, |at| at.elapsed().as_secs());
        Some(ForwardFailure { cause: failure.cause, at: self.clock.now().saturating_sub(failure.secs_ago.saturating_add(since_report)) })
    }

    /// 记下一个节点上报里的用量和状态。
    ///
    /// 出口的观测只看前 [`MAX_EXITS`] 项，只收经它自己网络里启用了出口的别的节点出去的：别的编号报上来也用不着留，留着只占地方。
    /// 节点不会经自己出去（代理不许把自己设成出口，netmap 里也没有它自己），报了也不收。
    /// 读存储失败、说不清哪些是出口时，这次的观测不记，别的照记。
    pub(super) fn usage_reported(&mut self, node: &NodeRecord, report: UsageReport) {
        let UsageReport { run, exit, exits, proxies, listeners, forwards } = report;
        let now = Instant::now();
        if let Some(live) = self.live.get_mut(&node.id) {
            live.reported_at = Some(now);
            live.proxies = proxies.into_iter().take(MAX_LISTENS).collect();
            live.listeners = listeners.into_iter().take(MAX_LISTENS).collect();
            live.forwards = forwards.into_iter().take(MAX_LISTENS).collect();
        }
        if let Some(exit) = exit {
            self.usage.exit_reported(node.id, run, *exit, now);
        }
        // 同一个出口报了几遍的，留最后那一遍。
        let exits: BTreeMap<NodeId, ExitObservation> =
            exits.into_iter().take(MAX_EXITS).filter(|seen| seen.exit != node.id).map(|seen| (seen.exit, seen)).collect();
        if exits.is_empty() {
            return;
        }
        match self.store.exits_among(node.network, exits.keys().copied()) {
            Ok(enabled) => self.usage.observed(node.id, exits.into_values().filter(|seen| enabled.contains(&seen.exit)), now),
            Err(err) => tracing::warn!(node = %node.id, "读不出哪些节点是出口，这次报的出口观测不记：{}", error_chain(&err)),
        }
    }
}

/// 一次上报里和用量、状态有关的部分。
pub(super) struct UsageReport {
    pub(super) run: u64,
    pub(super) exit: Option<Box<ExitReport>>,
    pub(super) exits: Vec<ExitObservation>,
    pub(super) proxies: Vec<ProxyReport>,
    pub(super) listeners: Vec<ListenerReport>,
    pub(super) forwards: Vec<ForwardReport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(total: u64, failed_by_exit: u64) -> ExitReport {
        ExitReport { total, failed_by_exit, ..ExitReport::default() }
    }

    fn id(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn seen(exit: NodeId, flows: u64) -> ExitObservation {
        ExitObservation { exit, flows, bytes_up: 0, bytes_down: 0, failed_by_target: 0, refused: 0, failed_by_exit: 0, unreachable: 0 }
    }

    /// 按发起节点记的和 `observed` 的键对得上，也没有空着的。
    fn assert_indexed(usage: &Usage) {
        let indexed: BTreeSet<(NodeId, NodeId)> =
            usage.observers.iter().flat_map(|(&by, exits)| exits.iter().map(move |&exit| (exit, by))).collect();
        assert_eq!(indexed, usage.observed.keys().copied().collect());
        assert!(usage.observers.values().all(|exits| !exits.is_empty()));
    }

    fn kept_by(usage: &Usage, by: NodeId) -> BTreeSet<u32> {
        usage.observed.keys().filter(|key| key.1 == by).map(|key| key.0.get()).collect()
    }

    #[test]
    fn health_counts_only_failures_of_the_exit_itself_over_the_last_five_minutes() {
        let mut usage = Usage::default();
        let exit = NodeId::new(2).unwrap();
        let start = Instant::now();
        usage.exit_reported(exit, 1, report(100, 0), start);
        usage.exit_reported(exit, 1, report(120, 4), start + Duration::from_secs(10));
        let seen = &usage.exits[&exit];
        assert_eq!(seen.recent(), (20, 4));
        assert_eq!(health(true, seen.recent()), ExitHealth::Degraded, "20 个请求里 4 个是出口自己的问题");
        assert_eq!(health(false, seen.recent()), ExitHealth::Unknown, "不在线时说不上来");
        assert_eq!(health(true, (100, 2)), ExitHealth::Ok, "偶尔两次不算");
        assert_eq!(health(true, (1000, 30)), ExitHealth::Ok, "不到一成不算");
        assert_eq!(health(true, (0, 0)), ExitHealth::Unknown, "没有请求就说不上来");

        // 5 分钟之后，早先的失败滑出窗口。
        usage.exit_reported(exit, 1, report(200, 4), start + HEALTH_WINDOW + Duration::from_secs(20));
        usage.exit_reported(exit, 1, report(300, 4), start + HEALTH_WINDOW + Duration::from_secs(30));
        assert_eq!(usage.exits[&exit].recent(), (180, 0));

        // 出口重启：累计的数从头开始，不和重启之前的相减。
        usage.exit_reported(exit, 2, report(5, 0), start + HEALTH_WINDOW + Duration::from_secs(40));
        assert_eq!(usage.exits[&exit].recent(), (0, 0));
    }

    #[test]
    fn an_exit_is_degraded_from_three_failures_and_one_request_in_ten_on() {
        assert_eq!(health(true, (30, 3)), ExitHealth::Degraded, "3 次，正好一成");
        assert_eq!(health(true, (31, 3)), ExitHealth::Ok, "31 个请求里 3 次不到一成");
        assert_eq!(health(true, (10, 3)), ExitHealth::Degraded);
        assert_eq!(health(true, (20, 2)), ExitHealth::Ok, "正好一成，但只有 2 次");
        assert_eq!(health(true, (2, 2)), ExitHealth::Ok, "全是失败，但只有 2 次");
        assert_eq!(health(true, (1000, 99)), ExitHealth::Ok);
        assert_eq!(health(true, (1000, 100)), ExitHealth::Degraded);
    }

    #[test]
    fn health_is_judged_exactly_however_large_the_reported_counts_are() {
        // 能被 10 整除的最大的请求数：门槛正好是它的十分之一。
        let requests = u64::MAX - 5;
        let tenth = requests / 10;
        assert_eq!(health(true, (requests, tenth - 1)), ExitHealth::Ok, "差一次不到一成");
        assert_eq!(health(true, (requests, tenth)), ExitHealth::Degraded, "正好一成");
        assert_eq!(health(true, (requests, tenth + 1)), ExitHealth::Degraded);
        // 不能整除的：一成带小数，要再多一次才够。
        assert_eq!(health(true, (u64::MAX, u64::MAX / 10)), ExitHealth::Ok);
        assert_eq!(health(true, (u64::MAX, u64::MAX / 10 + 1)), ExitHealth::Degraded);
        assert_eq!(health(true, (u64::MAX, 3)), ExitHealth::Ok);
        // 拿计数去乘的话，这两组在 64 位里绕回去，正好判反。
        assert_eq!(health(true, (u64::MAX / 10 + 1, 3)), ExitHealth::Ok, "请求数的 10 倍放不进 64 位");
        assert_eq!(health(true, (u64::MAX / 100 + 1, u64::MAX / 100 + 1)), ExitHealth::Degraded, "失败数的 100 倍放不进 64 位");

        // 从上报一路算下来也一样：同一次运行里，累计的数从 0 跳到最大。
        let mut usage = Usage::default();
        let exit = id(2);
        let start = Instant::now();
        usage.exit_reported(exit, 1, report(0, 0), start);
        usage.exit_reported(exit, 1, report(u64::MAX, u64::MAX), start + Duration::from_secs(10));
        let seen = &usage.exits[&exit];
        assert_eq!(seen.recent(), (u64::MAX, u64::MAX));
        assert_eq!(health(true, seen.recent()), ExitHealth::Degraded, "全是出口自己的失败");
    }

    #[test]
    fn observations_are_kept_per_exit_and_initiator_and_forgotten_with_either() {
        let mut usage = Usage::default();
        let (laptop, gw, phone, hk) = (id(1), id(2), id(3), id(4));
        usage.observed(laptop, vec![seen(gw, 3), seen(hk, 7)], Instant::now());
        usage.observed(phone, vec![seen(gw, 5)], Instant::now());
        usage.observed(laptop, vec![seen(gw, 4)], Instant::now());
        assert_eq!(usage.observed.len(), 3, "这次没报的 hk 还留着");
        assert_eq!(usage.observed[&(gw, laptop)].counts.flows, 4, "同一个发起节点的新报的顶替旧的");
        let about_gw: Vec<_> = usage.observed_about(gw).map(|(by, observed)| (by, observed.counts.flows)).collect();
        assert_eq!(about_gw, [(laptop, 4), (phone, 5)], "一个出口只看到经它出去的");
        assert_indexed(&usage);

        usage.forget(phone);
        assert_eq!(usage.observed.len(), 2);
        assert_indexed(&usage);
        usage.exit_disabled(gw);
        assert_eq!(usage.observed_keys(), [(hk, laptop)], "停用的出口的观测丢掉");
        assert_indexed(&usage);
        usage.observed(laptop, vec![seen(gw, 1)], Instant::now());
        usage.forget(gw);
        assert_eq!(usage.observed_keys(), [(hk, laptop)]);
        assert_indexed(&usage);
        usage.forget(laptop);
        assert!(usage.observed.is_empty() && usage.observers.is_empty());
    }

    #[test]
    fn an_initiator_keeps_at_most_max_exits_observations_and_the_longest_untouched_ones_go_first() {
        let mut usage = Usage::default();
        let (laptop, phone) = (id(100_001), id(100_002));
        let max = u32::try_from(MAX_EXITS).unwrap();
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        usage.observed(laptop, (1..=max).map(|exit| seen(id(exit), 1)), at(0));
        usage.observed(phone, vec![seen(id(1), 1)], at(0));
        usage.observed(laptop, vec![seen(id(1), 2), seen(id(3), 2)], at(10));
        assert_eq!(kept_by(&usage, laptop).len(), MAX_EXITS);

        // 满了之后又报了 3 个新的：去掉最久没有更新的 3 个，刚更新过的 1 和 3 留着。
        usage.observed(laptop, (1001..=1003).map(|exit| seen(id(exit), 1)), at(20));
        let kept = kept_by(&usage, laptop);
        assert_eq!(kept.len(), MAX_EXITS);
        assert!(kept.is_superset(&[1, 3, 1001, 1002, 1003].into()), "{kept:?}");
        assert!(kept.is_disjoint(&[2, 4, 5].into()), "{kept:?}");
        assert_eq!(usage.observed[&(id(1), laptop)].counts.flows, 2);
        assert_eq!(kept_by(&usage, phone), [1].into(), "别的发起节点的不受影响");
        assert_indexed(&usage);

        // 一次报得比上限还多：只收前面那些，之前留的全让给它们。
        usage.observed(laptop, (5001..=max + 5010).map(|exit| seen(id(exit), 1)), at(30));
        assert_eq!(kept_by(&usage, laptop), (5001..5001 + max).collect());
        assert_indexed(&usage);
    }
}
