//! 一个运行着的节点的各个部分，放在一处：上报、回答路由查询、本机状态接口和指标都从这里读。

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use i3t_access::Access;
use i3t_conn::{Endpoint, RouteChange};
use i3t_exit::{Exit, ExitStats, Os};
use i3t_model::Netmap;
use i3t_model::control::{
    BackboneRow, ExitObservation, ExitReport, ForwardReport, ListenTraffic, ListenerReport, MAX_LOCAL_ADDRESSES, MAX_REPORTED_SWITCHES,
    PerformanceReport, ProxyReport, QuotaUsage, Report, Route, RouteAnswer, RouteSince, RouteSwitch, SelfUpdate, VnetReport,
};
use i3t_model::update::UpdateStatus;
use i3t_proto::NodeId;
use tokio::sync::{broadcast, watch};

use crate::control::LinkState;
use crate::flows::{self, RelayActivity, Sample};
use crate::lanes::{self, NodeLanes};
use crate::program::Program;
use crate::route_detail;
use crate::status::{listen_state, target_failure};
use crate::vnet::Vnet;

/// 节点里的出口：流经共用的连接或者 lane 进来。
pub(crate) type NodeExit = Exit<Os, lanes::Connector>;
/// 节点里的入口：选了 ice3proxy 的代理的 TCP 流在备着 lane 时走 lane，别的走共用的连接。
pub(crate) type NodeAccess = Access<lanes::Connector>;

/// 一个运行着的节点。
pub(crate) struct Runtime {
    pub(crate) program: Program,
    /// 这次运行能不能自己更新，和报给 controller 的是同一个结论。
    pub(crate) self_update: SelfUpdate,
    pub(crate) started: Instant,
    /// controller 的地址；静态模式下没有。
    pub(crate) controller: Option<String>,
    pub(crate) endpoint: Arc<Endpoint>,
    pub(crate) lanes: Arc<NodeLanes>,
    pub(crate) exit: Arc<NodeExit>,
    pub(crate) access: Arc<NodeAccess>,
    /// 各层实际在用的 netmap（按本机配置调整过的）。
    pub(crate) netmap: watch::Receiver<Arc<Netmap>>,
    /// 这次运行的编号，上报里带着，controller 靠它知道累计的计数是不是从头开始了。
    pub(crate) run: u64,
    /// 长连接的状态；静态模式下没有。
    pub(crate) link: Option<watch::Receiver<LinkState>>,
    /// 报给 controller 的更新状态。
    pub(crate) update: watch::Receiver<UpdateStatus>,
    /// 活跃的流的数量，更新等它变成零。
    pub(crate) flows: watch::Receiver<usize>,
    /// 正在用的性能档位。
    pub(crate) performance: watch::Receiver<PerformanceReport>,
    /// 虚拟网卡。
    pub(crate) vnet: Arc<Vnet>,
    pub(crate) history: RouteHistory,
    relay_activity: Mutex<RelayActivity>,
}

/// [`Runtime::new`] 要的东西。
pub(crate) struct Parts {
    pub(crate) program: Program,
    pub(crate) self_update: SelfUpdate,
    pub(crate) controller: Option<String>,
    pub(crate) endpoint: Arc<Endpoint>,
    pub(crate) lanes: Arc<NodeLanes>,
    pub(crate) exit: Arc<NodeExit>,
    pub(crate) access: Arc<NodeAccess>,
    pub(crate) netmap: watch::Receiver<Arc<Netmap>>,
    pub(crate) link: Option<watch::Receiver<LinkState>>,
    pub(crate) update: watch::Receiver<UpdateStatus>,
    pub(crate) flows: watch::Receiver<usize>,
    pub(crate) performance: watch::Receiver<PerformanceReport>,
    pub(crate) vnet: Arc<Vnet>,
}

impl Runtime {
    pub(crate) fn new(parts: Parts) -> Self {
        let Parts { program, self_update, controller, endpoint, lanes, exit, access, netmap, link, update, flows, performance, vnet } =
            parts;
        Self {
            program,
            self_update,
            started: Instant::now(),
            controller,
            endpoint,
            lanes,
            exit,
            access,
            netmap,
            // 0 留给"旧版本的节点没有报"。
            run: rand::random::<u64>().max(1),
            link,
            update,
            flows,
            performance,
            vnet,
            history: RouteHistory::default(),
            relay_activity: Mutex::default(),
        }
    }

    /// 现在的入口连接数、出口流数，以及（本节点是唯一的 relay 时）是不是在替人转发。
    pub(crate) fn sample_flows(&self) -> Sample {
        let status = self.access.status();
        let ingress: usize = status
            .proxies
            .iter()
            .map(|proxy| proxy.active.get())
            .chain(status.local.iter().map(|entry| entry.active.get()))
            .chain(status.forwards.iter().map(|forward| forward.active.get()))
            .sum::<usize>();
        let exit = usize::try_from(self.exit.stats().active).unwrap_or(usize::MAX);
        let lanes = usize::try_from(self.lanes.status().total.in_use).unwrap_or(usize::MAX);
        let forwarding =
            self.relay_activity.lock().expect("relay activity mutex poisoned").observe(&self.endpoint.relay_counters(), Instant::now());
        Sample { ingress, exit, lanes, sole_relay_forwarding: forwarding && flows::is_only_relay(&self.netmap.borrow()) }
    }

    /// 报给 controller 的内容。`routes` 是完整的路由表，长连接自己挑要发的条目。
    pub(crate) fn report(&self) -> Report {
        let stats = self.exit.stats();
        let access = self.access.status();
        let proxies: Vec<ProxyReport> = access
            .proxies
            .iter()
            .map(|proxy| ProxyReport {
                id: proxy.id,
                bind: proxy.bind,
                state: listen_state(&proxy.state),
                traffic: ListenTraffic {
                    connections: count(proxy.active.get()),
                    bytes_up: proxy.traffic.up(),
                    bytes_down: proxy.traffic.down(),
                },
            })
            .collect();
        let listeners: Vec<ListenerReport> = access
            .local
            .iter()
            .map(|entry| ListenerReport {
                name: entry.name.clone(),
                bind: entry.bind,
                protocol: entry.protocol,
                builtin: true,
                state: listen_state(&entry.state),
                traffic: ListenTraffic {
                    connections: count(entry.active.get()),
                    bytes_up: entry.traffic.up(),
                    bytes_down: entry.traffic.down(),
                },
            })
            .collect();
        let forwards: Vec<ForwardReport> = access
            .forwards
            .iter()
            .map(|forward| ForwardReport {
                id: forward.id,
                bind: forward.bind,
                protocol: forward.protocol,
                state: listen_state(&forward.state),
                traffic: ListenTraffic {
                    connections: count(forward.active.get()),
                    bytes_up: forward.traffic.up(),
                    bytes_down: forward.traffic.down(),
                },
                target_failure: forward.target_failure.as_ref().map(target_failure),
            })
            .collect();
        let vnet = self.vnet_report();
        let ingress_up: u64 = proxies
            .iter()
            .map(|proxy| proxy.traffic.bytes_up)
            .chain(listeners.iter().map(|listener| listener.traffic.bytes_up))
            .chain(forwards.iter().map(|forward| forward.traffic.bytes_up))
            .sum::<u64>();
        let ingress_down: u64 = proxies
            .iter()
            .map(|proxy| proxy.traffic.bytes_down)
            .chain(listeners.iter().map(|listener| listener.traffic.bytes_down))
            .chain(forwards.iter().map(|forward| forward.traffic.bytes_down))
            .sum::<u64>();
        // 本机网卡上的地址，不管在不在网络的地址段里（controller 拿它找 relay 的地址、提醒地址段重叠）。
        // 虚拟网卡上放的是本节点自己的虚拟 IP，不算这台机器所在的网络。
        let own = self.netmap.borrow().me.virtual_ip;
        let local_addresses = i3t_underlay::ifaddr::local_addresses()
            .into_iter()
            .filter(|ip| ip.to_canonical() != std::net::IpAddr::V4(own))
            .take(MAX_LOCAL_ADDRESSES)
            .collect();
        Report {
            endpoints: self.endpoint.endpoints(),
            local_addresses: Some(local_addresses),
            mapping_varies: self.endpoint.mapping_varies(),
            attached: self.endpoint.attached(),
            flows: u32::try_from(*self.flows.borrow()).unwrap_or(u32::MAX),
            // 入口一侧客户端发出的、出口一侧发往目标的，都算本节点经流发出的字节；反过来是收到的。
            tx_bytes: stats.bytes_to_target.saturating_add(ingress_up),
            rx_bytes: stats.bytes_from_target.saturating_add(ingress_down),
            routes: self.endpoint.routes(),
            routes_full: false,
            update: Some(self.update.borrow().clone()),
            run: self.run,
            exit: Some(Box::new(exit_report(&stats))),
            exits: self.exit_observations(),
            proxies,
            listeners,
            forwards,
            route_kinds: self.endpoint.path_reports().iter().map(route_detail::kind).collect(),
            lanes: Some(Box::new(self.lanes.report())),
            performance: Some(Box::new(self.performance.borrow().clone())),
            vnet: Some(Box::new(vnet)),
            relays: self.endpoint.relay_tries(),
            peer_use: self.endpoint.peer_use(),
            relay_use: self.endpoint.relay_use(),
            switches: self.history.take_unreported(),
        }
    }

    /// 虚拟网卡的状态和这一路的计数。
    pub(crate) fn vnet_report(&self) -> VnetReport {
        self.vnet.report()
    }

    /// 本节点作为发起方，经各个出口出去的流。
    pub(crate) fn exit_observations(&self) -> Vec<ExitObservation> {
        let observed = self.access.exit_usage().into_iter();
        observed
            .map(|seen| ExitObservation {
                exit: seen.exit,
                flows: seen.flows,
                bytes_up: seen.bytes_up,
                bytes_down: seen.bytes_down,
                failed_by_target: seen.failed_by_target,
                refused: seen.refused,
                failed_by_exit: seen.failed_by_exit,
                unreachable: seen.unreachable,
            })
            .collect()
    }

    /// 回答"到 `peer` 现在会怎么走"：路由层手上现成的结论，不为此去探测或者建连接。
    pub(crate) fn route_to(&self, peer: NodeId) -> RouteAnswer {
        let entry = self.endpoint.routes().into_iter().find(|entry| entry.peer == peer);
        let known = self.netmap.borrow().peer(peer).is_some();
        match entry {
            Some(entry) => RouteAnswer {
                peer,
                route: Some(entry.route),
                rtt_ms: entry.rtt_ms,
                since: self.history.since(peer),
                detail: self.endpoint.path_report(peer).as_ref().map(route_detail::detail),
                connection_rtt_ms: self.endpoint.connection_rtt(peer).map(millis),
            },
            // 在 netmap 里、路由层还没有它的条目（刚下发）：对它还没有路。
            None if known => {
                RouteAnswer { peer, route: Some(Route::None), rtt_ms: None, since: None, detail: None, connection_rtt_ms: None }
            }
            None => RouteAnswer { peer, route: None, rtt_ms: None, since: None, detail: None, connection_rtt_ms: None },
        }
    }

    /// 回答"手上的骨干矩阵"：路由层现有的每一行。
    pub(crate) fn backbone(&self) -> Vec<BackboneRow> {
        route_detail::backbone(&self.endpoint.backbone())
    }
}

/// 出口一侧的计数写成上报的样子。
pub(crate) fn exit_report(stats: &ExitStats) -> ExitReport {
    ExitReport {
        active: stats.active,
        total: stats.total,
        bytes_to_target: stats.bytes_to_target,
        bytes_from_target: stats.bytes_from_target,
        failed_by_target: stats.failed_by_target,
        refused: stats.refused,
        failed_by_exit: stats.failed_by_exit,
        aborted: stats.aborted,
        draining: stats.draining,
        quota: stats.quota.map(|quota| QuotaUsage {
            limit_bytes: quota.limit_bytes,
            used_bytes: quota.used_bytes,
            period_start: quota.period.start,
            period_end: quota.period.end,
        }),
    }
}

/// 将时长转换为毫秒数，超出 `u32` 范围时饱和为最大值。
fn millis(duration: std::time::Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

/// 上报中的计数值均为 `u32`，超出范围时饱和为最大值。
fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// 记录到各对端最近一次路径切换的时间与原因。路由层仅在切换瞬间发出一次原因，此处负责留存。
///
/// 同时缓存尚未上报给 controller 的切换记录（controller 为每对节点保留一段历史），最多保留
/// [`MAX_REPORTED_SWITCHES`] 条：无法连接 controller 导致队列满时丢弃最早的记录。
#[derive(Debug, Clone, Default)]
pub(crate) struct RouteHistory {
    changes: Arc<Mutex<BTreeMap<NodeId, (Instant, RouteChange)>>>,
    unreported: Arc<Mutex<VecDeque<(Instant, RouteSwitch)>>>,
}

impl RouteHistory {
    /// 到 `peer` 的路是多久之前换上的、为什么。这次启动以来没有换过时是 `None`。
    pub(crate) fn since(&self, peer: NodeId) -> Option<RouteSince> {
        let changes = self.changes.lock().expect("route history mutex poisoned");
        changes.get(&peer).map(|(at, change)| RouteSince {
            secs_ago: at.elapsed().as_secs(),
            reason: change.reason.clone(),
            cause: Some(change.cause.clone()),
        })
    }

    fn record(&self, change: RouteChange) {
        let now = Instant::now();
        let mut changes = self.changes.lock().expect("route history mutex poisoned");
        let from = changes.get(&change.peer).map_or(Route::None, |(_, previous)| previous.route.clone());
        let switch = RouteSwitch { peer: change.peer, from, to: change.route.clone(), cause: change.cause.clone(), age_secs: 0 };
        changes.insert(change.peer, (now, change));
        drop(changes);
        let mut unreported = self.unreported.lock().expect("route history mutex poisoned");
        if unreported.len() >= MAX_REPORTED_SWITCHES {
            unreported.pop_front();
        }
        unreported.push_back((now, switch));
    }

    /// 取走还没有报过的换路，早的在前。上报的时候调用：取走了就不再报，那一次上报没有送到 controller 的话就少了这几条。
    pub(crate) fn take_unreported(&self) -> Vec<RouteSwitch> {
        let taken = std::mem::take(&mut *self.unreported.lock().expect("route history mutex poisoned"));
        let age = |at: Instant| u32::try_from(at.elapsed().as_secs()).unwrap_or(u32::MAX);
        taken.into_iter().map(|(at, switch)| RouteSwitch { age_secs: age(at), ..switch }).collect()
    }

    /// 一直记录换路事件，直到路由层关闭。
    pub(crate) async fn follow(self, mut changes: broadcast::Receiver<RouteChange>) {
        loop {
            match changes.recv().await {
                Ok(change) => self.record(change),
                // 消费落后导致部分事件被跳过：仅缺失少量历史原因记录，继续记录后续事件。
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use i3t_model::control::{RouteCause, RouteHint};

    use super::*;

    #[tokio::test]
    async fn the_latest_change_per_peer_is_remembered_with_its_reason() {
        let history = RouteHistory::default();
        let (tx, rx) = broadcast::channel(8);
        let following = tokio::spawn(history.clone().follow(rx));
        let peer = NodeId::new(2).unwrap();
        assert_eq!(history.since(peer), None);

        let lost = RouteCause::Unreachable { hint: RouteHint::DirectTimeouts };
        tx.send(RouteChange { peer, route: Route::None, reason: "直连超时".to_owned(), cause: lost }).unwrap();
        let relayed = Route::Relay { relays: vec![NodeId::new(9).unwrap()] };
        tx.send(RouteChange { peer, route: relayed, reason: "改走 relay".to_owned(), cause: RouteCause::RelayReady }).unwrap();
        for _ in 0..100 {
            if history.since(peer).is_some_and(|since| since.reason == "改走 relay") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let since = history.since(peer).unwrap();
        assert_eq!(since.reason, "改走 relay");
        assert_eq!(since.cause, Some(RouteCause::RelayReady), "原因的代码跟着原话一起记下");
        assert!(since.secs_ago <= 1);
        assert_eq!(history.since(NodeId::new(3).unwrap()), None);
        let switches = history.take_unreported();
        let steps: Vec<(Route, Route)> = switches.iter().map(|switch| (switch.from.clone(), switch.to.clone())).collect();
        assert_eq!(steps, [(Route::None, Route::None), (Route::None, Route::Relay { relays: vec![NodeId::new(9).unwrap()] })]);
        assert_eq!(switches[1].cause, RouteCause::RelayReady);
        assert!(history.take_unreported().is_empty(), "报过的不再报");

        drop(tx);
        tokio::time::timeout(Duration::from_secs(5), following).await.expect("路由层关闭之后应该停").unwrap();
    }
}
