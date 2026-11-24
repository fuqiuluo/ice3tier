//! 运行着的节点的状态，给本机的 `i3t status` 和 `i3t routes` 看。
//!
//! 这些类型就是本机状态接口应答的 JSON。问的一方和答的一方通常是同一个程序文件，但更新的那一小段时间里
//! 可能并非同一版本，因此字段均设有默认值，未识别的字段将被忽略。

use std::net::{Ipv4Addr, SocketAddr};

use i3t_access::{ListenCause, ListenState, TargetCause, TargetFailure};
use i3t_model::control::{
    self, BindCause, ExitReport, LaneReport, PerformanceReport, Route, RouteSince, SelfUpdate, TargetFailureReport, VnetReport,
};
use i3t_model::netmap::Attachment;
use i3t_model::update::UpdateStatus;
use serde::{Deserialize, Serialize};

use crate::control::LinkState;
use crate::ping::{RelayName, relay_names};
use crate::route_detail;
use crate::runtime::{Runtime, exit_report};

/// 一个运行着的节点现在的样子。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LiveStatus {
    /// 正在运行的程序的版本。
    pub version: String,
    pub uptime_secs: u64,
    pub name: String,
    pub virtual_ip: Option<Ipv4Addr>,
    pub network: String,
    pub netmap_version: u64,
    pub link: Link,
    /// controller 的地址；静态模式下没有。
    pub controller: Option<String>,
    /// 以本节点为起点或终点的活跃的流。更新等的就是它变成零。
    pub flows: usize,
    /// 本节点的 UDP 候选端点。
    pub endpoints: Vec<SocketAddr>,
    pub mapping_varies: Option<bool>,
    /// 挂靠的 relay 和到它们的延迟。
    pub attached: Vec<Attachment>,
    pub routes: Vec<LiveRoute>,
    /// `attached`、`routes`（路和换路的原因）里说到的 relay 的名字，和 `i3t ping` 一样按
    /// [`Netmap::node_name`](i3t_model::Netmap::node_name) 找。旧版本的节点不给，那时只写编号。
    pub relays: Vec<RelayName>,
    pub listeners: Vec<LiveListener>,
    pub update: LiveUpdate,
    /// 本节点启用为 relay 时有值。
    pub relay: Option<LiveRelay>,
    /// 本节点替别人连目标（出口一侧）的计数，配额用到了哪里。
    pub exit: Option<ExitReport>,
    /// ice3proxy（lane）。没有为任何对端打开、也从来没用过时没有。
    pub lanes: Option<LaneReport>,
    /// 正在用的性能档位。旧版本的节点不给。
    pub performance: Option<PerformanceReport>,
    /// 虚拟网卡。旧版本的节点不给。
    #[serde(default)]
    pub vnet: Option<VnetReport>,
}

/// 和 controller 的那条长连接。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Link {
    /// 静态模式：不连 controller。
    #[default]
    Static,
    Offline,
    Online,
    Revoked,
    Rejected,
    #[serde(other)]
    Unknown,
}

impl From<LinkState> for Link {
    fn from(state: LinkState) -> Self {
        match state {
            LinkState::Offline => Self::Offline,
            LinkState::Online => Self::Online,
            LinkState::Revoked => Self::Revoked,
            LinkState::Rejected => Self::Rejected,
        }
    }
}

/// 到一个对端现在怎么走。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveRoute {
    pub peer: u32,
    pub name: String,
    pub virtual_ip: Option<Ipv4Addr>,
    pub route: Route,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    /// 这条路是多久之前换上的、为什么。这次启动以来没有换过时没有。
    #[serde(default)]
    pub since: Option<RouteSince>,
    /// 直连现在在哪一步，不管现在走不走它。旧版本的节点不给。
    #[serde(default)]
    pub direct_status: Option<control::DirectStatus>,
}

/// 一个监听现在的状态（[`LiveListener::state`]）。JSON 里的写法和上报给 controller 的 [`control::ListenState`] 的 `state` 一样。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerState {
    Listening,
    PortInUse,
    Failed,
    Virtual,
    Unsupported,
    /// 来自较新版本节点、当前版本无法识别的状态。
    #[serde(other)]
    Unknown,
}

impl From<&control::ListenState> for ListenerState {
    fn from(state: &control::ListenState) -> Self {
        match state {
            control::ListenState::Listening { .. } => Self::Listening,
            control::ListenState::PortInUse { .. } => Self::PortInUse,
            control::ListenState::Failed { .. } => Self::Failed,
            control::ListenState::Virtual => Self::Virtual,
            control::ListenState::Unsupported { .. } => Self::Unsupported,
            control::ListenState::Unknown => Self::Unknown,
        }
    }
}

/// 一个代理、一个组网入口，或者一条端口转发的监听一侧。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveListener {
    /// 代理的名字，组网入口是 `local-socks5`、`local-http`，端口转发是 `forward-<编号>`。
    pub name: String,
    /// 配置里写的绑定地址。
    pub bind: SocketAddr,
    pub state: ListenerState,
    /// `port_in_use`、`failed`、`unsupported` 时是原因；端口写 0 时是实际的端口。
    #[serde(default)]
    pub detail: Option<String>,
    /// `listening` 时实际绑定的地址。
    #[serde(default)]
    pub local: Option<SocketAddr>,
    /// 没有绑上的原因的代码；`detail` 是系统的原话。
    #[serde(default)]
    pub cause: Option<BindCause>,
    /// 上面正在进行的连接数。
    #[serde(default)]
    pub active: usize,
    /// 这次运行以来客户端发进来的、发回给客户端的字节数。
    #[serde(default)]
    pub bytes_up: u64,
    #[serde(default)]
    pub bytes_down: u64,
}

/// 程序的更新。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LiveUpdate {
    pub status: UpdateStatus,
    /// 能不能自己更新，不能的话为什么。
    pub self_update: Option<SelfUpdate>,
    /// 正在排空：不接新的流，手上的结束之后重启。
    pub draining: bool,
}

/// relay 的计数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LiveRelay {
    pub sessions: u64,
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub dropped: u64,
}

impl LiveStatus {
    pub(crate) fn of(runtime: &Runtime) -> Self {
        let netmap = runtime.netmap.borrow().clone();
        let update = runtime.update.borrow().clone();
        let reports = runtime.endpoint.path_reports();
        let routes = runtime.endpoint.routes().into_iter().map(|entry| {
            let peer = netmap.peer(entry.peer);
            let report = reports.iter().find(|report| report.peer == entry.peer);
            LiveRoute {
                peer: entry.peer.get(),
                name: peer.map_or_else(|| format!("#{}", entry.peer), |peer| peer.name.clone()),
                virtual_ip: peer.map(|peer| peer.virtual_ip),
                route: entry.route,
                rtt_ms: entry.rtt_ms,
                since: runtime.history.since(entry.peer),
                direct_status: report.map(|report| route_detail::direct_status(&report.direct_status)),
            }
        });
        let access = runtime.access.status();
        let proxies = access.proxies.iter().map(|proxy| {
            let name = netmap
                .me
                .proxies
                .iter()
                .find(|config| config.id == proxy.id)
                .map_or_else(|| format!("proxy-{}", proxy.id), |config| config.name.clone());
            LiveListener {
                bytes_up: proxy.traffic.up(),
                bytes_down: proxy.traffic.down(),
                ..listener_of(name, proxy.bind, &proxy.state, proxy.active.get())
            }
        });
        let local = access.local.iter().map(|entry| LiveListener {
            bytes_up: entry.traffic.up(),
            bytes_down: entry.traffic.down(),
            ..listener_of(entry.name.clone(), entry.bind, &entry.state, entry.active.get())
        });
        let forwards = access.forwards.iter().map(|forward| LiveListener {
            bytes_up: forward.traffic.up(),
            bytes_down: forward.traffic.down(),
            ..listener_of(format!("forward-{}", forward.id), forward.bind, &forward.state, forward.active.get())
        });
        let routes: Vec<LiveRoute> = routes.collect();
        let attached = runtime.endpoint.attached();
        let on_routes = routes.iter().flat_map(|entry| {
            let cause = entry.since.as_ref().and_then(|since| since.cause.as_ref()).map_or(&[][..], control::RouteCause::relays);
            entry.route.relays().iter().chain(cause).copied()
        });
        let relays = relay_names(&netmap, attached.iter().map(|attachment| attachment.relay).chain(on_routes));
        let exit = runtime.exit.stats();
        let counters = runtime.endpoint.relay_counters();
        let lanes = runtime.lanes.report();
        let lanes_used = !lanes.peers.is_empty() || lanes.total != control::LaneCounts::default();
        Self {
            version: runtime.program.version.to_string(),
            uptime_secs: runtime.started.elapsed().as_secs(),
            name: netmap.me.name.clone(),
            virtual_ip: Some(netmap.me.virtual_ip),
            network: netmap.network.name.clone(),
            netmap_version: netmap.version,
            link: runtime.link.as_ref().map_or(Link::Static, |link| Link::from(*link.borrow())),
            controller: runtime.controller.clone(),
            flows: *runtime.flows.borrow(),
            endpoints: runtime.endpoint.endpoints(),
            mapping_varies: runtime.endpoint.mapping_varies(),
            attached,
            routes,
            relays,
            listeners: proxies.chain(local).chain(forwards).collect(),
            update: LiveUpdate { draining: exit.draining, status: update, self_update: Some(runtime.self_update) },
            relay: netmap.me.relay.is_some().then(|| LiveRelay {
                sessions: counters.sessions,
                forwarded_packets: counters.forwarded_packets,
                forwarded_bytes: counters.forwarded_bytes,
                dropped: counters.dropped_total(),
            }),
            exit: netmap.me.exit.is_some().then(|| exit_report(&exit)),
            lanes: lanes_used.then_some(lanes),
            performance: Some(runtime.performance.borrow().clone()),
            vnet: Some(runtime.vnet_report()),
        }
    }
}

fn listener_of(name: String, bind: SocketAddr, state: &ListenState, active: usize) -> LiveListener {
    let reported = listen_state(state);
    let (detail, local, cause) = match &reported {
        control::ListenState::Listening { local } => ((*local != bind).then(|| format!("实际绑定在 {local}")), Some(*local), None),
        control::ListenState::PortInUse { detail, cause }
        | control::ListenState::Failed { detail, cause }
        | control::ListenState::Unsupported { detail, cause } => (Some(detail.clone()), None, *cause),
        control::ListenState::Virtual | control::ListenState::Unknown => (None, None, None),
    };
    LiveListener { name, bind, state: ListenerState::from(&reported), detail, local, cause, active, bytes_up: 0, bytes_down: 0 }
}

/// 入口模块报的监听状态写成上报给 controller 的样子。
pub(crate) fn listen_state(state: &ListenState) -> control::ListenState {
    match state {
        ListenState::Listening { local } => control::ListenState::Listening { local: *local },
        ListenState::PortInUse { reason } => {
            control::ListenState::PortInUse { detail: reason.clone(), cause: Some(BindCause::AddressInUse) }
        }
        ListenState::Failed { reason, cause } => control::ListenState::Failed { detail: reason.clone(), cause: Some(bind_cause(*cause)) },
        ListenState::Virtual => control::ListenState::Virtual,
        ListenState::Unsupported { reason, cause } => {
            control::ListenState::Unsupported { detail: reason.clone(), cause: Some(bind_cause(*cause)) }
        }
        // 入口模块后续可能新增状态；当前无法识别时按 Unknown 上报。
        _ => control::ListenState::Unknown,
    }
}

/// 将入口模块的监听失败原因映射为上报原因码。
fn bind_cause(cause: ListenCause) -> BindCause {
    match cause {
        ListenCause::AddressInUse => BindCause::AddressInUse,
        ListenCause::PermissionDenied => BindCause::PermissionDenied,
        ListenCause::AddressNotAvailable => BindCause::AddressNotAvailable,
        ListenCause::VirtualPortZero => BindCause::VirtualPortZero,
        ListenCause::Other => BindCause::Other,
        // 入口模块后续可能新增原因分类；当前无法识别时归为 Other，原始详情保留在 `detail` 中。
        _ => BindCause::Other,
    }
}

/// 将端口转发最近一次目标失败记录转换为上报格式。
pub(crate) fn target_failure(failure: &TargetFailure) -> TargetFailureReport {
    let cause = match failure.cause {
        TargetCause::Refused => control::TargetCause::Refused,
        TargetCause::Timeout => control::TargetCause::Timeout,
        TargetCause::Unreachable => control::TargetCause::Unreachable,
        TargetCause::NotDeclared => control::TargetCause::NotDeclared,
        TargetCause::AccessDenied => control::TargetCause::AccessDenied,
        TargetCause::NodeUnreachable => control::TargetCause::NodeUnreachable,
        TargetCause::Other => control::TargetCause::Other,
        // 入口模块后续可能新增原因分类；当前无法识别时归为 Other。
        _ => control::TargetCause::Other,
    };
    TargetFailureReport { cause, secs_ago: failure.at.elapsed().as_secs() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_from_another_version_still_reads() {
        let status: LiveStatus = serde_json::from_value(serde_json::json!({
            "version": "9.0.0", "link": "something_new", "added_later": 1,
            "update": { "status": { "state": "also_new" }, "added_later": true },
            "routes": [{ "peer": 2, "name": "nas", "virtual_ip": "10.66.0.2", "route": { "via": "none" } }]
        }))
        .unwrap();
        assert_eq!((status.link, status.update.status.clone(), status.routes.len()), (Link::Unknown, UpdateStatus::Unknown, 1));
        assert_eq!(serde_json::from_str::<LiveStatus>("{}").unwrap(), LiveStatus::default());
        assert_eq!(serde_json::to_value(Link::Online).unwrap(), "online");
    }

    #[test]
    fn listener_states_are_spelt_out() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let listening = listener_of("socks".into(), bind, &ListenState::Listening { local }, 2);
        assert_eq!((listening.state, listening.active), (ListenerState::Listening, 2));
        assert_eq!(listening.local, Some(local), "端口写 0 时说出实际的端口");
        assert!(listening.detail.unwrap().contains("41000"));
        assert_eq!(listener_of("socks".into(), local, &ListenState::Listening { local }, 0).detail, None);
        let in_use = listener_of("http".into(), bind, &ListenState::PortInUse { reason: "地址已经在用".into() }, 0);
        assert_eq!((in_use.state, in_use.detail.as_deref()), (ListenerState::PortInUse, Some("地址已经在用")));
        assert_eq!(in_use.cause, Some(BindCause::AddressInUse));
        let failed = listener_of(
            "http".into(),
            bind,
            &ListenState::Failed { reason: "没有这个地址".into(), cause: ListenCause::AddressNotAvailable },
            0,
        );
        assert_eq!((failed.state, failed.detail.as_deref()), (ListenerState::Failed, Some("没有这个地址")));
        assert_eq!(failed.cause, Some(BindCause::AddressNotAvailable));
        assert_eq!(listener_of("forward-3".into(), bind, &ListenState::Virtual, 0).state, ListenerState::Virtual);
    }

    #[test]
    fn listener_states_are_written_like_the_reported_listen_states() {
        let local: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let reported = [
            control::ListenState::Listening { local },
            control::ListenState::PortInUse { detail: String::new(), cause: None },
            control::ListenState::Failed { detail: String::new(), cause: None },
            control::ListenState::Virtual,
            control::ListenState::Unsupported { detail: String::new(), cause: None },
            control::ListenState::Unknown,
        ];
        for state in &reported {
            let written = serde_json::to_value(ListenerState::from(state)).unwrap();
            assert_eq!(written, serde_json::to_value(state).unwrap()["state"], "{state:?}");
            assert_eq!(serde_json::from_value::<ListenerState>(written).unwrap(), ListenerState::from(state));
        }
        assert_eq!(serde_json::from_value::<ListenerState>("something_new".into()).unwrap(), ListenerState::Unknown);
    }

    #[test]
    fn listen_states_are_reported_to_the_controller_with_their_reason() {
        let local: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        assert_eq!(listen_state(&ListenState::Listening { local }), control::ListenState::Listening { local });
        assert_eq!(
            listen_state(&ListenState::PortInUse { reason: "in use".into() }),
            control::ListenState::PortInUse { detail: "in use".into(), cause: Some(BindCause::AddressInUse) }
        );
        assert_eq!(listen_state(&ListenState::Virtual), control::ListenState::Virtual);
        assert_eq!(
            listen_state(&ListenState::Unsupported { reason: "UDP".into(), cause: ListenCause::VirtualPortZero }),
            control::ListenState::Unsupported { detail: "UDP".into(), cause: Some(BindCause::VirtualPortZero) }
        );
    }

    #[test]
    fn a_bind_failure_is_classified_from_the_kind_the_entry_reports_not_from_its_sentence() {
        let kinds = [
            (ListenCause::PermissionDenied, BindCause::PermissionDenied),
            (ListenCause::AddressNotAvailable, BindCause::AddressNotAvailable),
            (ListenCause::Other, BindCause::Other),
        ];
        for (kind, code) in kinds {
            // 原话里写着别的错误号：不看它。
            let failed = listen_state(&ListenState::Failed { reason: "Address already in use (os error 98)".into(), cause: kind });
            assert_eq!(failed, control::ListenState::Failed { detail: "Address already in use (os error 98)".into(), cause: Some(code) });
        }
    }
}
