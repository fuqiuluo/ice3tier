//! 流走的是哪条路：每条流结束时的那一行摘要里写它开始时和结束时这对节点的连接走的路，中间换没换过。
//!
//! 路是连接层的事，入口和出口都不知道，所以由装配层交进来一个能问"到这个对端现在走哪条路"的东西（[`Routes`]）。
//! 不交时摘要里的路是"不知道"。
//!
//! 走 ice3proxy（lane）的流不经过这对节点的共用连接，摘要里写的仍然是共用连接的路：流层看不出一条流底下是哪一种传输。

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use i3t_model::Netmap;
use i3t_model::control::Route;
use i3t_proto::NodeId;

/// 到一个对端现在怎么走。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentRoute {
    pub route: Route,
    /// 上一次换路是多久之前；从来没有过路时是 `None`。
    pub since_switch: Option<Duration>,
}

/// 能回答"到 `peer` 现在走哪条路"。
pub trait Routes: Send + Sync + 'static {
    /// 到 `peer` 现在走的路；它不在配置里时是 `None`。只读手上现成的结论，不能等。
    fn current(&self, peer: NodeId) -> Option<CurrentRoute>;
}

/// 不知道路的时候用：摘要里写"不知道"。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRoutes;

impl Routes for NoRoutes {
    fn current(&self, _peer: NodeId) -> Option<CurrentRoute> {
        None
    }
}

/// 一条流开始时的路，流结束时拿来和那时的路比。
#[derive(Debug, Clone)]
pub struct RouteAtStart {
    peer: NodeId,
    route: Option<Route>,
    at: Instant,
}

impl RouteAtStart {
    /// 流开始时调一次。
    pub fn now(routes: &dyn Routes, peer: NodeId) -> Self {
        Self { peer, route: routes.current(peer).map(|current| current.route), at: Instant::now() }
    }

    /// 流结束时调：开始和结束时的路，和中间换没换过。换过又换回来的也算换过：结束时的路是在流开始之后换上的。
    #[must_use]
    pub fn ended(self, routes: &dyn Routes) -> RouteSpan {
        let now = routes.current(self.peer);
        let switched_since_start = now.as_ref().and_then(|now| now.since_switch).is_some_and(|since| since < self.at.elapsed());
        let end = now.map(|now| now.route);
        let changed = switched_since_start || end != self.route;
        RouteSpan { start: self.route, end, changed }
    }
}

/// 一条流从开始到结束这对节点的连接走的路。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpan {
    pub start: Option<Route>,
    pub end: Option<Route>,
    pub changed: bool,
}

impl RouteSpan {
    /// 写进日志的样子：`直连 203.0.113.7:20330`、`经 hk-1 → la-1`、`不可达`，不知道是 `?`。relay 的名字从 `netmap` 里找
    /// （[`Netmap::node_name`]，和 `i3t routes`、`i3t ping` 一样），找不到的写 `#编号`。
    #[must_use]
    pub fn start_label<'a>(&'a self, netmap: &'a Netmap) -> RouteLabel<'a> {
        RouteLabel { route: self.start.as_ref(), netmap }
    }

    #[must_use]
    pub fn end_label<'a>(&'a self, netmap: &'a Netmap) -> RouteLabel<'a> {
        RouteLabel { route: self.end.as_ref(), netmap }
    }
}

/// 一条路写进日志的样子。
#[derive(Debug, Clone, Copy)]
pub struct RouteLabel<'a> {
    route: Option<&'a Route>,
    netmap: &'a Netmap,
}

impl fmt::Display for RouteLabel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.route {
            None => f.write_str("?"),
            Some(Route::None) => f.write_str("不可达"),
            Some(Route::Direct { addr }) => write!(f, "直连 {addr}"),
            Some(Route::Relay { relays }) => {
                f.write_str("经 ")?;
                for (index, relay) in relays.iter().enumerate() {
                    f.write_str(if index == 0 { "" } else { " → " })?;
                    match self.netmap.node_name(*relay) {
                        Some(name) => f.write_str(name)?,
                        None => write!(f, "#{relay}")?,
                    }
                }
                Ok(())
            }
        }
    }
}

/// 装配层交进来的、各处共用的那一个。
pub type SharedRoutes = Arc<dyn Routes>;

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct Fake(Mutex<Option<CurrentRoute>>);

    impl Routes for Fake {
        fn current(&self, _peer: NodeId) -> Option<CurrentRoute> {
            self.0.lock().unwrap().clone()
        }
    }

    fn peer() -> NodeId {
        NodeId::new(2).unwrap()
    }

    fn direct() -> Route {
        Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() }
    }

    /// 本节点 1（laptop，自己也是 relay），relay 3（hk，不是对端），对端 5（nas，也是 relay）。
    fn netmap() -> Netmap {
        use i3t_model::netmap::{LaneMode, LocalNode, Network, Peer, Relay};
        use i3t_proto::PublicKey;

        let node = |raw: u32| NodeId::new(raw).unwrap();
        let relay = |raw: u32, name: &str| Relay {
            id: node(raw),
            key: PublicKey::from_bytes([1; 32]),
            name: name.into(),
            udp: Vec::new(),
            tcp: Vec::new(),
        };
        let nas = Peer {
            id: node(5),
            key: PublicKey::from_bytes([5; 32]),
            name: "nas".into(),
            virtual_ip: [10, 66, 0, 5].into(),
            inbound: true,
            outbound: true,
            endpoints: Vec::new(),
            attached: Vec::new(),
            exit: None,
            dial_out_only: false,
            keep_alive: false,
            lane: LaneMode::Off,
            congestion: None,
            no_udp: false,
        };
        Netmap {
            version: 1,
            network: Network {
                name: "home".into(),
                domain: "home.i3t".into(),
                cidr: "10.66.0.0/16".parse().unwrap(),
                routing: Default::default(),
                max_relay_hops: 2,
                reach: Default::default(),
                class: None,
                ack_eliciting_threshold: 3,
                max_ack_delay_ms: 2,
                bundle_small_packets: true,
            },
            me: LocalNode {
                id: node(1),
                name: "laptop".into(),
                virtual_ip: [10, 66, 0, 1].into(),
                routing: None,
                reach: None,
                dial_out_only: false,
                relay: None,
                exit: None,
                proxies: Vec::new(),
                forwards: Vec::new(),
                forward_targets: Vec::new(),
                pinned_relays: Vec::new(),
                profile: None,
                shared_relays: Vec::new(),
            },
            peers: vec![nas],
            relays: vec![relay(3, "hk")],
            relay_clients: Vec::new(),
            no_vnet: Vec::new(),
        }
    }

    #[test]
    fn a_flow_that_kept_its_route_says_so() {
        let routes = Fake(Mutex::new(Some(CurrentRoute { route: direct(), since_switch: Some(Duration::from_secs(60)) })));
        let span = RouteAtStart::now(&routes, peer()).ended(&routes);
        assert_eq!(span, RouteSpan { start: Some(direct()), end: Some(direct()), changed: false });
        assert_eq!(span.start_label(&netmap()).to_string(), "直连 203.0.113.7:20330");
    }

    #[test]
    fn a_switch_during_the_flow_counts_even_if_it_came_back_to_the_same_route() {
        let routes = Fake(Mutex::new(Some(CurrentRoute { route: direct(), since_switch: Some(Duration::from_secs(60)) })));
        let start = RouteAtStart::now(&routes, peer());
        std::thread::sleep(Duration::from_millis(5));
        *routes.0.lock().unwrap() = Some(CurrentRoute { route: direct(), since_switch: Some(Duration::ZERO) });
        assert!(start.clone().ended(&routes).changed, "又换回来的也算换过");

        let relayed = Route::Relay { relays: vec![NodeId::new(3).unwrap(), NodeId::new(5).unwrap()] };
        *routes.0.lock().unwrap() = Some(CurrentRoute { route: relayed.clone(), since_switch: Some(Duration::ZERO) });
        let span = start.ended(&routes);
        assert_eq!((span.end.clone(), span.changed), (Some(relayed), true));
        assert_eq!(span.end_label(&netmap()).to_string(), "经 hk → nas");
    }

    #[test]
    fn without_a_route_view_the_route_is_unknown() {
        let span = RouteAtStart::now(&NoRoutes, peer()).ended(&NoRoutes);
        assert_eq!(span, RouteSpan { start: None, end: None, changed: false });
        let netmap = netmap();
        assert_eq!(span.start_label(&netmap).to_string(), "?");
        assert_eq!(RouteLabel { route: Some(&Route::None), netmap: &netmap }.to_string(), "不可达");
    }

    #[test]
    fn relays_in_the_log_are_named_like_everywhere_else_and_unknown_ones_by_number() {
        let netmap = netmap();
        let via = Route::Relay { relays: [3, 1, 5, 7].map(|raw| NodeId::new(raw).unwrap()).to_vec() };
        let label = RouteLabel { route: Some(&via), netmap: &netmap };
        assert_eq!(label.to_string(), "经 hk → laptop → nas → #7", "relay 列表、本节点自己、对端都认得出来");
    }
}
