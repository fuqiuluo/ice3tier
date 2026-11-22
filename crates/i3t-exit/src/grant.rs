//! 一条流（或者数据报上下文里的一个目标）是凭什么被放行的，以及 netmap 变了之后它还成不成立。
//!
//! 放行一条流，除了访问规则还要靠本节点的能力：出口、局域网开关、端口转发。管理员关掉出口或局域网开关、删掉端口转发时，
//! 已经建立的流要跟着断开，不能只拒绝新的。所以放行时记下凭的是什么，
//! 每次 netmap 变了按新的 netmap 再核对一遍，不成立了就重置。
//!
//! TCP 流还会核对发起节点放行时的公钥。出站策略里随机器而变的部分（网卡的网段、本节点的公网地址）不在 netmap 里，
//! 放行时已按当时的情况查过。

use std::net::SocketAddr;

use i3t_model::Netmap;
use i3t_model::netmap::{ExitRole, ForwardProtocol};
use i3t_proto::{NodeId, PublicKey};

use crate::handler::{check_allow_list, forward_on_virtual_ip};

/// 放行时凭的是什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grant {
    /// 互联网目标：本节点是出口，并且出口允许这个端口。
    Internet { port: u16 },
    /// 局域网目标：本节点是出口，并且打开了局域网开关。
    Lan,
    /// 本节点自己的服务：只要访问规则还允许。
    NodeService,
    /// 监听在本节点虚拟 IP 的 `port` 端口上、编号是 `id`、目标是 `target` 节点的端口转发。
    /// 目标是本节点时 `addr` 是它指向的地址，否则是 `None`。
    VirtualForward { port: u16, id: u32, target: NodeId, addr: Option<SocketAddr> },
    /// 下发给本节点、由发起节点监听的 `id` 号端口转发，指向 `addr`。
    Forward { id: u32, addr: SocketAddr },
}

impl Grant {
    /// 按 `netmap`，`peer` 凭这一条的流还成不成立；不成立时返回给人看的原因。访问规则先查。
    ///
    /// `key` 是 TCP 流放行时的对端公钥。UDP 上下文的公钥吊销由底层连接处理。
    pub(crate) fn withdrawn(
        &self,
        netmap: &Netmap,
        peer: NodeId,
        protocol: ForwardProtocol,
        key: Option<PublicKey>,
    ) -> Option<&'static str> {
        let Some(initiator) = netmap.peer(peer).filter(|initiator| initiator.inbound) else {
            return Some("访问规则不再允许发起节点访问本节点");
        };
        if key.is_some_and(|key| initiator.key != key) {
            return Some("发起节点的公钥已变更");
        }
        match *self {
            Self::Internet { port } => match &netmap.me.exit {
                None => Some("本节点不再是出口"),
                Some(ExitRole { ports: Some(ports), .. }) if !ports.contains(&port) => Some("出口不再允许这个目标端口"),
                Some(_) => None,
            },
            Self::Lan => match &netmap.me.exit {
                None => Some("本节点不再是出口"),
                Some(ExitRole { lan: false, .. }) => Some("出口关掉了「允许访问本机局域网」"),
                Some(ExitRole { lan: true, .. }) => None,
            },
            Self::NodeService => None,
            Self::VirtualForward { port, id, target, addr } => {
                let current = forward_on_virtual_ip(netmap, port, protocol).filter(|forward| forward.id == id && forward.target == target);
                let Some(forward) = current else { return Some("这条端口转发被删掉或者改了") };
                if check_allow_list(initiator, forward).is_err() {
                    Some("发起节点不再在这条端口转发的来源白名单里")
                } else if target == netmap.me.id {
                    let points_to = netmap
                        .me
                        .forward_targets
                        .iter()
                        .find(|entry| entry.id == id && entry.listener == netmap.me.id && entry.protocol == protocol)
                        .map(|entry| entry.addr);
                    (points_to != addr).then_some("这条端口转发指向的地址被删掉或者改了")
                } else {
                    (!netmap.peer(target).is_some_and(|target| target.outbound))
                        .then_some("访问规则不再允许本节点访问这条端口转发的目标节点")
                }
            }
            Self::Forward { id, addr } => {
                let listed = netmap
                    .me
                    .forward_targets
                    .iter()
                    .any(|entry| entry.id == id && entry.listener == peer && entry.protocol == protocol && entry.addr == addr);
                (!listed).then_some("这条端口转发被删掉或者改了")
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use i3t_model::netmap::{Forward, ForwardTarget, LaneMode, LocalNode, Network, Peer};

    use super::*;

    const LAPTOP: u32 = 1;
    const GW: u32 = 2;
    const NAS: u32 = 3;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn peer(raw: u32) -> Peer {
        Peer {
            id: node(raw),
            key: PublicKey::from_bytes([u8::try_from(raw).unwrap(); 32]),
            name: format!("node-{raw}"),
            virtual_ip: [10, 66, 0, u8::try_from(raw).unwrap()].into(),
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
        }
    }

    /// gw 的 netmap：它是出口（80 和 443，局域网开关开着）；虚拟 IP 的 9100 端口转发到自己的 127.0.0.1:8081，
    /// 5353 端口（UDP）转发到 nas；laptop 监听着一条指向 gw 上 127.0.0.1:5432 的转发。
    pub(crate) fn netmap() -> Netmap {
        let forward = |id, protocol, port, target| Forward {
            id,
            protocol,
            bind: SocketAddr::from(([10, 66, 0, 2], port)),
            target: node(target),
            allow_from: Vec::new(),
            class: None,
        };
        let target = |id, protocol, addr: &str, listener| ForwardTarget {
            id,
            protocol,
            addr: addr.parse().unwrap(),
            listener: node(listener),
            proxy_protocol: None,
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
                vnet_offload: true,
                vnet_mtu: 1280,
            },
            me: LocalNode {
                id: node(GW),
                name: "gw".into(),
                virtual_ip: [10, 66, 0, 2].into(),
                routing: None,
                reach: None,
                dial_out_only: false,
                relay: None,
                exit: Some(ExitRole { lan: true, ..ExitRole::default() }),
                proxies: Vec::new(),
                forwards: vec![forward(7, ForwardProtocol::Tcp, 9100, GW), forward(8, ForwardProtocol::Udp, 5353, NAS)],
                forward_targets: vec![
                    target(7, ForwardProtocol::Tcp, "127.0.0.1:8081", GW),
                    target(9, ForwardProtocol::Tcp, "127.0.0.1:5432", LAPTOP),
                ],
                pinned_relays: Vec::new(),
                profile: None,
                shared_relays: Vec::new(),
            },
            peers: vec![peer(LAPTOP), peer(NAS)],
            relays: Vec::new(),
            relay_clients: Vec::new(),
            no_vnet: Vec::new(),
        }
    }

    fn after(change: impl FnOnce(&mut Netmap)) -> Netmap {
        let mut netmap = netmap();
        change(&mut netmap);
        netmap
    }

    fn withdrawn(grant: Grant, netmap: &Netmap, protocol: ForwardProtocol) -> Option<&'static str> {
        let key = (protocol == TCP).then(|| peer(LAPTOP).key);
        grant.withdrawn(netmap, node(LAPTOP), protocol, key)
    }

    const TCP: ForwardProtocol = ForwardProtocol::Tcp;

    #[test]
    fn every_grant_falls_with_the_access_rule() {
        let revoked = after(|netmap| netmap.peers[0].inbound = false);
        let gone = after(|netmap| netmap.peers.retain(|peer| peer.id != node(LAPTOP)));
        let internet = Grant::Internet { port: 443 };
        for grant in [internet, Grant::Lan, Grant::NodeService, Grant::Forward { id: 9, addr: "127.0.0.1:5432".parse().unwrap() }] {
            assert_eq!(withdrawn(grant, &netmap(), TCP), None, "{grant:?}");
            assert!(withdrawn(grant, &revoked, TCP).is_some(), "{grant:?}");
            assert!(withdrawn(grant, &gone, TCP).is_some(), "{grant:?}");
        }
    }

    #[test]
    fn a_tcp_grant_is_bound_to_the_initiators_key() {
        let current = after(|netmap| netmap.peers[0].key = PublicKey::from_bytes([42; 32]));
        assert!(withdrawn(Grant::NodeService, &current, TCP).is_some());
        let key = current.peers[0].key;
        assert_eq!(Grant::NodeService.withdrawn(&current, node(LAPTOP), TCP, Some(key)), None);
    }

    #[test]
    fn exit_grants_fall_when_the_exit_its_port_or_the_lan_switch_is_taken_back() {
        let internet = Grant::Internet { port: 443 };
        let no_exit = after(|netmap| netmap.me.exit = None);
        assert!(withdrawn(internet, &no_exit, TCP).is_some());
        assert!(withdrawn(Grant::Lan, &no_exit, TCP).is_some());

        let only_80 = after(|netmap| netmap.me.exit.as_mut().unwrap().ports = Some(vec![80]));
        assert!(withdrawn(internet, &only_80, TCP).is_some());
        assert_eq!(withdrawn(Grant::Internet { port: 80 }, &only_80, TCP), None);
        let any_port = after(|netmap| netmap.me.exit.as_mut().unwrap().ports = None);
        assert_eq!(withdrawn(Grant::Internet { port: 8080 }, &any_port, TCP), None);

        let lan_off = after(|netmap| netmap.me.exit.as_mut().unwrap().lan = false);
        assert!(withdrawn(Grant::Lan, &lan_off, TCP).is_some());
        assert_eq!(withdrawn(internet, &lan_off, TCP), None, "局域网开关只管局域网目标");
        // 本节点的服务不靠出口。
        assert_eq!(withdrawn(Grant::NodeService, &no_exit, TCP), None);
    }

    #[test]
    fn forward_grants_fall_when_the_forward_is_deleted_or_points_elsewhere() {
        let listed = Grant::Forward { id: 9, addr: "127.0.0.1:5432".parse().unwrap() };
        assert!(withdrawn(listed, &after(|netmap| netmap.me.forward_targets.retain(|entry| entry.id != 9)), TCP).is_some());
        let moved = after(|netmap| netmap.me.forward_targets[1].addr = "127.0.0.1:5433".parse().unwrap());
        assert!(withdrawn(listed, &moved, TCP).is_some());
        assert!(withdrawn(listed, &netmap(), ForwardProtocol::Udp).is_some(), "协议也要对得上");
        // 由别的节点监听的那一条，不是 laptop 的。
        assert!(listed.withdrawn(&netmap(), node(NAS), TCP, Some(peer(NAS).key)).is_some());

        let to_self = Grant::VirtualForward { port: 9100, id: 7, target: node(GW), addr: Some("127.0.0.1:8081".parse().unwrap()) };
        assert_eq!(withdrawn(to_self, &netmap(), TCP), None);
        assert!(withdrawn(to_self, &after(|netmap| netmap.me.forwards.retain(|forward| forward.id != 7)), TCP).is_some());
        assert!(withdrawn(to_self, &after(|netmap| netmap.me.forward_targets.retain(|entry| entry.id != 7)), TCP).is_some());
        let moved = after(|netmap| netmap.me.forward_targets[0].addr = "127.0.0.1:8082".parse().unwrap());
        assert!(withdrawn(to_self, &moved, TCP).is_some());
        let rebound = after(|netmap| netmap.me.forwards[0].bind = "10.66.0.2:9101".parse().unwrap());
        assert!(withdrawn(to_self, &rebound, TCP).is_some());
        let narrowed = after(|netmap| netmap.me.forwards[0].allow_from = vec!["10.66.0.3/32".parse().unwrap()]);
        assert!(withdrawn(to_self, &narrowed, TCP).is_some(), "发起节点不再在来源白名单里");

        let onward = Grant::VirtualForward { port: 5353, id: 8, target: node(NAS), addr: None };
        let udp = ForwardProtocol::Udp;
        assert_eq!(withdrawn(onward, &netmap(), udp), None);
        assert!(withdrawn(onward, &after(|netmap| netmap.peers[1].outbound = false), udp).is_some());
        assert!(withdrawn(onward, &after(|netmap| netmap.me.forwards[1].target = node(LAPTOP)), udp).is_some());
    }
}
