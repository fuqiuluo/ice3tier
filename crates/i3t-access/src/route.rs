//! 一个代理请求往哪里去。
//!
//! 按这个顺序判断：
//!
//! 1. 目标是组网地址（虚拟地址段里的 IP，或者带网络域名后缀的节点名）：访问那个节点自己的服务，不经出口。
//!    虚拟地址段里的目标永远不会被当成互联网目标交给出口。
//! 2. 别的目标经代理的出口出去：写成私有地址的是出口所在的局域网（要出口打开了局域网），其余是互联网目标。
//!    本机配置文件里的组网入口没有出口，这样的目标一律拒绝。
//!
//! 要用到的节点必须是 netmap 里本节点可以访问的对端。它不在 netmap 里和访问规则不允许是同一个结果：
//! controller 本来就只下发互相能访问的节点，两种情况对调用者也只有一种表现。

use std::net::{IpAddr, SocketAddr};

use i3t_model::Netmap;
use i3t_model::netmap::Peer;
use i3t_proto::flow::{Class, Host, Target};
use i3t_proto::{NodeId, PublicKey};

/// 请求最后怎么走：到 `peer` 开一条流。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route {
    pub peer: NodeId,
    pub key: PublicKey,
    pub target: Target,
    /// 按目标的种类，不等对端的 REPLY 就告诉客户端连上了。互联网目标默认这样做，省一个全程往返；
    /// 组网目标要等，客户端才能拿到准确的错误（比如端口没开时是"连接被拒绝"）。
    pub optimistic: bool,
}

/// 请求被入口自己拒绝的原因。只进日志，客户端看到的都一样。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Denied {
    #[error("目标节点不在 netmap 里，或者访问规则不允许本节点访问它")]
    NoSuchNode,
    #[error("代理的出口节点不在 netmap 里，或者访问规则不允许本节点访问它")]
    NoSuchExit,
    #[error("代理的出口节点没有启用出口")]
    ExitNotEnabled,
    #[error("代理的出口节点没有打开「允许访问本机局域网」")]
    LanNotEnabled,
    #[error("目标是本节点自己的虚拟 IP 或名字，入口不替本机连自己")]
    Myself,
    #[error("本机配置文件里的组网入口只通到组网里的节点，这个目标不在组网里")]
    MeshOnly,
}

/// 决定一个请求怎么走。`exit` 是代理的出口；本机的组网入口没有出口，是 `None`。
pub(crate) fn decide(netmap: &Netmap, exit: Option<NodeId>, host: &Host, port: u16) -> Result<Route, Denied> {
    if let Some(node) = mesh_node(netmap, host) {
        let node = node?;
        return Ok(Route { peer: node.id, key: node.key, target: Target::Node { port }, optimistic: false });
    }
    let exit = exit.ok_or(Denied::MeshOnly)?;
    let exit = netmap.peer(exit).filter(|peer| peer.outbound).ok_or(Denied::NoSuchExit)?;
    // 对端有没有启用出口，netmap 里有一份。在这里就查，客户端能马上得到失败，不用等对端来拒绝。
    let role = exit.exit.ok_or(Denied::ExitNotEnabled)?;

    // IPv4 映射的 IPv6 地址按 IPv4 发，对端的策略按同一个地址判断。
    let host = match host {
        Host::Ip(ip) => Host::Ip(ip.to_canonical()),
        Host::Name(name) => Host::Name(name.clone()),
    };
    match host {
        Host::Ip(ip) if is_lan_literal(ip) => {
            if !role.lan {
                return Err(Denied::LanNotEnabled);
            }
            Ok(Route { peer: exit.id, key: exit.key, target: Target::Lan { addr: SocketAddr::new(ip, port) }, optimistic: false })
        }
        host => Ok(Route { peer: exit.id, key: exit.key, target: Target::Internet { host, port }, optimistic: true }),
    }
}

/// 一条流的服务等级，优先级从高到低：代理或端口转发自己的设置、出口的默认值（只有经出口出去的流才看它）、
/// 网络的默认值。都没有时是 `auto`。
pub(crate) fn class_for(netmap: &Netmap, configured: Option<Class>, route: &Route) -> Class {
    let exit = route.target.needs_exit().then(|| netmap.peer(route.peer).and_then(|peer| peer.exit).and_then(|exit| exit.class)).flatten();
    configured.or(exit).or(netmap.network.class).unwrap_or_default()
}

/// 一条流用不用乐观回复，先看到哪一个设置用哪一个：代理的、出口的（只有经出口出去的流才看它）、
/// 按目标种类的默认值（[`Route::optimistic`]）。代理排在出口前面：它是为这一个入口定的，出口的设置管的是经它出去的所有代理。
pub(crate) fn optimistic_for(netmap: &Netmap, configured: Option<bool>, route: &Route) -> bool {
    let exit =
        route.target.needs_exit().then(|| netmap.peer(route.peer).and_then(|peer| peer.exit).and_then(|exit| exit.optimistic)).flatten();
    configured.or(exit).unwrap_or(route.optimistic)
}

/// 目标指的是不是组网里的一个节点。不是组网目标时返回 `None`；是的话给出那个对端，或者不能访问它的原因。
pub(crate) fn mesh_node<'a>(netmap: &'a Netmap, host: &Host) -> Option<Result<&'a Peer, Denied>> {
    let peer = match host {
        Host::Ip(ip) => {
            let IpAddr::V4(ip) = ip.to_canonical() else { return None };
            if !netmap.network.is_overlay_address(IpAddr::V4(ip)) {
                return None;
            }
            if ip == netmap.me.virtual_ip {
                return Some(Err(Denied::Myself));
            }
            netmap.peer_by_ip(ip)
        }
        Host::Name(name) => {
            // 只有带着网络域名后缀的才是节点名。单独一个 `nas-01` 可能是局域网里的主机名，不能抢过来。
            let full = name.as_str().strip_suffix('.').unwrap_or(name.as_str());
            let short = netmap.network.short_name(full);
            if short.len() == full.len() {
                return None;
            }
            if short.eq_ignore_ascii_case(&netmap.me.name) {
                return Some(Err(Denied::Myself));
            }
            netmap.peer_by_name(short)
        }
    };
    Some(peer.filter(|peer| peer.outbound).ok_or(Denied::NoSuchNode))
}

/// 写成字面量的地址是不是只在局域网里有意义：私有地址和链路本地地址。
///
/// 入口不知道出口节点的网卡上有哪些网段，只能按地址本身来分：这些地址按"出口的局域网"发过去，其余的按互联网目标发。
/// 出口节点会再核对它是不是真的在自己直连的网段里。出口测试（`i3t_exit::Outbound::probe`）按同一条分。
#[must_use]
pub fn is_lan_literal(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use i3t_model::netmap::{LaneMode, LocalNode, Network, PeerExit};

    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn peer(raw: u8, name: &str, exit: Option<PeerExit>) -> Peer {
        Peer {
            id: node(u32::from(raw)),
            key: PublicKey::from_bytes([raw; 32]),
            name: name.into(),
            virtual_ip: [10, 66, 0, raw].into(),
            inbound: true,
            outbound: true,
            endpoints: Vec::new(),
            attached: Vec::new(),
            exit,
            dial_out_only: false,
            keep_alive: false,
            lane: LaneMode::Off,
            congestion: None,
            no_udp: false,
        }
    }

    /// 本节点是 1 号 `laptop`（10.66.0.1）；2 号 `gw` 是出口并开了局域网；3 号 `web` 是出口；4 号 `nas` 不是出口；
    /// 5 号 `hidden` 不允许访问。对端的虚拟 IP 是 10.66.0.<编号>，都可以访问本节点。
    pub(crate) fn netmap() -> Netmap {
        let mut hidden = peer(5, "hidden", Some(PeerExit { lan: true, class: None, optimistic: None }));
        hidden.outbound = false;
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
            peers: vec![
                peer(2, "gw", Some(PeerExit { lan: true, class: None, optimistic: None })),
                peer(3, "web", Some(PeerExit { lan: false, class: Some(Class::Bulk), optimistic: None })),
                peer(4, "nas", None),
                hidden,
            ],
            relays: Vec::new(),
            relay_clients: Vec::new(),
            no_vnet: Vec::new(),
        }
    }

    fn route(netmap: &Netmap, exit: Option<u32>, host: &str, port: u16) -> Result<Route, Denied> {
        decide(netmap, exit.map(node), &host.parse().unwrap(), port)
    }

    fn internet(peer: u8, host: &str, port: u16) -> Result<Route, Denied> {
        Ok(Route {
            peer: node(u32::from(peer)),
            key: PublicKey::from_bytes([peer; 32]),
            target: Target::Internet { host: host.parse().unwrap(), port },
            optimistic: true,
        })
    }

    fn service(peer: u8, port: u16) -> Result<Route, Denied> {
        Ok(Route { peer: node(u32::from(peer)), key: PublicKey::from_bytes([peer; 32]), target: Target::Node { port }, optimistic: false })
    }

    #[test]
    fn targets_outside_the_mesh_leave_through_the_proxy_exit() {
        let netmap = netmap();
        assert_eq!(route(&netmap, Some(3), "example.com", 443), internet(3, "example.com", 443));
        assert_eq!(route(&netmap, Some(2), "203.0.113.7", 80), internet(2, "203.0.113.7", 80));
    }

    #[test]
    fn unknown_forbidden_and_own_exits_fail_the_same_way() {
        let netmap = netmap();
        for exit in [9, 5, 1] {
            assert_eq!(route(&netmap, Some(exit), "example.com", 443), Err(Denied::NoSuchExit), "{exit}");
        }
    }

    #[test]
    fn an_exit_must_have_the_capability_the_target_needs() {
        let netmap = netmap();
        assert_eq!(route(&netmap, Some(4), "example.com", 443), Err(Denied::ExitNotEnabled));
        assert_eq!(route(&netmap, Some(4), "192.168.1.10", 80), Err(Denied::ExitNotEnabled));
        assert_eq!(route(&netmap, Some(3), "192.168.1.10", 80), Err(Denied::LanNotEnabled));
    }

    #[test]
    fn private_address_literals_go_to_the_exit_as_lan_targets_and_wait_for_the_reply() {
        let netmap = netmap();
        for host in ["192.168.1.10", "172.16.5.5", "10.1.2.3", "169.254.1.1", "fd00::10", "fe80::1", "::ffff:192.168.1.10"] {
            let addr = SocketAddr::new(host.parse::<IpAddr>().unwrap().to_canonical(), 80);
            let expected =
                Ok(Route { peer: node(2), key: PublicKey::from_bytes([2; 32]), target: Target::Lan { addr }, optimistic: false });
            assert_eq!(route(&netmap, Some(2), host, 80), expected, "{host}");
        }
        // 域名和别的地址一律按互联网目标发：解析出内网地址时由出口的策略拒绝。
        assert_eq!(route(&netmap, Some(2), "printer.lan", 80), internet(2, "printer.lan", 80));
        assert_eq!(route(&netmap, Some(2), "127.0.0.1", 80), internet(2, "127.0.0.1", 80));
        assert_eq!(route(&netmap, Some(2), "100.64.0.1", 80), internet(2, "100.64.0.1", 80));
    }

    #[test]
    fn overlay_addresses_and_node_names_are_services_on_that_node_and_do_not_go_through_the_exit() {
        let netmap = netmap();
        for host in ["10.66.0.4", "nas.home.i3t", "NAS.Home.I3T", "nas.home.i3t.", "::ffff:10.66.0.4"] {
            assert_eq!(route(&netmap, Some(3), host, 8080), service(4, 8080), "{host}");
            assert_eq!(route(&netmap, None, host, 8080), service(4, 8080), "本机的组网入口：{host}");
        }
        assert_eq!(route(&netmap, Some(3), "web.home.i3t", 22), service(3, 22), "出口自己的服务也是组网目标");
    }

    #[test]
    fn mesh_targets_that_cannot_be_reached_never_fall_through_to_the_exit() {
        let netmap = netmap();
        for host in ["10.66.0.9", "10.66.255.255", "10.66.0.5", "nobody.home.i3t", "hidden.home.i3t"] {
            assert_eq!(route(&netmap, Some(3), host, 80), Err(Denied::NoSuchNode), "{host}");
            assert_eq!(route(&netmap, None, host, 80), Err(Denied::NoSuchNode), "{host}");
        }
        assert_eq!(route(&netmap, Some(3), "10.66.0.1", 80), Err(Denied::Myself));
        assert_eq!(route(&netmap, None, "laptop.home.i3t", 80), Err(Denied::Myself));
    }

    #[test]
    fn the_local_mesh_entry_refuses_everything_outside_the_mesh() {
        let netmap = netmap();
        for host in ["example.com", "nas", "nas.other.i3t", "192.168.1.10", "203.0.113.7", "home.i3t"] {
            assert_eq!(route(&netmap, None, host, 80), Err(Denied::MeshOnly), "{host}");
        }
    }

    #[test]
    fn names_outside_the_network_domain_are_not_node_names() {
        let netmap = netmap();
        for host in ["nas", "nas.other.i3t", "home.i3t", "nas.home.i3t.example.com"] {
            assert_eq!(route(&netmap, Some(3), host, 80), internet(3, host, 80), "{host}");
        }
    }

    #[test]
    fn class_comes_from_the_proxy_then_the_exit_then_the_network() {
        let mut netmap = netmap();
        let to_web = route(&netmap, Some(3), "example.com", 443).unwrap();
        let to_nas = route(&netmap, Some(3), "10.66.0.4", 22).unwrap();
        assert_eq!(class_for(&netmap, Some(Class::Reliable), &to_web), Class::Reliable, "先看代理");
        assert_eq!(class_for(&netmap, None, &to_web), Class::Bulk, "再看出口的默认值");
        assert_eq!(class_for(&netmap, None, &to_nas), Class::Auto, "不经出口的流不看出口的默认值");
        netmap.network.class = Some(Class::Reliable);
        assert_eq!(class_for(&netmap, None, &to_nas), Class::Reliable, "最后是网络的默认值");
        assert_eq!(class_for(&netmap, None, &to_web), Class::Bulk, "出口的默认值排在网络的前面");
    }

    #[test]
    fn the_optimistic_reply_follows_the_proxy_then_the_exit_then_the_kind_of_target() {
        let mut netmap = netmap();
        let to_web = route(&netmap, Some(3), "example.com", 443).unwrap();
        let to_nas = route(&netmap, Some(3), "10.66.0.4", 22).unwrap();
        assert!(optimistic_for(&netmap, None, &to_web), "没有设时按目标的种类");
        assert!(!optimistic_for(&netmap, None, &to_nas));
        netmap.peers.iter_mut().find(|peer| peer.name == "web").unwrap().exit.as_mut().unwrap().optimistic = Some(false);
        assert!(!optimistic_for(&netmap, None, &to_web), "出口的设置盖过按种类的默认值");
        assert!(optimistic_for(&netmap, Some(true), &to_web), "代理的设置排在出口的前面");
        assert!(optimistic_for(&netmap, Some(true), &to_nas), "不经出口的流只看代理的设置");
        netmap.peers.iter_mut().find(|peer| peer.name == "web").unwrap().exit.as_mut().unwrap().optimistic = Some(true);
        assert!(!optimistic_for(&netmap, None, &to_nas), "不经出口的流不看出口的设置");
    }
}
