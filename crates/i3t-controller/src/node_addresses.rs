//! 节点的真实地址能说明的两件事：relay 的地址，和网卡地址落进虚拟地址段时的提醒。
//!
//! relay 的地址没有人填，从三处来，按这个顺序合在一起，去掉重复的，最多 [`MAX_RELAY_ADDRESSES`] 个：
//!
//! 1. 节点上声明的（`i3t set relay-address`）：只有人知道的端口映射，所以排最前；
//! 2. controller 看到的：节点连 controller 时的来源 IP 加上它自报的端口；
//! 3. 节点本地网卡地址：均拼接节点自报的端口。IPv4 排在 IPv6 之前：同一局域网内的节点通常通过 IPv4 内网地址互通。
//!
//! 单个地址不必对所有节点均可达：各节点并行探测并选用实际可连通的地址。因此此处不区分「公网」与「内网」，
//! 仅过滤任何节点均不可达的地址（全零、组播、广播、链路本地）以及覆盖网自身地址段内的地址（节点不会将其视为真实地址连接）。
//!
//! 所有输入均来自持久化存储，节点离线后或 controller 重启后均可重新计算。

use std::net::{IpAddr, SocketAddr};

use i3t_model::admin::{AddressSource, MAX_RELAY_ADDRESSES, NodeWarning, RelayAddress};
use ipnet::Ipv4Net;

use crate::store::NodeRecord;

/// 这个节点作为 relay 的地址，按节点去试的顺序。
pub(crate) fn relay_addresses(node: &NodeRecord, cidr: Ipv4Net) -> Vec<RelayAddress> {
    let mut addresses: Vec<RelayAddress> = Vec::with_capacity(MAX_RELAY_ADDRESSES);
    let mut add = |address: SocketAddr, source: AddressSource| {
        let address = canonical(address);
        if addresses.len() < MAX_RELAY_ADDRESSES && usable(address, cidr) && !addresses.iter().any(|known| known.address == address) {
            addresses.push(RelayAddress { address, source });
        }
    };
    if let Some(declared) = node.declared.relay_address {
        add(declared, AddressSource::Declared);
    }
    if let Some(observed) = node.observed {
        add(observed, AddressSource::Observed);
    }
    // 网卡上的地址用节点自报的端口，它就在 controller 看到的那个地址里；节点没报过端口时不知道该连哪个端口。
    if let Some(port) = node.observed.map(|observed| observed.port()) {
        let mut local = local_ips(node);
        // 稳定排序：同一种地址保持节点报的顺序。
        local.sort_by_key(IpAddr::is_ipv6);
        for ip in local {
            add(SocketAddr::new(ip, port), AddressSource::Local);
        }
    }
    addresses
}

/// 节点网卡上的地址。旧版本的节点不单独报（[`NodeRecord::local_addresses`] 是 `None`），这时拿它的候选端点代替：
/// 里面有网卡地址，也夹着别人看到的地址和端口映射出来的地址，对 relay 来说都是可以试的地址。
fn local_ips(node: &NodeRecord) -> Vec<IpAddr> {
    match &node.local_addresses {
        Some(local) => local.clone(),
        None => node.endpoints.iter().map(|endpoint| endpoint.ip()).collect(),
    }
}

/// 值得提醒的情况：节点的网卡地址落在网络的地址段里。按节点最近一次报的网卡地址算。
pub(crate) fn warnings(node: &NodeRecord, cidr: Ipv4Net) -> Vec<NodeWarning> {
    let local = node.local_addresses.as_deref().unwrap_or_default();
    local.iter().map(|ip| ip.to_canonical()).filter(|ip| in_range(*ip, cidr)).map(|address| NodeWarning::RangeOverlap { address }).collect()
}

/// 同一个地址只有一种写法：IPv4 映射的 IPv6 地址写成它里面的 IPv4 地址。
pub(crate) fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

fn in_range(ip: IpAddr, cidr: Ipv4Net) -> bool {
    matches!(ip, IpAddr::V4(v4) if cidr.contains(&v4))
}

/// 判断该地址是否可供其他节点尝试连接：端口非 0，不属于通用不可达地址类型，且不在覆盖网自身地址段内。
/// 回环地址予以保留：同机部署的节点（常见于测试环境）依赖回环地址互通，跨机节点探测失败的开销仅数个数据包。
fn usable(address: SocketAddr, cidr: Ipv4Net) -> bool {
    let ip = address.ip();
    let unusable = match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast() || v6.is_unicast_link_local(),
    };
    address.port() != 0 && !unusable && !in_range(ip, cidr)
}

/// 节点声明的 relay 地址能不能收：别的节点会去连它，所以要是一个能连的单播地址。
pub(crate) fn declarable(address: SocketAddr, cidr: Ipv4Net) -> bool {
    usable(canonical(address), cidr) && !address.ip().is_loopback()
}

#[cfg(test)]
mod tests {
    use i3t_model::control::Declared;

    use super::*;

    const CIDR: &str = "10.66.0.0/16";

    fn node(observed: Option<&str>, local: Option<&[&str]>, declared: Option<&str>) -> NodeRecord {
        NodeRecord {
            name: "r".to_owned(),
            declared: Declared { relay: true, relay_address: declared.map(|text| text.parse().unwrap()), ..Declared::default() },
            endpoints: vec!["192.168.9.9:20330".parse().unwrap()],
            local_addresses: local.map(|ips| ips.iter().map(|ip| ip.parse().unwrap()).collect()),
            observed: observed.map(|text| text.parse().unwrap()),
            ..crate::store::fixtures::record(1)
        }
    }

    fn listed(addresses: &[RelayAddress]) -> Vec<(String, AddressSource)> {
        addresses.iter().map(|entry| (entry.address.to_string(), entry.source)).collect()
    }

    #[test]
    fn declared_comes_first_then_observed_then_interfaces_ipv4_before_ipv6() {
        let record = node(Some("198.51.100.4:20330"), Some(&["2001:db8::4", "192.168.1.5", "198.51.100.4"]), Some("203.0.113.9:40330"));
        assert_eq!(
            listed(&relay_addresses(&record, CIDR.parse().unwrap())),
            [
                ("203.0.113.9:40330".to_owned(), AddressSource::Declared),
                ("198.51.100.4:20330".to_owned(), AddressSource::Observed),
                ("192.168.1.5:20330".to_owned(), AddressSource::Local),
                ("[2001:db8::4]:20330".to_owned(), AddressSource::Local),
            ],
            "网卡上和 controller 看到的相同的地址只出现一次"
        );
    }

    #[test]
    fn addresses_nobody_can_use_and_the_overlay_range_are_left_out() {
        let local = ["10.66.3.7", "0.0.0.0", "169.254.1.1", "fe80::1", "224.0.0.1", "172.17.0.1"];
        let record = node(Some("[::ffff:198.51.100.4]:20330"), Some(&local), None);
        assert_eq!(
            listed(&relay_addresses(&record, CIDR.parse().unwrap())),
            [("198.51.100.4:20330".to_owned(), AddressSource::Observed), ("172.17.0.1:20330".to_owned(), AddressSource::Local)]
        );
    }

    #[test]
    fn the_list_is_bounded_and_a_node_that_never_reported_a_port_has_only_its_declared_address() {
        let many: Vec<String> = (1..=20).map(|host| format!("192.168.1.{host}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let record = node(Some("198.51.100.4:20330"), Some(&many), Some("203.0.113.9:40330"));
        assert_eq!(relay_addresses(&record, CIDR.parse().unwrap()).len(), MAX_RELAY_ADDRESSES);

        let silent = node(None, Some(&["192.168.1.5"]), Some("203.0.113.9:40330"));
        assert_eq!(listed(&relay_addresses(&silent, CIDR.parse().unwrap())), [("203.0.113.9:40330".to_owned(), AddressSource::Declared)]);
    }

    #[test]
    fn an_older_node_has_its_reported_endpoints_stand_in_for_its_interfaces() {
        let record = node(Some("198.51.100.4:20330"), None, None);
        assert_eq!(
            listed(&relay_addresses(&record, CIDR.parse().unwrap())),
            [("198.51.100.4:20330".to_owned(), AddressSource::Observed), ("192.168.9.9:20330".to_owned(), AddressSource::Local)]
        );
    }

    #[test]
    fn an_interface_address_inside_the_range_is_a_warning() {
        let record = node(None, Some(&["192.168.1.5", "10.66.3.7", "::ffff:10.66.0.9"]), None);
        assert_eq!(
            warnings(&record, CIDR.parse().unwrap()),
            [
                NodeWarning::RangeOverlap { address: "10.66.3.7".parse().unwrap() },
                NodeWarning::RangeOverlap { address: "10.66.0.9".parse().unwrap() }
            ]
        );
        assert!(warnings(&node(None, None, None), CIDR.parse().unwrap()).is_empty(), "没报过网卡地址的节点没有提醒");
    }

    #[test]
    fn a_declared_address_must_be_one_others_can_connect_to() {
        let cidr: Ipv4Net = CIDR.parse().unwrap();
        assert!(declarable("203.0.113.9:40330".parse().unwrap(), cidr));
        assert!(declarable("[2001:db8::1]:20330".parse().unwrap(), cidr));
        for bad in ["0.0.0.0:20330", "203.0.113.9:0", "127.0.0.1:20330", "10.66.0.4:20330", "224.0.0.1:20330", "[::1]:20330"] {
            assert!(!declarable(bad.parse().unwrap(), cidr), "{bad}");
        }
    }
}
