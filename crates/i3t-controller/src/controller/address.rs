//! 虚拟地址段和虚拟 IP 的分配规则。这里只有计算，不碰存储。

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::error::Error;

/// 地址段最长的前缀。再长就没有除了网络地址和广播地址之外的可分配地址了。
const MAX_PREFIX_LEN: u8 = 30;

/// 没指定地址段时依次试 `10.66.0.0/16`、`10.67.0.0/16`……
/// 该序列均位于 `10.0.0.0/8` 内，避开 `100.64.0.0/10`（CGNAT 地址段，常被其他组网工具或家用宽带 WAN 口使用）。
const DEFAULT_SECOND_OCTETS: std::ops::RangeInclusive<u8> = 66..=255;

/// 把管理员写的地址段规整成网络地址的形式（`10.66.3.4/16` 读成 `10.66.0.0/16`）。
pub(super) fn normalize(cidr: Ipv4Net) -> Result<Ipv4Net, Error> {
    if cidr.prefix_len() > MAX_PREFIX_LEN {
        return Err(Error::invalid_field("cidr", "too_small", format!("地址段 {cidr} 太小：前缀最长是 /{MAX_PREFIX_LEN}")));
    }
    Ok(cidr.trunc())
}

pub(super) fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// 第一个不和 `taken` 里任何一段重叠的默认地址段。
pub(super) fn default_range(taken: &[Ipv4Net]) -> Option<Ipv4Net> {
    DEFAULT_SECOND_OCTETS
        .map(|second| Ipv4Net::new(Ipv4Addr::new(10, second, 0, 0), 16).expect("16 是合法的 IPv4 前缀长度"))
        .find(|candidate| !taken.iter().any(|existing| overlaps(*candidate, *existing)))
}

/// `address` 能不能在这个地址段里分给节点：在段里，并且不是网络地址和广播地址。
pub(super) fn is_assignable(cidr: Ipv4Net, address: Ipv4Addr) -> bool {
    cidr.contains(&address) && address != cidr.network() && address != cidr.broadcast()
}

/// 地址段里最小的、不在 `unavailable` 里的可分配地址。
pub(super) fn lowest_free(cidr: Ipv4Net, unavailable: &BTreeSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    cidr.hosts().find(|address| !unavailable.contains(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> Ipv4Net {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    #[test]
    fn the_lowest_free_address_skips_network_broadcast_and_unavailable_ones() {
        let cidr = net("10.66.0.0/29");
        assert_eq!(lowest_free(cidr, &BTreeSet::new()), Some(ip("10.66.0.1")));
        let unavailable: BTreeSet<_> = [ip("10.66.0.1"), ip("10.66.0.2"), ip("10.66.0.4")].into();
        assert_eq!(lowest_free(cidr, &unavailable), Some(ip("10.66.0.3")));
        let all: BTreeSet<_> = (1..=6).map(|last| Ipv4Addr::new(10, 66, 0, last)).collect();
        assert_eq!(lowest_free(cidr, &all), None, "10.66.0.0 和 10.66.0.7 不能分出去");
    }

    #[test]
    fn network_and_broadcast_addresses_are_not_assignable() {
        let cidr = net("10.66.0.0/24");
        assert!(is_assignable(cidr, ip("10.66.0.1")) && is_assignable(cidr, ip("10.66.0.254")));
        assert!(!is_assignable(cidr, ip("10.66.0.0")) && !is_assignable(cidr, ip("10.66.0.255")));
        assert!(!is_assignable(cidr, ip("10.66.1.1")));
    }

    #[test]
    fn default_ranges_avoid_existing_networks_and_the_cgnat_block() {
        assert_eq!(default_range(&[]), Some(net("10.66.0.0/16")));
        assert_eq!(default_range(&[net("10.66.0.0/16")]), Some(net("10.67.0.0/16")));
        assert_eq!(default_range(&[net("10.64.0.0/14")]), Some(net("10.68.0.0/16")));
        assert_eq!(default_range(&[net("10.0.0.0/8")]), None);
        let cgnat = net("100.64.0.0/10");
        let mut taken = Vec::new();
        while let Some(range) = default_range(&taken) {
            assert!(!overlaps(range, cgnat), "{range}");
            taken.push(range);
        }
        assert_eq!(taken.len(), 190);
    }

    #[test]
    fn ranges_are_normalised_and_tiny_ones_refused() {
        assert_eq!(normalize(net("10.66.3.4/16")).unwrap(), net("10.66.0.0/16"));
        assert!(normalize(net("10.66.0.0/30")).is_ok());
        assert!(normalize(net("10.66.0.0/31")).is_err());
    }

    #[test]
    fn overlap_is_detected_in_both_directions() {
        assert!(overlaps(net("10.66.0.0/16"), net("10.66.5.0/24")));
        assert!(overlaps(net("10.66.5.0/24"), net("10.66.0.0/16")));
        assert!(overlaps(net("10.66.0.0/16"), net("10.66.0.0/16")));
        assert!(!overlaps(net("10.66.0.0/16"), net("10.67.0.0/16")));
    }
}
