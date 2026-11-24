//! 本机网卡地址。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 本机网卡上能拿来当候选端点的地址。
///
/// 去掉了回环地址和链路本地地址：前者别的机器连不上，后者要带网卡编号才有意义。
/// 读不到网卡列表时返回空表并记一条日志，节点照常工作，只是少了局域网的候选。
#[must_use]
pub fn local_addresses() -> Vec<IpAddr> {
    let interfaces = match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(error) => {
            tracing::warn!(%error, "读不到本机的网卡地址，候选端点里不会有局域网地址");
            return Vec::new();
        }
    };
    let mut addresses: Vec<IpAddr> =
        interfaces.iter().filter(|interface| interface.is_oper_up()).map(if_addrs::Interface::ip).filter(|&ip| is_candidate(ip)).collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

/// 本机一块启用着的网卡上的一个地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddr {
    pub ip: IpAddr,
    /// 网卡的编号。IPv6 的组播要靠它指明从哪块网卡收发；系统没有给时是 `None`。
    pub index: Option<u32>,
    /// 这个地址所在网段的前缀长度。系统没有给掩码时是 0。
    pub prefix: u8,
}

/// 本机启用着的网卡上的全部地址，不做筛选（回环和链路本地的也在）。读不到网卡列表时返回空表。
#[must_use]
pub fn interface_addresses() -> Vec<InterfaceAddr> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else { return Vec::new() };
    interfaces
        .iter()
        .filter(|interface| interface.is_oper_up())
        .map(|interface| {
            let prefix = match &interface.addr {
                if_addrs::IfAddr::V4(addr) => addr.prefixlen,
                if_addrs::IfAddr::V6(addr) => addr.prefixlen,
            };
            InterfaceAddr { ip: interface.ip(), index: interface.index, prefix }
        })
        .collect()
}

/// 一个地址能不能当候选端点。
#[must_use]
pub fn is_candidate(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_candidate_v4(ip),
        IpAddr::V6(ip) => is_candidate_v6(ip),
    }
}

fn is_candidate_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast())
}

fn is_candidate_v6(ip: Ipv6Addr) -> bool {
    !(ip.is_loopback() || ip.is_unicast_link_local() || ip.is_unspecified() || ip.is_multicast())
}

/// 一个地址是不是只在本地网络里有意义（私有地址、唯一本地地址、回环）。
///
/// 路径层用它实现"局域网直连无条件优先"：同一个对端有一个这样的地址和一个公网地址都通时，用这一个。
#[must_use]
pub fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_link_local_are_not_candidates() {
        for ip in ["127.0.0.1", "169.254.1.2", "0.0.0.0", "::1", "fe80::1", "::", "224.0.0.1", "ff02::1"] {
            assert!(!is_candidate(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["192.168.1.5", "10.0.0.1", "203.0.113.7", "2001:db8::1", "fd00::1"] {
            assert!(is_candidate(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn private_ranges_are_recognised() {
        for ip in ["192.168.1.5", "10.0.0.1", "172.16.3.4", "127.0.0.1", "fd00::1", "::ffff:10.0.0.1"] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["203.0.113.7", "8.8.8.8", "2001:db8::1"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn listing_never_contains_unusable_addresses() {
        assert!(local_addresses().into_iter().all(is_candidate));
    }
}
