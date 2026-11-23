//! 出站策略里和地址有关的那一部分：哪些地址出口不替别人去连。
//!
//! 出口把别人的流从本机送往互联网。它自己所在的内网、它自己、各种只在本地有意义的地址都不是"互联网"，
//! 放行了就等于把出口宿主的内网暴露给所有能用它的人。所以互联网目标只放行全球可路由的单播地址，
//! 而且是在域名解析之后对每一个要去连的地址判断：域名可以解析到任何地方。
//!
//! 这里是固定的那一部分（按 IANA 的特殊用途地址登记表）。本机网卡的网段和覆盖网的地址段随机器和网络而变，
//! 由调用者另外检查。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

const fn v4(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(a, b, c, d), prefix_len)
}

const fn v6(first: u16, second: u16, prefix_len: u8) -> Ipv6Net {
    Ipv6Net::new_assert(Ipv6Addr::new(first, second, 0, 0, 0, 0, 0, 0), prefix_len)
}

/// 不放行的 IPv4 网段，以及它是什么。
const BLOCKED_V4: [(Ipv4Net, &str); 16] = [
    (v4(0, 0, 0, 0, 8), "「本网络」地址"),
    (v4(10, 0, 0, 0, 8), "私有地址"),
    (v4(100, 64, 0, 0, 10), "运营商级 NAT 地址"),
    (v4(127, 0, 0, 0, 8), "回环地址"),
    (v4(169, 254, 0, 0, 16), "链路本地地址"),
    (v4(172, 16, 0, 0, 12), "私有地址"),
    (v4(192, 0, 0, 0, 24), "协议保留地址"),
    (v4(192, 0, 2, 0, 24), "文档用地址"),
    (v4(192, 88, 99, 0, 24), "6to4 中继地址"),
    (v4(192, 168, 0, 0, 16), "私有地址"),
    (v4(198, 18, 0, 0, 15), "基准测试用地址"),
    (v4(198, 51, 100, 0, 24), "文档用地址"),
    (v4(203, 0, 113, 0, 24), "文档用地址"),
    (v4(224, 0, 0, 0, 4), "组播地址"),
    (v4(240, 0, 0, 0, 4), "保留地址"),
    // Azure 的平台服务地址。它是一个公网地址，只在云主机内部可达，作用和元数据地址一样。
    (v4(168, 63, 129, 16, 32), "云平台的元数据地址"),
];

/// IPv6 的全球单播地址都在这一段里。这一段之外的（未指定、回环、映射、NAT64、唯一本地、链路本地、组播……）一律不放行。
const GLOBAL_UNICAST_V6: Ipv6Net = v6(0x2000, 0, 3);

/// 全球单播那一段里不放行的部分。
const BLOCKED_V6: [(Ipv6Net, &str); 4] = [
    // Teredo、ORCHID、基准测试等都在这里面，其中有的把一个 IPv4 地址包在里面。
    (v6(0x2001, 0, 23), "协议保留地址"),
    (v6(0x2001, 0x0db8, 32), "文档用地址"),
    (v6(0x2002, 0, 16), "6to4 地址"),
    (v6(0x3fff, 0, 20), "文档用地址"),
];

/// `ip` 不是全球可路由的单播地址时，返回它是什么地址（用在拒绝的说明里）。
///
/// IPv4 映射的 IPv6 地址按里面的 IPv4 地址判断。
pub(crate) fn not_public(ip: IpAddr) -> Option<&'static str> {
    match ip.to_canonical() {
        IpAddr::V4(ip) => BLOCKED_V4.iter().find(|(net, _)| net.contains(&ip)).map(|&(_, what)| what),
        IpAddr::V6(ip) if !GLOBAL_UNICAST_V6.contains(&ip) => Some("不是全球单播的 IPv6 地址"),
        IpAddr::V6(ip) => BLOCKED_V6.iter().find(|(net, _)| net.contains(&ip)).map(|&(_, what)| what),
    }
}

/// `ip` 是不是链路本地地址。这类地址要带着网卡才有意义，而且云平台的元数据服务就在这一段里。
pub(crate) fn is_link_local(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn ordinary_public_addresses_are_allowed() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.15.255.255",
            "172.32.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2400:3200::1",
            "2a00:1450:4001::64",
        ] {
            assert_eq!(not_public(ip(address)), None, "{address}");
        }
    }

    #[test]
    fn loopback_private_link_local_and_cgnat_are_refused() {
        for address in [
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "169.254.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "::1",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::1",
        ] {
            assert!(not_public(ip(address)).is_some(), "{address}");
        }
    }

    #[test]
    fn unspecified_multicast_broadcast_and_reserved_are_refused() {
        for address in ["0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "::", "ff02::1", "ff0e::1"] {
            assert!(not_public(ip(address)).is_some(), "{address}");
        }
    }

    #[test]
    fn documentation_benchmark_and_protocol_ranges_are_refused() {
        for address in [
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.0.1",
            "192.0.0.170",
            "192.88.99.1",
            "2001:db8::1",
            "3fff::1",
            "3fff:fff:ffff::1",
            "2001::1",
            "2001:2::1",
            "2001:1ff:ffff::1",
            "100::1",
        ] {
            assert!(not_public(ip(address)).is_some(), "{address}");
        }
    }

    #[test]
    fn addresses_that_wrap_an_ipv4_address_do_not_slip_through() {
        // 映射、兼容、NAT64、6to4、Teredo：里面都可以包着一个内网的 IPv4 地址。
        for address in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::10.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b:1::a00:1",
            "2002:a00:1::1",
            "2001:0:a00:1::1",
        ] {
            assert!(not_public(ip(address)).is_some(), "{address}");
        }
        assert_eq!(not_public(ip("::ffff:1.1.1.1")), None, "映射的公网地址按 IPv4 放行");
    }

    #[test]
    fn cloud_metadata_addresses_are_never_public() {
        for address in ["169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "::ffff:169.254.169.254"] {
            assert!(i3t_model::netmap::is_cloud_metadata(ip(address)), "{address}");
            assert!(not_public(ip(address)).is_some(), "{address}");
        }
    }

    #[test]
    fn link_local_addresses_are_recognised() {
        for address in ["169.254.0.1", "fe80::1", "::ffff:169.254.1.1"] {
            assert!(is_link_local(ip(address)), "{address}");
        }
        for address in ["192.168.1.1", "fd00::1", "2001:db8::1"] {
            assert!(!is_link_local(ip(address)), "{address}");
        }
    }

    #[test]
    fn the_edges_of_each_blocked_range_are_exact() {
        for (inside, outside) in [
            ("172.31.255.255", "172.32.0.0"),
            ("100.127.255.255", "100.128.0.0"),
            ("198.19.255.255", "198.20.0.0"),
            ("168.63.129.16", "168.63.129.17"),
        ] {
            assert!(not_public(ip(inside)).is_some(), "{inside}");
            assert_eq!(not_public(ip(outside)), None, "{outside}");
        }
        assert!(not_public(ip("1fff:ffff::1")).is_some());
        assert_eq!(not_public(ip("3ffe::1")), None);
        assert!(not_public(ip("4000::1")).is_some());
    }
}
