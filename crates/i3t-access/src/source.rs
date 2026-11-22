//! 按什么算"同一个来源"：按来源限制会话数、连接数时用。

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// 一个来源：IPv4 是一个地址，IPv6 是一个 /64（一台主机通常拿到的就是一整段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SourceHost(IpAddr);

impl SourceHost {
    /// 回环上的来源是本机的程序，不按来源限制，返回 `None`。
    pub(crate) fn of(client: SocketAddr) -> Option<Self> {
        match client.ip().to_canonical() {
            ip if ip.is_loopback() => None,
            IpAddr::V4(ip) => Some(Self(IpAddr::V4(ip))),
            IpAddr::V6(ip) => {
                let [a, b, c, d, ..] = ip.segments();
                Some(Self(IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_is_an_ipv4_address_or_an_ipv6_slash_64_and_loopback_is_not_counted() {
        let of = |text: &str| SourceHost::of(text.parse().unwrap());
        assert_eq!(of("203.0.113.7:1000"), of("203.0.113.7:2000"));
        assert_ne!(of("203.0.113.7:1000"), of("203.0.113.8:1000"));
        assert_eq!(of("[2001:db8:1:2::1]:1000"), of("[2001:db8:1:2:ffff::9]:2000"), "同一个 /64");
        assert_ne!(of("[2001:db8:1:2::1]:1000"), of("[2001:db8:1:3::1]:1000"));
        assert_eq!(of("[::ffff:203.0.113.7]:1000"), of("203.0.113.7:1"), "双栈 socket 上的 IPv4 客户端按 IPv4 算");
        assert_eq!(of("127.0.0.1:1000"), None);
        assert_eq!(of("[::1]:1000"), None);
        assert_eq!(of("[::ffff:127.0.0.1]:1000"), None, "双栈 socket 上的本机程序");
    }
}
