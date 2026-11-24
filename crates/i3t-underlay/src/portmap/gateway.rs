//! 默认路由的网关，以及本机朝着它的那个地址。

use std::net::Ipv4Addr;

/// 默认路由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DefaultRoute {
    pub(super) gateway: Ipv4Addr,
    /// 本机在默认路由那块网卡上的地址，网关把映射转到这里。
    pub(super) local: Ipv4Addr,
}

/// 读取系统的默认路由。没有默认路由或网关没有 IPv4 地址时返回 `None`。
///
/// 枚举网络接口和查询路由表会阻塞，异步调用方应通过 `spawn_blocking` 执行。
pub(super) fn default_route() -> Option<DefaultRoute> {
    let interface = match netdev::get_default_interface() {
        Ok(interface) => interface,
        Err(error) => {
            tracing::debug!(error, "无法确定默认路由的网络接口，跳过端口映射");
            return None;
        }
    };
    let gateway = *interface.gateway.as_ref()?.ipv4.first()?;
    // 一块网卡上可以有几个地址，取和网关在同一个网段的那个。
    let same_subnet = interface.ipv4.iter().find(|net| net.contains(&gateway));
    let local = same_subnet.or(interface.ipv4.first())?.addr();
    Some(DefaultRoute { gateway, local })
}

/// 判断本机地址是否需要端口映射。公网地址已可直接访问，无需映射；回环和链路本地地址之后没有网关。
///
/// 运营商级 NAT 地址段（100.64.0.0/10）也纳入映射范围：PCP 本身即面向该场景设计。
pub(super) fn needs_mapping(local: Ipv4Addr) -> bool {
    let [first, second, ..] = local.octets();
    local.is_private() || (first == 100 && second & 0xc0 == 64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_addresses_behind_a_translator_need_a_mapping() {
        for local in ["192.168.1.5", "10.0.0.2", "172.16.3.4", "100.64.0.9", "100.127.255.254"] {
            assert!(needs_mapping(local.parse().unwrap()), "{local}");
        }
        for local in ["203.0.113.7", "8.8.8.8", "100.128.0.1", "100.63.0.1", "127.0.0.1", "169.254.1.2", "0.0.0.0"] {
            assert!(!needs_mapping(local.parse().unwrap()), "{local}");
        }
    }

    #[test]
    fn reading_the_default_route_never_panics() {
        // 测试机器上有没有默认路由都可以，有的话两个地址都得是能用的。
        if let Some(route) = default_route() {
            assert!(!route.gateway.is_unspecified() && !route.local.is_unspecified());
        }
    }
}
