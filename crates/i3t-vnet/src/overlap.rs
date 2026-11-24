//! 检测虚拟网络网段是否与本机当前所处的真实网络重叠。
//!
//! 启用虚拟网卡后，网络网段路由将指向该网卡，且防伪造规则会丢弃从物理网卡进入、源地址属于该网段的数据包。
//! 若本机原本位于与虚拟网段重叠的真实网络（如局域网、云 VPC、容器网桥或其他组网工具），启用后可能导致本机失联甚至中断 SSH 会话。
//! 因此启用前会先检查本机网卡地址及 `main` 路由表是否与虚拟网段冲突。默认路由（包括 VPN 常用的对半拆分写法 `0.0.0.0/1`
//! 与 `128.0.0.0/1`）以及本节点自身虚拟网卡上的地址和路由不计为重叠。
//!
//! 作为安全保护机制，若无法读取或解析系统网络信息，按检查失败拒绝安装处理，而不默认视为无重叠。

use std::io;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde_json::Value;

use crate::device::Platform;
use crate::machine::{CommandError, Machine, Program};

/// 检查 `cidr` 是否与本机已有地址或路由重叠；无冲突时返回 `None`，冲突时返回类似 `ip` 风格的描述（如 `192.168.1.5/24 dev eth0`）。
/// `own` 为本节点当前已创建的虚拟网卡名称，其上的地址与路由会被排除。
///
/// 所有平台均检查本机接口地址与前缀；Linux 额外通过 `ip -j route` 检查主路由表（若无 `ip` 命令则跳过路由检查）。
///
/// # Errors
///
/// 无法获取本机接口地址，或无法执行/解析 `ip` 命令输出时返回错误。
pub fn find(machine: &mut impl Machine, platform: Platform, cidr: Ipv4Net, own: Option<&str>) -> Result<Option<String>, CommandError> {
    let interfaces = interfaces()
        .map_err(|error| CommandError::Io { program: Program::Ip, detail: format!("无法读取本机网卡地址：{error}") })?;
    if let Some(found) = addresses_overlapping(&interfaces, cidr, own) {
        return Ok(Some(found));
    }
    if platform != Platform::Linux {
        return Ok(None);
    }
    match machine.run(Program::Ip, &args(&["-j", "-4", "route", "show", "table", "main"]), None) {
        Ok(routes) => Ok(routes_overlapping(&listing(&routes)?, cidr, own)),
        Err(CommandError::Missing(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// 读取本机各网络接口的 IPv4 地址及网段前缀。
fn interfaces() -> io::Result<Vec<(String, Ipv4Net)>> {
    let found = if_addrs::get_if_addrs()?.into_iter().filter_map(|interface| match interface.addr {
        if_addrs::IfAddr::V4(v4) => Ipv4Net::new(v4.ip, v4.prefixlen).ok().map(|net| (interface.name, net)),
        if_addrs::IfAddr::V6(_) => None,
    });
    Ok(found.collect())
}

/// 解析 `ip -j` 输出的 JSON 数组；解析失败时按命令失败处理，确保无法确认安全时不继续启用网卡。
fn listing(json: &str) -> Result<Vec<Value>, CommandError> {
    serde_json::from_str(json).map_err(|error| CommandError::Failed {
        program: Program::Ip,
        status: None,
        detail: format!("无法解析 ip 命令输出：{error}"),
    })
}

/// 视为全网默认路由而非特定子网的最大前缀长度：涵盖默认路由及其对半拆分写法（`/1`）。
const CATCH_ALL_PREFIX: u8 = 1;

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// 判断两个 IPv4 网段是否存在地址交集。
fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// 返回首个与 `cidr` 重叠的非回环接口地址描述（排除 `own`）。
fn addresses_overlapping(interfaces: &[(String, Ipv4Net)], cidr: Ipv4Net, own: Option<&str>) -> Option<String> {
    interfaces
        .iter()
        .filter(|(name, net)| own != Some(name.as_str()) && !net.addr().is_loopback())
        .find(|(_, net)| overlaps(net.trunc(), cidr))
        .map(|(name, net)| format!("{net} dev {name}"))
}

/// 返回 `ip -j -4 route show table main` 输出中首条与 `cidr` 重叠的路由（排除默认路由及经由 `own` 的路由）。
fn routes_overlapping(routes: &[Value], cidr: Ipv4Net, own: Option<&str>) -> Option<String> {
    routes.iter().find_map(|route| {
        let dev = route.get("dev").and_then(Value::as_str);
        let dst = route.get("dst")?.as_str()?;
        if dst == "default" || (own.is_some() && dev == own) {
            return None;
        }
        // 主机路由不带前缀长度，解析为 `/32`。
        let net: Ipv4Net = dst.parse().or_else(|_| dst.parse::<Ipv4Addr>().map(Ipv4Net::from)).ok()?;
        if net.prefix_len() <= CATCH_ALL_PREFIX || !overlaps(net, cidr) {
            return None;
        }
        let mut words: Vec<&str> = Vec::new();
        words.extend(route.get("type").and_then(Value::as_str));
        words.push(dst);
        if let Some(dev) = dev {
            words.extend(["dev", dev]);
        }
        Some(words.join(" "))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // iproute2 6.17 在一个网络命名空间里真的输出：up0 是上网的网卡，lan0 在一个和覆盖网重叠的局域网里，i3t0 是自己的。
    const ROUTES: &str = r#"[{"dst":"default","gateway":"11.0.0.5","dev":"up0","flags":[]},{"dst":"10.66.200.0/24","dev":"lan0","protocol":"kernel","scope":"link","prefsrc":"10.66.200.1","flags":[]},{"dst":"10.67.0.0/16","gateway":"11.0.0.5","dev":"up0","flags":[]},{"type":"blackhole","dst":"10.68.1.0/24","flags":[]},{"dst":"11.0.0.4/30","dev":"up0","protocol":"kernel","scope":"link","prefsrc":"11.0.0.6","flags":[]}]"#;

    fn net(text: &str) -> Ipv4Net {
        text.parse().unwrap()
    }

    fn interfaces() -> Vec<(String, Ipv4Net)> {
        [("lo", "127.0.0.1/8"), ("up0", "11.0.0.6/30"), ("lan0", "10.66.200.1/24"), ("i3t0", "10.66.0.1/16")]
            .into_iter()
            .map(|(name, net)| (name.to_owned(), net.parse().unwrap()))
            .collect()
    }

    #[test]
    fn an_address_on_another_interface_inside_the_range_is_found() {
        let found = |cidr: &str| addresses_overlapping(&interfaces(), net(cidr), Some("i3t0"));
        assert_eq!(found("10.66.0.0/16").as_deref(), Some("10.66.200.1/24 dev lan0"));
        assert_eq!(found("10.0.0.0/8").as_deref(), Some("10.66.200.1/24 dev lan0"), "地址段包住网卡的网段");
        assert_eq!(found("10.66.200.128/25").as_deref(), Some("10.66.200.1/24 dev lan0"), "网卡的网段包住地址段");
        assert_eq!(found("10.70.0.0/16"), None);
        assert_eq!(found("10.66.0.0/24"), None, "只有自己的网卡在里面");
        assert_eq!(found("127.0.0.0/16"), None, "回环不算");
        assert_eq!(
            addresses_overlapping(&interfaces(), net("10.66.0.0/24"), None).as_deref(),
            Some("10.66.0.1/16 dev i3t0"),
            "还没有自己的网卡时，叫这个名字的网卡是别人的（另一个节点程序，同一个地址段）"
        );
    }

    #[test]
    fn the_real_interfaces_can_be_read() {
        assert!(super::interfaces().unwrap().iter().any(|(_, net)| net.addr().is_loopback()), "至少有回环");
    }

    #[test]
    fn routes_inside_or_around_the_range_are_found_but_not_the_default_route() {
        let found = |json: &str, cidr: &str| routes_overlapping(&listing(json).unwrap(), net(cidr), Some("i3t0"));
        assert_eq!(found(ROUTES, "10.67.0.0/16").as_deref(), Some("10.67.0.0/16 dev up0"));
        assert_eq!(found(ROUTES, "10.68.0.0/16").as_deref(), Some("blackhole 10.68.1.0/24"));
        assert_eq!(found(ROUTES, "10.70.0.0/16"), None, "默认路由不算");
        let host_route = r#"[{"dst":"10.71.0.9","dev":"tun0","scope":"link"},{"dst":"10.66.0.0/16","dev":"i3t0"}]"#;
        assert_eq!(found(host_route, "10.71.0.0/16").as_deref(), Some("10.71.0.9 dev tun0"), "没有前缀长度的是一个地址");
        assert_eq!(found(host_route, "10.66.0.0/16"), None, "经自己的网卡的不算");
        assert_eq!(
            routes_overlapping(&listing(host_route).unwrap(), net("10.66.0.0/16"), None).as_deref(),
            Some("10.66.0.0/16 dev i3t0"),
            "别人的同名网卡上的路由算"
        );
    }

    #[test]
    fn a_default_route_split_in_two_halves_is_not_a_network() {
        // VPN 常见的写法：不动原来的默认路由，另加两条各管一半的。
        let halves = r#"[{"dst":"0.0.0.0/1","dev":"tun0"},{"dst":"128.0.0.0/1","dev":"tun0"},{"dst":"default","dev":"eth0"}]"#;
        assert_eq!(routes_overlapping(&listing(halves).unwrap(), net("10.66.0.0/16"), None), None);
        let quarter = r#"[{"dst":"0.0.0.0/2","dev":"tun0"}]"#;
        assert_eq!(routes_overlapping(&listing(quarter).unwrap(), net("10.66.0.0/16"), None).as_deref(), Some("0.0.0.0/2 dev tun0"));
    }

    #[test]
    fn an_answer_that_cannot_be_read_is_an_error_not_a_clean_bill() {
        assert!(matches!(listing("Object \"-j\" is unknown, try \"ip help\"."), Err(CommandError::Failed { .. })));
        assert!(matches!(listing("{}"), Err(CommandError::Failed { .. })), "不是数组");
        assert_eq!(listing("[]").unwrap(), Vec::<Value>::new());
    }
}
