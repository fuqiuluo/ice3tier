//! 虚拟网卡：每个节点一块，上面是本节点的虚拟 IP，网络的地址段经它走。本机的程序因此用虚拟 IP
//! 访问别的节点，像一个局域网里的机器：别的节点上监听 `0.0.0.0:8080` 的服务在 `<它的虚拟 IP>:8080` 上，ping 由那台机器自己的内核回答，
//! 什么 IP 协议都行。
//!
//! 一个 IP 包在两个节点之间是这一对已有的那条连接上的一个不保证送达的数据报（`i3t_conn::Packets`），走路径层选的路；
//! 没有 UDP 的路上连接自己经 TCP 中转，这里什么都不多做。不带用户态的协议栈，不为 TCP 连接记状态，不用内核规则拦截。
//!
//! 装进系统里的东西：
//!
//! | 东西 | 做什么 |
//! |---|---|
//! | 虚拟网卡，MTU 默认 [`DEFAULT_MTU`]（本机可以改，见 [`MTU_RANGE`]）：Linux 上是一块 TUN（名字是 [`DEVICE_PATTERN`] 里第一个没人用的，通常是 `i3t0`），Windows 上是 Wintun 的适配器 `i3t0`，macOS 上是一块 utun（系统挑编号） | 本节点的虚拟 IP 和网络的地址段（因此有一条"地址段走它"的路由）。不是持久的：进程一退出（包括被杀掉）它就连同地址和路由一起没了 |
//! | Linux：系统 INPUT 链最前面一条 `-i <网卡> -m comment --comment ice3tier -j ACCEPT`（`iptables`；没有 `iptables` 的机器上用不着，不加）。Windows：Windows 防火墙里限定在这块网卡上的入站规则 `ice3tier-i3t0` | 从网卡进来的放行：默认拒绝入站的防火墙（ufw 之类、Windows 的"公用"网络）因此不把别的节点挡在外面 |
//! | Linux：nftables 的表 `ip <网卡名>`，一条链 `guard`；没有 `nft` 时是 `raw` 表 PREROUTING 链最前面的两条 `iptables` 规则 | 不是从这块网卡进来的包（回环除外），自称来自网络地址段的丢掉，要去本节点虚拟 IP 的也丢掉：同一个局域网里的机器冒充不了虚拟 IP，也不能把虚拟 IP 指到这台机器、绕过访问规则直接连上去（Linux 按弱主机模型收包）。Windows 和 macOS 上不加，见 [`plan`] |
//! | Linux：systemd-resolved 在网卡上的设置（有它时） | 只有网络的域名下的查询发给本节点的名字服务；只在内存里，网卡一删就没了。别的平台上名字用 `i3t hosts` |
//!
//! macOS 上程序不加任何防火墙规则（不碰 pf）。防火墙规则一个开关就能完全不碰（`[network] firewall`）。每一样都认得出是自己的
//! （表名、规则的注释 [`COMMENT`]、Windows 上规则的名字），别的东西一概不碰；崩溃留下的规则下次启动时被换掉，不会多一份。
//!
//! # 模块
//!
//! - [`device`]：网卡本身，平台之间的接缝（[`device::Device`]）；
//! - [`engine`]：网卡和连接之间搬包：核对、按包的访问规则、等连接时的小队列、切片和拼片、ICMP 的"不可达"；
//! - [`ipv4`]、[`filter`]、[`fragments`]、[`pieces`]：上面要用的几样，都不碰系统；
//! - [`plan`]：要装的规则写成 `nft`、`iptables` 的参数和脚本、PowerShell 的脚本；[`survey`]：读回系统里现在有的、属于自己的东西；
//! - [`setup`]：装、拆，和遇到上次留下的东西时怎么办；[`legacy`]：去掉以前的透明访问留下的东西；
//! - [`machine`]：和系统之间的接缝（执行程序，看本进程有没有需要的能力）；
//! - [`overlap`]：网络的地址段和这台机器所在的真实网络重不重叠（重叠时不装）；
//! - [`names`]：名字服务的应答，和 `/etc/hosts` 里的一段。

mod bundle;
pub mod device;
pub mod engine;
pub mod filter;
pub mod fragments;
pub mod ipv4;
pub mod legacy;
pub mod machine;
pub mod names;
pub mod overlap;
pub mod pieces;
pub mod plan;
pub mod setup;
pub mod survey;

pub use machine::{Capability, CommandError, Machine, Program};
pub use plan::Plan;
pub use survey::Survey;

/// 建网卡时给内核的名字。`%d` 由内核换成第一个没人用的编号：通常是 `i3t0`，同一台机器上跑着两个节点程序
/// （进两个网络）时第二个是 `i3t1`。
pub const DEVICE_PATTERN: &str = "i3t%d";

/// 网卡名字的前缀。名字是它加上编号的网卡、表，和注释是 [`COMMENT`] 的规则，才是自己的。
pub const DEVICE_PREFIX: &str = "i3t";

/// 网卡的 MTU，没有另外设时用的（配置文件的 `[network] mtu`，`i3t set mtu`）。
///
/// 一个 IP 包是连接上的一个数据报。连接刚建立时一个数据报只装得下一千一百多字节，路径 MTU 探测之后（最多 1400 字节的包）
/// 是一千三百多：1280 的包在探测完之前切成两片（[`pieces`]），之后整个装得下。比它小的 MTU 不用切，但每个包少带一成的数据，
/// 吞吐的量法和数在内部的测量记录里。取 1280 也因为 IPv6 要求链路至少送得了这么大的包：以后网卡上有 IPv6 的地址时不用改。
/// 应用不用管：两端的内核按它定 TCP 的分段长度，比它大的包内核自己切或者回"太大"。
pub const DEFAULT_MTU: u16 = 1280;

/// 网卡的 MTU 可以设成的值。两个节点设得不一样也通：TCP 按小的一头定分段长度。
///
/// 下限是 IPv4 要求每台主机都收得了的包长（Windows 也不让 IPv4 的网卡比它小）。上限是以太网的 1500：一个包最多切成两片，
/// 连接上最小的数据报装得下一千一百多字节，两片是两千三百多，1500 以内的包怎么都送得到；再大就有送不到的包，
/// 而且超过一千三百多之后每个满包都要切，只会更慢。
pub const MTU_RANGE: std::ops::RangeInclusive<u16> = 576..=1500;

/// 程序加的 iptables 规则的注释，认自己的规则靠它（加上 `-i <网卡>`，raw 表里防冒充的那条是 `! -i <网卡>`）。
pub const COMMENT: &str = "ice3tier";

/// 名字服务的端口，在本节点自己的虚拟 IP 上。
pub const DNS_PORT: u16 = 53;

/// `name` 是不是这个程序会建的网卡名：[`DEVICE_PREFIX`] 加上一串数字。
#[must_use]
pub fn is_device_name(name: &str) -> bool {
    name.strip_prefix(DEVICE_PREFIX).is_some_and(|number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_prefix_followed_by_digits_is_one_of_our_device_names() {
        assert!(is_device_name("i3t0"));
        assert!(is_device_name("i3t12"));
        assert!(!is_device_name("i3t"), "以前的透明访问的表名，没有编号");
        assert!(!is_device_name("i3t0x"));
        assert!(!is_device_name("eth0"));
        assert!(!is_device_name("xi3t0"));
    }
}
