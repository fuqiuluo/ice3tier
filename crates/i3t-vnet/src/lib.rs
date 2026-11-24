//! 虚拟网卡：每个节点分配一块虚拟网卡，配置本节点的虚拟 IP 与网络网段路由。本机应用可直接通过虚拟 IP
//! 访问其他节点，体验与同一局域网一致：对端监听在 `0.0.0.0:8080` 的服务可通过 `<对端虚拟 IP>:8080` 访问，
//! ping 由对端主机内核直接响应，支持任意 IP 协议。
//!
//! 两个节点间的 IP 数据包作为不可靠数据报（`i3t_conn::Packets`）经现有连接传输，沿路径层选定的路由发送；
//! 若链路不支持 UDP，连接层会自动回退至 TCP 中转，本模块无需额外处理。不内置用户态协议栈，不维护 TCP 连接状态，也不依赖内核拦截规则。
//!
//! 系统级配置项：
//!
//! | 配置项 | 作用 |
//! |---|---|
//! | 虚拟网卡，默认 MTU 为 [`DEFAULT_MTU`]（本机可覆盖，范围见 [`MTU_RANGE`]）：Linux 为 TUN 设备（名称按 [`DEVICE_PATTERN`] 分配首个可用编号，通常为 `i3t0`），Windows 为 Wintun 适配器 `i3t0`，macOS 为 utun 设备（由系统分配编号） | 承载本节点虚拟 IP 及网络网段路由。均为非持久化设备：进程退出（含被强制终止）后，网卡及其地址和路由会自动移除 |
//! | Linux：系统 `INPUT` 链首条规则 `-i <网卡> -m comment --comment ice3tier -j ACCEPT`（使用 `iptables`；系统无 `iptables` 时无需添加）。Windows：限定在该虚拟网卡上的入站防火墙规则 `ice3tier-i3t0` | 放行来自虚拟网卡的入站流量，避免默认拒绝入站的防火墙（如 ufw、Windows “公用”网络配置文件）拦截其他节点流量 |
//! | Linux：nftables 表 `ip <网卡名>` 及其 `guard` 链；无 `nft` 时回退为 `raw` 表 `PREROUTING` 链前两条 `iptables` 规则 | 丢弃非经本虚拟网卡进入（回环接口除外）、且源地址属于虚拟网段或目的地址为本节点虚拟 IP 的数据包，防止同局域网主机伪造虚拟 IP 或利用 Linux 弱主机模型绕过访问规则。Windows 与 macOS 平台不添加，详见 [`plan`] |
//! | Linux：在虚拟网卡上配置的 systemd-resolved 路由域（若可用） | 仅将本网络域名下的 DNS 查询转发至本节点名称服务；配置仅存于内存，网卡销毁后自动清除。其他平台可通过 `i3t hosts` 写入 hosts 文件 |
//!
//! macOS 平台不修改任何防火墙规则（不操作 pf）。防火墙规则可通过 `[network] firewall` 开关整体禁用。所有自有配置均带有可识别标识
//! （表名、规则注释 [`COMMENT`] 或 Windows 规则名），不会影响其他规则；异常崩溃遗留的规则会在下次启动时覆盖清理，不会产生重复项。
//!
//! # 模块说明
//!
//! - [`device`]：虚拟网卡设备抽象与各平台适配层（[`device::Device`]）；
//! - [`engine`]：网卡与连接层之间的数据包转发引擎：地址校验、访问控制过滤、建连等待队列、分片重组及 ICMP 不可达应答；
//! - [`ipv4`]、[`filter`]、[`fragments`]、[`pieces`]：纯用户态数据包解析、过滤与分片重组逻辑，不涉及系统调用；
//! - [`plan`]：生成 `nft`、`iptables` 与 PowerShell 防火墙规则参数及脚本；[`survey`]：探测系统中现有的自有防火墙配置；
//! - [`setup`]：防火墙与解析器配置的安装、卸载及遗留项清理；[`legacy`]：清理旧版透明代理模式遗留的系统配置；
//! - [`machine`]：外部命令执行与进程权限检测抽象；
//! - [`overlap`]：检测虚拟网段是否与本机已有真实网络重叠（重叠时拒绝启用）；
//! - [`names`]：内置 DNS 应答与 `/etc/hosts` 区块管理。

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

/// 创建虚拟网卡时传入内核的名称模板。`%d` 由内核替换为首个未占用的编号：通常为 `i3t0`，同一主机运行多个节点
/// （加入不同网络）时依次为 `i3t1` 等。
pub const DEVICE_PATTERN: &str = "i3t%d";

/// 虚拟网卡名称前缀。仅名称为该前缀加数字编号的网卡与 nftables 表，以及注释为 [`COMMENT`] 的规则归属本程序管理。
pub const DEVICE_PREFIX: &str = "i3t";

/// 虚拟网卡默认 MTU（未显式配置时使用）。网络级默认值由 `i3t_model::netmap::Network::vnet_mtu` 定义，
/// 单机可通过配置文件 `[network] mtu` 或 `i3t set mtu` 覆盖；两处共享模型中的同一套默认值与范围定义。
///
/// 每个 IP 数据包对应连接层的一个数据报。连接刚建立时单个数据报上限约为 1100 余字节，完成路径 MTU 探测后（上限 1400 字节）
/// 约为 1300 余字节：1280 字节的数据包在探测完成前拆分为两片传输（[`pieces`]），探测完成后可整包传输。更小的 MTU 虽可免除分片，
/// 但单包有效载荷约减少一成。选择 1280 同时满足 IPv6 最小链路 MTU 要求，便于后续平滑扩展 IPv6 地址。
/// 应用层无需感知：两端内核会自动按该 MTU 协商 TCP MSS，超长数据包由内核自行分片或返回“需要分片”。
pub const DEFAULT_MTU: u16 = i3t_model::netmap::DEFAULT_VNET_MTU;

/// 虚拟网卡允许配置的 MTU 范围。通信两端配置不同的 MTU 仍可互通（TCP 按较小值协商分段长度）。
///
/// 下限为 IPv4 规范要求主机必须接收的最小包长（Windows 同样限制 IPv4 网卡 MTU 不得低于此值）；上限为以太网标准 1500 字节：
/// 单包最多拆分为两片，连接最小数据报容量约 1100 余字节，两片合计超过 2300 字节，1500 字节以内的包均可完整送达；
/// 若继续增大则可能出现无法发送的数据包，且超过约 1300 字节后每个满载包均需拆分，反而降低吞吐。
pub const MTU_RANGE: std::ops::RangeInclusive<u16> = i3t_model::netmap::VNET_MTU;

/// 本程序添加的 iptables 规则注释标识，用于识别自有规则（配合 `-i <网卡>`，或 `raw` 表防伪造规则的 `! -i <网卡>`）。
pub const COMMENT: &str = "ice3tier";

/// 名称解析服务监听端口（绑定于本节点虚拟 IP）。
pub const DNS_PORT: u16 = 53;

/// 判断 `name` 是否符合本程序创建的虚拟网卡命名规则：[`DEVICE_PREFIX`] 后跟纯数字。
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
