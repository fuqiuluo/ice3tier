//! 虚拟网卡在一个节点上的状况：节点在上报里带着，controller 原样放进管理接口的节点详情，本机的状态接口也是它。
//!
//! 默认打开，所以没有装上时也报，用代码说清楚为什么（[`VnetCause`]），界面按自己的语言写。

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// 虚拟网卡的状况和这一路的计数。旧版本的节点不报。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VnetReport {
    #[serde(flatten)]
    pub state: VnetState,
    /// 程序添加的两条防火墙规则。虚拟网卡未启用或本机防火墙开关关闭时，两条均为 `off`。
    #[serde(default)]
    pub firewall: Firewall,
    /// 这次运行以来经虚拟网卡发给别的节点、从别的节点收进来（写进网卡）的包和字节（IP 包的长度）。
    #[serde(default)]
    pub sent_packets: u64,
    #[serde(default)]
    pub sent_bytes: u64,
    #[serde(default)]
    pub received_packets: u64,
    #[serde(default)]
    pub received_bytes: u64,
    /// 这次运行以来丢掉的包，按原因。
    #[serde(default)]
    pub dropped: VnetDrops,
}

/// 虚拟网卡装上了没有。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VnetState {
    /// 装好了：网卡 `device` 上是本节点的虚拟 IP，网络的地址段经它走，本机的程序直接用虚拟 IP 访问别的节点。
    Installed {
        /// 网卡的名字（`i3t0`）。
        device: String,
        mtu: u16,
        names: NameService,
    },
    /// 本机已关闭（配置文件中的 `[network] enabled`，或 `i3t set network off`）。
    Off,
    /// 本机已开启，但未能启用或运行中出错关闭；系统不残留配置，代理和端口转发不受影响。
    Failed { cause: VnetCause },
    /// 这个平台上没有（Linux、Windows、macOS 之外的）。
    Unsupported,
    /// 较新版本节点上报的未知状态。
    #[serde(other)]
    Unknown,
}

/// 虚拟网卡启用时，`<节点>.<网络的域名>` 的解析方式。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NameService {
    /// systemd-resolved 把网络的域名交给本节点的名字服务：本机的程序直接用名字就行。
    Resolved,
    /// 名称解析服务已运行（监听于本节点虚拟 IP 的 53 端口），但本机无 systemd-resolved：需通过 `i3t hosts` 写入 `/etc/hosts`，
    /// 或将本机解析器配置为把网络域名转发至该地址。
    NoResolver,
    /// 名称解析服务未能启动，或 systemd-resolved 拒绝配置；按虚拟 IP 访问仍正常可用。
    Failed { cause: VnetCause },
    #[serde(other)]
    Unknown,
}

/// 虚拟网卡及其组件（防火墙规则、名称解析服务）不可用的原因码，供界面按当前语言展示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum VnetCause {
    /// 节点进程缺这些能力：`CAP_NET_ADMIN`、`CAP_NET_BIND_SERVICE`（写法和 systemd 的 `AmbientCapabilities=` 一样）。
    NoPermission { missing: Vec<String> },
    /// 无法打开创建虚拟网卡所需的设备（Linux 上为 `/dev/net/tun`），`detail` 为系统返回的原始错误信息。容器环境常见，需挂载该设备。
    NoDevice { detail: String },
    /// 虚拟网卡创建或运行出错，`detail` 为系统返回的原始错误信息。
    DeviceFailed { detail: String },
    /// Windows：程序目录中缺少 Wintun 驱动文件（`wintun.dll`），`path` 为查找路径。
    DriverMissing { path: String },
    /// 系统里没有这个程序：`ip`（iproute2）、`nft`（nftables）、`iptables`。
    ProgramMissing { program: String },
    /// 一个程序报错退出，`detail` 是它的原话。
    CommandFailed { program: String, detail: String },
    /// 这个地址的端口被占着（名字服务的 53 端口）。
    PortInUse { address: SocketAddr },
    /// 因其他原因无法绑定该地址，`detail` 为系统返回的原始错误信息。
    BindFailed { address: SocketAddr, detail: String },
    /// 网络的地址段和这台机器所在的一个真实网络重叠，装上会把它从那个网络上切下来。`with` 是重叠的那个地址或者路由，
    /// 写法和 `ip` 一样：`192.168.1.5/24 dev eth0`、`10.0.0.0/8 dev tun0`。
    RangeInUse { with: String },
    /// 较新版本节点上报的未知原因。
    #[serde(other)]
    Unknown,
}

/// 程序加的两条防火墙规则（做法同 Tailscale）。本机一个开关（`[network] firewall`）关掉之后一条也不碰。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Firewall {
    /// 从虚拟网卡进来的放行：插在系统 INPUT 链的最前面（iptables），默认拒绝入站的防火墙因此不挡别的节点。
    /// 没有 `iptables` 的 Linux 上是 [`RuleState::NotNeeded`]。
    #[serde(default)]
    pub accept: RuleState,
    /// 自称来自网络地址段、却不是从虚拟网卡进来的包丢掉：在程序自己的一张 nftables 表里，不改用户的规则；
    /// 没有 `nft` 的 Linux 上是 `raw` 表 PREROUTING 链最前面的一条 iptables 规则。
    #[serde(default)]
    pub guard: RuleState,
}

/// 一条防火墙规则装上了没有。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RuleState {
    On,
    /// 未添加：本机开关已关闭，或虚拟网卡未启用。
    #[default]
    Off,
    /// 添加失败。虚拟网卡仍正常运行，相关流量策略由本机现有防火墙决定。
    Failed {
        cause: VnetCause,
    },
    /// 这个平台上程序不加这条规则：macOS 上两条都不加（不碰 pf）；Windows 上不加防冒充的那条（它默认按强主机模型收包）。
    Unsupported,
    /// 本机无需该规则，因此未添加。仅 Linux 的放行规则会出现此状态：该规则用于在 ufw 等防火墙通过 `iptables`
    /// 填充的 INPUT 链之前放行流量，无 `iptables` 的系统不存在此类链。若主机管理员自行配置了拦截入站的 nftables 规则集，
    /// 另一张表中的规则本身也无法绕过。
    NotNeeded,
    #[serde(other)]
    Unknown,
}

/// 丢掉的包，按原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VnetDrops {
    /// 对端发来的包，来源不是那个对端自己的虚拟 IP；或者它的 ICMP 差错报文说的是发往别处（不是它）的包。
    #[serde(default)]
    pub bad_source: u64,
    /// 对端发来的包，目的不是本节点的虚拟 IP；或者它的 ICMP 差错报文说的不是本节点发出的包。
    #[serde(default)]
    pub bad_destination: u64,
    /// 访问规则不允许对端访问本节点：它发起的新会话（TCP 的第一个握手包、ping 的请求、没有先例的 UDP 和别的协议）。
    /// 对端发来的 ICMP 重定向也算在这里。
    #[serde(default)]
    pub not_allowed: u64,
    /// 本机发出的数据包无法送达：目标为地址段内未分配地址、未启用虚拟网卡的节点、不可达节点，或等待建连时发送队列已满。
    #[serde(default)]
    pub unreachable: u64,
    /// 无法解析的数据包：非 IPv4、报文头无效、分片无法重组（重叠或长度不匹配），以及不应分片的报文（TCP、ICMP 差错报文）。
    #[serde(default)]
    pub malformed: u64,
}

impl VnetDrops {
    /// 全部加起来。
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.bad_source
            .saturating_add(self.bad_destination)
            .saturating_add(self.not_allowed)
            .saturating_add(self.unreachable)
            .saturating_add(self.malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Report;

    #[test]
    fn the_report_is_a_state_code_with_its_values_and_survives_newer_codes() {
        let installed = VnetReport {
            state: VnetState::Installed { device: "i3t0".into(), mtu: 1280, names: NameService::Resolved },
            firewall: Firewall { accept: RuleState::On, guard: RuleState::On },
            sent_packets: 3,
            sent_bytes: 300,
            received_packets: 2,
            received_bytes: 200,
            dropped: VnetDrops { not_allowed: 1, ..VnetDrops::default() },
        };
        let json = serde_json::to_value(&installed).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "state": "installed", "device": "i3t0", "mtu": 1280, "names": { "state": "resolved" },
                "firewall": { "accept": { "state": "on" }, "guard": { "state": "on" } },
                "sent_packets": 3, "sent_bytes": 300, "received_packets": 2, "received_bytes": 200,
                "dropped": { "bad_source": 0, "bad_destination": 0, "not_allowed": 1, "unreachable": 0, "malformed": 0 }
            })
        );
        assert_eq!(serde_json::from_value::<VnetReport>(json).unwrap(), installed);
        let without_iptables = Firewall { accept: RuleState::NotNeeded, guard: RuleState::On };
        let json = serde_json::to_value(&without_iptables).unwrap();
        assert_eq!(json, serde_json::json!({ "accept": { "state": "not_needed" }, "guard": { "state": "on" } }));
        assert_eq!(serde_json::from_value::<Firewall>(json).unwrap(), without_iptables);

        let failed = VnetState::Failed { cause: VnetCause::NoPermission { missing: vec!["CAP_NET_ADMIN".into()] } };
        let json = serde_json::to_value(&failed).unwrap();
        assert_eq!(json, serde_json::json!({ "state": "failed", "cause": { "code": "no_permission", "missing": ["CAP_NET_ADMIN"] } }));
        let overlap = VnetCause::RangeInUse { with: "192.168.1.5/24 dev eth0".into() };
        assert_eq!(
            serde_json::to_value(&overlap).unwrap(),
            serde_json::json!({ "code": "range_in_use", "with": "192.168.1.5/24 dev eth0" })
        );

        let newer: VnetReport = serde_json::from_value(serde_json::json!({ "state": "paused" })).unwrap();
        assert_eq!(newer.state, VnetState::Unknown);
        assert_eq!(newer.firewall, Firewall::default(), "没报规则的按关着");
        let newer: VnetReport = serde_json::from_value(serde_json::json!({
            "state": "failed", "cause": { "code": "solar_flare" }, "firewall": { "accept": { "state": "half" } }
        }))
        .unwrap();
        assert_eq!(newer.state, VnetState::Failed { cause: VnetCause::Unknown });
        assert_eq!(newer.firewall.accept, RuleState::Unknown);
        let older: Report = serde_json::from_value(serde_json::json!({ "intercept": { "state": "on" } })).unwrap();
        assert_eq!(older.vnet, None, "旧的节点不报；它报的透明访问没有人再看");
    }

    #[test]
    fn drops_add_up() {
        let drops = VnetDrops { bad_source: 1, bad_destination: 2, not_allowed: 3, unreachable: 4, malformed: 5 };
        assert_eq!(drops.total(), 15);
        assert_eq!(VnetDrops { malformed: u64::MAX, unreachable: 1, ..VnetDrops::default() }.total(), u64::MAX);
    }
}
