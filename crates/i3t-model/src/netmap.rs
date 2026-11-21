//! netmap：一个节点运行所需要的全部配置。
//!
//! controller 按最小权限为每个节点单独算一份：只有它能访问或者能访问它的对端，只有它自己的代理和端口转发。
//! 节点不需要知道标签和访问规则，它拿到的是编译之后的结果（每个对端上的 [`Peer::inbound`] 和 [`Peer::outbound`]）。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use i3t_proto::flow::Class;
use i3t_proto::{NodeId, PublicKey};
use ipnet::{IpNet, Ipv4Net};
use ring::digest;
use serde::{Deserialize, Serialize};

/// 一个节点的完整配置。版本号每次变更加一，节点用它确认自己应用到了哪一版。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Netmap {
    pub version: u64,
    pub network: Network,
    /// 本节点自己。
    pub me: LocalNode,
    /// 和本节点有访问关系的对端。没有被任何访问规则连通的节点不在这里。
    #[serde(default)]
    pub peers: Vec<Peer>,
    /// 网络里全部启用了的 relay，不受访问规则限制。一个 relay 同时是对端时，两个列表里都有它。
    #[serde(default)]
    pub relays: Vec<Relay>,
    /// 只有本节点启用为 relay 时才有：网络里全部节点的编号和公钥，用来认证中转会话。
    #[serde(default)]
    pub relay_clients: Vec<RelayClient>,
    /// `peers` 里说自己没有装虚拟网卡的那些（关着、没有权限、地址段重叠，或者是不懂虚拟网卡的旧版本），按编号排。
    /// 本机的程序发给它们的包当场回"主机不可达"，不白等。controller 还不知道的（这次启动以来没有报过、旧的 controller）不在里面：
    /// 包照发，对端没有网卡就是收不到。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub no_vnet: Vec<NodeId>,
}

impl Netmap {
    #[must_use]
    pub fn peer(&self, id: NodeId) -> Option<&Peer> {
        self.peers.iter().find(|peer| peer.id == id)
    }

    #[must_use]
    pub fn relay(&self, id: NodeId) -> Option<&Relay> {
        self.relays.iter().find(|relay| relay.id == id)
    }

    /// 一个节点的名字，用来把路上的 relay 写成名字：先找 relay 列表，再找对端，最后是本节点自己。
    /// relay 不一定是对端（访问规则没有连通它们），也可能是本节点自己；哪里都没有时是 `None`，显示时写编号。
    /// 显示路的地方（`i3t routes`、`i3t status`、`i3t ping`、流结束的日志）都用它。
    #[must_use]
    pub fn node_name(&self, id: NodeId) -> Option<&str> {
        let name = self.relay(id).map(|relay| &relay.name).or_else(|| self.peer(id).map(|peer| &peer.name));
        name.or_else(|| (self.me.id == id).then_some(&self.me.name)).map(String::as_str)
    }

    /// 按虚拟 IP 找对端。
    #[must_use]
    pub fn peer_by_ip(&self, ip: Ipv4Addr) -> Option<&Peer> {
        self.peers.iter().find(|peer| peer.virtual_ip == ip)
    }

    /// 按名字找对端。`name` 可以是短名字（`nas-01`），也可以是全名（`nas-01.<网络的域名后缀>`），不区分大小写。
    #[must_use]
    pub fn peer_by_name(&self, name: &str) -> Option<&Peer> {
        let short = self.network.short_name(name);
        self.peers.iter().find(|peer| peer.name.eq_ignore_ascii_case(short))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub name: String,
    /// 节点全名的后缀，例如 `home.i3t`：节点 `nas-01` 的全名是 `nas-01.home.i3t`。
    pub domain: String,
    /// 虚拟地址段。落在这一段里的目标一律是组网目标，不会被当成互联网目标交给出口。
    pub cidr: Ipv4Net,
    #[serde(default)]
    pub routing: RoutingMode,
    /// 一条路径最多经过几个 relay。
    #[serde(default = "default_max_relay_hops")]
    pub max_relay_hops: u8,
    #[serde(default)]
    pub reach: Reach,
    /// 网络的默认服务等级：代理、端口转发、出口都没有指定等级时用它；没有值时是 `auto`。
    #[serde(default)]
    pub class: Option<Class>,
    /// 节点之间的连接上，请对端攒到多于这么多个包才单独发一个确认包；这期间它有别的包要发，确认就搭在里面。
    /// 旧的 controller 不发这一项，读成 [`DEFAULT_ACK_ELICITING_THRESHOLD`]。
    #[serde(default = "default_ack_eliciting_threshold")]
    pub ack_eliciting_threshold: u32,
    /// 没攒够时，对端最多等多少毫秒就发确认。旧的 controller 不发这一项，读成 [`DEFAULT_MAX_ACK_DELAY_MS`]。
    #[serde(default = "default_max_ack_delay_ms")]
    pub max_ack_delay_ms: u32,
}

impl Network {
    /// 去掉全名里的域名后缀；本来就是短名字时原样返回。
    #[must_use]
    pub fn short_name<'a>(&self, name: &'a str) -> &'a str {
        let name = name.strip_suffix('.').unwrap_or(name);
        let Some(split) = name.len().checked_sub(self.domain.len() + 1) else { return name };
        match name.split_at_checked(split) {
            Some((short, rest)) if rest.strip_prefix('.').is_some_and(|domain| domain.eq_ignore_ascii_case(&self.domain)) => short,
            _ => name,
        }
    }

    /// 一个地址是不是落在网络的虚拟地址段里。
    #[must_use]
    pub fn is_overlay_address(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.cidr.contains(&v4),
            IpAddr::V6(_) => false,
        }
    }
}

pub(crate) const fn default_max_relay_hops() -> u8 {
    2
}

/// [`Network::ack_eliciting_threshold`] 的默认值。
///
/// QUIC 库自己的做法是每收到两个包就单独回一个确认包。虚拟网卡上跑着 TCP 时，回程本来就有里面那条连接自己的确认要送，
/// 再加上这些单独的确认包，回程的包数翻了一倍；回程按包数限速的线路上，能送过去的数据因此只有一半。
/// 取 10 之后回程只剩里面的确认，实测吞吐翻倍，小包的往返延迟不变；回程没有包可搭的单向流量，
/// 确认包从每两个包一个降到每十来个包一个。
pub const DEFAULT_ACK_ELICITING_THRESHOLD: u32 = 10;

/// [`Network::max_ack_delay_ms`] 的默认值。
///
/// 要小：发送方的窗口里装不下 [`Network::ack_eliciting_threshold`] 那么多个包时，对端永远攒不够，每一轮都要等满这么久才有确认。
/// 实测等 25 毫秒、阈值又超过窗口时，单向流量丢掉两成到九成；等 2 毫秒时不丢。
pub const DEFAULT_MAX_ACK_DELAY_MS: u32 = 2;

pub(crate) const fn default_ack_eliciting_threshold() -> u32 {
    DEFAULT_ACK_ELICITING_THRESHOLD
}

pub(crate) const fn default_max_ack_delay_ms() -> u32 {
    DEFAULT_MAX_ACK_DELAY_MS
}

/// 选路模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// 直连可用就走直连；否则只经一个 relay，取离目的节点最近的。
    #[default]
    DirectFirst,
    /// 直连和各条 relay 路径按实测代价比较，取最低的。
    LowestCost,
}

/// 对可用路径的限制，和选路模式无关。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    #[default]
    Any,
    /// 不使用 relay。
    DirectOnly,
    /// 不建立直连，不向对端暴露公网地址。
    RelayOnly,
}

/// 本节点自己的配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalNode {
    pub id: NodeId,
    pub name: String,
    pub virtual_ip: Ipv4Addr,
    /// 覆盖网络的默认选路模式。
    #[serde(default)]
    pub routing: Option<RoutingMode>,
    #[serde(default)]
    pub reach: Option<Reach>,
    /// 只主动连接：不接受别人主动发来的连接，不参与打洞。
    #[serde(default)]
    pub dial_out_only: bool,
    /// 启用为 relay 时有值。没有值时本节点不转发任何包。
    #[serde(default)]
    pub relay: Option<RelayRole>,
    /// 启用为出口时有值。没有值时本节点拒绝一切目标在本机之外的建流请求（下发给它的端口转发除外）。
    #[serde(default)]
    pub exit: Option<ExitRole>,
    /// 本节点上的代理。比这一版旧的 netmap 里的 `listeners` 和 `credentials` 不再认：它们说的是去掉了的写法。
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    /// 本节点负责监听的端口转发。
    #[serde(default)]
    pub forwards: Vec<Forward>,
    /// 本节点作为目标的端口转发。只有这里列出的地址，本节点才替别人去连。
    #[serde(default)]
    pub forward_targets: Vec<ForwardTarget>,
    /// 管理员固定的挂靠 relay；空表示自己挑延迟最低的。
    #[serde(default)]
    pub pinned_relays: Vec<NodeId>,
    /// 管理员给这个节点选的性能档位；没有值时节点用本机配置文件里的。比本程序新的 controller 下发了这里不认识的档位时
    /// 也读成没有值。
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "tolerant_profile")]
    pub profile: Option<Profile>,
    /// 除了自己按延迟挑的之外还要挂靠的 relay：有的对端连不上本节点挑的那几个、本节点也连不上它们挂靠的，
    /// controller 按各节点上报的"连得上哪些 relay"找一个两边都连得上的，让两边都挂上去。最多 [`MAX_SHARED_RELAYS`] 个。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_relays: Vec<NodeId>,
}

/// [`LocalNode::shared_relays`] 最多几个：加上自己挑的两个，一个节点同时保持的中转会话不超过六个。
pub const MAX_SHARED_RELAYS: usize = 4;

/// 性能档位：一组预设，节点按它定线程数、缓冲和空闲回收的时间。各项的值在节点上定（`i3t-agent`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// 低占用：给一个核、几百 MB 内存的机器长期运行。
    LowFootprint,
    /// 默认。
    #[default]
    Balanced,
    /// 高速度：流量大、对端多的机器。
    HighThroughput,
}

impl Profile {
    pub const ALL: [Self; 3] = [Self::LowFootprint, Self::Balanced, Self::HighThroughput];

    /// 在 netmap 和管理接口里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LowFootprint => "low_footprint",
            Self::Balanced => "balanced",
            Self::HighThroughput => "high_throughput",
        }
    }

    /// 在配置文件和命令行里的写法。
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            Self::LowFootprint => "low-footprint",
            Self::Balanced => "balanced",
            Self::HighThroughput => "high-throughput",
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 两种写法都认：`low_footprint`（JSON）和 `low-footprint`（配置文件、命令行）。
impl FromStr for Profile {
    type Err = UnknownProfile;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.into_iter().find(|profile| profile.as_str() == s || profile.spelling() == s).ok_or_else(|| UnknownProfile(s.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("不认识的性能档位 {0:?}：可以是 low-footprint、balanced、high-throughput")]
pub struct UnknownProfile(pub String);

/// netmap 里的档位：不认识的值读成没有值，不让整份 netmap 因为一个新的档位而读不了。
fn tolerant_profile<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Profile>, D::Error> {
    let text = Option::<String>::deserialize(deserializer)?;
    Ok(text.and_then(|text| text.parse().ok()))
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RelayRole {
    /// 转发的带宽上限；没有值表示不限。
    #[serde(default)]
    pub bandwidth_mbps: Option<u32>,
}

/// 出口的设置：netmap 里本节点的出口角色，也是管理接口里出口的设置（`PUT …/exit`）和 controller 存着的那一份。
///
/// 出口没有带宽上限。早先的 `bandwidth_mbps` 照收，没有作用（不认识的字段一律忽略）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitRole {
    /// 互联网目标允许的端口。没有值（默认）表示不限制；写了列表就只允许这些。局域网目标不受它限制。
    /// 不管端口一律不连的地址（私有、回环、链路本地、运营商级 NAT、云平台元数据、节点和覆盖网的地址）照样不连。
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    /// 允许把流送往本机网卡直连的网段。
    #[serde(default)]
    pub lan: bool,
    /// 把流交给本机配置的一个 SOCKS5 代理去连目标，而不是自己直接连。
    #[serde(default)]
    pub upstream_socks5: Option<SocketAddr>,
    /// 每个账期的流量配额，单位字节；没有值表示不限。算的是出口替别人搬运的互联网和局域网目标的流量，
    /// 两个方向相加，流和数据报都算。用完之后新的请求被拒绝，正在搬运的流被断开，直到下一个账期。
    #[serde(default)]
    pub quota_bytes: Option<u64>,
    /// 账期从每个月的哪一天开始（UTC 的 0 点），1 到 28。
    #[serde(default = "default_quota_reset_day")]
    pub quota_reset_day: u8,
    /// 互联网目标只连哪一种地址。域名解析出来的地址里只取这一种；目标是另一种地址时拒绝。
    #[serde(default)]
    pub family: IpFamily,
    /// 建连预算：同一个发起节点每分钟最多让出口向同一个互联网或局域网目标（主机加端口）新建多少条连接；
    /// 没有值表示不限。可以短时间用完一分钟的额度，之后按每分钟这么多的速度恢复。
    #[serde(default)]
    pub connects_per_minute: Option<u32>,
    /// 经这个出口的流的默认服务等级，排在代理自己的设置之后、网络的默认值之前。
    #[serde(default)]
    pub class: Option<Class>,
    /// 经这个出口的流用不用乐观回复（不等出口的 REPLY 就告诉客户端连上了），盖过按目标种类的默认值；
    /// 代理自己设了的话以代理的为准。没有值时按目标的种类：互联网目标用，局域网目标不用。
    #[serde(default)]
    pub optimistic: Option<bool>,
}

impl Default for ExitRole {
    fn default() -> Self {
        Self {
            ports: None,
            lan: false,
            upstream_socks5: None,
            quota_bytes: None,
            quota_reset_day: default_quota_reset_day(),
            family: IpFamily::default(),
            connects_per_minute: None,
            class: None,
            optimistic: None,
        }
    }
}

const fn default_quota_reset_day() -> u8 {
    1
}

/// 出口连互联网目标时用的地址族。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    /// IPv4 和 IPv6 都可以。
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl IpFamily {
    /// 这个地址族允许不允许 `ip`。IPv4 映射的 IPv6 地址按 IPv4 算。
    #[must_use]
    pub fn admits(self, ip: IpAddr) -> bool {
        match (self, ip.to_canonical()) {
            (Self::Any, _) | (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_)) => true,
            (Self::Ipv4, IpAddr::V6(_)) | (Self::Ipv6, IpAddr::V4(_)) => false,
        }
    }
}

/// 一个和本节点有访问关系的对端。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub id: NodeId,
    pub key: PublicKey,
    pub name: String,
    pub virtual_ip: Ipv4Addr,
    /// 这个对端可以访问本节点：本节点接受它开过来的流。
    pub inbound: bool,
    /// 本节点可以访问这个对端。
    pub outbound: bool,
    /// 对端上报的 UDP 候选端点。
    #[serde(default)]
    pub endpoints: Vec<SocketAddr>,
    /// 对端挂靠的 relay，按它到 relay 的延迟从低到高排。经 relay 到达它时，最后一跳必须是其中之一。
    #[serde(default)]
    pub attached: Vec<Attachment>,
    /// 对端启用了出口时有值。只用来让入口尽早失败，对端自己还会再查一遍。
    #[serde(default)]
    pub exit: Option<PeerExit>,
    #[serde(default)]
    pub dial_out_only: bool,
    /// 到这个对端的连接常驻，不因为没有流而关闭。
    #[serde(default)]
    pub keep_alive: bool,
    /// 和这个对端之间备不备着 ice3proxy（lane）。controller 只给有选了 ice3proxy 的代理（[`Proxy::lane`]）的一对
    /// 下发 `always`：代理监听的节点和它的出口，两边的 netmap 里是同一个值；别的都是 `off`。备着 lane 也只有这种代理的流走它，
    /// 端口转发和别的流照旧走共用的连接。比本程序新的 controller 下发了这里不认识的值时按 `off` 处理。
    #[serde(default, deserialize_with = "tolerant_lane_mode")]
    pub lane: LaneMode,
    /// 和这个对端之间的连接用哪种拥塞控制；没有值时用节点自己的默认（BBR）。一对节点各自的 netmap 里互相看到同一个值，
    /// 两边各自按它管自己往外发的那个方向。只对之后建立的连接生效。比本程序新的 controller 下发了不认识的值时按没有值处理。
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "tolerant_congestion")]
    pub congestion: Option<Congestion>,
    /// 对端用不了 UDP：它连上的 relay 一个也不经 UDP（controller 认定的，见管理接口的 `Node.no_udp`）。
    /// `udp_fallback` 下本节点经 relay 到它的路即使自己这一段有 UDP，也按没有 UDP 的路算：那条路上总有一段是它的 TCP。
    /// 和它直连着时不看这一项：直连的整条路都是 UDP（这样的节点出去的 UDP 有时到得了个别对端）。
    /// 旧的 controller 不发，读成 `false`；旧的节点不认。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_udp: bool,
}

/// netmap 里的拥塞控制设置：不认识的值按没有设置，不让整份 netmap 因为一个新的取值而读不了。
fn tolerant_congestion<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Congestion>, D::Error> {
    let text = Option::<String>::deserialize(deserializer)?;
    Ok(text.and_then(|text| text.parse().ok()))
}

/// 连接用哪种拥塞控制。只有程序里已经有的两种。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Congestion {
    /// 自己写的 BBR，节点的默认：不把随机丢包当作拥塞，长距离、有丢包的链路上快得多。
    Bbr,
    /// QUIC 库自带的 Cubic：每次丢包都减速。和别的 Cubic 流共用一个很深的缓冲时比 BBR 抢得到带宽。
    Cubic,
}

impl Congestion {
    /// 在 netmap、管理接口和命令行里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Cubic => "cubic",
        }
    }
}

impl fmt::Display for Congestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Congestion {
    type Err = UnknownCongestion;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::Bbr, Self::Cubic].into_iter().find(|algorithm| algorithm.as_str() == s).ok_or_else(|| UnknownCongestion(s.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("不认识的拥塞控制 {0:?}：可以是 bbr、cubic")]
pub struct UnknownCongestion(pub String);

/// netmap 里的 ice3proxy 设置：不认识的值按 `off`，不让整份 netmap 因为一个新的取值而读不了。
fn tolerant_lane_mode<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<LaneMode, D::Error> {
    let text = String::deserialize(deserializer)?;
    Ok(text.parse().unwrap_or_default())
}

/// 一对节点之间备不备着 ice3proxy（lane，每条流一条只属于它的 TCP），备着时什么时候用。
///
/// 要两个节点里至少有一个启用了 relay、它的 TCP 端口另一个连得上（见 [`Relay::tcp`]），否则不起作用，按 `off` 走。
/// 只有要求走 ice3proxy 的流（选了它的代理的 TCP 流）会用它；UDP 应用的数据、端口转发和别的流始终走共用的连接。
///
/// `Default` 是 `Off`：netmap 里没有这一项（旧的 controller）时就是不用。controller 现在只下发 `off` 和 `always`；
/// `udp_fallback` 留在线上格式里，旧的 controller 和静态的 netmap 还会写它，节点照旧认。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneMode {
    /// 不用：所有的流都在共用的连接上。
    #[default]
    Off,
    /// 共用的连接到对端的路上没有 UDP（UDP 不通、只能经 relay 的 TCP 中转）时，新的 TCP 流走 ice3proxy。
    /// 拨号方也只在这时拨，UDP 回来一阵之后放手：两边都有 UDP 的路时什么都不连。
    UdpFallback,
    /// 能开出 ice3proxy 时新的 TCP 流都走它。拨号方一直拨着。
    Always,
}

impl LaneMode {
    /// 在 netmap、管理接口和命令行里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::UdpFallback => "udp_fallback",
            Self::Always => "always",
        }
    }
}

impl fmt::Display for LaneMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LaneMode {
    type Err = UnknownLaneMode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::Off, Self::UdpFallback, Self::Always]
            .into_iter()
            .find(|mode| mode.as_str() == s)
            .ok_or_else(|| UnknownLaneMode(s.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("不认识的 ice3proxy 设置 {0:?}：可以是 off、udp_fallback、always")]
pub struct UnknownLaneMode(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub relay: NodeId,
    pub rtt_ms: u32,
    /// 不是节点按延迟自己挑的，是 controller 为了让连不上它那几个 relay 的对端也到得了它，要它另外挂靠的
    /// （[`LocalNode::shared_relays`]）。controller 算谁还缺一个共同的 relay 时只看节点自己挑的那几个，不然算出来的结果会来回变。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PeerExit {
    #[serde(default)]
    pub lan: bool,
    /// 这个出口的默认服务等级（[`ExitRole::class`]）。入口给经它出去的流挑等级时要用。
    #[serde(default)]
    pub class: Option<Class>,
    /// 这个出口的乐观回复设置（[`ExitRole::optimistic`]）。入口决定等不等 REPLY 时要用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimistic: Option<bool>,
}

/// 一个启用了的 relay。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    pub id: NodeId,
    pub key: PublicKey,
    pub name: String,
    /// 它的 UDP 地址，按要试的顺序。由 controller 下发时和 `tcp` 是同一组：controller 找出来的地址，
    /// 节点并行地试，用回答的那个。不一定每个都连得上：谁连得上它，它就是谁的 relay。
    #[serde(default)]
    pub udp: Vec<SocketAddr>,
    /// 它的 TCP 地址，给 UDP 用不了的节点用。
    #[serde(default)]
    pub tcp: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayClient {
    pub id: NodeId,
    pub key: PublicKey,
}

/// 一个代理：在本节点的 `bind` 上监听，请求经出口节点 `exit` 出去。
///
/// 目标在组网里的（节点的虚拟 IP、带网络域名后缀的节点名）不经出口，直接去那个节点；
/// 写成私有地址的目标是出口所在的局域网，要出口打开了局域网。出口不能是本节点自己。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proxy {
    /// controller 上的编号，节点上报这个代理的状态时按它对上。静态模式的 netmap 里自己编，不重复就行。
    pub id: u32,
    pub name: String,
    pub bind: SocketAddr,
    #[serde(default)]
    pub protocol: ListenerProtocol,
    /// 请求经哪个节点出去。
    pub exit: NodeId,
    /// 用户名和密码的校验值。没有时不认证：只在回环地址上可以这样，绑在别的地址上又没有它的代理，节点一律拒绝。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Verifier>,
    /// 来源白名单；空表示不限制。
    #[serde(default)]
    pub allow_from: Vec<IpNet>,
    /// 这个代理上的流的服务等级；没有值时看出口和网络的默认值。
    #[serde(default)]
    pub class: Option<Class>,
    /// 乐观回复：`true` 时不等对端的应答就告诉客户端连上了，`false` 时一律等。
    /// 没有值时看出口的设置，出口也没有设时按目标的种类：互联网目标不等，组网目标（节点的服务、局域网）等。
    #[serde(default)]
    pub optimistic: Option<bool>,
    /// 这个代理的 TCP 流（CONNECT 和明文 HTTP 的转发）走 ice3proxy：和对端之间备着 lane
    /// （那个对端的 [`Peer::lane`] 不是 `off`）就一律走它，开不出 lane 时退回共用的连接。controller 给这个代理的节点和出口之间
    /// 下发 `always`，所以经出口的流都走 ice3proxy；去组网里别的节点的流，那一对一般没有 lane，照旧走共用的连接。
    /// UDP 的数据报不走 ice3proxy。旧的 controller 不发，读成 `false`：节点什么都不放到 ice3proxy 上，直到 controller 也更新。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lane: bool,
}

/// 一个监听端口说哪种代理协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerProtocol {
    /// 两种都说：看客户端发来的第一个字节，`0x05` 是 SOCKS5，别的是 HTTP。
    #[default]
    Mixed,
    Socks5,
    Http,
}

impl ListenerProtocol {
    /// 在 netmap、管理接口和命令行里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mixed => "mixed",
            Self::Socks5 => "socks5",
            Self::Http => "http",
        }
    }
}

impl fmt::Display for ListenerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ListenerProtocol {
    type Err = UnknownListenerProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::Mixed, Self::Socks5, Self::Http]
            .into_iter()
            .find(|protocol| protocol.as_str() == s)
            .ok_or_else(|| UnknownListenerProtocol(s.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("不认识的代理协议 {0:?}：可以是 mixed、socks5、http")]
pub struct UnknownListenerProtocol(pub String);

/// 代理的用户名和密码的校验值：`SHA-256(盐 ‖ SHA-256(用户名) ‖ 密码)`。
///
/// 监听的节点只要核对，拿到的是它而不是密码：读到 netmap 的人拿它登录不了。盐每个代理一份，改密码时换，
/// 两个代理用同一个密码看不出来。用户名先哈希成定长再接上密码，两段的分界不会有歧义。
/// 密码是管理员写的，可能不长，所以校验值和 netmap 一样只该在节点和 controller 手里。
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verifier {
    pub salt: Hex<{ Verifier::SALT_LEN }>,
    pub hash: Hex<{ Verifier::HASH_LEN }>,
}

impl Verifier {
    pub const SALT_LEN: usize = 16;
    pub const HASH_LEN: usize = 32;

    /// 按 `salt` 算出 `username` 和 `password` 的校验值。
    #[must_use]
    pub fn derive(salt: [u8; Self::SALT_LEN], username: &[u8], password: &[u8]) -> Self {
        let name = digest::digest(&digest::SHA256, username);
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(&salt);
        context.update(name.as_ref());
        context.update(password);
        let hash = context.finish().as_ref().try_into().expect("SHA-256 的输出是 32 字节");
        Self { salt: Hex(salt), hash: Hex(hash) }
    }

    /// 客户端给的用户名和密码按同一个盐算出来的哈希。比较要由调用者做成常量时间的。
    #[must_use]
    pub fn hash_of(&self, username: &[u8], password: &[u8]) -> [u8; Self::HASH_LEN] {
        Self::derive(self.salt.0, username, password).hash.0
    }
}

/// 校验值不是密码，但打出来也没有用，日志里只留盐的开头。
impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Verifier({:02x}{:02x}…)", self.salt.0[0], self.salt.0[1])
    }
}

/// 定长的字节串，文本形式是小写十六进制。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hex<const N: usize>(pub [u8; N]);

impl<const N: usize> fmt::Display for Hex<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("应该是 {0} 个十六进制字符")]
pub struct InvalidHex(usize);

impl<const N: usize> FromStr for Hex<N> {
    type Err = InvalidHex;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s.as_bytes();
        if digits.len() != 2 * N {
            return Err(InvalidHex(2 * N));
        }
        let mut bytes = [0; N];
        for (byte, pair) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
            let text = std::str::from_utf8(pair).map_err(|_| InvalidHex(2 * N))?;
            *byte = u8::from_str_radix(text, 16).map_err(|_| InvalidHex(2 * N))?;
        }
        Ok(Self(bytes))
    }
}

impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardProtocol {
    Tcp,
    Udp,
}

/// 一条端口转发的监听一侧。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forward {
    /// 转发的编号，建流请求里靠它指明是哪一条。
    pub id: u32,
    pub protocol: ForwardProtocol,
    /// 监听地址。IP 是本节点的虚拟 IP 时只对组网里被允许的节点可达：经虚拟网卡来的连到这个地址上的监听，
    /// 经流来的（没有网卡的节点、SOCKS5 入口）由目标一侧接住。
    pub bind: SocketAddr,
    pub target: NodeId,
    #[serde(default)]
    pub allow_from: Vec<IpNet>,
    /// 这条转发上的流的服务等级；没有值时用网络的默认值。
    #[serde(default)]
    pub class: Option<Class>,
}

/// 一条端口转发的目标一侧。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardTarget {
    pub id: u32,
    pub protocol: ForwardProtocol,
    /// 本节点要去连的地址：回环地址或者本机所在局域网里的地址。
    pub addr: SocketAddr,
    /// 监听这条转发的节点。只有它开过来的流才能用这一条。
    pub listener: NodeId,
    /// 连上之后先给目标发一个 PROXY protocol 的头，说出发起节点的虚拟 IP（只有 TCP 的转发有）。
    /// 旧版本的节点不认这一项，照旧不发。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<ProxyProtocol>,
}

/// PROXY protocol 的哪一版（HAProxy 的规范）：v1 是一行文字，v2 是二进制的头。服务说它认哪一版就用哪一版。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    V1,
    V2,
}

impl ProxyProtocol {
    /// 在 netmap、管理接口和命令行里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

impl fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProxyProtocol {
    type Err = UnknownProxyProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::V1, Self::V2].into_iter().find(|version| version.as_str() == s).ok_or_else(|| UnknownProxyProtocol(s.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("不认识的 PROXY protocol 版本 {0:?}：可以是 v1、v2")]
pub struct UnknownProxyProtocol(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_is_optional_and_an_unknown_one_reads_as_none() {
        let mut netmap = minimal();
        assert_eq!(netmap.me.profile, None);
        assert!(!serde_json::to_string(&netmap).unwrap().contains("profile"), "没有选档位时 netmap 里不出现这个字段");
        netmap.me.profile = Some(Profile::LowFootprint);
        let json = serde_json::to_value(&netmap).unwrap();
        assert_eq!(json["me"]["profile"], "low_footprint");
        assert_eq!(serde_json::from_value::<Netmap>(json.clone()).unwrap(), netmap);
        let mut newer = json;
        newer["me"]["profile"] = "turbo".into();
        assert_eq!(serde_json::from_value::<Netmap>(newer).unwrap().me.profile, None);
    }

    #[test]
    fn profiles_read_in_both_spellings() {
        for profile in Profile::ALL {
            assert_eq!(profile.as_str().parse::<Profile>().unwrap(), profile);
            assert_eq!(profile.spelling().parse::<Profile>().unwrap(), profile);
        }
        assert!("fast".parse::<Profile>().is_err());
    }

    fn minimal() -> Netmap {
        serde_json::from_value(serde_json::json!({
            "version": 3,
            "network": { "name": "home", "domain": "home.i3t", "cidr": "10.66.0.0/16" },
            "me": { "id": 1, "name": "laptop", "virtual_ip": "10.66.0.1" },
            "peers": [{
                "id": 2, "key": PublicKey::from_bytes([2; 32]).to_string(), "name": "nas-01", "virtual_ip": "10.66.0.2",
                "inbound": true, "outbound": true
            }]
        }))
        .unwrap()
    }

    #[test]
    fn a_netmap_from_a_controller_without_the_acknowledgement_settings_reads_as_the_defaults() {
        let network = minimal().network;
        assert_eq!((network.ack_eliciting_threshold, network.max_ack_delay_ms), (10, 2), "旧的 controller 不发：用默认值");
        let mut json = serde_json::to_value(minimal()).unwrap();
        assert_eq!((&json["network"]["ack_eliciting_threshold"], &json["network"]["max_ack_delay_ms"]), (&10.into(), &2.into()));
        json["network"]["ack_eliciting_threshold"] = 4.into();
        json["network"]["max_ack_delay_ms"] = 5.into();
        let network = serde_json::from_value::<Netmap>(json).unwrap().network;
        assert_eq!((network.ack_eliciting_threshold, network.max_ack_delay_ms), (4, 5));
    }

    #[test]
    fn peers_without_a_virtual_nic_are_listed_only_when_there_are_any() {
        let mut netmap = minimal();
        assert!(netmap.no_vnet.is_empty(), "旧的 controller 不发：当作都有网卡");
        assert!(serde_json::to_value(&netmap).unwrap().get("no_vnet").is_none(), "没有的时候不写");
        netmap.no_vnet = vec![NodeId::new(2).unwrap()];
        let json = serde_json::to_value(&netmap).unwrap();
        assert_eq!(json["no_vnet"], serde_json::json!([2]));
        assert_eq!(serde_json::from_value::<Netmap>(json).unwrap(), netmap);
    }

    #[test]
    fn a_node_is_named_from_the_relay_list_then_the_peers_then_itself() {
        let mut netmap = minimal();
        let relay = |raw: u32, name: &str| Relay {
            id: NodeId::new(raw).unwrap(),
            key: PublicKey::from_bytes([9; 32]),
            name: name.into(),
            udp: Vec::new(),
            tcp: Vec::new(),
        };
        netmap.relays = vec![relay(9, "hk"), relay(2, "nas-relay")];
        let name = |raw: u32| netmap.node_name(NodeId::new(raw).unwrap());
        assert_eq!((name(9), name(2), name(1), name(7)), (Some("hk"), Some("nas-relay"), Some("laptop"), None));
        netmap.relays.clear();
        assert_eq!(netmap.node_name(NodeId::new(2).unwrap()), Some("nas-01"), "不在 relay 列表里的对端");
    }

    #[test]
    fn omitted_fields_take_their_defaults() {
        let netmap = minimal();
        assert_eq!(netmap.network.routing, RoutingMode::DirectFirst);
        assert_eq!(netmap.network.max_relay_hops, 2);
        assert_eq!(netmap.network.reach, Reach::Any);
        assert!(netmap.me.relay.is_none() && netmap.me.exit.is_none());
        assert!(netmap.relays.is_empty() && netmap.me.proxies.is_empty());
        assert!(netmap.peers[0].endpoints.is_empty());
    }

    #[test]
    fn unknown_fields_are_ignored_and_json_round_trips() {
        let mut value = serde_json::to_value(minimal()).unwrap();
        value["added_in_a_newer_version"] = serde_json::json!({ "x": 1 });
        let netmap: Netmap = serde_json::from_value(value).unwrap();
        assert_eq!(netmap, minimal());
    }

    #[test]
    fn a_lane_setting_from_a_newer_controller_reads_as_off_instead_of_breaking_the_netmap() {
        assert_eq!(minimal().peers[0].lane, LaneMode::Off, "旧的 controller 不发这一项");
        let mut value = serde_json::to_value(minimal()).unwrap();
        value["peers"][0]["lane"] = serde_json::json!("udp_fallback");
        assert_eq!(serde_json::from_value::<Netmap>(value.clone()).unwrap().peers[0].lane, LaneMode::UdpFallback);
        value["peers"][0]["lane"] = serde_json::json!("only_on_tuesdays");
        assert_eq!(serde_json::from_value::<Netmap>(value).unwrap().peers[0].lane, LaneMode::Off);
        // 管理接口和命令行收的设置不宽容：写错了要说出来。
        assert!(serde_json::from_str::<LaneMode>(r#""only_on_tuesdays""#).is_err());
        assert!("sometimes".parse::<LaneMode>().unwrap_err().to_string().contains("udp_fallback"));
        for mode in [LaneMode::Off, LaneMode::UdpFallback, LaneMode::Always] {
            assert_eq!(serde_json::to_value(mode).unwrap(), mode.as_str());
            assert_eq!(mode.as_str().parse::<LaneMode>(), Ok(mode));
        }
    }

    #[test]
    fn a_pair_congestion_setting_is_optional_and_one_from_a_newer_controller_reads_as_the_default() {
        assert_eq!(minimal().peers[0].congestion, None, "旧的 controller 不发这一项");
        let mut value = serde_json::to_value(minimal()).unwrap();
        assert!(value["peers"][0].get("congestion").is_none(), "没有设置时不写，旧的节点看到的和以前一样");
        value["peers"][0]["congestion"] = serde_json::json!("cubic");
        assert_eq!(serde_json::from_value::<Netmap>(value.clone()).unwrap().peers[0].congestion, Some(Congestion::Cubic));
        value["peers"][0]["congestion"] = serde_json::json!("vegas");
        assert_eq!(serde_json::from_value::<Netmap>(value).unwrap().peers[0].congestion, None);
        assert!("vegas".parse::<Congestion>().unwrap_err().to_string().contains("cubic"));
        for algorithm in [Congestion::Bbr, Congestion::Cubic] {
            assert_eq!(algorithm.as_str().parse::<Congestion>(), Ok(algorithm));
        }
    }

    #[test]
    fn exit_ports_default_to_unrestricted_and_a_list_restricts() {
        let default: ExitRole = serde_json::from_str("{}").unwrap();
        assert_eq!((default.ports.clone(), ExitRole::default().ports), (None, None));
        let any: ExitRole = serde_json::from_str(r#"{"ports": null}"#).unwrap();
        assert_eq!(any.ports, None);
        let listed: ExitRole = serde_json::from_str(r#"{"ports": [80, 443]}"#).unwrap();
        assert_eq!(listed.ports, Some(vec![80, 443]));
        assert_eq!(serde_json::to_value(&default).unwrap()["ports"], serde_json::Value::Null, "写出来的总有这一项，旧版本读到的也是不限");
    }

    #[test]
    fn an_exit_has_no_bandwidth_limit_and_an_old_setting_carrying_one_still_reads() {
        let old: ExitRole = serde_json::from_value(serde_json::json!({ "lan": true, "bandwidth_mbps": 50 })).unwrap();
        assert_eq!(old, ExitRole { lan: true, ..ExitRole::default() });
        assert!(serde_json::to_value(&old).unwrap().get("bandwidth_mbps").is_none(), "写出来的没有这一项");
    }

    #[test]
    fn peers_are_found_by_ip_and_by_short_or_full_name() {
        let netmap = minimal();
        let nas = NodeId::new(2).unwrap();
        assert_eq!(netmap.peer_by_ip("10.66.0.2".parse().unwrap()).map(|peer| peer.id), Some(nas));
        for name in ["nas-01", "NAS-01", "nas-01.home.i3t", "nas-01.HOME.i3t."] {
            assert_eq!(netmap.peer_by_name(name).map(|peer| peer.id), Some(nas), "{name}");
        }
        for name in ["nas", "nas-01.other.i3t", "home.i3t", ".home.i3t"] {
            assert_eq!(netmap.peer_by_name(name), None, "{name}");
        }
    }

    #[test]
    fn a_proxy_defaults_to_mixed_without_authentication_and_an_older_netmap_with_listeners_still_reads() {
        let proxy: Proxy =
            serde_json::from_value(serde_json::json!({ "id": 3, "name": "p", "bind": "127.0.0.1:1080", "exit": 2 })).unwrap();
        assert_eq!((proxy.protocol, proxy.auth, proxy.allow_from.len()), (ListenerProtocol::Mixed, None, 0));
        assert!(serde_json::to_value(&proxy).unwrap().get("auth").is_none(), "没有认证时不写");
        assert!(!proxy.lane, "旧的 controller 不发 lane：不走 ice3proxy");
        assert!(serde_json::to_value(&proxy).unwrap().get("lane").is_none(), "不走 ice3proxy 时不写，旧的节点看到的和以前一样");
        let with_lane = serde_json::to_value(Proxy { lane: true, ..proxy.clone() }).unwrap();
        assert_eq!(with_lane["lane"], true);
        assert!(serde_json::from_value::<Proxy>(with_lane).unwrap().lane);
        let mut old = serde_json::to_value(minimal()).unwrap();
        old["me"]["listeners"] = serde_json::json!([{ "name": "l", "bind": "127.0.0.1:1080", "protocol": "socks5" }]);
        old["credentials"] = serde_json::json!([{ "name": "c", "token": "0f".repeat(32) }]);
        assert_eq!(serde_json::from_value::<Netmap>(old).unwrap(), minimal(), "旧的 controller 下发的监听器和凭据不再认");
        for protocol in [ListenerProtocol::Mixed, ListenerProtocol::Socks5, ListenerProtocol::Http] {
            assert_eq!(serde_json::to_value(protocol).unwrap(), protocol.as_str());
            assert_eq!(protocol.as_str().parse::<ListenerProtocol>(), Ok(protocol));
        }
        assert!("socks4".parse::<ListenerProtocol>().unwrap_err().to_string().contains("mixed"));
    }

    #[test]
    fn a_verifier_admits_only_the_same_user_name_and_password_and_differs_per_salt() {
        let verifier = Verifier::derive([7; 16], b"alice", b"s3cret");
        assert_eq!(verifier.hash_of(b"alice", b"s3cret"), verifier.hash.0);
        for (username, password) in [(&b"alice"[..], &b"S3cret"[..]), (b"alic", b"es3cret"), (b"alice", b""), (b"", b"s3cret")] {
            assert_ne!(verifier.hash_of(username, password), verifier.hash.0, "{username:?} {password:?}");
        }
        assert_ne!(Verifier::derive([8; 16], b"alice", b"s3cret").hash, verifier.hash, "盐不同，同一个密码的校验值也不同");
        let json = serde_json::to_value(verifier).unwrap();
        assert_eq!(json["salt"], "07".repeat(16));
        assert_eq!(serde_json::from_value::<Verifier>(json).unwrap(), verifier);
        assert!(!format!("{verifier:?}").contains(&verifier.hash.to_string()), "Debug 不打出哈希");
        // 用户名先哈希，再和盐、密码接起来：和测试脚本里的写法一样（tests/e2e/harness.py）。
        let name = digest::digest(&digest::SHA256, b"alice");
        let whole = digest::digest(&digest::SHA256, &[&[7u8; 16][..], name.as_ref(), b"s3cret"].concat());
        assert_eq!(whole.as_ref(), verifier.hash.0);
    }

    #[test]
    fn hex_text_form_round_trips() {
        let hash = Hex([0x0f; 32]);
        let text = hash.to_string();
        assert_eq!(text, "0f".repeat(32));
        assert_eq!(text.parse::<Hex<32>>(), Ok(hash));
        assert_eq!("0f".parse::<Hex<32>>(), Err(InvalidHex(64)));
        assert_eq!("zz".repeat(32).parse::<Hex<32>>(), Err(InvalidHex(64)));
    }

    #[test]
    fn limits_and_classes_default_when_an_older_controller_omits_them() {
        let exit: ExitRole = serde_json::from_value(serde_json::json!({ "ports": [443], "lan": true })).unwrap();
        assert_eq!(
            (exit.quota_bytes, exit.quota_reset_day, exit.family, exit.connects_per_minute, exit.class),
            (None, 1, IpFamily::Any, None, None)
        );
        assert_eq!(exit, ExitRole { ports: Some(vec![443]), lan: true, ..ExitRole::default() });
        let forward: Forward =
            serde_json::from_value(serde_json::json!({ "id": 4, "protocol": "tcp", "bind": "127.0.0.1:0", "target": 2 })).unwrap();
        assert_eq!((forward.class, forward.bind.port()), (None, 0));
        assert_eq!(minimal().network.class, None);
        let peer_exit: PeerExit = serde_json::from_value(serde_json::json!({ "lan": true, "class": "bulk" })).unwrap();
        assert_eq!(peer_exit, PeerExit { lan: true, class: Some(Class::Bulk), optimistic: None });
        let quota: ExitRole = serde_json::from_value(serde_json::json!({ "family": "ipv4", "quota_bytes": 1_000_000 })).unwrap();
        assert_eq!((quota.family, quota.quota_bytes), (IpFamily::Ipv4, Some(1_000_000)));
    }

    #[test]
    fn an_address_family_admits_only_its_own_addresses() {
        let (v4, v6, mapped): (IpAddr, IpAddr, IpAddr) =
            ("1.1.1.1".parse().unwrap(), "2606:4700::1".parse().unwrap(), "::ffff:1.1.1.1".parse().unwrap());
        assert!(IpFamily::Any.admits(v4) && IpFamily::Any.admits(v6));
        assert!(IpFamily::Ipv4.admits(v4) && IpFamily::Ipv4.admits(mapped) && !IpFamily::Ipv4.admits(v6));
        assert!(IpFamily::Ipv6.admits(v6) && !IpFamily::Ipv6.admits(v4) && !IpFamily::Ipv6.admits(mapped));
    }

    #[test]
    fn proxy_protocol_versions_are_written_like_their_json() {
        for version in [ProxyProtocol::V1, ProxyProtocol::V2] {
            assert_eq!(serde_json::to_value(version).unwrap(), version.as_str());
            assert_eq!(version.to_string().parse(), Ok(version));
        }
        assert_eq!("v3".parse::<ProxyProtocol>(), Err(UnknownProxyProtocol("v3".to_owned())));
    }

    #[test]
    fn overlay_addresses_are_recognised() {
        let network = minimal().network;
        assert!(network.is_overlay_address("10.66.200.1".parse().unwrap()));
        assert!(!network.is_overlay_address("10.67.0.1".parse().unwrap()));
        assert!(!network.is_overlay_address("fd00::1".parse().unwrap()));
    }
}
