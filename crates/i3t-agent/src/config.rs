//! 节点的配置文件 `config.toml`。
//!
//! 这是使用者会亲手改的文件，所以：第一次运行时写出一份带注释的模板；写错了要说清楚哪一行、错在哪、应该怎么写；
//! 程序自己改它的时候（`i3t set …`）不能把注释和排版弄丢。
//!
//! 这里只放必须在本机决定的东西。其余的配置（对端、访问规则、监听器、端口转发）都由 controller 下发。

use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, bail};
use i3t_model::control::Declared;
use i3t_model::netmap::Profile;
use serde::Deserialize;

use crate::texts::texts;

/// 配置文件内容有误（语法错误、存在未识别的配置项或取值无效）。与读取文件失败区分处理：内容有误时重复重启也无法恢复。
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidConfig(String);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub declare: Declare,
    #[serde(default)]
    pub proxy: Proxy,
    #[serde(default)]
    pub metrics: Metrics,
    #[serde(default)]
    pub tests: Tests,
    #[serde(default)]
    pub performance: PerformanceConfig,
    #[serde(default)]
    pub network: Network,
    /// 原透明访问配置（`[intercept]`），已由虚拟网卡取代：仍接受但不生效，节点启动时记录日志（[`Config::retired`]）。
    #[serde(default, rename = "intercept")]
    retired_intercept: Option<Retired>,
    #[serde(default)]
    pub log: Log,
}

impl Config {
    /// 读取配置文件。文件不存在时返回默认值，不创建文件。
    ///
    /// # Errors
    ///
    /// 文件读取失败、语法错误、存在未识别的配置项或取值无效。错误信息包含文件名与出错位置。
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        crate::state::ensure_not_reparse_or_symlink(path).with_context(|| (texts().read_config)(path))?;
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(err).with_context(|| (texts().read_config)(path)),
        };
        Self::parse(&text).with_context(|| (texts().config_error)(path))
    }

    /// # Errors
    ///
    /// 同 [`load`](Self::load)，只是没有文件名。
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        // toml 的错误信息自带行号、列号和出错的那一行，原样给使用者看。
        let config: Self = toml::from_str(text).map_err(|err| InvalidConfig(err.to_string()))?;
        config.validate().map_err(|err| InvalidConfig(err.to_string()))?;
        Ok(config)
    }

    /// 配置文件不存在时写出模板，注释用这时的语言（`i3t_lang::current`）；已经存在时不动它，也不因为换了语言重写。
    ///
    /// # Errors
    ///
    /// 写文件失败。
    pub fn write_template_if_missing(path: &Path) -> anyhow::Result<()> {
        crate::state::ensure_not_reparse_or_symlink(path).with_context(|| (texts().create_config)(path))?;
        match crate::state::create_config_file(path) {
            Ok(mut file) => io::Write::write_all(&mut file, texts().template.as_bytes()).with_context(|| (texts().write_config)(path)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err).with_context(|| (texts().create_config)(path)),
        }
    }

    /// 将配置文件中的一项声明修改为 `on`，保留原有注释和排版。文件不存在时先写出模板。
    ///
    /// # Errors
    ///
    /// 文件读写失败，或现有内容无法解析。
    pub fn set_declared(path: &Path, capability: Capability, on: bool) -> anyhow::Result<()> {
        Self::set(path, Change::Declare(capability, on))
    }

    /// 修改配置文件中的一项，保留原有注释和排版。文件不存在时先写出模板。
    ///
    /// # Errors
    ///
    /// 文件读写失败，或现有内容无法解析。
    pub fn set(path: &Path, change: Change) -> anyhow::Result<()> {
        if let Change::CanForward(_) = change {
            return Ok(());
        }
        crate::state::ensure_not_reparse_or_symlink(path).with_context(|| (texts().read_config)(path))?;
        Self::write_template_if_missing(path)?;
        let text = fs::read_to_string(path).with_context(|| (texts().read_config)(path))?;
        let mut document: toml_edit::DocumentMut =
            text.parse().map_err(|err| anyhow::anyhow!("{err}")).with_context(|| (texts().config_error)(path))?;
        let (section, key) = change.setting().key();
        // 文件里还没有这一节（更早的版本写的、手写的）：加成一节。直接按下标写会写成一行 `节 = { 键 = 值 }`。
        if document.get(section).is_none() && change != Change::RelayAddress(None) {
            document[section] = toml_edit::table();
        }
        match change {
            Change::Declare(_, on) | Change::ThroughputTests(on) | Change::Network(on) | Change::Firewall(on) | Change::Offload(on) => {
                document[section][key] = toml_edit::value(on);
            }
            Change::CanForward(_) => {}
            Change::Profile(profile) => document[section][key] = toml_edit::value(profile.spelling()),
            Change::Mtu(mtu) => document[section][key] = toml_edit::value(i64::from(mtu)),
            Change::RelayAddress(Some(address)) => document[section][key] = toml_edit::value(address.to_string()),
            Change::RelayAddress(None) => {
                if let Some(table) = document.get_mut(section).and_then(toml_edit::Item::as_table_like_mut) {
                    table.remove(key);
                }
            }
        }
        let updated = document.to_string();
        // 修改后整体校验一遍，避免写入无法解析的配置。
        Self::parse(&updated).with_context(|| (texts().config_error)(path))?;
        fs::write(path, updated).with_context(|| (texts().write_config)(path))
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.port == 0 {
            bail!(texts().port_zero);
        }
        if let Some(address) = self.declare.relay_address
            && !is_relay_address(address)
        {
            bail!((texts().bad_relay_address)(&address.to_string()));
        }
        for (name, entry) in [("proxy.socks5", self.proxy.socks5), ("proxy.http", self.proxy.http)] {
            if let ProxyBind::At(addr) = entry
                && !addr.ip().is_loopback()
            {
                bail!((texts().proxy_not_loopback)(name, &addr.to_string()));
            }
        }
        if let ProxyBind::At(addr) = self.metrics.listen
            && !addr.ip().is_loopback()
        {
            bail!((texts().metrics_not_loopback)(&addr.to_string()));
        }
        if let (ProxyBind::At(socks5), ProxyBind::At(http)) = (self.proxy.socks5, self.proxy.http)
            && socks5 == http
        {
            bail!((texts().same_proxy_address)(&socks5.to_string()));
        }
        if !i3t_vnet::MTU_RANGE.contains(&self.network.mtu) {
            bail!((texts().bad_mtu)(&self.network.mtu.to_string()));
        }
        self.performance.validate()
    }

    /// 配置文件中仍保留但已失效的节（原透明访问的 `[intercept]`）。节点启动时逐一记录日志。
    #[must_use]
    pub fn retired(&self) -> Vec<&'static str> {
        self.retired_intercept.as_ref().map(|_| "intercept").into_iter().collect()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: default_port(),
            declare: Declare::default(),
            proxy: Proxy::default(),
            metrics: Metrics::default(),
            tests: Tests::default(),
            performance: PerformanceConfig::default(),
            network: Network::default(),
            retired_intercept: None,
            log: Log::default(),
        }
    }
}

/// 不再起作用的一节：里面写什么都照收，不看。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Retired;

impl<'de> Deserialize<'de> for Retired {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer).map(|_| Self)
    }
}

const fn default_port() -> u16 {
    crate::state::DEFAULT_PORT
}

/// 这台机器声明自己可以承担什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declare {
    #[serde(default)]
    pub exit: bool,
    #[serde(default)]
    pub relay: bool,
    /// 原“可作为端口转发目标”声明。现仅由管理员在 controller 上开启，本机不再声明：此项仍接受但不生效，
    /// 旧配置文件仍可正常加载。
    #[serde(default, rename = "forward")]
    _forward: bool,
    /// 作为 relay 时，别的节点还可以经这个地址连它：只有人知道的那一种，机房或者路由器把另一个地址上的端口
    /// 映射到这台机器。只一个：一台机器的端口映射到外面通常就是一个地址；controller 从网卡和连接上找出来的地址照样都用。
    #[serde(default)]
    pub relay_address: Option<SocketAddr>,
}

impl From<Declare> for Declared {
    fn from(declare: Declare) -> Self {
        Self { exit: declare.exit, relay: declare.relay, relay_address: declare.relay_address }
    }
}

/// 校验声明的 relay 地址是否对其他节点可达：须为具体单播地址（非全零、回环、组播、广播），且端口非 0。
fn is_relay_address(address: SocketAddr) -> bool {
    let ip = address.ip().to_canonical();
    let unusable =
        ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST);
    address.port() != 0 && !unusable
}

/// 可以在本机声明的两种能力。端口转发的目标不在这里：它只由管理员打开（见 [`Setting::CanForward`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Exit,
    Relay,
}

impl Capability {
    const fn key(self) -> &'static str {
        match self {
            Self::Exit => "exit",
            Self::Relay => "relay",
        }
    }
}

/// `i3t set` 能改的项：两项声明、声明的 relay 地址、接不接受吞吐测试、性能档位、虚拟网卡、它的防火墙规则和 MTU，和不再起作用的 `can-forward`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    Declare(Capability),
    /// 以前的"声明可以作为端口转发的目标"。现在由管理员在 controller 上打开，这一项照收、什么也不改，
    /// 照着旧的说明和脚本执行也不出错。
    CanForward,
    /// 声明的 relay 地址（`[declare] relay_address`）。
    RelayAddress,
    /// 接不接受管理员发起的吞吐测试（`[tests] throughput`）。
    ThroughputTests,
    /// controller 没有选档位时用的性能档位（`[performance] profile`）。
    Profile,
    /// 虚拟网卡（`[network] enabled`）。
    Network,
    /// 虚拟网卡的两条防火墙规则（`[network] firewall`）。
    Firewall,
    /// 虚拟网卡的 MTU（`[network] mtu`）。
    Mtu,
    /// 虚拟网卡与内核之间是否启用分片卸载（`[network] offload`，仅 Linux 支持）。
    Offload,
}

impl Setting {
    /// 在配置文件里的位置：节和键。
    const fn key(self) -> (&'static str, &'static str) {
        match self {
            Self::Declare(capability) => ("declare", capability.key()),
            // 以前写在这里；现在不写（见 `Config::set`）。
            Self::CanForward => ("declare", "forward"),
            Self::RelayAddress => ("declare", "relay_address"),
            Self::ThroughputTests => ("tests", "throughput"),
            Self::Profile => ("performance", "profile"),
            Self::Network => ("network", "enabled"),
            Self::Firewall => ("network", "firewall"),
            Self::Mtu => ("network", "mtu"),
            Self::Offload => ("network", "offload"),
        }
    }

    /// 这一项改成命令行上写的 `value`：开关写 `on` 或 `off`，档位写它的名字，relay 地址写 `地址:端口` 或者 `off`（不再声明），
    /// MTU 写字节数（[`i3t_vnet::MTU_RANGE`] 里的）。
    ///
    /// # Errors
    ///
    /// 值的写法不对。
    pub fn change(self, value: &str) -> anyhow::Result<Change> {
        let switch = || match value {
            "on" => Ok(true),
            "off" => Ok(false),
            other => Err(anyhow::anyhow!((texts().not_a_switch)(other))),
        };
        Ok(match self {
            Self::Declare(capability) => Change::Declare(capability, switch()?),
            Self::CanForward => Change::CanForward(switch()?),
            Self::ThroughputTests => Change::ThroughputTests(switch()?),
            Self::Network => Change::Network(switch()?),
            Self::Firewall => Change::Firewall(switch()?),
            Self::Offload => Change::Offload(switch()?),
            Self::Mtu => match value.parse::<u16>() {
                Ok(mtu) if i3t_vnet::MTU_RANGE.contains(&mtu) => Change::Mtu(mtu),
                Ok(_) | Err(_) => bail!((texts().bad_mtu)(value)),
            },
            Self::Profile => Change::Profile(value.parse().map_err(|_| anyhow::anyhow!((texts().unknown_profile)(value)))?),
            Self::RelayAddress => match value {
                "off" => Change::RelayAddress(None),
                text => {
                    let address: SocketAddr = text.parse().map_err(|_| anyhow::anyhow!((texts().bad_relay_address)(text)))?;
                    if !is_relay_address(address) {
                        bail!((texts().bad_relay_address)(text));
                    }
                    Change::RelayAddress(Some(address))
                }
            },
        })
    }
}

/// 命令行上的写法：`can-exit`、`can-relay`、`can-forward`、`relay-address`、`throughput-tests`、`profile`、`network`、`firewall`、`mtu`、
/// `offload`。
impl FromStr for Setting {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "can-forward" => Ok(Self::CanForward),
            "relay-address" => Ok(Self::RelayAddress),
            "throughput-tests" => Ok(Self::ThroughputTests),
            "profile" => Ok(Self::Profile),
            "network" => Ok(Self::Network),
            "firewall" => Ok(Self::Firewall),
            "mtu" => Ok(Self::Mtu),
            "offload" => Ok(Self::Offload),
            other => other.parse().map(Self::Declare).map_err(|_| anyhow::anyhow!((texts().unknown_setting)(other))),
        }
    }
}

impl fmt::Display for Setting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declare(capability) => capability.fmt(f),
            Self::CanForward => f.write_str("can-forward"),
            Self::RelayAddress => f.write_str("relay-address"),
            Self::ThroughputTests => f.write_str("throughput-tests"),
            Self::Profile => f.write_str("profile"),
            Self::Network => f.write_str("network"),
            Self::Firewall => f.write_str("firewall"),
            Self::Mtu => f.write_str("mtu"),
            Self::Offload => f.write_str("offload"),
        }
    }
}

/// `i3t set` 的一次修改：哪一项，改成什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Declare(Capability, bool),
    /// 什么也不改，见 [`Setting::CanForward`]。
    CanForward(bool),
    /// 声明的 relay 地址；`None` 是不再声明。
    RelayAddress(Option<SocketAddr>),
    ThroughputTests(bool),
    Profile(Profile),
    Network(bool),
    Firewall(bool),
    Mtu(u16),
    Offload(bool),
}

impl Change {
    #[must_use]
    pub const fn setting(self) -> Setting {
        match self {
            Self::Declare(capability, _) => Setting::Declare(capability),
            Self::CanForward(_) => Setting::CanForward,
            Self::RelayAddress(_) => Setting::RelayAddress,
            Self::ThroughputTests(_) => Setting::ThroughputTests,
            Self::Profile(_) => Setting::Profile,
            Self::Network(_) => Setting::Network,
            Self::Firewall(_) => Setting::Firewall,
            Self::Mtu(_) => Setting::Mtu,
            Self::Offload(_) => Setting::Offload,
        }
    }
}

/// 命令行上的写法：`on`、`off`，档位的名字，地址，或者字节数。
impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declare(_, on)
            | Self::CanForward(on)
            | Self::ThroughputTests(on)
            | Self::Network(on)
            | Self::Firewall(on)
            | Self::Offload(on) => f.write_str(if *on { "on" } else { "off" }),
            Self::Profile(profile) => f.write_str(profile.spelling()),
            Self::Mtu(mtu) => mtu.fmt(f),
            Self::RelayAddress(Some(address)) => address.fmt(f),
            Self::RelayAddress(None) => f.write_str("off"),
        }
    }
}

/// 命令行上的写法：`can-exit`、`can-relay`。
impl FromStr for Capability {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "can-exit" => Ok(Self::Exit),
            "can-relay" => Ok(Self::Relay),
            other => bail!((texts().unknown_setting)(other)),
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "can-{}", self.key())
    }
}

/// 本机组网入口（`[proxy]`）：仅通往组网内节点，不经出口、不鉴权，仅允许绑定回环地址。默认全部关闭：
/// 节点不会打开未配置的代理端口。旧版本默认开启 1080 和 1081，配置文件中已填写这两个地址的仍会开启，语义变更为“仅通往节点”。
/// 它们不属于 controller 下发的代理，不支持 ice3proxy 选项：流仅经共用连接传输。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    #[serde(default = "off")]
    pub socks5: ProxyBind,
    #[serde(default = "off")]
    pub http: ProxyBind,
}

impl Default for Proxy {
    fn default() -> Self {
        Self { socks5: ProxyBind::Off, http: ProxyBind::Off }
    }
}

const fn off() -> ProxyBind {
    ProxyBind::Off
}

/// 一个只给本机用的入口（代理、指标接口）绑在哪里，或者不开。配置文件里写地址，或者写 `"off"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyBind {
    Off,
    At(SocketAddr),
}

impl ProxyBind {
    #[must_use]
    pub const fn addr(self) -> Option<SocketAddr> {
        match self {
            Self::Off => None,
            Self::At(addr) => Some(addr),
        }
    }
}

impl<'de> Deserialize<'de> for ProxyBind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.eq_ignore_ascii_case("off") {
            return Ok(Self::Off);
        }
        text.parse().map(Self::At).map_err(|_| serde::de::Error::custom((texts().not_an_address)(&text)))
    }
}

/// 本机的指标接口。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// 绑在哪里，或者不开。写法和代理入口一样：地址，或者 `"off"`。
    #[serde(default = "default_metrics")]
    pub listen: ProxyBind,
}

impl Default for Metrics {
    fn default() -> Self {
        Self { listen: default_metrics() }
    }
}

fn default_metrics() -> ProxyBind {
    ProxyBind::At(SocketAddr::from(([127, 0, 0, 1], 20333)))
}

/// 主动测试的本机开关。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tests {
    /// 接受吞吐测试。关掉之后对端开来的测量流一律拒绝，controller 也知道（节点报给它），不会再发吞吐的测试项。
    #[serde(default = "default_true")]
    pub throughput: bool,
}

impl Default for Tests {
    fn default() -> Self {
        Self { throughput: true }
    }
}

const fn default_true() -> bool {
    true
}

/// 性能档位和逐项的覆盖（`[performance]`）。档位的值和它们的来历见 [`crate::performance`]。
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceConfig {
    /// controller 没有给这个节点选档位时用的档位。写法是 `low-footprint`、`balanced`、`high-throughput`。
    #[serde(default, deserialize_with = "profile_spelling")]
    pub profile: Profile,
    pub threads: Option<u32>,
    pub stream_buffer_kb: Option<u32>,
    pub stream_window_kb: Option<u32>,
    pub connection_window_mb: Option<u32>,
    /// 0 是不因为空闲关闭。
    pub idle_close_secs: Option<u64>,
    pub return_memory: Option<bool>,
    /// 本节点开出去、接进来的 TCP 通告的最大分段长度（MSS）。不写是 [`i3t_underlay::tcp_mss::DEFAULT`]，0 是用系统的。
    /// 不跟档位走：它是这台机器所在的网络的事（路径 MTU 黑洞，见 `i3t_underlay::tcp_mss`）。重启之后生效。
    pub tcp_mss: Option<u16>,
}

impl PerformanceConfig {
    /// 每一项的范围。流窗口的上限是连接层的硬上限（见 [`i3t_conn::MAX_STREAM_WINDOW`]）。
    const RANGES: [(&'static str, u64, u64); 4] = [
        ("threads", 1, 256),
        ("stream_buffer_kb", 1, 1024),
        ("stream_window_kb", 64, MAX_STREAM_WINDOW_KB),
        ("connection_window_mb", 1, 4095),
    ];

    fn validate(&self) -> anyhow::Result<()> {
        let values = [
            self.threads.map(u64::from),
            self.stream_buffer_kb.map(u64::from),
            self.stream_window_kb.map(u64::from),
            self.connection_window_mb.map(u64::from),
        ];
        for ((key, low, high), value) in Self::RANGES.into_iter().zip(values) {
            if let Some(value) = value
                && !(low..=high).contains(&value)
            {
                bail!((texts().performance_range)(key, low, high));
            }
        }
        let mss = i3t_underlay::tcp_mss::RANGE;
        if let Some(value) = self.tcp_mss
            && value != 0
            && !mss.contains(&value)
        {
            bail!((texts().performance_range)("tcp_mss", u64::from(*mss.start()), u64::from(*mss.end())));
        }
        Ok(())
    }
}

/// 流窗口最多能写多少 KB。
const MAX_STREAM_WINDOW_KB: u64 = i3t_conn::MAX_STREAM_WINDOW as u64 / 1024;

/// 配置文件里的档位用命令行的写法（`low-footprint`），也认 JSON 的写法（`low_footprint`）。
fn profile_spelling<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Profile, D::Error> {
    let text = String::deserialize(deserializer)?;
    text.parse().map_err(|_| serde::de::Error::custom((texts().unknown_profile)(&text)))
}

/// 虚拟网卡（`[network]`）：本机的程序用虚拟 IP 访问别的节点。默认打开。
///
/// 它会修改本机网络配置（网卡、地址、路由及两条防火墙规则），因此仅在本机开关，controller 仅展示状态。
/// 权限不足、缺少驱动或地址段与本机网络重叠时不安装，并在状态中说明原因，代理和端口转发不受影响。实现细节见 `i3t_vnet`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 是否由程序添加两条防火墙规则（类似 Tailscale 的 `--netfilter-mode`）。关闭时不修改任何防火墙规则。
    #[serde(default = "default_true")]
    pub firewall: bool,
    /// 本机虚拟网卡的 MTU（字节，`i3t set mtu`），须在 [`i3t_vnet::MTU_RANGE`] 范围内。保持 [`i3t_vnet::DEFAULT_MTU`]（未单独配置）
    /// 时使用网络默认值；配置为其他值时仅影响本机：其他节点配置不同也可互通。重启后生效。
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Linux：启用虚拟网卡与内核之间的分片卸载（`i3t set offload`）。默认开启，内核不支持时自动回退；
    /// 关闭用于排查经虚拟网卡传输的异常问题。虚拟网卡关闭时此项不生效。其他平台不支持。重启后生效。
    #[serde(default = "default_true")]
    pub offload: bool,
}

const fn default_mtu() -> u16 {
    i3t_vnet::DEFAULT_MTU
}

impl Default for Network {
    fn default() -> Self {
        Self { enabled: true, firewall: true, mtu: default_mtu(), offload: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[serde(default)]
    pub level: LogLevel,
}

impl Default for Log {
    fn default() -> Self {
        Self { level: LogLevel::Info }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// 日志库认的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_of(text: &str) -> String {
        format!("{:#}", Config::parse(text).unwrap_err())
    }

    #[test]
    fn the_template_parses_to_the_defaults() {
        assert_eq!(Config::parse(texts().template).unwrap(), Config::default());
    }

    #[test]
    fn an_empty_or_missing_file_means_defaults() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Config::load(&dir.path().join("config.toml")).unwrap(), Config::default());
    }

    #[test]
    fn a_misspelt_key_is_reported_with_its_line_and_the_valid_names() {
        let error = error_of("prot = 20330\n");
        assert!(error.contains("line 1"), "{error}");
        assert!(error.contains("prot") && error.contains("port"), "{error}");
    }

    #[test]
    fn a_wrong_type_is_reported_with_its_line() {
        let error = error_of("port = 20330\n[declare]\nexit = \"yes\"\n");
        assert!(error.contains("line 3"), "{error}");
    }

    #[test]
    fn proxy_entries_accept_an_address_or_off_and_explain_anything_else() {
        let config = Config::parse("[proxy]\nsocks5 = \"OFF\"\nhttp = \"[::1]:8080\"\n").unwrap();
        assert_eq!(config.proxy.socks5, ProxyBind::Off);
        assert_eq!(config.proxy.http.addr(), Some("[::1]:8080".parse().unwrap()));
        let error = error_of("[proxy]\nsocks5 = \"1080\"\n");
        assert!(error.contains(&(texts().not_an_address)("1080")), "{error}");
    }

    #[test]
    fn a_non_loopback_proxy_is_refused_with_a_pointer_to_the_right_place() {
        let error = error_of("[proxy]\nsocks5 = \"0.0.0.0:1080\"\n");
        assert!(error.contains(&(texts().proxy_not_loopback)("proxy.socks5", "0.0.0.0:1080")), "{error}");
    }

    #[test]
    fn the_metrics_endpoint_can_be_moved_or_switched_off_but_not_exposed() {
        assert_eq!(Config::default().metrics.listen.addr(), Some("127.0.0.1:20333".parse().unwrap()));
        let moved = Config::parse("[metrics]\nlisten = \"[::1]:9100\"\n").unwrap();
        assert_eq!(moved.metrics.listen.addr(), Some("[::1]:9100".parse().unwrap()));
        assert_eq!(Config::parse("[metrics]\nlisten = \"off\"\n").unwrap().metrics.listen, ProxyBind::Off);
        let error = error_of("[metrics]\nlisten = \"0.0.0.0:20333\"\n");
        assert!(error.contains(&(texts().metrics_not_loopback)("0.0.0.0:20333")), "{error}");
    }

    #[test]
    fn nonsense_values_are_refused() {
        assert!(error_of("port = 0\n").contains("port"));
        let error = error_of("[proxy]\nsocks5 = \"127.0.0.1:1080\"\nhttp = \"127.0.0.1:1080\"\n");
        assert!(error.contains(&(texts().same_proxy_address)("127.0.0.1:1080")), "{error}");
        assert!(error_of("[log]\nlevel = \"loud\"\n").contains("line 2"));
    }

    #[test]
    fn set_declared_changes_one_value_and_keeps_every_comment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        Config::set_declared(&path, Capability::Exit, true).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, texts().template.replace("exit = false", "exit = true"));
        assert_eq!(Config::load(&path).unwrap().declare, Declare { exit: true, ..Declare::default() });

        Config::set_declared(&path, Capability::Exit, false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), texts().template);
    }

    #[test]
    fn set_declared_works_on_a_hand_written_file_without_the_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "# 我的节点\nport = 20444\n").unwrap();
        Config::set_declared(&path, Capability::Relay, true).unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!((config.port, config.declare.relay), (20444, true));
        assert!(fs::read_to_string(&path).unwrap().starts_with("# 我的节点\n"));
    }

    #[test]
    fn set_declared_refuses_to_touch_a_broken_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "port = = 1\n").unwrap();
        assert!(Config::set_declared(&path, Capability::Exit, true).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "port = = 1\n");
    }

    #[test]
    fn throughput_tests_are_accepted_unless_switched_off_and_the_switch_keeps_the_comments() {
        assert!(Config::default().tests.throughput);
        assert!(Config::parse("[tests]\n").unwrap().tests.throughput, "没写就是接受");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let setting: Setting = "throughput-tests".parse().unwrap();
        Config::set(&path, setting.change("off").unwrap()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), texts().template.replace("throughput = true", "throughput = false"));
        assert!(!Config::load(&path).unwrap().tests.throughput);
        assert_eq!(setting.to_string(), "throughput-tests");
        assert_eq!("can-relay".parse::<Setting>().unwrap(), Setting::Declare(Capability::Relay));
        assert!("throughput".parse::<Setting>().unwrap_err().to_string().contains("throughput-tests"));
    }

    #[test]
    fn the_profile_is_set_by_name_and_each_item_has_a_range() {
        assert_eq!(Config::default().performance, PerformanceConfig::default());
        assert_eq!(Config::default().performance.profile, Profile::Balanced);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let change = Setting::Profile.change("low-footprint").unwrap();
        assert_eq!(change.to_string(), "low-footprint");
        Config::set(&path, change).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), texts().template.replace("profile = \"balanced\"", "profile = \"low-footprint\""));
        assert_eq!(Config::load(&path).unwrap().performance.profile, Profile::LowFootprint);
        assert!(Setting::Profile.change("fast").unwrap_err().to_string().contains("high-throughput"));
        assert!(Setting::ThroughputTests.change("yes").is_err());

        let tuned = Config::parse("[performance]\nprofile = \"high_throughput\"\nthreads = 8\nidle_close_secs = 0\n").unwrap();
        assert_eq!((tuned.performance.profile, tuned.performance.threads), (Profile::HighThroughput, Some(8)));
        assert!(error_of("[performance]\nprofile = \"turbo\"\n").contains("turbo"));
        assert!(error_of("[performance]\nthreads = 0\n").contains(&(texts().performance_range)("threads", 1, 256)));
        assert!(error_of("[performance]\nstream_window_kb = 4096\n").contains("stream_window_kb"), "流窗口不能超过连接层的上限");
        assert!(error_of("[performance]\nwindow = 1\n").contains("window"));
    }

    #[test]
    fn the_network_is_on_by_default_and_both_switches_keep_the_comments() {
        assert_eq!(Config::default().network, Network { enabled: true, firewall: true, mtu: 1280, offload: true });
        assert_eq!(Config::parse("[network]\n").unwrap().network, Network::default(), "没写就是开着");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let network: Setting = "network".parse().unwrap();
        assert_eq!((network, network.to_string()), (Setting::Network, "network".to_owned()));
        Config::set(&path, network.change("off").unwrap()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), texts().template.replace("enabled = true", "enabled = false"));
        assert!(!Config::load(&path).unwrap().network.enabled);
        let firewall: Setting = "firewall".parse().unwrap();
        Config::set(&path, firewall.change("off").unwrap()).unwrap();
        assert_eq!(Config::load(&path).unwrap().network, Network { enabled: false, firewall: false, ..Network::default() });
        Config::set(&path, network.change("on").unwrap()).unwrap();
        Config::set(&path, firewall.change("on").unwrap()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), texts().template);
        assert!(error_of("[network]\nenable = true\n").contains("enable"));
        assert!("intercept".parse::<Setting>().is_err(), "透明访问的开关没有了");
    }

    #[test]
    fn the_adapter_mtu_is_a_local_setting_within_its_range() {
        assert_eq!(Config::parse("[network]\nmtu = 1400\n").unwrap().network, Network { mtu: 1400, ..Network::default() });
        for bad in ["575", "1501", "0"] {
            let error = error_of(&format!("[network]\nmtu = {bad}\n"));
            assert!(error.contains(&(texts().bad_mtu)(bad)), "{bad}: {error}");
        }
        let mtu: Setting = "mtu".parse().unwrap();
        assert_eq!((mtu, mtu.to_string()), (Setting::Mtu, "mtu".to_owned()));
        assert_eq!(mtu.change("576").unwrap(), Change::Mtu(576));
        assert_eq!(mtu.change("1500").unwrap().to_string(), "1500");
        for bad in ["575", "1501", "on", "-1", "70000", ""] {
            assert_eq!(mtu.change(bad).unwrap_err().to_string(), (texts().bad_mtu)(bad), "{bad}");
        }

        // 模板里的那一行原地改，别的字节不动。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        Config::set(&path, mtu.change("1400").unwrap()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), texts().template.replace("mtu = 1280", "mtu = 1400"));
        assert_eq!(Config::load(&path).unwrap().network.mtu, 1400);
    }

    #[test]
    fn handing_whole_blocks_to_the_kernel_is_a_local_switch_that_is_on_by_default() {
        assert!(Network::default().offload);
        assert!(!Config::parse("[network]\noffload = false\n").unwrap().network.offload);
        let offload: Setting = "offload".parse().unwrap();
        assert_eq!((offload, offload.to_string()), (Setting::Offload, "offload".to_owned()));
        assert_eq!(offload.change("off").unwrap(), Change::Offload(false));
        assert_eq!(offload.change("on").unwrap().to_string(), "on");
        assert!(offload.change("1").is_err());

        // 模板里的那一行原地改，别的字节不动。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        Config::set(&path, Change::Offload(false)).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), texts().template.replace("offload = true", "offload = false"));
        assert!(!Config::load(&path).unwrap().network.offload);
    }

    #[test]
    fn a_setting_whose_section_is_missing_gets_a_section_of_its_own() {
        // 更早的版本写的配置文件里没有 [network]：加成一节，不是一行 `network = { … }`；已经写成那样的照样改得了。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "# 我的节点\nport = 20444\n\n[log]\nlevel = \"info\"\n").unwrap();
        Config::set(&path, Change::Network(false)).unwrap();
        Config::set(&path, Change::Mtu(1400)).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("[network]\nenabled = false\nmtu = 1400\n"), "{text}");
        assert!(text.starts_with("# 我的节点\nport = 20444\n\n[log]\n"), "原来的内容不动：{text}");
        assert_eq!(Config::load(&path).unwrap().network, Network { enabled: false, mtu: 1400, ..Network::default() });

        fs::write(&path, "network = { enabled = false, firewall = false }\n").unwrap();
        Config::set(&path, Change::Network(true)).unwrap();
        Config::set(&path, Change::Mtu(1200)).unwrap();
        assert_eq!(Config::load(&path).unwrap().network, Network { firewall: false, mtu: 1200, ..Network::default() });
    }

    #[test]
    fn an_old_intercept_section_does_not_stop_the_node_and_is_named_as_retired() {
        let old = Config::parse("[intercept]\nenabled = true\n").unwrap();
        assert_eq!(old.retired(), ["intercept"]);
        assert_eq!(old.network, Network::default(), "虚拟网卡照常默认开着");
        assert!(Config::default().retired().is_empty());
    }

    #[test]
    fn a_relay_address_is_declared_once_kept_with_the_comments_and_taken_back_with_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let setting: Setting = "relay-address".parse().unwrap();
        assert_eq!((setting, setting.to_string()), (Setting::RelayAddress, "relay-address".to_owned()));
        let change = setting.change("203.0.113.9:40330").unwrap();
        assert_eq!(change.to_string(), "203.0.113.9:40330");
        Config::set(&path, change).unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.declare.relay_address, Some("203.0.113.9:40330".parse().unwrap()));
        assert_eq!(Declared::from(config.declare).relay_address, config.declare.relay_address, "和 can-* 一起报给 controller");
        assert!(fs::read_to_string(&path).unwrap().contains("relay_address = \"203.0.113.9:40330\""));

        Config::set(&path, setting.change("off").unwrap()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), texts().template, "off 去掉这一项，别的原样");
        assert_eq!(Config::load(&path).unwrap().declare.relay_address, None);

        for bad in ["203.0.113.9", "0.0.0.0:40330", "127.0.0.1:20330", "203.0.113.9:0", "224.0.0.1:1", "nas:20330"] {
            assert!(setting.change(bad).is_err(), "{bad}");
        }
        assert!(error_of("[declare]\nrelay_address = \"127.0.0.1:20330\"\n").contains("127.0.0.1:20330"), "手写进文件的也查");
    }

    #[test]
    fn capabilities_use_the_command_line_spelling() {
        for capability in [Capability::Exit, Capability::Relay] {
            assert_eq!(capability.to_string().parse::<Capability>().unwrap(), capability);
        }
        assert!("exit".parse::<Capability>().is_err());
    }

    #[test]
    fn the_old_forward_declaration_is_still_accepted_and_changes_nothing() {
        let old = Config::parse("[declare]\nexit = true\nforward = true\n").unwrap();
        assert!(old.declare.exit, "写着 forward 的旧配置文件照样读得进来");
        assert_eq!(Declared::from(old.declare), Declared { exit: true, ..Declared::default() });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let setting: Setting = "can-forward".parse().unwrap();
        assert_eq!((setting, setting.to_string()), (Setting::CanForward, "can-forward".to_owned()));
        Config::set(&path, setting.change("on").unwrap()).unwrap();
        assert!(!path.exists(), "什么也不写");
        assert!(setting.change("yes").is_err(), "值照旧要写 on 或 off");
    }

    #[test]
    fn invalid_config_content_is_distinguished_from_io_errors() {
        let dir = tempfile::tempdir().unwrap();
        let bad_syntax = dir.path().join("bad-syntax.toml");
        fs::write(&bad_syntax, "port = \"not-a-number\"\n").unwrap();
        let error = Config::load(&bad_syntax).unwrap_err();
        assert!(error.chain().any(|cause| cause.is::<InvalidConfig>()), "语法错误应标为 InvalidConfig：{error:#}");

        let bad_value = dir.path().join("bad-value.toml");
        fs::write(&bad_value, "port = 0\n").unwrap();
        let error = Config::load(&bad_value).unwrap_err();
        assert!(error.chain().any(|cause| cause.is::<InvalidConfig>()), "配置值错误应标为 InvalidConfig：{error:#}");

        // 路径本身是目录时读文件会报 IO 错误，不是配置文件内容有错。
        let io_error = Config::load(dir.path()).unwrap_err();
        assert!(!io_error.chain().any(|cause| cause.is::<InvalidConfig>()), "IO 错误不应标为 InvalidConfig：{io_error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn config_load_and_set_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        fs::write(&secret, "root:SECRET_HASH:0:0\n").unwrap();
        let link = dir.path().join("config.toml");
        symlink(&secret, &link).unwrap();

        let err = Config::load(&link).unwrap_err();
        assert!(!format!("{err:#}").contains("SECRET_HASH"), "错误信息不得泄露符号链接目标内容：{err:#}");
        assert!(Config::set(&link, Change::Network(false)).is_err());
        assert_eq!(fs::read_to_string(&secret).unwrap(), "root:SECRET_HASH:0:0\n");
    }
}
