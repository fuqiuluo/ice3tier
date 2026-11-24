//! 命令行的参数。
//!
//! 结构在这里用 clap 的 derive 写；帮助的文字（命令和参数的说明、值的名字）在文字目录里，由 [`command`] 按语言装上去。
//! 所以这里的类型不写文档注释：clap 会把它们当成说明。

use std::net::{Ipv4Addr, SocketAddr};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use i3t_lang::Lang;
use i3t_model::admin::mcp::McpScope;
use i3t_model::admin::stats::Series;
use i3t_model::netmap::{Congestion, IpFamily, ListenerProtocol, Profile, ProxyProtocol, Reach, RoutingMode};
use i3t_proto::flow::Class;
use ipnet::{IpNet, Ipv4Net};

use crate::texts::{Help, Values, texts};

#[derive(Parser)]
#[command(name = "i3tctl", version)]
pub struct Cli {
    #[arg(long, env = "I3T_ADMIN_URL", default_value = "http://127.0.0.1:20332", global = true)]
    pub url: String,

    #[arg(long, env = "I3T_ADMIN_TOKEN", hide_env_values = true, global = true, allow_hyphen_values = true)]
    pub token: Option<String>,

    #[arg(long, env = "I3T_NETWORK", global = true)]
    pub network: Option<String>,

    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Status,
    Overview,
    Log {
        #[arg(long, default_value_t = 30)]
        limit: u32,
        #[arg(long)]
        action: Option<String>,
        #[arg(long = "ref")]
        reference: Option<String>,
        #[arg(long)]
        before: Option<u64>,
    },
    #[command(subcommand)]
    Network(NetworkCommand),
    #[command(subcommand)]
    Node(NodeCommand),
    #[command(subcommand)]
    Relay(RelayCommand),
    #[command(subcommand)]
    Exit(ExitCommand),
    #[command(subcommand)]
    Group(GroupCommand),
    #[command(subcommand)]
    Token(TokenCommand),
    #[command(subcommand)]
    Mcp(McpCommand),
    #[command(subcommand)]
    Rule(RuleCommand),
    #[command(subcommand)]
    Proxy(ProxyCommand),
    #[command(subcommand)]
    Forward(ForwardCommand),
    #[command(subcommand)]
    Pair(PairCommand),
    #[command(subcommand)]
    Access(AccessCommand),
    #[command(subcommand)]
    Update(UpdateCommand),
    Path {
        a: String,
        b: String,
    },
    Routes,
    Backbone,
    Stats {
        #[arg(value_parser = parse_series)]
        series: Series,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, default_value = "24h")]
        since: Lifetime,
    },
    Test {
        a: String,
        b: String,
        #[arg(long)]
        throughput: bool,
        #[arg(long)]
        via: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        only: Vec<TestItemArg>,
        #[arg(long)]
        no_wait: bool,
    },
    #[command(subcommand)]
    Tests(TestsCommand),
}

#[derive(Subcommand)]
pub enum TestsCommand {
    List {
        a: Option<String>,
        b: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    Show {
        id: u64,
    },
    Cancel {
        id: u64,
    },
    Matrix {
        #[arg(long, conflicts_with_all = ["cancel", "no_wait"])]
        show: bool,
        #[arg(long, conflicts_with = "no_wait")]
        cancel: bool,
        #[arg(long)]
        no_wait: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum TestItemArg {
    Direct,
    DirectQuality,
    RelayQuality,
    Route,
    Host,
}

impl From<TestItemArg> for i3t_model::admin::diag::TestItem {
    fn from(arg: TestItemArg) -> Self {
        match arg {
            TestItemArg::Direct => Self::Direct,
            TestItemArg::DirectQuality => Self::DirectQuality,
            TestItemArg::RelayQuality => Self::RelayQuality,
            TestItemArg::Route => Self::Route,
            TestItemArg::Host => Self::Host,
        }
    }
}

#[derive(Subcommand)]
pub enum NetworkCommand {
    List,
    Create {
        name: String,
        #[command(flatten)]
        settings: NetworkSettings,
    },
    Show,
    Set {
        #[command(flatten)]
        settings: NetworkSettings,
    },
    Delete {
        network: String,
    },
}

#[derive(Args)]
pub struct NetworkSettings {
    #[arg(long)]
    pub cidr: Option<Ipv4Net>,
    #[arg(long)]
    pub routing: Option<RoutingArg>,
    #[arg(long)]
    pub max_relay_hops: Option<u8>,
    #[arg(long)]
    pub reach: Option<ReachArg>,
    #[arg(long)]
    pub class: Option<Inherit<ClassArg>>,
    #[arg(long)]
    pub ack_eliciting_threshold: Option<u32>,
    #[arg(long)]
    pub max_ack_delay_ms: Option<u32>,
    #[arg(long)]
    pub bundle_small_packets: Option<OnOff>,
    #[arg(long)]
    pub vnet_offload: Option<OnOff>,
    #[arg(long)]
    pub vnet_mtu: Option<u16>,
}

#[derive(Subcommand)]
pub enum GroupCommand {
    List,
    Show {
        group: String,
    },
    Create {
        name: String,
    },
    Rename {
        group: String,
        name: String,
    },
    Delete {
        group: String,
    },
    Add {
        group: String,
        #[arg(required = true)]
        nodes: Vec<String>,
    },
    Remove {
        group: String,
        #[arg(required = true)]
        nodes: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum NodeCommand {
    List,
    Show {
        node: String,
    },
    Rename {
        node: String,
        name: String,
    },
    Groups {
        node: String,
        groups: Vec<String>,
    },
    Set {
        node: String,
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        #[arg(long)]
        dial_out_only: Option<OnOff>,
        #[arg(long)]
        routing: Option<Inherit<RoutingArg>>,
        #[arg(long)]
        reach: Option<Inherit<ReachArg>>,
        #[arg(long)]
        profile: Option<Inherit<ProfileArg>>,
        #[arg(long)]
        forward_target: Option<OnOff>,
        #[arg(long)]
        auto_update: Option<OnOff>,
        #[arg(long = "pin")]
        pins: Vec<String>,
        #[arg(long, conflicts_with = "pins")]
        unpin: bool,
    },
    Delete {
        node: String,
    },
    Succeed {
        node: String,
        predecessor: String,
    },
    Routes {
        node: String,
    },
    Access {
        node: String,
    },
    Listeners {
        node: String,
    },
}

#[derive(Subcommand)]
pub enum RelayCommand {
    Enable {
        node: String,
        #[arg(long)]
        bandwidth: Option<u32>,
    },
    Disable {
        node: String,
    },
    List,
}

#[derive(Subcommand)]
pub enum ExitCommand {
    Enable {
        node: String,
        #[arg(long, default_value = "any")]
        ports: PortList,
        #[arg(long)]
        lan: bool,
        #[arg(long)]
        upstream_socks5: Option<SocketAddr>,
        #[arg(long)]
        quota: Option<ByteSize>,
        #[arg(long, default_value_t = 1)]
        reset_day: u8,
        #[arg(long, default_value = "any")]
        family: FamilyArg,
        #[arg(long)]
        connects_per_minute: Option<u32>,
        #[arg(long)]
        class: Option<ClassArg>,
        #[arg(long)]
        optimistic: Option<OnOff>,
    },
    Disable {
        node: String,
    },
    List,
    Test {
        node: String,
        target: String,
    },
}

#[derive(Subcommand)]
pub enum TokenCommand {
    List {
        #[arg(long)]
        all: bool,
    },
    Create {
        #[arg(long, default_value = "24h")]
        expires: Lifetime,
        #[arg(long = "group")]
        groups: Vec<String>,
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        #[arg(long)]
        successor_of: Option<String>,
    },
    Delete {
        id: u32,
    },
}

#[derive(Subcommand)]
pub enum McpCommand {
    #[command(subcommand)]
    Token(McpTokenCommand),
}

#[derive(Subcommand)]
pub enum McpTokenCommand {
    List,
    // 只限哪个网络看全局的 `--network`：写了就只限它，没写就不限。
    Create {
        #[arg(long)]
        name: String,
        #[arg(long = "scope", required = true, value_delimiter = ',', value_parser = parse_scope)]
        scopes: Vec<McpScope>,
        #[arg(long)]
        expires_in: Lifetime,
    },
    Revoke {
        id: u32,
    },
}

#[derive(Subcommand)]
pub enum RuleCommand {
    List,
    Add {
        src: String,
        dst: String,
        #[arg(long)]
        one_way: bool,
        #[arg(long, default_value = "")]
        name: String,
        #[arg(long)]
        disabled: bool,
    },
    Enable {
        id: u32,
    },
    Disable {
        id: u32,
    },
    Delete {
        id: u32,
    },
}

#[derive(Subcommand)]
pub enum ProxyCommand {
    List {
        #[arg(long)]
        node: Option<String>,
    },
    Show {
        id: u32,
    },
    Add {
        node: String,
        bind: SocketAddr,
        exit: String,
        #[arg(long, default_value = "")]
        name: String,
        #[arg(long)]
        protocol: Option<ProtocolArg>,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long, default_value = "")]
        password: String,
        #[arg(long)]
        allow_from: Vec<IpNet>,
        #[arg(long)]
        class: Option<ClassArg>,
        #[arg(long)]
        optimistic: Option<OnOff>,
        #[arg(long)]
        disabled: bool,
        // 不写时在终端上问一次（不是终端、或者 --json 时不问，不走）。
        #[arg(long)]
        ice3proxy: bool,
    },
    // 至少要改一项。
    #[command(group(clap::ArgGroup::new("change").required(true).multiple(true).args([
        "node", "name", "bind", "exit", "protocol", "username", "password", "allow_from", "class", "optimistic", "enabled", "ice3proxy"
    ])))]
    Set {
        id: u32,
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        bind: Option<SocketAddr>,
        #[arg(long)]
        exit: Option<String>,
        #[arg(long)]
        protocol: Option<ProtocolArg>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, num_args = 0..)]
        allow_from: Option<Vec<IpNet>>,
        #[arg(long)]
        class: Option<Inherit<ClassArg>>,
        #[arg(long)]
        optimistic: Option<Inherit<OnOffArg>>,
        #[arg(long)]
        enabled: Option<OnOff>,
        #[arg(long)]
        ice3proxy: Option<OnOff>,
    },
    Delete {
        id: u32,
    },
}

/// 代理说哪种协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProtocolArg {
    Mixed,
    Socks5,
    Http,
}

impl From<ProtocolArg> for ListenerProtocol {
    fn from(arg: ProtocolArg) -> Self {
        match arg {
            ProtocolArg::Mixed => Self::Mixed,
            ProtocolArg::Socks5 => Self::Socks5,
            ProtocolArg::Http => Self::Http,
        }
    }
}

/// 开关写成 `on`、`off` 的又一种写法，给要能写 `default`（[`Inherit`]）的地方用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OnOffArg {
    On,
    Off,
}

impl From<OnOffArg> for bool {
    fn from(arg: OnOffArg) -> Self {
        arg == OnOffArg::On
    }
}

#[derive(Subcommand)]
pub enum ForwardCommand {
    List,
    Add {
        listen_node: String,
        bind: SocketAddr,
        target_node: String,
        target_addr: SocketAddr,
        #[arg(long)]
        udp: bool,
        #[arg(long, default_value = "")]
        name: String,
        #[arg(long)]
        allow_from: Vec<IpNet>,
        #[arg(long)]
        disabled: bool,
        #[arg(long)]
        class: Option<ClassArg>,
        #[arg(long, value_parser = parse_proxy_protocol)]
        proxy_protocol: Option<ProxyProtocol>,
    },
    Enable {
        id: u32,
    },
    Disable {
        id: u32,
    },
    Delete {
        id: u32,
    },
}

#[derive(Subcommand)]
pub enum PairCommand {
    List,
    Show {
        a: String,
        b: String,
    },
    // 至少要改一项。
    #[command(group(clap::ArgGroup::new("setting").required(true).multiple(true).args(["keep_alive", "congestion"])))]
    Set {
        a: String,
        b: String,
        #[arg(long)]
        keep_alive: Option<OnOff>,
        #[arg(long, value_parser = parse_congestion)]
        congestion: Option<CongestionArg>,
    },
    #[command(alias = "delete")]
    Unset {
        a: String,
        b: String,
    },
}

#[derive(Subcommand)]
pub enum AccessCommand {
    Graph,
    Check { from: String, to: String },
}

#[derive(Subcommand)]
pub enum UpdateCommand {
    Show,
    Set {
        #[arg(long)]
        auto: Option<OnOff>,
        #[arg(long)]
        source: Option<String>,
    },
    Check,
    Nodes,
    Node {
        node: String,
        #[arg(long)]
        drain: bool,
    },
    All {
        #[arg(long)]
        drain: bool,
    },
    Resume {
        version: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum RoutingArg {
    DirectFirst,
    LowestCost,
}

impl From<RoutingArg> for RoutingMode {
    fn from(arg: RoutingArg) -> Self {
        match arg {
            RoutingArg::DirectFirst => Self::DirectFirst,
            RoutingArg::LowestCost => Self::LowestCost,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ProfileArg {
    LowFootprint,
    Balanced,
    HighThroughput,
}

impl From<ProfileArg> for Profile {
    fn from(arg: ProfileArg) -> Self {
        match arg {
            ProfileArg::LowFootprint => Self::LowFootprint,
            ProfileArg::Balanced => Self::Balanced,
            ProfileArg::HighThroughput => Self::HighThroughput,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ClassArg {
    Auto,
    Interactive,
    Reliable,
    Bulk,
}

impl From<ClassArg> for Class {
    fn from(arg: ClassArg) -> Self {
        match arg {
            ClassArg::Auto => Self::Auto,
            ClassArg::Interactive => Self::Interactive,
            ClassArg::Reliable => Self::Reliable,
            ClassArg::Bulk => Self::Bulk,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum FamilyArg {
    Any,
    Ipv4,
    Ipv6,
}

impl From<FamilyArg> for IpFamily {
    fn from(arg: FamilyArg) -> Self {
        match arg {
            FamilyArg::Any => Self::Any,
            FamilyArg::Ipv4 => Self::Ipv4,
            FamilyArg::Ipv6 => Self::Ipv6,
        }
    }
}

/// `--congestion` 的值：一种拥塞控制，或者 `default`（改回节点的默认）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionArg(pub Option<Congestion>);

fn parse_congestion(text: &str) -> Result<CongestionArg, String> {
    match text {
        "default" => Ok(CongestionArg(None)),
        _ => text.parse().map(|algorithm| CongestionArg(Some(algorithm))).map_err(|_| (texts().ui.must_be)("bbr, cubic, default")),
    }
}

fn parse_proxy_protocol(text: &str) -> Result<ProxyProtocol, String> {
    text.parse().map_err(|_| (texts().ui.must_be)("v1, v2"))
}

/// 字节数：数字加可选的单位 K、M、G、T（按 1000 进位，和网络流量的计法一样）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteSize(pub u64);

impl std::str::FromStr for ByteSize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let wrong = || (texts().ui.must_be)("500M, 10G");
        let text = s.trim().trim_end_matches(['B', 'b']);
        let (digits, scale) = match text.char_indices().last() {
            Some((index, unit)) if unit.is_ascii_alphabetic() => {
                let scale: u64 = match unit.to_ascii_uppercase() {
                    'K' => 1_000,
                    'M' => 1_000_000,
                    'G' => 1_000_000_000,
                    'T' => 1_000_000_000_000,
                    _ => return Err(wrong()),
                };
                (&text[..index], scale)
            }
            _ => (text, 1),
        };
        let count: u64 = digits.trim().parse().map_err(|_| wrong())?;
        count.checked_mul(scale).map(Self).ok_or_else(|| texts().ui.too_large.to_owned())
    }
}

impl From<ByteSize> for u64 {
    fn from(size: ByteSize) -> Self {
        size.0
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ReachArg {
    Any,
    DirectOnly,
    RelayOnly,
}

impl From<ReachArg> for Reach {
    fn from(arg: ReachArg) -> Self {
        match arg {
            ReachArg::Any => Self::Any,
            ReachArg::DirectOnly => Self::DirectOnly,
            ReachArg::RelayOnly => Self::RelayOnly,
        }
    }
}

/// 节点上可以覆盖网络默认值的设置：写一个具体的值，或者写 `default` 改回用网络的。
#[derive(Clone, Copy)]
pub enum Inherit<T> {
    Default,
    Value(T),
}

impl<T: ValueEnum> std::str::FromStr for Inherit<T> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "default" {
            return Ok(Self::Default);
        }
        T::from_str(s, true).map(Self::Value).map_err(|_| {
            let values: Vec<String> =
                T::value_variants().iter().filter_map(ValueEnum::to_possible_value).map(|value| value.get_name().to_owned()).collect();
            (texts().ui.must_be)(&format!("{}, default", values.join(", ")))
        })
    }
}

impl<T> Inherit<T> {
    /// 管理 API 里的写法：`None` 表示清掉覆盖值。
    pub fn into_override<U: From<T>>(self) -> Option<U> {
        match self {
            Self::Default => None,
            Self::Value(value) => Some(U::from(value)),
        }
    }
}

#[derive(Clone, Copy)]
pub struct OnOff(pub bool);

impl std::str::FromStr for OnOff {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "on" => Ok(Self(true)),
            "off" => Ok(Self(false)),
            _ => Err((texts().ui.must_be)("on, off")),
        }
    }
}

/// 一段时间：数字加单位 s、m、h、d；只写数字按秒算。
#[derive(Clone, Copy)]
pub struct Lifetime {
    pub secs: u64,
}

impl std::str::FromStr for Lifetime {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let wrong = || (texts().ui.must_be)("30m, 24h, 7d");
        let (digits, unit) = match s.char_indices().last() {
            Some((index, unit)) if unit.is_ascii_alphabetic() => (&s[..index], unit),
            _ => (s, 's'),
        };
        let scale: u64 = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => return Err(wrong()),
        };
        let count: u64 = digits.parse().map_err(|_| wrong())?;
        count.checked_mul(scale).map(|secs| Self { secs }).ok_or_else(|| texts().ui.too_large.to_owned())
    }
}

/// `i3tctl stats` 能读的序列。
const SERIES: &str = "online|flows|tx|rx|node_tx|node_rx|node_flows|relay_attached|exit_tx|exit_rx";

fn parse_series(text: &str) -> Result<Series, String> {
    text.parse().map_err(|_| (texts().ui.must_be)(&SERIES.replace('|', ", ")))
}

/// MCP 令牌能有的权限。
const SCOPES: &str = "read|nodes:enroll|nodes:write|config:write|tests:run|updates:write|networks:write";

fn parse_scope(text: &str) -> Result<McpScope, String> {
    text.parse().map_err(|_| (texts().ui.must_be)(&SCOPES.replace('|', ", ")))
}

/// 出口允许的端口：一组端口，或者 `any`。
#[derive(Clone)]
pub struct PortList(pub Option<Vec<u16>>);

impl std::str::FromStr for PortList {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "any" {
            return Ok(Self(None));
        }
        let ports = s.split(',').map(|port| port.trim().parse::<u16>().map_err(|_| (texts().ui.must_be)("80,443, any")));
        ports.collect::<Result<Vec<_>, _>>().map(|ports| Self(Some(ports)))
    }
}

/// 命令行的定义，帮助按 `lang` 写。
pub fn command(lang: Lang) -> clap::Command {
    let texts = crate::texts::texts_in(lang);
    describe(Cli::command(), &texts.help, &texts.values)
}

/// 将文字目录中的帮助说明绑定到命令行定义。若命令或参数名拼写错误，clap 会在初始化时 panic；单元测试会按所有语言执行绑定，以确保名称一致。
fn describe(command: clap::Command, h: &Help, v: &Values) -> clap::Command {
    let node = |arg: clap::Arg| arg.value_name(v.node);
    let group = |arg: clap::Arg| arg.value_name(v.group);
    let id = |arg: clap::Arg| arg.value_name(v.id);
    let on_off = |arg: clap::Arg| arg.value_name("on|off");
    let routing = |arg: clap::Arg| arg.value_name("direct-first|lowest-cost");
    let reach = |arg: clap::Arg| arg.value_name("any|direct-only|relay-only");
    let class = |arg: clap::Arg| arg.value_name("auto|interactive|reliable|bulk");
    let settings = |sub: clap::Command| {
        sub.mut_arg("cidr", |arg| arg.help(h.network_cidr).value_name(v.cidr))
            .mut_arg("routing", |arg| routing(arg.help(h.routing)))
            .mut_arg("max_relay_hops", |arg| arg.help(h.network_max_relay_hops).value_name(v.count))
            .mut_arg("reach", |arg| reach(arg.help(h.reach)))
            .mut_arg("class", |arg| arg.help(h.class).value_name("auto|interactive|reliable|bulk|default"))
            .mut_arg("ack_eliciting_threshold", |arg| arg.help(h.network_ack_eliciting_threshold).value_name(v.count))
            .mut_arg("max_ack_delay_ms", |arg| arg.help(h.network_max_ack_delay_ms).value_name("ms"))
            .mut_arg("bundle_small_packets", |arg| on_off(arg.help(h.network_bundle_small_packets)))
            .mut_arg("vnet_offload", |arg| on_off(arg.help(h.network_vnet_offload)))
            .mut_arg("vnet_mtu", |arg| arg.help(h.network_vnet_mtu).value_name("576-1500"))
    };
    command
        .about(h.about)
        .mut_arg("url", |arg| arg.help(h.url).value_name(v.url))
        .mut_arg("token", |arg| arg.help(h.token).value_name(v.token))
        .mut_arg("network", |arg| arg.help(h.network).value_name(v.network))
        .mut_arg("json", |arg| arg.help(h.json))
        .mut_subcommand("status", |sub| sub.about(h.status))
        .mut_subcommand("overview", |sub| sub.about(h.overview))
        .mut_subcommand("log", |sub| {
            sub.about(h.log)
                .mut_arg("limit", |arg| arg.help(h.log_limit).value_name(v.count))
                .mut_arg("action", |arg| arg.help(h.log_action).value_name(v.action))
                .mut_arg("reference", |arg| arg.help(h.log_ref).value_name(v.reference))
                .mut_arg("before", |arg| arg.help(h.log_before).value_name(v.id))
        })
        .mut_subcommand("network", |sub| {
            sub.about(h.network_group)
                .mut_subcommand("list", |sub| sub.about(h.network_list))
                .mut_subcommand("create", |sub| {
                    settings(sub.about(h.network_create).mut_arg("name", |arg| arg.help(h.network_name).value_name(v.name)))
                })
                .mut_subcommand("show", |sub| sub.about(h.network_show))
                .mut_subcommand("set", |sub| settings(sub.about(h.network_set)))
                .mut_subcommand("delete", |sub| sub.about(h.network_delete).mut_arg("network", |arg| arg.value_name(v.network)))
        })
        .mut_subcommand("node", |sub| {
            sub.about(h.node_group)
                .mut_subcommand("list", |sub| sub.about(h.node_list))
                .mut_subcommand("show", |sub| sub.about(h.node_show).mut_arg("node", node))
                .mut_subcommand("rename", |sub| {
                    sub.about(h.node_rename).mut_arg("node", node).mut_arg("name", |arg| arg.value_name(v.name))
                })
                .mut_subcommand("groups", |sub| sub.about(h.node_groups).mut_arg("node", node).mut_arg("groups", group))
                .mut_subcommand("set", |sub| {
                    sub.about(h.node_set)
                        .mut_arg("node", node)
                        .mut_arg("ip", |arg| arg.help(h.node_ip).value_name(v.ip))
                        .mut_arg("dial_out_only", |arg| on_off(arg.help(h.node_dial_out_only)))
                        .mut_arg("routing", |arg| arg.help(h.node_routing).value_name("direct-first|lowest-cost|default"))
                        .mut_arg("reach", |arg| arg.help(h.node_reach).value_name("any|direct-only|relay-only|default"))
                        .mut_arg("profile", |arg| arg.help(h.node_profile).value_name("low-footprint|balanced|high-throughput|default"))
                        .mut_arg("forward_target", |arg| on_off(arg.help(h.node_forward_target)))
                        .mut_arg("auto_update", |arg| on_off(arg.help(h.node_auto_update)))
                        .mut_arg("pins", |arg| node(arg.help(h.node_pin)))
                        .mut_arg("unpin", |arg| arg.help(h.node_unpin))
                })
                .mut_subcommand("delete", |sub| sub.about(h.node_delete).mut_arg("node", node))
                .mut_subcommand("succeed", |sub| {
                    sub.about(h.node_succeed).mut_arg("node", node).mut_arg("predecessor", |arg| arg.value_name(v.predecessor))
                })
                .mut_subcommand("routes", |sub| sub.about(h.node_routes).mut_arg("node", node))
                .mut_subcommand("access", |sub| sub.about(h.node_access).mut_arg("node", node))
                .mut_subcommand("listeners", |sub| sub.about(h.node_listeners).mut_arg("node", node))
        })
        .mut_subcommand("relay", |sub| {
            sub.about(h.relay_group)
                .mut_subcommand("enable", |sub| {
                    sub.about(h.relay_enable).mut_arg("node", node).mut_arg("bandwidth", |arg| arg.help(h.bandwidth).value_name("MBIT/S"))
                })
                .mut_subcommand("disable", |sub| sub.about(h.relay_disable).mut_arg("node", node))
                .mut_subcommand("list", |sub| sub.about(h.relay_list))
        })
        .mut_subcommand("exit", |sub| {
            sub.about(h.exit_group)
                .mut_subcommand("enable", |sub| {
                    sub.about(h.exit_enable)
                        .mut_arg("node", node)
                        .mut_arg("ports", |arg| arg.help(h.exit_ports).value_name(v.ports))
                        .mut_arg("lan", |arg| arg.help(h.exit_lan))
                        .mut_arg("upstream_socks5", |arg| arg.help(h.exit_upstream).value_name(v.address))
                        .mut_arg("quota", |arg| arg.help(h.exit_quota).value_name(v.size))
                        .mut_arg("reset_day", |arg| arg.help(h.exit_reset_day).value_name(v.day))
                        .mut_arg("family", |arg| arg.help(h.exit_family).value_name("any|ipv4|ipv6"))
                        .mut_arg("connects_per_minute", |arg| arg.help(h.exit_connects).value_name(v.count))
                        .mut_arg("class", |arg| class(arg.help(h.class)))
                        .mut_arg("optimistic", |arg| on_off(arg.help(h.exit_optimistic)))
                })
                .mut_subcommand("disable", |sub| sub.about(h.exit_disable).mut_arg("node", node))
                .mut_subcommand("list", |sub| sub.about(h.exit_list))
                .mut_subcommand("test", |sub| {
                    sub.about(h.exit_test).mut_arg("node", node).mut_arg("target", |arg| arg.help(h.exit_test_target).value_name(v.target))
                })
        })
        .mut_subcommand("group", |sub| {
            sub.about(h.group_group)
                .mut_subcommand("list", |sub| sub.about(h.group_list))
                .mut_subcommand("show", |sub| sub.about(h.group_show).mut_arg("group", group))
                .mut_subcommand("create", |sub| sub.about(h.group_create).mut_arg("name", |arg| arg.value_name(v.name)))
                .mut_subcommand("rename", |sub| {
                    sub.about(h.group_rename).mut_arg("group", group).mut_arg("name", |arg| arg.value_name(v.name))
                })
                .mut_subcommand("delete", |sub| sub.about(h.group_delete).mut_arg("group", group))
                .mut_subcommand("add", |sub| sub.about(h.group_add).mut_arg("group", group).mut_arg("nodes", node))
                .mut_subcommand("remove", |sub| sub.about(h.group_remove).mut_arg("group", group).mut_arg("nodes", node))
        })
        .mut_subcommand("token", |sub| {
            sub.about(h.token_group)
                .mut_subcommand("list", |sub| sub.about(h.token_list).mut_arg("all", |arg| arg.help(h.token_all)))
                .mut_subcommand("create", |sub| {
                    sub.about(h.token_create)
                        .mut_arg("expires", |arg| arg.help(h.token_expires).value_name(v.duration))
                        .mut_arg("groups", |arg| group(arg.help(h.token_groups)))
                        .mut_arg("ip", |arg| arg.help(h.token_ip).value_name(v.ip))
                        .mut_arg("successor_of", |arg| node(arg.help(h.token_successor_of)))
                })
                .mut_subcommand("delete", |sub| sub.about(h.token_delete).mut_arg("id", id))
        })
        .mut_subcommand("mcp", |sub| {
            sub.about(h.mcp_group).mut_subcommand("token", |sub| {
                sub.about(h.mcp_token_group)
                    .mut_subcommand("list", |sub| sub.about(h.mcp_token_list))
                    .mut_subcommand("create", |sub| {
                        sub.about(h.mcp_token_create)
                            .mut_arg("name", |arg| arg.help(h.mcp_token_name).value_name(v.name))
                            .mut_arg("scopes", |arg| arg.help(h.mcp_token_scope).value_name(v.scope))
                            .mut_arg("expires_in", |arg| arg.help(h.mcp_token_expires_in).value_name(v.duration))
                    })
                    .mut_subcommand("revoke", |sub| sub.about(h.mcp_token_revoke).mut_arg("id", id))
            })
        })
        .mut_subcommand("rule", |sub| {
            sub.about(h.rule_group)
                .mut_subcommand("list", |sub| sub.about(h.rule_list))
                .mut_subcommand("add", |sub| {
                    sub.about(h.rule_add)
                        .mut_arg("src", |arg| arg.value_name(v.src))
                        .mut_arg("dst", |arg| arg.value_name(v.dst))
                        .mut_arg("one_way", |arg| arg.help(h.rule_one_way))
                        .mut_arg("name", |arg| arg.help(h.name).value_name(v.name))
                        .mut_arg("disabled", |arg| arg.help(h.create_disabled))
                })
                .mut_subcommand("enable", |sub| sub.about(h.rule_enable).mut_arg("id", id))
                .mut_subcommand("disable", |sub| sub.about(h.rule_disable).mut_arg("id", id))
                .mut_subcommand("delete", |sub| sub.about(h.rule_delete).mut_arg("id", id))
        })
        .mut_subcommand("proxy", |sub| {
            sub.about(h.proxy_group)
                .mut_subcommand("list", |sub| sub.about(h.proxy_list).mut_arg("node", |arg| node(arg.help(h.proxy_list_node))))
                .mut_subcommand("show", |sub| sub.about(h.proxy_show).mut_arg("id", id))
                .mut_subcommand("add", |sub| {
                    sub.about(h.proxy_add)
                        .mut_arg("node", node)
                        .mut_arg("bind", |arg| arg.help(h.proxy_bind).value_name(v.address))
                        .mut_arg("exit", |arg| node(arg.help(h.proxy_exit)))
                        .mut_arg("name", |arg| arg.help(h.proxy_name).value_name(v.name))
                        .mut_arg("protocol", |arg| arg.help(h.proxy_protocol))
                        .mut_arg("username", |arg| arg.help(h.proxy_username).value_name(v.name))
                        .mut_arg("password", |arg| arg.help(h.proxy_password).value_name(v.password))
                        .mut_arg("allow_from", |arg| arg.help(h.allow_from).value_name(v.cidr))
                        .mut_arg("class", |arg| class(arg.help(h.class)))
                        .mut_arg("optimistic", |arg| on_off(arg.help(h.proxy_optimistic)))
                        .mut_arg("ice3proxy", |arg| arg.help(h.proxy_ice3proxy))
                        .mut_arg("disabled", |arg| arg.help(h.create_disabled))
                })
                .mut_subcommand("set", |sub| {
                    sub.about(h.proxy_set)
                        .mut_arg("id", id)
                        .mut_arg("node", |arg| node(arg.help(h.proxy_set_node)))
                        .mut_arg("name", |arg| arg.help(h.name).value_name(v.name))
                        .mut_arg("bind", |arg| arg.help(h.proxy_bind).value_name(v.address))
                        .mut_arg("exit", |arg| node(arg.help(h.proxy_exit)))
                        .mut_arg("protocol", |arg| arg.help(h.proxy_protocol))
                        .mut_arg("username", |arg| arg.help(h.proxy_set_credentials).value_name(v.name))
                        .mut_arg("password", |arg| arg.help(h.proxy_set_credentials).value_name(v.password))
                        .mut_arg("allow_from", |arg| arg.help(h.proxy_set_allow_from).value_name(v.cidr))
                        .mut_arg("class", |arg| arg.help(h.proxy_set_class).value_name("auto|interactive|reliable|bulk|default"))
                        .mut_arg("optimistic", |arg| arg.help(h.proxy_set_optimistic).value_name("on|off|default"))
                        .mut_arg("enabled", |arg| on_off(arg.help(h.proxy_enabled)))
                        .mut_arg("ice3proxy", |arg| on_off(arg.help(h.proxy_set_ice3proxy)))
                })
                .mut_subcommand("delete", |sub| sub.about(h.proxy_delete).mut_arg("id", id))
        })
        .mut_subcommand("forward", |sub| {
            sub.about(h.forward_group)
                .mut_subcommand("list", |sub| sub.about(h.forward_list))
                .mut_subcommand("add", |sub| {
                    sub.about(h.forward_add)
                        .mut_arg("listen_node", |arg| arg.value_name(v.listen_node))
                        .mut_arg("bind", |arg| arg.value_name(v.bind))
                        .mut_arg("target_node", |arg| arg.value_name(v.target_node))
                        .mut_arg("target_addr", |arg| arg.value_name(v.target_addr))
                        .mut_arg("udp", |arg| arg.help(h.forward_udp))
                        .mut_arg("name", |arg| arg.help(h.name).value_name(v.name))
                        .mut_arg("allow_from", |arg| arg.help(h.allow_from).value_name(v.cidr))
                        .mut_arg("disabled", |arg| arg.help(h.create_disabled))
                        .mut_arg("class", |arg| class(arg.help(h.class)))
                        .mut_arg("proxy_protocol", |arg| arg.help(h.forward_proxy_protocol).value_name("v1|v2"))
                })
                .mut_subcommand("enable", |sub| sub.about(h.forward_enable).mut_arg("id", id))
                .mut_subcommand("disable", |sub| sub.about(h.forward_disable).mut_arg("id", id))
                .mut_subcommand("delete", |sub| sub.about(h.forward_delete).mut_arg("id", id))
        })
        .mut_subcommand("pair", |sub| {
            sub.about(h.pair_group)
                .mut_subcommand("list", |sub| sub.about(h.pair_list))
                .mut_subcommand("show", |sub| sub.about(h.pair_show).mut_arg("a", node).mut_arg("b", node))
                .mut_subcommand("set", |sub| {
                    sub.about(h.pair_set)
                        .mut_arg("a", node)
                        .mut_arg("b", node)
                        .mut_arg("keep_alive", |arg| on_off(arg.help(h.pair_keep_alive)))
                        .mut_arg("congestion", |arg| arg.help(h.pair_congestion).value_name("bbr|cubic|default"))
                })
                .mut_subcommand("unset", |sub| sub.about(h.pair_unset).mut_arg("a", node).mut_arg("b", node))
        })
        .mut_subcommand("access", |sub| {
            sub.about(h.access_group)
                .mut_subcommand("graph", |sub| sub.about(h.access_graph))
                .mut_subcommand("check", |sub| sub.about(h.access_check).mut_arg("from", node).mut_arg("to", node))
        })
        .mut_subcommand("update", |sub| {
            sub.about(h.update_group)
                .mut_subcommand("show", |sub| sub.about(h.update_show))
                .mut_subcommand("set", |sub| {
                    sub.about(h.update_set)
                        .mut_arg("auto", |arg| on_off(arg.help(h.update_auto)))
                        .mut_arg("source", |arg| arg.help(h.update_source).value_name(v.source))
                })
                .mut_subcommand("check", |sub| sub.about(h.update_check))
                .mut_subcommand("nodes", |sub| sub.about(h.update_nodes))
                .mut_subcommand("node", |sub| {
                    sub.about(h.update_node).mut_arg("node", node).mut_arg("drain", |arg| arg.help(h.update_drain))
                })
                .mut_subcommand("all", |sub| sub.about(h.update_all).mut_arg("drain", |arg| arg.help(h.update_drain)))
                .mut_subcommand("resume", |sub| sub.about(h.update_resume).mut_arg("version", |arg| arg.value_name(v.version)))
        })
        .mut_subcommand("path", |sub| sub.about(h.path).mut_arg("a", node).mut_arg("b", node))
        .mut_subcommand("routes", |sub| sub.about(h.routes))
        .mut_subcommand("backbone", |sub| sub.about(h.backbone))
        .mut_subcommand("stats", |sub| {
            sub.about(h.stats)
                .mut_arg("series", |arg| arg.help(h.stats_series).value_name(SERIES))
                .mut_arg("node", |arg| node(arg.help(h.stats_node)))
                .mut_arg("since", |arg| arg.help(h.stats_since).value_name(v.duration))
        })
        .mut_subcommand("test", |sub| {
            sub.about(h.test)
                .mut_arg("a", |arg| node(arg.help(h.test_a)))
                .mut_arg("b", node)
                .mut_arg("throughput", |arg| arg.help(h.test_throughput))
                .mut_arg("via", |arg| arg.help(h.test_via).value_name(v.relays))
                .mut_arg("only", |arg| arg.help(h.test_only).value_name("direct,direct-quality,relay-quality,route"))
                .mut_arg("no_wait", |arg| arg.help(h.no_wait))
        })
        .mut_subcommand("tests", |sub| {
            sub.about(h.tests_group)
                .mut_subcommand("list", |sub| {
                    sub.about(h.tests_list)
                        .mut_arg("a", node)
                        .mut_arg("b", node)
                        .mut_arg("limit", |arg| arg.help(h.tests_limit).value_name(v.count))
                })
                .mut_subcommand("show", |sub| sub.about(h.tests_show).mut_arg("id", id))
                .mut_subcommand("cancel", |sub| sub.about(h.tests_cancel).mut_arg("id", id))
                .mut_subcommand("matrix", |sub| {
                    sub.about(h.tests_matrix)
                        .mut_arg("show", |arg| arg.help(h.tests_matrix_show))
                        .mut_arg("cancel", |arg| arg.help(h.tests_matrix_cancel))
                        .mut_arg("no_wait", |arg| arg.help(h.no_wait))
                })
        })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use i3t_lang::cli::{CLAP_ENGLISH, all_help, has_chinese, try_parse_from};

    use super::*;

    fn parse(args: &[&str]) -> Cli {
        try_parse_from(command(Lang::English), Lang::English, ["i3tctl"].iter().chain(args).map(OsString::from)).unwrap()
    }

    fn fails(args: &[&str]) -> bool {
        try_parse_from::<Cli>(command(Lang::English), Lang::English, ["i3tctl"].iter().chain(args).map(OsString::from)).is_err()
    }

    #[test]
    fn the_command_line_definition_is_consistent_in_both_languages() {
        for lang in Lang::ALL {
            i3t_lang::cli::localize(command(lang), lang).debug_assert();
        }
    }

    #[test]
    fn every_command_and_option_is_described_in_both_languages_without_the_other_language() {
        for lang in Lang::ALL {
            let mut built = i3t_lang::cli::localize(command(lang), lang);
            built.build();
            let mut stack = vec![built];
            while let Some(command) = stack.pop() {
                assert!(command.get_about().is_some(), "{lang:?}：{} 没有说明", command.get_name());
                for arg in command.get_arguments().filter(|arg| !arg.is_positional()) {
                    assert!(
                        arg.get_help().is_some_and(|help| !help.to_string().is_empty()),
                        "{lang:?}：{} --{} 没有说明",
                        command.get_name(),
                        arg.get_id()
                    );
                }
                stack.extend(command.get_subcommands().cloned());
            }
        }
        for (path, help) in all_help(command(Lang::English), Lang::English) {
            assert!(!has_chinese(&help), "{path} 的英文帮助里有中文：\n{help}");
            assert!(!help.to_lowercase().contains("tag"), "{path}：分组不叫 tag 了\n{help}");
        }
        for (path, help) in all_help(command(Lang::ZhCn), Lang::ZhCn) {
            for english in CLAP_ENGLISH {
                assert!(!help.contains(english), "{path} 的中文帮助里有 {english}：\n{help}");
            }
            assert!(has_chinese(&help), "{path}：\n{help}");
            assert!(!help.contains("标签"), "{path}：分组不叫标签了\n{help}");
        }
    }

    #[test]
    fn positional_arguments_are_listed_in_the_order_they_are_typed() {
        // 按字母序的话"目的"（DST）会排在"源"（SRC）前面。
        let help = all_help(command(Lang::English), Lang::English)
            .into_iter()
            .find_map(|(path, help)| (path == "i3tctl rule add").then_some(help))
            .expect("rule add has help");
        let (src, dst) = (help.find("  <SRC-GROUP>").expect("source listed"), help.find("  <DST-GROUP>").expect("destination listed"));
        assert!(src < dst, "{help}");
    }

    #[test]
    fn lifetimes_ports_and_switches_parse() {
        let secs = |text: &str| text.parse::<Lifetime>().map(|lifetime| lifetime.secs);
        assert_eq!((secs("90"), secs("30m"), secs("24h"), secs("7d")), (Ok(90), Ok(1800), Ok(86400), Ok(604_800)));
        assert!(secs("soon").is_err() && secs("5w").is_err() && secs("").is_err());
        assert_eq!("80, 443".parse::<PortList>().unwrap().0, Some(vec![80, 443]));
        assert_eq!("any".parse::<PortList>().unwrap().0, None);
        assert!("http".parse::<PortList>().is_err());
        assert!("on".parse::<OnOff>().unwrap().0 && !"off".parse::<OnOff>().unwrap().0 && "yes".parse::<OnOff>().is_err());
    }

    #[test]
    fn node_overrides_accept_a_value_or_default() {
        let parse = |text: &str| text.parse::<Inherit<RoutingArg>>().map(Inherit::into_override::<RoutingMode>);
        assert_eq!(parse("default"), Ok(None));
        assert_eq!(parse("lowest-cost"), Ok(Some(RoutingMode::LowestCost)));
        assert!(parse("fastest").is_err());
    }

    #[test]
    fn update_and_path_commands_parse() {
        assert!(matches!(parse(&["update", "node", "nas", "--drain"]).command, Command::Update(UpdateCommand::Node { drain: true, .. })));
        assert!(matches!(parse(&["update", "all"]).command, Command::Update(UpdateCommand::All { drain: false })));
        assert!(matches!(
            parse(&["update", "set", "--auto", "off"]).command,
            Command::Update(UpdateCommand::Set { auto: Some(OnOff(false)), source: None })
        ));
        assert!(matches!(parse(&["path", "a", "b"]).command, Command::Path { .. }));
        assert!(matches!(parse(&["routes"]).command, Command::Routes));
        assert!(matches!(parse(&["backbone"]).command, Command::Backbone));
        assert!(fails(&["update", "set", "--auto", "maybe"]));
        assert!(matches!(
            parse(&["node", "set", "nas", "--auto-update", "off"]).command,
            Command::Node(NodeCommand::Set { auto_update: Some(OnOff(false)), forward_target: None, .. })
        ));
        assert!(fails(&["node", "set", "nas", "--auto-update", "maybe"]));
    }

    #[test]
    fn sizes_limits_and_the_new_commands_parse() {
        assert_eq!("500M".parse::<ByteSize>(), Ok(ByteSize(500_000_000)));
        assert_eq!("2t".parse::<ByteSize>(), Ok(ByteSize(2_000_000_000_000)));
        assert_eq!("1234".parse::<ByteSize>(), Ok(ByteSize(1234)));
        assert_eq!("10GB".parse::<ByteSize>(), Ok(ByteSize(10_000_000_000)));
        assert!("10X".parse::<ByteSize>().is_err() && "lots".parse::<ByteSize>().is_err());
        assert!(matches!(
            parse(&["proxy", "add", "laptop", "0.0.0.0:1080", "gw", "--protocol", "socks5"]).command,
            Command::Proxy(ProxyCommand::Add { protocol: Some(ProtocolArg::Socks5), disabled: false, ice3proxy: false, .. })
        ));
        assert!(matches!(
            parse(&["proxy", "add", "laptop", "0.0.0.0:1080", "gw", "--ice3proxy"]).command,
            Command::Proxy(ProxyCommand::Add { ice3proxy: true, .. })
        ));
        assert!(matches!(
            parse(&["proxy", "set", "3", "--ice3proxy", "off"]).command,
            Command::Proxy(ProxyCommand::Set { id: 3, ice3proxy: Some(OnOff(false)), enabled: None, .. })
        ));
        assert!(fails(&["proxy", "set", "3", "--ice3proxy"]), "改的时候要写 on 或者 off");
        assert!(matches!(
            parse(&["proxy", "set", "3", "--enabled", "off", "--class", "default", "--optimistic", "on"]).command,
            Command::Proxy(ProxyCommand::Set {
                id: 3,
                enabled: Some(OnOff(false)),
                class: Some(Inherit::Default),
                optimistic: Some(Inherit::Value(OnOffArg::On)),
                ..
            })
        ));
        assert!(
            matches!(
                parse(&["proxy", "set", "3", "--allow-from"]).command,
                Command::Proxy(ProxyCommand::Set { allow_from: Some(sources), .. }) if sources.is_empty()
            ),
            "只写 --allow-from 是清掉白名单"
        );
        assert!(fails(&["proxy", "set", "3"]), "至少要改一项");
        assert!(fails(&["proxy", "add", "laptop", "0.0.0.0:1080"]), "出口必填");
        assert!(fails(&["listener", "list"]) && fails(&["credential", "list"]), "去掉了");
        assert!(matches!(
            parse(&["exit", "enable", "gw", "--quota", "1G", "--family", "ipv4"]).command,
            Command::Exit(ExitCommand::Enable { quota: Some(ByteSize(1_000_000_000)), .. })
        ));
        assert!(
            matches!(parse(&["group", "add", "servers", "nas", "box"]).command, Command::Group(GroupCommand::Add { nodes, .. }) if nodes.len() == 2)
        );
        assert!(fails(&["group", "add", "servers"]), "要写至少一个节点");
        assert!(fails(&["tag", "rename", "a", "b"]), "标签的命令没有了");
        assert!(
            matches!(parse(&["node", "groups", "nas"]).command, Command::Node(NodeCommand::Groups { groups, .. }) if groups.is_empty())
        );
        assert!(matches!(
            parse(&["token", "create", "--group", "a", "--group", "b"]).command,
            Command::Token(TokenCommand::Create { groups, .. }) if groups == ["a", "b"]
        ));
        assert!(fails(&["token", "create", "--tag", "a"]));
        assert!(matches!(parse(&["token", "list", "--all"]).command, Command::Token(TokenCommand::List { all: true })));
        let Command::Mcp(McpCommand::Token(McpTokenCommand::Create { name, scopes, expires_in })) = parse(&[
            "mcp",
            "token",
            "create",
            "--name",
            "claude-code",
            "--scope",
            "read,nodes:enroll",
            "--scope",
            "config:write",
            "--expires-in",
            "30d",
        ])
        .command
        else {
            panic!("应该是 mcp token create")
        };
        assert_eq!((name.as_str(), expires_in.secs), ("claude-code", 30 * 86400));
        assert_eq!(scopes, [McpScope::Read, McpScope::NodesEnroll, McpScope::ConfigWrite], "可以用逗号隔开，也可以写多次");
        assert!(fails(&["mcp", "token", "create", "--name", "x", "--scope", "read"]), "过期时间必须写");
        assert!(fails(&["mcp", "token", "create", "--name", "x", "--expires-in", "1d"]), "权限必须写");
        assert!(fails(&["mcp", "token", "create", "--name", "x", "--scope", "root", "--expires-in", "1d"]), "没有这项权限");
        assert!(fails(&["mcp", "token", "create", "--name", "x", "--scope", "unknown", "--expires-in", "1d"]));
        assert!(matches!(
            parse(&["mcp", "token", "revoke", "3"]).command,
            Command::Mcp(McpCommand::Token(McpTokenCommand::Revoke { id: 3 }))
        ));
        assert!(matches!(parse(&["mcp", "token", "list"]).command, Command::Mcp(McpCommand::Token(McpTokenCommand::List))));
        assert!(matches!(parse(&["log", "--ref", "node:3", "--action", "node"]).command, Command::Log { .. }));
        assert!(matches!(parse(&["node", "listeners", "gw"]).command, Command::Node(NodeCommand::Listeners { .. })));
        assert!(fails(&["pair", "set", "a", "b", "--lane", "always"]), "ice3proxy 是代理的选项了，节点对上没有");
        assert!(matches!(
            parse(&["pair", "set", "a", "b", "--keep-alive", "on"]).command,
            Command::Pair(PairCommand::Set { keep_alive: Some(OnOff(true)), congestion: None, .. })
        ));
        let Command::Pair(PairCommand::Set { congestion, .. }) = parse(&["pair", "set", "a", "b", "--congestion", "cubic"]).command else {
            panic!("应该是 pair set")
        };
        assert_eq!(congestion, Some(CongestionArg(Some(Congestion::Cubic))));
        let Command::Pair(PairCommand::Set { congestion, .. }) = parse(&["pair", "set", "a", "b", "--congestion", "default"]).command
        else {
            panic!("应该是 pair set")
        };
        assert_eq!(congestion, Some(CongestionArg(None)), "default 是改回节点的默认");
        assert!(fails(&["pair", "set", "a", "b", "--congestion", "reno"]));
    }

    #[test]
    fn global_flags_can_follow_the_subcommand() {
        let cli = parse(&["node", "list", "--json", "--network", "home", "--url", "http://127.0.0.1:1"]);
        assert!(cli.json);
        assert_eq!((cli.network.as_deref(), cli.url.as_str()), (Some("home"), "http://127.0.0.1:1"));
        assert!(matches!(cli.command, Command::Node(NodeCommand::List)));
    }
}
