//! `i3tctl` 的文字目录：帮助、表格、提示、报错，两种语言各一份（[`zh`]、[`en`]）。
//!
//! 一样文字是一个字段，带值的是函数。少写一项、多写一项、参数不对都编译不过。控制面的代码（原因、状态）的写法在
//! `i3t_lang::codes`，两个命令行程序共用。

mod en;
mod zh;

use i3t_lang::Lang;
use i3t_model::admin::LogEntry;
use i3t_model::control::LaneCounts;
use i3t_model::control::diag::HostConnections;
use serde_json::{Map, Value};

/// 一种语言的全部文字。
#[derive(Debug)]
pub struct Texts {
    pub help: Help,
    pub values: Values,
    pub ui: Ui,
    /// 一条操作记录写成一句话：按 `action` 和 `params`。说不出来时（旧的记录没有参数、不认识的操作）是 `None`，
    /// 那时显示 controller 记下的原话。
    pub log: fn(&LogEntry) -> Option<String>,
}

/// 这个进程的语言的文字。
pub fn texts() -> &'static Texts {
    texts_in(i3t_lang::current())
}

pub fn texts_in(lang: Lang) -> &'static Texts {
    match lang {
        Lang::ZhCn => &zh::TEXTS,
        Lang::English => &en::TEXTS,
    }
}

/// 命令和参数的说明。命名：命令组用 `组_group`，命令用 `组_命令`，参数用 `组_参数` 或者 `组_命令_参数`。
#[derive(Debug)]
pub struct Help {
    pub about: &'static str,
    pub url: &'static str,
    pub token: &'static str,
    pub network: &'static str,
    pub json: &'static str,
    pub status: &'static str,
    pub overview: &'static str,
    pub log: &'static str,
    pub log_limit: &'static str,
    pub log_action: &'static str,
    pub log_ref: &'static str,
    pub log_before: &'static str,
    pub network_group: &'static str,
    pub network_list: &'static str,
    pub network_create: &'static str,
    pub network_name: &'static str,
    pub network_show: &'static str,
    pub network_set: &'static str,
    pub network_delete: &'static str,
    pub network_cidr: &'static str,
    pub network_max_relay_hops: &'static str,
    pub network_ack_eliciting_threshold: &'static str,
    pub network_max_ack_delay_ms: &'static str,
    pub routing: &'static str,
    pub reach: &'static str,
    pub class: &'static str,
    pub node_group: &'static str,
    pub node_list: &'static str,
    pub node_show: &'static str,
    pub node_rename: &'static str,
    pub node_groups: &'static str,
    pub node_set: &'static str,
    pub node_ip: &'static str,
    pub node_dial_out_only: &'static str,
    pub node_routing: &'static str,
    pub node_reach: &'static str,
    pub node_profile: &'static str,
    pub node_forward_target: &'static str,
    pub node_auto_update: &'static str,
    pub node_pin: &'static str,
    pub node_unpin: &'static str,
    pub node_delete: &'static str,
    pub node_succeed: &'static str,
    pub node_routes: &'static str,
    pub node_access: &'static str,
    pub node_listeners: &'static str,
    pub relay_group: &'static str,
    pub relay_enable: &'static str,
    pub relay_disable: &'static str,
    pub relay_list: &'static str,
    pub bandwidth: &'static str,
    pub exit_group: &'static str,
    pub exit_enable: &'static str,
    pub exit_ports: &'static str,
    pub exit_lan: &'static str,
    pub exit_upstream: &'static str,
    pub exit_quota: &'static str,
    pub exit_reset_day: &'static str,
    pub exit_family: &'static str,
    pub exit_connects: &'static str,
    pub exit_disable: &'static str,
    pub exit_list: &'static str,
    pub exit_test: &'static str,
    pub exit_test_target: &'static str,
    pub group_group: &'static str,
    pub group_list: &'static str,
    pub group_show: &'static str,
    pub group_create: &'static str,
    pub group_rename: &'static str,
    pub group_delete: &'static str,
    pub group_add: &'static str,
    pub group_remove: &'static str,
    pub token_group: &'static str,
    pub token_list: &'static str,
    pub token_all: &'static str,
    pub token_create: &'static str,
    pub token_expires: &'static str,
    pub token_groups: &'static str,
    pub token_ip: &'static str,
    pub token_successor_of: &'static str,
    pub token_delete: &'static str,
    pub rule_group: &'static str,
    pub rule_list: &'static str,
    pub rule_add: &'static str,
    pub rule_one_way: &'static str,
    pub rule_enable: &'static str,
    pub rule_disable: &'static str,
    pub rule_delete: &'static str,
    pub name: &'static str,
    pub create_disabled: &'static str,
    pub proxy_group: &'static str,
    pub proxy_list: &'static str,
    pub proxy_list_node: &'static str,
    pub proxy_show: &'static str,
    pub proxy_add: &'static str,
    pub proxy_bind: &'static str,
    pub proxy_exit: &'static str,
    pub proxy_name: &'static str,
    pub proxy_protocol: &'static str,
    pub proxy_username: &'static str,
    pub proxy_password: &'static str,
    pub allow_from: &'static str,
    pub proxy_optimistic: &'static str,
    pub exit_optimistic: &'static str,
    pub proxy_set: &'static str,
    pub proxy_set_node: &'static str,
    pub proxy_set_credentials: &'static str,
    pub proxy_set_allow_from: &'static str,
    pub proxy_set_class: &'static str,
    pub proxy_set_optimistic: &'static str,
    pub proxy_enabled: &'static str,
    pub proxy_ice3proxy: &'static str,
    pub proxy_set_ice3proxy: &'static str,
    pub proxy_delete: &'static str,
    pub forward_group: &'static str,
    pub forward_list: &'static str,
    pub forward_add: &'static str,
    pub forward_udp: &'static str,
    pub forward_proxy_protocol: &'static str,
    pub forward_enable: &'static str,
    pub forward_disable: &'static str,
    pub forward_delete: &'static str,
    pub pair_group: &'static str,
    pub pair_list: &'static str,
    pub pair_show: &'static str,
    pub pair_set: &'static str,
    pub pair_keep_alive: &'static str,
    pub pair_congestion: &'static str,
    pub pair_unset: &'static str,
    pub access_group: &'static str,
    pub access_graph: &'static str,
    pub access_check: &'static str,
    pub update_group: &'static str,
    pub update_show: &'static str,
    pub update_set: &'static str,
    pub update_auto: &'static str,
    pub update_source: &'static str,
    pub update_check: &'static str,
    pub update_nodes: &'static str,
    pub update_node: &'static str,
    pub update_drain: &'static str,
    pub update_all: &'static str,
    pub update_resume: &'static str,
    pub path: &'static str,
    pub routes: &'static str,
    pub backbone: &'static str,
    pub stats: &'static str,
    pub stats_series: &'static str,
    pub stats_node: &'static str,
    pub stats_since: &'static str,
    pub test: &'static str,
    pub test_a: &'static str,
    pub test_throughput: &'static str,
    pub test_via: &'static str,
    pub test_only: &'static str,
    pub no_wait: &'static str,
    pub tests_group: &'static str,
    pub tests_list: &'static str,
    pub tests_limit: &'static str,
    pub tests_show: &'static str,
    pub tests_cancel: &'static str,
    pub tests_matrix: &'static str,
    pub tests_matrix_show: &'static str,
    pub tests_matrix_cancel: &'static str,
}

/// 用法里值的名字：`<节点>`、`<NODE>`。只能填几种固定写法的值（`on|off`、选路模式）直接写那几种，不在这里。
#[derive(Debug)]
pub struct Values {
    pub node: &'static str,
    pub name: &'static str,
    pub id: &'static str,
    pub group: &'static str,
    /// 规则的两头。
    pub src: &'static str,
    pub dst: &'static str,
    pub address: &'static str,
    pub bind: &'static str,
    pub cidr: &'static str,
    pub ip: &'static str,
    pub url: &'static str,
    pub token: &'static str,
    pub network: &'static str,
    pub count: &'static str,
    pub size: &'static str,
    pub duration: &'static str,
    pub day: &'static str,
    pub ports: &'static str,
    pub action: &'static str,
    pub password: &'static str,
    pub reference: &'static str,
    pub predecessor: &'static str,
    pub listen_node: &'static str,
    pub target_node: &'static str,
    pub target_addr: &'static str,
    pub relays: &'static str,
    pub version: &'static str,
    pub source: &'static str,
    /// 出口测试的目标。
    pub target: &'static str,
}

/// 打印出来的东西：表头、名字、提示、报错。
#[derive(Debug)]
pub struct Ui {
    pub yes: &'static str,
    pub no: &'static str,
    pub on: &'static str,
    pub off: &'static str,
    pub online: &'static str,
    pub offline: &'static str,
    pub enabled: &'static str,
    pub disabled: &'static str,
    pub unlimited: &'static str,
    pub never: &'static str,
    pub default: &'static str,
    pub none_found: &'static str,
    /// 并列的几个短句之间：`；`、`; `。
    pub clauses: &'static str,

    pub key: &'static str,
    pub public_addr: &'static str,
    pub networks: &'static str,
    pub nodes: &'static str,
    pub newer_version: &'static str,
    pub of_online: fn(u64, u64) -> String,
    pub relays: &'static str,
    pub exits: &'static str,
    pub rules: &'static str,
    pub proxies: &'static str,
    pub forwards: &'static str,
    pub pending_tokens: &'static str,
    pub flows: &'static str,
    pub traffic: &'static str,
    pub unreachable_pairs: &'static str,
    pub no_relay_hint: &'static str,
    pub log_header: [&'static str; 5],

    pub node_offline: fn(&str) -> String,
    pub node_listeners_header: [&'static str; 7],
    pub builtin: &'static str,
    pub forward_name: fn(u32) -> String,

    pub no_exits: &'static str,
    pub health: &'static str,
    pub recent: &'static str,
    pub recent_requests: fn(u64, u64) -> String,
    pub ports: &'static str,
    pub lan: &'static str,
    pub family: &'static str,
    pub connects: &'static str,
    pub per_minute: fn(u32) -> String,
    pub requests: &'static str,
    pub exit_requests: fn(u64, u64, u64, u64) -> String,
    pub state: &'static str,
    pub draining: &'static str,
    pub quota: &'static str,
    pub seen_by: fn(&str) -> String,
    /// 出口测试：哪一步。
    pub resolve_step: &'static str,
    pub connect_step: &'static str,
    pub tls_step: &'static str,
    /// 出口按它的策略不连。
    pub exit_refused: &'static str,
    /// 出口没有做这次测试：另一个测试正在做或者刚做过。
    pub exit_busy: fn(&str) -> String,
    /// TLS 握手完成，证书没有检查。
    pub tls_done: &'static str,
    /// 出口只连某一种地址：`只连 IPv4`。
    pub family_only: fn(&str) -> String,
    /// 出口节点没有回答出口测试。
    pub exit_unanswered: fn(&str) -> String,
    pub exit_seen: fn(u64, u64, u64, u64, u64) -> String,

    pub networks_header: [&'static str; 7],
    pub no_networks: &'static str,
    pub domain: &'static str,
    pub cidr: &'static str,
    pub routing: &'static str,
    pub reach: &'static str,
    pub max_relay_hops: &'static str,
    pub class: &'static str,
    pub ack_eliciting_threshold: &'static str,
    pub max_ack_delay: &'static str,
    /// 写在一项改过的设置后面：它的默认值是什么。
    pub default_is: fn(&str) -> String,

    pub nodes_header: [&'static str; 8],
    pub no_nodes: &'static str,
    pub exit: &'static str,
    pub relay: &'static str,
    pub forward: &'static str,
    /// 角色和节点详情里的"可以作为端口转发的目标"。
    pub forward_target: &'static str,
    pub groups: &'static str,
    pub roles: &'static str,
    pub reachability: &'static str,
    pub reachability_header: [&'static str; 4],
    pub reachable: &'static str,
    pub reachability_note: &'static str,
    pub fqdn: &'static str,
    pub virtual_ip: &'static str,
    pub last_seen: &'static str,
    pub version: &'static str,
    pub hostname: &'static str,
    pub update: &'static str,
    pub declared: &'static str,
    /// relay 的地址（已经写好的一串）和带宽上限。
    pub relay_settings: fn(&str, &str) -> String,
    /// 一个地址和它的来源：`203.0.113.7:20330（controller 看到的）`。
    pub relay_address: fn(&str, &str) -> String,
    /// 启用了、但还不知道任何地址的 relay。
    pub no_address_yet: &'static str,
    pub declared_address: &'static str,
    pub warnings: &'static str,
    pub stats_header: [&'static str; 2],
    /// 出口的端口、局域网和上游代理。
    pub exit_settings: fn(&str, &str, &str) -> String,
    pub dial_out_only: &'static str,
    pub from_network: &'static str,
    pub pinned: &'static str,
    pub profile: &'static str,
    pub vnet: &'static str,
    /// 虚拟网卡装着时收发了多少：发出的包，收进的包，流量，丢掉的包。
    pub vnet_traffic: fn(u64, u64, &str, u64) -> String,
    /// 管理员没有选档位：节点用本机配置文件里的。
    pub profile_local: &'static str,
    /// 节点报的：在用的档位、工作线程数。
    pub profile_running: fn(&str, u32) -> String,
    pub restart_pending: &'static str,
    pub local_overrides: fn(&str) -> String,
    pub netmap_versions: fn(u64, u64, u64) -> String,
    pub endpoints: &'static str,
    pub observed: &'static str,
    /// 出口地址和它所在的国家或地区。
    pub egress: &'static str,
    pub attached: &'static str,
    /// 另外挂靠的 relay（controller 要它挂上去，好让别的节点到得了它）。
    pub shared_attachment: &'static str,
    /// 在线的节点里几个连得上、几个连不上、几个没报。
    pub reach_counts: fn(u32, u32, u32) -> String,
    pub relay_reach: &'static str,
    /// 试过一个 relay 的节点：节点、在线、结果、时间。
    pub reached_by_header: [&'static str; 4],
    /// 谁在用这个 relay：从、到、每秒多少字节。
    pub relay_users_header: [&'static str; 3],
    /// 其余的节点对合起来。
    pub relay_users_other: &'static str,
    /// 这个方向最近的换路。
    pub switches_of: fn(&str, &str) -> String,
    pub relays_header: [&'static str; 7],
    pub nat: &'static str,
    pub mapping_varies: &'static str,
    /// controller 认定节点用不了 UDP 时的一行。
    pub no_udp: &'static str,
    pub reported: &'static str,

    pub routes_header: [&'static str; 10],
    pub no_peers: &'static str,
    pub matrix_header: [&'static str; 6],
    pub stale: &'static str,
    pub never_reported: &'static str,
    /// 方向、路、路由层推算的延迟、连接自己量的往返时间、方式、来源、数据。
    pub path_header: [&'static str; 7],
    pub switched_ago: fn(&str) -> String,
    pub path_from_report: fn(&str) -> String,
    pub path_no_data: &'static str,
    pub path_not_peers: &'static str,
    pub candidates_of: fn(&str, &str, &str) -> String,
    pub why_this_route: &'static str,
    pub no_measurements: &'static str,
    pub candidates_header: [&'static str; 5],
    pub segment: fn(&str, &str, &str, &str, &str) -> String,
    pub no_relays: &'static str,
    pub backbone_header: [&'static str; 8],
    pub backbone_link: fn(&str, u32, u32, &str) -> String,
    pub backbone_down: fn(&str) -> String,
    pub backbone_nobody: &'static str,

    pub auto_update: &'static str,
    pub source: &'static str,
    pub latest: &'static str,
    /// 发布写了安全下限：标签，和"比哪个版本旧的有已知的安全问题"。
    pub security: &'static str,
    pub security_floor: fn(&str) -> String,
    pub not_found_yet: &'static str,
    pub checked: &'static str,
    pub check_failed: &'static str,
    pub update_counts: fn(u32, u32, u32, u32, u32, u32) -> String,
    pub controller_too_old: fn(&str) -> String,
    pub controller_newer: fn(&str) -> String,
    pub packages_header: [&'static str; 4],
    pub deleted_node: &'static str,
    pub paused: fn(&str, &str, &str, &str) -> String,
    pub resume_hint: fn(&str) -> String,
    pub node_updates_header: [&'static str; 8],
    pub too_old: &'static str,
    pub updating_to: fn(&str) -> String,
    pub nothing_to_update: &'static str,
    pub ordered: &'static str,
    pub queued: &'static str,
    pub skipped: fn(&str) -> String,
    pub when_idle: &'static str,
    pub now: &'static str,
    pub after_drain: &'static str,
    pub ordered_to: fn(&str, &str) -> String,
    pub available: fn(&str) -> String,
    pub up_to_date: &'static str,
    /// 节点的版本比安全下限旧：跟在更新情况后面的括注；没有可以更新到的版本时单说一句。
    pub security_update: &'static str,
    pub security_problem: &'static str,

    pub access_header: [&'static str; 4],
    pub can_reach: &'static str,
    pub reachable_by: &'static str,
    pub not_acknowledged: fn(&str) -> String,
    pub tokens_header: [&'static str; 8],
    pub no_tokens: &'static str,
    pub token_created: fn(u32, &str) -> String,
    pub token_use: &'static str,
    pub rules_header: [&'static str; 6],
    pub no_rules: &'static str,
    pub rule: &'static str,
    pub proxies_header: [&'static str; 10],
    pub no_proxies: &'static str,
    pub proxy: &'static str,
    pub listen_node: &'static str,
    pub listen_at: &'static str,
    pub allowed_from: &'static str,
    pub username: &'static str,
    pub password: &'static str,
    pub no_authentication: &'static str,
    pub usage: &'static str,
    /// 怎么用这个代理：`socks5h://用户名:密码@地址` 这样的一行。
    pub proxy_use: &'static str,
    pub forwards_header: [&'static str; 10],
    pub no_forwards: &'static str,
    pub pairs_header: [&'static str; 4],
    pub no_pairs: &'static str,
    /// 节点对没有存下的设置，各项是默认值。
    pub pair_default: &'static str,
    pub keep_alive: &'static str,
    pub lanes: &'static str,
    pub congestion: &'static str,
    /// 节点对没有指定拥塞控制：用节点的默认。
    pub congestion_default: &'static str,
    pub no_effect: &'static str,
    pub dialers: &'static str,
    pub peer_lanes: fn(bool, bool, u64, u64, u64, &str) -> String,
    pub lane_counts: fn(&LaneCounts, &str) -> String,
    pub total: &'static str,
    pub handshake_failures: &'static str,
    pub handshake_failure_counts: fn(u64, u64, u64, u64, u64) -> String,
    pub groups_header: [&'static str; 4],
    pub no_groups: &'static str,
    /// 访问关系图里的分组：名字、节点数、节点。
    pub graph_groups_header: [&'static str; 3],
    /// 删掉的分组：名字、从几个节点上去掉、删掉几条规则。
    pub group_deleted: fn(&str, usize, usize) -> String,
    pub unconnected: &'static str,
    pub unacknowledged: &'static str,
    pub can_access: fn(&str, &str) -> String,
    pub cannot_access: fn(&str, &str) -> String,

    pub test: &'static str,
    pub throughput: &'static str,
    pub test_failed: &'static str,
    pub path_quality: &'static str,
    pub quality_header: [&'static str; 12],
    pub mode_choices: &'static str,
    pub choices_header: [&'static str; 5],
    /// 延迟优先不换路时，那条更便宜的候选：路，代价（毫秒）。接在选择的说明后面，自己带着分隔的标点。
    pub cheaper_path: fn(&str, &str) -> String,
    pub note: &'static str,
    pub hosts_title: &'static str,
    pub hosts_header: [&'static str; 9],
    /// 进程：常驻内存，线程数（读不到时没有），运行了多久。
    pub host_process: fn(&str, Option<u32>, &str) -> String,
    /// 连接数：对端，挂靠的 relay，本节点作为 relay 的会话（不是 relay 时没有），流，ice3proxy 在用的和空闲的。
    pub host_connections: fn(&HostConnections) -> String,
    pub cpu_note: &'static str,
    pub peer_connection_title: &'static str,
    pub peer_connection_header: [&'static str; 12],
    pub no_connection: &'static str,
    pub direct_capability: &'static str,
    pub already_direct: &'static str,
    pub reason: &'static str,
    pub connected: &'static str,
    pub not_connected: &'static str,
    pub direct_side: fn(&str, &str, u32) -> String,
    pub other_way_back: fn(u32, u32) -> String,
    pub throughput_title: &'static str,
    pub throughput_header: [&'static str; 9],
    pub throughput_note: fn(&str, &str, &str, u32) -> String,
    pub tests_header: [&'static str; 8],
    pub no_tests: &'static str,
    pub matrix: &'static str,
    pub matrix_progress: fn(u32, u32, u32) -> String,
    pub cells_header: [&'static str; 8],

    pub no_token: &'static str,
    pub no_networks_yet: &'static str,
    pub several_networks: fn(&str) -> String,
    pub test_started: fn(u64) -> String,
    pub matrix_started: &'static str,
    pub both_nodes: &'static str,
    pub wait_timeout: fn(u64) -> String,
    pub no_such_node: fn(&str) -> String,
    pub no_such_group: fn(&str) -> String,
    pub no_such_network: fn(&str) -> String,
    pub no_such_forward: fn(u32) -> String,
    pub network_deleted: fn(&str) -> String,
    pub node_deleted: fn(&str) -> String,
    pub token_deleted: fn(u32) -> String,
    pub rule_deleted: fn(u32) -> String,
    pub proxy_deleted: fn(u32) -> String,
    pub forward_deleted: fn(u32) -> String,
    pub pair_unset: fn(u32, u32) -> String,
    pub bad_version: fn(&str) -> String,
    pub must_be: fn(&str) -> String,
    /// `proxy add` 在终端上问的一句，默认不要。后面不换行，回答接在同一行。
    pub ask_ice3proxy: &'static str,
    pub answer_unreadable: &'static str,
    pub too_large: &'static str,
    pub url_scheme: fn(&str) -> String,
    pub http_client: &'static str,
    pub cannot_connect: fn(&str) -> String,
    pub read_response: &'static str,
    pub not_json: &'static str,
    /// 管理令牌被拒绝：拒绝的原因，再提示去哪里改。
    pub token_rejected: fn(&str) -> String,
    pub unexpected_response: fn(u16) -> String,
    pub version_mismatch: &'static str,
}

/// 一条操作记录的参数，按名字取。没有这一项、或者类型不对时取到的是短横、`false`、0。
pub(crate) struct Params<'a>(&'a Map<String, Value>);

impl<'a> Params<'a> {
    pub(crate) const fn of(entry: &'a LogEntry) -> Self {
        Self(&entry.params)
    }

    /// 一个值写成文字：字符串原样，数原样，别的（`null`、没有）是短横。
    pub(crate) fn text(&self, key: &str) -> String {
        match self.0.get(key) {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) => number.to_string(),
            Some(Value::Bool(flag)) => flag.to_string(),
            Some(Value::Array(items)) => {
                items.iter().map(|item| item.as_str().map_or_else(|| item.to_string(), str::to_owned)).collect::<Vec<_>>().join(",")
            }
            Some(Value::Null | Value::Object(_)) | None => i3t_lang::NONE.to_owned(),
        }
    }

    /// 一样东西：有名字写名字，没有名字写 `#编号`。
    pub(crate) fn thing(&self, name: &str, id: &str) -> String {
        match self.0.get(name) {
            Some(Value::String(text)) if !text.is_empty() => text.clone(),
            _ => format!("#{}", self.text(id)),
        }
    }

    pub(crate) fn flag(&self, key: &str) -> bool {
        self.0.get(key).and_then(Value::as_bool).unwrap_or(false)
    }

    pub(crate) fn has(&self, key: &str) -> bool {
        self.0.get(key).is_some_and(|value| !value.is_null())
    }

    /// 一个嵌套的值，读成模型里的类型；读不懂是 `None`。
    pub(crate) fn decode<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.0.get(key).and_then(|value| serde_json::from_value(value.clone()).ok())
    }

    /// 一列东西（`added`、`removed` 这样的 `[{ "node": 2, "node_name": "laptop" }]`）的名字，没有名字的写 `#编号`。
    pub(crate) fn names(&self, key: &str, name: &str, id: &str) -> Vec<String> {
        let items = self.0.get(key).and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
        items.iter().filter_map(Value::as_object).map(|item| Params(item).thing(name, id)).collect()
    }

    /// `node.update` 里改了的项。
    pub(crate) fn changes(&self) -> Option<&'a Map<String, Value>> {
        self.0.get("changes").and_then(Value::as_object)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use i3t_lang::cli::has_chinese;
    use serde_json::json;

    use super::*;

    fn entry(action: &str, params: Value) -> LogEntry {
        let Value::Object(params) = params else { panic!("参数要是对象") };
        LogEntry { id: 1, at: 0, network: None, action: action.to_owned(), detail: "原话".to_owned(), refs: Vec::new(), params }
    }

    /// controller 记的每一种操作，带着它的参数。
    fn every_action() -> Vec<LogEntry> {
        let node = json!({ "node": 2, "node_name": "laptop" });
        let pair = json!({ "a": 1, "a_name": "nas", "b": 2, "b_name": "laptop", "keep_alive": true, "congestion": null });
        let rule = json!({
            "rule": 3, "rule_name": "ssh", "src": 1, "src_name": "All", "dst": 4, "dst_name": "servers", "direction": "one_way", "enabled": true
        });
        let credential = json!({ "credential": 4, "credential_name": "phone", "max_concurrent": 8, "max_bytes": null, "reset_usage": true, "used_bytes": 10 });
        let listener = json!({ "listener": 5, "listener_name": "lan", "node": 2, "node_name": "laptop", "bind": "127.0.0.1:1080", "protocol": "socks5" });
        let proxy = json!({ "proxy": 5, "proxy_name": "lan", "node": 2, "node_name": "laptop", "bind": "0.0.0.0:1080", "protocol": "mixed", "exit": 3, "exit_name": "gw", "enabled": true });
        let forward = json!({
            "forward": 6, "forward_name": "web", "protocol": "tcp", "listen_node": 2, "listen_node_name": "laptop", "bind": "127.0.0.1:8080",
            "target_node": 1, "target_node_name": "nas", "target_addr": "127.0.0.1:80", "enabled": true
        });
        let failure = json!({ "node": 2, "node_name": "laptop", "version": "0.2.0", "reason": "原话", "cause": { "code": "self_check", "exit_code": 1, "output": "boom" } });
        [
            ("admin.token", json!({})),
            ("network.create", json!({ "network": 1, "network_name": "home", "cidr": "10.66.0.0/16" })),
            ("network.update", json!({ "network": 1, "network_name": "home", "routing": "lowest_cost" })),
            ("network.delete", json!({ "network": 1, "network_name": "home" })),
            ("node.enroll", json!({ "node": 2, "node_name": "laptop", "virtual_ip": "10.66.0.2", "token": 1, "predecessor": 9, "predecessor_name": "old" })),
            ("node.update", json!({ "node": 2, "node_name": "laptop", "changes": {
                "name": { "from": "laptop", "to": "lap" }, "virtual_ip": { "from": "10.66.0.2", "to": "10.66.0.9" },
                "groups": [{ "group": 4, "group_name": "servers" }],
                "dial_out_only": true, "routing": "lowest_cost", "reach": null, "pinned_relays": [1], "auto_update": false
            } })),
            ("node.delete", json!({ "node": 2, "node_name": "laptop", "virtual_ip": "10.66.0.2" })),
            ("node.succeed", json!({ "node": 2, "node_name": "laptop", "predecessor": 9, "predecessor_name": "old" })),
            ("node.relay.enable", node.clone()),
            ("node.relay.disable", node.clone()),
            ("node.relay.withdrawn", node.clone()),
            ("node.exit.enable", node.clone()),
            ("node.exit.disable", node.clone()),
            ("node.exit.withdrawn", node.clone()),
            ("node.forward.withdrawn", json!({ "node": 2, "node_name": "laptop", "forwards": 2 })),
            ("token.create", json!({ "token": 1, "prefix": "i3t-abc" })),
            ("token.delete", json!({ "token": 1, "prefix": "i3t-abc" })),
            ("rule.create", rule.clone()),
            ("rule.update", rule.clone()),
            ("rule.delete", rule),
            ("group.create", json!({ "group": 4, "group_name": "servers" })),
            ("group.rename", json!({ "group": 4, "from": "servers", "to": "boxes" })),
            ("group.delete", json!({ "group": 4, "group_name": "boxes", "nodes": 2, "rules": 1, "tokens": 0 })),
            ("group.members", json!({
                "group": 4, "group_name": "boxes", "added": [{ "node": 2, "node_name": "laptop" }], "removed": [{ "node": 7, "node_name": null }]
            })),
            ("credential.create", credential.clone()),
            ("credential.update", credential.clone()),
            ("credential.revoke", credential.clone()),
            ("credential.delete", credential.clone()),
            ("credential.exhausted", credential),
            ("listener.create", listener.clone()),
            ("listener.update", listener.clone()),
            ("listener.delete", listener),
            ("proxy.create", proxy.clone()),
            ("proxy.update", proxy.clone()),
            ("proxy.delete", proxy),
            ("forward.create", forward.clone()),
            ("forward.update", forward.clone()),
            ("forward.delete", forward),
            ("pair.set", pair.clone()),
            ("pair.delete", pair),
            ("update.settings", json!({ "auto_update": true, "source": "https://example.com", "source_is_default": false })),
            ("update.release", json!({ "version": "0.2.0" })),
            ("update.pause", failure.clone()),
            ("update.failure", failure),
            ("update.resume", json!({ "version": "0.2.0" })),
            ("update.force", json!({ "node": 2, "node_name": "laptop", "timing": "after_drain" })),
            ("update.force_all", json!({ "timing": "now", "nodes": 3, "skipped": 1 })),
            ("test.start", json!({ "test": 7, "a": 1, "a_name": "nas", "b": 2, "b_name": "laptop", "items": ["direct"], "throughput": false })),
            ("test.cancel", json!({ "test": 7, "a": 1, "a_name": "nas", "b": 2, "b_name": "laptop" })),
            ("test.matrix", json!({ "matrix": 1, "nodes": 3, "pairs": 3, "testing": 2 })),
            ("test.matrix.cancel", json!({ "matrix": 1 })),
        ]
        .into_iter()
        .map(|(action, params)| entry(action, params))
        .collect()
    }

    #[test]
    fn every_logged_action_is_written_in_both_languages_from_its_parameters() {
        for entry in every_action() {
            let english = (en::TEXTS.log)(&entry).unwrap_or_else(|| panic!("英文写不出 {}", entry.action));
            assert!(!has_chinese(&english), "{}：{english}", entry.action);
            let chinese = (zh::TEXTS.log)(&entry).unwrap_or_else(|| panic!("中文写不出 {}", entry.action));
            assert!(!chinese.contains("原话"), "{}：要按参数写，不是照抄原话：{chinese}", entry.action);
        }
        let named = (en::TEXTS.log)(&every_action()[4]).unwrap();
        assert!(named.contains("laptop") && named.contains("old"), "{named}");
        let actions = every_action();
        let find = |action: &str| actions.iter().find(|entry| entry.action == action).unwrap();
        let members = (en::TEXTS.log)(find("group.members")).unwrap();
        assert!(members.contains("boxes") && members.contains("laptop") && members.contains("#7"), "{members}");
        let rule = (zh::TEXTS.log)(find("rule.create")).unwrap();
        assert!(rule.contains("All") && rule.contains("servers"), "规则写分组的名字：{rule}");
        let changed = (zh::TEXTS.log)(find("node.update")).unwrap();
        assert!(changed.contains("自动更新关"), "{changed}");
        assert!((en::TEXTS.log)(find("node.update")).unwrap().contains("automatic updates off"));
    }

    /// 参数里的每一个数都换成 1。
    fn ones(value: &mut Value) {
        match value {
            Value::Number(number) => *number = 1.into(),
            Value::Array(items) => items.iter_mut().for_each(ones),
            Value::Object(fields) => fields.values_mut().for_each(ones),
            Value::Null | Value::Bool(_) | Value::String(_) => {}
        }
    }

    #[test]
    fn english_counts_read_right_for_one() {
        let mut said: Vec<String> = every_action()
            .into_iter()
            .map(|mut entry| {
                entry.params.values_mut().for_each(ones);
                (en::TEXTS.log)(&entry).unwrap_or_default()
            })
            .collect();
        let ui = &en::TEXTS.ui;
        let counts = LaneCounts::default();
        said.extend([
            (ui.of_online)(1, 1),
            (ui.recent_requests)(1, 1),
            (ui.per_minute)(1),
            (ui.exit_requests)(1, 1, 1, 1),
            (ui.exit_seen)(1, 1, 1, 1, 1),
            (ui.vnet_traffic)(1, 1, "↑ 1 B  ↓ 1 B", 1),
            (ui.profile_running)("balanced", 1),
            (ui.netmap_versions)(1, 1, 1),
            (ui.update_counts)(1, 1, 1, 1, 1, 1),
            (ui.peer_lanes)(true, true, 1, 1, 1, &(ui.lane_counts)(&counts, "1 B")),
            (ui.handshake_failure_counts)(1, 1, 1, 1, 1),
            (ui.group_deleted)("servers", 1, 1),
            (ui.direct_side)("yes", "ok", 1),
            (ui.other_way_back)(1, 1),
            (ui.throughput_note)("quic", "bbr", "1 B", 1),
            (ui.matrix_progress)(1, 1, 1),
            (ui.wait_timeout)(1),
        ]);
        for text in said {
            assert_eq!(i3t_lang::cli::plural_after_one(&text), None, "{text}");
        }
    }

    #[test]
    fn entries_without_parameters_fall_back_to_what_the_controller_wrote() {
        assert_eq!((en::TEXTS.log)(&entry("node.delete", json!({}))), None);
        assert_eq!((en::TEXTS.log)(&entry("something.new", json!({ "x": 1 }))), None);
    }
}
