//! 把管理 API 的应答打印成给人看的样子。`--json` 时不经过这里。
//!
//! 文字都从文字目录里取（[`crate::texts`]），控制面的代码（原因、状态）按 `i3t_lang::codes` 写，数和时间按 [`Lang`] 的方法写。

use i3t_lang::codes::Codes;
use i3t_lang::table::{Fields, Table};
use i3t_lang::{Lang, NONE, optional};
use i3t_model::admin::stats::{SeriesView, Unit};
use i3t_model::admin::{
    AccessCheck, AccessGraph, BackboneView, CreatedEnrollToken, DeletedGroup, Direction, EnrollTokenInfo, ExitTestView, ExitView,
    ForcedUpdates, Forward, Group, GroupRef, LaneSide, ListenStatus, LogEntry, Network, Node, NodeAccess, NodeDetail, NodeListeners,
    NodeRef, NodeUpdate, Overview, PairView, PathLeg, PathSource, PathView, Proxy, RelayEnabled, RelayReach, RouteMatrix, RouteTable, Rule,
    Status, UpdateOverview,
};
use i3t_model::control::exit_test::ExitTestCause;
use i3t_model::control::{
    DirectKind, DirectStatus, LaneCounts, LaneReport, LegTransport, PathSegment, PeerLanes, PerformanceReport, Route, VnetReport, VnetState,
};
use i3t_model::netmap::{IpFamily, ListenerProtocol, Profile};
use i3t_model::update::UpdateTiming;
use i3t_proto::NodeId;
use i3t_proto::flow::Class;

use crate::texts::{Ui, texts};

mod diag;

pub use diag::{matrix, test, tests};

/// 把节点编号写成名字用的表：路上的 relay、代理监听的节点这些，应答里只有编号。表里没有的写成 `#编号`。
#[derive(Debug, Default)]
pub struct Names(Vec<(NodeId, String)>);

impl Names {
    pub fn new(nodes: &[Node]) -> Self {
        Self(nodes.iter().map(|node| (node.id, node.name.clone())).collect())
    }

    pub fn of(&self, id: NodeId) -> String {
        self.0.iter().find(|(known, _)| *known == id).map_or_else(|| format!("#{id}"), |(_, name)| name.clone())
    }
}

/// 这一次要用的文字、语言和代码的写法。
fn context() -> (&'static Ui, Lang, &'static Codes) {
    let lang = i3t_lang::current();
    (&crate::texts::texts_in(lang).ui, lang, lang.codes())
}

/// 枚举在 JSON 里的写法（`direct_first` 之类）。命令行上要写的值（选路模式、协议）照这个显示，和参数的写法一致；QoS 显示它的名字（`codes.class`）。
pub fn label<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        Ok(other) => other.to_string(),
        Err(_) => NONE.to_owned(),
    }
}

fn yes_no(value: bool) -> String {
    let t = &texts().ui;
    if value { t.yes } else { t.no }.to_owned()
}

fn on_off(on: bool) -> String {
    let t = &texts().ui;
    if on { t.on } else { t.off }.to_owned()
}

fn online(online: bool) -> &'static str {
    let t = &texts().ui;
    if online { t.online } else { t.offline }
}

pub fn status(status: &Status) {
    let (t, _, _) = context();
    println!("controller {}", status.version);
    let mut fields = Fields::new(2);
    fields.add(t.key, status.controller_key.to_string());
    fields.add(t.public_addr, status.public_addr.clone());
    fields.add(t.networks, status.networks.to_string());
    fields.add(t.nodes, (t.of_online)(u64::from(status.nodes), u64::from(status.online)));
    if let Some(newer) = &status.newer_version {
        fields.add(t.newer_version, newer.to_string());
    }
    fields.print();
}

pub fn overview(overview: &Overview) {
    let (t, lang, codes) = context();
    let mut fields = Fields::new(0);
    fields.add(t.nodes, (t.of_online)(u64::from(overview.nodes), u64::from(overview.online)));
    fields.add(t.relays, overview.relays.to_string());
    fields.add(t.exits, overview.exits.to_string());
    fields.add(t.rules, overview.rules.to_string());
    fields.add(t.proxies, overview.proxies.to_string());
    fields.add(t.forwards, overview.forwards.to_string());
    fields.add(t.pending_tokens, overview.pending_tokens.to_string());
    fields.add(t.flows, overview.flows.to_string());
    fields.add(t.traffic, format!("↑ {}  ↓ {}", lang.bytes(overview.tx_bytes), lang.bytes(overview.rx_bytes)));
    fields.add(t.online, lang.list(overview.online_nodes.iter().map(node_name)));
    fields.print();
    if !overview.warnings.is_empty() {
        println!("\n{}", lang.labelled(t.warnings, "").trim_end());
        for warning in &overview.warnings {
            println!("  {}", lang.labelled(node_name(&warning.node), &(codes.node_warning)(&warning.warning)));
        }
    }
    if overview.unreachable_pairs.is_empty() {
        return;
    }
    println!("\n{}", t.unreachable_pairs);
    for pair in &overview.unreachable_pairs {
        println!("  {} ↔ {}", node_name(&pair.a), node_name(&pair.b));
    }
    if overview.relays == 0 {
        println!("{}", t.no_relay_hint);
    }
}

/// 一条时间序列：每一段一行，没有数据的段写"—"。
pub fn series(view: &SeriesView) {
    let (t, lang, _) = context();
    let mut table = Table::new(&t.stats_header);
    for (at, value) in &view.points {
        let value = value.map_or_else(|| NONE.to_owned(), |value| series_value(view.unit, value));
        table.row(vec![lang.time(*at), value]);
    }
    print_table(&table, t.none_found);
}

fn series_value(unit: Unit, value: f64) -> String {
    match unit {
        Unit::Count => format!("{value:.1}"),
        Unit::BytesPerSecond => format!("{:.1} Mbit/s", value * 8.0 / 1_000_000.0),
    }
}

pub fn log(entries: &[LogEntry]) {
    let (t, lang, _) = context();
    let mut table = Table::new(&t.log_header);
    for entry in entries {
        let said = (texts().log)(entry).unwrap_or_else(|| entry.detail.clone());
        table.row(vec![entry.id.to_string(), lang.time(entry.at), optional(entry.network), entry.action.clone(), said]);
    }
    print_table(&table, t.none_found);
}

/// 一张表；没有行时说一声"没有"，不打印一个光秃秃的表头。
fn print_table(table: &Table, empty: &str) {
    if table.is_empty() { println!("{empty}") } else { table.print() }
}

pub fn groups(groups: &[Group]) {
    let (t, lang, _) = context();
    let mut table = Table::new(&t.groups_header);
    for group in groups {
        let name = if group.builtin { lang.paren(&group.name, t.builtin) } else { group.name.clone() };
        table.row(vec![group.id.to_string(), name, group.nodes.len().to_string(), group.rules.len().to_string()]);
    }
    print_table(&table, t.no_groups);
}

/// 一个分组：成员和用到它的规则。
pub fn group(group: &Group) {
    let (t, lang, _) = context();
    let title = format!("{} #{}", group.name, group.id);
    println!("{}", if group.builtin { lang.paren(&title, t.builtin) } else { title });
    let mut fields = Fields::new(2);
    fields.add(t.nodes, lang.list(group.nodes.iter().map(node_name)));
    fields.add(t.rules, lang.list(group.rules.iter().map(rule_text)));
    fields.print();
}

pub fn deleted_group(deleted: &DeletedGroup) {
    let (t, _, _) = context();
    println!("{}", (t.group_deleted)(&deleted.name, deleted.nodes.len(), deleted.rules.len()));
}

fn group_names(lang: Lang, groups: &[GroupRef]) -> String {
    lang.list(groups.iter().map(|group| group.name.as_str()))
}

fn listen_cells(status: Option<&ListenStatus>) -> [String; 3] {
    let (_, lang, codes) = context();
    let Some(status) = status else { return [NONE.to_owned(), NONE.to_owned(), NONE.to_owned()] };
    let traffic = format!("↑ {}  ↓ {}", lang.bytes(status.traffic.bytes_up), lang.bytes(status.traffic.bytes_down));
    [(codes.listen_state)(&status.state), status.traffic.connections.to_string(), traffic]
}

pub fn node_listeners(view: &NodeListeners) {
    let (t, _, _) = context();
    if !view.online {
        println!("{}", (t.node_offline)(&view.node.name));
        return;
    }
    let mut table = Table::new(&t.node_listeners_header);
    for listener in &view.listeners {
        let [state, connections, traffic] = listen_cells(Some(&listener.status));
        let id = if listener.builtin { t.builtin.to_owned() } else { optional(listener.id) };
        table.row(vec![id, listener.name.clone(), listener.bind.to_string(), label(&listener.protocol), connections, traffic, state]);
    }
    for forward in &view.forwards {
        let [state, connections, traffic] = listen_cells(Some(&forward.status));
        let name = (t.forward_name)(forward.id);
        table.row(vec![forward.id.to_string(), name, forward.bind.to_string(), label(&forward.protocol), connections, traffic, state]);
    }
    print_table(&table, t.none_found);
}

pub fn exit_test(view: &ExitTestView) {
    print!("{}", exit_test_text(view));
}

/// 出口测试的结果，每行以换行结尾。
fn exit_test_text(view: &ExitTestView) -> String {
    let (t, lang, codes) = context();
    let Some(result) = &view.result else {
        return format!("{}\n", (t.exit_unanswered)(&view.node.name));
    };
    // 出口忙着不是它的策略不连这个目标：一句话说完，不列步骤。
    if result.refused == Some(ExitTestCause::Busy) {
        return format!("{}\n", (t.exit_busy)(&view.node.name));
    }
    let header = lang.paren(&format!("{} → {}", view.node.name, view.target), (codes.exit_via)(result.via));
    // 节点上报的是截断后的整毫秒值：0 表示不足 1 毫秒而非未执行。JSON 输出仍保持原值 0。
    let ms = |ms: u32| if ms == 0 { "<1 ms".to_owned() } else { format!("{ms} ms") };
    let outcome = |cause: Option<&ExitTestCause>, ok: String| cause.map_or(ok, codes.exit_test_cause);
    let mut fields = Fields::new(2);
    if let Some(step) = &result.resolve {
        let mut found = lang.list(&step.addresses);
        if step.family != IpFamily::Any {
            found = format!("{found}  {}", (t.family_only)(&label(&step.family)));
        }
        fields.add(t.resolve_step, format!("{}  {}", ms(step.ms), outcome(step.cause.as_ref(), found)));
    }
    if let Some(step) = &result.connect {
        let address = step.address.map(|address| address.to_string()).unwrap_or_default();
        fields.add(t.connect_step, format!("{}  {}", ms(step.ms), outcome(step.cause.as_ref(), address)));
    }
    if let Some(step) = &result.tls {
        fields.add(t.tls_step, format!("{}  {}", ms(step.ms), outcome(step.cause.as_ref(), t.tls_done.to_owned())));
    }
    if let Some(cause) = &result.refused {
        fields.add(t.exit_refused, (codes.exit_test_cause)(cause));
    }
    format!("{header}\n{fields}")
}

pub fn exits(exits: &[ExitView], names: &Names) {
    let (t, lang, codes) = context();
    if exits.is_empty() {
        println!("{}", t.no_exits);
    }
    for (index, exit) in exits.iter().enumerate() {
        if index > 0 {
            println!();
        }
        let settings = &exit.settings;
        println!("{}", lang.paren(&exit.node.name, online(exit.online)));
        let unlimited = || t.unlimited.to_owned();
        let mut fields = Fields::new(2);
        fields.add(t.health, (codes.exit_health)(exit.health).to_owned());
        fields.add(t.recent, (t.recent_requests)(exit.recent_requests, exit.recent_failures));
        fields.add(t.ports, settings.ports.as_ref().map_or_else(unlimited, |ports| lang.list(ports)));
        fields.add(t.lan, yes_no(settings.lan));
        fields.add(t.family, label(&settings.family));
        fields.add(t.connects, settings.connects_per_minute.map_or_else(unlimited, |count| (t.per_minute)(count)));
        if let Some(usage) = &exit.usage {
            fields.add(t.requests, (t.exit_requests)(usage.total, usage.failed_by_target, usage.refused, usage.failed_by_exit));
            fields.add(t.traffic, format!("→ {}  ← {}", lang.bytes(usage.bytes_to_target), lang.bytes(usage.bytes_from_target)));
            if usage.draining {
                fields.add(t.state, t.draining.to_owned());
            }
            if let Some(quota) = usage.quota {
                let period = format!("{} – {}", lang.time(quota.period_start), lang.time(quota.period_end));
                fields.add(t.quota, format!("{} / {}  {period}", lang.bytes(quota.used_bytes), lang.bytes(quota.limit_bytes)));
            }
        }
        for seen in &exit.observed {
            let counts = &seen.counts;
            let traffic = format!("↑ {}  ↓ {}", lang.bytes(counts.bytes_up), lang.bytes(counts.bytes_down));
            let failures = (t.exit_seen)(counts.flows, counts.failed_by_target, counts.refused, counts.failed_by_exit, counts.unreachable);
            fields.add(&(t.seen_by)(&seen.by.name), format!("{failures}  {traffic}"));
        }
        for proxy in &exit.proxies {
            fields.add(
                t.proxy,
                format!("#{} {}  {} {}  {}", proxy.id, proxy.name, names.of(proxy.node), proxy.bind, (codes.proxy_status)(&proxy.status)),
            );
        }
        fields.print();
    }
}

pub fn networks(networks: &[Network]) {
    let (t, _, _) = context();
    let mut table = Table::new(&t.networks_header);
    for network in networks {
        table.row(vec![
            network.id.to_string(),
            network.name.clone(),
            network.cidr.to_string(),
            network.nodes.to_string(),
            label(&network.routing),
            label(&network.reach),
            network.max_relay_hops.to_string(),
        ]);
    }
    print_table(&table, t.no_networks);
}

pub fn network(network: &Network) {
    let (t, _, codes) = context();
    println!("{} #{}", network.name, network.id);
    let defaults = network.defaults.as_ref();
    // 一项设置的值；和 controller 报的默认值不一样时，后面写上默认值，一眼看得出哪些改过。
    let setting = |value: String, default: Option<String>| match default {
        Some(default) if default != value => format!("{value}{}", (t.default_is)(&default)),
        _ => value,
    };
    let class = |class: Option<Class>| (codes.class)(class.unwrap_or_default()).to_owned();
    let millis = |ms: u32| format!("{ms} ms");
    let mut fields = Fields::new(2);
    fields.add(t.domain, network.domain.clone());
    fields.add(t.cidr, network.cidr.to_string());
    fields.add(t.nodes, network.nodes.to_string());
    fields.add(t.routing, setting(label(&network.routing), defaults.map(|defaults| label(&defaults.routing))));
    fields.add(t.reach, setting(label(&network.reach), defaults.map(|defaults| label(&defaults.reach))));
    fields.add(t.max_relay_hops, setting(network.max_relay_hops.to_string(), defaults.map(|defaults| defaults.max_relay_hops.to_string())));
    fields.add(t.class, setting(class(network.class), defaults.map(|defaults| class(defaults.class))));
    fields.add(
        t.ack_eliciting_threshold,
        setting(network.ack_eliciting_threshold.to_string(), defaults.map(|defaults| defaults.ack_eliciting_threshold.to_string())),
    );
    fields.add(t.max_ack_delay, setting(millis(network.max_ack_delay_ms), defaults.map(|defaults| millis(defaults.max_ack_delay_ms))));
    fields.add(
        t.bundle_small_packets,
        setting(on_off(network.bundle_small_packets), defaults.map(|defaults| on_off(defaults.bundle_small_packets))),
    );
    fields.add(t.vnet_offload, setting(on_off(network.vnet_offload), defaults.map(|defaults| on_off(defaults.vnet_offload))));
    fields.add(t.vnet_mtu, setting(network.vnet_mtu.to_string(), defaults.map(|defaults| defaults.vnet_mtu.to_string())));
    fields.print();
}

pub fn nodes(nodes: &[Node]) {
    let (t, lang, _) = context();
    let mut table = Table::new(&t.nodes_header);
    for node in nodes {
        table.row(vec![
            node.id.to_string(),
            node.name.clone(),
            node.virtual_ip.to_string(),
            online(node.online).to_owned(),
            roles(node),
            node.version.clone(),
            node.platform.clone(),
            group_names(lang, &node.groups),
        ]);
    }
    print_table(&table, t.no_nodes);
}

/// 展示已启用的中继列表：在线节点对其的可达性统计（由各节点上报，仅反映现状而非故障）、地址数量、带宽上限，
/// 以及最近一个统计窗口的每秒转发速率。
pub fn relays(nodes: &[Node]) {
    let (t, lang, _) = context();
    let mut table = Table::new(&t.relays_header);
    for node in nodes {
        let Some(relay) = &node.relay else { continue };
        table.row(vec![
            node.id.to_string(),
            node.name.clone(),
            online(node.online).to_owned(),
            reach_cell(&relay.reach),
            relay.addresses.len().to_string(),
            bandwidth(relay.bandwidth_mbps),
            optional(relay.users.as_ref().map(|users| {
                let total = users.pairs.iter().map(|pair| pair.bytes).fold(users.other_bytes, u64::saturating_add);
                format!("{}/s", lang.bytes(total / u64::from(users.window_secs.max(1))))
            })),
        ]);
    }
    print_table(&table, t.no_relays);
}

/// 将在线节点中可达、不可达与未上报的数量格式化为 `3/1/0`。
fn reach_cell(reach: &RelayReach) -> String {
    format!("{}/{}/{}", reach.reached, reach.unreached, reach.unknown)
}

fn roles(node: &Node) -> String {
    let (t, lang, _) = context();
    let roles =
        [node.relay.is_some().then_some(t.relay), node.exit.is_some().then_some(t.exit), node.forward_target.then_some(t.forward_target)];
    lang.list(roles.into_iter().flatten())
}

/// 改动节点之后的回显：现在是什么样。
pub fn node_changed(node: &Node) {
    let (t, lang, _) = context();
    println!("{} #{}  {}  {}", node.name, node.id, node.virtual_ip, node.fqdn);
    let mut fields = Fields::new(2);
    fields.add(t.groups, group_names(lang, &node.groups));
    fields.add(t.roles, roles(node));
    fields.print();
}

/// 启用 relay 之后的回显，加上 controller 试连每个地址的结果。
pub fn relay_enabled(enabled: &RelayEnabled) {
    let (t, _, codes) = context();
    node_changed(&enabled.node);
    if enabled.reachability.is_empty() {
        return;
    }
    println!("\n{}", t.reachability);
    let mut table = Table::new(&t.reachability_header).indented(2);
    for check in &enabled.reachability {
        let result = match (check.reachable, check.cause) {
            (true, _) => t.reachable.to_owned(),
            (false, Some(cause)) => (codes.reach_cause)(cause).to_owned(),
            (false, None) => check.error.clone().unwrap_or_default(),
        };
        table.row(vec![label(&check.protocol), check.addr.to_string(), optional(check.rtt_ms), result]);
    }
    table.print();
    if enabled.reachability.iter().any(|check| !check.reachable) {
        println!("{}", t.reachability_note);
    }
}

pub fn node_detail(detail: &NodeDetail, names: &Names) {
    let (t, lang, codes) = context();
    let node = &detail.node;
    println!("{} #{}", node.name, node.id);
    let mut fields = Fields::new(2);
    fields.add(t.fqdn, node.fqdn.clone());
    fields.add(t.virtual_ip, node.virtual_ip.to_string());
    fields.add(t.key, node.key.to_string());
    fields.add(t.groups, group_names(lang, &node.groups));
    let state = if node.online {
        t.online.to_owned()
    } else {
        lang.paren(t.offline, &lang.labelled(t.last_seen, &node.last_seen_at.map_or_else(|| t.never.to_owned(), |at| lang.time(at))))
    };
    fields.add(t.state, state);
    fields.add(t.version, format!("{} / {}", node.version, node.platform));
    fields.add(t.hostname, if node.hostname.is_empty() { NONE.to_owned() } else { node.hostname.clone() });
    fields.add(t.update, update_summary(&node.update));
    fields.add(t.auto_update, on_off(node.auto_update));
    let declared = [node.declared.relay.then_some(t.relay), node.declared.exit.then_some(t.exit)];
    fields.add(t.declared, lang.list(declared.into_iter().flatten()));
    if let Some(address) = node.declared.relay_address {
        fields.add(t.declared_address, address.to_string());
    }
    let relay = node.relay.as_ref().map_or_else(
        || t.disabled.to_owned(),
        |relay| {
            let addresses =
                relay.addresses.iter().map(|entry| (t.relay_address)(&entry.address.to_string(), (codes.address_source)(entry.source)));
            let addresses: Vec<String> = addresses.collect();
            let addresses = if addresses.is_empty() { t.no_address_yet.to_owned() } else { lang.list(addresses) };
            (t.relay_settings)(&addresses, &bandwidth(relay.bandwidth_mbps))
        },
    );
    fields.add(t.relay, relay);
    if let Some(relay) = &node.relay {
        fields.add(t.relay_reach, (t.reach_counts)(relay.reach.reached, relay.reach.unreached, relay.reach.unknown));
    }
    let exit = node.exit.as_ref().map_or_else(
        || t.disabled.to_owned(),
        |exit| {
            let ports = exit.ports.as_ref().map_or_else(|| t.unlimited.to_owned(), |ports| lang.list(ports));
            (t.exit_settings)(&ports, &yes_no(exit.lan), &optional(exit.upstream_socks5))
        },
    );
    fields.add(t.exit, exit);
    fields.add(t.forward_target, yes_no(node.forward_target));
    fields.add(t.dial_out_only, yes_no(node.dial_out_only));
    fields.add(t.routing, node.routing.as_ref().map_or_else(|| t.from_network.to_owned(), label));
    fields.add(t.reach, node.reach.as_ref().map_or_else(|| t.from_network.to_owned(), label));
    fields.add(t.pinned, lang.list(node.pinned_relays.iter().map(|relay| names.of(*relay))));
    fields.add(t.profile, profile_summary(node.profile, detail.performance.as_ref()));
    if let Some(vnet) = &detail.vnet {
        fields.add(t.vnet, vnet_summary(vnet));
    }
    fields.add("netmap", (t.netmap_versions)(node.netmap_version, node.sent_version, node.acked_version));
    fields.add(t.endpoints, lang.list(&detail.endpoints));
    fields.add(t.observed, optional(detail.observed_endpoint));
    let egress = node.egress_ip.map(|ip| node.country.as_ref().map_or_else(|| ip.to_string(), |country| format!("{ip} {country}")));
    fields.add(t.egress, optional(egress));
    let attached = node.attached.iter().map(|attachment| {
        let line = format!("{} {} ms", names.of(attachment.relay), attachment.rtt_ms);
        if attachment.shared { lang.paren(&line, t.shared_attachment) } else { line }
    });
    fields.add(t.attached, lang.list(attached));
    if detail.mapping_varies == Some(true) {
        fields.add(t.nat, t.mapping_varies.to_owned());
    }
    if node.no_udp {
        fields.add("UDP", t.no_udp.to_owned());
    }
    fields.add(t.flows, detail.flows.to_string());
    fields.add(t.traffic, format!("↑ {}  ↓ {}", lang.bytes(detail.tx_bytes), lang.bytes(detail.rx_bytes)));
    if let Some(ago) = detail.reported_secs_ago {
        fields.add(t.reported, lang.ago(ago));
    }
    if !node.warnings.is_empty() {
        fields.add(t.warnings, lang.list(node.warnings.iter().map(|warning| (codes.node_warning)(warning))));
    }
    fields.print();
    if let Some(lanes) = &detail.lanes {
        lane_report(lanes);
    }
    if let Some(users) = node.relay.as_ref().and_then(|relay| relay.users.as_ref()).filter(|users| !users.pairs.is_empty()) {
        println!();
        let rate = |bytes: u64| format!("{}/s", lang.bytes(bytes / u64::from(users.window_secs.max(1))));
        let mut table = Table::new(&t.relay_users_header);
        for pair in &users.pairs {
            table.row(vec![names.of(pair.from), names.of(pair.to), rate(pair.bytes)]);
        }
        if users.other_bytes > 0 {
            table.row(vec![t.relay_users_other.to_owned(), String::new(), rate(users.other_bytes)]);
        }
        table.print();
    }
    if let Some(reached_by) = detail.reached_by.as_ref().filter(|entries| !entries.is_empty()) {
        println!();
        let mut table = Table::new(&t.reached_by_header);
        for entry in reached_by {
            table.row(vec![
                entry.node.name.clone(),
                online(entry.online).to_owned(),
                (codes.try_outcome)(entry.outcome).to_owned(),
                lang.time(entry.at),
            ]);
        }
        table.print();
    }
}

/// 节点报的虚拟网卡：状态，装着时加上防火墙规则和收发的计数。
fn vnet_summary(report: &VnetReport) -> String {
    let (t, lang, codes) = context();
    let state = (codes.vnet_state)(&report.state);
    match report.state {
        VnetState::Installed { .. } => {
            let traffic = format!("↑ {}  ↓ {}", lang.bytes(report.sent_bytes), lang.bytes(report.received_bytes));
            let counts = (t.vnet_traffic)(report.sent_packets, report.received_packets, &traffic, report.dropped.total());
            lang.list([state, (codes.firewall)(&report.firewall), counts])
        }
        VnetState::Off | VnetState::Failed { .. } | VnetState::Unsupported | VnetState::Unknown => state,
    }
}

/// 管理员选的档位，加上节点报的实际情况（在线并且报过时）。
fn profile_summary(chosen: Option<Profile>, running: Option<&PerformanceReport>) -> String {
    let (t, lang, _) = context();
    let chosen = chosen.map_or(t.profile_local, Profile::spelling);
    let Some(running) = running else { return chosen.to_owned() };
    let mut notes = vec![(t.profile_running)(running.profile.spelling(), running.threads)];
    if running.restart_pending {
        notes.push(t.restart_pending.to_owned());
    }
    if !running.overrides.is_empty() {
        notes.push((t.local_overrides)(&lang.list(&running.overrides)));
    }
    lang.paren(chosen, &lang.list(notes))
}

/// relay 的带宽上限。出口没有带宽上限。
fn bandwidth(mbps: Option<u32>) -> String {
    let (t, _, _) = context();
    mbps.map_or_else(|| t.unlimited.to_owned(), |mbps| format!("{mbps} Mbit/s"))
}

/// 一个节点的路由表。路上的 relay 按 `names` 写成名字（relay 不一定是这个节点的对端）。
pub fn routes(table: &RouteTable, names: &Names) {
    let (t, lang, codes) = context();
    if !table.online {
        println!("{}", (t.node_offline)(&table.node.name));
        return;
    }
    let name = |id: NodeId| names.of(id);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
    let mut rows = Table::new(&t.routes_header);
    for entry in &table.routes {
        let direct = entry.direct_status.map_or_else(
            || NONE.to_owned(),
            |view| {
                // controller 给的是时刻；写成"多久之前"，和节点上 `i3t routes` 的一样。
                let attempted_secs_ago = view.attempted_at.map(|at| now.saturating_sub(at));
                (codes.direct_status)(&DirectStatus { state: view.state, kind: view.kind, cause: view.cause, attempted_secs_ago })
            },
        );
        rows.row(vec![
            entry.peer.name.clone(),
            entry.peer.virtual_ip.to_string(),
            (codes.route)(&entry.route, &name),
            optional(entry.rtt_ms),
            kind_cell(&entry.route, entry.direct, entry.relay_leg),
            direct,
            // 这个节点没在用的那种选路模式此刻会选的路。
            entry.alternative.as_ref().map_or_else(
                || NONE.to_owned(),
                |other| {
                    let route = (codes.route)(&other.route, &name);
                    other.rtt_ms.map_or_else(|| route.clone(), |rtt| format!("{route}  {rtt} ms"))
                },
            ),
            lang.ago(entry.since_secs),
            optional(entry.flows),
            match (entry.tx_bytes, entry.rx_bytes) {
                (Some(tx), Some(rx)) => format!("{} / {}", lang.bytes(tx), lang.bytes(rx)),
                _ => NONE.to_owned(),
            },
        ]);
    }
    print_table(&rows, t.no_peers);
}

/// 展示路径传输方式：直连的建立方式，或经中继时到首跳中继的传输协议（UDP 或 TCP）；节点未上报时显示短横。
fn kind_cell(route: &Route, direct: Option<DirectKind>, relay_leg: Option<LegTransport>) -> String {
    let (_, _, codes) = context();
    match route {
        Route::Direct { .. } => optional(direct.map(codes.direct_kind)),
        Route::Relay { .. } => optional(relay_leg.map(codes.leg)),
        Route::None => NONE.to_owned(),
    }
}

pub fn route_matrix(matrix: &RouteMatrix) {
    let (t, lang, codes) = context();
    let name = |id| matrix.nodes.iter().find(|node| node.node.id == id).map_or_else(|| format!("#{id}"), |node| node.node.name.clone());
    let mut rows = Table::new(&t.matrix_header);
    for entry in &matrix.entries {
        rows.row(vec![
            name(entry.from),
            name(entry.to),
            (codes.route)(&entry.route, &name),
            optional(entry.rtt_ms),
            kind_cell(&entry.route, entry.direct, entry.relay_leg),
            if entry.stale { lang.paren(&lang.ago(entry.age_secs), t.stale) } else { lang.ago(entry.age_secs) },
        ]);
    }
    print_table(&rows, t.none_found);
    let silent: Vec<&str> = matrix
        .nodes
        .iter()
        .filter(|node| !matrix.entries.iter().any(|entry| entry.from == node.node.id))
        .map(|node| node.node.name.as_str())
        .collect();
    if !silent.is_empty() {
        println!("\n{}", lang.labelled(t.never_reported, &lang.list(silent)));
    }
}

pub fn path(view: &PathView, names: &Names) {
    let (t, lang, codes) = context();
    let name = |id: NodeId| names.of(id);
    let mut rows = Table::new(&t.path_header);
    for leg in [&view.forward, &view.reverse] {
        let route = leg.route.as_ref().map_or_else(|| NONE.to_owned(), |route| (codes.route)(route, &name));
        let kind = leg.route.as_ref().map_or_else(|| NONE.to_owned(), |route| kind_cell(route, leg.direct, leg.relay_leg));
        rows.row(vec![
            format!("{} → {}", leg.from.name, leg.to.name),
            route,
            optional(leg.rtt_ms),
            optional(leg.connection_rtt_ms),
            kind,
            (codes.path_source)(leg.source).to_owned(),
            leg.age_secs.map_or_else(|| NONE.to_owned(), |age| lang.ago(age)),
        ]);
    }
    rows.print();
    for leg in [&view.forward, &view.reverse] {
        if let Some(note) = path_note(leg, &name) {
            println!("{} → {}  {note}", leg.from.name, leg.to.name);
        }
    }
    for leg in [&view.forward, &view.reverse] {
        path_candidates(leg, &name);
    }
    for leg in [&view.forward, &view.reverse] {
        path_switches(leg, &name);
    }
}

/// 一个方向最近的换路：什么时候、从什么换成了什么、为什么。
fn path_switches(leg: &PathLeg, name: &dyn Fn(NodeId) -> String) {
    let (t, lang, codes) = context();
    if leg.switches.is_empty() {
        return;
    }
    println!("\n{}", (t.switches_of)(&leg.from.name, &leg.to.name));
    for switch in &leg.switches {
        let step = format!("{} → {}", (codes.route)(&switch.from, name), (codes.route)(&switch.to, name));
        println!("  {}  {}  {}", lang.time(switch.at), step, (codes.route_cause)(&switch.cause, name));
    }
}

/// 生成单个方向的补充说明：路径切换原因或数据来源。
fn path_note(leg: &PathLeg, name: &dyn Fn(NodeId) -> String) -> Option<String> {
    let (t, lang, codes) = context();
    match leg.source {
        PathSource::Query => leg.since.as_ref().map(|since| {
            let why = since.cause.as_ref().map_or_else(|| since.reason.clone(), |cause| (codes.route_cause)(cause, name));
            lang.labelled(&(t.switched_ago)(&lang.ago(since.secs_ago)), &why)
        }),
        PathSource::Report => Some((t.path_from_report)(&leg.from.name)),
        PathSource::None => Some(t.path_no_data.to_owned()),
        PathSource::NotPeers => Some(t.path_not_peers.to_owned()),
        PathSource::Unknown => None,
    }
}

/// 发送方考虑过的候选路径：每条一行，现在走的那条打星号。节点没有说的时候不打印。
fn path_candidates(leg: &PathLeg, name: &dyn Fn(NodeId) -> String) {
    let (t, lang, codes) = context();
    let Some(candidates) = &leg.candidates else { return };
    let mode = optional(leg.mode.as_ref().map(label));
    println!("\n{}", (t.candidates_of)(&leg.from.name, &leg.to.name, &mode));
    let why =
        leg.cause.as_ref().map(|cause| (codes.route_cause)(cause, name)).or_else(|| leg.reason.clone().filter(|reason| !reason.is_empty()));
    if let Some(why) = why {
        println!("  {}", lang.labelled(t.why_this_route, &why));
    }
    if candidates.is_empty() {
        println!("  {}", t.no_measurements);
        return;
    }
    let mut rows = Table::new(&t.candidates_header).indented(2);
    for candidate in candidates {
        let legs = candidate.legs.iter().map(|segment| leg_text(segment, name)).collect::<Vec<_>>().join("; ");
        rows.row(vec![
            if candidate.current { "*" } else { "" }.to_owned(),
            (codes.route)(&candidate.route, name),
            lang.millis(candidate.cost_us),
            candidate.load_percent.to_string(),
            legs,
        ]);
    }
    rows.print();
}

/// 一段的测量值：`laptop→hk-1 20.4 ms ±0.5 1.2%`。
fn leg_text(segment: &PathSegment, name: &dyn Fn(NodeId) -> String) -> String {
    let (t, lang, _) = context();
    (t.segment)(
        &name(segment.from),
        &name(segment.to),
        &lang.millis(u64::from(segment.rtt_us)),
        &lang.millis(u64::from(segment.jitter_us)),
        &lang.percent(segment.loss_permille),
    )
}

pub fn backbone(view: &BackboneView) {
    let (t, lang, codes) = context();
    if view.relays.is_empty() {
        println!("{}", t.no_relays);
        return;
    }
    let name = |id: NodeId| {
        view.relays.iter().find(|relay| relay.relay.id == id).map_or_else(|| format!("#{id}"), |relay| relay.relay.name.clone())
    };
    let mut rows = Table::new(&t.backbone_header);
    for relay in &view.relays {
        let links = relay.links.iter().map(|link| match link.rtt_ms {
            Some(rtt) => (t.backbone_link)(&name(link.to), rtt, link.jitter_ms, &lang.percent(link.loss_permille)),
            None => (t.backbone_down)(&name(link.to)),
        });
        rows.row(vec![
            relay.relay.name.clone(),
            online(relay.online).to_owned(),
            optional(relay.state.map(codes.relay_state)),
            optional(relay.load_percent),
            optional(relay.age_ms),
            optional(relay.reported_by.map(|from| {
                view.answered.iter().find(|node| node.id == from).map_or_else(|| format!("#{from}"), |node| node.name.clone())
            })),
            reach_cell(&relay.reach),
            lang.list(links),
        ]);
    }
    rows.print();
    if view.answered.is_empty() {
        println!("\n{}", t.backbone_nobody);
    }
}

pub fn update_overview(overview: &UpdateOverview) {
    let (t, lang, codes) = context();
    let mut fields = Fields::new(0);
    fields.add(t.auto_update, on_off(overview.auto_update));
    let source = if overview.source_is_default { lang.paren(&overview.source, t.default) } else { overview.source.clone() };
    fields.add(t.source, source);
    fields.add("controller", overview.controller_version.to_string());
    match &overview.release {
        Some(release) => {
            fields.add(t.latest, lang.paren(&release.version.to_string(), &lang.time(release.published)));
            if let Some(floor) = &release.security_floor {
                fields.add(t.security, (t.security_floor)(&floor.to_string()));
            }
        }
        None => fields.add(t.latest, t.not_found_yet.to_owned()),
    }
    fields.add(t.checked, overview.checked_at.map_or_else(|| t.never.to_owned(), |at| lang.time(at)));
    if let Some(error) = &overview.check_error {
        let why = overview.check_cause.as_ref().map_or_else(|| error.clone(), codes.release_cause);
        fields.add(t.check_failed, why);
    }
    let nodes = overview.nodes;
    fields.add(t.nodes, (t.update_counts)(nodes.total, nodes.updating, nodes.outdated, nodes.manual, nodes.failed, nodes.up_to_date));
    fields.print();
    if let Some(release) = &overview.release {
        if release.controller_too_old {
            println!("{}", (t.controller_too_old)(&release.min_controller.to_string()));
        } else if release.newer_than_controller {
            println!("{}", (t.controller_newer)(&release.version.to_string()));
        }
        println!();
        let mut packages = Table::new(&t.packages_header).indented(2);
        for package in &release.packages {
            let error = package.cause.as_ref().map(codes.release_cause).or_else(|| package.error.clone());
            packages.row(vec![
                package.platform.clone(),
                lang.bytes(package.size),
                (codes.package_state)(package.state).to_owned(),
                optional(error),
            ]);
        }
        packages.print();
    }
    for paused in &overview.paused {
        let node = paused.node.as_ref().map_or(t.deleted_node, node_name);
        let why = paused.cause.as_ref().map_or_else(|| paused.reason.clone(), codes.update_cause);
        println!("\n{}", (t.paused)(&paused.version.to_string(), node, &lang.time(paused.at), &why));
        println!("{}", (t.resume_hint)(&paused.version.to_string()));
    }
}

pub fn node_updates(nodes: &[Node]) {
    let (t, _, codes) = context();
    let mut table = Table::new(&t.node_updates_header);
    for node in nodes {
        let ability = match node.update.self_update {
            None => t.too_old.to_owned(),
            Some(ability) if ability.able => t.yes.to_owned(),
            Some(ability) => ability.blocker.map_or_else(|| t.no.to_owned(), |blocker| (codes.blocker)(blocker).to_owned()),
        };
        table.row(vec![
            node.id.to_string(),
            node.name.clone(),
            online(node.online).to_owned(),
            node.version.clone(),
            optional(node.update.available.as_ref()),
            ability,
            on_off(node.auto_update),
            update_summary(&node.update),
        ]);
    }
    print_table(&table, t.no_nodes);
}

/// 强制更新一个节点之后的回显。
pub fn node_update(name: &str, update: &NodeUpdate) {
    let (_, lang, _) = context();
    println!("{}", lang.labelled(name, &update_summary(update)));
}

pub fn forced_updates(forced: &ForcedUpdates) {
    let (t, lang, codes) = context();
    match &forced.version {
        Some(version) => println!("{}", (t.updating_to)(&version.to_string())),
        None => println!("{}", t.nothing_to_update),
    }
    let mut fields = Fields::new(2);
    fields.add(t.ordered, lang.list(forced.ordered.iter().map(node_name)));
    fields.add(t.queued, lang.list(forced.queued.iter().map(node_name)));
    for skipped in &forced.skipped {
        let why = skipped.cause.as_ref().map_or_else(|| skipped.reason.clone(), codes.skip_cause);
        fields.add(&(t.skipped)(&skipped.node.name), why);
    }
    fields.print();
}

/// 一个节点的更新情况，一短句。它的版本有已知的安全问题时说出来。
fn update_summary(update: &NodeUpdate) -> String {
    let (t, lang, codes) = context();
    let progress = match &update.status {
        i3t_model::update::UpdateStatus::Idle | i3t_model::update::UpdateStatus::Unknown => None,
        status => Some((codes.update_status)(status)),
    };
    let timing = |timing: UpdateTiming| match timing {
        UpdateTiming::Idle => t.when_idle,
        UpdateTiming::Now => t.now,
        UpdateTiming::AfterDrain => t.after_drain,
    };
    let order = update.ordered.as_ref().map(|order| (t.ordered_to)(&order.version.to_string(), timing(order.timing)));
    let waiting = update.waiting.map(|waiting| (codes.update_wait)(waiting).to_owned());
    let parts: Vec<String> = [progress, order, waiting].into_iter().flatten().collect();
    let summary = match (&update.available, parts.is_empty()) {
        (_, false) => parts.join(t.clauses),
        (Some(version), true) => (t.available)(&version.to_string()),
        // 没有可以让它更新到的版本（比如发布里没有它的平台），版本却有安全问题：不能说"已是最新"。
        (None, true) if update.security => return t.security_problem.to_owned(),
        (None, true) => t.up_to_date.to_owned(),
    };
    if update.security { lang.paren(&summary, t.security_update) } else { summary }
}

pub fn node_access(access: &NodeAccess) {
    let (t, lang, _) = context();
    let mut table = Table::new(&t.access_header);
    let edges =
        access.can_reach.iter().map(|edge| (t.can_reach, edge)).chain(access.reachable_by.iter().map(|edge| (t.reachable_by, edge)));
    for (direction, edge) in edges {
        table.row(vec![
            direction.to_owned(),
            edge.node.name.clone(),
            edge.node.virtual_ip.to_string(),
            lang.list(edge.rules.iter().map(|rule| format!("#{rule}"))),
        ]);
    }
    print_table(&table, t.none_found);
    if !access.acknowledged {
        println!("{}", (t.not_acknowledged)(&access.node.name));
    }
}

pub fn tokens(tokens: &[EnrollTokenInfo]) {
    let (t, lang, codes) = context();
    let mut table = Table::new(&t.tokens_header);
    for token in tokens {
        table.row(vec![
            token.id.to_string(),
            if token.prefix.is_empty() { NONE.to_owned() } else { format!("{}…", token.prefix) },
            (codes.token_state)(token.state).to_owned(),
            lang.time(token.expires_at),
            optional(token.used_by.as_ref().map(|node| node.name.clone())),
            optional(token.virtual_ip),
            optional(token.successor_of.map(|node| format!("#{node}"))),
            group_names(lang, &token.groups),
        ]);
    }
    print_table(&table, t.no_tokens);
}

pub fn created_token(created: &CreatedEnrollToken) {
    let (t, lang, _) = context();
    println!("{}\n", (t.token_created)(created.info.id, &lang.time(created.info.expires_at)));
    println!("    {}\n", created.token);
    println!("{}", t.token_use);
}

pub fn rules(rules: &[Rule]) {
    let (t, _, _) = context();
    let mut table = Table::new(&t.rules_header);
    for rule in rules {
        table.row(vec![
            rule.id.to_string(),
            rule.src.name.clone(),
            arrow(rule.direction).to_owned(),
            rule.dst.name.clone(),
            yes_no(rule.enabled),
            rule.name.clone(),
        ]);
    }
    print_table(&table, t.no_rules);
}

pub fn rule(rule: &Rule) {
    let (t, lang, _) = context();
    let state = if rule.enabled { t.enabled } else { t.disabled };
    println!("{}", lang.paren(&format!("{} {}", t.rule, rule_text(rule)), state));
}

/// `#2 laptops -> servers`。
fn rule_text(rule: &Rule) -> String {
    format!("#{} {} {} {}", rule.id, rule.src.name, arrow(rule.direction), rule.dst.name)
}

const fn arrow(direction: Direction) -> &'static str {
    match direction {
        Direction::Both => "<->",
        Direction::OneWay => "->",
    }
}

pub fn proxies(proxies: &[Proxy], names: &Names) {
    let (t, lang, codes) = context();
    let mut table = Table::new(&t.proxies_header);
    for proxy in proxies {
        table.row(vec![
            proxy.id.to_string(),
            names.of(proxy.node),
            proxy.bind.to_string(),
            label(&proxy.protocol),
            optional(proxy.exit.map(|exit| names.of(exit))),
            if proxy.username.is_empty() { t.no.to_owned() } else { proxy.username.clone() },
            proxy_lane_cell(proxy),
            (codes.proxy_status)(&proxy.status),
            format!("{}  ↑ {}  ↓ {}", proxy.usage.connections, lang.bytes(proxy.usage.bytes_up), lang.bytes(proxy.usage.bytes_down)),
            proxy.name.clone(),
        ]);
    }
    print_table(&table, t.no_proxies);
}

/// 一个代理，带用户名和密码（管理员要能再复制它们），和一行用法。
pub fn proxy(proxy: &Proxy, names: &Names) {
    let (t, lang, codes) = context();
    println!("{}", lang.paren(&format!("{} #{} {}", t.proxy, proxy.id, proxy.name), &(codes.proxy_status)(&proxy.status)));
    let mut fields = Fields::new(2);
    fields.add(t.listen_node, names.of(proxy.node));
    fields.add(t.listen_at, format!("{}  {}", proxy.bind, label(&proxy.protocol)));
    fields.add(t.exit, optional(proxy.exit.map(|exit| names.of(exit))));
    let anonymous = proxy.username.is_empty() && proxy.password.is_empty();
    if anonymous {
        fields.add(t.username, t.no_authentication.to_owned());
    } else {
        fields.add(t.username, proxy.username.clone());
        fields.add(t.password, proxy.password.clone());
    }
    if !proxy.allow_from.is_empty() {
        fields.add(t.allowed_from, lang.list(&proxy.allow_from));
    }
    fields.add(
        t.usage,
        format!("{}  ↑ {}  ↓ {}", proxy.usage.connections, lang.bytes(proxy.usage.bytes_up), lang.bytes(proxy.usage.bytes_down)),
    );
    fields.add(t.lanes, proxy_lane_cell(proxy));
    if let Some(effect) = &proxy.lane_effect {
        if !effect.dialers.is_empty() {
            fields.add(t.dialers, lang.list(effect.dialers.iter().map(|id| names.of(*id))));
        }
        for block in &effect.blocked {
            fields.add(t.no_effect, (codes.lane_block)(block, &|id| names.of(id)));
        }
    }
    for LaneSide { node, lanes, reported_secs_ago } in &proxy.lanes {
        let label = match reported_secs_ago {
            Some(ago) => format!("{} ({})", names.of(*node), lang.ago(*ago)),
            None => names.of(*node),
        };
        fields.add(&label, peer_lanes(lanes));
    }
    // 格式化为代理 URL，便于多数客户端直接复用；监听地址为 0.0.0.0 时需用户自行替换为节点实际地址，此处按原样输出。
    let login = if anonymous { String::new() } else { format!("{}:{}@", proxy.username, proxy.password) };
    let scheme = match proxy.protocol {
        ListenerProtocol::Http => "http",
        ListenerProtocol::Mixed | ListenerProtocol::Socks5 => "socks5h",
    };
    fields.add(t.proxy_use, format!("{scheme}://{login}{}", proxy.bind));
    fields.print();
}

pub fn forwards(forwards: &[Forward]) {
    let (t, lang, codes) = context();
    let mut table = Table::new(&t.forwards_header);
    for forward in forwards {
        let [state, connections, traffic] = listen_cells(forward.listen.as_ref());
        let status = (codes.forward_status)(forward.status);
        let status = match &forward.target_failure {
            Some(failure) => lang.paren(status, (codes.target_cause)(failure.cause)),
            None => status.to_owned(),
        };
        table.row(vec![
            forward.id.to_string(),
            label(&forward.protocol),
            format!("#{} {}", forward.listen_node, forward.bind),
            format!("#{} {}", forward.target_node, forward.target_addr),
            status,
            state,
            connections,
            traffic,
            lang.list(&forward.allow_from),
            forward.name.clone(),
        ]);
    }
    print_table(&table, t.no_forwards);
}

pub fn forward(forward: &Forward) {
    let (t, lang, codes) = context();
    let route = format!("#{} {} → #{} {}", forward.listen_node, forward.bind, forward.target_node, forward.target_addr);
    println!(
        "{}",
        lang.paren(&format!("{} #{} {}  {route}", t.forward, forward.id, label(&forward.protocol)), (codes.forward_status)(forward.status))
    );
}

pub fn pairs(pairs: &[PairView]) {
    let (t, _, _) = context();
    let mut table = Table::new(&t.pairs_header);
    for pair in pairs {
        let setting = &pair.setting;
        // 没有设置的一对两项都写"默认"，一眼分得出哪几对是特意设过的。
        let keep_alive = if pair.stored { yes_no(setting.keep_alive) } else { t.pair_default.to_owned() };
        let congestion = setting.congestion.map_or_else(|| t.congestion_default.to_owned(), |algorithm| algorithm.to_string());
        table.row(vec![format!("#{}", setting.a), format!("#{}", setting.b), keep_alive, congestion]);
    }
    print_table(&table, t.no_pairs);
}

pub fn pair(pair: &PairView) {
    let (t, lang, _) = context();
    let setting = &pair.setting;
    let title = format!("#{} ↔ #{}", setting.a, setting.b);
    println!("{}", if pair.stored { title } else { lang.paren(&title, t.pair_default) });
    let mut fields = Fields::new(2);
    fields.add(t.keep_alive, yes_no(setting.keep_alive));
    fields.add(t.congestion, setting.congestion.map_or_else(|| t.congestion_default.to_owned(), |algorithm| algorithm.to_string()));
    fields.print();
}

/// 显示代理是否启用 ice3proxy；若已启用但当前未生效，则附注"未生效"（具体原因见详情）。
fn proxy_lane_cell(proxy: &Proxy) -> String {
    let (t, lang, _) = context();
    match &proxy.lane_effect {
        Some(effect) if proxy.lane && !effect.effective => lang.paren(t.yes, t.no_effect),
        Some(_) | None => yes_no(proxy.lane),
    }
}

/// 和一个对端之间的 lane，一行。
fn peer_lanes(lanes: &PeerLanes) -> String {
    let (t, _, _) = context();
    (t.peer_lanes)(lanes.dials, lanes.control, lanes.idle, lanes.ready, lanes.parked_at_peer, &lane_counts(&lanes.counts))
}

fn lane_counts(counts: &LaneCounts) -> String {
    let (t, lang, _) = context();
    (t.lane_counts)(
        counts,
        &format!("{} / {} / {}", lang.bytes(counts.sealed_bytes), lang.bytes(counts.passthrough_bytes), lang.bytes(counts.spliced_bytes)),
    )
}

fn lane_report(report: &LaneReport) {
    let (t, _, _) = context();
    let failures = &report.handshake_failures;
    println!("\n{}", t.lanes);
    let mut fields = Fields::new(2);
    fields.add(t.total, lane_counts(&report.total));
    fields.add(
        t.handshake_failures,
        (t.handshake_failure_counts)(failures.deadline, failures.unknown_key, failures.tls, failures.protocol, failures.busy),
    );
    for peer in &report.peers {
        fields.add(&format!("#{}", peer.peer), peer_lanes(peer));
    }
    fields.print();
}

pub fn access_graph(graph: &AccessGraph) {
    let (t, lang, _) = context();
    let mut groups = Table::new(&t.graph_groups_header);
    for group in &graph.groups {
        groups.row(vec![group.name.clone(), group.nodes.len().to_string(), lang.list(group.nodes.iter().map(node_name))]);
    }
    groups.print();
    println!();
    rules(&graph.rules);
    if !graph.unconnected.is_empty() {
        println!("\n{}", lang.labelled(t.unconnected, &lang.list(graph.unconnected.iter().map(node_name))));
    }
    if !graph.unacknowledged.is_empty() {
        println!("\n{}", lang.labelled(t.unacknowledged, &lang.list(graph.unacknowledged.iter().map(node_name))));
    }
}

pub fn access_check(check: &AccessCheck) {
    let (t, lang, _) = context();
    if check.allowed {
        let rules = lang.list(check.rules.iter().map(rule_text));
        println!("{}", lang.labelled(&(t.can_access)(&check.from.name, &check.to.name), &rules));
    } else {
        println!("{}", (t.cannot_access)(&check.from.name, &check.to.name));
    }
}

fn node_name(node: &NodeRef) -> &str {
    &node.name
}

#[cfg(test)]
mod tests {
    use i3t_model::control::exit_test::{ConnectStep, ExitTestResult, ExitVia, TlsStep};

    use super::*;

    #[test]
    fn route_details_and_segments_read_in_the_current_language() {
        let (laptop, relay) = (NodeId::new(1).unwrap(), NodeId::new(9).unwrap());
        let segment = PathSegment { from: laptop, to: relay, rtt_us: 20_400, jitter_us: 500, loss_permille: 12 };
        let name = |id: NodeId| if id == laptop { "laptop".to_owned() } else { format!("#{id}") };
        let text = leg_text(&segment, &name);
        assert!(text.contains("laptop→#9") && text.contains("20.4") && text.contains("1.2%"), "{text}");
        let direct = Route::Direct { addr: "203.0.113.9:20330".parse().unwrap() };
        assert_ne!(kind_cell(&direct, Some(DirectKind::Punched), None), NONE);
        assert_eq!(kind_cell(&Route::Relay { relays: vec![relay] }, Some(DirectKind::Lan), Some(LegTransport::Tcp)), "TCP");
        assert_eq!(kind_cell(&direct, None, Some(LegTransport::Tcp)), NONE, "节点没有说的时候是短横");
        assert_eq!(label(&i3t_model::netmap::RoutingMode::LowestCost), "lowest_cost");
    }

    fn tested(result: ExitTestResult) -> ExitTestView {
        let node = NodeRef { id: NodeId::new(3).unwrap(), name: "gw".into(), virtual_ip: "10.66.0.3".parse().unwrap() };
        ExitTestView { node, target: "192.168.1.5:443".into(), answered: true, result: Some(result) }
    }

    #[test]
    fn a_busy_exit_gets_its_own_line_and_not_the_policy_label() {
        let (t, _, codes) = context();
        let busy = ExitTestResult { via: ExitVia::Direct, refused: Some(ExitTestCause::Busy), resolve: None, connect: None, tls: None };
        let text = exit_test_text(&tested(busy));
        assert_eq!(text, format!("{}\n", (t.exit_busy)("gw")));
        assert!(!text.contains(t.exit_refused) && !text.contains((codes.exit_test_cause)(&ExitTestCause::Busy).as_str()), "{text}");
        let refused = ExitTestCause::PortNotAllowed { port: 25 };
        let policy = ExitTestResult { via: ExitVia::Direct, refused: Some(refused), resolve: None, connect: None, tls: None };
        assert!(exit_test_text(&tested(policy)).contains(t.exit_refused), "策略不连的照旧在它的标签下");
    }

    #[test]
    fn times_under_a_millisecond_do_not_read_as_zero() {
        let address = "192.168.1.5:443".parse().unwrap();
        let result = ExitTestResult {
            via: ExitVia::Direct,
            refused: None,
            resolve: None,
            connect: Some(ConnectStep { ms: 0, address: Some(address), cause: None }),
            tls: Some(TlsStep { ms: 3, cause: None }),
        };
        let text = exit_test_text(&tested(result));
        assert!(text.contains("<1 ms") && text.contains("3 ms") && !text.contains(" 0 ms"), "{text}");
    }
}
