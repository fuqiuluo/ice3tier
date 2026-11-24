//! MCP 的工具：每个工具对应管理 API 的一个操作，调的是 [`Controller`] 上的同一个方法。
//!
//! 一个工具写明四样（[`Tool`]）：要哪项权限，是整个 controller 的事还是一个网络里的事，实际会做什么（只读、新增、
//! 改、删），以及参数的 JSON Schema。前三样在调用之前由这里统一核对，各个工具的处理函数里不用再写：
//!
//! - 令牌没有这项权限的，列表里没有这个工具，调了是 403；
//! - 一个网络里的事，参数里的 `network` 先核对过是令牌能碰的网络才交给处理函数。只限一个网络的令牌写了别的网络，
//!   得到的是"没有这个网络"，和那个网络真的不存在一样；
//! - 整个 controller 的事，只限一个网络的令牌做不了。
//!
//! 参数里除了指明对象的那几个（`network`、`node`、`rule`……），其余的就是管理 API 请求体里的字段，
//! 原样读成 `i3t_model::admin` 里的请求类型，所以取值、默认值和管理 API 完全一样。Schema 是照着这些类型手写的；
//! 测试里把每个请求类型的全部字段写一遍，和 Schema 里列的比对，类型加了字段而这里没跟上时测试过不了。

use std::borrow::Cow;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use i3t_model::admin::diag::{CreateTest, TestQuery};
use i3t_model::admin::mcp::McpScope;
use i3t_model::admin::stats::SeriesQuery;
use i3t_model::admin::{
    CreateEnrollToken, CreateGroup, CreateNetwork, CreateProxy, CreateRule, ExitTestInput, ForwardInput, GroupId, GroupMembers, LogRef,
    NetworkId, PairInput, RelaySettings, TokenState, UpdateGroup, UpdateNetwork, UpdateNode, UpdateProxy, UpdateRule, UpdateSettings,
};
use i3t_model::netmap::ExitRole;
use i3t_model::update::{UpdateTiming, Version};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use crate::admin::{DEFAULT_LOG_LIMIT, MAX_LOG_LIMIT, named_field, relay_enabled};
use crate::controller::{Controller, McpGrant};
use crate::error::{Entity, Error};
use crate::server::blocking;
use crate::store::{LogFilter, acting_as};

/// 一个工具的结果：写成 JSON 的应答，或者 controller 的错误（和管理 API 的错误是同一种）。
type Reply = Result<Value, Error>;
type Pending = Pin<Box<dyn Future<Output = Reply> + Send>>;

/// 一个工具实际会做什么，客户端据此决定要不要先问人（`readOnlyHint`、`destructiveHint`、`idempotentHint`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// 只读。
    Reads,
    /// 新增一样东西；再调一次会再多一样。
    Adds,
    /// 把一项设置改成给定的样子；再调一次还是那样。
    Sets,
    /// 删掉东西，或者关掉一项正在用的功能。
    Removes,
    /// 让节点重启、断开正在进行的流。
    Disrupts,
}

/// 一个工具怎么调 controller。前四种在阻塞线程上跑（controller 的方法是同步的），这期间记的操作都算在令牌头上。
enum Run {
    /// 整个 controller 的事。只限一个网络的令牌用不了。
    Global(fn(&Controller, Args) -> Reply),
    /// 结果随令牌变的：`Some` 是令牌只限的那个网络，只给它看那一个网络的。
    Limited(fn(&Controller, Option<NetworkId>, Args) -> Reply),
    /// 一个网络里的事。`NetworkId` 已经核对过是令牌能碰的。
    Network(fn(&Controller, NetworkId, Args) -> Reply),
    /// 一个网络里的事，中间要等节点回答，或者要从 controller 这边去试连。
    NetworkAsync(fn(Caller, NetworkId, Args) -> Pending),
}

pub(super) struct Tool {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    pub(super) scope: McpScope,
    effect: Effect,
    /// 会不会去碰 controller 管的这张网之外的东西（互联网上的目标、发布源）。
    open_world: bool,
    /// 参数的 JSON Schema。
    schema: Value,
    run: Run,
}

/// 令牌为什么调不了一个工具。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Denied {
    /// 没有这项权限。
    Scope,
    /// 工具管的是整个 controller 的事，令牌只限一个网络。
    Limited,
}

impl Tool {
    /// 这个令牌能不能调这个工具。
    pub(super) fn permits(&self, grant: &McpGrant) -> Result<(), Denied> {
        if !grant.scopes.contains(&self.scope) {
            return Err(Denied::Scope);
        }
        if grant.network.is_some() && matches!(self.run, Run::Global(_)) {
            return Err(Denied::Limited);
        }
        Ok(())
    }

    /// `tools/list` 里的一项。
    fn listing(&self) -> Value {
        let reads = self.effect == Effect::Reads;
        let mut annotations = json!({ "title": self.title, "readOnlyHint": reads, "openWorldHint": self.open_world });
        if !reads {
            annotations["destructiveHint"] = json!(matches!(self.effect, Effect::Removes | Effect::Disrupts));
            annotations["idempotentHint"] = json!(matches!(self.effect, Effect::Sets | Effect::Removes));
        }
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.schema,
            "annotations": annotations,
        })
    }

    /// 调这个工具。权限已经核对过（[`Tool::permits`]）。
    pub(super) async fn run(&self, app: &Arc<Controller>, grant: &McpGrant, arguments: Map<String, Value>) -> Reply {
        let mut args = Args(arguments);
        args.only_known(&self.schema)?;
        let caller = Caller { controller: Arc::clone(app), grant: grant.clone() };
        let mut value = match self.run {
            Run::Global(run) => caller.blocking(move |controller| run(controller, args)).await,
            Run::Limited(run) => {
                let only = grant.network;
                caller.blocking(move |controller| run(controller, only, args)).await
            }
            Run::Network(run) => {
                let network = args.network(grant)?;
                caller.blocking(move |controller| run(controller, network, args)).await
            }
            Run::NetworkAsync(run) => {
                let network = args.network(grant)?;
                run(caller, network, args).await
            }
        }?;
        // 代理的密码不止在代理的列表里：出口的视图里也带着经它出去的代理。所以不在各个工具里各管各的，统一在这里去掉。
        if !grant.scopes.contains(&McpScope::ConfigWrite) {
            hide_passwords(&mut value);
        }
        Ok(value)
    }
}

/// 替一个令牌调 controller。
struct Caller {
    controller: Arc<Controller>,
    grant: McpGrant,
}

impl Caller {
    /// 在阻塞线程上调 controller 的同步方法，这期间记的操作都算是这个令牌做的。
    async fn blocking<T: Send + 'static>(&self, call: impl FnOnce(&Controller) -> T + Send + 'static) -> T {
        let actor = self.grant.actor();
        blocking(&self.controller, move |controller| acting_as(actor, || call(controller))).await
    }
}

/// 一次调用的参数。处理函数从里面取走指明对象的那几个，剩下的整个读成请求体。
struct Args(Map<String, Value>);

impl Args {
    /// 参数都得是 Schema 里列了的：写错了名字的参数不会被悄悄忽略、然后工具照样"成功"。
    fn only_known(&self, schema: &Value) -> Result<(), Error> {
        let known = schema.get("properties").and_then(Value::as_object);
        match self.0.keys().find(|name| !known.is_some_and(|known| known.contains_key(*name))) {
            Some(unknown) => Err(in_field(unknown.clone(), Error::invalid("not_allowed", format!("这个工具没有 {unknown} 这个参数")))),
            None => Ok(()),
        }
    }

    /// 必须有的一个参数。
    fn take<T: DeserializeOwned>(&mut self, name: &'static str) -> Result<T, Error> {
        self.opt(name)?.ok_or_else(|| Error::invalid_field(name, "missing", format!("缺少参数 {name}")))
    }

    /// 可以没有的一个参数；写了 `null` 也算没有。
    fn opt<T: DeserializeOwned>(&mut self, name: &'static str) -> Result<Option<T>, Error> {
        match self.0.remove(name) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => serde_json::from_value(value)
                .map(Some)
                .map_err(|error| Error::invalid_field(name, "malformed", format!("参数 {name} 不合法：{error}"))),
        }
    }

    /// 剩下的参数整个读成管理 API 的一个请求类型。
    fn rest<T: DeserializeOwned>(self) -> Result<T, Error> {
        serde_json::from_value(Value::Object(self.0)).map_err(|error| {
            let text = error.to_string();
            let invalid = Error::invalid("malformed", format!("参数不合法：{text}"));
            match named_field(&text) {
                Some(field) => in_field(field, invalid),
                None => invalid,
            }
        })
    }

    /// 参数里的 `network`，核对过这个令牌能碰它。只限一个网络的令牌写了别的网络时，那个网络对它等于不存在。
    fn network(&mut self, grant: &McpGrant) -> Result<NetworkId, Error> {
        let network: NetworkId = self.take("network")?;
        match grant.network {
            Some(only) if only != network => Err(Error::NotFound(Entity::Network).in_field("network")),
            _ => Ok(network),
        }
    }
}

fn in_field(field: String, error: Error) -> Error {
    Error::InField { field: Cow::Owned(field), error: Box::new(error) }
}

/// 把 controller 的结果写成 JSON。
fn reply<T: Serialize>(result: Result<T, Error>) -> Reply {
    Ok(serde_json::to_value(result?)?)
}

/// 删除这一类没有应答体的操作成功了。
fn done(result: Result<(), Error>) -> Reply {
    result.map(|()| json!({ "ok": true }))
}

/// 安装脚本。和 README、WebUI「添加节点」里给的是同一个地址。
const INSTALL_SH: &str = "https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh";
const INSTALL_PS1: &str = "https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.ps1";

/// 拿着注册令牌在要加入的机器上执行的安装命令。注册令牌是 `i3t-` 加 base64url，不用加引号。
fn install_commands(token: &str) -> Value {
    json!({
        "linux_macos": format!("curl -fsSL {INSTALL_SH} | sh -s -- --token {token}"),
        "windows_powershell_as_administrator": format!("$env:I3T_TOKEN = '{token}'; irm {INSTALL_PS1} | iex"),
        "notes": "Run one of these on the machine to add. It installs the node as a system service, joins the network and starts. \
                  Append --can-relay or --can-exit on Linux/macOS if the machine may act as a relay or an exit. \
                  Then call enroll_token_status with this token's id to confirm the node joined and is online.",
    })
}

/// 没有 `config:write` 的令牌看到的代理的密码。有这项权限的令牌本来就能改密码，给它看原文。
const HIDDEN_PASSWORD: &str = "(hidden: needs the config:write scope)";

/// 把结果里每一处密码换掉，不管它嵌在哪一层。空的密码（不认证的代理）没有什么可藏的，原样留着。
fn hide_passwords(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(hide_passwords),
        Value::Object(fields) => {
            for (name, field) in fields {
                match field {
                    Value::String(password) if name == "password" && !password.is_empty() => *password = HIDDEN_PASSWORD.to_owned(),
                    other => hide_passwords(other),
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

// 下面是 Schema 里反复用到的参数。说明写给模型看，所以是英文的，尽量短。

fn id(what: &str) -> Value {
    json!({ "type": "integer", "minimum": 1, "description": what })
}

fn node(role: &str) -> Value {
    id(&format!("Node id (see node_list): {role}"))
}

fn text(what: &str) -> Value {
    json!({ "type": "string", "description": what })
}

fn flag(what: &str) -> Value {
    json!({ "type": "boolean", "description": what })
}

fn number(what: &str, minimum: u64, maximum: u64) -> Value {
    json!({ "type": "integer", "minimum": minimum, "maximum": maximum, "description": what })
}

fn choice(what: &str, values: &[&str]) -> Value {
    json!({ "type": "string", "enum": values, "description": what })
}

/// 可以写 `null` 的选项：`null` 表示清掉这项设置，回到默认。
fn choice_or_null(what: &str, values: &[&str]) -> Value {
    let mut values: Vec<Value> = values.iter().map(|value| json!(value)).collect();
    values.push(Value::Null);
    json!({ "type": ["string", "null"], "enum": values, "description": what })
}

fn list(items: Value, what: &str) -> Value {
    let mut schema = json!({ "type": "array", "description": what });
    schema["items"] = items;
    schema
}

const ROUTING: [&str; 2] = ["direct_first", "lowest_cost"];
const REACH: [&str; 3] = ["any", "direct_only", "relay_only"];
const CLASS: [&str; 4] = ["auto", "interactive", "reliable", "bulk"];
const TIMING: [&str; 2] = ["now", "after_drain"];

fn class(what: &str) -> Value {
    choice(what, &CLASS)
}

fn timing() -> Value {
    choice("now: restart at once, running flows break. after_drain: stop taking new flows, restart when the running ones end", &TIMING)
}

fn cidrs(what: &str) -> Value {
    list(json!({ "type": "string" }), what)
}

/// 网络的各项设置：建网和改网共用。
fn network_settings() -> Vec<(&'static str, Value)> {
    vec![
        ("cidr", text("IPv4 range of the virtual IPs, e.g. 10.66.0.0/16. Once nodes exist it can only grow")),
        ("routing", choice("How nodes pick a path", &ROUTING)),
        ("max_relay_hops", number("Most relays on one path", 1, 4)),
        ("reach", choice("Which paths nodes may use", &REACH)),
        ("class", class("Default service class of flows")),
        ("ack_eliciting_threshold", number("QUIC: packets received before an ACK is sent", 1, 100)),
        ("max_ack_delay_ms", number("QUIC: longest an ACK is held back, ms", 1, 25)),
        ("bundle_small_packets", flag("Bundle small packets into one datagram")),
        ("vnet_offload", flag("Segmentation offload on the virtual adapter")),
        ("vnet_mtu", number("MTU of the virtual adapter, bytes", 576, 1500)),
    ]
}

/// 代理的各项设置里建和改都有的那些。
fn proxy_settings() -> Vec<(&'static str, Value)> {
    vec![
        ("name", text("Display name; default <node name>-<port>")),
        ("protocol", choice("Proxy protocol spoken on the listener", &["mixed", "socks5", "http"])),
        ("username", text("With password: both or neither. Neither on a non-loopback bind makes the controller generate a pair")),
        ("password", text("See username")),
        ("enabled", flag("Default true")),
        ("allow_from", cidrs("Source ranges allowed to connect; empty = any")),
        ("lane", flag("Carry this proxy's TCP flows over ice3proxy (default false)")),
    ]
}

/// 出口的设置：`exit_enable` 的参数。
fn exit_settings() -> Vec<(&'static str, Value)> {
    vec![
        (
            "ports",
            json!({ "type": ["array", "null"], "items": { "type": "integer", "minimum": 1, "maximum": 65535 }, "description": "Internet ports allowed; null or omitted = any" }),
        ),
        ("lan", flag("Also allow targets on the exit's own LAN (default false)")),
        ("upstream_socks5", text("Hand flows to this SOCKS5 proxy (ip:port) instead of connecting directly")),
        (
            "quota_bytes",
            json!({ "type": ["integer", "null"], "minimum": 0, "description": "Traffic quota per billing period, bytes; null = unlimited" }),
        ),
        ("quota_reset_day", number("Day of the month the billing period starts (UTC), default 1", 1, 28)),
        ("family", choice("Address family used for internet targets (default any)", &["any", "ipv4", "ipv6"])),
        (
            "connects_per_minute",
            json!({ "type": ["integer", "null"], "minimum": 1, "description": "New connections per minute per source node and target; null = unlimited" }),
        ),
        ("class", class("Default service class of flows through this exit")),
        ("optimistic", flag("Tell the client it is connected before the exit confirms")),
    ]
}

fn forward_settings() -> Vec<(&'static str, Value)> {
    vec![
        ("name", text("Display name")),
        ("protocol", choice("Transport", &["tcp", "udp"])),
        ("listen_node", node("the node that listens")),
        ("bind", text("Listen address on listen_node, ip:port")),
        ("target_node", node("the node that connects to the target; it must have forward_target switched on (node_update)")),
        ("target_addr", text("Address target_node connects to, ip:port (loopback or its LAN)")),
        ("allow_from", cidrs("Source ranges allowed to connect; empty = any")),
        ("enabled", flag("Default true")),
        ("class", class("Service class of flows on this forward")),
        ("proxy_protocol", choice("Send a PROXY protocol header to the target", &["v1", "v2"])),
    ]
}

/// 一个工具的名字、权限、会做什么，和给人、给模型看的说明。参数和怎么调用由 [`Spec::with`] 补上。
struct Spec {
    name: &'static str,
    scope: McpScope,
    effect: Effect,
    title: &'static str,
    description: &'static str,
}

const fn spec(name: &'static str, scope: McpScope, effect: Effect, title: &'static str, description: &'static str) -> Spec {
    Spec { name, scope, effect, title, description }
}

impl Spec {
    /// 补上参数（名字和 Schema）、哪几个必须有、怎么调用。`network` 这个参数由 `run` 是哪一种决定要不要，不用写。
    fn with(self, properties: Vec<(&'static str, Value)>, required: &[&'static str], run: Run) -> Tool {
        let Self { name, scope, effect, title, description } = self;
        let mut fields = Map::new();
        let mut needed: Vec<&str> = Vec::new();
        match run {
            Run::Global(_) => {}
            Run::Limited(_) => {
                let only = "Only entries of this network id. A token limited to one network always gets only its own";
                fields.insert("network".to_owned(), id(only));
            }
            Run::Network(_) | Run::NetworkAsync(_) => {
                fields.insert("network".to_owned(), id("Network id (see network_list)"));
                needed.push("network");
            }
        }
        for (property, schema) in properties {
            let previous = fields.insert(property.to_owned(), schema);
            assert!(previous.is_none(), "工具 {name} 的参数 {property} 写了两遍");
        }
        needed.extend(required);
        assert!(needed.iter().all(|property| fields.contains_key(*property)), "工具 {name} 要求的参数都得在 Schema 里");
        let schema = json!({ "type": "object", "properties": fields, "required": needed, "additionalProperties": false });
        Tool { name, title, description, scope, effect, open_world: false, schema, run }
    }
}

/// 全部工具，顺序是固定的：只读的在前，然后按权限。`tools/list` 照这个顺序给，客户端缓存得住。
static TOOLS: LazyLock<Vec<Tool>> = LazyLock::new(all);

/// 这个令牌能调的工具，`tools/list` 的样子。
pub(super) fn listed(grant: &McpGrant) -> Vec<Value> {
    TOOLS.iter().filter(|tool| tool.permits(grant).is_ok()).map(Tool::listing).collect()
}

pub(super) fn find(name: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|tool| tool.name == name)
}

fn all() -> Vec<Tool> {
    use Effect::{Adds, Disrupts, Reads, Removes, Sets};
    use McpScope::{ConfigWrite, NetworksWrite, NodesEnroll, NodesWrite, Read, TestsRun, UpdatesWrite};

    vec![
        // ---- read ----
        spec("status", Read, Reads, "Controller status", "The controller's version, public address and key, and how many networks and nodes it has.").with(
            vec![],
            &[],
            Run::Global(|controller, _| reply(controller.status())),
        ),
        spec("network_list", Read, Reads, "List networks", "The networks with their ids, names, address ranges and settings. Start here: every other tool takes a network id.").with(
            vec![],
            &[],
            Run::Limited(|controller, only, mut args| {
                let wanted = args.opt::<NetworkId>("network")?.or(only);
                if only.is_some() && wanted != only {
                    return Ok(json!([]));
                }
                let networks = controller.networks()?;
                reply(Ok(networks.into_iter().filter(|network| wanted.is_none_or(|wanted| network.id == wanted)).collect::<Vec<_>>()))
            }),
        ),
        spec("network_show", Read, Reads, "Show a network", "One network: its settings and node count.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.network(network))),
        ),
        spec("overview", Read, Reads, "Network overview", "Counts for one network (nodes, online, relays, exits, rules, proxies, forwards, pending tokens), the pairs that cannot reach each other, traffic, and warnings.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.overview(network))),
        ),
        spec("node_list", Read, Reads, "List nodes", "The nodes of a network: id, name, virtual IP, groups, online or not, last seen, version, relay and exit roles, warnings.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.nodes(network))),
        ),
        spec("node_show", Read, Reads, "Show a node", "One node in detail, including what it last reported (addresses, listeners, virtual adapter, performance profile).").with(
            vec![("node", node("the node to show"))],
            &["node"],
            Run::Network(|controller, network, mut args| reply(controller.node(network, args.take("node")?))),
        ),
        spec("node_routes", Read, Reads, "A node's routes", "The route table a node last reported: how it reaches each peer (direct, via which relay, or not at all) and why.").with(
            vec![("node", node("whose routes"))],
            &["node"],
            Run::Network(|controller, network, mut args| reply(controller.routes(network, args.take("node")?))),
        ),
        spec("node_access", Read, Reads, "A node's access", "Which nodes this node may reach and which may reach it, under the access rules.").with(
            vec![("node", node("whose access"))],
            &["node"],
            Run::Network(|controller, network, mut args| reply(controller.node_access(network, args.take("node")?))),
        ),
        spec("node_listeners", Read, Reads, "A node's listeners", "What a node listens on (proxies, forwards, local entry points) and whether each bind works.").with(
            vec![("node", node("whose listeners"))],
            &["node"],
            Run::Network(|controller, network, mut args| reply(controller.node_listeners(network, args.take("node")?))),
        ),
        spec("node_update_status", Read, Reads, "A node's update state", "Whether a node can update itself, to which version, and how far an update has got.").with(
            vec![("node", node("whose update state"))],
            &["node"],
            Run::Network(|controller, network, mut args| reply(controller.node_update(network, args.take("node")?))),
        ),
        spec("group_list", Read, Reads, "List groups", "The groups of a network with their members and the rules that use them. Every node is in the built-in group All.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.groups(network))),
        ),
        spec("group_show", Read, Reads, "Show a group", "One group: its members and the rules that use it.").with(
            vec![("group", id("Group id (see group_list)"))],
            &["group"],
            Run::Network(|controller, network, mut args| reply(controller.group(network, args.take("group")?))),
        ),
        spec("rule_list", Read, Reads, "List access rules", "The access rules: nodes in group src may reach nodes in group dst (both ways unless direction is one_way). No rule, no access.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.rules(network))),
        ),
        spec("access_check", Read, Reads, "Check access", "Whether node `from` may reach node `to`, and the rules that allow it.").with(
            vec![("from", node("the node that connects")), ("to", node("the node it connects to"))],
            &["from", "to"],
            Run::Network(|controller, network, mut args| reply(controller.access_check(network, args.take("from")?, args.take("to")?))),
        ),
        spec("access_graph", Read, Reads, "Access graph", "Every pair of nodes that may reach each other under the rules.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.access_graph(network))),
        ),
        spec("proxy_list", Read, Reads, "List proxies", "The SOCKS5/HTTP proxies: listening node and address, exit node, state. Passwords are shown only to tokens with config:write.").with(
            vec![("node", node("only proxies listening on this node"))],
            &[],
            Run::Network(|controller, network, mut args| reply(controller.proxies(network, args.opt("node")?))),
        ),
        spec("proxy_show", Read, Reads, "Show a proxy", "One proxy. The password is shown only to tokens with config:write.").with(
            vec![("proxy", id("Proxy id (see proxy_list)"))],
            &["proxy"],
            Run::Network(|controller, network, mut args| reply(controller.proxy(network, args.take("proxy")?))),
        ),
        spec("forward_list", Read, Reads, "List port forwards", "The port forwards: a listener on one node that carries connections to an address reachable from another node.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.forwards(network))),
        ),
        spec("pair_list", Read, Reads, "List node pairs", "The per-pair settings (keep the connection alive, congestion control) of every pair of nodes.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.pairs(network))),
        ),
        spec("pair_show", Read, Reads, "Show a node pair", "The settings of one pair of nodes.").with(
            vec![("a", node("one node of the pair")), ("b", node("the other node"))],
            &["a", "b"],
            Run::Network(|controller, network, mut args| reply(controller.pair(network, args.take("a")?, args.take("b")?))),
        ),
        spec("exit_list", Read, Reads, "List exits", "The exit nodes: settings, traffic and quota, health, the proxies going out through them, and how the nodes using them see them.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.exits(network))),
        ),
        spec("exit_show", Read, Reads, "Show an exit", "One exit node: settings, traffic and quota, health.").with(
            vec![("node", node("the exit node"))],
            &["node"],
            Run::Network(|controller, network, mut args| reply(controller.exit(network, args.take("node")?))),
        ),
        spec("route_matrix", Read, Reads, "Route matrix", "For every pair of nodes, the route in use as last reported (direct, via relays, unreachable).").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.route_matrix(network))),
        ),
        spec("path_show", Read, Reads, "Path between two nodes", "The path from one node to another right now, asked from both ends: route, candidates, recent switches. Takes up to a few seconds.").with(
            vec![("from", node("the sending end")), ("to", node("the receiving end"))],
            &["from", "to"],
            Run::NetworkAsync(|caller, network, mut args| {
                Box::pin(async move {
                    let (from, to) = (args.take("from")?, args.take("to")?);
                    reply(caller.controller.path(network, from, to).await)
                })
            }),
        ),
        spec("backbone_show", Read, Reads, "Relay backbone", "The links between the relays as the relays measure them. Takes up to a few seconds.").with(
            vec![],
            &[],
            Run::NetworkAsync(|caller, network, _| Box::pin(async move { reply(caller.controller.backbone(network).await) })),
        ),
        spec("stats_series", Read, Reads, "Time series", "Points of one series over time. Network series: online, flows, tx, rx. Per-node series (need `node`): node_tx, node_rx, node_flows, relay_attached, exit_tx, exit_rx.").with(
            vec![
                ("series", choice("Which series", &["online", "flows", "tx", "rx", "node_tx", "node_rx", "node_flows", "relay_attached", "exit_tx", "exit_rx"])),
                ("node", node("required for the per-node series, not allowed for the network ones")),
                ("from", json!({ "type": "integer", "minimum": 0, "description": "Start, Unix seconds; default 24 hours before `to`" })),
                ("to", json!({ "type": "integer", "minimum": 0, "description": "End, Unix seconds; default now" })),
                ("step", json!({ "type": "integer", "enum": [300, 3600], "description": "Seconds between points; default by range" })),
            ],
            &["series"],
            Run::Network(|controller, network, args| reply(controller.series(network, &args.rest::<SeriesQuery>()?))),
        ),
        spec("test_list", Read, Reads, "List tests", "Recent active tests (started with test_start) and their results, newest first.").with(
            vec![("a", node("with `b`: only tests of this pair (give both or neither)")), ("b", node("the other node of the pair")), ("limit", number("How many, default 20", 1, 200))],
            &[],
            Run::Network(|controller, network, args| reply(controller.tests(network, &args.rest::<TestQuery>()?))),
        ),
        spec("test_show", Read, Reads, "Show a test", "One active test: its state and the results so far. Poll it after test_start until state is no longer running.").with(
            vec![("test", id("Test id"))],
            &["test"],
            Run::Network(|controller, network, mut args| reply(controller.test(network, args.take("test")?))),
        ),
        spec("matrix_show", Read, Reads, "Show the test matrix", "The latest all-pairs test matrix of the network and its progress.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.matrix(network))),
        ),
        spec("update_status", Read, Reads, "Update overview", "Node updates across the controller: settings, the latest release known, packages fetched, paused versions.").with(
            vec![],
            &[],
            Run::Global(|controller, _| reply(controller.update_overview())),
        ),
        spec("log", Read, Reads, "Operation log", "What was changed and when, newest first. Entries made through MCP carry `actor` (the token's name and jti).").with(
            vec![
                ("limit", number("How many entries, default 100", 1, u64::from(MAX_LOG_LIMIT))),
                ("before", id("Only entries with an id below this: pass the last id of the previous page")),
                ("action", text("Only this action or the ones under it: `node` covers node.update, node.relay.enable, ...")),
                ("ref", text("Only entries about this thing, as kind:id — network, node, group, token, rule, proxy or forward, e.g. node:3")),
            ],
            &[],
            Run::Limited(|controller, only, mut args| {
                let wanted = args.opt::<NetworkId>("network")?;
                // 只限一个网络的令牌只看得到那个网络的记录；和网络无关的（建删别的网络、更新设置）它看不到。
                let network = match (only, wanted) {
                    (Some(only), Some(wanted)) if only != wanted => return Ok(json!([])),
                    (Some(only), _) => Some(only),
                    (None, wanted) => wanted,
                };
                let reference = args.opt::<String>("ref")?.map(|text| text.parse::<LogRef>()).transpose();
                let reference = reference.map_err(|error| Error::invalid_field("ref", "malformed", format!("参数 ref 不合法：{error}")))?;
                let filter = LogFilter {
                    limit: args.opt::<u32>("limit")?.unwrap_or(DEFAULT_LOG_LIMIT).min(MAX_LOG_LIMIT),
                    before: args.opt("before")?,
                    network,
                    action: args.opt::<String>("action")?.filter(|action| !action.is_empty()),
                    reference,
                };
                reply(controller.oplog_filtered(&filter))
            }),
        ),
        // ---- nodes:enroll ----
        spec("enroll_token_list", NodesEnroll, Reads, "List enrollment tokens", "The enrollment tokens of a network that can still be used; with `all` also the used and expired ones. Never the token text.").with(
            vec![("all", flag("Also list used and expired tokens (kept for 30 days)"))],
            &[],
            Run::Network(|controller, network, mut args| reply(controller.tokens(network, args.opt("all")?.unwrap_or(false)))),
        ),
        spec("enroll_token_create", NodesEnroll, Adds, "Create an enrollment token", "Creates a one-time token that lets one machine join the network, and returns it with the install commands to run on that machine. The token text is a secret and is shown only here.").with(
            vec![
                ("expires_in_secs", number("Seconds until it expires, default one day", 1, 365 * 24 * 60 * 60)),
                ("groups", list(id("Group id"), "Groups the node joins (ids from group_list)")),
                ("virtual_ip", text("Preset virtual IPv4 address inside the network's range")),
                ("successor_of", node("an offline node the new one replaces: it takes over its name, IP, groups and settings")),
            ],
            &[],
            Run::Network(|controller, network, args| {
                let created = controller.create_token(network, &args.rest::<CreateEnrollToken>()?)?;
                let install = install_commands(&created.token);
                let mut value = serde_json::to_value(created)?;
                value["install"] = install;
                Ok(value)
            }),
        ),
        spec("enroll_token_status", NodesEnroll, Reads, "Has the token been used", "Whether a node has joined with this enrollment token and, if so, which node and whether it is online now. Use it to confirm a machine was really added.").with(
            vec![("token", id("Enrollment token id (from enroll_token_create or enroll_token_list)"))],
            &["token"],
            Run::Network(|controller, network, mut args| {
                let wanted: u32 = args.take("token")?;
                let token = controller.tokens(network, true)?.into_iter().find(|token| token.id == wanted);
                let token = token.ok_or(Error::NotFound(Entity::Token))?;
                let node = match &token.used_by {
                    Some(joined) => controller.nodes(network)?.into_iter().find(|node| node.id == joined.id),
                    None => None,
                };
                let online = node.as_ref().is_some_and(|node| node.online);
                Ok(json!({ "token": token, "joined": token.state == TokenState::Used, "online": online, "node": node }))
            }),
        ),
        spec("enroll_token_delete", NodesEnroll, Removes, "Withdraw an enrollment token", "Deletes an enrollment token so it can no longer be used. A node that already joined with it stays.").with(
            vec![("token", id("Enrollment token id"))],
            &["token"],
            Run::Network(|controller, network, mut args| done(controller.delete_token(network, args.take("token")?))),
        ),
        // ---- nodes:write ----
        spec("node_update", NodesWrite, Sets, "Change a node", "Changes a node's name, groups, virtual IP or settings. Only the fields given change. `groups` and `pinned_relays` replace the whole list.").with(
            vec![
                ("node", node("the node to change")),
                ("name", text("New name: lowercase letters, digits, hyphens")),
                ("groups", list(id("Group id"), "The groups the node is in afterwards (replaces the list; All is implied)")),
                ("virtual_ip", text("New virtual IPv4 address; configuration that refers to the old one stops working")),
                ("dial_out_only", flag("Only dial out: accept no inbound connections and take no part in hole punching")),
                ("routing", choice_or_null("Path selection for this node; null = the network's default", &ROUTING)),
                ("reach", choice_or_null("Paths this node may use; null = the network's default", &REACH)),
                ("pinned_relays", list(id("Relay node id"), "Relays this node attaches to (replaces the list; empty = not pinned)")),
                ("profile", choice_or_null("Performance profile; null = what the node's own config says", &["low_footprint", "balanced", "high_throughput"])),
                ("forward_target", flag("Allow this node to be the target of port forwards")),
                ("auto_update", flag("Let this node update itself automatically")),
            ],
            &["node"],
            Run::Network(|controller, network, mut args| {
                let node = args.take("node")?;
                reply(controller.update_node(network, node, &args.rest::<UpdateNode>()?))
            }),
        ),
        spec("node_delete", NodesWrite, Removes, "Delete a node", "Removes a node from the network: its key is revoked, it is disconnected, and its proxies, forwards and pair settings go with it. Its name and IP are held back for 90 days.").with(
            vec![("node", node("the node to delete"))],
            &["node"],
            Run::Network(|controller, network, mut args| done(controller.delete_node(network, args.take("node")?))),
        ),
        spec("node_succeed", NodesWrite, Removes, "Replace an offline node", "Makes `node` the successor of `predecessor`: it takes over the predecessor's name, virtual IP, groups and settings, and the predecessor is deleted. The predecessor must be offline.").with(
            vec![("node", node("the new node")), ("predecessor", node("the offline node it replaces; deleted afterwards"))],
            &["node", "predecessor"],
            Run::Network(|controller, network, mut args| {
                let (node, predecessor) = (args.take("node")?, args.take("predecessor")?);
                reply(controller.succeed(network, node, predecessor))
            }),
        ),
        spec("relay_enable", NodesWrite, Sets, "Enable a relay", "Makes a node a relay (or changes its relay settings). The node must have declared it can relay (`i3t set can-relay on` on the node). The answer includes a reachability check of its addresses from the controller, which only advises.").with(
            vec![("node", node("the node to make a relay")), ("bandwidth_mbps", json!({ "type": ["integer", "null"], "minimum": 1, "description": "Cap on relayed traffic, Mbit/s; null or omitted = no cap" }))],
            &["node"],
            Run::NetworkAsync(|caller, network, mut args| {
                Box::pin(async move {
                    let node = args.take("node")?;
                    let settings = args.rest::<RelaySettings>()?;
                    let node = caller.blocking(move |controller| controller.enable_relay(network, node, settings)).await?;
                    reply(Ok(relay_enabled(node).await))
                })
            }),
        ),
        spec("relay_disable", NodesWrite, Removes, "Disable a relay", "Stops a node from being a relay. Nodes attached to it move to other relays; pairs that can only talk through it lose their path.").with(
            vec![("node", node("the relay to disable"))],
            &["node"],
            Run::Network(|controller, network, mut args| reply(controller.disable_relay(network, args.take("node")?))),
        ),
        spec("exit_enable", NodesWrite, Sets, "Enable an exit", "Makes a node an exit (or replaces its exit settings): proxies may send traffic out through it. The node must have declared it can be an exit (`i3t set can-exit on` on the node). Settings left out go back to their defaults.").with(
            {
                let mut properties = vec![("node", node("the node to make an exit"))];
                properties.extend(exit_settings());
                properties
            },
            &["node"],
            Run::Network(|controller, network, mut args| {
                let node = args.take("node")?;
                reply(controller.enable_exit(network, node, args.rest::<ExitRole>()?))
            }),
        ),
        spec("exit_disable", NodesWrite, Removes, "Disable an exit", "Stops a node from being an exit and drops its exit settings. Proxies that go out through it stop working.").with(
            vec![("node", node("the exit to disable"))],
            &["node"],
            Run::Network(|controller, network, mut args| reply(controller.disable_exit(network, args.take("node")?))),
        ),
        // ---- config:write ----
        spec("group_create", ConfigWrite, Adds, "Create a group", "Creates an empty group. Add nodes with group_members_change, then let it reach others with rule_create.").with(
            vec![("name", text("1 to 32 letters, digits, hyphens or underscores; unique in the network, case-insensitive"))],
            &["name"],
            Run::Network(|controller, network, args| reply(controller.create_group(network, &args.rest::<CreateGroup>()?))),
        ),
        spec("group_rename", ConfigWrite, Sets, "Rename a group", "Renames a group. Rules keep working: they refer to the group by id.").with(
            vec![("group", id("Group id")), ("name", text("New name"))],
            &["group", "name"],
            Run::Network(|controller, network, mut args| {
                let group = args.take("group")?;
                reply(controller.update_group(network, group, &args.rest::<UpdateGroup>()?))
            }),
        ),
        spec("group_members_change", ConfigWrite, Sets, "Add or remove group members", "Adds nodes to a group and removes others, in one step. Adding a member or removing a non-member does nothing. Changes who may reach whom at once.").with(
            vec![("group", id("Group id")), ("add", list(id("Node id"), "Nodes to add")), ("remove", list(id("Node id"), "Nodes to remove"))],
            &["group"],
            Run::Network(|controller, network, mut args| {
                let group = args.take("group")?;
                reply(controller.change_members(network, group, &args.rest::<GroupMembers>()?))
            }),
        ),
        spec("group_delete", ConfigWrite, Removes, "Delete a group", "Deletes a group together with every rule that uses it; nodes that could reach each other only through those rules no longer can. The answer lists what was deleted.").with(
            vec![("group", id("Group id"))],
            &["group"],
            Run::Network(|controller, network, mut args| reply(controller.delete_group(network, args.take::<GroupId>("group")?))),
        ),
        spec("rule_create", ConfigWrite, Adds, "Create an access rule", "Lets the nodes of group `src` reach the nodes of group `dst`.").with(
            vec![
                ("name", text("Display name")),
                ("src", id("Group id of the side that connects")),
                ("dst", id("Group id of the side connected to")),
                ("direction", choice("both (default): either side may connect. one_way: only src may", &["both", "one_way"])),
                ("enabled", flag("Default true")),
            ],
            &["src", "dst"],
            Run::Network(|controller, network, args| reply(controller.create_rule(network, &args.rest::<CreateRule>()?))),
        ),
        spec("rule_update", ConfigWrite, Sets, "Change an access rule", "Changes a rule; only the fields given change. Disabling it takes away the access it gives.").with(
            vec![
                ("rule", id("Rule id (see rule_list)")),
                ("name", text("Display name")),
                ("src", id("Group id of the side that connects")),
                ("dst", id("Group id of the side connected to")),
                ("direction", choice("both or one_way", &["both", "one_way"])),
                ("enabled", flag("Whether the rule is in force")),
            ],
            &["rule"],
            Run::Network(|controller, network, mut args| {
                let rule = args.take("rule")?;
                reply(controller.update_rule(network, rule, &args.rest::<UpdateRule>()?))
            }),
        ),
        spec("rule_delete", ConfigWrite, Removes, "Delete an access rule", "Deletes a rule; nodes that could reach each other only through it no longer can.").with(
            vec![("rule", id("Rule id"))],
            &["rule"],
            Run::Network(|controller, network, mut args| done(controller.delete_rule(network, args.take("rule")?))),
        ),
        spec("proxy_create", ConfigWrite, Adds, "Create a proxy", "Opens a SOCKS5/HTTP proxy on a node; requests leave through an exit node. The listening node must be allowed to reach the exit by the access rules.").with(
            {
                let mut properties = vec![
                    ("node", node("the node that listens")),
                    ("bind", text("Listen address, ip:port")),
                    ("exit", node("the exit node requests leave through")),
                    ("class", class("Service class of flows on this proxy")),
                    ("optimistic", flag("Tell the client it is connected before the exit confirms")),
                ];
                properties.extend(proxy_settings());
                properties
            },
            &["node", "bind", "exit"],
            Run::Network(|controller, network, args| reply(controller.create_proxy(network, args.rest::<CreateProxy>()?))),
        ),
        spec("proxy_update", ConfigWrite, Sets, "Change a proxy", "Changes a proxy; only the fields given change.").with(
            {
                let mut properties = vec![
                    ("proxy", id("Proxy id (see proxy_list)")),
                    ("node", node("move the listener to this node")),
                    ("bind", text("Listen address, ip:port")),
                    ("exit", node("the exit node requests leave through")),
                    ("class", choice_or_null("Service class; null = no longer set here", &CLASS)),
                    ("optimistic", json!({ "type": ["boolean", "null"], "description": "Optimistic reply; null = no longer set here" })),
                ];
                properties.extend(proxy_settings());
                properties
            },
            &["proxy"],
            Run::Network(|controller, network, mut args| {
                let proxy = args.take("proxy")?;
                reply(controller.update_proxy(network, proxy, args.rest::<UpdateProxy>()?))
            }),
        ),
        spec("proxy_delete", ConfigWrite, Removes, "Delete a proxy", "Deletes a proxy; its listener closes.").with(
            vec![("proxy", id("Proxy id"))],
            &["proxy"],
            Run::Network(|controller, network, mut args| done(controller.delete_proxy(network, args.take("proxy")?))),
        ),
        spec("forward_create", ConfigWrite, Adds, "Create a port forward", "Opens a listener on one node that carries connections to an address reachable from another node.").with(
            forward_settings(),
            &["protocol", "listen_node", "bind", "target_node", "target_addr"],
            Run::Network(|controller, network, args| reply(controller.create_forward(network, args.rest::<ForwardInput>()?))),
        ),
        spec("forward_replace", ConfigWrite, Sets, "Replace a port forward", "Replaces every setting of a port forward: give all of them, as for forward_create.").with(
            {
                let mut properties = vec![("forward", id("Forward id (see forward_list)"))];
                properties.extend(forward_settings());
                properties
            },
            &["forward", "protocol", "listen_node", "bind", "target_node", "target_addr"],
            Run::Network(|controller, network, mut args| {
                let forward = args.take("forward")?;
                reply(controller.replace_forward(network, forward, args.rest::<ForwardInput>()?))
            }),
        ),
        spec("forward_delete", ConfigWrite, Removes, "Delete a port forward", "Deletes a port forward; its listener closes.").with(
            vec![("forward", id("Forward id"))],
            &["forward"],
            Run::Network(|controller, network, mut args| done(controller.delete_forward(network, args.take("forward")?))),
        ),
        spec("pair_set", ConfigWrite, Sets, "Set a node pair", "Sets how two nodes connect to each other; only the fields given change.").with(
            vec![
                ("a", node("one node of the pair")),
                ("b", node("the other node")),
                ("keep_alive", flag("Keep their connection open even when no flow uses it")),
                ("congestion", choice_or_null("Congestion control on their connection; null = the node default (bbr)", &["bbr", "cubic"])),
            ],
            &["a", "b"],
            Run::Network(|controller, network, mut args| {
                let (a, b) = (args.take("a")?, args.take("b")?);
                reply(controller.set_pair(network, a, b, args.rest::<PairInput>()?))
            }),
        ),
        spec("pair_reset", ConfigWrite, Removes, "Reset a node pair", "Drops the settings of a pair of nodes: both go back to their defaults.").with(
            vec![("a", node("one node of the pair")), ("b", node("the other node"))],
            &["a", "b"],
            Run::Network(|controller, network, mut args| done(controller.delete_pair(network, args.take("a")?, args.take("b")?))),
        ),
        // ---- tests:run ----
        spec("test_start", TestsRun, Adds, "Start a test", "Starts an active test between two nodes (can they connect directly, quality direct and via relays, which route each mode picks, host state). Returns at once: poll test_show. The same pair cannot be tested again right away.").with(
            vec![
                ("a", node("the initiating end")),
                ("b", node("the other end")),
                ("items", list(json!({ "type": "string", "enum": ["direct", "direct_quality", "relay_quality", "route", "host"] }), "What to test; default all")),
                ("throughput", flag("Also measure throughput on the tested paths. Uses bandwidth and traffic, so default false")),
                ("via", list(list(id("Relay node id"), "One path: the relays in order from a to b"), "Relay paths to test for relay_quality; default the ones the two modes would pick")),
            ],
            &["a", "b"],
            Run::Network(|controller, network, args| reply(controller.start_test(network, &args.rest::<CreateTest>()?))),
        ),
        spec("test_cancel", TestsRun, Sets, "Cancel a test", "Cancels a running test. What it has measured so far is kept.").with(
            vec![("test", id("Test id"))],
            &["test"],
            Run::Network(|controller, network, mut args| reply(controller.cancel_test(network, args.take("test")?))),
        ),
        spec("matrix_start", TestsRun, Adds, "Start the test matrix", "Starts a test of every pair of online nodes in the network, a few at a time. Returns at once: poll matrix_show. Takes minutes on a large network.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.start_matrix(network))),
        ),
        spec("matrix_cancel", TestsRun, Sets, "Cancel the test matrix", "Stops the running test matrix. The pairs already tested keep their results.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| reply(controller.cancel_matrix(network))),
        ),
        open_world(spec("exit_test", TestsRun, Reads, "Test an exit", "Asks an exit node to connect to a target on the internet and reports what happened (resolved, connected, timings, or why not). Nothing is changed. Takes up to several seconds.").with(
            vec![("node", node("the exit node")), ("target", text("host[:port]: a domain name, an IPv4 address or an IPv6 address in brackets; default port 443"))],
            &["node", "target"],
            Run::NetworkAsync(|caller, network, mut args| {
                Box::pin(async move {
                    let node = args.take("node")?;
                    let input = args.rest::<ExitTestInput>()?;
                    reply(caller.controller.exit_test(network, node, input).await)
                })
            }),
        )),
        // ---- updates:write ----
        spec("update_settings_set", UpdatesWrite, Sets, "Change update settings", "Changes how nodes are updated; only the fields given change.").with(
            vec![
                ("auto_update", flag("Update nodes automatically when a new release appears")),
                ("source", json!({ "type": ["string", "null"], "description": "Where releases come from (URL or directory); null = the project's default source" })),
            ],
            &[],
            Run::Global(|controller, args| reply(controller.set_update_settings(&args.rest::<UpdateSettings>()?))),
        ),
        open_world(spec("update_check", UpdatesWrite, Sets, "Check for a release", "Asks the release source for the latest release now instead of waiting for the hourly check. With automatic updates on, a new release then starts rolling out. May take tens of seconds.").with(
            vec![],
            &[],
            Run::Global(|controller, _| reply(controller.check_release())),
        )),
        spec("update_resume", UpdatesWrite, Sets, "Resume a paused version", "Resumes automatic updates to a version that was paused because nodes failed to update to it. The nodes that failed are still not retried.").with(
            vec![("version", text("The paused version, e.g. 0.1.35 (see update_status)"))],
            &["version"],
            Run::Global(|controller, mut args| reply(controller.resume_update(&args.take::<Version>("version")?))),
        ),
        spec("update_force_all", UpdatesWrite, Disrupts, "Update every node now", "Orders every node of every network to update to the latest release. Nodes restart; with timing now their running flows break. The answer says which nodes were ordered, queued or skipped and why.").with(
            vec![("timing", timing())],
            &["timing"],
            Run::Global(|controller, mut args| reply(controller.force_update_all(args.take::<UpdateTiming>("timing")?))),
        ),
        spec("node_force_update", UpdatesWrite, Disrupts, "Update one node now", "Orders one online node to update to the latest release. It restarts; with timing now its running flows break.").with(
            vec![("node", node("the node to update")), ("timing", timing())],
            &["node", "timing"],
            Run::Network(|controller, network, mut args| {
                let (node, timing) = (args.take("node")?, args.take::<UpdateTiming>("timing")?);
                reply(controller.force_update(network, node, timing))
            }),
        ),
        // ---- networks:write ----
        spec("network_create", NetworksWrite, Adds, "Create a network", "Creates a network with the built-in group All and a rule that lets all its nodes reach each other.").with(
            {
                let mut properties = vec![("name", text("Lowercase letters, digits and hyphens, at most 63; cannot be changed later"))];
                properties.extend(network_settings());
                properties
            },
            &["name"],
            Run::Global(|controller, args| reply(controller.create_network(&args.rest::<CreateNetwork>()?))),
        ),
        spec("network_update", NetworksWrite, Sets, "Change a network", "Changes a network's settings; only the fields given change.").with(
            {
                let mut properties = network_settings();
                properties.retain(|(name, _)| *name != "class");
                properties.push(("class", choice_or_null("Default service class of flows; null = auto", &CLASS)));
                properties
            },
            &[],
            Run::Network(|controller, network, args| reply(controller.update_network(network, &args.rest::<UpdateNetwork>()?))),
        ),
        spec("network_delete", NetworksWrite, Removes, "Delete a network", "Deletes an empty network with its groups, rules and enrollment tokens. Refused while it still has nodes.").with(
            vec![],
            &[],
            Run::Network(|controller, network, _| done(controller.delete_network(network))),
        ),
    ]
}

/// 会去碰这张网之外的东西的工具。
fn open_world(mut tool: Tool) -> Tool {
    tool.open_world = true;
    tool
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use i3t_model::admin::Direction;
    use i3t_model::admin::diag::TestItem;
    use i3t_model::admin::stats::Series;
    use i3t_model::netmap::{Congestion, ForwardProtocol, IpFamily, ListenerProtocol, Profile, ProxyProtocol, Reach, RoutingMode};
    use i3t_proto::NodeId;
    use i3t_proto::flow::Class;

    use super::*;

    /// 工具 `name` 的参数里，除了 `network` 和 `own`（指明对象的那几个）之外的名字：它们要读成请求类型。
    fn body_fields(name: &str, own: &[&str]) -> BTreeSet<String> {
        let tool = find(name).unwrap_or_else(|| panic!("没有工具 {name}"));
        let properties = tool.schema["properties"].as_object().unwrap();
        for own in own {
            assert!(properties.contains_key(*own), "{name} 要有参数 {own}");
        }
        properties.keys().filter(|property| *property != "network" && !own.contains(&property.as_str())).cloned().collect()
    }

    /// 一个请求类型写成 JSON 之后有哪些字段。`value` 要把每个字段都写上值，省略了的字段不会出现在 JSON 里。
    fn fields<T: Serialize>(value: &T) -> BTreeSet<String> {
        serde_json::to_value(value).unwrap().as_object().unwrap().keys().cloned().collect()
    }

    /// 类型的每个字段在 Schema 里都有，Schema 里也没有类型不认识的字段。
    #[track_caller]
    fn same<T: Serialize + DeserializeOwned>(tool: &str, own: &[&str], value: &T) {
        assert_eq!(body_fields(tool, own), fields(value), "{tool}");
        // 写满了的请求原样读得回来：Schema 里列的名字就是类型认的名字。
        serde_json::from_value::<T>(serde_json::to_value(value).unwrap()).unwrap_or_else(|error| panic!("{tool}: {error}"));
    }

    /// 下面的结构体都把字段写全，不用 `..Default::default()`：请求类型加了字段，这里先编译不过，改的人就会看到 Schema 要跟着加。
    #[test]
    fn the_schema_of_every_tool_lists_exactly_the_fields_of_the_request_type_it_is_read_into() {
        let node = NodeId::new(1).unwrap();
        let cidr = "10.66.0.0/16".parse().unwrap();
        let address = "127.0.0.1:1080".parse().unwrap();
        let ranges = vec!["192.168.1.0/24".parse().unwrap()];

        let create_network = CreateNetwork {
            name: "home".to_owned(),
            cidr: Some(cidr),
            routing: Some(RoutingMode::LowestCost),
            max_relay_hops: Some(2),
            reach: Some(Reach::Any),
            class: Some(Class::Bulk),
            ack_eliciting_threshold: Some(3),
            max_ack_delay_ms: Some(2),
            bundle_small_packets: Some(true),
            vnet_offload: Some(true),
            vnet_mtu: Some(1280),
        };
        same("network_create", &[], &create_network);
        let update_network = UpdateNetwork {
            cidr: Some(cidr),
            routing: Some(RoutingMode::LowestCost),
            max_relay_hops: Some(2),
            reach: Some(Reach::Any),
            class: Some(None),
            ack_eliciting_threshold: Some(3),
            max_ack_delay_ms: Some(2),
            bundle_small_packets: Some(true),
            vnet_offload: Some(true),
            vnet_mtu: Some(1280),
        };
        same("network_update", &[], &update_network);

        let update_node = UpdateNode {
            name: Some("nas".to_owned()),
            groups: Some(vec![GroupId(1)]),
            virtual_ip: Some("10.66.0.9".parse().unwrap()),
            dial_out_only: Some(false),
            routing: Some(None),
            reach: Some(Some(Reach::DirectOnly)),
            pinned_relays: Some(vec![node]),
            profile: Some(Some(Profile::Balanced)),
            forward_target: Some(true),
            auto_update: Some(true),
        };
        same("node_update", &["node"], &update_node);
        same("relay_enable", &["node"], &RelaySettings { bandwidth_mbps: Some(100) });
        let exit = ExitRole {
            ports: Some(vec![443]),
            lan: true,
            upstream_socks5: Some(address),
            quota_bytes: Some(1),
            quota_reset_day: 1,
            family: IpFamily::Ipv4,
            connects_per_minute: Some(60),
            class: Some(Class::Bulk),
            optimistic: Some(true),
        };
        same("exit_enable", &["node"], &exit);

        let token = CreateEnrollToken {
            expires_in_secs: Some(60),
            groups: vec![GroupId(1)],
            virtual_ip: Some("10.66.0.9".parse().unwrap()),
            successor_of: Some(node),
        };
        same("enroll_token_create", &[], &token);

        same("group_create", &[], &CreateGroup { name: "servers".to_owned() });
        same("group_rename", &["group"], &UpdateGroup { name: Some("boxes".to_owned()) });
        same("group_members_change", &["group"], &GroupMembers { add: vec![node], remove: vec![node] });
        let create_rule =
            CreateRule { name: "x".to_owned(), src: GroupId(1), dst: GroupId(2), direction: Direction::OneWay, enabled: true };
        same("rule_create", &[], &create_rule);
        let update_rule = UpdateRule {
            name: Some("x".to_owned()),
            src: Some(GroupId(1)),
            dst: Some(GroupId(2)),
            direction: Some(Direction::Both),
            enabled: Some(false),
        };
        same("rule_update", &["rule"], &update_rule);
        let create_proxy = CreateProxy {
            node,
            name: "out".to_owned(),
            bind: address,
            exit: node,
            protocol: ListenerProtocol::Socks5,
            username: "u".to_owned(),
            password: "p".to_owned(),
            enabled: true,
            allow_from: ranges.clone(),
            class: Some(Class::Bulk),
            optimistic: Some(true),
            lane: true,
        };
        same("proxy_create", &[], &create_proxy);
        let update_proxy = UpdateProxy {
            node: Some(node),
            name: Some("out".to_owned()),
            bind: Some(address),
            exit: Some(node),
            protocol: Some(ListenerProtocol::Http),
            username: Some("u".to_owned()),
            password: Some("p".to_owned()),
            enabled: Some(true),
            allow_from: Some(ranges.clone()),
            class: Some(None),
            optimistic: Some(Some(false)),
            lane: Some(false),
        };
        same("proxy_update", &["proxy"], &update_proxy);
        let forward = ForwardInput {
            name: "web".to_owned(),
            protocol: ForwardProtocol::Tcp,
            listen_node: node,
            bind: address,
            target_node: node,
            target_addr: address,
            allow_from: ranges,
            enabled: true,
            class: Some(Class::Bulk),
            proxy_protocol: Some(ProxyProtocol::V2),
        };
        same("forward_create", &[], &forward);
        same("forward_replace", &["forward"], &forward);
        same("pair_set", &["a", "b"], &PairInput { keep_alive: Some(true), congestion: Some(Some(Congestion::Cubic)) });

        let test = CreateTest { a: node, b: node, items: Some(vec![TestItem::Direct]), throughput: true, via: vec![vec![node]] };
        same("test_start", &[], &test);
        same("test_list", &[], &TestQuery { a: Some(node), b: Some(node), limit: Some(5) });
        let series = SeriesQuery { series: Series::NodeTx, node: Some(node), from: Some(1), to: Some(2), step: Some(300) };
        same("stats_series", &[], &series);
        same("exit_test", &["node"], &ExitTestInput { target: "example.com".to_owned() });
        let settings = UpdateSettings { auto_update: Some(true), source: Some(Some("https://example.com".to_owned())) };
        same("update_settings_set", &[], &settings);
    }

    /// Schema 里写的可选值就是类型认的那些：照着 Schema 写的参数不会被 controller 拒绝，类型认的值 Schema 里也没有漏。
    #[test]
    fn the_choices_a_schema_offers_are_the_values_the_request_types_take() {
        fn offered(tool: &str, property: &str) -> Vec<Value> {
            let schema = &find(tool).unwrap().schema["properties"][property];
            let choices =
                schema.get("enum").or_else(|| schema["items"].get("enum")).unwrap_or_else(|| panic!("{tool}.{property} 没有列出可选值"));
            choices.as_array().unwrap().iter().filter(|choice| !choice.is_null()).cloned().collect()
        }
        fn values<T: Serialize>(all: &[T]) -> Vec<Value> {
            all.iter().map(|value| serde_json::to_value(value).unwrap()).collect()
        }
        let routing = values(&[RoutingMode::DirectFirst, RoutingMode::LowestCost]);
        let reach = values(&[Reach::Any, Reach::DirectOnly, Reach::RelayOnly]);
        let class = values(&[Class::Auto, Class::Interactive, Class::Reliable, Class::Bulk]);
        for tool in ["network_create", "network_update", "node_update"] {
            assert_eq!(offered(tool, "routing"), routing, "{tool}");
            assert_eq!(offered(tool, "reach"), reach, "{tool}");
        }
        for tool in ["network_create", "network_update", "exit_enable", "proxy_create", "proxy_update", "forward_create"] {
            assert_eq!(offered(tool, "class"), class, "{tool}");
        }
        assert_eq!(offered("node_update", "profile"), values(&Profile::ALL));
        assert_eq!(offered("exit_enable", "family"), values(&[IpFamily::Any, IpFamily::Ipv4, IpFamily::Ipv6]));
        let protocols = values(&[ListenerProtocol::Mixed, ListenerProtocol::Socks5, ListenerProtocol::Http]);
        assert_eq!(offered("proxy_create", "protocol"), protocols);
        assert_eq!(offered("forward_create", "protocol"), values(&[ForwardProtocol::Tcp, ForwardProtocol::Udp]));
        assert_eq!(offered("forward_create", "proxy_protocol"), values(&[ProxyProtocol::V1, ProxyProtocol::V2]));
        assert_eq!(offered("pair_set", "congestion"), values(&[Congestion::Bbr, Congestion::Cubic]));
        assert_eq!(offered("rule_create", "direction"), values(&[Direction::Both, Direction::OneWay]));
        assert_eq!(offered("test_start", "items"), values(&TestItem::ALL));
        assert_eq!(offered("stats_series", "series"), values(&Series::ALL));
        // 管理员强制的更新只有这两种时机；`idle` 是自动更新用的。
        for tool in ["update_force_all", "node_force_update"] {
            assert_eq!(offered(tool, "timing"), values(&[UpdateTiming::Now, UpdateTiming::AfterDrain]), "{tool}");
        }
    }

    #[test]
    fn passwords_are_hidden_wherever_they_sit_and_empty_ones_are_left_alone() {
        let mut value = json!({
            "password": "secret",
            "proxies": [{ "username": "u", "password": "secret" }, { "password": "" }],
            "nested": { "deeper": [{ "password": "secret", "name": "password" }] },
            "not_a_password": "secret-looking",
        });
        hide_passwords(&mut value);
        assert_eq!(
            value,
            json!({
                "password": HIDDEN_PASSWORD,
                "proxies": [{ "username": "u", "password": HIDDEN_PASSWORD }, { "password": "" }],
                "nested": { "deeper": [{ "password": HIDDEN_PASSWORD, "name": "password" }] },
                "not_a_password": "secret-looking",
            })
        );
    }
}
