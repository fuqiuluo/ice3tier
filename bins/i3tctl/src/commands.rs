//! 每个子命令做什么：解析出网络和节点，发请求，交给 [`crate::render`] 打印。

use std::io::{self, BufRead, IsTerminal, Write};
use std::net::Ipv4Addr;

use anyhow::{Context, anyhow, bail};
use i3t_model::admin::diag::{CreateTest, MatrixRun, MatrixState, TestState, TestView};
use i3t_model::admin::mcp::{CreateMcpToken, MCP_PATH, McpTokenInfo};
use i3t_model::admin::{
    CreateEnrollToken, CreateGroup, CreateNetwork, CreateProxy, CreateRule, Direction, ExitTestInput, ForceUpdate, Forward, ForwardInput,
    Group, GroupId, GroupMembers, Network, NetworkId, Node, PairInput, RelaySettings, ResumeUpdate, Succeed, UpdateGroup, UpdateNetwork,
    UpdateNode, UpdateProxy, UpdateRule, UpdateSettings,
};
use i3t_model::netmap::{ExitRole, ForwardProtocol};
use i3t_model::update::UpdateTiming;
use i3t_proto::NodeId;
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::cli::{
    AccessCommand, Cli, Command, ExitCommand, ForwardCommand, GroupCommand, McpCommand, McpTokenCommand, NetworkCommand, NetworkSettings,
    NodeCommand, PairCommand, ProxyCommand, RelayCommand, RuleCommand, TestItemArg, TestsCommand, TokenCommand, UpdateCommand,
};
use crate::client::{Client, decode};
use crate::render;
use crate::texts::texts;

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let token = cli.token.context(texts().ui.no_token)?;
    let session = Session { client: Client::new(&cli.url, token)?, network: cli.network, json: cli.json };
    match cli.command {
        Command::Status => session.show(session.get("/status").await?, render::status),
        Command::Overview => {
            let network = session.network().await?;
            session.show(session.get(&format!("/networks/{}/overview", network.id)).await?, render::overview)
        }
        Command::Log { limit, action, reference, before } => {
            let mut query = format!("/log?limit={limit}");
            for (name, value) in [("action", action), ("ref", reference), ("before", before.map(|id| id.to_string()))] {
                if let Some(value) = value {
                    query.push_str(&format!("&{name}={value}"));
                }
            }
            session.show_list(session.get(&query).await?, render::log)
        }
        Command::Network(command) => session.network_command(command).await,
        Command::Node(command) => session.node_command(command).await,
        Command::Relay(command) => session.relay_command(command).await,
        Command::Exit(command) => session.exit_command(command).await,
        Command::Group(command) => session.group_command(command).await,
        Command::Token(command) => session.token_command(command).await,
        Command::Mcp(McpCommand::Token(command)) => session.mcp_token_command(command).await,
        Command::Rule(command) => session.rule_command(command).await,
        Command::Proxy(command) => session.proxy_command(command).await,
        Command::Forward(command) => session.forward_command(command).await,
        Command::Pair(command) => session.pair_command(command).await,
        Command::Access(command) => session.access_command(command).await,
        Command::Update(command) => session.update_command(command).await,
        Command::Path { a, b } => {
            let network = session.network().await?.id;
            let (a, b) = (session.node(network, &a).await?.id, session.node(network, &b).await?.id);
            let names = session.names(network).await?;
            session.show(session.get(&format!("/networks/{network}/path?from={a}&to={b}")).await?, |view| render::path(view, &names))
        }
        Command::Routes => {
            let network = session.network().await?.id;
            session.show(session.get(&format!("/networks/{network}/routes")).await?, render::route_matrix)
        }
        Command::Backbone => {
            let network = session.network().await?.id;
            session.show(session.get(&format!("/networks/{network}/backbone")).await?, render::backbone)
        }
        Command::Stats { series, node, since } => {
            let network = session.network().await?.id;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
            let mut query = format!("/networks/{network}/stats?series={series}&from={}", now.saturating_sub(since.secs));
            if let Some(node) = node {
                query.push_str(&format!("&node={}", session.node(network, &node).await?.id));
            }
            session.show(session.get(&query).await?, render::series)
        }
        Command::Test { a, b, throughput, via, only, no_wait } => session.test(TestArgs { a, b, throughput, via, only, no_wait }).await,
        Command::Tests(command) => session.tests_command(command).await,
    }
}

/// `i3tctl test` 的参数。
struct TestArgs {
    a: String,
    b: String,
    throughput: bool,
    via: Vec<String>,
    only: Vec<TestItemArg>,
    no_wait: bool,
}

/// 等测试和矩阵做完时多久问一次，最多等多久。一个带吞吐的测试最长两分多钟。
const POLL: std::time::Duration = std::time::Duration::from_secs(1);
const WAIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(600);

struct Session {
    client: Client,
    /// `--network` 的值：名字或编号。
    network: Option<String>,
    json: bool,
}

/// `proxy add` 的代理要不要 ice3proxy：写了 `--ice3proxy` 就要；没写时只在终端上问一次（默认不要）。
/// 不是终端、或者 `--json`（给脚本用的）时不问，不要：脚本不会因为等一个回答而卡住。
fn wants_ice3proxy(flag: bool, json: bool, terminal: bool, ask: impl FnOnce() -> io::Result<bool>) -> io::Result<bool> {
    if flag {
        return Ok(true);
    }
    if json || !terminal {
        return Ok(false);
    }
    ask()
}

/// 问一次"要不要 ice3proxy"，读一行回答：`y`、`yes`（不分大小写）、`要`、`是` 是要，别的（直接回车、读到头）是不要。
fn ask_ice3proxy(input: &mut impl BufRead, output: &mut impl Write) -> io::Result<bool> {
    output.write_all(texts().ui.ask_ice3proxy.as_bytes())?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes" | "要" | "是"))
}

impl Session {
    async fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.client.request(Method::GET, path, None::<&()>).await
    }

    async fn send<B: Serialize + Sync>(&self, method: Method, path: &str, body: &B) -> anyhow::Result<Value> {
        self.client.request(method, path, Some(body)).await
    }

    async fn delete(&self, path: &str) -> anyhow::Result<Value> {
        self.client.request(Method::DELETE, path, None::<&()>).await
    }

    /// 打印一个应答：`--json` 时原样输出，否则读成模型里的类型交给 `human`。
    fn show<T: DeserializeOwned>(&self, value: Value, human: impl FnOnce(&T)) -> anyhow::Result<()> {
        if self.json {
            if !value.is_null() {
                println!("{}", serde_json::to_string_pretty(&value).expect("JSON 的值写回 JSON 不会失败"));
            }
        } else {
            human(&decode(value)?);
        }
        Ok(())
    }

    /// 同 [`Session::show`]，应答是一个列表。
    fn show_list<T: DeserializeOwned>(&self, value: Value, human: impl FnOnce(&[T])) -> anyhow::Result<()> {
        self.show(value, |items: &Vec<T>| human(items))
    }

    /// 没有应答体的操作（删除）做完之后说一声；`--json` 时什么都不输出。
    fn done(&self, message: &str) {
        if !self.json {
            println!("{message}");
        }
    }

    /// 等待时在标准错误上说一声；`--json` 时不说。
    fn waiting(&self, message: &str) {
        if !self.json {
            eprintln!("{message}");
        }
    }

    /// 当前操作的网络：`--network` 指的那个；没写的话，只有一个网络时就是它。
    async fn network(&self) -> anyhow::Result<Network> {
        let networks: Vec<Network> = self.client.get("/networks").await?;
        match &self.network {
            Some(reference) => pick_network(networks, reference),
            None => match <[Network; 1]>::try_from(networks) {
                Ok([only]) => Ok(only),
                Err(networks) if networks.is_empty() => bail!(texts().ui.no_networks_yet),
                Err(networks) => {
                    let names = i3t_lang::current().list(networks.iter().map(|network| network.name.as_str()));
                    bail!((texts().ui.several_networks)(&names))
                }
            },
        }
    }

    async fn test(&self, args: TestArgs) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        let (a, b) = (self.node(network, &args.a).await?.id, self.node(network, &args.b).await?.id);
        let mut via = Vec::with_capacity(args.via.len());
        for path in &args.via {
            let mut relays = Vec::new();
            for relay in path.split(',').map(str::trim).filter(|relay| !relay.is_empty()) {
                relays.push(self.node(network, relay).await?.id);
            }
            via.push(relays);
        }
        let items = (!args.only.is_empty()).then(|| args.only.iter().map(|&item| item.into()).collect());
        let request = CreateTest { a, b, items, throughput: args.throughput, via };
        let started: TestView = decode(self.send(Method::POST, &format!("/networks/{network}/tests"), &request).await?)?;
        let path = format!("/networks/{network}/tests/{}", started.id);
        let names = self.names(network).await?;
        if args.no_wait {
            return self.show(self.get(&path).await?, |view| render::test(view, &names));
        }
        self.waiting(&(texts().ui.test_started)(started.id));
        let finished = self.wait(&path, |view: &TestView| view.state != TestState::Running).await?;
        self.show(finished, |view| render::test(view, &names))
    }

    async fn tests_command(&self, command: TestsCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        let tests = format!("/networks/{network}/tests");
        let names = self.names(network).await?;
        match command {
            TestsCommand::List { a, b, limit } => {
                let mut query = format!("{tests}?limit={limit}");
                if let (Some(a), Some(b)) = (&a, &b) {
                    let (a, b) = (self.node(network, a).await?.id, self.node(network, b).await?.id);
                    query.push_str(&format!("&a={a}&b={b}"));
                } else if a.is_some() {
                    bail!(texts().ui.both_nodes);
                }
                self.show_list(self.get(&query).await?, render::tests)
            }
            TestsCommand::Show { id } => self.show(self.get(&format!("{tests}/{id}")).await?, |view| render::test(view, &names)),
            TestsCommand::Cancel { id } => {
                self.show(self.send(Method::POST, &format!("{tests}/{id}/cancel"), &()).await?, |view| render::test(view, &names))
            }
            TestsCommand::Matrix { show, cancel, no_wait } => {
                let path = format!("{tests}/matrix");
                if show {
                    return self.show(self.get(&path).await?, |run| render::matrix(run, &names));
                }
                if cancel {
                    return self.show(self.send(Method::POST, &format!("{path}/cancel"), &()).await?, |run| render::matrix(run, &names));
                }
                let started = self.send(Method::POST, &path, &()).await?;
                if no_wait {
                    return self.show(started, |run| render::matrix(run, &names));
                }
                self.waiting(texts().ui.matrix_started);
                let finished = self.wait(&path, |run: &MatrixRun| run.state != MatrixState::Running).await?;
                self.show(finished, |run| render::matrix(run, &names))
            }
        }
    }

    /// 定期轮询 `path`，直到 `done` 判定完成，返回最终响应。
    async fn wait<T: DeserializeOwned>(&self, path: &str, done: impl Fn(&T) -> bool) -> anyhow::Result<Value> {
        let deadline = tokio::time::Instant::now() + WAIT_LIMIT;
        loop {
            let value = self.get(path).await?;
            let current: T = decode(value.clone())?;
            if done(&current) {
                return Ok(value);
            }
            if tokio::time::Instant::now() >= deadline {
                bail!((texts().ui.wait_timeout)(WAIT_LIMIT.as_secs()));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// 构建将响应中的节点编号映射为名称的查找表。`--json` 模式下原样输出响应，无需拉取节点列表。
    async fn names(&self, network: NetworkId) -> anyhow::Result<render::Names> {
        if self.json {
            return Ok(render::Names::default());
        }
        let nodes: Vec<Node> = self.client.get(&format!("/networks/{network}/nodes")).await?;
        Ok(render::Names::new(&nodes))
    }

    async fn node(&self, network: NetworkId, reference: &str) -> anyhow::Result<Node> {
        let nodes: Vec<Node> = self.client.get(&format!("/networks/{network}/nodes")).await?;
        pick_node(&nodes, reference).cloned()
    }

    /// 把命令行上写的分组找出来：先按名字（不分大小写），没有叫这个名字的再当编号。分组的名字可以全是数字，所以名字优先。
    async fn group(&self, network: NetworkId, reference: &str) -> anyhow::Result<Group> {
        let groups: Vec<Group> = self.client.get(&format!("/networks/{network}/groups")).await?;
        pick_group(&groups, reference).cloned()
    }

    /// 一串分组名换成编号，一个不存在就报出它的名字。
    async fn group_ids(&self, network: NetworkId, references: &[String]) -> anyhow::Result<Vec<GroupId>> {
        if references.is_empty() {
            return Ok(Vec::new());
        }
        let groups: Vec<Group> = self.client.get(&format!("/networks/{network}/groups")).await?;
        references.iter().map(|reference| pick_group(&groups, reference).map(|group| group.id)).collect()
    }

    async fn group_command(&self, command: GroupCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        let groups = format!("/networks/{network}/groups");
        match command {
            GroupCommand::List => self.show_list(self.get(&groups).await?, render::groups),
            GroupCommand::Show { group } => {
                let group = self.group(network, &group).await?;
                self.show(self.get(&format!("{groups}/{}", group.id)).await?, render::group)
            }
            GroupCommand::Create { name } => self.show(self.send(Method::POST, &groups, &CreateGroup { name }).await?, render::group),
            GroupCommand::Rename { group, name } => {
                let group = self.group(network, &group).await?;
                let request = UpdateGroup { name: Some(name) };
                self.show(self.send(Method::PATCH, &format!("{groups}/{}", group.id), &request).await?, render::group)
            }
            GroupCommand::Delete { group } => {
                let group = self.group(network, &group).await?;
                self.show(self.delete(&format!("{groups}/{}", group.id)).await?, render::deleted_group)
            }
            GroupCommand::Add { group, nodes } => {
                let group = self.group(network, &group).await?;
                let request = GroupMembers { add: self.node_ids(network, &nodes).await?, remove: Vec::new() };
                self.show(self.send(Method::PATCH, &format!("{groups}/{}/nodes", group.id), &request).await?, render::group)
            }
            GroupCommand::Remove { group, nodes } => {
                let group = self.group(network, &group).await?;
                let request = GroupMembers { add: Vec::new(), remove: self.node_ids(network, &nodes).await? };
                self.show(self.send(Method::PATCH, &format!("{groups}/{}/nodes", group.id), &request).await?, render::group)
            }
        }
    }

    async fn node_ids(&self, network: NetworkId, references: &[String]) -> anyhow::Result<Vec<NodeId>> {
        let mut ids = Vec::with_capacity(references.len());
        for reference in references {
            ids.push(self.node(network, reference).await?.id);
        }
        Ok(ids)
    }

    async fn network_command(&self, command: NetworkCommand) -> anyhow::Result<()> {
        match command {
            NetworkCommand::List => self.show_list(self.get("/networks").await?, render::networks),
            NetworkCommand::Create { name, settings } => {
                let NetworkSettings {
                    cidr,
                    routing,
                    max_relay_hops,
                    reach,
                    class,
                    ack_eliciting_threshold,
                    max_ack_delay_ms,
                    bundle_small_packets,
                    vnet_offload,
                    vnet_mtu,
                } = settings;
                let request = CreateNetwork {
                    name,
                    cidr,
                    routing: routing.map(Into::into),
                    max_relay_hops,
                    reach: reach.map(Into::into),
                    class: class.and_then(crate::cli::Inherit::into_override),
                    ack_eliciting_threshold,
                    max_ack_delay_ms,
                    bundle_small_packets: bundle_small_packets.map(|switch| switch.0),
                    vnet_offload: vnet_offload.map(|switch| switch.0),
                    vnet_mtu,
                };
                self.show(self.send(Method::POST, "/networks", &request).await?, render::network)
            }
            NetworkCommand::Show => {
                let network = self.network().await?;
                self.show(self.get(&format!("/networks/{}", network.id)).await?, render::network)
            }
            NetworkCommand::Set { settings } => {
                let network = self.network().await?;
                let NetworkSettings {
                    cidr,
                    routing,
                    max_relay_hops,
                    reach,
                    class,
                    ack_eliciting_threshold,
                    max_ack_delay_ms,
                    bundle_small_packets,
                    vnet_offload,
                    vnet_mtu,
                } = settings;
                let request = UpdateNetwork {
                    cidr,
                    routing: routing.map(Into::into),
                    max_relay_hops,
                    reach: reach.map(Into::into),
                    class: class.map(crate::cli::Inherit::into_override),
                    ack_eliciting_threshold,
                    max_ack_delay_ms,
                    bundle_small_packets: bundle_small_packets.map(|switch| switch.0),
                    vnet_offload: vnet_offload.map(|switch| switch.0),
                    vnet_mtu,
                };
                self.show(self.send(Method::PATCH, &format!("/networks/{}", network.id), &request).await?, render::network)
            }
            NetworkCommand::Delete { network } => {
                let network = pick_network(self.client.get("/networks").await?, &network)?;
                self.delete(&format!("/networks/{}", network.id)).await?;
                self.done(&(texts().ui.network_deleted)(&network.name));
                Ok(())
            }
        }
    }

    async fn node_command(&self, command: NodeCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        let nodes = format!("/networks/{network}/nodes");
        match command {
            NodeCommand::List => self.show_list(self.get(&nodes).await?, render::nodes),
            NodeCommand::Show { node } => {
                let node = self.node(network, &node).await?;
                let names = self.names(network).await?;
                self.show(self.get(&format!("{nodes}/{}", node.id)).await?, |detail| render::node_detail(detail, &names))
            }
            NodeCommand::Rename { node, name } => {
                let node = self.node(network, &node).await?;
                let request = UpdateNode { name: Some(name), ..UpdateNode::default() };
                self.show(self.send(Method::PATCH, &format!("{nodes}/{}", node.id), &request).await?, render::node_changed)
            }
            NodeCommand::Groups { node, groups } => {
                let node = self.node(network, &node).await?;
                let request = UpdateNode { groups: Some(self.group_ids(network, &groups).await?), ..UpdateNode::default() };
                self.show(self.send(Method::PATCH, &format!("{nodes}/{}", node.id), &request).await?, render::node_changed)
            }
            NodeCommand::Set { node, ip, dial_out_only, routing, reach, profile, forward_target, auto_update, pins, unpin } => {
                let node = self.node(network, &node).await?;
                let mut pinned_relays = if unpin { Some(Vec::new()) } else { None };
                if !pins.is_empty() {
                    let mut relays = Vec::with_capacity(pins.len());
                    for pin in &pins {
                        relays.push(self.node(network, pin).await?.id);
                    }
                    pinned_relays = Some(relays);
                }
                let request = UpdateNode {
                    virtual_ip: ip,
                    dial_out_only: dial_out_only.map(|switch| switch.0),
                    routing: routing.map(crate::cli::Inherit::into_override),
                    reach: reach.map(crate::cli::Inherit::into_override),
                    profile: profile.map(crate::cli::Inherit::into_override),
                    forward_target: forward_target.map(|switch| switch.0),
                    auto_update: auto_update.map(|switch| switch.0),
                    pinned_relays,
                    ..UpdateNode::default()
                };
                self.show(self.send(Method::PATCH, &format!("{nodes}/{}", node.id), &request).await?, render::node_changed)
            }
            NodeCommand::Delete { node } => {
                let node = self.node(network, &node).await?;
                self.delete(&format!("{nodes}/{}", node.id)).await?;
                self.done(&(texts().ui.node_deleted)(&node.name));
                Ok(())
            }
            NodeCommand::Succeed { node, predecessor } => {
                let node = self.node(network, &node).await?;
                let predecessor = self.node(network, &predecessor).await?;
                let request = Succeed { predecessor: predecessor.id };
                self.show(self.send(Method::POST, &format!("{nodes}/{}/succeed", node.id), &request).await?, render::node_changed)
            }
            NodeCommand::Routes { node } => {
                // 节点列表也用来把路上的 relay 写成名字：relay 不一定是这个节点的对端。
                let all: Vec<Node> = self.client.get(&nodes).await?;
                let node = pick_node(&all, &node)?;
                let names = render::Names::new(&all);
                self.show(self.get(&format!("{nodes}/{}/routes", node.id)).await?, |table| render::routes(table, &names))
            }
            NodeCommand::Access { node } => {
                let node = self.node(network, &node).await?;
                self.show(self.get(&format!("{nodes}/{}/access", node.id)).await?, render::node_access)
            }
            NodeCommand::Listeners { node } => {
                let node = self.node(network, &node).await?;
                self.show(self.get(&format!("{nodes}/{}/listeners", node.id)).await?, render::node_listeners)
            }
        }
    }

    async fn relay_command(&self, command: RelayCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        match command {
            RelayCommand::Enable { node, bandwidth } => {
                let node = self.node(network, &node).await?;
                let settings = RelaySettings { bandwidth_mbps: bandwidth };
                self.show(
                    self.send(Method::PUT, &format!("/networks/{network}/nodes/{}/relay", node.id), &settings).await?,
                    render::relay_enabled,
                )
            }
            RelayCommand::Disable { node } => {
                let node = self.node(network, &node).await?;
                self.show(self.delete(&format!("/networks/{network}/nodes/{}/relay", node.id)).await?, render::node_changed)
            }
            RelayCommand::List => {
                let nodes: Value = self.get(&format!("/networks/{network}/nodes")).await?;
                let relays = nodes.as_array().into_iter().flatten().filter(|node| !node["relay"].is_null()).cloned().collect();
                self.show_list(Value::Array(relays), render::relays)
            }
        }
    }

    async fn exit_command(&self, command: ExitCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        match command {
            ExitCommand::Enable { node, ports, lan, upstream_socks5, quota, reset_day, family, connects_per_minute, class, optimistic } => {
                let node = self.node(network, &node).await?;
                let settings = ExitRole {
                    ports: ports.0,
                    lan,
                    upstream_socks5,
                    quota_bytes: quota.map(|quota| quota.0),
                    quota_reset_day: reset_day,
                    family: family.into(),
                    connects_per_minute,
                    class: class.map(Into::into),
                    optimistic: optimistic.map(|on| on.0),
                };
                self.show(
                    self.send(Method::PUT, &format!("/networks/{network}/nodes/{}/exit", node.id), &settings).await?,
                    render::node_changed,
                )
            }
            ExitCommand::Disable { node } => {
                let node = self.node(network, &node).await?;
                self.show(self.delete(&format!("/networks/{network}/nodes/{}/exit", node.id)).await?, render::node_changed)
            }
            ExitCommand::List => {
                let names = self.names(network).await?;
                self.show_list(self.get(&format!("/networks/{network}/exits")).await?, |exits| render::exits(exits, &names))
            }
            ExitCommand::Test { node, target } => {
                let node = self.node(network, &node).await?;
                let input = ExitTestInput { target };
                self.show(self.send(Method::POST, &format!("/networks/{network}/exits/{}/test", node.id), &input).await?, render::exit_test)
            }
        }
    }

    async fn token_command(&self, command: TokenCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        let tokens = format!("/networks/{network}/tokens");
        match command {
            TokenCommand::List { all } => {
                let path = if all { format!("{tokens}?all=true") } else { tokens };
                self.show_list(self.get(&path).await?, render::tokens)
            }
            TokenCommand::Create { expires, groups, ip, successor_of } => {
                let successor_of = match successor_of {
                    Some(reference) => Some(self.node(network, &reference).await?.id),
                    None => None,
                };
                let groups = self.group_ids(network, &groups).await?;
                let request = CreateEnrollToken { expires_in_secs: Some(expires.secs), groups, virtual_ip: ip, successor_of };
                self.show(self.send(Method::POST, &tokens, &request).await?, render::created_token)
            }
            TokenCommand::Delete { id } => {
                self.delete(&format!("{tokens}/{id}")).await?;
                self.done(&(texts().ui.token_deleted)(id));
                Ok(())
            }
        }
    }

    async fn mcp_token_command(&self, command: McpTokenCommand) -> anyhow::Result<()> {
        let tokens = format!("{MCP_PATH}/tokens");
        match command {
            McpTokenCommand::List => {
                let networks: Vec<Network> = if self.json { Vec::new() } else { self.client.get("/networks").await? };
                self.show_list(self.get(&tokens).await?, |tokens| render::mcp_tokens(tokens, &networks))
            }
            McpTokenCommand::Create { name, scopes, expires_in } => {
                // `--network` 写了就只限它，没写就不限。不像别的命令那样"只有一个网络就是它"：不替管理员把令牌收窄。
                let network = match self.network.as_deref().filter(|reference| !reference.is_empty()) {
                    Some(reference) => Some(pick_network(self.client.get("/networks").await?, reference)?),
                    None => None,
                };
                let request =
                    CreateMcpToken { name, scopes, network: network.as_ref().map(|network| network.id), expires_in_secs: expires_in.secs };
                let endpoint = self.client.url_of(MCP_PATH);
                let network = network.map(|network| network.name);
                self.show(self.send(Method::POST, &tokens, &request).await?, |created| {
                    render::created_mcp_token(created, network.as_deref(), &endpoint);
                })
            }
            McpTokenCommand::Revoke { id } => {
                let revoked = self.client.request(Method::POST, &format!("{tokens}/{id}/revoke"), None::<&()>).await?;
                self.show(revoked, |token: &McpTokenInfo| println!("{}", (texts().ui.mcp_token_revoked)(token.id, &token.name)))
            }
        }
    }

    async fn rule_command(&self, command: RuleCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        let rules = format!("/networks/{network}/rules");
        let set_enabled = |enabled| UpdateRule { enabled: Some(enabled), ..UpdateRule::default() };
        match command {
            RuleCommand::List => self.show_list(self.get(&rules).await?, render::rules),
            RuleCommand::Add { src, dst, one_way, name, disabled } => {
                let direction = if one_way { Direction::OneWay } else { Direction::Both };
                let (src, dst) = (self.group(network, &src).await?.id, self.group(network, &dst).await?.id);
                let request = CreateRule { name, src, dst, direction, enabled: !disabled };
                self.show(self.send(Method::POST, &rules, &request).await?, render::rule)
            }
            RuleCommand::Enable { id } => {
                self.show(self.send(Method::PATCH, &format!("{rules}/{id}"), &set_enabled(true)).await?, render::rule)
            }
            RuleCommand::Disable { id } => {
                self.show(self.send(Method::PATCH, &format!("{rules}/{id}"), &set_enabled(false)).await?, render::rule)
            }
            RuleCommand::Delete { id } => {
                self.delete(&format!("{rules}/{id}")).await?;
                self.done(&(texts().ui.rule_deleted)(id));
                Ok(())
            }
        }
    }

    async fn proxy_command(&self, command: ProxyCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        let proxies = format!("/networks/{network}/proxies");
        match command {
            ProxyCommand::List { node } => {
                let path = match node {
                    Some(reference) => format!("{proxies}?node={}", self.node(network, &reference).await?.id),
                    None => proxies,
                };
                let names = self.names(network).await?;
                self.show_list(self.get(&path).await?, |proxies| render::proxies(proxies, &names))
            }
            ProxyCommand::Show { id } => {
                let names = self.names(network).await?;
                self.show(self.get(&format!("{proxies}/{id}")).await?, |proxy| render::proxy(proxy, &names))
            }
            ProxyCommand::Add {
                node,
                bind,
                exit,
                name,
                protocol,
                username,
                password,
                allow_from,
                class,
                optimistic,
                disabled,
                ice3proxy,
            } => {
                let (node, exit) = (self.node(network, &node).await?.id, self.node(network, &exit).await?.id);
                // 节点都找到了再问：写错了节点不该先答一个问题。
                let terminal = io::stdin().is_terminal() && io::stderr().is_terminal();
                let lane = wants_ice3proxy(ice3proxy, self.json, terminal, || ask_ice3proxy(&mut io::stdin().lock(), &mut io::stderr()))
                    .context(texts().ui.answer_unreadable)?;
                let request = CreateProxy {
                    node,
                    name,
                    bind,
                    exit,
                    protocol: protocol.map(Into::into).unwrap_or_default(),
                    username,
                    password,
                    enabled: !disabled,
                    allow_from,
                    class: class.map(Into::into),
                    optimistic: optimistic.map(|on| on.0),
                    lane,
                };
                let names = self.names(network).await?;
                self.show(self.send(Method::POST, &proxies, &request).await?, |proxy| render::proxy(proxy, &names))
            }
            ProxyCommand::Set {
                id,
                node,
                name,
                bind,
                exit,
                protocol,
                username,
                password,
                allow_from,
                class,
                optimistic,
                enabled,
                ice3proxy,
            } => {
                let node = match node {
                    Some(reference) => Some(self.node(network, &reference).await?.id),
                    None => None,
                };
                let exit = match exit {
                    Some(reference) => Some(self.node(network, &reference).await?.id),
                    None => None,
                };
                let request = UpdateProxy {
                    node,
                    name,
                    bind,
                    exit,
                    protocol: protocol.map(Into::into),
                    username,
                    password,
                    enabled: enabled.map(|on| on.0),
                    allow_from,
                    class: class.map(crate::cli::Inherit::into_override),
                    optimistic: optimistic.map(crate::cli::Inherit::into_override),
                    lane: ice3proxy.map(|on| on.0),
                };
                let names = self.names(network).await?;
                self.show(self.send(Method::PATCH, &format!("{proxies}/{id}"), &request).await?, |proxy| render::proxy(proxy, &names))
            }
            ProxyCommand::Delete { id } => {
                self.delete(&format!("{proxies}/{id}")).await?;
                self.done(&(texts().ui.proxy_deleted)(id));
                Ok(())
            }
        }
    }

    async fn forward_command(&self, command: ForwardCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        let forwards = format!("/networks/{network}/forwards");
        match command {
            ForwardCommand::List => self.show_list(self.get(&forwards).await?, render::forwards),
            ForwardCommand::Add { listen_node, bind, target_node, target_addr, udp, name, allow_from, disabled, class, proxy_protocol } => {
                let input = ForwardInput {
                    name,
                    protocol: if udp { ForwardProtocol::Udp } else { ForwardProtocol::Tcp },
                    listen_node: self.node(network, &listen_node).await?.id,
                    bind,
                    target_node: self.node(network, &target_node).await?.id,
                    target_addr,
                    allow_from,
                    enabled: !disabled,
                    class: class.map(Into::into),
                    proxy_protocol,
                };
                self.show(self.send(Method::POST, &forwards, &input).await?, render::forward)
            }
            ForwardCommand::Enable { id } => self.switch_forward(&forwards, id, true).await,
            ForwardCommand::Disable { id } => self.switch_forward(&forwards, id, false).await,
            ForwardCommand::Delete { id } => {
                self.delete(&format!("{forwards}/{id}")).await?;
                self.done(&(texts().ui.forward_deleted)(id));
                Ok(())
            }
        }
    }

    /// 启用或停用一条转发。管理 API 只能整条替换，所以先取出来，改掉开关再放回去。
    async fn switch_forward(&self, forwards: &str, id: u32, enabled: bool) -> anyhow::Result<()> {
        let existing: Vec<Forward> = self.client.get(forwards).await?;
        let forward = existing.into_iter().find(|forward| forward.id == id).ok_or_else(|| anyhow!((texts().ui.no_such_forward)(id)))?;
        let input = ForwardInput {
            name: forward.name,
            protocol: forward.protocol,
            listen_node: forward.listen_node,
            bind: forward.bind,
            target_node: forward.target_node,
            target_addr: forward.target_addr,
            allow_from: forward.allow_from,
            enabled,
            class: forward.class,
            proxy_protocol: forward.proxy_protocol,
        };
        self.show(self.send(Method::PUT, &format!("{forwards}/{id}"), &input).await?, render::forward)
    }

    async fn pair_command(&self, command: PairCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        let pairs = format!("/networks/{network}/pairs");
        match command {
            PairCommand::List => self.show_list(self.get(&pairs).await?, render::pairs),
            PairCommand::Show { a, b } => {
                let (a, b) = (self.node(network, &a).await?.id, self.node(network, &b).await?.id);
                self.show(self.get(&format!("{pairs}/{a}/{b}")).await?, render::pair)
            }
            PairCommand::Set { a, b, keep_alive, congestion } => {
                let (a, b) = (self.node(network, &a).await?.id, self.node(network, &b).await?.id);
                let input = PairInput { keep_alive: keep_alive.map(|on| on.0), congestion: congestion.map(|arg| arg.0) };
                self.show(self.send(Method::PUT, &format!("{pairs}/{a}/{b}"), &input).await?, render::pair)
            }
            PairCommand::Unset { a, b } => {
                let (a, b) = (self.node(network, &a).await?.id, self.node(network, &b).await?.id);
                self.delete(&format!("{pairs}/{a}/{b}")).await?;
                self.done(&(texts().ui.pair_unset)(a.get(), b.get()));
                Ok(())
            }
        }
    }

    async fn access_command(&self, command: AccessCommand) -> anyhow::Result<()> {
        let network = self.network().await?.id;
        match command {
            AccessCommand::Graph => self.show(self.get(&format!("/networks/{network}/access/graph")).await?, render::access_graph),
            AccessCommand::Check { from, to } => {
                let (from, to) = (self.node(network, &from).await?.id, self.node(network, &to).await?.id);
                self.show(self.get(&format!("/networks/{network}/access/check?from={from}&to={to}")).await?, render::access_check)
            }
        }
    }
}

impl Session {
    async fn update_command(&self, command: UpdateCommand) -> anyhow::Result<()> {
        let timing = |drain: bool| if drain { UpdateTiming::AfterDrain } else { UpdateTiming::Now };
        match command {
            UpdateCommand::Show => self.show(self.get("/update").await?, render::update_overview),
            UpdateCommand::Set { auto, source } => {
                let source = source.map(|source| (source != "default").then_some(source));
                let request = UpdateSettings { auto_update: auto.map(|switch| switch.0), source };
                self.show(self.send(Method::PATCH, "/update", &request).await?, render::update_overview)
            }
            UpdateCommand::Check => {
                self.show(self.send(Method::POST, "/update/check", &serde_json::json!({})).await?, render::update_overview)
            }
            UpdateCommand::Nodes => {
                let network = self.network().await?.id;
                self.show_list(self.get(&format!("/networks/{network}/nodes")).await?, render::node_updates)
            }
            UpdateCommand::Node { node, drain } => {
                let network = self.network().await?.id;
                let node = self.node(network, &node).await?;
                let request = ForceUpdate { timing: timing(drain) };
                let path = format!("/networks/{network}/nodes/{}/update", node.id);
                self.show(self.send(Method::POST, &path, &request).await?, |update| render::node_update(&node.name, update))
            }
            UpdateCommand::All { drain } => {
                let request = ForceUpdate { timing: timing(drain) };
                self.show(self.send(Method::POST, "/update/force", &request).await?, render::forced_updates)
            }
            UpdateCommand::Resume { version } => {
                let version = version.parse().map_err(|_| anyhow!((texts().ui.bad_version)(&version)))?;
                self.show(self.send(Method::POST, "/update/resume", &ResumeUpdate { version }).await?, render::update_overview)
            }
        }
    }
}

/// 命令行上写的节点：编号、虚拟 IP 或者名字（不分大小写）。
fn pick_node<'a>(nodes: &'a [Node], reference: &str) -> anyhow::Result<&'a Node> {
    let by_id = reference.parse::<NodeId>().ok();
    let by_ip = reference.parse::<Ipv4Addr>().ok();
    let found =
        nodes.iter().find(|node| Some(node.id) == by_id || Some(node.virtual_ip) == by_ip || node.name.eq_ignore_ascii_case(reference));
    found.ok_or_else(|| anyhow!((texts().ui.no_such_node)(reference)))
}

/// 按名字或编号在网络列表里找一个。
/// 名字不分大小写（按 Unicode 的小写比）；没有叫这个名字的分组时，写的是数字就当编号。
fn pick_group<'a>(groups: &'a [Group], reference: &str) -> anyhow::Result<&'a Group> {
    let folded = reference.to_lowercase();
    let by_id = reference.parse::<GroupId>().ok();
    let by_name = groups.iter().find(|group| group.name.to_lowercase() == folded);
    by_name.or_else(|| groups.iter().find(|group| Some(group.id) == by_id)).ok_or_else(|| anyhow!((texts().ui.no_such_group)(reference)))
}

fn pick_network(networks: Vec<Network>, reference: &str) -> anyhow::Result<Network> {
    let by_id = reference.parse::<NetworkId>().ok();
    let found = networks.into_iter().find(|network| network.name.eq_ignore_ascii_case(reference) || Some(network.id) == by_id);
    found.ok_or_else(|| anyhow!((texts().ui.no_such_network)(reference)))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;

    use super::*;

    #[test]
    fn proxy_add_asks_about_ice3proxy_only_on_a_terminal_without_the_flag_or_json() {
        let asked = Cell::new(0);
        let ask = |answer: bool| {
            let asked = &asked;
            move || {
                asked.set(asked.get() + 1);
                Ok(answer)
            }
        };
        assert!(wants_ice3proxy(true, false, true, ask(false)).unwrap(), "写了 --ice3proxy：要，不问");
        assert!(!wants_ice3proxy(false, true, true, ask(true)).unwrap(), "--json：不问，不要");
        assert!(!wants_ice3proxy(false, false, false, ask(true)).unwrap(), "不是终端：不问，不要");
        assert_eq!(asked.get(), 0);
        assert!(wants_ice3proxy(false, false, true, ask(true)).unwrap(), "终端上没写：问，按回答");
        assert!(!wants_ice3proxy(false, false, true, ask(false)).unwrap());
        assert_eq!(asked.get(), 2, "只问一次");
    }

    #[test]
    fn the_ice3proxy_question_defaults_to_no() {
        let answer = |typed: &str| {
            let mut shown = Vec::new();
            let wanted = ask_ice3proxy(&mut Cursor::new(typed.as_bytes()), &mut shown).unwrap();
            assert_eq!(String::from_utf8(shown).unwrap(), texts().ui.ask_ice3proxy, "问的是这一句");
            wanted
        };
        for yes in ["y\n", "Y\n", "yes\n", " YES \n", "要\n", "是\n"] {
            assert!(answer(yes), "{yes:?}");
        }
        for no in ["\n", "", "n\n", "no\n", "sure\n"] {
            assert!(!answer(no), "{no:?}：直接回车、读到头和别的回答都是不要");
        }
    }
}
