//! 节点：查看、改名、改所在的分组、启用能力、删除、继任。

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};

use i3t_model::admin::{LogRef, NetworkId, Node, NodeDetail, RelaySettings, Timestamp, UpdateNode, action};
use i3t_model::control::ToNode;
use i3t_model::netmap::ExitRole;
use i3t_proto::NodeId;
use serde_json::{Map, Value, json};

use super::groups::resolve_groups;
use super::{COOLDOWN_SECS, Controller, Inner, Seeds, address, first_failure, listed, naming, switch};
use crate::error::{Capability, Entity, Error, InField};
use crate::relay_reach::{self, ReachIndex};
use crate::store::{CooldownKind, GroupRecord, NetworkRecord, NodeRecord, Store, is_pending};

/// 一个节点最多固定几个挂靠 relay。只是防止填错。
const MAX_PINNED_RELAYS: usize = 8;

impl Controller {
    /// 一个网络里的全部节点。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn nodes(&self, network: NetworkId) -> Result<Vec<Node>, Error> {
        let inner = self.lock();
        let network = inner.require_network(network)?;
        let now = inner.clock.now();
        let groups = inner.store.groups(network.id)?;
        let records = inner.store.nodes(network.id)?;
        let reach = ReachIndex::new(&records, |id| inner.is_online(id));
        Ok(records.iter().map(|record| inner.node_view(&network, &groups, record, now, &reach)).collect())
    }

    /// # Errors
    ///
    /// 这个网络里没有这个节点，或者读存储失败。
    pub fn node(&self, network: NetworkId, id: NodeId) -> Result<NodeDetail, Error> {
        let inner = self.lock();
        let network = inner.require_network(network)?;
        let record = inner.require_node(network.id, id)?;
        let live = inner.live.get(&id);
        let records = inner.store.nodes(network.id)?;
        let reach = ReachIndex::new(&records, |id| inner.is_online(id));
        let reached_by = record.relay.as_ref().map(|_| relay_reach::reached_by(&records, id, |id| inner.is_online(id)));
        Ok(NodeDetail {
            node: inner.node_view(&network, &inner.store.groups(network.id)?, &record, inner.clock.now(), &reach),
            endpoints: record.endpoints,
            observed_endpoint: record.observed,
            mapping_varies: live.and_then(|live| live.mapping_varies),
            flows: live.map_or(0, |live| live.flows),
            tx_bytes: live.map_or(0, |live| live.tx_bytes),
            rx_bytes: live.map_or(0, |live| live.rx_bytes),
            lanes: live.and_then(|live| live.lanes.clone()),
            reported_secs_ago: live.and_then(|live| live.reported_at).map(|at| at.elapsed().as_secs()),
            performance: live.and_then(|live| live.performance.clone()),
            vnet: live.and_then(|live| live.vnet.clone()),
            reached_by,
        })
    }

    /// 改节点的名字、所在的分组、虚拟 IP 和各个开关。只改请求里写了的字段。
    ///
    /// # Errors
    ///
    /// 名字或虚拟 IP 不合法、被占用、在冷却期；固定的挂靠 relay 不是这个网络里启用了的 relay；
    /// 分组不是这个网络里已有的分组（`field` 是 `groups[序号]`）。
    pub fn update_node(&self, network: NetworkId, id: NodeId, request: &UpdateNode) -> Result<Node, Error> {
        let mut inner = self.lock();
        let network = inner.require_network(network)?;
        let now = inner.clock.now();
        let (before, after, groups, listeners) = inner.store.atomically(|store| {
            let before = require_node(store, network.id, id)?;
            let mut node = before.clone();
            if let Some(name) = &request.name {
                node.name = naming::label("节点", name).in_field("name")?;
                if node.name != before.name {
                    check_node_name(store, network.id, &node.name, now).in_field("name")?;
                }
            }
            if let Some(groups) = &request.groups {
                node.groups = resolve_groups(store, network.id, groups, "groups")?;
            }
            if let Some(virtual_ip) = request.virtual_ip.filter(|ip| *ip != before.virtual_ip) {
                check_address(store, &network, virtual_ip, now).in_field("virtual_ip")?;
                node.virtual_ip = virtual_ip;
            }
            if let Some(pinned) = &request.pinned_relays {
                node.pinned_relays = check_pinned_relays(store, &node, pinned)?;
            }
            node.dial_out_only = request.dial_out_only.unwrap_or(node.dial_out_only);
            node.routing = request.routing.unwrap_or(node.routing);
            node.reach = request.reach.unwrap_or(node.reach);
            node.profile = request.profile.unwrap_or(node.profile);
            node.forward_target = request.forward_target.unwrap_or(node.forward_target);
            node.auto_update = request.auto_update.unwrap_or(node.auto_update);
            store.update_node(&node)?;
            if node.groups != before.groups {
                store.set_node_groups(id, &node.groups)?;
            }
            let groups = store.groups(network.id)?;
            let params = update_params(&before, &node, &groups);
            let detail = describe_update(&before, &node, &groups);
            store.log_refs(now, Some(network.id), action::NODE_UPDATE, &detail, &[LogRef::node(id)], params)?;
            // 需要重算的节点集合也在此事务内读取：若提交后再读取，一旦读取失败会导致变更已生效但无人触发重算。
            // relay 的名字写在全网每个节点的 netmap 里（这时是 `None`：全网都要重算，不用读）；别的改动只影响 netmap 里有它的节点。
            // 端口转发目标的开关只管指向它的转发：两端的节点（监听节点不一定在它的 netmap 里，比如访问规则不允许时）。
            let listeners = if node.relay.is_some() && before.name != node.name {
                None
            } else if node.forward_target != before.forward_target {
                let forwards = store.forwards(network.id)?.into_iter();
                Some(forwards.filter(|forward| forward.config.target_node == id).map(|forward| forward.config.listen_node).collect())
            } else {
                Some(Vec::new())
            };
            Ok::<_, Error>((before, node, groups, listeners))
        })?;
        // 事务提交后再记录日志：若未提交则未发生任何状态变更。
        if after.forward_target != before.forward_target {
            let state = if after.forward_target { "打开" } else { "关闭" };
            tracing::info!(node = %id, name = %after.name, "管理员已{state}节点的端口转发目标开关");
        }
        if after.auto_update != before.auto_update {
            let state = if after.auto_update { "打开" } else { "关闭" };
            tracing::info!(node = %id, name = %after.name, "管理员已{state}节点的自动更新");
        }
        let seeds = match listeners {
            None => Seeds::All,
            Some(listeners) if after.forward_target != before.forward_target => {
                let mut seeds = inner.holders_of(id);
                seeds.insert(id);
                seeds.extend(listeners);
                Seeds::Nodes(seeds)
            }
            Some(_) => inner.holders_and(id),
        };
        let refreshed = inner.refresh(network.id, seeds, None);
        // 关闭自动更新时撤回尚未执行的自动更新指令，开启时将其纳入调度，与全局开关行为一致；即使重算失败也需执行，因为开关变更已提交。
        let rolled = if after.auto_update == before.auto_update { Ok(()) } else { inner.roll_out() };
        self.wake_if_needed(&inner);
        first_failure(refreshed, rolled)?;
        Ok(inner.node_view(&network, &groups, &after, now, &inner.reach_index(network.id)?))
    }

    /// 把节点启用为 relay，或者改它的 relay 设置。
    ///
    /// 无需手动指定地址：relay 地址由 controller 自动收集。也不预先要求连通性校验：能否作为中继取决于各节点自身到它的连通性，
    /// 当前尚无任何已知地址的节点也可启用，待其上线后将自动补全地址。
    ///
    /// # Errors
    ///
    /// 节点没有声明可以作为 relay；带宽上限写了 0。
    pub fn enable_relay(&self, network: NetworkId, id: NodeId, settings: RelaySettings) -> Result<Node, Error> {
        let settings = check_relay_settings(settings)?;
        self.set_capability(network, id, Affects::WholeNetwork, action::NODE_RELAY_ENABLE, move |node| {
            if !node.declared.relay {
                return Err(Error::NotDeclared { node: node.name.clone(), capability: Capability::Relay });
            }
            node.relay = Some(settings);
            Ok(())
        })
    }

    /// # Errors
    ///
    /// 这个网络里没有这个节点。
    pub fn disable_relay(&self, network: NetworkId, id: NodeId) -> Result<Node, Error> {
        self.set_capability(network, id, Affects::WholeNetwork, action::NODE_RELAY_DISABLE, |node| {
            node.relay = None;
            Ok(())
        })
    }

    /// 把节点启用为出口，或者改它的出口设置。
    ///
    /// # Errors
    ///
    /// 节点没有声明可以作为出口；端口或上游代理的地址不合法。
    pub fn enable_exit(&self, network: NetworkId, id: NodeId, settings: ExitRole) -> Result<Node, Error> {
        let settings = check_exit_settings(settings)?;
        self.set_capability(network, id, Affects::Holders, action::NODE_EXIT_ENABLE, move |node| {
            if !node.declared.exit {
                return Err(Error::NotDeclared { node: node.name.clone(), capability: Capability::Exit });
            }
            node.exit = Some(settings);
            Ok(())
        })
    }

    /// # Errors
    ///
    /// 这个网络里没有这个节点。
    pub fn disable_exit(&self, network: NetworkId, id: NodeId) -> Result<Node, Error> {
        self.set_capability(network, id, Affects::Holders, action::NODE_EXIT_DISABLE, |node| {
            node.exit = None;
            Ok(())
        })
    }

    fn set_capability(
        &self,
        network: NetworkId,
        id: NodeId,
        affects: Affects,
        action: &str,
        change: impl FnOnce(&mut NodeRecord) -> Result<(), Error>,
    ) -> Result<Node, Error> {
        let mut inner = self.lock();
        let network = inner.require_network(network)?;
        let now = inner.clock.now();
        let node = inner.store.atomically(|store| {
            let mut node = require_node(store, network.id, id)?;
            change(&mut node)?;
            store.update_node(&node)?;
            let params = json!({ "node": id, "node_name": node.name });
            store.log_refs(now, Some(network.id), action, &format!("节点 {}", node.name), &[LogRef::node(id)], params)?;
            Ok::<_, Error>(node)
        })?;
        tracing::info!(node = %id, name = %node.name, action, "修改节点的能力");
        if node.exit.is_none() {
            inner.usage.exit_disabled(id);
        }
        let seeds = match affects {
            Affects::WholeNetwork => Seeds::All,
            Affects::Holders => inner.holders_and(id),
        };
        let refreshed = inner.refresh(network.id, seeds, None);
        // relay 更新需串行排队，节点是否作为 relay 变更会影响轮次分配；即使 netmap 重算失败也需推进更新，因为能力变更已生效。
        let rolled = inner.roll_out();
        self.wake_if_needed(&inner);
        first_failure(refreshed, rolled)?;
        Ok(inner.node_view(&network, &inner.store.groups(network.id)?, &node, now, &inner.reach_index(network.id)?))
    }

    /// 删掉一个节点：吊销它的公钥，立即把它从所有节点的 netmap 里去掉。
    /// 它的虚拟 IP 和名字进入冷却期，到期之前不分给别的节点。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个节点，或者写存储失败。
    pub fn delete_node(&self, network: NetworkId, id: NodeId) -> Result<(), Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let node = inner.store.atomically(|store| {
            let node = require_node(store, network, id)?;
            let until = now.saturating_add(COOLDOWN_SECS);
            store.add_cooldown(network, CooldownKind::Address, &node.virtual_ip.to_string(), until)?;
            store.add_cooldown(network, CooldownKind::Name, &node.name, until)?;
            unpin_everywhere(store, network, id)?;
            store.delete_node(id)?;
            store.log_refs(
                now,
                Some(network),
                action::NODE_DELETE,
                &format!("删除节点 {}（{}）", node.name, node.virtual_ip),
                &[LogRef::node(id)],
                json!({ "node": id, "node_name": node.name, "virtual_ip": node.virtual_ip }),
            )?;
            Ok::<_, Error>(node)
        })?;
        tracing::info!(node = %id, name = %node.name, "删除节点，吊销它的公钥");
        // 先告诉它自己，再从别人那里去掉它。它的连接随着发送队列的关闭而结束。
        inner.send(id, ToNode::Revoked);
        inner.forget_node(id);
        let refreshed = inner.refresh(network, Seeds::All, None);
        // 若被删节点正占用 relay 更新轮次，则推进至下一个 relay；即使 netmap 重算失败也需执行，因为节点已被删除。
        let rolled = inner.roll_out();
        self.wake_if_needed(&inner);
        first_failure(refreshed, rolled)
    }

    /// 把 `id` 指定为已下线节点 `predecessor` 的继任：继承它的虚拟 IP、名字、所在的分组（和自己的合并），
    /// 以及指向它的端口转发、监听器和节点对设置；然后删掉 `predecessor`。
    ///
    /// relay 和出口不继承：要在新机器上重新声明，再重新启用。管理员的两个开关跟着身份走：可以作为端口转发的目标（打开的），
    /// 和关掉的自动更新（管理员不让自动更新的是这个身份，换了机器也一样）。
    ///
    /// # Errors
    ///
    /// 两个节点不都在这个网络里，或者 `predecessor` 还在线。
    pub fn succeed(&self, network: NetworkId, id: NodeId, predecessor: NodeId) -> Result<Node, Error> {
        if id == predecessor {
            return Err(Error::invalid_field("predecessor", "same_node", "节点不能继任自身"));
        }
        let mut inner = self.lock();
        let network = inner.require_network(network)?;
        let now = inner.clock.now();
        if inner.is_online(predecessor) {
            return Err(Error::PredecessorOnline(inner.require_node(network.id, predecessor)?.name));
        }
        let node = inner.store.atomically(|store| {
            let old = require_node(store, network.id, predecessor).in_field("predecessor")?;
            let mut node = require_node(store, network.id, id)?;
            let former = format!("{}（{}）", node.name, node.virtual_ip);
            let params = json!({
                "node": id,
                "node_name": node.name,
                "virtual_ip": node.virtual_ip,
                "predecessor": predecessor,
                "predecessor_name": old.name,
                "predecessor_virtual_ip": old.virtual_ip,
            });
            store.park_node(predecessor)?;
            node.name.clone_from(&old.name);
            node.virtual_ip = old.virtual_ip;
            store.update_node(&node)?;
            inherit(store, network.id, &old, &node)?;
            let node = require_node(store, network.id, id)?;
            let detail = format!("节点 {former} 继任 {}（{}）", old.name, old.virtual_ip);
            store.log_refs(now, Some(network.id), action::NODE_SUCCEED, &detail, &[LogRef::node(id), LogRef::node(predecessor)], params)?;
            Ok::<_, Error>(node)
        })?;
        tracing::info!(node = %id, %predecessor, name = %node.name, "节点继任");
        inner.forget_node(predecessor);
        let refreshed = inner.refresh(network.id, Seeds::All, None);
        // 继任者可能继承了关闭的自动更新开关，需撤回已下发的自动更新；即使 netmap 重算失败也需执行，因为继任已生效。
        let rolled = inner.roll_out();
        self.wake_if_needed(&inner);
        first_failure(refreshed, rolled)?;
        Ok(inner.node_view(&network, &inner.store.groups(network.id)?, &node, now, &inner.reach_index(network.id)?))
    }
}

/// 一项能力的变化要重算哪些节点。
#[derive(Clone, Copy)]
enum Affects {
    /// relay 列在全网每个节点的 netmap 里。
    WholeNetwork,
    /// 出口只写在能访问它的节点的 netmap 里。
    Holders,
}

impl Inner {
    /// `id` 自己，加上 netmap 里有它的节点。
    pub(crate) fn holders_and(&self, id: NodeId) -> Seeds {
        let mut seeds = self.holders_of(id);
        seeds.insert(id);
        Seeds::Nodes(seeds)
    }

    /// 一个节点不存在了：丢掉它的下发状态和排着的工作，别的节点也不再记着它。
    pub(crate) fn forget_node(&mut self, id: NodeId) {
        self.live.remove(&id);
        self.sync.remove(&id);
        self.dirty.remove(&id);
        self.routes.remove(&id);
        self.usage.forget(id);
        self.stats_forget(id);
        self.drop_route_queries(id);
        self.updates.forget(id);
        for sync in self.sync.values_mut() {
            sync.forget(id);
        }
    }
}

pub(super) fn require_node(store: &Store, network: NetworkId, id: NodeId) -> Result<NodeRecord, Error> {
    store.node(id)?.filter(|node| node.network == network).ok_or(Error::NotFound(Entity::Node))
}

/// 一个名字现在能不能给节点用：没有别的节点在用，也不在冷却期。
pub(super) fn check_node_name(store: &Store, network: NetworkId, name: &str, now: Timestamp) -> Result<(), Error> {
    if store.nodes(network)?.iter().any(|node| node.name == name) {
        return Err(Error::NameTaken(name.to_owned()));
    }
    match store.cooldown_until(network, CooldownKind::Name, name, now)? {
        Some(until) => Err(Error::NameCoolingDown { name: name.to_owned(), until }),
        None => Ok(()),
    }
}

/// 一个虚拟 IP 现在能不能分给节点：在地址段里，没有别的节点在用，也不在冷却期。
pub(super) fn check_address(store: &Store, network: &NetworkRecord, address: Ipv4Addr, now: Timestamp) -> Result<(), Error> {
    if !address::is_assignable(network.cidr, address) {
        return Err(Error::AddressOutOfRange { address, cidr: network.cidr });
    }
    if store.nodes(network.id)?.iter().any(|node| node.virtual_ip == address) {
        return Err(Error::AddressTaken(address));
    }
    match store.cooldown_until(network.id, CooldownKind::Address, &address.to_string(), now)? {
        Some(until) => Err(Error::AddressCoolingDown { address, until }),
        None => Ok(()),
    }
}

/// 给新节点挑虚拟 IP：地址段里最小的空闲地址。在用的、冷却期里的、还没用掉的注册令牌预设的都不算空闲。
pub(super) fn allocate_address(store: &Store, network: &NetworkRecord, now: Timestamp) -> Result<Ipv4Addr, Error> {
    let in_use = store.nodes(network.id)?.into_iter().map(|node| node.virtual_ip);
    let reserved = store.tokens(network.id)?.into_iter().filter(|token| is_pending(token, now)).filter_map(|token| token.virtual_ip);
    let unavailable: BTreeSet<Ipv4Addr> = in_use.chain(reserved).chain(store.cooling_addresses(network.id, now)?).collect();
    address::lowest_free(network.cidr, &unavailable).ok_or(Error::RangeExhausted(network.cidr))
}

/// 继任的后半段：`successor` 已经拿到了 `old` 的名字和虚拟 IP，这里把指向 `old` 的配置和 `old` 所在的分组转给它，
/// 再删掉 `old`。
pub(super) fn inherit(store: &Store, network: NetworkId, old: &NodeRecord, successor: &NodeRecord) -> Result<(), Error> {
    store.repoint_node(old.id, successor.id)?;
    // 已让出名称与虚拟 IP 的原节点记录此时处于占位状态无法正常读取，需先删除它，后续才可遍历该网络中的节点。
    store.delete_node(old.id)?;
    unpin_everywhere(store, network, old.id)?;
    // 端口转发的目标是管理员的开关，和分组一样随身份交给继任者：继承来的转发照旧生效，外部配置不用改。
    if old.forward_target && !successor.forward_target {
        store.set_node_forward_target(successor.id, true)?;
    }
    if !old.auto_update && successor.auto_update {
        store.set_node_auto_update(successor.id, false)?;
    }
    Ok(())
}

/// 别的节点不再把 `relay` 固定为挂靠 relay。
fn unpin_everywhere(store: &Store, network: NetworkId, relay: NodeId) -> Result<(), Error> {
    for mut node in store.nodes(network)? {
        if node.pinned_relays.contains(&relay) {
            node.pinned_relays.retain(|pinned| *pinned != relay);
            store.update_node(&node)?;
        }
    }
    Ok(())
}

fn check_pinned_relays(store: &Store, node: &NodeRecord, pinned: &[NodeId]) -> Result<Vec<NodeId>, Error> {
    if pinned.len() > MAX_PINNED_RELAYS {
        return Err(Error::invalid_field("pinned_relays", "too_many", format!("最多固定 {MAX_PINNED_RELAYS} 个挂靠的中继")));
    }
    let mut checked = Vec::with_capacity(pinned.len());
    for &relay in pinned {
        let record = require_node(store, node.network, relay).in_field("pinned_relays")?;
        if relay == node.id || record.relay.is_none() {
            return Err(Error::invalid_field("pinned_relays", "not_relay", format!("节点 {} 不是可以挂靠的中继", record.name)));
        }
        if !checked.contains(&relay) {
            checked.push(relay);
        }
    }
    Ok(checked)
}

fn check_relay_settings(settings: RelaySettings) -> Result<RelaySettings, Error> {
    if settings.bandwidth_mbps == Some(0) {
        return Err(Error::invalid_field("bandwidth_mbps", "zero", "带宽上限不能为 0；若不限制请留空"));
    }
    Ok(settings)
}

fn check_exit_settings(mut settings: ExitRole) -> Result<ExitRole, Error> {
    if let Some(ports) = &mut settings.ports {
        if ports.contains(&0) {
            return Err(Error::invalid_field("ports", "zero", "端口不能为 0"));
        }
        ports.sort_unstable();
        ports.dedup();
    }
    if settings.upstream_socks5.is_some_and(|address| !is_connectable(&address)) {
        return Err(Error::invalid_field("upstream_socks5", "not_connectable", "上游代理地址不是有效的可连接地址"));
    }
    Ok(settings)
}

/// 一个地址能不能当连接的目的地：不是全零地址，端口不是 0。
pub(super) fn is_connectable(address: &SocketAddr) -> bool {
    !address.ip().is_unspecified() && address.port() != 0
}

/// 操作记录里的参数：节点（改之前的名字），和改了的项。没有改的项不在 `changes` 里；改名和改地址写出前后两个值。
fn update_params(before: &NodeRecord, after: &NodeRecord, groups: &[GroupRecord]) -> Value {
    let mut changes = Map::new();
    if before.name != after.name {
        changes.insert("name".to_owned(), json!({ "from": before.name, "to": after.name }));
    }
    if before.virtual_ip != after.virtual_ip {
        changes.insert("virtual_ip".to_owned(), json!({ "from": before.virtual_ip, "to": after.virtual_ip }));
    }
    if before.groups != after.groups {
        let entries = member_groups(after, groups).map(|group| json!({ "group": group.id, "group_name": group.name })).collect();
        changes.insert("groups".to_owned(), Value::Array(entries));
    }
    if before.dial_out_only != after.dial_out_only {
        changes.insert("dial_out_only".to_owned(), json!(after.dial_out_only));
    }
    if before.routing != after.routing {
        changes.insert("routing".to_owned(), json!(after.routing));
    }
    if before.reach != after.reach {
        changes.insert("reach".to_owned(), json!(after.reach));
    }
    if before.pinned_relays != after.pinned_relays {
        changes.insert("pinned_relays".to_owned(), json!(after.pinned_relays));
    }
    if before.profile != after.profile {
        changes.insert("profile".to_owned(), json!(after.profile));
    }
    if before.forward_target != after.forward_target {
        changes.insert("forward_target".to_owned(), json!(after.forward_target));
    }
    if before.auto_update != after.auto_update {
        changes.insert("auto_update".to_owned(), json!(after.auto_update));
    }
    json!({ "node": after.id, "node_name": before.name, "changes": changes })
}

/// 操作记录里的一句话：这次改了什么。
fn describe_update(before: &NodeRecord, after: &NodeRecord, groups: &[GroupRecord]) -> String {
    let mut changes = Vec::new();
    if before.name != after.name {
        changes.push(format!("名字 {} → {}", before.name, after.name));
    }
    if before.virtual_ip != after.virtual_ip {
        changes.push(format!("虚拟 IP {} → {}", before.virtual_ip, after.virtual_ip));
    }
    if before.groups != after.groups {
        changes.push(format!("分组 {}", listed(member_groups(after, groups).map(|group| &group.name))));
    }
    if before.dial_out_only != after.dial_out_only {
        changes.push(format!("只主动连接 {}", switch(after.dial_out_only)));
    }
    if before.routing != after.routing || before.reach != after.reach {
        changes.push("选路设置".to_owned());
    }
    if before.pinned_relays != after.pinned_relays {
        changes.push(format!("固定挂靠的中继 {}", listed(after.pinned_relays.iter().map(|relay| format!("#{relay}")))));
    }
    if before.profile != after.profile {
        changes.push(format!("性能档位 {}", after.profile.map_or("本机决定", |profile| profile.as_str())));
    }
    if before.auto_update != after.auto_update {
        changes.push(format!("自动更新 {}", switch(after.auto_update)));
    }
    if changes.is_empty() {
        format!("节点 {}：没有变化", after.name)
    } else {
        format!("节点 {}：{}", before.name, changes.join("，"))
    }
}

/// `node` 所在的分组，按 `groups` 的顺序（名字）。
fn member_groups<'a>(node: &'a NodeRecord, groups: &'a [GroupRecord]) -> impl Iterator<Item = &'a GroupRecord> {
    groups.iter().filter(|group| node.groups.contains(&group.id))
}
