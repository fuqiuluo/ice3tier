//! 分组：增删改查和成员。
//!
//! 分组只在 controller 里：节点拿到的是按规则算好的访问关系，看不到分组。所以改名不下发任何东西；
//! 成员变了、用到它的规则被删了，才要重算受影响的节点。

use std::collections::BTreeSet;

use i3t_model::admin::{
    CreateGroup, DeletedGroup, Group, GroupId, GroupMembers, LogRef, NetworkId, NodeRef, RefKind, Rule, UpdateGroup, action,
};
use i3t_proto::NodeId;
use serde_json::{Value, json};

use super::nodes::require_node;
use super::{Controller, Inner, Seeds, count, listed, naming};
use crate::error::{Error, InField};
use crate::netmap::NetworkView;
use crate::store::{BUILTIN_GROUP, GroupRecord, NodeRecord, Store};

impl Controller {
    /// 一个网络的全部分组：`All` 在最前面，其余按名字排。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn groups(&self, network: NetworkId) -> Result<Vec<Group>, Error> {
        let inner = self.lock();
        let view = inner.view(network)?;
        Ok(view.groups.iter().map(|group| group_view(&view, group)).collect())
    }

    /// 一个分组，带着它的成员和用到它的规则。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个分组，或者读存储失败。
    pub fn group(&self, network: NetworkId, id: GroupId) -> Result<Group, Error> {
        self.lock().group_view(network, id)
    }

    /// 新建一个分组。名字在这个网络里不分大小写唯一。
    ///
    /// # Errors
    ///
    /// 没有这个网络；名字的写法不对，或者被占用了。
    pub fn create_group(&self, network: NetworkId, request: &CreateGroup) -> Result<Group, Error> {
        let name = naming::group_name(&request.name).in_field("name")?;
        let mut inner = self.lock();
        inner.require_network(network)?;
        let now = inner.clock.now();
        let id = inner.store.atomically(|store| {
            check_group_name(store, network, &name, None)?;
            let id = store.insert_group(network, &name)?;
            let params = json!({ "group": id, "group_name": name });
            store.log_refs(now, Some(network), action::GROUP_CREATE, &format!("新建分组 {name}"), &[group_ref(id)], params)?;
            Ok::<_, Error>(id)
        })?;
        tracing::info!(%network, group = %id, %name, "新建分组");
        inner.group_view(network, id)
    }

    /// 改一个分组的名字。规则记的是编号，所以改名不改变谁能访问谁，不用重算任何节点。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个分组；它是内置的 `All`；名字的写法不对，或者被占用了。
    pub fn update_group(&self, network: NetworkId, id: GroupId, request: &UpdateGroup) -> Result<Group, Error> {
        let name = request.name.as_deref().map(naming::group_name).transpose().in_field("name")?;
        let mut inner = self.lock();
        let now = inner.clock.now();
        inner.store.atomically(|store| {
            let group = require_group(store, network, id)?;
            let Some(name) = name else { return Ok(()) };
            refuse_builtin(&group)?;
            if name == group.name {
                return Ok(());
            }
            check_group_name(store, network, &name, Some(id))?;
            store.rename_group(id, &name)?;
            let params = json!({ "group": id, "from": group.name, "to": name });
            let detail = format!("分组 {} 改名为 {name}", group.name);
            store.log_refs(now, Some(network), action::GROUP_RENAME, &detail, &[group_ref(id)], params)?;
            tracing::info!(%network, group = %id, from = %group.name, to = %name, "分组改名");
            Ok::<_, Error>(())
        })?;
        inner.group_view(network, id)
    }

    /// 删掉一个分组：从成员节点上、从预设了它的注册令牌上去掉它，删掉用到它的规则。都在一个事务里。
    ///
    /// 只经由这些规则才被允许的访问随即撤销，和删掉一条规则一样。没有规则用到它时谁能访问谁不变，不用重算。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个分组，或者它是内置的 `All`。
    pub fn delete_group(&self, network: NetworkId, id: GroupId) -> Result<DeletedGroup, Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let deleted = inner.store.atomically(|store| {
            let group = require_group(store, network, id)?;
            refuse_builtin(&group)?;
            let nodes: Vec<NodeRef> =
                store.nodes(network)?.iter().filter(|node| node.groups.contains(&id)).map(NodeRecord::to_ref).collect();
            let rules: Vec<Rule> = store.rules(network)?.into_iter().filter(|rule| rule.src.id == id || rule.dst.id == id).collect();
            let tokens = store.pending_tokens_with_group(id)?;
            for rule in &rules {
                store.delete_rule(rule.id)?;
            }
            store.delete_group(id)?;
            let refs: Vec<LogRef> = std::iter::once(group_ref(id))
                .chain(nodes.iter().map(|node| LogRef::node(node.id)))
                .chain(rules.iter().map(|rule| LogRef::new(RefKind::Rule, rule.id)))
                .chain(tokens.iter().map(|&token| LogRef::new(RefKind::Token, token)))
                .collect();
            let (node_count, rule_count, token_count) = (count(nodes.len()), count(rules.len()), count(tokens.len()));
            let params = json!({ "group": id, "group_name": group.name, "nodes": node_count, "rules": rule_count, "tokens": token_count });
            let detail = format!(
                "删除分组 {}：从 {node_count} 个节点上去掉，删掉 {rule_count} 条规则，从 {token_count} 个注册令牌上去掉",
                group.name
            );
            store.log_refs(now, Some(network), action::GROUP_DELETE, &detail, &refs, params)?;
            Ok::<_, Error>(DeletedGroup { id, name: group.name, nodes, rules, tokens })
        })?;
        tracing::info!(%network, group = %id, name = %deleted.name, nodes = deleted.nodes.len(), rules = deleted.rules.len(), "删除分组");
        if !deleted.rules.is_empty() {
            inner.refresh(network, Seeds::All, None)?;
            self.wake_if_needed(&inner);
        }
        Ok(deleted)
    }

    /// 批量增减一个分组的成员。要么全部做到，要么一个都不改。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个分组，或者它是内置的 `All`；`add`、`remove` 里有不在这个网络里的节点
    /// （`field` 是 `add[序号]`、`remove[序号]`）；同一个节点既要加入又要移出。
    pub fn change_members(&self, network: NetworkId, id: GroupId, request: &GroupMembers) -> Result<Group, Error> {
        self.members(network, id, |store| {
            let nodes = |field: &'static str, ids: &[NodeId]| -> Result<Vec<NodeRecord>, Error> {
                let lookup = ids.iter().enumerate();
                lookup.map(|(index, &node)| require_node(store, network, node).map_err(|error| error.in_item(field, index))).collect()
            };
            let (add, remove) = (nodes("add", &request.add)?, nodes("remove", &request.remove)?);
            if let Some(both) = remove.iter().find(|node| request.add.contains(&node.id)) {
                return Err(Error::invalid_field("remove", "duplicate", format!("节点 {} 不能既加入又移出", both.name)));
            }
            Ok((add, remove))
        })
    }

    /// 把一个节点加入分组。已经在里面时什么也不做。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个分组或者这个节点；分组是内置的 `All`。
    pub fn add_member(&self, network: NetworkId, id: GroupId, node: NodeId) -> Result<Group, Error> {
        self.members(network, id, |store| Ok((vec![require_node(store, network, node)?], Vec::new())))
    }

    /// 把一个节点移出分组。本来就不在里面时什么也不做。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个分组或者这个节点；分组是内置的 `All`。
    pub fn remove_member(&self, network: NetworkId, id: GroupId, node: NodeId) -> Result<Group, Error> {
        self.members(network, id, |store| Ok((Vec::new(), vec![require_node(store, network, node)?])))
    }

    /// 增减成员的共同部分。`pick` 在事务里查清楚要加入、要移出的节点。成员真的变了的节点要重算。
    fn members(
        &self,
        network: NetworkId,
        id: GroupId,
        pick: impl FnOnce(&Store) -> Result<(Vec<NodeRecord>, Vec<NodeRecord>), Error>,
    ) -> Result<Group, Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let changed = inner.store.atomically(|store| {
            let group = require_group(store, network, id)?;
            refuse_builtin(&group)?;
            let (add, remove) = pick(store)?;
            // 本来就在（或者本来就不在）的不算：只记、只重算真的变了的。
            let mut added = Vec::new();
            for node in &add {
                if store.add_member(id, node.id)? {
                    added.push(node);
                }
            }
            let mut removed = Vec::new();
            for node in &remove {
                if store.remove_member(id, node.id)? {
                    removed.push(node);
                }
            }
            if added.is_empty() && removed.is_empty() {
                return Ok(BTreeSet::new());
            }
            let entries =
                |nodes: &[&NodeRecord]| -> Value { nodes.iter().map(|node| json!({ "node": node.id, "node_name": node.name })).collect() };
            let params = json!({ "group": id, "group_name": group.name, "added": entries(&added), "removed": entries(&removed) });
            let mut clauses = Vec::new();
            if !added.is_empty() {
                clauses.push(format!("加入 {}", listed(added.iter().map(|node| &node.name))));
            }
            if !removed.is_empty() {
                clauses.push(format!("移出 {}", listed(removed.iter().map(|node| &node.name))));
            }
            let detail = format!("分组 {}：{}", group.name, clauses.join("，"));
            let changed: BTreeSet<NodeId> = added.iter().chain(&removed).map(|node| node.id).collect();
            let refs: Vec<LogRef> = std::iter::once(group_ref(id)).chain(changed.iter().map(|&node| LogRef::node(node))).collect();
            store.log_refs(now, Some(network), action::GROUP_MEMBERS, &detail, &refs, params)?;
            Ok::<_, Error>(changed)
        })?;
        if !changed.is_empty() {
            tracing::info!(%network, group = %id, nodes = ?changed, "分组的成员变了");
            inner.refresh(network, Seeds::of(changed), None)?;
            self.wake_if_needed(&inner);
        }
        inner.group_view(network, id)
    }
}

impl Inner {
    fn group_view(&self, network: NetworkId, id: GroupId) -> Result<Group, Error> {
        let view = self.view(network)?;
        let group = view.groups.iter().find(|group| group.id == id).ok_or(Error::NoSuchGroup(id))?;
        Ok(group_view(&view, group))
    }
}

/// 在这些分组里的节点：一条规则变了，要重算的就是它两头的节点。有 `All` 时是全网。
///
/// 在改规则的事务里读：提交之后再读，读不出来时规则已经改了，却没人去重算。
pub(super) fn members_of(store: &Store, network: NetworkId, groups: &[GroupId]) -> Result<Seeds, Error> {
    if store.builtin_group(network)?.is_some_and(|all| groups.contains(&all)) {
        return Ok(Seeds::All);
    }
    let members = store.nodes(network)?.into_iter().filter(|node| groups.iter().any(|group| node.groups.contains(group)));
    Ok(Seeds::of(members.map(|node| node.id)))
}

/// 管理 API 里的一个分组：成员（`All` 是全部节点）和用到它的规则。
pub(super) fn group_view(view: &NetworkView, group: &GroupRecord) -> Group {
    let members = view.nodes.values().filter(|node| group.builtin || node.groups.contains(&group.id));
    Group {
        id: group.id,
        name: group.name.clone(),
        builtin: group.builtin,
        nodes: members.map(NodeRecord::to_ref).collect(),
        rules: view.rules.iter().filter(|rule| rule.src.id == group.id || rule.dst.id == group.id).cloned().collect(),
    }
}

/// 请求里一个分组编号的列表（节点的、注册令牌的 `groups`）：每个都要是这个网络里已有的分组。
/// 返回去掉 `All`（每个节点本来就在）和重复之后的集合。不存在的那个报在 `field[序号]` 上。
pub(super) fn resolve_groups(store: &Store, network: NetworkId, ids: &[GroupId], field: &'static str) -> Result<BTreeSet<GroupId>, Error> {
    let mut groups = BTreeSet::new();
    for (index, &id) in ids.iter().enumerate() {
        let group = require_group(store, network, id).map_err(|error| error.in_item(field, index))?;
        if !group.builtin {
            groups.insert(id);
        }
    }
    Ok(groups)
}

/// 找一个分组，它必须属于 `network`：别的网络的分组在这里等于不存在。
pub(super) fn require_group(store: &Store, network: NetworkId, id: GroupId) -> Result<GroupRecord, Error> {
    store.group(network, id)?.ok_or(Error::NoSuchGroup(id))
}

fn refuse_builtin(group: &GroupRecord) -> Result<(), Error> {
    if group.builtin {
        return Err(Error::invalid_field("group", "builtin", format!("内置分组 {BUILTIN_GROUP} 不能改名、删除，也不能增减成员")));
    }
    Ok(())
}

/// 名字能不能给分组 `except` 以外的分组用：不分大小写没有别的分组叫这个名字。
fn check_group_name(store: &Store, network: NetworkId, name: &str, except: Option<GroupId>) -> Result<(), Error> {
    match store.group_named(network, name)? {
        Some(other) if Some(other.id) != except => Err(Error::GroupNameTaken(name.to_owned()).in_field("name")),
        _ => Ok(()),
    }
}

fn group_ref(id: GroupId) -> LogRef {
    LogRef::new(RefKind::Group, id.0)
}
