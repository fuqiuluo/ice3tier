//! 访问规则的增删改。规则的两头是分组，按编号引用。

use i3t_model::admin::{CreateRule, Direction, GroupId, GroupRef, LogRef, NetworkId, RefKind, Rule, UpdateRule, action};
use serde_json::json;

use super::groups::{members_of, require_group};
use super::{Controller, naming};
use crate::error::{Entity, Error, InField};
use crate::store::Store;

impl Controller {
    /// 一个网络的全部规则，包括停用的。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn rules(&self, network: NetworkId) -> Result<Vec<Rule>, Error> {
        let inner = self.lock();
        inner.require_network(network)?;
        Ok(inner.store.rules(network)?)
    }

    /// # Errors
    ///
    /// 没有这个网络；名字的写法不对；`src` 或 `dst` 不是这个网络里已有的分组。
    pub fn create_rule(&self, network: NetworkId, request: &CreateRule) -> Result<Rule, Error> {
        let name = naming::title("规则", &request.name, false).in_field("name")?;
        let mut inner = self.lock();
        inner.require_network(network)?;
        let now = inner.clock.now();
        let (rule, seeds) = inner.store.atomically(|store| {
            let mut rule = Rule {
                id: 0,
                name,
                src: group_ref(store, network, request.src).in_field("src")?,
                dst: group_ref(store, network, request.dst).in_field("dst")?,
                direction: request.direction,
                enabled: request.enabled,
            };
            rule.id = store.insert_rule(network, &rule)?;
            store.log_refs(
                now,
                Some(network),
                action::RULE_CREATE,
                &describe(&rule),
                &[LogRef::new(RefKind::Rule, rule.id)],
                params(&rule),
            )?;
            let seeds = members_of(store, network, &[rule.src.id, rule.dst.id])?;
            Ok::<_, Error>((rule, seeds))
        })?;
        inner.refresh(network, seeds, None)?;
        self.wake_if_needed(&inner);
        Ok(rule)
    }

    /// 改一条规则。只改请求里写了的字段。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这条规则；名字的写法不对；`src` 或 `dst` 不是这个网络里已有的分组。
    pub fn update_rule(&self, network: NetworkId, id: u32, request: &UpdateRule) -> Result<Rule, Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let (after, seeds) = inner.store.atomically(|store| {
            let before = store.rule(network, id)?.ok_or(Error::NotFound(Entity::Rule))?;
            let mut rule = before.clone();
            if let Some(name) = &request.name {
                rule.name = naming::title("规则", name, false).in_field("name")?;
            }
            if let Some(src) = request.src {
                rule.src = group_ref(store, network, src).in_field("src")?;
            }
            if let Some(dst) = request.dst {
                rule.dst = group_ref(store, network, dst).in_field("dst")?;
            }
            rule.direction = request.direction.unwrap_or(rule.direction);
            rule.enabled = request.enabled.unwrap_or(rule.enabled);
            store.update_rule(&rule)?;
            store.log_refs(now, Some(network), action::RULE_UPDATE, &describe(&rule), &[LogRef::new(RefKind::Rule, id)], params(&rule))?;
            let seeds = members_of(store, network, &[before.src.id, before.dst.id, rule.src.id, rule.dst.id])?;
            Ok::<_, Error>((rule, seeds))
        })?;
        inner.refresh(network, seeds, None)?;
        self.wake_if_needed(&inner);
        Ok(after)
    }

    /// # Errors
    ///
    /// 这个网络里没有这条规则。
    pub fn delete_rule(&self, network: NetworkId, id: u32) -> Result<(), Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let seeds = inner.store.atomically(|store| {
            let rule = store.rule(network, id)?.ok_or(Error::NotFound(Entity::Rule))?;
            store.delete_rule(id)?;
            store.log_refs(now, Some(network), action::RULE_DELETE, &describe(&rule), &[LogRef::new(RefKind::Rule, id)], params(&rule))?;
            members_of(store, network, &[rule.src.id, rule.dst.id])
        })?;
        inner.refresh(network, seeds, None)?;
        self.wake_if_needed(&inner);
        Ok(())
    }
}

/// 操作记录里一条规则的参数：它改完（或者删掉之前）的样子。
fn params(rule: &Rule) -> serde_json::Value {
    json!({
        "rule": rule.id,
        "rule_name": rule.name,
        "src": rule.src.id,
        "src_name": rule.src.name,
        "dst": rule.dst.id,
        "dst_name": rule.dst.name,
        "direction": rule.direction,
        "enabled": rule.enabled,
    })
}

fn describe(rule: &Rule) -> String {
    let arrow = match rule.direction {
        Direction::Both => "<->",
        Direction::OneWay => "->",
    };
    let state = if rule.enabled { "启用" } else { "停用" };
    format!("规则 #{} {} {arrow} {}（{state}）", rule.id, rule.src.name, rule.dst.name)
}

/// 规则的一头：这个网络里已有的分组，带着它现在的名字。
fn group_ref(store: &Store, network: NetworkId, id: GroupId) -> Result<GroupRef, Error> {
    Ok(require_group(store, network, id)?.to_ref())
}
