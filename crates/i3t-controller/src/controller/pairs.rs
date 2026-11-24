//! 节点对设置：连接常驻和拥塞控制。
//!
//! 网络里任意两个节点都是一对。没有存下设置的一对用默认值：连接不常驻，拥塞控制用节点的默认；存下的都是和默认不一样的设置。
//! ice3proxy 以前也是这里的一项，现在是代理的选项（见 `proxies`）；旧的客户端在请求里还写着它时忽略，不报错。

use std::collections::HashMap;

use i3t_model::admin::{LogRef, NetworkId, PairInput, PairSetting, PairView, action};
use i3t_model::netmap::Congestion;
use i3t_proto::NodeId;
use serde_json::{Value, json};

use super::nodes::require_node;
use super::{Controller, Seeds, switch};
use crate::error::{Entity, Error, InField};
use crate::store::{PairOptions, Store};

impl Controller {
    /// 一个网络里全部的节点对，按两个节点的编号排：存着设置的带着设置，其余的是默认值（`stored` 是 `false`）。
    /// 行数随节点数的平方长（100 个节点是 4950 行）。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn pairs(&self, network: NetworkId) -> Result<Vec<PairView>, Error> {
        let inner = self.lock();
        inner.require_network(network)?;
        // 按编号排着，所以下面每一对里 `a` 小于 `b`。
        let nodes: Vec<NodeId> = inner.store.nodes(network)?.into_iter().map(|node| node.id).collect();
        let stored: HashMap<(NodeId, NodeId), PairSetting> =
            inner.store.pairs(network)?.into_iter().map(|setting| ((setting.a, setting.b), setting)).collect();
        let pairs = nodes.iter().enumerate().flat_map(|(index, &a)| nodes.iter().skip(index + 1).map(move |&b| (a, b)));
        Ok(pairs.map(|(a, b)| view(stored.get(&(a, b)).copied(), a, b)).collect())
    }

    /// 一对节点的设置，有没有存下设置都有：没有的是默认值（`stored` 是 `false`）。两个节点的先后顺序无所谓。
    ///
    /// # Errors
    ///
    /// 两个节点不都在这个网络里，或者是同一个节点。
    pub fn pair(&self, network: NetworkId, a: NodeId, b: NodeId) -> Result<PairView, Error> {
        if a == b {
            return Err(Error::invalid_field("b", "same_node", "节点对必须由两个不同的节点组成"));
        }
        let inner = self.lock();
        require_node(&inner.store, network, a).in_field("a")?;
        require_node(&inner.store, network, b).in_field("b")?;
        Ok(view(inner.store.pair(a, b)?, a, b))
    }

    /// 改一对节点的设置：请求里写了的项改掉，没写的不变（这一对还没有设置时取默认值）。两个节点的先后顺序无所谓。
    /// 改完各项都是默认值的一对不留着设置，应答里 `stored` 是 `false`。
    ///
    /// # Errors
    ///
    /// 两个节点不都在这个网络里，或者是同一个节点。
    pub fn set_pair(&self, network: NetworkId, a: NodeId, b: NodeId, input: PairInput) -> Result<PairView, Error> {
        if a == b {
            return Err(Error::invalid_field("b", "same_node", "节点对必须由两个不同的节点组成"));
        }
        let mut inner = self.lock();
        let now = inner.clock.now();
        let view = inner.store.atomically(|store| {
            require_node(store, network, a).in_field("a")?;
            require_node(store, network, b).in_field("b")?;
            let before = store.pair(a, b)?.unwrap_or_else(|| PairSetting::unset(a, b));
            let keep_alive = input.keep_alive.unwrap_or(before.keep_alive);
            let congestion = input.congestion.unwrap_or(before.congestion);
            let setting = PairSetting { a: a.min(b), b: a.max(b), keep_alive, congestion };
            let stored = !setting.is_default();
            if stored {
                store.set_pair(a, b, PairOptions { keep_alive, congestion })?;
            } else {
                store.delete_pair(a, b)?;
            }
            let congestion_text = congestion.map_or("节点的默认", Congestion::as_str);
            let detail = format!("节点 #{a} 和 #{b}：连接常驻 {}，拥塞控制 {congestion_text}", switch(keep_alive));
            let params = json!({ "keep_alive": keep_alive, "congestion": congestion });
            store.log_refs(
                now,
                Some(network),
                action::PAIR_SET,
                &detail,
                &[LogRef::node(a), LogRef::node(b)],
                pair_params(store, a, b, params)?,
            )?;
            Ok::<_, Error>(PairView { setting, stored })
        })?;
        inner.refresh(network, Seeds::of([a, b]), None)?;
        self.wake_if_needed(&inner);
        Ok(view)
    }

    /// 去掉一对节点的设置，回到默认。
    ///
    /// # Errors
    ///
    /// 两个节点不都在这个网络里，或者这一对没有设置。
    pub fn delete_pair(&self, network: NetworkId, a: NodeId, b: NodeId) -> Result<(), Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        inner.store.atomically(|store| {
            require_node(store, network, a)?;
            require_node(store, network, b)?;
            if !store.delete_pair(a, b)? {
                return Err(Error::NotFound(Entity::PairSetting));
            }
            store.log_refs(
                now,
                Some(network),
                action::PAIR_DELETE,
                &format!("节点 #{a} 和 #{b}：清除节点对设置"),
                &[LogRef::node(a), LogRef::node(b)],
                pair_params(store, a, b, json!({}))?,
            )?;
            Ok(())
        })?;
        inner.refresh(network, Seeds::of([a, b]), None)?;
        self.wake_if_needed(&inner);
        Ok(())
    }
}

/// 节点对视图。各项均为默认值的记录（可能由更早版本写入）与无记录等效，均视为未自定义。
fn view(found: Option<PairSetting>, a: NodeId, b: NodeId) -> PairView {
    let setting = found.unwrap_or_else(|| PairSetting::unset(a, b));
    PairView { setting, stored: !setting.is_default() }
}

/// 操作记录里一对节点的参数：`a` 是编号小的那个，两个都带着当时的名字；`extra` 里的项加在后面。
fn pair_params(store: &Store, a: NodeId, b: NodeId, extra: Value) -> Result<Value, Error> {
    let (a, b) = (a.min(b), a.max(b));
    let name = |node| Ok::<_, Error>(store.node(node)?.map(|node| node.name));
    let mut params = json!({ "a": a, "a_name": name(a)?, "b": b, "b_name": name(b)? });
    if let (Value::Object(params), Value::Object(extra)) = (&mut params, extra) {
        params.extend(extra);
    }
    Ok(params)
}
