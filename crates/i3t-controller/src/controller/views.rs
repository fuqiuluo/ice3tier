//! 给界面看的几个现算的视图：总览、访问关系图、访问检查。

use std::collections::BTreeSet;

use i3t_model::admin::{AccessCheck, AccessEdge, AccessGraph, NetworkId, NetworkWarning, NodeAccess, NodePair, NodeRef, Overview};
use i3t_model::control::Route;
use i3t_proto::NodeId;

use super::groups::group_view;
use super::{Controller, Inner, count};
use crate::access::AccessMap;
use crate::error::{Entity, Error};
use crate::netmap::NetworkView;
use crate::node_addresses;
use crate::relay_reach::ReachIndex;
use crate::store::{NodeRecord, is_pending};

impl Controller {
    /// 一个网络的总览。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn overview(&self, network: NetworkId) -> Result<Overview, Error> {
        let inner = self.lock();
        let view = inner.view(network)?;
        let now = inner.clock.now();
        let online_nodes: Vec<NodeRef> = view.nodes.values().filter(|node| inner.is_online(node.id)).map(NodeRecord::to_ref).collect();
        let live = inner.live.values().filter(|live| live.network == network);
        let reach = ReachIndex::new(view.nodes.values(), |id| inner.is_online(id));
        Ok(Overview {
            network,
            nodes: count(view.nodes.len()),
            online: count(online_nodes.len()),
            relays: count(view.nodes.values().filter(|node| node.relay.is_some()).count()),
            exits: count(view.nodes.values().filter(|node| node.exit.is_some()).count()),
            rules: count(view.rules.len()),
            proxies: count(view.proxies.len()),
            forwards: count(view.forwards.len()),
            pending_tokens: count(inner.store.tokens(network)?.iter().filter(|token| is_pending(token, now)).count()),
            unreachable_pairs: inner.unreachable_pairs(&view),
            online_nodes,
            flows: live.clone().map(|live| u64::from(live.flows)).sum(),
            tx_bytes: live.clone().map(|live| live.tx_bytes).fold(0, u64::saturating_add),
            rx_bytes: live.map(|live| live.rx_bytes).fold(0, u64::saturating_add),
            warnings: view
                .nodes
                .values()
                .flat_map(|node| {
                    let warnings = node_addresses::warnings(node, view.network.cidr);
                    let unreached = node.relay.as_ref().and_then(|_| reach.warning(node.id));
                    warnings.into_iter().chain(unreached).map(|warning| NetworkWarning { node: node.to_ref(), warning })
                })
                .collect(),
        })
    }

    /// 访问关系图的分组视图：全部分组（和分组列表一样）、全部规则。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn access_graph(&self, network: NetworkId) -> Result<AccessGraph, Error> {
        let inner = self.lock();
        let view = inner.view(network)?;
        let access = view.access();
        let is_connected = |id: NodeId| view.nodes.keys().any(|&other| access.allows(id, other) || access.allows(other, id));
        Ok(AccessGraph {
            groups: view.groups.iter().map(|group| group_view(&view, group)).collect(),
            unconnected: view.nodes.values().filter(|node| !is_connected(node.id)).map(NodeRecord::to_ref).collect(),
            unacknowledged: view.nodes.values().filter(|node| !inner.has_acknowledged(node.id)).map(NodeRecord::to_ref).collect(),
            rules: view.rules,
        })
    }

    /// 访问关系图的节点视图：`id` 能访问谁、谁能访问它、各是哪些规则允许的。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个节点，或者读存储失败。
    pub fn node_access(&self, network: NetworkId, id: NodeId) -> Result<NodeAccess, Error> {
        let inner = self.lock();
        let view = inner.view(network)?;
        let node = view.nodes.get(&id).ok_or(Error::NotFound(Entity::Node))?;
        let access = view.access();
        let edges = |outbound: bool| -> Vec<AccessEdge> {
            let others = view.nodes.values().filter(|other| other.id != id);
            others
                .filter_map(|other| {
                    let (from, to) = if outbound { (id, other.id) } else { (other.id, id) };
                    let rules: Vec<u32> = access.rules_allowing(from, to).map(|rule| rule.id).collect();
                    (!rules.is_empty()).then(|| AccessEdge { node: other.to_ref(), rules })
                })
                .collect()
        };
        Ok(NodeAccess { node: node.to_ref(), can_reach: edges(true), reachable_by: edges(false), acknowledged: inner.has_acknowledged(id) })
    }

    /// 访问检查：`from` 能不能访问 `to`，是哪些规则允许的。
    ///
    /// # Errors
    ///
    /// 两个节点不都在这个网络里，或者读存储失败。
    pub fn access_check(&self, network: NetworkId, from: NodeId, to: NodeId) -> Result<AccessCheck, Error> {
        let inner = self.lock();
        let view = inner.view(network)?;
        let node = |id: NodeId| view.nodes.get(&id).map(NodeRecord::to_ref).ok_or(Error::NotFound(Entity::Node));
        let access: AccessMap<'_> = view.access();
        let rules: Vec<_> = access.rules_allowing(from, to).cloned().collect();
        Ok(AccessCheck { from: node(from)?, to: node(to)?, allowed: !rules.is_empty(), rules })
    }
}

impl Inner {
    pub(super) fn view(&self, network: NetworkId) -> Result<NetworkView, Error> {
        NetworkView::load(&self.store, network)?.ok_or(Error::NotFound(Entity::Network))
    }

    /// 节点是不是已经确认了它该有的 netmap：确认到了当前的版本号，没有欠着的确认，也没有做不成、还在重试的重算。
    /// 后两样在新的版本号一时记不进存储时才会和第一样不一致：版本号没加，它确认过的"当前版本"其实是旧的内容。
    fn has_acknowledged(&self, id: NodeId) -> bool {
        self.sync.get(&id).is_none_or(|sync| sync.state.acked >= sync.state.version && !sync.is_waiting() && !sync.retrying)
    }

    /// 两端都在线、但至少一端上报"没有可用的路"的节点对。
    fn unreachable_pairs(&self, view: &NetworkView) -> Vec<NodePair> {
        let mut pairs = BTreeSet::new();
        let reporting = self.live.keys().filter_map(|&id| Some((id, self.current_routes(id)?)));
        for (id, reported) in reporting {
            let no_route = reported.entries.values().filter(|entry| entry.route == Route::None).map(|entry| entry.peer);
            pairs.extend(no_route.filter(|peer| self.is_online(*peer)).map(|peer| (id.min(peer), id.max(peer))));
        }
        let pair = |(a, b): (NodeId, NodeId)| Some(NodePair { a: view.nodes.get(&a)?.to_ref(), b: view.nodes.get(&b)?.to_ref() });
        pairs.into_iter().filter_map(pair).collect()
    }
}
