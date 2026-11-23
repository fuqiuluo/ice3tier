//! 重算 netmap 并发给节点。
//!
//! 入口是 [`Inner::refresh`]：给它一批"内容可能变了"的节点，它重算这些节点的 netmap，内容真的变了才加版本号、才下发。
//! 访问关系的变更按 [`crate::sync`] 里说的顺序生效，所以一次调用可能只走完第一步，剩下的等节点确认之后由
//! [`Inner::flush_due`] 接着做。

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use i3t_model::admin::NetworkId;
use i3t_model::control::ToNode;
use i3t_proto::NodeId;
use tokio::sync::mpsc::error::TrySendError;

use super::{Deferred, Inner};
use crate::access::AccessMap;
use crate::error::Error;
use crate::netmap::{NetworkView, Relation};
use crate::secret;
use crate::sync::NodeSync;

/// 延后的重算失败之后多久再试。
const RETRY_DELAY: Duration = Duration::from_secs(1);
/// 别的节点的上报引起的重算，一个节点有一阵没有这样的重算了时，等这么久就做：同一刻到的几份上报合成一次。
const REPORT_LEAD: Duration = Duration::from_millis(50);

/// 一次重算从哪些节点开始。和它们的访问关系有变化的对端会被自动带上。
pub(crate) enum Seeds {
    /// 网络里的全部节点。影响面说不清的少见操作（改网络设置、启用 relay、删节点）用它，多算的节点内容没变就不会下发。
    All,
    Nodes(BTreeSet<NodeId>),
}

impl Seeds {
    pub(crate) fn of(nodes: impl IntoIterator<Item = NodeId>) -> Self {
        Self::Nodes(nodes.into_iter().collect())
    }
}

impl Inner {
    /// 启动时建立下发状态。假定每个节点手上的 netmap 和规则一致，没有谁欠着确认：
    /// 上次运行期间没走完的顺序已经无从得知，节点重新连上来时会拿到当前的内容。
    pub(crate) fn load_sync(&mut self) -> Result<(), Error> {
        for network in self.store.networks()? {
            let Some(view) = NetworkView::load(&self.store, network.id)? else { continue };
            let access = view.access();
            for (id, node) in &view.nodes {
                self.sync.insert(*id, NodeSync::with_state(node.netmap, view.target_relations(&access, *id)));
            }
            self.load_no_udp(view.nodes.values(), Instant::now());
        }
        Ok(())
    }

    /// 哪些节点的 netmap 里有 `node`。它的名字、端点之类变了的时候，要重算的就是它们。
    pub(crate) fn holders_of(&self, node: NodeId) -> BTreeSet<NodeId> {
        self.sync.iter().filter(|(_, sync)| sync.knows(node)).map(|(id, _)| *id).collect()
    }

    /// 重算 `seeds` 和被它们牵连的节点的 netmap，内容变了的下发。
    /// `force` 指定的节点即使内容没变也发一份：它刚连上来，不知道它手上是哪一版。
    ///
    /// 出错时没算完的节点已经排上了重试，后台任务也叫醒了：调用方把错误交回去就行，不用自己再排。
    pub(crate) fn refresh(&mut self, network: NetworkId, seeds: Seeds, force: Option<NodeId>) -> Result<(), Error> {
        let view = match NetworkView::load(&self.store, network) {
            Ok(Some(view)) => view,
            Ok(None) => return Ok(()),
            Err(err) => {
                let nodes = match seeds {
                    Seeds::Nodes(nodes) => nodes,
                    // 网络读不出来，说不出"全部"是哪些：排上在线的。不在线的回来时拿到的本来就是那时的内容。
                    Seeds::All => self.live.iter().filter(|(_, live)| live.network == network).map(|(node, _)| *node).collect(),
                };
                self.retry_later(network, nodes);
                return Err(err.into());
            }
        };
        let access = view.access();
        let seeds: BTreeSet<NodeId> = match seeds {
            Seeds::All => view.nodes.keys().copied().collect(),
            Seeds::Nodes(nodes) => nodes.into_iter().filter(|node| view.nodes.contains_key(node)).collect(),
        };
        for node in view.nodes.keys() {
            self.sync.entry(*node).or_default();
        }
        let batch = self.reconcile(&view, &access, &seeds);
        for &node in &batch {
            if let Err(err) = self.publish(&view, &access, node, force == Some(node)) {
                // 这一个和排在它后面的都还没算完。`reconcile` 已经替它们登记了等待，
                // 不重试的话它们要到下一次碰巧有别的变化才会拿到新的 netmap。
                self.retry_later(network, batch.range(node..).copied());
                return Err(err);
            }
        }
        Ok(())
    }

    /// 这些节点的重算没做成：过一会儿再试，并且叫醒后台任务，让它到点来做。
    /// 一个节点都没有时（要重算整个网络，网络读不出来，又没有谁在线）没有排上谁，就不叫。
    fn retry_later(&mut self, network: NetworkId, nodes: impl IntoIterator<Item = NodeId>) {
        let mut nodes = nodes.into_iter().peekable();
        if nodes.peek().is_none() {
            return;
        }
        self.defer(network, nodes, RETRY_DELAY);
        self.wake.notify_one();
    }

    /// 先把访问关系变更的第一步登记到所有相关节点上，再去算任何一份 netmap。
    /// 这样算的时候不管先算哪个节点，看到的都是同一套"谁在等谁确认"。返回要重算的节点。
    fn reconcile(&mut self, view: &NetworkView, access: &AccessMap<'_>, seeds: &BTreeSet<NodeId>) -> BTreeSet<NodeId> {
        let now = Instant::now();
        let mut batch = seeds.clone();
        for &seed in seeds {
            let others = view.nodes.keys().copied().filter(|&other| other != seed);
            for other in others {
                self.reconcile_direction(access, seed, other, now, &mut batch);
                self.reconcile_direction(access, other, seed, now, &mut batch);
            }
        }
        batch
    }

    /// 看 `from` 访问 `to` 这一个方向：规则说的和两个节点的 netmap 里写的是否一致，不一致就推进一步。
    /// 推进时登记的等待从 `now` 开始算超时：登记完马上就会下发。
    fn reconcile_direction(&mut self, access: &AccessMap<'_>, from: NodeId, to: NodeId, now: Instant, batch: &mut BTreeSet<NodeId>) {
        let allowed = access.allows(from, to);
        let dials = self.sync.get(&from).is_some_and(|sync| sync.dials(to));
        let accepts = self.sync.get(&to).is_some_and(|sync| sync.accepts(from));
        match (allowed, accepts, dials) {
            (true, true, true) | (false, false, false) => {}
            // 新的授权：目的端先认。目的端不在线时没有可等的，发起端这一轮就可以用。
            (true, false, _) => {
                let online = self.is_online(to);
                self.sync.entry(to).or_default().begin_accepting(from, online, now);
                batch.insert(to);
                if !online {
                    batch.insert(from);
                }
            }
            // 目的端已经认了：它确认过，发起端才可以用。
            (true, true, false) => {
                if self.sync.get(&to).is_some_and(|sync| sync.has_confirmed_accepting(from)) {
                    batch.insert(from);
                }
            }
            // 撤销：发起端先停。发起端不在线时没有可等的，目的端这一轮就不认它。
            (false, _, true) => {
                let online = self.is_online(from);
                self.sync.entry(from).or_default().begin_undialing(to, online, now);
                batch.insert(from);
                if !online {
                    batch.insert(to);
                }
            }
            // 发起端已经停了：它确认过，目的端才不认它。
            (false, true, false) => {
                if !self.sync.get(&from).is_some_and(|sync| sync.may_still_dial(to)) {
                    batch.insert(to);
                }
            }
        }
    }

    /// `id` 的 netmap 里现在该写的访问关系：规则算出来的，减去还在等对端确认的。
    fn effective_relations(&self, view: &NetworkView, access: &AccessMap<'_>, id: NodeId) -> BTreeMap<NodeId, Relation> {
        let others = view.nodes.keys().copied().filter(|&other| other != id);
        others
            .filter_map(|peer| {
                let theirs = self.sync.get(&peer)?;
                let relation = Relation {
                    inbound: access.allows(peer, id) || theirs.may_still_dial(id),
                    outbound: access.allows(id, peer) && theirs.has_confirmed_accepting(id),
                };
                (!relation.is_empty()).then_some((peer, relation))
            })
            .collect()
    }

    fn publish(&mut self, view: &NetworkView, access: &AccessMap<'_>, id: NodeId, force: bool) -> Result<(), Error> {
        let relations = self.effective_relations(view, access, id);
        let Some(mut netmap) = view.compile(access, id, &relations, &*self) else { return Ok(()) };
        // 摘要是对不带版本号的内容算的，所以"内容没变"和"版本号不加"是一回事。
        let digest = secret::sha256(&serde_json::to_vec(&netmap)?);

        let sync = self.sync.entry(id).or_default();
        let changed = sync.state.digest != Some(digest);
        let version = sync.state.version + u64::from(changed);
        if changed {
            // 新的版本号先记进存储，记下了才算数。记不下来时这里什么都没动，调用方过一会儿重试，算出来的还是"内容变了"。
            // 反过来先改这里的话，重试时摘要已经对得上，这一版就既记不下来也发不出去。
            self.store.set_node_netmap(id, version, &digest)?;
            sync.state.version = version;
            sync.state.digest = Some(digest);
        }
        let released = sync.settle(relations);
        self.defer(view.network.id, released, Duration::ZERO);

        if (changed || force) && self.is_online(id) {
            netmap.version = version;
            tracing::debug!(node = %id, version, peers = netmap.peers.len(), relays = netmap.relays.len(), "下发 netmap");
            if self.send(id, ToNode::Snapshot(Box::new(netmap))) {
                self.counters.snapshots_sent += 1;
                // 发出去了就是发出去了，先记在这里：节点的确认要拿它来对。存储里的记不下来只是旧一些，下一次发的时候补上。
                let sync = self.sync.entry(id).or_default();
                sync.state.sent = version;
                self.store.set_node_sent(id, version)?;
            }
        }
        Ok(())
    }

    /// 把一条消息放进节点的发送队列。节点不在线时返回 `false`。
    ///
    /// 队列是有界的：满了说明这个节点不读，继续攒只会占内存，所以直接断开它。它重连之后会拿到最新的 netmap。
    pub(crate) fn send(&mut self, node: NodeId, message: ToNode) -> bool {
        let Some(live) = self.live.get(&node) else { return false };
        let reason = match live.outbox.try_send(message) {
            Ok(()) => return true,
            Err(TrySendError::Full(_)) => "它的发送队列满了，说明它不读",
            Err(TrySendError::Closed(_)) => "它的连接已经结束",
        };
        tracing::warn!(%node, reason, "断开节点");
        self.drop_session(node);
        false
    }

    /// 节点不再在线：去掉它的连接，记下最近在线的时间，并且不再等它确认。
    pub(crate) fn drop_session(&mut self, node: NodeId) {
        let Some(live) = self.live.remove(&node) else { return };
        // 注册时那一条连接不算"最近在线"。
        if !live.enrolling
            && let Err(err) = self.store.set_node_last_seen(node, self.clock.now())
        {
            // 只影响界面上的"最近在线"，不值得让调用方的操作失败。
            tracing::warn!(%node, "记录节点最近在线的时间失败：{err}");
        }
        self.drop_route_queries(node);
        self.stop_waiting_for(live.network, node);
        self.tests_node_gone(node);
    }

    /// 不再等 `node` 确认：等它确认才能继续的对端现在就可以继续。
    pub(crate) fn stop_waiting_for(&mut self, network: NetworkId, node: NodeId) {
        let released = self.sync.get_mut(&node).map(NodeSync::confirm_all).unwrap_or_default();
        self.defer(network, released, self.timing.ack_coalesce);
    }

    /// 别的节点的上报（端点、挂靠、连得上哪些 relay）引起的重算：每个节点两次这样的重算至少隔 `report_coalesce`，
    /// 可是离上一次已经够久时，这一次只等 [`REPORT_LEAD`]。
    ///
    /// 这样两个节点刚上线时，对端的挂靠信息不用等满一个 `report_coalesce` 才到（经 relay 的第一个请求原来要多等将近一秒）；
    /// 许多节点同时挂上来时，每个节点照旧最多每 `report_coalesce` 收到一份因此重算的 netmap，不会一阵阵地发。
    /// 已经排着、并且不比这更晚的重算照旧，这次的变化跟着它一起算（重算读的是那时存储里的东西）。
    pub(crate) fn defer_report(&mut self, network: NetworkId, nodes: impl IntoIterator<Item = NodeId>) {
        let now = Instant::now();
        let window = self.timing.report_coalesce;
        for node in nodes {
            let sync = self.sync.entry(node).or_default();
            let due = (now + REPORT_LEAD).max(sync.report_due.map_or(now, |last| last + window));
            match self.dirty.get_mut(&node) {
                Some(pending) if pending.due <= due => {}
                Some(pending) => {
                    pending.due = due;
                    sync.report_due = Some(due);
                }
                None => {
                    self.dirty.insert(node, Deferred { network, due });
                    sync.report_due = Some(due);
                }
            }
        }
    }

    /// 过 `delay` 之后重算这些节点。已经排着的取较早的时间，所以不断有新的变化也推迟不了它。
    pub(crate) fn defer(&mut self, network: NetworkId, nodes: impl IntoIterator<Item = NodeId>, delay: Duration) {
        let due = Instant::now() + delay;
        for node in nodes {
            self.dirty.entry(node).and_modify(|deferred| deferred.due = deferred.due.min(due)).or_insert(Deferred { network, due });
        }
    }

    /// 重算到期的节点。返回剩下的里面最早的到期时间。
    pub(crate) fn flush_due(&mut self, now: Instant) -> Result<Option<Instant>, Error> {
        let mut due: BTreeMap<NetworkId, BTreeSet<NodeId>> = BTreeMap::new();
        self.dirty.retain(|node, deferred| {
            let is_due = deferred.due <= now;
            if is_due {
                due.entry(deferred.network).or_default().insert(*node);
            }
            !is_due
        });
        let mut first_error = None;
        for (network, nodes) in due {
            // 一个网络失败不耽误别的网络；没算完的 `refresh` 自己放回了队列，过一会儿再试。
            if let Err(err) = self.refresh(network, Seeds::Nodes(nodes), None) {
                first_error.get_or_insert(err);
            }
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(self.dirty.values().map(|deferred| deferred.due).min()),
        }
    }

    /// 在线的节点太久不确认时不再等它，免得它卡住别的节点。
    ///
    /// 每一项等待从登记的那一刻算起，满了 `ack_timeout` 就不再等。这期间节点收到多少份 netmap、换了多少次连接都不算：
    /// 不然一个不回话的节点只要不停地重连，或者不停地让自己的 netmap 变一变，就能让一次撤销一直生效不了。
    pub(crate) fn give_up_on_slow_acks(&mut self, now: Instant) {
        let timeout = self.timing.ack_timeout;
        let mut given_up = Vec::new();
        for (node, live) in &self.live {
            let Some(sync) = self.sync.get_mut(node) else { continue };
            let peers = sync.give_up_waiting(now, timeout);
            if !peers.is_empty() {
                tracing::warn!(%node, ?timeout, ?peers, "节点迟迟不确认新的 netmap，不再等它");
                given_up.push((live.network, peers));
            }
        }
        for (network, peers) in given_up {
            self.defer(network, peers, self.timing.ack_coalesce);
        }
    }
}
