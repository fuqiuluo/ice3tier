//! 重算 netmap 并发给节点。
//!
//! 入口是 [`Inner::refresh`]：给它一批"内容可能变了"的节点，它重算这些节点的 netmap，内容真的变了才加版本号、才下发。
//! 访问关系的变更按 [`crate::sync`] 定义的顺序生效，因此单次调用可能仅完成第一步，后续步骤待节点确认后由
//! [`Inner::flush_due`] 继续推进。

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use i3t_model::admin::NetworkId;
use i3t_model::control::ToNode;
use i3t_proto::NodeId;
use tokio::sync::mpsc;

use super::switchboard::Undelivered;
use super::{Admitted, Deferred, Failures, Inner, Live, admin_token_hash};
use crate::access::AccessMap;
use crate::error::Error;
use crate::netmap::{NetworkView, Relation};
use crate::secret;
use crate::sync::NodeSync;

/// 延迟重算失败后的重试间隔。
const RETRY_DELAY: Duration = Duration::from_secs(1);
/// 由其他节点上报触发的重算：当目标节点近期未触发此类重算时，等待该时长后执行，以便合并同一时刻到达的多份上报。
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

/// 一次重算未能全部完成，失败节点已加入重试队列。
pub(crate) struct Unfinished {
    /// 首个错误；若整个数据库不可写，则记录该全局错误。
    pub(crate) error: Error,
    /// 已完成的节点：netmap 已重算、持久化并完成必要下发。
    pub(crate) done: BTreeSet<NodeId>,
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
    /// 单个节点失败不阻塞其余节点：失败节点已排入重试队列并唤醒后台任务，
    /// 调用方直接返回错误即可，无需重复安排重试。
    pub(crate) fn refresh(&mut self, network: NetworkId, seeds: Seeds, force: Option<NodeId>) -> Result<(), Error> {
        self.refresh_reporting(network, seeds, force).map_err(|unfinished| unfinished.error)
    }

    /// 与 [`Self::refresh`] 相同，但在部分失败时会同时返回已成功完成的节点集合。
    pub(crate) fn refresh_reporting(&mut self, network: NetworkId, seeds: Seeds, force: Option<NodeId>) -> Result<(), Unfinished> {
        let view = match NetworkView::load(&self.store, network) {
            Ok(Some(view)) => view,
            Ok(None) => return Ok(()),
            Err(err) => {
                let nodes = match seeds {
                    Seeds::Nodes(nodes) => nodes,
                    // 无法读取网络信息时无法确定全量节点列表：仅将当前在线节点排入重试，离线节点重新上线时会自动获取最新内容。
                    Seeds::All => self.live.iter().filter(|(_, live)| live.network == network).map(|(node, _)| *node).collect(),
                };
                if err.is_database_wide() {
                    self.back_off();
                }
                self.retry_later(network, nodes);
                return Err(Unfinished { error: err.into(), done: BTreeSet::new() });
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
        let mut done = BTreeSet::new();
        let mut failed = BTreeSet::new();
        let mut error = None;
        for &node in &batch {
            match self.publish(&view, &access, node, force == Some(node)) {
                Ok(()) => {
                    done.insert(node);
                }
                // 整个数据库不可写：其余节点也会遭遇相同错误，不再继续尝试。
                Err(err) if err.is_database_wide() => {
                    failed.extend(batch.range(node..).copied());
                    error = Some(err);
                    self.back_off();
                    break;
                }
                // 仅当前节点失败，不阻塞同批次其他节点：各节点基于同一套确认等待视图独立计算。
                // 否则单个持续持久化失败的节点会阻塞其后的节点（例如等待其停用后才能撤销许可的目的端）。
                //
                // 当该节点所在行（或整张表）被其他连接持锁并触发锁超时时同样如此。等待锁期间持有 controller 锁，
                // 但等待时长由存储层控制：触发一次锁超时后，在随后的保护窗口内不再等锁（见 `Store` 文档），被锁项立即失败并
                // 放回队列，未受影响项正常写入。因此此处不让整个后台重算退避，否则前台每秒多次命中被锁节点时，
                // 其他网络已到期的重算将长期得不到执行。
                Err(err) => {
                    failed.insert(node);
                    error.get_or_insert(err);
                }
            }
        }
        // `reconcile` 已为失败节点登记了确认等待；若不安排重试，这些节点要等到后续恰好出现其他变更时才能收到新版 netmap。
        self.retry_later(network, failed);
        error.map_or(Ok(()), |error| Err(Unfinished { error, done }))
    }

    /// 这些节点的重算未能完成：安排延迟重试并唤醒后台任务。在重试成功前标记为「重试中」。
    /// 若节点集合为空（全部完成，或全网重算时网络读取失败且无在线节点），则不安排也不唤醒。
    fn retry_later(&mut self, network: NetworkId, nodes: impl IntoIterator<Item = NodeId>) {
        let nodes: BTreeSet<NodeId> = nodes.into_iter().collect();
        if nodes.is_empty() {
            return;
        }
        for node in &nodes {
            if let Some(sync) = self.sync.get_mut(node) {
                sync.retrying = true;
            }
        }
        self.defer(network, nodes, RETRY_DELAY);
        self.wake.notify_one();
    }

    /// 整个数据库刚出现读写失败：令后台重算短暂退避，见 [`Inner::flush_after`]。
    /// 仅单行或单表被锁（触发锁超时）不进入退避：该场景由存储层自行限流，见 [`Self::refresh_reporting`]。
    pub(crate) fn back_off(&mut self) {
        self.flush_after = Some(Instant::now() + RETRY_DELAY);
    }

    /// 截至 `now` 仍处于退避期（见 [`Self::back_off`]）。`now` 取自本次调用开始时，调用期间开始的退避同样计入。
    pub(crate) fn backing_off(&self, now: Instant) -> bool {
        self.flush_after.is_some_and(|after| now < after)
    }

    /// 提交的回答没有回来的那些事务（[`StoreError::CommitUnknown`](crate::store::StoreError::CommitUnknown)）：
    /// 问数据库它们后来算了数没有。算了数的话，数据库里已经是改过的样子，而提交之后才做的那些事当时没有做
    /// （调用方带着错误返回了）：照数据库现在的样子补上。不补的话，一条删掉了的规则、一个删掉了的节点会一直留在
    /// 别的节点的 netmap 里，管理员再删一次只会得到"没有这个东西"。
    ///
    /// 返回过多久再来问：数据库那边还没做完的时候。
    pub(crate) fn settle_commits(&mut self, now: Instant) -> Result<Option<Instant>, Error> {
        // 整个数据库刚发生读写失败，尚处于退避期：由 `flush_due` 返回下次重试时刻。
        if self.flush_after.is_some_and(|after| now < after) {
            return Ok(None);
        }
        let settled = self.settle_commits_now(now);
        if settled.as_ref().is_err_and(Error::is_database_wide) {
            self.back_off();
        }
        settled
    }

    fn settle_commits_now(&mut self, now: Instant) -> Result<Option<Instant>, Error> {
        let settled = self.store.settle_commits()?;
        self.out_of_step |= settled.committed;
        if self.out_of_step {
            tracing::warn!("检测到先前结果未明的事务已提交，将按当前数据库状态重算各网络");
            self.catch_up_with_store()?;
            self.out_of_step = false;
        }
        Ok(settled.pending.then(|| now + RETRY_DELAY))
    }

    /// 照数据库现在的样子把内存里跟着它的状态补齐：数据库里已经没有的节点断开、忘掉，管理令牌按库里记的来，
    /// 每个网络的 netmap 重算一遍（内容没变的不会下发）。做到一半出错的话下次从头再做，重做没有坏处。
    fn catch_up_with_store(&mut self) -> Result<(), Error> {
        let networks = self.store.networks()?;
        let mut known = BTreeSet::new();
        for network in &networks {
            known.extend(self.store.nodes(network.id)?.into_iter().map(|node| node.id));
        }
        let gone: BTreeSet<NodeId> = self.sync.keys().chain(self.live.keys()).filter(|node| !known.contains(node)).copied().collect();
        for node in gone {
            tracing::info!(%node, "节点已不存在于数据库中，正在吊销");
            let revoked = self.switchboard().revoke(node);
            self.delivered(node, revoked);
            self.forget_node(node);
        }
        *self.admin_token.lock().expect("admin token mutex poisoned") = admin_token_hash(&self.store)?;
        for network in networks {
            match self.refresh(network.id, Seeds::All, None) {
                Ok(()) => {}
                // 整个数据库再次不可读写：其余网络也会遭遇相同错误，留待下次从头重试。
                Err(error) if error.is_database_wide() => return Err(error),
                // 未完成的节点已由 `refresh` 加入重试队列，无需整体重做。
                Err(error) => tracing::warn!(network = %network.id, %error, "按数据库状态重算网络未全部完成，失败节点将稍后重试"),
            }
        }
        self.roll_out()
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
            // 撤销：发起端先停用出向访问。若发起端不在线则无需等待，目的端本轮即可移除许可。
            (false, _, true) => {
                let online = self.is_online(from);
                self.sync.entry(from).or_default().begin_undialing(to, online, now);
                batch.insert(from);
                if !online {
                    batch.insert(to);
                }
            }
            // 发起端已停用出向访问：待其确认后，目的端才移除入向许可。
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
            // 新版本号须先持久化至存储才视为生效。写入失败时内存状态不变，后续重试时仍能检测到内容变更；
            // 若先修改内存状态，重试时会因摘要一致而跳过写入与下发。
            self.store.set_node_netmap(id, version, &digest)?;
            sync.state.version = version;
            sync.state.digest = Some(digest);
            sync.version_issued(Instant::now());
        }
        let released = sync.settle(relations);
        self.defer(view.network.id, released, Duration::ZERO);

        if (changed || force) && self.is_online(id) {
            netmap.version = version;
            tracing::debug!(node = %id, version, peers = netmap.peers.len(), relays = netmap.relays.len(), "下发 netmap");
            let sent = self.switchboard().send_netmap(id, netmap);
            if self.delivered(id, sent) {
                self.counters.snapshots_sent += 1;
                // 消息已进入发送队列，先更新内存中的已发送版本号以匹配后续节点确认；存储写入失败仅导致持久化值滞后，下次下发时会补写。
                let sync = self.sync.entry(id).or_default();
                sync.state.sent = version;
                self.store.set_node_sent(id, version)?;
            }
        }
        self.sync.entry(id).or_default().retrying = false;
        Ok(())
    }

    /// 把一条消息放进节点的发送队列。节点不在线时返回 `false`。
    ///
    /// 队列是有界的：满了说明这个节点不读，继续攒只会占内存，所以直接断开它。它重连之后会拿到最新的 netmap。
    pub(crate) fn send(&mut self, node: NodeId, message: ToNode) -> bool {
        let sent = self.switchboard().send(node, message);
        self.delivered(node, sent)
    }

    /// 处理放入节点发送队列的结果（[`Self::send`]）：无法放入（队列已满、连接已关闭）时断开该节点。
    pub(crate) fn delivered(&mut self, node: NodeId, sent: Result<(), Undelivered>) -> bool {
        match sent {
            Ok(()) => true,
            // 不持有本锁时消息无法放入，连接已从 `Switchboard` 去掉，`live` 中仍有记录：同样断开。
            Err(Undelivered::Offline) if self.live.contains_key(&node) => {
                tracing::warn!(%node, "节点的连接此前因消息无法放入发送队列而去掉，断开节点");
                self.drop_session(node);
                false
            }
            Err(Undelivered::Offline) => false,
            Err(undelivered @ (Undelivered::Full | Undelivered::Closed)) => {
                tracing::warn!(%node, reason = undelivered.reason(), "断开节点");
                self.drop_session(node);
                false
            }
        }
    }

    /// 不持有本锁时因消息无法放入发送队列而去掉了连接的节点（见 `Switchboard::send`）：将它们记为离线。
    /// 去掉连接的一方会唤醒后台任务（`Controller::on_switchboard`），后台每一轮都核对一遍。
    pub(crate) fn drop_lost_sessions(&mut self) {
        let lost: Vec<NodeId> = {
            let switchboard = self.switchboard();
            self.live
                .iter()
                .filter(|(node, live)| !switchboard.is_current(Admitted { node: **node, conn: live.conn }))
                .map(|(node, _)| *node)
                .collect()
        };
        for node in lost {
            tracing::warn!(%node, "节点的连接因消息无法放入发送队列而去掉，断开节点");
            self.drop_session(node);
        }
    }

    /// 节点上线：登记它的连接。之前的连接被顶替，它的发送队列随之关闭，那条连接自己会结束。返回被顶替的连接。
    pub(crate) fn go_online(&mut self, node: NodeId, live: Live, outbox: mpsc::Sender<ToNode>) -> Option<Live> {
        self.switchboard().connect(node, live.conn, outbox);
        self.live.insert(node, live)
    }

    /// 去掉节点的连接（`live` 和发送队列），发给它的查询不会再有回答。返回去掉的连接。
    pub(crate) fn go_offline(&mut self, node: NodeId) -> Option<Live> {
        self.switchboard().disconnect(node);
        self.live.remove(&node)
    }

    /// 节点不再在线：去掉它的连接，记下最近在线的时间，并且不再等它确认。
    ///
    /// 处于退避期（[`Self::back_off`]）时不记录最近在线的时间：该时间仅用于界面显示，不值得持有 controller 锁等待数据库响应；
    /// 节点参与的测试的结果同样交由后台任务写入（见 [`Inner::tests_node_gone`]）。
    pub(crate) fn drop_session(&mut self, node: NodeId) {
        let now = Instant::now();
        let Some(live) = self.go_offline(node) else { return };
        // 注册时那一条连接不算"最近在线"。
        if !live.enrolling
            && !self.backing_off(now)
            && let Err(err) = self.store.set_node_last_seen(node, self.clock.now())
        {
            // 只影响界面上的"最近在线"，不值得让调用方的操作失败。
            tracing::warn!(%node, "记录节点最近在线的时间失败：{err}");
            if err.is_database_wide() {
                self.back_off();
            }
        }
        self.stop_waiting_for(live.network, node);
        self.tests_node_gone(node, now);
    }

    /// 不再等 `node` 确认：等它确认才能继续的对端现在就可以继续。
    pub(crate) fn stop_waiting_for(&mut self, network: NetworkId, node: NodeId) {
        let released = self.sync.get_mut(&node).map(NodeSync::confirm_all).unwrap_or_default();
        self.defer(network, released, self.timing.ack_coalesce);
    }

    /// 由其他节点上报（端点、挂靠、relay 可达性）触发的重算：同一节点两次此类重算至少间隔 `report_coalesce`，
    /// 但若距上次已超出间隔，则本次仅等待 [`REPORT_LEAD`]。
    ///
    /// 这样两节点刚上线时，对端挂靠信息无需等满整个 `report_coalesce` 即可送达（避免首条经 relay 请求多等待近一秒）；
    /// 大量节点同时上线时，单个节点仍最多每 `report_coalesce` 收到一次上报触发的 netmap，避免突发高频推送。
    /// 若已存在不晚于本次时刻的待执行重算，则沿用原计划，本次变更随其一并计算（重算时读取届时的存储内容）。
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

    /// 延迟 `delay` 后重算指定节点。若节点已在队列中则取较早的计划时刻，避免持续变更无限推迟重算。
    pub(crate) fn defer(&mut self, network: NetworkId, nodes: impl IntoIterator<Item = NodeId>, delay: Duration) {
        let due = Instant::now() + delay;
        for node in nodes {
            self.dirty.entry(node).and_modify(|deferred| deferred.due = deferred.due.min(due)).or_insert(Deferred { network, due });
        }
    }

    /// 重算到期的节点，出的错记进 `failures`。返回剩下的里面最早的到期时间。
    pub(crate) fn flush_due(&mut self, now: Instant, failures: &mut Failures) -> Option<Instant> {
        // 整个数据库刚发生读写失败，尚处于退避期：暂不处理到期任务，避免访问数据库。
        if let Some(after) = self.flush_after.filter(|after| now < *after) {
            return Some(after);
        }
        let mut due: BTreeMap<NetworkId, BTreeSet<NodeId>> = BTreeMap::new();
        self.dirty.retain(|node, deferred| {
            let is_due = deferred.due <= now;
            if is_due {
                due.entry(deferred.network).or_default().insert(*node);
            }
            !is_due
        });
        let mut due = due.into_iter();
        for (network, nodes) in due.by_ref() {
            // 单个网络失败不阻塞其他网络；未完成的节点由 `refresh` 重新放回队列等待重试。
            let refreshed = self.refresh(network, Seeds::Nodes(nodes), None);
            let database_wide = refreshed.as_ref().is_err_and(Error::is_database_wide);
            failures.keep(refreshed);
            if database_wide {
                break;
            }
        }
        // 整个数据库不可读写时跳过剩余网络（见 `refresh_reporting`），放回队列留待下次重试。
        for (network, nodes) in due {
            self.retry_later(network, nodes);
        }
        // 这一轮刚开始退避的话，退避完之前来了也不做：不用为它白来。
        let after = self.flush_after.filter(|after| now < *after);
        self.dirty.values().map(|deferred| deferred.due).min().map(|due| after.map_or(due, |after| due.max(after)))
    }

    /// 在线的节点太久不确认时不再等它，免得它卡住别的节点。
    ///
    /// 每一项等待从登记的那一刻算起，满了 `ack_timeout` 就不再等。这期间节点收到多少份 netmap、换了多少次连接都不算：
    /// 否则无响应节点只需持续重连或频繁触发自身 netmap 变更，即可使撤销操作永久无法生效。
    pub(crate) fn give_up_on_slow_acks(&mut self, now: Instant) {
        let timeout = self.timing.ack_timeout;
        let mut given_up = Vec::new();
        for (node, live) in &self.live {
            let Some(sync) = self.sync.get_mut(node) else { continue };
            let peers = sync.give_up_waiting(now, timeout);
            if !peers.is_empty() {
                tracing::warn!(%node, ?timeout, ?peers, "节点超时未确认新 netmap，停止等待");
                given_up.push((live.network, peers));
            }
        }
        for (network, peers) in given_up {
            self.defer(network, peers, self.timing.ack_coalesce);
        }
    }
}
