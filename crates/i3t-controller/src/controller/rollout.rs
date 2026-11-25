//! 让谁更新：按已知的发布和每个节点的情况，给节点下发更新指令，或者撤回。
//!
//! 规矩都在 [`Inner::plan`] 和 [`Inner::roll_out`] 里：
//!
//! - **能更新的节点**：在线、支持更新协议、允许自主更新、当前版本低于已知正式版，且发布清单中包含其对应平台的更新包。
//!   不满足条件的节点绝不下发指令，管理员强制触发亦不例外。
//! - **等节点先上报**：节点连上来之后，要等它的第一次上报到了才给它下发。上报里有它的更新状态，
//!   它可能正带着"这个版本在我这里失败过"回来；不等的话会先把同一个版本又发给它一遍。
//! - **自动更新**（时机是"空闲时"）：全局的开关和这个节点自己的开关都开着，这个版本在节点所在的网络里没有被暂停，
//!   这个节点没有在这个版本上失败过。节点自己等到没有流才换程序。
//! - **强制更新**（"立刻"或者"排空后"）：管理员点的，不看两个开关、暂停和以前的失败。
//! - **更新包**：待更新节点对应平台的更新包下载缓存完成前暂不下发指令，先触发下载。
//! - **relay 逐台滚动更新**：同一网络内同一时间仅允许一台 relay 更新，待其完成更新、重新上线并度过稳定期后才轮到下一台，
//!   确保节点切换路径时总有其他 relay 可用。当前轮次的 relay 离线期间持续等待而不跳过：若其更新后未能恢复上线，
//!   极可能是新版本存在故障，此时继续更新其他 relay 会导致全网 relay 瘫痪。管理员单独触发的「立即更新」不受该队列限制。
//!   关闭了自身自动更新开关的 relay 不参与排队：它不会收到自动更新指令，也不占用轮次；若在轮到它时关闭其开关，
//!   将立即撤回其指令并让出轮次，不阻塞后续 relay。
//! - **网络里唯一的 relay** 没有特别的处理：节点自己知道它是不是唯一的 relay、有没有在替人转发，
//!   "空闲时"的时机下它把正在转发也算作不空闲。
//! - **撤回**：自动更新条件不再满足时（全局或节点开关关闭、版本被暂停），向尚未完成更新的节点发送撤回指令，
//!   若节点尚未替换程序则中止更新。
//!
//! 离线的节点什么都不用记：它重新连上来的时候和别的节点一样过一遍这些规矩。

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use i3t_model::admin::{NetworkId, UpdateWait};
use i3t_model::control::ToNode;
use i3t_model::update::{FailureKind, Platform, UpdateTiming, Version};
use i3t_proto::NodeId;

use super::update::Package;
use super::{Failures, Inner, Live};
use crate::error::Error;
use crate::store::NodeRecord;

/// 更新指令调度未完成（如存储读取失败）时的重试间隔。
const ROLLOUT_RETRY: Duration = Duration::from_secs(1);

/// 这次连接上发给一个节点的更新指令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Order {
    pub(crate) version: Version,
    pub(crate) timing: UpdateTiming,
    /// 节点已上报本次更新失败。保留该标记以避免在同一连接上反复重发；下次检查发布源时清除以允许重试。
    pub(crate) failed: bool,
}

/// 管理员强制的一次更新。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Forced {
    pub(crate) timing: UpdateTiming,
    /// 对单节点单独触发的「立即更新」跳过 relay 队列；「全部更新」中的 relay 仍按序逐台更新。
    pub(crate) skips_relay_queue: bool,
}

/// 一个网络里现在轮到更新的那个 relay。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Turn {
    pub(crate) holder: NodeId,
    /// 它拿到指令之后重新连上来的时刻。从这时起再过一段站稳的时间，才轮到下一个。
    pub(crate) back_since: Option<Instant>,
}

/// 一个节点和已知的发布对起来的结论。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Plan {
    /// 可以让它更新到的版本。
    pub(crate) available: Option<Version>,
    /// 现在该让它按什么时机更新；不该让它更新时是 `None`。
    pub(crate) wanted: Option<UpdateTiming>,
    /// 该让它更新、但指令还不能发的原因。
    pub(crate) waiting: Option<UpdateWait>,
}

impl Live {
    /// 节点是否支持更新相关协议消息。初代协议节点收到未知消息会断开连接，因此不支持的节点不得下发。
    pub(crate) const fn understands_updates(&self) -> bool {
        self.protocol >= 1
    }

    /// 可以给它下发更新指令了：懂更新，并且这次连接上已经报过它的更新状态。
    const fn takes_orders(&self) -> bool {
        self.understands_updates() && self.update.is_some()
    }
}

impl Inner {
    /// 一个节点现在该不该更新、更新到哪个版本、还差什么。只看内存里的状态和 `node` 本身。
    pub(crate) fn plan(&self, node: &NodeRecord) -> Plan {
        let Some(release) = self.updates.usable_release() else { return Plan::default() };
        let manifest = &release.manifest;
        let is_older = node.version.parse::<Version>().is_ok_and(|running| running < manifest.version);
        let has_package = node.platform.parse::<Platform>().is_ok_and(|platform| manifest.artifact(&platform).is_some());
        if !(is_older && has_package) {
            return Plan::default();
        }
        let version = manifest.version.clone();

        let can_be_ordered =
            self.live.get(&node.id).is_some_and(Live::takes_orders) && node.self_update.is_some_and(|ability| ability.able);
        let forced = self.updates.forced.get(&node.id);
        let failed_this_version =
            node.update_failure.as_ref().is_some_and(|failure| failure.version == version && failure.kind == FailureKind::VersionRejected);
        let automatic =
            self.updates.auto_update() && node.auto_update && !self.updates.is_paused_in(&version, node.network) && !failed_this_version;
        let wanted = forced.map(|forced| forced.timing).or(automatic.then_some(UpdateTiming::Idle)).filter(|_| can_be_ordered);

        let waiting = wanted.and_then(|timing| {
            let already_ordered = self
                .live
                .get(&node.id)
                .and_then(|live| live.order.as_ref())
                .is_some_and(|order| order.version == version && order.timing == timing);
            if already_ordered {
                return None;
            }
            if !matches!(self.updates.packages.get(&node.platform), Some(Package::Cached(_))) {
                return Some(UpdateWait::Package);
            }
            let queues = self.queues_for_turn(node);
            let taken = self.updates.relay_turns.get(&node.network).is_some_and(|turn| turn.holder != node.id);
            (queues && taken).then_some(UpdateWait::RelayTurn)
        });
        Plan { available: Some(version), wanted, waiting }
    }

    /// 按现在的情况给该更新的节点下发指令，撤回不该再做的。任何可能改变结论的事情之后都要调用一次：
    /// 节点上线、节点报了失败、查到了新的发布、包取回来了、设置变了、管理员点了按钮、轮到的 relay 站稳了。
    ///
    /// 存储读取失败导致未完成时，间隔 [`ROLLOUT_RETRY`] 后重试：否则只能等到下一次状态变更事件，期间应下发的指令无法发出，
    /// 应撤回的指令（例如管理员刚关闭自动更新）也无法及时撤回。
    ///
    /// 若有多个节点读取失败，返回首个错误并记录其余错误日志。
    pub(crate) fn roll_out(&mut self) -> Result<(), Error> {
        self.roll_out_reporting(Failures::into_result)
    }

    /// 后台定时触发的 [`Self::roll_out`]：若多个节点读取失败，其余错误仅输出 debug 日志。当持续失败时，
    /// 后台每 [`ROLLOUT_RETRY`] 都会重试；错误日志由调用方统一限流（见 `server::maintain`），
    /// 若在此处逐条输出会绕过限流。
    pub(crate) fn roll_out_in_background(&mut self) -> Result<(), Error> {
        self.roll_out_reporting(Failures::into_first)
    }

    /// `report` 控制多个节点读取失败时，首个之外的错误如何记录。
    fn roll_out_reporting(&mut self, report: fn(Failures) -> Result<(), Error>) -> Result<(), Error> {
        self.updates.next_rollout = None;
        let mut failures = Failures::default();
        let outcome = self.roll_out_at(Instant::now(), &mut failures).and_then(|()| report(failures));
        if outcome.is_err() {
            // 从出错的时候算：读存储可能等了很久（数据库被别的进程锁着时要等满超时），从开始算的话这时已经到点了。
            let retry = Instant::now() + ROLLOUT_RETRY;
            self.updates.next_rollout = Some(self.updates.next_rollout.map_or(retry, |at| at.min(retry)));
        }
        outcome
    }

    /// 它要排 relay 的队：是 relay，并且不是管理员单独点的"立即更新"。
    fn queues_for_turn(&self, node: &NodeRecord) -> bool {
        node.relay.is_some() && !self.updates.forced.get(&node.id).is_some_and(|forced| forced.skips_relay_queue)
    }

    /// 先撤回、再下发：撤回的都发出去了，才给任何节点下发新的指令。
    ///
    /// relay 的轮次在 [`Inner::settle_relay_turns`] 里就让出来了，比如轮到的 relay 刚被关掉了自动更新；
    /// 边看边发的话，排在它前面的下一个 relay 先拿到指令，看到它之前读存储出了错，它的撤回这一轮就发不出去，
    /// 两个 relay 同时在更新。
    ///
    /// 仅单个节点读取失败时跳过该节点，继续处理其余节点：避免单节点持续失败阻塞全量调度，
    /// 甚至影响管理员对其他节点的强制更新。若该节点仍持有未撤回的指令，无法确认其是否应被撤回，它可能仍在更新并占用本网轮次，
    /// 因此本轮不启动该网络中排队的其他 relay。若整个数据库不可读则提前中止，避免对剩余节点做无效尝试。
    ///
    /// 单节点错误记录到 `failures`；整个数据库不可读时直接返回该错误。
    fn roll_out_at(&mut self, now: Instant, failures: &mut Failures) -> Result<(), Error> {
        self.settle_relay_turns(now, failures)?;

        // 按网络一次读出全部节点，再按节点编号依次处理在线的：每个在线节点各读一次的话，节点重连时每份首次上报都要读一遍全部
        // 在线节点，controller 重启后的重连合计按节点数的平方增长。一个网络整体读不出来（又不是整个数据库的故障）时，
        // 这个网络的在线节点逐个读，单个节点读取失败只跳过它，同上。
        let networks: BTreeSet<NetworkId> = self.live.values().map(|live| live.network).collect();
        let mut records = BTreeMap::new();
        let mut unsure = BTreeSet::new();
        for network in networks {
            match self.store.nodes(network) {
                Ok(nodes) => records.extend(nodes.into_iter().map(|node| (node.id, node))),
                Err(err) if err.is_database_wide() => return Err(err.into()),
                Err(_) => {
                    let members: Vec<NodeId> = self.live.iter().filter(|(_, live)| live.network == network).map(|(id, _)| *id).collect();
                    for id in members {
                        match self.store.node(id) {
                            Ok(Some(node)) => {
                                records.insert(id, node);
                            }
                            Ok(None) => {}
                            Err(err) if err.is_database_wide() => return Err(err.into()),
                            Err(err) => {
                                if self.live.get(&id).is_some_and(|live| live.order.as_ref().is_some_and(|order| !order.failed)) {
                                    unsure.insert(network);
                                }
                                failures.keep(Err::<(), _>(err.into()));
                            }
                        }
                    }
                }
            }
        }
        let online: Vec<NodeId> = self.live.keys().copied().collect();
        let mut wanted = Vec::new();
        for id in online {
            let Some(node) = records.remove(&id) else { continue };
            let plan = self.plan(&node);
            let current = self.live.get(&id).and_then(|live| live.order.clone());
            match (plan.wanted, plan.available) {
                (Some(_), Some(_)) => wanted.push(node),
                // 失败了的指令不用撤回：节点那边已经结束了，撤回只会把它报上来的失败原因盖掉。
                _ => {
                    if current.is_some_and(|order| !order.failed) {
                        self.cancel_order(&node);
                    }
                }
            }
        }
        // 结论要重新看：前面的 relay 拿到指令时占了这一轮，同一个网络里后面的 relay 就要等。
        for node in wanted {
            let plan = self.plan(&node);
            let (Some(timing), Some(version)) = (plan.wanted, plan.available) else { continue };
            let current = self.live.get(&node.id).and_then(|live| live.order.as_ref());
            if current.is_some_and(|order| order.version == version && order.timing == timing) {
                continue;
            }
            // 不将空闲轮次分配给排队的 relay：读取失败的节点可能仍在更新（见上）。若当前节点自身已持有轮次则正常推进，不会新增并发更新的 relay。
            let blocked =
                unsure.contains(&node.network) && self.queues_for_turn(&node) && !self.updates.relay_turns.contains_key(&node.network);
            match plan.waiting {
                None if blocked => {}
                None => self.order(&node, version, timing),
                Some(UpdateWait::Package) => self.want_package(&node.platform),
                Some(UpdateWait::RelayTurn | UpdateWait::Unknown) => {}
            }
        }
        Ok(())
    }

    fn order(&mut self, node: &NodeRecord, version: Version, timing: UpdateTiming) {
        let Some(manifest) = self.updates.release.as_ref().map(|release| release.signed.clone()) else { return };
        if !self.send(node.id, ToNode::Update { manifest, timing }) {
            return;
        }
        tracing::info!(node = %node.id, name = %node.name, running = %node.version, %version, ?timing, relay = node.relay.is_some(), "给节点下发更新指令");
        self.counters.orders_sent += 1;
        self.updates.offered.insert(node.id, version.clone());
        if let Some(live) = self.live.get_mut(&node.id) {
            live.order = Some(Order { version, timing, failed: false });
        }
        // 不排队的 relay 也占着这一轮（这一轮空着的话）：它重启期间不该再让别的 relay 自动更新。
        if node.relay.is_some() {
            self.updates.relay_turns.entry(node.network).or_insert(Turn { holder: node.id, back_since: None });
        }
    }

    fn cancel_order(&mut self, node: &NodeRecord) {
        if self.send(node.id, ToNode::UpdateCancel) {
            tracing::info!(node = %node.id, name = %node.name, "撤回节点的更新指令：当前不再满足更新条件");
            self.counters.orders_cancelled += 1;
        }
        if let Some(live) = self.live.get_mut(&node.id) {
            live.order = None;
        }
    }

    fn want_package(&mut self, platform: &str) {
        if !self.updates.packages.contains_key(platform) {
            self.updates.packages.insert(platform.to_owned(), Package::Wanted);
        }
    }

    /// 轮到的 relay 重新连上来了：从现在起算它站稳的时间。
    pub(super) fn relay_is_back(&mut self, node: &NodeRecord) {
        if let Some(turn) = self.updates.relay_turns.get_mut(&node.network).filter(|turn| turn.holder == node.id) {
            turn.back_since = Some(Instant::now());
        }
    }

    /// 检查各网络当前持有轮次的 relay 是否已完成更新轮次，若已完成则释放轮次。
    ///
    /// 若仅该节点读取失败，则暂保留其轮次（无法确认其是否仍在更新），错误记录到 `failures`，其余网络正常处理；
    /// 若整个数据库不可读则提前中止。
    fn settle_relay_turns(&mut self, now: Instant, failures: &mut Failures) -> Result<(), Error> {
        let turns: Vec<_> = self.updates.relay_turns.iter().map(|(network, turn)| (*network, *turn)).collect();
        for (network, turn) in turns {
            let over = match self.store.node(turn.holder) {
                Ok(Some(node)) if node.relay.is_some() => self.turn_is_over(&node, turn, now),
                // 节点被删掉了，或者不再是 relay。
                Ok(Some(_) | None) => true,
                Err(err) if err.is_database_wide() => return Err(err.into()),
                Err(err) => {
                    failures.keep(Err::<(), _>(err.into()));
                    false
                }
            };
            if over {
                tracing::info!(%network, relay = %turn.holder, "该 relay 更新轮次结束，允许下一个 relay 更新");
                self.updates.relay_turns.remove(&network);
            }
        }
        Ok(())
    }

    fn turn_is_over(&mut self, node: &NodeRecord, turn: Turn, now: Instant) -> bool {
        let Some(target) = self.updates.usable_release().map(|release| release.manifest.version.clone()) else { return true };
        let updated = node.version.parse::<Version>().is_ok_and(|running| running >= target);
        let Some(live) = self.live.get(&node.id) else {
            // 离线通常表示节点正在重启。保持等待而不跳过（原因见模块文档）。
            return false;
        };
        if live.update.is_none() {
            // 刚连上来，还没有上报：它是更新成了还是带着失败回来的，等第一次上报才知道。
            return false;
        }
        if updated {
            // 已经是新版本并且在线。再等它站稳：挂靠它的节点重新建好中转会话要几秒。
            let since = turn.back_since.unwrap_or(now);
            let steady_at = since + self.timing.relay_settle;
            if now >= steady_at {
                return true;
            }
            if let Some(held) = self.updates.relay_turns.get_mut(&node.network) {
                held.back_since = Some(since);
            }
            self.updates.next_rollout = Some(self.updates.next_rollout.map_or(steady_at, |at| at.min(steady_at)));
            return false;
        }
        match &live.order {
            // 不再满足更新条件（如开关关闭或版本暂停）：本次 `roll_out` 随后即撤回指令，无需等到下一轮再释放轮次。
            Some(order) => order.failed || self.plan(node).wanted.is_none(),
            // 节点在线、仍为旧版本且本次连接尚未下发指令：若仍需更新则会立即重发，本轮继续由其持有。
            None => self.plan(node).wanted.is_none(),
        }
    }
}
