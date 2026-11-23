//! 让谁更新：按已知的发布和每个节点的情况，给节点下发更新指令，或者撤回。
//!
//! 规矩都在 [`Inner::plan`] 和 [`Inner::roll_out`] 里：
//!
//! - **能更新的节点**：在线、懂更新的协议、自己说能自己更新、版本比已知的发布旧、发布里有它的平台的包。
//!   不满足的节点从不下发，管理员强制也不行。
//! - **等节点先上报**：节点连上来之后，要等它的第一次上报到了才给它下发。上报里有它的更新状态，
//!   它可能正带着"这个版本在我这里失败过"回来；不等的话会先把同一个版本又发给它一遍。
//! - **自动更新**（时机是"空闲时"）：全局的开关和这个节点自己的开关都开着，这个版本在节点所在的网络里没有被暂停，
//!   这个节点没有在这个版本上失败过。节点自己等到没有流才换程序。
//! - **强制更新**（"立刻"或者"排空后"）：管理员点的，不看两个开关、暂停和以前的失败。
//! - **包**：要更新的节点所用平台的包取回来之前不下发，先去取。
//! - **relay 一个一个来**：同一个网络里一次只让一个 relay 更新，它更新完、重新上线并且站稳之后才轮到下一个，
//!   这样节点换路时总有别的 relay 可用。轮到的 relay 离线期间一直等它，不跳过：它要是更新之后再也没有回来，
//!   多半是新版本有问题，这时候接着更新别的 relay 只会把 relay 全部搞掉。管理员单独点的"立即更新"不排这个队。
//!   自己的自动更新开关关着的 relay 不在队里：它拿不到自动的指令，也就不占轮次；轮到它的时候关掉它的开关，
//!   它的指令被撤回，这一轮随即让给下一个，别的 relay 不用等它。
//! - **网络里唯一的 relay** 没有特别的处理：节点自己知道它是不是唯一的 relay、有没有在替人转发，
//!   "空闲时"的时机下它把正在转发也算作不空闲。
//! - **撤回**：自动更新不该再做的时候（全局的或者节点自己的开关关了、版本被暂停了），给还没做完的节点发撤回，
//!   节点没有换上去的话就此停下。
//!
//! 离线的节点什么都不用记：它重新连上来的时候和别的节点一样过一遍这些规矩。

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use i3t_model::admin::UpdateWait;
use i3t_model::control::ToNode;
use i3t_model::update::{FailureKind, Platform, UpdateTiming, Version};
use i3t_proto::NodeId;

use super::update::Package;
use super::{Failures, Inner, Live};
use crate::error::Error;
use crate::store::NodeRecord;

/// 下发更新指令没做完（读不出存储）时，过多久再做一遍。
const ROLLOUT_RETRY: Duration = Duration::from_secs(1);

/// 这次连接上发给一个节点的更新指令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Order {
    pub(crate) version: Version,
    pub(crate) timing: UpdateTiming,
    /// 节点说没有成。留着这条记录，同一条连接上就不会反复重发；下次查发布源时清掉，于是会再试。
    pub(crate) failed: bool,
}

/// 管理员强制的一次更新。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Forced {
    pub(crate) timing: UpdateTiming,
    /// 单独点的"立即更新"不排 relay 的队；"全部更新"里的 relay 照样一个一个来。
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
    /// 节点懂不懂更新用的那几条消息。最初一版的节点收到不认识的消息会断开，所以不懂的不能发。
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
    /// 读不出存储、没做完时过 [`ROLLOUT_RETRY`] 再做一遍：不然要等下一件可能改变结论的事，这期间该下发的指令发不出去，
    /// 该撤回的（比如管理员刚关掉了自动更新）也撤不回来。
    pub(crate) fn roll_out(&mut self) -> Result<(), Error> {
        self.updates.next_rollout = None;
        let outcome = self.roll_out_at(Instant::now());
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
    /// 只是某一个节点读不出来时跳过它，别的照常：不然它一直读不出的话，每次重做都卡在它这里，谁都拿不到指令，
    /// 管理员强制更新别的节点也不行。它手上还有没撤回的指令时，不知道该不该撤回，它可能正在更新、占着这个网络的轮次：
    /// 这个网络里排队的 relay 这一轮不开始。整个数据库都读不了时不往下试，别的节点也读不出来。
    fn roll_out_at(&mut self, now: Instant) -> Result<(), Error> {
        let mut failures = Failures::default();
        self.settle_relay_turns(now, &mut failures)?;

        let online: Vec<NodeId> = self.live.keys().copied().collect();
        let mut wanted = Vec::new();
        let mut unsure = BTreeSet::new();
        for id in online {
            let node = match self.store.node(id) {
                Ok(Some(node)) => node,
                Ok(None) => continue,
                Err(err) if err.is_database_wide() => return Err(err.into()),
                Err(err) => {
                    let ordered = self.live.get(&id).filter(|live| live.order.as_ref().is_some_and(|order| !order.failed));
                    if let Some(live) = ordered {
                        unsure.insert(live.network);
                    }
                    failures.keep(Err::<(), _>(err.into()));
                    continue;
                }
            };
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
            // 空着的轮次不给排队的 relay：读不出来的节点可能还在更新（见上）。它自己占着这一轮时照常，多不出一个 relay。
            let blocked =
                unsure.contains(&node.network) && self.queues_for_turn(&node) && !self.updates.relay_turns.contains_key(&node.network);
            match plan.waiting {
                None if blocked => {}
                None => self.order(&node, version, timing),
                Some(UpdateWait::Package) => self.want_package(&node.platform),
                Some(UpdateWait::RelayTurn | UpdateWait::Unknown) => {}
            }
        }
        failures.into_result()
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
            tracing::info!(node = %node.id, name = %node.name, "撤回给节点的更新指令：现在不该让它更新了");
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

    /// 看每个网络里轮到的那个 relay 是不是已经结束了它的这一轮，结束了就把这一轮让出来。
    ///
    /// 只是它读不出来时这一轮还留给它（不知道它是不是还在更新），错误记进 `failures`，别的网络照常；
    /// 整个数据库都读不了时不往下试。
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
                tracing::info!(%network, relay = %turn.holder, "这个 relay 的更新告一段落，轮到下一个");
                self.updates.relay_turns.remove(&network);
            }
        }
        Ok(())
    }

    fn turn_is_over(&mut self, node: &NodeRecord, turn: Turn, now: Instant) -> bool {
        let Some(target) = self.updates.usable_release().map(|release| release.manifest.version.clone()) else { return true };
        let updated = node.version.parse::<Version>().is_ok_and(|running| running >= target);
        let Some(live) = self.live.get(&node.id) else {
            // 不在线：多半是正在重启。等它回来，不跳过它（原因见模块文档）。
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
            // 不该再让它更新了（开关关了、版本被暂停了）：这次 `roll_out` 接着就撤回它的指令，这一轮不用等到下一次才让出来。
            Some(order) => order.failed || self.plan(node).wanted.is_none(),
            // 在线、还是旧版本、这次连接上还没有发过指令：还该让它更新的话马上会重发，这一轮接着是它的。
            None => self.plan(node).wanted.is_none(),
        }
    }
}
