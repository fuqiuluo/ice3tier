//! 每个节点的 netmap 下发到了哪一步，以及变更的生效顺序。
//!
//! 访问关系的变更要按顺序生效，否则版本交错期间会出现"发起端已经在用、目的端还不认"的失败：
//!
//! - **授权**先到目的端：目的节点确认自己已经认了发起节点之后，发起节点的 netmap 里才出现"可以访问它"。
//! - **撤销**先到发起端：发起节点确认自己已经不再访问目的节点之后，目的节点的 netmap 里才去掉"它可以访问我"。
//!
//! 所以一个节点的 netmap 里实际写着的关系可能暂时落后于规则算出来的关系。这里记的就是这两样东西：
//! 每个节点的 netmap 里现在实际写着什么（[`NodeSync::relations`]），以及它还欠着哪些确认。
//!
//! 确认有三个来源：节点发来 `Ack`；节点不在线（它没法确认，等它没有意义）；等得太久（不让一个不回话的节点卡住别人）。
//! "太久"从开始等的那一刻算起，每一项分开算：之后再给节点发多少份 netmap、节点换多少次连接都不往后推，
//! 否则一个不回话的节点只要不停地让 controller 给它发东西，就能让一次撤销永远生效不了。

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use i3t_proto::NodeId;

use crate::netmap::Relation;
use crate::store::NetmapState;

#[derive(Debug, Default)]
pub(crate) struct NodeSync {
    pub state: NetmapState,
    /// 这个节点当前版本的 netmap 里和各个对端的关系。
    pub relations: BTreeMap<NodeId, Relation>,
    /// 新认下的发起节点 → 第一次带着它的版本。节点确认到这个版本之前，对方还不能来访问。
    awaiting_accept: BTreeMap<NodeId, Pending>,
    /// 刚被收回许可的目的节点 → 去掉它的那个版本。节点确认到这个版本之前，它可能还在访问对方。
    awaiting_undial: BTreeMap<NodeId, Pending>,
    /// 最近一次因为别的节点的上报（端点、挂靠、连得上哪些 relay）给它排的重算的时刻，见 `Inner::defer_report`。
    pub report_due: Option<Instant>,
}

/// 一项还欠着的确认。
#[derive(Debug, Clone, Copy)]
struct Pending {
    /// 节点确认到这个版本才算数。
    version: u64,
    /// 开始等的时刻。等没等太久从这里算起。
    since: Instant,
}

/// 开始等 `peer` 这一项确认到 `version`。已经在等的沿用原来开始等的时刻：重新登记不能让它多等。
fn start_waiting(awaiting: &mut BTreeMap<NodeId, Pending>, peer: NodeId, version: u64, now: Instant) {
    awaiting.entry(peer).and_modify(|pending| pending.version = version).or_insert(Pending { version, since: now });
}

/// 去掉 `awaiting` 里 `done` 的等待，返回它们的对端。
fn take(awaiting: &mut BTreeMap<NodeId, Pending>, done: impl Fn(&Pending) -> bool) -> BTreeSet<NodeId> {
    let mut released = BTreeSet::new();
    awaiting.retain(|peer, pending| {
        let done = done(pending);
        if done {
            released.insert(*peer);
        }
        !done
    });
    released
}

impl NodeSync {
    pub(crate) fn with_state(state: NetmapState, relations: BTreeMap<NodeId, Relation>) -> Self {
        Self { state, relations, ..Self::default() }
    }

    /// 这个节点的 netmap 里认 `peer`，不管它确认了没有。
    pub(crate) fn accepts(&self, peer: NodeId) -> bool {
        self.relations.get(&peer).is_some_and(|relation| relation.inbound)
    }

    pub(crate) fn dials(&self, peer: NodeId) -> bool {
        self.relations.get(&peer).is_some_and(|relation| relation.outbound)
    }

    /// 这个节点的 netmap 里有没有 `peer`。
    pub(crate) fn knows(&self, peer: NodeId) -> bool {
        self.relations.contains_key(&peer)
    }

    /// `peer` 现在可以放心地来访问这个节点了：它的 netmap 里认 `peer`，而且已经确认过。
    pub(crate) fn has_confirmed_accepting(&self, peer: NodeId) -> bool {
        self.accepts(peer) && !self.awaiting_accept.contains_key(&peer)
    }

    /// 这个节点可能还在访问 `peer`：许可已经收回，但它还没确认。
    pub(crate) fn may_still_dial(&self, peer: NodeId) -> bool {
        self.awaiting_undial.contains_key(&peer)
    }

    /// 授权的第一步：这个节点从下一个版本起认 `peer`。在线的节点要确认过才算数。
    pub(crate) fn begin_accepting(&mut self, peer: NodeId, online: bool, now: Instant) {
        self.relations.entry(peer).or_default().inbound = true;
        if online {
            start_waiting(&mut self.awaiting_accept, peer, self.state.version + 1, now);
        }
    }

    /// 撤销的第一步：这个节点从下一个版本起不再访问 `peer`。在线的节点要确认过，`peer` 那边才能不认它。
    ///
    /// 和 [`Self::begin_accepting`] 一样，关系在这里就改掉，不等新的一版定下来。不然这一版一直定不下来时，
    /// 等待超时之后看到的还是"它在访问 `peer`"，同一项等待又被登记一遍，`peer` 那边永远等不到头。
    pub(crate) fn begin_undialing(&mut self, peer: NodeId, online: bool, now: Instant) {
        if let Entry::Occupied(mut relation) = self.relations.entry(peer) {
            relation.get_mut().outbound = false;
            if relation.get().is_empty() {
                relation.remove();
            }
        }
        if online {
            start_waiting(&mut self.awaiting_undial, peer, self.state.version + 1, now);
        }
    }

    /// 新算出来的 netmap 已经定下版本号：记下里面的关系，丢掉已经没有意义的等待。
    ///
    /// 返回因此不用再等的对端。正常情况下是空的；它们的 netmap 要重新算一遍。
    pub(crate) fn settle(&mut self, relations: BTreeMap<NodeId, Relation>) -> BTreeSet<NodeId> {
        let version = self.state.version;
        self.relations = relations;
        let relations = &self.relations;
        let mut released = BTreeSet::new();
        // 等待登记的是"下一个版本"。内容其实没变、版本号没有加的话，那个版本永远不会被确认，不能留着。
        // 关系又变回去的（刚认下又不认了、刚收回又给了）也不用再等。
        self.awaiting_accept.retain(|peer, pending| {
            let keep = pending.version <= version && relations.get(peer).is_some_and(|relation| relation.inbound);
            if !keep {
                released.insert(*peer);
            }
            keep
        });
        self.awaiting_undial.retain(|peer, pending| {
            let keep = pending.version <= version && !relations.get(peer).is_some_and(|relation| relation.outbound);
            if !keep {
                released.insert(*peer);
            }
            keep
        });
        released
    }

    /// 节点确认了 `version`。返回因此可以继续下一步的对端：它们的 netmap 要重新算。
    pub(crate) fn confirm(&mut self, version: u64) -> BTreeSet<NodeId> {
        self.release(|pending| pending.version <= version)
    }

    /// 开始等了 `timeout` 还没确认的不再等。后来才开始等的照旧等满它自己的时间。返回可以继续下一步的对端。
    ///
    /// 等的那一版还没定下来时（版本号记不进存储，还在重试），两种等待都往严的一边靠：
    ///
    /// - 授权接着等。节点没有可确认的东西，这时放开发起端，它就先于目的端拿到许可。
    /// - 撤销到点就不等。目的端多久之后不认发起端，不能取决于发起端那一版记不记得下来；
    ///   发起端晚一点才停，只是它那几次访问被拒绝。
    pub(crate) fn give_up_waiting(&mut self, now: Instant, timeout: Duration) -> BTreeSet<NodeId> {
        let issued = self.state.version;
        let overdue = |pending: &Pending| now.saturating_duration_since(pending.since) >= timeout;
        let mut released = take(&mut self.awaiting_accept, |pending| pending.version <= issued && overdue(pending));
        released.extend(take(&mut self.awaiting_undial, overdue));
        released
    }

    /// 不再等这个节点确认（它下线了）。返回可以继续下一步的对端。
    pub(crate) fn confirm_all(&mut self) -> BTreeSet<NodeId> {
        self.confirm(u64::MAX)
    }

    /// 去掉 `done` 的等待，返回它们的对端。
    fn release(&mut self, done: impl Fn(&Pending) -> bool) -> BTreeSet<NodeId> {
        let mut released = take(&mut self.awaiting_accept, &done);
        released.extend(take(&mut self.awaiting_undial, &done));
        released
    }

    pub(crate) fn is_waiting(&self) -> bool {
        !self.awaiting_accept.is_empty() || !self.awaiting_undial.is_empty()
    }

    /// `peer` 被删掉了：和它有关的一切都作废。
    pub(crate) fn forget(&mut self, peer: NodeId) {
        self.relations.remove(&peer);
        self.awaiting_accept.remove(&peer);
        self.awaiting_undial.remove(&peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn inbound() -> Relation {
        Relation { inbound: true, outbound: false }
    }

    /// 测试开始之后第 `secs` 秒。
    fn at(secs: u64) -> Instant {
        static START: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
        *START + Duration::from_secs(secs)
    }

    #[test]
    fn an_online_node_must_confirm_before_the_peer_may_come() {
        let mut sync = NodeSync::default();
        sync.begin_accepting(id(2), true, at(0));
        assert!(sync.accepts(id(2)) && !sync.has_confirmed_accepting(id(2)));

        sync.state.version = 1;
        assert!(sync.settle([(id(2), inbound())].into()).is_empty());
        assert!(sync.confirm(0).is_empty());
        assert!(!sync.has_confirmed_accepting(id(2)));
        assert_eq!(sync.confirm(1), [id(2)].into());
        assert!(sync.has_confirmed_accepting(id(2)) && !sync.is_waiting());
    }

    #[test]
    fn an_offline_node_counts_as_confirmed_at_once() {
        let mut sync = NodeSync::default();
        sync.begin_accepting(id(2), false, at(0));
        assert!(sync.has_confirmed_accepting(id(2)));
        sync.begin_undialing(id(3), false, at(0));
        assert!(!sync.may_still_dial(id(3)));
    }

    #[test]
    fn a_revoked_destination_is_released_only_by_a_late_enough_ack() {
        let mut sync = NodeSync::with_state(
            NetmapState { version: 4, ..NetmapState::default() },
            [(id(2), Relation { inbound: false, outbound: true })].into(),
        );
        sync.begin_undialing(id(2), true, at(0));
        sync.state.version = 5;
        assert!(sync.settle(BTreeMap::new()).is_empty());
        assert!(sync.may_still_dial(id(2)));
        assert!(sync.confirm(4).is_empty());
        assert_eq!(sync.confirm(7), [id(2)].into());
        assert!(!sync.may_still_dial(id(2)));
    }

    #[test]
    fn waiting_for_a_version_that_was_never_issued_is_dropped() {
        let mut sync = NodeSync::default();
        sync.begin_accepting(id(2), true, at(0));
        // 内容没变，版本号没有加：还是 0。
        assert_eq!(sync.settle([(id(2), inbound())].into()), [id(2)].into());
        assert!(sync.has_confirmed_accepting(id(2)));
    }

    #[test]
    fn going_offline_releases_everything_and_a_deleted_peer_is_forgotten() {
        let mut sync = NodeSync::default();
        sync.begin_accepting(id(2), true, at(0));
        sync.begin_accepting(id(3), true, at(0));
        sync.begin_undialing(id(4), true, at(0));
        sync.forget(id(3));
        assert!(!sync.knows(id(3)));
        assert_eq!(sync.confirm_all(), [id(2), id(4)].into());
        assert!(!sync.is_waiting());
    }

    #[test]
    fn each_wait_times_out_on_its_own_counted_from_when_it_began() {
        let timeout = Duration::from_secs(10);
        let mut sync = NodeSync::default();
        sync.begin_undialing(id(2), true, at(0));
        sync.state.version = 1;
        assert!(sync.settle(BTreeMap::new()).is_empty());
        sync.begin_accepting(id(3), true, at(6));
        sync.state.version = 2;
        assert!(sync.settle([(id(3), inbound())].into()).is_empty());

        assert!(sync.give_up_waiting(at(9), timeout).is_empty());
        assert_eq!(sync.give_up_waiting(at(10), timeout), [id(2)].into(), "后来开始的等待不推迟先开始的");
        assert!(!sync.may_still_dial(id(2)));
        assert!(!sync.has_confirmed_accepting(id(3)), "先开始的超时了，后来开始的还要等满它自己的时间");
        assert!(sync.give_up_waiting(at(15), timeout).is_empty());
        assert_eq!(sync.give_up_waiting(at(16), timeout), [id(3)].into());
        assert!(!sync.is_waiting());
    }

    #[test]
    fn before_its_version_has_gone_out_a_grant_keeps_waiting_and_a_revocation_still_times_out() {
        let timeout = Duration::from_secs(10);
        let mut sync = NodeSync::with_state(NetmapState::default(), [(id(3), Relation { inbound: false, outbound: true })].into());
        sync.begin_accepting(id(2), true, at(0));
        sync.begin_undialing(id(3), true, at(0));
        // 新的一版还没定下来。撤销到点就不等，不然对端永远等不到头；授权等多久都谈不上它迟迟不确认。
        assert!(sync.give_up_waiting(at(9), timeout).is_empty());
        assert_eq!(sync.give_up_waiting(at(60), timeout), [id(3)].into());
        assert!(!sync.may_still_dial(id(3)) && !sync.has_confirmed_accepting(id(2)));

        sync.state.version = 1;
        assert!(sync.settle([(id(2), inbound())].into()).is_empty());
        assert_eq!(sync.give_up_waiting(at(60), timeout), [id(2)].into(), "定下来之后照旧从开始等的那一刻算");
    }

    #[test]
    fn a_revocation_counts_as_not_dialing_from_the_moment_it_is_registered() {
        let both = Relation { inbound: true, outbound: true };
        let mut sync =
            NodeSync::with_state(NetmapState::default(), [(id(2), Relation { inbound: false, outbound: true }), (id(3), both)].into());
        sync.begin_undialing(id(2), true, at(0));
        sync.begin_undialing(id(3), true, at(0));
        assert!(!sync.dials(id(2)) && !sync.knows(id(2)), "只有这一个方向的关系，收回了就没有关系了");
        assert!(!sync.dials(id(3)) && sync.accepts(id(3)), "另一个方向不受影响");
        assert!(sync.may_still_dial(id(2)) && sync.may_still_dial(id(3)), "它确认之前可能还在访问");
        // 没有这个对端的关系时登记也不出错。
        sync.begin_undialing(id(4), false, at(0));
        assert!(!sync.knows(id(4)));
    }

    #[test]
    fn registering_a_wait_again_does_not_restart_its_clock() {
        let timeout = Duration::from_secs(10);
        let mut sync = NodeSync::default();
        sync.begin_undialing(id(2), true, at(0));
        sync.begin_undialing(id(2), true, at(8));
        sync.state.version = 1;
        assert!(sync.settle(BTreeMap::new()).is_empty());
        assert_eq!(sync.give_up_waiting(at(10), timeout), [id(2)].into());
    }
}
