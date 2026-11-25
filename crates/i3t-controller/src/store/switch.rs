//! 换路的历史：节点上报的每一次换路一行。
//!
//! # Invariants
//! - 一对节点（两个方向一共）只留最近的 [`KEEP_SWITCHES`] 条，一个网络一共最多 [`KEEP_PER_NETWORK`] 条：
//!   互相通信、又换过路的节点对再多，表的大小也有上限。

use super::codec::{Int, Json, SqlNetwork, SqlNode, Unsigned};
use super::{Store, StoreError};
use i3t_model::admin::{KEEP_SWITCHES, NetworkId, SwitchView, Timestamp};
use i3t_model::control::{Route, RouteCause};
use i3t_proto::NodeId;

/// 一个网络一共最多留多少条换路的记录，再多就删最老的。
pub const KEEP_PER_NETWORK: u32 = 10_000;

/// 一次要记下的换路。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSwitch {
    pub network: NetworkId,
    pub from: NodeId,
    pub to: NodeId,
    pub at: Timestamp,
    pub previous: Route,
    pub route: Route,
    pub cause: RouteCause,
}

impl Store {
    /// 记下一批换路，每条之后删掉这一对和这个网络多出来的老记录，留下的与逐条记下时相同。
    ///
    /// 全部在一个事务里：要么都记下，要么都不记。整批在提交时落盘一次，不再每条换路各落盘至少一次；
    /// 代价是多三次往返（开始事务、查询事务编号、提交），只有一条换路时并不更快。
    ///
    /// # Errors
    ///
    /// 写数据库失败，包括有节点不存在。
    pub fn insert_switches(&mut self, switches: &[NewSwitch]) -> Result<(), StoreError> {
        if switches.is_empty() {
            return Ok(());
        }
        self.atomically(|store| switches.iter().try_for_each(|switch| store.insert_switch(switch)))
    }

    /// 记下一次换路，然后把这一对和这个网络多出来的老记录删掉。
    fn insert_switch(&self, switch: &NewSwitch) -> Result<(), StoreError> {
        self.execute(
            "INSERT INTO route_switches (network_id, from_node, to_node, at, previous, route, cause) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &SqlNetwork(switch.network),
                &SqlNode(switch.from),
                &SqlNode(switch.to),
                &Unsigned(switch.at),
                &Json(&switch.previous),
                &Json(&switch.route),
                &Json(&switch.cause),
            ],
        )?;
        let keep = u32::try_from(KEEP_SWITCHES).unwrap_or(u32::MAX);
        self.execute(
            "DELETE FROM route_switches WHERE network_id = $1 AND ((from_node = $2 AND to_node = $3) OR (from_node = $3 AND to_node = $2))
             AND id NOT IN (
                 SELECT id FROM route_switches WHERE network_id = $1 AND ((from_node = $2 AND to_node = $3) OR (from_node = $3 AND to_node = $2))
                 ORDER BY at DESC, id DESC LIMIT $4)",
            &[&SqlNetwork(switch.network), &SqlNode(switch.from), &SqlNode(switch.to), &Int(keep)],
        )?;
        self.execute(
            "DELETE FROM route_switches WHERE network_id = $1 AND id NOT IN (
                 SELECT id FROM route_switches WHERE network_id = $1 ORDER BY id DESC LIMIT $2)",
            &[&SqlNetwork(switch.network), &Int(KEEP_PER_NETWORK)],
        )?;
        Ok(())
    }

    /// `from` 发往 `to` 这个方向留着的换路，新的在前。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn switches(&self, from: NodeId, to: NodeId) -> Result<Vec<SwitchView>, StoreError> {
        let sql = "SELECT at, previous, route, cause FROM route_switches WHERE from_node = $1 AND to_node = $2 ORDER BY at DESC, id DESC";
        self.query(sql, &[&SqlNode(from), &SqlNode(to)], |row| {
            Ok(SwitchView {
                at: row.try_get::<_, Unsigned>(0)?.0,
                from: row.try_get::<_, Json<Route>>(1)?.0,
                to: row.try_get::<_, Json<Route>>(2)?.0,
                cause: row.try_get::<_, Json<RouteCause>>(3)?.0,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fixtures::store_with_nodes;

    #[test]
    fn a_pair_keeps_its_latest_switches_in_both_directions_and_they_go_with_the_node() {
        let (mut store, network, nodes) = store_with_nodes(3);
        let relayed = Route::Relay { relays: vec![nodes[2]] };
        let direct = Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() };
        let switch = |from, to, at, previous: &Route, route: &Route| NewSwitch {
            network,
            from,
            to,
            at,
            previous: previous.clone(),
            route: route.clone(),
            cause: RouteCause::DirectVerified,
        };
        store
            .insert_switches(&[switch(nodes[0], nodes[1], 10, &Route::None, &relayed), switch(nodes[0], nodes[1], 20, &relayed, &direct)])
            .unwrap();
        store.insert_switches(&[switch(nodes[1], nodes[0], 15, &Route::None, &relayed)]).unwrap();
        let forward = store.switches(nodes[0], nodes[1]).unwrap();
        assert_eq!(
            forward.iter().map(|switch| (switch.at, switch.to.clone())).collect::<Vec<_>>(),
            [(20, direct.clone()), (10, relayed.clone())]
        );
        assert_eq!(store.switches(nodes[1], nodes[0]).unwrap().len(), 1, "两个方向分开查");

        let batch: Vec<NewSwitch> = (100..130).map(|at| switch(nodes[0], nodes[1], at, &relayed, &direct)).collect();
        store.insert_switches(&batch).unwrap();
        let kept = store.switches(nodes[0], nodes[1]).unwrap().len() + store.switches(nodes[1], nodes[0]).unwrap().len();
        assert_eq!(kept, KEEP_SWITCHES, "一对节点两个方向一共只留这么多");
        assert_eq!(store.switches(nodes[0], nodes[1]).unwrap()[0].at, 129);

        store.delete_node(nodes[1]).unwrap();
        assert!(store.switches(nodes[0], nodes[1]).unwrap().is_empty(), "节点删掉时它的记录跟着删");
    }

    #[test]
    fn a_batch_of_switches_is_recorded_as_a_whole_or_not_at_all() {
        let (mut store, network, nodes) = store_with_nodes(2);
        let switch = |to| NewSwitch {
            network,
            from: nodes[0],
            to,
            at: 10,
            previous: Route::None,
            route: Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() },
            cause: RouteCause::DirectVerified,
        };
        // 第二条的对端不存在：这一批一条也不记。
        let gone = NodeId::new(9999).unwrap();
        assert!(store.insert_switches(&[switch(nodes[1]), switch(gone)]).is_err());
        assert!(store.switches(nodes[0], nodes[1]).unwrap().is_empty(), "前面那条也撤销了");
        store.insert_switches(&[switch(nodes[1])]).unwrap();
        assert_eq!(store.switches(nodes[0], nodes[1]).unwrap().len(), 1);
        store.insert_switches(&[]).unwrap();
    }

    #[test]
    fn a_batch_keeps_the_same_switches_as_writing_them_one_by_one() {
        let (mut store, network, nodes) = store_with_nodes(4);
        let switch = |from: NodeId, to: NodeId, at: u64| NewSwitch {
            network,
            from,
            to,
            at,
            previous: Route::None,
            route: Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() },
            cause: RouteCause::DirectVerified,
        };
        // 网络里编号最小的一条属于节点对 0-1；这一对共有 KEEP_SWITCHES 条，其中时刻最早的另有一条（at=10）。
        store.insert_switches(&[switch(nodes[0], nodes[1], 100)]).unwrap();
        let fillers = KEEP_PER_NETWORK - u32::try_from(KEEP_SWITCHES).unwrap();
        store.execute_batch(&format!(
            "INSERT INTO route_switches (network_id, from_node, to_node, at, previous, route, cause)
             SELECT a.network_id, a.id, b.id, n, '0', '0', '0'
             FROM nodes a, nodes b, generate_series(1, {fillers}) AS n
             WHERE a.id = (SELECT id FROM nodes ORDER BY id OFFSET 2 LIMIT 1) AND b.id = (SELECT id FROM nodes ORDER BY id OFFSET 3 LIMIT 1)"
        ));
        let pair: Vec<NewSwitch> = [10].into_iter().chain(200..218).map(|at| switch(nodes[0], nodes[1], at)).collect();
        store.insert_switches(&pair).unwrap();
        assert_eq!(store.query_i64("SELECT COUNT(*) FROM route_switches"), i64::from(KEEP_PER_NETWORK));

        // 逐条写入时：第一条挤掉编号最小的那条（节点对 0-1 剩 19 条），第二条使这一对回到 20 条，at=10 的一条留下。
        store.insert_switches(&[switch(nodes[0], nodes[2], 500), switch(nodes[0], nodes[1], 500)]).unwrap();
        let kept: Vec<u64> = store.switches(nodes[0], nodes[1]).unwrap().into_iter().map(|switch| switch.at).collect();
        assert!(kept.contains(&10), "与逐条写入时相同：{kept:?}");
        assert_eq!(store.query_i64("SELECT COUNT(*) FROM route_switches"), i64::from(KEEP_PER_NETWORK));
    }

    #[test]
    fn a_network_keeps_its_latest_switches_up_to_the_limit() {
        let (mut store, network, nodes) = store_with_nodes(3);
        // 这个网络已经记满了：最老的编号最小。
        store.execute_batch(&format!(
            "INSERT INTO route_switches (network_id, from_node, to_node, at, previous, route, cause)
             SELECT a.network_id, a.id, b.id, n, '0', '0', '0'
             FROM nodes a, nodes b, generate_series(1, {KEEP_PER_NETWORK}) AS n
             WHERE a.id = (SELECT MIN(id) FROM nodes) AND b.id = (SELECT MIN(id) FROM nodes WHERE id > a.id)"
        ));
        let oldest = store.query_i64("SELECT MIN(id) FROM route_switches");
        let switch = NewSwitch {
            network,
            from: nodes[0],
            to: nodes[2],
            at: 10,
            previous: Route::None,
            route: Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() },
            cause: RouteCause::DirectVerified,
        };
        store.insert_switches(&[switch.clone(), switch]).unwrap();
        assert_eq!(store.query_i64("SELECT COUNT(*) FROM route_switches"), i64::from(KEEP_PER_NETWORK), "不超过上限");
        assert_eq!(store.query_i64("SELECT MIN(id) FROM route_switches"), oldest + 2, "删掉的是最老的两条");
        assert_eq!(store.switches(nodes[0], nodes[2]).unwrap().len(), 2, "新记下的都在");
    }
}
