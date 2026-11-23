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
    /// 记下一次换路，然后把这一对和这个网络多出来的老记录删掉。
    ///
    /// # Errors
    ///
    /// 写数据库失败，包括两个节点有一个不存在。
    pub fn insert_switch(&self, switch: &NewSwitch) -> Result<(), StoreError> {
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
        let (store, network, nodes) = store_with_nodes(3);
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
        store.insert_switch(&switch(nodes[0], nodes[1], 10, &Route::None, &relayed)).unwrap();
        store.insert_switch(&switch(nodes[0], nodes[1], 20, &relayed, &direct)).unwrap();
        store.insert_switch(&switch(nodes[1], nodes[0], 15, &Route::None, &relayed)).unwrap();
        let forward = store.switches(nodes[0], nodes[1]).unwrap();
        assert_eq!(
            forward.iter().map(|switch| (switch.at, switch.to.clone())).collect::<Vec<_>>(),
            [(20, direct.clone()), (10, relayed.clone())]
        );
        assert_eq!(store.switches(nodes[1], nodes[0]).unwrap().len(), 1, "两个方向分开查");

        for at in 100..130 {
            store.insert_switch(&switch(nodes[0], nodes[1], at, &relayed, &direct)).unwrap();
        }
        let kept = store.switches(nodes[0], nodes[1]).unwrap().len() + store.switches(nodes[1], nodes[0]).unwrap().len();
        assert_eq!(kept, KEEP_SWITCHES, "一对节点两个方向一共只留这么多");
        assert_eq!(store.switches(nodes[0], nodes[1]).unwrap()[0].at, 129);

        store.delete_node(nodes[1]).unwrap();
        assert!(store.switches(nodes[0], nodes[1]).unwrap().is_empty(), "节点删掉时它的记录跟着删");
    }
}
