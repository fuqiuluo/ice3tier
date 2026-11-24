//! 主动测试的结果：每个测试一行，整个结果按 JSON 存。一对节点只留最近的 [`KEEP_PER_PAIR`] 个，够对比时段的差异。

use i3t_model::admin::NetworkId;
use i3t_model::admin::diag::TestView;
use i3t_proto::NodeId;
use tokio_postgres::Row;

use super::codec::{Int, Json, Read, SqlNetwork, SqlNode, Unsigned};
use super::{Store, StoreError};

/// 一对节点最多留多少个测试的结果，再多就删最老的。
pub const KEEP_PER_PAIR: u32 = 20;

/// 编号取行的 `id`：插入时结果中的编号为 0，此后不一定再更新。
fn from_row(row: &Row) -> Read<TestView> {
    Ok(TestView { id: row.try_get::<_, Unsigned>("id")?.0, ..row.try_get::<_, Json<TestView>>("view")?.0 })
}

impl Store {
    /// 插入新发起的主动测试记录并返回生成的编号。`view` 中的编号不作数，读取时以行的 `id` 为准。
    ///
    /// # Errors
    ///
    /// 写数据库失败，包括两个节点有一个不存在。
    pub fn insert_test(&self, view: &TestView) -> Result<u64, StoreError> {
        let id = self.query_one(
            "INSERT INTO tests (network_id, node_a, node_b, started_at, view) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            &[&SqlNetwork(view.network), &SqlNode(view.a.id), &SqlNode(view.b.id), &Unsigned(view.started_at), &Json(view)],
            |row| Ok(row.try_get::<_, Unsigned>(0)?.0),
        )?;
        self.prune_tests(view.network, view.a.id, view.b.id)?;
        Ok(id)
    }

    /// 换上一个测试的最新结果。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn update_test(&self, view: &TestView) -> Result<(), StoreError> {
        self.execute("UPDATE tests SET view = $2 WHERE id = $1", &[&Unsigned(view.id), &Json(view)])?;
        Ok(())
    }

    /// 一个网络里的一个测试。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn test(&self, network: NetworkId, id: u64) -> Result<Option<TestView>, StoreError> {
        // 测试编号由数据库生成，必然在有符号 64 位整数范围内；超出该范围的编号不可能存在，直接视为未找到而非报错。
        if i64::try_from(id).is_err() {
            return Ok(None);
        }
        let sql = "SELECT id, view FROM tests WHERE id = $1 AND network_id = $2";
        self.query_opt(sql, &[&Unsigned(id), &SqlNetwork(network)], from_row)
    }

    /// 最近的测试，新的在前。`pair` 有值时只要这一对节点的（先后无所谓）。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn tests(&self, network: NetworkId, pair: Option<(NodeId, NodeId)>, limit: u32) -> Result<Vec<TestView>, StoreError> {
        match pair {
            Some((a, b)) => self.query(
                "SELECT id, view FROM tests WHERE network_id = $1 AND ((node_a = $2 AND node_b = $3) OR (node_a = $3 AND node_b = $2))
                 ORDER BY id DESC LIMIT $4",
                &[&SqlNetwork(network), &SqlNode(a), &SqlNode(b), &Int(limit)],
                from_row,
            ),
            None => {
                let sql = "SELECT id, view FROM tests WHERE network_id = $1 ORDER BY id DESC LIMIT $2";
                self.query(sql, &[&SqlNetwork(network), &Int(limit)], from_row)
            }
        }
    }

    fn prune_tests(&self, network: NetworkId, a: NodeId, b: NodeId) -> Result<(), StoreError> {
        self.execute(
            "DELETE FROM tests WHERE network_id = $1 AND ((node_a = $2 AND node_b = $3) OR (node_a = $3 AND node_b = $2)) AND id NOT IN (
                 SELECT id FROM tests WHERE network_id = $1 AND ((node_a = $2 AND node_b = $3) OR (node_a = $3 AND node_b = $2))
                 ORDER BY id DESC LIMIT $4)",
            &[&SqlNetwork(network), &SqlNode(a), &SqlNode(b), &Int(KEEP_PER_PAIR)],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::store::fixtures::store_with_nodes;

    #[test]
    fn an_id_no_test_can_have_is_simply_not_found() {
        let (store, network, _nodes) = store_with_nodes(2);
        assert_eq!(store.test(network, 7).unwrap(), None);
        // 放不进数据库的整数的编号：以前在绑定参数时出错（管理 API 上是 500），应该是"没有这个测试"。
        for id in [u64::MAX, u64::try_from(i64::MAX).unwrap() + 1] {
            assert_eq!(store.test(network, id).unwrap(), None, "{id}");
        }
    }
}
