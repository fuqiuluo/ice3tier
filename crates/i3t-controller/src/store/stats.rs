//! 给界面画图的时间序列：每个点一行。

use std::collections::BTreeMap;

use i3t_model::admin::stats::Series;
use i3t_model::admin::{NetworkId, Timestamp};
use i3t_proto::NodeId;

use super::codec::{Int, SqlNetwork, Unsigned};
use super::{Store, StoreError};

/// 时间序列里的一个点。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StatPoint {
    pub network: NetworkId,
    pub series: Series,
    /// 节点的序列是这个节点；网络的序列是 `None`。
    pub node: Option<NodeId>,
    /// 该时间分段的起始时间戳，按步长对齐。
    pub at: Timestamp,
    pub value: f64,
}

/// 序列在表里的编号。写进数据库的数，已经用过的不能改，也不能给别的序列。
const fn code(series: Series) -> i64 {
    match series {
        Series::Online => 1,
        Series::Flows => 2,
        Series::Tx => 3,
        Series::Rx => 4,
        Series::NodeTx => 5,
        Series::NodeRx => 6,
        Series::NodeFlows => 7,
        Series::RelayAttached => 8,
        Series::ExitTx => 9,
        Series::ExitRx => 10,
    }
}

fn node_column(node: Option<NodeId>) -> u32 {
    node.map_or(0, NodeId::get)
}

/// [`Store::roll_up_stats`] 的语句。与 [`PRUNE`] 一样仅按 `step` 与 `at` 筛选，由索引 `stats_by_step_at` 定位数据点。
const ROLL_UP: &str = "INSERT INTO stats (network_id, series, node_id, step, at, value)
     SELECT network_id, series, node_id, $2::bigint, $3::bigint, AVG(value) FROM stats
     WHERE step = $1 AND at >= $3 AND at < $4
     GROUP BY network_id, series, node_id
     ON CONFLICT (network_id, series, node_id, step, at) DO UPDATE SET value = excluded.value";

/// [`Store::prune_stats`] 的语句。
const PRUNE: &str = "DELETE FROM stats WHERE step = $1 AND at < $2";

impl Store {
    /// 写下一批点，步长都是 `step`。同一段已经有点时换成新的。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn insert_stats(&self, step: u32, points: &[StatPoint]) -> Result<(), StoreError> {
        // 单条语句一次往返批量写入。若同一分段在批次中重复出现则保留后者，与逐条写入行为一致：
        // 单条 `INSERT … ON CONFLICT` 不能两次更新同一行。
        let mut latest = BTreeMap::new();
        for point in points {
            latest.insert((point.network, code(point.series), node_column(point.node), point.at), point.value);
        }
        if latest.is_empty() {
            return Ok(());
        }
        let (mut networks, mut series, mut nodes, mut times, mut values) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for ((network, code, node, at), value) in latest {
            networks.push(SqlNetwork(network));
            series.push(code);
            nodes.push(Int(node));
            times.push(Unsigned(at));
            values.push(value);
        }
        self.execute(
            "INSERT INTO stats (network_id, series, node_id, step, at, value)
             SELECT network_id, series, node_id, $6::bigint, at, value
             FROM UNNEST($1::bigint[], $2::bigint[], $3::bigint[], $4::bigint[], $5::double precision[])
                  AS point (network_id, series, node_id, at, value)
             ON CONFLICT (network_id, series, node_id, step, at) DO UPDATE SET value = excluded.value",
            &[&networks, &series, &nodes, &times, &values, &Int(step)],
        )?;
        Ok(())
    }

    /// 将 `[start, start + to_step)` 内步长为 `from_step` 的数据点按序列聚合为步长为 `to_step` 的均值点。
    /// 若某序列在该时段内无任何数据点则不写入（图表中表现为断开）。返回写入的数据点数。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn roll_up_stats(&self, from_step: u32, to_step: u32, start: Timestamp) -> Result<usize, StoreError> {
        let end = start.saturating_add(u64::from(to_step));
        self.execute(ROLL_UP, &[&Int(from_step), &Int(to_step), &Unsigned(start), &Unsigned(end)])
    }

    /// 删掉步长是 `step`、时间在 `before` 之前的点。返回删了几个。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn prune_stats(&self, step: u32, before: Timestamp) -> Result<usize, StoreError> {
        self.execute(PRUNE, &[&Int(step), &Unsigned(before)])
    }

    /// 一条序列在 `[from, to]` 里步长是 `step` 的点，按时间排。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn stats(
        &self,
        network: NetworkId,
        series: Series,
        node: Option<NodeId>,
        step: u32,
        range: (Timestamp, Timestamp),
    ) -> Result<Vec<(Timestamp, f64)>, StoreError> {
        self.query(
            "SELECT at, value FROM stats WHERE network_id = $1 AND series = $2 AND node_id = $3 AND step = $4 AND at >= $5 AND at <= $6
             ORDER BY at",
            &[&SqlNetwork(network), &code(series), &Int(node_column(node)), &Int(step), &Unsigned(range.0), &Unsigned(range.1)],
            |row| Ok((row.try_get::<_, Unsigned>(0)?.0, row.try_get::<_, f64>(1)?)),
        )
    }

    /// 表里一共有多少个点。测试和日志用。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn stats_count(&self) -> Result<u64, StoreError> {
        self.query_one("SELECT COUNT(*) FROM stats", &[], |row| Ok(row.try_get::<_, Unsigned>(0)?.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fixtures::home;

    fn point(network: NetworkId, series: Series, node: Option<u32>, at: Timestamp, value: f64) -> StatPoint {
        StatPoint { network, series, node: node.and_then(NodeId::new), at, value }
    }

    #[test]
    fn every_series_has_its_own_code() {
        let mut codes: Vec<i64> = Series::ALL.into_iter().map(code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), Series::ALL.len());
    }

    #[test]
    fn points_are_read_back_per_series_node_and_step_and_rolled_up_into_averages() {
        let store = Store::temporary();
        let network = store.insert_network(&home()).unwrap();
        let points = [
            point(network, Series::NodeTx, Some(3), 3_600, 100.0),
            point(network, Series::NodeTx, Some(3), 3_900, 300.0),
            point(network, Series::NodeTx, Some(4), 3_600, 7.0),
            point(network, Series::Online, None, 3_600, 2.0),
            point(network, Series::NodeTx, Some(3), 7_200, 9.0),
        ];
        store.insert_stats(300, &points).unwrap();
        let node3 = NodeId::new(3);
        assert_eq!(store.stats(network, Series::NodeTx, node3, 300, (0, 4_000)).unwrap(), [(3_600, 100.0), (3_900, 300.0)]);
        assert_eq!(store.stats(network, Series::Online, None, 300, (0, 9_000)).unwrap(), [(3_600, 2.0)]);
        assert!(store.stats(network, Series::NodeRx, node3, 300, (0, 9_000)).unwrap().is_empty());

        assert_eq!(store.roll_up_stats(300, 3600, 3_600).unwrap(), 3, "三条序列在这一小时里有点");
        assert_eq!(store.stats(network, Series::NodeTx, node3, 3600, (0, 9_000)).unwrap(), [(3_600, 200.0)], "7200 的点在下一小时");
        store.insert_stats(300, &[point(network, Series::NodeTx, Some(3), 3_900, 500.0)]).unwrap();
        assert_eq!(store.stats(network, Series::NodeTx, node3, 300, (3_900, 3_900)).unwrap(), [(3_900, 500.0)], "同一段写两次留后一次");

        assert_eq!(store.prune_stats(300, 3_900).unwrap(), 3, "3600 的三个点");
        assert_eq!(store.stats_count().unwrap(), 2 + 3);
        store.delete_network(network).unwrap();
        assert_eq!(store.stats_count().unwrap(), 0, "删掉网络连同它的点");
    }

    /// 整点汇总与过期清理在 controller 持锁时执行：须经索引定位要处理的数据点，不能顺序扫描全表。
    /// 语句按连接缓存，执行多次后数据库可能改用不看参数值的通用计划，两种计划都要检查。
    #[test]
    fn rolling_up_and_pruning_find_their_points_through_the_index_without_scanning_the_table() {
        let store = Store::temporary();
        store.insert_network(&home()).unwrap();
        let (fine, coarse, day) = (300, 3600, 86_400);
        let hour = 1_800_000_000_u64;
        // 整点清理之前的表：每条序列有 25 小时的 5 分钟粒度点和 168 个 1 小时粒度点，两档各有最早一小时的点已过保留期；
        // 按写入先后排列。
        store.execute_batch(&format!(
            "INSERT INTO stats (network_id, series, node_id, step, at, value)
             SELECT networks.id, 5, node, times.step, times.at, 1
             FROM networks, generate_series(1, 200) AS node,
                  (SELECT {fine} AS step, generate_series({}, {}, {fine}) AS at
                   UNION ALL SELECT {coarse}, generate_series({}, {}, {coarse})) AS times
             ORDER BY times.at + times.step, node;
             ANALYZE stats;
             PREPARE roll_up (bigint, bigint, bigint, bigint) AS {ROLL_UP};
             PREPARE prune (bigint, bigint) AS {PRUNE};",
            hour - 25 * 3600,
            hour - fine,
            hour - 7 * day - 3600,
            hour - 2 * 3600,
        ));
        let calls = [
            format!("roll_up({fine}, {coarse}, {}, {hour})", hour - 3600),
            format!("prune({fine}, {})", hour - day),
            format!("prune({coarse}, {})", hour - 7 * day),
        ];
        for mode in ["force_custom_plan", "force_generic_plan"] {
            store.execute_batch(&format!("SET plan_cache_mode = {mode}"));
            for call in &calls {
                let plan: Vec<String> = store.query(&format!("EXPLAIN (COSTS OFF) EXECUTE {call}"), &[], |row| row.try_get(0)).unwrap();
                let plan = plan.join("\n");
                assert!(plan.contains("stats_by_step_at") && !plan.contains("Seq Scan"), "{mode} {call}:\n{plan}");
            }
        }
    }
}
