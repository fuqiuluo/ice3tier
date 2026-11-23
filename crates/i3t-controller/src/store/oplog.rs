//! 操作记录：何时改了什么，说的是哪些东西。

use i3t_model::admin::{LogEntry, LogRef, NetworkId, Timestamp};
use serde_json::{Map, Value as JsonValue};
use tokio_postgres::Row;
use tokio_postgres::types::ToSql;

use super::codec::{Int, Json, Read, SqlNetwork, Unsigned, without_nul};
use super::{Store, StoreError};

/// 查操作记录的条件。都可以不写。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogFilter {
    /// 最多多少条。
    pub limit: u32,
    /// 只要编号比它小的：翻页时写上一页最后一条的编号。
    pub before: Option<u64>,
    pub network: Option<NetworkId>,
    /// 这种操作，或者以它加一个点开头的操作：`node` 包括 `node.update`、`node.relay.enable` 等。
    pub action: Option<String>,
    /// 提到了这样东西的。
    pub reference: Option<LogRef>,
}

/// 最多留这么多条，再多就从最老的删起。个人用的 controller 一年也攒不到这个数。
const KEEP: u32 = 10_000;

fn from_row(row: &Row) -> Read<LogEntry> {
    Ok(LogEntry {
        id: row.try_get::<_, Unsigned>("id")?.0,
        at: row.try_get::<_, Unsigned>("at")?.0,
        network: row.try_get::<_, Option<SqlNetwork>>("network_id")?.map(|network| network.0),
        action: row.try_get("action")?,
        detail: row.try_get("detail")?,
        refs: row.try_get::<_, Json<Vec<LogRef>>>("refs")?.0,
        params: row.try_get::<_, Json<Map<String, JsonValue>>>("params")?.0,
    })
}

impl Store {
    /// 记一条操作。`detail` 和 `params` 里不能有令牌之类的秘密。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn log(&self, at: Timestamp, network: Option<NetworkId>, action: &str, detail: &str, params: JsonValue) -> Result<(), StoreError> {
        self.log_refs(at, network, action, detail, &[], params)
    }

    /// 记一条操作，带上它说的是哪些东西。`detail` 和 `params` 里不能有令牌之类的秘密。
    ///
    /// `params` 是一个 JSON 对象（`serde_json::json!({ … })`）：按名字给出的参数。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn log_refs(
        &self,
        at: Timestamp,
        network: Option<NetworkId>,
        action: &str,
        detail: &str,
        refs: &[LogRef],
        params: JsonValue,
    ) -> Result<(), StoreError> {
        let params = match params {
            JsonValue::Object(params) => params,
            other => {
                // 调用方写错了。不为一条记录的参数让整个操作失败：记下原话，参数留空。
                debug_assert!(false, "操作记录的参数要是一个 JSON 对象，{action} 给的是 {other}");
                tracing::error!(action, params = %other, "操作记录的参数不是一个 JSON 对象，不记参数");
                Map::new()
            }
        };
        // 说明里会带着外面来的话（节点报的更新失败的原因、管理员填的发布源）：里面的 NUL 存不进文本列，去掉它，
        // 不让整条记录、连同它所在的那次操作一起失败。`params` 是 JSON，另有同样的处理。
        let (action, detail) = (without_nul(action), without_nul(detail));
        self.execute(
            "INSERT INTO oplog (at, network_id, action, detail, refs, params) VALUES ($1, $2, $3, $4, $5, $6)",
            &[&Unsigned(at), &network.map(SqlNetwork), &action, &detail, &Json(refs), &Json(&params)],
        )?;
        // 按条数删，不按编号算：编号是序列发的，撤销了的事务也占着号，编号差了一万不等于有一万条。
        // 不到 KEEP 条时里面那一句找不到第 KEEP + 1 新的，什么都不删。
        self.execute("DELETE FROM oplog WHERE id <= (SELECT id FROM oplog ORDER BY id DESC OFFSET $1 LIMIT 1)", &[&Int(KEEP)])?;
        Ok(())
    }

    /// 最近的 `limit` 条操作记录，新的在前。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn oplog(&self, limit: u32) -> Result<Vec<LogEntry>, StoreError> {
        self.oplog_filtered(&LogFilter { limit, ..LogFilter::default() })
    }

    /// 符合条件的操作记录，新的在前，最多 `filter.limit` 条。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn oplog_filtered(&self, filter: &LogFilter) -> Result<Vec<LogEntry>, StoreError> {
        // 每个条件的参数接着往下编号：放进 `values` 之后，它的长度就是这个参数的编号。
        let mut conditions: Vec<String> = Vec::new();
        let mut values: Vec<Box<dyn ToSql + Sync>> = Vec::new();
        if let Some(before) = filter.before {
            values.push(Box::new(i64::try_from(before).unwrap_or(i64::MAX)));
            conditions.push(format!("id < ${}", values.len()));
        }
        if let Some(network) = filter.network {
            values.push(Box::new(SqlNetwork(network)));
            conditions.push(format!("network_id = ${}", values.len()));
        }
        if let Some(action) = &filter.action {
            // 不用 LIKE：操作的名字里有下划线，在 LIKE 里它是通配符。
            values.push(Box::new(action.clone()));
            let action = values.len();
            conditions.push(format!("(action = ${action} OR starts_with(action, ${action} || '.'))"));
        }
        if let Some(reference) = filter.reference {
            // refs 是一个 JSON 数组：要里面有这一项的。
            values.push(Box::new(Json([reference])));
            conditions.push(format!("refs @> ${}", values.len()));
        }
        let condition = if conditions.is_empty() { String::new() } else { format!("WHERE {}", conditions.join(" AND ")) };
        values.push(Box::new(Int(filter.limit)));
        let sql = format!("SELECT * FROM oplog {condition} ORDER BY id DESC LIMIT ${}", values.len());
        let params: Vec<&(dyn ToSql + Sync)> = values.iter().map(|value| &**value).collect();
        self.query(&sql, &params, from_row)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::store::fixtures::home;

    #[test]
    fn old_entries_are_trimmed_by_count_not_by_how_far_the_ids_have_run() {
        let store = Store::temporary();
        store.log(10, None, "first", "", json!({})).unwrap();
        // 编号往前跳了很多（撤销了的事务也占着号），条数却只有两条：早先的那一条不该被删。
        store.execute_batch("SELECT setval(pg_get_serial_sequence('oplog', 'id'), 500000)");
        store.log(20, None, "second", "", json!({})).unwrap();
        assert_eq!(store.oplog(10).unwrap().iter().map(|entry| entry.action.as_str()).collect::<Vec<_>>(), ["second", "first"]);

        // 真的满了才删最老的。
        store.execute_batch(&format!(
            "INSERT INTO oplog (at, network_id, action, detail, refs, params) \
             SELECT 30, NULL, 'filler', '', '[]', '{{}}' FROM generate_series(1, {})",
            KEEP - 2
        ));
        assert_eq!(store.query_one("SELECT COUNT(*) FROM oplog", &[], |row| row.try_get::<_, i64>(0)).unwrap(), i64::from(KEEP));
        store.log(40, None, "newest", "", json!({})).unwrap();
        assert_eq!(store.query_one("SELECT COUNT(*) FROM oplog", &[], |row| row.try_get::<_, i64>(0)).unwrap(), i64::from(KEEP));
        let left = |action: &str| store.oplog_filtered(&LogFilter { limit: 1, action: Some(action.to_owned()), ..LogFilter::default() });
        assert!(left("first").unwrap().is_empty(), "最老的一条删掉了");
        assert_eq!(left("second").unwrap().len(), 1);
        assert_eq!(left("newest").unwrap().len(), 1);
    }

    #[test]
    fn a_nul_in_the_text_of_an_entry_is_dropped_instead_of_failing_it() {
        let store = Store::temporary();
        store.log(10, None, "node.update\0", "节点说：坏\0了", json!({ "reason": "坏\0了" })).unwrap();
        let entry = store.oplog(1).unwrap().remove(0);
        assert_eq!((entry.action.as_str(), entry.detail.as_str()), ("node.update", "节点说：坏了"));
        assert_eq!(entry.params["reason"], "坏了");
    }

    #[test]
    fn operations_are_listed_newest_first() {
        let store = Store::temporary();
        let network = store.insert_network(&home()).unwrap();
        store.log(10, None, "controller.start", "first start", json!({})).unwrap();
        store.log(20, Some(network), "node.rename", "node-1 -> nas-01", json!({ "node": 1, "node_name": "nas-01" })).unwrap();
        let entries = store.oplog(10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!((entries[0].at, entries[0].network, entries[0].action.as_str()), (20, Some(network), "node.rename"));
        assert_eq!((entries[1].at, entries[1].network, entries[1].detail.as_str()), (10, None, "first start"));
        assert_eq!(serde_json::Value::Object(entries[0].params.clone()), json!({ "node": 1, "node_name": "nas-01" }));
        assert!(entries[1].params.is_empty());
        assert_eq!(store.oplog(1).unwrap().len(), 1);
    }

    #[test]
    fn entries_can_be_paged_and_filtered_by_network_action_and_reference() {
        use i3t_model::admin::RefKind;
        let store = Store::temporary();
        let network = store.insert_network(&home()).unwrap();
        let node = |id| LogRef::new(RefKind::Node, id);
        store.log_refs(1, Some(network), "node.update", "a", &[node(3)], json!({})).unwrap();
        store.log_refs(2, Some(network), "node.relay.enable", "b", &[node(30)], json!({})).unwrap();
        store.log_refs(3, None, "update.force_all", "c", &[], json!({})).unwrap();
        store.log_refs(4, Some(network), "proxy.create", "d", &[LogRef::new(RefKind::Proxy, 3)], json!({})).unwrap();
        store.log(5, Some(network), "nodes.weird", "e", json!({})).unwrap();
        let ids = |filter: LogFilter| {
            store.oplog_filtered(&LogFilter { limit: 100, ..filter }).unwrap().iter().map(|entry| entry.at).collect::<Vec<_>>()
        };

        assert_eq!(ids(LogFilter::default()), [5, 4, 3, 2, 1]);
        let page = store.oplog_filtered(&LogFilter { limit: 2, ..LogFilter::default() }).unwrap();
        assert_eq!(page.iter().map(|entry| entry.at).collect::<Vec<_>>(), [5, 4]);
        assert_eq!(ids(LogFilter { before: Some(page[1].id), ..LogFilter::default() }), [3, 2, 1], "下一页从上一页最后一条之后接着");
        assert_eq!(ids(LogFilter { network: Some(network), ..LogFilter::default() }), [5, 4, 2, 1]);
        assert_eq!(ids(LogFilter { action: Some("node".into()), ..LogFilter::default() }), [2, 1], "nodes.weird 不算 node 开头的操作");
        assert_eq!(ids(LogFilter { action: Some("node.relay.enable".into()), ..LogFilter::default() }), [2]);
        assert_eq!(ids(LogFilter { action: Some("update.force_all".into()), ..LogFilter::default() }), [3]);
        assert_eq!(ids(LogFilter { reference: Some(node(3)), ..LogFilter::default() }), [1], "节点 3，不是节点 30，也不是代理 3");
        assert_eq!(store.oplog(10).unwrap()[3].refs, [node(30)]);
    }
}
