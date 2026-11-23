//! 访问规则。存的就是管理 API 里的 [`Rule`]：两头记分组的编号，读的时候带上分组现在的名字。

use i3t_model::admin::{Direction, GroupRef, NetworkId, Rule};
use tokio_postgres::Row;

use super::codec::{Int, Json, Read, SqlGroup, SqlNetwork};
use super::{Store, StoreError};

/// 读规则时顺带取出两头分组的名字，和它是不是内置的 `All`。
const SELECT: &str = "SELECT rules.*, src.name AS src_name, src.builtin AS src_builtin, dst.name AS dst_name, dst.builtin AS dst_builtin
                      FROM rules JOIN groups AS src ON src.id = rules.src JOIN groups AS dst ON dst.id = rules.dst";

fn from_row(row: &Row) -> Read<Rule> {
    Ok(Rule {
        id: row.try_get::<_, Int<u32>>("id")?.0,
        name: row.try_get("name")?,
        src: GroupRef { id: row.try_get::<_, SqlGroup>("src")?.0, name: row.try_get("src_name")?, builtin: row.try_get("src_builtin")? },
        dst: GroupRef { id: row.try_get::<_, SqlGroup>("dst")?.0, name: row.try_get("dst_name")?, builtin: row.try_get("dst_builtin")? },
        direction: row.try_get::<_, Json<Direction>>("direction")?.0,
        enabled: row.try_get("enabled")?,
    })
}

impl Store {
    /// 加一条规则。`rule.id` 和两头分组的名字不用，返回新分配的编号。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn insert_rule(&self, network: NetworkId, rule: &Rule) -> Result<u32, StoreError> {
        self.insert(
            "INSERT INTO rules (network_id, name, src, dst, direction, enabled) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            &[&SqlNetwork(network), &rule.name, &SqlGroup(rule.src.id), &SqlGroup(rule.dst.id), &Json(rule.direction), &rule.enabled],
        )
    }

    /// 一个网络的全部规则，按编号排。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn rules(&self, network: NetworkId) -> Result<Vec<Rule>, StoreError> {
        self.query(&format!("{SELECT} WHERE rules.network_id = $1 ORDER BY rules.id"), &[&SqlNetwork(network)], from_row)
    }

    /// 只在这个网络里找：别的网络的规则编号在这里等于不存在。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn rule(&self, network: NetworkId, id: u32) -> Result<Option<Rule>, StoreError> {
        let sql = format!("{SELECT} WHERE rules.network_id = $1 AND rules.id = $2");
        self.query_opt(&sql, &[&SqlNetwork(network), &Int(id)], from_row)
    }

    /// 写回一条规则。两头分组的名字不用。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn update_rule(&self, rule: &Rule) -> Result<(), StoreError> {
        self.execute(
            "UPDATE rules SET name = $2, src = $3, dst = $4, direction = $5, enabled = $6 WHERE id = $1",
            &[&Int(rule.id), &rule.name, &SqlGroup(rule.src.id), &SqlGroup(rule.dst.id), &Json(rule.direction), &rule.enabled],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// 写数据库失败。
    pub fn delete_rule(&self, id: u32) -> Result<(), StoreError> {
        self.execute("DELETE FROM rules WHERE id = $1", &[&Int(id)])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewNetwork;
    use crate::store::fixtures::home;

    #[test]
    fn rules_round_trip_and_stay_inside_their_network() {
        let store = Store::temporary();
        let home_id = store.insert_network(&home()).unwrap();
        let lab_id = store.insert_network(&NewNetwork { name: "lab".to_owned(), cidr: "10.67.0.0/16".parse().unwrap(), ..home() }).unwrap();
        let laptops = store.insert_group(home_id, "laptops").unwrap();
        let servers = store.insert_group(home_id, "servers").unwrap();
        let mut rule = Rule {
            id: 0,
            name: "laptops reach servers".to_owned(),
            src: GroupRef { id: laptops, name: "laptops".to_owned(), builtin: false },
            dst: GroupRef { id: servers, name: "servers".to_owned(), builtin: false },
            direction: Direction::OneWay,
            enabled: true,
        };
        rule.id = store.insert_rule(home_id, &rule).unwrap();
        assert_eq!(store.rules(home_id).unwrap(), vec![rule.clone()]);
        assert_eq!(store.rule(home_id, rule.id).unwrap(), Some(rule.clone()));
        assert_eq!(store.rule(lab_id, rule.id).unwrap(), None);
        assert!(store.rules(lab_id).unwrap().is_empty());

        rule.direction = Direction::Both;
        rule.enabled = false;
        store.update_rule(&rule).unwrap();
        assert_eq!(store.rule(home_id, rule.id).unwrap(), Some(rule.clone()));

        store.rename_group(servers, "boxes").unwrap();
        assert_eq!(store.rule(home_id, rule.id).unwrap().unwrap().dst.name, "boxes", "规则记的是编号，名字跟着分组走");
        assert!(store.delete_group(servers).is_err(), "还有规则用着它时不能删");

        store.delete_rule(rule.id).unwrap();
        assert!(store.rules(home_id).unwrap().is_empty());
        store.delete_group(servers).unwrap();
    }
}
