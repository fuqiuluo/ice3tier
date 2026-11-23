//! 冷却期：删掉的节点留下的虚拟 IP 和名字，到期之前不分给别的节点。

use std::net::Ipv4Addr;

use super::codec::{SqlNetwork, Text, Unsigned};
use super::{Store, StoreError};
use i3t_model::admin::{NetworkId, Timestamp};

/// 冷却的是什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooldownKind {
    Address,
    Name,
}

impl CooldownKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Name => "name",
        }
    }
}

impl Store {
    /// 让一个值进入冷却期，到 `until` 为止。已经在冷却的取较晚的那个期限。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn add_cooldown(&self, network: NetworkId, kind: CooldownKind, value: &str, until: Timestamp) -> Result<(), StoreError> {
        self.execute(
            "INSERT INTO cooldowns (network_id, kind, value, until) VALUES ($1, $2, $3, $4)
             ON CONFLICT (network_id, kind, value) DO UPDATE SET until = GREATEST(cooldowns.until, excluded.until)",
            &[&SqlNetwork(network), &kind.as_str(), &value, &Unsigned(until)],
        )?;
        Ok(())
    }

    /// 一个值在 `now` 这个时刻还在不在冷却；在的话返回到什么时候为止。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn cooldown_until(
        &self,
        network: NetworkId,
        kind: CooldownKind,
        value: &str,
        now: Timestamp,
    ) -> Result<Option<Timestamp>, StoreError> {
        let sql = "SELECT until FROM cooldowns WHERE network_id = $1 AND kind = $2 AND value = $3 AND until > $4";
        self.query_opt(sql, &[&SqlNetwork(network), &kind.as_str(), &value, &Unsigned(now)], |row| Ok(row.try_get::<_, Unsigned>(0)?.0))
    }

    /// 一个网络里在 `now` 这个时刻还在冷却的虚拟 IP。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn cooling_addresses(&self, network: NetworkId, now: Timestamp) -> Result<Vec<Ipv4Addr>, StoreError> {
        let sql = "SELECT value FROM cooldowns WHERE network_id = $1 AND kind = $2 AND until > $3";
        self.query(sql, &[&SqlNetwork(network), &CooldownKind::Address.as_str(), &Unsigned(now)], |row| {
            Ok(row.try_get::<_, Text<Ipv4Addr>>(0)?.0)
        })
    }

    /// 清掉已经到期的冷却记录，返回清掉了几条。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn purge_cooldowns(&self, now: Timestamp) -> Result<usize, StoreError> {
        self.execute("DELETE FROM cooldowns WHERE until <= $1", &[&Unsigned(now)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewNetwork;
    use crate::store::fixtures::home;

    #[test]
    fn a_value_cools_down_until_its_deadline_and_only_in_its_network() {
        let store = Store::temporary();
        let home_id = store.insert_network(&home()).unwrap();
        let lab_id = store.insert_network(&NewNetwork { name: "lab".to_owned(), cidr: "10.67.0.0/16".parse().unwrap(), ..home() }).unwrap();
        store.add_cooldown(home_id, CooldownKind::Name, "nas-01", 500).unwrap();
        store.add_cooldown(home_id, CooldownKind::Address, "10.66.0.5", 500).unwrap();

        assert_eq!(store.cooldown_until(home_id, CooldownKind::Name, "nas-01", 499).unwrap(), Some(500));
        assert_eq!(store.cooldown_until(home_id, CooldownKind::Name, "nas-01", 500).unwrap(), None);
        assert_eq!(store.cooldown_until(home_id, CooldownKind::Address, "nas-01", 100).unwrap(), None, "名字和地址各管各的");
        assert_eq!(store.cooldown_until(lab_id, CooldownKind::Name, "nas-01", 100).unwrap(), None);
        assert_eq!(store.cooling_addresses(home_id, 100).unwrap(), vec!["10.66.0.5".parse::<Ipv4Addr>().unwrap()]);
        assert!(store.cooling_addresses(home_id, 500).unwrap().is_empty());
        assert!(store.cooling_addresses(lab_id, 100).unwrap().is_empty());
    }

    #[test]
    fn cooling_down_again_keeps_the_later_deadline_and_expired_entries_are_purged() {
        let store = Store::temporary();
        let network = store.insert_network(&home()).unwrap();
        store.add_cooldown(network, CooldownKind::Name, "a", 500).unwrap();
        store.add_cooldown(network, CooldownKind::Name, "a", 300).unwrap();
        assert_eq!(store.cooldown_until(network, CooldownKind::Name, "a", 0).unwrap(), Some(500));
        store.add_cooldown(network, CooldownKind::Name, "b", 900).unwrap();
        assert_eq!(store.purge_cooldowns(500).unwrap(), 1);
        assert_eq!(store.cooldown_until(network, CooldownKind::Name, "b", 0).unwrap(), Some(900));
    }
}
