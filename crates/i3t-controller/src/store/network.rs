//! 网络。

use i3t_model::admin::{NetworkId, Timestamp};
use i3t_model::netmap::{Reach, RoutingMode};
use i3t_proto::flow::Class;
use ipnet::Ipv4Net;
use rusqlite::{OptionalExtension, Row, params};

use super::codec::{Json, SqlNetwork, Text, Unsigned, row_id};
use super::{Store, StoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRecord {
    pub id: NetworkId,
    pub name: String,
    pub cidr: Ipv4Net,
    pub routing: RoutingMode,
    pub max_relay_hops: u8,
    pub reach: Reach,
    pub created_at: Timestamp,
    /// 网络的默认服务等级。
    pub class: Option<Class>,
    /// 节点之间的连接请对端怎样确认：攒到多于几个包才单独发确认，没攒够时最多等多少毫秒。
    pub ack_eliciting_threshold: u32,
    pub max_ack_delay_ms: u32,
}

impl NetworkRecord {
    /// 节点全名的后缀。
    #[must_use]
    pub fn domain(&self) -> String {
        format!("{}.i3t", self.name)
    }

    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get::<_, SqlNetwork>("id")?.0,
            name: row.get("name")?,
            cidr: row.get::<_, Text<Ipv4Net>>("cidr")?.0,
            routing: row.get::<_, Json<RoutingMode>>("routing")?.0,
            max_relay_hops: row.get("max_relay_hops")?,
            reach: row.get::<_, Json<Reach>>("reach")?.0,
            created_at: row.get::<_, Unsigned>("created_at")?.0,
            class: row.get::<_, Option<Json<Class>>>("class")?.map(|json| json.0),
            ack_eliciting_threshold: row.get("ack_eliciting_threshold")?,
            max_ack_delay_ms: row.get("max_ack_delay_ms")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNetwork {
    pub name: String,
    pub cidr: Ipv4Net,
    pub routing: RoutingMode,
    pub max_relay_hops: u8,
    pub reach: Reach,
    pub created_at: Timestamp,
    pub class: Option<Class>,
    pub ack_eliciting_threshold: u32,
    pub max_ack_delay_ms: u32,
}

impl Store {
    /// 加一个网络，连同它的内置分组 `All`：每个网络从建好起就有它。
    ///
    /// # Errors
    ///
    /// 写数据库失败，包括名字和已有的网络重复。
    pub fn insert_network(&self, new: &NewNetwork) -> Result<NetworkId, StoreError> {
        self.conn.execute(
            "INSERT INTO networks (name, cidr, routing, max_relay_hops, reach, created_at, class, ack_eliciting_threshold, max_ack_delay_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                new.name,
                Text(new.cidr),
                Json(new.routing),
                new.max_relay_hops,
                Json(new.reach),
                Unsigned(new.created_at),
                new.class.map(Json),
                new.ack_eliciting_threshold,
                new.max_ack_delay_ms
            ],
        )?;
        let id = NetworkId(row_id(self.conn.last_insert_rowid())?);
        self.insert_builtin_group(id)?;
        Ok(id)
    }

    /// # Errors
    ///
    /// 读数据库失败。
    pub fn network(&self, id: NetworkId) -> Result<Option<NetworkRecord>, StoreError> {
        Ok(self.conn.query_row("SELECT * FROM networks WHERE id = ?1", params![SqlNetwork(id)], NetworkRecord::from_row).optional()?)
    }

    /// # Errors
    ///
    /// 读数据库失败。
    pub fn network_by_name(&self, name: &str) -> Result<Option<NetworkRecord>, StoreError> {
        Ok(self.conn.query_row("SELECT * FROM networks WHERE name = ?1", params![name], NetworkRecord::from_row).optional()?)
    }

    /// 全部网络，按编号排。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn networks(&self) -> Result<Vec<NetworkRecord>, StoreError> {
        let mut statement = self.conn.prepare("SELECT * FROM networks ORDER BY id")?;
        let rows = statement.query_map([], NetworkRecord::from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 改网络的设置。名字和创建时间不改。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn update_network(&self, network: &NetworkRecord) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE networks SET cidr = ?2, routing = ?3, max_relay_hops = ?4, reach = ?5, class = ?6,
                                 ack_eliciting_threshold = ?7, max_ack_delay_ms = ?8
             WHERE id = ?1",
            params![
                SqlNetwork(network.id),
                Text(network.cidr),
                Json(network.routing),
                network.max_relay_hops,
                Json(network.reach),
                network.class.map(Json),
                network.ack_eliciting_threshold,
                network.max_ack_delay_ms
            ],
        )?;
        Ok(())
    }

    /// 删掉一个网络，连同它的分组、规则、凭据、注册令牌和冷却记录。网络里还有节点时会因为外键失败。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn delete_network(&self, id: NetworkId) -> Result<(), StoreError> {
        self.conn.execute("DELETE FROM networks WHERE id = ?1", params![SqlNetwork(id)])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fixtures::home;

    #[test]
    fn networks_round_trip_and_ids_are_not_reused() {
        let store = Store::open_in_memory().unwrap();
        let first = store.insert_network(&home()).unwrap();
        let record = store.network(first).unwrap().unwrap();
        assert_eq!(record.name, "home");
        assert_eq!(record.domain(), "home.i3t");
        assert_eq!(record.cidr, "10.66.0.0/16".parse().unwrap());
        assert_eq!((record.ack_eliciting_threshold, record.max_ack_delay_ms), (10, 2));
        assert_eq!(store.network_by_name("home").unwrap(), Some(record.clone()));
        assert_eq!(store.networks().unwrap(), vec![record.clone()]);

        let updated = NetworkRecord {
            routing: RoutingMode::LowestCost,
            reach: Reach::RelayOnly,
            max_relay_hops: 3,
            class: Some(Class::Bulk),
            ack_eliciting_threshold: 4,
            max_ack_delay_ms: 5,
            ..record
        };
        store.update_network(&updated).unwrap();
        assert_eq!(store.network(first).unwrap(), Some(updated));

        store.delete_network(first).unwrap();
        assert_eq!(store.network(first).unwrap(), None);
        let second = store.insert_network(&home()).unwrap();
        assert!(second > first, "删掉的网络的编号不能再分出去");
    }

    #[test]
    fn two_networks_cannot_share_a_name() {
        let store = Store::open_in_memory().unwrap();
        store.insert_network(&home()).unwrap();
        assert!(store.insert_network(&home()).is_err());
    }
}
