//! 网络。

use i3t_model::admin::{NetworkId, Timestamp};
use i3t_model::netmap::{Reach, RoutingMode};
use i3t_proto::flow::Class;
use ipnet::Ipv4Net;
use tokio_postgres::Row;

use super::codec::{Int, Json, Read, SqlNetwork, Text, Unsigned};
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
    /// 节点之间直连时把同一时刻要发的几个小网络包合成一个包发。
    pub bundle_small_packets: bool,
    /// 节点的虚拟网卡：和内核之间是不是一大块一大块地交接，和默认的 MTU。
    pub vnet_offload: bool,
    pub vnet_mtu: u16,
}

impl NetworkRecord {
    /// 节点全名的后缀。
    #[must_use]
    pub fn domain(&self) -> String {
        format!("{}.i3t", self.name)
    }

    fn from_row(row: &Row) -> Read<Self> {
        Ok(Self {
            id: row.try_get::<_, SqlNetwork>("id")?.0,
            name: row.try_get("name")?,
            cidr: row.try_get::<_, Text<Ipv4Net>>("cidr")?.0,
            routing: row.try_get::<_, Json<RoutingMode>>("routing")?.0,
            max_relay_hops: row.try_get::<_, Int<u8>>("max_relay_hops")?.0,
            reach: row.try_get::<_, Json<Reach>>("reach")?.0,
            created_at: row.try_get::<_, Unsigned>("created_at")?.0,
            class: row.try_get::<_, Option<Json<Class>>>("class")?.map(|json| json.0),
            ack_eliciting_threshold: row.try_get::<_, Int<u32>>("ack_eliciting_threshold")?.0,
            max_ack_delay_ms: row.try_get::<_, Int<u32>>("max_ack_delay_ms")?.0,
            bundle_small_packets: row.try_get("bundle_small_packets")?,
            vnet_offload: row.try_get("vnet_offload")?,
            vnet_mtu: row.try_get::<_, Int<u16>>("vnet_mtu")?.0,
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
    pub bundle_small_packets: bool,
    pub vnet_offload: bool,
    pub vnet_mtu: u16,
}

impl Store {
    /// 加一个网络，连同它的内置分组 `All`：每个网络从建好起就有它。
    ///
    /// # Errors
    ///
    /// 写数据库失败，包括名字和已有的网络重复。
    pub fn insert_network(&self, new: &NewNetwork) -> Result<NetworkId, StoreError> {
        let id = self.insert(
            "INSERT INTO networks (name, cidr, routing, max_relay_hops, reach, created_at, class, ack_eliciting_threshold, max_ack_delay_ms,
                                   bundle_small_packets, vnet_offload, vnet_mtu)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             RETURNING id",
            &[
                &new.name,
                &Text(new.cidr),
                &Json(new.routing),
                &Int(new.max_relay_hops),
                &Json(new.reach),
                &Unsigned(new.created_at),
                &new.class.map(Json),
                &Int(new.ack_eliciting_threshold),
                &Int(new.max_ack_delay_ms),
                &new.bundle_small_packets,
                &new.vnet_offload,
                &Int(new.vnet_mtu),
            ],
        )?;
        let id = NetworkId(id);
        self.insert_builtin_group(id)?;
        Ok(id)
    }

    /// # Errors
    ///
    /// 读数据库失败。
    pub fn network(&self, id: NetworkId) -> Result<Option<NetworkRecord>, StoreError> {
        self.query_opt("SELECT * FROM networks WHERE id = $1", &[&SqlNetwork(id)], NetworkRecord::from_row)
    }

    /// # Errors
    ///
    /// 读数据库失败。
    pub fn network_by_name(&self, name: &str) -> Result<Option<NetworkRecord>, StoreError> {
        self.query_opt("SELECT * FROM networks WHERE name = $1", &[&name], NetworkRecord::from_row)
    }

    /// 全部网络，按编号排。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn networks(&self) -> Result<Vec<NetworkRecord>, StoreError> {
        self.query("SELECT * FROM networks ORDER BY id", &[], NetworkRecord::from_row)
    }

    /// 改网络的设置。名字和创建时间不改。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn update_network(&self, network: &NetworkRecord) -> Result<(), StoreError> {
        self.execute(
            "UPDATE networks SET cidr = $2, routing = $3, max_relay_hops = $4, reach = $5, class = $6,
                                 ack_eliciting_threshold = $7, max_ack_delay_ms = $8, bundle_small_packets = $9,
                                 vnet_offload = $10, vnet_mtu = $11
             WHERE id = $1",
            &[
                &SqlNetwork(network.id),
                &Text(network.cidr),
                &Json(network.routing),
                &Int(network.max_relay_hops),
                &Json(network.reach),
                &network.class.map(Json),
                &Int(network.ack_eliciting_threshold),
                &Int(network.max_ack_delay_ms),
                &network.bundle_small_packets,
                &network.vnet_offload,
                &Int(network.vnet_mtu),
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
        self.execute("DELETE FROM networks WHERE id = $1", &[&SqlNetwork(id)])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fixtures::home;

    #[test]
    fn networks_round_trip_and_ids_are_not_reused() {
        let store = Store::temporary();
        let first = store.insert_network(&home()).unwrap();
        let record = store.network(first).unwrap().unwrap();
        assert_eq!(record.name, "home");
        assert_eq!(record.domain(), "home.i3t");
        assert_eq!(record.cidr, "10.66.0.0/16".parse().unwrap());
        assert_eq!((record.ack_eliciting_threshold, record.max_ack_delay_ms, record.bundle_small_packets), (3, 2, true));
        assert_eq!((record.vnet_offload, record.vnet_mtu), (true, 1280));
        assert_eq!(store.network_by_name("home").unwrap(), Some(record.clone()));
        assert_eq!(store.networks().unwrap(), vec![record.clone()]);

        let updated = NetworkRecord {
            routing: RoutingMode::LowestCost,
            reach: Reach::RelayOnly,
            max_relay_hops: 3,
            class: Some(Class::Bulk),
            ack_eliciting_threshold: 4,
            max_ack_delay_ms: 5,
            bundle_small_packets: false,
            vnet_offload: false,
            vnet_mtu: 1400,
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
        let store = Store::temporary();
        store.insert_network(&home()).unwrap();
        assert!(store.insert_network(&home()).is_err());
    }
}
