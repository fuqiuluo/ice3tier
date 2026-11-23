//! 端口转发。

use std::net::SocketAddr;

use i3t_model::admin::{ForwardInput, NetworkId};
use i3t_model::netmap::{ForwardProtocol, ProxyProtocol};
use i3t_proto::flow::Class;
use ipnet::IpNet;
use tokio_postgres::Row;

use super::codec::{Int, Json, Read, SqlNetwork, SqlNode, Text};
use super::{Store, StoreError};

/// 一条存着的端口转发。它现在的状态不存，由 controller 现算。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRecord {
    pub id: u32,
    pub config: ForwardInput,
}

impl ForwardRecord {
    fn from_row(row: &Row) -> Read<Self> {
        Ok(Self {
            id: row.try_get::<_, Int<u32>>("id")?.0,
            config: ForwardInput {
                name: row.try_get("name")?,
                protocol: row.try_get::<_, Json<ForwardProtocol>>("protocol")?.0,
                listen_node: row.try_get::<_, SqlNode>("listen_node")?.0,
                bind: row.try_get::<_, Text<SocketAddr>>("bind")?.0,
                target_node: row.try_get::<_, SqlNode>("target_node")?.0,
                target_addr: row.try_get::<_, Text<SocketAddr>>("target_addr")?.0,
                allow_from: row.try_get::<_, Json<Vec<IpNet>>>("allow_from")?.0,
                enabled: row.try_get("enabled")?,
                class: row.try_get::<_, Option<Json<Class>>>("class")?.map(|json| json.0),
                proxy_protocol: row.try_get::<_, Option<Json<ProxyProtocol>>>("proxy_protocol")?.map(|json| json.0),
            },
        })
    }
}

impl Store {
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn insert_forward(&self, network: NetworkId, config: &ForwardInput) -> Result<u32, StoreError> {
        self.insert(
            "INSERT INTO forwards (network_id, name, protocol, listen_node, bind, target_node, target_addr, allow_from, enabled, class,
                                   proxy_protocol)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             RETURNING id",
            &[
                &SqlNetwork(network),
                &config.name,
                &Json(config.protocol),
                &SqlNode(config.listen_node),
                &Text(config.bind),
                &SqlNode(config.target_node),
                &Text(config.target_addr),
                &Json(&config.allow_from),
                &config.enabled,
                &config.class.map(Json),
                &config.proxy_protocol.map(Json),
            ],
        )
    }

    /// 一个网络的全部端口转发，按编号排。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn forwards(&self, network: NetworkId) -> Result<Vec<ForwardRecord>, StoreError> {
        self.query("SELECT * FROM forwards WHERE network_id = $1 ORDER BY id", &[&SqlNetwork(network)], ForwardRecord::from_row)
    }

    /// 只在这个网络里找。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn forward(&self, network: NetworkId, id: u32) -> Result<Option<ForwardRecord>, StoreError> {
        let sql = "SELECT * FROM forwards WHERE network_id = $1 AND id = $2";
        self.query_opt(sql, &[&SqlNetwork(network), &Int(id)], ForwardRecord::from_row)
    }

    /// 整个替换一条转发。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn update_forward(&self, id: u32, config: &ForwardInput) -> Result<(), StoreError> {
        self.execute(
            "UPDATE forwards SET name = $2, protocol = $3, listen_node = $4, bind = $5, target_node = $6, target_addr = $7,
                                 allow_from = $8, enabled = $9, class = $10, proxy_protocol = $11
             WHERE id = $1",
            &[
                &Int(id),
                &config.name,
                &Json(config.protocol),
                &SqlNode(config.listen_node),
                &Text(config.bind),
                &SqlNode(config.target_node),
                &Text(config.target_addr),
                &Json(&config.allow_from),
                &config.enabled,
                &config.class.map(Json),
                &config.proxy_protocol.map(Json),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// 写数据库失败。
    pub fn delete_forward(&self, id: u32) -> Result<(), StoreError> {
        self.execute("DELETE FROM forwards WHERE id = $1", &[&Int(id)])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use i3t_proto::NodeId;

    use super::*;
    use crate::store::fixtures::store_with_nodes;

    fn config(listen_node: NodeId, target_node: NodeId) -> ForwardInput {
        ForwardInput {
            name: "web".to_owned(),
            protocol: ForwardProtocol::Tcp,
            listen_node,
            bind: "127.0.0.1:8080".parse().unwrap(),
            target_node,
            target_addr: "192.168.1.10:80".parse().unwrap(),
            allow_from: Vec::new(),
            enabled: true,
            class: None,
            proxy_protocol: Some(ProxyProtocol::V2),
        }
    }

    #[test]
    fn forwards_round_trip_and_can_be_replaced() {
        let (store, network, nodes) = store_with_nodes(2);
        let original = config(nodes[0], nodes[1]);
        let id = store.insert_forward(network, &original).unwrap();
        assert_eq!(store.forwards(network).unwrap(), vec![ForwardRecord { id, config: original.clone() }]);

        let replacement = ForwardInput {
            protocol: ForwardProtocol::Udp,
            bind: "0.0.0.0:5353".parse().unwrap(),
            allow_from: vec!["10.0.0.0/8".parse().unwrap()],
            enabled: false,
            class: Some(i3t_proto::flow::Class::Interactive),
            proxy_protocol: None,
            ..original
        };
        store.update_forward(id, &replacement).unwrap();
        assert_eq!(store.forward(network, id).unwrap(), Some(ForwardRecord { id, config: replacement }));
        store.delete_forward(id).unwrap();
        assert_eq!(store.forward(network, id).unwrap(), None);
    }

    #[test]
    fn deleting_either_end_removes_the_forward_and_repointing_keeps_it() {
        let (store, network, nodes) = store_with_nodes(4);
        let (old, new, other, gone) = (nodes[0], nodes[1], nodes[2], nodes[3]);
        let inherited = store.insert_forward(network, &config(other, old)).unwrap();
        let listening = store.insert_forward(network, &config(old, other)).unwrap();
        let dropped = store.insert_forward(network, &config(other, gone)).unwrap();

        store.repoint_node(old, new).unwrap();
        store.delete_node(old).unwrap();
        store.delete_node(gone).unwrap();
        assert_eq!(store.forward(network, inherited).unwrap().unwrap().config.target_node, new);
        assert_eq!(store.forward(network, listening).unwrap().unwrap().config.listen_node, new);
        assert_eq!(store.forward(network, dropped).unwrap(), None);
    }
}
