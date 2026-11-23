//! 分组和它的成员。
//!
//! 内置分组 `All` 是一行 `builtin` 为真的分组，每个网络一个，建网时一起建（[`Store::insert_network`]）。
//! 它的成员是全部节点，不写在成员表里。名字在一个网络里不分大小写唯一，靠的是存着的小写写法上的唯一约束。

use std::collections::BTreeSet;

use i3t_model::admin::{GroupId, GroupRef, NetworkId};
use i3t_proto::NodeId;
use tokio_postgres::Row;

use super::codec::{Int, Read, SqlGroup, SqlNetwork, SqlNode};
use super::{Store, StoreError};

/// 内置分组的名字。
pub const BUILTIN_GROUP: &str = "All";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub id: GroupId,
    pub network: NetworkId,
    /// 写的时候的大小写。
    pub name: String,
    /// 内置分组 `All`。
    pub builtin: bool,
}

impl GroupRecord {
    /// 管理 API 里指代它的写法：编号和现在的名字。
    #[must_use]
    pub fn to_ref(&self) -> GroupRef {
        GroupRef { id: self.id, name: self.name.clone(), builtin: self.builtin }
    }

    fn from_row(row: &Row) -> Read<Self> {
        Ok(Self {
            id: row.try_get::<_, SqlGroup>("id")?.0,
            network: row.try_get::<_, SqlNetwork>("network_id")?.0,
            name: row.try_get("name")?,
            builtin: row.try_get("builtin")?,
        })
    }
}

/// 比较名字用的写法：Unicode 的小写。`Servers` 和 `servers` 是同一个名字。
#[must_use]
pub fn folded(name: &str) -> String {
    name.to_lowercase()
}

impl Store {
    /// 加一个分组，返回它的编号。
    ///
    /// # Errors
    ///
    /// 写数据库失败，包括这个网络里已经有不分大小写同名的分组。
    pub fn insert_group(&self, network: NetworkId, name: &str) -> Result<GroupId, StoreError> {
        self.insert_group_row(network, name, false)
    }

    /// 建网时给它建内置分组。
    pub(super) fn insert_builtin_group(&self, network: NetworkId) -> Result<GroupId, StoreError> {
        self.insert_group_row(network, BUILTIN_GROUP, true)
    }

    fn insert_group_row(&self, network: NetworkId, name: &str, builtin: bool) -> Result<GroupId, StoreError> {
        let sql = "INSERT INTO groups (network_id, name, folded, builtin) VALUES ($1, $2, $3, $4) RETURNING id";
        Ok(GroupId(self.insert(sql, &[&SqlNetwork(network), &name, &folded(name), &builtin])?))
    }

    /// 一个网络的全部分组：内置的在最前面，其余按名字排（不分大小写）。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn groups(&self, network: NetworkId) -> Result<Vec<GroupRecord>, StoreError> {
        let sql = "SELECT * FROM groups WHERE network_id = $1 ORDER BY builtin DESC, folded, id";
        self.query(sql, &[&SqlNetwork(network)], GroupRecord::from_row)
    }

    /// 只在这个网络里找：别的网络的分组编号在这里等于不存在。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn group(&self, network: NetworkId, id: GroupId) -> Result<Option<GroupRecord>, StoreError> {
        let sql = "SELECT * FROM groups WHERE network_id = $1 AND id = $2";
        self.query_opt(sql, &[&SqlNetwork(network), &SqlGroup(id)], GroupRecord::from_row)
    }

    /// 这个网络里不分大小写叫 `name` 的分组。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn group_named(&self, network: NetworkId, name: &str) -> Result<Option<GroupRecord>, StoreError> {
        let sql = "SELECT * FROM groups WHERE network_id = $1 AND folded = $2";
        self.query_opt(sql, &[&SqlNetwork(network), &folded(name)], GroupRecord::from_row)
    }

    /// 网络的内置分组 `All`。网络不存在时是 `None`。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn builtin_group(&self, network: NetworkId) -> Result<Option<GroupId>, StoreError> {
        let sql = "SELECT id FROM groups WHERE network_id = $1 AND builtin";
        self.query_opt(sql, &[&SqlNetwork(network)], |row| Ok(row.try_get::<_, SqlGroup>(0)?.0))
    }

    /// # Errors
    ///
    /// 写数据库失败，包括新名字和这个网络里的另一个分组不分大小写重名。
    pub fn rename_group(&self, id: GroupId, name: &str) -> Result<(), StoreError> {
        self.execute("UPDATE groups SET name = $2, folded = $3 WHERE id = $1", &[&SqlGroup(id), &name, &folded(name)])?;
        Ok(())
    }

    /// 删掉一个分组，连同它的成员关系和注册令牌上的预设。用到它的规则要先删掉，否则外键不让删。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn delete_group(&self, id: GroupId) -> Result<(), StoreError> {
        self.execute("DELETE FROM groups WHERE id = $1", &[&SqlGroup(id)])?;
        Ok(())
    }

    /// 把节点加入分组。返回它原来是不是不在里面（也就是这次真的加了）。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn add_member(&self, group: GroupId, node: NodeId) -> Result<bool, StoreError> {
        let sql = "INSERT INTO group_members (group_id, node_id) VALUES ($1, $2) ON CONFLICT DO NOTHING";
        Ok(self.execute(sql, &[&SqlGroup(group), &SqlNode(node)])? > 0)
    }

    /// 把节点移出分组。返回它原来在不在里面。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn remove_member(&self, group: GroupId, node: NodeId) -> Result<bool, StoreError> {
        let sql = "DELETE FROM group_members WHERE group_id = $1 AND node_id = $2";
        Ok(self.execute(sql, &[&SqlGroup(group), &SqlNode(node)])? > 0)
    }

    /// 整个替换一个节点所在的分组。内置分组不在 `groups` 里：每个节点本来就在。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn set_node_groups(&self, node: NodeId, groups: &BTreeSet<GroupId>) -> Result<(), StoreError> {
        self.execute("DELETE FROM group_members WHERE node_id = $1", &[&SqlNode(node)])?;
        for &group in groups {
            self.add_member(group, node)?;
        }
        Ok(())
    }

    /// 预设了这个分组、还没用掉的注册令牌，按编号排。用掉了的令牌预设过什么只是记录，不算在内。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn pending_tokens_with_group(&self, group: GroupId) -> Result<Vec<u32>, StoreError> {
        let sql = "SELECT token_id FROM token_groups JOIN enroll_tokens ON enroll_tokens.id = token_groups.token_id
                   WHERE group_id = $1 AND enroll_tokens.used_at IS NULL ORDER BY token_id";
        self.query(sql, &[&SqlGroup(group)], |row| Ok(row.try_get::<_, Int<u32>>(0)?.0))
    }
}

#[cfg(test)]
mod tests {
    use crate::store::fixtures::store_with_nodes;

    #[test]
    fn every_network_has_its_builtin_group_and_names_are_unique_ignoring_case() {
        let (store, network, nodes) = store_with_nodes(2);
        let all = store.builtin_group(network).unwrap().unwrap();
        assert_eq!(store.group(network, all).unwrap().map(|group| (group.name, group.builtin)), Some(("All".to_owned(), true)));

        let servers = store.insert_group(network, "Servers").unwrap();
        assert!(store.insert_group(network, "SERVERS").is_err(), "不分大小写同名");
        assert!(store.insert_group(network, "all").is_err(), "All 占着它的名字");
        let laptops = store.insert_group(network, "laptops").unwrap();
        let names: Vec<String> = store.groups(network).unwrap().into_iter().map(|group| group.name).collect();
        assert_eq!(names, ["All", "laptops", "Servers"], "内置的在前，其余不分大小写按名字排");
        assert_eq!(store.group_named(network, "servers").unwrap().map(|group| group.id), Some(servers));

        assert!(store.add_member(servers, nodes[0]).unwrap());
        assert!(!store.add_member(servers, nodes[0]).unwrap(), "已经在里面");
        store.set_node_groups(nodes[1], &[servers, laptops].into()).unwrap();
        assert_eq!(store.node(nodes[1]).unwrap().unwrap().groups, [servers, laptops].into());
        assert!(store.remove_member(servers, nodes[1]).unwrap());
        assert!(!store.remove_member(servers, nodes[1]).unwrap());

        store.rename_group(laptops, "Phones").unwrap();
        assert!(store.rename_group(laptops, "servers").is_err());
        store.delete_group(servers).unwrap();
        assert!(store.node(nodes[0]).unwrap().unwrap().groups.is_empty(), "删掉分组，成员关系跟着没了");
        assert_eq!(store.group(network, servers).unwrap(), None);
    }

    #[test]
    fn group_ids_are_not_reused_and_stay_inside_their_network() {
        let (store, network, _) = store_with_nodes(0);
        let first = store.insert_group(network, "a").unwrap();
        store.delete_group(first).unwrap();
        let second = store.insert_group(network, "a").unwrap();
        assert!(second > first);
        let other = store
            .insert_network(&crate::store::NewNetwork {
                name: "lab".to_owned(),
                cidr: "10.67.0.0/16".parse().unwrap(),
                ..crate::store::fixtures::home()
            })
            .unwrap();
        assert_eq!(store.group(other, second).unwrap(), None);
        assert!(store.insert_group(other, "a").is_ok(), "别的网络里可以同名");
    }
}
