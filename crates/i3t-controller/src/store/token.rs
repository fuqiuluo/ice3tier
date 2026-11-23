//! 注册令牌。只存一次性密钥的哈希，和令牌文本开头给人认的一小段。
//!
//! 用掉的令牌不删：留着谁用的、什么时候用的，界面上看得到。用掉的和过期的令牌留 [`RETENTION_SECS`] 再清掉。

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use i3t_model::admin::{EnrollTokenInfo, GroupId, GroupRef, NetworkId, NodeRef, Timestamp, TokenState};
use i3t_proto::NodeId;
use tokio_postgres::Row;

use super::codec::{Blob, Int, Json, Read, SqlGroup, SqlIp, SqlNetwork, SqlNode, Unsigned};
use super::group::folded;
use super::{DIGEST_LEN, Store, StoreError};

/// 用掉的、过期的令牌留多久。
pub const RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

/// 存着的注册令牌。能给管理员看的部分就是 [`EnrollTokenInfo`]。
///
/// 读出来的 `state` 只分"用掉了"和"还没用"：过没过期要和当前的时间比，由 controller 判断（[`TokenRecord::is_pending`]）。
pub type TokenRecord = EnrollTokenInfo;

/// 读出来的令牌在 `now` 这一刻的样子：没用掉、已经过期的标成过期。
#[must_use]
pub fn token_at(mut token: TokenRecord, now: Timestamp) -> TokenRecord {
    if token.state == TokenState::Pending && token.expires_at <= now {
        token.state = TokenState::Expired;
    }
    token
}

/// 令牌在 `now` 这一刻还能不能用：没用掉，也没过期。
#[must_use]
pub fn is_pending(token: &TokenRecord, now: Timestamp) -> bool {
    token.used_at.is_none() && token.expires_at > now
}

/// 读令牌时顺带取出用它加入的节点（没有用过或者那个节点后来被删掉时没有），和它预设的分组（JSON 数组）。
const SELECT: &str = "SELECT enroll_tokens.*, nodes.name AS used_by_name, nodes.virtual_ip AS used_by_ip,
                             (SELECT COALESCE(jsonb_agg(jsonb_build_object('id', groups.id, 'name', groups.name,
                                                                           'builtin', groups.builtin)), '[]'::jsonb)
                              FROM token_groups JOIN groups ON groups.id = token_groups.group_id
                              WHERE token_groups.token_id = enroll_tokens.id) AS groups
                      FROM enroll_tokens LEFT JOIN nodes ON nodes.id = enroll_tokens.used_by";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewToken {
    pub network: NetworkId,
    pub secret_hash: [u8; DIGEST_LEN],
    /// 令牌文本开头给人认的一小段。
    pub prefix: String,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    /// 用它加入的节点自动加入的分组。不含内置分组。
    pub groups: BTreeSet<GroupId>,
    pub virtual_ip: Option<Ipv4Addr>,
    pub successor_of: Option<NodeId>,
}

fn from_row(row: &Row) -> Read<TokenRecord> {
    let used_at = row.try_get::<_, Option<Unsigned>>("used_at")?.map(|at| at.0);
    let used_by = match (row.try_get::<_, Option<SqlNode>>("used_by")?, row.try_get::<_, Option<String>>("used_by_name")?) {
        (Some(id), Some(name)) => Some(NodeRef { id: id.0, name, virtual_ip: row.try_get::<_, SqlIp>("used_by_ip")?.0 }),
        _ => None,
    };
    let mut groups = row.try_get::<_, Json<Vec<GroupRef>>>("groups")?.0;
    groups.sort_by_cached_key(|group| (folded(&group.name), group.id));
    Ok(TokenRecord {
        id: row.try_get::<_, Int<u32>>("id")?.0,
        network: row.try_get::<_, SqlNetwork>("network_id")?.0,
        created_at: row.try_get::<_, Unsigned>("created_at")?.0,
        expires_at: row.try_get::<_, Unsigned>("expires_at")?.0,
        groups,
        virtual_ip: row.try_get::<_, Option<SqlIp>>("virtual_ip")?.map(|ip| ip.0),
        successor_of: row.try_get::<_, Option<SqlNode>>("successor_of")?.map(|node| node.0),
        prefix: row.try_get("prefix")?,
        state: if used_at.is_some() { TokenState::Used } else { TokenState::Pending },
        used_at,
        used_by,
    })
}

impl Store {
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn insert_token(&self, new: &NewToken) -> Result<u32, StoreError> {
        let id = self.insert(
            "INSERT INTO enroll_tokens (network_id, secret_hash, prefix, created_at, expires_at, virtual_ip, successor_of)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id",
            &[
                &SqlNetwork(new.network),
                &Blob(new.secret_hash),
                &new.prefix,
                &Unsigned(new.created_at),
                &Unsigned(new.expires_at),
                &new.virtual_ip.map(SqlIp),
                &new.successor_of.map(SqlNode),
            ],
        )?;
        for &group in &new.groups {
            self.execute("INSERT INTO token_groups (token_id, group_id) VALUES ($1, $2)", &[&Int(id), &SqlGroup(group)])?;
        }
        Ok(id)
    }

    /// 一个网络里的全部令牌：还没用的、用掉的、过期的（还没清掉的那些）。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn tokens(&self, network: NetworkId) -> Result<Vec<TokenRecord>, StoreError> {
        let sql = format!("{SELECT} WHERE enroll_tokens.network_id = $1 ORDER BY enroll_tokens.id");
        self.query(&sql, &[&SqlNetwork(network)], from_row)
    }

    /// # Errors
    ///
    /// 读数据库失败。
    pub fn token(&self, id: u32) -> Result<Option<TokenRecord>, StoreError> {
        self.query_opt(&format!("{SELECT} WHERE enroll_tokens.id = $1"), &[&Int(id)], from_row)
    }

    /// 按一次性密钥的哈希找还没用掉的令牌。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn token_by_hash(&self, secret_hash: &[u8; DIGEST_LEN]) -> Result<Option<TokenRecord>, StoreError> {
        let sql = format!("{SELECT} WHERE enroll_tokens.secret_hash = $1 AND enroll_tokens.used_at IS NULL");
        self.query_opt(&sql, &[&Blob(*secret_hash)], from_row)
    }

    /// 令牌被用掉了。它不再指向要继任的节点：那个节点紧接着就被删掉，指着它的话这一行会被一起删掉。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn consume_token(&self, id: u32, at: Timestamp) -> Result<(), StoreError> {
        self.execute("UPDATE enroll_tokens SET used_at = $2, successor_of = NULL WHERE id = $1", &[&Int(id), &Unsigned(at)])?;
        Ok(())
    }

    /// 记下用令牌加入的是哪个节点。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn set_token_user(&self, id: u32, node: NodeId) -> Result<(), StoreError> {
        self.execute("UPDATE enroll_tokens SET used_by = $2 WHERE id = $1", &[&Int(id), &SqlNode(node)])?;
        Ok(())
    }

    /// 删掉一个令牌（用掉了，或者管理员收回）。返回它之前在不在。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn delete_token(&self, id: u32) -> Result<bool, StoreError> {
        Ok(self.execute("DELETE FROM enroll_tokens WHERE id = $1", &[&Int(id)])? > 0)
    }

    /// 清掉用掉或者过期已经超过 [`RETENTION_SECS`] 的令牌，返回清掉了几个。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn purge_expired_tokens(&self, now: Timestamp) -> Result<usize, StoreError> {
        let before = Unsigned(now.saturating_sub(RETENTION_SECS));
        self.execute(
            "DELETE FROM enroll_tokens WHERE (used_at IS NULL AND expires_at <= $1) OR (used_at IS NOT NULL AND used_at <= $1)",
            &[&before],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fixtures::store_with_nodes;

    #[test]
    fn a_token_is_found_by_its_hash_until_it_is_consumed() {
        let (store, network, nodes) = store_with_nodes(1);
        let servers = store.insert_group(network, "servers").unwrap();
        let new = NewToken {
            network,
            secret_hash: [9; DIGEST_LEN],
            prefix: "i3t-eyJzIjoiAb".to_owned(),
            created_at: 100,
            expires_at: 200,
            groups: [servers].into(),
            virtual_ip: Some("10.66.0.50".parse().unwrap()),
            successor_of: Some(nodes[0]),
        };
        let id = store.insert_token(&new).unwrap();
        let record = store.token_by_hash(&[9; DIGEST_LEN]).unwrap().unwrap();
        assert_eq!(record.id, id);
        assert_eq!(record.groups, vec![GroupRef { id: servers, name: "servers".to_owned(), builtin: false }]);
        store.delete_group(servers).unwrap();
        assert!(store.token(id).unwrap().unwrap().groups.is_empty(), "删掉的分组也从令牌上去掉");
        let record = store.token(id).unwrap().unwrap();
        assert_eq!(record.virtual_ip, new.virtual_ip);
        assert_eq!(record.successor_of, Some(nodes[0]));
        assert_eq!(store.tokens(network).unwrap(), vec![record.clone()]);
        assert_eq!(store.token(id).unwrap(), Some(record));
        assert_eq!(store.token_by_hash(&[8; DIGEST_LEN]).unwrap(), None);

        assert!(store.delete_token(id).unwrap());
        assert!(!store.delete_token(id).unwrap());
        assert_eq!(store.token_by_hash(&[9; DIGEST_LEN]).unwrap(), None);
    }

    #[test]
    fn a_used_token_stays_listed_with_the_node_that_used_it_and_is_purged_later() {
        let (store, network, nodes) = store_with_nodes(2);
        let new = NewToken {
            network,
            secret_hash: [4; DIGEST_LEN],
            prefix: "i3t-eyJzIjoiQx".to_owned(),
            created_at: 100,
            expires_at: 10_000,
            groups: BTreeSet::new(),
            virtual_ip: None,
            successor_of: Some(nodes[1]),
        };
        let id = store.insert_token(&new).unwrap();
        assert!(is_pending(&store.token(id).unwrap().unwrap(), 200));
        store.consume_token(id, 200).unwrap();
        store.set_token_user(id, nodes[0]).unwrap();
        assert_eq!(store.token_by_hash(&[4; DIGEST_LEN]).unwrap(), None, "用掉的令牌不能再用");
        let used = store.token(id).unwrap().unwrap();
        assert_eq!((used.state, used.used_at, used.successor_of), (TokenState::Used, Some(200), None));
        assert_eq!(used.used_by.as_ref().map(|node| node.id), Some(nodes[0]));
        assert!(!is_pending(&used, 200));

        store.delete_node(nodes[1]).unwrap();
        assert!(store.token(id).unwrap().is_some(), "被继任的节点删掉了，令牌的记录还在");
        store.delete_node(nodes[0]).unwrap();
        assert_eq!(store.token(id).unwrap().unwrap().used_by, None, "用它加入的节点删掉之后不再指向它");
        assert_eq!(store.purge_expired_tokens(200 + RETENTION_SECS - 1).unwrap(), 0);
        assert_eq!(store.purge_expired_tokens(200 + RETENTION_SECS).unwrap(), 1);
    }

    #[test]
    fn pending_tokens_turn_expired_at_their_expiry_time() {
        let (store, network, _nodes) = store_with_nodes(1);
        let id = store
            .insert_token(&NewToken {
                network,
                secret_hash: [5; DIGEST_LEN],
                prefix: String::new(),
                created_at: 100,
                expires_at: 300,
                groups: BTreeSet::new(),
                virtual_ip: None,
                successor_of: None,
            })
            .unwrap();
        let token = store.token(id).unwrap().unwrap();
        assert_eq!(token_at(token.clone(), 299).state, TokenState::Pending);
        assert_eq!(token_at(token, 300).state, TokenState::Expired);
    }

    #[test]
    fn expired_tokens_are_purged_and_a_successor_token_goes_with_its_node() {
        let (store, network, nodes) = store_with_nodes(1);
        let token = |hash: u8, expires_at, successor_of| NewToken {
            network,
            secret_hash: [hash; DIGEST_LEN],
            prefix: String::new(),
            created_at: 100,
            expires_at,
            groups: BTreeSet::new(),
            virtual_ip: None,
            successor_of,
        };
        store.insert_token(&token(1, 200, None)).unwrap();
        let kept = store.insert_token(&token(2, 300, None)).unwrap();
        let successor = store.insert_token(&token(3, 300, Some(nodes[0]))).unwrap();
        assert_eq!(store.purge_expired_tokens(200).unwrap(), 0, "过期的令牌还要留一阵");
        assert_eq!(store.purge_expired_tokens(200 + RETENTION_SECS).unwrap(), 1);
        assert_eq!(store.tokens(network).unwrap().iter().map(|token| token.id).collect::<Vec<_>>(), vec![kept, successor]);

        store.delete_node(nodes[0]).unwrap();
        assert_eq!(store.tokens(network).unwrap().iter().map(|token| token.id).collect::<Vec<_>>(), vec![kept]);
    }
}
