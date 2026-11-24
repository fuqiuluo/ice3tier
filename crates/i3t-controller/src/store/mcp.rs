//! 签出去的 MCP 令牌的记录。不存 JWT 本身：只有它的 `jti`、签给了谁、能做什么、什么时候过期、撤销了没有。
//!
//! 撤销的不删：留着给管理员看。过期超过 [`RETENTION_SECS`](super::RETENTION_SECS) 的清掉（撤销了的也按过期时间算）。

use i3t_model::admin::mcp::{McpScope, McpTokenInfo, McpTokenState};
use i3t_model::admin::{NetworkId, Timestamp};
use tokio_postgres::Row;

use super::codec::{Int, Json, Read, SqlNetwork, Unsigned};
use super::{RETENTION_SECS, Store, StoreError};

/// 存着的 MCP 令牌，就是给管理员看的 [`McpTokenInfo`]。
///
/// 读出来的 `state` 只分"撤销了"和"没撤销"：过没过期要和当前的时间比，由 controller 判断（[`mcp_token_at`]）。
pub type McpTokenRecord = McpTokenInfo;

/// 读出来的令牌在 `now` 这一刻的样子：没撤销、已经过期的标成过期。
#[must_use]
pub fn mcp_token_at(mut token: McpTokenRecord, now: Timestamp) -> McpTokenRecord {
    if token.state == McpTokenState::Active && token.expires_at <= now {
        token.state = McpTokenState::Expired;
    }
    token
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMcpToken {
    pub jti: String,
    pub name: String,
    pub scopes: Vec<McpScope>,
    pub network: Option<NetworkId>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

fn from_row(row: &Row) -> Read<McpTokenRecord> {
    let revoked_at = row.try_get::<_, Option<Unsigned>>("revoked_at")?.map(|at| at.0);
    Ok(McpTokenRecord {
        id: row.try_get::<_, Int<u32>>("id")?.0,
        jti: row.try_get("jti")?,
        name: row.try_get("name")?,
        scopes: row.try_get::<_, Json<Vec<McpScope>>>("scopes")?.0,
        network: row.try_get::<_, Option<SqlNetwork>>("network_id")?.map(|network| network.0),
        created_at: row.try_get::<_, Unsigned>("created_at")?.0,
        expires_at: row.try_get::<_, Unsigned>("expires_at")?.0,
        revoked_at,
        state: if revoked_at.is_some() { McpTokenState::Revoked } else { McpTokenState::Active },
    })
}

impl Store {
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn insert_mcp_token(&self, new: &NewMcpToken) -> Result<u32, StoreError> {
        self.insert(
            "INSERT INTO mcp_tokens (jti, name, scopes, network_id, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id",
            &[&new.jti, &new.name, &Json(&new.scopes), &new.network.map(SqlNetwork), &Unsigned(new.created_at), &Unsigned(new.expires_at)],
        )
    }

    /// 全部 MCP 令牌，按编号排：还能用的、过期的、撤销的（还没清掉的那些）。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn mcp_tokens(&self) -> Result<Vec<McpTokenRecord>, StoreError> {
        self.query("SELECT * FROM mcp_tokens ORDER BY id", &[], from_row)
    }

    /// # Errors
    ///
    /// 读数据库失败。
    pub fn mcp_token(&self, id: u32) -> Result<Option<McpTokenRecord>, StoreError> {
        self.query_opt("SELECT * FROM mcp_tokens WHERE id = $1", &[&Int(id)], from_row)
    }

    /// 撤销一个令牌。已经撤销的不改它当初撤销的时间。返回这一次是不是真的撤销了它。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn revoke_mcp_token(&self, id: u32, at: Timestamp) -> Result<bool, StoreError> {
        Ok(self.execute("UPDATE mcp_tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL", &[&Int(id), &Unsigned(at)])? > 0)
    }

    /// 把还没撤销的令牌全部撤销（签名密钥换了），返回撤销了几个。过了期的不算在里面：它们本来就不能用了。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn revoke_all_mcp_tokens(&self, at: Timestamp) -> Result<usize, StoreError> {
        self.execute("UPDATE mcp_tokens SET revoked_at = $1 WHERE revoked_at IS NULL AND expires_at > $1", &[&Unsigned(at)])
    }

    /// 清掉过期已经超过 [`RETENTION_SECS`] 的令牌，返回清掉了几个。
    ///
    /// # Errors
    ///
    /// 写数据库失败。
    pub fn purge_expired_mcp_tokens(&self, now: Timestamp) -> Result<usize, StoreError> {
        self.execute("DELETE FROM mcp_tokens WHERE expires_at <= $1", &[&Unsigned(now.saturating_sub(RETENTION_SECS))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fixtures::home;

    fn new(jti: &str, network: Option<NetworkId>, expires_at: Timestamp) -> NewMcpToken {
        NewMcpToken {
            jti: jti.to_owned(),
            name: "claude-code".to_owned(),
            scopes: vec![McpScope::Read, McpScope::NodesEnroll],
            network,
            created_at: 100,
            expires_at,
        }
    }

    #[test]
    fn a_token_is_kept_with_what_it_may_do_and_revoking_it_twice_keeps_the_first_time() {
        let store = Store::temporary();
        let network = store.insert_network(&home()).unwrap();
        let id = store.insert_mcp_token(&new("a", Some(network), 500)).unwrap();
        let record = store.mcp_token(id).unwrap().unwrap();
        assert_eq!(
            record,
            McpTokenRecord {
                id,
                jti: "a".to_owned(),
                name: "claude-code".to_owned(),
                scopes: vec![McpScope::Read, McpScope::NodesEnroll],
                network: Some(network),
                created_at: 100,
                expires_at: 500,
                revoked_at: None,
                state: McpTokenState::Active,
            }
        );
        assert_eq!(mcp_token_at(record.clone(), 499).state, McpTokenState::Active);
        assert_eq!(mcp_token_at(record, 500).state, McpTokenState::Expired);
        assert!(store.insert_mcp_token(&new("a", None, 500)).is_err(), "jti 不能重复");

        assert!(store.revoke_mcp_token(id, 200).unwrap());
        assert!(!store.revoke_mcp_token(id, 300).unwrap(), "已经撤销了");
        assert!(!store.revoke_mcp_token(id + 1, 300).unwrap(), "没有这个令牌");
        let revoked = store.mcp_token(id).unwrap().unwrap();
        assert_eq!((revoked.state, revoked.revoked_at), (McpTokenState::Revoked, Some(200)));
        assert_eq!(mcp_token_at(revoked, 900).state, McpTokenState::Revoked, "撤销了的过期之后还是算撤销");
        assert_eq!(store.mcp_tokens().unwrap().len(), 1);
    }

    #[test]
    fn revoking_everything_leaves_the_expired_alone_and_old_tokens_are_purged_by_their_expiry() {
        let store = Store::temporary();
        let expired = store.insert_mcp_token(&new("expired", None, 150)).unwrap();
        let live = store.insert_mcp_token(&new("live", None, 900)).unwrap();
        let revoked = store.insert_mcp_token(&new("revoked", None, 900)).unwrap();
        store.revoke_mcp_token(revoked, 120).unwrap();

        assert_eq!(store.revoke_all_mcp_tokens(200).unwrap(), 1, "只有还能用的那一个");
        assert_eq!(store.mcp_token(expired).unwrap().unwrap().revoked_at, None);
        assert_eq!(store.mcp_token(live).unwrap().unwrap().revoked_at, Some(200));
        assert_eq!(store.mcp_token(revoked).unwrap().unwrap().revoked_at, Some(120));

        assert_eq!(store.purge_expired_mcp_tokens(150 + RETENTION_SECS - 1).unwrap(), 0, "过期的还要留一阵");
        assert_eq!(store.purge_expired_mcp_tokens(150 + RETENTION_SECS).unwrap(), 1);
        assert_eq!(store.mcp_tokens().unwrap().iter().map(|token| token.id).collect::<Vec<_>>(), [live, revoked]);
        assert_eq!(store.purge_expired_mcp_tokens(900 + RETENTION_SECS).unwrap(), 2, "撤销了的也按过期时间清");
    }

    #[test]
    fn the_tokens_of_a_network_go_with_it() {
        let store = Store::temporary();
        let network = store.insert_network(&home()).unwrap();
        let bound = store.insert_mcp_token(&new("bound", Some(network), 900)).unwrap();
        let free = store.insert_mcp_token(&new("free", None, 900)).unwrap();
        store.delete_network(network).unwrap();
        assert_eq!(store.mcp_token(bound).unwrap(), None);
        assert!(store.mcp_token(free).unwrap().is_some());
    }
}
