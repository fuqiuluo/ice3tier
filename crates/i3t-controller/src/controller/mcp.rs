//! MCP 令牌：签给 AI Agent 的 JWT 的签发、验证和撤销。
//!
//! JWT 用一把专门的 Ed25519 密钥签（数据目录里的 [`MCP_KEY_FILE`]），不是 controller 的那一把：节点认的密钥不拿来签别的东西。
//! 算法固定是 `EdDSA`，验证时根本不看 JWT 头里写的 `alg`：`alg: none`、换成 HMAC 再拿公钥当密钥这类把戏在这里无从下手。
//!
//! 签过的每一个令牌都记在数据库里（[`Store::mcp_tokens`]），内存里另有一份（[`McpAuth`]）。验证只看内存里的这一份，
//! 不查库：每次 MCP 调用都要验证，不能让它等数据库，也不放在 controller 的大锁里。JWT 要签名对、没过期、
//! 而且它的 `jti` 在这一份里没被撤销才算数，所以撤销之后的下一次调用就被拒绝，库里没有记录的 JWT 也不认。
//!
//! 换密钥：停 controller，删掉 [`MCP_KEY_FILE`]，再启动，controller 生成一把新的。原来签的 JWT 全部验不过；
//! 库里记着这些令牌是哪把密钥签的（[`MCP_KEY_META`]），启动时发现换了就把它们都标成撤销，列表里不会有一个看着能用、
//! 其实不能用的令牌。恢复备份时没有把这个文件放回来也是一样。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use i3t_crypto::{NodeKey, Signature, verify_raw};
use i3t_model::admin::mcp::{CreateMcpToken, CreatedMcpToken, MAX_LIFETIME_SECS, MCP_PATH, McpScope, McpTokenInfo};
use i3t_model::admin::{API_PREFIX, ActorKind, LogActor, NetworkId, Timestamp, action};
use i3t_proto::PublicKey;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{Controller, Inner, create_key, naming, read_key};
use crate::error::{Entity, Error};
use crate::store::{NewMcpToken, Store, StoreError, mcp_token_at};

/// 数据目录里签 MCP 令牌的密钥。要留着已经签出去的令牌，备份时带上它。
pub(crate) const MCP_KEY_FILE: &str = "mcp.key";
/// 库里的 MCP 令牌是哪把密钥签的：它的公钥。
const MCP_KEY_META: &str = "mcp_key";

/// JWT 的头。只有这一种，所以是写死的。
const JWT_HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;
/// 比这更长的不是这里签的 JWT：名字最长 64 个字符，加上别的字段也到不了一半。不去解码它。
const MAX_JWT_LEN: usize = 2048;
/// `jti` 是这么多个随机字节的 base64url。
const JTI_BYTES: usize = 16;

/// JWT 里的内容。
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// 是哪个 controller 签的（[`issuer`]）。
    iss: String,
    /// 给哪里用的：这个 controller 的 MCP 端点（[`audience`]）。
    aud: String,
    /// 签发时起的名字。
    sub: String,
    jti: String,
    iat: Timestamp,
    exp: Timestamp,
    /// 权限，用空格隔开。
    scope: String,
    /// 只限这一个网络。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<NetworkId>,
}

/// 一个验过的 MCP 令牌说的话：是谁，能做什么。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpGrant {
    /// 签发时起的名字。
    pub name: String,
    pub jti: String,
    pub scopes: BTreeSet<McpScope>,
    /// 只能看到和操作这一个网络；`None` 表示不限。
    pub network: Option<NetworkId>,
}

impl McpGrant {
    /// 操作记录里写的"是谁做的"。
    #[must_use]
    pub fn actor(&self) -> LogActor {
        LogActor { kind: ActorKind::Mcp, name: self.name.clone(), jti: self.jti.clone() }
    }
}

/// 一个 MCP 令牌为什么不算数。给日志看的；应答里不分这么细。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum McpRefusal {
    #[error("不是一个 JWT")]
    Malformed,
    #[error("签名不对")]
    BadSignature,
    #[error("不是这个 controller 签的")]
    WrongIssuer,
    #[error("不是签给 MCP 端点的")]
    WrongAudience,
    #[error("已经过期")]
    Expired,
    #[error("没有签过这个令牌的记录")]
    Unlisted,
    #[error("已经被撤销")]
    Revoked,
}

/// 内存里记着的一个签过的令牌。
#[derive(Debug, Clone, Copy)]
struct Listed {
    network: Option<NetworkId>,
    expires_at: Timestamp,
    revoked: bool,
}

/// 签名的密钥，和内存里的那一份令牌记录。每次 MCP 调用都要用它，所以不放在 controller 的大锁里。
pub(crate) struct McpAuth {
    key: NodeKey,
    /// JWT 里的 `iss`。
    issuer: String,
    /// 按 `jti` 记着的签过的令牌。过期了的不在里面（后台清掉）。
    listed: Mutex<BTreeMap<String, Listed>>,
}

/// JWT 里的 `iss`：签它的 controller，按 controller 的公钥认。两个 controller 就算用了同一把签名密钥，签的也互不相认。
fn issuer(controller: &PublicKey) -> String {
    format!("i3t-controller:{controller}")
}

/// JWT 里的 `aud`：MCP 端点的路径。
fn audience() -> String {
    format!("{API_PREFIX}{MCP_PATH}")
}

impl McpAuth {
    /// `key` 是签名的密钥，`controller` 是 controller 自己的公钥。内存里的那一份照 `store` 里的建。
    pub(crate) fn load(store: &Store, key: NodeKey, controller: &PublicKey) -> Result<Self, StoreError> {
        let auth = Self { key, issuer: issuer(controller), listed: Mutex::default() };
        auth.reload(store)?;
        Ok(auth)
    }

    fn listed(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Listed>> {
        self.listed.lock().expect("mcp token mutex poisoned")
    }

    /// 照数据库里的重新建内存里的那一份。
    pub(crate) fn reload(&self, store: &Store) -> Result<(), StoreError> {
        let tokens = store.mcp_tokens()?;
        *self.listed() = tokens.iter().map(|token| (token.jti.clone(), listed(token))).collect();
        Ok(())
    }

    /// 网络删掉了：只限它的令牌跟着没有了。
    pub(crate) fn forget_network(&self, network: NetworkId) {
        self.listed().retain(|_, token| token.network != Some(network));
    }

    /// 过期了的不用再记着：JWT 自己写着过期时间，验证时先看它。
    pub(crate) fn forget_expired(&self, now: Timestamp) {
        self.listed().retain(|_, token| token.expires_at > now);
    }

    /// 签一个 JWT。
    fn sign(&self, claims: &Claims) -> Result<String, Error> {
        let payload = serde_json::to_vec(claims)?;
        let mut token = format!("{}.{}", URL_SAFE_NO_PAD.encode(JWT_HEADER), URL_SAFE_NO_PAD.encode(payload));
        let signature = self.key.sign_raw(token.as_bytes());
        token.push('.');
        token.push_str(&URL_SAFE_NO_PAD.encode(signature.as_bytes()));
        Ok(token)
    }

    /// 验一个 JWT。先验签名，再读里面的内容：签名不对的东西不去解析。头里写的算法不看。
    fn verify(&self, token: &str, now: Timestamp) -> Result<McpGrant, McpRefusal> {
        if token.len() > MAX_JWT_LEN {
            return Err(McpRefusal::Malformed);
        }
        let (signed, signature) = token.rsplit_once('.').ok_or(McpRefusal::Malformed)?;
        let (_header, payload) = signed.split_once('.').ok_or(McpRefusal::Malformed)?;
        let signature = URL_SAFE_NO_PAD.decode(signature).ok().and_then(|bytes| <[u8; Signature::LEN]>::try_from(bytes).ok());
        let signature = Signature::from_bytes(signature.ok_or(McpRefusal::Malformed)?);
        verify_raw(&self.key.public(), signed.as_bytes(), &signature).map_err(|_| McpRefusal::BadSignature)?;
        let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|_| McpRefusal::Malformed)?;
        let claims: Claims = serde_json::from_slice(&payload).map_err(|_| McpRefusal::Malformed)?;
        if claims.iss != self.issuer {
            return Err(McpRefusal::WrongIssuer);
        }
        if claims.aud != audience() {
            return Err(McpRefusal::WrongAudience);
        }
        if claims.exp <= now {
            return Err(McpRefusal::Expired);
        }
        match self.listed().get(&claims.jti) {
            None => return Err(McpRefusal::Unlisted),
            Some(listed) if listed.revoked => return Err(McpRefusal::Revoked),
            Some(_) => {}
        }
        // 认不出的权限（更新的版本签的、之后又退回了旧版本）当它没有。
        let scopes = claims.scope.split(' ').filter_map(|scope| scope.parse().ok()).collect();
        Ok(McpGrant { name: claims.sub, jti: claims.jti, scopes, network: claims.network })
    }
}

fn listed(token: &McpTokenInfo) -> Listed {
    Listed { network: token.network, expires_at: token.expires_at, revoked: token.revoked_at.is_some() }
}

/// 一个新的 `jti`。
fn new_jti() -> Result<String, Error> {
    let mut bytes = [0; JTI_BYTES];
    SystemRandom::new().fill(&mut bytes).map_err(|_| Error::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// 请求里的权限，规整过的：去掉重复，按 [`McpScope::ALL`] 的顺序。
fn checked_scopes(request: &CreateMcpToken) -> Result<Vec<McpScope>, Error> {
    if request.scopes.is_empty() {
        return Err(Error::invalid_field("scopes", "empty", "至少要给一项权限"));
    }
    if request.scopes.contains(&McpScope::Unknown) {
        return Err(Error::invalid_field("scopes", "malformed", "有这个 controller 不认识的权限"));
    }
    if request.network.is_some()
        && let Some(global) = request.scopes.iter().find(|scope| scope.is_global())
    {
        let message = format!("{global} 管的是整个 controller 的事，不能签给只限一个网络的令牌");
        return Err(Error::invalid_field("scopes", "not_allowed", message));
    }
    Ok(McpScope::ALL.into_iter().filter(|scope| request.scopes.contains(scope)).collect())
}

impl Controller {
    /// 签发一个 MCP 令牌。返回的 JWT 只有这一次能拿到。
    ///
    /// # Errors
    ///
    /// 名字不合法，没有给权限或者给了不认识的，只限一个网络的令牌带了管整个 controller 的权限，没有这个网络，
    /// 过期时间不在 1 秒到 [`MAX_LIFETIME_SECS`] 之间，或者写存储失败。
    pub fn create_mcp_token(&self, request: &CreateMcpToken) -> Result<CreatedMcpToken, Error> {
        let name = naming::title("MCP 令牌", &request.name, true).map_err(|error| error.in_field("name"))?;
        let scopes = checked_scopes(request)?;
        if !(1..=MAX_LIFETIME_SECS).contains(&request.expires_in_secs) {
            let message = format!("过期时间必须写，最长 {} 天", MAX_LIFETIME_SECS / (24 * 60 * 60));
            return Err(Error::invalid_field("expires_in_secs", "out_of_range", message));
        }
        let jti = new_jti()?;
        let mut inner = self.lock();
        let now = inner.clock.now();
        let new = NewMcpToken { jti, name, scopes, network: request.network, created_at: now, expires_at: now + request.expires_in_secs };
        let info = inner.store.atomically(|store| {
            let network =
                new.network.map(|id| store.network(id)?.ok_or(Error::NotFound(Entity::Network).in_field("network"))).transpose()?;
            let id = store.insert_mcp_token(&new)?;
            let info = store.mcp_token(id)?.ok_or(Error::NotFound(Entity::McpToken))?;
            let params = json!({
                "token": id,
                "name": info.name,
                "jti": info.jti,
                "scopes": info.scopes,
                "network": info.network,
                "network_name": network.as_ref().map(|network| &network.name),
                "expires_at": info.expires_at,
            });
            let detail = format!("签发 MCP 令牌 #{id}（{}）", info.name);
            store.log(now, info.network, action::MCP_TOKEN_CREATE, &detail, params)?;
            Ok::<_, Error>(info)
        })?;
        let claims = Claims {
            iss: self.mcp.issuer.clone(),
            aud: audience(),
            sub: info.name.clone(),
            jti: info.jti.clone(),
            iat: info.created_at,
            exp: info.expires_at,
            scope: info.scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>().join(" "),
            network: info.network,
        };
        let token = self.mcp.sign(&claims)?;
        self.mcp.listed().insert(info.jti.clone(), listed(&info));
        tracing::info!(token = info.id, name = %info.name, jti = %info.jti, "签发 MCP 令牌");
        Ok(CreatedMcpToken { info, token })
    }

    /// 签过的 MCP 令牌，按编号排：还能用的、过期的、撤销的（过期 30 天之后清掉）。
    ///
    /// # Errors
    ///
    /// 读存储失败。
    pub fn mcp_tokens(&self) -> Result<Vec<McpTokenInfo>, Error> {
        let inner = self.lock();
        let now = inner.clock.now();
        Ok(inner.store.mcp_tokens()?.into_iter().map(|token| mcp_token_at(token, now)).collect())
    }

    /// 撤销一个 MCP 令牌：它的下一次调用就被拒绝。已经撤销的再撤销一次什么也不做。
    ///
    /// # Errors
    ///
    /// 没有这个令牌，或者写存储失败。提交的结果不明（数据库在那一刻断了）时也报错，但内存里已经按撤销算：
    /// 撤销宁可多算，不可少算。
    pub fn revoke_mcp_token(&self, id: u32) -> Result<McpTokenInfo, Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let mut jti = None;
        let outcome = inner.store.atomically(|store| {
            let token = store.mcp_token(id)?.ok_or(Error::NotFound(Entity::McpToken))?;
            jti = Some(token.jti.clone());
            if store.revoke_mcp_token(id, now)? {
                let params = json!({ "token": id, "name": token.name, "jti": token.jti });
                let detail = format!("撤销 MCP 令牌 #{id}（{}）", token.name);
                store.log(now, token.network, action::MCP_TOKEN_REVOKE, &detail, params)?;
                tracing::info!(token = id, name = %token.name, jti = %token.jti, "撤销 MCP 令牌");
            }
            store.mcp_token(id)?.ok_or(Error::NotFound(Entity::McpToken))
        });
        let settled = !matches!(outcome, Err(Error::Store(StoreError::CommitUnknown(_))));
        if let Some(jti) = jti.filter(|_| outcome.is_ok() || !settled)
            && let Some(listed) = self.mcp.listed().get_mut(&jti)
        {
            listed.revoked = true;
        }
        outcome.map(|token| mcp_token_at(token, now))
    }

    /// 验一个 MCP 令牌。不查库，也不拿 controller 的锁。
    ///
    /// # Errors
    ///
    /// 它不算数的原因。
    pub fn mcp_grant(&self, token: &str) -> Result<McpGrant, McpRefusal> {
        self.mcp.verify(token, self.clock.now())
    }
}

impl Inner {
    /// 清掉过期很久的 MCP 令牌，内存里过期了的也不再记着。
    pub(crate) fn purge_mcp_tokens(&mut self, now: Timestamp) -> Result<(), Error> {
        self.mcp.forget_expired(now);
        self.store.purge_expired_mcp_tokens(now)?;
        Ok(())
    }
}

/// 数据目录里签 MCP 令牌的密钥，没有就生成一把。库里的令牌要是另一把密钥签的（密钥换了、恢复时没有带回来），
/// 它们都验不过了：全部标成撤销，记一条操作，再记下现在这一把。
///
/// 和 controller 自己的密钥不一样，这一把丢了不用拦着启动：重新签发令牌就行。
pub(super) fn bound_mcp_key(store: &mut Store, path: &Path, now: Timestamp) -> Result<NodeKey, Error> {
    let key = match read_key(path)? {
        Some(key) => key,
        None => create_key(path, "生成了签 MCP 令牌的密钥")?,
    };
    let public = key.public();
    store.atomically(|store| {
        if store.meta(MCP_KEY_META)?.as_deref() == Some(public.as_bytes().as_slice()) {
            return Ok(());
        }
        let revoked = store.revoke_all_mcp_tokens(now)?;
        store.set_meta(MCP_KEY_META, public.as_bytes())?;
        if revoked > 0 {
            tracing::warn!(revoked, path = %path.display(), "签 MCP 令牌的密钥和签发已有令牌时的不是同一把：这些令牌全部作废，需要重新签发");
            let detail = format!("签 MCP 令牌的密钥换了，原来签的 {revoked} 个令牌全部作废");
            store.log(now, None, action::MCP_KEY_ROTATE, &detail, json!({ "revoked": revoked }))?;
        }
        Ok::<_, Error>(())
    })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use ring::hmac;

    use super::super::testing::Lab;
    use super::*;

    const HOUR: u64 = 60 * 60;

    fn encode(part: impl AsRef<[u8]>) -> String {
        URL_SAFE_NO_PAD.encode(part)
    }

    /// 一个签了 JWT 的 controller，和 JWT 的三段。
    fn issued() -> (Lab, String, [String; 3]) {
        let lab = Lab::new();
        let request = CreateMcpToken { name: "claude-code".to_owned(), scopes: vec![McpScope::Read], network: None, expires_in_secs: HOUR };
        let token = lab.controller.create_mcp_token(&request).unwrap().token;
        let parts: Vec<&str> = token.split('.').collect();
        let parts = [parts[0].to_owned(), parts[1].to_owned(), parts[2].to_owned()];
        (lab, token, parts)
    }

    /// 这个 controller 签的、内容是 `change` 改过的 JWT：签名是对的，只有内容不一样。
    fn signed_with(lab: &Lab, token: &str, change: impl FnOnce(&mut Claims)) -> String {
        let payload = token.split('.').nth(1).unwrap();
        let mut claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        change(&mut claims);
        lab.controller.mcp.sign(&claims).unwrap()
    }

    #[test]
    fn a_jwt_is_three_base64url_parts_with_a_fixed_header_and_the_claims_the_endpoint_checks() {
        let (lab, token, [header, payload, signature]) = issued();
        assert_eq!(URL_SAFE_NO_PAD.decode(header).unwrap(), br#"{"alg":"EdDSA","typ":"JWT"}"#);
        assert_eq!(URL_SAFE_NO_PAD.decode(signature).unwrap().len(), Signature::LEN);
        let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        let listed = lab.controller.mcp_tokens().unwrap().remove(0);
        assert_eq!(
            claims,
            json!({
                "iss": format!("i3t-controller:{}", lab.controller.public_key()),
                "aud": "/api/v1/mcp",
                "sub": "claude-code",
                "jti": listed.jti,
                "iat": listed.created_at,
                "exp": listed.created_at + HOUR,
                "scope": "read",
            })
        );
        assert!(token.len() < MAX_JWT_LEN / 2);

        // 名字最长、权限全给、限了网络的 JWT 也远不到长度的上限。
        let network = lab.network("home").id;
        let scopes = McpScope::ALL.into_iter().filter(|scope| !scope.is_global()).collect();
        let longest = CreateMcpToken { name: "名".repeat(64), scopes, network: Some(network), expires_in_secs: MAX_LIFETIME_SECS };
        let longest = lab.controller.create_mcp_token(&longest).unwrap().token;
        assert!(longest.len() < MAX_JWT_LEN, "{}", longest.len());
        assert_eq!(lab.controller.mcp_grant(&longest).unwrap().network, Some(network));
    }

    #[test]
    fn what_is_not_a_jwt_signed_with_the_mcp_key_is_refused_whatever_its_header_says() {
        let (lab, token, [header, payload, signature]) = issued();
        let refused = |token: &str| lab.controller.mcp_grant(token).unwrap_err();
        assert_eq!(lab.controller.mcp_grant(&token).unwrap().name, "claude-code");

        for garbage in ["", "abc", "a.b", "a.b.c", "....", &"x".repeat(MAX_JWT_LEN + 1)] {
            assert_eq!(refused(garbage), McpRefusal::Malformed, "{garbage:.20}");
        }
        assert_eq!(refused(&format!("{token}.extra")), McpRefusal::Malformed, "四段");
        // 管理令牌不是 MCP 令牌。
        assert_eq!(refused(&lab.controller.issue_admin_token().unwrap()), McpRefusal::Malformed);

        // 改了内容（给自己加权限），签名还是原来的。
        let mut claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&payload).unwrap()).unwrap();
        claims["scope"] = json!("read networks:write");
        let escalated = encode(claims.to_string());
        assert_eq!(refused(&format!("{header}.{escalated}.{signature}")), McpRefusal::BadSignature);

        // `alg: none`：不带签名，或者带着原来的签名。
        let none = encode(r#"{"alg":"none","typ":"JWT"}"#);
        assert_eq!(refused(&format!("{none}.{payload}.")), McpRefusal::Malformed);
        assert_eq!(refused(&format!("{none}.{escalated}.")), McpRefusal::Malformed);
        assert_eq!(refused(&format!("{none}.{payload}.{signature}")), McpRefusal::BadSignature);

        // 换成 HMAC，拿公钥当密钥：公钥谁都算得出来（`iss` 里就有 controller 的，签名密钥的也不当秘密）。
        let public = lab.controller.mcp.key.public();
        for (alg, algorithm) in [("HS256", hmac::HMAC_SHA256), ("HS512", hmac::HMAC_SHA512)] {
            let header = encode(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#));
            let signed = format!("{header}.{escalated}");
            let mac = hmac::sign(&hmac::Key::new(algorithm, public.as_bytes()), signed.as_bytes());
            let forged = refused(&format!("{signed}.{}", encode(mac.as_ref())));
            // HS256 的 MAC 是 32 字节，连 Ed25519 签名的长度都不对；HS512 的长度对，验不过。
            assert!(matches!(forged, McpRefusal::Malformed | McpRefusal::BadSignature), "{alg}: {forged:?}");
        }
        let header = encode(r#"{"alg":"HS512","typ":"JWT"}"#);
        let signed = format!("{header}.{payload}");
        let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, public.as_bytes()), signed.as_bytes());
        assert_eq!(refused(&format!("{signed}.{}", encode(mac.as_ref()))), McpRefusal::BadSignature);

        // 头里写什么都不看：签名对的照样认。
        let odd_header = encode(r#"{"alg":"HS256"}"#);
        let signed = format!("{odd_header}.{payload}");
        let resigned = format!("{signed}.{}", encode(lab.controller.mcp.key.sign_raw(signed.as_bytes()).as_bytes()));
        assert_eq!(lab.controller.mcp_grant(&resigned).unwrap().name, "claude-code");

        // 另一把密钥签的。
        let other = NodeKey::generate().unwrap();
        let signed = format!("{header}.{payload}");
        let foreign = format!("{signed}.{}", encode(other.sign_raw(signed.as_bytes()).as_bytes()));
        assert_eq!(refused(&foreign), McpRefusal::BadSignature);
        // controller 自己的密钥也不行：签 MCP 令牌的是另外一把。
        let another = Lab::new();
        assert_eq!(another.controller.mcp_grant(&token).unwrap_err(), McpRefusal::BadSignature);
    }

    #[test]
    fn a_rightly_signed_jwt_must_also_name_this_controller_its_mcp_endpoint_and_a_listed_unexpired_token() {
        let (lab, token, _) = issued();
        let refused = |change: fn(&mut Claims)| lab.controller.mcp_grant(&signed_with(&lab, &token, change)).unwrap_err();
        assert_eq!(lab.controller.mcp_grant(&signed_with(&lab, &token, |_| {})).unwrap().name, "claude-code", "不改就认");

        assert_eq!(refused(|claims| claims.aud = "/api/v1".to_owned()), McpRefusal::WrongAudience);
        assert_eq!(refused(|claims| claims.aud = "https://other.example.com/api/v1/mcp".to_owned()), McpRefusal::WrongAudience);
        assert_eq!(refused(|claims| claims.iss = "i3t-controller:someone-else".to_owned()), McpRefusal::WrongIssuer);
        assert_eq!(refused(|claims| claims.exp = claims.iat), McpRefusal::Expired);
        assert_eq!(refused(|claims| claims.jti = "never-issued".to_owned()), McpRefusal::Unlisted);

        // 认不出的权限当它没有，认得的照旧。
        let grant = lab.controller.mcp_grant(&signed_with(&lab, &token, |claims| claims.scope = "read future:scope".to_owned())).unwrap();
        assert_eq!(grant.scopes, BTreeSet::from([McpScope::Read]));
    }
}
