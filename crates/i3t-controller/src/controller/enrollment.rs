//! 注册令牌，和节点拿着令牌加入网络。

use std::net::{IpAddr, Ipv4Addr};

use i3t_model::admin::{CreateEnrollToken, CreatedEnrollToken, EnrollTokenInfo, LogRef, NetworkId, RefKind, Timestamp, action};
use i3t_model::control::{EnrollToken, Hello, ToNode};
use i3t_proto::{NodeId, PublicKey};
use serde_json::json;
use tokio::sync::mpsc;

use super::groups::resolve_groups;
use super::nodes::{allocate_address, check_address, check_node_name, inherit, require_node};
use super::protocol::{Joined, clip};
use super::{Admitted, Controller, Inner, naming};
use crate::error::{Entity, Error, InField, Rejection, error_chain};
use crate::secret;
use crate::store::{DIGEST_LEN, NewNode, NewToken, NodeRecord, Store, TokenRecord, is_pending, token_at};

/// 注册令牌默认一天之后过期。
const DEFAULT_TOKEN_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// 注册失败的原因：向节点返回的拒绝原因，或 controller 内部错误。
enum EnrollFailure {
    Rejected(Rejection),
    Internal(Error),
}

impl<E: Into<Error>> From<E> for EnrollFailure {
    fn from(error: E) -> Self {
        Self::Internal(error.into())
    }
}

impl Controller {
    /// 一个网络里还没被用掉、也没过期的注册令牌；`all` 时还有用掉的和过期的（留 30 天）。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn tokens(&self, network: NetworkId, all: bool) -> Result<Vec<EnrollTokenInfo>, Error> {
        let inner = self.lock();
        inner.require_network(network)?;
        let now = inner.clock.now();
        let tokens = inner.store.tokens(network)?.into_iter().filter(|token| all || is_pending(token, now));
        Ok(tokens.map(|token| token_at(token, now)).collect())
    }

    /// 生成一个注册令牌。返回的令牌文本只有这一次能拿到。
    ///
    /// # Errors
    ///
    /// 分组不是这个网络里已有的分组（`field` 是 `groups[序号]`）；预设的虚拟 IP 现在不能用；要继任的节点不在这个网络里。
    pub fn create_token(&self, network: NetworkId, request: &CreateEnrollToken) -> Result<CreatedEnrollToken, Error> {
        if request.successor_of.is_some() && request.virtual_ip.is_some() {
            return Err(Error::invalid_field("virtual_ip", "with_successor", "继任的节点继承原节点的虚拟 IP，不能同时预设另一个"));
        }
        let secret = secret::generate()?;
        let token = EnrollToken { secret: secret.clone(), controller: self.public_addr.clone(), key: self.public_key() }.to_string();
        let prefix: String = token.chars().take(EnrollToken::VISIBLE_PREFIX_LEN).collect();
        let mut inner = self.lock();
        let network = inner.require_network(network)?;
        let now = inner.clock.now();
        let info = inner.store.atomically(|store| {
            let groups = resolve_groups(store, network.id, &request.groups, "groups")?;
            if let Some(virtual_ip) = request.virtual_ip {
                check_address(store, &network, virtual_ip, now).in_field("virtual_ip")?;
                if store.tokens(network.id)?.iter().any(|token| is_pending(token, now) && token.virtual_ip == Some(virtual_ip)) {
                    return Err(Error::Conflict {
                        with: Entity::Token,
                        message: format!("虚拟 IP {virtual_ip} 已预设在另一个未使用的注册令牌上"),
                    }
                    .in_field("virtual_ip"));
                }
            }
            if let Some(predecessor) = request.successor_of {
                require_node(store, network.id, predecessor).in_field("successor_of")?;
            }
            let new = NewToken {
                network: network.id,
                secret_hash: secret::sha256(secret.as_bytes()),
                prefix: prefix.clone(),
                created_at: now,
                expires_at: now.saturating_add(request.expires_in_secs.unwrap_or(DEFAULT_TOKEN_LIFETIME_SECS)),
                groups,
                virtual_ip: request.virtual_ip,
                successor_of: request.successor_of,
            };
            let id = store.insert_token(&new)?;
            let info = store.token(id)?.ok_or(Error::NotFound(Entity::Token))?;
            let groups: Vec<_> = info.groups.iter().map(|group| json!({ "group": group.id, "group_name": group.name })).collect();
            store.log_refs(
                now,
                Some(network.id),
                action::TOKEN_CREATE,
                &format!("生成注册令牌 #{id}（{prefix}…）"),
                &[LogRef::new(RefKind::Token, id)],
                json!({
                    "token": id,
                    "prefix": prefix,
                    "expires_at": new.expires_at,
                    "groups": groups,
                    "virtual_ip": new.virtual_ip,
                    "successor_of": new.successor_of,
                }),
            )?;
            Ok::<_, Error>(info)
        })?;
        Ok(CreatedEnrollToken { info, token })
    }

    /// 收回一个还没用掉的注册令牌。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个令牌。
    pub fn delete_token(&self, network: NetworkId, id: u32) -> Result<(), Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        inner.store.atomically(|store| {
            let token = store.token(id)?.filter(|token| token.network == network).ok_or(Error::NotFound(Entity::Token))?;
            store.delete_token(id)?;
            let params = json!({ "token": id, "prefix": token.prefix });
            store.log_refs(
                now,
                Some(network),
                action::TOKEN_DELETE,
                &format!("收回注册令牌 #{id}"),
                &[LogRef::new(RefKind::Token, id)],
                params,
            )?;
            Ok(())
        })
    }

    /// 节点拿着注册令牌里的一次性密钥加入网络。`key` 是它在 TLS 握手里证明过的公钥。
    ///
    /// 成功时节点已经登记为在线，它的第一份 netmap 已经在 `outbox` 里。
    ///
    /// # Errors
    ///
    /// 令牌无效，或该公钥、令牌预设的配置当前不可用。失败原因可直接返回给节点。
    pub fn enroll(
        &self,
        key: PublicKey,
        secret: &str,
        hello: &Hello,
        remote: IpAddr,
        outbox: mpsc::Sender<ToNode>,
    ) -> Result<Admitted, Rejection> {
        let mut inner = self.lock();
        let outcome = inner.enroll(key, secret, hello, remote, outbox);
        self.wake_if_needed(&inner);
        outcome.map_err(|failure| match failure {
            EnrollFailure::Rejected(rejection) => {
                if let Some(suppressed) = self.refusal_log.allow() {
                    tracing::warn!(key = ?key, %remote, reason = %rejection, suppressed, "拒绝注册");
                }
                rejection
            }
            EnrollFailure::Internal(err) => {
                tracing::error!(key = ?key, %remote, "处理注册请求时出错：{}", error_chain(&err));
                Rejection::Internal
            }
        })
    }
}

impl Inner {
    fn enroll(
        &mut self,
        key: PublicKey,
        secret: &str,
        hello: &Hello,
        remote: IpAddr,
        outbox: mpsc::Sender<ToNode>,
    ) -> Result<Admitted, EnrollFailure> {
        let secret_hash = secret::sha256(secret.as_bytes());
        let now = self.clock.now();
        if let Some(existing) = self.store.node_by_key(&key)? {
            // 上一次注册其实成功了，只是回答没送到：节点拿着同一个令牌重试，当作它来报到。
            return if existing.enrolled_with == Some(secret_hash) {
                Ok(self.admit(existing, Joined { hello, remote, outbox, enrolling: true })?)
            } else {
                Err(EnrollFailure::Rejected(Rejection::KeyAlreadyEnrolled))
            };
        }
        let token = self.store.token_by_hash(&secret_hash)?.filter(|token| token.expires_at > now);
        let token = token.ok_or(EnrollFailure::Rejected(Rejection::BadToken))?;
        if token.successor_of.is_some_and(|predecessor| self.is_online(predecessor)) {
            return Err(EnrollFailure::Rejected(Rejection::PredecessorOnline));
        }

        let (node, predecessor) = self.store.atomically(|store| create_node(store, &token, key, secret_hash, hello, now))?;
        tracing::info!(node = %node.id, name = %node.name, network = %node.network, virtual_ip = %node.virtual_ip, ?predecessor, "节点注册");
        if let Some(predecessor) = predecessor {
            self.forget_node(predecessor);
        }
        Ok(self.admit(node, Joined { hello, remote, outbox, enrolling: true })?)
    }
}

/// 重名时最多试到几号。再多说明这个主机名本身没有区分度，不如叫 `node-<编号>`。
const MAX_NAME_SUFFIX: u32 = 99;

/// 按节点上报的主机名给新节点起名字：主机名本身，被占用（或者在冷却期）时加 `-2`、`-3`……
/// 主机名无法提取出合法名称或序号已用尽时返回 `None`，节点将命名为 `node-<编号>`。
fn name_after_hostname(store: &Store, network: NetworkId, hostname: &str, now: Timestamp) -> Result<Option<String>, Error> {
    let Some(base) = naming::from_hostname(hostname).filter(|base| !naming::is_default_node_name(base)) else { return Ok(None) };
    let candidates = std::iter::once(base.clone()).chain((2..=MAX_NAME_SUFFIX).map(|index| format!("{base}-{index}")));
    for candidate in candidates.filter(|candidate| !naming::is_default_node_name(candidate)) {
        match check_node_name(store, network, &candidate, now) {
            Ok(()) => return Ok(Some(candidate)),
            Err(Error::NameTaken(_) | Error::NameCoolingDown { .. }) => {}
            Err(other) => return Err(other),
        }
    }
    Ok(None)
}

/// 用掉令牌，建出节点。它加入令牌预设的分组。令牌指名继任时，新节点接手原节点的名字、虚拟 IP、所在的分组和指向它的配置，
/// 原节点被删掉。
fn create_node(
    store: &Store,
    token: &TokenRecord,
    key: PublicKey,
    secret_hash: [u8; DIGEST_LEN],
    hello: &Hello,
    now: Timestamp,
) -> Result<(NodeRecord, Option<NodeId>), EnrollFailure> {
    let network = store.network(token.network)?.ok_or(Error::NotFound(Entity::Network))?;
    let predecessor = token.successor_of.map(|id| require_node(store, network.id, id)).transpose()?;
    let mut new = NewNode {
        network: network.id,
        key,
        name: None,
        virtual_ip: Ipv4Addr::UNSPECIFIED,
        groups: token.groups.iter().map(|group| group.id).collect(),
        declared: hello.declared,
        platform: clip(&hello.platform),
        version: clip(&hello.version),
        created_at: now,
        enrolled_with: Some(secret_hash),
    };
    // 令牌先标成用掉：它预设的虚拟 IP 在分配时算作"被令牌占着"，不标就轮不到自己用。
    store.consume_token(token.id, now)?;
    if let Some(old) = &predecessor {
        store.park_node(old.id)?;
        new.name = Some(old.name.clone());
        new.virtual_ip = old.virtual_ip;
    } else {
        new.name = name_after_hostname(store, network.id, &hello.hostname, now)?;
        new.virtual_ip = match token.virtual_ip {
            Some(preset) => {
                check_address(store, &network, preset, now)
                    .map_err(|err| EnrollFailure::Rejected(Rejection::AddressUnavailable(err.to_string())))?;
                preset
            }
            None => allocate_address(store, &network, now).map_err(|err| match err {
                Error::RangeExhausted(_) => EnrollFailure::Rejected(Rejection::RangeExhausted),
                other => EnrollFailure::Internal(other),
            })?,
        };
    }
    let id = store.insert_node(&new)?;
    store.set_token_user(token.id, id)?;
    let node = store.node(id)?.ok_or(Error::NotFound(Entity::Node))?;
    let detail = match &predecessor {
        Some(old) => {
            inherit(store, network.id, old, &node)?;
            format!("节点 {}（{}）用令牌 #{} 加入，继任原来的节点 #{}", node.name, node.virtual_ip, token.id, old.id)
        }
        None => format!("节点 {}（{}）用令牌 #{} 加入", node.name, node.virtual_ip, token.id),
    };
    // 继任时接手了原节点所在的分组，重新读一遍。
    let node = store.node(id)?.ok_or(Error::NotFound(Entity::Node))?;
    let params = json!({
        "node": node.id,
        "node_name": node.name,
        "virtual_ip": node.virtual_ip,
        "token": token.id,
        "predecessor": predecessor.as_ref().map(|old| old.id),
        "predecessor_name": predecessor.as_ref().map(|old| &old.name),
    });
    store.log_refs(
        now,
        Some(network.id),
        action::NODE_ENROLL,
        &detail,
        &[LogRef::node(id), LogRef::new(RefKind::Token, token.id)],
        params,
    )?;
    Ok((node, predecessor.map(|old| old.id)))
}
