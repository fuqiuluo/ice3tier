//! MCP 令牌：管理员签给 AI Agent（Claude Code、Codex、Cursor 这一类，不是节点上的 `i3t-agent`）的 JWT，和它的权限。
//!
//! controller 自己就是一个 MCP Server，端点在管理 API 的监听上（[`MCP_PATH`]）。Agent 带着 JWT 连上来，能做什么
//! 由 JWT 里的 scope（[`McpScope`]）决定，controller 每次调用都检查。
//!
//! 签发、列出、撤销 JWT 只能用管理令牌做（`…/mcp/tokens`），JWT 自己做不了：不然 Agent 能给自己升权限。
//! JWT 的明文只在签发它的那一次应答里出现（[`CreatedMcpToken`]）；controller 只记它的编号（`jti`）和签给了谁。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::{NetworkId, Timestamp};

/// MCP 端点在管理 API 前缀（[`API_PREFIX`](super::API_PREFIX)）之下的路径。
pub const MCP_PATH: &str = "/mcp";

/// 一个 MCP 令牌最长能用多久：90 天。签发时必须写过期时间，不能比这更长。
pub const MAX_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;

/// 签发时起的名字最长多少个字符。
pub const MAX_NAME_LEN: usize = 64;

/// MCP 令牌的一项权限。JWT 的 `scope` 里是它们的写法（[`McpScope::as_str`]），用空格隔开。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum McpScope {
    /// 只读：状态、网络、节点、overview、路由和路径、出口、访问检查、测试结果、统计、操作记录，以及分组、规则、
    /// 代理（不带密码）、端口转发、节点对的设置。
    #[serde(rename = "read")]
    Read,
    /// 添加节点：建、列、删注册令牌，查一个注册令牌加入了哪个节点。
    #[serde(rename = "nodes:enroll")]
    NodesEnroll,
    /// 改节点、删节点、继任、开关中继和出口。
    #[serde(rename = "nodes:write")]
    NodesWrite,
    /// 分组和成员、访问规则、代理、端口转发、节点对的设置。
    #[serde(rename = "config:write")]
    ConfigWrite,
    /// 发起和取消测试。
    #[serde(rename = "tests:run")]
    TestsRun,
    /// 更新设置、检查更新、强制更新。只能签给不限网络的令牌。
    #[serde(rename = "updates:write")]
    UpdatesWrite,
    /// 建、改、删网络。只能签给不限网络的令牌。
    #[serde(rename = "networks:write")]
    NetworksWrite,
    /// 较新版本 controller 才有的权限。
    #[serde(other)]
    Unknown,
}

impl McpScope {
    /// 现在有的全部权限，按文档里列出的顺序。
    pub const ALL: [Self; 7] =
        [Self::Read, Self::NodesEnroll, Self::NodesWrite, Self::ConfigWrite, Self::TestsRun, Self::UpdatesWrite, Self::NetworksWrite];

    /// 在 JWT、管理 API 和命令行里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::NodesEnroll => "nodes:enroll",
            Self::NodesWrite => "nodes:write",
            Self::ConfigWrite => "config:write",
            Self::TestsRun => "tests:run",
            Self::UpdatesWrite => "updates:write",
            Self::NetworksWrite => "networks:write",
            Self::Unknown => "unknown",
        }
    }

    /// 这项权限管的是不是整个 controller 的事（建删网络、更新设置）。这样的权限不能签给只限一个网络的令牌。
    #[must_use]
    pub const fn is_global(self) -> bool {
        matches!(self, Self::UpdatesWrite | Self::NetworksWrite)
    }
}

impl fmt::Display for McpScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for McpScope {
    type Err = UnknownMcpScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == s).ok_or_else(|| UnknownMcpScope(s.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("没有 {0} 这项权限；有的是 read、nodes:enroll、nodes:write、config:write、tests:run、updates:write、networks:write")]
pub struct UnknownMcpScope(pub String);

/// 一个签出去的 MCP 令牌。里面没有 JWT 本身。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpTokenInfo {
    /// controller 里的编号，撤销时用它。
    pub id: u32,
    /// JWT 的 `jti`。操作记录里靠它认是哪一个令牌做的：名字可以重复，它不会。
    pub jti: String,
    /// 签发时起的名字（JWT 的 `sub`）：给谁用的。
    pub name: String,
    /// 按 [`McpScope::ALL`] 的顺序，没有重复。
    pub scopes: Vec<McpScope>,
    /// 只能看到和操作这一个网络；`null` 表示不限。
    pub network: Option<NetworkId>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    /// 被撤销的时间。
    pub revoked_at: Option<Timestamp>,
    pub state: McpTokenState,
}

/// 一个 MCP 令牌现在的情况。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTokenState {
    /// 还能用。
    Active,
    /// 已经过期。
    Expired,
    /// 被撤销了：管理员撤销的，或者 controller 换了签名密钥（那时原来签的全部作废）。
    Revoked,
    #[serde(other)]
    Unknown,
}

/// 签发一个 MCP 令牌。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMcpToken {
    /// 给谁用的，最长 [`MAX_NAME_LEN`] 个字符。不要求唯一。
    pub name: String,
    /// 至少一项。
    pub scopes: Vec<McpScope>,
    /// 写了就只能看到和操作这一个网络；这时不能带 [`McpScope::is_global`] 的权限。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkId>,
    /// 多少秒之后过期。必须写，1 到 [`MAX_LIFETIME_SECS`]。
    pub expires_in_secs: u64,
}

/// 签发 MCP 令牌的应答。`token` 是 JWT，只在这里出现一次。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedMcpToken {
    #[serde(flatten)]
    pub info: McpTokenInfo,
    pub token: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn scopes_are_written_the_same_way_in_json_on_the_command_line_and_in_a_jwt() {
        for scope in McpScope::ALL {
            assert_eq!(serde_json::to_value(scope).unwrap(), json!(scope.as_str()));
            assert_eq!(scope.as_str().parse::<McpScope>().unwrap(), scope);
            assert_eq!(scope.to_string(), scope.as_str());
        }
        assert_eq!(serde_json::from_value::<McpScope>(json!("nodes:enroll")).unwrap(), McpScope::NodesEnroll);
        assert_eq!(serde_json::from_value::<McpScope>(json!("something:new")).unwrap(), McpScope::Unknown, "新版本才有的权限");
        assert!("unknown".parse::<McpScope>().is_err(), "命令行上不能写出一个不存在的权限");
        assert!("nodes".parse::<McpScope>().is_err());
    }

    #[test]
    fn only_the_scopes_about_the_whole_controller_are_global() {
        let global: Vec<McpScope> = McpScope::ALL.into_iter().filter(|scope| scope.is_global()).collect();
        assert_eq!(global, [McpScope::UpdatesWrite, McpScope::NetworksWrite]);
    }

    #[test]
    fn a_created_token_is_the_info_with_the_jwt_next_to_it() {
        let created = CreatedMcpToken {
            info: McpTokenInfo {
                id: 3,
                jti: "abc".to_owned(),
                name: "claude-code".to_owned(),
                scopes: vec![McpScope::Read, McpScope::NodesEnroll],
                network: Some(NetworkId(1)),
                created_at: 10,
                expires_at: 20,
                revoked_at: None,
                state: McpTokenState::Active,
            },
            token: "a.b.c".to_owned(),
        };
        let value = serde_json::to_value(&created).unwrap();
        assert_eq!(
            value,
            json!({
                "id": 3, "jti": "abc", "name": "claude-code", "scopes": ["read", "nodes:enroll"], "network": 1,
                "created_at": 10, "expires_at": 20, "revoked_at": null, "state": "active", "token": "a.b.c"
            })
        );
        assert_eq!(serde_json::from_value::<CreatedMcpToken>(value).unwrap(), created);
        // 不限网络的请求里可以不写 `network`。
        let request: CreateMcpToken = serde_json::from_value(json!({ "name": "x", "scopes": ["read"], "expires_in_secs": 60 })).unwrap();
        assert_eq!(request.network, None);
        assert!(serde_json::from_value::<CreateMcpToken>(json!({ "name": "x", "scopes": ["read"] })).is_err(), "过期时间必须写");
    }
}
