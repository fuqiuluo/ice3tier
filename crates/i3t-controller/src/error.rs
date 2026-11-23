//! controller 的错误类型。

use std::borrow::Cow;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use i3t_model::admin::{ErrorCode, GroupId, SkipCause, Timestamp};
use i3t_model::control::{RejectCause, ToNode};
use ipnet::Ipv4Net;

use crate::store::StoreError;

/// 管理操作失败的原因。[`Error::code`] 是给程序看的分类，[`Error::what`]、[`Error::field`] 是更具体的一层，
/// `Display` 是给人看的说明。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("没有这个{0}")]
    NotFound(Entity),
    /// 分组不存在。原话写出编号：请求里常常一次引用好几个分组。
    #[error("没有分组 #{0}")]
    NoSuchGroup(GroupId),
    /// 请求不合法。`what` 是哪里不对的代码。
    #[error("{message}")]
    Invalid { what: &'static str, message: String },
    #[error("名字 {0} 已经被占用")]
    NameTaken(String),
    /// 分组的名字被占用（不分大小写）。和 [`Error::NameTaken`] 同一个代码，`what` 是 `group`。
    #[error("分组名 {0} 已经被占用（名字不分大小写）")]
    GroupNameTaken(String),
    #[error("名字 {name} 属于一个刚删除的节点，还在冷却期（到 Unix 时间 {until} 为止），现在不能分给别的节点")]
    NameCoolingDown { name: String, until: Timestamp },
    #[error("虚拟 IP {0} 已经分给了另一个节点")]
    AddressTaken(Ipv4Addr),
    #[error("虚拟 IP {address} 属于一个刚删除的节点，还在冷却期（到 Unix 时间 {until} 为止），现在不能分给别的节点")]
    AddressCoolingDown { address: Ipv4Addr, until: Timestamp },
    #[error("虚拟 IP {address} 不能用：它必须在地址段 {cidr} 里，并且不是网络地址和广播地址")]
    AddressOutOfRange { address: Ipv4Addr, cidr: Ipv4Net },
    #[error("地址段 {cidr} 和网络 {other} 的地址段 {other_cidr} 重叠")]
    RangeOverlaps { cidr: Ipv4Net, other: String, other_cidr: Ipv4Net },
    #[error("地址段 {0} 里没有空闲的地址了")]
    RangeExhausted(Ipv4Net),
    #[error("网络里已经有节点，地址段只能扩大：新的地址段必须包含原来的 {0}")]
    RangeNotSuperset(Ipv4Net),
    #[error("网络 {0} 里还有节点，先删掉节点才能删网络")]
    NetworkNotEmpty(String),
    #[error("节点 {node} 没有声明{capability}。在节点上执行 `{command}` 之后才能启用", command = capability.command())]
    NotDeclared { node: String, capability: Capability },
    #[error("节点 {0} 没有打开\"可以作为端口转发的目标\"。在 controller 上打开：`i3tctl node set {0} --forward-target on`")]
    ForwardTargetOff(String),
    #[error("节点 {0} 还在线。只有已经下线的节点才能被继任")]
    PredecessorOnline(String),
    /// 代理的出口节点没有启用出口。
    #[error("节点 {0} 没有启用出口：先把它启用成出口，或者选别的出口")]
    ExitNotEnabled(String),
    /// 代理的出口是监听的节点自己。
    #[error("出口要是另一个节点：不支持从监听的节点自己出去")]
    ExitIsNode,
    /// 访问规则不让代理的监听节点访问它的出口。
    #[error("访问规则不允许 {node} 访问 {exit}：先加一条让 {node} 能访问 {exit} 的规则")]
    AccessDenied { node: String, exit: String },
    /// 代理的用户名和密码只写了一个。
    #[error("用户名和密码要么都写，要么都不写（不在回环地址上的代理都不写时由 controller 生成一对）")]
    CredentialsIncomplete,
    /// 和已有的配置冲突。`with` 是挡着的东西。
    #[error("{message}")]
    Conflict { with: Entity, message: String },
    #[error("节点 {0} 不在线。让节点立即更新要它连着 controller")]
    NodeOffline(String),
    /// 节点不能自己更新（[`SkipCause::TooOld`] 或 [`SkipCause::CannotSelfUpdate`]）。
    #[error("节点 {node} 不能自己更新：{reason}")]
    CannotSelfUpdate { node: String, reason: String, cause: Box<SkipCause> },
    /// 没有可以让这个节点更新到的版本。
    #[error("{message}")]
    NoUpdate { message: String, cause: Box<SkipCause> },
    /// 同一对节点刚测过，或者全网矩阵刚开始过。
    #[error("{0}")]
    TooSoon(String),
    /// 正在测，或者要取消的已经结束了。
    #[error("{0}")]
    Busy(String),
    #[error("存储出错")]
    Store(#[from] StoreError),
    #[error("netmap 序列化失败")]
    Encode(#[from] serde_json::Error),
    #[error("系统的随机数源不可用")]
    Random,
    #[error("读写 {path} 失败")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("controller 的密钥文件 {path} 读不出来")]
    Key {
        path: PathBuf,
        #[source]
        source: i3t_crypto::KeyError,
    },
    #[error("生成 controller 的密钥失败")]
    KeyGeneration(#[source] i3t_crypto::KeyError),
    #[error("准备 TLS 配置失败")]
    Tls(#[from] i3t_crypto::tls::TlsError),
    #[error("绑定 {address} 失败")]
    Bind {
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("网络端口出错")]
    Socket(#[source] std::io::Error),
    /// 数据目录里的密钥和数据库里记的不是同一把：数据目录和数据库不是同一个 controller 的。
    #[error("{} 不是这个数据库的 controller 的密钥：数据目录和数据库对不上", path.display())]
    KeyMismatch { path: PathBuf },
    /// 数据库里是一个已有的 controller 的数据，数据目录里却没有它的密钥。不生成新的：节点认的是原来那一把。
    #[error("数据库里是一个已有的 controller 的数据，可是没有它的密钥 {}：把备份的密钥放回来", path.display())]
    KeyMissing { path: PathBuf },
    /// 要重新生成管理令牌的目录不是 controller 的数据目录：缺了 `missing` 这个文件。
    #[error("{} 里没有 {missing}，不是 controller 的数据目录", dir.display())]
    NotDataDir { dir: PathBuf, missing: &'static str },
    /// 请求里的 `field` 这一项引起的错误。只是给 [`Error::field`] 带上字段名，别的都和 `error` 一样。
    /// 内部错误不会被这样包起来（见 [`Error::in_field`]），所以不用往下转来由。
    #[error("{error}")]
    InField { field: Cow<'static, str>, error: Box<Error> },
}

impl Error {
    /// 是不是整个数据库都读写不了（见 [`StoreError::is_database_wide`]）。这时别的节点、别的网络也是一样的结果，不用往下试。
    pub(crate) fn is_database_wide(&self) -> bool {
        matches!(self, Self::Store(err) if err.is_database_wide())
    }

    /// 给程序看的分类，管理 API 的应答里用它。
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) | Self::NoSuchGroup(_) => ErrorCode::NotFound,
            Self::Invalid { .. } => ErrorCode::InvalidRequest,
            Self::NameTaken(_) | Self::GroupNameTaken(_) => ErrorCode::NameTaken,
            Self::NameCoolingDown { .. } => ErrorCode::NameCoolingDown,
            Self::AddressTaken(_) => ErrorCode::AddressTaken,
            Self::AddressCoolingDown { .. } => ErrorCode::AddressCoolingDown,
            Self::AddressOutOfRange { .. } => ErrorCode::AddressOutOfRange,
            Self::RangeOverlaps { .. } => ErrorCode::RangeOverlaps,
            Self::RangeExhausted(_) => ErrorCode::RangeExhausted,
            Self::RangeNotSuperset(_) => ErrorCode::RangeNotSuperset,
            Self::NetworkNotEmpty(_) => ErrorCode::NetworkNotEmpty,
            Self::NotDeclared { .. } => ErrorCode::NotDeclared,
            Self::ForwardTargetOff(_) => ErrorCode::ForwardTargetOff,
            Self::PredecessorOnline(_) => ErrorCode::PredecessorOnline,
            Self::ExitNotEnabled(_) => ErrorCode::ExitNotEnabled,
            Self::ExitIsNode => ErrorCode::ExitIsNode,
            Self::AccessDenied { .. } => ErrorCode::AccessDenied,
            Self::CredentialsIncomplete => ErrorCode::CredentialsIncomplete,
            Self::Conflict { .. } => ErrorCode::Conflict,
            Self::NodeOffline(_) => ErrorCode::NodeOffline,
            Self::CannotSelfUpdate { .. } => ErrorCode::CannotSelfUpdate,
            Self::NoUpdate { .. } => ErrorCode::NoUpdate,
            Self::TooSoon(_) => ErrorCode::TooSoon,
            Self::Busy(_) => ErrorCode::Busy,
            Self::Store(_)
            | Self::Encode(_)
            | Self::Random
            | Self::Io { .. }
            | Self::Key { .. }
            | Self::KeyGeneration(_)
            | Self::Tls(_)
            | Self::Bind { .. }
            | Self::Socket(_)
            | Self::KeyMismatch { .. }
            | Self::KeyMissing { .. }
            | Self::NotDataDir { .. } => ErrorCode::Internal,
            Self::InField { error, .. } => error.code(),
        }
    }

    /// 比 [`code`](Self::code) 更具体的一层，管理 API 的错误里的 `what`。说不出来时是 `None`。
    ///
    /// - `not_found`：找不到的东西（[`Entity::code`]）；
    /// - `invalid_request`：哪里不对；
    /// - `conflict`：挡着的东西；
    /// - `cannot_self_update`：节点说的原因（`container` 之类），或者 `too_old`、`unknown`；
    /// - `no_update`：[`SkipCause`] 的代码；
    /// - `not_declared`：没有声明的能力（`relay`、`exit`）；
    /// - `internal`：出错的环节（`store`、`io` 之类）。日志里有细节，应答里只有这一个词。
    #[must_use]
    pub fn what(&self) -> Option<String> {
        let what = match self {
            Self::NotFound(entity) | Self::Conflict { with: entity, .. } => entity.code(),
            Self::NoSuchGroup(_) | Self::GroupNameTaken(_) => Entity::Group.code(),
            Self::Invalid { what, .. } => what,
            Self::CannotSelfUpdate { cause, .. } => match cause.as_ref() {
                SkipCause::CannotSelfUpdate { blocker: Some(blocker) } => return cause_code(blocker),
                SkipCause::CannotSelfUpdate { blocker: None } => "unknown",
                cause => return cause_code(cause),
            },
            Self::NoUpdate { cause, .. } => return cause_code(cause.as_ref()),
            Self::Store(_) => "store",
            Self::Encode(_) => "encode",
            Self::Random => "random",
            Self::Io { .. } => "io",
            Self::Key { .. } | Self::KeyGeneration(_) | Self::KeyMismatch { .. } | Self::KeyMissing { .. } => "key",
            Self::Tls(_) => "tls",
            Self::Bind { .. } | Self::Socket(_) => "socket",
            Self::NotDataDir { .. } => "data_dir",
            Self::InField { error, .. } => return error.what(),
            Self::NotDeclared { capability, .. } => capability.code(),
            Self::NameTaken(_)
            | Self::NameCoolingDown { .. }
            | Self::AddressTaken(_)
            | Self::AddressCoolingDown { .. }
            | Self::AddressOutOfRange { .. }
            | Self::RangeOverlaps { .. }
            | Self::RangeExhausted(_)
            | Self::RangeNotSuperset(_)
            | Self::NetworkNotEmpty(_)
            | Self::ForwardTargetOff(_)
            | Self::PredecessorOnline(_)
            | Self::ExitNotEnabled(_)
            | Self::ExitIsNode
            | Self::AccessDenied { .. }
            | Self::CredentialsIncomplete
            | Self::NodeOffline(_)
            | Self::TooSoon(_)
            | Self::Busy(_) => return None,
        };
        Some(what.to_owned())
    }

    /// 请求里引起这个错误的字段，管理 API 的错误里的 `field`。
    #[must_use]
    pub fn field(&self) -> Option<&str> {
        match self {
            Self::InField { field, .. } => Some(field),
            _ => None,
        }
    }

    /// 标上这个错误是请求里的哪一项引起的。已经标过的不再改：最里面的那一层最清楚。
    /// 内部错误不标：那不是请求的问题，而且它的来由要原样留给日志。
    #[must_use]
    pub fn in_field(self, field: &'static str) -> Self {
        self.marked(Cow::Borrowed(field))
    }

    /// 标上这个错误是请求里的编号列表 `field` 的第 `index` 项（从 0 数）引起的：`field` 写成 `groups[1]`。
    #[must_use]
    pub fn in_item(self, field: &'static str, index: usize) -> Self {
        self.marked(Cow::Owned(format!("{field}[{index}]")))
    }

    fn marked(self, field: Cow<'static, str>) -> Self {
        match self {
            Self::InField { .. } => self,
            error if error.code() == ErrorCode::Internal => error,
            error => Self::InField { field, error: Box::new(error) },
        }
    }

    pub(crate) fn invalid(what: &'static str, message: impl Into<String>) -> Self {
        Self::Invalid { what, message: message.into() }
    }

    /// 字段 `field` 不合法。
    pub(crate) fn invalid_field(field: &'static str, what: &'static str, message: impl Into<String>) -> Self {
        Self::invalid(what, message).in_field(field)
    }
}

/// 给 `Result` 用的 [`Error::in_field`]。
pub(crate) trait InField<T> {
    fn in_field(self, field: &'static str) -> Result<T, Error>;
}

impl<T> InField<T> for Result<T, Error> {
    fn in_field(self, field: &'static str) -> Self {
        self.map_err(|error| error.in_field(field))
    }
}

/// 一个带 `code` 的原因在 JSON 里的代码，或者一个单纯的枚举值在 JSON 里的写法。代码只在模型里写一次，这里照着取。
fn cause_code(cause: &impl serde::Serialize) -> Option<String> {
    match serde_json::to_value(cause).ok()? {
        serde_json::Value::String(code) => Some(code),
        serde_json::Value::Object(mut fields) => match fields.remove("code")? {
            serde_json::Value::String(code) => Some(code),
            _ => None,
        },
        _ => None,
    }
}

/// 找不到的是什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entity {
    Network,
    Node,
    Token,
    Rule,
    Proxy,
    Forward,
    PairSetting,
    PausedVersion,
    /// 启用了出口的节点。
    Exit,
    /// 主动测试。
    Test,
    /// 全网矩阵。
    Matrix,
    Group,
}

impl Entity {
    /// 管理 API 的错误里 `what` 的写法。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Node => "node",
            Self::Token => "token",
            Self::Rule => "rule",
            Self::Proxy => "proxy",
            Self::Forward => "forward",
            Self::PairSetting => "pair",
            Self::PausedVersion => "paused_version",
            Self::Exit => "exit",
            Self::Test => "test",
            Self::Matrix => "matrix",
            Self::Group => "group",
        }
    }
}

impl fmt::Display for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Network => "网络",
            Self::Node => "节点",
            Self::Token => "注册令牌",
            Self::Rule => "规则",
            Self::Proxy => "代理",
            Self::Forward => "端口转发",
            Self::PairSetting => "节点对设置",
            Self::PausedVersion => "被暂停的版本",
            Self::Exit => "出口",
            Self::Test => "测试",
            Self::Matrix => "全网矩阵",
            Self::Group => "分组",
        })
    }
}

/// 要节点先在本地声明、管理员才能启用的两种能力。端口转发的目标只要管理员的开关（[`Error::ForwardTargetOff`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Relay,
    Exit,
}

impl Capability {
    /// 管理 API 的错误里 `what` 的写法。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Exit => "exit",
        }
    }

    /// 在节点上声明这项能力要执行的命令。
    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Relay => "i3t set can-relay on",
            Self::Exit => "i3t set can-exit on",
        }
    }
}

/// 写成"可以作为……"的整句，直接接在"节点没有声明"后面。
impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Relay => "可以作为中继",
            Self::Exit => "可以作为出口",
        })
    }
}

/// controller 不接受一个节点的原因。原样放进 `Rejected` 消息发给节点，所以不能带内部细节。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    #[error("注册令牌无效：它不存在、已经用过，或者已经过期")]
    BadToken,
    #[error("这把公钥没有在 controller 上注册。节点可能已经被删除，要重新加入网络")]
    UnknownKey,
    #[error("这把公钥已经注册过了。要重新加入，先在 controller 上删掉原来的节点")]
    KeyAlreadyEnrolled,
    #[error("要继任的节点还在线。等它下线之后再用这个令牌加入")]
    PredecessorOnline,
    #[error("令牌预设的虚拟 IP 现在不能用：{0}")]
    AddressUnavailable(String),
    #[error("网络的地址段里没有空闲的地址了")]
    RangeExhausted,
    #[error("连接上的第一条消息必须是 enroll 或者 hello")]
    UnexpectedFirstMessage,
    #[error("controller 内部出错，稍后再试")]
    Internal,
}

impl Rejection {
    /// 发给节点的回答。controller 自己出的错不是"不认这个节点"：节点收到 `Rejected` 会就此停下、等人重新加入，
    /// 所以这时回 `TryLater`，让它按退避重连。
    #[must_use]
    pub fn reply(&self) -> ToNode {
        let reason = self.to_string();
        let cause = match self {
            Self::Internal => return ToNode::TryLater { reason },
            Self::BadToken => RejectCause::BadToken,
            Self::UnknownKey => RejectCause::UnknownKey,
            Self::KeyAlreadyEnrolled => RejectCause::KeyAlreadyEnrolled,
            Self::PredecessorOnline => RejectCause::PredecessorOnline,
            Self::AddressUnavailable(_) => RejectCause::AddressUnavailable,
            Self::RangeExhausted => RejectCause::RangeExhausted,
            Self::UnexpectedFirstMessage => RejectCause::UnexpectedFirstMessage,
        };
        ToNode::Rejected { reason, cause: Some(cause) }
    }
}

/// 把错误连同它的来源链写成一行，日志里用。
pub(crate) fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push('：');
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_undeclared_capability_names_the_command_to_run_on_the_node() {
        let cases = [(Capability::Exit, "i3t set can-exit on"), (Capability::Relay, "i3t set can-relay on")];
        for (capability, command) in cases {
            let error = Error::NotDeclared { node: "nas-01".to_owned(), capability };
            let message = error.to_string();
            assert!(message.contains("nas-01") && message.contains(command), "{message}");
            assert_eq!(error.code(), ErrorCode::NotDeclared);
            assert_eq!(error.what().as_deref(), Some(capability.code()));
        }
    }

    #[test]
    fn an_error_names_what_was_wrong_and_which_field_caused_it() {
        let missing = Error::NotFound(Entity::Node).in_field("pinned_relays");
        assert_eq!(
            (missing.code(), missing.what().as_deref(), missing.field()),
            (ErrorCode::NotFound, Some("node"), Some("pinned_relays"))
        );
        assert_eq!(missing.to_string(), "没有这个节点", "字段不改原话");
        let zero = Error::invalid_field("ports", "zero", "端口不能是 0").in_field("exit");
        assert_eq!((zero.what().as_deref(), zero.field()), (Some("zero"), Some("ports")), "最里面的字段算数");
        let conflict = Error::Conflict { with: Entity::Proxy, message: "x".into() };
        assert_eq!((conflict.code(), conflict.what().as_deref()), (ErrorCode::Conflict, Some("proxy")));
        let exit = Error::ExitNotEnabled("gw".into()).in_field("exit");
        assert_eq!((exit.code(), exit.what(), exit.field()), (ErrorCode::ExitNotEnabled, None, Some("exit")));
        let blocked = Error::CannotSelfUpdate {
            node: "nas".into(),
            reason: "x".into(),
            cause: Box::new(SkipCause::CannotSelfUpdate { blocker: Some(i3t_model::update::SelfUpdateBlocker::Container) }),
        };
        assert_eq!(blocked.what().as_deref(), Some("container"));
        let too_old = Error::CannotSelfUpdate { node: "nas".into(), reason: "x".into(), cause: Box::new(SkipCause::TooOld) };
        assert_eq!(too_old.what().as_deref(), Some("too_old"));
        let none = Error::NoUpdate { message: "x".into(), cause: Box::new(SkipCause::NoRelease) };
        assert_eq!(none.what().as_deref(), Some("no_release"));
        assert_eq!(Error::Random.what().as_deref(), Some("random"));
        assert_eq!(Error::NodeOffline("nas".into()).what(), None);
    }

    #[test]
    fn only_an_internal_error_tells_the_node_to_try_again_later() {
        assert!(matches!(Rejection::Internal.reply(), ToNode::TryLater { reason } if reason.contains("稍后再试")));
        for definite in [Rejection::UnknownKey, Rejection::BadToken, Rejection::KeyAlreadyEnrolled, Rejection::RangeExhausted] {
            assert!(matches!(definite.reply(), ToNode::Rejected { cause: Some(_), .. }), "{definite:?}");
        }
        assert!(matches!(Rejection::BadToken.reply(), ToNode::Rejected { cause: Some(RejectCause::BadToken), .. }));
    }
}
