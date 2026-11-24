//! 操作记录里的操作名（[`LogEntry::action`](super::LogEntry::action)）：controller 记的时候写它，`i3tctl` 照它把记录写成一句话。
//!
//! 名字已经写进了数据库，也是管理 API 的一部分（`GET /log` 的 `action` 可以按它的前缀筛），不能改。
//! 早期版本记录过、现已不再写入的操作名也保留在此，以便兼容解析历史记录。

/// 生成了新的管理令牌。
pub const ADMIN_TOKEN: &str = "admin.token";

pub const NETWORK_CREATE: &str = "network.create";
pub const NETWORK_UPDATE: &str = "network.update";
pub const NETWORK_DELETE: &str = "network.delete";

pub const NODE_ENROLL: &str = "node.enroll";
pub const NODE_UPDATE: &str = "node.update";
pub const NODE_DELETE: &str = "node.delete";
/// 一个节点接替了另一个（换机器、重装）。
pub const NODE_SUCCEED: &str = "node.succeed";
pub const NODE_RELAY_ENABLE: &str = "node.relay.enable";
pub const NODE_RELAY_DISABLE: &str = "node.relay.disable";
/// 节点不再声明自己能当中继，controller 随之把它关掉。
pub const NODE_RELAY_WITHDRAWN: &str = "node.relay.withdrawn";
pub const NODE_EXIT_ENABLE: &str = "node.exit.enable";
pub const NODE_EXIT_DISABLE: &str = "node.exit.disable";
/// 节点不再声明自己能当出口，controller 随之把它关掉。
pub const NODE_EXIT_WITHDRAWN: &str = "node.exit.withdrawn";

pub const TOKEN_CREATE: &str = "token.create";
pub const TOKEN_DELETE: &str = "token.delete";

pub const RULE_CREATE: &str = "rule.create";
pub const RULE_UPDATE: &str = "rule.update";
pub const RULE_DELETE: &str = "rule.delete";

pub const GROUP_CREATE: &str = "group.create";
pub const GROUP_RENAME: &str = "group.rename";
pub const GROUP_DELETE: &str = "group.delete";
/// 分组里加了、去掉了节点。
pub const GROUP_MEMBERS: &str = "group.members";

pub const PROXY_CREATE: &str = "proxy.create";
pub const PROXY_UPDATE: &str = "proxy.update";
pub const PROXY_DELETE: &str = "proxy.delete";

pub const FORWARD_CREATE: &str = "forward.create";
pub const FORWARD_UPDATE: &str = "forward.update";
pub const FORWARD_DELETE: &str = "forward.delete";

pub const PAIR_SET: &str = "pair.set";
pub const PAIR_DELETE: &str = "pair.delete";

pub const UPDATE_SETTINGS: &str = "update.settings";
/// 发布源上有了新版本。
pub const UPDATE_RELEASE: &str = "update.release";
/// 节点更新到某个版本失败，这个版本的自动更新停了下来。
pub const UPDATE_PAUSE: &str = "update.pause";
/// 节点报告某个版本不能用。
pub const UPDATE_FAILURE: &str = "update.failure";
pub const UPDATE_RESUME: &str = "update.resume";
pub const UPDATE_FORCE: &str = "update.force";
pub const UPDATE_FORCE_ALL: &str = "update.force_all";

pub const TEST_START: &str = "test.start";
pub const TEST_CANCEL: &str = "test.cancel";
pub const TEST_MATRIX: &str = "test.matrix";
pub const TEST_MATRIX_CANCEL: &str = "test.matrix.cancel";

/// 以前的版本记过的：节点不再声明能做端口转发的目标，它的端口转发随之停用。
pub const NODE_FORWARD_WITHDRAWN: &str = "node.forward.withdrawn";
/// 以前的版本记过的：代理的登录凭据（0.1.15 起代理自己带密码）。
pub const CREDENTIAL_CREATE: &str = "credential.create";
pub const CREDENTIAL_UPDATE: &str = "credential.update";
pub const CREDENTIAL_REVOKE: &str = "credential.revoke";
pub const CREDENTIAL_DELETE: &str = "credential.delete";
pub const CREDENTIAL_EXHAUSTED: &str = "credential.exhausted";
/// 以前的版本记过的：监听（0.1.15 起是代理）。
pub const LISTENER_CREATE: &str = "listener.create";
pub const LISTENER_UPDATE: &str = "listener.update";
pub const LISTENER_DELETE: &str = "listener.delete";
