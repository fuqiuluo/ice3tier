//! ice3tier 控制面的数据。
//!
//! 这里只有类型和它们的 JSON 形式，没有行为。controller 产生它们，节点消费它们，WebUI 和命令行通过管理 API 读写它们，
//! 所以这是几方共同遵守的约定。
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`netmap`] | 一个节点运行所需要的全部配置 |
//! | [`control`] | 节点和 controller 之间的消息 |
//! | [`admin`] | 管理 API 的数据结构 |
//! | [`update`] | 发布清单 |
//!
//! 兼容性约定：新增字段均带 `#[serde(default)]`，接收方忽略未知字段。
//! 这样节点和 controller 的版本可以不一样（节点更新是分批的）。

pub mod admin;
pub mod control;
pub mod netmap;
pub mod update;

pub use netmap::Netmap;
