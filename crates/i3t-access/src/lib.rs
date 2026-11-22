//! 入口：把本机或者别处的应用连进组网。
//!
//! | 入口 | 说明 |
//! |---|---|
//! | 代理 | SOCKS5（`CONNECT` 和 `UDP ASSOCIATE`，用户名密码认证）、HTTP 代理（`CONNECT`，和明文 HTTP 的转发 `GET http://…`，一条流一个请求，`Proxy-Authorization: Basic`），或者在同一个端口上两种都说（按第一个字节分） |
//! | 组网入口 | 本机配置文件里的：和代理一样，只是不认证、没有出口，只通到组网里的节点 |
//! | 端口转发 | 监听一个端口。TCP 的每条连接变成到目标节点的一条流；UDP 的每个客户端地址是一个会话，走数据报上下文 |
//!
//! 一个代理是"在本节点的一个端口上监听，经一个出口节点出去，认一对用户名和密码"（netmap 的 `me.proxies`）。
//! 节点只拿到用户名和密码的校验值（[`i3t_model::netmap::Verifier`]）。不在回环地址上的端口一定要认证。
//! 还没完成握手的连接同时有多少条有上限，全节点一份、每个来源一份（[`HandshakeLimits`]），超过的新连接直接关掉。
//! 一个请求最后往哪里去的规则在 `route` 模块的文档里：组网里的目标直接去那个节点，别的经代理的出口。
//!
//! 用法是造一个 [`Access`]，然后让它的 [`run`](Access::run) 一直跑着：监听什么由 netmap 决定，netmap 变了它自己跟着调整。
//!
//! 入口按监听、按出口记用量（`usage` 模块），装配层取快照上报。

mod admission;
mod entry;
mod failure;
mod first_data;
mod forward_health;
mod http;
mod manager;
mod message;
pub mod proxy_header;
mod route;
mod routes;
mod session;
mod socks5;
mod source;
mod udp;
mod usage;

pub use admission::HandshakeLimits;
pub use entry::LocalEntry;
pub use forward_health::{ForwardHealth, TargetCause, TargetFailure};
pub use manager::{
    Access, AccessStatus, Active, ForwardStatus, ListenCause, ListenState, ListenerStatus, NoPortBook, PortBook, ProxyStatus, Traffic,
};
pub use route::is_lan_literal;
pub use routes::{CurrentRoute, NoRoutes, RouteAtStart, RouteLabel, RouteSpan, Routes, SharedRoutes};
pub use usage::{ExitSnapshot, Tally};
