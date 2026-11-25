//! ice3tier 的 controller。
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`store`] | 存储：一个 PostgreSQL 数据库 |
//! | [`access`] | 访问规则的编译：谁能访问谁 |
//! | [`netmap`] | 给一个节点算它的 netmap |
//! | [`Controller`] | 存储之上的全部规则，和 netmap 的下发。节点协议和管理 API 都只是它的入口 |
//! | [`node_server`]、[`frame`] | 节点协议的服务端和分帧 |
//! | [`addr_server`] | 地址查询的应答 |
//! | [`admin`] | 管理 API：路由和处理函数；HTTP 的服务端在 `admin_server` 里 |
//! | [`release`] | 发布源：从哪里取发布清单和节点的更新包 |
//! | [`webui`] | WebUI 的静态文件从哪里来 |
//! | [`Server`] | 把上面这些装在一起跑 |
//!
//! ```no_run
//! # async fn example() -> Result<(), i3t_controller::Error> {
//! use std::sync::Arc;
//! use i3t_controller::webui::WebUi;
//! use i3t_controller::{Controller, ServeOptions, Server};
//!
//! let database = "postgres://i3t:secret@127.0.0.1/i3t".parse()?;
//! let opened = Controller::open("/var/lib/i3t-controller".as_ref(), &database, "ctl.example.com:20331".to_owned())?;
//! if let Some(token) = opened.admin_token {
//!     println!("管理令牌（只显示这一次）：{token}");
//! }
//! let options = ServeOptions {
//!     node_listen: "0.0.0.0:20331".parse().expect("合法的地址"),
//!     admin_listen: "127.0.0.1:20332".parse().expect("合法的地址"),
//!     webui: WebUi::NotIncluded,
//!     follow_releases: true,
//! };
//! let server = Server::bind(Arc::new(opened.controller), options).await?;
//! // 返回后关闭运行时应设定等待期限（`Runtime::shutdown_timeout`），原因见 `Server::run` 的文档。
//! server.run(async { tokio::signal::ctrl_c().await.ok(); }).await
//! # }
//! ```

pub mod access;
pub mod addr_server;
pub mod admin;
mod admin_server;
mod controller;
mod error;
pub mod frame;
mod gate;
mod geo;
pub mod netmap;
mod node_addresses;
pub mod node_server;
mod reachability;
mod relay_reach;
pub mod release;
mod secret;
mod server;
pub mod store;
mod sync;
pub mod webui;

pub use controller::{ALPN, Admitted, Controller, Opened, RouteAnswers, TickFailed, Timing, Waits};
pub use error::{Capability, Entity, Error, Rejection};
pub use server::{ServeOptions, Server};
