//! 节点的装配层：把各层装成一个可以运行的节点。
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`state`] | 本地状态目录：节点密钥、controller 的地址和公钥、本地声明、最后一份 netmap |
//! | [`config`] | 使用者手改的配置文件 `config.toml` |
//! | [`program`] | 这个节点程序自己的情况：版本、程序文件、能不能自己更新 |
//! | [`control`] | 连 controller 的那条长连接：注册、收 netmap、上报、转发信令、取更新包、回答路由查询 |
//! | [`join`] | 用注册令牌加入网络 |
//! | [`node`] | 把各层装成一个运行着的节点 |
//! | [`performance`] | 性能档位：预设加上本机的覆盖，落实成线程数、缓冲、窗口和空闲回收的时间 |
//! | `lanes` | ice3proxy（lane）：和共用的连接装成一个连接层，跟着 netmap 拨谁、接谁 |
//! | [`drain`] | 排空：更新之前不再接新的流 |
//! | `exit_test` | 出口测试：按本节点的出站策略试着连 controller 给的目标，一次一个 |
//! | `diag` | 主动测试：收 controller 的指令，按本机的规矩量、配合，送回结果；测量服务 |
//! | [`selfcheck`] | 新程序的自检（`i3t self-check`） |
//! | [`status`]、[`local`] | 运行着的节点的状态，和本机问它的接口（`i3t status`、`i3t routes`、`/metrics`） |
//! | [`ping`] | `i3t ping`：在到另一个节点的连接上量往返 |
//! | [`vnet`] | 虚拟网卡：按本机配置初始化、随 netmap 更新、停止时清理；内置 DNS 服务 |
//!
//! 节点更新的验签、取包、替换和回退在 `i3t-update` 里，这里只是把它接到长连接和数据面上。

pub mod config;
pub mod control;
mod diag;
pub mod drain;
mod exit_test;
mod flows;
mod http;
pub mod join;
mod lanes;
pub mod local;
mod memory;
mod metrics;
pub mod node;
pub mod performance;
mod persist;
pub mod ping;
pub mod program;
mod route_detail;
mod runtime;
pub mod selfcheck;
pub mod state;
pub mod status;
mod texts;
mod update;
pub mod vnet;

pub use i3t_model::update::Version;
pub use i3t_update::RESTART_EXIT_CODE;
pub use node::NO_RESTART_EXIT_CODE;
