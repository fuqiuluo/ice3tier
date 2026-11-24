//! 节点更新。
//!
//! 节点不直接连接发布源。controller 下发带签名的发布清单后，节点使用内置公钥验签，经控制链路分块下载更新包，
//! 经校验、自检、替换后重启；新版本连接上 controller 后确认更新成功，否则回滚至旧版本。
//!
//! | 模块 | 内容 |
//! |---|---|
//! | `trust` | 受信任发布公钥管理，以及清单签名与验签（[`TrustedKeys`]、[`sign_manifest`]） |
//! | `source` | 更新包来源抽象：由调用方实现的 [`PackageSource`] |
//! | `download` | 分块下载更新包、断点续传，以及大小与 SHA-256 校验 |
//! | [`mod@self_check`] | 新版本自检：旧版本如何启动候选程序，以及候选程序需确认的检查项 |
//! | `program` | 可执行文件的替换与回滚，以及 Windows 与 Unix 的平台差异 |
//! | `state` | 持久状态：待确认版本与历史失败版本记录 |
//! | `timing` | 等待 controller 指定的更新时机：空闲时、立即或排空后 |
//! | `blocker` | 检测当前节点是否支持自动更新（[`self_update_blocker`]） |
//! | `updater` | 将上述步骤组合为完整更新流程的 [`Updater`] |
//!
//! 发布清单格式与节点上报给 controller 的状态定义位于 `i3t_model::update`。

mod blocker;
mod digest;
mod download;
mod error;
mod program;
pub mod self_check;
mod source;
mod state;
mod timing;
mod trust;
mod updater;

pub use blocker::{current_program, self_update_blocker};
pub use digest::FileDigest;
pub use error::{ManifestError, Refusal, UpdateError};
pub use self_check::{SelfCheckFailure, self_check};
pub use source::{ChunkRequest, PackageSource, SourceError};
pub use state::FailedVersion;
pub use trust::{MANIFEST_PURPOSE, TrustedKeys, sign_manifest};
pub use updater::{
    CONFIRMATION_WINDOW, MAX_UNCONFIRMED_STARTS, Offer, Prepared, RESTART_EXIT_CODE, RestartRequired, RolledBack, Startup, Updater,
    UpdaterConfig,
};
