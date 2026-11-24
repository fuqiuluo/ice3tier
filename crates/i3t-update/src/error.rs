//! 更新流程中的错误类型定义。

use std::error::Error;
use std::fmt::Write;
use std::io;
use std::path::{Path, PathBuf};

use i3t_model::update::{FailureKind, Platform, SelfUpdateBlocker, Sha256, UpdateCause, Version};

/// 带签名发布清单的校验错误。
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("发布清单签名验证失败：签名与受信任的发布公钥不匹配")]
    BadSignature,
    /// 签名有效，通常表示发布清单格式有误，或清单由更新版本的发布工具生成。
    #[error("发布清单签名验证通过，内容解析失败")]
    Malformed(#[source] serde_json::Error),
}

/// 节点拒绝应用发布清单的原因。此时尚未对本地状态或可执行文件做任何修改。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("{0}")]
    CannotSelfUpdate(SelfUpdateBlocker),
    #[error("发布清单中的版本 {offered} 不高于当前运行版本 {running}")]
    NotNewer { offered: Version, running: Version },
    #[error("目标版本 {offered} 为预发布版，而当前运行版本 {running} 为正式版")]
    Prerelease { offered: Version, running: Version },
    #[error("版本 {version} 在当前主机曾更新失败，不再自动重试（上次失败原因：{reason}）")]
    FailedBefore { version: Version, reason: String },
    #[error("版本 {version} 缺少适用于 {platform} 平台的更新包")]
    NoArtifact { version: Version, platform: Platform },
    /// 当前进程已安装新版本但尚未重启，重启前不允许再次安装。
    #[error("已安装版本 {installed}，等待进程重启生效")]
    RestartPending { installed: Version },
}

impl Refusal {
    fn cause(&self) -> UpdateCause {
        match self {
            Self::Manifest(ManifestError::BadSignature) => UpdateCause::BadSignature,
            Self::Manifest(ManifestError::Malformed(_)) => UpdateCause::BadManifest,
            Self::CannotSelfUpdate(blocker) => UpdateCause::CannotSelfUpdate { blocker: *blocker },
            Self::NotNewer { offered, running } => UpdateCause::NotNewer { offered: offered.clone(), running: running.clone() },
            Self::Prerelease { offered, running } => UpdateCause::Prerelease { offered: offered.clone(), running: running.clone() },
            Self::FailedBefore { version, .. } => UpdateCause::FailedBefore { version: version.clone() },
            Self::NoArtifact { version, platform } => UpdateCause::NoPackage { version: version.clone(), platform: platform.clone() },
            Self::RestartPending { installed } => UpdateCause::RestartPending { installed: installed.clone() },
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UpdateError {
    #[error("已拒绝该发布清单")]
    Refused(#[from] Refusal),
    /// 更新源明确无法提供更新包，或返回的数据不符合分块协议约定。链路中断不会返回该错误，而是持续重试。
    #[error("获取更新包失败：{0}")]
    Unavailable(String),
    #[error("更新包校验失败：实际大小 {actual_size} 字节、SHA-256 {actual}，预期大小 {expected_size} 字节、SHA-256 {expected}")]
    Corrupt { expected_size: u64, expected: Sha256, actual_size: u64, actual: Sha256 },
    #[error("版本 {version} 自检失败：{reason}")]
    SelfCheck {
        version: Version,
        reason: String,
        /// 新版本程序的退出码；被信号终止、无法启动或超时时为 `None`。
        exit_code: Option<i32>,
        /// 新版本程序标准错误输出的末尾内容。
        output: String,
    },
    #[error("活跃流计数通道已关闭，无法等待更新时机")]
    Cancelled,
    #[error("{action} {} 失败", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("无法解析更新状态文件 {}", path.display())]
    State {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

impl UpdateError {
    /// 判断该错误是否应归类为“该版本在当前主机不可用”。仅自检失败属于此类；
    /// 安装后未能连接 controller 的情况不经由该错误类型，而在回滚流程中直接记录。
    #[must_use]
    pub const fn kind(&self) -> FailureKind {
        match self {
            Self::SelfCheck { .. } => FailureKind::VersionRejected,
            Self::Refused(_) | Self::Unavailable(_) | Self::Corrupt { .. } | Self::Cancelled | Self::Io { .. } | Self::State { .. } => {
                FailureKind::NotInstalled
            }
        }
    }

    /// 转换为上报给 controller 的结构化原因代码，与 [`describe`] 生成的描述语义一致。
    #[must_use]
    pub fn cause(&self) -> UpdateCause {
        match self {
            Self::Refused(refusal) => refusal.cause(),
            Self::Unavailable(detail) => UpdateCause::Unavailable { detail: detail.clone() },
            Self::Corrupt { expected_size, actual_size, .. } => {
                UpdateCause::Corrupt { expected_size: *expected_size, actual_size: *actual_size }
            }
            Self::SelfCheck { exit_code, output, .. } => UpdateCause::SelfCheck { exit_code: *exit_code, output: output.clone() },
            Self::Cancelled => UpdateCause::Cancelled,
            Self::Io { path, source, .. } => UpdateCause::Io { path: path.display().to_string(), error: source.to_string() },
            Self::State { path, .. } => UpdateCause::StateUnreadable { path: path.display().to_string() },
        }
    }

    /// 供 `map_err` 使用：将 I/O 错误与对应的操作名称和文件路径封装为 [`UpdateError::Io`]。
    pub(crate) fn io(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> Self {
        let path = path.to_owned();
        move |source| Self::Io { action, path, source }
    }
}

/// 将错误及其完整原因链拼接为单行描述。由于上报给 controller 的失败原因仅为单个字符串，需将底层原因一并串联。
pub(crate) fn describe(error: &dyn Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        // 写入 String 不会失败。
        let _ = write!(text, "：{cause}");
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_includes_every_cause_once() {
        let error = UpdateError::Refused(Refusal::Manifest(ManifestError::BadSignature));
        assert_eq!(describe(&error), "已拒绝该发布清单：发布清单签名验证失败：签名与受信任的发布公钥不匹配");
        let error = UpdateError::Io { action: "写", path: PathBuf::from("/x/y"), source: io::Error::other("磁盘满了") };
        assert_eq!(describe(&error), "写 /x/y 失败：磁盘满了");
    }

    #[test]
    fn every_failure_has_a_code_with_the_values_its_sentence_uses() {
        let refused = UpdateError::Refused(Refusal::Manifest(ManifestError::BadSignature));
        assert_eq!(refused.cause(), UpdateCause::BadSignature);
        let (offered, running) = (Version::new(0, 2, 0), Version::new(0, 3, 0));
        let not_newer = UpdateError::Refused(Refusal::NotNewer { offered: offered.clone(), running: running.clone() });
        assert_eq!(not_newer.cause(), UpdateCause::NotNewer { offered, running });
        let io = UpdateError::Io { action: "写", path: PathBuf::from("/x/y"), source: io::Error::other("磁盘满了") };
        assert_eq!(io.cause(), UpdateCause::Io { path: "/x/y".into(), error: "磁盘满了".into() });
        let check = UpdateError::SelfCheck {
            version: Version::new(1, 0, 0),
            reason: "退出码 3：坏了".into(),
            exit_code: Some(3),
            output: "坏了".into(),
        };
        assert_eq!(check.cause(), UpdateCause::SelfCheck { exit_code: Some(3), output: "坏了".into() });
        let blocked = UpdateError::Refused(Refusal::CannotSelfUpdate(SelfUpdateBlocker::Container));
        assert_eq!(blocked.cause(), UpdateCause::CannotSelfUpdate { blocker: SelfUpdateBlocker::Container });
    }

    #[test]
    fn only_a_failed_self_check_blames_the_version() {
        let version = Version::new(1, 0, 0);
        let failed = UpdateError::SelfCheck { version, reason: String::new(), exit_code: Some(1), output: String::new() };
        assert_eq!(failed.kind(), FailureKind::VersionRejected);
        assert_eq!(UpdateError::Unavailable(String::new()).kind(), FailureKind::NotInstalled);
        assert_eq!(UpdateError::Refused(Refusal::Manifest(ManifestError::BadSignature)).kind(), FailureKind::NotInstalled);
    }
}
