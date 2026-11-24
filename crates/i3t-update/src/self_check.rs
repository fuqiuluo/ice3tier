//! 更新前自检：在替换可执行文件前，验证新版本能够在当前主机正常运行。
//!
//! 自检流程由两端共同约定：
//!
//! **旧版本进程**将已校验的候选程序置于同目录并启动执行（由本 crate 内部调用）：
//!
//! - 命令行为 `<新程序> <参数…>`，参数由节点在 [`UpdaterConfig::self_check_args`](crate::UpdaterConfig::self_check_args)
//!   中提供，通常为 `--state-dir <状态目录> self-check`；
//! - 通过环境变量 [`EXPECTED_VERSION_ENV`] 传入清单中的目标版本号，其余环境变量原样继承；
//! - 关闭标准输入、丢弃标准输出，并捕获标准错误；
//! - 退出码为 0 表示通过；非零退出码、被信号终止或超过 [`TIMEOUT`] 未退出（将被强制终止）均视为失败，
//!   并截取标准错误末尾内容作为失败原因上报给 controller。
//!
//! **新版本进程**的自检子命令调用 [`self_check`]，成功时以 0 退出，失败时将原因输出至标准错误并以非零退出码退出。需确认以下三项：
//!
//! 1. 程序可正常启动，且版本号与发布清单一致（进入该函数即表明已正常启动）；
//! 2. 能够读取现有配置与本地状态；
//! 3. 能够与 controller 完成一次握手。
//!
//! 自检期间旧版本仍在运行，因此新版本**不得**绑定节点端口、修改状态目录，
//! 也不得以节点身份向 controller 注册上线：握手在完成双向认证后即刻断开，避免 controller 将其视为重连并断开旧版本连接。

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use i3t_model::update::Version;
use tokio::process::{Child, Command};

/// 旧版本通过该环境变量向新版本传递发布清单中的预期版本号。
pub const EXPECTED_VERSION_ENV: &str = "I3T_SELF_CHECK_VERSION";

/// 整个自检过程的总超时时间。握手阶段设有更短的时限（[`HANDSHAKE_TIMEOUT`]），正常情况下不会触发此上限。
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// 自检阶段与 controller 握手的超时时间。
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// 上报给 controller 的失败原因最多保留的标准错误字符数。
const REASON_CHARS: usize = 400;

/// 新版本自检失败的原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelfCheckFailure {
    /// 发布时内置版本号与清单不一致。若继续安装，节点会持续认为自身处于旧版本并反复触发更新。
    #[error("当前程序版本为 {running}，与发布清单中的预期版本 {expected} 不符")]
    WrongVersion { expected: String, running: Version },
    #[error("无法读取现有配置与状态：{0}")]
    State(String),
    #[error("未能与 controller 完成握手：{0}")]
    Handshake(String),
    #[error("在 {} 秒内未能与 controller 完成握手", HANDSHAKE_TIMEOUT.as_secs())]
    HandshakeTimeout,
}

/// 执行新版本自检。由节点自检子命令调用，并根据结果决定退出码。
///
/// - `running`：当前程序版本号；
/// - `load`：加载现有配置与状态，并将结果传递给握手步骤；
/// - `handshake`：使用加载的状态与 controller 完成一次握手后断开，不得注册上线（原因见模块文档）。
///
/// 手动执行自检子命令时未设置 [`EXPECTED_VERSION_ENV`]，此时跳过版本号校验。
///
/// # Errors
///
/// 任一检查项失败时返回对应的 [`SelfCheckFailure`]。
pub async fn self_check<T, E, L, H>(running: &Version, load: L, handshake: H) -> Result<(), SelfCheckFailure>
where
    L: FnOnce() -> Result<T, E>,
    H: AsyncFnOnce(T) -> Result<(), E>,
    E: fmt::Display,
{
    check(std::env::var(EXPECTED_VERSION_ENV).ok(), running, load, handshake).await
}

async fn check<T, E, L, H>(expected: Option<String>, running: &Version, load: L, handshake: H) -> Result<(), SelfCheckFailure>
where
    L: FnOnce() -> Result<T, E>,
    H: AsyncFnOnce(T) -> Result<(), E>,
    E: fmt::Display,
{
    if let Some(expected) = expected
        && expected != running.to_string()
    {
        return Err(SelfCheckFailure::WrongVersion { expected, running: running.clone() });
    }
    // 使用 `{:#}` 展开 anyhow 错误的原因链，不影响其他错误类型。
    let loaded = load().map_err(|error| SelfCheckFailure::State(format!("{error:#}")))?;
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(loaded)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(SelfCheckFailure::Handshake(format!("{error:#}"))),
        Err(_) => Err(SelfCheckFailure::HandshakeTimeout),
    }
}

/// 新版本自检被拒绝的详细信息：包含面向用户的描述以及用于结构化上报的字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rejected {
    pub(crate) reason: String,
    /// 新版本程序的退出码；被信号终止、无法启动或超时时为 `None`。
    pub(crate) exit_code: Option<i32>,
    /// 新版本标准错误输出的末尾内容；未执行到输出阶段时为错误描述本身。
    pub(crate) output: String,
}

impl Rejected {
    fn without_output(reason: String) -> Self {
        Self { output: reason.clone(), reason, exit_code: None }
    }
}

/// 在旧版本进程中启动候选新程序执行自检，失败时返回拒绝原因。
pub(crate) async fn run_candidate(candidate: &Path, args: &[OsString], version: &Version, limit: Duration) -> Result<(), Rejected> {
    let mut command = Command::new(candidate);
    command
        .args(args)
        .env(EXPECTED_VERSION_ENV, version.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        // 超时或调用方取消导致 future 被丢弃时，自动终止子进程。
        .kill_on_drop(true);
    let child = spawn(&mut command).await.map_err(|error| Rejected::without_output(format!("无法启动新版本程序：{error}")))?;
    match tokio::time::timeout(limit, child.wait_with_output()).await {
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => {
            let said = tail(&output.stderr);
            Err(Rejected { reason: format!("{}：{said}", describe_exit(output.status)), exit_code: output.status.code(), output: said })
        }
        Ok(Err(error)) => Err(Rejected::without_output(format!("等待新版本程序退出时出错：{error}"))),
        Err(_) => Err(Rejected::without_output(format!("自检超时（超过 {} 秒未退出）", limit.as_secs()))),
    }
}

/// 启动子进程。
///
/// 在 Unix 平台上，文件刚写入完成即执行时偶发 `ETXTBSY`（ExecutableFileBusy）：若其他线程恰好同时 fork 子进程，
/// 刚创建的子进程在 exec 前可能短暂持有写入文件描述符。短暂等待并重试即可避免误报。
async fn spawn(command: &mut Command) -> io::Result<Child> {
    const ATTEMPTS: u32 = 20;
    const PAUSE: Duration = Duration::from_millis(50);
    for _ in 1..ATTEMPTS {
        match command.spawn() {
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => tokio::time::sleep(PAUSE).await,
            result => return result,
        }
    }
    command.spawn()
}

fn describe_exit(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("退出码 {code}"),
        None => "被信号终止".to_owned(),
    }
}

/// 提取标准错误输出的末尾片段。失败原因通常位于最后几行，前面可能包含较长日志。
fn tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let text = text.trim();
    if text.is_empty() {
        return "未输出错误原因".to_owned();
    }
    let start = text.char_indices().rev().nth(REASON_CHARS - 1).map_or(0, |(index, _)| index);
    text[start..].to_owned()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn version() -> Version {
        Version::new(0, 2, 0)
    }

    async fn passing_handshake(_loaded: u8) -> Result<(), String> {
        Ok(())
    }

    #[tokio::test]
    async fn check_passes_when_all_three_things_work() {
        let loaded = Cell::new(None);
        let result = check(
            Some("0.2.0".to_owned()),
            &version(),
            || Ok::<_, String>(7u8),
            async |state| {
                loaded.set(Some(state));
                Ok(())
            },
        )
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(loaded.get(), Some(7), "读出来的配置和状态应该交给握手那一步");
    }

    #[tokio::test]
    async fn check_refuses_a_program_that_is_not_the_version_the_manifest_names() {
        let result = check(Some("0.3.0".to_owned()), &version(), || Ok::<_, String>(0u8), passing_handshake).await;
        assert_eq!(result, Err(SelfCheckFailure::WrongVersion { expected: "0.3.0".to_owned(), running: version() }));
    }

    #[tokio::test]
    async fn check_run_by_hand_does_not_compare_versions() {
        assert_eq!(check(None, &version(), || Ok::<_, String>(0u8), passing_handshake).await, Ok(()));
    }

    #[tokio::test]
    async fn unreadable_state_fails_before_any_handshake() {
        let shook_hands = Cell::new(false);
        let result = check(
            None,
            &version(),
            || Err::<u8, _>("config.toml 第 3 行写错了"),
            async |_| {
                shook_hands.set(true);
                Ok(())
            },
        )
        .await;
        assert_eq!(result, Err(SelfCheckFailure::State("config.toml 第 3 行写错了".to_owned())));
        assert!(!shook_hands.get());
    }

    #[tokio::test]
    async fn a_failed_handshake_fails_the_check() {
        let result = check(None, &version(), || Ok(0u8), async |_| Err("controller 不认这把公钥".to_owned())).await;
        assert_eq!(result, Err(SelfCheckFailure::Handshake("controller 不认这把公钥".to_owned())));
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_that_never_finishes_times_out() {
        let started = tokio::time::Instant::now();
        let result = check(None, &version(), || Ok::<_, String>(0u8), async |_| std::future::pending().await).await;
        assert_eq!(result, Err(SelfCheckFailure::HandshakeTimeout));
        assert_eq!(started.elapsed(), HANDSHAKE_TIMEOUT);
    }

    #[test]
    fn reason_keeps_only_the_end_of_a_long_stderr() {
        assert_eq!(tail(b"  \n"), "未输出错误原因");
        assert_eq!(tail("第一行\n原因在这里\n".as_bytes()), "第一行\n原因在这里");
        let long = format!("{}结尾", "很长的日志。".repeat(1000));
        let kept = tail(long.as_bytes());
        assert_eq!(kept.chars().count(), REASON_CHARS);
        assert!(kept.ends_with("结尾"));
        // 不是合法 UTF-8 的输出也不能让它出错。
        assert!(tail(&[0xff, 0xfe, b'x']).ends_with('x'));
    }

    #[cfg(unix)]
    mod candidate {
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;

        use super::*;

        fn script(dir: &Path, body: &str) -> PathBuf {
            let path = dir.join("i3t.new");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        }

        async fn run(body: &str, limit: Duration) -> Result<(), String> {
            let dir = tempfile::tempdir().unwrap();
            let args = [OsString::from("--state-dir"), OsString::from("/var/lib/i3t"), OsString::from("self-check")];
            run_candidate(&script(dir.path(), body), &args, &version(), limit).await.map_err(|rejected| rejected.reason)
        }

        #[tokio::test]
        async fn exit_status_zero_passes() {
            assert_eq!(run("exit 0", TIMEOUT).await, Ok(()));
        }

        #[tokio::test]
        async fn candidate_receives_the_arguments_and_the_expected_version() {
            let body = r#"[ "$1 $2 $3" = "--state-dir /var/lib/i3t self-check" ] || { echo "参数不对：$*" >&2; exit 2; }
[ "$I3T_SELF_CHECK_VERSION" = 0.2.0 ] || { echo "版本不对：$I3T_SELF_CHECK_VERSION" >&2; exit 3; }"#;
            assert_eq!(run(body, TIMEOUT).await, Ok(()));
        }

        #[tokio::test]
        async fn a_non_zero_exit_fails_with_the_reason_from_stderr() {
            let result = run("echo 这一行在标准输出上，不算; echo 读不了 config.toml >&2; exit 3", TIMEOUT).await;
            assert_eq!(result, Err("退出码 3：读不了 config.toml".to_owned()));
        }

        #[tokio::test]
        async fn a_failure_keeps_the_exit_code_and_what_the_program_said() {
            let dir = tempfile::tempdir().unwrap();
            let rejected = run_candidate(&script(dir.path(), "echo 读不了 config.toml >&2; exit 3"), &[], &version(), TIMEOUT).await;
            let rejected = rejected.unwrap_err();
            assert_eq!((rejected.exit_code, rejected.output.as_str()), (Some(3), "读不了 config.toml"));
        }

        #[tokio::test]
        async fn a_candidate_killed_by_a_signal_fails() {
            assert_eq!(run("kill -9 $$", TIMEOUT).await, Err("被信号终止：未输出错误原因".to_owned()));
        }

        #[tokio::test]
        async fn a_candidate_that_hangs_is_stopped_at_the_time_limit() {
            let started = std::time::Instant::now();
            let result = run("exec sleep 30", Duration::from_millis(300)).await;
            assert_eq!(result, Err("自检超时（超过 0 秒未退出）".to_owned()));
            assert!(started.elapsed() < Duration::from_secs(10));
        }

        #[tokio::test]
        async fn a_file_that_cannot_be_run_fails() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("i3t.new");
            std::fs::write(&path, "不是程序").unwrap();
            let result = run_candidate(&path, &[], &version(), TIMEOUT).await;
            assert!(result.unwrap_err().reason.starts_with("无法启动新版本程序："));
        }
    }
}
