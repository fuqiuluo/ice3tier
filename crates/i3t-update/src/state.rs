//! 更新持久化状态：记录待确认的已安装版本以及本机历史上失败过的版本。
//!
//! 存储在状态目录的 `update/state.json` 中。读写双方通常分属不同版本：写入“待确认”记录的是旧版本，
//! 启动时读取它的是新版本；回滚后读取失败记录的又是旧版本。因此字段只增不改，反序列化时忽略未知字段。

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use i3t_model::update::{UpdateCause, Version};
use serde::{Deserialize, Serialize};

use crate::error::UpdateError;

const STATE_FILE: &str = "state.json";

/// 保留的失败记录数量上限。每个版本仅保留一条，新版本确认后旧记录会被清除，正常情况下仅有 0 至 1 条；
/// 设置上限仅用于防止异常场景下状态文件无限增长。
const MAX_FAILURES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct State {
    #[serde(default)]
    pub pending: Option<Pending>,
    #[serde(default)]
    pub failed: Vec<FailedVersion>,
}

/// 已安装但尚未确认的新版本记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Pending {
    pub version: Version,
    /// 被替换并留作备份的上一版本。
    pub previous: Version,
    /// 新版本已尝试启动的次数。
    pub starts: u32,
    /// 新版本的安装时间（Unix 时间戳，单位：秒）。
    pub since: u64,
}

impl Pending {
    /// 计算距离安装经过的时间。若系统时钟被回拨，则视为 0 秒（刚刚安装）。
    pub fn age(&self, now: u64) -> Duration {
        Duration::from_secs(now.saturating_sub(self.since))
    }
}

/// 本机历史上更新失败的版本记录：包括自检失败，或安装后未能连接 controller 而触发回滚的版本。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedVersion {
    pub version: Version,
    pub reason: String,
    /// 失败时间（Unix 时间戳，单位：秒）。
    pub at: u64,
    /// 对应 `reason` 的结构化原因代码。旧版本写入的记录中可能缺失该字段。
    #[serde(default)]
    pub cause: Option<UpdateCause>,
}

impl State {
    pub fn failure_of(&self, version: &Version) -> Option<&FailedVersion> {
        self.failed.iter().find(|failure| &failure.version == version)
    }

    /// 记录一次版本失败。同一版本仅保留最近一条记录。
    pub fn record_failure(&mut self, version: Version, reason: String, cause: UpdateCause) {
        self.failed.retain(|failure| failure.version != version);
        self.failed.push(FailedVersion { version, reason, at: now(), cause: Some(cause) });
        let excess = self.failed.len().saturating_sub(MAX_FAILURES);
        self.failed.drain(..excess);
    }

    /// 版本 `version` 已确认更新成功，清除该版本及更早版本的失败记录。
    pub fn forget_failures_up_to(&mut self, version: &Version) {
        self.failed.retain(|failure| &failure.version > version);
    }
}

/// 当前系统时间（Unix 时间戳，单位：秒）。
pub(crate) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since_epoch| since_epoch.as_secs())
}

#[derive(Debug, Clone)]
pub(crate) struct StateFile {
    path: PathBuf,
}

impl StateFile {
    pub fn new(update_dir: &Path) -> Self {
        Self { path: update_dir.join(STATE_FILE) }
    }

    /// 状态文件不存在时返回空状态。若文件损坏则返回错误，而不能按空状态处理，否则会丢失待确认记录导致无法回滚备份。
    pub fn load(&self) -> Result<State, UpdateError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| UpdateError::State { path: self.path.clone(), source }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(State::default()),
            Err(error) => Err(UpdateError::io("读取", &self.path)(error)),
        }
    }

    /// 先写入临时文件再原子重命名，并在同步落盘后返回：调用方随后将替换可执行文件，状态记录必须先可靠落盘。
    pub fn save(&self, state: &State) -> Result<(), UpdateError> {
        let bytes = serde_json::to_vec_pretty(state).expect("更新状态序列化失败");
        let temporary = self.path.with_extension("json.tmp");
        let write = || -> io::Result<()> {
            let mut file = File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            // Windows 不支持以只读句柄打开目录进行同步；重命名持久化由文件系统日志保证。
            if cfg!(unix)
                && let Some(dir) = self.path.parent()
            {
                File::open(dir)?.sync_all()?;
            }
            Ok(())
        };
        write().map_err(UpdateError::io("写入", &self.path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> Version {
        text.parse().unwrap()
    }

    #[test]
    fn state_survives_a_round_trip_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = StateFile::new(dir.path());
        assert_eq!(file.load().unwrap(), State::default());

        let mut state = State {
            pending: Some(Pending { version: version("0.2.0"), previous: version("0.1.0"), starts: 2, since: 1_763_200_000 }),
            failed: Vec::new(),
        };
        state.record_failure(version("0.1.5"), "自检没有通过".to_owned(), UpdateCause::Cancelled);
        file.save(&state).unwrap();
        assert_eq!(file.load().unwrap(), state);
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(names, [STATE_FILE]);
    }

    #[test]
    fn state_written_by_another_version_of_the_program_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        let file = StateFile::new(dir.path());
        // 没有的字段取默认值，多出来的字段忽略。
        fs::write(dir.path().join(STATE_FILE), r#"{ "pending": null, "added_later": [1, 2] }"#).unwrap();
        assert_eq!(file.load().unwrap(), State::default());
        fs::write(dir.path().join(STATE_FILE), r#"{ "failed": [{ "version": "0.2.0", "reason": "x", "at": 5, "added_later": true }] }"#)
            .unwrap();
        assert_eq!(file.load().unwrap().failure_of(&version("0.2.0")).unwrap().reason, "x");
    }

    #[test]
    fn a_corrupt_state_file_is_an_error_not_a_clean_slate() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(STATE_FILE), "{ 写了一半").unwrap();
        assert!(matches!(StateFile::new(dir.path()).load(), Err(UpdateError::State { .. })));
    }

    #[test]
    fn each_version_has_one_failure_record_and_old_ones_are_dropped_on_success() {
        let mut state = State::default();
        state.record_failure(version("0.2.0"), "第一次".to_owned(), UpdateCause::Cancelled);
        state.record_failure(version("0.3.0"), "另一个版本".to_owned(), UpdateCause::Cancelled);
        state.record_failure(version("0.2.0"), "第二次".to_owned(), UpdateCause::Cancelled);
        assert_eq!(state.failed.len(), 2);
        assert_eq!(state.failure_of(&version("0.2.0")).unwrap().reason, "第二次");
        assert_eq!(state.failure_of(&version("0.2.1")), None);

        state.forget_failures_up_to(&version("0.2.5"));
        assert_eq!(state.failure_of(&version("0.2.0")), None);
        assert!(state.failure_of(&version("0.3.0")).is_some());
    }

    #[test]
    fn failure_records_are_bounded() {
        let mut state = State::default();
        for patch in 0..40 {
            state.record_failure(Version::new(0, 1, patch), String::new(), UpdateCause::Cancelled);
        }
        assert_eq!(state.failed.len(), MAX_FAILURES);
        assert_eq!(state.failed.last().unwrap().version, Version::new(0, 1, 39));
    }

    #[test]
    fn age_never_goes_negative_when_the_clock_steps_back() {
        let pending = Pending { version: version("0.2.0"), previous: version("0.1.0"), starts: 0, since: 1000 };
        assert_eq!(pending.age(1090), Duration::from_secs(90));
        assert_eq!(pending.age(900), Duration::ZERO);
    }
}
