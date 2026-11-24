//! 可执行文件的替换与回滚。
//!
//! 可执行文件同目录下可能出现以下辅助文件（以 `i3t` 为例，Windows 平台下标记插入在 `.exe` 之前）：
//!
//! | 文件 | 用途 | 生命周期 |
//! |---|---|---|
//! | `i3t.new` | 已校验、待安装的新版本候选程序 | 从自检开始到替换完成前 |
//! | `i3t.old` | 被替换的旧版本备份 | 从替换完成到新版本被确认或回滚前 |
//! | `i3t.failed` | 回滚时移出的新版本程序 | 仅限 Windows 平台，保留至下次启动清理 |
//!
//! 上述文件均与主程序位于同一目录，因此重命名不会跨文件系统，具有原子性。

use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

/// 正在运行的可执行文件的替换策略。两种策略均仅依赖重命名操作，可在所有平台上运行，便于单元测试覆盖。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Swap {
    /// 将新文件直接重命名覆盖目标路径。Unix 允许覆盖正在运行的可执行文件，当前进程继续使用旧文件句柄。
    /// 该方式可保证任意时刻目标路径上均存在完整的可执行文件。
    Overwrite,
    /// 先将当前运行文件重命名移出，再将新文件重命名到目标路径。Windows 不允许覆盖或删除正在运行的可执行文件，但允许重命名。
    /// 两次重命名之间存在极短窗口目标路径为空，若此时异常断电需手动将备份文件改回原名。
    MoveAside,
}

impl Swap {
    pub const NATIVE: Self = if cfg!(windows) { Self::MoveAside } else { Self::Overwrite };
}

#[derive(Debug, Clone)]
pub(crate) struct ProgramFiles {
    program: PathBuf,
    swap: Swap,
}

impl ProgramFiles {
    pub fn new(program: PathBuf, swap: Swap) -> Self {
        Self { program, swap }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    /// 待安装的新版本候选文件路径。
    pub fn candidate(&self) -> PathBuf {
        self.sibling("new")
    }

    /// 被替换的旧版本备份文件路径。
    pub fn backup(&self) -> PathBuf {
        self.sibling("old")
    }

    fn discarded(&self) -> PathBuf {
        self.sibling("failed")
    }

    /// 生成同目录下带标记的辅助文件路径。保留末尾的 `.exe` 扩展名，以满足 Windows 执行要求。
    fn sibling(&self, tag: &str) -> PathBuf {
        let name = self.program.file_name().unwrap_or_default();
        let is_exe = self.program.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("exe"));
        let mut tagged = OsString::from(if is_exe { self.program.file_stem().unwrap_or(name) } else { name });
        tagged.push(".");
        tagged.push(tag);
        if is_exe {
            tagged.push(".exe");
        }
        self.program.with_file_name(tagged)
    }

    /// 将已校验的更新包复制到目标程序同目录并沿用原文件权限。该调用为阻塞 I/O。
    pub fn place_candidate(&self, package: &Path) -> io::Result<()> {
        let candidate = self.candidate();
        remove_if_exists(&candidate)?;
        let mut file = File::create_new(&candidate)?;
        io::copy(&mut File::open(package)?, &mut file)?;
        file.set_permissions(fs::metadata(&self.program)?.permissions())?;
        file.sync_all()
    }

    /// 将候选新程序替换到目标路径，并保留旧程序作为备份。失败时保持原程序不变。
    pub fn install_candidate(&self) -> io::Result<()> {
        let (candidate, backup) = (self.candidate(), self.backup());
        remove_if_exists(&backup)?;
        match self.swap {
            Swap::Overwrite => {
                // 优先使用硬链接避免拷贝与额外空间占用；文件系统不支持时回退为复制。
                if fs::hard_link(&self.program, &backup).is_err() {
                    fs::copy(&self.program, &backup)?;
                }
                fs::rename(&candidate, &self.program).inspect_err(|_| discard(&backup))?;
            }
            Swap::MoveAside => {
                fs::rename(&self.program, &backup)?;
                fs::rename(&candidate, &self.program).inspect_err(|_| put_back(&backup, &self.program))?;
            }
        }
        self.sync_dir()
    }

    pub fn has_backup(&self) -> bool {
        self.backup().exists()
    }

    pub fn remove_backup(&self) -> io::Result<()> {
        remove_if_exists(&self.backup())
    }

    /// 将备份的旧程序回滚至目标路径。由正在运行的新程序调用，其自身文件会被覆盖或移出；失败时保持当前新程序不变。
    pub fn restore_backup(&self) -> io::Result<()> {
        let backup = self.backup();
        match self.swap {
            Swap::Overwrite => fs::rename(&backup, &self.program)?,
            Swap::MoveAside => {
                let discarded = self.discarded();
                remove_if_exists(&discarded)?;
                fs::rename(&self.program, &discarded)?;
                fs::rename(&backup, &self.program).inspect_err(|_| put_back(&discarded, &self.program))?;
            }
        }
        self.sync_dir()
    }

    /// 清理不再需要的遗留文件：未完成安装的候选新程序，以及上次 Windows 回滚时因正在运行而移出的失败程序。
    /// 清理失败不影响正常运行，将在下次启动时重试，因此仅记录警告日志。
    pub fn remove_leftovers(&self) {
        for leftover in [self.candidate(), self.discarded()] {
            if let Err(error) = remove_if_exists(&leftover) {
                tracing::warn!(path = %leftover.display(), %error, "无法清理上次更新遗留的文件");
            }
        }
    }

    /// 同步父目录元数据以确保重命名落盘。Windows 不支持以此方式打开目录，其重命名持久化由文件系统日志保证。
    fn sync_dir(&self) -> io::Result<()> {
        if cfg!(unix) {
            let dir = self.program.parent().ok_or_else(|| io::Error::other("可执行文件路径缺少父目录"))?;
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// 替换失败后清理刚创建的备份文件。清理失败不影响程序运行，将在下次启动时重试。
fn discard(backup: &Path) {
    if let Err(error) = remove_if_exists(backup) {
        tracing::warn!(path = %backup.display(), %error, "程序替换失败后无法删除新建的备份文件");
    }
}

/// 第二次重命名失败后尝试恢复刚移出的原程序文件。若恢复也失败，目标路径将缺失可执行文件，必须记录明确错误供人工介入。
fn put_back(moved: &Path, program: &Path) {
    if let Err(error) = fs::rename(moved, program) {
        tracing::error!(
            from = %moved.display(), to = %program.display(), %error,
            "程序替换中途失败，且无法恢复原可执行文件：请手动将其重命名回原路径，否则节点下次将无法启动"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        dir: tempfile::TempDir,
        files: ProgramFiles,
    }

    impl Fixture {
        fn new(swap: Swap) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let program = dir.path().join("i3t");
            fs::write(&program, "旧程序").unwrap();
            Self { files: ProgramFiles::new(program, swap), dir }
        }

        fn place(&self, content: &str) {
            let package = self.dir.path().join("package");
            fs::write(&package, content).unwrap();
            self.files.place_candidate(&package).unwrap();
            fs::remove_file(package).unwrap();
        }

        fn names(&self) -> Vec<String> {
            let mut names: Vec<String> =
                fs::read_dir(self.dir.path()).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
            names.sort();
            names
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.dir.path().join(name)).unwrap()
        }
    }

    #[test]
    fn tagged_files_sit_next_to_the_program_and_keep_the_exe_extension() {
        let unix = ProgramFiles::new(PathBuf::from("/opt/i3t/bin/i3t"), Swap::Overwrite);
        assert_eq!(unix.candidate(), Path::new("/opt/i3t/bin/i3t.new"));
        assert_eq!(unix.backup(), Path::new("/opt/i3t/bin/i3t.old"));
        let windows = ProgramFiles::new(PathBuf::from("bin/i3t.EXE"), Swap::MoveAside);
        assert_eq!(windows.candidate(), Path::new("bin/i3t.new.exe"));
        assert_eq!(windows.discarded(), Path::new("bin/i3t.failed.exe"));
        // 名字里别的点不算扩展名。
        let dotted = ProgramFiles::new(PathBuf::from("i3t-0.2.0"), Swap::Overwrite);
        assert_eq!(dotted.backup(), Path::new("i3t-0.2.0.old"));
    }

    #[test]
    fn install_swaps_the_program_and_keeps_the_old_one_with_either_strategy() {
        for swap in [Swap::Overwrite, Swap::MoveAside] {
            let fixture = Fixture::new(swap);
            fixture.place("新程序");
            assert_eq!(fixture.names(), ["i3t", "i3t.new"]);
            assert!(!fixture.files.has_backup());

            fixture.files.install_candidate().unwrap();
            assert_eq!(fixture.names(), ["i3t", "i3t.old"], "{swap:?}");
            assert_eq!(fixture.read("i3t"), "新程序");
            assert_eq!(fixture.read("i3t.old"), "旧程序");
            assert!(fixture.files.has_backup());

            fixture.files.remove_backup().unwrap();
            assert_eq!(fixture.names(), ["i3t"]);
        }
    }

    #[test]
    fn restore_brings_the_old_program_back() {
        let fixture = Fixture::new(Swap::Overwrite);
        fixture.place("新程序");
        fixture.files.install_candidate().unwrap();
        fixture.files.restore_backup().unwrap();
        assert_eq!(fixture.names(), ["i3t"]);
        assert_eq!(fixture.read("i3t"), "旧程序");
    }

    #[test]
    fn restore_by_moving_aside_leaves_the_new_program_to_be_cleaned_up_later() {
        let fixture = Fixture::new(Swap::MoveAside);
        fixture.place("新程序");
        fixture.files.install_candidate().unwrap();
        fixture.files.restore_backup().unwrap();
        assert_eq!(fixture.names(), ["i3t", "i3t.failed"]);
        assert_eq!(fixture.read("i3t"), "旧程序");
        assert_eq!(fixture.read("i3t.failed"), "新程序");
        fixture.files.remove_leftovers();
        assert_eq!(fixture.names(), ["i3t"]);
    }

    #[test]
    fn a_failed_install_leaves_the_program_as_it_was() {
        for swap in [Swap::Overwrite, Swap::MoveAside] {
            let fixture = Fixture::new(swap);
            // 没有放新程序就去换：第二步改名会失败。
            assert!(fixture.files.install_candidate().is_err());
            assert_eq!(fixture.names(), ["i3t"], "{swap:?}");
            assert_eq!(fixture.read("i3t"), "旧程序");
        }
    }

    #[test]
    fn a_failed_restore_leaves_the_program_as_it_was() {
        for swap in [Swap::Overwrite, Swap::MoveAside] {
            let fixture = Fixture::new(swap);
            assert!(fixture.files.restore_backup().is_err());
            assert_eq!(fixture.names(), ["i3t"], "{swap:?}");
            assert_eq!(fixture.read("i3t"), "旧程序");
        }
    }

    #[test]
    fn a_stale_backup_or_candidate_does_not_get_in_the_way() {
        let fixture = Fixture::new(Swap::NATIVE);
        fs::write(fixture.files.backup(), "更早的备份").unwrap();
        fs::write(fixture.files.candidate(), "上次没换上去的").unwrap();
        fixture.place("新程序");
        fixture.files.install_candidate().unwrap();
        assert_eq!(fixture.read("i3t"), "新程序");
        assert_eq!(fixture.read("i3t.old"), "旧程序");
    }

    #[cfg(unix)]
    #[test]
    fn candidate_gets_the_permissions_of_the_running_program() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new(Swap::Overwrite);
        fs::set_permissions(fixture.files.program(), fs::Permissions::from_mode(0o750)).unwrap();
        fixture.place("新程序");
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&fixture.files.candidate()), 0o750);
        fixture.files.install_candidate().unwrap();
        assert_eq!(mode(fixture.files.program()), 0o750);
    }
}
