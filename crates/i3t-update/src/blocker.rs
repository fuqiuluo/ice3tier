//! 检测当前节点是否支持自动更新。
//!
//! 判断策略保持保守，宁可漏判也不做猜测：漏判仅会导致在 WebUI 中点击“立即更新”时返回明确错误，
//! 而误判会将原本可自动更新的节点标记为不可更新。按以下三项依次检查：
//!
//! 1. **容器环境**（仅限 Linux）：存在 `/.dockerenv`（Docker）或 `/run/.containerenv`（Podman），
//!    或设置了 `KUBERNETES_SERVICE_HOST`（Kubernetes）或非空的 `container` 环境变量（Podman、systemd-nspawn 等会设置）。
//!    在类似虚拟机使用的系统容器（LXC）中，服务进程看不到这些标记，按普通主机处理：其文件系统持久存在，可以正常自动更新。
//! 2. **包管理器安装**：仅根据可执行文件路径判断。位于 `/usr` 下（`/usr/local` 除外）、`/bin`、`/sbin`、`/nix/store`、`/snap`、
//!    `/opt/homebrew`、`/home/linuxbrew` 中，或路径包含名为 `Cellar`、`WindowsApps`、`WinGet`、`scoop`、`chocolatey` 的目录组件。
//!    不查询 dpkg 或 rpm。
//! 3. **目录不可写**：在可执行文件所在目录实际创建临时文件以探测写入权限。只读挂载、权限不足、服务单元保护选项均需通过实际写入检测。

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use i3t_model::update::SelfUpdateBlocker;

/// 存在这些文件即视为运行在容器环境中。
const CONTAINER_MARKER_FILES: [&str; 2] = ["/.dockerenv", "/run/.containerenv"];

/// 设置了这些非空环境变量即视为运行在容器环境中。
const CONTAINER_MARKER_VARS: [&str; 2] = ["KUBERNETES_SERVICE_HOST", "container"];

/// 由包管理器管理的安装根目录。
const MANAGED_ROOTS: [&str; 7] = ["/usr", "/bin", "/sbin", "/nix/store", "/snap", "/opt/homebrew", "/home/linuxbrew"];

/// `/usr` 下供手动安装使用的子目录。
const UNMANAGED_ROOT: &str = "/usr/local";

/// 路径中包含这些目录名时，视为由包管理器安装（Homebrew、Windows 应用商店、winget、Scoop、Chocolatey）。
const MANAGED_DIR_NAMES: [&str; 5] = ["Cellar", "WindowsApps", "WinGet", "scoop", "chocolatey"];

/// 获取当前运行的可执行文件的规范路径（已解析符号链接）。
///
/// 应在进程启动时立即调用并保存结果：可执行文件被替换后，系统返回的当前程序路径可能不再指向原位置。
///
/// # Errors
///
/// 无法获取或规范化当前可执行文件路径时返回错误。
pub fn current_program() -> io::Result<PathBuf> {
    std::env::current_exe()?.canonicalize()
}

/// 检测当前节点无法自动更新的原因；支持自动更新时返回 `None`。`program` 为 [`current_program`] 的返回值。
///
/// 该函数会在可执行文件所在目录创建并删除一个临时探测文件，因此仅应在启动时调用一次，并将结果上报给 controller
/// 及传入 [`UpdaterConfig::blocker`](crate::UpdaterConfig::blocker)。
#[must_use]
pub fn self_update_blocker(program: &Path) -> Option<SelfUpdateBlocker> {
    let blocker = if cfg!(target_os = "linux") && in_container(Path::exists, |name| std::env::var_os(name)) {
        Some(SelfUpdateBlocker::Container)
    } else if is_package_managed(program) {
        Some(SelfUpdateBlocker::PackageManager)
    } else if !dir_is_writable(program) {
        Some(SelfUpdateBlocker::ReadOnlyDir)
    } else {
        None
    };
    if let Some(blocker) = blocker {
        tracing::info!(program = %program.display(), reason = %blocker, "当前节点无法自动更新");
    }
    blocker
}

fn in_container(exists: impl Fn(&Path) -> bool, var: impl Fn(&str) -> Option<OsString>) -> bool {
    CONTAINER_MARKER_FILES.iter().any(|file| exists(Path::new(file)))
        || CONTAINER_MARKER_VARS.iter().any(|name| var(name).is_some_and(|value| !value.is_empty()))
}

fn is_package_managed(program: &Path) -> bool {
    let under_managed_root = MANAGED_ROOTS.iter().any(|root| program.starts_with(root)) && !program.starts_with(UNMANAGED_ROOT);
    let in_managed_dir = program.parent().is_some_and(|dir| {
        dir.components().any(|component| MANAGED_DIR_NAMES.iter().any(|name| component.as_os_str().eq_ignore_ascii_case(name)))
    });
    under_managed_root || in_managed_dir
}

fn dir_is_writable(program: &Path) -> bool {
    let Some(dir) = program.parent() else { return false };
    let probe = dir.join(format!(".i3t-update-probe-{}", std::process::id()));
    let created = OpenOptions::new().write(true).create(true).truncate(true).open(&probe).is_ok();
    if created && let Err(error) = fs::remove_file(&probe) {
        tracing::warn!(path = %probe.display(), %error, "删除目录可写性探测文件失败");
    }
    created
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_is_recognised_by_marker_files_and_variables() {
        let nothing = |_: &Path| false;
        let no_vars = |_: &str| None;
        assert!(!in_container(nothing, no_vars));
        assert!(in_container(|path| path == Path::new("/.dockerenv"), no_vars));
        assert!(in_container(|path| path == Path::new("/run/.containerenv"), no_vars));
        assert!(in_container(nothing, |name| (name == "KUBERNETES_SERVICE_HOST").then(|| OsString::from("10.0.0.1"))));
        assert!(in_container(nothing, |name| (name == "container").then(|| OsString::from("podman"))));
        assert!(!in_container(nothing, |name| (name == "container").then(OsString::new)), "空的变量不算");
        assert!(!in_container(nothing, |name| (name == "HOME").then(|| OsString::from("/root"))));
    }

    #[test]
    fn package_manager_installs_are_recognised_by_path() {
        let managed = [
            "/usr/bin/i3t",
            "/usr/sbin/i3t",
            "/usr/lib/i3t/i3t",
            "/bin/i3t",
            "/nix/store/abc123-i3t-0.2.0/bin/i3t",
            "/snap/i3t/12/bin/i3t",
            "/opt/homebrew/bin/i3t",
            "/usr/local/Cellar/i3t/0.2.0/bin/i3t",
            "/home/linuxbrew/.linuxbrew/bin/i3t",
            "/Users/me/scoop/apps/i3t/current/i3t.exe",
            "/ProgramData/Chocolatey/lib/i3t/tools/i3t.exe",
            "/Program Files/WindowsApps/i3t_1.0/i3t.exe",
        ];
        for path in managed {
            assert!(is_package_managed(Path::new(path)), "{path} 应该算包管理器装的");
        }
        let manual = [
            "/var/lib/i3t/bin/i3t",
            "/usr/local/bin/i3t",
            "/opt/i3t/i3t",
            "/home/me/bin/i3t",
            "/home/me/.local/bin/i3t",
            "/usrlocal/i3t",
            // 程序自己叫这个名字不算，要的是它上面的某一级目录。
            "/home/me/bin/scoop",
        ];
        for path in manual {
            assert!(!is_package_managed(Path::new(path)), "{path} 不应该算包管理器装的");
        }
    }

    #[test]
    fn writability_is_found_out_by_actually_writing() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("i3t");
        assert!(dir_is_writable(&program));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0, "试写的文件不应该留下");
        assert!(!dir_is_writable(&dir.path().join("missing-dir").join("i3t")));
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_blocks_self_update() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("i3t");
        fs::write(&program, "").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
        // root 不受权限位的限制，那样的环境里这一条测不出来。
        let restricted = fs::File::create(dir.path().join("probe")).is_err();
        let writable = dir_is_writable(&program);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(writable, !restricted);
    }

    #[test]
    fn the_running_test_program_has_a_real_path() {
        let program = current_program().unwrap();
        assert!(program.is_absolute() && program.is_file(), "{}", program.display());
    }
}
