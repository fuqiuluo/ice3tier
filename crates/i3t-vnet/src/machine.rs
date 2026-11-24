//! 系统交互抽象层：执行 `ip`、`nft`、`iptables`、`resolvectl`（Windows 为 `powershell`），并检测当前进程所需权限。
//!
//! 网卡防火墙规则与 DNS 解析器的安装、清理和状态探测均经由 [`Machine`] 完成，便于单元测试使用模拟实现覆盖完整流程而无需 root 权限。
//! 生产环境实现为 [`Shell`]，通过调用系统命令而非直接发送 netlink 消息：nftables 脚本具备事务性（原子全量替换或保持原状），
//! `iptables` 会自动沿用主机当前使用的后端（nftables 或传统 xtables），且报错信息直观便于排查。

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// 支持调用的外部系统程序。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Program {
    Nft,
    Ip,
    Iptables,
    Resolvectl,
    /// Windows PowerShell（`powershell.exe`），用于管理 Windows 防火墙规则。
    PowerShell,
}

impl Program {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Nft => "nft",
            Self::Ip => "ip",
            Self::Iptables => "iptables",
            Self::Resolvectl => "resolvectl",
            Self::PowerShell => "powershell",
        }
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// 执行外部命令失败时的错误类型。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// 系统中未安装该程序。
    #[error("未找到可执行程序 {0}")]
    Missing(Program),
    /// 程序已启动但以非零状态码退出。`detail` 为去除首尾空白后的标准错误输出。
    #[error("执行 {program} 失败（退出码 {status:?}）：{detail}")]
    Failed { program: Program, status: Option<i32>, detail: String },
    /// 无法启动子进程，或与子进程标准 I/O 通信失败。
    #[error("执行 {program} 出错：{detail}")]
    Io { program: Program, detail: String },
}

impl CommandError {
    /// 判断命令标准错误输出是否包含 `needle`（不区分大小写），用于识别“目标本就不存在”等可按空结果处理的场景。
    #[must_use]
    pub fn says(&self, needle: &str) -> bool {
        match self {
            Self::Failed { detail, .. } => detail.to_lowercase().contains(&needle.to_lowercase()),
            Self::Missing(_) | Self::Io { .. } => false,
        }
    }

    /// 判断探测防火墙配置时的失败是否表明目标类别在系统中本就不存在，从而按空结果而非读取失败处理：
    /// 包括对应程序未安装，或目标表不存在（例如内核未加载 `raw` 表模块，或容器环境中 `iptables` 提示 "Table does not exist"）。
    /// 权限不足等错误不在此列。
    #[must_use]
    pub fn means_absent(&self) -> bool {
        match self {
            Self::Missing(_) => true,
            Self::Failed { .. } => self.says("does not exist"),
            Self::Io { .. } => false,
        }
    }
}

/// 外部命令执行环境抽象。生产实现为 [`Shell`]，单元测试可注入模拟实现。
pub trait Machine {
    /// 执行 `program args…`，将 `input` 写入其标准输入，成功时返回标准输出。
    ///
    /// # Errors
    ///
    /// 程序不存在、启动失败或以非零退出码结束时返回错误。
    fn run(&mut self, program: Program, args: &[String], input: Option<&str>) -> Result<String, CommandError>;
}

/// 真实系统命令执行器：在 `PATH` 及常见系统目录下查找并执行外部程序。
///
/// 系统服务环境的 `PATH` 通常包含 `/usr/sbin`，而普通用户 shell 可能不包含，因此额外搜索常见系统目录；Windows 额外搜索 `System32`。
#[derive(Debug, Clone, Copy, Default)]
pub struct Shell;

/// 除 `PATH` 外的补充搜索目录。
#[cfg(unix)]
fn system_dirs() -> Vec<PathBuf> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"].into_iter().map(PathBuf::from).collect()
}

#[cfg(not(unix))]
fn system_dirs() -> Vec<PathBuf> {
    let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    vec![root.join("System32"), root.join(r"System32\WindowsPowerShell\v1.0")]
}

impl Shell {
    /// 查找可执行文件的完整路径；未找到时返回 `None`。
    #[must_use]
    pub fn locate(program: Program) -> Option<PathBuf> {
        let from_path = std::env::var_os("PATH").map(|path| std::env::split_paths(&path).collect::<Vec<_>>()).unwrap_or_default();
        let file = format!("{}{}", program.name(), std::env::consts::EXE_SUFFIX);
        from_path.into_iter().chain(system_dirs()).map(|dir| dir.join(&file)).find(|path| is_executable(path))
    }
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata().is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

impl Machine for Shell {
    fn run(&mut self, program: Program, args: &[String], input: Option<&str>) -> Result<String, CommandError> {
        let path = Self::locate(program).ok_or(CommandError::Missing(program))?;
        let io = |error: std::io::Error| CommandError::Io { program, detail: error.to_string() };
        let mut child = Command::new(path)
            .args(args)
            // 强制使用 C locale，确保命令输出格式固定以便稳定解析，不受系统语言环境影响。
            .env("LC_ALL", "C")
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(io)?;
        if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
            stdin.write_all(text.as_bytes()).map_err(io)?;
        }
        let output = child.wait_with_output().map_err(io)?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        Err(CommandError::Failed {
            program,
            status: output.status.code(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

/// 虚拟网卡功能所需的 Linux 进程能力（Capabilities）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// 创建虚拟网卡、配置地址及修改防火墙规则；缺少该能力时无法启用虚拟网卡。
    NetAdmin,
    /// 绑定 1024 以下特权端口（名称服务监听 53 端口，见 [`DNS_PORT`](crate::DNS_PORT)）；缺少时仍可启用网卡，但内置名称服务不可用。
    NetBindService,
}

impl Capability {
    pub const ALL: [Self; 2] = [Self::NetAdmin, Self::NetBindService];

    /// 内核能力位编号（定义于 `linux/capability.h`）。
    const fn bit(self) -> u32 {
        match self {
            Self::NetAdmin => 12,
            Self::NetBindService => 10,
        }
    }

    /// 返回能力名称（与 systemd `AmbientCapabilities=` 格式一致）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NetAdmin => "CAP_NET_ADMIN",
            Self::NetBindService => "CAP_NET_BIND_SERVICE",
        }
    }

    /// 查询当前进程缺失的能力列表。无法读取 `/proc/self/status`（如非 Linux 平台）时一律视为全部缺失。
    #[must_use]
    pub fn missing() -> Vec<Self> {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        Self::missing_in(&status)
    }

    /// 解析 `/proc/<pid>/status` 内容中的 `CapEff` 位图，返回缺失的能力列表。
    fn missing_in(status: &str) -> Vec<Self> {
        let effective = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            .unwrap_or(0);
        Self::ALL.into_iter().filter(|capability| effective & (1 << capability.bit()) == 0).collect()
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// 检查创建虚拟网卡是否缺少所需权限，返回用于提示的权限名称：Linux 为 `CAP_NET_ADMIN`，Windows 为 `Administrator`（需以管理员身份运行），
/// macOS 为 `root`；权限满足时返回 `None`，无法判断的平台默认视为缺失。
#[must_use]
pub fn missing_privilege() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Capability::missing().contains(&Capability::NetAdmin).then_some(Capability::NetAdmin.name())
    } else if cfg!(windows) {
        (!elevated()).then_some("Administrator")
    } else {
        (!is_root()).then_some("root")
    }
}

#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: geteuid 无参数且不会失败，仅读取当前进程的有效用户 ID。
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Windows：检测当前进程令牌是否已提权（以管理员身份运行）。无法读取时按未提权处理。
#[cfg(windows)]
fn elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess 返回无需关闭的伪句柄；`token` 为局部变量，调用成功后由系统写入需关闭的令牌句柄。
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut written = 0u32;
    let size = u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).expect("TOKEN_ELEVATION 大小固定为 4 字节");
    // SAFETY: `token` 为已打开且具查询权限的句柄；缓冲区为有效的 TOKEN_ELEVATION 实例，大小与结构长度一致。
    let ok = unsafe { GetTokenInformation(token, TokenElevation, (&raw mut elevation).cast(), size, &raw mut written) } != 0;
    // SAFETY: `token` 由 OpenProcessToken 返回，此处仅关闭一次。
    unsafe { CloseHandle(token) };
    ok && elevation.TokenIsElevated != 0
}

#[cfg(not(windows))]
fn elevated() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_capabilities_are_read_from_the_status_file() {
        let root = "Name:\ti3t\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\n";
        assert_eq!(Capability::missing_in(root), []);
        let plain = "CapEff:\t0000000000000000\n";
        assert_eq!(Capability::missing_in(plain), [Capability::NetAdmin, Capability::NetBindService]);
        // systemd 的 AmbientCapabilities=CAP_NET_ADMIN：只有第 12 位。
        let admin_only = "CapEff:\t0000000000001000\n";
        assert_eq!(Capability::missing_in(admin_only), [Capability::NetBindService]);
        assert_eq!(Capability::missing_in(""), Capability::ALL, "读不出来时一律算缺");
    }

    #[test]
    fn a_failure_can_be_matched_by_what_the_program_said() {
        let error = CommandError::Failed { program: Program::Ip, status: Some(2), detail: "Error: ipv4: FIB table does not exist.".into() };
        assert!(error.says("fib table does not exist"));
        assert!(!CommandError::Missing(Program::Ip).says("does not exist"));
    }

    #[test]
    fn a_missing_program_or_table_means_nothing_is_there_and_a_refusal_does_not() {
        let failed = |detail: &str| CommandError::Failed { program: Program::Iptables, status: Some(3), detail: detail.into() };
        assert!(CommandError::Missing(Program::Nft).means_absent());
        assert!(
            failed("iptables v1.8.9 (legacy): can't initialize iptables table `raw': Table does not exist (do you need to insmod?)")
                .means_absent()
        );
        assert!(
            !failed("iptables v1.8.9 (legacy): can't initialize iptables table `raw': Permission denied (you must be root)").means_absent()
        );
        assert!(!CommandError::Io { program: Program::Iptables, detail: "broken pipe".into() }.means_absent());
    }

    #[cfg(unix)]
    #[test]
    fn programs_are_found_on_the_path_or_in_the_system_directories() {
        let mut shell = Shell;
        let version = shell.run(Program::Nft, &["--version".into()], None);
        match Shell::locate(Program::Nft) {
            Some(_) => assert!(version.unwrap().contains("nftables")),
            None => assert_eq!(version, Err(CommandError::Missing(Program::Nft)), "没有这个程序要说出来"),
        }
        let wrong = shell.run(Program::Ip, &["no-such-object".into()], None);
        match Shell::locate(Program::Ip) {
            Some(path) => {
                assert!(path.ends_with("ip"));
                assert!(matches!(wrong, Err(CommandError::Failed { program: Program::Ip, .. })), "报错退出要带着它说的话：{wrong:?}");
            }
            None => assert_eq!(wrong, Err(CommandError::Missing(Program::Ip))),
        }
    }
}
