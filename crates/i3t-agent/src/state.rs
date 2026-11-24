//! 节点的本地状态目录。
//!
//! | 文件 | 内容 |
//! |---|---|
//! | `node.key` | 节点私钥，PKCS#8 的 PEM，只有属主可读 |
//! | `controller.json` | controller 的地址和公钥，注册时从令牌里得到 |
//! | `config.toml` | 使用者手改的配置，见 [`crate::config`] |
//! | `netmap.json` | 最后一份成功应用的 netmap。controller 离线时节点按该配置继续运行 |
//! | `local.json` | 正在运行的节点的本机状态接口在哪里、凭什么问它。节点启动时写，退出时删 |
//! | `ports.json` | 配置端口为 0 的端口转发所分配的监听端口，按转发编号记录，重启后继续使用 |
//! | `quota.json` | 本节点作为出口时本账期的流量用量，重启后继续累计 |
//! | `update/` | 归 `i3t-update` 管：取了一半的更新包、待确认的版本、失败过的版本 |
//!
//! 所有文件都是先写临时文件再改名，所以断电不会留下写了一半的文件。
//!
//! 目录和里面的文件只有属主能访问：Unix 上是 0700 和 0600；Windows 上是 SYSTEM、Administrators，进程令牌中
//! Administrators 组未启用时，或状态目录位于当前账户自己的目录（例如 `%LOCALAPPDATA%`）中时，再加上当前账户
//! （见 [`windows`]）。

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use i3t_crypto::NodeKey;
use i3t_model::Netmap;
use i3t_proto::PublicKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::texts::texts;

#[cfg(windows)]
mod windows;

const KEY_FILE: &str = "node.key";
const CONTROLLER_FILE: &str = "controller.json";
const CONFIG_FILE: &str = "config.toml";
const NETMAP_FILE: &str = "netmap.json";
const LOCAL_FILE: &str = "local.json";
const PORTS_FILE: &str = "ports.json";
const QUOTA_FILE: &str = "quota.json";

/// 节点默认绑定的端口。
pub const DEFAULT_PORT: u16 = 20330;

/// 出口本账期的流量用量，持久化保存以供重启后继续统计。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct QuotaRecord {
    /// 这份用量属于哪个账期：账期开始的时刻，Unix 秒。
    pub period_start: u64,
    pub used_bytes: u64,
}

/// 到哪里找 controller，以及凭什么确认连上的是它。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerInfo {
    /// `主机:端口`，主机可以是域名。
    pub address: String,
    pub key: PublicKey,
}

/// 正在运行的节点的本机状态接口：地址，和问它要带的令牌。
///
/// 这个文件和节点私钥放在同一个目录里、权限一样，所以"谁能问节点的状态"和"谁能读节点的私钥"是同一批人：
/// 运行节点的那个用户（和 root；Windows 上是 SYSTEM 和 Administrators）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalEndpoint {
    pub addr: std::net::SocketAddr,
    pub token: String,
}

/// 令牌不能进日志。
impl std::fmt::Debug for LocalEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalEndpoint").field("addr", &self.addr).finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// 打开状态目录，不存在则创建（仅属主可访问）。
    ///
    /// # Errors
    ///
    /// 状态目录创建或权限设置失败；Windows 上还有：已有的目录属主不可信，或者别的账户能写。
    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        let root = without_trailing_separator(&root).with_context(|| (texts().create_state_dir)(&root))?;
        ensure_not_reparse_or_symlink(&root).with_context(|| (texts().create_state_dir)(&root))?;
        make_private_dir(&root)?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// 读取节点私钥；尚不存在时返回 `None`。
    ///
    /// # Errors
    ///
    /// 文件读取失败，或内容不是有效的节点私钥。
    pub fn key(&self) -> anyhow::Result<Option<NodeKey>> {
        let path = self.root.join(KEY_FILE);
        ensure_not_reparse_or_symlink(&path).with_context(|| (texts().read_key)(&path))?;
        match fs::read_to_string(&path) {
            Ok(pem) => Ok(Some(NodeKey::from_pem(&pem).with_context(|| (texts().parse_key)(&path))?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| (texts().read_key)(&path)),
        }
    }

    /// 读取节点私钥；尚不存在时生成新私钥并保存。
    ///
    /// # Errors
    ///
    /// 同 [`key`](Self::key)，以及生成或写入失败。
    pub fn key_or_generate(&self) -> anyhow::Result<NodeKey> {
        if let Some(key) = self.key()? {
            return Ok(key);
        }
        let key = NodeKey::generate().context(texts().generate_key)?;
        self.write(KEY_FILE, key.to_pem().as_bytes())?;
        Ok(key)
    }

    /// # Errors
    ///
    /// 文件读取或解析失败。
    pub fn controller(&self) -> anyhow::Result<Option<ControllerInfo>> {
        self.read_json(CONTROLLER_FILE)
    }

    /// # Errors
    ///
    /// 写入失败。
    pub fn save_controller(&self, controller: &ControllerInfo) -> anyhow::Result<()> {
        self.write_json(CONTROLLER_FILE, controller)
    }

    /// 配置文件默认放在状态目录里。
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }

    /// # Errors
    ///
    /// 文件读取或解析失败。
    pub fn netmap(&self) -> anyhow::Result<Option<Netmap>> {
        self.read_json(NETMAP_FILE)
    }

    /// # Errors
    ///
    /// 写入失败。
    pub fn save_netmap(&self, netmap: &Netmap) -> anyhow::Result<()> {
        self.write_json(NETMAP_FILE, netmap)
    }

    /// 正在运行的节点留下的本机状态接口；无节点运行（或启动状态接口失败）时返回 `None`。
    ///
    /// # Errors
    ///
    /// 文件读取或解析失败。
    pub fn local(&self) -> anyhow::Result<Option<LocalEndpoint>> {
        self.read_json(LOCAL_FILE)
    }

    /// # Errors
    ///
    /// 写入失败。
    pub fn save_local(&self, local: &LocalEndpoint) -> anyhow::Result<()> {
        self.write_json(LOCAL_FILE, local)
    }

    /// 节点退出时删除本机状态接口记录。文件不存在时不执行任何操作。
    ///
    /// # Errors
    ///
    /// 文件存在但删除失败。
    pub fn remove_local(&self) -> anyhow::Result<()> {
        let path = self.root.join(LOCAL_FILE);
        ensure_not_reparse_or_symlink(&path).with_context(|| format!("删除 {}", path.display()))?;
        match fs::remove_file(&path) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err).with_context(|| format!("删除 {}", path.display())),
            _ => Ok(()),
        }
    }

    /// 配置端口为 0 的端口转发所分配的监听端口：转发编号 → 端口号。
    ///
    /// # Errors
    ///
    /// 文件读取或解析失败。
    pub fn forward_ports(&self) -> anyhow::Result<BTreeMap<u32, u16>> {
        Ok(self.read_json(PORTS_FILE)?.unwrap_or_default())
    }

    /// # Errors
    ///
    /// 写入失败。
    pub fn save_forward_ports(&self, ports: &BTreeMap<u32, u16>) -> anyhow::Result<()> {
        self.write_json(PORTS_FILE, ports)
    }

    /// 上次保存的出口配额用量；从未保存过时返回 `None`。
    ///
    /// # Errors
    ///
    /// 文件读取或解析失败。
    pub fn exit_quota(&self) -> anyhow::Result<Option<QuotaRecord>> {
        self.read_json(QUOTA_FILE)
    }

    /// # Errors
    ///
    /// 写入失败。
    pub fn save_exit_quota(&self, quota: &QuotaRecord) -> anyhow::Result<()> {
        self.write_json(QUOTA_FILE, quota)
    }

    fn read_json<T: DeserializeOwned>(&self, name: &str) -> anyhow::Result<Option<T>> {
        let path = self.root.join(name);
        ensure_not_reparse_or_symlink(&path).with_context(|| format!("读 {}", path.display()))?;
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).with_context(|| format!("解析 {}", path.display()))?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("读 {}", path.display())),
        }
    }

    fn write_json<T: Serialize>(&self, name: &str, value: &T) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(value).with_context(|| format!("序列化 {name}"))?;
        self.write(name, &bytes)
    }

    /// 先写临时文件再改名。目录里的文件一律只有属主可读：除了私钥，netmap 里也有对端的地址。
    fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        let path = self.root.join(name);
        let temporary = self.root.join(format!("{name}.tmp"));
        let result = (|| -> io::Result<()> {
            ensure_real_directory(&self.root)?;
            ensure_not_reparse_or_symlink(&path)?;
            ensure_not_reparse_or_symlink(&temporary)?;
            match fs::remove_file(&temporary) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
            let mut file = create_owner_only(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)
        })();
        result.with_context(|| format!("写 {}", path.display()))
    }
}

/// 去掉末尾的分隔符和 `.`（根目录本身保留）：带着它们时系统会跟随最后一级的符号链接或重解析点，检查看到的
/// 将是链接所指的目录而不是链接本身。Windows 上先按系统打开文件时的规则展开为绝对路径，最后一级末尾的空格和点
/// 随之去掉，否则 `i3t\ ` 交给系统时仍以分隔符结尾。
fn without_trailing_separator(root: &Path) -> io::Result<PathBuf> {
    #[cfg(windows)]
    let root = &std::path::absolute(root)?;
    Ok(root.components().collect())
}

/// 拒绝符号链接以及 Windows 重解析点（含 NTFS Junction），防止被诱导跨目录读写或删改。
pub(crate) fn ensure_not_reparse_or_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => check_not_reparse_or_symlink(&meta),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// 确认路径是真实目录（既不是符号链接也不是重解析点）。
fn ensure_real_directory(path: &Path) -> io::Result<()> {
    check_real_directory(&fs::symlink_metadata(path)?)
}

fn check_real_directory(meta: &fs::Metadata) -> io::Result<()> {
    check_not_reparse_or_symlink(meta)?;
    if !meta.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "状态目录路径不是目录"));
    }
    Ok(())
}

fn check_not_reparse_or_symlink(meta: &fs::Metadata) -> io::Result<()> {
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "拒绝跟随符号链接"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "拒绝跟随重解析点"));
        }
    }
    Ok(())
}

/// 建出状态目录，或者确认已有的那个能用并收紧它的权限。
#[cfg(unix)]
fn make_private_dir(root: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(root).with_context(|| (texts().create_state_dir)(root))?;
    ensure_real_directory(root).with_context(|| (texts().restrict_state_dir)(root))?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).with_context(|| (texts().restrict_state_dir)(root))
}

/// 建出状态目录，或者确认已有的那个能用并收紧它的权限。上级目录照常继承；状态目录本身连同访问控制一起建，
/// 而不是先建出再修改：两步之间该目录使用继承的权限，其他用户可在其中放入文件。
#[cfg(windows)]
fn make_private_dir(root: &Path) -> anyhow::Result<()> {
    if let Some(parent) = root.parent() {
        fs::create_dir_all(parent).with_context(|| (texts().create_state_dir)(root))?;
    }
    if windows::create_private_dir(root).with_context(|| (texts().create_state_dir)(root))? {
        return Ok(());
    }
    ensure_real_directory(root).with_context(|| (texts().restrict_state_dir)(root))?;
    windows::secure_existing_dir(root).with_context(|| (texts().restrict_state_dir)(root))
}

/// 新建一个只有属主能读写的文件，已经有了就失败：不跟随竞态中放进来的链接。
#[cfg(unix)]
fn create_owner_only(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

/// 新建一个只有可信的账户能访问的文件，已经有了就失败：不跟随竞态中放进来的重解析点。访问控制在建的同时设上，
/// 不靠目录的继承。
#[cfg(windows)]
fn create_owner_only(path: &Path) -> io::Result<fs::File> {
    windows::create_private_file(path)
}

/// 新建配置文件，已经有了就失败。Unix 上照旧按 umask，靠 0700 的状态目录挡住别人；Windows 上和目录里别的文件一样，
/// 只给可信的账户。
pub(crate) fn create_config_file(path: &Path) -> io::Result<fs::File> {
    if cfg!(windows) { create_owner_only(path) } else { fs::OpenOptions::new().write(true).create_new(true).open(path) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> (tempfile::TempDir, StateDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path().join("i3t")).unwrap();
        (dir, state)
    }

    #[test]
    fn key_is_generated_once_and_then_reused() {
        let (_dir, state) = state();
        assert!(state.key().unwrap().is_none());
        let first = state.key_or_generate().unwrap().public();
        let second = state.key_or_generate().unwrap().public();
        assert_eq!(first, second);
        assert_eq!(state.key().unwrap().unwrap().public(), first);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_and_directory_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, state) = state();
        state.key_or_generate().unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&state.path().join(KEY_FILE)), 0o600);
        assert_eq!(mode(state.path()), 0o700);
    }

    #[test]
    fn controller_info_is_absent_until_saved_and_survives_reopening() {
        let (_dir, state) = state();
        assert_eq!(state.controller().unwrap(), None);
        let controller = ControllerInfo { address: "ctl.example.com:20331".to_owned(), key: PublicKey::from_bytes([5; 32]) };
        state.save_controller(&controller).unwrap();
        let reopened = StateDir::open(state.path()).unwrap();
        assert_eq!(reopened.controller().unwrap(), Some(controller));
    }

    #[test]
    fn the_local_endpoint_record_is_private_and_goes_away_cleanly() {
        let (_dir, state) = state();
        assert_eq!(state.local().unwrap(), None);
        state.remove_local().unwrap();
        let local = LocalEndpoint { addr: "127.0.0.1:40123".parse().unwrap(), token: "s3cret-token".to_owned() };
        state.save_local(&local).unwrap();
        assert_eq!(state.local().unwrap(), Some(local.clone()));
        assert!(!format!("{local:?}").contains("s3cret-token"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(state.path().join(LOCAL_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        state.remove_local().unwrap();
        assert_eq!(state.local().unwrap(), None);
    }

    #[test]
    fn a_corrupt_file_is_an_error_not_a_silent_default() {
        let (_dir, state) = state();
        fs::write(state.path().join(CONTROLLER_FILE), b"{ not json").unwrap();
        assert!(state.controller().is_err());
        fs::write(state.path().join(KEY_FILE), b"garbage").unwrap();
        assert!(state.key().is_err());
    }

    #[test]
    fn forward_ports_and_the_exit_quota_survive_reopening() {
        let (_dir, state) = state();
        assert!(state.forward_ports().unwrap().is_empty());
        assert_eq!(state.exit_quota().unwrap(), None);
        state.save_forward_ports(&BTreeMap::from([(7, 41_000), (9, 41_001)])).unwrap();
        let quota = QuotaRecord { period_start: 1_794_787_200, used_bytes: 12_345 };
        state.save_exit_quota(&quota).unwrap();
        let reopened = StateDir::open(state.path()).unwrap();
        assert_eq!(reopened.forward_ports().unwrap(), BTreeMap::from([(7, 41_000), (9, 41_001)]));
        assert_eq!(reopened.exit_quota().unwrap(), Some(quota));
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let (_dir, state) = state();
        let controller = ControllerInfo { address: "c:1".to_owned(), key: PublicKey::from_bytes([5; 32]) };
        state.save_controller(&controller).unwrap();
        let names: Vec<_> = fs::read_dir(state.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(names, [CONTROLLER_FILE]);
    }

    #[cfg(windows)]
    #[test]
    fn the_state_directory_and_its_files_are_private_on_windows() {
        use windows::tests::{access_of, grants_me, me, owner_of, privileged};

        let (dir, state) = state();
        state.key_or_generate().unwrap();
        state.save_local(&LocalEndpoint { addr: "127.0.0.1:40123".parse().unwrap(), token: "s3cret-token".to_owned() }).unwrap();
        state.save_forward_ports(&BTreeMap::from([(7, 41_000)])).unwrap();
        crate::config::Config::write_template_if_missing(&state.config_path()).unwrap();
        // Administrators 组已启用时属主是 Administrators，不随「默认所有者」策略变成管理员本人；否则是当前账户。
        let owner = if privileged() { "S-1-5-32-544".to_owned() } else { me() };
        // 临时目录在当前账户自己的用户配置目录中，已提权时同样另给当前账户，未提权的同一账户仍可访问。
        let mine = !privileged() || grants_me(dir.path());
        for path in [
            state.path().to_owned(),
            state.path().join(KEY_FILE),
            state.path().join(LOCAL_FILE),
            state.path().join(PORTS_FILE),
            state.config_path(),
        ] {
            assert_eq!(access_of(&path), (true, true), "{}", path.display());
            assert_eq!(owner_of(&path), owner, "{}", path.display());
            assert_eq!(grants_me(&path), mine, "{}", path.display());
        }
        // 日志、更新自己新建的文件和目录继承状态目录的。
        fs::create_dir(state.path().join("update")).unwrap();
        fs::write(state.path().join("update").join("state.json"), "{}").unwrap();
        assert!(access_of(&state.path().join("update").join("state.json")).1);
    }

    #[cfg(windows)]
    #[test]
    fn an_existing_directory_other_users_can_write_to_is_not_used() {
        use windows::tests::{access_of, make_dir_with, me};

        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("i3t");
        // C:\ProgramData 下面直接新建的目录就是这样：Users 能读，还能在里面新建文件和目录。
        let me = me();
        make_dir_with(&root, &format!("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)"));
        let error = StateDir::open(&root).unwrap_err();
        assert!(format!("{error:#}").contains("S-1-5-32-545"), "{error:#}");
        assert_eq!(access_of(&root), (false, false), "不能用的目录原样不动");
    }

    #[cfg(windows)]
    #[test]
    fn an_existing_directory_other_users_can_only_read_is_tightened_with_everything_inside() {
        use windows::tests::{access_of, grants_me, make_dir_with, me};

        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("i3t");
        let me = me();
        make_dir_with(&root, &format!("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})(A;OICI;0x1200a9;;;BU)"));
        fs::write(root.join(CONTROLLER_FILE), "{}").unwrap();
        fs::create_dir(root.join("update")).unwrap();
        fs::write(root.join("update").join("state.json"), "{}").unwrap();
        let inside = [root.clone(), root.join(CONTROLLER_FILE), root.join("update"), root.join("update").join("state.json")];
        for path in &inside {
            assert!(!access_of(path).1, "{} 起初 Users 能读", path.display());
        }
        StateDir::open(&root).unwrap();
        for path in &inside {
            assert_eq!(access_of(path), (true, true), "{}", path.display());
            // 旧版本在用户配置目录中留下的目录：已提权收紧后，同一账户未提权运行时仍可访问。
            assert!(grants_me(path), "{}", path.display());
        }
        StateDir::open(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn an_elevated_node_gives_a_place_that_is_not_its_accounts_own_to_system_and_administrators_only() {
        use windows::tests::{access_of, grants_me, make_dir_with, privileged};

        if !privileged() {
            return;
        }
        // 与 %ProgramData% 一样，上级目录没有按 SID 给当前账户的项。
        let outer = tempfile::tempdir().unwrap();
        let machine = outer.path().join("machine");
        make_dir_with(&machine, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        let state = StateDir::open(machine.join("i3t")).unwrap();
        state.key_or_generate().unwrap();
        for path in [state.path().to_owned(), state.path().join(KEY_FILE)] {
            assert_eq!(access_of(&path), (true, true), "{}", path.display());
            assert!(!grants_me(&path), "{}", path.display());
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_state_directory_with_a_long_path_works() {
        let outer = tempfile::tempdir().unwrap();
        let deep = outer.path().join("a".repeat(100)).join("b".repeat(100));
        fs::create_dir_all(&deep).unwrap();
        let root = deep.join("i3t");
        assert!(root.as_os_str().len() >= 248, "{}", root.display());
        let state = StateDir::open(&root).unwrap();
        state.key_or_generate().unwrap();
        state.save_controller(&ControllerInfo { address: "c:1".to_owned(), key: PublicKey::from_bytes([5; 32]) }).unwrap();
        crate::config::Config::write_template_if_missing(&state.config_path()).unwrap();
        assert!(StateDir::open(&root).unwrap().key().unwrap().is_some());
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_inside_an_existing_directory_is_not_followed() {
        use windows::tests::{access_of, make_dir_with, me};

        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("i3t");
        let elsewhere = outer.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::write(elsewhere.join("secret"), "x").unwrap();
        let me = me();
        make_dir_with(&root, &format!("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})(A;OICI;0x1200a9;;;BU)"));
        // 建目录联接不要特权。
        let output =
            std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(root.join("update")).arg(&elsewhere).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(StateDir::open(&root).is_err());
        assert!(!access_of(&root).0, "不能用的目录原样不动");
        assert!(!access_of(&elsewhere.join("secret")).0, "联接那头的东西没有被改");
    }

    #[cfg(windows)]
    #[test]
    fn a_trailing_separator_does_not_make_a_junction_usable_as_the_state_directory() {
        use windows::tests::access_of;

        let outer = tempfile::tempdir().unwrap();
        let elsewhere = outer.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let link = outer.path().join("i3t");
        let output = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(&link).arg(&elsewhere).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let link = link.display();
        for spelled in [format!("{link}\\"), format!("{link}/"), format!("{link}\\."), format!("{link}\\ "), format!("{link}\\...")] {
            assert!(StateDir::open(&spelled).is_err(), "{spelled}");
        }
        assert!(!access_of(&elsewhere).0, "联接所指的目录未被收紧");
        assert!(fs::read_dir(&elsewhere).unwrap().next().is_none(), "联接所指的目录中未写入任何文件");
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_and_files_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let outer = tempfile::tempdir().unwrap();
        let real = outer.path().join("real");
        fs::create_dir(&real).unwrap();
        let link_dir = outer.path().join("link");
        symlink(&real, &link_dir).unwrap();
        assert!(StateDir::open(&link_dir).is_err(), "拒绝打开符号链接作为状态目录");

        let (_dir, state) = state();
        let decoy = outer.path().join("decoy");
        fs::write(&decoy, "untouched").unwrap();
        symlink(&decoy, state.path().join(format!("{CONTROLLER_FILE}.tmp"))).unwrap();
        let controller = ControllerInfo { address: "c:1".to_owned(), key: PublicKey::from_bytes([5; 32]) };
        assert!(state.save_controller(&controller).is_err(), "拒绝写入符号链接临时文件");
        assert_eq!(fs::read_to_string(&decoy).unwrap(), "untouched");

        symlink(&decoy, state.path().join(LOCAL_FILE)).unwrap();
        assert!(state.local().is_err(), "拒绝读取指向外部的符号链接");
        assert!(state.remove_local().is_err(), "拒绝删除指向外部的符号链接");
        assert!(decoy.exists());

        symlink(&decoy, state.path().join(KEY_FILE)).unwrap();
        assert!(state.key().is_err(), "拒绝读取符号链接私钥文件");
    }

    #[cfg(unix)]
    #[test]
    fn a_trailing_separator_does_not_make_a_symlink_usable_as_the_state_directory() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let outer = tempfile::tempdir().unwrap();
        let real = outer.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
        let link = outer.path().join("link");
        symlink(&real, &link).unwrap();
        let link = link.display();
        for spelled in [format!("{link}/"), format!("{link}//"), format!("{link}/.")] {
            assert!(StateDir::open(&spelled).is_err(), "{spelled}");
        }
        assert_eq!(fs::metadata(&real).unwrap().permissions().mode() & 0o777, 0o755, "链接所指的目录权限未被改动");
    }
}
