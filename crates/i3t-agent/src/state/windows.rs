//! Windows 上状态目录的访问控制。
//!
//! Unix 上状态目录是 0700、里面的文件是 0600。Windows 上新建的目录和文件默认继承上级目录的访问控制，而
//! `C:\ProgramData` 让本机所有用户都能读，还能在里面新建文件和目录。所以这里不靠继承：
//!
//! - 目录和文件都用受保护（不继承上级）的访问控制列表，给 SYSTEM 和 Administrators，与 `deploy/install.ps1` 给
//!   `%ProgramData%\i3t` 设的一致。进程令牌中 Administrators 组未启用时（未提权的管理员、普通用户、不属于该组的
//!   服务账户）另加当前账户，否则进程自身无法访问；组已启用时，状态目录位于当前账户自己的目录中（例如
//!   `%LOCALAPPDATA%`）也另加当前账户，见 [`Account::grantees_in`]。
//! - 目录不存在时连同访问控制一起建出来，中间没有一段时间用着继承来的权限。
//! - 目录已经存在时先查：属主不是 SYSTEM、Administrators 或当前用户，或者别的账户能写、能改它的权限，就不用它。
//!   别人可能已经改过里面的 `controller.json`、`config.toml`，这时再收紧权限也晚了。查过没问题、但还有别的账户能读
//!   （例如继承来的 `Users` 读权限）或者还继承着上级目录的权限时，收紧目录和里面的每一项。
//! - 卷不保存访问控制（FAT、exFAT）时不查也不改。

use std::ffi::{OsStr, c_void};
use std::fs::{self, File};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WIN32_ERROR};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL, CheckTokenMembership, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, GetVolumeInformationByHandleW, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    FILE_PERSISTENT_ACLS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::texts::texts;

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
/// 继承时换成新建那一项的账户，它本身不给谁权限。
const CREATOR_OWNER: &str = "S-1-3-0";
/// 给属主的权限，属主已经查过了。
const OWNER_RIGHTS: &str = "S-1-3-4";

/// 有其中任何一项，就能往目录里放东西、删改换掉里面的项，或者改它的访问控制和属主。
/// 和 `deploy/install.ps1` 的 `UntrustedWriteMask`（0x500D0156）是同一组。
const WRITE_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_ALL
    | GENERIC_WRITE;

/// 建出只有可信的账户能访问的目录，上级目录要已经有了。已经有这个名字时什么也不做，返回 `false`。
pub(super) fn create_private_dir(path: &Path) -> io::Result<bool> {
    let account = Account::current()?;
    let descriptor = Descriptor::from_sddl(&sddl(&account, account.grantees_in(path.parent()), true))?;
    let attributes = security_attributes(&descriptor);
    let name = wide_path(path)?;
    // SAFETY: `name` 以 0 结尾；`attributes` 和它指向的描述符在调用期间都有效。
    if unsafe { CreateDirectoryW(name.as_ptr(), &raw const attributes) } != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if already_there(&error, path) { Ok(false) } else { Err(error) }
}

/// 建目录失败后，该名称是否已存在。不只看错误码：卷的根目录、挂载卷的目录，以及部分网络或第三方文件系统，
/// 对已存在的名称报告拒绝访问而不是已存在。已存在的项一律交由调用方检查。
fn already_there(error: &io::Error, path: &Path) -> bool {
    error.kind() == io::ErrorKind::AlreadyExists || fs::symlink_metadata(path).is_ok()
}

/// 查已经有的目录能不能用；能用但还有别的账户能读、或者还继承着上级目录的权限时，收紧它和里面的每一项。
pub(super) fn secure_existing_dir(path: &Path) -> io::Result<()> {
    let account = Account::current()?;
    let dir = open_for_acl(path)?;
    super::check_real_directory(&dir.metadata()?)?;
    if !keeps_acls(&dir) {
        return Ok(());
    }
    if verdict(&Descriptor::of(&dir)?, &account)? == Verdict::Private {
        return Ok(());
    }
    // 先把里面的每一项都查一遍、什么都不改：有一项不能用，整个目录就不用，也不留下改了一半的权限。
    let mut entries = Vec::new();
    collect(path, &account, &mut entries)?;
    let grantees = account.grantees_in(path.parent());
    let dir_dacl = Descriptor::from_sddl(&sddl(&account, grantees, true))?;
    let file_dacl = Descriptor::from_sddl(&sddl(&account, grantees, false))?;
    set_dacl(&dir, &dir_dacl)?;
    for entry in &entries {
        set_dacl(&entry.file, if entry.directory { &dir_dacl } else { &file_dacl }).map_err(|error| at(&entry.path, &error))?;
    }
    Ok(())
}

/// 新建一个只有可信的账户能访问的文件，已经有了就失败。
pub(super) fn create_private_file(path: &Path) -> io::Result<File> {
    let account = Account::current()?;
    let descriptor = Descriptor::from_sddl(&sddl(&account, account.grantees_in(path.parent()), false))?;
    let attributes = security_attributes(&descriptor);
    let path = wide_path(path)?;
    // SAFETY: `path` 以 0 结尾；`attributes` 和它指向的描述符在调用期间都有效；不用模板文件。共享方式和
    // `fs::OpenOptions` 默认的一样：文件开着也能被改名，写完之后要把它改名成正式的文件。
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 刚打开的有效句柄，交给 `File` 关闭。
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

/// 运行这个进程的账户。
#[derive(Debug)]
struct Account {
    /// 当前用户的 SID，写成 `S-1-5-…`。
    user: String,
    /// 令牌中 Administrators 组已启用（已提权的管理员、SYSTEM）：新建的项属主为 Administrators；是否另给这个账户
    /// 见 [`Account::grantees_in`]。
    privileged: bool,
}

/// 访问控制中给哪些账户。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grantees {
    /// 只给 SYSTEM 与 Administrators。
    Administrators,
    /// 另给当前账户。
    AlsoCurrent,
}

impl Account {
    fn current() -> io::Result<Self> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess 返回的伪句柄不用关闭；成功时系统把打开的令牌句柄写进局部变量 `token`。
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `token` 是刚打开的有效句柄，交给 `OwnedHandle` 关闭。
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let user = token_information(&token, TokenUser)?;
        // SAFETY: 系统在缓冲区开头写了一个 TOKEN_USER，其中的 SID 指向同一个缓冲区里面，缓冲区这时还在。
        let user = sid_string(unsafe { user.as_ptr().cast::<TOKEN_USER>().read() }.User.Sid)?;
        // 查询失败时按未启用处理：访问控制里多一个当前账户，进程不会失去对自身状态目录的访问。
        let privileged = user == SYSTEM || administrators_enabled().unwrap_or(false);
        Ok(Self { user, privileged })
    }

    /// SYSTEM、Administrators 和当前用户。
    fn trusts(&self, sid: &str) -> bool {
        sid == SYSTEM || sid == ADMINISTRATORS || sid == self.user
    }

    /// 在目录 `place` 中新建或收紧的项给哪些账户。
    ///
    /// Administrators 组未启用时必须另给当前账户，否则进程自身无法访问。组已启用时，若 `place` 的访问控制明确给
    /// 当前账户写入权限（该账户自己的目录，例如默认状态目录所在的 `%LOCALAPPDATA%`），同样另给当前账户：该账户
    /// 本可替换整个状态目录，不给它不增加安全性，只会使它未提权运行的节点和 `i3t status` 无法访问。其他位置
    /// （例如以 SYSTEM 运行的服务所用的 `%ProgramData%\i3t`）只给 SYSTEM 与 Administrators，与 `deploy/install.ps1`
    /// 一致，未提权的进程无法改动以 SYSTEM 运行的节点所读的配置。
    fn grantees_in(&self, place: Option<&Path>) -> Grantees {
        let own_place = || self.user != SYSTEM && place.is_some_and(|place| self.may_write(place));
        if !self.privileged || own_place() { Grantees::AlsoCurrent } else { Grantees::Administrators }
    }

    /// `place` 的访问控制列表中有按 SID 给当前账户（不经所属的组）写入权限的项。读取失败时按没有处理。
    fn may_write(&self, place: &Path) -> bool {
        let grants = fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(place)
            .and_then(|dir| Descriptor::of(&dir)?.grants());
        matches!(grants, Ok(Some(grants)) if grants.iter().any(|grant| grant.sid == self.user && grant.rights & WRITE_RIGHTS != 0))
    }
}

/// 进程令牌中 Administrators 组已启用。
///
/// 不以令牌是否已提权判断：Backup Operators 等组的成员提权运行时，以及以 LOCAL SERVICE、NETWORK SERVICE 或虚拟
/// 服务账户运行的服务，令牌可标为已提权，却不在 Administrators 组中，只给 SYSTEM 和 Administrators 的访问控制会使
/// 这些进程无法访问自己建的目录。未提权的管理员令牌中该组仅用于拒绝访问，同样按未启用处理。
fn administrators_enabled() -> io::Result<bool> {
    let administrators = wide(OsStr::new(ADMINISTRATORS))?;
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `administrators` 以 0 结尾；成功时系统分配 SID，地址写进 `sid`。
    if unsafe { ConvertStringSidToSidW(administrators.as_ptr(), &raw mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = Local(sid);
    let mut member = 0;
    // SAFETY: 令牌句柄为空时检查当前线程的令牌，线程未模拟其他账户时即为进程令牌；`sid` 有效；系统只往局部变量
    // `member` 里写。
    if unsafe { CheckTokenMembership(ptr::null_mut(), sid.0, &raw mut member) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(member != 0)
}

/// 令牌里的一项信息，放在按 8 字节对齐的缓冲区里。
fn token_information(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: 不给缓冲区，只问要多大；系统只往局部变量 `needed` 里写。
    unsafe { GetTokenInformation(token.as_raw_handle(), class, ptr::null_mut(), 0, &raw mut needed) };
    let mut buffer = vec![0u64; needed.div_ceil(8) as usize];
    // SAFETY: 缓冲区可写，至少有 `needed` 个字节。
    if unsafe { GetTokenInformation(token.as_raw_handle(), class, buffer.as_mut_ptr().cast(), needed, &raw mut needed) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

/// 给 SYSTEM、Administrators（`grantees` 为 [`Grantees::AlsoCurrent`] 时另给当前账户）的访问控制列表，受保护：不继承
/// 上级目录的。目录的各项让里面新建的文件和目录继承（OICI），所以节点、更新和日志后来新建的文件也是这样。
///
/// Administrators 组已启用时属主明确设为 Administrators，与 `deploy/install.ps1` 一致：本地安全策略
/// "System objects: Default owner for objects created by members of the Administrators group" 设为
/// "Object creator" 时，不指定则属主为该管理员本人，以 SYSTEM 运行的服务和其他管理员将拒绝使用该目录。
/// 组未启用时不指定，属主为当前账户。
fn sddl(account: &Account, grantees: Grantees, directory: bool) -> String {
    let inherit = if directory { "OICI" } else { "" };
    let owner = if account.privileged { "O:BA" } else { "" };
    let user = (grantees == Grantees::AlsoCurrent && account.user != SYSTEM).then_some(account.user.as_str());
    let aces: String = ["SY", "BA"].into_iter().chain(user).map(|sid| format!("(A;{inherit};FA;;;{sid})")).collect();
    format!("{owner}D:P{aces}")
}

/// 只为读、改访问控制打开 `path`，不跟随重解析点：打开的是链接本身。
fn open_for_acl(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        // 打开目录要带 FILE_FLAG_BACKUP_SEMANTICS。
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// 所在的卷保存访问控制（NTFS、ReFS 保存，FAT、exFAT 不保存）。查询失败时按保存处理，照常检查。
fn keeps_acls(file: &File) -> bool {
    let mut flags = 0u32;
    // SAFETY: 句柄有效；卷名和文件系统名都不要，系统只往局部变量 `flags` 里写。
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut flags,
            ptr::null_mut(),
            0,
        )
    } != 0;
    !ok || flags & FILE_PERSISTENT_ACLS != 0
}

/// 目录里的一项，打开着，查过了。
struct Entry {
    path: PathBuf,
    file: File,
    directory: bool,
}

/// 目录里的每一项（一层层往下），逐项查：不是重解析点，属主可信，别的账户不能写。
fn collect(dir: &Path, account: &Account, entries: &mut Vec<Entry>) -> io::Result<()> {
    for entry in fs::read_dir(dir).map_err(|error| at(dir, &error))? {
        let path = entry.map_err(|error| at(dir, &error))?.path();
        let file = match open_for_acl(&path) {
            Ok(file) => file,
            // 运行着的节点刚把临时文件改了名。
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(at(&path, &error)),
        };
        let checked = (|| {
            let meta = file.metadata()?;
            super::check_not_reparse_or_symlink(&meta)?;
            verdict(&Descriptor::of(&file)?, account)?;
            Ok(meta.is_dir())
        })();
        let directory = checked.map_err(|error: io::Error| at(&path, &error))?;
        entries.push(Entry { path: path.clone(), file, directory });
        if directory {
            collect(&path, account, entries)?;
        }
    }
    Ok(())
}

/// 出错的是目录里的哪一项。
fn at(path: &Path, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), i3t_lang::current().chain([path.display().to_string(), error.to_string()]))
}

/// 换上 `descriptor` 里的访问控制列表，不再继承上级目录的。
fn set_dacl(file: &File, descriptor: &Descriptor) -> io::Result<()> {
    let dacl = descriptor.dacl()?.ok_or_else(|| io::Error::other("安全描述符中没有访问控制列表"))?;
    // SAFETY: 句柄有效、带 WRITE_DAC；`dacl` 指向 `descriptor` 里的列表，调用期间有效。属主、组和系统列表不改。
    check(unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    })
}

fn check(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS { Ok(()) } else { Err(io::Error::from_raw_os_error(status.cast_signed())) }
}

fn security_attributes(descriptor: &Descriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("SECURITY_ATTRIBUTES 只有几十个字节"),
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    }
}

/// 路径写成以 0 结尾的 UTF-16，给 CreateDirectoryW、CreateFileW 用。与 std 相同，达到 248 个字符（建目录时的上限）
/// 的路径先展开为绝对路径，再改写为 `\\?\` 形式，不受 MAX_PATH 的限制。
fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    const LEGACY_MAX_PATH: usize = 248;
    if path.as_os_str().encode_wide().count() < LEGACY_MAX_PATH {
        return wide(path.as_os_str());
    }
    let full = std::path::absolute(path)?;
    let text = full.as_os_str().encode_wide();
    let verbatim: Vec<u16> = match full.components().next() {
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)) => r"\\?\".encode_utf16().chain(text).collect(),
        // `\\server\share\…` 写成 `\\?\UNC\server\share\…`。
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::UNC(..)) => {
            r"\\?\UNC".encode_utf16().chain(text.skip(1)).collect()
        }
        // 已是 `\\?\` 形式或设备路径。
        _ => text.collect(),
    };
    terminated(verbatim)
}

/// 以 0 结尾的 UTF-16，给 Win32 函数用。中间有 0 时报错，免得被截成另一个路径。
fn wide(text: &OsStr) -> io::Result<Vec<u16>> {
    terminated(text.encode_wide().collect())
}

fn terminated(mut wide: Vec<u16>) -> io::Result<Vec<u16>> {
    if wide.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "路径中有空字符"));
    }
    wide.push(0);
    Ok(wide)
}

/// 系统分配、要由调用者用 LocalFree 释放的内存。
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: 指针来自系统的 LocalAlloc（或者是空指针，LocalFree 不做什么），只释放这一次。
        unsafe { LocalFree(self.0) };
    }
}

/// SID 写成 `S-1-5-…`。
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` 指向一个 SID，系统会先检查它；成功时系统分配一段以 0 结尾的字符串，地址写进 `text`。
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _free = Local(text.cast());
    let mut len = 0;
    // SAFETY: `text` 以 0 结尾，0 之前的每个字符都能读。
    while unsafe { text.add(len).read() } != 0 {
        len += 1;
    }
    // SAFETY: 同上，前 `len` 个字符都能读，`_free` 到函数结束才释放。
    Ok(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) }))
}

/// 一个安全描述符：属主和访问控制列表。
struct Descriptor(Local);

impl Descriptor {
    /// 按 SDDL 的写法建一个。
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl = wide(OsStr::new(sddl))?;
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl` 以 0 结尾；成功时系统分配描述符，地址写进 `descriptor`；不要它的长度。
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &raw mut descriptor, ptr::null_mut())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(Local(descriptor)))
    }

    /// 打开着的文件或目录现在的属主和访问控制列表。
    fn of(file: &File) -> io::Result<Self> {
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: 句柄有效、带 READ_CONTROL；属主和列表都从整个描述符里取，不单独要它们的指针。成功时系统分配描述符，
        // 地址写进 `descriptor`。
        check(unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut descriptor,
            )
        })?;
        Ok(Self(Local(descriptor)))
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0.0
    }

    /// 属主的 SID。
    fn owner(&self) -> io::Result<String> {
        let mut owner: PSID = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: 描述符有效；系统只往两个局部变量里写，`owner` 指向描述符里面。
        if unsafe { GetSecurityDescriptorOwner(self.as_ptr(), &raw mut owner, &raw mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if owner.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "安全描述符中没有属主"));
        }
        sid_string(owner)
    }

    /// 访问控制列表是受保护的：不继承上级目录的。
    fn protected(&self) -> io::Result<bool> {
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: 描述符有效；系统只往两个局部变量里写。
        if unsafe { GetSecurityDescriptorControl(self.as_ptr(), &raw mut control, &raw mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(control & SE_DACL_PROTECTED != 0)
    }

    /// 访问控制列表；没有列表（谁都能做任何事）时是 `None`。
    fn dacl(&self) -> io::Result<Option<*const ACL>> {
        let mut present = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: 描述符有效；系统只往三个局部变量里写，`dacl` 指向描述符里面。
        if unsafe { GetSecurityDescriptorDacl(self.as_ptr(), &raw mut present, &raw mut dacl, &raw mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((present != 0 && !dacl.is_null()).then_some(dacl.cast_const()))
    }

    /// 列表里允许访问的各项；拒绝访问的项只会少给权限，不管。没有列表时是 `None`。
    fn grants(&self) -> io::Result<Option<Vec<Grant>>> {
        let Some(dacl) = self.dacl()? else { return Ok(None) };
        // SAFETY: `dacl` 指向描述符里一个有效的列表。
        let count = unsafe { dacl.read_unaligned() }.AceCount;
        let mut grants = Vec::new();
        for index in 0..count {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: `index` 小于列表的项数；系统把这一项的地址写进局部变量 `ace`，它指向列表里面。
            if unsafe { GetAce(dacl, u32::from(index), &raw mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let ace = ace.cast::<u8>().cast_const();
            // SAFETY: 每一项都以 ACE_HEADER 开头。
            let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
            let size = usize::from(header.AceSize);
            let damaged = || io::Error::new(io::ErrorKind::InvalidData, "访问控制列表中有损坏的项");
            // 允许访问的几种项都是：头（4 字节）、权限（4 字节），对象项再有标志（4 字节）和标志说有的一两个 GUID，然后是 SID。
            // 每次读取之前先确认所读的字节在这一项的 `AceSize` 之内。
            let sid_at = match u32::from(header.AceType) {
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => 8,
                ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                    if size < 12 {
                        return Err(damaged());
                    }
                    // SAFETY: 对象项的第 8 到 11 字节是标志，上面已确认在这一项之内。
                    let flags = unsafe { ace.add(8).cast::<u32>().read_unaligned() };
                    let guids =
                        [ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT].iter().filter(|&&flag| flags & flag != 0).count();
                    12 + 16 * guids
                }
                _ => continue,
            };
            // SID 的固定部分为 8 个字节，其中第 1 个字节是子授权的个数，每个子授权再占 4 个字节。
            if sid_at + 8 > size {
                return Err(damaged());
            }
            // SAFETY: 第 `sid_at + 1` 个字节在上面确认过的范围之内。
            let sub_authorities = usize::from(unsafe { ace.add(sid_at + 1).read() });
            if sid_at + 8 + 4 * sub_authorities > size {
                return Err(damaged());
            }
            // SAFETY: 第 4 到 7 字节是权限，`sid_at` 不小于 8，已在这一项之内。
            let rights = unsafe { ace.add(4).cast::<u32>().read_unaligned() };
            // SAFETY: 整个 SID 在这一项之内（上面已核对长度）；`sid_string` 还会检查它的格式。
            let sid = sid_string(unsafe { ace.add(sid_at) }.cast_mut().cast())?;
            grants.push(Grant { sid, rights });
        }
        Ok(Some(grants))
    }
}

/// 一条允许访问的项：给谁（SID）、哪些权限。
#[derive(Debug)]
struct Grant {
    sid: String,
    rights: u32,
}

/// 已经有的目录或者里面的一项查下来怎样。
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// 只有可信的账户能访问，访问控制也不继承上级：不用改。
    Private,
    /// 其他账户无写入权限，但仍可读取，或者访问控制仍继承自上级目录：收紧。
    Tighten,
}

/// 不能用的原因。
#[derive(Debug, PartialEq, Eq)]
enum Untrusted {
    /// 属主不是可信的账户。
    Owner(String),
    /// 这个账户能写，或者能改访问控制、属主。
    Writer(String),
    /// 没有访问控制列表：谁都能做任何事。
    NoDacl,
}

impl Untrusted {
    fn into_error(self) -> io::Error {
        let t = texts();
        let message = match self {
            Self::Owner(sid) => (t.untrusted_owner)(&sid),
            Self::Writer(sid) => (t.untrusted_writer)(&sid),
            Self::NoDacl => t.no_dacl.to_owned(),
        };
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    }
}

fn verdict(descriptor: &Descriptor, account: &Account) -> io::Result<Verdict> {
    judge(&descriptor.owner()?, descriptor.grants()?.as_deref(), descriptor.protected()?, account).map_err(Untrusted::into_error)
}

/// `grants` 是 `None`：没有访问控制列表。`protected`：访问控制列表不继承上级目录的。
fn judge(owner: &str, grants: Option<&[Grant]>, protected: bool, account: &Account) -> Result<Verdict, Untrusted> {
    if !account.trusts(owner) {
        return Err(Untrusted::Owner(owner.to_owned()));
    }
    let grants = grants.ok_or(Untrusted::NoDacl)?;
    let others = || grants.iter().filter(|grant| !account.trusts(&grant.sid) && grant.sid != CREATOR_OWNER && grant.sid != OWNER_RIGHTS);
    if let Some(writer) = others().find(|grant| grant.rights & WRITE_RIGHTS != 0) {
        return Err(Untrusted::Writer(writer.sid.clone()));
    }
    Ok(if protected && others().next().is_none() { Verdict::Private } else { Verdict::Tighten })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// 访问控制列表是不是受保护的（不继承上级目录的），给的账户是不是都可信：SYSTEM、Administrators 和当前用户。
    pub(in crate::state) fn access_of(path: &Path) -> (bool, bool) {
        let descriptor = Descriptor::of(&open_for_acl(path).unwrap()).unwrap();
        let account = Account::current().unwrap();
        let grants = descriptor.grants().unwrap().unwrap();
        (descriptor.protected().unwrap(), grants.iter().all(|grant| account.trusts(&grant.sid)))
    }

    /// 当前用户的 SID。
    pub(in crate::state) fn me() -> String {
        Account::current().unwrap().user
    }

    /// 进程令牌中 Administrators 组已启用。
    pub(in crate::state) fn privileged() -> bool {
        Account::current().unwrap().privileged
    }

    /// 访问控制列表中有给当前账户（按 SID）的项。
    pub(in crate::state) fn grants_me(path: &Path) -> bool {
        let me = me();
        Descriptor::of(&open_for_acl(path).unwrap()).unwrap().grants().unwrap().unwrap().iter().any(|grant| grant.sid == me)
    }

    /// 属主的 SID。
    pub(in crate::state) fn owner_of(path: &Path) -> String {
        Descriptor::of(&open_for_acl(path).unwrap()).unwrap().owner().unwrap()
    }

    /// 按 SDDL 建一个目录（不检查，就像别的程序或者别的用户建的那样）。
    pub(in crate::state) fn make_dir_with(path: &Path, sddl: &str) {
        let descriptor = Descriptor::from_sddl(sddl).unwrap();
        let attributes = security_attributes(&descriptor);
        let path = wide(path.as_os_str()).unwrap();
        // SAFETY: 同 `create_private_dir`。
        assert_ne!(unsafe { CreateDirectoryW(path.as_ptr(), &raw const attributes) }, 0, "{}", io::Error::last_os_error());
    }

    const USER: &str = "S-1-5-21-1-2-3-1001";
    const USERS: &str = "S-1-5-32-545";

    fn judge_sddl(sddl: &str, privileged: bool) -> Result<Verdict, Untrusted> {
        let descriptor = Descriptor::from_sddl(sddl).unwrap();
        let account = Account { user: USER.to_owned(), privileged };
        judge(&descriptor.owner().unwrap(), descriptor.grants().unwrap().as_deref(), descriptor.protected().unwrap(), &account)
    }

    #[test]
    fn a_failed_create_leaves_an_existing_name_to_the_caller_whatever_the_error() {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS};

        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let denied = io::Error::from_raw_os_error(ERROR_ACCESS_DENIED.cast_signed());
        let exists = io::Error::from_raw_os_error(ERROR_ALREADY_EXISTS.cast_signed());
        // 卷的根目录等对已存在的名称报告拒绝访问。
        assert!(already_there(&denied, dir.path()));
        assert!(!already_there(&denied, &missing));
        assert!(already_there(&exists, dir.path()));
    }

    #[test]
    fn the_write_rights_are_the_same_as_the_installers() {
        assert_eq!(WRITE_RIGHTS, 0x500D_0156);
    }

    #[test]
    fn the_access_list_has_the_current_user_unless_administrators_alone_are_wanted() {
        let user = Account { user: USER.to_owned(), privileged: false };
        let admin = Account { user: USER.to_owned(), privileged: true };
        let system = Account { user: SYSTEM.to_owned(), privileged: true };
        // 未启用 Administrators 组时无论在哪里都另给当前账户；启用时没有可查的上级目录则只给 SYSTEM 与 Administrators。
        assert_eq!(user.grantees_in(None), Grantees::AlsoCurrent);
        assert_eq!(admin.grantees_in(None), Grantees::Administrators);
        assert_eq!(system.grantees_in(None), Grantees::Administrators);
        assert_eq!(sddl(&user, Grantees::AlsoCurrent, true), format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{USER})"));
        assert_eq!(sddl(&user, Grantees::AlsoCurrent, false), format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{USER})"));
        assert_eq!(sddl(&admin, Grantees::Administrators, true), "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert_eq!(sddl(&admin, Grantees::Administrators, false), "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
        assert_eq!(sddl(&admin, Grantees::AlsoCurrent, true), format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{USER})"));
        assert_eq!(sddl(&system, Grantees::AlsoCurrent, false), "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
    }

    #[test]
    fn a_directory_is_used_only_if_trusted_accounts_own_it_and_alone_can_write_to_it() {
        // install.ps1 建的、这里建的：不用改。
        assert_eq!(judge_sddl("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true), Ok(Verdict::Private));
        assert_eq!(judge_sddl(&format!("O:{USER}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{USER})"), false), Ok(Verdict::Private));
        // 继承上级的，或者别人能读：收紧。
        assert_eq!(
            judge_sddl(&format!("O:{USER}D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;{USER})"), false),
            Ok(Verdict::Tighten)
        );
        assert_eq!(judge_sddl("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BU)", true), Ok(Verdict::Tighten));
        // 新建者占位和拒绝访问的项不给别人权限。
        assert_eq!(judge_sddl("O:SYD:P(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(D;OICI;FA;;;BU)", true), Ok(Verdict::Private));
        // 别人建的。
        assert_eq!(judge_sddl("O:BUD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true), Err(Untrusted::Owner(USERS.to_owned())));
        assert_eq!(judge_sddl("O:S-1-5-21-1-2-3-1002D:P(A;;FA;;;SY)", false), Err(Untrusted::Owner("S-1-5-21-1-2-3-1002".to_owned())));
        // 别人能写、能往里面放东西、能改权限，哪怕只是给里面新建的项：C:\ProgramData 下面新建的目录就是这样。
        assert_eq!(
            judge_sddl("O:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)", true),
            Err(Untrusted::Writer(USERS.to_owned()))
        );
        assert_eq!(judge_sddl("O:SYD:P(A;OICIIO;GW;;;BU)", true), Err(Untrusted::Writer(USERS.to_owned())));
        assert_eq!(judge_sddl("O:SYD:P(A;;WD;;;WD)", true), Err(Untrusted::Writer("S-1-1-0".to_owned())));
        assert_eq!(judge_sddl("O:SYD:P(OA;;FA;;;AU)", true), Err(Untrusted::Writer("S-1-5-11".to_owned())));
        // 没有访问控制列表：谁都能写。
        assert_eq!(judge_sddl("O:SYD:NO_ACCESS_CONTROL", true), Err(Untrusted::NoDacl));
    }
}
