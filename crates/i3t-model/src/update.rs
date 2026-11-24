//! 发布清单：一个版本有哪些文件，以及它们的签名。
//!
//! 一次发布是一组文件加一份清单（[`Manifest`]）。清单写明版本号，以及每个平台的节点程序是哪个文件、多大、SHA-256 是多少。
//! 清单的原文带着一个 Ed25519 签名一起传（[`SignedManifest`]），节点用编译在程序里的公钥验。
//! 因此经手的 controller、发布源与镜像均无需受信任：它们无法篡改清单，也无法替换发布文件。
//!
//! 发布源的目录结构和 GitHub Release 的下载地址一样，镜像照着摆：
//!
//! ```text
//! <发布源>/latest/download/manifest.json         最新正式版的清单（[`LATEST_DIR`]、[`MANIFEST_FILE`]）
//! <发布源>/latest/download/manifest.json.sig     它的签名（[`SIGNATURE_FILE`]）
//! <发布源>/download/v<版本号>/manifest.json       某个版本的清单（[`Version::release_dir`]）
//! <发布源>/download/v<版本号>/manifest.json.sig
//! <发布源>/download/v<版本号>/<文件名>            清单里列出的文件（[`Artifact::file`]）
//! ```
//!
//! 这里还有节点和 controller 谈更新时用的几个类型：什么时候装（[`UpdateTiming`]）、装到哪一步了（[`UpdateStatus`]）、
//! 这个节点为什么不能自己更新（[`SelfUpdateBlocker`]）。验签、取包和安装在 `i3t-update` 里，这里只有数据。

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

/// 清单文件的名字。
pub const MANIFEST_FILE: &str = "manifest.json";

/// 签名文件的名字。内容是一行文本：签名的 base64url。
pub const SIGNATURE_FILE: &str = "manifest.json.sig";

/// 发布源里放"最新正式版"的清单的目录。预发布版不会出现在这里。
pub const LATEST_DIR: &str = "latest/download";

/// 节点程序的名字。只有它走自动更新，清单里列的就是各个平台上的它。
pub const NODE_PROGRAM: &str = "i3t";

/// 版本号，写法是语义化版本：`主.次.修订`，预发布版在后面跟 `-标识`，例如 `0.3.0-rc.1`。
///
/// 大小按语义化版本的规则比：先比三个数字；数字相同时预发布版比正式版小；两个预发布版逐段比较标识，
/// 纯数字的段按数值比并且比带字母的段小，前面都相同时段数多的大。
///
/// 不接受 `+构建信息`：它不参与比较，留着会出现"写法不同但一样新"的两个版本号。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    /// 预发布标识，不带开头的 `-`。正式版是空的。
    pre: String,
}

impl Version {
    /// 一个正式版的版本号。
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self { major, minor, patch, pre: String::new() }
    }

    #[must_use]
    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }

    /// 这个版本的文件在发布源里的目录，例如 `download/v0.3.0`。
    #[must_use]
    pub fn release_dir(&self) -> String {
        format!("download/v{self}")
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if self.is_prerelease() {
            write!(f, "-{}", self.pre)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} 不是有效的版本号，应形如 1.2.3 或 1.2.3-rc.1")]
pub struct InvalidVersion(String);

impl FromStr for Version {
    type Err = InvalidVersion;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidVersion(s.to_owned());
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) if is_prerelease_tag(pre) => (core, pre),
            Some(_) => return Err(invalid()),
            None => (s, ""),
        };
        let numbers: Vec<u64> = core.split('.').map(parse_number).collect::<Option<_>>().ok_or_else(invalid)?;
        let [major, minor, patch] = numbers[..] else { return Err(invalid()) };
        Ok(Self { major, minor, patch, pre: pre.to_owned() })
    }
}

/// 十进制数，不允许多余的前导零：`01` 和 `1` 得是同一个版本号才行，所以只留一种写法。
fn parse_number(text: &str) -> Option<u64> {
    let canonical = text == "0" || !text.starts_with('0');
    (canonical && is_number(text)).then(|| text.parse().ok())?
}

fn is_number(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_prerelease_tag(tag: &str) -> bool {
    tag.split('.').all(|part| {
        let well_formed = !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        well_formed && (!is_number(part) || part == "0" || !part.starts_with('0'))
    })
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)).then_with(|| {
            match (self.is_prerelease(), other.is_prerelease()) {
                (false, false) => Ordering::Equal,
                (false, true) => Ordering::Greater,
                (true, false) => Ordering::Less,
                (true, true) => compare_prerelease_tags(&self.pre, &other.pre),
            }
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease_tags(left: &str, right: &str) -> Ordering {
    left.split('.')
        .zip(right.split('.'))
        .map(|(left, right)| match (is_number(left), is_number(right)) {
            // 没有前导零，所以位数多的就大，位数相同时字典序就是数值的大小。这样不用担心数字超出整数的范围。
            (true, true) => left.len().cmp(&right.len()).then_with(|| left.cmp(right)),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => left.cmp(right),
        })
        .find(|ordering| ordering.is_ne())
        .unwrap_or_else(|| left.split('.').count().cmp(&right.split('.').count()))
}

/// 操作系统和架构，例如 `linux-x86_64`、`windows-x86_64`、`macos-aarch64`。
/// 和节点在 [`Hello::platform`](crate::control::Hello::platform) 里报的是同一种写法。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Platform(String);

impl Platform {
    /// 这个程序是为哪个平台编译的。
    #[must_use]
    pub fn current() -> Self {
        Self(format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 名叫 `program` 的程序在这个平台上的发布文件叫什么：`<程序名>-<平台>`，Windows 上再加 `.exe`。
    #[must_use]
    pub fn program_file(&self, program: &str) -> String {
        let extension = if self.0.starts_with("windows-") { ".exe" } else { "" };
        format!("{program}-{self}{extension}")
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} 不是有效的平台名，应形如 linux-x86_64")]
pub struct InvalidPlatform(String);

impl FromStr for Platform {
    type Err = InvalidPlatform;

    /// 只认"系统-架构"两段，每段是小写字母、数字和下划线。
    /// 发布文件的名字里还有程序名，平台名里要是也能有 `-`，就分不清哪一段是哪一段了。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let is_word =
            |word: &str| !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        match s.split_once('-') {
            Some((os, arch)) if is_word(os) && is_word(arch) => Ok(Self(s.to_owned())),
            _ => Err(InvalidPlatform(s.to_owned())),
        }
    }
}

/// 一个文件的 SHA-256。文本形式是 64 个十六进制字符，输出用小写。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256([u8; Self::LEN]);

impl Sha256 {
    pub const LEN: usize = 32;

    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// 日志里只需要认得出是哪一个，所以只打前 4 个字节。
impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({:02x}{:02x}{:02x}{:02x}…)", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("无效的 SHA-256：应为 64 个十六进制字符")]
pub struct InvalidSha256;

impl FromStr for Sha256 {
    type Err = InvalidSha256;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let nibble = |byte: u8| char::from(byte).to_digit(16);
        let bytes: Vec<u8> = s
            .as_bytes()
            .chunks(2)
            .map(|pair| match *pair {
                [high, low] => u8::try_from(nibble(high)? * 16 + nibble(low)?).ok(),
                _ => None,
            })
            .collect::<Option<_>>()
            .ok_or(InvalidSha256)?;
        bytes.try_into().map(Self).map_err(|_| InvalidSha256)
    }
}

/// 发布里的一个文件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// 文件名，不带目录。它和清单放在发布源的同一个目录里。
    pub file: String,
    /// 字节数。
    pub size: u64,
    pub sha256: Sha256,
}

/// 发布清单。
///
/// 清单带有签名，修改任一字节都会导致验签失败，因此接收方不可反序列化后再重新生成，须原样转发原始文本
/// （[`SignedManifest::manifest`]）。新版本清单可新增字段，旧版本程序会忽略未知字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: Version,
    /// 该版本节点所需的 controller 最低版本。controller 版本低于此值时不下发更新，界面提示先升级 controller。
    pub min_controller: Version,
    /// 发布时间，Unix 秒。
    pub published: u64,
    /// 各个平台上的节点程序，键是平台名（[`Platform`] 的写法）。
    /// 键保留为字符串：后续若出现新格式平台名，旧版本程序仅跳过该项，而不致无法解析整份清单。
    pub artifacts: BTreeMap<String, Artifact>,
    /// 最低的没有已知安全问题的版本：比它旧的版本有已知的安全问题。没有写是 `None`，清单里也就没有这个字段。
    ///
    /// 只是告诉人的，怎么下发更新不因它而变。发布的人从修了问题的那一版起每一版都带上它，跳过了几版的节点照样知道。
    /// 较旧版本程序仍可正常识别该清单：签名覆盖原始字节，解析时会忽略未知字段。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_floor: Option<Version>,
    /// 节点自更新清单之外的发布文件（`i3t-controller-*`、`i3tctl-*`、Windows 压缩包等），键是文件名。
    ///
    /// 旧版本节点与 controller 会忽略该未知字段；安装脚本用它校验所下载的各非自更新发布产物。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, Artifact>,
}

impl Manifest {
    /// `platform` 上的节点程序；这个版本没有为它出包时是 `None`。
    #[must_use]
    pub fn artifact(&self, platform: &Platform) -> Option<&Artifact> {
        self.artifacts.get(platform.as_str())
    }

    /// 按文件名查找清单里的发布产物（先查节点程序，再查其余发布文件）。
    #[must_use]
    pub fn file(&self, name: &str) -> Option<&Artifact> {
        self.artifacts.values().find(|artifact| artifact.file == name).or_else(|| self.files.get(name))
    }

    /// 运行着 `running` 的节点有没有已知的安全问题：比 [`Manifest::security_floor`] 旧。清单没有写下限时总是 `false`。
    #[must_use]
    pub fn is_below_security_floor(&self, running: &Version) -> bool {
        self.security_floor.as_ref().is_some_and(|floor| running < floor)
    }

    /// 预发布版的清单：版本号带预发布标识。它不会被放到 [`LATEST_DIR`] 下面，节点对它也另有规矩（见 `i3t-update`）。
    #[must_use]
    pub fn is_prerelease(&self) -> bool {
        self.version.is_prerelease()
    }
}

/// 清单的签名：Ed25519，64 字节。文本形式是不带填充的 base64url。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ManifestSignature([u8; Self::LEN]);

impl ManifestSignature {
    pub const LEN: usize = 64;

    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Display for ManifestSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for ManifestSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManifestSignature({:02x}{:02x}{:02x}{:02x}…)", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("无效的清单签名：应为 64 字节的 base64url")]
pub struct InvalidManifestSignature;

impl FromStr for ManifestSignature {
    type Err = InvalidManifestSignature;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| InvalidManifestSignature)?;
        bytes.try_into().map(Self).map_err(|_| InvalidManifestSignature)
    }
}

/// 一份清单的原文和它的签名。controller 从发布源取到之后原样发给节点。
///
/// 这个类型没有"取出清单"的方法：要先验签才能相信里面的内容，验签在 `i3t-update` 的 `TrustedKeys::verify` 里，
/// 验过了才会得到 [`Manifest`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    /// 清单文件的原文。签名盖的就是这些字节。
    pub manifest: String,
    pub signature: ManifestSignature,
}

impl SignedManifest {
    /// 从发布源的两个文件的内容得到一份带签名的清单。`signature` 是签名文件的内容，前后的空白不计。
    ///
    /// # Errors
    ///
    /// 签名文件的内容不是一个签名。清单的原文这时还没有被看过。
    pub fn from_files(manifest: String, signature: &str) -> Result<Self, InvalidManifestSignature> {
        Ok(Self { manifest, signature: signature.trim().parse()? })
    }
}

/// 这几个类型在 JSON 里都是一个字符串，写法就是它们的 `Display` 和 `FromStr`。
macro_rules! serde_as_text {
    ($($type:ty),+ $(,)?) => {$(
        impl Serialize for $type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <std::borrow::Cow<'de, str> as Deserialize>::deserialize(deserializer)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    )+};
}

serde_as_text!(Version, Platform, Sha256, ManifestSignature);

/// 换程序的时机，由 controller 决定。
///
/// 下载、验签和自检不等时机，拿到清单就做；这里说的只是"什么时候换程序并重启"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateTiming {
    /// 等到节点上没有活跃的流。自动更新用这个；一直有流的节点一直等。
    Idle,
    /// 立刻，正在进行的流会断。管理员点"立即更新"。
    Now,
    /// 节点不再接新的流，手上的流都结束之后再换。管理员选"排空后更新"。
    AfterDrain,
}

impl UpdateTiming {
    /// 是不是管理员强制的更新。自动更新不会重试在这台机器上失败过的版本，强制的会。
    #[must_use]
    pub const fn is_forced(self) -> bool {
        match self {
            Self::Idle => false,
            Self::Now | Self::AfterDrain => true,
        }
    }
}

/// 节点上的更新进行到哪一步了。节点每次变化都报给 controller，WebUI 照着显示。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpdateStatus {
    /// 没有更新在进行。
    #[default]
    Idle,
    /// 正在从 controller 下载安装包。链路断开后会断点续传，进度计数不会回退。
    Downloading { version: Version, received: u64, total: u64 },
    /// 安装包下载完成，正在校验大小和 SHA-256。
    Verifying { version: Version },
    /// 正在运行新程序的自检。
    SelfCheck { version: Version },
    /// 新程序已经准备好，在等节点上没有活跃的流。
    WaitingForIdle { version: Version },
    /// 新程序已经准备好，节点不再接新的流，在等手上的流结束。
    Draining { version: Version },
    /// 正在替换程序文件。
    Installing { version: Version },
    /// 程序文件已经换好，节点马上重启。
    Restarting { version: Version },
    /// 新程序连上了 controller，更新完成。
    Confirmed { version: Version },
    /// 更新失败。若尚未通过清单校验，`version` 为 `null`。
    Failed {
        version: Option<Version>,
        kind: FailureKind,
        reason: String,
        /// `reason` 的代码和它要用到的值。旧版本的节点不报。
        #[serde(default)]
        cause: Option<UpdateCause>,
    },
    /// 较新版本节点上报的未知状态。节点版本可以高于 controller。
    #[serde(other)]
    Unknown,
}

/// 更新失败的两种类型。controller 仅在 [`FailureKind::VersionRejected`] 时暂停该版本的自动更新并告警。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// 未完成安装，与目标版本本身质量无关：清单被拒（签名无效、版本不高于当前版本、缺少对应平台安装包）、无法获取安装包或校验不符、
    /// 磁盘出错。后续可再次尝试。
    NotInstalled,
    /// 该版本在本机不可用：自检未通过，或安装后未能连接到 controller 并已回滚至旧版本。
    /// 节点记下了这次失败，不再自动重试这个版本。
    VersionRejected,
}

/// 节点最近一次更新失败的原因码及格式化所需参数；同级 `reason` 为原始中文说明。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum UpdateCause {
    /// 清单的签名不是任何一把受信任的发布公钥签的。
    BadSignature,
    /// 签名有效，但无法解析清单内容。
    BadManifest,
    /// 节点不能自己更新。
    CannotSelfUpdate { blocker: SelfUpdateBlocker },
    /// 清单里的版本不比正在运行的新。
    NotNewer { offered: Version, running: Version },
    /// 清单里是预发布版，而正在运行的是正式版。
    Prerelease { offered: Version, running: Version },
    /// 这个版本在这台机器上失败过，不再自动重试。
    FailedBefore { version: Version },
    /// 这个版本没有这台机器的平台的包。
    NoPackage { version: Version, platform: Platform },
    /// 已经换上了另一个版本，在等进程重启。
    RestartPending { installed: Version },
    /// 无法从 controller 获取安装包。`detail` 为 controller 或节点返回的原始错误信息。
    Unavailable { detail: String },
    /// 下载的安装包与清单校验不符。
    Corrupt { expected_size: u64, actual_size: u64 },
    /// 新程序的自检没有通过。`exit_code` 是它的退出码（被信号杀掉、没有运行起来或者超时时是 `null`），
    /// `output` 是它在标准错误上最后说的话，原样。
    SelfCheck { exit_code: Option<i32>, output: String },
    /// 节点不再通报流的数量，等不到换程序的时机。
    Cancelled,
    /// 对一个文件的读写失败。`error` 是系统的原话。
    Io { path: String, error: String },
    /// 节点上的更新状态文件无法解析。
    StateUnreadable { path: String },
    /// 新程序启动后 `minutes` 分钟内未能连接到 controller，已回滚至旧版本。
    NotConfirmed { minutes: u64 },
    /// 新程序启动 `starts` 次均未能连接到 controller，已回滚至旧版本。
    StartsUnconfirmed { starts: u32 },
    /// 较新版本节点上报的未知原因。
    #[serde(other)]
    Unknown,
}

/// 节点无法自更新的原因。节点连接 controller 时上报，WebUI 据此展示原因及手动更新方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfUpdateBlocker {
    /// 运行在容器中。替换程序文件在容器重建后会恢复为镜像版本，应通过更换镜像更新。
    Container,
    /// 程序由系统包管理器安装。自行替换文件会导致与包管理器记录不一致，应通过包管理器更新。
    PackageManager,
    /// 程序文件所在的目录不可写。
    ReadOnlyDir,
}

impl fmt::Display for SelfUpdateBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Container => "节点运行在容器中，请通过更换镜像更新",
            Self::PackageManager => "节点程序由系统包管理器安装，请通过包管理器更新",
            Self::ReadOnlyDir => "节点程序所在目录不可写",
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn version(text: &str) -> Version {
        text.parse().unwrap()
    }

    #[test]
    fn version_text_round_trips() {
        for text in ["0.1.0", "1.2.3", "10.20.30", "1.0.0-rc.1", "1.0.0-alpha", "1.0.0-0.3.7", "1.0.0-x-y.z", "18446744073709551615.0.0"] {
            assert_eq!(version(text).to_string(), text);
        }
        assert_eq!(version("0.3.0"), Version::new(0, 3, 0));
        assert_eq!(serde_json::to_value(version("1.2.3-rc.1")).unwrap(), json!("1.2.3-rc.1"));
        assert_eq!(serde_json::from_value::<Version>(json!("1.2.3")).unwrap(), Version::new(1, 2, 3));
    }

    #[test]
    fn malformed_versions_are_rejected() {
        let malformed = [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "1.2.x",
            "01.2.3",
            "1.02.3",
            "1.2.3-",
            "1.2.3-rc..1",
            "1.2.3-rc.01",
            "1.2.3-rc_1",
            "1.2.3+build",
            "1.2.3-rc.1+build",
            " 1.2.3",
            "1.2.3 ",
            "+1.2.3",
            "1.-2.3",
            "18446744073709551616.0.0",
        ];
        for text in malformed {
            assert!(text.parse::<Version>().is_err(), "{text:?} 不应该被接受");
        }
        assert!(serde_json::from_value::<Version>(json!(1)).is_err());
    }

    #[test]
    fn versions_order_by_semver_precedence() {
        // 语义化版本规范第 11 条里的例子，再加上三个数字各自的比较。
        let ascending = [
            "0.9.9",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.0.10",
            "1.1.0",
            "2.0.0-0",
            "2.0.0",
        ];
        for (index, low) in ascending.iter().enumerate() {
            assert_eq!(version(low).cmp(&version(low)), Ordering::Equal, "{low}");
            for high in &ascending[index + 1..] {
                assert!(version(low) < version(high), "{low} 应该比 {high} 旧");
                assert!(version(high) > version(low), "{high} 应该比 {low} 新");
            }
        }
    }

    #[test]
    fn numeric_prerelease_parts_compare_by_value_even_when_huge() {
        assert!(version("1.0.0-9") < version("1.0.0-10"));
        assert!(version("1.0.0-99999999999999999999999999") < version("1.0.0-100000000000000000000000000"));
        assert!(version("1.0.0-99999999999999999999999999") < version("1.0.0-a"));
    }

    #[test]
    fn prerelease_is_recognisable() {
        assert!(!version("1.0.0").is_prerelease());
        assert!(version("1.0.0-rc.1").is_prerelease());
        assert_eq!(version("1.0.0-rc.1").release_dir(), "download/v1.0.0-rc.1");
    }

    #[test]
    fn platform_names_and_release_file_names() {
        let linux: Platform = "linux-x86_64".parse().unwrap();
        let windows: Platform = "windows-x86_64".parse().unwrap();
        assert_eq!(linux.program_file(NODE_PROGRAM), "i3t-linux-x86_64");
        assert_eq!(windows.program_file(NODE_PROGRAM), "i3t-windows-x86_64.exe");
        assert_eq!(windows.program_file("i3tctl"), "i3tctl-windows-x86_64.exe");
        assert_eq!(serde_json::to_value(&linux).unwrap(), json!("linux-x86_64"));
        for bad in ["", "linux", "linux-", "-x86_64", "controller-linux-x86_64", "Linux-x86_64", "linux-x86 64", "linux/x86_64"] {
            assert!(bad.parse::<Platform>().is_err(), "{bad:?} 不应该被接受");
        }
        assert_eq!(Platform::current().as_str().parse::<Platform>().unwrap(), Platform::current());
    }

    #[test]
    fn sha256_text_round_trips_and_rejects_garbage() {
        let digest = Sha256::from_bytes(std::array::from_fn(|index| u8::try_from(index * 8 + 1).unwrap()));
        let text = digest.to_string();
        assert_eq!(text.len(), 64);
        assert!(text.starts_with("01091119"), "{text}");
        assert_eq!(text.parse::<Sha256>(), Ok(digest));
        assert_eq!(text.to_uppercase().parse::<Sha256>(), Ok(digest));
        assert_eq!(format!("{digest:?}"), "Sha256(01091119…)");
        for bad in ["", "00", &text[..63], &format!("{text}0"), &format!("+{}", &text[1..]), &format!("g{}", &text[1..])] {
            assert_eq!(bad.parse::<Sha256>(), Err(InvalidSha256), "{bad:?}");
        }
    }

    fn manifest() -> Manifest {
        let artifact = |file: &str| Artifact { file: file.to_owned(), size: 3, sha256: Sha256::from_bytes([0xab; 32]) };
        Manifest {
            version: version("0.3.0"),
            min_controller: version("0.2.0"),
            published: 1_763_200_000,
            artifacts: BTreeMap::from([
                ("linux-x86_64".to_owned(), artifact("i3t-linux-x86_64")),
                ("windows-x86_64".to_owned(), artifact("i3t-windows-x86_64.exe")),
            ]),
            security_floor: None,
            files: BTreeMap::new(),
        }
    }

    #[test]
    fn manifest_has_a_stable_json_shape() {
        let value = serde_json::to_value(manifest()).unwrap();
        let sha256 = "ab".repeat(32);
        assert_eq!(
            value,
            json!({
                "version": "0.3.0",
                "min_controller": "0.2.0",
                "published": 1_763_200_000u64,
                "artifacts": {
                    "linux-x86_64": { "file": "i3t-linux-x86_64", "size": 3, "sha256": sha256 },
                    "windows-x86_64": { "file": "i3t-windows-x86_64.exe", "size": 3, "sha256": sha256 },
                },
            })
        );
        assert_eq!(serde_json::from_value::<Manifest>(value).unwrap(), manifest());
    }

    #[test]
    fn a_security_floor_is_written_only_when_there_is_one_and_marks_older_versions() {
        let without = serde_json::to_value(manifest()).unwrap();
        assert!(without.get("security_floor").is_none(), "没有下限的清单和这个字段出现之前一个字节不差");
        let manifest = Manifest { security_floor: Some(version("0.2.5")), ..manifest() };
        let value = serde_json::to_value(&manifest).unwrap();
        assert_eq!(value["security_floor"], json!("0.2.5"));
        assert_eq!(serde_json::from_value::<Manifest>(value).unwrap(), manifest);
        for (running, below) in [("0.2.4", true), ("0.2.5-rc.1", true), ("0.2.5", false), ("0.3.0", false)] {
            assert_eq!(manifest.is_below_security_floor(&version(running)), below, "{running}");
        }
        assert!(!Manifest { security_floor: None, ..manifest }.is_below_security_floor(&version("0.0.1")));
        let malformed = json!({ "version": "0.3.0", "min_controller": "0.2.0", "published": 1, "artifacts": {}, "security_floor": "x" });
        assert!(serde_json::from_value::<Manifest>(malformed).is_err(), "下限是签名盖着的，写错了就是清单不对");
    }

    #[test]
    fn manifest_from_a_newer_release_tool_still_parses() {
        let mut value = serde_json::to_value(manifest()).unwrap();
        value["added_later"] = json!({ "x": 1 });
        value["artifacts"]["linux-x86_64"]["added_later"] = json!(true);
        value["artifacts"]["linux-musl-x86_64"] = json!({ "file": "i3t-linux-musl-x86_64", "size": 1, "sha256": "00".repeat(32) });
        let parsed: Manifest = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.artifact(&"linux-x86_64".parse().unwrap()), manifest().artifact(&"linux-x86_64".parse().unwrap()));
        assert_eq!(parsed.artifacts.len(), 3);
    }

    #[test]
    fn manifest_knows_its_platforms_and_whether_it_is_a_prerelease() {
        let mut manifest = manifest();
        assert_eq!(manifest.artifact(&"linux-x86_64".parse().unwrap()).unwrap().file, "i3t-linux-x86_64");
        assert_eq!(manifest.artifact(&"macos-aarch64".parse().unwrap()), None);
        assert!(!manifest.is_prerelease());
        manifest.version = version("0.3.0-rc.1");
        assert!(manifest.is_prerelease());
    }

    #[test]
    fn signed_manifest_keeps_the_text_byte_for_byte() {
        let text = "{ \"version\":   \"0.3.0\",\n\t\"注\": \"空白和顺序都要原样保留\" }\n";
        let signature = ManifestSignature::from_bytes([7; 64]);
        let signed = SignedManifest::from_files(text.to_owned(), &format!("{signature}\n")).unwrap();
        assert_eq!(signed.signature, signature);
        let wire = serde_json::to_string(&signed).unwrap();
        let received: SignedManifest = serde_json::from_str(&wire).unwrap();
        assert_eq!(received.manifest, text);
        assert_eq!(received, signed);
    }

    #[test]
    fn signature_text_must_be_exactly_64_bytes_of_base64url() {
        let text = ManifestSignature::from_bytes([7; 64]).to_string();
        assert_eq!(text.len(), 86);
        for bad in ["", "AAAA", &text[..85], &format!("{text}A"), &text.replace('B', "+")] {
            assert_eq!(SignedManifest::from_files(String::new(), bad), Err(InvalidManifestSignature), "{bad:?}");
        }
    }

    #[test]
    fn only_idle_timing_is_automatic() {
        assert!(!UpdateTiming::Idle.is_forced());
        assert!(UpdateTiming::Now.is_forced());
        assert!(UpdateTiming::AfterDrain.is_forced());
        assert_eq!(serde_json::to_value(UpdateTiming::AfterDrain).unwrap(), json!("after_drain"));
    }

    #[test]
    fn status_has_a_stable_json_shape() {
        let downloading = UpdateStatus::Downloading { version: version("0.3.0"), received: 10, total: 30 };
        assert_eq!(
            serde_json::to_value(&downloading).unwrap(),
            json!({ "state": "downloading", "version": "0.3.0", "received": 10, "total": 30 })
        );
        let failed = UpdateStatus::Failed {
            version: None,
            kind: FailureKind::NotInstalled,
            reason: "签名不对".to_owned(),
            cause: Some(UpdateCause::BadSignature),
        };
        let value = serde_json::to_value(&failed).unwrap();
        assert_eq!(
            value,
            json!({ "state": "failed", "version": null, "kind": "not_installed", "reason": "签名不对", "cause": { "code": "bad_signature" } })
        );
        assert_eq!(serde_json::from_value::<UpdateStatus>(value).unwrap(), failed);
        let old = json!({ "state": "failed", "version": null, "kind": "not_installed", "reason": "签名不对" });
        assert!(matches!(serde_json::from_value(old).unwrap(), UpdateStatus::Failed { cause: None, .. }), "旧版本的节点不报原因的代码");
        assert_eq!(serde_json::to_value(UpdateStatus::Idle).unwrap(), json!({ "state": "idle" }));
        assert_eq!(serde_json::to_value(UpdateStatus::WaitingForIdle { version: version("0.3.0") }).unwrap()["state"], "waiting_for_idle");
        assert_eq!(serde_json::to_value(UpdateStatus::SelfCheck { version: version("0.3.0") }).unwrap()["state"], "self_check");
    }

    #[test]
    fn status_from_a_newer_node_reads_as_unknown() {
        let status: UpdateStatus = serde_json::from_value(json!({ "state": "something_new", "version": "9.0.0" })).unwrap();
        assert_eq!(status, UpdateStatus::Unknown);
    }

    #[test]
    fn blocker_has_a_stable_json_shape() {
        assert_eq!(serde_json::to_value(SelfUpdateBlocker::PackageManager).unwrap(), json!("package_manager"));
        assert_eq!(serde_json::to_value(SelfUpdateBlocker::ReadOnlyDir).unwrap(), json!("read_only_dir"));
    }
}
