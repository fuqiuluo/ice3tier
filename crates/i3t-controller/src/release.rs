//! 发布源：controller 从哪里取发布清单和节点程序。
//!
//! 发布源是一个地址前缀，下面的布局和 GitHub Release 的下载地址一样：
//!
//! ```text
//! <发布源>/latest/download/manifest.json         最新正式版的清单
//! <发布源>/latest/download/manifest.json.sig     它的签名
//! <发布源>/download/v<版本号>/<文件名>            清单里列出的文件
//! ```
//!
//! 它可以是一个 `http://` 或 `https://` 地址（项目的 GitHub Release、镜像），也可以是 controller 所在机器上的一个目录。
//! 发布源不需要可信：清单带签名，包的大小和 SHA-256 写在清单里，这里取回来的每样东西调用方都会核对。
//!
//! 这里的函数都是阻塞的（网络和磁盘），要在阻塞线程上调用，并且不能拿着 controller 的锁。

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use i3t_model::admin::ReleaseCause;
use i3t_model::update::{Artifact, LATEST_DIR, MANIFEST_FILE, SIGNATURE_FILE, SignedManifest, Version};
use i3t_update::FileDigest;

/// 项目的发布源：GitHub Release。
pub const DEFAULT_SOURCE: &str = "https://github.com/fuqiuluo/ice3tier/releases";

/// 清单最长这么多字节。正常的清单不到 2 KB；上限只是不让一个乱来的发布源塞给 controller 一大块内存。
const MAX_MANIFEST_LEN: u64 = 1024 * 1024;
/// 签名文件只有一行 86 个字符。
const MAX_SIGNATURE_LEN: u64 = 4096;

/// 连接发布源最多等多久。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 取清单最多用多久。
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(30);
/// 取一个包最多用多久。包有几十 MB，慢的线路上要几分钟。
const PACKAGE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// 取到一半的包在缓存目录里的后缀。核对通过之后才改成正式的名字。
const PARTIAL_SUFFIX: &str = ".part";

/// 一个发布源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// 地址前缀，不带末尾的斜杠。
    Http(String),
    /// 本机的一个目录。
    Dir(PathBuf),
}

/// 发布源格式无效。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("发布源 {0:?} 格式无效：必须为 https://… 或 http://… 地址，或 controller 所在主机的目录绝对路径")]
pub struct InvalidSource(String);

impl FromStr for Source {
    type Err = InvalidSource;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let text = s.trim();
        // 地址与路径均不允许包含控制字符（如 NUL、换行等）：该值会被持久化存储、写入操作记录并用于拼接请求。
        if text.chars().any(char::is_control) {
            return Err(InvalidSource(s.to_owned()));
        }
        let is_url = ["http://", "https://"].iter().any(|scheme| text.strip_prefix(scheme).is_some_and(|rest| !rest.is_empty()));
        if is_url && !text.contains(char::is_whitespace) {
            return Ok(Self::Http(text.trim_end_matches('/').to_owned()));
        }
        let path = Path::new(text);
        if path.is_absolute() { Ok(Self::Dir(path.to_owned())) } else { Err(InvalidSource(s.to_owned())) }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(base) => f.write_str(base),
            Self::Dir(dir) => write!(f, "{}", dir.display()),
        }
    }
}

/// 从发布源获取清单或发布包失败。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    #[error("无法从 {url} 获取文件")]
    Http {
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
    #[error("读写 {} 失败", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("发布源返回的签名文件格式无效")]
    BadSignatureFile,
    #[error("清单中的文件名 {0:?} 不是合法的纯文件名")]
    BadFileName(String),
    #[error("发布文件 {file} 校验失败：实际大小 {actual_size} 字节、SHA-256 {actual}，预期大小 {expected_size} 字节、SHA-256 {expected}")]
    Mismatch { file: String, expected_size: u64, expected: String, actual_size: u64, actual: String },
}

impl FetchError {
    /// 管理 API 里的原因代码，和 `Display` 写的那句话说的是同一件事。
    #[must_use]
    pub fn cause(&self) -> ReleaseCause {
        match self {
            Self::Http { url, source } => ReleaseCause::FetchFailed { url: url.clone(), error: source.to_string() },
            Self::Io { path, source } => ReleaseCause::Io { path: path.display().to_string(), error: source.to_string() },
            Self::BadSignatureFile => ReleaseCause::BadSignatureFile,
            Self::BadFileName(file) => ReleaseCause::BadFileName { file: file.clone() },
            Self::Mismatch { file, expected_size, actual_size, .. } => {
                ReleaseCause::Mismatch { file: file.clone(), expected_size: *expected_size, actual_size: *actual_size }
            }
        }
    }
}

impl Source {
    /// 取最新正式版的清单和签名。取回来的东西还没有验过签，调用方验过才能看里面的内容。
    ///
    /// # Errors
    ///
    /// 连接失败、文件不存在、文件超过大小上限，或签名文件内容无效。
    pub fn latest(&self) -> Result<SignedManifest, FetchError> {
        let manifest = self.read_text(&format!("{LATEST_DIR}/{MANIFEST_FILE}"), MAX_MANIFEST_LEN)?;
        let signature = self.read_text(&format!("{LATEST_DIR}/{SIGNATURE_FILE}"), MAX_SIGNATURE_LEN)?;
        SignedManifest::from_files(manifest, &signature).map_err(|_| FetchError::BadSignatureFile)
    }

    /// 把 `version` 的一个文件取到 `cache_dir` 里，核对大小和 SHA-256，返回它在缓存里的路径。
    ///
    /// 缓存里已经有一份核对得上的就直接用，不再取。取到一半的文件用另外的名字，所以缓存里叫正式名字的一定是完整的。
    ///
    /// # Errors
    ///
    /// 获取失败、写入缓存失败，或下载内容与清单校验不一致（此时不会在缓存目录残留文件）。
    pub fn fetch(&self, version: &Version, artifact: &Artifact, cache_dir: &Path) -> Result<PathBuf, FetchError> {
        if Path::new(&artifact.file).file_name().and_then(|name| name.to_str()) != Some(artifact.file.as_str()) {
            return Err(FetchError::BadFileName(artifact.file.clone()));
        }
        let dir = cache_dir.join(format!("v{version}"));
        let path = dir.join(&artifact.file);
        if FileDigest::of_file(&path).is_ok_and(|digest| digest.matches(artifact)) {
            return Ok(path);
        }
        fs::create_dir_all(&dir).map_err(io_error(&dir))?;
        let partial = dir.join(format!("{}{PARTIAL_SUFFIX}", artifact.file));
        let outcome = self.download(&format!("{}/{}", version.release_dir(), artifact.file), artifact, &partial).and_then(|()| {
            let digest = FileDigest::of_file(&partial).map_err(io_error(&partial))?;
            if !digest.matches(artifact) {
                return Err(FetchError::Mismatch {
                    file: artifact.file.clone(),
                    expected_size: artifact.size,
                    expected: artifact.sha256.to_string(),
                    actual_size: digest.size,
                    actual: digest.sha256.to_string(),
                });
            }
            fs::rename(&partial, &path).map_err(io_error(&path))
        });
        if outcome.is_err() {
            // 保留临时文件无意义（下次会重新完整下载）；若删除失败仅占用磁盘空间。
            let _removed = fs::remove_file(&partial);
        }
        outcome.map(|()| path)
    }

    fn read_text(&self, relative: &str, limit: u64) -> Result<String, FetchError> {
        match self {
            Self::Http(base) => {
                let url = format!("{base}/{relative}");
                let http_error = |source| FetchError::Http { url: url.clone(), source: Box::new(source) };
                let mut response = agent(MANIFEST_TIMEOUT).get(&url).call().map_err(http_error)?;
                response.body_mut().with_config().limit(limit).read_to_string().map_err(http_error)
            }
            Self::Dir(dir) => {
                let path = dir.join(relative);
                let mut text = String::new();
                let file = File::open(&path).map_err(io_error(&path))?;
                file.take(limit).read_to_string(&mut text).map_err(io_error(&path))?;
                Ok(text)
            }
        }
    }

    /// 把一个文件写到 `to`。最多写 `artifact.size + 1` 字节：多出来的那一个字节足够让之后的核对发现它太长，
    /// 又不会让一个乱来的发布源把磁盘写满。
    fn download(&self, relative: &str, artifact: &Artifact, to: &Path) -> Result<(), FetchError> {
        let limit = artifact.size.saturating_add(1);
        let mut out = File::create(to).map_err(io_error(to))?;
        match self {
            Self::Http(base) => {
                let url = format!("{base}/{relative}");
                let http_error = |source| FetchError::Http { url: url.clone(), source: Box::new(source) };
                let response = agent(PACKAGE_TIMEOUT).get(&url).call().map_err(http_error)?;
                let mut body = response.into_body().into_reader().take(limit);
                io::copy(&mut body, &mut out).map_err(|source| http_error(ureq::Error::Io(source)))?;
            }
            Self::Dir(dir) => {
                let path = dir.join(relative);
                let mut file = File::open(&path).map_err(io_error(&path))?.take(limit);
                io::copy(&mut file, &mut out).map_err(io_error(&path))?;
            }
        }
        out.sync_all().map_err(io_error(to))
    }
}

/// 删掉缓存里不属于 `keep` 这个版本的包。换了版本之后旧的包不会再有人要。
pub fn prune_cache(cache_dir: &Path, keep: &Version) {
    let keep = format!("v{keep}");
    let Ok(entries) = fs::read_dir(cache_dir) else { return };
    for entry in entries.filter_map(Result::ok).filter(|entry| entry.file_name().to_str() != Some(keep.as_str())) {
        if let Err(error) = fs::remove_dir_all(entry.path()) {
            tracing::warn!(path = %entry.path().display(), %error, "删除缓存中的旧版本更新包失败");
        }
    }
}

fn agent(budget: Duration) -> ureq::Agent {
    ureq::Agent::config_builder().timeout_connect(Some(CONNECT_TIMEOUT)).timeout_global(Some(budget)).build().new_agent()
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> FetchError {
    let path = path.to_owned();
    move |source| FetchError::Io { path, source }
}

#[cfg(test)]
mod tests {
    use i3t_model::update::Sha256;
    use ring::digest;

    use super::*;

    fn artifact(file: &str, content: &[u8]) -> Artifact {
        let hash: [u8; 32] = digest::digest(&digest::SHA256, content).as_ref().try_into().unwrap();
        Artifact { file: file.to_owned(), size: u64::try_from(content.len()).unwrap(), sha256: Sha256::from_bytes(hash) }
    }

    /// 一个照着模块开头的布局摆的发布目录。
    fn mirror(version: &Version, files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let release = root.path().join(version.release_dir());
        fs::create_dir_all(&release).unwrap();
        for (name, content) in files {
            fs::write(release.join(name), content).unwrap();
        }
        root
    }

    #[test]
    fn sources_are_urls_or_absolute_directories() {
        assert_eq!(DEFAULT_SOURCE.parse::<Source>().unwrap(), Source::Http(DEFAULT_SOURCE.to_owned()));
        assert_eq!(" http://mirror.lan/releases/ ".parse::<Source>().unwrap(), Source::Http("http://mirror.lan/releases".to_owned()));
        // 绝对路径的写法各个系统不一样，拿一个真的来试。
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(dir.path().to_str().unwrap().parse::<Source>().unwrap(), Source::Dir(dir.path().to_owned()));
        for bad in ["", "releases", "./releases", "ftp://x/y", "https://", "http://a b/c"] {
            assert!(bad.parse::<Source>().is_err(), "{bad:?} 不应该被接受");
        }
        // 控制字符：存不进数据库的文本列（NUL），也不该出现在地址和路径里。
        for bad in ["https://mirror.lan/a\0b", "https://mirror.lan/\u{7}", "/srv/rele\0ase"] {
            assert!(bad.parse::<Source>().is_err(), "{bad:?} 不应该被接受");
        }
        assert_eq!("http://mirror.lan/r/".parse::<Source>().unwrap().to_string(), "http://mirror.lan/r");
    }

    #[test]
    fn the_latest_manifest_is_read_from_a_directory_without_being_interpreted() {
        let root = tempfile::tempdir().unwrap();
        let latest = root.path().join(LATEST_DIR);
        fs::create_dir_all(&latest).unwrap();
        fs::write(latest.join(MANIFEST_FILE), "{ 原文 }\n").unwrap();
        fs::write(latest.join(SIGNATURE_FILE), format!("{}\n", "A".repeat(86))).unwrap();
        let signed = Source::Dir(root.path().to_owned()).latest().unwrap();
        assert_eq!(signed.manifest, "{ 原文 }\n");

        fs::write(latest.join(SIGNATURE_FILE), "不是签名").unwrap();
        assert!(matches!(Source::Dir(root.path().to_owned()).latest(), Err(FetchError::BadSignatureFile)));
        fs::remove_file(latest.join(MANIFEST_FILE)).unwrap();
        assert!(matches!(Source::Dir(root.path().to_owned()).latest(), Err(FetchError::Io { .. })));
    }

    #[test]
    fn a_package_is_fetched_once_and_verified() {
        let version = Version::new(0, 3, 0);
        let content = b"new program".repeat(1000);
        let root = mirror(&version, &[("i3t-linux-x86_64", &content)]);
        let cache = tempfile::tempdir().unwrap();
        let source = Source::Dir(root.path().to_owned());
        let artifact = artifact("i3t-linux-x86_64", &content);

        let path = source.fetch(&version, &artifact, cache.path()).unwrap();
        assert_eq!(path, cache.path().join("v0.3.0").join("i3t-linux-x86_64"));
        assert_eq!(fs::read(&path).unwrap(), content);

        // 发布源没了也不要紧：缓存里那一份核对得上，不会再去取。
        drop(root);
        assert_eq!(source.fetch(&version, &artifact, cache.path()).unwrap(), path);
    }

    #[test]
    fn a_package_that_does_not_match_the_manifest_is_not_kept() {
        let version = Version::new(0, 3, 0);
        let root = mirror(&version, &[("i3t-linux-x86_64", b"tampered program")]);
        let cache = tempfile::tempdir().unwrap();
        let source = Source::Dir(root.path().to_owned());

        let wrong_hash = artifact("i3t-linux-x86_64", b"original program");
        assert!(matches!(source.fetch(&version, &wrong_hash, cache.path()), Err(FetchError::Mismatch { actual_size: 16, .. })));
        let too_long = Artifact { size: 4, ..artifact("i3t-linux-x86_64", b"tamp") };
        assert!(
            matches!(source.fetch(&version, &too_long, cache.path()), Err(FetchError::Mismatch { actual_size: 5, .. })),
            "多写的只有一个字节"
        );
        let files: Vec<_> = fs::read_dir(cache.path().join("v0.3.0")).unwrap().collect();
        assert!(files.is_empty(), "核对不上的包不应该留在缓存里：{files:?}");
    }

    #[test]
    fn a_corrupt_cached_package_is_fetched_again() {
        let version = Version::new(0, 3, 0);
        let root = mirror(&version, &[("i3t-linux-x86_64", b"program")]);
        let cache = tempfile::tempdir().unwrap();
        let source = Source::Dir(root.path().to_owned());
        let artifact = artifact("i3t-linux-x86_64", b"program");
        let path = source.fetch(&version, &artifact, cache.path()).unwrap();
        fs::write(&path, b"bit rot").unwrap();
        assert_eq!(fs::read(source.fetch(&version, &artifact, cache.path()).unwrap()).unwrap(), b"program");
    }

    #[test]
    fn file_names_that_escape_the_cache_are_refused() {
        let version = Version::new(0, 3, 0);
        let cache = tempfile::tempdir().unwrap();
        let source = Source::Dir(cache.path().to_owned());
        for name in ["../escape", "a/b", "", ".."] {
            assert!(matches!(source.fetch(&version, &artifact(name, b"x"), cache.path()), Err(FetchError::BadFileName(_))), "{name:?}");
        }
    }

    #[test]
    fn pruning_keeps_only_the_current_version() {
        let cache = tempfile::tempdir().unwrap();
        for version in ["v0.2.0", "v0.3.0"] {
            fs::create_dir_all(cache.path().join(version)).unwrap();
            fs::write(cache.path().join(version).join("i3t-linux-x86_64"), b"x").unwrap();
        }
        prune_cache(cache.path(), &Version::new(0, 3, 0));
        let left: Vec<_> = fs::read_dir(cache.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(left, ["v0.3.0"]);
    }
}
