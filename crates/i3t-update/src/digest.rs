//! 文件大小与 SHA-256 摘要计算。

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use i3t_model::update::{Artifact, Sha256};
use ring::digest::{Context, SHA256};

/// 文件的实际大小与 SHA-256 摘要，用于与发布清单中的记录比对。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDigest {
    pub size: u64,
    pub sha256: Sha256,
}

impl FileDigest {
    /// 从头读取文件并计算其大小与 SHA-256 摘要。该调用为阻塞 I/O，更新包通常为数十 MB，异步代码中应置于阻塞线程池中执行。
    ///
    /// # Errors
    ///
    /// 无法打开或读取文件时返回错误。
    pub fn of_file(path: &Path) -> io::Result<Self> {
        let mut hasher = Hasher(Context::new(&SHA256));
        let size = io::copy(&mut File::open(path)?, &mut hasher)?;
        let sha256: [u8; Sha256::LEN] = hasher.0.finish().as_ref().try_into().expect("SHA-256 摘要长度固定为 32 字节");
        Ok(Self { size, sha256: Sha256::from_bytes(sha256) })
    }

    #[must_use]
    pub fn matches(&self, artifact: &Artifact) -> bool {
        self.size == artifact.size && self.sha256 == artifact.sha256
    }
}

/// 将 [`io::copy`] 读取的字节流式写入哈希上下文。
struct Hasher(Context);

impl Write for Hasher {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_matches_the_published_test_vector() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abc");
        std::fs::write(&path, b"abc").unwrap();
        let digest = FileDigest::of_file(&path).unwrap();
        assert_eq!(digest.size, 3);
        // FIPS 180-2 附录 B.1 的例子。
        assert_eq!(digest.sha256.to_string(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn a_file_matches_only_an_artifact_with_the_same_size_and_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, vec![7; 200_000]).unwrap();
        let digest = FileDigest::of_file(&path).unwrap();
        let artifact = Artifact { file: "file".to_owned(), size: 200_000, sha256: digest.sha256 };
        assert!(digest.matches(&artifact));
        assert!(!digest.matches(&Artifact { size: 200_001, ..artifact.clone() }));
        assert!(!digest.matches(&Artifact { sha256: Sha256::from_bytes([0; 32]), ..artifact }));
        assert!(FileDigest::of_file(&dir.path().join("missing")).is_err());
    }
}
