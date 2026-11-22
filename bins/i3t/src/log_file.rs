//! Windows 服务的日志文件。服务没有终端，也没有 journald、newsyslog 替它收日志和轮转，这里自己来。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// 一个日志文件最多这么大。
#[cfg(windows)]
pub const FILE_LIMIT: u64 = 16 * 1024 * 1024;

/// 日志文件（`i3t.log`）和它的一份归档（`i3t.log.old`）。
///
/// 每写一条之前先看文件里还装不装得下，装不下就轮转：文件改名成归档，顶掉上一份，再开一个空的接着写。
/// 两个文件都不超过上限，合起来不超过两倍，服务运行多久都一样。
/// 改不了名（比如归档正被别的程序打开着）就清空日志文件接着写：宁可丢掉旧日志，也不能写满状态目录所在的盘。
pub struct LogFile {
    path: PathBuf,
    archive: PathBuf,
    limit: u64,
    open: Mutex<Option<Open>>,
}

/// 打开着的日志文件和里面已经有多少字节。
struct Open {
    file: File,
    len: u64,
}

impl LogFile {
    /// 写到 `path` 的日志，每个文件不超过 `limit` 字节。第一次写的时候才打开文件。
    pub fn new(path: PathBuf, limit: u64) -> Self {
        let archive = path.with_extension("log.old");
        Self { path, archive, limit, open: Mutex::new(None) }
    }

    /// 添一行。和别的日志一样受上限管着。
    pub fn append_line(&self, line: &str) {
        // 拼成一条再写：分开写的话，轮转可能正好落在这一行和它的换行之间。
        let _dropped = self.write_record(format!("{line}\n").as_bytes());
    }

    fn write_record(&self, record: &[u8]) -> io::Result<()> {
        // 一条比整个文件还大的只留开头，否则文件就超过了上限。
        let record = &record[..record.len().min(usize::try_from(self.limit).unwrap_or(usize::MAX))];
        let size = record.len() as u64;
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        // 先拿出来：下面任何一步出错，这里就是空的，下一条重新打开。
        let mut current = match open.take() {
            Some(current) => current,
            None => self.open_existing()?,
        };
        if current.len > 0 && current.len + size > self.limit {
            // 改名之前先关上：Windows 上打开着的文件不一定改得了名。
            drop(current);
            current = self.rotate()?;
        }
        current.file.write_all(record)?;
        current.len += size;
        *open = Some(current);
        Ok(())
    }

    /// 接着已有的文件写。
    fn open_existing(&self) -> io::Result<Open> {
        // 比上限还大的文件是旧版本留下的：那时只在启动时轮转，一次运行写了多少就有多大。
        let _kept = keep_tail(&self.archive, self.limit);
        let _kept = keep_tail(&self.path, self.limit);
        reject_link(&self.path)?;
        let file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let len = file.metadata()?.len();
        Ok(Open { file, len })
    }

    /// 文件改名成归档，开一个新的；改不了名就把文件清空。
    fn rotate(&self) -> io::Result<Open> {
        if reject_link(&self.archive).and_then(|()| fs::rename(&self.path, &self.archive)).is_ok() {
            return self.open_existing();
        }
        reject_link(&self.path)?;
        let file = OpenOptions::new().create(true).write(true).truncate(true).open(&self.path)?;
        Ok(Open { file, len: 0 })
    }
}

/// 给 `tracing_subscriber` 当写入器用（`Arc<LogFile>`）。它每条日志调一次 `write_all`。
impl Write for &LogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // 写不进去就算了，不能让日志拖住节点；下一条会重新打开文件再试。
        let _dropped = self.write_record(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 文件比 `limit` 大就只留最后的部分，从一行的开头算起，不超过 `limit` 字节。没有这个文件不算错。
fn keep_tail(path: &Path, limit: u64) -> io::Result<()> {
    reject_link(path)?;
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        file => file?,
    };
    let len = file.metadata()?.len();
    if len <= limit {
        return Ok(());
    }
    // 多读前面一个字节：它是换行的话，最后 `limit` 字节正好从一行的开头起。
    let mut tail = Vec::new();
    file.seek(SeekFrom::Start(len - limit - 1))?;
    (&file).take(limit + 1).read_to_end(&mut tail)?;
    let start = tail.iter().position(|&byte| byte == b'\n').map_or(1, |newline| newline + 1).min(tail.len());
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&tail[start..])?;
    file.set_len((tail.len() - start) as u64)
}

/// 确认路径本身不是符号链接或重解析点（如 NTFS Junction），免得以 `LocalSystem` 运行的服务被引着写到别处。
fn reject_link(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || is_reparse_point(&meta) => {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "拒绝跟随符号链接或重解析点"))
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(windows)]
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_meta: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const LIMIT: u64 = 1024;

    fn size(path: &Path) -> u64 {
        fs::metadata(path).map_or(0, |meta| meta.len())
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap_or_default()
    }

    /// 状态目录里所有日志文件合起来多大。
    fn total(dir: &Path) -> u64 {
        fs::read_dir(dir).expect("读状态目录").map(|entry| size(&entry.expect("目录项").path())).sum()
    }

    /// 日志里第几条记录（`record=N`）。
    fn records(text: &str) -> Vec<u64> {
        text.lines().filter_map(|line| line.rsplit_once("record=")).map(|(_, n)| n.trim().parse().expect("记录编号")).collect()
    }

    #[test]
    fn a_long_running_service_rotates_while_writing_and_its_log_stays_bounded() {
        let dir = tempfile::tempdir().expect("临时状态目录");
        let path = dir.path().join("i3t.log");
        let archive = dir.path().join("i3t.log.old");
        let log = Arc::new(LogFile::new(path.clone(), LIMIT));
        let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(Arc::clone(&log)).finish();

        // 同一个写入器连着写约 30 个文件的量，中间不重启。
        let filler = "x".repeat(60);
        tracing::subscriber::with_default(subscriber, || {
            for record in 0..300_u64 {
                tracing::info!(filler = filler.as_str(), record);
                assert!(size(&path) <= LIMIT, "第 {record} 条之后日志文件 {} 字节，超过了 {LIMIT}", size(&path));
                assert!(size(&archive) <= LIMIT, "第 {record} 条之后归档 {} 字节，超过了 {LIMIT}", size(&archive));
                assert!(total(dir.path()) <= 2 * LIMIT, "第 {record} 条之后合计 {} 字节", total(dir.path()));
            }
        });

        let active = records(&read(&path));
        let archived = records(&read(&archive));
        assert_eq!(active.last(), Some(&299), "最新的一条不用重启就能在日志文件里读到");
        assert!(archived.first().is_some_and(|&first| first > 0), "轮转了不止一次，最早的记录已经清掉：{archived:?}");
        let kept: Vec<u64> = archived.iter().chain(&active).copied().collect();
        let expected: Vec<u64> = (kept[0]..300).collect();
        assert_eq!(kept, expected, "归档接着日志文件，中间没有丢记录");
        assert_eq!(fs::read_dir(dir.path()).expect("读状态目录").count(), 2, "只有日志文件和一份归档");
    }

    #[test]
    fn the_last_error_of_a_failed_run_obeys_the_same_limit() {
        let dir = tempfile::tempdir().expect("临时状态目录");
        let path = dir.path().join("i3t.log");
        let log = LogFile::new(path.clone(), LIMIT);
        let full = "y".repeat(usize::try_from(LIMIT).expect("上限放得进 usize") - 1);
        log.append_line(&full);
        assert_eq!(size(&path), LIMIT);

        log.append_line("i3t: 配置文件读不了");
        assert_eq!(read(&path), "i3t: 配置文件读不了\n", "写满之后报错的那一行进了新的日志文件");
        assert_eq!(read(&dir.path().join("i3t.log.old")), format!("{full}\n"));

        log.append_line(&"z".repeat(3 * usize::try_from(LIMIT).expect("上限放得进 usize")));
        assert_eq!(size(&path), LIMIT, "比整个文件还大的一行只留开头");
        assert!(total(dir.path()) <= 2 * LIMIT);
    }

    #[test]
    fn oversized_files_left_by_an_older_version_keep_only_their_tail() {
        let dir = tempfile::tempdir().expect("临时状态目录");
        let path = dir.path().join("i3t.log");
        let archive = dir.path().join("i3t.log.old");
        // 旧版本只在启动时轮转：一次运行写多少，归档和日志文件就有多大。
        let old: String = (0..200).map(|record| format!("old record={record}\n")).collect();
        fs::write(&path, &old).expect("写旧日志");
        fs::write(&archive, "older\n".repeat(1000)).expect("写旧归档");

        LogFile::new(path.clone(), LIMIT).append_line("i3t: 新版本的第一行");

        assert_eq!(read(&path), "i3t: 新版本的第一行\n");
        let archived = read(&archive);
        assert!(size(&archive) <= LIMIT, "归档 {} 字节", size(&archive));
        assert!(!archived.contains("older"), "更早的归档被顶掉了");
        assert!(old.ends_with(&archived) && archived.starts_with("old record="), "旧日志留下了最后的、从一行开头起的部分：{archived:?}");
        assert_eq!(records(&archived).last(), Some(&199));
        assert!(total(dir.path()) <= 2 * LIMIT, "合计 {} 字节", total(dir.path()));
    }

    #[test]
    fn cutting_an_oversized_file_keeps_whole_lines_when_the_cut_falls_on_a_line_break() {
        let dir = tempfile::tempdir().expect("临时状态目录");
        let path = dir.path().join("i3t.log");
        // 每行 16 字节，最后 LIMIT 字节正好是 64 行。
        fs::write(&path, "0123456789abcde\n".repeat(100)).expect("写旧日志");
        keep_tail(&path, LIMIT).expect("裁短");
        assert_eq!(read(&path), "0123456789abcde\n".repeat(64));
    }

    #[test]
    fn when_the_archive_cannot_be_replaced_the_log_is_emptied_instead_of_growing() {
        let dir = tempfile::tempdir().expect("临时状态目录");
        let path = dir.path().join("i3t.log");
        // 归档的位置被一个目录占着，改名一定失败。
        let blocker = dir.path().join("i3t.log.old");
        fs::create_dir(&blocker).expect("建目录");
        fs::write(blocker.join("keep"), "").expect("目录里放个文件");

        let log = LogFile::new(path.clone(), LIMIT);
        for record in 0..100 {
            log.append_line(&format!("{} record={record}", "w".repeat(60)));
            assert!(size(&path) <= LIMIT, "第 {record} 条之后日志文件 {} 字节", size(&path));
        }
        assert_eq!(records(&read(&path)).last(), Some(&99), "清空之后接着写");
        assert!(blocker.join("keep").exists(), "占着位置的目录没有动");
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_not_written_through_a_link() {
        let dir = tempfile::tempdir().expect("临时状态目录");
        let elsewhere = tempfile::tempdir().expect("别处");
        let target = elsewhere.path().join("target");
        fs::write(&target, "").expect("建链接的目标");
        let path = dir.path().join("i3t.log");
        std::os::unix::fs::symlink(&target, &path).expect("建符号链接");

        LogFile::new(path, LIMIT).append_line("i3t: 不该写到链接指向的地方");

        assert_eq!(read(&target), "", "链接指向的文件没有被写");
    }
}
