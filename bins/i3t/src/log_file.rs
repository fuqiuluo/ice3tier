//! Windows 服务的日志文件。服务没有终端，也没有 journald、newsyslog 替它收日志和轮转，这里自己来。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// 一个日志文件最多这么大。
#[cfg(windows)]
pub const FILE_LIMIT: u64 = 16 * 1024 * 1024;

/// 日志文件打不开、过大的归档处理不了的时候，过这么久再试。
const RETRY_AFTER: Duration = Duration::from_secs(1);

/// 裁短文件时一次读写这么多。
const CHUNK: usize = 64 * 1024;

/// 日志文件（`i3t.log`）和它的一份归档（`i3t.log.old`）。
///
/// 每写一条之前先看文件里还装不装得下，装不下就轮转：文件改名成归档，顶掉上一份，再开一个空的接着写。
/// 两个文件都不超过上限，合起来不超过两倍，服务运行多久都一样。
///
/// Windows 上别的程序开着其中一个文件看的时候（`Get-Content -Wait`）改不了名。这时把内容抄进归档，清空日志文件接着写；
/// 抄也抄不成，这一份就不留了：宁可丢掉旧日志，也不能写满状态目录所在的盘。
pub struct LogFile {
    path: PathBuf,
    archive: PathBuf,
    limit: u64,
    state: Mutex<State>,
}

struct State {
    open: Option<Open>,
    /// 日志文件打不开、轮转不了之后，到这个时刻之前不再试：免得每条日志都把文件系统碰一遍。
    closed_until: Option<Instant>,
    /// 什么时候去看归档有没有超过上限。看过没有问题就不再看：之后只有这里往归档里放东西。
    check_archive_at: Option<Instant>,
}

/// 打开着的日志文件和里面已经有多少字节。
struct Open {
    file: File,
    len: u64,
}

impl LogFile {
    /// 写到 `path` 的日志，每个文件不超过 `limit` 字节。
    pub fn open(path: PathBuf, limit: u64) -> Self {
        let mut archive = path.clone().into_os_string();
        archive.push(".old");
        let state = State { open: None, closed_until: None, check_archive_at: Some(Instant::now()) };
        let log = Self { path, archive: archive.into(), limit, state: Mutex::new(state) };
        // 现在就打开：旧版本留下的过大文件这时就处理掉，不等第一条日志（日志级别设得高的话，可能很久都没有一条）。
        log.write_record(b"", true);
        log
    }

    /// 添一行。和别的日志一样受上限管着。这是报错的最后一条路，文件刚才打不开也再试一次。
    pub fn append_line(&self, line: &str) {
        // 拼成一条再写：分开写的话，轮转可能正好落在这一行和它的换行之间。
        self.write_record(format!("{line}\n").as_bytes(), true);
    }

    /// 写一条，写不进去就丢掉。`insist`：文件刚才打不开、还没到再试的时候，这一条也去试。
    fn write_record(&self, record: &[u8], insist: bool) {
        // 一条比整个文件还大的只留开头：断在字符的边界上，补上换行。
        let room = usize::try_from(self.limit).unwrap_or(usize::MAX);
        let (head, newline): (&[u8], &[u8]) = if record.len() <= room {
            (record, b"")
        } else {
            (&record[..char_boundary(record, room.saturating_sub(1))], &b"\n"[..room.min(1)])
        };
        let size = (head.len() + newline.len()) as u64;

        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.check_archive_at.is_some_and(|at| at <= Instant::now()) {
            state.check_archive_at = self.fit_archive().is_err().then(|| Instant::now() + RETRY_AFTER);
        }
        if state.open.is_none() && !insist && state.closed_until.is_some_and(|until| Instant::now() < until) {
            return;
        }
        match self.ready(state.open.take(), size) {
            Ok(mut current) => {
                current.len = match current.file.write_all(head).and_then(|()| current.file.write_all(newline)) {
                    Ok(()) => current.len.saturating_add(size),
                    // 没写进去（盘满了），或者只写进去一半：有多少以文件为准。文件留着开，下一条接着试。
                    Err(_) => current.file.metadata().map_or(current.len.saturating_add(size), |file| file.len()),
                };
                state.open = Some(current);
                state.closed_until = None;
            }
            Err(_) => state.closed_until = Some(Instant::now() + RETRY_AFTER),
        }
    }

    /// 打开着的、还装得下 `size` 字节的日志文件：没开着就打开，装不下就先轮转。
    fn ready(&self, open: Option<Open>, size: u64) -> io::Result<Open> {
        let current = match open {
            Some(current) => current,
            None => {
                // 比上限还大的是旧版本留下的：那时只在启动时轮转，一次运行写了多少就有多大。裁不了的，下面轮转时清空。
                let _oversized = shrink(&self.path, self.limit);
                self.open_active()?
            }
        };
        if current.len == 0 || current.len.saturating_add(size) <= self.limit {
            return Ok(current);
        }
        // 先关上自己开着的，再去改名。
        let len = current.len;
        drop(current);
        self.rotate(len)
    }

    fn open_active(&self) -> io::Result<Open> {
        let file = open_unlinked(&self.path, OpenOptions::new().create(true).append(true))?;
        let len = file.metadata()?.len();
        Ok(Open { file, len })
    }

    /// 日志文件（里面有 `len` 字节）留作归档，再开一个空的。
    fn rotate(&self, len: u64) -> io::Result<Open> {
        // 比上限还大的（旧版本留下、又裁不了的）不留：归档也不能超过上限。
        if len <= self.limit {
            if fs::rename(&self.path, &self.archive).is_ok() {
                return self.open_active();
            }
            // 改不了名，多半是别的程序正开着其中一个文件。把内容抄进归档；抄不成这一份就不留了。
            let _lost = self.copy_to_archive();
        }
        // 清空之后用追加的方式重新打开：这样别人中途清空了文件，也不会接着往原来的位置写。
        open_unlinked(&self.path, OpenOptions::new().create(true).write(true))?.set_len(0)?;
        self.open_active()
    }

    /// 日志文件的内容抄进归档，盖掉归档原来的内容。两个文件都留在原地，别的程序开着它们也不碍事。
    fn copy_to_archive(&self) -> io::Result<()> {
        let active = open_unlinked(&self.path, OpenOptions::new().read(true))?;
        let mut archive = open_unlinked(&self.archive, OpenOptions::new().create(true).write(true))?;
        archive.set_len(0)?;
        io::copy(&mut active.take(self.limit), &mut archive)?;
        Ok(())
    }

    /// 旧版本留下的归档可能比上限大：裁短，裁不了就删掉。都不成（正被别的程序开着）就是错误，过一会儿再试。
    fn fit_archive(&self) -> io::Result<()> {
        match fs::symlink_metadata(&self.archive) {
            Ok(archive) if archive.is_file() && archive.len() > self.limit => {
                shrink(&self.archive, self.limit).or_else(|_| fs::remove_file(&self.archive))
            }
            // 没有归档、没有超过上限，或者那里根本不是文件。
            _ => Ok(()),
        }
    }
}

/// 给 `tracing_subscriber` 当写入器用（`Arc<LogFile>`）。它每条日志调一次 `write_all`。
impl Write for &LogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // 写不进去就算了，不能让日志拖住节点。
        self.write_record(buf, false);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 文件比 `limit` 大就裁到不超过 `limit`，只留最后那些完整的行。留不下来（盘满了，原地往前挪也写不进去）就清空，
/// 先把地方让出来。没有这个文件不算错。
fn shrink(path: &Path, limit: u64) -> io::Result<()> {
    let mut file = match open_unlinked(path, OpenOptions::new().read(true).write(true)) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        file => file?,
    };
    let len = file.metadata()?.len();
    if len <= limit {
        return Ok(());
    }
    keep_tail(&mut file, len, limit).or_else(|_| file.set_len(0))
}

/// 把 `len` 字节的文件裁到不超过 `limit` 字节：最后那些完整的行原地挪到开头，不另占地方，一次只读写 [`CHUNK`] 字节。
/// 最后一行自己就比 `limit` 长的话什么都不留。
fn keep_tail(file: &mut File, len: u64, limit: u64) -> io::Result<()> {
    let mut chunk = vec![0; CHUNK];
    // 留下的部分从哪里起：从倒数第 `limit + 1` 个字节往后找到的第一个换行之后。
    // 那个字节自己就是换行的话，最后 `limit` 字节正好是完整的行。
    let mut at = len.saturating_sub(limit.saturating_add(1));
    file.seek(SeekFrom::Start(at))?;
    let mut from = loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            // 到末尾都没有换行。
            break at;
        }
        if let Some(newline) = chunk[..read].iter().position(|&byte| byte == b'\n') {
            break at + newline as u64 + 1;
        }
        at += read as u64;
    };
    // 读的位置总在写的位置后面，挪的时候盖不到还没读的部分。
    let mut to = 0;
    loop {
        file.seek(SeekFrom::Start(from))?;
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        file.seek(SeekFrom::Start(to))?;
        file.write_all(&chunk[..read])?;
        from += read as u64;
        to += read as u64;
    }
    file.set_len(to)
}

/// `bytes` 里不超过 `at` 的最后一个字符边界。UTF-8 的一个字符最多有三个后续字节（`10xxxxxx`）。
fn char_boundary(bytes: &[u8], at: usize) -> usize {
    (at.saturating_sub(3)..=at).rev().find(|&index| bytes.get(index).is_none_or(|byte| byte & 0xC0 != 0x80)).unwrap_or(at)
}

/// 打开日志用的文件。路径是符号链接或别的重解析点（如 NTFS Junction）时不打开，
/// 免得以 `LocalSystem` 运行的服务被引着写到别处。
#[cfg(windows)]
fn open_unlinked(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    // 带着这个标志，路径是链接时打开的是链接自己，不是它指向的文件。再看打开的这一个是不是重解析点：
    // 看的和打开的是同一个东西，中间没有空子可以换掉它。
    let file = options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "拒绝跟随符号链接或重解析点"));
    }
    Ok(file)
}

/// 别的系统上节点的日志不写文件，这里只有测试用得到。
#[cfg(not(windows))]
fn open_unlinked(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    options.open(path)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// 测试用的上限，一个文件装得下十来条。
    const ROOM: usize = 1024;
    const LIMIT: u64 = ROOM as u64;

    fn size(path: &Path) -> u64 {
        fs::metadata(path).map_or(0, |meta| meta.len())
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap_or_default()
    }

    /// 状态目录里所有日志文件合起来多大。
    fn total(dir: &Path) -> u64 {
        fs::read_dir(dir).unwrap().map(|entry| size(&entry.unwrap().path())).sum()
    }

    /// 日志里的记录编号（每行末尾的 `record=N`）。
    fn records(text: &str) -> Vec<u64> {
        text.lines().filter_map(|line| line.rsplit_once("record=")).map(|(_, n)| n.trim().parse().unwrap()).collect()
    }

    /// 第 `record` 条，七十来个字节。
    fn line(record: u64) -> String {
        format!("{} record={record}", "w".repeat(60))
    }

    /// 归档接着日志文件，里面的记录一条不缺，直到第 `last` 条。
    fn assert_nothing_lost(archive: &Path, path: &Path, last: u64) {
        let kept: Vec<u64> = records(&read(archive)).into_iter().chain(records(&read(path))).collect();
        let expected: Vec<u64> = (kept[0]..=last).collect();
        assert_eq!(kept, expected, "归档接着日志文件，中间没有丢记录");
    }

    fn write(log: &LogFile, record: &str) {
        let mut writer = log;
        writer.write_all(record.as_bytes()).unwrap();
    }

    #[test]
    fn a_long_running_service_rotates_while_writing_and_its_log_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t.log");
        let archive = dir.path().join("i3t.log.old");
        let log = Arc::new(LogFile::open(path.clone(), LIMIT));
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

        assert_eq!(records(&read(&path)).last(), Some(&299), "最新的一条不用重启就能在日志文件里读到");
        assert!(records(&read(&archive))[0] > 0, "轮转了不止一次，最早的记录已经清掉");
        assert_nothing_lost(&archive, &path, 299);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2, "只有日志文件和一份归档");
    }

    #[test]
    fn threads_logging_at_once_keep_whole_lines_and_the_bound() {
        const THREADS: usize = 4;
        const RECORDS: u64 = 200;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t.log");
        let archive = dir.path().join("i3t.log.old");
        let log = Arc::new(LogFile::open(path.clone(), LIMIT));
        let dispatch = tracing::Dispatch::new(tracing_subscriber::fmt().with_ansi(false).with_writer(Arc::clone(&log)).finish());

        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                let (dispatch, path, archive, dir) = (&dispatch, &path, &archive, dir.path());
                scope.spawn(move || {
                    tracing::dispatcher::with_default(dispatch, || {
                        for record in 0..RECORDS {
                            tracing::info!(thread, record);
                            assert!(size(path) <= LIMIT && size(archive) <= LIMIT && total(dir) <= 2 * LIMIT);
                        }
                    });
                });
            }
        });

        // 每一行都完整（轮转没有落在一条的中间，两个线程的也没有搅在一起），每个线程留下的记录是连着的。
        let text = read(&archive) + &read(&path);
        let mut next = [None; THREADS];
        for line in text.lines() {
            let (thread, record) = line.split_once(" thread=").and_then(|(_, fields)| fields.split_once(" record=")).expect(line);
            let (thread, record): (usize, u64) = (thread.parse().expect(line), record.parse().expect(line));
            assert!(next[thread].is_none_or(|expected| expected == record), "线程 {thread} 的第 {record} 条前面缺了：{line}");
            next[thread] = Some(record + 1);
        }
        assert_eq!(records(&read(&path)).last(), Some(&(RECORDS - 1)), "最后写的一条在日志文件的末尾");
    }

    #[test]
    fn the_last_error_of_a_failed_run_obeys_the_same_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t.log");
        let archive = dir.path().join("i3t.log.old");
        let log = LogFile::open(path.clone(), LIMIT);
        let full = "y".repeat(ROOM - 1);
        log.append_line(&full);
        assert_eq!(size(&path), LIMIT);

        log.append_line("i3t: 配置文件读不了");
        assert_eq!(read(&path), "i3t: 配置文件读不了\n", "写满之后报错的那一行进了新的日志文件");
        assert_eq!(read(&archive), format!("{full}\n"));

        // 比整个文件还大的一行只留开头：断在字符的边界上，换行还在。
        log.append_line(&format!("i{}", "日".repeat(1000)));
        assert_eq!(fs::read_to_string(&path).expect("还是 UTF-8"), format!("i{}\n", "日".repeat(340)));
        log.append_line(&"z".repeat(3 * ROOM));
        assert_eq!(read(&path), format!("{}\n", "z".repeat(ROOM - 1)));
        assert!(total(dir.path()) <= 2 * LIMIT);
    }

    #[test]
    fn oversized_files_left_by_an_older_version_keep_only_their_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t.log");
        let archive = dir.path().join("i3t.log.old");
        // 旧版本只在启动时轮转：一次运行写多少，归档和日志文件就有多大。
        let old: String = (0..200).map(|record| format!("old record={record}\n")).collect();
        let older = "older\n".repeat(1000);
        fs::write(&path, &old).unwrap();
        fs::write(&archive, &older).unwrap();

        // 一打开就裁，不等第一条日志：日志级别设得高的节点可能很久都不写一条。
        let log = LogFile::open(path.clone(), LIMIT);
        let (kept, kept_older) = (read(&path), read(&archive));
        assert!(size(&path) <= LIMIT && size(&archive) <= LIMIT, "日志 {} 字节，归档 {} 字节", size(&path), size(&archive));
        assert!(old.ends_with(&kept) && kept.starts_with("old record="), "旧日志留下了最后那些完整的行：{kept:?}");
        assert!(older.ends_with(&kept_older) && kept_older.starts_with("older\n"), "旧归档也是：{kept_older:?}");
        assert_eq!(records(&kept).last(), Some(&199));

        log.append_line("i3t: 新版本的第一行");
        assert_eq!(read(&path), "i3t: 新版本的第一行\n");
        assert_eq!(read(&archive), kept, "装不下时照常轮转，裁过的旧日志成了归档");
    }

    #[test]
    fn cutting_an_oversized_file_keeps_the_last_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t.log");
        let cut = |content: &str, limit: u64| {
            fs::write(&path, content).unwrap();
            shrink(&path, limit).unwrap();
            read(&path)
        };
        let lines = "0123456789abcde\n".repeat(100);
        assert_eq!(cut(&lines, LIMIT), "0123456789abcde\n".repeat(64), "正好裁在换行上，最后 1024 字节整行都留下");
        assert_eq!(cut(&lines, LIMIT - 1), "0123456789abcde\n".repeat(63), "裁在一行的中间，这一行不留");
        assert_eq!(cut(&lines, 1600), lines, "不超过上限的不动");
        assert_eq!(cut(&format!("{lines}partial"), 40), "0123456789abcde\n0123456789abcde\npartial", "末尾没写完的一行照留");
        assert_eq!(cut(&"x".repeat(3000), LIMIT), "", "最后一行比上限还长，什么都不留");
        assert_eq!(cut(&format!("{}\n", "x".repeat(3000)), LIMIT), "");
        assert_eq!(cut(&lines, 0), "");
    }

    #[test]
    fn cutting_moves_a_tail_larger_than_one_chunk_without_holding_it_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t.log");
        // 1 MiB 多的日志裁到 200 KiB：留下的部分跨好几个 64 KiB 的读写块。
        let content: String = (0..20_000).map(|record| format!("{} record={record}\n", "v".repeat(40))).collect();
        let limit = 200 * 1024;
        fs::write(&path, &content).unwrap();

        shrink(&path, limit).unwrap();

        let kept = read(&path);
        assert!(kept.len() as u64 <= limit && kept.len() as u64 > limit - 100, "留下 {} 字节", kept.len());
        assert!(content.ends_with(&kept) && kept.starts_with("vvvv"), "留下的是原来的末尾，从一行的开头起");
    }

    #[test]
    fn when_the_archive_cannot_be_written_the_log_is_emptied_instead_of_growing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t.log");
        // 归档的位置被一个目录占着，改名和抄写都一定失败。
        let blocker = dir.path().join("i3t.log.old");
        fs::create_dir(&blocker).unwrap();
        fs::write(blocker.join("keep"), "").unwrap();

        let log = LogFile::open(path.clone(), LIMIT);
        for record in 0..100 {
            log.append_line(&line(record));
            assert!(size(&path) <= LIMIT, "第 {record} 条之后日志文件 {} 字节", size(&path));
        }
        assert_eq!(records(&read(&path)).last(), Some(&99), "清空之后接着写");
        assert!(blocker.join("keep").exists(), "占着位置的目录没有动");

        // 别人中途清空了日志文件（`Clear-Content`）：接着从开头写，不在原来写到的位置前面留一段空洞。
        File::create(&path).unwrap();
        log.append_line("i3t: 被清空之后");
        assert_eq!(read(&path), "i3t: 被清空之后\n");
    }

    #[test]
    fn a_log_that_cannot_be_opened_is_tried_again_after_a_pause_not_on_every_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t.log");
        // 日志文件的位置被一个目录占着，打不开。
        fs::create_dir(&path).unwrap();
        let log = LogFile::open(path.clone(), LIMIT);
        fs::remove_dir(&path).unwrap();

        write(&log, "too soon\n");
        assert!(!path.exists(), "刚失败过，这一条不去碰文件系统");

        // 到了再试的时候。
        log.state.lock().unwrap().closed_until = Some(Instant::now());
        write(&log, "after the pause\n");
        write(&log, "and on\n");
        assert_eq!(read(&path), "after the pause\nand on\n");
    }

    #[test]
    fn the_last_error_is_written_even_right_after_the_log_could_not_be_opened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t.log");
        fs::create_dir(&path).unwrap();
        let log = LogFile::open(path.clone(), LIMIT);
        fs::remove_dir(&path).unwrap();

        log.append_line("i3t: 配置文件读不了");
        write(&log, "and on\n");
        assert_eq!(read(&path), "i3t: 配置文件读不了\nand on\n");
    }

    /// 这些测试靠文件权限造出"改不了、打不开"，特权用户不受权限管，测不了。
    #[cfg(unix)]
    mod without_permission {
        use std::os::unix::fs::PermissionsExt;

        use super::*;

        fn allow(path: &Path, mode: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }

        fn privileged(dir: &Path) -> bool {
            let probe = dir.join("probe");
            fs::write(&probe, "").unwrap();
            allow(&probe, 0o000);
            let readable = File::open(&probe).is_ok();
            fs::remove_file(&probe).unwrap();
            readable
        }

        #[test]
        fn when_renaming_fails_the_log_is_copied_to_the_archive_and_nothing_is_lost() {
            let dir = tempfile::tempdir().unwrap();
            if privileged(dir.path()) {
                return;
            }
            let path = dir.path().join("i3t.log");
            let archive = dir.path().join("i3t.log.old");
            let log = LogFile::open(path.clone(), LIMIT);
            log.append_line(&line(0));
            fs::write(&archive, "").unwrap();
            // 目录只读：两个文件都还能写，可是改不了名。Windows 上有人开着文件看的时候就是这样。
            allow(dir.path(), 0o555);

            for record in 1..100 {
                log.append_line(&line(record));
                assert!(size(&path) <= LIMIT && size(&archive) <= LIMIT, "第 {record} 条之后");
            }

            allow(dir.path(), 0o755);
            assert!(records(&read(&archive))[0] > 0, "归档换过不止一次");
            assert_nothing_lost(&archive, &path, 99);
        }

        #[test]
        fn an_oversized_log_that_cannot_be_cut_is_emptied_not_kept_as_the_archive() {
            let dir = tempfile::tempdir().unwrap();
            if privileged(dir.path()) {
                return;
            }
            let path = dir.path().join("i3t.log");
            fs::write(&path, "old\n".repeat(1000)).unwrap();
            // 只能写不能读：裁不了（要读出末尾），清空和追加都还行。
            allow(&path, 0o200);

            let log = LogFile::open(path.clone(), LIMIT);
            assert_eq!(size(&path), 0, "裁不了就清空");
            assert!(!dir.path().join("i3t.log.old").exists(), "比上限大的不留作归档");

            log.append_line("i3t: 接着写");
            allow(&path, 0o644);
            assert_eq!(read(&path), "i3t: 接着写\n");
        }

        #[test]
        fn an_oversized_archive_that_cannot_be_cut_yet_is_cut_later() {
            let dir = tempfile::tempdir().unwrap();
            if privileged(dir.path()) {
                return;
            }
            let path = dir.path().join("i3t.log");
            let archive = dir.path().join("i3t.log.old");
            fs::write(&path, "").unwrap();
            fs::write(&archive, "older\n".repeat(1000)).unwrap();
            // 归档打不开，目录只读所以也删不掉：像被别的程序占着。
            allow(&archive, 0o000);
            allow(dir.path(), 0o555);

            let log = LogFile::open(path.clone(), LIMIT);
            log.append_line("i3t: 日志照常写");
            assert_eq!(read(&path), "i3t: 日志照常写\n");
            assert!(size(&archive) > LIMIT);
            assert!(log.state.lock().unwrap().check_archive_at.is_some_and(|at| at > Instant::now()), "记着过一会儿再试");

            // 占着的程序走了，也到了再试的时候。
            allow(dir.path(), 0o755);
            allow(&archive, 0o644);
            log.state.lock().unwrap().check_archive_at = Some(Instant::now());
            log.append_line("i3t: 再写一行");
            assert_eq!(read(&archive), "older\n".repeat(170), "归档裁到了上限以内");
            assert!(log.state.lock().unwrap().check_archive_at.is_none(), "不用再看了");
        }
    }

    /// Windows 上别的程序开着日志看的时候：开的方式不许别人改名、删除，轮转得绕过去。
    #[cfg(windows)]
    mod while_someone_holds_a_file_open {
        use std::os::windows::fs::OpenOptionsExt;

        use super::*;

        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;

        /// 开着文件看，`share` 是允许别人同时做的事。没有 `FILE_SHARE_DELETE`，别人就改不了名、删不掉。
        fn watch(path: &Path, share: u32) -> File {
            OpenOptions::new().read(true).share_mode(share).open(path).unwrap()
        }

        /// 手里开着的那个文件现在的内容。
        fn seen(mut viewer: &File) -> String {
            let mut text = String::new();
            viewer.seek(SeekFrom::Start(0)).unwrap();
            viewer.read_to_string(&mut text).unwrap();
            text
        }

        #[test]
        fn the_log_being_watched_is_copied_to_the_archive_and_nothing_is_lost() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("i3t.log");
            let archive = dir.path().join("i3t.log.old");
            let log = LogFile::open(path.clone(), LIMIT);
            log.append_line(&line(0));
            // `Get-Content -Wait` 就是这样开的。
            let viewer = watch(&path, FILE_SHARE_READ | FILE_SHARE_WRITE);

            for record in 1..100 {
                log.append_line(&line(record));
                assert!(size(&path) <= LIMIT && size(&archive) <= LIMIT, "第 {record} 条之后");
            }

            assert_eq!(seen(&viewer), read(&path), "日志文件没有改名，是原地清空的：看的人手里还是它");
            assert!(records(&read(&archive))[0] > 0, "归档换过不止一次");
            assert_nothing_lost(&archive, &path, 99);
        }

        #[test]
        fn the_archive_being_watched_is_rewritten_in_place_and_nothing_is_lost() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("i3t.log");
            let archive = dir.path().join("i3t.log.old");
            let log = LogFile::open(path.clone(), LIMIT);
            for record in 0..20 {
                log.append_line(&line(record));
            }
            let viewer = watch(&archive, FILE_SHARE_READ | FILE_SHARE_WRITE);

            for record in 20..100 {
                log.append_line(&line(record));
                assert!(size(&path) <= LIMIT && size(&archive) <= LIMIT, "第 {record} 条之后");
            }

            assert_eq!(seen(&viewer), read(&archive), "归档没有被顶掉，是原地重写的：看的人手里还是它");
            assert_nothing_lost(&archive, &path, 99);
        }

        #[test]
        fn an_archive_that_cannot_be_written_stays_and_the_log_is_emptied() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("i3t.log");
            let archive = dir.path().join("i3t.log.old");
            let log = LogFile::open(path.clone(), LIMIT);
            for record in 0..20 {
                log.append_line(&line(record));
            }
            let before = read(&archive);
            // 开着归档，别人只许读。
            let _viewer = watch(&archive, FILE_SHARE_READ);

            for record in 20..100 {
                log.append_line(&line(record));
                assert!(size(&path) <= LIMIT, "第 {record} 条之后日志文件 {} 字节", size(&path));
            }

            assert_eq!(read(&archive), before, "归档动不了，原样留着");
            assert_eq!(records(&read(&path)).last(), Some(&99), "清空之后接着写");
        }

        #[test]
        fn nothing_is_written_through_a_link() {
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            let path = dir.path().join("i3t.log");
            let target = elsewhere.path().join("target");
            fs::write(&target, "").unwrap();
            match std::os::windows::fs::symlink_file(&target, &path) {
                Ok(()) => {}
                // 没有建符号链接的权限（不是管理员，也没开开发者模式）就测不了。CI 上有，在那里不许跳过。
                Err(err) if err.raw_os_error() == Some(1314) && std::env::var_os("CI").is_none() => return,
                Err(err) => panic!("建符号链接：{err}"),
            }

            let log = LogFile::open(path.clone(), LIMIT);
            log.append_line("i3t: 不该写到链接指向的地方");
            assert_eq!(read(&target), "", "日志文件的位置是链接：不写");

            // 归档的位置是链接：轮转顶掉的是链接自己，不是它指向的文件。
            fs::remove_file(&path).unwrap();
            std::os::windows::fs::symlink_file(&target, dir.path().join("i3t.log.old")).unwrap();
            let log = LogFile::open(path.clone(), LIMIT);
            for record in 0..100 {
                log.append_line(&line(record));
            }
            assert_eq!(read(&target), "");
            assert_eq!(records(&read(&path)).last(), Some(&99));
        }
    }
}
