//! 更新包下载到暂存文件：支持分块下载、断点续传与完整性校验。

use std::io::{self, SeekFrom};
use std::path::Path;
use std::time::Duration;

use i3t_model::update::{Artifact, Platform, UpdateStatus, Version};
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::digest::FileDigest;
use crate::error::UpdateError;
use crate::source::{ChunkRequest, PackageSource, SourceError};

/// 单次请求的块大小。控制链路单帧上限为 16 MB，且同一链路还承载其他消息，因此分块不宜过大；
/// 使用 256 KB 分块时，下载 20 MB 更新包约需 80 次往返。
const CHUNK_LEN: u32 = 256 * 1024;

/// 下载中断后的退避重试间隔：从 1 秒开始指数退避，上限 30 秒；成功接收到数据后重置为 1 秒。
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

/// 单次下载任务：将 `artifact` 下载到 `path`。
pub(crate) struct Download<'a, S> {
    pub source: &'a S,
    pub version: &'a Version,
    pub platform: &'a Platform,
    pub artifact: &'a Artifact,
    /// 暂存文件路径。文件中已存在的字节视为已下载，进程重启后将从该位置断点续传。
    pub path: &'a Path,
}

impl<S: PackageSource> Download<'_, S> {
    /// 完整下载更新包并校验其完整性。每下载完一个分块及开始校验时，均会调用 `report` 上报当前状态。
    ///
    /// 链路中断不视为失败：将持续重试直至恢复下载，调用方可在任意时刻丢弃该 future 以取消下载，下次会从暂存文件长度处续传。
    ///
    /// 若断点续传完成后的校验失败，会删除暂存文件并从头重新下载一次（此前保留的部分可能因异常断电损坏）。
    /// 若从头完整下载后的校验仍失败，则说明更新源提供的数据有误，直接返回错误。
    ///
    /// # Errors
    ///
    /// 当更新源明确无法提供更新包、完整下载的内容与发布清单不符，或暂存文件读写失败时返回错误。
    pub async fn run(&self, mut report: impl FnMut(UpdateStatus)) -> Result<(), UpdateError> {
        loop {
            let resumed_from = self.fetch(&mut report).await?;
            report(UpdateStatus::Verifying { version: self.version.clone() });
            let path = self.path.to_owned();
            let digest = tokio::task::spawn_blocking(move || FileDigest::of_file(&path))
                .await
                .expect("文件摘要计算任务异常终止")
                .map_err(self.io("读取暂存文件"))?;
            if digest.matches(self.artifact) {
                return Ok(());
            }
            fs::remove_file(self.path).await.map_err(self.io("删除暂存文件"))?;
            if resumed_from == 0 {
                tracing::warn!(version = %self.version, actual = %digest.sha256, expected = %self.artifact.sha256, "更新包校验失败：大小或 SHA-256 与发布清单不符");
                return Err(UpdateError::Corrupt {
                    expected_size: self.artifact.size,
                    expected: self.artifact.sha256,
                    actual_size: digest.size,
                    actual: digest.sha256,
                });
            }
            tracing::warn!(version = %self.version, resumed_from, "断点续传后的更新包与发布清单不符，已删除暂存文件并将重新下载");
        }
    }

    /// 将暂存文件下载补齐至发布清单声明的大小，并返回本次续传的起始偏移量。
    async fn fetch(&self, report: &mut impl FnMut(UpdateStatus)) -> Result<u64, UpdateError> {
        let size = self.artifact.size;
        let mut progress = |received| report(UpdateStatus::Downloading { version: self.version.clone(), received, total: size });
        let resumed_from = match fs::metadata(self.path).await {
            Ok(metadata) if metadata.len() <= size => metadata.len(),
            // 文件长度超出发布清单声明的大小，说明并非当前更新包的前缀，需从头下载。
            Ok(_) => 0,
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(self.io("查询暂存文件信息")(error)),
        };
        // 使用按偏移写入而非追加模式：上次下载被取消时可能仍有分块在后台落盘，按偏移覆盖可保证字节位置不错位。
        let mut file =
            OpenOptions::new().create(true).truncate(false).write(true).open(self.path).await.map_err(self.io("打开暂存文件"))?;
        file.set_len(resumed_from).await.map_err(self.io("截断暂存文件"))?;
        file.seek(SeekFrom::Start(resumed_from)).await.map_err(self.io("定位暂存文件"))?;
        if resumed_from > 0 {
            tracing::info!(version = %self.version, resumed_from, size, "检测到已有部分暂存文件，将从断点继续下载");
        }

        let mut received = resumed_from;
        progress(received);
        let mut retry_in = RETRY_FIRST;
        while received < size {
            let len = u32::try_from(size - received).map_or(CHUNK_LEN, |rest| rest.min(CHUNK_LEN));
            let request = ChunkRequest { version: self.version, platform: self.platform, offset: received, len };
            match self.source.fetch(request).await {
                Ok(chunk) => {
                    let got = u32::try_from(chunk.len()).ok().filter(|got| (1..=len).contains(got));
                    let Some(got) = got else {
                        return Err(UpdateError::Unavailable(format!(
                            "在偏移量 {received} 请求 {len} 字节，但更新源返回了 {} 字节",
                            chunk.len()
                        )));
                    };
                    file.write_all(&chunk).await.map_err(self.io("写入暂存文件"))?;
                    // 等待当前分块刷新到操作系统后再上报进度：tokio 的文件写入在后台线程执行，未刷新前上报的字节数可能超前于文件内容。
                    file.flush().await.map_err(self.io("写入暂存文件"))?;
                    received += u64::from(got);
                    progress(received);
                    retry_in = RETRY_FIRST;
                }
                Err(SourceError::Interrupted(reason)) => {
                    tracing::info!(version = %self.version, received, size, %reason, ?retry_in, "更新包下载中断，将在等待后从断点继续下载");
                    tokio::time::sleep(retry_in).await;
                    retry_in = (retry_in * 2).min(RETRY_MAX);
                }
                Err(SourceError::Unavailable(reason)) => {
                    tracing::warn!(version = %self.version, platform = %self.platform, %reason, "更新源无法提供该更新包，已停止下载");
                    return Err(UpdateError::Unavailable(reason));
                }
            }
        }
        file.sync_all().await.map_err(self.io("同步暂存文件到磁盘"))?;
        Ok(resumed_from)
    }

    fn io(&self, action: &'static str) -> impl FnOnce(io::Error) -> UpdateError {
        UpdateError::io(action, self.path)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use i3t_model::update::Sha256;
    use ring::digest;
    use tokio::sync::Notify;

    use super::*;

    const CHUNK: u64 = CHUNK_LEN as u64;

    /// 一个按脚本行事的来源：每次被要一块，先看脚本里下一步让它怎么做；脚本走完之后老老实实地给。
    struct ScriptedSource {
        package: Vec<u8>,
        script: Mutex<VecDeque<Step>>,
        /// 每次被要的位置，包括没有给出东西的那些。
        offsets: Mutex<Vec<u64>>,
        stalled: Notify,
    }

    #[derive(Debug, Clone, Copy)]
    enum Step {
        Serve,
        /// 给的比要的少。
        ServeShort(usize),
        Interrupt,
        Refuse,
        ServeNothing,
        ServeTooMuch,
        /// 永远不回答，并且让测试知道已经停在这里了。
        Stall,
    }

    impl ScriptedSource {
        fn new(package: &[u8], script: impl IntoIterator<Item = Step>) -> Self {
            Self {
                package: package.to_owned(),
                script: Mutex::new(script.into_iter().collect()),
                offsets: Mutex::default(),
                stalled: Notify::new(),
            }
        }

        fn offsets(&self) -> Vec<u64> {
            self.offsets.lock().unwrap().clone()
        }
    }

    impl PackageSource for ScriptedSource {
        async fn fetch(&self, request: ChunkRequest<'_>) -> Result<Vec<u8>, SourceError> {
            self.offsets.lock().unwrap().push(request.offset);
            let step = self.script.lock().unwrap().pop_front().unwrap_or(Step::Serve);
            let start = usize::try_from(request.offset).unwrap();
            let want = usize::try_from(request.len).unwrap();
            let serve = |len: usize| Ok(self.package[start..self.package.len().min(start + len)].to_vec());
            match step {
                Step::Serve => serve(want),
                Step::ServeShort(len) => serve(len.min(want)),
                Step::Interrupt => Err(SourceError::Interrupted("链路断了".to_owned())),
                Step::Refuse => Err(SourceError::Unavailable("没有这个版本".to_owned())),
                Step::ServeNothing => Ok(Vec::new()),
                Step::ServeTooMuch => Ok(vec![0; want + 1]),
                Step::Stall => {
                    self.stalled.notify_one();
                    std::future::pending().await
                }
            }
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
        package: Vec<u8>,
        artifact: Artifact,
        version: Version,
        platform: Platform,
    }

    impl Fixture {
        /// 一个两块半大的包，各处的内容不重复，这样写错了位置能被哈希查出来。
        fn new() -> Self {
            let len = usize::try_from(CHUNK).unwrap() * 5 / 2;
            let package: Vec<u8> = (0..len).map(|index| (index * 31 + index / 251).to_le_bytes()[0]).collect();
            Self {
                dir: tempfile::tempdir().unwrap(),
                artifact: artifact_of(&package),
                package,
                version: Version::new(0, 2, 0),
                platform: Platform::current(),
            }
        }

        fn path(&self) -> PathBuf {
            self.dir.path().join("staged")
        }

        /// 跑一次下载，返回结果和一路报出来的"已取到多少字节"。
        async fn download(&self, source: &ScriptedSource) -> (Result<(), UpdateError>, Vec<u64>) {
            let path = self.path();
            let download = Download { source, version: &self.version, platform: &self.platform, artifact: &self.artifact, path: &path };
            let mut statuses = Vec::new();
            let result = download.run(|status| statuses.push(status)).await;
            if result.is_ok() {
                assert_eq!(statuses.last(), Some(&UpdateStatus::Verifying { version: self.version.clone() }));
            }
            let received = statuses
                .into_iter()
                .filter_map(|status| {
                    let UpdateStatus::Downloading { received, total, .. } = status else { return None };
                    assert_eq!(total, self.artifact.size);
                    Some(received)
                })
                .collect();
            (result, received)
        }

        fn on_disk(&self) -> Vec<u8> {
            std::fs::read(self.path()).unwrap()
        }
    }

    fn artifact_of(package: &[u8]) -> Artifact {
        let sha256: [u8; 32] = digest::digest(&digest::SHA256, package).as_ref().try_into().unwrap();
        Artifact { file: "i3t".to_owned(), size: u64::try_from(package.len()).unwrap(), sha256: Sha256::from_bytes(sha256) }
    }

    #[tokio::test]
    async fn package_is_fetched_in_chunks_and_progress_is_reported() {
        let fixture = Fixture::new();
        let source = ScriptedSource::new(&fixture.package, []);
        let (result, received) = fixture.download(&source).await;
        result.unwrap();
        assert_eq!(fixture.on_disk(), fixture.package);
        assert_eq!(source.offsets(), [0, CHUNK, 2 * CHUNK]);
        assert_eq!(received, [0, CHUNK, 2 * CHUNK, fixture.artifact.size]);
    }

    #[tokio::test]
    async fn short_chunks_are_accepted_and_the_rest_is_asked_for() {
        let fixture = Fixture::new();
        let source = ScriptedSource::new(&fixture.package, [Step::ServeShort(1000), Step::ServeShort(1)]);
        fixture.download(&source).await.0.unwrap();
        assert_eq!(fixture.on_disk(), fixture.package);
        assert_eq!(source.offsets(), [0, 1000, 1001, 1001 + CHUNK, 1001 + 2 * CHUNK]);
    }

    #[tokio::test(start_paused = true)]
    async fn interruptions_are_retried_from_the_same_offset_and_are_not_a_failure() {
        let fixture = Fixture::new();
        let script = [Step::Serve, Step::Interrupt, Step::Interrupt, Step::Interrupt, Step::Serve, Step::Interrupt, Step::Serve];
        let source = ScriptedSource::new(&fixture.package, script);
        let started = tokio::time::Instant::now();
        let (result, received) = fixture.download(&source).await;
        result.unwrap();
        assert_eq!(fixture.on_disk(), fixture.package);
        assert_eq!(source.offsets(), [0, CHUNK, CHUNK, CHUNK, CHUNK, 2 * CHUNK, 2 * CHUNK]);
        assert!(received.is_sorted(), "进度不应该倒退：{received:?}");
        // 连着三次被打断，等 1 + 2 + 4 秒；取到一块之后再被打断，又从 1 秒等起。
        assert_eq!(started.elapsed(), Duration::from_secs(1 + 2 + 4 + 1));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_delay_stops_growing_at_the_cap() {
        let fixture = Fixture::new();
        let source = ScriptedSource::new(&fixture.package, [Step::Interrupt; 8]);
        let started = tokio::time::Instant::now();
        fixture.download(&source).await.0.unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(1 + 2 + 4 + 8 + 16 + 30 + 30 + 30));
    }

    #[tokio::test]
    async fn download_resumes_after_a_restart_from_what_is_on_disk() {
        let fixture = Fixture::new();
        // 第一个进程取了一块多一点，然后没了：来源在第三次请求上不再回答，这时把下载丢弃。
        let first = ScriptedSource::new(&fixture.package, [Step::Serve, Step::ServeShort(100), Step::Stall]);
        tokio::select! {
            (result, _) = fixture.download(&first) => panic!("下载应该停在第三次请求上：{result:?}"),
            () = first.stalled.notified() => {}
        }
        assert_eq!(first.offsets(), [0, CHUNK, CHUNK + 100]);
        assert_eq!(fixture.on_disk(), fixture.package[..usize::try_from(CHUNK).unwrap() + 100]);

        // 第二个进程什么都不记得，只有暂存文件。
        let second = ScriptedSource::new(&fixture.package, []);
        let (result, received) = fixture.download(&second).await;
        result.unwrap();
        assert_eq!(fixture.on_disk(), fixture.package);
        assert_eq!(second.offsets(), [CHUNK + 100, 2 * CHUNK + 100], "应该从暂存文件的长度接着取，而不是从头");
        assert_eq!(received.first(), Some(&(CHUNK + 100)));
    }

    #[tokio::test]
    async fn a_complete_file_on_disk_is_verified_without_asking_the_source() {
        let fixture = Fixture::new();
        std::fs::write(fixture.path(), &fixture.package).unwrap();
        let source = ScriptedSource::new(&fixture.package, []);
        fixture.download(&source).await.0.unwrap();
        assert_eq!(source.offsets(), [0u64; 0]);
    }

    #[tokio::test]
    async fn a_damaged_partial_file_is_thrown_away_and_fetched_again() {
        let fixture = Fixture::new();
        let mut damaged = fixture.package[..300_000].to_vec();
        damaged[5] ^= 1;
        std::fs::write(fixture.path(), &damaged).unwrap();
        let source = ScriptedSource::new(&fixture.package, []);
        fixture.download(&source).await.0.unwrap();
        assert_eq!(fixture.on_disk(), fixture.package);
        assert_eq!(source.offsets(), [300_000, 300_000 + CHUNK, 0, CHUNK, 2 * CHUNK]);
    }

    #[tokio::test]
    async fn a_file_longer_than_the_package_is_not_resumed() {
        let fixture = Fixture::new();
        std::fs::write(fixture.path(), vec![0; fixture.package.len() + 1]).unwrap();
        let source = ScriptedSource::new(&fixture.package, []);
        fixture.download(&source).await.0.unwrap();
        assert_eq!(fixture.on_disk(), fixture.package);
        assert_eq!(source.offsets(), [0, CHUNK, 2 * CHUNK]);
    }

    #[tokio::test]
    async fn wrong_content_is_a_hash_mismatch_and_leaves_nothing_behind() {
        let fixture = Fixture::new();
        let mut wrong = fixture.package.clone();
        wrong[123_456] ^= 0x80;
        let source = ScriptedSource::new(&wrong, []);
        let (result, _) = fixture.download(&source).await;
        let Err(UpdateError::Corrupt { expected, actual, expected_size, actual_size }) = result else {
            panic!("应该报内容对不上：{result:?}")
        };
        assert_eq!((expected, expected_size, actual_size), (fixture.artifact.sha256, fixture.artifact.size, fixture.artifact.size));
        assert_eq!(actual, artifact_of(&wrong).sha256);
        assert!(!fixture.path().exists(), "对不上的文件不应该留着");
        assert_eq!(source.offsets(), [0, CHUNK, 2 * CHUNK], "从头取的对不上就不再重取");
    }

    #[tokio::test]
    async fn a_package_shorter_than_the_manifest_says_cannot_be_completed() {
        let mut fixture = Fixture::new();
        let source = ScriptedSource::new(&fixture.package, []);
        fixture.artifact.size += 10;
        let (result, _) = fixture.download(&source).await;
        // 来源在文件末尾给不出东西，这违反了"不能给 0 字节"的约定。
        assert!(matches!(result, Err(UpdateError::Unavailable(_))), "{result:?}");
    }

    #[tokio::test]
    async fn a_package_longer_than_the_manifest_says_fails_the_hash() {
        let mut fixture = Fixture::new();
        let source = ScriptedSource::new(&fixture.package, []);
        fixture.artifact.size -= 10;
        let (result, _) = fixture.download(&source).await;
        let Err(UpdateError::Corrupt { expected_size, actual_size, .. }) = result else { panic!("应该报内容对不上：{result:?}") };
        assert_eq!(expected_size, actual_size, "只取清单上写的那么多，所以大小一样，是哈希对不上");
        assert!(!fixture.path().exists());
    }

    #[tokio::test]
    async fn a_file_with_the_right_hash_but_the_wrong_size_in_the_manifest_is_rejected() {
        let mut fixture = Fixture::new();
        std::fs::write(fixture.path(), &fixture.package).unwrap();
        // 清单上的哈希是对的，大小写多了：文件补不到那么长。
        fixture.artifact.size += 1;
        let source = ScriptedSource::new(&fixture.package, []);
        let (result, _) = fixture.download(&source).await;
        assert!(matches!(result, Err(UpdateError::Unavailable(_))), "{result:?}");
    }

    #[tokio::test]
    async fn a_refusal_ends_the_download_but_keeps_what_was_fetched() {
        let fixture = Fixture::new();
        let source = ScriptedSource::new(&fixture.package, [Step::Serve, Step::Refuse]);
        let (result, _) = fixture.download(&source).await;
        assert!(matches!(result, Err(UpdateError::Unavailable(reason)) if reason == "没有这个版本"));
        assert_eq!(fixture.on_disk().len(), usize::try_from(CHUNK).unwrap());
    }

    #[tokio::test]
    async fn a_source_that_breaks_the_contract_is_not_asked_again() {
        for step in [Step::ServeNothing, Step::ServeTooMuch] {
            let fixture = Fixture::new();
            let source = ScriptedSource::new(&fixture.package, [step]);
            let (result, _) = fixture.download(&source).await;
            assert!(matches!(result, Err(UpdateError::Unavailable(_))), "{step:?}：{result:?}");
            assert_eq!(source.offsets(), [0]);
        }
    }
}
