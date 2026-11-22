//! 在临时目录里把一次更新从头走到尾。"程序"是小的 shell 脚本，"重启"是用新的版本号再建一个 [`Updater`]。

use std::collections::BTreeMap;

use i3t_crypto::NodeKey;
use i3t_model::update::{ManifestSignature, Sha256};
use ring::digest;

use super::*;
use crate::error::ManifestError;
use crate::trust::sign_manifest;

const OLD: &str = "0.1.0";
const NEW: &str = "0.2.0";

fn version(text: &str) -> Version {
    text.parse().unwrap()
}

/// 一台装着节点的机器：一个放程序的目录，一个状态目录，还有它认的那把发布公钥对应的私钥。
struct Node {
    dir: tempfile::TempDir,
    release_key: NodeKey,
}

impl Node {
    fn new() -> Self {
        let node = Self { dir: tempfile::tempdir().unwrap(), release_key: NodeKey::generate().unwrap() };
        fs::create_dir(node.dir.path().join("bin")).unwrap();
        fs::write(node.program(), fake_program(OLD, "exit 0")).unwrap();
        node
    }

    fn program(&self) -> PathBuf {
        self.dir.path().join("bin").join("i3t")
    }

    fn config(&self, running: &str) -> UpdaterConfig {
        UpdaterConfig {
            program: self.program(),
            state_dir: self.dir.path().join("state"),
            running: version(running),
            self_check_args: vec!["--state-dir".into(), self.dir.path().join("state").into(), "self-check".into()],
            blocker: None,
        }
    }

    /// 一个正在运行 `running` 版的进程。
    fn process(&self, running: &str) -> Updater {
        Updater::assemble(self.config(running), TrustedKeys::from(self.release_key.public()), Swap::NATIVE)
    }

    /// 一次发布的清单：只有本平台的包，用这台机器认的钥匙签。
    fn manifest(&self, version: &str, package: &str) -> SignedManifest {
        signed_manifest(&self.release_key, version, &Platform::current(), package.as_bytes())
    }
}

/// 假的节点程序。`self_check` 是它被运行时执行的 shell 语句。
fn fake_program(version: &str, self_check: &str) -> String {
    format!("#!/bin/sh\n# 假的节点程序，版本 {version}\n{self_check}\n")
}

/// 一份签好的清单，里面只有 `platform` 的包，内容是 `package`。
fn signed_manifest(key: &NodeKey, version: &str, platform: &Platform, package: &[u8]) -> SignedManifest {
    let sha256: [u8; 32] = digest::digest(&digest::SHA256, package).as_ref().try_into().unwrap();
    let artifact =
        Artifact { file: platform.program_file("i3t"), size: u64::try_from(package.len()).unwrap(), sha256: Sha256::from_bytes(sha256) };
    let manifest = Manifest {
        version: version.parse().unwrap(),
        min_controller: Version::new(0, 1, 0),
        published: 1_763_200_000,
        artifacts: BTreeMap::from([(platform.to_string(), artifact)]),
        security_floor: None,
        files: BTreeMap::new(),
    };
    sign_manifest(key, serde_json::to_string_pretty(&manifest).unwrap())
}

fn refusal(result: Result<Offer, UpdateError>) -> Refusal {
    match result {
        Err(UpdateError::Refused(refusal)) => refusal,
        other => panic!("应该被拒绝：{other:?}"),
    }
}

#[test]
fn a_newer_signed_manifest_with_a_package_for_this_platform_is_accepted() {
    let node = Node::new();
    let manifest = node.manifest(NEW, "新程序");
    let offer = node.process(OLD).check(&manifest, UpdateTiming::Idle).unwrap();
    assert_eq!(offer.version, version(NEW));
    assert_eq!(offer.artifact.size, 9);
    assert_eq!(offer.artifact.file, Platform::current().program_file("i3t"));
}

#[test]
fn a_security_floor_in_the_manifest_changes_nothing_on_the_node() {
    let node = Node::new();
    let manifest = node.manifest(NEW, "新程序");
    let mut value: serde_json::Value = serde_json::from_str(&manifest.manifest).unwrap();
    value["security_floor"] = serde_json::json!(NEW);
    let with_floor = sign_manifest(&node.release_key, serde_json::to_string_pretty(&value).unwrap());
    let offer = node.process(OLD).check(&with_floor, UpdateTiming::Idle).unwrap();
    assert_eq!((offer.version, offer.artifact), (version(NEW), node.process(OLD).check(&manifest, UpdateTiming::Idle).unwrap().artifact));
}

#[test]
fn a_manifest_signed_with_another_key_is_refused() {
    let node = Node::new();
    let stranger = NodeKey::generate().unwrap();
    let manifest = signed_manifest(&stranger, NEW, &Platform::current(), b"x");
    let updater = node.process(OLD);
    assert!(matches!(refusal(updater.check(&manifest, UpdateTiming::Now)), Refusal::Manifest(ManifestError::BadSignature)));
    // 连清单都没有验过，所以状态里说不出是哪个版本。
    let status = updater.status().borrow().clone();
    let UpdateStatus::Failed { version: None, kind: FailureKind::NotInstalled, reason, cause } = status else { panic!("{status:?}") };
    assert_eq!(reason, "不装这份清单：清单的签名不是任何一把受信任的发布公钥签的");
    assert_eq!(cause, Some(UpdateCause::BadSignature));
}

#[test]
fn a_manifest_altered_after_signing_is_refused() {
    let node = Node::new();
    let mut altered = node.manifest(NEW, "x");
    // 改的是合法的 JSON 里的一个值：要是先解析再验签，这种改动才是危险的。
    altered.manifest = altered.manifest.replace("\"0.2.0\"", "\"0.2.1\"");
    assert!(matches!(refusal(node.process(OLD).check(&altered, UpdateTiming::Now)), Refusal::Manifest(ManifestError::BadSignature)));
    // 只多一个空格也不行：签的是原文的每一个字节。
    let mut padded = node.manifest(NEW, "x");
    padded.manifest.push(' ');
    assert!(matches!(refusal(node.process(OLD).check(&padded, UpdateTiming::Now)), Refusal::Manifest(ManifestError::BadSignature)));
}

#[test]
fn a_signature_made_for_another_purpose_is_refused() {
    let node = Node::new();
    let mut manifest = node.manifest(NEW, "x");
    let elsewhere = node.release_key.sign("relay-session", manifest.manifest.as_bytes());
    manifest.signature = ManifestSignature::from_bytes(*elsewhere.as_bytes());
    assert!(matches!(refusal(node.process(OLD).check(&manifest, UpdateTiming::Now)), Refusal::Manifest(ManifestError::BadSignature)));
}

#[test]
fn a_correctly_signed_text_that_is_not_a_manifest_is_refused() {
    let node = Node::new();
    let signed = sign_manifest(&node.release_key, "{ \"version\": \"0.2.0\" }".to_owned());
    assert!(matches!(refusal(node.process(OLD).check(&signed, UpdateTiming::Now)), Refusal::Manifest(ManifestError::Malformed(_))));
}

#[test]
fn the_same_or_an_older_version_is_refused_without_touching_the_status() {
    let node = Node::new();
    let updater = node.process("0.2.0");
    for offered in ["0.2.0", "0.1.9", "0.2.0-rc.1", "0.0.1"] {
        let manifest = node.manifest(offered, "x");
        // 管理员强制也不行：不降级，不重装。
        for timing in [UpdateTiming::Idle, UpdateTiming::Now, UpdateTiming::AfterDrain] {
            let refusal = refusal(updater.check(&manifest, timing));
            assert!(matches!(refusal, Refusal::NotNewer { .. }), "{offered}：{refusal:?}");
        }
    }
    assert_eq!(*updater.status().borrow(), UpdateStatus::Idle, "节点已经够新了，这不是一次失败");
}

#[test]
fn a_prerelease_is_only_installed_over_a_prerelease() {
    let node = Node::new();
    let candidate = node.manifest("0.2.0-rc.2", "x");
    let on_stable = node.process("0.1.0");
    assert!(matches!(refusal(on_stable.check(&candidate, UpdateTiming::Idle)), Refusal::Prerelease { .. }));
    assert!(matches!(refusal(on_stable.check(&candidate, UpdateTiming::Now)), Refusal::Prerelease { .. }), "强制也不行");

    let on_prerelease = node.process("0.2.0-rc.1");
    assert_eq!(on_prerelease.check(&candidate, UpdateTiming::Idle).unwrap().version, version("0.2.0-rc.2"));
    // 预发布版之后的正式版，谁都可以装。
    let stable = node.manifest("0.2.0", "x");
    assert_eq!(on_prerelease.check(&stable, UpdateTiming::Idle).unwrap().version, version("0.2.0"));
    assert_eq!(on_stable.check(&stable, UpdateTiming::Idle).unwrap().version, version("0.2.0"));
}

#[test]
fn a_release_without_a_package_for_this_platform_is_refused() {
    let node = Node::new();
    let elsewhere: Platform = "plan9-mips".parse().unwrap();
    let manifest = signed_manifest(&node.release_key, NEW, &elsewhere, b"x");
    let updater = node.process(OLD);
    let refusal = refusal(updater.check(&manifest, UpdateTiming::Idle));
    assert!(
        matches!(&refusal, Refusal::NoArtifact { version: offered, platform } if *offered == version(NEW) && *platform == Platform::current())
    );
    let status = updater.status().borrow().clone();
    assert!(matches!(status, UpdateStatus::Failed { version: Some(_), kind: FailureKind::NotInstalled, .. }), "{status:?}");
}

#[test]
fn a_node_that_cannot_update_itself_refuses_every_newer_manifest() {
    let node = Node::new();
    let config = UpdaterConfig { blocker: Some(SelfUpdateBlocker::Container), ..node.config(OLD) };
    let updater = Updater::assemble(config, TrustedKeys::from(node.release_key.public()), Swap::NATIVE);
    let manifest = node.manifest(NEW, "x");
    assert!(matches!(refusal(updater.check(&manifest, UpdateTiming::Now)), Refusal::CannotSelfUpdate(SelfUpdateBlocker::Container)));
}

#[test]
fn a_production_updater_only_trusts_the_compiled_in_keys() {
    let node = Node::new();
    let manifest = node.manifest(NEW, "x");
    let updater = Updater::new(node.config(OLD));
    assert!(matches!(refusal(updater.check(&manifest, UpdateTiming::Now)), Refusal::Manifest(ManifestError::BadSignature)));
}

#[test]
fn startup_and_confirm_do_nothing_on_a_node_that_never_updated() {
    let node = Node::new();
    let updater = node.process(OLD);
    assert_eq!(updater.startup().unwrap(), Startup::Clean);
    assert_eq!(updater.confirm().unwrap(), None);
    assert_eq!(updater.failures().unwrap(), []);
    assert_eq!(*updater.status().borrow(), UpdateStatus::Idle);
    assert_eq!(fs::read_to_string(node.program()).unwrap(), fake_program(OLD, "exit 0"));
}

/// 节点会把更新放到后台任务里跑，所以这个对象和它的每个 future 都要能在线程之间移动。
#[test]
fn updater_and_its_futures_can_be_moved_to_another_thread() {
    struct NoSource;

    impl PackageSource for NoSource {
        async fn fetch(&self, _request: crate::source::ChunkRequest<'_>) -> Result<Vec<u8>, crate::source::SourceError> {
            Err(crate::source::SourceError::Unavailable("测试里没有包".to_owned()))
        }
    }

    fn assert_send(_: &impl Send) {}
    fn assert_sync(_: &impl Sync) {}

    let node = Node::new();
    let updater = node.process(OLD);
    let manifest = node.manifest(NEW, "x");
    let (_flows_tx, mut flows) = watch::channel(0);
    assert_send(&updater);
    assert_sync(&updater);
    assert_send(&updater.prepare(&manifest, UpdateTiming::Idle, &NoSource));
    assert_send(&updater.update(&manifest, UpdateTiming::Idle, &NoSource, &mut flows));
    assert_send(&updater.enforce_confirmation_deadline());
}

/// 要真的运行"程序"的测试。脚本只在 Unix 上能直接运行。
#[cfg(unix)]
mod flow {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Mutex as StdMutex;

    use tokio::sync::Notify;

    use super::*;
    use crate::source::{ChunkRequest, SourceError};

    /// 自检通过：核对一下收到的参数和版本号，证明旧程序是按约定运行它的。
    const PASSES: &str = r#"[ "$1" = --state-dir ] && [ "$3" = self-check ] || { echo "参数不对：$*" >&2; exit 64; }
[ -n "$I3T_SELF_CHECK_VERSION" ] || { echo "没有收到版本号" >&2; exit 65; }
exit 0"#;

    const FAILS: &str = "echo 读不了 config.toml >&2\nexit 3";

    /// 一次发布：签好的清单，和能给出包的来源。
    struct Release {
        signed: SignedManifest,
        source: MemorySource,
    }

    /// 把包放在内存里的来源，记下每次被要的位置。
    struct MemorySource {
        package: Vec<u8>,
        offsets: StdMutex<Vec<u64>>,
    }

    impl MemorySource {
        fn new(package: &[u8]) -> Self {
            Self { package: package.to_owned(), offsets: StdMutex::default() }
        }

        fn offsets(&self) -> Vec<u64> {
            self.offsets.lock().unwrap().clone()
        }
    }

    impl PackageSource for MemorySource {
        async fn fetch(&self, request: ChunkRequest<'_>) -> Result<Vec<u8>, SourceError> {
            self.offsets.lock().unwrap().push(request.offset);
            let start = usize::try_from(request.offset).unwrap();
            let end = self.package.len().min(start + usize::try_from(request.len).unwrap());
            Ok(self.package[start..end].to_vec())
        }
    }

    impl Node {
        fn release(&self, version: &str, program: &str) -> Release {
            Release { signed: self.manifest(version, program), source: MemorySource::new(program.as_bytes()) }
        }

        /// 程序文件要能运行；测试里的"安装"就是把权限设好。
        fn installed() -> Self {
            let node = Self::new();
            fs::set_permissions(node.program(), fs::Permissions::from_mode(0o755)).unwrap();
            node
        }

        fn process_swapping(&self, running: &str, swap: Swap) -> Updater {
            Updater::assemble(self.config(running), TrustedKeys::from(self.release_key.public()), swap)
        }

        fn running_program(&self) -> String {
            fs::read_to_string(self.program()).unwrap()
        }

        fn bin(&self) -> Vec<String> {
            names_in(&self.dir.path().join("bin"))
        }

        fn update_dir(&self) -> Vec<String> {
            names_in(&self.dir.path().join("state").join("update"))
        }

        fn state_file(&self) -> StateFile {
            StateFile::new(&self.dir.path().join("state").join("update"))
        }

        /// 把新版本装上去（旧进程做完三步），返回这次发布。之后"重启"就是 `process(NEW)`。
        async fn install(&self, swap: Swap) -> Release {
            let release = self.release(NEW, &fake_program(NEW, PASSES));
            let old = self.process_swapping(OLD, swap);
            let (_flows_tx, mut flows) = watch::channel(0);
            assert_restart(old.update(&release.signed, UpdateTiming::Idle, &release.source, &mut flows).await, NEW);
            release
        }
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        names
    }

    /// 状态的名字，用来核对先后顺序。
    fn stage(status: &UpdateStatus) -> &'static str {
        match status {
            UpdateStatus::Idle => "idle",
            UpdateStatus::Downloading { .. } => "downloading",
            UpdateStatus::Verifying { .. } => "verifying",
            UpdateStatus::SelfCheck { .. } => "self_check",
            UpdateStatus::WaitingForIdle { .. } => "waiting_for_idle",
            UpdateStatus::Draining { .. } => "draining",
            UpdateStatus::Installing { .. } => "installing",
            UpdateStatus::Restarting { .. } => "restarting",
            UpdateStatus::Confirmed { .. } => "confirmed",
            UpdateStatus::Failed { .. } => "failed",
            UpdateStatus::Unknown => "unknown",
        }
    }

    /// 在后台记下状态依次变成了什么（相邻重复的只记一次）。
    ///
    /// 状态走的是 `watch`，只保证看得到最新的值：两次变化挨得太近时，中间那个可能看不到。
    /// 所以这里记下来的是实际顺序的一个子序列，用 [`assert_stages`] 核对。每一步报的状态本身在各自的模块里逐个核对过。
    fn record_stages(updater: &Updater) -> tokio::task::JoinHandle<Vec<&'static str>> {
        let mut status = updater.status();
        let mut stages = vec![stage(&status.borrow_and_update())];
        tokio::spawn(async move {
            while status.changed().await.is_ok() {
                let now = stage(&status.borrow_and_update());
                if stages.last() != Some(&now) {
                    stages.push(now);
                }
            }
            stages
        })
    }

    /// 看到的状态没有乱序、没有多出来的，头和尾都对，而且看到了自检（那一步要等一个进程，一定看得到）。
    fn assert_stages(seen: &[&str], expected: &[&str]) {
        let mut rest = expected.iter();
        assert!(
            seen.iter().all(|stage| rest.any(|expected| expected == stage)),
            "状态的顺序不对：{seen:?}，应该是 {expected:?} 里按顺序的一部分"
        );
        assert_eq!((seen.first(), seen.last()), (expected.first(), expected.last()), "{seen:?}");
        assert!(seen.contains(&"self_check"), "{seen:?}");
    }

    /// 更新做完了，并且要求重启到 `expected` 版。
    fn assert_restart(result: Result<RestartRequired, UpdateError>, expected: &str) {
        assert_eq!(result.unwrap(), RestartRequired { version: version(expected) });
    }

    #[tokio::test]
    async fn update_replaces_the_program_and_confirmation_removes_the_backup() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, PASSES));
        let old = node.process(OLD);
        assert_eq!(old.startup().unwrap(), Startup::Clean);
        let stages = record_stages(&old);
        let (_flows_tx, mut flows) = watch::channel(0);

        assert_restart(old.update(&release.signed, UpdateTiming::Idle, &release.source, &mut flows).await, NEW);
        assert_eq!(*old.status().borrow(), UpdateStatus::Restarting { version: version(NEW) });
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));
        assert_eq!(node.bin(), ["i3t", "i3t.old"]);
        assert_eq!(fs::read_to_string(node.dir.path().join("bin/i3t.old")).unwrap(), fake_program(OLD, "exit 0"));
        assert_eq!(node.update_dir(), ["state.json"], "取下来的包换上去之后就不用留了");
        assert_eq!(release.source.offsets(), [0]);
        drop(old);
        assert_stages(&stages.await.unwrap(), &["idle", "downloading", "verifying", "self_check", "installing", "restarting"]);

        // 进程重启，跑起来的是新程序。
        let new = node.process(NEW);
        assert_eq!(new.startup().unwrap(), Startup::AwaitingConfirmation { version: version(NEW) });
        assert_eq!(node.bin(), ["i3t", "i3t.old"], "确认之前备份要留着");
        assert_eq!(new.confirm().unwrap(), Some(version(NEW)));
        assert_eq!(*new.status().borrow(), UpdateStatus::Confirmed { version: version(NEW) });
        assert_eq!(node.bin(), ["i3t"]);
        assert_eq!(new.confirm().unwrap(), None, "确认过了再调用什么都不做");

        // 以后再启动就和没更新过一样。
        assert_eq!(node.process(NEW).startup().unwrap(), Startup::Clean);
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));
    }

    #[tokio::test]
    async fn failed_self_check_leaves_everything_untouched() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, FAILS));
        let old = node.process(OLD);
        let stages = record_stages(&old);
        let (_flows_tx, mut flows) = watch::channel(0);

        let error = old.update(&release.signed, UpdateTiming::Now, &release.source, &mut flows).await.unwrap_err();
        assert!(
            matches!(&error, UpdateError::SelfCheck { version: failed, reason, .. } if *failed == version(NEW) && reason == "退出码 3：读不了 config.toml"),
            "{error:?}"
        );
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
        assert_eq!(node.bin(), ["i3t"], "没有备份，放过去的新程序也收走了");
        assert_eq!(node.update_dir(), ["state.json"]);
        assert_eq!(
            *old.status().borrow(),
            UpdateStatus::Failed {
                version: Some(version(NEW)),
                kind: FailureKind::VersionRejected,
                reason: "版本 0.2.0 的自检没有通过：退出码 3：读不了 config.toml".to_owned(),
                cause: Some(UpdateCause::SelfCheck { exit_code: Some(3), output: "读不了 config.toml".to_owned() }),
            }
        );
        // 没有换程序，所以启动时没有东西要确认，也没有东西要换回。
        assert_eq!(node.process(OLD).startup().unwrap(), Startup::Clean);
        drop(old);
        assert_stages(&stages.await.unwrap(), &["idle", "downloading", "verifying", "self_check", "failed"]);
    }

    #[tokio::test]
    async fn an_update_abandoned_during_the_self_check_takes_the_unchecked_program_away() {
        let node = Node::installed();
        // 自检迟迟不结束：这期间 controller 撤回了更新，调用方丢弃这个 future。
        let release = node.release(NEW, &fake_program(NEW, "sleep 30"));
        let old = node.process(OLD);
        let (_flows_tx, mut flows) = watch::channel(0);
        {
            let update = old.update(&release.signed, UpdateTiming::Now, &release.source, &mut flows);
            tokio::pin!(update);
            let mut status = old.status();
            let checking = async {
                while !matches!(*status.borrow_and_update(), UpdateStatus::SelfCheck { .. }) || node.bin() != ["i3t", "i3t.new"] {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            };
            tokio::select! {
                result = &mut update => panic!("自检还没有结束，更新不该有结果：{result:?}"),
                () = checking => {}
            }
        }
        assert_eq!(node.bin(), ["i3t"], "没验过的新程序不留在程序旁边");
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
        // 取下来的包还在：再来一次不用重新取。
        assert!(node.update_dir().iter().any(|name| name.starts_with("staged-")), "{:?}", node.update_dir());
    }

    #[tokio::test]
    async fn a_version_that_failed_its_self_check_is_not_retried_automatically() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, FAILS));
        let old = node.process(OLD);
        let (_flows_tx, mut flows) = watch::channel(0);
        old.update(&release.signed, UpdateTiming::Idle, &release.source, &mut flows).await.unwrap_err();
        let failures = old.failures().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!((&failures[0].version, failures[0].reason.as_str()), (&version(NEW), "自检没有通过：退出码 3：读不了 config.toml"));

        // 自动更新再来，连包都不取。重启之后也一样。
        let asked = release.source.offsets().len();
        for process in [old, node.process(OLD)] {
            let error = process.update(&release.signed, UpdateTiming::Idle, &release.source, &mut flows).await.unwrap_err();
            assert!(matches!(error, UpdateError::Refused(Refusal::FailedBefore { .. })), "{error:?}");
        }
        assert_eq!(release.source.offsets().len(), asked);

        // 管理员强制的更新可以再试；这个包还是不行，所以还是自检不通过。
        let error = node.process(OLD).update(&release.signed, UpdateTiming::Now, &release.source, &mut flows).await.unwrap_err();
        assert!(matches!(error, UpdateError::SelfCheck { .. }), "{error:?}");

        // 别的版本不受影响。
        let fixed = node.release("0.2.1", &fake_program("0.2.1", PASSES));
        assert_restart(node.process(OLD).update(&fixed.signed, UpdateTiming::Idle, &fixed.source, &mut flows).await, "0.2.1");
        assert_eq!(node.running_program(), fake_program("0.2.1", PASSES));
    }

    #[tokio::test]
    async fn an_update_is_rolled_back_after_three_unconfirmed_starts() {
        let node = Node::installed();
        let release = node.install(Swap::NATIVE).await;

        for _ in 0..MAX_UNCONFIRMED_STARTS {
            assert_eq!(node.process(NEW).startup().unwrap(), Startup::AwaitingConfirmation { version: version(NEW) });
            assert_eq!(node.running_program(), fake_program(NEW, PASSES));
        }
        let fourth = node.process(NEW);
        let Startup::RolledBack(rolled_back) = fourth.startup().unwrap() else { panic!("第四次启动应该换回旧程序") };
        assert_eq!(rolled_back.failed, version(NEW));
        assert_eq!(rolled_back.restart, RestartRequired { version: version(OLD) });
        assert_eq!(rolled_back.reason, "新程序启动了 3 次都没有连上 controller");
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
        assert_eq!(node.bin(), ["i3t"]);
        assert!(matches!(&*fourth.status().borrow(), UpdateStatus::Failed { kind: FailureKind::VersionRejected, .. }));

        // 旧程序重新启动：没有待确认的东西，但它记得那次失败，并且摆在状态上等着报给 controller。
        let old = node.process(OLD);
        assert_eq!(old.startup().unwrap(), Startup::Clean);
        assert_eq!(
            *old.status().borrow(),
            UpdateStatus::Failed {
                version: Some(version(NEW)),
                kind: FailureKind::VersionRejected,
                reason: rolled_back.reason,
                cause: Some(UpdateCause::StartsUnconfirmed { starts: MAX_UNCONFIRMED_STARTS }),
            }
        );
        let error = old.check(&release.signed, UpdateTiming::Idle).unwrap_err();
        assert!(matches!(error, UpdateError::Refused(Refusal::FailedBefore { .. })), "{error:?}");
        assert_eq!(old.check(&release.signed, UpdateTiming::Now).unwrap().version, version(NEW), "管理员可以强制再试");
    }

    #[tokio::test]
    async fn an_update_is_rolled_back_at_startup_once_the_time_limit_has_passed() {
        let node = Node::installed();
        node.install(Swap::NATIVE).await;
        assert_eq!(node.process(NEW).startup().unwrap(), Startup::AwaitingConfirmation { version: version(NEW) });

        // 把"换上去的时刻"往前拨到期限之外。
        let file = node.state_file();
        let mut state = file.load().unwrap();
        state.pending.as_mut().unwrap().since -= CONFIRMATION_WINDOW.as_secs() + 1;
        file.save(&state).unwrap();

        let Startup::RolledBack(rolled_back) = node.process(NEW).startup().unwrap() else { panic!("过了期限应该换回旧程序") };
        assert_eq!(rolled_back.reason, "新程序换上去 5 分钟还没有连上 controller");
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
        assert_eq!(node.process(OLD).failures().unwrap()[0].version, version(NEW));
    }

    #[tokio::test]
    async fn a_running_program_rolls_itself_back_when_the_time_limit_passes() {
        let node = Node::installed();
        node.install(Swap::NATIVE).await;
        let new = node.process(NEW);
        assert_eq!(new.startup().unwrap(), Startup::AwaitingConfirmation { version: version(NEW) });

        // 从这里起用假的时钟：等待会立刻跳到头，不用真的等 5 分钟。
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let rolled_back = new.enforce_confirmation_deadline().await.unwrap().expect("到期没有确认，应该换回旧程序");
        let waited = started.elapsed();
        // 定时器的粒度是毫秒；从换上去到这里真实过去的那一点时间已经从期限里扣掉了。
        let slack = Duration::from_secs(60);
        assert!(waited > CONFIRMATION_WINDOW - slack && waited < CONFIRMATION_WINDOW + Duration::from_millis(10), "等了 {waited:?}");
        assert_eq!(rolled_back.failed, version(NEW));
        assert_eq!(rolled_back.restart, RestartRequired { version: version(OLD) });
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
    }

    #[tokio::test]
    async fn the_deadline_does_nothing_once_the_update_is_confirmed() {
        let node = Node::installed();
        node.install(Swap::NATIVE).await;
        let new = node.process(NEW);
        assert_eq!(new.startup().unwrap(), Startup::AwaitingConfirmation { version: version(NEW) });

        tokio::time::pause();
        let deadline = new.enforce_confirmation_deadline();
        let confirm = async {
            // 让守期限的那一边先睡下，再确认。
            tokio::time::sleep(Duration::from_secs(10)).await;
            new.confirm().unwrap()
        };
        let (outcome, confirmed) = tokio::join!(deadline, confirm);
        assert_eq!(confirmed, Some(version(NEW)));
        assert_eq!(outcome.unwrap(), None);
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));

        // 没有待确认的更新时立刻返回。
        assert_eq!(node.process(NEW).enforce_confirmation_deadline().await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_confirmed_newer_version_clears_older_failure_records() {
        let node = Node::installed();
        let broken = node.release(NEW, &fake_program(NEW, FAILS));
        let (_flows_tx, mut flows) = watch::channel(0);
        node.process(OLD).update(&broken.signed, UpdateTiming::Idle, &broken.source, &mut flows).await.unwrap_err();
        assert_eq!(node.process(OLD).failures().unwrap().len(), 1);

        let fixed = node.release("0.2.1", &fake_program("0.2.1", PASSES));
        assert_restart(node.process(OLD).update(&fixed.signed, UpdateTiming::Idle, &fixed.source, &mut flows).await, "0.2.1");
        let new = node.process("0.2.1");
        assert_eq!(new.startup().unwrap(), Startup::AwaitingConfirmation { version: version("0.2.1") });
        assert_eq!(new.failures().unwrap().len(), 1, "还没确认的时候记录还在");
        new.confirm().unwrap();
        assert_eq!(new.failures().unwrap(), []);
    }

    #[tokio::test]
    async fn rollback_by_moving_the_running_program_aside_cleans_up_on_the_next_start() {
        let node = Node::installed();
        node.install(Swap::MoveAside).await;
        assert_eq!(node.bin(), ["i3t", "i3t.old"]);
        let new = |node: &Node| node.process_swapping(NEW, Swap::MoveAside);
        for _ in 0..MAX_UNCONFIRMED_STARTS {
            assert_eq!(new(&node).startup().unwrap(), Startup::AwaitingConfirmation { version: version(NEW) });
        }
        assert!(matches!(new(&node).startup().unwrap(), Startup::RolledBack(_)));
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
        // 被换下去的新程序这时候还在运行，Windows 上删不掉，先挪到一边。
        assert_eq!(node.bin(), ["i3t", "i3t.failed"]);
        assert_eq!(node.process_swapping(OLD, Swap::MoveAside).startup().unwrap(), Startup::Clean);
        assert_eq!(node.bin(), ["i3t"]);
    }

    #[tokio::test]
    async fn idle_timing_waits_until_the_caller_reports_no_flows() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, PASSES));
        let old = node.process(OLD);
        let mut status = old.status();
        let (flows_tx, mut flows) = watch::channel(2);
        let mut update = std::pin::pin!(old.update(&release.signed, UpdateTiming::Idle, &release.source, &mut flows));

        // 包取了、自检过了，然后停在"等待空闲"。
        tokio::select! {
            result = &mut update => panic!("还有流的时候不应该换程序：{result:?}"),
            waiting = status.wait_for(|status| matches!(status, UpdateStatus::WaitingForIdle { .. })) => drop(waiting.unwrap()),
        }
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
        assert_eq!(node.bin(), ["i3t", "i3t.new"]);

        // 少了一条流还不够。
        flows_tx.send_replace(1);
        assert!(tokio::time::timeout(Duration::from_millis(100), &mut update).await.is_err());
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));

        flows_tx.send_replace(0);
        assert_restart(update.await, NEW);
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));
    }

    #[tokio::test]
    async fn now_timing_does_not_wait_for_flows() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, PASSES));
        let old = node.process(OLD);
        let stages = record_stages(&old);
        let (_flows_tx, mut flows) = watch::channel(5);
        assert_restart(old.update(&release.signed, UpdateTiming::Now, &release.source, &mut flows).await, NEW);
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));
        drop(old);
        assert_stages(&stages.await.unwrap(), &["idle", "downloading", "verifying", "self_check", "installing", "restarting"]);
    }

    #[tokio::test]
    async fn after_drain_timing_announces_draining_and_waits_for_the_last_flow() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, PASSES));
        let old = node.process(OLD);
        let mut status = old.status();
        let (flows_tx, mut flows) = watch::channel(1);
        let mut update = std::pin::pin!(old.update(&release.signed, UpdateTiming::AfterDrain, &release.source, &mut flows));

        tokio::select! {
            result = &mut update => panic!("手上还有流的时候不应该换程序：{result:?}"),
            draining = status.wait_for(|status| matches!(status, UpdateStatus::Draining { .. })) => drop(draining.unwrap()),
        }
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
        flows_tx.send_replace(0);
        assert_restart(update.await, NEW);
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));
    }

    #[tokio::test]
    async fn timing_can_be_changed_by_calling_again_without_fetching_the_package_twice() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, PASSES));
        let old = node.process(OLD);
        let mut status = old.status();
        let (_flows_tx, mut flows) = watch::channel(1);
        {
            let mut waiting = std::pin::pin!(old.update(&release.signed, UpdateTiming::Idle, &release.source, &mut flows));
            tokio::select! {
                result = &mut waiting => panic!("{result:?}"),
                reached = status.wait_for(|status| matches!(status, UpdateStatus::WaitingForIdle { .. })) => drop(reached.unwrap()),
            }
        }
        // 管理员点了"立即更新"：丢掉在等空闲的那一次，换个时机重新来。
        assert_restart(old.update(&release.signed, UpdateTiming::Now, &release.source, &mut flows).await, NEW);
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));
        assert_eq!(release.source.offsets(), [0], "第二次用的是已经取下来的包");
    }

    #[tokio::test]
    async fn a_package_that_does_not_match_the_manifest_is_not_installed_and_not_blamed_on_the_version() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, PASSES));
        let tampered = MemorySource::new(fake_program(NEW, "echo 我被换过了; exit 0").as_bytes());
        let old = node.process(OLD);
        let (_flows_tx, mut flows) = watch::channel(0);

        let error = old.update(&release.signed, UpdateTiming::Now, &tampered, &mut flows).await.unwrap_err();
        assert!(matches!(error, UpdateError::Corrupt { .. } | UpdateError::Unavailable(_)), "{error:?}");
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
        assert_eq!(node.bin(), ["i3t"], "对不上的包不会被放到程序旁边，更不会被运行");
        let status = old.status().borrow().clone();
        assert!(matches!(status, UpdateStatus::Failed { kind: FailureKind::NotInstalled, .. }), "{status:?}");
        assert_eq!(old.failures().unwrap(), [], "这不是这个版本的问题，以后还可以再试");

        // 换一个给对的来源，同一个版本照常装上。
        assert_restart(old.update(&release.signed, UpdateTiming::Idle, &release.source, &mut flows).await, NEW);
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));
    }

    /// 给了第一块之后就不再回答的来源，用来模拟取到一半进程没了。
    struct StallsAfterFirstChunk {
        inner: MemorySource,
        stalled: Notify,
    }

    impl PackageSource for StallsAfterFirstChunk {
        async fn fetch(&self, request: ChunkRequest<'_>) -> Result<Vec<u8>, SourceError> {
            if request.offset > 0 {
                self.stalled.notify_one();
                std::future::pending::<()>().await;
            }
            self.inner.fetch(request).await
        }
    }

    #[tokio::test]
    async fn an_interrupted_download_is_resumed_by_the_next_process() {
        let node = Node::installed();
        // 包要比一块大，才有"取到一半"。脚本在 exit 之后的内容不会被读到。
        let program = format!("{}# {}\n", fake_program(NEW, PASSES), "填充".repeat(100_000));
        let release = node.release(NEW, &program);
        let (_flows_tx, mut flows) = watch::channel(0);

        let first = node.process(OLD);
        let stalling = StallsAfterFirstChunk { inner: MemorySource::new(program.as_bytes()), stalled: Notify::new() };
        tokio::select! {
            result = first.update(&release.signed, UpdateTiming::Idle, &stalling, &mut flows) => panic!("应该停在第二块上：{result:?}"),
            () = stalling.stalled.notified() => {}
        }
        let UpdateStatus::Downloading { received, total, .. } = first.status().borrow().clone() else { panic!("应该还在取包") };
        assert!(received > 0 && received < total, "取了 {received} / {total}");
        drop(first);

        // 进程重启。新进程从暂存文件的长度接着取，不从头来。
        let second = node.process(OLD);
        assert_eq!(second.startup().unwrap(), Startup::Clean);
        assert_restart(second.update(&release.signed, UpdateTiming::Idle, &release.source, &mut flows).await, NEW);
        assert_eq!(release.source.offsets().first(), Some(&received));
        assert_eq!(node.running_program(), program);
    }

    #[tokio::test]
    async fn nothing_more_is_installed_until_the_process_has_restarted() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, PASSES));
        let newer = node.release("0.3.0", &fake_program("0.3.0", PASSES));
        let old = node.process(OLD);
        let (_flows_tx, mut flows) = watch::channel(0);
        assert_restart(old.update(&release.signed, UpdateTiming::Now, &release.source, &mut flows).await, NEW);

        // 旧进程还没退出，又来了一份更新的清单。这时备份是 0.1.0，再换一次就把它盖掉了。
        let error = old.update(&newer.signed, UpdateTiming::Now, &newer.source, &mut flows).await.unwrap_err();
        assert!(matches!(&error, UpdateError::Refused(Refusal::RestartPending { installed }) if *installed == version(NEW)), "{error:?}");
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));
        assert_eq!(fs::read_to_string(node.dir.path().join("bin/i3t.old")).unwrap(), fake_program(OLD, "exit 0"));
    }

    #[tokio::test]
    async fn a_candidate_changed_after_its_self_check_is_not_installed() {
        let node = Node::installed();
        let release = node.release(NEW, &fake_program(NEW, PASSES));
        let old = node.process(OLD);
        let prepared = old.prepare(&release.signed, UpdateTiming::Idle, &release.source).await.unwrap();
        assert_eq!(prepared.version(), &version(NEW));
        assert_eq!(*old.status().borrow(), UpdateStatus::SelfCheck { version: version(NEW) });
        fs::write(node.dir.path().join("bin/i3t.new"), "等空闲的时候被改过了").unwrap();

        let error = old.install(prepared).await.unwrap_err();
        assert!(matches!(error, UpdateError::Corrupt { .. }), "{error:?}");
        assert_eq!(node.running_program(), fake_program(OLD, "exit 0"));
        assert_eq!(node.bin(), ["i3t"]);
        assert_eq!(node.process(OLD).startup().unwrap(), Startup::Clean);
    }

    #[tokio::test]
    async fn a_pending_record_that_does_not_match_the_running_program_is_dropped() {
        let node = Node::installed();
        node.install(Swap::NATIVE).await;
        // 有人在确认之前手动换了别的版本。
        fs::write(node.program(), fake_program("0.5.0", PASSES)).unwrap();
        let manual = node.process("0.5.0");
        assert_eq!(manual.startup().unwrap(), Startup::Clean);
        assert_eq!(node.running_program(), fake_program("0.5.0", PASSES), "不是它换上去的，不能替它换回");
        assert_eq!(node.bin(), ["i3t"]);
        assert_eq!(manual.confirm().unwrap(), None);
        assert_eq!(manual.failures().unwrap(), []);
    }

    #[tokio::test]
    async fn a_missing_backup_means_the_new_program_keeps_running() {
        let node = Node::installed();
        node.install(Swap::NATIVE).await;
        fs::remove_file(node.dir.path().join("bin/i3t.old")).unwrap();
        for _ in 0..MAX_UNCONFIRMED_STARTS {
            assert_eq!(node.process(NEW).startup().unwrap(), Startup::AwaitingConfirmation { version: version(NEW) });
        }
        assert_eq!(node.process(NEW).startup().unwrap(), Startup::Clean, "没有东西可以换回");
        assert_eq!(node.running_program(), fake_program(NEW, PASSES));
        assert_eq!(node.process(NEW).startup().unwrap(), Startup::Clean);
    }
}
