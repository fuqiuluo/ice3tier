//! 节点更新的规矩：发布源、包的缓存、让谁更新、暂停与继续。
//!
//! 发布源是一个临时目录，照 `crate::release` 里的布局摆；清单用测试自己的钥匙签，controller 换成只认这一把。

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use i3t_crypto::NodeKey;
use i3t_model::admin::{ErrorCode, NetworkId, PackageState, RelaySettings, UpdateNode, UpdateSettings, UpdateWait};
use i3t_model::control::{Declared, Hello, MAX_PACKAGE_CHUNK, SelfUpdate, ToController};
use i3t_model::update::{
    Artifact, FailureKind, LATEST_DIR, MANIFEST_FILE, Manifest, NODE_PROGRAM, Platform, SIGNATURE_FILE, SelfUpdateBlocker, Sha256,
    UpdateCause, UpdateStatus, UpdateTiming, Version,
};
use i3t_update::{TrustedKeys, sign_manifest};
use ring::digest;

use super::super::testing::{CAN_DO_ALL, Lab, Member, hello, modern_hello};
use super::super::{Controller, Timing};
use crate::store::Store;

const LINUX: &str = "linux-x86_64";
const OLD: &str = "0.1.0";
const NEW: &str = "0.2.0";

fn version(text: &str) -> Version {
    text.parse().unwrap()
}

/// 一个发布源目录，和签它的那把钥匙。
struct Publisher {
    key: NodeKey,
    root: tempfile::TempDir,
}

impl Publisher {
    fn new() -> Self {
        Self { key: NodeKey::generate().unwrap(), root: tempfile::tempdir().unwrap() }
    }

    fn source(&self) -> String {
        self.root.path().to_str().unwrap().to_owned()
    }

    fn program_path(&self, release: &str, platform: &str) -> std::path::PathBuf {
        let file = platform.parse::<Platform>().unwrap().program_file(NODE_PROGRAM);
        self.root.path().join(version(release).release_dir()).join(file)
    }

    /// 发布一个版本：放好各个平台的程序，签清单，再把清单放到"最新"的位置上。
    fn publish(&self, release: &str, programs: &[(&str, &[u8])]) {
        self.publish_with(&self.key, release, "0.0.0", programs);
    }

    fn publish_with(&self, key: &NodeKey, release: &str, min_controller: &str, programs: &[(&str, &[u8])]) {
        let artifacts = self.place(release, programs);
        let manifest = Manifest {
            version: version(release),
            min_controller: version(min_controller),
            published: 1_763_200_000,
            artifacts,
            security_floor: None,
            files: BTreeMap::new(),
        };
        self.sign_as_latest(key, &manifest);
    }

    /// 发布一个写了安全下限的版本。
    fn publish_with_floor(&self, release: &str, floor: &str, programs: &[(&str, &[u8])]) {
        let artifacts = self.place(release, programs);
        let manifest = Manifest {
            version: version(release),
            min_controller: version("0.0.0"),
            published: 1_763_200_000,
            artifacts,
            security_floor: Some(version(floor)),
            files: BTreeMap::new(),
        };
        self.sign_as_latest(&self.key, &manifest);
    }

    /// 把各个平台的程序放进这个版本的目录，返回清单里的那一项项。
    fn place(&self, release: &str, programs: &[(&str, &[u8])]) -> BTreeMap<String, Artifact> {
        let mut artifacts = BTreeMap::new();
        for (platform, content) in programs {
            let path = self.program_path(release, platform);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            let hash: [u8; 32] = digest::digest(&digest::SHA256, content).as_ref().try_into().unwrap();
            let artifact = Artifact {
                file: path.file_name().unwrap().to_str().unwrap().to_owned(),
                size: u64::try_from(content.len()).unwrap(),
                sha256: Sha256::from_bytes(hash),
            };
            artifacts.insert((*platform).to_owned(), artifact);
        }
        artifacts
    }

    /// 签清单，再把它放到"最新"的位置上。
    fn sign_as_latest(&self, key: &NodeKey, manifest: &Manifest) {
        let signed = sign_manifest(key, serde_json::to_string_pretty(manifest).unwrap());
        let latest = self.root.path().join(LATEST_DIR);
        fs::create_dir_all(&latest).unwrap();
        fs::write(latest.join(MANIFEST_FILE), &signed.manifest).unwrap();
        fs::write(latest.join(SIGNATURE_FILE), format!("{}\n", signed.signature)).unwrap();
    }
}

/// 一个认测试钥匙、发布源指向测试目录的 controller，带一个网络。
struct Fleet {
    lab: Lab,
    publisher: Publisher,
    cache: tempfile::TempDir,
    network: NetworkId,
}

impl Fleet {
    fn new() -> Self {
        Self::with_controller(|controller| controller, Duration::ZERO)
    }

    fn with_controller(adjust: impl FnOnce(Controller) -> Controller, relay_settle: Duration) -> Self {
        let publisher = Publisher::new();
        let cache = tempfile::tempdir().unwrap();
        let timing = Timing { ack_coalesce: Duration::ZERO, report_coalesce: Duration::ZERO, relay_settle, ..Timing::default() };
        let controller = Controller::new(Store::temporary(), NodeKey::generate().unwrap(), "ctl.example.com:20331".to_owned(), timing)
            .unwrap()
            .with_release_keys(TrustedKeys::from(publisher.key.public()))
            .unwrap()
            .with_release_cache(cache.path().to_owned());
        let controller = adjust(controller);
        let settings = UpdateSettings { source: Some(Some(publisher.source())), ..UpdateSettings::default() };
        controller.set_update_settings(&settings).unwrap();
        let lab = Lab::around(controller);
        let network = lab.network("home").id;
        Self { lab, publisher, cache, network }
    }

    fn controller(&self) -> &Controller {
        &self.lab.controller
    }

    /// 查一次发布源，并把要用的包取回来：后台任务每小时做的事。
    fn sync(&self) {
        self.controller().check_release().unwrap();
        self.controller().fetch_packages().unwrap();
    }

    /// 发布 `NEW`，只有 Linux 的包。
    fn release(&self) {
        self.publisher.publish(NEW, &[(LINUX, b"the new program")]);
        self.sync();
    }

    /// 一个懂更新的节点加入并做了第一次上报。
    fn node(&mut self, running: &str) -> Member {
        self.node_as(&modern_hello(running))
    }

    fn node_as(&mut self, hello: &Hello) -> Member {
        let mut member = self.lab.join_as(self.network, hello);
        self.first_report(&mut member, UpdateStatus::Idle);
        member
    }

    /// 一个启用了 relay 的节点。
    fn relay(&mut self, running: &str) -> Member {
        let member = self.node_as(&Hello { declared: CAN_DO_ALL, ..modern_hello(running) });
        let settings = RelaySettings::default();
        self.controller().enable_relay(self.network, member.id, settings).unwrap();
        member
    }

    /// 节点连上之后的第一次上报。controller 等它到了才给节点下发指令，所以这时候把包也取一下。
    fn first_report(&self, member: &mut Member, status: UpdateStatus) {
        member.report_update(self.controller(), status);
        self.controller().fetch_packages().unwrap();
        member.receive();
    }

    /// 节点重启成了 `running` 这个版本：旧连接断开，新连接报到并做第一次上报。
    fn restarted(&mut self, member: &Member, hello: &Hello, status: UpdateStatus) -> Member {
        self.controller().disconnect(member.session);
        let mut again = self.lab.connect_as(member.key, hello).unwrap();
        self.first_report(&mut again, status);
        again
    }

    fn update_of(&self, member: &Member) -> i3t_model::admin::NodeUpdate {
        self.controller().node_update(self.network, member.id).unwrap()
    }

    /// 节点最近收到的指令里的版本和时机。
    fn last_order(&self, member: &mut Member) -> Option<(Version, UpdateTiming)> {
        member.receive();
        let (signed, timing) = member.orders.last()?;
        let manifest = TrustedKeys::from(self.publisher.key.public()).verify(signed).expect("下发的清单应该原样带着签名");
        Some((manifest.version, *timing))
    }
}

fn failed(release: &str, kind: FailureKind) -> UpdateStatus {
    UpdateStatus::Failed {
        version: Some(version(release)),
        kind,
        reason: "自检没有通过：读不了 config.toml".to_owned(),
        cause: Some(UpdateCause::SelfCheck { exit_code: Some(1), output: "读不了 config.toml".to_owned() }),
    }
}

#[test]
fn an_outdated_node_is_told_to_update_when_idle_once_it_has_reported() {
    let mut fleet = Fleet::new();
    fleet.release();
    let mut node = fleet.lab.join_as(fleet.network, &modern_hello(OLD));
    assert_eq!(fleet.last_order(&mut node), None, "第一次上报之前不下发：还不知道它是带着什么回来的");
    assert_eq!(fleet.update_of(&node).available, Some(version(NEW)));

    fleet.first_report(&mut node, UpdateStatus::Idle);
    assert_eq!(fleet.last_order(&mut node), Some((version(NEW), UpdateTiming::Idle)));
    let update = fleet.update_of(&node);
    assert_eq!(update.ordered.map(|order| (order.version, order.timing)), Some((version(NEW), UpdateTiming::Idle)));
    assert_eq!(fleet.controller().update_overview().unwrap().nodes.updating, 1);

    // 同一条连接上不重复下发。
    node.report_update(fleet.controller(), UpdateStatus::WaitingForIdle { version: version(NEW) });
    fleet.sync();
    node.receive();
    assert_eq!(node.orders.len(), 1);
    assert_eq!(fleet.update_of(&node).status, UpdateStatus::WaitingForIdle { version: version(NEW) });
}

#[test]
fn a_node_that_is_already_up_to_date_or_newer_is_left_alone() {
    let mut fleet = Fleet::new();
    fleet.release();
    let mut current = fleet.node(NEW);
    let mut newer = fleet.node("0.3.0-rc.1");
    assert_eq!((fleet.last_order(&mut current), fleet.last_order(&mut newer)), (None, None));
    assert_eq!(fleet.update_of(&current).available, None);
    let counts = fleet.controller().update_overview().unwrap().nodes;
    assert_eq!((counts.total, counts.up_to_date), (2, 2));
}

#[test]
fn nodes_that_were_offline_get_the_update_when_they_reconnect() {
    let mut fleet = Fleet::new();
    let node = fleet.node(OLD);
    fleet.controller().disconnect(node.session);
    fleet.release();
    assert!(node.orders.is_empty());
    assert_eq!(fleet.update_of(&node).available, Some(version(NEW)), "离线的节点也标出有新版本");

    let mut back = fleet.restarted(&node, &modern_hello(OLD), UpdateStatus::Idle);
    assert_eq!(fleet.last_order(&mut back), Some((version(NEW), UpdateTiming::Idle)));
}

#[test]
fn nodes_that_cannot_update_themselves_are_never_told_to() {
    let mut fleet = Fleet::new();
    fleet.release();
    let blocked_hello = Hello { self_update: Some(SelfUpdate::from(Some(SelfUpdateBlocker::Container))), ..modern_hello(OLD) };
    let mut blocked = fleet.node_as(&blocked_hello);
    // 最初那一版的节点：不懂更新的消息，发给它它会断开。
    let mut ancient = fleet.lab.join_as(fleet.network, &hello(Declared::default()));
    ancient.send(fleet.controller(), ToController::Report(Box::default()));
    fleet.sync();
    assert_eq!((fleet.last_order(&mut blocked), fleet.last_order(&mut ancient)), (None, None));

    for (member, expected) in [(&blocked, "容器"), (&ancient, "太旧")] {
        let update = fleet.update_of(member);
        assert_eq!(update.available, Some(version(NEW)), "仍然标出有新版本，好让管理员手动更新");
        let error = fleet.controller().force_update(fleet.network, member.id, UpdateTiming::Now).unwrap_err();
        assert_eq!(error.code(), ErrorCode::CannotSelfUpdate);
        assert!(error.to_string().contains(expected), "{error}");
    }
    assert_eq!(fleet.update_of(&blocked).self_update, Some(SelfUpdate { able: false, blocker: Some(SelfUpdateBlocker::Container) }));
    assert_eq!(fleet.update_of(&ancient).self_update, None);

    let forced = fleet.controller().force_update_all(UpdateTiming::Now).unwrap();
    assert!(forced.ordered.is_empty() && forced.queued.is_empty());
    assert_eq!(forced.skipped.len(), 2);
    assert_eq!((fleet.last_order(&mut blocked), fleet.last_order(&mut ancient)), (None, None));
    assert_eq!(fleet.controller().update_overview().unwrap().nodes.manual, 2);
}

#[test]
fn a_release_that_needs_a_newer_controller_is_not_rolled_out() {
    let mut fleet = Fleet::with_controller(|controller| controller.with_version(version("0.1.0")), Duration::ZERO);
    fleet.publisher.publish_with(&fleet.publisher.key, NEW, "0.2.0", &[(LINUX, b"needs a newer controller")]);
    fleet.sync();
    let mut node = fleet.node(OLD);
    assert_eq!(fleet.last_order(&mut node), None);

    let overview = fleet.controller().update_overview().unwrap();
    let release = overview.release.unwrap();
    assert!(release.controller_too_old && release.newer_than_controller);
    assert_eq!(fleet.controller().status().unwrap().newer_version, Some(version(NEW)), "提醒管理员手动更新 controller");
    assert_eq!(fleet.update_of(&node).available, None);
    let error = fleet.controller().force_update(fleet.network, node.id, UpdateTiming::Now).unwrap_err();
    assert_eq!(error.code(), ErrorCode::NoUpdate);
    assert!(error.to_string().contains("先更新 controller"), "{error}");

    // 同一份发布，controller 够新就照常下发。
    let mut fleet = Fleet::with_controller(|controller| controller.with_version(version("0.2.0")), Duration::ZERO);
    fleet.publisher.publish_with(&fleet.publisher.key, NEW, "0.2.0", &[(LINUX, b"needs a newer controller")]);
    fleet.sync();
    let mut node = fleet.node(OLD);
    assert_eq!(fleet.last_order(&mut node), Some((version(NEW), UpdateTiming::Idle)));
    assert_eq!(fleet.controller().status().unwrap().newer_version, None);
}

#[test]
fn a_manifest_the_controller_cannot_verify_is_not_believed() {
    let mut fleet = Fleet::new();
    let stranger = NodeKey::generate().unwrap();
    fleet.publisher.publish_with(&stranger, NEW, "0.0.0", &[(LINUX, b"signed by someone else")]);
    fleet.sync();
    let mut node = fleet.node(OLD);
    let overview = fleet.controller().update_overview().unwrap();
    assert_eq!(overview.release, None);
    assert!(overview.check_error.as_deref().is_some_and(|reason| reason.contains("签名")), "{:?}", overview.check_error);
    assert!(overview.checked_at.is_some());
    assert_eq!(fleet.last_order(&mut node), None);

    // 之前查到过的发布不受一次坏结果的影响。
    fleet.release();
    assert_eq!(fleet.last_order(&mut node), Some((version(NEW), UpdateTiming::Idle)));
    fleet.publisher.publish_with(&stranger, "0.9.0", "0.0.0", &[(LINUX, b"signed by someone else")]);
    fleet.sync();
    let overview = fleet.controller().update_overview().unwrap();
    assert_eq!(overview.release.map(|release| release.version), Some(version(NEW)));
    assert!(overview.check_error.is_some());

    // 清单的内容被人动过也一样：签名盖的是原文。
    fleet.publisher.publish(NEW, &[(LINUX, b"the new program")]);
    let manifest = fleet.publisher.root.path().join(LATEST_DIR).join(MANIFEST_FILE);
    fs::write(&manifest, fs::read_to_string(&manifest).unwrap().replace("0.2.0", "0.2.1")).unwrap();
    fleet.sync();
    assert!(fleet.controller().update_overview().unwrap().check_error.is_some());
}

#[test]
fn a_prerelease_at_the_source_is_ignored() {
    let mut fleet = Fleet::new();
    fleet.publisher.publish("0.2.0-rc.1", &[(LINUX, b"release candidate")]);
    fleet.sync();
    let mut node = fleet.node(OLD);
    let overview = fleet.controller().update_overview().unwrap();
    assert_eq!(overview.release, None);
    assert!(overview.check_error.as_deref().is_some_and(|reason| reason.contains("预发布")), "{:?}", overview.check_error);
    assert_eq!(fleet.last_order(&mut node), None);
}

#[test]
fn a_package_that_does_not_match_the_manifest_is_not_cached_or_offered() {
    let mut fleet = Fleet::new();
    fleet.publisher.publish(NEW, &[(LINUX, b"the new program"), ("windows-x86_64", b"the windows program")]);
    // 发布源上的包被换过了：清单验得过，包的哈希对不上。
    fs::write(fleet.publisher.program_path(NEW, LINUX), b"a tampered program").unwrap();
    fleet.sync();
    let mut node = fleet.node(OLD);
    fleet.sync();

    assert_eq!(fleet.last_order(&mut node), None, "包没有核对过之前不下发");
    let package = |fleet: &Fleet, platform: &str| {
        let release = fleet.controller().update_overview().unwrap().release.unwrap();
        release.packages.into_iter().find(|package| package.platform == platform).unwrap()
    };
    let linux = package(&fleet, LINUX);
    assert_eq!(linux.state, PackageState::Failed);
    assert!(linux.error.as_deref().is_some_and(|reason| reason.contains("对不上")), "{:?}", linux.error);
    assert_eq!(package(&fleet, "windows-x86_64").state, PackageState::NotNeeded, "没有节点用的平台不取");
    assert_eq!(fleet.update_of(&node).waiting, Some(UpdateWait::Package));
    let cached: Vec<_> = fs::read_dir(fleet.cache.path().join("v0.2.0")).unwrap().collect();
    assert!(cached.is_empty(), "核对不上的包不留在缓存里：{cached:?}");

    // 发布源修好之后，下一次查的时候重新取。
    fs::write(fleet.publisher.program_path(NEW, LINUX), b"the new program").unwrap();
    fleet.sync();
    assert_eq!(package(&fleet, LINUX).state, PackageState::Cached);
    assert_eq!(fleet.last_order(&mut node), Some((version(NEW), UpdateTiming::Idle)));
}

#[test]
fn packages_are_served_in_chunks_from_the_cache_and_a_download_can_resume() {
    let mut fleet = Fleet::new();
    let program: Vec<u8> = (0..=u8::MAX).cycle().take(700_000).collect();
    fleet.publisher.publish(NEW, &[(LINUX, &program)]);
    fleet.sync();
    let mut node = fleet.node(OLD);
    let platform: Platform = LINUX.parse().unwrap();
    // 请求编号、版本、平台、位置、长度。
    type Ask<'a> = (u64, &'a str, &'a Platform, u64, u32);
    let ask = |fleet: &Fleet, member: &Member, (request, release, platform, offset, len): Ask<'_>| {
        let message = ToController::PackageRequest { request, version: version(release), platform: platform.clone(), offset, len };
        member.send(fleet.controller(), message);
    };

    ask(&fleet, &node, (1, NEW, &platform, 0, MAX_PACKAGE_CHUNK));
    ask(&fleet, &node, (2, NEW, &platform, 262_144, u32::MAX));
    node.receive();
    let chunk = |member: &Member, request: u64| member.chunks.iter().find(|(id, _)| *id == request).unwrap().1.clone();
    assert_eq!(chunk(&node, 1).unwrap(), program[..262_144]);
    assert_eq!(chunk(&node, 2).unwrap(), program[262_144..524_288], "一段最多 256 KiB，不管节点要多少");

    // 链路断了重连之后从断点接着要，要到的还是同一个包的后一半。
    let mut again =
        fleet.restarted(&node, &modern_hello(OLD), UpdateStatus::Downloading { version: version(NEW), received: 524_288, total: 700_000 });
    let other_platform: Platform = "macos-aarch64".parse().unwrap();
    ask(&fleet, &again, (3, NEW, &platform, 524_288, MAX_PACKAGE_CHUNK));
    ask(&fleet, &again, (4, NEW, &platform, 700_000, MAX_PACKAGE_CHUNK));
    ask(&fleet, &again, (5, NEW, &other_platform, 0, MAX_PACKAGE_CHUNK));
    ask(&fleet, &again, (6, "0.9.0", &platform, 0, MAX_PACKAGE_CHUNK));
    again.receive();
    assert_eq!(chunk(&again, 3).unwrap(), program[524_288..]);
    for request in [4, 5, 6] {
        assert!(chunk(&again, request).is_err(), "第 {request} 个请求应该得到“给不了”");
    }
    assert!(chunk(&again, 5).unwrap_err().contains("macos-aarch64"));
}

#[test]
fn a_version_failure_pauses_the_rollout_until_an_admin_resumes_it() {
    let mut fleet = Fleet::new();
    fleet.release();
    let (mut victim, mut waiting) = (fleet.node(OLD), fleet.node(OLD));
    assert!(fleet.last_order(&mut victim).is_some() && fleet.last_order(&mut waiting).is_some());

    victim.report_update(fleet.controller(), failed(NEW, FailureKind::VersionRejected));
    let overview = fleet.controller().update_overview().unwrap();
    assert_eq!(overview.paused.len(), 1);
    assert_eq!((overview.paused[0].version.clone(), overview.paused[0].node.as_ref().map(|node| node.id)), (version(NEW), Some(victim.id)));
    assert!(overview.paused[0].reason.contains("自检"));
    assert_eq!(overview.nodes.failed, 1);
    let failure = fleet.update_of(&victim).failure.unwrap();
    assert_eq!((failure.version, failure.kind), (version(NEW), FailureKind::VersionRejected));
    assert!(fleet.controller().oplog(10).unwrap().iter().any(|entry| entry.action == "update.pause"));

    // 还没换上去的节点被叫停；失败的那个不用叫停，它已经结束了。
    waiting.receive();
    victim.receive();
    assert_eq!((waiting.cancels, victim.cancels), (1, 0));
    assert_eq!(fleet.update_of(&waiting).ordered, None);
    // 暂停期间新连上来的节点也不下发。
    let mut late = fleet.node(OLD);
    assert_eq!(fleet.last_order(&mut late), None);
    fleet.sync();
    assert_eq!(fleet.last_order(&mut late), None, "再查一次发布源也不会绕过暂停");

    fleet.controller().resume_update(&version(NEW)).unwrap();
    assert!(fleet.controller().update_overview().unwrap().paused.is_empty());
    waiting.receive();
    assert_eq!(waiting.orders.len(), 2, "继续之后重新下发");
    assert!(fleet.last_order(&mut late).is_some());
    victim.receive();
    assert_eq!(victim.orders.len(), 1, "失败过的节点不再自动装这个版本");

    // 失败的节点换回旧程序重启之后还带着同一条失败来报到：这不是新的失败，不能把已经继续的版本再暂停一次。
    let mut victim = fleet.restarted(&victim, &modern_hello(OLD), failed(NEW, FailureKind::VersionRejected));
    assert!(fleet.controller().update_overview().unwrap().paused.is_empty());
    assert_eq!(fleet.last_order(&mut victim), None);
    assert_eq!(fleet.controller().resume_update(&version(NEW)).unwrap_err().code(), ErrorCode::NotFound);
}

#[test]
fn a_node_that_rolled_back_reports_it_on_reconnect_and_that_pauses_the_rollout() {
    let mut fleet = Fleet::new();
    fleet.release();
    let (mut first, mut second) = (fleet.node(OLD), fleet.node(OLD));
    assert!(fleet.last_order(&mut first).is_some());
    // 第一个节点换上了新程序、重启、连不上、自己换回旧程序再重启：它带着失败回来。
    fleet.controller().disconnect(first.session);
    let mut back = fleet.lab.connect_as(first.key, &modern_hello(OLD)).unwrap();
    assert_eq!(fleet.last_order(&mut back), None, "它的第一次上报到之前，不把同一个版本再发给它");
    let rolled_back = UpdateStatus::Failed {
        version: Some(version(NEW)),
        kind: FailureKind::VersionRejected,
        reason: "新程序启动了 3 次都没有连上 controller".to_owned(),
        cause: Some(UpdateCause::StartsUnconfirmed { starts: 3 }),
    };
    fleet.first_report(&mut back, rolled_back);

    assert_eq!(fleet.last_order(&mut back), None);
    assert_eq!(fleet.controller().update_overview().unwrap().paused.len(), 1);
    second.receive();
    assert_eq!(second.cancels, 1);
}

#[test]
fn a_failure_that_does_not_blame_the_version_is_retried_at_the_next_check_without_pausing() {
    let mut fleet = Fleet::new();
    fleet.release();
    let (mut unlucky, mut other) = (fleet.node(OLD), fleet.node(OLD));
    assert!(fleet.last_order(&mut unlucky).is_some());
    unlucky.report_update(fleet.controller(), failed(NEW, FailureKind::NotInstalled));

    assert!(fleet.controller().update_overview().unwrap().paused.is_empty());
    assert_eq!(fleet.update_of(&unlucky).failure, None);
    other.receive();
    unlucky.receive();
    assert_eq!((other.cancels, unlucky.cancels, unlucky.orders.len()), (0, 0, 1), "别的节点不受影响，同一条连接上也不马上重发");

    fleet.sync();
    unlucky.receive();
    assert_eq!(unlucky.orders.len(), 2, "下一次查发布源时再试");
}

#[test]
fn turning_auto_update_off_offers_nothing_and_withdraws_pending_orders() {
    let mut fleet = Fleet::new();
    fleet.release();
    let mut pending = fleet.node(OLD);
    assert!(fleet.last_order(&mut pending).is_some());

    let off = UpdateSettings { auto_update: Some(false), ..UpdateSettings::default() };
    assert!(!fleet.controller().set_update_settings(&off).unwrap().auto_update);
    pending.receive();
    assert_eq!(pending.cancels, 1);
    let mut later = fleet.node(OLD);
    assert_eq!(fleet.last_order(&mut later), None);
    let update = fleet.update_of(&later);
    assert_eq!((update.available, update.ordered), (Some(version(NEW)), None), "关着的时候只标出有新版本，等管理员点");
    assert_eq!(fleet.controller().update_overview().unwrap().nodes.outdated, 2);

    // 强制更新不看开关。
    let update = fleet.controller().force_update(fleet.network, later.id, UpdateTiming::AfterDrain).unwrap();
    assert_eq!(update.ordered.map(|order| order.timing), Some(UpdateTiming::AfterDrain));
    assert_eq!(fleet.last_order(&mut later), Some((version(NEW), UpdateTiming::AfterDrain)));
    pending.receive();
    assert_eq!(pending.orders.len(), 1, "别的节点不受影响");

    let on = UpdateSettings { auto_update: Some(true), ..UpdateSettings::default() };
    fleet.controller().set_update_settings(&on).unwrap();
    pending.receive();
    assert_eq!(pending.orders.len(), 2);
}

/// 管理员打开或者关掉一个节点的自动更新。
fn switch_auto_update(fleet: &Fleet, member: &Member, on: bool) {
    let request = UpdateNode { auto_update: Some(on), ..UpdateNode::default() };
    let node = fleet.controller().update_node(fleet.network, member.id, &request).unwrap();
    assert_eq!(node.auto_update, on);
}

#[test]
fn a_node_with_its_own_switch_off_is_left_alone_until_an_admin_forces_it() {
    let mut fleet = Fleet::new();
    let mut kept = fleet.node(OLD);
    switch_auto_update(&fleet, &kept, false);
    let mut pending = fleet.node(OLD);
    fleet.release();
    assert_eq!(fleet.last_order(&mut kept), None, "它自己的开关关着");
    assert!(fleet.last_order(&mut pending).is_some(), "别的节点照常");
    let update = fleet.update_of(&kept);
    assert_eq!((update.available, update.ordered, update.waiting), (Some(version(NEW)), None, None), "只标出有新版本，等管理员点");
    assert_eq!(fleet.controller().update_overview().unwrap().nodes.outdated, 1);

    // 关掉还没换上去的那个：和关掉全局的开关一样撤回，别的节点不受影响。
    switch_auto_update(&fleet, &pending, false);
    pending.receive();
    assert_eq!((pending.cancels, fleet.update_of(&pending).ordered), (1, None));
    kept.receive();
    assert_eq!(kept.cancels, 0);

    // 打开就轮到它；全局的开关关着时两个都要开着才算。
    switch_auto_update(&fleet, &pending, true);
    assert_eq!(fleet.last_order(&mut pending), Some((version(NEW), UpdateTiming::Idle)));
    fleet.controller().set_update_settings(&UpdateSettings { auto_update: Some(false), ..UpdateSettings::default() }).unwrap();
    switch_auto_update(&fleet, &kept, true);
    assert_eq!(fleet.last_order(&mut kept), None, "全局的开关关着");
    switch_auto_update(&fleet, &kept, false);
    fleet.controller().set_update_settings(&UpdateSettings { auto_update: Some(true), ..UpdateSettings::default() }).unwrap();
    assert_eq!(fleet.last_order(&mut kept), None, "它自己的又关了");

    // "立即更新"不看它的开关。
    fleet.controller().force_update(fleet.network, kept.id, UpdateTiming::Now).unwrap();
    assert_eq!(fleet.last_order(&mut kept), Some((version(NEW), UpdateTiming::Now)));
}

#[test]
fn a_relay_with_its_switch_off_does_not_hold_up_the_other_relays() {
    let mut fleet = Fleet::new();
    let mut skipped = fleet.relay(OLD);
    switch_auto_update(&fleet, &skipped, false);
    let (mut first, mut second) = (fleet.relay(OLD), fleet.relay(OLD));
    fleet.release();
    assert_eq!(fleet.last_order(&mut skipped), None, "开关关着的 relay 不排队，也就不占轮次");
    assert!(fleet.last_order(&mut first).is_some(), "编号最小的 relay 开关关着，轮到下一个");
    assert_eq!(fleet.last_order(&mut second), None);
    assert_eq!(fleet.update_of(&second).waiting, Some(UpdateWait::RelayTurn));

    // 轮到的 relay 被关掉开关：指令撤回，这一轮马上让给下一个。
    switch_auto_update(&fleet, &first, false);
    first.receive();
    assert_eq!(first.cancels, 1);
    assert!(fleet.last_order(&mut second).is_some(), "不用等它");
    assert_eq!(fleet.update_of(&first).waiting, None);

    // "全部更新"不看开关：开关关着的 relay 照样排队。
    let forced = fleet.controller().force_update_all(UpdateTiming::Now).unwrap();
    let ids: Vec<_> = forced.queued.iter().map(|node| node.id).collect();
    assert_eq!(ids, [skipped.id, first.id], "第二个 relay 占着这一轮");
}

#[test]
fn nodes_below_the_security_floor_are_marked_and_nothing_else_changes() {
    let mut fleet = Fleet::new();
    let mut old = fleet.node(OLD);
    let current = fleet.node(NEW);
    fleet.publisher.publish_with_floor(NEW, NEW, &[(LINUX, b"the fixed program")]);
    fleet.sync();

    let overview = fleet.controller().update_overview().unwrap();
    assert_eq!(overview.release.and_then(|release| release.security_floor), Some(version(NEW)));
    assert!(fleet.update_of(&old).security);
    assert!(!fleet.update_of(&current).security, "已经是下限那一版的节点没有已知的安全问题");
    assert_eq!(fleet.last_order(&mut old), Some((version(NEW), UpdateTiming::Idle)), "照常是自动的、空闲时的更新");

    // 开关关着的节点也标出来：这是告诉人的，人决定。
    let kept = fleet.node("0.0.9");
    switch_auto_update(&fleet, &kept, false);
    let update = fleet.update_of(&kept);
    assert!(update.security && update.ordered.is_none());

    // 下一个发布没有写下限：不再标。不在线的节点也按版本号算。
    fleet.controller().disconnect(kept.session);
    fleet.publisher.publish("0.3.0", &[(LINUX, b"a later program")]);
    fleet.sync();
    assert_eq!(fleet.controller().update_overview().unwrap().release.and_then(|release| release.security_floor), None);
    assert!(!fleet.update_of(&kept).security);
    fleet.publisher.publish_with_floor("0.4.0", "0.3.0", &[(LINUX, b"an even later program")]);
    fleet.sync();
    assert!(fleet.update_of(&kept).security, "带下去的下限：跳过了几版的节点照样知道");
    assert!(fleet.update_of(&current).security, "{NEW} 也比新的下限旧了");
}

#[test]
fn a_forced_update_ignores_the_pause_and_an_earlier_failure_and_can_change_the_timing() {
    let mut fleet = Fleet::new();
    fleet.release();
    let mut node = fleet.node(OLD);
    node.report_update(fleet.controller(), failed(NEW, FailureKind::VersionRejected));
    assert_eq!(fleet.controller().update_overview().unwrap().paused.len(), 1);

    assert_eq!(fleet.controller().force_update(fleet.network, node.id, UpdateTiming::Idle).unwrap_err().code(), ErrorCode::InvalidRequest);
    let update = fleet.controller().force_update(fleet.network, node.id, UpdateTiming::Now).unwrap();
    assert_eq!(update.failure, None, "管理员要再试，上一次的失败不再算数");
    assert_eq!(fleet.last_order(&mut node), Some((version(NEW), UpdateTiming::Now)));
    assert_eq!(fleet.controller().update_overview().unwrap().paused.len(), 1, "强制更新不解除暂停");

    // 等空闲的节点，管理员改成排空后更新：按新的时机重发。
    fleet.controller().resume_update(&version(NEW)).unwrap();
    let mut waiting = fleet.node(OLD);
    assert_eq!(fleet.last_order(&mut waiting), Some((version(NEW), UpdateTiming::Idle)));
    fleet.controller().force_update(fleet.network, waiting.id, UpdateTiming::AfterDrain).unwrap();
    assert_eq!(fleet.last_order(&mut waiting), Some((version(NEW), UpdateTiming::AfterDrain)));

    // 再失败一次是新的失败：重新暂停。
    fleet.controller().resume_update(&version(NEW)).unwrap_err();
    node.report_update(fleet.controller(), UpdateStatus::SelfCheck { version: version(NEW) });
    node.report_update(fleet.controller(), failed(NEW, FailureKind::VersionRejected));
    assert_eq!(fleet.controller().update_overview().unwrap().paused.len(), 1);

    let offline = fleet.node(OLD);
    fleet.controller().disconnect(offline.session);
    assert_eq!(fleet.controller().force_update(fleet.network, offline.id, UpdateTiming::Now).unwrap_err().code(), ErrorCode::NodeOffline);
}

#[test]
fn relays_are_updated_one_at_a_time_and_the_next_waits_for_the_previous_to_come_back() {
    let mut fleet = Fleet::new();
    let (mut first, mut second, mut third) = (fleet.relay(OLD), fleet.relay(OLD), fleet.relay(OLD));
    let mut plain = fleet.node(OLD);
    fleet.release();

    assert!(fleet.last_order(&mut plain).is_some(), "普通节点不排队");
    assert!(fleet.last_order(&mut first).is_some());
    assert_eq!((fleet.last_order(&mut second), fleet.last_order(&mut third)), (None, None));
    assert_eq!(fleet.update_of(&second).waiting, Some(UpdateWait::RelayTurn));

    // 第一个 relay 在等空闲、在下载、在重启的时候，别的 relay 都不动。
    first.report_update(fleet.controller(), UpdateStatus::Restarting { version: version(NEW) });
    fleet.controller().disconnect(first.session);
    fleet.sync();
    assert_eq!((fleet.last_order(&mut second), fleet.last_order(&mut third)), (None, None), "前一个还没回来");

    // 它带着新版本回来了：轮到下一个，仍然只有一个。
    let relay_hello = |running: &str| Hello { declared: CAN_DO_ALL, ..modern_hello(running) };
    let mut first = fleet.restarted(&first, &relay_hello(NEW), UpdateStatus::Confirmed { version: version(NEW) });
    assert_eq!(fleet.last_order(&mut first), None);
    assert!(fleet.last_order(&mut second).is_some());
    assert_eq!(fleet.last_order(&mut third), None);

    // 第二个没装成（不怪版本）：这一轮让出来，第三个接着来。
    second.report_update(fleet.controller(), failed(NEW, FailureKind::NotInstalled));
    assert!(fleet.last_order(&mut third).is_some());
    assert!(fleet.controller().update_overview().unwrap().paused.is_empty());
}

#[test]
fn the_next_relay_waits_until_the_previous_one_has_been_back_for_a_while() {
    let settle = Duration::from_millis(150);
    let mut fleet = Fleet::with_controller(|controller| controller, settle);
    let (mut first, mut second) = (fleet.relay(OLD), fleet.relay(OLD));
    fleet.release();
    assert!(fleet.last_order(&mut first).is_some());

    let relay_hello = Hello { declared: CAN_DO_ALL, ..modern_hello(NEW) };
    let _first = fleet.restarted(&first, &relay_hello, UpdateStatus::Confirmed { version: version(NEW) });
    assert_eq!(fleet.last_order(&mut second), None, "刚回来，挂靠它的节点还没有重新建好会话");
    let wake_at = fleet.controller().tick().unwrap().expect("后台任务应该知道什么时候再来看");
    assert!(wake_at <= std::time::Instant::now() + settle);

    std::thread::sleep(settle);
    fleet.controller().tick().unwrap();
    assert!(fleet.last_order(&mut second).is_some());
}

#[test]
fn a_relay_that_rolled_back_gives_up_its_turn_and_pauses_the_rollout() {
    let mut fleet = Fleet::new();
    let (mut first, mut second) = (fleet.relay(OLD), fleet.relay(OLD));
    fleet.release();
    assert!(fleet.last_order(&mut first).is_some());

    fleet.controller().disconnect(first.session);
    let mut back = fleet.lab.connect_as(first.key, &Hello { declared: CAN_DO_ALL, ..modern_hello(OLD) }).unwrap();
    assert_eq!(fleet.last_order(&mut second), None, "它刚连上来，是成了还是失败了还不知道");
    fleet.first_report(&mut back, failed(NEW, FailureKind::VersionRejected));

    assert_eq!(fleet.last_order(&mut second), None, "这个版本被暂停了，下一个 relay 不该再装它");
    assert_eq!(fleet.controller().update_overview().unwrap().paused.len(), 1);
    fleet.controller().resume_update(&version(NEW)).unwrap();
    assert!(fleet.last_order(&mut second).is_some(), "继续之后轮到下一个 relay，失败的那个不挡路");
}

#[test]
fn updating_everything_at_once_still_queues_the_relays_but_one_node_can_jump_the_queue() {
    let mut fleet = Fleet::new();
    let off = UpdateSettings { auto_update: Some(false), ..UpdateSettings::default() };
    fleet.controller().set_update_settings(&off).unwrap();
    let (mut first, mut second, mut third) = (fleet.relay(OLD), fleet.relay(OLD), fleet.relay(OLD));
    let mut plain = fleet.node(OLD);
    let offline = fleet.node(OLD);
    fleet.controller().disconnect(offline.session);
    fleet.release();
    assert_eq!(fleet.last_order(&mut plain), None);

    // 自动更新关着的时候没有人要过包，所以第一次点的时候全部先排着，等包取回来。
    let ids = |nodes: &[i3t_model::admin::NodeRef]| nodes.iter().map(|node| node.id).collect::<Vec<_>>();
    let forced = fleet.controller().force_update_all(UpdateTiming::Now).unwrap();
    assert_eq!(forced.version, Some(version(NEW)));
    assert!(forced.ordered.is_empty());
    assert_eq!(ids(&forced.queued), [first.id, second.id, third.id, plain.id]);
    assert_eq!(forced.skipped.len(), 1);
    assert!(forced.skipped[0].node.id == offline.id && forced.skipped[0].reason.contains("不在线"));
    assert_eq!(fleet.update_of(&plain).waiting, Some(UpdateWait::Package));

    // 包取回来之后：普通节点和第一个 relay 拿到指令，别的 relay 排着。再点一次看到的就是这个结果。
    fleet.controller().fetch_packages().unwrap();
    assert_eq!(fleet.last_order(&mut plain), Some((version(NEW), UpdateTiming::Now)));
    assert_eq!(fleet.last_order(&mut first), Some((version(NEW), UpdateTiming::Now)));
    assert_eq!(fleet.last_order(&mut second), None);
    let again = fleet.controller().force_update_all(UpdateTiming::Now).unwrap();
    assert_eq!(ids(&again.ordered), [first.id, plain.id]);
    assert_eq!(ids(&again.queued), [second.id, third.id]);
    first.receive();
    assert_eq!(first.orders.len(), 1, "已经发过的指令不重发");

    // 单独点了"立即更新"的 relay 不排队。
    fleet.controller().force_update(fleet.network, third.id, UpdateTiming::Now).unwrap();
    assert_eq!(fleet.last_order(&mut third), Some((version(NEW), UpdateTiming::Now)));
    assert_eq!(fleet.last_order(&mut second), None);

    // 第一个回来之后，排着的那个带着管理员选的时机轮到。
    let relay_hello = Hello { declared: CAN_DO_ALL, ..modern_hello(NEW) };
    fleet.restarted(&first, &relay_hello, UpdateStatus::Confirmed { version: version(NEW) });
    assert_eq!(fleet.last_order(&mut second), Some((version(NEW), UpdateTiming::Now)));
}

#[test]
fn a_deleted_or_demoted_relay_does_not_hold_up_the_others() {
    let mut fleet = Fleet::new();
    let (mut first, mut second, mut third) = (fleet.relay(OLD), fleet.relay(OLD), fleet.relay(OLD));
    fleet.release();
    assert!(fleet.last_order(&mut first).is_some());
    fleet.controller().disconnect(first.session);
    fleet.controller().delete_node(fleet.network, first.id).unwrap();
    assert!(fleet.last_order(&mut second).is_some());
    assert_eq!(fleet.last_order(&mut third), None);

    fleet.controller().disable_relay(fleet.network, second.id).unwrap();
    assert!(fleet.last_order(&mut third).is_some(), "不再是 relay 的节点不占着 relay 的轮次");
}

#[test]
fn a_newer_release_replaces_what_nodes_were_told_and_drops_the_old_packages() {
    let mut fleet = Fleet::new();
    fleet.release();
    let mut node = fleet.node(OLD);
    assert_eq!(fleet.last_order(&mut node), Some((version(NEW), UpdateTiming::Idle)));

    fleet.publisher.publish("0.3.0", &[(LINUX, b"an even newer program")]);
    fleet.sync();
    fleet.sync();
    assert_eq!(fleet.last_order(&mut node), Some((version("0.3.0"), UpdateTiming::Idle)));
    let cached: Vec<_> = fs::read_dir(fleet.cache.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(cached, ["v0.3.0"]);
}

#[test]
fn settings_the_known_release_pauses_and_failures_survive_a_restart() {
    let scratch = crate::store::Scratch::new();
    let database = scratch.database();
    let publisher = Publisher::new();
    let cache = tempfile::tempdir().unwrap();
    let open = || {
        let store = Store::open(&database).unwrap();
        Controller::new(store, NodeKey::generate().unwrap(), "ctl.example.com:20331".to_owned(), Timing::default())
            .unwrap()
            .with_release_keys(TrustedKeys::from(publisher.key.public()))
            .unwrap()
            .with_release_cache(cache.path().to_owned())
    };
    let controller = open();
    let defaults = controller.update_overview().unwrap();
    assert!(defaults.auto_update && defaults.source_is_default);
    assert_eq!((defaults.source.as_str(), defaults.release, defaults.checked_at), (crate::release::DEFAULT_SOURCE, None, None));

    controller.set_update_settings(&UpdateSettings { auto_update: Some(false), source: Some(Some(publisher.source())) }).unwrap();
    publisher.publish(NEW, &[(LINUX, b"the new program")]);
    controller.check_release().unwrap();
    let mut lab = Lab::around(controller);
    let network = lab.network("home").id;
    let node = lab.join_as(network, &modern_hello(OLD));
    // 自动更新关着：管理员让它立即更新，它装失败了。只有 controller 让它装过的版本，它的失败才暂停自动更新。
    node.report_update(&lab.controller, UpdateStatus::Idle);
    lab.controller.force_update(network, node.id, UpdateTiming::Now).unwrap();
    lab.controller.fetch_packages().unwrap();
    node.report_update(&lab.controller, failed(NEW, FailureKind::VersionRejected));
    let before = lab.controller.update_overview().unwrap();
    assert_eq!(before.paused.len(), 1);
    drop(lab);

    let controller = open();
    let after = controller.update_overview().unwrap();
    assert_eq!(
        (after.auto_update, after.source.as_str(), after.source_is_default, after.checked_at),
        (false, publisher.source().as_str(), false, before.checked_at)
    );
    assert_eq!(after.release.map(|release| release.version), Some(version(NEW)));
    assert_eq!(after.paused, before.paused);
    assert_eq!(controller.node_update(network, node.id).unwrap().failure.map(|failure| failure.version), Some(version(NEW)));

    // 改回默认的发布源；写法不对的发布源不收。
    let reset = controller.set_update_settings(&UpdateSettings { source: Some(None), ..UpdateSettings::default() }).unwrap();
    assert!(reset.source_is_default && !reset.auto_update);
    assert!(controller.release_check_requested(), "发布源变了要尽快查一次");
    let error = controller.set_update_settings(&UpdateSettings { source: Some(Some("ftp://x".to_owned())), ..UpdateSettings::default() });
    assert_eq!(error.unwrap_err().code(), ErrorCode::InvalidRequest);

    // 换了一把钥匙之后，存下来的那份清单验不过，不再相信它。
    drop(controller);
    let store = Store::open(&database).unwrap();
    let controller = Controller::new(store, NodeKey::generate().unwrap(), "ctl.example.com:20331".to_owned(), Timing::default()).unwrap();
    assert_eq!(controller.update_overview().unwrap().release, None);
}

#[test]
fn a_failure_for_a_version_the_node_was_never_given_does_not_pause_anything_but_is_on_record() {
    let mut fleet = Fleet::new();
    fleet.release();
    let mut waiting = fleet.node(OLD);
    assert!(fleet.last_order(&mut waiting).is_some());
    // 已经是新版本的节点没有被要求装它，却说它在自己那里不能用。
    let liar = fleet.node(NEW);
    liar.report_update(fleet.controller(), failed(NEW, FailureKind::VersionRejected));

    assert!(fleet.controller().update_overview().unwrap().paused.is_empty(), "一个没让它装过这个版本的节点暂停不了更新");
    waiting.receive();
    assert_eq!(waiting.cancels, 0, "别的节点照常更新");
    let log = fleet.controller().oplog(10).unwrap();
    let entry = log.iter().find(|entry| entry.action == "update.failure").expect("这次报告记进了操作记录");
    assert!(entry.detail.contains("没有让它装过"), "{}", entry.detail);
    assert_eq!(
        fleet.controller().lock().store.node(liar.id).unwrap().unwrap().update_failure.map(|failure| failure.version),
        Some(version(NEW))
    );
}

#[test]
fn a_pause_holds_only_in_the_network_of_the_node_that_failed() {
    let mut fleet = Fleet::new();
    fleet.release();
    let other = fleet.lab.network("lab").id;
    let mut victim = fleet.node(OLD);
    let mut elsewhere = fleet.lab.join_as(other, &modern_hello(OLD));
    fleet.first_report(&mut elsewhere, UpdateStatus::Idle);
    assert!(fleet.last_order(&mut victim).is_some() && fleet.last_order(&mut elsewhere).is_some());

    victim.report_update(fleet.controller(), failed(NEW, FailureKind::VersionRejected));
    let paused = fleet.controller().update_overview().unwrap().paused;
    assert_eq!(
        paused.iter().map(|paused| (paused.version.clone(), paused.network)).collect::<Vec<_>>(),
        [(version(NEW), Some(fleet.network))]
    );
    elsewhere.receive();
    assert_eq!(elsewhere.cancels, 0, "另一个网络里的节点不受这次失败影响");
    let mut late = fleet.lab.join_as(other, &modern_hello(OLD));
    fleet.first_report(&mut late, UpdateStatus::Idle);
    assert!(fleet.last_order(&mut late).is_some(), "另一个网络里新连上来的节点照常更新");
    let mut late_here = fleet.node(OLD);
    assert_eq!(fleet.last_order(&mut late_here), None, "失败的节点所在的网络暂停了");

    fleet.controller().resume_update(&version(NEW)).unwrap();
    assert!(fleet.controller().update_overview().unwrap().paused.is_empty());
    assert!(fleet.last_order(&mut late_here).is_some());
}

#[test]
fn a_node_cannot_wipe_its_own_failure_to_pause_the_version_again_after_a_resume() {
    let mut fleet = Fleet::new();
    fleet.release();
    let mut node = fleet.node(OLD);
    assert!(fleet.last_order(&mut node).is_some());
    node.report_update(fleet.controller(), failed(NEW, FailureKind::VersionRejected));
    assert_eq!(fleet.controller().update_overview().unwrap().paused.len(), 1);
    fleet.controller().resume_update(&version(NEW)).unwrap();
    let mut other = fleet.node(OLD);
    assert!(fleet.last_order(&mut other).is_some());

    // 它先说自己已经是新版本，再换回旧版本带着同一个版本的失败回来。
    let node = fleet.restarted(&node, &modern_hello(NEW), UpdateStatus::Idle);
    assert_eq!(fleet.update_of(&node).failure, None, "已经用不上的失败不显示");
    let mut node = fleet.restarted(&node, &modern_hello(OLD), failed(NEW, FailureKind::VersionRejected));
    assert!(fleet.controller().update_overview().unwrap().paused.is_empty(), "同一个节点在同一个版本上只能让它暂停一次");
    assert_eq!(fleet.last_order(&mut node), None, "它自己仍然不会被自动更新到这个版本");
    other.receive();
    assert_eq!(other.cancels, 0);
    assert_eq!(fleet.update_of(&node).failure.map(|failure| failure.version), Some(version(NEW)), "失败记录还在，管理员看得到");
}

#[test]
fn a_node_that_updated_some_other_way_loses_its_failure_record() {
    let mut fleet = Fleet::new();
    fleet.release();
    let node = fleet.node(OLD);
    node.report_update(fleet.controller(), failed(NEW, FailureKind::VersionRejected));
    assert!(fleet.update_of(&node).failure.is_some());
    let node = fleet.restarted(&node, &modern_hello(NEW), UpdateStatus::Idle);
    let update = fleet.update_of(&node);
    assert_eq!((update.failure, update.available), (None, None));
}

#[test]
fn update_metrics_follow_the_rollout() {
    let mut fleet = Fleet::new();
    fleet.release();
    let mut node = fleet.node(OLD);
    assert!(fleet.last_order(&mut node).is_some());
    let metrics = fleet.controller().metrics().unwrap();
    for line in [
        "i3t_controller_nodes_online 1\n",
        "i3t_controller_update_orders_total 1\n",
        "i3t_controller_update_nodes{state=\"updating\"} 1\n",
        "i3t_controller_update_release_info{version=\"0.2.0\"} 1\n",
        "i3t_controller_update_auto 1\n",
    ] {
        assert!(metrics.contains(line), "指标里应该有 {line:?}：\n{metrics}");
    }
    assert!(metrics.contains("i3t_controller_snapshots_sent_total "));
}
