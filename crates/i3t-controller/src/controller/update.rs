//! 节点更新在 controller 这一侧：设置、发布源、已知的发布、包的缓存，以及管理员的几个操作。
//!
//! 分工是这样的：
//!
//! - 这里管"知道什么"：发布源上最新的正式版是哪个（清单验过签才算数）、各个平台的包取回来没有、哪些版本被暂停了。
//! - [`rollout`](super::rollout) 管"让谁更新"：按这里知道的东西和每个节点的情况，决定给谁下发指令、撤回谁的。
//! - 节点自己再验一遍签名，自己决定装不装。controller 被攻破也只能让节点不更新，换不了它的程序。
//!
//! 查发布源和取包都要走网络，不能拿着 controller 的锁做。所以这两件事是"拿锁取出要做什么 → 放开锁去做 → 再拿锁记下结果"三段，
//! 入口是 [`Controller::check_release`] 和 [`Controller::fetch_packages`]，由后台任务和管理 API 在阻塞线程上调用。
//!
//! 设置、已知的发布和被暂停的版本存在数据库里，重启之后还在。管理员强制的更新、relay 的轮次和下发过的版本只在内存里：
//! controller 重启之后，还没有做完的强制更新要重新点。
//!
//! 暂停只信得过的失败：节点报的失败只有在 controller 确实让它装过这个版本时才暂停，并且只暂停它所在的网络。
//! 见 [`Inner::version_rejected`]。
//!
//! 清单写了安全下限时，版本比它旧的节点在管理 API 里标成有安全更新（`NodeUpdate::security`）。这只是告诉人的：
//! 让谁更新、强不强制都不看它，人看了自己决定。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use i3t_model::admin::{
    ForcedUpdates, LogRef, NetworkId, NodeUpdate, PackageInfo, PackageState, PausedVersion, ReleaseCause, ReleaseInfo, SkipCause,
    SkippedUpdate, Timestamp, UpdateCounts, UpdateFailure, UpdateOrder, UpdateOverview, UpdateSettings, action,
};
use i3t_model::update::{Artifact, FailureKind, Manifest, Platform, SignedManifest, UpdateCause, UpdateStatus, UpdateTiming, Version};
use i3t_proto::NodeId;
use i3t_update::TrustedKeys;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::rollout::{Forced, Turn};
use super::{Controller, Inner};
use crate::error::{Entity, Error, error_chain};
use crate::release::{self, DEFAULT_SOURCE, FetchError, Source};
use crate::store::{NodeRecord, Store};

const SETTINGS_META: &str = "update.settings";
const RELEASE_META: &str = "update.release";
const PAUSED_META: &str = "update.paused";

/// 数据目录里放包的子目录。
pub(super) const CACHE_DIR: &str = "releases";

/// 存在数据库里的设置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Settings {
    auto_update: bool,
    /// 发布源；`None` 是项目默认的。
    source: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self { auto_update: true, source: None }
    }
}

/// 一份验过签的清单，连同它的原文。原文要原样发给节点，节点自己再验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Release {
    pub(crate) signed: SignedManifest,
    pub(crate) manifest: Manifest,
}

/// 存在数据库里的发布：只存原文和签名，读出来之后重新验签。
#[derive(Serialize, Deserialize)]
struct StoredRelease {
    signed: SignedManifest,
    checked_at: Timestamp,
}

/// 一个网络里被暂停自动更新的版本，和导致暂停的那次失败。同一个版本在不同的网络里各有各的一条。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Paused {
    pub(crate) version: Version,
    pub(crate) node: NodeId,
    pub(crate) network: NetworkId,
    pub(crate) reason: String,
    pub(crate) at: Timestamp,
    /// `reason` 的代码。这个字段出现之前存下的暂停没有。
    #[serde(default)]
    pub(crate) cause: Option<UpdateCause>,
}

/// 查发布源或者取包没有成功：给管理员看的一句话，和它的代码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseFailure {
    pub(crate) reason: String,
    pub(crate) cause: ReleaseCause,
}

impl ReleaseFailure {
    fn fetch(error: &FetchError) -> Self {
        Self { reason: error_chain(error), cause: error.cause() }
    }

    fn invalid_source(error: &release::InvalidSource) -> Self {
        Self { reason: error.to_string(), cause: ReleaseCause::InvalidSource }
    }
}

/// 不能让一个节点立即更新：原因的代码，和单独让它更新时管理 API 回的错误。
struct Blocked {
    cause: SkipCause,
    error: Error,
}

/// 一个平台的包在缓存里的情况。没有记录的平台是还没有节点要用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Package {
    /// 有节点要用，排着队等后台去取。
    Wanted,
    Fetching,
    /// 已经在缓存里，核对过。
    Cached(PathBuf),
    /// 没有取成。下次查发布源时清掉这条记录，于是会再试。
    Failed(ReleaseFailure),
}

/// 节点更新在 controller 上的全部状态。
pub(crate) struct Updates {
    /// controller 自己的版本。清单里的 `min_controller` 和它比。
    pub(crate) version: Version,
    cache_dir: Option<PathBuf>,
    keys: TrustedKeys,
    settings: Settings,
    pub(crate) release: Option<Release>,
    checked_at: Option<Timestamp>,
    check_error: Option<ReleaseFailure>,
    pub(crate) paused: Vec<Paused>,
    /// 当前这个发布的各个平台的包，键是平台名。
    pub(crate) packages: BTreeMap<String, Package>,
    /// 管理员强制、还没有做完的更新。
    pub(crate) forced: BTreeMap<NodeId, Forced>,
    /// 每个网络里现在轮到哪个 relay 更新。
    pub(crate) relay_turns: BTreeMap<NetworkId, Turn>,
    /// 这次运行以来给各个节点下发过的版本，自动的和强制的都算。节点说某个版本不能用时，只有这里有记录才暂停自动更新。
    ///
    /// 只在内存里：controller 在下发和节点报告失败之间重启的话，这次失败不暂停，只记在节点头上。这时同一网络里下一个
    /// 失败的节点会让它暂停，代价是多一个节点试装一次（失败的节点会自己换回旧程序）。
    pub(crate) offered: BTreeMap<NodeId, Version>,
    /// 到这个时刻要再看一遍该让谁更新（等 relay 重新上线之后站稳）。
    pub(crate) next_rollout: Option<Instant>,
    /// 设置变了之后要尽快查一次发布源。
    check_requested: bool,
}

impl Updates {
    pub(super) fn load(store: &Store, version: Version) -> Result<Self, Error> {
        let mut updates = Self {
            version,
            cache_dir: None,
            keys: TrustedKeys::compiled_in(),
            settings: read_meta(store, SETTINGS_META)?.unwrap_or_default(),
            release: None,
            checked_at: None,
            check_error: None,
            paused: read_meta(store, PAUSED_META)?.unwrap_or_default(),
            packages: BTreeMap::new(),
            forced: BTreeMap::new(),
            relay_turns: BTreeMap::new(),
            offered: BTreeMap::new(),
            next_rollout: None,
            check_requested: false,
        };
        updates.load_release(store)?;
        Ok(updates)
    }

    /// 读出上次存下来的发布。存的是原文和签名，用现在认的公钥重新验：程序换了版本，认的公钥可能也换了。
    fn load_release(&mut self, store: &Store) -> Result<(), Error> {
        self.release = None;
        self.checked_at = None;
        let Some(stored) = read_meta::<StoredRelease>(store, RELEASE_META)? else { return Ok(()) };
        match self.keys.verify(&stored.signed) {
            Ok(manifest) => {
                self.release = Some(Release { signed: stored.signed, manifest });
                self.checked_at = Some(stored.checked_at);
            }
            Err(error) => tracing::warn!(reason = %error_chain(&error), "上次存下来的发布清单现在验不过了，丢掉它，等下一次查发布源"),
        }
        Ok(())
    }

    pub(crate) fn auto_update(&self) -> bool {
        self.settings.auto_update
    }

    fn source_text(&self) -> &str {
        self.settings.source.as_deref().unwrap_or(DEFAULT_SOURCE)
    }

    /// 可以下发的发布：已经查到，并且 controller 自己不比它要求的旧。
    pub(crate) fn usable_release(&self) -> Option<&Release> {
        self.release.as_ref().filter(|release| release.manifest.min_controller <= self.version)
    }

    /// 这个版本是不是在某个网络里被暂停着。
    pub(crate) fn is_paused(&self, version: &Version) -> bool {
        self.paused.iter().any(|paused| paused.version == *version)
    }

    /// 这个版本在 `network` 里的自动更新是不是被暂停了。
    pub(crate) fn is_paused_in(&self, version: &Version, network: NetworkId) -> bool {
        self.paused.iter().any(|paused| paused.version == *version && paused.network == network)
    }

    /// 一个节点不存在了。
    pub(super) fn forget(&mut self, node: NodeId) {
        self.forced.remove(&node);
        self.offered.remove(&node);
        self.relay_turns.retain(|_, turn| turn.holder != node);
    }

    /// 当前发布里 `platform` 的包在缓存里的位置；还没有取回来时是 `None`。
    pub(crate) fn cached_package(&self, version: &Version, platform: &str) -> Option<(&Path, &Artifact)> {
        let release = self.release.as_ref().filter(|release| release.manifest.version == *version)?;
        match self.packages.get(platform) {
            Some(Package::Cached(path)) => Some((path, release.manifest.artifacts.get(platform)?)),
            Some(Package::Wanted | Package::Fetching | Package::Failed(_)) | None => None,
        }
    }
}

/// 一次要做的取包。
struct FetchJob {
    source: Result<Source, ReleaseFailure>,
    cache_dir: Option<PathBuf>,
    version: Version,
    platform: String,
    artifact: Artifact,
}

impl Controller {
    /// controller 自己的版本。可执行文件用它报上自己的版本号：发布清单里的"需要的 controller 最低版本"和它比。
    /// 不设时是这个库的版本。
    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.inner_mut().updates.version = version;
        self
    }

    /// 取回来的包缓存在哪个目录。不设的话取不了包，也就下发不了更新。
    #[must_use]
    pub fn with_release_cache(mut self, dir: PathBuf) -> Self {
        self.inner_mut().updates.cache_dir = Some(dir);
        self
    }

    /// 换一组 controller 认的发布公钥。默认是编译在程序里的那些；测试用这个入口换成自己的。
    ///
    /// 节点不受它影响：节点只认编译在节点程序里的公钥，controller 认了一份节点不认的清单，节点照样不装。
    ///
    /// # Errors
    ///
    /// 读存储失败。
    pub fn with_release_keys(mut self, keys: TrustedKeys) -> Result<Self, Error> {
        let inner = self.inner_mut();
        inner.updates.keys = keys;
        inner.updates.load_release(&inner.store)?;
        Ok(self)
    }

    /// 更新的设置和现状。
    ///
    /// # Errors
    ///
    /// 读存储失败。
    pub fn update_overview(&self) -> Result<UpdateOverview, Error> {
        self.lock().update_overview()
    }

    /// 改更新的设置：自动更新的开关、发布源。发布源变了的话后台会马上去查一次。
    ///
    /// # Errors
    ///
    /// 发布源的写法不对，或者写存储失败。
    pub fn set_update_settings(&self, request: &UpdateSettings) -> Result<UpdateOverview, Error> {
        let source = match &request.source {
            None => None,
            Some(None) => Some(None),
            Some(Some(text)) => {
                let source: Source =
                    text.parse().map_err(|error: release::InvalidSource| Error::invalid_field("source", "malformed", error.to_string()))?;
                let text = source.to_string();
                Some((text != DEFAULT_SOURCE).then_some(text))
            }
        };
        let mut inner = self.lock();
        let before = inner.updates.settings.clone();
        let mut after = before.clone();
        let mut rolled = Ok(());
        after.auto_update = request.auto_update.unwrap_or(before.auto_update);
        after.source = source.unwrap_or_else(|| before.source.clone());
        if after != before {
            let now = inner.clock.now();
            write_meta(&inner.store, SETTINGS_META, &after)?;
            let source = after.source.as_deref().unwrap_or(DEFAULT_SOURCE);
            let detail = format!("自动更新 {}，发布源 {source}", if after.auto_update { "开" } else { "关" });
            let params = json!({ "auto_update": after.auto_update, "source": source, "source_is_default": after.source.is_none() });
            inner.store.log(now, None, action::UPDATE_SETTINGS, &detail, params)?;
            tracing::info!(auto_update = after.auto_update, source = after.source.as_deref().unwrap_or(DEFAULT_SOURCE), "更新的设置变了");
            let source_changed = after.source != before.source;
            inner.updates.settings = after;
            if source_changed {
                inner.updates.check_requested = true;
                inner.updates.check_error = None;
                self.check_wake.notify_one();
            }
            rolled = inner.roll_out();
        }
        // 下发没做完也要叫醒后台任务：它排了重试，要后台任务到点来做（下面几个入口一样）。
        self.wake_if_needed(&inner);
        rolled?;
        inner.update_overview()
    }

    /// 查一次发布源，返回查完之后的现状。查不到、验不过都不是这个函数的错误：原因写在
    /// [`UpdateOverview::check_error`] 里，已知的发布保持上一次查到的。
    ///
    /// 这个调用要走网络，会阻塞到查完或者超时，期间不拿 controller 的锁。
    ///
    /// # Errors
    ///
    /// 读写存储失败。
    pub fn check_release(&self) -> Result<UpdateOverview, Error> {
        let (source_text, keys) = {
            let mut inner = self.lock();
            inner.updates.check_requested = false;
            (inner.updates.source_text().to_owned(), inner.updates.keys.clone())
        };
        let checked = check(&source_text, &keys);
        let mut inner = self.lock();
        let finished = if inner.updates.source_text() == source_text {
            inner.check_finished(&source_text, checked)
        } else {
            tracing::info!(source = %source_text, "查的时候发布源被改了，这次的结果不要");
            Ok(())
        };
        self.wake_if_needed(&inner);
        finished?;
        inner.update_overview()
    }

    /// 设置变了之后有没有要求尽快查一次发布源。后台任务用它决定要不要提前查。
    #[must_use]
    pub fn release_check_requested(&self) -> bool {
        self.lock().updates.check_requested
    }

    /// 等到设置变了、要尽快重新查发布源。
    pub async fn wait_for_check_request(&self) {
        self.check_wake.notified().await;
    }

    /// 把有节点要用、还没有取回来的包都取回来，一次一个。阻塞到取完，期间不拿 controller 的锁。
    ///
    /// # Errors
    ///
    /// 读写存储失败。取包本身的失败不在这里：原因记在那个平台的包上，下次查发布源时再试。
    pub fn fetch_packages(&self) -> Result<(), Error> {
        loop {
            let Some(job) = self.lock().next_fetch() else { return Ok(()) };
            let outcome = job.run();
            let mut inner = self.lock();
            let finished = inner.fetch_finished(&job, outcome);
            // 出错时也要叫醒：还有别的平台的包排着的话，取包的任务等的就是这一声。
            self.wake_if_needed(&inner);
            finished?;
        }
    }

    /// 等到有包要取。
    pub async fn wait_for_wanted_packages(&self) {
        self.release_wake.notified().await;
    }

    /// 继续一个被暂停的版本的自动更新，所有网络里的都继续。失败过的那些节点仍然不会被自动更新到这个版本。
    ///
    /// # Errors
    ///
    /// 这个版本没有被暂停。
    pub fn resume_update(&self, version: &Version) -> Result<UpdateOverview, Error> {
        let mut inner = self.lock();
        if !inner.updates.is_paused(version) {
            return Err(Error::NotFound(Entity::PausedVersion));
        }
        inner.updates.paused.retain(|paused| paused.version != *version);
        let now = inner.clock.now();
        write_meta(&inner.store, PAUSED_META, &inner.updates.paused)?;
        inner.store.log(now, None, action::UPDATE_RESUME, &format!("继续版本 {version} 的自动更新"), json!({ "version": version }))?;
        tracing::info!(%version, "管理员继续了这个版本的自动更新");
        let rolled = inner.roll_out();
        self.wake_if_needed(&inner);
        rolled?;
        inner.update_overview()
    }

    /// 一个节点的更新情况。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个节点。
    pub fn node_update(&self, network: NetworkId, id: NodeId) -> Result<NodeUpdate, Error> {
        let inner = self.lock();
        Ok(inner.node_update(&inner.require_node(network, id)?))
    }

    /// 让一个节点立即更新到已知的最新版，不管自动更新开没开、这个版本有没有被暂停。
    ///
    /// # Errors
    ///
    /// `timing` 不是强制的时机；节点不在线、不能自己更新，或者没有可以更新到的版本。
    pub fn force_update(&self, network: NetworkId, id: NodeId, timing: UpdateTiming) -> Result<NodeUpdate, Error> {
        require_forced(timing)?;
        let mut inner = self.lock();
        let node = inner.require_node(network, id)?;
        if let Some(blocked) = inner.cannot_force(&node) {
            return Err(blocked.error);
        }
        // 管理员明说了要再试一次，上一次的失败就不再算数。这样它要是又失败了，会被当成新的失败重新告警。
        let node = inner.forget_update_failure(node)?;
        inner.updates.forced.insert(id, Forced { timing, skips_relay_queue: true });
        let now = inner.clock.now();
        inner.store.log_refs(
            now,
            Some(network),
            action::UPDATE_FORCE,
            &format!("让节点 {} 立即更新（{}）", node.name, describe_timing(timing)),
            &[LogRef::node(node.id)],
            json!({ "node": node.id, "node_name": node.name, "timing": timing }),
        )?;
        tracing::info!(node = %id, name = %node.name, ?timing, "管理员让这个节点立即更新");
        let rolled = inner.roll_out();
        self.wake_if_needed(&inner);
        rolled?;
        Ok(inner.node_update(&node))
    }

    /// 让全部网络里所有能更新的节点立即更新。relay 仍然一个一个来。
    ///
    /// # Errors
    ///
    /// `timing` 不是强制的时机，或者读写存储失败。
    pub fn force_update_all(&self, timing: UpdateTiming) -> Result<ForcedUpdates, Error> {
        require_forced(timing)?;
        let mut inner = self.lock();
        let mut outcome = ForcedUpdates {
            version: inner.updates.usable_release().map(|release| release.manifest.version.clone()),
            ..ForcedUpdates::default()
        };
        let mut accepted = Vec::new();
        for network in inner.store.networks()? {
            for node in inner.store.nodes(network.id)? {
                match inner.cannot_force(&node) {
                    Some(Blocked { cause, error }) => {
                        outcome.skipped.push(SkippedUpdate { node: node.to_ref(), reason: error.to_string(), cause: Some(cause) });
                    }
                    None => {
                        let node = inner.forget_update_failure(node)?;
                        // 已经单独点过"立即更新"的节点保持它不排队的待遇。
                        let skips_relay_queue = inner.updates.forced.get(&node.id).is_some_and(|forced| forced.skips_relay_queue);
                        inner.updates.forced.insert(node.id, Forced { timing, skips_relay_queue });
                        accepted.push(node);
                    }
                }
            }
        }
        let now = inner.clock.now();
        let detail = format!("让全部节点立即更新（{}）：{} 个节点", describe_timing(timing), accepted.len());
        let params = json!({ "timing": timing, "nodes": accepted.len(), "skipped": outcome.skipped.len() });
        inner.store.log(now, None, action::UPDATE_FORCE_ALL, &detail, params)?;
        tracing::info!(?timing, nodes = accepted.len(), skipped = outcome.skipped.len(), "管理员让全部节点立即更新");
        let rolled = inner.roll_out();
        self.wake_if_needed(&inner);
        rolled?;
        for node in &accepted {
            let ordered = inner.live.get(&node.id).and_then(|live| live.order.as_ref()).is_some_and(|order| order.timing == timing);
            if ordered { outcome.ordered.push(node.to_ref()) } else { outcome.queued.push(node.to_ref()) }
        }
        Ok(outcome)
    }
}

fn require_forced(timing: UpdateTiming) -> Result<(), Error> {
    if timing.is_forced() {
        Ok(())
    } else {
        Err(Error::invalid_field("timing", "not_allowed", "立即更新的时机要写 now 或者 after_drain；idle 是自动更新用的"))
    }
}

fn describe_timing(timing: UpdateTiming) -> &'static str {
    match timing {
        UpdateTiming::Idle => "空闲时",
        UpdateTiming::Now => "立刻",
        UpdateTiming::AfterDrain => "排空后",
    }
}

/// 取清单并验签。
fn check(source_text: &str, keys: &TrustedKeys) -> Result<Release, ReleaseFailure> {
    let source: Source = source_text.parse().map_err(|error| ReleaseFailure::invalid_source(&error))?;
    let signed = source.latest().map_err(|error| ReleaseFailure::fetch(&error))?;
    // 验过签才看里面的内容：发布源和镜像都不需要可信。
    let manifest = keys.verify(&signed).map_err(|error| {
        let cause = match &error {
            i3t_update::ManifestError::BadSignature => ReleaseCause::BadSignature,
            i3t_update::ManifestError::Malformed(_) => ReleaseCause::BadManifest,
        };
        ReleaseFailure { reason: format!("发布源给的清单不能用：{}", error_chain(&error)), cause }
    })?;
    if manifest.is_prerelease() {
        return Err(ReleaseFailure {
            reason: format!("发布源的最新版是预发布版 {}，不取", manifest.version),
            cause: ReleaseCause::Prerelease { version: manifest.version },
        });
    }
    Ok(Release { signed, manifest })
}

impl FetchJob {
    fn run(&self) -> Result<PathBuf, ReleaseFailure> {
        let source = self.source.as_ref().map_err(Clone::clone)?;
        let cache_dir =
            self.cache_dir.as_deref().ok_or_else(|| ReleaseFailure {
                reason: "这个 controller 没有配置放包的缓存目录".to_owned(),
                cause: ReleaseCause::Internal,
            })?;
        source.fetch(&self.version, &self.artifact, cache_dir).map_err(|error| ReleaseFailure::fetch(&error))
    }
}

impl Inner {
    /// 记下一次查发布源的结果。
    fn check_finished(&mut self, source: &str, checked: Result<Release, ReleaseFailure>) -> Result<(), Error> {
        let now = self.clock.now();
        self.updates.checked_at = Some(now);
        self.counters.release_checks += 1;
        match checked {
            Ok(release) => {
                self.updates.check_error = None;
                let version = release.manifest.version.clone();
                if self.updates.release.as_ref() == Some(&release) {
                    tracing::debug!(%version, source, "查了发布源，最新的正式版没有变");
                } else {
                    let security_floor = release.manifest.security_floor.as_ref().map(ToString::to_string);
                    tracing::info!(
                        %version,
                        min_controller = %release.manifest.min_controller,
                        security_floor = security_floor.as_deref().unwrap_or("-"),
                        source,
                        "发布源上有新的正式版"
                    );
                    self.store.log(
                        now,
                        None,
                        action::UPDATE_RELEASE,
                        &format!("发布源上最新的正式版是 {version}"),
                        json!({ "version": version }),
                    )?;
                    self.updates.release = Some(release.clone());
                    self.updates.packages.clear();
                    // 只有当前的发布会被暂停，别的版本的下发记录用不上了。
                    self.updates.offered.retain(|_, offered| *offered == version);
                    if let Some(cache_dir) = &self.updates.cache_dir {
                        release::prune_cache(cache_dir, &version);
                    }
                }
                write_meta(&self.store, RELEASE_META, &StoredRelease { signed: release.signed, checked_at: now })?;
                if release.manifest.min_controller > self.updates.version {
                    tracing::warn!(
                        %version,
                        needs = %release.manifest.min_controller,
                        controller = %self.updates.version,
                        "这个版本的节点需要更新的 controller，先更新 controller 才会下发"
                    );
                }
                // 每查一次就把上次没成的事再试一遍：没取成的包，和没装成（不怪版本）的节点。
                self.updates.packages.retain(|_, package| !matches!(package, Package::Failed(_)));
                for live in self.live.values_mut() {
                    if live.order.as_ref().is_some_and(|order| order.failed) {
                        live.order = None;
                    }
                }
            }
            Err(failure) => {
                self.counters.release_check_failures += 1;
                tracing::warn!(source, reason = %failure.reason, "查发布源没有成功，已知的发布保持不变");
                self.updates.check_error = Some(failure);
            }
        }
        self.roll_out()
    }

    /// 挑一个排着队的包去取，并把它标成正在取。
    fn next_fetch(&mut self) -> Option<FetchJob> {
        let release = self.updates.release.as_ref()?;
        let platform =
            self.updates.packages.iter().find(|(_, package)| **package == Package::Wanted).map(|(platform, _)| platform.clone())?;
        let artifact = release.manifest.artifacts.get(&platform).cloned();
        let version = release.manifest.version.clone();
        let Some(artifact) = artifact else {
            // 想要的平台清单里没有：不会走到这里，要用它的节点在选的时候就被排除了。
            self.updates.packages.remove(&platform);
            return self.next_fetch();
        };
        self.updates.packages.insert(platform.clone(), Package::Fetching);
        let source = self.updates.source_text().parse::<Source>().map_err(|error| ReleaseFailure::invalid_source(&error));
        tracing::info!(%version, %platform, file = %artifact.file, size = artifact.size, "从发布源取这个平台的包");
        Some(FetchJob { source, cache_dir: self.updates.cache_dir.clone(), version, platform, artifact })
    }

    fn fetch_finished(&mut self, job: &FetchJob, outcome: Result<PathBuf, ReleaseFailure>) -> Result<(), Error> {
        // 取的时候发布换了：这个包已经没有人要了。
        if self.updates.release.as_ref().is_none_or(|release| release.manifest.version != job.version) {
            return Ok(());
        }
        let package = match outcome {
            Ok(path) => {
                tracing::info!(version = %job.version, platform = %job.platform, path = %path.display(), "包已经取回来并且核对过");
                Package::Cached(path)
            }
            Err(failure) => {
                tracing::warn!(version = %job.version, platform = %job.platform, reason = %failure.reason, "包没有取成，下次查发布源时再试");
                Package::Failed(failure)
            }
        };
        self.updates.packages.insert(job.platform.clone(), package);
        self.roll_out()
    }

    /// 节点报了它的更新进度。
    pub(super) fn update_reported(&mut self, node: &NodeRecord, status: UpdateStatus) -> Result<(), Error> {
        let Some(live) = self.live.get_mut(&node.id) else { return Ok(()) };
        if live.update.as_ref() == Some(&status) {
            return Ok(());
        }
        let first_report = live.update.is_none();
        // 日志里用它在 JSON 里的写法：和管理 API 里看到的一样，也比 Debug 的写法短。
        let described = serde_json::to_string(&status)?;
        match &status {
            UpdateStatus::Idle | UpdateStatus::Downloading { .. } => {
                tracing::debug!(node = %node.id, name = %node.name, status = %described, "节点的更新进度")
            }
            UpdateStatus::Verifying { .. }
            | UpdateStatus::SelfCheck { .. }
            | UpdateStatus::WaitingForIdle { .. }
            | UpdateStatus::Draining { .. }
            | UpdateStatus::Installing { .. }
            | UpdateStatus::Restarting { .. }
            | UpdateStatus::Confirmed { .. }
            | UpdateStatus::Failed { .. }
            | UpdateStatus::Unknown => tracing::info!(node = %node.id, name = %node.name, status = %described, "节点的更新进度变了"),
        }
        live.update = Some(status.clone());
        let UpdateStatus::Failed { version, kind, reason, cause } = status else {
            // 这次连接上的第一次上报：现在知道它是带着什么回来的，可以轮到它了。之后的进度变化不改变该让谁更新。
            return if first_report { self.roll_out() } else { Ok(()) };
        };
        match (kind, version) {
            (FailureKind::VersionRejected, Some(version)) => self.version_rejected(node, &version, &reason, cause)?,
            // 连是哪个版本都没有说的失败，没法记到某个版本头上，和没装成一样对待。
            (FailureKind::VersionRejected, None) | (FailureKind::NotInstalled, _) => {
                self.order_failed(node.id, None);
                tracing::warn!(node = %node.id, name = %node.name, %reason, "节点没有装成这个版本（不怪版本），下次查发布源时再试");
            }
        }
        self.roll_out()
    }

    /// 节点说某个版本在它那台机器上不能用：记在它头上；信得过的话，暂停这个版本在它所在网络里的自动更新。
    ///
    /// 一个节点的一句话影响不了别的网络，也不能一再生效：
    ///
    /// - controller 这次运行以来确实让它装过这个版本，它的失败才暂停自动更新。没让它装过的节点说什么都只记在它自己头上，
    ///   另记一条操作记录给管理员看；
    /// - 暂停只在它所在的网络生效，别的网络照常更新；
    /// - 同一个节点在同一个版本上只失败一次：记录在 controller 上，节点自报的版本号清不掉，管理员点"立即更新"才清。
    ///   所以管理员继续之后，同一个节点不能把这个版本再暂停一次。
    fn version_rejected(&mut self, node: &NodeRecord, version: &Version, reason: &str, cause: Option<UpdateCause>) -> Result<(), Error> {
        self.order_failed(node.id, Some(version));
        // 节点每次上报都带着同一条失败，重启之后也还带着。记过的就不是新闻，不能因此把管理员已经继续的版本再暂停一次。
        let already_recorded =
            node.update_failure.as_ref().is_some_and(|failure| failure.version == *version && failure.kind == FailureKind::VersionRejected);
        if already_recorded {
            return Ok(());
        }
        let now = self.clock.now();
        let failure = UpdateFailure {
            version: version.clone(),
            kind: FailureKind::VersionRejected,
            reason: reason.to_owned(),
            at: now,
            cause: cause.clone(),
        };
        self.store.set_node_update_failure(node.id, Some(&failure))?;
        self.counters.version_failures += 1;
        tracing::warn!(node = %node.id, name = %node.name, %version, %reason, "节点说这个版本在它那里不能用，以后不再自动让它装这个版本");

        let params = json!({ "node": node.id, "node_name": node.name, "version": version, "reason": reason, "cause": cause });
        let offered = self.updates.offered.get(&node.id) == Some(version);
        if !offered {
            tracing::warn!(node = %node.id, name = %node.name, %version, "controller 没有让这个节点装过这个版本，它的失败不暂停自动更新");
            let detail =
                format!("节点 {} 说版本 {version} 在它那里不能用（{reason}）；controller 没有让它装过这个版本，不因此暂停", node.name);
            self.store.log_refs(now, Some(node.network), action::UPDATE_FAILURE, &detail, &[LogRef::node(node.id)], params)?;
            return Ok(());
        }
        self.updates.offered.remove(&node.id);
        let is_current = self.updates.release.as_ref().is_some_and(|release| release.manifest.version == *version);
        if is_current && !self.updates.is_paused_in(version, node.network) {
            self.updates.paused.push(Paused {
                version: version.clone(),
                node: node.id,
                network: node.network,
                reason: reason.to_owned(),
                at: now,
                cause,
            });
            write_meta(&self.store, PAUSED_META, &self.updates.paused)?;
            let detail = format!("节点 {} 更新到 {version} 失败（{reason}），暂停这个版本在这个网络里的自动更新", node.name);
            self.store.log_refs(now, Some(node.network), action::UPDATE_PAUSE, &detail, &[LogRef::node(node.id)], params)?;
            tracing::warn!(%version, node = %node.id, network = %node.network, "暂停这个版本在这个网络里的自动更新，等管理员看过之后继续");
        }
        Ok(())
    }

    /// 这次连接上发给节点的指令没有成：记下来，不在同一条连接上反复重发；强制的更新到此为止。
    fn order_failed(&mut self, node: NodeId, version: Option<&Version>) {
        if let Some(order) = self.live.get_mut(&node).and_then(|live| live.order.as_mut())
            && version.is_none_or(|version| order.version == *version)
        {
            order.failed = true;
        }
        self.updates.forced.remove(&node);
    }

    /// 清掉节点头上的失败记录，返回清过之后的节点。
    pub(super) fn forget_update_failure(&mut self, mut node: NodeRecord) -> Result<NodeRecord, Error> {
        if node.update_failure.take().is_some() {
            self.store.set_node_update_failure(node.id, None)?;
        }
        Ok(node)
    }

    /// 为什么不能让这个节点立即更新；可以的话是 `None`。
    fn cannot_force(&self, node: &NodeRecord) -> Option<Blocked> {
        let name = || node.name.clone();
        let Some(live) = self.live.get(&node.id) else {
            return Some(Blocked { cause: SkipCause::Offline, error: Error::NodeOffline(name()) });
        };
        let cannot = |cause: SkipCause, reason: String| Blocked {
            error: Error::CannotSelfUpdate { node: name(), reason, cause: Box::new(cause.clone()) },
            cause,
        };
        let Some(ability) = node.self_update.filter(|_| live.understands_updates()) else {
            return Some(cannot(SkipCause::TooOld, "它的版本太旧，不懂更新，要手动换程序".to_owned()));
        };
        if !ability.able {
            let reason = ability.blocker.map_or_else(|| "节点说它不能自己更新".to_owned(), |blocker| blocker.to_string());
            return Some(cannot(SkipCause::CannotSelfUpdate { blocker: ability.blocker }, reason));
        }
        let (cause, message) = self.unavailable_reason(node)?;
        Some(Blocked { error: Error::NoUpdate { message, cause: Box::new(cause.clone()) }, cause })
    }

    /// 为什么没有可以让这个节点更新到的版本：原因的代码和给人看的一句话；有的话是 `None`。
    fn unavailable_reason(&self, node: &NodeRecord) -> Option<(SkipCause, String)> {
        let Some(release) = &self.updates.release else {
            return Some((SkipCause::NoRelease, "还没有从发布源查到任何发布".to_owned()));
        };
        let manifest = &release.manifest;
        if manifest.min_controller > self.updates.version {
            let message = format!(
                "最新的发布 {} 需要 controller 至少是 {}，现在是 {}。先更新 controller",
                manifest.version, manifest.min_controller, self.updates.version
            );
            let cause = SkipCause::ControllerTooOld {
                version: manifest.version.clone(),
                min_controller: manifest.min_controller.clone(),
                controller: self.updates.version.clone(),
            };
            return Some((cause, message));
        }
        let Ok(running) = node.version.parse::<Version>() else {
            let message = format!("节点 {} 报的版本号 {:?} 看不懂", node.name, node.version);
            return Some((SkipCause::UnreadableVersion { version: node.version.clone() }, message));
        };
        if running >= manifest.version {
            let message = format!("节点 {} 已经是 {running}，不比最新的发布 {} 旧", node.name, manifest.version);
            return Some((SkipCause::UpToDate { running, latest: manifest.version.clone() }, message));
        }
        let has_package = node.platform.parse::<Platform>().is_ok_and(|platform| manifest.artifact(&platform).is_some());
        (!has_package).then(|| {
            let message = format!("发布 {} 里没有 {} 平台的包", manifest.version, node.platform);
            (SkipCause::NoPackage { version: manifest.version.clone(), platform: node.platform.clone() }, message)
        })
    }

    /// 管理 API 里一个节点的更新情况。
    pub(crate) fn node_update(&self, node: &NodeRecord) -> NodeUpdate {
        let plan = self.plan(node);
        let live = self.live.get(&node.id);
        let order = live.and_then(|live| live.order.as_ref()).filter(|order| !order.failed);
        NodeUpdate {
            self_update: node.self_update,
            available: plan.available,
            status: live.and_then(|live| live.update.clone()).unwrap_or_default(),
            ordered: order.map(|order| UpdateOrder { version: order.version.clone(), timing: order.timing }),
            waiting: plan.waiting,
            // 节点已经在跑失败过的那个版本（或者更新的）了，多半是手动换的程序：那条失败不再值得显示。记录本身留着，见 `apply_hello`。
            failure: node
                .update_failure
                .clone()
                .filter(|failure| !node.version.parse::<Version>().is_ok_and(|running| running >= failure.version)),
            security: self.below_security_floor(node),
        }
    }

    /// 节点在跑的版本比已知的最新发布写的安全下限旧。看的是已知的发布，不管 controller 够不够新、它有没有这个平台的包：
    /// 这是告诉人的，人可以手动更新。版本号看不懂时说不上来，算 `false`。
    fn below_security_floor(&self, node: &NodeRecord) -> bool {
        let Some(release) = &self.updates.release else { return false };
        node.version.parse::<Version>().is_ok_and(|running| release.manifest.is_below_security_floor(&running))
    }

    pub(super) fn update_overview(&self) -> Result<UpdateOverview, Error> {
        let updates = &self.updates;
        let release = updates.release.as_ref().map(|release| {
            let manifest = &release.manifest;
            let packages = manifest.artifacts.iter().map(|(platform, artifact)| {
                let (state, failure) = match updates.packages.get(platform) {
                    None => (PackageState::NotNeeded, None),
                    Some(Package::Wanted | Package::Fetching) => (PackageState::Fetching, None),
                    Some(Package::Cached(_)) => (PackageState::Cached, None),
                    Some(Package::Failed(failure)) => (PackageState::Failed, Some(failure.clone())),
                };
                let (error, cause) = failure.map(|failure| (failure.reason, failure.cause)).unzip();
                PackageInfo { platform: platform.clone(), file: artifact.file.clone(), size: artifact.size, state, error, cause }
            });
            ReleaseInfo {
                version: manifest.version.clone(),
                published: manifest.published,
                min_controller: manifest.min_controller.clone(),
                controller_too_old: manifest.min_controller > updates.version,
                newer_than_controller: manifest.version > updates.version,
                packages: packages.collect(),
                security_floor: manifest.security_floor.clone(),
            }
        });
        let mut counts = UpdateCounts::default();
        for network in self.store.networks()? {
            for node in self.store.nodes(network.id)? {
                let update = self.node_update(&node);
                counts.total += 1;
                let failed_this = update.failure.as_ref().map(|failure| &failure.version) == update.available.as_ref();
                let slot = match &update {
                    NodeUpdate { ordered: Some(_), .. } => &mut counts.updating,
                    NodeUpdate { available: None, .. } => &mut counts.up_to_date,
                    NodeUpdate { .. } if failed_this => &mut counts.failed,
                    NodeUpdate { self_update, .. } if !self_update.is_some_and(|ability| ability.able) => &mut counts.manual,
                    NodeUpdate { .. } => &mut counts.outdated,
                };
                *slot += 1;
            }
        }
        let paused = updates.paused.iter().map(|paused| {
            Ok(PausedVersion {
                version: paused.version.clone(),
                node: self.store.node(paused.node)?.as_ref().map(NodeRecord::to_ref),
                network: Some(paused.network),
                reason: paused.reason.clone(),
                at: paused.at,
                cause: paused.cause.clone(),
            })
        });
        Ok(UpdateOverview {
            auto_update: updates.settings.auto_update,
            source: updates.source_text().to_owned(),
            source_is_default: updates.settings.source.is_none(),
            controller_version: updates.version.clone(),
            release,
            checked_at: updates.checked_at,
            check_error: updates.check_error.as_ref().map(|failure| failure.reason.clone()),
            check_cause: updates.check_error.as_ref().map(|failure| failure.cause.clone()),
            paused: paused.collect::<Result<_, Error>>()?,
            nodes: counts,
        })
    }
}

fn read_meta<T: serde::de::DeserializeOwned>(store: &Store, key: &str) -> Result<Option<T>, Error> {
    let Some(bytes) = store.meta(key)? else { return Ok(None) };
    match serde_json::from_slice(&bytes) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            // 多半是更新版本的程序写的。按没有处理：这些都是可以重新查、重新设的东西，不值得为此启动不了。
            tracing::warn!(key, %error, "数据库里的这项更新设置读不懂，按没有处理");
            Ok(None)
        }
    }
}

fn write_meta<T: Serialize>(store: &Store, key: &str, value: &T) -> Result<(), Error> {
    Ok(store.set_meta(key, &serde_json::to_vec(value)?)?)
}
