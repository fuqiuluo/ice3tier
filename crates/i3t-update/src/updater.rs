//! 串联验签、下载、自检、安装、确认与回滚的完整更新流程。

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex as StdMutex, MutexGuard};
use std::time::Duration;

use i3t_model::update::{
    Artifact, FailureKind, Manifest, Platform, SelfUpdateBlocker, SignedManifest, UpdateCause, UpdateStatus, UpdateTiming, Version,
};
use tokio::sync::{Mutex, watch};

use crate::digest::FileDigest;
use crate::download::Download;
use crate::error::{Refusal, UpdateError, describe};
use crate::program::{ProgramFiles, Swap};
use crate::self_check;
use crate::source::PackageSource;
use crate::state::{self, FailedVersion, Pending, State, StateFile};
use crate::timing;
use crate::trust::TrustedKeys;

/// 新版本安装后的最大未确认启动次数；达到该上限仍未能连接 controller 时，下次启动将回滚至旧版本。
pub const MAX_UNCONFIRMED_STARTS: u32 = 3;

/// 新版本安装后的确认等待窗口；超过该时长仍未能连接 controller 时将回滚至旧版本。
pub const CONFIRMATION_WINDOW: Duration = Duration::from_secs(5 * 60);

/// 可执行文件替换完成后，进程以该退出码退出，由外部进程管理器拉起新进程。
///
/// 该值对应 sysexits 中的 `EX_TEMPFAIL`（临时故障，请重试）。项目附带的 systemd 单元配置为 `Restart=always`，
/// 任意退出码都会触发重启；使用独立退出码便于日志与守护进程区分“请求重启”与“异常退出”。
pub const RESTART_EXIT_CODE: u8 = 75;

/// 状态目录下用于存放更新文件的子目录。
const UPDATE_DIR: &str = "update";

/// 更新目录中暂存包的文件名前缀，完整名称为 `staged-<SHA-256>.bin`。包含摘要可确保断点续传对应同一更新包。
const STAGED_PREFIX: &str = "staged-";

/// 构造 [`Updater`] 所需的配置。
#[derive(Debug, Clone)]
pub struct UpdaterConfig {
    /// 当前运行的可执行文件路径，来自 [`current_program`](crate::current_program)。
    pub program: PathBuf,
    /// 节点状态目录。更新模块仅使用其下的 `update/` 子目录。
    pub state_dir: PathBuf,
    /// 当前运行的版本号。
    pub running: Version,
    /// 启动新版本执行自检时传递的命令行参数，通常为 `["--state-dir", <状态目录>, "self-check"]`。约定见 [`mod@self_check`]。
    pub self_check_args: Vec<OsString>,
    /// 当前节点无法自动更新的原因，来自 [`self_update_blocker`](crate::self_update_blocker)。非 `None` 时将拒绝所有发布清单。
    pub blocker: Option<SelfUpdateBlocker>,
}

/// 通过校验、可供下载的发布清单中与本节点相关的信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub version: Version,
    /// 适用于当前平台的节点可执行文件元数据。
    pub artifact: Artifact,
}

/// 已完成下载、完整性校验与自检的新版本候选程序，已放置于主程序同目录等待安装。
#[derive(Debug)]
#[must_use = "新版本仅已完成准备，需调用 Updater::install 才会执行安装"]
pub struct Prepared {
    version: Version,
    artifact: Artifact,
}

impl Prepared {
    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }
}

/// 可执行文件已完成替换，调用方应重启进程：以 [`RESTART_EXIT_CODE`] 退出，或自行重新拉起进程。
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "可执行文件已替换，未重启前仍将继续运行旧版本"]
pub struct RestartRequired {
    /// 重启后将运行的版本。
    pub version: Version,
}

/// 未完成确认的新版本已回滚至旧版本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolledBack {
    /// 被回滚的新版本。该版本已记录为在当前主机更新失败。
    pub failed: Version,
    pub reason: String,
    pub restart: RestartRequired,
}

/// 启动阶段更新状态检查结果，由 [`Updater::startup`] 返回。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// 无待确认更新，正常启动。
    Clean,
    /// 当前运行的是刚安装且尚未确认的新版本。应继续正常启动；连接上 controller 后调用 [`Updater::confirm`]，
    /// 同时在后台运行 [`Updater::enforce_confirmation_deadline`]。
    AwaitingConfirmation { version: Version },
    /// 当前运行的是刚安装的新版本，但一直未能连接 controller，已回滚至旧版本。不应继续启动，应按 [`RolledBack::restart`] 重启。
    RolledBack(RolledBack),
}

/// 节点更新器。单个进程创建一个实例，生命周期贯穿启动至退出。
///
/// 一次完整更新分为三步，可分段调用，也可通过 [`Updater::update`] 连续执行：
///
/// 1. [`prepare`](Self::prepare)：验签、下载、完整性校验与自检。不修改当前运行的程序，可随时取消。
/// 2. [`wait_for_slot`](Self::wait_for_slot)：等待 controller 指定的安装时机。
/// 3. [`install`](Self::install)：替换可执行文件、保留旧版本备份，并通知调用方重启。
///
/// 重启后的新进程应先调用 [`startup`](Self::startup)，连接上 controller 后再调用 [`confirm`](Self::confirm)。
///
/// 发布清单仅使用编译内置的公钥验签（[`TrustedKeys::compiled_in`]），不提供运行时替换公钥的入口。
#[derive(Debug)]
pub struct Updater {
    files: ProgramFiles,
    update_dir: PathBuf,
    state: StateFile,
    running: Version,
    platform: Platform,
    keys: TrustedKeys,
    self_check_args: Vec<OsString>,
    blocker: Option<SelfUpdateBlocker>,
    status: watch::Sender<UpdateStatus>,
    /// 同一时刻仅允许准备一个新版本：暂存文件与候选可执行文件均只有一份。
    preparing: Mutex<()>,
    /// 串行化“读取状态—替换文件—写入状态”临界区。确认更新与超时回滚可能并发发生，
    /// 若无互斥保护，可能出现程序已回滚但状态记录仍写入已确认的竞态。
    transition: StdMutex<()>,
}

impl Updater {
    #[must_use]
    pub fn new(config: UpdaterConfig) -> Self {
        Self::assemble(config, TrustedKeys::compiled_in(), Swap::NATIVE)
    }

    /// 供 crate 内部测试注入自定义公钥与替换策略的构造入口。
    fn assemble(config: UpdaterConfig, keys: TrustedKeys, swap: Swap) -> Self {
        let update_dir = config.state_dir.join(UPDATE_DIR);
        Self {
            files: ProgramFiles::new(config.program, swap),
            state: StateFile::new(&update_dir),
            update_dir,
            running: config.running,
            platform: Platform::current(),
            keys,
            self_check_args: config.self_check_args,
            blocker: config.blocker,
            status: watch::Sender::new(UpdateStatus::Idle),
            preparing: Mutex::new(()),
            transition: StdMutex::new(()),
        }
    }

    fn transition(&self) -> MutexGuard<'_, ()> {
        self.transition.lock().expect("transition mutex poisoned")
    }

    /// 订阅当前更新状态。调用方应将每次状态变更上报给 controller。
    ///
    /// 观察到 [`UpdateStatus::Draining`] 时，调用方应停止接受新流，直至进程重启。
    #[must_use]
    pub fn status(&self) -> watch::Receiver<UpdateStatus> {
        self.status.subscribe()
    }

    /// 返回当前主机历史上更新失败、不再自动重试的版本列表。
    ///
    /// # Errors
    ///
    /// 无法读取或解析更新状态文件时返回错误。
    pub fn failures(&self) -> Result<Vec<FailedVersion>, UpdateError> {
        Ok(self.state.load()?.failed)
    }

    /// 进程启动时在连接 controller 之前调用一次。
    ///
    /// 若存在待确认更新则递增启动计数；若已启动 [`MAX_UNCONFIRMED_STARTS`] 次，或安装至今已超过
    /// [`CONFIRMATION_WINDOW`]，则回滚至旧版本并将该版本记录为失败。
    ///
    /// 局限说明：若新版本在执行到此函数前即崩溃，无法自动触发回滚；此类故障依赖安装前的自检阶段拦截。
    ///
    /// # Errors
    ///
    /// 加载或保存更新状态失败，或回滚到上一版本失败。
    pub fn startup(&self) -> Result<Startup, UpdateError> {
        let _transition = self.transition();
        let mut state = self.state.load()?;
        let Some(pending) = state.pending.clone() else {
            self.tidy();
            self.announce_standing_failure(&state);
            return Ok(Startup::Clean);
        };
        if pending.version != self.running {
            // 待确认记录与当前运行版本不一致：可能发生在安装中途断电，或人工手动替换了可执行文件。
            tracing::warn!(recorded = %pending.version, running = %self.running, "当前运行版本与待确认版本不一致，将清除待确认记录");
            state.pending = None;
            self.state.save(&state)?;
            self.tidy();
            return Ok(Startup::Clean);
        }

        let give_up = if pending.starts >= MAX_UNCONFIRMED_STARTS {
            Some((
                format!("新版本已启动 {MAX_UNCONFIRMED_STARTS} 次仍未能连接 controller"),
                UpdateCause::StartsUnconfirmed { starts: MAX_UNCONFIRMED_STARTS },
            ))
        } else if pending.age(state::now()) >= CONFIRMATION_WINDOW {
            Some(overdue())
        } else {
            None
        };
        if let Some((reason, cause)) = give_up {
            return Ok(self.roll_back(state, &pending, reason, cause)?.map_or(Startup::Clean, Startup::RolledBack));
        }

        let starts = pending.starts + 1;
        state.pending = Some(Pending { starts, ..pending });
        self.state.save(&state)?;
        tracing::info!(version = %self.running, starts, "新版本已启动，等待连接 controller 以确认更新");
        Ok(Startup::AwaitingConfirmation { version: self.running.clone() })
    }

    /// 确认新版本已成功连接 controller：清除待确认记录并删除旧版本备份。返回已确认版本号；若无待确认更新则无操作并返回 `None`。
    ///
    /// 每次成功连接 controller 时均可调用。
    ///
    /// # Errors
    ///
    /// 无法读取或保存更新状态文件时返回错误。
    pub fn confirm(&self) -> Result<Option<Version>, UpdateError> {
        let _transition = self.transition();
        let mut state = self.state.load()?;
        if state.pending.as_ref().is_none_or(|pending| pending.version != self.running) {
            return Ok(None);
        }
        state.pending = None;
        state.forget_failures_up_to(&self.running);
        self.state.save(&state)?;
        // 状态已持久化落盘，此时备份文件已不再需要；若删除失败将在下次启动时重试清理。
        self.tidy();
        tracing::info!(version = %self.running, "新版本已连接 controller，更新已确认完成");
        self.status.send_replace(UpdateStatus::Confirmed { version: self.running.clone() });
        Ok(Some(self.running.clone()))
    }

    /// 监控新版本确认期限：若安装满 [`CONFIRMATION_WINDOW`] 仍未调用 [`confirm`](Self::confirm)，则自动回滚至旧版本。
    ///
    /// 在 [`startup`](Self::startup) 返回 [`Startup::AwaitingConfirmation`] 后，调用方应在后台运行此任务：
    /// 返回 `Some` 时应按 [`RolledBack::restart`] 重启进程；返回 `None` 表示更新已确认或原本不存在待确认更新。
    ///
    /// 确认期限按系统时钟自安装时刻起算，因此跨进程重启依然有效。
    ///
    /// # Errors
    ///
    /// 加载或保存更新状态失败，或回滚旧版本失败。
    pub async fn enforce_confirmation_deadline(&self) -> Result<Option<RolledBack>, UpdateError> {
        let Some(pending) = self.unconfirmed(&self.state.load()?) else { return Ok(None) };
        tokio::time::sleep(CONFIRMATION_WINDOW.saturating_sub(pending.age(state::now()))).await;
        // 等待期间更新可能已完成确认；唤醒后无需再次比对系统时钟，已等待满确认窗口即可触发判定。
        let _transition = self.transition();
        let state = self.state.load()?;
        match self.unconfirmed(&state) {
            Some(pending) => {
                let (reason, cause) = overdue();
                self.roll_back(state, &pending, reason, cause)
            }
            None => Ok(None),
        }
    }

    /// 校验发布清单签名并判断该发布清单是否适用。不下载更新包，也不修改磁盘。拒绝原因会更新到状态中
    /// （目标版本不高于当前版本除外，该情况不视为错误）。
    ///
    /// 校验规则：
    ///
    /// - 签名必须由内置受信任公钥之一签发；
    /// - 仅接受高于当前运行版本的更新，拒绝同版本及降级；
    /// - 预发布版仅允许安装在当前运行预发布版的节点上，正式版节点不会因收到预发布清单而切换至预发布版；
    /// - 当前主机历史上失败过的版本不会由自动更新（[`UpdateTiming::Idle`]）重试，但管理员强制更新可以重试；
    /// - 清单中必须包含适用于当前平台的更新包。
    ///
    /// # Errors
    ///
    /// 拒绝清单时返回 [`UpdateError::Refused`]，或读取状态文件失败时返回对应错误。
    pub fn check(&self, signed: &SignedManifest, timing: UpdateTiming) -> Result<Offer, UpdateError> {
        let manifest = self.keys.verify(signed).map_err(|error| self.refuse(None, error.into()))?;
        let state = self.state.load()?;
        self.judge(&manifest, &state, timing).map_err(|refusal| self.refuse(Some(&manifest.version), refusal))
    }

    fn judge(&self, manifest: &Manifest, state: &State, timing: UpdateTiming) -> Result<Offer, Refusal> {
        let offered = &manifest.version;
        if let Some(installed) = self.awaiting_restart(state) {
            return Err(Refusal::RestartPending { installed });
        }
        if *offered <= self.running {
            return Err(Refusal::NotNewer { offered: offered.clone(), running: self.running.clone() });
        }
        if let Some(blocker) = self.blocker {
            return Err(Refusal::CannotSelfUpdate(blocker));
        }
        if manifest.is_prerelease() && !self.running.is_prerelease() {
            return Err(Refusal::Prerelease { offered: offered.clone(), running: self.running.clone() });
        }
        if let Some(failure) = state.failure_of(offered).filter(|_| !timing.is_forced()) {
            return Err(Refusal::FailedBefore { version: offered.clone(), reason: failure.reason.clone() });
        }
        let artifact = manifest
            .artifact(&self.platform)
            .ok_or_else(|| Refusal::NoArtifact { version: offered.clone(), platform: self.platform.clone() })?;
        Ok(Offer { version: offered.clone(), artifact: artifact.clone() })
    }

    /// 第一步：验签、下载更新包、校验大小与 SHA-256、放置候选程序并执行自检。
    ///
    /// 不会影响当前运行中的程序。链路中断会持续重试而不视为失败；调用方可随时丢弃该 future，已下载的部分保留在状态目录中，
    /// 下次（包括进程重启后）将自动断点续传。同一时刻仅允许执行一次准备流程，后续调用需等待前一次完成或取消。
    ///
    /// 自检失败时不会替换可执行文件，并将该版本记录为在当前主机失败。
    ///
    /// # Errors
    ///
    /// 发布清单被拒绝、更新包获取或校验失败、自检未通过或磁盘读写错误时返回错误。除“版本不高于当前版本”外，其余原因均会写入状态。
    pub async fn prepare<S: PackageSource>(
        &self,
        signed: &SignedManifest,
        timing: UpdateTiming,
        source: &S,
    ) -> Result<Prepared, UpdateError> {
        let _preparing = self.preparing.lock().await;
        let offer = self.check(signed, timing)?;
        tracing::info!(version = %offer.version, running = %self.running, ?timing, size = offer.artifact.size, "开始准备新版本");
        self.stage(&offer, source).await.inspect_err(|error| self.fail(Some(&offer.version), error))?;
        Ok(Prepared { version: offer.version, artifact: offer.artifact })
    }

    async fn stage<S: PackageSource>(&self, offer: &Offer, source: &S) -> Result<(), UpdateError> {
        let Offer { version, artifact } = offer;
        fs::create_dir_all(&self.update_dir).map_err(UpdateError::io("创建", &self.update_dir))?;
        let package = self.update_dir.join(format!("{STAGED_PREFIX}{}.bin", artifact.sha256));
        self.remove_staged_packages(Some(&package));
        let download = Download { source, version, platform: &self.platform, artifact, path: &package };
        download
            .run(|status| {
                self.status.send_replace(status);
            })
            .await?;

        self.status.send_replace(UpdateStatus::SelfCheck { version: version.clone() });
        let candidate = self.files.candidate();
        // 在自检通过前，候选程序尚未完成验证：无论因自检失败、更新取消还是 future 被丢弃退出，均通过守卫自动清理。
        let unchecked = Unchecked::new(candidate.clone());
        let (files, from) = (self.files.clone(), package.clone());
        tokio::task::spawn_blocking(move || files.place_candidate(&from))
            .await
            .expect("候选程序复制任务异常终止")
            .map_err(UpdateError::io("写入候选程序", &candidate))?;
        if let Err(rejected) = self_check::run_candidate(&candidate, &self.self_check_args, version, self_check::TIMEOUT).await {
            drop(unchecked);
            discard(&package);
            let _transition = self.transition();
            let mut state = self.state.load()?;
            let recorded = format!("自检失败：{}", rejected.reason);
            let error = UpdateError::SelfCheck {
                version: version.clone(),
                reason: rejected.reason,
                exit_code: rejected.exit_code,
                output: rejected.output,
            };
            state.record_failure(version.clone(), recorded, error.cause());
            self.state.save(&state)?;
            return Err(error);
        }
        unchecked.passed();
        tracing::info!(%version, "新版本自检通过");
        Ok(())
    }

    /// 第二步：等待允许安装新版本的时机。`flows` 为调用方上报的活跃流数量，本模块不直接计数。
    ///
    /// - [`UpdateTiming::Now`]：立即返回；
    /// - [`UpdateTiming::Idle`]：等待活跃流归零，期间状态为 [`UpdateStatus::WaitingForIdle`]；
    /// - [`UpdateTiming::AfterDrain`]：将状态切换为 [`UpdateStatus::Draining`]（调用方据此停止接收新流），并等待活跃流归零。
    ///
    /// 可随时丢弃该 future 并以新的时机重新调用（例如等待空闲期间管理员触发“立即更新”）。
    /// 返回后应立即调用 [`install`](Self::install)，避免重启前进入的新流被中断。
    ///
    /// # Errors
    ///
    /// `flows` 发送端已关闭时返回错误。
    pub async fn wait_for_slot(
        &self,
        prepared: &Prepared,
        timing: UpdateTiming,
        flows: &mut watch::Receiver<usize>,
    ) -> Result<(), UpdateError> {
        timing::wait_for_slot(timing, &prepared.version, flows, &self.status)
            .await
            .inspect_err(|error| self.fail(Some(&prepared.version), error))
    }

    /// 第三步：将候选新版本替换到目标路径、保留旧版本备份，并持久化“待确认”记录。成功后调用方应重启进程。
    ///
    /// 替换前会再次校验候选文件的大小与 SHA-256，防止等待安装时机期间文件发生变动。
    ///
    /// # Errors
    ///
    /// 候选文件缺失或被篡改、状态保存失败或可执行文件替换失败时返回错误；此时当前运行的程序未被修改。
    pub async fn install(&self, prepared: Prepared) -> Result<RestartRequired, UpdateError> {
        let Prepared { version, artifact } = prepared;
        self.status.send_replace(UpdateStatus::Installing { version: version.clone() });
        let restart = self.swap_in(&version, &artifact).await.inspect_err(|error| self.fail(Some(&version), error))?;
        tracing::info!(%version, previous = %self.running, "新版本已安装，重启后生效");
        self.status.send_replace(UpdateStatus::Restarting { version });
        Ok(restart)
    }

    async fn swap_in(&self, version: &Version, artifact: &Artifact) -> Result<RestartRequired, UpdateError> {
        let candidate = self.files.candidate();
        let path = candidate.clone();
        let digest = tokio::task::spawn_blocking(move || FileDigest::of_file(&path))
            .await
            .expect("文件摘要计算任务异常终止")
            .map_err(UpdateError::io("读取", &candidate))?;
        if !digest.matches(artifact) {
            discard(&candidate);
            return Err(UpdateError::Corrupt {
                expected_size: artifact.size,
                expected: artifact.sha256,
                actual_size: digest.size,
                actual: digest.sha256,
            });
        }

        let _transition = self.transition();
        let mut state = self.state.load()?;
        if let Some(installed) = self.awaiting_restart(&state) {
            return Err(Refusal::RestartPending { installed }.into());
        }
        // 先持久化待确认记录，再替换可执行文件。若颠倒顺序，替换后尚未写盘即断电会导致新版本启动时缺少确认与回滚保护。
        // 若写盘后替换失败或中途断电，下次启动时会因运行版本与记录不一致而自动清除该待确认记录。
        state.pending = Some(Pending { version: version.clone(), previous: self.running.clone(), starts: 0, since: state::now() });
        self.state.save(&state)?;
        if let Err(error) = self.files.install_candidate() {
            state.pending = None;
            if let Err(error) = self.state.save(&state) {
                tracing::warn!(error = %describe(&error), "程序替换失败后无法清除待确认记录，将在下次启动时自动清理");
            }
            return Err(UpdateError::io("替换程序文件", self.files.program())(error));
        }
        self.remove_staged_packages(None);
        Ok(RestartRequired { version: version.clone() })
    }

    /// 连续执行准备、等待时机与安装三步流程。成功后调用方应重启进程。
    ///
    /// 若 controller 中途变更策略（调整时机或发布更新版本），可直接丢弃该 future 并重新调用，已下载的暂存包会被复用。
    ///
    /// # Errors
    ///
    /// 见 [`prepare`](Self::prepare)、[`wait_for_slot`](Self::wait_for_slot)、[`install`](Self::install)。
    pub async fn update<S: PackageSource>(
        &self,
        signed: &SignedManifest,
        timing: UpdateTiming,
        source: &S,
        flows: &mut watch::Receiver<usize>,
    ) -> Result<RestartRequired, UpdateError> {
        let prepared = self.prepare(signed, timing, source).await?;
        self.wait_for_slot(&prepared, timing, flows).await?;
        self.install(prepared).await
    }

    /// 判断当前运行的版本是否为刚安装且尚未确认的新版本。
    fn unconfirmed(&self, state: &State) -> Option<Pending> {
        state.pending.clone().filter(|pending| pending.version == self.running)
    }

    /// 判断当前进程是否已安装了其他版本并正在等待重启：此时磁盘上的可执行文件与备份已发生变更，禁止再次安装。
    fn awaiting_restart(&self, state: &State) -> Option<Version> {
        state.pending.as_ref().filter(|pending| pending.version != self.running).map(|pending| pending.version.clone())
    }

    /// 回滚至旧版本并将当前新版本记录为失败。若备份文件缺失则无法回滚，返回 `None` 并继续运行当前版本。
    fn roll_back(
        &self,
        mut state: State,
        pending: &Pending,
        reason: String,
        cause: UpdateCause,
    ) -> Result<Option<RolledBack>, UpdateError> {
        state.pending = None;
        if !self.files.has_backup() {
            tracing::error!(version = %pending.version, %reason, "新版本未完成确认，但旧版本备份文件缺失，将继续运行当前新版本");
            self.state.save(&state)?;
            return Ok(None);
        }
        self.files.restore_backup().map_err(UpdateError::io("回滚旧版本程序", self.files.program()))?;
        state.record_failure(pending.version.clone(), reason.clone(), cause.clone());
        self.state.save(&state)?;
        tracing::warn!(version = %pending.version, previous = %pending.previous, %reason, "新版本未完成确认，已回滚至旧版本，需要重启");
        self.status.send_replace(UpdateStatus::Failed {
            version: Some(pending.version.clone()),
            kind: FailureKind::VersionRejected,
            reason: reason.clone(),
            cause: Some(cause),
        });
        Ok(Some(RolledBack { failed: pending.version.clone(), reason, restart: RestartRequired { version: pending.previous.clone() } }))
    }

    /// 回滚后的旧版本重新启动时，将高于当前版本的最近一次失败记录同步到状态中，便于连接 controller 后立即上报。
    fn announce_standing_failure(&self, state: &State) {
        if let Some(failure) = state.failed.iter().filter(|failure| failure.version > self.running).max_by(|a, b| a.version.cmp(&b.version))
        {
            self.status.send_replace(UpdateStatus::Failed {
                version: Some(failure.version.clone()),
                kind: FailureKind::VersionRejected,
                reason: failure.reason.clone(),
                cause: failure.cause.clone(),
            });
        }
    }

    fn refuse(&self, version: Option<&Version>, refusal: Refusal) -> UpdateError {
        let not_newer = matches!(refusal, Refusal::NotNewer { .. });
        let error = UpdateError::from(refusal);
        if not_newer {
            // 节点已运行相同或更新版本，不视为错误，因此不修改当前状态。
            tracing::info!(reason = %describe(&error), "当前版本无需更新，已跳过该发布清单");
        } else {
            self.fail(version, &error);
        }
        error
    }

    fn fail(&self, version: Option<&Version>, error: &UpdateError) {
        let reason = describe(error);
        tracing::warn!(version = version.map(tracing::field::display), %reason, "更新失败");
        self.status.send_replace(UpdateStatus::Failed {
            version: version.cloned(),
            kind: error.kind(),
            reason,
            cause: Some(error.cause()),
        });
    }

    /// 无待确认更新时，清理主程序同目录下不再需要的遗留文件（旧版本备份与未安装的候选程序）。
    /// 不在此处清理部分下载的暂存包：它们保留在状态目录中，供下次断点续传。
    fn tidy(&self) {
        if let Err(error) = self.files.remove_backup() {
            tracing::warn!(path = %self.files.backup().display(), %error, "无法删除旧版本备份文件");
        }
        self.files.remove_leftovers();
    }

    /// 清理暂存更新包，`keep` 指定的路径除外。
    fn remove_staged_packages(&self, keep: Option<&Path>) {
        let Ok(entries) = fs::read_dir(&self.update_dir) else { return };
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(STAGED_PREFIX))
            .map(|entry| entry.path())
            .filter(|path| Some(path.as_path()) != keep)
            .for_each(|path| discard(&path));
    }
}

/// 位于主程序同目录、尚未通过自检的候选文件守卫。若在自检通过前被丢弃，则自动删除文件，避免未验证的可执行文件残留。
///
/// 准备阶段的 future 可能因 controller 撤回指令或变更时机而被随时取消，因此必须借助 `Drop` 析构执行清理，而非仅依赖某条返回路径。
/// 典型场景：某节点正在自检时，其他节点率先上报该版本失败导致 controller 撤回指令，若无守卫则损坏的 `i3t.new` 将残留在磁盘上。
struct Unchecked(Option<PathBuf>);

impl Unchecked {
    fn new(candidate: PathBuf) -> Self {
        Self(Some(candidate))
    }

    /// 标记自检已通过：解除自动清理，保留候选文件等待安装。
    fn passed(mut self) {
        self.0 = None;
    }
}

impl Drop for Unchecked {
    fn drop(&mut self) {
        if let Some(candidate) = &self.0 {
            discard(candidate);
        }
    }
}

/// 删除更新过程中遗留的文件。删除失败仅占用少量磁盘空间，下次启动仍会重试清理，因此仅记录警告日志。
fn discard(path: &Path) {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => tracing::warn!(path = %path.display(), %error, "无法删除更新遗留文件"),
        _ => {}
    }
}

/// 生成确认超时的失败描述与原因代码。
fn overdue() -> (String, UpdateCause) {
    let minutes = CONFIRMATION_WINDOW.as_secs() / 60;
    (format!("新版本安装超过 {minutes} 分钟仍未连接 controller"), UpdateCause::NotConfirmed { minutes })
}

#[cfg(test)]
mod tests;
