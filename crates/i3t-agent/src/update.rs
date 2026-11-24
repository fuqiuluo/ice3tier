//! 节点这一侧的更新：把 controller 的指示交给更新库去做，把进度报回去。
//!
//! 验签、取包、自检、替换和回退都在 `i3t-update` 里，这里只是接线：
//!
//! - controller 的指示从长连接来（[`UpdateCommand`]）。新的一条顶替正在做的那一条：更新库保证做到一半丢下是安全的，
//!   取过的包也不会重新取。撤回就是丢下正在做的，把状态改回"没有更新在进行"。
//!   和正在做的一模一样的指示不算新的：controller 每次重新连上都会把指示再发一遍，不能因此把做到一半的更新从头来过。
//! - 更新包经长连接拉取（[`Packages`](crate::control::Packages)），链路中断视为“已中断”，更新库会自动重试续传。
//! - 更新库的状态每变一次就转出去（[`Driver::run`] 的 `reported`），装配层据此马上上报，并据此决定要不要排空。
//! - 程序文件换好之后 [`Driver::run`] 返回，装配层让进程以"请重启我"的退出码退出。

use std::sync::Arc;

use i3t_model::update::{SignedManifest, UpdateStatus, UpdateTiming};
use i3t_update::{RestartRequired, UpdateError, Updater};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::{JoinError, JoinHandle};

use crate::control::UpdateCommand;

/// 管更新的那个任务要的东西。
pub(crate) struct Driver<S> {
    pub(crate) updater: Arc<Updater>,
    /// controller 的指示。
    pub(crate) commands: mpsc::Receiver<UpdateCommand>,
    /// 取包的来路。
    pub(crate) packages: S,
    /// 节点上活跃的流的数量，更新库等它变成零。
    pub(crate) flows: watch::Receiver<usize>,
    /// 报给 controller 的更新状态放在这里。
    pub(crate) reported: watch::Sender<UpdateStatus>,
    /// 状态变了就通知它，让长连接马上上报一次。
    pub(crate) report_now: Arc<Notify>,
}

/// 一次正在做的更新，和要求它的那条指示。
struct Running {
    manifest: SignedManifest,
    timing: UpdateTiming,
    task: JoinHandle<Result<RestartRequired, UpdateError>>,
}

impl Running {
    /// `command` 是不是就是要求了这次更新的那条指示（清单和时机都一样）。
    fn was_ordered_by(&self, command: &UpdateCommand) -> bool {
        matches!(command, UpdateCommand::Update { manifest, timing } if *manifest == self.manifest && *timing == self.timing)
    }
}

impl<S: i3t_update::PackageSource + Clone + 'static> Driver<S> {
    /// 一直处理 controller 的指示，直到程序文件换好了、需要重启进程时才返回。
    pub(crate) async fn run(mut self) -> RestartRequired {
        let mut status = self.updater.status();
        // 启动时更新库可能已有状态需要上报（如上次更新失败已回退）。
        self.publish(status.borrow_and_update().clone());
        let mut running: Option<Running> = None;
        loop {
            tokio::select! {
                command = self.commands.recv() => {
                    let Some(command) = command else {
                        // 长连接没了，不会再有指示。正在做的那一次让它做完。
                        return match running {
                            Some(running) => self.finish(running.task).await,
                            None => std::future::pending().await,
                        };
                    };
                    if running.as_ref().is_some_and(|current| current.was_ordered_by(&command)) {
                        tracing::debug!("controller 重发了当前正在执行的更新指令，继续执行");
                        continue;
                    }
                    // 先停下正在做的。它要是恰好已经把程序换好了，那就不能再做别的，只能重启。
                    if let Some(current) = running.take() {
                        current.task.abort();
                        if let Ok(Ok(restart)) = current.task.await {
                            return self.restart(restart);
                        }
                    }
                    match command {
                        UpdateCommand::Update { manifest, timing } => {
                            tracing::info!(?timing, "controller 要求更新");
                            running = Some(self.start(manifest, timing));
                        }
                        UpdateCommand::Cancel => {
                            tracing::info!("controller 撤回了更新的要求，停下还没有做完的更新");
                            // 更新库的状态停在被丢下的那一步，不会自己变回来。
                            self.publish(UpdateStatus::Idle);
                        }
                    }
                }
                Ok(()) = status.changed() => {
                    let now = status.borrow_and_update().clone();
                    self.publish(now);
                }
                outcome = async { (&mut running.as_mut().expect("这个分支只在有任务时才等").task).await }, if running.is_some() => {
                    running = None;
                    if let Some(restart) = settled(outcome) {
                        return self.restart(restart);
                    }
                }
            }
        }
    }

    fn start(&self, manifest: SignedManifest, timing: UpdateTiming) -> Running {
        let (updater, packages, mut flows) = (Arc::clone(&self.updater), self.packages.clone(), self.flows.clone());
        let order = manifest.clone();
        let task = tokio::spawn(async move { updater.update(&order, timing, &packages, &mut flows).await });
        Running { manifest, timing, task }
    }

    /// 程序文件换好了。返回之前把更新库最后的状态（"马上重启"）转出去：
    /// 任务结束和状态变化是同时发生的，不能指望循环里已经先看到了后者。
    fn restart(&self, restart: RestartRequired) -> RestartRequired {
        self.publish(self.updater.status().borrow().clone());
        restart
    }

    /// 等待正在执行的更新任务完成。若未成功则不再返回。
    async fn finish(&self, task: JoinHandle<Result<RestartRequired, UpdateError>>) -> RestartRequired {
        match settled(task.await) {
            Some(restart) => self.restart(restart),
            None => std::future::pending().await,
        }
    }

    fn publish(&self, status: UpdateStatus) {
        let changed = self.reported.send_if_modified(|current| {
            let changed = *current != status;
            *current = status;
            changed
        });
        if changed {
            self.report_now.notify_one();
        }
    }
}

/// 一次更新任务的结局：把程序换好了时是要求重启。没有换好时原因已经在状态里，更新库也记过日志；
/// 任务本身异常结束（panic）的原因只有这里知道，在这里记。
fn settled(outcome: Result<Result<RestartRequired, UpdateError>, JoinError>) -> Option<RestartRequired> {
    match outcome {
        Ok(Ok(restart)) => Some(restart),
        Ok(Err(_)) => None,
        Err(error) => {
            tracing::error!(%error, "做更新的任务异常结束");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::time::Duration;

    use i3t_crypto::NodeKey;
    use i3t_model::update::{FailureKind, Version};
    use i3t_update::{ChunkRequest, SourceError, UpdaterConfig, sign_manifest};
    use tokio::time::timeout;

    use super::*;

    /// 一个从来给不了包的来路。测试里的清单过不了验签，走不到取包这一步。
    #[derive(Clone)]
    struct NoPackages;

    impl i3t_update::PackageSource for NoPackages {
        async fn fetch(&self, _request: ChunkRequest<'_>) -> Result<Vec<u8>, SourceError> {
            Err(SourceError::Unavailable("测试里没有包".to_owned()))
        }
    }

    struct Fixture {
        commands: mpsc::Sender<UpdateCommand>,
        reported: watch::Receiver<UpdateStatus>,
        report_now: Arc<Notify>,
        _flows: watch::Sender<usize>,
        _dir: tempfile::TempDir,
        task: JoinHandle<RestartRequired>,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let updater = Arc::new(Updater::new(UpdaterConfig {
            program: dir.path().join("i3t"),
            state_dir: dir.path().join("state"),
            running: Version::new(0, 1, 0),
            self_check_args: vec![OsString::from("self-check")],
            blocker: None,
        }));
        let (commands, commands_rx) = mpsc::channel(8);
        let (flows_tx, flows) = watch::channel(0);
        let (reported_tx, reported) = watch::channel(UpdateStatus::Idle);
        let report_now = Arc::new(Notify::new());
        let driver = Driver {
            updater,
            commands: commands_rx,
            packages: NoPackages,
            flows,
            reported: reported_tx,
            report_now: Arc::clone(&report_now),
        };
        Fixture { commands, reported, report_now, _flows: flows_tx, _dir: dir, task: tokio::spawn(driver.run()) }
    }

    /// 一份不是任何受信任的公钥签的清单：节点应该拒绝它，什么都不装。
    fn untrusted_order(timing: UpdateTiming) -> UpdateCommand {
        let text = r#"{ "version": "0.2.0", "min_controller": "0.0.0", "published": 1, "artifacts": {} }"#;
        UpdateCommand::Update { manifest: sign_manifest(&NodeKey::generate().unwrap(), text.to_owned()), timing }
    }

    #[tokio::test]
    async fn an_order_the_node_does_not_trust_is_refused_reported_and_does_not_restart_anything() {
        let mut fixture = fixture();
        fixture.commands.send(untrusted_order(UpdateTiming::Now)).await.unwrap();
        let failed = |status: &UpdateStatus| matches!(status, UpdateStatus::Failed { kind: FailureKind::NotInstalled, .. });
        let status = timeout(Duration::from_secs(5), fixture.reported.wait_for(failed)).await.unwrap().unwrap().clone();
        let UpdateStatus::Failed { version, reason, .. } = status else { unreachable!("上面等的就是失败") };
        assert_eq!(version, None, "清单没有验过，里面写的版本号不能信");
        assert!(reason.contains("签名"), "{reason}");
        // 状态一变就要求马上上报。
        timeout(Duration::from_secs(5), fixture.report_now.notified()).await.expect("应该通知长连接上报");
        assert!(!fixture.task.is_finished(), "没有装任何东西，不需要重启");
    }

    #[tokio::test]
    async fn only_an_identical_order_counts_as_a_repeat_of_the_one_in_progress() {
        let dir = tempfile::tempdir().unwrap();
        let updater = Arc::new(Updater::new(UpdaterConfig {
            program: dir.path().join("i3t"),
            state_dir: dir.path().join("state"),
            running: Version::new(0, 1, 0),
            self_check_args: Vec::new(),
            blocker: None,
        }));
        let (flows_tx, flows) = watch::channel(0);
        let (reported, _reported_rx) = watch::channel(UpdateStatus::Idle);
        let (_commands, commands_rx) = mpsc::channel(1);
        let driver = Driver { updater, commands: commands_rx, packages: NoPackages, flows, reported, report_now: Arc::new(Notify::new()) };
        let UpdateCommand::Update { manifest, timing } = untrusted_order(UpdateTiming::Idle) else {
            unreachable!("上面造的就是一条更新指示")
        };
        let running = driver.start(manifest.clone(), timing);
        let same = UpdateCommand::Update { manifest: manifest.clone(), timing };
        assert!(running.was_ordered_by(&same), "清单和时机都一样：是 controller 重连之后重发的同一条");
        assert!(
            !running.was_ordered_by(&UpdateCommand::Update { manifest, timing: UpdateTiming::Now }),
            "时机变了：管理员改了主意，要按新的来"
        );
        assert!(!running.was_ordered_by(&untrusted_order(UpdateTiming::Idle)), "清单变了：有了更新的版本");
        assert!(!running.was_ordered_by(&UpdateCommand::Cancel));
        drop(flows_tx);
    }

    /// 收下日志的输出，测试看记了什么。
    #[derive(Clone, Default)]
    struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Logs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn an_update_task_that_panics_after_the_controller_is_gone_is_logged() {
        let logs = Logs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
        let _logging = tracing::subscriber::set_default(subscriber);
        let dir = tempfile::tempdir().unwrap();
        let updater = Arc::new(Updater::new(UpdaterConfig {
            program: dir.path().join("i3t"),
            state_dir: dir.path().join("state"),
            running: Version::new(0, 1, 0),
            self_check_args: Vec::new(),
            blocker: None,
        }));
        let (_flows_tx, flows) = watch::channel(0);
        let (reported, _reported_rx) = watch::channel(UpdateStatus::Idle);
        let (_commands, commands_rx) = mpsc::channel(1);
        let driver = Driver { updater, commands: commands_rx, packages: NoPackages, flows, reported, report_now: Arc::new(Notify::new()) };
        let task: JoinHandle<Result<RestartRequired, UpdateError>> = tokio::spawn(async { panic!("更新任务里的 bug") });
        assert!(timeout(Duration::from_millis(200), driver.finish(task)).await.is_err(), "没有换好程序，不重启");
        let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("做更新的任务异常结束") && logged.contains("更新任务里的 bug"), "{logged}");
    }

    #[tokio::test]
    async fn a_cancel_puts_the_reported_status_back_to_idle() {
        let mut fixture = fixture();
        fixture.commands.send(untrusted_order(UpdateTiming::Idle)).await.unwrap();
        timeout(Duration::from_secs(5), fixture.reported.wait_for(|status| *status != UpdateStatus::Idle)).await.unwrap().unwrap();
        fixture.commands.send(UpdateCommand::Cancel).await.unwrap();
        timeout(Duration::from_secs(5), fixture.reported.wait_for(|status| *status == UpdateStatus::Idle)).await.unwrap().unwrap();
        // 之后的指示照常处理。
        fixture.commands.send(untrusted_order(UpdateTiming::AfterDrain)).await.unwrap();
        timeout(Duration::from_secs(5), fixture.reported.wait_for(|status| *status != UpdateStatus::Idle)).await.unwrap().unwrap();
        assert!(!fixture.task.is_finished());
    }
}
