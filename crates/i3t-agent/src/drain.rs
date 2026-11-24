//! 排空：更新之前不再接新的流，手上的流不受影响。
//!
//! 管理员选"排空后更新"时，更新进行到"排空中"这一步，节点就把门关上，直到进程重启：
//!
//! - **出口一侧**（别的节点开过来的流和数据报上下文）：出口模块在查过访问规则之后用"正在排空"（`Draining`）这个状态拒绝，
//!   说明里写着为什么。它不算出口坏了：调用方据此换一个出口，而不是以为自己没有权限。
//! - **入口一侧**（本机代理监听器与端口转发）：监听器保持开启，新请求将被明确拒绝（SOCKS5 返回 0x01、HTTP 返回 503），
//!   端口转发的新连接将被重置；已建立的连接继续运行直至结束。
//!
//! 门什么时候关由更新的状态决定（[`Drain`]），不另外记一个开关：更新被撤回或者失败了，状态离开这几步，门自己就开了。
//! "正在替换程序"和"马上重启"两步门也是关着的：从流数到零到进程退出之间不该再放新的流进来。

use i3t_model::update::{UpdateStatus, Version};
use tokio::sync::watch;

/// 节点现在是不是在排空。可以克隆，各处拿着的看到的是同一个状态。
#[derive(Debug, Clone)]
pub struct Drain {
    status: watch::Receiver<UpdateStatus>,
    /// [`changed`](Self::changed) 上一次告诉调用方的值。一开始当作没有在排空。
    told: bool,
}

impl Drain {
    /// `status` 是节点报给 controller 的那个更新状态。
    #[must_use]
    pub const fn new(status: watch::Receiver<UpdateStatus>) -> Self {
        Self { status, told: false }
    }

    /// 正在排空的话，是为了更新到哪个版本。
    #[must_use]
    pub fn version(&self) -> Option<Version> {
        draining_for(&self.status.borrow()).cloned()
    }

    #[must_use]
    pub fn is_draining(&self) -> bool {
        draining_for(&self.status.borrow()).is_some()
    }

    /// 正在排空时给发起方和日志看的说明；不在排空时是 `None`。
    #[must_use]
    pub fn detail(&self) -> Option<String> {
        self.version().map(|version| format!("节点正在排空，准备更新到 {version} 后重启，不再接受新流；请切换其他出口或稍后重试"))
    }

    /// 等到"是不是在排空"和上一次告诉调用方的不一样了，返回新的值。第一次调用时，已经在排空的话马上返回。
    /// 状态不会再变（发送端没了）时一直等下去。
    pub async fn changed(&mut self) -> bool {
        loop {
            let now = draining_for(&self.status.borrow_and_update()).is_some();
            if now != self.told {
                self.told = now;
                return now;
            }
            if self.status.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }
}

/// 这个更新状态下门是不是关着的；关着的话是为了哪个版本。
fn draining_for(status: &UpdateStatus) -> Option<&Version> {
    match status {
        UpdateStatus::Draining { version } | UpdateStatus::Installing { version } | UpdateStatus::Restarting { version } => Some(version),
        UpdateStatus::Idle
        | UpdateStatus::Downloading { .. }
        | UpdateStatus::Verifying { .. }
        | UpdateStatus::SelfCheck { .. }
        | UpdateStatus::WaitingForIdle { .. }
        | UpdateStatus::Confirmed { .. }
        | UpdateStatus::Failed { .. }
        | UpdateStatus::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    fn version() -> Version {
        Version::new(0, 2, 0)
    }

    #[test]
    fn the_door_is_shut_from_draining_until_the_restart() {
        let shut = [
            UpdateStatus::Draining { version: version() },
            UpdateStatus::Installing { version: version() },
            UpdateStatus::Restarting { version: version() },
        ];
        for status in shut {
            assert_eq!(draining_for(&status), Some(&version()), "{status:?}");
        }
        let open = [
            UpdateStatus::Idle,
            UpdateStatus::Downloading { version: version(), received: 1, total: 2 },
            UpdateStatus::SelfCheck { version: version() },
            UpdateStatus::WaitingForIdle { version: version() },
            UpdateStatus::Confirmed { version: version() },
            UpdateStatus::Unknown,
        ];
        for status in open {
            assert_eq!(draining_for(&status), None, "{status:?}");
        }
    }

    #[tokio::test]
    async fn drain_changes_are_reported_once_per_flip() {
        let (status, receiver) = watch::channel(UpdateStatus::Idle);
        let mut drain = Drain::new(receiver);
        assert!(!drain.is_draining());
        status.send_replace(UpdateStatus::WaitingForIdle { version: version() });
        status.send_replace(UpdateStatus::Draining { version: version() });
        assert!(timeout(Duration::from_secs(5), drain.changed()).await.unwrap());
        assert_eq!(drain.version(), Some(version()));
        assert!(drain.detail().is_some_and(|detail| detail.contains("排空") && detail.contains("0.2.0")));
        // 从排空走到替换程序：门还是关着的，不算变化。
        status.send_replace(UpdateStatus::Installing { version: version() });
        assert!(timeout(Duration::from_millis(100), drain.changed()).await.is_err());
        // 更新被撤回：门开了。
        status.send_replace(UpdateStatus::Idle);
        assert!(!timeout(Duration::from_secs(5), drain.changed()).await.unwrap());
    }
}
