//! 更新安装时机控制。
//!
//! 更新时机由 controller 指定（[`UpdateTiming`]），活跃流数量由调用方通过 `watch` 通道提供。
//! 本模块不直接统计流量，仅按以下规则协调二者：
//!
//! | 时机 | 存在活跃流 | 无活跃流 |
//! |---|---|---|
//! | `Now` | 立即安装 | 立即安装 |
//! | `Idle` | 上报“等待空闲”，直至活跃流归零 | 立即安装 |
//! | `AfterDrain` | 上报“排空中”，直至活跃流归零 | 上报“排空中”，随后立即安装 |
//!
//! 调用方观察到“排空中”状态后将不再接受新流，直至进程重启。即使当前无活跃流也先切换为排空状态，
//! 以阻止安装到重启间隙内新流进入。

use i3t_model::update::{UpdateStatus, UpdateTiming, Version};
use tokio::sync::watch;

use crate::error::UpdateError;

/// 等待允许安装新版本的时机。可随时丢弃该 future 以取消等待：此阶段不会修改磁盘或状态。
///
/// # Errors
///
/// `flows` 发送端已关闭，无法继续获取活跃流数量时返回错误。
pub(crate) async fn wait_for_slot(
    timing: UpdateTiming,
    version: &Version,
    flows: &mut watch::Receiver<usize>,
    status: &watch::Sender<UpdateStatus>,
) -> Result<(), UpdateError> {
    let waiting = match timing {
        UpdateTiming::Now => return Ok(()),
        UpdateTiming::Idle if *flows.borrow() == 0 => return Ok(()),
        UpdateTiming::Idle => UpdateStatus::WaitingForIdle { version: version.clone() },
        UpdateTiming::AfterDrain => UpdateStatus::Draining { version: version.clone() },
    };
    tracing::info!(%version, ?timing, flows = *flows.borrow(), "新版本已就绪，等待活跃流归零后执行安装");
    status.send_replace(waiting);
    flows.wait_for(|active| *active == 0).await.map_err(|_| UpdateError::Cancelled)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use super::*;

    static VERSION: Version = Version::new(0, 2, 0);

    /// 推进一步，看它是不是已经结束。
    fn poll_once<T>(future: std::pin::Pin<&mut impl Future<Output = T>>) -> Poll<T> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn now_does_not_wait_for_flows() {
        let (_flows_tx, mut flows) = watch::channel(7);
        let (status, _) = watch::channel(UpdateStatus::Idle);
        let wait = pin!(wait_for_slot(UpdateTiming::Now, &VERSION, &mut flows, &status));
        assert!(matches!(poll_once(wait), Poll::Ready(Ok(()))));
        assert_eq!(*status.borrow(), UpdateStatus::Idle);
    }

    #[test]
    fn idle_proceeds_at_once_when_there_are_no_flows() {
        let (_flows_tx, mut flows) = watch::channel(0);
        let (status, _) = watch::channel(UpdateStatus::Idle);
        let wait = pin!(wait_for_slot(UpdateTiming::Idle, &VERSION, &mut flows, &status));
        assert!(matches!(poll_once(wait), Poll::Ready(Ok(()))));
        assert_eq!(*status.borrow(), UpdateStatus::Idle, "不用等的时候不该报等待空闲");
    }

    #[test]
    fn idle_waits_until_the_last_flow_ends() {
        let (flows_tx, mut flows) = watch::channel(2);
        let (status, _) = watch::channel(UpdateStatus::Idle);
        let mut wait = pin!(wait_for_slot(UpdateTiming::Idle, &VERSION, &mut flows, &status));
        assert!(poll_once(wait.as_mut()).is_pending());
        assert_eq!(*status.borrow(), UpdateStatus::WaitingForIdle { version: VERSION.clone() });
        flows_tx.send_replace(1);
        assert!(poll_once(wait.as_mut()).is_pending());
        flows_tx.send_replace(3);
        assert!(poll_once(wait.as_mut()).is_pending());
        flows_tx.send_replace(0);
        assert!(matches!(poll_once(wait), Poll::Ready(Ok(()))));
    }

    #[test]
    fn after_drain_announces_draining_even_without_flows() {
        let (_flows_tx, mut flows) = watch::channel(0);
        let (status, _) = watch::channel(UpdateStatus::Idle);
        let wait = pin!(wait_for_slot(UpdateTiming::AfterDrain, &VERSION, &mut flows, &status));
        assert!(matches!(poll_once(wait), Poll::Ready(Ok(()))));
        assert_eq!(*status.borrow(), UpdateStatus::Draining { version: VERSION.clone() });
    }

    #[test]
    fn after_drain_waits_for_the_flows_in_hand() {
        let (flows_tx, mut flows) = watch::channel(1);
        let (status, _) = watch::channel(UpdateStatus::Idle);
        let mut wait = pin!(wait_for_slot(UpdateTiming::AfterDrain, &VERSION, &mut flows, &status));
        assert!(poll_once(wait.as_mut()).is_pending());
        assert_eq!(*status.borrow(), UpdateStatus::Draining { version: VERSION.clone() });
        flows_tx.send_replace(0);
        assert!(matches!(poll_once(wait), Poll::Ready(Ok(()))));
    }

    #[test]
    fn waiting_ends_with_an_error_when_the_caller_stops_reporting_flows() {
        let (flows_tx, mut flows) = watch::channel(1);
        let (status, _) = watch::channel(UpdateStatus::Idle);
        let mut wait = pin!(wait_for_slot(UpdateTiming::Idle, &VERSION, &mut flows, &status));
        assert!(poll_once(wait.as_mut()).is_pending());
        drop(flows_tx);
        assert!(matches!(poll_once(wait), Poll::Ready(Err(UpdateError::Cancelled))));
    }
}
