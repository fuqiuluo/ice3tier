//! 端口转发目标的连通性状态。
//!
//! 连通性由监听侧观测：向目标节点发起的流被目标节点拒绝时，REPLY 中的状态即为原因（目标节点可区分连接被拒绝、超时、
//! 不可达、未下发该转发等）；若无法向目标节点建流，则说明到目标节点不可达。该状态记录在监听节点上，随 `ForwardReport` 上报给 controller。
//! 一旦有流成功（目标节点返回成功，或已收到返回数据），即清除失败记录。
//!
//! 监听在虚拟 IP 上的转发由出口模块（`i3t_exit`）处理，并将相同结果写入同一份状态（[`ForwardHealth`] 可共享）。
//! UDP 转发只能观测会话是否成功建立：报文发出后目标是否收到，UDP 协议本身无法反馈。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use i3t_flow::{End, Summary};
use i3t_proto::flow::Status;

/// 端口转发的流在目标侧失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TargetCause {
    /// 目标地址拒绝了连接：那个端口上没有程序在听。
    Refused,
    /// 连目标地址超时。
    Timeout,
    /// 目标地址所在的网络或主机不可达。
    Unreachable,
    /// 目标节点没有这条转发：它没有声明可以作为端口转发的目标，或者它的配置还不是最新的。
    NotDeclared,
    /// 目标节点的访问规则不允许监听节点访问它。
    AccessDenied,
    /// 无法向目标节点建立流：目标节点不在线，或无可用路由。
    NodeUnreachable,
    /// 别的原因（目标节点在排空、内部出错等），见监听节点的日志。
    Other,
}

impl TargetCause {
    /// 目标节点在 REPLY 里给的状态是哪一种原因。成功时是 `None`。
    #[must_use]
    pub const fn of(status: Status) -> Option<Self> {
        Some(match status {
            Status::Ok => return None,
            Status::ConnectionRefused => Self::Refused,
            Status::TimedOut => Self::Timeout,
            Status::Unreachable | Status::NameNotFound => Self::Unreachable,
            Status::UnknownForward => Self::NotDeclared,
            Status::AccessDenied => Self::AccessDenied,
            Status::NotEnabled
            | Status::PolicyDenied
            | Status::Draining
            | Status::QuotaExhausted
            | Status::RateLimited
            | Status::TooManyStreams
            | Status::ResolverFailure
            | Status::InternalError => Self::Other,
        })
    }

    /// 判断一条已进入数据转发阶段（未等待 REPLY）的流所反映的结果：失败返回具体原因，成功返回 `Ok`，无法判断（如客户端先断开）返回 `None`。
    pub(crate) fn of_summary(summary: &Summary) -> Option<Result<(), Self>> {
        match &summary.end {
            End::Refused(reply) => Some(Err(Self::of(reply.status).unwrap_or(Self::Other))),
            End::BadReply(_) => Some(Err(Self::Other)),
            End::Clean => Some(Ok(())),
            // 对端已返回数据，说明 REPLY 成功；后续流如何结束与目标连通性无关。
            _ if summary.from_flow.first_byte.is_some() => Some(Ok(())),
            _ => None,
        }
    }
}

/// 一条转发最近一次在目标那里失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetFailure {
    pub cause: TargetCause,
    pub at: Instant,
}

/// 每条端口转发最近一次在目标那里的失败，成功一次就清掉。克隆出来的是同一份。
#[derive(Debug, Clone, Default)]
pub struct ForwardHealth(Arc<Mutex<HashMap<u32, TargetFailure>>>);

impl ForwardHealth {
    /// 记下编号是 `forward` 的转发的一条流的结果。
    pub fn record(&self, forward: u32, outcome: Result<(), TargetCause>) {
        let mut failures = self.0.lock().expect("forward health mutex poisoned");
        match outcome {
            Ok(()) => {
                if failures.remove(&forward).is_some() {
                    tracing::info!(forward, "端口转发目标已恢复连接");
                }
            }
            Err(cause) => {
                if failures.insert(forward, TargetFailure { cause, at: Instant::now() }).is_none_or(|before| before.cause != cause) {
                    tracing::info!(forward, ?cause, "连接端口转发目标失败");
                }
            }
        }
    }

    /// 这条转发最近一次失败；之后成功过或者从来没有失败过时是 `None`。
    #[must_use]
    pub fn last_failure(&self, forward: u32) -> Option<TargetFailure> {
        self.0.lock().expect("forward health mutex poisoned").get(&forward).copied()
    }

    /// 只留还在配置里的转发的记录。
    pub(crate) fn retain(&self, forwards: impl Fn(u32) -> bool) {
        self.0.lock().expect("forward health mutex poisoned").retain(|id, _| forwards(*id));
    }
}

#[cfg(test)]
mod tests {
    use i3t_flow::Traffic;
    use i3t_proto::flow::Reply;

    use super::*;

    #[test]
    fn a_failure_is_kept_until_a_stream_succeeds() {
        let health = ForwardHealth::default();
        assert_eq!(health.last_failure(3), None);
        health.record(3, Err(TargetCause::Refused));
        health.record(3, Err(TargetCause::Timeout));
        assert_eq!(health.last_failure(3).map(|failure| failure.cause), Some(TargetCause::Timeout), "最近的一次");
        assert_eq!(health.last_failure(4), None, "各条转发分开记");
        health.record(3, Ok(()));
        assert_eq!(health.last_failure(3), None);
    }

    #[test]
    fn the_status_of_the_reply_names_the_cause() {
        assert_eq!(TargetCause::of(Status::Ok), None);
        assert_eq!(TargetCause::of(Status::ConnectionRefused), Some(TargetCause::Refused));
        assert_eq!(TargetCause::of(Status::TimedOut), Some(TargetCause::Timeout));
        assert_eq!(TargetCause::of(Status::Unreachable), Some(TargetCause::Unreachable));
        assert_eq!(TargetCause::of(Status::UnknownForward), Some(TargetCause::NotDeclared));
        assert_eq!(TargetCause::of(Status::AccessDenied), Some(TargetCause::AccessDenied));
        assert_eq!(TargetCause::of(Status::Draining), Some(TargetCause::Other));
    }

    #[test]
    fn a_relayed_stream_tells_success_failure_or_nothing() {
        let summary = |end, first_byte| Summary { from_tcp: Traffic::default(), from_flow: Traffic { bytes: 0, first_byte }, end };
        let refused = summary(End::Refused(Reply::new(Status::ConnectionRefused, "")), None);
        assert_eq!(TargetCause::of_summary(&refused), Some(Err(TargetCause::Refused)));
        assert_eq!(TargetCause::of_summary(&summary(End::Clean, None)), Some(Ok(())));
        let answered = summary(End::Tcp(std::io::ErrorKind::ConnectionReset.into()), Some(std::time::Duration::from_millis(3)));
        assert_eq!(TargetCause::of_summary(&answered), Some(Ok(())));
        let client_left = summary(End::Tcp(std::io::ErrorKind::ConnectionReset.into()), None);
        assert_eq!(TargetCause::of_summary(&client_left), None);
    }
}
