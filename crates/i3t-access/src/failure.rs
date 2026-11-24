//! 代理的客户端能看到哪几种失败。

use i3t_proto::flow::Status;

use crate::http::Response;
use crate::socks5::ReplyCode;

/// 一次代理请求失败时告诉客户端的原因。两种代理协议各自把它翻译成自己的错误码。
///
/// 被拒绝只有 [`Failure::Denied`] 这一种表现：节点不存在、访问规则不允许、对方没有启用出口、
/// 出站策略不允许，客户端看到的都一样，所以不能拿它来枚举节点。具体原因在日志里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Denied,
    /// 域名不存在。
    HostUnreachable,
    /// 目标所在的网络或主机不可达。
    NetworkUnreachable,
    ConnectionRefused,
    /// 连接目标超时。
    TimedOut,
    /// 无法到达出口节点，或出口节点内部发生故障。
    ExitUnavailable,
    /// 本节点在出口上同时开着的流到了出口给每个节点的上限。
    TooManyConnections,
    /// 节点正在排空，不接新的连接：入口自己，或者请求要去的出口。客户端应该换一个，或者稍后再试。
    Draining,
    /// 流量的限额用完了：出口本账期的配额。
    LimitReached,
    /// 超过了出口的建连预算：同一个目标短时间里连得太多。
    RateLimited,
}

impl Failure {
    pub(crate) const fn socks5(self) -> ReplyCode {
        match self {
            Self::Denied => ReplyCode::NotAllowed,
            // SOCKS5 没有专门的超时码（0x06 是 TTL 耗尽），按惯例归到主机不可达。
            Self::HostUnreachable | Self::TimedOut => ReplyCode::HostUnreachable,
            Self::NetworkUnreachable => ReplyCode::NetworkUnreachable,
            Self::ConnectionRefused => ReplyCode::ConnectionRefused,
            Self::ExitUnavailable | Self::TooManyConnections | Self::Draining | Self::RateLimited => ReplyCode::GeneralFailure,
            // 限额是一条规则：0x02 的意思就是"规则不允许这条连接"。
            Self::LimitReached => ReplyCode::NotAllowed,
        }
    }

    pub(crate) const fn http(self) -> Response {
        match self {
            Self::Denied => Response::Forbidden,
            Self::HostUnreachable | Self::NetworkUnreachable | Self::ConnectionRefused => Response::BadGateway,
            Self::TimedOut => Response::GatewayTimeout,
            Self::ExitUnavailable => Response::ServiceUnavailable,
            Self::TooManyConnections | Self::LimitReached | Self::RateLimited => Response::TooManyRequests,
            Self::Draining => Response::Draining,
        }
    }
}

/// 对端给出的失败状态怎么告诉客户端。
impl From<Status> for Failure {
    fn from(status: Status) -> Self {
        match status {
            Status::NameNotFound => Self::HostUnreachable,
            Status::ConnectionRefused => Self::ConnectionRefused,
            Status::Unreachable => Self::NetworkUnreachable,
            Status::TimedOut => Self::TimedOut,
            Status::AccessDenied | Status::NotEnabled | Status::PolicyDenied | Status::UnknownForward => Self::Denied,
            // 这几种只有能用这个出口的调用者才会看到（出口先查访问规则），说清楚不会帮人枚举节点。
            Status::Draining => Self::Draining,
            Status::QuotaExhausted => Self::LimitReached,
            Status::RateLimited => Self::RateLimited,
            Status::TooManyStreams => Self::TooManyConnections,
            // 拒绝里写着"成功"是对端的错，和它别的内部错误一样对待。
            Status::Ok | Status::ResolverFailure | Status::InternalError => Self::ExitUnavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_of_refusal_looks_the_same_to_the_client() {
        for status in [Status::AccessDenied, Status::NotEnabled, Status::PolicyDenied, Status::UnknownForward] {
            let failure = Failure::from(status);
            assert_eq!(failure.socks5(), ReplyCode::NotAllowed, "{status:?}");
            assert_eq!(failure.http(), Response::Forbidden, "{status:?}");
        }
    }

    #[test]
    fn target_failures_keep_their_precise_codes() {
        assert_eq!(Failure::from(Status::ConnectionRefused).socks5(), ReplyCode::ConnectionRefused);
        assert_eq!(Failure::from(Status::NameNotFound).socks5(), ReplyCode::HostUnreachable);
        assert_eq!(Failure::from(Status::Unreachable).socks5(), ReplyCode::NetworkUnreachable);
        assert_eq!(Failure::from(Status::TimedOut).socks5(), ReplyCode::HostUnreachable);
        assert_eq!(Failure::from(Status::ConnectionRefused).http(), Response::BadGateway);
        assert_eq!(Failure::from(Status::TimedOut).http(), Response::GatewayTimeout);
    }

    #[test]
    fn draining_and_limits_get_their_own_proxy_errors() {
        assert_eq!(Failure::from(Status::Draining).socks5(), ReplyCode::GeneralFailure);
        assert_eq!(Failure::from(Status::Draining).http(), Response::Draining);
        assert!(std::str::from_utf8(Response::Draining.as_bytes()).unwrap().starts_with("HTTP/1.1 503 "));
        assert!(std::str::from_utf8(Response::Draining.as_bytes()).unwrap().contains("Retry-After: "));
        assert_eq!(Failure::from(Status::QuotaExhausted).socks5(), ReplyCode::NotAllowed);
        assert_eq!(Failure::from(Status::QuotaExhausted).http(), Response::TooManyRequests);
        assert_eq!(Failure::from(Status::RateLimited).socks5(), ReplyCode::GeneralFailure);
        assert_eq!(Failure::from(Status::RateLimited).http(), Response::TooManyRequests);
        assert_eq!(Failure::LimitReached.http(), Response::TooManyRequests);
        assert_eq!(Failure::from(Status::TooManyStreams).socks5(), ReplyCode::GeneralFailure);
        assert_eq!(Failure::from(Status::TooManyStreams).http(), Response::TooManyRequests);
    }

    #[test]
    fn failures_of_the_exit_are_not_blamed_on_the_target() {
        for status in [Status::ResolverFailure, Status::InternalError] {
            assert_eq!(Failure::from(status).socks5(), ReplyCode::GeneralFailure);
            assert_eq!(Failure::from(status).http(), Response::ServiceUnavailable);
        }
        assert_eq!(Failure::TooManyConnections.http(), Response::TooManyRequests);
        assert_eq!(Failure::TooManyConnections.socks5(), ReplyCode::GeneralFailure);
    }
}
