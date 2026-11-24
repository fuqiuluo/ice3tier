use std::io;
use std::time::Duration;

use i3t_conn::OpenError;
use i3t_proto::flow::{DecodeError, Reason, Reply};

/// 建流阶段（开流、写入或读取流头）失败的原因。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FlowError {
    #[error("到对端开流失败")]
    Connect(#[from] OpenError),
    #[error("流头写入失败")]
    Write(#[source] io::Error),
    #[error("读取流头时流发生错误")]
    Read(#[source] io::Error),
    #[error("流头尚未读取完整，流已结束")]
    Truncated,
    #[error("流头格式无效")]
    Malformed(#[from] DecodeError),
    #[error("等待流头超时（{0:?}）")]
    Deadline(Duration),
    #[error("对端拒绝建流请求：{:?}（{}）", .0.status, .0.detail)]
    Refused(Reply),
    #[error("对端请求建立数据报上下文，当前入口仅接受流")]
    NotAStream,
    #[error("对端指定的上下文号 {0} 已被占用")]
    ContextInUse(u32),
}

impl FlowError {
    /// 建流失败并放弃该流时用于重置流的原因码。对端流头不合法视为协议错误，其余失败按本端取消处理。
    pub(crate) const fn reset_reason(&self) -> Reason {
        match self {
            Self::Malformed(_) => Reason::ProtocolError,
            Self::Connect(_)
            | Self::Write(_)
            | Self::Read(_)
            | Self::Truncated
            | Self::Deadline(_)
            | Self::Refused(_)
            | Self::NotAStream
            | Self::ContextInUse(_) => Reason::Cancelled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_malformed_header_is_reset_as_a_protocol_error() {
        assert_eq!(FlowError::Malformed(DecodeError::UnknownKind(0x7f)).reset_reason(), Reason::ProtocolError);
        for other in [FlowError::Truncated, FlowError::Deadline(Duration::from_secs(1)), FlowError::NotAStream, FlowError::ContextInUse(3)]
        {
            assert_eq!(other.reset_reason(), Reason::Cancelled, "{other}");
        }
    }
}
