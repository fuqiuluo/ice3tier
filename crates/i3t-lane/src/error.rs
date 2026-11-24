use std::io;
use std::time::Duration;

use i3t_conn::OpenError;
use i3t_proto::NodeId;

use crate::frame::FrameError;

/// 单条 lane 上发生的错误，包括握手、读帧和写帧。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LaneError {
    #[error("socket I/O 错误")]
    Io(#[source] io::Error),
    #[error("TLS 错误")]
    Tls(#[source] rustls::Error),
    #[error("帧格式无效")]
    Frame(#[source] FrameError),
    #[error("对端违反协议：{0}")]
    Protocol(&'static str),
    #[error("对端已关闭连接")]
    Closed,
    #[error("操作超时（{0:?}）")]
    Deadline(Duration),
}

impl LaneError {
    /// 判断该错误是否可归因于对端公钥不受信任（未知或已吊销）。
    pub(crate) fn is_unknown_key(&self) -> bool {
        matches!(
            self,
            Self::Tls(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
                | Self::Tls(rustls::Error::AlertReceived(rustls::AlertDescription::BadCertificate))
        )
    }
}

/// 在 lane 上开流失败的原因。调用方可据此回退到共用连接：此时开流请求尚未发出，切换传输不会导致重复执行。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenLaneError {
    #[error("未为节点 {0} 启用 ice3proxy")]
    NotEnabled(NodeId),
    #[error("节点 {0} 的控制 lane 未建立，当前无可用驻留 lane")]
    NoControl(NodeId),
    #[error("节点 {0} 正在排空，不再在其 lane 上开启新流")]
    GoingAway(NodeId),
    #[error("节点 {peer} 的驻留 lane 已耗尽，等待 {waited:?} 后仍未补充")]
    PoolDry { peer: NodeId, waited: Duration },
    #[error("与节点 {0} 的活跃 lane 数量已达上限")]
    TooMany(NodeId),
    #[error("拨号连接节点 {peer} 失败")]
    Dial {
        peer: NodeId,
        #[source]
        source: LaneError,
    },
}

impl OpenLaneError {
    /// 转换为连接层契约定义的开流错误：通过 [`i3t_conn::Connector`] 使用 lane 的调用方仅可见这些错误。
    #[must_use]
    pub fn to_open_error(&self) -> OpenError {
        match self {
            Self::NotEnabled(peer) | Self::NoControl(peer) | Self::GoingAway(peer) | Self::TooMany(peer) => OpenError::NoRoute(*peer),
            Self::PoolDry { peer, .. } => OpenError::Timeout(*peer),
            Self::Dial { peer, source } => OpenError::ConnectionLost { peer: *peer, reason: source.to_string() },
        }
    }
}
