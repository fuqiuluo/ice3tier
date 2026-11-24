//! 连接层里跟着性能档位变的几项。值由装配方按档位给（`i3t-agent`），这里只给出今天的默认值和上限。

use std::time::Duration;

/// 每条流的接收窗口的上限。
///
/// QUIC 库给每条流的乱序缓冲设了 1024 个空洞的硬上限，超过就关掉整条连接；窗口 16MB 时在千兆链路上实测触发过，
/// 窗口不超过 2 MB 时不会触发该限制。因此各档位均不超过此上限，单流吞吐相应受限于“窗口 ÷ 往返时间”。
pub const MAX_STREAM_WINDOW: u32 = 2 * 1024 * 1024;

/// 连接层跟着档位变的设置。
///
/// [`Endpoint::tune`](crate::Endpoint::tune) 换上新的一份之后：窗口对之后建立的连接生效，已有的连接保持建立时的窗口；
/// 空闲回收的时间对所有连接立刻生效。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// 每条流的接收窗口，字节。超过 [`MAX_STREAM_WINDOW`] 的按它算。
    pub stream_window: u32,
    /// 一条连接上所有的流加起来，写进去了、对端还没有确认的数据，和对端发过来、上层还没有读走的数据，各自最多多少字节。
    ///
    /// 一个读得慢的对端（或者故意不读的）最多让本端压住这么多。
    pub connection_window: u32,
    /// 没有流之后多久关闭到一个对端的连接；`None` 表示不因为空闲关闭（被设为常驻的对端本来就不关）。
    pub idle_close: Option<Duration>,
}

impl Default for Tuning {
    /// 不按档位调的时候的值，也就是 `balanced`。连接窗口取 64MB 的理由见 `quic` 模块。
    fn default() -> Self {
        Self { stream_window: MAX_STREAM_WINDOW, connection_window: 64 * 1024 * 1024, idle_close: Some(Duration::from_secs(300)) }
    }
}

impl Tuning {
    /// 实际用的流窗口：不超过 [`MAX_STREAM_WINDOW`]，也不超过连接窗口。
    pub(crate) fn effective_stream_window(&self) -> u32 {
        self.stream_window.min(MAX_STREAM_WINDOW).min(self.connection_window)
    }
}
