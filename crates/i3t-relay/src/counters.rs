//! relay 的计数器。

use std::sync::atomic::{AtomicU64, Ordering};

/// relay 没有照办的原因。每一种单独计数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// 本节点没有启用 relay。
    Disabled,
    /// 帧不完整，或者不是该由 relay 处理的类型。
    Malformed,
    /// 握手的节点不在允许的名单里。
    UnknownClient,
    /// AUTH 里的 cookie 不是发给这个地址的，或者过期了。
    BadCookie,
    /// AUTH 的签名不对。
    BadSignature,
    /// cookie 验证通过，但该来源（或全局）短期内发送的 AUTH 过多，已触发限流并跳过签名验证。
    TooManyHandshakes,
    /// 来源节点没有会话，或者数据报不是从会话绑定的地方来的。
    NoSession,
    /// 目的节点没有会话。
    PeerUnattached,
    /// 超过了带宽上限。
    RateLimited,
    /// 内核的 UDP 发送缓冲区满了。
    SendBufferFull,
    /// 目的节点那条 TCP 的待发队列满了。
    QueueFull,
    /// 多级中转的包：路径上没有本节点，或者目的节点写在了路径中间。
    NotOnRoute,
    /// 多级中转的包：路径比网络允许的级数长。
    HopLimit,
    /// 多级中转的包：不是路径上的前一个 relay 经骨干发来的，或者到下一个 relay 没有骨干连接。
    NoBackbone,
}

impl DropReason {
    pub const ALL: [Self; 14] = [
        Self::Disabled,
        Self::Malformed,
        Self::UnknownClient,
        Self::BadCookie,
        Self::BadSignature,
        Self::NoSession,
        Self::PeerUnattached,
        Self::RateLimited,
        Self::SendBufferFull,
        Self::QueueFull,
        Self::NotOnRoute,
        Self::HopLimit,
        Self::NoBackbone,
        Self::TooManyHandshakes,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Disabled => 0,
            Self::Malformed => 1,
            Self::UnknownClient => 2,
            Self::BadCookie => 3,
            Self::BadSignature => 4,
            Self::NoSession => 5,
            Self::PeerUnattached => 6,
            Self::RateLimited => 7,
            Self::SendBufferFull => 8,
            Self::QueueFull => 9,
            Self::NotOnRoute => 10,
            Self::HopLimit => 11,
            Self::NoBackbone => 12,
            Self::TooManyHandshakes => 13,
        }
    }
}

/// 某一时刻的计数。除了 `sessions` 都是启动以来的累计值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayCounters {
    /// 转发出去的包数。
    pub forwarded_packets: u64,
    /// 转发出去的字节数，含中转头。
    pub forwarded_bytes: u64,
    /// 现在有多少个会话。
    pub sessions: u64,
    /// 握手成功过多少次。
    pub sessions_opened: u64,
    dropped: [u64; DropReason::ALL.len()],
}

impl RelayCounters {
    /// 因为 `reason` 丢掉的包（或者拒绝的握手）有多少。
    #[must_use]
    pub const fn dropped(&self, reason: DropReason) -> u64 {
        self.dropped[reason.index()]
    }

    /// 各种原因丢掉的总数。
    #[must_use]
    pub fn dropped_total(&self) -> u64 {
        self.dropped.iter().sum()
    }
}

#[derive(Debug, Default)]
pub(crate) struct Counters {
    forwarded_packets: AtomicU64,
    forwarded_bytes: AtomicU64,
    sessions_opened: AtomicU64,
    dropped: [AtomicU64; DropReason::ALL.len()],
}

impl Counters {
    pub(crate) fn forwarded(&self, packets: usize, bytes: usize) {
        self.forwarded_packets.fetch_add(widen(packets), Ordering::Relaxed);
        self.forwarded_bytes.fetch_add(widen(bytes), Ordering::Relaxed);
    }

    pub(crate) fn dropped(&self, reason: DropReason, packets: usize) {
        self.dropped[reason.index()].fetch_add(widen(packets), Ordering::Relaxed);
    }

    pub(crate) fn session_opened(&self) {
        self.sessions_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn sessions_opened(&self) -> u64 {
        self.sessions_opened.load(Ordering::Relaxed)
    }

    pub(crate) fn snapshot(&self, sessions: usize) -> RelayCounters {
        RelayCounters {
            forwarded_packets: self.forwarded_packets.load(Ordering::Relaxed),
            forwarded_bytes: self.forwarded_bytes.load(Ordering::Relaxed),
            sessions: widen(sessions),
            sessions_opened: self.sessions_opened.load(Ordering::Relaxed),
            dropped: std::array::from_fn(|index| self.dropped[index].load(Ordering::Relaxed)),
        }
    }
}

/// `usize` 在所有支持的平台上都不超过 64 位。
fn widen(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_has_its_own_counter() {
        let counters = Counters::default();
        for (index, reason) in DropReason::ALL.into_iter().enumerate() {
            assert_eq!(reason.index(), index);
            counters.dropped(reason, index + 1);
        }
        counters.forwarded(3, 4200);
        counters.session_opened();
        let snapshot = counters.snapshot(2);
        for (index, reason) in DropReason::ALL.into_iter().enumerate() {
            assert_eq!(snapshot.dropped(reason), widen(index + 1));
        }
        assert_eq!(snapshot.dropped_total(), 105);
        assert_eq!((snapshot.forwarded_packets, snapshot.forwarded_bytes), (3, 4200));
        assert_eq!((snapshot.sessions, snapshot.sessions_opened), (2, 1));
    }
}
