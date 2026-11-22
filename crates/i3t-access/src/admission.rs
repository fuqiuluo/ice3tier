//! 代理连接在完成握手之前要占的名额。
//!
//! 代理端口谁都连得上，用户名和密码要到握手里才看得到。连上来却不说话的连接也占着一个文件描述符、一个任务和读缓冲；
//! 握手的时限只管一条连接能等多久，不管同时有多少条。所以接受连接之后、开任务之前先领名额：全节点一份，每个来源一份。
//! 领不到就直接关掉，不让它占着位子排队。握手完成时还回去，失败、超时的在连接关掉时还；之后的搬运不占名额。
//!
//! 端口转发没有握手，不领。

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use crate::source::SourceHost;

/// 拒绝的日志最多隔这么久记一条，中间拒绝了多少条写在下一条里。
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// 同时最多有多少条代理连接还没完成握手。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeLimits {
    /// 本节点所有代理和组网入口合计。
    pub total: usize,
    /// 同一个来源（IPv4 的一个地址、IPv6 的一个 /64）。回环上的来源是本机的程序，只算在总数里。
    pub per_source: usize,
}

impl Default for HandshakeLimits {
    /// 全节点 1024 条，每个来源 64 条。浏览器经一个代理同时开的连接一般不超过 32 条，握手又只要几个往返，
    /// 同一个 NAT 后面的几台设备一起用也够；1024 条还没握手的连接也只占几十 MB 内存。
    fn default() -> Self {
        Self { total: 1024, per_source: 64 }
    }
}

/// 还没完成握手的连接占着的名额，按来源记，另有总数。克隆出来的是同一份。
#[derive(Debug, Clone)]
pub(crate) struct Handshakes(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    limits: HandshakeLimits,
    counts: Mutex<Counts>,
    refusals: Mutex<RefusalLog>,
}

#[derive(Debug, Default)]
struct Counts {
    by_source: HashMap<SourceHost, usize>,
    total: usize,
}

/// 领不到名额的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Full {
    /// 全节点的名额用完了。
    Node,
    /// 这个来源的名额用完了。
    Source,
}

impl fmt::Display for Full {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Node => "还没完成握手的代理连接在全节点到了上限，关掉了新来的连接",
            Self::Source => "这个来源还没完成握手的代理连接到了上限，关掉了新来的连接",
        })
    }
}

impl Handshakes {
    pub(crate) fn new(limits: HandshakeLimits) -> Self {
        Self(Arc::new(Inner { limits, counts: Mutex::default(), refusals: Mutex::default() }))
    }

    /// 来自 `from` 的一条新连接领一个名额。名额跟着返回的 [`Pass`] 走，丢掉它就还回去。
    pub(crate) fn admit(&self, from: SocketAddr) -> Result<Pass, Full> {
        let source = SourceHost::of(from);
        let HandshakeLimits { total: max_total, per_source: max_per_source } = self.0.limits;
        let mut counts = self.0.counts.lock().expect("handshake quota mutex poisoned");
        let Counts { by_source, total } = &mut *counts;
        if *total >= max_total {
            return Err(Full::Node);
        }
        if let Some(source) = source {
            // 先只看不插：拒绝的来源不在表里留下一个 0。
            if by_source.get(&source).copied().unwrap_or(0) >= max_per_source {
                return Err(Full::Source);
            }
            *by_source.entry(source).or_default() += 1;
        }
        *total += 1;
        Ok(Pass { handshakes: Arc::clone(&self.0), source })
    }

    /// 记一次拒绝。日志限速：有人一直往上连的时候不刷屏。
    pub(crate) fn refused(&self, listen: &impl fmt::Display, from: SocketAddr, full: Full) {
        let Some(more) = self.0.refusals.lock().expect("handshake refusal log mutex poisoned").due(Instant::now()) else { return };
        let HandshakeLimits { total, per_source } = self.0.limits;
        tracing::warn!(%listen, %from, more, total, per_source, "{full}");
    }
}

/// 一条还没完成握手的连接占着的名额，丢掉时还回去。
#[derive(Debug)]
pub(crate) struct Pass {
    handshakes: Arc<Inner>,
    /// 回环上的来源不按来源记，是 `None`。
    source: Option<SourceHost>,
}

impl Drop for Pass {
    fn drop(&mut self) {
        let mut counts = self.handshakes.counts.lock().expect("handshake quota mutex poisoned");
        let Counts { by_source, total } = &mut *counts;
        *total = total.saturating_sub(1);
        let Some(source) = self.source else { return };
        if let Some(count) = by_source.get_mut(&source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                by_source.remove(&source);
            }
        }
    }
}

/// 拒绝日志的限速。
#[derive(Debug, Default)]
struct RefusalLog {
    logged: Option<Instant>,
    skipped: u64,
}

impl RefusalLog {
    /// 这一次拒绝要不要记日志。要的话返回上一条之后又悄悄拒绝了多少条。
    fn due(&mut self, now: Instant) -> Option<u64> {
        if self.logged.is_some_and(|at| now.saturating_duration_since(at) < REFUSAL_LOG_INTERVAL) {
            self.skipped += 1;
            return None;
        }
        self.logged = Some(now);
        Some(std::mem::take(&mut self.skipped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn counted(handshakes: &Handshakes) -> (usize, usize) {
        let counts = handshakes.0.counts.lock().unwrap();
        (counts.total, counts.by_source.len())
    }

    #[test]
    fn a_source_at_its_limit_leaves_the_remaining_places_to_other_sources() {
        let handshakes = Handshakes::new(HandshakeLimits { total: 3, per_source: 2 });
        let first = [handshakes.admit(at("192.0.2.1:1000")).unwrap(), handshakes.admit(at("192.0.2.1:1001")).unwrap()];
        assert_eq!(handshakes.admit(at("192.0.2.1:1002")).unwrap_err(), Full::Source);
        let other = handshakes.admit(at("192.0.2.2:1000")).unwrap();
        assert_eq!(handshakes.admit(at("198.51.100.1:1000")).unwrap_err(), Full::Node, "三个名额都占着");
        assert_eq!(counted(&handshakes), (3, 2), "被拒绝的来源不在表里留下记录");

        drop(other);
        let third = handshakes.admit(at("198.51.100.1:1000")).unwrap();
        drop(first);
        assert_eq!(counted(&handshakes), (1, 1));
        drop(third);
        assert_eq!(counted(&handshakes), (0, 0), "名额都还了，表是空的");
    }

    #[test]
    fn a_place_is_back_as_soon_as_its_pass_is_dropped() {
        let handshakes = Handshakes::new(HandshakeLimits { total: 1, per_source: 1 });
        for _ in 0..3 {
            let pass = handshakes.admit(at("192.0.2.1:1000")).unwrap();
            assert_eq!(handshakes.admit(at("192.0.2.1:1001")).unwrap_err(), Full::Node);
            drop(pass);
        }
        assert_eq!(counted(&handshakes), (0, 0));
    }

    #[test]
    fn programs_on_this_machine_count_only_towards_the_node_wide_limit() {
        let handshakes = Handshakes::new(HandshakeLimits { total: 3, per_source: 1 });
        let local = [handshakes.admit(at("127.0.0.1:1000")).unwrap(), handshakes.admit(at("[::1]:1000")).unwrap()];
        assert_eq!(counted(&handshakes), (2, 0));
        let _remote = handshakes.admit(at("192.0.2.1:1000")).unwrap();
        assert_eq!(handshakes.admit(at("127.0.0.1:1001")).unwrap_err(), Full::Node);
        drop(local);
        assert_eq!(counted(&handshakes), (1, 1));
    }

    #[test]
    fn ipv6_addresses_in_one_64_are_one_source() {
        let handshakes = Handshakes::new(HandshakeLimits { total: 16, per_source: 1 });
        let _first = handshakes.admit(at("[2001:db8::1]:1000")).unwrap();
        assert_eq!(handshakes.admit(at("[2001:db8::ffff:2]:1000")).unwrap_err(), Full::Source, "同一个 /64");
        let _next = handshakes.admit(at("[2001:db8:0:1::1]:1000")).unwrap();
    }

    #[test]
    fn a_limit_of_zero_admits_nobody_and_records_nothing() {
        let handshakes = Handshakes::new(HandshakeLimits { total: 4, per_source: 0 });
        assert_eq!(handshakes.admit(at("192.0.2.1:1000")).unwrap_err(), Full::Source);
        assert_eq!(counted(&handshakes), (0, 0));
        let none = Handshakes::new(HandshakeLimits { total: 0, per_source: 4 });
        assert_eq!(none.admit(at("127.0.0.1:1000")).unwrap_err(), Full::Node);
    }

    #[test]
    fn refusals_are_logged_at_most_once_per_interval_with_the_count_in_between() {
        let mut log = RefusalLog::default();
        let start = Instant::now();
        assert_eq!(log.due(start), Some(0));
        assert_eq!(log.due(start + Duration::from_secs(1)), None);
        assert_eq!(log.due(start + Duration::from_secs(2)), None);
        assert_eq!(log.due(start + REFUSAL_LOG_INTERVAL), Some(2));
    }
}
