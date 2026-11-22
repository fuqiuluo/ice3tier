//! 还认不出是谁的连接占的名额。
//!
//! 节点协议在握手阶段（含首帧）、管理 API 在连接的整个存续期间，用 `Gate` 按来源地址给连接记账：
//!
//! - 每个来源最多 [`Limits::per_source`] 条，再来一条就挤掉这个来源最老的那条；
//! - 全部加起来最多 [`Limits::total`] 条，再来一条就挤掉占得最多的那个来源最老的那条。
//!
//! 满了也不拒绝新来的：拒绝的话，谁先占满名额谁就能把所有人挡在外面；挤掉的话，占得越多越先被挤。
//! 正常的连接很快就交还名额（握手完了，或者请求答完了），被挤到的基本只有一直不说话的。
//!
//! 来源按 IP 地址算，IPv6 按 /64 算：一台机器通常握着整个 /64。几个节点在同一个家用 NAT 后面时共用一个来源，
//! 所以 `per_source` 要比一户人家同时重连的节点数宽裕。

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

/// 被挤掉、被拒绝这一类日志，同一个入口多久最多记一条。洪泛的时候每条连接记一行只会把日志刷满。
pub(crate) const LOG_EVERY: Duration = Duration::from_secs(10);

/// 名额。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) per_source: usize,
    pub(crate) total: usize,
}

/// 一组名额，和占着它们的连接。
pub(crate) struct Gate {
    /// 这是哪个入口的名额，写进日志。
    what: &'static str,
    limits: Limits,
    slots: Mutex<Slots>,
    log: Throttle,
}

#[derive(Default)]
struct Slots {
    /// 下一条连接的编号。编号只增不减，所以同一个来源的队列里越靠前越老。
    next: u64,
    total: usize,
    by_source: HashMap<Source, VecDeque<Slot>>,
}

struct Slot {
    id: u64,
    /// 丢掉它就是通知那条连接：你被挤掉了。
    _evict: oneshot::Sender<()>,
}

/// 记账用的来源：IPv4 地址，或者 IPv6 地址所在的 /64。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Source(IpAddr);

impl From<IpAddr> for Source {
    fn from(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self(IpAddr::V4(v4)),
            IpAddr::V6(v6) => {
                let [a, b, c, d, ..] = v6.segments();
                Self(IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0)))
            }
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            IpAddr::V4(v4) => v4.fmt(f),
            IpAddr::V6(v6) => write!(f, "{v6}/64"),
        }
    }
}

/// 一条连接占着的名额。丢弃它就交还名额。
pub(crate) struct Pass {
    gate: Arc<Gate>,
    source: Source,
    id: u64,
    /// 名额已经交还，或者已经收到淘汰通知后是 `None`。
    evicted: Option<oneshot::Receiver<()>>,
}

impl Pass {
    pub(crate) fn source(&self) -> Source {
        self.source
    }

    /// 归还名额。返回 `false` 表示 Gate 已经将它淘汰，即使连接还没收到通知。
    pub(crate) fn finish(mut self) -> bool {
        self.evicted = None;
        self.gate.release(self.source, self.id)
    }

    /// 等到这条连接被挤掉。已经被挤掉的马上返回。
    pub(crate) async fn evicted(&mut self) {
        if let Some(evicted) = &mut self.evicted {
            // 发送的一头被丢掉就是被挤掉了；它从来不真的发东西。
            let _gone = evicted.await;
            self.evicted = None;
        }
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        if self.evicted.is_some() {
            self.gate.release(self.source, self.id);
        }
    }
}

impl Gate {
    pub(crate) fn new(what: &'static str, limits: Limits) -> Arc<Self> {
        Arc::new(Self { what, limits, slots: Mutex::default(), log: Throttle::new(LOG_EVERY) })
    }

    /// 给从 `ip` 来的一条新连接一个名额。名额满了时挤掉一条老的连接，新来的总是能进。
    pub(crate) fn admit(self: &Arc<Self>, ip: IpAddr) -> Pass {
        let source = Source::from(ip);
        let (evict, evicted) = oneshot::channel();
        let (id, victim) = {
            let mut slots = self.lock();
            let id = slots.next;
            slots.next += 1;
            let victim = if slots.by_source.get(&source).is_some_and(|queue| queue.len() >= self.limits.per_source) {
                slots.pop_oldest(source)
            } else if slots.total >= self.limits.total {
                slots.largest().and_then(|largest| slots.pop_oldest(largest))
            } else {
                None
            };
            slots.by_source.entry(source).or_default().push_back(Slot { id, _evict: evict });
            slots.total += 1;
            (id, victim)
        };
        if let Some((from, victim)) = victim {
            if let Some(suppressed) = self.log.allow() {
                tracing::warn!(
                    what = self.what,
                    %from,
                    newcomer = %source,
                    suppressed,
                    "名额满了，挤掉来自同一来源（或者占得最多的来源）最老的一条连接"
                );
            }
            drop(victim);
        }
        Pass { gate: Arc::clone(self), source, id, evicted: Some(evicted) }
    }

    fn release(&self, source: Source, id: u64) -> bool {
        let mut slots = self.lock();
        let Some(queue) = slots.by_source.get_mut(&source) else { return false };
        // 被挤掉的那条已经不在队列里了。
        let Some(index) = queue.iter().position(|slot| slot.id == id) else { return false };
        queue.remove(index);
        if queue.is_empty() {
            slots.by_source.remove(&source);
        }
        slots.total -= 1;
        true
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Slots> {
        self.slots.lock().expect("connection gate mutex poisoned")
    }

    #[cfg(test)]
    fn occupied(&self) -> (usize, usize) {
        let slots = self.lock();
        (slots.total, slots.by_source.len())
    }
}

impl Slots {
    /// 占得最多的来源；一样多时取最老的连接所在的那个。
    fn largest(&self) -> Option<Source> {
        let oldest = |queue: &VecDeque<Slot>| queue.front().map_or(u64::MAX, |slot| slot.id);
        let ranked = self.by_source.iter().max_by(|(_, a), (_, b)| a.len().cmp(&b.len()).then_with(|| oldest(b).cmp(&oldest(a))));
        ranked.map(|(source, _)| *source)
    }

    fn pop_oldest(&mut self, source: Source) -> Option<(Source, Slot)> {
        let queue = self.by_source.get_mut(&source)?;
        let slot = queue.pop_front()?;
        if queue.is_empty() {
            self.by_source.remove(&source);
        }
        self.total -= 1;
        Some((source, slot))
    }
}

/// 限速的日志：一段时间里只放行一条，并说出这期间省掉了几条。
pub(crate) struct Throttle {
    every: Duration,
    state: Mutex<ThrottleState>,
}

#[derive(Default)]
struct ThrottleState {
    last: Option<Instant>,
    suppressed: u64,
}

impl Throttle {
    pub(crate) fn new(every: Duration) -> Self {
        Self { every, state: Mutex::default() }
    }

    /// 现在可以记一条吗。可以时返回上一条之后省掉了几条。
    pub(crate) fn allow(&self) -> Option<u64> {
        let mut state = self.state.lock().expect("log throttle mutex poisoned");
        let now = Instant::now();
        if state.last.is_some_and(|last| now.duration_since(last) < self.every) {
            state.suppressed += 1;
            return None;
        }
        state.last = Some(now);
        Some(std::mem::take(&mut state.suppressed))
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use super::*;

    const SMALL: Limits = Limits { per_source: 2, total: 4 };

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// 这条连接现在是不是已经被挤掉了。
    fn is_evicted(pass: &mut Pass) -> bool {
        let mut evicted = pin!(pass.evicted());
        matches!(evicted.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(()))
    }

    #[test]
    fn a_removed_slot_cannot_finish_even_before_its_eviction_notification() {
        let gate = Gate::new("测试", SMALL);
        let mut old = gate.admit(ip("192.0.2.1"));
        // admit 先从名额表移除旧连接，放开锁以后才丢掉通知的发送端。
        let victim = gate.lock().pop_oldest(old.source()).unwrap();
        assert!(!is_evicted(&mut old));
        assert!(!old.finish());
        drop(victim);
    }

    #[test]
    fn one_source_cannot_hold_more_than_its_share_and_loses_its_oldest_first() {
        let gate = Gate::new("测试", SMALL);
        let mut first = gate.admit(ip("192.0.2.1"));
        let mut second = gate.admit(ip("192.0.2.1"));
        let mut third = gate.admit(ip("192.0.2.1"));
        assert!(is_evicted(&mut first), "同一个来源的第三条挤掉了它最老的那条");
        assert!(!is_evicted(&mut second) && !is_evicted(&mut third));
        assert_eq!(gate.occupied(), (2, 1));
    }

    #[test]
    fn when_everything_is_taken_the_biggest_source_gives_way_and_newcomers_always_get_in() {
        let gate = Gate::new("测试", SMALL);
        let mut flood = [gate.admit(ip("198.51.100.9")), gate.admit(ip("198.51.100.9"))];
        let mut quiet = [gate.admit(ip("192.0.2.1")), gate.admit(ip("192.0.2.2"))];
        let mut newcomer = gate.admit(ip("203.0.113.5"));
        assert!(is_evicted(&mut flood[0]), "占得最多的来源让出它最老的一条");
        assert!(!is_evicted(&mut flood[1]) && quiet.iter_mut().all(|pass| !is_evicted(pass)) && !is_evicted(&mut newcomer));
        assert_eq!(gate.occupied().0, 4);

        // 都只占一条时，最老的那条让位。
        let mut later = gate.admit(ip("203.0.113.6"));
        assert!(is_evicted(&mut flood[1]));
        assert!(quiet.iter_mut().all(|pass| !is_evicted(pass)) && !is_evicted(&mut later));
    }

    #[test]
    fn a_finished_connection_gives_its_slot_back() {
        let gate = Gate::new("测试", SMALL);
        let first = gate.admit(ip("192.0.2.1"));
        let mut second = gate.admit(ip("192.0.2.1"));
        drop(first);
        assert_eq!(gate.occupied(), (1, 1));
        let mut third = gate.admit(ip("192.0.2.1"));
        assert!(!is_evicted(&mut second) && !is_evicted(&mut third), "交还了名额之后不用挤");
        drop((second, third));
        assert_eq!(gate.occupied(), (0, 0));
    }

    #[test]
    fn an_ipv6_slash_64_counts_as_one_source_and_mapped_ipv4_as_ipv4() {
        let gate = Gate::new("测试", SMALL);
        let mut first = gate.admit(ip("2001:db8:1:2::1"));
        let _second = gate.admit(ip("2001:db8:1:2:ffff::7"));
        let _third = gate.admit(ip("2001:db8:1:2:abcd::9"));
        assert!(is_evicted(&mut first), "同一个 /64 里换着地址也是同一个来源");
        let _other = gate.admit(ip("2001:db8:1:3::1"));
        assert_eq!(gate.occupied(), (3, 2));
        assert_eq!(Source::from(ip("::ffff:192.0.2.1")), Source::from(ip("192.0.2.1")));
        assert_eq!(Source::from(ip("2001:db8:1:2::1")).to_string(), "2001:db8:1:2::/64");
    }

    #[test]
    fn the_log_throttle_lets_one_line_through_per_period_and_counts_the_rest() {
        let throttle = Throttle::new(Duration::from_secs(3600));
        assert_eq!(throttle.allow(), Some(0));
        assert_eq!((throttle.allow(), throttle.allow()), (None, None));
        let open = Throttle::new(Duration::ZERO);
        assert_eq!((open.allow(), open.allow()), (Some(0), Some(0)));
    }
}
