//! 计数和水位：节点上报、在 `/metrics` 和 `i3t status` 里显示的东西。
//!
//! 全节点的计数和每个对端的计数分开记：对端从 netmap 里去掉之后它的那一份跟着消失，全节点的只增不减，
//! 拿去做 Prometheus 的计数器不会倒退。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use i3t_proto::NodeId;

/// 只增不减的计数。
#[derive(Debug, Default)]
pub(crate) struct Counter(Arc<AtomicU64>);

impl Counter {
    pub(crate) fn add(&self, n: usize) {
        // usize 不会比 u64 宽，这里不会截断。
        self.0.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub(crate) fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// 底下的原子数本身：交给别人去加（ice3proxy 交出去直接搬时，搬的一方往上加）。
    pub(crate) fn shared(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.0)
    }
}

/// 有进有出的水位，用 [`Gauge`] 守卫进出。
#[derive(Debug, Default)]
pub(crate) struct Level(Arc<AtomicU64>);

impl Level {
    pub(crate) fn enter(&self) -> Gauge {
        self.0.fetch_add(1, Ordering::Relaxed);
        Gauge(Arc::clone(&self.0))
    }

    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// 占着水位里的一个数，丢弃时减回去。
#[derive(Debug)]
pub(crate) struct Gauge(Arc<AtomicU64>);

impl Drop for Gauge {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 一个对端的计数。全节点的同名计数在 [`Counters`] 里另记一份。
#[derive(Debug, Default)]
pub(crate) struct Tally {
    pub(crate) in_use: Level,
    pub(crate) dialling: Level,
    pub(crate) claims: Counter,
    pub(crate) claims_waited: Counter,
    pub(crate) claim_wait_micros: Counter,
    pub(crate) claims_failed: Counter,
    pub(crate) fallbacks: Counter,
    pub(crate) dial_failures: Counter,
    pub(crate) refused: Counter,
    pub(crate) sealed_bytes: Counter,
    pub(crate) raw_bytes: Counter,
    pub(crate) spliced_bytes: Counter,
}

/// 全节点的计数：各对端的合计，加上分不到对端名下的握手失败。
#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub(crate) all: Tally,
    pub(crate) handshake_deadline: Counter,
    pub(crate) handshake_unknown_key: Counter,
    pub(crate) handshake_tls: Counter,
    pub(crate) handshake_protocol: Counter,
    pub(crate) handshake_busy: Counter,
}

/// 记一个数：对端的一份和全节点的一份一起记。
#[derive(Debug, Clone)]
pub(crate) struct Book {
    pub(crate) node: Arc<Counters>,
    pub(crate) peer: Arc<Tally>,
}

impl Book {
    pub(crate) fn both(&self, pick: impl Fn(&Tally) -> &Counter) -> [&Counter; 2] {
        [pick(&self.node.all), pick(&self.peer)]
    }

    pub(crate) fn bump(&self, pick: impl Fn(&Tally) -> &Counter) {
        self.both(pick).iter().for_each(|counter| counter.bump());
    }

    pub(crate) fn add(&self, pick: impl Fn(&Tally) -> &Counter, n: usize) {
        self.both(pick).iter().for_each(|counter| counter.add(n));
    }

    /// 交出去直接搬的字节记在哪里：两份。
    pub(crate) fn spliced(&self) -> Vec<Arc<AtomicU64>> {
        self.both(|tally| &tally.spliced_bytes).iter().map(|counter| counter.shared()).collect()
    }

    /// 进一个水位：两份各占一个数。
    pub(crate) fn enter(&self, pick: impl Fn(&Tally) -> &Level) -> [Gauge; 2] {
        [pick(&self.node.all).enter(), pick(&self.peer).enter()]
    }
}

/// lane 的状况，[`crate::Lanes::status`] 给出。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaneStatus {
    /// 全节点的合计（从启动算起，对端去掉之后也不减）。
    pub total: LaneCounts,
    /// 拨入连接握手失败的分类统计。由于未能归属到具体对端，仅统计节点级总计。
    pub handshake_failures: HandshakeFailures,
    /// 每个打开了 ice3proxy 的对端。
    pub peers: Vec<PeerLaneStatus>,
}

/// 一个对端的 lane 的状况。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerLaneStatus {
    pub peer: NodeId,
    /// 本节点是否主动向其拨号（其 TCP 端口可达且当前配置已启用）。
    pub dials: bool,
    /// 和它之间的控制 lane 在不在：本节点拨它时是本节点拨的那条，否则是它拨来的那条。
    pub control: bool,
    /// 它拨来、停在本节点等本节点开流时取用的空闲 lane。
    pub idle: u64,
    /// 本节点拨好、留给自己开流的空闲 lane。
    pub ready: u64,
    /// 本节点拨出去、停在它那里等它取用的 lane（按本节点所知；它刚取走的要过半个往返才知道）。
    pub parked_at_peer: u64,
    pub counts: LaneCounts,
}

/// 计数和水位，全节点的合计和每个对端的是同一组。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaneCounts {
    /// 正在承载流的 lane。
    pub in_use: u64,
    /// 正在拨号（连接或握手）的 lane。
    pub dialling: u64,
    /// 从停在本节点的 lane 里取用的次数。
    pub claims: u64,
    /// 其中池是空的、要等补拨的次数，和一共等了多久。
    pub claims_waited: u64,
    pub claim_wait: Duration,
    /// 获取 lane 失败的次数（池耗尽超时、控制 lane 未建立、对端正在排空或按需拨号失败）。
    pub claims_failed: u64,
    /// 原计划走 lane，因获取 lane 失败而回退至共用连接的流数量。
    pub fallbacks: u64,
    /// 本节点拨号失败的次数。
    pub dial_failures: u64,
    /// 握手成功、但 lane 因为用途或者数量不对被关掉的次数（旧的 epoch、超过上限、没有为对方打开）。
    pub refused: u64,
    /// 经 lane 的 TLS 收发的流数据字节数（两个方向合计）。
    pub sealed_bytes: u64,
    /// 不再加密的流在用户态搬的原始字节数。
    pub passthrough_bytes: u64,
    /// 不再加密的流交出去直接在两条 TCP 之间搬（Linux 上是 splice）的字节数。
    pub spliced_bytes: u64,
}

/// 拨进来的握手失败的原因。这些都是外人能造成的，所以只计数，每一次只记 debug 日志。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HandshakeFailures {
    /// 没有在时限之内完成（包括连上来什么都不发的）。
    pub deadline: u64,
    /// 对端公钥未知或已吊销。
    pub unknown_key: u64,
    /// 别的 TLS 错误。
    pub tls: u64,
    /// 握手之后的 HELLO 不对，或者根本不是 TLS；没握手完连接就断了（对方关掉、重置）的也算在这里。
    pub protocol: u64,
    /// 还没握手完的连接太多（同一来源或者全部），被挤掉或者拒绝的。
    pub busy: u64,
}

impl LaneStatus {
    /// 一个对端的那一份。
    #[must_use]
    pub fn peer(&self, peer: NodeId) -> Option<&PeerLaneStatus> {
        self.peers.iter().find(|status| status.peer == peer)
    }

    /// 各对端停在本节点的空闲 lane 合计。
    #[must_use]
    pub fn idle(&self) -> u64 {
        self.peers.iter().map(|status| status.idle).sum()
    }

    /// 本节点留给自己开流的空闲 lane 合计。
    #[must_use]
    pub fn ready(&self) -> u64 {
        self.peers.iter().map(|status| status.ready).sum()
    }

    /// 本节点停在各对端那里的 lane 合计。
    #[must_use]
    pub fn parked_at_peers(&self) -> u64 {
        self.peers.iter().map(|status| status.parked_at_peer).sum()
    }
}

impl PeerLaneStatus {
    pub(crate) fn new(peer: NodeId, counts: LaneCounts) -> Self {
        Self { peer, dials: false, control: false, idle: 0, ready: 0, parked_at_peer: 0, counts }
    }
}

impl Tally {
    pub(crate) fn counts(&self) -> LaneCounts {
        LaneCounts {
            in_use: self.in_use.get(),
            dialling: self.dialling.get(),
            claims: self.claims.get(),
            claims_waited: self.claims_waited.get(),
            claim_wait: Duration::from_micros(self.claim_wait_micros.get()),
            claims_failed: self.claims_failed.get(),
            fallbacks: self.fallbacks.get(),
            dial_failures: self.dial_failures.get(),
            refused: self.refused.get(),
            sealed_bytes: self.sealed_bytes.get(),
            passthrough_bytes: self.raw_bytes.get(),
            spliced_bytes: self.spliced_bytes.get(),
        }
    }
}

impl Counters {
    pub(crate) fn handshake_failures(&self) -> HandshakeFailures {
        HandshakeFailures {
            deadline: self.handshake_deadline.get(),
            unknown_key: self.handshake_unknown_key.get(),
            tls: self.handshake_tls.get(),
            protocol: self.handshake_protocol.get(),
            busy: self.handshake_busy.get(),
        }
    }
}
