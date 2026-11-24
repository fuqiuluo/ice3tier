//! relay 的限速：转发的带宽上限和它在各个来源节点之间的分配，给没有会话的来源回错误帧的频率，以及握手时验签名的次数。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use i3t_proto::NodeId;

/// 桶里最少能攒下这么多字节。带宽上限设得很低时，也要让一批合并发送的包整批过得去。
const MIN_BURST_BYTES: f64 = 128.0 * 1024.0;
/// 桶里最多攒多长时间的额度。
const BURST: Duration = Duration::from_millis(100);

/// 负载按多长的时间片统计。
const LOAD_SLICE: Duration = Duration::from_secs(1);
/// 负载的平滑系数：每个时间片新的测量值占这么多。负载惩罚要带平滑，不然节点会跟着瞬时的起伏来回换路。
const LOAD_SMOOTHING: f64 = 0.3;
/// 平滑之后的占用到了上限的这个比例算过载，回落到 [`OVERLOAD_CLEAR`] 以下才算恢复。两个门槛之间不变，免得反复通知。
///
/// 负载里每个来源节点最多算它的公平份额（见 [`Bandwidth`]），所以它不会超过 1，平滑之后只会慢慢逼近 1：门槛要比 1 低一点。
const OVERLOAD_ENTER: f64 = 0.95;
const OVERLOAD_CLEAR: f64 = 0.8;
/// 最多分别记多少个来源节点的用量。正常情况下就是会话的个数；更多的（多级中转里别的 relay 带来的来源）不单独算，只受总的上限。
const MAX_SENDERS: usize = 1024;

/// 令牌桶：按配置的带宽放行数据，超出限额的直接丢弃。relay 不做排队，不延迟发送。
///
/// 带宽在来源节点之间公平地分：这一秒和上一秒里有包要转发的来源节点有 n 个，每个的公平份额就是上限的 n 分之一。
/// 没人争的时候谁都可以用满（只有一个来源时没有份额的限制，几个来源时空着的额度也照样放行）；
/// 桶里的额度不到一半时，最近一秒里放行的已经够了份额的来源让路，剩下的留给没用够的。所以一个成员灌包占不满别人的那一份，
/// 几个都要得多的来源也各拿到差不多一份。
///
/// 它同时统计负载：要转发的流量（放行的加上被它丢掉的）占带宽上限的比例，按秒统计再做平滑。每个来源超出公平份额的部分不算：
/// 一个成员自己灌包，只是它自己的包被丢掉，relay 不会因此对所有节点宣布过载、把大家都赶走。
#[derive(Debug)]
pub(crate) struct Bandwidth {
    bytes_per_sec: f64,
    capacity: f64,
    available: f64,
    refilled: Instant,
    /// 当前时间片是什么时候开始的、里面来了多少字节。
    slice_started: Instant,
    slice_bytes: f64,
    /// 平滑之后的占用比例。
    utilisation: f64,
    overloaded: bool,
    /// 各个来源节点的用量。这个时间片和上一个时间片里都没有包要转发的不留。
    senders: HashMap<NodeId, Usage>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Usage {
    /// 这个时间片和上一个里要转发的字节（放行的加上丢掉的）。前者算负载，两个合起来看它是不是还在发。
    offered: f64,
    offered_before: f64,
    /// 这个时间片和上一个里放行的字节，看它最近一秒用了多少。
    admitted: f64,
    admitted_before: f64,
}

impl Usage {
    /// 最近一秒里放行了多少：这个时间片的，加上上一个时间片里还落在这一秒之内的那一部分（按均匀算）。
    fn recent(&self, slice_left: f64) -> f64 {
        self.admitted + self.admitted_before * slice_left
    }
}

/// relay 的负载。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Load {
    /// 要转发的流量占带宽上限的比例，平滑过的。可以超过 1。
    pub(crate) utilisation: f64,
    pub(crate) overloaded: bool,
}

impl Bandwidth {
    pub(crate) fn new(mbps: u32, now: Instant) -> Self {
        let bytes_per_sec = f64::from(mbps) * 125_000.0;
        let capacity = (bytes_per_sec * BURST.as_secs_f64()).max(MIN_BURST_BYTES);
        Self {
            bytes_per_sec,
            capacity,
            available: capacity,
            refilled: now,
            slice_started: now,
            slice_bytes: 0.0,
            utilisation: 0.0,
            overloaded: false,
            senders: HashMap::new(),
        }
    }

    /// 现在的负载。
    pub(crate) fn load(&mut self, now: Instant) -> Load {
        self.roll(now);
        Load { utilisation: self.utilisation, overloaded: self.overloaded }
    }

    /// 把已经过完的时间片算进平滑值。空闲了很久之后占用早就衰减到 0 了，不用一片一片地算。
    fn roll(&mut self, now: Instant) {
        const MAX_IDLE_SLICES: u32 = 64;
        let mut slices = 0;
        while now.saturating_duration_since(self.slice_started) >= LOAD_SLICE && slices < MAX_IDLE_SLICES {
            let rate = self.slice_bytes / LOAD_SLICE.as_secs_f64();
            self.utilisation += LOAD_SMOOTHING * (rate / self.bytes_per_sec.max(1.0) - self.utilisation);
            self.slice_bytes = 0.0;
            self.slice_started += LOAD_SLICE;
            slices += 1;
            for usage in self.senders.values_mut() {
                usage.offered_before = std::mem::take(&mut usage.offered);
                usage.admitted_before = std::mem::take(&mut usage.admitted);
            }
            self.senders.retain(|_, usage| usage.offered_before > 0.0);
        }
        if slices == MAX_IDLE_SLICES {
            self.slice_started = now;
            self.utilisation = 0.0;
            self.senders.clear();
        }
        if self.utilisation >= OVERLOAD_ENTER {
            self.overloaded = true;
        } else if self.utilisation < OVERLOAD_CLEAR {
            self.overloaded = false;
        }
    }

    /// 来源节点 `src` 要转发 `bytes` 字节：额度够就扣掉并返回 `true`，不够返回 `false`，这批包应该丢掉。
    pub(crate) fn admit(&mut self, src: NodeId, bytes: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.refilled).as_secs_f64();
        self.available = (self.available + elapsed * self.bytes_per_sec).min(self.capacity);
        self.refilled = now;
        // 一批包最大 64KB。真有超过 4GB 的，按"无论如何都不够"算。
        let wanted = u32::try_from(bytes).map_or(f64::INFINITY, f64::from);
        self.roll(now);
        if !self.senders.contains_key(&src) && self.senders.len() >= MAX_SENDERS {
            // 来源计数表已满：不再为该来源单独分配份额，其请求流量全部计入总负载。
            self.slice_bytes += wanted.min(self.capacity);
            return self.take(wanted);
        }
        let senders = self.senders.len() + usize::from(!self.senders.contains_key(&src));
        let share = self.bytes_per_sec * LOAD_SLICE.as_secs_f64() / f64::from(u32::try_from(senders).unwrap_or(u32::MAX));
        let slice_left = 1.0 - (now.saturating_duration_since(self.slice_started).as_secs_f64() / LOAD_SLICE.as_secs_f64()).min(1.0);
        let usage = self.senders.entry(src).or_default();
        let (offered, recent) = (usage.offered, usage.recent(slice_left));
        if wanted.is_finite() {
            usage.offered += wanted;
            self.slice_bytes += wanted.min((share - offered).max(0.0));
        }
        if senders > 1 && recent >= share && self.available < self.capacity / 2.0 {
            return false;
        }
        let admitted = self.take(wanted);
        if admitted && let Some(usage) = self.senders.get_mut(&src) {
            usage.admitted += wanted;
        }
        admitted
    }

    fn take(&mut self, wanted: f64) -> bool {
        if wanted > self.available {
            return false;
        }
        self.available -= wanted;
        true
    }
}

/// 限速时怎么把来源地址归成"同一个来源"：IPv4 按地址，IPv6 按 /64。一台机器通常就拿到一个 /64，按单个地址算的话
/// 换个地址就是一个新来源，限速形同虚设。
pub(crate) fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(ip.to_bits() & !u128::from(u64::MAX))),
    }
}

/// 一个普通的令牌桶：每秒补 `rate` 个，最多攒 `burst` 个。
#[derive(Debug, Clone, Copy)]
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    refilled: Instant,
}

impl Bucket {
    const fn full(rate: f64, burst: f64, now: Instant) -> Self {
        Self { rate, burst, tokens: burst, refilled: now }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.refilled).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.refilled = now;
    }

    fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }

    fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.burst
    }
}

/// 同一个来源每秒最多验多少个 AUTH 的签名，最多攒多少个。正常的节点握一次手只有一个 AUTH，重发也是半秒一个；
/// 同一个 NAT 后面的几个节点同时重连也够用。
const HANDSHAKES_PER_SOURCE: f64 = 5.0;
const HANDSHAKE_BURST_PER_SOURCE: f64 = 10.0;
/// 全局每秒最大验签次数。单次验签耗时数十微秒，该上限将握手验签耗时控制在收包路径的 1% 左右；
/// 即使 relay 重启后所有挂靠节点同时带随机抖动重连，个人网络规模下也远不会触及此上限。
const HANDSHAKES_TOTAL: f64 = 200.0;
/// 最多分别记多少个来源。满了之后新来源只受总数的限制，直到旧的攒满额度被忘掉。
const MAX_HANDSHAKE_SOURCES: usize = 4096;

/// 握手时验签名的限速。
///
/// cookie 证明了来源地址是真的，但同一个 cookie 在有效期里可以用任意多次：拿到一个 cookie 的人可以不停地发签名不对的 AUTH，
/// 每一个都要 relay 验一次签名，而验签就在收包的路径上。所以 cookie 验过之后、验签之前再按来源限一次速，另加一个总数的上限。
/// cookie 验过之前不查这里，所以 relay 不会为伪造来源地址的包记任何东西。
#[derive(Debug)]
pub(crate) struct HandshakeLimiter {
    per_source: HashMap<IpAddr, Bucket>,
    total: Bucket,
}

impl HandshakeLimiter {
    pub(crate) fn new(now: Instant) -> Self {
        Self { per_source: HashMap::new(), total: Bucket::full(HANDSHAKES_TOTAL, HANDSHAKES_TOTAL, now) }
    }

    /// 现在能不能为来自 `from` 的一个 AUTH 验签名。返回 `true` 就算用掉了一次。
    pub(crate) fn allow(&mut self, from: IpAddr, now: Instant) -> bool {
        let key = source_key(from);
        if !self.per_source.contains_key(&key) && self.per_source.len() >= MAX_HANDSHAKE_SOURCES {
            self.sweep(now);
        }
        if self.per_source.len() < MAX_HANDSHAKE_SOURCES || self.per_source.contains_key(&key) {
            let bucket = self.per_source.entry(key).or_insert_with(|| Bucket::full(HANDSHAKES_PER_SOURCE, HANDSHAKE_BURST_PER_SOURCE, now));
            if !bucket.take(now) {
                return false;
            }
        }
        self.total.take(now)
    }

    /// 忘掉额度已经攒满的来源：它们和从来没有来过的一样。
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.per_source.retain(|_, bucket| !bucket.is_full(now));
    }
}

/// 同一个来源地址多久才再回一个错误帧。
const REFUSAL_INTERVAL: Duration = Duration::from_secs(1);
/// 最多记多少个来源地址。满了之后陌生地址一律不回，直到旧的过期：错误帧只是个提示，不回也不影响正确性。
const MAX_TRACKED_SOURCES: usize = 4096;

/// 错误帧的限速。没有会话的来源是没有认证过的，回给它的东西必须又小又少。
#[derive(Debug, Default)]
pub(crate) struct RefusalLimiter {
    last_sent: HashMap<SocketAddr, Instant>,
}

impl RefusalLimiter {
    /// 现在能不能给 `to` 回一个错误帧。返回 `true` 就算回过了。
    pub(crate) fn allow(&mut self, to: SocketAddr, now: Instant) -> bool {
        if let Some(last) = self.last_sent.get_mut(&to) {
            if now.saturating_duration_since(*last) < REFUSAL_INTERVAL {
                return false;
            }
            *last = now;
            return true;
        }
        if self.last_sent.len() >= MAX_TRACKED_SOURCES {
            self.sweep(now);
            if self.last_sent.len() >= MAX_TRACKED_SOURCES {
                return false;
            }
        }
        self.last_sent.insert(to, now);
        true
    }

    /// 忘掉已经过了限速间隔的来源。
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.last_sent.retain(|_, last| now.saturating_duration_since(*last) < REFUSAL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    const SRC: u32 = 1;

    #[test]
    fn bandwidth_admits_the_configured_rate_and_drops_the_excess() {
        let start = Instant::now();
        // 8 Mbit/s 是每秒 1MB。
        let mut bandwidth = Bandwidth::new(8, start);
        let packet = 1400;
        let burst = (0..10_000).take_while(|_| bandwidth.admit(node(SRC), packet, start)).count();
        assert!((90..=95).contains(&burst), "开始时桶是满的，能过 128KB 左右：{burst}");
        assert!(!bandwidth.admit(node(SRC), packet, start));

        // 之后的一秒里放行的量应该就是配置的带宽。
        let mut admitted = 0;
        for millis in 1..=1000 {
            let now = start + Duration::from_millis(millis);
            while bandwidth.admit(node(SRC), packet, now) {
                admitted += packet;
            }
        }
        assert!((990_000..=1_010_000).contains(&admitted), "{admitted}");
    }

    #[test]
    fn idle_time_does_not_accumulate_beyond_the_burst() {
        let start = Instant::now();
        let mut bandwidth = Bandwidth::new(800, start);
        assert!(bandwidth.admit(node(SRC), 1400, start));
        let later = start + Duration::from_secs(3600);
        let burst = (0..1_000_000).take_while(|_| bandwidth.admit(node(SRC), 1400, later)).count() * 1400;
        // 800 Mbit/s 的 100ms 是 10MB。
        assert!((9_990_000..=10_000_000).contains(&burst), "{burst}");
    }

    /// 每毫秒要转发 `bytes_per_ms` 字节，持续 `seconds` 秒，返回最后的负载。上限是 8 Mbit/s，也就是每毫秒 1000 字节。
    fn offer(bandwidth: &mut Bandwidth, start: Instant, from_ms: u64, seconds: u64, bytes_per_ms: usize) -> Load {
        for millis in from_ms..from_ms + seconds * 1000 {
            bandwidth.admit(node(SRC), bytes_per_ms, start + Duration::from_millis(millis));
        }
        bandwidth.load(start + Duration::from_millis(from_ms + seconds * 1000))
    }

    #[test]
    fn load_is_the_smoothed_share_of_the_cap_that_is_being_offered() {
        let start = Instant::now();
        let mut bandwidth = Bandwidth::new(8, start);
        assert_eq!(bandwidth.load(start), Load { utilisation: 0.0, overloaded: false });

        // 一半的带宽：平滑值逐步靠近 0.5，不是一下子跳过去。
        let after_one = offer(&mut bandwidth, start, 0, 1, 500);
        assert!((0.1..0.2).contains(&after_one.utilisation), "{after_one:?}");
        let settled = offer(&mut bandwidth, start, 1000, 20, 500);
        assert!((0.48..=0.52).contains(&settled.utilisation), "{settled:?}");
        assert!(!settled.overloaded);

        // 停了之后慢慢回落，很久没有流量就是 0。
        let cooling = bandwidth.load(start + Duration::from_secs(23));
        assert!(cooling.utilisation < settled.utilisation && cooling.utilisation > 0.1, "{cooling:?}");
        assert_eq!(bandwidth.load(start + Duration::from_secs(3600)).utilisation, 0.0);
    }

    #[test]
    fn overload_is_declared_at_the_cap_and_cleared_only_well_below_it() {
        let start = Instant::now();
        let mut bandwidth = Bandwidth::new(8, start);
        // 要转发的是上限的一倍半：只有一个来源时它的份额就是整个上限，负载到顶。
        let flooded = offer(&mut bandwidth, start, 0, 20, 1500);
        assert!(flooded.overloaded && flooded.utilisation > OVERLOAD_ENTER, "{flooded:?}");
        // 回落到上限的九成：还在两个门槛之间，仍然算过载。
        let easing = offer(&mut bandwidth, start, 20_000, 20, 900);
        assert!(easing.overloaded && easing.utilisation < 1.0, "{easing:?}");
        let recovered = offer(&mut bandwidth, start, 40_000, 20, 500);
        assert!(!recovered.overloaded, "{recovered:?}");
    }

    /// 两个来源同时要转发，持续 `seconds` 秒：每毫秒 `heavy` 个 1400 字节的包和每 `light_every` 毫秒一个 1400 字节的包，
    /// 灌包的那个总是先来。返回两个各被放行了多少个包，以及最后的负载。
    fn compete(bandwidth: &mut Bandwidth, start: Instant, seconds: u64, heavy: usize, light_every: u64) -> (usize, usize, Load) {
        let (mut heavy_admitted, mut light_admitted) = (0, 0);
        for millis in 0..seconds * 1000 {
            let now = start + Duration::from_millis(millis);
            heavy_admitted += (0..heavy).filter(|_| bandwidth.admit(node(1), 1400, now)).count();
            if millis % light_every == 0 && bandwidth.admit(node(2), 1400, now) {
                light_admitted += 1;
            }
        }
        (heavy_admitted, light_admitted, bandwidth.load(start + Duration::from_secs(seconds)))
    }

    #[test]
    fn a_member_flooding_the_relay_cannot_starve_the_others_or_make_it_declare_overload() {
        let start = Instant::now();
        // 上限每毫秒 1000 字节。一个来源要十倍，另一个只要七分之一（每 10ms 一个包）。
        let mut bandwidth = Bandwidth::new(8, start);
        let (heavy, light, load) = compete(&mut bandwidth, start, 20, 7, 10);
        // 头一秒里灌包的那个还没用够份额，和另一个平起平坐；之后它让路。不分份额的话，另一个几乎一个包都过不去。
        assert!(light >= 1900, "要得少的那个基本没有丢包：2000 个里过了 {light} 个");
        assert!(heavy * 1400 > 20 * 1000 * 800, "空着的额度照样给灌包的那个，没有浪费：{heavy} 个包");
        // 负载里灌包的那个只算它的一半份额，加上另一个的七分之一：远没到过载。
        assert!(!load.overloaded && (0.55..0.75).contains(&load.utilisation), "{load:?}");
    }

    #[test]
    fn senders_that_all_want_more_than_their_share_split_the_cap_and_do_overload_it() {
        let start = Instant::now();
        let mut bandwidth = Bandwidth::new(8, start);
        let (first, second, load) = compete(&mut bandwidth, start, 20, 2, 1);
        let ratio = f64::from(u32::try_from(first).unwrap()) / f64::from(u32::try_from(second).unwrap());
        assert!((0.8..1.25).contains(&ratio), "两个各拿一半左右：{first} 和 {second} 个包");
        let bytes = (first + second) * 1400;
        assert!((19_000_000..=20_200_000).contains(&bytes), "合起来还是上限：{bytes}");
        assert!(load.overloaded, "大家都要满份额，确实满了：{load:?}");
    }

    #[test]
    fn handshakes_are_limited_per_source_and_in_total() {
        let start = Instant::now();
        let mut limiter = HandshakeLimiter::new(start);
        let one: IpAddr = "203.0.113.7".parse().unwrap();
        let burst = (0..100).take_while(|_| limiter.allow(one, start)).count();
        assert_eq!(burst, 10, "一个来源先攒着 10 个");
        assert!(limiter.allow(one, start + Duration::from_millis(200)), "之后每秒 5 个");
        assert!(!limiter.allow(one, start + Duration::from_millis(250)));
        assert!(limiter.allow("203.0.113.8".parse().unwrap(), start), "别的来源不受影响");

        // 很多个来源加起来也有上限。
        let mut limiter = HandshakeLimiter::new(start);
        let source = |index: u32| IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + index));
        let allowed = (0..1000).filter(|&index| limiter.allow(source(index), start)).count();
        assert_eq!(allowed, 200);
    }

    #[test]
    fn an_ipv6_host_cannot_dodge_the_limit_by_changing_addresses_within_its_prefix() {
        let start = Instant::now();
        let mut limiter = HandshakeLimiter::new(start);
        let allowed =
            (1..=100u16).filter(|&host| limiter.allow(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, host)), start)).count();
        assert_eq!(allowed, 10, "同一个 /64 算一个来源");
        assert!(limiter.allow("2001:db8:1:3::1".parse().unwrap(), start), "另一个 /64 是另一个来源");
        assert_eq!(source_key("::ffff:203.0.113.7".parse().unwrap()), "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn the_handshake_limiter_forgets_sources_that_went_quiet() {
        let start = Instant::now();
        let mut limiter = HandshakeLimiter::new(start);
        for index in 0..MAX_HANDSHAKE_SOURCES {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(u32::try_from(index).unwrap()));
            limiter.allow(ip, start + Duration::from_millis(u64::try_from(index).unwrap()));
        }
        assert_eq!(limiter.per_source.len(), MAX_HANDSHAKE_SOURCES);
        limiter.sweep(start + Duration::from_secs(60));
        assert!(limiter.per_source.is_empty(), "额度都攒满了，和没来过一样");
    }

    #[test]
    fn refusals_are_limited_per_source_address() {
        let start = Instant::now();
        let mut limiter = RefusalLimiter::default();
        let (a, b): (SocketAddr, SocketAddr) = ("203.0.113.7:1".parse().unwrap(), "203.0.113.7:2".parse().unwrap());
        assert!(limiter.allow(a, start));
        assert!(!limiter.allow(a, start + Duration::from_millis(999)));
        assert!(limiter.allow(b, start), "别的来源不受影响");
        assert!(limiter.allow(a, start + REFUSAL_INTERVAL));
    }

    #[test]
    fn a_flood_of_sources_cannot_grow_the_table_without_bound() {
        let start = Instant::now();
        let mut limiter = RefusalLimiter::default();
        let source = |index: usize| SocketAddr::from(([10, 0, u8::try_from(index / 256).unwrap(), u8::try_from(index % 256).unwrap()], 9));
        let allowed = (0..MAX_TRACKED_SOURCES + 100).filter(|&index| limiter.allow(source(index), start)).count();
        assert_eq!(allowed, MAX_TRACKED_SOURCES);
        assert_eq!(limiter.last_sent.len(), MAX_TRACKED_SOURCES);
        assert!(limiter.allow(source(MAX_TRACKED_SOURCES + 1), start + REFUSAL_INTERVAL), "旧的过期之后又有位置了");
    }
}
