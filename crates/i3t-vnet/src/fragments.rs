//! 入站 IPv4 分片缓存与校验：在用户态收齐并校验全部分片后，再批量写入虚拟网卡。
//!
//! 操作系统内核的 IP 分片重组缓存在同一网络命名空间内全局共享（Linux 默认约 4 MB，不完整分片超时长达 30 秒），
//! 缓存占满后会影响主机所有网卡的分片重组。若恶意对端持续发送不完整分片即可耗尽内核缓存。因此不完整分片不直接交由内核，
//! 而是按（源 IP、标识、协议）在本模块暂存，直至从 0 到末片连续无缺、互不重叠且末片到达后，再按偏移顺序一并写入虚拟网卡，
//! 使内核即时完成重组并释放资源。超时未收齐的分片在本进程的有界内存内淘汰，且仅影响发送对端自身配额。支持乱序分片重组。
//!
//! 访问控制规则需要依据首片判定（端口及 ICMP 类型均位于首片）：收齐后取首片送入策略检查（[`crate::engine`]），不放行时整包丢弃，
//! 防止后续分片绕过检查单独进入内核。遇到重叠分片直接丢弃整包，避免不同内核的覆盖策略导致首片端口或标志位被篡改
//! （RFC 1858、RFC 3128）。TCP 分片会在进入本模块前即被拒绝。
//!
//! 由于收齐的分片会原样写入虚拟网卡，每片均须满足内核前置合法性检查：若某分片因校验和错误或非法 IP 选项被内核在重组前丢弃，
//! 其余分片将滞留内核缓存。因此本模块要求所有分片不含 IP 选项（头长严格为 20 字节）、IP 头校验和正确、未置 DF 或保留位且 TTL 非 0，
//! 任一条件不满足则丢弃整包。
//!
//! 内存配额：单个对端最多同时缓存 [`MAX_PER_PEER`] 个未完成包、占用 [`PEER_BYTES`] 字节（超限时淘汰该对端最早缓存的包）；
//! 所有对端总计不超过 [`TOTAL_BYTES`] 字节（超限时淘汰占用最多字节的对端中最早缓存的包）。单包自首片到达起最多等待 [`FRAGMENT_WAIT`]。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::ipv4::Ipv4;

/// 单个对端最多同时缓存的未完成分片包数量。正常场景下同一包的分片连续发出，同时在途的通常仅 1–2 个。
pub const MAX_PER_PEER: usize = 64;

/// 单个对端分片缓存占用的最大字节数（含每片元数据开销 [`PIECE_OVERHEAD`]），足以容纳数个最大尺寸 IPv4 包（65535 字节）。
pub const PEER_BYTES: usize = 256 * 1024;

/// 所有对端分片缓存合计占用的最大字节数。
pub const TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// 单个分片包的最长等待时间。分片连续发出时正常延迟不超过一次往返；超时未齐通常意味着丢包，交由上层协议重传。
pub const FRAGMENT_WAIT: Duration = Duration::from_secs(5);

/// 单个数据包允许的最大分片数。按最小 MTU（576 字节）拆分最大 IPv4 包约 120 片，此处预留一定余量。
pub const MAX_PIECES: usize = 192;

/// 每个分片在内存记账时附加的固定开销，用于限制大量微小分片占用过多结构开销。
const PIECE_OVERHEAD: usize = 64;

/// 重组后负载（不含 IP 头）的最大长度：IPv4 最大包长 65535 字节减去 20 字节固定 IP 头。
const MAX_CONTENT: usize = 65535 - 20;

/// 过期分片清理扫描的最小间隔。
const SWEEP_EVERY: Duration = Duration::from_secs(1);

/// 接收单个 IP 分片后的处理结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gathered {
    /// 分片尚未收齐，已暂存等待。
    Waiting,
    /// 全部分片已收齐：按偏移量升序排列（首片位于索引 0）。
    Complete(Vec<Bytes>),
    /// 当前分片自身非法或与已缓存分片冲突：已连同该包已缓存分片一并丢弃。
    Broken(&'static str),
}

/// 入站 IPv4 分片重组缓存表。
#[derive(Debug)]
pub struct Fragments {
    peers: HashMap<Ipv4Addr, Peer>,
    /// 所有对端当前缓存占用的总字节数。
    total: usize,
    swept: Instant,
}

impl Default for Fragments {
    fn default() -> Self {
        Self { peers: HashMap::new(), total: 0, swept: Instant::now() }
    }
}

/// 同一源地址下区分不同分片包的复合键：IP 标识与协议号（目的地址均为本节点虚拟 IP）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    id: u16,
    protocol: u8,
}

/// 单个对端的未完成分片包集合。
#[derive(Debug, Default)]
struct Peer {
    bytes: usize,
    datagrams: HashMap<Key, Datagram>,
}

/// 单个尚未收齐的分片包状态。
#[derive(Debug)]
struct Datagram {
    started: Instant,
    /// 末片声明的完整负载总长度；末片尚未到达时为 `None`。
    end: Option<usize>,
    /// 已到达的有效负载总字节数。由于所有分片互不重叠且不超过末片长度，当该值等于 `end` 时即表示收齐。
    content: usize,
    /// 该包在记账中占用的总字节数。
    cost: usize,
    pieces: Vec<Piece>,
}

#[derive(Debug)]
struct Piece {
    /// 当前分片负载在原数据包负载中的字节区间 `[start, end)`。
    start: usize,
    end: usize,
    packet: Bytes,
}

impl Fragments {
    /// 接收来自对端的单个 IP 分片：`ip` 为已解析的 `packet`，且源、目的地址已通过校验。
    pub fn accept(&mut self, ip: &Ipv4<'_>, packet: Bytes, now: Instant) -> Gathered {
        self.sweep(now);
        let source = ip.source();
        let key = Key { id: ip.identification(), protocol: ip.protocol() };
        let start = ip.fragment_offset();
        let end = start + ip.payload().len();
        let last = !ip.more_fragments();
        if let Err(why) = check_alone(ip, start, end, last) {
            self.remove(source, key);
            return Gathered::Broken(why);
        }
        let cost = packet.len() + PIECE_OVERHEAD;
        self.make_room(source, key, cost);
        let peer = self.peers.entry(source).or_default();
        let datagram = peer.datagrams.entry(key).or_insert_with(|| Datagram::new(now));
        if let Err(why) = datagram.add(Piece { start, end, packet }, last) {
            self.remove(source, key);
            return Gathered::Broken(why);
        }
        datagram.cost += cost;
        peer.bytes += cost;
        self.total += cost;
        if !datagram.is_complete() {
            return Gathered::Waiting;
        }
        let mut pieces = self.remove(source, key).map(|datagram| datagram.pieces).unwrap_or_default();
        pieces.sort_unstable_by_key(|piece| piece.start);
        Gathered::Complete(pieces.into_iter().map(|piece| piece.packet).collect())
    }

    /// 返回当前未收齐的分片包数量。
    #[must_use]
    pub fn pending(&self) -> usize {
        self.peers.values().map(|peer| peer.datagrams.len()).sum()
    }

    /// 返回当前分片缓存占用的总字节数（含每片开销）。
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.total
    }

    /// 为来自 `source`、归属 `key` 且记账大小为 `cost` 的新分片腾出配额：先按单对端上限淘汰该对端最早的包，
    /// 再按全局上限淘汰占用字节最多的对端中最早的包。不淘汰当前正在接收的 `key`。
    fn make_room(&mut self, source: Ipv4Addr, key: Key, cost: usize) {
        while let Some(peer) = self.peers.get(&source) {
            let new = !peer.datagrams.contains_key(&key);
            if !(new && peer.datagrams.len() >= MAX_PER_PEER) && peer.bytes + cost <= PEER_BYTES {
                break;
            }
            let Some(oldest) = peer.oldest(Some(key)) else { break };
            self.remove(source, oldest);
        }
        while self.total + cost > TOTAL_BYTES {
            let victim = self
                .peers
                .iter()
                .filter_map(|(ip, peer)| peer.oldest((*ip == source).then_some(key)).map(|oldest| (peer.bytes, *ip, oldest)))
                .max_by_key(|(bytes, ..)| *bytes);
            let Some((_, ip, oldest)) = victim else { break };
            self.remove(ip, oldest);
        }
    }

    /// 移除并返回指定分片包的状态。
    fn remove(&mut self, source: Ipv4Addr, key: Key) -> Option<Datagram> {
        let peer = self.peers.get_mut(&source)?;
        let datagram = peer.datagrams.remove(&key)?;
        peer.bytes -= datagram.cost;
        self.total -= datagram.cost;
        if peer.datagrams.is_empty() {
            self.peers.remove(&source);
        }
        Some(datagram)
    }

    /// 清理超过 [`FRAGMENT_WAIT`] 仍未收齐的过期包，至多每 [`SWEEP_EVERY`] 执行一次。
    fn sweep(&mut self, now: Instant) {
        if now.saturating_duration_since(self.swept) < SWEEP_EVERY {
            return;
        }
        self.swept = now;
        let mut freed = 0;
        self.peers.retain(|_, peer| {
            peer.datagrams.retain(|_, datagram| {
                let keep = now.saturating_duration_since(datagram.started) < FRAGMENT_WAIT;
                if !keep {
                    peer.bytes -= datagram.cost;
                    freed += datagram.cost;
                }
                keep
            });
            !peer.datagrams.is_empty()
        });
        self.total -= freed;
    }
}

/// 检查单个分片自身的合法性：过滤内核重组前就会丢弃的异常头部，以及非法的负载长度与偏移。
fn check_alone(ip: &Ipv4<'_>, start: usize, end: usize, last: bool) -> Result<(), &'static str> {
    if ip.header_len() != 20 {
        return Err("分片包含 IP 选项");
    }
    if !ip.header_checksum_ok() {
        return Err("IP 头校验和错误");
    }
    if ip.dont_fragment_or_reserved() {
        return Err("分片设置了 DF 或保留标志位");
    }
    if ip.ttl() == 0 {
        return Err("TTL 为 0");
    }
    if end == start {
        return Err("分片负载为空");
    }
    if !last && !(end - start).is_multiple_of(8) {
        return Err("非末片长度不是 8 字节的倍数");
    }
    if end > MAX_CONTENT {
        return Err("重组后长度超出 IPv4 最大限制");
    }
    Ok(())
}

impl Peer {
    /// 返回该对端最早开始缓存的包（跳过 `skip`）。
    fn oldest(&self, skip: Option<Key>) -> Option<Key> {
        self.datagrams.iter().filter(|(key, _)| Some(**key) != skip).min_by_key(|(_, datagram)| datagram.started).map(|(key, _)| *key)
    }
}

impl Datagram {
    fn new(now: Instant) -> Self {
        Self { started: now, end: None, content: 0, cost: 0, pieces: Vec::new() }
    }

    /// 追加一个分片。若与已有分片冲突或超出上限，则保持状态不变并返回错误原因。
    fn add(&mut self, piece: Piece, last: bool) -> Result<(), &'static str> {
        if self.pieces.len() >= MAX_PIECES {
            return Err("单个数据包的分片数量超出上限");
        }
        if self.pieces.iter().any(|other| other.start < piece.end && piece.start < other.end) {
            return Err("分片与已接收分片重叠");
        }
        if last {
            if self.end.is_some() {
                return Err("收到重复的末片");
            }
            if self.pieces.iter().any(|other| other.end > piece.end) {
                return Err("已有分片超出末片声明的总长度");
            }
            self.end = Some(piece.end);
        } else if self.end.is_some_and(|end| piece.end > end) {
            return Err("分片超出末片声明的总长度");
        }
        self.content += piece.end - piece.start;
        self.pieces.push(piece);
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.end == Some(self.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::testing::{header_checksum, icmp, refragment, split, udp};

    const ME: [u8; 4] = [10, 66, 0, 1];
    const B: [u8; 4] = [10, 66, 0, 2];
    const C: [u8; 4] = [10, 66, 0, 3];

    fn give(fragments: &mut Fragments, piece: &[u8], now: Instant) -> Gathered {
        fragments.accept(&Ipv4::parse(piece).unwrap(), Bytes::copy_from_slice(piece), now)
    }

    fn complete(pieces: &[Vec<u8>]) -> Gathered {
        Gathered::Complete(pieces.iter().map(|piece| Bytes::copy_from_slice(piece)).collect())
    }

    #[test]
    fn the_pieces_come_out_together_and_in_order_once_all_have_arrived() {
        let mut fragments = Fragments::default();
        let now = Instant::now();
        let pieces = split(&udp(B, ME, (53, 5000), &[7; 3000]), 1, 1280);
        assert_eq!(pieces.len(), 3);
        assert_eq!(give(&mut fragments, &pieces[2], now), Gathered::Waiting, "最后一片先到");
        assert_eq!(give(&mut fragments, &pieces[0], now), Gathered::Waiting);
        assert_eq!(fragments.pending(), 1);
        assert_eq!(give(&mut fragments, &pieces[1], now), complete(&pieces), "齐了：第一片在前，按先后");
        assert_eq!((fragments.pending(), fragments.bytes()), (0, 0));
    }

    #[test]
    fn pieces_of_different_packets_are_kept_apart() {
        let mut fragments = Fragments::default();
        let now = Instant::now();
        let from_b = split(&udp(B, ME, (53, 5000), &[1; 100]), 9, 48);
        let from_c = split(&udp(C, ME, (53, 5000), &[2; 100]), 9, 48);
        let other_protocol = split(&icmp(B, ME, 0).into_iter().chain([3; 92]).collect::<Vec<u8>>(), 9, 48);
        for pieces in [&from_b, &from_c, &other_protocol] {
            assert_eq!(give(&mut fragments, &pieces[0], now), Gathered::Waiting);
        }
        assert_eq!(fragments.pending(), 3, "标识一样，来源或者协议不一样，是不同的包");
        for pieces in [&from_b, &from_c] {
            assert_eq!(give(&mut fragments, &pieces[1], now), Gathered::Waiting);
            assert_eq!(give(&mut fragments, &pieces[2], now), complete(pieces));
        }
    }

    #[test]
    fn overlapping_or_inconsistent_pieces_break_the_packet() {
        let now = Instant::now();
        let whole = udp(B, ME, (53, 5000), &[5; 100]);
        let pieces = split(&whole, 3, 48);
        let mut fragments = Fragments::default();
        give(&mut fragments, &pieces[0], now);
        // 盖住第一片的后半截（偏移 8）：有的系统拼的时候让它盖掉先到的。
        let mut overlap = whole[..20 + 48].to_vec();
        overlap[2..4].copy_from_slice(&68u16.to_be_bytes());
        assert_eq!(give(&mut fragments, &refragment(overlap, 3, 8, true), now), Gathered::Broken("分片与已接收分片重叠"));
        assert_eq!(fragments.pending(), 0, "攒着的也扔了");
        assert_eq!(give(&mut fragments, &pieces[1], now), Gathered::Waiting, "之后再来的从头攒");

        let mut fragments = Fragments::default();
        give(&mut fragments, &pieces[2], now);
        assert_eq!(give(&mut fragments, &pieces[2], now), Gathered::Broken("分片与已接收分片重叠"), "同一片来两次");
        give(&mut fragments, &pieces[2], now);
        let longer_last = refragment(pieces[1].clone(), 3, 48, false);
        assert_eq!(give(&mut fragments, &longer_last, now), Gathered::Broken("收到重复的末片"));
        give(&mut fragments, &pieces[1], now);
        assert_eq!(give(&mut fragments, &refragment(pieces[2].clone(), 3, 40, false), now), Gathered::Broken("分片与已接收分片重叠"));

        let mut fragments = Fragments::default();
        give(&mut fragments, &pieces[2], now);
        let beyond = refragment(pieces[0].clone(), 3, 112, true);
        assert_eq!(give(&mut fragments, &beyond, now), Gathered::Broken("分片超出末片声明的总长度"));
        give(&mut fragments, &refragment(pieces[1].clone(), 3, 200, true), now);
        assert_eq!(give(&mut fragments, &pieces[2], now), Gathered::Broken("已有分片超出末片声明的总长度"));
    }

    #[test]
    fn a_piece_that_is_wrong_by_itself_is_refused() {
        let now = Instant::now();
        let mut fragments = Fragments::default();
        let odd = refragment(udp(B, ME, (53, 5000), &[1; 13]), 4, 0, true);
        assert_eq!(give(&mut fragments, &odd, now), Gathered::Broken("非末片长度不是 8 字节的倍数"));
        let empty = refragment(crate::ipv4::testing::packet(17, B, ME, &[]), 4, 64, false);
        assert_eq!(give(&mut fragments, &empty, now), Gathered::Broken("分片负载为空"));
        let huge = refragment(udp(B, ME, (53, 5000), &[1; 40]), 4, 65512, false);
        assert_eq!(give(&mut fragments, &huge, now), Gathered::Broken("重组后长度超出 IPv4 最大限制"));
        assert_eq!(fragments.pending(), 0);
    }

    #[test]
    fn a_piece_the_kernel_would_drop_before_reassembly_breaks_the_whole_packet() {
        let now = Instant::now();
        let pieces = split(&icmp(B, ME, 0).into_iter().chain([7; 8]).collect::<Vec<u8>>(), 9, 8);
        assert_eq!(pieces.len(), 2);
        // 第二片带上不合规矩的选项（记录路由，长度写 0），头的校验和是对的：内核在拼片之前就扔掉它，第一片会留在缓存里。
        let mut options = pieces[1][..20].to_vec();
        options[0] = 0x46;
        options[2..4].copy_from_slice(&32u16.to_be_bytes());
        options.extend_from_slice(&[7, 0, 0, 0]);
        options.extend_from_slice(&pieces[1][20..]);
        options[10..12].fill(0);
        let sum = header_checksum(&options[..24]);
        options[10..12].copy_from_slice(&sum.to_be_bytes());
        let mut bad_sum = pieces[1].clone();
        bad_sum[11] ^= 0xff;
        let mut df = pieces[1].clone();
        df[6] |= 0x40;
        let mut reserved = pieces[1].clone();
        reserved[6] |= 0x80;
        let mut no_ttl = pieces[1].clone();
        no_ttl[8] = 0;
        // 改了头之后把校验和重新算对：只让要测的那一条不对。
        let resum = |mut bytes: Vec<u8>| {
            bytes[10..12].fill(0);
            let sum = header_checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&sum.to_be_bytes());
            bytes
        };
        for (piece, why) in [
            (options, "分片包含 IP 选项"),
            (bad_sum, "IP 头校验和错误"),
            (resum(df), "分片设置了 DF 或保留标志位"),
            (resum(reserved), "分片设置了 DF 或保留标志位"),
            (resum(no_ttl), "TTL 为 0"),
        ] {
            let mut fragments = Fragments::default();
            assert_eq!(give(&mut fragments, &pieces[0], now), Gathered::Waiting);
            assert_eq!(give(&mut fragments, &piece, now), Gathered::Broken(why));
            assert_eq!(fragments.pending(), 0, "{why}：第一片也扔了，不会交给内核");
        }
        let mut fragments = Fragments::default();
        give(&mut fragments, &pieces[0], now);
        assert_eq!(give(&mut fragments, &pieces[1], now), complete(&pieces), "对照：两片都是好的");
    }

    #[test]
    fn packets_that_never_complete_are_dropped_after_a_while() {
        let start = Instant::now();
        let mut fragments = Fragments::default();
        let pieces = split(&udp(B, ME, (53, 5000), &[1; 100]), 5, 48);
        give(&mut fragments, &pieces[0], start);
        give(&mut fragments, &pieces[1], start);
        let other = split(&udp(B, ME, (53, 5000), &[1; 100]), 6, 48);
        give(&mut fragments, &other[0], start + FRAGMENT_WAIT);
        assert_eq!(fragments.pending(), 1, "等太久的扔了");
        assert_eq!(give(&mut fragments, &pieces[2], start + FRAGMENT_WAIT), Gathered::Waiting, "最后一片来晚了：前面的已经没了");
    }

    #[test]
    fn a_peer_cannot_hold_more_than_its_share_and_only_loses_its_own_oldest() {
        let start = Instant::now();
        let mut fragments = Fragments::default();
        let first = |source: [u8; 4], id: u16| split(&udp(source, ME, (53, 5000), &[1; 100]), id, 48).remove(0);
        let at = |n: u16| start + Duration::from_millis(u64::from(n));
        give(&mut fragments, &first(C, 1), start);
        for id in 0..u16::try_from(MAX_PER_PEER + 5).unwrap() {
            assert_eq!(give(&mut fragments, &first(B, id), at(id)), Gathered::Waiting);
        }
        assert_eq!(fragments.pending(), MAX_PER_PEER + 1, "B 最多攒这么多个，C 的那个还在");
        let rest_of_c = split(&udp(C, ME, (53, 5000), &[1; 100]), 1, 48);
        give(&mut fragments, &rest_of_c[1], at(100));
        assert_eq!(give(&mut fragments, &rest_of_c[2], at(100)), complete(&rest_of_c));
        let rest_of_oldest = split(&udp(B, ME, (53, 5000), &[1; 100]), 0, 48);
        assert_eq!(give(&mut fragments, &rest_of_oldest[1], at(100)), Gathered::Waiting);
        assert_eq!(give(&mut fragments, &rest_of_oldest[2], at(100)), Gathered::Waiting, "B 最早的那个已经被挤掉了，拼不齐");

        // 字节数的上限：几个很大的包，都差最后一片。
        let mut fragments = Fragments::default();
        let big = |id: u16| split(&udp(B, ME, (53, 5000), &[1; 60000]), id, 1480);
        for id in 0..6 {
            let pieces = big(id);
            for piece in &pieces[..pieces.len() - 1] {
                give(&mut fragments, piece, at(id));
                assert!(fragments.bytes() <= PEER_BYTES, "{}", fragments.bytes());
            }
        }
        assert!(fragments.pending() < 6, "早的被挤掉了");
        let newest = big(5);
        assert_eq!(give(&mut fragments, newest.last().unwrap(), at(10)), complete(&newest), "正在攒的那个不挤");
    }

    #[test]
    fn all_peers_together_stay_under_the_total_and_the_biggest_gives_way() {
        let start = Instant::now();
        let mut fragments = Fragments::default();
        let mut n = 0u64;
        for host in 2..=70u8 {
            for id in 0..u16::try_from(MAX_PER_PEER).unwrap() {
                n += 1;
                let piece = split(&udp([10, 66, 1, host], ME, (53, 5000), &[1; 3000]), id, 1480).remove(0);
                give(&mut fragments, &piece, start + Duration::from_micros(n));
                assert!(fragments.bytes() <= TOTAL_BYTES);
            }
        }
        assert!(fragments.bytes() > TOTAL_BYTES - PEER_BYTES, "满了：{}", fragments.bytes());
        let peers = fragments.peers.len();
        let small = split(&udp(B, ME, (53, 5000), &[1; 100]), 1, 48);
        give(&mut fragments, &small[0], start + Duration::from_secs(1));
        assert_eq!(fragments.peers.len(), peers + 1, "新来的对端也攒得下");
        give(&mut fragments, &small[1], start + Duration::from_secs(1));
        assert_eq!(give(&mut fragments, &small[2], start + Duration::from_secs(1)), complete(&small));
    }
}
