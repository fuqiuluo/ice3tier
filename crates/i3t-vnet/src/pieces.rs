//! 数据报分片重组：当单个 IP 包超出连接数据报上限时，发送方将其拆分为两片（`i3t_proto::flow::PacketPieces`），接收方在此重组还原。
//!
//! 仅在连接刚建立、路径 MTU 探测尚未提升上限时，或路径最大包长持续受限时触发（虚拟网卡默认 MTU 见 [`crate::DEFAULT_MTU`]）。
//! 分片可能丢失或乱序到达：先到的分片暂存等待配对，超时未齐则丢弃。内存占用严格有界：全局最多缓存 [`MAX_PENDING`] 个未完成包，
//! 单包最长等待 [`PIECE_WAIT`]，超限时淘汰最早记录；单个对端最多占用 [`MAX_PENDING_PER_PEER`] 个槽位，超限时仅淘汰该对端最早记录，
//! 避免单个对端发送大量孤立分片挤占其他对端的重组缓存。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use i3t_proto::NodeId;
use i3t_proto::flow::{Fragment, MAX_PACKET_LEN};

/// 全局同时缓存的未完成分片包上限（所有对端合计）。每条仅存一片（约千余字节），总内存上限为数百 KB。
pub const MAX_PENDING: usize = 256;

/// 单个对端允许同时占用的最大缓存槽位数。
pub const MAX_PENDING_PER_PEER: usize = MAX_PENDING / 4;

/// 单个分片等待另一片的最长时长。两片连续发出，正常情况下间隔不超过一次往返；超时未到通常意味着丢包，交由上层协议重传。
pub const PIECE_WAIT: Duration = Duration::from_secs(2);

/// 未完成分片缓存表：以 `(对端, 消息序号)` 为键存储先到达的分片。容量上限为 [`MAX_PENDING`]，过期清理与淘汰直接线性扫描。
#[derive(Debug, Default)]
pub struct Reassembly {
    pending: HashMap<(NodeId, u16), Partial>,
}

#[derive(Debug)]
struct Partial {
    arrived: Instant,
    count: u8,
    index: u8,
    bytes: Bytes,
}

/// 接收单个数据报分片后的处理结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assembled {
    /// 已重组还原为完整 IP 数据包。
    Packet(Bytes),
    /// 已暂存，等待配对分片到达。
    Waiting,
    /// 当前分片与先到分片元数据冲突（总片数不一致或序号重复），或重组后超出长度上限：两片均予丢弃。
    Broken,
}

impl Reassembly {
    /// 接收来自 `peer` 的一个数据报分片。
    pub fn accept(&mut self, peer: NodeId, fragment: Fragment, bytes: Bytes, now: Instant) -> Assembled {
        self.pending.retain(|_, partial| now.saturating_duration_since(partial.arrived) < PIECE_WAIT);
        let key = (peer, fragment.message);
        let Some(first) = self.pending.remove(&key) else {
            if self.pending.keys().filter(|(from, _)| *from == peer).count() >= MAX_PENDING_PER_PEER {
                self.drop_oldest(Some(peer));
            }
            if self.pending.len() >= MAX_PENDING {
                self.drop_oldest(None);
            }
            self.pending.insert(key, Partial { arrived: now, count: fragment.count, index: fragment.index, bytes });
            return Assembled::Waiting;
        };
        // 协议限定分片最多为 2 片（`MAX_PACKET_PIECES`），因此另一片到达即完成重组。
        if first.count != fragment.count || first.index == fragment.index || fragment.count != 2 {
            return Assembled::Broken;
        }
        let (head, tail) = if first.index < fragment.index { (first.bytes, bytes) } else { (bytes, first.bytes) };
        if head.len() + tail.len() > MAX_PACKET_LEN {
            return Assembled::Broken;
        }
        let mut packet = BytesMut::with_capacity(head.len() + tail.len());
        packet.extend_from_slice(&head);
        packet.extend_from_slice(&tail);
        Assembled::Packet(packet.freeze())
    }

    /// 返回当前等待配对的分片数量。
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// 淘汰最早到达的分片：指定 `peer` 时仅在该对端条目内筛选。因总条目上限为 [`MAX_PENDING`]，直接线性扫描即可。
    fn drop_oldest(&mut self, peer: Option<NodeId>) {
        let oldest = self
            .pending
            .iter()
            .filter(|((from, _), _)| peer.is_none_or(|peer| *from == peer))
            .min_by_key(|(_, partial)| partial.arrived)
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.pending.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use i3t_proto::flow::{PacketHeader, PacketPieces};

    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    /// 把一个包切成两片，返回（分片头，这一片）。
    fn cut(message: u16, packet: &[u8]) -> Vec<(Fragment, Bytes)> {
        PacketPieces::split(message, packet, 1162)
            .unwrap()
            .map(|frame| match PacketHeader::decode(&frame).unwrap() {
                (PacketHeader::Piece(fragment), piece) => (fragment, Bytes::copy_from_slice(piece)),
                (PacketHeader::Whole | PacketHeader::Bundle, _) => panic!("切出来的都是片"),
            })
            .collect()
    }

    #[test]
    fn two_pieces_in_either_order_make_the_packet_again() {
        let packet: Vec<u8> = (0..1280u32).map(|n| u8::try_from(n % 251).unwrap()).collect();
        let now = Instant::now();
        let mut reassembly = Reassembly::default();
        let pieces = cut(7, &packet);
        assert_eq!(reassembly.accept(node(2), pieces[1].0, pieces[1].1.clone(), now), Assembled::Waiting);
        assert_eq!(reassembly.pending(), 1);
        assert_eq!(reassembly.accept(node(2), pieces[0].0, pieces[0].1.clone(), now), Assembled::Packet(Bytes::from(packet.clone())));
        assert_eq!(reassembly.pending(), 0);
        // 同样的包号从另一个对端来，是另一个包。
        let [first, second] = <[_; 2]>::try_from(cut(7, &packet)).unwrap();
        assert_eq!(reassembly.accept(node(3), first.0, first.1, now), Assembled::Waiting);
        assert_eq!(reassembly.accept(node(2), second.0, second.1.clone(), now), Assembled::Waiting);
        assert_eq!(reassembly.pending(), 2);
    }

    #[test]
    fn a_piece_that_waits_too_long_is_dropped_and_a_mismatch_breaks_the_pair() {
        let packet = vec![1; 1300];
        let now = Instant::now();
        let mut reassembly = Reassembly::default();
        let [first, second] = <[_; 2]>::try_from(cut(9, &packet)).unwrap();
        assert_eq!(reassembly.accept(node(2), first.0, first.1.clone(), now), Assembled::Waiting);
        let later = now + PIECE_WAIT;
        assert_eq!(reassembly.accept(node(2), second.0, second.1, later), Assembled::Waiting, "先到的那片已经扔了，这一片重新等");
        assert_eq!(reassembly.pending(), 1);

        let mut reassembly = Reassembly::default();
        assert_eq!(reassembly.accept(node(2), first.0, first.1.clone(), now), Assembled::Waiting);
        assert_eq!(reassembly.accept(node(2), first.0, first.1, now), Assembled::Broken, "同一片来了两次");
        assert_eq!(reassembly.pending(), 0);
    }

    #[test]
    fn memory_is_bounded_by_dropping_the_oldest_waiting_piece() {
        let now = Instant::now();
        let mut reassembly = Reassembly::default();
        let piece = Fragment { message: 0, index: 0, count: 2 };
        for message in 0..u16::try_from(MAX_PENDING + 10).unwrap() {
            let at = now + Duration::from_millis(u64::from(message));
            let peer = node(2 + u32::from(message) % 4);
            assert_eq!(reassembly.accept(peer, Fragment { message, ..piece }, Bytes::from_static(b"x"), at), Assembled::Waiting);
        }
        assert_eq!(reassembly.pending(), MAX_PENDING);
        let mut reassembly = Reassembly::default();
        for message in 0..u16::try_from(MAX_PENDING + 10).unwrap() {
            let at = now + Duration::from_millis(u64::from(message));
            assert_eq!(reassembly.accept(node(2), Fragment { message, ..piece }, Bytes::from_static(b"x"), at), Assembled::Waiting);
        }
        let at = now + Duration::from_millis(300);
        let second = Fragment { message: 0, index: 1, count: 2 };
        assert_eq!(reassembly.accept(node(2), second, Bytes::from_static(b"y"), at), Assembled::Waiting, "最早的那个已经被挤掉了");
        let newest = Fragment { message: u16::try_from(MAX_PENDING + 9).unwrap(), index: 1, count: 2 };
        assert_eq!(reassembly.accept(node(2), newest, Bytes::from_static(b"y"), at), Assembled::Packet(Bytes::from_static(b"xy")));
    }

    #[test]
    fn one_peer_cannot_push_out_the_pieces_another_is_waiting_for() {
        let now = Instant::now();
        let mut reassembly = Reassembly::default();
        let first = Fragment { message: 1, index: 0, count: 2 };
        assert_eq!(reassembly.accept(node(3), first, Bytes::from_static(b"a"), now), Assembled::Waiting);
        for message in 0..u16::try_from(MAX_PENDING * 2).unwrap() {
            let at = now + Duration::from_millis(u64::from(message));
            reassembly.accept(node(2), Fragment { message, index: 0, count: 2 }, Bytes::from_static(b"x"), at);
        }
        assert_eq!(reassembly.pending(), MAX_PENDING_PER_PEER + 1, "node 2 只占得了自己的份额");
        let second = Fragment { message: 1, index: 1, count: 2 };
        assert_eq!(reassembly.accept(node(3), second, Bytes::from_static(b"b"), now), Assembled::Packet(Bytes::from_static(b"ab")));
    }
}
