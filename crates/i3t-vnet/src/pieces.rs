//! 装不进一个数据报的包：发的一方切成两片（`i3t_proto::flow::PacketPieces`），收的一方在这里拼回去。
//!
//! 只在连接刚建立、路径 MTU 还没有探测上去的那一会儿，或者路上的包长一直上不去时才有（网卡的 MTU 见 [`crate::DEFAULT_MTU`]）。
//! 片会丢、会乱序：先到的一片存着，等另一片；等不到就扔。内存有上限：同时最多 [`MAX_PENDING`] 个没拼完的包，每个最多等
//! [`PIECE_WAIT`]，超出时扔最早的。一个对端最多占 [`MAX_PENDING_PER_PEER`] 个，超出时扔它自己最早的：一个对端发来一堆凑不成对的片，
//! 挤不掉别的对端正在等的。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use i3t_proto::NodeId;
use i3t_proto::flow::{Fragment, MAX_PACKET_LEN};

/// 同时最多攒多少个还没拼完的包（所有对端加起来）。每个至多一片，一千多字节：上限是几百 KB。
pub const MAX_PENDING: usize = 256;

/// 一个对端最多同时占多少个。
pub const MAX_PENDING_PER_PEER: usize = MAX_PENDING / 4;

/// 一片最多等另一片多久。两片是一前一后发出去的，正常时差不了一个往返；等不到多半是丢了，上面的协议自己重发。
pub const PIECE_WAIT: Duration = Duration::from_secs(2);

/// 没拼完的包：（对端，包号）到已经到了的那一片。最多 [`MAX_PENDING`] 个，过期的和最早的都直接扫这张表找，不另外记先后。
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

/// 一片收下之后怎样了。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assembled {
    /// 拼成了一个完整的包。
    Packet(Bytes),
    /// 存着，等别的片。
    Waiting,
    /// 这一片和先到的对不上（片数不同、同一片又来一次），或者拼出来太长：两片都扔了。
    Broken,
}

impl Reassembly {
    /// 收下 `peer` 发来的一片。
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
        // 切片最多两片（`MAX_PACKET_PIECES`），所以另一片一到就齐了。
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

    /// 还在等的片有几个。
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// 扔掉最早到的那一片：`peer` 有值时只在它的里面挑。表最多 [`MAX_PENDING`] 个，直接扫。
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
