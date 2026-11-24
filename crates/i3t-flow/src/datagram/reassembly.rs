//! 把切成几片的数据报拼回去。
//!
//! 片是走不可靠的通道来的：会丢、会重复、会乱序，不同报文的片会夹在一起。拼不齐的报文不能一直留着，
//! 所以每个对端用的内存有上限，拼到一半的报文过一小会儿就扔掉。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use i3t_proto::flow::{Fragment, MAX_DATAGRAM_BODY_LEN};

/// 一个报文从收到第一片起，多久拼不齐就扔掉。各片是一口气发出来的，正常情况下前后脚到；
/// 留出几秒是给很慢的链路：一个切成几十片的大报文在几百 kbit/s 的链路上要发一两秒。
pub(crate) const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(3);

/// 一个对端同时拼着的报文最多多少个。再来新的报文时，最老的那个被扔掉。
const MAX_MESSAGES: usize = 16;

/// 一个对端拼到一半的报文加起来最多占多少字节。超过时从最老的扔起。
const MAX_BUFFERED: usize = 4 * MAX_DATAGRAM_BODY_LEN;

/// 一个报文是谁：哪个上下文的第几个报文。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    context: u32,
    message: u16,
}

/// 拼到一半的报文。
#[derive(Debug)]
struct Partial {
    started: Instant,
    /// 每一片一个位置，按片序号。
    pieces: Vec<Option<Bytes>>,
    missing: usize,
    len: usize,
}

/// 一个对端发来的分片，按报文拼。
#[derive(Debug, Default)]
pub(crate) struct Reassembler {
    messages: HashMap<Key, Partial>,
    buffered: usize,
}

impl Reassembler {
    /// 收下一片。它把一个报文补齐了的话，返回完整的内容。
    ///
    /// 重复分片会被忽略；与同一报文已有分片总数不一致的分片会被丢弃；
    /// 拼起来会超过 [`MAX_DATAGRAM_BODY_LEN`] 的报文整个扔掉。
    pub(crate) fn push(&mut self, context: u32, fragment: Fragment, piece: Bytes, now: Instant) -> Option<Bytes> {
        self.expire(now);
        let key = Key { context, message: fragment.message };
        let (index, count) = (usize::from(fragment.index), usize::from(fragment.count));
        if index >= count {
            return None;
        }

        // 新的报文要占一个位置：先腾出来，再放进去。
        if self.messages.len() >= MAX_MESSAGES && !self.messages.contains_key(&key) {
            self.evict_oldest_except(key);
        }
        let partial =
            self.messages.entry(key).or_insert_with(|| Partial { started: now, pieces: vec![None; count], missing: count, len: 0 });
        if partial.pieces.len() != count || partial.pieces[index].is_some() {
            return None;
        }
        if partial.len + piece.len() > MAX_DATAGRAM_BODY_LEN {
            self.remove(key);
            return None;
        }
        partial.len += piece.len();
        partial.missing -= 1;
        self.buffered += piece.len();
        partial.pieces[index] = Some(piece);

        if partial.missing == 0 {
            let complete = self.remove(key)?;
            let mut body = BytesMut::with_capacity(complete.len);
            complete.pieces.iter().flatten().for_each(|piece| body.extend_from_slice(piece));
            return Some(body.freeze());
        }
        while self.buffered > MAX_BUFFERED && self.messages.len() > 1 {
            self.evict_oldest_except(key);
        }
        None
    }

    /// 一个上下文结束了：它拼到一半的报文不会再有人要。
    pub(crate) fn forget(&mut self, context: u32) {
        let stale: Vec<Key> = self.messages.keys().filter(|key| key.context == context).copied().collect();
        for key in stale {
            self.remove(key);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    fn expire(&mut self, now: Instant) {
        let stale: Vec<Key> = self
            .messages
            .iter()
            .filter(|(_, partial)| now.saturating_duration_since(partial.started) >= REASSEMBLY_TIMEOUT)
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            self.remove(key);
        }
    }

    fn evict_oldest_except(&mut self, keep: Key) {
        let oldest = self.messages.iter().filter(|(key, _)| **key != keep).min_by_key(|(_, partial)| partial.started).map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.remove(key);
        }
    }

    fn remove(&mut self, key: Key) -> Option<Partial> {
        let partial = self.messages.remove(&key)?;
        self.buffered -= partial.len;
        Some(partial)
    }
}

#[cfg(test)]
mod tests {
    use i3t_proto::flow::{DatagramHeader, Frames, Recipient};

    use super::*;

    /// 把 `body` 切成每片最多 `piece_len` 字节的分片。
    fn pieces(message: u16, body: &[u8], piece_len: usize) -> Vec<(Fragment, Bytes)> {
        let frames = Frames::split(Recipient::Acceptor, 1, message, body, DatagramHeader::FRAGMENT_LEN + piece_len).unwrap();
        frames
            .map(|frame| {
                let (header, piece) = DatagramHeader::decode(&frame).unwrap();
                (header.fragment.expect("装不下的内容每一帧都带分片头"), Bytes::copy_from_slice(piece))
            })
            .collect()
    }

    fn body(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|index| seed.wrapping_add(u8::try_from(index % 251).unwrap())).collect()
    }

    /// 把一个报文的片按给定的顺序喂进去，返回每一次的结果。
    fn feed(
        reassembler: &mut Reassembler,
        context: u32,
        pieces: &[(Fragment, Bytes)],
        order: &[usize],
        now: Instant,
    ) -> Vec<Option<Bytes>> {
        order.iter().map(|&index| reassembler.push(context, pieces[index].0, pieces[index].1.clone(), now)).collect()
    }

    #[test]
    fn pieces_in_any_order_come_back_as_the_original_body() {
        let original = body(2500, 3);
        let cut = pieces(7, &original, 1000);
        assert_eq!(cut.len(), 3);
        let now = Instant::now();
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
            let mut reassembler = Reassembler::default();
            let results = feed(&mut reassembler, 1, &cut, &order, now);
            assert_eq!(results[..2], [None, None], "{order:?}");
            assert_eq!(results[2].as_deref(), Some(&original[..]), "{order:?}");
            assert!(reassembler.is_empty() && reassembler.buffered == 0, "拼完之后不留东西");
        }
    }

    #[test]
    fn a_message_with_a_lost_piece_never_completes_and_is_dropped_after_the_timeout() {
        let cut = pieces(7, &body(2500, 3), 1000);
        let mut reassembler = Reassembler::default();
        let start = Instant::now();
        assert_eq!(feed(&mut reassembler, 1, &cut, &[0, 2], start), [None, None]);
        assert_eq!(reassembler.buffered, 1500);

        // 时限之内，别的报文照常拼，它还留着。
        let other = pieces(8, &body(1200, 9), 1000);
        let almost = start + REASSEMBLY_TIMEOUT - Duration::from_millis(1);
        assert_eq!(feed(&mut reassembler, 1, &other, &[0, 1], almost)[1].as_deref(), Some(&body(1200, 9)[..]));
        assert_eq!(reassembler.messages.len(), 1);

        // 过了时限它被扔掉；迟到的那一片不会把它补齐，只是又开了一个注定拼不齐的，它自己也会过期。
        let late = start + REASSEMBLY_TIMEOUT;
        assert_eq!(reassembler.push(1, cut[1].0, cut[1].1.clone(), late), None);
        assert_eq!(reassembler.buffered, 1000);
        assert_eq!(reassembler.push(1, other[0].0, other[0].1.clone(), late + REASSEMBLY_TIMEOUT), None);
        assert_eq!((reassembler.messages.len(), reassembler.buffered), (1, 1000), "只剩刚来的这一片");
    }

    #[test]
    fn duplicate_pieces_are_ignored() {
        let original = body(2500, 3);
        let cut = pieces(7, &original, 1000);
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        assert_eq!(feed(&mut reassembler, 1, &cut, &[0, 0, 1, 1, 0], now), [None, None, None, None, None]);
        assert_eq!(reassembler.buffered, 2000, "重复的片不占地方");
        assert_eq!(reassembler.push(1, cut[2].0, cut[2].1.clone(), now).as_deref(), Some(&original[..]));
        // 拼完之后再来的重复片只会开一个拼不齐的报文，不会让同一个报文交出去两次。
        assert_eq!(feed(&mut reassembler, 1, &cut, &[2], now), [None]);
    }

    #[test]
    fn interleaved_messages_and_contexts_are_kept_apart() {
        let (first, second, third) = (body(2500, 1), body(2100, 50), body(1800, 100));
        let (a, b, c) = (pieces(1, &first, 1000), pieces(2, &second, 1000), pieces(1, &third, 1000));
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        // 同一个上下文的两个报文，加上另一个上下文里报文号相同的一个，片全部夹在一起。
        assert_eq!(reassembler.push(1, a[0].0, a[0].1.clone(), now), None);
        assert_eq!(reassembler.push(1, b[2].0, b[2].1.clone(), now), None);
        assert_eq!(reassembler.push(2, c[1].0, c[1].1.clone(), now), None);
        assert_eq!(reassembler.push(1, a[2].0, a[2].1.clone(), now), None);
        assert_eq!(reassembler.push(1, b[0].0, b[0].1.clone(), now), None);
        assert_eq!(reassembler.push(2, c[0].0, c[0].1.clone(), now).as_deref(), Some(&third[..]));
        assert_eq!(reassembler.push(1, b[1].0, b[1].1.clone(), now).as_deref(), Some(&second[..]));
        assert_eq!(reassembler.push(1, a[1].0, a[1].1.clone(), now).as_deref(), Some(&first[..]));
        assert!(reassembler.is_empty());
    }

    #[test]
    fn pieces_that_contradict_the_message_they_claim_to_belong_to_are_dropped() {
        let original = body(2500, 3);
        let cut = pieces(7, &original, 1000);
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        assert_eq!(reassembler.push(1, cut[0].0, cut[0].1.clone(), now), None);
        // 同一个报文号，片数却不一样。
        let liar = Fragment { message: 7, index: 1, count: 2 };
        assert_eq!(reassembler.push(1, liar, Bytes::from_static(b"x"), now), None);
        // 片序号超出片数（解析帧的时候就会被拒绝，这里再挡一次）。
        let beyond = Fragment { message: 7, index: 3, count: 3 };
        assert_eq!(reassembler.push(1, beyond, Bytes::from_static(b"x"), now), None);
        // 原来的报文不受影响。
        assert_eq!(feed(&mut reassembler, 1, &cut, &[1, 2], now)[1].as_deref(), Some(&original[..]));
    }

    #[test]
    fn the_largest_body_is_reassembled_and_anything_larger_is_thrown_away() {
        let largest = body(MAX_DATAGRAM_BODY_LEN, 5);
        let cut = pieces(1, &largest, 1100);
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        let order: Vec<usize> = (0..cut.len()).collect();
        assert_eq!(feed(&mut reassembler, 1, &cut, &order, now).pop().unwrap().as_deref(), Some(&largest[..]));

        // 255 片、每片 300 字节：到第 219 片就超过了上限，整个报文被扔掉，后面的片也拼不出东西。
        let piece = Bytes::from(vec![0; 300]);
        let mut completed = 0;
        for index in 0..=254u8 {
            let fragment = Fragment { message: 2, index, count: 255 };
            completed += usize::from(reassembler.push(1, fragment, piece.clone(), now).is_some());
            assert!(reassembler.buffered <= MAX_DATAGRAM_BODY_LEN);
        }
        assert_eq!(completed, 0);
    }

    #[test]
    fn memory_per_peer_is_bounded_by_dropping_the_oldest_unfinished_messages() {
        let mut reassembler = Reassembler::default();
        let start = Instant::now();
        // 一百个报文，每个都只来第一片（60000 字节），而且都还没过期。
        let piece = Bytes::from(vec![0; 60_000]);
        for message in 0..100u16 {
            let now = start + Duration::from_millis(u64::from(message));
            assert_eq!(reassembler.push(1, Fragment { message, index: 0, count: 2 }, piece.clone(), now), None);
            assert!(reassembler.messages.len() <= MAX_MESSAGES);
            assert!(reassembler.buffered <= MAX_BUFFERED, "{}", reassembler.buffered);
        }
        // 留下来的是最新的那几个：最后一个报文的第二片还补得齐。
        let last = Fragment { message: 99, index: 1, count: 2 };
        assert_eq!(
            reassembler.push(1, last, Bytes::from_static(b"tail"), start + Duration::from_millis(100)).map(|body| body.len()),
            Some(60_004)
        );
        // 最早的那些已经被扔了。
        let first = Fragment { message: 0, index: 1, count: 2 };
        assert_eq!(reassembler.push(1, first, Bytes::from_static(b"tail"), start + Duration::from_millis(100)), None);

        // 很多小报文：个数也有上限。
        let mut reassembler = Reassembler::default();
        for message in 0..100u16 {
            reassembler.push(1, Fragment { message, index: 0, count: 2 }, Bytes::from_static(b"x"), start);
        }
        assert_eq!(reassembler.messages.len(), MAX_MESSAGES);
    }

    #[test]
    fn a_finished_context_takes_its_unfinished_messages_with_it() {
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        let piece = Bytes::from(vec![0; 1000]);
        for (context, message) in [(1, 1), (1, 2), (2, 1)] {
            reassembler.push(context, Fragment { message, index: 0, count: 2 }, piece.clone(), now);
        }
        reassembler.forget(1);
        assert_eq!((reassembler.messages.len(), reassembler.buffered), (1, 1000));
        reassembler.forget(2);
        assert!(reassembler.is_empty() && reassembler.buffered == 0);
    }
}
