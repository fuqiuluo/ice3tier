//! 虚拟网卡上的一个 IP 包在连接的数据报通道里的样子，以及连接层按首字节把数据报交给谁。
//! 逐字节的格式在上一级模块的文档里。

use std::slice::Chunks;

use super::dgram::{FLAG_FRAGMENT, FLAG_TO_INITIATOR, Fragment, FrameError, Recipient};

/// 首字节里的这一位说明这是一个网络包帧。比它旧的节点把这一位当作保留位，带着它的数据报一律丢掉。
const FLAG_PACKET: u8 = 0b0000_0100;
/// 网络包帧的首字节里的这一位说明帧里合着好几个包（[`PacketHeader::Bundle`]）。不认识它的节点把它当作保留位，
/// 这样的帧一律丢掉，所以只发给握手时说过自己认识的对端。
const FLAG_BUNDLE: u8 = 0b0000_1000;
/// 网络包帧的首字节里必须是 0 的位：bit 0（数据报上下文才分接受方和发起方）和 bit 4～7。
const PACKET_RESERVED: u8 = 0b1111_0000 | FLAG_TO_INITIATOR;

/// 一个网络包最长多少字节：IPv4 头里的总长度是 16 位。收的一方按它限制拼包用的内存。
pub const MAX_PACKET_LEN: usize = u16::MAX as usize;

/// 一个网络包最多切成几片。
///
/// 虚拟网卡的 MTU（1280）只比连接刚建立时一个数据报装得下的（一千一百多字节）大一点，两片总是够的；
/// QUIC 要求路径至少送得了 1200 字节的包，所以一个数据报不会比这还小。切成更多片的帧收的一方当作坏帧丢掉。
pub const MAX_PACKET_PIECES: u8 = 2;

/// 连接层收到的一个不保证送达的数据报交给谁，只看首字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// 数据报上下文的数据报，交给上下文的这一侧。
    Context(Recipient),
    /// 虚拟网卡的包。
    Packet,
}

impl Channel {
    /// 空的帧、首字节里有这个程序不认识的位的帧返回 `None`，应该直接丢掉。
    #[must_use]
    pub fn peek(frame: &[u8]) -> Option<Self> {
        let &flags = frame.first()?;
        if flags & FLAG_PACKET == 0 {
            return Recipient::peek(frame).map(Self::Context);
        }
        (flags & PACKET_RESERVED == 0).then_some(Self::Packet)
    }
}

/// 网络包帧开头的头。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketHeader {
    /// 后面是一个完整的 IP 包。
    Whole,
    /// 后面是一个 IP 包的一片。
    Piece(Fragment),
    /// 后面合着好几个完整的 IP 包，每个前面是它的长度（[`Bundled`]）。
    Bundle,
}

impl PacketHeader {
    /// 不分片时头占多少字节。
    pub const WHOLE_LEN: usize = 1;
    /// 分片时头占多少字节。
    pub const PIECE_LEN: usize = 1 + 2 + 1 + 1;
    /// 不分片的帧的首字节：头就是它。发的一方可以先把它放在缓冲区的第一个字节，再把 IP 包直接读到后面，不用再拷一次。
    pub const WHOLE_BYTE: u8 = FLAG_PACKET;
    /// 合着好几个包的帧，头占多少字节。
    pub const BUNDLE_LEN: usize = 1;

    /// 把头追加到 `buf` 末尾，IP 包（或者它的一片）直接接在后面。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Whole => buf.push(Self::WHOLE_BYTE),
            Self::Bundle => buf.push(FLAG_PACKET | FLAG_BUNDLE),
            Self::Piece(piece) => {
                buf.push(FLAG_PACKET | FLAG_FRAGMENT);
                buf.extend_from_slice(&piece.message.to_be_bytes());
                buf.extend_from_slice(&[piece.index, piece.count]);
            }
        }
    }

    /// 解析一帧，返回头和它后面的字节（一个完整的 IP 包，它的一片，或者合在一起的几个包，那用 [`Bundled`] 读）。
    /// 不检查 IP 包本身。
    ///
    /// # Errors
    ///
    /// 不是网络包帧、标志里有不认识的位、帧比头还短，或者头自相矛盾（片数不在 2～[`MAX_PACKET_PIECES`] 之间、
    /// 片序号不小于片数，又是一片又合着好几个包）。这样的帧应该直接丢掉。
    pub fn decode(frame: &[u8]) -> Result<(Self, &[u8]), FrameError> {
        let truncated = FrameError::Truncated { len: frame.len() };
        let (&flags, rest) = frame.split_first().ok_or(truncated)?;
        if flags & FLAG_PACKET == 0 || flags & PACKET_RESERVED != 0 {
            return Err(FrameError::ReservedFlags(flags));
        }
        if flags & FLAG_BUNDLE != 0 {
            // 合在一起的都是完整的小包，不会再切。
            return if flags & FLAG_FRAGMENT == 0 { Ok((Self::Bundle, rest)) } else { Err(FrameError::ReservedFlags(flags)) };
        }
        if flags & FLAG_FRAGMENT == 0 {
            return Ok((Self::Whole, rest));
        }
        let (&[m0, m1, index, count], rest) = rest.split_first_chunk().ok_or(truncated)?;
        if !(2..=MAX_PACKET_PIECES).contains(&count) || index >= count {
            return Err(FrameError::InvalidFragment { index, count });
        }
        Ok((Self::Piece(Fragment { message: u16::from_be_bytes([m0, m1]), index, count }), rest))
    }
}

/// 合在一帧里的各个 IP 包，按发的一方放进去的顺序。
///
/// 帧的头（[`PacketHeader::Bundle`]）后面每个包是两字节的长度（大端）接着包本身，一个挨一个到帧的末尾。
/// 读到坏的地方给出一个错误，然后就结束：坏的那个之前的包是好的。
#[derive(Debug, Clone)]
pub struct Bundled<'a> {
    rest: &'a [u8],
    /// 下一个是第几个，从 0 数。
    index: usize,
    broken: bool,
}

impl<'a> Bundled<'a> {
    /// 每个包前面的长度占多少字节。
    pub const PREFIX_LEN: usize = 2;

    /// `body` 是 [`PacketHeader::decode`] 给出的、头后面的字节。
    #[must_use]
    pub const fn new(body: &'a [u8]) -> Self {
        Self { rest: body, index: 0, broken: false }
    }

    /// 把一个包接到 `frame` 后面（`frame` 里已经有头，也许还有别的包）：先是它的长度，然后是它。
    ///
    /// # Errors
    ///
    /// 包是空的，或者超过 [`MAX_PACKET_LEN`]：长度写不进两个字节。`frame` 不变。
    pub fn push(frame: &mut Vec<u8>, packet: &[u8]) -> Result<(), PieceError> {
        let len = u16::try_from(packet.len()).ok().filter(|len| *len != 0).ok_or(PieceError::PacketTooLarge { len: packet.len() })?;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(packet);
        Ok(())
    }
}

impl<'a> Iterator for Bundled<'a> {
    type Item = Result<&'a [u8], FrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        // 一个包都没有的帧也是坏的：发的一方不会发。
        if self.broken || (self.rest.is_empty() && self.index != 0) {
            return None;
        }
        let packet = self.rest.split_first_chunk().and_then(|(&len, rest)| {
            let len = usize::from(u16::from_be_bytes(len));
            (len != 0).then(|| rest.split_at_checked(len)).flatten()
        });
        let Some((packet, rest)) = packet else {
            self.broken = true;
            return Some(Err(FrameError::BrokenBundle { index: self.index }));
        };
        self.rest = rest;
        self.index += 1;
        Some(Ok(packet))
    }
}

/// 一个装不下一帧的 IP 包切成的帧，按片序号的顺序。除了最后一片，每一帧都正好是 `max_len` 字节。
#[derive(Debug, Clone)]
pub struct PacketPieces<'a> {
    message: u16,
    count: u8,
    next: u8,
    chunks: Chunks<'a, u8>,
}

impl<'a> PacketPieces<'a> {
    /// 把 `packet` 切成每帧不超过 `max_len` 字节的几片。`message` 是这个包的包号：同一个对端最近切过的包里不重复就行。
    ///
    /// 只在一帧装不下的时候用：装得下的包用 [`PacketHeader::Whole`] 发，不带分片头。
    ///
    /// # Errors
    ///
    /// 包超过 [`MAX_PACKET_LEN`]，或者切成 [`MAX_PACKET_PIECES`] 片也装不下。
    pub fn split(message: u16, packet: &'a [u8], max_len: usize) -> Result<Self, PieceError> {
        if packet.len() > MAX_PACKET_LEN {
            return Err(PieceError::PacketTooLarge { len: packet.len() });
        }
        // 装得下一帧的包不该来这里：照样切的话，分片头比整包的头长，可能切出一片空的。
        if packet.len() + PacketHeader::WHOLE_LEN <= max_len {
            return Err(PieceError::FitsWhole { len: packet.len(), max_len });
        }
        let room = max_len.saturating_sub(PacketHeader::PIECE_LEN);
        let count = if room == 0 { usize::MAX } else { packet.len().div_ceil(room) };
        match u8::try_from(count) {
            Ok(count) if (2..=MAX_PACKET_PIECES).contains(&count) => Ok(Self { message, count, next: 0, chunks: packet.chunks(room) }),
            _ => Err(PieceError::FrameTooSmall { len: packet.len(), max_len }),
        }
    }
}

impl Iterator for PacketPieces<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        let chunk = self.chunks.next()?;
        let header = PacketHeader::Piece(Fragment { message: self.message, index: self.next, count: self.count });
        // 片序号最大是片数减一，加一不会溢出。
        self.next += 1;
        let mut frame = Vec::with_capacity(PacketHeader::PIECE_LEN + chunk.len());
        header.encode(&mut frame);
        frame.extend_from_slice(chunk);
        Some(frame)
    }
}

/// 一个网络包切不了的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PieceError {
    #[error("网络包有 {len} 字节，最短 1 字节，最长 {MAX_PACKET_LEN} 字节")]
    PacketTooLarge { len: usize },
    #[error("连接一次只能发 {max_len} 字节的数据报，{len} 字节的网络包切成 {MAX_PACKET_PIECES} 片也装不下")]
    FrameTooSmall { len: usize, max_len: usize },
    #[error("{len} 字节的网络包一帧（{max_len} 字节）就装得下，不用切")]
    FitsWhole { len: usize, max_len: usize },
}

// 片数要能写进一个字节。
const _: () = assert!(MAX_PACKET_PIECES >= 2);

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(packet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        PacketPieces::split(0x0102, packet, max_len).unwrap().collect()
    }

    #[test]
    fn a_whole_packet_has_the_documented_one_byte_header() {
        let mut frame = Vec::new();
        PacketHeader::Whole.encode(&mut frame);
        frame.extend_from_slice(b"\x45ip");
        assert_eq!(frame, [0x04, 0x45, b'i', b'p']);
        assert_eq!(PacketHeader::decode(&frame), Ok((PacketHeader::Whole, &b"\x45ip"[..])));
        assert_eq!(frame[0], PacketHeader::WHOLE_BYTE);
        assert_eq!(Channel::peek(&frame), Some(Channel::Packet));
    }

    fn bundle(packets: &[&[u8]]) -> Vec<u8> {
        let mut frame = Vec::new();
        PacketHeader::Bundle.encode(&mut frame);
        for packet in packets {
            Bundled::push(&mut frame, packet).unwrap();
        }
        frame
    }

    #[test]
    fn several_packets_in_one_frame_have_the_documented_layout_and_come_out_in_order() {
        let frame = bundle(&[b"\x45ip", b"\x45x"]);
        assert_eq!(frame, [0x0c, 0, 3, 0x45, b'i', b'p', 0, 2, 0x45, b'x']);
        assert_eq!(Channel::peek(&frame), Some(Channel::Packet), "连接层照旧把它交给虚拟网卡");
        let (header, body) = PacketHeader::decode(&frame).unwrap();
        assert_eq!(header, PacketHeader::Bundle);
        let packets: Vec<_> = Bundled::new(body).collect();
        assert_eq!(packets, [Ok(&b"\x45ip"[..]), Ok(&b"\x45x"[..])]);
        assert_eq!(frame.len(), PacketHeader::BUNDLE_LEN + 2 * Bundled::PREFIX_LEN + 5);
    }

    #[test]
    fn a_bundle_that_does_not_add_up_gives_its_good_packets_and_then_one_error() {
        let good = bundle(&[b"\x45one", b"\x45two"]);
        let body = &good[PacketHeader::BUNDLE_LEN..];
        let read = |body| Bundled::new(body).collect::<Vec<_>>();
        // 第二个包被截短；只剩一个字节的长度；长度写的是 0。
        assert_eq!(read(&body[..body.len() - 1]), [Ok(&b"\x45one"[..]), Err(FrameError::BrokenBundle { index: 1 })]);
        assert_eq!(read(&body[..7]), [Ok(&b"\x45one"[..]), Err(FrameError::BrokenBundle { index: 1 })]);
        assert_eq!(read(&[0, 0, 0x45]), [Err(FrameError::BrokenBundle { index: 0 })]);
        assert_eq!(read(&[]), [Err(FrameError::BrokenBundle { index: 0 })], "一个包都没有");
        // 一片不能同时又是合在一起的；别的保留位照旧不认。
        assert_eq!(PacketHeader::decode(&[0x0e, 0, 1, 0, 2]), Err(FrameError::ReservedFlags(0x0e)));
        assert_eq!(PacketHeader::decode(&[0x14, 0x45]), Err(FrameError::ReservedFlags(0x14)));
        assert_eq!(Channel::peek(&[0x14, 0x45]), None);
    }

    #[test]
    fn a_packet_too_long_for_its_length_field_or_empty_cannot_be_bundled() {
        let mut frame = vec![0x0c];
        assert_eq!(Bundled::push(&mut frame, &[]), Err(PieceError::PacketTooLarge { len: 0 }));
        assert_eq!(Bundled::push(&mut frame, &vec![0; MAX_PACKET_LEN + 1]), Err(PieceError::PacketTooLarge { len: MAX_PACKET_LEN + 1 }));
        assert_eq!(frame, [0x0c], "放不进去的不留半截");
    }

    #[test]
    fn a_packet_that_does_not_fit_is_cut_into_two_pieces_with_the_documented_header() {
        let packet: Vec<u8> = (0..=u8::MAX).cycle().take(1280).collect();
        let cut = pieces(&packet, 1162);
        assert_eq!(cut.len(), 2);
        assert_eq!(cut[0].len(), 1162, "第一片填满");
        assert_eq!(cut[0][..PacketHeader::PIECE_LEN], [0x06, 0x01, 0x02, 0, 2]);
        assert_eq!(cut[1][..PacketHeader::PIECE_LEN], [0x06, 0x01, 0x02, 1, 2]);
        let mut rebuilt = Vec::new();
        for (index, frame) in cut.iter().enumerate() {
            let (header, piece) = PacketHeader::decode(frame).unwrap();
            let expected = Fragment { message: 0x0102, index: u8::try_from(index).unwrap(), count: 2 };
            assert_eq!(header, PacketHeader::Piece(expected));
            assert_eq!(Channel::peek(frame), Some(Channel::Packet));
            rebuilt.extend_from_slice(piece);
        }
        assert_eq!(rebuilt, packet);
    }

    #[test]
    fn packets_that_cannot_or_need_not_be_cut_are_refused() {
        let split = |len: usize, max_len| PacketPieces::split(1, &vec![0; len], max_len).map(Iterator::count);
        assert_eq!(split(1279, 1280), Err(PieceError::FitsWhole { len: 1279, max_len: 1280 }));
        // 差一个字节装不下：分片头长 4 字节，两片都不空。
        let barely: Vec<usize> = PacketPieces::split(1, &[0; 1280], 1280).unwrap().map(|frame| frame.len()).collect();
        assert_eq!(barely, [1280, 1280 - (1280 - PacketHeader::PIECE_LEN) + PacketHeader::PIECE_LEN]);
        // 两片正好装满。
        assert_eq!(split(2 * (1000 - PacketHeader::PIECE_LEN), 1000), Ok(2));
        assert_eq!(split(2 * (1000 - PacketHeader::PIECE_LEN) + 1, 1000), Err(PieceError::FrameTooSmall { len: 1991, max_len: 1000 }));
        assert_eq!(split(100, PacketHeader::PIECE_LEN), Err(PieceError::FrameTooSmall { len: 100, max_len: 5 }));
        assert_eq!(split(MAX_PACKET_LEN + 1, usize::MAX), Err(PieceError::PacketTooLarge { len: MAX_PACKET_LEN + 1 }));
    }

    #[test]
    fn malformed_packet_frames_are_rejected() {
        assert_eq!(PacketHeader::decode(&[]), Err(FrameError::Truncated { len: 0 }));
        assert_eq!(PacketHeader::decode(&[0x06, 0, 1, 0]), Err(FrameError::Truncated { len: 4 }));
        for flags in [0x05, 0x14, 0x84, 0x00, 0x02] {
            assert_eq!(PacketHeader::decode(&[flags, 0x45]), Err(FrameError::ReservedFlags(flags)), "{flags:#04x}");
        }
        for (index, count) in [(0, 0), (0, 1), (2, 2), (0, 3)] {
            assert_eq!(PacketHeader::decode(&[0x06, 0, 1, index, count]), Err(FrameError::InvalidFragment { index, count }));
        }
        // 只有头、没有包的帧是合法的帧，包本身对不对由收的一方查。
        assert_eq!(PacketHeader::decode(&[0x04]), Ok((PacketHeader::Whole, &[][..])));
    }

    #[test]
    fn the_first_byte_alone_tells_contexts_packets_and_unknown_frames_apart() {
        assert_eq!(Channel::peek(&[0x00, 1]), Some(Channel::Context(Recipient::Acceptor)));
        assert_eq!(Channel::peek(&[0x03, 1]), Some(Channel::Context(Recipient::Initiator)));
        assert_eq!(Channel::peek(&[0x04]), Some(Channel::Packet));
        assert_eq!(Channel::peek(&[0x06]), Some(Channel::Packet));
        // 网络包没有上下文的哪一侧；更高的位是以后的。
        assert_eq!(Channel::peek(&[0x0c]), Some(Channel::Packet), "合着好几个包的帧");
        assert_eq!(Channel::peek(&[0x05]), None);
        assert_eq!(Channel::peek(&[0x14]), None);
        assert_eq!(Channel::peek(&[0x08]), None);
        assert_eq!(Channel::peek(b"{\"kind\":1}"), None, "连接里的信令不是数据报");
        assert_eq!(Channel::peek(&[]), None);
        // 旧的节点只认识上下文的数据报：网络包帧在它那里是保留位不为 0 的帧，丢掉。
        assert_eq!(Recipient::peek(&[0x04, 0x45]), None);
        assert_eq!(Recipient::peek(&[0x06, 0x45]), None);
    }
}
