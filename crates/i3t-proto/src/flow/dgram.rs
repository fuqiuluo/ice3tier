//! 数据报上下文中的帧结构：帧头定义，以及将超出单帧容量的内容拆分为多分片。逐字节格式见上级模块文档。

use std::slice::Chunks;

pub(super) const FLAG_TO_INITIATOR: u8 = 0b0000_0001;
pub(super) const FLAG_FRAGMENT: u8 = 0b0000_0010;
/// 数据报上下文的帧里必须是 0 的位。bit 2 标着网络包帧（`packet` 模块），它们不交给上下文。
const FLAG_RESERVED: u8 = 0b1111_1100;

/// 一个数据报的内容（目标加载荷）最长多少字节。
///
/// UDP 自己的载荷上限是 65507 字节，所以只有贴着上限的报文、加上目标之后才会超出，那样的报文发不过去。
/// 收的一方按这个数限制重组用的内存。
pub const MAX_DATAGRAM_BODY_LEN: usize = u16::MAX as usize;

/// 一个报文最多切成多少片：片数在头里占 1 字节。
const MAX_FRAGMENTS: usize = u8::MAX as usize;

/// 数据报是发给上下文的哪一侧的。
///
/// 一个节点既是它自己开的那些上下文的发起方，也是别人开过来的那些上下文的接受方，两边各有各的上下文号。
/// 所以每个数据报都写明它是给哪一侧的，连接层按这一位把它交给对应的人。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recipient {
    /// 发起方发给接受方的。
    Acceptor,
    /// 接受方发给发起方的。
    Initiator,
}

impl Recipient {
    /// 上下文的另一侧。
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Acceptor => Self::Initiator,
            Self::Initiator => Self::Acceptor,
        }
    }

    /// 仅检查首字节以判断帧的接收侧。空帧或标志含未知位的帧返回 `None`，应直接丢弃。
    #[must_use]
    pub fn peek(frame: &[u8]) -> Option<Self> {
        let &flags = frame.first()?;
        (flags & FLAG_RESERVED == 0).then(|| Self::of(flags))
    }

    const fn of(flags: u8) -> Self {
        if flags & FLAG_TO_INITIATOR == 0 { Self::Acceptor } else { Self::Initiator }
    }

    const fn flag(self) -> u8 {
        match self {
            Self::Acceptor => 0,
            Self::Initiator => FLAG_TO_INITIATOR,
        }
    }
}

/// 分片头：这一帧是哪个报文的第几片。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fragment {
    /// 报文号。同一个报文的各片相同。
    pub message: u16,
    /// 这是第几片，从 0 开始。
    pub index: u8,
    /// 这个报文一共几片，2～255。
    pub count: u8,
}

/// 一帧开头的头。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramHeader {
    pub recipient: Recipient,
    pub context: u32,
    /// 没有值时这一帧就是完整的内容。
    pub fragment: Option<Fragment>,
}

impl DatagramHeader {
    /// 不分片时头占多少字节。
    pub const LEN: usize = 1 + 4;
    /// 分片时头占多少字节。
    pub const FRAGMENT_LEN: usize = Self::LEN + 2 + 1 + 1;

    /// 把头追加到 `buf` 末尾。内容（或者内容的一片）直接接在后面。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let fragmented = if self.fragment.is_some() { FLAG_FRAGMENT } else { 0 };
        buf.push(self.recipient.flag() | fragmented);
        buf.extend_from_slice(&self.context.to_be_bytes());
        if let Some(fragment) = self.fragment {
            buf.extend_from_slice(&fragment.message.to_be_bytes());
            buf.extend_from_slice(&[fragment.index, fragment.count]);
        }
    }

    /// 解析一帧，返回头和它后面的字节（完整的内容，或者内容的一片）。
    ///
    /// # Errors
    ///
    /// 帧长度短于帧头、标志含未知位，或分片头无效。此类帧应直接丢弃。
    pub fn decode(frame: &[u8]) -> Result<(Self, &[u8]), FrameError> {
        let truncated = FrameError::Truncated { len: frame.len() };
        let (&[flags, c0, c1, c2, c3], rest) = frame.split_first_chunk().ok_or(truncated)?;
        if flags & FLAG_RESERVED != 0 {
            return Err(FrameError::ReservedFlags(flags));
        }
        let (recipient, context) = (Recipient::of(flags), u32::from_be_bytes([c0, c1, c2, c3]));
        if flags & FLAG_FRAGMENT == 0 {
            return Ok((Self { recipient, context, fragment: None }, rest));
        }
        let (&[m0, m1, index, count], rest) = rest.split_first_chunk().ok_or(truncated)?;
        if count < 2 || index >= count {
            return Err(FrameError::InvalidFragment { index, count });
        }
        let fragment = Fragment { message: u16::from_be_bytes([m0, m1]), index, count };
        Ok((Self { recipient, context, fragment: Some(fragment) }, rest))
    }
}

/// 帧解析失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("数据报长度为 {len} 字节，短于帧头长度")]
    Truncated { len: usize },
    #[error("标志中的保留位非 0：{0:#010b}")]
    ReservedFlags(u8),
    #[error("分片头无效：总片数为 {count}，当前片序号为 {index}（从 0 开始）")]
    InvalidFragment { index: u8, count: u8 },
    #[error("合并帧中第 {index} 个数据包（从 0 开始）解析失败：帧为空、声明长度为 0 或声明长度超过剩余字节数")]
    BrokenBundle { index: usize },
}

/// 一个报文的内容切成的帧，按片序号的顺序。
///
/// 一帧装得下就只有一帧，不带分片头；否则每一帧都带分片头，除了最后一帧都填满。
#[derive(Debug, Clone)]
pub struct Frames<'a> {
    recipient: Recipient,
    context: u32,
    plan: Plan<'a>,
}

#[derive(Debug, Clone)]
enum Plan<'a> {
    Whole(Option<&'a [u8]>),
    Split { message: u16, count: u8, next: u8, chunks: Chunks<'a, u8> },
}

impl<'a> Frames<'a> {
    /// 把 `body` 切成每帧不超过 `max_len` 字节的帧。`message` 是这个报文的报文号，只在要分片时用到。
    ///
    /// 走单向流的数据报没有长度限制，`max_len` 传 `usize::MAX`，得到的就是不分片的一帧。
    ///
    /// # Errors
    ///
    /// 内容超过 [`MAX_DATAGRAM_BODY_LEN`]，或 `max_len` 过小导致即使分为 255 片仍无法容纳。
    pub fn split(recipient: Recipient, context: u32, message: u16, body: &'a [u8], max_len: usize) -> Result<Self, SplitError> {
        if body.len() > MAX_DATAGRAM_BODY_LEN {
            return Err(SplitError::BodyTooLarge { len: body.len() });
        }
        // 内容不超过 [`MAX_DATAGRAM_BODY_LEN`]，加上头不会溢出。
        if body.len() + DatagramHeader::LEN <= max_len {
            return Ok(Self { recipient, context, plan: Plan::Whole(Some(body)) });
        }
        let room = max_len.saturating_sub(DatagramHeader::FRAGMENT_LEN);
        let count = if room == 0 { usize::MAX } else { body.len().div_ceil(room) };
        match u8::try_from(count) {
            Ok(count) if usize::from(count) <= MAX_FRAGMENTS => {
                Ok(Self { recipient, context, plan: Plan::Split { message, count, next: 0, chunks: body.chunks(room) } })
            }
            _ => Err(SplitError::FrameTooSmall { len: body.len(), max_len }),
        }
    }
}

impl Iterator for Frames<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        let (recipient, context) = (self.recipient, self.context);
        let (fragment, chunk) = match &mut self.plan {
            Plan::Whole(body) => (None, body.take()?),
            Plan::Split { message, count, next, chunks } => {
                let chunk = chunks.next()?;
                let fragment = Fragment { message: *message, index: *next, count: *count };
                *next += 1;
                (Some(fragment), chunk)
            }
        };
        let header = DatagramHeader { recipient, context, fragment };
        let mut frame = Vec::with_capacity(DatagramHeader::FRAGMENT_LEN + chunk.len());
        header.encode(&mut frame);
        frame.extend_from_slice(chunk);
        Some(frame)
    }
}

/// 报文无法分片发送的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SplitError {
    #[error("数据报内容长度为 {len} 字节，超过上限 {MAX_DATAGRAM_BODY_LEN} 字节")]
    BodyTooLarge { len: usize },
    #[error("单次数据报最大长度为 {max_len} 字节，{len} 字节内容即使分为 {MAX_FRAGMENTS} 片仍无法容纳")]
    FrameTooSmall { len: usize, max_len: usize },
}

// 片序号加一不会溢出：序号最大是片数减一。
const _: () = assert!(MAX_FRAGMENTS == u8::MAX as usize);

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(recipient: Recipient, body: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        Frames::split(recipient, 0x0a0b_0c0d, 0x0102, body, max_len).unwrap().collect()
    }

    #[test]
    fn a_frame_that_fits_has_the_documented_unfragmented_layout() {
        assert_eq!(frames(Recipient::Acceptor, b"body", 1200), [[&[0x00, 0x0a, 0x0b, 0x0c, 0x0d][..], b"body"].concat()]);
        assert_eq!(frames(Recipient::Initiator, b"body", 1200), [[&[0x01, 0x0a, 0x0b, 0x0c, 0x0d][..], b"body"].concat()]);
        // 正好装满也不分片。
        assert_eq!(frames(Recipient::Acceptor, b"body", DatagramHeader::LEN + 4).len(), 1);
    }

    #[test]
    fn a_body_that_does_not_fit_is_cut_into_full_frames_with_the_documented_fragment_header() {
        let cut = frames(Recipient::Initiator, b"0123456789", DatagramHeader::FRAGMENT_LEN + 4);
        let header = |index| [0x03, 0x0a, 0x0b, 0x0c, 0x0d, 0x01, 0x02, index, 3];
        assert_eq!(cut, [[&header(0)[..], b"0123"].concat(), [&header(1)[..], b"4567"].concat(), [&header(2)[..], b"89"].concat()]);
        assert!(cut.iter().all(|frame| frame.len() <= DatagramHeader::FRAGMENT_LEN + 4));

        // 不分片时头短 4 字节。内容只比那样一帧多 1 字节，也要按分片的头来切。
        let barely = frames(Recipient::Acceptor, b"123456789", DatagramHeader::FRAGMENT_LEN + 4);
        let pieces: Vec<&[u8]> = barely.iter().map(|frame| &frame[DatagramHeader::FRAGMENT_LEN..]).collect();
        assert_eq!(pieces, [&b"1234"[..], b"5678", b"9"]);
        assert_eq!(barely[0][..DatagramHeader::FRAGMENT_LEN], [0x02, 0x0a, 0x0b, 0x0c, 0x0d, 0x01, 0x02, 0, 3]);
    }

    #[test]
    fn every_frame_decodes_back_to_its_header_and_its_piece_of_the_body() {
        let body: Vec<u8> = (0..=u8::MAX).cycle().take(3000).collect();
        let cut = frames(Recipient::Acceptor, &body, 1200);
        assert_eq!(cut.len(), 3);
        let mut rebuilt = Vec::new();
        for (index, frame) in cut.iter().enumerate() {
            let (header, piece) = DatagramHeader::decode(frame).unwrap();
            let fragment = Fragment { message: 0x0102, index: u8::try_from(index).unwrap(), count: 3 };
            assert_eq!(header, DatagramHeader { recipient: Recipient::Acceptor, context: 0x0a0b_0c0d, fragment: Some(fragment) });
            assert_eq!(Recipient::peek(frame), Some(Recipient::Acceptor));
            rebuilt.extend_from_slice(piece);
        }
        assert_eq!(rebuilt, body);

        let whole = frames(Recipient::Initiator, b"x", 1200).remove(0);
        let expected = DatagramHeader { recipient: Recipient::Initiator, context: 0x0a0b_0c0d, fragment: None };
        assert_eq!(DatagramHeader::decode(&whole), Ok((expected, &b"x"[..])));
        assert_eq!(Recipient::peek(&whole), Some(Recipient::Initiator));
    }

    #[test]
    fn a_stream_carries_any_body_in_one_unfragmented_frame() {
        let body = vec![7; MAX_DATAGRAM_BODY_LEN];
        let cut = frames(Recipient::Acceptor, &body, usize::MAX);
        assert_eq!(cut.len(), 1);
        assert_eq!(cut[0].len(), DatagramHeader::LEN + MAX_DATAGRAM_BODY_LEN);
        assert_eq!(DatagramHeader::decode(&cut[0]).unwrap().0.fragment, None);
    }

    #[test]
    fn the_largest_body_fits_in_255_fragments_at_the_smallest_quic_datagram_size() {
        // 路径 MTU 是 QUIC 的下限 1200 时，一个数据报帧能带的字节略多于 1100。
        let body = vec![0; MAX_DATAGRAM_BODY_LEN];
        let cut = frames(Recipient::Acceptor, &body, 1100);
        assert_eq!(cut.len(), 61);
        assert_eq!(cut.iter().map(|frame| frame.len() - DatagramHeader::FRAGMENT_LEN).sum::<usize>(), MAX_DATAGRAM_BODY_LEN);
    }

    #[test]
    fn bodies_that_cannot_be_sent_are_refused_instead_of_truncated() {
        let split = |len: usize, max_len| Frames::split(Recipient::Acceptor, 1, 1, &vec![0; len], max_len).map(Iterator::count);
        assert_eq!(split(MAX_DATAGRAM_BODY_LEN + 1, usize::MAX), Err(SplitError::BodyTooLarge { len: MAX_DATAGRAM_BODY_LEN + 1 }));
        // 每片只带得动 1 字节：255 片最多 255 字节。
        assert_eq!(split(255, DatagramHeader::FRAGMENT_LEN + 1), Ok(255));
        assert_eq!(split(256, DatagramHeader::FRAGMENT_LEN + 1), Err(SplitError::FrameTooSmall { len: 256, max_len: 10 }));
        // 连分片头都放不下。
        for max_len in [0, DatagramHeader::LEN, DatagramHeader::FRAGMENT_LEN] {
            assert_eq!(split(100, max_len), Err(SplitError::FrameTooSmall { len: 100, max_len }), "{max_len}");
        }
        // 空的内容只要放得下头。放不下头时不能照样给出一帧。
        assert_eq!(split(0, DatagramHeader::LEN), Ok(1));
        for max_len in [0, 1, DatagramHeader::LEN - 1] {
            assert_eq!(split(0, max_len), Err(SplitError::FrameTooSmall { len: 0, max_len }), "{max_len}");
        }
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert_eq!(DatagramHeader::decode(&[]), Err(FrameError::Truncated { len: 0 }));
        assert_eq!(DatagramHeader::decode(&[0, 0, 0, 0]), Err(FrameError::Truncated { len: 4 }));
        assert_eq!(DatagramHeader::decode(&[0x02, 0, 0, 0, 1, 0, 0, 0]), Err(FrameError::Truncated { len: 8 }));
        assert_eq!(DatagramHeader::decode(&[0x04, 0, 0, 0, 1]), Err(FrameError::ReservedFlags(0x04)));
        assert_eq!(DatagramHeader::decode(&[0x80, 0, 0, 0, 1]), Err(FrameError::ReservedFlags(0x80)));
        for (index, count) in [(0, 0), (0, 1), (2, 2), (9, 3)] {
            let frame = [0x02, 0, 0, 0, 1, 0, 0, index, count];
            assert_eq!(DatagramHeader::decode(&frame), Err(FrameError::InvalidFragment { index, count }));
        }
        // 没有内容的帧是合法的：头后面什么都没有。
        assert!(DatagramHeader::decode(&[0x01, 0, 0, 0, 1]).is_ok());
    }

    #[test]
    fn the_first_byte_alone_tells_which_side_a_frame_is_for() {
        assert_eq!(Recipient::peek(&[0x00]), Some(Recipient::Acceptor));
        assert_eq!(Recipient::peek(&[0x02, 0xff]), Some(Recipient::Acceptor));
        assert_eq!(Recipient::peek(&[0x01]), Some(Recipient::Initiator));
        assert_eq!(Recipient::peek(&[0x03]), Some(Recipient::Initiator));
        assert_eq!(Recipient::peek(&[]), None);
        // 连接里送的信令是一个 JSON 对象，首字节是 `{`：它不会被当成数据报。
        assert_eq!(Recipient::peek(b"{\"kind\":\"punch\"}"), None);
        assert_eq!(Recipient::Acceptor.other(), Recipient::Initiator);
        assert_eq!(Recipient::Initiator.other(), Recipient::Acceptor);
    }
}
