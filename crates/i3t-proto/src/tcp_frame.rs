//! TCP 中转的分帧。
//!
//! 无法使用 UDP 的节点向 relay 建立并保持一条 TCP 连接，将原本经 UDP 发送的数据报原样封装写入，
//! 每个数据报前面加 2 字节的长度（大端，不含它自己）：
//!
//! ```text
//! [长度][数据报] [长度][数据报] ...
//! ```
//!
//! 收的一方按长度取出每个数据报，之后的处理和从 UDP 收到的完全一样（见 [`crate::datagram`]）。
//! 长度为 0 的帧不带任何内容，会被跳过。

use bytes::{BufMut, Bytes, BytesMut};

/// 一帧最多能装多长的数据报。
pub const MAX_FRAME_LEN: usize = u16::MAX as usize;

const LEN_PREFIX: usize = size_of::<u16>();

/// 数据报过长，超出单帧上限。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("数据报长度为 {len} 字节，单帧上限为 {MAX_FRAME_LEN} 字节")]
pub struct FrameTooLong {
    pub len: usize,
}

/// 把一个数据报连同它的长度前缀追加到 `buf` 末尾。
///
/// # Errors
///
/// 数据报超过 [`MAX_FRAME_LEN`] 时返回错误，`buf` 不变。
pub fn put_frame(buf: &mut BytesMut, datagram: &[u8]) -> Result<(), FrameTooLong> {
    let len = u16::try_from(datagram.len()).map_err(|_| FrameTooLong { len: datagram.len() })?;
    buf.reserve(LEN_PREFIX + datagram.len());
    buf.put_u16(len);
    buf.put_slice(datagram);
    Ok(())
}

/// 把 TCP 上读到的字节流切回一个个数据报。
///
/// 用法是把读到的字节交给 [`extend_from_slice`](Self::extend_from_slice)（或者直接读进 [`buffer_mut`](Self::buffer_mut)），
/// 然后反复调 [`next_frame`](Self::next_frame) 直到它返回 `None`，再去读更多的字节。
/// 这样缓冲区里最多留下一个不完整的帧。
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: BytesMut,
}

impl FrameDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// 还没切出去的字节。读 TCP 时可以直接读到它的末尾，省一次拷贝。
    pub fn buffer_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    /// 取出下一个完整的数据报；字节还不够时返回 `None`。
    ///
    /// 返回的 [`Bytes`] 和内部缓冲区共用同一块内存，不拷贝。
    pub fn next_frame(&mut self) -> Option<Bytes> {
        loop {
            let &[hi, lo] = self.buf.first_chunk::<LEN_PREFIX>()?;
            let len = usize::from(u16::from_be_bytes([hi, lo]));
            if self.buf.len() < LEN_PREFIX + len {
                return None;
            }
            let _prefix = self.buf.split_to(LEN_PREFIX);
            if len > 0 {
                return Some(self.buf.split_to(len).freeze());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_of(datagrams: &[&[u8]]) -> BytesMut {
        let mut stream = BytesMut::new();
        for datagram in datagrams {
            put_frame(&mut stream, datagram).unwrap();
        }
        stream
    }

    fn drain(decoder: &mut FrameDecoder) -> Vec<Bytes> {
        std::iter::from_fn(|| decoder.next_frame()).collect()
    }

    #[test]
    fn frame_is_a_big_endian_length_followed_by_the_datagram() {
        assert_eq!(&stream_of(&[b"abc"])[..], [0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn several_frames_in_one_read_come_out_in_order() {
        let mut decoder = FrameDecoder::new();
        decoder.extend_from_slice(&stream_of(&[b"one", b"two", b"three"]));
        assert_eq!(drain(&mut decoder), [&b"one"[..], b"two", b"three"]);
        assert_eq!(decoder.next_frame(), None);
    }

    #[test]
    fn frames_split_at_any_byte_boundary_are_reassembled() {
        let stream = stream_of(&[b"first", b"", b"second datagram"]);
        let mut decoder = FrameDecoder::new();
        let mut frames = Vec::new();
        for byte in &stream[..] {
            decoder.extend_from_slice(std::slice::from_ref(byte));
            frames.extend(drain(&mut decoder));
        }
        assert_eq!(frames, [&b"first"[..], b"second datagram"]);
    }

    #[test]
    fn empty_frames_are_skipped() {
        let mut decoder = FrameDecoder::new();
        decoder.extend_from_slice(&stream_of(&[b"", b"", b"x", b""]));
        assert_eq!(drain(&mut decoder), [&b"x"[..]]);
    }

    #[test]
    fn longest_frame_round_trips_and_longer_is_refused() {
        let longest = vec![0xa5; MAX_FRAME_LEN];
        let mut decoder = FrameDecoder::new();
        decoder.buffer_mut().unsplit(stream_of(&[&longest]));
        assert_eq!(decoder.next_frame().as_deref(), Some(&longest[..]));

        let mut buf = BytesMut::from(&b"keep"[..]);
        let too_long = vec![0; MAX_FRAME_LEN + 1];
        assert_eq!(put_frame(&mut buf, &too_long), Err(FrameTooLong { len: MAX_FRAME_LEN + 1 }));
        assert_eq!(&buf[..], b"keep");
    }
}
