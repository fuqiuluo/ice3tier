//! 一条 lane 的 TLS 状态和收发缓冲，不做 I/O。
//!
//! # 一次只喂一条记录
//!
//! passthrough 的方向在某一条记录之后离开 TLS，紧跟着的就是用户的原始字节，可能和这条记录在同一个 TCP 段里。
//! 所以 TLS 库绝不能多吞字节：从 socket 读到的字节先放在 [`Sealed::inbound`]，这里自己按记录头切出一条完整的记录，
//! 只把这一条交给 TLS，处理完、把明文全部取出来，再看下一条。切换发生时，`inbound` 里剩下的就是原始字节，一个不少。

use std::io::{self, Read, Write};

use bytes::{BufMut, BytesMut};
use rustls::Connection;

use crate::error::LaneError;
use crate::frame::{Frame, HEADER_LEN};

/// 记录头：类型 1 字节、版本 2 字节、长度 2 字节。
const RECORD_HEADER_LEN: usize = 5;

/// 一条记录的内容最长多少字节。TLS 1.3 密文最长 2^14 + 256；再放宽到和 TLS 库自己的上限一样（2^14 + 2048）。
const MAX_RECORD_BODY: usize = (1 << 14) + 2048;

/// TLS 的记录类型：change_cipher_spec、alert、handshake、application_data。
const RECORD_TYPES: std::ops::RangeInclusive<u8> = 20..=23;

/// `buf` 开头有一条完整的记录时返回它的总长度；还不完整时返回 `None`。
///
/// # Errors
///
/// 记录头不像 TLS：类型不对、主版本不是 3、长度超出上限。
pub(crate) fn complete_record(buf: &[u8]) -> Result<Option<usize>, LaneError> {
    let Some(&[kind, major, _minor, hi, lo]) = buf.first_chunk::<RECORD_HEADER_LEN>() else { return Ok(None) };
    let len = usize::from(u16::from_be_bytes([hi, lo]));
    if !RECORD_TYPES.contains(&kind) || major != 3 || len == 0 || len > MAX_RECORD_BODY {
        return Err(LaneError::Protocol("不是 TLS 记录"));
    }
    let total = RECORD_HEADER_LEN + len;
    Ok((buf.len() >= total).then_some(total))
}

/// 从 TLS 里取下一个帧的结果。
#[derive(Debug)]
pub(crate) enum Next {
    Frame(Frame),
    /// 要从 socket 再读一些字节。
    More,
    /// 对端发了 close_notify：这个方向正常结束了。
    Closed,
}

pub(crate) struct Sealed {
    tls: Connection,
    /// 从 socket 读到、还没交给 TLS 的字节。
    pub(crate) inbound: BytesMut,
    /// TLS 解出来、还没拆成帧的明文。
    plain: BytesMut,
    /// 遇到未知帧类型时选择跳过（控制 lane）还是报错（承载流的 lane）。
    allow_unknown: bool,
    /// 对端发过 close_notify。之后 TLS 不再收任何字节，这里也不再喂。
    peer_closed: bool,
}

impl Sealed {
    /// `inbound` 是已经从 socket 读到的字节（例如 relay 为了分辨协议先读走的那几个）。
    pub(crate) fn new(mut tls: Connection, inbound: BytesMut) -> Self {
        // 发送缓冲由这里控制（每写一帧就取走密文），不需要 TLS 库再替我们拦。
        tls.set_buffer_limit(None);
        Self { tls, inbound, plain: BytesMut::new(), allow_unknown: false, peer_closed: false }
    }

    pub(crate) fn allow_unknown_frames(&mut self) {
        self.allow_unknown = true;
    }

    pub(crate) fn is_handshaking(&self) -> bool {
        self.tls.is_handshaking()
    }

    pub(crate) fn connection(&self) -> &Connection {
        &self.tls
    }

    /// 把 `inbound` 开头的一条完整记录交给 TLS 处理，解出来的明文全部移到 `plain`。没有完整的记录时返回 `false`。
    ///
    /// # Errors
    ///
    /// 记录头不像 TLS，或者 TLS 处理这条记录时出错（解密失败、握手不通过、对端发了告警）。
    pub(crate) fn feed_record(&mut self) -> Result<bool, LaneError> {
        let Some(len) = complete_record(&self.inbound)? else { return Ok(false) };
        let record = self.inbound.split_to(len);
        let mut rest = &record[..];
        while !rest.is_empty() {
            // 绝不能给 TLS 一个空的读取源：它会把读到 0 当作对端关了连接。
            if self.tls.read_tls(&mut rest).map_err(LaneError::Io)? == 0 {
                return Err(LaneError::Protocol("TLS 引擎拒绝接收更多字节"));
            }
        }
        let state = self.tls.process_new_packets().map_err(LaneError::Tls)?;
        self.peer_closed = state.peer_has_closed();
        let available = state.plaintext_bytes_to_read();
        if available > 0 {
            let start = self.plain.len();
            self.plain.resize(start + available, 0);
            self.tls.reader().read_exact(&mut self.plain[start..]).map_err(LaneError::Io)?;
        }
        Ok(true)
    }

    /// 取下一个帧，不够时先处理 `inbound` 里已有的完整记录。
    ///
    /// # Errors
    ///
    /// 记录或帧不合法；close_notify 之前的最后一个帧不完整。
    pub(crate) fn next_frame(&mut self) -> Result<Next, LaneError> {
        loop {
            if let Some(frame) = Frame::decode(&mut self.plain, self.allow_unknown).map_err(LaneError::Frame)? {
                return Ok(Next::Frame(frame));
            }
            if self.peer_closed {
                return if self.plain.is_empty() {
                    Ok(Next::Closed)
                } else {
                    Err(LaneError::Protocol("close_notify 之前的帧不完整"))
                };
            }
            if !self.feed_record()? {
                return Ok(Next::More);
            }
        }
    }

    /// 刚处理完的记录正好在一个帧的末尾结束：明文全部用完了。切换到原始字节之前要确认这一点。
    pub(crate) fn at_record_boundary(&self) -> bool {
        self.plain.is_empty()
    }

    /// 把几段字节合在一起加密：不超过一条记录的上限时，它们在同一条记录里（帧头和内容不分开）。
    pub(crate) fn seal(&mut self, parts: &[&[u8]]) {
        let slices: Vec<io::IoSlice<'_>> = parts.iter().map(|part| io::IoSlice::new(part)).collect();
        let total: usize = parts.iter().map(|part| part.len()).sum();
        let wrote = self.tls.writer().write_vectored(&slices).expect("TLS 的明文只写进内存缓冲，不会失败");
        if wrote < total {
            // 发送缓冲没有上限（见 `new`），TLS 库一次就全部收下；万一没有，剩下的照顺序补上。
            let joined = parts.concat();
            self.tls.writer().write_all(&joined[wrote..]).expect("同上");
        }
    }

    pub(crate) fn seal_frame(&mut self, frame: &Frame) {
        let mut buf = Vec::with_capacity(HEADER_LEN + 16);
        frame.encode(&mut buf);
        self.seal(&[&buf]);
    }

    /// 关闭这个方向：发 close_notify。之后不能再写。
    pub(crate) fn close_notify(&mut self) {
        self.tls.send_close_notify();
    }

    /// 把 TLS 要发的密文全部移到 `out` 末尾。
    pub(crate) fn take_output(&mut self, out: &mut BytesMut) {
        let mut writer = out.writer();
        while self.tls.wants_write() {
            self.tls.write_tls(&mut writer).expect("往内存缓冲里写不会失败");
        }
    }

    /// 切换到原始字节时，`inbound` 里剩下的字节交出去。
    pub(crate) fn take_inbound(&mut self) -> BytesMut {
        std::mem::take(&mut self.inbound)
    }

    /// 空闲的时候把占着的缓冲还回去：成千上万条静默的流时，每条省下几十 KB。
    pub(crate) fn shrink(&mut self) {
        if self.inbound.is_empty() && self.inbound.capacity() > 0 {
            self.inbound = BytesMut::new();
        }
        if self.plain.is_empty() && self.plain.capacity() > 0 {
            self.plain = BytesMut::new();
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use i3t_crypto::NodeKey;
    use i3t_crypto::tls::Identity;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ServerConnection};

    use super::*;
    use crate::frame::{Mode, Purpose};
    use crate::lane::{client_config, server_config};

    /// 在内存里握完手的一对：拨号方（客户端）和接受方（服务端）。
    fn pair() -> (Sealed, Sealed) {
        let (dialler, acceptor) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        let dialler_public = dialler.public();
        let client = client_config(&Identity::new(&dialler).unwrap(), acceptor.public()).unwrap();
        let server = server_config(&Identity::new(&acceptor).unwrap(), move |key| *key == dialler_public).unwrap();
        let client = ClientConnection::new(client, ServerName::try_from("i3t").unwrap()).unwrap();
        let mut client = Sealed::new(Connection::Client(client), BytesMut::new());
        let mut server = Sealed::new(Connection::Server(ServerConnection::new(server).unwrap()), BytesMut::new());
        for _ in 0..10 {
            client.take_output(&mut server.inbound);
            while server.feed_record().unwrap() {}
            server.take_output(&mut client.inbound);
            while client.feed_record().unwrap() {}
            if !client.is_handshaking() && !server.is_handshaking() {
                return (client, server);
            }
        }
        panic!("握手没有完成");
    }

    /// 一段可以辨认的原始字节：用户自己的 TLS 记录，lane 不能动它。
    fn raw_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0x17, 0x03, 0x03];
        bytes.extend((0..len).map(|i| u8::try_from(i % 251).unwrap()));
        bytes
    }

    /// 把 `wire` 按 `cuts` 切成几段，一段一段喂给 `receiver`，每喂一段就把能取的帧都取出来，
    /// 直到看到 `switch` 认定的那个切换帧。返回切换之前取到的帧，以及切换之后剩下的全部字节（这时还在缓冲里的，加上没喂的）。
    fn deliver(receiver: &mut Sealed, wire: &[u8], cuts: &[usize], switch: impl Fn(&Frame) -> bool) -> (Vec<Frame>, Vec<u8>) {
        let mut frames = Vec::new();
        let mut start = 0;
        for &end in cuts.iter().chain(std::iter::once(&wire.len())) {
            receiver.inbound.extend_from_slice(&wire[start..end]);
            start = end;
            loop {
                match receiver.next_frame().unwrap() {
                    Next::Frame(frame) => {
                        let switched = switch(&frame);
                        frames.push(frame);
                        if switched {
                            assert!(receiver.at_record_boundary(), "切换帧必须是它那条记录里的最后一个帧");
                            let mut rest = receiver.take_inbound().to_vec();
                            rest.extend_from_slice(&wire[start..]);
                            return (frames, rest);
                        }
                    }
                    Next::More => break,
                    Next::Closed => panic!("不该收到 close_notify"),
                }
            }
        }
        panic!("没有看到切换帧，收到 {frames:?}");
    }

    /// 没升级的发起方这个方向在线上的样子：HELLO、OPENING（[`Mode::Early`]），然后是原始字节。
    fn initiator_wire(dialler: &mut Sealed, header: &[u8], raw: &[u8]) -> (Vec<u8>, usize) {
        let mut wire = BytesMut::new();
        dialler.seal_frame(&Frame::Hello { purpose: Purpose::Own, epoch: 9 });
        dialler.seal_frame(&Frame::Opening { mode: Mode::Early, header: Bytes::copy_from_slice(header) });
        dialler.take_output(&mut wire);
        let tls_len = wire.len();
        wire.extend_from_slice(raw);
        (wire.to_vec(), tls_len)
    }

    fn is_opening(frame: &Frame) -> bool {
        matches!(frame, Frame::Opening { .. })
    }

    fn is_switch(frame: &Frame) -> bool {
        matches!(frame, Frame::Switch)
    }

    /// 发起方开流、随即转成原始字节，接受方按 `cuts` 给出的切法收到。
    fn opening_then_raw(cuts: impl FnOnce(usize, usize) -> Vec<usize>) {
        let header = b"OPEN + first data".repeat(20);
        let raw = raw_bytes(300);
        let (mut dialler, mut acceptor) = pair();
        let (wire, tls_len) = initiator_wire(&mut dialler, &header, &raw);
        let cuts = cuts(wire.len(), tls_len);
        let (frames, rest) = deliver(&mut acceptor, &wire, &cuts, is_opening);
        assert!(
            matches!(frames.as_slice(), [Frame::Hello { .. }, Frame::Opening { mode: Mode::Early, header: got }] if got[..] == header[..])
        );
        assert_eq!(rest, raw, "切法 {cuts:?}：OPENING 之后的字节必须一个不少、原样交出");
    }

    /// 接受方回 REPLY、发 SWITCH、随即转成原始字节，发起方按 `cuts` 给出的切法收到。
    fn reply_then_raw(cuts: impl FnOnce(usize, usize) -> Vec<usize>) {
        let raw = raw_bytes(500);
        let (mut dialler, mut acceptor) = pair();
        // 接受方先要读到发起方的帧（握手的最后一步也在这里完成），之后才轮到它说话。
        let (wire, _) = initiator_wire(&mut dialler, b"open", &[]);
        let _ = deliver(&mut acceptor, &wire, &[], is_opening);
        let mut back = BytesMut::new();
        acceptor.seal_frame(&Frame::Data(Bytes::from_static(b"\x00\x00 reply")));
        acceptor.seal_frame(&Frame::Switch);
        acceptor.take_output(&mut back);
        let tls_len = back.len();
        back.extend_from_slice(&raw);
        let cuts = cuts(back.len(), tls_len);
        let (frames, rest) = deliver(&mut dialler, &back, &cuts, is_switch);
        assert!(matches!(frames.as_slice(), [Frame::Data(reply), Frame::Switch] if &reply[..] == b"\x00\x00 reply"));
        assert_eq!(rest, raw, "切法 {cuts:?}：SWITCH 之后的字节必须一个不少、原样交出");
    }

    /// 线上字节的长度和 TLS 部分的长度，每一对新握手的连接都一样，先量一次。
    fn wire_lengths() -> (usize, usize) {
        let (mut dialler, _) = pair();
        let (wire, tls_len) = initiator_wire(&mut dialler, &b"OPEN + first data".repeat(20), &raw_bytes(300));
        (wire.len(), tls_len)
    }

    #[test]
    fn the_raw_bytes_after_an_opening_survive_every_two_piece_split_near_the_switch() {
        let (len, tls_len) = wire_lengths();
        // 切换点前后 64 字节逐个都切一遍，其余每隔几个切一次。
        let cuts = (1..len).filter(|&cut| cut.abs_diff(tls_len) <= 64 || cut % 7 == 0);
        for cut in cuts {
            opening_then_raw(|_, _| vec![cut]);
        }
    }

    #[test]
    fn the_raw_bytes_after_an_opening_survive_one_byte_at_a_time() {
        opening_then_raw(|len, _| (1..len).collect());
    }

    #[test]
    fn the_last_record_and_the_first_raw_bytes_may_arrive_in_one_segment() {
        // 最后一条记录的末尾和原始字节的开头在同一段里；再试一次整条最后的记录加原始字节一起到。
        opening_then_raw(|_, tls_len| vec![tls_len - 1, tls_len + 5]);
        opening_then_raw(|_, tls_len| vec![tls_len - 30]);
        opening_then_raw(|_, _| Vec::new());
    }

    #[test]
    fn the_raw_bytes_after_an_opening_survive_irregular_segmentation() {
        // 固定种子的伪随机切法，失败时能复现。
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        for _ in 0..30 {
            opening_then_raw(|len, _| {
                let mut cuts = Vec::new();
                let mut at = 0;
                loop {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    at += 1 + usize::try_from(seed % 97).unwrap();
                    if at >= len {
                        return cuts;
                    }
                    cuts.push(at);
                }
            });
        }
    }

    #[test]
    fn the_raw_bytes_after_a_switch_survive_every_segmentation_near_it() {
        let (len, tls_len) = {
            let probe = std::cell::Cell::new((0, 0));
            reply_then_raw(|len, tls_len| {
                probe.set((len, tls_len));
                Vec::new()
            });
            probe.get()
        };
        for cut in (1..len).filter(|&cut| cut.abs_diff(tls_len) <= 64 || cut % 11 == 0) {
            reply_then_raw(|_, _| vec![cut]);
        }
        reply_then_raw(|len, _| (1..len).collect());
        reply_then_raw(|_, tls_len| vec![tls_len - 1]);
    }

    #[test]
    fn a_switch_frame_followed_by_more_in_the_same_record_is_caught() {
        let (mut dialler, mut acceptor) = pair();
        let (wire, _) = initiator_wire(&mut dialler, b"open", &[]);
        let _ = deliver(&mut acceptor, &wire, &[], is_opening);
        let mut back = BytesMut::new();
        // SWITCH 和后面的帧在同一条记录里：这是对端不守协议，接收方必须看得出来。
        let mut both = Vec::new();
        Frame::Switch.encode(&mut both);
        Frame::Data(Bytes::from_static(b"smuggled")).encode(&mut both);
        acceptor.seal(&[&both]);
        acceptor.take_output(&mut back);
        dialler.inbound.extend_from_slice(&back);
        assert!(matches!(dialler.next_frame().unwrap(), Next::Frame(Frame::Switch)));
        assert!(!dialler.at_record_boundary());
    }

    #[test]
    fn garbage_is_refused_by_its_record_header() {
        assert!(complete_record(b"GET / HTTP/1.1\r\n").is_err());
        assert!(complete_record(&[0x17, 0x03, 0x03, 0xff, 0xff]).is_err(), "超过上限的长度");
        assert!(complete_record(&[0x17, 0x02, 0x03, 0x00, 0x10]).is_err(), "主版本不是 3");
        assert_eq!(complete_record(&[0x17, 0x03, 0x03, 0x00, 0x02, 1]).unwrap(), None);
        assert_eq!(complete_record(&[0x17, 0x03, 0x03, 0x00, 0x02, 1, 2, 3]).unwrap(), Some(7));
    }

    #[test]
    fn sealed_data_and_close_notify_arrive_intact_in_small_pieces() {
        let (mut dialler, mut acceptor) = pair();
        let (wire, _) = initiator_wire(&mut dialler, b"open", &[]);
        let _ = deliver(&mut acceptor, &wire, &[], is_opening);
        let big = Bytes::from(raw_bytes(40_000));
        let mut out = BytesMut::new();
        for chunk in big.chunks(crate::frame::MAX_DATA_LEN) {
            acceptor.seal(&[&crate::frame::data_header(chunk.len()), chunk]);
        }
        acceptor.close_notify();
        acceptor.take_output(&mut out);
        let mut received = Vec::new();
        for piece in out.chunks(333) {
            dialler.inbound.extend_from_slice(piece);
            loop {
                match dialler.next_frame().unwrap() {
                    Next::Frame(Frame::Data(data)) => received.extend_from_slice(&data),
                    Next::Frame(other) => panic!("意外的帧 {other:?}"),
                    Next::More => break,
                    Next::Closed => {
                        assert_eq!(received, big);
                        return;
                    }
                }
            }
        }
        panic!("没有收到 close_notify");
    }
}
