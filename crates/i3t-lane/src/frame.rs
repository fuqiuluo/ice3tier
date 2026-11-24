//! lane 的 TLS 里面传的帧。格式见 crate 文档的"线上格式"一节。
//!
//! 每种帧的长度都有上限，并且在帧头（3 字节）一到就检查：对端声称一个过长的帧时，不等它的内容就报错，
//! 所以对端乱写也不能让读的一方多缓冲内存。

use bytes::{Buf, BufMut, Bytes, BytesMut};
use i3t_conn::Payload;

/// 帧头：类型 1 字节，长度 2 字节（大端，不含帧头）。
pub(crate) const HEADER_LEN: usize = 3;

/// 一个 DATA 帧最多带多少字节。帧头加内容正好是一条 TLS 记录的明文上限（2^14），一帧一条记录。
pub(crate) const MAX_DATA_LEN: usize = (1 << 14) - HEADER_LEN;

/// OPENING 里流的头最长多少字节。流层的头（OPEN 连同首批数据）不超过 17 KB，这里留一倍的余量。
pub(crate) const MAX_HEADER_LEN: usize = 32 * 1024;

/// 未知帧的最大允许长度。仅在控制 lane 上跳过以预留版本扩展空间；在承载流的 lane 上收到未知帧视为协议错误。
const MAX_UNKNOWN_LEN: usize = 1024;

const TYPE_HELLO: u8 = 0x01;
const TYPE_POOL: u8 = 0x02;
const TYPE_PING: u8 = 0x03;
const TYPE_PONG: u8 = 0x04;
const TYPE_GOAWAY: u8 = 0x05;
const TYPE_OPENING: u8 = 0x10;
const TYPE_DATA: u8 = 0x11;
const TYPE_SWITCH: u8 = 0x12;
const TYPE_ABORT: u8 = 0x13;
const TYPE_STOP: u8 = 0x14;

const MODE_SEALED: u8 = 0;
const MODE_EARLY: u8 = 1;
const MODE_MUTUAL: u8 = 2;

/// 一条 lane 拨出来是做什么用的。拨号的一方在 HELLO 里说明，之后不变，所以两边永远不会争用同一条 lane。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// 控制 lane：不承载业务流，仅传输池补拨指令、保活及排空（GoAway）通知。
    Control,
    /// 停在接受方那里，给接受方开往拨号方的流用。
    Parked,
    /// 拨号方自己开往接受方的流用。
    Own,
}

impl Purpose {
    const fn to_wire(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Parked => 1,
            Self::Own => 2,
        }
    }

    const fn from_wire(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Control),
            1 => Some(Self::Parked),
            2 => Some(Self::Own),
            _ => None,
        }
    }
}

/// OPENING 里的负载方式：两个方向什么时候离开 TLS。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// 两个方向一直在 TLS 里。
    Sealed,
    /// `i3t-lane/1` 的 passthrough：发起方的方向在 OPENING 所在的记录之后就离开 TLS，接受方的在它的 SWITCH 之后。
    /// 那时目标会怎么回还不知道，发起方后面的字节（HelloRetryRequest 之后的第二个 ClientHello、TLS 1.2 的客户端证书）
    /// 就明文出去了。所以本端不再发它，只为没升级的发起方收它（issue #34）。
    Early,
    /// `i3t-lane/2` 的 passthrough：两个方向都等 SWITCH。接受方看到目标回了 TLS 1.3 的 ServerHello 时先发，
    /// 发起方收到之后回一个，各自在自己的 SWITCH 所在的记录之后离开 TLS。接受方不发时两个方向都一直在 TLS 里。
    Mutual,
}

impl Mode {
    const fn to_wire(self) -> u8 {
        match self {
            Self::Sealed => MODE_SEALED,
            Self::Early => MODE_EARLY,
            Self::Mutual => MODE_MUTUAL,
        }
    }

    const fn from_wire(raw: u8) -> Option<Self> {
        match raw {
            MODE_SEALED => Some(Self::Sealed),
            MODE_EARLY => Some(Self::Early),
            MODE_MUTUAL => Some(Self::Mutual),
            _ => None,
        }
    }

    /// 对流层说的负载方式：`Early` 和 `Mutual` 都是 passthrough，只是什么时候切换不同。
    pub(crate) const fn payload(self) -> Payload {
        match self {
            Self::Sealed => Payload::Sealed,
            Self::Early | Self::Mutual => Payload::Passthrough,
        }
    }
}

/// 一个帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Frame {
    /// 拨号方在每条 lane 上发的第一个帧。`epoch` 在拨号方每次启动、换了地址、控制 lane 断了之后换一个新的随机值。
    Hello {
        purpose: Purpose,
        epoch: u64,
    },
    /// 控制 lane 上，接受方告诉拨号方：平时为它停着 `idle` 条空闲的 lane；现在另外再拨 `extra` 条（池被抽干了）。
    Pool {
        idle: u16,
        extra: u16,
    },
    Ping(u64),
    Pong(u64),
    /// 发送方进入排空状态：对端不再在与其之间的 lane 上新建流，并关闭空闲 lane。
    GoAway,
    /// 发起方在一条 lane 上开流：选定的负载方式，和流的头（流层的 OPEN 连同首批数据）。
    /// 负载方式是 [`Mode::Early`] 时，发起方这个方向在这个帧所在的记录之后就离开 TLS。
    Opening {
        mode: Mode,
        header: Bytes,
    },
    /// 流的数据（sealed 的方向）。
    Data(Bytes),
    /// 发的一方这个方向在这个帧所在的记录之后离开 TLS。只在 passthrough 的流上允许：接受方在 [`Mode::Early`] 和
    /// [`Mode::Mutual`] 的流上都可以发；发起方只在 [`Mode::Mutual`] 的流上、收到接受方的 SWITCH 之后发，作为回应。
    Switch,
    /// 发的一方异常结束了这条流，带原因码。之后这条 lane 被重置。
    Abort(u32),
    /// 发的一方不再读了，请对方停止发送，带原因码。
    Stop(u32),
    /// 未知帧类型，其内容已被跳过。
    Unknown(u8),
}

impl Frame {
    /// 编码成帧头加内容，追加到 `buf` 末尾。DATA 不走这里，见 [`data_header`]。
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Hello { purpose, epoch } => {
                put_header(buf, TYPE_HELLO, 9);
                buf.push(purpose.to_wire());
                buf.extend_from_slice(&epoch.to_be_bytes());
            }
            Self::Pool { idle, extra } => {
                put_header(buf, TYPE_POOL, 4);
                buf.extend_from_slice(&idle.to_be_bytes());
                buf.extend_from_slice(&extra.to_be_bytes());
            }
            Self::Ping(nonce) => {
                put_header(buf, TYPE_PING, 8);
                buf.extend_from_slice(&nonce.to_be_bytes());
            }
            Self::Pong(nonce) => {
                put_header(buf, TYPE_PONG, 8);
                buf.extend_from_slice(&nonce.to_be_bytes());
            }
            Self::GoAway => put_header(buf, TYPE_GOAWAY, 0),
            Self::Opening { mode, header } => {
                assert!(header.len() <= MAX_HEADER_LEN, "流的头 {} 字节，调用方应该已经限制在 {MAX_HEADER_LEN} 以内", header.len());
                put_header(buf, TYPE_OPENING, 1 + header.len());
                buf.push(mode.to_wire());
                buf.extend_from_slice(header);
            }
            Self::Data(data) => {
                buf.extend_from_slice(&data_header(data.len()));
                buf.extend_from_slice(data);
            }
            Self::Switch => put_header(buf, TYPE_SWITCH, 0),
            Self::Abort(code) => {
                put_header(buf, TYPE_ABORT, 4);
                buf.extend_from_slice(&code.to_be_bytes());
            }
            Self::Stop(code) => {
                put_header(buf, TYPE_STOP, 4);
                buf.extend_from_slice(&code.to_be_bytes());
            }
            Self::Unknown(kind) => put_header(buf, *kind, 0),
        }
    }

    /// 从 `buf` 开头取出一个完整的帧；字节还不够时返回 `None`，`buf` 不变。
    ///
    /// DATA 和 OPENING 的内容和 `buf` 共用内存，不拷贝。
    ///
    /// # Errors
    ///
    /// 收到帧头即校验类型与长度：未知帧类型（`allow_unknown` 为 `false` 时）、长度超出允许范围或帧内容不合法。
    pub(crate) fn decode(buf: &mut BytesMut, allow_unknown: bool) -> Result<Option<Self>, FrameError> {
        let Some(&[kind, hi, lo]) = buf.first_chunk::<HEADER_LEN>() else { return Ok(None) };
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        let allowed = match kind {
            TYPE_HELLO => 9..=9,
            TYPE_POOL => 4..=4,
            TYPE_PING | TYPE_PONG => 8..=8,
            TYPE_GOAWAY | TYPE_SWITCH => 0..=0,
            TYPE_OPENING => 1..=1 + MAX_HEADER_LEN,
            TYPE_DATA => 1..=MAX_DATA_LEN,
            TYPE_ABORT | TYPE_STOP => 4..=4,
            _ if allow_unknown => 0..=MAX_UNKNOWN_LEN,
            _ => return Err(FrameError::UnknownType(kind)),
        };
        if !allowed.contains(&len) {
            return Err(FrameError::Length { kind, len });
        }
        if buf.len() < HEADER_LEN + len {
            return Ok(None);
        }
        buf.advance(HEADER_LEN);
        let mut body = buf.split_to(len);
        let frame = match kind {
            TYPE_HELLO => {
                let purpose = Purpose::from_wire(body.get_u8()).ok_or(FrameError::Invalid("HELLO 中的用途字段"))?;
                Self::Hello { purpose, epoch: body.get_u64() }
            }
            TYPE_POOL => Self::Pool { idle: body.get_u16(), extra: body.get_u16() },
            TYPE_PING => Self::Ping(body.get_u64()),
            TYPE_PONG => Self::Pong(body.get_u64()),
            TYPE_GOAWAY => Self::GoAway,
            TYPE_OPENING => {
                let mode = Mode::from_wire(body.get_u8()).ok_or(FrameError::Invalid("OPENING 中的负载方式字段"))?;
                Self::Opening { mode, header: body.freeze() }
            }
            TYPE_DATA => Self::Data(body.freeze()),
            TYPE_SWITCH => Self::Switch,
            TYPE_ABORT => Self::Abort(body.get_u32()),
            TYPE_STOP => Self::Stop(body.get_u32()),
            other => Self::Unknown(other),
        };
        Ok(Some(frame))
    }
}

/// DATA 帧的帧头。内容另外写，这样内容不用先拷进一块连续的缓冲区。
pub(crate) fn data_header(len: usize) -> [u8; HEADER_LEN] {
    assert!((1..=MAX_DATA_LEN).contains(&len), "DATA 帧 {len} 字节，调用方应该已经切成 1..={MAX_DATA_LEN}");
    let [hi, lo] = u16::try_from(len).expect("上一行已经限制在 u16 以内").to_be_bytes();
    [TYPE_DATA, hi, lo]
}

fn put_header(buf: &mut Vec<u8>, kind: u8, len: usize) {
    let len = u16::try_from(len).expect("各种帧的长度在编码之前都已经限制在 u16 以内");
    buf.push(kind);
    buf.put_u16(len);
}

/// 帧格式无效。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("未知帧类型 {0:#04x}")]
    UnknownType(u8),
    #[error("帧类型 {kind:#04x} 的长度 {len} 无效")]
    Length { kind: u8, len: usize },
    #[error("帧内容无效：{0}")]
    Invalid(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(frame: &Frame) -> Frame {
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let mut bytes = BytesMut::from(&buf[..]);
        let decoded = Frame::decode(&mut bytes, false).unwrap().unwrap();
        assert!(bytes.is_empty(), "一个帧应该正好用完它的字节");
        decoded
    }

    #[test]
    fn every_frame_survives_encoding() {
        let frames = [
            Frame::Hello { purpose: Purpose::Parked, epoch: 0x0102_0304_0506_0708 },
            Frame::Pool { idle: 12, extra: 512 },
            Frame::Ping(7),
            Frame::Pong(u64::MAX),
            Frame::GoAway,
            Frame::Opening { mode: Mode::Early, header: Bytes::from_static(b"open and first data") },
            Frame::Opening { mode: Mode::Mutual, header: Bytes::from_static(b"open and first data") },
            Frame::Opening { mode: Mode::Sealed, header: Bytes::new() },
            Frame::Data(Bytes::from(vec![9; MAX_DATA_LEN])),
            Frame::Switch,
            Frame::Abort(5),
            Frame::Stop(u32::MAX),
        ];
        for frame in &frames {
            assert_eq!(&round_trip(frame), frame);
        }
    }

    /// 0 和 1 是 `i3t-lane/1` 就有的，没升级的节点还在用：编码不能变。
    #[test]
    fn opening_modes_keep_their_wire_values() {
        for (mode, wire) in [(Mode::Sealed, 0), (Mode::Early, 1), (Mode::Mutual, 2)] {
            let mut buf = Vec::new();
            Frame::Opening { mode, header: Bytes::from_static(b"open") }.encode(&mut buf);
            assert_eq!(buf[..4], [TYPE_OPENING, 0, 5, wire], "{mode:?}");
        }
    }

    #[test]
    fn a_frame_is_not_taken_before_all_of_it_arrived() {
        let mut buf = Vec::new();
        Frame::Opening { mode: Mode::Sealed, header: Bytes::from_static(b"0123456789") }.encode(&mut buf);
        for cut in 0..buf.len() {
            let mut bytes = BytesMut::from(&buf[..cut]);
            assert_eq!(Frame::decode(&mut bytes, false), Ok(None), "前 {cut} 字节");
            assert_eq!(bytes.len(), cut, "不完整时不能动缓冲区");
        }
    }

    #[test]
    fn an_oversized_frame_is_refused_from_its_header_alone() {
        let mut bytes = BytesMut::from(&[TYPE_DATA, 0xff, 0xff][..]);
        assert_eq!(Frame::decode(&mut bytes, false), Err(FrameError::Length { kind: TYPE_DATA, len: 0xffff }));
        let mut bytes = BytesMut::from(&[TYPE_OPENING, 0x80, 0x02][..]);
        assert!(matches!(Frame::decode(&mut bytes, false), Err(FrameError::Length { .. })));
        let mut bytes = BytesMut::from(&[TYPE_DATA, 0, 0][..]);
        assert!(matches!(Frame::decode(&mut bytes, false), Err(FrameError::Length { .. })), "空的 DATA 没有意义");
        let mut bytes = BytesMut::from(&[TYPE_HELLO, 0, 8][..]);
        assert!(matches!(Frame::decode(&mut bytes, false), Err(FrameError::Length { .. })));
    }

    #[test]
    fn unknown_frames_are_skipped_only_where_allowed() {
        let mut bytes = BytesMut::from(&[0x7f, 0, 2, 1, 2, TYPE_GOAWAY, 0, 0][..]);
        assert_eq!(Frame::decode(&mut bytes.clone(), false), Err(FrameError::UnknownType(0x7f)));
        assert_eq!(Frame::decode(&mut bytes, true), Ok(Some(Frame::Unknown(0x7f))));
        assert_eq!(Frame::decode(&mut bytes, true), Ok(Some(Frame::GoAway)));
        let mut too_long = BytesMut::from(&[0x7f, 0x04, 0x01][..]);
        assert!(matches!(Frame::decode(&mut too_long, true), Err(FrameError::Length { .. })));
    }

    #[test]
    fn bad_contents_are_refused() {
        let mut bytes = BytesMut::from(&[TYPE_HELLO, 0, 9, 3, 0, 0, 0, 0, 0, 0, 0, 0][..]);
        assert!(matches!(Frame::decode(&mut bytes, false), Err(FrameError::Invalid(_))));
        let mut bytes = BytesMut::from(&[TYPE_OPENING, 0, 1, 3][..]);
        assert!(matches!(Frame::decode(&mut bytes, false), Err(FrameError::Invalid(_))));
    }
}
