//! 一个端口上收到的 UDP 数据报怎么分类，以及经 relay 转发时加在包前面的中转头。
//!
//! 节点只用一个 UDP 端口。端到端连接的包和路径层自己的帧都从这里进来，靠首字节区分：
//!
//! - QUIC 包的首字节一定带 `0x40` 这一位（RFC 9000 §17.2、§17.3 的 Fixed Bit）。带这一位的数据报是对端直连发来的连接包，
//!   整个交给连接层。这要求两端都不启用 RFC 9287 的"把这一位随机化"。
//! - 不带这一位的是路径层的帧，首字节是帧的类型，取值在 `0x00`～`0x3f` 之间。
//!   `0x80`～`0xbf` 不分配给任何帧：QUIC 的版本协商包可能落在这一段（它的这一位是随机填的）。
//!   两端的 QUIC 版本相同时不会有这种包，收到就按不认识的帧丢掉。
//!
//! 帧的类型：
//!
//! | 首字节 | 帧 | 格式在哪里 |
//! |---|---|---|
//! | `0x01` | 经一个 relay 转发的包 | 本模块 |
//! | `0x02`～`0x07`、`0x0c` | 中转会话帧 | [`crate::session`] |
//! | `0x08`、`0x09` | 探测帧 | [`crate::probe`] |
//! | `0x0f`、`0x10` | 主动测试的探测帧 | [`crate::probe`] |
//! | `0x0a`、`0x0b` | 地址查询与应答 | [`crate::addr`] |
//! | `0x0d` | 经多个 relay 转发的包 | 本模块 |
//! | `0x0e` | 骨干矩阵的一行，也是 relay 的过载和下线通知 | [`crate::backbone`] |
//! | `0x11` | 封好的网络包：虚拟网卡的 IP 包，单独加密，不进 QUIC | [`crate::sealed`] |
//!
//! [`Datagram::parse`] 一次调用就把上面这些全部分出来。其余的首字节不认识，数据报直接丢掉，不回应。
//!
//! 经 relay 转发的包：
//!
//! ```text
//! 0      1              5              9
//! +------+--------------+--------------+------------------
//! | 0x01 | 目的节点编号 | 来源节点编号 | 连接层的包 ...
//! +------+--------------+--------------+------------------
//! ```
//!
//! relay 只看前 9 个字节：按目的节点查出它挂上来的地址，把整个数据报原样转出去，不改一个字节。
//! 来源节点编号是给目的节点看的，它据此知道这个包属于和谁的连接。relay 要核对来源节点就是这个数据报所属的中转会话的主人，
//! 不然任何节点都能冒别人的名字往外发包。
//!
//! 经多个 relay 转发的包（A → R1 → … → Rk → D）：
//!
//! ```text
//! 0      1      2              6              10                 10+4n
//! +------+------+--------------+--------------+------------------+------------------
//! | 0x0d | n    | 目的节点编号 | 来源节点编号 | n 个 relay 的编号 | 连接层的包 ...
//! +------+------+--------------+--------------+------------------+------------------
//! ```
//!
//! 头里按顺序写着要经过的全部 relay，n 在 1 到 [`MAX_RELAY_HOPS`] 之间，同一个 relay 不能出现两次。
//! 这个数据报从来源节点到目的节点一路上一个字节都不改：每个 relay 在表里找到自己，前一个是它该从谁那里收到，
//! 后一个是它该转给谁；自己是最后一个时转给目的节点。所以
//!
//! - 表里没有自己的 relay 不转发；
//! - 每个 relay 只认"表里排在自己前面的那一个"发来的（排第一的认来源节点的中转会话），所以一个包在每个 relay 上最多过一次，
//!   绕不成圈；
//! - 级数的上限写在格式里（解析时就拒绝），网络设的更小的上限由每个 relay 在转发时再查一遍。
//!
//! 只经一个 relay 时用前一种 9 字节的头，两种头可以同时存在。

use crate::node::NodeId;
use crate::sealed::{self, SealedHeader};
use crate::{addr, backbone, probe, session};

/// 连接层的一个包最长多少字节。
///
/// 直连和经 relay 这两条路必须装得下同样大的包。连接是按当前那条路探测最大包长的，
/// 如果直连能发的包比经 relay 的大，换到 relay 那条路之后大包就发不出去了。所以每条路都按"加上最长的中转头"来算：
/// 1400 加多级中转的头（最长 26 字节）、UDP 头和 IPv6 头是 1474 字节，以太网（1500）和 PPPoE（1492）都装得下。
/// 更小的链路靠连接层自己的路径 MTU 探测，它从 1200 起步往上试，这里是它的上限。
pub const MAX_CONN_PACKET_LEN: u16 = 1400;

/// 一条路径最多经过几个 relay。这是协议的硬上限，网络可以设得更小（netmap 的 `max_relay_hops`）。
pub const MAX_RELAY_HOPS: usize = 4;

const QUIC_FIXED_BIT: u8 = 0x40;
const KIND_RELAYED: u8 = 0x01;
const KIND_ROUTED: u8 = 0x0d;

const _: () = {
    const UDP_HEADER: usize = 8;
    const IPV6_HEADER: usize = 40;
    const PPPOE_MTU: usize = 1492;
    assert!(RelayHeader::LEN <= RouteHeader::MAX_LEN);
    assert!(MAX_CONN_PACKET_LEN as usize + RouteHeader::MAX_LEN + UDP_HEADER + IPV6_HEADER <= PPPOE_MTU);
    // 帧的类型不能和 QUIC 包的首字节混淆。
    assert!(KIND_RELAYED < QUIC_FIXED_BIT && KIND_ROUTED < QUIC_FIXED_BIT && backbone::KIND_ROW < QUIC_FIXED_BIT);
    assert!(session::KIND_ERROR < QUIC_FIXED_BIT && probe::KIND_PONG < QUIC_FIXED_BIT && addr::KIND_REPLY < QUIC_FIXED_BIT);
    assert!(sealed::KIND_SEALED < QUIC_FIXED_BIT);
};

/// 经 relay 转发的包前面的头。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayHeader {
    /// 包要送到哪个节点。
    pub dst: NodeId,
    /// 包是哪个节点发出的。
    pub src: NodeId,
}

impl RelayHeader {
    /// 编码之后占的字节数：类型 1 字节，两个节点编号各 4 字节。
    pub const LEN: usize = 1 + 2 * NodeId::WIRE_LEN;

    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        let [d0, d1, d2, d3] = self.dst.to_be_bytes();
        let [s0, s1, s2, s3] = self.src.to_be_bytes();
        [KIND_RELAYED, d0, d1, d2, d3, s0, s1, s2, s3]
    }

    /// `bytes` 的首字节已经确认是 [`KIND_RELAYED`]。
    const fn from_bytes(bytes: &[u8; Self::LEN]) -> Result<Self, DatagramError> {
        let [_, d0, d1, d2, d3, s0, s1, s2, s3] = *bytes;
        match (NodeId::from_be_bytes([d0, d1, d2, d3]), NodeId::from_be_bytes([s0, s1, s2, s3])) {
            (Some(dst), Some(src)) => Ok(Self { dst, src }),
            _ => Err(DatagramError::ZeroNodeId),
        }
    }
}

/// 经多个 relay 时按顺序要经过的 relay：1 到 [`MAX_RELAY_HOPS`] 个，没有重复的。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayPath {
    len: u8,
    /// 用不到的位置填的是第一个 relay，这样逐字段比较和哈希都只取决于路径本身。
    relays: [NodeId; MAX_RELAY_HOPS],
}

impl RelayPath {
    /// # Errors
    ///
    /// `relays` 是空的、超过 [`MAX_RELAY_HOPS`] 个，或者同一个 relay 出现了两次。
    pub fn new(relays: &[NodeId]) -> Result<Self, InvalidRelayPath> {
        let (Some((&first, rest)), true) = (relays.split_first(), relays.len() <= MAX_RELAY_HOPS) else {
            return Err(InvalidRelayPath::Length { len: relays.len() });
        };
        let mut path = Self { len: 1, relays: [first; MAX_RELAY_HOPS] };
        for &relay in rest {
            if path.as_slice().contains(&relay) {
                return Err(InvalidRelayPath::Repeated(relay));
            }
            path.relays[usize::from(path.len)] = relay;
            path.len += 1;
        }
        Ok(path)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[NodeId] {
        &self.relays[..usize::from(self.len)]
    }

    /// 第一个 relay：来源节点把包交给它。
    #[must_use]
    pub const fn first(&self) -> NodeId {
        self.relays[0]
    }

    /// 最后一个 relay：它把包交给目的节点，所以必须是目的节点挂靠的。
    #[must_use]
    pub fn last(&self) -> NodeId {
        self.relays[usize::from(self.len) - 1]
    }

    /// `relay` 在路径上的位置和它的前后邻居。`relay` 不在路径上时返回 `None`。
    #[must_use]
    pub fn around(&self, relay: NodeId) -> Option<Neighbours> {
        let relays = self.as_slice();
        let index = relays.iter().position(|hop| *hop == relay)?;
        Some(Neighbours { previous: index.checked_sub(1).map(|previous| relays[previous]), next: relays.get(index + 1).copied() })
    }
}

impl std::fmt::Debug for RelayPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

/// 路径上一个 relay 的前后邻居。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Neighbours {
    /// 前一个 relay；`None` 表示这个 relay 排第一，包应该直接来自来源节点。
    pub previous: Option<NodeId>,
    /// 后一个 relay；`None` 表示这个 relay 排最后，包应该交给目的节点。
    pub next: Option<NodeId>,
}

/// 一组 relay 不能当作路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidRelayPath {
    #[error("路径上要有 1 到 {MAX_RELAY_HOPS} 个 relay，给了 {len} 个")]
    Length { len: usize },
    #[error("relay {0} 在路径上出现了两次")]
    Repeated(NodeId),
}

/// 经多个 relay 转发的包前面的头。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteHeader {
    /// 包要送到哪个节点。
    pub dst: NodeId,
    /// 包是哪个节点发出的。
    pub src: NodeId,
    pub relays: RelayPath,
}

impl RouteHeader {
    /// relay 表之前的部分：类型、relay 的个数、两个节点编号。
    const FIXED_LEN: usize = 2 + 2 * NodeId::WIRE_LEN;
    /// 编码之后最长多少字节。
    pub const MAX_LEN: usize = Self::FIXED_LEN + MAX_RELAY_HOPS * NodeId::WIRE_LEN;

    /// 编码之后占的字节数。
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        Self::FIXED_LEN + self.relays.as_slice().len() * NodeId::WIRE_LEN
    }

    /// 把头追加到 `buf` 末尾。
    pub fn put(&self, buf: &mut Vec<u8>) {
        buf.push(KIND_ROUTED);
        buf.push(self.relays.len);
        buf.extend_from_slice(&self.dst.to_be_bytes());
        buf.extend_from_slice(&self.src.to_be_bytes());
        for relay in self.relays.as_slice() {
            buf.extend_from_slice(&relay.to_be_bytes());
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.put(&mut bytes);
        bytes
    }

    /// 从数据报开头取出头，返回它和后面的包。首字节已经确认是 [`KIND_ROUTED`]。
    fn take(datagram: &[u8]) -> Result<(Self, &[u8]), DatagramError> {
        let truncated = DatagramError::TruncatedRelayHeader { len: datagram.len() };
        let (&[_, count, d0, d1, d2, d3, s0, s1, s2, s3], rest) = datagram.split_first_chunk::<{ Self::FIXED_LEN }>().ok_or(truncated)?;
        let count = usize::from(count);
        if count == 0 || count > MAX_RELAY_HOPS {
            return Err(DatagramError::BadRoute);
        }
        let (list, packet) = rest.split_at_checked(count * NodeId::WIRE_LEN).ok_or(truncated)?;
        let (Some(dst), Some(src)) = (NodeId::from_be_bytes([d0, d1, d2, d3]), NodeId::from_be_bytes([s0, s1, s2, s3])) else {
            return Err(DatagramError::ZeroNodeId);
        };
        // 先放一个占位的编号，逐个换成帧里写的；这样不用为了几个编号去分配。
        let mut relays = [dst; MAX_RELAY_HOPS];
        for (slot, id) in relays.iter_mut().zip(list.as_chunks::<{ NodeId::WIRE_LEN }>().0) {
            *slot = NodeId::from_be_bytes(*id).ok_or(DatagramError::ZeroNodeId)?;
        }
        let relays = RelayPath::new(&relays[..count]).map_err(|_| DatagramError::BadRoute)?;
        Ok((Self { dst, src, relays }, packet))
    }
}

/// 一个 UDP 数据报（或 TCP 中转里的一帧）解析出来的内容。
///
/// 带着包的几种借用原来的缓冲区，不拷贝；其余几种是路径层自己的帧，都很短，解析成值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datagram<'a> {
    /// 对端直连发来的连接包，就是整个数据报。
    Conn(&'a [u8]),
    /// 经一个 relay 转发的包。`packet` 是去掉中转头之后的连接包。
    Relayed { header: RelayHeader, packet: &'a [u8] },
    /// 经多个 relay 转发的包。`packet` 是去掉头之后的连接包。
    Routed { header: RouteHeader, packet: &'a [u8] },
    /// 对端直连发来的封好的网络包，就是整个数据报。这里只核对过长度；密钥在连接层，认不认由它定。
    Sealed(&'a [u8]),
    /// 骨干矩阵的一行，是整个数据报。这里只核对过长度对得上，内容用 [`backbone::Row::parse`] 取，签名由收的一方去验。
    Row(&'a [u8]),
    /// 中转会话帧。[`session::Frame::is_request`] 为真的归 relay 处理，其余是 relay 的应答，归路径层。
    Session(session::Frame),
    /// 探测帧，归路径层。
    Probe(probe::Frame),
    /// 地址查询。
    AddrQuery(addr::Query),
    /// 地址查询的应答。
    AddrReply(addr::Reply),
}

impl<'a> Datagram<'a> {
    /// # Errors
    ///
    /// 数据报是空的、帧的类型不认识、帧不完整或者里面的节点编号是 0。
    /// 这些数据报都应该直接丢掉，不回应。
    pub fn parse(datagram: &'a [u8]) -> Result<Self, DatagramError> {
        let &first = datagram.first().ok_or(DatagramError::Empty)?;
        if first & QUIC_FIXED_BIT != 0 {
            return Ok(Self::Conn(datagram));
        }
        let malformed = DatagramError::Malformed { kind: first };
        match first {
            KIND_RELAYED => {
                let (head, packet) = datagram
                    .split_first_chunk::<{ RelayHeader::LEN }>()
                    .ok_or(DatagramError::TruncatedRelayHeader { len: datagram.len() })?;
                Ok(Self::Relayed { header: RelayHeader::from_bytes(head)?, packet })
            }
            KIND_ROUTED => RouteHeader::take(datagram).map(|(header, packet)| Self::Routed { header, packet }),
            backbone::KIND_ROW if backbone::Row::is_complete(datagram) => Ok(Self::Row(datagram)),
            backbone::KIND_ROW => Err(malformed),
            kind if session::Frame::is_session_kind(kind) => session::Frame::parse(datagram).map(Self::Session).ok_or(malformed),
            probe::KIND_PING | probe::KIND_PONG | probe::KIND_TEST_PING | probe::KIND_TEST_PONG => {
                probe::Frame::parse(datagram).map(Self::Probe).ok_or(malformed)
            }
            addr::KIND_QUERY => addr::Query::parse(datagram).map(Self::AddrQuery).ok_or(malformed),
            addr::KIND_REPLY => addr::Reply::parse(datagram).map(Self::AddrReply).ok_or(malformed),
            sealed::KIND_SEALED if SealedHeader::is_complete(datagram) => Ok(Self::Sealed(datagram)),
            sealed::KIND_SEALED => Err(malformed),
            kind => Err(DatagramError::UnknownKind(kind)),
        }
    }
}

/// 只取出一个经 relay 转发的数据报要去的节点，别的都不看。不是这种数据报时返回 `None`。
///
/// relay 用它决定往哪里转。内核一次交上来的一批数据报可能来自不同的节点、发往不同的节点，
/// 所以要对每一个数据报调用，不能看了第一个就把整批转给同一个目的地。
#[must_use]
pub fn relayed_dst(datagram: &[u8]) -> Option<NodeId> {
    match datagram.split_first_chunk::<{ 1 + NodeId::WIRE_LEN }>()? {
        (&[KIND_RELAYED, d0, d1, d2, d3], _) => NodeId::from_be_bytes([d0, d1, d2, d3]),
        _ => None,
    }
}

/// 一个要由 relay 转发的数据报（一级或者多级）前面的头有多长。不是这两种数据报，或者头不完整时返回 `None`。
///
/// relay 用它把一批数据报里头完全相同的一段找出来，整段一次转出去。它只看长度，头的内容由 [`Datagram::parse`] 去核对。
#[must_use]
pub fn forwarding_header_len(datagram: &[u8]) -> Option<usize> {
    let len = match *datagram {
        [KIND_RELAYED, ..] => RelayHeader::LEN,
        [KIND_ROUTED, count, ..] => RouteHeader::FIXED_LEN + usize::from(count) * NodeId::WIRE_LEN,
        _ => return None,
    };
    (len <= datagram.len() && len <= RouteHeader::MAX_LEN).then_some(len)
}

/// 数据报解析不了的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DatagramError {
    #[error("数据报是空的")]
    Empty,
    #[error("不认识的帧类型 {0:#04x}")]
    UnknownKind(u8),
    #[error("中转头要 {} 字节，整个数据报只有 {len} 字节", RelayHeader::LEN)]
    TruncatedRelayHeader { len: usize },
    #[error("中转头里的节点编号是 0")]
    ZeroNodeId,
    #[error("多级中转的头里 relay 的个数不在 1 到 {MAX_RELAY_HOPS} 之间，或者同一个 relay 出现了两次")]
    BadRoute,
    #[error("类型是 {kind:#04x} 的帧不完整，或者内容不合格式")]
    Malformed { kind: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn relayed(dst: u32, src: u32, packet: &[u8]) -> Vec<u8> {
        let mut datagram = RelayHeader { dst: node(dst), src: node(src) }.to_bytes().to_vec();
        datagram.extend_from_slice(packet);
        datagram
    }

    #[test]
    fn a_sealed_packet_is_recognised_whole_and_a_truncated_one_is_malformed() {
        let mut datagram = SealedHeader { session: 7, counter: 9 }.to_bytes().to_vec();
        datagram.extend_from_slice(&[0xab; SealedHeader::TAG_LEN + 1]);
        assert_eq!(Datagram::parse(&datagram), Ok(Datagram::Sealed(&datagram)));
        assert_eq!(relayed_dst(&datagram), None, "它不是中转帧");
        let short = &datagram[..datagram.len() - 1];
        assert_eq!(Datagram::parse(short), Err(DatagramError::Malformed { kind: sealed::KIND_SEALED }));
    }

    #[test]
    fn packets_with_the_quic_fixed_bit_go_to_the_connection_untouched() {
        for first in [0x40, 0x7f, 0xc0, 0xff] {
            let datagram = [first, 1, 2, 3];
            assert_eq!(Datagram::parse(&datagram), Ok(Datagram::Conn(&datagram)));
            assert_eq!(relayed_dst(&datagram), None);
        }
    }

    #[test]
    fn relayed_frame_has_the_documented_layout() {
        let datagram = relayed(2, 0x0a0b_0c0d, b"quic");
        assert_eq!(datagram, [0x01, 0, 0, 0, 2, 0x0a, 0x0b, 0x0c, 0x0d, b'q', b'u', b'i', b'c']);
    }

    #[test]
    fn relayed_frame_round_trips() {
        let datagram = relayed(7, 9, b"payload");
        let expected = Datagram::Relayed { header: RelayHeader { dst: node(7), src: node(9) }, packet: b"payload" };
        assert_eq!(Datagram::parse(&datagram), Ok(expected));
        assert_eq!(relayed_dst(&datagram), Some(node(7)));
    }

    #[test]
    fn relayed_frame_may_carry_an_empty_packet() {
        let datagram = relayed(7, 9, b"");
        assert!(matches!(Datagram::parse(&datagram), Ok(Datagram::Relayed { packet: [], .. })));
    }

    #[test]
    fn truncated_relay_header_is_rejected() {
        let datagram = relayed(7, 9, b"");
        for len in 1..RelayHeader::LEN {
            assert_eq!(Datagram::parse(&datagram[..len]), Err(DatagramError::TruncatedRelayHeader { len }));
        }
        // 目的节点那 4 个字节不全时，relay 的快速路径也不能给出结果。
        for len in 0..=NodeId::WIRE_LEN {
            assert_eq!(relayed_dst(&datagram[..len]), None);
        }
    }

    #[test]
    fn zero_node_ids_are_rejected() {
        assert_eq!(Datagram::parse(&[0x01, 0, 0, 0, 0, 0, 0, 0, 9]), Err(DatagramError::ZeroNodeId));
        assert_eq!(Datagram::parse(&[0x01, 0, 0, 0, 7, 0, 0, 0, 0]), Err(DatagramError::ZeroNodeId));
        assert_eq!(relayed_dst(&[0x01, 0, 0, 0, 0, 0, 0, 0, 9]), None);
    }

    #[test]
    fn empty_and_unknown_datagrams_are_rejected() {
        assert_eq!(Datagram::parse(&[]), Err(DatagramError::Empty));
        for kind in [0x00, 0x12, 0x3f, 0x80, 0xbf] {
            assert_eq!(Datagram::parse(&[kind, 0, 0, 0, 1, 0, 0, 0, 2]), Err(DatagramError::UnknownKind(kind)));
            assert_eq!(relayed_dst(&[kind, 0, 0, 0, 1, 0, 0, 0, 2]), None);
            assert_eq!(forwarding_header_len(&[kind, 0, 0, 0, 1, 0, 0, 0, 2]), None);
        }
    }

    #[test]
    fn session_frames_are_classified_by_their_first_byte() {
        let nonce = [7; session::NONCE_LEN];
        let observed = "203.0.113.7:20330".parse().unwrap();
        let frames = [
            session::Frame::Init(session::Init { node: node(1), nonce }),
            session::Frame::Challenge(session::Challenge { nonce, cookie: [3; session::COOKIE_LEN] }),
            session::Frame::Auth(session::Auth { node: node(1), nonce, cookie: [3; 16], signature: [4; 64] }),
            session::Frame::Ok(session::Accepted { nonce, valid_for: 30, observed, signature: [4; 64] }),
            session::Frame::Ping(session::Ping { node: node(1), nonce }),
            session::Frame::Pong(session::Pong { nonce, observed }),
            session::Frame::Error(session::Refused { reason: session::RefusalReason::NoSession, node: node(1) }),
        ];
        for frame in frames {
            let bytes = match frame {
                session::Frame::Init(init) => init.to_bytes().to_vec(),
                session::Frame::Challenge(challenge) => challenge.to_bytes().to_vec(),
                session::Frame::Auth(auth) => auth.to_bytes().to_vec(),
                session::Frame::Ok(ok) => ok.to_bytes(),
                session::Frame::Ping(ping) => ping.to_bytes().to_vec(),
                session::Frame::Pong(pong) => pong.to_bytes(),
                session::Frame::Error(refused) => refused.to_bytes().to_vec(),
            };
            assert_eq!(Datagram::parse(&bytes), Ok(Datagram::Session(frame)));
            assert_eq!(relayed_dst(&bytes), None);
        }
    }

    #[test]
    fn probe_and_address_frames_are_classified_by_their_first_byte() {
        let nonce = [7; 8];
        let observed = "[2001:db8::1]:443".parse().unwrap();
        let ping = probe::Ping { src: node(1), dst: node(2), nonce, signature: [4; 64] };
        assert_eq!(Datagram::parse(&ping.to_bytes()), Ok(Datagram::Probe(probe::Frame::Ping(ping))));
        let pong = probe::Pong { src: node(2), dst: node(1), nonce, observed, signature: [4; 64] };
        assert_eq!(Datagram::parse(&pong.to_bytes()), Ok(Datagram::Probe(probe::Frame::Pong(pong))));

        let query = addr::Query { nonce };
        assert_eq!(Datagram::parse(&query.to_bytes()), Ok(Datagram::AddrQuery(query)));
        let reply = addr::Reply { nonce, observed };
        assert_eq!(Datagram::parse(&reply.to_bytes()), Ok(Datagram::AddrReply(reply)));
    }

    #[test]
    fn truncated_frames_of_a_known_kind_are_rejected_as_malformed() {
        for kind in [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0e] {
            assert_eq!(Datagram::parse(&[kind, 0, 0, 0, 1]), Err(DatagramError::Malformed { kind }));
        }
    }

    fn routed(dst: u32, src: u32, relays: &[u32], packet: &[u8]) -> Vec<u8> {
        let relays: Vec<NodeId> = relays.iter().map(|&relay| node(relay)).collect();
        let mut datagram = RouteHeader { dst: node(dst), src: node(src), relays: RelayPath::new(&relays).unwrap() }.to_bytes();
        datagram.extend_from_slice(packet);
        datagram
    }

    #[test]
    fn routed_frame_has_the_documented_layout_and_round_trips() {
        let datagram = routed(2, 0x0a0b_0c0d, &[8, 9], b"quic");
        assert_eq!(datagram, [0x0d, 2, 0, 0, 0, 2, 0x0a, 0x0b, 0x0c, 0x0d, 0, 0, 0, 8, 0, 0, 0, 9, b'q', b'u', b'i', b'c']);
        let Ok(Datagram::Routed { header, packet }) = Datagram::parse(&datagram) else { panic!("应该是多级中转的包") };
        assert_eq!((header.dst, header.src, header.relays.as_slice()), (node(2), node(0x0a0b_0c0d), &[node(8), node(9)][..]));
        assert_eq!((packet, header.encoded_len()), (&b"quic"[..], 18));
        assert_eq!(forwarding_header_len(&datagram), Some(18));
        assert_eq!(relayed_dst(&datagram), None, "一级中转的快速路径不认它");

        // 级数从 1 到协议的上限都可以；头最长 26 字节。
        for hops in 1..=MAX_RELAY_HOPS {
            let relays: Vec<u32> = (100..).take(hops).collect();
            let datagram = routed(2, 1, &relays, b"");
            assert_eq!(datagram.len(), 10 + 4 * hops);
            assert!(matches!(Datagram::parse(&datagram), Ok(Datagram::Routed { packet: [], .. })));
        }
        assert_eq!(RouteHeader::MAX_LEN, 26);
        assert_eq!(forwarding_header_len(&relayed(7, 9, b"x")), Some(RelayHeader::LEN));
    }

    #[test]
    fn a_relay_finds_its_neighbours_on_the_path() {
        let path = RelayPath::new(&[node(7), node(8), node(9)]).unwrap();
        assert_eq!((path.first(), path.last()), (node(7), node(9)));
        assert_eq!(path.around(node(7)), Some(Neighbours { previous: None, next: Some(node(8)) }));
        assert_eq!(path.around(node(8)), Some(Neighbours { previous: Some(node(7)), next: Some(node(9)) }));
        assert_eq!(path.around(node(9)), Some(Neighbours { previous: Some(node(8)), next: None }));
        assert_eq!(path.around(node(5)), None, "不在路径上的 relay 不该转发");
        let single = RelayPath::new(&[node(7)]).unwrap();
        assert_eq!(single.around(node(7)), Some(Neighbours { previous: None, next: None }));
        assert_eq!(format!("{path:?}"), "[NodeId(7), NodeId(8), NodeId(9)]");
        assert_eq!(path, RelayPath::new(&[node(7), node(8), node(9)]).unwrap());
        assert_ne!(path, RelayPath::new(&[node(7), node(8)]).unwrap());
    }

    #[test]
    fn paths_that_loop_or_exceed_the_hop_limit_cannot_be_built_or_parsed() {
        let ids = |raw: &[u32]| raw.iter().map(|&id| node(id)).collect::<Vec<_>>();
        assert_eq!(RelayPath::new(&[]), Err(InvalidRelayPath::Length { len: 0 }));
        assert_eq!(RelayPath::new(&ids(&[1, 2, 3, 4, 5])), Err(InvalidRelayPath::Length { len: 5 }));
        assert_eq!(RelayPath::new(&ids(&[7, 8, 7])), Err(InvalidRelayPath::Repeated(node(7))));

        // 线上：relay 的个数是 0、超过上限，或者同一个 relay 出现两次（想让包绕圈）。
        let mut frame = routed(2, 1, &[7, 8, 9], b"x");
        frame[1] = 0;
        assert_eq!(Datagram::parse(&frame), Err(DatagramError::BadRoute));
        let mut too_long = vec![0x0d, 5, 0, 0, 0, 2, 0, 0, 0, 1];
        too_long.extend((7..12u32).flat_map(u32::to_be_bytes));
        assert_eq!(Datagram::parse(&too_long), Err(DatagramError::BadRoute));
        assert_eq!(forwarding_header_len(&too_long), None);
        let mut looped = routed(2, 1, &[7, 8, 9], b"x");
        looped[18..22].copy_from_slice(&[0, 0, 0, 7]);
        assert_eq!(Datagram::parse(&looped), Err(DatagramError::BadRoute));
    }

    #[test]
    fn truncated_or_zeroed_routed_headers_are_rejected() {
        let datagram = routed(2, 1, &[7, 8], b"");
        for len in 1..datagram.len() {
            assert_eq!(Datagram::parse(&datagram[..len]), Err(DatagramError::TruncatedRelayHeader { len }), "{len}");
            assert_eq!(forwarding_header_len(&datagram[..len]), None, "{len}");
        }
        for zeroed in [2..6, 6..10, 10..14, 14..18] {
            let mut frame = datagram.clone();
            frame[zeroed].fill(0);
            assert_eq!(Datagram::parse(&frame), Err(DatagramError::ZeroNodeId));
        }
    }

    #[test]
    fn a_backbone_row_is_recognised_by_its_length_alone() {
        let row = backbone::Row { origin: node(9), seq: 1, state: backbone::RelayState::Serving, load_percent: 0, links: Vec::new() };
        let frame = row.to_bytes(&[4; 64]);
        assert_eq!(Datagram::parse(&frame), Ok(Datagram::Row(&frame)));
        assert_eq!(Datagram::parse(&frame[..frame.len() - 1]), Err(DatagramError::Malformed { kind: 0x0e }));
        assert_eq!(forwarding_header_len(&frame), None);
    }
}
