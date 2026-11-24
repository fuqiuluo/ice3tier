//! 探测帧（节点和节点之间的直连验证、打洞、测延迟）。
//!
//! ```text
//! A → B  PING  0x08 | 来源 A 4 | 目的 B 4 | 随机数 8 | 签名 64 | 填充到 100 字节
//! B → A  PONG  0x09 | 来源 B 4 | 目的 A 4 | 随机数 8 | 地址 7 或 19 | 签名 64            最长 100 字节
//! ```
//!
//! 整数都是大端。地址是 B 看到的这个 PING 的来源地址，编码和中转会话帧里的一样（[`crate::session`]）。
//!
//! A 向 B 的某个候选地址发 PING，收到带着同一个随机数、签名正确的 PONG，这个地址才算 B 的已验证直连地址。
//!
//! 同样的两种帧也用来做端到端的路径探测：A 把 PING 当作"连接层的包"套上中转头，经它现在走的那条 relay 路径发给 B，
//! B 从它自己到 A 的路把 PONG 发回来（这时"看到的地址"没有意义，填 `0.0.0.0:0`）。回答到了，说明这条路径确实送得到 B。
//! 路径上后续 relay 无法将"不可达"通知 A，A 依赖该机制检测中间中断的多级路径。连接包首字节必定置有 QUIC 固定位，
//! 所以 B 分得清收到的是连接包还是探测。
//!
//! # 对没有认证过的来源
//!
//! - **应答不大于请求。** PING 带填充，与最长 PONG 等长；长度短于规定值的 PING 一律拒绝。
//! - 每个探测帧都带发送方的签名，所以收的一方要先验签名才知道该不该理。验签名不便宜，
//!   实现要先用不花钱的条件筛一遍（目的是不是自己、来源是不是 netmap 里的对端），并且对陌生地址来的 PING 限速。
//! - 收的一方不因为一个 PING 记下任何长期状态：PONG 里要的东西都在 PING 里。
//!
//! # 签的是什么
//!
//! 签名由调用方用 `i3t_crypto::NodeKey::sign(用途, 消息)` 来算，这里只规定消息的字节：
//!
//! | 帧 | 用途标签 | 消息 |
//! |---|---|---|
//! | PING | [`Ping::PURPOSE`] | [`Ping::signed_message`]：来源、目的、随机数 |
//! | PONG | [`Pong::PURPOSE`] | [`Pong::signed_message`]：来源、目的、随机数、地址 |
//!
//! 签名消息包含目的节点，因此发给 B 的探测帧无法复用于 C。重放 PONG 亦无效，因为随机数不匹配。
//!
//! PING 里没有时间，也没有 B 给出的东西，所以一个截下来的 PING 可以从任何地址重放，签名照样是对的。收的一方因此不能
//! 只凭一个 PING 就长期相信它的来源地址：只能短暂地认那个地址来的连接包，要等自己向那个地址发的 PING 得到回答才算验证过；
//! 一个地址同时被几个对端认领时，归正在把它当直连用的那个。PONG 里"看到的地址"也要核对：中间有人来回转发探测时，
//! 它是转发者的地址，不是本节点的。这些规则在路径层（`i3t-path` 的 `direct` 和 `control`）。
//!
//! # 主动测试的探测
//!
//! 管理员发起的主动测试在一条指定的路径上发一列探测量延迟和丢包，用另外两种帧：
//!
//! ```text
//! A → B  TPING 0x0f | 来源 A 4 | 目的 B 4 | 测试编号 8 | 序号 4 | relay 数 n 1 | n 个 relay 4n | 签名 64 | 填充到 102 字节
//! B → A  TPONG 0x10 | 来源 B 4 | 目的 A 4 | 测试编号 8 | 序号 4 | 停留 4 | 已收到 4 | 标志 1 | 签名 64                 94 字节
//! ```
//!
//! - `n` 是 0 时 TPING 直接发到 B 的直连地址；不是 0 时它和连接包一样套上中转头，按顺序经过这 n 个 relay。
//!   B 把 TPONG 从同一条路径倒着发回来（直连的回到 TPING 的来源地址），这样量到的是这条路径两个方向的往返。
//!   当 B 无法沿反向路径返回时（例如与末跳 relay 无会话），则经自身当前路径回传，并将标志第 0 位置为 0。
//! - 停留是 B 从收到 TPING 到发出 TPONG 用了多少微秒，A 从往返时间里减掉它，量到的就只是路上的时间。
//! - 已收到是 B 在这个测试的这条路径上一共收到了几个不同的 TPING（含这一个），A 用它把丢包分成去和回两个方向。
//! - 测试编号来自 controller 给两端的同一个指令。B 只回答它知道的、还在时间窗里的测试，并且只回答指令里那个对端的；
//!   每个序号只回答一次，所以重放一个 TPING 引不出第二个 TPONG。TPING 带填充，比 TPONG 长。
//! - 签名的用途标签和普通的探测不同，两种帧互相拿去冒充没有用。

use std::net::SocketAddr;

use crate::datagram::{MAX_RELAY_HOPS, RelayPath};
use crate::node::NodeId;
use crate::session::{self, MAX_ADDR_LEN, NONCE_LEN, Nonce, SIGNATURE_LEN};

pub const KIND_PING: u8 = 0x08;
pub const KIND_PONG: u8 = 0x09;
pub const KIND_TEST_PING: u8 = 0x0f;
pub const KIND_TEST_PONG: u8 = 0x10;

/// 主动测试的编号。controller 给的，同一个测试在两端是同一个数。
pub type TestId = u64;

/// TPONG 标志：从 TPING 来的那条路径倒着发回来的。
const FLAG_SAME_PATH: u8 = 0b0000_0001;

/// 类型、来源、目的、随机数。
const HEAD_LEN: usize = 1 + 2 * NodeId::WIRE_LEN + NONCE_LEN;

struct Head {
    src: NodeId,
    dst: NodeId,
    nonce: Nonce,
}

impl Head {
    fn put(&self, kind: u8, buf: &mut Vec<u8>) {
        buf.push(kind);
        buf.extend_from_slice(&self.src.to_be_bytes());
        buf.extend_from_slice(&self.dst.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
    }

    fn take(datagram: &[u8], kind: u8) -> Option<(Self, &[u8])> {
        let (&first, rest) = datagram.split_first()?;
        if first != kind {
            return None;
        }
        let (&src, rest) = rest.split_first_chunk::<{ NodeId::WIRE_LEN }>()?;
        let (&dst, rest) = rest.split_first_chunk::<{ NodeId::WIRE_LEN }>()?;
        let (&nonce, rest) = rest.split_first_chunk::<NONCE_LEN>()?;
        Some((Self { src: NodeId::from_be_bytes(src)?, dst: NodeId::from_be_bytes(dst)?, nonce }, rest))
    }

    fn signed_message(&self, extra_capacity: usize) -> Vec<u8> {
        let mut message = Vec::with_capacity(HEAD_LEN - 1 + extra_capacity);
        message.extend_from_slice(&self.src.to_be_bytes());
        message.extend_from_slice(&self.dst.to_be_bytes());
        message.extend_from_slice(&self.nonce);
        message
    }
}

/// PING：`src` 问 `dst`"你在这个地址上吗"。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub src: NodeId,
    pub dst: NodeId,
    pub nonce: Nonce,
    /// `src` 对 [`Ping::signed_message`] 的签名。
    pub signature: [u8; SIGNATURE_LEN],
}

impl Ping {
    /// 帧的长度，含填充。和最长的 PONG 一样长。
    pub const LEN: usize = Pong::MAX_LEN;
    /// 签名的用途标签。
    pub const PURPOSE: &str = "probe-ping";

    #[must_use]
    pub fn signed_message(src: NodeId, dst: NodeId, nonce: &Nonce) -> Vec<u8> {
        Head { src, dst, nonce: *nonce }.signed_message(0)
    }

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        let (head, rest) = bytes.split_at_mut(HEAD_LEN);
        head[0] = KIND_PING;
        head[1..1 + NodeId::WIRE_LEN].copy_from_slice(&self.src.to_be_bytes());
        head[1 + NodeId::WIRE_LEN..1 + 2 * NodeId::WIRE_LEN].copy_from_slice(&self.dst.to_be_bytes());
        head[1 + 2 * NodeId::WIRE_LEN..].copy_from_slice(&self.nonce);
        rest[..SIGNATURE_LEN].copy_from_slice(&self.signature);
        bytes
    }

    /// 非完整 PING 时返回 `None`。长度小于 [`Ping::LEN`] 的一律拒绝，避免应答大于请求。
    /// 只看格式，签名由收的一方去验。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < Self::LEN {
            return None;
        }
        let (head, rest) = Head::take(datagram, KIND_PING)?;
        Some(Self { src: head.src, dst: head.dst, nonce: head.nonce, signature: *rest.first_chunk::<SIGNATURE_LEN>()? })
    }
}

/// PONG：`src` 回答 `dst` 的 PING。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    /// 回答的一方，也就是 PING 的目的节点。
    pub src: NodeId,
    /// PING 的来源节点。
    pub dst: NodeId,
    /// 原样抄回 PING 里的随机数。
    pub nonce: Nonce,
    /// `src` 看到的 PING 的来源地址，`dst` 靠它知道自己在 NAT 外面的地址。
    pub observed: SocketAddr,
    /// `src` 对 [`Pong::signed_message`] 的签名。
    pub signature: [u8; SIGNATURE_LEN],
}

impl Pong {
    /// 帧最长多少字节（IPv6 地址时）。
    pub const MAX_LEN: usize = HEAD_LEN + MAX_ADDR_LEN + SIGNATURE_LEN;
    /// 签名的用途标签。
    pub const PURPOSE: &str = "probe-pong";

    #[must_use]
    pub fn signed_message(src: NodeId, dst: NodeId, nonce: &Nonce, observed: SocketAddr) -> Vec<u8> {
        let mut message = Head { src, dst, nonce: *nonce }.signed_message(MAX_ADDR_LEN);
        session::put_addr(&mut message, observed);
        message
    }

    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::MAX_LEN);
        Head { src: self.src, dst: self.dst, nonce: self.nonce }.put(KIND_PONG, &mut bytes);
        session::put_addr(&mut bytes, self.observed);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// 不是一个完整的 PONG 时返回 `None`。只看格式，签名和随机数由收的一方去核对。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (head, rest) = Head::take(datagram, KIND_PONG)?;
        let (observed, rest) = session::take_addr(rest)?;
        let signature = *<&[u8; SIGNATURE_LEN]>::try_from(rest).ok()?;
        Some(Self { src: head.src, dst: head.dst, nonce: head.nonce, observed, signature })
    }
}

/// TPING 和 TPONG 开头相同的部分：类型、来源、目的、测试编号、序号。
const TEST_HEAD_LEN: usize = 1 + 2 * NodeId::WIRE_LEN + 8 + 4;

/// TPING、TPONG 类型之后的那几个字段。
struct TestHead {
    src: NodeId,
    dst: NodeId,
    test: TestId,
    seq: u32,
}

impl TestHead {
    /// `kind` 是 `None` 时不写类型：签名的消息里没有它，用途标签已经分开了两种帧。
    fn put(&self, kind: Option<u8>, buf: &mut Vec<u8>) {
        buf.extend(kind);
        buf.extend_from_slice(&self.src.to_be_bytes());
        buf.extend_from_slice(&self.dst.to_be_bytes());
        buf.extend_from_slice(&self.test.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
    }

    fn take(datagram: &[u8], kind: u8) -> Option<(Self, &[u8])> {
        let (&first, rest) = datagram.split_first()?;
        if first != kind {
            return None;
        }
        let (&src, rest) = rest.split_first_chunk::<{ NodeId::WIRE_LEN }>()?;
        let (&dst, rest) = rest.split_first_chunk::<{ NodeId::WIRE_LEN }>()?;
        let (&test, rest) = rest.split_first_chunk::<8>()?;
        let (&seq, rest) = rest.split_first_chunk::<4>()?;
        let head = Self {
            src: NodeId::from_be_bytes(src)?,
            dst: NodeId::from_be_bytes(dst)?,
            test: u64::from_be_bytes(test),
            seq: u32::from_be_bytes(seq),
        };
        Some((head, rest))
    }
}

/// 主动测试里的探测：`src` 经 `path` 问 `dst`（见模块文档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestPing {
    pub src: NodeId,
    pub dst: NodeId,
    pub test: TestId,
    /// 发的一方在这个测试里给探测编的号，每个都不一样。
    pub seq: u32,
    /// 经过的 relay；`None` 是直连。
    pub path: Option<RelayPath>,
    /// `src` 对 [`TestPing::signed_message`] 的签名。
    pub signature: [u8; SIGNATURE_LEN],
}

impl TestPing {
    /// 帧的长度，含填充：经 4 个 relay 时的长度。比 TPONG 长。
    pub const LEN: usize = TEST_HEAD_LEN + 1 + MAX_RELAY_HOPS * NodeId::WIRE_LEN + SIGNATURE_LEN;
    pub const PURPOSE: &str = "test-ping";

    /// `src` 签名的消息：除了类型、签名和填充以外的全部字段。`signature` 字段不参与，签名之前可以先填零。
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(Self::LEN);
        self.head().put(None, &mut message);
        put_path(&mut message, self.path);
        message
    }

    fn head(&self) -> TestHead {
        TestHead { src: self.src, dst: self.dst, test: self.test, seq: self.seq }
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut encoded = Vec::with_capacity(Self::LEN);
        self.head().put(Some(KIND_TEST_PING), &mut encoded);
        put_path(&mut encoded, self.path);
        encoded.extend_from_slice(&self.signature);
        let mut bytes = [0; Self::LEN];
        bytes[..encoded.len()].copy_from_slice(&encoded);
        bytes
    }

    /// 非完整 TPING 时返回 `None`。长度小于 [`TestPing::LEN`] 的一律拒绝，避免应答大于请求。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < Self::LEN {
            return None;
        }
        let (TestHead { src, dst, test, seq }, rest) = TestHead::take(datagram, KIND_TEST_PING)?;
        let (&count, rest) = rest.split_first()?;
        let count = usize::from(count);
        if count > MAX_RELAY_HOPS {
            return None;
        }
        let (list, rest) = rest.split_at_checked(count * NodeId::WIRE_LEN)?;
        let relays: Option<Vec<NodeId>> = list.as_chunks::<{ NodeId::WIRE_LEN }>().0.iter().map(|id| NodeId::from_be_bytes(*id)).collect();
        let path = match relays?.as_slice() {
            [] => None,
            relays => Some(RelayPath::new(relays).ok()?),
        };
        Some(Self { src, dst, test, seq, path, signature: *rest.first_chunk::<SIGNATURE_LEN>()? })
    }
}

/// 对 TPING 的回答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestPong {
    /// 回答的一方，也就是 TPING 的目的节点。
    pub src: NodeId,
    pub dst: NodeId,
    pub test: TestId,
    /// 抄回 TPING 的序号。
    pub seq: u32,
    /// 从收到 TPING 到发出这个回答用了多少微秒，到头了停在最大值。
    pub held_us: u32,
    /// 回答的一方在这个测试的这条路径上一共收到了几个不同的 TPING，含这一个。
    pub received: u32,
    /// 是从 TPING 来的那条路径倒着发回来的；`false` 时走的是回答的一方自己现在的路。
    pub same_path: bool,
    pub signature: [u8; SIGNATURE_LEN],
}

impl TestPong {
    pub const LEN: usize = TEST_HEAD_LEN + 4 + 4 + 1 + SIGNATURE_LEN;
    pub const PURPOSE: &str = "test-pong";

    /// `src` 签名的消息：除了类型和签名以外的全部字段。`signature` 字段不参与，签名之前可以先填零。
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(Self::LEN);
        self.head().put(None, &mut message);
        self.put_tail(&mut message);
        message
    }

    fn head(&self) -> TestHead {
        TestHead { src: self.src, dst: self.dst, test: self.test, seq: self.seq }
    }

    fn put_tail(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.held_us.to_be_bytes());
        buf.extend_from_slice(&self.received.to_be_bytes());
        buf.push(if self.same_path { FLAG_SAME_PATH } else { 0 });
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::LEN);
        self.head().put(Some(KIND_TEST_PONG), &mut bytes);
        self.put_tail(&mut bytes);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// 不是一个完整的 TPONG 时返回 `None`。只看格式，签名由收的一方去验。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        if datagram.len() != Self::LEN {
            return None;
        }
        let (TestHead { src, dst, test, seq }, rest) = TestHead::take(datagram, KIND_TEST_PONG)?;
        let (&held, rest) = rest.split_first_chunk::<4>()?;
        let (&received, rest) = rest.split_first_chunk::<4>()?;
        let (&flags, rest) = rest.split_first()?;
        Some(Self {
            src,
            dst,
            test,
            seq,
            held_us: u32::from_be_bytes(held),
            received: u32::from_be_bytes(received),
            same_path: flags & FLAG_SAME_PATH != 0,
            signature: *rest.first_chunk::<SIGNATURE_LEN>()?,
        })
    }
}

fn put_path(buf: &mut Vec<u8>, path: Option<RelayPath>) {
    let relays = path.as_ref().map_or(&[][..], RelayPath::as_slice);
    buf.push(u8::try_from(relays.len()).expect("一条路径最多 4 个 relay"));
    for relay in relays {
        buf.extend_from_slice(&relay.to_be_bytes());
    }
}

/// 任意一种探测帧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    Ping(Ping),
    Pong(Pong),
    TestPing(TestPing),
    TestPong(TestPong),
}

impl Frame {
    /// 首字节不是探测帧的类型，或者帧不完整时返回 `None`。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        match *datagram.first()? {
            KIND_PING => Ping::parse(datagram).map(Self::Ping),
            KIND_PONG => Pong::parse(datagram).map(Self::Pong),
            KIND_TEST_PING => TestPing::parse(datagram).map(Self::TestPing),
            KIND_TEST_PONG => TestPong::parse(datagram).map(Self::TestPong),
            _ => None,
        }
    }

    /// 帧里写的来源和目的节点。
    #[must_use]
    pub const fn ends(&self) -> Ends {
        match self {
            Self::Ping(Ping { src, dst, .. })
            | Self::Pong(Pong { src, dst, .. })
            | Self::TestPing(TestPing { src, dst, .. })
            | Self::TestPong(TestPong { src, dst, .. }) => Ends { src: *src, dst: *dst },
        }
    }
}

/// 一个探测帧是谁发给谁的（[`Frame::ends`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ends {
    pub src: NodeId,
    pub dst: NodeId,
}

const _: () = {
    assert!(Pong::MAX_LEN <= Ping::LEN);
    assert!(HEAD_LEN + SIGNATURE_LEN <= Ping::LEN);
    assert!(TestPong::LEN <= TestPing::LEN);
    assert!(KIND_TEST_PONG < 0x40);
};

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: Nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    const SIGNATURE: [u8; SIGNATURE_LEN] = [0x5a; SIGNATURE_LEN];

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn v4() -> SocketAddr {
        "203.0.113.7:20330".parse().unwrap()
    }

    fn v6() -> SocketAddr {
        "[2001:db8::1]:443".parse().unwrap()
    }

    fn ping() -> Ping {
        Ping { src: node(0x0a0b_0c0d), dst: node(2), nonce: NONCE, signature: SIGNATURE }
    }

    #[test]
    fn ping_has_the_documented_layout_and_round_trips() {
        let bytes = ping().to_bytes();
        assert_eq!(bytes.len(), 100);
        assert_eq!(&bytes[..17], [0x08, 0x0a, 0x0b, 0x0c, 0x0d, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[17..81], SIGNATURE);
        assert!(bytes[81..].iter().all(|&byte| byte == 0));
        assert_eq!(Ping::parse(&bytes), Some(ping()));
        assert_eq!(Frame::parse(&bytes), Some(Frame::Ping(ping())));
    }

    #[test]
    fn pong_has_the_documented_layout_and_round_trips_for_both_address_families() {
        let pong = Pong { src: node(2), dst: node(1), nonce: NONCE, observed: v4(), signature: SIGNATURE };
        let bytes = pong.to_bytes();
        assert_eq!(&bytes[..17], [0x09, 0, 0, 0, 2, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[17..24], [4, 203, 0, 113, 7, 0x4f, 0x6a]);
        assert_eq!(&bytes[24..], SIGNATURE);
        assert_eq!(Pong::parse(&bytes), Some(pong));

        let pong = Pong { observed: v6(), ..pong };
        let bytes = pong.to_bytes();
        assert_eq!(bytes.len(), Pong::MAX_LEN);
        assert_eq!(Pong::parse(&bytes), Some(pong));
        assert_eq!(Frame::parse(&bytes), Some(Frame::Pong(pong)));
    }

    #[test]
    fn pong_is_never_larger_than_ping() {
        let ping_len = ping().to_bytes().len();
        for observed in [v4(), v6()] {
            let pong = Pong { src: node(2), dst: node(1), nonce: NONCE, observed, signature: SIGNATURE };
            assert!(pong.to_bytes().len() <= ping_len);
        }
    }

    #[test]
    fn a_ping_shorter_than_its_padded_length_is_not_recognised() {
        let bytes = ping().to_bytes();
        for len in 0..Ping::LEN {
            assert_eq!(Ping::parse(&bytes[..len]), None, "{len}");
        }
    }

    #[test]
    fn malformed_frames_are_not_recognised() {
        let pong = Pong { src: node(2), dst: node(1), nonce: NONCE, observed: v4(), signature: SIGNATURE }.to_bytes();
        assert_eq!(Pong::parse(&pong[..pong.len() - 1]), None);
        assert_eq!(Pong::parse(&[&pong[..], &[0]].concat()), None);
        let mut bad_family = pong.clone();
        bad_family[17] = 5;
        assert_eq!(Pong::parse(&bad_family), None);
        let mut zero_src = pong;
        zero_src[1..5].fill(0);
        assert_eq!(Pong::parse(&zero_src), None);

        let mut zero_dst = ping().to_bytes();
        zero_dst[5..9].fill(0);
        assert_eq!(Ping::parse(&zero_dst), None);
        assert_eq!(Ping::parse(&[0x09; 100]), None);
        assert_eq!(Frame::parse(&[]), None);
        assert_eq!(Frame::parse(&[0x07; 100]), None);
    }

    fn test_ping(path: Option<RelayPath>) -> TestPing {
        TestPing { src: node(1), dst: node(2), test: 0x0102_0304_0506_0708, seq: 9, path, signature: SIGNATURE }
    }

    #[test]
    fn a_test_ping_has_the_documented_layout_for_direct_and_relayed_paths_and_round_trips() {
        let direct = test_ping(None).to_bytes();
        assert_eq!(direct.len(), 102);
        assert_eq!(&direct[..26], [0x0f, 0, 0, 0, 1, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 9, 0, 0x5a, 0x5a, 0x5a, 0x5a]);
        assert!(direct[22 + SIGNATURE_LEN..].iter().all(|&byte| byte == 0), "签名之后是填充");
        assert_eq!(TestPing::parse(&direct), Some(test_ping(None)));

        let path = RelayPath::new(&[node(8), node(9)]).unwrap();
        let relayed = test_ping(Some(path)).to_bytes();
        assert_eq!(&relayed[21..30], [2, 0, 0, 0, 8, 0, 0, 0, 9]);
        assert_eq!(Frame::parse(&relayed), Some(Frame::TestPing(test_ping(Some(path)))));
        for len in 0..TestPing::LEN {
            assert_eq!(TestPing::parse(&relayed[..len]), None, "短于 {} 字节的不认：{len}", TestPing::LEN);
        }
        let mut repeated = relayed;
        repeated[26..30].copy_from_slice(&8u32.to_be_bytes());
        assert_eq!(TestPing::parse(&repeated), None, "同一个 relay 出现两次");
        let mut too_long = relayed;
        too_long[21] = 5;
        assert_eq!(TestPing::parse(&too_long), None);
    }

    #[test]
    fn a_test_pong_round_trips_and_is_never_larger_than_a_test_ping() {
        let pong =
            TestPong { src: node(2), dst: node(1), test: 7, seq: 9, held_us: 1500, received: 42, same_path: true, signature: SIGNATURE };
        let bytes = pong.to_bytes();
        assert_eq!(bytes.len(), TestPong::LEN);
        assert_eq!(&bytes[21..30], [0, 0, 0x05, 0xdc, 0, 0, 0, 42, 1]);
        assert_eq!(Frame::parse(&bytes), Some(Frame::TestPong(pong)));
        assert_eq!(Frame::parse(&bytes).map(|frame| frame.ends()), Some(Ends { src: node(2), dst: node(1) }));
        let other_path = TestPong { same_path: false, ..pong };
        assert_eq!(TestPong::parse(&other_path.to_bytes()), Some(other_path));
        assert_eq!(TestPong::parse(&bytes[..bytes.len() - 1]), None);
        assert_ne!(pong.signed_message(), TestPong { held_us: 1, ..pong }.signed_message(), "停留时间在签名里，路上改不了");
        assert_ne!(pong.signed_message(), other_path.signed_message());
    }

    #[test]
    fn a_test_ping_signs_the_test_the_sequence_number_and_the_path() {
        let path = RelayPath::new(&[node(8)]).ok();
        let ping = TestPing { src: node(1), dst: node(2), test: 7, seq: 9, path, signature: [0; SIGNATURE_LEN] };
        let message = ping.signed_message();
        assert_eq!(message, [0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 9, 1, 0, 0, 0, 8]);
        assert_ne!(message, TestPing { path: None, ..ping }.signed_message(), "换一条路径签名就不同");
        assert_ne!(message, TestPing { test: 8, ..ping }.signed_message());
        assert_eq!(message, TestPing { signature: SIGNATURE, ..ping }.signed_message(), "签名不在签名的消息里");
    }

    #[test]
    fn signatures_cover_direction_nonce_and_observed_address() {
        let message = Ping::signed_message(node(1), node(2), &NONCE);
        assert_eq!(message, [0, 0, 0, 1, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_ne!(message, Ping::signed_message(node(2), node(1), &NONCE), "方向反过来签名就不同");

        let message = Pong::signed_message(node(2), node(1), &NONCE, v4());
        assert_eq!(&message[..16], [0, 0, 0, 2, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&message[16..], [4, 203, 0, 113, 7, 0x4f, 0x6a]);
        assert_ne!(message, Pong::signed_message(node(2), node(1), &NONCE, v6()));
        assert_ne!(message, Pong::signed_message(node(2), node(1), &[9; 8], v4()));
    }
}
