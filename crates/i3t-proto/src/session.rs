//! 中转会话的帧（节点和 relay 之间）。
//!
//! 节点要经某个 relay 收发包，先和它建一个中转会话。走 UDP 时每一帧是一个数据报；走 TCP 时同样的帧装在
//! [`crate::tcp_frame`] 里，握手完全一样。
//!
//! ```text
//! 握手
//! 节点 → relay  INIT       0x02 | 节点编号 4 | 随机数 8 | 填充到 32 字节
//! relay → 节点  CHALLENGE  0x03 | 随机数 8 | cookie 16                                          25 字节
//! 节点 → relay  AUTH       0x04 | 节点编号 4 | 随机数 8 | cookie 16 | 签名 64 | 填充到 96 字节
//! relay → 节点  OK         0x05 | 随机数 8 | 有效期 2 | 地址 7 或 19 | 签名 64                 最长 94 字节
//!
//! 保活
//! 节点 → relay  PING       0x06 | 节点编号 4 | 随机数 8 | 填充到 32 字节
//! relay → 节点  PONG       0x07 | 随机数 8 | 地址 7 或 19                                      最长 28 字节
//!
//! 拒绝
//! relay → 节点  ERROR      0x0c | 原因 1 | 节点编号 4 | 回显 8                                   14 字节
//! ```
//!
//! 整数都是大端。地址的编码是：地址族 1 字节（4 或 6）、地址 4 或 16 字节、端口 2 字节。
//! 有效期的单位是秒：这么久收不到 PING，relay 就把会话删掉。
//!
//! # relay 对没有认证过的来源做什么
//!
//! 这几条是格式本身保证的，不靠实现自觉：
//!
//! - **应答不比请求大。** INIT、AUTH、PING 都带填充，比它们各自的应答长；ERROR 比任何能引出它的帧都短。
//!   因此伪造来源地址无法利用 relay 放大流量。长度短于规定值的请求一律拒绝。
//! - **来源地址得到证明之前，relay 不记状态，也不验签名。** CHALLENGE 里的 cookie 是 relay 用只有自己知道的密钥
//!   对"来源地址 + 节点编号 + 时间片"算出来的，算完就忘。AUTH 把 cookie 带回来，relay 重算一遍对得上，
//!   才说明对方确实收得到发往这个地址的包，这之后才去验签名、建会话。
//! - CHALLENGE 与 PONG 原样回显请求中的随机数，路径外的攻击者无法伪造。OK 附带 relay 的签名。
//! - ERROR 不比引出它的请求长：比 [`Refused::LEN`] 短的请求，relay 不回 ERROR。
//!
//! # ERROR 的回显
//!
//! ERROR 会触发节点拆除会话或切换路径，而伪造来源地址很容易冒充 relay 发送 ERROR。因此 ERROR 回显 8 字节，
//! 节点只认回显对得上的（[`Echo`]）：
//!
//! | 原因 | 引出它的请求 | 回显 |
//! |---|---|---|
//! | [`RefusalReason::NoSession`] | PING | PING 里的随机数 |
//! | [`RefusalReason::NoSession`] | 中转帧 | 去掉中转头之后的前 8 个字节，不够的补 0 |
//! | [`RefusalReason::PeerUnattached`]、[`RefusalReason::RouteUnavailable`] | 中转帧 | 这个会话握手时节点给的随机数（AUTH 里的那个） |
//!
//! 后两种只发给拥有会话的那个来源，所以 relay 回显的是只有它们两个知道的东西。中转帧引出的 `NoSession` 发给的是没有会话的来源，
//! relay 侧没有可供回显的共享秘密，节点也无法核对连接包开头，因此该 ERROR 仅作提示：节点应立即发送保活 PING，
//! 仅 relay 对该 PING 的应答（PONG 或回显其随机数的 ERROR）才作为有效依据。
//!
//! # 签的是什么
//!
//! 签名由调用方用 `i3t_crypto::NodeKey::sign(用途, 消息)` 来算，这里只规定消息的字节：
//!
//! | 帧 | 谁签 | 用途标签 | 消息 |
//! |---|---|---|---|
//! | AUTH | 节点 | [`Auth::PURPOSE`] | [`Auth::signed_message`]：relay 编号、节点编号、随机数、cookie |
//! | OK | relay | [`Accepted::PURPOSE`] | [`Accepted::signed_message`]：relay 编号、节点编号、随机数、有效期、地址 |
//!
//! 帧类型中 `0x02`～`0x07` 用于握手与保活。ERROR 排在地址查询之后的 `0x0c`：该区间仅有六个值，无法容纳第七种帧。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::node::NodeId;

pub const KIND_INIT: u8 = 0x02;
pub const KIND_CHALLENGE: u8 = 0x03;
pub const KIND_AUTH: u8 = 0x04;
pub const KIND_OK: u8 = 0x05;
pub const KIND_PING: u8 = 0x06;
pub const KIND_PONG: u8 = 0x07;
pub const KIND_ERROR: u8 = 0x0c;

/// 请求方生成的随机数，应答原样抄回。
pub type Nonce = [u8; NONCE_LEN];
/// relay 发给节点、节点在 AUTH 里带回来的地址证明。内容只有 relay 自己看得懂。
pub type Cookie = [u8; COOKIE_LEN];
/// ERROR 回显的、引出它的请求里不在路径上的人猜不到的字节。取什么见模块文档。
pub type Echo = [u8; ECHO_LEN];

pub const NONCE_LEN: usize = 8;
pub const COOKIE_LEN: usize = 16;
pub const ECHO_LEN: usize = 8;
/// Ed25519 签名的长度。这个 crate 不依赖密码学库，所以签名在这里只是 64 个字节。
pub const SIGNATURE_LEN: usize = 64;

const FAMILY_V4: u8 = 4;
const FAMILY_V6: u8 = 6;
/// 地址编码之后最长多少字节（IPv6 时）。
pub(crate) const MAX_ADDR_LEN: usize = 1 + 16 + 2;

/// 把地址追加到 `buf` 末尾。IPv4 映射的 IPv6 地址按 IPv4 编码：双栈 socket 上收到的 IPv4 包就是这种形式。
pub(crate) fn put_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip().to_canonical() {
        IpAddr::V4(ip) => {
            buf.push(FAMILY_V4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(FAMILY_V6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// 从 `bytes` 开头取出一个地址，返回地址和剩下的字节。
pub(crate) fn take_addr(bytes: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let (&family, rest) = bytes.split_first()?;
    let (ip, rest) = match family {
        FAMILY_V4 => {
            let (&octets, rest) = rest.split_first_chunk::<4>()?;
            (IpAddr::V4(Ipv4Addr::from(octets)), rest)
        }
        FAMILY_V6 => {
            let (&octets, rest) = rest.split_first_chunk::<16>()?;
            (IpAddr::V6(Ipv6Addr::from(octets)), rest)
        }
        _ => return None,
    };
    let (&port, rest) = rest.split_first_chunk::<2>()?;
    // 编码把 IPv4 映射的 IPv6 地址写成 IPv4（[`put_addr`]）。对方硬把它按 IPv6 写过来时，这里也给出 IPv4：
    // 同一个地址只有一种写法，拿它和本机的地址比才比得上。
    Some((SocketAddr::new(ip.to_canonical(), u16::from_be_bytes(port)), rest))
}

/// 请求帧开头的公共部分：类型、节点编号、随机数。`kind` 不匹配或长度小于 `min_len` 时返回 `None`。
fn parse_request_head(datagram: &[u8], kind: u8, min_len: usize) -> Option<(NodeId, Nonce, &[u8])> {
    if datagram.len() < min_len {
        return None;
    }
    let (&first, rest) = datagram.split_first()?;
    if first != kind {
        return None;
    }
    let (&node, rest) = rest.split_first_chunk::<{ NodeId::WIRE_LEN }>()?;
    let (&nonce, rest) = rest.split_first_chunk::<NONCE_LEN>()?;
    Some((NodeId::from_be_bytes(node)?, nonce, rest))
}

fn request_head(bytes: &mut [u8], kind: u8, node: NodeId, nonce: &Nonce) {
    bytes[0] = kind;
    bytes[1..1 + NodeId::WIRE_LEN].copy_from_slice(&node.to_be_bytes());
    bytes[1 + NodeId::WIRE_LEN..REQUEST_HEAD_LEN].copy_from_slice(nonce);
}

const REQUEST_HEAD_LEN: usize = 1 + NodeId::WIRE_LEN + NONCE_LEN;

/// INIT：节点请 relay 发一个 cookie。relay 收到它不记任何状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Init {
    pub node: NodeId,
    pub nonce: Nonce,
}

impl Init {
    /// 帧的长度，含填充。比 CHALLENGE 长。
    pub const LEN: usize = 32;

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        request_head(&mut bytes, KIND_INIT, self.node, &self.nonce);
        bytes
    }

    /// 非完整 INIT 时返回 `None`。长度小于 [`Init::LEN`] 的一律拒绝，避免应答大于请求。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (node, nonce, _padding) = parse_request_head(datagram, KIND_INIT, Self::LEN)?;
        Some(Self { node, nonce })
    }
}

/// CHALLENGE：relay 对 INIT 的回答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge {
    /// 原样抄回 INIT 里的随机数。
    pub nonce: Nonce,
    pub cookie: Cookie,
}

impl Challenge {
    pub const LEN: usize = 1 + NONCE_LEN + COOKIE_LEN;

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        bytes[0] = KIND_CHALLENGE;
        bytes[1..=NONCE_LEN].copy_from_slice(&self.nonce);
        bytes[1 + NONCE_LEN..].copy_from_slice(&self.cookie);
        bytes
    }

    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let bytes: &[u8; Self::LEN] = datagram.try_into().ok()?;
        let (&[KIND_CHALLENGE], rest) = bytes.split_first_chunk::<1>()? else { return None };
        let (&nonce, cookie) = rest.split_first_chunk::<NONCE_LEN>()?;
        Some(Self { nonce, cookie: *cookie.first_chunk::<COOKIE_LEN>()? })
    }
}

/// AUTH：节点带着 cookie 和签名来建会话。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth {
    pub node: NodeId,
    /// 和 INIT 里的是同一个随机数。
    pub nonce: Nonce,
    pub cookie: Cookie,
    /// 节点对 [`Auth::signed_message`] 的签名。
    pub signature: [u8; SIGNATURE_LEN],
}

impl Auth {
    /// 帧的长度，含填充。比最长的 OK 长。
    pub const LEN: usize = 96;
    /// 签名的用途标签。
    pub const PURPOSE: &str = "relay-session-auth";
    /// [`Auth::signed_message`] 的长度。
    pub const SIGNED_LEN: usize = 2 * NodeId::WIRE_LEN + NONCE_LEN + COOKIE_LEN;

    /// 节点签的消息。带上 relay 的编号，这个签名就不能拿到别的 relay 上去用；
    /// cookie 里有来源地址和时间片，所以也不能换一个地址或者隔很久再用。
    #[must_use]
    pub fn signed_message(relay: NodeId, node: NodeId, nonce: &Nonce, cookie: &Cookie) -> [u8; Self::SIGNED_LEN] {
        let mut message = [0; Self::SIGNED_LEN];
        let (ids, rest) = message.split_at_mut(2 * NodeId::WIRE_LEN);
        ids[..NodeId::WIRE_LEN].copy_from_slice(&relay.to_be_bytes());
        ids[NodeId::WIRE_LEN..].copy_from_slice(&node.to_be_bytes());
        rest[..NONCE_LEN].copy_from_slice(nonce);
        rest[NONCE_LEN..].copy_from_slice(cookie);
        message
    }

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        request_head(&mut bytes, KIND_AUTH, self.node, &self.nonce);
        let cookie_end = REQUEST_HEAD_LEN + COOKIE_LEN;
        bytes[REQUEST_HEAD_LEN..cookie_end].copy_from_slice(&self.cookie);
        bytes[cookie_end..cookie_end + SIGNATURE_LEN].copy_from_slice(&self.signature);
        bytes
    }

    /// 不是一个完整的 AUTH 时返回 `None`。只看格式，cookie 和签名由 relay 去验。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (node, nonce, rest) = parse_request_head(datagram, KIND_AUTH, Self::LEN)?;
        let (&cookie, rest) = rest.split_first_chunk::<COOKIE_LEN>()?;
        Some(Self { node, nonce, cookie, signature: *rest.first_chunk::<SIGNATURE_LEN>()? })
    }
}

/// OK：会话建好了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// 原样抄回 AUTH 里的随机数。
    pub nonce: Nonce,
    /// 多少秒收不到 PING 之后 relay 删掉会话。
    pub valid_for: u16,
    /// relay 看到的节点地址。走 TCP 时是那条 TCP 的来源地址，不能当作 UDP 的候选端点。
    pub observed: SocketAddr,
    /// relay 对 [`Accepted::signed_message`] 的签名。
    pub signature: [u8; SIGNATURE_LEN],
}

impl Accepted {
    /// 帧最长多少字节（IPv6 地址时）。
    pub const MAX_LEN: usize = 1 + NONCE_LEN + 2 + MAX_ADDR_LEN + SIGNATURE_LEN;
    /// 签名的用途标签。
    pub const PURPOSE: &str = "relay-session-ok";

    /// relay 签的消息：帧里除了签名之外的全部内容，前面加上双方的编号。
    #[must_use]
    pub fn signed_message(relay: NodeId, node: NodeId, nonce: &Nonce, valid_for: u16, observed: SocketAddr) -> Vec<u8> {
        let mut message = Vec::with_capacity(2 * NodeId::WIRE_LEN + NONCE_LEN + 2 + MAX_ADDR_LEN);
        message.extend_from_slice(&relay.to_be_bytes());
        message.extend_from_slice(&node.to_be_bytes());
        message.extend_from_slice(nonce);
        message.extend_from_slice(&valid_for.to_be_bytes());
        put_addr(&mut message, observed);
        message
    }

    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::MAX_LEN);
        bytes.push(KIND_OK);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.valid_for.to_be_bytes());
        put_addr(&mut bytes, self.observed);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// 不是一个完整的 OK 时返回 `None`。只看格式，签名由节点去验。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (&[KIND_OK], rest) = datagram.split_first_chunk::<1>()? else { return None };
        let (&nonce, rest) = rest.split_first_chunk::<NONCE_LEN>()?;
        let (&valid_for, rest) = rest.split_first_chunk::<2>()?;
        let (observed, rest) = take_addr(rest)?;
        let signature = *<&[u8; SIGNATURE_LEN]>::try_from(rest).ok()?;
        Some(Self { nonce, valid_for: u16::from_be_bytes(valid_for), observed, signature })
    }
}

/// PING：会话的保活。relay 只认从会话绑定的地址（或那条 TCP）来的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub node: NodeId,
    pub nonce: Nonce,
}

impl Ping {
    /// 帧的长度，含填充。比最长的 PONG 长。
    pub const LEN: usize = 32;

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        request_head(&mut bytes, KIND_PING, self.node, &self.nonce);
        bytes
    }

    /// 非完整 PING 时返回 `None`。长度小于 [`Ping::LEN`] 的一律拒绝。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (node, nonce, _padding) = parse_request_head(datagram, KIND_PING, Self::LEN)?;
        Some(Self { node, nonce })
    }
}

/// PONG：relay 对 PING 的回答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    /// 原样抄回 PING 里的随机数。
    pub nonce: Nonce,
    /// relay 看到的节点地址。
    pub observed: SocketAddr,
}

impl Pong {
    /// 帧最长多少字节（IPv6 地址时）。
    pub const MAX_LEN: usize = 1 + NONCE_LEN + MAX_ADDR_LEN;

    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::MAX_LEN);
        bytes.push(KIND_PONG);
        bytes.extend_from_slice(&self.nonce);
        put_addr(&mut bytes, self.observed);
        bytes
    }

    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (&[KIND_PONG], rest) = datagram.split_first_chunk::<1>()? else { return None };
        let (&nonce, rest) = rest.split_first_chunk::<NONCE_LEN>()?;
        let (observed, []) = take_addr(rest)? else { return None };
        Some(Self { nonce, observed })
    }
}

/// relay 拒绝的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    /// 发来的帧自称属于某个节点，但这个节点在 relay 上没有会话，或者会话不是绑定在这个来源上的。
    /// 帧里的节点编号就是那个节点。收到的节点应该重新握手。
    NoSession,
    /// 要转发的包的目的节点在这个 relay 上没有会话。帧里的节点编号是目的节点。收到的节点应该换一个 relay。
    PeerUnattached,
    /// 多级中转数据包无法按指定路径继续转发：当前 relay 与下一跳 relay 之间无骨干连接（帧中节点编号为下一跳 relay），
    /// 或者路径比网络允许的级数长（帧里的节点编号是这个 relay 自己）。只有路径上的第一个 relay 会回这个，
    /// 后面的 relay 不知道来源节点在哪里。收到的节点应该换一条路径。
    RouteUnavailable,
}

impl RefusalReason {
    const fn code(self) -> u8 {
        match self {
            Self::NoSession => 1,
            Self::PeerUnattached => 2,
            Self::RouteUnavailable => 3,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::NoSession),
            2 => Some(Self::PeerUnattached),
            3 => Some(Self::RouteUnavailable),
            _ => None,
        }
    }
}

/// ERROR：relay 没有照办。relay 按来源地址限速地发。
///
/// 帧里还有回显的 8 个字节（见模块文档），它们不在这个结构里：同一个拒绝可以回答不同的请求，
/// 编码时用 [`to_bytes_echoing`](Self::to_bytes_echoing) 给出，收到时用 [`echo`](Self::echo) 从帧里取。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    pub reason: RefusalReason,
    /// 和哪个节点有关，含义见 [`RefusalReason`]。
    pub node: NodeId,
}

impl Refused {
    pub const LEN: usize = 1 + 1 + NodeId::WIRE_LEN + ECHO_LEN;

    /// 编码成回显 `echo` 的 ERROR 帧。
    #[must_use]
    pub const fn to_bytes_echoing(self, echo: &Echo) -> [u8; Self::LEN] {
        let [n0, n1, n2, n3] = self.node.to_be_bytes();
        let [e0, e1, e2, e3, e4, e5, e6, e7] = *echo;
        [KIND_ERROR, self.reason.code(), n0, n1, n2, n3, e0, e1, e2, e3, e4, e5, e6, e7]
    }

    /// 编码成回显的字节全是 0 的 ERROR 帧：它不在回答任何请求，节点核对不出来，最多当作提示。
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.to_bytes_echoing(&[0; ECHO_LEN])
    }

    /// 非完整 ERROR 或原因码未知时返回 `None`。回显字节可通过 [`echo`](Self::echo) 获取。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (&[KIND_ERROR, code, n0, n1, n2, n3], _echo) = Self::split(datagram)? else { return None };
        Some(Self { reason: RefusalReason::from_code(code)?, node: NodeId::from_be_bytes([n0, n1, n2, n3])? })
    }

    /// 一个完整的 ERROR 帧回显的字节。不是 ERROR 帧时返回 `None`。
    #[must_use]
    pub fn echo(datagram: &[u8]) -> Option<Echo> {
        Self::parse(datagram)?;
        Self::split(datagram).map(|(_, echo)| *echo)
    }

    fn split(datagram: &[u8]) -> Option<(&[u8; Self::LEN - ECHO_LEN], &Echo)> {
        let bytes: &[u8; Self::LEN] = datagram.try_into().ok()?;
        let (head, echo) = bytes.split_first_chunk::<{ Self::LEN - ECHO_LEN }>()?;
        Some((head, echo.try_into().ok()?))
    }
}

/// 中转帧引出的 ERROR 回显什么：去掉中转头之后的前 8 个字节，不够的补 0。
#[must_use]
pub fn payload_echo(payload: &[u8]) -> Echo {
    let mut echo = [0; ECHO_LEN];
    let len = payload.len().min(ECHO_LEN);
    echo[..len].copy_from_slice(&payload[..len]);
    echo
}

/// 任意一种中转会话帧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    Init(Init),
    Challenge(Challenge),
    Auth(Auth),
    Ok(Accepted),
    Ping(Ping),
    Pong(Pong),
    Error(Refused),
}

impl Frame {
    /// 首字节是不是中转会话帧的类型。
    #[must_use]
    pub const fn is_session_kind(kind: u8) -> bool {
        matches!(kind, KIND_INIT..=KIND_PONG | KIND_ERROR)
    }

    /// 首字节不是中转会话帧的类型，或者帧不完整时返回 `None`。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        match *datagram.first()? {
            KIND_INIT => Init::parse(datagram).map(Self::Init),
            KIND_CHALLENGE => Challenge::parse(datagram).map(Self::Challenge),
            KIND_AUTH => Auth::parse(datagram).map(Self::Auth),
            KIND_OK => Accepted::parse(datagram).map(Self::Ok),
            KIND_PING => Ping::parse(datagram).map(Self::Ping),
            KIND_PONG => Pong::parse(datagram).map(Self::Pong),
            KIND_ERROR => Refused::parse(datagram).map(Self::Error),
            _ => None,
        }
    }

    /// 这一帧是节点发给 relay 的（由 relay 处理），还是 relay 发给节点的（由路径层处理）。
    #[must_use]
    pub const fn is_request(&self) -> bool {
        match self {
            Self::Init(_) | Self::Auth(_) | Self::Ping(_) => true,
            Self::Challenge(_) | Self::Ok(_) | Self::Pong(_) | Self::Error(_) => false,
        }
    }
}

const _: () = {
    // 应答不比请求大。
    assert!(Challenge::LEN <= Init::LEN);
    assert!(Accepted::MAX_LEN <= Auth::LEN);
    assert!(Pong::MAX_LEN <= Ping::LEN);
    // ERROR 由 PING 或中转帧触发。中转帧长度可能短于 ERROR，relay 不会对此类短帧回复 ERROR。
    assert!(Refused::LEN <= Ping::LEN);
    // 填充之前的内容装得进规定的长度。
    assert!(REQUEST_HEAD_LEN <= Init::LEN && REQUEST_HEAD_LEN <= Ping::LEN);
    assert!(REQUEST_HEAD_LEN + COOKIE_LEN + SIGNATURE_LEN <= Auth::LEN);
};

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: Nonce = [1, 2, 3, 4, 5, 6, 7, 8];
    const COOKIE: Cookie = [0xc0; COOKIE_LEN];
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

    #[test]
    fn init_has_the_documented_layout_and_round_trips() {
        let init = Init { node: node(0x0a0b_0c0d), nonce: NONCE };
        let bytes = init.to_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[..13], [0x02, 0x0a, 0x0b, 0x0c, 0x0d, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(bytes[13..].iter().all(|&byte| byte == 0));
        assert_eq!(Init::parse(&bytes), Some(init));
        assert_eq!(Frame::parse(&bytes), Some(Frame::Init(init)));
    }

    #[test]
    fn challenge_has_the_documented_layout_and_round_trips() {
        let challenge = Challenge { nonce: NONCE, cookie: COOKIE };
        let bytes = challenge.to_bytes();
        assert_eq!(bytes.len(), 25);
        assert_eq!(&bytes[..9], [0x03, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[9..], COOKIE);
        assert_eq!(Challenge::parse(&bytes), Some(challenge));
        assert_eq!(Frame::parse(&bytes), Some(Frame::Challenge(challenge)));
    }

    #[test]
    fn auth_has_the_documented_layout_and_round_trips() {
        let auth = Auth { node: node(7), nonce: NONCE, cookie: COOKIE, signature: SIGNATURE };
        let bytes = auth.to_bytes();
        assert_eq!(bytes.len(), 96);
        assert_eq!(&bytes[..13], [0x04, 0, 0, 0, 7, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[13..29], COOKIE);
        assert_eq!(&bytes[29..93], SIGNATURE);
        assert_eq!(&bytes[93..], [0, 0, 0]);
        assert_eq!(Auth::parse(&bytes), Some(auth));
        assert_eq!(Frame::parse(&bytes), Some(Frame::Auth(auth)));
    }

    #[test]
    fn an_ipv4_address_sent_in_ipv6_clothes_is_read_as_ipv4() {
        // 地址族写的是 6，地址是 ::ffff:192.0.2.7。
        let mut bytes = vec![6];
        bytes.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped().octets());
        bytes.extend_from_slice(&4433u16.to_be_bytes());
        let (addr, rest) = take_addr(&bytes).unwrap();
        assert_eq!((addr, rest), ("192.0.2.7:4433".parse().unwrap(), &[][..]));

        let mut again = Vec::new();
        put_addr(&mut again, addr);
        assert_eq!(take_addr(&again), Some((addr, &[][..])), "读出来的地址再写再读，还是它");
    }

    #[test]
    fn ok_has_the_documented_layout_and_round_trips_for_both_address_families() {
        let ok = Accepted { nonce: NONCE, valid_for: 0x0102, observed: v4(), signature: SIGNATURE };
        let bytes = ok.to_bytes();
        assert_eq!(&bytes[..11], [0x05, 1, 2, 3, 4, 5, 6, 7, 8, 0x01, 0x02]);
        assert_eq!(&bytes[11..18], [4, 203, 0, 113, 7, 0x4f, 0x6a]);
        assert_eq!(&bytes[18..], SIGNATURE);
        assert_eq!(Accepted::parse(&bytes), Some(ok));

        let ok = Accepted { observed: v6(), ..ok };
        let bytes = ok.to_bytes();
        assert_eq!(bytes.len(), Accepted::MAX_LEN);
        assert_eq!(bytes[11], 6);
        assert_eq!(Accepted::parse(&bytes), Some(ok));
        assert_eq!(Frame::parse(&bytes), Some(Frame::Ok(ok)));
    }

    #[test]
    fn ping_and_pong_have_the_documented_layout_and_round_trip() {
        let ping = Ping { node: node(9), nonce: NONCE };
        let bytes = ping.to_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[..13], [0x06, 0, 0, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(bytes[13..].iter().all(|&byte| byte == 0));
        assert_eq!(Ping::parse(&bytes), Some(ping));
        assert_eq!(Frame::parse(&bytes), Some(Frame::Ping(ping)));

        for observed in [v4(), v6()] {
            let pong = Pong { nonce: NONCE, observed };
            let bytes = pong.to_bytes();
            assert_eq!(&bytes[..9], [0x07, 1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(Pong::parse(&bytes), Some(pong));
            assert_eq!(Frame::parse(&bytes), Some(Frame::Pong(pong)));
        }
        assert_eq!(Pong { nonce: NONCE, observed: v6() }.to_bytes().len(), Pong::MAX_LEN);
    }

    #[test]
    fn error_has_the_documented_layout_and_round_trips() {
        let refused = Refused { reason: RefusalReason::PeerUnattached, node: node(0x0102_0304) };
        let bytes = refused.to_bytes_echoing(&NONCE);
        assert_eq!(bytes, [0x0c, 2, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(Refused::parse(&bytes), Some(refused));
        assert_eq!(Refused::echo(&bytes), Some(NONCE));
        assert_eq!(Frame::parse(&bytes), Some(Frame::Error(refused)), "回显的字节不影响帧的含义");
        let no_session = Refused { reason: RefusalReason::NoSession, node: node(5) };
        assert_eq!(no_session.to_bytes(), [0x0c, 1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0], "不回答任何请求的 ERROR 回显全 0");
        let unroutable = Refused { reason: RefusalReason::RouteUnavailable, node: node(8) };
        assert_eq!(Refused::parse(&unroutable.to_bytes()), Some(unroutable));

        let mut unknown = bytes;
        unknown[1] = 9;
        assert_eq!(Refused::parse(&unknown), None, "不认识的原因码");
        assert_eq!(Refused::echo(&unknown), None);
        let mut zero = bytes;
        zero[2..6].fill(0);
        assert_eq!(Refused::parse(&zero), None, "节点编号是 0");
        assert_eq!(Refused::parse(&bytes[..Refused::LEN - 1]), None, "没有回显的旧格式不认");
        assert_eq!(Refused::parse(&[&bytes[..], &[0]].concat()), None);
    }

    #[test]
    fn a_relayed_frame_is_echoed_by_its_first_eight_payload_bytes() {
        assert_eq!(payload_echo(&[0xc1, 1, 2, 3, 4, 5, 6, 7, 8, 9]), [0xc1, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(payload_echo(&[0xc1, 1, 2]), [0xc1, 1, 2, 0, 0, 0, 0, 0], "不够的补 0");
        assert_eq!(payload_echo(&[]), [0; ECHO_LEN]);
    }

    #[test]
    fn every_reply_fits_inside_the_request_that_can_trigger_it() {
        let challenge = Challenge { nonce: NONCE, cookie: COOKIE }.to_bytes();
        assert!(challenge.len() <= Init { node: node(1), nonce: NONCE }.to_bytes().len());

        let auth = Auth { node: node(1), nonce: NONCE, cookie: COOKIE, signature: SIGNATURE }.to_bytes();
        let ping = Ping { node: node(1), nonce: NONCE }.to_bytes();
        let error = Refused { reason: RefusalReason::NoSession, node: node(1) }.to_bytes();
        for observed in [v4(), v6()] {
            let ok = Accepted { nonce: NONCE, valid_for: 30, observed, signature: SIGNATURE }.to_bytes();
            assert!(ok.len() <= auth.len());
            assert!(Pong { nonce: NONCE, observed }.to_bytes().len() <= ping.len());
        }
        // ERROR 由 PING 或者一个中转帧引出。比它短的中转帧 relay 不回答，所以这里只看 PING。
        assert!(error.len() <= ping.len());
    }

    #[test]
    fn requests_shorter_than_their_padded_length_are_not_recognised() {
        let init = Init { node: node(1), nonce: NONCE }.to_bytes();
        let auth = Auth { node: node(1), nonce: NONCE, cookie: COOKIE, signature: SIGNATURE }.to_bytes();
        let ping = Ping { node: node(1), nonce: NONCE }.to_bytes();
        for len in 0..Init::LEN {
            assert_eq!(Init::parse(&init[..len]), None);
            assert_eq!(Ping::parse(&ping[..len]), None);
        }
        for len in 0..Auth::LEN {
            assert_eq!(Auth::parse(&auth[..len]), None);
        }
        assert_eq!(Frame::parse(&init[..Init::LEN - 1]), None);
    }

    #[test]
    fn malformed_replies_are_not_recognised() {
        let challenge = Challenge { nonce: NONCE, cookie: COOKIE }.to_bytes();
        assert_eq!(Challenge::parse(&challenge[..24]), None);
        assert_eq!(Challenge::parse(&[&challenge[..], &[0]].concat()), None);

        let ok = Accepted { nonce: NONCE, valid_for: 30, observed: v4(), signature: SIGNATURE }.to_bytes();
        assert_eq!(Accepted::parse(&ok[..ok.len() - 1]), None);
        assert_eq!(Accepted::parse(&[&ok[..], &[0]].concat()), None);
        let mut bad_family = ok;
        bad_family[11] = 5;
        assert_eq!(Accepted::parse(&bad_family), None);

        let pong = Pong { nonce: NONCE, observed: v6() }.to_bytes();
        assert_eq!(Pong::parse(&pong[..pong.len() - 1]), None);
        assert_eq!(Pong::parse(&[&pong[..], &[0]].concat()), None);
    }

    #[test]
    fn frames_with_a_zero_node_id_or_a_foreign_kind_are_not_recognised() {
        let mut init = Init { node: node(1), nonce: NONCE }.to_bytes();
        init[1..5].fill(0);
        assert_eq!(Init::parse(&init), None);
        let ping = Ping { node: node(1), nonce: NONCE }.to_bytes();
        assert_eq!(Init::parse(&ping), None, "PING 不是 INIT，虽然长得一样");
        assert_eq!(Frame::parse(&[]), None);
        assert_eq!(Frame::parse(&[0x08; 32]), None);
    }

    #[test]
    fn mapped_ipv4_is_reported_as_ipv4() {
        let pong = Pong { nonce: NONCE, observed: "[::ffff:203.0.113.7]:5000".parse().unwrap() };
        assert_eq!(Pong::parse(&pong.to_bytes()).unwrap().observed, "203.0.113.7:5000".parse().unwrap());
    }

    #[test]
    fn auth_signature_covers_relay_node_nonce_and_cookie() {
        let message = Auth::signed_message(node(0x0102_0304), node(7), &NONCE, &COOKIE);
        assert_eq!(&message[..4], [1, 2, 3, 4]);
        assert_eq!(&message[4..8], [0, 0, 0, 7]);
        assert_eq!(&message[8..16], NONCE);
        assert_eq!(&message[16..], COOKIE);
        assert_ne!(message, Auth::signed_message(node(9), node(7), &NONCE, &COOKIE), "换一个 relay 签名就不同");
    }

    #[test]
    fn ok_signature_covers_both_ids_and_the_whole_frame_body() {
        let message = Accepted::signed_message(node(3), node(7), &NONCE, 30, v4());
        assert_eq!(&message[..8], [0, 0, 0, 3, 0, 0, 0, 7]);
        assert_eq!(&message[8..16], NONCE);
        assert_eq!(&message[16..18], [0, 30]);
        assert_eq!(&message[18..], [4, 203, 0, 113, 7, 0x4f, 0x6a]);
        for other in [
            Accepted::signed_message(node(3), node(8), &NONCE, 30, v4()),
            Accepted::signed_message(node(3), node(7), &[9; 8], 30, v4()),
            Accepted::signed_message(node(3), node(7), &NONCE, 31, v4()),
            Accepted::signed_message(node(3), node(7), &NONCE, 30, v6()),
        ] {
            assert_ne!(message, other);
        }
    }

    #[test]
    fn requests_and_replies_are_told_apart() {
        let request = Frame::Ping(Ping { node: node(1), nonce: NONCE });
        let reply = Frame::Pong(Pong { nonce: NONCE, observed: v4() });
        assert!(request.is_request() && !reply.is_request());
        assert!(Frame::is_session_kind(0x02) && Frame::is_session_kind(0x07) && Frame::is_session_kind(0x0c));
        assert!(!Frame::is_session_kind(0x01) && !Frame::is_session_kind(0x08) && !Frame::is_session_kind(0x0b));
    }
}
