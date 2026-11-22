//! 建流请求与应答，以及数据报上下文里的数据报。
//!
//! 每条用户连接是端到端连接上的一条双向流。发起方在流上先写一个 OPEN 头，后面直接跟调用者的数据；
//! 接受方先写一个 REPLY 头，后面直接跟目标发回来的数据。多字节整数都是大端。
//!
//! UDP 应用的数据不走流：发起方用另一种 OPEN 在一条流上建立一个数据报上下文，之后的数据报带着上下文号，
//! 走连接上的数据报通道。那条流一直开着，它就是上下文的寿命：任何一方正常结束或者重置它，上下文就结束。
//!
//! ```text
//! OPEN（流）
//! +------+------+======+========+============+
//! | 0x01 | 标志 | 目标 | 凭据名 | 客户端地址 |
//! +------+------+======+========+============+
//!
//! OPEN（数据报上下文）
//! +------+------+----------+========+============+
//! | 0x02 | 标志 | 上下文号 | 凭据名 | 客户端地址 |
//! +------+------+----------+========+============+
//!
//! OPEN（测量流，主动测试量吞吐用，见 [`OpenMeasure`]）
//! +------+------+----------+----------+===========+----------+----------+
//! | 0x03 | 方式 | 测试编号 | relay 数 | relay 编号 | 字节上限 | 时长上限 |
//! +------+------+----------+----------+===========+----------+----------+
//!            1        8          1         4n          8         4（毫秒）
//!
//! OPEN（往返测量，`i3t ping` 用，见 [`OpenPing`]）
//! +------+------+
//! | 0x04 | 0x00 |
//! +------+------+
//! 接受方读到它就回一个成功的 REPLY（状态 0x00，没有说明），然后结束这条流。访问规则和每个对端的流数上限照常在读 OPEN 之前查。
//! 比它旧的接受方不认这一种，用 [`Reason::ProtocolError`] 重置这条流。
//!
//! 标志        bit 0～1  服务等级：0 auto，1 interactive，2 reliable，3 bulk
//!             bit 2     后面有凭据名
//!             bit 3     后面有客户端地址
//!             bit 4～7  必须是 0
//!
//! 上下文号    4 字节，发起方挑的，在它到这个对端还开着的上下文里不重复
//!
//! 目标        类型 1 字节，后面的内容随类型：
//!             0x01  互联网，IPv4        地址 4 字节 | 端口 2 字节
//!             0x02  互联网，IPv6        地址 16 字节 | 端口 2 字节
//!             0x03  互联网，域名        长度 1 字节（1～253）| 域名 | 端口 2 字节
//!             0x04  对端节点自己的端口  端口 2 字节
//!             0x05  对端的局域网，IPv4  地址 4 字节 | 端口 2 字节
//!             0x06  对端的局域网，IPv6  地址 16 字节 | 端口 2 字节
//!             0x07  端口转发            转发编号 4 字节
//!
//! 凭据名      长度 1 字节（0～64）| UTF-8
//! 客户端地址  地址族 1 字节（4 或 6）| 地址 4 或 16 字节 | 端口 2 字节
//!
//! REPLY
//! +------+----------+======+
//! | 状态 | 说明长度 | 说明 |
//! +------+----------+======+
//!
//! 状态        见 [`Status`]
//! 说明        给人看的 UTF-8 文字，长度 0～255 字节
//! ```
//!
//! 两个头都不带总长度，也都有上限（[`Open::MAX_LEN`]、[`Reply::MAX_LEN`]）。读的一方从流的开头读起，
//! 每次按 [`Decoded::Incomplete`] 给的字节数去读：这个数不会超过头里还没读到的部分，所以头读完时，
//! 流里的下一个字节就是数据，不会读过头；对端乱写也不能让读的一方多分配内存。
//!
//! 流的异常结束用连接层的重置来传递，带一个原因码，见 [`Reason`]。
//!
//! # 数据报
//!
//! 数据报上下文的 OPEN 里没有目标。一个上下文在接受方那边是一个 UDP 端口，发往不同目标的数据报都从它出去
//! （所以目标看到的来源地址不随目标变），目标写在每个数据报里；接受方发回来的数据报在同一个位置写的是来源。
//! 发起方读到成功的 REPLY 之后才开始发数据报：那时接受方已经认得这个上下文号了。
//!
//! 下面是连接的数据报通道上一个数据报的全部内容。只有等级是 interactive 的上下文用数据报通道；别的等级
//! （[`Class::keeps_every_datagram`]）每个数据报单独开一条单向流，流的全部内容就是这样一帧（不分片）。
//!
//! ```text
//! 不分片
//! +------+----------+======+======+
//! | 标志 | 上下文号 | 目标 | 载荷 |
//! +------+----------+======+======+
//!    1        4
//!
//! 分片
//! +------+----------+--------+--------+------+==================+
//! | 标志 | 上下文号 | 报文号 | 片序号 | 片数 | 内容的这一片      |
//! +------+----------+--------+--------+------+==================+
//!    1        4         2        1       1
//!
//! 标志        bit 0     收的一方：0 是上下文的接受方，1 是上下文的发起方
//!             bit 1     这是一个分片
//!             bit 2～7  必须是 0
//! 目标        和 OPEN 里的目标同一种编码。发起方发的是这个数据报要去哪里，接受方发的是它从哪里来
//! 报文号      同一个报文的各片相同。每个上下文的每个方向各自从 0 往上数，到头了回到 0
//! 片序号      从 0 开始
//! 片数        2～255
//! ```
//!
//! 「目标 + 载荷」叫做内容，最长 [`MAX_DATAGRAM_BODY_LEN`] 字节。一帧装得下就不分片；装不下时把内容切成几片，
//! 除了最后一片都把帧填满，收的一方按片序号拼回去再解析。分片只发生在两个端点之间，relay 看到的只是连接的包。
//!
//! 连接层只看首字节的 bit 0：一个节点既可能是某些上下文的发起方，也可能是另一些上下文的接受方，
//! 两种数据报要交给不同的人处理（[`Recipient::peek`]）。
//!
//! # 网络包
//!
//! 虚拟网卡上的一个 IPv4 包也走连接的数据报通道（不保证送达，不重传），首字节的 bit 2 标着它，
//! 连接层按首字节把它交给第三个人（[`Channel::peek`]）。比它旧的节点把 bit 2 当作保留位，这样的数据报一律丢掉。
//!
//! ```text
//! 完整的包
//! +------+=======+
//! | 0x04 | IP 包 |
//! +------+=======+
//!    1
//!
//! 一片（包装不进一个数据报时）
//! +------+--------+--------+------+==============+
//! | 0x06 | 包号   | 片序号 | 片数 | 这个包的一片 |
//! +------+--------+--------+------+==============+
//!    1       2        1       1
//!
//! 合着好几个小包（只发给握手时说过自己认识这种帧的对端）
//! +------+------+=======+------+=======+ ...
//! | 0x0c | 长度 | IP 包 | 长度 | IP 包 |
//! +------+------+=======+------+=======+ ...
//!    1      2              2
//!
//! 标志        bit 1     这是一片
//!             bit 2     网络包，必须是 1
//!             bit 3     合着好几个包；不能和 bit 1 同时有
//!             bit 0、4～7  必须是 0
//! IP 包       一个完整的 IPv4 包，原样，最长 [`MAX_PACKET_LEN`] 字节
//! 长度        后面那个 IP 包的字节数，大端，不是 0。包一个挨一个，正好排到帧的末尾，至少有一个
//! 包号        同一个包的各片相同。每个方向各自往上数，到头了回到 0
//! 片序号      从 0 开始
//! 片数        2～[`MAX_PACKET_PIECES`]
//! ```
//!
//! 一个包装得进一个数据报就不切；装不下时切成两片，第一片把帧填满，收的一方拼回去再写进自己的网卡。
//! 合在一起发的是同一时刻要发给同一个对端的小包（TCP 的确认之类）：少发几个包，线路按包数限速的方向上省得多。
//! 包里写的来源和目的地址由收的一方核对，这一层只管怎么送。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

mod dgram;
mod measure;
mod packet;

pub use dgram::{DatagramHeader, Fragment, FrameError, Frames, MAX_DATAGRAM_BODY_LEN, Recipient, SplitError};
pub use measure::{MeasureEnd, MeasureMode, MeasureSteady, MeasureSummary, OpenMeasure};
pub use packet::{Bundled, Channel, MAX_PACKET_LEN, MAX_PACKET_PIECES, PacketHeader, PacketPieces, PieceError};

/// 域名最长多少字节。DNS 的名字写成文本最长就是这么多。
pub const MAX_DOMAIN_LEN: usize = 253;
/// 凭据名最长多少字节，编码时超出的部分被截掉。
pub const MAX_CREDENTIAL_LEN: usize = 64;
/// REPLY 里的说明最长多少字节，编码时超出的部分被截掉。
pub const MAX_DETAIL_LEN: usize = u8::MAX as usize;

const KIND_OPEN_STREAM: u8 = 0x01;
const KIND_OPEN_DATAGRAMS: u8 = 0x02;
const KIND_OPEN_MEASURE: u8 = 0x03;
const KIND_OPEN_PING: u8 = 0x04;

const FLAG_CLASS: u8 = 0b0000_0011;
const FLAG_CREDENTIAL: u8 = 0b0000_0100;
const FLAG_CLIENT: u8 = 0b0000_1000;
const FLAG_RESERVED: u8 = 0b1111_0000;

const TARGET_INTERNET_V4: u8 = 0x01;
const TARGET_INTERNET_V6: u8 = 0x02;
const TARGET_INTERNET_NAME: u8 = 0x03;
const TARGET_NODE: u8 = 0x04;
const TARGET_LAN_V4: u8 = 0x05;
const TARGET_LAN_V6: u8 = 0x06;
const TARGET_FORWARD: u8 = 0x07;

const FAMILY_V4: u8 = 4;
const FAMILY_V6: u8 = 6;

const V4_ENDPOINT_LEN: usize = 4 + 2;
const V6_ENDPOINT_LEN: usize = 16 + 2;

/// 定义一个在线上用整数表示的枚举。变体和数值只在这里写一次，两个方向的转换都从它生成。
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident: $repr:ty {
            $($(#[$variant_meta:meta])* $variant:ident = $value:literal,)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$variant_meta])* $variant,)*
        }

        impl $name {
            /// 线上的数值。
            #[must_use]
            pub const fn to_wire(self) -> $repr {
                match self {
                    $(Self::$variant => $value,)*
                }
            }

            /// 不认识的数值返回 `None`。
            #[must_use]
            pub const fn from_wire(raw: $repr) -> Option<Self> {
                match raw {
                    $($value => Some(Self::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

wire_enum! {
    /// 服务等级：同一条连接上流与流之间谁先发，以及 UDP 应用的数据怎么送。
    ///
    /// 流在任何等级下都是可靠的，等级只决定调度上的先后。真正可以选择"丢"的只有数据报，而且只有 `Interactive`
    /// 会丢（[`Class::keeps_every_datagram`]）：默认不丢包，要低延迟的应用自己选。
    /// 配置里（netmap、管理 API）写成小写的名字：`"auto"`、`"interactive"`、`"reliable"`、`"bulk"`。
    #[derive(Default, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Class: u8 {
        /// 开始按 interactive 的先后对待，流量大了之后让位。数据报一个都不丢，和 `Reliable` 一样送。
        #[default]
        Auto = 0,
        /// 尾延迟最重要：调度优先。数据报走不可靠的通道，过期即丢。只有它会丢数据报。
        Interactive = 1,
        /// 一个报文都不丢，延迟次之：普通调度。数据报每个单独开一条单向流，由连接重传，互相不阻塞。
        Reliable = 2,
        /// 吞吐优先，调度上让位。数据报一个都不丢。
        Bulk = 3,
    }
}

impl Class {
    /// 这个等级的数据报是不是一个都不丢：每个单独开一条单向流，由连接重传。
    ///
    /// 只有 `Interactive` 不是：它的数据报走连接的不可靠通道，来不及发时丢掉旧的，换来最低的延迟。
    #[must_use]
    pub const fn keeps_every_datagram(self) -> bool {
        match self {
            Self::Auto | Self::Reliable | Self::Bulk => true,
            Self::Interactive => false,
        }
    }
}

wire_enum! {
    /// REPLY 里的状态。
    ///
    /// 数值按归因分段：`0x1_` 归因于目标，`0x2_` 是被规则或策略拒绝，`0x3_` 是出口自己出了问题。
    /// 只有最后一段计入出口节点的健康度，见 [`Status::attribution`]。
    ///
    /// `0x24`～`0x27` 是后来加的：出口有意不接（排空、配额、建连预算、同时开着的流太多）。比它们旧的发起方读到这几个值时
    /// 认不出来，按 REPLY 不合法处理，流照样是失败的，只是说明不够准确。
    pub enum Status: u8 {
        /// 目标已经连上，后面是它发回来的数据。
        Ok = 0x00,
        /// 域名不存在。
        NameNotFound = 0x10,
        /// 目标拒绝了连接（端口没有人监听）。
        ConnectionRefused = 0x11,
        /// 目标所在的网络或主机不可达。
        Unreachable = 0x12,
        /// 连接目标超时。
        TimedOut = 0x13,
        /// 访问规则不允许发起节点访问这个节点。
        AccessDenied = 0x20,
        /// 这个节点没有启用请求所需要的能力：不是出口，或者没有打开"允许访问本机局域网"。
        NotEnabled = 0x21,
        /// 出站策略不允许这个目标：端口不在允许的范围里，或者地址属于拒绝的网段。
        PolicyDenied = 0x22,
        /// 没有下发给发起节点的这一条端口转发。
        UnknownForward = 0x23,
        /// 节点正在排空（准备更新后重启），不接新的流。调用方应该换一个出口，或者稍后再试。
        Draining = 0x24,
        /// 出口本账期的流量配额已经用完。
        QuotaExhausted = 0x25,
        /// 发起节点在短时间里向同一个目标建了太多连接，超过了出口的建连预算。
        RateLimited = 0x26,
        /// 发起节点在这个节点上同时开着的流到了上限，新的流要等它手上的流结束一些。
        TooManyStreams = 0x27,
        /// 解析域名时解析器出错或者超时。
        ResolverFailure = 0x30,
        /// 出口内部出错，包括它的上游代理不可用。
        InternalError = 0x31,
    }
}

wire_enum! {
    /// 流被重置（或者被叫停）时带的原因码，就是连接层的流原因码的数值。
    pub enum Reason: u32 {
        /// 这一端不要这条流了，没有更具体的原因。
        Cancelled = 0,
        /// 流上的头解析不了，或者迟迟没有发来。
        ProtocolError = 1,
        /// 目标重置了连接。
        TargetReset = 2,
        /// 到目标的连接出了别的错，比如保活探测超时。
        TargetError = 3,
        /// 入口一侧的客户端异常断开。
        ClientReset = 4,
        /// 发起节点不再被允许这样访问这个节点：访问规则变了，或者这条流用到的能力被收回了
        /// （出口、局域网开关、端口转发）。访问规则本来就不允许的节点开过来的流，也是带着它立刻重置的。
        AccessRevoked = 5,
        /// 出口节点正在关闭。
        ShuttingDown = 6,
        /// 流量的限额用完了：出口本账期的配额，或者入口上接入凭据的流量上限。
        LimitReached = 7,
    }
}

/// 一次失败算在谁头上。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Attribution {
    /// 目标的问题：域名不存在、拒绝连接、不可达、超时。
    Target,
    /// 被访问规则或出站策略拒绝，或者出口有意不接（排空、配额用完、超过建连预算）。
    Refused,
    /// 出口节点自己的问题。只有这一类计入它的健康度。
    Exit,
}

impl Status {
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// 失败算在谁头上；成功时返回 `None`。
    #[must_use]
    pub const fn attribution(self) -> Option<Attribution> {
        match self {
            Self::Ok => None,
            Self::NameNotFound | Self::ConnectionRefused | Self::Unreachable | Self::TimedOut => Some(Attribution::Target),
            // 排空、配额和建连预算是出口按自己的设置有意不接，不是它坏了，所以不算进健康度。
            Self::AccessDenied
            | Self::NotEnabled
            | Self::PolicyDenied
            | Self::UnknownForward
            | Self::Draining
            | Self::QuotaExhausted
            | Self::RateLimited
            | Self::TooManyStreams => Some(Attribution::Refused),
            Self::ResolverFailure | Self::InternalError => Some(Attribution::Exit),
        }
    }
}

/// 一个域名。
///
/// 构造时就查过：1～[`MAX_DOMAIN_LEN`] 字节，只有 ASCII 的字母、数字、`-`、`_` 和 `.`。
/// 国际化域名要先转成 punycode。这样它一定编得进 OPEN，写进日志也不会带出控制字符。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName(String);

impl DomainName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(name: &[u8]) -> Result<(), InvalidDomainName> {
        if name.is_empty() || name.len() > MAX_DOMAIN_LEN {
            return Err(InvalidDomainName::Length(name.len()));
        }
        match name.iter().find(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))) {
            Some(&byte) => Err(InvalidDomainName::Byte(byte)),
            None => Ok(()),
        }
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for DomainName {
    type Err = InvalidDomainName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate(s.as_bytes())?;
        Ok(Self(s.to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidDomainName {
    #[error("域名应该是 1 到 {MAX_DOMAIN_LEN} 字节，实际 {0} 字节")]
    Length(usize),
    #[error("域名里有不允许的字节 {0:#04x}")]
    Byte(u8),
}

/// 互联网目标的主机部分。域名在出口节点上解析。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Name(DomainName),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Name(name) => name.fmt(f),
        }
    }
}

/// 能当 IP 地址读的就是地址（IPv6 不带方括号），其余按域名校验。
impl FromStr for Host {
    type Err = InvalidDomainName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<IpAddr>() {
            Ok(ip) => Ok(Self::Ip(ip)),
            Err(_) => s.parse().map(Self::Name),
        }
    }
}

/// 一条流要去哪里。地址都在对端节点的网络位置上解释。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    /// 经对端访问互联网。对端必须启用了出口。
    Internet { host: Host, port: u16 },
    /// 对端节点自己的服务。
    Node { port: u16 },
    /// 对端网卡直连的网段里的一个地址。对端必须启用了出口并打开了局域网开关。
    Lan { addr: SocketAddr },
    /// 下发给对端的一条端口转发，对端按编号去连它指向的地址。
    Forward { id: u32 },
}

impl Target {
    /// 编码之后最长多少字节：域名目标。
    pub const MAX_LEN: usize = 1 + 1 + MAX_DOMAIN_LEN + 2;

    /// 目标是哪一类。用在日志里：流日志默认不记目标地址。
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Internet { .. } => "internet",
            Self::Node { .. } => "node",
            Self::Lan { .. } => "lan",
            Self::Forward { .. } => "forward",
        }
    }

    /// 要对端启用了出口才能去的目标：互联网，和对端所在的局域网。
    #[must_use]
    pub const fn needs_exit(&self) -> bool {
        matches!(self, Self::Internet { .. } | Self::Lan { .. })
    }

    /// 把目标追加到 `buf` 末尾。OPEN 里和每个数据报里用的是同一种编码。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Internet { host: Host::Ip(ip), port } => {
                put_endpoint(buf, TARGET_INTERNET_V4, TARGET_INTERNET_V6, SocketAddr::new(*ip, *port));
            }
            Self::Internet { host: Host::Name(name), port } => {
                buf.push(TARGET_INTERNET_NAME);
                put_short(buf, name.as_str());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::Node { port } => {
                buf.push(TARGET_NODE);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::Lan { addr } => put_endpoint(buf, TARGET_LAN_V4, TARGET_LAN_V6, *addr),
            Self::Forward { id } => {
                buf.push(TARGET_FORWARD);
                buf.extend_from_slice(&id.to_be_bytes());
            }
        }
    }

    /// 解析 `buf` 开头的一个目标。数据报的内容就是一个目标后面跟着载荷，所以 [`Decoded::Complete`] 里的 `len` 之后是载荷。
    ///
    /// # Errors
    ///
    /// 已经读到的部分不是一个合法的目标。
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, DecodeError> {
        Reader::run(buf, Reader::target)
    }
}

/// 这条流在入口那边是怎么来的。只用于统计和日志，不参与访问控制：对端认的是发起节点，不是这里写的东西。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Origin {
    /// 调用者用的接入凭据的名字。超过 [`MAX_CREDENTIAL_LEN`] 字节时编码会截断。接入凭据去掉之后入口不再写它，
    /// 线上的写法留着：旧版本的入口还会发，照样读得出来。
    pub credential: Option<String>,
    /// 入口看到的客户端地址。
    pub client: Option<SocketAddr>,
}

impl Origin {
    /// 标志里说明后面有哪几项的那两位。
    fn flags(&self) -> u8 {
        let credential = if self.credential.is_some() { FLAG_CREDENTIAL } else { 0 };
        let client = if self.client.is_some() { FLAG_CLIENT } else { 0 };
        credential | client
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        if let Some(name) = &self.credential {
            put_short(buf, truncated(name, MAX_CREDENTIAL_LEN));
        }
        if let Some(client) = self.client {
            put_endpoint(buf, FAMILY_V4, FAMILY_V6, client);
        }
    }
}

/// 建流请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub target: Target,
    pub class: Class,
    pub origin: Origin,
}

impl Open {
    /// 编码之后最长多少字节：域名目标，带最长的凭据名和 IPv6 的客户端地址。
    pub const MAX_LEN: usize = 2 + Target::MAX_LEN + (1 + MAX_CREDENTIAL_LEN) + (1 + V6_ENDPOINT_LEN);

    /// 把头追加到 `buf` 末尾。调用者的首批数据直接接在后面。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[KIND_OPEN_STREAM, self.class.to_wire() | self.origin.flags()]);
        self.target.encode(buf);
        self.origin.encode(buf);
    }

    /// 解析从流的开头读到的字节。
    ///
    /// # Errors
    ///
    /// 已经读到的部分不是一个合法的 OPEN 头。这时应该用 [`Reason::ProtocolError`] 重置这条流。
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, DecodeError> {
        Reader::run(buf, |reader| match reader.kind_and_flags()? {
            (KIND_OPEN_STREAM, flags) => Self::after_kind(reader, flags),
            (kind, _) => Err(DecodeError::UnknownKind(kind).into()),
        })
    }

    /// 类型和标志已经读走，读剩下的部分。
    fn after_kind(reader: &mut Reader<'_>, flags: u8) -> Result<Self, Halt> {
        let class = class_of(flags)?;
        let target = reader.target()?;
        Ok(Self { target, class, origin: reader.origin(flags)? })
    }
}

/// 建立数据报上下文的请求。
///
/// 和 [`Open`] 的区别是没有目标：目标写在每个数据报里（见模块文档）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenDatagrams {
    /// 上下文号。之后两个方向的数据报都带着它。
    pub context: u32,
    pub class: Class,
    pub origin: Origin,
}

impl OpenDatagrams {
    /// 编码之后最长多少字节：带最长的凭据名和 IPv6 的客户端地址。
    pub const MAX_LEN: usize = 2 + 4 + (1 + MAX_CREDENTIAL_LEN) + (1 + V6_ENDPOINT_LEN);

    /// 把头追加到 `buf` 末尾。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[KIND_OPEN_DATAGRAMS, self.class.to_wire() | self.origin.flags()]);
        buf.extend_from_slice(&self.context.to_be_bytes());
        self.origin.encode(buf);
    }

    /// 解析从流的开头读到的字节。
    ///
    /// # Errors
    ///
    /// 已经读到的部分不是一个合法的数据报上下文的 OPEN 头。这时应该用 [`Reason::ProtocolError`] 重置这条流。
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, DecodeError> {
        Reader::run(buf, |reader| match reader.kind_and_flags()? {
            (KIND_OPEN_DATAGRAMS, flags) => Self::after_kind(reader, flags),
            (kind, _) => Err(DecodeError::UnknownKind(kind).into()),
        })
    }

    fn after_kind(reader: &mut Reader<'_>, flags: u8) -> Result<Self, Halt> {
        let class = class_of(flags)?;
        let context = u32::from_be_bytes(reader.array()?);
        Ok(Self { context, class, origin: reader.origin(flags)? })
    }
}

/// 对端开过来的一条流上的第一样东西：它要一条流，要建立一个数据报上下文，要一条测量流，还是只量一个往返。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    Stream(Open),
    Datagrams(OpenDatagrams),
    Measure(OpenMeasure),
    Ping(OpenPing),
}

/// 往返测量的 OPEN：接受方马上回一个成功的 REPLY。从写出它到读到 REPLY 就是这对节点的连接上的一个往返（`i3t ping`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenPing;

impl OpenPing {
    /// 编码之后的长度。
    pub const LEN: usize = 2;

    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[KIND_OPEN_PING, 0]);
    }

    fn after_kind(flags: u8) -> Result<Self, Halt> {
        if flags != 0 {
            return Err(DecodeError::ReservedFlags(flags).into());
        }
        Ok(Self)
    }
}

impl Opening {
    /// 编码之后最长多少字节。
    pub const MAX_LEN: usize = Open::MAX_LEN;

    /// 解析从流的开头读到的字节。接受方还不知道对端发的是哪一种 OPEN 时用它。
    ///
    /// # Errors
    ///
    /// 已经读到的部分不是任何一种合法的 OPEN 头。这时应该用 [`Reason::ProtocolError`] 重置这条流。
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, DecodeError> {
        Reader::run(buf, |reader| match reader.kind_and_flags()? {
            (KIND_OPEN_STREAM, flags) => Open::after_kind(reader, flags).map(Self::Stream),
            (KIND_OPEN_DATAGRAMS, flags) => OpenDatagrams::after_kind(reader, flags).map(Self::Datagrams),
            (KIND_OPEN_MEASURE, mode) => OpenMeasure::after_kind(reader, mode).map(Self::Measure),
            (KIND_OPEN_PING, flags) => OpenPing::after_kind(flags).map(Self::Ping),
            (kind, _) => Err(DecodeError::UnknownKind(kind).into()),
        })
    }
}

/// 标志里的服务等级。保留位不是 0 的标志在这里拒绝。
fn class_of(flags: u8) -> Result<Class, DecodeError> {
    if flags & FLAG_RESERVED != 0 {
        return Err(DecodeError::ReservedFlags(flags));
    }
    Ok(Class::from_wire(flags & FLAG_CLASS).expect("两位能表示的四个值都是已定义的等级"))
}

fn internet(addr: SocketAddr) -> Target {
    Target::Internet { host: Host::Ip(addr.ip()), port: addr.port() }
}

/// 对建流请求的应答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: Status,
    /// 给人看的说明，进发起方的日志。超过 [`MAX_DETAIL_LEN`] 字节时编码会截断。
    pub detail: String,
}

impl Reply {
    /// 编码之后最长多少字节。
    pub const MAX_LEN: usize = 2 + MAX_DETAIL_LEN;

    /// 目标已经连上。
    #[must_use]
    pub const fn ok() -> Self {
        Self { status: Status::Ok, detail: String::new() }
    }

    #[must_use]
    pub fn new(status: Status, detail: impl Into<String>) -> Self {
        Self { status, detail: detail.into() }
    }

    /// 把头追加到 `buf` 末尾。目标发回来的数据直接接在后面。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.status.to_wire());
        put_short(buf, truncated(&self.detail, MAX_DETAIL_LEN));
    }

    /// 解析从流的开头读到的字节。
    ///
    /// # Errors
    ///
    /// 已经读到的部分不是一个合法的 REPLY 头。
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, DecodeError> {
        Reader::run(buf, |reader| {
            let [status, len] = reader.array()?;
            let status = Status::from_wire(status).ok_or(DecodeError::UnknownStatus(status))?;
            let detail = str::from_utf8(reader.bytes(usize::from(len))?).map_err(|_| DecodeError::NotUtf8)?;
            Ok(Self { status, detail: detail.to_owned() })
        })
    }
}

/// 解析一个头的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded<T> {
    /// 头完整了。它占 `buf` 开头的 `len` 字节，后面的是数据。
    Complete { value: T, len: usize },
    /// 还不完整：再读 `more` 字节之后重新解析。`more` 不会超过头里还没读到的部分。
    Incomplete { more: usize },
}

/// 一个头解析不了的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("不认识的建流请求类型 {0:#04x}")]
    UnknownKind(u8),
    #[error("标志里的保留位不是 0：{0:#010b}")]
    ReservedFlags(u8),
    #[error("不认识的目标类型 {0:#04x}")]
    UnknownTarget(u8),
    #[error("目标里的域名不合法")]
    InvalidDomain(#[source] InvalidDomainName),
    #[error("凭据名有 {0} 字节，最长 {MAX_CREDENTIAL_LEN} 字节")]
    CredentialTooLong(usize),
    #[error("文字不是合法的 UTF-8")]
    NotUtf8,
    #[error("不认识的地址族 {0}")]
    UnknownAddressFamily(u8),
    #[error("不认识的状态 {0:#04x}")]
    UnknownStatus(u8),
    #[error("不认识的测量方式 {0}")]
    UnknownMeasureMode(u8),
    #[error("测量流里的路径不合法：超过 4 个 relay、编号是 0，或者同一个 relay 出现了两次")]
    BadPath,
}

/// 解析停下来的原因：字节不够，或者内容不对。
enum Halt {
    Short { more: usize },
    Invalid(DecodeError),
}

impl From<DecodeError> for Halt {
    fn from(error: DecodeError) -> Self {
        Self::Invalid(error)
    }
}

/// 顺着缓冲区往后取字段。字节不够时报出还差多少，由 [`Reader::run`] 转成 [`Decoded::Incomplete`]。
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn run<T>(buf: &'a [u8], parse: impl FnOnce(&mut Self) -> Result<T, Halt>) -> Result<Decoded<T>, DecodeError> {
        let mut reader = Self { rest: buf };
        match parse(&mut reader) {
            Ok(value) => Ok(Decoded::Complete { value, len: buf.len() - reader.rest.len() }),
            Err(Halt::Short { more }) => Ok(Decoded::Incomplete { more }),
            Err(Halt::Invalid(error)) => Err(error),
        }
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], Halt> {
        let (head, rest) = self.rest.split_at_checked(len).ok_or(Halt::Short { more: len.saturating_sub(self.rest.len()) })?;
        self.rest = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Halt> {
        let (head, rest) = self.rest.split_first_chunk::<N>().ok_or(Halt::Short { more: N.saturating_sub(self.rest.len()) })?;
        self.rest = rest;
        Ok(*head)
    }

    fn u8(&mut self) -> Result<u8, Halt> {
        self.array::<1>().map(|[byte]| byte)
    }

    /// OPEN 开头的类型和标志。
    fn kind_and_flags(&mut self) -> Result<(u8, u8), Halt> {
        let [kind, flags] = self.array()?;
        Ok((kind, flags))
    }

    fn target(&mut self) -> Result<Target, Halt> {
        Ok(match self.u8()? {
            TARGET_INTERNET_V4 => internet(self.endpoint_v4()?),
            TARGET_INTERNET_V6 => internet(self.endpoint_v6()?),
            TARGET_INTERNET_NAME => {
                let len = usize::from(self.u8()?);
                if len == 0 || len > MAX_DOMAIN_LEN {
                    return Err(DecodeError::InvalidDomain(InvalidDomainName::Length(len)).into());
                }
                // 域名和后面的端口一次要齐，少读一趟。
                let (name, port) = self.bytes(len + 2)?.split_at(len);
                DomainName::validate(name).map_err(DecodeError::InvalidDomain)?;
                let name = str::from_utf8(name).expect("校验过的域名只有 ASCII").to_owned();
                Target::Internet { host: Host::Name(DomainName(name)), port: u16::from_be_bytes([port[0], port[1]]) }
            }
            TARGET_NODE => Target::Node { port: u16::from_be_bytes(self.array()?) },
            TARGET_LAN_V4 => Target::Lan { addr: self.endpoint_v4()? },
            TARGET_LAN_V6 => Target::Lan { addr: self.endpoint_v6()? },
            TARGET_FORWARD => Target::Forward { id: u32::from_be_bytes(self.array()?) },
            other => return Err(DecodeError::UnknownTarget(other).into()),
        })
    }

    /// 标志说有的那几项来源说明。
    fn origin(&mut self, flags: u8) -> Result<Origin, Halt> {
        let credential = if flags & FLAG_CREDENTIAL != 0 {
            let len = usize::from(self.u8()?);
            if len > MAX_CREDENTIAL_LEN {
                return Err(DecodeError::CredentialTooLong(len).into());
            }
            let name = str::from_utf8(self.bytes(len)?).map_err(|_| DecodeError::NotUtf8)?;
            Some(name.to_owned())
        } else {
            None
        };
        let client = if flags & FLAG_CLIENT != 0 {
            Some(match self.u8()? {
                FAMILY_V4 => self.endpoint_v4()?,
                FAMILY_V6 => self.endpoint_v6()?,
                other => return Err(DecodeError::UnknownAddressFamily(other).into()),
            })
        } else {
            None
        };
        Ok(Origin { credential, client })
    }

    fn endpoint_v4(&mut self) -> Result<SocketAddr, Halt> {
        let [a, b, c, d, hi, lo] = self.array::<V4_ENDPOINT_LEN>()?;
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), u16::from_be_bytes([hi, lo])))
    }

    fn endpoint_v6(&mut self) -> Result<SocketAddr, Halt> {
        let bytes = self.array::<V6_ENDPOINT_LEN>()?;
        let (ip, port) = bytes.split_first_chunk::<16>().expect("IPv6 的地址加端口是 18 字节");
        Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), u16::from_be_bytes([port[0], port[1]])))
    }
}

/// 写一个地址加端口，前面的标记字节按地址族取 `v4` 或 `v6`。
fn put_endpoint(buf: &mut Vec<u8>, v4: u8, v6: u8, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(v4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(v6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// 写一段前面带 1 字节长度的文字。调用者保证它不超过 255 字节。
fn put_short(buf: &mut Vec<u8>, text: &str) {
    let len = u8::try_from(text.len()).expect("调用者已经把文字限制在 255 字节以内");
    buf.push(len);
    buf.extend_from_slice(text.as_bytes());
}

/// 把文字截到不超过 `max` 字节，不切开一个字符。
fn truncated(text: &str, max: usize) -> &str {
    &text[..text.floor_char_boundary(max)]
}

// 域名和凭据名的长度各占 1 字节；等级占标志的低两位。
const _: () = {
    assert!(MAX_DOMAIN_LEN <= u8::MAX as usize);
    assert!(MAX_CREDENTIAL_LEN <= u8::MAX as usize);
    assert!(Class::Bulk.to_wire() <= FLAG_CLASS);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Host {
        Host::Name(text.parse().unwrap())
    }

    fn open(target: Target) -> Open {
        Open { target, class: Class::Auto, origin: Origin::default() }
    }

    fn encoded(open: &Open) -> Vec<u8> {
        let mut buf = Vec::new();
        open.encode(&mut buf);
        buf
    }

    /// 像真正的读者那样读：每次只取解析器要的那么多字节。返回解析出来的值和一共取了多少字节。
    fn read_incrementally<T>(stream: &[u8], decode: fn(&[u8]) -> Result<Decoded<T>, DecodeError>) -> Result<(T, usize), DecodeError> {
        let mut taken = 0;
        loop {
            match decode(&stream[..taken])? {
                Decoded::Complete { value, len } => {
                    assert_eq!(len, taken, "头读完时不应该有多读的字节");
                    return Ok((value, taken));
                }
                Decoded::Incomplete { more } => {
                    assert!(more > 0, "字节不够时至少要再读 1 字节");
                    taken += more;
                    assert!(taken <= stream.len(), "解析器要的字节超出了头本身");
                }
            }
        }
    }

    fn samples() -> Vec<Open> {
        let client_v4: SocketAddr = "192.0.2.9:50000".parse().unwrap();
        let client_v6: SocketAddr = "[2001:db8::9]:50001".parse().unwrap();
        vec![
            open(Target::Internet { host: Host::Ip("203.0.113.7".parse().unwrap()), port: 443 }),
            open(Target::Internet { host: Host::Ip("2001:db8::1".parse().unwrap()), port: 80 }),
            open(Target::Internet { host: name("example.com"), port: 443 }),
            open(Target::Node { port: 8080 }),
            open(Target::Lan { addr: "192.168.1.10:80".parse().unwrap() }),
            open(Target::Lan { addr: "[fd00::10]:22".parse().unwrap() }),
            open(Target::Forward { id: 0x0102_0304 }),
            Open {
                target: Target::Internet { host: name("api.example.com"), port: 443 },
                class: Class::Interactive,
                origin: Origin { credential: Some("gateway-01".into()), client: Some(client_v4) },
            },
            Open {
                target: Target::Node { port: 22 },
                class: Class::Reliable,
                origin: Origin { credential: None, client: Some(client_v6) },
            },
            Open {
                target: Target::Forward { id: 1 },
                class: Class::Bulk,
                origin: Origin { credential: Some(String::new()), client: None },
            },
        ]
    }

    #[test]
    fn open_has_the_documented_layout() {
        let request = Open {
            target: Target::Internet { host: name("a.io"), port: 443 },
            class: Class::Interactive,
            origin: Origin { credential: Some("gw".into()), client: Some("192.0.2.9:513".parse().unwrap()) },
        };
        #[rustfmt::skip]
        let expected = [
            0x01, 0b0000_1101,
            0x03, 4, b'a', b'.', b'i', b'o', 0x01, 0xbb,
            2, b'g', b'w',
            4, 192, 0, 2, 9, 0x02, 0x01,
        ];
        assert_eq!(encoded(&request), expected);

        assert_eq!(
            encoded(&open(Target::Internet { host: Host::Ip("203.0.113.7".parse().unwrap()), port: 80 })),
            [1, 0, 0x01, 203, 0, 113, 7, 0, 80]
        );
        assert_eq!(encoded(&open(Target::Node { port: 8080 })), [1, 0, 0x04, 0x1f, 0x90]);
        assert_eq!(encoded(&open(Target::Lan { addr: "192.168.1.10:80".parse().unwrap() })), [1, 0, 0x05, 192, 168, 1, 10, 0, 80]);
        assert_eq!(encoded(&open(Target::Forward { id: 0x0102_0304 })), [1, 0, 0x07, 1, 2, 3, 4]);
    }

    #[test]
    fn open_round_trips_for_every_target_class_and_origin() {
        for request in samples() {
            let bytes = encoded(&request);
            assert!(bytes.len() <= Open::MAX_LEN);
            assert_eq!(Open::decode(&bytes), Ok(Decoded::Complete { value: request.clone(), len: bytes.len() }), "{request:?}");
        }
    }

    #[test]
    fn open_is_read_incrementally_without_touching_the_data_behind_it() {
        for request in samples() {
            let header = encoded(&request);
            let mut stream = header.clone();
            stream.extend_from_slice(b"\x16\x03\x01 first bytes of the caller");
            assert_eq!(read_incrementally(&stream, Open::decode), Ok((request.clone(), header.len())), "{request:?}");
            // 整个缓冲区一次给它时，它也只认头那一段。
            assert_eq!(Open::decode(&stream), Ok(Decoded::Complete { value: request, len: header.len() }));
        }
    }

    #[test]
    fn every_strict_prefix_of_an_open_is_incomplete() {
        for request in samples() {
            let bytes = encoded(&request);
            for len in 0..bytes.len() {
                match Open::decode(&bytes[..len]) {
                    Ok(Decoded::Incomplete { more }) => {
                        assert!(more >= 1 && len + more <= bytes.len(), "{request:?} 前 {len} 字节")
                    }
                    other => panic!("{request:?} 的前 {len} 字节不应该解析成 {other:?}"),
                }
            }
        }
    }

    #[test]
    fn longest_open_is_exactly_max_len() {
        let longest = Open {
            target: Target::Internet { host: name(&"a".repeat(MAX_DOMAIN_LEN)), port: 443 },
            class: Class::Bulk,
            origin: Origin { credential: Some("c".repeat(MAX_CREDENTIAL_LEN)), client: Some("[2001:db8::9]:1".parse().unwrap()) },
        };
        let bytes = encoded(&longest);
        assert_eq!(bytes.len(), Open::MAX_LEN);
        assert_eq!(read_incrementally(&bytes, Open::decode), Ok((longest, Open::MAX_LEN)));
    }

    #[test]
    fn overlong_credential_name_is_truncated_at_a_character_boundary() {
        let mut request = open(Target::Node { port: 1 });
        request.origin.credential = Some("凭".repeat(30));
        let Ok(Decoded::Complete { value, .. }) = Open::decode(&encoded(&request)) else { panic!("应该能解析") };
        // 每个字 3 字节，64 字节里放得下 21 个。
        assert_eq!(value.origin.credential, Some("凭".repeat(21)));
    }

    #[test]
    fn malformed_open_is_rejected() {
        let cases: [(&[u8], DecodeError); 12] = [
            (&[0x02, 0, 0x04], DecodeError::UnknownKind(0x02)),
            (&[0x00, 0, 0x04], DecodeError::UnknownKind(0x00)),
            (&[0x01, 0b0001_0000, 0x04], DecodeError::ReservedFlags(0b0001_0000)),
            (&[0x01, 0b1000_0001, 0x04], DecodeError::ReservedFlags(0b1000_0001)),
            (&[0x01, 0, 0x00], DecodeError::UnknownTarget(0x00)),
            (&[0x01, 0, 0x08], DecodeError::UnknownTarget(0x08)),
            (&[0x01, 0, 0x03, 0], DecodeError::InvalidDomain(InvalidDomainName::Length(0))),
            (&[0x01, 0, 0x03, 254], DecodeError::InvalidDomain(InvalidDomainName::Length(254))),
            (&[0x01, 0, 0x03, 3, b'a', b' ', b'b', 0, 80], DecodeError::InvalidDomain(InvalidDomainName::Byte(b' '))),
            (&[0x01, 0b0100, 0x04, 0, 80, 65], DecodeError::CredentialTooLong(65)),
            (&[0x01, 0b0100, 0x04, 0, 80, 2, 0xff, 0xfe], DecodeError::NotUtf8),
            (&[0x01, 0b1000, 0x04, 0, 80, 5], DecodeError::UnknownAddressFamily(5)),
        ];
        for (bytes, error) in cases {
            assert_eq!(Open::decode(bytes), Err(error), "{bytes:02x?}");
        }
    }

    #[test]
    fn a_hostile_length_never_asks_for_more_than_the_header_can_hold() {
        // 长度字节写到最大，解析器要的也不会超过头的上限。
        for prefix in [&[0x01, 0, 0x03, 253][..], &[0x01, 0b0100, 0x04, 0, 80, 64], &[0x01, 0b1000, 0x04, 0, 80, 6]] {
            let Ok(Decoded::Incomplete { more }) = Open::decode(prefix) else { panic!("{prefix:02x?} 应该还不完整") };
            assert!(prefix.len() + more <= Open::MAX_LEN);
        }
        let Ok(Decoded::Incomplete { more }) = Reply::decode(&[0x00, 255]) else { panic!("应该还不完整") };
        assert_eq!(2 + more, Reply::MAX_LEN);
    }

    #[test]
    fn domain_names_are_validated() {
        for good in ["example.com", "a", "xn--fiq228c.example", "_dmarc.example.com", "nas-01.home.i3t.", &"a".repeat(253)] {
            assert_eq!(good.parse::<DomainName>().unwrap().as_str(), good);
        }
        assert_eq!("".parse::<DomainName>(), Err(InvalidDomainName::Length(0)));
        assert_eq!("a".repeat(254).parse::<DomainName>(), Err(InvalidDomainName::Length(254)));
        assert_eq!("exa mple.com".parse::<DomainName>(), Err(InvalidDomainName::Byte(b' ')));
        assert_eq!("example.com\r\n".parse::<DomainName>(), Err(InvalidDomainName::Byte(b'\r')));
        assert_eq!("host:80".parse::<DomainName>(), Err(InvalidDomainName::Byte(b':')));
        assert!("例子.example".parse::<DomainName>().is_err());
    }

    #[test]
    fn host_text_is_an_address_when_it_parses_as_one() {
        assert_eq!("203.0.113.7".parse(), Ok(Host::Ip("203.0.113.7".parse().unwrap())));
        assert_eq!("2001:db8::1".parse(), Ok(Host::Ip("2001:db8::1".parse().unwrap())));
        assert_eq!("example.com".parse(), Ok(name("example.com")));
        // 不是完整的点分十进制时按域名对待，由解析器去判断。
        assert_eq!("203.0.113".parse(), Ok(name("203.0.113")));
        assert!("[2001:db8::1]".parse::<Host>().is_err());
        assert_eq!(name("example.com").to_string(), "example.com");
    }

    #[test]
    fn reply_has_the_documented_layout_and_round_trips() {
        let mut buf = Vec::new();
        Reply::ok().encode(&mut buf);
        assert_eq!(buf, [0x00, 0]);

        let refused = Reply::new(Status::ConnectionRefused, "no");
        buf.clear();
        refused.encode(&mut buf);
        assert_eq!(buf, [0x11, 2, b'n', b'o']);

        buf.extend_from_slice(b"data from the target");
        assert_eq!(read_incrementally(&buf, Reply::decode), Ok((refused, 4)));
    }

    #[test]
    fn overlong_reply_detail_is_truncated_at_a_character_boundary() {
        let mut buf = Vec::new();
        Reply::new(Status::InternalError, "错".repeat(100)).encode(&mut buf);
        assert!(buf.len() <= Reply::MAX_LEN);
        let Ok(Decoded::Complete { value, len }) = Reply::decode(&buf) else { panic!("应该能解析") };
        assert_eq!(len, buf.len());
        assert_eq!(value.detail, "错".repeat(85));
    }

    #[test]
    fn malformed_reply_is_rejected() {
        assert_eq!(Reply::decode(&[0x01, 0]), Err(DecodeError::UnknownStatus(0x01)));
        assert_eq!(Reply::decode(&[0xff, 0]), Err(DecodeError::UnknownStatus(0xff)));
        assert_eq!(Reply::decode(&[0x00, 1, 0xff]), Err(DecodeError::NotUtf8));
        assert_eq!(Reply::decode(&[]), Ok(Decoded::Incomplete { more: 2 }));
        assert_eq!(Reply::decode(&[0x00, 3, b'a']), Ok(Decoded::Incomplete { more: 2 }));
    }

    #[test]
    fn wire_values_round_trip_and_unknown_ones_are_refused() {
        for class in [Class::Auto, Class::Interactive, Class::Reliable, Class::Bulk] {
            assert_eq!(Class::from_wire(class.to_wire()), Some(class));
        }
        assert_eq!(Class::from_wire(4), None);
        assert_eq!(Class::default(), Class::Auto);

        for raw in 0..=u8::MAX {
            if let Some(status) = Status::from_wire(raw) {
                assert_eq!(status.to_wire(), raw);
            }
        }
        assert_eq!(Status::from_wire(0x11), Some(Status::ConnectionRefused));

        for reason in [
            Reason::Cancelled,
            Reason::ProtocolError,
            Reason::TargetReset,
            Reason::TargetError,
            Reason::ClientReset,
            Reason::AccessRevoked,
            Reason::ShuttingDown,
            Reason::LimitReached,
        ] {
            assert_eq!(Reason::from_wire(reason.to_wire()), Some(reason));
        }
        assert_eq!(Reason::Cancelled.to_wire(), 0);
        assert_eq!(Reason::from_wire(0xdead_beef), None);
    }

    #[test]
    fn only_failures_of_the_exit_itself_are_attributed_to_the_exit() {
        assert_eq!(Status::Ok.attribution(), None);
        assert!(Status::Ok.is_ok());
        for status in [Status::NameNotFound, Status::ConnectionRefused, Status::Unreachable, Status::TimedOut] {
            assert_eq!(status.attribution(), Some(Attribution::Target), "{status:?}");
        }
        for status in [
            Status::AccessDenied,
            Status::NotEnabled,
            Status::PolicyDenied,
            Status::UnknownForward,
            Status::Draining,
            Status::QuotaExhausted,
            Status::RateLimited,
            Status::TooManyStreams,
        ] {
            assert_eq!(status.attribution(), Some(Attribution::Refused), "{status:?}");
        }
        for status in [Status::ResolverFailure, Status::InternalError] {
            assert_eq!(status.attribution(), Some(Attribution::Exit), "{status:?}");
            assert!(!status.is_ok());
        }
    }

    fn datagram_samples() -> Vec<OpenDatagrams> {
        vec![
            OpenDatagrams { context: 0, class: Class::Auto, origin: Origin::default() },
            OpenDatagrams {
                context: 0x0102_0304,
                class: Class::Reliable,
                origin: Origin { credential: Some("gateway-01".into()), client: Some("192.0.2.9:50000".parse().unwrap()) },
            },
            OpenDatagrams {
                context: u32::MAX,
                class: Class::Interactive,
                origin: Origin { credential: None, client: Some("[2001:db8::9]:50001".parse().unwrap()) },
            },
        ]
    }

    fn encoded_datagrams(open: &OpenDatagrams) -> Vec<u8> {
        let mut buf = Vec::new();
        open.encode(&mut buf);
        buf
    }

    #[test]
    fn datagram_open_has_the_documented_layout() {
        let request = OpenDatagrams {
            context: 0x0102_0304,
            class: Class::Reliable,
            origin: Origin { credential: Some("gw".into()), client: Some("192.0.2.9:513".parse().unwrap()) },
        };
        #[rustfmt::skip]
        let expected = [
            0x02, 0b0000_1110,
            1, 2, 3, 4,
            2, b'g', b'w',
            4, 192, 0, 2, 9, 0x02, 0x01,
        ];
        assert_eq!(encoded_datagrams(&request), expected);
        assert_eq!(encoded_datagrams(&datagram_samples()[0]), [0x02, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn datagram_open_round_trips_and_is_read_incrementally() {
        for request in datagram_samples() {
            let header = encoded_datagrams(&request);
            assert!(header.len() <= OpenDatagrams::MAX_LEN);
            let mut stream = header.clone();
            stream.extend_from_slice(b"nothing follows a datagram open, but a reader must not care");
            assert_eq!(read_incrementally(&stream, OpenDatagrams::decode), Ok((request.clone(), header.len())), "{request:?}");
            for len in 0..header.len() {
                assert!(matches!(OpenDatagrams::decode(&header[..len]), Ok(Decoded::Incomplete { .. })), "{request:?} 前 {len} 字节");
            }
        }
        let longest = OpenDatagrams {
            context: 7,
            class: Class::Bulk,
            origin: Origin { credential: Some("c".repeat(MAX_CREDENTIAL_LEN)), client: Some("[2001:db8::9]:1".parse().unwrap()) },
        };
        assert_eq!(encoded_datagrams(&longest).len(), OpenDatagrams::MAX_LEN);
    }

    #[test]
    fn malformed_datagram_open_is_rejected() {
        let cases: [(&[u8], DecodeError); 5] = [
            (&[0x01, 0, 0, 0, 0, 1], DecodeError::UnknownKind(0x01)),
            (&[0x03, 0], DecodeError::UnknownKind(0x03)),
            (&[0x02, 0b0010_0000], DecodeError::ReservedFlags(0b0010_0000)),
            (&[0x02, 0b0100, 0, 0, 0, 1, 65], DecodeError::CredentialTooLong(65)),
            (&[0x02, 0b1000, 0, 0, 0, 1, 9], DecodeError::UnknownAddressFamily(9)),
        ];
        for (bytes, error) in cases {
            assert_eq!(OpenDatagrams::decode(bytes), Err(error), "{bytes:02x?}");
        }
    }

    #[test]
    fn the_acceptor_tells_the_two_kinds_of_open_apart_by_the_first_byte() {
        for request in samples() {
            let bytes = encoded(&request);
            assert_eq!(read_incrementally(&bytes, Opening::decode), Ok((Opening::Stream(request), bytes.len())));
        }
        for request in datagram_samples() {
            let bytes = encoded_datagrams(&request);
            assert!(bytes.len() <= Opening::MAX_LEN);
            assert_eq!(read_incrementally(&bytes, Opening::decode), Ok((Opening::Datagrams(request), bytes.len())));
        }
        assert_eq!(Opening::decode(&[0x00, 0]), Err(DecodeError::UnknownKind(0x00)));
        assert_eq!(Opening::decode(&[0x05, 0]), Err(DecodeError::UnknownKind(0x05)));
        let mut ping = Vec::new();
        OpenPing.encode(&mut ping);
        assert_eq!(ping.len(), OpenPing::LEN);
        assert_eq!(read_incrementally(&ping, Opening::decode), Ok((Opening::Ping(OpenPing), 2)), "0x04 是往返测量");
        assert_eq!(Opening::decode(&[0x04, 1]), Err(DecodeError::ReservedFlags(1)));
        assert_eq!(Opening::decode(&[0x03, 0]), Err(DecodeError::UnknownMeasureMode(0)), "0x03 是测量流");
        assert_eq!(Opening::decode(&[0x01, 0x10]), Err(DecodeError::ReservedFlags(0x10)));
        assert_eq!(Opening::decode(&[0x02]), Ok(Decoded::Incomplete { more: 1 }));
    }

    #[test]
    fn a_datagram_body_is_a_target_followed_by_the_payload() {
        for request in samples() {
            let mut body = Vec::new();
            request.target.encode(&mut body);
            assert!(body.len() <= Target::MAX_LEN);
            // OPEN 里的目标和数据报里的目标是同一种编码。
            assert_eq!(encoded(&open(request.target.clone()))[2..], body[..]);
            let target_len = body.len();
            body.extend_from_slice(b"payload");
            assert_eq!(Target::decode(&body), Ok(Decoded::Complete { value: request.target.clone(), len: target_len }));
            assert_eq!(&body[target_len..], b"payload");
            for len in 0..target_len {
                assert!(matches!(Target::decode(&body[..len]), Ok(Decoded::Incomplete { .. })), "{:?} 前 {len} 字节", request.target);
            }
        }
        let mut longest = Vec::new();
        Target::Internet { host: name(&"a".repeat(MAX_DOMAIN_LEN)), port: 53 }.encode(&mut longest);
        assert_eq!(longest.len(), Target::MAX_LEN);
        assert_eq!(Target::decode(&[0x09, 1, 2]), Err(DecodeError::UnknownTarget(0x09)));
        assert_eq!(Target::decode(&[0x03, 2, b'a', b' ', 0, 53]), Err(DecodeError::InvalidDomain(InvalidDomainName::Byte(b' '))));
    }

    #[test]
    fn statuses_added_later_have_fixed_wire_values() {
        assert_eq!(Status::Draining.to_wire(), 0x24);
        assert_eq!(Status::QuotaExhausted.to_wire(), 0x25);
        assert_eq!(Status::RateLimited.to_wire(), 0x26);
        assert_eq!(Status::TooManyStreams.to_wire(), 0x27);
        assert_eq!(Reason::LimitReached.to_wire(), 7);
    }

    #[test]
    fn classes_are_written_by_name_in_configuration() {
        assert_eq!(serde_json::to_value(Class::Interactive).unwrap(), serde_json::json!("interactive"));
        assert_eq!(serde_json::from_value::<Class>(serde_json::json!("bulk")).unwrap(), Class::Bulk);
        assert!(serde_json::from_value::<Class>(serde_json::json!("fast")).is_err());
    }

    #[test]
    fn target_kind_names_what_the_flow_log_may_show() {
        let kinds: Vec<&str> = samples().iter().map(|request| request.target.kind()).collect();
        assert_eq!(kinds[..7], ["internet", "internet", "internet", "node", "lan", "lan", "forward"]);
        let via_exit: Vec<bool> = samples().iter().map(|request| request.target.needs_exit()).collect();
        assert_eq!(via_exit[..7], [true, true, true, false, true, true, false]);
    }
}
