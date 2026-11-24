//! IPv4 头部解析与 ICMP 不可达报文构造：用于源/目的地址校验、逐包访问控制判定，以及在本机应用访问不可达目标时返回 ICMP 差错应答。
//!
//! 本模块默认不校验 IP 头校验和：出站包由本机内核刚生成，入站包在写入虚拟网卡后由接收端内核校验并丢弃损坏包。

use std::net::Ipv4Addr;

/// IP 头部协议号常量。
pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

/// ICMP 报文类型常量。
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_UNREACHABLE: u8 = 3;
const ICMP_REDIRECT: u8 = 5;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_PARAMETER_PROBLEM: u8 = 12;

/// TCP 标志位常量。
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// TCP 头部最小长度（字节）。
const TCP_HEADER_MIN: usize = 20;

/// IP 头部标志位（保留位、禁止分片 DF、更多分片 MF）及 13 位分片偏移掩码。
const RESERVED_FLAG: u16 = 0x8000;
const DONT_FRAGMENT: u16 = 0x4000;
const MORE_FRAGMENTS: u16 = 0x2000;
const FRAGMENT_OFFSET: u16 = 0x1fff;

/// ICMP 不可达报文中引用的原始数据包最大字节数：确保含外层 IP/ICMP 头在内的总长不超过 576 字节（RFC 1812）。
/// 接收端内核依据引用的 IP 头与传输层端口（TCP 还包含序号）定位对应的本地套接字。
const QUOTED_MAX: usize = 576 - 20 - 8;

/// 已解析的 IPv4 报文视图（零拷贝切片）。
#[derive(Debug, Clone, Copy)]
pub struct Ipv4<'a> {
    bytes: &'a [u8],
    header_len: usize,
}

/// IPv4 数据包格式解析错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    #[error("非 IPv4 数据包（版本号 {0}）")]
    NotIpv4(u8),
    #[error("数据包仅 {0} 字节，不足 IPv4 头部最小长度")]
    Truncated(usize),
    #[error("IPv4 长度字段不一致：头长 {header_len} 字节、总长 {total_len} 字节，实际包长 {len} 字节")]
    Lengths { header_len: usize, total_len: usize, len: usize },
}

impl<'a> Ipv4<'a> {
    /// 解析完整的 IPv4 数据包，要求头部声明的总长度严格等于 `bytes.len()`。
    ///
    /// # Errors
    ///
    /// 数据包不是 IPv4、长度不足最小头部，或头部长度字段与实际字节长度不一致时返回错误。
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Malformed> {
        let &first = bytes.first().ok_or(Malformed::Truncated(0))?;
        if first >> 4 != 4 {
            return Err(Malformed::NotIpv4(first >> 4));
        }
        if bytes.len() < 20 {
            return Err(Malformed::Truncated(bytes.len()));
        }
        let header_len = usize::from(first & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if header_len < 20 || header_len > total_len || total_len != bytes.len() {
            return Err(Malformed::Lengths { header_len, total_len, len: bytes.len() });
        }
        Ok(Self { bytes, header_len })
    }

    /// 读取 IP 版本号（首字节高 4 位）；空切片返回 0。
    #[must_use]
    pub fn version_of(bytes: &[u8]) -> u8 {
        bytes.first().map_or(0, |first| first >> 4)
    }

    #[must_use]
    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.bytes[12], self.bytes[13], self.bytes[14], self.bytes[15])
    }

    #[must_use]
    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.bytes[16], self.bytes[17], self.bytes[18], self.bytes[19])
    }

    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.bytes[9]
    }

    /// 返回 IP 头部长度（字节）：标准头部为 20，含 IP 选项时更长。
    #[must_use]
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    #[must_use]
    pub fn ttl(&self) -> u8 {
        self.bytes[8]
    }

    /// 校验 IPv4 头部校验和。常规解析不执行此检查（见模块文档），仅在用户态分片重组前预检时调用（[`crate::fragments`]）。
    #[must_use]
    pub fn header_checksum_ok(&self) -> bool {
        checksum(&self.bytes[..self.header_len]) == 0
    }

    /// 判断标志位中是否设置了禁止分片（DF）或保留位。
    #[must_use]
    pub fn dont_fragment_or_reserved(&self) -> bool {
        self.flags_and_offset() & (DONT_FRAGMENT | RESERVED_FLAG) != 0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// 返回 IP 标识字段（配合源地址、目的地址与协议号用于分片重组）。
    #[must_use]
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }

    fn flags_and_offset(&self) -> u16 {
        u16::from_be_bytes([self.bytes[6], self.bytes[7]])
    }

    /// 返回 MF（More Fragments）标志：为 `true` 表示该包为非末片的分片包。
    #[must_use]
    pub fn more_fragments(&self) -> bool {
        self.flags_and_offset() & MORE_FRAGMENTS != 0
    }

    /// 返回当前分片负载在原数据包负载中的起始字节偏移（13 位分片偏移乘 8）；未分片包为 0。
    #[must_use]
    pub fn fragment_offset(&self) -> usize {
        usize::from(self.flags_and_offset() & FRAGMENT_OFFSET) * 8
    }

    /// 分片偏移非 0：表示该包为分片包的后续分片，不包含传输层端口信息。
    #[must_use]
    pub fn is_later_fragment(&self) -> bool {
        self.flags_and_offset() & FRAGMENT_OFFSET != 0
    }

    /// 判断该包是否属于 IPv4 分片（首片、中间片或末片）。
    #[must_use]
    pub fn is_fragment(&self) -> bool {
        self.more_fragments() || self.is_later_fragment()
    }

    /// 返回 IP 头部之后的负载切片。
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len..]
    }

    /// 识别该数据包在会话中的角色，供逐包访问控制使用。
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        if self.is_later_fragment() {
            return Conversation::LaterFragment;
        }
        let payload = self.payload();
        match self.protocol() {
            // 拒绝分片 TCP 及头部不完整的 TCP：两端按虚拟网卡 MTU 协商 MSS，正常节点间 TCP 不会分片；
            // 分片首片可能截断 TCP 头，且标志位存在被重叠分片篡改的风险（RFC 1858）。
            TCP if self.more_fragments() || payload.len() < TCP_HEADER_MIN => Conversation::Other,
            TCP => match payload[13] {
                flags if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 => Conversation::TcpOpen,
                _ => Conversation::TcpOngoing,
            },
            UDP => match payload.first_chunk::<4>() {
                Some(&[s0, s1, d0, d1]) => {
                    Conversation::Udp { source: u16::from_be_bytes([s0, s1]), destination: u16::from_be_bytes([d0, d1]) }
                }
                None => Conversation::Other,
            },
            ICMP => match payload.first() {
                Some(&ICMP_ECHO_REQUEST) => Conversation::IcmpRequest,
                Some(&(ICMP_ECHO_REPLY | ICMP_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM)) => Conversation::IcmpAnswer,
                // 其他类型 ICMP（如时间戳请求、路由器通告等）按非回包处理，避免误放行。
                _ => Conversation::Other,
            },
            _ => Conversation::Other,
        }
    }

    /// 判断是否为 ICMP 差错报文（目的不可达、超时、参数问题）。差错报文不得再触发差错回复（RFC 1122 3.2.2）。
    /// 后续 IP 分片的负载为原包中间字节，无法判断 ICMP 类型，因此返回 `false`。
    #[must_use]
    pub fn is_icmp_error(&self) -> bool {
        matches!(self.icmp_type(), Some(ICMP_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM))
    }

    /// 判断是否为 ICMP 重定向报文（通知主机更换下一跳）。后续 IP 分片同上返回 `false`。
    #[must_use]
    pub fn is_icmp_redirect(&self) -> bool {
        self.icmp_type() == Some(ICMP_REDIRECT)
    }

    /// 提取 ICMP 报文类型：仅当协议为 ICMP、非后续分片且负载非空时返回 `Some`。
    fn icmp_type(&self) -> Option<u8> {
        (self.protocol() == ICMP && !self.is_later_fragment()).then(|| self.payload().first().copied()).flatten()
    }

    /// 解析 ICMP 差错报文中引用的原始数据包：需至少包含完整 IPv4 头部，可用于读取原包的源/目的地址、协议及传输层端口
    /// （若引用长度足够；RFC 792 要求至少包含 IP 头后 8 字节）。非差错报文或引用头部不完整时返回 `None`。
    ///
    /// 返回视图仅覆盖被引用截取的部分，其 IP 头中的总长度字段仍为原始数据包的长度，可能大于当前切片长度。
    #[must_use]
    pub fn quoted(&self) -> Option<Ipv4<'a>> {
        if !self.is_icmp_error() {
            return None;
        }
        let inner = self.payload().get(8..)?;
        let &first = inner.first()?;
        let header_len = usize::from(first & 0x0f) * 4;
        (first >> 4 == 4 && header_len >= 20 && inner.len() >= header_len).then_some(Ipv4 { bytes: inner, header_len })
    }
}

/// 数据包在会话中的分类（用于区分新会话发起包与回包）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conversation {
    /// TCP 首次握手包（置 SYN 且未置 ACK）。
    TcpOpen,
    /// 非首个 SYN 的 TCP 包。此类数据包无法建立新连接，内核对不存在的连接仅回复 RST。
    TcpOngoing,
    /// ICMP Echo 请求（ping 请求）。
    IcmpRequest,
    /// ICMP Echo 应答及差错报文（不可达、超时、参数问题），均属对本机发出报文的响应。
    IcmpAnswer,
    Udp {
        source: u16,
        destination: u16,
    },
    /// IP 分片包的后续分片：不含传输层端口，无法单独判定。对端分片会在 [`crate::fragments`] 重组齐后按首片判定。
    LaterFragment,
    /// 其他协议或无法可靠识别的数据包（含分片 TCP 及头部不完整的 TCP）。
    Other,
}

/// ICMP 目的不可达子代码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Unreachable {
    /// 主机不可达（Code 1）：网段内无此节点、对端未启用虚拟网卡或无法建立连接。内核会向应用返回 `EHOSTUNREACH`（"No route to host"），
    /// 使正在建立的 TCP 连接立即失败。
    Host = 1,
    /// 被管理员禁止（Code 13）：访问规则不允许本节点访问目标节点。内核同样向应用返回 `EHOSTUNREACH`。
    Prohibited = 13,
}

/// 针对本机出站包 `original` 构造 ICMP 目的不可达报文，用于写回虚拟网卡通知本机内核。
/// 对不应回复差错报文的包返回 `None`：包括 ICMP 差错报文本身、后续 IP 分片以及组播/广播包（RFC 1122 3.2.2）。
///
/// 报文源地址设为原包目的地址以模拟目标主机响应：若设为本节点自身地址，内核会因“从外部接口收到本机源地址”将其当作伪造包丢弃；
/// 原目的地址位于经该网卡路由的网段内，内核会正常受理。
#[must_use]
pub fn unreachable(original: &Ipv4<'_>, code: Unreachable) -> Option<Vec<u8>> {
    let destination = original.destination();
    if original.is_icmp_error() || original.is_later_fragment() || destination.is_multicast() || destination.is_broadcast() {
        return None;
    }
    let quoted = &original.bytes[..original.bytes.len().min(QUOTED_MAX)];
    let total = 20 + 8 + quoted.len();
    let mut packet = Vec::with_capacity(total);
    let total_len = u16::try_from(total).expect("ICMP 报文长度不超过 576 字节");
    packet.extend_from_slice(&[0x45, 0xc0]);
    packet.extend_from_slice(&total_len.to_be_bytes());
    // IP 标识 0、不分片、TTL 64、协议 ICMP，校验和字段先置零。
    packet.extend_from_slice(&[0, 0, 0, 0, 64, ICMP, 0, 0]);
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(&original.source().octets());
    let header_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
    packet.extend_from_slice(&[ICMP_UNREACHABLE, code as u8, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(quoted);
    let icmp_sum = checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(packet)
}

/// 计算互联网校验和（RFC 1071）。
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes.chunks(2).map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("校验和折叠后不超过 16 位")
}

#[cfg(test)]
pub(crate) mod testing {
    //! 测试里用的包。
    use super::{ICMP, TCP, UDP, checksum};

    /// 一个 IPv4 包：头 20 字节，后面是 `payload`。
    pub(crate) fn packet(protocol: u8, source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = u16::try_from(20 + payload.len()).unwrap();
        let mut bytes = vec![0x45, 0];
        bytes.extend_from_slice(&total.to_be_bytes());
        bytes.extend_from_slice(&[0x12, 0x34, 0x40, 0, 64, protocol, 0, 0]);
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&destination);
        let sum = checksum(&bytes);
        bytes[10..12].copy_from_slice(&sum.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    /// 一个 TCP 包，`flags` 是标志字节。
    pub(crate) fn tcp(source: [u8; 4], destination: [u8; 4], ports: (u16, u16), flags: u8) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&ports.0.to_be_bytes());
        segment.extend_from_slice(&ports.1.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0x10, 0, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        packet(TCP, source, destination, &segment)
    }

    pub(crate) fn udp(source: [u8; 4], destination: [u8; 4], ports: (u16, u16), data: &[u8]) -> Vec<u8> {
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&ports.0.to_be_bytes());
        datagram.extend_from_slice(&ports.1.to_be_bytes());
        datagram.extend_from_slice(&u16::try_from(8 + data.len()).unwrap().to_be_bytes());
        datagram.extend_from_slice(&[0, 0]);
        datagram.extend_from_slice(data);
        packet(UDP, source, destination, &datagram)
    }

    pub(crate) fn icmp(source: [u8; 4], destination: [u8; 4], kind: u8) -> Vec<u8> {
        packet(ICMP, source, destination, &[kind, 0, 0, 0, 0, 1, 0, 1])
    }

    /// 一个 ICMP 差错报文（`kind` 是类型，`code` 是代码），带回 `original` 的开头（最多头加 8 个字节之外的 `extra` 个）。
    pub(crate) fn icmp_error(source: [u8; 4], destination: [u8; 4], kind: u8, code: u8, original: &[u8]) -> Vec<u8> {
        let mut payload = vec![kind, code, 0, 0, 0, 0, 0x02, 0x28];
        payload.extend_from_slice(original);
        packet(ICMP, source, destination, &payload)
    }

    /// IP 头的校验和（校验和那两个字节要先清零）。
    pub(crate) fn header_checksum(header: &[u8]) -> u16 {
        checksum(header)
    }

    /// 改写一个包（[`packet`] 造的）的分片字段：标识 `id`，片偏移 `offset`（字节，8 的倍数），`more` 是 MF。
    pub(crate) fn refragment(mut bytes: Vec<u8>, id: u16, offset: usize, more: bool) -> Vec<u8> {
        let field = u16::try_from(offset / 8).unwrap() | if more { 0x2000 } else { 0 };
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[6..8].copy_from_slice(&field.to_be_bytes());
        bytes[10..12].fill(0);
        let sum = checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&sum.to_be_bytes());
        bytes
    }

    /// 像内核那样把一个包（头 20 字节）切成片：每片头后面最多 `size` 个字节（8 的倍数），标识 `id`。
    pub(crate) fn split(whole: &[u8], id: u16, size: usize) -> Vec<Vec<u8>> {
        let (header, payload) = whole.split_at(20);
        let chunks: Vec<&[u8]> = payload.chunks(size).collect();
        let last = chunks.len() - 1;
        chunks
            .into_iter()
            .enumerate()
            .map(|(index, chunk)| {
                let mut bytes = header.to_vec();
                bytes[2..4].copy_from_slice(&u16::try_from(20 + chunk.len()).unwrap().to_be_bytes());
                bytes.extend_from_slice(chunk);
                refragment(bytes, id, index * size, index != last)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{icmp, icmp_error, packet, refragment, split, tcp, udp};
    use super::*;

    const A: [u8; 4] = [10, 66, 0, 1];
    const B: [u8; 4] = [10, 66, 0, 2];

    #[test]
    fn the_header_gives_addresses_protocol_and_payload() {
        let bytes = udp(A, B, (5000, 53), b"query");
        let ip = Ipv4::parse(&bytes).unwrap();
        assert_eq!((ip.source(), ip.destination(), ip.protocol(), ip.len()), (A.into(), B.into(), UDP, 33));
        assert_eq!(&ip.payload()[8..], b"query");
        assert_eq!(ip.conversation(), Conversation::Udp { source: 5000, destination: 53 });
        assert!(!ip.is_later_fragment());
    }

    #[test]
    fn packets_that_are_not_whole_ipv4_packets_are_refused() {
        assert_eq!(Ipv4::parse(&[]).unwrap_err(), Malformed::Truncated(0));
        let mut v6 = vec![0x60; 40];
        assert_eq!(Ipv4::parse(&v6).unwrap_err(), Malformed::NotIpv4(6));
        v6[0] = 0x45;
        assert!(matches!(Ipv4::parse(&v6[..10]), Err(Malformed::Truncated(10))));
        let mut bytes = udp(A, B, (1, 2), b"x");
        bytes.push(0);
        assert!(matches!(Ipv4::parse(&bytes), Err(Malformed::Lengths { .. })), "总长度和包对不上");
        let mut short_header = udp(A, B, (1, 2), b"x");
        short_header[0] = 0x44;
        assert!(matches!(Ipv4::parse(&short_header), Err(Malformed::Lengths { header_len: 16, .. })));
        assert_eq!(Ipv4::version_of(&[0x45]), 4);
        assert_eq!(Ipv4::version_of(&[]), 0);
    }

    #[test]
    fn conversations_are_told_apart_by_what_can_open_one() {
        let kind = |bytes: Vec<u8>| Ipv4::parse(&bytes).unwrap().conversation();
        assert_eq!(kind(tcp(A, B, (40000, 22), TCP_SYN)), Conversation::TcpOpen);
        assert_eq!(kind(tcp(A, B, (22, 40000), TCP_SYN | TCP_ACK)), Conversation::TcpOngoing, "SYN-ACK 是回答");
        assert_eq!(kind(tcp(A, B, (22, 40000), TCP_ACK)), Conversation::TcpOngoing);
        assert_eq!(kind(icmp(A, B, ICMP_ECHO_REQUEST)), Conversation::IcmpRequest);
        assert_eq!(kind(icmp(A, B, ICMP_ECHO_REPLY)), Conversation::IcmpAnswer);
        assert_eq!(kind(icmp(A, B, ICMP_UNREACHABLE)), Conversation::IcmpAnswer);
        assert_eq!(kind(icmp(A, B, 13)), Conversation::Other, "时间戳请求不是回答");
        assert_eq!(kind(packet(47, A, B, b"gre")), Conversation::Other);
        assert_eq!(kind(packet(TCP, A, B, b"short")), Conversation::Other, "看不到标志的 TCP");
        let mut later = udp(A, B, (1, 2), b"rest");
        later[6..8].copy_from_slice(&0x00b9u16.to_be_bytes());
        assert_eq!(kind(later), Conversation::LaterFragment);
    }

    #[test]
    fn fragments_tell_their_identification_offset_and_whether_more_follow() {
        let whole = udp(A, B, (5000, 53), &[1; 100]);
        let ip = Ipv4::parse(&whole).unwrap();
        assert!(!ip.is_fragment(), "不许分片（DF）的整包");
        assert_eq!((ip.identification(), ip.fragment_offset(), ip.more_fragments()), (0x1234, 0, false));
        let pieces = split(&whole, 77, 48);
        assert_eq!(pieces.len(), 3);
        let parsed: Vec<Ipv4<'_>> = pieces.iter().map(|piece| Ipv4::parse(piece).unwrap()).collect();
        let fields: Vec<_> =
            parsed.iter().map(|ip| (ip.identification(), ip.fragment_offset(), ip.more_fragments(), ip.payload().len())).collect();
        assert_eq!(fields, [(77, 0, true, 48), (77, 48, true, 48), (77, 96, false, 12)]);
        assert!(parsed.iter().all(Ipv4::is_fragment));
        assert_eq!(parsed[0].conversation(), Conversation::Udp { source: 5000, destination: 53 }, "第一片里有端口");
        assert_eq!(parsed[1].conversation(), Conversation::LaterFragment);
        assert_eq!(parsed[2].conversation(), Conversation::LaterFragment, "最后一片");
    }

    #[test]
    fn the_header_tells_its_length_ttl_checksum_and_flags() {
        let mut bytes = udp(A, B, (5000, 53), b"x");
        let ip = Ipv4::parse(&bytes).unwrap();
        assert_eq!((ip.header_len(), ip.ttl()), (20, 64));
        assert!(ip.header_checksum_ok());
        assert!(ip.dont_fragment_or_reserved(), "测试造的整包置了 DF");
        let cut = refragment(bytes.clone(), 1, 0, true);
        assert!(!Ipv4::parse(&cut).unwrap().dont_fragment_or_reserved(), "切开的片没有 DF");
        bytes[11] ^= 1;
        assert!(!Ipv4::parse(&bytes).unwrap().header_checksum_ok());
        bytes[6] = 0x80;
        assert!(Ipv4::parse(&bytes).unwrap().dont_fragment_or_reserved(), "保留位");
        // 带 4 个字节的选项（一个 NOP 和三个"选项结束"）。
        let mut with_options = vec![0x46, 0, 0, 28, 0, 1, 0x20, 0, 64, UDP, 0, 0, 10, 66, 0, 2, 10, 66, 0, 1, 1, 0, 0, 0];
        with_options.extend_from_slice(&[0, 53, 19, 136]);
        let sum = checksum(&with_options[..24]);
        with_options[10..12].copy_from_slice(&sum.to_be_bytes());
        let ip = Ipv4::parse(&with_options).unwrap();
        assert_eq!(ip.header_len(), 24);
        assert!(ip.header_checksum_ok());
    }

    #[test]
    fn a_tcp_segment_that_is_cut_or_too_short_for_its_header_is_not_judged_by_its_flags() {
        let kind = |bytes: &[u8]| Ipv4::parse(bytes).unwrap().conversation();
        // RFC 1858 的手法：第一片短得只有 16 个字节、标志是 ACK，后面偏移 8 的一片把标志改写成 SYN。
        let ack = tcp(A, B, (40000, 22), TCP_ACK);
        let mut head = ack[..36].to_vec();
        head[2..4].copy_from_slice(&36u16.to_be_bytes());
        assert_eq!(kind(&refragment(head, 9, 0, true)), Conversation::Other, "切开的 TCP 的第一片");
        assert_eq!(kind(&refragment(ack.clone(), 9, 8, false)), Conversation::LaterFragment);
        assert_eq!(kind(&packet(TCP, A, B, &ack[20..39])), Conversation::Other, "头不够 20 个字节");
        assert_eq!(kind(&ack), Conversation::TcpOngoing, "对照：完整的");
    }

    #[test]
    fn an_icmp_error_gives_the_packet_it_quotes() {
        let sent = udp(A, B, (5000, 53), b"query");
        let error = icmp_error(B, A, ICMP_UNREACHABLE, 3, &sent[..28]);
        let ip = Ipv4::parse(&error).unwrap();
        assert!(ip.is_icmp_error());
        let quoted = ip.quoted().unwrap();
        assert_eq!((quoted.source(), quoted.destination(), quoted.protocol()), (A.into(), B.into(), UDP));
        assert_eq!(quoted.conversation(), Conversation::Udp { source: 5000, destination: 53 });
        let header_only = icmp_error(B, A, ICMP_TIME_EXCEEDED, 0, &sent[..20]);
        assert_eq!(
            Ipv4::parse(&header_only).unwrap().quoted().map(|quoted| quoted.conversation()),
            Some(Conversation::Other),
            "头后面没带"
        );
        let cut = icmp_error(B, A, ICMP_UNREACHABLE, 3, &sent[..19]);
        assert!(Ipv4::parse(&cut).unwrap().quoted().is_none(), "头都不完整");
        let not_ipv4 = icmp_error(B, A, ICMP_PARAMETER_PROBLEM, 0, &[0x60; 28]);
        assert!(Ipv4::parse(&not_ipv4).unwrap().quoted().is_none());
        assert!(Ipv4::parse(&icmp(B, A, ICMP_ECHO_REPLY)).unwrap().quoted().is_none(), "ping 的回答不是差错报文");
        let redirect = icmp_error(B, A, ICMP_REDIRECT, 1, &sent[..28]);
        assert!(Ipv4::parse(&redirect).unwrap().is_icmp_redirect());
        assert!(!ip.is_icmp_redirect());
        // 后面几片头后面是原包中间的字节，碰巧是 3 或者 5 也不算。
        let later_error = refragment(icmp_error(B, A, ICMP_UNREACHABLE, 3, &sent[..28]), 5, 8, false);
        assert!(!Ipv4::parse(&later_error).unwrap().is_icmp_error());
        assert!(Ipv4::parse(&later_error).unwrap().quoted().is_none());
        let later_redirect = refragment(redirect, 5, 8, false);
        assert!(!Ipv4::parse(&later_redirect).unwrap().is_icmp_redirect());
    }

    #[test]
    fn an_unreachable_answer_quotes_the_packet_and_comes_from_its_destination() {
        let original = tcp(A, [10, 66, 0, 9], (40000, 80), TCP_SYN);
        let parsed = Ipv4::parse(&original).unwrap();
        let answer = unreachable(&parsed, Unreachable::Host).unwrap();
        let ip = Ipv4::parse(&answer).unwrap();
        assert_eq!((ip.source(), ip.destination(), ip.protocol()), (Ipv4Addr::new(10, 66, 0, 9), A.into(), ICMP));
        assert_eq!(checksum(&answer[..20]), 0, "头的校验和对得上");
        assert_eq!(checksum(&answer[20..]), 0, "ICMP 的校验和对得上");
        assert_eq!(&answer[20..22], &[ICMP_UNREACHABLE, 1]);
        assert_eq!(&answer[28..], &original[..], "整个原包带回去（不长）");
        assert_eq!(ip.conversation(), Conversation::IcmpAnswer);

        let prohibited = unreachable(&parsed, Unreachable::Prohibited).unwrap();
        assert_eq!(prohibited[21], 13);

        let big = udp(A, B, (1, 2), &[7; 1200]);
        let quoted = unreachable(&Ipv4::parse(&big).unwrap(), Unreachable::Host).unwrap();
        assert_eq!(quoted.len(), 576, "大包只带回开头");
    }

    #[test]
    fn errors_later_fragments_and_group_addresses_get_no_answer() {
        let error = icmp(A, B, ICMP_UNREACHABLE);
        assert_eq!(unreachable(&Ipv4::parse(&error).unwrap(), Unreachable::Host), None, "不对差错报文回差错报文");
        let request = icmp(A, B, ICMP_ECHO_REQUEST);
        assert!(unreachable(&Ipv4::parse(&request).unwrap(), Unreachable::Host).is_some(), "ping 的请求要回");
        let mut later = udp(A, B, (1, 2), b"x");
        later[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
        assert_eq!(unreachable(&Ipv4::parse(&later).unwrap(), Unreachable::Host), None);
        for group in [[224, 0, 0, 251], [255, 255, 255, 255]] {
            let mdns = udp(A, group, (5353, 5353), b"q");
            assert_eq!(unreachable(&Ipv4::parse(&mdns).unwrap(), Unreachable::Host), None);
        }
    }
}
