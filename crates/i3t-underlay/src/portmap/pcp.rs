//! PCP（RFC 6887）的 MAP 请求和回答。只有编码和解析，不做 I/O。
//!
//! ```text
//! 请求  2 | 1（MAP）| 0 0 | 希望的有效期 4 | 客户端地址 16                                      头，24 字节
//!       随机数 12 | 协议 1（17 是 UDP，6 是 TCP）| 0 0 0 | 内部端口 2 | 希望的外部端口 2 | 希望的外部地址 16
//! 回答  2 | 129 | 0 | 结果 1 | 有效期 4 | 网关的时间 4 | 0 × 12                                 头，24 字节
//!       随机数 12 | 协议 1 | 0 0 0 | 内部端口 2 | 分到的外部端口 2 | 分到的外部地址 16
//! ```
//!
//! 整数都是大端，有效期的单位是秒，IPv4 地址写成映射的 IPv6 地址。请求和回答都是 60 字节。
//!
//! - 客户端地址必须就是发请求的那个源地址，网关靠它发现中间还有没有别的地址转换。
//! - 随机数由客户端为每个映射选定，续期和删除均需携带同一随机数，防止其他主机篡改该映射。
//! - 删除映射是"有效期填 0"的 MAP 请求。
//!
//! 只会 NAT-PMP 的网关收到 PCP 的请求时，按 NAT-PMP 的格式回一个"不支持的版本"（RFC 6887 附录 A）。
//! 这里把版本不是 2 的回答都当成这种情况，调用方不用等超时就可以改用 NAT-PMP。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{Protocol, Refused};

const VERSION: u8 = 2;
const OP_MAP: u8 = 1;
const REPLY_BIT: u8 = 0x80;
/// 结果码：网关不支持该协议版本。
const UNSUPPORTED_VERSION: u16 = 1;

const HEADER_LEN: usize = 24;
pub(super) const NONCE_LEN: usize = 12;
/// MAP 的请求和回答一样长。
pub(super) const MAP_LEN: usize = HEADER_LEN + NONCE_LEN + 4 + 2 + 2 + 16;

/// 一个映射的随机数。
pub(super) type Nonce = [u8; NONCE_LEN];

const fn protocol_number(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Udp => 17,
        Protocol::Tcp => 6,
    }
}

/// 一个 MAP 请求里要填的东西。
#[derive(Debug, Clone, Copy)]
pub(super) struct MapRequest {
    pub(super) nonce: Nonce,
    pub(super) protocol: Protocol,
    /// 发这个请求用的本机地址。
    pub(super) client: Ipv4Addr,
    pub(super) internal_port: u16,
    /// 希望的外部端口；0 表示随网关给。
    pub(super) external_port: u16,
    /// 0 表示删除这个映射。
    pub(super) lifetime_secs: u32,
}

impl MapRequest {
    pub(super) fn to_bytes(self) -> [u8; MAP_LEN] {
        let mut bytes = [0; MAP_LEN];
        let (header, map) = bytes.split_at_mut(HEADER_LEN);
        header[0] = VERSION;
        header[1] = OP_MAP;
        header[4..8].copy_from_slice(&self.lifetime_secs.to_be_bytes());
        header[8..].copy_from_slice(&self.client.to_ipv6_mapped().octets());
        map[..NONCE_LEN].copy_from_slice(&self.nonce);
        map[NONCE_LEN] = protocol_number(self.protocol);
        map[16..18].copy_from_slice(&self.internal_port.to_be_bytes());
        map[18..20].copy_from_slice(&self.external_port.to_be_bytes());
        // 希望的外部地址填"IPv4 的未指定地址"，意思是随网关给。
        map[20..].copy_from_slice(&Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().octets());
        bytes
    }

    /// 判断数据报是否为当前请求的响应。不匹配时返回 `None`，由调用方继续等待。
    pub(super) fn parse_reply(&self, datagram: &[u8]) -> Option<Result<Granted, Refused>> {
        let (&[version, op, _, code], rest) = datagram.split_first_chunk::<4>()?;
        if version != VERSION {
            return Some(Err(Refused { code: UNSUPPORTED_VERSION }));
        }
        if op != REPLY_BIT | OP_MAP {
            return None;
        }
        if code != 0 {
            // 出错的回答也把请求的内容抄回来，但有的网关只回一个头：不去核对后面的部分。
            return Some(Err(Refused { code: u16::from(code) }));
        }
        let (&lifetime, rest) = rest.split_first_chunk::<4>()?;
        // 网关的时间 4 字节、保留 12 字节。
        let (_, map) = rest.split_at_checked(HEADER_LEN - 8)?;
        let (&nonce, map) = map.split_first_chunk::<NONCE_LEN>()?;
        let &[protocol, _, _, _, i0, i1, e0, e1, ref address @ ..] = map else { return None };
        let address: &[u8; 16] = address.try_into().ok()?;
        let ours = nonce == self.nonce && protocol == protocol_number(self.protocol) && u16::from_be_bytes([i0, i1]) == self.internal_port;
        ours.then(|| {
            Ok(Granted {
                external_ip: Ipv6Addr::from(*address).to_canonical(),
                external_port: u16::from_be_bytes([e0, e1]),
                lifetime_secs: u32::from_be_bytes(lifetime),
            })
        })
    }
}

/// 网关给的映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Granted {
    pub(super) external_ip: IpAddr,
    pub(super) external_port: u16,
    pub(super) lifetime_secs: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: Nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    fn request() -> MapRequest {
        MapRequest {
            nonce: NONCE,
            protocol: Protocol::Udp,
            client: Ipv4Addr::new(192, 168, 1, 5),
            internal_port: 20330,
            external_port: 20330,
            lifetime_secs: 7200,
        }
    }

    /// 网关对 `request` 的成功回答：外部地址 203.0.113.7:40000，有效期 3600 秒。
    fn reply(request: &MapRequest) -> Vec<u8> {
        let mut bytes = request.to_bytes().to_vec();
        bytes[1] = 0x81;
        bytes[3] = 0;
        bytes[4..8].copy_from_slice(&3600u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&77u32.to_be_bytes());
        bytes[12..24].fill(0);
        bytes[42..44].copy_from_slice(&40000u16.to_be_bytes());
        bytes[44..].copy_from_slice(&Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped().octets());
        bytes
    }

    #[test]
    fn a_map_request_has_the_documented_layout() {
        let bytes = request().to_bytes();
        assert_eq!(bytes.len(), 60);
        assert_eq!(&bytes[..8], [2, 1, 0, 0, 0, 0, 0x1c, 0x20]);
        assert_eq!(&bytes[8..24], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 5], "客户端地址写成映射的 IPv6 地址");
        assert_eq!(&bytes[24..36], NONCE);
        assert_eq!(&bytes[36..44], [17, 0, 0, 0, 0x4f, 0x6a, 0x4f, 0x6a]);
        assert_eq!(&bytes[44..], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0]);

        let delete = MapRequest { protocol: Protocol::Tcp, external_port: 0, lifetime_secs: 0, ..request() }.to_bytes();
        assert_eq!(&delete[4..8], [0, 0, 0, 0], "删除：有效期是 0");
        assert_eq!(delete[36], 6);
    }

    #[test]
    fn a_successful_reply_yields_the_external_address_and_the_granted_lifetime() {
        let request = request();
        let granted = Granted { external_ip: "203.0.113.7".parse().unwrap(), external_port: 40000, lifetime_secs: 3600 };
        assert_eq!(request.parse_reply(&reply(&request)), Some(Ok(granted)));
    }

    #[test]
    fn an_ipv6_external_address_is_reported_as_it_is() {
        let request = request();
        let mut bytes = reply(&request);
        let address: Ipv6Addr = "2001:db8::7".parse().unwrap();
        bytes[44..].copy_from_slice(&address.octets());
        assert_eq!(request.parse_reply(&bytes).unwrap().unwrap().external_ip, IpAddr::V6(address));
    }

    #[test]
    fn replies_that_do_not_match_the_request_are_ignored() {
        let request = request();
        let tamper = |edit: fn(&mut Vec<u8>)| {
            let mut bytes = reply(&request);
            edit(&mut bytes);
            request.parse_reply(&bytes)
        };
        assert_eq!(tamper(|bytes| bytes[24] ^= 0xff), None, "随机数不对");
        assert_eq!(tamper(|bytes| bytes[36] = 6), None, "协议不对");
        assert_eq!(tamper(|bytes| bytes[41] ^= 1), None, "内部端口不对");
        assert_eq!(tamper(|bytes| bytes[1] = 0x82), None, "别的操作码的回答");
        assert_eq!(tamper(|bytes| bytes[1] = 1), None, "请求不是回答");
        assert_eq!(tamper(|bytes| bytes.push(0)), None, "太长");
        let bytes = reply(&request);
        for len in 0..bytes.len() {
            assert_eq!(request.parse_reply(&bytes[..len]), None, "{len}");
        }
    }

    #[test]
    fn error_result_codes_are_reported_as_refusals() {
        let request = request();
        let mut not_authorized = reply(&request);
        not_authorized[3] = 2;
        assert_eq!(request.parse_reply(&not_authorized), Some(Err(Refused { code: 2 })));
        // 只回一个头的也认。
        assert_eq!(request.parse_reply(&not_authorized[..24]), Some(Err(Refused { code: 2 })));
        assert_eq!(request.parse_reply(&[2, 0x81, 0, 8]), Some(Err(Refused { code: 8 })));
    }

    #[test]
    fn a_reply_in_another_version_means_the_gateway_does_not_speak_pcp() {
        // 只会 NAT-PMP 的网关：版本 0，结果码 1。
        let nat_pmp_only = [0, 129, 0, 1, 0, 0, 0, 9];
        assert_eq!(request().parse_reply(&nat_pmp_only), Some(Err(Refused { code: 1 })));
        // 只会 PCP 第 1 版的网关。
        assert_eq!(request().parse_reply(&[1, 0x81, 0, 1]), Some(Err(Refused { code: 1 })));
    }
}
