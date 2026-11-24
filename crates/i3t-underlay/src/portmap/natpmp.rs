//! NAT-PMP（RFC 6886）的报文。只有编码和解析，不做 I/O。
//!
//! ```text
//! 问公网地址  0 | 0                                                                     2 字节
//! 回答        0 | 128 | 结果 2 | 网关启动以来的秒数 4 | 公网地址 4                        12 字节
//! 请求映射    0 | 1（UDP）或 2（TCP）| 0 0 | 内部端口 2 | 希望的外部端口 2 | 希望的有效期 4   12 字节
//! 回答        0 | 129 或 130 | 结果 2 | 秒数 4 | 内部端口 2 | 外部端口 2 | 有效期 4          16 字节
//! ```
//!
//! 整数都是大端，有效期的单位是秒。删除映射是"外部端口和有效期都填 0"的映射请求。
//!
//! 该协议不含随机数，响应通过操作码和内部端口与请求匹配。请求通过仅与网关通信的已连接 socket 发送，
//! 路径外主机无法注入伪造响应。

use std::net::Ipv4Addr;

use super::{Protocol, Refused};

const VERSION: u8 = 0;
const OP_ADDRESS: u8 = 0;
/// 回答的操作码是请求的操作码加上这一位。
const REPLY_BIT: u8 = 0x80;

const fn map_opcode(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Udp => 1,
        Protocol::Tcp => 2,
    }
}

/// 网关给的映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Granted {
    pub(super) external_port: u16,
    pub(super) lifetime_secs: u32,
}

pub(super) const fn address_request() -> [u8; 2] {
    [VERSION, OP_ADDRESS]
}

pub(super) const fn map_request(protocol: Protocol, internal_port: u16, external_port: u16, lifetime_secs: u32) -> [u8; 12] {
    let [i0, i1] = internal_port.to_be_bytes();
    let [e0, e1] = external_port.to_be_bytes();
    let [l0, l1, l2, l3] = lifetime_secs.to_be_bytes();
    [VERSION, map_opcode(protocol), 0, 0, i0, i1, e0, e1, l0, l1, l2, l3]
}

/// 解析响应公共头部（版本、操作码、结果码）。操作码与请求 `opcode` 不匹配时返回 `None`。
fn reply_head(datagram: &[u8], opcode: u8) -> Option<(u16, &[u8])> {
    let (&[VERSION, op, hi, lo], rest) = datagram.split_first_chunk::<4>()? else { return None };
    (op == REPLY_BIT | opcode).then(|| (u16::from_be_bytes([hi, lo]), rest))
}

/// 判断数据报是否为公网地址查询的响应。不匹配时返回 `None`，由调用方继续等待。
pub(super) fn parse_address_reply(datagram: &[u8]) -> Option<Result<Ipv4Addr, Refused>> {
    let (code, rest) = reply_head(datagram, OP_ADDRESS)?;
    if code != 0 {
        return Some(Err(Refused { code }));
    }
    let &[_, _, _, _, a, b, c, d] = rest else { return None };
    Some(Ok(Ipv4Addr::new(a, b, c, d)))
}

/// 判断数据报是否为指定 `protocol` 与 `internal_port` 映射请求的响应。不匹配时返回 `None`，由调用方继续等待。
pub(super) fn parse_map_reply(datagram: &[u8], protocol: Protocol, internal_port: u16) -> Option<Result<Granted, Refused>> {
    let (code, rest) = reply_head(datagram, map_opcode(protocol))?;
    if code != 0 {
        return Some(Err(Refused { code }));
    }
    let &[_, _, _, _, i0, i1, e0, e1, l0, l1, l2, l3] = rest else { return None };
    (u16::from_be_bytes([i0, i1]) == internal_port)
        .then(|| Ok(Granted { external_port: u16::from_be_bytes([e0, e1]), lifetime_secs: u32::from_be_bytes([l0, l1, l2, l3]) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_have_the_documented_layout() {
        assert_eq!(address_request(), [0, 0]);
        assert_eq!(map_request(Protocol::Udp, 20330, 20330, 7200), [0, 1, 0, 0, 0x4f, 0x6a, 0x4f, 0x6a, 0, 0, 0x1c, 0x20]);
        assert_eq!(map_request(Protocol::Tcp, 20330, 0, 0), [0, 2, 0, 0, 0x4f, 0x6a, 0, 0, 0, 0, 0, 0], "删除：外部端口和有效期都是 0");
    }

    #[test]
    fn an_address_reply_yields_the_public_address() {
        let reply = [0, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 7];
        assert_eq!(parse_address_reply(&reply), Some(Ok(Ipv4Addr::new(203, 0, 113, 7))));
    }

    #[test]
    fn a_map_reply_yields_the_external_port_and_the_granted_lifetime() {
        let reply = [0, 129, 0, 0, 0, 0, 0, 9, 0x4f, 0x6a, 0x9c, 0x40, 0, 0, 0x0e, 0x10];
        assert_eq!(parse_map_reply(&reply, Protocol::Udp, 20330), Some(Ok(Granted { external_port: 40000, lifetime_secs: 3600 })));
    }

    #[test]
    fn error_result_codes_are_reported_as_refusals() {
        // 不支持的版本（1）、网关拒绝（2）：出错的回答可以只有头和秒数。
        assert_eq!(parse_address_reply(&[0, 128, 0, 1, 0, 0, 0, 9]), Some(Err(Refused { code: 1 })));
        assert_eq!(parse_map_reply(&[0, 130, 0, 2, 0, 0, 0, 9], Protocol::Tcp, 20330), Some(Err(Refused { code: 2 })));
        let full = [0, 129, 0, 4, 0, 0, 0, 9, 0x4f, 0x6a, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_map_reply(&full, Protocol::Udp, 20330), Some(Err(Refused { code: 4 })));
    }

    #[test]
    fn replies_to_something_else_are_not_mistaken_for_ours() {
        let udp_reply = [0, 129, 0, 0, 0, 0, 0, 9, 0x4f, 0x6a, 0x9c, 0x40, 0, 0, 0x0e, 0x10];
        assert_eq!(parse_map_reply(&udp_reply, Protocol::Tcp, 20330), None, "操作码是另一种协议的");
        assert_eq!(parse_map_reply(&udp_reply, Protocol::Udp, 20331), None, "内部端口是别的映射的");
        assert_eq!(parse_address_reply(&udp_reply), None, "映射的回答不是地址的回答");
        assert_eq!(parse_address_reply(&[0, 0]), None, "请求不是回答");
        // 版本不是 0 的（比如 PCP 的回答）不认。
        assert_eq!(parse_address_reply(&[2, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 7]), None);
    }

    #[test]
    fn truncated_or_overlong_replies_are_ignored() {
        let address = [0, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 7];
        let map = [0, 129, 0, 0, 0, 0, 0, 9, 0x4f, 0x6a, 0x9c, 0x40, 0, 0, 0x0e, 0x10];
        for len in 0..address.len() {
            assert_eq!(parse_address_reply(&address[..len]), None, "{len}");
        }
        for len in 0..map.len() {
            assert_eq!(parse_map_reply(&map[..len], Protocol::Udp, 20330), None, "{len}");
        }
        assert_eq!(parse_address_reply(&[&address[..], &[0]].concat()), None);
        assert_eq!(parse_map_reply(&[&map[..], &[0]].concat(), Protocol::Udp, 20330), None);
    }
}
