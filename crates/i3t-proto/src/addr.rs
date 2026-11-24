//! 地址查询与应答："你看到我的地址是什么"。
//!
//! 节点靠它知道自己在 NAT 外面的地址，不依赖第三方的 STUN 服务。能回答的有 controller（专门开一个 UDP 端口）、
//! relay 和已经连上的对端。
//!
//! ```text
//! 查询  0x0a | 随机数 8 字节 | 填充到 32 字节
//! 应答  0x0b | 随机数 8 字节 | 地址族 1 字节（4 或 6） | 地址 4 或 16 字节 | 端口 2 字节（大端）
//! ```
//!
//! 查询固定为 32 字节，应答最长为 28 字节：应答不超过查询大小，可防止伪造来源地址用于流量放大攻击。
//! 应答方不保存任何状态。随机数由查询方生成，用于将应答与查询关联，并防止路径外的攻击者伪造应答。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 查询帧的首字节。
pub const KIND_QUERY: u8 = 0x0a;
/// 应答帧的首字节。
pub const KIND_REPLY: u8 = 0x0b;

const NONCE_LEN: usize = 8;
const FAMILY_V4: u8 = 4;
const FAMILY_V6: u8 = 6;

/// 一次地址查询。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query {
    pub nonce: [u8; NONCE_LEN],
}

impl Query {
    /// 查询帧的长度。比最长的应答还长，多出来的是填充。
    pub const LEN: usize = 32;

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        bytes[0] = KIND_QUERY;
        bytes[1..=NONCE_LEN].copy_from_slice(&self.nonce);
        bytes
    }

    /// 非完整查询帧时返回 `None`。长度小于 [`Query::LEN`] 的一律拒绝，避免应答大于查询。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < Self::LEN {
            return None;
        }
        let (&[KIND_QUERY], rest) = datagram.split_first_chunk::<1>()? else { return None };
        Some(Self { nonce: *rest.first_chunk::<NONCE_LEN>()? })
    }
}

/// 对一次查询的回答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    /// 原样抄回查询里的随机数。
    pub nonce: [u8; NONCE_LEN],
    /// 回答的一方看到的查询来源地址。
    pub observed: SocketAddr,
}

impl Reply {
    /// 应答帧最长多少字节（IPv6 地址时）。
    pub const MAX_LEN: usize = 1 + NONCE_LEN + 1 + 16 + 2;

    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::MAX_LEN);
        bytes.push(KIND_REPLY);
        bytes.extend_from_slice(&self.nonce);
        // IPv4 映射的 IPv6 地址按 IPv4 报告：双栈 socket 上收到的 IPv4 包就是这种形式。
        match self.observed.ip().to_canonical() {
            IpAddr::V4(ip) => {
                bytes.push(FAMILY_V4);
                bytes.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                bytes.push(FAMILY_V6);
                bytes.extend_from_slice(&ip.octets());
            }
        }
        bytes.extend_from_slice(&self.observed.port().to_be_bytes());
        bytes
    }

    /// 不是一个完整的应答帧时返回 `None`。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (&[KIND_REPLY], rest) = datagram.split_first_chunk::<1>()? else { return None };
        let (&nonce, rest) = rest.split_first_chunk::<NONCE_LEN>()?;
        let (&family, rest) = rest.split_first()?;
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
        let &[hi, lo] = rest else { return None };
        // 和编码一致：IPv4 映射的 IPv6 地址就是那个 IPv4 地址，只有一种写法。
        Some(Self { nonce, observed: SocketAddr::new(ip.to_canonical(), u16::from_be_bytes([hi, lo])) })
    }
}

const _: () = assert!(Reply::MAX_LEN <= Query::LEN);

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn query_round_trips_and_is_padded() {
        let bytes = Query { nonce: NONCE }.to_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[..9], [0x0a, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(bytes[9..].iter().all(|&byte| byte == 0));
        assert_eq!(Query::parse(&bytes), Some(Query { nonce: NONCE }));
    }

    #[test]
    fn short_or_foreign_queries_are_ignored() {
        let bytes = Query { nonce: NONCE }.to_bytes();
        assert_eq!(Query::parse(&bytes[..31]), None);
        assert_eq!(Query::parse(&[0x0b; 32]), None);
        assert_eq!(Query::parse(&[]), None);
    }

    #[test]
    fn an_ipv4_address_sent_in_ipv6_clothes_is_read_as_ipv4() {
        let mut bytes = vec![KIND_REPLY];
        bytes.extend_from_slice(&NONCE);
        bytes.push(FAMILY_V6);
        bytes.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped().octets());
        bytes.extend_from_slice(&4433u16.to_be_bytes());
        let reply = Reply::parse(&bytes).unwrap();
        assert_eq!(reply.observed, "192.0.2.7:4433".parse().unwrap());
        assert_eq!(Reply::parse(&reply.to_bytes()), Some(reply), "读出来的应答再写再读，还是它");
    }

    #[test]
    fn reply_round_trips_for_both_address_families() {
        for observed in ["203.0.113.7:20330", "[2001:db8::1]:443"] {
            let reply = Reply { nonce: NONCE, observed: observed.parse().unwrap() };
            let bytes = reply.to_bytes();
            assert!(bytes.len() <= Query::LEN);
            assert_eq!(Reply::parse(&bytes), Some(reply));
        }
    }

    #[test]
    fn mapped_ipv4_is_reported_as_ipv4() {
        let reply = Reply { nonce: NONCE, observed: "[::ffff:203.0.113.7]:5000".parse().unwrap() };
        let parsed = Reply::parse(&reply.to_bytes()).unwrap();
        assert_eq!(parsed.observed, "203.0.113.7:5000".parse().unwrap());
    }

    #[test]
    fn malformed_replies_are_ignored() {
        let bytes = Reply { nonce: NONCE, observed: "203.0.113.7:20330".parse().unwrap() }.to_bytes();
        assert_eq!(Reply::parse(&bytes[..bytes.len() - 1]), None);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(Reply::parse(&trailing), None);
        let mut bad_family = bytes;
        bad_family[9] = 5;
        assert_eq!(Reply::parse(&bad_family), None);
    }
}
