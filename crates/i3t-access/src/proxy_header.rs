//! PROXY protocol 的头（HAProxy 公开的规范，v1 和 v2）：端口转发的目标节点连上目标之后先发它，
//! 认它的服务（nginx 的 `proxy_protocol`、HAProxy、Postfix 等）据此看到是谁连过来的，而不是目标节点自己的地址。
//! 出口一侧（别的节点开流过来）和入口一侧（监听和目标在同一个节点上的转发）都用它，所以放在这里。
//!
//! 头里的来源由调用方给，只能是核对过的地址，客户端自己说的不算：
//!
//! - 别的节点开流过来：发起节点的虚拟 IP（连接的握手认出的发起节点），端口是连到目标的那条 TCP 的本地端口；
//! - 监听和目标在同一个节点上：监听上那条连接的来源地址和端口。经虚拟网卡进来的是对端的虚拟 IP，
//!   别的网卡上进来的（局域网里的机器、IPv6 的客户端）是它的真实地址。
//!
//! 目的是这条 TCP 实际连到的地址。两个地址要同一族：有一个是 IPv6 时，另一个写成 IPv4 映射的 IPv6 地址。
//! 认这个头的服务把连接上最先到的字节当成头来读，所以要求了这个头的转发不能有哪条连接不发它：
//! 那样客户端自己的头几个字节就成了"头"，来源随它写。所以哪一种来源都写得出头来。

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use i3t_model::netmap::ProxyProtocol;

/// v2 的头开头的 12 个字节。
const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// 版本 2，命令 PROXY（转述别人的连接）。
const V2_PROXY: u8 = 0x21;
const V2_TCP4: u8 = 0x11;
const V2_TCP6: u8 = 0x21;

/// `source` 连到 `destination` 的头。IPv4 映射的 IPv6 地址按里面的 IPv4 地址算。
#[must_use]
pub fn encode(version: ProxyProtocol, source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let (source_port, destination_port) = (source.port(), destination.port());
    match (source.ip().to_canonical(), destination.ip().to_canonical()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => match version {
            ProxyProtocol::V1 => format!("PROXY TCP4 {source} {destination} {source_port} {destination_port}\r\n").into_bytes(),
            ProxyProtocol::V2 => v2(V2_TCP4, &source.octets(), &destination.octets(), source_port, destination_port),
        },
        (source, destination) => {
            let (source, destination) = (as_v6(source), as_v6(destination));
            match version {
                ProxyProtocol::V1 => format!("PROXY TCP6 {source} {destination} {source_port} {destination_port}\r\n").into_bytes(),
                ProxyProtocol::V2 => v2(V2_TCP6, &source.octets(), &destination.octets(), source_port, destination_port),
            }
        }
    }
}

/// v2 的头：签名、版本和命令、地址族、后面的长度，然后是两个地址和两个端口。
fn v2(family: u8, source: &[u8], destination: &[u8], source_port: u16, destination_port: u16) -> Vec<u8> {
    let length = u16::try_from(source.len() + destination.len() + 4).expect("两个地址加两个端口最多 36 个字节");
    let mut header = V2_SIGNATURE.to_vec();
    header.extend_from_slice(&[V2_PROXY, family]);
    header.extend_from_slice(&length.to_be_bytes());
    header.extend_from_slice(source);
    header.extend_from_slice(destination);
    header.extend_from_slice(&source_port.to_be_bytes());
    header.extend_from_slice(&destination_port.to_be_bytes());
    header
}

fn as_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn v1_is_one_line_with_the_source_and_the_address_the_connection_reached() {
        let header = encode(ProxyProtocol::V1, at("10.66.0.2:41000"), at("127.0.0.1:5432"));
        assert_eq!(header, b"PROXY TCP4 10.66.0.2 127.0.0.1 41000 5432\r\n");
        let header = encode(ProxyProtocol::V1, at("10.66.0.2:41000"), at("[::1]:8080"));
        assert_eq!(header, b"PROXY TCP6 ::ffff:10.66.0.2 ::1 41000 8080\r\n");
        let header = encode(ProxyProtocol::V1, at("10.66.0.2:1"), at("[::ffff:192.168.1.10]:80"));
        assert_eq!(header, b"PROXY TCP4 10.66.0.2 192.168.1.10 1 80\r\n", "映射的 IPv4 目标按 IPv4 写");
        assert!(header.len() <= 107, "v1 的头最长 107 字节");
    }

    #[test]
    fn an_ipv6_source_gets_a_tcp6_header_whatever_the_family_of_the_destination() {
        let header = encode(ProxyProtocol::V1, at("[2001:db8::9]:50000"), at("127.0.0.1:8080"));
        assert_eq!(header, b"PROXY TCP6 2001:db8::9 ::ffff:127.0.0.1 50000 8080\r\n");
        let header = encode(ProxyProtocol::V1, at("[::1]:50000"), at("[::1]:8080"));
        assert_eq!(header, b"PROXY TCP6 ::1 ::1 50000 8080\r\n");
        let header = encode(ProxyProtocol::V1, at("[::ffff:192.168.1.9]:50000"), at("127.0.0.1:8080"));
        assert_eq!(header, b"PROXY TCP4 192.168.1.9 127.0.0.1 50000 8080\r\n", "双栈监听上的 IPv4 客户端按 IPv4 写");
        // 最长的写法也在 v1 的上限之内。
        let longest = encode(
            ProxyProtocol::V1,
            at("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"),
            at("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535"),
        );
        assert!(longest.len() <= 107, "{}", longest.len());

        let header = encode(ProxyProtocol::V2, at("[2001:db8::9]:50000"), at("127.0.0.1:8080"));
        assert_eq!(&header[..16], b"\r\n\r\n\0\r\nQUIT\n\x21\x21\x00\x24");
        assert_eq!(&header[16..32], &"2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(&header[32..48], &"::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(&header[48..], &[0xc3, 0x50, 0x1f, 0x90]);
    }

    #[test]
    fn v2_is_the_binary_header_for_tcp_over_ipv4_and_ipv6() {
        let header = encode(ProxyProtocol::V2, at("10.66.0.2:4660"), at("192.168.1.10:80"));
        let mut expected = b"\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0c".to_vec();
        expected.extend_from_slice(&[10, 66, 0, 2, 192, 168, 1, 10, 0x12, 0x34, 0, 80]);
        assert_eq!(header, expected);

        let header = encode(ProxyProtocol::V2, at("10.66.0.2:7"), at("[2001:db8::5]:443"));
        assert_eq!(&header[12..16], &[0x21, 0x21, 0, 36]);
        assert_eq!(&header[16..32], &"::ffff:10.66.0.2".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(&header[32..48], &"2001:db8::5".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(&header[48..], &[0, 7, 1, 187]);
    }
}
