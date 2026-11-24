//! 替别人往外发 UDP 用的 socket。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// 一个出站用的 UDP 端口：绑在系统挑的端口上，IPv4 和 IPv6 的目标都从它发。
///
/// 一个数据报上下文（或者一个就地出站的 UDP 关联）只用一个这样的端口，发往不同目标的报文都从它出去，
/// 所以每个目标看到的来源端口是同一个（与目的地址无关的映射）。为了一个端口两种地址都能发，
/// 它是一个同时收发 IPv4 的 IPv6 socket；机器上没有 IPv6 时退回只有 IPv4 的 socket，那时 IPv6 的目标发不出去。
#[derive(Debug)]
pub struct OutboundSocket {
    socket: UdpSocket,
    /// 这是一个 IPv6 的 socket，IPv4 的地址要写成映射地址才发得出去。
    dual_stack: bool,
}

impl OutboundSocket {
    /// 绑一个新的端口。要在 tokio 运行时里调用。
    ///
    /// # Errors
    ///
    /// 系统不给 socket（比如文件描述符用完了）。
    pub fn bind() -> io::Result<Self> {
        match Self::bind_dual_stack() {
            Ok(socket) => Ok(Self { socket, dual_stack: true }),
            Err(error) => {
                tracing::debug!(%error, "绑定双栈 IPv6 端口失败，回退为仅 IPv4 端口");
                let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
                socket.set_nonblocking(true)?;
                Ok(Self { socket: UdpSocket::from_std(socket)?, dual_stack: false })
            }
        }
    }

    fn bind_dual_stack() -> io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        // 有的系统默认只收发 IPv6。
        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
        UdpSocket::from_std(socket.into())
    }

    /// 系统挑的端口号。
    ///
    /// # Errors
    ///
    /// 系统不给（不应该发生）。
    pub fn port(&self) -> io::Result<u16> {
        self.socket.local_addr().map(|addr| addr.port())
    }

    /// 发一个报文到 `addr`。
    ///
    /// # Errors
    ///
    /// 系统拒绝发送，如地址族不可用、网络不可达或报文过长等。
    pub async fn send_to(&self, payload: &[u8], addr: SocketAddr) -> io::Result<()> {
        let addr = match addr.ip().to_canonical() {
            IpAddr::V4(ip) if self.dual_stack => SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port()),
            ip => SocketAddr::new(ip, addr.port()),
        };
        self.socket.send_to(payload, addr).await.map(drop)
    }

    /// 收一个报文，返回它的长度和来源。IPv4 的来源给的是 IPv4 地址，不是映射地址。
    /// 比 `buf` 长的报文被截断。可以放在 `select!` 里：被取消时不会丢报文。
    ///
    /// # Errors
    ///
    /// 系统报错。有的系统会把上一次发送引起的"端口不可达"报在这里。
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (len, from) = self.socket.recv_from(buf).await?;
        Ok((len, SocketAddr::new(from.ip().to_canonical(), from.port())))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    async fn echo_once(server: &UdpSocket) {
        let mut buf = [0; 64];
        let (len, from) = server.recv_from(&mut buf).await.unwrap();
        server.send_to(&buf[..len], from).await.unwrap();
    }

    #[tokio::test]
    async fn one_port_reaches_ipv4_targets_and_reports_their_addresses_as_ipv4() {
        let socket = OutboundSocket::bind().unwrap();
        let (first, second) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut seen_ports = Vec::new();
        for server in [&first, &second] {
            let target = server.local_addr().unwrap();
            socket.send_to(b"ping", target).await.unwrap();
            let mut buf = [0; 64];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            seen_ports.push(from.port());
            server.send_to(&buf[..len], from).await.unwrap();

            let (len, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await.unwrap().unwrap();
            assert_eq!((&buf[..len], from), (&b"ping"[..], target), "来源是 IPv4 地址，不是映射地址");
        }
        // 两个目标看到的是同一个来源端口。
        assert_eq!(seen_ports, [socket.port().unwrap(); 2]);
    }

    #[tokio::test]
    async fn the_same_port_reaches_ipv6_targets_when_the_machine_has_ipv6() {
        let Ok(server) = UdpSocket::bind("[::1]:0").await else {
            eprintln!("跳过：这台机器没有 IPv6 的回环地址");
            return;
        };
        let socket = OutboundSocket::bind().unwrap();
        let target = server.local_addr().unwrap();
        socket.send_to(b"ping", target).await.unwrap();
        echo_once(&server).await;
        let mut buf = [0; 64];
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!((&buf[..len], from), (&b"ping"[..], target));
    }
}
