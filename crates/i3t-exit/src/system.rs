//! 出口要向操作系统要的几样东西：本机网卡上的地址、域名解析、TCP 连接，以及 UDP 报文发到哪里。

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};

use if_addrs::IfAddr;
use ipnet::IpNet;
use tokio::net::TcpStream;

/// 出口和操作系统之间的接缝。
///
/// 正常运行时用 [`Os`]。测试里换成假的：给出想要的网卡和解析结果，把"公网地址"引到本机的测试服务上。
/// 策略检查全部在这一层之上做，所以换掉它不会绕过任何检查。
pub trait System: Send + Sync + 'static {
    /// 本机所有网卡上的地址，各自带着前缀长度：地址用来连本机自己的服务，网段用来判断一个目标是不是在直连的局域网里。
    ///
    /// # Errors
    ///
    /// 操作系统返回错误。此时出口无法判断目标是否属于本机内网，将拒绝请求。
    fn interfaces(&self) -> io::Result<Vec<IpNet>>;

    /// 在本机解析一个域名。
    fn resolve(&self, name: &str) -> impl Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send;

    /// 建一条到 `addr` 的 TCP 连接。连接的选项（NODELAY、保活）由调用者设置。
    fn connect(&self, addr: SocketAddr) -> impl Future<Output = io::Result<TcpStream>> + Send;

    /// 发往 `addr` 的 UDP 报文实际发到哪个地址。
    ///
    /// 真的操作系统上就是 `addr` 自己，所以有这个默认实现。测试里的替身用它把"公网地址"引到本机的测试服务上，
    /// 作用和替身的 [`connect`](Self::connect) 一样；策略检查在这之前已经按 `addr` 做完了。
    fn udp_route(&self, addr: SocketAddr) -> SocketAddr {
        addr
    }
}

/// 域名解析失败的原因。两种情况的归因不同：域名不存在算目标的，解析器出问题算出口自己的。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("域名不存在")]
    NotFound,
    #[error("解析器出错：{0}")]
    Failed(String),
}

/// 真正的操作系统。
///
/// 域名通过系统解析器（`getaddrinfo`）解析，因此 hosts 文件与本机 DNS 配置均正常生效，解析结果与本机其他程序一致。
#[derive(Debug, Clone, Copy, Default)]
pub struct Os;

impl System for Os {
    fn interfaces(&self) -> io::Result<Vec<IpNet>> {
        let interfaces = if_addrs::get_if_addrs()?;
        let nets = interfaces.into_iter().filter_map(|interface| {
            let (ip, prefix_len) = match interface.addr {
                IfAddr::V4(addr) => (IpAddr::V4(addr.ip), addr.prefixlen),
                IfAddr::V6(addr) => (IpAddr::V6(addr.ip), addr.prefixlen),
            };
            IpNet::new(ip, prefix_len).ok()
        });
        Ok(nets.collect())
    }

    async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let name = name.to_owned();
        // getaddrinfo 是阻塞的。
        let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_host(&name).map(Iterator::collect::<Vec<IpAddr>>));
        match lookup.await {
            Ok(Ok(addrs)) => Ok(addrs),
            Ok(Err(error)) => match error.kind() {
                dns_lookup::LookupErrorKind::NoName | dns_lookup::LookupErrorKind::NoData => Err(ResolveError::NotFound),
                _ => Err(ResolveError::Failed(io::Error::from(error).to_string())),
            },
            Err(error) => Err(ResolveError::Failed(error.to_string())),
        }
    }

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        // 目标通常并非本程序：仅能通过本端通告的 MSS 避免对端发送链路无法承载的大分段（见 `i3t_underlay::tcp_mss`）。
        i3t_underlay::tcp_mss::connect(addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_loopback_interface_is_listed_with_its_prefix() {
        let interfaces = Os.interfaces().unwrap();
        let loopback = interfaces.iter().find(|net| net.addr() == IpAddr::from([127, 0, 0, 1])).expect("本机应该有回环网卡");
        assert_eq!(loopback.prefix_len(), 8);
        assert!(loopback.contains(&IpAddr::from([127, 9, 9, 9])));
    }

    #[tokio::test]
    async fn localhost_resolves_to_a_loopback_address() {
        let addrs = Os.resolve("localhost").await.unwrap();
        assert!(!addrs.is_empty() && addrs.iter().all(IpAddr::is_loopback), "{addrs:?}");
    }
}
