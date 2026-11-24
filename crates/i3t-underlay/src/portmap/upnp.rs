//! UPnP-IGD：找到局域网里的网关设备，用它的 SOAP 接口加、删端口映射。协议本身交给 `igd-next`。

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use igd_next::aio::Gateway;
use igd_next::aio::tokio::{Tokio, search_gateway};
use igd_next::{AddAnyPortError, AddPortError, GatewayIpVersion, PortMappingProtocol, SearchOptions};

use super::{Lease, MapError, Protocol, Timing};

/// 向网关申请的有效期。到期之前会续；网关重启丢了映射的话，最迟这么久之后它自己消失。
const LEASE_SECS: u32 = 3600;
/// 写在映射上的说明，路由器的管理界面里看得到。
const DESCRIPTION: &str = "ice3tier";

/// SSDP 搜索往哪里发、认谁的回答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ssdp {
    pub(super) to: SocketAddr,
    /// 有值时只认这个地址上的设备。正常使用时是默认网关：替本机做地址转换的是它，别的设备上的映射没有用。
    pub(super) only: Option<IpAddr>,
    /// 除响应搜索的地址外，设备描述中额外允许的地址列表。`igd-next` 默认拒绝回环地址，测试中的模拟网关需显式放行。
    pub(super) trusted: Vec<IpAddr>,
}

/// 一台找到的网关设备。
#[derive(Debug, Clone)]
pub(super) struct Igd {
    gateway: Gateway<Tokio>,
}

impl PartialEq for Igd {
    fn eq(&self, other: &Self) -> bool {
        self.gateway.addr == other.gateway.addr && self.gateway.control_url == other.gateway.control_url
    }
}

impl Eq for Igd {}

const fn protocol(protocol: Protocol) -> PortMappingProtocol {
    match protocol {
        Protocol::Udp => PortMappingProtocol::UDP,
        Protocol::Tcp => PortMappingProtocol::TCP,
    }
}

/// 搜索网关设备。每次搜索发三个组播包（三种设备类型各问一次），最多搜 `timing.ssdp_searches` 次。
pub(super) async fn search(local: Ipv4Addr, ssdp: &Ssdp, timing: &Timing) -> Option<Igd> {
    for _ in 0..timing.ssdp_searches {
        let mut options = SearchOptions::default();
        // 从要映射的那个本机地址发出去，组播包才会走对网卡。
        options.bind_addr = SocketAddr::new(IpAddr::V4(local), 0);
        options.broadcast_address = ssdp.to;
        options.timeout = Some(timing.ssdp_wait);
        options.single_search_timeout = Some(timing.ssdp_wait);
        options.gateway_ip_version = GatewayIpVersion::V4;
        options.allowed_gateway_ips.clone_from(&ssdp.trusted);
        match search_gateway(options).await {
            Ok(gateway) if ssdp.only.is_none_or(|only| only == gateway.addr.ip()) => return Some(Igd { gateway }),
            Ok(gateway) => tracing::debug!(device = %gateway.addr, "响应 UPnP 搜索的设备非默认网关，已忽略"),
            Err(error) => tracing::debug!(%error, "UPnP 搜索未发现网关设备"),
        }
    }
    None
}

impl Igd {
    /// 将外部端口 `external_port` 映射到 `local`。若该端口已被其他主机占用，则由网关自动分配。
    pub(super) async fn map(&self, kind: Protocol, local: SocketAddrV4, external_port: u16, wait: Duration) -> Result<Lease, MapError> {
        let within = |what: &'static str| MapError::Upnp(format!("{what}超时"));
        let ip = tokio::time::timeout(wait, self.gateway.get_external_ip())
            .await
            .map_err(|_| within("查询公网地址"))?
            .map_err(|error| MapError::Upnp(error.to_string()))?;
        if ip.is_unspecified() {
            return Err(MapError::NoExternalAddress);
        }
        let external_port = tokio::time::timeout(wait, self.add(kind, local, external_port)).await.map_err(|_| within("添加映射"))??;
        Ok(Lease { external: SocketAddr::new(ip, external_port), lifetime: Duration::from_secs(u64::from(LEASE_SECS)) })
    }

    async fn add(&self, kind: Protocol, local: SocketAddrV4, external_port: u16) -> Result<u16, MapError> {
        let (kind, local) = (protocol(kind), SocketAddr::V4(local));
        let failed = |error: AddPortError| MapError::Upnp(error.to_string());
        match self.gateway.add_port(kind, external_port, local, LEASE_SECS, DESCRIPTION).await {
            Ok(()) => Ok(external_port),
            // 有的路由器只接受永久的映射。到期之前照样会"续"，路由器重启丢了映射时靠它补回来。
            Err(AddPortError::OnlyPermanentLeasesSupported) => {
                self.gateway.add_port(kind, external_port, local, 0, DESCRIPTION).await.map(|()| external_port).map_err(failed)
            }
            // 同一个路由器后面的另一台机器已经占了这个外部端口（两台都用默认端口的时候）：让网关另挑一个。
            Err(AddPortError::PortInUse) => match self.gateway.add_any_port(kind, local, LEASE_SECS, DESCRIPTION).await {
                Err(AddAnyPortError::OnlyPermanentLeasesSupported) => self.gateway.add_any_port(kind, local, 0, DESCRIPTION).await,
                other => other,
            }
            .map_err(|error| MapError::Upnp(error.to_string())),
            Err(error) => Err(failed(error)),
        }
    }

    pub(super) async fn unmap(&self, kind: Protocol, external_port: u16) -> Result<(), MapError> {
        self.gateway.remove_port(protocol(kind), external_port).await.map_err(|error| MapError::Upnp(error.to_string()))
    }
}
