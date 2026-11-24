//! 自动端口映射。
//!
//! 节点位于 NAT 之后时，请求路由器将公网侧端口转发至本机唯一监听端口。映射得到的公网地址可作为
//! 对端直接可达的候选端点，从而无需打洞。不同路由器支持的协议各异，因此按以下顺序依次尝试并采用首个成功的协议：
//!
//! | 协议 | 怎么说 | 在哪里 |
//! |---|---|---|
//! | PCP（RFC 6887） | 网关的 UDP 5351 端口，一问一答 | `pcp` |
//! | NAT-PMP（RFC 6886） | 同一个端口，PCP 的前身 | `natpmp` |
//! | UPnP-IGD | SSDP 组播找到网关设备，再用 HTTP 上的 SOAP | `upnp`（协议本身用 `igd-next`） |
//!
//! 映射具有租期，过半时执行续期；续期失败则视为失效，重新探测网关。节点停止时删除映射（[`PortMapper::shutdown`]）。
//! 仅映射 IPv4：IPv6 无需地址转换，防火墙放行不在本模块职责范围内。
//!
//! # 不支持的网关只花几个包
//!
//! 很多网络里这三种协议一种都没有。一次探测最多发：PCP 和 NAT-PMP 的请求各 3 个，SSDP 搜索 2 次（每次 3 个组播包）。
//! 都没有回答就不再发任何东西，直到本机的网络变了（[`PortMapper::network_changed`]）或者过了半小时。
//! 本机没有默认路由，或者朝着网关的那个地址本来就是公网地址时，一个包都不发。
//!
//! # 映射出来的地址可信吗
//!
//! 不需要可信。它只是一个候选端点，和别的候选一样要用带签名的探测验证过才会用。
//! 即使局域网内存在伪造网关，最多导致节点多上报一个不可达地址。

mod gateway;
mod natpmp;
mod pcp;
#[cfg(test)]
mod tests;
mod upnp;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

/// NAT-PMP 和 PCP 的网关都听这个端口。
const NATPMP_PCP_PORT: u16 = 5351;
/// SSDP 的组播地址。
const SSDP_MULTICAST: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
/// 向 PCP、NAT-PMP 网关申请的有效期，RFC 6886 建议的值。网关可以给得更短，以它给的为准。
const LIFETIME_SECS: u32 = 7200;
/// PCP 的报文最长 1100 字节（RFC 6887 §7）。
const MAX_REPLY_LEN: usize = 1100;
/// [`PortMapper::shutdown`] 在后台任务规定的时限之外再多等这么久，留给任务切换。
const SHUTDOWN_SLACK: Duration = Duration::from_millis(200);

/// 建 [`PortMapper`] 要的东西。
#[derive(Debug, Clone)]
pub struct PortMapConfig {
    /// 节点那个唯一的端口号：内部端口。向网关要同号的外部端口，网关给别的号也接受。
    pub port: u16,
    pub gateway: GatewaySource,
}

/// 网关在哪里。
#[derive(Debug, Clone)]
pub enum GatewaySource {
    /// 默认路由的网关，NAT-PMP / PCP 用标准端口 5351，UPnP 用标准的 SSDP 组播地址。
    System,
    /// 测试用：直接指定各协议往哪里发。没有给的协议不试。`local` 是 IPv6 地址时什么都不做。
    Fixed { local: IpAddr, natpmp_pcp: Option<SocketAddr>, ssdp: Option<SocketAddr> },
}

/// 映射出来的外部地址。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mapped {
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Udp,
    Tcp,
}

/// 网关明确地拒绝了请求。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("网关拒绝了请求，结果码 {code}")]
struct Refused {
    code: u16,
}

/// 一次映射或删除操作失败。
#[derive(Debug, thiserror::Error)]
enum MapError {
    #[error("网关无响应")]
    Silent,
    #[error(transparent)]
    Refused(#[from] Refused),
    #[error("与网关通信失败：{0}")]
    Io(#[from] io::Error),
    #[error("网关没有可用的公网地址")]
    NoExternalAddress,
    #[error("网关返回的有效期为 0")]
    ZeroLifetime,
    #[error("UPnP：{0}")]
    Upnp(String),
}

/// 网关给的一个映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lease {
    external: SocketAddr,
    /// 网关给的有效期。
    lifetime: Duration,
}

impl Lease {
    fn new(ip: IpAddr, port: u16, lifetime_secs: u32) -> Result<Self, MapError> {
        if ip.is_unspecified() {
            return Err(MapError::NoExternalAddress);
        }
        if lifetime_secs == 0 {
            return Err(MapError::ZeroLifetime);
        }
        Ok(Self { external: SocketAddr::new(ip, port), lifetime: Duration::from_secs(u64::from(lifetime_secs)) })
    }
}

/// 各种等待的时长。产品里只用 [`Timing::default`]，测试里换成短的。
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// PCP、NAT-PMP 的一个请求第一次等多久；每重发一次加倍。
    udp_first_wait: Duration,
    /// 一个请求一共发几次。
    udp_attempts: u32,
    /// 一次 SSDP 搜索等多久。设备可以拖到 3 秒才回答（请求里的 MX）。
    ssdp_wait: Duration,
    ssdp_searches: u32,
    /// UPnP 的一个 HTTP 请求等多久。
    http_wait: Duration,
    /// 探测不到任何协议之后隔多久再试。
    retry: Duration,
    /// 两次续期至少隔这么久，免得给了极短有效期的网关被问个不停。
    min_renew: Duration,
    /// 停止时删映射最多花多久。
    release_wait: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            udp_first_wait: Duration::from_millis(250),
            udp_attempts: 3,
            ssdp_wait: Duration::from_millis(3500),
            ssdp_searches: 2,
            http_wait: Duration::from_secs(5),
            retry: Duration::from_secs(30 * 60),
            min_renew: Duration::from_secs(5),
            release_wait: Duration::from_millis(1500),
        }
    }
}

/// 这一次探测往哪里发、映射到本机的哪个地址。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    local: Ipv4Addr,
    /// NAT-PMP 和 PCP 的网关地址。
    udp: Option<SocketAddr>,
    ssdp: Option<upnp::Ssdp>,
}

impl Target {
    /// 默认路由是 `route` 时往哪里发：各协议都用标准的端口和地址。本机朝着网关的地址不在地址转换后面时返回 `None`。
    fn behind(route: gateway::DefaultRoute) -> Option<Self> {
        if !gateway::needs_mapping(route.local) {
            tracing::debug!(local = %route.local, "默认路由本地地址不在 NAT 之后，跳过端口映射");
            return None;
        }
        let gateway = IpAddr::V4(route.gateway);
        Some(Self {
            local: route.local,
            udp: Some(SocketAddr::new(gateway, NATPMP_PCP_PORT)),
            ssdp: Some(upnp::Ssdp { to: SSDP_MULTICAST, only: Some(gateway), trusted: Vec::new() }),
        })
    }
}

/// 映射是用哪种协议、在哪个网关上做的。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Via {
    Pcp(SocketAddr),
    NatPmp(SocketAddr),
    Upnp(upnp::Igd),
}

impl Via {
    const fn name(&self) -> &'static str {
        match self {
            Self::Pcp(_) => "PCP",
            Self::NatPmp(_) => "NAT-PMP",
            Self::Upnp(_) => "UPnP",
        }
    }
}

/// 现在有效的映射。
#[derive(Debug)]
struct Active {
    target: Target,
    via: Via,
    udp: Lease,
    tcp: Option<Lease>,
    renew_at: Instant,
}

/// 到网关 5351 端口的一问一答，PCP 和 NAT-PMP 共用。
#[derive(Debug, Clone, Copy)]
struct UdpGateway {
    local: Ipv4Addr,
    addr: SocketAddr,
    first_wait: Duration,
    attempts: u32,
}

impl UdpGateway {
    /// 发 `request`，等到 `accept` 认出回答为止；没有回答就重发，每次等的时间加倍。
    async fn exchange<T>(&self, request: &[u8], accept: impl Fn(&[u8]) -> Option<Result<T, Refused>>) -> Result<T, MapError> {
        // 每个请求用一个新的、只和网关通信的 socket：别的地址来的包内核不会交上来。
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(self.local), 0)).await?;
        socket.connect(self.addr).await?;
        let mut buf = [0u8; MAX_REPLY_LEN];
        let mut wait = self.first_wait;
        for _ in 0..self.attempts {
            socket.send(request).await?;
            let deadline = Instant::now() + wait;
            // 时限之内可能先到一个不相干的包（别的请求迟到的回答），接着等。
            while let Ok(received) = tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                // 网关上没有人听这个端口时，内核把"端口不可达"报在这里：不用再重发了。
                if let Some(answer) = accept(&buf[..received?]) {
                    return Ok(answer?);
                }
            }
            wait *= 2;
        }
        Err(MapError::Silent)
    }
}

enum Command {
    SetTcp(bool),
    NetworkChanged,
    Shutdown(oneshot::Sender<()>),
}

/// 自动端口映射。
///
/// 后台任务找网关、申请映射、到期之前续；这个值是它的把手。映射出来的地址用 [`mapped`](Self::mapped) 读，
/// 或者用 [`subscribe`](Self::subscribe) 等变化。
///
/// 停止节点时调用 [`shutdown`](Self::shutdown)，映射才保证被删掉。直接丢弃这个值时后台任务也会去删，
/// 但那是尽力而为：运行时紧接着就关掉的话来不及，映射要等有效期到了才消失。
#[derive(Debug)]
pub struct PortMapper {
    mapped: watch::Receiver<Mapped>,
    commands: mpsc::UnboundedSender<Command>,
    release_wait: Duration,
}

impl PortMapper {
    /// 启动后台任务（要在 tokio 运行时里调用）。先只映射 UDP。
    #[must_use]
    pub fn spawn(config: PortMapConfig) -> Self {
        Self::spawn_with(config, Timing::default())
    }

    fn spawn_with(config: PortMapConfig, timing: Timing) -> Self {
        let (mapped_tx, mapped) = watch::channel(Mapped::default());
        let (commands, inbox) = mpsc::unbounded_channel();
        let worker = Worker {
            config,
            timing,
            nonces: [crate::random_bytes(), crate::random_bytes()],
            mapped: mapped_tx,
            want_tcp: false,
            active: None,
        };
        tokio::spawn(worker.run(inbox));
        Self { mapped, commands, release_wait: timing.release_wait }
    }

    /// 现在的映射。
    #[must_use]
    pub fn mapped(&self) -> Mapped {
        *self.mapped.borrow()
    }

    /// 订阅变化。
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Mapped> {
        self.mapped.clone()
    }

    /// 节点启用或者停用了 relay：要不要同时映射同号的 TCP 端口。
    pub fn set_tcp(&self, wanted: bool) {
        self.send(Command::SetTcp(wanted));
    }

    /// 本机的网卡地址变了：网关可能换了，重新探测。网关和本机地址其实都没变时只是提前续一次。
    pub fn network_changed(&self) {
        self.send(Command::NetworkChanged);
    }

    /// 删掉映射再停下。最多等一两秒：网关迟迟不确认的话不再等，映射会在有效期到了之后自己消失。
    pub async fn shutdown(self) {
        let (done, finished) = oneshot::channel();
        self.send(Command::Shutdown(done));
        // 后台任务已经没了的话 `finished` 立刻出错返回，同样不用等。
        if tokio::time::timeout(self.release_wait + SHUTDOWN_SLACK, finished).await.is_err() {
            tracing::warn!("未能在关闭超时前删除端口映射（后台任务正忙），映射将在有效期届满后自动失效");
        }
    }

    fn send(&self, command: Command) {
        // 发不出去说明后台任务已经结束（运行时在关闭），这时这些命令也没有意义了。
        let _stopped = self.commands.send(command);
    }
}

struct Worker {
    config: PortMapConfig,
    timing: Timing,
    /// PCP 里两个映射各自的随机数（UDP、TCP）。整个生命期里不换：续期、换网络之后重新申请、删除都要带原来的那个。
    nonces: [pcp::Nonce; 2],
    mapped: watch::Sender<Mapped>,
    want_tcp: bool,
    active: Option<Active>,
}

impl Worker {
    async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        let mut probe_at = Instant::now();
        loop {
            let wake_at = self.active.as_ref().map_or(probe_at, |active| active.renew_at);
            tokio::select! {
                command = commands.recv() => match command {
                    Some(Command::SetTcp(wanted)) => self.set_tcp(wanted).await,
                    Some(Command::NetworkChanged) => {
                        if self.network_changed().await {
                            probe_at = Instant::now();
                        }
                    }
                    Some(Command::Shutdown(done)) => {
                        self.release().await;
                        // 调用方等得不耐烦已经走了的话，没有人要这个通知。
                        let _waiting = done.send(());
                        return;
                    }
                    // 把手被丢弃了：尽力把映射删掉。
                    None => return self.release().await,
                },
                () = tokio::time::sleep_until(wake_at) => {
                    if !self.renew().await {
                        self.probe().await;
                        probe_at = Instant::now() + self.timing.retry;
                    }
                }
            }
        }
    }

    /// 找网关并申请映射，把结果公布出去。
    async fn probe(&mut self) {
        self.active = None;
        if let Some(target) = self.resolve().await {
            match self.find_gateway(&target).await {
                Some((via, udp)) => {
                    let lifetime_secs = udp.lifetime.as_secs();
                    tracing::info!(protocol = via.name(), external = %udp.external, lifetime_secs, "端口映射成功（UDP）");
                    let mut active = Active { target, via, udp, tcp: None, renew_at: Instant::now() };
                    if self.want_tcp {
                        active.tcp = self.map_tcp(&active).await;
                    }
                    active.renew_at = self.next_renewal(&active);
                    self.active = Some(active);
                }
                None => tracing::debug!(local = %target.local, "网关不支持 PCP、NAT-PMP 和 UPnP，或所有协议申请均失败；将在下次间隔后重试"),
            }
        }
        self.publish();
    }

    /// 这一次探测往哪里发。没有可映射的地址时返回 `None`，这时一个包都不发。
    async fn resolve(&self) -> Option<Target> {
        match &self.config.gateway {
            GatewaySource::System => {
                // 任务被取消或者 panic 了都当作"没有默认路由"。
                let route = tokio::task::spawn_blocking(gateway::default_route).await.ok().flatten()?;
                Target::behind(route)
            }
            GatewaySource::Fixed { local: IpAddr::V4(local), natpmp_pcp, ssdp } => {
                let ssdp = ssdp.map(|to| upnp::Ssdp { to, only: None, trusted: vec![to.ip()] });
                Some(Target { local: *local, udp: *natpmp_pcp, ssdp })
            }
            GatewaySource::Fixed { local: IpAddr::V6(_), .. } => None,
        }
    }

    /// 三种协议里取第一个成的。UPnP 的搜索和前两种同时进行（它慢，而且只是找设备，不改网关的状态），
    /// 前两种有一个成了就不再等它。
    async fn find_gateway(&self, target: &Target) -> Option<(Via, Lease)> {
        let search = async {
            match &target.ssdp {
                Some(ssdp) => upnp::search(target.local, ssdp, &self.timing).await,
                None => None,
            }
        };
        let quick = self.try_udp_protocols(target);
        tokio::pin!(search, quick);
        // 外层的 `None` 表示搜索还没有结束。
        let mut searched: Option<Option<upnp::Igd>> = None;
        let mapped = loop {
            tokio::select! {
                biased;
                mapped = &mut quick => break mapped,
                found = &mut search, if searched.is_none() => searched = Some(found),
            }
        };
        if mapped.is_some() {
            return mapped;
        }
        let igd = match searched {
            Some(found) => found,
            None => search.await,
        }?;
        let via = Via::Upnp(igd);
        match self.map(&via, target.local, Protocol::Udp, self.config.port).await {
            Ok(lease) => Some((via, lease)),
            Err(error) => {
                tracing::debug!(%error, "UPnP UDP 端口映射申请失败");
                None
            }
        }
    }

    async fn try_udp_protocols(&self, target: &Target) -> Option<(Via, Lease)> {
        let gateway = target.udp?;
        for via in [Via::Pcp(gateway), Via::NatPmp(gateway)] {
            match self.map(&via, target.local, Protocol::Udp, self.config.port).await {
                Ok(lease) => return Some((via, lease)),
                Err(error) => tracing::debug!(protocol = via.name(), %gateway, %error, "通过当前协议申请 UDP 端口映射失败"),
            }
        }
        None
    }

    const fn nonce(&self, protocol: Protocol) -> pcp::Nonce {
        match protocol {
            Protocol::Udp => self.nonces[0],
            Protocol::Tcp => self.nonces[1],
        }
    }

    const fn udp_gateway(&self, local: Ipv4Addr, addr: SocketAddr) -> UdpGateway {
        UdpGateway { local, addr, first_wait: self.timing.udp_first_wait, attempts: self.timing.udp_attempts }
    }

    fn pcp_request(&self, protocol: Protocol, client: Ipv4Addr, external_port: u16, lifetime_secs: u32) -> pcp::MapRequest {
        pcp::MapRequest { nonce: self.nonce(protocol), protocol, client, internal_port: self.config.port, external_port, lifetime_secs }
    }

    /// 申请或者续一个映射，希望的外部端口是 `external_port`。
    async fn map(&self, via: &Via, local: Ipv4Addr, protocol: Protocol, external_port: u16) -> Result<Lease, MapError> {
        let port = self.config.port;
        match via {
            Via::Pcp(gateway) => {
                let request = self.pcp_request(protocol, local, external_port, LIFETIME_SECS);
                let granted = self.udp_gateway(local, *gateway).exchange(&request.to_bytes(), |reply| request.parse_reply(reply)).await?;
                Lease::new(granted.external_ip, granted.external_port, granted.lifetime_secs)
            }
            Via::NatPmp(gateway) => {
                let gateway = self.udp_gateway(local, *gateway);
                // 公网地址每次都重新问：拨号重连之后它会变，而这个协议的映射回答里不带地址。
                let ip = gateway.exchange(&natpmp::address_request(), natpmp::parse_address_reply).await?;
                if ip.is_unspecified() {
                    return Err(MapError::NoExternalAddress);
                }
                let request = natpmp::map_request(protocol, port, external_port, LIFETIME_SECS);
                let granted = gateway.exchange(&request, |reply| natpmp::parse_map_reply(reply, protocol, port)).await?;
                Lease::new(IpAddr::V4(ip), granted.external_port, granted.lifetime_secs)
            }
            Via::Upnp(igd) => igd.map(protocol, SocketAddrV4::new(local, port), external_port, self.timing.http_wait).await,
        }
    }

    async fn unmap(&self, via: &Via, local: Ipv4Addr, protocol: Protocol, lease: &Lease) -> Result<(), MapError> {
        let port = self.config.port;
        match via {
            Via::Pcp(gateway) => {
                let request = self.pcp_request(protocol, local, 0, 0);
                self.udp_gateway(local, *gateway).exchange(&request.to_bytes(), |reply| request.parse_reply(reply)).await.map(|_| ())
            }
            Via::NatPmp(gateway) => {
                let request = natpmp::map_request(protocol, port, 0, 0);
                self.udp_gateway(local, *gateway)
                    .exchange(&request, |reply| natpmp::parse_map_reply(reply, protocol, port))
                    .await
                    .map(|_| ())
            }
            Via::Upnp(igd) => igd.unmap(protocol, lease.external.port()).await,
        }
    }

    async fn map_tcp(&self, active: &Active) -> Option<Lease> {
        let external_port = active.tcp.map_or(self.config.port, |lease| lease.external.port());
        match self.map(&active.via, active.target.local, Protocol::Tcp, external_port).await {
            Ok(lease) => {
                if active.tcp.is_none_or(|previous| previous.external != lease.external) {
                    let lifetime_secs = lease.lifetime.as_secs();
                    tracing::info!(protocol = active.via.name(), external = %lease.external, lifetime_secs, "端口映射成功（TCP）");
                }
                Some(lease)
            }
            Err(error) => {
                tracing::warn!(protocol = active.via.name(), %error, "TCP 端口映射失败，将在下次 UDP 映射续期时重试");
                None
            }
        }
    }

    /// 映射的有效期过一半时续。
    fn next_renewal(&self, active: &Active) -> Instant {
        let shortest = active.tcp.map_or(active.udp.lifetime, |tcp| tcp.lifetime.min(active.udp.lifetime));
        Instant::now() + (shortest / 2).max(self.timing.min_renew)
    }

    /// 续期。返回映射还在不在；不在的话调用方要重新探测。
    async fn renew(&mut self) -> bool {
        let Some(mut active) = self.active.take() else { return false };
        match self.map(&active.via, active.target.local, Protocol::Udp, active.udp.external.port()).await {
            Ok(lease) => {
                if lease.external != active.udp.external {
                    tracing::info!(protocol = active.via.name(), external = %lease.external, "UDP 端口映射的外部地址已变更");
                }
                active.udp = lease;
            }
            Err(error) => {
                tracing::warn!(protocol = active.via.name(), %error, "UDP 端口映射续期失败，撤下已发布地址并重新探测网关");
                // 先把地址撤下来再去探测：探测要花几秒，这期间别人不该再拿它当候选。
                self.publish();
                return false;
            }
        }
        if self.want_tcp {
            active.tcp = self.map_tcp(&active).await;
        }
        active.renew_at = self.next_renewal(&active);
        self.active = Some(active);
        self.publish();
        true
    }

    async fn set_tcp(&mut self, wanted: bool) {
        self.want_tcp = wanted;
        let Some(mut active) = self.active.take() else { return };
        match (wanted, active.tcp) {
            (true, None) => active.tcp = self.map_tcp(&active).await,
            (false, Some(lease)) => {
                match self.unmap(&active.via, active.target.local, Protocol::Tcp, &lease).await {
                    Ok(()) => tracing::info!(protocol = active.via.name(), external = %lease.external, "TCP 端口映射已删除"),
                    Err(error) => {
                        tracing::warn!(protocol = active.via.name(), %error, "删除 TCP 端口映射失败，映射将在有效期届满后自动失效")
                    }
                }
                active.tcp = None;
            }
            (true, Some(_)) | (false, None) => {}
        }
        self.active = Some(active);
        self.publish();
    }

    /// 本机的网络变了。返回要不要马上重新探测。
    async fn network_changed(&mut self) -> bool {
        let target = self.resolve().await;
        match &mut self.active {
            // 网关和本机地址都没变：映射多半还在，提前续一次确认。
            Some(active) if target.as_ref() == Some(&active.target) => {
                active.renew_at = Instant::now();
                false
            }
            // 原映射位于旧网络中，无法从新地址访问或删除，等待其自然过期。已发布地址待重新探测完成后统一更新。
            active @ (Some(_) | None) => {
                *active = None;
                true
            }
        }
    }

    /// 把做过的映射都删掉。
    async fn release(&mut self) {
        let Some(active) = self.active.take() else { return };
        let (via, local) = (&active.via, active.target.local);
        let removal = async {
            let udp = self.unmap(via, local, Protocol::Udp, &active.udp);
            let tcp = async {
                match &active.tcp {
                    Some(lease) => self.unmap(via, local, Protocol::Tcp, lease).await,
                    None => Ok(()),
                }
            };
            let (udp, tcp) = tokio::join!(udp, tcp);
            udp.and(tcp)
        };
        match tokio::time::timeout(self.timing.release_wait, removal).await {
            Ok(Ok(())) => tracing::info!(protocol = via.name(), "端口映射已删除"),
            Ok(Err(error)) => tracing::warn!(protocol = via.name(), %error, "删除端口映射失败，映射将在有效期届满后自动失效"),
            Err(_) => tracing::warn!(protocol = via.name(), "等待网关确认删除端口映射超时，映射将在有效期届满后自动失效"),
        }
        self.publish();
    }

    fn publish(&self) {
        let mapped = self
            .active
            .as_ref()
            .map_or_else(Mapped::default, |active| Mapped { udp: Some(active.udp.external), tcp: active.tcp.map(|lease| lease.external) });
        self.mapped.send_if_modified(|current| std::mem::replace(current, mapped) != mapped);
    }
}
