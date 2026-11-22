//! 出站：检查策略、解析域名、连接目标。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use i3t_model::Netmap;
use i3t_model::control::exit_test::{ConnectStep, ExitTestCause, ExitTestResult, ExitVia, ResolveStep};
use i3t_model::netmap::{ExitRole, IpFamily, Network};
use i3t_proto::NodeId;
use i3t_proto::flow::{Host, Reply, Status};
use ipnet::IpNet;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time;

use crate::dns_cache::{self, DnsCache};
use crate::system::{Os, ResolveError, System};
use crate::{policy, upstream};

/// 连一个地址最多等多久。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 连本机自己的地址最多等多久。本机不会丢包，等不到就是没有。
///
/// 要比 Windows 报出"被拒绝"的时间长：那里连一个没有人监听的端口，收到 RST 之后还会重发 SYN，两秒左右才报错。
/// 时限比这短的话，关着的端口在 Windows 上报成超时（客户端看到"主机不可达"），而不是"连接被拒绝"。
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// 解析一个域名最多等多久。
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// 一个域名最多取几个地址。它们会被挨个尝试，每个都可能等满 [`CONNECT_TIMEOUT`]，所以要有上限。
const MAX_ADDRESSES: usize = 8;

/// 网卡的地址列表缓存多久。每条流都要用它，而它很少变。
const INTERFACES_TTL: Duration = Duration::from_secs(5);

/// 同时在进行的域名解析最多多少个。
///
/// 系统的解析器是阻塞的：每个解析占一个阻塞线程，直到解析器自己返回为止，调用者超时走了也停不下来（glibc 最长要三十秒左右）。
/// tokio 的阻塞线程池一共 512 个线程，别的阻塞操作也要用。没有上限的话，一个节点拿权威服务器不回应的随机子域名不停地发请求，
/// 每秒几十个就能把线程池占满。正常的解析几十毫秒就回来，加上缓存，同时在解析的很少超过十几个。
const MAX_LOOKUPS: usize = 64;

/// 其中一个请求方（一个发起节点，或者本机的出口测试）最多同时占多少个。一个节点刷解析时只占满它自己的这一份，
/// 别的节点和本机照常解析。浏览器一下子打开几十个域名时多出来的排一会儿队，每个只等几十毫秒。
const MAX_LOOKUPS_PER_ASKER: usize = 16;

/// 出站的拨号器。出口处理别人的流和出口测试都用它，所以两者是同一份出站策略、同一个解析缓存。克隆出来的是同一个。
pub struct Outbound<S = Os> {
    inner: Arc<Inner<S>>,
}

/// 本节点自己对外的地址从哪里问，见 [`Outbound::with_own_endpoints`]。
type OwnEndpoints = Box<dyn Fn() -> Vec<SocketAddr> + Send + Sync>;

struct Inner<S> {
    system: S,
    netmap: watch::Receiver<Arc<Netmap>>,
    dns: Mutex<DnsCache>,
    interfaces: Mutex<Option<Interfaces>>,
    own_endpoints: Option<OwnEndpoints>,
    lookups: Lookups,
}

/// 一次连接经什么出去。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via {
    Direct,
    /// 出口配的上游 SOCKS5 代理。
    Upstream(SocketAddr),
}

/// 谁要解析域名。同时进行的解析按它分开限额。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Asker {
    /// 一个发起节点：出口替它连互联网目标。
    Peer(NodeId),
    /// 本机：出口测试。
    Local,
}

/// 同时进行的域名解析的名额：总共 [`MAX_LOOKUPS`] 个，每个请求方最多 [`MAX_LOOKUPS_PER_ASKER`] 个。
#[derive(Debug)]
struct Lookups {
    total: Arc<Semaphore>,
    per_asker: Mutex<HashMap<Asker, Arc<Semaphore>>>,
}

impl Default for Lookups {
    fn default() -> Self {
        Self { total: Arc::new(Semaphore::new(MAX_LOOKUPS)), per_asker: Mutex::default() }
    }
}

/// 一个解析占着的两份名额。
struct LookupPermits {
    _own: OwnedSemaphorePermit,
    _total: OwnedSemaphorePermit,
}

impl Lookups {
    /// 等到 `asker` 自己的名额和总的名额都有空。先占自己的再占总的：一个请求方排队时不占着总的名额。
    async fn acquire(&self, asker: Asker) -> LookupPermits {
        let own = {
            let mut per_asker = self.per_asker.lock().expect("lookup limit mutex poisoned");
            // 没有解析在进行的请求方不留记录：节点会从 netmap 里消失。
            // 有解析在进行或者在排队的，别处还拿着它的克隆（占着的名额也拿着一个）。
            per_asker.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
            Arc::clone(per_asker.entry(asker).or_insert_with(|| Arc::new(Semaphore::new(MAX_LOOKUPS_PER_ASKER))))
        };
        let own = own.acquire_owned().await.expect("lookup semaphores are never closed");
        let total = Arc::clone(&self.total).acquire_owned().await.expect("lookup semaphores are never closed");
        LookupPermits { _own: own, _total: total }
    }
}

struct Interfaces {
    read_at: Instant,
    nets: Arc<[IpNet]>,
}

impl<S> Clone for Outbound<S> {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

impl<S> std::fmt::Debug for Outbound<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound").finish_non_exhaustive()
    }
}

impl<S: System> Outbound<S> {
    /// `netmap` 是本节点当前的那一份：查覆盖网的地址段、出口测试时用，那时没有别人给出该按哪一版配置判断。
    pub fn new(netmap: watch::Receiver<Arc<Netmap>>, system: S) -> Self {
        let inner =
            Inner { system, netmap, dns: Mutex::default(), interfaces: Mutex::new(None), own_endpoints: None, lookups: Lookups::default() };
        Self { inner: Arc::new(inner) }
    }

    /// 本节点自己对外的地址从哪里问：装配时交进来数据面报给 controller 的候选端点（`Endpoint::endpoints`），
    /// 里面有路由器上映射出来的地址、relay 和地址查询服务器看到的反射地址。
    ///
    /// 出口不把这些地址当互联网目标去连：家用路由器常常把从局域网连向它自己公网地址的连接交给它的管理页面，
    /// 放行了就绕过了局域网开关。netmap 里别的节点和 relay 的地址同样不连。
    /// 不设时只排除 netmap 里的那些。
    ///
    /// # Panics
    ///
    /// 在克隆之后调用：克隆出来的是同一个拨号器，这个设置要在交出去之前定下来。
    #[must_use]
    pub fn with_own_endpoints(mut self, own: impl Fn() -> Vec<SocketAddr> + Send + Sync + 'static) -> Self {
        Arc::get_mut(&mut self.inner).expect("with_own_endpoints 要在克隆拨号器之前调用").own_endpoints = Some(Box::new(own));
        self
    }

    /// 互联网目标：本节点必须是出口，端口要在允许的范围里，解析出来的每一个地址都要过出站策略。
    pub(crate) async fn internet(&self, netmap: &Netmap, host: &Host, port: u16, asker: Asker) -> Result<TcpStream, Reply> {
        let (role, targets) = self.internet_targets(netmap, host, port, asker).await?;
        self.connect_first(targets, CONNECT_TIMEOUT, role.upstream_socks5.map_or(Via::Direct, Via::Upstream)).await
    }

    /// 互联网目标的检查。通过的话返回可以去连的地址，流和数据报用的是同一份检查。
    async fn internet_targets<'n>(
        &self,
        netmap: &'n Netmap,
        host: &Host,
        port: u16,
        asker: Asker,
    ) -> Result<(&'n ExitRole, Vec<SocketAddr>), Reply> {
        let role = internet_role(netmap, port)?;
        let resolved = self.resolve(host, asker).await?;
        let addresses = self.admissible(netmap, role, &resolved)?;
        Ok((role, addresses.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()))
    }

    /// 解析出来的地址里出口会去连的那些：先按地址族挑，再一个个过出站策略。
    fn admissible(&self, netmap: &Netmap, role: &ExitRole, resolved: &[IpAddr]) -> Result<Vec<IpAddr>, Stop> {
        // 出口只连某一种地址时，先按地址族挑：另一种地址根本不会去连，也就不用为它拒绝整个请求。
        let addresses: Vec<IpAddr> = resolved.iter().copied().filter(|&ip| role.family.admits(ip)).collect();
        if addresses.is_empty() {
            return Err(Stop::FamilyUnavailable(role.family));
        }
        // 域名可以解析到任何地方，所以要看解析之后的地址；只要有一个不该连，整个请求都拒绝，
        // 不然对方可以把一个内网地址夹在几个公网地址中间碰运气。
        let interfaces = self.interfaces()?;
        let nodes = self.node_addresses(netmap);
        if let Some((ip, what)) =
            addresses.iter().find_map(|&ip| forbidden_as_internet(&netmap.network, &interfaces, &nodes, ip).map(|what| (ip, what)))
        {
            return Err(Stop::Forbidden { ip, what });
        }
        Ok(addresses)
    }

    /// 网络里节点自己的地址：本节点的候选端点（含反射地址、端口映射拿到的地址），netmap 里各个对端报上来的端点，
    /// 各个 relay 的地址。只比 IP 不比端口：同一个 IP 上别的端口一样是那台机器（或者它前面的路由器）。
    fn node_addresses(&self, netmap: &Netmap) -> Vec<IpAddr> {
        let own = self.inner.own_endpoints.as_ref().map(|own| own()).unwrap_or_default();
        let peers = netmap.peers.iter().flat_map(|peer| &peer.endpoints);
        let relays = netmap.relays.iter().flat_map(|relay| relay.udp.iter().chain(&relay.tcp));
        own.iter().chain(peers).chain(relays).map(|addr| addr.ip().to_canonical()).collect()
    }

    /// 互联网目标的 UDP 报文该发到哪个地址。检查和流的一样；域名取解析出来的第一个地址。
    ///
    /// 配了上游代理的出口不替别人发 UDP：上游代理只承载 TCP，绕过它直接发就违背了"都经上游出去"的本意。
    pub(crate) async fn udp_internet(&self, netmap: &Netmap, host: &Host, port: u16, asker: Asker) -> Result<SocketAddr, Reply> {
        let (role, targets) = self.internet_targets(netmap, host, port, asker).await?;
        if role.upstream_socks5.is_some() {
            return Err(Reply::new(Status::NotEnabled, "这个出口经上游代理出站，上游代理不承载 UDP"));
        }
        targets.first().copied().ok_or_else(|| Reply::new(Status::Unreachable, "没有可以发的地址"))
    }

    /// 局域网目标：本节点必须是出口并且打开了局域网开关，地址必须在本机某块网卡直连的网段里。端口不受限制。
    pub(crate) async fn lan(&self, netmap: &Netmap, addr: SocketAddr) -> Result<TcpStream, Reply> {
        let target = self.lan_target(netmap, addr)?;
        self.connect_first([target], CONNECT_TIMEOUT, Via::Direct).await
    }

    /// 局域网目标的检查。通过的话返回可以去连的地址，流和数据报用的是同一份检查。
    pub(crate) fn lan_target(&self, netmap: &Netmap, addr: SocketAddr) -> Result<SocketAddr, Reply> {
        Ok(self.lan_check(netmap, addr)?)
    }

    fn lan_check(&self, netmap: &Netmap, addr: SocketAddr) -> Result<SocketAddr, Stop> {
        match &netmap.me.exit {
            None => return Err(Stop::NotEnabled),
            Some(ExitRole { lan: false, .. }) => return Err(Stop::LanNotEnabled),
            Some(ExitRole { lan: true, .. }) => {}
        }
        let ip = addr.ip().to_canonical();
        let attached = self.interfaces()?.iter().any(|net| !net.addr().is_loopback() && subnet_contains(net, ip));
        let refused = if ip.is_loopback() || policy::is_link_local(ip) || policy::is_cloud_metadata(ip) {
            Some("回环、链路本地和云平台的元数据地址不算局域网")
        } else if netmap.network.is_overlay_address(ip) {
            Some("覆盖网的地址不算局域网")
        } else if !attached {
            Some("目标不在本机网卡直连的网段里")
        } else {
            None
        };
        match refused {
            Some(why) => Err(Stop::NotOnLan { ip, why }),
            None => Ok(SocketAddr::new(ip, addr.port())),
        }
    }

    /// 出口测试（`i3tctl exit test`）：按替别人连这个目标时的同一套规矩试着连 `host:port`，记下每一步花了多久、
    /// 停在了哪里。写成字面量的私有地址按局域网目标查（和入口分的一样），别的按互联网目标查：不是出口、端口不允许、
    /// 解析出来的地址不能连，拒绝的原因和别人经这个出口访问时一样。
    ///
    /// 和替别人连时不同的只有两处：解析不用缓存里的结果（要量它花了多久），每一步最多 [`PROBE_STEP`]。
    /// 连上了的话连接交给调用方（TLS 握手在装配层做）。一次一个、隔多久做一次由调用方管。
    pub async fn probe(&self, host: &Host, port: u16) -> Probe {
        let netmap = Arc::clone(&self.inner.netmap.borrow());
        let upstream = netmap.me.exit.as_ref().and_then(|role| role.upstream_socks5);
        let mut result = ExitTestResult {
            via: if upstream.is_some() { ExitVia::Upstream } else { ExitVia::Direct },
            refused: None,
            resolve: None,
            connect: None,
            tls: None,
        };
        let lan = match host {
            Host::Ip(ip) if i3t_access::is_lan_literal(*ip) => Some(SocketAddr::new(*ip, port)),
            Host::Ip(_) | Host::Name(_) => None,
        };
        let (targets, via) = match lan {
            // 局域网目标不经上游代理（[`Outbound::lan`]）。
            Some(addr) => match self.lan_check(&netmap, addr) {
                Ok(target) => {
                    result.via = ExitVia::Direct;
                    (vec![target], Via::Direct)
                }
                Err(stop) => return Probe::refused(result, &stop),
            },
            None => {
                let role = match internet_role(&netmap, port) {
                    Ok(role) => role,
                    Err(stop) => return Probe::refused(result, &stop),
                };
                let started = Instant::now();
                let resolved = self.resolve_with(host, Asker::Local, Cache::Bypass, PROBE_STEP).await;
                if matches!(host, Host::Name(_)) {
                    result.resolve = Some(ResolveStep {
                        ms: millis(started.elapsed()),
                        addresses: resolved.clone().unwrap_or_default(),
                        family: role.family,
                        cause: resolved.as_ref().err().filter(|stop| stop.is_resolution()).map(Stop::cause),
                    });
                }
                let admitted = resolved.and_then(|resolved| self.admissible(&netmap, role, &resolved));
                match admitted {
                    Ok(addresses) => {
                        (addresses.into_iter().map(|ip| SocketAddr::new(ip, port)).collect(), upstream.map_or(Via::Direct, Via::Upstream))
                    }
                    Err(stop) if stop.is_resolution() => return Probe { result, stream: None },
                    Err(stop) => return Probe::refused(result, &stop),
                }
            }
        };

        let started = Instant::now();
        let deadline = started + PROBE_STEP;
        let mut last = None;
        for target in targets {
            let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()) else { break };
            let cause = match time::timeout(left, self.connect_one(target, via)).await {
                Ok(Ok(stream)) => {
                    tune(&stream);
                    result.connect = Some(ConnectStep { ms: millis(started.elapsed()), address: Some(target), cause: None });
                    return Probe { result, stream: Some(stream) };
                }
                Ok(Err(reply)) => connect_cause(reply.status, via),
                Err(_) => ExitTestCause::Timeout,
            };
            // 几个地址都连不上时报最说明问题的那个，和替别人连时一样。
            if last.is_none_or(|kept| cause_rank(cause) > cause_rank(kept)) {
                last = Some(cause);
            }
        }
        result.connect =
            Some(ConnectStep { ms: millis(started.elapsed()), address: None, cause: Some(last.unwrap_or(ExitTestCause::Timeout)) });
        Probe { result, stream: None }
    }

    /// 本节点自己的服务：只用本机的非回环地址去连。
    ///
    /// 所以只监听 127.0.0.1 的服务连不上，不会因为装了这个程序就对组网可见；要暴露这样的服务得显式配端口转发。
    /// 本机有几个地址就挨个试：服务可能只监听在其中一个上。
    pub(crate) async fn node_port(&self, port: u16) -> Result<TcpStream, Reply> {
        let targets = self.node_targets(port)?;
        self.connect_first(targets, LOCAL_CONNECT_TIMEOUT, Via::Direct).await
    }

    /// 本机的非回环地址加上 `port`，IPv4 在前：只监听 0.0.0.0 的服务最常见。
    fn node_targets(&self, port: u16) -> Result<Vec<SocketAddr>, Reply> {
        let interfaces = self.interfaces()?;
        let own = interfaces.iter().map(IpNet::addr).filter(|ip| !(ip.is_loopback() || ip.is_unspecified() || policy::is_link_local(*ip)));
        let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = own.partition(IpAddr::is_ipv4);
        let targets: Vec<SocketAddr> = v4.into_iter().chain(v6).map(|ip| SocketAddr::new(ip, port)).collect();
        if targets.is_empty() {
            return Err(Reply::new(Status::Unreachable, "这个节点没有非回环的地址，它上面的服务不可达"));
        }
        Ok(targets)
    }

    /// 本节点自己的服务的 UDP 报文该发到哪个地址：本机的第一个非回环地址。
    ///
    /// TCP 可以挨个地址去试哪个连得上，UDP 没有"连上"这回事，试不了；只监听在别的地址上的服务要配端口转发。
    pub(crate) fn udp_node(&self, port: u16) -> Result<SocketAddr, Reply> {
        let targets = self.node_targets(port)?;
        targets.first().copied().ok_or_else(|| Reply::new(Status::Unreachable, "这个节点没有非回环的地址"))
    }

    /// 发往 `addr` 的 UDP 报文实际发到哪个地址，见 [`System::udp_route`]。
    pub(crate) fn udp_route(&self, addr: SocketAddr) -> SocketAddr {
        self.inner.system.udp_route(addr)
    }

    /// 端口转发指向的地址。回环地址和局域网地址都可以：下发给本节点的端口转发就是访问它们的显式途径。
    /// 覆盖网的地址不连（[`Outbound::not_overlay`]）。
    pub(crate) async fn forward(&self, addr: SocketAddr) -> Result<TcpStream, Reply> {
        self.not_overlay(addr)?;
        self.connect_first([addr], CONNECT_TIMEOUT, Via::Direct).await
    }

    /// 本节点自己去连的地址不能是覆盖网的地址：那些地址只在组网里有意义，到它们的连接是到那个节点开的流。
    /// 端口转发写了这样的地址、或者一个域名解析成了这样的地址时直接拒绝，不当作普通的地址去连：
    /// 虚拟网卡装着的时候，那样的连接会经网卡绕回组网里，替别人连的就成了以本节点的身份访问别的节点。
    pub(crate) fn not_overlay(&self, addr: SocketAddr) -> Result<(), Reply> {
        if self.inner.netmap.borrow().network.is_overlay_address(addr.ip().to_canonical()) {
            return Err(Reply::new(Status::PolicyDenied, "目标是覆盖网的地址：要访问那个节点，开到它的流"));
        }
        Ok(())
    }

    /// 域名对应的地址，最多 [`MAX_ADDRESSES`] 个。本来就是地址的不用解析。
    ///
    /// 等解析的名额（[`MAX_LOOKUPS`]、[`MAX_LOOKUPS_PER_ASKER`]）也算在 [`RESOLVE_TIMEOUT`] 里。
    async fn resolve(&self, host: &Host, asker: Asker) -> Result<Vec<IpAddr>, Reply> {
        Ok(self.resolve_with(host, asker, Cache::Use, RESOLVE_TIMEOUT).await?)
    }

    /// 同 [`resolve`](Self::resolve)。`cache` 是 [`Cache::Bypass`] 时不用缓存里的结果（量解析要多久的时候），解析出来的照样放进去。
    async fn resolve_with(&self, host: &Host, asker: Asker, cache: Cache, timeout: Duration) -> Result<Vec<IpAddr>, Stop> {
        let name = match host {
            Host::Ip(ip) => return Ok(vec![ip.to_canonical()]),
            Host::Name(name) => dns_cache::normalize(name.as_str()),
        };
        if cache == Cache::Use
            && let Some(cached) = self.inner.dns.lock().expect("dns cache mutex poisoned").get(&name, Instant::now())
        {
            return Ok(cached);
        }
        let resolved = match time::timeout(timeout, self.lookup(name.clone(), asker)).await {
            Ok(Ok(resolved)) => resolved,
            Ok(Err(ResolveError::NotFound)) => return Err(Stop::NameNotFound("域名不存在")),
            Ok(Err(ResolveError::Failed(reason))) => return Err(Stop::ResolverFailed(reason)),
            Err(_) => return Err(Stop::ResolveTimeout(timeout)),
        };
        let mut addresses: Vec<IpAddr> = Vec::with_capacity(resolved.len().min(MAX_ADDRESSES));
        for ip in resolved.into_iter().map(|ip| ip.to_canonical()) {
            if addresses.len() < MAX_ADDRESSES && !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        if addresses.is_empty() {
            return Err(Stop::NameNotFound("域名没有地址记录"));
        }
        self.inner.dns.lock().expect("dns cache mutex poisoned").put(name, addresses.clone(), Instant::now());
        Ok(addresses)
    }

    /// 占到名额之后在系统的解析器上解析 `name`。
    ///
    /// 解析在自己的任务里做，名额跟着它走：调用者等不及（超时）走了，系统的解析器还要过一阵才返回，这期间名额不能还回去，
    /// 不然一个不停地解析不存在的名字的节点能让阻塞线程越积越多。
    async fn lookup(&self, name: String, asker: Asker) -> Result<Vec<IpAddr>, ResolveError> {
        let permits = self.inner.lookups.acquire(asker).await;
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            let _permits = permits;
            inner.system.resolve(&name).await
        });
        task.await.unwrap_or_else(|error| Err(ResolveError::Failed(format!("解析的任务没有正常结束：{error}"))))
    }

    /// 本机网卡上的地址和网段。读不到时拒绝请求：没有它就判断不了目标是不是在本机的内网里。
    fn interfaces(&self) -> Result<Arc<[IpNet]>, Stop> {
        let mut cached = self.inner.interfaces.lock().expect("interfaces mutex poisoned");
        if let Some(interfaces) = cached.as_ref().filter(|interfaces| interfaces.read_at.elapsed() < INTERFACES_TTL) {
            return Ok(Arc::clone(&interfaces.nets));
        }
        let nets: Arc<[IpNet]> = self.inner.system.interfaces().map_err(|error| Stop::Interfaces(error.to_string()))?.into();
        *cached = Some(Interfaces { read_at: Instant::now(), nets: Arc::clone(&nets) });
        Ok(nets)
    }

    /// 挨个尝试 `targets`，返回第一条连上的连接。都连不上时返回其中最说明问题的那个失败。
    async fn connect_first(&self, targets: impl IntoIterator<Item = SocketAddr>, timeout: Duration, via: Via) -> Result<TcpStream, Reply> {
        let mut failure: Option<Reply> = None;
        for target in targets {
            let attempt = match time::timeout(timeout, self.connect_one(target, via)).await {
                Ok(attempt) => attempt,
                Err(_) => Err(Reply::new(Status::TimedOut, format!("{timeout:?} 之内没有连上"))),
            };
            match attempt {
                Ok(stream) => {
                    tune(&stream);
                    return Ok(stream);
                }
                Err(reply) => {
                    if failure.as_ref().is_none_or(|kept| rank(reply.status) > rank(kept.status)) {
                        failure = Some(reply);
                    }
                }
            }
        }
        Err(failure.unwrap_or_else(|| Reply::new(Status::Unreachable, "没有可以连的地址")))
    }

    async fn connect_one(&self, target: SocketAddr, via: Via) -> Result<TcpStream, Reply> {
        let system = &self.inner.system;
        let reply = |error: io::Error| Reply::new(connect_status(&error), error.to_string());
        let proxy = match via {
            Via::Direct => return system.connect(target).await.map_err(reply),
            Via::Upstream(proxy) => proxy,
        };
        let mut stream = self
            .inner
            .system
            .connect(proxy)
            .await
            .map_err(|error| Reply::new(Status::InternalError, format!("连不上上游代理：{error}")))?;
        upstream::connect(&mut stream, target).await?;
        Ok(stream)
    }
}

/// 出站停在了哪一步、为什么。
///
/// 替别人连时写成 REPLY（`From<Stop> for Reply`），出口测试时写成代码（[`Stop::cause`]）：同一个值，
/// 所以出口测试说的拒绝原因和别人经这个出口访问时被拒绝的原因一样。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stop {
    NotEnabled,
    LanNotEnabled,
    PortNotAllowed(u16),
    FamilyUnavailable(IpFamily),
    Forbidden {
        ip: IpAddr,
        what: &'static str,
    },
    NotOnLan {
        ip: IpAddr,
        why: &'static str,
    },
    NameNotFound(&'static str),
    ResolverFailed(String),
    ResolveTimeout(Duration),
    /// 读不到本机网卡的地址。
    Interfaces(String),
}

impl Stop {
    /// 出口测试里的代码。
    pub(crate) const fn cause(&self) -> ExitTestCause {
        match self {
            Self::NotEnabled => ExitTestCause::NotEnabled,
            Self::LanNotEnabled => ExitTestCause::LanNotEnabled,
            Self::PortNotAllowed(port) => ExitTestCause::PortNotAllowed { port: *port },
            Self::FamilyUnavailable(family) => ExitTestCause::FamilyUnavailable { family: *family },
            Self::Forbidden { ip, .. } => ExitTestCause::AddressNotAllowed { address: *ip },
            Self::NotOnLan { ip, .. } => ExitTestCause::NotOnLan { address: *ip },
            Self::NameNotFound(_) => ExitTestCause::NameNotFound,
            Self::ResolverFailed(_) => ExitTestCause::ResolverFailed,
            Self::ResolveTimeout(_) => ExitTestCause::Timeout,
            Self::Interfaces(_) => ExitTestCause::Other,
        }
    }

    /// 是解析域名这一步的失败（而不是出站策略的拒绝）。
    const fn is_resolution(&self) -> bool {
        matches!(self, Self::NameNotFound(_) | Self::ResolverFailed(_) | Self::ResolveTimeout(_))
    }
}

impl From<Stop> for Reply {
    fn from(stop: Stop) -> Self {
        match stop {
            Stop::NotEnabled => Self::new(Status::NotEnabled, "这个节点没有启用出口"),
            Stop::LanNotEnabled => Self::new(Status::NotEnabled, "这个出口没有打开「允许访问本机局域网」"),
            Stop::PortNotAllowed(port) => Self::new(Status::PolicyDenied, format!("出口不允许目标端口 {port}")),
            Stop::FamilyUnavailable(family) => {
                let wanted = match family {
                    IpFamily::Ipv4 => "IPv4",
                    IpFamily::Ipv6 => "IPv6",
                    IpFamily::Any => "可以连",
                };
                Self::new(Status::PolicyDenied, format!("出口只连 {wanted} 地址，这个目标没有这种地址"))
            }
            Stop::Forbidden { what, .. } => Self::new(Status::PolicyDenied, format!("目标地址是{what}，出口不替别人连这类地址")),
            Stop::NotOnLan { why, .. } => Self::new(Status::PolicyDenied, why),
            Stop::NameNotFound(detail) => Self::new(Status::NameNotFound, detail),
            Stop::ResolverFailed(reason) => Self::new(Status::ResolverFailure, reason),
            Stop::ResolveTimeout(timeout) => Self::new(Status::ResolverFailure, format!("{timeout:?} 之内没有解析出来")),
            Stop::Interfaces(error) => Self::new(Status::InternalError, format!("读不到本机网卡的地址：{error}")),
        }
    }
}

/// 出口测试每一步（解析、连接）最多等多久。
pub const PROBE_STEP: Duration = Duration::from_secs(5);

/// 一次出口测试做到的地方，连上了的话还有那条连接。
#[derive(Debug)]
pub struct Probe {
    pub result: ExitTestResult,
    pub stream: Option<TcpStream>,
}

impl Probe {
    fn refused(mut result: ExitTestResult, stop: &Stop) -> Self {
        tracing::info!(?stop, "出口测试：按出口的策略不替别人连这个目标");
        result.refused = Some(stop.cause());
        Self { result, stream: None }
    }
}

/// 一段时间写成整毫秒，超出的按上限算。
fn millis(elapsed: Duration) -> u32 {
    u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX)
}

/// 连接失败的状态在出口测试里是哪一种原因。经上游代理时，代理自己不对劲（[`Status::InternalError`]）就是上游的问题。
fn connect_cause(status: Status, via: Via) -> ExitTestCause {
    match status {
        Status::ConnectionRefused => ExitTestCause::Refused,
        Status::TimedOut => ExitTestCause::Timeout,
        Status::Unreachable => ExitTestCause::Unreachable,
        Status::InternalError if matches!(via, Via::Upstream(_)) => ExitTestCause::UpstreamFailed,
        // 别的状态连接这一步给不出来（策略的拒绝在连之前就查过了），有的话照实说是别的原因。
        _ => ExitTestCause::Other,
    }
}

/// 同 [`rank`]：越具体的失败越优先。
const fn cause_rank(cause: ExitTestCause) -> u8 {
    match cause {
        ExitTestCause::Refused => 4,
        ExitTestCause::Timeout => 3,
        ExitTestCause::Unreachable => 2,
        ExitTestCause::UpstreamFailed => 1,
        // 连接这一步只会给出上面这几种，别的排在最后。
        _ => 0,
    }
}

/// 解析域名时用不用缓存里的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cache {
    Use,
    Bypass,
}

/// 本节点能不能替别人连这个端口上的互联网目标：必须是出口，端口要在允许的范围里。
fn internet_role(netmap: &Netmap, port: u16) -> Result<&ExitRole, Stop> {
    let role = netmap.me.exit.as_ref().ok_or(Stop::NotEnabled)?;
    if role.ports.as_ref().is_some_and(|ports| !ports.contains(&port)) {
        return Err(Stop::PortNotAllowed(port));
    }
    Ok(role)
}

/// `ip` 不能当互联网目标去连时，返回它是什么地址。`nodes` 是网络里节点自己的地址（[`Outbound::node_addresses`]）。
fn forbidden_as_internet(network: &Network, interfaces: &[IpNet], nodes: &[IpAddr], ip: IpAddr) -> Option<&'static str> {
    if let Some(what) = policy::not_public(ip) {
        Some(what)
    } else if network.is_overlay_address(ip) {
        Some("覆盖网的地址")
    } else if interfaces.iter().any(|net| subnet_contains(net, ip)) {
        Some("本机网卡所在网段的地址")
    } else if nodes.contains(&ip) {
        Some("节点自己的地址（本节点对外的地址，或者网络里别的节点、relay 的地址）")
    } else {
        None
    }
}

/// `ip` 是不是在这块网卡的网段里。前缀长度是 0 的网卡地址（没有网段信息）只算它自己。
fn subnet_contains(interface: &IpNet, ip: IpAddr) -> bool {
    if interface.prefix_len() == 0 { interface.addr() == ip } else { interface.contains(&ip) }
}

/// 给到目标的连接设置选项：关掉 Nagle，打开内核保活（[`i3t_flow::keep_alive`]：流没有空闲时限，目标的死活靠它判断）。
/// 设不上不影响这条连接能用，只记一行。
fn tune(stream: &TcpStream) {
    let tuned = stream.set_nodelay(true).and_then(|()| i3t_flow::keep_alive(stream));
    if let Err(error) = tuned {
        tracing::warn!(%error, "到目标的连接设置不了 NODELAY 或者保活，静默久了可能被中间的路由器回收");
    }
}

/// 连接失败算哪一种。前几种是目标的问题；剩下的（文件描述符用完之类）是出口自己的问题。
fn connect_status(error: &io::Error) -> Status {
    match error.kind() {
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => Status::ConnectionRefused,
        io::ErrorKind::TimedOut => Status::TimedOut,
        io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::PermissionDenied => Status::Unreachable,
        _ => Status::InternalError,
    }
}

/// 几个地址都连不上时报哪一个失败：越具体的越优先。"拒绝连接"说明主机在、端口没开，比"不可达"有用。
const fn rank(status: Status) -> u8 {
    match status {
        Status::ConnectionRefused => 4,
        Status::TimedOut => 3,
        Status::Unreachable => 2,
        Status::PolicyDenied => 1,
        Status::Ok
        | Status::NameNotFound
        | Status::AccessDenied
        | Status::NotEnabled
        | Status::UnknownForward
        | Status::Draining
        | Status::QuotaExhausted
        | Status::RateLimited
        | Status::TooManyStreams
        | Status::ResolverFailure
        | Status::InternalError => 0,
    }
}

#[cfg(test)]
mod tests {
    use socket2::SockRef;

    use super::*;

    #[test]
    fn connect_errors_are_attributed_to_the_target_unless_they_are_local() {
        let status = |kind: io::ErrorKind| connect_status(&io::Error::from(kind));
        assert_eq!(status(io::ErrorKind::ConnectionRefused), Status::ConnectionRefused);
        assert_eq!(status(io::ErrorKind::TimedOut), Status::TimedOut);
        assert_eq!(status(io::ErrorKind::NetworkUnreachable), Status::Unreachable);
        assert_eq!(status(io::ErrorKind::HostUnreachable), Status::Unreachable);
        assert_eq!(status(io::ErrorKind::AddrNotAvailable), Status::Unreachable);
        assert_eq!(status(io::ErrorKind::OutOfMemory), Status::InternalError);
        assert_eq!(status(io::ErrorKind::Other), Status::InternalError);
    }

    #[test]
    fn an_interface_without_prefix_information_only_covers_its_own_address() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let lan: IpNet = "192.168.1.5/24".parse().unwrap();
        assert!(subnet_contains(&lan, ip("192.168.1.200")));
        assert!(subnet_contains(&lan, ip("192.168.1.5")));
        assert!(!subnet_contains(&lan, ip("192.168.2.1")));

        let unknown: IpNet = "203.0.113.5/0".parse().unwrap();
        assert!(subnet_contains(&unknown, ip("203.0.113.5")));
        assert!(!subnet_contains(&unknown, ip("8.8.8.8")));
    }

    #[test]
    fn internet_targets_exclude_the_overlay_range_and_every_attached_subnet_whatever_range_they_use() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        // 覆盖网和本机网卡用的都是公网模样的地址段：固定的那张表认不出它们，要靠这两项检查。
        let network = Network {
            name: "odd".into(),
            domain: "odd.i3t".into(),
            cidr: "44.128.0.0/16".parse().unwrap(),
            routing: Default::default(),
            max_relay_hops: 2,
            reach: Default::default(),
            class: None,
            ack_eliciting_threshold: 3,
            max_ack_delay_ms: 2,
            bundle_small_packets: true,
        };
        let interfaces: Vec<IpNet> =
            vec!["127.0.0.1/8".parse().unwrap(), "198.20.0.5/24".parse().unwrap(), "2400:db00::5/64".parse().unwrap()];

        assert_eq!(forbidden_as_internet(&network, &interfaces, &[], ip("44.128.3.4")), Some("覆盖网的地址"));
        assert_eq!(forbidden_as_internet(&network, &interfaces, &[], ip("198.20.0.77")), Some("本机网卡所在网段的地址"));
        assert_eq!(
            forbidden_as_internet(&network, &interfaces, &[], ip("198.20.0.5")),
            Some("本机网卡所在网段的地址"),
            "本机自己的地址也在里面"
        );
        assert_eq!(forbidden_as_internet(&network, &interfaces, &[], ip("2400:db00::99")), Some("本机网卡所在网段的地址"));
        assert_eq!(forbidden_as_internet(&network, &interfaces, &[], ip("10.1.2.3")), Some("私有地址"));

        for public in ["44.129.0.1", "198.20.1.1", "2400:db00:0:1::1", "1.1.1.1"] {
            assert_eq!(forbidden_as_internet(&network, &interfaces, &[], ip(public)), None, "{public}");
        }

        // 节点自己的公网地址（本节点的反射地址、别的节点和 relay 的地址）也不是互联网目标，哪个端口都不行。
        let nodes = [ip("45.76.1.2"), ip("2a05:f480::7")];
        assert!(forbidden_as_internet(&network, &interfaces, &nodes, ip("45.76.1.2")).is_some_and(|what| what.contains("节点自己的地址")));
        assert!(forbidden_as_internet(&network, &interfaces, &nodes, ip("2a05:f480::7")).is_some());
        assert_eq!(forbidden_as_internet(&network, &interfaces, &nodes, ip("45.76.1.3")), None);
    }

    #[tokio::test]
    async fn connections_to_targets_have_nagle_off_and_keepalive_probes_after_25_idle_seconds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        assert!(!SockRef::from(&stream).keepalive().unwrap(), "系统默认不开保活");

        tune(&stream);

        assert!(stream.nodelay().unwrap());
        let socket = SockRef::from(&stream);
        assert!(socket.keepalive().unwrap());
        // 读回这两个值的接口 Windows 上没有。
        #[cfg(not(windows))]
        {
            assert_eq!(socket.tcp_keepalive_time().unwrap(), Duration::from_secs(25));
            assert_eq!(socket.tcp_keepalive_interval().unwrap(), Duration::from_secs(25));
        }
    }

    /// 像 Windows 那样，连一个关着的端口要两秒多才报"被拒绝"的系统。网卡是回环和一个局域网地址。
    struct SlowRefusal;

    impl System for SlowRefusal {
        fn interfaces(&self) -> io::Result<Vec<IpNet>> {
            Ok(vec!["127.0.0.1/8".parse().unwrap(), "192.168.1.5/24".parse().unwrap()])
        }

        async fn resolve(&self, _name: &str) -> Result<Vec<IpAddr>, ResolveError> {
            Err(ResolveError::NotFound)
        }

        async fn connect(&self, _addr: SocketAddr) -> io::Result<TcpStream> {
            time::sleep(Duration::from_millis(2500)).await;
            Err(io::ErrorKind::ConnectionRefused.into())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_port_of_this_node_reads_as_refused_even_where_the_system_takes_seconds_to_say_so() {
        let (_netmap, receiver) = watch::channel(Arc::new(crate::grant::tests::netmap()));
        let reply = Outbound::new(receiver, SlowRefusal).node_port(22).await.unwrap_err();
        assert_eq!(reply.status, Status::ConnectionRefused, "{reply:?}");
    }

    #[test]
    fn the_most_specific_failure_wins() {
        assert!(rank(Status::ConnectionRefused) > rank(Status::TimedOut));
        assert!(rank(Status::TimedOut) > rank(Status::Unreachable));
        assert!(rank(Status::Unreachable) > rank(Status::InternalError));
    }

    /// 一个解析器：名字以 `hang` 开头的一直不返回，直到 `release`；记下同时有多少个解析在里面。
    #[derive(Clone, Default)]
    struct SlowResolver {
        inside: Arc<std::sync::atomic::AtomicUsize>,
        most: Arc<std::sync::atomic::AtomicUsize>,
        release: Arc<tokio::sync::Notify>,
    }

    impl System for SlowResolver {
        fn interfaces(&self) -> io::Result<Vec<IpNet>> {
            Ok(Vec::new())
        }

        async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
            use std::sync::atomic::Ordering::SeqCst;
            let now = self.inside.fetch_add(1, SeqCst) + 1;
            self.most.fetch_max(now, SeqCst);
            if name.starts_with("hang") {
                self.release.notified().await;
            }
            self.inside.fetch_sub(1, SeqCst);
            Ok(vec![IpAddr::from([93, 184, 216, 34])])
        }

        async fn connect(&self, _addr: SocketAddr) -> io::Result<TcpStream> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    fn slow_outbound() -> (Outbound<SlowResolver>, SlowResolver) {
        let resolver = SlowResolver::default();
        let (_netmap, receiver) = watch::channel(Arc::new(crate::grant::tests::netmap()));
        (Outbound::new(receiver, resolver.clone()), resolver)
    }

    fn name(text: &str) -> Host {
        Host::Name(text.parse().unwrap())
    }

    fn peer(raw: u32) -> Asker {
        Asker::Peer(NodeId::new(raw).unwrap())
    }

    /// 让 `asker` 同时解析 `count` 个一直不返回的名字，等它们都超时。
    async fn hang(outbound: &Outbound<SlowResolver>, asker: Asker, count: usize) {
        let lookups = (0..count).map(|index| {
            let outbound = outbound.clone();
            tokio::spawn(async move { outbound.resolve(&name(&format!("hang-{index}.example")), asker).await })
        });
        for lookup in lookups.collect::<Vec<_>>() {
            let reply = lookup.await.unwrap().expect_err("一直不返回的解析应该超时");
            assert_eq!(reply.status, Status::ResolverFailure);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn one_asker_cannot_hold_more_than_its_share_of_lookups_even_after_they_time_out() {
        let (outbound, resolver) = slow_outbound();
        hang(&outbound, peer(1), 3 * MAX_LOOKUPS_PER_ASKER).await;
        assert_eq!(resolver.most.load(std::sync::atomic::Ordering::SeqCst), MAX_LOOKUPS_PER_ASKER, "同时在解析器里的不超过它的那一份");

        // 超时只是调用者不等了，解析器里那些还没返回：名额还占着，这个节点新的解析照样排不上。
        assert_eq!(outbound.resolve(&name("quick.example"), peer(1)).await.unwrap_err().status, Status::ResolverFailure);
        // 别的节点和本机不受影响。
        assert!(outbound.resolve(&name("other.example"), peer(2)).await.is_ok());
        assert!(outbound.resolve(&name("local.example"), Asker::Local).await.is_ok());

        // 解析器终于返回了，名额也就还回来了。
        resolver.release.notify_waiters();
        tokio::task::yield_now().await;
        assert!(outbound.resolve(&name("quick.example"), peer(1)).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn all_askers_together_cannot_hold_more_than_the_total_number_of_lookups() {
        let (outbound, resolver) = slow_outbound();
        let askers = MAX_LOOKUPS / MAX_LOOKUPS_PER_ASKER + 2;
        let all = (1..=askers).map(|raw| hang(&outbound, peer(u32::try_from(raw).unwrap()), MAX_LOOKUPS_PER_ASKER));
        for done in all.collect::<Vec<_>>() {
            done.await;
        }
        assert_eq!(resolver.most.load(std::sync::atomic::Ordering::SeqCst), MAX_LOOKUPS);
    }
}
