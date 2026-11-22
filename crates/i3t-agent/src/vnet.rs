//! 虚拟网卡在节点里的接法：默认打开，按本机配置装上，跟着 netmap 走，节点停下时拆掉。
//!
//! 网卡、搬包、防火墙规则、认出自己的东西都在 `i3t_vnet` 里；这里只管什么时候做：
//!
//! - 启动时：本机开着就装（Linux、Windows、macOS）。装不上（没有权限、没有驱动、地址段和本机的网络重叠……）就不装，
//!   状态里用代码说为什么（[`VnetState::Failed`]），代理和端口转发照常。关着的话，有权限时把上次（崩溃、被杀掉）留下的规则拆掉。
//! - netmap 变了：对端、访问规则变了引擎自己跟着（每个包按当前的 netmap 判断），什么都不用重装；本节点的虚拟 IP 或者网络的地址段
//!   变了整个重装；域名变了重设名字（Linux 上的 systemd-resolved）。
//! - 装着（或者因为重叠、网卡坏了没装）的时候每 [`RECHECK`] 再查一次地址段和本机的网络重不重叠：后来才有的地址（DHCP 换了地址、
//!   VPN 连上）重叠了就当场拆掉；重叠没了再装上。查不清的那一次什么也不改。
//! - 停下时全部拆掉。进程被杀掉时网卡和它的地址、路由随进程没了（不是持久的）；留下的防火墙规则下次启动时被认出来、换掉或者拆掉。
//!
//! 系统命令是阻塞的，放在阻塞线程里执行：低占用档位的运行时只有一个工作线程，不能让它等。

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use i3t_conn::Endpoint;
use i3t_model::Netmap;
use i3t_model::control::{Firewall, NameService, RuleState, VnetCause, VnetReport, VnetState};
use i3t_vnet::device::{DeviceError, DeviceSpec, Platform, Tun};
use i3t_vnet::engine::{Counters, Engine, Stopped};
use i3t_vnet::machine::{Machine, Program, Shell, missing_privilege};
use i3t_vnet::names::Names;
use i3t_vnet::plan::Plan;
use i3t_vnet::{legacy, overlap, setup};
use ipnet::Ipv4Net;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

use crate::config::Network;

/// 装着、或者因为重叠或网卡坏了没装的时候，隔多久再查一次。读一遍网卡的地址（Linux 上再加一个 `ip` 命令），几毫秒的 CPU；
/// 机器后来进了一个重叠的网络时，最多这么久它就不再被切断。
const RECHECK: Duration = Duration::from_secs(5);

/// 虚拟网卡现在的样子：报给 controller、本机状态里显示的那两项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) state: VnetState,
    pub(crate) firewall: Firewall,
}

impl Status {
    fn of(state: VnetState) -> Self {
        Self { state, firewall: Firewall::default() }
    }
}

/// 虚拟网卡这一部分。丢弃它不拆系统里的东西，要调用 [`Vnet::stop`]（上报的一方和停的一方都拿着它，所以停只要共享的引用）。
pub(crate) struct Vnet {
    status: watch::Receiver<Status>,
    counters: Arc<Counters>,
    stop: Mutex<Option<oneshot::Sender<()>>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Vnet {
    /// 按本机配置（`[network]`）开始。装的过程在自己的任务里，状态从 [`report`](Self::report) 看。
    pub(crate) fn start(network: Network, netmap: watch::Receiver<Arc<Netmap>>, endpoint: Arc<Endpoint>) -> Self {
        let counters = Arc::new(Counters::default());
        let (stop_tx, stop) = oneshot::channel();
        let (status_tx, status) = watch::channel(Status::of(VnetState::Off));
        let task = if !network.enabled {
            // 防火墙的开关也关着时一条规则也不碰，留下的由 `i3t set firewall off` 那一下拆。
            network.firewall.then(|| tokio::spawn(clean_leftovers("虚拟网卡关着")))
        } else if Platform::CURRENT == Platform::Other {
            tracing::info!("这个平台上还没有虚拟网卡，代理和端口转发照常");
            status_tx.send_replace(Status::of(VnetState::Unsupported));
            None
        } else {
            let parts = Parts {
                netmap,
                endpoint,
                counters: Arc::clone(&counters),
                firewall: network.firewall,
                mtu: network.mtu,
                offload: network.offload,
            };
            Some(tokio::spawn(supervise(parts, status_tx, stop)))
        };
        Self { status, counters, stop: Mutex::new(Some(stop_tx)), task: Mutex::new(task) }
    }

    /// 现在的状态和这次运行以来的计数。
    pub(crate) fn report(&self) -> VnetReport {
        let Status { state, firewall } = self.status.borrow().clone();
        let traffic = self.counters.snapshot();
        VnetReport {
            state,
            firewall,
            sent_packets: traffic.sent_packets,
            sent_bytes: traffic.sent_bytes,
            received_packets: traffic.received_packets,
            received_bytes: traffic.received_bytes,
            dropped: traffic.dropped,
        }
    }

    /// 拆掉装进系统里的东西，等拆完。再调用什么也不做。
    pub(crate) async fn stop(&self) {
        if let Some(stop) = self.stop.lock().expect("vnet stop mutex poisoned").take() {
            // 任务已经结束（关着、这个平台上没有）时没有人收，不要紧。
            let _ = stop.send(());
        }
        let task = self.task.lock().expect("vnet task mutex poisoned").take();
        if let Some(task) = task
            && let Err(error) = task.await
        {
            tracing::error!(%error, "虚拟网卡的任务没有正常结束，系统里可能留着它的防火墙规则，下次启动时会拆掉");
        }
    }
}

/// 在阻塞线程里执行系统命令。
async fn blocking<T: Send + 'static>(work: impl FnOnce(&mut Shell) -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(move || work(&mut Shell)).await.expect("执行系统命令的任务不会被取消，panic 了就让它传上来")
}

/// 这台机器上现在有的网卡的名字：有节点程序在用的虚拟网卡（同一台机器上可以跑几个节点程序）的规则不归别人拆。
#[must_use]
pub fn present_devices() -> Vec<String> {
    if_addrs::get_if_addrs().map(|interfaces| interfaces.into_iter().map(|interface| interface.name).collect()).unwrap_or_default()
}

/// 关着（或者装不上）的时候，把上次留下的防火墙规则和以前的透明访问留下的东西拆掉。没有权限时什么都不做：那样的节点也装不了它们。
async fn clean_leftovers(why: &'static str) {
    if missing_privilege().is_some() {
        return;
    }
    let present = present_devices();
    let removed = blocking(move |shell| setup::remove_leftovers(shell, Platform::CURRENT, &present)).await;
    match removed {
        Ok(0) => {}
        Ok(count) => tracing::info!(count, why, "拆掉了上次留下的虚拟网卡的防火墙规则"),
        Err(error) => tracing::debug!(%error, "看不清有没有上次留下的防火墙规则"),
    }
    remove_legacy().await;
}

/// 以前的透明访问（Linux）被杀掉时留下的东西：它们会让虚拟网卡不通，拆掉。
async fn remove_legacy() {
    if Platform::CURRENT != Platform::Linux {
        return;
    }
    let removed = blocking(|shell| {
        let found = legacy::Leftover::find(shell)?;
        found.remove(shell).map(|()| found)
    })
    .await;
    match removed {
        Ok(found) if !found.is_empty() => tracing::info!(?found, "拆掉了以前的透明访问留下的规则、路由和网卡"),
        Ok(_) => {}
        // 没有 nft 或者 ip 的机器上本来就没有过透明访问。
        Err(error) => tracing::debug!(%error, "看不清有没有以前的透明访问留下的东西"),
    }
}

/// 虚拟网卡用到的节点的部分。
struct Parts {
    netmap: watch::Receiver<Arc<Netmap>>,
    endpoint: Arc<Endpoint>,
    counters: Arc<Counters>,
    firewall: bool,
    /// 网卡的 MTU（本机配置的 `[network] mtu`）。
    mtu: u16,
    /// 网卡和内核之间要不要一大块一大块地交接（本机配置的 `[network] offload`）。
    offload: bool,
}

/// 装上、跟着 netmap 改、隔一阵再查地址段的重叠、收到停止就拆掉。
async fn supervise(parts: Parts, status: watch::Sender<Status>, mut stop: oneshot::Receiver<()>) {
    if !parts.firewall {
        tracing::info!("虚拟网卡的防火墙开关关着：程序一条防火墙规则也不碰");
    }
    remove_legacy().await;
    let mut netmap = parts.netmap.clone();
    let mut recheck = tokio::time::interval_at(tokio::time::Instant::now() + RECHECK, RECHECK);
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let current = Arc::clone(&netmap.borrow_and_update());
        let mut engine: Option<JoinHandle<Stopped>> = None;
        let mut session = match Session::open(&parts, &current).await {
            Ok((session, running)) => {
                tracing::info!(device = session.device_name, ?session.status, "虚拟网卡装好了");
                status.send_replace(session.status.clone());
                engine = Some(running);
                Some(session)
            }
            Err(cause) => {
                tracing::warn!(?cause, "虚拟网卡装不上，系统里什么都没有留下；代理和端口转发照常可用");
                status.send_replace(Status::of(VnetState::Failed { cause }));
                if parts.firewall {
                    clean_leftovers("虚拟网卡装不上").await;
                }
                None
            }
        };
        let reinstall = loop {
            // 装着的要查会不会被切断；因为重叠或者网卡坏了没装的要查能不能再装。别的原因（权限、驱动）不会自己没了。
            let watching = session.is_some()
                || matches!(
                    &status.borrow().state,
                    VnetState::Failed { cause: VnetCause::RangeInUse { .. } | VnetCause::DeviceFailed { .. } }
                );
            let engine_done = async {
                match engine.as_mut() {
                    Some(running) => running.await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = &mut stop => break false,
                changed = netmap.changed() => {
                    if changed.is_err() {
                        break false;
                    }
                    let next = Arc::clone(&netmap.borrow_and_update());
                    if next.me.virtual_ip != current.me.virtual_ip || next.network.cidr != current.network.cidr {
                        tracing::info!("本节点的虚拟 IP 或者网络的地址段变了，虚拟网卡整个重装");
                        break true;
                    }
                    if let Some(session) = session.as_mut()
                        && !next.network.domain.eq_ignore_ascii_case(&session.domain)
                    {
                        session.rename(&next.network.domain).await;
                        status.send_replace(session.status.clone());
                    }
                }
                ended = engine_done => {
                    let detail = match ended {
                        Ok(Stopped::Device(error)) => error.to_string(),
                        Ok(Stopped::Closed) => break false,
                        Err(error) => error.to_string(),
                    };
                    tracing::warn!(%detail, "虚拟网卡读不了了（被别的程序删掉了？），拆掉，隔一阵再装");
                    engine = None;
                    if let Some(session) = session.take() {
                        session.close(None).await;
                    }
                    status.send_replace(Status::of(VnetState::Failed { cause: VnetCause::DeviceFailed { detail } }));
                }
                _ = recheck.tick(), if watching => {
                    let cidr = netmap.borrow().network.cidr;
                    let own = session.as_ref().map(|session| session.device_name.clone());
                    match blocking(move |shell| overlap::find(shell, Platform::CURRENT, cidr, own.as_deref())).await {
                        Ok(Some(with)) => {
                            if let Some(installed) = session.take() {
                                tracing::warn!(%with, "网络的地址段和本机后来进的一个网络重叠了，虚拟网卡当场拆掉，免得把这台机器从那个网络上切下来；重叠没了再装上");
                                installed.close(engine.take()).await;
                            }
                            let failed = Status::of(VnetState::Failed { cause: VnetCause::RangeInUse { with } });
                            status.send_if_modified(|current| {
                                if *current == failed {
                                    return false;
                                }
                                *current = failed;
                                true
                            });
                        }
                        Ok(None) if session.is_none() => {
                            tracing::info!("重叠的网络没了（或者网卡可以再试了），虚拟网卡再装上");
                            break true;
                        }
                        Ok(None) => {}
                        Err(error) => tracing::debug!(%error, "查不清地址段和本机的网络重不重叠，这一次什么也不改"),
                    }
                }
            }
        };
        if let Some(session) = session.take() {
            session.close(engine.take()).await;
        }
        if !reinstall {
            status.send_replace(Status::of(VnetState::Off));
            return;
        }
    }
}

/// 装好了的虚拟网卡。
struct Session {
    device_name: String,
    plan: Plan,
    domain: String,
    firewall: bool,
    status: Status,
    names: Option<JoinHandle<()>>,
}

impl Session {
    /// 装上：查权限和重叠、建网卡、加防火墙规则、开名字服务、开始搬包（返回的第二项是搬包的任务）。
    /// 失败时系统里什么都不留，返回原因。
    async fn open(parts: &Parts, netmap: &Netmap) -> Result<(Self, JoinHandle<Stopped>), VnetCause> {
        let platform = Platform::CURRENT;
        if let Some(missing) = missing_privilege() {
            return Err(VnetCause::NoPermission { missing: vec![missing.to_owned()] });
        }
        let (own, cidr) = (netmap.me.virtual_ip, netmap.network.cidr);
        // Windows 上网卡的名字是固定的：万一上次的适配器还在（带着本节点的地址），它是自己的，接着用，不算重叠。
        let ours = (platform == Platform::Windows).then_some(i3t_vnet::device::WINDOWS_NAME);
        match blocking(move |shell| overlap::find(shell, platform, cidr, ours)).await {
            Ok(Some(with)) => return Err(VnetCause::RangeInUse { with }),
            Ok(None) => {}
            Err(error) => return Err(setup::cause(error)),
        }
        let spec =
            DeviceSpec::new(platform, own, cidr, std::env::current_exe().ok().as_deref()).with_mtu(parts.mtu).with_offload(parts.offload);
        let mtu = spec.mtu;
        let tun = tokio::task::spawn_blocking(move || Tun::create(&spec))
            .await
            .map_err(|error| VnetCause::DeviceFailed { detail: error.to_string() })?
            .map_err(device_cause)?;
        let device_name = tun.name().to_owned();
        tracing::info!(device = device_name, offload = %tun.offload(), "虚拟网卡建好了");
        let plan = Plan { device: device_name.clone(), own, cidr };
        let firewall = if parts.firewall {
            let present = present_devices();
            let leftovers = blocking(move |shell| setup::remove_leftovers(shell, platform, &present)).await;
            if let Ok(removed @ 1..) = leftovers {
                tracing::info!(removed, "拆掉了上次留下、网卡已经不在了的防火墙规则");
            }
            let firewall = blocking({
                let plan = plan.clone();
                move |shell| setup::install_firewall(shell, platform, &plan)
            })
            .await;
            log_firewall(&firewall);
            firewall
        } else {
            Firewall::default()
        };
        let (names, responder) = start_names(parts.netmap.clone(), own, &device_name, &netmap.network.domain).await;
        let engine = Engine::new(Arc::new(tun), Arc::clone(&parts.endpoint), parts.netmap.clone(), Arc::clone(&parts.counters));
        let engine = tokio::spawn(engine.run());
        let status = Status { state: VnetState::Installed { device: device_name.clone(), mtu, names }, firewall };
        let session = Self { device_name, plan, domain: netmap.network.domain.clone(), firewall: parts.firewall, status, names: responder };
        Ok((session, engine))
    }

    /// 网络的域名变了：重设名字（名字服务答的名字本来就跟着 netmap）。
    async fn rename(&mut self, domain: &str) {
        tracing::info!(domain, "网络的域名变了，重设名字");
        self.domain = domain.to_owned();
        let names = configure_resolver(&self.device_name, domain, self.plan.own).await;
        if let VnetState::Installed { names: current, .. } = &mut self.status.state {
            *current = names;
        }
    }

    /// 拆掉：停止搬包（`engine`，已经停了的是 `None`）和名字服务，撤掉名字的设置和防火墙规则，丢掉网卡（连同它的地址和路由）。
    async fn close(self, engine: Option<JoinHandle<Stopped>>) {
        if let Some(engine) = &engine {
            engine.abort();
        }
        if let Some(names) = &self.names {
            names.abort();
        }
        let (platform, device) = (Platform::CURRENT, self.device_name.clone());
        if platform == Platform::Linux {
            let device = device.clone();
            // 网卡一删，systemd-resolved 就忘了它上面的设置；先撤一下只是更干净，撤不了不要紧。
            let _reverted = blocking(move |shell| shell.run(Program::Resolvectl, &["revert".to_owned(), device], None)).await;
        }
        if self.firewall {
            match blocking(move |shell| setup::remove_firewall(shell, platform, &device)).await {
                Ok(()) => {}
                Err(error) => tracing::warn!(%error, "虚拟网卡的防火墙规则没有全部拆掉，下次启动时会拆掉"),
            }
        }
        // 等搬包的任务真的停下来：网卡在它手里，它停了网卡才丢掉。
        if let Some(engine) = engine {
            let _stopped = engine.await;
        }
        tracing::info!(device = self.device_name, "虚拟网卡拆掉了");
    }
}

/// 防火墙规则装得怎么样，各记一行。
fn log_firewall(firewall: &Firewall) {
    for (rule, state) in [("accept", &firewall.accept), ("guard", &firewall.guard)] {
        match state {
            RuleState::On => tracing::info!(rule, "虚拟网卡的防火墙规则装上了"),
            RuleState::Failed { cause } => {
                tracing::warn!(rule, ?cause, "虚拟网卡的防火墙规则装不上，网卡照常；这一条管的事由这台机器自己的防火墙定")
            }
            RuleState::Unsupported => tracing::info!(rule, "这个平台上程序不加这条防火墙规则"),
            RuleState::NotNeeded => tracing::info!(rule, "这台机器上不需要这条防火墙规则"),
            RuleState::Off | RuleState::Unknown => {}
        }
    }
}

/// 网卡建不起来的原因写成状态里的代码。
fn device_cause(error: DeviceError) -> VnetCause {
    match error {
        DeviceError::NoPermission { missing, .. } => VnetCause::NoPermission { missing: vec![missing] },
        DeviceError::NoDevice { detail } => VnetCause::NoDevice { detail },
        DeviceError::DriverMissing { path } => VnetCause::DriverMissing { path: path.display().to_string() },
        DeviceError::Failed(error) => VnetCause::DeviceFailed { detail: error.to_string() },
        DeviceError::Unsupported => VnetCause::DeviceFailed { detail: "这个平台上还没有虚拟网卡".to_owned() },
    }
}

/// 开名字服务（本节点虚拟 IP 的 53 端口），Linux 上再让 systemd-resolved 把网络的域名交给它。
/// Windows 和 macOS 上不碰系统的解析器，名字用 `i3t hosts`。
async fn start_names(
    netmap: watch::Receiver<Arc<Netmap>>,
    own: Ipv4Addr,
    device: &str,
    domain: &str,
) -> (NameService, Option<JoinHandle<()>>) {
    let address = SocketAddr::from((own, i3t_vnet::DNS_PORT));
    let socket = match UdpSocket::bind(address).await {
        Ok(socket) => socket,
        Err(error) => {
            tracing::warn!(%address, %error, "名字服务开不起来，按虚拟 IP 访问照常可用");
            return (NameService::Failed { cause: bind_cause(address, &error) }, None);
        }
    };
    let responder = tokio::spawn(answer_names(socket, netmap, own));
    (configure_resolver(device, domain, own).await, Some(responder))
}

async fn configure_resolver(device: &str, domain: &str, own: Ipv4Addr) -> NameService {
    if Platform::CURRENT != Platform::Linux {
        return NameService::NoResolver;
    }
    let (device, domain) = (device.to_owned(), domain.to_owned());
    let service = blocking(move |shell| setup::configure_resolver(shell, &device, &domain, own)).await;
    match &service {
        NameService::NoResolver => {
            tracing::info!("这台机器没有在跑 systemd-resolved：名字要写进 hosts 文件（i3t hosts），按虚拟 IP 访问照常可用");
        }
        NameService::Failed { cause } => tracing::warn!(?cause, "systemd-resolved 不接受设置，名字解析不了，按虚拟 IP 访问照常可用"),
        NameService::Resolved | NameService::Unknown => {}
    }
    service
}

/// 回答名字的查询，用节点现在看到的网络：本节点能访问的对端和自己。只答本机来的查询（来源是回环或者本节点自己的虚拟 IP）：
/// 别的节点经网卡也到得了这个端口，它们不该从这里知道本节点能访问哪些节点。
async fn answer_names(socket: UdpSocket, netmap: watch::Receiver<Arc<Netmap>>, own: Ipv4Addr) {
    let mut buf = vec![0; 1500];
    let mut cached: Option<(u64, Names)> = None;
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(error) => {
                tracing::debug!(%error, "名字服务收报文出错");
                continue;
            }
        };
        if !(from.ip().is_loopback() || from.ip() == std::net::IpAddr::V4(own)) {
            tracing::debug!(%from, "名字服务不回答别的机器来的查询");
            continue;
        }
        let current = Arc::clone(&netmap.borrow());
        if cached.as_ref().is_none_or(|(version, _)| *version != current.version) {
            cached = Some((current.version, names_of(&current)));
        }
        let Some((_, names)) = &cached else { continue };
        if let Some(answer) = names.answer(&buf[..len])
            && let Err(error) = socket.send_to(&answer, from).await
        {
            tracing::debug!(%error, %from, "名字服务的应答发不出去");
        }
    }
}

/// netmap 里的名字：本节点能访问的对端，加上自己。名字服务和 `i3t hosts` 答的都是它。
#[must_use]
pub fn names_of(netmap: &Netmap) -> Names {
    let peers = netmap.peers.iter().filter(|peer| peer.outbound).map(|peer| (peer.name.clone(), peer.virtual_ip));
    Names::new(&netmap.network.domain, peers.chain([(netmap.me.name.clone(), netmap.me.virtual_ip)]))
}

fn bind_cause(address: SocketAddr, error: &io::Error) -> VnetCause {
    match error.kind() {
        io::ErrorKind::AddrInUse => VnetCause::PortInUse { address },
        io::ErrorKind::PermissionDenied => VnetCause::NoPermission { missing: vec!["CAP_NET_BIND_SERVICE".to_owned()] },
        _ => VnetCause::BindFailed { address, detail: error.to_string() },
    }
}

/// 本机的命令（`i3t network status`）要的：这台机器上像是本程序建的网卡和它们的 IPv4 地址。`cidr` 是网络的地址段（知道的话）：
/// macOS 的 utun 看不出是谁建的，地址在地址段里的才算。
#[must_use]
pub fn devices(cidr: Option<Ipv4Net>) -> Vec<(String, Ipv4Net)> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else { return Vec::new() };
    interfaces
        .into_iter()
        .filter_map(|interface| match interface.addr {
            if_addrs::IfAddr::V4(v4) => Ipv4Net::new(v4.ip, v4.prefixlen).ok().map(|net| (interface.name, net)),
            if_addrs::IfAddr::V6(_) => None,
        })
        .filter(|(name, net)| {
            i3t_vnet::is_device_name(name)
                || (Platform::CURRENT == Platform::MacOs && name.starts_with("utun") && cidr.is_some_and(|cidr| cidr.contains(&net.addr())))
        })
        .collect()
}

/// 程序旁边的驱动文件（Windows 的 `wintun.dll`）在哪里找；不是 Windows 时是 `None`。
#[must_use]
pub fn driver_path() -> Option<PathBuf> {
    DeviceSpec::new(Platform::CURRENT, Ipv4Addr::UNSPECIFIED, Ipv4Net::default(), std::env::current_exe().ok().as_deref()).driver
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::testing::netmap;

    fn peer(raw: u8, name: &str, outbound: bool) -> i3t_model::netmap::Peer {
        serde_json::from_value(serde_json::json!({
            "id": raw, "key": i3t_proto::PublicKey::from_bytes([raw; 32]).to_string(), "name": name,
            "virtual_ip": format!("10.66.0.{raw}"), "inbound": true, "outbound": outbound
        }))
        .unwrap()
    }

    #[test]
    fn only_peers_this_node_may_access_and_itself_are_named() {
        let mut map = netmap(1);
        map.peers = vec![peer(5, "nas", true), peer(9, "hidden", false)];
        let names = names_of(&map);
        assert_eq!(names.lookup(&format!("nas.{}", map.network.domain)), Some(map.peers[0].virtual_ip));
        assert_eq!(names.lookup(&format!("hidden.{}", map.network.domain)), None);
        assert_eq!(names.lookup(&format!("{}.{}", map.me.name, map.network.domain)), Some(map.me.virtual_ip), "自己的名字也答");
    }

    #[test]
    fn failures_become_codes_with_their_values() {
        let denied =
            DeviceError::NoPermission { missing: "CAP_NET_ADMIN".into(), source: io::Error::from(io::ErrorKind::PermissionDenied) };
        assert_eq!(device_cause(denied), VnetCause::NoPermission { missing: vec!["CAP_NET_ADMIN".into()] });
        assert_eq!(
            device_cause(DeviceError::DriverMissing { path: PathBuf::from("wintun.dll") }),
            VnetCause::DriverMissing { path: "wintun.dll".into() }
        );
        assert!(matches!(device_cause(DeviceError::NoDevice { detail: "x".into() }), VnetCause::NoDevice { .. }));
        let address: SocketAddr = "10.66.0.1:53".parse().unwrap();
        assert_eq!(bind_cause(address, &io::Error::from(io::ErrorKind::AddrInUse)), VnetCause::PortInUse { address });
        assert_eq!(
            bind_cause(address, &io::Error::from(io::ErrorKind::PermissionDenied)),
            VnetCause::NoPermission { missing: vec!["CAP_NET_BIND_SERVICE".into()] }
        );
    }

    #[tokio::test]
    async fn switched_off_it_reports_off() {
        let (_tx, rx) = watch::channel(Arc::new(netmap(1)));
        let key = Arc::new(i3t_crypto::NodeKey::generate().unwrap());
        let config = i3t_conn::EndpointConfig { key, bind: "127.0.0.1:0".parse().unwrap(), netmap: rx.clone(), addr_servers: Vec::new() };
        let endpoint = Arc::new(Endpoint::bind(config).unwrap());
        let vnet = Vnet::start(Network { enabled: false, ..Network::default() }, rx, endpoint);
        assert_eq!(vnet.report().state, VnetState::Off);
        assert_eq!(vnet.report().firewall, Firewall::default());
        vnet.stop().await;
    }
}
