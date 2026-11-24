//! 虚拟网卡在节点中的集成：默认启用，按本机配置初始化，随 netmap 动态更新，节点停止时清理。
//!
//! 网卡、搬包、防火墙规则、认出自己的东西都在 `i3t_vnet` 里；这里只管什么时候做：
//!
//! - 启动时：若本机启用则尝试初始化（Linux、Windows、macOS）。初始化失败（缺少权限、缺少驱动、地址段与本机网络重叠等）时放弃安装，
//!   通过状态原因码说明原因（[`VnetState::Failed`]），代理和端口转发不受影响。若关闭且具备权限，则清理上次（崩溃或被强制终止）残留的规则。
//! - netmap 变了：对端、访问规则变了引擎自己跟着（每个包按当前的 netmap 判断），什么都不用重装；本节点的虚拟 IP 或者网络的地址段
//!   变了整个重装；域名变了重设名字（Linux 上的 systemd-resolved）。
//! - 已安装（或因重叠、网卡异常而未安装）期间每 [`RECHECK`] 重新检查一次地址段与本机网络是否重叠：新增地址（如 DHCP 变更或
//!   VPN 连接）发生重叠时立即清理虚拟网卡；重叠解除后重新初始化。单次检查失败时保持现状不变。
//! - 停止时执行完整清理。进程被强制终止时，非持久化的网卡及其地址和路由会随进程释放；残留防火墙规则将在下次启动时被识别并替换或清理。
//!
//! 系统命令是阻塞的，放在阻塞线程里执行：低占用档位的运行时只有一个工作线程，不能让它等。

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use i3t_access::{Claim, OwnListener, OwnListeners};
use i3t_conn::Endpoint;
use i3t_model::Netmap;
use i3t_model::control::{Firewall, NameService, RuleState, VnetCause, VnetReport, VnetState};
use i3t_model::netmap::ForwardProtocol;
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
    ///
    /// 名字服务开着的时候登记在 `own_listeners` 里：它只答本机来的查询，认的是来源地址，而出口替别的节点连
    /// "本节点的端口"时用的正是本机的地址，所以出口要知道这个监听在哪里、绕开它。
    pub(crate) fn start(
        network: Network,
        netmap: watch::Receiver<Arc<Netmap>>,
        endpoint: Arc<Endpoint>,
        own_listeners: OwnListeners,
    ) -> Self {
        let counters = Arc::new(Counters::default());
        let (stop_tx, stop) = oneshot::channel();
        let (status_tx, status) = watch::channel(Status::of(VnetState::Off));
        let task = if !network.enabled {
            // 防火墙的开关也关着时一条规则也不碰，留下的由 `i3t set firewall off` 那一下拆。
            network.firewall.then(|| tokio::spawn(clean_leftovers("虚拟网卡已关闭")))
        } else if Platform::CURRENT == Platform::Other {
            tracing::info!("当前平台不支持虚拟网卡，仍可使用代理和端口转发");
            status_tx.send_replace(Status::of(VnetState::Unsupported));
            None
        } else {
            let parts = Parts {
                netmap,
                endpoint,
                own_listeners,
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

    /// 清理已安装的系统资源并等待完成。重复调用不产生副作用。
    pub(crate) async fn stop(&self) {
        if let Some(stop) = self.stop.lock().expect("vnet stop mutex poisoned").take() {
            // 任务已结束（如已关闭或当前平台不支持）时无接收方，忽略发送失败。
            let _ = stop.send(());
        }
        let task = self.task.lock().expect("vnet task mutex poisoned").take();
        if let Some(task) = task
            && let Err(error) = task.await
        {
            tracing::error!(%error, "虚拟网卡任务异常结束，系统中可能残留防火墙规则，将在下次启动时清理");
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

/// 在虚拟网卡关闭（或初始化失败）时，清理上次残留的防火墙规则与原透明访问残留配置。权限不足时直接跳过（无权限节点也不会安装这些资源）。
async fn clean_leftovers(why: &'static str) {
    if missing_privilege().is_some() {
        return;
    }
    let present = present_devices();
    let removed = blocking(move |shell| setup::remove_leftovers(shell, Platform::CURRENT, &present)).await;
    match removed {
        Ok(0) => {}
        Ok(count) => tracing::info!(count, why, "已清理上次残留的虚拟网卡防火墙规则"),
        Err(error) => tracing::debug!(%error, "检查上次残留的虚拟网卡防火墙规则失败"),
    }
    remove_legacy().await;
}

/// 清理原透明访问（Linux）进程异常终止后残留的配置：这些残留会导致虚拟网卡不可达。
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
        Ok(found) if !found.is_empty() => tracing::info!(?found, "已清理原透明访问残留的防火墙规则、路由和网卡"),
        Ok(_) => {}
        // 没有 nft 或者 ip 的机器上本来就没有过透明访问。
        Err(error) => tracing::debug!(%error, "检查原透明访问残留配置失败"),
    }
}

/// 虚拟网卡用到的节点的部分。
struct Parts {
    netmap: watch::Receiver<Arc<Netmap>>,
    endpoint: Arc<Endpoint>,
    /// 节点的程序自己在监听的地址的那张表，名字服务登记在里面。
    own_listeners: OwnListeners,
    counters: Arc<Counters>,
    firewall: bool,
    /// 网卡的 MTU（本机配置的 `[network] mtu`）。
    mtu: u16,
    /// 网卡和内核之间要不要一大块一大块地交接（本机配置的 `[network] offload`）。
    offload: bool,
}

impl Parts {
    fn shape(&self, netmap: &Netmap) -> Shape {
        Shape::of(Platform::CURRENT, self.mtu, self.offload, &netmap.network)
    }
}

/// 网卡照什么建：本机的配置和网络的设置合起来算出来的。netmap 换了、算出来的不一样了，网卡就重装一遍。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Shape {
    mtu: u16,
    offload: bool,
}

impl Shape {
    /// MTU：本机另外设了就用本机的，没有就用网络的默认值。分段卸载：网络和本机都开着才用，而且只有 Linux 上有这回事，
    /// 别的平台上网络的开关怎么变都不用重装。
    fn of(platform: Platform, local_mtu: u16, local_offload: bool, network: &i3t_model::netmap::Network) -> Self {
        Self { mtu: network.adapter_mtu(local_mtu), offload: platform == Platform::Linux && local_offload && network.vnet_offload }
    }
}

/// 虚拟网卡主循环：初始化、响应 netmap 变更、定期检查地址段重叠，并在收到停止信号时清理。
async fn supervise(parts: Parts, status: watch::Sender<Status>, mut stop: oneshot::Receiver<()>) {
    if !parts.firewall {
        tracing::info!("虚拟网卡防火墙规则管理已关闭，程序不会修改任何防火墙规则");
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
                tracing::warn!(?cause, "虚拟网卡初始化失败，代理和端口转发仍可用");
                status.send_replace(Status::of(VnetState::Failed { cause }));
                if parts.firewall {
                    clean_leftovers("虚拟网卡初始化失败").await;
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
                        tracing::info!("本节点虚拟 IP 或网络地址段已变更，将重新初始化虚拟网卡");
                        break true;
                    }
                    let (was, now) = (parts.shape(&current), parts.shape(&next));
                    if was != now {
                        tracing::info!(?was, ?now, "网络虚拟网卡 MTU 或分片卸载配置已变更，将重新初始化虚拟网卡");
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
                    tracing::warn!(%detail, "虚拟网卡运行异常，将先清理资源，再尝试重新初始化");
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
                                tracing::warn!(%with, "虚拟网络地址段与本机新增网络重叠，立即停用并清理虚拟网卡以避免影响本机网络通信；重叠解除后将重新初始化");
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
                            tracing::info!("地址段重叠已解除（或可重试初始化虚拟网卡），将重新初始化虚拟网卡");
                            break true;
                        }
                        Ok(None) => {}
                        Err(error) => tracing::debug!(%error, "检查地址段是否与本机网络重叠失败，本次保持当前状态不变"),
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
    names: Option<NameResponder>,
}

/// 开着的名字服务：回答查询的任务（socket 在它手里），和它在"程序自己的监听"里的登记。
struct NameResponder {
    task: JoinHandle<()>,
    /// 任务停下、socket 关掉之后才撤销（[`Session::close`]）。
    _claim: Claim,
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
        // Windows 平台虚拟网卡名称固定：若上次残留适配器仍存在（携带本节点地址），属于本节点自身设备，可复用而不视为地址段重叠。
        let ours = (platform == Platform::Windows).then_some(i3t_vnet::device::WINDOWS_NAME);
        match blocking(move |shell| overlap::find(shell, platform, cidr, ours)).await {
            Ok(Some(with)) => return Err(VnetCause::RangeInUse { with }),
            Ok(None) => {}
            Err(error) => return Err(setup::cause(error)),
        }
        let shape = parts.shape(netmap);
        let spec =
            DeviceSpec::new(platform, own, cidr, std::env::current_exe().ok().as_deref()).with_mtu(shape.mtu).with_offload(shape.offload);
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
                tracing::info!(removed, "已清理上次残留且对应网卡已不存在的防火墙规则");
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
        let (names, responder) = start_names(parts, own, &device_name, &netmap.network.domain).await;
        let engine = Engine::new(Arc::new(tun), Arc::clone(&parts.endpoint), parts.netmap.clone(), Arc::clone(&parts.counters));
        let engine = tokio::spawn(engine.run());
        let status = Status { state: VnetState::Installed { device: device_name.clone(), mtu, names }, firewall };
        let session = Self { device_name, plan, domain: netmap.network.domain.clone(), firewall: parts.firewall, status, names: responder };
        Ok((session, engine))
    }

    /// 网络域名变更后重新配置系统解析器（内置 DNS 服务自动跟随最新 netmap）。
    async fn rename(&mut self, domain: &str) {
        tracing::info!(domain, "网络域名已变更，正在重新配置名称解析");
        self.domain = domain.to_owned();
        let names = configure_resolver(&self.device_name, domain, self.plan.own).await;
        if let VnetState::Installed { names: current, .. } = &mut self.status.state {
            *current = names;
        }
    }

    /// 清理虚拟网卡：停止数据转发（`engine`，已停止时为 `None`）与 DNS 服务，撤销解析器配置与防火墙规则，并释放网卡（连同其地址和路由）。
    async fn close(self, engine: Option<JoinHandle<Stopped>>) {
        if let Some(engine) = &engine {
            engine.abort();
        }
        if let Some(names) = &self.names {
            names.task.abort();
        }
        let (platform, device) = (Platform::CURRENT, self.device_name.clone());
        if platform == Platform::Linux {
            let device = device.clone();
            // 网卡释放后 systemd-resolved 会自动清除其配置；提前撤销仅用于保持状态整洁，失败可忽略。
            let _reverted = blocking(move |shell| shell.run(Program::Resolvectl, &["revert".to_owned(), device], None)).await;
        }
        if self.firewall {
            match blocking(move |shell| setup::remove_firewall(shell, platform, &device)).await {
                Ok(()) => {}
                Err(error) => tracing::warn!(%error, "虚拟网卡防火墙规则未完全清理，将在下次启动时继续清理"),
            }
        }
        // 等待 DNS 服务的 socket 真正关闭后，再将其从自有监听表中注销。
        if let Some(NameResponder { task, _claim }) = self.names {
            // 任务是被取消的，它的结果只会是"已取消"。
            let _ = task.await;
        }
        // 等搬包的任务真的停下来：网卡在它手里，它停了网卡才丢掉。
        if let Some(engine) = engine {
            let _stopped = engine.await;
        }
        tracing::info!(device = self.device_name, "虚拟网卡已清理");
    }
}

/// 记录各条防火墙规则的安装结果。
fn log_firewall(firewall: &Firewall) {
    for (rule, state) in [("accept", &firewall.accept), ("guard", &firewall.guard)] {
        match state {
            RuleState::On => tracing::info!(rule, "虚拟网卡防火墙规则已安装"),
            RuleState::Failed { cause } => {
                tracing::warn!(rule, ?cause, "虚拟网卡防火墙规则安装失败。虚拟网卡仍可用，相关流量由本机防火墙规则处理。")
            }
            RuleState::Unsupported => tracing::info!(rule, "当前平台不安装该防火墙规则"),
            RuleState::NotNeeded => tracing::info!(rule, "当前主机无需安装该防火墙规则"),
            RuleState::Off | RuleState::Unknown => {}
        }
    }
}

/// 将虚拟网卡创建或运行故障转换为上报状态的原因码。
fn device_cause(error: DeviceError) -> VnetCause {
    match error {
        DeviceError::NoPermission { missing, .. } => VnetCause::NoPermission { missing: vec![missing] },
        DeviceError::NoDevice { detail } => VnetCause::NoDevice { detail },
        DeviceError::DriverMissing { path } => VnetCause::DriverMissing { path: path.display().to_string() },
        DeviceError::Failed(error) => VnetCause::DeviceFailed { detail: error.to_string() },
        DeviceError::Unsupported => VnetCause::DeviceFailed { detail: "当前平台暂不支持虚拟网卡功能".to_owned() },
    }
}

/// 启动内置 DNS 服务（本节点虚拟 IP 的 53 端口），Linux 上同时配置 systemd-resolved 将网络域名转发至该服务。
/// Windows 和 macOS 上不修改系统解析器，可通过 `i3t hosts` 配置名称解析。
async fn start_names(parts: &Parts, own: Ipv4Addr, device: &str, domain: &str) -> (NameService, Option<NameResponder>) {
    let address = SocketAddr::from((own, i3t_vnet::DNS_PORT));
    // 先登记再绑定：绑定后即开始响应查询，出口必须在此之前知晓该地址不可从本机访问。绑定失败时登记随凭据自动撤销。
    // 每次初始化虚拟网卡仅尝试启动一次 DNS 服务，绑定失败不重试，不会重复登记。
    let claim = parts.own_listeners.claim(OwnListener { protocol: ForwardProtocol::Udp, local: address, forward: None });
    let socket = match UdpSocket::bind(address).await {
        Ok(socket) => socket,
        Err(error) => {
            tracing::warn!(%address, %error, "DNS 服务启动失败，仍可通过虚拟 IP 访问");
            return (NameService::Failed { cause: bind_cause(address, &error) }, None);
        }
    };
    let task = tokio::spawn(answer_names(socket, parts.netmap.clone(), own));
    (configure_resolver(device, domain, own).await, Some(NameResponder { task, _claim: claim }))
}

async fn configure_resolver(device: &str, domain: &str, own: Ipv4Addr) -> NameService {
    if Platform::CURRENT != Platform::Linux {
        return NameService::NoResolver;
    }
    let (device, domain) = (device.to_owned(), domain.to_owned());
    let service = blocking(move |shell| setup::configure_resolver(shell, &device, &domain, own)).await;
    match &service {
        NameService::NoResolver => {
            tracing::info!("systemd-resolved 不可用。可通过 hosts 文件配置名称解析（i3t hosts），也可直接使用虚拟 IP 访问。");
        }
        NameService::Failed { cause } => tracing::warn!(?cause, "配置 systemd-resolved 失败，名称解析不可用，仍可通过虚拟 IP 访问"),
        NameService::Resolved | NameService::Unknown => {}
    }
    service
}

/// 响应基于当前 netmap 的名称查询（包含本节点可访问的对端与本节点自身）。仅响应本机查询（源地址为回环或本节点虚拟 IP）：
/// 其他节点经虚拟网卡也能访问该端口，不应允许其借此探测本节点可访问的对端列表。
async fn answer_names(socket: UdpSocket, netmap: watch::Receiver<Arc<Netmap>>, own: Ipv4Addr) {
    let mut buf = vec![0; 1500];
    let mut cached: Option<(u64, Names)> = None;
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(error) => {
                tracing::debug!(%error, "DNS 服务接收报文失败");
                continue;
            }
        };
        if !(from.ip().is_loopback() || from.ip() == std::net::IpAddr::V4(own)) {
            tracing::debug!(%from, "DNS 服务已忽略来自非本机地址的查询");
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
            tracing::debug!(%error, %from, "发送 DNS 应答失败");
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

/// 供本机命令（`i3t network status`）查询当前主机上疑似由本程序创建的网卡及其 IPv4 地址。`cidr` 为虚拟网络地址段（若已知）：
/// macOS 的 utun 无法区分创建者，仅匹配地址落在虚拟网络地址段内的接口。
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
    fn the_adapter_follows_the_network_unless_this_machine_set_its_own() {
        let mut network = netmap(1).network;
        let linux = |mtu, offload, network: &i3t_model::netmap::Network| Shape::of(Platform::Linux, mtu, offload, network);
        assert_eq!(linux(1280, true, &network), Shape { mtu: 1280, offload: true }, "都是默认值");

        (network.vnet_mtu, network.vnet_offload) = (1400, false);
        assert_eq!(linux(1280, true, &network), Shape { mtu: 1400, offload: false }, "本机没有另外设：跟着网络");
        assert_eq!(linux(1200, true, &network).mtu, 1200, "本机另外设了 MTU：用本机的");

        network.vnet_offload = true;
        assert!(!linux(1280, false, &network).offload, "本机关了分段卸载：网络开着也不用");
        assert!(!Shape::of(Platform::Windows, 1280, true, &network).offload, "别的平台上没有这回事，网络的开关变了也不用重装");

        network.vnet_mtu = 9000;
        assert_eq!(linux(1280, true, &network).mtu, 1280, "controller 发来的值不在范围里：不用它");
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
        let vnet = Vnet::start(Network { enabled: false, ..Network::default() }, rx, endpoint, OwnListeners::default());
        assert_eq!(vnet.report().state, VnetState::Off);
        assert_eq!(vnet.report().firewall, Firewall::default());
        vnet.stop().await;
    }
}
