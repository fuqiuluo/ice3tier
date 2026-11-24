//! 虚拟网卡设备抽象：创建、读写及析构清理。各平台均通过 `tun-rs` 封装（Linux TUN、Windows Wintun、macOS utun）。
//!
//! 网卡参数先构建为声明式配置（[`DeviceSpec`]：名称、地址、前缀长度、MTU 及 Windows 驱动路径），以便所有平台的配置逻辑均可在任意主机上
//! 单元测试；仅 [`Tun::create`] 会实际调用系统接口创建设备。配置地址与前缀后，系统会自动生成指向该网卡的网段路由（Linux 与 Windows 由内核自动添加，
//! macOS utun 由 `tun-rs` 通过 `associate_route` 添加）。虚拟网卡均为非持久化设备：进程退出（含异常终止）时，Linux 与 macOS 内核会自动移除设备及关联地址和路由；
//! Windows Wintun 适配器随句柄关闭销毁，若异常崩溃遗留同名适配器，下次启动将按名称重新打开并复用。
//!
//! 转发引擎仅面向 [`Device`] 抽象（单包读取、单包或批量写入），测试中可替换为内存队列。Linux 平台网卡与内核间的分段卸载（[`Offload`]）
//! 完全封装在 [`Tun`] 内部，引擎侧收发的仍为不超过 MTU 的独立 IP 包。

use std::fmt;
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use bytes::Bytes;
use ipnet::Ipv4Net;

use crate::{DEFAULT_MTU, DEVICE_PATTERN};

#[cfg(target_os = "linux")]
mod offload;

/// 转发引擎与虚拟网卡之间的抽象接口：支持单包读取以及单包或批量写入。
pub trait Device: Send + Sync + 'static {
    /// 读取下一个由本机发出并经该虚拟网卡路由的数据包，写入 `buf` 并返回字节长度。
    ///
    /// 返回 `InvalidData` 错误表示读出的数据无法组成合法数据包并已丢弃，网卡本身仍正常，应继续读取；其余错误表示网卡读取失败。
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// 非阻塞尝试读取当前已就绪的数据包；无数据时立即返回 `None`。
    ///
    /// 引擎在读到首个数据包后调用该方法排空后续已就绪数据包。不能以“轮询一次 [`recv`](Self::recv) 未就绪即丢弃”替代：
    /// 在 Windows 平台上每次异步等待 `recv` 都会创建内核事件并向阻塞线程池派发任务，取消时会产生明显额外开销。
    fn try_recv(&self, buf: &mut [u8]) -> Option<io::Result<usize>>;

    /// 向本机内核注入单个入站数据包（视同从该虚拟网卡收到）。
    fn send(&self, packet: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    /// 按顺序向本机内核注入一批入站数据包。默认逐包写入；支持分段卸载的网卡会先聚合连续分段再写入。
    ///
    /// # Errors
    ///
    /// 若部分数据包写入失败，返回失败包数、字节数与最后一个错误；其余数据包已写入成功。
    fn send_many(&self, packets: &[Bytes]) -> impl Future<Output = Result<(), Unwritten>> + Send {
        send_singly(self, packets)
    }
}

/// 批量写入虚拟网卡时未能成功写入的数据包统计。
#[derive(Debug)]
pub struct Unwritten {
    pub packets: usize,
    pub bytes: usize,
    /// 最后一次写入失败的底层错误。
    pub error: io::Error,
}

impl Unwritten {
    /// 累加本次批量写入中新增的失败包数、字节数及错误。
    fn add(lost: &mut Option<Self>, packets: usize, bytes: usize, error: io::Error) {
        let (earlier_packets, earlier_bytes) = lost.as_ref().map_or((0, 0), |lost| (lost.packets, lost.bytes));
        *lost = Some(Self { packets: earlier_packets + packets, bytes: earlier_bytes + bytes, error });
    }
}

/// 逐包写入虚拟网卡，记录失败项并继续处理后续数据包。
pub(crate) async fn send_singly<D: Device + ?Sized>(device: &D, packets: &[Bytes]) -> Result<(), Unwritten> {
    let mut lost = None;
    for packet in packets {
        if let Err(error) = device.send(packet).await {
            Unwritten::add(&mut lost, 1, packet.len(), error);
        }
    }
    lost.map_or(Ok(()), Err)
}

/// 虚拟网卡与内核之间的分段卸载模式（仅限 Linux）。
///
/// 非 [`Off`](Self::Off) 时，内核可将本机发出的连续数据合并为最大 64 KB 的大块交付用户态拆分；
/// 入站方向则将连续数据包聚合后一次性提交内核，大幅减少系统调用次数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offload {
    /// 逐包收发模式（非 Linux 平台、本机禁用分段卸载或内核不支持时使用）。
    Off,
    /// 仅启用 TCP 分段卸载。
    Tcp,
    /// 同时启用 TCP 与 UDP 分段卸载（需 Linux 6.2 及以上内核）。
    TcpUdp,
}

impl fmt::Display for Offload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Tcp => "tcp",
            Self::TcpUdp => "tcp+udp",
        })
    }
}

/// 虚拟网卡目标平台。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
    /// 暂不支持虚拟网卡的其他平台。
    Other,
}

impl Platform {
    /// 当前二进制编译目标平台。
    pub const CURRENT: Self = if cfg!(target_os = "linux") {
        Self::Linux
    } else if cfg!(windows) {
        Self::Windows
    } else if cfg!(target_os = "macos") {
        Self::MacOs
    } else {
        Self::Other
    };
}

/// Windows 平台 Wintun 驱动文件名：与 `i3t` 可执行文件置于同一目录并在运行时动态加载（不提交至源码仓库，发布时随安装包分发）。
pub const WINTUN_DLL: &str = "wintun.dll";

/// Windows 平台虚拟网卡名称。Wintun 适配器按名称识别，异常崩溃后遗留的同名适配器会在下次启动时自动重新打开并复用。
pub const WINDOWS_NAME: &str = "i3t0";

/// 虚拟网卡描述信息（显示于 Windows “网络连接”列表）。
pub const DESCRIPTION: &str = "ice3tier";

/// 创建虚拟网卡所需的规格参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSpec {
    pub platform: Platform,
    /// 创建设备时指定的名称：Linux 为 [`DEVICE_PATTERN`]（由内核分配编号），Windows 为 [`WINDOWS_NAME`]，macOS 为 `None`（由系统分配 `utunN`）。
    pub name: Option<String>,
    /// 本节点虚拟 IP。
    pub address: Ipv4Addr,
    /// 网络网段前缀长度：配置地址后系统据此生成网段路由。
    pub prefix: u8,
    /// 网卡 MTU，默认为 [`DEFAULT_MTU`]，可通过 [`DeviceSpec::with_mtu`] 覆盖。
    pub mtu: u16,
    /// Windows 平台 Wintun 驱动文件路径（位于主程序同目录）。
    pub driver: Option<PathBuf>,
    /// 是否尝试启用分段卸载（[`Offload`]）。仅 Linux 平台有效；若内核不支持则自动回退为逐包模式。
    pub offload: bool,
}

impl DeviceSpec {
    /// 根据目标平台、本节点虚拟 IP `own`、网络网段 `cidr` 及主程序路径 `program`（Windows 用于定位同目录驱动）构造网卡规格。
    #[must_use]
    pub fn new(platform: Platform, own: Ipv4Addr, cidr: Ipv4Net, program: Option<&std::path::Path>) -> Self {
        let name = match platform {
            Platform::Linux => Some(DEVICE_PATTERN.to_owned()),
            Platform::Windows => Some(WINDOWS_NAME.to_owned()),
            Platform::MacOs | Platform::Other => None,
        };
        let driver = match platform {
            Platform::Windows => program.map(|program| program.with_file_name(WINTUN_DLL)),
            Platform::Linux | Platform::MacOs | Platform::Other => None,
        };
        let offload = platform == Platform::Linux;
        Self { platform, name, address: own, prefix: cidr.prefix_len(), mtu: DEFAULT_MTU, driver, offload }
    }

    /// 设置自定义 MTU。调用方需保证其处于 [`crate::MTU_RANGE`] 范围内（加载配置时已校验）。
    #[must_use]
    pub const fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// 配置是否启用分段卸载（`[network] offload`）。非 Linux 平台始终保持关闭。
    #[must_use]
    pub const fn with_offload(mut self, wanted: bool) -> Self {
        self.offload = wanted && matches!(self.platform, Platform::Linux);
        self
    }

    /// 返回该网卡启用后对应的系统网段路由。
    #[must_use]
    pub fn route(&self) -> Ipv4Net {
        Ipv4Net::new(self.address, self.prefix).expect("前缀长度来自合法网段").trunc()
    }
}

/// 创建或配置虚拟网卡时的错误。
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// 权限不足：Linux 缺少 `CAP_NET_ADMIN`，Windows 未以管理员身份运行，macOS 非 root 用户。`missing` 为缺失权限的名称。
    #[error("缺少创建虚拟网卡所需的权限（缺少 {missing}）：{source}")]
    NoPermission { missing: String, source: io::Error },
    /// 缺少创建虚拟网卡所需的设备节点或驱动：Linux 无法打开 `/dev/net/tun`，Windows 同目录下缺少 `wintun.dll`。
    #[error("缺少创建虚拟网卡所需的设备或驱动：{detail}")]
    NoDevice { detail: String },
    #[error("Windows 程序同目录下缺少 Wintun 驱动文件 {}", .path.display())]
    DriverMissing { path: PathBuf },
    #[error("创建虚拟网卡失败：{0}")]
    Failed(io::Error),
    #[error("当前平台暂不支持虚拟网卡功能")]
    Unsupported,
}

impl DeviceError {
    /// 将系统 I/O 错误归类为权限不足、设备缺失或其他失败。
    fn classify(platform: Platform, error: io::Error) -> Self {
        let missing = match platform {
            Platform::Linux => "CAP_NET_ADMIN",
            Platform::Windows => "Administrator",
            Platform::MacOs | Platform::Other => "root",
        };
        match error.kind() {
            io::ErrorKind::PermissionDenied => Self::NoPermission { missing: missing.to_owned(), source: error },
            // Linux：`/dev/net/tun` 不存在（ENOENT），或内核未加载 tun 模块（ENODEV、ENXIO）。
            io::ErrorKind::NotFound => Self::NoDevice { detail: error.to_string() },
            _ if matches!(error.raw_os_error(), Some(code) if no_device_code(platform, code)) => {
                Self::NoDevice { detail: error.to_string() }
            }
            _ => Self::Failed(error),
        }
    }
}

/// Linux 平台预检：先直接打开 `/dev/net/tun`，以明确区分“设备缺失或未授权挂载”与“缺少网络管理权限”。
///
/// 若设备节点不存在，`tun-rs` 会尝试自行通过 `mknod` 创建；在容器中通常因默认拥有 `CAP_MKNOD` 而创建成功，
/// 但打开时会被容器设备白名单拒绝并返回 `PermissionDenied`，容易误判为缺少 `CAP_NET_ADMIN`，实际原因是容器未挂载 TUN 设备。
fn open_tun_node() -> Result<(), DeviceError> {
    const NODE: &str = "/dev/net/tun";
    match std::fs::OpenOptions::new().read(true).write(true).open(NODE) {
        Ok(_) => Ok(()),
        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied) => {
            Err(DeviceError::NoDevice { detail: format!("{NODE}: {error}") })
        }
        Err(error) => Err(DeviceError::classify(Platform::Linux, error)),
    }
}

/// 判断系统错误码是否表示设备不可用（Linux 的 `ENODEV` 与 `ENXIO`）。
fn no_device_code(platform: Platform, code: i32) -> bool {
    const ENXIO: i32 = 6;
    const ENODEV: i32 = 19;
    platform == Platform::Linux && matches!(code, ENODEV | ENXIO)
}

/// 已创建的虚拟网卡句柄。丢弃该实例后设备自动销毁（Linux 与 macOS 同时移除地址与路由）。
pub struct Tun {
    device: tun_rs::AsyncDevice,
    name: String,
    /// 启用分段卸载时持有分片拆解与聚合状态。
    #[cfg(target_os = "linux")]
    segmented: Option<offload::Segmented>,
}

impl std::fmt::Debug for Tun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tun").field("name", &self.name).finish_non_exhaustive()
    }
}

impl Tun {
    /// 按 `spec` 创建、配置并启用虚拟网卡。必须在 tokio 运行时上下文中调用。
    ///
    /// # Errors
    ///
    /// 权限不足、缺少设备或驱动、系统调用失败，或当前平台不支持时返回对应错误。
    pub fn create(spec: &DeviceSpec) -> Result<Self, DeviceError> {
        if spec.platform != Platform::CURRENT || spec.platform == Platform::Other {
            return Err(DeviceError::Unsupported);
        }
        if let Some(driver) = spec.driver.as_ref().filter(|driver| !driver.exists()) {
            return Err(DeviceError::DriverMissing { path: driver.clone() });
        }
        if spec.platform == Platform::Linux {
            open_tun_node()?;
        }
        match Self::build(spec, spec.offload) {
            // 若内核不支持分段卸载（如较老内核或受限 TUN 实现），未建成的设备句柄已自动关闭，回退为逐包模式重试。
            Err(DeviceError::Failed(error)) if spec.offload => {
                tracing::info!(%error, "启用分段卸载创建虚拟网卡失败，回退为逐包模式重试");
                Self::build(spec, false)
            }
            built => built,
        }
    }

    fn build(spec: &DeviceSpec, offload: bool) -> Result<Self, DeviceError> {
        let mut builder = tun_rs::DeviceBuilder::new().ipv4(spec.address, spec.prefix, None).mtu(spec.mtu).enable(true);
        if let Some(name) = &spec.name {
            builder = builder.name(name.clone());
        }
        #[cfg(windows)]
        {
            builder = builder.description(DESCRIPTION);
            if let Some(driver) = &spec.driver {
                builder = builder.wintun_file(driver.display().to_string());
            }
        }
        #[cfg(target_os = "macos")]
        {
            // macOS utun 配置地址后不会自动生成网段路由，需启用 associate_route 由 tun-rs 关联添加并在销毁时清理。
            builder = builder.with(|options| {
                options.associate_route(true);
            });
        }
        #[cfg(target_os = "linux")]
        {
            builder = builder.with(|options| {
                options.offload(offload);
            });
        }
        #[cfg(not(target_os = "linux"))]
        let _ = offload;
        let device = builder.build_async().map_err(|error| DeviceError::classify(spec.platform, error))?;
        let name = device.name().map_err(DeviceError::Failed)?;
        Ok(Self {
            #[cfg(target_os = "linux")]
            segmented: device.tcp_gso().then(|| offload::Segmented::new(device.udp_gso())),
            device,
            name,
        })
    }

    /// 返回操作系统实际分配的虚拟网卡名称（如 Linux/Windows 的 `i3t0`、macOS 的 `utun7`）。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 返回当前虚拟网卡实际生效的分段卸载模式。
    #[must_use]
    pub fn offload(&self) -> Offload {
        #[cfg(target_os = "linux")]
        if let Some(segmented) = &self.segmented {
            return if segmented.udp { Offload::TcpUdp } else { Offload::Tcp };
        }
        Offload::Off
    }
}

impl Device for Tun {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        if let Some(segmented) = &self.segmented {
            return segmented.recv(&self.device, buf).await;
        }
        self.device.recv(buf).await
    }

    fn try_recv(&self, buf: &mut [u8]) -> Option<io::Result<usize>> {
        #[cfg(target_os = "linux")]
        if let Some(segmented) = &self.segmented {
            return segmented.try_recv(&self.device, buf);
        }
        match self.device.try_recv(buf) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            result => Some(result),
        }
    }

    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if self.segmented.is_some() {
            return offload::send_plain(&self.device, packet).await;
        }
        self.device.send(packet).await.map(drop)
    }

    async fn send_many(&self, packets: &[Bytes]) -> Result<(), Unwritten> {
        #[cfg(target_os = "linux")]
        if let Some(segmented) = &self.segmented {
            return segmented.send_many(&self.device, packets).await;
        }
        send_singly(self, packets).await
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn cidr() -> Ipv4Net {
        "10.66.0.0/16".parse().unwrap()
    }

    #[test]
    fn each_platform_gets_its_name_address_prefix_mtu_and_route() {
        let own = Ipv4Addr::new(10, 66, 0, 5);
        let linux = DeviceSpec::new(Platform::Linux, own, cidr(), Some(Path::new("/usr/bin/i3t")));
        assert_eq!(linux.name.as_deref(), Some("i3t%d"), "Linux 上内核挑编号");
        assert_eq!((linux.address, linux.prefix, linux.mtu, linux.driver.as_ref()), (own, 16, 1280, None));
        assert_eq!(linux.route(), cidr());
        assert_eq!(linux.clone().with_mtu(1400), DeviceSpec { mtu: 1400, ..linux.clone() }, "本机设了别的 MTU：只有它变");
        assert!(crate::MTU_RANGE.contains(&DEFAULT_MTU) && *crate::MTU_RANGE.end() == 1500);

        let windows = DeviceSpec::new(Platform::Windows, own, cidr(), Some(Path::new(r"C:\ice3tier\i3t.exe")));
        assert_eq!(windows.name.as_deref(), Some("i3t0"));
        assert_eq!(
            windows.driver.as_deref(),
            Some(Path::new(r"C:\ice3tier\i3t.exe").with_file_name("wintun.dll").as_path()),
            "驱动在程序旁边"
        );

        let mac = DeviceSpec::new(Platform::MacOs, Ipv4Addr::new(10, 67, 0, 5), "10.67.0.0/20".parse().unwrap(), None);
        assert_eq!((mac.name.as_deref(), mac.prefix), (None, 20), "macOS 上系统挑一个 utunN");
        assert_eq!(mac.route(), "10.67.0.0/20".parse::<Ipv4Net>().unwrap());

        assert!(linux.offload && !linux.clone().with_offload(false).offload, "Linux 上默认和内核成块地交接，本机可以关");
        assert!(!windows.offload && !mac.offload && !windows.with_offload(true).offload, "别的平台上没有这回事，设了也没有");
    }

    #[test]
    fn errors_say_whether_privilege_or_the_device_is_missing() {
        let denied = DeviceError::classify(Platform::Linux, io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(matches!(denied, DeviceError::NoPermission { ref missing, .. } if missing == "CAP_NET_ADMIN"), "{denied:?}");
        let windows = DeviceError::classify(Platform::Windows, io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(matches!(windows, DeviceError::NoPermission { ref missing, .. } if missing == "Administrator"));
        let mac = DeviceError::classify(Platform::MacOs, io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(matches!(mac, DeviceError::NoPermission { ref missing, .. } if missing == "root"));
        assert!(matches!(DeviceError::classify(Platform::Linux, io::Error::from(io::ErrorKind::NotFound)), DeviceError::NoDevice { .. }));
        assert!(matches!(DeviceError::classify(Platform::Linux, io::Error::from_raw_os_error(19)), DeviceError::NoDevice { .. }));
        assert!(matches!(DeviceError::classify(Platform::Linux, io::Error::from_raw_os_error(16)), DeviceError::Failed(_)), "EBUSY");
    }

    /// 真的建一块网卡：要权限，所以只在设了 `I3T_VNET_DEVICE_TEST=1` 时做（Linux 上在端到端实验环境的 `unshare -Urn` 里，
    /// Windows 和 macOS 上是 CI 里以管理员、root 跑的那一步，Windows 上程序旁边要有 `wintun.dll`）。
    ///
    /// 只用三个平台都有的办法看：网卡上有这个地址；往地址段里另一个地址"连"一个 UDP 套接字，系统挑的源地址就是它（路由经它）；
    /// 丢掉之后地址没了。
    #[tokio::test]
    async fn a_real_device_gets_its_address_and_route_and_goes_away_when_dropped() {
        if std::env::var_os("I3T_VNET_DEVICE_TEST").is_none() {
            return;
        }
        let own = Ipv4Addr::new(10, 66, 0, 5);
        let spec = DeviceSpec::new(Platform::CURRENT, own, cidr(), std::env::current_exe().ok().as_deref());
        let tun = Tun::create(&spec).unwrap();
        println!("网卡 {}", tun.name());
        let has_address = |name: &str| {
            if_addrs::get_if_addrs().unwrap().iter().any(|interface| interface.name == name && interface.ip() == std::net::IpAddr::V4(own))
        };
        // Windows 配地址要一点时间。
        for _ in 0..50 {
            if has_address(tun.name()) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(has_address(tun.name()), "网卡上有本节点的虚拟 IP");
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        probe.connect("10.66.0.9:9").unwrap();
        assert_eq!(probe.local_addr().unwrap().ip(), std::net::IpAddr::V4(own), "地址段经这块网卡走");
        let name = tun.name().to_owned();
        drop(tun);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(!has_address(&name), "丢掉就没了");
    }

    #[test]
    fn a_missing_driver_or_another_platform_is_refused_before_touching_the_system() {
        let other = if Platform::CURRENT == Platform::Linux { Platform::MacOs } else { Platform::Linux };
        let spec = DeviceSpec::new(other, Ipv4Addr::new(10, 66, 0, 5), cidr(), None);
        assert!(matches!(Tun::create(&spec), Err(DeviceError::Unsupported)));
        if Platform::CURRENT == Platform::Windows {
            let spec = DeviceSpec::new(Platform::Windows, Ipv4Addr::new(10, 66, 0, 5), cidr(), Some(Path::new("/nowhere/i3t.exe")));
            assert!(matches!(Tun::create(&spec), Err(DeviceError::DriverMissing { .. })));
        }
    }
}
