//! 网卡本身：建、读写，丢掉就拆。三个平台都经 `tun-rs`：Linux 的 TUN、Windows 的 Wintun、macOS 的 utun。
//!
//! 要建成什么样先写成数据（[`DeviceSpec`]：名字、地址、前缀、MTU，Windows 上另有驱动文件的位置），三个平台的都能在任何一台机器上
//! 单元测试；真的去建的只有 [`Tun::create`]。地址和前缀给了，系统就有一条"网络的地址段走这块网卡"的路由：Linux 和 Windows 由内核
//! 按前缀自己加，macOS 的 utun 不会，由 `tun-rs` 加（它的 `associate_route`）。网卡不是持久的：进程退出（包括被杀掉）时 Linux 和 macOS
//! 的内核把它连同地址和路由一起删掉；Windows 上 Wintun 的适配器随句柄关掉而删掉，崩溃留下的同名适配器下次按名字认出来、接着用。
//!
//! 引擎只看 [`Device`]：读一个包，写一个包或者一批。测试里换成一对内存里的队列。Linux 上网卡和内核之间一次可以交接一大块
//! （[`Offload`]），那是 [`Tun`] 里面的事：引擎读到、写下的还是一个个不超过 MTU 的包。

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

/// 引擎和网卡之间的接缝：一次读一个包，一次写一个包或者一批。
pub trait Device: Send + Sync + 'static {
    /// 读下一个本机发出、经这块网卡走的包，放进 `buf`，返回长度。
    ///
    /// `InvalidData` 的错误是说读到的东西不成一个包、已经丢掉了，网卡还在，接着读就是；别的错误是网卡读不了了。
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// 网卡上现在就有包的话读一个，没有就是 `None`，不等。
    ///
    /// 引擎读到一个包之后用它把紧跟着的也取出来。"把 [`recv`](Self::recv) 试一下、还要等就丢掉"代替不了它：
    /// Windows 上 `recv` 每等一次都要建一个内核事件、往阻塞线程池里派一个任务，丢掉时再取消掉，每一阵包的末尾白做一遍。
    fn try_recv(&self, buf: &mut [u8]) -> Option<io::Result<usize>>;

    /// 把一个包交给本机的内核，像是从这块网卡进来的。
    fn send(&self, packet: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    /// 把一批包按顺序交给本机的内核。默认一个一个地写；写得了一大块的网卡把首尾相接的先合起来。
    ///
    /// # Errors
    ///
    /// 有写不进去的：几个、多少字节、为什么。别的都写进去了。
    fn send_many(&self, packets: &[Bytes]) -> impl Future<Output = Result<(), Unwritten>> + Send {
        send_singly(self, packets)
    }
}

/// 一批里没写进网卡的包。
#[derive(Debug)]
pub struct Unwritten {
    pub packets: usize,
    pub bytes: usize,
    /// 最后一个写不进去的原因。
    pub error: io::Error,
}

impl Unwritten {
    /// 一批里又有 `packets` 个、一共 `bytes` 字节没写进去。
    fn add(lost: &mut Option<Self>, packets: usize, bytes: usize, error: io::Error) {
        let (earlier_packets, earlier_bytes) = lost.as_ref().map_or((0, 0), |lost| (lost.packets, lost.bytes));
        *lost = Some(Self { packets: earlier_packets + packets, bytes: earlier_bytes + bytes, error });
    }
}

/// 一个一个地写，写不进去的记下来接着写后面的。
pub(crate) async fn send_singly<D: Device + ?Sized>(device: &D, packets: &[Bytes]) -> Result<(), Unwritten> {
    let mut lost = None;
    for packet in packets {
        if let Err(error) = device.send(packet).await {
            Unwritten::add(&mut lost, 1, packet.len(), error);
        }
    }
    lost.map_or(Ok(()), Err)
}

/// 网卡和内核之间一次交接多少（Linux）。
///
/// 不是 [`Off`](Self::Off) 时内核把本机发出的数据一大块（最长 64 KB）地交过来，程序自己切成不超过 MTU 的包；
/// 对端来的包合成大块再交给内核。每个包一次系统调用变成几十个包一次。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offload {
    /// 一次一个包。别的平台上，本机设了不要，或者内核不给的时候。
    Off,
    /// TCP 的数据成块地交接。
    Tcp,
    /// UDP 的也是（Linux 6.2 起）。
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

/// 建网卡的平台。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
    /// 别的平台：没有网卡（状态是"这个平台上还没有"）。
    Other,
}

impl Platform {
    /// 这个程序编译给的平台。
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

/// Windows 上 Wintun 的驱动文件名：和 `i3t` 的程序放在同一个目录里，运行时加载（不随仓库提交，发布时打进 Windows 的包里）。
pub const WINTUN_DLL: &str = "wintun.dll";

/// Windows 上网卡的名字。Wintun 的适配器按名字认：上次崩溃留下的同名适配器被打开接着用，不会多出一块。
pub const WINDOWS_NAME: &str = "i3t0";

/// 网卡的描述（Windows 的"网络连接"里显示的那一行）。
pub const DESCRIPTION: &str = "ice3tier";

/// 要建成什么样的网卡。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSpec {
    pub platform: Platform,
    /// 建的时候给的名字：Linux 是 [`DEVICE_PATTERN`]（内核挑编号），Windows 是 [`WINDOWS_NAME`]，macOS 不给（系统挑一个 `utunN`）。
    pub name: Option<String>,
    /// 本节点的虚拟 IP。
    pub address: Ipv4Addr,
    /// 网络地址段的前缀长度：地址带着它，系统就有一条地址段走这块网卡的路由。
    pub prefix: u8,
    /// 默认是 [`DEFAULT_MTU`]，本机另外设了时是设的值（[`DeviceSpec::with_mtu`]）。
    pub mtu: u16,
    /// Windows：Wintun 的驱动文件在哪里（程序旁边）。
    pub driver: Option<PathBuf>,
    /// 要不要和内核一大块一大块地交接（[`Offload`]）。只有 Linux 上有；内核不给时照一次一个包的办法建。
    pub offload: bool,
}

impl DeviceSpec {
    /// 本节点的虚拟 IP 是 `own`、网络的地址段是 `cidr` 时，在 `platform` 上要建的网卡。`program` 是这个程序自己的路径，
    /// Windows 上驱动文件在它旁边。
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

    /// 换一个 MTU（本机配置里设的）。调用方保证它在 [`crate::MTU_RANGE`] 里：配置文件读进来时查过。
    #[must_use]
    pub const fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// 本机设了要不要一大块一大块地交接（`[network] offload`）。没有这回事的平台上怎么设都是不要。
    #[must_use]
    pub const fn with_offload(mut self, wanted: bool) -> Self {
        self.offload = wanted && matches!(self.platform, Platform::Linux);
        self
    }

    /// 装上之后系统里那条路由：地址段走这块网卡。
    #[must_use]
    pub fn route(&self) -> Ipv4Net {
        Ipv4Net::new(self.address, self.prefix).expect("前缀长度来自一个合法的地址段").trunc()
    }
}

/// 网卡建不起来的原因。
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// 没有权限：Linux 上缺 `CAP_NET_ADMIN`，Windows 上不是以管理员运行，macOS 上不是 root。`missing` 是缺的东西的写法。
    #[error("没有建网卡的权限（缺 {missing}）：{source}")]
    NoPermission { missing: String, source: io::Error },
    /// 建网卡用的设备或者驱动没有：Linux 上打不开 `/dev/net/tun`，Windows 上程序旁边没有 `wintun.dll`。
    #[error("没有建网卡用的设备或驱动：{detail}")]
    NoDevice { detail: String },
    #[error("Windows 上程序旁边没有 {}", .path.display())]
    DriverMissing { path: PathBuf },
    #[error("建不起网卡：{0}")]
    Failed(io::Error),
    #[error("这个平台上还没有虚拟网卡")]
    Unsupported,
}

impl DeviceError {
    /// 按系统给的错误分类：没有权限、没有设备，或者别的。
    fn classify(platform: Platform, error: io::Error) -> Self {
        let missing = match platform {
            Platform::Linux => "CAP_NET_ADMIN",
            Platform::Windows => "Administrator",
            Platform::MacOs | Platform::Other => "root",
        };
        match error.kind() {
            io::ErrorKind::PermissionDenied => Self::NoPermission { missing: missing.to_owned(), source: error },
            // Linux：没有 /dev/net/tun（ENOENT），或者内核没有 tun 模块（ENODEV、ENXIO）。
            io::ErrorKind::NotFound => Self::NoDevice { detail: error.to_string() },
            _ if matches!(error.raw_os_error(), Some(code) if no_device_code(platform, code)) => {
                Self::NoDevice { detail: error.to_string() }
            }
            _ => Self::Failed(error),
        }
    }
}

/// Linux：先自己打开一次 `/dev/net/tun`，把"设备不在"和"不让用这个设备"说清楚。
///
/// 不在的时候 `tun-rs` 会试着自己建这个设备文件；容器里它多半建得出来（Docker 默认给 `CAP_MKNOD`），打开时却被容器的
/// 设备白名单拒绝，那样的"没有权限"看起来像是缺 `CAP_NET_ADMIN`，其实是容器没有把这个设备给它。
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

/// 说明"没有这个设备"的系统错误码（Linux 的 ENODEV 和 ENXIO）。
fn no_device_code(platform: Platform, code: i32) -> bool {
    const ENXIO: i32 = 6;
    const ENODEV: i32 = 19;
    platform == Platform::Linux && matches!(code, ENODEV | ENXIO)
}

/// 建好了的网卡。丢掉它，网卡就拆了（Linux 和 macOS 上连同地址和路由）。
pub struct Tun {
    device: tun_rs::AsyncDevice,
    name: String,
    /// 和内核一大块一大块地交接时有。
    #[cfg(target_os = "linux")]
    segmented: Option<offload::Segmented>,
}

impl std::fmt::Debug for Tun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tun").field("name", &self.name).finish_non_exhaustive()
    }
}

impl Tun {
    /// 按 `spec` 建网卡、配上地址和 MTU、打开。要在 tokio 运行时里调用。
    ///
    /// # Errors
    ///
    /// 没有权限、没有设备或驱动、系统不给（原话在错误里），或者这个平台上没有。
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
            // 内核不收分段卸载的设置（很老的内核，或者不完整的 TUN 实现）：没建成的那一块已经随着关掉没了，
            // 照一次一个包的办法再建。
            Err(DeviceError::Failed(error)) if spec.offload => {
                tracing::info!(%error, "带着分段卸载建不起虚拟网卡，照一次一个包的办法再建");
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
            // utun 配上地址不会自己有到网段的路由：要 tun-rs 加，网卡拆的时候路由跟着没了。
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

    /// 网卡实际的名字：`i3t0`（Linux、Windows）、`utun7`（macOS）。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 这块网卡和内核之间谈下来的交接办法。
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
