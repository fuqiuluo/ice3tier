//! 节点唯一的那个 UDP 端口。
//!
//! 端到端连接的包、中转、探测、地址查询都走这一个端口，所以它只管收发，不看内容。
//! 收发都是批量的：发送时一次系统调用可以带多个等长的数据报（分段卸载），接收时内核可能把同一个来源的多个数据报
//! 合成一块交上来（合并接收）。平台不支持时退化成一次一个，接口不变。

use std::fmt;
use std::future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use quinn_udp::{EcnCodepoint, UdpSocketState};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// 一次接收最多填多少个缓冲区。
pub const BATCH_SIZE: usize = quinn_udp::BATCH_SIZE;

/// 向内核要的收发缓冲区大小。默认的两百 KB 左右在高速率下本机就会溢出；内核会把它截到系统允许的上限。
const SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// 发送出错的日志，同一类最多多久记一条：出错的时候常常是每一个包都出错。
const SEND_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// IP 头里的显式拥塞通知标记。端口原样收发它，relay 转发时也带着，这样两端的连接能看到路上的拥塞标记。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecn {
    Ect0,
    Ect1,
    Ce,
}

impl From<EcnCodepoint> for Ecn {
    fn from(codepoint: EcnCodepoint) -> Self {
        match codepoint {
            EcnCodepoint::Ect0 => Self::Ect0,
            EcnCodepoint::Ect1 => Self::Ect1,
            EcnCodepoint::Ce => Self::Ce,
        }
    }
}

impl From<Ecn> for EcnCodepoint {
    fn from(ecn: Ecn) -> Self {
        match ecn {
            Ecn::Ect0 => Self::Ect0,
            Ecn::Ect1 => Self::Ect1,
            Ecn::Ce => Self::Ce,
        }
    }
}

/// 一次发送。
#[derive(Debug, Clone, Copy)]
pub struct Transmit<'a> {
    pub destination: SocketAddr,
    /// 一个数据报，或者若干个等长的数据报首尾相接（最后一个可以短）。
    pub contents: &'a [u8],
    /// `contents` 里每个数据报的长度；只有一个数据报时是 `None`。
    /// 数据报的个数不能超过 [`UdpPort::max_gso_segments`]。
    pub segment_size: Option<usize>,
    pub ecn: Option<Ecn>,
}

impl<'a> Transmit<'a> {
    /// `contents` 里的各个数据报。
    pub fn segments(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        segments(self.contents, self.segment_size.unwrap_or(self.contents.len()))
    }
}

/// 一个接收缓冲区里装了什么。
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
    /// 来源地址。双栈 socket 上收到的 IPv4 包报成 IPv4 地址，不是映射出来的 IPv6 地址。
    pub addr: SocketAddr,
    /// 缓冲区里有多少字节。
    pub len: usize,
    /// 每个数据报的长度。`len` 比它大时缓冲区里是来自同一个地址的多个数据报，每 `stride` 字节一个，最后一个可以短。
    /// 它们不一定是同一种帧，也不一定发往同一个节点，要逐个看。
    pub stride: usize,
    pub ecn: Option<Ecn>,
}

impl Default for RecvMeta {
    fn default() -> Self {
        Self { addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0), len: 0, stride: 0, ecn: None }
    }
}

/// 把一个接收缓冲区（或者一次发送的内容）切成一个个数据报。
pub fn segments(data: &[u8], stride: usize) -> impl Iterator<Item = &[u8]> {
    data.chunks(stride.max(1))
}

/// 包的方向，给 [`PacketFilter`] 用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// 故障注入用的过滤器：返回 `false` 的包被丢掉，就像在网络上丢了一样。
///
/// 参数是方向、对方的地址和数据报的内容。一次批量收发里有多个数据报时只拿第一个来问，结果作用于整批。
pub type PacketFilter = Arc<dyn Fn(Direction, SocketAddr, &[u8]) -> bool + Send + Sync>;

/// IPv6 的 socket 兼收 IPv4 这件事做不到时怎么办。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DualStack {
    /// 做不到就算绑定失败（调用方会退回只绑 IPv4）。
    Required,
    /// 做不到就只用 IPv6。
    Preferred,
}

/// 绑定好的 UDP 端口。
pub struct UdpPort {
    io: UdpSocket,
    state: UdpSocketState,
    local: SocketAddr,
    /// 没装过滤器时收发路径上只多读一个原子变量。
    filtered: AtomicBool,
    filter: RwLock<Option<PacketFilter>>,
    unreachable_logged: Throttle,
    send_error_logged: Throttle,
}

/// 内核不肯发一个数据报的原因，按怎么对待分的类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendFailure {
    /// 发送缓冲区满了：等可写之后再发。
    Busy,
    /// 比出去的那块网卡的 MTU 大。连接层探测路径 MTU 时发的大包会这样，是预料之中的。
    TooLong,
    /// 从这台机器到不了那个地址。最常见的是本机没有 IPv6，而对端公布的地址里有 IPv6：
    /// 这是正常的状态，和发到一个不通的地址没有区别，不该是一条警告。
    Unreachable,
    Other,
}

impl SendFailure {
    fn of(error: &io::Error) -> Self {
        #[cfg(unix)]
        const MESSAGE_TOO_LONG: i32 = libc::EMSGSIZE;
        /// `WSAEMSGSIZE`。
        #[cfg(windows)]
        const MESSAGE_TOO_LONG: i32 = 10040;

        match error.kind() {
            io::ErrorKind::WouldBlock => Self::Busy,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => Self::Unreachable,
            _ if error.raw_os_error() == Some(MESSAGE_TOO_LONG) => Self::TooLong,
            _ => Self::Other,
        }
    }
}

/// 一类日志隔 [`SEND_ERROR_LOG_INTERVAL`] 才记一条。
#[derive(Debug, Default)]
struct Throttle(Mutex<Option<Instant>>);

impl Throttle {
    /// 现在该不该记。该记的话，从现在起重新计时。
    fn ready(&self, now: Instant) -> bool {
        let mut last = self.0.lock().expect("log throttle mutex poisoned");
        if last.is_some_and(|last| now.saturating_duration_since(last) < SEND_ERROR_LOG_INTERVAL) {
            return false;
        }
        *last = Some(now);
        true
    }
}

impl UdpPort {
    /// 绑定 `addr`。
    ///
    /// 绑定在未指定地址上时尽量做成双栈：IPv6 的未指定地址（`[::]`）同时收发 IPv4；给的是 IPv4 的未指定地址
    /// （`0.0.0.0`）时，平台允许就改绑 `[::]` 的同一个端口，这样节点的那一个端口上 IPv4 和 IPv6 的候选端点都有。
    /// 平台不允许（没有 IPv6，或者 IPv6 的 socket 不能兼收 IPv4）时照原样只绑 IPv4。绑定在具体地址上时不变。
    ///
    /// 要在 tokio 运行时里调用。
    ///
    /// # Errors
    ///
    /// 端口被占用、地址不属于本机等，原样返回操作系统的错误。
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        if addr.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
            let dual = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), addr.port());
            match Self::bind_socket(dual, DualStack::Required) {
                Ok(port) => return Ok(port),
                Err(error) => tracing::debug!(%error, "绑不成双栈的 UDP 端口，只用 IPv4"),
            }
        }
        Self::bind_socket(addr, DualStack::Preferred)
    }

    fn bind_socket(addr: SocketAddr, dual_stack: DualStack) -> io::Result<Self> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6() {
            // 有的系统默认只收 IPv6（Windows），有的不让改（OpenBSD）。
            match (socket.set_only_v6(false), dual_stack) {
                (Ok(()), _) => {}
                (Err(error), DualStack::Required) => return Err(error),
                // 调用方点名要的就是 IPv6 的地址：改不了就只用 IPv6，不算错。
                (Err(error), DualStack::Preferred) => tracing::debug!(%error, "这个系统上 IPv6 的 socket 不能同时收发 IPv4"),
            }
        }
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        let socket = std::net::UdpSocket::from(socket);
        let state = UdpSocketState::new((&socket).into())?;
        for (what, result) in [
            ("接收", state.set_recv_buffer_size((&socket).into(), SOCKET_BUFFER_BYTES)),
            ("发送", state.set_send_buffer_size((&socket).into(), SOCKET_BUFFER_BYTES)),
        ] {
            if let Err(error) = result {
                tracing::debug!(%error, "调大 UDP {what}缓冲区失败，沿用系统默认值");
            }
        }
        let local = socket.local_addr()?;
        Ok(Self {
            io: UdpSocket::from_std(socket)?,
            state,
            local,
            filtered: AtomicBool::new(false),
            filter: RwLock::new(None),
            unreachable_logged: Throttle::default(),
            send_error_logged: Throttle::default(),
        })
    }

    /// 实际绑定的地址。`bind` 时端口给的是 0 的话，这里是系统分配的端口。
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// 本端口上别人可能连得上的地址：绑定在具体地址上时就是它；绑定在未指定地址上时是本机各个网卡的地址配上端口。
    #[must_use]
    pub fn local_candidates(&self) -> Vec<SocketAddr> {
        let port = self.local.port();
        if !self.local.ip().is_unspecified() {
            return vec![self.local];
        }
        let reachable = |ip: &IpAddr| self.local.is_ipv6() || ip.is_ipv4();
        crate::ifaddr::local_addresses().into_iter().filter(reachable).map(|ip| SocketAddr::new(ip, port)).collect()
    }

    /// 发送，不等待。给有人在等"可写"的调用方用（连接层）。
    ///
    /// # Errors
    ///
    /// 只会返回 [`io::ErrorKind::WouldBlock`]：现在发不了，等 [`writable`](Self::writable) 之后再试。
    /// 别的发送错误（目的不可达、包太大等）只记日志：UDP 本来就会丢包，上面的协议自己会重传。
    pub fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let Some(transmit) = self.outgoing(transmit) else { return Ok(()) };
        self.io.try_io(Interest::WRITABLE, || self.hand_to_kernel(&transmit))
    }

    /// 发送，内核的发送缓冲区满了就丢掉。返回有没有发出去。
    ///
    /// 给不等待的调用方用：relay 转发（它不替任何人排队），路径层自己的帧（它们都有各自的重试），
    /// 以及封好的网络包（丢了由包里面的协议重传）。
    /// 它直接问内核，不看运行时记的"可写"状态，所以刚绑定好的端口上也能立刻发。
    pub fn send_or_drop(&self, transmit: &Transmit<'_>) -> bool {
        let Some(transmit) = self.outgoing(transmit) else { return false };
        self.hand_to_kernel(&transmit).is_ok()
    }

    /// 交给内核发。只把"现在发不了"（[`io::ErrorKind::WouldBlock`]）报给调用方；别的错误在这里记一笔就算了，
    /// 包当作丢了：UDP 本来就会丢包，上面的协议自己会重传。
    ///
    /// 不用底层库自带的那一层错误处理：它把所有的错误都记成警告，"从这台机器到不了那个地址"也在里面，
    /// 于是没有 IPv6 的机器只要有一个对端公布了 IPv6 地址，日志里就每分钟一条警告。
    fn hand_to_kernel(&self, transmit: &quinn_udp::Transmit<'_>) -> io::Result<()> {
        let Err(error) = self.state.try_send((&self.io).into(), transmit) else { return Ok(()) };
        let destination = SocketAddr::new(transmit.destination.ip().to_canonical(), transmit.destination.port());
        match SendFailure::of(&error) {
            SendFailure::Busy => return Err(error),
            SendFailure::TooLong => {}
            SendFailure::Unreachable => {
                if self.unreachable_logged.ready(Instant::now()) {
                    tracing::debug!(%destination, %error, "从这台机器到不了这个地址，发给它的包丢掉");
                }
            }
            SendFailure::Other => {
                if self.send_error_logged.ready(Instant::now()) {
                    tracing::warn!(%destination, len = transmit.contents.len(), segment_size = ?transmit.segment_size, %error, "UDP 发送出错，包丢掉");
                }
            }
        }
        Ok(())
    }

    /// 用 [`send_or_drop`](Self::send_or_drop) 发一个数据报。
    pub fn send_datagram(&self, datagram: &[u8], destination: SocketAddr) {
        let transmit = Transmit { destination, contents: datagram, segment_size: None, ecn: None };
        if !self.send_or_drop(&transmit) {
            tracing::trace!(%destination, "一个数据报没有发出去");
        }
    }

    /// 过滤器放行、地址族也发得出去时，换成底层库要的形式。
    fn outgoing<'a>(&self, transmit: &Transmit<'a>) -> Option<quinn_udp::Transmit<'a>> {
        if !self.passes(Direction::Outbound, transmit.destination, transmit.segments().next().unwrap_or_default()) {
            return None;
        }
        // 这个 socket 发不出去的地址族：丢掉，和发到一个不通的地址没有区别。
        let destination = self.wire_destination(transmit.destination)?;
        Some(quinn_udp::Transmit {
            destination,
            ecn: transmit.ecn.map(EcnCodepoint::from),
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: None,
        })
    }

    /// 等到可以再发。可以有多个任务同时等。
    ///
    /// # Errors
    ///
    /// socket 本身出错。
    pub async fn writable(&self) -> io::Result<()> {
        self.io.writable().await
    }

    /// 收一批。返回填了前几个缓冲区，对应的 `metas` 说明每个缓冲区里有什么。
    ///
    /// # Errors
    ///
    /// socket 本身出错。
    pub fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], metas: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let limit = bufs.len().min(metas.len()).min(BATCH_SIZE);
        let mut raw = [quinn_udp::RecvMeta::default(); BATCH_SIZE];
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let received = self.io.try_io(Interest::READABLE, || self.state.recv((&self.io).into(), &mut bufs[..limit], &mut raw[..limit]));
            let count = match received {
                Ok(count) => count,
                // try_io 已经清掉了就绪标记，回到循环顶部重新登记唤醒。
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                // Windows 把上一次发送引来的"端口不可达"报在接收上，和这个端口能不能用没有关系。
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let mut kept = 0;
            for index in 0..count {
                let meta = RecvMeta::from(&raw[index]);
                let first = &bufs[index][..meta.len.min(meta.stride)];
                if !self.passes(Direction::Inbound, meta.addr, first) {
                    continue;
                }
                bufs.swap(kept, index);
                metas[kept] = meta;
                kept += 1;
            }
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    /// [`poll_recv`](Self::poll_recv) 的 async 形式。
    ///
    /// # Errors
    ///
    /// socket 本身出错。
    pub async fn recv(&self, bufs: &mut [IoSliceMut<'_>], metas: &mut [RecvMeta]) -> io::Result<usize> {
        future::poll_fn(|cx| self.poll_recv(cx, bufs, metas)).await
    }

    /// 一次发送最多能带几个数据报。不支持分段卸载的平台上是 1；用的时候发现内核不支持也会降到 1，所以每次发送前都要重新读。
    #[must_use]
    pub fn max_gso_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    /// 一个接收缓冲区里最多会有几个数据报。接收缓冲区要按"最大数据报长度 × 这个数"来分配。
    #[must_use]
    pub fn gro_segments(&self) -> usize {
        self.state.gro_segments()
    }

    /// 发出去的数据报在路上会不会被 IP 层分片。
    #[must_use]
    pub fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    /// 装上或者卸掉故障注入用的过滤器。只给测试用：产品代码里没有任何地方调用它。
    ///
    /// # Panics
    ///
    /// 过滤器自己 panic 过（锁中毒）。
    pub fn set_filter(&self, filter: Option<PacketFilter>) {
        let mut slot = self.filter.write().expect("packet filter lock poisoned");
        self.filtered.store(filter.is_some(), Ordering::Release);
        *slot = filter;
    }

    fn passes(&self, direction: Direction, peer: SocketAddr, datagram: &[u8]) -> bool {
        if !self.filtered.load(Ordering::Acquire) {
            return true;
        }
        let filter = self.filter.read().expect("packet filter lock poisoned");
        filter.as_ref().is_none_or(|filter| filter(direction, peer, datagram))
    }

    /// 把目的地址换成这个 socket 发得出去的形式；发不出去时返回 `None`。
    fn wire_destination(&self, destination: SocketAddr) -> Option<SocketAddr> {
        match (self.local, destination.ip().to_canonical()) {
            (SocketAddr::V6(_), IpAddr::V4(ip)) => Some(SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), destination.port())),
            (SocketAddr::V6(_), IpAddr::V6(_)) => Some(destination),
            (SocketAddr::V4(_), IpAddr::V4(ip)) => Some(SocketAddr::new(IpAddr::V4(ip), destination.port())),
            (SocketAddr::V4(_), IpAddr::V6(_)) => None,
        }
    }
}

impl From<&quinn_udp::RecvMeta> for RecvMeta {
    fn from(raw: &quinn_udp::RecvMeta) -> Self {
        Self {
            addr: SocketAddr::new(raw.addr.ip().to_canonical(), raw.addr.port()),
            len: raw.len,
            stride: if raw.stride == 0 { raw.len } else { raw.stride },
            ecn: raw.ecn.map(Ecn::from),
        }
    }
}

impl fmt::Debug for UdpPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPort").field("local", &self.local).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_DATAGRAM: usize = 1500;

    fn bind() -> UdpPort {
        UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap()
    }

    /// 收到凑够 `want` 个数据报为止，按到达顺序返回 (来源, 内容)。
    async fn receive(port: &UdpPort, want: usize) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut storage = vec![0u8; MAX_DATAGRAM * port.gro_segments() * BATCH_SIZE];
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        let mut datagrams = Vec::new();
        while datagrams.len() < want {
            let mut bufs: Vec<IoSliceMut<'_>> = storage.chunks_mut(MAX_DATAGRAM * port.gro_segments()).map(IoSliceMut::new).collect();
            let count =
                tokio::time::timeout(Duration::from_secs(5), port.recv(&mut bufs, &mut metas)).await.expect("等数据报超时").unwrap();
            for (meta, buf) in metas.iter().zip(&bufs).take(count) {
                datagrams.extend(segments(&buf[..meta.len], meta.stride).map(|datagram| (meta.addr, datagram.to_vec())));
            }
        }
        datagrams
    }

    #[test]
    fn an_address_this_machine_cannot_reach_is_not_a_send_error_worth_a_warning() {
        let kind = |kind: io::ErrorKind| SendFailure::of(&io::Error::from(kind));
        assert_eq!(kind(io::ErrorKind::WouldBlock), SendFailure::Busy);
        assert_eq!(kind(io::ErrorKind::NetworkUnreachable), SendFailure::Unreachable);
        assert_eq!(kind(io::ErrorKind::HostUnreachable), SendFailure::Unreachable);
        assert_eq!(kind(io::ErrorKind::PermissionDenied), SendFailure::Other);
    }

    /// 内核给的错误码要认得出来：没有 IPv6 的机器往 IPv6 地址发时就是 `ENETUNREACH`。
    #[cfg(unix)]
    #[test]
    fn kernel_error_codes_are_told_apart() {
        let code = |code: i32| SendFailure::of(&io::Error::from_raw_os_error(code));
        assert_eq!(code(libc::EAGAIN), SendFailure::Busy);
        assert_eq!(code(libc::ENETUNREACH), SendFailure::Unreachable);
        assert_eq!(code(libc::EHOSTUNREACH), SendFailure::Unreachable);
        assert_eq!(code(libc::EMSGSIZE), SendFailure::TooLong);
        assert_eq!(code(libc::EPERM), SendFailure::Other);
        assert_eq!(code(libc::EINVAL), SendFailure::Other);
    }

    #[test]
    fn a_kind_of_send_error_is_logged_once_per_interval() {
        let throttle = Throttle::default();
        let start = Instant::now();
        assert!(throttle.ready(start));
        assert!(!throttle.ready(start + SEND_ERROR_LOG_INTERVAL / 2));
        assert!(throttle.ready(start + SEND_ERROR_LOG_INTERVAL));
        assert!(!throttle.ready(start + SEND_ERROR_LOG_INTERVAL + Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn a_single_datagram_arrives_with_its_source_address() {
        let (a, b) = (bind(), bind());
        a.send_datagram(b"hello", b.local_addr());
        assert_eq!(receive(&b, 1).await, [(a.local_addr(), b"hello".to_vec())]);
    }

    #[tokio::test]
    async fn a_segmented_transmit_arrives_as_separate_datagrams_in_order() {
        let (a, b) = (bind(), bind());
        let count = a.max_gso_segments().min(4);
        let contents: Vec<u8> = (0..count).flat_map(|index| [u8::try_from(index).unwrap(); 300]).collect();
        // 最后一个数据报比别的短。
        let contents = &contents[..contents.len() - 100];
        let segment_size = (count > 1).then_some(300);
        assert!(a.send_or_drop(&Transmit { destination: b.local_addr(), contents, segment_size, ecn: None }));

        let received = receive(&b, count).await;
        let expected: Vec<Vec<u8>> = contents.chunks(300).map(<[u8]>::to_vec).collect();
        assert_eq!(received.into_iter().map(|(_, datagram)| datagram).collect::<Vec<_>>(), expected);
    }

    #[tokio::test]
    async fn the_filter_drops_packets_in_either_direction_and_can_be_removed() {
        let (a, b) = (bind(), bind());
        let b_addr = b.local_addr();
        a.set_filter(Some(Arc::new(move |direction, peer, _| !(direction == Direction::Outbound && peer == b_addr))));
        a.send_datagram(b"dropped on the way out", b.local_addr());
        a.set_filter(None);

        b.set_filter(Some(Arc::new(|direction, _, datagram: &[u8]| !(direction == Direction::Inbound && datagram.starts_with(b"drop")))));
        a.send_datagram(b"dropped on the way in", b.local_addr());
        a.send_datagram(b"kept", b.local_addr());
        assert_eq!(receive(&b, 1).await, [(a.local_addr(), b"kept".to_vec())]);
    }

    #[tokio::test]
    async fn a_port_bound_to_a_specific_address_offers_exactly_that_candidate() {
        let port = bind();
        assert_eq!(port.local_candidates(), [port.local_addr()]);
        assert_ne!(port.local_addr().port(), 0);
    }

    #[tokio::test]
    async fn a_dual_stack_port_talks_to_ipv4_and_reports_plain_ipv4_sources() {
        let Ok(dual) = UdpPort::bind("[::]:0".parse().unwrap()) else { return };
        let v4 = bind();
        let dual_via_v4 = SocketAddr::new("127.0.0.1".parse().unwrap(), dual.local_addr().port());
        v4.send_datagram(b"to dual", dual_via_v4);
        let received = receive(&dual, 1).await;
        assert_eq!(received, [(v4.local_addr(), b"to dual".to_vec())]);
        dual.send_datagram(b"to v4", v4.local_addr());
        assert_eq!(receive(&v4, 1).await, [(dual_via_v4, b"to v4".to_vec())]);
    }

    #[tokio::test]
    async fn binding_the_ipv4_wildcard_gives_a_dual_stack_port_where_the_platform_allows_it() {
        let port = UdpPort::bind("0.0.0.0:0".parse().unwrap()).unwrap();
        let v4 = bind();
        let via_v4 = SocketAddr::new("127.0.0.1".parse().unwrap(), port.local_addr().port());
        v4.send_datagram(b"over v4", via_v4);
        assert_eq!(receive(&port, 1).await, [(v4.local_addr(), b"over v4".to_vec())], "不管是不是双栈，IPv4 都要通");
        if !port.local_addr().is_ipv6() {
            // 这台机器上绑不成双栈（没有 IPv6）：退回只绑 IPv4，上面那一条已经说明它能用。
            return;
        }
        assert!(port.local_addr().ip().is_unspecified());
        let Ok(v6) = UdpPort::bind("[::1]:0".parse().unwrap()) else { return };
        v6.send_datagram(b"over v6", SocketAddr::new("::1".parse().unwrap(), port.local_addr().port()));
        assert_eq!(receive(&port, 1).await, [(v6.local_addr(), b"over v6".to_vec())], "同一个端口上也收得到 IPv6");
        assert!(port.local_candidates().iter().all(|candidate| candidate.port() == port.local_addr().port()));
    }

    #[tokio::test]
    async fn an_ipv4_port_silently_drops_ipv6_destinations() {
        let port = bind();
        let transmit = Transmit { destination: "[2001:db8::1]:9".parse().unwrap(), contents: b"x", segment_size: None, ecn: None };
        assert!(port.try_send(&transmit).is_ok());
        assert!(!port.send_or_drop(&transmit));
    }
}
