//! QUIC 库眼里的"socket"：其实是路径层。
//!
//! 每个对端有一个固定的虚拟地址，由它的节点编号算出来。QUIC 库只见得到虚拟地址，包实际从哪条路走由路径层决定，
//! 所以换路时 QUIC 不知道，连接和上面的流不受影响。

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use i3t_path::{PacketMeta, Packets, Paths};
use i3t_proto::NodeId;
use i3t_underlay::Ecn;
use quinn::udp::{BATCH_SIZE, EcnCodepoint, RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::sealed::Inbox;

/// 虚拟地址的前缀。取自 IPv6 的唯一本地地址段，不会和任何真实的地址混淆；后 32 位是节点编号。
const VIRTUAL_PREFIX: [u16; 6] = [0xfd69, 0x3374, 0, 0, 0, 0];
/// 虚拟地址的端口。QUIC 库要求端口不是 0，除此之外它没有意义。
const VIRTUAL_PORT: u16 = 20330;

/// 节点在 QUIC 库眼里的地址。
pub(crate) fn virtual_addr(id: NodeId) -> SocketAddr {
    let [p0, p1, p2, p3, p4, p5] = VIRTUAL_PREFIX;
    let [b0, b1, b2, b3] = id.to_be_bytes();
    let ip = Ipv6Addr::new(p0, p1, p2, p3, p4, p5, u16::from_be_bytes([b0, b1]), u16::from_be_bytes([b2, b3]));
    SocketAddr::new(IpAddr::V6(ip), VIRTUAL_PORT)
}

/// 虚拟地址对应的节点；不是虚拟地址时返回 `None`。
pub(crate) fn node_of(addr: SocketAddr) -> Option<NodeId> {
    let IpAddr::V6(ip) = addr.ip() else { return None };
    let [p0, p1, p2, p3, p4, p5, hi, lo] = ip.segments();
    if [p0, p1, p2, p3, p4, p5] != VIRTUAL_PREFIX || addr.port() != VIRTUAL_PORT {
        return None;
    }
    let [b0, b1] = hi.to_be_bytes();
    let [b2, b3] = lo.to_be_bytes();
    NodeId::from_be_bytes([b0, b1, b2, b3])
}

const fn ecn_from_quic(codepoint: EcnCodepoint) -> Ecn {
    match codepoint {
        EcnCodepoint::Ect0 => Ecn::Ect0,
        EcnCodepoint::Ect1 => Ecn::Ect1,
        EcnCodepoint::Ce => Ecn::Ce,
    }
}

const fn ecn_to_quic(ecn: Ecn) -> EcnCodepoint {
    match ecn {
        Ecn::Ect0 => EcnCodepoint::Ect0,
        Ecn::Ect1 => EcnCodepoint::Ect1,
        Ecn::Ce => EcnCodepoint::Ce,
    }
}

/// 交给 QUIC 库的 socket。
///
/// 路径层交上来的包里，封好的网络包（虚拟网卡的 IP 包，不进 QUIC）在这里就分出去，QUIC 库看不到它们。
pub(crate) struct PathSocket {
    paths: Arc<Paths>,
    me: NodeId,
    inbox: Arc<Inbox>,
}

impl PathSocket {
    pub(crate) fn new(paths: Arc<Paths>, me: NodeId, inbox: Arc<Inbox>) -> Arc<Self> {
        Arc::new(Self { paths, me, inbox })
    }
}

impl fmt::Debug for PathSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PathSocket").field("me", &self.me).finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for PathSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(WritablePoller { paths: Arc::clone(&self.paths), waiting: None })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // QUIC 库只会往它见过的地址发包，而它见过的都是虚拟地址；别的丢掉，和发到一个不通的地址没有区别。
        let Some(peer) = node_of(transmit.destination) else { return Ok(()) };
        let packets = Packets { contents: transmit.contents, segment_size: transmit.segment_size, ecn: transmit.ecn.map(ecn_from_quic) };
        self.paths.try_send(peer, &packets)
    }

    fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let mut metas = [PacketMeta { peer: self.me, len: 0, stride: 0, ecn: None }; BATCH_SIZE];
        let limit = bufs.len().min(meta.len()).min(BATCH_SIZE);
        let count = ready!(self.paths.poll_recv(cx, &mut bufs[..limit], &mut metas[..limit]))?;
        for ((out, packet), buf) in meta.iter_mut().zip(&metas[..count]).zip(bufs.iter_mut()) {
            // 整个缓冲区都是封好的包时长度是 0，QUIC 库就当这一格是空的。
            let len = self.inbox.sift(packet.peer, &mut buf[..packet.len], packet.stride);
            *out = RecvMeta { addr: virtual_addr(packet.peer), len, stride: packet.stride, ecn: packet.ecn.map(ecn_to_quic), dst_ip: None };
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // QUIC 库拿它判断地址族：虚拟地址都是 IPv6 的，和真实的端口绑在什么地址上无关。
        Ok(virtual_addr(self.me))
    }

    fn max_transmit_segments(&self) -> usize {
        self.paths.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.paths.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.paths.may_fragment()
    }
}

type Writable = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

/// QUIC 库在 `try_send` 返回 `WouldBlock` 后通过它等待端口恢复可写。每条连接各自持有一个实例，需支持并发等待。
struct WritablePoller {
    paths: Arc<Paths>,
    waiting: Option<Writable>,
}

impl fmt::Debug for WritablePoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WritablePoller").finish_non_exhaustive()
    }
}

impl UdpPoller for WritablePoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let waiting = this.waiting.get_or_insert_with(|| {
            let paths = Arc::clone(&this.paths);
            Box::pin(async move { paths.writable().await })
        });
        let result = ready!(waiting.as_mut().poll(cx));
        this.waiting = None;
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_node_has_its_own_virtual_address_and_it_maps_back() {
        for raw in [1, 2, 258, 0x0102_0304, u32::MAX] {
            let id = NodeId::new(raw).unwrap();
            let addr = virtual_addr(id);
            assert!(addr.is_ipv6());
            assert_eq!(node_of(addr), Some(id), "{addr}");
        }
        assert_eq!(virtual_addr(NodeId::new(0x0102_0304).unwrap()).to_string(), "[fd69:3374::102:304]:20330");
    }

    #[test]
    fn real_addresses_are_not_mistaken_for_virtual_ones() {
        for addr in ["203.0.113.7:20330", "[2001:db8::1]:20330", "[fd69:3374::1]:20331", "[fd69:3374:1::1]:20330", "[fd69:3374::]:20330"] {
            assert_eq!(node_of(addr.parse().unwrap()), None, "{addr}");
        }
    }
}
