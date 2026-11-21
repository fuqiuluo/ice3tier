//! 收发每个包时要查的东西：到每个对端现在走哪条路，哪些来源地址是谁。
//!
//! 这些由控制任务（[`crate::control`]）写，由收发包的路径读。发包时只查"现在走哪条路"这一个结果，不做别的判断。

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use i3t_model::control::Signal;
use i3t_proto::NodeId;
use i3t_proto::datagram::{RelayHeader, RouteHeader};
use i3t_proto::probe::TestId;
use i3t_underlay::lan::LanDiscovery;
use i3t_underlay::tcp_leg::FrameSender;
use i3t_underlay::{Ecn, Transmit, UdpPort};
use tokio::sync::{Notify, broadcast, mpsc};

use crate::backbone::Gates;
use crate::control::{Ctrl, Inbound};
use crate::timing::{PEER_ACTIVE, SILENCE, STASH_MAX_AGE, UNANSWERED_WINDOW};
use crate::{LocalRelay, RouteChange, Status};

/// 路可疑或者没有路的时候，留着最后几个包，路恢复时立刻补发。
const STASH_PACKETS: usize = 4;
/// 多久没有收到对端的包，就开始把发出去的包多留一份。比连接正常时两个确认之间的间隔长得多。
const STASH_WHEN_SILENT: Duration = Duration::from_millis(500);
/// 对端头一次、或者静默了 [`STASH_WHEN_SILENT`] 以上之后又发来包，之后这么久之内发给它的包也多留一份。
///
/// 这时两头的路往往还在定：对端刚重启、刚连上来，它在各个 relay 上的会话陆续建起来，本节点到它的路还会换一两次
/// （relay 回"对端没挂在我这里"，或者更好的中转会话建好了）。回给它的头几个包（握手的应答、第一条流的回答）恰好在这时发出，
/// 发出时对端刚说过话，不算可疑，以前不留底；路紧接着一换，它们留在了走不通的旧路上，连接只能等自己的重传：握手阶段 1 秒，
/// 之后至少三个往返，而且每丢一次加倍。实验环境里量到（只有 TCP、往返 250ms 的节点重启后马上开流）：对端的应答经它还没挂上的
/// relay 发出，0.1 毫秒到 150 毫秒之后换路，握手从 0.25 秒拖到 1.25 秒。留了底，换路时随补发一起从新路出去。
/// 两秒盖得住慢路上的头几个往返；这段时间里只是多拷几个包，换路时多补发几个重复的包。
const STASH_AFTER_CONTACT: Duration = Duration::from_secs(2);

/// 连接层交下来的一批包：一个，或者若干个等长的首尾相接（最后一个可以短）。
#[derive(Debug, Clone, Copy)]
pub struct Packets<'a> {
    pub contents: &'a [u8],
    /// 每个包的长度；只有一个包时是 `None`。
    pub segment_size: Option<usize>,
    pub ecn: Option<Ecn>,
}

impl<'a> Packets<'a> {
    fn segments(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        self.contents.chunks(self.segment_size.unwrap_or(self.contents.len()).max(1))
    }
}

/// 一批包里没有发出去的那一部分。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Unsent {
    pub packets: usize,
    pub bytes: usize,
}

impl Unsent {
    /// 都发出去了。
    pub const NONE: Self = Self { packets: 0, bytes: 0 };

    /// 一个都没有发出去。
    pub(crate) fn all(packets: &Packets<'_>) -> Self {
        Self { packets: packets.segments().count(), bytes: packets.contents.len() }
    }

    fn unless(sent: bool, packets: &Packets<'_>) -> Self {
        if sent { Self::NONE } else { Self::all(packets) }
    }
}

/// 从进程启动算起的毫秒数，够用来比较"多久之前"，又能放进一个原子变量。
#[derive(Debug)]
pub(crate) struct Clock(Instant);

impl Clock {
    pub(crate) fn new() -> Self {
        Self(Instant::now())
    }

    /// 最小是 1：0 留给"从来没有过"。
    fn now(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX).saturating_add(1)
    }
}

/// 某件事最近一次发生的时刻。收发包的路径上只写一个原子变量。
#[derive(Debug, Default)]
pub(crate) struct Stamp(AtomicU64);

impl Stamp {
    pub(crate) fn touch(&self, clock: &Clock) {
        self.0.store(clock.now(), Ordering::Relaxed);
    }

    /// 距离上一次过了多久；从来没有过时返回 `None`。
    pub(crate) fn elapsed(&self, clock: &Clock) -> Option<Duration> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            at => Some(Duration::from_millis(clock.now().saturating_sub(at))),
        }
    }

    /// 是不是在最近 `window` 之内发生过。
    pub(crate) fn within(&self, clock: &Clock, window: Duration) -> bool {
        self.elapsed(clock).is_some_and(|elapsed| elapsed < window)
    }

    /// 这件事是不是比 `other` 晚发生（精确到毫秒；`other` 从来没有发生过也算）。
    pub(crate) fn is_after(&self, other: &Self) -> bool {
        self.0.load(Ordering::Relaxed) > other.0.load(Ordering::Relaxed)
    }
}

/// 发出去的包有没有落空：`tx` 之后再没有 `rx`，而且已经静了一阵。
///
/// 连接在传数据时对面的确认是连续不断的，所以"发了却一直没有回音"很能说明路断了。
/// 只看最近发过的：连接的重传在断路期间会退避到几秒一次，窗口要比探测间隔长才接得上。
pub(crate) fn unanswered(clock: &Clock, tx: &Stamp, rx: &Stamp) -> bool {
    tx.is_after(rx) && tx.within(clock, UNANSWERED_WINDOW) && !rx.within(clock, SILENCE)
}

/// 一个 relay 在收发路径上的记录。
#[derive(Debug)]
pub(crate) struct RelaySlot {
    pub(crate) id: NodeId,
    /// 最近一次从它收到任何东西。
    pub(crate) last_rx: Stamp,
    /// 最近一次经它发包。
    pub(crate) last_tx: Stamp,
}

impl RelaySlot {
    pub(crate) fn new(id: NodeId) -> Arc<Self> {
        Arc::new(Self { id, last_rx: Stamp::default(), last_tx: Stamp::default() })
    }
}

/// 经 relay 的包前面要加的头，已经编码好。只经一个 relay 时是 9 字节的那一种，经多个时带着整条路径。
#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameHeader {
    len: usize,
    bytes: [u8; RouteHeader::MAX_LEN],
}

impl FrameHeader {
    /// 经一个 relay：老的格式，relay 不用升级也认识。
    pub(crate) fn single(header: RelayHeader) -> Self {
        let mut bytes = [0; RouteHeader::MAX_LEN];
        bytes[..RelayHeader::LEN].copy_from_slice(&header.to_bytes());
        Self { len: RelayHeader::LEN, bytes }
    }

    /// 经多个 relay。
    pub(crate) fn routed(header: &RouteHeader) -> Self {
        let encoded = header.to_bytes();
        let mut bytes = [0; RouteHeader::MAX_LEN];
        bytes[..encoded.len()].copy_from_slice(&encoded);
        Self { len: encoded.len(), bytes }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// 发给一个对端的包此刻怎么送。
#[derive(Debug)]
pub(crate) enum Hop {
    /// 没有路，包被丢掉。
    None,
    Direct(SocketAddr),
    /// 加上 `header` 发给路径上第一个 relay 的 UDP 地址。
    RelayUdp {
        relay: Arc<RelaySlot>,
        addr: SocketAddr,
        header: FrameHeader,
    },
    /// 加上 `header` 写进到第一个 relay 的那条 TCP。
    RelayTcp {
        relay: Arc<RelaySlot>,
        sender: FrameSender,
        header: FrameHeader,
    },
    /// 对端挂在本节点自己的 relay 上，直接交给它的会话。
    Local,
}

#[derive(Debug)]
struct SlotInner {
    hop: Hop,
    /// 给经 relay 的包加头时用的缓冲，免得每次发送都分配。
    scratch: Vec<u8>,
    stash: VecDeque<(Instant, Vec<u8>)>,
}

/// 一个对端在收发路径上的记录。
#[derive(Debug)]
pub(crate) struct PeerSlot {
    pub(crate) id: NodeId,
    /// 连接层最近一次有包要发给它（不管有没有路）。
    pub(crate) last_tx: Stamp,
    /// 最近一次有人明确表示要和它通信：上层准备拨号，或者它发来了打洞信令。
    pub(crate) last_demand: Stamp,
    /// 最近一次从它的直连地址收到东西。
    pub(crate) last_rx_direct: Stamp,
    /// 最近一次收到它的连接包，不管从哪条路来的。
    pub(crate) last_rx: Stamp,
    /// 最近一次它头一次、或者静默了一阵之后又发来包的时刻，见 [`STASH_AFTER_CONTACT`]。
    contact: Stamp,
    /// 当前的路可疑（探测没有回答），或者根本没有路。这时发的包多留一份，见 [`PeerSlot::flush`]。
    doubt: AtomicBool,
    inner: Mutex<SlotInner>,
}

impl PeerSlot {
    pub(crate) fn new(id: NodeId) -> Arc<Self> {
        Arc::new(Self {
            id,
            last_tx: Stamp::default(),
            last_demand: Stamp::default(),
            last_rx_direct: Stamp::default(),
            last_rx: Stamp::default(),
            contact: Stamp::default(),
            doubt: AtomicBool::new(true),
            inner: Mutex::new(SlotInner { hop: Hop::None, scratch: Vec::new(), stash: VecDeque::new() }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SlotInner> {
        self.inner.lock().expect("peer slot mutex poisoned")
    }

    pub(crate) fn set_hop(&self, hop: Hop) {
        self.lock().hop = hop;
    }

    /// 这个对端是不是活跃的：最近有包要发给它，或者有人要和它通信。
    /// 只有活跃的对端才值得探测直连、为它保持临时的中转会话。
    pub(crate) fn is_active(&self, clock: &Clock) -> bool {
        self.last_tx.within(clock, PEER_ACTIVE) || self.last_demand.within(clock, PEER_ACTIVE)
    }

    /// 收到了它的一个连接包（不管从哪条路来的）。
    ///
    /// 它静默了 [`SILENCE`] 以上又出现时，把留着的包补发一遍（见 [`flush`](Self::flush)）。路断的时候两头都在退避：
    /// 恢复路的那一头会补发自己的包，可另一头的路一直是"通的"（比如它到 relay 的那一段没断，断的是对端到 relay 的那一段），
    /// 它不知道路恢复了，只能等自己退避到很久之后的下一次重传。实测（对端经 TCP 中转、那一段断开 20 秒）：发数据的这一头
    /// 被拥塞窗口卡着，连收到的包都不确认，对端的连接 30 秒没有收到任何东西，空闲超时断掉。对端的包一到就补发，
    /// 它收到之后回确认，两头的丢包检测都立刻恢复。没断过的连接两次保活之间也会补发一两个重复的小包，代价可以忽略。
    ///
    /// 它头一次、或者静默了 [`STASH_WHEN_SILENT`] 以上之后又发来包时，之后一小段时间里发给它的包也留底（[`STASH_AFTER_CONTACT`]）。
    pub(crate) fn received(&self, shared: &Shared) {
        let silent = self.last_rx.elapsed(&shared.clock);
        self.last_rx.touch(&shared.clock);
        if silent.is_none_or(|silent| silent >= STASH_WHEN_SILENT) {
            self.contact.touch(&shared.clock);
        }
        if silent.is_some_and(|silent| silent >= SILENCE) {
            self.flush(shared, Instant::now());
        }
    }

    /// 现在有没有路。
    pub(crate) fn has_hop(&self) -> bool {
        !matches!(self.lock().hop, Hop::None)
    }

    pub(crate) fn set_doubt(&self, doubt: bool) {
        self.doubt.store(doubt, Ordering::Relaxed);
    }

    /// 连接层的发送。没有路时包被悄悄丢掉。
    ///
    /// # Errors
    ///
    /// 只会返回 [`io::ErrorKind::WouldBlock`]：UDP 的发送缓冲区满了。
    pub(crate) fn send(&self, shared: &Shared, packets: &Packets<'_>) -> io::Result<()> {
        self.last_tx.touch(&shared.clock);
        let mut inner = self.lock();
        let SlotInner { hop, scratch, stash } = &mut *inner;
        // 路可疑、没有路，或者有一阵没有收到对端的任何包了，或者对端刚刚（又）出现：这个包多留一份。
        // 连接正常传数据时不会走到这里，因为对面的确认是连续不断的。
        let clock = &shared.clock;
        let suspicious = self.doubt.load(Ordering::Relaxed)
            || !self.last_rx.within(clock, STASH_WHEN_SILENT)
            || self.contact.within(clock, STASH_AFTER_CONTACT);
        if suspicious && let Some(last) = packets.segments().last() {
            // 放满了就挪用最旧的那一份的缓冲，不再分配。
            let mut copy =
                if stash.len() == STASH_PACKETS { stash.pop_front().map(|(_, copy)| copy).unwrap_or_default() } else { Vec::new() };
            copy.clear();
            copy.extend_from_slice(last);
            stash.push_back((Instant::now(), copy));
        }
        match hop {
            Hop::None => Ok(()),
            Hop::Direct(addr) => shared.port.try_send(&Transmit {
                destination: *addr,
                contents: packets.contents,
                segment_size: packets.segment_size,
                ecn: packets.ecn,
            }),
            Hop::RelayUdp { relay, addr, header } => {
                relay.last_tx.touch(&shared.clock);
                let transmit = framed(header.as_slice(), scratch, packets, *addr);
                shared.port.try_send(&transmit)
            }
            Hop::RelayTcp { relay, sender, header } => {
                relay.last_tx.touch(&shared.clock);
                for packet in packets.segments() {
                    // 队列满了就丢：让连接看到丢包，而不是越积越多的延迟。
                    sender.try_send(frame(header.as_slice(), packet));
                }
                Ok(())
            }
            Hop::Local => {
                let transmit = framed(&self.header(shared), scratch, packets, shared.port.local_addr());
                if let Some(relay) = shared.local_relay.get() {
                    relay.send_to_client(self.id, transmit.contents, transmit.segment_size, transmit.ecn);
                }
                Ok(())
            }
        }
    }

    /// 发一批丢了也没关系的包（封好的网络包），不等，也不留底：端口忙着、经 TCP 中转时队列满了，或者没有路，
    /// 发不出去的就丢掉。返回没有发出去的那一部分。
    ///
    /// 它直接问内核，不走 [`send`](Self::send) 用的那个入口。那个入口是给会等"可写"的连接用的：内核说过一次
    /// "现在发不了"之后，运行时记下端口不可写，到它收到下一次可写的通知之前，再来的包不问内核就当作发不了。
    /// 连接会等；不等的调用方在这段时间里一个包也发不出去，尽管内核一有地方就能收。
    ///
    /// 不留底：这样的包本来就不保证送达，补发一个过了时的没有用，还会把连接自己的包从留底里挤出去。
    pub(crate) fn send_or_drop(&self, shared: &Shared, packets: &Packets<'_>) -> Unsent {
        self.last_tx.touch(&shared.clock);
        let mut inner = self.lock();
        let SlotInner { hop, scratch, .. } = &mut *inner;
        match hop {
            Hop::None => Unsent::all(packets),
            Hop::Direct(addr) => {
                let sent = shared.port.send_or_drop(&Transmit {
                    destination: *addr,
                    contents: packets.contents,
                    segment_size: packets.segment_size,
                    ecn: packets.ecn,
                });
                Unsent::unless(sent, packets)
            }
            Hop::RelayUdp { relay, addr, header } => {
                relay.last_tx.touch(&shared.clock);
                let sent = shared.port.send_or_drop(&framed(header.as_slice(), scratch, packets, *addr));
                Unsent::unless(sent, packets)
            }
            Hop::RelayTcp { relay, sender, header } => {
                relay.last_tx.touch(&shared.clock);
                let mut unsent = Unsent::NONE;
                // 队列满了也接着试后面的：中间可能正好腾出了位置。
                for packet in packets.segments() {
                    if !sender.try_send(frame(header.as_slice(), packet)) {
                        unsent.packets += 1;
                        unsent.bytes += packet.len();
                    }
                }
                unsent
            }
            Hop::Local => {
                let transmit = framed(&self.header(shared), scratch, packets, shared.port.local_addr());
                // 那边只说是不是全送出去了：有一个没送出去，这一批就都算没发。
                let sent = shared
                    .local_relay
                    .get()
                    .is_some_and(|relay| relay.send_to_client(self.id, transmit.contents, transmit.segment_size, transmit.ecn));
                Unsent::unless(sent, packets)
            }
        }
    }

    /// 路恢复了（可疑的路又通了，或者换了一条路，包括从没有路到有路）：把留着的包从现在这条路补发出去。
    ///
    /// 连接在路断着的时候重传定时器会退避到几秒一次（实测：断 3 秒，数据到第 6 秒才恢复）。连接库没有
    /// "现在就发一个包"的接口，而且拥塞窗口被断路之前发出去的包占着，新的包也发不出去。补发断路期间最后的几个包
    /// 就够了：对面收到之后回确认，这边的丢包检测和重传立刻恢复。补发的包对面要是已经收到过，会被当作重复的丢掉，没有害处。
    ///
    /// 补发之后包还留着，直到放满 [`STASH_MAX_AGE`]：恢复的过程中路常常要换好几次（经 TCP 的中转刚连上又断了，
    /// 或者先换到 relay、再换到直连），中间那条路要是没送到，下一次恢复时还得再补发一遍。在实际链路上见过：
    /// 补发的包都交给了一条马上又断掉的路，等真正能用的路回来时手上已经没有可补的，连接又干等了 4 秒，等它自己的重传。
    /// 多补发几次的代价只是对面多收到几个重复的包。
    pub(crate) fn flush(&self, shared: &Shared, now: Instant) {
        let mut inner = self.lock();
        let SlotInner { hop, scratch, stash } = &mut *inner;
        stash.retain(|(stashed, _)| now.saturating_duration_since(*stashed) <= STASH_MAX_AGE);
        for (_, packet) in stash.iter() {
            self.emit(shared, hop, scratch, packet);
        }
    }

    /// 把路径层自己的一个帧从现在这条路送给对端：经 relay 时和连接包一样套上中转头，直连时原样发。
    /// 端到端的路径探测靠它走和连接包完全相同的路。它不算连接层的流量：不动"最近发过包"的记录，也不留底。
    /// 没有路时什么都不做。
    pub(crate) fn send_frame(&self, shared: &Shared, frame: &[u8]) {
        let mut inner = self.lock();
        let SlotInner { hop, scratch, .. } = &mut *inner;
        self.emit(shared, hop, scratch, frame);
    }

    /// 从 `hop` 这条路发一个包。尽力而为：发不出去就算了。
    fn emit(&self, shared: &Shared, hop: &Hop, scratch: &mut Vec<u8>, packet: &[u8]) {
        emit(shared, self.id, hop, scratch, packet);
    }

    fn header(&self, shared: &Shared) -> [u8; RelayHeader::LEN] {
        RelayHeader { dst: self.id, src: shared.me }.to_bytes()
    }
}

/// 从 `hop` 这条路给对端 `peer` 发路径层自己的一个帧，不管这条路是不是它现在走的。主动测试从指定的路径回答探测时用它。
/// 尽力而为：发不出去就算了。
pub(crate) fn send_frame_via(shared: &Shared, peer: NodeId, hop: &Hop, frame: &[u8]) {
    emit(shared, peer, hop, &mut Vec::new(), frame);
}

fn emit(shared: &Shared, peer: NodeId, hop: &Hop, scratch: &mut Vec<u8>, packet: &[u8]) {
    let packets = Packets { contents: packet, segment_size: None, ecn: None };
    match hop {
        Hop::None => {}
        Hop::Direct(addr) => {
            let _sent = shared.port.send_or_drop(&Transmit { destination: *addr, contents: packet, segment_size: None, ecn: None });
        }
        Hop::RelayUdp { addr, header, .. } => {
            let _sent = shared.port.send_or_drop(&framed(header.as_slice(), scratch, &packets, *addr));
        }
        Hop::RelayTcp { sender, header, .. } => {
            let _queued = sender.try_send(frame(header.as_slice(), packet));
        }
        Hop::Local => {
            let header = RelayHeader { dst: peer, src: shared.me }.to_bytes();
            let transmit = framed(&header, scratch, &packets, shared.port.local_addr());
            if let Some(relay) = shared.local_relay.get() {
                relay.send_to_client(peer, transmit.contents, transmit.segment_size, transmit.ecn);
            }
        }
    }
}

/// 给每个包加上中转头，放进 `scratch`。每个包都多了同样长的头，所以仍然是等长的，分段卸载照样能用。
fn framed<'a>(header: &[u8], scratch: &'a mut Vec<u8>, packets: &Packets<'_>, destination: SocketAddr) -> Transmit<'a> {
    scratch.clear();
    for packet in packets.segments() {
        scratch.extend_from_slice(header);
        scratch.extend_from_slice(packet);
    }
    Transmit { destination, contents: scratch, segment_size: packets.segment_size.map(|size| size + header.len()), ecn: packets.ecn }
}

fn frame(header: &[u8], packet: &[u8]) -> Bytes {
    let mut datagram = BytesMut::with_capacity(header.len() + packet.len());
    datagram.put_slice(header);
    datagram.put_slice(packet);
    datagram.freeze()
}

/// 收包时按来源地址查的表。
#[derive(Debug, Default)]
pub(crate) struct Table {
    pub(crate) peers: HashMap<NodeId, Arc<PeerSlot>>,
    /// 这些地址来的连接包算作这个对端的。只有收到过对端签了名的探测帧的地址才在这里。
    pub(crate) direct: HashMap<SocketAddr, Arc<PeerSlot>>,
    /// netmap 里各个 relay 的 UDP 地址。只有这些地址来的中转帧才收。
    pub(crate) relays: HashMap<SocketAddr, Arc<RelaySlot>>,
}

/// 把信令送出去的钩子，由装配的一方提供。
pub(crate) type SignalHook = Arc<dyn Fn(NodeId, &Signal) + Send + Sync>;

/// 收发路径和控制任务共用的全部状态。
pub(crate) struct Shared {
    pub(crate) me: NodeId,
    pub(crate) port: Arc<UdpPort>,
    pub(crate) clock: Clock,
    pub(crate) table: RwLock<Table>,
    /// 交给控制任务的事：TCP 中转腿的事件、信令、端口映射、关机、唤醒。
    pub(crate) ctrl: mpsc::Sender<Ctrl>,
    /// 收包路径认出来的、从 relay 的地址来的帧（会话的应答和错误帧、矩阵的行）。和下面的分开排队：
    /// 不认识的人往本节点灌探测，挤不掉 relay 的应答。
    pub(crate) from_relays: mpsc::Sender<Ctrl>,
    /// 收包路径认出来的别的帧（探测、地址查询的应答），以及局域网里看到的信标。
    pub(crate) from_peers: mpsc::Sender<Ctrl>,
    /// 不是直接从 UDP 端口读进连接层缓冲区的包：TCP 中转来的、本节点的 relay 交过来的、一批里放不下的。
    pub(crate) inbound: mpsc::Sender<(NodeId, Bytes)>,
    pub(crate) inbound_rx: Mutex<mpsc::Receiver<(NodeId, Bytes)>>,
    pub(crate) local_relay: OnceLock<Arc<dyn LocalRelay>>,
    /// 骨干上走着 TCP 的那几段，本节点的 relay 经 [`crate::BackboneInbox`] 问（见 [`crate::backbone`]）。
    pub(crate) gates: Arc<Gates>,
    pub(crate) signal_hook: RwLock<Option<SignalHook>>,
    pub(crate) changes: broadcast::Sender<RouteChange>,
    /// 任何一个对端的路变了就通知一次，等路的人靠它醒来。
    pub(crate) route_changed: Notify,
    pub(crate) status: Mutex<Status>,
    /// 局域网发现。绑在具体地址上的端口（测试）不自动开，要调用方明确要求。
    pub(crate) lan: Mutex<Option<LanDiscovery>>,
    /// 打开着的主动测试和它们的对端。收包路径凭它把不属于任何测试的测试探测当场丢掉，不进控制任务的队列。
    pub(crate) open_tests: RwLock<HashSet<(TestId, NodeId)>>,
}

impl Shared {
    pub(crate) fn table(&self) -> std::sync::RwLockReadGuard<'_, Table> {
        self.table.read().expect("path table lock poisoned")
    }

    pub(crate) fn table_mut(&self) -> std::sync::RwLockWriteGuard<'_, Table> {
        self.table.write().expect("path table lock poisoned")
    }

    /// 把收到的一帧放进控制任务对应的队列。队列满了就丢掉，返回 `false`：它们都是有重试的握手和探测。
    pub(crate) fn queue_frame(&self, from: SocketAddr, frame: Inbound) -> bool {
        let queue = match frame {
            Inbound::Session(_) | Inbound::Refusal(..) | Inbound::Row(_) => &self.from_relays,
            Inbound::Probe(_) | Inbound::AddrReply(_) | Inbound::PathProbe { .. } | Inbound::Test { .. } => &self.from_peers,
        };
        queue.try_send(Ctrl::Frame { from, frame }).is_ok()
    }

    /// 有没有和 `peer` 之间编号是 `test` 的测试打开着。
    pub(crate) fn expects_test(&self, test: TestId, peer: NodeId) -> bool {
        self.open_tests.read().expect("open tests lock poisoned").contains(&(test, peer))
    }

    pub(crate) fn send_signal(&self, to: NodeId, signal: &Signal) {
        let hook = self.signal_hook.read().expect("signal hook lock poisoned").clone();
        if let Some(hook) = hook {
            hook(to, signal);
        }
    }
}

#[cfg(test)]
impl Shared {
    /// 测试用：一份绑在 `port` 上的共用状态，和控制任务那三个队列的接收端（没有人在读它们）。帧的两个队列各只装得下 `frames` 个。
    pub(crate) fn for_tests(me: NodeId, port: Arc<UdpPort>, frames: usize) -> (Arc<Self>, [mpsc::Receiver<Ctrl>; 3]) {
        let (ctrl, ctrl_rx) = mpsc::channel(16);
        let (from_relays, from_relays_rx) = mpsc::channel(frames);
        let (from_peers, from_peers_rx) = mpsc::channel(frames);
        let (inbound, inbound_rx) = mpsc::channel(16);
        let shared = Arc::new(Self {
            me,
            port,
            clock: Clock::new(),
            table: RwLock::new(Table::default()),
            ctrl,
            from_relays,
            from_peers,
            inbound,
            inbound_rx: Mutex::new(inbound_rx),
            local_relay: OnceLock::new(),
            gates: Arc::default(),
            signal_hook: RwLock::new(None),
            changes: broadcast::Sender::new(16),
            route_changed: Notify::new(),
            status: Mutex::new(Status::default()),
            lan: Mutex::new(None),
            open_tests: RwLock::default(),
        });
        (shared, [ctrl_rx, from_relays_rx, from_peers_rx])
    }
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").field("me", &self.me).field("port", &self.port.local_addr()).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> Arc<Shared> {
        shared_with_queues().0
    }

    /// 帧的两个队列各只装得下一个。
    fn shared_with_queues() -> (Arc<Shared>, [mpsc::Receiver<Ctrl>; 3]) {
        Shared::for_tests(NodeId::new(1).unwrap(), Arc::new(UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap()), 1)
    }

    /// 从 `receiver` 收一个数据报，等不到就是 `None`。
    async fn receive(receiver: &UdpPort) -> Option<Vec<u8>> {
        let mut storage = vec![0u8; 2048 * receiver.gro_segments()];
        let mut metas = [i3t_underlay::RecvMeta::default(); 1];
        let mut bufs = [std::io::IoSliceMut::new(&mut storage)];
        let received = tokio::time::timeout(Duration::from_millis(300), receiver.recv(&mut bufs, &mut metas)).await.ok()?.ok()?;
        (received == 1).then(|| bufs[0][..metas[0].len].to_vec())
    }

    #[tokio::test]
    async fn packets_kept_while_the_route_was_down_are_resent_again_when_the_first_route_back_fails_too() {
        let shared = shared();
        let slot = PeerSlot::new(NodeId::new(2).unwrap());
        // 没有路：连接层发的包被丢掉，最后几个留着。
        for byte in 1..=2u8 {
            slot.send(&shared, &Packets { contents: &[byte; 100], segment_size: None, ecn: None }).unwrap();
        }
        // 路回来了，补发。但这条路马上又断了（比如经 TCP 的中转刚连上就断开），补发的包没有送到。
        let lost = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        slot.set_hop(Hop::Direct(lost.local_addr()));
        let now = Instant::now();
        slot.flush(&shared, now);
        assert_eq!(receive(&lost).await, Some(vec![1; 100]));
        assert_eq!(receive(&lost).await, Some(vec![2; 100]));
        slot.set_hop(Hop::None);

        // 能用的路回来了：手上还有可以补发的包。
        let working = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        slot.set_hop(Hop::Direct(working.local_addr()));
        slot.flush(&shared, now + Duration::from_secs(4));
        assert_eq!(receive(&working).await, Some(vec![1; 100]));
        assert_eq!(receive(&working).await, Some(vec![2; 100]));

        // 留得太久的不再补发：对面拿它算出来的延迟没有意义。
        slot.flush(&shared, now + STASH_MAX_AGE + Duration::from_secs(1));
        assert_eq!(receive(&working).await, None);
    }

    #[tokio::test]
    async fn packets_kept_while_the_peer_was_silent_are_resent_when_it_is_heard_from_again() {
        let shared = shared();
        let receiver = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let slot = PeerSlot::new(NodeId::new(2).unwrap());
        slot.set_hop(Hop::Direct(receiver.local_addr()));
        slot.received(&shared);
        // 对端一直没有回音：路"通着"，包照样发出去（这里收到的是第一次发送），同时留了底。
        tokio::time::sleep(STASH_WHEN_SILENT + Duration::from_millis(50)).await;
        slot.send(&shared, &Packets { contents: &[7; 100], segment_size: None, ecn: None }).unwrap();
        assert_eq!(receive(&receiver).await, Some(vec![7; 100]));
        tokio::time::sleep(SILENCE).await;
        // 对端又出现了：留着的包再发一遍。
        slot.received(&shared);
        assert_eq!(receive(&receiver).await, Some(vec![7; 100]), "静默之后对端的包一到就补发");
        // 包连续地来的时候不补发。
        slot.received(&shared);
        assert_eq!(receive(&receiver).await, None);
    }

    #[tokio::test]
    async fn packets_answering_a_peer_that_just_appeared_are_resent_when_the_route_moves_right_after() {
        let shared = shared();
        // 回给对端的路其实走不通（对端还没挂到这个 relay 上），只是本节点还不知道。
        let dead = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let slot = PeerSlot::new(NodeId::new(2).unwrap());
        slot.set_hop(Hop::Direct(dead.local_addr()));
        slot.set_doubt(false);
        // 对端头一次发来包，本节点马上回答：发出时刚收到它的包，路也不可疑。
        slot.received(&shared);
        shared.port.writable().await.unwrap();
        slot.send(&shared, &Packets { contents: &[3; 100], segment_size: None, ecn: None }).unwrap();
        assert_eq!(receive(&dead).await, Some(vec![3; 100]));
        // relay 回"它没挂在我这里"，路紧接着换了：回答要跟着从新路补发出去，不能只等连接自己的重传。
        let working = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        slot.set_hop(Hop::Direct(working.local_addr()));
        slot.flush(&shared, Instant::now());
        assert_eq!(receive(&working).await, Some(vec![3; 100]));

        // 静默了一阵又出现的对端也一样。
        tokio::time::sleep(STASH_WHEN_SILENT).await;
        slot.received(&shared);
        shared.port.writable().await.unwrap();
        slot.send(&shared, &Packets { contents: &[4; 100], segment_size: None, ecn: None }).unwrap();
        assert_eq!(receive(&working).await, Some(vec![4; 100]));
        slot.flush(&shared, Instant::now());
        assert_eq!(receive(&working).await, Some(vec![3; 100]), "先留的先补发");
        assert_eq!(receive(&working).await, Some(vec![4; 100]));
    }

    #[tokio::test]
    async fn a_peer_that_keeps_talking_is_not_copied_once_the_first_exchanges_are_over() {
        let shared = shared();
        let receiver = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let slot = PeerSlot::new(NodeId::new(2).unwrap());
        slot.set_hop(Hop::Direct(receiver.local_addr()));
        slot.set_doubt(false);
        slot.received(&shared);
        assert!(slot.contact.within(&shared.clock, STASH_AFTER_CONTACT), "头一次收到它的包：开始留底");
        // 之后它一直在说话（间隔不到半秒），过了那一小段时间就不再留底，正常的流量不多拷一份。
        let mut waited = Duration::ZERO;
        while waited <= STASH_AFTER_CONTACT {
            tokio::time::sleep(Duration::from_millis(200)).await;
            waited += Duration::from_millis(200);
            slot.received(&shared);
        }
        assert!(!slot.contact.within(&shared.clock, STASH_AFTER_CONTACT));
        assert!(slot.lock().stash.is_empty());
        shared.port.writable().await.unwrap();
        slot.send(&shared, &Packets { contents: &[5; 100], segment_size: None, ecn: None }).unwrap();
        assert!(slot.lock().stash.is_empty(), "连接正常时不留底");
    }

    #[tokio::test]
    async fn packets_that_may_be_dropped_go_straight_to_the_kernel_and_are_never_kept_for_resending() {
        let shared = shared();
        let receiver = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        // 刚建的对端的路是可疑的：连接包这时都留底。
        let slot = PeerSlot::new(NodeId::new(2).unwrap());
        slot.set_hop(Hop::Direct(receiver.local_addr()));
        // 端口刚绑定，运行时还没有收到它的头一次"可写"通知，在它看来端口是不可写的，和内核说过一次"现在发不了"之后一样。
        // 这里故意不等可写：经过运行时的那个入口这时一个包也发不出去。
        let packets = Packets { contents: &[6; 100], segment_size: None, ecn: None };
        assert_eq!(slot.send_or_drop(&shared, &packets), Unsent::NONE);
        assert_eq!(receive(&receiver).await, Some(vec![6; 100]));
        assert!(slot.lock().stash.is_empty(), "丢了也没关系的包不留底");
        slot.send(&shared, &Packets { contents: &[0x40; 100], segment_size: None, ecn: None }).unwrap();
        assert_eq!(slot.lock().stash.len(), 1, "同样的时候连接包是留的");
    }

    #[tokio::test]
    async fn packets_dropped_for_want_of_a_route_or_of_room_in_a_tcp_relay_queue_are_reported() {
        let shared = shared();
        let slot = PeerSlot::new(NodeId::new(2).unwrap());
        let packets = Packets { contents: &[6; 250], segment_size: Some(100), ecn: None };
        assert_eq!(slot.send_or_drop(&shared, &packets), Unsent { packets: 3, bytes: 250 }, "没有路");

        // 没有人在写这条 TCP：排进队列的包不会走。
        let (sender, _queue) = i3t_underlay::tcp_leg::frame_queue();
        let header = FrameHeader::single(RelayHeader { dst: slot.id, src: shared.me });
        slot.set_hop(Hop::RelayTcp { relay: RelaySlot::new(NodeId::new(9).unwrap()), sender: sender.clone(), header });
        assert_eq!(slot.send_or_drop(&shared, &packets), Unsent::NONE, "队列里有地方");
        // 把队列填到只剩一个位置：三个包里排得进去的只有头一个。
        for _ in 3..i3t_underlay::tcp_leg::SEND_QUEUE_PACKETS - 1 {
            assert!(sender.try_send(Bytes::new()));
        }
        assert_eq!(slot.send_or_drop(&shared, &packets), Unsent { packets: 2, bytes: 150 }, "后两个没有排进去，其中最后一个是短的");
        assert_eq!(slot.send_or_drop(&shared, &packets), Unsent { packets: 3, bytes: 250 }, "队列满了");
    }

    #[tokio::test]
    async fn a_flood_of_probes_cannot_crowd_relay_replies_out_of_the_control_queues() {
        let (shared, _receivers) = shared_with_queues();
        let from: SocketAddr = "203.0.113.9:4000".parse().unwrap();
        let probe = || {
            let ping = i3t_proto::probe::Ping { src: NodeId::new(2).unwrap(), dst: shared.me, nonce: [1; 8], signature: [0; 64] };
            Inbound::Probe(i3t_proto::probe::Frame::Ping(ping))
        };
        assert!(shared.queue_frame(from, probe()));
        assert!(!shared.queue_frame(from, probe()), "探测的队列满了");
        let challenge = i3t_proto::session::Challenge { nonce: [2; 8], cookie: [3; 16] };
        assert!(shared.queue_frame(from, Inbound::Session(i3t_proto::session::Frame::Challenge(challenge))), "relay 的应答有自己的队列");
    }

    #[tokio::test]
    async fn a_path_layer_frame_takes_the_same_route_as_connection_packets_without_counting_as_traffic() {
        let shared = shared();
        let receiver = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let slot = PeerSlot::new(NodeId::new(2).unwrap());
        // 没有路：什么都不发。
        slot.send_frame(&shared, b"probe");

        // 经 relay：套上和连接包一样的中转头。
        let header = FrameHeader::single(RelayHeader { dst: slot.id, src: shared.me });
        slot.set_hop(Hop::RelayUdp { relay: RelaySlot::new(NodeId::new(9).unwrap()), addr: receiver.local_addr(), header });
        slot.send_frame(&shared, b"probe");
        let mut storage = vec![0u8; 2048 * receiver.gro_segments()];
        let mut metas = [i3t_underlay::RecvMeta::default(); 1];
        let mut bufs = [std::io::IoSliceMut::new(&mut storage)];
        let received = tokio::time::timeout(Duration::from_secs(5), receiver.recv(&mut bufs, &mut metas)).await.unwrap().unwrap();
        assert_eq!(received, 1);
        let expected = [&RelayHeader { dst: slot.id, src: shared.me }.to_bytes()[..], b"probe"].concat();
        assert_eq!(&bufs[0][..metas[0].len], expected);
        assert_eq!(slot.last_tx.elapsed(&shared.clock), None, "探测不算连接层发过包：不活跃的对端不会因为它一直被当成活跃的");
    }

    #[test]
    fn a_frame_header_is_the_single_relay_header_or_the_whole_route() {
        let (me, peer) = (NodeId::new(1).unwrap(), NodeId::new(2).unwrap());
        let single = FrameHeader::single(RelayHeader { dst: peer, src: me });
        assert_eq!(single.as_slice(), RelayHeader { dst: peer, src: me }.to_bytes());
        let relays = i3t_proto::datagram::RelayPath::new(&[NodeId::new(8).unwrap(), NodeId::new(9).unwrap()]).unwrap();
        let header = RouteHeader { dst: peer, src: me, relays };
        assert_eq!(FrameHeader::routed(&header).as_slice(), header.to_bytes());
        assert_eq!(frame(single.as_slice(), b"quic").len(), RelayHeader::LEN + 4);
    }
}
