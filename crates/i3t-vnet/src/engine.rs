//! 网卡和连接之间搬包。两个方向各一个任务：
//!
//! **出去**（本机的程序发出、经网卡读出来的包）：
//!
//! 1. 不是 IPv4 的不管（网卡上没有 IPv6 的地址）；来源不是本节点的虚拟 IP 的丢掉（经这台机器转发过来的别人的包：
//!    对端也会丢，不用白送）。
//! 2. 目的是组播、广播的不管；不在网络地址段里、地址段里不是节点的、对端说它没有网卡的，回 ICMP"主机不可达"：
//!    本机的程序当场知道（连接立刻失败，ping 说不可达），不白等。
//! 3. 访问规则不允许本节点访问它时，新的会话（TCP 的第一个握手包、ping 的请求）回"被管理员禁止"，早一点失败；
//!    别的照发，对端自己按规则收（对端可以访问本节点时，这里发的可能是给它的回包）。对端不能访问本节点时记下发给它的 UDP，
//!    它的回包靠这个才进得来（[`crate::filter`]）。
//! 4. 一个包是一个不保证送达的数据报，走这一对节点之间已有的那条连接；装不下时切成两片（[`crate::pieces`]）。
//!    还没有连接时先建：建的这一会儿发出的包排在一个小队列里（每个对端最多 [`MAX_WAITING`] 个），连上了一起发出去，
//!    第一个 ping 不丢、第一个 TCP 握手包不用等一秒重发；建不起来时给排着的包回"主机不可达"，之后 [`REFUSE_FOR`] 之内
//!    发往它的包当场回"主机不可达"，过了再试。
//!
//! **进来**（对端发来的包）：来源必须是发来它的那个对端的虚拟 IP（连接是按公钥认证的，冒充不了别的节点），目的必须是本节点的
//! 虚拟 IP；对端不被允许访问本节点时只放行回包。不符合的丢掉并计数（[`Counters`]），符合的原样写进网卡，剩下的全是操作系统的事。
//! 另外几条，不管对端能不能访问本节点：
//!
//! - 被切开的 IPv4 包（IP 分片）先攒齐（[`crate::fragments`]），齐了按第一片判断，让进来的几片一起写进网卡：拼不齐的片
//!   不占内核里整台机器共用的拼片缓存，后面的片也不会绕过判断单独进来。切开的 TCP 丢掉（节点之间的 TCP 不会被切）。
//! - ICMP 差错报文（不可达、超时、参数问题）说的必须是本节点发给这个对端的包：覆盖网里节点之间没有路由器，对端只会对
//!   本节点发给它的包回差错报文。不核对的话，对端可以说"到某某（别的节点，甚至这台机器在别的网卡外面要连的地址）的路径 MTU
//!   只有 552"，本机内核照着改路由缓存；也可以让本机别的 UDP 套接字收到一个"连接被拒绝"。被切开的差错报文丢掉。
//! - ICMP 重定向丢掉：没有路由器，也就没有谁该说"换一个下一跳"。
//!
//! 每个包不另外记日志：丢掉的每一种原因第一次记一行，之后每分钟最多一行，带着这段时间丢了多少。

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use i3t_conn::contract::{Datagram, DatagramSendError, OpenError, PacketSender, Packets};
use i3t_model::Netmap;
use i3t_model::control::VnetDrops;
use i3t_proto::NodeId;
use i3t_proto::flow::{Bundled, PacketHeader, PacketPieces};
use ipnet::Ipv4Net;
use tokio::sync::{mpsc, watch};

use crate::device::Device;
use crate::filter::{Replies, Verdict};
use crate::fragments::{Fragments, Gathered};
use crate::ipv4::{Conversation, Ipv4, Malformed, TCP, Unreachable, unreachable};
use crate::pieces::{Assembled, Reassembly};

/// 连接还没建起来时，发往一个对端的包最多排多少个。几个 ping、一次 TCP 握手和 DNS 的往返绰绰有余；多出来的丢掉，
/// 由上面的协议自己重发。
pub const MAX_WAITING: usize = 32;

/// 到一个对端的连接建不起来之后，多久之内发往它的包当场回"主机不可达"、不再去建。
pub const REFUSE_FOR: Duration = Duration::from_secs(3);

/// 每秒最多回多少个"不可达"：本机的程序往一个到不了的地址猛发时，节点不跟着一个一个地回。
const ICMP_PER_SECOND: u32 = 200;

/// 一次从连接层最多取多少个进来的包。
const INBOUND_BATCH: usize = 64;

/// 网卡上读出来的包最长多少（Linux 的 TUN 不会给比 MTU 大的包；留够 IPv4 的上限）。
const READ_BUFFER: usize = u16::MAX as usize;
/// 网卡上现成的包一口气最多读几个再交下去。一条跑满的流因此成批地走，别的事（建好的连接、进来的包）也轮得到。
const OUTBOUND_BURST: usize = 32;

/// 丢掉的包按原因的计数，和收发的计数。上报和本机的状态都读它。
#[derive(Debug, Default)]
pub struct Counters {
    sent_packets: AtomicU64,
    sent_bytes: AtomicU64,
    received_packets: AtomicU64,
    received_bytes: AtomicU64,
    drops: [AtomicU64; Loss::COUNT],
}

/// 丢掉一个包的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loss {
    BadSource,
    BadDestination,
    NotAllowed,
    Unreachable,
    Malformed,
}

impl Loss {
    const COUNT: usize = 5;

    const fn index(self) -> usize {
        match self {
            Self::BadSource => 0,
            Self::BadDestination => 1,
            Self::NotAllowed => 2,
            Self::Unreachable => 3,
            Self::Malformed => 4,
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::BadSource => {
                "来源不对：对端发来的不是它自己的虚拟 IP，或者它的 ICMP 差错报文说的是发往别处的包；或者本机发出的不是本节点的虚拟 IP"
            }
            Self::BadDestination => "目的不对：对端发来的包不是给本节点的虚拟 IP 的，或者它的 ICMP 差错报文说的不是本节点发出的包",
            Self::NotAllowed => "访问规则不允许：对端发起的新会话，或者本节点发起的、对端不让访问的；还有对端发来的 ICMP 重定向",
            Self::Unreachable => "送不到：地址段里没有这个节点、它没有网卡、连不上，或者等连接时排不下",
            Self::Malformed => "读不懂：不是一个完整的 IPv4 包、片拼不起来，或者是不该被切开的包（TCP、ICMP 差错报文）",
        }
    }
}

impl Counters {
    /// 这次运行以来的计数：（发出的包，字节；收进的包，字节；丢掉的）。
    #[must_use]
    pub fn snapshot(&self) -> Traffic {
        let drop = |kind: Loss| self.drops[kind.index()].load(Ordering::Relaxed);
        Traffic {
            sent_packets: self.sent_packets.load(Ordering::Relaxed),
            sent_bytes: self.sent_bytes.load(Ordering::Relaxed),
            received_packets: self.received_packets.load(Ordering::Relaxed),
            received_bytes: self.received_bytes.load(Ordering::Relaxed),
            dropped: VnetDrops {
                bad_source: drop(Loss::BadSource),
                bad_destination: drop(Loss::BadDestination),
                not_allowed: drop(Loss::NotAllowed),
                unreachable: drop(Loss::Unreachable),
                malformed: drop(Loss::Malformed),
            },
        }
    }

    fn sent(&self, bytes: usize) {
        self.sent_packets.fetch_add(1, Ordering::Relaxed);
        self.sent_bytes.fetch_add(count(bytes), Ordering::Relaxed);
    }

    fn received(&self, bytes: usize) {
        self.received_packets.fetch_add(1, Ordering::Relaxed);
        self.received_bytes.fetch_add(count(bytes), Ordering::Relaxed);
    }
}

/// [`Counters::snapshot`] 的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Traffic {
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub received_packets: u64,
    pub received_bytes: u64,
    pub dropped: VnetDrops,
}

fn count(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// 每种原因的丢包日志：第一次记一行，之后每分钟最多一行。
#[derive(Debug, Default)]
struct DropLog {
    last: [Option<(Instant, u64)>; Loss::COUNT],
}

const DROP_LOG_EVERY: Duration = Duration::from_secs(60);

impl DropLog {
    fn note(&mut self, counters: &Counters, kind: Loss, detail: &dyn std::fmt::Display) {
        let total = counters.drops[kind.index()].fetch_add(1, Ordering::Relaxed) + 1;
        let now = Instant::now();
        let slot = &mut self.last[kind.index()];
        if let Some((at, _)) = *slot
            && now.saturating_duration_since(at) < DROP_LOG_EVERY
        {
            return;
        }
        let since = slot.map_or(total, |(_, logged)| total - logged);
        tracing::info!(reason = kind.reason(), %detail, dropped = since, "虚拟网卡丢掉了包（同一个原因每分钟最多记一行）");
        *slot = Some((now, total));
    }
}

/// netmap 里引擎要的几样，netmap 换了才重算。
#[derive(Debug, Clone)]
struct Index {
    own: Ipv4Addr,
    cidr: Ipv4Net,
    by_ip: HashMap<Ipv4Addr, PeerInfo>,
    by_id: HashMap<NodeId, PeerInfo>,
}

#[derive(Debug, Clone, Copy)]
struct PeerInfo {
    id: NodeId,
    ip: Ipv4Addr,
    /// 它可以访问本节点。
    inbound: bool,
    /// 本节点可以访问它。
    outbound: bool,
    /// 它说它没有网卡。
    no_vnet: bool,
}

impl Index {
    fn of(netmap: &Netmap) -> Self {
        let peers: Vec<PeerInfo> = netmap
            .peers
            .iter()
            .map(|peer| PeerInfo {
                id: peer.id,
                ip: peer.virtual_ip,
                inbound: peer.inbound,
                outbound: peer.outbound,
                no_vnet: netmap.no_vnet.contains(&peer.id),
            })
            .collect();
        Self {
            own: netmap.me.virtual_ip,
            cidr: netmap.network.cidr,
            by_ip: peers.iter().map(|peer| (peer.ip, *peer)).collect(),
            by_id: peers.iter().map(|peer| (peer.id, *peer)).collect(),
        }
    }

    /// netmap 换了的话重算。
    fn follow(&mut self, netmap: &mut watch::Receiver<Arc<Netmap>>) {
        if netmap.has_changed().unwrap_or(false) {
            *self = Self::of(&netmap.borrow_and_update());
        }
    }
}

/// 搬包的那一部分。造好之后 [`run`](Self::run)。
pub struct Engine<D, P> {
    device: Arc<D>,
    packets: Arc<P>,
    netmap: watch::Receiver<Arc<Netmap>>,
    counters: Arc<Counters>,
}

/// [`Engine::run`] 结束的原因。
#[derive(Debug, thiserror::Error)]
pub enum Stopped {
    /// 网卡读不了了（被别人删掉了之类）：装配方该拆掉重来。
    #[error("读不了网卡：{0}")]
    Device(io::Error),
    /// 连接层关了（节点在停）。
    #[error("连接层关了")]
    Closed,
}

impl<D: Device, P: Packets> Engine<D, P> {
    #[must_use]
    pub fn new(device: Arc<D>, packets: Arc<P>, netmap: watch::Receiver<Arc<Netmap>>, counters: Arc<Counters>) -> Self {
        Self { device, packets, netmap, counters }
    }

    /// 两个方向一起搬，直到网卡读不了或者连接层关了。丢弃这个 future 就停。
    pub async fn run(self) -> Stopped {
        let replies = Arc::new(Mutex::new(Replies::default()));
        let mut outbound = Outbound {
            device: Arc::clone(&self.device),
            sender: self.packets.packet_sender(),
            netmap: self.netmap.clone(),
            index: Index::of(&self.netmap.borrow()),
            counters: Arc::clone(&self.counters),
            replies: Arc::clone(&replies),
            waiting: HashMap::new(),
            refused: HashMap::new(),
            message: 0,
            icmp: IcmpBudget::default(),
            log: DropLog::default(),
        };
        let mut inbound = Inbound {
            device: self.device,
            packets: self.packets,
            netmap: self.netmap.clone(),
            index: Index::of(&self.netmap.borrow()),
            counters: self.counters,
            replies,
            reassembly: Reassembly::default(),
            fragments: Fragments::default(),
            log: DropLog::default(),
        };
        tokio::select! {
            stopped = outbound.run() => stopped,
            stopped = inbound.run() => stopped,
        }
    }
}

/// 回"不可达"的预算：每秒 [`ICMP_PER_SECOND`] 个。
#[derive(Debug)]
struct IcmpBudget {
    second: Instant,
    used: u32,
}

impl Default for IcmpBudget {
    fn default() -> Self {
        Self { second: Instant::now(), used: 0 }
    }
}

impl IcmpBudget {
    fn take(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.second) >= Duration::from_secs(1) {
            (self.second, self.used) = (now, 0);
        }
        self.used += 1;
        self.used <= ICMP_PER_SECOND
    }
}

/// 一个对端的连接正在建：排着的包。
#[derive(Debug, Default)]
struct Waiting {
    frames: VecDeque<Bytes>,
}

struct Outbound<D, S> {
    device: Arc<D>,
    sender: S,
    netmap: watch::Receiver<Arc<Netmap>>,
    index: Index,
    counters: Arc<Counters>,
    replies: Arc<Mutex<Replies>>,
    /// 正在建连接的对端和排着的包。
    waiting: HashMap<NodeId, Waiting>,
    /// 连接建不起来的对端，到什么时候之前当场回"不可达"。
    refused: HashMap<NodeId, Instant>,
    /// 切片的包号。
    message: u16,
    icmp: IcmpBudget,
    log: DropLog,
}

/// 出去的方向这一轮等到了什么。
enum Event {
    Read(io::Result<usize>),
    Dialed(NodeId, Result<(), OpenError>),
}

impl<D: Device, S: PacketSender> Outbound<D, S> {
    async fn run(&mut self) -> Stopped {
        let (dialed_tx, mut dialed) = mpsc::unbounded_channel::<(NodeId, Result<(), OpenError>)>();
        // 第一个字节留给帧头：读进来的包后面直接就是一个完整的帧，不用再拷一次。
        let mut buf = vec![0u8; 1 + READ_BUFFER];
        buf[0] = PacketHeader::WHOLE_BYTE;
        loop {
            let event = tokio::select! {
                read = self.device.recv(&mut buf[1..]) => Event::Read(read),
                Some((peer, result)) = dialed.recv() => Event::Dialed(peer, result),
            };
            match event {
                Event::Read(read) => {
                    // 网卡上紧跟着还有现成的包就接着读，一口气交下去：连接层把一样长的凑成一批发，少几次系统调用。
                    // 只取现成的，不等：没有了就把手上的发掉。
                    let mut read = Some(read);
                    let mut taken = 0;
                    while let Some(result) = read.take() {
                        match result {
                            Ok(len) => {
                                let frame = Bytes::copy_from_slice(&buf[..=len]);
                                if let Some(peer) = self.route(&frame).await {
                                    self.send(peer, frame, &dialed_tx).await;
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                            Err(error) => {
                                self.sender.flush();
                                return Stopped::Device(error);
                            }
                        }
                        taken += 1;
                        if taken < OUTBOUND_BURST {
                            read = self.device.try_recv(&mut buf[1..]);
                        }
                    }
                }
                Event::Dialed(peer, result) => self.dialed(peer, result).await,
            }
            self.sender.flush();
        }
    }

    /// 本机发出的一个包该发给哪个对端；不该发的在这里处理掉（丢掉、回"不可达"），返回 `None`。
    async fn route(&mut self, frame: &Bytes) -> Option<NodeId> {
        self.index.follow(&mut self.netmap);
        let packet = &frame[1..];
        let ip = match Ipv4::parse(packet) {
            Ok(ip) => ip,
            // 网卡上没有 IPv6 的地址，内核偶尔还是会发几个（邻居发现之类），不算丢包。
            Err(Malformed::NotIpv4(_)) => return None,
            Err(error) => {
                self.log.note(&self.counters, Loss::Malformed, &error);
                return None;
            }
        };
        if ip.source() != self.index.own {
            self.log.note(&self.counters, Loss::BadSource, &ip.source());
            return None;
        }
        let destination = ip.destination();
        if destination.is_multicast() || destination.is_broadcast() || destination == self.index.cidr.broadcast() {
            return None;
        }
        let peer = self.index.by_ip.get(&destination).copied();
        let refused = peer.and_then(|peer| self.refused.get(&peer.id)).is_some_and(|until| Instant::now() < *until);
        match peer {
            None => self.unreachable(&ip, Unreachable::Host, Loss::Unreachable, &destination).await,
            Some(peer) if peer.no_vnet || refused => self.unreachable(&ip, Unreachable::Host, Loss::Unreachable, &destination).await,
            Some(peer) if !peer.outbound && matches!(ip.conversation(), Conversation::TcpOpen | Conversation::IcmpRequest) => {
                self.unreachable(&ip, Unreachable::Prohibited, Loss::NotAllowed, &destination).await;
            }
            Some(peer) => {
                if !peer.inbound {
                    self.replies.lock().expect("replies mutex poisoned").sent(&ip, Instant::now());
                }
                return Some(peer.id);
            }
        }
        None
    }

    /// 丢掉一个本机发出的包，给发它的程序回一个"不可达"。
    async fn unreachable(&mut self, ip: &Ipv4<'_>, code: Unreachable, kind: Loss, detail: &Ipv4Addr) {
        self.log.note(&self.counters, kind, detail);
        if !self.icmp.take(Instant::now()) {
            return;
        }
        let Some(answer) = unreachable(ip, code) else { return };
        // 写网卡可能要等（它的队列满着的时候）。同一阵里排在前面、交下去还没发的包先发掉，不让它们陪着等。
        self.sender.flush();
        if let Err(error) = self.device.send(&answer).await {
            tracing::debug!(%error, "回给本机程序的不可达写不进网卡");
        }
    }

    async fn send(&mut self, peer: NodeId, frame: Bytes, dialed: &mpsc::UnboundedSender<(NodeId, Result<(), OpenError>)>) {
        if let Some(waiting) = self.waiting.get_mut(&peer) {
            return Self::queue(waiting, frame, &self.counters, &mut self.log);
        }
        let len = frame.len() - 1;
        match self.sender.queue_packet(peer, frame.clone()) {
            Ok(()) => self.counters.sent(len),
            Err(DatagramSendError::NotConnected(_) | DatagramSendError::ConnectionLost { .. }) => {
                let mut waiting = Waiting::default();
                Self::queue(&mut waiting, frame, &self.counters, &mut self.log);
                self.waiting.insert(peer, waiting);
                let (sender, dialed) = (self.sender.clone(), dialed.clone());
                tracing::debug!(%peer, "虚拟网卡有包要发给对端，和它还没有连接：先建，这一会儿的包排着");
                tokio::spawn(async move {
                    let result = sender.connect(peer).await;
                    // 引擎已经停了的话没有人收，不要紧。
                    let _ = dialed.send((peer, result));
                });
            }
            Err(DatagramSendError::TooLarge { max, .. }) => self.send_pieces(peer, &frame[1..], max),
            Err(DatagramSendError::Unsupported(_)) => {
                let detail = format!("对端 {peer} 不收数据报");
                self.log.note(&self.counters, Loss::Unreachable, &detail);
            }
        }
    }

    fn queue(waiting: &mut Waiting, frame: Bytes, counters: &Counters, log: &mut DropLog) {
        if waiting.frames.len() >= MAX_WAITING {
            log.note(counters, Loss::Unreachable, &"连接还在建，排着的包满了");
            return;
        }
        waiting.frames.push_back(frame);
    }

    /// 一个包装不进现在的数据报（`max` 字节）：切成两片发。
    fn send_pieces(&mut self, peer: NodeId, packet: &[u8], max: usize) {
        self.message = self.message.wrapping_add(1);
        let pieces = match PacketPieces::split(self.message, packet, max) {
            Ok(pieces) => pieces,
            Err(error) => return self.log.note(&self.counters, Loss::Unreachable, &error),
        };
        for piece in pieces {
            if let Err(error) = self.sender.queue_packet(peer, Bytes::from(piece)) {
                return self.log.note(&self.counters, Loss::Unreachable, &error);
            }
        }
        self.counters.sent(packet.len());
    }

    /// 到 `peer` 的连接建好了（或者没建成）：把排着的包发出去，或者给它们回"不可达"。
    async fn dialed(&mut self, peer: NodeId, result: Result<(), OpenError>) {
        let Some(waiting) = self.waiting.remove(&peer) else { return };
        match result {
            Ok(()) => {
                self.refused.remove(&peer);
                tracing::debug!(%peer, queued = waiting.frames.len(), "和对端的连接建好了，排着的包发出去");
                for frame in waiting.frames {
                    let len = frame.len() - 1;
                    match self.sender.queue_packet(peer, frame.clone()) {
                        Ok(()) => self.counters.sent(len),
                        Err(DatagramSendError::TooLarge { max, .. }) => self.send_pieces(peer, &frame[1..], max),
                        Err(error) => self.log.note(&self.counters, Loss::Unreachable, &error),
                    }
                }
            }
            Err(error) => {
                tracing::info!(%peer, %error, queued = waiting.frames.len(), "虚拟网卡到对端的连接建不起来：排着的包回主机不可达，{REFUSE_FOR:?} 之内发往它的包当场回不可达");
                self.refused.retain(|_, until| Instant::now() < *until);
                self.refused.insert(peer, Instant::now() + REFUSE_FOR);
                for frame in waiting.frames {
                    if let Ok(ip) = Ipv4::parse(&frame[1..]) {
                        let destination = ip.destination();
                        self.unreachable(&ip, Unreachable::Host, Loss::Unreachable, &destination).await;
                    }
                }
            }
        }
    }
}

struct Inbound<D, P> {
    device: Arc<D>,
    packets: Arc<P>,
    netmap: watch::Receiver<Arc<Netmap>>,
    index: Index,
    counters: Arc<Counters>,
    replies: Arc<Mutex<Replies>>,
    reassembly: Reassembly,
    fragments: Fragments,
    log: DropLog,
}

impl<D: Device, P: Packets> Inbound<D, P> {
    async fn run(&mut self) -> Stopped {
        let mut batch: Vec<Datagram> = Vec::with_capacity(INBOUND_BATCH);
        let mut admitted: Vec<Bytes> = Vec::new();
        loop {
            if self.packets.recv_packets(&mut batch, INBOUND_BATCH).await == 0 {
                return Stopped::Closed;
            }
            self.index.follow(&mut self.netmap);
            for datagram in batch.drain(..) {
                self.admit(datagram, &mut admitted);
                for packet in admitted.drain(..) {
                    let len = packet.len();
                    match self.device.send(&packet).await {
                        Ok(()) => self.counters.received(len),
                        Err(error) => self.log.note(&self.counters, Loss::Malformed, &error),
                    }
                }
            }
        }
    }

    /// 对端发来的一帧：取出里面的包（切开的拼好，合在一起的拆开），逐个核对，能写进网卡的放进 `admitted`。
    fn admit(&mut self, datagram: Datagram, admitted: &mut Vec<Bytes>) {
        let Datagram { peer, payload } = datagram;
        match PacketHeader::decode(&payload) {
            Ok((PacketHeader::Whole, _)) => self.admit_packet(peer, payload.slice(PacketHeader::WHOLE_LEN..), admitted),
            Ok((PacketHeader::Piece(fragment), _)) => {
                match self.reassembly.accept(peer, fragment, payload.slice(PacketHeader::PIECE_LEN..), Instant::now()) {
                    Assembled::Packet(packet) => self.admit_packet(peer, packet, admitted),
                    Assembled::Waiting => {}
                    Assembled::Broken => self.log.note(&self.counters, Loss::Malformed, &"片拼不起来"),
                }
            }
            // 合在一帧里的几个包各是各的：一个一个地核对，哪个不合格丢哪个。帧本身坏了的话，坏的地方之前的照收。
            Ok((PacketHeader::Bundle, body)) => {
                for packet in Bundled::new(body) {
                    match packet {
                        Ok(packet) => self.admit_packet(peer, payload.slice_ref(packet), admitted),
                        Err(error) => self.log.note(&self.counters, Loss::Malformed, &error),
                    }
                }
            }
            Err(error) => self.log.note(&self.counters, Loss::Malformed, &error),
        }
    }

    /// 对端 `peer` 发来的一个完整的 IP 包：核对，能写进网卡的放进 `admitted`。一个 IP 分片的包齐了的时候是好几个（它的每一片）。
    fn admit_packet(&mut self, peer: NodeId, packet: Bytes, admitted: &mut Vec<Bytes>) {
        let ip = match Ipv4::parse(&packet) {
            Ok(ip) => ip,
            Err(error) => return self.log.note(&self.counters, Loss::Malformed, &error),
        };
        let Some(sender) = self.index.by_id.get(&peer).copied() else {
            return self.log.note(&self.counters, Loss::BadSource, &format!("节点 {peer} 不在 netmap 里"));
        };
        if ip.source() != sender.ip {
            let detail = format!("节点 {peer}（{}）发来的包写的来源是 {}", sender.ip, ip.source());
            return self.log.note(&self.counters, Loss::BadSource, &detail);
        }
        if ip.destination() != self.index.own {
            return self.log.note(&self.counters, Loss::BadDestination, &format!("节点 {peer} 发来的包要去 {}", ip.destination()));
        }
        if !ip.is_fragment() {
            if self.judge(peer, sender, &ip) {
                admitted.push(packet);
            }
            return;
        }
        if ip.protocol() == TCP {
            return self.log.note(&self.counters, Loss::Malformed, &format!("节点 {peer} 发来的 TCP 被切成了片"));
        }
        // 差错报文和重定向齐了也不放（见 [`Self::judge`]），第一片一到就扔，不用攒。
        if ip.is_icmp_error() {
            return self.log.note(&self.counters, Loss::Malformed, &format!("节点 {peer}：ICMP 差错报文被切成了片"));
        }
        if ip.is_icmp_redirect() {
            return self.log.note(&self.counters, Loss::NotAllowed, &format!("节点 {peer} 发来一个 ICMP 重定向"));
        }
        match self.fragments.accept(&ip, packet.clone(), Instant::now()) {
            Gathered::Waiting => {}
            Gathered::Broken(why) => self.log.note(&self.counters, Loss::Malformed, &format!("节点 {peer} 发来的 IP 分片拼不起来：{why}")),
            Gathered::Complete(pieces) => {
                let first = Ipv4::parse(&pieces[0]).expect("攒下的片都读过");
                if self.judge(peer, sender, &first) {
                    admitted.extend(pieces);
                }
            }
        }
    }

    /// 来源、目的都对的一个包（被切开的包是它的第一片）让不让进来；不让的记下原因。
    fn judge(&mut self, peer: NodeId, sender: PeerInfo, ip: &Ipv4<'_>) -> bool {
        if let Some((kind, detail)) = quote_problem(ip, self.index.own, sender.ip) {
            self.log.note(&self.counters, kind, &format!("节点 {peer}：{detail}"));
            return false;
        }
        if ip.is_icmp_redirect() {
            self.log.note(&self.counters, Loss::NotAllowed, &format!("节点 {peer} 发来一个 ICMP 重定向"));
            return false;
        }
        if !sender.inbound && self.replies.lock().expect("replies mutex poisoned").admit(ip, Instant::now()) == Verdict::NewConversation {
            self.log.note(&self.counters, Loss::NotAllowed, &format!("节点 {peer} 不能访问本节点，它发来的不是回包"));
            return false;
        }
        true
    }
}

/// 对端 `sender` 发来的 ICMP 差错报文有什么不对：它说的必须是本节点（`own`）发给它的一个包。不是差错报文的没有问题。
fn quote_problem(ip: &Ipv4<'_>, own: Ipv4Addr, sender: Ipv4Addr) -> Option<(Loss, String)> {
    if !ip.is_icmp_error() {
        return None;
    }
    if ip.is_fragment() {
        return Some((Loss::Malformed, "ICMP 差错报文被切成了片".to_owned()));
    }
    let Some(quoted) = ip.quoted() else {
        return Some((Loss::Malformed, "ICMP 差错报文带回来的原包连头都不完整".to_owned()));
    };
    if quoted.source() != own {
        return Some((Loss::BadDestination, format!("ICMP 差错报文说的是 {} 发出的包", quoted.source())));
    }
    if quoted.destination() != sender {
        return Some((Loss::BadSource, format!("ICMP 差错报文说的是发往 {} 的包", quoted.destination())));
    }
    None
}

#[cfg(test)]
mod tests;
