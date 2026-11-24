//! 虚拟网卡与连接层之间的数据包转发引擎。出站与入站各由一个独立异步任务驱动：
//!
//! **出站**（本机应用发出、从虚拟网卡读取的数据包）：
//!
//! 1. 忽略非 IPv4 数据包（虚拟网卡未配置 IPv6 地址）；丢弃源 IP 非本节点虚拟 IP 的数据包（例如经本机转发的其他主机流量，
//!    对端同样会丢弃，无需发送）。
//! 2. 忽略组播与广播数据包；对不在网络网段内、目标无对应节点或对端未启用虚拟网卡的包，直接回复 ICMP“主机不可达”，
//!    使本机应用立即感知失败而无需等待超时。
//! 3. 若访问规则禁止本节点访问目标节点，则对新会话起始包（TCP SYN、ICMP Echo 请求）回复“被管理员禁止”以快速失败；
//!    其余包仍正常发出并由对端按规则过滤（若允许对端访问本节点，出站包可能是回包）。若禁止对端访问本节点，则记录发往该对端的 UDP 会话，
//!    以便放行其回包（[`crate::filter`]）。
//! 4. 每个 IP 数据包作为不可靠数据报通过节点间现有连接发送；超出单报上限时拆分为两片传输（[`crate::pieces`]）。
//!    尚未建立连接时自动发起建连：建连期间发往该对端的数据包暂存于小队列中（每个对端最多 [`MAX_WAITING`] 个），连上后按序发出，
//!    避免首个 ping 丢包或首个 TCP SYN 等待重传；建连失败时向队列中的包回复“主机不可达”，并在随后 [`REFUSE_FOR`] 期间内
//!    对发往该对端的包直接返回“主机不可达”，冷却期结束后再重新尝试。
//!
//! **入站**（对端发来的数据包）：源地址必须与发送对端的虚拟 IP 一致（连接经公钥认证，无法伪造其他节点），目的地址必须为本节点
//! 虚拟 IP；若访问规则不允许对端访问本节点，则仅放行本节点发起会话的回包。校验未通过的包予以丢弃并计数（[`Counters`]），
//! 通过校验的包原样写入虚拟网卡交由操作系统协议栈处理。此外，无论访问规则如何，均强制执行以下校验：
//!
//! - IPv4 分片包需先在用户态收集齐所有分片（[`crate::fragments`]），收齐后依据首片执行访问控制检查，通过后再将各分片一并写入虚拟网卡：
//!   避免不完整分片占用内核全局重组缓存，也防止后续分片绕过过滤检查。TCP 分片直接丢弃（节点间 TCP 不会发生 IP 分片）。
//! - ICMP 差错报文（不可达、超时、参数问题）引用的原始数据包必须是本节点发往该对端的报文：覆盖网络节点间不存在路由器，对端仅可能
//!   针对本节点发往它的包回复差错报文。若不校验，恶意对端可能伪造差错报文篡改本机路由缓存中的路径 MTU，或向无关 UDP 套接字注入错误。
//!   分片的 ICMP 差错报文直接丢弃。
//! - 丢弃所有 ICMP 重定向报文：覆盖网络中不存在中间路由器，不应接受路由重定向。
//!
//! 丢包日志按原因限流：每种丢包原因首次触发时记录一次，此后每分钟最多记录一次并附带统计计数。

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

use crate::bundle::{Bundler, SMALL_PACKET};
use ipnet::Ipv4Net;
use tokio::sync::{mpsc, watch};

use crate::device::Device;
use crate::filter::{Replies, Verdict};
use crate::fragments::{Fragments, Gathered};
use crate::ipv4::{Conversation, Ipv4, Malformed, TCP, Unreachable, unreachable};
use crate::pieces::{Assembled, Reassembly};

/// 连接建立期间，发往单个对端的数据包最大等待队列长度。足以容纳若干 ping、一次 TCP 握手及 DNS 往返；超出部分丢弃，
/// 由上层协议自行重传。
pub const MAX_WAITING: usize = 32;

/// 到对端的连接建立失败后的拒绝冷却时长：在此期间发往该对端的数据包直接回复“主机不可达”，不再重复建连。
pub const REFUSE_FOR: Duration = Duration::from_secs(3);

/// 每秒最多回复的 ICMP 不可达报文数，防止本机应用向不可达地址高速发包时产生等量 ICMP 响应风暴。
const ICMP_PER_SECOND: u32 = 200;

/// 单次从连接层批量拉取入站数据包的最大数量。
const INBOUND_BATCH: usize = 64;

/// 从虚拟网卡读取单包的缓冲区上限（实际包长不超过 MTU，按 IPv4 最大包长预留）。
const READ_BUFFER: usize = u16::MAX as usize;
/// 单轮从虚拟网卡连续非阻塞读取的最大包数量。使高吞吐流得以批量提交连接层，同时兼顾其他事件（如建连完成、入站包）的调度公平性。
/// Linux 内核单次分段卸载交付的 64 KB 大块在默认 MTU 下约 53 个包，单轮可完整处理。
const OUTBOUND_BURST: usize = 64;

/// 按原因分类的丢包计数与收发流量统计，供上报与本地状态查询读取。
#[derive(Debug, Default)]
pub struct Counters {
    sent_packets: AtomicU64,
    sent_bytes: AtomicU64,
    received_packets: AtomicU64,
    received_bytes: AtomicU64,
    drops: [AtomicU64; Loss::COUNT],
}

/// 数据包丢弃原因分类。
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
                "源地址异常：对端发来的数据包源 IP 与其虚拟 IP 不符，或其 ICMP 差错报文引用的目标地址不符；或本机发出的数据包源 IP 不是本节点虚拟 IP"
            }
            Self::BadDestination => {
                "目的地址异常：对端发来的数据包目的 IP 不是本节点虚拟 IP，或其 ICMP 差错报文引用的源地址不是本节点虚拟 IP"
            }
            Self::NotAllowed => "访问规则拒绝：对端发起的新会话或本节点无权访问的目标会话，以及对端发来的 ICMP 重定向报文",
            Self::Unreachable => "目标不可达：网段中无此节点、对端未启用虚拟网卡、无法建立连接，或建连等待队列已满",
            Self::Malformed => "报文格式异常：非完整 IPv4 数据包、分片重组失败，或禁止分片的报文（TCP、ICMP 差错报文）",
        }
    }
}

impl Counters {
    /// 获取自本次启动以来的收发及丢包计数快照。
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

    fn received(&self, packets: usize, bytes: usize) {
        self.received_packets.fetch_add(count(packets), Ordering::Relaxed);
        self.received_bytes.fetch_add(count(bytes), Ordering::Relaxed);
    }
}

/// [`Counters::snapshot`] 返回的流量统计快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Traffic {
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub received_packets: u64,
    pub received_bytes: u64,
    pub dropped: VnetDrops,
}

fn count(amount: usize) -> u64 {
    u64::try_from(amount).unwrap_or(u64::MAX)
}

/// 按丢包原因限流的日志记录器：每种原因首次出现立即记录，之后每分钟最多记录一次。
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
        tracing::info!(reason = kind.reason(), %detail, dropped = since, "虚拟网卡丢包统计（同一原因每分钟最多记录一次）");
        *slot = Some((now, total));
    }
}

/// 转发引擎所需的 netmap 索引视图，仅在 netmap 变更时重建。
#[derive(Debug, Clone)]
struct Index {
    own: Ipv4Addr,
    cidr: Ipv4Net,
    /// 网络级开关：是否启用小包聚合发送（[`crate::bundle`]）。
    bundle: bool,
    by_ip: HashMap<Ipv4Addr, PeerInfo>,
    by_id: HashMap<NodeId, PeerInfo>,
}

#[derive(Debug, Clone, Copy)]
struct PeerInfo {
    id: NodeId,
    ip: Ipv4Addr,
    /// 是否允许该对端访问本节点。
    inbound: bool,
    /// 是否允许本节点访问该对端。
    outbound: bool,
    /// 该对端是否声明未启用虚拟网卡。
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
            bundle: netmap.network.bundle_small_packets,
            by_ip: peers.iter().map(|peer| (peer.ip, *peer)).collect(),
            by_id: peers.iter().map(|peer| (peer.id, *peer)).collect(),
        }
    }

    /// 检测并同步最新的 netmap 变更。
    fn follow(&mut self, netmap: &mut watch::Receiver<Arc<Netmap>>) {
        if netmap.has_changed().unwrap_or(false) {
            *self = Self::of(&netmap.borrow_and_update());
        }
    }
}

/// 虚拟网卡数据包转发引擎。构造后调用 [`run`](Self::run) 启动。
pub struct Engine<D, P> {
    device: Arc<D>,
    packets: Arc<P>,
    netmap: watch::Receiver<Arc<Netmap>>,
    counters: Arc<Counters>,
}

/// [`Engine::run`] 停止运行的原因。
#[derive(Debug, thiserror::Error)]
pub enum Stopped {
    /// 无法继续读取虚拟网卡（例如设备被外部移除）：上层管理组件应重建虚拟网卡。
    #[error("无法从虚拟网卡读取数据：{0}")]
    Device(io::Error),
    /// 连接层已关闭（通常因节点正在停止）。
    #[error("连接层已关闭")]
    Closed,
}

impl<D: Device, P: Packets> Engine<D, P> {
    #[must_use]
    pub fn new(device: Arc<D>, packets: Arc<P>, netmap: watch::Receiver<Arc<Netmap>>, counters: Arc<Counters>) -> Self {
        Self { device, packets, netmap, counters }
    }

    /// 并发运行出站与入站转发循环，直至虚拟网卡读取失败或连接层关闭。丢弃该 future 即可停止。
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
            bundles: Bundler::default(),
            answers: Vec::new(),
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

/// ICMP 不可达报文回复速率限制：每秒最多 [`ICMP_PER_SECOND`] 个。
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

/// 等待目标对端连接建立期间暂存的数据帧队列。
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
    /// 正在建立连接的对端及其等待发送队列。
    waiting: HashMap<NodeId, Waiting>,
    /// 建连失败对端的拒绝冷却截止时刻：在此之前发往该对端的包直接回复不可达。
    refused: HashMap<NodeId, Instant>,
    /// 数据报分片消息序号。
    message: u16,
    icmp: IcmpBudget,
    log: DropLog,
    /// 待聚合为单帧发送的小包缓冲器。
    bundles: Bundler,
    /// 本轮待写回虚拟网卡的 ICMP 不可达报文：待本轮所有出站包提交发送后再异步写入网卡，避免阻塞出站路径。
    answers: Vec<Vec<u8>>,
}

/// 出站事件循环单轮触发的事件类型。
enum Event {
    Read(io::Result<usize>),
    Dialed(NodeId, Result<(), OpenError>),
    /// 存在已到达发送窗口的聚合小包帧。
    BundlesDue,
}

/// 等待至 `deadline`；为 `None` 时永久挂起。
async fn until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

impl<D: Device, S: PacketSender> Outbound<D, S> {
    async fn run(&mut self) -> Stopped {
        let (dialed_tx, mut dialed) = mpsc::unbounded_channel::<(NodeId, Result<(), OpenError>)>();
        // 首字节预留帧头，读取完成后可直接构成完整数据帧，避免二次拷贝。
        let mut buf = vec![0u8; 1 + READ_BUFFER];
        buf[0] = PacketHeader::WHOLE_BYTE;
        loop {
            let deadline = self.bundles.deadline();
            let event = tokio::select! {
                read = self.device.recv(&mut buf[1..]) => Event::Read(read),
                Some((peer, result)) = dialed.recv() => Event::Dialed(peer, result),
                () = until(deadline) => Event::BundlesDue,
            };
            let mut broken = None;
            match event {
                Event::Read(read) => {
                    // 连续排空虚拟网卡上已就绪的后续数据包并批量提交连接层（减少系统调用并合并同批小包），
                    // 仅执行非阻塞读取，无现成数据时立即结束本轮并刷新发送。
                    let mut read = Some(read);
                    let mut taken = 0;
                    while let Some(result) = read.take() {
                        match result {
                            Ok(len) => {
                                let frame = Bytes::copy_from_slice(&buf[..=len]);
                                if let Some(peer) = self.route(&frame) {
                                    self.offer(peer, frame, &dialed_tx);
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                            // 读取的数据无法组成合法数据包且已由网卡丢弃（见 [`Device::recv`]）。
                            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                                self.log.note(&self.counters, Loss::Malformed, &error);
                            }
                            Err(error) => {
                                broken = Some(error);
                                break;
                            }
                        }
                        taken += 1;
                        if taken < OUTBOUND_BURST {
                            read = self.device.try_recv(&mut buf[1..]);
                        }
                    }
                }
                Event::Dialed(peer, result) => self.dialed(peer, result),
                Event::BundlesDue => {
                    if let Some(deadline) = deadline {
                        self.bundles.woke(deadline, tokio::time::Instant::now());
                    }
                }
            }
            // 本轮处理完毕：提交已就绪的聚合帧并刷新连接层发送缓冲，随后再异步将 ICMP 不可达报文写回虚拟网卡。
            for (peer, frame) in self.bundles.due(tokio::time::Instant::now(), self.index.bundle && broken.is_none()) {
                self.emit(peer, frame, &dialed_tx);
            }
            self.sender.flush();
            for answer in std::mem::take(&mut self.answers) {
                if let Err(error) = self.device.send(&answer).await {
                    tracing::debug!(%error, "无法将 ICMP 不可达报文写入虚拟网卡");
                }
            }
            if let Some(error) = broken {
                return Stopped::Device(error);
            }
        }
    }

    /// 处理待发往 `peer` 的本机出站数据包。满足条件的小包先尝试合入聚合缓冲（[`crate::bundle`]），其余按常规方式发送。
    fn offer(&mut self, peer: NodeId, frame: Bytes, dialed: &mpsc::UnboundedSender<(NodeId, Result<(), OpenError>)>) {
        let packet = &frame[PacketHeader::WHOLE_LEN..];
        if self.index.bundle && packet.len() <= SMALL_PACKET && !self.waiting.contains_key(&peer) {
            let sender = &self.sender;
            let pushed = self.bundles.push(peer, packet, || sender.bundle_capacity(peer), tokio::time::Instant::now());
            if let Some(full) = pushed.emit {
                self.emit(peer, full, dialed);
            }
            if pushed.taken {
                return;
            }
        } else if let Some(pending) = self.bundles.take(peer) {
            // 先发出该对端已缓存的小包，保持包序不变。
            self.emit(peer, pending, dialed);
        }
        self.send(peer, frame, dialed);
    }

    /// 将聚合结果提交连接层。仅含单包时以普通帧发送；若聚合帧发送失败（例如连接已断开或路径 MTU 缩小），
    /// 则拆回逐包走常规发送流程（按需触发建连或分片）。
    fn emit(&mut self, peer: NodeId, frame: Bytes, dialed: &mpsc::UnboundedSender<(NodeId, Result<(), OpenError>)>) {
        let Ok((PacketHeader::Bundle, body)) = PacketHeader::decode(&frame) else { return self.send(peer, frame, dialed) };
        let packets = Bundled::new(body).flatten();
        if self.sender.queue_packet(peer, frame.clone()).is_ok() {
            packets.for_each(|packet| self.counters.sent(packet.len()));
            return;
        }
        for packet in packets {
            let mut whole = Vec::with_capacity(PacketHeader::WHOLE_LEN + packet.len());
            PacketHeader::Whole.encode(&mut whole);
            whole.extend_from_slice(packet);
            self.send(peer, whole.into(), dialed);
        }
    }

    /// 解析本机出站数据包并确定目标对端；不符合转发条件的包在此丢弃或排队回复 ICMP 不可达，返回 `None`。
    fn route(&mut self, frame: &Bytes) -> Option<NodeId> {
        self.index.follow(&mut self.netmap);
        let packet = &frame[1..];
        let ip = match Ipv4::parse(packet) {
            Ok(ip) => ip,
            // 虚拟网卡未配置 IPv6 地址，内核偶发发出的 IPv6 报文（如邻居发现）直接忽略，不计为丢包。
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
            None => self.unreachable(&ip, Unreachable::Host, Loss::Unreachable, &destination),
            Some(peer) if peer.no_vnet || refused => self.unreachable(&ip, Unreachable::Host, Loss::Unreachable, &destination),
            Some(peer) if !peer.outbound && matches!(ip.conversation(), Conversation::TcpOpen | Conversation::IcmpRequest) => {
                self.unreachable(&ip, Unreachable::Prohibited, Loss::NotAllowed, &destination);
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

    /// 丢弃本机发出的不可送达数据包，并按限流预算生成 ICMP 不可达报文回复本机应用。
    ///
    /// 生成的回复报文先暂存，待本轮所有出站包提交并刷新后再写入虚拟网卡（见 [`run`](Self::run)），
    /// 避免网卡写入阻塞拖累同批次中已在队列等待发送的正常数据包。
    fn unreachable(&mut self, ip: &Ipv4<'_>, code: Unreachable, kind: Loss, detail: &Ipv4Addr) {
        self.log.note(&self.counters, kind, detail);
        if self.icmp.take(Instant::now())
            && let Some(answer) = unreachable(ip, code)
        {
            self.answers.push(answer);
        }
    }

    fn send(&mut self, peer: NodeId, frame: Bytes, dialed: &mpsc::UnboundedSender<(NodeId, Result<(), OpenError>)>) {
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
                tracing::debug!(%peer, "虚拟网卡存在发往对端的数据包但尚未建立连接，开始建连并暂存待发包");
                tokio::spawn(async move {
                    let result = sender.connect(peer).await;
                    // 若转发引擎已停止导致接收端关闭，忽略发送错误即可。
                    let _ = dialed.send((peer, result));
                });
            }
            Err(DatagramSendError::TooLarge { max, .. }) => self.send_pieces(peer, &frame[1..], max),
            Err(DatagramSendError::Unsupported(_)) => {
                let detail = format!("对端 {peer} 不支持数据报传输");
                self.log.note(&self.counters, Loss::Unreachable, &detail);
            }
        }
    }

    fn queue(waiting: &mut Waiting, frame: Bytes, counters: &Counters, log: &mut DropLog) {
        if waiting.frames.len() >= MAX_WAITING {
            log.note(counters, Loss::Unreachable, &"对端连接正在建立，等待发送队列已满");
            return;
        }
        waiting.frames.push_back(frame);
    }

    /// 数据包超出当前数据报上限（`max` 字节）时，将其拆分为两片发送。
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

    /// 处理到 `peer` 的异步建连结果：成功则发送等待队列中的所有数据包，失败则回复“主机不可达”。
    fn dialed(&mut self, peer: NodeId, result: Result<(), OpenError>) {
        let Some(waiting) = self.waiting.remove(&peer) else { return };
        match result {
            Ok(()) => {
                self.refused.remove(&peer);
                tracing::debug!(%peer, queued = waiting.frames.len(), "到对端的连接已建立，开始发送等待队列中的数据包");
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
                tracing::info!(%peer, %error, queued = waiting.frames.len(), "虚拟网卡到对端的连接建立失败：已向等待队列返回主机不可达，{REFUSE_FOR:?} 内发往该对端的数据包将直接返回不可达");
                self.refused.retain(|_, until| Instant::now() < *until);
                self.refused.insert(peer, Instant::now() + REFUSE_FOR);
                for frame in waiting.frames {
                    if let Ok(ip) = Ipv4::parse(&frame[1..]) {
                        let destination = ip.destination();
                        self.unreachable(&ip, Unreachable::Host, Loss::Unreachable, &destination);
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
            }
            self.deliver(&admitted).await;
            admitted.clear();
        }
    }

    /// 将本批通过校验的数据包批量写入虚拟网卡：支持分段卸载的网卡可先聚合连续流再提交内核（[`Device::send_many`]）。
    /// 仅聚合当前已到达的数据包，不额外等待后续包。
    async fn deliver(&mut self, admitted: &[Bytes]) {
        let (mut packets, mut bytes) = (admitted.len(), admitted.iter().map(Bytes::len).sum::<usize>());
        if packets == 0 {
            return;
        }
        if let Err(unwritten) = self.device.send_many(admitted).await {
            packets = packets.saturating_sub(unwritten.packets);
            bytes = bytes.saturating_sub(unwritten.bytes);
            for _ in 0..unwritten.packets {
                self.log.note(&self.counters, Loss::Malformed, &unwritten.error);
            }
        }
        self.counters.received(packets, bytes);
    }

    /// 解码对端发来的数据帧（重组数据报分片或展开小包聚合帧），逐包校验并将允许放行的数据包追加至 `admitted`。
    fn admit(&mut self, datagram: Datagram, admitted: &mut Vec<Bytes>) {
        let Datagram { peer, payload } = datagram;
        match PacketHeader::decode(&payload) {
            Ok((PacketHeader::Whole, _)) => self.admit_packet(peer, payload.slice(PacketHeader::WHOLE_LEN..), admitted),
            Ok((PacketHeader::Piece(fragment), _)) => {
                match self.reassembly.accept(peer, fragment, payload.slice(PacketHeader::PIECE_LEN..), Instant::now()) {
                    Assembled::Packet(packet) => self.admit_packet(peer, packet, admitted),
                    Assembled::Waiting => {}
                    Assembled::Broken => self.log.note(&self.counters, Loss::Malformed, &"数据报分片重组失败"),
                }
            }
            // 聚合帧中的各数据包相互独立，逐一校验并仅丢弃不合格的包；若帧本身损坏，损坏位置之前已解出的包仍正常接收。
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

    /// 校验对端 `peer` 发来的单个 IPv4 数据包，通过后追加至 `admitted`（若为重组完成的 IP 分片包，则按序追加全部分片）。
    fn admit_packet(&mut self, peer: NodeId, packet: Bytes, admitted: &mut Vec<Bytes>) {
        let ip = match Ipv4::parse(&packet) {
            Ok(ip) => ip,
            Err(error) => return self.log.note(&self.counters, Loss::Malformed, &error),
        };
        let Some(sender) = self.index.by_id.get(&peer).copied() else {
            return self.log.note(&self.counters, Loss::BadSource, &format!("节点 {peer} 不在当前 netmap 中"));
        };
        if ip.source() != sender.ip {
            let detail = format!("节点 {peer}（{}）发来的数据包源 IP 为 {}", sender.ip, ip.source());
            return self.log.note(&self.counters, Loss::BadSource, &detail);
        }
        if ip.destination() != self.index.own {
            return self.log.note(
                &self.counters,
                Loss::BadDestination,
                &format!("节点 {peer} 发来的数据包目的 IP 为 {}", ip.destination()),
            );
        }
        if !ip.is_fragment() {
            if self.judge(peer, sender, &ip) {
                admitted.push(packet);
            }
            return;
        }
        if ip.protocol() == TCP {
            return self.log.note(&self.counters, Loss::Malformed, &format!("节点 {peer} 发来的 TCP 报文存在 IP 分片"));
        }
        // 分片的 ICMP 差错报文与重定向报文无论如何均不放行（见 [`Self::judge`]），首片到达即直接丢弃，无需缓存重组。
        if ip.is_icmp_error() {
            return self.log.note(&self.counters, Loss::Malformed, &format!("节点 {peer}：ICMP 差错报文存在 IP 分片"));
        }
        if ip.is_icmp_redirect() {
            return self.log.note(&self.counters, Loss::NotAllowed, &format!("节点 {peer} 发来 ICMP 重定向报文"));
        }
        match self.fragments.accept(&ip, packet.clone(), Instant::now()) {
            Gathered::Waiting => {}
            Gathered::Broken(why) => self.log.note(&self.counters, Loss::Malformed, &format!("IP 分片重组失败（来源节点 {peer}）：{why}")),
            Gathered::Complete(pieces) => {
                let first = Ipv4::parse(&pieces[0]).expect("已缓存的分片均已通过 IPv4 解析");
                if self.judge(peer, sender, &first) {
                    admitted.extend(pieces);
                }
            }
        }
    }

    /// 对源、目的地址已通过校验的数据包（或 IP 分片包的首片）执行策略与安全审查；拒绝时记录丢包原因。
    fn judge(&mut self, peer: NodeId, sender: PeerInfo, ip: &Ipv4<'_>) -> bool {
        if let Some((kind, detail)) = quote_problem(ip, self.index.own, sender.ip) {
            self.log.note(&self.counters, kind, &format!("节点 {peer}：{detail}"));
            return false;
        }
        if ip.is_icmp_redirect() {
            self.log.note(&self.counters, Loss::NotAllowed, &format!("节点 {peer} 发来 ICMP 重定向报文"));
            return false;
        }
        if !sender.inbound && self.replies.lock().expect("replies mutex poisoned").admit(ip, Instant::now()) == Verdict::NewConversation {
            self.log.note(&self.counters, Loss::NotAllowed, &format!("节点 {peer} 无权访问本节点，且收到的数据包不属于回包"));
            return false;
        }
        true
    }
}

/// 检查对端 `sender` 发来的 ICMP 差错报文合法性：引用的原始数据包必须是由本节点（`own`）发往 `sender` 的报文。非差错报文返回 `None`。
fn quote_problem(ip: &Ipv4<'_>, own: Ipv4Addr, sender: Ipv4Addr) -> Option<(Loss, String)> {
    if !ip.is_icmp_error() {
        return None;
    }
    if ip.is_fragment() {
        return Some((Loss::Malformed, "ICMP 差错报文存在 IP 分片".to_owned()));
    }
    let Some(quoted) = ip.quoted() else {
        return Some((Loss::Malformed, "ICMP 差错报文引用的原始数据包 IP 头不完整".to_owned()));
    };
    if quoted.source() != own {
        return Some((Loss::BadDestination, format!("ICMP 差错报文引用的原始数据包源地址为 {}", quoted.source())));
    }
    if quoted.destination() != sender {
        return Some((Loss::BadSource, format!("ICMP 差错报文引用的原始数据包目的地址为 {}", quoted.destination())));
    }
    None
}

#[cfg(test)]
mod tests;
