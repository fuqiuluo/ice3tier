//! 按对端管理连接：一对节点一条连接，按需建立，空闲回收，对端从 netmap 里消失就立刻关闭。

use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use i3t_crypto::NodeKey;
use i3t_crypto::tls;
use i3t_model::Netmap;
use i3t_model::control::{PeerUse, Signal};
use i3t_model::netmap::Congestion;
use i3t_path::Paths;
use i3t_proto::flow::{Channel, DatagramHeader, MAX_DATAGRAM_BODY_LEN, Recipient};
use i3t_proto::sealed::SealedHeader;
use i3t_proto::{NodeId, PublicKey};
use quinn::rustls::pki_types::CertificateDer;
use quinn::{ConnectError, SendDatagramError, TransportConfig, VarInt};
use tokio::sync::{Notify, mpsc, watch};

use crate::congestion::Algorithm;
use crate::contract::{Datagram, DatagramSendError, DatagramSender, Incoming, OpenError, PacketSender};
use crate::quic::{self, AckFrequency, SERVER_NAME};
use crate::sealed::{self, Batch, Inbox, PacketTransport, Role, Session};
use crate::socket;
use crate::stream::{self, RecvHalf, SendHalf, StreamCount};
use crate::tuning::Tuning;

/// 建立连接的时限：等到一条路，加上握手，一共这么久。没有 relay 可走时，这段时间花在等直连打通上。
/// 上层要等"连接建起来"时按它算（`i3t ping` 的第一个往返）。
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// 对端连进来时握手的时限。
const WELCOME_TIMEOUT: Duration = Duration::from_secs(10);
/// 两边同时拨号会留下两条连接。多出来的那一条没有流之后这么久就关。
const DUPLICATE_IDLE_CLOSE: Duration = Duration::from_secs(10);
/// 多久看一次连接是不是空闲。
const IDLE_CHECK: Duration = Duration::from_secs(1);
/// 连接里送来的一条信令最长多少字节、最多等多久。
const SIGNAL_MAX_BYTES: usize = 4096;
const SIGNAL_TIMEOUT: Duration = Duration::from_secs(5);
/// 走单向流的数据报最多等多久读完。它是一次写进去的，正常情况下一到就是完整的。
const RELIABLE_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(10);
/// 对端发来、上层还没有取走的数据报，每一侧最多排多少个。
pub(crate) const DATAGRAM_BACKLOG: usize = 1024;
/// 对端发来、虚拟网卡还没有取走的网络包最多排多少个，满了丢新来的（和路由器的队列一样）。
/// 每包最大约 1400 字节，队列内存占用上限约 2～3 MB；消费侧批量拉取，正常情况下不会积压。
pub(crate) const PACKET_BACKLOG: usize = 2048;

/// 和同一个对端最多同时留几条连接。
///
/// 正常情况下保持 1 条连接；双向同时拨号时会暂时多出 1 条（空闲后很快关闭）；对端重启后，旧连接在空闲超时前可能与新连入连接短暂共存。
/// 再多就不正常了：每条连接能让对端压住一个接收窗口（64MB）的数据和上万条流，条数不设限的话，内存的上限也就没有了。
/// 超出时关掉最旧的：一个正常的对端只有在它那边已经没有能用的连接时才会再拨，所以最旧的那条在它那边早就不在了。
const MAX_CONNS_PER_PEER: usize = 2;

/// 对端连进来、还在握手的连接最多多少条。
///
/// 握手要做一次密钥交换和一次签名，没握完的还要占着状态等到握手超时。连进来的包算在哪个对端名下，
/// 可以靠伪造 relay 的来源地址来决定，所以伪造来源的人每秒发多少个，这里就要做多少次握手。
/// 正常的网络里同一时刻在握手的连接屈指可数，取 64 远远够用。
const MAX_HANDSHAKES: usize = 64;

/// 其中自称来自同一个对端的最多多少条。正常的对端同一时刻只拨一次（重启、换网络之后再拨一次）。
const MAX_HANDSHAKES_PER_PEER: usize = 4;

/// 超出上面两个数之后，来源地址验证过（带着本端 Retry 给的令牌回来）的握手还能再接这么多。
/// 令牌只送到了那个节点真正的路上，伪造来源的人拿不到，所以这些是真的对端：别人占满了名额，它也连得进来。
const MAX_VALIDATED_HANDSHAKES: usize = 2 * MAX_HANDSHAKES;

/// 关闭连接时带给对端的码。
const CLOSE_IDLE: u32 = 0;
const CLOSE_SHUTDOWN: u32 = 1;
const CLOSE_REVOKED: u32 = 2;
const CLOSE_IDENTITY: u32 = 3;
const CLOSE_SURPLUS: u32 = 4;
const CLOSE_KEYS_SPENT: u32 = 5;

type Stream = Incoming<SendHalf, RecvHalf>;

/// 到一个对端的那条连接（开新流用的那一条）现在的状况，数来自 QUIC 库。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionReport {
    /// 握手完成的时刻。前后两次读到的不是同一个时刻，就是连接中间换过了。
    pub established: Instant,
    /// 平滑的往返时间，和连接建立以来见过的最小值。
    pub rtt: Duration,
    pub min_rtt: Duration,
    /// 拥塞窗口。
    pub cwnd_bytes: u64,
    /// 现在一个包最长多少字节（路径 MTU 探测的结果）。
    pub mtu: u16,
    pub congestion: Congestion,
    pub counters: ConnectionCounters,
}

/// 一条连接从建立起累计的计数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnectionCounters {
    pub sent_packets: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    /// 拥塞控制认定发生了拥塞的次数。
    pub congestion_events: u64,
    /// 线路实际收发字节数（UDP 数据报载荷，含 QUIC 头部），同时包含绕过 QUIC 的独立加密网络包。
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl ConnectionCounters {
    /// 从 `earlier` 到现在增加了多少。
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            sent_packets: self.sent_packets.saturating_sub(earlier.sent_packets),
            lost_packets: self.lost_packets.saturating_sub(earlier.lost_packets),
            lost_bytes: self.lost_bytes.saturating_sub(earlier.lost_bytes),
            congestion_events: self.congestion_events.saturating_sub(earlier.congestion_events),
            bytes_sent: self.bytes_sent.saturating_sub(earlier.bytes_sent),
            bytes_received: self.bytes_received.saturating_sub(earlier.bytes_received),
        }
    }
}

/// 对端发来的数据报排在这里等上层来取，给上下文的接受方和发起方的各一个队列，虚拟网卡的包另一个。
pub(crate) struct DatagramQueues {
    pub acceptor: mpsc::Sender<Datagram>,
    pub initiator: mpsc::Sender<Datagram>,
    pub packets: mpsc::Sender<Datagram>,
}

impl DatagramQueues {
    fn of(&self, recipient: Recipient) -> &mpsc::Sender<Datagram> {
        match recipient {
            Recipient::Acceptor => &self.acceptor,
            Recipient::Initiator => &self.initiator,
        }
    }
}

/// 虚拟网卡的包在新建的连接上怎么走，和收封好的包的那一头。那一头和 QUIC 库的 socket 共用，所以由装配的一方建好传进来。
pub(crate) struct PacketRoute {
    pub transport: PacketTransport,
    pub inbox: Arc<Inbox>,
}

/// 一条和对端的连接。
struct Conn {
    quic: quinn::Connection,
    /// 握手时两端都声明了收得了封好的包：这条连接上网络包用它封了直接走路径层，不进 QUIC。
    sealed: Option<Arc<Session>>,
    /// 握手时两端都声明了认识一帧里合着好几个小网络包的。
    bundles: bool,
    /// 这条连接是谁拨的。两边同时拨号时，双方都留下编号小的那个节点拨的那一条。
    dialer: NodeId,
    /// 对端握手时使用的公钥；若 netmap 中其公钥变更，该连接即失效。
    key: PublicKey,
    /// 越新的越大。
    serial: u64,
    /// 握手完成、登记进来的时刻。
    established: Instant,
    streams: Arc<StreamCount>,
    /// 空闲够久了，却因为关掉就建不回来而留着（见 [`hold_idle`]）。只用来让开始和结束各记一行日志。
    held: AtomicBool,
    /// 这条连接建立时用的拥塞控制。连接一直用它，节点对的设置后来改了也不变。
    algorithm: Algorithm,
    /// 最近一次在这条连接上发网络包、或者从数据报里收到网络包的时刻；收到封好的包的时刻记在 `sealed` 里。
    /// 只运包的连接没有流，空闲回收按这两个算（见 [`Manager::idle_verdict`]）。
    packets: PacketClock,
}

impl Conn {
    /// 最近一次收发网络包的时刻，两种走法都算。
    fn last_packet(&self) -> Option<Instant> {
        let heard = self.sealed.as_ref().and_then(|session| session.heard());
        self.packets.last(self.established).max(heard)
    }

    /// 线上发出、收到的字节数：QUIC 的（含它自己的开销和重传），加上封好的网络包。
    fn traffic(&self) -> (u64, u64) {
        let stats = self.quic.stats();
        let (sealed_sent, sealed_received) = self.sealed.as_ref().map_or((0, 0), |session| session.traffic());
        (stats.udp_tx.bytes.saturating_add(sealed_sent), stats.udp_rx.bytes.saturating_add(sealed_received))
    }
}

/// 一条连接上最近一次收发网络包的时刻，记成连接建立之后的毫秒数加一（0 是还没有过）：每个包只写一次原子数。
#[derive(Debug, Default)]
struct PacketClock(AtomicU64);

impl PacketClock {
    fn touch(&self, established: Instant) {
        let millis = u64::try_from(established.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        self.0.store(millis + 1, Ordering::Relaxed);
    }

    fn last(&self, established: Instant) -> Option<Instant> {
        let stored = self.0.load(Ordering::Relaxed);
        (stored != 0).then(|| established + Duration::from_millis(stored - 1))
    }
}

#[derive(Default)]
struct PeerEntry {
    conns: Vec<Arc<Conn>>,
    /// 和这个对端之间已经关掉的连接一共发出、收到的字节数（线上的）。现在的连接的数另外从 QUIC 库读。
    closed_traffic: (u64, u64),
    /// 同一时刻只有一个任务在拨这个对端，别的等它的结果。
    dial: Arc<tokio::sync::Mutex<()>>,
    /// 有新的连接登记进来时通知：正在拨号的人可以改用对端连进来的那一条。
    arrived: Arc<Notify>,
}

impl PeerEntry {
    /// 开新的流用哪一条：编号小的那个节点拨的；同一方拨的取最新的。
    fn preferred(&self) -> Option<Arc<Conn>> {
        let alive = self.conns.iter().filter(|conn| conn.quic.close_reason().is_none());
        alive.min_by_key(|conn| (conn.dialer, Reverse(conn.serial))).cloned()
    }

    /// 还活着的连接超过 [`MAX_CONNS_PER_PEER`] 条时，把最旧的几条从表里拿掉，交给调用者关闭。
    fn take_surplus(&mut self) -> Vec<Arc<Conn>> {
        let alive: Vec<u64> = self.conns.iter().filter(|conn| conn.quic.close_reason().is_none()).map(|conn| conn.serial).collect();
        let doomed = oldest_beyond(&alive, MAX_CONNS_PER_PEER);
        let (surplus, kept) = self.conns.drain(..).partition(|conn| doomed.contains(&conn.serial));
        self.conns = kept;
        surplus
    }
}

/// `serials` 里除了最新的 `keep` 个之外的那些（编号越新越大）。
fn oldest_beyond(serials: &[u64], keep: usize) -> Vec<u64> {
    let mut sorted = serials.to_vec();
    sorted.sort_unstable_by_key(|&serial| Reverse(serial));
    sorted.split_off(keep.min(sorted.len()))
}

pub(crate) struct Manager {
    me: NodeId,
    key: Arc<NodeKey>,
    quic: quinn::Endpoint,
    paths: Arc<Paths>,
    netmap: watch::Receiver<Arc<Netmap>>,
    /// 现在的档位设置、网络的确认设置和按它们建好的配置。之后建立的连接用它；空闲回收每次检查时读它。
    configs: Mutex<Configs>,
    /// 接受连接一方的配置里不随档位和拥塞控制变的那部分（TLS）。
    server: quinn::ServerConfig,
    /// 节点对没有指定拥塞控制时用哪一种（环境变量 `I3T_CONGESTION`，没有就是 BBR），进程启动时定。
    default_algorithm: Algorithm,
    /// controller 当前是否在线（决定打洞信令是否可达）。装配层未通知时默认在线（静态模式不依赖 controller），
    /// 空闲连接按常规策略回收。
    controller_online: AtomicBool,
    peers: Mutex<HashMap<NodeId, PeerEntry>>,
    next_serial: AtomicU64,
    /// 对端连进来、还在握手的连接。
    handshakes: Arc<Handshakes>,
    /// 对端开过来的流排在这里等上层来取。
    incoming: mpsc::Sender<Stream>,
    datagrams: DatagramQueues,
    /// 新建的连接上网络包怎么走。进程启动时定。
    packets: PacketTransport,
    /// 收到的封好的包在这里按连接的密钥解开。连接登记时把密钥交给它，结束时收回。
    inbox: Arc<Inbox>,
    /// 封好了、还没有交给路径层的包（见 [`PacketSender::queue_packet`]）。
    batch: Mutex<Batch>,
    closed: watch::Sender<bool>,
}

impl Manager {
    pub(crate) fn new(
        key: Arc<NodeKey>,
        endpoint: (quinn::Endpoint, quinn::ServerConfig),
        paths: Arc<Paths>,
        netmap: watch::Receiver<Arc<Netmap>>,
        incoming: mpsc::Sender<Stream>,
        datagrams: DatagramQueues,
        packets: PacketRoute,
    ) -> Arc<Self> {
        let (quic, server) = endpoint;
        let (me, ack) = {
            let netmap = netmap.borrow();
            (netmap.me.id, AckFrequency::from(&netmap.network))
        };
        Arc::new(Self {
            me,
            key,
            quic,
            paths,
            netmap,
            configs: Mutex::new(Configs::new(Tuning::default(), ack, &server)),
            server,
            default_algorithm: Algorithm::from_env(),
            controller_online: AtomicBool::new(true),
            peers: Mutex::new(HashMap::new()),
            next_serial: AtomicU64::new(0),
            handshakes: Arc::default(),
            incoming,
            datagrams,
            packets: packets.transport,
            inbox: packets.inbox,
            batch: Mutex::default(),
            closed: watch::Sender::new(false),
        })
    }

    fn configs(&self) -> std::sync::MutexGuard<'_, Configs> {
        self.configs.lock().expect("connection configs mutex poisoned")
    }

    /// 换上新的档位设置。之后建立的连接（本端拨出的、对端连进来的）用它，已有的连接保持原样。
    pub(crate) fn tune(&self, tuning: Tuning) {
        let mut configs = self.configs();
        let ack = configs.ack;
        self.rebuild(&mut configs, tuning, ack);
    }

    /// 换上网络现在的确认设置。和档位一样：之后建立的连接用它，已有的连接保持建立时的设置。
    fn request_acks(&self, ack: AckFrequency) {
        let mut configs = self.configs();
        if configs.ack == ack {
            return;
        }
        let tuning = configs.tuning;
        self.rebuild(&mut configs, tuning, ack);
        tracing::info!(
            eliciting_threshold = ack.eliciting_threshold,
            max_delay = ?ack.max_delay,
            "网络 ACK 频率配置已更新，后续新建连接将通知对端采用新配置"
        );
    }

    /// 按新的档位和确认设置重建配置。调用者一直拿着 `current` 的锁，换档位的和换确认设置的不会互相盖掉对方的那一半。
    fn rebuild(&self, current: &mut Configs, tuning: Tuning, ack: AckFrequency) {
        let configs = Configs::new(tuning, ack, &self.server);
        // 无法识别具体对端的连接请求（不会进入握手）也需提供默认服务端配置，此处使用默认拥塞控制算法。
        self.quic.set_server_config(Some(configs.server(self.default_algorithm).as_ref().clone()));
        *current = configs;
    }

    /// 和 `peer` 之间新建的连接用哪种拥塞控制：节点对设置了的话用它，否则用节点的默认。
    pub(crate) fn algorithm_for(&self, peer: NodeId) -> Algorithm {
        let chosen = self.netmap.borrow().peer(peer).and_then(|info| info.congestion);
        chosen.map_or(self.default_algorithm, Algorithm::from)
    }

    /// 到 `peer` 的连接（开新流用的那一条）自己量的往返时间。没有连接时是 `None`。
    pub(crate) fn connection_rtt(&self, peer: NodeId) -> Option<Duration> {
        self.preferred(peer).map(|conn| conn.quic.rtt())
    }

    /// 到 `peer` 的连接（开新流用的那一条）现在的状况。没有连接时是 `None`。
    pub(crate) fn connection_report(&self, peer: NodeId) -> Option<ConnectionReport> {
        let conn = self.preferred(peer)?;
        let stats = conn.quic.stats();
        let (bytes_sent, bytes_received) = conn.traffic();
        Some(ConnectionReport {
            established: conn.established,
            rtt: stats.path.rtt,
            min_rtt: stats.path.min_rtt,
            cwnd_bytes: stats.path.cwnd,
            mtu: stats.path.current_mtu,
            congestion: Congestion::from(conn.algorithm),
            counters: ConnectionCounters {
                sent_packets: stats.path.sent_packets,
                lost_packets: stats.path.lost_packets,
                lost_bytes: stats.path.lost_bytes,
                congestion_events: stats.path.congestion_events,
                bytes_sent,
                bytes_received,
            },
        })
    }

    /// 到 `peer` 的连接现在用的拥塞控制；还没有连接时是新建的连接会用的那一种。
    pub(crate) fn congestion(&self, peer: NodeId) -> Algorithm {
        self.preferred(peer).map_or_else(|| self.algorithm_for(peer), |conn| conn.algorithm)
    }

    pub(crate) fn set_controller_online(&self, online: bool) {
        self.controller_online.store(online, Ordering::Relaxed);
    }

    fn peers(&self) -> std::sync::MutexGuard<'_, HashMap<NodeId, PeerEntry>> {
        self.peers.lock().expect("connection table mutex poisoned")
    }

    fn preferred(&self, peer: NodeId) -> Option<Arc<Conn>> {
        self.peers().get(&peer).and_then(PeerEntry::preferred)
    }

    pub(crate) fn subscribe_closed(&self) -> watch::Receiver<bool> {
        self.closed.subscribe()
    }

    /// 到 `peer` 开一条流。没有连接时先建；有对端连进来的连接就直接用。
    pub(crate) async fn open(self: &Arc<Self>, peer: NodeId) -> Result<(SendHalf, RecvHalf), OpenError> {
        let mut retried = false;
        loop {
            if *self.closed.borrow() {
                return Err(OpenError::Closed);
            }
            let conn = self.connection(peer).await?;
            match conn.quic.open_bi().await {
                Ok((send, recv)) => return Ok(stream::wrap(send, recv, &conn.streams)),
                // 查到的连接刚好断了：重建一次。再不行就报错，不无限重试。
                Err(error) if retried => return Err(OpenError::ConnectionLost { peer, reason: error.to_string() }),
                Err(_) => {
                    self.forget(peer, &conn);
                    retried = true;
                }
            }
        }
    }

    async fn connection(self: &Arc<Self>, peer: NodeId) -> Result<Arc<Conn>, OpenError> {
        let (dial, arrived) = {
            if self.netmap.borrow().peer(peer).is_none() {
                return Err(OpenError::UnknownPeer(peer));
            }
            let mut peers = self.peers();
            let entry = peers.entry(peer).or_default();
            if let Some(conn) = entry.preferred() {
                return Ok(conn);
            }
            (Arc::clone(&entry.dial), Arc::clone(&entry.arrived))
        };
        let _dialing = dial.lock().await;
        // 等锁的时候别人可能已经拨通了，或者对端连进来了。
        if let Some(conn) = self.preferred(peer) {
            return Ok(conn);
        }
        // 先登记再拨号，拨号期间对端连进来就不会漏掉。
        let arrival = arrived.notified();
        tokio::pin!(arrival);
        arrival.as_mut().enable();
        // 在独立任务中执行拨号，即使对端先连入也允许本次拨号完成而不中途取消。双向同时拨号时，对端可能已登记本端连接并开始开流，
        // 若中途丢弃会导致这些流断开（对端看到 "closed by peer"）；若对端同样因本端先连入而丢弃自身连接，双方将无可用连接而报错。
        // 多余的并发连接无碍，每个对端本来允许保留两条并由空闲回收清理。
        let manager = Arc::clone(self);
        let mut dialing = tokio::spawn(async move { manager.dial(peer).await });
        loop {
            tokio::select! {
                dialed = &mut dialing => {
                    return dialed.unwrap_or_else(|error| Err(OpenError::ConnectionLost { peer, reason: error.to_string() }));
                }
                () = &mut arrival => {
                    if let Some(conn) = self.preferred(peer) {
                        return Ok(conn);
                    }
                    // 对端连入的连接已关闭，继续等待本端拨号结果。
                    arrival.set(arrived.notified());
                    arrival.as_mut().enable();
                }
            }
        }
    }

    async fn dial(self: &Arc<Self>, peer: NodeId) -> Result<Arc<Conn>, OpenError> {
        let (peer_key, dial_out_only) = match self.netmap.borrow().peer(peer) {
            Some(info) => (info.key, info.dial_out_only),
            None => return Err(OpenError::UnknownPeer(peer)),
        };
        if dial_out_only {
            tracing::info!(%peer, "对端配置为仅主动出站，不接受入站连接，需等待其主动连入");
            return Err(OpenError::NoRoute(peer));
        }
        let deadline = tokio::time::Instant::now() + DIAL_TIMEOUT;
        if !self.paths.wait_for_route(peer, DIAL_TIMEOUT).await {
            tracing::info!(%peer, "{} 秒内未获取到对端可用路径（直连未建立且无可用 relay）", DIAL_TIMEOUT.as_secs());
            return Err(OpenError::NoRoute(peer));
        }
        let lost = |reason: String| OpenError::ConnectionLost { peer, reason };
        let algorithm = self.algorithm_for(peer);
        let transport = self.configs().transport(algorithm);
        let config = quic::client(&self.key, peer_key, transport, self.packets).map_err(|error| lost(error.to_string()))?;
        let connecting = match self.quic.connect_with(config, socket::virtual_addr(peer), SERVER_NAME) {
            Ok(connecting) => connecting,
            Err(ConnectError::EndpointStopping) => return Err(OpenError::Closed),
            Err(error) => return Err(lost(error.to_string())),
        };
        match tokio::time::timeout_at(deadline, connecting).await {
            Ok(Ok(connection)) => self
                .register(peer, connection, Origin { dialer: self.me, key: peer_key, algorithm })
                .ok_or_else(|| lost("握手期间对端已从 netmap 移除或公钥已变更".to_owned())),
            Ok(Err(error)) => {
                tracing::info!(%peer, %error, "和对端的握手失败");
                Err(lost(error.to_string()))
            }
            Err(_) => {
                tracing::info!(%peer, "和对端建立连接超时");
                Err(OpenError::Timeout(peer))
            }
        }
    }

    /// 登记一条握手完成的连接，并开始接收它上面的流。
    ///
    /// 握手期间 netmap 可能已更新（对端被移除或公钥变更），因此在持有连接表锁的情况下再次校验，不匹配则拒绝登记、
    /// 关掉，返回 `None`。[`follow_netmap`](Self::follow_netmap) 清扫时也要这把锁：这里读到的还是旧的 netmap，
    /// 清扫就排在登记之后，会看到这一条；读到的是新的，就在这里拦下。这条连接封包用的密钥也在这把锁下面登记，
    /// 道理一样。
    fn register(self: &Arc<Self>, peer: NodeId, quic: quinn::Connection, origin: Origin) -> Option<Arc<Conn>> {
        let serial = self.next_serial.fetch_add(1, Ordering::Relaxed);
        let Origin { dialer, key, algorithm } = origin;
        let streams = StreamCount::new();
        let agreed = sealed::agreed(&quic);
        let sealed = agreed.sealed.then(|| self.sealed_session(peer, &quic, dialer)).flatten();
        let conn = Arc::new(Conn {
            quic,
            sealed,
            bundles: agreed.bundles,
            dialer,
            key,
            serial,
            established: Instant::now(),
            streams,
            held: AtomicBool::new(false),
            algorithm,
            packets: PacketClock::default(),
        });
        let (surplus, early) = {
            let mut peers = self.peers();
            if self.netmap.borrow().peer(peer).map(|info| info.key) != Some(key) {
                drop(peers);
                tracing::info!(%peer, %dialer, "握手期间对端已从 netmap 移除或公钥已变更，不予登记并关闭连接");
                conn.quic.close(VarInt::from_u32(CLOSE_REVOKED), b"revoked");
                return None;
            }
            let entry = peers.entry(peer).or_default();
            entry.conns.push(Arc::clone(&conn));
            entry.arrived.notify_waiters();
            // 封包的密钥和连接在同一把锁下面登记，清扫要撤的也是这两样：放开锁之后才登记密钥的话，清扫正好插在中间时
            // 撤不到它，被吊销的对端的包还能再收一小会儿（到这条连接的任务收场为止）。
            let early = conn.sealed.as_ref().map(|session| self.inbox.admit(peer, session)).unwrap_or_default();
            (entry.take_surplus(), early)
        };
        // 对端握手完成得早的话，它的头几个封好的包已经到了，现在补收。要解密，所以放开锁之后做。
        self.inbox.deliver_early(peer, early);
        tracing::info!(
            %peer,
            %dialer,
            congestion = %Congestion::from(algorithm),
            sealed_packets = conn.sealed.is_some(),
            bundles = conn.bundles,
            "和对端的连接建立"
        );
        for old in surplus {
            tracing::info!(%peer, dialer = %old.dialer, "与该对端的连接数超过上限（{MAX_CONNS_PER_PEER}），关闭最早的连接");
            old.quic.close(VarInt::from_u32(CLOSE_SURPLUS), b"too many connections");
        }
        tokio::spawn(Arc::clone(self).serve(peer, Arc::clone(&conn)));
        Some(conn)
    }

    /// 从握手里导出这条连接封包用的密钥。握手时两端都声明了收得了封好的包才来这里。
    fn sealed_session(&self, peer: NodeId, quic: &quinn::Connection, dialer: NodeId) -> Option<Arc<Session>> {
        let role = if dialer == self.me { Role::Dialer } else { Role::Acceptor };
        match Session::derive(quic, role) {
            Ok(session) => Some(Arc::new(session)),
            Err(error) => {
                tracing::warn!(%peer, ?error, "无法从握手导出封包密钥，该连接上的网络包回退为数据报传输");
                None
            }
        }
    }

    fn forget(&self, peer: NodeId, conn: &Arc<Conn>) {
        if let Some(session) = &conn.sealed {
            self.inbox.dismiss(peer, session);
        }
        if let Some(entry) = self.peers().get_mut(&peer) {
            let before = entry.conns.len();
            entry.conns.retain(|other| !Arc::ptr_eq(other, conn));
            if entry.conns.len() < before {
                let (sent, received) = conn.traffic();
                entry.closed_traffic = (entry.closed_traffic.0.saturating_add(sent), entry.closed_traffic.1.saturating_add(received));
            }
        }
    }

    /// 和各个对端之间现在的连接上开着几条流、本节点启动以来两个方向各走了多少字节（关掉的连接也算），
    /// 只有现在有连接的对端，流量大的在前，最多 `limit` 个。
    pub(crate) fn peer_use(&self, limit: usize) -> Vec<PeerUse> {
        let peers = self.peers();
        let mut used: Vec<PeerUse> = peers
            .iter()
            .filter(|(_, entry)| entry.conns.iter().any(|conn| conn.quic.close_reason().is_none()))
            .map(|(&peer, entry)| {
                let flows = entry.conns.iter().map(|conn| conn.streams.open()).sum::<usize>();
                let (sent, received) = entry
                    .conns
                    .iter()
                    .map(|conn| conn.traffic())
                    .fold(entry.closed_traffic, |(a, b), (c, d)| (a.saturating_add(c), b.saturating_add(d)));
                PeerUse { peer, flows: u32::try_from(flows).unwrap_or(u32::MAX), tx_bytes: sent, rx_bytes: received }
            })
            .collect();
        used.sort_unstable_by_key(|entry| (std::cmp::Reverse(entry.tx_bytes.saturating_add(entry.rx_bytes)), entry.peer));
        used.truncate(limit);
        used
    }

    /// 一条连接的一生：接收对端开过来的流、数据报和信令，空闲够久就关掉。
    async fn serve(self: Arc<Self>, peer: NodeId, conn: Arc<Conn>) {
        let mut idle_check = tokio::time::interval(IDLE_CHECK);
        idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let reason = loop {
            tokio::select! {
                accepted = conn.quic.accept_bi() => match accepted {
                    Ok((send, recv)) => {
                        let (send, recv) = stream::wrap(send, recv, &conn.streams);
                        if self.incoming.send(Incoming { peer, send, recv }).await.is_err() {
                            break "本端正在关闭".to_owned();
                        }
                    }
                    Err(error) => break error.to_string(),
                },
                accepted = conn.quic.accept_uni() => match accepted {
                    Ok(recv) => drop(tokio::spawn(Arc::clone(&self).read_uni(peer, conn.quic.clone(), recv))),
                    Err(error) => break error.to_string(),
                },
                received = conn.quic.read_datagram() => match received {
                    Ok(payload) => self.deliver_datagram(peer, &conn, payload),
                    Err(error) => break error.to_string(),
                },
                _ = idle_check.tick() => {
                    if let Some(reason) = self.idle_verdict(peer, &conn) {
                        conn.quic.close(VarInt::from_u32(CLOSE_IDLE), reason.as_bytes());
                        break reason.to_owned();
                    }
                    // 关掉之后上层有包要发时会重建，新的连接是新的密钥。
                    if conn.sealed.as_ref().is_some_and(|session| session.is_spent()) {
                        conn.quic.close(VarInt::from_u32(CLOSE_KEYS_SPENT), b"sealed packet keys spent");
                        break "封包会话密钥已达使用上限".to_owned();
                    }
                }
            }
        };
        self.forget(peer, &conn);
        // 封好的包在端口忙的时候是直接丢的，没有别的地方看得到丢了多少。
        let unsent_sealed_packets = conn.sealed.as_ref().map_or(0, |session| session.unsent());
        tracing::info!(%peer, reason, unsent_sealed_packets, "和对端的连接结束");
    }

    /// 把对端发来的一个不保证送达的数据报排进上层的队列。队列满了就丢：上层来不及取，留着也只会过期。
    fn deliver_datagram(&self, peer: NodeId, conn: &Conn, payload: Bytes) {
        let queue = match Channel::peek(&payload) {
            Some(Channel::Context(recipient)) => self.datagrams.of(recipient),
            Some(Channel::Packet) => {
                conn.packets.touch(conn.established);
                &self.datagrams.packets
            }
            None => return tracing::trace!(%peer, len = payload.len(), "丢弃数据报：首字节无法识别目标通道"),
        };
        if queue.try_send(Datagram { peer, payload }).is_err() {
            tracing::trace!(%peer, "丢弃数据报：上层接收队列已满或本端正在关闭");
        }
    }

    /// 读对端开过来的一条单向流。首字节说明它是什么：数据报帧的首字节是标志，高位都是 0；
    /// 其余的是一条信令（一个 JSON 对象，首字节是 `{`）。
    async fn read_uni(self: Arc<Self>, peer: NodeId, connection: quinn::Connection, mut stream: quinn::RecvStream) {
        let mut first = [0; 1];
        match tokio::time::timeout(SIGNAL_TIMEOUT, stream.read_exact(&mut first)).await {
            Ok(Ok(())) => {}
            // 空的流什么都不表示；迟迟不写的流不等它。
            Ok(Err(_)) | Err(_) => return,
        }
        match Recipient::peek(&first) {
            Some(recipient) => self.read_reliable_datagram(peer, recipient, first, &connection, stream).await,
            None => read_signal(&self.paths, peer, first, stream).await,
        }
    }

    /// 读一个走单向流的数据报，排进上层的队列。
    ///
    /// 先向队列预留槽位再读取流：队列满时暂停读取，利用对端并发单向流上限形成反压，
    /// 阻止对端继续开启新流从而降低发送速率，既避免丢弃可靠数据报，也限制内存占用。
    async fn read_reliable_datagram(
        &self,
        peer: NodeId,
        recipient: Recipient,
        first: [u8; 1],
        connection: &quinn::Connection,
        mut stream: quinn::RecvStream,
    ) {
        let permit = tokio::select! {
            permit = self.datagrams.of(recipient).reserve() => match permit {
                Ok(permit) => permit,
                // 本端正在关闭。
                Err(_) => return,
            },
            // 连接没了就不用等了，不然没有人取的队列会把这些任务永远留着。
            _ = connection.closed() => return,
        };
        let limit = DatagramHeader::LEN + MAX_DATAGRAM_BODY_LEN - first.len();
        let rest = match tokio::time::timeout(RELIABLE_DATAGRAM_TIMEOUT, read_rest(&mut stream, limit)).await {
            Ok(Ok(rest)) => rest,
            Ok(Err(error)) => return tracing::debug!(%peer, %error, "丢弃单向流数据报：读取不完整或超出长度上限"),
            Err(_) => return tracing::debug!(%peer, "丢弃单向流数据报：读取超时"),
        };
        let mut payload = BytesMut::with_capacity(first.len() + rest.len());
        payload.put_slice(&first);
        payload.put_slice(&rest);
        permit.send(Datagram { peer, payload: payload.freeze() });
    }

    fn batch(&self) -> std::sync::MutexGuard<'_, Batch> {
        self.batch.lock().expect("sealed packet batch mutex poisoned")
    }

    /// 把一个网络包帧用这条连接的密钥封好，交给路径层，不进 QUIC。`hold` 说它可不可以先攒着等后面的一起发。
    fn send_sealed(&self, peer: NodeId, conn: &Conn, session: &Arc<Session>, frame: &[u8], hold: Hold) -> Result<(), DatagramSendError> {
        // 上限和走数据报时是同一个数，上层切片的办法不用变。封好之后多出 29 个字节，比 QUIC 的包头加数据报帧头
        // （至少 30 个）还少，所以装得进连接现在探测到的包长。
        let max = conn.quic.max_datagram_size().ok_or(DatagramSendError::Unsupported(peer))?;
        if frame.len() > max {
            return Err(DatagramSendError::TooLarge { len: frame.len(), max });
        }
        // 在不支持分段卸载（GSO）的平台上上限为 1，逐包单独发送。
        let limit = self.paths.max_transmit_segments().clamp(1, sealed::BATCH_PACKETS);
        let mut batch = self.batch();
        if batch.must_send_before(peer, session, frame.len() + SealedHeader::OVERHEAD, limit) {
            batch.send(&self.paths);
        }
        if let Err(spent) = batch.push(peer, session, frame) {
            // 关掉之后上层会重建，新的连接是新的密钥。
            conn.quic.close(VarInt::from_u32(CLOSE_KEYS_SPENT), b"sealed packet keys spent");
            return Err(DatagramSendError::ConnectionLost { peer, reason: spent.to_string() });
        }
        if hold == Hold::No || batch.is_full(limit) {
            batch.send(&self.paths);
        }
        drop(batch);
        // 空的数据报对端收到就丢，要的只是连接为它走一个来回：对端的进程换过的话，回来的是重置。
        if session.probe_due()
            && let Err(error) = conn.quic.send_datagram(Bytes::new())
        {
            tracing::trace!(%peer, %error, "发送空数据报探测对端存活失败");
        }
        Ok(())
    }

    /// 把一个网络包帧发给 `peer`：这条连接上包是封好了直接走路径层的就那样走，不然作为连接的数据报。
    fn send_packet(&self, peer: NodeId, frame: Bytes, hold: Hold) -> Result<(), DatagramSendError> {
        let conn = self.preferred(peer).ok_or(DatagramSendError::NotConnected(peer))?;
        match &conn.sealed {
            // 只在到对端是直连的时候这样发。经 relay 的路上可能有一段是 TCP，这种不受连接的拥塞控制管的包会把它灌满
            // （见 `Paths::send_direct`）：那时照旧作为连接的数据报，量有连接管着。对端收哪一种都一样，所以一个包一个包地定。
            Some(session) if self.paths.is_direct(peer) => self.send_sealed(peer, &conn, session, &frame, hold)?,
            // 连接的数据报由 QUIC 库自己成批地发，这里不用攒。
            Some(_) | None => {
                let len = frame.len();
                conn.quic.send_datagram(frame).map_err(|error| match error {
                    SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => DatagramSendError::Unsupported(peer),
                    SendDatagramError::TooLarge => DatagramSendError::TooLarge { len, max: conn.quic.max_datagram_size().unwrap_or(0) },
                    SendDatagramError::ConnectionLost(reason) => DatagramSendError::ConnectionLost { peer, reason: reason.to_string() },
                })?;
            }
        }
        conn.packets.touch(conn.established);
        Ok(())
    }

    /// 发数据报用的句柄。它不让连接多活：本端关掉之后，拿着它也发不出去。
    pub(crate) fn datagram_handle(self: &Arc<Self>) -> DatagramHandle {
        DatagramHandle { manager: Arc::downgrade(self) }
    }

    /// 这条连接该不该因为空闲而关掉；该关的话返回原因。
    ///
    /// 空闲是"没有流，也没有网络包"：从最后一条流结束和最后一个网络包两者里晚的那个算起。只运包的连接（虚拟网卡上的 ping、
    /// 如经虚拟网卡的 TCP 连接）在有网络包收发时保持存活，停止流量后按常规策略回收。
    fn idle_verdict(&self, peer: NodeId, conn: &Arc<Conn>) -> Option<&'static str> {
        let streams_ended = conn.streams.idle_since()?;
        let idle = conn.last_packet().map_or(streams_ended, |packet| packet.max(streams_ended)).elapsed();
        let preferred = self.preferred(peer).is_some_and(|preferred| Arc::ptr_eq(&preferred, conn));
        let keep_alive = self.netmap.borrow().peer(peer).is_some_and(|info| info.keep_alive);
        let idle_close = self.configs().tuning.idle_close;
        let (limit, reason) = idle_limit(preferred, keep_alive, idle_close)?;
        if idle < limit {
            return None;
        }
        // 只有到了该关的时候才去问路径层，平时每秒的检查不碰它。
        let online = self.controller_online.load(Ordering::Relaxed);
        let hold = hold_idle(preferred, online, || self.paths.has_relay_path(peer));
        if hold != conn.held.swap(hold, Ordering::Relaxed) {
            if hold {
                tracing::info!(%peer, "暂不回收空闲连接：controller 不可达且无 relay 路径可回退，关闭后无法重建");
            } else {
                tracing::info!(%peer, online, "controller 已恢复连接或已有经 relay 路径，恢复正常回收空闲连接");
            }
        }
        (!hold).then_some(reason)
    }

    /// 接受对端连进来的连接，直到本端关闭。
    pub(crate) async fn accept_loop(self: Arc<Self>) {
        while let Some(incoming) = self.quic.accept().await {
            let claimed = socket::node_of(incoming.remote_address());
            let (known, dial_out_only) = {
                let netmap = self.netmap.borrow();
                (claimed.filter(|id| netmap.peer(*id).is_some()), netmap.me.dial_out_only)
            };
            let Some(claimed) = known else {
                tracing::debug!(from = %incoming.remote_address(), "忽略非 netmap 节点的入站连接");
                incoming.ignore();
                continue;
            };
            if dial_out_only {
                tracing::info!(peer = %claimed, "本节点配置为仅主动出站，拒绝入站连接");
                incoming.refuse();
                continue;
            }
            let crowd = self.handshakes.crowd(claimed);
            match HandshakeGate::decide(crowd, incoming.remote_address_validated(), incoming.may_retry()) {
                HandshakeGate::Accept => {
                    let slot = self.handshakes.enter(claimed);
                    tokio::spawn(Arc::clone(&self).welcome(incoming, claimed, slot));
                }
                HandshakeGate::Retry => {
                    // 每个这样的包一行，不记成 info：伪造来源的人能让这里每秒来很多次。
                    tracing::debug!(peer = %claimed, ?crowd, "并发握手连接数过多，发送 QUIC Retry 验证来源地址");
                    if let Err(error) = incoming.retry() {
                        tracing::debug!(peer = %claimed, %error, "发送 QUIC Retry 失败");
                    }
                }
                HandshakeGate::Ignore => {
                    tracing::debug!(peer = %claimed, ?crowd, "并发握手连接数过多，忽略该连接请求");
                    incoming.ignore();
                }
            }
        }
    }

    /// 和一个连进来的对端握手，核对它是谁。`slot` 在握手结束（成功或者失败）之前占着握手的名额。
    async fn welcome(self: Arc<Self>, incoming: quinn::Incoming, claimed: NodeId, slot: HandshakeSlot) {
        // 拥塞控制算法先按对端宣称的身份选择；握手完成后再核对公钥，不匹配的连接会被直接关闭。
        let algorithm = self.algorithm_for(claimed);
        let server = self.configs().server(algorithm);
        let connecting = match incoming.accept_with(server) {
            Ok(connecting) => connecting,
            Err(error) => {
                tracing::debug!(peer = %claimed, %error, "接受对端入站连接失败");
                return;
            }
        };
        let handshake = tokio::time::timeout(WELCOME_TIMEOUT, connecting).await;
        drop(slot);
        let connection = match handshake {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                // 公钥不在 netmap 里的对端在这里被拒绝。
                tracing::info!(peer = %claimed, %error, "对端入站连接握手失败");
                return;
            }
            Err(_) => {
                tracing::info!(peer = %claimed, "对端入站连接握手超时");
                return;
            }
        };
        // 对端是谁只看握手里的公钥。包是从哪个节点的路上来的（`claimed`）必须和它对得上，
        // 不然这条连接的回包会被送到另一个节点那里去。
        match self.identify(&connection) {
            Some((peer, key)) if peer == claimed => drop(self.register(peer, connection, Origin { dialer: peer, key, algorithm })),
            identified => {
                tracing::warn!(peer = %claimed, identified = ?identified.map(|(peer, _)| peer), "连入对端的公钥与其宣称的节点身份不匹配，关闭连接");
                connection.close(VarInt::from_u32(CLOSE_IDENTITY), b"identity mismatch");
            }
        }
    }

    /// 握手时对端出示的公钥是 netmap 里哪个节点的。
    fn identify(&self, connection: &quinn::Connection) -> Option<(NodeId, PublicKey)> {
        let certificates = connection.peer_identity()?.downcast::<Vec<CertificateDer<'static>>>().ok()?;
        let key = tls::peer_key(certificates.first()?).ok()?;
        self.netmap.borrow().peers.iter().find(|peer| peer.key == key).map(|peer| (peer.id, key))
    }

    /// 跟随 netmap：对端被删除（吊销）或者换了公钥，和它的连接立刻关闭；网络的确认设置换了，之后建立的连接用新的。
    pub(crate) async fn follow_netmap(self: Arc<Self>) {
        let mut netmap = self.netmap.clone();
        while netmap.changed().await.is_ok() {
            let current = Arc::clone(&netmap.borrow_and_update());
            self.request_acks(AckFrequency::from(&current.network));
            self.peers().retain(|&peer, entry| {
                let expected = current.peer(peer).map(|info| info.key);
                entry.conns.retain(|conn| {
                    let valid = expected == Some(conn.key);
                    if !valid {
                        tracing::info!(%peer, "对端已从 netmap 移除或公钥已变更，关闭现有连接");
                        conn.quic.close(VarInt::from_u32(CLOSE_REVOKED), b"revoked");
                        // 它的封好的包从现在起也不收了，不等这条连接的任务自己收场。
                        if let Some(session) = &conn.sealed {
                            self.inbox.dismiss(peer, session);
                        }
                    }
                    valid
                });
                expected.is_some()
            });
        }
    }

    /// 在已有的连接里把一条信令送给对端。没有连接就不送：这时信令只能靠装配方的钩子（controller）。
    pub(crate) fn send_signal(&self, to: NodeId, signal: &Signal) {
        let Some(conn) = self.preferred(to) else { return };
        let body = match serde_json::to_vec(signal) {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(peer = %to, %error, "信令编码失败");
                return;
            }
        };
        tokio::spawn(async move {
            let sent = async {
                let mut stream = conn.quic.open_uni().await.map_err(|error| error.to_string())?;
                stream.write_all(&body).await.map_err(|error| error.to_string())?;
                stream.finish().map_err(|error| error.to_string())
            };
            if let Err(error) = sent.await {
                tracing::debug!(peer = %to, error, "通过连接发送信令失败");
            }
        });
    }

    /// 关闭：不再接受新的流，所有连接带着关闭帧结束。
    pub(crate) async fn close(&self) {
        self.closed.send_replace(true);
        self.quic.close(VarInt::from_u32(CLOSE_SHUTDOWN), b"shutdown");
        // 给关闭帧一点时间发出去；对面收不到也没关系，它那边会空闲超时。
        let _flushed = tokio::time::timeout(Duration::from_secs(1), self.quic.wait_idle()).await;
    }

    /// 不等待的关闭，丢弃时用。
    pub(crate) fn abort(&self) {
        self.closed.send_replace(true);
        self.quic.close(VarInt::from_u32(CLOSE_SHUTDOWN), b"shutdown");
    }
}

/// 指示独立加密的网络包是否允许暂存，以便与后续数据包合并批量发送。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hold {
    No,
    /// 调用方保证之后会 [`PacketSender::flush`]。
    UntilFlush,
}

/// 一条连接是谁拨的、对端握手时的公钥、用的拥塞控制。
#[derive(Debug, Clone, Copy)]
struct Origin {
    dialer: NodeId,
    key: PublicKey,
    algorithm: Algorithm,
}

/// 按一份档位设置和网络的确认设置建好的配置：每种拥塞控制一份传输参数，和用它的、接受连接一方的配置。
///
/// 拥塞控制在 QUIC 库里是按连接的传输参数选的，建立之后不能换，所以每种各备一份，建连接时按节点对的设置挑。
struct Configs {
    tuning: Tuning,
    ack: AckFrequency,
    bbr: (Arc<TransportConfig>, Arc<quinn::ServerConfig>),
    cubic: (Arc<TransportConfig>, Arc<quinn::ServerConfig>),
}

impl Configs {
    fn new(tuning: Tuning, ack: AckFrequency, server: &quinn::ServerConfig) -> Self {
        let build = |algorithm: Algorithm| {
            let transport = quic::transport(&tuning, algorithm, ack);
            let mut server = server.clone();
            server.transport_config(Arc::clone(&transport));
            (transport, Arc::new(server))
        };
        Self { tuning, ack, bbr: build(Algorithm::Bbr), cubic: build(Algorithm::Cubic) }
    }

    fn of(&self, algorithm: Algorithm) -> &(Arc<TransportConfig>, Arc<quinn::ServerConfig>) {
        match algorithm {
            Algorithm::Bbr => &self.bbr,
            Algorithm::Cubic => &self.cubic,
        }
    }

    fn transport(&self, algorithm: Algorithm) -> Arc<TransportConfig> {
        Arc::clone(&self.of(algorithm).0)
    }

    fn server(&self, algorithm: Algorithm) -> Arc<quinn::ServerConfig> {
        Arc::clone(&self.of(algorithm).1)
    }
}

/// 正在握手的、对端连进来的连接：总数和按自称的对端分的数。
#[derive(Debug, Default)]
struct Handshakes {
    counts: Mutex<HandshakeCounts>,
}

#[derive(Debug, Default)]
struct HandshakeCounts {
    total: usize,
    per_peer: HashMap<NodeId, usize>,
}

/// 一个连接请求到的时候，握手名额被占了多少。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Crowd {
    /// 自称来自同一个对端、还在握手的。
    peer: usize,
    /// 所有还在握手的。
    total: usize,
}

impl Handshakes {
    fn counts(&self) -> std::sync::MutexGuard<'_, HandshakeCounts> {
        self.counts.lock().expect("handshake table mutex poisoned")
    }

    fn crowd(&self, peer: NodeId) -> Crowd {
        let counts = self.counts();
        Crowd { peer: counts.per_peer.get(&peer).copied().unwrap_or(0), total: counts.total }
    }

    fn enter(self: &Arc<Self>, peer: NodeId) -> HandshakeSlot {
        let mut counts = self.counts();
        counts.total += 1;
        *counts.per_peer.entry(peer).or_insert(0) += 1;
        HandshakeSlot { table: Arc::clone(self), peer }
    }
}

/// 一个握手占着的名额，握手结束时丢弃。
struct HandshakeSlot {
    table: Arc<Handshakes>,
    peer: NodeId,
}

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        let mut counts = self.table.counts();
        counts.total -= 1;
        if let Some(count) = counts.per_peer.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                counts.per_peer.remove(&self.peer);
            }
        }
    }
}

/// 连接请求的处理策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeGate {
    /// 接受并开始握手。
    Accept,
    /// 先返回 Retry，要求对端携带令牌重试以验证源地址真实性；本端无需消耗算力或保存状态。
    /// Retry 会发往对端声称的源地址，伪造源地址的发送方无法收到该令牌。
    Retry,
    /// 忽略请求。真实对端会自动重传，待名额释放后再行接纳。
    Ignore,
}

impl HandshakeGate {
    /// `validated`：源地址已通过 Retry 令牌验证；`may_retry`：允许要求对端 Retry（已携带令牌的请求不能再次要求 Retry）。
    fn decide(crowd: Crowd, validated: bool, may_retry: bool) -> Self {
        let crowded = crowd.peer >= MAX_HANDSHAKES_PER_PEER || crowd.total >= MAX_HANDSHAKES;
        match (crowded, validated) {
            (false, _) => Self::Accept,
            (true, true) if crowd.total < MAX_VALIDATED_HANDSHAKES => Self::Accept,
            (true, true) => Self::Ignore,
            (true, false) if may_retry => Self::Retry,
            (true, false) => Self::Ignore,
        }
    }
}

/// 没有流的连接最多留多久、到时候关闭的原因；不回收时返回 `None`。
///
/// `preferred`：到这个对端开新的流用的就是这一条。不是的话它是两边同时拨号多出来的那一条，很快就关。
/// `keep_alive`：netmap 将该对端标记为常驻连接。由于对端可能不可直接连入，关闭后只能等待其重连，因此不回收。
/// `idle_close`：档位定的空闲回收时间，默认 5 分钟，这样 N 个节点不会留下 N² 条常驻连接和保活流量；`None` 不回收。
fn idle_limit(preferred: bool, keep_alive: bool, idle_close: Option<Duration>) -> Option<(Duration, &'static str)> {
    match (preferred, keep_alive, idle_close) {
        (false, _, _) => Some((DUPLICATE_IDLE_CLOSE, "同一对端存在多余连接，回收空闲的冗余连接")),
        (true, true, _) | (true, false, None) => None,
        (true, false, Some(limit)) => Some((limit, "空闲时长已超过档位配置的回收阈值")),
    }
}

/// 到了空闲回收的时间，这条连接是不是要先留着。
///
/// 连接关闭后若要重建，握手包需经 relay 转发或重新打洞（打洞信令依赖 controller）。当两者均不可用时
/// （controller 不可达且无经 relay 路径），关闭后将无法重建，因此暂缓回收；待 controller 恢复连接
/// 或出现经 relay 路径后，下一次周期检查（每秒一次）恢复正常回收。冗余连接（`preferred` 为 `false`）仍按原规则关闭，保留主连接。
/// `relay_path` 只在需要时才问。
fn hold_idle(preferred: bool, controller_online: bool, relay_path: impl FnOnce() -> bool) -> bool {
    preferred && !controller_online && !relay_path()
}

/// 一条流剩下的内容读不完整的原因。
#[derive(Debug, thiserror::Error)]
enum ReadRestError {
    #[error(transparent)]
    Read(#[from] quinn::ReadError),
    #[error("内容超过了 {limit} 字节的上限")]
    TooLong { limit: usize },
}

/// 把一条流剩下的内容读完，最多 `limit` 字节。
///
/// 不用 quinn 的 `read_to_end`：它不按顺序读，对端重传过的数据会被算两遍。读到一半把流丢掉（超时，或者连接关了）时，
/// 库里给流量控制记账的减法就会减出负数：debug 构建直接 panic，release 构建悄悄绕回成一个巨大的额度。按顺序读没有这个问题。
async fn read_rest(stream: &mut quinn::RecvStream, limit: usize) -> Result<Vec<u8>, ReadRestError> {
    let mut rest = Vec::new();
    while let Some(chunk) = stream.read_chunk(limit - rest.len() + 1, true).await? {
        if chunk.bytes.len() > limit - rest.len() {
            return Err(ReadRestError::TooLong { limit });
        }
        rest.extend_from_slice(&chunk.bytes);
    }
    Ok(rest)
}

/// 读对端在连接里送来的一条信令（一条单向流，内容是一个 JSON 对象），交给路径层。`first` 是已经读走的首字节。
async fn read_signal(paths: &Paths, peer: NodeId, first: [u8; 1], mut stream: quinn::RecvStream) {
    let rest = match tokio::time::timeout(SIGNAL_TIMEOUT, read_rest(&mut stream, SIGNAL_MAX_BYTES - first.len())).await {
        Ok(Ok(rest)) => rest,
        Ok(Err(error)) => {
            tracing::debug!(%peer, %error, "读取连接内信令失败");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "读取连接内信令超时");
            return;
        }
    };
    let body = [&first[..], &rest].concat();
    match serde_json::from_slice::<Signal>(&body) {
        Ok(signal) => paths.handle_signal(peer, signal),
        Err(error) => tracing::debug!(%peer, %error, "连接内信令解析失败"),
    }
}

/// 往对端发数据报的句柄，[`crate::Endpoint`] 给出来的。
///
/// 数据报走开新的流会用的那条连接。两边同时拨号留下两条连接时，两端可能各用各的那一条发，
/// 这没有关系：收的一方不分数据报是从哪一条连接上来的，只认对端是谁。
#[derive(Clone)]
pub struct DatagramHandle {
    manager: Weak<Manager>,
}

impl std::fmt::Debug for DatagramHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramHandle").finish_non_exhaustive()
    }
}

impl DatagramHandle {
    fn connection(&self, peer: NodeId) -> Result<Arc<Conn>, DatagramSendError> {
        self.manager.upgrade().and_then(|manager| manager.preferred(peer)).ok_or(DatagramSendError::NotConnected(peer))
    }
}

impl PacketSender for DatagramHandle {
    fn send_packet(&self, peer: NodeId, frame: Bytes) -> Result<(), DatagramSendError> {
        let manager = self.manager.upgrade().ok_or(DatagramSendError::NotConnected(peer))?;
        manager.send_packet(peer, frame, Hold::No)
    }

    fn queue_packet(&self, peer: NodeId, frame: Bytes) -> Result<(), DatagramSendError> {
        let manager = self.manager.upgrade().ok_or(DatagramSendError::NotConnected(peer))?;
        manager.send_packet(peer, frame, Hold::UntilFlush)
    }

    fn flush(&self) {
        if let Some(manager) = self.manager.upgrade() {
            manager.batch().send(&manager.paths);
        }
    }

    fn bundle_capacity(&self, peer: NodeId) -> Option<usize> {
        let manager = self.manager.upgrade()?;
        let conn = manager.preferred(peer)?;
        (conn.bundles && conn.sealed.is_some() && manager.paths.is_direct(peer)).then(|| conn.quic.max_datagram_size()).flatten()
    }

    async fn connect(&self, peer: NodeId) -> Result<(), OpenError> {
        let manager = self.manager.upgrade().ok_or(OpenError::Closed)?;
        if *manager.closed.borrow() {
            return Err(OpenError::Closed);
        }
        manager.connection(peer).await.map(drop)
    }
}

impl DatagramSender for DatagramHandle {
    fn max_datagram_len(&self, peer: NodeId) -> Option<usize> {
        self.connection(peer).ok()?.quic.max_datagram_size()
    }

    fn send_datagram(&self, peer: NodeId, datagram: Bytes) -> Result<(), DatagramSendError> {
        let conn = self.connection(peer)?;
        let len = datagram.len();
        conn.quic.send_datagram(datagram).map_err(|error| match error {
            SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => DatagramSendError::Unsupported(peer),
            SendDatagramError::TooLarge => DatagramSendError::TooLarge { len, max: conn.quic.max_datagram_size().unwrap_or(0) },
            SendDatagramError::ConnectionLost(reason) => DatagramSendError::ConnectionLost { peer, reason: reason.to_string() },
        })
    }

    async fn send_reliable(&self, peer: NodeId, datagram: Bytes) -> Result<(), DatagramSendError> {
        let conn = self.connection(peer)?;
        let lost = |reason: String| DatagramSendError::ConnectionLost { peer, reason };
        // 对端同时接受的单向流有上限，到了上限就在这里等它读完前面的。
        let mut stream = conn.quic.open_uni().await.map_err(|error| lost(error.to_string()))?;
        stream.write_all(&datagram).await.map_err(|error| lost(error.to_string()))?;
        stream.finish().map_err(|error| lost(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn beyond_two_connections_to_a_peer_the_oldest_ones_go() {
        assert!(oldest_beyond(&[3, 7], MAX_CONNS_PER_PEER).is_empty());
        assert_eq!(oldest_beyond(&[3, 9, 7], MAX_CONNS_PER_PEER), [3]);
        assert_eq!(oldest_beyond(&[12, 3, 9, 7, 10], MAX_CONNS_PER_PEER), [9, 7, 3]);
        assert!(oldest_beyond(&[], MAX_CONNS_PER_PEER).is_empty());
    }

    /// 同一个对端一条接一条连进来，每一条都是回环地址上真的 QUIC 连接，本端这一头按先后编号。
    struct Arrivals {
        listener: quinn::Endpoint,
        dialer: quinn::Endpoint,
        config: quinn::ClientConfig,
        peer_key: PublicKey,
        next_serial: u64,
        /// 对端那一头。放下它连接就关了，所以一直拿着。
        far_ends: Vec<quinn::Connection>,
    }

    impl Arrivals {
        fn new() -> Self {
            let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let (me, peer) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
            let transport = quic::transport(&Tuning::default(), Algorithm::from_env(), AckFrequency::default());
            Self {
                listener: quinn::Endpoint::server(quic::server(&me, |_| true, PacketTransport::default()).unwrap(), loopback).unwrap(),
                dialer: quinn::Endpoint::client(loopback).unwrap(),
                config: quic::client(&peer, me.public(), transport, PacketTransport::default()).unwrap(),
                peer_key: peer.public(),
                next_serial: 1,
                far_ends: Vec::new(),
            }
        }

        async fn next(&mut self) -> Arc<Conn> {
            let to = self.listener.local_addr().unwrap();
            let dialing = self.dialer.connect_with(self.config.clone(), to, SERVER_NAME).unwrap();
            let (far, near) = tokio::join!(dialing, async { self.listener.accept().await.unwrap().await });
            self.far_ends.push(far.unwrap());
            let serial = self.next_serial;
            self.next_serial += 1;
            Arc::new(Conn {
                quic: near.unwrap(),
                sealed: None,
                bundles: false,
                dialer: NodeId::new(2).unwrap(),
                key: self.peer_key,
                serial,
                established: Instant::now(),
                streams: StreamCount::new(),
                held: AtomicBool::new(false),
                algorithm: Algorithm::from_env(),
                packets: PacketClock::default(),
            })
        }
    }

    fn serials(conns: &[Arc<Conn>]) -> Vec<u64> {
        conns.iter().map(|conn| conn.serial).collect()
    }

    // 集成测试（tests/limits.rs）里很难让同一个对端的三条连接同时活着：对端重启回来之后，旧连接在新的握完手之前
    // 就被无状态重置关掉了。这里直接拿真的连接来验证上限。
    #[tokio::test]
    async fn a_peer_keeps_its_two_newest_live_connections_and_closed_ones_do_not_count() {
        let mut arrivals = Arrivals::new();
        let mut entry = PeerEntry::default();

        for _ in 0..MAX_CONNS_PER_PEER {
            entry.conns.push(arrivals.next().await);
            assert!(entry.take_surplus().is_empty(), "没有超过上限时一条也不动");
        }

        entry.conns.push(arrivals.next().await);
        assert_eq!(serials(&entry.take_surplus()), [1], "超过上限时交出最旧的那条");
        assert_eq!(serials(&entry.conns), [2, 3]);

        // 已经断掉的不占名额：它留在表里（等它自己的任务收尾时拿掉），新来的不会把还活着的挤掉。
        entry.conns[0].quic.close(VarInt::from_u32(CLOSE_SHUTDOWN), b"");
        entry.conns.push(arrivals.next().await);
        assert!(entry.take_surplus().is_empty(), "活着的只有两条");
        assert_eq!(serials(&entry.conns), [2, 3, 4]);

        entry.conns.push(arrivals.next().await);
        assert_eq!(serials(&entry.take_surplus()), [3], "活着的三条里交出最旧的");
        assert_eq!(serials(&entry.conns), [2, 4, 5]);
        assert_eq!(entry.preferred().map(|conn| conn.serial), Some(5), "开新的流用最新的那条");
    }

    #[test]
    fn handshakes_are_accepted_until_crowded_then_asked_to_prove_their_address() {
        let crowd = |peer, total| Crowd { peer, total };
        assert_eq!(HandshakeGate::decide(crowd(0, 0), false, true), HandshakeGate::Accept);
        assert_eq!(HandshakeGate::decide(crowd(MAX_HANDSHAKES_PER_PEER - 1, MAX_HANDSHAKES - 1), false, true), HandshakeGate::Accept);

        // 同一个对端名下的握手太多，或者总的太多：没有验证过地址的先要 Retry，Retry 过了还不行的就不理。
        for crowded in [crowd(MAX_HANDSHAKES_PER_PEER, 0), crowd(0, MAX_HANDSHAKES)] {
            assert_eq!(HandshakeGate::decide(crowded, false, true), HandshakeGate::Retry, "{crowded:?}");
            assert_eq!(HandshakeGate::decide(crowded, false, false), HandshakeGate::Ignore, "{crowded:?}");
            // 带着令牌回来的是真的对端：别人占满了名额它也接，直到更高的上限。
            assert_eq!(HandshakeGate::decide(crowded, true, false), HandshakeGate::Accept, "{crowded:?}");
        }
        assert_eq!(HandshakeGate::decide(crowd(0, MAX_VALIDATED_HANDSHAKES), true, false), HandshakeGate::Ignore);
    }

    #[test]
    fn a_handshake_holds_its_slot_until_it_ends() {
        let table = Arc::new(Handshakes::default());
        let (a, b) = (NodeId::new(1).unwrap(), NodeId::new(2).unwrap());
        let first = table.enter(a);
        let second = table.enter(a);
        let other = table.enter(b);
        assert_eq!(table.crowd(a), Crowd { peer: 2, total: 3 });
        assert_eq!(table.crowd(b), Crowd { peer: 1, total: 3 });
        drop((first, other));
        assert_eq!(table.crowd(a), Crowd { peer: 1, total: 1 });
        drop(second);
        assert_eq!(table.crowd(a), Crowd { peer: 0, total: 0 });
        assert!(table.counts().per_peer.is_empty(), "没有在握手的对端不留记录");
    }

    #[test]
    fn idle_connections_are_closed_after_the_profile_time_unless_the_peer_is_kept_alive() {
        let default = Tuning::default().idle_close;
        assert_eq!(idle_limit(true, false, default).map(|(limit, _)| limit), Some(Duration::from_secs(300)));
        assert_eq!(idle_limit(true, false, Some(Duration::from_secs(60))).map(|(limit, _)| limit), Some(Duration::from_secs(60)));
        assert_eq!(idle_limit(true, true, default), None, "常驻的对端不回收");
        assert_eq!(idle_limit(true, false, None), None, "档位说不回收");
        // 多出来的那一条连接很快就关，常驻和不回收的档位也一样：留着的是另一条。
        for idle_close in [default, None] {
            assert_eq!(idle_limit(false, false, idle_close).map(|(limit, _)| limit), Some(DUPLICATE_IDLE_CLOSE));
            assert_eq!(idle_limit(false, true, idle_close).map(|(limit, _)| limit), Some(DUPLICATE_IDLE_CLOSE));
        }
    }

    #[test]
    fn an_idle_connection_is_held_only_while_neither_the_controller_nor_a_relay_could_bring_it_back() {
        assert!(hold_idle(true, false, || false), "controller 连不上、也没有经 relay 的路：关掉就建不回来");
        assert!(!hold_idle(true, true, || false), "controller 连得上：信令有路走，照常回收");
        assert!(!hold_idle(true, false, || true), "有经 relay 的路：照常回收");
        assert!(!hold_idle(false, false, || false), "多出来的那一条照样关，留着的是另一条");
        // controller 连得上时不去问路径层。
        assert!(!hold_idle(true, true, || unreachable!("controller 连得上时不该问有没有经 relay 的路")));
    }
}
