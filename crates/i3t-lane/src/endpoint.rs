//! [`Lanes`]：一个节点上所有的 lane。按对端分，开流和接受流都从这里走。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use i3t_conn::contract::{Datagram, DatagramSendError, DatagramSender, Datagrams};
use i3t_conn::{Acceptor, Connector, Incoming, OpenError};
use i3t_crypto::NodeKey;
use i3t_crypto::tls::{Identity, TlsError};
use i3t_proto::flow::Recipient;
use i3t_proto::{NodeId, PublicKey};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{ClientConfig, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, watch};
use tokio::time::Instant;

use crate::admission::Admission;
use crate::demand::Demand;
use crate::dialler::{self, DialSide, Opening};
use crate::error::{LaneError, OpenLaneError};
use crate::frame::Purpose;
use crate::holder::{self, Holder};
use crate::lane::{self, Dial, Lane};
use crate::status::{Book, Counters, LaneStatus, PeerLaneStatus, Tally};
use crate::stream::{self, LaneRecv, LaneSend};

/// 一个对端同时在用的 lane 最多这么多条（和共用连接上的并发流上限一样）。再开过来的流直接重置。
const MAX_IN_USE_PER_PEER: usize = 16384;
/// 一个对端拨来、等它自己开流的 lane（它的热 lane）最多这么多条。
const MAX_OWN_WAITING_PER_PEER: usize = 64;
/// 当场拨一条 lane 给自己开流最多等多久。超过了调用方改走共用的连接，一次 SYN 重传（1 秒）还等得起。
const OWN_DIAL_DEADLINE: Duration = Duration::from_secs(3);
/// ClientHello 要在接受连接之后多久之内到齐。
const FIRST_RECORD_DEADLINE: Duration = Duration::from_secs(3);
/// 拒绝和挤掉连接的日志最多隔这么久记一条。
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// lane 的设置。默认值就是产品里用的；测试可以把时间调短。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LaneConfig {
    /// 平时至少备着多少条空闲的 lane：接受方是每个拨号方为本节点停着的（本节点自己也拨它时是 0），
    /// 拨号方是留给自己开流的（往对方开过流之后才备）。实际备多少跟着新流的速率往上走（见 `demand`）。
    pub min_idle: usize,
    /// 控制 lane 上多久发一次 PING。三个周期听不到对方就判控制 lane 断了。
    pub ping_interval: Duration,
    /// 池空时取 lane 最多等多久。
    pub claim_wait: Duration,
    /// 拨进来的连接从接受起多久之内要握手完成并发来 HELLO。
    pub handshake_deadline: Duration,
}

impl Default for LaneConfig {
    fn default() -> Self {
        Self {
            min_idle: 4,
            ping_interval: Duration::from_secs(10),
            claim_wait: Duration::from_secs(2),
            handshake_deadline: Duration::from_secs(10),
        }
    }
}

/// 一个打开了 ice3proxy 的对端。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanePeer {
    pub id: NodeId,
    /// netmap 里它的公钥。lane 的 TLS 握手钉住它。
    pub key: PublicKey,
    /// 本节点拨它时用的地址：它的节点端口（启用了 relay 的节点在这个端口上听 TCP）。
    /// 空的表示本节点不拨它，只接受它拨来的 lane。
    pub dial: Vec<SocketAddr>,
}

/// 一个节点上所有的 lane。实现 [`Connector`] 和 [`Acceptor`]：到对端开流、接受对端开来的流。
///
/// 丢弃它时所有的空闲 lane 和控制 lane 都被关掉；正在承载流的 lane 不受影响，跑到流自己结束。
pub struct Lanes {
    inner: Arc<Inner>,
    _shutdown: watch::Sender<()>,
}

type AllowedKeys = HashMap<PublicKey, (NodeId, watch::Receiver<()>)>;

pub(crate) struct Inner {
    identity: Identity,
    server: Arc<ServerConfig>,
    pub(crate) config: LaneConfig,
    pub(crate) counters: Arc<Counters>,
    /// 认得的公钥。TLS 的校验器在握手时查它，所以和 `peers` 分开放。
    keys: Arc<Mutex<AllowedKeys>>,
    peers: Mutex<HashMap<NodeId, Peer>>,
    /// 包括正在排空的 lane。需要同时持锁时先拿 peers，再拿 active。
    active: Mutex<HashMap<NodeId, ActivePeer>>,
    incoming: mpsc::UnboundedSender<Incoming<LaneSend, LaneRecv>>,
    accepted: tokio::sync::Mutex<mpsc::UnboundedReceiver<Incoming<LaneSend, LaneRecv>>>,
    admission: Arc<Admission>,
    pub(crate) shutdown: watch::Receiver<()>,
    going_away: AtomicBool,
    random: SystemRandom,
    refusal_log: Mutex<RefusalLog>,
}

pub(crate) struct Peer {
    key: PublicKey,
    /// 移除表项会关闭这个 channel，通知旧的空闲 lane 和尚未完成的开流。
    _enabled: watch::Sender<()>,
    pub(crate) membership: watch::Receiver<()>,
    pub(crate) holder: Holder,
    dial: Option<DialSide>,
    /// 它拨来、等它自己开流的 lane 有几条。
    own_waiting: usize,
    /// 这个对端的计数。
    tally: Arc<Tally>,
}

struct ActivePeer {
    key: PublicKey,
    revoked: watch::Sender<bool>,
}

impl Peer {
    pub(crate) fn matches(&self, membership: &watch::Receiver<()>) -> bool {
        self.membership.same_channel(membership)
    }

    /// 本节点拨不拨这个对端。拨的话，本节点往它开流用自己拨的 lane，不需要它停 lane 过来。
    pub(crate) fn dials(&self) -> bool {
        self.dial.is_some()
    }
}

/// 拨一条 lane 要用的东西。
pub(crate) struct DialPlan {
    pub(crate) addrs: Vec<SocketAddr>,
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) membership: watch::Receiver<()>,
    pub(crate) book: Book,
}

impl DialPlan {
    fn new(dial: &DialSide, membership: &watch::Receiver<()>, book: Book) -> Self {
        Self { addrs: dial.addrs_in_order(), config: Arc::clone(&dial.config), membership: membership.clone(), book }
    }
}

struct DialChoice {
    generation: Arc<Notify>,
    lane: Result<Lane, DialPlan>,
}

impl Lanes {
    /// # Errors
    ///
    /// 用节点密钥签证书失败。
    pub fn new(key: &NodeKey, config: LaneConfig) -> Result<Self, TlsError> {
        let identity = Identity::new(key)?;
        let keys: Arc<Mutex<AllowedKeys>> = Arc::default();
        let allowed = Arc::clone(&keys);
        let server = lane::server_config(&identity, move |key| allowed.lock().expect("lane keys mutex poisoned").contains_key(key))?;
        let (incoming, accepted) = mpsc::unbounded_channel();
        let (shutdown_sender, shutdown) = watch::channel(());
        let inner = Inner {
            identity,
            server,
            config,
            counters: Arc::default(),
            keys,
            peers: Mutex::default(),
            active: Mutex::default(),
            incoming,
            accepted: tokio::sync::Mutex::new(accepted),
            admission: Arc::default(),
            shutdown,
            going_away: AtomicBool::new(false),
            random: SystemRandom::new(),
            refusal_log: Mutex::default(),
        };
        Ok(Self { inner: Arc::new(inner), _shutdown: shutdown_sender })
    }

    /// 换成新的一组对端。移除对端或更换公钥会关闭它的所有 lane。
    ///
    /// # Errors
    ///
    /// 为某个对端构建 TLS 配置失败；调用失败时现有状态保持不变。
    pub fn set_peers(&self, peers: impl IntoIterator<Item = LanePeer>) -> Result<(), TlsError> {
        let peers: Vec<_> = peers.into_iter().collect();
        let identities: Vec<_> = peers.iter().map(|peer| (peer.id, peer.key)).collect();
        self.set_peers_with_identities(peers, identities)
    }

    /// 用完整的 netmap 身份更新 lane。仍在 netmap 中且公钥没变的对端可以关闭 ice3proxy，让存量流自然结束。
    /// 节点离开 netmap 或公钥变化时吊销它的存量流。要在 tokio 运行时里调用。
    ///
    /// # Errors
    ///
    /// 为某个对端构建 TLS 配置失败；调用失败时现有状态保持不变。
    pub fn set_peers_with_identities(
        &self,
        peers: impl IntoIterator<Item = LanePeer>,
        identities: impl IntoIterator<Item = (NodeId, PublicKey)>,
    ) -> Result<(), TlsError> {
        let inner = &self.inner;
        let identities: HashMap<_, _> = identities.into_iter().collect();
        let wanted: HashMap<_, _> =
            peers.into_iter().filter(|peer| identities.get(&peer.id) == Some(&peer.key)).map(|peer| (peer.id, peer)).collect();
        let configs = wanted
            .values()
            .filter(|peer| !peer.dial.is_empty())
            .map(|peer| Ok((peer.id, lane::client_config(&inner.identity, peer.key)?)))
            .collect::<Result<HashMap<NodeId, Arc<ClientConfig>>, TlsError>>()?;
        let mut peers = inner.lock_peers();
        inner.active.lock().expect("lane active mutex poisoned").retain(|id, entry| {
            if identities.get(id) != Some(&entry.key) {
                // 在接受新流之前发布吊销。这里只更新信号，流自己停止 I/O 并关闭 socket。
                entry.revoked.send_replace(true);
                return false;
            }
            wanted.contains_key(id) || entry.revoked.receiver_count() != 0
        });
        peers.retain(|id, entry| {
            let keep = wanted.get(id).is_some_and(|peer| peer.key == entry.key);
            if !keep {
                entry.holder.close();
                tracing::info!(peer = %id, "停止为该节点启用 ice3proxy");
            }
            keep
        });
        for peer in wanted.into_values() {
            let entry = peers.entry(peer.id).or_insert_with(|| {
                let (enabled, membership) = watch::channel(());
                Peer {
                    key: peer.key,
                    _enabled: enabled,
                    membership,
                    holder: Holder::default(),
                    dial: None,
                    own_waiting: 0,
                    tally: Arc::default(),
                }
            });
            let same_dial = entry.dial.as_ref().is_some_and(|dial| dial.addrs == peer.dial);
            if same_dial || (peer.dial.is_empty() && entry.dial.is_none()) {
                continue;
            }
            entry.dial = configs.get(&peer.id).map(|config| {
                let wake = Arc::new(Notify::new());
                let task = tokio::spawn(dialler::run(Arc::clone(inner), peer.id, Arc::clone(&wake))).abort_handle();
                tracing::info!(peer = %peer.id, addrs = ?peer.dial, "开始向该节点拨号建立 ice3proxy");
                DialSide {
                    addrs: peer.dial.clone(),
                    config: Arc::clone(config),
                    warm: Default::default(),
                    peer_going_away: false,
                    control_up: false,
                    parked: 0,
                    own: None,
                    dial_time: None,
                    trimmed: None,
                    wake,
                    task,
                    last_good: None,
                }
            });
        }
        *inner.keys.lock().expect("lane keys mutex poisoned") =
            peers.iter().map(|(&id, entry)| (entry.key, (id, entry.membership.clone()))).collect();
        Ok(())
    }

    /// 接过一条已经被接受的 TCP 连接：它是拨来的 lane（开头是 TLS 记录，见 [`is_lane`]）。
    ///
    /// 给节点端口上的 TCP 监听用：那个监听属于 relay，它按开头的字节分辨出 lane 之后交到这里。
    /// `already_read` 是它为了分辨已经从连接上读走的字节（用 `peek` 的话传空）。
    ///
    /// 不等待：握手在自己的任务里做，从接受起有绝对的时限；同一来源、以及全部来源还没握手完的连接数有上限，
    /// 满了挤掉最老的。
    pub fn accept_tcp(&self, stream: TcpStream, from: SocketAddr, already_read: &[u8]) {
        let inner = &self.inner;
        let (ticket, evicted) = inner.admission.admit(from.ip());
        if evicted > 0 {
            inner.counters.handshake_busy.add(evicted);
            inner.log_refusal(format_args!("未完成握手的 lane 数量超出上限，已驱逐 {evicted} 条最早的连接（因收到来自 {from} 的新连接）"));
        }
        let id = ticket.id();
        let started = Instant::now();
        let task = tokio::spawn({
            let inner = Arc::clone(inner);
            let prefix = BytesMut::from(already_read);
            async move {
                let deadline = started + inner.config.handshake_deadline;
                let first_record = started + FIRST_RECORD_DEADLINE;
                let resolve = |key: &PublicKey| inner.keys.lock().expect("lane keys mutex poisoned").get(key).cloned();
                let accepted = lane::accept(stream, prefix, Arc::clone(&inner.server), resolve, first_record, deadline).await;
                drop(ticket);
                match accepted {
                    Ok(lane) => inner.dispatch(lane),
                    Err(error) => inner.handshake_failed(from, &error),
                }
            }
        });
        inner.admission.attach(id, task.abort_handle());
    }

    /// 在 `listener` 上接受拨来的 lane，直到本节点关闭。节点用的是 relay 的监听（见 [`accept_tcp`](Self::accept_tcp)）；
    /// 这个给测试和单独跑 lane 的场合用。
    pub async fn serve(&self, listener: TcpListener) {
        let mut shutdown = self.inner.shutdown.clone();
        loop {
            let accepted = tokio::select! {
                _ = shutdown.changed() => return,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, from)) => self.accept_tcp(stream, from, &[]),
                Err(error) => {
                    tracing::warn!(%error, "接受 lane 连接失败");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// 在 lane 上到 `peer` 开一条流。
    ///
    /// 本节点拨 `peer` 时用自己的热 lane，没有了就当场拨一条（最多等 3 秒）；否则从 `peer` 停在本节点的 lane 里取，
    /// 池空时等它补拨，最多等 [`LaneConfig::claim_wait`]。
    ///
    /// 返回的流还没有发出任何东西：头写完时调 [`LaneSend::end_header`]（见那里）。
    ///
    /// # Errors
    ///
    /// 获取可用 lane 失败。此时开流请求尚未发出，调用方可安全回退到共用连接。
    pub async fn open_stream(&self, peer: NodeId) -> Result<(LaneSend, LaneRecv), OpenLaneError> {
        let inner = &self.inner;
        if inner.is_going_away() {
            return Err(OpenLaneError::GoingAway(peer));
        }
        let (book, membership) = {
            let peers = inner.lock_peers();
            let entry = peers.get(&peer).ok_or(OpenLaneError::NotEnabled(peer))?;
            (inner.stream_book(peer, entry)?, entry.membership.clone())
        };
        let (lane, generation) = match inner.take_warm(peer, &membership, &book)? {
            Some(DialChoice { generation, lane }) => {
                let lane = match lane {
                    Ok(lane) => lane,
                    Err(plan) => inner.dial_now(peer, plan, &generation).await?,
                };
                (lane, Some(generation))
            }
            None => (holder::claim(inner, peer, &membership, &book).await?, None),
        };
        let (book, revoked) = inner.register_stream(lane.peer, &lane.membership, generation.as_ref())?;
        Ok(stream::initiate(lane, book, revoked))
    }

    /// 现在能不能在 lane 上到 `peer` 开流（不保证池里马上有）。不能的话调用方直接走共用的连接，不用试。
    #[must_use]
    pub fn can_open(&self, peer: NodeId) -> bool {
        let inner = &self.inner;
        if inner.is_going_away() {
            return false;
        }
        inner.lock_peers().get(&peer).is_some_and(|entry| match &entry.dial {
            Some(dial) => dial.control_up && !dial.peer_going_away,
            None => entry.holder.available(inner.config.ping_interval),
        })
    }

    /// 标记本节点进入排空状态：通知所有对端不再拨建新 lane；对端随之不再在现有 lane 上新建流。
    /// 存量流保持运行直至自然结束。
    pub fn go_away(&self) {
        let inner = &self.inner;
        inner.going_away.store(true, Ordering::Relaxed);
        let mut peers = inner.lock_peers();
        for entry in peers.values_mut() {
            entry.holder.go_away();
            if let Some(dial) = &mut entry.dial {
                dial.warm.clear();
                dial.wake.notify_one();
            }
        }
        drop(peers);
        tracing::info!("ice3proxy 进入排空状态：已通知对端，停止拨号新建 lane");
    }

    /// 排空撤销了（更新没有继续下去）：重新在 lane 上接新的流。
    ///
    /// "要走"已经说出去了，线上没有收回的帧：拨出去的 lane 换一个新的 epoch 重拨，对端拨来的控制 lane 断开让它重拨。
    /// 两边都按新的控制 lane 忘掉"要走"。没有在排空时什么都不做。
    pub fn come_back(&self) {
        let inner = &self.inner;
        if !inner.going_away.swap(false, Ordering::Relaxed) {
            return;
        }
        let mut peers = inner.lock_peers();
        for (id, entry) in peers.iter_mut() {
            entry.holder.close();
            if let Some(dial) = &mut entry.dial {
                dial.redial(inner, *id);
            }
        }
        drop(peers);
        tracing::info!("ice3proxy 已撤销排空：控制 lane 重建后恢复正常开流");
    }

    /// 本节点地址变更（如宽带重拨等）：已拨出的 lane 大多已失效且不会收到重置，全部切换新 epoch 重新拨号。
    pub fn address_changed(&self) {
        let inner = &self.inner;
        let mut peers = inner.lock_peers();
        for (id, entry) in peers.iter_mut() {
            if let Some(dial) = &mut entry.dial {
                dial.redial(inner, *id);
            }
        }
        drop(peers);
        tracing::info!("本节点地址发生变化，已切换新 epoch 重新拨号所有出站 lane");
    }

    #[must_use]
    pub fn status(&self) -> LaneStatus {
        let inner = &self.inner;
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let peers = inner.lock_peers();
        let mut list: Vec<PeerLaneStatus> = peers
            .iter()
            .map(|(id, entry)| {
                let mut status = PeerLaneStatus::new(*id, entry.tally.counts());
                status.idle = count(entry.holder.idle());
                match &entry.dial {
                    Some(dial) => {
                        status.dials = true;
                        status.control = dial.control_up;
                        status.ready = count(dial.warm.len());
                        status.parked_at_peer = count(dial.parked);
                    }
                    None => status.control = entry.holder.available(inner.config.ping_interval),
                }
                status
            })
            .collect();
        drop(peers);
        list.sort_by_key(|status| status.peer);
        LaneStatus { total: inner.counters.all.counts(), handshake_failures: inner.counters.handshake_failures(), peers: list }
    }

    /// 记下一条本来要走 lane、改走了共用连接的流。
    pub fn note_fallback(&self, peer: NodeId) {
        if let Some(entry) = self.inner.lock_peers().get(&peer) {
            self.inner.book(entry).bump(|tally| &tally.fallbacks);
        }
    }
}

impl Inner {
    pub(crate) fn lock_peers(&self) -> MutexGuard<'_, HashMap<NodeId, Peer>> {
        self.peers.lock().expect("lane peers mutex poisoned")
    }

    pub(crate) fn random_u64(&self) -> u64 {
        let mut bytes = [0; 8];
        self.random.fill(&mut bytes).expect("系统的随机数源不可用");
        u64::from_be_bytes(bytes)
    }

    pub(crate) fn is_going_away(&self) -> bool {
        self.going_away.load(Ordering::Relaxed)
    }

    /// 握手完成的一条 lane，按它的用途交出去。
    fn dispatch(self: &Arc<Self>, lane: Lane) {
        match lane.purpose {
            Purpose::Control => holder::control_arrived(self, lane),
            Purpose::Parked => holder::parked_arrived(self, lane),
            Purpose::Own => self.own_arrived(lane),
        }
    }

    /// 对端拨来一条给它自己开流用的 lane：守着它，等对端开流。
    fn own_arrived(self: &Arc<Self>, mut lane: Lane) {
        let peer = lane.peer;
        {
            let mut peers = self.lock_peers();
            let Some(entry) = peers.get_mut(&peer).filter(|entry| entry.matches(&lane.membership)) else {
                drop(peers);
                return self.refuse(peer, &lane.membership, "对端 lane 授权已失效");
            };
            if entry.own_waiting >= MAX_OWN_WAITING_PER_PEER {
                drop(peers);
                return self.refuse(peer, &lane.membership, "对端等待开流的 lane 数量已达上限");
            }
            entry.own_waiting += 1;
        }
        let inner = Arc::clone(self);
        tokio::spawn(async move {
            let mut shutdown = inner.shutdown.clone();
            let mut membership = lane.membership.clone();
            let opening = tokio::select! {
                _ = shutdown.changed() => Ok(None),
                _ = membership.changed() => return,
                opening = dialler::await_opening(&mut lane) => opening,
            };
            inner.finish_own_wait(peer, &membership);
            match opening {
                Ok(Some(opening)) => inner.deliver(lane, &opening, None),
                Ok(None) => {}
                Err(error) => tracing::debug!(%peer, %error, "对端 lane 未开启流即关闭"),
            }
        });
    }

    fn finish_own_wait(&self, peer: NodeId, membership: &watch::Receiver<()>) {
        if let Some(entry) = self.lock_peers().get_mut(&peer).filter(|entry| entry.matches(membership)) {
            entry.own_waiting -= 1;
        }
    }

    /// 对方在一条 lane 上开了流：交给接受队列。
    pub(crate) fn deliver(&self, lane: Lane, opening: &Opening, generation: Option<&Arc<Notify>>) {
        let peer = lane.peer;
        let (book, revoked) = match self.register_stream(peer, &lane.membership, generation) {
            Ok(registered) => registered,
            Err(error) => return self.refuse(peer, &lane.membership, &error.to_string()),
        };
        let (send, recv) = stream::respond(lane, opening.mode, &opening.header, book, revoked);
        let incoming = Incoming { peer, send, recv };
        // 接受队列没有人在收（本节点在关闭）：流被丢弃，对方看到重置。
        let _ = self.incoming.send(incoming);
    }

    /// 记当前对端的一份和全节点的一份。
    fn book(&self, entry: &Peer) -> Book {
        Book { node: Arc::clone(&self.counters), peer: Arc::clone(&entry.tally) }
    }

    /// 一条 lane 开始承载流时用的计数。和这个对端之间在用的到了上限时失败。
    fn stream_book(&self, peer: NodeId, entry: &Peer) -> Result<Book, OpenLaneError> {
        let book = self.book(entry);
        let in_use = usize::try_from(book.peer.in_use.get()).unwrap_or(usize::MAX);
        if in_use >= MAX_IN_USE_PER_PEER {
            return Err(OpenLaneError::TooMany(peer));
        }
        Ok(book)
    }

    /// 在对端表锁内核对授权和拨号代次，并订阅吊销信号。netmap 更新不会漏掉已经登记的流。
    fn register_stream(
        &self,
        peer: NodeId,
        membership: &watch::Receiver<()>,
        generation: Option<&Arc<Notify>>,
    ) -> Result<(Book, watch::Receiver<bool>), OpenLaneError> {
        let peers = self.lock_peers();
        let entry = peers.get(&peer).filter(|entry| entry.matches(membership)).ok_or(OpenLaneError::NotEnabled(peer))?;
        if let Some(generation) = generation
            && !entry.dial.as_ref().is_some_and(|dial| dial.matches(generation))
        {
            return Err(OpenLaneError::NoControl(peer));
        }
        let book = self.stream_book(peer, entry)?;
        let mut active = self.active.lock().expect("lane active mutex poisoned");
        let active = active.entry(peer).or_insert_with(|| ActivePeer { key: entry.key, revoked: watch::Sender::new(false) });
        Ok((book, active.revoked.subscribe()))
    }

    /// 握手完成之后因为用途或者数量不对关掉一条 lane。对方是认证过的节点，但它可以一直这样做，所以只记 debug。
    pub(crate) fn refuse(&self, peer: NodeId, membership: &watch::Receiver<()>, reason: &str) {
        self.counters.all.refused.bump();
        if let Some(entry) = self.lock_peers().get(&peer).filter(|entry| entry.matches(membership)) {
            entry.tally.refused.bump();
        }
        tracing::debug!(%peer, reason, "已关闭对端拨入的 lane");
    }

    fn handshake_failed(&self, from: SocketAddr, error: &LaneError) {
        let counter = match error {
            LaneError::Deadline(_) => &self.counters.handshake_deadline,
            LaneError::Tls(_) if error.is_unknown_key() => &self.counters.handshake_unknown_key,
            LaneError::Tls(_) => &self.counters.handshake_tls,
            // 没握手完连接就断了（对方关掉、重置，socket 出错）也记在这里：上报给 controller 的原因只有这几种
            // （`LaneHandshakeFailures`），不为它另加一种。
            LaneError::Frame(_) | LaneError::Protocol(_) | LaneError::Io(_) | LaneError::Closed => &self.counters.handshake_protocol,
        };
        counter.bump();
        // 外人能造成的失败，每次都记 info 就能刷屏。
        tracing::debug!(%from, %error, "拨入 lane 握手失败");
    }

    fn log_refusal(&self, message: std::fmt::Arguments<'_>) {
        let mut log = self.refusal_log.lock().expect("refusal log mutex poisoned");
        if let Some(skipped) = log.due(Instant::now()) {
            tracing::warn!(skipped, "{message}");
        }
    }

    pub(crate) fn log_dry_pool(&self, peer: NodeId, waited: Duration) {
        let mut log = self.refusal_log.lock().expect("refusal log mutex poisoned");
        if let Some(skipped) = log.due(Instant::now()) {
            tracing::info!(%peer, ?waited, skipped, "对端驻留 lane 已耗尽且等待补充超时，新流回退至共用连接");
        }
    }

    /// 先取热 lane。热的用完就当场拨，本节点不拨时则从对方停过来的 lane 里取。
    fn take_warm(&self, peer: NodeId, membership: &watch::Receiver<()>, book: &Book) -> Result<Option<DialChoice>, OpenLaneError> {
        let mut peers = self.lock_peers();
        let entry = peers.get_mut(&peer).filter(|entry| entry.matches(membership)).ok_or(OpenLaneError::NotEnabled(peer))?;
        let Some(dial) = &mut entry.dial else { return Ok(None) };
        if dial.peer_going_away {
            return Err(OpenLaneError::GoingAway(peer));
        }
        // 对端尚未信任（或已撤销信任）本节点：现拨的 lane 会在开流帧发出后才被拒绝，届时已无法安全回退到共用连接。
        if !dial.control_up {
            return Err(OpenLaneError::NoControl(peer));
        }
        dial.own.get_or_insert_with(|| Demand::new(std::time::Instant::now())).record();
        dial.wake.notify_one();
        while let Some(lane) = dial.warm.pop_back() {
            if lane.is_usable() {
                return Ok(Some(DialChoice { generation: Arc::clone(&dial.wake), lane: Ok(lane) }));
            }
        }
        Ok(Some(DialChoice { generation: Arc::clone(&dial.wake), lane: Err(DialPlan::new(dial, membership, book.clone())) }))
    }

    /// 当场拨一条 lane 给自己开流。HELLO 留在待发的密文里，和开流的帧一起走。
    async fn dial_now(&self, peer: NodeId, plan: DialPlan, generation: &Arc<Notify>) -> Result<Lane, OpenLaneError> {
        let dial = Dial {
            addrs: &plan.addrs,
            config: plan.config,
            peer,
            purpose: Purpose::Own,
            membership: plan.membership.clone(),
            epoch: 0,
            deadline: Instant::now() + OWN_DIAL_DEADLINE,
        };
        let started = Instant::now();
        let dialled = {
            let _dialling = plan.book.enter(|tally| &tally.dialling);
            let mut removed = plan.membership;
            tokio::select! {
                biased;
                _ = removed.changed() => return Err(OpenLaneError::NotEnabled(peer)),
                result = lane::dial(dial) => result,
            }
        };
        match dialled {
            Ok((lane, addr)) => {
                self.remember_good(peer, generation, addr);
                self.note_dial_time(peer, generation, started.elapsed());
                Ok(lane)
            }
            Err(source) => {
                plan.book.bump(|tally| &tally.dial_failures);
                plan.book.bump(|tally| &tally.claims_failed);
                Err(OpenLaneError::Dial { peer, source })
            }
        }
    }

    pub(crate) fn dial_plan(&self, peer: NodeId, generation: &Arc<Notify>) -> Option<DialPlan> {
        let peers = self.lock_peers();
        let entry = peers.get(&peer)?;
        let dial = entry.dial.as_ref().filter(|dial| dial.matches(generation))?;
        Some(DialPlan::new(dial, &entry.membership, self.book(entry)))
    }

    pub(crate) fn remember_good(&self, peer: NodeId, generation: &Arc<Notify>, addr: SocketAddr) {
        if let Some(dial) = Self::dial_mut(&mut self.lock_peers(), peer, generation) {
            dial.last_good = Some(addr);
        }
    }

    /// 热 lane 的条数，和对方是不是说了要走。本节点不拨它时返回 `None`。
    pub(crate) fn warm_state(&self, peer: NodeId, generation: &Arc<Notify>) -> Option<(usize, bool)> {
        let peers = self.lock_peers();
        let dial = peers.get(&peer)?.dial.as_ref().filter(|dial| dial.matches(generation))?;
        Some((dial.warm.len(), dial.peer_going_away))
    }

    pub(crate) fn add_warm(&self, lane: Lane, generation: &Arc<Notify>) {
        if let Some(dial) = Self::dial_mut(&mut self.lock_peers(), lane.peer, generation) {
            dial.warm.push_back(lane);
        }
    }

    fn dial_mut<'a>(peers: &'a mut HashMap<NodeId, Peer>, peer: NodeId, generation: &Arc<Notify>) -> Option<&'a mut DialSide> {
        peers.get_mut(&peer)?.dial.as_mut().filter(|dial| dial.matches(generation))
    }

    /// 一次拨号（连上加握手）用了多久：拨号方据此估计补一条热 lane 要多久。
    pub(crate) fn note_dial_time(&self, peer: NodeId, generation: &Arc<Notify>, took: Duration) {
        if let Some(dial) = Self::dial_mut(&mut self.lock_peers(), peer, generation) {
            dial.dial_time = Some(dial.dial_time.map_or(took, |average| (average * 7 + took) / 8));
        }
    }

    /// 拨号方留给自己开流的热 lane 该有几条：和接受方的池同一个估计（见 `demand`），补一条的时间是测到的拨号时间。
    /// 多出来的（速率落下来之后）从最老的关起，每次最多关十分之一。
    ///
    /// 本节点还没有往这个对端开过流时是 0：网关里出口拨入口，只为入口停 lane，自己从不往入口开流，备着的热 lane 白占连接。
    /// 第一条流当场拨，之后才按速率备。
    pub(crate) fn size_ready(&self, peer: NodeId, generation: &Arc<Notify>) -> Option<usize> {
        let mut peers = self.lock_peers();
        let dial = Self::dial_mut(&mut peers, peer, generation)?;
        let now = std::time::Instant::now();
        let Some(demand) = dial.own.as_mut() else { return Some(0) };
        demand.update(now);
        let refill = dial.dial_time.unwrap_or(Duration::from_millis(200)) + Duration::from_millis(5);
        let target = demand.target(refill, self.config.min_idle);
        let excess = dial.warm.len().saturating_sub(target);
        if excess > 0 && dial.trimmed.is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(1)) {
            dial.warm.drain(..(excess / 10).max(1));
            dial.trimmed = Some(now);
        }
        Some(target)
    }

    pub(crate) fn set_parked(&self, peer: NodeId, generation: &Arc<Notify>, parked: usize) {
        if let Some(dial) = Self::dial_mut(&mut self.lock_peers(), peer, generation) {
            dial.parked = parked;
        }
    }

    pub(crate) fn set_control_up(&self, peer: NodeId, generation: &Arc<Notify>, up: bool) {
        if let Some(dial) = Self::dial_mut(&mut self.lock_peers(), peer, generation) {
            dial.control_up = up;
            if up {
                // 排空状态仅对发送它的那条控制 lane 有效：新控制 lane 被接受，说明对端（重启或撤销排空后）已重新接受新流。
                // 它还在排空的话会在新的控制 lane 上再说一次。
                dial.peer_going_away = false;
            } else {
                dial.warm.clear();
            }
        }
    }

    pub(crate) fn peer_going_away(&self, peer: NodeId, generation: &Arc<Notify>) {
        let mut peers = self.lock_peers();
        let Some(dial) = Self::dial_mut(&mut peers, peer, generation) else { return };
        dial.peer_going_away = true;
        dial.warm.clear();
        drop(peers);
        tracing::info!(%peer, "对端已通知进入排空状态，停止向其拨号新建 lane 且不再在其 lane 上开流");
    }
}

/// 一条 TCP 连接开头的字节像不像 lane：lane 以 TLS 的握手记录开头（`0x16 0x03`）。
///
/// relay 的 TCP 中转以 2 字节的帧长度开头，第一个帧是很短的会话握手，长度的高字节远小于 `0x16`，两者不会混淆。
/// 只有第一个字节时按第一个字节判断。
#[must_use]
pub fn is_lane(prefix: &[u8]) -> bool {
    matches!(prefix, [0x16] | [0x16, 0x03, ..])
}

/// 拒绝和挤掉连接的日志的限速：有人一直往上连的时候不刷屏。
#[derive(Debug, Default)]
struct RefusalLog {
    logged: Option<Instant>,
    skipped: u64,
}

impl RefusalLog {
    fn due(&mut self, now: Instant) -> Option<u64> {
        if self.logged.is_some_and(|at| now.saturating_duration_since(at) < REFUSAL_LOG_INTERVAL) {
            self.skipped += 1;
            return None;
        }
        self.logged = Some(now);
        Some(std::mem::take(&mut self.skipped))
    }
}

impl Connector for Lanes {
    type Send = LaneSend;
    type Recv = LaneRecv;

    async fn open(&self, peer: NodeId) -> Result<(LaneSend, LaneRecv), OpenError> {
        self.open_stream(peer).await.map_err(|error| error.to_open_error())
    }
}

impl Acceptor for Lanes {
    type Send = LaneSend;
    type Recv = LaneRecv;

    async fn accept(&self) -> Option<Incoming<LaneSend, LaneRecv>> {
        let mut accepted = self.inner.accepted.lock().await;
        loop {
            let incoming = accepted.recv().await?;
            if !incoming.recv.is_revoked() {
                return Some(incoming);
            }
        }
    }
}

/// lane 不传数据报：UDP 应用的数据始终走共用的连接。实现它只是为了让 `i3t_flow::serve` 能直接跑在 lane 上；
/// 数据报接收端立即结束，`serve` 仅正常接受流。
impl Datagrams for Lanes {
    type Sender = NoDatagrams;

    fn datagram_sender(&self) -> NoDatagrams {
        NoDatagrams
    }

    async fn recv_datagram(&self, _recipient: Recipient) -> Option<Datagram> {
        None
    }
}

/// lane 不支持发送数据报。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDatagrams;

impl DatagramSender for NoDatagrams {
    fn max_datagram_len(&self, _peer: NodeId) -> Option<usize> {
        None
    }

    fn send_datagram(&self, peer: NodeId, _datagram: Bytes) -> Result<(), DatagramSendError> {
        Err(DatagramSendError::Unsupported(peer))
    }

    async fn send_reliable(&self, peer: NodeId, _datagram: Bytes) -> Result<(), DatagramSendError> {
        Err(DatagramSendError::Unsupported(peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacing_a_peer_rejects_old_lane_memberships() {
        for rotate_key in [false, true] {
            let local = NodeKey::generate().unwrap();
            let key = NodeKey::generate().unwrap().public();
            let id = NodeId::new(1).unwrap();
            let endpoint = Lanes::new(&local, LaneConfig::default()).unwrap();
            let peer = LanePeer { id, key, dial: Vec::new() };

            endpoint.set_peers([peer.clone()]).unwrap();
            let before = endpoint.inner.lock_peers().get(&id).unwrap().membership.clone();
            if rotate_key {
                let key = NodeKey::generate().unwrap().public();
                endpoint.set_peers([LanePeer { key, ..peer }]).unwrap();
            } else {
                endpoint.set_peers([]).unwrap();
                endpoint.set_peers([peer]).unwrap();
            }
            assert!(before.has_changed().is_err());

            let after = {
                let mut peers = endpoint.inner.lock_peers();
                let current = peers.get_mut(&id).unwrap();
                assert!(!current.matches(&before));
                assert_eq!(current.own_waiting, 0);
                current.own_waiting = 1;
                current.membership.clone()
            };

            // 自己的 lane 和拨出去的停车 lane 共用这道检查。
            let old_dialler = Arc::new(Notify::new());
            for generation in [None, Some(&old_dialler)] {
                assert!(
                    matches!(endpoint.inner.register_stream(id, &before, generation), Err(OpenLaneError::NotEnabled(peer)) if peer == id)
                );
                endpoint.inner.refuse(id, &before, "旧的 lane 授权");
            }
            let status = endpoint.status();
            assert_eq!(status.total.refused, 2);
            assert_eq!(status.peer(id).unwrap().counts.refused, 0);

            endpoint.inner.finish_own_wait(id, &before);
            assert_eq!(endpoint.inner.lock_peers().get(&id).unwrap().own_waiting, 1);
            endpoint.inner.finish_own_wait(id, &after);
            assert_eq!(endpoint.inner.lock_peers().get(&id).unwrap().own_waiting, 0);
            assert!(endpoint.inner.register_stream(id, &after, None).is_ok());
        }
    }

    #[tokio::test]
    async fn replacing_the_dialler_does_not_replace_the_membership() {
        let local = NodeKey::generate().unwrap();
        let key = NodeKey::generate().unwrap().public();
        let id = NodeId::new(1).unwrap();
        let endpoint = Lanes::new(&local, LaneConfig::default()).unwrap();
        let peer = LanePeer { id, key, dial: vec![([127, 0, 0, 1], 1).into()] };
        endpoint.set_peers([peer.clone()]).unwrap();
        let (membership, first) = {
            let peers = endpoint.inner.lock_peers();
            let entry = peers.get(&id).unwrap();
            (entry.membership.clone(), Arc::clone(&entry.dial.as_ref().unwrap().wake))
        };

        endpoint.address_changed();
        let second = {
            let peers = endpoint.inner.lock_peers();
            let entry = peers.get(&id).unwrap();
            assert!(entry.matches(&membership));
            Arc::clone(&entry.dial.as_ref().unwrap().wake)
        };
        assert!(endpoint.inner.dial_plan(id, &first).is_none());
        assert!(endpoint.inner.dial_plan(id, &second).is_some());
        assert!(matches!(endpoint.inner.register_stream(id, &membership, Some(&first)), Err(OpenLaneError::NoControl(peer)) if peer == id));
        assert!(endpoint.inner.register_stream(id, &membership, Some(&second)).is_ok());

        endpoint.set_peers([LanePeer { dial: vec![([127, 0, 0, 1], 2).into()], ..peer }]).unwrap();
        endpoint.inner.set_control_up(id, &second, true);
        endpoint.inner.set_parked(id, &second, 1);
        let status = endpoint.status();
        let current = status.peer(id).unwrap();
        assert!(current.dials);
        assert!(!current.control);
        assert_eq!(current.parked_at_peer, 0);
        assert!(endpoint.inner.lock_peers().get(&id).unwrap().matches(&membership));
    }
}
