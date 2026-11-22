//! 封好的网络包：虚拟网卡的 IP 包不进 QUIC，单独加密之后直接交给路径层。
//!
//! # 为什么不走连接的数据报
//!
//! QUIC 的数据报不重传，但是照样要对端确认，也照样受连接的拥塞控制管：发出去、还没有被确认的量到了窗口就停，
//! 等确认回来。虚拟网卡的包里面是两端内核自己的 TCP（或者别的协议），它本来就有自己的确认和拥塞控制，外面再套一层，
//! 确认的包多出一倍，回程窄的路上数据只能送一半；外面这层的确认一晚到，里面所有的流一起停。
//!
//! 所以这些包只做 WireGuard 那样的事：一个包进来，加密，发出去。没有确认，没有重传，没有窗口，也不排队；
//! 发不出去就丢，由包里面的协议自己处理。连接还是那一条，流（代理、端口转发）照旧走它，包只借用它握手的结果。
//!
//! # 密钥
//!
//! 握手时两端都声明了 [`ALPN_SEALED`](crate::quic::ALPN_SEALED) 的连接才这样走。握手完成之后两端各自用 TLS 的密钥导出
//! （RFC 8446 §7.5）取同样的一段：连接标识，和两把 ChaCha20-Poly1305 的密钥，一个方向一把。不多握一次手；
//! 连接没了，密钥跟着作废，新的连接是新的密钥。格式见 [`i3t_proto::sealed`]。
//!
//! 只用 ChaCha20-Poly1305：它一把密钥能加密的包数没有实际的上限（RFC 9001 §6.6），不用在连接中途换密钥。
//! 认证失败的包数有上限（2^36），到了就把连接关掉重建。
//!
//! # 序号和重放
//!
//! 每个方向的序号从 0 起，每发一个加 1，也是加密的随机数。收的一方用一个滑动窗口记住见过哪些：
//! 见过的、比窗口还旧的都丢掉。窗口只在认证通过之后才动，伪造的包推不动它。
//!
//! # 对端重启
//!
//! 对端的进程换了，密钥就没了，本端发的包在它那里解不开，也没有任何回音。走 QUIC 时对端会回一个无状态重置，
//! 一个往返就知道；这里靠同样的机制：在发、却有一阵没有收到对端任何封好的包时，隔一会儿在连接上发一个空的数据报
//! （[`Session::probe_due`]）。对端还在就只是确认它；换了进程就回重置，连接关闭，上层重建。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use i3t_path::{Packets, Paths};
use i3t_proto::NodeId;
use i3t_proto::flow::Channel;
use i3t_proto::sealed::{KIND_SEALED, SealedHeader};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use tokio::sync::mpsc;

use crate::contract::Datagram;
use crate::quic::{ALPN_BUNDLES, ALPN_SEALED};

/// 从握手里导出密钥时的标签。换格式或者换算法时要换一个，新旧两种包就互相解不开。
const EXPORT_LABEL: &[u8] = b"EXPORTER-i3t-sealed-packets-1";
const KEY_LEN: usize = 32;
/// 导出的那一段：连接标识，拨号一方发的那个方向的密钥，接受一方发的那个方向的密钥。
const MATERIAL_LEN: usize = 4 + 2 * KEY_LEN;

/// 一个方向上最多发这么多个包。到不了：每秒一百万个也要十四万年；留着是为了序号绝不绕回去重复。
const COUNTER_LIMIT: u64 = 1 << 62;
/// 认证失败的包到了这么多个，这把密钥就不再用（RFC 9001 §6.6 给 ChaCha20-Poly1305 的上限）。
const FORGERY_LIMIT: u64 = 1 << 36;

/// 在发、却这么久没有收到对端任何封好的包，就让连接去问一下对端还在不在；每次问也隔这么久。
/// 只朝一个方向走的流量（没有回程的包）因此每秒多一个小包，换来对端重启之后一两秒之内发现。
const PROBE_EVERY: Duration = Duration::from_secs(1);

/// 重放窗口记多少个序号。和 WireGuard 的取值在一个量级：路上乱序超过这么多个包的，当作丢了。
const REPLAY_WORDS: usize = 32;
const REPLAY_WORD_BITS: u64 = 64;

/// 攒成一批一起交给内核的封好的包最多几个。一批最大的也就两万多字节，远在一次发送的上限（64 KB）之内。
pub(crate) const BATCH_PACKETS: usize = 16;

/// 认不出是哪条连接的包（连接标识还没有登记）先留这么多个、这么久。
///
/// 握手完成的一方马上就能发，另一方登记密钥要晚几毫秒：这中间到的包不留的话，一条新连接上的头几个包
/// （TCP 的 SYN、第一个 ping）必丢，上层要等一秒的重传。
const EARLY_PACKETS: usize = 64;
const EARLY_MAX_AGE: Duration = Duration::from_secs(2);

/// 虚拟网卡的包在连接上怎么走。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacketTransport {
    /// 对端也这样声明的连接上，单独加密、直接走路径层；别的连接走数据报。还认识一帧里合着好几个小包的。
    #[default]
    Sealed,
    /// 和 [`Sealed`](Self::Sealed) 一样，只是不认识一帧里合着好几个包的：有合并小包之前的程序是这样的。
    /// 测试新旧程序之间怎么来往时用。
    SealedOneByOne,
    /// 一律走连接的数据报，和不认识封好的包的旧程序一样。做对比测试时用。
    Datagram,
}

impl PacketTransport {
    /// 指定走哪一种的环境变量，取值 `on`（默认）或 `off`。做对比测试时用。
    pub const ENV: &str = "I3T_SEALED_PACKETS";

    /// 环境变量 [`Self::ENV`] 指定的那一种；没有设置或者值看不懂时用默认的。
    #[must_use]
    pub fn from_env() -> Self {
        std::env::var(Self::ENV).map_or_else(|_| Self::default(), |value| Self::from_env_value(&value))
    }

    fn from_env_value(value: &str) -> Self {
        match value {
            "on" => Self::Sealed,
            "off" => Self::Datagram,
            _ => {
                tracing::warn!(%value, "环境变量 {} 的值不是 on 或 off，照默认的来（on）", Self::ENV);
                Self::default()
            }
        }
    }
}

/// 握手时两端说定的、这条连接上网络包能怎么走。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Agreed {
    /// 两端都收得了封好的包。
    pub(crate) sealed: bool,
    /// 两端都认识一帧里合着好几个小包的。
    pub(crate) bundles: bool,
}

impl Agreed {
    /// 握手协商出来的协议名说明了什么。
    fn from_protocol(protocol: Option<&[u8]>) -> Self {
        let bundles = protocol == Some(ALPN_BUNDLES);
        Self { sealed: bundles || protocol == Some(ALPN_SEALED), bundles }
    }
}

/// 握手时两端说定了什么。
pub(crate) fn agreed(connection: &quinn::Connection) -> Agreed {
    let data = connection.handshake_data().and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok());
    Agreed::from_protocol(data.as_ref().and_then(|data| data.protocol.as_deref()))
}

/// 这条连接上本端是哪一方。两把密钥按它分：一方发的那个方向，就是另一方收的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Dialer,
    Acceptor,
}

/// 密钥用到头了：序号发完了，或者认证失败的包到了上限。这条连接该关掉重建。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("这条连接上封包的密钥用到头了")]
pub(crate) struct Spent;

/// 一个封好的包为什么没有收下。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Rejected {
    #[error("序号见过了，或者比重放窗口还旧")]
    Replayed,
    #[error("校验对不上")]
    Forged,
    #[error("序号超出了发的一方会用的范围")]
    OutOfRange,
}

/// 一条连接上封包用的东西：两个方向的密钥、发的序号、收的重放窗口，和几个计数。
pub(crate) struct Session {
    id: u32,
    sealing: LessSafeKey,
    /// 下一个要发的序号。
    next: AtomicU64,
    opening: LessSafeKey,
    replay: Mutex<Replay>,
    created: Instant,
    /// 最近一次收下对端的包，和最近一次让连接去问对端在不在：都是 [`Self::millis`] 的值，0 是还没有过。
    heard: AtomicU64,
    probed: AtomicU64,
    /// 认证失败的包数。
    forged: AtomicU64,
    /// 线上的字节数（整个封好的包）。
    sent_bytes: AtomicU64,
    received_bytes: AtomicU64,
    /// 没有发出去就丢掉的包数：端口忙着，或者封好之后到对端刚好不再是直连。
    unsent: AtomicU64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("id", &self.id).finish_non_exhaustive()
    }
}

impl Session {
    /// 从一条握手完成的连接里导出。
    ///
    /// # Errors
    ///
    /// TLS 库不给导出。握手完成的连接上不会发生。
    pub(crate) fn derive(connection: &quinn::Connection, role: Role) -> Result<Self, quinn_proto::crypto::ExportKeyingMaterialError> {
        let mut material = [0; MATERIAL_LEN];
        connection.export_keying_material(&mut material, EXPORT_LABEL, &[])?;
        Ok(Self::from_material(&material, role))
    }

    fn from_material(material: &[u8; MATERIAL_LEN], role: Role) -> Self {
        let (id, keys) = material.split_first_chunk::<4>().expect("导出的那一段比连接标识长");
        let (from_dialer, from_acceptor) = keys.split_at(KEY_LEN);
        let key = |bytes: &[u8]| LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, bytes).expect("ChaCha20-Poly1305 的密钥是 32 字节"));
        let (sealing, opening) = match role {
            Role::Dialer => (key(from_dialer), key(from_acceptor)),
            Role::Acceptor => (key(from_acceptor), key(from_dialer)),
        };
        Self {
            id: u32::from_be_bytes(*id),
            sealing,
            next: AtomicU64::new(0),
            opening,
            replay: Mutex::new(Replay::default()),
            created: Instant::now(),
            heard: AtomicU64::new(0),
            probed: AtomicU64::new(0),
            forged: AtomicU64::new(0),
            sent_bytes: AtomicU64::new(0),
            received_bytes: AtomicU64::new(0),
            unsent: AtomicU64::new(0),
        }
    }

    /// 把一个网络包帧封好，接在 `out` 后面：头、密文、校验，就是线上的那个包。失败时 `out` 不变。
    ///
    /// # Errors
    ///
    /// 序号发完了。
    pub(crate) fn seal(&self, frame: &[u8], out: &mut Vec<u8>) -> Result<(), Spent> {
        let counter = self.next.fetch_add(1, Ordering::Relaxed);
        if counter >= COUNTER_LIMIT {
            return Err(Spent);
        }
        let header = SealedHeader { session: self.id, counter }.to_bytes();
        let start = out.len();
        out.reserve(SealedHeader::OVERHEAD + frame.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(frame);
        // 只有内容长到算法处理不了（几百 GB）才会失败。
        let Ok(tag) = self.sealing.seal_in_place_separate_tag(nonce(counter), Aad::from(header), &mut out[start + SealedHeader::LEN..])
        else {
            out.truncate(start);
            return Err(Spent);
        };
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// 认证并解开一个封好的包，返回里面的网络包帧。`packet` 是整个包，就地解开；`header` 是从它开头取出来的。
    ///
    /// # Errors
    ///
    /// 序号是发的一方不会用的，重放的，或者校验对不上的。
    pub(crate) fn open<'a>(&self, header: SealedHeader, packet: &'a mut [u8]) -> Result<&'a [u8], Rejected> {
        // 守规矩的对端发不出这么大的序号（[`seal`](Self::seal) 到这里就停了）。校验对得上也不收：拿着密钥的对端要是故意发一个
        // 最大的序号，重放窗口记"下一个"时就没有数可记了。
        if header.counter >= COUNTER_LIMIT {
            return Err(Rejected::OutOfRange);
        }
        // 先看一眼窗口，重放的包不值得解；认证通过之后才记进去。
        if !self.replay().admits(header.counter) {
            return Err(Rejected::Replayed);
        }
        let len = packet.len();
        let (head, body) = packet.split_at_mut(SealedHeader::LEN);
        let Ok(frame) = self.opening.open_in_place(nonce(header.counter), Aad::from(&*head), body) else {
            self.forged.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected::Forged);
        };
        if !self.replay().accept(header.counter) {
            return Err(Rejected::Replayed);
        }
        self.heard.store(self.millis(), Ordering::Relaxed);
        self.received_bytes.fetch_add(u64::try_from(len).unwrap_or(u64::MAX), Ordering::Relaxed);
        Ok(frame)
    }

    fn replay(&self) -> std::sync::MutexGuard<'_, Replay> {
        self.replay.lock().expect("sealed packet replay window mutex poisoned")
    }

    /// 从这个会话建立算起的毫秒数加一：0 留给"还没有过"。
    fn millis(&self) -> u64 {
        u64::try_from(self.created.elapsed().as_millis()).unwrap_or(u64::MAX - 1) + 1
    }

    /// 几个封好的包发出去了，`len` 是它们在线上一共的字节数。
    pub(crate) fn sent(&self, len: usize) {
        self.sent_bytes.fetch_add(u64::try_from(len).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// `packets` 个封好的包没有发出去，丢掉了。
    pub(crate) fn not_sent(&self, packets: usize) {
        self.unsent.fetch_add(u64::try_from(packets).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// 没有发出去就丢掉的封好的包一共多少个。
    pub(crate) fn unsent(&self) -> u64 {
        self.unsent.load(Ordering::Relaxed)
    }

    /// 发出、收下的封好的包在线上一共多少字节。
    pub(crate) fn traffic(&self) -> (u64, u64) {
        (self.sent_bytes.load(Ordering::Relaxed), self.received_bytes.load(Ordering::Relaxed))
    }

    /// 最近一次收下对端的包是什么时候。
    pub(crate) fn heard(&self) -> Option<Instant> {
        let heard = self.heard.load(Ordering::Relaxed);
        (heard != 0).then(|| self.created + Duration::from_millis(heard - 1))
    }

    /// 刚发了一个包：现在该不该让连接去问一下对端还在不在。返回真的那一次由调用方去问，之后一阵子都返回假。
    pub(crate) fn probe_due(&self) -> bool {
        let every = u64::try_from(PROBE_EVERY.as_millis()).unwrap_or(u64::MAX);
        let now = self.millis();
        let heard = self.heard.load(Ordering::Relaxed);
        if heard != 0 && now.saturating_sub(heard) < every {
            return false;
        }
        let probed = self.probed.load(Ordering::Relaxed);
        // 会话刚建立时握手本身就是回音，头一段时间不用问。
        now.saturating_sub(probed) >= every && self.probed.compare_exchange(probed, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    }

    /// 密钥是不是用到头了。到头了的连接该关掉，重建之后是新的密钥。
    pub(crate) fn is_spent(&self) -> bool {
        self.next.load(Ordering::Relaxed) >= COUNTER_LIMIT || self.forged.load(Ordering::Relaxed) >= FORGERY_LIMIT
    }
}

/// 攒着等一起交给路径层的封好的包：发给同一个对端，首尾相接，等长，只有最后一个可以短。
/// 这正是一次系统调用发得出去的样子（内核按固定的长度切开）。
///
/// 虚拟网卡一口气读出来的几个包多半是同一条流的，一样长；一个一个地发，每个包一次系统调用，大流量时一半的 CPU 花在这上面。
#[derive(Debug, Default)]
pub(crate) struct Batch {
    /// 发给谁、用的哪个会话。空着的时候是 `None`。
    to: Option<(NodeId, Arc<Session>)>,
    contents: Vec<u8>,
    /// 第一个包的长度，后面的不能比它长。
    stride: usize,
    packets: usize,
    /// 最后一个比前面的短：这一批到此为止。
    ended: bool,
}

impl Batch {
    /// 再放一个封好之后 `len` 字节、发给 `peer` 的包之前，要不要先把攒着的发掉：换了对端或者会话，
    /// 攒够了 `limit` 个，上一个是短的，或者这一个比前面的长。
    pub(crate) fn must_send_before(&self, peer: NodeId, session: &Arc<Session>, len: usize, limit: usize) -> bool {
        self.to.as_ref().is_some_and(|(to, with)| {
            *to != peer || !Arc::ptr_eq(with, session) || self.ended || self.packets >= limit || len > self.stride
        })
    }

    /// 把一个网络包帧封好接在后面。调用之前要先问过 [`must_send_before`](Self::must_send_before)。
    ///
    /// # Errors
    ///
    /// 这个会话的序号发完了。这一批不变。
    pub(crate) fn push(&mut self, peer: NodeId, session: &Arc<Session>, frame: &[u8]) -> Result<(), Spent> {
        let before = self.contents.len();
        session.seal(frame, &mut self.contents)?;
        let len = self.contents.len() - before;
        if self.to.is_none() {
            self.to = Some((peer, Arc::clone(session)));
            self.stride = len;
        }
        self.ended = len < self.stride;
        self.packets += 1;
        Ok(())
    }

    /// 攒着的不能再加了：到了 `limit` 个，或者最后一个是短的。
    pub(crate) fn is_full(&self, limit: usize) -> bool {
        self.ended || self.packets >= limit
    }

    /// 把攒着的交给路径层，然后清空。发不出去的（端口忙着，或者到对端刚好不再是直连）就丢了：
    /// 这里没有队列可排，包里面的协议自己会重传、会降速。
    pub(crate) fn send(&mut self, paths: &Paths) {
        let Some((peer, session)) = self.to.take() else { return };
        let segment_size = (self.packets > 1).then_some(self.stride);
        if paths.send_direct(peer, &Packets { contents: &self.contents, segment_size, ecn: None }) {
            session.sent(self.contents.len());
        } else {
            session.not_sent(self.packets);
        }
        self.contents.clear();
        self.packets = 0;
        self.ended = false;
    }
}

/// 序号就是随机数：前 4 个字节是 0，后 8 个字节是序号。两个方向的密钥不同，所以不会撞。
fn nonce(counter: u64) -> Nonce {
    let mut bytes = [0; NONCE_LEN];
    bytes[NONCE_LEN - 8..].copy_from_slice(&counter.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

/// 重放窗口：一圈位图，每个序号一位，记着最近 [`REPLAY_WORDS`] 个字（每个字 64 个序号）里见过哪些。
///
/// 序号按 64 个一组分成块，块号对圈长取余就是它在圈里的位置。见到更新的块时，把中间跨过去的位置清零。
#[derive(Debug, Default)]
struct Replay {
    seen: [u64; REPLAY_WORDS],
    /// 见过的最大的序号加一；0 是还一个都没见过。
    next: u64,
}

impl Replay {
    const fn block(counter: u64) -> u64 {
        counter / REPLAY_WORD_BITS
    }

    /// 序号所在的那个字在圈里的位置，和它在字里的那一位。
    fn place(counter: u64) -> (usize, u64) {
        let word = usize::try_from(Self::block(counter) % REPLAY_WORDS as u64).expect("对圈长取余之后放得进 usize");
        (word, 1 << (counter % REPLAY_WORD_BITS))
    }

    /// 这个序号还收不收：没见过，而且没有旧到出了窗口。
    fn admits(&self, counter: u64) -> bool {
        if counter >= self.next {
            return true;
        }
        // 走到这里 `next` 不是 0。最新的块往前数一圈之外的，位置已经被别的块用了。
        let newest = Self::block(self.next - 1);
        if Self::block(counter) + REPLAY_WORDS as u64 <= newest {
            return false;
        }
        let (word, bit) = Self::place(counter);
        self.seen[word] & bit == 0
    }

    /// 记下这个序号。它已经见过、或者出了窗口时返回假，什么都不改。
    fn accept(&mut self, counter: u64) -> bool {
        if !self.admits(counter) {
            return false;
        }
        if counter >= self.next {
            // 最大的那个数后面没有"下一个"可记，不收。用这个窗口的一方本来就不该把它交进来（见 [`Session::open`]），
            // 这里再挡一次，窗口自己就不会算溢出。
            let Some(next) = counter.checked_add(1) else { return false };
            // 一个都没见过时整圈本来就是空的，从块 0 算起也只是把空的再清一遍。
            let newest = Self::block(self.next.saturating_sub(1));
            let skipped = (Self::block(counter) - newest).min(REPLAY_WORDS as u64);
            for step in 1..=skipped {
                let (word, _) = Self::place((newest + step) * REPLAY_WORD_BITS);
                self.seen[word] = 0;
            }
            self.next = next;
        }
        let (word, bit) = Self::place(counter);
        self.seen[word] |= bit;
        true
    }
}

/// 收到的封好的包在这里解开，排进虚拟网卡的队列。
///
/// 路径层只认得出"这是哪个对端发来的"（直连时凭验证过的地址，经 relay 时凭 relay 的担保）；是不是真的出自那个对端，
/// 由这里用那条连接的密钥认证。
pub(crate) struct Inbox {
    sessions: RwLock<HashMap<(NodeId, u32), Arc<Session>>>,
    early: Mutex<EarlyPackets>,
    packets: mpsc::Sender<Datagram>,
}

/// 一个到得比密钥登记还早的包。
struct Early {
    at: Instant,
    session: u32,
    packet: Vec<u8>,
}

/// 到得比密钥登记还早的包，每个对端名下留一小队。
#[derive(Default)]
struct EarlyPackets {
    waiting: HashMap<NodeId, VecDeque<Early>>,
    /// 上一次把过期的清掉是什么时候。
    swept: Option<Instant>,
}

impl EarlyPackets {
    fn hold(&mut self, peer: NodeId, session: u32, packet: &[u8]) {
        self.sweep();
        let waiting = self.waiting.entry(peer).or_default();
        if waiting.len() >= EARLY_PACKETS {
            waiting.pop_front();
        }
        waiting.push_back(Early { at: Instant::now(), session, packet: packet.to_vec() });
    }

    /// 取走 `peer` 名下连接标识是 `session` 的那些，按到的先后。别的会话的留着，等它们自己的密钥。
    fn take(&mut self, peer: NodeId, session: u32) -> Vec<Vec<u8>> {
        self.sweep();
        let Some(waiting) = self.waiting.remove(&peer) else { return Vec::new() };
        let (wanted, others): (VecDeque<Early>, VecDeque<Early>) = waiting.into_iter().partition(|early| early.session == session);
        if !others.is_empty() {
            self.waiting.insert(peer, others);
        }
        wanted.into_iter().filter(|early| early.at.elapsed() <= EARLY_MAX_AGE).map(|early| early.packet).collect()
    }

    /// 隔一阵把所有对端名下过期的清掉：没等到密钥的包（对端手上的密钥已经作废了）不能一直占着内存。
    /// 每次留包、取包、连接结束时都会走到这里，真正去清的间隔不短于 [`EARLY_MAX_AGE`]。
    fn sweep(&mut self) {
        if self.swept.is_some_and(|at| at.elapsed() < EARLY_MAX_AGE) {
            return;
        }
        self.swept = Some(Instant::now());
        self.waiting.retain(|_, waiting| {
            waiting.retain(|early| early.at.elapsed() <= EARLY_MAX_AGE);
            !waiting.is_empty()
        });
    }
}

impl std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbox").finish_non_exhaustive()
    }
}

impl Inbox {
    /// `packets` 是虚拟网卡取包的那个队列，和走数据报来的网络包是同一个。
    pub(crate) fn new(packets: mpsc::Sender<Datagram>) -> Arc<Self> {
        Arc::new(Self { sessions: RwLock::default(), early: Mutex::default(), packets })
    }

    fn early(&self) -> std::sync::MutexGuard<'_, EarlyPackets> {
        self.early.lock().expect("early sealed packets mutex poisoned")
    }

    /// 开始收 `peer` 用这个会话封的包。返回比它早到的那几个，交给 [`deliver_early`](Self::deliver_early) 补收。
    ///
    /// 分成两步：登记要和连接表的登记在同一把锁下面做（见 `Manager::register`），这样清扫被吊销的对端时不会漏掉
    /// 一把登记到一半的密钥；补收要解密，不该占着那把锁。
    #[must_use = "早到的包要交给 deliver_early 补收"]
    pub(crate) fn admit(&self, peer: NodeId, session: &Arc<Session>) -> Vec<Vec<u8>> {
        self.sessions.write().expect("sealed session table lock poisoned").insert((peer, session.id), Arc::clone(session));
        self.early().take(peer, session.id)
    }

    /// 补收 [`admit`](Self::admit) 交出来的包。这期间那个会话要是已经撤掉了（对端被吊销），它们解不开，重新留着等到过期。
    pub(crate) fn deliver_early(&self, peer: NodeId, early: Vec<Vec<u8>>) {
        for mut packet in early {
            self.receive(peer, &mut packet);
        }
    }

    /// 不再收这个会话的包：连接结束了，或者对端被吊销了。登记的已经是另一个会话（连接标识碰巧相同）时不动它。
    pub(crate) fn dismiss(&self, peer: NodeId, session: &Arc<Session>) {
        let mut sessions = self.sessions.write().expect("sealed session table lock poisoned");
        if sessions.get(&(peer, session.id)).is_some_and(|current| Arc::ptr_eq(current, session)) {
            sessions.remove(&(peer, session.id));
        }
        drop(sessions);
        self.early().sweep();
    }

    /// 把路径层交上来的一串包里封好的挑出来收下，剩下的连接包挪到前面接好，返回它们一共多少字节。
    ///
    /// `data` 是 `peer` 发来的一串包，每个 `stride` 字节，只有最后一个可以短。挑走几个之后剩下的还是这样：
    /// 短的那个要么被挑走了，要么还在最后。
    pub(crate) fn sift(&self, peer: NodeId, data: &mut [u8], stride: usize) -> usize {
        let stride = stride.max(1);
        if !data.chunks(stride).any(|packet| packet.first() == Some(&KIND_SEALED)) {
            return data.len();
        }
        let (mut kept, mut offset) = (0, 0);
        while offset < data.len() {
            let end = (offset + stride).min(data.len());
            if data[offset] == KIND_SEALED {
                self.receive(peer, &mut data[offset..end]);
            } else {
                data.copy_within(offset..end, kept);
                kept += end - offset;
            }
            offset = end;
        }
        kept
    }

    /// 路径层送上来一个 `peer` 发来的封好的包。解得开、里面是网络包帧的排进队列，其余的丢掉。
    pub(crate) fn receive(&self, peer: NodeId, packet: &mut [u8]) {
        let Some(header) = SealedHeader::parse(packet) else {
            return tracing::trace!(%peer, len = packet.len(), "丢掉一个封好的包：短得不成格式");
        };
        let session = self.sessions.read().expect("sealed session table lock poisoned").get(&(peer, header.session)).cloned();
        let Some(session) = session else {
            // 连接标识还没有登记：多半是对端握手完成得比本端早了几毫秒，先留着。也可能是对端手上的密钥已经作废
            // （本端重启过），那样的留一会儿就过期了。
            return self.early().hold(peer, header.session, packet);
        };
        match session.open(header, packet) {
            Ok(frame) if Channel::peek(frame) == Some(Channel::Packet) => {
                if self.packets.try_send(Datagram { peer, payload: Bytes::copy_from_slice(frame) }).is_err() {
                    tracing::trace!(%peer, "丢掉一个网络包：虚拟网卡的队列满了，或者本端正在关闭");
                }
            }
            Ok(_) => tracing::trace!(%peer, "丢掉一个封好的包：里面不是网络包帧"),
            Err(rejected) => tracing::trace!(%peer, %rejected, "丢掉一个封好的包"),
        }
    }
}

#[cfg(test)]
mod tests {
    use i3t_proto::flow::PacketHeader;

    use super::*;

    fn material(fill: u8) -> [u8; MATERIAL_LEN] {
        std::array::from_fn(|index| fill.wrapping_add(u8::try_from(index).unwrap()))
    }

    fn pair() -> (Session, Session) {
        (Session::from_material(&material(1), Role::Dialer), Session::from_material(&material(1), Role::Acceptor))
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        PacketHeader::Whole.encode(&mut frame);
        frame.extend_from_slice(body);
        frame
    }

    fn sealed(from: &Session, frame: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        from.seal(frame, &mut packet).unwrap();
        packet
    }

    fn opened(by: &Session, packet: &[u8]) -> Result<Vec<u8>, Rejected> {
        let mut packet = packet.to_vec();
        let header = SealedHeader::parse(&packet).unwrap();
        by.open(header, &mut packet).map(<[u8]>::to_vec)
    }

    #[test]
    fn each_side_opens_what_the_other_sealed_and_nothing_else() {
        let (dialer, acceptor) = pair();
        assert_eq!(dialer.id, acceptor.id, "两端导出的连接标识一样");
        assert_eq!(opened(&acceptor, &sealed(&acceptor, &frame(b"own"))), Err(Rejected::Forged), "自己这个方向的密钥解不开自己发的");
        let packet = sealed(&dialer, &frame(b"\x45 hello"));
        assert_eq!(packet.len(), frame(b"\x45 hello").len() + SealedHeader::OVERHEAD);
        assert_eq!(opened(&acceptor, &packet), Ok(frame(b"\x45 hello")));
        assert_eq!(opened(&dialer, &sealed(&acceptor, &frame(b"\x45 back"))), Ok(frame(b"\x45 back")));

        let stranger = Session::from_material(&material(9), Role::Acceptor);
        assert_eq!(opened(&stranger, &sealed(&dialer, &frame(b"x"))), Err(Rejected::Forged), "别的连接的密钥解不开");
        assert_eq!(acceptor.traffic(), (0, u64::try_from(packet.len()).unwrap()), "只有收下的才算流量");
    }

    #[test]
    fn packets_sealed_one_after_another_into_one_buffer_open_separately() {
        let (dialer, acceptor) = pair();
        let bodies = [&b"\x45 one"[..], b"\x45 two", b"\x45 six"];
        let mut batch = Vec::new();
        for body in bodies {
            dialer.seal(&frame(body), &mut batch).unwrap();
        }
        let stride = frame(bodies[0]).len() + SealedHeader::OVERHEAD;
        assert_eq!(batch.len(), 3 * stride);
        for (packet, body) in batch.chunks(stride).zip(bodies) {
            assert_eq!(opened(&acceptor, packet), Ok(frame(body)));
        }
    }

    #[test]
    fn any_changed_byte_fails_the_check_and_leaves_the_window_alone() {
        let (dialer, acceptor) = pair();
        let packet = sealed(&dialer, &frame(b"\x45 payload"));
        // 首字节（类型）和连接标识是路径层和收的一方用来分发的，改了根本到不了这里；其余的每个字节都算在校验里。
        for index in 5..packet.len() {
            let mut tampered = packet.clone();
            tampered[index] ^= 0x01;
            let header = SealedHeader::parse(&tampered).unwrap();
            let verdict = acceptor.open(header, &mut tampered).map(<[u8]>::to_vec);
            assert_eq!(verdict, Err(Rejected::Forged), "改了第 {index} 个字节");
        }
        assert_eq!(opened(&acceptor, &packet), Ok(frame(b"\x45 payload")), "伪造的包没有占掉这个序号");
    }

    #[test]
    fn a_packet_is_taken_once_and_reordering_within_the_window_is_fine() {
        let (dialer, acceptor) = pair();
        let packets: Vec<Vec<u8>> = (0..200u32).map(|index| sealed(&dialer, &frame(&index.to_be_bytes()))).collect();
        // 倒着到：每个都收，再来一遍都不收。
        for packet in packets.iter().rev() {
            assert!(opened(&acceptor, packet).is_ok());
        }
        for packet in &packets {
            assert_eq!(opened(&acceptor, packet), Err(Rejected::Replayed));
        }
    }

    #[test]
    fn the_replay_window_forgets_what_is_too_old_and_never_takes_a_number_twice() {
        let span = REPLAY_WORDS as u64 * REPLAY_WORD_BITS;
        let mut window = Replay::default();
        assert!(window.accept(0) && !window.accept(0));
        assert!(window.accept(5) && window.accept(3) && !window.accept(3) && !window.accept(5));
        // 往前跳一大步：跳过去的还能收一次，旧得出了窗口的不收。
        assert!(window.accept(10 * span + 7));
        assert!(!window.accept(4), "比窗口旧的不收，哪怕没见过");
        assert!(window.accept(10 * span + 6) && !window.accept(10 * span + 6));
        let oldest_block = 10 * span + 7 - (REPLAY_WORDS as u64 - 1) * REPLAY_WORD_BITS;
        let oldest = oldest_block - oldest_block % REPLAY_WORD_BITS;
        assert!(window.accept(oldest), "窗口里最旧的那个字还收");
        assert!(!window.accept(oldest - 1), "再往前一个就出了窗口");
        // 圈转回来用到同一个位置时，那里旧的记号已经清掉了。
        assert!(window.accept(11 * span + 7) && !window.accept(11 * span + 7));
        assert!(!window.accept(10 * span + 7), "上一圈同一个位置上的序号已经出了窗口");
    }

    #[test]
    fn every_number_in_a_shuffled_run_is_accepted_exactly_once() {
        // 一个固定的打乱：步长和个数互素，把 0..n 走一遍。乱序的跨度比窗口小。
        let count = 1500u64;
        let mut window = Replay::default();
        let mut taken = 0;
        for round in 0..2 {
            for index in 0..count {
                let counter = (index * 7) % count;
                if window.accept(counter) {
                    taken += 1;
                }
            }
            assert_eq!(taken, count, "第 {round} 遍之后一共收下的个数");
        }
    }

    /// 用 `from` 的密钥封一个序号是 `counter` 的包，不管这个序号它自己肯不肯用：拿着密钥、不守规矩的对端做得出来。
    fn sealed_as(from: &Session, counter: u64, frame: &[u8]) -> Vec<u8> {
        let header = SealedHeader { session: from.id, counter }.to_bytes();
        let mut body = frame.to_vec();
        let tag = from.sealing.seal_in_place_separate_tag(nonce(counter), Aad::from(header), &mut body).unwrap();
        [&header[..], &body, tag.as_ref()].concat()
    }

    #[test]
    fn a_number_no_sender_would_use_is_refused_even_with_the_right_key_and_the_window_is_untouched() {
        let (dialer, acceptor) = pair();
        let earlier = sealed(&dialer, &frame(b"earlier"));
        assert!(opened(&acceptor, &earlier).is_ok());
        for counter in [COUNTER_LIMIT, u64::MAX - 1, u64::MAX] {
            let packet = sealed_as(&dialer, counter, &frame(b"from a peer that does not keep to the rules"));
            assert_eq!(opened(&acceptor, &packet), Err(Rejected::OutOfRange), "序号 {counter:#x}");
        }
        assert!(!acceptor.is_spent(), "这不算认证失败");
        assert_eq!(opened(&acceptor, &earlier), Err(Rejected::Replayed), "窗口没有被冲掉：收过的还是不收");
        assert!(opened(&acceptor, &sealed(&dialer, &frame(b"next"))).is_ok(), "正常的包照收");
        let last = sealed_as(&dialer, COUNTER_LIMIT - 1, &frame(b"the last number a sender uses"));
        assert!(opened(&acceptor, &last).is_ok(), "发的一方用得到的最后一个序号还是收的");
    }

    #[test]
    fn the_window_itself_refuses_the_largest_number_instead_of_overflowing() {
        let mut replay = Replay::default();
        assert!(replay.accept(7));
        assert!(!replay.accept(u64::MAX));
        assert!(!replay.accept(7), "之前记下的还在");
        assert!(replay.accept(8));
    }

    #[test]
    fn the_sender_stops_when_its_numbers_run_out() {
        let (dialer, _acceptor) = pair();
        dialer.next.store(COUNTER_LIMIT - 1, Ordering::Relaxed);
        let mut packets = Vec::new();
        assert_eq!(dialer.seal(&frame(b"last"), &mut packets), Ok(()));
        assert!(dialer.is_spent());
        let one = packets.clone();
        assert_eq!(dialer.seal(&frame(b"one too many"), &mut packets), Err(Spent));
        assert_eq!(packets, one, "封不成的不留半截在缓冲区里");
    }

    #[test]
    fn too_many_forgeries_retire_the_key() {
        let (_dialer, acceptor) = pair();
        assert!(!acceptor.is_spent());
        acceptor.forged.store(FORGERY_LIMIT, Ordering::Relaxed);
        assert!(acceptor.is_spent());
    }

    #[test]
    fn a_silent_peer_is_probed_once_per_interval_and_a_talking_one_never() {
        let (dialer, _acceptor) = pair();
        assert!(!dialer.probe_due(), "刚握完手，不用问");
        // 一个建立了很久的会话，不用真的等。
        let old =
            |role| Session { created: Instant::now().checked_sub(3 * PROBE_EVERY).unwrap(), ..Session::from_material(&material(1), role) };
        let silent = old(Role::Dialer);
        assert!(silent.probe_due(), "一直没有回音：该问了");
        assert!(!silent.probe_due(), "刚问过，这一阵不再问");
        // 对端在说话的，不问。
        let talking = old(Role::Acceptor);
        let from_dialer = sealed(&dialer, &frame(b"\x45 ping"));
        assert!(opened(&talking, &from_dialer).is_ok());
        assert!(!talking.probe_due());
        assert!(talking.heard().is_some());
    }

    #[test]
    fn the_switch_reads_on_and_off_and_falls_back_on_anything_else() {
        assert_eq!(PacketTransport::from_env_value("on"), PacketTransport::Sealed);
        assert_eq!(PacketTransport::from_env_value("off"), PacketTransport::Datagram);
        assert_eq!(PacketTransport::from_env_value("maybe"), PacketTransport::Sealed);
    }

    #[test]
    fn the_negotiated_protocol_name_says_what_both_ends_understand() {
        assert_eq!(Agreed::from_protocol(Some(b"i3t/3")), Agreed { sealed: true, bundles: true });
        assert_eq!(Agreed::from_protocol(Some(b"i3t/2")), Agreed { sealed: true, bundles: false });
        assert_eq!(Agreed::from_protocol(Some(b"i3t/1")), Agreed::default());
        assert_eq!(Agreed::from_protocol(None), Agreed::default());
    }

    fn inbox() -> (Arc<Inbox>, mpsc::Receiver<Datagram>) {
        let (packets, queue) = mpsc::channel(8);
        (Inbox::new(packets), queue)
    }

    fn peer() -> NodeId {
        NodeId::new(2).unwrap()
    }

    /// 登记，并且马上补收早到的包。
    fn admit(inbox: &Inbox, session: &Arc<Session>) {
        inbox.deliver_early(peer(), inbox.admit(peer(), session));
    }

    #[test]
    fn the_inbox_queues_packets_of_admitted_sessions_only() {
        let (inbox, mut queue) = inbox();
        let (dialer, acceptor) = pair();
        let acceptor = Arc::new(acceptor);
        admit(&inbox, &acceptor);

        inbox.receive(peer(), &mut sealed(&dialer, &frame(b"\x45 one")));
        let got = queue.try_recv().unwrap();
        assert_eq!((got.peer, &got.payload[..]), (peer(), &frame(b"\x45 one")[..]));

        // 同一个连接标识、别的对端名下：找不到会话。
        inbox.receive(NodeId::new(3).unwrap(), &mut sealed(&dialer, &frame(b"\x45 two")));
        // 解得开，但里面不是网络包帧（首字节没有那一位）。
        inbox.receive(peer(), &mut sealed(&dialer, b"\x00 not a packet frame"));
        assert!(queue.try_recv().is_err());

        inbox.dismiss(peer(), &acceptor);
        inbox.receive(peer(), &mut sealed(&dialer, &frame(b"\x45 three")));
        assert!(queue.try_recv().is_err(), "会话撤掉之后不再收");
    }

    #[test]
    fn packets_that_beat_the_session_are_delivered_when_it_is_admitted() {
        let (inbox, mut queue) = inbox();
        let (dialer, acceptor) = pair();
        for body in [&b"\x45 first"[..], b"\x45 second"] {
            inbox.receive(peer(), &mut sealed(&dialer, &frame(body)));
        }
        assert!(queue.try_recv().is_err(), "密钥还没有登记");
        admit(&inbox, &Arc::new(acceptor));
        assert_eq!(&queue.try_recv().unwrap().payload[..], &frame(b"\x45 first")[..]);
        assert_eq!(&queue.try_recv().unwrap().payload[..], &frame(b"\x45 second")[..]);
    }

    #[test]
    fn early_packets_are_not_delivered_if_the_session_is_dismissed_before_they_are_replayed() {
        let (inbox, mut queue) = inbox();
        let (dialer, acceptor) = pair();
        let acceptor = Arc::new(acceptor);
        for body in [&b"\x45 first"[..], b"\x45 second"] {
            inbox.receive(peer(), &mut sealed(&dialer, &frame(body)));
        }
        // 登记和补收之间对端被吊销了：登记这一步自己不投递，撤掉之后补收的那几个也解不开。
        let early = inbox.admit(peer(), &acceptor);
        assert_eq!(early.len(), 2);
        assert!(queue.try_recv().is_err(), "登记这一步不投递");
        inbox.dismiss(peer(), &acceptor);
        inbox.deliver_early(peer(), early);
        assert!(queue.try_recv().is_err(), "会话已经撤掉了，早到的包不收");
        inbox.receive(peer(), &mut sealed(&dialer, &frame(b"\x45 later")));
        assert!(queue.try_recv().is_err(), "之后到的也不收");
    }

    #[test]
    fn early_packets_of_another_session_wait_for_their_own_key_and_the_queue_is_bounded() {
        let (inbox, mut queue) = inbox();
        let (dialer, acceptor) = pair();
        let other = Session::from_material(&material(9), Role::Dialer);
        inbox.receive(peer(), &mut sealed(&other, &frame(b"\x45 for another session")));
        for body in [&b"\x45 a"[..], b"\x45 b", b"\x45 c"] {
            inbox.receive(peer(), &mut sealed(&dialer, &frame(body)));
        }
        admit(&inbox, &Arc::new(acceptor));
        for body in [&b"\x45 a"[..], b"\x45 b", b"\x45 c"] {
            assert_eq!(&queue.try_recv().unwrap().payload[..], &frame(body)[..], "按到的先后补上");
        }
        assert!(queue.try_recv().is_err());
        assert_eq!(inbox.early().waiting.get(&peer()).map(VecDeque::len), Some(1), "另一个会话的那个还留着");

        // 一直等不到密钥的，留着的个数有上限，新的挤掉旧的。
        for index in 0..EARLY_PACKETS + 10 {
            inbox.receive(peer(), &mut sealed(&other, &frame(&u32::try_from(index).unwrap().to_be_bytes())));
        }
        assert_eq!(inbox.early().waiting.get(&peer()).map(VecDeque::len), Some(EARLY_PACKETS));
    }

    #[test]
    fn early_packets_that_never_get_a_key_are_swept_away() {
        let mut early = EarlyPackets::default();
        early.hold(peer(), 7, b"stale");
        // 假装这个包和上一次清扫都是很久以前的事。
        let long_ago = Instant::now().checked_sub(2 * EARLY_MAX_AGE).unwrap();
        early.waiting.get_mut(&peer()).unwrap()[0].at = long_ago;
        early.swept = Some(long_ago);
        assert!(early.take(peer(), 7).is_empty(), "过期的不再交出去");
        assert!(early.waiting.is_empty());
    }

    #[test]
    fn sealed_packets_are_picked_out_of_a_batch_and_the_rest_stays_in_order() {
        let (inbox, mut queue) = inbox();
        let (dialer, acceptor) = pair();
        admit(&inbox, &Arc::new(acceptor));
        // 等长的一串：连接包、封好的、连接包、封好的，最后一个短的连接包。
        let body = [0x45; 40];
        let stride = sealed(&dialer, &frame(&body)).len();
        let quic = |fill: u8, len: usize| {
            let mut packet = vec![fill; len];
            packet[0] = 0x40;
            packet
        };
        let batch = [quic(1, stride), sealed(&dialer, &frame(&body)), quic(2, stride), sealed(&dialer, &frame(&body)), quic(3, 17)];
        let mut data = batch.concat();
        let kept = inbox.sift(peer(), &mut data, stride);
        assert_eq!(&data[..kept], &[quic(1, stride), quic(2, stride), quic(3, 17)].concat()[..]);
        assert_eq!(&queue.try_recv().unwrap().payload[..], &frame(&body)[..]);
        assert!(queue.try_recv().is_ok() && queue.try_recv().is_err(), "两个封好的包各收下一次");

        // 全是连接包的原样不动；全是封好的一个不剩。
        let mut plain = [quic(4, stride), quic(5, 9)].concat();
        let untouched = plain.clone();
        assert_eq!(inbox.sift(peer(), &mut plain, stride), untouched.len());
        assert_eq!(plain, untouched);
        let mut all_sealed = sealed(&dialer, &frame(&body));
        assert_eq!(inbox.sift(peer(), &mut all_sealed, stride), 0);
        assert!(queue.try_recv().is_ok());
    }

    #[test]
    fn dismissing_an_old_session_leaves_a_newer_one_with_the_same_id_alone() {
        let (inbox, mut queue) = inbox();
        let (dialer, acceptor) = pair();
        let old = Arc::new(Session::from_material(&material(1), Role::Acceptor));
        let current = Arc::new(acceptor);
        admit(&inbox, &old);
        admit(&inbox, &current);
        inbox.dismiss(peer(), &old);
        inbox.receive(peer(), &mut sealed(&dialer, &frame(b"\x45 still here")));
        assert!(queue.try_recv().is_ok());
    }
}
