//! controller 的核心：存储之上的全部规则，和每个节点的 netmap 的下发。
//!
//! [`Controller`] 的方法都是同步的，状态都在一把锁里：一次操作要么完整地做完（写存储、重算受影响的 netmap、
//! 放进各个节点的发送队列），要么不做。节点协议和管理 API 只是它的两个入口。不读写存储的节点消息（转发信令、交回查询的回答、
//! 取更新包）用到的那一小部分另外加锁，数据库卡住时不跟着等（见 [`switchboard`]）。
//!
//! 方法里有数据库读写，重算一个大网络也要花时间，所以异步代码要经 `spawn_blocking` 调用它们。

mod address;
mod diag;
mod enrollment;
mod exit_test;
mod forwards;
mod groups;
mod metrics;
mod naming;
mod networks;
mod no_udp;
mod nodes;
mod pairs;
mod protocol;
mod proxies;
mod publish;
mod rollout;
mod routes;
mod rules;
mod stats;
mod switchboard;
#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
mod update;
mod usage;
mod views;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use i3t_crypto::{NodeKey, tls};
use i3t_model::Netmap;
use i3t_model::admin::{LogEntry, NetworkId, Node, RelayView, Status, Timestamp, action};
use i3t_model::control::{ForwardReport, LaneReport, ListenerReport, PeerUse, PerformanceReport, ProxyReport, RelayUse, VnetReport};
use i3t_model::update::{UpdateStatus, Version};
use i3t_proto::{NodeId, PublicKey};
use tokio::sync::Notify;

use crate::error::{Entity, Error, error_chain};
use crate::gate::Throttle;
use crate::netmap::NetworkView;
use crate::node_server::{PENDING, VerificationQuota};
use crate::relay_reach::{self, ReachIndex};
use crate::store::{DIGEST_LEN, Database, GroupRecord, LogFilter, NetworkRecord, NodeRecord, Store, StoreError};
use crate::sync::NodeSync;
use crate::{node_addresses, secret};
use switchboard::Switchboard;

pub use protocol::{Admitted, Waits};
pub(crate) use publish::Seeds;
pub use routes::RouteAnswers;

/// 节点协议在 TLS 上的 ALPN。
pub const ALPN: &[u8] = b"i3t-ctl/1";

const KEY_FILE: &str = "controller.key";
/// 用 SQLite 的版本（0.1.34 和更早）留在数据目录里的数据库文件。
const OLD_DATABASE_FILE: &str = "controller.db";
const ADMIN_TOKEN_META: &str = "admin_token_hash";
/// 这个库是哪个 controller 的：它的公钥。数据目录里的密钥要和它是一对（见 [`bound_key`]）。
const CONTROLLER_KEY_META: &str = "controller_key";

/// 删掉的节点的虚拟 IP 和名字多久之后才能再分出去。
const COOLDOWN_SECS: u64 = 90 * 24 * 60 * 60;
/// 拒绝没有注册的公钥、无效的令牌这一类日志多久最多记一条。谁都能拿一把新生成的公钥连上来，不限的话日志会被刷满。
const REFUSAL_LOG_EVERY: Duration = Duration::from_secs(10);

/// controller 里的几个时间。默认值是协议约定的，测试里会改短。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// 节点确认之后等多久，再把因此可以继续的变更发给别的节点。一批确认并成一次下发。
    pub ack_coalesce: Duration,
    /// 节点上报的端点或挂靠关系变了，要发给它的对端：同一个对端因此被重算的两次之间至少隔这么久，
    /// 所以一个反复变化的节点引不起下发风暴。离上一次已经够久时不等这么久，只等很短的一下（见 `defer_report`）。
    pub report_coalesce: Duration,
    /// 访问关系变更的一项等待，从登记的那一刻起这么久还没等到在线的节点确认，就不再等，免得它卡住别的节点。
    /// 这期间给它发了多少份 netmap、它换了多少次连接都不往后推。
    pub ack_timeout: Duration,
    /// controller 连续这么久没有东西要发给一个节点时，发一个心跳。
    pub heartbeat_idle: Duration,
    /// 这么久收不到节点的任何消息，就把它记为离线。
    pub liveness_timeout: Duration,
    /// 新连接要在这么久之内完成 TLS 握手并发来第一条消息。
    pub handshake_timeout: Duration,
    /// 一个 relay 更新完重新连上来之后，过这么久才轮到同一个网络里的下一个 relay 更新：
    /// 挂靠它的节点要重新建好中转会话，换路的时候才有路可换。
    pub relay_settle: Duration,
    /// 节点报的结果说它用不了 UDP，要一直这样这么久才认定（见 `no_udp`）。
    ///
    /// 有 UDP 的节点也会一阵子只经 TCP 连着 relay：会话让 UDP 先走一秒，没握上手就先用 TCP，30 秒之后再试 UDP；
    /// 没有会话的 relay 每分钟用 UDP 问一次延迟。两分钟里这两样都至少轮过一次，有 UDP 的节点总会有一个 relay 经 UDP 回答。
    pub no_udp_settle: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            ack_coalesce: Duration::from_millis(50),
            report_coalesce: Duration::from_secs(1),
            ack_timeout: Duration::from_secs(10),
            heartbeat_idle: Duration::from_secs(20),
            liveness_timeout: Duration::from_secs(35),
            handshake_timeout: Duration::from_secs(10),
            relay_settle: Duration::from_secs(30),
            no_udp_settle: Duration::from_secs(120),
        }
    }
}

pub struct Controller {
    key: NodeKey,
    public_addr: String,
    /// 从数据目录打开时是那个目录。
    data_dir: Option<PathBuf>,
    timing: Timing,
    /// 管理令牌的哈希。每个管理请求都要查它，所以不放在大锁里。`Inner` 手上也有一份。
    admin_token: Arc<Mutex<Option<[u8; DIGEST_LEN]>>>,
    inner: Mutex<Inner>,
    /// 不读写存储的节点消息用到的状态，不放在大锁里（见 [`switchboard`]）。`Inner` 手上也有一份。
    switchboard: Arc<Mutex<Switchboard>>,
    /// 有延后的下发时叫醒后台任务。`Inner` 手上也有一份。
    wake: Arc<Notify>,
    /// 有包要取时叫醒取包的后台任务。
    release_wake: Notify,
    /// 设置变了、要尽快重新查发布源时叫醒查发布源的后台任务。
    check_wake: Notify,
    /// 给还没认出来的连接的拒绝日志限速。
    pub(crate) refusal_log: Throttle,
    /// 同一个控制器的节点监听器共用核验配额。重开监听时，旧的阻塞任务仍可能在运行。
    pub(crate) verification_quota: Arc<VerificationQuota>,
}

/// [`Controller::open`] 的结果。
pub struct Opened {
    pub controller: Controller,
    /// 第一次启动时生成的管理令牌。只有这一次能拿到，controller 只存它的哈希。
    pub admin_token: Option<String>,
}

pub(crate) struct Inner {
    pub(crate) store: Store,
    pub(crate) timing: Timing,
    pub(crate) clock: Clock,
    /// 每个节点的 netmap 下发到了哪一步。存储里有的节点这里都有。
    pub(crate) sync: BTreeMap<NodeId, NodeSync>,
    /// 现在连着的节点。
    pub(crate) live: BTreeMap<NodeId, Live>,
    /// 报的结果说它用不了 UDP 的节点，和从什么时候起（见 `no_udp`）。controller 重启时按存储里的结果重新建。
    pub(crate) no_udp: BTreeMap<NodeId, no_udp::NoUdp>,
    /// 有节点报的 relay 结果变了、要重新看谁用不了 UDP 的网络。
    pub(crate) no_udp_dirty: BTreeSet<NetworkId>,
    /// 最近一次上报说自己没有装虚拟网卡的节点，别的节点的 netmap 里列出来（`Netmap::no_vnet`）。
    /// 不存进存储：controller 重启之后、节点报上来之前当作都有，最坏只是那一会儿发给它的包收不到。离线时照旧记着最后的样子。
    pub(crate) no_vnet: BTreeSet<NodeId>,
    /// 等着延后重算的节点。
    pub(crate) dirty: BTreeMap<NodeId, Deferred>,
    /// 叫醒后台任务，和 [`Controller::wake_if_needed`] 用的是同一个。重算没做成、排了重试时在这里叫：
    /// 那时调用方多半带着错误提前返回了，轮不到它来叫。
    pub(crate) wake: Arc<Notify>,
    /// 后台工作时整个数据库读写不了（连不上、只读了、盘满了）：这个时刻之前后台不再去重算，也不做别的要写存储的
    /// 不急的事（见 `Inner::tick_work`）。不然到期时间错开的节点、被叫醒的后台任务会让它一次接一次地去碰数据库。
    /// 只是某一行、某张表被别的连接占着不算，那由存储限着等多久。
    pub(crate) flush_after: Option<Instant>,
    /// 有一次提交当时不知道结果、后来查出来是算了数的：提交之后该做的事（重算 netmap、断开被删的节点）那时没有做，
    /// 内存里的状态和数据库对不上，要照数据库补齐（见 [`Inner::settle_commits`]）。
    pub(crate) out_of_step: bool,
    /// 管理令牌的哈希，和 [`Controller::is_admin_token`] 查的是同一个。照数据库补齐时按库里记的改它。
    pub(crate) admin_token: Arc<Mutex<Option<[u8; DIGEST_LEN]>>>,
    /// 和 [`Controller`] 手上的是同一个。先拿着这把大锁、再拿它的锁（见 [`switchboard`]）。
    switchboard: Arc<Mutex<Switchboard>>,
    /// 各个节点最近上报的路由表。节点离线之后留着，界面上显示成过期的；controller 重启就没有了。
    pub(crate) routes: BTreeMap<NodeId, routes::Reported>,
    /// 出口和用出口的节点报的计数，算健康和交叉核对用。节点离线之后留着；controller 重启就没有了。
    pub(crate) usage: usage::Usage,
    /// 进行中的主动测试和全网矩阵。
    pub(crate) diag: diag::Diag,
    /// 节点更新：已知的发布、包、设置、轮次。
    pub(crate) updates: update::Updates,
    pub(crate) counters: metrics::Counters,
    /// 给界面画图的时间序列：这一段里攒着、还没写进存储的数。
    pub(crate) stats: stats::Collector,
    /// controller 对外地址（`--public-addr`）里的主机是哪个 IP：节点走回环连过来时，别的机器要用它找到这个节点。
    /// 主机是域名、还没有解析出来时是 `None`。
    pub(crate) public_host: Option<IpAddr>,
    next_conn: u64,
    next_request: u64,
    last_purge: Option<Instant>,
}

/// 一个在线节点的连接，和它在这次连接期间上报的东西。
pub(crate) struct Live {
    /// 连接的序号。旧连接收尾时靠它知道自己已经被新连接顶替了。
    pub(crate) conn: u64,
    pub(crate) network: NetworkId,
    pub(crate) mapping_varies: Option<bool>,
    pub(crate) flows: u32,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_bytes: u64,
    /// 节点说的节点协议是第几版。后来加的消息只发给够新的节点。
    pub(crate) protocol: u32,
    /// 节点这次连接上最近一次报的更新进度；还没有上报过（或者它不懂更新）时是 `None`。
    pub(crate) update: Option<UpdateStatus>,
    /// 这次连接上发给它的更新指令。
    pub(crate) order: Option<rollout::Order>,
    /// 这条连接是 `i3t join` 注册时的那一条，不是节点真的跑起来连上的：它不算"最近在线"。
    pub(crate) enrolling: bool,
    /// 这次连接上最近一次上报的时刻；还没有上报过时是 `None`。
    pub(crate) reported_at: Option<Instant>,
    /// 最近一次上报里的代理、节点按本机配置开的组网入口和端口转发的状态。
    pub(crate) proxies: Vec<ProxyReport>,
    pub(crate) listeners: Vec<ListenerReport>,
    pub(crate) forwards: Vec<ForwardReport>,
    /// 最近一次上报里 ice3proxy 的状况。
    pub(crate) lanes: Option<LaneReport>,
    /// 最近一次上报里节点实际在用的性能档位。
    pub(crate) performance: Option<PerformanceReport>,
    /// 最近一次上报里虚拟网卡的状况。
    pub(crate) vnet: Option<VnetReport>,
    /// 节点说它接不接受吞吐测试（本机配置文件里的开关）。
    pub(crate) throughput_tests: bool,
    /// 这条连接的来源 IP 和节点自报的端口。controller 对外地址的主机后来才知道时，靠它们重算 controller 看到的地址。
    pub(crate) remote: IpAddr,
    pub(crate) port: u16,
    /// 最近一次上报里到各个对端的连接上的流数和流量（最多 [`MAX_PEER_USE`](i3t_model::control::MAX_PEER_USE) 个）。
    pub(crate) peer_use: BTreeMap<NodeId, PeerUse>,
    /// 节点是 relay 时，最近一次上报里谁在用它。
    pub(crate) relay_use: Option<RelayUse>,
}

pub(crate) struct Deferred {
    pub(crate) network: NetworkId,
    pub(crate) due: Instant,
}

impl Controller {
    /// 打开数据目录和数据库：第一次启动时生成 controller 的密钥，在库里建表，生成管理令牌。
    ///
    /// 数据目录里只有 controller 的密钥和更新包的缓存；网络、节点和各项设置都在 `database` 里。
    /// 两样要配着用：节点认的是这把密钥，库里记的是这把密钥名下的节点。库里记着它是哪把密钥的，
    /// 对不上的不开：拿错了数据目录、连错了库，或者恢复时忘了把密钥放回来，都不会悄悄变成另一个 controller。
    ///
    /// `public_addr` 是节点连 controller 用的 `主机:端口`，会写进每个注册令牌。
    ///
    /// # Errors
    ///
    /// 目录建不了、密钥文件读不出来，连不上数据库、读写它失败，或者密钥和数据库对不上
    /// （[`Error::KeyMismatch`]、[`Error::KeyMissing`]）。
    pub fn open(data_dir: &Path, database: &Database, public_addr: String) -> Result<Opened, Error> {
        fs::create_dir_all(data_dir).map_err(|source| Error::Io { path: data_dir.to_owned(), source })?;
        // 先连数据库，再碰密钥：连不上的话不在数据目录里留下一把新生成的密钥。
        let store = Store::open(database)?;
        let key = bound_key(&store, &data_dir.join(KEY_FILE))?;
        // 早先的版本把数据存在数据目录里的这个文件里。现在不读它了：升级上来的人看到一个空的 controller 时，日志里有原因。
        let old = data_dir.join(OLD_DATABASE_FILE);
        if old.exists() {
            tracing::warn!(path = %old.display(), "数据目录里有旧版本的数据库文件：这个版本的数据在 PostgreSQL 里，不再读它，里面的数据也不会搬过来");
        }
        let mut controller = Self::new(store, key, public_addr, Timing::default())?.with_release_cache(data_dir.join(update::CACHE_DIR));
        controller.data_dir = Some(data_dir.to_owned());
        let admin_token = if controller.has_admin_token() { None } else { Some(controller.issue_admin_token()?) };
        Ok(Opened { controller, admin_token })
    }

    /// 在一个已经打开的存储上建 controller。不生成管理令牌。
    ///
    /// # Errors
    ///
    /// 读存储失败。
    pub fn new(mut store: Store, key: NodeKey, public_addr: String, timing: Timing) -> Result<Self, Error> {
        let admin_token = Arc::new(Mutex::new(admin_token_hash(&store)?));
        let version: Version = env!("CARGO_PKG_VERSION").parse().expect("Cargo 保证包的版本号是合法的语义化版本");
        let updates = update::Updates::load(&store, version)?;
        let wake = Arc::new(Notify::new());
        store.wake_on_unsettled_commit(Arc::clone(&wake));
        let switchboard = Arc::new(Mutex::new(Switchboard::default()));
        let mut inner = Inner {
            store,
            timing,
            clock: Clock::default(),
            sync: BTreeMap::new(),
            live: BTreeMap::new(),
            no_udp: BTreeMap::new(),
            no_udp_dirty: BTreeSet::new(),
            no_vnet: BTreeSet::new(),
            dirty: BTreeMap::new(),
            wake: Arc::clone(&wake),
            flush_after: None,
            out_of_step: false,
            admin_token: Arc::clone(&admin_token),
            switchboard: Arc::clone(&switchboard),
            routes: BTreeMap::new(),
            usage: usage::Usage::default(),
            diag: diag::Diag::default(),
            updates,
            counters: metrics::Counters::default(),
            stats: stats::Collector::default(),
            public_host: host_ip(&public_addr),
            next_conn: 0,
            next_request: 0,
            last_purge: None,
        };
        inner.load_sync()?;
        Ok(Self {
            key,
            public_addr,
            data_dir: None,
            timing,
            admin_token,
            inner: Mutex::new(inner),
            switchboard,
            wake,
            release_wake: Notify::new(),
            check_wake: Notify::new(),
            refusal_log: Throttle::new(REFUSAL_LOG_EVERY),
            verification_quota: VerificationQuota::new(PENDING),
        })
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.key.public()
    }

    #[must_use]
    pub fn public_addr(&self) -> &str {
        &self.public_addr
    }

    /// controller 对外地址里的主机，它是域名（不是 IP 地址）的话。
    #[must_use]
    pub fn public_host_name(&self) -> Option<&str> {
        let (host, _port) = self.public_addr.rsplit_once(':')?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.parse::<IpAddr>().is_err().then_some(host)
    }

    #[must_use]
    pub const fn timing(&self) -> Timing {
        self.timing
    }

    /// 节点协议的 TLS 配置。任何公钥都能完成握手：还没注册的节点要先连上来才能交注册令牌，
    /// 认不认这把公钥在第一条消息上决定。
    ///
    /// # Errors
    ///
    /// 用 controller 的密钥签证书失败。
    pub fn tls_config(&self) -> Result<rustls::ServerConfig, Error> {
        Ok(tls::server_config(&self.key, |_| true, ALPN)?)
    }

    fn has_admin_token(&self) -> bool {
        self.admin_token.lock().expect("admin token mutex poisoned").is_some()
    }

    /// 生成一个新的管理令牌，原来的随即作废。返回的明文只有这一次能拿到。
    ///
    /// # Errors
    ///
    /// 随机数源不可用，或者写存储失败。
    pub fn issue_admin_token(&self) -> Result<String, Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let (token, hash) = new_admin_token()?;
        inner.store.atomically(|store| record_admin_token(store, &hash, now))?;
        *self.admin_token.lock().expect("admin token mutex poisoned") = Some(hash);
        Ok(token)
    }

    /// 给数据目录 `data_dir`、数据库 `database` 的 controller 生成一个新的管理令牌，原来的随即作废。
    /// 返回的明文只有这一次能拿到。
    ///
    /// 换的是数据库里管理令牌的哈希，另记一条操作；不建 controller，所以不需要对外地址。
    /// 正运行着的 controller 记着原来的哈希，不知道令牌换了，所以要在它停着时做。
    ///
    /// 和 [`Controller::open`] 一样：密钥读不懂的话不做；表结构会升到这个程序的版本，之后更旧的程序就打不开它了。
    /// 和它不一样的是这里不建任何东西：`data_dir` 写错了、或者连到了一个空的库，不会在那里生成一个新的空 controller。
    /// 库是另一个 controller 的（它记的不是这个数据目录里的密钥）时也不做：不会拿着这一个的数据目录换掉那一个的令牌。
    ///
    /// # Errors
    ///
    /// `data_dir` 里没有密钥（[`Error::NotDataDir`]）或者密钥读不懂，库里没有 controller 的表
    /// （[`StoreError::Empty`](crate::store::StoreError::Empty)），库不是这把密钥的（[`Error::KeyMismatch`]），
    /// 连不上或者读写数据库失败，或者随机数源不可用。
    pub fn reset_admin_token(data_dir: &Path, database: &Database) -> Result<String, Error> {
        let key = required(data_dir, KEY_FILE)?;
        // 密钥读不懂的话 controller 启动不了，换了令牌也用不上：现在就说，别等到启动时。
        let pem = fs::read_to_string(&key).map_err(|source| Error::Io { path: key.clone(), source })?;
        let node_key = NodeKey::from_pem(&pem).map_err(|source| Error::Key { path: key.clone(), source })?;
        let mut store = Store::open_existing(database)?;
        let public = node_key.public();
        let (token, hash) = new_admin_token()?;
        let now = Clock::default().now();
        store.atomically(|store| {
            // controller 在一个库上启动过，库里就记着它的公钥。没有记的库没有哪个 controller 用过，也算对不上。
            // 和换令牌在同一个事务里核对。
            if store.meta(CONTROLLER_KEY_META)?.as_deref() != Some(public.as_bytes().as_slice()) {
                return Err(Error::KeyMismatch { path: key.clone() });
            }
            Ok(record_admin_token(store, &hash, now)?)
        })?;
        Ok(token)
    }

    /// `token` 是不是当前的管理令牌。
    #[must_use]
    pub fn is_admin_token(&self, token: &str) -> bool {
        let expected = *self.admin_token.lock().expect("admin token mutex poisoned");
        expected.is_some_and(|expected| secret::digests_match(&expected, &secret::sha256(token.as_bytes())))
    }

    /// # Errors
    ///
    /// 读存储失败。
    pub fn status(&self) -> Result<Status, Error> {
        let inner = self.lock();
        let updates = &inner.updates;
        let newer = updates.release.as_ref().map(|release| &release.manifest.version).filter(|version| **version > updates.version);
        Ok(Status {
            version: updates.version.to_string(),
            controller_key: self.public_key(),
            public_addr: self.public_addr.clone(),
            networks: count(inner.store.networks()?.len()),
            nodes: inner.store.node_count(None)?,
            online: count(inner.live.len()),
            newer_version: newer.cloned(),
            data_dir: self.data_dir.as_ref().map(|dir| dir.display().to_string()),
        })
    }

    /// 最近的操作记录，新的在前。
    ///
    /// # Errors
    ///
    /// 读存储失败。
    pub fn oplog(&self, limit: u32) -> Result<Vec<LogEntry>, Error> {
        Ok(self.lock().store.oplog(limit)?)
    }

    /// 符合条件的操作记录，新的在前。
    ///
    /// # Errors
    ///
    /// 读存储失败。
    pub fn oplog_filtered(&self, filter: &LogFilter) -> Result<Vec<LogEntry>, Error> {
        Ok(self.lock().store.oplog_filtered(filter)?)
    }

    /// 一个节点当前版本的 netmap，和发给它的那一份相同。节点不存在时返回 `None`。
    ///
    /// # Errors
    ///
    /// 读存储失败。
    pub fn netmap_of(&self, node: NodeId) -> Result<Option<Netmap>, Error> {
        let inner = self.lock();
        let Some(record) = inner.store.node(node)? else { return Ok(None) };
        let Some(view) = NetworkView::load(&inner.store, record.network)? else { return Ok(None) };
        let Some(sync) = inner.sync.get(&node) else { return Ok(None) };
        let netmap = view.compile(&view.access(), node, &sync.relations, &*inner);
        Ok(netmap.map(|netmap| Netmap { version: sync.state.version, ..netmap }))
    }

    /// 做到期的后台工作：延后的下发、不再等迟迟不确认的节点、清理过期的令牌和冷却记录。
    /// 返回下一次最晚什么时候再调用；有新的延后工作时 [`Controller::wait_for_work`] 会提前返回。
    ///
    /// # Errors
    ///
    /// 有工作读写存储失败（[`TickFailed`]）。别的工作照样做了，出错的留着下次再做；下一次的时刻也照样算出来了。
    pub fn tick(&self) -> Result<Option<Instant>, TickFailed> {
        let mut inner = self.lock();
        let wall = inner.clock.now();
        let next = inner.tick(Instant::now(), wall);
        // 到点的 `roll_out` 可能要了新的包，叫醒取包的任务。`wake` 不用叫：调用这里的就是后台任务，它拿着返回的时刻接着去等。
        self.wake_fetcher_if_needed(&inner);
        next
    }

    /// 等到有新的延后工作。
    pub async fn wait_for_work(&self) {
        self.wake.notified().await;
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("controller state mutex poisoned")
    }

    /// 不读写存储的节点消息用到的状态（见 [`switchboard`]）。不拿大锁。
    fn switchboard(&self) -> MutexGuard<'_, Switchboard> {
        self.switchboard.lock().expect("switchboard mutex poisoned")
    }

    /// 不拿大锁，在 [`Switchboard`] 上执行 `f`。其间因消息无法放入发送队列而去掉了连接时，唤醒后台任务将这些节点记为离线：
    /// `Inner::live` 只能在持有大锁时修改（见 `Inner::drop_lost_sessions`）。
    fn on_switchboard<T>(&self, f: impl FnOnce(&mut Switchboard) -> T) -> T {
        let mut switchboard = self.switchboard();
        let value = f(&mut switchboard);
        if switchboard.take_lost() {
            self.wake.notify_one();
        }
        value
    }

    /// 还没有别人拿着这个 controller 的时候直接改它里面的东西，给 `with_…` 这几个装配用的方法用。
    fn inner_mut(&mut self) -> &mut Inner {
        self.inner.get_mut().expect("controller state mutex poisoned")
    }

    /// 操作留下了要后台任务接着做的事时叫醒它：有延后的下发，有节点欠着确认（要有人盯着它是不是等得太久），
    /// 或者有 relay 更新完在等站稳。有包要取时另外叫醒管发布的后台任务。
    pub(crate) fn wake_if_needed(&self, inner: &Inner) {
        if !inner.dirty.is_empty()
            || !inner.no_udp_dirty.is_empty()
            || inner.sync.values().any(NodeSync::is_waiting)
            || inner.updates.next_rollout.is_some()
            || !inner.diag.is_idle()
        {
            self.wake.notify_one();
        }
        self.wake_fetcher_if_needed(inner);
    }

    /// 有包要取时叫醒管发布的后台任务。
    fn wake_fetcher_if_needed(&self, inner: &Inner) {
        if inner.updates.packages.values().any(|package| *package == update::Package::Wanted) {
            self.release_wake.notify_one();
        }
    }

    /// 测试用：持有 controller 的锁直到返回值被丢弃，模拟一次卡在数据库上的操作。
    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    #[must_use = "丢弃返回值即释放锁"]
    pub fn stall(&self) -> impl Sized + '_ {
        self.lock()
    }

    #[cfg(test)]
    pub(crate) fn advance_clock(&self, secs: u64) {
        self.lock().clock.advance(secs);
    }
}

impl Inner {
    /// 不读写存储的节点消息用到的状态（见 [`switchboard`]）。拿着它时不读写存储，也不再去拿别的锁。
    pub(crate) fn switchboard(&self) -> MutexGuard<'_, Switchboard> {
        self.switchboard.lock().expect("switchboard mutex poisoned")
    }

    pub(crate) fn require_network(&self, id: NetworkId) -> Result<NetworkRecord, Error> {
        self.store.network(id)?.ok_or(Error::NotFound(Entity::Network))
    }

    /// 找一个节点，并且它必须属于 `network`：别的网络的节点在这里等于不存在。
    pub(crate) fn require_node(&self, network: NetworkId, id: NodeId) -> Result<NodeRecord, Error> {
        self.store.node(id)?.filter(|node| node.network == network).ok_or(Error::NotFound(Entity::Node))
    }

    pub(crate) fn is_online(&self, node: NodeId) -> bool {
        self.live.contains_key(&node)
    }

    pub(crate) fn next_conn(&mut self) -> u64 {
        self.next_conn += 1;
        self.next_conn
    }

    /// 发给节点的查询的编号。
    pub(crate) fn next_request(&mut self) -> u64 {
        self.next_request += 1;
        self.next_request
    }

    /// 网络里每个 relay 被在线的节点连上的情况（[`ReachIndex`]）。手上已经有全部节点的记录时直接用 [`ReachIndex::new`]。
    pub(crate) fn reach_index(&self, network: NetworkId) -> Result<ReachIndex, Error> {
        let nodes = self.store.nodes(network)?;
        Ok(ReachIndex::new(&nodes, |id| self.is_online(id)))
    }

    /// 管理 API 里的节点：存储里的记录，加上它现在在不在线、netmap 发到了第几版。
    /// `groups` 是这个网络的全部分组（[`Store::groups`] 的顺序），用来写出它所在分组的名字；`reach` 是这个网络的 [`ReachIndex`]。
    pub(crate) fn node_view(
        &self,
        network: &NetworkRecord,
        groups: &[GroupRecord],
        record: &NodeRecord,
        now: Timestamp,
        reach: &ReachIndex,
    ) -> Node {
        let online = self.is_online(record.id);
        // 只是注册时连上过（`i3t join`）不算在线过：节点真的跑起来连上了才有"最近在线"。
        let running = self.live.get(&record.id).is_some_and(|live| !live.enrolling);
        let state = self.sync.get(&record.id).map_or(record.netmap, |sync| sync.state);
        let egress = relay_reach::egress_ip(record);
        Node {
            id: record.id,
            network: record.network,
            key: record.key,
            name: record.name.clone(),
            fqdn: format!("{}.{}", record.name, network.domain()),
            virtual_ip: record.virtual_ip,
            groups: groups.iter().filter(|group| record.groups.contains(&group.id)).map(GroupRecord::to_ref).collect(),
            declared: record.declared,
            forward_target: record.forward_target,
            relay: record.relay.as_ref().map(|settings| RelayView {
                addresses: node_addresses::relay_addresses(record, network.cidr),
                bandwidth_mbps: settings.bandwidth_mbps,
                reach: reach.of(record.id),
                users: self.live.get(&record.id).and_then(|live| live.relay_use.clone()),
            }),
            exit: record.exit.clone(),
            dial_out_only: record.dial_out_only,
            routing: record.routing,
            reach: record.reach,
            pinned_relays: record.pinned_relays.clone(),
            profile: record.profile,
            platform: record.platform.clone(),
            version: record.version.clone(),
            online,
            last_seen_at: if running { Some(now) } else { record.last_seen_at },
            created_at: record.created_at,
            netmap_version: state.version,
            sent_version: state.sent,
            acked_version: state.acked,
            hostname: record.hostname.clone(),
            auto_update: record.auto_update,
            update: self.node_update(record),
            attached: record.attached.clone(),
            country: egress.and_then(crate::geo::country),
            egress_ip: egress,
            warnings: node_addresses::warnings(record, network.cidr)
                .into_iter()
                .chain(record.relay.as_ref().and_then(|_| reach.warning(record.id)))
                .collect(),
            no_udp: self.no_udp(record.id),
        }
    }

    fn tick(&mut self, now: Instant, wall: Timestamp) -> Result<Option<Instant>, TickFailed> {
        let mut failures = Failures::default();
        let work = self.tick_work(now, wall, &mut failures);
        // 时间序列不跟着别的工作出错停下：它要按时切段，不然这期间上报的数都算进上一段。它写不进存储时自己隔一会儿再试。
        let stats = failures.keep(self.stats_tick(now, wall).map(Some));
        failures.into_tick(now, work.into_iter().chain(stats).min())
    }

    /// 时间序列以外的后台工作。返回下一次要做的时刻，出的错记进 `failures`。
    ///
    /// 一样工作出错不耽误后面的：每一样出错时都自己留着下次再做（排着的重算、要重新看谁用不了 UDP 的网络、`next_rollout`），
    /// 别的工作要它回来的时刻照样算，调用方过一会儿再来（见 [`Failures::into_tick`]）。
    ///
    /// 只有整个数据库都读写不了时（连不上、只读了、盘满了）例外：后面不急的清理、存测试结果、开始矩阵里排着的测试这一轮不做，
    /// 退避期间（见 [`Inner::flush_after`]）的每一轮也都不做。它们每写一次存储都要拿着 controller 的锁等满一次超时，
    /// 所有连接和管理请求都被拖住；退避期间不做，是因为排上重试的重算刚叫醒了后台任务，它马上就会再来一轮。
    fn tick_work(&mut self, now: Instant, wall: Timestamp, failures: &mut Failures) -> Option<Instant> {
        self.drop_lost_sessions();
        self.give_up_on_slow_acks(now);
        let unsettled = failures.keep(self.settle_commits(now));
        let no_udp = self.no_udp_tick(now, failures);
        let next = self.flush_due(now, failures);
        // 下发、撤回更新指令只读存储，照样做：该撤回的（比如管理员刚关掉了自动更新）不该等数据库。
        if self.updates.next_rollout.is_some_and(|at| at <= now) {
            failures.keep(self.roll_out_in_background());
        }
        let backing_off = failures.database_wide || self.flush_after.is_some_and(|after| now < after);
        if !backing_off && self.last_purge.is_none_or(|last| now.duration_since(last) >= PURGE_INTERVAL) {
            self.last_purge = Some(now);
            // 两张表各清各的：一张出错不耽误另一张。
            failures.keep(self.store.purge_expired_tokens(wall).map(drop).map_err(Error::from));
            if !failures.database_wide {
                failures.keep(self.store.purge_cooldowns(wall).map(drop).map_err(Error::from));
            }
        }
        // 不管是哪一样遇到的，都退避一会儿：重算也先不碰数据库。
        if failures.database_wide {
            self.back_off();
        }
        // 还有节点欠着确认时，隔一会儿要回来看它们是不是等得太久了。
        let waiting = self.sync.values().any(NodeSync::is_waiting).then(|| now + self.timing.ack_timeout.min(SWEEP_INTERVAL));
        let tests = if backing_off || failures.database_wide {
            // 测试结果这一轮不存，到点了的测试的结果照样先定下来：不然迟到的上报会把超时的测试记成做完了。
            self.time_out_tests(now);
            None
        } else {
            self.tests_tick(now)
        };
        [next, no_udp, waiting, self.updates.next_rollout, tests, unsettled].into_iter().flatten().min()
    }
}

/// 后台的一轮里有工作出了错（[`Controller::tick`]）。别的工作照样做了，出错的留着下次再做。
#[derive(Debug)]
pub struct TickFailed {
    /// 出的错，先出的在前，至少有一个。
    pub errors: Vec<Error>,
    /// 下一次最晚什么时候再来：别的工作要它回来的时刻照样算在里面，最晚是出错的工作过一会儿再试的时候。
    pub next: Instant,
}

/// 一连做了好几样工作、每一样都可能出错时，记下出了什么错。
#[derive(Default)]
pub(crate) struct Failures {
    /// 出的错，先出的在前。
    errors: Vec<Error>,
    /// 出过整个数据库都读写不了的错（连不上、只读了、盘满了）：后面要写存储的不急的事就不去试了。
    database_wide: bool,
}

impl Failures {
    /// 记下一样工作的结果，出错时交回默认值。
    fn keep<T: Default>(&mut self, outcome: Result<T, Error>) -> T {
        outcome.unwrap_or_else(|err| {
            self.database_wide |= err.is_database_wide();
            self.errors.push(err);
            T::default()
        })
    }

    /// 第一个错误留给调用方，后面的打日志：调用方只拿得到一个，不然就看不到了。
    fn into_result(self) -> Result<(), Error> {
        let mut errors = self.errors.into_iter();
        let first = errors.next();
        for err in errors {
            tracing::error!("同时还出了一个错，稍后再试：{}", error_chain(&err));
        }
        first.map_or(Ok(()), Err)
    }

    /// 和 [`Self::into_result`] 一样，只是后面的错误只打在 debug 里：后台每一轮都可能再碰上它们，
    /// 后台的错误日志由调用方限着频，见 [`Self::into_tick`]。
    fn into_first(self) -> Result<(), Error> {
        let mut errors = self.errors.into_iter();
        let first = errors.next();
        for err in errors {
            tracing::debug!("同时还出了一个错，稍后再试：{}", error_chain(&err));
        }
        first.map_or(Ok(()), Err)
    }

    /// 后台的一轮做完了，`next` 是各样工作要它回来的时刻。出了错时错误都交给调用方（它来决定打多少日志），
    /// 并且最晚过 [`TICK_RETRY`] 再来：出错的工作有的自己排了再试的时刻（重算、更新指令），有的没有
    /// （要重新看谁用不了 UDP 的网络、照数据库补齐），没排的就等这一次。
    fn into_tick(self, now: Instant, next: Option<Instant>) -> Result<Option<Instant>, TickFailed> {
        if self.errors.is_empty() {
            return Ok(next);
        }
        // 从做完的时候算：读写存储可能等了很久（比如连数据库等到了超时），从开始算的话这时已经到点了。
        let retry = Instant::now().max(now) + TICK_RETRY;
        Err(TickFailed { errors: self.errors, next: next.map_or(retry, |next| next.min(retry)) })
    }
}

/// 前后两样都做了的工作：交回第一个错误，两样都出错时后一个打日志。
pub(crate) fn first_failure(first: Result<(), Error>, then: Result<(), Error>) -> Result<(), Error> {
    let mut failures = Failures::default();
    failures.keep(first);
    failures.keep(then);
    failures.into_result()
}

/// 过期的令牌和冷却记录多久清一次。它们过期之后本来就不起作用，清理只是不让表一直长。
const PURGE_INTERVAL: Duration = Duration::from_secs(60);
/// 有节点欠着确认时多久查一次超时。
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// 后台的一轮有工作出了错时，最晚过多久再来一轮。
const TICK_RETRY: Duration = Duration::from_secs(1);

/// `主机:端口` 里的主机，是 IP 地址的话。回环和全零的地址对别的机器没有用，不算。
fn host_ip(public_addr: &str) -> Option<IpAddr> {
    let (host, _port) = public_addr.rsplit_once(':')?;
    let ip: IpAddr = host.trim_start_matches('[').trim_end_matches(']').parse().ok()?;
    let ip = ip.to_canonical();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// 操作记录里一个开关现在是开还是关。
pub(crate) const fn switch(on: bool) -> &'static str {
    if on { "开" } else { "关" }
}

/// 操作记录里的一串名字：用顿号连起来，一个都没有时写"无"。
pub(crate) fn listed<T: std::fmt::Display>(items: impl Iterator<Item = T>) -> String {
    let items: Vec<String> = items.map(|item| item.to_string()).collect();
    if items.is_empty() { "无".to_owned() } else { items.join("、") }
}

/// 管理 API 里的计数都是 `u32`。真的数不下时停在最大值，不回绕。
pub(crate) fn count(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

/// 墙上时钟。测试里可以往前拨，用来试过期和冷却期。
#[derive(Debug, Default)]
pub(crate) struct Clock {
    #[cfg(test)]
    skew: std::sync::atomic::AtomicU64,
}

impl Clock {
    pub(crate) fn now(&self) -> Timestamp {
        // 系统时钟被拨到 1970 年之前时当作 0：时间戳只用来比较先后和展示，不值得为此让操作失败。
        let system = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
        #[cfg(test)]
        let system = system + self.skew.load(std::sync::atomic::Ordering::Relaxed);
        system
    }

    #[cfg(test)]
    fn advance(&self, secs: u64) {
        self.skew.fetch_add(secs, std::sync::atomic::Ordering::Relaxed);
    }
}

/// 数据库里记着的管理令牌的哈希。
pub(crate) fn admin_token_hash(store: &Store) -> Result<Option<[u8; DIGEST_LEN]>, StoreError> {
    Ok(store.meta(ADMIN_TOKEN_META)?.and_then(|hash| <[u8; DIGEST_LEN]>::try_from(hash).ok()))
}

/// 一个新的管理令牌：明文，和存进数据库的哈希。
fn new_admin_token() -> Result<(String, [u8; DIGEST_LEN]), Error> {
    let token = secret::generate()?;
    let hash = secret::sha256(token.as_bytes());
    Ok((token, hash))
}

/// 换上哈希是 `hash` 的管理令牌，并记一条操作。要放在一个事务里（[`Store::atomically`]）：记不下来的话原来的令牌
/// 照旧有效，不会出现"原来的已经作废、新的却没有交到调用方手上"。
fn record_admin_token(store: &Store, hash: &[u8; DIGEST_LEN], now: Timestamp) -> Result<(), StoreError> {
    store.set_meta(ADMIN_TOKEN_META, hash)?;
    store.log(now, None, action::ADMIN_TOKEN, "生成了新的管理令牌", serde_json::json!({}))
}

/// 数据目录里一定要有的文件。不在时说这不是一个数据目录。
fn required(dir: &Path, name: &'static str) -> Result<PathBuf, Error> {
    let path = dir.join(name);
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(path),
        Err(source) if source.kind() != std::io::ErrorKind::NotFound => Err(Error::Io { path, source }),
        Ok(_) | Err(_) => Err(Error::NotDataDir { dir: dir.to_owned(), missing: name }),
    }
}

/// 数据目录里的密钥，核对过它就是这个库的 controller 的那一把。
///
/// | 数据目录里 | 库里记着 | |
/// |---|---|---|
/// | 有密钥 | 同一把 | 平时的启动 |
/// | 有密钥 | 没有记 | 这个库头一次有 controller 启动（新装，或者数据目录是从早先的版本留下来的）：记下它 |
/// | 有密钥 | 另一把 | 数据目录和库对不上：不开 |
/// | 没有 | 没有记 | 新装：生成一把，记下它 |
/// | 没有 | 记着一把 | 库是一个已有的 controller 的，它的密钥没有带过来：不开，更不生成新的。节点认的是原来那一把，
/// 换了它，已经加入的节点一个都连不回来 |
fn bound_key(store: &Store, path: &Path) -> Result<NodeKey, Error> {
    let recorded = store.meta(CONTROLLER_KEY_META)?;
    let key = match (read_key(path)?, &recorded) {
        (Some(key), _) => key,
        (None, Some(_)) => return Err(Error::KeyMissing { path: path.to_owned() }),
        (None, None) => create_key(path)?,
    };
    let public = key.public();
    let recorded = match recorded {
        Some(recorded) => recorded,
        // 两个数据目录同时头一次连上同一个空库的话，只有一个记得上：另一个在这里读到的是别人的那一把。
        None => store.set_meta_once(CONTROLLER_KEY_META, public.as_bytes())?,
    };
    if recorded != public.as_bytes() {
        return Err(Error::KeyMismatch { path: path.to_owned() });
    }
    Ok(key)
}

fn read_key(path: &Path) -> Result<Option<NodeKey>, Error> {
    match fs::read_to_string(path) {
        Ok(pem) => NodeKey::from_pem(&pem).map(Some).map_err(|source| Error::Key { path: path.to_owned(), source }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Io { path: path.to_owned(), source }),
    }
}

fn create_key(path: &Path) -> Result<NodeKey, Error> {
    let key = NodeKey::generate().map_err(Error::KeyGeneration)?;
    create_private_file(path)
        .and_then(|file| write_synced(file, key.to_pem().as_bytes()))
        .map_err(|source| Error::Io { path: path.to_owned(), source })?;
    tracing::info!(path = %path.display(), public = %key.public(), "生成了 controller 的密钥");
    Ok(key)
}

/// 新建一个只有属主可读的文件，已经有了就失败，不覆盖。密钥用它。
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    // 别的平台靠数据目录本身的权限。
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, PRIVATE_MODE);
    options.open(path)
}

/// 只有属主可读写。
#[cfg(unix)]
const PRIVATE_MODE: u32 = 0o600;

/// 写完并且落盘之后才算写好。
fn write_synced(mut file: fs::File, content: &[u8]) -> std::io::Result<()> {
    file.write_all(content)?;
    file.sync_all()
}
