//! controller 的核心：存储之上的全部规则，和每个节点的 netmap 的下发。
//!
//! [`Controller`] 的方法都是同步的，内部只有一把锁：一次操作要么完整地做完（写存储、重算受影响的 netmap、
//! 放进各个节点的发送队列），要么不做。节点协议和管理 API 只是它的两个入口。
//!
//! 方法里有数据库读写，重算一个大网络也要花时间，所以异步代码要经 `spawn_blocking` 调用它们。

mod address;
mod backup;
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
use i3t_model::control::{
    ForwardReport, LaneReport, ListenerReport, PeerUse, PerformanceReport, ProxyReport, RelayUse, ToNode, VnetReport,
};
use i3t_model::update::{UpdateStatus, Version};
use i3t_proto::{NodeId, PublicKey};
use tokio::sync::{Notify, mpsc};

use crate::error::{Entity, Error, error_chain};
use crate::gate::Throttle;
use crate::netmap::NetworkView;
use crate::node_server::{PENDING, VerificationQuota};
use crate::relay_reach::{self, ReachIndex};
use crate::store::{DIGEST_LEN, GroupRecord, LogFilter, NetworkRecord, NodeRecord, Store};
use crate::sync::NodeSync;
use crate::{node_addresses, secret};

pub use backup::{Backup, BackupFile};
pub use protocol::Admitted;
pub(crate) use publish::Seeds;
pub use routes::RouteAnswers;

/// 节点协议在 TLS 上的 ALPN。
pub const ALPN: &[u8] = b"i3t-ctl/1";

const KEY_FILE: &str = "controller.key";
const DATABASE_FILE: &str = "controller.db";
const ADMIN_TOKEN_META: &str = "admin_token_hash";

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
    /// 管理令牌的哈希。每个管理请求都要查它，所以不放在大锁里。
    admin_token: Mutex<Option<[u8; DIGEST_LEN]>>,
    inner: Mutex<Inner>,
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
    /// 各个节点最近上报的路由表。节点离线之后留着，界面上显示成过期的；controller 重启就没有了。
    pub(crate) routes: BTreeMap<NodeId, routes::Reported>,
    /// 出口和用出口的节点报的计数，算健康和交叉核对用。节点离线之后留着；controller 重启就没有了。
    pub(crate) usage: usage::Usage,
    /// 已经发给节点、还在等回答的路由查询。
    pub(crate) route_queries: BTreeMap<u64, routes::PendingQuery>,
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
    pub(crate) outbox: mpsc::Sender<ToNode>,
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
    /// 打开数据目录：第一次启动时在里面生成 controller 的密钥、数据库和管理令牌。
    ///
    /// `public_addr` 是节点连 controller 用的 `主机:端口`，会写进每个注册令牌。
    ///
    /// # Errors
    ///
    /// 目录建不了、密钥文件或数据库读不出来。
    pub fn open(data_dir: &Path, public_addr: String) -> Result<Opened, Error> {
        fs::create_dir_all(data_dir).map_err(|source| Error::Io { path: data_dir.to_owned(), source })?;
        let key = load_or_create_key(&data_dir.join(KEY_FILE))?;
        let database = data_dir.join(DATABASE_FILE);
        keep_private(&database)?;
        let store = Store::open(&database)?;
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
    pub fn new(store: Store, key: NodeKey, public_addr: String, timing: Timing) -> Result<Self, Error> {
        let admin_token = store.meta(ADMIN_TOKEN_META)?.and_then(|hash| <[u8; DIGEST_LEN]>::try_from(hash).ok());
        let version: Version = env!("CARGO_PKG_VERSION").parse().expect("Cargo 保证包的版本号是合法的语义化版本");
        let updates = update::Updates::load(&store, version)?;
        let wake = Arc::new(Notify::new());
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
            routes: BTreeMap::new(),
            usage: usage::Usage::default(),
            route_queries: BTreeMap::new(),
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
            admin_token: Mutex::new(admin_token),
            inner: Mutex::new(inner),
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
        let inner = self.lock();
        let (token, hash) = store_admin_token(&inner.store, inner.clock.now())?;
        *self.admin_token.lock().expect("admin token mutex poisoned") = Some(hash);
        Ok(token)
    }

    /// 给数据目录 `data_dir` 里的 controller 生成一个新的管理令牌，原来的随即作废。返回的明文只有这一次能拿到。
    ///
    /// 换的是数据库里管理令牌的哈希，另记一条操作；不建 controller，所以不需要对外地址。
    /// 正运行着的 controller 记着原来的哈希，不知道令牌换了，所以要在它停着时做。
    ///
    /// 和 [`Controller::open`] 一样：密钥读不懂的话不做；数据库的权限会收紧，表结构会升到这个程序的版本，
    /// 之后更旧的程序就打不开它了。和它不一样的是这里不建任何东西：`data_dir` 写错了的话不会在那里生成一个新的空 controller。
    ///
    /// # Errors
    ///
    /// `data_dir` 里没有密钥或者数据库（[`Error::NotDataDir`]），密钥读不懂，读写数据库失败，或者随机数源不可用。
    pub fn reset_admin_token(data_dir: &Path) -> Result<String, Error> {
        let key = required(data_dir, KEY_FILE)?;
        let database = required(data_dir, DATABASE_FILE)?;
        // 密钥读不懂的话 controller 启动不了，换了令牌也用不上：现在就说，别等到启动时。
        let pem = fs::read_to_string(&key).map_err(|source| Error::Io { path: key.clone(), source })?;
        NodeKey::from_pem(&pem).map_err(|source| Error::Key { path: key, source })?;
        keep_private(&database)?;
        let store = Store::open(&database)?;
        let (token, _) = store_admin_token(&store, Clock::default().now())?;
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
    /// 读写存储失败。到期的工作留在队列里，下次再试。
    pub fn tick(&self) -> Result<Option<Instant>, Error> {
        let mut inner = self.lock();
        let wall = inner.clock.now();
        inner.tick(Instant::now(), wall)
    }

    /// 等到有新的延后工作。
    pub async fn wait_for_work(&self) {
        self.wake.notified().await;
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("controller state mutex poisoned")
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
        if inner.updates.packages.values().any(|package| *package == update::Package::Wanted) {
            self.release_wake.notify_one();
        }
    }

    #[cfg(test)]
    pub(crate) fn advance_clock(&self, secs: u64) {
        self.lock().clock.advance(secs);
    }
}

impl Inner {
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

    fn tick(&mut self, now: Instant, wall: Timestamp) -> Result<Option<Instant>, Error> {
        let work = self.tick_work(now, wall);
        // 时间序列不跟着别的工作出错停下：它要按时切段，不然这期间上报的数都算进上一段。它写不进存储时自己隔一会儿再试。
        let stats = self.stats_tick(now, wall);
        match (work, stats) {
            (Ok(next), Ok(stats)) => Ok(next.into_iter().chain([stats]).min()),
            (Err(err), Ok(_)) | (Ok(_), Err(err)) => Err(err),
            (Err(err), Err(stats)) => {
                tracing::error!("时间序列出错，稍后再试：{}", error_chain(&stats));
                Err(err)
            }
        }
    }

    /// 时间序列以外的后台工作。返回下一次要做的时刻。
    fn tick_work(&mut self, now: Instant, wall: Timestamp) -> Result<Option<Instant>, Error> {
        self.give_up_on_slow_acks(now);
        let no_udp = self.no_udp_tick(now)?;
        let next = self.flush_due(now)?;
        if self.updates.next_rollout.is_some_and(|at| at <= now) {
            self.roll_out()?;
        }
        if self.last_purge.is_none_or(|last| now.duration_since(last) >= PURGE_INTERVAL) {
            self.last_purge = Some(now);
            self.store.purge_expired_tokens(wall)?;
            self.store.purge_cooldowns(wall)?;
        }
        // 还有节点欠着确认时，隔一会儿要回来看它们是不是等得太久了。
        let waiting = self.sync.values().any(NodeSync::is_waiting).then(|| now + self.timing.ack_timeout.min(SWEEP_INTERVAL));
        let tests = self.tests_tick(now);
        Ok([next, no_udp, waiting, self.updates.next_rollout, tests].into_iter().flatten().min())
    }
}

/// 过期的令牌和冷却记录多久清一次。它们过期之后本来就不起作用，清理只是不让表一直长。
const PURGE_INTERVAL: Duration = Duration::from_secs(60);
/// 有节点欠着确认时多久查一次超时。
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

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

/// 生成一个新的管理令牌，把它的哈希写进存储，记一条操作。返回明文和哈希。
fn store_admin_token(store: &Store, now: Timestamp) -> Result<(String, [u8; DIGEST_LEN]), Error> {
    let token = secret::generate()?;
    let hash = secret::sha256(token.as_bytes());
    store.set_meta(ADMIN_TOKEN_META, &hash)?;
    store.log(now, None, action::ADMIN_TOKEN, "生成了新的管理令牌", serde_json::json!({}))?;
    Ok((token, hash))
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

fn load_or_create_key(path: &Path) -> Result<NodeKey, Error> {
    match fs::read_to_string(path) {
        Ok(pem) => NodeKey::from_pem(&pem).map_err(|source| Error::Key { path: path.to_owned(), source }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let key = NodeKey::generate().map_err(Error::KeyGeneration)?;
            create_private_file(path)
                .and_then(|file| write_synced(file, key.to_pem().as_bytes()))
                .map_err(|source| Error::Io { path: path.to_owned(), source })?;
            tracing::info!(path = %path.display(), public = %key.public(), "生成了 controller 的密钥");
            Ok(key)
        }
        Err(source) => Err(Error::Io { path: path.to_owned(), source }),
    }
}

/// 新建一个只有属主可读的文件，已经有了就失败，不覆盖。密钥、数据库和它们的备份都用它，所以权限处处一样。
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

/// 数据库只有属主可读：里面有令牌和凭据的摘要、每个节点的地址。
///
/// 还没有数据库时先建一个空文件（SQLite 肯在空文件里建库），已经有了就把权限收紧，早先的版本建的是谁都可读的。
/// 旁边的 `-wal`、`-shm` 是 SQLite 照主文件的权限建的，上次没有正常退出留下来的也一起收紧。
fn keep_private(database: &Path) -> Result<(), Error> {
    match create_private_file(database) {
        Ok(_) => return Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(Error::Io { path: database.to_owned(), source }),
    }
    #[cfg(unix)]
    for suffix in ["", "-wal", "-shm"] {
        use std::os::unix::fs::PermissionsExt;

        let mut path = database.as_os_str().to_owned();
        path.push(suffix);
        let path = PathBuf::from(path);
        match fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_MODE)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(Error::Io { path, source }),
        }
    }
    Ok(())
}

/// 写完并且落盘之后才算写好。
fn write_synced(mut file: fs::File, content: &[u8]) -> std::io::Result<()> {
    file.write_all(content)?;
    file.sync_all()
}
