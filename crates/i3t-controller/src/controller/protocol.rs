//! 节点协议的各个消息在 controller 这一侧的处理。
//!
//! 这里不碰 socket：连接由 [`crate::node_server`] 管，它把收到的消息交到这里，从发送队列里取要发的消息。
//! 节点是谁由连接的 TLS 握手确定，所以这里的入口拿到的公钥和节点编号都是认证过的。

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use i3t_model::admin::{LogRef, action};
use i3t_model::control::{
    Hello, MAX_LOCAL_ADDRESSES, MAX_PACKAGE_CHUNK, MAX_PEER_USE, MAX_RELAY_USERS, MAX_REPORTED_SWITCHES, RelayTry, Report, RouteSwitch,
    ToController, ToNode, VnetReport, VnetState,
};
use i3t_model::netmap::Attachment;
use i3t_model::update::{Platform, Version};
use i3t_proto::{NodeId, PublicKey};
use serde_json::json;
use tokio::sync::mpsc;

use super::switchboard::{Answer, Undelivered};
use super::usage::UsageReport;
use super::{Controller, Inner, Live, Seeds, first_failure};
use crate::error::{Entity, Error, Rejection, error_chain};
use crate::netmap::{MAX_ENDPOINTS, VnetFacts};
use crate::store::{NewSwitch, NodeRecord};
use crate::{node_addresses, relay_reach};

/// 单个节点的挂靠关系最多保留的 relay 数量。默认仅挂靠 2 个；管理员固定与 controller 分配的共享挂靠合计亦远低于此上限。
const MAX_ATTACHMENTS: usize = 16;
/// 节点自报的版本号、平台最长留这么多个字符。
const MAX_HELLO_TEXT: usize = 64;
/// 节点自报的主机名最长留这么多个字符。域名最长就是这么长。
const MAX_HOSTNAME: usize = 253;
/// 到 relay 的延迟变化不超过这个数（毫秒）、也不超过原来的四分之一时，不算变化。
/// 延迟每次测出来都差几毫秒，不这样就每次上报都要给全部对端重发 netmap。
const RTT_NOISE_MS: u32 = 10;

impl VnetFacts for Inner {
    fn lacks_vnet(&self, node: NodeId) -> bool {
        self.no_vnet.contains(&node)
    }
}

/// [`Controller::handle`] 处理一条消息要等什么（[`Controller::waits`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waits {
    /// 什么都不等：只拿一把很短的锁（转发信令、交回查询的回答），可以直接在异步任务里处理。
    Nothing,
    /// 读文件（取更新包），不拿 controller 的锁。
    File,
    /// 拿 controller 的锁，可能要等数据库。
    Store,
}

/// 一条被接受的连接：哪个节点，第几条连接。之后这条连接上的消息都带着它交进来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    pub node: NodeId,
    pub(crate) conn: u64,
}

impl Controller {
    /// 已经注册的节点连上来报到。`key` 是它在 TLS 握手里证明过的公钥。
    ///
    /// 成功时节点已经登记为在线（之前的连接被顶替），当前的 netmap 已经在 `outbox` 里。
    ///
    /// # Errors
    ///
    /// 这把公钥没有注册。原因可以原样告诉节点。
    pub fn hello(&self, key: PublicKey, hello: &Hello, remote: IpAddr, outbox: mpsc::Sender<ToNode>) -> Result<Admitted, Rejection> {
        let mut inner = self.lock();
        let known = inner.store.node_by_key(&key).map_err(Error::from);
        let outcome = match known {
            Ok(Some(node)) => inner.admit(node, Joined { hello, remote, outbox, enrolling: false }),
            Ok(None) => {
                if let Some(suppressed) = self.refusal_log.allow() {
                    tracing::warn!(key = ?key, %remote, suppressed, "拒绝连接：这把公钥没有注册");
                }
                return Err(Rejection::UnknownKey);
            }
            Err(err) => Err(err),
        };
        self.wake_if_needed(&inner);
        outcome.map_err(|err| {
            if let Some(suppressed) = self.error_log_allowance(&err) {
                tracing::error!(key = ?key, %remote, suppressed, "处理节点报到时出错：{}", error_chain(&err));
            }
            Rejection::Internal
        })
    }

    /// 处理一条已经被接受的连接上收到的消息。连接已经被顶替、或者节点已经被删掉时，消息被忽略。
    ///
    /// 不读写存储的消息（[`Controller::waits`] 不是 [`Waits::Store`]）不拿 controller 的锁：拿着它的操作可能正在等数据库，
    /// 转发信令、交回查询的回答、给节点更新包不该跟着等（见 [`switchboard`](super::switchboard)）。
    ///
    /// # Errors
    ///
    /// 读写存储失败。这条消息没有处理完，连接可以继续用。
    pub fn handle(&self, session: Admitted, remote: IpAddr, message: ToController) -> Result<(), Error> {
        match message {
            ToController::PackageRequest { request, version, platform, offset, len } => {
                self.package_request(session, request, &version, &platform, PackageRange { offset, len });
                Ok(())
            }
            ToController::RouteAnswer { request, answer } => {
                self.switchboard().answered(session, request, Answer::Route(answer));
                Ok(())
            }
            ToController::BackboneAnswer { request, rows } => {
                self.switchboard().answered(session, request, Answer::Backbone(rows));
                Ok(())
            }
            ToController::ExitTestAnswer { request, result } => {
                self.switchboard().answered(session, request, Answer::ExitTest(*result));
                Ok(())
            }
            ToController::Signal { to, signal } => {
                self.on_switchboard(|switchboard| switchboard.signal(session, to, signal));
                Ok(())
            }
            ToController::Heartbeat => Ok(()),
            ToController::Enroll { .. } => {
                tracing::debug!(node = %session.node, "忽略已经报到的连接上的注册请求");
                Ok(())
            }
            ToController::TestReport(report) => self.handle_locked(session, |inner| inner.test_reported(session.node, *report)),
            ToController::Report(report) => self.handle_locked(session, |inner| inner.report(session.node, *report)),
            ToController::Ack { version } => self.handle_locked(session, |inner| inner.ack(session.node, version)),
            // 节点的本地声明变了的时候会在同一条连接上再发一次。
            ToController::Hello(hello) => self.handle_locked(session, |inner| inner.rehello(session.node, &hello, remote)),
        }
    }

    /// [`Controller::handle`] 处理这条消息要等什么。节点的连接据此分开处理消息，不读写存储的不排在同一个节点等数据库的消息后面。
    #[must_use]
    pub const fn waits(message: &ToController) -> Waits {
        match message {
            ToController::RouteAnswer { .. }
            | ToController::BackboneAnswer { .. }
            | ToController::ExitTestAnswer { .. }
            | ToController::Signal { .. }
            | ToController::Heartbeat
            | ToController::Enroll { .. } => Waits::Nothing,
            ToController::PackageRequest { .. } => Waits::File,
            ToController::TestReport(_) | ToController::Report(_) | ToController::Ack { .. } | ToController::Hello(_) => Waits::Store,
        }
    }

    /// 拿着 controller 的锁处理一条消息。连接已经被顶替、或者节点已经被删掉时忽略。
    fn handle_locked(&self, session: Admitted, handle: impl FnOnce(&mut Inner) -> Result<(), Error>) -> Result<(), Error> {
        let mut inner = self.lock();
        if inner.live.get(&session.node).is_none_or(|live| live.conn != session.conn) {
            return Ok(());
        }
        let outcome = handle(&mut inner);
        self.wake_if_needed(&inner);
        outcome
    }

    /// 一条连接结束了。它还是这个节点当前的连接时，节点记为离线。
    pub fn disconnect(&self, session: Admitted) {
        let mut inner = self.lock();
        if inner.live.get(&session.node).is_some_and(|live| live.conn == session.conn) {
            tracing::info!(node = %session.node, "节点离线");
            inner.drop_session(session.node);
            self.wake_if_needed(&inner);
        }
    }

    /// controller 对外地址里的主机解析出来的 IP（主机是域名时由后台任务定期解析）。见 [`Inner::observed_endpoint`]。
    ///
    /// # Errors
    ///
    /// 读写存储失败。
    pub fn set_public_host(&self, host: Option<IpAddr>) -> Result<(), Error> {
        let mut inner = self.lock();
        let outcome = inner.set_public_host(host);
        self.wake_if_needed(&inner);
        outcome
    }

    /// 现在在线的节点。
    #[must_use]
    pub fn online_nodes(&self) -> Vec<NodeId> {
        self.lock().live.keys().copied().collect()
    }

    /// 节点要更新包里的一段。包是公开的发布文件，所以只要是已经报到的节点就给，不看它有没有收到过更新指令。
    ///
    /// 不拿 controller 的锁：缓存在哪里、回复放进发送队列都只用到 [`Switchboard`](super::switchboard::Switchboard)，读文件时什么锁都不拿。
    /// 回复无法放入发送队列（节点未及时读取、连接已关闭）时断开节点（见 [`Switchboard::send`](super::switchboard::Switchboard::send)）。
    fn package_request(&self, session: Admitted, request: u64, version: &Version, platform: &Platform, range: PackageRange) {
        let cached = {
            let switchboard = self.switchboard();
            if !switchboard.is_current(session) {
                return;
            }
            switchboard.cached_package(version, platform.as_str())
        };
        let chunk = match cached {
            Some((path, size)) => range.read(&path, size),
            None => Err(format!("controller 未缓存 {version} 版本 {platform} 平台的更新包")),
        };
        let (reply, bytes) = match chunk {
            Ok(data) => {
                let bytes = u64::try_from(data.len()).unwrap_or(u64::MAX);
                (ToNode::PackageChunk { request, data }, bytes)
            }
            Err(reason) => {
                tracing::warn!(node = %session.node, %version, %platform, offset = range.offset, %reason, "无法提供节点请求的更新包片段");
                (ToNode::PackageUnavailable { request, reason }, 0)
            }
        };
        self.on_switchboard(|switchboard| {
            if !switchboard.is_current(session) {
                return;
            }
            match switchboard.send(session.node, reply) {
                Ok(()) => switchboard.package_bytes += bytes,
                Err(Undelivered::Offline) => {}
                Err(undelivered @ (Undelivered::Full | Undelivered::Closed)) => {
                    tracing::warn!(node = %session.node, reason = undelivered.reason(), "断开节点");
                }
            }
        });
    }
}

/// controller 看到的节点地址：这条连接的来源 IP 加上节点自报的 UDP 端口，节点没报端口时是 `None`。
/// 来源是回环地址时换成 controller 对外地址里的主机 `public_host`（见 [`Inner::observed_endpoint`]）。
fn observed_endpoint(public_host: Option<IpAddr>, remote: IpAddr, port: u16) -> Option<SocketAddr> {
    let remote = remote.to_canonical();
    let ip = if remote.is_loopback() { public_host.unwrap_or(remote) } else { remote };
    (port != 0).then(|| SocketAddr::new(ip, port))
}

/// 节点请求的更新包片段范围：起始偏移量与最大字节数。
#[derive(Debug, Clone, Copy)]
struct PackageRange {
    offset: u64,
    len: u32,
}

impl PackageRange {
    /// 从缓存的更新包中读取指定片段。返回数据非空且不超过 [`MAX_PACKAGE_CHUNK`]；读取失败时返回可返回给节点的错误原因。
    fn read(self, path: &Path, size: u64) -> Result<Vec<u8>, String> {
        let wanted = u64::from(self.len.min(MAX_PACKAGE_CHUNK)).min(size.saturating_sub(self.offset));
        if wanted == 0 {
            return Err(format!("请求的偏移量 {} 超出包大小（共 {size} 字节），或请求长度为 0", self.offset));
        }
        let read = || -> std::io::Result<Vec<u8>> {
            let mut file = File::open(path)?;
            file.seek(SeekFrom::Start(self.offset))?;
            let mut data = Vec::with_capacity(usize::try_from(wanted).unwrap_or(0));
            file.take(wanted).read_to_end(&mut data)?;
            Ok(data)
        };
        match read() {
            Ok(data) if !data.is_empty() => Ok(data),
            Ok(_) => Err("缓存中的更新包小于清单声明的大小".to_owned()),
            Err(error) => Err(format!("无法读取缓存中的更新包：{error}")),
        }
    }
}

/// 一条刚连上来、要被接受的连接。
pub(super) struct Joined<'a> {
    pub(super) hello: &'a Hello,
    pub(super) remote: IpAddr,
    pub(super) outbox: mpsc::Sender<ToNode>,
    /// 这是 `i3t join` 注册时的那一条连接：节点只是拿了配置就走，还没有真的跑起来。
    pub(super) enrolling: bool,
}

impl Inner {
    /// 让一个节点上线：记下它的自我介绍，登记连接，发给它当前的 netmap。
    pub(super) fn admit(&mut self, mut node: NodeRecord, joined: Joined<'_>) -> Result<Admitted, Error> {
        let Joined { hello, remote, outbox, enrolling } = joined;
        let seeds = self.apply_hello(&mut node, hello, remote)?;
        let conn = self.next_conn();
        let live = Live {
            conn,
            network: node.network,
            mapping_varies: None,
            flows: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            protocol: hello.protocol,
            update: None,
            order: None,
            enrolling,
            reported_at: None,
            proxies: Vec::new(),
            listeners: Vec::new(),
            forwards: Vec::new(),
            lanes: None,
            performance: None,
            vnet: None,
            throughput_tests: hello.throughput_tests,
            remote,
            port: hello.port,
            peer_use: BTreeMap::new(),
            relay_use: None,
        };
        if self.go_online(node.id, live, outbox).is_some() {
            // 旧连接的发送队列随着被替换掉而关闭，那条连接自己会结束。
            tracing::info!(node = %node.id, "同一个节点的新连接顶替了旧连接");
        }
        tracing::info!(node = %node.id, name = %node.name, %remote, version = %node.version, platform = %node.platform, enrolling, "节点上线");
        let outcome = match self.refresh_reporting(node.network, seeds, Some(node.id)) {
            // 节点自身的 netmap 已下发成功，仅同批次中的其他节点失败（已进入重试队列），不应因此阻止当前节点上线：
            // 否则只要有一个节点持续持久化失败，其余所有节点都将无法上线。「完成」不代表已送达：发送队列对端已关闭
            // 或队列已满时，连接会在下发当下被断开，因此还需确认当前连接仍处于活跃状态。
            Err(unfinished) if unfinished.done.contains(&node.id) && self.live.get(&node.id).is_some_and(|live| live.conn == conn) => {
                tracing::error!(node = %node.id, "节点上线时，同批次部分其他节点的 netmap 下发失败，将稍后重试：{}", error_chain(&unfinished.error));
                Ok(())
            }
            outcome => outcome.map_err(|unfinished| unfinished.error),
        };
        if let Err(err) = outcome {
            // 它没能上线，就不在线：不再等它确认。不然它欠着的确认没人放，`give_up_on_slow_acks` 只看在线的节点。
            self.go_offline(node.id);
            self.stop_waiting_for(node.network, node.id);
            return Err(err);
        }
        // 注册时那一条连接不算"最近在线"：节点真的跑起来、带着 Hello 连上来才算。上线了才记，没上线的不该被记成刚刚在线过；
        // 整个数据库被别的进程锁着时，也就只在重算那里拿着 controller 的锁等一次超时，不是两次。
        // 写入失败仅影响界面展示的「最近在线」（与 `drop_session` 相同），不因此拒绝上线：节点信息已落盘，netmap 也已下发。
        if !enrolling && let Err(err) = self.store.set_node_last_seen(node.id, self.clock.now()) {
            tracing::warn!(node = %node.id, "记录节点最近在线的时间失败：{}", error_chain(&err));
        }
        // 更新的指令不在这里发：要等它的第一次上报，才知道它是带着什么回来的（见 `rollout`）。
        self.relay_is_back(&node);
        Ok(Admitted { node: node.id, conn })
    }

    fn rehello(&mut self, id: NodeId, hello: &Hello, remote: IpAddr) -> Result<(), Error> {
        let Some(mut node) = self.store.node(id)? else { return Ok(()) };
        let seeds = self.apply_hello(&mut node, hello, remote)?;
        if let Some(live) = self.live.get_mut(&id) {
            live.protocol = hello.protocol;
            live.throughput_tests = hello.throughput_tests;
            live.remote = remote;
            live.port = hello.port;
        }
        let refreshed = self.refresh(node.network, seeds, None);
        // 它会不会自己更新可能变了。重算没成也要做：自我介绍已经记下了。
        let rolled = self.roll_out();
        first_failure(refreshed, rolled)
    }

    /// 记下节点的自我介绍。节点撤回了某项声明时，已经启用的那项能力随之关闭。返回因此要重算的节点。
    fn apply_hello(&mut self, node: &mut NodeRecord, hello: &Hello, remote: IpAddr) -> Result<Seeds, Error> {
        let before = node.clone();
        let now = self.clock.now();
        let cidr = self.require_network(node.network)?.cidr;
        let addresses_before = node_addresses::relay_addresses(node, cidr);
        node.declared = hello.declared;
        // 别的节点会去连声明的地址，所以只收一个能连的单播地址。节点自己也查过，这里防的是乱报的节点。
        if let Some(address) = node.declared.relay_address.filter(|address| !node_addresses::declarable(*address, cidr)) {
            tracing::warn!(node = %node.id, %address, "节点声明的 relay 地址不可供其他节点连接，已忽略");
            node.declared.relay_address = None;
        }
        node.platform = clip(&hello.platform);
        node.version = clip(&hello.version);
        node.hostname = hello.hostname.chars().filter(|ch| !ch.is_control()).take(MAX_HOSTNAME).collect();
        node.self_update = hello.self_update;
        // 节点自报的版本号不清它的失败记录，哪怕它说自己已经在跑那个版本（或者更新的）：否则它报一个高版本、
        // 再报回原来的版本，就能把同一次失败报成"新的"，让管理员已经继续的版本再被暂停一次。
        // 已过时的失败记录在管理 API 中不再展示（见 `Inner::node_update`），仅在管理员触发「立即更新」时清除。

        let mut whole_network = false;
        let mut affected = BTreeSet::from([node.id]);
        let mut withdrawn = Vec::new();
        if node.relay.is_some() && !node.declared.relay {
            node.relay = None;
            whole_network = true;
            withdrawn.push((action::NODE_RELAY_WITHDRAWN, "中继"));
        }
        if node.exit.is_some() && !node.declared.exit {
            node.exit = None;
            affected.extend(self.holders_of(node.id));
            withdrawn.push((action::NODE_EXIT_WITHDRAWN, "出口"));
        }
        // 撤回了声明的话节点也变了，所以有撤回时这个一定是真的。
        let declared_changed = *node != before;
        node.observed = self.observed_endpoint(remote, hello.port);
        let observed_changed = node.observed != before.observed;
        // 在同一事务内原子写入：若只写入部分变更即返回（例如能力已关闭但未返回待重算节点集合），
        // 将导致无人触发重算。当没有任何变更时（大多数重连场景）无需开启事务。
        if declared_changed || observed_changed {
            self.store.atomically(|store| {
                for (action, what) in &withdrawn {
                    let detail = format!("节点 {} 撤回了声明，{what}已关闭", node.name);
                    let params = json!({ "node": node.id, "node_name": node.name });
                    store.log_refs(now, Some(node.network), action, &detail, &[LogRef::node(node.id)], params)?;
                }
                if declared_changed {
                    store.update_node(node)?;
                }
                if observed_changed {
                    store.set_node_observed(node.id, node.observed)?;
                }
                Ok::<_, Error>(())
            })?;
        }
        if before.relay.is_some() && node.relay.is_none() {
            tracing::warn!(node = %node.id, name = %node.name, "节点已撤回 relay 能力声明，自动关闭其 relay 功能");
        }
        if before.exit.is_some() && node.exit.is_none() {
            tracing::warn!(node = %node.id, name = %node.name, "节点已撤回出口能力声明，自动关闭其出口功能");
            self.usage.exit_disabled(node.id);
        }
        if observed_changed {
            let holders = self.holders_of(node.id);
            self.defer(node.network, holders, self.timing.report_coalesce);
        }
        // relay 的地址写在全网每个节点的 netmap 里：声明的或者 controller 看到的地址变了，大家都要知道。
        if node.relay.is_some() && node_addresses::relay_addresses(node, cidr) != addresses_before {
            tracing::info!(node = %node.id, name = %node.name, "relay 地址已变更");
            whole_network = true;
        }
        Ok(if whole_network { Seeds::All } else { Seeds::Nodes(affected) })
    }

    /// controller 看到的节点地址：这条连接的来源 IP 加上节点自报的 UDP 端口，节点没报端口时是 `None`。
    ///
    /// 当节点与 controller 位于同一主机并通过回环连接时，回环地址对其他主机无效，改用 controller 对外地址中的主机；
    /// 若该主机为域名且尚未解析成功，则仍保留回环地址以供同机节点使用。
    fn observed_endpoint(&self, remote: IpAddr, port: u16) -> Option<SocketAddr> {
        observed_endpoint(self.public_host, remote, port)
    }

    /// controller 对外地址中的主机已解析或发生变更：同步更新通过回环连接的节点的观测地址。
    ///
    /// 所有回环连接节点在同一事务中批量更新，仅在事务提交后才记录新主机 IP：若中途读写存储失败则全部回滚，主机记录维持旧值，
    /// 保证存储中的地址始终与已记录的主机一致。若逐条更新，中途失败会导致部分节点更新而部分未更新，后续解析出相同 IP 时又会跳过处理。
    pub(super) fn set_public_host(&mut self, host: Option<IpAddr>) -> Result<(), Error> {
        if self.public_host == host {
            return Ok(());
        }
        let looped: Vec<(NodeId, IpAddr, u16, BTreeSet<NodeId>)> = self
            .live
            .iter()
            .filter(|(_, live)| live.remote.to_canonical().is_loopback())
            .map(|(id, live)| (*id, live.remote, live.port, self.holders_of(*id)))
            .collect();
        let changed = self.store.atomically(|store| {
            let mut changed = Vec::new();
            for (id, remote, port, mut affected) in looped {
                let Some(mut node) = store.node(id)? else { continue };
                let cidr = store.network(node.network)?.ok_or(Error::NotFound(Entity::Network))?.cidr;
                let before = node_addresses::relay_addresses(&node, cidr);
                node.observed = observed_endpoint(host, remote, port);
                if node.relay.is_some() && node_addresses::relay_addresses(&node, cidr) != before {
                    affected.extend(store.nodes(node.network)?.into_iter().map(|record| record.id));
                }
                store.set_node_observed(id, node.observed)?;
                changed.push((node.network, affected));
            }
            Ok::<_, Error>(changed)
        })?;
        for (network, affected) in changed {
            self.defer(network, affected, self.timing.report_coalesce);
        }
        tracing::info!(?host, "已解析 controller 对外地址的主机 IP");
        self.public_host = host;
        Ok(())
    }

    fn report(&mut self, id: NodeId, mut report: Report) -> Result<(), Error> {
        // 只依赖内存的部分先记下，存储读写失败时也不丢：上报没有确认，节点不会重发；路由表按增量上报，漏掉一份之后
        // 会一直和节点对不上，之后不带变化的上报还会把它显示成最新的。
        if let Some(live) = self.live.get_mut(&id) {
            live.mapping_varies = report.mapping_varies;
            live.flows = report.flows;
            live.tx_bytes = report.tx_bytes;
            live.rx_bytes = report.rx_bytes;
            live.lanes = report.lanes.as_deref().cloned();
            live.performance = report.performance.as_deref().cloned();
            live.vnet = report.vnet.as_deref().cloned();
            live.peer_use = report.peer_use.iter().take(MAX_PEER_USE).map(|used| (used.peer, *used)).collect();
            live.relay_use = report.relay_use.clone().map(|mut used| {
                used.pairs.truncate(MAX_RELAY_USERS);
                used
            });
        }
        self.routes_reported(id, std::mem::take(&mut report.routes), std::mem::take(&mut report.route_kinds), report.routes_full);

        let Some(node) = self.store.node(id)? else { return Ok(()) };
        self.stats_reported(&node, &report);
        // 换路只记进界面上的历史：无法记录时仍处理这份上报的其余部分（更新进度、relay 探测、端点与挂靠）。其余部分也出错时
        // 交回其余部分的错误；换路的错误只记在调试日志里，不另记一条错误日志：两者多半出于同一个原因（例如数据库只读）。
        let switched = self.switches_reported(&node, &report.switches);
        let applied = self.state_reported(node, report);
        if let (Err(_), Err(err)) = (&applied, &switched) {
            tracing::debug!(node = %id, "记录节点上报的换路失败：{}", error_chain(err));
        }
        applied.and(switched)
    }

    /// 记下上报里的状态：代理与转发、更新进度、挂靠与 relay 探测、虚拟网卡、本地地址、端点。`node` 是这个节点在存储里的记录。
    fn state_reported(&mut self, mut node: NodeRecord, report: Report) -> Result<(), Error> {
        let id = node.id;
        let Report { run, exit, exits, proxies, listeners, forwards, .. } = report;
        self.usage_reported(&node, UsageReport { run, exit, exits, proxies, listeners, forwards });
        let report = Report { exits: Vec::new(), proxies: Vec::new(), listeners: Vec::new(), forwards: Vec::new(), exit: None, ..report };
        if let Some(status) = report.update {
            self.update_reported(&node, status)?;
        }

        // 挂靠关系与 relay 探测结果均需对照本网络的已启用 relay 过滤。统计、变更判断与持久化均使用过滤后的挂靠列表。
        // 当三者均为空时无需查询数据库（此时 `relay_tries_reported` 也是空操作），避免无 relay 网络或纯直连节点每次上报都访问存储。
        let relays = if report.attached.is_empty() && report.relays.is_empty() && node.relay_reach.is_empty() {
            BTreeSet::new()
        } else {
            self.store.relays_in(node.network)?
        };
        let attached = usable_attachments(report.attached, id, &relays);
        self.stats_attached(&node, &attached);
        self.relay_tries_reported(&node, &report.relays, &relays)?;
        self.vnet_reported(&node, report.vnet.as_deref());

        if let Some(local) = report.local_addresses {
            let mut local = local.into_vec();
            local.truncate(MAX_LOCAL_ADDRESSES);
            if node.local_addresses.as_ref() != Some(&local) {
                self.local_addresses_reported(&mut node, local)?;
            }
        }

        let mut endpoints: Vec<SocketAddr> = Vec::with_capacity(report.endpoints.len().min(MAX_ENDPOINTS));
        for endpoint in report.endpoints {
            if endpoints.len() < MAX_ENDPOINTS && !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }

        if same_endpoints(&node.endpoints, &endpoints) && !attachments_differ(&node.attached, &attached) {
            return Ok(());
        }
        tracing::debug!(node = %id, endpoints = endpoints.len(), attached = attached.len(), "节点端点或挂靠关系已变更");
        self.store.set_node_report(id, &endpoints, &attached)?;
        let holders = self.holders_of(id);
        self.defer_report(node.network, holders);
        // 它自己的 netmap 也要重算：它要另外挂靠哪些 relay（`shared_relays`）是按它自己挑的那几个算的。
        // 这一份不算进"别的节点的上报引起的"那条节奏里，不然它会把紧跟着到的对端的挂靠信息推后一个窗口。
        self.defer(node.network, [id], self.timing.report_coalesce);
        Ok(())
    }

    /// 节点报的换路记进历史。只记对端还是这个网络里的节点的；一次最多 [`MAX_REPORTED_SWITCHES`] 条，一起写入（见 [`Store::insert_switches`]）。
    ///
    /// [`Store::insert_switches`]: crate::store::Store::insert_switches
    fn switches_reported(&mut self, node: &NodeRecord, switches: &[RouteSwitch]) -> Result<(), Error> {
        let now = self.clock.now();
        let mut recorded = Vec::new();
        for switch in switches.iter().take(MAX_REPORTED_SWITCHES) {
            if self.store.node(switch.peer)?.is_none_or(|peer| peer.network != node.network) {
                continue;
            }
            recorded.push(NewSwitch {
                network: node.network,
                from: node.id,
                to: switch.peer,
                at: now.saturating_sub(switch.age_secs.into()),
                previous: switch.from.clone(),
                route: switch.to.clone(),
                cause: switch.cause.clone(),
            });
        }
        Ok(self.store.insert_switches(&recorded)?)
    }

    /// 将节点上报的 relay 连通性探测结果合并到持久化记录中。若可达性发生变化，则触发本节点及其对端的 netmap 重算，
    /// 因为节点间是否缺少共同可达 relay 可能随之改变。
    /// `relays` 是它所在网络的 relay。
    fn relay_tries_reported(&mut self, node: &NodeRecord, tries: &[RelayTry], relays: &BTreeSet<NodeId>) -> Result<(), Error> {
        if tries.is_empty() && node.relay_reach.is_empty() {
            return Ok(());
        }
        let Some(merged) = relay_reach::merge(&node.relay_reach, tries, node.id, relays, self.clock.now()) else { return Ok(()) };
        self.store.set_node_relay_reach(node.id, &merged.records)?;
        // 传输协议在 UDP 与 TCP 之间切换不改变可达性，此处不触发重算；节点是否不可用 UDP 由 `no_udp` 另行判定。
        self.no_udp_dirty.insert(node.network);
        if merged.reach_changed {
            let reached: Vec<NodeId> = merged.records.iter().filter(|record| record.outcome.reached()).map(|record| record.relay).collect();
            tracing::debug!(node = %node.id, ?reached, "节点可达的 relay 集合已变更");
            let holders = self.holders_of(node.id);
            self.defer_report(node.network, holders);
            self.defer(node.network, [node.id], self.timing.report_coalesce);
        }
        Ok(())
    }

    /// 节点报的虚拟网卡装没装。变了的话它的对端的 netmap 要重算：本机的程序发给没有网卡的节点的包当场回"不可达"。
    /// 不报的节点（比虚拟网卡旧的版本）没有网卡。
    fn vnet_reported(&mut self, node: &NodeRecord, vnet: Option<&VnetReport>) {
        let lacks = !vnet.is_some_and(|vnet| matches!(vnet.state, VnetState::Installed { .. }));
        let changed = if lacks { self.no_vnet.insert(node.id) } else { self.no_vnet.remove(&node.id) };
        if changed {
            tracing::info!(node = %node.id, name = %node.name, installed = !lacks, "节点虚拟网卡安装状态已变更，将更新对端 netmap");
            let holders = self.holders_of(node.id);
            self.defer_report(node.network, holders);
        }
    }

    /// 节点报的网卡地址变了。它是 relay 的话，它的地址跟着变，全网的节点都要知道。
    fn local_addresses_reported(&mut self, node: &mut NodeRecord, local: Vec<IpAddr>) -> Result<(), Error> {
        let cidr = self.require_network(node.network)?.cidr;
        let before = node_addresses::relay_addresses(node, cidr);
        self.store.set_node_local_addresses(node.id, &local)?;
        node.local_addresses = Some(local);
        for warning in node_addresses::warnings(node, cidr) {
            tracing::warn!(node = %node.id, name = %node.name, ?warning, %cidr, "节点本地网卡地址落入网络虚拟地址段");
        }
        if node.relay.is_some() && node_addresses::relay_addresses(node, cidr) != before {
            tracing::info!(node = %node.id, name = %node.name, "relay 本地网卡地址已变更");
            let everyone: Vec<NodeId> = self.store.nodes(node.network)?.into_iter().map(|record| record.id).collect();
            self.defer(node.network, everyone, self.timing.report_coalesce);
        }
        Ok(())
    }

    fn ack(&mut self, id: NodeId, version: u64) -> Result<(), Error> {
        let Some(sync) = self.sync.get_mut(&id) else { return Ok(()) };
        // 节点不能确认尚未下发给它的版本号。
        let version = version.min(sync.state.sent);
        if version <= sync.state.acked {
            return Ok(());
        }
        sync.state.acked = version;
        let released = sync.confirm(version);
        // 先将等待该确认的对端排入重算队列，再持久化 acked：节点不会重复确认同一版本，避免持久化失败时遗漏对端重算。
        if let Some(network) = self.live.get(&id).map(|live| live.network) {
            self.defer(network, released, self.timing.ack_coalesce);
        }
        self.store.set_node_acked(id, version)?;
        Ok(())
    }
}

/// 节点自报的文本只留开头一段，免得一个乱报的节点往数据库里塞大段内容。
pub(super) fn clip(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_control()).take(MAX_HELLO_TEXT).collect()
}

/// 两组端点是不是同一组，不管顺序。
fn same_endpoints(old: &[SocketAddr], new: &[SocketAddr]) -> bool {
    old.len() == new.len() && new.iter().all(|endpoint| old.contains(endpoint))
}

/// 过滤节点上报的挂靠关系：仅保留本网络已启用的 relay（`relays`）且排除节点自身；按上报顺序最多保留 [`MAX_ATTACHMENTS`] 条，
/// 无效条目不占名额。同一 relay 重复上报时仅在其首次出现的位置保留一条：若存在节点自主选择的条目（`shared` 为 `false`）
/// 则保留该条目，否则保留首条。controller 仅将 `shared` 为 `false` 的条目视为节点自主挂靠，误留共享条目会导致误判缺少共同 relay。
///
/// 这是在 controller 的锁里做的，一帧最多能塞几十万条：留满了以后只看还能不能把留下的另外挂靠的换成自己挑的，
/// 留下的都是自己挑的就不再往后看。
fn usable_attachments(reported: Vec<Attachment>, me: NodeId, relays: &BTreeSet<NodeId>) -> Vec<Attachment> {
    if relays.is_empty() {
        return Vec::new();
    }
    let mut usable: Vec<Attachment> = Vec::with_capacity(reported.len().min(MAX_ATTACHMENTS));
    // 留下的里面另外挂靠的有几条。
    let mut shared = 0;
    for attachment in reported {
        let full = usable.len() == MAX_ATTACHMENTS;
        if full && shared == 0 {
            break;
        }
        if full && attachment.shared {
            continue;
        }
        let relay = attachment.relay;
        // 留下的都核对过：和其中一条重复的不用再核对。
        if let Some(kept) = usable.iter_mut().find(|kept| kept.relay == relay) {
            if kept.shared && !attachment.shared {
                *kept = attachment;
                shared -= 1;
            }
        } else if !full && relay != me && relays.contains(&relay) {
            shared += usize::from(attachment.shared);
            usable.push(attachment);
        }
    }
    usable
}

/// 挂靠关系有没有值得告诉对端的变化：挂靠的 relay 换了（包括从自己挑的变成另外挂的），或者到某个 relay 的延迟变了不少。
fn attachments_differ(old: &[Attachment], new: &[Attachment]) -> bool {
    old.len() != new.len()
        || new.iter().any(|attachment| {
            let Some(previous) = old.iter().find(|previous| previous.relay == attachment.relay) else { return true };
            previous.shared != attachment.shared || attachment.rtt_ms.abs_diff(previous.rtt_ms) > RTT_NOISE_MS.max(previous.rtt_ms / 4)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attachment(relay: u32, rtt_ms: u32) -> Attachment {
        Attachment { relay: NodeId::new(relay).unwrap(), rtt_ms, shared: false }
    }

    #[test]
    fn small_rtt_changes_are_noise_but_a_new_relay_or_a_big_change_is_not() {
        let old = [attachment(1, 20), attachment(2, 200)];
        assert!(!attachments_differ(&old, &[attachment(2, 240), attachment(1, 28)]));
        assert!(attachments_differ(&old, &[attachment(1, 31), attachment(2, 200)]));
        assert!(attachments_differ(&old, &[attachment(1, 20), attachment(2, 260)]));
        assert!(attachments_differ(&old, &[attachment(1, 20), attachment(3, 200)]));
        assert!(attachments_differ(&old, &[attachment(1, 20)]));
    }

    #[test]
    fn a_relay_reported_twice_is_kept_once_and_as_the_node_s_own_choice_if_either_entry_says_so() {
        let shared = |relay, rtt_ms| Attachment { shared: true, ..attachment(relay, rtt_ms) };
        let me = NodeId::new(99).unwrap();
        let relays: BTreeSet<NodeId> = (1..=17).chain([99]).map(|raw| NodeId::new(raw).unwrap()).collect();
        let reported = vec![shared(1, 5), attachment(2, 6), attachment(99, 1), attachment(1, 7), shared(2, 8)];
        assert_eq!(usable_attachments(reported, me, &relays), [attachment(1, 7), attachment(2, 6)]);

        // 已经留满了：多出来的 relay 不要，但是排在后面的"自己挑的"照样换掉前面那条另外挂靠的。
        let mut reported: Vec<Attachment> = (1..=16).map(|relay| shared(relay, 10)).collect();
        reported.extend([attachment(17, 1), attachment(1, 3)]);
        let kept = usable_attachments(reported, me, &relays);
        assert_eq!(kept.len(), MAX_ATTACHMENTS);
        assert_eq!(kept[0], attachment(1, 3));
        assert!(kept.iter().all(|attachment| attachment.relay != NodeId::new(17).unwrap()));

        assert!(usable_attachments(vec![attachment(1, 5)], me, &BTreeSet::new()).is_empty(), "网络里没有 relay");
    }

    #[test]
    fn endpoints_are_compared_as_sets() {
        let a: SocketAddr = "192.168.1.5:20330".parse().unwrap();
        let b: SocketAddr = "203.0.113.7:20330".parse().unwrap();
        assert!(same_endpoints(&[a, b], &[b, a]));
        assert!(!same_endpoints(&[a, b], &[a]));
        assert!(!same_endpoints(&[a], &[b]));
    }

    #[test]
    fn a_package_range_is_clamped_to_the_chunk_limit_and_the_end_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i3t-linux-x86_64");
        let content: Vec<u8> = (0..=u8::MAX).cycle().take(600_000).collect();
        std::fs::write(&path, &content).unwrap();
        let size = u64::try_from(content.len()).unwrap();
        let read = |offset, len| PackageRange { offset, len }.read(&path, size);

        assert_eq!(read(0, 10).unwrap(), content[..10]);
        assert_eq!(read(1000, u32::MAX).unwrap(), content[1000..1000 + 262_144], "一段不超过上限");
        assert_eq!(read(599_990, 4096).unwrap(), content[599_990..], "最后一段只给到文件末尾");
        assert!(read(600_000, 10).is_err() && read(700_000, 10).is_err(), "文件末尾之后没有东西可给");
        assert!(read(0, 0).is_err(), "不给空的段");
        assert!(PackageRange { offset: 0, len: 10 }.read(&dir.path().join("missing"), 100).is_err());
        assert!(read(0, 10).is_ok() && PackageRange { offset: 500_000, len: 10 }.read(&path, 100).is_err());
    }

    #[test]
    fn hello_text_is_clipped() {
        assert_eq!(clip("linux-x86_64"), "linux-x86_64");
        assert_eq!(clip(&"x".repeat(500)).len(), MAX_HELLO_TEXT);
        assert_eq!(clip("a\nb"), "ab");
    }
}
