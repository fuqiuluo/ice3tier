//! 不读写存储的节点消息用到的状态：在线连接的发送队列和它们收到的对端、等着回答的查询、缓存里的更新包。
//!
//! controller 的其余状态在一把锁里（[`Inner`](super::Inner)），拿着它的操作可能正在等数据库（见 [`crate::store`]）。
//! 转发信令、交回查询的回答、取更新包都不读写存储，这几样状态另放在 [`Switchboard`] 里、单独加锁，数据库卡住时这些消息照常处理
//! （见 [`Controller::handle`](super::Controller::handle)）。
//!
//! 登记连接、记下查询、切换发布由持有 `Inner` 锁的操作完成，与 `Inner` 自己的状态同时修改：总是先拿 `Inner` 的锁、再拿这一把。
//! 不持有 `Inner` 锁的一方只取走查询的应答、累加计数，以及在消息无法放入发送队列时去掉连接；连接只在持有 `Inner` 锁时登记，
//! 所以这里的连接总是 `Inner::live` 中同一序号的连接，或者已被去掉、`live` 中尚未清除（见 [`Switchboard::send`]）。
//! 持有这一把锁时不读写存储、不读写文件，只拿这一把锁的一方最多等待很短的时间。

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use i3t_model::Netmap;
use i3t_model::control::{BackboneRow, ExitTestResult, RouteAnswer, Signal, ToNode};
use i3t_model::update::Version;
use i3t_proto::NodeId;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use super::protocol::Admitted;
use super::routes::{PendingQuery, Reply};

#[derive(Debug, Default)]
pub(crate) struct Switchboard {
    /// 在线节点当前的连接。发送队列只在这里有一份：连接被顶替或者去掉时队列随之关闭，那条连接随之结束。
    lines: BTreeMap<NodeId, Line>,
    /// 自上次取走以来是否因消息无法放入发送队列而去掉过连接；不持有 `Inner` 锁时去掉的，`Inner::live` 中可能仍记着在线（见 [`Self::take_lost`]）。
    lost: bool,
    /// 已经发给节点、还在等回答的查询。
    queries: BTreeMap<u64, PendingQuery>,
    /// 当前发布里已经取到缓存里的包。
    packages: Option<CachedRelease>,
    /// 启动以来发给节点的更新包字节数。
    pub(crate) package_bytes: u64,
}

/// 一个在线节点当前的连接。
#[derive(Debug)]
struct Line {
    conn: u64,
    outbox: mpsc::Sender<ToNode>,
    /// 最近一份放进这条连接的 netmap 里写着的对端。连接刚登记、netmap 还没放进去时是空的。
    peers: BTreeSet<NodeId>,
}

/// 一个发布里已经取到缓存、核对过的包：平台 → 文件和它的大小。
#[derive(Debug)]
struct CachedRelease {
    version: Version,
    files: BTreeMap<String, (PathBuf, u64)>,
}

/// 消息没有放进节点的发送队列。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Undelivered {
    /// 节点不在线。
    Offline,
    /// 队列满了：节点没有及时读。
    Full,
    /// 连接已经关了，还没有记为离线。
    Closed,
}

impl Undelivered {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Offline => "节点不在线",
            Self::Full => "节点发送队列已满（对端未及时读取）",
            Self::Closed => "节点连接已关闭",
        }
    }
}

/// 节点对一条查询的回答。
#[derive(Debug)]
pub(crate) enum Answer {
    Route(RouteAnswer),
    Backbone(Vec<BackboneRow>),
    ExitTest(ExitTestResult),
}

impl Switchboard {
    /// 节点上线：`conn` 是这条连接的序号。之前的连接被顶替，它的发送队列随之关闭；发给它的查询不会再有回答。
    pub(crate) fn connect(&mut self, node: NodeId, conn: u64, outbox: mpsc::Sender<ToNode>) {
        self.drop_queries(node);
        self.lines.insert(node, Line { conn, outbox, peers: BTreeSet::new() });
    }

    /// 节点离线：去掉它的连接，发给它的查询不会再有回答。
    pub(crate) fn disconnect(&mut self, node: NodeId) {
        self.lines.remove(&node);
        self.drop_queries(node);
    }

    /// 告诉节点它被删掉了，并去掉它的连接：`Revoked` 是这条连接上最后一条消息，之后不会再有信令或者更新包排在它后面。
    pub(crate) fn revoke(&mut self, node: NodeId) -> Result<(), Undelivered> {
        let sent = self.send(node, ToNode::Revoked);
        self.disconnect(node);
        sent
    }

    /// 这条连接还是这个节点当前的连接。
    pub(crate) fn is_current(&self, session: Admitted) -> bool {
        self.lines.get(&session.node).is_some_and(|line| line.conn == session.conn)
    }

    /// 将一条消息放入节点的发送队列。无法放入（队列已满、连接已关闭）时去掉这条连接，效果等同于断开：发送队列随之关闭，
    /// 那条连接随之结束。`Inner::live` 中的记录由持有 `Inner` 锁的一方清除：经 `Inner` 发送时当场清除，
    /// 不持有 `Inner` 锁时由后台任务清除（见 [`Self::take_lost`]）。
    pub(crate) fn send(&mut self, node: NodeId, message: ToNode) -> Result<(), Undelivered> {
        let line = self.lines.get(&node).ok_or(Undelivered::Offline)?;
        let undelivered = match line.outbox.try_send(message) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(_)) => Undelivered::Full,
            Err(TrySendError::Closed(_)) => Undelivered::Closed,
        };
        self.disconnect(node);
        self.lost = true;
        Err(undelivered)
    }

    /// 自上次调用以来是否因消息无法放入发送队列而去掉过连接。不持有 `Inner` 锁的一方据此唤醒后台任务，
    /// 由它将这些节点记为离线（`Inner::drop_lost_sessions`）。
    pub(crate) fn take_lost(&mut self) -> bool {
        std::mem::take(&mut self.lost)
    }

    /// 把一份 netmap 放进节点的发送队列，并记下里面写着的对端：转发信令时，两个节点都收到了写着对方的 netmap 才转。
    pub(crate) fn send_netmap(&mut self, node: NodeId, netmap: Netmap) -> Result<(), Undelivered> {
        let peers = netmap.peers.iter().map(|peer| peer.id).collect();
        self.send(node, ToNode::Snapshot(Box::new(netmap)))?;
        if let Some(line) = self.lines.get_mut(&node) {
            line.peers = peers;
        }
        Ok(())
    }

    /// 测试用：最近一份放进 `node` 当前连接的 netmap 里写着的对端；不在线时是 `None`。
    #[cfg(test)]
    pub(crate) fn peers_of(&self, node: NodeId) -> Option<&BTreeSet<NodeId>> {
        self.lines.get(&node).map(|line| &line.peers)
    }

    /// 将 `session` 对应节点发来的信令转发给 `to`。仅当两个节点互为对端时转发，否则丢弃：信令不得用于探测或打扰不可见的节点。
    ///
    /// 「互为对端」指两个节点当前的连接都已放入写着对方的 netmap。节点重连报到、新的 netmap 尚未放入队列期间（包括其间的存储读写），
    /// 发给它的信令会被丢弃；netmap 无法写入存储期间，按此前放入队列的 netmap 判断。
    pub(crate) fn signal(&mut self, session: Admitted, to: NodeId, signal: Signal) {
        let from = session.node;
        let knows = |node: NodeId, peer: NodeId| self.lines.get(&node).is_some_and(|line| line.peers.contains(&peer));
        if !self.is_current(session) || !(knows(from, to) && knows(to, from)) {
            tracing::debug!(%from, %to, "丢弃信令：两个节点互不为对端，或者目的节点不在线");
            return;
        }
        // 信令尽力而为。目的节点的队列已积压一半时不再放入：
        // 不能让频繁发送信令的节点占满其他节点的队列，使其被视为未及时读取而断开。
        // 放入队列均需持有这把锁，因此确认仍有一半空位之后，放入时不会满。
        if self.lines.get(&to).is_some_and(|line| line.outbox.capacity() * 2 < line.outbox.max_capacity()) {
            tracing::debug!(%from, %to, "丢弃信令：目的节点发送队列积压");
            return;
        }
        if let Err(undelivered) = self.send(to, ToNode::Signal { from, signal }) {
            tracing::debug!(%from, %to, reason = undelivered.reason(), "丢弃信令");
        }
    }

    /// 向节点发送第 `request` 号查询 `message`，并登记等待应答的一方。先登记再发送：应答可能在这把锁释放之后立即到达。
    pub(super) fn query(&mut self, node: NodeId, request: u64, message: ToNode, reply: Reply) -> Result<(), Undelivered> {
        // 顺带清理调用方已放弃等待的查询：若节点长期不应答，这些条目不会自行移除。
        self.queries.retain(|_, pending| !pending.is_abandoned());
        self.queries.insert(request, PendingQuery::new(node, reply));
        let sent = self.send(node, message);
        if sent.is_err() {
            self.queries.remove(&request);
        }
        sent
    }

    /// `session` 对应节点应答了第 `request` 号查询。应答节点或应答类型与查询不匹配时忽略，原查询继续等待。
    pub(crate) fn answered(&mut self, session: Admitted, request: u64, answer: Answer) {
        let node = session.node;
        if !self.is_current(session) {
            return;
        }
        let Some(pending) = self.queries.remove(&request) else {
            tracing::debug!(%node, request, "忽略查询应答：未找到对应的待处理请求（可能已超时放弃）");
            return;
        };
        if let Err(unmatched) = pending.answer(node, answer) {
            tracing::debug!(%node, asked = %unmatched.node(), request, "忽略查询应答：应答节点或应答类型与请求不匹配");
            self.queries.insert(request, unmatched);
        }
    }

    /// 发给 `node` 的查询不会有回答了。
    fn drop_queries(&mut self, node: NodeId) {
        self.queries.retain(|_, pending| pending.node() != node);
    }

    /// 换成了一个新的发布：之前取到的包都不再提供。
    pub(crate) fn new_release(&mut self, version: Version) {
        self.packages = Some(CachedRelease { version, files: BTreeMap::new() });
    }

    /// 发布 `version` 里 `platform` 的包取到了缓存里的 `path`，大小 `size`。
    pub(crate) fn package_cached(&mut self, version: &Version, platform: &str, path: PathBuf, size: u64) {
        let release = self.packages.get_or_insert_with(|| CachedRelease { version: version.clone(), files: BTreeMap::new() });
        if release.version != *version {
            *release = CachedRelease { version: version.clone(), files: BTreeMap::new() };
        }
        release.files.insert(platform.to_owned(), (path, size));
    }

    /// 发布 `version` 里 `platform` 的包在缓存里的位置和大小；还没有取回来、或者已经不是当前的发布时是 `None`。
    pub(crate) fn cached_package(&self, version: &Version, platform: &str) -> Option<(PathBuf, u64)> {
        let release = self.packages.as_ref().filter(|release| release.version == *version)?;
        release.files.get(platform).cloned()
    }
}
