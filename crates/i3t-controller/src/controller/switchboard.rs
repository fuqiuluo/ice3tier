//! 不读写存储的节点消息用到的状态：在线连接的发送队列和它们收到的对端、等着回答的查询、缓存里的更新包。
//!
//! controller 的其余状态在一把锁里（[`Inner`](super::Inner)），拿着它的操作可能正在等数据库（见 [`crate::store`]）。
//! 转发信令、交回查询的回答、取更新包都不读写存储，这几样状态另放在 [`Switchboard`] 里、单独加锁，数据库卡住时这些消息照常处理
//! （见 [`Controller::handle`](super::Controller::handle)）。
//!
//! 这几样仍由拿着 `Inner` 的锁的操作维护，和 `Inner` 自己的状态一起改：总是先拿 `Inner` 的锁、再拿这一把。
//! 拿着这一把时不读写存储、不读写文件，只拿这一把的一方因此最多等一小会儿。

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
    /// 在线节点当前的连接，和 `Inner::live` 同时增删。发送队列只在这里有一份：连接被顶替或者去掉时队列随之关闭，
    /// 那条连接自己会结束。
    lines: BTreeMap<NodeId, Line>,
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

    /// 把一条消息放进节点的发送队列。放不进去（队列满了、连接已经关了）时去掉这条连接：发送队列随之关闭，
    /// 那条连接自己会结束并记为离线，和断开它一样。
    pub(crate) fn send(&mut self, node: NodeId, message: ToNode) -> Result<(), Undelivered> {
        let line = self.lines.get(&node).ok_or(Undelivered::Offline)?;
        let undelivered = match line.outbox.try_send(message) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(_)) => Undelivered::Full,
            Err(TrySendError::Closed(_)) => Undelivered::Closed,
        };
        self.disconnect(node);
        Err(undelivered)
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

    /// 把 `session` 的节点发来的一条信令转给 `to`。只在两个节点互为对端时转，否则丢掉：信令不能用来探测或打扰看不见的节点。
    pub(crate) fn signal(&mut self, session: Admitted, to: NodeId, signal: Signal) {
        let from = session.node;
        let knows = |node: NodeId, peer: NodeId| self.lines.get(&node).is_some_and(|line| line.peers.contains(&peer));
        if !self.is_current(session) || !(knows(from, to) && knows(to, from)) {
            tracing::debug!(%from, %to, "丢弃信令：两个节点互不为对端，或者目的节点不在线");
            return;
        }
        // 信令是尽力而为的。目的节点的队列已经积了一半时不再往里放：
        // 不能让一个猛发信令的节点把别人的队列塞满，害得它被当成"不读"而断开。
        // 往队列里放东西都要拿着这把锁，所以看过还空着一半之后，放的时候不会满。
        if self.lines.get(&to).is_some_and(|line| line.outbox.capacity() * 2 < line.outbox.max_capacity()) {
            tracing::debug!(%from, %to, "丢弃信令：目的节点发送队列积压");
            return;
        }
        if let Err(undelivered) = self.send(to, ToNode::Signal { from, signal }) {
            tracing::debug!(%from, %to, reason = undelivered.reason(), "丢弃信令");
        }
    }

    /// 给节点发第 `request` 号查询 `message`，记下谁在等回答。先记下再发：回答可能在这把锁放开之后马上到。
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

    /// `session` 的节点回答了第 `request` 号查询。来源节点或回答的种类和查询对不上时忽略，原来的查询接着等。
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
