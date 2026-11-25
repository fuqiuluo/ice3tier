//! 路由视图：各个节点上报的路由表、全网的路由矩阵，以及"到某个节点现在会怎么走"的现问现答。
//!
//! 路是发送方在本地选的，controller 不参与，所以这里的数据全部来自节点：
//!
//! - **上报**：节点连上之后的第一次上报带着完整的路由表，之后只报变化的条目。这里存每个节点最近的一份，
//!   节点离线之后留着（界面上标成过期），controller 重启就没有了。
//! - **实时查询**：controller 向发送方下发查询，由其基于当前测量值应答。无法查询时（离线、版本过旧或超时未应答）退回最近的上报记录。
//!   回答里带着选路的细节：模式、候选路径和它们的代价、为什么是现在这条。这些随时在变，又只有看路径的时候才用得到，
//!   所以不随上报走，只在问的时候现取。
//! - **骨干矩阵**：relay 之间的延迟，每个 relay 自己测、签好名发给别的 relay 和挂靠它的节点。controller 也是现问：
//!   问几个在线的节点手上的矩阵，每个 relay 取最新的那一行。查询和回答用的是同一套编号和等待（[`PendingQuery`]）。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use i3t_model::admin::{
    BackboneRelay, BackboneView, DirectStatusView, MatrixEntry, MatrixLanes, MatrixNode, NetworkId, NodeRoute, PathLeg, PathSource,
    PathView, RouteMatrix, RouteTable, Timestamp,
};
use i3t_model::control::{BackboneRow, ExitTestResult, PathDetail, Route, RouteAnswer, RouteEntry, RouteKind, ToNode};
use i3t_proto::NodeId;
use tokio::sync::oneshot;

use super::switchboard::Answer;
use super::{Controller, Inner, Live};
use crate::error::Error;
use crate::relay_reach::ReachIndex;
use crate::server::blocking;
use crate::store::NodeRecord;

/// 等节点回答一次路由查询最多等多久。节点是拿手上现成的结论答的，正常只要一个往返。
const ANSWER_TIMEOUT: Duration = Duration::from_secs(3);
/// 现问骨干矩阵时最多问几个节点。relay 手上没有它自己的那一行（挂靠它的节点手上有），所以先问 relay，再问挂靠了 relay 的节点。
const MAX_BACKBONE_ASKED: usize = 4;
/// 一个方向最多转给管理 API 这么多条候选路径。节点自己报的本来就不超过这个数，这里只是不全信它。
const MAX_CANDIDATES: usize = 16;

/// 一个节点最近上报的路由表。
#[derive(Debug)]
pub(crate) struct Reported {
    pub(crate) entries: BTreeMap<NodeId, RouteEntry>,
    /// 各条路径的详细信息：直连类型、到首跳 relay 的传输方式以及直连探测阶段。节点无法提供（或版本过旧未上报）的对端不包含在内。
    kinds: BTreeMap<NodeId, ReportedKind>,
    /// 每一条路 controller 第一次看到它的时刻：路换了才重新算，只是延迟变了不算。
    since: BTreeMap<NodeId, Instant>,
    /// 最近一次上报的时刻。没有变化的条目节点不重复报，所以整张表都是"截至这个时刻"的。
    pub(crate) at: Instant,
    /// 是节点的哪一条连接报的。不是它现在这条连接报的，就是过期的：它离线了，或者重新连上来之后还没有上报。
    conn: u64,
}

/// 一条路的细节，和收到它时按 controller 的时钟换算出来的最近一次直连尝试的时刻。
///
/// 节点报的是"多少秒之前"，细节没变时不重报，所以收到时换算一次就一直对。
#[derive(Debug, Clone)]
struct ReportedKind {
    kind: RouteKind,
    attempted_at: Option<Timestamp>,
}

impl ReportedKind {
    fn new(kind: RouteKind, now: Timestamp) -> Self {
        let attempted = kind.direct_status.and_then(|status| status.attempted_secs_ago);
        Self { attempted_at: attempted.map(|ago| now.saturating_sub(ago)), kind }
    }

    fn direct_status(&self) -> Option<DirectStatusView> {
        let status = self.kind.direct_status?;
        Some(DirectStatusView { state: status.state, kind: status.kind, cause: status.cause, attempted_at: self.attempted_at })
    }
}

/// 一条发出去、还在等回答的查询（记在 [`Switchboard`](super::switchboard::Switchboard) 里）。
#[derive(Debug)]
pub(crate) struct PendingQuery {
    /// 被查询的目标节点，仅接受该节点返回的应答。
    node: NodeId,
    reply: Reply,
}

impl PendingQuery {
    pub(super) const fn new(node: NodeId, reply: Reply) -> Self {
        Self { node, reply }
    }

    pub(super) const fn node(&self) -> NodeId {
        self.node
    }

    /// 查询方已放弃等待。
    pub(super) fn is_abandoned(&self) -> bool {
        match &self.reply {
            Reply::Route(reply) => reply.is_closed(),
            Reply::Backbone(reply) => reply.is_closed(),
            Reply::ExitTest(reply) => reply.is_closed(),
        }
    }

    /// 将 `from` 的应答交给查询方。应答节点或应答类型与查询不匹配时原样交还该查询，继续等待。
    pub(super) fn answer(self, from: NodeId, answer: Answer) -> Result<(), Self> {
        if from != self.node {
            return Err(self);
        }
        // 查询方可能已超时放弃，发送失败无需处理。
        match (self.reply, answer) {
            (Reply::Route(reply), Answer::Route(answer)) => {
                let _unread = reply.send(answer);
            }
            (Reply::Backbone(reply), Answer::Backbone(rows)) => {
                let _unread = reply.send(rows);
            }
            (Reply::ExitTest(reply), Answer::ExitTest(result)) => {
                let _unread = reply.send(result);
            }
            (
                reply @ (Reply::Route(_) | Reply::Backbone(_) | Reply::ExitTest(_)),
                Answer::Route(_) | Answer::Backbone(_) | Answer::ExitTest(_),
            ) => {
                return Err(Self { node: self.node, reply });
            }
        }
        Ok(())
    }
}

/// 回答交给谁。问的是什么，答的就得是什么。
#[derive(Debug)]
pub(super) enum Reply {
    Route(oneshot::Sender<RouteAnswer>),
    Backbone(oneshot::Sender<Vec<BackboneRow>>),
    /// 出口测试（`exit_test` 模块）。
    ExitTest(oneshot::Sender<ExitTestResult>),
}

/// 一个节点对骨干矩阵查询的回答，还在路上。
type PendingRows = oneshot::Receiver<Vec<BackboneRow>>;

/// 两个方向各自等待的查询应答。无法发起查询的方向为 `None`。
#[derive(Debug)]
pub struct RouteAnswers {
    forward: Option<oneshot::Receiver<RouteAnswer>>,
    reverse: Option<oneshot::Receiver<RouteAnswer>>,
}

impl Controller {
    /// 一个节点最近上报的路由表：它到各个对端现在怎么走。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这个节点，或者读存储失败。
    pub fn routes(&self, network: NetworkId, id: NodeId) -> Result<RouteTable, Error> {
        let inner = self.lock();
        let record = inner.require_node(network, id)?;
        let peers = inner.store.nodes(network)?;
        let now = Instant::now();
        let used = inner.live.get(&id).map(|live| &live.peer_use);
        let routes = inner.current_routes(id).map(|reported| {
            let age_secs = now.saturating_duration_since(reported.at).as_secs();
            let known = reported.entries.values().filter_map(|entry| {
                let peer = peers.iter().find(|peer| peer.id == entry.peer)?;
                let since = reported.since.get(&entry.peer).map_or(reported.at, |since| *since);
                let kind = reported.kinds.get(&entry.peer);
                let use_of = used.and_then(|used| used.get(&entry.peer));
                Some(NodeRoute {
                    peer: peer.to_ref(),
                    route: entry.route.clone(),
                    rtt_ms: entry.rtt_ms,
                    age_secs,
                    since_secs: now.saturating_duration_since(since).as_secs(),
                    direct: kind.and_then(|kind| kind.kind.direct),
                    relay_leg: kind.and_then(|kind| kind.kind.relay_leg),
                    flows: use_of.map(|use_of| use_of.flows),
                    tx_bytes: use_of.map(|use_of| use_of.tx_bytes),
                    rx_bytes: use_of.map(|use_of| use_of.rx_bytes),
                    direct_status: kind.and_then(ReportedKind::direct_status),
                    alternative: kind.and_then(|kind| kind.kind.alternative.clone()),
                })
            });
            known.collect()
        });
        Ok(RouteTable { node: record.to_ref(), online: inner.is_online(id), routes: routes.unwrap_or_default() })
    }

    /// 整个网络的路由矩阵，取自各个节点最近的上报。离线的节点留着它最后报的那一份，标成过期。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn route_matrix(&self, network: NetworkId) -> Result<RouteMatrix, Error> {
        let inner = self.lock();
        inner.require_network(network)?;
        let nodes = inner.store.nodes(network)?;
        let members: BTreeSet<NodeId> = nodes.iter().map(|node| node.id).collect();
        let now = Instant::now();
        let entries = nodes.iter().filter_map(|node| Some((node.id, inner.routes.get(&node.id)?))).flat_map(|(from, reported)| {
            let age_secs = now.saturating_duration_since(reported.at).as_secs();
            let stale = inner.current_routes(from).is_none();
            // 离线的节点没有 `live`：过期的格子里不带 lane。
            let lanes = inner.live.get(&from).and_then(|live| live.lanes.as_ref());
            let listed = reported.entries.values().filter(|entry| members.contains(&entry.peer));
            listed.map(move |entry| {
                let kind = reported.kinds.get(&entry.peer);
                let lanes = lanes.and_then(|report| report.peers.iter().find(|peer| peer.peer == entry.peer));
                MatrixEntry {
                    from,
                    to: entry.peer,
                    route: entry.route.clone(),
                    rtt_ms: entry.rtt_ms,
                    age_secs,
                    stale,
                    direct: kind.and_then(|kind| kind.kind.direct),
                    relay_leg: kind.and_then(|kind| kind.kind.relay_leg),
                    lanes: lanes.map(MatrixLanes::from),
                }
            })
        });
        Ok(RouteMatrix {
            entries: entries.collect(),
            nodes: nodes.iter().map(|node| MatrixNode { node: node.to_ref(), online: inner.is_online(node.id) }).collect(),
        })
    }

    /// 查询两个节点间双向当前路径：先向两端实时查询，无法查询的方向退回最近的上报记录。
    ///
    /// 两个方向各由发送方决定走哪条路，所以两端都要问。最多等几秒。
    ///
    /// # Errors
    ///
    /// 两个节点不都在这个网络里，是同一个节点，或者读存储失败。
    pub async fn path(self: &Arc<Self>, network: NetworkId, from: NodeId, to: NodeId) -> Result<PathView, Error> {
        let asked = blocking(self, move |controller| controller.ask_path(network, from, to)).await?;
        let wait = async |pending: Option<oneshot::Receiver<RouteAnswer>>| match pending {
            Some(pending) => tokio::time::timeout(ANSWER_TIMEOUT, pending).await.ok().and_then(Result::ok),
            None => None,
        };
        let (forward, reverse) = tokio::join!(wait(asked.forward), wait(asked.reverse));
        blocking(self, move |controller| controller.path_view(network, from, to, forward, reverse)).await
    }

    /// [`Controller::path`] 的前一半：给两端各发一条查询。
    ///
    /// # Errors
    ///
    /// 两个节点不都在这个网络里，或者是同一个节点。
    pub fn ask_path(&self, network: NetworkId, from: NodeId, to: NodeId) -> Result<RouteAnswers, Error> {
        if from == to {
            return Err(Error::invalid_field("to", "same_node", "查询路径的两端必须为不同的节点"));
        }
        let mut inner = self.lock();
        inner.require_node(network, from)?;
        inner.require_node(network, to)?;
        Ok(RouteAnswers { forward: inner.ask_route(from, to), reverse: inner.ask_route(to, from) })
    }

    /// [`Controller::path`] 的后一半：把问到的回答和上报的数据拼成结果。没有问到的方向传 `None`。
    ///
    /// # Errors
    ///
    /// 两个节点不都在这个网络里。
    pub fn path_view(
        &self,
        network: NetworkId,
        from: NodeId,
        to: NodeId,
        forward: Option<RouteAnswer>,
        reverse: Option<RouteAnswer>,
    ) -> Result<PathView, Error> {
        let inner = self.lock();
        let (from, to) = (inner.require_node(network, from)?, inner.require_node(network, to)?);
        let history = |from: &NodeRecord, to: &NodeRecord| inner.store.switches(from.id, to.id);
        let forward = PathLeg { switches: history(&from, &to)?, ..inner.path_leg(&from, &to, forward) };
        let reverse = PathLeg { switches: history(&to, &from)?, ..inner.path_leg(&to, &from, reverse) };
        Ok(PathView { forward, reverse })
    }

    /// 网络里 relay 之间的延迟矩阵：现问几个在线的节点，每个 relay 取最新的那一行。最多等几秒。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub async fn backbone(self: &Arc<Self>, network: NetworkId) -> Result<BackboneView, Error> {
        let asked = blocking(self, move |controller| controller.ask_backbone(network)).await?;
        // 查询已并发发出，因此顺序等待并共用同一截止时间，总耗时不超过单次超时上限。
        let deadline = tokio::time::Instant::now() + ANSWER_TIMEOUT;
        let mut answers = Vec::with_capacity(asked.len());
        for (node, pending) in asked {
            if let Ok(Ok(rows)) = tokio::time::timeout_at(deadline, pending).await {
                answers.push((node, rows));
            }
        }
        blocking(self, move |controller| controller.backbone_view(network, &answers)).await
    }

    /// [`Controller::backbone`] 的前一半：挑几个在线、懂这条查询的节点，各发一条查询。relay 排在前面，其次是挂靠了 relay 的节点。
    fn ask_backbone(&self, network: NetworkId) -> Result<Vec<(NodeId, PendingRows)>, Error> {
        let mut inner = self.lock();
        inner.require_network(network)?;
        let mut nodes: Vec<NodeRecord> = inner.store.nodes(network)?;
        nodes.retain(|node| inner.live.get(&node.id).is_some_and(Live::understands_backbone));
        nodes.sort_by_key(|node| (node.relay.is_none(), node.attached.is_empty(), node.id));
        let asked = nodes.iter().take(MAX_BACKBONE_ASKED).filter_map(|node| Some((node.id, inner.ask_backbone_of(node.id)?)));
        Ok(asked.collect())
    }

    /// [`Controller::backbone`] 的后一半：把各个节点的回答合成一张表，每个 relay 取最新的那一行。
    fn backbone_view(&self, network: NetworkId, answers: &[(NodeId, Vec<BackboneRow>)]) -> Result<BackboneView, Error> {
        let inner = self.lock();
        inner.require_network(network)?;
        let nodes = inner.store.nodes(network)?;
        let relays: BTreeSet<NodeId> = nodes.iter().filter(|node| node.relay.is_some()).map(|node| node.id).collect();
        let mut freshest: BTreeMap<NodeId, (NodeId, BackboneRow)> = BTreeMap::new();
        for (from, rows) in answers {
            // 回答来自认证过的节点，但只收这个网络里的 relay 的行和链路：别的编号节点本来就不该知道。
            for mut row in rows.iter().filter(|row| relays.contains(&row.relay)).cloned() {
                row.links.retain(|link| relays.contains(&link.to));
                if freshest.get(&row.relay).is_none_or(|(_, kept)| row.age_ms < kept.age_ms) {
                    freshest.insert(row.relay, (*from, row));
                }
            }
        }
        let reach = ReachIndex::new(&nodes, |id| inner.is_online(id));
        let rows = nodes.iter().filter(|node| node.relay.is_some()).map(|node| {
            let found = freshest.remove(&node.id);
            BackboneRelay {
                relay: node.to_ref(),
                online: inner.is_online(node.id),
                state: found.as_ref().map(|(_, row)| row.state),
                load_percent: found.as_ref().map(|(_, row)| row.load_percent),
                age_ms: found.as_ref().map(|(_, row)| row.age_ms),
                reported_by: found.as_ref().map(|(from, _)| *from),
                links: found.map(|(_, row)| row.links).unwrap_or_default(),
                reach: reach.of(node.id),
            }
        });
        let answered = answers.iter().filter_map(|(from, _)| nodes.iter().find(|node| node.id == *from).map(NodeRecord::to_ref));
        Ok(BackboneView { relays: rows.collect(), answered: answered.collect() })
    }
}

impl Live {
    /// 节点协议第 2 版起，节点会回答骨干矩阵的查询，回答路由查询时带着选路的细节。
    const fn understands_backbone(&self) -> bool {
        self.protocol >= 2
    }
}

impl Inner {
    /// 节点这次连接上报过的路由表。它不在线、或者重新连上来之后还没有上报时是 `None`。
    pub(crate) fn current_routes(&self, id: NodeId) -> Option<&Reported> {
        let conn = self.live.get(&id)?.conn;
        self.routes.get(&id).filter(|reported| reported.conn == conn)
    }

    /// 记下节点上报的路由和它们的细节。`full` 时整个替换，否则只更新报上来的条目。
    ///
    /// `kinds` 与 `routes` 对应同一批对端：若上报条目缺少对应细节，表示节点当前无法提供，旧缓存记录也随之失效。
    pub(super) fn routes_reported(&mut self, id: NodeId, routes: Vec<RouteEntry>, kinds: Vec<RouteKind>, full: bool) {
        let (Some(sync), Some(live)) = (self.sync.get(&id), self.live.get(&id)) else { return };
        let now = Instant::now();
        let wall = self.clock.now();
        let reported = self.routes.entry(id).or_insert_with(|| Reported {
            entries: BTreeMap::new(),
            kinds: BTreeMap::new(),
            since: BTreeMap::new(),
            at: now,
            conn: live.conn,
        });
        let before: BTreeMap<NodeId, Route> = reported.entries.iter().map(|(peer, entry)| (*peer, entry.route.clone())).collect();
        // 上一条连接留下的表，节点没有说完整的也要先清掉：增量是相对于这条连接上报过的内容说的。
        if full || reported.conn != live.conn {
            reported.entries.clear();
            reported.kinds.clear();
        }
        reported.conn = live.conn;
        // 只记到它 netmap 里的对端的路由：别的编号它本来就不该知道，记下来只会让表无限长。
        reported.entries.retain(|peer, _| sync.knows(*peer));
        let kinds: BTreeMap<NodeId, RouteKind> = kinds.into_iter().map(|kind| (kind.peer, kind)).collect();
        for entry in routes.into_iter().filter(|entry| sync.knows(entry.peer)) {
            match kinds.get(&entry.peer) {
                Some(kind) => reported.kinds.insert(entry.peer, ReportedKind::new(kind.clone(), wall)),
                None => reported.kinds.remove(&entry.peer),
            };
            if before.get(&entry.peer) == Some(&entry.route) {
                reported.since.entry(entry.peer).or_insert(now);
            } else {
                reported.since.insert(entry.peer, now);
            }
            reported.entries.insert(entry.peer, entry);
        }
        let entries = &reported.entries;
        reported.since.retain(|peer, _| entries.contains_key(peer));
        reported.kinds.retain(|peer, _| entries.contains_key(peer));
        reported.at = now;
    }

    /// 向 `from` 查询当前前往 `to` 的路由。无法发起查询（节点离线或版本不支持该消息）时返回 `None`。
    fn ask_route(&mut self, from: NodeId, to: NodeId) -> Option<oneshot::Receiver<RouteAnswer>> {
        if !self.live.get(&from).is_some_and(Live::understands_updates) {
            return None;
        }
        let (reply, answer) = oneshot::channel();
        self.query(from, |request| ToNode::RouteQuery { request, peer: to }, Reply::Route(reply))?;
        Some(answer)
    }

    /// 向 `node` 查询其持有的骨干矩阵。无法发起查询（节点离线或版本不支持该消息）时返回 `None`。
    fn ask_backbone_of(&mut self, node: NodeId) -> Option<PendingRows> {
        if !self.live.get(&node).is_some_and(Live::understands_backbone) {
            return None;
        }
        let (reply, answer) = oneshot::channel();
        self.query(node, |request| ToNode::BackboneQuery { request }, Reply::Backbone(reply))?;
        Some(answer)
    }

    /// 给节点发一条查询，记下谁在等回答。回答不经 controller 的锁交给问的人（见 [`Switchboard::answered`]）。
    /// 发送失败时返回 `None`。
    ///
    /// [`Switchboard::answered`]: super::switchboard::Switchboard::answered
    pub(super) fn query(&mut self, node: NodeId, message: impl FnOnce(u64) -> ToNode, reply: Reply) -> Option<()> {
        let request = self.next_request();
        let sent = self.switchboard().query(node, request, message(request), reply);
        if !self.delivered(node, sent) {
            return None;
        }
        self.counters.route_queries += 1;
        Some(())
    }

    fn path_leg(&self, from: &NodeRecord, to: &NodeRecord, answer: Option<RouteAnswer>) -> PathLeg {
        let leg = |source, route, rtt_ms, age_secs, since| PathLeg {
            from: from.to_ref(),
            to: to.to_ref(),
            source,
            route,
            rtt_ms,
            age_secs,
            since,
            direct: None,
            relay_leg: None,
            mode: None,
            reason: None,
            cause: None,
            candidates: None,
            connection_rtt_ms: None,
            switches: Vec::new(),
        };
        let reported = self.routes.get(&from.id);
        // 仅当上报记录与当前查询结果指向同一条路径时，才复用其细节字段。
        let reported_kind = |route: &Route| {
            let reported = reported?;
            reported.entries.get(&to.id).filter(|entry| entry.route == *route)?;
            reported.kinds.get(&to.id).map(|kind| kind.kind.clone())
        };
        match answer {
            Some(RouteAnswer { route: Some(route), rtt_ms, since, detail, connection_rtt_ms, .. }) => {
                let kind = reported_kind(&route);
                let leg = PathLeg { connection_rtt_ms, ..leg(PathSource::Query, Some(route), rtt_ms, Some(0), since) };
                match detail {
                    Some(detail) => with_detail(leg, detail),
                    None => PathLeg {
                        direct: kind.as_ref().and_then(|kind| kind.direct),
                        relay_leg: kind.and_then(|kind| kind.relay_leg),
                        ..leg
                    },
                }
            }
            Some(RouteAnswer { route: None, .. }) => leg(PathSource::NotPeers, None, None, Some(0), None),
            None => match reported.and_then(|reported| Some((reported.entries.get(&to.id)?, reported.at))) {
                Some((entry, at)) => {
                    let kind = reported_kind(&entry.route);
                    let leg = leg(PathSource::Report, Some(entry.route.clone()), entry.rtt_ms, Some(at.elapsed().as_secs()), None);
                    PathLeg { direct: kind.as_ref().and_then(|kind| kind.direct), relay_leg: kind.and_then(|kind| kind.relay_leg), ..leg }
                }
                None => leg(PathSource::None, None, None, None, None),
            },
        }
    }
}

/// 把节点现答的选路细节填进一个方向。
fn with_detail(leg: PathLeg, detail: PathDetail) -> PathLeg {
    let PathDetail { mode, direct, relay_leg, reason, cause, mut candidates } = detail;
    candidates.truncate(MAX_CANDIDATES);
    PathLeg { direct, relay_leg, mode, reason: Some(reason), cause, candidates: Some(candidates), ..leg }
}
