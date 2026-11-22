//! 控制任务：路径层里所有"慢"的事情都在这一个任务里做，所以这些状态不需要锁。
//!
//! 它处理收包路径认出来的帧（relay 的应答、探测、骨干矩阵的行）、信令、局域网里看到的信标、TCP 中转腿的事件、
//! netmap 的更新，并且每隔一小段时间把各个状态机的定时器推进一步。每处理完一批，就重新看一遍到每个对端该走哪条路，
//! 有变化才去改收发路径上的那张表。
//!
//! 选路有两种模式，按 netmap 里本节点的设置（没有就用网络的默认值）：
//!
//! - **默认模式**：直连可用就走直连；否则只经一个 relay，按 [`relay_candidates`](route::relay_candidates) 的顺序取第一个能用的；一个都用不了时
//!   经一串 relay（`View::chain`）。每一轮都重新看，所以直连一验证通过、一个 relay 一断开，路马上跟着变。
//! - **延迟优先**：候选路径（直连、经 1 到最大中转级数个 relay）按代价比较，规则见 [`crate::routing`]。
//!   代价每个评估窗口（5 秒）算一次；窗口之间只看现在的路还在不在，不在了立刻换。
//!
//! 两种模式下都会定期把候选路径和代价算出来放进对外公布的状态，给界面解释"为什么走这条路"。
//!
//! # 不可信的输入
//!
//! 收包路径交来的帧都没有经过认证，来源地址也可以伪造。这里的规矩是：
//!
//! - 验签名之前先扣额度（[`crate::budget`]），额度按对端、按候选地址、按矩阵行的主人分开算，一个来源灌包花不掉别人的额度；
//! - relay 的错误帧只在回显对得上时才算数（[`crate::attach`]），说多级路径走不通的还要是本节点正在用的路径；
//! - 一个直连地址被几个对端认领时，收包表归正在把它当直连用的那个（[`rebuild_direct`]）；
//! - 对端回答直连探测时报的"看到的本节点地址"必须像是本节点的（[`observed_is_mine`]），
//!   不然可能是有人在中间来回转发，把自己插进了"直连"里。
//! - 主动测试的探测只在测试打开着的时候、只对测试指定的对端回答，个数有上限，签名在这些检查之后才验（[`crate::diag`]）。

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use i3t_crypto::NodeKey;
use i3t_model::Netmap;
use i3t_model::control::{RouteCause, RouteHint, Signal};
use i3t_model::netmap::{Attachment, Reach, RoutingMode};
use i3t_proto::backbone::RelayState;
use i3t_proto::datagram::{MAX_RELAY_HOPS, RelayPath};
use i3t_proto::probe::TestId;
use i3t_proto::session::{Echo, Nonce, Refused};
use i3t_proto::{NodeId, PublicKey, addr, probe, session};
use i3t_underlay::lan::Sighting;
use i3t_underlay::portmap::{GatewaySource, PortMapConfig, PortMapper};
use i3t_underlay::{AddrQuery, ifaddr};
use tokio::sync::{mpsc, oneshot, watch};

use self::route::{Reason, RouteKey, Via, View, describe, explain, relay_in_use};
use crate::RouteChange;
use crate::backbone::{Accepted, Gate};
use crate::budget::Budget;
use crate::diag::{
    DirectAttempt, HopReport, Pin, RouteDecision, Side, TestPath, TestSpec, TrainError, TrainReport, TrainRun, TrainSpec, Window,
};
use crate::direct::{DirectPath, Policy};
use crate::estimate::Sampler;
use crate::matrix::Matrix;
use crate::relays::{RelayLink, Wire};
use crate::routing::{Candidate, PathId, Selector};
use crate::table::{self, Hop, PeerSlot, RelaySlot, Shared, Table};
use crate::tcp::{self, TcpEvent, TcpLegHandle};
use crate::timing::{EVAL_WINDOW, MAX_TIMEOUTS, PEER_ACTIVE, PROBE_INTERVAL, TICK};

mod active;
mod backbone;
mod direct;
mod relays;
mod route;
mod status;

/// 多久重新看一次本机的网卡地址。
const LOCAL_ADDRESS_REFRESH: Duration = Duration::from_secs(5);
/// 多久重新考虑一次挂靠哪几个 relay。
const ATTACH_REVIEW: Duration = Duration::from_secs(1);
/// 多久刷新一次对外公布的状态（路由表里的延迟等）。路变了的时候不等这个间隔。
const STATUS_REFRESH: Duration = Duration::from_millis(500);
/// relay 说某个对端没挂在它上面、或者某条骨干连接走不通之后，多久之内不走那条路。
const UNATTACHED_HOLD: Duration = Duration::from_secs(10);
/// 陌生地址（不是对端的候选地址）来的 PING，全体加起来每秒最多验多少个签名。对端候选地址来的各有各的额度（见 `direct`）。
const STRANGER_VERIFIES_PER_SEC: f64 = 50.0;
/// 陌生地址来的、自称是同一个对端的 PING，每秒最多验多少个，最多攒多少个。伪造某一个对端的 PING 只花得掉这一份，
/// 别的对端从新地址发来的真 PING 还能用上面那个总的额度。
const STRANGER_VERIFIES_PER_PEER: f64 = 5.0;
const STRANGER_VERIFY_BURST_PER_PEER: f64 = 10.0;
/// 每个 relay 的矩阵行每秒最多验多少个签名，最多攒多少个。正常情况下一个 relay 几秒才有一行新的。
const ROW_VERIFIES_PER_SEC: f64 = 2.0;
const ROW_VERIFY_BURST: f64 = 5.0;
/// 状态变了的行、说哪一段骨干又通了的行不等下一轮就转给本节点 relay 上的会话，但同一个 relay 的行最多这么频繁地转：
/// 状态或者连通来回翻的行再多，经本节点放大出去的也有限，其余的跟着下一轮一起发。
const ROW_FORWARD_GAP: Duration = Duration::from_secs(1);
/// 控制任务每一轮从每个队列最多处理多少条，免得一个队列被灌满时别的等太久。
const BATCH: usize = 256;
/// 经多个 relay 的路径上后面的 relay 没法把"送不到"告诉来源节点，所以本节点自己经这条路径给对端发端到端的探测
/// （对端从它自己的路回答）。有流量时每隔这么久探测一次，没有流量时按普通的探测间隔。
const PATH_PROBE_BUSY: Duration = Duration::from_secs(1);
/// 一个路径探测等多久没有回答算丢了。连续丢 [`MAX_TIMEOUTS`] 个就认为这条路径中间断了。
const PATH_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// 同一个对端的路径探测最多这么频繁地回答：验签名不便宜，对端正常情况下一秒才发一个。
const PATH_PING_MIN_GAP: Duration = Duration::from_millis(200);
/// 量"本节点的 relay → 对端"那一段的探测（见 [`View::local_leg`]）和经多级路径的探测至少隔这么久才发：两条路的延迟不一样，
/// 发出去隔了这么久，到对端时一般也还隔着 [`PATH_PING_MIN_GAP`] 以上，不会有一个被它的频率上限挡掉。
const LOCAL_PROBE_APART: Duration = Duration::from_millis(500);
/// 被这样怀疑的路径多久之内不再用（除非没有别的路）。
const SUSPECT_HOLD: Duration = Duration::from_secs(20);
/// relay 宣布下线之后，多久之内把它排在别的 relay 后面。比通知本身的有效期短得多：它要是升级完很快回来了，
/// 不该因为一行旧的通知一直被冷落；它回来之后发的新的一行到了，这个标记也就提前解除。
/// 这段时间里到它的会话照常保持、断了照常重连（带退避和随机抖动）：只有它一个 relay 可走的节点还得靠它。
const DRAIN_HOLD: Duration = Duration::from_secs(30);
/// relay 通知过载之后，至少这么久不回去用它，另外每个节点再加上 0 到这么久的一段随机时间。
const OVERLOAD_HOLD: Duration = Duration::from_secs(30);
/// 有新的会话时，至少隔这么久才为它们额外发一轮矩阵。
const NEWCOMER_BATCH: Duration = Duration::from_millis(500);
/// 一个对端的候选路径最多报多少条给界面。
const MAX_REPORTED_CANDIDATES: usize = 16;
/// 每分钟的 UDP 询问没有回答的 relay，隔这么久用一次会话（UDP 和 TCP 一起）去试：看它是只有 TCP 连得上，还是根本连不上。
const PROBE_AGAIN: Duration = Duration::from_secs(600);
/// 这样的一次试最多多久。同一时刻只试一个，所以网络里 relay 再多，多出来的也只有一个会话。
const PROBE_LIMIT: Duration = Duration::from_secs(20);
/// 本节点能访问的对端不超过这么多个时，不等流量就去试到每一个的直连（见 [`eager_direct`]）。
///
/// 只在第一次用到时才试的话，两台还没说过话的公网服务器的路由表上是"经 relay，直连：未尝试"，看起来像打洞失败了。
/// 一个节点为每个这样的对端付出的是：开始时一次尝试（几个探测、一条打洞信令），通了之后每 5 秒一个保活探测，
/// 不通的照常退避，最后每分钟再试一次，和一对正在用的节点一样。个数封顶，免得网络大了之后每个节点都要和所有节点保持探测，
/// 合起来随节点数的平方增长；超过的网络照旧在第一次用到时才试。
pub(crate) const EAGER_DIRECT_PEERS: usize = 32;
/// 测试用的开关：环境变量 `I3T_TEST_EAGER_DIRECT_PEERS` 改上面那个上限（实验环境里搭 33 个节点太重）。
const EAGER_DIRECT_TEST_SWITCH: &str = "I3T_TEST_EAGER_DIRECT_PEERS";
/// 不等流量就试的直连在这么长的时间里随机错开开始：刚启动、或者 netmap 一下子带来很多对端和地址时，不在同一刻一起发探测和信令。
const EAGER_SPREAD: Duration = Duration::from_secs(3);

/// 交给控制任务处理的事情。
#[derive(Debug)]
pub(crate) enum Ctrl {
    /// UDP 上收到的、归路径层自己处理的一帧。
    Frame { from: SocketAddr, frame: Inbound },
    /// 到某个 relay 的 TCP 上发生的事。
    Tcp { relay: NodeId, conn: u64, event: TcpEvent },
    /// relay `relay` 拨进来、本节点的 relay 接住的第 `conn` 条 TCP 上归路径层的事（骨干，见 [`crate::backbone`]）。
    Accepted { relay: NodeId, conn: u64, event: Accepted },
    /// relay `relay` 经 UDP 敲了门：它的 AUTH 被本节点的 relay 挡下了（[`crate::BackboneInbox::knocked`]）。
    Knock { relay: NodeId },
    /// 对端发来的信令。
    Signal { from: NodeId, signal: Signal },
    /// 在本地网段上看到了一个对端的信标。
    Lan(Sighting),
    /// 局域网发现刚启动：把要认的对端告诉它。
    LanStarted,
    /// 按这份参数（重新）启动端口映射。
    PortMap(PortMapConfig),
    /// 节点要停了：删掉端口映射，然后结束控制任务。
    Shutdown(oneshot::Sender<()>),
    /// 有人在等路：别等下一个定时器，现在就把状态机推进一步。
    Wake,
    /// 打开一个主动测试的时间窗。
    OpenTest(TestSpec),
    /// 关掉一个主动测试的时间窗（测试做完了、被取消了，或者等它的一方不在了）。
    CloseTest(TestId),
    /// 在一条路径上发一列探测。
    Train { spec: TrainSpec, reply: oneshot::Sender<Result<TrainReport, TrainError>> },
    /// 把到对端的路暂时固定在一条路径上。
    Pin { peer: NodeId, pin: Pin },
    /// 解除固定。`id` 对不上（已经被新的固定替换了）时不做什么。
    Unpin { peer: NodeId, id: u64 },
    /// 现在就试一次直连（带头），或者等对端来试（跟随），最多等 `limit`。
    AttemptDirect { peer: NodeId, side: Side, limit: Duration, reply: oneshot::Sender<DirectAttempt> },
    /// 两种选路模式此刻各会选哪条路。
    Decide { peer: NodeId, reply: oneshot::Sender<Option<RouteDecision>> },
    /// 一条路径上各段的测量值。
    Hops { peer: NodeId, path: TestPath, reply: oneshot::Sender<Vec<HopReport>> },
}

#[derive(Debug, Clone)]
pub(crate) enum Inbound {
    /// relay 发来的会话帧，错误帧除外。
    Session(session::Frame),
    /// relay 发来的错误帧和它回显的字节。
    Refusal(Refused, Echo),
    Probe(probe::Frame),
    AddrReply(addr::Reply),
    /// 骨干矩阵的一行，整帧。
    Row(Bytes),
    /// 对端经 relay 送来的端到端路径探测，或者对本端探测的回答。
    PathProbe {
        peer: NodeId,
        frame: probe::Frame,
    },
    /// 主动测试的探测或者回答（`frame` 是 [`probe::Frame::TestPing`] 或 [`probe::Frame::TestPong`]）。
    /// `at` 是收包路径看到它的时刻，往返时间从这里算，不含它在队列里等的时间；`relayed` 说它是经 relay 来的还是直连来的。
    Test {
        frame: probe::Frame,
        at: Instant,
        relayed: bool,
    },
}

/// 控制任务要读的三个队列，见 [`Shared`] 里对应的发送端。
#[derive(Debug)]
pub(crate) struct Queues {
    pub(crate) ctrl: mpsc::Receiver<Ctrl>,
    pub(crate) from_relays: mpsc::Receiver<Ctrl>,
    pub(crate) from_peers: mpsc::Receiver<Ctrl>,
}

struct PeerState {
    key: PublicKey,
    /// 对端挂靠的 relay，按它到 relay 的延迟从低到高。
    attached: Vec<Attachment>,
    /// 对端上报的候选端点。用来推断它和本节点是不是在同一个 NAT 后面。
    endpoints: Vec<SocketAddr>,
    /// 对端自己是不是网络里的 relay。
    is_relay: bool,
    dial_out_only: bool,
    direct: DirectPath,
    slot: Arc<PeerSlot>,
    route: RouteKey,
    doubt: bool,
    /// 算作这个对端的来源地址，和其中正在当作直连用的那个。收包表按所有对端的这两项建（[`rebuild_direct`]）。
    sources: Vec<SocketAddr>,
    active_source: Option<SocketAddr>,
    /// 陌生地址来的、自称是这个对端的 PING 的验签额度。
    stranger_budget: Budget,
    /// 下一次换路的直接起因。
    hint: Option<RouteHint>,
    /// 哪些 relay 说过这个对端没挂在它上面，到什么时候为止不把它们当作最后一个 relay。
    unattached: Vec<(NodeId, Instant)>,
    /// 端到端的探测没有回音的多级路径，到什么时候为止不用。
    suspect: Vec<(RelayPath, Instant)>,
    probe: PathProbe,
    /// 延迟优先模式下的选路状态。
    selector: Selector,
    /// 最近一次算出来的候选路径，按代价从低到高。
    candidates: Vec<Candidate>,
    /// 现在这条路是为什么选的，以及是什么时候换上的。
    reason: Reason,
    switched: Option<Instant>,
    /// 上一次从没有路变成有路的时刻。见 [`route::relay_in_use`]。
    first_route: Option<Instant>,
    /// 主动测试把路暂时固定在哪里（见 [`crate::diag`]）。
    pin: Option<Pin>,
    /// 现在的路是不是固定出来的。
    pinned: bool,
    /// 选路规则此刻选的路。没有固定时就是 `route`；固定期间选路规则照样每一轮都选，"现在走着的 relay"这类判断看的是它，
    /// 所以测试结束之后回到的是没有这次测试时会走的那条路。
    policy_route: RouteKey,
    /// 本节点没在用的那种选路模式此刻会选的路，给界面比较用（[`PathReport::alternative`](crate::report::PathReport::alternative)），不影响选路。
    /// 默认模式下每个评估窗口按延迟优先的规则算一次，延迟优先模式下每一轮按默认模式的规则算。
    /// 外层是 `None`：还没有算过；里层是 `None`：那种模式此刻没有路可走。
    other_mode: Option<Option<PathId>>,
    /// 不等流量就试到它的直连（见 [`EAGER_DIRECT_PEERS`]）：从这个时刻起。不这样试的对端是 `None`。
    eager_from: Option<Instant>,
    /// 对端挂在本节点的 relay 上、这一段又没有别的测量值时，本节点经这个会话发的端到端探测（见 [`View::local_leg`]）。
    local_leg: Sampler,
    /// 最近一次收到它的打洞信令的时刻：之后一段时间里陪它把直连试完（见 [`direct_policy`]）。
    signalled: Option<Instant>,
}

/// 一次正在进行的直连尝试（主动测试）。
#[derive(Debug)]
struct Attempt {
    peer: NodeId,
    side: Side,
    started: Instant,
    deadline: Instant,
    reply: oneshot::Sender<DirectAttempt>,
}

/// 经现在这条多级路径做的端到端探测。
#[derive(Debug, Default)]
struct PathProbe {
    /// 在等回答的那个探测。
    pending: Option<(Nonce, Instant)>,
    last_sent: Option<Instant>,
    /// 连续几个没有回答。
    missed: u8,
    /// 最近一次回答对端的探测，用来限速。
    answered: Option<Instant>,
}

/// 别的 relay 拨进来、本节点的 relay 接住的一条 TCP：它在上面建好了会话，路径层可以借来建自己的（[`crate::backbone`]）。
#[derive(Debug)]
struct InboundLeg {
    /// relay 给它的编号。
    accepted: u64,
    addr: SocketAddr,
    sender: i3t_underlay::tcp_leg::FrameSender,
}

struct RelayEntry {
    link: RelayLink,
    slot: Arc<RelaySlot>,
    /// 这个 relay 最近通知的状态。不是正常服务时，路径和挂靠都尽量避开它。
    state: RelayState,
    /// 它通知过过载：到这个时刻之前，哪怕它说自己恢复了也先不回去。
    cooling_until: Option<Instant>,
}

/// 一个 relay 的矩阵行：验签名的额度，和上一次不等下一轮就把它的行转给本节点 relay 上的会话的时刻。
struct RowGate {
    budget: Budget,
    forwarded: Option<Instant>,
}

impl RowGate {
    const fn new(now: Instant) -> Self {
        Self { budget: Budget::new(ROW_VERIFIES_PER_SEC, ROW_VERIFY_BURST, now), forwarded: None }
    }

    /// 现在能不能把这个 relay 状态变了的行立刻转出去。返回 `true` 就算转过了。
    fn forward(&mut self, now: Instant) -> bool {
        if self.forwarded.is_some_and(|at| now.saturating_duration_since(at) < ROW_FORWARD_GAP) {
            return false;
        }
        self.forwarded = Some(now);
        true
    }
}

pub(crate) struct Control {
    shared: Arc<Shared>,
    key: Arc<NodeKey>,
    netmap: Arc<Netmap>,
    /// 这三项来自 netmap：能不能用直连、能不能用 relay、本节点是不是只主动连接。
    allow_direct: bool,
    allow_relay: bool,
    dial_out_only: bool,
    /// 本节点的选路模式，和一条路径最多经过几个 relay。
    mode: RoutingMode,
    max_hops: usize,
    peers: HashMap<NodeId, PeerState>,
    relays: HashMap<NodeId, RelayEntry>,
    legs: HashMap<NodeId, TcpLegHandle>,
    /// 每个 relay 拨进来的那条 TCP（最近的一条），等着借来用。
    inbound: HashMap<NodeId, InboundLeg>,
    /// 最近一次交给本节点的 relay 的骨干闸门（`Shared::gates`，见 [`crate::backbone`]）：变了才重写。
    gates: HashMap<NodeId, Gate>,
    /// 按来源地址认 relay：一个地址可能是好几个 relay 的（不同局域网里的内网地址会撞），所以是一个列表。
    relay_by_addr: HashMap<SocketAddr, Vec<NodeId>>,
    /// 按延迟自己挑的挂靠对象（或者管理员固定的）。
    attached: Vec<NodeId>,
    /// controller 要本节点另外挂靠的（netmap 的 `shared_relays`），去掉已经在 `attached` 里的。
    shared_relays: Vec<NodeId>,
    attach_reviewed: Option<Instant>,
    /// 正在用会话试的、UDP 询问没有回答的那个 relay，和开始的时刻（见 [`PROBE_AGAIN`]）。
    probing: Option<(NodeId, Instant)>,
    /// 最近一次公布的状态里挂靠着的 relay（[`Control::attachment_ids`]）。变了就不等刷新的间隔马上公布。
    published_attachments: Vec<NodeId>,
    addr_query: AddrQuery,
    local_candidates: Vec<SocketAddr>,
    local_refreshed: Option<Instant>,
    endpoints: Vec<SocketAddr>,
    /// 别人看到的本节点地址（见 [`crate::Paths::public_addresses`]），不管用不用直连。
    public_addresses: Vec<SocketAddr>,
    mapping_varies: Option<bool>,
    /// 陌生地址来的 PING 全体的验签额度。
    verify_budget: Budget,
    /// 各个 relay 的矩阵行的验签额度和转发的节奏。只有 netmap 里的 relay 在这里。
    row_gates: HashMap<NodeId, RowGate>,
    next_conn: u64,
    status_refreshed: Option<Instant>,
    /// 手上的骨干矩阵。
    matrix: Matrix,
    /// relay 说走不通的骨干连接（从前一个到后一个），到什么时候为止不用。两个编号相同表示那个 relay 不肯转发多级路径。
    broken: Vec<(NodeId, NodeId, Instant)>,
    /// 上一个评估窗口是什么时候开始的。
    evaluated: Option<Instant>,
    /// 本节点是 relay 时：上一次把矩阵发给会话的时刻，和当时自己的状态、握手成功过的次数。
    rows_sent: Option<Instant>,
    own_state: Option<RelayState>,
    sessions_seen: u64,
    /// 上一次发出去的那一行里连通的 relay。
    rows_linked: Vec<NodeId>,
    portmap: Option<PortMapper>,
    /// 打开着的主动测试。
    windows: HashMap<TestId, Window>,
    /// 正在发的探测包列。
    trains: Vec<TrainRun>,
    /// 正在进行的直连尝试。
    attempts: Vec<Attempt>,
}

/// 把 [`RelayLink`] 要发的东西真的发出去。
struct LinkWire<'a> {
    shared: &'a Arc<Shared>,
    slot: &'a Arc<RelaySlot>,
    legs: &'a mut HashMap<NodeId, TcpLegHandle>,
    inbound: &'a HashMap<NodeId, InboundLeg>,
    next_conn: &'a mut u64,
}

impl Wire for LinkWire<'_> {
    fn udp(&mut self, to: SocketAddr, frame: &[u8]) {
        self.shared.port.send_datagram(frame, to);
    }

    fn tcp(&mut self, frame: &[u8]) {
        if let Some(leg) = self.legs.get(&self.slot.id) {
            // 队列满了就丢，握手和保活都有自己的重试。
            leg.sender.try_send(Bytes::copy_from_slice(frame));
        }
    }

    fn tcp_connect(&mut self, addrs: &[SocketAddr]) {
        let conn = *self.next_conn;
        *self.next_conn += 1;
        let leg = tcp::spawn(Arc::clone(self.shared), Arc::clone(self.slot), conn, addrs.to_vec());
        self.legs.insert(self.slot.id, leg);
    }

    fn tcp_adopt(&mut self) -> Option<(SocketAddr, u64)> {
        let offered = self.inbound.get(&self.slot.id)?;
        let conn = *self.next_conn;
        *self.next_conn += 1;
        self.legs.insert(self.slot.id, TcpLegHandle::adopted(conn, offered.accepted, offered.sender.clone()));
        Some((offered.addr, offered.accepted))
    }

    fn tcp_close(&mut self) {
        self.legs.remove(&self.slot.id);
    }
}

impl Control {
    pub(crate) fn new(shared: Arc<Shared>, key: Arc<NodeKey>, netmap: Arc<Netmap>, addr_servers: Vec<SocketAddr>) -> Self {
        let now = Instant::now();
        // 端口绑在未指定地址上的才是真的节点（测试里的节点绑在回环的具体地址上）：只有它们自动去找网关要端口映射。
        let local = shared.port.local_addr();
        let portmap =
            local.ip().is_unspecified().then(|| PortMapper::spawn(PortMapConfig { port: local.port(), gateway: GatewaySource::System }));
        let mut control = Self {
            shared,
            key,
            netmap: Arc::clone(&netmap),
            allow_direct: true,
            allow_relay: true,
            dial_out_only: false,
            mode: RoutingMode::DirectFirst,
            max_hops: 1,
            peers: HashMap::new(),
            relays: HashMap::new(),
            legs: HashMap::new(),
            inbound: HashMap::new(),
            gates: HashMap::new(),
            relay_by_addr: HashMap::new(),
            attached: Vec::new(),
            shared_relays: Vec::new(),
            attach_reviewed: None,
            probing: None,
            published_attachments: Vec::new(),
            addr_query: AddrQuery::new(addr_servers),
            local_candidates: Vec::new(),
            local_refreshed: None,
            endpoints: Vec::new(),
            public_addresses: Vec::new(),
            mapping_varies: None,
            verify_budget: Budget::new(STRANGER_VERIFIES_PER_SEC, STRANGER_VERIFIES_PER_SEC, now),
            row_gates: HashMap::new(),
            next_conn: 1,
            status_refreshed: None,
            matrix: Matrix::default(),
            broken: Vec::new(),
            evaluated: None,
            rows_sent: None,
            own_state: None,
            sessions_seen: 0,
            rows_linked: Vec::new(),
            portmap,
            windows: HashMap::new(),
            trains: Vec::new(),
            attempts: Vec::new(),
        };
        control.apply_netmap(netmap, now);
        control.poll(now);
        control
    }

    pub(crate) async fn run(mut self, queues: Queues, mut netmap: watch::Receiver<Arc<Netmap>>) {
        let Queues { mut ctrl, mut from_relays, mut from_peers } = queues;
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut netmap_open = true;
        loop {
            // 探测包列的间隔比定时器细：有列在发的时候按它们自己的时刻醒，只推进它们。
            let train_wake = self.trains.iter().map(TrainRun::wake_at).min();
            let train_sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(train_wake.unwrap_or_else(|| Instant::now() + TICK)));
            let first = tokio::select! {
                () = train_sleep, if train_wake.is_some() => {
                    self.poll_trains(Instant::now());
                    continue;
                }
                message = ctrl.recv() => {
                    let Some(message) = message else { return };
                    Some(message)
                }
                Some(message) = from_relays.recv() => Some(message),
                Some(message) = from_peers.recv() => Some(message),
                changed = netmap.changed(), if netmap_open => match changed {
                    Ok(()) => {
                        let latest = Arc::clone(&netmap.borrow_and_update());
                        self.apply_netmap(latest, Instant::now());
                        None
                    }
                    // 发 netmap 的一方没了（节点在退出）：按最后一份继续。
                    Err(_) => {
                        netmap_open = false;
                        None
                    }
                },
                _ = tick.tick() => None,
            };
            // 攒着的一起处理完再重新选路，免得每一帧都把所有对端过一遍。每个队列每轮最多拿 [`BATCH`] 条。
            let now = Instant::now();
            let batch = first
                .into_iter()
                .chain(std::iter::from_fn(|| ctrl.try_recv().ok()).take(BATCH))
                .chain(std::iter::from_fn(|| from_relays.try_recv().ok()).take(BATCH))
                .chain(std::iter::from_fn(|| from_peers.try_recv().ok()).take(BATCH));
            for message in batch {
                if let Ctrl::Shutdown(done) = message {
                    self.shutdown().await;
                    // 等结果的一方不等了也没有关系。
                    let _waiting = done.send(());
                    return;
                }
                self.handle(message, now);
            }
            self.poll(Instant::now());
        }
    }

    fn handle(&mut self, message: Ctrl, now: Instant) {
        match message {
            Ctrl::Frame { from, frame: Inbound::Session(frame) } => self.on_relay_frame(from, &frame, now),
            Ctrl::Frame { from, frame: Inbound::Refusal(refused, echo) } => self.on_relay_refusal(from, &refused, &echo, now),
            Ctrl::Frame { from, frame: Inbound::Probe(probe::Frame::Ping(ping)) } => self.on_ping(from, &ping, now),
            Ctrl::Frame { from, frame: Inbound::Probe(probe::Frame::Pong(pong)) } => self.on_pong(from, &pong, now),
            Ctrl::Frame { from, frame: Inbound::AddrReply(reply) } => {
                if let Some(observation) = self.addr_query.handle_reply(from, &reply, now) {
                    tracing::debug!(observer = %from, observed = %observation.observed, "地址查询有了回答");
                }
            }
            Ctrl::Frame { from, frame: Inbound::Row(frame) } => {
                if let Some(&relay) = self.relays_at(from).first() {
                    self.on_row(relay, &frame, now);
                }
            }
            Ctrl::Frame { frame: Inbound::PathProbe { peer, frame: probe::Frame::Ping(ping) }, .. } => self.on_path_ping(peer, &ping, now),
            Ctrl::Frame { frame: Inbound::PathProbe { peer, frame: probe::Frame::Pong(pong) }, .. } => self.on_path_pong(peer, &pong, now),
            Ctrl::Frame { from, frame: Inbound::Test { frame: probe::Frame::TestPing(ping), at, relayed } } => {
                self.on_test_ping(from, &ping, at, relayed, now);
            }
            Ctrl::Frame { frame: Inbound::Test { frame: probe::Frame::TestPong(pong), at, .. }, .. } => self.on_test_pong(&pong, at),
            // 收包路径只把测试的帧放进 `Test`，也不会把测试的帧当作普通的探测：这几种组合不会出现。
            Ctrl::Frame {
                frame:
                    Inbound::Test { frame: probe::Frame::Ping(_) | probe::Frame::Pong(_), .. }
                    | Inbound::Probe(probe::Frame::TestPing(_) | probe::Frame::TestPong(_))
                    | Inbound::PathProbe { frame: probe::Frame::TestPing(_) | probe::Frame::TestPong(_), .. },
                ..
            } => {}
            Ctrl::OpenTest(spec) => self.open_test(&spec, now),
            Ctrl::CloseTest(test) => self.close_test(test, "测试结束"),
            Ctrl::Train { spec, reply } => self.start_train(spec, reply, now),
            Ctrl::Pin { peer, pin } => self.pin(peer, pin, now),
            Ctrl::Unpin { peer, id } => self.unpin(peer, id),
            Ctrl::AttemptDirect { peer, side, limit, reply } => self.attempt_direct(peer, side, limit, reply, now),
            Ctrl::Decide { peer, reply } => {
                // 问的人不等了也没有关系。
                let _waiting = reply.send(self.decide(peer, now));
            }
            Ctrl::Hops { peer, path, reply } => {
                let _waiting = reply.send(self.hops(peer, path, now));
            }
            Ctrl::Tcp { relay, conn, event } => self.on_tcp(relay, conn, &event, now),
            Ctrl::Accepted { relay, conn, event } => self.on_accepted(relay, conn, event, now),
            Ctrl::Knock { relay } => self.on_knock(relay, now),
            Ctrl::Signal { from, signal } => self.on_signal(from, &signal, now),
            Ctrl::Lan(sighting) => self.on_lan(sighting, now),
            Ctrl::LanStarted => self.sync_lan(),
            Ctrl::PortMap(config) => {
                let mapper = PortMapper::spawn(config);
                mapper.set_tcp(self.netmap.me.relay.is_some());
                self.portmap = Some(mapper);
            }
            // 在 `run` 里已经处理掉了；这里只是让匹配保持完整。
            Ctrl::Shutdown(_) | Ctrl::Wake => {}
        }
    }

    /// 节点要停了：把在路由器上申请的端口映射删掉。
    async fn shutdown(&mut self) {
        if let Some(mapper) = self.portmap.take() {
            mapper.shutdown().await;
        }
    }

    /// 按新的 netmap 更新对端、relay 和各种限制。
    fn apply_netmap(&mut self, netmap: Arc<Netmap>, now: Instant) {
        let me = self.shared.me;
        if netmap.me.id != me {
            tracing::error!(expected = %me, got = %netmap.me.id, "netmap 里本节点的编号变了，忽略这份 netmap");
            return;
        }
        let reach = netmap.me.reach.unwrap_or(netmap.network.reach);
        self.allow_direct = reach != Reach::RelayOnly;
        self.allow_relay = reach != Reach::DirectOnly;
        self.dial_out_only = netmap.me.dial_out_only;
        let mode = netmap.me.routing.unwrap_or(netmap.network.routing);
        let max_hops = usize::from(netmap.network.max_relay_hops).clamp(1, MAX_RELAY_HOPS);
        if (mode, max_hops) != (self.mode, self.max_hops) {
            let name = match mode {
                RoutingMode::DirectFirst => "默认模式（直连优先，否则经一个 relay，没有两端都用得上的 relay 时经一串）",
                RoutingMode::LowestCost => "延迟优先（按代价比较直连和各条 relay 路径）",
            };
            tracing::info!(mode = name, max_relay_hops = max_hops, "本节点的选路模式");
            self.mode = mode;
            self.max_hops = max_hops;
            // 换了规则：不等下一个窗口，马上按新的规则看一遍。
            self.evaluated = None;
        }

        let mut table = self.shared.table_mut();
        let gone: Vec<NodeId> = self.peers.keys().copied().filter(|id| netmap.peer(*id).is_none()).collect();
        for &id in &gone {
            let Some(peer) = self.peers.remove(&id) else { continue };
            table.peers.remove(&id);
            peer.slot.set_hop(Hop::None);
            if peer.route != RouteKey::None {
                self.announce(id, RouteKey::None, Reason::new("对端不在 netmap 里了", RouteCause::PeerRemoved));
            }
        }
        if !gone.is_empty() {
            rebuild_direct(&mut table, &self.peers);
        }
        drop(table);
        for test in self.windows.iter().filter(|(_, window)| gone.contains(&window.peer)).map(|(test, _)| *test).collect::<Vec<_>>() {
            self.close_test(test, "对端不在 netmap 里了");
        }
        let mut table = self.shared.table_mut();
        let local = self.shared.port.local_addr();
        let eager = eager_direct(&netmap, eager_direct_limit());
        for info in &netmap.peers {
            if info.id == me {
                continue;
            }
            let new_peer = !self.peers.contains_key(&info.id);
            let peer = self.peers.entry(info.id).or_insert_with(|| {
                let slot = PeerSlot::new(info.id);
                table.peers.insert(info.id, Arc::clone(&slot));
                PeerState {
                    key: info.key,
                    attached: Vec::new(),
                    endpoints: Vec::new(),
                    is_relay: false,
                    dial_out_only: false,
                    direct: DirectPath::for_port(local),
                    slot,
                    route: RouteKey::None,
                    doubt: true,
                    sources: Vec::new(),
                    active_source: None,
                    stranger_budget: Budget::new(STRANGER_VERIFIES_PER_PEER, STRANGER_VERIFY_BURST_PER_PEER, now),
                    hint: None,
                    unattached: Vec::new(),
                    suspect: Vec::new(),
                    probe: PathProbe::default(),
                    selector: Selector::default(),
                    candidates: Vec::new(),
                    reason: Reason::no_route_yet(),
                    switched: None,
                    first_route: None,
                    pin: None,
                    pinned: false,
                    policy_route: RouteKey::None,
                    other_mode: None,
                    eager_from: None,
                    local_leg: Sampler::new(),
                    signalled: None,
                }
            });
            if peer.key != info.key {
                // 换了密钥就是另一个身份：以前验证过的地址全部作废。
                tracing::info!(peer = %info.id, "对端的公钥变了，重新验证它的直连地址");
                peer.key = info.key;
                peer.direct = DirectPath::for_port(local);
            }
            peer.attached.clone_from(&info.attached);
            peer.endpoints.clone_from(&info.endpoints);
            peer.is_relay = netmap.relay(info.id).is_some();
            peer.dial_out_only = info.dial_out_only;
            let new_addresses = peer.direct.set_reported(&info.endpoints, now);
            // 小网络里不等流量就试直连：新的对端、对端有了新的地址、刚变得可以这样试时，在一小段时间里错开开始。
            peer.eager_from = match (eager.contains(&info.id), peer.eager_from) {
                (false, _) => None,
                (true, Some(from)) if !new_peer && !new_addresses => Some(from),
                (true, _) => Some(now + crate::relays::jitter(EAGER_SPREAD)),
            };
        }
        if !eager.is_empty() {
            tracing::debug!(peers = eager.len(), "能访问的对端不多：不等流量就试到它们的直连");
        }

        let gone: Vec<NodeId> = self.relays.keys().copied().filter(|id| netmap.relay(*id).is_none()).collect();
        for id in gone {
            self.relays.remove(&id);
            self.legs.remove(&id);
            self.inbound.remove(&id);
            tracing::info!(relay = %id, "relay 不在 netmap 里了，到它的中转会话关闭");
        }
        let own = self.own_addresses();
        for info in netmap.relays.iter().filter(|relay| relay.id != me) {
            let entry = self.relays.entry(info.id).or_insert_with(|| RelayEntry {
                link: RelayLink::new(info, now),
                slot: RelaySlot::new(info.id),
                state: RelayState::Serving,
                cooling_until: None,
            });
            entry.link.update(info);
            entry.link.set_own(&own);
        }
        drop(table);
        let slots = self.relay_addresses();
        self.shared.table_mut().relays = slots;
        self.matrix.retain(now, |relay| netmap.relay(relay).is_some());
        self.row_gates.retain(|relay, _| netmap.relay(*relay).is_some());
        if let Some(mapper) = &self.portmap {
            // relay 在同一个端口号上还监听 TCP，那个端口也要映射出去。
            mapper.set_tcp(netmap.me.relay.is_some());
        }
        self.netmap = netmap;
        self.sync_lan();
        // 对端和 relay 都可能变了：挂靠关系马上重新考虑，对外公布的状态马上刷新。
        self.attach_reviewed = None;
        self.status_refreshed = None;
    }

    /// 本节点自己的地址：网卡上的候选端点，端口绑在全零地址上时还有回环地址。relay 的地址里有它们的话不去试。
    fn own_addresses(&self) -> Vec<SocketAddr> {
        let local = self.shared.port.local_addr();
        let mut own = self.local_candidates.clone();
        own.push(local);
        if local.ip().is_unspecified() {
            own.extend([SocketAddr::from(([127, 0, 0, 1], local.port())), SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, local.port()))]);
        }
        own
    }

    /// 把所有的定时器推进一步，然后重新选路。
    fn poll(&mut self, now: Instant) {
        self.refresh_endpoints(now);
        if self.allow_direct {
            self.addr_query.poll(&self.shared.port, now);
        }
        let clock = &self.shared.clock;
        let active: HashSet<NodeId> = self.peers.iter().filter(|(_, peer)| peer.slot.is_active(clock)).map(|(&id, _)| id).collect();
        self.sync_standing(now);
        self.review_attachments(now);
        self.poll_relays(now, &active);
        self.poll_directs(now);
        self.poll_tests(now);
        self.publish_rows(now);
        let window = self.evaluated.is_none_or(|at| now.saturating_duration_since(at) >= EVAL_WINDOW);
        if window {
            self.evaluated = Some(now);
        }
        let changed = self.update_routes(now, window);
        // 挂靠的 relay 变了（会话刚建好、刚断）也马上公布：别的节点要靠上报的挂靠才找得到本节点，晚半秒就晚通半秒。
        let attachments_changed = self.attachment_ids() != self.published_attachments;
        if changed || attachments_changed || self.status_refreshed.is_none_or(|at| now.saturating_duration_since(at) >= STATUS_REFRESH) {
            self.publish_status(now);
        }
    }

    /// 本节点的候选端点：网卡地址，relay 和地址查询服务器看到的地址，路由器上映射出来的地址。
    fn refresh_endpoints(&mut self, now: Instant) {
        if self.local_refreshed.is_none_or(|at| now.saturating_duration_since(at) >= LOCAL_ADDRESS_REFRESH) {
            let local = outside_overlay(self.shared.port.local_candidates(), &self.netmap);
            if local != self.local_candidates {
                // 网卡地址变了多半是换了网络：网关可能也换了，端口映射要重新申请。头一次读到地址不算变化。
                if let (Some(mapper), true) = (&self.portmap, self.local_refreshed.is_some()) {
                    mapper.network_changed();
                }
                self.local_candidates = local;
                let own = self.own_addresses();
                for entry in self.relays.values_mut() {
                    entry.link.set_own(&own);
                }
            }
            self.local_refreshed = Some(now);
        }
        // 只有公网上的观察点才拿来判断"映射出来的端口是否随对端变化"。
        let observed: Vec<SocketAddr> = self
            .relays
            .values()
            .filter_map(|entry| entry.link.observed(now))
            .chain(self.addr_query.observations(now).map(|observation| observation.observed))
            .collect();
        self.mapping_varies = mapping_varies(&observed);
        let mapping = self.portmap.as_ref().map(PortMapper::mapped).unwrap_or_default();
        let mapped = mapping.udp;
        let mut public: Vec<SocketAddr> = observed.iter().chain(&mapping.udp).chain(&mapping.tcp).copied().collect();
        public.sort_unstable();
        public.dedup();
        if public != self.public_addresses {
            tracing::debug!(addresses = ?public, "别人看到的本节点地址变了");
            self.public_addresses = public;
            self.status_refreshed = None;
        }

        // 两边的公网地址相同，说明在同一个 NAT 后面：对端的私有地址多半就在本节点的局域网里。
        let public: Vec<IpAddr> = observed.iter().chain(&mapped).map(SocketAddr::ip).filter(|ip| !ifaddr::is_private(*ip)).collect();
        for peer in self.peers.values_mut() {
            peer.direct.set_same_nat(shares_public_address(&public, &peer.endpoints));
        }

        // 不建立直连的节点不向别人暴露自己的地址（relay-only）。
        let mut endpoints: Vec<SocketAddr> =
            if self.allow_direct { self.local_candidates.iter().chain(&observed).chain(&mapped).copied().collect() } else { Vec::new() };
        endpoints.sort_unstable();
        endpoints.dedup();
        if endpoints != self.endpoints {
            tracing::debug!(?endpoints, "本节点的候选端点变了");
            self.endpoints = endpoints;
            let clock = &self.shared.clock;
            for peer in self.peers.values_mut() {
                peer.direct.local_changed();
                // 不等流量就试的那些也要按新的端点重试，同样错开，不在同一刻一起发。正在用的照旧马上试。
                if peer.eager_from.is_some() && peer.direct.active().is_none() && !peer.slot.is_active(clock) {
                    peer.eager_from = Some(now + crate::relays::jitter(EAGER_SPREAD));
                }
            }
        }
    }

    /// 重新看一遍到每个对端走哪条路，把变化写进收发路径上的表。`window`：这一轮是不是一个评估窗口的开始。
    /// 返回有没有变化。
    fn update_routes(&mut self, now: Instant, window: bool) -> bool {
        self.broken.retain(|(_, _, until)| now < *until);
        let entries = self.entries(now);
        let Self { shared, key, relays, legs, peers, matrix, broken, allow_direct, allow_relay, mode, max_hops, .. } = self;
        let view = View {
            shared,
            relays,
            legs,
            matrix,
            broken,
            entries: &entries,
            allow_direct: *allow_direct,
            allow_relay: *allow_relay,
            max_hops: *max_hops,
            now,
        };
        let mut claims_changed = false;
        for peer in peers.values_mut() {
            let (sources, active): (Vec<SocketAddr>, _) = if *allow_direct {
                (peer.direct.sources(now).collect(), peer.direct.active().map(|(addr, _)| addr))
            } else {
                (Vec::new(), None)
            };
            if (&sources, active) != (&peer.sources, peer.active_source) {
                peer.sources = sources;
                peer.active_source = active;
                claims_changed = true;
            }
        }
        if claims_changed {
            rebuild_direct(&mut shared.table_mut(), peers);
        }
        let mut announcements = Vec::new();
        for (&id, peer) in peers.iter_mut() {
            peer.unattached.retain(|(_, until)| now < *until);
            peer.suspect.retain(|(_, until)| now < *until);
            match peer.route {
                RouteKey::Relay { path, .. } if path.as_slice().len() > 1 && peer.slot.is_active(&shared.clock) => {
                    if peer.probe.pending.is_some_and(|(_, sent)| now.saturating_duration_since(sent) >= PATH_PROBE_TIMEOUT) {
                        peer.probe.pending = None;
                        peer.probe.missed += 1;
                    }
                    if peer.probe.missed >= MAX_TIMEOUTS {
                        peer.probe = PathProbe { answered: peer.probe.answered, ..PathProbe::default() };
                        peer.suspect.retain(|(suspect, _)| *suspect != path);
                        peer.suspect.push((path, now + SUSPECT_HOLD));
                        peer.hint = Some(RouteHint::PathProbeSilent);
                    } else if peer.probe.pending.is_none() {
                        // 有流量、或者已经丢过探测时探测得勤一些：断了要在几秒之内发现。
                        let busy = peer.probe.missed > 0 || peer.slot.last_tx.within(&shared.clock, PATH_PROBE_BUSY);
                        let interval = if busy { PATH_PROBE_BUSY } else { PROBE_INTERVAL };
                        if peer.probe.last_sent.is_none_or(|at| now.saturating_duration_since(at) >= interval) {
                            let nonce: Nonce = i3t_underlay::random_bytes();
                            let message = probe::Ping::signed_message(shared.me, id, &nonce);
                            let signature = *key.sign(probe::Ping::PURPOSE, &message).as_bytes();
                            peer.slot.send_frame(shared, &probe::Ping { src: shared.me, dst: id, nonce, signature }.to_bytes());
                            peer.probe.pending = Some((nonce, now));
                            peer.probe.last_sent = Some(now);
                        }
                    }
                }
                RouteKey::None | RouteKey::Direct(_) | RouteKey::Relay { .. } => {
                    peer.probe = PathProbe { answered: peer.probe.answered, ..PathProbe::default() };
                }
            }
            // 延迟优先要拿"经本节点的 relay"这条路和别的比，得知道对端的会话那一段多长（见 `View::local_leg`）。
            // 和上面经多级路径的探测错开：对端回答同一个对端的路径探测有频率上限，挤在一起的会被它挡掉一个。
            let apart = peer.probe.pending.is_none()
                && peer.probe.last_sent.is_none_or(|at| now.saturating_duration_since(at) >= LOCAL_PROBE_APART);
            let wanted = *mode == RoutingMode::LowestCost
                && *allow_relay
                && apart
                && peer.slot.is_active(&shared.clock)
                && view.needs_local_probe(id, peer);
            if let Some(nonce) = peer.local_leg.poll(now, wanted, PROBE_INTERVAL) {
                let message = probe::Ping::signed_message(shared.me, id, &nonce);
                let signature = *key.sign(probe::Ping::PURPOSE, &message).as_bytes();
                table::send_frame_via(shared, id, &Hop::Local, &probe::Ping { src: shared.me, dst: id, nonce, signature }.to_bytes());
            }

            let mut why = None;
            let path = match mode {
                RoutingMode::DirectFirst => {
                    // 直连、一个 relay 都走不了时经一串 relay（见 `View::chain`）。现在走着的一串还走得了就不用每一轮重算候选。
                    let single = view.direct_first(id, peer);
                    let chain = match peer.policy_route {
                        RouteKey::Relay { path, .. } if path.as_slice().len() > 1 => {
                            Some(PathId::Relays(path)).filter(|path| view.alive(id, peer, *path))
                        }
                        RouteKey::Relay { .. } | RouteKey::Direct(_) | RouteKey::None => None,
                    };
                    if window || (single.is_none() && chain.is_none()) {
                        peer.candidates = view.candidates(id, peer);
                    }
                    let chosen = single.or_else(|| view.chain(id, peer, &peer.candidates, chain));
                    if window {
                        // 默认模式不拿代价在直连和 relay 之间做选择，算出来给界面看：候选和它们的代价，以及延迟优先模式会选哪条。
                        let usable: Vec<&Candidate> =
                            peer.candidates.iter().filter(|candidate| view.resolve(id, peer, candidate.path).is_some()).collect();
                        peer.other_mode = Some(active::lowest_cost_path(&usable, chosen));
                    }
                    chosen
                }
                RoutingMode::LowestCost => {
                    let current = peer.selector.current();
                    let gone = current.is_none_or(|path| !view.alive(id, peer, path));
                    let lan_waiting = *allow_direct && peer.direct.is_lan_active() && !matches!(current, Some(PathId::Direct(_)));
                    if window || gone || lan_waiting {
                        let mut found = view.candidates(id, peer);
                        found.retain(|candidate| view.resolve(id, peer, candidate.path).is_some());
                        peer.candidates = found;
                        why = peer.selector.choose(now, &peer.candidates, window, &mut random_below);
                    }
                    // 给界面比较：默认模式此刻会选哪条（直连、一个 relay，都没有时一串 relay）。候选刚算过，不多花什么。
                    peer.other_mode = Some(view.default_route(id, peer, &peer.candidates, None));
                    peer.selector.current()
                }
            };
            let (policy_key, policy_hop) = path.and_then(|path| view.resolve(id, peer, path)).unwrap_or((RouteKey::None, Hop::None));
            peer.policy_route = policy_key;
            if peer.pin.is_some_and(|pin| now >= pin.until) {
                tracing::info!(peer = %id, "主动测试固定的路到期了，解除");
                peer.pin = None;
            }
            // 固定的路此刻走不了（直连没了、到第一个 relay 的会话断了）时照常按选路规则走：有路总比没有强。
            let pinned = peer.pin.and_then(|pin| {
                let path = match pin.path {
                    TestPath::Direct => PathId::Direct(peer.direct.active()?.0),
                    TestPath::Relays(relays) => PathId::Relays(relays),
                };
                view.resolve(id, peer, path)
            });
            let was_pinned = peer.pinned;
            peer.pinned = pinned.is_some();
            let (key, hop) = pinned.unwrap_or((policy_key, policy_hop));
            let doubt = match key {
                RouteKey::None => true,
                RouteKey::Direct(_) => peer.direct.in_doubt(),
                RouteKey::Relay { via: Via::Local, .. } => false,
                RouteKey::Relay { path, via: Via::Udp(_) | Via::Tcp(_) } => {
                    relays.get(&path.first()).is_some_and(|entry| entry.link.in_doubt())
                }
            };
            let changed = key != peer.route;
            // 可疑的路又通了，或者换了一条路（包括从没有路到有路）：把攒着的包补发出去。
            let restored = key != RouteKey::None && (changed || (peer.doubt && !doubt));
            if changed {
                // 刚有路时先连上的一个 relay 换成对端排在前面的另一个；从一串 relay 换到一个不算这一种（那是少绕了路）。
                if matches!((peer.route, key), (RouteKey::Relay { path, .. }, RouteKey::Relay { .. }) if path.as_slice().len() == 1)
                    && *mode == RoutingMode::DirectFirst
                    && relay_in_use(peer, now).is_none()
                    && peer.hint.is_none()
                {
                    peer.hint = Some(RouteHint::PreferredRelayReady);
                }
                let hint = peer.hint.take();
                let reason = if peer.pinned {
                    Reason::new(format!("主动测试暂时把路固定在{key}"), RouteCause::TestPinned)
                } else if was_pinned {
                    Reason::new(format!("主动测试结束，回到选路规则选的{key}"), RouteCause::TestEnded)
                } else {
                    match why {
                        Some(why) => explain(why, key, peer.route, &peer.candidates, hint),
                        None => describe(id, peer.route, key, hint),
                    }
                };
                peer.slot.set_hop(hop);
                // 新的路要从头探测。
                peer.probe = PathProbe { answered: peer.probe.answered, ..PathProbe::default() };
                peer.reason.clone_from(&reason);
                peer.switched = Some(now);
                if peer.route == RouteKey::None {
                    peer.first_route = Some(now);
                }
                announcements.push((id, key, reason));
                peer.route = key;
            }
            if doubt != peer.doubt {
                peer.slot.set_doubt(doubt);
                peer.doubt = doubt;
            }
            if restored {
                peer.slot.flush(shared, now);
            }
        }
        let changed = !announcements.is_empty();
        for (id, key, reason) in announcements {
            self.announce(id, key, reason);
        }
        changed
    }

    /// 每一次换路都记一条带原因的日志，并且通知订阅的人。
    fn announce(&self, peer: NodeId, key: RouteKey, reason: Reason) {
        let route = key.to_route();
        tracing::info!(%peer, path = %key, reason = reason.text.as_str(), "到对端的路变了");
        // 没有人订阅时发送会失败，那就是没有人要听。
        let _subscribers = self.shared.changes.send(RouteChange { peer, route, reason: reason.text, cause: reason.cause });
        self.shared.route_changed.notify_waiters();
    }
}

/// 按每个对端认领的来源地址重建收包表里的直连部分。
///
/// 同一个地址可能被几个对端认领：重放的 PING、网络里的恶意成员自己签的 PING，都能让一个对端认领别的对端在用的地址。
/// 所以不能每个对端各改各的条目（那样后来的会覆盖先来的，过期时又会把别人的条目删掉）。按这个顺序归属：
///
/// 1. 正在把它当作直连地址用的对端（它的保活一直在证明这个地址）；
/// 2. 原来就登记着、现在还认领它的对端；
/// 3. 编号最小的那个。
fn rebuild_direct(table: &mut Table, peers: &HashMap<NodeId, PeerState>) {
    let previous = std::mem::take(&mut table.direct);
    let mut ordered: Vec<(&NodeId, &PeerState)> = peers.iter().collect();
    ordered.sort_unstable_by_key(|(id, _)| **id);
    let claims = |id: NodeId, addr: &SocketAddr| peers.get(&id).is_some_and(|peer| peer.sources.contains(addr));
    for (_, peer) in &ordered {
        if let Some(addr) = peer.active_source.filter(|addr| peer.sources.contains(addr)) {
            table.direct.entry(addr).or_insert_with(|| Arc::clone(&peer.slot));
        }
    }
    for &(&id, peer) in &ordered {
        for addr in &peer.sources {
            if let Some(owner) = table.direct.get(addr) {
                if owner.id != id {
                    tracing::debug!(%addr, owner = %owner.id, claimant = %id, "两个对端认领同一个直连地址，只算其中一个的");
                }
                continue;
            }
            let owner = previous.get(addr).filter(|owner| claims(owner.id, addr)).unwrap_or(&peer.slot);
            table.direct.insert(*addr, Arc::clone(owner));
        }
    }
}

/// 对端回答直连探测时报的、它看到的本节点地址 `observed` 像不像真的是本节点的。
///
/// 有人在两个节点之间来回转发探测（经过的 relay、局域网里恰好占着某个候选地址的主机），两边就会把它的地址验证成对方的直连地址，
/// 流量改走它那里。这时对端看到的是转发者的地址，不是本节点的，所以看一眼就分得出来：
///
/// - `local_network`：探测发往的地址不经过地址转换（私有地址、局域网信标里来的）。对端看到的必须是本节点网卡上的地址。
/// - 其余的：必须是本节点已知的地址之一（网卡上的，relay 和地址查询服务器看到的，路由器映射出来的）。
///   本节点还不知道自己这个地址族的任何公网地址时没法判断，只好接受。
///
/// 读不到网卡地址时同样没法判断，接受。
fn observed_is_mine(observed: SocketAddr, local_network: bool, interfaces: &[SocketAddr], known: &[SocketAddr]) -> bool {
    let ip = observed.ip().to_canonical();
    let same = |addr: &SocketAddr| addr.ip().to_canonical() == ip;
    if local_network {
        return interfaces.is_empty() || interfaces.iter().any(same);
    }
    let public_known =
        known.iter().map(|addr| addr.ip().to_canonical()).any(|own| own.is_ipv4() == ip.is_ipv4() && !ifaddr::is_private(own));
    !public_known || known.iter().chain(interfaces).any(same)
}

/// 这个对端此刻适用的直连限制。
///
/// 一对正在用的节点（有包要发、或者有人要和它通信）要直连；小网络里不等流量的那些对端（[`EAGER_DIRECT_PEERS`]）过了错开的时刻也要。
/// 后一种只是在路径层验证这条直连、照常保活和退避：不碰连接层，不建连接，也不让已有的连接晚关一点；第一条流来的时候路已经是直连。
///
/// 对端刚发来过打洞信令的也要（[`PeerState::signalled`]）：它想和本端建立直连，后面几轮探测要跟上。这不等于本端有包要发给它：
/// 信令不算流量。原来算，小网络里对端每分钟不等流量地试一次直连，直连又永远打不通时（比如它没有 UDP），本端就每分钟
/// 把它当成活跃的 45 秒：为它建一次临时的中转会话、把路换过去，会话回收之后路又换回来，一直这样来回。
fn direct_policy<'a>(
    shared: &Shared,
    allow_direct: bool,
    node_dial_out_only: bool,
    mode: RoutingMode,
    endpoints: &'a [SocketAddr],
    peer: &PeerState,
    now: Instant,
) -> Policy<'a> {
    let clock = &shared.clock;
    let in_use = peer.slot.is_active(clock);
    let eager = peer.eager_from.is_some_and(|from| now >= from);
    let answering = peer.signalled.is_some_and(|at| now.saturating_duration_since(at) < PEER_ACTIVE);
    Policy {
        wanted: allow_direct && (in_use || eager || answering),
        initiate: !peer.dial_out_only,
        signal: !node_dial_out_only && !peer.dial_out_only,
        silent: matches!(peer.route, RouteKey::Direct(_)) && table::unanswered(clock, &peer.slot.last_tx, &peer.slot.last_rx_direct),
        local: endpoints,
        // 延迟优先模式下直连是要和 relay 路径比代价的候选，丢包率得测出来；没在用的对端不用为它多发探测包列。
        train: mode == RoutingMode::LowestCost && in_use,
    }
}

/// 不等流量就试直连的对端（[`EAGER_DIRECT_PEERS`]）：本节点能访问的对端不超过 `limit` 个时，其中上报了端点的那些。
///
/// 不这样试的：本节点只主动连接（它不参与打洞）或者只经 relay；对端只主动连接（它不理别人主动的探测）；对端上报的端点是空的
/// （只经 relay 的节点 controller 不下发它的地址，还没上报过的节点也是这样）；访问规则不让本节点访问的对端（`outbound`）。
/// 它们在第一次用到时照旧试。
fn eager_direct(netmap: &Netmap, limit: usize) -> HashSet<NodeId> {
    let reach = netmap.me.reach.unwrap_or(netmap.network.reach);
    let reachable = || netmap.peers.iter().filter(|peer| peer.id != netmap.me.id && peer.outbound);
    if reach == Reach::RelayOnly || netmap.me.dial_out_only || reachable().count() > limit {
        return HashSet::new();
    }
    reachable().filter(|peer| !peer.dial_out_only && !peer.endpoints.is_empty()).map(|peer| peer.id).collect()
}

/// [`EAGER_DIRECT_PEERS`]，测试可以用环境变量改。
fn eager_direct_limit() -> usize {
    static LIMIT: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        std::env::var(EAGER_DIRECT_TEST_SWITCH).ok().and_then(|value| value.parse().ok()).unwrap_or(EAGER_DIRECT_PEERS)
    });
    *LIMIT
}

/// 映射出来的端口是不是随对端变化。要有两个以上的观察点看到同一个地址族的地址才知道。
/// 去掉覆盖网的地址：本节点的虚拟 IP 在虚拟网卡上（`i3t-vnet`），它只在组网里有意义，
/// 别的节点连不上它，也不该去试。
fn outside_overlay(candidates: Vec<SocketAddr>, netmap: &Netmap) -> Vec<SocketAddr> {
    candidates.into_iter().filter(|addr| !netmap.network.is_overlay_address(addr.ip().to_canonical())).collect()
}

fn mapping_varies(observed: &[SocketAddr]) -> Option<bool> {
    let verdict = |family: fn(&SocketAddr) -> bool| {
        let mut seen = observed.iter().filter(|addr| family(addr));
        let first = seen.next()?;
        let mut rest = seen.peekable();
        rest.peek()?;
        Some(rest.any(|addr| addr != first))
    };
    // IPv4 上才有地址转换的问题，先看它；没有 IPv4 的观察时再看 IPv6（有的网络也给 IPv6 做转换）。
    verdict(SocketAddr::is_ipv4).or_else(|| verdict(SocketAddr::is_ipv6))
}

/// 对端上报的端点里有没有和本节点相同的公网地址（端口不算）。有的话两个节点在同一个 NAT 后面。
/// `public` 是别人看到的本节点的公网地址。
fn shares_public_address(public: &[IpAddr], peer_endpoints: &[SocketAddr]) -> bool {
    peer_endpoints.iter().map(SocketAddr::ip).any(|ip| !ifaddr::is_private(ip) && public.contains(&ip))
}

/// 0 到 `bound - 1` 之间的一个随机数。
fn random_below(bound: usize) -> usize {
    let raw = u32::from_be_bytes(i3t_underlay::random_bytes());
    usize::try_from(raw).unwrap_or(0) % bound.max(1)
}

#[cfg(test)]
mod tests {
    use i3t_crypto::Signature;
    use i3t_proto::backbone::Link;
    use i3t_proto::probe::{TestPing, TestPong};

    use super::*;
    use crate::SessionLeg;
    use crate::relays::Complaint;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn overlay_addresses_on_local_interfaces_are_never_candidates() {
        let netmap: Netmap = serde_json::from_value(serde_json::json!({
            "version": 1,
            "network": { "name": "test", "domain": "test.i3t", "cidr": "10.66.0.0/16" },
            "me": { "id": 1, "name": "me", "virtual_ip": "10.66.0.1" }
        }))
        .unwrap();
        let local = vec![addr("192.168.1.5:20330"), addr("10.66.0.1:20330"), addr("[2001:db8::5]:20330"), addr("10.67.0.1:20330")];
        assert_eq!(
            outside_overlay(local, &netmap),
            [addr("192.168.1.5:20330"), addr("[2001:db8::5]:20330"), addr("10.67.0.1:20330")],
            "虚拟网卡上的虚拟 IP 不公布给别人"
        );
    }

    /// 一份 netmap：本节点 1（`me` 里的字段加进去），对端 2..=`count`+1，各自上报一个端点、本节点能访问它们。
    /// `peer` 改其中某个对端的字段。
    fn netmap_with(count: u32, me: &serde_json::Value, peer: impl Fn(u32, &mut serde_json::Value)) -> Netmap {
        let peers: Vec<serde_json::Value> = (2..count + 2)
            .map(|id| {
                let mut entry = serde_json::json!({
                    "id": id, "key": i3t_proto::PublicKey::from_bytes([2; 32]), "name": format!("n{id}"), "virtual_ip": format!("10.66.0.{id}"),
                    "inbound": true, "outbound": true, "endpoints": [format!("203.0.113.{id}:20330")],
                });
                peer(id, &mut entry);
                entry
            })
            .collect();
        let mut local = serde_json::json!({ "id": 1, "name": "me", "virtual_ip": "10.66.0.1" });
        local.as_object_mut().unwrap().extend(me.as_object().cloned().unwrap_or_default());
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "network": { "name": "test", "domain": "test.i3t", "cidr": "10.66.0.0/16" },
            "me": local,
            "peers": peers,
        }))
        .unwrap()
    }

    #[test]
    fn a_node_with_few_peers_tries_the_direct_path_to_each_without_waiting_for_traffic_and_one_with_many_does_not() {
        let none = serde_json::json!({});
        let tried = |netmap: &Netmap| {
            let mut ids: Vec<u32> = eager_direct(netmap, EAGER_DIRECT_PEERS).iter().map(|id| id.get()).collect();
            ids.sort_unstable();
            ids
        };
        assert_eq!(tried(&netmap_with(3, &none, |_, _| {})), [2, 3, 4]);
        assert_eq!(tried(&netmap_with(32, &none, |_, _| {})).len(), 32, "正好在上限上的照样试");
        assert!(tried(&netmap_with(33, &none, |_, _| {})).is_empty(), "超过上限：照旧在第一次用到时才试");
        // 只数本节点能访问的：访问规则不让本节点访问的对端不算数，也不试。
        let reachable_only = netmap_with(40, &none, |id, peer| peer["outbound"] = serde_json::json!(id < 10));
        assert_eq!(tried(&reachable_only), [2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn nodes_and_peers_that_take_no_part_in_direct_paths_are_not_tried_without_traffic() {
        let none = serde_json::json!({});
        let tried = |netmap: &Netmap| eager_direct(netmap, EAGER_DIRECT_PEERS).len();
        assert_eq!(tried(&netmap_with(3, &serde_json::json!({ "dial_out_only": true }), |_, _| {})), 0, "本节点只主动连接");
        assert_eq!(tried(&netmap_with(3, &serde_json::json!({ "reach": "relay_only" }), |_, _| {})), 0, "本节点只经 relay");
        let relay_only_network: Netmap = {
            let mut netmap = netmap_with(3, &none, |_, _| {});
            netmap.network.reach = Reach::RelayOnly;
            netmap
        };
        assert_eq!(tried(&relay_only_network), 0, "网络默认只经 relay");
        let picky = netmap_with(4, &none, |id, peer| match id {
            2 => peer["dial_out_only"] = serde_json::json!(true),
            // 只经 relay 的对端：controller 不下发它的地址。
            3 => peer["endpoints"] = serde_json::json!([]),
            4 => peer["outbound"] = serde_json::json!(false),
            _ => {}
        });
        let ids: Vec<u32> = eager_direct(&picky, EAGER_DIRECT_PEERS).iter().map(|id| id.get()).collect();
        assert_eq!(ids, [5]);
    }

    #[tokio::test]
    async fn a_punch_signal_keeps_the_direct_attempt_going_but_is_not_traffic() {
        let mut harness = Harness::new(&[(2, &[addr("203.0.113.2:20330")])]);
        let now = Instant::now();
        // 不是"不等流量就试"的对端：只看信令。
        harness.control.peers.get_mut(&node(2)).unwrap().eager_from = None;
        let wanted = |harness: &Harness, at: Instant| {
            direct_policy(&harness.control.shared, true, false, RoutingMode::DirectFirst, &[], &harness.control.peers[&node(2)], at).wanted
        };
        assert!(!wanted(&harness, now), "没有流量也没有信令：不试");

        harness.control.on_signal(node(2), &Signal::PunchRequest { endpoints: vec![addr("203.0.113.2:20330")] }, now);
        let peer = &harness.control.peers[&node(2)];
        assert!(!peer.slot.is_active(&harness.control.shared.clock), "信令不算流量：不为它建中转会话，也不动到它的路");
        assert!(wanted(&harness, now + Duration::from_secs(1)), "陪它把直连试完");
        assert!(!wanted(&harness, now + PEER_ACTIVE), "过了这一阵就不再试");
    }

    #[tokio::test]
    async fn the_eager_attempts_are_spread_out_and_restart_for_new_addresses_but_open_no_traffic() {
        let mut harness = Harness::new(&[(2, &[addr("203.0.113.2:20330")]), (3, &[addr("203.0.113.3:20330")])]);
        let start = Instant::now();
        let from = |harness: &Harness, id: u32| harness.control.peers[&node(id)].eager_from;
        let first = (from(&harness, 2).unwrap(), from(&harness, 3).unwrap());
        assert!(first.0 <= start + EAGER_SPREAD && first.1 <= start + EAGER_SPREAD, "几秒之内都开始");
        let peer = &harness.control.peers[&node(2)];
        assert!(!peer.slot.is_active(&harness.control.shared.clock), "不等流量的尝试不算有流量：不让连接层觉得它在用");
        let policy = direct_policy(&harness.control.shared, true, false, RoutingMode::LowestCost, &[], peer, first.0);
        assert!(policy.wanted && !policy.train, "到点就试；没在用的对端不为它发探测包列");
        let early = direct_policy(&harness.control.shared, true, false, RoutingMode::DirectFirst, &[], peer, start);
        assert_eq!(early.wanted, first.0 <= start);

        // 同一份 netmap 再来一次：不重新错开。对端 3 上报了新的地址：它重新错开开始。
        let netmap = Arc::clone(&harness.control.netmap);
        harness.control.apply_netmap(Arc::clone(&netmap), start + Duration::from_secs(10));
        assert_eq!(from(&harness, 2), Some(first.0));
        let mut moved = (*netmap).clone();
        moved.peers.iter_mut().find(|peer| peer.id == node(3)).unwrap().endpoints = vec![addr("198.51.100.3:20330")];
        let later = start + Duration::from_secs(20);
        harness.control.apply_netmap(Arc::new(moved), later);
        assert!(from(&harness, 3).is_some_and(|at| at >= later && at <= later + EAGER_SPREAD));
        assert_eq!(from(&harness, 2), Some(first.0));
    }

    #[test]
    fn mapping_variation_needs_two_observers_of_the_same_family() {
        assert_eq!(mapping_varies(&[]), None);
        assert_eq!(mapping_varies(&[addr("203.0.113.7:4000")]), None);
        assert_eq!(mapping_varies(&[addr("203.0.113.7:4000"), addr("[2001:db8::1]:4000")]), None, "两个地址族各一个，比不了");
        assert_eq!(mapping_varies(&[addr("203.0.113.7:4000"), addr("203.0.113.7:4000")]), Some(false));
        assert_eq!(mapping_varies(&[addr("203.0.113.7:4000"), addr("203.0.113.7:4001")]), Some(true), "端口随对端变化");
        assert_eq!(mapping_varies(&[addr("203.0.113.7:4000"), addr("203.0.113.8:4000")]), Some(true));
        let v6 = [addr("[2001:db8::1]:4000"), addr("[2001:db8::1]:4000")];
        assert_eq!(mapping_varies(&v6), Some(false));
    }

    /// 一个只有控制任务、没有收包路径的节点：测试直接调用它处理帧的方法，看它发出了什么、表里记了什么。
    struct Harness {
        control: Control,
        /// 各个对端的密钥，测试拿它们签探测帧。
        keys: HashMap<NodeId, NodeKey>,
        _queues: [mpsc::Receiver<Ctrl>; 3],
    }

    const ME: u32 = 1;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    impl Harness {
        /// 本节点是 1。`peers` 是对端的编号和它在 netmap 里上报的端点。
        fn new(peers: &[(u32, &[SocketAddr])]) -> Self {
            Self::with_me(peers, &serde_json::json!({}))
        }

        /// 同 [`new`](Self::new)，`me` 里的字段加进 netmap 里本节点的那一项（例如路径限制）。
        fn with_me(peers: &[(u32, &[SocketAddr])], me: &serde_json::Value) -> Self {
            let keys: HashMap<NodeId, NodeKey> = peers.iter().map(|&(id, _)| (node(id), NodeKey::generate().unwrap())).collect();
            let entries: Vec<serde_json::Value> = peers
                .iter()
                .map(|&(id, endpoints)| {
                    serde_json::json!({
                        "id": id, "key": keys[&node(id)].public(), "name": format!("n{id}"), "virtual_ip": format!("10.66.0.{id}"),
                        "inbound": true, "outbound": true, "endpoints": endpoints,
                    })
                })
                .collect();
            let mut local = serde_json::json!({ "id": ME, "name": "me", "virtual_ip": "10.66.0.1" });
            local.as_object_mut().unwrap().extend(me.as_object().cloned().unwrap_or_default());
            let netmap = serde_json::json!({
                "version": 1,
                "network": { "name": "test", "domain": "test.i3t", "cidr": "10.66.0.0/16" },
                "me": local,
                "peers": entries,
            });
            let port = Arc::new(i3t_underlay::UdpPort::bind(addr("127.0.0.1:0")).unwrap());
            let (shared, queues) = Shared::for_tests(node(ME), port, 16);
            let control =
                Control::new(shared, Arc::new(NodeKey::generate().unwrap()), Arc::new(serde_json::from_value(netmap).unwrap()), Vec::new());
            Self { control, keys, _queues: queues }
        }

        fn me(&self) -> SocketAddr {
            self.control.shared.port.local_addr()
        }

        fn ping(&self, from: u32, nonce: Nonce) -> probe::Ping {
            let (src, dst) = (node(from), node(ME));
            let signature = *self.keys[&src].sign(probe::Ping::PURPOSE, &probe::Ping::signed_message(src, dst, &nonce)).as_bytes();
            probe::Ping { src, dst, nonce, signature }
        }

        fn pong(&self, from: u32, nonce: Nonce, observed: SocketAddr) -> probe::Pong {
            let (src, dst) = (node(from), node(ME));
            let message = probe::Pong::signed_message(src, dst, &nonce, observed);
            probe::Pong { src, dst, nonce, observed, signature: *self.keys[&src].sign(probe::Pong::PURPOSE, &message).as_bytes() }
        }

        fn direct_owner(&self, addr: SocketAddr) -> Option<NodeId> {
            self.control.shared.table().direct.get(&addr).map(|slot| slot.id)
        }
    }

    /// 一个扮演对端地址的 UDP socket。
    struct Socket(tokio::net::UdpSocket);

    impl Socket {
        async fn new() -> Self {
            Self(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap())
        }

        fn addr(&self) -> SocketAddr {
            self.0.local_addr().unwrap()
        }

        /// 收到的下一个探测帧；等一会儿还没有就是 `None`。
        async fn probe(&self) -> Option<probe::Frame> {
            let mut buf = [0u8; 2048];
            let (len, _) = tokio::time::timeout(Duration::from_millis(300), self.0.recv_from(&mut buf)).await.ok()?.ok()?;
            probe::Frame::parse(&buf[..len])
        }

        /// 收完眼下到了的测试探测的回答。
        async fn test_pongs(&self) -> Vec<TestPong> {
            let mut pongs = Vec::new();
            while let Some(frame) = self.probe().await {
                if let probe::Frame::TestPong(pong) = frame {
                    pongs.push(pong);
                }
            }
            pongs
        }

        /// 收完眼下到了的探测帧，返回其中的 PONG 和 PING。
        async fn drain(&self) -> (Vec<probe::Pong>, Vec<probe::Ping>) {
            let (mut pongs, mut pings) = (Vec::new(), Vec::new());
            while let Some(frame) = self.probe().await {
                match frame {
                    probe::Frame::Pong(pong) => pongs.push(pong),
                    probe::Frame::Ping(ping) => pings.push(ping),
                    probe::Frame::TestPing(_) | probe::Frame::TestPong(_) => {}
                }
            }
            (pongs, pings)
        }
    }

    /// 对端 `peer` 从 `socket` 的地址验证通过、成为本节点在用的直连地址。
    async fn validate(harness: &mut Harness, peer: u32, socket: &Socket, now: Instant) {
        let ping = harness.ping(peer, [peer.to_be_bytes()[3]; 8]);
        harness.control.on_ping(socket.addr(), &ping, now);
        let (_, reverse) = socket.drain().await;
        let pong = harness.pong(peer, reverse[0].nonce, harness.me());
        harness.control.on_pong(socket.addr(), &pong, now);
        assert_eq!(harness.control.peers[&node(peer)].direct.active().map(|(addr, _)| addr), Some(socket.addr()));
    }

    #[tokio::test]
    async fn a_replayed_ping_can_neither_take_over_nor_later_remove_another_peers_direct_address() {
        let c = Socket::new().await;
        let mut harness = Harness::new(&[(2, &[]), (3, &[])]);
        let start = Instant::now();
        validate(&mut harness, 3, &c, start).await;
        harness.control.update_routes(start, false);
        assert_eq!(harness.direct_owner(c.addr()), Some(node(3)));

        // 对端 2 的一个签名真实的 PING，以 3 的直连地址为来源重放过来（或者 2 自己签了一个这样发）。
        let replayed = harness.ping(2, [0x22; 8]);
        harness.control.on_ping(c.addr(), &replayed, start + Duration::from_secs(1));
        harness.control.update_routes(start + Duration::from_secs(1), false);
        assert_eq!(harness.direct_owner(c.addr()), Some(node(3)), "3 正在用这个地址，它的包不能被当成 2 的");

        // 2 对这个地址的认领过期了：3 的条目不能跟着被删掉。
        harness.control.update_routes(start + Duration::from_secs(20), false);
        assert_eq!(harness.direct_owner(c.addr()), Some(node(3)));
    }

    #[tokio::test]
    async fn forged_pings_cannot_use_up_the_budget_of_real_ones() {
        let (a_known, stranger, c_new) = (Socket::new().await, Socket::new().await, Socket::new().await);
        let mut harness = Harness::new(&[(2, &[a_known.addr()]), (3, &[])]);
        let now = Instant::now();
        // 不认识的地址灌进来两百个自称是 2 的 PING，签名是瞎编的。
        for index in 0..200u8 {
            let forged = probe::Ping { signature: [index; 64], ..harness.ping(2, [index; 8]) };
            harness.control.on_ping(stranger.addr(), &forged, now);
        }
        // 2 从它上报过的地址发来的真 PING 照样有回答。
        harness.control.on_ping(a_known.addr(), &harness.ping(2, [1; 8]), now);
        assert_eq!(a_known.drain().await.0.len(), 1, "上报过的地址有自己的额度");
        // 3 从一个新地址发来的真 PING 也有回答：伪造的只花掉了"自称是 2 的"那一份。
        harness.control.on_ping(c_new.addr(), &harness.ping(3, [2; 8]), now);
        assert_eq!(c_new.drain().await.0.len(), 1, "别的对端的陌生地址还有额度");
        assert!(stranger.drain().await.0.is_empty());
    }

    #[tokio::test]
    async fn a_forged_path_probe_costs_its_peer_the_answering_slot_before_the_signature_is_checked() {
        let mut harness = Harness::new(&[(2, &[])]);
        let now = Instant::now();
        let forged = probe::Ping { signature: [0; 64], ..harness.ping(2, [1; 8]) };
        harness.control.on_path_ping(node(2), &forged, now);
        assert_eq!(harness.control.peers[&node(2)].probe.answered, Some(now), "签名不对的也算一次，验签的次数才有上限");
    }

    #[tokio::test]
    async fn a_pong_reporting_an_address_that_is_not_this_nodes_does_not_validate_the_candidate() {
        let a = Socket::new().await;
        let mut harness = Harness::new(&[(2, &[a.addr()])]);
        let now = Instant::now();
        harness.control.on_ping(a.addr(), &harness.ping(2, [1; 8]), now);
        let (_, reverse) = a.drain().await;
        // 有人在中间来回转发：对端看到的探测是从转发者的地址来的。
        let relayed = harness.pong(2, reverse[0].nonce, addr("198.51.100.77:4000"));
        harness.control.on_pong(a.addr(), &relayed, now);
        assert_eq!(harness.control.peers[&node(2)].direct.active(), None);
        let genuine = harness.pong(2, reverse[0].nonce, harness.me());
        harness.control.on_pong(a.addr(), &genuine, now);
        assert!(harness.control.peers[&node(2)].direct.active().is_some());
    }

    #[test]
    fn an_observed_address_has_to_be_one_this_node_is_known_by() {
        let interfaces = [addr("192.168.1.5:20330"), addr("[2001:db8::5]:20330")];
        let known = [interfaces[0], interfaces[1], addr("203.0.113.7:41000")];
        // 局域网里的地址：对端看到的必须是本节点网卡上的地址。
        assert!(observed_is_mine(addr("192.168.1.5:20330"), true, &interfaces, &known));
        assert!(!observed_is_mine(addr("192.168.1.66:20330"), true, &interfaces, &known));
        assert!(!observed_is_mine(addr("203.0.113.7:41000"), true, &interfaces, &known));
        // 公网上的：relay 看到的地址也算，端口不算。
        assert!(observed_is_mine(addr("203.0.113.7:5555"), false, &interfaces, &known));
        assert!(observed_is_mine(addr("[2001:db8::5]:1"), false, &interfaces, &known));
        assert!(!observed_is_mine(addr("198.51.100.77:4000"), false, &interfaces, &known));
        // 还不知道自己的公网地址（没有 relay，也没有地址查询服务器）：没法判断，只好接受。
        assert!(observed_is_mine(addr("198.51.100.77:4000"), false, &interfaces, &interfaces));
        assert!(observed_is_mine(addr("192.168.1.66:20330"), true, &[], &[]), "读不到网卡地址");
    }

    #[tokio::test]
    async fn a_complaint_about_a_path_this_node_is_not_using_is_ignored_and_repeats_do_not_pile_up() {
        let mut harness = Harness::new(&[(2, &[])]);
        let now = Instant::now();
        harness.control.on_complaint(node(9), Complaint::RouteUnavailable(node(8)), now);
        assert!(harness.control.broken.is_empty(), "本节点没有在走 9 → 8");

        let path = RelayPath::new(&[node(9), node(8)]).unwrap();
        harness.control.peers.get_mut(&node(2)).unwrap().route = RouteKey::Relay { path, via: Via::Udp(addr("198.51.100.9:20330")) };
        for next in 1..=1000u32 {
            harness.control.on_complaint(node(9), Complaint::RouteUnavailable(node(next)), now);
        }
        harness.control.on_complaint(node(9), Complaint::RouteUnavailable(node(8)), now);
        let broken: Vec<(NodeId, NodeId)> = harness.control.broken.iter().map(|&(from, to, _)| (from, to)).collect();
        assert_eq!(broken, [(node(9), node(8)), (node(9), node(9))], "只记正在走的那一段，和 9 自己不肯转发多级路径");
    }

    #[test]
    fn rows_of_one_relay_cannot_use_up_the_budget_of_another() {
        let now = Instant::now();
        let (mut noisy, mut quiet) = (RowGate::new(now), RowGate::new(now));
        assert_eq!((0..100).filter(|_| noisy.budget.take(now)).count(), 5);
        assert!(quiet.budget.take(now));
        assert!(noisy.budget.take(now + Duration::from_millis(500)), "之后每秒 2 个");
        assert!(noisy.forward(now) && !noisy.forward(now + Duration::from_millis(999)), "状态变了的行每秒最多立刻转一次");
        assert!(noisy.forward(now + ROW_FORWARD_GAP));
    }

    #[test]
    fn peers_behind_the_same_nat_are_recognised_by_a_shared_public_address() {
        let public: Vec<IpAddr> = vec!["203.0.113.7".parse().unwrap()];
        // 对端上报的反射地址和本节点的是同一个 IP（端口不同）：在同一个 NAT 后面。
        assert!(shares_public_address(&public, &[addr("192.168.1.9:20330"), addr("203.0.113.7:41000")]));
        assert!(!shares_public_address(&public, &[addr("192.168.1.9:20330"), addr("203.0.113.8:41000")]));
        // 两边都只有私有地址说明不了什么：不相干的两个网络可以用同一个私有网段。
        assert!(!shares_public_address(&["192.168.1.5".parse().unwrap()], &[addr("192.168.1.5:20330")]));
        assert!(!shares_public_address(&[], &[addr("203.0.113.7:41000")]));
    }

    #[test]
    fn the_random_pick_stays_within_bounds() {
        assert!((0..1000).all(|_| random_below(3) < 3));
        assert_eq!(random_below(1), 0);
        assert_eq!(random_below(0), 0);
    }

    /// 本节点自己的 relay，只说哪些对端在它上面有会话。
    struct LocalSessions(Vec<NodeId>);

    impl crate::LocalRelay for LocalSessions {
        fn handle_udp(&self, _from: SocketAddr, _ecn: Option<i3t_underlay::Ecn>, _data: &[u8], _stride: usize) {}

        fn has_session(&self, client: NodeId) -> bool {
            self.0.contains(&client)
        }

        fn session_reopened(&self, _client: NodeId) -> Option<Duration> {
            None
        }

        fn session_at(&self, _client: NodeId, _from: SocketAddr) -> bool {
            false
        }

        fn send_to_client(&self, _client: NodeId, _contents: &[u8], _segment_size: Option<usize>, _ecn: Option<i3t_underlay::Ecn>) -> bool {
            true
        }

        fn session_leg(&self, client: NodeId) -> Option<crate::SessionLeg> {
            self.has_session(client).then_some(SessionLeg::Udp)
        }

        fn handle_leg_frame(&self, _conn: u64, _addr: SocketAddr, _sender: &i3t_underlay::tcp_leg::FrameSender, _frame: &[u8]) {}

        fn leg_closed(&self, _conn: u64) {}

        fn status(&self) -> Option<crate::RelayStatus> {
            None
        }

        fn publish_row(&self, _links: &[Link]) {}

        fn broadcast(&self, _frame: &[u8]) {}
    }

    #[tokio::test]
    async fn a_pinned_route_overrides_the_policy_until_it_is_released_or_runs_out() {
        let socket = Socket::new().await;
        let mut harness = Harness::new(&[(2, &[])]);
        let start = Instant::now();
        assert!(harness.control.shared.local_relay.set(Arc::new(LocalSessions(vec![node(2)]))).is_ok());
        validate(&mut harness, 2, &socket, start).await;
        harness.control.update_routes(start, true);
        let direct = RouteKey::Direct(socket.addr());
        let route = |harness: &Harness| harness.control.peers[&node(2)].route;
        assert_eq!(route(&harness), direct, "默认模式：直连可用就走直连");

        // 固定在本节点自己的 relay 上（对端在它上面有会话）：选路规则照样选直连，走的却是被固定的路。
        let own = RelayPath::new(&[node(ME)]).unwrap();
        let pinned = RouteKey::Relay { path: own, via: Via::Local };
        let mut changes = harness.control.shared.changes.subscribe();
        harness.control.pin(node(2), Pin { id: 1, path: TestPath::Relays(own), until: start + Duration::from_secs(10) }, start);
        harness.control.update_routes(start, false);
        assert_eq!(route(&harness), pinned);
        assert_eq!(harness.control.peers[&node(2)].policy_route, direct, "选路规则选的还是直连");
        let decision = harness.control.decide(node(2), start).unwrap();
        assert_eq!(decision.current, direct.to_route(), "测试的结果里写的是规则选的路，不是测试自己固定的");
        let change = changes.try_recv().unwrap();
        assert!(change.reason.contains("主动测试暂时把路固定在"));
        assert_eq!(change.cause, RouteCause::TestPinned);
        let peer = &harness.control.peers[&node(2)];
        assert_eq!(harness.control.report(node(2), peer, start).cause, Some(RouteCause::TestPinned), "现问时说的也是同一个原因");

        // 别的固定的解除不算数；这一次的解除之后回到直连。
        harness.control.unpin(node(2), 7);
        harness.control.update_routes(start, false);
        assert_eq!(route(&harness), pinned);
        harness.control.unpin(node(2), 1);
        harness.control.update_routes(start, false);
        assert_eq!(route(&harness), direct);
        let change = changes.try_recv().unwrap();
        assert!(change.reason.contains("主动测试结束"));
        assert_eq!(change.cause, RouteCause::TestEnded);

        // 到期的固定由控制任务自己解除，拿着它的一方什么都不用做。
        harness.control.pin(node(2), Pin { id: 2, path: TestPath::Relays(own), until: start + Duration::from_secs(1) }, start);
        harness.control.update_routes(start, false);
        assert_eq!(route(&harness), pinned);
        harness.control.update_routes(start + Duration::from_secs(2), false);
        assert_eq!((route(&harness), harness.control.peers[&node(2)].pin), (direct, None));

        // 不管要多久，最多固定 MAX_PIN。
        harness.control.pin(node(2), Pin { id: 3, path: TestPath::Direct, until: start + Duration::from_secs(3600) }, start);
        assert_eq!(harness.control.peers[&node(2)].pin.map(|pin| pin.until), Some(start + crate::diag::MAX_PIN));
    }

    fn test_ping(harness: &Harness, from: u32, test: TestId, seq: u32, path: Option<RelayPath>) -> TestPing {
        let (src, dst) = (node(from), node(ME));
        let ping = TestPing { src, dst, test, seq, path, signature: [0; 64] };
        TestPing { signature: *harness.keys[&src].sign(TestPing::PURPOSE, &ping.signed_message()).as_bytes(), ..ping }
    }

    fn window(peer: u32, test: TestId, max_probes: u32) -> TestSpec {
        TestSpec { test, peer: node(peer), side: Side::Lead, window: Duration::from_secs(10), max_probes, relays: Vec::new() }
    }

    #[tokio::test]
    async fn test_probes_are_answered_only_inside_an_open_test_from_its_peer_once_each_up_to_the_limit() {
        let a = Socket::new().await;
        let mut harness = Harness::new(&[(2, &[]), (3, &[])]);
        let now = Instant::now();
        let me = harness.control.key.public();

        harness.control.on_test_ping(a.addr(), &test_ping(&harness, 2, 7, 0, None), now, false, now);
        assert!(a.test_pongs().await.is_empty(), "没有打开的测试不回答：对端自己开不了测试");
        assert!(!harness.control.shared.expects_test(7, node(2)), "收包路径也不会把它交上来");

        harness.control.open_test(&window(2, 7, 3), now);
        assert!(harness.control.shared.expects_test(7, node(2)));
        harness.control.on_test_ping(a.addr(), &test_ping(&harness, 2, 7, 0, None), now, false, now);
        let pongs = a.test_pongs().await;
        assert_eq!(pongs.len(), 1, "直连的探测回到它的来源地址");
        let pong = pongs[0];
        assert_eq!((pong.seq, pong.received, pong.same_path, pong.dst), (0, 1, true, node(2)));
        assert!(i3t_crypto::verify(&me, TestPong::PURPOSE, &pong.signed_message(), &Signature::from_bytes(pong.signature)).is_ok());

        harness.control.on_test_ping(a.addr(), &test_ping(&harness, 2, 7, 0, None), now, false, now);
        assert!(a.test_pongs().await.is_empty(), "重放的探测不回答第二次");
        harness.control.on_test_ping(a.addr(), &test_ping(&harness, 3, 7, 1, None), now, false, now);
        assert!(a.test_pongs().await.is_empty(), "别的对端拿着这个编号也不行");
        let forged = TestPing { signature: [0; 64], ..test_ping(&harness, 2, 7, 1, None) };
        harness.control.on_test_ping(a.addr(), &forged, now, false, now);
        assert!(a.test_pongs().await.is_empty(), "签名不对");
        harness.control.on_test_ping(a.addr(), &test_ping(&harness, 2, 7, 1, None), now, true, now);
        assert!(a.test_pongs().await.is_empty(), "说是直连、却是经 relay 来的");

        for seq in 1..5 {
            harness.control.on_test_ping(a.addr(), &test_ping(&harness, 2, 7, seq, None), now, false, now);
        }
        let answered: Vec<u32> = a.test_pongs().await.iter().map(|pong| pong.seq).collect();
        assert_eq!(answered, [1, 2], "这个测试最多回答 3 个");

        harness.control.open_test(&window(2, 8, 10), now);
        let later = now + Duration::from_secs(11);
        harness.control.on_test_ping(a.addr(), &test_ping(&harness, 2, 8, 0, None), later, false, later);
        assert!(a.test_pongs().await.is_empty(), "时间窗过了");
        harness.control.poll_tests(later);
        assert!(!harness.control.shared.expects_test(8, node(2)), "过了时间窗的测试自己关掉");
        harness.control.close_test(7, "测试结束");
        assert!(!harness.control.shared.expects_test(7, node(2)));
    }

    #[tokio::test]
    async fn a_relay_only_node_answers_no_direct_test_probe_and_refuses_to_try_a_direct_path() {
        let a = Socket::new().await;
        let mut harness = Harness::with_me(&[(2, &[])], &serde_json::json!({ "reach": "relay_only" }));
        let now = Instant::now();
        harness.control.open_test(&window(2, 7, 10), now);
        harness.control.on_test_ping(a.addr(), &test_ping(&harness, 2, 7, 0, None), now, false, now);
        assert!(a.test_pongs().await.is_empty(), "回答直连的探测就把地址告诉了对端");

        let (reply, answer) = oneshot::channel();
        harness.control.attempt_direct(node(2), Side::Lead, Duration::from_secs(1), reply, now);
        let attempt = answer.await.unwrap();
        assert_eq!((attempt.ok, attempt.failure), (false, Some(crate::diag::DirectFailure::RelayOnly)));
        assert!(harness.control.attempts.is_empty(), "不建立直连的节点连试都不试");
    }

    #[tokio::test]
    async fn a_direct_attempt_reports_an_existing_direct_path_at_once_and_otherwise_gives_up_with_a_reason() {
        let socket = Socket::new().await;
        let mut harness = Harness::new(&[(2, &[]), (3, &[])]);
        let now = Instant::now();
        validate(&mut harness, 2, &socket, now).await;
        let (reply, answer) = oneshot::channel();
        harness.control.attempt_direct(node(2), Side::Lead, Duration::from_secs(1), reply, now);
        let attempt = answer.await.unwrap();
        assert!(attempt.ok && attempt.already && attempt.elapsed.is_none());

        // 对端 3 没有任何候选地址：到时间也没有结果，说得出原因。
        let (reply, answer) = oneshot::channel();
        harness.control.attempt_direct(node(3), Side::Lead, Duration::from_secs(1), reply, now);
        harness.control.poll_tests(now);
        assert_eq!(harness.control.attempts.len(), 1, "还在等");
        harness.control.poll_tests(now + Duration::from_secs(1));
        let attempt = answer.await.unwrap();
        assert_eq!((attempt.ok, attempt.failure, attempt.candidates), (false, Some(crate::diag::DirectFailure::NoCandidates), 0));
    }

    /// 本节点自己的 relay：`clients` 在它上面有会话，绑在给定的地方。发给它们的帧记下来。
    #[derive(Default)]
    struct OwnRelay {
        clients: Vec<(NodeId, SessionLeg)>,
        sent: std::sync::Mutex<Vec<(NodeId, Vec<u8>)>>,
    }

    impl crate::LocalRelay for OwnRelay {
        fn handle_udp(&self, _from: SocketAddr, _ecn: Option<i3t_underlay::Ecn>, _data: &[u8], _stride: usize) {}

        fn has_session(&self, client: NodeId) -> bool {
            self.session_leg(client).is_some()
        }

        fn session_reopened(&self, _client: NodeId) -> Option<Duration> {
            None
        }

        fn session_at(&self, _client: NodeId, _from: SocketAddr) -> bool {
            false
        }

        fn send_to_client(&self, client: NodeId, contents: &[u8], _segment_size: Option<usize>, _ecn: Option<i3t_underlay::Ecn>) -> bool {
            self.sent.lock().unwrap().push((client, contents.to_vec()));
            true
        }

        fn session_leg(&self, client: NodeId) -> Option<SessionLeg> {
            self.clients.iter().find(|(id, _)| *id == client).map(|(_, leg)| *leg)
        }

        fn handle_leg_frame(&self, _conn: u64, _addr: SocketAddr, _sender: &i3t_underlay::tcp_leg::FrameSender, _frame: &[u8]) {}

        fn leg_closed(&self, _conn: u64) {}

        fn status(&self) -> Option<crate::RelayStatus> {
            None
        }

        fn publish_row(&self, _links: &[Link]) {}

        fn broadcast(&self, _frame: &[u8]) {}
    }

    /// 本节点（延迟优先）的 relay 上挂着对端 2，绑在一条接进来的 TCP 上；对端 2 没有把本节点列进挂靠表，也没有别的路。
    fn own_relay_harness() -> (Harness, Arc<OwnRelay>) {
        let harness = Harness::with_me(&[(2, &[])], &serde_json::json!({ "routing": "lowest_cost", "reach": "relay_only" }));
        let relay = Arc::new(OwnRelay { clients: vec![(node(2), SessionLeg::Accepted(7))], ..OwnRelay::default() });
        harness.control.shared.local_relay.set(Arc::clone(&relay) as Arc<dyn crate::LocalRelay>).ok().unwrap();
        harness.control.peers[&node(2)].slot.last_demand.touch(&harness.control.shared.clock);
        (harness, relay)
    }

    fn own_relay_candidate(harness: &Harness) -> Candidate {
        let path = PathId::Relays(RelayPath::new(&[node(ME)]).unwrap());
        harness.control.peers[&node(2)]
            .candidates
            .iter()
            .find(|candidate| candidate.path == path)
            .cloned()
            .expect("经本节点 relay 的那条路是候选")
    }

    /// 发给对端 2 的、经本节点 relay 的会话送去的端到端探测。
    fn probes_sent(relay: &OwnRelay) -> Vec<probe::Ping> {
        let sent = std::mem::take(&mut *relay.sent.lock().unwrap());
        sent.iter()
            .filter_map(|(client, frame)| match i3t_proto::Datagram::parse(frame) {
                Ok(i3t_proto::Datagram::Relayed { header, packet }) if *client == node(2) && header.dst == node(2) => {
                    match probe::Frame::parse(packet) {
                        Some(probe::Frame::Ping(ping)) => Some(ping),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect()
    }

    const MS: Duration = Duration::from_millis(1);

    #[tokio::test]
    async fn the_leg_from_this_nodes_own_relay_is_measured_on_the_session_instead_of_being_priced_near_zero() {
        let (mut harness, relay) = own_relay_harness();
        let start = Instant::now();
        harness.control.update_routes(start, true);
        // 还没有量到：按探测等回答的上限算，不是以前的 2 毫秒；只有它一条路，照样走它，但不会因为代价换到它上面。
        let unmeasured = own_relay_candidate(&harness);
        assert!((unmeasured.cost_ms - (crate::timing::PROBE_TIMEOUT_MAX.as_secs_f64() * 1000.0 + 1.0)).abs() < 1e-6, "{unmeasured:?}");
        assert!(!unmeasured.settled);
        assert_eq!(harness.control.peers[&node(2)].route, RouteKey::Relay { path: RelayPath::new(&[node(ME)]).unwrap(), via: Via::Local });

        // 同时经这个会话发了一个签名的端到端探测；对端从它自己的路回答，300 ms 之后到。
        let pings = probes_sent(&relay);
        assert_eq!(pings.len(), 1, "一次只发一个");
        let message = probe::Ping::signed_message(node(ME), node(2), &pings[0].nonce);
        assert!(
            i3t_crypto::verify(&harness.control.key.public(), probe::Ping::PURPOSE, &message, &Signature::from_bytes(pings[0].signature))
                .is_ok()
        );
        let pong = harness.pong(2, pings[0].nonce, addr("0.0.0.0:0"));
        harness.control.on_path_pong(node(2), &pong, start + 300 * MS);
        harness.control.update_routes(start + Duration::from_secs(1), true);
        let measured = own_relay_candidate(&harness);
        assert!((measured.cost_ms - 301.0).abs() < 1e-6, "量到的这一段（TCP 上按平均延迟）加上经一个 relay 的 1 ms：{measured:?}");
        assert!(measured.settled, "量到了，会话也没有断过：可以拿来和别的路比");
        assert!(probes_sent(&relay).is_empty(), "下一个要等探测的间隔");
        harness.control.update_routes(start + PROBE_INTERVAL + 300 * MS, false);
        let next = probes_sent(&relay);
        assert_eq!(next.len(), 1);

        // 签名不对的回答不算：还在等真的那个。
        let mut forged = harness.pong(2, next[0].nonce, addr("0.0.0.0:0"));
        forged.signature[0] ^= 1;
        harness.control.on_path_pong(node(2), &forged, start + Duration::from_secs(6));
        assert!(harness.control.peers[&node(2)].local_leg.expects(&next[0].nonce));
    }

    #[tokio::test]
    async fn a_peer_that_lists_this_node_among_its_relays_is_taken_at_its_word_and_not_probed() {
        let (mut harness, relay) = own_relay_harness();
        let mut netmap = (*harness.control.netmap).clone();
        netmap.peers[0].attached = vec![Attachment { relay: node(ME), rtt_ms: 120, shared: false }];
        let start = Instant::now();
        harness.control.apply_netmap(Arc::new(netmap), start);
        harness.control.update_routes(start, true);
        let candidate = own_relay_candidate(&harness);
        assert!((candidate.cost_ms - 121.0).abs() < 1e-6 && candidate.settled, "{candidate:?}");
        assert!(probes_sent(&relay).is_empty(), "对端在这个会话上测着，不用另外探测");
        let hops = harness.control.hops(node(2), TestPath::Relays(RelayPath::new(&[node(ME)]).unwrap()), start);
        assert_eq!((hops.len(), hops[0].rtt_ms, hops[0].source), (1, Some(120.0), crate::diag::HopSource::Reported));
    }

    #[tokio::test]
    async fn a_multi_relay_path_that_answers_again_is_no_longer_blamed_for_the_next_switch() {
        let mut harness = Harness::new(&[(2, &[])]);
        let now = Instant::now();
        let nonce = [7; 8];
        // 经多个 relay 的路径上连着几个探测没有回音，可是没有别的路可换：起因记下了，路没换。
        let peer = harness.control.peers.get_mut(&node(2)).unwrap();
        peer.hint = Some(RouteHint::PathProbeSilent);
        peer.probe.pending = Some((nonce, now));

        let pong = harness.pong(2, nonce, addr("0.0.0.0:0"));
        harness.control.on_path_pong(node(2), &pong, now + 20 * MS);
        let peer = &harness.control.peers[&node(2)];
        assert_eq!(peer.probe.pending, None, "等着的那个探测有了回答");
        assert_eq!(peer.hint, None, "路径又送得到了，下一次换路不再算在探测没有回音上");
    }
}
