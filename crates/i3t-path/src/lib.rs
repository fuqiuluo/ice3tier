//! 路由层：包怎么送到对端。
//!
//! 为每个对端维护"现在走哪条路"：直连某个验证过的地址，经一个或几个 relay（到第一个 relay 走 UDP 或 TCP），或者没有路。
//! 连接层只和节点编号打交道，所以路可以随时换，连接和上面的流不受影响。
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`paths`] | 对外的入口 [`Paths`]：收发包（按首字节分类）、状态查询、信令、局域网发现和端口映射的开关 |
//! | `control` | 控制任务：处理 relay 的应答和探测、应用 netmap、选路；`control::route` 是把选路结果落实成收发做法的那一部分 |
//! | `routing` | 候选路径的穷举、代价的比较、延迟优先模式的迟滞 |
//! | `cost` | 一条路径的代价怎么算 |
//! | `estimate` | 一段链路的延迟、抖动和丢包估计，探测包列 |
//! | `matrix` | 骨干延迟矩阵在节点一侧的存放 |
//! | `direct` | 到一个对端的直连：候选地址、验证、打洞的重试、保活 |
//! | `attach` | 节点一侧的中转会话：握手、保活 |
//! | `relays` | 到一个 relay 的联系（UDP 和 TCP 同时试，优先 UDP），挂靠哪几个 relay |
//! | `tcp` | 到 relay 的那条 TCP |
//! | [`backbone`] | relay 和 relay 之间走 TCP 的骨干连接：一对 relay 一条，两个会话都在上面 |
//! | `table` | 收发每个包时查的表 |
//! | `budget` | 验签名的额度 |
//! | [`report`] | 给界面看的选路情况和骨干矩阵 |
//! | [`diag`] | 主动测试：时间窗、探测包列、暂时固定路，和它们的结果 |
//!
//! 选路模式按 netmap 里本节点的设置（没有就用网络的默认值），每个节点只为自己发出的包选路，所以一条连接的两个方向可以走不同的路：
//!
//! - 默认模式：直连可用就走直连，否则经一个 relay。两个节点之间有直接的中转会话时用它
//!   （对端自己是 relay，或者对端挂在本节点的 relay 上），不然用对端挂靠的 relay 里第一个能用的。
//!   一个都用不了时（没有一个 relay 两端都用得上），经延迟优先模式的候选里代价最低的一串 relay。
//! - 延迟优先：直连和经 1 到最大中转级数个 relay 的路径按代价比较，切换有迟滞；局域网直连无条件优先。
//!
//! 本节点同时是 relay 时，路径层还负责骨干：和别的 relay 保持会话并互测，把测到的这一行和手上别的 relay 的行
//! 交给 [`LocalRelay`] 发给挂靠的节点。两个 relay 之间 UDP 不通时，骨干上的这一段走一条 TCP（[`backbone`]）。

mod attach;
pub mod backbone;
mod budget;
mod control;
mod cost;
pub mod diag;
mod direct;
mod estimate;
mod matrix;
pub mod paths;
mod relays;
pub mod report;
mod routing;
mod table;
mod tcp;
mod timing;

use std::net::SocketAddr;
use std::time::Duration;

use i3t_model::control::{Route, RouteCause, RouteEntry};
use i3t_model::netmap::Attachment;
use i3t_proto::NodeId;
use i3t_proto::backbone::{Link, RelayState};
use i3t_underlay::Ecn;
use i3t_underlay::tcp_leg::FrameSender;

pub use backbone::BackboneInbox;
pub use cost::Segment;
pub use diag::{
    ChoiceReason, DirectAttempt, DirectFailure, HopReport, HopSource, LatencySummary, ModeChoice, RouteDecision, Side, TestPath, TestSpec,
    TrainError, TrainReport, TrainSpec,
};
pub use paths::{PacketMeta, PathConfig, Paths, RoutePin, TestGuard};
pub use report::{
    Alternative, BackboneLink, BackboneRow, CandidateReport, DirectFailureCause, DirectKind, DirectState, DirectStatus, LegReport,
    PathReport, RelayLeg,
};
pub use table::{Packets, Unsent};
pub use tcp::connect_first;

/// 本节点的 relay 角色，路径层要它做的几件事。实现在 `i3t-relay`。
///
/// 节点只有一个 UDP 端口，由路径层收包，所以归 relay 的数据报要由路径层转交；反过来，
/// 挂在本节点自己的 relay 上的对端，路径层要经 relay 的会话才送得到。
pub trait LocalRelay: Send + Sync + 'static {
    /// UDP 上收到的、归 relay 管的数据：节点发来的中转会话帧、发给别的节点的中转帧、地址查询。
    /// `data` 里是来自 `from` 的若干个数据报，每 `stride` 字节一个（最后一个可以短）。
    /// 本节点没有启用 relay 时全部丢掉，不回应。
    fn handle_udp(&self, from: SocketAddr, ecn: Option<Ecn>, data: &[u8], stride: usize);

    /// `client` 现在在本节点的 relay 上有没有会话。
    fn has_session(&self, client: NodeId) -> bool;

    /// `client` 现在的会话如果是它上一个会话断掉之后重新建的，返回重新建立以来过了多久；
    /// 没有会话，或者这是它头一次建立的会话，返回 `None`。
    /// 选路靠它分辨"刚断过又连上、还看不出稳不稳"的会话。
    fn session_reopened(&self, client: NodeId) -> Option<Duration>;

    /// `client` 的会话是不是绑定在 UDP 地址 `from` 上。
    fn session_at(&self, client: NodeId, from: SocketAddr) -> bool;

    /// 把带着中转头的数据报送到 `client` 的会话上。`contents` 可以是若干个等长的首尾相接，
    /// 这时 `segment_size` 是每个的长度。返回有没有送出去。
    fn send_to_client(&self, client: NodeId, contents: &[u8], segment_size: Option<usize>, ecn: Option<Ecn>) -> bool;

    /// `client`（另一个 relay）在本节点的 relay 上的会话绑定在哪里；没有会话是 `None`。
    /// 骨干上的一条连接要两边互相都有会话、而且走的是同一种传输（同一条 TCP）才转发得过去，本节点报矩阵时靠它判断这条连接算不算通。
    fn session_leg(&self, client: NodeId) -> Option<SessionLeg>;

    /// 本节点的路径层拨向另一个 relay 的第 `conn` 条 TCP 上来了一帧归 relay 管的：那个 relay 在这条 TCP 上反过来和本节点的 relay
    /// 建会话的握手和保活，或者它要本节点往下转的包（见 [`backbone`]）。`addr` 是这条 TCP 的对端地址，`sender` 往这条 TCP 里写。
    fn handle_leg_frame(&self, conn: u64, addr: SocketAddr, sender: &FrameSender, frame: &[u8]);

    /// 本节点的路径层拨出去的第 `conn` 条 TCP 没了：绑在上面的会话跟着关闭。
    fn leg_closed(&self, conn: u64);

    /// 本节点的 relay 现在的状态和负载。没有启用 relay 时返回 `None`。
    fn status(&self) -> Option<RelayStatus>;

    /// 把本节点测到的骨干链路签成矩阵的一行，发给所有会话。
    fn publish_row(&self, links: &[Link]);

    /// 把一帧原样发给所有会话：别的 relay 的矩阵行要这样传下去。
    fn broadcast(&self, frame: &[u8]);
}

/// 一个会话在本节点的 relay 上绑定在哪里（[`LocalRelay::session_leg`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLeg {
    Udp,
    /// relay 接进来的一条 TCP，号是 relay 编的（就是它在 [`BackboneInbox`] 里报的那个号）。
    Accepted(u64),
    /// 本节点的路径层拨出去的一条 TCP，号是路径层编的（[`LocalRelay::handle_leg_frame`] 带过去的那个号）。
    Dialled(u64),
}

/// 本节点的 relay 的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStatus {
    pub state: RelayState,
    /// 转发带宽占用了上限的百分之几；没有设上限时是 0。
    pub load_percent: u8,
    /// 启动以来握手成功过多少次。它变了说明有新的会话：新挂上来的节点要尽快拿到骨干矩阵，不该等下一轮。
    pub sessions_opened: u64,
}

/// 到一个对端的路换了。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteChange {
    pub peer: NodeId,
    /// 换成了哪条路。
    pub route: Route,
    /// 为什么换，给人看的。
    pub reason: String,
    /// `reason` 的代码和它要用到的值。
    pub cause: RouteCause,
}

/// 对外公布的状态，由控制任务定期刷新。
#[derive(Debug, Default)]
pub(crate) struct Status {
    pub(crate) routes: Vec<RouteEntry>,
    pub(crate) endpoints: Vec<SocketAddr>,
    pub(crate) public_addresses: Vec<SocketAddr>,
    pub(crate) mapping_varies: Option<bool>,
    pub(crate) attached: Vec<Attachment>,
    pub(crate) reports: Vec<PathReport>,
    pub(crate) backbone: Vec<BackboneRow>,
    pub(crate) relay_tries: Vec<i3t_model::control::RelayTry>,
}
