//! 主动测试在节点协议里的样子：controller 给两端的指令，和两端各自的上报。
//!
//! ```text
//! controller → 两端   Test { 编号, 对端, 发起方还是接受方, 测试项, 指定的路径, 时间窗 }
//! 发起方 → 对端       测试探测（经直连或者指定的路径）、测量流
//! 两端 → controller   TestReport { 编号, 自己这一侧看到的 }
//! controller → 两端   TestEnd { 编号 }                     做完了或者被取消了：关掉时间窗
//! ```
//!
//! 管理 API 里的结果也用这里的几个结构（延迟、每一段、吞吐），所以数都带着单位写在名字里：微秒、千分之几、字节、毫秒。

use std::fmt;

use i3t_proto::NodeId;
use serde::{Deserialize, Serialize};

use super::{DirectKind, LegTransport, PathCandidate, Route};
use crate::netmap::RoutingMode;

/// 两端在一个测试里的角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestRole {
    /// 发探测、开测量流、量结果的一方（管理 API 里的 `a`）。
    Initiator,
    /// 回答探测、提供测量服务的一方（`b`）。
    Responder,
}

/// 一个测试要做哪几项。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TestItems {
    /// 直连能力：现在就试一次直连。
    pub direct: bool,
    /// 直连质量：在直连上发探测包列。
    pub direct_quality: bool,
    /// relay 质量：经 relay 的路径上发探测包列。
    pub relay_quality: bool,
    /// 两种选路模式各会选哪条路。
    pub route: bool,
    /// 在测质量的路径上另外量吞吐（要上面两项之一）。
    pub throughput: bool,
    /// 两端各上报一份主机、进程以及到对端连接的状况（[`HostReport`]）。旧版本节点不支持该项，不会上报。
    pub host: bool,
}

/// controller 给两端的测试指令。两端拿到的是同一个编号、同样的测试项和路径，只是角色和对端不同。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestOrder {
    pub test: u64,
    pub peer: NodeId,
    pub role: TestRole,
    pub items: TestItems,
    /// 管理员指定的 relay 路径，按发起方到接受方的顺序。没有指定时 relay 质量测发起方选的默认两条。
    #[serde(default)]
    pub paths: Vec<Vec<NodeId>>,
    /// 时间窗多长，秒。节点按自己的上限截断。
    pub window_secs: u32,
}

/// 一端的上报。发起方做完了才报一次；接受方做完自己那一侧的直连尝试和选路之后先报一次，测试结束时（`TestEnd`）
/// 或者时间窗到了再报一次最后的。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TestReport {
    pub test: u64,
    #[serde(default)]
    pub role: Option<TestRole>,
    /// 这是这一端的最后一次上报。
    #[serde(default)]
    pub last: bool,
    /// 节点拒绝了整个测试时的原因。
    #[serde(default)]
    pub refused: Option<TestProblem>,
    /// 这一端看到的直连能力。
    #[serde(default)]
    pub direct: Option<DirectSide>,
    /// 量过的路径，按量的顺序。只有发起方有。
    #[serde(default)]
    pub paths: Vec<PathMeasure>,
    /// 这一端发往对端的方向上，两种模式各会选哪条路。
    #[serde(default)]
    pub decision: Option<Decision>,
    /// 接受方：被要求提供吞吐测量、却没有提供的原因（本机关掉了吞吐测试等）。
    #[serde(default)]
    pub throughput_refused: Option<TestProblem>,
    /// 这一端的主机和连接状况。只在这一端的最后一次上报里有。
    #[serde(default)]
    pub host: Option<HostReport>,
}

/// 一端在一个测试期间看到的：这台机器、节点这个进程，和它到对端的那条连接。
///
/// 无法采集的指标为 `null`（当前平台不支持或读取出错），不计为测试失败。目前仅 Linux 支持采集主机和进程指标。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostReport {
    pub system: Option<HostSystem>,
    /// 测试开始的头一秒里 CPU 用了多少。
    pub cpu: Option<CpuUse>,
    /// 测试期间最忙的一秒（两个数各取各的最大值）。量吞吐时进程的那个数接近 100，就是一个核跑满了。
    pub cpu_peak: Option<CpuUse>,
    /// 系统的 1、5、15 分钟平均负载，乘了 100。
    pub load_x100: Option<[u32; 3]>,
    pub memory: Option<HostMemory>,
    pub process: Option<HostProcess>,
    pub connections: Option<HostConnections>,
    /// 这一端到对端的那条连接。没有连接时是 `null`。
    pub to_peer: Option<PeerConnection>,
}

/// 机器本身。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostSystem {
    /// 发行版名称，例如 `Debian GNU/Linux 13 (trixie)`；无法读取发行版信息时退回为操作系统类型（`linux`、`windows`、`macos`）。
    pub os: Option<String>,
    pub kernel: Option<String>,
    /// `x86_64`、`aarch64` 等。
    pub arch: String,
    pub cpu_model: Option<String>,
    /// 当前进程可用的 CPU 核心数。
    pub cores: u32,
    pub uptime_secs: Option<u64>,
}

/// 一秒里 CPU 用了多少。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CpuUse {
    /// 整台机器，所有的核加在一起，0 到 100。
    pub system_percent: u32,
    /// 节点这个进程，按一个核算：多个线程同时忙的时候会超过 100。
    pub process_percent: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HostMemory {
    pub total_bytes: u64,
    /// 不动用交换就还能给程序用的。
    pub available_bytes: u64,
    /// 节点这个进程常驻的。
    pub process_rss_bytes: u64,
}

/// 节点这个进程。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostProcess {
    pub uptime_secs: u64,
    pub threads: Option<u32>,
}

/// 这个节点现在连着多少东西。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostConnections {
    /// 和多少个对端之间有连接。
    pub peers: u32,
    /// 挂靠着几个 relay。
    pub relays: u32,
    /// 本节点是 relay 时，它上面有多少个会话；不是 relay 时是 `null`。
    pub relay_clients: Option<u32>,
    /// 共用的连接上开着多少条流。
    pub streams: u32,
    /// ice3proxy 的连接：正在承载流的，和空闲着的。
    pub lanes_in_use: u32,
    pub lanes_idle: u32,
}

/// 一端到对端的那条连接。往返时间、窗口和包长是测试结束时的值；收发和丢包的计数是测试期间增加的。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConnection {
    pub route: Route,
    /// 平滑的往返时间，和连接建立以来见过的最小值，微秒。
    pub rtt_us: u32,
    #[serde(default)]
    pub min_rtt_us: Option<u32>,
    /// 拥塞窗口。
    pub cwnd_bytes: u64,
    /// 现在一个包最长多少字节。
    pub mtu: u32,
    /// `"bbr"` 或 `"cubic"`。
    pub congestion: String,
    pub sent_packets: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    /// 拥塞控制认定发生了拥塞的次数。
    pub congestion_events: u64,
    /// 线上的字节数。
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// 这条连接建立了多久。
    pub age_secs: u64,
}

/// 测试里一样事做不成的原因：一个码，说的是哪个节点，和一小段给人看的话。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestProblem {
    pub code: TestCode,
    /// 导致问题的节点；无法归因到具体节点时为 `null`。
    #[serde(default)]
    pub node: Option<NodeId>,
    #[serde(default)]
    pub message: String,
}

impl TestProblem {
    #[must_use]
    pub fn new(code: TestCode, node: Option<NodeId>) -> Self {
        Self { code, node, message: code.text().to_owned() }
    }
}

/// 测试原因码。界面按该字段渲染，`message` 仅作未翻译场景的兜底文本。后续可能新增枚举值，未知值反序列化为 `unknown`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestCode {
    /// 节点版本过旧，不支持主动测试。
    NotSupported,
    /// 节点不在线。
    NodeOffline,
    /// 访问规则没有把这两个节点连通：它们拿不到对方的地址和公钥。
    NotConnected,
    /// 节点的路径限制是只经 relay：不参加直连的测试，不向对端暴露地址。
    RelayOnly,
    /// 节点的路径限制是只用直连：不参加经 relay 的测试。
    DirectOnly,
    /// 节点在本地关掉了吞吐测试。
    ThroughputOff,
    /// 网络里没有能用的 relay 路径。
    NoRelay,
    /// 两个节点之间没有可用的直连，无法测量直连质量。
    NoDirect,
    /// 手上没有对端的候选地址。
    NoCandidates,
    /// 节点的 UDP 不通。
    UdpBlocked,
    /// 节点映射的端口随对端变化（对称型 NAT），无法打洞。
    MappingVaries,
    /// 两个节点都是只主动连接的。
    DialOutOnly,
    /// 试过了，没有在时限之内成功。
    Timeout,
    /// 该路径当前不可达：与首跳 relay 无可用会话，或路径中存在未启用转发的 relay。
    Unreachable,
    /// 对端拒绝了测量流。
    Refused,
    /// 节点上同时进行的测试太多，或者和这个对端的上一次测试刚刚做过。
    Busy,
    /// 同一对节点刚执行过测试，需间隔一段时间后再测。
    TooSoon,
    /// 测试被取消了。
    Cancelled,
    /// 节点没有在时限之内上报结果。
    NoReport,
    /// 测量流中途断了。
    StreamFailed,
    /// 指定的路径不能用：经过的节点不是 relay、太长、或者有重复。
    InvalidPath,
    /// 节点内部出错。
    Internal,
    #[serde(other)]
    Unknown,
}

impl TestCode {
    /// 简短的中文说明。
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::NotSupported => "节点版本过旧，不支持主动测试",
            Self::NodeOffline => "节点不在线",
            Self::NotConnected => "访问规则未允许这两个节点连通",
            Self::RelayOnly => "节点仅经中继，不参加直连测试",
            Self::DirectOnly => "节点仅使用直连，不参加中继测试",
            Self::ThroughputOff => "节点已关闭吞吐测试",
            Self::NoRelay => "没有可用的中继路径",
            Self::NoDirect => "没有可用的直连",
            Self::NoCandidates => "没有对端的候选地址",
            Self::UdpBlocked => "UDP 不通",
            Self::MappingVaries => "端口映射随对端变化，无法打洞",
            Self::DialOutOnly => "两个节点均仅主动连接",
            Self::Timeout => "超时",
            Self::Unreachable => "该路径当前不可达",
            Self::Refused => "对端拒绝测量",
            Self::Busy => "节点正忙",
            Self::TooSoon => "近期已测试，请稍后重试",
            Self::Cancelled => "已取消",
            Self::NoReport => "节点未按时上报结果",
            Self::StreamFailed => "测量中途断开",
            Self::InvalidPath => "指定的路径不可用",
            Self::Internal => "节点内部错误",
            Self::Unknown => "未知原因",
        }
    }
}

impl fmt::Display for TestCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

/// 一端看到的直连能力。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DirectSide {
    /// 这一端到对端有了验证过的直连。
    pub ok: bool,
    /// 开始时就已经有直连（这时不算耗时）。
    #[serde(default)]
    pub already: bool,
    /// 直连是怎么建立的。
    #[serde(default)]
    pub kind: Option<DirectKind>,
    /// 从开始尝试到验证通过，毫秒。
    #[serde(default)]
    pub elapsed_ms: Option<u32>,
    /// 未成功时本端观测到的原因。
    #[serde(default)]
    pub failure: Option<TestCode>,
    /// 这一端的 UDP 通不通；不知道是 `null`。
    #[serde(default)]
    pub udp: Option<bool>,
    /// 这一端映射出来的端口是不是随对端变化；不知道是 `null`。
    #[serde(default)]
    pub mapping_varies: Option<bool>,
    /// 尝试时手上有几个对端的候选地址。
    #[serde(default)]
    pub candidates: u32,
}

/// 量过的一条路径。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathMeasure {
    /// 直连时是对端的地址，经 relay 时是按顺序经过的 relay。
    pub route: Route,
    /// 为什么量这一条。
    #[serde(default)]
    pub picked_by: Vec<PathPick>,
    /// 无法测量时的原因。
    #[serde(default)]
    pub failure: Option<TestCode>,
    #[serde(default)]
    pub latency: Option<Latency>,
    /// 按代价公式（`i3t_path::cost`）、用这次量到的延迟、抖动和丢包算的代价，微秒。
    #[serde(default)]
    pub cost_us: Option<u64>,
    /// 各段的测量值，按经过的顺序。
    #[serde(default)]
    pub hops: Vec<Hop>,
    /// 经 relay 时，发起方到首跳 relay 所使用的传输协议（UDP 或 TCP）。
    #[serde(default)]
    pub relay_leg: Option<LegTransport>,
    #[serde(default)]
    pub throughput: Option<Throughput>,
}

/// 为什么量这一条路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathPick {
    /// 直连质量。
    Direct,
    /// 默认模式会经的 relay（不算直连时）。
    DirectFirst,
    /// 延迟优先模式会选的经 relay 的路径。
    LowestCost,
    /// 管理员指定的。
    Admin,
    #[serde(other)]
    Unknown,
}

/// 一列探测量到的延迟和丢包。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Latency {
    /// 发了几个探测，有几个得到了回答。
    pub probes: u32,
    pub answered: u32,
    /// 往返延迟（减掉了对端处理的时间），微秒。一个回答都没有时是 `null`。
    pub min_us: Option<u32>,
    pub avg_us: Option<u32>,
    pub p95_us: Option<u32>,
    /// 相邻两个往返延迟之差的绝对值的平均，微秒。
    pub jitter_us: Option<u32>,
    /// 往返的丢包，千分之几。
    pub loss_permille: u16,
    /// 去程（发起方到对端）与回程的丢包率（千分比）：根据对端回报的接收数拆分计算；无法拆分时为 `null`。
    pub loss_up_permille: Option<u16>,
    pub loss_down_permille: Option<u16>,
    /// 回答里有几个是沿同一条路径倒着回来的。不是全部时，回程走的是对端自己的路。
    pub same_path: u32,
    /// 两个探测之间隔多少毫秒，整列用了多少毫秒。
    pub interval_ms: u32,
    pub duration_ms: u32,
}

/// 路径上的一段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub from: NodeId,
    pub to: NodeId,
    /// 往返延迟，微秒；不知道时是 `null`。
    #[serde(default)]
    pub rtt_us: Option<u32>,
    #[serde(default)]
    pub jitter_us: Option<u32>,
    /// 丢包，千分之几；不知道时是 `null`。
    #[serde(default)]
    pub loss_permille: Option<u16>,
    pub source: HopSource,
}

/// 一段的测量值从哪里来。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopSource {
    /// 由该段起点节点自行测量（到 relay 的会话或直连）。
    Measured,
    /// relay 之间的骨干矩阵。
    Backbone,
    /// 对端上报的它到 relay 的延迟（只有延迟）。
    Reported,
    /// 没有数据。
    #[serde(other)]
    Unknown,
}

/// 一条路径上的吞吐。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Throughput {
    /// 发起方到对端及对端到发起方的传输结果。未测量或无法测量的方向为 `null`。
    #[serde(default)]
    pub up: Option<Transfer>,
    #[serde(default)]
    pub down: Option<Transfer>,
    /// 无法测量时的原因（如对端拒绝、已关闭吞吐测试、流中途断开等）。
    #[serde(default)]
    pub failure: Option<TestCode>,
    /// 用的传输。现在总是 `"quic"`：测量流走这一对节点之间共用的连接，不经 ice3proxy。
    #[serde(default)]
    pub transport: String,
    /// 连接用的拥塞控制：`"bbr"` 或 `"cubic"`。
    #[serde(default)]
    pub congestion: String,
    /// 每个方向的上限：字节数和毫秒，先到为止。
    #[serde(default)]
    pub limit_bytes: u64,
    #[serde(default)]
    pub limit_ms: u32,
    /// 发起方到对端的那条连接在整个测量期间都固定在这条路径上。
    #[serde(default)]
    pub pinned: bool,
}

/// 一个方向的吞吐。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    pub bytes: u64,
    /// 从第一个字节到最后一个字节，毫秒。
    pub ms: u32,
    /// 平均每秒多少比特；用时不到 1 毫秒时是 `null`。
    #[serde(default)]
    pub bits_per_second: Option<u64>,
    /// 为什么停的：对方结束了、到了字节上限、到了时长上限。
    pub stopped_by: TransferEnd,
}

/// 一个方向的搬运为什么停。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferEnd {
    Finished,
    Bytes,
    Time,
    #[serde(other)]
    Unknown,
}

/// 一端发往对端的方向上，两种模式各会选哪条路。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// 本端当前使用的选路模式；较新版本节点上报未知模式时为 `null`。
    #[serde(default)]
    pub mode: Option<RoutingMode>,
    /// 这一端现在走的路。
    #[serde(default)]
    pub current: Option<Route>,
    pub direct_first: Choice,
    pub lowest_cost: Choice,
    /// 考虑过的候选路径和代价，按代价从低到高。
    #[serde(default)]
    pub candidates: Vec<PathCandidate>,
}

/// 一种模式的选择。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choice {
    /// 选的路；没有能走的路时是 `null`。
    #[serde(default)]
    pub route: Option<Route>,
    pub reason: ChoiceCode,
    /// 这条路的代价，微秒；没有测量值时是 `null`。
    #[serde(default)]
    pub cost_us: Option<u64>,
    /// `reason` 是 [`ChoiceCode::WithinMargin`] 时：比选的这条（现在的路）便宜、却没有便宜到要换的那条候选。别的时候，
    /// 和不报它的旧节点，是 `null`。
    #[serde(default)]
    pub cheaper: Option<CheaperPath>,
}

/// 更便宜、但不够换过去的一条候选路径。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheaperPath {
    pub route: Route,
    /// 微秒。
    pub cost_us: u64,
}

/// 为什么选这条路。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChoiceCode {
    /// 同一个局域网，局域网直连无条件优先。
    Lan,
    /// 默认模式：直连可用就走直连。
    Direct,
    /// 对端自己就是 relay，两个节点之间有直接的中转会话。
    PeerIsRelay,
    /// 对端挂在这一端自己的 relay 上。
    OwnRelay,
    /// 对端挂靠的 relay。
    PeerRelay,
    /// 默认模式：不存在两端均可用的单个 relay，改经多级 relay 链路（候选中代价最低的路径）。
    NoSharedRelay,
    /// 候选里代价最低的。
    LowestCost,
    /// 延迟优先：留在现在的路上。有更便宜的候选（`cheaper`），但没有便宜到选路器换路要的差距（`max(5ms, 10%)`）。
    WithinMargin,
    /// 没有能走的路。
    NoPath,
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ToController, ToNode};

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    #[test]
    fn a_test_order_has_a_stable_json_shape() {
        let order = TestOrder {
            test: 12,
            peer: node(3),
            role: TestRole::Responder,
            items: TestItems { direct: true, relay_quality: true, throughput: true, ..TestItems::default() },
            paths: vec![vec![node(8), node(9)]],
            window_secs: 60,
        };
        let wire = serde_json::to_value(ToNode::Test(Box::new(order.clone()))).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({
                "type": "test", "test": 12, "peer": 3, "role": "responder",
                "items": { "direct": true, "direct_quality": false, "relay_quality": true, "route": false, "throughput": true, "host": false },
                "paths": [[8, 9]], "window_secs": 60
            })
        );
        assert_eq!(serde_json::from_value::<ToNode>(wire).unwrap(), ToNode::Test(Box::new(order)));
        assert_eq!(serde_json::to_value(ToNode::TestEnd { test: 12 }).unwrap(), serde_json::json!({ "type": "test_end", "test": 12 }));
    }

    #[test]
    fn a_test_report_reads_with_missing_fields_and_unknown_codes() {
        let report: ToController = serde_json::from_value(serde_json::json!({
            "type": "test_report", "test": 12,
            "refused": { "code": "something_new", "node": 3 },
            "direct": { "ok": false, "failure": "udp_blocked" }
        }))
        .unwrap();
        let ToController::TestReport(report) = report else { panic!("不是测试的上报") };
        assert_eq!(report.refused, Some(TestProblem { code: TestCode::Unknown, node: Some(node(3)), message: String::new() }));
        assert_eq!(report.direct.as_ref().and_then(|direct| direct.failure), Some(TestCode::UdpBlocked));
        assert!(report.paths.is_empty() && !report.last && report.role.is_none());
    }

    #[test]
    fn a_measured_path_has_numbers_with_units_in_their_names() {
        let path = PathMeasure {
            route: Route::Relay { relays: vec![node(9)] },
            picked_by: vec![PathPick::DirectFirst, PathPick::LowestCost],
            failure: None,
            latency: Some(Latency { probes: 100, answered: 98, min_us: Some(40_100), loss_permille: 20, ..Latency::default() }),
            cost_us: Some(55_000),
            hops: vec![Hop {
                from: node(1),
                to: node(9),
                rtt_us: Some(20_000),
                jitter_us: None,
                loss_permille: Some(0),
                source: HopSource::Measured,
            }],
            relay_leg: Some(LegTransport::Udp),
            throughput: Some(Throughput {
                up: Some(Transfer { bytes: 20_000_000, ms: 4100, bits_per_second: Some(39_024_390), stopped_by: TransferEnd::Bytes }),
                down: None,
                failure: Some(TestCode::ThroughputOff),
                transport: "quic".to_owned(),
                congestion: "bbr".to_owned(),
                limit_bytes: 20_000_000,
                limit_ms: 5000,
                pinned: true,
            }),
        };
        let wire = serde_json::to_value(&path).unwrap();
        assert_eq!(wire["picked_by"], serde_json::json!(["direct_first", "lowest_cost"]));
        assert_eq!(wire["latency"]["min_us"], 40_100);
        assert_eq!(wire["hops"][0]["source"], "measured");
        assert_eq!(wire["throughput"]["up"]["stopped_by"], "bytes");
        assert_eq!(wire["throughput"]["failure"], "throughput_off");
        assert_eq!(serde_json::from_value::<PathMeasure>(wire).unwrap(), path);
    }

    #[test]
    fn a_choice_that_stays_within_the_margin_names_the_cheaper_path_and_old_reports_still_read() {
        let choice = Choice {
            route: Some(Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() }),
            reason: ChoiceCode::WithinMargin,
            cost_us: Some(74_300),
            cheaper: Some(CheaperPath { route: Route::Relay { relays: vec![node(3)] }, cost_us: 74_100 }),
        };
        let wire = serde_json::to_value(&choice).unwrap();
        assert_eq!(wire["reason"], "within_margin");
        assert_eq!(wire["cheaper"], serde_json::json!({ "route": { "via": "relay", "relays": [3] }, "cost_us": 74_100 }));
        assert_eq!(serde_json::from_value::<Choice>(wire).unwrap(), choice);
        let old: Choice = serde_json::from_value(serde_json::json!({ "route": null, "reason": "no_path", "cost_us": null })).unwrap();
        assert_eq!((old.reason, old.cheaper), (ChoiceCode::NoPath, None));
        let newer: Choice = serde_json::from_value(serde_json::json!({ "reason": "something_new" })).unwrap();
        assert_eq!(newer.reason, ChoiceCode::Unknown);
    }

    #[test]
    fn every_test_code_has_a_short_text() {
        assert_eq!(TestCode::UdpBlocked.to_string(), "UDP 不通");
        assert_eq!(TestProblem::new(TestCode::TooSoon, None).message, "近期已测试，请稍后重试");
        assert_eq!(serde_json::to_value(TestCode::ThroughputOff).unwrap(), "throughput_off");
    }
}
