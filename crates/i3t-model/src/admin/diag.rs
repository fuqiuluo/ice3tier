//! 管理 API 里的主动测试：发起一个测试、看它的进度和结果、一对节点的历史、全网矩阵。
//!
//! 结果里的每一项都有状态（[`ItemState`]）和原因（[`TestProblem`]：码、节点、一小段话），数都带着单位写在名字里，
//! 界面不用解析任何文字。量出来的结构（延迟、每一段、吞吐、两种模式的选择）和节点上报的是同一套
//! （[`crate::control::diag`]）。

use i3t_proto::NodeId;
use serde::{Deserialize, Serialize};

use super::{NetworkId, NodeRef, Timestamp};
use crate::control::diag::{Choice, DirectSide, Hop, HostReport, Latency, PathPick, Throughput};
use crate::control::{DirectKind, LegTransport, PathCandidate, Route};
use crate::netmap::RoutingMode;

pub use crate::control::diag::{
    ChoiceCode, CpuUse, HopSource, HostConnections, HostMemory, HostProcess, HostSystem, PeerConnection, TestCode, TestProblem, Transfer,
    TransferEnd,
};

/// 测试项。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestItem {
    /// 能不能直连：现在就试一次。
    Direct,
    /// 直连的延迟、抖动、丢包（要了吞吐时还有吞吐）。
    DirectQuality,
    /// 经 relay 的延迟、抖动、丢包，和每一段的分解（要了吞吐时还有吞吐）。
    RelayQuality,
    /// 两种选路模式各会选哪条路。
    Route,
    /// 两端各自的机器、进程和它们之间那条连接的状况。
    Host,
}

impl TestItem {
    pub const ALL: [Self; 5] = [Self::Direct, Self::DirectQuality, Self::RelayQuality, Self::Route, Self::Host];
}

/// 发起一个测试。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTest {
    /// 发起方。探测和测量流从它发出。
    pub a: NodeId,
    pub b: NodeId,
    /// 做哪几项；省略时是全部四项。
    #[serde(default)]
    pub items: Option<Vec<TestItem>>,
    /// 在测质量的路径上另外量吞吐。消耗带宽和流量，所以要明确写 `true`。
    #[serde(default)]
    pub throughput: bool,
    /// 指定 relay 质量测哪几条路径，每条是按 `a` 到 `b` 的顺序经过的 relay；省略或者空的时候测两种模式默认会选的。
    #[serde(default)]
    pub via: Vec<Vec<NodeId>>,
}

/// 一个测试被要求做的事，规整过的：测试项按固定的顺序、去掉重复。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestRequest {
    pub items: Vec<TestItem>,
    pub throughput: bool,
    #[serde(default)]
    pub via: Vec<Vec<NodeId>>,
}

/// 一个测试现在的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestState {
    /// 正在进行。
    Running,
    /// 做完了（各项可能有成有败，看各项自己的状态）。
    Done,
    /// 整个测试无法执行，原因见 `error`。
    Failed,
    /// 被管理员取消了。已经有的结果照样留着。
    Cancelled,
    #[serde(other)]
    Unknown,
}

/// 一项的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// 还没有结果。
    Pending,
    /// 已得出结果。直连能力测试"未成功"同样属于正常结果（`ok` 为 `false`），并非测试失败。
    Done,
    /// 没有做：条件不满足（原因在 `problem` 里）。
    Skipped,
    /// 做了，但没能量出来（原因在 `problem` 里）。
    Failed,
    #[serde(other)]
    Unknown,
}

/// 一个测试：请求、进度和结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestView {
    pub id: u64,
    pub network: NetworkId,
    /// 发起方和接受方。
    pub a: NodeRef,
    pub b: NodeRef,
    pub state: TestState,
    pub request: TestRequest,
    pub started_at: Timestamp,
    /// 结束的时间；还在进行时是 `null`。
    pub finished_at: Option<Timestamp>,
    /// 属于哪一次全网矩阵；单独发起的是 `null`。
    pub matrix: Option<u64>,
    /// 整个测试无法执行时的原因（`state` 为 `failed`）。
    pub error: Option<TestProblem>,
    /// 直连能力；没有要这一项时是 `null`。
    pub direct: Option<DirectResult>,
    /// 直连质量；没有要这一项时是 `null`。
    pub direct_quality: Option<PathResult>,
    /// relay 质量，每条测过（或者要测）的路径一项；没有要这一项时是 `[]`。
    pub relay_quality: Vec<PathResult>,
    /// 两种选路模式的选择；没有要这一项时是 `null`。
    pub route: Option<RouteResult>,
    /// 两端的主机和连接状况，`a` 在前；没有要这一项时是 `null`。
    #[serde(default)]
    pub hosts: Option<Vec<HostResult>>,
    /// 不影响结果、但值得说的事：一端没有按时上报、吞吐测试时别的流量也在这条路上。
    pub notes: Vec<TestProblem>,
}

/// 一端的主机和连接状况（测试项 `host`）。
///
/// 那一端最后一次上报到了才有内容，之前是 `pending`、各项都是 `null`。`done` 而里面有的项是 `null` 是正常的：
/// 该主机无法采集对应指标。节点版本不支持该项时状态为 `skipped`、原因为 `not_supported`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostResult {
    pub node: NodeId,
    pub state: ItemState,
    pub problem: Option<TestProblem>,
    #[serde(flatten)]
    pub report: HostReport,
}

/// 直连能力。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectResult {
    pub state: ItemState,
    /// 两边都有了验证过的直连。
    pub ok: bool,
    /// 发起方观测到的直连建立方式：`lan`、`ipv6`、`reachable`（端口直接可达，包括端口映射）、`punched`（NAT 打洞）。
    pub kind: Option<DirectKind>,
    /// 建立耗时（毫秒）；测试开始前已存在直连（`already`）或未成功时为 `null`。
    pub elapsed_ms: Option<u32>,
    pub already: bool,
    /// 未成功或未执行时的原因，并指明相关节点。
    pub problem: Option<TestProblem>,
    /// 两端各自看到的，`a` 在前。没有上报的一端不在里面。
    pub sides: Vec<DirectSideView>,
}

/// 一端看到的直连能力。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectSideView {
    pub node: NodeId,
    #[serde(flatten)]
    pub side: DirectSide,
}

/// 一条路径的质量。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathResult {
    pub state: ItemState,
    /// 测的路径：`{ "via": "direct", "addr": … }` 或 `{ "via": "relay", "relays": [...] }`。还不知道测哪条时是 `null`。
    pub route: Option<Route>,
    /// 为什么测这一条：`direct`、`direct_first`（默认模式会经的 relay）、`lowest_cost`、`admin`（管理员指定的）。
    pub picked_by: Vec<PathPick>,
    pub problem: Option<TestProblem>,
    pub latency: Option<Latency>,
    /// 用这次测到的延迟、抖动和丢包按代价公式（`i3t_path::cost`）算的代价，微秒。
    pub cost_us: Option<u64>,
    /// 各段的延迟、抖动、丢包，按经过的顺序：`a` 到第一个 relay 是 `a` 测的，relay 之间来自骨干矩阵，
    /// 最后一个 relay 到 `b` 是 `b` 上报的延迟（只有延迟）。
    pub hops: Vec<Hop>,
    /// `a` 到第一个 relay 这一跳使用的传输协议（UDP 或 TCP）。
    pub relay_leg: Option<LegTransport>,
    /// 吞吐；没有要吞吐时是 `null`。
    pub throughput: Option<ThroughputResult>,
}

/// 一条路径上的吞吐。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputResult {
    pub state: ItemState,
    pub problem: Option<TestProblem>,
    #[serde(flatten)]
    pub measured: Throughput,
    /// 测量流走的是这一对节点之间共用的连接：测量期间这一对节点之间别的流量也走在这条路径上（总是 `true`）。
    pub shared_connection: bool,
}

/// 两个方向上两种选路模式各会选哪条路。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteResult {
    pub state: ItemState,
    pub problem: Option<TestProblem>,
    /// `a` 到 `b`、`b` 到 `a`。那一端没有上报时是 `null`。
    pub forward: Option<DecisionView>,
    pub reverse: Option<DecisionView>,
}

/// 一个方向上的选择。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionView {
    pub from: NodeId,
    pub to: NodeId,
    /// 发送方现在用的模式。
    pub mode: Option<RoutingMode>,
    /// 发送方现在走的路。
    pub current: Option<Route>,
    pub direct_first: Choice,
    pub lowest_cost: Choice,
    pub candidates: Vec<PathCandidate>,
}

/// 列出测试时的查询参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TestQuery {
    /// 只要这一对节点的（两个都写时，先后无所谓）。
    #[serde(default)]
    pub a: Option<NodeId>,
    #[serde(default)]
    pub b: Option<NodeId>,
    /// 最多多少个，默认 20。
    #[serde(default)]
    pub limit: Option<u32>,
}

/// 一次全网矩阵。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixRun {
    pub id: u64,
    pub network: NetworkId,
    pub state: MatrixState,
    pub started_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    /// 同时最多跑几个测试。
    pub concurrency: u32,
    /// 一共几对，已经有结果的几对。
    pub total: u32,
    pub finished: u32,
    /// 开始时网络里的节点。
    pub nodes: Vec<NodeRef>,
    /// 每一对一格，`a` 的编号小于 `b`。
    pub cells: Vec<MatrixCell>,
}

/// 矩阵的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixState {
    Running,
    Done,
    Cancelled,
    #[serde(other)]
    Unknown,
}

/// 矩阵里的一对。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixCell {
    pub a: NodeId,
    pub b: NodeId,
    pub state: CellState,
    /// 这一对的测试（看细节用 `GET …/tests/{id}`）；还没开始或者没有做时是 `null`。
    pub test: Option<u64>,
    /// 能不能直连，怎么连上的，用了多久。
    pub direct_ok: Option<bool>,
    pub direct_kind: Option<DirectKind>,
    pub direct_elapsed_ms: Option<u32>,
    /// 测延迟的那条路径：有直连时是直连，否则是默认模式会经的 relay。
    pub route: Option<Route>,
    pub latency: Option<Latency>,
    pub problem: Option<TestProblem>,
}

/// 矩阵里一对的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellState {
    Pending,
    Running,
    Done,
    /// 没有做：节点不在线、版本太旧、访问规则没有连通（原因在 `problem` 里）。
    Skipped,
    Failed,
    Cancelled,
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_result_is_one_flat_object_with_null_for_what_was_not_read() {
        let pending = HostResult { node: NodeId::new(3).unwrap(), state: ItemState::Pending, problem: None, report: HostReport::default() };
        assert_eq!(
            serde_json::to_value(&pending).unwrap(),
            serde_json::json!({
                "node": 3, "state": "pending", "problem": null,
                "system": null, "cpu": null, "cpu_peak": null, "load_x100": null,
                "memory": null, "process": null, "connections": null, "to_peer": null
            })
        );
        let report = HostReport {
            cpu_peak: Some(CpuUse { system_percent: 61, process_percent: 98 }),
            load_x100: Some([35, 22, 18]),
            ..HostReport::default()
        };
        let done = HostResult { state: ItemState::Done, report, ..pending };
        let wire = serde_json::to_value(&done).unwrap();
        assert_eq!(wire["cpu_peak"], serde_json::json!({ "system_percent": 61, "process_percent": 98 }));
        assert_eq!(wire["load_x100"], serde_json::json!([35, 22, 18]));
        assert_eq!(serde_json::from_value::<HostResult>(wire).unwrap(), done);

        assert_eq!(serde_json::to_value(TestItem::Host).unwrap(), serde_json::json!("host"));
        assert!(TestItem::ALL.contains(&TestItem::Host), "没有写测试项时也做这一项");
    }

    #[test]
    fn a_test_request_needs_only_the_two_nodes() {
        let request: CreateTest = serde_json::from_value(serde_json::json!({ "a": 1, "b": 2 })).unwrap();
        assert_eq!((request.items, request.throughput, request.via.len()), (None, false, 0));
        let request: CreateTest =
            serde_json::from_value(serde_json::json!({ "a": 1, "b": 2, "items": ["relay_quality"], "throughput": true, "via": [[3, 4]] }))
                .unwrap();
        assert_eq!(request.items, Some(vec![TestItem::RelayQuality]));
        assert_eq!(request.via, vec![vec![NodeId::new(3).unwrap(), NodeId::new(4).unwrap()]]);
    }

    #[test]
    fn a_throughput_result_keeps_the_measured_fields_on_the_same_level() {
        let result = ThroughputResult {
            state: ItemState::Done,
            problem: None,
            measured: Throughput {
                up: None,
                down: Some(Transfer { bytes: 1000, ms: 10, bits_per_second: Some(800_000), stopped_by: TransferEnd::Bytes }),
                failure: None,
                transport: "quic".to_owned(),
                congestion: "bbr".to_owned(),
                limit_bytes: 20_000_000,
                limit_ms: 5000,
                pinned: true,
            },
            shared_connection: true,
        };
        let wire = serde_json::to_value(&result).unwrap();
        assert_eq!(wire["down"]["bits_per_second"], 800_000);
        assert_eq!((wire["congestion"].as_str(), wire["shared_connection"].as_bool()), (Some("bbr"), Some(true)));
        assert_eq!(serde_json::from_value::<ThroughputResult>(wire).unwrap(), result);
    }
}
