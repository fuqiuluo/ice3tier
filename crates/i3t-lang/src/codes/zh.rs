//! 控制面的代码的中文写法。

use i3t_model::admin::diag::{CellState, ItemState, MatrixState, TestState};
use i3t_model::admin::{
    AddressSource, ApiError, ExitHealth, ForwardStatus, LaneBlock, NodeWarning, PackageState, PathSource, ProxyStatus, ReachCause,
    ReleaseCause, SkipCause, TokenState, UpdateWait,
};
use i3t_model::control::diag::{ChoiceCode, HopSource, PathPick, TestCode, TransferEnd};
use i3t_model::control::exit_test::{ExitTestCause, ExitVia};
use i3t_model::control::{
    BindCause, DirectCause, DirectKind, DirectState, DirectStatus, Firewall, LegTransport, ListenState, NameService, RejectCause,
    RelayState, Route, RouteCause, RouteHint, RuleState, TargetCause, TryOutcome, VnetCause, VnetState,
};
use i3t_model::netmap::IpFamily;
use i3t_model::update::{FailureKind, SelfUpdateBlocker, UpdateCause, UpdateStatus};
use i3t_proto::flow::Class;

use super::{Codes, Names, cost_ms, relays};
use crate::Lang;

pub(super) static CODES: Codes = Codes {
    route,
    route_cause,
    route_hint,
    direct_kind,
    leg,
    relay_state,
    listen_state,
    bind_cause,
    update_status,
    update_cause,
    blocker,
    update_wait,
    release_cause,
    package_state,
    skip_cause,
    reach_cause,
    address_source,
    try_outcome,
    node_warning,
    reject_cause,
    api_error,
    lane_block,
    forward_status,
    target_cause,
    exit_test_cause,
    exit_via,
    token_state,
    proxy_status,
    exit_health,
    path_source,
    test_code,
    test_state,
    item_state,
    matrix_state,
    cell_state,
    choice,
    hop_source,
    path_pick,
    transfer_end,
    vnet_state,
    vnet_cause,
    firewall,
    name_service,
    class,
    direct_status,
};

fn route(route: &Route, names: Names<'_>) -> String {
    match route {
        Route::None => "不可达".to_owned(),
        Route::Direct { addr } => format!("直连 {addr}"),
        Route::Relay { relays: path } => format!("经 {}", relays(path, names)),
    }
}

fn route_cause(cause: &RouteCause, names: Names<'_>) -> String {
    let cost = |cost_us: Option<u64>| cost_us.map(|cost| format!("，代价 {} ms", cost_ms(cost))).unwrap_or_default();
    match cause {
        RouteCause::NoRouteYet => "还没有路".to_owned(),
        RouteCause::TestPinned => "主动测试暂时固定了这条路".to_owned(),
        RouteCause::TestEnded => "主动测试结束，回到选路规则选的路".to_owned(),
        RouteCause::DirectVerified => "直连验证通过".to_owned(),
        RouteCause::DirectLost { hint } => format!("{}，退回中继", route_hint(*hint)),
        RouteCause::RelayReady => "中转会话可用".to_owned(),
        RouteCause::LegChanged { transport: Some(transport) } => format!("到中继的会话改走 {}", leg(*transport)),
        RouteCause::LegChanged { transport: None } => "改经本节点自己的中继".to_owned(),
        RouteCause::RelayChanged { hint, previous } => format!("{}，原来经 {}", route_hint(*hint), relays(previous, names)),
        RouteCause::NoSharedRelay { hint: None } => "没有两端都用得上的中继，经多个中继".to_owned(),
        RouteCause::NoSharedRelay { hint: Some(hint) } => format!("{}；没有两端都用得上的中继，经多个中继", route_hint(*hint)),
        RouteCause::Unreachable { hint } => route_hint(*hint).to_owned(),
        RouteCause::PeerRemoved => "对端不在本节点的配置里了".to_owned(),
        RouteCause::Lan => "同一个局域网，直连优先".to_owned(),
        RouteCause::LowestCost { candidates, cost_us } => format!("{candidates} 条候选里代价最低{}", cost(*cost_us)),
        RouteCause::Failover { hint, candidates, cost_us } => {
            format!("{}，立刻换到 {candidates} 条候选里代价最低的{}", route_hint(*hint), cost(*cost_us))
        }
        RouteCause::Cheaper { previous, previous_cost_us, cost_us, windows } => format!(
            "连续 {windows} 个评估窗口比原来的{}便宜：{} ms，原来 {} ms",
            route(previous, names),
            cost_ms(*cost_us),
            cost_ms(*previous_cost_us)
        ),
        RouteCause::Unknown => "原因未知".to_owned(),
    }
}

const fn route_hint(hint: RouteHint) -> &'static str {
    match hint {
        RouteHint::DirectTimeouts => "直连探测连续超时",
        RouteHint::DirectLoss => "直连丢包超过 20%",
        RouteHint::DirectStale => "直连地址过期",
        RouteHint::DirectUnavailable => "直连不可用",
        RouteHint::RelayDraining => "中继即将下线",
        RouteHint::RelayOverloaded => "中继过载",
        RouteHint::RelayPathBroken => "多级路径走不通",
        RouteHint::PeerNotAttached => "对端没有挂靠这个中继",
        RouteHint::PathProbeSilent => "多级路径的探测没有回音",
        RouteHint::PreferredRelayReady => "对端优先的中继可用了",
        RouteHint::Shortcut => "有了少绕路的中转会话",
        RouteHint::RelayUnavailable => "原来的中继不可用",
        RouteHint::RelayLost => "中转会话断开",
        RouteHint::RouteFailed => "原来的路不可用",
        RouteHint::NoPath => "没有可用的路",
        RouteHint::Unknown => "原因未知",
    }
}

const fn direct_kind(kind: DirectKind) -> &'static str {
    match kind {
        DirectKind::Lan => "局域网",
        DirectKind::Ipv6 => "IPv6",
        DirectKind::Reachable => "地址可达",
        DirectKind::Punched => "打洞",
        DirectKind::Unknown => "未知",
    }
}

const fn leg(transport: LegTransport) -> &'static str {
    match transport {
        LegTransport::Udp => "UDP",
        LegTransport::Tcp => "TCP",
        LegTransport::Unknown => "未知",
    }
}

const fn relay_state(state: RelayState) -> &'static str {
    match state {
        RelayState::Serving => "正常",
        RelayState::Overloaded => "过载",
        RelayState::Draining => "即将下线",
        RelayState::Unknown => "未知",
    }
}

fn listen_state(state: &ListenState) -> String {
    let failed = |detail: &str, cause: Option<BindCause>| match cause {
        Some(cause) => bind_cause(cause).to_owned(),
        None => format!("没有绑上：{detail}"),
    };
    match state {
        ListenState::Listening { local } => format!("监听在 {local}"),
        ListenState::PortInUse { .. } => bind_cause(BindCause::AddressInUse).to_owned(),
        ListenState::Failed { detail, cause } | ListenState::Unsupported { detail, cause } => failed(detail, *cause),
        ListenState::Virtual => "在虚拟 IP 上".to_owned(),
        ListenState::Unknown => "未知".to_owned(),
    }
}

const fn bind_cause(cause: BindCause) -> &'static str {
    match cause {
        BindCause::AddressInUse => "端口被占用",
        BindCause::PermissionDenied => "没有权限",
        BindCause::AddressNotAvailable => "地址不在这台机器上",
        BindCause::VirtualPortZero => "虚拟 IP 上要写明端口",
        BindCause::Other => "没有绑上",
        BindCause::Unknown => "原因未知",
    }
}

fn update_status(status: &UpdateStatus) -> String {
    match status {
        UpdateStatus::Idle => "没有在更新".to_owned(),
        UpdateStatus::Downloading { version, received, total } => format!("正在下载 {version}（{received}/{total} 字节）"),
        UpdateStatus::Verifying { version } => format!("正在核对 {version}"),
        UpdateStatus::SelfCheck { version } => format!("正在自检 {version}"),
        UpdateStatus::WaitingForIdle { version } => format!("{version} 已就绪，等待空闲"),
        UpdateStatus::Draining { version } => format!("{version} 已就绪，正在排空"),
        UpdateStatus::Installing { version } => format!("正在安装 {version}"),
        UpdateStatus::Restarting { version } => format!("正在重启到 {version}"),
        UpdateStatus::Confirmed { version } => format!("已更新到 {version}"),
        UpdateStatus::Failed { version, kind, reason, cause } => {
            let version = version.as_ref().map_or_else(|| "新版本".to_owned(), ToString::to_string);
            let why = cause.as_ref().map_or_else(|| reason.clone(), update_cause);
            let kind = match kind {
                FailureKind::VersionRejected => "这个版本不再自动重试",
                FailureKind::NotInstalled => "以后会再试",
            };
            format!("更新到 {version} 失败：{why}（{kind}）")
        }
        UpdateStatus::Unknown => "未知".to_owned(),
    }
}

fn update_cause(cause: &UpdateCause) -> String {
    match cause {
        UpdateCause::BadSignature => "清单的签名不对".to_owned(),
        UpdateCause::BadManifest => "清单读不懂".to_owned(),
        UpdateCause::CannotSelfUpdate { blocker: why } => blocker(*why).to_owned(),
        UpdateCause::NotNewer { offered, running } => format!("{offered} 不比正在运行的 {running} 新"),
        UpdateCause::Prerelease { offered, .. } => format!("{offered} 是预发布版"),
        UpdateCause::FailedBefore { version } => format!("{version} 在这台机器上失败过"),
        UpdateCause::NoPackage { version, platform } => format!("{version} 没有 {platform} 的包"),
        UpdateCause::RestartPending { installed } => format!("已换上 {installed}，等待重启"),
        UpdateCause::Unavailable { detail } => format!("取不到包：{detail}"),
        UpdateCause::Corrupt { expected_size, actual_size } => {
            format!("包和清单对不上（{actual_size} 字节，应为 {expected_size} 字节）")
        }
        UpdateCause::SelfCheck { exit_code: Some(code), output } => format!("自检没有通过（退出码 {code}）：{output}"),
        UpdateCause::SelfCheck { exit_code: None, output } => format!("自检没有通过：{output}"),
        UpdateCause::Cancelled => "等不到换程序的时机".to_owned(),
        UpdateCause::Io { path, error } => format!("读写 {path} 失败：{error}"),
        UpdateCause::StateUnreadable { path } => format!("更新状态文件 {path} 读不懂"),
        UpdateCause::NotConfirmed { minutes } => format!("新程序 {minutes} 分钟内没有连上 controller，已换回"),
        UpdateCause::StartsUnconfirmed { starts } => format!("新程序启动 {starts} 次都没有连上 controller，已换回"),
        UpdateCause::Unknown => "原因未知".to_owned(),
    }
}

const fn blocker(blocker: SelfUpdateBlocker) -> &'static str {
    match blocker {
        SelfUpdateBlocker::Container => "在容器里运行，换镜像来更新",
        SelfUpdateBlocker::PackageManager => "由包管理器安装，用包管理器更新",
        SelfUpdateBlocker::ReadOnlyDir => "程序目录不可写",
    }
}

const fn update_wait(wait: UpdateWait) -> &'static str {
    match wait {
        UpdateWait::Package => "等待下载包",
        UpdateWait::RelayTurn => "等待前一个中继更新完",
        UpdateWait::Unknown => "等待中",
    }
}

fn release_cause(cause: &ReleaseCause) -> String {
    match cause {
        ReleaseCause::InvalidSource => "发布源的写法不对".to_owned(),
        ReleaseCause::FetchFailed { url, error } => format!("取不到 {url}：{error}"),
        ReleaseCause::Io { path, error } => format!("读写 {path} 失败：{error}"),
        ReleaseCause::BadSignatureFile => "签名文件不是一个签名".to_owned(),
        ReleaseCause::BadSignature => "清单的签名不对".to_owned(),
        ReleaseCause::BadManifest => "清单读不懂".to_owned(),
        ReleaseCause::Prerelease { version } => format!("最新的 {version} 是预发布版，不取"),
        ReleaseCause::BadFileName { file } => format!("文件名不对：{file}"),
        ReleaseCause::Mismatch { file, expected_size, actual_size } => {
            format!("{file} 和清单对不上（{actual_size} 字节，应为 {expected_size} 字节）")
        }
        ReleaseCause::Internal => "controller 内部出错".to_owned(),
        ReleaseCause::Unknown => "原因未知".to_owned(),
    }
}

const fn package_state(state: PackageState) -> &'static str {
    match state {
        PackageState::NotNeeded => "不需要",
        PackageState::Fetching => "正在下载",
        PackageState::Cached => "已下载",
        PackageState::Failed => "下载失败",
        PackageState::Unknown => "未知",
    }
}

fn skip_cause(cause: &SkipCause) -> String {
    match cause {
        SkipCause::Offline => "离线".to_owned(),
        SkipCause::TooOld => "版本太旧，不能自己更新".to_owned(),
        SkipCause::CannotSelfUpdate { blocker: Some(why) } => blocker(*why).to_owned(),
        SkipCause::CannotSelfUpdate { blocker: None } => "不能自己更新".to_owned(),
        SkipCause::NoRelease => "还没有查到发布".to_owned(),
        SkipCause::ControllerTooOld { min_controller, .. } => format!("要先把 controller 更新到 {min_controller}"),
        SkipCause::UnreadableVersion { version } => format!("版本号看不懂：{version}"),
        SkipCause::UpToDate { running, .. } => format!("已是最新（{running}）"),
        SkipCause::NoPackage { platform, .. } => format!("没有 {platform} 的包"),
        SkipCause::Unknown => "原因未知".to_owned(),
    }
}

const fn reach_cause(cause: ReachCause) -> &'static str {
    match cause {
        ReachCause::Refused => "连接被拒绝",
        ReachCause::Timeout => "超时",
        ReachCause::Unreachable => "网络不通",
        ReachCause::Local => "controller 这边出错",
        ReachCause::Other => "连不上",
        ReachCause::Unknown => "原因未知",
    }
}

const fn try_outcome(outcome: TryOutcome) -> &'static str {
    match outcome {
        TryOutcome::Udp => "UDP",
        TryOutcome::Tcp => "只有 TCP",
        TryOutcome::Unreached => "连不上",
        TryOutcome::Unknown => "未知",
    }
}

const fn address_source(source: AddressSource) -> &'static str {
    match source {
        AddressSource::Declared => "节点上声明的",
        AddressSource::Observed => "controller 看到的",
        AddressSource::Local => "网卡上的",
        AddressSource::Unknown => "来源未知",
    }
}

fn node_warning(warning: &NodeWarning) -> String {
    match warning {
        NodeWarning::RangeOverlap { address } => format!("网卡地址 {address} 在网络的地址段里"),
        NodeWarning::RelayUnreached { tried } => format!("在线的节点里有 {tried} 个试过这个中继，都没连上"),
        NodeWarning::Unknown => "未知的提醒".to_owned(),
    }
}

const fn reject_cause(cause: RejectCause) -> &'static str {
    match cause {
        RejectCause::BadToken => "注册令牌无效：不存在、已经用过或者已经过期",
        RejectCause::UnknownKey => "这把公钥没有注册，节点可能已被删除，要重新加入",
        RejectCause::KeyAlreadyEnrolled => "这把公钥已经注册过",
        RejectCause::PredecessorOnline => "要继任的节点还在线",
        RejectCause::AddressUnavailable => "令牌预设的虚拟 IP 现在不能用",
        RejectCause::RangeExhausted => "地址段里没有空闲的地址了",
        RejectCause::UnexpectedFirstMessage => "连接上的第一条消息不对",
        RejectCause::Unknown => "原因未知",
    }
}

/// controller 的原话本来就是中文，并且比按代码拼出来的说得细。
fn api_error(error: &ApiError) -> String {
    error.message.clone()
}

fn lane_block(block: &LaneBlock, names: Names<'_>) -> String {
    match block {
        LaneBlock::NoRelay => "两个节点都没有启用中继".to_owned(),
        LaneBlock::NoTcpAddress { node } => format!("{} 还没有已知的地址", names(*node)),
        LaneBlock::NodeTooOld { node } => format!("{} 的版本太旧", names(*node)),
        LaneBlock::NotConnected => "访问规则不让监听的节点访问出口".to_owned(),
    }
}

const fn forward_status(status: ForwardStatus) -> &'static str {
    match status {
        ForwardStatus::Disabled => "已停用",
        ForwardStatus::ForwardTargetOff => "目标的转发开关关着",
        ForwardStatus::AccessDenied => "访问规则不允许",
        ForwardStatus::TargetNotAllowed => "目标地址不能用",
        ForwardStatus::ListenerOffline => "监听节点离线",
        ForwardStatus::TargetOffline => "目标节点离线",
        ForwardStatus::Active => "生效",
        ForwardStatus::Unknown => "未知",
    }
}

const fn target_cause(cause: TargetCause) -> &'static str {
    match cause {
        TargetCause::Refused => "目标拒绝连接",
        TargetCause::Timeout => "连目标超时",
        TargetCause::Unreachable => "目标不可达",
        TargetCause::NotDeclared => "目标节点没有这条转发",
        TargetCause::AccessDenied => "目标节点不允许访问",
        TargetCause::NodeUnreachable => "到目标节点不通",
        TargetCause::Other => "目标连不上",
        TargetCause::Unknown => "目标连不上",
    }
}

fn exit_test_cause(cause: &ExitTestCause) -> String {
    let family = |family: IpFamily| match family {
        IpFamily::Ipv4 => "IPv4",
        IpFamily::Ipv6 => "IPv6",
        IpFamily::Any => "任何",
    };
    match cause {
        ExitTestCause::Busy => "出口上另一个测试正在做或者刚做过，稍后再试".to_owned(),
        ExitTestCause::BadTarget => "出口读不懂这个目标".to_owned(),
        ExitTestCause::NotEnabled => "这个节点没有启用出口".to_owned(),
        ExitTestCause::LanNotEnabled => "局域网的地址：出口没有打开局域网访问".to_owned(),
        ExitTestCause::PortNotAllowed { port } => format!("端口 {port} 不在出口允许的范围里"),
        ExitTestCause::FamilyUnavailable { family: wanted } => format!("出口只连 {} 地址，目标没有", family(*wanted)),
        ExitTestCause::AddressNotAllowed { address } => format!("出口不替别人连 {address} 这类地址"),
        ExitTestCause::NotOnLan { address } => format!("{address} 不在出口直连的网段里"),
        ExitTestCause::NameNotFound => "域名不存在".to_owned(),
        ExitTestCause::ResolverFailed => "解析器出错".to_owned(),
        ExitTestCause::Timeout => "超时".to_owned(),
        ExitTestCause::Refused => "连接被拒绝".to_owned(),
        ExitTestCause::Unreachable => "不可达".to_owned(),
        ExitTestCause::UpstreamFailed => "连不上出口的上游代理".to_owned(),
        ExitTestCause::Closed => "握手完成之前对方关了连接".to_owned(),
        ExitTestCause::Alert => "对方回了 TLS 告警".to_owned(),
        ExitTestCause::Other | ExitTestCause::Unknown => "别的原因，见出口节点的日志".to_owned(),
    }
}

const fn exit_via(via: ExitVia) -> &'static str {
    match via {
        ExitVia::Direct => "直接连",
        ExitVia::Upstream => "经上游代理",
        ExitVia::Unknown => "不知道经什么",
    }
}

const fn token_state(state: TokenState) -> &'static str {
    match state {
        TokenState::Pending => "未使用",
        TokenState::Used => "已使用",
        TokenState::Expired => "已过期",
        TokenState::Unknown => "未知",
    }
}

fn proxy_status(status: &ProxyStatus) -> String {
    match status {
        ProxyStatus::Listening { local } => format!("监听在 {local}"),
        ProxyStatus::Disabled => "已停用".to_owned(),
        ProxyStatus::Pending => "等节点报上来".to_owned(),
        ProxyStatus::NodeOffline => "节点离线".to_owned(),
        ProxyStatus::PortInUse { .. } => "端口被占用".to_owned(),
        ProxyStatus::BindFailed { cause, detail } => match cause {
            Some(cause) => format!("没有绑上：{}", bind_cause(*cause)),
            None => format!("没有绑上：{detail}"),
        },
        ProxyStatus::ExitDisabled { .. } => "出口节点没有启用出口".to_owned(),
        ProxyStatus::AccessDenied { .. } => "访问规则不允许它访问出口".to_owned(),
        ProxyStatus::ExitOffline { .. } => "出口离线".to_owned(),
        ProxyStatus::ExitMissing => "没有出口：选好出口才能启用".to_owned(),
        ProxyStatus::Unknown => "未知".to_owned(),
    }
}

const fn exit_health(health: ExitHealth) -> &'static str {
    match health {
        ExitHealth::Ok => "正常",
        ExitHealth::Degraded => "异常",
        ExitHealth::Unknown => "未知",
    }
}

const fn path_source(source: PathSource) -> &'static str {
    match source {
        PathSource::Query => "现问",
        PathSource::Report => "上报",
        PathSource::None => "没有数据",
        PathSource::NotPeers => "不连通",
        PathSource::Unknown => "未知",
    }
}

const fn test_code(code: TestCode) -> &'static str {
    match code {
        TestCode::NotSupported => "版本太旧，不支持主动测试",
        TestCode::NodeOffline => "离线",
        TestCode::NotConnected => "访问规则没有连通",
        TestCode::RelayOnly => "只经中继，不测直连",
        TestCode::DirectOnly => "只直连，不测中继",
        TestCode::ThroughputOff => "关掉了吞吐测试",
        TestCode::NoRelay => "没有可用的中继路径",
        TestCode::NoDirect => "没有可用的直连",
        TestCode::NoCandidates => "没有对端的候选地址",
        TestCode::UdpBlocked => "UDP 不通",
        TestCode::MappingVaries => "端口映射随对端变化，打不了洞",
        TestCode::DialOutOnly => "两个节点都只主动连接",
        TestCode::Timeout => "超时",
        TestCode::Unreachable => "路径走不通",
        TestCode::Refused => "对端拒绝了测量",
        TestCode::Busy => "节点正忙",
        TestCode::TooSoon => "刚测过",
        TestCode::Cancelled => "已取消",
        TestCode::NoReport => "没有按时报告结果",
        TestCode::StreamFailed => "测量中途断开",
        TestCode::InvalidPath => "路径不能用",
        TestCode::Internal => "内部出错",
        TestCode::Unknown => "原因未知",
    }
}

const fn test_state(state: TestState) -> &'static str {
    match state {
        TestState::Running => "进行中",
        TestState::Done => "完成",
        TestState::Failed => "失败",
        TestState::Cancelled => "已取消",
        TestState::Unknown => "未知",
    }
}

const fn item_state(state: ItemState) -> &'static str {
    match state {
        ItemState::Pending => "等待",
        ItemState::Done => "完成",
        ItemState::Skipped => "跳过",
        ItemState::Failed => "失败",
        ItemState::Unknown => "未知",
    }
}

const fn matrix_state(state: MatrixState) -> &'static str {
    match state {
        MatrixState::Running => "进行中",
        MatrixState::Done => "完成",
        MatrixState::Cancelled => "已取消",
        MatrixState::Unknown => "未知",
    }
}

const fn cell_state(state: CellState) -> &'static str {
    match state {
        CellState::Pending => "等待",
        CellState::Running => "进行中",
        CellState::Done => "完成",
        CellState::Skipped => "跳过",
        CellState::Failed => "失败",
        CellState::Cancelled => "已取消",
        CellState::Unknown => "未知",
    }
}

const fn choice(code: ChoiceCode) -> &'static str {
    match code {
        ChoiceCode::Lan => "局域网直连优先",
        ChoiceCode::Direct => "直连可用",
        ChoiceCode::PeerIsRelay => "对端是中继",
        ChoiceCode::OwnRelay => "对端挂靠本节点",
        ChoiceCode::PeerRelay => "对端挂靠的中继",
        ChoiceCode::NoSharedRelay => "没有两端都用得上的中继，经多个中继",
        ChoiceCode::LowestCost => "代价最低",
        ChoiceCode::WithinMargin => "不换：便宜得不够换路",
        ChoiceCode::NoPath => "没有路",
        ChoiceCode::Unknown => "未知",
    }
}

const fn hop_source(source: HopSource) -> &'static str {
    match source {
        HopSource::Measured => "实测",
        HopSource::Backbone => "骨干",
        HopSource::Reported => "对端上报",
        HopSource::Unknown => "未知",
    }
}

const fn path_pick(pick: PathPick) -> &'static str {
    match pick {
        PathPick::Direct => "直连",
        PathPick::DirectFirst => "默认",
        PathPick::LowestCost => "延迟优先",
        PathPick::Admin => "指定",
        PathPick::Unknown => "未知",
    }
}

const fn transfer_end(end: TransferEnd) -> &'static str {
    match end {
        TransferEnd::Finished => "传完",
        TransferEnd::Bytes => "到字节上限",
        TransferEnd::Time => "到时长上限",
        TransferEnd::Unknown => "未知",
    }
}

fn vnet_state(state: &VnetState) -> String {
    match state {
        VnetState::Installed { device, mtu, names } => format!("装着（{device}，MTU {mtu}；{}）", name_service(names)),
        VnetState::Off => "关着".to_owned(),
        VnetState::Failed { cause } => format!("装不上：{}", vnet_cause(cause)),
        VnetState::Unsupported => "这个平台上没有".to_owned(),
        VnetState::Unknown => "未知".to_owned(),
    }
}

fn vnet_cause(cause: &VnetCause) -> String {
    match cause {
        VnetCause::NoPermission { missing } => match missing.as_slice() {
            [only] if only == "Administrator" => "要以管理员运行".to_owned(),
            [only] if only == "root" => "要 root".to_owned(),
            missing => format!("缺 {}", missing.join("、")),
        },
        VnetCause::NoDevice { detail } => format!("打不开建网卡用的设备：{detail}"),
        VnetCause::DriverMissing { path } => format!("程序旁边没有 wintun.dll（{path}）"),
        VnetCause::DeviceFailed { detail } => format!("网卡建不起来：{detail}"),
        VnetCause::ProgramMissing { program } => match program.as_str() {
            "nft" => "找不到 nft（装 nftables）".to_owned(),
            "ip" => "找不到 ip（装 iproute2）".to_owned(),
            "iptables" => "找不到 iptables".to_owned(),
            other => format!("找不到 {other}"),
        },
        VnetCause::CommandFailed { program, detail } => format!("{program} 报错：{detail}"),
        VnetCause::PortInUse { address } => format!("{address} 被占用"),
        VnetCause::BindFailed { address, detail } => format!("绑不上 {address}：{detail}"),
        VnetCause::RangeInUse { with } => format!("网络的地址段和本机的 {with} 重叠"),
        VnetCause::Unknown => "未知原因".to_owned(),
    }
}

fn rule_state(state: &RuleState) -> String {
    match state {
        RuleState::On => "开着".to_owned(),
        RuleState::Off => "没加".to_owned(),
        RuleState::Failed { cause } => format!("加不上（{}）", vnet_cause(cause)),
        RuleState::Unsupported => "这个平台上不加".to_owned(),
        RuleState::NotNeeded => "不需要".to_owned(),
        RuleState::Unknown => "未知".to_owned(),
    }
}

fn firewall(firewall: &Firewall) -> String {
    match (&firewall.accept, &firewall.guard) {
        (RuleState::Off, RuleState::Off) => "没加规则".to_owned(),
        (RuleState::Unsupported, RuleState::Unsupported) => "这个平台上不加规则".to_owned(),
        (accept, guard) => format!("放行{}，防冒充{}", rule_state(accept), rule_state(guard)),
    }
}

fn name_service(names: &NameService) -> String {
    match names {
        NameService::Resolved => "名字经 systemd-resolved".to_owned(),
        NameService::NoResolver => "名字用 i3t hosts".to_owned(),
        NameService::Failed { cause } => format!("名字解析不了：{}", vnet_cause(cause)),
        NameService::Unknown => "名字：未知".to_owned(),
    }
}

const fn class(class: Class) -> &'static str {
    match class {
        Class::Auto => "自动",
        Class::Interactive => "低延迟",
        Class::Reliable => "不丢包",
        Class::Bulk => "后台",
    }
}

fn direct_status(status: &DirectStatus) -> String {
    let state = match status.state {
        DirectState::NotTried => "未尝试",
        DirectState::Trying => "尝试中",
        DirectState::Verified => "已通",
        DirectState::Failed => "失败",
        DirectState::Unknown => "未知",
    };
    let aside: Vec<String> = match status.state {
        DirectState::Verified => status.kind.map(|kind| direct_kind(kind).to_owned()).into_iter().collect(),
        DirectState::Failed => {
            let cause = status.cause.map(|cause| direct_cause(cause).to_owned());
            cause.into_iter().chain(status.attempted_secs_ago.map(|ago| Lang::ZhCn.ago(ago))).collect()
        }
        DirectState::NotTried | DirectState::Trying | DirectState::Unknown => Vec::new(),
    };
    if aside.is_empty() { state.to_owned() } else { format!("{state}（{}）", aside.join("，")) }
}

const fn direct_cause(cause: DirectCause) -> &'static str {
    match cause {
        DirectCause::NoAnswer => "没有回应",
        DirectCause::NoCandidates => "没有对端的地址",
        DirectCause::Timeouts => "探测超时",
        DirectCause::Loss => "丢包太多",
        DirectCause::Stale => "闲置后放下",
        DirectCause::Unknown => "未知原因",
    }
}
