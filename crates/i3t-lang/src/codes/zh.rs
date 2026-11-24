//! 控制面状态码与原因码的中文文案。

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
        RouteCause::NoRouteYet => "暂无可用路径".to_owned(),
        RouteCause::TestPinned => "主动测试暂时固定了当前路径".to_owned(),
        RouteCause::TestEnded => "主动测试结束，恢复按选路规则选择路径".to_owned(),
        RouteCause::DirectVerified => "直连验证通过".to_owned(),
        RouteCause::DirectLost { hint } => format!("{}，退回中继", route_hint(*hint)),
        RouteCause::RelayReady => "中转会话可用".to_owned(),
        RouteCause::LegChanged { transport: Some(transport) } => format!("到中继的会话切换为 {}", leg(*transport)),
        RouteCause::LegChanged { transport: None } => "切换为经本节点自身中继".to_owned(),
        RouteCause::RelayChanged { hint, previous } => format!("{}，原经 {}", route_hint(*hint), relays(previous, names)),
        RouteCause::NoSharedRelay { hint: None } => "没有两端均可用的中继，经多级中继".to_owned(),
        RouteCause::NoSharedRelay { hint: Some(hint) } => format!("{}；没有两端均可用的中继，经多级中继", route_hint(*hint)),
        RouteCause::Unreachable { hint } => route_hint(*hint).to_owned(),
        RouteCause::PeerRemoved => "对端已不在本节点配置中".to_owned(),
        RouteCause::Lan => "同一局域网，直连优先".to_owned(),
        RouteCause::LowestCost { candidates, cost_us } => format!("{candidates} 条候选路径中代价最低{}", cost(*cost_us)),
        RouteCause::Failover { hint, candidates, cost_us } => {
            format!("{}，立即切换至 {candidates} 条候选路径中代价最低的路径{}", route_hint(*hint), cost(*cost_us))
        }
        RouteCause::Cheaper { previous, previous_cost_us, cost_us, windows } => format!(
            "连续 {windows} 个评估窗口代价低于原路径（{}）：{} ms，原为 {} ms",
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
        RouteHint::RelayPathBroken => "多级中继路径中断",
        RouteHint::PeerNotAttached => "对端未挂靠该中继",
        RouteHint::PathProbeSilent => "多级路径探测无响应",
        RouteHint::PreferredRelayReady => "对端优先中继已可用",
        RouteHint::Shortcut => "已有更短的中转会话",
        RouteHint::RelayUnavailable => "原中继不可用",
        RouteHint::RelayLost => "中转会话断开",
        RouteHint::RouteFailed => "原路径不可用",
        RouteHint::NoPath => "没有可用路径",
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
        None => format!("绑定失败：{detail}"),
    };
    match state {
        ListenState::Listening { local } => format!("监听在 {local}"),
        ListenState::PortInUse { .. } => bind_cause(BindCause::AddressInUse).to_owned(),
        ListenState::Failed { detail, cause } | ListenState::Unsupported { detail, cause } => failed(detail, *cause),
        ListenState::Virtual => "位于虚拟 IP".to_owned(),
        ListenState::Unknown => "未知".to_owned(),
    }
}

const fn bind_cause(cause: BindCause) -> &'static str {
    match cause {
        BindCause::AddressInUse => "端口被占用",
        BindCause::PermissionDenied => "没有权限",
        BindCause::AddressNotAvailable => "本机不存在该地址",
        BindCause::VirtualPortZero => "虚拟 IP 上必须指定端口",
        BindCause::Other => "绑定失败",
        BindCause::Unknown => "原因未知",
    }
}

fn update_status(status: &UpdateStatus) -> String {
    match status {
        UpdateStatus::Idle => "未在更新".to_owned(),
        UpdateStatus::Downloading { version, received, total } => format!("正在下载 {version}（{received}/{total} 字节）"),
        UpdateStatus::Verifying { version } => format!("正在校验 {version}"),
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
                FailureKind::VersionRejected => "该版本不再自动重试",
                FailureKind::NotInstalled => "后续将重试",
            };
            format!("更新到 {version} 失败：{why}（{kind}）")
        }
        UpdateStatus::Unknown => "未知".to_owned(),
    }
}

fn update_cause(cause: &UpdateCause) -> String {
    match cause {
        UpdateCause::BadSignature => "清单签名无效".to_owned(),
        UpdateCause::BadManifest => "无法解析清单".to_owned(),
        UpdateCause::CannotSelfUpdate { blocker: why } => blocker(*why).to_owned(),
        UpdateCause::NotNewer { offered, running } => format!("{offered} 不高于当前运行的 {running}"),
        UpdateCause::Prerelease { offered, .. } => format!("{offered} 是预发布版"),
        UpdateCause::FailedBefore { version } => format!("{version} 在本机曾更新失败"),
        UpdateCause::NoPackage { version, platform } => format!("{version} 缺少 {platform} 平台的安装包"),
        UpdateCause::RestartPending { installed } => format!("已安装 {installed}，等待重启"),
        UpdateCause::Unavailable { detail } => format!("无法获取安装包：{detail}"),
        UpdateCause::Corrupt { expected_size, actual_size } => {
            format!("安装包与清单不符（实际 {actual_size} 字节，应为 {expected_size} 字节）")
        }
        UpdateCause::SelfCheck { exit_code: Some(code), output } => format!("自检未通过（退出码 {code}）：{output}"),
        UpdateCause::SelfCheck { exit_code: None, output } => format!("自检未通过：{output}"),
        UpdateCause::Cancelled => "未能等到切换程序的时机".to_owned(),
        UpdateCause::Io { path, error } => format!("读写 {path} 失败：{error}"),
        UpdateCause::StateUnreadable { path } => format!("无法解析更新状态文件 {path}"),
        UpdateCause::NotConfirmed { minutes } => format!("新程序在 {minutes} 分钟内未能连接到 controller，已回滚"),
        UpdateCause::StartsUnconfirmed { starts } => format!("新程序启动 {starts} 次均未能连接到 controller，已回滚"),
        UpdateCause::Unknown => "原因未知".to_owned(),
    }
}

const fn blocker(blocker: SelfUpdateBlocker) -> &'static str {
    match blocker {
        SelfUpdateBlocker::Container => "运行在容器中，请通过更换镜像更新",
        SelfUpdateBlocker::PackageManager => "由包管理器安装，请通过包管理器更新",
        SelfUpdateBlocker::ReadOnlyDir => "程序目录不可写",
    }
}

const fn update_wait(wait: UpdateWait) -> &'static str {
    match wait {
        UpdateWait::Package => "等待下载安装包",
        UpdateWait::RelayTurn => "等待前一个中继更新完成",
        UpdateWait::Unknown => "等待中",
    }
}

fn release_cause(cause: &ReleaseCause) -> String {
    match cause {
        ReleaseCause::InvalidSource => "发布源配置格式无效".to_owned(),
        ReleaseCause::FetchFailed { url, error } => format!("获取 {url} 失败：{error}"),
        ReleaseCause::Io { path, error } => format!("读写 {path} 失败：{error}"),
        ReleaseCause::BadSignatureFile => "签名文件格式无效".to_owned(),
        ReleaseCause::BadSignature => "清单签名无效".to_owned(),
        ReleaseCause::BadManifest => "无法解析清单".to_owned(),
        ReleaseCause::Prerelease { version } => format!("最新版本 {version} 为预发布版，已跳过"),
        ReleaseCause::BadFileName { file } => format!("文件名无效：{file}"),
        ReleaseCause::Mismatch { file, expected_size, actual_size } => {
            format!("{file} 与清单不符（实际 {actual_size} 字节，应为 {expected_size} 字节）")
        }
        ReleaseCause::Internal => "controller 内部错误".to_owned(),
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
        SkipCause::TooOld => "版本过旧，不支持自更新".to_owned(),
        SkipCause::CannotSelfUpdate { blocker: Some(why) } => blocker(*why).to_owned(),
        SkipCause::CannotSelfUpdate { blocker: None } => "不支持自更新".to_owned(),
        SkipCause::NoRelease => "尚未获取到发布版本".to_owned(),
        SkipCause::ControllerTooOld { min_controller, .. } => format!("需先将 controller 更新至 {min_controller}"),
        SkipCause::UnreadableVersion { version } => format!("无法解析版本号：{version}"),
        SkipCause::UpToDate { running, .. } => format!("已是最新（{running}）"),
        SkipCause::NoPackage { platform, .. } => format!("缺少 {platform} 平台的安装包"),
        SkipCause::Unknown => "原因未知".to_owned(),
    }
}

const fn reach_cause(cause: ReachCause) -> &'static str {
    match cause {
        ReachCause::Refused => "连接被拒绝",
        ReachCause::Timeout => "超时",
        ReachCause::Unreachable => "网络不通",
        ReachCause::Local => "controller 端发生错误",
        ReachCause::Other => "无法连接",
        ReachCause::Unknown => "原因未知",
    }
}

const fn try_outcome(outcome: TryOutcome) -> &'static str {
    match outcome {
        TryOutcome::Udp => "UDP",
        TryOutcome::Tcp => "仅 TCP",
        TryOutcome::Unreached => "不可达",
        TryOutcome::Unknown => "未知",
    }
}

const fn address_source(source: AddressSource) -> &'static str {
    match source {
        AddressSource::Declared => "节点声明",
        AddressSource::Observed => "controller 观测",
        AddressSource::Local => "本机网卡",
        AddressSource::Unknown => "来源未知",
    }
}

fn node_warning(warning: &NodeWarning) -> String {
    match warning {
        NodeWarning::RangeOverlap { address } => format!("网卡地址 {address} 在网络的地址段里"),
        NodeWarning::RelayUnreached { tried } => format!("{tried} 个在线节点尝试连接该中继均未成功"),
        NodeWarning::Unknown => "未知提醒".to_owned(),
    }
}

const fn reject_cause(cause: RejectCause) -> &'static str {
    match cause {
        RejectCause::BadToken => "注册令牌无效：不存在、已使用或已过期",
        RejectCause::UnknownKey => "该公钥未注册，节点可能已被删除，需重新加入",
        RejectCause::KeyAlreadyEnrolled => "该公钥已注册",
        RejectCause::PredecessorOnline => "待替换的节点仍在线",
        RejectCause::AddressUnavailable => "令牌预设的虚拟 IP 当前不可用",
        RejectCause::RangeExhausted => "地址段内已无空闲地址",
        RejectCause::UnexpectedFirstMessage => "连接首条消息无效",
        RejectCause::Unknown => "原因未知",
    }
}

/// controller 的原话本来就是中文，并且比按代码拼出来的说得细。
fn api_error(error: &ApiError) -> String {
    error.message.clone()
}

fn lane_block(block: &LaneBlock, names: Names<'_>) -> String {
    match block {
        LaneBlock::NoRelay => "两个节点均未启用中继".to_owned(),
        LaneBlock::NoTcpAddress { node } => format!("{} 尚无已知地址", names(*node)),
        LaneBlock::NodeTooOld { node } => format!("{} 版本过旧", names(*node)),
        LaneBlock::NotConnected => "访问规则不允许监听节点访问出口".to_owned(),
    }
}

const fn forward_status(status: ForwardStatus) -> &'static str {
    match status {
        ForwardStatus::Disabled => "已停用",
        ForwardStatus::ForwardTargetOff => "目标节点未开启转发",
        ForwardStatus::AccessDenied => "访问规则不允许",
        ForwardStatus::TargetNotAllowed => "目标地址不允许",
        ForwardStatus::ListenerOffline => "监听节点离线",
        ForwardStatus::TargetOffline => "目标节点离线",
        ForwardStatus::Active => "生效",
        ForwardStatus::Unknown => "未知",
    }
}

const fn target_cause(cause: TargetCause) -> &'static str {
    match cause {
        TargetCause::Refused => "目标拒绝连接",
        TargetCause::Timeout => "连接目标超时",
        TargetCause::Unreachable => "目标不可达",
        TargetCause::NotDeclared => "目标节点未配置该转发",
        TargetCause::AccessDenied => "目标节点不允许访问",
        TargetCause::NodeUnreachable => "目标节点不可达",
        TargetCause::Other => "目标连接失败",
        TargetCause::Unknown => "目标连接失败",
    }
}

fn exit_test_cause(cause: &ExitTestCause) -> String {
    let family = |family: IpFamily| match family {
        IpFamily::Ipv4 => "IPv4",
        IpFamily::Ipv6 => "IPv6",
        IpFamily::Any => "任意",
    };
    match cause {
        ExitTestCause::Busy => "出口正在执行或刚完成另一项测试，请稍后重试".to_owned(),
        ExitTestCause::BadTarget => "出口无法解析该目标".to_owned(),
        ExitTestCause::NotEnabled => "该节点未启用出口".to_owned(),
        ExitTestCause::LanNotEnabled => "局域网地址：出口未开启局域网访问".to_owned(),
        ExitTestCause::PortNotAllowed { port } => format!("端口 {port} 不在出口允许的范围里"),
        ExitTestCause::FamilyUnavailable { family: wanted } => format!("出口仅支持 {} 地址，目标无对应地址", family(*wanted)),
        ExitTestCause::AddressNotAllowed { address } => format!("出口不允许代理访问 {address} 这类地址"),
        ExitTestCause::NotOnLan { address } => format!("{address} 不在出口直连的网段里"),
        ExitTestCause::NameNotFound => "域名不存在".to_owned(),
        ExitTestCause::ResolverFailed => "解析器错误".to_owned(),
        ExitTestCause::Timeout => "超时".to_owned(),
        ExitTestCause::Refused => "连接被拒绝".to_owned(),
        ExitTestCause::Unreachable => "不可达".to_owned(),
        ExitTestCause::UpstreamFailed => "无法连接出口的上游代理".to_owned(),
        ExitTestCause::Closed => "握手完成前对端关闭了连接".to_owned(),
        ExitTestCause::Alert => "对端返回 TLS 告警".to_owned(),
        ExitTestCause::Other | ExitTestCause::Unknown => "其他原因，详见出口节点日志".to_owned(),
    }
}

const fn exit_via(via: ExitVia) -> &'static str {
    match via {
        ExitVia::Direct => "直连",
        ExitVia::Upstream => "经上游代理",
        ExitVia::Unknown => "出站路径未知",
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
        ProxyStatus::Pending => "等待节点上报".to_owned(),
        ProxyStatus::NodeOffline => "节点离线".to_owned(),
        ProxyStatus::PortInUse { .. } => "端口被占用".to_owned(),
        ProxyStatus::BindFailed { cause, detail } => match cause {
            Some(cause) => format!("绑定失败：{}", bind_cause(*cause)),
            None => format!("绑定失败：{detail}"),
        },
        ProxyStatus::ExitDisabled { .. } => "出口节点未启用出口".to_owned(),
        ProxyStatus::AccessDenied { .. } => "访问规则不允许该节点访问出口".to_owned(),
        ProxyStatus::ExitOffline { .. } => "出口离线".to_owned(),
        ProxyStatus::ExitMissing => "未指定出口：需指定出口后方可启用".to_owned(),
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
        PathSource::Query => "实时查询",
        PathSource::Report => "上报",
        PathSource::None => "无数据",
        PathSource::NotPeers => "不连通",
        PathSource::Unknown => "未知",
    }
}

const fn test_code(code: TestCode) -> &'static str {
    match code {
        TestCode::NotSupported => "版本过旧，不支持主动测试",
        TestCode::NodeOffline => "离线",
        TestCode::NotConnected => "访问规则未允许连通",
        TestCode::RelayOnly => "仅经中继，不测试直连",
        TestCode::DirectOnly => "仅直连，不测试中继",
        TestCode::ThroughputOff => "已关闭吞吐测试",
        TestCode::NoRelay => "没有可用的中继路径",
        TestCode::NoDirect => "没有可用的直连",
        TestCode::NoCandidates => "没有对端的候选地址",
        TestCode::UdpBlocked => "UDP 不通",
        TestCode::MappingVaries => "端口映射随对端变化，无法打洞",
        TestCode::DialOutOnly => "两个节点均仅主动连接",
        TestCode::Timeout => "超时",
        TestCode::Unreachable => "路径不可达",
        TestCode::Refused => "对端拒绝测量",
        TestCode::Busy => "节点正忙",
        TestCode::TooSoon => "近期已测试",
        TestCode::Cancelled => "已取消",
        TestCode::NoReport => "未按时上报结果",
        TestCode::StreamFailed => "测量中途断开",
        TestCode::InvalidPath => "路径不可用",
        TestCode::Internal => "内部错误",
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
        ChoiceCode::NoSharedRelay => "没有两端均可用的中继，经多级中继",
        ChoiceCode::LowestCost => "代价最低",
        ChoiceCode::WithinMargin => "保持原路径：代价优势未达切换阈值",
        ChoiceCode::NoPath => "无可用路径",
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
        TransferEnd::Finished => "传输完成",
        TransferEnd::Bytes => "达到字节上限",
        TransferEnd::Time => "达到时长上限",
        TransferEnd::Unknown => "未知",
    }
}

fn vnet_state(state: &VnetState) -> String {
    match state {
        VnetState::Installed { device, mtu, names } => format!("已启用（{device}，MTU {mtu}；{}）", name_service(names)),
        VnetState::Off => "已关闭".to_owned(),
        VnetState::Failed { cause } => format!("不可用（{}）", vnet_cause(cause)),
        VnetState::Unsupported => "当前平台不支持".to_owned(),
        VnetState::Unknown => "未知".to_owned(),
    }
}

fn vnet_cause(cause: &VnetCause) -> String {
    match cause {
        VnetCause::NoPermission { missing } => match missing.as_slice() {
            [only] if only == "Administrator" => "需要以管理员权限运行".to_owned(),
            [only] if only == "root" => "需要 root 权限".to_owned(),
            missing => format!("缺少 {}", missing.join("、")),
        },
        VnetCause::NoDevice { detail } => format!("无法打开虚拟网卡设备：{detail}"),
        VnetCause::DriverMissing { path } => format!("程序目录中缺少 wintun.dll（{path}）"),
        VnetCause::DeviceFailed { detail } => format!("虚拟网卡故障：{detail}"),
        VnetCause::ProgramMissing { program } => match program.as_str() {
            "nft" => "未找到 nft（请安装 nftables）".to_owned(),
            "ip" => "未找到 ip（请安装 iproute2）".to_owned(),
            "iptables" => "未找到 iptables".to_owned(),
            other => format!("未找到 {other}"),
        },
        VnetCause::CommandFailed { program, detail } => format!("{program} 执行失败：{detail}"),
        VnetCause::PortInUse { address } => format!("{address} 已被占用"),
        VnetCause::BindFailed { address, detail } => format!("无法绑定 {address}：{detail}"),
        VnetCause::RangeInUse { with } => format!("网络的地址段和本机的 {with} 重叠"),
        VnetCause::Unknown => "未知原因".to_owned(),
    }
}

fn rule_state(state: &RuleState) -> String {
    match state {
        RuleState::On => "已启用".to_owned(),
        RuleState::Off => "未添加".to_owned(),
        RuleState::Failed { cause } => format!("添加失败（{}）", vnet_cause(cause)),
        RuleState::Unsupported => "当前平台不添加".to_owned(),
        RuleState::NotNeeded => "不需要".to_owned(),
        RuleState::Unknown => "未知".to_owned(),
    }
}

fn firewall(firewall: &Firewall) -> String {
    match (&firewall.accept, &firewall.guard) {
        (RuleState::Off, RuleState::Off) => "未添加规则".to_owned(),
        (RuleState::Unsupported, RuleState::Unsupported) => "当前平台不添加规则".to_owned(),
        (accept, guard) => format!("放行{}，防冒充{}", rule_state(accept), rule_state(guard)),
    }
}

fn name_service(names: &NameService) -> String {
    match names {
        NameService::Resolved => "名称解析经 systemd-resolved".to_owned(),
        NameService::NoResolver => "名称解析使用 i3t hosts".to_owned(),
        NameService::Failed { cause } => format!("名称解析服务不可用（{}）", vnet_cause(cause)),
        NameService::Unknown => "名称解析：未知".to_owned(),
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
        DirectCause::NoCandidates => "无对端地址",
        DirectCause::Timeouts => "探测超时",
        DirectCause::Loss => "丢包率过高",
        DirectCause::Stale => "闲置超时已释放",
        DirectCause::Unknown => "未知原因",
    }
}
