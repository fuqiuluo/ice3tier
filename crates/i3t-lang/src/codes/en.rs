//! 控制面的代码的英文写法。

use i3t_model::admin::diag::{CellState, ItemState, MatrixState, TestState};
use i3t_model::admin::{
    AddressSource, ApiError, ErrorCode, ExitHealth, ForwardStatus, LaneBlock, NodeWarning, PackageState, PathSource, ProxyStatus,
    ReachCause, ReleaseCause, SkipCause, TokenState, UpdateWait,
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
        Route::None => "unreachable".to_owned(),
        Route::Direct { addr } => format!("direct {addr}"),
        Route::Relay { relays: path } => format!("via {}", relays(path, names)),
    }
}

fn route_cause(cause: &RouteCause, names: Names<'_>) -> String {
    let cost = |cost_us: Option<u64>| cost_us.map(|cost| format!(", cost {} ms", cost_ms(cost))).unwrap_or_default();
    match cause {
        RouteCause::NoRouteYet => "No route yet".to_owned(),
        RouteCause::TestPinned => "Pinned by an active test".to_owned(),
        RouteCause::TestEnded => "Active test ended, back to the chosen route".to_owned(),
        RouteCause::DirectVerified => "Direct path verified".to_owned(),
        RouteCause::DirectLost { hint } => format!("{}, back to relay", route_hint(*hint)),
        RouteCause::RelayReady => "Relay session ready".to_owned(),
        RouteCause::LegChanged { transport: Some(transport) } => format!("Relay session moved to {}", leg(*transport)),
        RouteCause::LegChanged { transport: None } => "Moved to this node's own relay".to_owned(),
        RouteCause::RelayChanged { hint, previous } => format!("{}, was via {}", route_hint(*hint), relays(previous, names)),
        RouteCause::NoSharedRelay { hint: None } => "No relay serves both ends, via a chain of relays".to_owned(),
        RouteCause::NoSharedRelay { hint: Some(hint) } => {
            format!("{}; no relay serves both ends, via a chain of relays", route_hint(*hint))
        }
        RouteCause::Unreachable { hint } => route_hint(*hint).to_owned(),
        RouteCause::PeerRemoved => "Peer no longer in this node's configuration".to_owned(),
        RouteCause::Lan => "Same LAN, direct first".to_owned(),
        RouteCause::LowestCost { candidates, cost_us } => format!("Lowest cost (candidates {candidates}){}", cost(*cost_us)),
        RouteCause::Failover { hint, candidates, cost_us } => {
            format!("{}, switched at once to the lowest cost (candidates {candidates}){}", route_hint(*hint), cost(*cost_us))
        }
        RouteCause::Cheaper { previous, previous_cost_us, cost_us, windows } => format!(
            "Cheaper than {} (windows in a row: {windows}): {} ms, was {} ms",
            route(previous, names),
            cost_ms(*cost_us),
            cost_ms(*previous_cost_us)
        ),
        RouteCause::Unknown => "Unknown reason".to_owned(),
    }
}

const fn route_hint(hint: RouteHint) -> &'static str {
    match hint {
        RouteHint::DirectTimeouts => "Direct probes timed out",
        RouteHint::DirectLoss => "Direct path loss above 20%",
        RouteHint::DirectStale => "Direct address expired",
        RouteHint::DirectUnavailable => "Direct path unavailable",
        RouteHint::RelayDraining => "Relay going offline",
        RouteHint::RelayOverloaded => "Relay overloaded",
        RouteHint::RelayPathBroken => "Multi-relay path broken",
        RouteHint::PeerNotAttached => "Peer not attached to that relay",
        RouteHint::PathProbeSilent => "Multi-relay path probes unanswered",
        RouteHint::PreferredRelayReady => "Peer's preferred relay ready",
        RouteHint::Shortcut => "Shorter relay session available",
        RouteHint::RelayUnavailable => "Previous relay unavailable",
        RouteHint::RelayLost => "Relay session lost",
        RouteHint::RouteFailed => "Previous route failed",
        RouteHint::NoPath => "No usable route",
        RouteHint::Unknown => "Unknown reason",
    }
}

const fn direct_kind(kind: DirectKind) -> &'static str {
    match kind {
        DirectKind::Lan => "LAN",
        DirectKind::Ipv6 => "IPv6",
        DirectKind::Reachable => "reachable",
        DirectKind::Punched => "hole punched",
        DirectKind::Unknown => "unknown",
    }
}

const fn leg(transport: LegTransport) -> &'static str {
    match transport {
        LegTransport::Udp => "UDP",
        LegTransport::Tcp => "TCP",
        LegTransport::Unknown => "unknown",
    }
}

const fn relay_state(state: RelayState) -> &'static str {
    match state {
        RelayState::Serving => "serving",
        RelayState::Overloaded => "overloaded",
        RelayState::Draining => "going offline",
        RelayState::Unknown => "unknown",
    }
}

fn listen_state(state: &ListenState) -> String {
    let failed = |detail: &str, cause: Option<BindCause>| match cause {
        Some(cause) => bind_cause(cause).to_owned(),
        None => format!("Not bound: {detail}"),
    };
    match state {
        ListenState::Listening { local } => format!("Listening on {local}"),
        ListenState::PortInUse { .. } => bind_cause(BindCause::AddressInUse).to_owned(),
        ListenState::Failed { detail, cause } | ListenState::Unsupported { detail, cause } => failed(detail, *cause),
        ListenState::Virtual => "On the virtual IP".to_owned(),
        ListenState::Unknown => "Unknown".to_owned(),
    }
}

const fn bind_cause(cause: BindCause) -> &'static str {
    match cause {
        BindCause::AddressInUse => "Port in use",
        BindCause::PermissionDenied => "Permission denied",
        BindCause::AddressNotAvailable => "Address not on this machine",
        BindCause::VirtualPortZero => "Port required on the virtual IP",
        BindCause::Other => "Not bound",
        BindCause::Unknown => "Unknown reason",
    }
}

fn update_status(status: &UpdateStatus) -> String {
    match status {
        UpdateStatus::Idle => "Not updating".to_owned(),
        UpdateStatus::Downloading { version, received, total } => format!("Downloading {version} ({received}/{total} B)"),
        UpdateStatus::Verifying { version } => format!("Verifying {version}"),
        UpdateStatus::SelfCheck { version } => format!("Self-checking {version}"),
        UpdateStatus::WaitingForIdle { version } => format!("{version} ready, waiting for idle"),
        UpdateStatus::Draining { version } => format!("{version} ready, draining"),
        UpdateStatus::Installing { version } => format!("Installing {version}"),
        UpdateStatus::Restarting { version } => format!("Restarting into {version}"),
        UpdateStatus::Confirmed { version } => format!("Updated to {version}"),
        UpdateStatus::Failed { version, kind, cause, .. } => {
            let version = version.as_ref().map_or_else(|| "the new version".to_owned(), ToString::to_string);
            let why = cause.as_ref().map_or_else(|| "reason not reported".to_owned(), update_cause);
            let kind = match kind {
                FailureKind::VersionRejected => "won't retry this version",
                FailureKind::NotInstalled => "will retry",
            };
            format!("Update to {version} failed: {why} ({kind})")
        }
        UpdateStatus::Unknown => "Unknown".to_owned(),
    }
}

fn update_cause(cause: &UpdateCause) -> String {
    match cause {
        UpdateCause::BadSignature => "Manifest signature invalid".to_owned(),
        UpdateCause::BadManifest => "Manifest unreadable".to_owned(),
        UpdateCause::CannotSelfUpdate { blocker: why } => blocker(*why).to_owned(),
        UpdateCause::NotNewer { offered, running } => format!("{offered} isn't newer than {running}"),
        UpdateCause::Prerelease { offered, .. } => format!("{offered} is a pre-release"),
        UpdateCause::FailedBefore { version } => format!("{version} failed here before"),
        UpdateCause::NoPackage { version, platform } => format!("{version} has no {platform} package"),
        UpdateCause::RestartPending { installed } => format!("{installed} installed, restart pending"),
        UpdateCause::Unavailable { detail } => format!("Package unavailable: {detail}"),
        UpdateCause::Corrupt { expected_size, actual_size } => {
            format!("Package doesn't match the manifest ({actual_size} B, expected {expected_size} B)")
        }
        UpdateCause::SelfCheck { exit_code: Some(code), output } => format!("Self-check failed (exit code {code}): {output}"),
        UpdateCause::SelfCheck { exit_code: None, output } => format!("Self-check failed: {output}"),
        UpdateCause::Cancelled => "No moment to switch programs".to_owned(),
        UpdateCause::Io { path, error } => format!("Couldn't read or write {path}: {error}"),
        UpdateCause::StateUnreadable { path } => format!("Update state file {path} unreadable"),
        UpdateCause::NotConfirmed { minutes } => format!("New program didn't reach the controller in {minutes} min, rolled back"),
        UpdateCause::StartsUnconfirmed { starts } => format!("New program didn't reach the controller (starts: {starts}), rolled back"),
        UpdateCause::Unknown => "Unknown reason".to_owned(),
    }
}

const fn blocker(blocker: SelfUpdateBlocker) -> &'static str {
    match blocker {
        SelfUpdateBlocker::Container => "Runs in a container; update the image",
        SelfUpdateBlocker::PackageManager => "Installed by a package manager; update with it",
        SelfUpdateBlocker::ReadOnlyDir => "Program directory is read-only",
    }
}

const fn update_wait(wait: UpdateWait) -> &'static str {
    match wait {
        UpdateWait::Package => "Waiting for the package",
        UpdateWait::RelayTurn => "Waiting for the previous relay",
        UpdateWait::Unknown => "Waiting",
    }
}

fn release_cause(cause: &ReleaseCause) -> String {
    match cause {
        ReleaseCause::InvalidSource => "Release source malformed".to_owned(),
        ReleaseCause::FetchFailed { url, error } => format!("Couldn't fetch {url}: {error}"),
        ReleaseCause::Io { path, error } => format!("Couldn't read or write {path}: {error}"),
        ReleaseCause::BadSignatureFile => "Signature file isn't a signature".to_owned(),
        ReleaseCause::BadSignature => "Manifest signature invalid".to_owned(),
        ReleaseCause::BadManifest => "Manifest unreadable".to_owned(),
        ReleaseCause::Prerelease { version } => format!("Latest {version} is a pre-release; skipped"),
        ReleaseCause::BadFileName { file } => format!("Bad file name: {file}"),
        ReleaseCause::Mismatch { file, expected_size, actual_size } => {
            format!("{file} doesn't match the manifest ({actual_size} B, expected {expected_size} B)")
        }
        ReleaseCause::Internal => "Controller internal error".to_owned(),
        ReleaseCause::Unknown => "Unknown reason".to_owned(),
    }
}

const fn package_state(state: PackageState) -> &'static str {
    match state {
        PackageState::NotNeeded => "not needed",
        PackageState::Fetching => "downloading",
        PackageState::Cached => "downloaded",
        PackageState::Failed => "failed",
        PackageState::Unknown => "unknown",
    }
}

fn skip_cause(cause: &SkipCause) -> String {
    match cause {
        SkipCause::Offline => "Offline".to_owned(),
        SkipCause::TooOld => "Too old to update itself".to_owned(),
        SkipCause::CannotSelfUpdate { blocker: Some(why) } => blocker(*why).to_owned(),
        SkipCause::CannotSelfUpdate { blocker: None } => "Can't update itself".to_owned(),
        SkipCause::NoRelease => "No release found yet".to_owned(),
        SkipCause::ControllerTooOld { min_controller, .. } => format!("Update the controller to {min_controller} first"),
        SkipCause::UnreadableVersion { version } => format!("Unreadable version: {version}"),
        SkipCause::UpToDate { running, .. } => format!("Up to date ({running})"),
        SkipCause::NoPackage { platform, .. } => format!("No {platform} package"),
        SkipCause::Unknown => "Unknown reason".to_owned(),
    }
}

const fn reach_cause(cause: ReachCause) -> &'static str {
    match cause {
        ReachCause::Refused => "Connection refused",
        ReachCause::Timeout => "Timed out",
        ReachCause::Unreachable => "Network unreachable",
        ReachCause::Local => "Controller-side error",
        ReachCause::Other => "Couldn't connect",
        ReachCause::Unknown => "Unknown reason",
    }
}

const fn try_outcome(outcome: TryOutcome) -> &'static str {
    match outcome {
        TryOutcome::Udp => "UDP",
        TryOutcome::Tcp => "TCP only",
        TryOutcome::Unreached => "unreached",
        TryOutcome::Unknown => "unknown",
    }
}

const fn address_source(source: AddressSource) -> &'static str {
    match source {
        AddressSource::Declared => "declared on the node",
        AddressSource::Observed => "seen by the controller",
        AddressSource::Local => "interface",
        AddressSource::Unknown => "unknown source",
    }
}

fn node_warning(warning: &NodeWarning) -> String {
    match warning {
        NodeWarning::RangeOverlap { address } => format!("interface address {address} is inside the network's range"),
        NodeWarning::RelayUnreached { tried } => format!("{tried} online nodes tried this relay; none reached it"),
        NodeWarning::Unknown => "unknown warning".to_owned(),
    }
}

const fn reject_cause(cause: RejectCause) -> &'static str {
    match cause {
        RejectCause::BadToken => "Invalid enrollment token: unknown, used or expired",
        RejectCause::UnknownKey => "This key isn't registered; the node may have been deleted. Join again",
        RejectCause::KeyAlreadyEnrolled => "This key is already registered",
        RejectCause::PredecessorOnline => "The node to replace is still online",
        RejectCause::AddressUnavailable => "The token's preset virtual IP isn't available",
        RejectCause::RangeExhausted => "The address range is full",
        RejectCause::UnexpectedFirstMessage => "Unexpected first message",
        RejectCause::Unknown => "Unknown reason",
    }
}

/// 按错误码写，`what` 和 `field` 补上细节；controller 的原话是中文的，不用。
fn api_error(error: &ApiError) -> String {
    let what = error.what.as_deref();
    let field = error.field.as_deref().map(|field| format!(" ({field})")).unwrap_or_default();
    let thing = |what: Option<&str>| match what {
        Some("network") => "network",
        Some("node") => "node",
        Some("group") => "group",
        Some("token") => "enrollment token",
        Some("rule") => "rule",
        Some("proxy") => "proxy",
        Some("forward") => "port forward",
        Some("pair") => "node pair setting",
        Some("paused_version") => "paused version",
        Some("exit") => "exit",
        Some("test") => "test",
        Some("matrix") => "test matrix",
        Some("endpoint") => "API endpoint",
        _ => "item",
    };
    match error.code {
        ErrorCode::Unauthorized => "Admin token missing or wrong".to_owned(),
        ErrorCode::NotFound => format!("No such {}{field}", thing(what)),
        ErrorCode::InvalidRequest => {
            let problem = match what {
                Some("too_small") => "too small",
                Some("zero" | "zero_port") => "can't be 0",
                Some("too_many") => "too many",
                Some("too_long") => "too long",
                Some("out_of_range") => "out of range",
                Some("empty") => "empty",
                Some("malformed") => "malformed",
                Some("all_digits") => "can't be all digits",
                Some("same_node") => "must differ",
                Some("builtin") => "the built-in group All can't change",
                Some("required") => "required here",
                Some("missing") => "missing",
                Some("not_relay") => "not an enabled relay",
                Some("not_connectable") => "not a connectable address",
                Some("cloud_metadata") => "a cloud metadata address can't be a target",
                Some("overlay_address") => "an address inside the network's own range can't be a target",
                Some("not_allowed") => "not allowed",
                Some("duplicate") => "repeated",
                Some("with_successor") => "can't be set together with a successor",
                Some("no_default") => "no free default range",
                Some("needs_quality") => "needs a quality test",
                Some("method") => "method not allowed",
                Some(_) | None => "invalid",
            };
            format!("Invalid request{field}: {problem}")
        }
        ErrorCode::AddressOutOfRange => format!("Virtual IP outside the address range{field}"),
        ErrorCode::NameTaken if what == Some("group") => format!("Group name already taken{field}"),
        ErrorCode::NameTaken => format!("Name already taken{field}"),
        ErrorCode::NameCoolingDown => format!("Name belongs to a recently deleted node{field}"),
        ErrorCode::AddressTaken => format!("Virtual IP already taken{field}"),
        ErrorCode::AddressCoolingDown => format!("Virtual IP belongs to a recently deleted node{field}"),
        ErrorCode::RangeOverlaps => "Address range overlaps another network".to_owned(),
        ErrorCode::RangeExhausted => "Address range full".to_owned(),
        ErrorCode::RangeNotSuperset => "New address range must contain the old one".to_owned(),
        ErrorCode::NetworkNotEmpty => "Network still has nodes".to_owned(),
        ErrorCode::NotDeclared => {
            let command = match what {
                Some("relay") => "i3t set can-relay on",
                Some("exit") => "i3t set can-exit on",
                _ => "i3t set can-… on",
            };
            format!("Node hasn't declared it. Run '{command}' on the node first.")
        }
        ErrorCode::ForwardTargetOff => {
            "Target node isn't switched on as a forward target (i3tctl node set <node> --forward-target on)".to_owned()
        }
        ErrorCode::PredecessorOnline => "Node to replace is still online".to_owned(),
        ErrorCode::Conflict => format!("Conflicts with an existing {}{field}", thing(what)),
        ErrorCode::NodeOffline => "Node offline".to_owned(),
        ErrorCode::CannotSelfUpdate => {
            let why = match what {
                Some("container") => blocker(SelfUpdateBlocker::Container),
                Some("package_manager") => blocker(SelfUpdateBlocker::PackageManager),
                Some("read_only_dir") => blocker(SelfUpdateBlocker::ReadOnlyDir),
                Some("too_old") => "Too old to update itself",
                Some(_) | None => "Can't update itself",
            };
            format!("Node can't update itself: {why}")
        }
        ErrorCode::NoUpdate => {
            let why = match what {
                Some("no_release") => "no release found yet",
                Some("controller_too_old") => "update the controller first",
                Some("unreadable_version") => "its version is unreadable",
                Some("up_to_date") => "already up to date",
                Some("no_package") => "no package for its platform",
                Some(_) | None => "nothing to update to",
            };
            format!("No update: {why}")
        }
        ErrorCode::TooSoon => "Too soon; try again shortly".to_owned(),
        ErrorCode::Busy => "Busy or already finished".to_owned(),
        ErrorCode::ExitNotEnabled => format!("The exit node isn't enabled as an exit{field}"),
        ErrorCode::ExitIsNode => format!("The exit must be another node, not the one listening{field}"),
        ErrorCode::AccessDenied => format!("The access rules don't let the node reach the exit{field}"),
        ErrorCode::CredentialsIncomplete => format!("Give both user name and password, or neither{field}"),
        ErrorCode::Internal => "Controller internal error; see its log".to_owned(),
        // 比这个程序新的 controller 才有的错误码：只能说出错了，原话是中文的。
        _ => "Request failed".to_owned(),
    }
}

fn lane_block(block: &LaneBlock, names: Names<'_>) -> String {
    match block {
        LaneBlock::NoRelay => "Neither node is a relay".to_owned(),
        LaneBlock::NoTcpAddress { node } => format!("{} has no known address yet", names(*node)),
        LaneBlock::NodeTooOld { node } => format!("{} is too old", names(*node)),
        LaneBlock::NotConnected => "No rule lets the listening node reach the exit".to_owned(),
    }
}

const fn forward_status(status: ForwardStatus) -> &'static str {
    match status {
        ForwardStatus::Disabled => "disabled",
        ForwardStatus::ForwardTargetOff => "target switched off",
        ForwardStatus::AccessDenied => "no access",
        ForwardStatus::TargetNotAllowed => "target address not allowed",
        ForwardStatus::ListenerOffline => "listener offline",
        ForwardStatus::TargetOffline => "target offline",
        ForwardStatus::Active => "in effect",
        ForwardStatus::Unknown => "unknown",
    }
}

const fn target_cause(cause: TargetCause) -> &'static str {
    match cause {
        TargetCause::Refused => "target refused",
        TargetCause::Timeout => "target timed out",
        TargetCause::Unreachable => "target unreachable",
        TargetCause::NotDeclared => "target node lacks this forward",
        TargetCause::AccessDenied => "target node denies access",
        TargetCause::NodeUnreachable => "target node unreachable",
        TargetCause::Other => "target failed",
        TargetCause::Unknown => "target failed",
    }
}

fn exit_test_cause(cause: &ExitTestCause) -> String {
    let family = |family: IpFamily| match family {
        IpFamily::Ipv4 => "IPv4",
        IpFamily::Ipv6 => "IPv6",
        IpFamily::Any => "any",
    };
    match cause {
        ExitTestCause::Busy => "Another test is running or just ran on the exit; try again shortly".to_owned(),
        ExitTestCause::BadTarget => "The exit can't read this target".to_owned(),
        ExitTestCause::NotEnabled => "Not an exit".to_owned(),
        ExitTestCause::LanNotEnabled => "LAN address: the exit doesn't allow LAN access".to_owned(),
        ExitTestCause::PortNotAllowed { port } => format!("Port {port} isn't allowed on this exit"),
        ExitTestCause::FamilyUnavailable { family: wanted } => format!("The exit only uses {} and the target has none", family(*wanted)),
        ExitTestCause::AddressNotAllowed { address } => format!("The exit doesn't connect others to {address}"),
        ExitTestCause::NotOnLan { address } => format!("{address} isn't on a network the exit is attached to"),
        ExitTestCause::NameNotFound => "No such name".to_owned(),
        ExitTestCause::ResolverFailed => "Resolver error".to_owned(),
        ExitTestCause::Timeout => "Timed out".to_owned(),
        ExitTestCause::Refused => "Connection refused".to_owned(),
        ExitTestCause::Unreachable => "Unreachable".to_owned(),
        ExitTestCause::UpstreamFailed => "Can't reach the exit's upstream proxy".to_owned(),
        ExitTestCause::Closed => "Closed before the handshake finished".to_owned(),
        ExitTestCause::Alert => "TLS alert from the server".to_owned(),
        ExitTestCause::Other | ExitTestCause::Unknown => "Other reason, see the exit's log".to_owned(),
    }
}

const fn exit_via(via: ExitVia) -> &'static str {
    match via {
        ExitVia::Direct => "direct",
        ExitVia::Upstream => "via upstream proxy",
        ExitVia::Unknown => "unknown route out",
    }
}

const fn token_state(state: TokenState) -> &'static str {
    match state {
        TokenState::Pending => "unused",
        TokenState::Used => "used",
        TokenState::Expired => "expired",
        TokenState::Unknown => "unknown",
    }
}

fn proxy_status(status: &ProxyStatus) -> String {
    match status {
        ProxyStatus::Listening { local } => format!("listening on {local}"),
        ProxyStatus::Disabled => "disabled".to_owned(),
        ProxyStatus::Pending => "waiting for the node".to_owned(),
        ProxyStatus::NodeOffline => "node offline".to_owned(),
        ProxyStatus::PortInUse { .. } => "port in use".to_owned(),
        ProxyStatus::BindFailed { cause, detail } => match cause {
            Some(cause) => format!("bind failed: {}", bind_cause(*cause)),
            None => format!("bind failed: {detail}"),
        },
        ProxyStatus::ExitDisabled { .. } => "exit node isn't an exit".to_owned(),
        ProxyStatus::AccessDenied { .. } => "rules don't allow reaching the exit".to_owned(),
        ProxyStatus::ExitOffline { .. } => "exit offline".to_owned(),
        ProxyStatus::ExitMissing => "no exit; choose one to enable it".to_owned(),
        ProxyStatus::Unknown => "unknown".to_owned(),
    }
}

const fn exit_health(health: ExitHealth) -> &'static str {
    match health {
        ExitHealth::Ok => "ok",
        ExitHealth::Degraded => "degraded",
        ExitHealth::Unknown => "unknown",
    }
}

const fn path_source(source: PathSource) -> &'static str {
    match source {
        PathSource::Query => "asked",
        PathSource::Report => "reported",
        PathSource::None => "no data",
        PathSource::NotPeers => "not connected",
        PathSource::Unknown => "unknown",
    }
}

const fn test_code(code: TestCode) -> &'static str {
    match code {
        TestCode::NotSupported => "Too old for active tests",
        TestCode::NodeOffline => "Offline",
        TestCode::NotConnected => "No rule connects them",
        TestCode::RelayOnly => "Relay only; no direct tests",
        TestCode::DirectOnly => "Direct only; no relay tests",
        TestCode::ThroughputOff => "Throughput tests off",
        TestCode::NoRelay => "No relay path",
        TestCode::NoDirect => "No direct path",
        TestCode::NoCandidates => "No peer addresses",
        TestCode::UdpBlocked => "UDP blocked",
        TestCode::MappingVaries => "Port mapping varies by peer; no hole punching",
        TestCode::DialOutOnly => "Both nodes dial out only",
        TestCode::Timeout => "Timed out",
        TestCode::Unreachable => "Path unreachable",
        TestCode::Refused => "Peer refused the test",
        TestCode::Busy => "Node busy",
        TestCode::TooSoon => "Tested moments ago",
        TestCode::Cancelled => "Cancelled",
        TestCode::NoReport => "No report in time",
        TestCode::StreamFailed => "Test stream broke",
        TestCode::InvalidPath => "Path not usable",
        TestCode::Internal => "Internal error",
        TestCode::Unknown => "Unknown reason",
    }
}

const fn test_state(state: TestState) -> &'static str {
    match state {
        TestState::Running => "running",
        TestState::Done => "done",
        TestState::Failed => "failed",
        TestState::Cancelled => "cancelled",
        TestState::Unknown => "unknown",
    }
}

const fn item_state(state: ItemState) -> &'static str {
    match state {
        ItemState::Pending => "pending",
        ItemState::Done => "done",
        ItemState::Skipped => "skipped",
        ItemState::Failed => "failed",
        ItemState::Unknown => "unknown",
    }
}

const fn matrix_state(state: MatrixState) -> &'static str {
    match state {
        MatrixState::Running => "running",
        MatrixState::Done => "done",
        MatrixState::Cancelled => "cancelled",
        MatrixState::Unknown => "unknown",
    }
}

const fn cell_state(state: CellState) -> &'static str {
    match state {
        CellState::Pending => "pending",
        CellState::Running => "running",
        CellState::Done => "done",
        CellState::Skipped => "skipped",
        CellState::Failed => "failed",
        CellState::Cancelled => "cancelled",
        CellState::Unknown => "unknown",
    }
}

const fn choice(code: ChoiceCode) -> &'static str {
    match code {
        ChoiceCode::Lan => "LAN direct first",
        ChoiceCode::Direct => "direct available",
        ChoiceCode::PeerIsRelay => "peer is a relay",
        ChoiceCode::OwnRelay => "peer attached here",
        ChoiceCode::PeerRelay => "peer's relay",
        ChoiceCode::NoSharedRelay => "no relay serves both ends, a chain of relays",
        ChoiceCode::LowestCost => "lowest cost",
        ChoiceCode::WithinMargin => "stays: not cheaper by the switch margin",
        ChoiceCode::NoPath => "no route",
        ChoiceCode::Unknown => "unknown",
    }
}

const fn hop_source(source: HopSource) -> &'static str {
    match source {
        HopSource::Measured => "measured",
        HopSource::Backbone => "backbone",
        HopSource::Reported => "reported",
        HopSource::Unknown => "unknown",
    }
}

const fn path_pick(pick: PathPick) -> &'static str {
    match pick {
        PathPick::Direct => "direct",
        PathPick::DirectFirst => "default",
        PathPick::LowestCost => "lowest latency",
        PathPick::Admin => "given",
        PathPick::Unknown => "unknown",
    }
}

const fn transfer_end(end: TransferEnd) -> &'static str {
    match end {
        TransferEnd::Finished => "finished",
        TransferEnd::Bytes => "byte limit",
        TransferEnd::Time => "time limit",
        TransferEnd::Unknown => "unknown",
    }
}

fn vnet_state(state: &VnetState) -> String {
    match state {
        VnetState::Installed { device, mtu, names } => format!("installed ({device}, MTU {mtu}; {})", name_service(names)),
        VnetState::Off => "off".to_owned(),
        VnetState::Failed { cause } => format!("not installed: {}", vnet_cause(cause)),
        VnetState::Unsupported => "not available on this platform".to_owned(),
        VnetState::Unknown => "unknown".to_owned(),
    }
}

fn vnet_cause(cause: &VnetCause) -> String {
    match cause {
        VnetCause::NoPermission { missing } => match missing.as_slice() {
            [only] if only == "Administrator" => "run as administrator".to_owned(),
            [only] if only == "root" => "needs root".to_owned(),
            missing => format!("missing {}", missing.join(", ")),
        },
        VnetCause::NoDevice { detail } => format!("can't open the device for virtual adapters: {detail}"),
        VnetCause::DriverMissing { path } => format!("wintun.dll not next to the program ({path})"),
        VnetCause::DeviceFailed { detail } => format!("can't create the adapter: {detail}"),
        VnetCause::ProgramMissing { program } => match program.as_str() {
            "nft" => "nft not found (install nftables)".to_owned(),
            "ip" => "ip not found (install iproute2)".to_owned(),
            "iptables" => "iptables not found".to_owned(),
            other => format!("{other} not found"),
        },
        VnetCause::CommandFailed { program, detail } => format!("{program} failed: {detail}"),
        VnetCause::PortInUse { address } => format!("{address} in use"),
        VnetCause::BindFailed { address, detail } => format!("can't bind {address}: {detail}"),
        VnetCause::RangeInUse { with } => format!("the network's range overlaps {with} on this machine"),
        VnetCause::Unknown => "unknown cause".to_owned(),
    }
}

fn rule_state(state: &RuleState) -> String {
    match state {
        RuleState::On => "on".to_owned(),
        RuleState::Off => "off".to_owned(),
        RuleState::Failed { cause } => format!("failed ({})", vnet_cause(cause)),
        RuleState::Unsupported => "not added on this platform".to_owned(),
        RuleState::NotNeeded => "not needed".to_owned(),
        RuleState::Unknown => "unknown".to_owned(),
    }
}

fn firewall(firewall: &Firewall) -> String {
    match (&firewall.accept, &firewall.guard) {
        (RuleState::Off, RuleState::Off) => "no rules".to_owned(),
        (RuleState::Unsupported, RuleState::Unsupported) => "no rules on this platform".to_owned(),
        (accept, guard) => format!("accept {}, anti-spoofing {}", rule_state(accept), rule_state(guard)),
    }
}

fn name_service(names: &NameService) -> String {
    match names {
        NameService::Resolved => "names via systemd-resolved".to_owned(),
        NameService::NoResolver => "names via i3t hosts".to_owned(),
        NameService::Failed { cause } => format!("names unavailable: {}", vnet_cause(cause)),
        NameService::Unknown => "names: unknown".to_owned(),
    }
}

const fn class(class: Class) -> &'static str {
    match class {
        Class::Auto => "Auto",
        Class::Interactive => "Low latency",
        Class::Reliable => "No loss",
        Class::Bulk => "Background",
    }
}

fn direct_status(status: &DirectStatus) -> String {
    let state = match status.state {
        DirectState::NotTried => "not tried",
        DirectState::Trying => "trying",
        DirectState::Verified => "verified",
        DirectState::Failed => "failed",
        DirectState::Unknown => "unknown",
    };
    let aside: Vec<String> = match status.state {
        DirectState::Verified => status.kind.map(|kind| direct_kind(kind).to_owned()).into_iter().collect(),
        DirectState::Failed => {
            let cause = status.cause.map(|cause| direct_cause(cause).to_owned());
            cause.into_iter().chain(status.attempted_secs_ago.map(|ago| Lang::English.ago(ago))).collect()
        }
        DirectState::NotTried | DirectState::Trying | DirectState::Unknown => Vec::new(),
    };
    if aside.is_empty() { state.to_owned() } else { format!("{state} ({})", aside.join(", ")) }
}

const fn direct_cause(cause: DirectCause) -> &'static str {
    match cause {
        DirectCause::NoAnswer => "no answer",
        DirectCause::NoCandidates => "no peer address",
        DirectCause::Timeouts => "probes timed out",
        DirectCause::Loss => "too much loss",
        DirectCause::Stale => "dropped while idle",
        DirectCause::Unknown => "unknown cause",
    }
}
