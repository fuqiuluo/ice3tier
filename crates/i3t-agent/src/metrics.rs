//! 节点的指标，Prometheus 的文本格式。
//!
//! 各层的计数都是它们自己的原子变量，这里只在被抓的时候读一遍、排成文本，没有后台任务。
//!
//! 现在有的：流（入口、出口各有多少在进行，出口一共收到过多少）、字节数、没建成的请求按归因分类、
//! 出口的配额，按凭据的用量，经各个出口出去的流（发起这一侧看到的），relay 的转发和丢弃、
//! 到每个对端走的是哪一种路和延迟、ice3proxy（lane）的水位和计数、虚拟网卡的收发和丢包、和 controller 的连接、更新的状态。
//! 不做交叉组合：按凭据和按出口是两组各自独立的数，没有"某个凭据经某个出口"这样的组合。

use i3t_conn::DropReason;
use i3t_lane::LaneStatus;
use i3t_metrics::Exposition;
use i3t_model::control::{Route, VnetReport, VnetState};
use i3t_model::update::UpdateStatus;
use i3t_proto::NodeId;

use crate::control::LinkState;
use crate::runtime::Runtime;

/// 当前的指标，可以直接作为 `/metrics` 的应答。
pub(crate) fn render(runtime: &Runtime) -> String {
    let mut out = Exposition::new();
    let netmap = runtime.netmap.borrow().clone();
    out.gauge("i3t_info", "节点程序版本", &[("version", &runtime.program.version.to_string())], 1.0);
    out.gauge("i3t_uptime_seconds", "进程已运行时长（秒）", &[], runtime.started.elapsed().as_secs_f64());
    out.gauge("i3t_netmap_version", "当前生效的 netmap 版本号", &[], as_gauge(netmap.version));

    // 静态模式下没有这条连接，也就没有这个指标。
    if let Some(link) = &runtime.link {
        let online = *link.borrow() == LinkState::Online;
        out.gauge("i3t_controller_link_up", "与 controller 的长连接状态：已连接为 1，未连接为 0", &[], f64::from(u8::from(online)));
    }

    let sample = runtime.sample_flows();
    let help = "活跃流数：ingress 为入口连接，exit 为替对端节点转发目标的流与数据报上下文";
    out.gauge("i3t_flows_active", help, &[("side", "ingress")], as_gauge(sample.ingress));
    out.gauge("i3t_flows_active", help, &[("side", "exit")], as_gauge(sample.exit));
    out.gauge(
        "i3t_flows_blocking_update",
        "阻塞更新重启的活跃计数：活跃流数，若作为唯一 relay 正在转发则加 1",
        &[],
        as_gauge(*runtime.flows.borrow()),
    );

    let stats = runtime.exit.stats();
    out.counter("i3t_exit_flows_total", "出口收到的建流请求总数", &[], stats.total);
    let help = "出口转发的字节数";
    out.counter("i3t_exit_bytes_total", help, &[("direction", "to_target")], stats.bytes_to_target);
    out.counter("i3t_exit_bytes_total", help, &[("direction", "from_target")], stats.bytes_from_target);
    let help = "出口未能建立的请求数，按归因分类：target 为目标问题，refused 为规则或策略拒绝，exit 为出口自身问题";
    out.counter("i3t_exit_failures_total", help, &[("attribution", "target")], stats.failed_by_target);
    out.counter("i3t_exit_failures_total", help, &[("attribution", "refused")], stats.refused);
    out.counter("i3t_exit_failures_total", help, &[("attribution", "exit")], stats.failed_by_exit);
    out.counter("i3t_exit_flows_aborted_total", "建立后异常结束的流数量", &[], stats.aborted);
    out.counter(
        "i3t_drain_refused_total",
        "因节点正在排空而拒绝的请求数（含入口与出口）",
        &[],
        stats.drained.saturating_add(runtime.access.drained()),
    );
    out.gauge("i3t_draining", "节点正在排空时为 1（不再接受新流），否则为 0", &[], f64::from(u8::from(stats.draining)));
    if let Some(quota) = stats.quota {
        out.gauge("i3t_exit_quota_bytes", "出口每个账期的流量配额（字节）", &[], bytes_gauge(quota.limit_bytes));
        out.gauge("i3t_exit_quota_used_bytes", "出口本账期已经用掉的流量（字节）", &[], bytes_gauge(quota.used_bytes));
    }

    for proxy in runtime.access.status().proxies {
        let name = netmap
            .me
            .proxies
            .iter()
            .find(|config| config.id == proxy.id)
            .map_or_else(|| format!("#{}", proxy.id), |config| config.name.clone());
        let labels = |direction| [("proxy", name.as_str()), ("direction", direction)];
        let help = "经每个代理搬运的字节数，up 是客户端发出的，down 是发回给客户端的";
        out.counter("i3t_proxy_bytes_total", help, &labels("up"), proxy.traffic.up());
        out.counter("i3t_proxy_bytes_total", help, &labels("down"), proxy.traffic.down());
        out.gauge("i3t_proxy_connections", "每个代理现在的连接数", &[("proxy", name.as_str())], as_gauge(proxy.active.get()));
    }

    let name_of = |peer| netmap.peer(peer).map_or_else(|| format!("#{peer}"), |peer| peer.name.clone());
    for seen in runtime.access.exit_usage() {
        let exit = name_of(seen.exit);
        out.counter("i3t_exit_observed_flows_total", "本节点经每个出口发起的流", &[("exit", &exit)], seen.flows);
        let help = "本节点经每个出口搬运的字节数（发起这一侧看到的），up 是发往出口的";
        out.counter("i3t_exit_observed_bytes_total", help, &[("exit", &exit), ("direction", "up")], seen.bytes_up);
        out.counter("i3t_exit_observed_bytes_total", help, &[("exit", &exit), ("direction", "down")], seen.bytes_down);
        let help = "本节点经每个出口发起、没有建成的流，按归因分：unreachable 是到出口开流就失败了";
        for (attribution, value) in
            [("target", seen.failed_by_target), ("refused", seen.refused), ("exit", seen.failed_by_exit), ("unreachable", seen.unreachable)]
        {
            out.counter("i3t_exit_observed_failures_total", help, &[("exit", &exit), ("attribution", attribution)], value);
        }
    }

    let relay = runtime.endpoint.relay_counters();
    out.gauge("i3t_relay_enabled", "本节点是否启用为 relay（启用为 1，未启用为 0）", &[], f64::from(u8::from(netmap.me.relay.is_some())));
    out.gauge("i3t_relay_sessions", "relay 当前的中转会话数", &[], as_gauge(relay.sessions));
    out.counter("i3t_relay_sessions_opened_total", "relay 握手成功总次数", &[], relay.sessions_opened);
    out.counter("i3t_relay_forwarded_packets_total", "relay 转发的数据包总数", &[], relay.forwarded_packets);
    out.counter("i3t_relay_forwarded_bytes_total", "relay 转发的字节总数（含中转头）", &[], relay.forwarded_bytes);
    for reason in DropReason::ALL {
        let label = snake_case(&format!("{reason:?}"));
        out.counter(
            "i3t_relay_dropped_total",
            "relay 丢弃或拒绝的数据包与握手次数，按原因分类",
            &[("reason", &label)],
            relay.dropped(reason),
        );
    }

    let routes = runtime.endpoint.routes();
    for entry in &routes {
        let via = match entry.route {
            Route::None => "none",
            Route::Direct { .. } => "direct",
            Route::Relay { .. } => "relay",
        };
        out.gauge("i3t_peer_route", "到每个对端现在走的是哪一种路", &[("peer", &name_of(entry.peer)), ("via", via)], 1.0);
    }
    for entry in &routes {
        if let Some(rtt_ms) = entry.rtt_ms {
            out.gauge(
                "i3t_peer_rtt_ms",
                "到每个对端的路上最近测到的往返延迟（毫秒）",
                &[("peer", &name_of(entry.peer))],
                f64::from(rtt_ms),
            );
        }
    }
    // 预测和实际：路由层按各段的探测推算的延迟，和连接自己量的往返时间。只有到对端有连接时才有。
    for entry in &routes {
        let Some(actual) = runtime.endpoint.connection_rtt(entry.peer) else { continue };
        let peer = name_of(entry.peer);
        out.gauge("i3t_peer_connection_rtt_ms", "到各对端连接的实测往返时间（毫秒）", &[("peer", &peer)], millis(actual));
        if let Some(deviation) = rtt_deviation_ms(entry.rtt_ms, actual) {
            let help = "到各对端连接的实测往返时间与路由层推算值之差（毫秒）：偏差过大表示测量失真";
            out.gauge("i3t_peer_rtt_deviation_ms", help, &[("peer", &peer)], deviation);
        }
    }

    lane_metrics(&mut out, &runtime.lanes.listed_status(), &name_of);
    vnet_metrics(&mut out, &runtime.vnet_report());

    let update = update_label(&runtime.update.borrow());
    out.gauge("i3t_update_state", "程序更新当前所处阶段", &[("state", &update)], 1.0);
    out.finish()
}

/// 虚拟网卡指标：安装状态、收发数据包与字节数，以及按原因分类的丢包数。
fn vnet_metrics(out: &mut Exposition, report: &VnetReport) {
    let installed = matches!(report.state, VnetState::Installed { .. });
    out.gauge("i3t_vnet_installed", "虚拟网卡已安装为 1，未安装（已关闭或初始化失败）为 0", &[], f64::from(u8::from(installed)));
    let help = "经虚拟网卡发送至对端（sent）与从对端接收（received）的数据包数";
    out.counter("i3t_vnet_packets_total", help, &[("direction", "sent")], report.sent_packets);
    out.counter("i3t_vnet_packets_total", help, &[("direction", "received")], report.received_packets);
    let help = "经虚拟网卡发送与接收的字节数（按 IP 包长度统计）";
    out.counter("i3t_vnet_bytes_total", help, &[("direction", "sent")], report.sent_bytes);
    out.counter("i3t_vnet_bytes_total", help, &[("direction", "received")], report.received_bytes);
    let dropped = report.dropped;
    let help = "虚拟网卡丢弃的数据包数，按原因分类";
    for (reason, count) in [
        ("bad_source", dropped.bad_source),
        ("bad_destination", dropped.bad_destination),
        ("not_allowed", dropped.not_allowed),
        ("unreachable", dropped.unreachable),
        ("malformed", dropped.malformed),
    ] {
        out.counter("i3t_vnet_dropped_total", help, &[("reason", reason)], count);
    }
}

fn millis(duration: std::time::Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// 连接实测往返时间与路由层推算值之差（毫秒，偏小为负值）。无法推算时返回 `None`。
fn rtt_deviation_ms(predicted_ms: Option<u32>, actual: std::time::Duration) -> Option<f64> {
    predicted_ms.map(|predicted| millis(actual) - f64::from(predicted))
}

/// ice3proxy（lane）指标：为每个展示对端输出一组指标（`always` 与 `udp_fallback` 中需要或正在使用的对端，见 `lanes::listed`），
/// 外加全节点的握手失败计数。
fn lane_metrics(out: &mut Exposition, status: &LaneStatus, name_of: &impl Fn(NodeId) -> String) {
    for peer in &status.peers {
        let name = name_of(peer.peer);
        let label = [("peer", name.as_str())];
        let counts = &peer.counts;
        out.gauge(
            "i3t_lane_control_up",
            "与各对端之间的控制 lane 状态：已建立为 1，未建立时新 TCP 流走共用连接",
            &label,
            f64::from(u8::from(peer.control)),
        );
        let help = "空闲的 lane：parked_here 为对端停靠在本节点的，ready 为本节点拨好预留自用的，parked_at_peer 为本节点停靠在对端的";
        for (pool, value) in [("parked_here", peer.idle), ("ready", peer.ready), ("parked_at_peer", peer.parked_at_peer)] {
            out.gauge("i3t_lane_idle", help, &[("peer", name.as_str()), ("pool", pool)], as_gauge(value));
        }
        out.gauge("i3t_lane_in_use", "正在承载流的 lane 数量", &label, as_gauge(counts.in_use));
        out.gauge("i3t_lane_dialling", "正在拨号（连接或握手）的 lane 数量", &label, as_gauge(counts.dialling));
        out.counter("i3t_lane_claims_total", "从对端停靠在本节点的 lane 池中取用的次数", &label, counts.claims);
        out.counter("i3t_lane_claims_waited_total", "获取 lane 时池为空并等待补拨的次数", &label, counts.claims_waited);
        let waited = u64::try_from(counts.claim_wait.as_millis()).unwrap_or(u64::MAX);
        out.counter("i3t_lane_claim_wait_milliseconds_total", "获取 lane 累计等待时长（毫秒）", &label, waited);
        out.counter("i3t_lane_claims_failed_total", "获取 lane 失败的次数", &label, counts.claims_failed);
        out.counter("i3t_lane_fallbacks_total", "计划经 lane 传输但因获取失败而回退到共用连接的 TCP 流数量", &label, counts.fallbacks);
        out.counter("i3t_lane_dial_failures_total", "本节点拨号建立 lane 失败的次数", &label, counts.dial_failures);
        out.counter("i3t_lane_refused_total", "握手成功但因用途或数量不符被关闭的 lane 数量", &label, counts.refused);
        let help = "经 lane 传输的流数据字节数（双向合计）：sealed 为 TLS 加密转发，passthrough 为应用层直通转发，spliced 为内核态直接转发";
        for (mode, value) in [("sealed", counts.sealed_bytes), ("passthrough", counts.passthrough_bytes), ("spliced", counts.spliced_bytes)]
        {
            out.counter("i3t_lane_bytes_total", help, &[("peer", name.as_str()), ("mode", mode)], value);
        }
    }
    let failures = &status.handshake_failures;
    let help = "入站拨号中握手失败的连接数，按原因分类";
    for (reason, value) in [
        ("deadline", failures.deadline),
        ("unknown_key", failures.unknown_key),
        ("tls", failures.tls),
        ("protocol", failures.protocol),
        ("busy", failures.busy),
    ] {
        out.counter("i3t_lane_handshake_failures_total", help, &[("reason", reason)], value);
    }
}

/// 将整数转换为状态量（gauge）值。此处均为小数值（流数、会话数、版本号），超出 `u32` 范围时饱和为最大值。
fn as_gauge(value: impl TryInto<u32>) -> f64 {
    f64::from(value.try_into().unwrap_or(u32::MAX))
}

/// 字节数当作状态量的值。这不是收窄：超过 2^53 字节（约 9 PB）时只会损失精度，配额不会有这么大。
fn bytes_gauge(bytes: u64) -> f64 {
    bytes as f64
}

/// `PeerUnattached` → `peer_unattached`。丢弃原因的名字取自它的 Debug 写法：relay 加了新的原因，这里不用跟着改。
fn snake_case(name: &str) -> String {
    let mut snake = String::with_capacity(name.len() + 4);
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() && index > 0 {
            snake.push('_');
        }
        snake.push(ch.to_ascii_lowercase());
    }
    snake
}

/// 更新状态在 JSON 里的 `state` 字段的写法，指标里用同一个：从 serde 取，名字只写在 [`UpdateStatus`] 的属性里。
fn update_label(status: &UpdateStatus) -> String {
    serde_json::to_value(status).ok().and_then(|value| value.get("state")?.as_str().map(str::to_owned)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use i3t_model::update::Version;

    use super::*;

    #[test]
    fn the_deviation_is_what_the_connection_measured_minus_what_the_legs_predicted() {
        let actual = std::time::Duration::from_micros(52_500);
        assert_eq!(rtt_deviation_ms(Some(40), actual), Some(12.5));
        assert_eq!(rtt_deviation_ms(Some(60), actual), Some(-7.5), "比推算的快是负的");
        assert_eq!(rtt_deviation_ms(None, actual), None, "推算不出来时没有");
    }

    #[test]
    fn drop_reasons_become_snake_case_labels() {
        assert_eq!(snake_case("PeerUnattached"), "peer_unattached");
        assert_eq!(snake_case("Disabled"), "disabled");
        let labels: Vec<String> = DropReason::ALL.iter().map(|reason| snake_case(&format!("{reason:?}"))).collect();
        assert!(labels.contains(&"rate_limited".to_owned()), "{labels:?}");
        assert!(labels.iter().all(|label| label.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_')), "{labels:?}");
    }

    #[test]
    fn update_labels_match_the_json_spelling() {
        let version = Version::new(0, 2, 0);
        let labels = [UpdateStatus::Idle, UpdateStatus::WaitingForIdle { version: version.clone() }, UpdateStatus::SelfCheck { version }]
            .iter()
            .map(update_label)
            .collect::<Vec<_>>();
        assert_eq!(labels, ["idle", "waiting_for_idle", "self_check"]);
    }
}
