//! 下发的顺序和节奏：授权先到目的端，撤销先到发起端；上报引起的变化合并下发；删除立即生效。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use i3t_model::admin::{CreateRule, Direction, ErrorCode};
use i3t_model::control::{Declared, Report, Route, RouteEntry, Signal, ToController, ToNode};
use i3t_proto::NodeId;
use tokio::sync::mpsc;

use super::super::Timing;
use super::super::testing::{Lab, Member, REMOTE, hello};
use super::{add_rule, drop_default_rule, peer_ids, relations};
use crate::error::{Error, Rejection};
use crate::store::NetmapState;

/// 两个在线的节点，一个带标签 `src`，一个带标签 `dst`，之间没有任何规则，都已经确认了当前的 netmap。
fn two_unconnected(lab: &mut Lab) -> (i3t_model::admin::NetworkId, Member, Member) {
    let network = lab.network("home");
    drop_default_rule(lab, network.id);
    let mut source = lab.join(network.id, &["src"]);
    let mut destination = lab.join(network.id, &["dst"]);
    lab.settle(&mut [&mut source, &mut destination]);
    assert!(source.netmap().peers.is_empty() && destination.netmap().peers.is_empty());
    (network.id, source, destination)
}

fn report_endpoints(lab: &Lab, member: &Member, endpoint: &str) {
    let report = Report { endpoints: vec![endpoint.parse().unwrap()], ..Report::default() };
    lab.controller.handle(member.session, REMOTE, ToController::Report(Box::new(report))).unwrap();
}

#[test]
fn a_grant_reaches_the_destination_before_the_initiator() {
    let mut lab = Lab::new();
    let (network, mut source, mut destination) = two_unconnected(&mut lab);
    let (before_source, before_destination) = (source.snapshots.len(), destination.snapshots.len());

    add_rule(&lab, network, "src", "dst", Direction::OneWay);
    lab.controller.tick().unwrap();
    destination.receive();
    source.receive();
    assert_eq!(relations(destination.netmap()), vec![(source.id, true, false)], "目的端马上认发起端");
    assert_eq!(destination.snapshots.len(), before_destination + 1);
    assert_eq!(source.snapshots.len(), before_source, "目的端确认之前，发起端还不知道可以访问它");
    let graph = lab.controller.access_graph(network).unwrap();
    assert_eq!(graph.unacknowledged.iter().map(|node| node.id).collect::<Vec<_>>(), vec![destination.id]);
    assert!(!lab.controller.node_access(network, destination.id).unwrap().acknowledged);

    destination.ack(&lab.controller);
    lab.settle(&mut [&mut source, &mut destination]);
    assert_eq!(relations(source.netmap()), vec![(destination.id, false, true)]);
    assert_eq!(source.snapshots.len(), before_source + 1);
    assert_eq!(destination.snapshots.len(), before_destination + 1, "目的端不用再发一次");
    assert!(lab.controller.access_graph(network).unwrap().unacknowledged.is_empty());
}

#[test]
fn a_revocation_reaches_the_initiator_before_the_destination() {
    let mut lab = Lab::new();
    let (network, mut source, mut destination) = two_unconnected(&mut lab);
    let rule = add_rule(&lab, network, "src", "dst", Direction::OneWay);
    lab.settle(&mut [&mut source, &mut destination]);
    let (before_source, before_destination) = (source.snapshots.len(), destination.snapshots.len());

    lab.controller.delete_rule(network, rule).unwrap();
    lab.controller.tick().unwrap();
    source.receive();
    destination.receive();
    assert!(source.netmap().peers.is_empty(), "发起端马上不能再访问");
    assert_eq!(source.snapshots.len(), before_source + 1);
    assert_eq!(destination.snapshots.len(), before_destination, "发起端确认之前，目的端还认它");
    assert_eq!(relations(&lab.netmap(destination.id)), vec![(source.id, true, false)]);

    source.ack(&lab.controller);
    lab.settle(&mut [&mut source, &mut destination]);
    assert!(destination.netmap().peers.is_empty());
    assert_eq!(destination.snapshots.len(), before_destination + 1);
}

#[test]
fn a_two_way_grant_lets_each_side_dial_only_after_the_other_acknowledged() {
    let mut lab = Lab::new();
    let (network, mut a, mut b) = two_unconnected(&mut lab);
    add_rule(&lab, network, "src", "dst", Direction::Both);
    a.receive();
    b.receive();
    assert_eq!(relations(a.netmap()), vec![(b.id, true, false)]);
    assert_eq!(relations(b.netmap()), vec![(a.id, true, false)]);

    a.ack(&lab.controller);
    lab.settle(&mut []);
    b.receive();
    a.receive();
    assert_eq!(relations(b.netmap()), vec![(a.id, true, true)], "a 确认了，b 可以访问 a");
    assert_eq!(relations(a.netmap()), vec![(b.id, true, false)], "b 还没确认，a 还不能访问 b");

    lab.settle(&mut [&mut a, &mut b]);
    assert_eq!(relations(a.netmap()), vec![(b.id, true, true)]);
}

#[test]
fn an_offline_node_is_not_waited_for() {
    let mut lab = Lab::new();
    let (network, mut source, destination) = two_unconnected(&mut lab);
    lab.controller.disconnect(destination.session);
    let rule = add_rule(&lab, network, "src", "dst", Direction::OneWay);
    source.receive();
    assert_eq!(relations(source.netmap()), vec![(destination.id, false, true)], "目的端不在线，没有可等的");
    assert_eq!(relations(&lab.netmap(destination.id)), vec![(source.id, true, false)]);

    // 反过来：发起端不在线时撤销，目的端马上不认它。
    let mut destination = lab.connect(destination.key, Declared::default()).unwrap();
    lab.settle(&mut [&mut source, &mut destination]);
    lab.controller.disconnect(source.session);
    lab.controller.delete_rule(network, rule).unwrap();
    destination.receive();
    assert!(destination.netmap().peers.is_empty());
}

#[test]
fn a_node_going_offline_releases_those_waiting_for_it() {
    let mut lab = Lab::new();
    let (network, mut source, mut destination) = two_unconnected(&mut lab);
    add_rule(&lab, network, "src", "dst", Direction::OneWay);
    destination.receive();
    lab.settle(&mut [&mut source]);
    assert!(source.netmap().peers.is_empty());

    lab.controller.disconnect(destination.session);
    lab.settle(&mut [&mut source]);
    assert_eq!(peer_ids(source.netmap()), vec![destination.id]);
}

#[test]
fn a_node_that_never_acknowledges_stops_being_waited_for() {
    let timing = Timing {
        ack_coalesce: Duration::ZERO,
        report_coalesce: Duration::ZERO,
        ack_timeout: Duration::from_millis(80),
        ..Timing::default()
    };
    let mut lab = Lab::with_timing(timing);
    let (network, mut source, mut destination) = two_unconnected(&mut lab);
    add_rule(&lab, network, "src", "dst", Direction::OneWay);
    destination.receive();
    lab.settle(&mut [&mut source]);
    assert!(source.netmap().peers.is_empty());
    assert!(lab.controller.tick().unwrap().is_some(), "还有节点欠着确认，后台任务要回来看");

    std::thread::sleep(Duration::from_millis(100));
    lab.settle(&mut [&mut source]);
    assert_eq!(peer_ids(source.netmap()), vec![destination.id]);
    assert!(lab.controller.node(network, destination.id).unwrap().node.online, "只是不再等它，不断开它");
}

/// 延后的下发不等待，确认最多等 `ack_timeout`。
fn impatient(ack_timeout: Duration) -> Timing {
    Timing { ack_coalesce: Duration::ZERO, report_coalesce: Duration::ZERO, ack_timeout, ..Timing::default() }
}

#[test]
fn reconnecting_without_acknowledging_does_not_keep_a_revocation_pending() {
    let timeout = Duration::from_millis(200);
    let mut lab = Lab::with_timing(impatient(timeout));
    let (network, mut source, mut destination) = two_unconnected(&mut lab);
    let rule = add_rule(&lab, network, "src", "dst", Direction::OneWay);
    lab.settle(&mut [&mut source, &mut destination]);

    lab.controller.delete_rule(network, rule).unwrap();
    let revoked = Instant::now();
    source.receive();
    assert!(source.netmap().peers.is_empty());
    // 发起端收下 netmap 但从不确认，每隔不到一个超时就换一条新连接：每条新连接上都会重发一份 netmap。
    let mut reconnects = 0;
    while revoked.elapsed() < timeout * 3 {
        std::thread::sleep(timeout / 4);
        source = lab.connect(source.key, Declared::default()).unwrap();
        reconnects += 1;
        lab.controller.tick().unwrap();
        destination.receive_and_ack(&lab.controller);
    }
    assert!(reconnects >= 4);
    lab.settle(&mut [&mut destination]);
    assert!(destination.netmap().peers.is_empty(), "等满一个超时就不再认发起端，换连接推迟不了");
}

#[test]
fn a_netmap_that_keeps_changing_does_not_keep_a_revocation_pending() {
    let timeout = Duration::from_millis(200);
    let mut lab = Lab::with_timing(impatient(timeout));
    let network = lab.network("home");
    drop_default_rule(&lab, network.id);
    let rule = add_rule(&lab, network.id, "src", "dst", Direction::OneWay);
    add_rule(&lab, network.id, "pal", "src", Direction::OneWay);
    let mut source = lab.join(network.id, &["src"]);
    let mut destination = lab.join(network.id, &["dst"]);
    let mut pal = lab.join(network.id, &["pal"]);
    lab.settle(&mut [&mut source, &mut destination, &mut pal]);

    lab.controller.delete_rule(network.id, rule).unwrap();
    let revoked = Instant::now();
    source.receive();
    let before = source.snapshots.len();
    // 发起端一直在线、从不确认；它的另一个对端不停地报新的端点，发起端的 netmap 跟着一直在变、一直在重发。
    let mut port = 0;
    while revoked.elapsed() < timeout * 3 {
        port += 1;
        report_endpoints(&lab, &pal, &format!("203.0.113.7:{port}"));
        std::thread::sleep(timeout / 4);
        lab.controller.tick().unwrap();
        source.receive();
        destination.receive_and_ack(&lab.controller);
        pal.receive_and_ack(&lab.controller);
    }
    assert!(source.snapshots.len() >= before + 4, "这期间发起端不断收到新的 netmap");
    lab.settle(&mut [&mut destination, &mut pal]);
    assert!(destination.netmap().peers.is_empty(), "等满一个超时就不再认发起端，重发推迟不了");
}

/// 比"失败之后多久再试"长：把后台工作的时间往后拨这么多，排着重试的就都到期了，测试不用真的等。
const PAST_RETRY: Duration = Duration::from_secs(2);

/// 做一遍后台工作，时间算作 `after` 之后。
fn tick_after(lab: &Lab, after: Duration) -> Result<Option<Instant>, Error> {
    let mut inner = lab.controller.lock();
    let wall = inner.clock.now();
    inner.tick(Instant::now() + after, wall)
}

/// 存储里记着的这个节点的 netmap 下发到了哪一步。
fn stored(lab: &Lab, node: NodeId) -> NetmapState {
    lab.controller.lock().store.node(node).unwrap().expect("节点应该存在").netmap
}

#[test]
fn a_netmap_the_store_could_not_record_goes_out_once_it_can() {
    let mut lab = Lab::new();
    let network = lab.network("home");
    let mut reporter = lab.join(network.id, &[]);
    let mut peer = lab.join(network.id, &[]);
    lab.settle(&mut [&mut reporter, &mut peer]);
    let version = peer.netmap().version;
    let before = stored(&lab, peer.id);
    assert_eq!((before.version, before.sent, before.acked), (version, version, version));

    // 另一头报了新的端点，对端的 netmap 要变；可是轮到重算的时候存储写不进去。
    report_endpoints(&lab, &reporter, "203.0.113.9:1");
    lab.controller.lock().store.set_read_only(true);
    assert!(tick_after(&lab, PAST_RETRY).is_err());
    assert!(tick_after(&lab, PAST_RETRY).is_err(), "隔一会儿再试，还是写不进去");
    assert_eq!(peer.receive(), 0, "版本号记不下来，这一版就不发");
    assert_eq!(stored(&lab, peer.id), before);
    assert_eq!(lab.controller.node(network.id, peer.id).unwrap().node.netmap_version, version, "没记下来的版本号不算数");

    lab.controller.lock().store.set_read_only(false);
    tick_after(&lab, PAST_RETRY).unwrap();
    assert_eq!(peer.receive(), 1, "能写了之后补发");
    assert_eq!(peer.netmap().version, version + 1);
    assert_eq!(peer.netmap().peer(reporter.id).unwrap().endpoints[0], "203.0.113.9:1".parse::<SocketAddr>().unwrap());
    let after = stored(&lab, peer.id);
    assert_eq!((after.version, after.sent), (version + 1, version + 1));
    assert!(after.digest.is_some() && after.digest != before.digest);

    lab.settle(&mut [&mut reporter, &mut peer]);
    assert_eq!(peer.snapshots.last().unwrap().version, version + 1, "只补发一次");
    assert_eq!(stored(&lab, peer.id).acked, version + 1);
}

#[test]
fn a_two_step_change_goes_on_once_the_store_can_record_the_second_step() {
    let mut lab = Lab::new();
    let (network, mut source, mut destination) = two_unconnected(&mut lab);

    // 授权：目的端认了、也确认了，轮到发起端时存储写不进去。
    let rule = add_rule(&lab, network, "src", "dst", Direction::OneWay);
    destination.receive_and_ack(&lab.controller);
    lab.controller.lock().store.set_read_only(true);
    assert!(tick_after(&lab, PAST_RETRY).is_err());
    assert_eq!(source.receive(), 0);
    lab.controller.lock().store.set_read_only(false);
    tick_after(&lab, PAST_RETRY).unwrap();
    source.receive();
    assert_eq!(relations(source.netmap()), vec![(destination.id, false, true)], "能写了之后发起端接着拿到许可");
    lab.settle(&mut [&mut source, &mut destination]);

    // 撤销：发起端停了、也确认了，轮到目的端时存储写不进去。
    lab.controller.delete_rule(network, rule).unwrap();
    source.receive_and_ack(&lab.controller);
    assert!(source.netmap().peers.is_empty());
    lab.controller.lock().store.set_read_only(true);
    assert!(tick_after(&lab, PAST_RETRY).is_err());
    assert_eq!(destination.receive(), 0);
    lab.controller.lock().store.set_read_only(false);
    tick_after(&lab, PAST_RETRY).unwrap();
    destination.receive();
    assert!(destination.netmap().peers.is_empty(), "能写了之后目的端接着不认发起端");
}

#[test]
fn an_acknowledgement_the_store_could_not_record_still_lets_the_peer_go_on() {
    let mut lab = Lab::new();
    let (network, mut source, mut destination) = two_unconnected(&mut lab);
    add_rule(&lab, network, "src", "dst", Direction::OneWay);
    destination.receive();
    let version = destination.netmap().version;

    lab.controller.lock().store.set_read_only(true);
    assert!(lab.controller.handle(destination.session, REMOTE, ToController::Ack { version }).is_err());
    lab.controller.lock().store.set_read_only(false);

    // 节点不会把同一版再确认一遍：它确认过了就是确认过了，等它的发起端不能就此没人管。
    tick_after(&lab, PAST_RETRY).unwrap();
    source.receive();
    assert_eq!(relations(source.netmap()), vec![(destination.id, false, true)]);
    assert!(lab.controller.access_graph(network).unwrap().unacknowledged.iter().all(|node| node.id != destination.id));
}

#[test]
fn nodes_behind_a_failed_one_in_the_same_push_are_not_forgotten() {
    let mut lab = Lab::new();
    let network = lab.network("home");
    drop_default_rule(&lab, network.id);
    let mut source = lab.join(network.id, &["src"]);
    let mut first = lab.join(network.id, &["dst"]);
    let mut second = lab.join(network.id, &["dst"]);
    lab.settle(&mut [&mut source, &mut first, &mut second]);

    // 规则存下来了，可是给第一个目的端记新版本号时写不进去：这一次下发到它为止，第二个目的端还没轮到。
    lab.controller
        .lock()
        .store
        .execute_batch("CREATE TRIGGER no_netmap BEFORE UPDATE OF netmap_version ON nodes BEGIN SELECT RAISE(ABORT, 'no netmap'); END;");
    let (src, dst) = (lab.group(network.id, "src"), lab.group(network.id, "dst"));
    let request = CreateRule { name: String::new(), src, dst, direction: Direction::OneWay, enabled: true };
    assert!(lab.controller.create_rule(network.id, &request).is_err());
    assert_eq!(first.receive() + second.receive(), 0);
    lab.controller.lock().store.execute_batch("DROP TRIGGER no_netmap;");

    tick_after(&lab, PAST_RETRY).unwrap();
    first.receive();
    second.receive();
    assert_eq!(relations(first.netmap()), vec![(source.id, true, false)], "失败的那个过一会儿重试");
    assert_eq!(relations(second.netmap()), vec![(source.id, true, false)], "排在它后面的也没有落下");
    lab.settle(&mut [&mut source, &mut first, &mut second]);
    assert_eq!(peer_ids(source.netmap()), vec![first.id, second.id], "两个目的端都确认之后，发起端可以访问它们");
}

#[test]
fn report_changes_reach_peers_once_however_often_the_node_flaps() {
    let window = Duration::from_millis(150);
    let timing = Timing { ack_coalesce: Duration::ZERO, report_coalesce: window, ..Timing::default() };
    let mut lab = Lab::with_timing(timing);
    let network = lab.network("home");
    let mut flapping = lab.join(network.id, &[]);
    let mut peer = lab.join(network.id, &[]);
    lab.settle(&mut [&mut flapping, &mut peer]);
    let before_self = flapping.snapshots.len();
    let peer_id = peer.id;
    let due = |lab: &Lab| lab.controller.lock().dirty.get(&peer_id).map(|deferred| deferred.due);

    // 安静了一阵之后的第一次变化不等满一个窗口就发出去（`defer_report`）。
    report_endpoints(&lab, &flapping, "203.0.113.9:1");
    let previous = due(&lab).expect("对端的 netmap 要重算");
    std::thread::sleep(previous.saturating_duration_since(Instant::now()));
    lab.controller.tick().unwrap();
    assert_eq!(peer.receive(), 1, "到点发出去了");
    let before_peer = peer.snapshots.len();

    // 接着反复变化：都并进同一次重算，它离上一次至少一个窗口。
    report_endpoints(&lab, &flapping, "203.0.113.5:1");
    let closes = due(&lab).expect("对端的 netmap 要重算");
    assert!(closes >= previous + window, "同一个对端因为上报而重算，两次之间至少隔一个窗口");
    // tick 用的时间不晚于窗口关上之前的那一刻。机器忙的时候下面这些上报本身就可能比窗口长，那时到点发出去是对的；
    // 这里测的是"窗口之内什么都不发"，不是这台机器够不够快。
    let tick_inside_window = |lab: &Lab| {
        let mut inner = lab.controller.lock();
        let wall = inner.clock.now();
        inner.tick(Instant::now().min(closes - Duration::from_millis(1)), wall).unwrap();
    };
    tick_inside_window(&lab);
    for port in 2..=20 {
        report_endpoints(&lab, &flapping, &format!("203.0.113.5:{port}"));
        assert_eq!(due(&lab), Some(closes), "后来的变化跟着已经排着的那一次走，不推迟它，也不提前它");
        tick_inside_window(&lab);
    }
    assert_eq!(peer.receive(), 0, "合并窗口之内什么都不发");

    lab.settle(&mut [&mut flapping, &mut peer]);
    assert_eq!(peer.snapshots.len(), before_peer + 1, "二十次变化只发一次");
    let endpoints = &peer.netmap().peer(flapping.id).unwrap().endpoints;
    assert_eq!(endpoints[0], "203.0.113.5:20".parse::<SocketAddr>().unwrap(), "发的是最后的状态");
    assert_eq!(flapping.snapshots.len(), before_self, "它自己的 netmap 里没有自己的端点，不用重发");

    // 同样的内容再报一次不算变化。
    report_endpoints(&lab, &flapping, "203.0.113.5:20");
    assert!(lab.controller.lock().dirty.is_empty());
    let detail = lab.controller.node(network.id, flapping.id).unwrap();
    assert_eq!(detail.endpoints, vec!["203.0.113.5:20".parse::<SocketAddr>().unwrap()]);
    assert_eq!(detail.observed_endpoint, Some(SocketAddr::new(REMOTE, 20330)));
}

#[test]
fn reported_counters_and_routes_show_up_in_the_admin_views() {
    let mut lab = Lab::new();
    let network = lab.network("home");
    let mut a = lab.join(network.id, &[]);
    let mut b = lab.join(network.id, &[]);
    let stranger = lab.join_offline(lab.network("office").id, &[], Declared::default());
    lab.settle(&mut [&mut a, &mut b]);
    let report = Report {
        mapping_varies: Some(true),
        flows: 3,
        tx_bytes: 1_000,
        rx_bytes: 2_000,
        routes: vec![
            RouteEntry { peer: b.id, route: Route::None, rtt_ms: None },
            // 不在它 netmap 里的编号不记。
            RouteEntry { peer: stranger, route: Route::None, rtt_ms: None },
        ],
        ..Report::default()
    };
    lab.controller.handle(a.session, REMOTE, ToController::Report(Box::new(report))).unwrap();

    let detail = lab.controller.node(network.id, a.id).unwrap();
    assert_eq!((detail.mapping_varies, detail.flows, detail.tx_bytes, detail.rx_bytes), (Some(true), 3, 1_000, 2_000));
    let table = lab.controller.routes(network.id, a.id).unwrap();
    assert!(table.online);
    assert_eq!(table.routes.iter().map(|route| (route.peer.id, route.route.clone())).collect::<Vec<_>>(), vec![(b.id, Route::None)]);
    let overview = lab.controller.overview(network.id).unwrap();
    assert_eq!((overview.nodes, overview.online, overview.relays, overview.rules), (2, 2, 0, 1));
    assert_eq!(overview.unreachable_pairs.iter().map(|pair| (pair.a.id, pair.b.id)).collect::<Vec<_>>(), vec![(a.id, b.id)]);

    // 只报变化的部分：后来的上报覆盖同一个对端的那一项。
    let direct = Route::Direct { addr: "203.0.113.9:20330".parse().unwrap() };
    let update = Report { routes: vec![RouteEntry { peer: b.id, route: direct.clone(), rtt_ms: Some(12) }], ..Report::default() };
    lab.controller.handle(a.session, REMOTE, ToController::Report(Box::new(update))).unwrap();
    let table = lab.controller.routes(network.id, a.id).unwrap();
    assert_eq!((table.routes[0].route.clone(), table.routes[0].rtt_ms), (direct, Some(12)));
    assert!(lab.controller.overview(network.id).unwrap().unreachable_pairs.is_empty());

    lab.controller.disconnect(a.session);
    let table = lab.controller.routes(network.id, a.id).unwrap();
    assert!(!table.online && table.routes.is_empty());
    assert_eq!(lab.controller.overview(network.id).unwrap().online_nodes.iter().map(|node| node.id).collect::<Vec<_>>(), vec![b.id]);
}

#[test]
fn deleting_a_node_revokes_it_and_removes_it_from_everyone_at_once() {
    let mut lab = Lab::new();
    let network = lab.network("home");
    let mut doomed = lab.join(network.id, &[]);
    let mut other = lab.join(network.id, &[]);
    lab.settle(&mut [&mut doomed, &mut other]);
    assert_eq!(peer_ids(other.netmap()), vec![doomed.id]);

    lab.controller.delete_node(network.id, doomed.id).unwrap();
    other.receive();
    assert!(other.netmap().peers.is_empty(), "不等任何确认，删除的那一刻就从别人的 netmap 里消失");
    doomed.receive();
    assert!(doomed.revoked && doomed.is_closed());
    assert_eq!(lab.controller.node(network.id, doomed.id).unwrap_err().code(), ErrorCode::NotFound);
    assert_eq!(lab.connect(doomed.key, Declared::default()).err(), Some(Rejection::UnknownKey));
    // 旧连接上迟到的消息不起作用。
    lab.controller.handle(doomed.session, REMOTE, ToController::Ack { version: 99 }).unwrap();
    lab.controller.disconnect(doomed.session);
    assert_eq!(lab.controller.online_nodes(), vec![other.id]);
}

#[test]
fn signals_are_forwarded_only_between_mutual_peers() {
    let mut lab = Lab::new();
    let network = lab.network("home");
    drop_default_rule(&lab, network.id);
    add_rule(&lab, network.id, "a", "b", Direction::OneWay);
    let mut a = lab.join(network.id, &["a"]);
    let mut b = lab.join(network.id, &["b"]);
    let mut hidden = lab.join(network.id, &["c"]);
    let elsewhere = lab.network("office");
    let mut foreign = lab.join(elsewhere.id, &[]);
    lab.settle(&mut [&mut a, &mut b, &mut hidden, &mut foreign]);
    let signal = |endpoint: &str| Signal::PunchRequest { endpoints: vec![endpoint.parse().unwrap()] };
    let send = |from: &Member, to: &Member, signal: Signal| {
        lab.controller.handle(from.session, REMOTE, ToController::Signal { to: to.id, signal }).unwrap();
    };

    send(&a, &b, signal("203.0.113.1:1"));
    send(&b, &a, signal("203.0.113.2:2"));
    send(&a, &hidden, signal("203.0.113.3:3"));
    send(&hidden, &a, signal("203.0.113.4:4"));
    send(&foreign, &a, signal("203.0.113.5:5"));
    send(&a, &foreign, signal("203.0.113.6:6"));
    send(&a, &a, signal("203.0.113.7:7"));
    for member in [&mut a, &mut b, &mut hidden, &mut foreign] {
        member.receive();
    }
    assert_eq!(b.signals, vec![(a.id, signal("203.0.113.1:1"))], "一个方向的规则就够：两个节点互为对端");
    assert_eq!(a.signals, vec![(b.id, signal("203.0.113.2:2"))]);
    assert!(hidden.signals.is_empty() && foreign.signals.is_empty());

    // 对端不在线时信令被丢掉，不会留到它回来。
    lab.controller.disconnect(b.session);
    send(&a, &b, signal("203.0.113.8:8"));
    let mut b = lab.connect(b.key, Declared::default()).unwrap();
    b.receive();
    assert!(b.signals.is_empty());
}

#[test]
fn a_new_connection_replaces_the_old_one() {
    let mut lab = Lab::new();
    let network = lab.network("home");
    let mut first = lab.join(network.id, &[]);
    let mut second = lab.connect(first.key, Declared::default()).unwrap();
    assert_eq!(second.id, first.id);
    assert!(first.is_closed(), "旧连接的发送队列被关掉");
    assert_eq!(second.netmap().version, first.netmap().version, "新连接上先收到当前的 netmap");

    // 旧连接收尾时不能把节点标成离线，它上面迟到的消息也不算数。
    lab.controller.handle(first.session, REMOTE, ToController::Report(Box::new(Report { flows: 9, ..Report::default() }))).unwrap();
    lab.controller.disconnect(first.session);
    let detail = lab.controller.node(network.id, first.id).unwrap();
    assert!(detail.node.online);
    assert_eq!(detail.flows, 0);

    let mut other = lab.join(network.id, &[]);
    lab.settle(&mut [&mut second, &mut other]);
    assert_eq!(peer_ids(second.netmap()), vec![other.id], "之后的下发走新连接");
    lab.controller.disconnect(second.session);
    assert!(!lab.controller.node(network.id, first.id).unwrap().node.online);
}

#[test]
fn a_node_that_does_not_read_is_disconnected_instead_of_queueing_forever() {
    let mut lab = Lab::new();
    let network = lab.network("home");
    let secret = lab.secret(network.id, &Default::default());
    let key = lab.fresh_key();
    // 队列只有三格，这个"节点"从来不读：报到时的 netmap、对端加入、对端确认之后可以访问它，正好放满。
    let (outbox, mut inbox) = mpsc::channel(3);
    let stuck = lab.controller.enroll(key, &secret, &hello(Declared::default()), REMOTE, outbox).unwrap();
    let mut peer = lab.join(network.id, &[]);
    lab.settle(&mut [&mut peer]);
    assert!(lab.controller.node(network.id, stuck.node).unwrap().node.online);

    for name in ["one", "two", "three"] {
        super::rename(&lab, network.id, peer.id, name);
        lab.settle(&mut [&mut peer]);
    }
    assert!(!lab.controller.node(network.id, stuck.node).unwrap().node.online, "队列满了就断开");
    assert!(matches!(inbox.try_recv(), Ok(ToNode::Snapshot(_))));
    assert_eq!(peer.netmap().me.name, "three", "别的节点不受影响");
}
