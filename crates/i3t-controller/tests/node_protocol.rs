//! 节点协议的集成测试：真的 TCP、真的 TLS，节点一侧用 `i3t-crypto` 搭的客户端。

// clippy.toml 里的 allow-unwrap-in-tests 只认 `#[test]` 函数本身，认不出集成测试里的辅助函数。
#![allow(clippy::unwrap_used, reason = "整个文件都是测试代码，出错就该直接失败")]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{Link, Node, PATIENCE, Publisher, Running, eventually, fast_timing, hello, settle};
use i3t_controller::Timing;
use i3t_controller::webui::WebUi;
use i3t_crypto::NodeKey;
use i3t_model::admin::{CreateRule, Direction, PackageState, PathSource, RelaySettings};
use i3t_model::control::{Declared, MAX_PACKAGE_CHUNK, Report, Route, RouteAnswer, Signal, ToController, ToNode};
use i3t_model::update::{UpdateStatus, UpdateTiming, Version};
use i3t_proto::addr::{Query, Reply};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;

fn peer_ids(node: &Node) -> Vec<i3t_proto::NodeId> {
    node.netmap().peers.iter().map(|peer| peer.id).collect()
}

#[tokio::test]
async fn a_node_enrols_and_gets_its_snapshot() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let node = running.join(network.id, &["servers"]).await;

    let netmap = node.netmap();
    assert_eq!(netmap.version, 1);
    assert_eq!((netmap.network.name.as_str(), netmap.network.cidr), ("home", network.cidr));
    assert_eq!(netmap.me.virtual_ip, "10.66.0.1".parse::<std::net::Ipv4Addr>().unwrap());
    assert!(netmap.peers.is_empty());

    // controller 认的是 TLS 握手里证明过的公钥。
    let listed = running.controller.nodes(network.id).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].id, listed[0].key), (node.id(), node.key.public()));
    assert_eq!(listed[0].groups.iter().map(|group| group.name.as_str()).collect::<Vec<_>>(), ["servers"]);
    assert!(listed[0].online);
    assert_eq!((listed[0].platform.as_str(), listed[0].version.as_str()), ("linux-x86_64", "0.1.0"));
    let detail = running.controller.node(network.id, node.id()).unwrap();
    assert_eq!(detail.observed_endpoint, Some("127.0.0.1:20330".parse().unwrap()), "来源 IP 加上节点自报的 UDP 端口");
    eventually("controller 记下节点的确认", || running.controller.node(network.id, node.id()).unwrap().node.acked_version == 1).await;
    running.shutdown().await;
}

#[tokio::test]
async fn a_second_node_appears_in_the_first_nodes_next_snapshot() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut first = running.join(network.id, &[]).await;
    let mut second = running.join(network.id, &[]).await;

    first.until("第二个节点出现并且可以互相访问", |netmap| netmap.peers.iter().any(|peer| peer.inbound && peer.outbound)).await;
    second.until("第一个节点可以互相访问", |netmap| netmap.peers.iter().any(|peer| peer.inbound && peer.outbound)).await;
    let seen = first.netmap().peer(second.id()).unwrap();
    assert_eq!((seen.key, seen.virtual_ip), (second.key.public(), second.netmap().me.virtual_ip));
    assert_eq!(seen.endpoints, vec!["127.0.0.1:20330".parse::<SocketAddr>().unwrap()]);
    assert_eq!(peer_ids(&second), vec![first.id()]);
    assert!(first.netmap().version > 1);
    running.shutdown().await;
}

#[tokio::test]
async fn report_changes_propagate_to_peers() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut reporter = running.join(network.id, &[]).await;
    let mut peer = running.join(network.id, &[]).await;
    let mut relay = Node::new();
    relay.declared = Declared { relay: true, ..Declared::default() };
    relay.enroll(&running, &running.secret(network.id, &[])).await.unwrap();
    let settings = RelaySettings::default();
    running.controller.enable_relay(network.id, relay.id(), settings).unwrap();
    let reporter_id = reporter.id();
    settle(&mut [&mut reporter, &mut peer, &mut relay]).await;
    assert!(peer.netmap().peer(reporter_id).is_some_and(|peer| peer.outbound) && peer.netmap().relays.len() == 1);

    let endpoint: SocketAddr = "203.0.113.50:40000".parse().unwrap();
    let attached = i3t_model::netmap::Attachment { relay: relay.id(), rtt_ms: 12, shared: false };
    reporter
        .send(ToController::Report(Box::new(Report { endpoints: vec![endpoint], attached: vec![attached], ..Report::default() })))
        .await;
    peer.until("上报的端点和挂靠关系出现在对端的 netmap 里", |netmap| {
        netmap.peer(reporter_id).is_some_and(|peer| peer.endpoints.contains(&endpoint) && peer.attached == vec![attached])
    })
    .await;

    // 同样的内容再报一次，对端不会收到新的 netmap。
    let version = peer.netmap().version;
    reporter
        .send(ToController::Report(Box::new(Report { endpoints: vec![endpoint], attached: vec![attached], ..Report::default() })))
        .await;
    assert!(peer.stays_quiet(Duration::from_millis(200)).await);
    assert_eq!(running.controller.netmap_of(peer.id()).unwrap().unwrap().version, version);
    running.shutdown().await;
}

#[tokio::test]
async fn nodes_that_share_no_relay_are_told_to_meet_on_one_both_reach_and_who_reaches_a_relay_is_shown() {
    use i3t_model::admin::{NodeWarning, RelayReach};
    use i3t_model::control::{RelayTry, TryOutcome};
    use i3t_model::netmap::Attachment;

    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut home = running.join(network.id, &[]).await;
    let mut abroad = running.join(network.id, &[]).await;
    let mut relays = Vec::new();
    for _ in 0..3 {
        let mut relay = Node::new();
        relay.declared = Declared { relay: true, ..Declared::default() };
        relay.enroll(&running, &running.secret(network.id, &[])).await.unwrap();
        running.controller.enable_relay(network.id, relay.id(), RelaySettings::default()).unwrap();
        relays.push(relay);
    }
    let [local_1, local_2, everyone] = [relays[0].id(), relays[1].id(), relays[2].id()];
    let tried = |relay, outcome, seen_as: &str| RelayTry { relay, outcome, age_secs: 0, seen_as: Some(seen_as.parse().unwrap()) };
    let own = |relay, rtt_ms| Attachment { relay, rtt_ms, shared: false };

    // 家里的节点挑了两个只有家里连得上的 relay；国外的节点只连得上第三个。家里的节点也连得上第三个。
    let home_tries = vec![
        tried(local_1, TryOutcome::Udp, "203.0.113.20"),
        tried(local_2, TryOutcome::Udp, "203.0.113.20"),
        tried(everyone, TryOutcome::Udp, "203.0.113.20"),
    ];
    let abroad_tries = vec![
        tried(everyone, TryOutcome::Tcp, "198.51.100.30"),
        RelayTry { relay: local_1, outcome: TryOutcome::Unreached, age_secs: 40, seen_as: None },
        RelayTry { relay: local_2, outcome: TryOutcome::Unreached, age_secs: 40, seen_as: None },
    ];
    let home_report = Report { attached: vec![own(local_1, 2), own(local_2, 3)], relays: home_tries, ..Report::default() };
    home.send(ToController::Report(Box::new(home_report))).await;
    abroad
        .send(ToController::Report(Box::new(Report { attached: vec![own(everyone, 80)], relays: abroad_tries, ..Report::default() })))
        .await;

    // 家里的节点要另外挂上两边都连得上的那个；国外的节点不用（家里的节点连得上它挂的那个）。
    home.until("家里的节点被要求另外挂靠两边都连得上的 relay", |netmap| netmap.me.shared_relays == vec![everyone]).await;
    abroad
        .until("国外的节点看到家里的节点的挂靠", |netmap| {
            netmap.peer(home.id()).is_some_and(|peer| peer.attached.len() == 2)
        })
        .await;
    assert!(abroad.netmap().me.shared_relays.is_empty());

    // 每个 relay 有几个在线的节点连得上：只有家里连得上的照样不提醒，只是如实数出来。
    let listed = running.controller.nodes(network.id).unwrap();
    let relay_view = |id| listed.iter().find(|node| node.id == id).unwrap().clone();
    assert_eq!(relay_view(local_1).relay.unwrap().reach, RelayReach { reached: 1, unreached: 1, unknown: 2 });
    assert!(relay_view(local_1).warnings.is_empty(), "有节点连得上就不是毛病");
    let detail = running.controller.node(network.id, local_1).unwrap();
    let by: Vec<_> = detail.reached_by.unwrap().iter().map(|entry| (entry.node.id, entry.outcome)).collect();
    assert_eq!(by, [(home.id(), TryOutcome::Udp), (abroad.id(), TryOutcome::Unreached)]);
    assert_eq!(running.controller.node(network.id, home.id()).unwrap().reached_by, None, "不是 relay");

    // 没有一个在线的节点连得上的 relay 有一条如实的提醒，总览里也有。
    let nobody = vec![RelayTry { relay: local_2, outcome: TryOutcome::Unreached, age_secs: 0, seen_as: None }];
    home.send(ToController::Report(Box::new(Report { attached: vec![own(local_1, 2)], relays: nobody, ..Report::default() }))).await;
    eventually("家里的节点也连不上第二个 relay 了", || {
        running.controller.nodes(network.id).unwrap().iter().any(|node| node.id == local_2 && !node.warnings.is_empty())
    })
    .await;
    let warned = running.controller.overview(network.id).unwrap().warnings;
    assert_eq!(
        warned.iter().map(|entry| (entry.node.id, entry.warning)).collect::<Vec<_>>(),
        [(local_2, NodeWarning::RelayUnreached { tried: 2 })]
    );

    // 出口地址：controller 看到的是回环地址（不是公网地址），所以用 relay 看到的那个，国家从它查。
    let home_node = running.controller.node(network.id, home.id()).unwrap().node;
    assert_eq!(home_node.egress_ip, Some("203.0.113.20".parse().unwrap()));
    let abroad_node = running.controller.node(network.id, abroad.id()).unwrap().node;
    assert_eq!(abroad_node.egress_ip, Some("198.51.100.30".parse().unwrap()), "TCP 上看到的地址照样是出口地址");
    running.shutdown().await;
}

#[tokio::test]
async fn signals_are_forwarded_only_between_peers() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    for rule in running.controller.rules(network.id).unwrap() {
        running.controller.delete_rule(network.id, rule.id).unwrap();
    }
    let (src, dst) = (running.group(network.id, "a"), running.group(network.id, "b"));
    let rule = CreateRule { name: String::new(), src, dst, direction: Direction::Both, enabled: true };
    running.controller.create_rule(network.id, &rule).unwrap();
    let mut a = running.join(network.id, &["a"]).await;
    let mut b = running.join(network.id, &["b"]).await;
    let mut outsider = running.join(network.id, &["c"]).await;
    let (a_id, b_id, outsider_id) = (a.id(), b.id(), outsider.id());
    a.until("a 可以访问 b", |netmap| netmap.peer(b_id).is_some_and(|peer| peer.outbound)).await;
    b.until("b 可以访问 a", |netmap| netmap.peer(a_id).is_some_and(|peer| peer.outbound)).await;
    assert!(outsider.netmap().peers.is_empty());

    // 先发一条到不了的，再发一条到得了的：b 收到的第一条信令是后一条，说明前一条被丢掉了。
    let dropped = Signal::PunchRequest { endpoints: vec!["203.0.113.66:1".parse().unwrap()] };
    let delivered = Signal::PunchRequest { endpoints: vec!["203.0.113.1:20330".parse().unwrap()] };
    outsider.send(ToController::Signal { to: b_id, signal: dropped.clone() }).await;
    a.send(ToController::Signal { to: outsider_id, signal: dropped }).await;
    a.send(ToController::Signal { to: b_id, signal: delivered.clone() }).await;
    assert_eq!(b.next().await, Some(ToNode::Signal { from: a_id, signal: delivered }));
    let reply = Signal::PunchReply { endpoints: vec!["203.0.113.2:20330".parse().unwrap()] };
    b.send(ToController::Signal { to: a_id, signal: reply.clone() }).await;
    assert_eq!(a.next().await, Some(ToNode::Signal { from: b_id, signal: reply }));
    assert!(outsider.stays_quiet(Duration::from_millis(100)).await, "不是对端的节点什么都收不到");
    running.shutdown().await;
}

#[tokio::test]
async fn deleting_a_node_revokes_it_and_its_key_is_no_longer_accepted() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut doomed = running.join(network.id, &[]).await;
    let mut other = running.join(network.id, &[]).await;
    let doomed_id = doomed.id();
    other.until("两个节点互相看得见", |netmap| netmap.peer(doomed_id).is_some()).await;

    running.controller.delete_node(network.id, doomed_id).unwrap();
    let mut seen = Vec::new();
    while let Some(message) = doomed.next().await {
        seen.push(message);
    }
    assert_eq!(seen.last(), Some(&ToNode::Revoked), "被删的节点最后收到的是 revoked，然后连接被关闭：{seen:?}");
    other.until("被删的节点从别人的 netmap 里消失", |netmap| netmap.peers.is_empty()).await;

    let reason = doomed.connect(&running).await.unwrap_err();
    assert!(reason.contains("没有") && reason.contains("注册"), "{reason}");
    assert!(running.controller.online_nodes() == vec![other.id()]);
    running.shutdown().await;
}

#[tokio::test]
async fn a_bad_token_is_rejected_with_a_reason() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut node = Node::new();
    let reason = node.enroll(&running, "not-a-real-secret").await.unwrap_err();
    assert!(reason.contains("令牌"), "{reason}");

    // 令牌只能用一次：第二个节点拿同一个令牌进不来。
    let secret = running.secret(network.id, &[]);
    node.enroll(&running, &secret).await.unwrap();
    let mut second = Node::new();
    assert!(second.enroll(&running, &secret).await.is_err());
    assert_eq!(running.controller.nodes(network.id).unwrap().len(), 1);
    running.shutdown().await;
}

#[tokio::test]
async fn an_unknown_key_is_rejected_and_the_first_message_must_introduce_the_node() {
    let running = Running::start(fast_timing()).await;
    running.network("home");
    let mut stranger = Node::new();
    let reason = stranger.connect(&running).await.unwrap_err();
    assert!(reason.contains("公钥"), "{reason}");

    let key = NodeKey::generate().unwrap();
    let mut link = Link::open(running.node_addr, &key, running.controller.public_key()).await.unwrap();
    link.send(&ToController::Heartbeat).await;
    assert!(matches!(link.recv().await, Some(ToNode::Rejected { .. })));
    assert_eq!(link.recv().await, None, "拒绝之后连接被关闭");
    assert!(running.controller.online_nodes().is_empty());
    running.shutdown().await;
}

#[tokio::test]
async fn a_client_expecting_another_controller_key_does_not_connect() {
    let running = Running::start(fast_timing()).await;
    let key = NodeKey::generate().unwrap();
    let impostor = NodeKey::generate().unwrap().public();
    assert!(Link::open(running.node_addr, &key, impostor).await.is_err(), "节点只认注册令牌里写的那把 controller 公钥");
    running.shutdown().await;
}

#[tokio::test]
async fn a_new_connection_replaces_the_old_one() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut node = running.join(network.id, &[]).await;
    let id = node.id();

    // 同一把密钥再连一次：旧连接被 controller 关掉，节点一直是在线的。
    let mut again = Node::with_key(NodeKey::from_pem(&node.key.to_pem()).unwrap());
    again.connect(&running).await.unwrap();
    assert_eq!(again.id(), id);
    assert_eq!(node.next().await, None, "旧连接应该被关闭");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(running.controller.node(network.id, id).unwrap().node.online, "旧连接收尾不能把节点标成离线");

    let other = running.join(network.id, &[]).await;
    let other_id = other.id();
    again.until("之后的下发走新连接", |netmap| netmap.peer(other_id).is_some()).await;

    again.disconnect();
    eventually("连接断开之后节点记为离线", || !running.controller.node(network.id, id).unwrap().node.online).await;
    assert!(running.controller.node(network.id, id).unwrap().node.last_seen_at.is_some());
    running.shutdown().await;
}

#[tokio::test]
async fn a_changed_declaration_can_be_sent_on_the_same_connection() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut node = running.join(network.id, &[]).await;
    let id = node.id();
    assert!(running.controller.enable_exit(network.id, id, Default::default()).is_err());

    node.send(ToController::Hello(hello(Declared { exit: true, ..Declared::default() }))).await;
    eventually("controller 记下新的声明", || running.controller.node(network.id, id).unwrap().node.declared.exit).await;
    running.controller.enable_exit(network.id, id, Default::default()).unwrap();
    node.until("出口启用了", |netmap| netmap.me.exit.is_some()).await;

    node.send(ToController::Hello(hello(Declared::default()))).await;
    node.until("撤回声明之后出口关闭", |netmap| netmap.me.exit.is_none()).await;
    assert!(running.controller.node(network.id, id).unwrap().node.exit.is_none());
    running.shutdown().await;
}

#[tokio::test]
async fn the_controller_sends_heartbeats_when_idle_and_drops_silent_nodes() {
    let timing = Timing { heartbeat_idle: Duration::from_millis(100), liveness_timeout: Duration::from_millis(600), ..fast_timing() };
    let running = Running::start(timing).await;
    let network = running.network("home");
    let mut node = running.join(network.id, &[]).await;
    let id = node.id();

    // 节点一直不说话：先收到几个心跳，然后因为太久没有消息被断开。
    let mut heartbeats = 0;
    let closed = async {
        while let Some(message) = node.link().recv().await {
            assert_eq!(message, ToNode::Heartbeat);
            heartbeats += 1;
        }
    };
    timeout(PATIENCE, closed).await.expect("沉默的节点应该被断开");
    assert!(heartbeats >= 2, "空闲时应该定期发心跳，只收到 {heartbeats} 个");
    eventually("沉默的节点记为离线", || !running.controller.node(network.id, id).unwrap().node.online).await;

    // 定期上报的节点不会被断开。
    node.connect(&running).await.unwrap();
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        node.send(ToController::Report(Box::default())).await;
    }
    assert!(running.controller.node(network.id, id).unwrap().node.online);
    running.shutdown().await;
}

#[tokio::test]
async fn a_node_stays_online_while_the_controller_is_stuck_handling_its_messages() {
    /// controller 卡住的时长，远超存活期限。
    const STALL: Duration = Duration::from_millis(1500);
    let timing = Timing { heartbeat_idle: Duration::from_millis(100), liveness_timeout: Duration::from_millis(600), ..fast_timing() };
    let running = Running::start(timing).await;
    let network = running.network("home");
    let mut node = running.join(network.id, &[]).await;
    let id = node.id();

    // controller 卡在锁上，例如等待无响应的数据库。
    let controller = Arc::clone(&running.controller);
    let (held, holding) = oneshot::channel();
    let stuck = tokio::task::spawn_blocking(move || {
        let _stalled = controller.stall();
        held.send(()).unwrap();
        std::thread::sleep(STALL);
    });
    holding.await.unwrap();

    // 卡住期间节点照常上报、发心跳：上报要等锁才能处理，但不影响心跳的收发和存活判定。
    // 上报多到待处理的队列装不下：读取因此暂停，同样不算节点沉默。
    for _ in 0..32 {
        node.send(ToController::Report(Box::default())).await;
    }
    let mut heartbeats = 0;
    while !stuck.is_finished() {
        node.send(ToController::Heartbeat).await;
        if let Some(message) = node.link().recv_within(Duration::from_millis(100)).await {
            assert_eq!(message, ToNode::Heartbeat);
            heartbeats += 1;
        }
    }
    stuck.await.unwrap();
    assert!(heartbeats >= 5, "卡住期间 controller 应照常发送心跳，只收到 {heartbeats} 个");
    assert!(running.controller.node(network.id, id).unwrap().node.online, "一直在说话的节点不应被判为离线");
    node.send(ToController::Heartbeat).await;
    assert_eq!(node.link().recv().await, Some(ToNode::Heartbeat), "连接仍然可用");
    running.shutdown().await;
}

#[tokio::test]
async fn signals_answers_and_package_requests_do_not_wait_for_a_controller_stuck_on_the_store() {
    /// controller 卡住的时长，长于等路由查询回答的期限（3 秒）。
    const STALL: Duration = Duration::from_secs(4);
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let (mut a, mut b) = (Node::new(), Node::new());
    for node in [&mut a, &mut b] {
        node.modern = Some("0.2.0");
        node.enroll(&running, &running.secret(network.id, &[])).await.unwrap();
    }
    let (a_id, b_id) = (a.id(), b.id());
    settle(&mut [&mut a, &mut b]).await;

    // 两端各收到一条路由查询，之后 controller 卡在锁上，例如等待无响应的数据库。
    let controller = Arc::clone(&running.controller);
    let asking = tokio::spawn(async move { controller.path(network.id, a_id, b_id).await.unwrap() });
    let ToNode::RouteQuery { request: forward, .. } = next_other(&mut a).await else { panic!("a 应该收到路由查询") };
    let ToNode::RouteQuery { request: reverse, .. } = next_other(&mut b).await else { panic!("b 应该收到路由查询") };
    let controller = Arc::clone(&running.controller);
    let (held, holding) = oneshot::channel();
    let stuck = tokio::task::spawn_blocking(move || {
        let _stalled = controller.stall();
        held.send(()).unwrap();
        std::thread::sleep(STALL);
    });
    holding.await.unwrap();

    // 每个节点先发一份上报（要等锁才能处理，排在它自己的队列里），再发不读写存储的消息：后者不排在上报后面。
    a.send(ToController::Report(Box::default())).await;
    b.send(ToController::Report(Box::default())).await;
    let answer = |peer| RouteAnswer {
        peer,
        route: Some(Route::Direct { addr: "203.0.113.9:20330".parse().unwrap() }),
        rtt_ms: Some(7),
        since: None,
        detail: None,
        connection_rtt_ms: None,
    };
    a.send(ToController::RouteAnswer { request: forward, answer: answer(b_id) }).await;
    b.send(ToController::RouteAnswer { request: reverse, answer: answer(a_id) }).await;
    let signal = Signal::PunchRequest { endpoints: vec!["203.0.113.1:20330".parse().unwrap()] };
    a.send(ToController::Signal { to: b_id, signal: signal.clone() }).await;
    assert_eq!(next_other(&mut b).await, ToNode::Signal { from: a_id, signal }, "信令照常转发");
    let platform = "linux-x86_64".parse().unwrap();
    let version = "0.9.0".parse().unwrap();
    a.send(ToController::PackageRequest { request: 5, version, platform, offset: 0, len: 1 }).await;
    assert!(matches!(next_other(&mut a).await, ToNode::PackageUnavailable { request: 5, .. }), "取包照常回复");
    assert!(!stuck.is_finished(), "以上都发生在 controller 卡住期间");

    stuck.await.unwrap();
    let view = timeout(PATIENCE, asking).await.unwrap().unwrap();
    assert_eq!((view.forward.source, view.forward.rtt_ms), (PathSource::Query, Some(7)), "回答在等待期限内交给了问的人");
    assert_eq!((view.reverse.source, view.reverse.rtt_ms), (PathSource::Query, Some(7)));
    running.shutdown().await;
}

#[tokio::test]
async fn a_grant_waits_for_the_destination_but_not_forever() {
    let timing = Timing { ack_timeout: Duration::from_millis(300), ..fast_timing() };
    let running = Running::start(timing).await;
    let network = running.network("home");
    for rule in running.controller.rules(network.id).unwrap() {
        running.controller.delete_rule(network.id, rule.id).unwrap();
    }
    let mut source = running.join(network.id, &["src"]).await;
    let mut destination = running.join(network.id, &["dst"]).await;
    let (source_id, destination_id) = (source.id(), destination.id());

    let (src, dst) = (running.group(network.id, "src"), running.group(network.id, "dst"));
    let rule = CreateRule { name: String::new(), src, dst, direction: Direction::OneWay, enabled: true };
    running.controller.create_rule(network.id, &rule).unwrap();
    // 目的端收到了新的 netmap 但还没确认：发起端这时还不知道可以访问它。
    let granted = destination.link().recv().await;
    let Some(ToNode::Snapshot(netmap)) = granted else { panic!("目的端应该先收到 netmap：{granted:?}") };
    assert!(netmap.peer(source_id).is_some_and(|peer| peer.inbound && !peer.outbound));
    assert!(source.stays_quiet(Duration::from_millis(100)).await, "目的端确认之前不通告发起端");

    // 目的端一直不确认。controller 等够了就不再等，发起端照样拿到授权。
    source
        .until("目的端迟迟不确认，发起端最终也拿到授权", |netmap| {
            netmap.peer(destination_id).is_some_and(|peer| peer.outbound)
        })
        .await;
    assert!(running.controller.node(network.id, destination_id).unwrap().node.online);
    running.shutdown().await;
}

#[tokio::test]
async fn unknown_message_types_are_skipped_without_dropping_the_connection() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut node = running.join(network.id, &[]).await;
    let id = node.id();
    // 更新版本的节点可能发来这个版本不认识的消息。
    let body = serde_json::to_vec(&serde_json::json!({ "type": "added_in_a_newer_version", "x": 1 })).unwrap();
    let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    node.link().send_raw(&frame).await;
    node.send(ToController::Report(Box::new(Report { flows: 5, ..Report::default() }))).await;
    eventually("后面的消息照常处理", || running.controller.node(network.id, id).unwrap().flows == 5).await;
    running.shutdown().await;
}

#[tokio::test]
async fn the_address_port_answers_queries_and_ignores_everything_else() {
    let running = Running::start(fast_timing()).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    let mut buffer = [0; 64];

    // 不是查询的包没有回应；之后的查询照常回答，回答不比查询大。
    socket.send_to(&[0xff; 32], running.node_addr).await.unwrap();
    socket.send_to(&Query { nonce: [7; 8] }.to_bytes()[..20], running.node_addr).await.unwrap();
    let query = Query { nonce: [1, 2, 3, 4, 5, 6, 7, 8] };
    socket.send_to(&query.to_bytes(), running.node_addr).await.unwrap();
    let (len, from) = timeout(PATIENCE, socket.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(from, running.node_addr, "地址查询和节点协议用同一个端口号");
    assert!(len <= Query::LEN);
    assert_eq!(Reply::parse(&buffer[..len]), Some(Reply { nonce: query.nonce, observed: local }));
    assert!(timeout(Duration::from_millis(100), socket.recv_from(&mut buffer)).await.is_err(), "只有一个应答");
    running.shutdown().await;
}

#[tokio::test]
async fn shutting_down_closes_node_connections_and_marks_them_offline() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut node = running.join(network.id, &[]).await;
    let id = node.id();
    let controller = std::sync::Arc::clone(&running.controller);
    running.shutdown().await;
    assert_eq!(node.next().await, None);
    assert!(!controller.node(network.id, id).unwrap().node.online);
}

/// 等下一条不是 netmap、也不是心跳的消息。
async fn next_other(node: &mut Node) -> ToNode {
    loop {
        match node.next().await.expect("连接不应该断") {
            ToNode::Snapshot(_) => {}
            other => return other,
        }
    }
}

#[tokio::test]
async fn a_node_is_told_to_update_and_fetches_the_package_in_chunks_over_the_link() {
    let publisher = Publisher::new();
    let cache = tempfile::tempdir().unwrap();
    let program: Vec<u8> = (0..=u8::MAX).cycle().take(600_000).collect();
    publisher.publish("0.2.0", &[("linux-x86_64", &program)]);
    let running = Running::serve(publisher.controller(fast_timing(), cache.path()), WebUi::NotIncluded).await;
    let network = running.network("home");
    running.controller.check_release().unwrap();

    let mut old = running.join(network.id, &[]).await;
    let mut node = Node::new();
    node.modern = Some("0.1.0");
    node.enroll(&running, &running.secret(network.id, &[])).await.unwrap();
    node.send(ToController::Report(Box::new(Report { update: Some(UpdateStatus::Idle), routes_full: true, ..Report::default() }))).await;
    old.send(ToController::Report(Box::default())).await;
    let wanted = || running.controller.update_overview().unwrap().release.unwrap().packages[0].state == PackageState::Fetching;
    eventually("controller 知道这个平台的包有人要", wanted).await;
    // 后台任务在测试里是关着的，替它取一次包。
    let controller = std::sync::Arc::clone(&running.controller);
    tokio::task::spawn_blocking(move || controller.fetch_packages().unwrap()).await.unwrap();

    let ToNode::Update { manifest, timing } = next_other(&mut node).await else { panic!("应该收到更新指令") };
    assert_eq!(timing, UpdateTiming::Idle);
    let verified = publisher.keys().verify(&manifest).expect("清单原样带着签名发下来，节点自己验得过");
    let version: Version = "0.2.0".parse().unwrap();
    assert_eq!(verified.version, version);
    let artifact = verified.artifacts["linux-x86_64"].clone();

    // 一段一段取，取到清单上写的大小为止。
    let mut received = Vec::new();
    let mut request = 0;
    while u64::try_from(received.len()).unwrap() < artifact.size {
        request += 1;
        let offset = u64::try_from(received.len()).unwrap();
        let platform = "linux-x86_64".parse().unwrap();
        node.send(ToController::PackageRequest { request, version: version.clone(), platform, offset, len: MAX_PACKAGE_CHUNK }).await;
        let ToNode::PackageChunk { request: answered, data } = next_other(&mut node).await else { panic!("应该收到一段包") };
        assert_eq!(answered, request);
        assert!(!data.is_empty() && data.len() <= usize::try_from(MAX_PACKAGE_CHUNK).unwrap());
        received.extend_from_slice(&data);
    }
    assert_eq!(received, program);
    assert_eq!(request, 3, "600 KB 的包是三段");

    // 没有的包明说给不了。
    let platform = "macos-aarch64".parse().unwrap();
    node.send(ToController::PackageRequest { request: 9, version, platform, offset: 0, len: 1 }).await;
    assert!(matches!(next_other(&mut node).await, ToNode::PackageUnavailable { request: 9, .. }));

    while let Some(message) = old.link().recv_within(Duration::from_millis(300)).await {
        assert!(matches!(message, ToNode::Snapshot(_) | ToNode::Heartbeat), "最初那一版的节点不懂更新，不该收到 {message:?}");
    }
    let listed = running.controller.nodes(network.id).unwrap();
    let outdated = listed.iter().find(|listed| listed.id == old.id()).unwrap();
    assert!(outdated.update.available.is_some() && outdated.update.self_update.is_none());
    running.shutdown().await;
}

#[tokio::test]
async fn a_route_query_goes_to_the_node_and_its_answer_comes_back_to_the_caller() {
    let running = Running::start(fast_timing()).await;
    let network = running.network("home");
    let mut asked = Node::new();
    asked.modern = Some("0.2.0");
    asked.enroll(&running, &running.secret(network.id, &[])).await.unwrap();
    let mut old = running.join(network.id, &[]).await;
    let (from, to) = (asked.id(), old.id());
    settle(&mut [&mut asked, &mut old]).await;

    let controller = std::sync::Arc::clone(&running.controller);
    let asking = tokio::spawn(async move { controller.path(network.id, from, to).await.unwrap() });
    let ToNode::RouteQuery { request, peer } = next_other(&mut asked).await else { panic!("应该收到路由查询") };
    assert_eq!(peer, to);
    let answer = RouteAnswer {
        peer,
        route: Some(Route::Relay { relays: vec![to] }),
        rtt_ms: Some(31),
        since: None,
        detail: None,
        connection_rtt_ms: None,
    };
    asked.send(ToController::RouteAnswer { request, answer }).await;

    let view = timeout(PATIENCE, asking).await.unwrap().unwrap();
    assert_eq!((view.forward.source, view.forward.rtt_ms), (PathSource::Query, Some(31)));
    assert_eq!(view.forward.route, Some(Route::Relay { relays: vec![to] }));
    assert_eq!(view.reverse.source, PathSource::None, "最初那一版的节点不会被问，它也没有上报过");
    assert!(old.stays_quiet(Duration::from_millis(200)).await, "配置已经收敛，它不该再收到任何东西");
    running.shutdown().await;
}
