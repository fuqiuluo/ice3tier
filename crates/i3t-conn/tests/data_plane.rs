//! 数据面的集成测试：几个节点在同一个进程里，都绑在回环地址上，netmap 由测试直接给。
//! 每个测试说的是上层看得到的行为：流通不通、换路时数据丢不丢、该拒绝的有没有拒绝。

// 这个文件里全是测试。clippy.toml 的 allow-unwrap-in-tests 只管 #[test] 函数本身，管不到它们调用的辅助函数。
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Node, Peer, SOON, Transfer, View, drain_reasons, echo_once, is_direct, is_none, is_relay};
use i3t_conn::{Acceptor, Connector, DropReason, OpenError};
use i3t_model::control::Route;
use i3t_model::netmap::Congestion;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 断言"这件事不会发生"时观察多久。
const QUIET: Duration = Duration::from_millis(1500);

fn megabyte() -> Vec<u8> {
    (0..1024 * 1024u32).map(|index| u8::try_from(index % 251).unwrap()).collect()
}

/// A、B 都挂靠在 relay R 上。`know_endpoints` 决定它们的 netmap 里有没有对方的地址。
async fn through_relay(a: &Node, r: &Node, b: &Node, know_endpoints: bool, reach: Option<&'static str>) {
    r.apply(&View { relay_clients: Some(&[a, b]), ..View::default() });
    r.wait_tcp_listening().await;
    let peer = |node| if know_endpoints { Peer::both(node, std::slice::from_ref(&r)) } else { Peer::via(node, std::slice::from_ref(&r)) };
    a.apply(&View { peers: &[peer(b)], relays: &[r], reach, ..View::default() });
    b.apply(&View { peers: &[peer(a)], relays: &[r], reach, ..View::default() });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_with_known_endpoints_exchange_a_stream_directly() {
    let (a, b) = (Node::start(1), Node::start(2));
    a.apply(&View { peers: &[Peer::direct(&b)], ..View::default() });
    b.apply(&View { peers: &[Peer::direct(&a)], ..View::default() });
    a.spawn_echo();
    b.spawn_echo();

    // 一条流的两个方向都正常结束：写的一头 shutdown，读的一头读到 EOF。
    echo_once(&a, &b, &megabyte()).await;
    assert_eq!(a.route_to(&b), Route::Direct { addr: b.addr() });
    assert_eq!(b.route_to(&a), Route::Direct { addr: a.addr() });
    assert!(a.endpoint.routes()[0].rtt_ms.is_some());

    // 反方向在同一条连接上开流，不用再握手。
    echo_once(&b, &a, b"the other way").await;
    assert_eq!(a.endpoint.endpoints(), [a.addr()], "绑定在具体地址上时，候选端点就是它");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_works_through_a_relay_over_udp_when_there_is_no_direct_path() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    a.block(&[&b]);
    through_relay(&a, &r, &b, true, None).await;
    b.spawn_echo();

    echo_once(&a, &b, &megabyte()).await;
    assert_eq!(a.route_to(&b), Route::Relay { relays: vec![r.id] });
    assert_eq!(b.route_to(&a), Route::Relay { relays: vec![r.id] });
    let counters = r.endpoint.relay_counters();
    assert!(counters.forwarded_bytes > 2 * 1024 * 1024, "一兆字节来回各一次都经过 relay：{counters:?}");
    assert_eq!(counters.sessions, 2);
    assert_eq!(a.endpoint.attached().iter().map(|attachment| attachment.relay).collect::<Vec<_>>(), [r.id]);
    // relay 把它看到的地址告诉了节点。
    assert_eq!(a.endpoint.endpoints(), [a.addr()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_works_with_one_node_attached_to_the_relay_over_tcp() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    // A 的 UDP 完全用不了：到 relay 的、到 B 的都不通。
    a.block(&[&b, &r]);
    let mut changes = a.endpoint.route_changes();
    through_relay(&a, &r, &b, true, None).await;
    b.spawn_echo();

    echo_once(&a, &b, &megabyte()).await;
    assert_eq!(a.route_to(&b), Route::Relay { relays: vec![r.id] });
    let reasons = drain_reasons(&mut changes, &b);
    assert!(reasons.iter().any(|reason| reason.contains("TCP")), "A 应该是经 TCP 挂到 relay 上的：{reasons:?}");
    assert_eq!(a.endpoint.mapping_varies(), None, "TCP 上看到的地址不算 UDP 的反射地址");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_works_with_both_nodes_attached_to_the_relay_over_tcp() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    a.block(&[&b, &r]);
    b.block(&[&a, &r]);
    through_relay(&a, &r, &b, true, None).await;
    a.spawn_echo();
    b.spawn_echo();

    echo_once(&a, &b, &megabyte()).await;
    echo_once(&b, &a, &megabyte()).await;
    assert!(is_relay(&a.route_to(&b)) && is_relay(&b.route_to(&a)));
    // 回环上连接发得比那条 TCP 的队列消化得快，队列满了就丢（这正是要它做的事），数据靠两端的连接重传补齐。
    let counters = r.endpoint.relay_counters();
    assert!(counters.forwarded_bytes > 4 * 1024 * 1024, "{counters:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_on_tcp_switches_back_to_udp_when_udp_works_again() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    a.block(&[&b, &r]);
    let mut changes = a.endpoint.route_changes();
    through_relay(&a, &r, &b, false, Some("relay_only")).await;
    b.spawn_echo();
    let transfer = Transfer::start(&a, &b, 200).await;
    transfer.expect_progress(100).await;
    assert!(drain_reasons(&mut changes, &b).iter().any(|reason| reason.contains("TCP")));

    // UDP 恢复了。走着 TCP 的节点每 30 秒才再试一次 UDP，测试等不了那么久；让 relay 掉一次会话，重连时 UDP 和 TCP 会重新比一次。
    a.unblock();
    r.apply(&View::default());
    tokio::time::sleep(Duration::from_millis(300)).await;
    r.apply(&View { relay_clients: Some(&[&a, &b]), ..View::default() });
    let started = Instant::now();
    loop {
        if drain_reasons(&mut changes, &b).iter().any(|reason| reason.contains("UDP")) {
            break;
        }
        assert!(started.elapsed() < 3 * SOON, "UDP 通了之后应该改回 UDP");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    transfer.expect_progress(100).await;
    transfer.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_route_switches_from_relay_to_direct_under_a_running_stream_without_losing_data() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    a.block(&[&b]);
    through_relay(&a, &r, &b, true, None).await;
    b.spawn_echo();
    let mut changes = a.endpoint.route_changes();

    let transfer = Transfer::start(&a, &b, 500).await;
    transfer.expect_progress(300).await;
    assert!(is_relay(&a.route_to(&b)) && is_relay(&b.route_to(&a)));

    // 直连打通了。
    a.unblock();
    a.wait_route(&b, "直连", is_direct).await;
    b.wait_route(&a, "直连", is_direct).await;
    // 换路的那一刻还有几个包在经 relay 的路上，等它们走完再数。
    transfer.expect_progress(200).await;
    let forwarded = r.endpoint.relay_counters().forwarded_packets;
    transfer.expect_progress(1000).await;
    assert_eq!(r.endpoint.relay_counters().forwarded_packets, forwarded, "改走直连之后包不再经过 relay");

    let blocks = transfer.finish().await;
    assert!(blocks > 1500);
    let reasons = drain_reasons(&mut changes, &b);
    assert!(reasons.iter().any(|reason| reason.contains("验证通过")), "{reasons:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_direct_path_falls_back_to_the_relay_and_the_stream_survives() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    through_relay(&a, &r, &b, true, None).await;
    b.spawn_echo();
    let transfer = Transfer::start(&a, &b, 500).await;
    a.wait_route(&b, "直连", is_direct).await;
    b.wait_route(&a, "直连", is_direct).await;
    transfer.expect_progress(300).await;
    let mut changes = a.endpoint.route_changes();

    // 直连断了，到 relay 的路还在。
    a.block(&[&b]);
    a.wait_route(&b, "经 relay", is_relay).await;
    b.wait_route(&a, "经 relay", is_relay).await;
    let stall = transfer.expect_progress(500).await;
    println!("直连断开之后，数据恢复流动用了 {stall:?}");
    transfer.finish().await;

    let reasons = drain_reasons(&mut changes, &b);
    assert!(reasons.iter().any(|reason| reason.contains("直连探测连续超时") && reason.contains("退回对端挂靠的 relay")), "{reasons:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stream_survives_when_every_route_dies_for_a_few_seconds() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    through_relay(&a, &r, &b, true, None).await;
    b.spawn_echo();
    let transfer = Transfer::start(&a, &b, 500).await;
    a.wait_route(&b, "直连", is_direct).await;
    transfer.expect_progress(300).await;

    // A 的网络整个断掉：直连和 relay 都不通。
    a.block_all();
    tokio::time::sleep(Duration::from_secs(4)).await;
    let before = transfer.verified();
    a.unblock();
    let recovery = transfer.expect_progress(200).await;
    println!("所有的路断了 4 秒，恢复之后 {recovery:?} 数据重新流动（断开前核对到第 {before} 块）");
    // 连接自己的重传定时器这时已经退避到几秒一次；路径层在路恢复时补发最后几个包，不用等它。
    assert!(recovery < Duration::from_millis(2500), "路恢复之后数据应该很快重新流动，实际用了 {recovery:?}");
    transfer.expect_progress(1000).await;
    transfer.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_disabled_in_the_netmap_stops_forwarding() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    through_relay(&a, &r, &b, false, Some("relay_only")).await;
    b.spawn_echo();
    let transfer = Transfer::start(&a, &b, 500).await;
    transfer.expect_progress(300).await;

    // 管理员在 netmap 里去掉了 R 的 relay 角色。
    r.apply(&View::default());
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (forwarded, verified) = (r.endpoint.relay_counters().forwarded_packets, transfer.verified());
    tokio::time::sleep(QUIET).await;
    let counters = r.endpoint.relay_counters();
    assert_eq!(counters.forwarded_packets, forwarded, "停用之后一个包都不该再转发");
    assert_eq!(transfer.verified(), verified, "数据不该再流动");
    assert!(counters.dropped(DropReason::Disabled) > 0);
    assert_eq!(counters.sessions, 0);
    // 节点这边发现会话没了，这对节点之间没有路了。
    a.wait_route(&b, "没有路", is_none).await;

    // 重新启用：节点重新握手，流接着传。它一直没有断，因为中断没有超过连接的空闲超时。
    r.apply(&View { relay_clients: Some(&[&a, &b]), ..View::default() });
    transfer.expect_progress(500).await;
    transfer.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_peer_from_the_netmap_closes_its_connection_and_refuses_new_dials() {
    let (a, b) = (Node::start(1), Node::start(2));
    a.apply(&View { peers: &[Peer::direct(&b)], ..View::default() });
    b.apply(&View { peers: &[Peer::direct(&a)], ..View::default() });
    b.spawn_echo();
    let (mut send, mut recv) = a.endpoint.open(b.id).await.unwrap();
    send.write_all(b"before").await.unwrap();
    let mut echoed = [0u8; 6];
    recv.read_exact(&mut echoed).await.unwrap();

    // B 被吊销：A 的 netmap 里没有它了。
    a.apply(&View::default());
    let error = tokio::time::timeout(SOON, recv.read(&mut echoed)).await.expect("连接应该立刻关闭").expect_err("流不该正常结束");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted, "{error}");
    assert_eq!(a.endpoint.open(b.id).await.unwrap_err(), OpenError::UnknownPeer(b.id));
    tokio::time::timeout(SOON, async {
        while !a.endpoint.routes().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("路由表里不该还有被去掉的对端");

    // 被吊销的一方再怎么发也进不来：它的包在 A 那里没有人认。它自己那边的连接要到空闲超时才知道断了，
    // 所以它开流可能"成功"，但 A 这边什么都收不到。
    let from_revoked = tokio::spawn({
        let endpoint = Arc::clone(&b.endpoint);
        let target = a.id;
        async move {
            if let Ok((mut send, _recv)) = endpoint.open(target).await {
                let _unacknowledged = send.write_all(b"let me in").await;
                tokio::time::sleep(2 * QUIET).await;
            }
        }
    });
    assert!(tokio::time::timeout(QUIET, a.endpoint.accept()).await.is_err(), "被吊销的节点开过来的流不该到达上层");
    from_revoked.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_begun_under_a_peers_old_key_leaves_no_connection_once_the_key_has_changed() {
    let (a, r, old) = (Node::start(1), Node::start(9), Node::start(2));
    // 同一个编号、另一把密钥：换了密钥之后 netmap 里的 2 号。它自己不上线，只出一把公钥。
    let new = Node::start(2);
    r.apply(&View { relay_clients: Some(&[&a, &old]), ..View::default() });
    r.wait_tcp_listening().await;
    // 拿着旧密钥的那一个还挂在 relay 上，也还认 A。
    old.apply(&View { peers: &[Peer::via(&a, &[&r])], relays: &[&r], ..View::default() });

    // A 认得 2 号（旧密钥），但到它还没有路：拨号读完 netmap 之后停在等路上。
    a.apply(&View { peers: &[Peer { endpoints: false, ..Peer::direct(&old) }], ..View::default() });
    let dialing = tokio::spawn({
        let endpoint = Arc::clone(&a.endpoint);
        let peer = old.id;
        async move { endpoint.open(peer).await.map(drop) }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // netmap 变了：2 号换了公钥，同时有了经 relay 的路。拨号接着拿开始时读到的旧公钥去握手，和拿旧密钥的那一个握得成。
    a.apply(&View { peers: &[Peer::via(&new, &[&r])], relays: &[&r], ..View::default() });
    let outcome = tokio::time::timeout(SOON, dialing).await.expect("拨号迟迟不结束").unwrap();
    assert!(matches!(outcome, Err(OpenError::ConnectionLost { .. })), "{outcome:?}");
    assert_eq!(a.endpoint.connection_rtt(new.id), None, "拿旧公钥握成的连接不该算成 2 号的连接");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_that_do_not_know_each_others_addresses_find_a_direct_path_through_in_band_signals() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    // netmap 里没有对方的端点，也没有人替它们转信令：只能靠已经建好的连接。
    through_relay(&a, &r, &b, false, None).await;
    b.spawn_echo();
    // 第一条流不等直连，先经 relay：没有连接就没有信令，这时直连还不可能有。先看到经 relay 的路再开流；
    // 开了流再看就晚了，机器忙的时候带内的信令可能已经把直连打通。
    a.wait_route(&b, "经 relay", is_relay).await;
    let transfer = Transfer::start(&a, &b, 200).await;

    a.wait_route(&b, "直连", is_direct).await;
    b.wait_route(&a, "直连", is_direct).await;
    transfer.expect_progress(200).await;
    transfer.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_relay_the_first_stream_waits_for_hole_punching_coordinated_by_the_signal_hook() {
    let (a, b) = (Arc::new(Node::start(1)), Arc::new(Node::start(2)));
    let unknown = |node| Peer { endpoints: false, ..Peer::direct(node) };
    a.apply(&View { peers: &[unknown(&b)], ..View::default() });
    b.apply(&View { peers: &[unknown(&a)], ..View::default() });
    b.spawn_echo();

    // 没有信令通道时：谁也不知道对方在哪里，5 秒的时限之内等不到路。
    let started = Instant::now();
    assert_eq!(a.endpoint.open(b.id).await.unwrap_err(), OpenError::NoRoute(b.id));
    assert!((Duration::from_secs(4)..Duration::from_secs(7)).contains(&started.elapsed()), "{:?}", started.elapsed());

    // 装配方把信令经 controller 的通道转给对端。这里直接交过去。
    let (to_b, from_a) = (Arc::clone(&b), a.id);
    a.endpoint.set_signal_hook(move |to, signal| {
        assert_eq!(to, to_b.id);
        to_b.endpoint.deliver_signal(from_a, signal.clone());
    });
    let (to_a, from_b) = (Arc::clone(&a), b.id);
    b.endpoint.set_signal_hook(move |to, signal| {
        assert_eq!(to, to_a.id);
        to_a.endpoint.deliver_signal(from_b, signal.clone());
    });
    echo_once(&a, &b, b"punched").await;
    assert!(is_direct(&a.route_to(&b)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reach_settings_restrict_which_routes_are_used() {
    // relay-only：知道对方的地址也不建立直连，不向对端暴露自己的地址。
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    through_relay(&a, &r, &b, true, Some("relay_only")).await;
    b.spawn_echo();
    let transfer = Transfer::start(&a, &b, 200).await;
    tokio::time::sleep(QUIET).await;
    assert!(is_relay(&a.route_to(&b)) && is_relay(&b.route_to(&a)));
    assert!(a.endpoint.endpoints().is_empty());
    transfer.finish().await;

    // direct-only：直连不通时宁可没有路，也不经 relay。
    let (c, r2, d) = (Node::start(3), Node::start(8), Node::start(4));
    c.block(&[&d]);
    through_relay(&c, &r2, &d, true, Some("direct_only")).await;
    assert_eq!(c.endpoint.open(d.id).await.unwrap_err(), OpenError::NoRoute(d.id));
    assert_eq!(r2.endpoint.relay_counters().sessions_opened, 0, "不使用 relay 的节点也不去挂靠");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_out_only_node_cannot_be_dialled_but_its_own_connection_is_reused() {
    let (a, b) = (Node::start(1), Node::start(2));
    a.apply(&View { peers: &[Peer { dial_out_only: true, ..Peer::direct(&b) }], ..View::default() });
    b.apply(&View { peers: &[Peer::direct(&a)], dial_out_only: true, ..View::default() });
    a.spawn_echo();
    b.spawn_echo();

    let started = Instant::now();
    assert_eq!(a.endpoint.open(b.id).await.unwrap_err(), OpenError::NoRoute(b.id));
    assert!(started.elapsed() < Duration::from_secs(1), "只主动连接的对端连不进去，不用等满时限");

    // 它连过来之后，反方向的流走它建的那条连接。
    echo_once(&b, &a, b"dialled out").await;
    echo_once(&a, &b, b"reusing the inbound connection").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_sides_dialling_at_the_same_time_both_get_their_streams() {
    let (a, b) = (Node::start(1), Node::start(2));
    a.apply(&View { peers: &[Peer::direct(&b)], ..View::default() });
    b.apply(&View { peers: &[Peer::direct(&a)], ..View::default() });
    a.spawn_echo();
    b.spawn_echo();
    let payload = megabyte();
    tokio::join!(echo_once(&a, &b, &payload), echo_once(&b, &a, &payload));
    tokio::join!(echo_once(&a, &b, b"again"), echo_once(&b, &a, b"again"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_whose_udp_is_blocked_reaches_a_peer_that_is_itself_a_relay_over_tcp() {
    // R 有公网端口并启用为 relay，A 的 UDP 用不了。A 用一条 TCP 连到 R，R 本身就是目的地。
    let (a, r) = (Node::start(1), Node::start(9));
    a.block(&[&r]);
    r.apply(&View { peers: &[Peer { endpoints: false, ..Peer::direct(&a) }], relay_clients: Some(&[&a]), ..View::default() });
    a.apply(&View { peers: &[Peer::direct(&r)], relays: &[&r], ..View::default() });
    a.spawn_echo();
    r.spawn_echo();

    echo_once(&a, &r, &megabyte()).await;
    echo_once(&r, &a, &megabyte()).await;
    assert_eq!(a.route_to(&r), Route::Relay { relays: vec![r.id] });
    assert_eq!(r.route_to(&a), Route::Relay { relays: vec![r.id] }, "R 经它自己的 relay 会话把包送给 A");
    assert_eq!(r.endpoint.relay_counters().forwarded_packets, 0, "这是 R 自己的流量，不算转发");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_an_endpoint_ends_accept_and_fails_new_streams() {
    let (a, b) = (Node::start(1), Node::start(2));
    a.apply(&View { peers: &[Peer::direct(&b)], ..View::default() });
    b.apply(&View { peers: &[Peer::direct(&a)], ..View::default() });
    b.spawn_echo();
    echo_once(&a, &b, b"hello").await;

    let accepting = {
        let endpoint = Arc::clone(&a.endpoint);
        tokio::spawn(async move { endpoint.accept().await.is_none() })
    };
    a.endpoint.close().await;
    assert!(tokio::time::timeout(SOON, accepting).await.expect("关闭之后 accept 应该返回").unwrap());
    assert_eq!(a.endpoint.open(b.id).await.unwrap_err(), OpenError::Closed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_learns_its_reflexive_address_from_its_relay_and_from_an_address_query_server() {
    // 另一个启用了 relay 的节点充当地址查询的服务器（产品里是 controller 的那个 UDP 端口）。
    let server = Node::start(8);
    server.apply(&View { relay_clients: Some(&[]), ..View::default() });
    let (a, r) = (Node::start_with(1, &[server.addr()]), Node::start(9));
    assert_eq!(a.endpoint.mapping_varies(), None, "还没有任何观察点");
    r.apply(&View { relay_clients: Some(&[&a]), ..View::default() });
    a.apply(&View { relays: &[&r], ..View::default() });

    // 两个观察点（relay 的会话、地址查询）看到的是同一个地址：映射出来的端口不随对端变化。
    tokio::time::timeout(SOON, async {
        while a.endpoint.mapping_varies().is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("两个观察点都应该有回答");
    assert_eq!(a.endpoint.mapping_varies(), Some(false));
    assert_eq!(a.endpoint.endpoints(), [a.addr()]);
    let attached = a.endpoint.attached();
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].relay, r.id);
    assert!(attached[0].rtt_ms >= 1);
}

/// 两个 relay（R1、R2）互为对端、互相挂靠，节点 A 挂靠在两个上面。每个 relay 的挂靠表里只有另一个 relay，
/// A 的挂靠表里 R1 排在前面。`tcp_only` 时 A 的 UDP 完全用不了，到两个 relay 都是 TCP。
///
/// 这是真实网络里出过问题的布局：照着挂靠表选的话，A 到 R2 会绕 R1，R2 到 A 也会绕 R1，
/// 而 A 明明和 R2 之间就有一个中转会话。
async fn relay_peers_are_reached_without_a_detour(tcp_only: bool) {
    let (a, r1, r2) = (Node::start(1), Node::start(8), Node::start(9));
    // UDP 通的那一轮禁用直连，这样看到的一定是 relay 路径的选择；TCP 那一轮 UDP 本来就不通。
    let reach = if tcp_only { None } else { Some("relay_only") };
    if tcp_only {
        a.block(&[&r1, &r2]);
    }
    let mut a_changes = a.endpoint.route_changes();
    let mut r2_changes = r2.endpoint.route_changes();

    r1.apply(&View {
        peers: &[Peer::via(&a, &[&r1, &r2]), Peer::via(&r2, &[&r1])],
        relays: &[&r1, &r2],
        relay_clients: Some(&[&a, &r2]),
        reach,
        ..View::default()
    });
    r2.apply(&View {
        peers: &[Peer::via(&a, &[&r1, &r2]), Peer::via(&r1, &[&r2])],
        relays: &[&r1, &r2],
        relay_clients: Some(&[&a, &r1]),
        reach,
        ..View::default()
    });
    r1.wait_tcp_listening().await;
    r2.wait_tcp_listening().await;
    a.apply(&View { peers: &[Peer::via(&r1, &[&r2]), Peer::via(&r2, &[&r1])], relays: &[&r1, &r2], reach, ..View::default() });
    a.spawn_echo();
    r1.spawn_echo();
    r2.spawn_echo();

    // 对端自己就是 relay：经到它的会话直接送达，不管它的挂靠表里写的是谁。
    let via = |relay: &Node| Route::Relay { relays: vec![relay.id] };
    a.wait_route(&r2, "经 R2 自己", |route| *route == via(&r2)).await;
    a.wait_route(&r1, "经 R1 自己", |route| *route == via(&r1)).await;
    // 反过来：对端挂在本节点的 relay 上，就用那个会话，哪怕它的挂靠表里别的 relay 排在前面。
    r2.wait_route(&a, "经 R2 自己的 relay", |route| *route == via(&r2)).await;
    r1.wait_route(&a, "经 R1 自己的 relay", |route| *route == via(&r1)).await;

    let forwarded = |relay: &Node| relay.endpoint.relay_counters().forwarded_packets;
    let before = (forwarded(&r1), forwarded(&r2));
    echo_once(&a, &r2, &megabyte()).await;
    echo_once(&r2, &a, &megabyte()).await;
    echo_once(&a, &r1, b"and the other relay").await;
    assert_eq!((forwarded(&r1), forwarded(&r2)), before, "这些流量没有经过第三个节点转发");
    assert_eq!((a.route_to(&r2), r2.route_to(&a)), (via(&r2), via(&r2)));

    let reasons = drain_reasons(&mut a_changes, &r2);
    assert!(reasons.iter().any(|reason| reason.contains("对端自己的 relay")), "{reasons:?}");
    if tcp_only {
        assert!(reasons.iter().any(|reason| reason.contains("TCP")), "{reasons:?}");
    }
    let reasons = drain_reasons(&mut r2_changes, &a);
    assert!(reasons.iter().any(|reason| reason.contains("本节点自己的 relay")), "{reasons:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_is_itself_a_relay_is_reached_through_the_session_with_it_not_through_the_relay_it_lists() {
    relay_peers_are_reached_without_a_detour(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_without_udp_reaches_relay_peers_over_its_tcp_session_with_them_not_through_another_relay() {
    relay_peers_are_reached_without_a_detour(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_ends_use_the_pairs_congestion_control_and_a_change_applies_to_the_next_connection() {
    let (a, b) = (Node::start(1), Node::start(2));
    let cubic = |node| Peer { congestion: Some("cubic"), ..Peer::direct(node) };
    a.apply(&View { peers: &[cubic(&b)], ..View::default() });
    b.apply(&View { peers: &[cubic(&a)], ..View::default() });
    let _echo = b.spawn_echo();
    echo_once(&a, &b, b"over cubic").await;
    assert_eq!(a.endpoint.congestion(b.id), Congestion::Cubic, "拨出的一方按节点对的设置");
    assert_eq!(b.endpoint.congestion(a.id), Congestion::Cubic, "接受连接的一方也按节点对的设置，管它自己发出的方向");

    // 改回默认：已经建立的连接不换，空闲回收之后新建的连接才用默认的。
    let quick = i3t_conn::Tuning { idle_close: Some(Duration::from_millis(500)), ..i3t_conn::Tuning::default() };
    a.apply(&View { peers: &[Peer::direct(&b)], ..View::default() });
    b.apply(&View { peers: &[Peer::direct(&a)], ..View::default() });
    a.wait_knows(&b).await;
    assert_eq!(a.endpoint.congestion(b.id), Congestion::Cubic, "已有的连接不换拥塞控制");
    a.endpoint.tune(quick);
    b.endpoint.tune(quick);
    let deadline = Instant::now() + 3 * SOON;
    while a.endpoint.congestion(b.id) != Congestion::Bbr || b.endpoint.congestion(a.id) != Congestion::Bbr {
        assert!(Instant::now() < deadline, "空闲的连接一直没有被回收");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    echo_once(&a, &b, b"over bbr").await;
    assert_eq!((a.endpoint.congestion(b.id), b.endpoint.congestion(a.id)), (Congestion::Bbr, Congestion::Bbr));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_peer_shows_its_open_flows_and_the_traffic_of_its_connections() {
    let (a, b) = (Node::start(1), Node::start(2));
    a.apply(&View { peers: &[Peer::direct(&b)], ..View::default() });
    b.apply(&View { peers: &[Peer::direct(&a)], ..View::default() });
    let _echo = b.spawn_echo();
    assert!(a.endpoint.peer_use().is_empty(), "还没有连接");

    let (mut send, mut recv) = tokio::time::timeout(SOON, a.endpoint.open(b.id)).await.expect("开流超时").unwrap();
    send.write_all(&[7; 100_000]).await.unwrap();
    let mut echoed = vec![0; 100_000];
    recv.read_exact(&mut echoed).await.unwrap();
    let used = a.endpoint.peer_use();
    assert_eq!(used.len(), 1);
    assert_eq!((used[0].peer, used[0].flows), (b.id, 1), "开着的这条流");
    assert!(used[0].tx_bytes >= 100_000 && used[0].rx_bytes >= 100_000, "{used:?}");

    // 流结束之后（两半都放下了）不再算。
    send.shutdown().await.unwrap();
    let mut rest = Vec::new();
    recv.read_to_end(&mut rest).await.unwrap();
    drop((send, recv));
    let deadline = Instant::now() + SOON;
    while a.endpoint.peer_use()[0].flows != 0 {
        assert!(Instant::now() < deadline, "结束的流一直还算着");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(b.endpoint.peer_use()[0].rx_bytes >= 100_000, "另一端也数得到");
}
