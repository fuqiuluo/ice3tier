//! 虚拟网卡的包：第一个包之前把连接建起来，直连和经 relay 都通，和数据报上下文互不串门；
//! 只运包的连接在包走的时候不被当作空闲回收，包停了照常回收。
//!
//! 两端都是现在的程序时，包单独加密、不进 QUIC；有一端不认识这种包时照旧走连接的数据报。两种走法上层看不出区别。

// 这个文件里全是测试。clippy.toml 的 allow-unwrap-in-tests 只管 #[test] 函数本身，管不到它们调用的辅助函数。
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{Node, Peer, SOON, View, is_direct};
use i3t_conn::ConnectionCounters;
use i3t_conn::contract::{Datagram, DatagramSendError, DatagramSender, Datagrams, OpenError, PacketSender, Packets};
use i3t_model::control::Route;
use i3t_proto::flow::{DatagramHeader, PacketHeader, Recipient};

/// 一个网络包帧：头后面跟着 `packet`。连接层只看首字节。
fn packet(body: &[u8]) -> Bytes {
    let mut frame = Vec::new();
    PacketHeader::Whole.encode(&mut frame);
    frame.extend_from_slice(body);
    frame.into()
}

async fn next(node: &Node) -> Datagram {
    let mut got = Vec::new();
    let taken = tokio::time::timeout(SOON, node.endpoint.recv_packets(&mut got, 1)).await.expect("等网络包超时");
    assert_eq!(taken, 1, "本端没有关闭");
    got.remove(0)
}

fn pair() -> (Node, Node) {
    let (a, b) = (Node::start(1), Node::start(2));
    a.apply(&View { peers: &[Peer::direct(&b)], ..View::default() });
    b.apply(&View { peers: &[Peer::direct(&a)], ..View::default() });
    (a, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_packet_brings_the_connection_up_and_packets_cross_both_ways() {
    let (a, b) = pair();
    let (from_a, from_b) = (a.endpoint.packet_sender(), b.endpoint.packet_sender());
    assert_eq!(from_a.send_packet(b.id, packet(b"early")), Err(DatagramSendError::NotConnected(b.id)), "包不会自己去建连接");

    tokio::time::timeout(SOON, from_a.connect(b.id)).await.expect("建连接超时").unwrap();
    from_a.send_packet(b.id, packet(b"\x45 to b")).unwrap();
    let got = next(&b).await;
    assert_eq!((got.peer, &got.payload[..]), (a.id, &packet(b"\x45 to b")[..]), "原样送到，带着认证过的发送方");
    // 反方向用对端连进来的同一条连接，不用另外握手。
    tokio::time::timeout(SOON, from_b.connect(a.id)).await.expect("已有连接时立刻返回").unwrap();
    from_b.send_packet(a.id, packet(b"\x45 back")).unwrap();
    assert_eq!(next(&a).await.peer, b.id);

    // 连接现在能带多大的帧，太大的不截断、带着上限退回来，调用方自己切。
    let refused = from_a.send_packet(b.id, packet(&[0; 1400])).unwrap_err();
    assert!(matches!(refused, DatagramSendError::TooLarge { len: 1401, max } if (1100..1400).contains(&max)), "{refused:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packets_and_context_datagrams_never_reach_each_others_queues() {
    let (a, b) = pair();
    let sender = a.endpoint.packet_sender();
    sender.connect(b.id).await.unwrap();
    let mut context = Vec::new();
    DatagramHeader { recipient: Recipient::Acceptor, context: 7, fragment: None }.encode(&mut context);
    context.extend_from_slice(b"for a context");
    a.endpoint.datagram_sender().send_datagram(b.id, context.clone().into()).unwrap();
    sender.send_packet(b.id, packet(b"for the nic")).unwrap();

    let to_context = tokio::time::timeout(SOON, b.endpoint.recv_datagram(Recipient::Acceptor)).await.unwrap().unwrap();
    assert_eq!(&to_context.payload[..], &context[..]);
    assert_eq!(&next(&b).await.payload[..], &packet(b"for the nic")[..]);
    let mut more = Vec::new();
    let late = tokio::time::timeout(Duration::from_millis(200), b.endpoint.recv_packets(&mut more, 8)).await;
    assert!(late.is_err(), "上下文的数据报没有混进网络包里：{more:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_only_carries_packets_stays_while_they_flow_and_goes_when_they_stop() {
    let (a, b) = pair();
    let quick = i3t_conn::Tuning { idle_close: Some(Duration::from_millis(500)), ..i3t_conn::Tuning::default() };
    a.endpoint.tune(quick);
    b.endpoint.tune(quick);
    let sender = a.endpoint.packet_sender();
    sender.connect(b.id).await.unwrap();
    let established = a.endpoint.connection_report(b.id).expect("连接建起来了").established;

    // 包走了两秒，远远超过空闲回收的时间：一条流也没有，连接照样是同一条。
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        sender.send_packet(b.id, packet(b"tick")).unwrap();
        next(&b).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(a.endpoint.connection_report(b.id).map(|report| report.established), Some(established), "包在走，连接一直留着");
    assert!(b.endpoint.connection_report(a.id).is_some(), "收包的一端也不回收");

    // 包停了：两端按空闲回收时间关掉它。
    let deadline = Instant::now() + 3 * SOON;
    while a.endpoint.connection_report(b.id).is_some() || b.endpoint.connection_report(a.id).is_some() {
        assert!(Instant::now() < deadline, "包停了之后连接一直没有回收");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(sender.send_packet(b.id, packet(b"late")), Err(DatagramSendError::NotConnected(b.id)));
}

/// 从 `from` 到 `to` 一个一个地送 `count` 个网络包，每个都等对面收到再送下一个，所以一个包就是一个 QUIC 包
/// （两端的网络包都走数据报时）。返回这期间 `to` 发了多少个包：它没有别的要发，发的都是确认。
async fn acks_for(from: &Node, to: &Node, count: usize) -> u64 {
    let sent = || to.endpoint.connection_report(from.id).expect("连接还在").counters.sent_packets;
    let sender = from.endpoint.packet_sender();
    // 先送一个不算数的：拨号的一端握手完了，对面可能还没有把这条连接登记好。
    sender.send_packet(to.id, packet(b"first")).unwrap();
    next(to).await;
    let before = sent();
    for _ in 0..count {
        sender.send_packet(to.id, packet(b"one way")).unwrap();
        next(to).await;
    }
    sent() - before
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_peer_acknowledges_as_seldom_as_the_network_asks_from_the_next_connection_on() {
    const PACKETS: usize = 300;
    // 数的是 QUIC 的确认，所以网络包要走连接的数据报：封好的包不进 QUIC，对端不为它们发确认。
    let (a, b) = (Node::start_datagram_only(1), Node::start_datagram_only(2));
    b.apply(&View { peers: &[Peer::direct(&a)], ..View::default() });
    // 等待时间取最长的，测的就只是阈值：包一个接一个地到，攒够之前等不满这么久。
    let asking =
        |eliciting_threshold| a.apply(&View { peers: &[Peer::direct(&b)], ack: Some((eliciting_threshold, 25)), ..View::default() });
    let quick = i3t_conn::Tuning { idle_close: Some(Duration::from_millis(500)), ..i3t_conn::Tuning::default() };
    a.endpoint.tune(quick);
    b.endpoint.tune(quick);
    let sender = a.endpoint.packet_sender();

    // 阈值 1 是 QUIC 库自己的做法：每两个包一个确认。
    asking(1);
    tokio::time::timeout(SOON, sender.connect(b.id)).await.expect("建连接超时").unwrap();
    let established = a.endpoint.connection_report(b.id).expect("连接建起来了").established;
    let often = acks_for(&a, &b, PACKETS).await;
    assert!(often >= 100, "每两个包一个确认，{PACKETS} 个包应该有一百多个：{often}");

    // 设置换了，已有的连接还是建立时的那样。
    asking(10);
    let unchanged = acks_for(&a, &b, PACKETS).await;
    assert_eq!(a.endpoint.connection_report(b.id).map(|report| report.established), Some(established), "换设置不动已有的连接");
    assert!(unchanged >= 100, "已有的连接不跟着变：{unchanged}");

    // 等它空闲回收，再建的连接用新的设置：十来个包才一个确认。
    let deadline = Instant::now() + 3 * SOON;
    while a.endpoint.connection_report(b.id).is_some() || b.endpoint.connection_report(a.id).is_some() {
        assert!(Instant::now() < deadline, "包停了之后连接一直没有回收");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::timeout(SOON, sender.connect(b.id)).await.expect("重新建连接超时").unwrap();
    let seldom = acks_for(&a, &b, PACKETS).await;
    assert!(seldom * 2 < often, "新的连接上对端确认得少了：原来 {often} 个，现在 {seldom} 个");
}

/// `from` 到 `to` 的那条连接上，QUIC 自己累计的计数。
fn counters(from: &Node, to: &Node) -> ConnectionCounters {
    from.endpoint.connection_report(to.id).expect("连接还在").counters
}

/// 从 `from` 到 `to` 一个一个地送 `count` 个 1000 字节的网络包，每个都等对面收到。返回这期间两端的连接各自增加的计数。
async fn one_way(from: &Node, to: &Node, count: usize) -> (ConnectionCounters, ConnectionCounters) {
    let sender = from.endpoint.packet_sender();
    tokio::time::timeout(SOON, sender.connect(to.id)).await.expect("建连接超时").unwrap();
    sender.send_packet(to.id, packet(b"first")).unwrap();
    next(to).await;
    let before = (counters(from, to), counters(to, from));
    for _ in 0..count {
        sender.send_packet(to.id, packet(&[0x45; 1000])).unwrap();
        assert_eq!(next(to).await.payload.len(), 1001);
    }
    (counters(from, to).since(before.0), counters(to, from).since(before.1))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packets_between_current_nodes_stay_out_of_the_connection_and_still_count_as_traffic() {
    const PACKETS: usize = 300;
    let (a, b) = pair();
    let (sent, received) = one_way(&a, &b, PACKETS).await;
    // 连接自己这期间只有路径 MTU 的探测和零星的保活：包没有进它，对端也没有为这些包发任何确认。
    assert!(sent.sent_packets < 50, "发的一方的连接只多发了几个包：{sent:?}");
    assert!(received.sent_packets < 50, "收的一方没有为这些包发确认：{received:?}");
    // 流量照样记在这条连接名下。
    let carried = u64::try_from(PACKETS * 1000).unwrap();
    assert!(sent.bytes_sent >= carried && received.bytes_received >= carried, "{sent:?} {received:?}");

    // 包不进连接，连接照样自己把路径 MTU 探测做完，能带的帧跟着变大：网卡上一整个 1280 字节的 IP 包不用切。
    let deadline = Instant::now() + SOON;
    while a.endpoint.connection_report(b.id).expect("连接还在").mtu < i3t_proto::MAX_CONN_PACKET_LEN {
        assert!(Instant::now() < deadline, "连接上只有封好的包在走时，路径 MTU 一直没有探测上去");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    a.endpoint.packet_sender().send_packet(b.id, packet(&[0x45; 1280])).unwrap();
    assert_eq!(next(&b).await.payload.len(), 1281);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_does_not_know_sealed_packets_gets_them_as_datagrams_whoever_dials() {
    const PACKETS: usize = 100;
    for new_dials in [true, false] {
        let (new, old) = (Node::start(1), Node::start_datagram_only(2));
        new.apply(&View { peers: &[Peer::direct(&old)], ..View::default() });
        old.apply(&View { peers: &[Peer::direct(&new)], ..View::default() });
        let (dialer, acceptor) = if new_dials { (&new, &old) } else { (&old, &new) };
        let (sent, _) = one_way(dialer, acceptor, PACKETS).await;
        assert!(sent.sent_packets >= u64::try_from(PACKETS).unwrap(), "包走的是连接的数据报，一个包一个 QUIC 包：{sent:?}");
        // 反方向用同一条连接，也是数据报。
        let (back, _) = one_way(acceptor, dialer, PACKETS).await;
        assert!(back.sent_packets >= u64::try_from(PACKETS).unwrap(), "{back:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_one_way_flow_keeps_its_route_and_costs_the_connection_about_a_packet_a_second() {
    let (a, b) = pair();
    let sender = a.endpoint.packet_sender();
    tokio::time::timeout(SOON, sender.connect(b.id)).await.expect("建连接超时").unwrap();
    a.wait_route(&b, "直连", is_direct).await;
    sender.send_packet(b.id, packet(b"first")).unwrap();
    next(&b).await;
    // 等连接自己的路径 MTU 探测做完，之后它发的就只有"问一下对端还在不在"。
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = (counters(&a, &b), counters(&b, &a));
    // B 一个包都不回：没有任何回程的流量。
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        sender.send_packet(b.id, packet(&[0x45; 200])).unwrap();
        next(&b).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(is_direct(&a.route_to(&b)), "没有回程的包，路也没有被当成断了：{:?}", a.route_to(&b));
    let (asked, answered) = (counters(&a, &b).since(before.0), counters(&b, &a).since(before.1));
    assert!((1..=10).contains(&asked.sent_packets), "三秒里连接替它问了对端几次：{asked:?}");
    assert!(answered.sent_packets <= 10, "对端只回了那几次的确认：{answered:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packets_resume_within_seconds_after_the_peer_crashed_and_came_back() {
    let a = Node::start(1);
    let first = Node::start(2);
    let (key, addr) = (Arc::clone(&first.key), first.addr());
    let directly = |b: &Node| {
        a.apply(&View { peers: &[Peer::direct(b)], ..View::default() });
        b.apply(&View { peers: &[Peer::direct(&a)], ..View::default() });
    };
    directly(&first);
    let sender = a.endpoint.packet_sender();
    tokio::time::timeout(SOON, sender.connect(first.id)).await.expect("建连接超时").unwrap();
    a.wait_route(&first, "直连", is_direct).await;
    sender.send_packet(first.id, packet(b"\x45 before")).unwrap();
    assert_eq!(next(&first).await.peer, a.id);
    // 等连接自己的路径 MTU 探测做完：之后它自己没有东西要发，下一次保活在 15 秒之后。
    tokio::time::sleep(Duration::from_secs(1)).await;
    // 这条路是直连，包是封好了单独发的，不进连接：下面要看的正是这种包没有回音时怎么办。经 relay 的路上包是连接的数据报，
    // 对端重启之后头一个数据报自己就引出重置，走不到那一步。
    let before = counters(&a, &first);
    for _ in 0..20 {
        sender.send_packet(first.id, packet(&[0x45; 200])).unwrap();
        next(&first).await;
    }
    let quiet = counters(&a, &first).since(before);
    assert!(quiet.sent_packets <= 3, "二十个网络包走了，连接自己几乎没有发东西：{quiet:?}");

    // B 崩溃了：一个包也不再发，连关闭帧也没有。然后带着同一把密钥、在原来的地址上回来。
    first.block_all();
    drop(first);
    let back = Node::restart_at(2, key, addr).await;
    directly(&back);

    // A 只管接着发，没有任何回程的包。新的 B 没有那条连接的密钥，这些包它解不开，也不会回什么；A 的连接隔一秒替它问一次，
    // 新的 B 回一个无状态重置，A 这才知道连接没了，不用等 15 秒的保活。
    //
    // 引出重置的还可能是另一样东西：路径层要是察觉了这一下中断，路恢复时会把留底的旧连接包补发一遍。所以这个用例看的是结果
    // （几秒之内恢复），"隔一秒问一次"这件事本身由上面单向流的那个用例盯着（不问的话那里连接一个包都不发）。
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        while sender.send_packet(back.id, packet(b"\x45 into the void")).is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    ended.await.expect("旧连接应该在几秒之内结束，而不是等到保活或者空闲超时");

    // 重建之后照常，旧连接上那些解不开的包一个也没有混进来。
    tokio::time::timeout(3 * SOON, sender.connect(back.id)).await.expect("重新建连接超时").unwrap();
    sender.send_packet(back.id, packet(b"\x45 after")).unwrap();
    assert_eq!(&next(&back).await.payload[..], &packet(b"\x45 after")[..]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packets_cross_a_relay_when_there_is_no_direct_path() {
    let (a, r, b) = (Node::start(1), Node::start(9), Node::start(2));
    a.block(&[&b]);
    r.apply(&View { relay_clients: Some(&[&a, &b]), ..View::default() });
    r.wait_tcp_listening().await;
    a.apply(&View { peers: &[Peer::both(&b, &[&r])], relays: &[&r], ..View::default() });
    b.apply(&View { peers: &[Peer::both(&a, &[&r])], relays: &[&r], ..View::default() });
    let sender = a.endpoint.packet_sender();
    tokio::time::timeout(3 * SOON, sender.connect(b.id)).await.expect("经 relay 建连接超时").unwrap();
    assert_eq!(a.route_to(&b), Route::Relay { relays: vec![r.id] });
    sender.send_packet(b.id, packet(b"via r")).unwrap();
    assert_eq!(next(&b).await.peer, a.id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connecting_to_a_node_that_is_not_a_peer_or_after_closing_fails_plainly() {
    let (a, b) = (Node::start(1), Node::start(2));
    let sender = a.endpoint.packet_sender();
    assert_eq!(sender.connect(b.id).await, Err(OpenError::UnknownPeer(b.id)));
    a.endpoint.close().await;
    assert_eq!(sender.connect(b.id).await, Err(OpenError::Closed));
    let mut got = Vec::new();
    assert_eq!(tokio::time::timeout(SOON, a.endpoint.recv_packets(&mut got, 4)).await.expect("关闭之后不再等"), 0);
}
