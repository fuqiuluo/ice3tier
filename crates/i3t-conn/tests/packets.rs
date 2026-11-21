//! 虚拟网卡的包：第一个包之前把连接建起来，直连和经 relay 都通，和数据报上下文互不串门；
//! 只运包的连接在包走的时候不被当作空闲回收，包停了照常回收。

// 这个文件里全是测试。clippy.toml 的 allow-unwrap-in-tests 只管 #[test] 函数本身，管不到它们调用的辅助函数。
#![allow(clippy::unwrap_used)]

mod common;

use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{Node, Peer, SOON, View};
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

/// 从 `from` 到 `to` 一个一个地送 `count` 个网络包，每个都等对面收到再送下一个，所以一个包就是一个 QUIC 包。
/// 返回这期间 `to` 发了多少个包：它没有别的要发，发的都是确认。
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
    let (a, b) = (Node::start(1), Node::start(2));
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
