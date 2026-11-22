//! relay 的行为测试：真的 UDP 端口和 TCP 连接，都在回环上。节点一侧用最原始的 socket 手写握手，
//! 这样测到的是线上的字节，不是另一份实现的理解。

// 这个文件里全是测试。clippy.toml 的 allow-unwrap-in-tests 只管 #[test] 函数本身，管不到它们调用的辅助函数。
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use common::{Client, RELAY_ID, Role, SILENCE, TcpClient, TestRelay, WAIT, node, relayed, verified_row};
use i3t_crypto::NodeKey;
use i3t_proto::Datagram;
use i3t_proto::backbone::RelayState;
use i3t_proto::session::{Auth, Frame, Init, Ping, Pong, RefusalReason, Refused};
use i3t_relay::DropReason;
use tokio::net::{TcpStream, UdpSocket};

#[tokio::test]
async fn the_handshake_opens_a_session_and_ping_reports_the_observed_address() {
    let client = Client::new(1).await;
    let relay = TestRelay::start(&[&client]);

    let ok = client.attach(&relay).await;
    assert_eq!(ok.observed, client.addr());
    assert!(ok.valid_for >= 15, "有效期要比保活间隔长得多：{}", ok.valid_for);
    assert!(relay.relay().has_session(client.id));
    assert!(relay.relay().session_at(client.id, client.addr()));
    assert!(!relay.relay().session_at(client.id, "127.0.0.1:9".parse().unwrap()));

    let ping = Ping { node: client.id, nonce: [7; 8] };
    client.send(&ping.to_bytes(), &relay).await;
    let reply = client.recv().await;
    assert!(reply.len() <= Ping::LEN, "PONG 不能比 PING 大");
    assert_eq!(Frame::parse(&reply), Some(Frame::Pong(Pong { nonce: [7; 8], observed: client.addr() })));

    let counters = relay.relay().counters();
    assert_eq!((counters.sessions, counters.sessions_opened), (1, 1));
}

#[tokio::test]
async fn relayed_frames_reach_the_destination_byte_for_byte() {
    let (a, b) = (Client::new(1).await, Client::new(2).await);
    let relay = TestRelay::start(&[&a, &b]);
    a.attach(&relay).await;
    b.attach(&relay).await;

    let to_b = relayed(b.id, a.id, &[0x40; 1200]);
    a.send(&to_b, &relay).await;
    assert_eq!(b.recv().await, to_b);

    let to_a = relayed(a.id, b.id, b"");
    b.send(&to_a, &relay).await;
    assert_eq!(a.recv().await, to_a, "只有中转头的帧也照转");

    let counters = relay.relay().counters();
    assert_eq!(counters.forwarded_packets, 2);
    assert_eq!(counters.forwarded_bytes, u64::try_from(to_b.len() + to_a.len()).unwrap());
    assert_eq!(counters.dropped_total(), 0);
}

#[tokio::test]
async fn a_sender_without_a_session_is_refused_with_a_rate_limited_error() {
    let (a, b, stranger) = (Client::new(1).await, Client::new(2).await, Client::new(3).await);
    let relay = TestRelay::start(&[&a, &b, &stranger]);
    b.attach(&relay).await;

    // stranger 在名单里，但没有握过手。
    let frame = relayed(b.id, stranger.id, b"payload");
    stranger.send(&frame, &relay).await;
    let reply = stranger.recv().await;
    assert!(reply.len() <= frame.len(), "错误帧不能比引出它的帧大");
    assert_eq!(Frame::parse(&reply), Some(Frame::Error(Refused { reason: RefusalReason::NoSession, node: stranger.id })));
    assert_eq!(Refused::echo(&reply), Some(*b"payload\0"), "回显去掉中转头之后的前 8 个字节，不够的补 0");

    // 紧接着再发：照样不转发，但这一秒里不再回错误帧。
    stranger.send(&frame, &relay).await;
    stranger.expect_silence().await;
    b.expect_silence().await;
    assert_eq!(relay.relay().counters().dropped(DropReason::NoSession), 2);
    assert_eq!(relay.relay().counters().forwarded_packets, 0);

    // 没有会话时的 PING 也是同样的回答，回显 PING 的随机数。
    a.send(&Ping { node: a.id, nonce: [1; 8] }.to_bytes(), &relay).await;
    let reply = a.recv().await;
    assert_eq!(Frame::parse(&reply), Some(Frame::Error(Refused { reason: RefusalReason::NoSession, node: a.id })));
    assert_eq!(Refused::echo(&reply), Some([1; 8]));
}

#[tokio::test]
async fn a_relayed_frame_shorter_than_an_error_gets_no_error() {
    let (a, b) = (Client::new(1).await, Client::new(2).await);
    let relay = TestRelay::start(&[&a, &b]);
    let short = relayed(b.id, a.id, b"tiny");
    assert!(short.len() < Refused::LEN);
    a.send(&short, &relay).await;
    a.expect_silence().await;
    assert_eq!(relay.relay().counters().dropped(DropReason::NoSession), 1, "照样不转发，只是不回应");
    // 长一个字节就够了。
    a.send(&relayed(b.id, a.id, b"tiny!"), &relay).await;
    assert!(Refused::echo(&a.recv().await).is_some());
}

#[tokio::test]
async fn a_refused_keepalive_is_answered_even_right_after_a_refused_relayed_frame() {
    let (a, b) = (Client::new(1).await, Client::new(2).await);
    let relay = TestRelay::start(&[&a, &b]);
    // 节点以为自己有会话（relay 重启过）：中转帧引出一个错误帧，节点马上发 PING 核实，relay 对 PING 的回答不能被压下去。
    a.send(&relayed(b.id, a.id, &[0x41; 1200]), &relay).await;
    assert!(Refused::echo(&a.recv().await).is_some());
    a.send(&Ping { node: a.id, nonce: [9; 8] }.to_bytes(), &relay).await;
    let reply = a.recv().await;
    assert_eq!(Frame::parse(&reply), Some(Frame::Error(Refused { reason: RefusalReason::NoSession, node: a.id })));
    assert_eq!(Refused::echo(&reply), Some([9; 8]));
    // 接着再来一个 PING：这一秒里不再回。
    a.send(&Ping { node: a.id, nonce: [10; 8] }.to_bytes(), &relay).await;
    a.expect_silence().await;
}

#[tokio::test]
async fn a_spoofed_source_node_is_refused() {
    let (a, b, victim) = (Client::new(1).await, Client::new(2).await, Client::new(3).await);
    let relay = TestRelay::start(&[&a, &b, &victim]);
    a.attach(&relay).await;
    b.attach(&relay).await;
    victim.attach(&relay).await;

    // a 有自己的会话，但想冒 victim 的名字给 b 发包：数据报不是从 victim 的会话绑定的地址来的。
    a.send(&relayed(b.id, victim.id, b"forged"), &relay).await;
    assert_eq!(Frame::parse(&a.recv().await), Some(Frame::Error(Refused { reason: RefusalReason::NoSession, node: victim.id })));
    b.expect_silence().await;
    assert_eq!(relay.relay().counters().dropped(DropReason::NoSession), 1);
}

#[tokio::test]
async fn frames_for_a_destination_without_a_session_are_refused() {
    let (a, b) = (Client::new(1).await, Client::new(2).await);
    let relay = TestRelay::start(&[&a, &b]);
    let ok = a.attach(&relay).await;

    a.send(&relayed(b.id, a.id, b"anyone there"), &relay).await;
    let reply = a.recv().await;
    assert_eq!(Frame::parse(&reply), Some(Frame::Error(Refused { reason: RefusalReason::PeerUnattached, node: b.id })));
    assert_eq!(Refused::echo(&reply), Some(ok.nonce), "回显会话握手时节点给的随机数：伪造来源地址的人不知道它");
    assert_eq!(relay.relay().counters().dropped(DropReason::PeerUnattached), 1);
}

#[tokio::test]
async fn bad_handshakes_and_unknown_frames_get_no_reply_at_all() {
    let (client, outsider) = (Client::new(1).await, Client::new(9).await);
    let relay = TestRelay::start(&[&client]);

    // 不在名单里的节点：INIT 没有回应。
    outsider.send(&Init { node: outsider.id, nonce: [1; 8] }.to_bytes(), &relay).await;
    outsider.expect_silence().await;

    // 比规定长度短的 INIT：不认。
    client.send(&Init { node: client.id, nonce: [1; 8] }.to_bytes()[..Init::LEN - 1], &relay).await;
    client.expect_silence().await;

    // cookie 是瞎编的。
    client.send(&client.auth(node(RELAY_ID), [1; 8], [0; 16]).to_bytes(), &relay).await;
    client.expect_silence().await;

    // cookie 是真的，但是发给另一个地址的：从别的地址拿来用不行。
    let nonce = [2; 8];
    let challenge = client.challenge(&relay, nonce).await;
    let elsewhere = Client { id: client.id, key: NodeKey::generate().unwrap(), socket: UdpSocket::bind("127.0.0.1:0").await.unwrap() };
    elsewhere.send(&client.auth(node(RELAY_ID), nonce, challenge.cookie).to_bytes(), &relay).await;
    elsewhere.expect_silence().await;

    // cookie 对，签名是别人的密钥签的。
    let forged = Auth {
        signature: *outsider
            .key
            .sign(Auth::PURPOSE, &Auth::signed_message(node(RELAY_ID), client.id, &nonce, &challenge.cookie))
            .as_bytes(),
        ..client.auth(node(RELAY_ID), nonce, challenge.cookie)
    };
    client.send(&forged.to_bytes(), &relay).await;
    client.expect_silence().await;

    // cookie 对，签名签的是另一个 relay 的编号。
    client.send(&client.auth(node(RELAY_ID + 1), nonce, challenge.cookie).to_bytes(), &relay).await;
    client.expect_silence().await;

    // 不认识的类型、relay 自己才会发的帧、空的中转头。
    for junk in [vec![0x00; 40], vec![0x0d; 40], vec![0x3f; 40], Pong { nonce, observed: client.addr() }.to_bytes(), vec![0x01, 0, 0]] {
        client.send(&junk, &relay).await;
    }
    client.expect_silence().await;

    assert!(!relay.relay().has_session(client.id));
    let counters = relay.relay().counters();
    assert_eq!(counters.sessions_opened, 0);
    assert_eq!(counters.dropped(DropReason::UnknownClient), 1);
    assert_eq!(counters.dropped(DropReason::BadCookie), 2);
    assert_eq!(counters.dropped(DropReason::BadSignature), 2);
    assert_eq!(counters.dropped(DropReason::Malformed), 6);

    // 同一个 cookie 配上正确的签名是可以的：前面的失败没有留下任何状态。
    client.send(&client.auth(node(RELAY_ID), nonce, challenge.cookie).to_bytes(), &relay).await;
    assert!(matches!(Frame::parse(&client.recv().await), Some(Frame::Ok(_))));
}

#[tokio::test]
async fn a_tcp_leg_uses_the_same_handshake_and_mixes_with_udp_clients() {
    let udp = Client::new(1).await;
    // TCP 节点的公钥要在名单里，所以先造身份再起 relay。
    let (tcp_key_a, tcp_key_b) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let relay = TestRelay::start(&[&udp]);
    relay.set_identities(Role::On, &[(udp.id, udp.key.public()), (node(2), tcp_key_a.public()), (node(3), tcp_key_b.public())]);
    let mut a = TcpClient::connect_as(node(2), tcp_key_a, &relay).await;
    let mut b = TcpClient::connect_as(node(3), tcp_key_b, &relay).await;

    udp.attach(&relay).await;
    let ok = a.attach(&relay).await;
    assert_eq!(ok.observed, a.local, "走 TCP 时报的是那条 TCP 的来源地址");
    b.attach(&relay).await;

    // UDP → TCP
    let frame = relayed(a.id, udp.id, &[0x41; 900]);
    udp.send(&frame, &relay).await;
    assert_eq!(a.recv().await, frame);
    // TCP → UDP
    let frame = relayed(udp.id, a.id, &[0x42; 900]);
    a.send(&frame).await;
    assert_eq!(udp.recv().await, frame);
    // TCP → TCP
    let frame = relayed(b.id, a.id, &[0x43; 900]);
    a.send(&frame).await;
    assert_eq!(b.recv().await, frame);

    // 保活也在这条 TCP 里。
    a.send(&Ping { node: a.id, nonce: [5; 8] }.to_bytes()).await;
    assert_eq!(Frame::parse(&a.recv().await), Some(Frame::Pong(Pong { nonce: [5; 8], observed: a.local })));

    // TCP 上同样不能冒别人的名字。
    a.send(&relayed(udp.id, b.id, b"forged")).await;
    assert_eq!(Frame::parse(&a.recv().await), Some(Frame::Error(Refused { reason: RefusalReason::NoSession, node: b.id })));
    udp.expect_silence().await;

    // TCP 断开，会话跟着没有。
    let a_id = a.id;
    drop(a);
    tokio::time::timeout(WAIT, async {
        while relay.relay().has_session(a_id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("TCP 断开之后会话应该被删掉");
    assert!(relay.relay().has_session(b.id));
}

#[tokio::test]
async fn a_node_moves_from_tcp_back_to_udp_by_handshaking_again() {
    let client = Client::new(1).await;
    let peer = Client::new(2).await;
    let relay = TestRelay::start(&[&client, &peer]);
    peer.attach(&relay).await;

    let mut leg = TcpClient::connect_as(node(1), NodeKey::from_pem(&client.key.to_pem()).unwrap(), &relay).await;
    leg.attach(&relay).await;
    let frame = relayed(client.id, peer.id, b"via tcp");
    peer.send(&frame, &relay).await;
    assert_eq!(leg.recv().await, frame);

    // 同一个节点在 UDP 上再握一次手：之后的包改走 UDP，原来那条 TCP 断开也不影响。
    client.attach(&relay).await;
    let frame = relayed(client.id, peer.id, b"via udp");
    peer.send(&frame, &relay).await;
    assert_eq!(client.recv().await, frame);
    drop(leg);
    tokio::time::sleep(SILENCE).await;
    assert!(relay.relay().session_at(client.id, client.addr()));
}

#[tokio::test]
async fn a_batch_from_the_kernel_with_mixed_destinations_is_forwarded_per_datagram() {
    let (a, b, c) = (Client::new(1).await, Client::new(2).await, Client::new(3).await);
    let relay = TestRelay::start(&[&a, &b, &c]);
    a.attach(&relay).await;
    b.attach(&relay).await;
    c.attach(&relay).await;

    // 内核合并接收交上来的样子：同一个来源的几个等长数据报首尾相接，目的各不相同，最后一个短一些。
    let datagrams = [
        relayed(b.id, a.id, &[1; 500]),
        relayed(b.id, a.id, &[2; 500]),
        relayed(c.id, a.id, &[3; 500]),
        relayed(b.id, a.id, &[4; 500]),
        relayed(c.id, a.id, &[5; 100]),
    ];
    let stride = datagrams[0].len();
    relay.relay().handle_udp(a.addr(), None, &datagrams.concat(), stride);

    assert_eq!([b.recv().await, b.recv().await, b.recv().await], [datagrams[0].clone(), datagrams[1].clone(), datagrams[3].clone()]);
    assert_eq!([c.recv().await, c.recv().await], [datagrams[2].clone(), datagrams[4].clone()]);
    assert_eq!(relay.relay().counters().forwarded_packets, 5);
}

#[tokio::test]
async fn disabling_the_relay_stops_forwarding_and_drops_every_session() {
    let (a, b) = (Client::new(1).await, Client::new(2).await);
    let relay = TestRelay::start(&[&a, &b]);
    a.attach(&relay).await;
    b.attach(&relay).await;
    let frame = relayed(b.id, a.id, b"before");
    a.send(&frame, &relay).await;
    assert_eq!(b.recv().await, frame);
    assert!(relay.relay().is_enabled());

    relay.set_netmap(Role::Off, &[&a, &b]);
    tokio::time::timeout(WAIT, async {
        while relay.relay().is_enabled() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("netmap 里去掉 relay 角色之后应该停用");
    assert_eq!(relay.relay().counters().sessions, 0);
    // 会话关掉之前，每个会话都收到了一行"即将下线"的通知，节点据此立刻换到别处。
    for client in [&a, &b] {
        assert_eq!(verified_row(&client.recv().await, &relay).state, RelayState::Draining);
    }

    // 停用之后：不转发，不回错误帧，握手也没有人理，TCP 也不再监听。
    a.send(&relayed(b.id, a.id, b"after"), &relay).await;
    a.send(&Init { node: a.id, nonce: [1; 8] }.to_bytes(), &relay).await;
    a.expect_silence().await;
    b.expect_silence().await;
    assert!(relay.relay().counters().dropped(DropReason::Disabled) >= 2);
    assert!(TcpStream::connect(relay.addr).await.is_err());

    // 重新启用之后要重新握手才能用。
    relay.set_netmap(Role::On, &[&a, &b]);
    a.attach(&relay).await;
    b.attach(&relay).await;
    let frame = relayed(b.id, a.id, b"again");
    a.send(&frame, &relay).await;
    assert_eq!(b.recv().await, frame);
}

#[tokio::test]
async fn a_node_started_without_the_relay_role_ignores_everything() {
    let client = Client::new(1).await;
    let relay = TestRelay::start_with(Role::Off, &[&client]);
    assert!(!relay.relay().is_enabled());
    client.send(&Init { node: client.id, nonce: [1; 8] }.to_bytes(), &relay).await;
    client.send(&relayed(node(2), client.id, b"x"), &relay).await;
    client.expect_silence().await;
}

#[tokio::test]
async fn removing_a_client_from_the_netmap_closes_its_session_at_once() {
    let (a, b) = (Client::new(1).await, Client::new(2).await);
    let relay = TestRelay::start(&[&a, &b]);
    a.attach(&relay).await;
    b.attach(&relay).await;

    relay.set_netmap(Role::On, &[&b]);
    tokio::time::timeout(WAIT, async {
        while relay.relay().has_session(a.id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("被去掉的节点的会话应该立刻关闭");

    a.send(&relayed(b.id, a.id, b"revoked"), &relay).await;
    assert_eq!(Frame::parse(&a.recv().await), Some(Frame::Error(Refused { reason: RefusalReason::NoSession, node: a.id })));
    b.expect_silence().await;
    // 它也握不上手了。
    a.send(&Init { node: a.id, nonce: [1; 8] }.to_bytes(), &relay).await;
    a.expect_silence().await;
}

#[tokio::test]
async fn a_new_key_for_a_client_in_the_netmap_closes_the_session_its_old_key_opened() {
    let (a, b) = (Client::new(1).await, Client::new(2).await);
    let relay = TestRelay::start(&[&a, &b]);
    a.attach(&relay).await;
    b.attach(&relay).await;

    // 编号 1 还在名单里，公钥换了：旧钥匙握手建的会话不是新钥匙的主人的。
    let successor = a.rekeyed().await;
    relay.set_netmap(Role::On, &[&successor, &b]);
    assert!(relay.session_closes(a.id).await, "公钥换了的节点，旧钥匙建的会话应该立刻关闭");

    // 拿着旧钥匙的一方还在原来的地址上：它发的包不转发，它的保活也续不了期（PING 没有签名，只认会话）。
    a.send(&relayed(b.id, a.id, b"sent under the old key"), &relay).await;
    assert_eq!(Frame::parse(&a.recv().await), Some(Frame::Error(Refused { reason: RefusalReason::NoSession, node: a.id })));
    a.send(&Ping { node: a.id, nonce: [2; 8] }.to_bytes(), &relay).await;
    assert_eq!(Frame::parse(&a.recv().await), Some(Frame::Error(Refused { reason: RefusalReason::NoSession, node: a.id })));
    // 发给这个编号的包也不往它那里送。
    b.send(&relayed(a.id, b.id, b"for the holder of the new key"), &relay).await;
    assert_eq!(Frame::parse(&b.recv().await), Some(Frame::Error(Refused { reason: RefusalReason::PeerUnattached, node: a.id })));
    a.expect_silence().await;
    b.expect_silence().await;
    assert_eq!(relay.relay().counters().forwarded_packets, 0);

    // 旧钥匙也握不上手了：INIT 照常回答（编号在名单里），AUTH 的签名对不上新公钥。
    let challenge = a.challenge(&relay, [3; 8]).await;
    a.send(&a.auth(node(RELAY_ID), [3; 8], challenge.cookie).to_bytes(), &relay).await;
    a.expect_silence().await;
    assert_eq!(relay.relay().counters().dropped(DropReason::BadSignature), 1);
    assert!(!relay.relay().has_session(a.id));

    // 新钥匙的主人握手之后，这个编号的包归它。
    successor.attach(&relay).await;
    let frame = relayed(a.id, b.id, b"to the new key");
    b.send(&frame, &relay).await;
    assert_eq!(successor.recv().await, frame);
    a.expect_silence().await;
}

#[tokio::test]
async fn the_bandwidth_cap_drops_what_exceeds_it() {
    let (a, b) = (Client::new(1).await, Client::new(2).await);
    let relay = TestRelay::start_with(Role::Capped(1), &[&a, &b]);
    a.attach(&relay).await;
    b.attach(&relay).await;

    // 1 Mbit/s 的桶里开始时有 128KB。一口气交 300 个 1KB 的包，过得去的只有一百多个。
    let frame = relayed(b.id, a.id, &[0; 1015]);
    for _ in 0..300 {
        relay.relay().handle_udp(a.addr(), None, &frame, frame.len());
    }
    let counters = relay.relay().counters();
    assert_eq!(counters.forwarded_packets + counters.dropped(DropReason::RateLimited), 300);
    assert!((120..=135).contains(&counters.forwarded_packets), "{counters:?}");
}

#[tokio::test]
async fn frames_addressed_to_the_relay_node_itself_are_delivered_locally_and_it_can_answer() {
    let client = Client::new(1).await;
    let relay = TestRelay::start(&[&client]);
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&delivered);
    relay.relay().set_local_delivery(move |src, packet| sink.lock().unwrap().push((src, packet)));
    client.attach(&relay).await;

    relay.relay().handle_udp(client.addr(), None, &relayed(node(RELAY_ID), client.id, b"for the relay node"), 1400);
    assert_eq!(*delivered.lock().unwrap(), [(client.id, Bytes::from_static(b"for the relay node"))]);

    // 没有会话的来源冒充不了。
    let stranger = Client::new(2).await;
    relay.relay().handle_udp(stranger.addr(), None, &relayed(node(RELAY_ID), client.id, b"forged"), 1400);
    assert_eq!(delivered.lock().unwrap().len(), 1);

    // 反方向：relay 节点自己给挂在它上面的节点发包。
    let reply = relayed(client.id, node(RELAY_ID), b"from the relay node");
    assert!(relay.relay().send_to_client(client.id, &reply, None, None));
    assert_eq!(client.recv().await, reply);
    assert!(!relay.relay().send_to_client(node(7), &reply, None, None), "没有会话的节点送不到");
}

#[tokio::test]
async fn datagram_classification_and_relay_agree_on_what_a_request_is() {
    // relay 的应答从节点一侧看都是"不是请求"的会话帧，路径层靠这个把它们留给自己。
    let client = Client::new(1).await;
    let relay = TestRelay::start(&[&client]);
    let challenge = client.challenge(&relay, [3; 8]).await;
    let bytes = challenge.to_bytes();
    let Ok(Datagram::Session(frame)) = Datagram::parse(&bytes) else { panic!("CHALLENGE 应该被分成会话帧") };
    assert!(!frame.is_request());
}
