//! 多级中转、骨干矩阵和下线通知在 relay 上的行为，包括各种不怀好意的输入。
//! 被测的 relay 是真的；它的邻居 relay 和节点都用原始的 UDP socket 扮演，这样每个字节都是测试自己写的。

// 这个文件里全是测试。clippy.toml 的 allow-unwrap-in-tests 只管 #[test] 函数本身，管不到它们调用的辅助函数。
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{Client, Net, RELAY_ID, Role, TcpClient, TestRelay, WAIT, node, relayed, routed, verified_row};
use i3t_crypto::NodeKey;
use i3t_path::SessionLeg;
use i3t_proto::backbone::{Link, LinkQuality, RelayState, Row};
use i3t_proto::datagram::RouteHeader;
use i3t_proto::session::{Challenge, Frame, Init, RefusalReason, Refused};
use i3t_proto::{Datagram, MAX_CONN_PACKET_LEN};
use i3t_relay::DropReason;

const ME: u32 = RELAY_ID;

/// 一个小网络：被测的 relay，两个邻居 relay（101、102），两个节点（1、2）。
struct Backbone {
    relay: TestRelay,
    a: Client,
    d: Client,
    before: Client,
    after: Client,
}

impl Backbone {
    /// `attach` 之后，四个扮演者都在被测的 relay 上建好了会话。
    async fn start(max_relay_hops: u8) -> Self {
        let (a, d) = (Client::new(1).await, Client::new(2).await);
        let (before, after) = (Client::new(101).await, Client::new(102).await);
        let relay = TestRelay::start_in(&Net { role: Role::On, clients: &[&a, &d], relays: &[&before, &after], max_relay_hops });
        for client in [&a, &d, &before, &after] {
            client.attach(&relay).await;
        }
        Self { relay, a, d, before, after }
    }

    fn dropped(&self, reason: DropReason) -> u64 {
        self.relay.relay().counters().dropped(reason)
    }

    async fn nobody_receives(&self) {
        for client in [&self.a, &self.d, &self.before, &self.after] {
            client.expect_silence().await;
        }
    }
}

fn refused(frame: &[u8]) -> Refused {
    match Frame::parse(frame) {
        Some(Frame::Error(refused)) => refused,
        other => panic!("应该是一个错误帧：{other:?}"),
    }
}

#[tokio::test]
async fn the_first_relay_passes_a_routed_frame_to_the_next_relay_byte_for_byte() {
    let net = Backbone::start(2).await;
    let frame = routed(net.d.id, net.a.id, &[node(ME), net.after.id], &[0x40; 1200]);
    net.a.send(&frame, &net.relay).await;
    assert_eq!(net.after.recv().await, frame, "头和包都原样转出去");
    let counters = net.relay.relay().counters();
    assert_eq!((counters.forwarded_packets, counters.dropped_total()), (1, 0));
}

#[tokio::test]
async fn the_last_relay_delivers_to_the_destination_and_a_middle_relay_passes_it_on() {
    let net = Backbone::start(3).await;
    // 排最后：交给目的节点。目的节点收到的仍然是带着完整路径的那一帧。
    let last = routed(net.d.id, net.a.id, &[net.before.id, node(ME)], b"to the destination");
    net.before.send(&last, &net.relay).await;
    assert_eq!(net.d.recv().await, last);
    // 排中间：交给下一个 relay。
    let middle = routed(net.d.id, net.a.id, &[net.before.id, node(ME), net.after.id], b"passing through");
    net.before.send(&middle, &net.relay).await;
    assert_eq!(net.after.recv().await, middle);
    assert_eq!(net.relay.relay().counters().forwarded_packets, 2);
}

#[tokio::test]
async fn the_longest_frame_with_the_longest_header_is_still_forwarded() {
    let (a, d) = (Client::new(1).await, Client::new(2).await);
    let relays = [Client::new(101).await, Client::new(102).await, Client::new(103).await];
    let relay =
        TestRelay::start_in(&Net { role: Role::On, clients: &[&a, &d], relays: &[&relays[0], &relays[1], &relays[2]], max_relay_hops: 4 });
    for client in [&a, &relays[0]] {
        client.attach(&relay).await;
    }
    let path = [node(ME), relays[0].id, relays[1].id, relays[2].id];
    let frame = routed(d.id, a.id, &path, &vec![0x40; usize::from(MAX_CONN_PACKET_LEN)]);
    assert_eq!(frame.len(), usize::from(MAX_CONN_PACKET_LEN) + RouteHeader::MAX_LEN);
    a.send(&frame, &relay).await;
    assert_eq!(relays[0].recv().await, frame);
}

#[tokio::test]
async fn a_path_longer_than_the_network_allows_is_not_forwarded() {
    let net = Backbone::start(1).await;
    // 网络只允许一级。来源节点发来两级的路径：排第一的 relay 拒绝，并且告诉来源节点。
    let frame = routed(net.d.id, net.a.id, &[node(ME), net.after.id], b"too far");
    net.a.send(&frame, &net.relay).await;
    let reply = net.a.recv().await;
    assert!(reply.len() <= frame.len());
    assert_eq!(refused(&reply), Refused { reason: RefusalReason::RouteUnavailable, node: node(ME) });
    // 邻居 relay 发来的同样不转发，而且什么都不回：排在后面的 relay 不知道来源节点在哪里。
    net.before.send(&routed(net.d.id, net.a.id, &[net.before.id, node(ME)], b"too far"), &net.relay).await;
    net.nobody_receives().await;
    assert_eq!(net.dropped(DropReason::HopLimit), 2);

    // 一级的路径在这个网络里照常能用，不管写成哪一种头。
    let single = routed(net.d.id, net.a.id, &[node(ME)], b"one hop");
    net.a.send(&single, &net.relay).await;
    assert_eq!(net.d.recv().await, single);
    let classic = relayed(net.d.id, net.a.id, b"one hop");
    net.a.send(&classic, &net.relay).await;
    assert_eq!(net.d.recv().await, classic);
}

#[tokio::test]
async fn frames_that_try_to_loop_or_name_a_relay_twice_cannot_even_be_parsed() {
    let net = Backbone::start(4).await;
    // 手写一个让包在两个 relay 之间来回的头：relay 的个数是 3，第三个和第一个相同。
    let mut looped = routed(net.d.id, net.a.id, &[node(ME), net.after.id, net.before.id], b"round and round");
    looped[18..22].copy_from_slice(&node(ME).to_be_bytes());
    assert!(Datagram::parse(&looped).is_err());
    net.a.send(&looped, &net.relay).await;
    // 个数写成 5（超过协议的上限）。
    let mut too_many = routed(net.d.id, net.a.id, &[node(ME), net.after.id], b"");
    too_many[1] = 5;
    too_many.extend_from_slice(&[0; 12]);
    net.a.send(&too_many, &net.relay).await;
    net.nobody_receives().await;
    assert_eq!(net.dropped(DropReason::Malformed), 2);
    assert_eq!(net.relay.relay().counters().forwarded_packets, 0);
}

#[tokio::test]
async fn a_relay_that_is_not_on_the_path_does_not_forward() {
    let net = Backbone::start(4).await;
    net.a.send(&routed(net.d.id, net.a.id, &[net.before.id, net.after.id], b"not for you"), &net.relay).await;
    // 目的节点写在路径中间的也不转发：到了它那里还得往外送，没有意义。
    net.a.send(&routed(net.after.id, net.a.id, &[node(ME), net.after.id, net.before.id], b"through the destination"), &net.relay).await;
    net.nobody_receives().await;
    assert_eq!(net.dropped(DropReason::NotOnRoute), 2);
}

#[tokio::test]
async fn an_unknown_or_unconnected_next_relay_is_refused_at_the_first_hop() {
    let net = Backbone::start(4).await;
    // 下一站是一个普通节点（它有会话，但不是 relay）。
    net.a.send(&routed(net.before.id, net.a.id, &[node(ME), net.d.id], b"via a client"), &net.relay).await;
    assert_eq!(refused(&net.a.recv().await), Refused { reason: RefusalReason::RouteUnavailable, node: net.d.id });
    net.d.expect_silence().await;

    // 下一站是 netmap 里根本没有的编号。换一个来源节点发，避开错误帧的限速。
    net.d.send(&routed(net.a.id, net.d.id, &[node(ME), node(777)], b"via nobody"), &net.relay).await;
    assert_eq!(refused(&net.d.recv().await), Refused { reason: RefusalReason::RouteUnavailable, node: node(777) });
    assert_eq!(net.dropped(DropReason::NoBackbone), 2);

    // 下一站是 netmap 里的 relay，但它在本节点上没有会话：同样走不通。
    let (a, absent) = (Client::new(1).await, Client::new(103).await);
    let relay = TestRelay::start_in(&Net { role: Role::On, clients: &[&a], relays: &[&absent], max_relay_hops: 4 });
    a.attach(&relay).await;
    a.send(&routed(node(2), a.id, &[node(ME), absent.id], b"no session"), &relay).await;
    assert_eq!(refused(&a.recv().await), Refused { reason: RefusalReason::RouteUnavailable, node: absent.id });
    absent.expect_silence().await;
}

#[tokio::test]
async fn a_spoofed_source_is_refused_on_a_routed_frame_too() {
    let net = Backbone::start(4).await;
    // a 有自己的会话，却在头里写 d 是来源。
    net.a.send(&routed(net.before.id, net.d.id, &[node(ME), net.after.id], b"forged"), &net.relay).await;
    assert_eq!(refused(&net.a.recv().await), Refused { reason: RefusalReason::NoSession, node: net.d.id });
    net.after.expect_silence().await;
    assert_eq!(net.dropped(DropReason::NoSession), 1);
}

#[tokio::test]
async fn only_the_previous_relay_on_the_path_may_hand_over_a_frame() {
    let net = Backbone::start(4).await;
    let via_before = routed(net.d.id, net.a.id, &[net.before.id, node(ME)], b"claims to come over the backbone");
    // 一个普通节点从自己的地址发来"前一站是 relay 101"的帧：它不是从 101 的会话来的。
    net.a.send(&via_before, &net.relay).await;
    // 另一个 relay 发来的也不行：路径上写的前一站不是它。
    net.after.send(&via_before, &net.relay).await;
    // 一个普通节点把自己写成路径上的前一站：它有会话，但不是 relay。
    net.a.send(&routed(net.d.id, net.a.id, &[net.a.id, node(ME)], b"a client posing as a relay"), &net.relay).await;
    // 没有会话的陌生地址发来的。
    let stranger = Client::new(55).await;
    stranger.send(&via_before, &net.relay).await;
    stranger.expect_silence().await;
    net.nobody_receives().await;
    assert_eq!(net.dropped(DropReason::NoBackbone), 4);
    assert_eq!(net.relay.relay().counters().forwarded_packets, 0);

    // 真的从前一站来的才转发。
    net.before.send(&via_before, &net.relay).await;
    assert_eq!(net.d.recv().await, via_before);
}

#[tokio::test]
async fn a_new_key_for_a_neighbour_relay_in_the_netmap_takes_its_old_session_off_the_backbone() {
    let net = Backbone::start(3).await;
    // relay 101 还在 netmap 里，公钥换了。
    let successor = net.before.rekeyed().await;
    net.relay.set_net(&Net { role: Role::On, clients: &[&net.a, &net.d], relays: &[&successor, &net.after], max_relay_hops: 3 });
    assert!(net.relay.session_closes(net.before.id).await, "公钥换了的 relay，旧钥匙建的会话应该立刻关闭");

    // 拿着旧钥匙的一方从原来的地址交过来的包不转发。排在后面的 relay 只认前一站的会话，头里的来源节点它想写谁就写谁。
    net.before.send(&routed(net.d.id, net.a.id, &[net.before.id, node(ME)], b"handed over under the old key"), &net.relay).await;
    // 要经它往下走的包也不往它那里送，来源节点被告知这一段不通。
    net.a.send(&routed(net.d.id, net.a.id, &[node(ME), net.before.id], b"via the old key"), &net.relay).await;
    assert_eq!(refused(&net.a.recv().await), Refused { reason: RefusalReason::RouteUnavailable, node: net.before.id });
    // 矩阵行发给所有会话，它不在里面了。
    net.relay.relay().publish_row(&links());
    for client in [&net.a, &net.d, &net.after] {
        verified_row(&client.recv().await, &net.relay);
    }
    net.nobody_receives().await;
    assert_eq!(net.dropped(DropReason::NoBackbone), 2);
    assert_eq!(net.relay.relay().counters().forwarded_packets, 0);

    // 新钥匙握手之后，这一段骨干又通了。
    successor.attach(&net.relay).await;
    let frame = routed(net.d.id, net.a.id, &[successor.id, node(ME)], b"handed over under the new key");
    successor.send(&frame, &net.relay).await;
    assert_eq!(net.d.recv().await, frame);
}

#[tokio::test]
async fn a_stranger_gets_at_most_one_small_error_and_nothing_is_reflected() {
    let net = Backbone::start(4).await;
    let stranger = Client::new(1).await;
    // 陌生地址自称是节点 1，发排第一的多级帧，目的是把大包反射给别人。
    let frame = routed(net.d.id, net.a.id, &[node(ME), net.after.id], &[0x40; 1200]);
    for _ in 0..20 {
        stranger.send(&frame, &net.relay).await;
    }
    let reply = stranger.recv().await;
    assert!(reply.len() <= frame.len() && reply.len() == Refused::LEN, "只回一个不比请求大的错误帧");
    assert_eq!(refused(&reply), Refused { reason: RefusalReason::NoSession, node: net.a.id });
    assert_eq!(Refused::echo(&reply), Some([0x40; 8]), "回显的是请求里的东西，不是节点 1 的会话的秘密");
    stranger.expect_silence().await;
    net.nobody_receives().await;
    assert_eq!(net.dropped(DropReason::NoSession), 20);
}

#[tokio::test]
async fn the_backbone_may_run_over_tcp_and_so_may_the_first_and_last_hop() {
    let (a, d) = (Client::new(1).await, Client::new(2).await);
    let (before, after) = (Client::new(101).await, Client::new(102).await);
    let relay = TestRelay::start_in(&Net { role: Role::On, clients: &[&a, &d], relays: &[&before, &after], max_relay_hops: 3 });
    after.attach(&relay).await;
    // 来源节点走 TCP 中转：排第一的 relay 照样往骨干上送。
    let mut a_tcp = TcpClient::connect_as(a.id, NodeKey::from_pem(&a.key.to_pem()).unwrap(), &relay).await;
    a_tcp.attach(&relay).await;
    let frame = routed(d.id, a.id, &[node(ME), after.id], b"tcp in, udp out");
    a_tcp.send(&frame).await;
    assert_eq!(after.recv().await, frame);

    // 目的节点走 TCP 中转：最后一个 relay 写进它的 TCP。
    let mut d_tcp = TcpClient::connect_as(d.id, NodeKey::from_pem(&d.key.to_pem()).unwrap(), &relay).await;
    d_tcp.attach(&relay).await;
    let frame = routed(d.id, a.id, &[after.id, node(ME)], b"udp in, tcp out");
    after.send(&frame, &relay).await;
    assert_eq!(&d_tcp.recv().await[..], frame);

    // 邻居 relay 和本节点之间 UDP 不通，它的会话在 TCP 上：骨干照样走这条 TCP，两个方向都转，路径的中间也可以是它。
    let mut before_tcp = TcpClient::connect_as(before.id, NodeKey::from_pem(&before.key.to_pem()).unwrap(), &relay).await;
    before_tcp.attach(&relay).await;
    let from_neighbour = routed(d.id, a.id, &[before.id, node(ME)], b"backbone over tcp");
    before_tcp.send(&from_neighbour).await;
    assert_eq!(&d_tcp.recv().await[..], from_neighbour);
    let to_neighbour = routed(d.id, a.id, &[node(ME), before.id, after.id], b"to a tcp neighbour in the middle");
    a_tcp.send(&to_neighbour).await;
    assert_eq!(&before_tcp.recv().await[..], to_neighbour);
    let through = routed(d.id, a.id, &[after.id, node(ME), before.id], b"udp neighbour to tcp neighbour");
    after.send(&through, &relay).await;
    assert_eq!(&before_tcp.recv().await[..], through);
    tokio::time::sleep(common::SILENCE).await;
    assert_eq!(relay.relay().counters().dropped(DropReason::NoBackbone), 0);
    assert_eq!(relay.relay().counters().forwarded_packets, 5);

    // 一个普通节点的 TCP 会话不是骨干：它自称前一站是 relay 101，不转发。
    a_tcp.send(&routed(d.id, a.id, &[before.id, node(ME)], b"a client posing as the neighbour")).await;
    tokio::time::sleep(common::SILENCE).await;
    assert_eq!(relay.relay().counters().dropped(DropReason::NoBackbone), 1);
}

#[tokio::test]
async fn packets_a_tcp_neighbour_hands_over_for_this_node_are_delivered_on_its_word() {
    let (a, peer) = (Client::new(1).await, Client::new(5).await);
    let neighbour = Client::new(101).await;
    let relay = TestRelay::start_in(&Net { role: Role::On, clients: &[&a], relays: &[&neighbour], max_relay_hops: 2 });
    let delivered = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&delivered);
    relay.relay().set_local_delivery(move |src, packet| sink.lock().unwrap().push((src, packet)));
    let mut tcp = TcpClient::connect_as(neighbour.id, NodeKey::from_pem(&neighbour.key.to_pem()).unwrap(), &relay).await;
    tcp.attach(&relay).await;
    // 邻居替挂在它上面的节点 5 送来的（5 在本节点上没有会话）：经一个 relay 的，和经几个 relay、它排最后的。
    tcp.send(&relayed(node(ME), peer.id, b"one hop")).await;
    tcp.send(&routed(node(ME), peer.id, &[node(77), neighbour.id], b"last hop")).await;
    tokio::time::sleep(common::SILENCE).await;
    let got: Vec<(i3t_proto::NodeId, Vec<u8>)> = delivered.lock().unwrap().iter().map(|(src, packet)| (*src, packet.to_vec())).collect();
    assert_eq!(got, [(peer.id, b"one hop".to_vec()), (peer.id, b"last hop".to_vec())]);

    // 普通节点的 TCP 会话没有这个资格：它替别人送的，本节点不收。
    let mut client = TcpClient::connect_as(a.id, NodeKey::from_pem(&a.key.to_pem()).unwrap(), &relay).await;
    client.attach(&relay).await;
    client.send(&relayed(node(ME), peer.id, b"not on its word")).await;
    tokio::time::sleep(common::SILENCE).await;
    assert_eq!(delivered.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_tcp_neighbour_whose_key_changed_is_not_taken_at_its_word_from_its_very_next_frame() {
    let peer = Client::new(5).await;
    let neighbour = Client::new(101).await;
    let relay = TestRelay::start_in(&Net { role: Role::On, clients: &[], relays: &[&neighbour], max_relay_hops: 2 });
    let delivered = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&delivered);
    relay.relay().set_local_delivery(move |src, packet| sink.lock().unwrap().push((src, packet)));
    let mut tcp = TcpClient::connect_as(neighbour.id, NodeKey::from_pem(&neighbour.key.to_pem()).unwrap(), &relay).await;
    tcp.attach(&relay).await;
    tcp.send(&relayed(node(ME), peer.id, b"while its key stood")).await;
    tokio::time::sleep(common::SILENCE).await;
    assert_eq!(delivered.lock().unwrap().len(), 1);

    // 这条 TCP 正等着下一帧的时候，netmap 里这个 relay 换了公钥：旧钥匙在上面建的会话没了。
    let successor = neighbour.rekeyed().await;
    relay.set_net(&Net { role: Role::On, clients: &[], relays: &[&successor], max_relay_hops: 2 });
    assert!(relay.session_closes(neighbour.id).await, "公钥换了的 relay，旧钥匙建的会话应该立刻关闭");

    // 旧钥匙的一方在这条 TCP 上再发来的，从头一帧起就不作数：它替别的节点送的包，本节点不收。
    tcp.send(&relayed(node(ME), peer.id, b"its first frame after the change")).await;
    tcp.send(&routed(node(ME), peer.id, &[node(77), neighbour.id], b"and the one after")).await;
    tokio::time::sleep(common::SILENCE).await;
    assert_eq!(delivered.lock().unwrap().len(), 1, "换了公钥之后它送来的包不该交给本节点");
}

#[tokio::test]
async fn a_neighbour_relay_opens_its_session_on_a_connection_this_node_dialled_and_is_forwarded_to_over_it() {
    let a = Client::new(1).await;
    let neighbour = Client::new(101).await;
    let relay = TestRelay::start_in(&Net { role: Role::On, clients: &[&a], relays: &[&neighbour], max_relay_hops: 2 });
    a.attach(&relay).await;
    // 本节点的路径层拨向邻居的一条 TCP（这里是一对本机的 socket）：一头的写入由它的队列来，另一头扮演邻居。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (ours, theirs) = tokio::join!(tokio::net::TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
    let (ours, (theirs, _)) = (ours.unwrap(), theirs.unwrap());
    let (sender, queue) = i3t_underlay::tcp_leg::frame_queue();
    let _writer = tokio::spawn(i3t_underlay::tcp_leg::write_frames(ours.into_split().1, queue));
    let mut reader = i3t_underlay::tcp_leg::FrameReader::new(theirs.into_split().0);
    let mut next = async || tokio::time::timeout(common::WAIT, reader.next()).await.unwrap().unwrap().unwrap();
    let leg = listener.local_addr().unwrap();

    // 邻居在这条 TCP 上反过来握手：经路径层交进来，回话写进同一条 TCP。
    let nonce = [9; 8];
    relay.relay().handle_leg_frame(7, leg, &sender, &i3t_proto::session::Init { node: neighbour.id, nonce }.to_bytes());
    let Some(Frame::Challenge(challenge)) = Frame::parse(&next().await) else { panic!("应该回 CHALLENGE") };
    relay.relay().handle_leg_frame(7, leg, &sender, &neighbour.auth(node(ME), nonce, challenge.cookie).to_bytes());
    let Some(Frame::Ok(ok)) = Frame::parse(&next().await) else { panic!("应该回 OK") };
    common::verify_ok(&ok, &relay, neighbour.id, nonce);
    assert_eq!(relay.relay().session_leg(neighbour.id), Some(i3t_path::SessionLeg::Dialled(7)));

    // 骨干：经它的包写进这条 TCP；它交进来的包按它在这条 TCP 上的会话认。
    let frame = routed(node(2), a.id, &[node(ME), neighbour.id], b"over the dialled leg");
    a.send(&frame, &relay).await;
    assert_eq!(&next().await[..], frame);
    relay.relay().handle_leg_frame(7, leg, &sender, &routed(a.id, node(2), &[neighbour.id, node(ME)], b"back"));
    assert_eq!(a.recv().await, routed(a.id, node(2), &[neighbour.id, node(ME)], b"back"));
    // 另一条 TCP 冒充它不行。
    relay.relay().handle_leg_frame(8, leg, &sender, &routed(a.id, node(2), &[neighbour.id, node(ME)], b"forged"));
    a.expect_silence().await;

    // 这条 TCP 没了：会话跟着关闭。
    relay.relay().leg_closed(7);
    assert_eq!(relay.relay().session_leg(neighbour.id), None);
}

/// 邻居 relay 拨进来、在这条 TCP 上建了会话。被测的 relay 旁边的路径层借这条 TCP 走骨干（这一段改走了 TCP），在上面反过来握手
/// （扮演邻居的不回答）。返回这条 TCP 和邻居在被测的 relay 上的会话的位置。
async fn neighbour_on_tcp(relay: &TestRelay, neighbour: &Client) -> (TcpClient, Option<SessionLeg>) {
    let mut tcp = TcpClient::connect_as(neighbour.id, NodeKey::from_pem(&neighbour.key.to_pem()).unwrap(), relay).await;
    tcp.attach(relay).await;
    while !matches!(Frame::parse(&tcp.recv().await), Some(Frame::Init(_))) {}
    let leg = relay.relay().session_leg(neighbour.id);
    assert!(matches!(leg, Some(SessionLeg::Accepted(_))), "{leg:?}");
    // 路径层借来这条 TCP 之前经 UDP 发过的握手。
    neighbour.drain().await;
    (tcp, leg)
}

/// 经 UDP 握手，返回 relay 对 AUTH 的回答之前的那些：CHALLENGE 照常回答，之后收到的第一个会话帧。
async fn auth_over_udp(relay: &TestRelay, client: &Client, nonce: [u8; 8]) -> Frame {
    client.send(&Init { node: client.id, nonce }.to_bytes(), relay).await;
    let Frame::Challenge(challenge) = client.recv_answer().await else { panic!("relay 不记状态地回答 INIT") };
    client.send(&client.auth(node(ME), nonce, challenge.cookie).to_bytes(), relay).await;
    client.recv_frame().await
}

#[tokio::test]
async fn a_neighbour_on_tcp_moves_its_session_to_udp_only_once_this_node_knows_its_own_udp_reaches_the_neighbour() {
    let neighbour = Client::new(101).await;
    let relay = TestRelay::start_with_paths(&Net { role: Role::On, clients: &[], relays: &[&neighbour], max_relay_hops: 2 });
    let (_tcp, on_tcp) = neighbour_on_tcp(&relay, &neighbour).await;
    let opened = relay.relay().status().unwrap().sessions_opened;

    // 它经 UDP 来的 AUTH：本节点还不知道自己的 UDP 到不到得了它。不建会话、不回答；路径层被敲了门，马上自己经 UDP 来问。
    let Frame::Init(asked) = auth_over_udp(&relay, &neighbour, [5; 8]).await else { panic!("没有 OK，先到的是路径层的 INIT") };
    assert_eq!(relay.relay().session_leg(neighbour.id), on_tcp, "会话还在那条 TCP 上");
    assert_eq!(relay.relay().status().unwrap().sessions_opened, opened);
    assert_eq!(relay.relay().counters().dropped_total(), 0, "挡下它不算丢弃：它没有做错什么");

    // 回答路径层：本节点的 UDP 到得了它。路径层接着发 AUTH（扮演邻居的不理）。
    neighbour.send(&Challenge { nonce: asked.nonce, cookie: [7; 16] }.to_bytes(), &relay).await;
    neighbour.recv_request(|frame| matches!(frame, Frame::Auth(_))).await;

    // 现在它经 UDP 来的 AUTH 能把会话搬过来。
    let nonce = [6; 8];
    let Frame::Ok(ok) = auth_over_udp(&relay, &neighbour, nonce).await else { panic!("这一次应该建会话") };
    common::verify_ok(&ok, &relay, neighbour.id, nonce);
    assert_eq!(relay.relay().session_leg(neighbour.id), Some(SessionLeg::Udp));
}

#[tokio::test]
async fn an_ordinary_node_moves_from_tcp_to_udp_as_before_while_a_backbone_link_runs_over_tcp() {
    let (client, neighbour) = (Client::new(1).await, Client::new(101).await);
    let relay = TestRelay::start_with_paths(&Net { role: Role::On, clients: &[&client], relays: &[&neighbour], max_relay_hops: 2 });
    let (_tcp, on_tcp) = neighbour_on_tcp(&relay, &neighbour).await;

    let mut client_tcp = TcpClient::connect_as(client.id, NodeKey::from_pem(&client.key.to_pem()).unwrap(), &relay).await;
    client_tcp.attach(&relay).await;
    assert!(matches!(relay.relay().session_leg(client.id), Some(SessionLeg::Accepted(_))));
    let nonce = [8; 8];
    let Frame::Ok(ok) = auth_over_udp(&relay, &client, nonce).await else { panic!("普通节点从 TCP 换回 UDP，和以前一样") };
    common::verify_ok(&ok, &relay, client.id, nonce);
    assert_eq!(relay.relay().session_leg(client.id), Some(SessionLeg::Udp));
    assert_eq!(relay.relay().session_leg(neighbour.id), on_tcp);
}

#[tokio::test]
async fn a_relay_in_the_netmap_may_open_a_session_without_being_listed_as_a_client() {
    let neighbour = Client::new(101).await;
    let relay = TestRelay::start_in(&Net { role: Role::On, clients: &[], relays: &[&neighbour], max_relay_hops: 2 });
    neighbour.attach(&relay).await;
    assert!(relay.relay().has_udp_session(neighbour.id));
    assert!(!relay.relay().has_udp_session(node(7)));
}

fn links() -> Vec<Link> {
    vec![
        Link { relay: node(101), quality: Some(LinkQuality { rtt_ms: 140, jitter_ms: 2, loss_half_percent: 1 }) },
        Link { relay: node(102), quality: None },
    ]
}

#[tokio::test]
async fn a_published_row_reaches_every_session_signed_by_the_relay() {
    let net = Backbone::start(2).await;
    let mut tcp = TcpClient::connect(3, &net.relay).await;
    net.relay.set_identities(Role::On, &[(net.a.id, net.a.key.public()), (tcp.id, tcp.key.public())]);
    net.a.attach(&net.relay).await;
    tcp.attach(&net.relay).await;
    // 上面换 netmap 的时候 d 和两个邻居的会话被关掉了，剩下 a 和走 TCP 的那个节点。
    net.relay.relay().publish_row(&links());
    let first = verified_row(&net.a.recv().await, &net.relay);
    assert_eq!((first.state, first.load_percent, &first.links), (RelayState::Serving, 0, &links()));
    assert_eq!(verified_row(&tcp.recv().await, &net.relay), first, "TCP 上的会话收到同一行");
    net.d.expect_silence().await;

    // 序号一行比一行大，收的一方靠它分新旧。
    net.relay.relay().publish_row(&[]);
    let second = verified_row(&net.a.recv().await, &net.relay);
    assert!(second.seq > first.seq, "{} 应该大于 {}", second.seq, first.seq);
    assert_eq!(net.relay.relay().counters().forwarded_packets, 0, "通知不算转发的流量");
}

#[tokio::test]
async fn rows_of_other_relays_are_passed_on_verbatim() {
    let net = Backbone::start(2).await;
    let foreign = Row { origin: net.before.id, seq: 42, state: RelayState::Overloaded, load_percent: 120, links: Vec::new() };
    let signature = net.before.key.sign(Row::PURPOSE, &foreign.to_unsigned_bytes());
    let frame = foreign.to_bytes(signature.as_bytes());
    net.relay.relay().broadcast(&frame);
    for client in [&net.a, &net.d, &net.before, &net.after] {
        assert_eq!(client.recv().await, frame, "别人签的行原样传下去，签名还是它主人的");
    }
}

#[tokio::test]
async fn announcing_shutdown_tells_every_session_once_and_keeps_forwarding() {
    let net = Backbone::start(2).await;
    assert_eq!(net.relay.relay().status().map(|status| status.state), Some(RelayState::Serving));
    net.relay.relay().announce_shutdown();
    for client in [&net.a, &net.d, &net.before, &net.after] {
        let notice = verified_row(&client.recv().await, &net.relay);
        assert_eq!((notice.state, notice.links.len()), (RelayState::Draining, 0));
    }
    assert_eq!(net.relay.relay().status().map(|status| status.state), Some(RelayState::Draining));
    net.relay.relay().announce_shutdown();
    net.a.expect_silence().await;

    // 通知之后、进程退出之前，路上的包照常转发。
    let frame = relayed(net.d.id, net.a.id, b"still in flight");
    net.a.send(&frame, &net.relay).await;
    assert_eq!(net.d.recv().await, frame);
    // 之后发的每一行都带着这个状态。
    net.relay.relay().publish_row(&links());
    assert_eq!(verified_row(&net.a.recv().await, &net.relay).state, RelayState::Draining);
}

#[tokio::test]
async fn dropping_the_relay_sends_the_shutdown_notice_as_a_last_resort() {
    let mut net = Backbone::start(2).await;
    let key = net.relay.key.public();
    drop(net.relay.relay.take());
    let frame = net.a.recv().await;
    let (notice, signature) = Row::parse(&frame).expect("应该是一行通知");
    i3t_crypto::verify(&key, Row::PURPOSE, Row::signed_part(&frame).unwrap(), &i3t_crypto::Signature::from_bytes(signature)).unwrap();
    assert_eq!((notice.origin, notice.state), (node(ME), RelayState::Draining));
}

#[tokio::test]
async fn a_relay_that_is_not_enabled_publishes_nothing() {
    let a = Client::new(1).await;
    let relay = TestRelay::start_with(Role::Off, &[&a]);
    assert_eq!(relay.relay().status(), None);
    relay.relay().publish_row(&links());
    relay.relay().broadcast(b"anything");
    relay.relay().announce_shutdown();
    a.expect_silence().await;
}

#[tokio::test]
async fn load_and_overload_show_up_in_the_status_and_in_the_rows() {
    let (a, b) = (Client::new(1).await, Client::new(2).await);
    // 1 Mbit/s 的上限：每秒 125KB。
    let relay = TestRelay::start_with(Role::Capped(1), &[&a, &b]);
    a.attach(&relay).await;
    b.attach(&relay).await;
    let frame = relayed(b.id, a.id, &[0x40; 1200]);
    // 持续几秒按上限的三倍左右发。
    let flood = async {
        loop {
            for _ in 0..3 {
                a.send(&frame, &relay).await;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let drain = async {
        let mut buf = [0u8; 2048];
        loop {
            let _received = b.socket.recv_from(&mut buf).await;
        }
    };
    let overloaded = async {
        loop {
            if relay.relay().status().is_some_and(|status| status.state == RelayState::Overloaded) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::select! {
        () = flood => {}
        () = drain => {}
        result = tokio::time::timeout(4 * WAIT, overloaded) => result.expect("持续超过带宽上限应该进入过载状态"),
    }
    // 只有一个来源：它的份额就是整个上限，负载到顶就是过载。
    let status = relay.relay().status().unwrap();
    assert!(status.load_percent >= 95, "{status:?}");
    assert!(relay.relay().counters().dropped(DropReason::RateLimited) > 0);

    relay.relay().publish_row(&[]);
    // b 的 socket 里还排着转发过来的包，逐个看，直到见到那一行。
    let row = tokio::time::timeout(WAIT, async {
        loop {
            let datagram = a.recv().await;
            if Row::is_complete(&datagram) && datagram.first() == Some(&i3t_proto::backbone::KIND_ROW) {
                break verified_row(&datagram, &relay);
            }
        }
    })
    .await
    .expect("a 应该收到一行");
    assert_eq!(row.state, RelayState::Overloaded);
    assert!(row.load_percent >= 95);
}
