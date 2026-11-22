//! 不握手、或者握手时乱来的来源能占用 relay 多少东西：签名验证的次数，TCP 中转的位子。
//! 用最原始的 socket 往真的 relay 上灌，看它是不是把代价封住了，正常的节点是不是还进得来。

// 这个文件里全是测试。clippy.toml 的 allow-unwrap-in-tests 只管 #[test] 函数本身，管不到它们调用的辅助函数。
#![allow(clippy::unwrap_used)]

mod common;

use std::time::{Duration, Instant};

use common::{Client, RELAY_ID, Role, TestRelay, WAIT, node};
use i3t_proto::addr::Query;
use i3t_proto::session::{Auth, Frame, Init, Ping};
use i3t_proto::{Datagram, tcp_frame};
use i3t_relay::DropReason;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

/// 和 relay 里的握手时限一样。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 等 relay 的后台任务把 TCP 监听起来，然后从 `local` 这个地址连上去。
async fn connect_from(local: &str, relay: &TestRelay) -> TcpStream {
    tokio::time::timeout(WAIT, async {
        loop {
            let socket = TcpSocket::new_v4().unwrap();
            socket.bind(local.parse().unwrap()).unwrap();
            match socket.connect(relay.addr).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("relay 的 TCP 端口一直连不上")
}

async fn send_frame(stream: &mut (impl AsyncWriteExt + Unpin), datagram: &[u8]) -> std::io::Result<()> {
    let mut framed = bytes::BytesMut::new();
    tcp_frame::put_frame(&mut framed, datagram).unwrap();
    stream.write_all(&framed).await
}

/// relay 有没有关掉这条连接：读到对方关闭或者连接被重置。`within` 之内一直有数据来、没有关闭就算没关。
async fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    let mut buf = [0u8; 256];
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
            Err(_) => return false,
        }
    }
}

#[tokio::test]
async fn one_cookie_buys_only_a_handful_of_signature_checks() {
    let attacker = Client::new(1).await;
    let relay = TestRelay::start(&[&attacker]);
    // 攻击者知道一个合法的节点编号，没有它的密钥。拿到一个发给自己地址的 cookie，然后不停地发签名不对的 AUTH。
    let nonce = [5; 8];
    let challenge = attacker.challenge(&relay, nonce).await;
    let stranger = i3t_crypto::NodeKey::generate().unwrap();
    let signature = *stranger.sign(Auth::PURPOSE, b"anything").as_bytes();
    let bogus = Auth { node: attacker.id, nonce, cookie: challenge.cookie, signature }.to_bytes();
    let sent = 20_000;
    for _ in 0..sent {
        relay.relay().handle_udp(attacker.addr(), None, &bogus, bogus.len());
    }
    let counters = relay.relay().counters();
    let checked = counters.dropped(DropReason::BadSignature);
    assert!(checked <= 12, "一个来源先攒着 10 次，之后每秒 5 次：验了 {checked} 次");
    assert_eq!(checked + counters.dropped(DropReason::TooManyHandshakes), sent, "剩下的连签名都没验");
}

/// 握手限速是按来源算的：一个来源灌满了，别的来源照样握得上手。回环上的第二个地址只有 Linux 默认就有。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_source_flooding_handshakes_does_not_lock_out_the_others() {
    let attacker = Client::new(1).await;
    let honest = Client { socket: tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap(), ..Client::new(2).await };
    let relay = TestRelay::start(&[&attacker, &honest]);
    let challenge = attacker.challenge(&relay, [5; 8]).await;
    let bogus = Auth { node: attacker.id, nonce: [5; 8], cookie: challenge.cookie, signature: [0x11; 64] }.to_bytes();
    for _ in 0..1000 {
        relay.relay().handle_udp(attacker.addr(), None, &bogus, bogus.len());
    }
    assert!(relay.relay().counters().dropped(DropReason::TooManyHandshakes) > 900);
    honest.attach(&relay).await;
    assert!(relay.relay().has_session(honest.id));
}

#[tokio::test]
async fn a_tcp_leg_must_finish_its_handshake_in_time_however_chatty_it_is() {
    let client = Client::new(1).await;
    let relay = TestRelay::start(&[&client]);
    let stream = connect_from("127.0.0.1:0", &relay).await;
    let opened = Instant::now();
    let (mut read_half, mut write_half) = stream.into_split();
    // 每秒发一个 INIT（握手之前被接受的两种帧之一），一直不发 AUTH。每一帧都不延长时限。
    let init = Init { node: client.id, nonce: [1; 8] }.to_bytes();
    let chatter = tokio::spawn(async move {
        while send_frame(&mut write_half, &init).await.is_ok() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let mut buf = [0u8; 256];
    let closed = tokio::time::timeout(HANDSHAKE_TIMEOUT + Duration::from_secs(2), async {
        while read_half.read(&mut buf).await.is_ok_and(|len| len > 0) {}
    })
    .await;
    chatter.abort();
    assert!(closed.is_ok(), "握手时限是从接受连接时算的，来多少帧都不延长");
    assert!(opened.elapsed() >= HANDSHAKE_TIMEOUT - Duration::from_millis(100), "时限之前不关：{:?}", opened.elapsed());
}

#[tokio::test]
async fn a_tcp_leg_that_lost_its_session_must_handshake_again_in_time_however_chatty_it_is() {
    let client = Client::new(1).await;
    let relay = TestRelay::start(&[&client]);
    let (read_half, mut write_half) = connect_from("127.0.0.1:0", &relay).await.into_split();
    let mut reader = i3t_underlay::tcp_leg::FrameReader::new(read_half);
    let mut next = async || tokio::time::timeout(WAIT, reader.next()).await.unwrap().unwrap().unwrap();
    send_frame(&mut write_half, &Init { node: client.id, nonce: [3; 8] }.to_bytes()).await.unwrap();
    let Some(Frame::Challenge(challenge)) = Frame::parse(&next().await) else { panic!("应该是 CHALLENGE") };
    send_frame(&mut write_half, &client.auth(node(RELAY_ID), [3; 8], challenge.cookie).to_bytes()).await.unwrap();
    assert!(matches!(Frame::parse(&next().await), Some(Frame::Ok(_))));

    // netmap 里这个节点换了公钥：旧钥匙在这条 TCP 上建的会话没了，它也握不上新的。
    relay.set_netmap(Role::On, &[&client.rekeyed().await]);
    assert!(relay.session_closes(client.id).await, "公钥换了的节点，旧钥匙建的会话应该立刻关闭");

    // 它照旧每秒发一个 PING。会话没了之后的时限从 relay 发现的那一刻算起，来多少帧都不延长。
    let lost = Instant::now();
    let ping = Ping { node: client.id, nonce: [4; 8] }.to_bytes();
    let chatter = tokio::spawn(async move {
        while send_frame(&mut write_half, &ping).await.is_ok() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let closed = tokio::time::timeout(HANDSHAKE_TIMEOUT + Duration::from_secs(2), async {
        while reader.next().await.is_ok_and(|frame| frame.is_some()) {}
    })
    .await;
    chatter.abort();
    assert!(closed.is_ok(), "会话没了之后重新握手的时限，来多少帧都不延长");
    assert!(lost.elapsed() >= HANDSHAKE_TIMEOUT - Duration::from_millis(100), "时限之前不关，留给它重新握手：{:?}", lost.elapsed());
}

#[tokio::test]
async fn a_tcp_leg_that_sends_anything_but_a_handshake_first_is_closed_at_once() {
    let client = Client::new(1).await;
    let relay = TestRelay::start(&[&client]);
    // 一个不认识的帧，一个地址查询（UDP 上谁都可以问，TCP 上要先握手），一个中转帧。
    for datagram in [vec![0x00], Query { nonce: [9; 8] }.to_bytes().to_vec(), common::relayed(client.id, client.id, &[0x41; 100])] {
        let mut stream = connect_from("127.0.0.1:0", &relay).await;
        send_frame(&mut stream, &datagram).await.unwrap();
        assert!(closed_within(&mut stream, Duration::from_secs(1)).await, "{datagram:?} 之后应该被断开");
    }
    // 先握手就没事：INIT 换来 CHALLENGE，连接留着。
    let mut stream = connect_from("127.0.0.1:0", &relay).await;
    send_frame(&mut stream, &Init { node: client.id, nonce: [1; 8] }.to_bytes()).await.unwrap();
    let (read_half, _write_half) = stream.into_split();
    let mut reader = i3t_underlay::tcp_leg::FrameReader::new(read_half);
    let reply = tokio::time::timeout(WAIT, reader.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(Frame::parse(&reply), Some(Frame::Challenge(_))));
    assert!(!matches!(Datagram::parse(&reply), Ok(Datagram::AddrReply(_))));
}

/// 一个来源最多占 8 条还没握手成功的 TCP；别的来源照样连得上。回环上的第二个地址只有 Linux 默认就有。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn one_source_cannot_hold_more_than_a_few_tcp_legs_without_a_session() {
    let honest = Client::new(2).await;
    let relay = TestRelay::start(&[&honest]);
    let mut held = Vec::new();
    for _ in 0..20 {
        held.push(connect_from("127.0.0.1:0", &relay).await);
    }
    let mut refused = 0;
    for stream in &mut held {
        if closed_within(stream, Duration::from_millis(300)).await {
            refused += 1;
        }
    }
    assert_eq!(refused, 12, "同一个来源只留 8 条");

    // 只能走 TCP 的节点从另一个地址来：照样握得上手。macOS 的回环网卡上只有 127.0.0.1，没有另一个地址可以来，那里只查上面这一半。
    if cfg!(target_os = "macos") {
        return;
    }
    let stream = connect_from("127.0.0.2:0", &relay).await;
    assert_eq!(stream.local_addr().unwrap().ip().to_string(), "127.0.0.2");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = i3t_underlay::tcp_leg::FrameReader::new(read_half);
    send_frame(&mut write_half, &Init { node: honest.id, nonce: [3; 8] }.to_bytes()).await.unwrap();
    let reply = tokio::time::timeout(WAIT, reader.next()).await.unwrap().unwrap().unwrap();
    let Some(Frame::Challenge(challenge)) = Frame::parse(&reply) else { panic!("应该是 CHALLENGE：{reply:?}") };
    let auth = honest.auth(node(RELAY_ID), [3; 8], challenge.cookie);
    send_frame(&mut write_half, &auth.to_bytes()).await.unwrap();
    let reply = tokio::time::timeout(WAIT, reader.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(Frame::parse(&reply), Some(Frame::Ok(_))));
    assert!(relay.relay().has_session(honest.id));
    drop(held);
}
