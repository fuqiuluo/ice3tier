//! 版本怎么谈，以及和没升级的节点（`i3t-lane/1`）之间两边各自开的 passthrough 流怎么走（issue #34）；
//! 另含需要查看流内部状态的用例，例如被对端叫停后发送方向如何结束（issue #75）。
//!
//! 没升级的节点用这里的帧层照它的样子写出来：它只提供 `i3t-lane/1`；它开 passthrough 的流时 OPENING 是 [`Mode::Early`]，
//! 那条记录之后紧跟着不加密的字节。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use i3t_conn::{Payload, RecvStream, SendStream, StreamAborted, StreamCode};
use i3t_crypto::NodeKey;
use i3t_crypto::tls::Identity;
use i3t_proto::flow::{Class, Open, Origin, Reason, Reply, Status, Target};
use i3t_proto::{NodeId, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::dialler::await_opening;
use crate::endpoint::{LaneConfig, LanePeer, Lanes};
use crate::error::LaneError;
use crate::frame::{Frame, Mode, Purpose};
use crate::lane::{self, ALPN, ALPN_V1, Dial, Lane, Version};
use crate::status::Book;
use crate::stream::{LaneRecv, LaneSend, RecvState, SendState};

/// 升级了的节点提供的版本，和 [`lane::client_config`]、[`lane::server_config`] 里的一样。
const NEW: &[&[u8]] = &[ALPN, ALPN_V1];
/// 没升级的节点只有这一个。
const OLD: &[&[u8]] = &[ALPN_V1];

const PATIENCE: Duration = Duration::from_secs(5);

fn id(raw: u32) -> NodeId {
    NodeId::new(raw).unwrap()
}

/// `key` 的节点只提供 `alpn` 里的版本，拨 `addr` 上的 `to`：一条给它自己开流用的 lane，HELLO 已经发出。
async fn dial(key: &NodeKey, to: PublicKey, addr: SocketAddr, alpn: &[&[u8]]) -> Lane {
    let mut config = Arc::unwrap_or_clone(lane::client_config(&Identity::new(key).unwrap(), to).unwrap());
    config.alpn_protocols = alpn.iter().map(|alpn| alpn.to_vec()).collect();
    let addrs = [addr];
    let membership = watch::channel(()).1;
    let deadline = Instant::now() + PATIENCE;
    let dial = Dial { addrs: &addrs, config: Arc::new(config), peer: id(1), membership, purpose: Purpose::Own, epoch: 1, deadline };
    let (mut lane, _) = lane::dial(dial).await.unwrap();
    // `dial` 只把 HELLO 排进待发的密文。
    lane.flush().await.unwrap();
    lane
}

/// 回环上握完手的一条 lane 的两头：拨号方提供 `dialler` 里的版本，接受方认 `acceptor` 里的。返回（拨号方的，接受方的）。
async fn ends(dialler: &[&[u8]], acceptor: &[&[u8]]) -> (Lane, Lane) {
    ends_on(TcpListener::bind("127.0.0.1:0").await.unwrap(), dialler, acceptor).await
}

/// 和 [`ends`] 一样，接受方在 `listener` 上接（调用方可以先给它设好接收缓冲，接进来的连接从握手起就照它通告窗口）。
async fn ends_on(listener: TcpListener, dialler: &[&[u8]], acceptor: &[&[u8]]) -> (Lane, Lane) {
    let (dialler_key, acceptor_key) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let dialler_public = dialler_key.public();
    let mut server =
        Arc::unwrap_or_clone(lane::server_config(&Identity::new(&acceptor_key).unwrap(), move |key| *key == dialler_public).unwrap());
    server.alpn_protocols = acceptor.iter().map(|alpn| alpn.to_vec()).collect();
    let addr = listener.local_addr().unwrap();
    // 接受方读 HELLO 时也看着它：发送的一头丢了就当作对端被拿掉了。
    let (_members, membership) = watch::channel(());
    let deadline = Instant::now() + PATIENCE;
    tokio::join!(dial(&dialler_key, acceptor_key.public(), addr, dialler), async {
        let (socket, _) = listener.accept().await.unwrap();
        lane::accept(socket, BytesMut::new(), Arc::new(server), |_| Some((id(2), membership.clone())), deadline, deadline).await.unwrap()
    })
}

fn book() -> Book {
    Book { node: Arc::default(), peer: Arc::default() }
}

/// 本端在 `lane` 上发起一条流。
fn initiate(lane: Lane) -> (LaneSend, LaneRecv) {
    super::initiate(lane, book(), watch::channel(false).1)
}

/// 本端在 `lane` 上等对方开流，接下它。返回两个方向和 OPENING 里的负载方式。
async fn respond(mut lane: Lane) -> (LaneSend, LaneRecv, Mode) {
    let opening = await_opening(&mut lane).await.unwrap().expect("对方没有开流就关了 lane");
    let (send, recv) = super::respond(lane, opening.mode, &opening.header, book(), watch::channel(false).1);
    (send, recv, opening.mode)
}

/// 没升级的发起方开 passthrough 的流：OPENING 是 [`Mode::Early`]，装着 `header`；它所在的记录之后紧跟着 `raw`，不加密。
async fn open_as_old_node(lane: &mut Lane, header: &[u8], raw: &[u8]) {
    lane.queue(&Frame::Opening { mode: Mode::Early, header: Bytes::copy_from_slice(header) });
    lane.flush().await.unwrap();
    lane::write_all(&lane.socket, &mut BytesMut::from(raw)).await.unwrap();
}

async fn read_to_end(recv: &mut LaneRecv) -> io::Result<Vec<u8>> {
    let mut all = Vec::new();
    tokio::time::timeout(PATIENCE, recv.read_to_end(&mut all)).await.expect("读等得太久")?;
    Ok(all)
}

/// 两个升级了的节点之间的一条流：发起方写完 OPEN 并以 `payload` 结束头，接受方读完 OPEN。返回（发起方的，接受方的）。
async fn stream_on(dialled: Lane, accepted: Lane, payload: Payload) -> ((LaneSend, LaneRecv), (LaneSend, LaneRecv)) {
    let (mut send, recv) = initiate(dialled);
    send.write_all(b"OPEN").await.unwrap();
    send.end_header(payload);
    let (far_send, mut far_recv, _) = respond(accepted).await;
    let mut open = [0; 4];
    far_recv.read_exact(&mut open).await.unwrap();
    far_recv.end_header();
    ((send, recv), (far_send, far_recv))
}

/// 持续写入 `send`，直至无法继续写入：连续两次、间隔一段时间均无法写入才算写满（刚写入的数据仍在传输时，发送缓冲会腾出少量空间）。
#[cfg(target_os = "linux")]
async fn fill_until_stuck(send: &mut LaneSend) {
    let chunk = vec![7; 16 * 1024];
    let mut stuck = 0;
    while stuck < 2 {
        if tokio::time::timeout(Duration::from_millis(100), send.write_all(&chunk)).await.is_ok() {
            stuck = 0;
        } else {
            stuck += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// `send` 已被对端以 `code` 叫停：不交出原始句柄，写入返回叫停的原因码。
async fn assert_refused(send: &mut LaneSend, code: u32, what: &str) {
    assert!(send.take_raw().is_none(), "{what}：被叫停的方向不得交出原始句柄");
    let error = send.write_all(b"more").await.expect_err("被叫停的方向写入应失败");
    assert_eq!(StreamAborted::of(&error), Some(StreamAborted::Stopped(StreamCode(code))), "{what}");
}

#[tokio::test]
async fn upgraded_nodes_agree_on_v2_and_an_old_node_at_either_end_gets_v1() {
    for (what, dialler, acceptor, expected) in
        [("都升级了", NEW, NEW, Version::V2), ("拨号方没升级", OLD, NEW, Version::V1), ("接受方没升级", NEW, OLD, Version::V1)]
    {
        let (dialled, accepted) = ends(dialler, acceptor).await;
        assert_eq!((dialled.version, accepted.version), (expected, expected), "{what}");
    }
}

/// 本端开的 passthrough 流：两头都升级了时 OPENING 是 [`Mode::Mutual`]；对端没升级时是 sealed（那边不认"等 SWITCH"，
/// 本端也不再在 OPENING 之后马上离开 TLS），那边照旧读得懂，接受方说可以不加密了也一直加密。拨号方和接受方开流都一样。
#[tokio::test]
async fn a_passthrough_stream_towards_an_old_node_is_opened_sealed_and_still_works() {
    for (what, dialler, acceptor, expected) in
        [("都升级了", NEW, NEW, Mode::Mutual), ("拨号方没升级", OLD, NEW, Mode::Sealed), ("接受方没升级", NEW, OLD, Mode::Sealed)]
    {
        for dialler_initiates in [true, false] {
            let (dialled, accepted) = ends(dialler, acceptor).await;
            let (near, far) = if dialler_initiates { (dialled, accepted) } else { (accepted, dialled) };
            let (mut send, mut recv) = initiate(near);
            send.write_all(b"OPEN").await.unwrap();
            send.end_header(Payload::Passthrough);
            let (mut far_send, mut far_recv, mode) = respond(far).await;
            assert_eq!(mode, expected, "{what}，拨号方开流：{dialler_initiates}");
            assert_eq!(far_recv.payload(), Some(expected.payload()));

            let mut open = [0; 4];
            far_recv.read_exact(&mut open).await.unwrap();
            assert_eq!(&open, b"OPEN");
            far_recv.end_header();
            far_send.write_all(b"REPLY").await.unwrap();
            far_send.end_header(Payload::Passthrough);
            if expected == Mode::Sealed {
                assert!(far_send.take_raw().is_none(), "{what}：sealed 的流上接受方不切换");
            }
            far_send.write_all(b", answer").await.unwrap();
            far_send.shutdown().await.unwrap();
            let mut reply = [0; 5];
            recv.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"REPLY");
            recv.end_header();
            assert_eq!(read_to_end(&mut recv).await.unwrap(), b", answer", "{what}");
            send.write_all(b", request").await.unwrap();
            send.shutdown().await.unwrap();
            assert_eq!(read_to_end(&mut far_recv).await.unwrap(), b", request", "{what}");
        }
    }
}

/// 没升级的发起方开的 passthrough 流照旧：它的方向在 OPENING 之后就是原始字节，头读完之后按顺序接着交出来；
/// 接受方的 SWITCH 之后也是原始字节。
#[tokio::test]
async fn an_old_initiators_passthrough_stream_still_works() {
    let (mut old, new) = ends(OLD, NEW).await;
    open_as_old_node(&mut old, b"OPEN first data", b", raw data").await;
    crate::socket::shutdown_write(&old.socket).unwrap();
    let (mut send, mut recv, mode) = respond(new).await;
    assert_eq!(mode, Mode::Early);
    let mut open = [0; 4];
    recv.read_exact(&mut open).await.unwrap();
    assert_eq!(&open, b"OPEN");
    recv.end_header();
    assert_eq!(read_to_end(&mut recv).await.unwrap(), b" first data, raw data");

    send.write_all(b"REPLY").await.unwrap();
    send.end_header(Payload::Passthrough);
    send.write_all(b" raw answer").await.unwrap();
    send.shutdown().await.unwrap();
    assert!(matches!(old.read_frame().await.unwrap(), Some(Frame::Data(reply)) if reply[..] == b"REPLY"[..]));
    assert_eq!(old.read_frame().await.unwrap(), Some(Frame::Switch));
    assert!(old.sealed.at_record_boundary(), "SWITCH 是它那条记录里的最后一个帧");
    let mut answer = old.sealed.take_inbound();
    loop {
        match tokio::time::timeout(PATIENCE, lane::read_more(&old.socket, &mut answer)).await.expect("读等得太久") {
            Ok(()) => {}
            Err(LaneError::Closed) => break,
            Err(error) => panic!("{error}"),
        }
    }
    assert_eq!(&answer[..], b" raw answer");
}

/// 流层的头只能来自 TLS 里面：没升级的发起方在 OPENING 里只放了半个头、另一半跟在原始字节里时（路上的人改得了的就是这一半），
/// 读出错，不会把后面的原始字节当作头交出来（issue #17）。
#[tokio::test]
async fn an_old_initiator_cannot_complete_a_header_with_bytes_from_outside_tls() {
    let (mut old, new) = ends(OLD, NEW).await;
    open_as_old_node(&mut old, b"OP", b"EN, then data").await;
    let (_send, mut recv, _) = respond(new).await;
    let mut got = [0; 2];
    recv.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"OP");
    let error = recv.read_exact(&mut got).await.expect_err("头的另一半不在 TLS 里，不能交出来");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
}

/// [`Mode::Mutual`] 的流上发起方的 SWITCH 只能是回应：接受方自己还没切换时收到它是协议错误，后面的原始字节不交出去。
/// 所以接受方看过目标的回答之前，发起方的方向上不会有一个字节不加密。
#[tokio::test]
async fn an_initiator_switch_that_answers_nothing_is_a_protocol_error() {
    let (mut initiator, new) = ends(NEW, NEW).await;
    initiator.queue(&Frame::Opening { mode: Mode::Mutual, header: Bytes::from_static(b"OPEN") });
    initiator.queue(&Frame::Switch);
    initiator.flush().await.unwrap();
    lane::write_all(&initiator.socket, &mut BytesMut::from(&b"plaintext before the responder switched"[..])).await.unwrap();
    let (_send, mut recv, mode) = respond(new).await;
    assert_eq!(mode, Mode::Mutual);
    let mut open = [0; 4];
    recv.read_exact(&mut open).await.unwrap();
    recv.end_header();
    let error = read_to_end(&mut recv).await.expect_err("没有人要的 SWITCH");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
}

/// 发起方回应的 SWITCH 还没交给内核（发送缓冲满着）时，接收方向不交出去：那时由后台任务去写它，撞上对端的重置时拿走的
/// 错误（Linux 上只报一次）只记在流里，交出去的接收方向读到的只是 EOF，会被当成正常结束。排空之后照常交出去。
///
/// 只在 Linux 上跑：要写满得靠对端的小接收缓冲，Linux 设了 `SO_RCVBUF` 就照它，别的系统还会自己往大里调，窗口慢慢打开，
/// 排着的回应随后就写出去了，"写不动"等不稳。只报一次错的也正是 Linux。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_read_side_stays_in_the_stream_while_the_answering_switch_is_still_queued() {
    use socket2::SockRef;

    // 缓冲调小：接受方不读时，发起方很快就写不动。接收缓冲要在接受连接之前设，窗口从握手起就是小的。
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    SockRef::from(&listener).set_recv_buffer_size(4096).unwrap();
    let (dialled, accepted) = ends_on(listener, NEW, NEW).await;
    SockRef::from(&*dialled.socket).set_send_buffer_size(4096).unwrap();
    let (mut send, mut recv) = initiate(dialled);
    send.write_all(b"OPEN").await.unwrap();
    send.end_header(Payload::Passthrough);
    let (mut far_send, mut far_recv, _) = respond(accepted).await;
    let mut open = [0; 4];
    far_recv.read_exact(&mut open).await.unwrap();
    far_recv.end_header();
    fill_until_stuck(&mut send).await;

    far_send.write_all(b"REPLY").await.unwrap();
    far_send.end_header(Payload::Passthrough);
    let mut reply = [0; 5];
    recv.read_exact(&mut reply).await.unwrap();
    recv.end_header();
    // SWITCH 跟在 REPLY 后面，可能还在路上。收到时发起方回应，回应排在写不动的密文后面。
    tokio::time::timeout(PATIENCE, async {
        while !recv.shared.lock().switched {
            assert!(recv.wait_raw().await.is_none(), "回应的 SWITCH 还没交给内核时，接收方向不交出去");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("发起方没有回应接受方的 SWITCH");
    assert!(!recv.shared.lock().out.is_empty(), "发送缓冲满着，回应应该还排在待发的密文里");
    assert!(recv.wait_raw().await.is_none(), "回应的 SWITCH 还没交给内核时，接收方向不交出去");

    // 接受方读走之后，后台任务把回应写完，两头的接收方向都交得出去。
    let far = tokio::spawn(async move {
        let mut buf = vec![0; 64 * 1024];
        loop {
            if let Some(raw) = far_recv.wait_raw().await {
                return raw;
            }
            assert!(far_recv.read(&mut buf).await.unwrap() > 0, "发起方的 SWITCH 之前不该结束");
        }
    });
    tokio::time::timeout(PATIENCE, async {
        while recv.wait_raw().await.is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("回应写完之后接收方向应该交得出去");
    tokio::time::timeout(PATIENCE, far).await.expect("接受方没有等到发起方的 SWITCH").unwrap();
}

/// 被对端叫停（STOP）的发送方向，flush 与 shutdown 均返回叫停的原因码，且不发出 close_notify 与 FIN：对端已不再读取，
/// 此前写入的数据未必全部送达，不能按正常结束处理（issue #75）。发起方与接受方各被叫停一次。
#[tokio::test]
async fn a_stopped_direction_neither_flushes_nor_shuts_down_cleanly() {
    for initiator_stopped in [true, false] {
        let (dialled, accepted) = ends(NEW, NEW).await;
        let (initiator, responder) = stream_on(dialled, accepted, Payload::Sealed).await;
        let ((mut send, mut recv), (mut peer_send, mut peer_recv)) =
            if initiator_stopped { (initiator, responder) } else { (responder, initiator) };
        peer_recv.stop(StreamCode(9));
        peer_send.write_all(b"REPLY").await.unwrap();
        peer_send.shutdown().await.unwrap();
        // STOP 排在 REPLY 之前：读完 REPLY 时本端已处理 STOP。
        assert_eq!(read_to_end(&mut recv).await.unwrap(), b"REPLY");
        let endings = [("flush", send.flush().await), ("shutdown", send.shutdown().await), ("再次 shutdown", send.shutdown().await)];
        for (what, ended) in endings {
            let error = ended.expect_err("被叫停的方向不能按正常结束处理");
            assert_eq!(
                StreamAborted::of(&error),
                Some(StreamAborted::Stopped(StreamCode(9))),
                "{what}，被叫停的是发起方：{initiator_stopped}"
            );
        }
        assert!(matches!(send.shared.lock().send, SendState::Sealed), "被叫停的方向不得发出 close_notify 与 FIN");
    }
}

/// 已正常结束的发送方向，之后才收到对端的 STOP：再次 shutdown 与 flush 仍然成功，与其他流实现一致（issue #75）。
#[tokio::test]
async fn a_finished_direction_still_shuts_down_cleanly_after_a_late_stop() {
    let (dialled, accepted) = ends(NEW, NEW).await;
    let ((mut send, mut recv), (mut far_send, mut far_recv)) = stream_on(dialled, accepted, Payload::Sealed).await;
    send.shutdown().await.unwrap();
    // 接受方尚未读到 close_notify 即叫停：STOP 照常发出。
    far_recv.stop(StreamCode(9));
    far_send.write_all(b"REPLY").await.unwrap();
    far_send.shutdown().await.unwrap();
    assert_eq!(read_to_end(&mut recv).await.unwrap(), b"REPLY");
    assert_eq!(send.shared.lock().send_refused, Some(StreamAborted::Stopped(StreamCode(9))), "STOP 应已送达");
    send.shutdown().await.expect("已正常结束的方向，再次 shutdown 仍应成功");
    send.flush().await.expect("已正常结束的方向，flush 仍应成功");
}

/// 被叫停的方向不再离开 TLS，也不交出原始的发送方向：交出后写入绕过 [`LaneSend`]，叫停的原因随之丢失（issue #75）。
#[tokio::test]
async fn a_stopped_direction_does_not_leave_tls_or_hand_itself_out() {
    // 接受方先被叫停，随后才要切换。发起方的方向仍在 TLS 内（等待接受方的 SWITCH），STOP 可以发出。
    let (dialled, accepted) = ends(NEW, NEW).await;
    let ((mut send, mut recv), (mut far_send, mut far_recv)) = stream_on(dialled, accepted, Payload::Passthrough).await;
    recv.stop(StreamCode(4));
    send.write_all(b"!").await.unwrap();
    // STOP 排在这个字节之前。
    far_recv.read_exact(&mut [0; 1]).await.unwrap();
    far_send.end_header(Payload::Passthrough);
    assert!(matches!(far_send.shared.lock().send, SendState::Sealed), "被叫停的接受方不再切换");
    assert_refused(&mut far_send, 4, "接受方被叫停后切换").await;

    // 发起方先被叫停，随后才收到接受方的 SWITCH：不再回应切换。
    let (dialled, accepted) = ends(NEW, NEW).await;
    let ((mut send, mut recv), (mut far_send, mut far_recv)) = stream_on(dialled, accepted, Payload::Passthrough).await;
    far_recv.stop(StreamCode(4));
    far_send.write_all(b"REPLY").await.unwrap();
    far_send.end_header(Payload::Passthrough);
    far_send.write_all(b"!").await.unwrap();
    let mut reply = [0; 5];
    recv.read_exact(&mut reply).await.unwrap();
    recv.end_header();
    // SWITCH 之后的原始字节：读到时 SWITCH 已处理。
    recv.read_exact(&mut [0; 1]).await.unwrap();
    assert!(matches!(recv.shared.lock().recv, RecvState::Raw(_)), "接受方的方向应已离开 TLS");
    assert!(matches!(send.shared.lock().send, SendState::Sealed), "被叫停的发起方不回应 SWITCH");
    assert_refused(&mut send, 4, "发起方被叫停后收到 SWITCH").await;

    // 接受方已经切换，之后才收到 STOP（发起方尚未读到它的 SWITCH）：方向已是原始字节，同样不交出。
    let (dialled, accepted) = ends(NEW, NEW).await;
    let ((mut send, mut recv), (mut far_send, mut far_recv)) = stream_on(dialled, accepted, Payload::Passthrough).await;
    far_send.end_header(Payload::Passthrough);
    recv.stop(StreamCode(4));
    send.write_all(b"!").await.unwrap();
    far_recv.read_exact(&mut [0; 1]).await.unwrap();
    assert!(matches!(far_send.shared.lock().send, SendState::Raw));
    assert_refused(&mut far_send, 4, "接受方切换后被叫停").await;
}

/// 发送缓冲已满、本端阻塞在 flush 或 shutdown 时，对端发来 STOP 或 ABORT：立即返回叫停的原因码。对端已不再读取，socket 不会再变为可写；
/// 若继续等待，Linux 上会一直等到 `TCP_USER_TIMEOUT`，其他系统上则无限期等待（issue #75）。
///
/// 只在 Linux 上运行，原因同上一个测试。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_flush_or_shutdown_stuck_on_a_full_socket_ends_once_the_peer_stops_or_aborts() {
    use socket2::SockRef;

    for (abort, shutdown) in [(false, false), (false, true), (true, false), (true, true)] {
        let what = format!("{}，对端{}", if shutdown { "shutdown" } else { "flush" }, if abort { "重置" } else { "叫停" });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        SockRef::from(&listener).set_recv_buffer_size(4096).unwrap();
        let (dialled, accepted) = ends_on(listener, NEW, NEW).await;
        SockRef::from(&*dialled.socket).set_send_buffer_size(4096).unwrap();
        let ((mut send, mut recv), (mut far_send, mut far_recv)) = stream_on(dialled, accepted, Payload::Sealed).await;
        fill_until_stuck(&mut send).await;
        // 接收方向持续读取：STOP 与 ABORT 由它处理。
        let reading = tokio::spawn(async move {
            let mut sink = Vec::new();
            let _ = recv.read_to_end(&mut sink).await;
        });
        let ending = async { if shutdown { send.shutdown().await } else { send.flush().await } };
        tokio::pin!(ending);
        assert!(tokio::time::timeout(Duration::from_millis(200), &mut ending).await.is_err(), "{what}：发送缓冲已满，应等待 socket 可写");
        if abort {
            far_send.reset(StreamCode(9));
        } else {
            far_recv.stop(StreamCode(9));
        }
        let error = tokio::time::timeout(PATIENCE, ending)
            .await
            .unwrap_or_else(|_| panic!("{what}：收到之后仍在等待 socket 可写"))
            .expect_err("被叫停的方向不能按正常结束处理");
        assert_eq!(StreamAborted::of(&error), Some(StreamAborted::Stopped(StreamCode(9))), "{what}");
        reading.abort();
    }
}

/// 出口：只数见过几个请求，然后拒绝。
struct Watching(Arc<AtomicUsize>);

impl i3t_flow::Handler for Watching {
    async fn handle<S: SendStream, R: RecvStream>(&self, request: i3t_flow::Request<S, R>) {
        self.0.fetch_add(1, Ordering::Relaxed);
        request.refuse(&Reply::new(Status::AccessDenied, "测试")).await;
    }
}

/// 流层也一样：没升级的节点开过来的流，OPEN 的后一半跟在原始字节里时，出口的流层以协议错误重置流，处理者见不到这个请求
/// （issue #17）。升级了的发起方在接受方切换之前不会离开 TLS，用不着这一条；没升级的还会。
#[tokio::test]
async fn the_flow_layer_does_not_take_an_open_that_an_old_node_completed_outside_tls() {
    let (old_key, new_key) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let lanes = Arc::new(Lanes::new(&new_key, LaneConfig::default()).unwrap());
    lanes.set_peers([LanePeer { id: id(1), key: old_key.public(), dial: Vec::new() }]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(Watching(Arc::clone(&seen)));
    let serving = Arc::clone(&lanes);
    tokio::spawn(async move { tokio::join!(serving.serve(listener), i3t_flow::serve(&*serving, handler)) });

    let mut old = dial(&old_key, new_key.public(), addr, OLD).await;
    let mut open = Vec::new();
    Open { target: Target::Node { port: 443 }, class: Class::Auto, origin: Origin::default() }.encode(&mut open);
    let (sealed, raw) = open.split_at(open.len() / 2);
    open_as_old_node(&mut old, sealed, &[raw, &i3t_flow::testing::client_hello(b"")].concat()).await;
    let answer = tokio::time::timeout(PATIENCE, old.read_frame()).await.expect("等出口的回答等得太久").unwrap();
    assert_eq!(answer, Some(Frame::Abort(Reason::ProtocolError.to_wire())), "出口应该以协议错误重置这条流");
    assert_eq!(seen.load(Ordering::Relaxed), 0, "处理者不该见到这个请求");
}
