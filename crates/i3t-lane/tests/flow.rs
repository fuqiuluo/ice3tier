//! 流层跑在 lane 上：客户端 TCP ↔ 入口 ↔ lane ↔ 出口 ↔ 目标 TCP。
//!
//! 流层自己（`i3t_flow::open`、`serve`、`Flow::relay`）在头写完时结束头，首批数据是 TLS 时走 passthrough，
//! 搬运时把不再加密的方向交给 splice。`stand_in` 是同样几步的手写版本，给要在中间看着线上字节的测试用。

// clippy.toml 里的 allow-unwrap-in-tests 只管 #[test] 函数，管不到集成测试里的辅助函数。这里 unwrap 失败就是测试失败。
#![allow(clippy::unwrap_used)]

mod common;

use std::future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Hop, Pair, quick, wait_for};
use i3t_conn::{RecvStream, SendStream, StreamAborted, StreamCode};
use i3t_flow::engine::Splicer;
use i3t_flow::testing::{client_hello, server_hello};
use i3t_flow::{End, FlowError, Handler, Request};
use i3t_lane::{Lanes, Payload};
use i3t_proto::NodeId;
use i3t_proto::flow::{Class, Open, Origin, Reason, Reply, Target};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(10);
/// 一条流上来回搬的字节数：比 TLS 的一个记录（16 KB）和套接字的缓冲都大得多。
const BULK: u32 = 150_000;

fn open_request() -> Open {
    Open { target: Target::Node { port: 443 }, class: Class::Auto, origin: Origin::default() }
}

/// 出口：每条流都连到 `target`，然后用流层自己的搬运。每次搬运的结局记在 `ends` 里，测试失败时说出来。
struct ToTarget {
    target: SocketAddr,
    ends: Arc<Mutex<Vec<String>>>,
}

impl ToTarget {
    fn new(target: SocketAddr) -> Self {
        Self { target, ends: Arc::default() }
    }
}

impl Handler for ToTarget {
    async fn handle<S: SendStream, R: RecvStream>(&self, request: Request<S, R>) {
        let target = TcpStream::connect(self.target).await.unwrap();
        let flow = request.accept().await.unwrap();
        let summary = flow.relay(target, future::pending()).await;
        self.ends.lock().unwrap().push(format!("{:?}", summary.end));
    }
}

/// 一对连好的 TCP：`near` 是测试扮演的那一头，`far` 交给被测的搬运。
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let near = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (far, _) = listener.accept().await.unwrap();
    (near, far)
}

/// 一个目标：把收到的每个字节原样送回去，对方结束了它也结束。
async fn echo_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    addr
}

/// 一个 TLS 1.3 目标的替身：先回一个 ServerHello（出口往回的方向在它之后才不再加密），然后把收到的每个字节原样送回去。
async fn tls13_echo_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                stream.write_all(&server_hello()).await.unwrap();
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    addr
}

/// 一个目标：读到请求的第一块之后回一半的答案，然后用 RST 断开。
async fn resetting_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0; 9];
                let _ = stream.read_exact(&mut request).await;
                stream.write_all(b"half of the ans").await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                stream.set_zero_linger().unwrap();
            });
        }
    });
    addr
}

/// 回 ServerHello 之后、密文回到一半时重置的 TLS 1.3 目标给的那一半。
const HALF_ANSWER: &[u8] = b"\x17\x03\x03\x00\x40half of an encrypted answer";

/// 一个 TLS 1.3 目标：读到 ClientHello 之后回 ServerHello 和半截密文，过 `pause` 之后用 RST 断开。
async fn tls13_resetting_target(pause: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut hello = vec![0; client_hello(b"").len()];
                let _ = stream.read_exact(&mut hello).await;
                stream.write_all(&[&server_hello()[..], HALF_ANSWER].concat()).await.unwrap();
                tokio::time::sleep(pause).await;
                stream.set_zero_linger().unwrap();
            });
        }
    });
    addr
}

/// 读到 EOF 或者出错。返回读到的字节，和是不是正常结束的。
async fn drain(stream: &mut (impl AsyncRead + Unpin)) -> (Vec<u8>, io::Result<()>) {
    let mut all = Vec::new();
    let mut buf = [0; 8192];
    loop {
        match timeout(PATIENCE, stream.read(&mut buf)).await.expect("读等得太久") {
            Ok(0) => return (all, Ok(())),
            Ok(len) => all.extend_from_slice(&buf[..len]),
            Err(error) => return (all, Err(error)),
        }
    }
}

/// 流层：入口用 `open` + `established` + `relay`，出口用 `serve`。
async fn through_flow(lanes: &Lanes, peer: NodeId, client_side: TcpStream, first_data: &[u8]) -> End {
    let pending = i3t_flow::open(lanes, peer, &open_request(), first_data, i3t_flow::Carriage::Lane).await.unwrap();
    let flow = pending.established().await.unwrap();
    flow.relay(client_side, future::pending()).await.end
}

#[tokio::test]
async fn the_flow_layer_runs_sealed_on_lanes_in_both_directions_of_initiative() {
    let pair = Pair::new(quick()).await;
    pair.ready(2).await;
    let target = echo_target().await;
    for lanes in [&pair.entry.lanes, &pair.exit.lanes] {
        let lanes = Arc::clone(lanes);
        tokio::spawn(async move { i3t_flow::serve(&*lanes, Arc::new(ToTarget::new(target))).await });
    }
    for (from, to) in [(&pair.entry, &pair.exit), (&pair.exit, &pair.entry)] {
        let (mut client, client_side) = tcp_pair().await;
        let lanes = Arc::clone(&from.lanes);
        let peer = to.id;
        let relay = tokio::spawn(async move { through_flow(&lanes, peer, client_side, b"first ").await });
        let body: Vec<u8> = (0..200_000u32).map(|i| u8::try_from(i % 249).unwrap()).collect();
        client.write_all(&body).await.unwrap();
        client.shutdown().await.unwrap();
        let (echoed, end) = drain(&mut client).await;
        end.unwrap();
        let mut expected = b"first ".to_vec();
        expected.extend_from_slice(&body);
        assert_eq!(echoed.len(), expected.len());
        assert!(echoed == expected, "回显的字节不一样");
        assert!(relay.await.unwrap().is_clean());
    }
    let status = pair.entry.lanes.status();
    assert!(status.total.sealed_bytes >= 400_000, "{status:?}");
    assert_eq!(status.total.passthrough_bytes + status.total.spliced_bytes, 0, "首批数据不是 TLS，一律是 sealed");
}

#[tokio::test]
async fn the_flow_layer_passes_tls_through_and_splices_it() {
    let pair = Pair::new(quick()).await;
    pair.ready(1).await;
    let target = tls13_echo_target().await;
    let lanes = Arc::clone(&pair.exit.lanes);
    let exit = Arc::new(ToTarget::new(target));
    let exit_ends = Arc::clone(&exit.ends);
    tokio::spawn(async move { i3t_flow::serve(&*lanes, exit).await });
    let (mut client, client_side) = tcp_pair().await;
    let lanes = Arc::clone(&pair.entry.lanes);
    let peer = pair.exit.id;
    let hello = client_hello(b"");
    let first = hello.clone();
    let relay = tokio::spawn(async move { through_flow(&lanes, peer, client_side, &first).await });
    // 像真的 TLS 客户端一样，等到服务器的第一批回答（这里是 ServerHello 和回显的 ClientHello）再往下发：
    // 入口的方向要等出口切换了才跟着切换，在那之前发的照样加密。
    let mut flight = vec![0; server_hello().len() + hello.len()];
    timeout(PATIENCE, client.read_exact(&mut flight)).await.unwrap().unwrap();
    assert!(flight == [&server_hello()[..], &hello].concat(), "服务器的第一批回答不一样");
    let body: Vec<u8> = (0..3_000_000u32).map(|i| u8::try_from(i % 239).unwrap()).collect();
    let (mut from_target, mut to_target) = client.split();
    // 一边发一边收，各自记下走到了哪里：macOS 上这里曾经一直不结束，等不到时要能看出卡在哪一段。
    let (sent, received) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let exchange = async {
        tokio::join!(
            async {
                for piece in body.chunks(64 * 1024) {
                    to_target.write_all(piece).await.unwrap();
                    sent.fetch_add(piece.len(), Ordering::Relaxed);
                }
                to_target.shutdown().await.unwrap();
            },
            async {
                let (mut echoed, mut buf) = (Vec::new(), vec![0; 64 * 1024]);
                let end = loop {
                    match from_target.read(&mut buf).await {
                        Ok(0) => break Ok(()),
                        Ok(len) => {
                            echoed.extend_from_slice(&buf[..len]);
                            received.fetch_add(len, Ordering::Relaxed);
                        }
                        Err(error) => break Err(error),
                    }
                };
                (echoed, end)
            }
        )
    };
    let Ok(((), (echoed, end))) = timeout(PATIENCE, exchange).await else {
        let hop: Vec<_> = pair
            .hop
            .recordings
            .lock()
            .unwrap()
            .iter()
            .map(|recording| {
                let recording = recording.lock().unwrap();
                (recording.forward.len(), recording.forward_end, recording.backward.len(), recording.backward_end)
            })
            .collect();
        panic!(
            "{PATIENCE:?} 之内没有回显完：客户端发出 {} 字节、收回 {} 字节，入口的搬运{}结束；入口 {:?}；出口 {:?}；\
             出口的搬运的结局 {:?}；中间一跳每条连接的（出口到入口的字节、结局，入口到出口的字节、结局）{hop:?}",
            sent.load(Ordering::Relaxed),
            received.load(Ordering::Relaxed),
            if relay.is_finished() { "已经" } else { "还没有" },
            pair.entry.lanes.status().total,
            pair.exit.lanes.status().total,
            exit_ends.lock().unwrap(),
        );
    };
    if let Err(error) = end {
        panic!("回显收到 {} 字节之后读出错 {error:?}；出口的搬运的结局 {:?}", echoed.len(), exit_ends.lock().unwrap());
    }
    assert!(echoed == body, "回显的字节不一样");
    assert!(timeout(PATIENCE, relay).await.expect("客户端读完之后入口的搬运应该结束").unwrap().is_clean());
    let entry = pair.entry.lanes.status();
    let exit = pair.exit.lanes.status();
    // 两头都把不再加密的方向交给了搬运引擎：每个方向的数据都过了 splice（非 Linux 上是用户态拷贝，同样经引擎）。
    assert!(entry.total.spliced_bytes >= 2 * 3_000_000, "{entry:?}");
    assert!(exit.total.spliced_bytes >= 2 * 3_000_000, "{exit:?}");
    assert!(entry.total.sealed_bytes < 1024, "加密的只有开流时的头、REPLY 和目标的 ServerHello：{entry:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_revocation_resets_both_ends_of_an_active_passthrough_relay() {
    let pair = Pair::direct(quick()).await;
    pair.ready(2).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit = Arc::new(ToTarget::new(target.local_addr().unwrap()));
    let lanes = Arc::clone(&pair.exit.lanes);
    tokio::spawn(async move { i3t_flow::serve(&*lanes, exit).await });

    let (mut client, client_side) = tcp_pair().await;
    let lanes = Arc::clone(&pair.entry.lanes);
    let peer = pair.exit.id;
    let hello = client_hello(b"");
    let first = hello.clone();
    let relay = tokio::spawn(async move { through_flow(&lanes, peer, client_side, &first).await });
    let (mut target, _) = timeout(PATIENCE, target.accept()).await.unwrap().unwrap();

    // 先正常搬一轮，让两边的搬运任务都已经拿到原始 socket。
    timeout(PATIENCE, async {
        let mut first = vec![0; hello.len()];
        target.read_exact(&mut first).await.unwrap();
        assert_eq!(first, hello);
        // 目标先回 ServerHello：之后往回的方向才不再加密，入口那边跟着切换。
        target.write_all(&[&server_hello()[..], b"reply"].concat()).await.unwrap();
        let mut answer = vec![0; server_hello().len() + 5];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [&server_hello()[..], b"reply"].concat());
        client.write_all(b"request").await.unwrap();
        let mut body = [0; 7];
        target.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"request");
    })
    .await
    .unwrap();
    wait_for("请求和应答都已走原始 socket", PATIENCE, || {
        [&pair.entry.lanes, &pair.exit.lanes].iter().all(|lanes| lanes.status().total.spliced_bytes >= 12)
    })
    .await;

    pair.entry.lanes.set_peers([]).unwrap();

    let ((_, client_end), (_, target_end)) = tokio::join!(drain(&mut client), drain(&mut target));
    assert!(client_end.is_err(), "客户端应看到连接重置，实际是 {client_end:?}");
    assert!(target_end.is_err(), "目标应看到连接重置，实际是 {target_end:?}");
    let entry_end = timeout(PATIENCE, relay).await.unwrap().unwrap();
    assert!(matches!(entry_end, End::Cancelled(Reason::AccessRevoked)), "{entry_end:?}");
}

#[tokio::test]
async fn an_upstream_reset_in_the_middle_of_an_answer_reaches_the_client_as_a_reset_through_the_flow_layer() {
    let pair = Pair::new(quick()).await;
    pair.ready(1).await;
    let target = resetting_target().await;
    let lanes = Arc::clone(&pair.exit.lanes);
    tokio::spawn(async move { i3t_flow::serve(&*lanes, Arc::new(ToTarget::new(target))).await });
    let (mut client, client_side) = tcp_pair().await;
    let lanes = Arc::clone(&pair.entry.lanes);
    let peer = pair.exit.id;
    let relay = tokio::spawn(async move { through_flow(&lanes, peer, client_side, b"").await });
    client.write_all(b"request!!").await.unwrap();
    let (got, end) = drain(&mut client).await;
    assert_eq!(got, b"half of the ans");
    let error = end.expect_err("半截的回答之后必须是重置，不能是正常结束");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert!(!relay.await.unwrap().is_clean());
}

/// 不再加密的流也一样：目标回了 TLS 1.3 的 ServerHello 和半截密文之后重置，客户端看到的是重置，不是正常结束。
/// 立刻重置时，入口回应出口的 SWITCH 那一刻 lane 可能已经被重置了：Linux 上那次写拿走的错误不能让读的一方当成 FIN。
#[tokio::test]
async fn an_upstream_reset_after_a_tls13_server_hello_reaches_the_client_as_a_reset_through_the_flow_layer() {
    for pause in [Duration::ZERO, Duration::from_millis(50)] {
        for _ in 0..3 {
            let pair = Pair::new(quick()).await;
            pair.ready(1).await;
            let target = tls13_resetting_target(pause).await;
            let lanes = Arc::clone(&pair.exit.lanes);
            tokio::spawn(async move { i3t_flow::serve(&*lanes, Arc::new(ToTarget::new(target))).await });
            let (mut client, client_side) = tcp_pair().await;
            let lanes = Arc::clone(&pair.entry.lanes);
            let peer = pair.exit.id;
            let relay = tokio::spawn(async move { through_flow(&lanes, peer, client_side, &client_hello(b"")).await });
            let (got, end) = drain(&mut client).await;
            let answer = [&server_hello()[..], HALF_ANSWER].concat();
            assert!(answer.starts_with(&got), "停 {pause:?}：客户端收到的不是目标回的开头");
            let error = end.expect_err("半截的回答之后必须是重置，不能是正常结束");
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "停 {pause:?}：{error}");
            assert!(!timeout(PATIENCE, relay).await.unwrap().unwrap().is_clean(), "停 {pause:?}");
        }
    }
}

/// 流层的头只能来自 TLS 里面：接受方在 REPLY 写完之前就发了 SWITCH，REPLY 的后一半跟在原始字节里时，发起方的流层不把它当作
/// 对端的回复（issue #17）。反方向（发起方的 OPEN 后一半不在 TLS 里）只有没升级的节点做得出来，见 `i3t-lane` 里流的单元测试。
#[tokio::test]
async fn the_flow_layer_does_not_complete_a_reply_with_bytes_from_outside_tls() {
    let pair = Pair::new(quick()).await;
    pair.ready(1).await;
    let exit = Arc::clone(&pair.exit.lanes);
    let responder = tokio::spawn(async move {
        use i3t_conn::Acceptor;
        let incoming = exit.accept().await.unwrap();
        let (mut send, mut recv) = (incoming.send, incoming.recv);
        let _open = stand_in::read_header(&mut recv, i3t_proto::flow::Opening::decode).await;
        let mut reply = Vec::new();
        Reply::ok().encode(&mut reply);
        let (sealed, raw) = reply.split_at(reply.len() / 2);
        send.write_all(sealed).await.unwrap();
        send.end_header(Payload::Passthrough);
        send.write_all(raw).await.unwrap();
        (send, recv)
    });
    let pending =
        i3t_flow::open(&*pair.entry.lanes, pair.exit.id, &open_request(), &client_hello(b""), i3t_flow::Carriage::Lane).await.unwrap();
    let error = pending.established().await.expect_err("REPLY 的后一半不在 TLS 里，不能当作对端答应了");
    assert!(matches!(error, FlowError::Read(_)), "{error:?}");
    drop(responder.await.unwrap());
}

/// 出口回完应答并叫停上传之后，客户端才结束上传：入口的搬运不能算作正常结束，客户端写入的数据对端并未全部读取（issue #75）。
#[tokio::test]
async fn an_upload_the_exit_stopped_does_not_end_clean_when_the_client_finishes_later() {
    let pair = Pair::new(quick()).await;
    pair.ready(1).await;
    let exit = Arc::clone(&pair.exit.lanes);
    let responder = tokio::spawn(async move {
        use i3t_conn::Acceptor;
        let incoming = exit.accept().await.unwrap();
        let (mut send, mut recv) = (incoming.send, incoming.recv);
        let _open = stand_in::read_header(&mut recv, i3t_proto::flow::Opening::decode).await;
        let mut reply = Vec::new();
        Reply::ok().encode(&mut reply);
        send.write_all(&reply).await.unwrap();
        recv.stop(StreamCode(6));
        send.write_all(b"answer").await.unwrap();
        send.shutdown().await.unwrap();
        (send, recv)
    });
    let (mut client, client_side) = tcp_pair().await;
    let lanes = Arc::clone(&pair.entry.lanes);
    let peer = pair.exit.id;
    let relay = tokio::spawn(async move { through_flow(&lanes, peer, client_side, b"").await });
    // 客户端读完应答时，入口已处理排在应答之前的 STOP；此后客户端才结束上传。
    let (answer, end) = drain(&mut client).await;
    end.unwrap();
    assert_eq!(answer, b"answer");
    client.shutdown().await.unwrap();
    let end = timeout(PATIENCE, relay).await.expect("入口的搬运应结束").unwrap();
    assert!(matches!(end, End::Aborted(StreamAborted::Stopped(StreamCode(6)))), "{end:?}");
    drop(responder.await.unwrap());
}

/// 下一阶段流层要做的事的替身。
mod stand_in {
    use std::sync::Arc;

    use i3t_conn::{RecvStream, SendStream as _};
    use i3t_flow::engine::Splicer;
    use i3t_lane::{LaneRecv, LaneSend, Lanes, Payload};
    use i3t_proto::NodeId;
    use i3t_proto::flow::{DecodeError, Decoded, Opening, Reply};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// 照流层的 `header::read`：一次只读解析器要的字节，不多读；读完了告诉流。
    pub async fn read_header<T>(recv: &mut impl RecvStream, decode: fn(&[u8]) -> Result<Decoded<T>, DecodeError>) -> T {
        let mut buf = Vec::new();
        loop {
            match decode(&buf).unwrap() {
                Decoded::Complete { value, .. } => {
                    recv.end_header();
                    return value;
                }
                Decoded::Incomplete { more } => {
                    let have = buf.len();
                    buf.resize(have + more, 0);
                    recv.read_exact(&mut buf[have..]).await.unwrap();
                }
            }
        }
    }

    /// 首批数据：读完整的第一条 TLS 记录（入口模块的 `first_data::read` 的简化版）。
    pub async fn first_data(client: &mut TcpStream) -> Vec<u8> {
        let mut header = [0; 5];
        client.read_exact(&mut header).await.unwrap();
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut record = header.to_vec();
        record.resize(5 + len, 0);
        client.read_exact(&mut record[5..]).await.unwrap();
        record
    }

    /// 两个方向离开 TLS 之后交给 splice。接收方向先照常读、写给 `user`，直到它离开 TLS（`wait_raw`）：接受方这边先是 OPENING 里
    /// 头后面的首批数据，发起方的 SWITCH 跟在后面；发起方这边对端的 SWITCH 可能还在路上，收到时自己的方向才跟着切换。
    pub async fn relay(splicer: &Splicer, mut send: LaneSend, mut recv: LaneRecv, mut user: TcpStream) -> Option<std::io::Error> {
        let raw_recv = loop {
            if let Some(raw) = recv.wait_raw().await {
                break raw;
            }
            let mut buf = [0; 4096];
            let len = recv.read(&mut buf).await.unwrap();
            assert!(len > 0, "这个替身只用在两个方向都会离开 TLS 的流上");
            user.write_all(&buf[..len]).await.unwrap();
        };
        let raw_send = send.take_raw().expect("对端切换之后，发起方的方向跟着切换；接受方的方向在 end_header 时就切换了");
        let (lane, unsent) = raw_send.into_parts();
        let (_, received) = raw_recv.into_parts();
        let relayed = splicer.relay(&user, received, &lane, unsent).await;
        relayed.error.map(|error| std::io::Error::other(error.to_string()))
    }

    /// 入口：开流、写 OPEN 和首批数据、选负载方式、读 REPLY，然后搬运。
    pub async fn initiate(lanes: &Lanes, peer: NodeId, mut client: TcpStream, splicer: &Splicer) -> Option<std::io::Error> {
        let first = first_data(&mut client).await;
        let payload = Payload::for_first_data(&first);
        let (mut send, mut recv) = lanes.open_stream(peer).await.unwrap();
        let mut header = Vec::new();
        super::open_request().encode(&mut header);
        header.extend_from_slice(&first);
        send.write_all(&header).await.unwrap();
        send.end_header(payload);
        let reply = read_header(&mut recv, Reply::decode).await;
        assert!(reply.status.is_ok());
        relay(splicer, send, recv, client).await
    }

    /// 出口：读 OPEN、连目标、回 REPLY、结束头，然后搬运。
    pub async fn respond(lanes: Arc<Lanes>, target: std::net::SocketAddr, splicer: Arc<Splicer>) {
        use i3t_conn::Acceptor;
        while let Some(incoming) = lanes.accept().await {
            let splicer = Arc::clone(&splicer);
            tokio::spawn(async move {
                let (mut send, mut recv) = (incoming.send, incoming.recv);
                let Opening::Stream(_open) = read_header(&mut recv, Opening::decode).await else { panic!("不是流") };
                let target = TcpStream::connect(target).await.unwrap();
                let mut reply = Vec::new();
                Reply::ok().encode(&mut reply);
                send.write_all(&reply).await.unwrap();
                send.end_header(Payload::Passthrough);
                let _ = relay(&splicer, send, recv, target).await;
            });
        }
    }
}

/// 一对 TLS 的两端：服务器的证书由测试自己签，客户端只信它。
mod user_tls {
    use std::sync::Arc;

    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    pub const NAME: &str = "secret-hostname.example";

    pub fn configs() -> (TlsConnector, TlsAcceptor) {
        configs_with(|_| {})
    }

    /// 和 [`configs`] 一样，只是服务器用的密码学套件先交给 `adjust_server` 改一改（比如只留 P-256，逼出 HelloRetryRequest）。
    pub fn configs_with(adjust_server: impl FnOnce(&mut CryptoProvider)) -> (TlsConnector, TlsAcceptor) {
        let issued = rcgen::generate_simple_self_signed(vec![NAME.to_owned()]).unwrap();
        let cert = CertificateDer::from(issued.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(issued.signing_key.serialize_der()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_provider = rustls::crypto::ring::default_provider();
        adjust_server(&mut server_provider);
        let server = ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (TlsConnector::from(Arc::new(client)), TlsAcceptor::from(Arc::new(server)))
    }

    pub fn name() -> ServerName<'static> {
        ServerName::try_from(NAME).unwrap()
    }
}

/// 一个 TLS 服务器：读到客户端说完，把内容倒过来送回去，然后 close_notify。
async fn tls_server(acceptor: tokio_rustls::TlsAcceptor) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(stream).await.unwrap();
                let mut request = Vec::new();
                tls.read_to_end(&mut request).await.unwrap();
                request.reverse();
                tls.write_all(&request).await.unwrap();
                tls.shutdown().await.unwrap();
            });
        }
    });
    addr
}

/// 一条 passthrough 的流，两头是真的 TLS 客户端和服务器，中间三处录音：客户端到入口、lane、出口到服务器。
/// 客户端发 `len` 字节，服务器倒着发回来。
/// 返回 (客户端发出的, 服务器发出的, lane 上从出口到入口的, lane 上从入口到出口的)。
async fn passthrough_with_recordings(splicer: Splicer, lane_chunk: usize, len: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let pair = Pair::new(quick()).await;
    *pair.hop.chunk.lock().unwrap() = lane_chunk;
    pair.ready(1).await;
    let (connector, acceptor) = user_tls::configs();
    let server = tls_server(acceptor).await;
    let to_server = Hop::start(server).await;
    let splicer = Arc::new(splicer);
    tokio::spawn(stand_in::respond(Arc::clone(&pair.exit.lanes), to_server.addr, Arc::clone(&splicer)));

    let entry_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let from_client = Hop::start(entry_listener.local_addr().unwrap()).await;
    let lanes = Arc::clone(&pair.entry.lanes);
    let peer = pair.exit.id;
    let entry_splicer = Arc::clone(&splicer);
    let entry = tokio::spawn(async move {
        let (client_side, _) = entry_listener.accept().await.unwrap();
        stand_in::initiate(&lanes, peer, client_side, &entry_splicer).await
    });

    let tcp = TcpStream::connect(from_client.addr).await.unwrap();
    let mut tls = connector.connect(user_tls::name(), tcp).await.unwrap();
    let request: Vec<u8> = (0..len).map(|i| u8::try_from(i % 241).unwrap()).collect();
    tls.write_all(&request).await.unwrap();
    tls.shutdown().await.unwrap();
    let mut answer = Vec::new();
    timeout(PATIENCE, tls.read_to_end(&mut answer)).await.unwrap().unwrap();
    let mut expected = request.clone();
    expected.reverse();
    assert!(answer == expected, "经过 lane 之后 TLS 里的内容不一样");
    assert!(entry.await.unwrap().is_none(), "入口一侧的搬运应该正常结束");

    let (client_sent, server_sent) = {
        let client = from_client.recordings.lock().unwrap();
        let server = to_server.recordings.lock().unwrap();
        let client = client[0].lock().unwrap();
        let server = server[0].lock().unwrap();
        (client.forward.clone(), server.backward.clone())
    };
    let recordings = pair.hop.recordings.lock().unwrap();
    // 承载这条流的那条 lane：出口到入口的方向以服务器发出的字节结尾。
    let lane =
        recordings.iter().find(|recording| recording.lock().unwrap().forward.ends_with(&server_sent)).expect("找不到承载这条流的 lane");
    let lane = lane.lock().unwrap();
    (client_sent, server_sent, lane.forward.clone(), lane.backward.clone())
}

fn first_record_len(bytes: &[u8]) -> usize {
    5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]]))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// 经过流层（入口 `i3t_flow::open`、出口 `serve` 和 `Flow::relay`）的一条流，两头是真的 TLS 客户端和服务器。
/// 客户端发一段，服务器倒着发回来。
struct TlsThroughFlow {
    /// 服务器发出的全部字节。
    server_sent: Vec<u8>,
    /// lane 上每条连接从出口到入口的字节。
    lanes_down: Vec<Vec<u8>>,
    /// lane 上每条连接从入口到出口的字节。
    lanes_up: Vec<Vec<u8>>,
    entry: i3t_lane::LaneCounts,
}

async fn tls_through_the_flow_layer(connector: tokio_rustls::TlsConnector, acceptor: tokio_rustls::TlsAcceptor) -> TlsThroughFlow {
    let pair = Pair::new(quick()).await;
    pair.ready(1).await;
    let to_server = Hop::start(tls_server(acceptor).await).await;
    let lanes = Arc::clone(&pair.exit.lanes);
    let exit = Arc::new(ToTarget::new(to_server.addr));
    tokio::spawn(async move { i3t_flow::serve(&*lanes, exit).await });

    let (client, mut client_side) = tcp_pair().await;
    let lanes = Arc::clone(&pair.entry.lanes);
    let peer = pair.exit.id;
    let entry = tokio::spawn(async move {
        let first = stand_in::first_data(&mut client_side).await;
        through_flow(&lanes, peer, client_side, &first).await
    });
    let mut tls = connector.connect(user_tls::name(), client).await.unwrap();
    let request: Vec<u8> = (0..BULK).map(|i| u8::try_from(i % 241).unwrap()).collect();
    tls.write_all(&request).await.unwrap();
    tls.shutdown().await.unwrap();
    let mut answer = Vec::new();
    timeout(PATIENCE, tls.read_to_end(&mut answer)).await.unwrap().unwrap();
    assert!(answer.iter().eq(request.iter().rev()), "经过 lane 之后 TLS 里的内容不一样");
    assert!(timeout(PATIENCE, entry).await.unwrap().unwrap().is_clean(), "入口一侧的搬运应该正常结束");

    let server_sent = to_server.recordings.lock().unwrap()[0].lock().unwrap().backward.clone();
    let recordings = pair.hop.recordings.lock().unwrap();
    let lanes_down = recordings.iter().map(|recording| recording.lock().unwrap().forward.clone()).collect();
    let lanes_up = recordings.iter().map(|recording| recording.lock().unwrap().backward.clone()).collect();
    TlsThroughFlow { server_sent, lanes_down, lanes_up, entry: pair.entry.lanes.status().total }
}

/// 出口往回的方向在目标的 TLS 1.3 ServerHello 之后才离开 lane 的 TLS：ServerHello 本身（里面有服务器的密钥交换）还加密，
/// 之后的全是用户自己的 TLS 记录，原样走、由内核搬（issue #17）。
#[tokio::test]
async fn the_return_direction_leaves_tls_right_after_a_tls13_server_hello() {
    let (connector, acceptor) = user_tls::configs();
    let flow = tls_through_the_flow_layer(connector, acceptor).await;
    let hello = first_record_len(&flow.server_sent);
    assert_eq!(flow.server_sent[5], 0x02, "服务器的第一条记录是 ServerHello");
    let lane =
        flow.lanes_down.iter().find(|down| down.ends_with(&flow.server_sent[hello..])).expect("ServerHello 之后的字节应该原样走在 lane 上");
    assert!(!contains(lane, &flow.server_sent[..hello]), "ServerHello 不该明文出现在 lane 上");
    assert!(flow.entry.sealed_bytes < 4096, "往回的方向在 ServerHello 之后就不再加密：{:?}", flow.entry);
}

/// 目标回了 HelloRetryRequest：出口不在它之后切换（不然路上的人能冒充目标再要一次 ClientHello），等真正的 ServerHello。
/// 入口那边也就一直加密：客户端的第二个 ClientHello（里面有要访问的名字）不会明文出现在 lane 上（issue #34）。
#[tokio::test]
async fn after_a_hello_retry_request_the_return_direction_waits_for_the_real_server_hello() {
    // 客户端先给 X25519 的密钥，服务器只肯用 P-256：它会先回 HelloRetryRequest。
    let (connector, acceptor) = user_tls::configs_with(|server| server.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1]);
    let flow = tls_through_the_flow_layer(connector, acceptor).await;
    let sent = &flow.server_sent;
    let retry = first_record_len(sent);
    const HELLO_RETRY_REQUEST: [u8; 4] = [0xcf, 0x21, 0xad, 0x74];
    assert_eq!(sent[11..15], HELLO_RETRY_REQUEST, "服务器先回 HelloRetryRequest");
    let mut at = retry;
    if sent[at] == 0x14 {
        at += first_record_len(&sent[at..]);
    }
    assert_eq!(sent[at + 5], 0x02, "然后是真正的 ServerHello");
    let hello_end = at + first_record_len(&sent[at..]);
    let lane = flow.lanes_down.iter().find(|down| down.ends_with(&sent[hello_end..])).expect("ServerHello 之后的字节应该原样走在 lane 上");
    assert!(!contains(lane, &sent[..retry]), "HelloRetryRequest 不该明文出现在 lane 上");
    assert!(!contains(lane, &sent[at..hello_end]), "ServerHello 不该明文出现在 lane 上");
    for up in &flow.lanes_up {
        assert!(!contains(up, user_tls::NAME.as_bytes()), "第二个 ClientHello 不该明文出现在 lane 上");
    }
    assert!(flow.entry.sealed_bytes < 8192, "两个方向在真正的 ServerHello 之后就不再加密：{:?}", flow.entry);
}

/// 出口：把开过来的流接到另一条开往 `peer` 的流上（`Flow::splice`，监听在虚拟 IP 上、目标是别的节点的端口转发就是这样）。
struct Onward {
    lanes: Arc<Lanes>,
    peer: NodeId,
}

impl Handler for Onward {
    async fn handle<S: SendStream, R: RecvStream>(&self, request: Request<S, R>) {
        let pending = i3t_flow::open(&*self.lanes, self.peer, &open_request(), b"", i3t_flow::Carriage::Lane).await.unwrap();
        let onward = pending.established().await.unwrap();
        let flow = request.accept().await.unwrap();
        let _ = flow.splice(onward, future::pending()).await;
    }
}

/// 接到另一条流上的流也一样：往回的方向在目标的 TLS 1.3 ServerHello 之后才不再加密。
#[tokio::test]
async fn a_spliced_flow_leaves_tls_after_the_server_hello_too() {
    let pair = Pair::new(quick()).await;
    pair.ready(2).await;
    let target = tls13_echo_target().await;
    let lanes = Arc::clone(&pair.entry.lanes);
    tokio::spawn(async move { i3t_flow::serve(&*lanes, Arc::new(ToTarget::new(target))).await });
    let lanes = Arc::clone(&pair.exit.lanes);
    let onward = Arc::new(Onward { lanes: Arc::clone(&pair.exit.lanes), peer: pair.entry.id });
    tokio::spawn(async move { i3t_flow::serve(&*lanes, onward).await });

    let (mut client, client_side) = tcp_pair().await;
    let lanes = Arc::clone(&pair.entry.lanes);
    let peer = pair.exit.id;
    let relay = tokio::spawn(async move { through_flow(&lanes, peer, client_side, &client_hello(b"")).await });
    // 和真的 TLS 客户端一样，等到 ServerHello（和回显的 ClientHello）再发：入口的方向在出口切换之后才跟着切换。
    let mut flight = vec![0; server_hello().len() + client_hello(b"").len()];
    timeout(PATIENCE, client.read_exact(&mut flight)).await.unwrap().unwrap();
    assert!(flight == [&server_hello()[..], &client_hello(b"")].concat(), "服务器的第一批回答不一样");
    let body: Vec<u8> = (0..BULK).map(|i| u8::try_from(i % 233).unwrap()).collect();
    let (mut from_target, mut to_target) = client.split();
    let ((), (echoed, end)) = tokio::join!(
        async {
            to_target.write_all(&body).await.unwrap();
            to_target.shutdown().await.unwrap();
        },
        drain(&mut from_target)
    );
    end.unwrap();
    assert!(echoed == body, "回显的字节不一样");
    assert!(timeout(PATIENCE, relay).await.unwrap().unwrap().is_clean());
    // 出口上，开过来的那条流两个方向都是原始字节：上行是客户端的、下行是目标在 ServerHello 之后回的。
    let exit = pair.exit.lanes.status().total;
    assert!(exit.passthrough_bytes >= 2 * u64::from(BULK), "{exit:?}");
}

/// 一条握手记录，里面正好一个类型是 `kind`、内容是 `body` 的握手消息。
fn handshake_record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    record.push(kind);
    record.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    record.extend_from_slice(body);
    record
}

/// 目标用的是 TLS 1.2、还要客户端证书：它的证书（带着要访问的名字）紧跟着 ServerHello 明文回来，客户端的证书（带着它自己的名字）
/// 在客户端的第二批里明文过去。出口往回的方向一直加密（issue #17），入口那边没有 SWITCH 可回应，也一直加密（issue #34）：
/// 两张证书都不会明文出现在 lane 上。
#[tokio::test]
async fn both_directions_stay_sealed_when_a_tls12_target_asks_for_a_client_certificate() {
    // TLS 1.2 的 ServerHello（没有 supported_versions），后面是带着名字的 Certificate、CertificateRequest、ServerHelloDone。
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0x42; 32]);
    hello.extend_from_slice(&[0x00, 0xc0, 0x2f, 0x00]);
    let flight = [
        handshake_record(0x02, &hello),
        handshake_record(0x0b, user_tls::NAME.as_bytes()),
        handshake_record(0x0d, &[0x01, 0x01, 0x00, 0x02, 0x04, 0x03, 0x00, 0x00]),
        handshake_record(0x0e, &[]),
    ]
    .concat();
    // 客户端的第二批：Certificate（带着客户端自己的名字）、ClientKeyExchange、CertificateVerify。
    const CLIENT_NAME: &[u8] = b"client-identity.example";
    let second =
        [handshake_record(0x0b, CLIENT_NAME), handshake_record(0x10, &[0x20; 33]), handshake_record(0x0f, &[0x04, 0x03, 0x00, 0x01, 0x30])]
            .concat();

    let pair = Pair::new(quick()).await;
    pair.ready(1).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let answer = flight.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = vec![0; client_hello(b"").len()];
        stream.read_exact(&mut hello).await.unwrap();
        stream.write_all(&answer).await.unwrap();
        let (mut read, mut write) = stream.split();
        let _ = tokio::io::copy(&mut read, &mut write).await;
        let _ = write.shutdown().await;
    });
    let lanes = Arc::clone(&pair.exit.lanes);
    tokio::spawn(async move { i3t_flow::serve(&*lanes, Arc::new(ToTarget::new(target))).await });

    let (mut client, client_side) = tcp_pair().await;
    let lanes = Arc::clone(&pair.entry.lanes);
    let peer = pair.exit.id;
    let relay = tokio::spawn(async move { through_flow(&lanes, peer, client_side, &client_hello(b"")).await });
    let mut got = vec![0; flight.len()];
    timeout(PATIENCE, client.read_exact(&mut got)).await.unwrap().unwrap();
    assert_eq!(got, flight);
    client.write_all(&second).await.unwrap();
    client.shutdown().await.unwrap();
    let (echoed, end) = drain(&mut client).await;
    end.unwrap();
    assert_eq!(echoed, second);
    assert!(timeout(PATIENCE, relay).await.unwrap().unwrap().is_clean());

    for recording in pair.hop.recordings.lock().unwrap().iter() {
        let recording = recording.lock().unwrap();
        assert!(!contains(&recording.forward, user_tls::NAME.as_bytes()), "TLS 1.2 的服务器证书不该明文出现在 lane 上");
        assert!(!contains(&recording.backward, CLIENT_NAME), "客户端证书不该明文出现在 lane 上");
        assert!(!contains(&recording.forward, CLIENT_NAME), "回显的客户端证书也不该");
    }
    let entry = pair.entry.lanes.status().total;
    assert_eq!(entry.passthrough_bytes + entry.spliced_bytes, 0, "两个方向都一直加密：{entry:?}");
}

/// 客户端发了一个提供 TLS 1.3 的 ClientHello，后面跟着明文，目标却根本不是 TLS（这里把收到的原样送回去）：出口不发 SWITCH，
/// 入口也就不切换，客户端后面的明文不会出现在 lane 上（issue #34）。
#[tokio::test]
async fn plaintext_after_a_client_hello_stays_sealed_when_the_target_is_not_tls() {
    let pair = Pair::new(quick()).await;
    pair.ready(1).await;
    let target = echo_target().await;
    let lanes = Arc::clone(&pair.exit.lanes);
    tokio::spawn(async move { i3t_flow::serve(&*lanes, Arc::new(ToTarget::new(target))).await });
    let (mut client, client_side) = tcp_pair().await;
    let lanes = Arc::clone(&pair.entry.lanes);
    let peer = pair.exit.id;
    let relay = tokio::spawn(async move { through_flow(&lanes, peer, client_side, &client_hello(b"")).await });
    // 等目标回了点什么（回显的 ClientHello）再发明文：出口要切换的话这时已经切换了。
    let mut echoed_hello = vec![0; client_hello(b"").len()];
    timeout(PATIENCE, client.read_exact(&mut echoed_hello)).await.unwrap().unwrap();
    const PLAINTEXT: &[u8] = b"GET /secret HTTP/1.1\r\nAuthorization: Bearer plaintext-token\r\n\r\n";
    client.write_all(PLAINTEXT).await.unwrap();
    client.shutdown().await.unwrap();
    let (echoed, end) = drain(&mut client).await;
    end.unwrap();
    assert_eq!(echoed, PLAINTEXT);
    assert!(timeout(PATIENCE, relay).await.unwrap().unwrap().is_clean());

    for recording in pair.hop.recordings.lock().unwrap().iter() {
        let recording = recording.lock().unwrap();
        assert!(!contains(&recording.backward, PLAINTEXT), "客户端的明文不该出现在 lane 上");
        assert!(!contains(&recording.forward, PLAINTEXT), "回显的明文也不该");
    }
    let entry = pair.entry.lanes.status().total;
    assert_eq!(entry.passthrough_bytes + entry.spliced_bytes, 0, "两个方向都一直加密：{entry:?}");
}

#[tokio::test]
async fn passthrough_carries_the_inner_tls_records_unchanged_after_the_opening_exchange() {
    let (client_sent, server_sent, exit_to_entry, entry_to_exit) = passthrough_with_recordings(Splicer::new(), 0, BULK).await;
    let hello = first_record_len(&client_sent);
    // 入口到出口：lane 自己的 TLS（握手、装着 ClientHello 的 OPENING、回应出口的 SWITCH）之后，正好是客户端在 ClientHello
    // 之后发出的全部字节：真的 TLS 客户端在收到服务器的第一批回答之前不再发东西，那时入口已经跟着切换了。
    assert!(entry_to_exit.ends_with(&client_sent[hello..]), "入口到出口的方向在开流之后必须是客户端的原始字节");
    // 出口到入口：lane 自己的 TLS（握手、HELLO、REPLY、SWITCH）之后，正好是服务器发出的全部字节。
    assert!(exit_to_entry.ends_with(&server_sent));
    // ClientHello 只在 lane 的 TLS 里面走过：线上看不到客户端要访问的名字。
    assert!(contains(&client_sent, user_tls::NAME.as_bytes()), "客户端的 ClientHello 里有名字");
    assert!(!contains(&entry_to_exit, user_tls::NAME.as_bytes()), "lane 上不能看到明文的名字");
    // lane 自己的 TLS 部分很小：开流之前和之后的字节差不多全是用户的。
    let lane_overhead = entry_to_exit.len() - (client_sent.len() - hello);
    assert!(lane_overhead < hello + 2048, "入口到出口方向 lane 自己的字节 {lane_overhead}");
}

#[tokio::test]
async fn passthrough_survives_a_lane_that_delivers_tiny_segments() {
    // 每段一两个字节时每个字节一次系统调用，量大了只是慢（十五万字节来回要七八秒，机器一忙就过了等待的上限，
    // 看起来像流卡死了）。这里要看的是 TLS 的记录被切在任意位置也不出错：两万字节跨过一个记录的边界，够了。
    for (chunk, len) in [(1, 20_000), (3, 20_000), (100, BULK)] {
        let (client_sent, server_sent, exit_to_entry, entry_to_exit) = passthrough_with_recordings(Splicer::new(), chunk, len).await;
        let hello = first_record_len(&client_sent);
        assert!(entry_to_exit.ends_with(&client_sent[hello..]), "每段 {chunk} 字节");
        assert!(exit_to_entry.ends_with(&server_sent), "每段 {chunk} 字节");
    }
}

#[tokio::test]
async fn splice_and_user_space_copy_move_identical_bytes() {
    // 经过 lane 的真 TLS 流，两种引擎各跑一遍：TLS 能解开、内容对（在里面检查）。
    let _ = passthrough_with_recordings(Splicer::new(), 0, BULK).await;
    let _ = passthrough_with_recordings(Splicer::copying(), 0, BULK).await;

    // 再直接比一次：同一份字节分别用两种引擎搬过两条 TCP。
    let data: Vec<u8> = (0..20_000_000u32).map(|i| u8::try_from((i * 7 + i / 255) % 256).unwrap()).collect();
    for splicer in [Splicer::new(), Splicer::copying()] {
        let (mut source, source_side) = tcp_pair().await;
        let (mut sink, sink_side) = tcp_pair().await;
        let relay = async { splicer.relay(&source_side, bytes::Bytes::new(), &sink_side, bytes::Bytes::from_static(b"prefix")).await };
        let send = async {
            source.write_all(&data).await.unwrap();
            source.shutdown().await.unwrap();
        };
        let receive = async {
            let mut got = Vec::new();
            sink.read_to_end(&mut got).await.unwrap();
            sink.shutdown().await.unwrap();
            got
        };
        let (relayed, (), got) = tokio::join!(relay, send, receive);
        assert!(relayed.error.is_none());
        assert_eq!(&got[..6], b"prefix");
        assert!(got[6..] == data[..], "引擎 {splicer:?} 搬出来的字节不一样");
        let moved = splicer.spliced_bytes() + splicer.copied_bytes();
        assert_eq!(moved, u64::try_from(data.len() + 6).unwrap());
    }
}

#[tokio::test]
async fn both_engines_deliver_what_is_still_queued_when_the_relay_ends() {
    // 一头先结束（它的 FIN 先到），另一头再发一大块并结束。收的那一头接收缓冲小、搬运那一侧的发送缓冲大，并且等搬运结束、
    // 两条连接都关了才读：那时这一块的大半还在内核里没发出去。正常关闭时内核接着发完；以 RST 关闭时它们被丢掉，读到的是
    // 重置或者一直等。macOS 上一条 socket 两个方向都关了之后改不回正常关闭，就会这样（见 `i3t_underlay::tcp_reset`）。
    for splicer in [Splicer::new(), Splicer::copying()] {
        let (mut source, source_side) = tcp_pair().await;
        let (mut sink, sink_side) = tcp_pair().await;
        socket2::SockRef::from(&sink).set_recv_buffer_size(16 * 1024).unwrap();
        socket2::SockRef::from(&sink_side).set_send_buffer_size(1024 * 1024).unwrap();
        sink.shutdown().await.unwrap();
        // 发送缓冲在 Linux 上有上限（`net.core.wmem_max`，常见的是 208 KB，内核给两倍）：这一块要放得进去，搬运才能结束。
        let block: Vec<u8> = (0..192 * 1024u32).map(|i| u8::try_from(i % 233).unwrap()).collect();
        let relay = async {
            let relayed = splicer.relay(&source_side, bytes::Bytes::new(), &sink_side, bytes::Bytes::new()).await;
            drop((source_side, sink_side));
            relayed
        };
        let send = async {
            source.write_all(&block).await.unwrap();
            source.shutdown().await.unwrap();
            let (rest, end) = drain(&mut source).await;
            assert!(rest.is_empty() && end.is_ok(), "另一头先正常结束了：{rest:?} {end:?}");
        };
        let (relayed, ()) = tokio::join!(relay, send);
        assert!(relayed.error.is_none(), "引擎 {splicer:?}：{:?}", relayed.error);
        let (got, end) = drain(&mut sink).await;
        assert!(end.is_ok(), "引擎 {splicer:?}：收到 {} 字节之后结束的方式是 {end:?}，应该是正常结束", got.len());
        assert!(got == block, "引擎 {splicer:?}：收到 {} 字节，应该是 {}", got.len(), block.len());
    }
}

#[tokio::test]
async fn an_upstream_reset_in_the_middle_of_an_answer_reaches_the_client_as_a_reset_in_passthrough() {
    for splicer in [Splicer::new(), Splicer::copying()] {
        let pair = Pair::new(quick()).await;
        pair.ready(1).await;
        let target = resetting_target().await;
        let splicer = Arc::new(splicer);
        tokio::spawn(stand_in::respond(Arc::clone(&pair.exit.lanes), target, Arc::clone(&splicer)));
        let (mut client, client_side) = tcp_pair().await;
        let lanes = Arc::clone(&pair.entry.lanes);
        let peer = pair.exit.id;
        let entry = tokio::spawn(async move { stand_in::initiate(&lanes, peer, client_side, &splicer).await });
        // ClientHello 做首批数据，让入口选 passthrough。
        client.write_all(&client_hello(b"")).await.unwrap();
        let (got, end) = drain(&mut client).await;
        assert_eq!(got, b"half of the ans");
        let error = end.expect_err("半截的回答之后必须是重置，不能是正常结束");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert!(entry.await.unwrap().is_some(), "入口一侧的搬运要报异常结束");
    }
}

#[tokio::test]
async fn sealed_mode_still_runs_when_the_responder_never_switches() {
    // 发起方选了 passthrough，接受方不调 end_header：两个方向都一直在 TLS 里（发起方没有 SWITCH 可回应），照样读得懂。
    let pair = Pair::new(quick()).await;
    pair.ready(1).await;
    let exit = Arc::clone(&pair.exit.lanes);
    let responder = tokio::spawn(async move {
        use i3t_conn::Acceptor;
        let incoming = exit.accept().await.unwrap();
        let (mut send, mut recv) = (incoming.send, incoming.recv);
        let _open = stand_in::read_header(&mut recv, i3t_proto::flow::Opening::decode).await;
        let mut reply = Vec::new();
        Reply::ok().encode(&mut reply);
        send.write_all(&reply).await.unwrap();
        let mut rest = Vec::new();
        recv.read_to_end(&mut rest).await.unwrap();
        send.write_all(&rest).await.unwrap();
        send.shutdown().await.unwrap();
    });
    let (mut send, mut recv) = pair.entry.lanes.open_stream(pair.exit.id).await.unwrap();
    let mut header = Vec::new();
    open_request().encode(&mut header);
    header.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0, 0, 0]);
    send.write_all(&header).await.unwrap();
    send.end_header(Payload::Passthrough);
    let reply = stand_in::read_header(&mut recv, Reply::decode).await;
    assert!(reply.status.is_ok());
    assert!(recv.take_raw().is_none(), "接受方没有 SWITCH，它的方向还在 TLS 里");
    send.write_all(b"raw up").await.unwrap();
    send.shutdown().await.unwrap();
    let (echoed, end) = drain(&mut recv).await;
    end.unwrap();
    assert_eq!(echoed, [&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0, 0, 0][..], b"raw up"].concat());
    responder.await.unwrap();
}
