//! 节点协议的服务端：TCP 上的 TLS 1.3，双方按公钥互相认证，上面是分帧的 JSON 消息。
//!
//! 这里只管连接：握手、读写、心跳、超时。每条消息怎么处理在 [`Controller`] 里。
//!
//! 单条连接上的交互顺序：节点先发送 `Enroll` 或 `Hello`；controller 回复 `Snapshot`，不接受该节点时回复 `Rejected` 并断开连接，
//! 自身出错时回复 `TryLater` 并断开连接（节点将按退避策略重连）。此后节点负责上报、确认与发送信令，controller 下发 netmap 并转发信令。
//!
//! 握手和成员资格核验分别按来源地址记账（[`crate::gate`]）。握手名额满了挤掉老连接，核验名额满了让新来的稍后重试。
//! 连上之后 [`CLIENT_HELLO_TIMEOUT`] 之内要收到 TLS 的 ClientHello，从连上算起 [`Timing::handshake_timeout`] 之内要完成握手并发来第一条消息。
//!
//! 报到之后，每条连接由三个任务配合：读取任务读帧并记下最近一次收到消息的时刻，处理任务按顺序把消息交给 controller，
//! 连接自身的循环负责发送、心跳和存活判定。controller 处理消息可能因等锁或等数据库而耗时较长，此时只有处理任务被阻塞：
//! 心跳照常发送，收到的消息照常计入存活，不会因处理慢而把仍在说话的节点判为离线。
//!
//! 不读写存储的消息不排在同一个节点卡在数据库上的上报后面（见 [`Controller::waits`]）：信令和查询的回答由读取任务直接处理，
//! 取更新包另排一队，处理任务同时处理这一队和其余的消息。
//!
//! [`Timing::handshake_timeout`]: crate::Timing::handshake_timeout

mod verification;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use i3t_crypto::tls;
use i3t_model::control::{MAX_FRAME_LEN, ToController, ToNode};
use i3t_proto::PublicKey;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, sleep, sleep_until, timeout, timeout_at};
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;

use crate::controller::{Admitted, Controller, Waits};
use crate::error::{Rejection, error_chain};
use crate::frame::{FrameError, read_frame, write_frame};
use crate::gate::{Gate, Limits, Pass, Throttle};
use crate::server::blocking;
use verification::AdmissionError;
pub(crate) use verification::VerificationQuota;

/// 还没报到的连接上，一帧最长这么多字节。`Enroll` 和 `Hello` 都只有几百字节。
const FIRST_FRAME_LIMIT: usize = 64 * 1024;
/// 握手和核验各用一组名额：每个来源最多 16 条，全部最多 256 条。
///
/// 正常的节点连上来几个往返就报到完了，同一个家用 NAT 后面的节点在 controller 重启之后带着随机的退避陆续连回来，
/// 同时处于握手阶段的连接数远低于 16 条。
pub(crate) const PENDING: Limits = Limits { per_source: 16, total: 256 };
/// 连上之后这么久还没有收到 TLS 的 ClientHello 就断开。正常的节点连上就发；只连不说话的连接不值得等满整个握手时限。
pub const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(3);
/// 接受连接失败（通常由文件描述符耗尽导致）日志的最小记录间隔。
const ACCEPT_ERROR_LOG_EVERY: Duration = Duration::from_secs(10);
/// 每个节点的发送队列有多少格。满了说明节点不读，controller 会断开它。
const OUTBOX_CAPACITY: usize = 64;
/// 每条连接上已收到、等待 controller 处理的消息，每一队最多积压多少条。满了之后暂停读取，直到处理任务跟上。
const INBOUND_CAPACITY: usize = 16;
/// 报到失败的应答很小，写入和关闭合计最多占用名额这么久。之前的核验耗时另计。
const ADMISSION_REPLY_TIMEOUT: Duration = Duration::from_secs(2);
/// 已报到节点的一帧写这么久还没写完，就认为连接已经死了。
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// 关闭时最多等连接收尾这么久。
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

type Reader = ReadHalf<TlsStream<TcpStream>>;
type Writer = WriteHalf<TlsStream<TcpStream>>;

/// 在 `listener` 上接受节点的连接，直到 `shutdown` 变化。`tls` 来自 [`Controller::tls_config`]。
pub async fn serve(
    controller: Arc<Controller>,
    tls: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) {
    let pending = Gate::new("还没报到的节点连接", PENDING);
    let accept_errors = Throttle::new(ACCEPT_ERROR_LOG_EVERY);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = i3t_underlay::tcp_mss::accept(&listener) => match accepted {
                Ok((stream, remote)) => {
                    let pass = pending.admit(remote.ip());
                    let mut connection = Connection { controller: Arc::clone(&controller), remote, shutdown: shutdown.clone() };
                    let tls = Arc::clone(&tls);
                    connections.spawn(async move {
                        let Some(established) = connection.establish(tls, stream, pass).await else { return };
                        connection.run(established).await;
                    });
                }
                Err(err) => {
                    // 通常由文件描述符耗尽导致。短暂休眠后再继续接受连接，避免空转。
                    if let Some(suppressed) = accept_errors.allow() {
                        tracing::warn!(suppressed, "接受连接失败：{err}");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            _ = shutdown.changed() => break,
        }
    }
    drop(listener);
    // 每条连接自己也在看 shutdown：它们会把节点记为离线再退出。
    if timeout(SHUTDOWN_GRACE, async { while connections.join_next().await.is_some() {} }).await.is_err() {
        tracing::warn!("部分节点连接未在 {SHUTDOWN_GRACE:?} 内结束，放弃等待");
    }
}

struct Connection {
    controller: Arc<Controller>,
    remote: SocketAddr,
    shutdown: watch::Receiver<bool>,
}

/// 一条已经报到的连接。
struct Established {
    session: Admitted,
    reader: Reader,
    writer: Writer,
    outbox: mpsc::Receiver<ToNode>,
}

impl Connection {
    /// 执行握手、读取首条消息并由 controller 校验节点准入。未通过时回复 `Rejected`（或 `TryLater`）并返回 `None`。
    ///
    /// `pass` 在取得核验名额后交还。满额或首帧不合要求时，应答仍受握手名额和时限约束。
    async fn establish(&mut self, tls: Arc<rustls::ServerConfig>, stream: TcpStream, mut pass: Pass) -> Option<Established> {
        let remote = self.remote;
        let deadline = Instant::now() + self.controller.timing().handshake_timeout;
        let handshake = timeout_at(deadline, handshake(tls, stream));
        let outcome = tokio::select! {
            outcome = handshake => outcome,
            () = pass.evicted() => {
                tracing::debug!(%remote, "未完成报到的连接数已达上限，当前连接被淘汰");
                return None;
            }
        };
        let (key, first, reader, mut writer) = match outcome {
            Ok(Ok(parts)) => parts,
            Ok(Err(reason)) => {
                tracing::debug!(%remote, %reason, "连接没有完成报到");
                return None;
            }
            Err(_) => {
                tracing::debug!(%remote, "连接没有在限定时间内完成握手并发来第一条消息");
                return None;
            }
        };

        let ip = remote.ip();
        let (hello, token) = match first {
            ToController::Enroll { token, hello } => (hello, Some(token)),
            ToController::Hello(hello) => (hello, None),
            ToController::Report(_)
            | ToController::Ack { .. }
            | ToController::Signal { .. }
            | ToController::Heartbeat
            | ToController::PackageRequest { .. }
            | ToController::RouteAnswer { .. }
            | ToController::BackboneAnswer { .. }
            | ToController::TestReport(_)
            | ToController::ExitTestAnswer { .. } => {
                if let Some(suppressed) = self.controller.refusal_log.allow() {
                    tracing::warn!(key = ?key, remote = %ip, suppressed, "拒绝连接：第一条消息不是 enroll 也不是 hello");
                }
                AdmissionError::UnexpectedFirstMessage(pass).reply(&mut writer, remote, deadline, &mut self.shutdown).await;
                return None;
            }
        };
        let (outbox, inbox) = mpsc::channel(OUTBOX_CAPACITY);
        let check = move |controller: &Controller| match token {
            Some(token) => controller.enroll(key, &token, &hello, ip, outbox),
            None => controller.hello(key, &hello, ip, outbox),
        };
        match self.controller.verify_node(pass, check).await {
            Ok(session) => Some(Established { session, reader, writer, outbox: inbox }),
            Err(error) => {
                error.reply(&mut writer, remote, deadline, &mut self.shutdown).await;
                None
            }
        }
    }

    async fn run(mut self, established: Established) {
        let Established { session, reader, mut writer, mut outbox } = established;
        let timing = self.controller.timing();
        let (heard, last_heard) = watch::channel(Some(Instant::now()));
        let (inbound, queues) = inbound();
        let remote = self.remote.ip();
        let mut reader = Owned(spawn_reader(reader, Arc::clone(&self.controller), session, remote, heard, inbound));
        let mut worker = Owned(spawn_worker(Arc::clone(&self.controller), session, remote, queues));
        // 处理任务在连接结束之前就结束时的结果。
        let mut worker_ended = None;
        // 读取任务直接处理一部分消息（见 [`Waits::Nothing`]），它在处理时的 panic 和处理任务里的一样对待。
        let mut reader_panic = None;
        let mut last_sent = Instant::now();

        // 第二项：连接是否因读取结束而结束。是的话，节点在关闭连接之前发来的消息仍要处理完。
        let (reason, read_to_end) = loop {
            let silent_until = silent_since(*last_heard.borrow()) + timing.liveness_timeout;
            tokio::select! {
                ended = &mut reader.0 => match ended {
                    Ok(reason) => break (reason, true),
                    // 读取任务只在被丢弃时取消，那是在这个循环之后：这里只会是 panic。
                    Err(error) => {
                        reader_panic = error.try_into_panic().ok();
                        break ("读取任务意外结束".to_owned(), false);
                    }
                },
                ended = &mut worker.0, if worker_ended.is_none() => {
                    let failed = ended.is_err();
                    worker_ended = Some(ended);
                    // 处理任务只在 panic 或队列关闭时结束。队列关闭说明读取任务已结束，下一轮从读取任务取得结束原因。
                    if failed {
                        break ("处理节点消息的任务意外结束".to_owned(), false);
                    }
                }
                outgoing = outbox.recv() => match outgoing {
                    Some(message) => match timeout(WRITE_TIMEOUT, write_frame(&mut writer, &message)).await {
                        Ok(Ok(())) => last_sent = Instant::now(),
                        Ok(Err(err)) => break (format!("写入失败：{}", error_chain(&err)), false),
                        Err(_) => break (format!("消息写入在 {WRITE_TIMEOUT:?} 内未完成"), false),
                    },
                    // 发送队列的另一头没了：这条连接被同一个节点的新连接顶替，或者节点被删除（Revoked 已经在上面发出去了）。
                    None => break ("controller 结束了这条连接".to_owned(), false),
                },
                () = sleep_until(last_sent + timing.heartbeat_idle) => {
                    match timeout(WRITE_TIMEOUT, write_frame(&mut writer, &ToNode::Heartbeat)).await {
                        Ok(Ok(())) => last_sent = Instant::now(),
                        _ => break ("发送心跳失败".to_owned(), false),
                    }
                }
                () = sleep_until(silent_until) => {
                    // 等待期间读取任务可能刚收到过消息：按最新的状态重新判断。
                    if Instant::now() >= silent_since(*last_heard.borrow()) + timing.liveness_timeout {
                        break (format!("{:?} 没有收到节点的任何消息", timing.liveness_timeout), false);
                    }
                }
                _ = self.shutdown.changed() => break ("controller 正在关闭".to_owned(), false),
            }
        };

        tracing::info!(node = %session.node, remote = %self.remote, %reason, "和节点的连接结束");
        drop(reader);
        let worker_ended = match worker_ended {
            Some(ended) => Some(ended),
            // 读取任务已退出，处理任务处理完队列里剩下的消息后自行结束。controller 正在关闭时不再等待。
            None if read_to_end => tokio::select! {
                ended = &mut worker.0 => Some(ended),
                _ = self.shutdown.wait_for(|&stopping| stopping) => None,
            },
            // 其余情况下剩下的消息不再处理：连接已被顶替、节点已沉默或 controller 正在关闭。
            None if worker.0.is_finished() => Some((&mut worker.0).await),
            None => None,
        };
        drop(worker);
        let panic = reader_panic.or_else(|| match worker_ended {
            Some(Err(err)) => err.try_into_panic().ok(),
            Some(Ok(())) | None => None,
        });
        // controller 里的 panic 是 bug，收尾之后照原样传出去（见 [`blocking`]）。panic 时 controller 的锁可能已经中毒，
        // 不再去拿它记离线（那会再 panic 一次、盖住原来的那个）：发送队列的接收端随这里退出而关闭，之后给它发消息时会断开它。
        if let Some(panic) = panic {
            close(&mut writer).await;
            std::panic::resume_unwind(panic);
        }
        blocking(&self.controller, move |controller| controller.disconnect(session)).await;
        close(&mut writer).await;
    }
}

/// 连接派生的任务。被丢弃时取消该任务：连接任务本身被取消时（例如关闭时等不及），不留下仍在读连接、处理消息的任务。
struct Owned<T>(JoinHandle<T>);

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 从何时起算节点沉默：最近一次收到消息的时刻。读取任务因积压暂停读取时（`None`）按现在算：
/// 这段时间读不到节点的消息是因为 controller 还没处理完之前的消息，不是节点沉默。
fn silent_since(heard: Option<Instant>) -> Instant {
    heard.unwrap_or_else(Instant::now)
}

/// TLS 握手，取出对端的公钥，读第一条消息。失败时返回给日志看的原因。
///
/// ClientHello 要在 [`CLIENT_HELLO_TIMEOUT`] 之内到；整个过程的时限由调用的一方管。
async fn handshake(tls: Arc<rustls::ServerConfig>, stream: TcpStream) -> Result<(PublicKey, ToController, Reader, Writer), String> {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!("设置 TCP_NODELAY 失败：{err}");
    }
    let hello = timeout(CLIENT_HELLO_TIMEOUT, LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream))
        .await
        .map_err(|_| format!("{CLIENT_HELLO_TIMEOUT:?} 之内没有收到 TLS 的 ClientHello"))?
        .map_err(|err| format!("TLS 握手失败：{err}"))?;
    let stream = hello.into_stream(tls).await.map_err(|err| format!("TLS 握手失败：{err}"))?;
    let key = {
        let (_, session) = stream.get_ref();
        let certificate = session.peer_certificates().and_then(|chain| chain.first()).ok_or("对端没有出示证书")?;
        tls::peer_key(certificate).map_err(|err| format!("对端证书无效：{err}"))?
    };
    let (mut reader, writer) = tokio::io::split(stream);
    match read_frame(&mut reader, FIRST_FRAME_LIMIT).await {
        Ok(Some(first)) => Ok((key, first, reader, writer)),
        Ok(None) => Err("对端没有发消息就关闭了连接".to_owned()),
        Err(err) => Err(format!("无法读取首条消息：{}", error_chain(&err))),
    }
}

/// 收到的消息里要排队处理的两队：取更新包的一队（[`Waits::File`]），其余的一队（[`Waits::Store`]）。各自按收到的顺序处理。
struct Inbound {
    files: mpsc::Sender<ToController>,
    store: mpsc::Sender<ToController>,
}

/// [`Inbound`] 的另一头，交给处理任务。
struct Queues {
    files: mpsc::Receiver<ToController>,
    store: mpsc::Receiver<ToController>,
}

fn inbound() -> (Inbound, Queues) {
    let (files, files_queue) = mpsc::channel(INBOUND_CAPACITY);
    let (store, store_queue) = mpsc::channel(INBOUND_CAPACITY);
    (Inbound { files, store }, Queues { files: files_queue, store: store_queue })
}

/// 读取任务：读帧，记下收到的时刻（`heard`），什么都不等的消息（[`Waits::Nothing`]）当场处理，其余的按顺序放进 `inbound`
/// 的两队之一。返回连接结束的原因。
///
/// 读一帧不能被打断（长度和内容分两次读），所以不能直接放在 `select!` 里。心跳只说明节点还在，不进队列，也不占用 controller 的锁；
/// 无法解析的帧（通常为更高版本节点发来的未知消息类型）同样计入存活，跳过即可。
///
/// 一队满时暂停读取，直到处理任务跟上，期间 `heard` 为 `None`（见 [`silent_since`]）。这时后面的信令和回答也要等：
/// 每一队能积压 [`INBOUND_CAPACITY`] 条，节点每 10 秒上报一次，积满要等 controller 卡住很久。
fn spawn_reader(
    mut reader: Reader,
    controller: Arc<Controller>,
    session: Admitted,
    remote: IpAddr,
    heard: watch::Sender<Option<Instant>>,
    inbound: Inbound,
) -> JoinHandle<String> {
    const WORKER_GONE: &str = "处理节点消息的任务意外结束";
    let node = session.node;
    tokio::spawn(async move {
        loop {
            match read_frame(&mut reader, MAX_FRAME_LEN).await {
                Ok(Some(message)) => {
                    heard.send_replace(Some(Instant::now()));
                    let queue = match Controller::waits(&message) {
                        // 只拿一把很短的锁，不进阻塞线程池：那里可能挤满了等 controller 的锁的任务。
                        Waits::Nothing => {
                            if let Err(err) = controller.handle(session, remote, message) {
                                tracing::error!(%node, "处理节点的消息时出错：{}", error_chain(&err));
                            }
                            continue;
                        }
                        Waits::File => &inbound.files,
                        Waits::Store => &inbound.store,
                    };
                    let message = match queue.try_send(message) {
                        Ok(()) => continue,
                        Err(mpsc::error::TrySendError::Full(message)) => message,
                        Err(mpsc::error::TrySendError::Closed(_)) => return WORKER_GONE.to_owned(),
                    };
                    heard.send_replace(None);
                    if queue.send(message).await.is_err() {
                        return WORKER_GONE.to_owned();
                    }
                    heard.send_replace(Some(Instant::now()));
                }
                Ok(None) => return "节点关闭了连接".to_owned(),
                Err(FrameError::Json(err)) => {
                    heard.send_replace(Some(Instant::now()));
                    tracing::debug!(%node, "无法解析节点消息，已忽略：{err}");
                }
                Err(err) => return format!("读取失败：{}", error_chain(&err)),
            }
        }
    })
}

/// 处理任务：两队消息同时处理，每一队按收到的顺序逐条交给 controller，一队卡住（等锁、等数据库、读文件）不耽误另一队。
/// 两队的发送端都关闭且队列都处理完时结束；controller 处理消息时 panic 也会结束。
fn spawn_worker(controller: Arc<Controller>, session: Admitted, remote: IpAddr, queues: Queues) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Queues { files, store } = queues;
        tokio::join!(handle_queue(&controller, session, remote, files), handle_queue(&controller, session, remote, store));
    })
}

/// 按顺序处理一队消息，直到队列的发送端关闭、队列处理完。
async fn handle_queue(controller: &Arc<Controller>, session: Admitted, remote: IpAddr, mut queue: mpsc::Receiver<ToController>) {
    while let Some(message) = queue.recv().await {
        let handled = blocking(controller, move |controller| controller.handle(session, remote, message)).await;
        if let Err(err) = handled {
            tracing::error!(node = %session.node, "处理节点的消息时出错：{}", error_chain(&err));
        }
    }
}

impl AdmissionError {
    async fn reply(
        self,
        writer: &mut (impl AsyncWrite + Unpin),
        remote: SocketAddr,
        deadline: Instant,
        shutdown: &mut watch::Receiver<bool>,
    ) {
        let (mut pass, reply) = match self {
            Self::Evicted => {
                tracing::debug!(%remote, "握手名额已被淘汰，跳过成员资格核验");
                return;
            }
            Self::Rejected(reason, _permit) => {
                reply_and_close(writer, reason.reply(), remote, shutdown).await;
                return;
            }
            Self::Busy(pass) => (pass, ToNode::TryLater { reason: "当前正在核验的节点过多，请稍后再试".to_owned() }),
            Self::UnexpectedFirstMessage(pass) => (pass, Rejection::UnexpectedFirstMessage.reply()),
        };
        tokio::select! {
            biased;
            () = pass.evicted() => tracing::debug!(%remote, "发送报到应答时握手名额被淘汰"),
            () = sleep_until(deadline) => tracing::debug!(%remote, "发送报到应答时已到握手时限"),
            () = reply_and_close(writer, reply, remote, shutdown) => {}
        }
    }
}

async fn reply_and_close(writer: &mut (impl AsyncWrite + Unpin), reply: ToNode, remote: SocketAddr, shutdown: &mut watch::Receiver<bool>) {
    let send = async {
        match write_frame(writer, &reply).await {
            Ok(()) => close(writer).await,
            Err(err) => tracing::debug!(%remote, "发送拒绝原因失败：{}", error_chain(&err)),
        }
    };
    tokio::select! {
        biased;
        _ = shutdown.wait_for(|&stopping| stopping) => {}
        () = sleep(ADMISSION_REPLY_TIMEOUT) => tracing::debug!(%remote, "拒绝应答未在 {ADMISSION_REPLY_TIMEOUT:?} 内发送完成并关闭连接"),
        () = send => {}
    }
}

/// 尽量体面地关掉连接。对方不配合也不多等。
async fn close(writer: &mut (impl AsyncWrite + Unpin)) {
    // 关不关得干净不影响任何状态：连接反正要丢弃了。
    let _ = timeout(Duration::from_secs(1), writer.shutdown()).await;
}
