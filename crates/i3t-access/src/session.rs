//! 一条客户端连接，从握手到搬运结束。

use std::convert::Infallible;
use std::future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use i3t_conn::Connector;
use i3t_conn::contract::Datagrams;
use i3t_flow::datagram::Opener;
use i3t_flow::{Carriage, End, FlowError, Framing, Summary};
use i3t_model::Netmap;
use i3t_model::netmap::{self, Forward, ListenerProtocol};
use i3t_proto::flow::{Host, Open, Origin, Reason, Target};
use i3t_proto::{NodeId, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time;

use crate::admission::{Handshakes, Pass};
use crate::entry::{Entry, Gate, LocalEntry};
use crate::failure::Failure;
use crate::first_data::{self, FIRST_BYTE_WAIT};
use crate::forward_health::{ForwardHealth, TargetCause};
use crate::manager::{Connection, PortBook, allowed, virtual_ip_admits};
use crate::message::{Parsed, Parser};
use crate::route::{self, Route};
use crate::routes::{RouteAtStart, RouteSpan, SharedRoutes};
use crate::usage::{ExitTally, IngressMeter, Usage};
use crate::{http, socks5, udp};

/// 客户端要在这么长时间之内完成代理握手。握手只有几个小报文，这个时限只是不让不说话的连接一直占着。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 握手阶段每次最多从客户端读这么多。
const READ_CHUNK: usize = 4096;

/// 回了失败的应答之后，最多再等客户端这么久才关连接。
const CLOSE_LINGER: Duration = Duration::from_millis(500);

/// SOCKS5 的问候以版本号 5 开头；HTTP 的请求行以方法名开头，是字母。两种协议都说的端口按它分。
const SOCKS5_VERSION: u8 = 0x05;

/// 所有连接共用的东西。
pub(crate) struct Shared<C: Datagrams> {
    pub connector: Arc<C>,
    /// 本节点开的数据报上下文。对端发回来的数据报由它分发，所以 [`crate::Access::run`] 要让它一直跑着。
    pub opener: Arc<Opener<C>>,
    pub netmap: watch::Receiver<Arc<Netmap>>,
    /// 本机配置文件里的组网入口。启动时定下，之后不变。
    pub local: Vec<LocalEntry>,
    /// 按出口的用量。
    pub usage: Usage,
    /// 端口写 0 的端口转发挑定的端口记在哪里。
    pub ports: Arc<dyn PortBook>,
    /// 节点正在排空时有值：为什么排空，写进拒绝的日志。
    pub draining: Mutex<Option<String>>,
    /// 因为排空而拒绝的连接和 UDP 会话。
    pub drained: AtomicU64,
    /// UDP 端口转发的会话没有报文往来多久之后回收。
    pub udp_idle_timeout: Duration,
    /// 端口转发的目标最近连不上的记录。
    pub forward_health: ForwardHealth,
    /// 到各个对端现在走哪条路，写进每条流结束时的摘要。
    pub routes: SharedRoutes,
    /// 代理连接在完成握手之前占的名额。
    pub handshakes: Handshakes,
}

impl<C: Datagrams> Shared<C> {
    /// 节点正在排空时记一次拒绝，返回 `true`。
    pub(crate) fn refuse_while_draining(&self, what: &str) -> bool {
        let Some(why) = self.draining.lock().expect("draining mutex poisoned").clone() else { return false };
        self.drained.fetch_add(1, Ordering::Relaxed);
        tracing::info!(what, why, "拒绝了一个新的请求：节点正在排空");
        true
    }
}

/// 握手阶段的客户端连接：带着一个缓冲区，里面是已经读进来、还没有被解析走的字节。
struct Client {
    stream: TcpStream,
    buffer: Vec<u8>,
}

/// 握手阶段读一个报文失败的原因。
enum Broken<E> {
    Io(io::Error),
    /// 客户端在报文发完之前关掉了连接。
    Closed,
    Malformed(E),
}

impl Client {
    /// 读到 `parse` 认出一个完整的报文为止。缓冲区里它后面的字节留给下一次。
    ///
    /// 这里不限制缓冲区的长度：两种协议的解析器都保证"还不完整"不会无限持续（见各自的模块文档）。
    async fn read<T, E>(&mut self, parse: Parser<T, E>) -> Result<T, Broken<E>> {
        loop {
            if let Some(Parsed { value, len }) = parse(&self.buffer).map_err(Broken::Malformed)? {
                self.buffer.drain(..len);
                return Ok(value);
            }
            self.buffer.reserve(READ_CHUNK);
            // usize 不会比 u64 宽，这里不会截断。
            let read = (&mut self.stream).take(READ_CHUNK as u64).read_buf(&mut self.buffer).await.map_err(Broken::Io)?;
            if read == 0 {
                return Err(Broken::Closed);
            }
        }
    }

    /// 看客户端发来的第一个字节分出它说的是哪种协议：`0x05` 是 SOCKS5，别的是 HTTP。这个字节留在缓冲区里，握手照常从它读起。
    async fn sniff(&mut self) -> Result<Front, Broken<Infallible>> {
        let first = self.read(first_byte).await?;
        Ok(if first == SOCKS5_VERSION { Front::Socks5 } else { Front::Http })
    }

    /// 告诉客户端请求失败了，然后关闭连接。写不出去说明客户端已经走了，没有人需要这个应答。
    async fn fail(mut self, front: Front, failure: Failure) {
        let _ = self.stream.write_all(&front.failure(failure)).await;
        self.close().await;
    }

    /// 发完失败的应答之后关闭连接，并且让应答送得到。
    ///
    /// 客户端可能还在发数据（比如没读完的超长请求头）。带着没读的数据直接关，内核发的是 RST，
    /// 已经写出去的应答可能被冲掉。所以先只关写的一半，把客户端发来的东西读掉，等它关了或者过了一小会儿再关。
    async fn close(mut self) {
        let discard = async {
            self.stream.shutdown().await?;
            let mut sink = [0; 1024];
            while self.stream.read(&mut sink).await? > 0 {}
            io::Result::Ok(())
        };
        // 超时和出错都只是不再等了，连接反正要关。
        let _ = time::timeout(CLOSE_LINGER, discard).await;
    }

    /// 重置客户端的连接：已经告诉过它"连上了"，之后的失败只能这样表现。
    fn reset(self) {
        reset(self.stream);
    }
}

/// 用 RST 关掉一条连接，客户端是 macOS 上的程序时也让它认（见 `i3t_underlay::tcp_reset`）。
/// 设不上 SO_LINGER 时退化成普通的关闭，没有更好的办法。
pub(crate) fn reset(stream: TcpStream) {
    i3t_underlay::tcp_reset::close(stream);
}

/// 第一个字节，不从缓冲区里取走。
fn first_byte(buf: &[u8]) -> Result<Option<Parsed<u8>>, Infallible> {
    Ok(buf.first().map(|&value| Parsed { value, len: 0 }))
}

/// 客户端说的是哪种代理协议。
#[derive(Debug, Clone, Copy)]
enum Front {
    Socks5,
    Http,
}

impl Front {
    fn established(self) -> Vec<u8> {
        match self {
            Self::Socks5 => socks5::reply(socks5::ReplyCode::Succeeded).to_vec(),
            Self::Http => http::Response::Established.as_bytes().to_vec(),
        }
    }

    fn failure(self, failure: Failure) -> Vec<u8> {
        match self {
            Self::Socks5 => socks5::reply(failure.socks5()).to_vec(),
            Self::Http => failure.http().as_bytes().to_vec(),
        }
    }
}

/// 客户端要做什么。
enum Command {
    /// 一条隧道：SOCKS5 或 HTTP 的 CONNECT。
    Connect,
    /// SOCKS5 的 UDP ASSOCIATE。
    UdpAssociate,
    /// 转发一个明文 HTTP 请求。
    Forward(Plain),
}

/// 一个要转发的明文 HTTP 请求，已经准备好随 OPEN 发出。
struct Plain {
    /// 改写好的请求头，加上握手时一起读进来的那部分请求体。
    first: Vec<u8>,
    /// 请求体剩下的部分到哪里为止。
    body: http::BodyFraming,
}

/// 握手得到的结果：客户端要做什么、去哪里。
struct Ask {
    command: Command,
    /// CONNECT 和明文 HTTP 的目标；UDP ASSOCIATE 时是客户端自称会用来发报文的地址。
    host: Host,
    port: u16,
}

/// SOCKS5 握手：问候、（要认证时的）用户名密码认证、请求（CONNECT 或者 UDP ASSOCIATE）。失败时已经回了相应的应答，返回 `None`。
async fn socks5_handshake(client: &mut Client, gate: Gate) -> Option<Ask> {
    let greeting = match client.read(socks5::Greeting::parse).await {
        Ok(greeting) => greeting,
        Err(broken) => return give_up("问候", &broken),
    };
    let method = greeting.choose(gate.needs_password());
    client.stream.write_all(&socks5::method_selection(method)).await.ok()?;
    let Some(method) = method else {
        tracing::info!("拒绝了一条 SOCKS5 连接：客户端没有提供可用的认证方法（这个代理要用户名和密码）");
        return None;
    };

    let auth = match method {
        socks5::Method::None => None,
        socks5::Method::Password => match client.read(socks5::parse_auth).await {
            Ok(auth) => Some(auth),
            Err(broken) => return give_up("认证", &broken),
        },
    };
    let admitted = gate.admits(auth.as_ref());
    if auth.is_some() {
        client.stream.write_all(&socks5::auth_status(admitted)).await.ok()?;
    }
    if !admitted {
        tracing::info!("拒绝了一条 SOCKS5 连接：用户名或者密码不对");
        return None;
    }

    match client.read(socks5::Request::parse).await {
        Ok(socks5::Request { command, host, port }) => {
            let command = match command {
                socks5::Command::Connect => Command::Connect,
                socks5::Command::UdpAssociate => Command::UdpAssociate,
            };
            Some(Ask { command, host, port })
        }
        Err(Broken::Malformed(error)) => {
            tracing::info!(%error, "拒绝了一个 SOCKS5 请求");
            // 写不出去说明客户端已经走了。
            let _ = client.stream.write_all(&socks5::reply(error.reply())).await;
            None
        }
        Err(broken) => give_up("请求", &broken),
    }
}

/// HTTP 握手：一个 CONNECT 请求，或者一个要转发的明文 HTTP 请求。失败时已经回了相应的应答，返回 `None`。
async fn http_handshake(client: &mut Client, gate: Gate) -> Option<Ask> {
    let request = match client.read(http::Request::parse).await {
        Ok(request) => request,
        Err(Broken::Malformed(error)) => {
            tracing::info!(%error, "拒绝了一个 HTTP 代理请求");
            // 写不出去说明客户端已经走了。
            let _ = client.stream.write_all(error.response().as_bytes()).await;
            return None;
        }
        Err(broken) => return give_up("请求", &broken),
    };
    let (command, host, port, auth) = match request {
        http::Request::Connect(http::Connect { host, port, auth }) => (Command::Connect, host, port, auth),
        http::Request::Forward(http::Forward { host, port, auth, head, body }) => {
            // 握手时多读进来的是请求体的开头，属于这个请求的那一截随请求头一起发出；后面的（流水线里的下一个请求）丢掉。
            let mut body = body.framing();
            let buffered = std::mem::take(&mut client.buffer);
            let Ok(taken) = body.take(&buffered) else {
                tracing::info!("拒绝了一个明文 HTTP 请求：chunked 的请求体写得不对");
                // 写不出去说明客户端已经走了。
                let _ = client.stream.write_all(http::Response::BadRequest.as_bytes()).await;
                return None;
            };
            let first = [head.as_slice(), &buffered[..taken]].concat();
            (Command::Forward(Plain { first, body }), host, port, auth)
        }
    };
    if !gate.admits(auth.as_ref()) {
        tracing::info!(presented = auth.is_some(), "拒绝了一个 HTTP 代理请求：没有带用户名和密码，或者不对");
        // 写不出去说明客户端已经走了。
        let _ = client.stream.write_all(http::Response::ProxyAuthenticationRequired.as_bytes()).await;
        return None;
    }
    Some(Ask { command, host, port })
}

/// 握手读到一半读不下去了：连接出错、客户端走了，或者发来的根本不是这种协议。没有什么可回的，记一行就放弃。
fn give_up<E: std::fmt::Display>(stage: &str, broken: &Broken<E>) -> Option<Ask> {
    match broken {
        Broken::Io(error) => tracing::debug!(stage, %error, "握手时连接出错"),
        Broken::Closed => tracing::debug!(stage, "客户端在握手完成之前关掉了连接"),
        Broken::Malformed(error) => tracing::info!(stage, %error, "拒绝了一条连接：握手报文不合法"),
    }
    None
}

/// 处理代理端口上的一条连接。`entry` 是这个端口在连接进来那一刻的设置，`pass` 是这条连接占着的握手名额（有的话）：
/// 握手完成时还回去，没完成的在这里返回时还。
pub(crate) async fn proxy<C: Connector + Datagrams>(
    shared: &Arc<Shared<C>>,
    netmap: &Netmap,
    entry: Entry,
    stream: TcpStream,
    from: SocketAddr,
    connection: &Connection,
    pass: Option<Pass>,
) {
    let mut client = Client { stream, buffer: Vec::new() };
    let handshake = async {
        let front = match entry.protocol {
            ListenerProtocol::Socks5 => Front::Socks5,
            ListenerProtocol::Http => Front::Http,
            ListenerProtocol::Mixed => match client.sniff().await {
                Ok(front) => front,
                Err(broken) => return give_up("第一个字节", &broken).map(|ask| (Front::Http, ask)),
            },
        };
        let ask = match front {
            Front::Socks5 => socks5_handshake(&mut client, entry.gate).await,
            Front::Http => http_handshake(&mut client, entry.gate).await,
        };
        ask.map(|ask| (front, ask))
    };
    let (front, ask) = match time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Some(done)) => done,
        Ok(None) => return client.close().await,
        Err(_) => {
            tracing::info!("关掉了一条连接：{HANDSHAKE_TIMEOUT:?} 之内没有完成代理握手");
            return;
        }
    };
    // 握手完成了：认证已经过了，之后的连接不再占握手的名额。
    drop(pass);
    // 排空时也先把握手做完：客户端要拿到一个看得懂的拒绝，而不是连接莫名其妙地断了。认证在拒绝之前，
    // 没有用户名和密码的人看不出节点在排空。
    if shared.refuse_while_draining("代理请求") {
        return client.fail(front, Failure::Draining).await;
    }

    if matches!(ask.command, Command::UdpAssociate) {
        // 每个报文各有各的目标，往哪里去等报文来了再判断。
        let origin = Origin { credential: None, client: origin_address(from) };
        let meter = IngressMeter { listen: &connection.traffic, exit: None };
        let request = udp::association::Ask { declared: (ask.host, ask.port), origin, meter };
        return udp::association::run(shared, entry, client.stream, from, request).await;
    }
    let route = match route::decide(netmap, entry.exit, &ask.host, ask.port) {
        Ok(route) => route,
        Err(reason) => {
            tracing::info!(%reason, "拒绝了一个代理请求");
            return client.fail(front, Failure::Denied).await;
        }
    };

    let class = route::class_for(netmap, entry.class, &route);
    let optimistic = route::optimistic_for(netmap, entry.optimistic, &route);
    let plain = match ask.command {
        Command::Forward(plain) => Some(plain),
        Command::Connect | Command::UdpAssociate => None,
    };
    let Route { peer, key, target, .. } = route;
    let exit = target.needs_exit().then(|| shared.usage.exit(peer));
    if let Some(exit) = &exit {
        exit.started();
    }
    let meter = IngressMeter { listen: &connection.traffic, exit: exit.as_deref().map(ExitTally::traffic) };
    let origin = Origin { credential: None, client: origin_address(from) };
    let request = Open { target, class, origin };
    let carriage = entry.carriage;
    tracing::debug!(%peer, kind = request.target.kind(), ?class, optimistic, ?carriage, "代理请求经对端节点出去");
    let flow = Outbound { peer, key, request: &request, meter, exit: exit.as_deref(), carriage };
    // 明文 HTTP 总是等 REPLY：目标的应答本来就在 REPLY 之后才到，等它不多花时间，被拒绝时客户端还能拿到状态码。
    if optimistic && plain.is_none() {
        without_waiting(shared, client, front, flow).await;
    } else {
        after_reply(shared, client, front, flow, plain).await;
    }
}

/// 一条到对端节点的流要用到的东西。
struct Outbound<'a> {
    peer: NodeId,
    key: PublicKey,
    request: &'a Open,
    meter: IngressMeter<'a>,
    /// 对端是出口时，发起这一侧看到的计数记在这里。
    exit: Option<&'a ExitTally>,
    /// 能不能走 ice3proxy：代理选了它才能。
    carriage: Carriage,
}

/// 目标节点被移除或换钥时停止这条流。先核对当前 netmap，以免错过从选路到开流之间的变化。
async fn peer_revoked(mut netmap: watch::Receiver<Arc<Netmap>>, peer: NodeId, key: PublicKey) -> Reason {
    if netmap.wait_for(|current| current.peer(peer).is_none_or(|entry| entry.key != key)).await.is_ok() {
        return Reason::AccessRevoked;
    }
    // 发送端没了表示节点正在关闭，交给连接层结束流。
    future::pending().await
}

/// 乐观回复：先告诉客户端连上了，读到它的首批数据，和 OPEN 一起发出去，不等对端的 REPLY。
async fn without_waiting<C: Connector + Datagrams>(shared: &Shared<C>, mut client: Client, front: Front, flow: Outbound<'_>) {
    let Outbound { peer, key, request, meter, exit, carriage } = flow;
    if let Err(error) = client.stream.write_all(&front.established()).await {
        return tracing::debug!(%error, "客户端在应答写出去之前断开了");
    }
    let buffered = std::mem::take(&mut client.buffer);
    let first_data = match first_data::read(&mut client.stream, buffered, FIRST_BYTE_WAIT).await {
        Ok(first_data) => first_data,
        Err(error) => return tracing::debug!(%error, "客户端在发出数据之前断开了"),
    };
    // 首批数据随 OPEN 一起发出，不经过搬运时的关卡，在这里补记。
    meter.record(true, first_data.len());
    let route = RouteAtStart::now(&*shared.routes, peer);
    let revoked = peer_revoked(shared.netmap.clone(), peer, key);
    tokio::pin!(revoked);
    let opened = tokio::select! {
        biased;
        _ = &mut revoked => return client.reset(),
        opened = i3t_flow::open(&*shared.connector, peer, request, &first_data, carriage) => opened,
    };
    match opened {
        Ok(pending) => {
            let summary = pending.relay_metered(client.stream, revoked, &meter).await;
            if let (Some(exit), End::Refused(reply)) = (exit, &summary.end) {
                exit.refused_with(reply.status);
            }
            log_summary(peer, request, &summary, &route.ended(&*shared.routes), &shared.netmap.borrow());
        }
        Err(error) => {
            if let Some(exit) = exit {
                exit.unreachable();
            }
            tracing::info!(%peer, ?error, "到对端节点建流失败，重置了客户端的连接");
            client.reset();
        }
    }
}

/// 不用乐观回复：等对端说连上了，才告诉客户端；对端拒绝时客户端拿到的是具体的错误码。
///
/// 转发明文 HTTP 请求（`plain`）时首批数据是改写好的请求，连上之后没有"连上了"要告诉客户端，目标的应答就是给它的回答；
/// 之后只搬这个请求剩下的请求体。
async fn after_reply<C: Connector + Datagrams>(
    shared: &Shared<C>,
    mut client: Client,
    front: Front,
    flow: Outbound<'_>,
    plain: Option<Plain>,
) {
    let Outbound { peer, key, request, meter, exit, carriage } = flow;
    // 客户端这时还没有收到应答，通常什么都没有发；万一握手时多读进来了一点，就当作首批数据。
    let (first_data, mut body) = match plain {
        Some(Plain { first, body }) => (first, Some(body)),
        None => (std::mem::take(&mut client.buffer), None),
    };
    meter.record(true, first_data.len());
    let route = RouteAtStart::now(&*shared.routes, peer);
    let establish = async {
        match i3t_flow::open(&*shared.connector, peer, request, &first_data, carriage).await {
            Ok(pending) => pending.established().await,
            Err(error) => {
                if let Some(exit) = exit {
                    exit.unreachable();
                }
                Err(error)
            }
        }
    };
    let revoked = peer_revoked(shared.netmap.clone(), peer, key);
    tokio::pin!(revoked);
    let opened = tokio::select! {
        biased;
        _ = &mut revoked => return client.fail(front, Failure::Denied).await,
        opened = establish => opened,
    };
    let flow = match opened {
        Ok(flow) => flow,
        Err(FlowError::Refused(reply)) => {
            if let Some(exit) = exit {
                exit.refused_with(reply.status);
            }
            // 说明是对端写的，按 Debug 打印，里面的控制字符会被转义。
            tracing::info!(%peer, kind = request.target.kind(), status = ?reply.status, detail = ?reply.detail, "对端节点拒绝了建流请求");
            return client.fail(front, Failure::from(reply.status)).await;
        }
        Err(error) => {
            tracing::info!(%peer, ?error, "到对端节点建流失败");
            return client.fail(front, Failure::ExitUnavailable).await;
        }
    };
    let summary = match &mut body {
        Some(body) => flow.relay_framed(client.stream, revoked, &meter, body).await,
        None => {
            if let Err(error) = client.stream.write_all(&front.established()).await {
                tracing::debug!(%error, "客户端在应答写出去之前断开了");
                return flow.abort(Reason::ClientReset);
            }
            flow.relay_metered(client.stream, revoked, &meter).await
        }
    };
    log_summary(peer, request, &summary, &route.ended(&*shared.routes), &shared.netmap.borrow());
}

/// 处理端口转发监听上的一条连接：它整个变成到目标节点的一条流。
///
/// 端口转发没有地方告诉客户端错误码，所以不等对端的 REPLY：失败一律表现为连接被重置。
/// 它的流只走共用的连接，和目标节点之间备着 ice3proxy 也不用（ice3proxy 只归选了它的代理）。
pub(crate) async fn forward<C: Connector + Datagrams>(
    shared: &Shared<C>,
    netmap: &Netmap,
    forward: &Forward,
    mut stream: TcpStream,
    from: SocketAddr,
    connection: &Connection,
) {
    if shared.refuse_while_draining("端口转发的连接") {
        return reset(stream);
    }
    if forward.target == netmap.me.id {
        return forward_here(shared, netmap, forward, stream, from, connection).await;
    }
    if !netmap.peer(forward.target).is_some_and(|peer| peer.outbound) {
        tracing::info!(target = %forward.target, "重置了一条端口转发的连接：目标节点不在 netmap 里，或者访问规则不允许本节点访问它");
        return reset(stream);
    }
    let first_data = match first_data::read(&mut stream, Vec::new(), FIRST_BYTE_WAIT).await {
        Ok(first_data) => first_data,
        Err(error) => return tracing::debug!(%error, "客户端在发出数据之前断开了"),
    };
    let meter = IngressMeter { listen: &connection.traffic, exit: None };
    meter.record(true, first_data.len());
    let origin = Origin { credential: None, client: origin_address(from) };
    let class = forward.class.or(netmap.network.class).unwrap_or_default();
    let request = Open { target: Target::Forward { id: forward.id }, class, origin };
    let route = RouteAtStart::now(&*shared.routes, forward.target);
    match i3t_flow::open(&*shared.connector, forward.target, &request, &first_data, Carriage::Shared).await {
        Ok(pending) => {
            let summary = pending.relay_metered(stream, future::pending(), &meter).await;
            if let Some(outcome) = TargetCause::of_summary(&summary) {
                shared.forward_health.record(forward.id, outcome);
            }
            log_summary(forward.target, &request, &summary, &route.ended(&*shared.routes), &shared.netmap.borrow());
        }
        Err(error) => {
            tracing::info!(target = %forward.target, ?error, "到目标节点建流失败，重置了端口转发的连接");
            shared.forward_health.record(forward.id, Err(TargetCause::NodeUnreachable));
            reset(stream);
        }
    }
}

/// 监听和目标都在本节点上的端口转发（比如把回环里的服务转发到本节点的虚拟 IP `10.77.0.1:8080` 上，别的节点经虚拟网卡连进来；
/// 监听也可以在别的地址上，那时连进来的是那块网卡上的机器）：本节点自己去连目标，两条 TCP 接起来。
/// 和别的节点经流来访问时出口模块做的一样：只连下发给本节点、由本节点自己监听的那一条转发指向的地址，
/// 覆盖网的地址和云平台的元数据地址不连，要求的话先发 PROXY protocol 的头。
///
/// 连进来的是谁看来源地址：经虚拟网卡进来的包的来源核对过是那个对端的虚拟 IP，访问规则不允许它访问本节点时它的 TCP 握手进不来；
/// 接受连接时已经查过监听在虚拟 IP 上的只收可以访问本节点的节点和本机（[`crate::manager::virtual_ip_admits`]：从别的网卡进来的不收），
/// 和来源白名单（`allow_from`）。这两项和这条转发本身，netmap 变了之后再核对，不成立了这条连接就重置（[`withdrawn_here`]）。
async fn forward_here<C: Connector + Datagrams>(
    shared: &Shared<C>,
    netmap: &Netmap,
    forward: &Forward,
    mut stream: TcpStream,
    from: SocketAddr,
    connection: &Connection,
) {
    let entry = netmap
        .me
        .forward_targets
        .iter()
        .find(|entry| entry.id == forward.id && entry.listener == netmap.me.id && entry.protocol == forward.protocol)
        .copied();
    let Some(entry) = entry else {
        tracing::info!(forward = forward.id, "重置了一条端口转发的连接：这条转发的目标地址没有下发给本节点");
        shared.forward_health.record(forward.id, Err(TargetCause::NotDeclared));
        return reset(stream);
    };
    let target_ip = entry.addr.ip().to_canonical();
    if netmap.network.is_overlay_address(target_ip) {
        tracing::info!(forward = forward.id, target = %entry.addr, "重置了一条端口转发的连接：目标是覆盖网的地址，本节点不当普通地址去连");
        return reset(stream);
    }
    if netmap::is_cloud_metadata(target_ip) {
        tracing::info!(forward = forward.id, target = %entry.addr, "重置了一条端口转发的连接：目标是云平台的元数据地址，本节点不替别人连它");
        return reset(stream);
    }
    let mut target = match i3t_underlay::tcp_mss::connect(entry.addr).await {
        Ok(target) => target,
        Err(error) => {
            tracing::info!(forward = forward.id, target = %entry.addr, %error, "端口转发的目标连不上，重置了监听上的连接");
            let cause = match error.kind() {
                io::ErrorKind::ConnectionRefused => TargetCause::Refused,
                io::ErrorKind::TimedOut => TargetCause::Timeout,
                io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => TargetCause::Unreachable,
                _ => TargetCause::Other,
            };
            shared.forward_health.record(forward.id, Err(cause));
            return reset(stream);
        }
    };
    shared.forward_health.record(forward.id, Ok(()));
    // 要求了头就一定发：来源是 IPv6 的也写得出来。不发的话，认这个头的服务会把客户端的头几个字节当成头，来源随客户端写。
    if let Some(version) = entry.proxy_protocol {
        let header = crate::proxy_header::encode(version, from, target.peer_addr().unwrap_or(entry.addr));
        if let Err(error) = target.write_all(&header).await {
            tracing::info!(forward = forward.id, %error, "目标在收到 PROXY protocol 的头之前断开了，重置了监听上的连接");
            return reset(stream);
        }
    }
    for side in [&stream, &target] {
        if let Err(error) = i3t_flow::keep_alive(side) {
            tracing::debug!(%error, "打不开内核保活");
        }
    }
    let copied = tokio::select! {
        biased;
        why = withdrawn_here(shared.netmap.clone(), forward, entry.addr, from) => Err(why),
        copied = tokio::io::copy_bidirectional(&mut stream, &mut target) => Ok(copied),
    };
    match copied {
        Ok(Ok((up, down))) => {
            let meter = IngressMeter { listen: &connection.traffic, exit: None };
            meter.record(true, usize::try_from(up).unwrap_or(usize::MAX));
            meter.record(false, usize::try_from(down).unwrap_or(usize::MAX));
            tracing::info!(forward = forward.id, sent = up, received = down, "监听和目标都在本节点上的端口转发的连接结束");
        }
        Ok(Err(error)) => {
            tracing::info!(forward = forward.id, %error, "监听和目标都在本节点上的端口转发的连接异常结束");
            reset(stream);
        }
        Err(why) => {
            tracing::info!(forward = forward.id, %from, why, "重置一条已经建立的端口转发的连接：它不再被允许");
            reset(stream);
            reset(target);
        }
    }
}

/// 等到 netmap 不再让 `from` 的这条连接接着用 `forward`（监听和目标都在本节点上、指向 `target` 的那一条），返回原因。
///
/// 一上来先按现在的 netmap 查一遍：接受连接之后、连上目标之前的变化也算。
async fn withdrawn_here(mut netmap: watch::Receiver<Arc<Netmap>>, forward: &Forward, target: SocketAddr, from: SocketAddr) -> &'static str {
    let mut why = None;
    let withdrawn = netmap.wait_for(|current| {
        why = withdrawn_by(current, forward, target, from);
        why.is_some()
    });
    // 等到的那一版 netmap 的引用不带过下面的 await。
    let withdrawn = withdrawn.await.is_ok();
    match why.filter(|_| withdrawn) {
        Some(why) => why,
        // 发送端没了表示节点正在关闭，连接留给进程的退出去结束。
        None => future::pending().await,
    }
}

/// 按 `netmap`，`from` 的连接还能不能接着用 `forward`（监听和目标都在本节点上、指向 `target` 的那一条）；不能时返回给人看的原因。
///
/// 和接受连接时查的是同样几项：这条转发还在、监听的地址和目标节点没有变，来源过得了虚拟 IP 的限制和白名单，指向的地址没有变。
fn withdrawn_by(netmap: &Netmap, forward: &Forward, target: SocketAddr, from: SocketAddr) -> Option<&'static str> {
    let same = |current: &&Forward| {
        current.id == forward.id && current.protocol == forward.protocol && current.bind == forward.bind && current.target == netmap.me.id
    };
    let Some(current) = netmap.me.forwards.iter().find(same) else {
        return Some("这条端口转发被删掉或者改了");
    };
    if !virtual_ip_admits(netmap, current.bind, from) {
        return Some("来源不再是可以访问本节点的节点");
    }
    if !allowed(&current.allow_from, from) {
        return Some("来源不再在这条端口转发的白名单里");
    }
    let points_to = netmap
        .me
        .forward_targets
        .iter()
        .find(|entry| entry.id == forward.id && entry.listener == netmap.me.id && entry.protocol == forward.protocol)
        .map(|entry| entry.addr);
    (points_to != Some(target)).then_some("这条端口转发指向的地址被删掉或者改了")
}

/// 写进 OPEN 的客户端地址。本机的程序连过来时不带：回环地址对另一头没有意义。
pub(crate) fn origin_address(from: SocketAddr) -> Option<SocketAddr> {
    let ip = from.ip().to_canonical();
    (!ip.is_loopback()).then(|| SocketAddr::new(ip, from.port()))
}

/// 每条流结束时的一行摘要。不记目标地址，只记它是哪一类；记这对节点的连接开始和结束时走的路（relay 写名字，
/// 从 `netmap` 里找）、中间换没换过。不采样。
pub(crate) fn log_summary(peer: NodeId, request: &Open, summary: &Summary, route: &RouteSpan, netmap: &Netmap) {
    tracing::info!(
        %peer,
        kind = request.target.kind(),
        class = ?request.class,
        sent = summary.from_tcp.bytes,
        received = summary.from_flow.bytes,
        first_byte_ms = summary.from_flow.first_byte.map(|elapsed| elapsed.as_millis()),
        end = ?summary.end,
        route_start = %route.start_label(netmap),
        route_end = %route.end_label(netmap),
        route_changed = route.changed,
        "流结束"
    );
}

#[cfg(test)]
mod tests {
    use i3t_model::netmap::{ForwardProtocol, ForwardTarget};

    use super::*;

    #[test]
    fn a_connection_through_a_forward_to_this_node_holds_only_while_everything_it_was_admitted_on_does() {
        let at = |text: &str| text.parse::<SocketAddr>().unwrap();
        let (target, peer, local) = (at("127.0.0.1:8081"), at("10.66.0.2:40000"), at("192.168.1.9:40000"));
        let me = crate::route::tests::netmap().me.id;
        let forward =
            |bind: &str| Forward { id: 9, protocol: ForwardProtocol::Tcp, bind: at(bind), target: me, allow_from: Vec::new(), class: None };
        let with = |forward: &Forward| {
            let mut netmap = crate::route::tests::netmap();
            netmap.me.forwards = vec![forward.clone()];
            netmap.me.forward_targets =
                vec![ForwardTarget { id: 9, protocol: ForwardProtocol::Tcp, addr: target, listener: me, proxy_protocol: None }];
            netmap
        };
        let (on_virtual_ip, everywhere) = (forward("10.66.0.1:8080"), forward("0.0.0.0:8080"));
        assert_eq!(withdrawn_by(&with(&on_virtual_ip), &on_virtual_ip, target, peer), None);
        assert_eq!(withdrawn_by(&with(&everywhere), &everywhere, target, local), None);

        // 转发删掉了、换了监听的地址、改成指向别的节点。
        let mut netmap = with(&everywhere);
        netmap.me.forwards.clear();
        assert!(withdrawn_by(&netmap, &everywhere, target, local).is_some());
        assert!(withdrawn_by(&with(&forward("0.0.0.0:8081")), &everywhere, target, local).is_some());
        let mut netmap = with(&everywhere);
        netmap.me.forwards[0].target = netmap.peers[0].id;
        assert!(withdrawn_by(&netmap, &everywhere, target, local).is_some());

        // 白名单收紧了：不在里面的断开，还在里面的留着。
        let mut netmap = with(&everywhere);
        netmap.me.forwards[0].allow_from = vec!["192.168.1.0/24".parse().unwrap()];
        assert_eq!(withdrawn_by(&netmap, &everywhere, target, local), None);
        assert!(withdrawn_by(&netmap, &everywhere, target, peer).is_some());

        // 监听在虚拟 IP 上的：对端不再能访问本节点。
        let mut netmap = with(&on_virtual_ip);
        netmap.peers.iter_mut().for_each(|peer| peer.inbound = false);
        assert!(withdrawn_by(&netmap, &on_virtual_ip, target, peer).is_some());

        // 指向的地址改了、没有了。
        let mut netmap = with(&everywhere);
        netmap.me.forward_targets[0].addr = at("127.0.0.1:8082");
        assert!(withdrawn_by(&netmap, &everywhere, target, local).is_some());
        netmap.me.forward_targets.clear();
        assert!(withdrawn_by(&netmap, &everywhere, target, local).is_some());
    }

    #[test]
    fn loopback_clients_are_not_reported_as_the_origin() {
        assert_eq!(origin_address("127.0.0.1:5000".parse().unwrap()), None);
        assert_eq!(origin_address("[::1]:5000".parse().unwrap()), None);
        assert_eq!(origin_address("[::ffff:127.0.0.1]:5000".parse().unwrap()), None);
        assert_eq!(origin_address("192.168.1.9:5000".parse().unwrap()), Some("192.168.1.9:5000".parse().unwrap()));
        assert_eq!(origin_address("[::ffff:192.168.1.9]:5000".parse().unwrap()), Some("192.168.1.9:5000".parse().unwrap()));
    }

    #[test]
    fn the_first_byte_is_looked_at_without_being_taken() {
        assert_eq!(first_byte(b""), Ok(None));
        assert_eq!(first_byte(&[0x05, 0x01, 0x00]), Ok(Some(Parsed { value: 0x05, len: 0 })));
        assert_eq!(first_byte(b"CONNECT"), Ok(Some(Parsed { value: b'C', len: 0 })));
    }
}
