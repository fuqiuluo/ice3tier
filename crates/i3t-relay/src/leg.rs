//! relay 一侧的 TCP 中转：UDP 用不了的节点连上来，在这条 TCP 里做同样的握手、收发同样的帧。
//!
//! 拨进来的是 netmap 里别的 relay 时，这条 TCP 还是骨干上的一段（[`i3t_path::backbone`]）：本节点的路径层在上面反过来
//! 和它建会话，所以这条 TCP 上来的应答、矩阵行和送给本节点的包交给路径层，别的照常。
//!
//! # 没有握手成功的连接
//!
//! 谁都可以连上来，所以还没有会话的连接要尽快打发掉，不能让人占着位子把只能走 TCP 的节点挡在外面：
//!
//! - 从接受连接时算起 [`HANDSHAKE_TIMEOUT`] 之内必须握手成功，这期间来多少帧都不延长；
//! - 握手成功之后会话又没了的（过期、节点在别处重新握了手、被从名单里去掉、换了公钥）也一样：从发现会话没了算起
//!   [`HANDSHAKE_TIMEOUT`] 之内要重新握手成功，来多少帧都不延长；
//! - 握手成功之前只收 INIT 和 AUTH，来了别的就断开；
//! - 同一个来源（IPv4 地址，或者 IPv6 的 /64）同时最多有 [`MAX_PENDING_PER_SOURCE`] 条还没握手成功的连接。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use i3t_proto::session::Frame;
use i3t_proto::{Datagram, NodeId};
use i3t_underlay::tcp_leg::{self, FrameReader};
use i3t_underlay::tcp_recovery::Recovery;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::limit::source_key;
use crate::relay::{Inner, Source, Via};
use crate::session::{SESSION_TTL, TcpConn};

/// 连上来之后多久之内必须握手成功。没有会话的 TCP 不值得留着。
///
/// 握手是两个往返。只能走 TCP 的节点往往就在丢包的链路上，一次重传一两秒，所以留 10 秒；
/// 占着连接不握手的人被每个来源的条数上限挡着，这个时间长一点不给他们多少便宜。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 同时最多接多少条 TCP。每个走 TCP 的节点只有一条，这个数对个人用的网络绰绰有余；
/// 它挡的是有人开一大堆连接又不握手。
const MAX_LEGS: usize = 1024;
/// 同一个来源同时最多有几条还没握手成功的 TCP。同一个 NAT 后面的几个节点同时连上来也够用。
const MAX_PENDING_PER_SOURCE: usize = 8;
/// 拒绝连接的日志最多隔这么久记一条，中间拒绝了多少条写在下一条里。
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);
/// 还没来得及接受的连接最多排多少条。
const LISTEN_BACKLOG: i32 = 1024;

/// 在 UDP 端口的同一个地址和端口号上监听 TCP。
///
/// # Errors
///
/// 绑不上（端口被别的程序占着）。调用方稍后再试。
pub(crate) fn listen(inner: &Arc<Inner>) -> io::Result<JoinHandle<()>> {
    let addr = inner.port.local_addr();
    let listener = bind(addr)?;
    tracing::info!(%addr, "relay 开始监听 TCP 中转");
    Ok(tokio::spawn(accept(Arc::clone(inner), listener)))
}

/// UDP 端口是双栈的（绑在 `[::]` 上）时，TCP 也要 IPv4 和 IPv6 都接。有的系统上 IPv6 的 TCP 默认不接 IPv4，所以明确设一下。
fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6()
        && let Err(error) = socket.set_only_v6(false)
    {
        tracing::debug!(%error, "这个系统上 IPv6 的 TCP 监听不能同时接 IPv4 的连接");
    }
    // 和标准库在 Unix 上的做法一样：进程重启之后不用等旧连接的 TIME_WAIT 过去就能重新绑定。Windows 上这个选项的含义是
    // "允许别的进程抢同一个端口"，不能设。
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    // 接进来的中转和 lane 都继承它：对端发过来的分段不超过压低的 MSS（路径 MTU 黑洞，见 `i3t_underlay::tcp_mss`）。
    // 只在 Linux 上管用；别的 Unix 在接进来之后才能设，而且只压得住本端发的（[`accept`] 里的 `tcp_mss::accept`）。
    i3t_underlay::tcp_mss::clamp(&socket);
    socket.bind(&addr.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    TcpListener::from_std(socket.into())
}

async fn accept(inner: Arc<Inner>, listener: TcpListener) {
    let gate = Arc::new(Gate {
        slots: Arc::new(Semaphore::new(MAX_LEGS)),
        pending: Arc::new(Pending::default()),
        unclassified: Arc::new(Unclassified::default()),
        refusals: Mutex::new(RefusalLog::default()),
    });
    let mut enabled = inner.subscribe_enabled();
    loop {
        let accepted = tokio::select! {
            // relay 被停用，或者整个 relay 被丢弃了：不再监听。
            _ = enabled.wait_for(|enabled| !enabled) => return,
            accepted = i3t_underlay::tcp_mss::accept(&listener) => accepted,
        };
        let (stream, addr) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                // 多半是文件描述符用完了。歇一下再接，不然会空转。
                tracing::warn!(%error, "relay 接受 TCP 连接失败");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let handoff = inner.tcp_handoff.read().expect("relay tcp handoff lock poisoned").clone();
        match handoff {
            // 端口上只有中转：和以前一样，接受了就按中转的规矩来。
            None => gate.serve_leg(&inner, stream, addr),
            Some(handoff) => {
                let Some(ticket) = gate.unclassified.admit(addr.ip()) else {
                    gate.refused(addr, "这个来源还没认出协议的 TCP 太多，拒绝新的连接");
                    continue;
                };
                let (gate, inner) = (Arc::clone(&gate), Arc::clone(&inner));
                tokio::spawn(async move {
                    let mut first = [0; 1];
                    let peeked = tokio::time::timeout(CLASSIFY_TIMEOUT, stream.peek(&mut first)).await;
                    drop(ticket);
                    match peeked {
                        Ok(Ok(1..)) if first[0] == LANE_FIRST_BYTE => handoff(stream, addr),
                        Ok(Ok(1..)) => gate.serve_leg(&inner, stream, addr),
                        // 什么都没发就断了、出错了，或者迟迟不说话：不值得留着。外人能造成的，只记 debug。
                        Ok(Ok(_) | Err(_)) => tracing::debug!(from = %addr, "TCP 连接没有发来任何字节就结束了"),
                        Err(_) => tracing::debug!(from = %addr, "TCP 连接 {CLASSIFY_TIMEOUT:?} 之内没有发来第一个字节，断开"),
                    }
                });
            }
        }
    }
}

/// 同一个端口上还接 ice3proxy 时，连接多久之内要发来第一个字节，才知道它是哪一种。
pub(crate) const CLASSIFY_TIMEOUT: Duration = Duration::from_secs(3);
/// ice3proxy 以 TLS 的握手记录开头。中转以 2 字节的帧长度开头，第一帧是很短的会话握手，高字节远小于它。
const LANE_FIRST_BYTE: u8 = 0x16;
/// 还没认出协议的 TCP，同一个来源同时最多几条。比中转的握手名额（8）大：一个拨 ice3proxy 的节点池被抽干时
/// 一下子会拨上百条（它自己限制在 128 条以内），全都从同一个地址来，第一个字节一个往返之内就到。
const MAX_UNCLASSIFIED_PER_SOURCE: usize = 256;
/// 还没认出协议的 TCP，全部来源合计最多几条。
const MAX_UNCLASSIFIED: usize = 1024;

/// 接受下来的 TCP 要过的几道名额，和拒绝时的日志。
struct Gate {
    slots: Arc<Semaphore>,
    pending: Arc<Pending>,
    unclassified: Arc<Unclassified>,
    refusals: Mutex<RefusalLog>,
}

impl Gate {
    /// 按中转的规矩接下一条 TCP：总数上限、同一来源还没握手成功的上限，然后服务它。
    fn serve_leg(&self, inner: &Arc<Inner>, stream: TcpStream, addr: SocketAddr) {
        let Ok(slot) = Arc::clone(&self.slots).try_acquire_owned() else {
            return self.refused(addr, "TCP 中转的连接数到了上限，拒绝新的连接");
        };
        let Some(handshake) = self.pending.admit(addr.ip()) else {
            return self.refused(addr, "这个来源已经有太多条 TCP 还没握手成功，拒绝新的连接");
        };
        let inner = Arc::clone(inner);
        tokio::spawn(async move {
            let reason = serve(&inner, stream, addr, handshake).await;
            tracing::debug!(from = %addr, reason, "一条 TCP 中转结束");
            drop(slot);
        });
    }

    /// 拒绝一条连接。日志限速：有人一直往上连的时候不刷屏。
    fn refused(&self, addr: SocketAddr, what: &str) {
        if let Some(more) = self.refusals.lock().expect("refusal log mutex poisoned").due(Instant::now()) {
            tracing::warn!(from = %addr, more, max_legs = MAX_LEGS, max_pending = MAX_PENDING_PER_SOURCE, "{what}");
        }
    }
}

/// 还没认出协议的 TCP 有几条，按来源算，另有总数。
#[derive(Debug, Default)]
struct Unclassified(Mutex<(HashMap<IpAddr, usize>, usize)>);

/// 一条还没认出协议的 TCP 占着的名额。
#[derive(Debug)]
struct Unknown {
    counts: Arc<Unclassified>,
    source: IpAddr,
}

impl Unclassified {
    fn admit(self: &Arc<Self>, from: IpAddr) -> Option<Unknown> {
        let source = source_key(from);
        let mut counts = self.0.lock().expect("unclassified TCP mutex poisoned");
        let (by_source, total) = &mut *counts;
        let count = by_source.entry(source).or_default();
        if *count >= MAX_UNCLASSIFIED_PER_SOURCE || *total >= MAX_UNCLASSIFIED {
            return None;
        }
        *count += 1;
        *total += 1;
        Some(Unknown { counts: Arc::clone(self), source })
    }
}

impl Drop for Unknown {
    fn drop(&mut self) {
        let mut counts = self.counts.0.lock().expect("unclassified TCP mutex poisoned");
        let (by_source, total) = &mut *counts;
        *total = total.saturating_sub(1);
        if let Some(count) = by_source.get_mut(&self.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                by_source.remove(&self.source);
            }
        }
    }
}

/// 还没握手成功的 TCP 有几条，按来源算。
#[derive(Debug, Default)]
struct Pending(Mutex<HashMap<IpAddr, usize>>);

impl Pending {
    /// 来自 `from` 的一条新连接能不能接。能的话返回它占着的名额，握手成功或者连接结束时放掉。
    fn admit(self: &Arc<Self>, from: IpAddr) -> Option<Handshaking> {
        let source = source_key(from);
        let mut by_source = self.0.lock().expect("pending TCP legs mutex poisoned");
        let count = by_source.entry(source).or_default();
        if *count >= MAX_PENDING_PER_SOURCE {
            return None;
        }
        *count += 1;
        Some(Handshaking { pending: Arc::clone(self), source })
    }
}

/// 一条还没握手成功的 TCP 占着的名额。
#[derive(Debug)]
struct Handshaking {
    pending: Arc<Pending>,
    source: IpAddr,
}

impl Drop for Handshaking {
    fn drop(&mut self) {
        let mut by_source = self.pending.0.lock().expect("pending TCP legs mutex poisoned");
        if let Some(count) = by_source.get_mut(&self.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                by_source.remove(&self.source);
            }
        }
    }
}

/// 拒绝连接的日志的限速：有人一直往上连的时候不刷屏。
#[derive(Debug, Default)]
struct RefusalLog {
    logged: Option<Instant>,
    skipped: u64,
}

impl RefusalLog {
    /// 这一次拒绝要不要记日志。要的话返回上一条之后又悄悄拒绝了多少条。
    fn due(&mut self, now: Instant) -> Option<u64> {
        if self.logged.is_some_and(|at| now.saturating_duration_since(at) < REFUSAL_LOG_INTERVAL) {
            self.skipped += 1;
            return None;
        }
        self.logged = Some(now);
        Some(std::mem::take(&mut self.skipped))
    }
}

/// 握手成功之前只收这两种帧。
fn is_handshake(frame: &[u8]) -> bool {
    matches!(Datagram::parse(frame), Ok(Datagram::Session(Frame::Init(_) | Frame::Auth(_))))
}

/// 服务一条 TCP，直到它断开、超时或者 relay 被停用。返回结束的原因，给日志用。
async fn serve(inner: &Inner, stream: TcpStream, addr: SocketAddr, handshake: Handshaking) -> &'static str {
    if let Err(error) = tcp_leg::configure(&stream) {
        tracing::debug!(from = %addr, %error, "给 TCP 中转设置选项失败");
        return "设置不了 socket 选项";
    }
    // 重传上限和放弃时限一起设（见 `i3t_underlay::tcp_recovery`）。放弃时限取会话的有效期：relay 自己留着一条没有任何帧的
    // TCP 也就这么久，TCP 不会比它先判死，也不会在它关掉之后还留着。
    Recovery::giving_up_after(SESSION_TTL).apply(&stream);
    let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
    let id = inner.next_conn();
    let conn = TcpConn::Accepted(id);
    let (read_half, write_half) = stream.into_split();
    let (sender, queue) = tcp_leg::frame_queue();
    let writer = tokio::spawn(tcp_leg::write_frames(write_half, queue));
    let mut reader = FrameReader::new(read_half);
    let mut enabled = inner.subscribe_enabled();
    let source = Source { addr, via: Via::Tcp { conn, sender: &sender } };
    let mut owner: Option<NodeId> = None;
    // 这条 TCP 上没有会话的时候，最晚到什么时候要握手成功。握手成功之前从接受连接时算起；之后会话又没了的，
    // 从发现它没了的那一刻算起。来多少帧都不延长：不然占着连接的人隔几秒发一帧就能一直留着。
    let mut handshake_by = Some(Instant::now() + HANDSHAKE_TIMEOUT);
    let mut handshake = Some(handshake);

    let reason = loop {
        // 有会话的时候按会话的有效期等，每一帧重新算：节点的 PING 也从这条 TCP 来，这么久没有任何帧说明它不在了。
        let has_session = owner.is_some_and(|node| inner.tcp_session_alive(node, conn));
        let until = if has_session {
            handshake_by = None;
            Instant::now() + SESSION_TTL
        } else {
            *handshake_by.get_or_insert_with(|| Instant::now() + HANDSHAKE_TIMEOUT)
        };
        tokio::select! {
            _ = enabled.wait_for(|enabled| !enabled) => break "relay 停用",
            frame = tokio::time::timeout_at(until, reader.next()) => match frame {
                Ok(Ok(Some(frame))) => {
                    if owner.is_none() && !is_handshake(&frame) {
                        break "握手成功之前发来了别的帧";
                    }
                    // 拨进来的是别的 relay：本节点自己在它那里的会话也在这条 TCP 上，那一部分的帧归路径层。
                    // 它的会话还在不在这条 TCP 上由 `neighbour_frame` 现看，不用上面等这一帧之前看到的。
                    if owner.is_some_and(|node| inner.neighbour_frame(node, id, &frame)) {
                        continue;
                    }
                    if let Some(node) = inner.handle_tcp_frame(&source, &frame) {
                        owner = Some(node);
                        // 握手成功了：不再占着"还没握手成功"的名额。
                        drop(handshake.take());
                        if inner.is_relay(node)
                            && let Some(inbox) = inner.inbox()
                        {
                            inbox.opened(node, id, addr, sender.clone());
                        }
                    }
                }
                Ok(Ok(None)) => break "对方关闭",
                Ok(Err(_)) => break "读出错",
                Err(_) if has_session => break "会话过期",
                Err(_) if owner.is_some() => break "会话没了之后迟迟没有重新握手",
                Err(_) => break "迟迟没有握手成功",
            },
        }
    };
    inner.close_tcp(conn);
    if let Some((node, inbox)) = owner.filter(|node| inner.is_relay(*node)).zip(inner.inbox()) {
        inbox.closed(node, id);
    }
    writer.abort();
    reason
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connections_accepted_by_the_relay_port_are_told_the_clamped_segment_size() {
        // 连上来的一方自己什么都不设（像别的程序那样）：它发过来的分段照样不超过 relay 通告的 MSS。回环的 MTU 很大
        // （Linux 65536，macOS 16384），不压的话是一万多到六万多。lane 也是这个端口接进来的。接的做法和 [`accept`] 里一样。
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let (dialled, accepted) =
            tokio::join!(TcpStream::connect(listener.local_addr().unwrap()), i3t_underlay::tcp_mss::accept(&listener));
        let (dialled, (accepted, _)) = (dialled.unwrap(), accepted.unwrap());
        let mss = |stream: &TcpStream| socket2::SockRef::from(stream).tcp_mss().unwrap();
        let clamped = u32::from(i3t_underlay::tcp_mss::DEFAULT);
        assert!(mss(&accepted) <= clamped, "接进来的连接的 MSS 是 {}", mss(&accepted));
        // macOS 上通告的 MSS 压不低（`i3t_underlay::tcp_mss::ADVERTISED`，那边的测试确认了这一点）：连上来的若不是本程序，
        // 从它那里过来的方向遇到路径 MTU 黑洞还是会卡。本程序的节点连上来时它自己会压住它发的。
        if i3t_underlay::tcp_mss::ADVERTISED {
            assert!(mss(&dialled) <= clamped, "连上来的一方的 MSS 是 {}", mss(&dialled));
        }
    }
}
