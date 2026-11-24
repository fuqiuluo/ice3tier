//! 节点侧到 relay 的 TCP 连接（UDP 不可用时的回退通道）。握手规则见 [`crate::relays`]，本模块仅负责连接建立与帧收发。
//!
//! 当本节点为 relay 且拨号目标为另一个 relay 时，该 TCP 连接作为骨干链路（[`crate::backbone`]）：对方在该连接上反向与本节点
//! relay 建立会话并转发数据报，相关帧交给本节点 relay 处理。另一种情况是由其他 relay 拨入、本节点 relay 接受的连接，
//! 路径层直接复用该连接（[`TcpLegHandle::adopted`]），读写仍由 relay 侧负责。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use i3t_proto::Datagram;
use i3t_proto::datagram::RelayHeader;
use i3t_proto::session::{Echo, Frame, Refused};
use i3t_underlay::tcp_leg::{self, FrameQueue, FrameReader, FrameSender};
use i3t_underlay::tcp_mss;
use i3t_underlay::tcp_recovery::Recovery;
use tokio::net::TcpStream;
use tokio::task::{JoinHandle, JoinSet};

use crate::SessionLeg;
use crate::control::Ctrl;
use crate::table::{RelaySlot, Shared};
use crate::timing::TCP_LEG_GIVE_UP;

/// 单个地址的连接超时时间。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
/// relay 存在多个地址时，若前一个地址尚未连上，每隔该时间并发尝试下一个地址（前一个失败时立即尝试下一个）。
/// 不可达地址通常会静默丢包，若顺序等待完整的 [`CONNECT_TIMEOUT`]，排在后面的可用地址将被延迟数秒。
const CONNECT_STAGGER: Duration = Duration::from_millis(250);

/// 该 TCP 连接上产生并上报给控制任务的事件。
#[derive(Debug)]
pub(crate) enum TcpEvent {
    /// 已连接到该地址。
    Connected(SocketAddr),
    /// relay 发来的会话帧（错误帧除外）。
    Frame(Frame),
    /// relay 发来的错误帧及其回显字节。
    Refusal(Refused, Echo),
    /// relay 发来的骨干矩阵行（完整帧）。
    Row(Bytes),
    /// 连接失败或已断开。
    Closed,
}

/// 到 relay 的 TCP 连接句柄。丢弃该句柄将关闭连接（复用的外部拨入连接除外，其所有权属于本节点 relay）。
#[derive(Debug)]
pub(crate) struct TcpLegHandle {
    /// 控制任务为该 TCP 连接分配的编号。同一 relay 多次重连时，用于识别迟到事件所属的连接。
    pub(crate) conn: u64,
    pub(crate) sender: FrameSender,
    origin: Origin,
}

#[derive(Debug)]
enum Origin {
    /// 本节点主动拨出的连接及其读写任务。
    Dialled { task: JoinHandle<()>, shared: Arc<Shared> },
    /// 其他 relay 拨入、由本节点 relay 接受的第 `accepted` 条连接（relay 侧编号）。
    Adopted { accepted: u64 },
}

impl TcpLegHandle {
    /// 复用其他 relay 拨入的第 `accepted` 条 TCP 连接（[`crate::backbone`]）：路径层在其上建立会话，通过 `sender` 写入帧。
    pub(crate) const fn adopted(conn: u64, accepted: u64, sender: FrameSender) -> Self {
        Self { conn, sender, origin: Origin::Adopted { accepted } }
    }

    /// 复用连接在 relay 侧的编号；本节点主动拨出时为 `None`。
    pub(crate) const fn accepted(&self) -> Option<u64> {
        match self.origin {
            Origin::Adopted { accepted } => Some(accepted),
            Origin::Dialled { .. } => None,
        }
    }

    /// 检查对方 relay 在本节点 relay 上的会话（`theirs`）是否位于该 TCP 连接上：骨干链路需两端会话共用同一条 TCP 连接方可互通。
    pub(crate) fn carries(&self, theirs: SessionLeg) -> bool {
        match self.origin {
            Origin::Adopted { accepted } => theirs == SessionLeg::Accepted(accepted),
            Origin::Dialled { .. } => theirs == SessionLeg::Dialled(self.conn),
        }
    }
}

impl Drop for TcpLegHandle {
    fn drop(&mut self) {
        if let Origin::Dialled { task, shared } = &self.origin {
            task.abort();
            // 对方反向绑定在该 TCP 连接上的骨干会话随之失效。
            if let Some(local) = shared.local_relay.get() {
                local.leg_closed(self.conn);
            }
        }
    }
}

/// 尝试连接 `addrs` 中的地址（按顺序错峰并发连接，取最先建立的一条），随后在该 TCP 连接上收发帧。
pub(crate) fn spawn(shared: Arc<Shared>, relay: Arc<RelaySlot>, conn: u64, addrs: Vec<SocketAddr>) -> TcpLegHandle {
    let (sender, queue) = tcp_leg::frame_queue();
    let leg = sender.clone();
    let task = tokio::spawn({
        let shared = Arc::clone(&shared);
        async move {
            let reason = run(&shared, &relay, conn, &addrs, (leg, queue)).await;
            tracing::debug!(relay = %relay.id, conn, reason, "到 relay 的 TCP 连接结束");
            // 控制任务已停止时无需处理该关闭事件。
            let _closed = shared.ctrl.send(Ctrl::Tcp { relay: relay.id, conn, event: TcpEvent::Closed }).await;
        }
    });
    TcpLegHandle { conn, sender, origin: Origin::Dialled { task, shared } }
}

async fn run(
    shared: &Shared,
    relay: &RelaySlot,
    conn: u64,
    addrs: &[SocketAddr],
    (sender, queue): (FrameSender, FrameQueue),
) -> &'static str {
    let Ok((stream, addr)) = connect_first(addrs).await else { return "TCP 连接失败" };
    if tcp_leg::configure(&stream).is_err() {
        return "socket选项无法修改";
    }
    if !Recovery::giving_up_after(TCP_LEG_GIVE_UP).apply(&stream) {
        tracing::debug!(relay = %relay.id, "到 relay 的 TCP 连接未设置重传超时上限（内核不支持），断网后恢复会较慢");
    }
    if shared.ctrl.send(Ctrl::Tcp { relay: relay.id, conn, event: TcpEvent::Connected(addr) }).await.is_err() {
        return "路径层已停止";
    }
    let (read_half, write_half) = stream.into_split();
    let leg = Leg { conn, addr, sender };
    tokio::select! {
        _ = tcp_leg::write_frames(write_half, queue) => "TCP 写入任务结束",
        reason = read(shared, relay, &leg, FrameReader::new(read_half)) => reason,
    }
}

/// 读取该 TCP 连接所需的上下文：连接编号、对端地址及写入端（供本节点 relay 应答使用）。
struct Leg {
    conn: u64,
    addr: SocketAddr,
    sender: FrameSender,
}

/// 按顺序尝试连接 `addrs`：每隔 250 毫秒（或前一个地址失败后立即）并发连接下一个地址，取最先成功的一条，
/// 取消其余尝试。单个地址最多等待 4 秒，避免排在前面的不可达地址阻塞后续可用地址。
/// 握手阶段会通告下调后的 MSS（[`tcp_mss`]）。
///
/// controller 发现的 relay 地址并非全部可达，到 relay 的 TCP 中继连接与 ice3proxy（`i3t-lane`）
/// 均采用该策略。调用方应将上次成功连接的地址排在 `addrs` 最前。
///
/// # Errors
///
/// 所有地址均连接失败时返回最后一个错误；全部超时（或 `addrs` 为空）时返回 [`io::ErrorKind::TimedOut`]。
pub async fn connect_first(addrs: &[SocketAddr]) -> io::Result<(TcpStream, SocketAddr)> {
    let mut pending = addrs.iter().copied();
    let mut attempts = JoinSet::new();
    let mut next_start = tokio::time::Instant::now();
    let mut last_error = io::Error::new(io::ErrorKind::TimedOut, "无可达地址");
    loop {
        let more = pending.len() > 0;
        tokio::select! {
            () = tokio::time::sleep_until(next_start), if more => {
                if let Some(addr) = pending.next() {
                    attempts.spawn(async move { (addr, tokio::time::timeout(CONNECT_TIMEOUT, tcp_mss::connect(addr)).await) });
                }
                next_start = tokio::time::Instant::now() + CONNECT_STAGGER;
            }
            Some(done) = attempts.join_next() => match done {
                Ok((addr, Ok(Ok(stream)))) => return Ok((stream, addr)),
                Ok((addr, Ok(Err(error)))) => {
                    tracing::debug!(%addr, %error, "TCP 连接失败");
                    last_error = error;
                    next_start = tokio::time::Instant::now();
                }
                Ok((addr, Err(_))) => tracing::debug!(%addr, "TCP 连接超时"),
                // 连接任务不会 panic，仅在此处取消丢弃。
                Err(_) => {}
            },
            else => return Err(last_error),
        }
    }
}

/// 读取该 TCP 连接：将发往本节点的中转帧去除头部后交给连接层，会话应答与矩阵行交给控制任务；
/// 对方 relay 的会话请求与待转发数据包交给本节点 relay（非 relay 节点丢弃）；其余帧丢弃。
async fn read(shared: &Shared, relay: &RelaySlot, leg: &Leg, mut reader: FrameReader) -> &'static str {
    let conn = leg.conn;
    let to_relay = |frame: &[u8]| {
        if let Some(local) = shared.local_relay.get() {
            local.handle_leg_frame(leg.conn, leg.addr, &leg.sender, frame);
        }
    };
    loop {
        let frame = match reader.next().await {
            Ok(Some(frame)) => frame,
            Ok(None) => return "relay 已关闭连接",
            Err(_) => return "TCP 读取失败",
        };
        relay.last_rx.touch(&shared.clock);
        match Datagram::parse(&frame) {
            Ok(Datagram::Relayed { header, .. }) if header.dst == shared.me => {
                // 连接层来不及接收时在此阻塞，背压传递回该 TCP 连接，relay 端队列将开始丢包。
                if shared.inbound.send((header.src, frame.slice(RelayHeader::LEN..))).await.is_err() {
                    return "路径层已停止";
                }
            }
            // 多级中转的包：这条 TCP 通向的 relay 必须就是路径上的最后一个。
            Ok(Datagram::Routed { header, .. })
                if header.dst == shared.me && header.relays.last() == relay.id && header.relays.around(shared.me).is_none() =>
            {
                if shared.inbound.send((header.src, frame.slice(header.encoded_len()..))).await.is_err() {
                    return "路径层已停止";
                }
            }
            // 骨干：对方在这条 TCP 上反过来和本节点的 relay 建会话、保活，或者把要本节点往下转的包交过来。
            Ok(Datagram::Session(session)) if session.is_request() => to_relay(&frame),
            Ok(Datagram::Relayed { .. }) => to_relay(&frame),
            Ok(Datagram::Routed { header, .. }) if header.relays.around(shared.me).is_some() => to_relay(&frame),
            Ok(Datagram::Session(session)) if !session.is_request() => {
                let event = match (session, Refused::echo(&frame)) {
                    (Frame::Error(refused), Some(echo)) => TcpEvent::Refusal(refused, echo),
                    (session, _) => TcpEvent::Frame(session),
                };
                if shared.ctrl.send(Ctrl::Tcp { relay: relay.id, conn, event }).await.is_err() {
                    return "路径层已停止";
                }
            }
            Ok(Datagram::Row(_)) => {
                if shared.ctrl.send(Ctrl::Tcp { relay: relay.id, conn, event: TcpEvent::Row(frame) }).await.is_err() {
                    return "路径层已停止";
                }
            }
            Ok(_) | Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// 一个不回答握手的地址，和让它不回答的东西（丢掉之后地址就不"死"了）。
    ///
    /// 两种系统做法不同，各用各的：
    /// - Linux、Windows：监听着、却从不接受连接，等着接受的队列已经满了，再来的 SYN 内核直接丢掉。
    ///   只绑定、不监听的 socket 在这两个系统上会回 RST，不行。
    /// - macOS：队列满了照样回应握手（CI 上量到 300 毫秒之内就有了结果），不行；只绑定、不监听的 socket 收到 SYN 什么都不回，正好。
    async fn silent_address() -> (SocketAddr, Box<dyn std::any::Any + Send>) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = socket.local_addr().unwrap();
        if cfg!(target_os = "macos") {
            return (addr, Box::new(socket));
        }
        let listener = socket.listen(0).unwrap();
        let filler = TcpStream::connect(addr).await.unwrap();
        (addr, Box::new((listener, filler)))
    }

    #[tokio::test]
    async fn an_address_that_never_answers_does_not_hold_up_the_next_one() {
        // 排在前面的地址不回答：错开一点时间就去连下一个，不等它超时。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        let (dead, _silence) = silent_address().await;
        assert!(tokio::time::timeout(Duration::from_millis(300), TcpStream::connect(dead)).await.is_err(), "这个地址应该不回答");
        let started = tokio::time::Instant::now();
        let (stream, addr) = connect_first(&[dead, live]).await.unwrap();
        assert_eq!(addr, live);
        assert!(started.elapsed() < Duration::from_secs(1), "等了 {:?}", started.elapsed());

        // 连上的那一条压低了 MSS：本端发出去的分段不超过它；系统能通告时（`tcp_mss::ADVERTISED`，macOS 不能），对端
        // （这里是一个什么都不设的监听者）发过来的也不超过它。回环上不压的话是一万多到六万多。
        #[cfg(unix)]
        {
            let accepted = listener.accept().await.unwrap().0;
            let clamped = u32::from(tcp_mss::DEFAULT);
            assert!(socket2::SockRef::from(&stream).tcp_mss().unwrap() <= clamped);
            if tcp_mss::ADVERTISED {
                assert!(socket2::SockRef::from(&accepted).tcp_mss().unwrap() <= clamped, "对端按本端通告的 MSS 发");
            }
        }
        drop(stream);

        // 一个也连不上：说出最后一个的原因。
        drop(listener);
        assert!(connect_first(&[live]).await.is_err());
        assert_eq!(connect_first(&[]).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
