//! 最小的 relay：按中转头里的目的节点查表，把包原样转发出去。不解密，不缓冲，发不出去就丢。
//!
//! 节点可以用 UDP 挂上来，也可以用一条 TCP 挂上来；两种可以混用，relay 在中间转换。

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use bytes::Bytes;
use quinn::udp::{BATCH_SIZE, RecvMeta, Transmit, UdpSocketState};
use serde::Serialize;
use tokio::io::Interest;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::path::{SOCKET_BUFFER_BYTES, read_frame, write_frames};
use crate::stats::ProcessUsage;
use crate::wire::{self, Frame, NodeId};

/// 内核把同一条流的 UDP 包合并上交时，一次最多 64KB。
const RECV_BUF_LEN: usize = 64 * 1024;

pub struct RelayConfig {
    pub udp: SocketAddr,
    pub tcp: Option<SocketAddr>,
    /// 目的节点不在本 relay 上时转给哪个地址（下一个 relay 的 UDP 端口）。
    pub routes: Vec<(NodeId, SocketAddr)>,
    /// 发往一条 TCP 的包最多排多少个，排满就丢。
    pub tcp_queue: usize,
}

#[derive(Clone)]
enum NextHop {
    Udp(SocketAddr),
    Tcp(mpsc::Sender<Bytes>),
}

#[derive(Debug, Serialize)]
pub struct RelayReport {
    role: &'static str,
    packets: u64,
    bytes: u64,
    dropped: u64,
    /// 调用内核发送的次数。比 `packets` 小多少，说明批量发送合并了多少。
    sends: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<ProcessUsage>,
}

struct Relay {
    io: UdpSocket,
    state: UdpSocketState,
    attached: Mutex<HashMap<NodeId, NextHop>>,
    routes: HashMap<NodeId, SocketAddr>,
    tcp_queue: usize,
    packets: AtomicU64,
    bytes: AtomicU64,
    dropped: AtomicU64,
    sends: AtomicU64,
}

/// 运行到收到 SIGINT / SIGTERM 为止，返回这段时间的转发统计。
pub async fn run(config: RelayConfig) -> anyhow::Result<RelayReport> {
    let std_sock = std::net::UdpSocket::bind(config.udp).with_context(|| format!("绑定 UDP {}", config.udp))?;
    std_sock.set_nonblocking(true)?;
    let state = UdpSocketState::new((&std_sock).into())?;
    state.set_recv_buffer_size((&std_sock).into(), SOCKET_BUFFER_BYTES)?;
    state.set_send_buffer_size((&std_sock).into(), SOCKET_BUFFER_BYTES)?;
    let relay = Arc::new(Relay {
        state,
        io: UdpSocket::from_std(std_sock)?,
        attached: Mutex::new(HashMap::new()),
        routes: config.routes.into_iter().collect(),
        tcp_queue: config.tcp_queue.max(1),
        packets: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
        sends: AtomicU64::new(0),
    });

    if let Some(addr) = config.tcp {
        let listener = TcpListener::bind(addr).await.with_context(|| format!("绑定 TCP {addr}"))?;
        tokio::spawn(Arc::clone(&relay).accept_tcp(listener));
    }
    let udp_loop = tokio::spawn(Arc::clone(&relay).forward_udp());

    crate::wait_for_shutdown().await?;
    udp_loop.abort();
    relay.report()
}

impl Relay {
    fn report(&self) -> anyhow::Result<RelayReport> {
        Ok(RelayReport {
            role: "relay",
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            sends: self.sends.load(Ordering::Relaxed),
            usage: ProcessUsage::of_this_process(),
        })
    }

    fn next_hop(&self, dst: NodeId) -> Option<NextHop> {
        let attached = self.attached.lock().expect("attached mutex poisoned");
        attached.get(&dst).cloned().or_else(|| self.routes.get(&dst).copied().map(NextHop::Udp))
    }

    fn attach(&self, id: NodeId, hop: NextHop) {
        self.attached.lock().expect("attached mutex poisoned").insert(id, hop);
    }

    async fn forward_udp(self: Arc<Self>) {
        let mut storage = vec![0u8; RECV_BUF_LEN * BATCH_SIZE];
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        loop {
            if let Err(err) = self.io.readable().await {
                eprintln!("relay 的 UDP socket 出错：{err}");
                return;
            }
            let received = {
                let mut iovs: Vec<IoSliceMut<'_>> = storage.chunks_mut(RECV_BUF_LEN).map(IoSliceMut::new).collect();
                self.io.try_io(Interest::READABLE, || self.state.recv((&self.io).into(), &mut iovs, &mut metas))
            };
            let Ok(count) = received else { continue };
            for (meta, buf) in metas.iter().zip(storage.chunks(RECV_BUF_LEN)).take(count) {
                self.forward_batch(meta, &buf[..meta.len]);
            }
        }
    }

    /// 处理一次接收到的数据。内核可能把来自同一个地址的多个等长包合并成一批上交。
    fn forward_batch(&self, meta: &RecvMeta, data: &[u8]) {
        let stride = if meta.stride == 0 { data.len().max(1) } else { meta.stride };
        let mut rest = data;
        while !rest.is_empty() {
            let first = &rest[..stride.min(rest.len())];
            match Frame::parse(first) {
                Some(Frame::Register { id }) => {
                    self.attach(id, NextHop::Udp(meta.addr));
                    rest = &rest[first.len()..];
                }
                Some(Frame::Data { dst, .. }) => {
                    let run = same_destination_run(rest, stride, self.state.max_gso_segments());
                    self.forward_run(dst, &rest[..run], stride);
                    rest = &rest[run..];
                }
                Some(Frame::Quic) | None => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    rest = &rest[first.len()..];
                }
            }
        }
    }

    /// 转发一段发往同一个目的节点的包。
    fn forward_run(&self, dst: NodeId, run: &[u8], stride: usize) {
        let packets = run.len().div_ceil(stride) as u64;
        match self.next_hop(dst) {
            Some(NextHop::Udp(destination)) => {
                let transmit =
                    Transmit { destination, ecn: None, contents: run, segment_size: (run.len() > stride).then_some(stride), src_ip: None };
                match self.send_udp(&transmit) {
                    Ok(()) => self.count_forwarded(packets, run.len()),
                    // 发送缓冲满了就丢，relay 不替任何人排队。
                    Err(_) => {
                        self.dropped.fetch_add(packets, Ordering::Relaxed);
                    }
                }
            }
            Some(NextHop::Tcp(queue)) => {
                for frame in run.chunks(stride) {
                    self.push_tcp(&queue, Bytes::copy_from_slice(frame));
                }
            }
            None => {
                self.dropped.fetch_add(packets, Ordering::Relaxed);
            }
        }
    }

    fn send_udp(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.sends.fetch_add(1, Ordering::Relaxed);
        self.io.try_io(Interest::WRITABLE, || self.state.send((&self.io).into(), transmit))
    }

    fn push_tcp(&self, queue: &mpsc::Sender<Bytes>, frame: Bytes) {
        let len = frame.len();
        match queue.try_send(frame) {
            Ok(()) => self.count_forwarded(1, len),
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn count_forwarded(&self, packets: u64, bytes: usize) {
        self.packets.fetch_add(packets, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    async fn accept_tcp(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let relay = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(err) = relay.serve_tcp(stream).await {
                            eprintln!("relay 上的一条 TCP 结束：{err}");
                        }
                    });
                }
                Err(err) => {
                    eprintln!("relay 接受 TCP 连接失败：{err}");
                    return;
                }
            }
        }
    }

    /// 一条 TCP 上挂着一个节点：第一帧登记它是谁，之后每一帧是一个要转发的包。
    async fn serve_tcp(&self, stream: TcpStream) -> anyhow::Result<()> {
        stream.set_nodelay(true)?;
        let (mut reader, writer) = stream.into_split();
        let first = read_frame(&mut reader).await?.context("TCP 连接建立后立即关闭")?;
        let Some(Frame::Register { id }) = Frame::parse(&first) else {
            anyhow::bail!("TCP 上的第一帧不是登记帧");
        };
        let (queue, queue_rx) = mpsc::channel(self.tcp_queue);
        self.attach(id, NextHop::Tcp(queue));
        tokio::spawn(write_frames(writer, queue_rx, None));

        while let Some(frame) = read_frame(&mut reader).await? {
            let Some(Frame::Data { dst, .. }) = Frame::parse(&frame) else { continue };
            match self.next_hop(dst) {
                Some(NextHop::Udp(destination)) => {
                    let transmit = Transmit { destination, ecn: None, contents: &frame, segment_size: None, src_ip: None };
                    // UDP 发送缓冲满时等它可写：这条 TCP 的读取跟着停下，压力回到发送方的 TCP 上。
                    loop {
                        match self.send_udp(&transmit) {
                            Ok(()) => break self.count_forwarded(1, frame.len()),
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => self.io.writable().await?,
                            Err(err) => return Err(err.into()),
                        }
                    }
                }
                Some(NextHop::Tcp(queue)) => self.push_tcp(&queue, frame),
                None => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Ok(())
    }
}

/// 从 `data` 开头起，连续多少字节的包发往同一个目的节点（最多 `max_segments` 个包）。
///
/// 这样的一段可以用一次带分段卸载的发送转出去，不用逐个包调内核。
fn same_destination_run(data: &[u8], stride: usize, max_segments: usize) -> usize {
    let dst = wire::data_dst_bytes(data);
    let segments = data.chunks(stride).take(max_segments.max(1)).take_while(|segment| wire::data_dst_bytes(segment) == dst).count().max(1);
    (segments * stride).min(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(dst: &str, payload_len: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        wire::push_data_header(&mut buf, dst.parse().unwrap(), "1".parse().unwrap());
        buf.resize(buf.len() + payload_len, 0xab);
        buf
    }

    #[test]
    fn run_stops_where_destination_changes() {
        let stride = frame("2", 100).len();
        let data = [frame("2", 100), frame("2", 100), frame("3", 100), frame("2", 40)].concat();
        assert_eq!(same_destination_run(&data, stride, 64), 2 * stride);
        assert_eq!(same_destination_run(&data[2 * stride..], stride, 64), stride);
        assert_eq!(same_destination_run(&data[3 * stride..], stride, 64), data.len() - 3 * stride);
    }

    #[test]
    fn run_is_capped_by_segment_limit() {
        let stride = frame("2", 100).len();
        let data = [frame("2", 100), frame("2", 100), frame("2", 100)].concat();
        assert_eq!(same_destination_run(&data, stride, 1), stride);
        assert_eq!(same_destination_run(&data, stride, 2), 2 * stride);
    }
}
