//! TCP 中继连接封装：用于无法使用 UDP 的节点与 relay 之间的传输。分帧格式见 [`i3t_proto::tcp_frame`]。
//!
//! 节点和 relay 两头往这条 TCP 里写的方式完全一样，所以放在这里共用。
//!
//! # 为什么要限制积压
//!
//! 该 TCP 连接承载端到端传输数据包。由于 TCP 会自行重传，该段丢包时两端连接无法感知丢包而仅表现为延迟升高，
//! 从而不会降速并导致数据包持续积压。为将积压转化为丢包信号，需在两处设置上限（实测：RTT 50ms、丢包 1% 时，
//! 只设第一处小消息往返的中位数是 780ms，两处都设是 113ms）：
//!
//! 1. 待发队列最多 [`SEND_QUEUE_PACKETS`] 个包，满了就丢新来的；
//! 2. 内核里还没发出去的数据最多 [`UNSENT_LIMIT_BYTES`]。不设的话数据积在内核的发送缓冲里，队列设多短都没用。
//!
//! 第二条在 Linux 上用 `TCP_NOTSENT_LOWAT`：未发出的数据到了这个数，写就会停下来等。别的系统没有效果相同、
//! 标准库又够得着的选项，退而求其次把整个发送缓冲区（`SO_SNDBUF`）缩到同样的大小，它连已发出未确认的数据也算在内，
//! 所以更紧，高延迟的链路上吞吐会低一些。

use std::io;

use bytes::{Bytes, BytesMut};
use i3t_proto::tcp_frame::{self, FrameDecoder};
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

/// 待发队列最多排多少个包。
pub const SEND_QUEUE_PACKETS: usize = 32;
/// 内核里还没发出去的数据的上限。
pub const UNSENT_LIMIT_BYTES: u32 = 16 * 1024;

/// 一次写最多攒多少字节。攒得太多的话，写被内核的上限卡住时这一批也成了积压。
const WRITE_BATCH_BYTES: usize = UNSENT_LIMIT_BYTES as usize;
/// 每次从 TCP 读多少。
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// 给一条刚建好的 TCP 设上中转需要的选项：关掉 Nagle（包要立刻走），限制内核里的积压（见模块文档）。
///
/// # Errors
///
/// 设置选项失败，原样返回操作系统的错误。
pub fn configure(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    limit_unsent(&SockRef::from(stream))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn limit_unsent(socket: &SockRef<'_>) -> io::Result<()> {
    socket.set_tcp_notsent_lowat(UNSENT_LIMIT_BYTES)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn limit_unsent(socket: &SockRef<'_>) -> io::Result<()> {
    socket.set_send_buffer_size(WRITE_BATCH_BYTES)
}

/// TCP 中继连接的非阻塞发送端，支持克隆。
#[derive(Debug, Clone)]
pub struct FrameSender {
    queue: mpsc::Sender<Bytes>,
}

impl FrameSender {
    /// 把一个数据报排进待发队列。队列满了，或者这条 TCP 已经断了，返回 `false`，数据报被丢掉。
    pub fn try_send(&self, datagram: Bytes) -> bool {
        self.queue.try_send(datagram).is_ok()
    }

    /// 这条 TCP 的写入是不是已经结束了。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.queue.is_closed()
    }

    /// 两个发送端是不是通向同一条 TCP。
    #[must_use]
    pub fn same_leg(&self, other: &Self) -> bool {
        self.queue.same_channel(&other.queue)
    }
}

/// [`FrameSender`] 的另一头，交给 [`write_frames`]。
#[derive(Debug)]
pub struct FrameQueue {
    queue: mpsc::Receiver<Bytes>,
}

/// 建一条待发队列，容量是 [`SEND_QUEUE_PACKETS`]。
#[must_use]
pub fn frame_queue() -> (FrameSender, FrameQueue) {
    let (sender, receiver) = mpsc::channel(SEND_QUEUE_PACKETS);
    (FrameSender { queue: sender }, FrameQueue { queue: receiver })
}

/// 把队列里的数据报加上长度前缀写进 TCP，直到所有的 [`FrameSender`] 都被丢弃。
///
/// 写被内核的积压上限卡住时这里停下来，队列随之排满，新来的包在 [`FrameSender::try_send`] 那里被丢掉。
///
/// # Errors
///
/// 写入 TCP 数据时失败或因关闭写入端失败时返回错误。
pub async fn write_frames(mut writer: OwnedWriteHalf, mut queue: FrameQueue) -> io::Result<()> {
    let mut batch = BytesMut::with_capacity(2 * WRITE_BATCH_BYTES);
    while let Some(first) = queue.queue.recv().await {
        batch.clear();
        put(&mut batch, &first);
        while batch.len() < WRITE_BATCH_BYTES {
            let Ok(next) = queue.queue.try_recv() else { break };
            put(&mut batch, &next);
        }
        writer.write_all(&batch).await?;
    }
    writer.shutdown().await
}

fn put(batch: &mut BytesMut, datagram: &[u8]) {
    if let Err(error) = tcp_frame::put_frame(batch, datagram) {
        // 数据报都是从 UDP 或者连接层来的，长不到 64KB；真有的话丢掉这一个，不影响别的。
        tracing::warn!(%error, "数据报超出 TCP 中继单帧长度上限，已丢弃");
    }
}

/// 逐帧读取 TCP 中继连接中的数据报。
#[derive(Debug)]
pub struct FrameReader {
    reader: OwnedReadHalf,
    decoder: FrameDecoder,
}

impl FrameReader {
    #[must_use]
    pub fn new(reader: OwnedReadHalf) -> Self {
        Self { reader, decoder: FrameDecoder::new() }
    }

    /// 读出下一个数据报。对方正常关闭时返回 `None`。
    ///
    /// # Errors
    ///
    /// 读取 TCP 数据失败，或在读完当前帧前遇到 EOF（[`io::ErrorKind::UnexpectedEof`]）。
    pub async fn next(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            if let Some(frame) = self.decoder.next_frame() {
                return Ok(Some(frame));
            }
            let buffer = self.decoder.buffer_mut();
            buffer.reserve(READ_CHUNK_BYTES);
            if self.reader.read_buf(buffer).await? == 0 {
                return if buffer.is_empty() { Ok(None) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpListener;

    use super::*;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn datagrams_come_out_the_other_end_whole_and_in_order() {
        let (client, server) = pair().await;
        configure(&client).unwrap();
        let (sender, queue) = frame_queue();
        let writer = tokio::spawn(write_frames(client.into_split().1, queue));

        let datagrams: Vec<Bytes> = (0..20u8).map(|index| Bytes::from(vec![index; 100 + usize::from(index) * 50])).collect();
        for datagram in &datagrams {
            assert!(sender.try_send(datagram.clone()));
        }
        drop(sender);

        let mut reader = FrameReader::new(server.into_split().0);
        let mut received = Vec::new();
        while let Some(datagram) = reader.next().await.unwrap() {
            received.push(datagram);
        }
        assert_eq!(received, datagrams);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_full_queue_drops_new_datagrams_instead_of_growing() {
        // 没有人在写：队列里的包发不出去。
        let (sender, _queue) = frame_queue();
        let accepted = (0..SEND_QUEUE_PACKETS + 10).filter(|_| sender.try_send(Bytes::from_static(b"x"))).count();
        assert_eq!(accepted, SEND_QUEUE_PACKETS);
    }

    #[tokio::test]
    async fn a_stalled_receiver_makes_the_writer_stop_instead_of_buffering_everything() {
        let (client, server) = pair().await;
        configure(&client).unwrap();
        let (sender, queue) = frame_queue();
        let _writer = tokio::spawn(write_frames(client.into_split().1, queue));

        // 对面一个字节都不读。一直塞，能塞进去的总量应该很快封顶：收发两头的内核缓冲加上队列。
        let datagram = Bytes::from(vec![0u8; 1400]);
        let mut accepted = 0usize;
        let mut stalled_rounds = 0;
        while stalled_rounds < 20 {
            if sender.try_send(datagram.clone()) {
                accepted += 1;
                stalled_rounds = 0;
            } else {
                stalled_rounds += 1;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(accepted < 100_000, "塞了 140MB 还没有被挡住，积压没有上限");
        }
        drop(server);
    }

    #[tokio::test]
    async fn senders_notice_when_the_leg_is_gone() {
        let (client, server) = pair().await;
        let (sender, queue) = frame_queue();
        let other = sender.clone();
        assert!(sender.same_leg(&other));
        assert!(!sender.same_leg(&frame_queue().0));
        let writer = tokio::spawn(write_frames(client.into_split().1, queue));
        drop(server);
        // 对面关了之后，写迟早会失败，写任务结束，发送端随之看到队列关闭。
        tokio::time::timeout(Duration::from_secs(5), async {
            while !sender.is_closed() {
                sender.try_send(Bytes::from(vec![0u8; 1400]));
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("写任务应该在对面关闭之后结束");
        assert!(writer.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_connection_cut_in_the_middle_of_a_frame_is_an_error() {
        let (mut client, server) = pair().await;
        client.write_all(&[0, 10, 1, 2, 3]).await.unwrap();
        drop(client);
        let mut reader = FrameReader::new(server.into_split().0);
        assert_eq!(reader.next().await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_kernel_backlog_limit_is_applied_on_linux() {
        let (client, _server) = pair().await;
        configure(&client).unwrap();
        assert_eq!(SockRef::from(&client).tcp_notsent_lowat().unwrap(), UNSENT_LIMIT_BYTES);
        assert!(client.nodelay().unwrap());
    }
}
