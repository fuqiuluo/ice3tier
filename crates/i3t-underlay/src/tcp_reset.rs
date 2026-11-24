//! 异常结束一条 TCP 连接：关闭时发 RST 而不是 FIN，并且让对端认这个 RST。以及设成这样的连接怎样正常结束（最后一节）。
//!
//! RST 的序号为本端下一个待发送字节的序号。对端仅接受序号精确匹配的 RST（RFC 5961），不匹配时将其忽略并回复挑战 ACK。
//! Linux 将其与下一个待接收字节序号比较，只要对端已收到本端已发送数据即可匹配。macOS 则将其与最后一次确认的位置比较：
//! 当对端刚收到数据且尚未发出延迟确认（最长约 100~200 毫秒）时，序号不匹配，RST 被丢弃。挑战 ACK 返回本端后：Linux 上连接已移除，
//! 内核会回复新的 RST 并被对端接受；而 macOS 上刚关闭的连接仍停留在连接表中，挑战 ACK 会被静默丢弃。因此当两端均为 macOS 时
//! （如本机代理与本机程序），刚发送完数据即被重置的连接会使对端无法感知重置而持续等待。
//!
//! 所以 macOS 上关闭之前先等对端确认完本端发出去的所有数据（发送缓冲空了：`SO_NWRITE` 是 0），这时它最后一次确认到的
//! 位置就是 RST 的序号。最多等 [`ACK_WAIT`]，等不到（对端不读了、断了）也照样关。等的时候连接在后台留着，调用方不用等。
//! 别的系统上马上关。
//!
//! # 一开始就设成"关闭时发 RST"的连接怎样正常结束
//!
//! 搬运用户数据的连接一开始就设成"关闭时发 RST"（`SO_LINGER` 为 0），中途出错、任务被取消、进程退出时对端看到的
//! 都是重置；两个方向都正常结束了才改回正常关闭。macOS 上这一步可能来不及：一条 socket 两个方向都关了之后（本端发了
//! FIN 且已收到对端 FIN），后续 setsockopt 会一律返回 EINVAL，无法再取消"关闭时发送 RST"设置。结果正常结束的连接仍会以
//! RST 关闭，发送缓冲区中尚未送达的数据会被丢弃：对端会收到连接重置；若对端同样为 macOS 且不接受该 RST，则会一直等待剩余数据。
//! 因此此类连接应使用 [`shutdown_write`] 发送 FIN、使用 [`graceful_close`] 恢复正常关闭，避免直接调用 `shutdown` 和 `set_linger`。

use std::borrow::Borrow;
use std::io;
use std::net::Shutdown;

use socket2::SockRef;
use tokio::net::TcpStream;

/// 一条 socket 两个方向都关了之后还能不能改 `SO_LINGER`。macOS 不能（见模块文档）。
const LINGER_SETTABLE_ONCE_SHUT: bool = !cfg!(target_os = "macos");

/// 最多等对端确认多久。macOS 的延迟确认最多一两百毫秒，再加上一个往返。
#[cfg(target_os = "macos")]
const ACK_WAIT: std::time::Duration = std::time::Duration::from_secs(1);
/// 等的时候隔多久看一次发送缓冲。
#[cfg(target_os = "macos")]
const POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// 关掉 `stream`，对端看到的是重置（RST），不是正常结束。见模块文档。
///
/// 可传 socket 或它的一个共享句柄。共享时调用方也要释放剩下的句柄。
/// 不用等：macOS 上要等对端确认时，连接交给一个后台任务，它在 tokio 运行时里关掉连接；不在运行时里时马上关。
pub fn close(stream: impl Borrow<TcpStream> + Send + 'static) {
    if let Err(error) = stream.borrow().set_zero_linger() {
        tracing::debug!(%error, "设置 SO_LINGER 失败，关闭连接时对端可能看到正常结束");
    }
    #[cfg(target_os = "macos")]
    if unacknowledged(stream.borrow()).is_ok_and(|bytes| bytes > 0)
        && let Ok(runtime) = tokio::runtime::Handle::try_current()
    {
        drop(runtime.spawn(async move {
            let deadline = tokio::time::Instant::now() + ACK_WAIT;
            while tokio::time::Instant::now() < deadline && unacknowledged(stream.borrow()).is_ok_and(|bytes| bytes > 0) {
                tokio::time::sleep(POLL).await;
            }
            drop(stream);
        }));
        return;
    }
    drop(stream);
}

/// 正常结束写的一半：发 FIN，排在还没送出去的数据后面。连接设着"关闭时发 RST"、要等两个方向都结束才定怎么关时用它。
///
/// 本端无法控制对端 FIN 的到达时机；若在收到对端 FIN 后再发 FIN，macOS 上将无法恢复正常关闭（见模块文档）。因此 macOS 上在发 FIN
/// 之前先恢复正常关闭：该发送方向至此已完整。若后续整条连接异常终止，调用方仍会重新设置"关闭时发 RST"（由 [`close`]
/// 执行）；若此时对端 FIN 已到达而无法设置，对端将看到正常关闭（其待发送数据此时已发完，仅无法得知是否送达）。
/// 其他系统可随时修改该选项，此处仅发送 FIN，待 [`graceful_close`] 再恢复正常关闭，确保中途取消或进程退出时对端仍会收到重置。
///
/// # Errors
///
/// `shutdown` 的错误：连接已经被重置、断开。
pub fn shutdown_write(stream: &TcpStream) -> io::Result<()> {
    let socket = SockRef::from(stream);
    if !LINGER_SETTABLE_ONCE_SHUT && let Err(error) = socket.set_linger(None) {
        tracing::debug!(%error, "发送 FIN 前恢复正常关闭模式失败，连接关闭时可能发送 RST");
    }
    socket.shutdown(Shutdown::Write)
}

/// 两个方向都正常结束了：关闭时正常关闭，不再发 RST。写的一半要已经用 [`shutdown_write`] 关掉。
///
/// macOS 上 [`shutdown_write`] 已经改过了，这时两个方向都关了，再改只会得到 EINVAL，所以那里什么都不做。
///
/// # Errors
///
/// 无法设置 `SO_LINGER`，该连接在关闭时仍会发送 RST。
pub fn graceful_close(stream: &TcpStream) -> io::Result<()> {
    if LINGER_SETTABLE_ONCE_SHUT { SockRef::from(stream).set_linger(None) } else { Ok(()) }
}

/// 发送缓冲里还有多少字节：还没发出去的，加上发出去了、对端还没确认的。
#[cfg(target_os = "macos")]
fn unacknowledged(stream: &TcpStream) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;

    let mut value: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("一个 int 的长度装得进 socklen_t");
    // SAFETY: `stream` 借着，文件描述符在调用期间活着；指针指向栈上的一个 `c_int`，长度就是它的长度，内核最多写这么多，
    // 调用结束之后不再用这个指针。
    let result = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_NWRITE, (&raw mut value).cast(), &raw mut len) };
    if result == 0 { Ok(usize::try_from(value).unwrap_or(0)) } else { Err(std::io::Error::last_os_error()) }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// 一对连好的 TCP：(拨出的, 接进来的)。
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (dialled, accepted) = tokio::join!(TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
        (dialled.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn linger_can_be_changed_once_both_halves_are_shut_exactly_where_the_code_assumes_it() {
        // 对端先发 FIN，本端读到结束之后也发 FIN：两个方向都关了。这时还改不改得了 SO_LINGER，要和
        // `LINGER_SETTABLE_ONCE_SHUT` 说的一样（macOS 改不了，见模块文档）。哪天系统变了，这一句会失败，提醒去改。
        let (mut near, mut far) = pair().await;
        near.shutdown().await.unwrap();
        assert_eq!(far.read(&mut [0; 1]).await.unwrap(), 0, "对端的 FIN 到了");
        SockRef::from(&far).shutdown(Shutdown::Write).unwrap();
        let changed = SockRef::from(&far).set_linger(None);
        assert_eq!(changed.is_ok(), LINGER_SETTABLE_ONCE_SHUT, "两个方向都关了之后改 SO_LINGER：{changed:?}");
        drop(near);
    }

    #[tokio::test]
    async fn a_connection_set_to_reset_that_ends_normally_delivers_its_queued_tail_and_a_clean_end() {
        // 对端先发完（它的 FIN 先到），本端再写一大块、发 FIN、正常关闭。对端的接收缓冲小、本端的发送缓冲大，关闭时
        // 这一块的大半还在本端的内核里。正常关闭时内核接着把它们发完；以 RST 关闭时它们被丢掉，对端读到的是重置或者
        // 一直等下去：macOS 上发完 FIN 才改回正常关闭时就是这样（模块文档）。
        let (mut reader, mut writer) = pair().await;
        SockRef::from(&reader).set_recv_buffer_size(16 * 1024).unwrap();
        SockRef::from(&writer).set_send_buffer_size(1024 * 1024).unwrap();
        writer.set_zero_linger().unwrap();
        reader.shutdown().await.unwrap();
        assert_eq!(writer.read(&mut [0; 1]).await.unwrap(), 0, "对端的 FIN 到了");
        // 发送缓冲在 Linux 上有上限（`net.core.wmem_max`，常见的是 208 KB，内核给两倍）：这一块要放得进去，不然写不完。
        let block: Vec<u8> = (0..192 * 1024u32).map(|i| u8::try_from(i % 251).unwrap()).collect();
        writer.write_all(&block).await.unwrap();
        shutdown_write(&writer).unwrap();
        graceful_close(&writer).unwrap();
        drop(writer);
        let mut received = Vec::new();
        let end = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_to_end(&mut received)).await;
        let end = end.expect("对端应该及时读到结束");
        assert!(end.is_ok(), "读到 {} 字节之后结束的方式是 {end:?}，应该是正常结束", received.len());
        assert!(received == block, "读到 {} 字节，应该是 {}", received.len(), block.len());
    }

    #[tokio::test]
    async fn the_peer_reading_right_after_the_data_sees_a_reset() {
        // 对端一直在读：每一段数据刚到，它都可能还欠着确认。读完数据之后读到的必须是重置，而且要及时（macOS 上见模块文档）。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (dialled, accepted) = tokio::join!(TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
        let (mut reader, (mut writer, _)) = (dialled.unwrap(), accepted.unwrap());
        let block = vec![7u8; 100_000];
        let read = tokio::spawn(async move {
            let mut received = Vec::new();
            let end = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_to_end(&mut received)).await;
            (received.len(), end.map(|end| end.map_err(|error| error.kind())))
        });
        for chunk in block.chunks(1000) {
            writer.write_all(chunk).await.unwrap();
        }
        close(writer);
        let (received, end) = read.await.unwrap();
        let end = end.expect("对端应该及时知道连接结束了");
        // Windows 上收到 RST 时报的可能是 ConnectionAborted。
        assert!(
            matches!(end, Err(std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted)),
            "读到 {received} 字节之后结束的方式是 {end:?}，应该是重置"
        );
    }
}
