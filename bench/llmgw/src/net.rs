//! TCP 连接上两端都要用的小事：拿到 TLS 下面那条 TCP，把关闭变成重置，把读写错误归类。

use std::io;
use std::time::Duration;

use socket2::SockRef;
use tokio::net::TcpStream;

/// 能拿到底下那条 TCP 连接的流：明文的就是它自己，TLS 的是被包着的那条。
pub trait TcpSocket {
    fn tcp(&self) -> &TcpStream;
}

impl TcpSocket for TcpStream {
    fn tcp(&self) -> &TcpStream {
        self
    }
}

impl TcpSocket for tokio_rustls::server::TlsStream<TcpStream> {
    fn tcp(&self) -> &TcpStream {
        self.get_ref().0
    }
}

impl TcpSocket for tokio_rustls::client::TlsStream<TcpStream> {
    fn tcp(&self) -> &TcpStream {
        self.get_ref().0
    }
}

/// macOS 上重置之前等多久，见 [`reset_on_close`]。
const MACOS_ACK_GRACE: Duration = Duration::from_millis(300);

/// 让这条连接关闭时发 RST 而不是 FIN：上游中途出错时就是这样断的。返回之后把流丢掉即可。
///
/// macOS 上会先等待一段时间再返回。对端刚收到数据、尚未发送延迟确认时，RST 的序列号与对端已确认位置不一致：macOS 会拒绝此类
/// RST 并回复 challenge ACK，而本端（同样为 macOS 时）已关闭的连接会静默丢弃该 challenge ACK，导致对端持续等待、感知不到重置。
/// Linux 对端按期望接收的下一个字节比对 RST 序列号并予以接受，本端也会响应 challenge ACK。延迟确认通常在一两百毫秒内完成，等待
/// 该时间后再关闭可使对端完成确认、序列号对齐。正式实现中会等待发送缓冲区排空后再关闭（`i3t_underlay::tcp_reset`）；本工具不依赖
/// 正式代码，也无需为此调用系统接口，因此直接等待固定时长。
///
/// # Errors
///
/// 设置 `SO_LINGER` 失败。
pub async fn reset_on_close(tcp: &TcpStream) -> io::Result<()> {
    SockRef::from(tcp).set_linger(Some(Duration::ZERO))?;
    if cfg!(target_os = "macos") {
        tokio::time::sleep(MACOS_ACK_GRACE).await;
    }
    Ok(())
}

/// 一条连接是怎么断的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// 收到了 RST（或者在它之后写）。异常结束就应该是这样。
    Reset,
    /// 对面正常关闭了（FIN），TLS 的话是没有 close_notify 的 FIN。答案没完时这就是"截断了却像正常结束"。
    Eof,
    Other,
}

impl From<&io::Error> for Broken {
    fn from(err: &io::Error) -> Self {
        match err.kind() {
            // 收到 RST 之后再写，Linux 报 EPIPE。
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe => Self::Reset,
            // rustls 在没有 close_notify 的 FIN 上报这个。
            io::ErrorKind::UnexpectedEof => Self::Eof,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn reset_on_close_makes_the_reader_see_a_reset_not_an_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            conn.write_all(b"partial").await.unwrap();
            reset_on_close(&conn).await.unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        server.await.unwrap();
        let mut seen = Vec::new();
        let err = loop {
            let mut buf = [0_u8; 64];
            match client.read(&mut buf).await {
                Ok(0) => panic!("应该是 RST，却读到了 EOF；之前收到 {seen:?}"),
                Ok(n) => seen.extend_from_slice(&buf[..n]),
                Err(err) => break err,
            }
        };
        assert_eq!(Broken::from(&err), Broken::Reset, "{err}");
    }

    #[test]
    fn error_kinds_map_to_how_the_connection_broke() {
        assert_eq!(Broken::from(&io::Error::from(io::ErrorKind::BrokenPipe)), Broken::Reset);
        assert_eq!(Broken::from(&io::Error::from(io::ErrorKind::UnexpectedEof)), Broken::Eof);
        assert_eq!(Broken::from(&io::Error::from(io::ErrorKind::TimedOut)), Broken::Other);
    }
}
