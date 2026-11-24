//! 从流上读一个头（OPEN 或 REPLY）。

use std::io;

use i3t_conn::{RecvStream, StreamAborted, StreamCode};
use i3t_proto::flow::{DecodeError, Decoded, Opening, Reason, Reply, Status};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::FlowError;

/// 读到头完整为止，一个字节也不多读：头后面紧跟着数据，多读了就得有人把它们还回去。读完了告诉流（[`RecvStream::end_header`]）。
///
/// 头只能来自对端本人：跑在 ice3proxy 上的流在 `end_header` 之前只交出加密送来的字节，头没有在那里面读完就是读出错，
/// 不会拿后面未经认证的原始字节凑出一个头来。
pub(crate) async fn read<T>(recv: &mut impl RecvStream, decode: fn(&[u8]) -> Result<Decoded<T>, DecodeError>) -> Result<T, FlowError> {
    let value = read_bytes(recv, decode).await?;
    recv.end_header();
    Ok(value)
}

/// 每次只读解析器要的那么多字节，而解析器要的不会超过头的上限，所以对端乱写也不能让这里多分配内存。
async fn read_bytes<T>(recv: &mut (impl AsyncRead + Unpin), decode: fn(&[u8]) -> Result<Decoded<T>, DecodeError>) -> Result<T, FlowError> {
    let mut buf = Vec::new();
    loop {
        match decode(&buf)? {
            Decoded::Complete { value, .. } => return Ok(value),
            Decoded::Incomplete { more } => {
                let have = buf.len();
                buf.resize(have + more, 0);
                recv.read_exact(&mut buf[have..]).await.map_err(|error| match error.kind() {
                    io::ErrorKind::UnexpectedEof => FlowError::Truncated,
                    _ => FlowError::Read(error),
                })?;
            }
        }
    }
}

/// 读对端的 OPEN。
///
/// 和 [`read`] 不同，只有要一条流（[`Opening::Stream`]）的 OPEN 读完时才告诉流头读完了。别的几种（数据报上下文、测量、往返）
/// 不会开在 ice3proxy 上（只有 [`i3t_conn::Connector::open_tcp`] 开出来的流会），所以它们之后也只读得到加密送来的字节：
/// 若对端在 lane 上开启上述类型并选择透传模式，会在读到原始字节前报错，防止中间人注入数据（issue #17）。
pub(crate) async fn read_open(recv: &mut impl RecvStream) -> Result<Opening, FlowError> {
    let opening = read_bytes(recv, Opening::decode).await?;
    if matches!(opening, Opening::Stream(_)) {
        recv.end_header();
    }
    Ok(opening)
}

/// 读对端的 REPLY。
///
/// 接受方可以不读 OPEN 就带着 [`Reason::AccessRevoked`] 重置整条流：访问规则不允许本节点访问它（见 [`crate::Handler::screen`]）。
/// 这和它读了 OPEN 再回一个 [`Status::AccessDenied`] 是同一个结论，所以也当作这样一个 REPLY 交出去，
/// 发起方给客户端的失败和别的拒绝一样，不会因此多透露什么。
pub(crate) async fn read_reply(recv: &mut impl RecvStream) -> Result<Reply, FlowError> {
    match read(recv, Reply::decode).await {
        Err(FlowError::Read(error)) if refused_unread(&error) => {
            Ok(Reply::new(Status::AccessDenied, "对端未读取建流请求即重置流：访问规则不允许本节点访问"))
        }
        other => other,
    }
}

fn refused_unread(error: &io::Error) -> bool {
    StreamAborted::of(error) == Some(StreamAborted::Reset(StreamCode(Reason::AccessRevoked.to_wire())))
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use i3t_proto::flow::{Class, Open, OpenPing, Origin, Reply, Status, Target};
    use tokio::io::{AsyncWriteExt, DuplexStream, ReadBuf};

    use super::*;

    /// 一个接收方向：读的是内存里的管道，记下有没有人告诉它头读完了。
    struct Recv {
        pipe: DuplexStream,
        header_ended: bool,
    }

    impl AsyncRead for Recv {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_read(cx, buf)
        }
    }

    impl RecvStream for Recv {
        fn stop(&mut self, _code: StreamCode) {}

        fn end_header(&mut self) {
            self.header_ended = true;
        }
    }

    fn pipe() -> (Recv, DuplexStream) {
        let (near, far) = tokio::io::duplex(1024);
        (Recv { pipe: near, header_ended: false }, far)
    }

    #[tokio::test]
    async fn header_is_read_without_consuming_the_data_behind_it() {
        let (mut near, mut far) = pipe();
        let mut bytes = Vec::new();
        Reply::new(Status::ConnectionRefused, "端口没开").encode(&mut bytes);
        bytes.extend_from_slice(b"data");
        far.write_all(&bytes).await.unwrap();

        let reply = read(&mut near, Reply::decode).await.unwrap();
        assert_eq!(reply, Reply::new(Status::ConnectionRefused, "端口没开"));
        assert!(near.header_ended, "头读完了要告诉流");
        let mut data = [0; 4];
        near.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"data");
    }

    #[tokio::test]
    async fn clean_end_in_the_middle_of_a_header_is_truncation() {
        let (mut near, mut far) = pipe();
        far.write_all(&[0x00]).await.unwrap();
        drop(far);
        assert!(matches!(read(&mut near, Reply::decode).await, Err(FlowError::Truncated)));
        assert!(!near.header_ended, "没有读完的头不算读完");
    }

    #[tokio::test]
    async fn malformed_header_is_reported_as_soon_as_it_is_seen() {
        let (mut near, mut far) = pipe();
        far.write_all(&[0xff, 200]).await.unwrap();
        // 对端没有再写任何东西：错在前两个字节，不需要等那 200 字节的说明。
        assert!(matches!(read(&mut near, Reply::decode).await, Err(FlowError::Malformed(DecodeError::UnknownStatus(0xff)))));
        assert!(!near.header_ended);
    }

    /// 只有要一条流的 OPEN 读完才算头读完：别的几种不开在 ice3proxy 上，之后也不该读到不再加密的字节（issue #17）。
    #[tokio::test]
    async fn only_a_stream_open_ends_the_header() {
        let (mut near, mut far) = pipe();
        let open = Open { target: Target::Node { port: 80 }, class: Class::Auto, origin: Origin::default() };
        let mut bytes = Vec::new();
        open.encode(&mut bytes);
        far.write_all(&bytes).await.unwrap();
        assert_eq!(read_open(&mut near).await.unwrap(), Opening::Stream(open));
        assert!(near.header_ended);

        let (mut near, mut far) = pipe();
        let mut bytes = Vec::new();
        OpenPing.encode(&mut bytes);
        far.write_all(&bytes).await.unwrap();
        assert_eq!(read_open(&mut near).await.unwrap(), Opening::Ping(OpenPing));
        assert!(!near.header_ended, "往返测量不开在 ice3proxy 上");
    }
}
