//! 首批数据：发出 OPEN 之前先从客户端读到的那一点数据。
//!
//! 它随 OPEN 一起发给对端，对端连上目标就能立刻写过去，省掉一个全程往返。读的规则：
//!
//! - 是 TLS 握手记录的开头（ClientHello）时，把这一条记录读完整再发；
//! - 别的数据，读到多少发多少；
//! - 客户端迟迟不说话时不干等。服务器先说话的协议（SSH、SMTP、数据库）里客户端要先等对面，
//!   所以只等一小段时间，过了就带着空的首批数据发 OPEN。

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{self, Instant};

/// 等客户端的第一个字节等多久。
///
/// 这是一个固定值，没有跟随客户端的往返延迟：回环和局域网上的客户端在这之内一定已经把数据发来了；
/// 较远客户端未能在时限内发出数据时，仅首批数据为空，后续数据仍正常经流传输，不影响正确性。
/// 服务器先说话的协议每条连接多等这么久。
pub(crate) const FIRST_BYTE_WAIT: Duration = Duration::from_millis(50);

/// 已经看到 TLS 记录的开头之后，等它剩下的部分等多久。剩下的字节已经在路上了，所以可以等得久一些。
const RECORD_WAIT: Duration = Duration::from_millis(500);

const TLS_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_MAJOR: u8 = 0x03;
/// 明文的 TLS 记录最长 2^14 字节（RFC 8446 §5.1）。声称更长的不是 TLS，不为它多等。
const MAX_TLS_RECORD_LEN: usize = 1 << 14;

/// 一次最多读这么多。首批数据不会比它更长（握手阶段多读进来的那一点除外）。
const MAX_LEN: usize = TLS_HEADER_LEN + MAX_TLS_RECORD_LEN;

/// 读首批数据。`data` 是握手时多读进来的字节（通常是空的），返回的数据以它开头。
///
/// 客户端没有说话，或者已经关掉了它的发送方向时，原样返回 `data`。
///
/// # Errors
///
/// 读客户端的连接出错（比如被重置）。
pub(crate) async fn read(stream: &mut (impl AsyncRead + Unpin), mut data: Vec<u8>, first_byte_wait: Duration) -> io::Result<Vec<u8>> {
    if data.is_empty() {
        let Ok(read) = time::timeout(first_byte_wait, read_some(stream, &mut data, MAX_LEN)).await else { return Ok(data) };
        if read? == 0 {
            return Ok(data);
        }
    }
    let deadline = Instant::now() + RECORD_WAIT;
    loop {
        let missing = missing_tls_bytes(&data);
        if missing == 0 {
            return Ok(data);
        }
        let Ok(read) = time::timeout_at(deadline, read_some(stream, &mut data, missing)).await else { return Ok(data) };
        if read? == 0 {
            return Ok(data);
        }
    }
}

/// 往 `data` 后面最多读 `limit` 字节。被取消时什么都不会丢：字节要么已经在 `data` 里，要么还在连接上。
async fn read_some(stream: &mut (impl AsyncRead + Unpin), data: &mut Vec<u8>, limit: usize) -> io::Result<usize> {
    // `read_buf` 只往已经留好的空间里读，不先留够的话一次只读得到几十字节。
    data.reserve(limit);
    // usize 不会比 u64 宽，这里不会截断。
    stream.take(limit as u64).read_buf(data).await
}

/// `data` 是一条 TLS 握手记录的开头时，返回这条记录还差多少字节；不是，或者记录已经完整时返回 0。
fn missing_tls_bytes(data: &[u8]) -> usize {
    let Some(header) = data.first_chunk::<TLS_HEADER_LEN>() else {
        // 记录头还没到齐：已有的字节和握手记录的开头对得上才继续等。
        let matches_so_far = data.iter().zip([TLS_HANDSHAKE, TLS_MAJOR]).all(|(&byte, expected)| byte == expected);
        return if matches_so_far { TLS_HEADER_LEN - data.len() } else { 0 };
    };
    let &[TLS_HANDSHAKE, TLS_MAJOR, _minor, hi, lo] = header else { return 0 };
    match usize::from(u16::from_be_bytes([hi, lo])) {
        len @ 1..=MAX_TLS_RECORD_LEN => (TLS_HEADER_LEN + len).saturating_sub(data.len()),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use super::*;

    /// 一条 `len` 字节负载的 TLS 握手记录。
    fn client_hello(len: usize) -> Vec<u8> {
        let mut record = vec![TLS_HANDSHAKE, TLS_MAJOR, 0x01];
        record.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        record.extend((0..=u8::MAX).cycle().take(len));
        record
    }

    fn pipe() -> (DuplexStream, DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    #[test]
    fn only_a_tls_handshake_record_is_worth_waiting_for() {
        assert_eq!(missing_tls_bytes(&[]), 5);
        assert_eq!(missing_tls_bytes(&[0x16]), 4);
        assert_eq!(missing_tls_bytes(&[0x16, 0x03, 0x01]), 2);
        assert_eq!(missing_tls_bytes(&[0x16, 0x03, 0x01, 0x02, 0x00]), 512);
        assert_eq!(missing_tls_bytes(&client_hello(512)[..100]), 417);
        assert_eq!(missing_tls_bytes(&client_hello(512)), 0);

        assert_eq!(missing_tls_bytes(b"G"), 0);
        assert_eq!(missing_tls_bytes(b"GET / HTTP/1.1\r\n"), 0);
        assert_eq!(missing_tls_bytes(&[0x16, 0x02]), 0, "SSL 2 不算");
        assert_eq!(missing_tls_bytes(&[0x17, 0x03, 0x03, 0x00, 0x10]), 0, "应用数据记录不算");
        assert_eq!(missing_tls_bytes(&[0x16, 0x03, 0x01, 0x00, 0x00]), 0, "空记录不算");
        assert_eq!(missing_tls_bytes(&[0x16, 0x03, 0x01, 0x40, 0x01]), 0, "超过 2^14 的长度不是 TLS");
        assert_eq!(missing_tls_bytes(&[0x16, 0x03, 0x01, 0x40, 0x00]), MAX_TLS_RECORD_LEN);
    }

    #[tokio::test]
    async fn a_client_hello_split_across_packets_is_read_to_the_end_of_its_record() {
        let (mut near, mut far) = pipe();
        let hello = client_hello(1500);
        let expected = hello.clone();
        let writer = tokio::spawn(async move {
            for piece in hello.chunks(400) {
                far.write_all(piece).await.unwrap();
                time::sleep(Duration::from_millis(5)).await;
            }
            far
        });
        assert_eq!(read(&mut near, Vec::new(), FIRST_BYTE_WAIT).await.unwrap(), expected);
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn bytes_behind_the_record_are_left_for_the_relay_when_they_arrive_later() {
        let (mut near, mut far) = pipe();
        let hello = client_hello(300);
        far.write_all(&hello[..200]).await.unwrap();
        let reader = tokio::spawn(async move { (read(&mut near, Vec::new(), FIRST_BYTE_WAIT).await.unwrap(), near) });
        time::sleep(Duration::from_millis(5)).await;
        far.write_all(&hello[200..]).await.unwrap();
        far.write_all(b"second flight").await.unwrap();

        let (first, mut near) = reader.await.unwrap();
        assert_eq!(first, hello);
        let mut rest = [0; 13];
        near.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"second flight");
    }

    #[tokio::test]
    async fn other_data_is_passed_on_as_soon_as_something_arrives() {
        let (mut near, mut far) = pipe();
        far.write_all(b"GET / HT").await.unwrap();
        let started = Instant::now();
        assert_eq!(read(&mut near, Vec::new(), Duration::from_secs(30)).await.unwrap(), b"GET / HT");
        assert!(started.elapsed() < Duration::from_secs(5), "读到了就该返回，不该等满时限");
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_client_is_not_waited_for_beyond_the_short_wait() {
        let (mut near, _far) = pipe();
        let started = Instant::now();
        assert_eq!(read(&mut near, Vec::new(), FIRST_BYTE_WAIT).await.unwrap(), b"");
        assert_eq!(started.elapsed(), FIRST_BYTE_WAIT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_client_hello_is_sent_as_far_as_it_got() {
        let (mut near, mut far) = pipe();
        let hello = client_hello(1000);
        far.write_all(&hello[..300]).await.unwrap();
        let started = Instant::now();
        assert_eq!(read(&mut near, Vec::new(), FIRST_BYTE_WAIT).await.unwrap(), &hello[..300]);
        assert_eq!(started.elapsed(), RECORD_WAIT);
    }

    #[tokio::test]
    async fn a_client_that_closed_without_sending_yields_no_first_data() {
        let (mut near, far) = pipe();
        drop(far);
        assert_eq!(read(&mut near, Vec::new(), Duration::from_secs(30)).await.unwrap(), b"");

        let (mut near, mut far) = pipe();
        far.write_all(&client_hello(100)[..50]).await.unwrap();
        drop(far);
        assert_eq!(read(&mut near, Vec::new(), Duration::from_secs(30)).await.unwrap().len(), 50);
    }

    #[tokio::test(start_paused = true)]
    async fn bytes_read_during_the_handshake_come_first() {
        // 握手时多读进来的不是 TLS：不再等任何东西。
        let (mut near, _far) = pipe();
        assert_eq!(read(&mut near, b"early".to_vec(), FIRST_BYTE_WAIT).await.unwrap(), b"early");

        // 多读进来的是半个 ClientHello：把它读完整。
        let (mut near, mut far) = pipe();
        let hello = client_hello(64);
        far.write_all(&hello[10..]).await.unwrap();
        assert_eq!(read(&mut near, hello[..10].to_vec(), FIRST_BYTE_WAIT).await.unwrap(), hello);
    }

    #[tokio::test]
    async fn a_flood_is_cut_at_the_bound() {
        let (mut near, mut far) = tokio::io::duplex(1 << 20);
        far.write_all(&vec![b'x'; 200_000]).await.unwrap();
        assert_eq!(read(&mut near, Vec::new(), FIRST_BYTE_WAIT).await.unwrap().len(), MAX_LEN);
    }
}
