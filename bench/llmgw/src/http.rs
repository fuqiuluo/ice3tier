//! HTTP/1.1 的请求头和响应头：读到空行为止，再交给 httparse 解析。请求体和响应体由各自的端点处理。

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// 头部最长多少字节。这里的请求头和响应头都只有几百字节。
const MAX_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 64;

/// 从 `stream` 读到头部结束（空行）。返回头部的长度；`buf` 里在它之后的字节是已经读进来的正文。
///
/// # Errors
///
/// 读出错；头部还没完连接就关了（`UnexpectedEof`）；头部太长（`InvalidData`）。
pub async fn read_head<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> io::Result<usize> {
    let mut scanned: usize = 0;
    loop {
        // 从上一次看过的位置往前退 3 个字节再找，空行可能跨在两次读之间。
        let from = scanned.saturating_sub(3);
        if let Some(at) = buf[from..].windows(4).position(|window| window == b"\r\n\r\n") {
            return Ok(from + at + 4);
        }
        scanned = buf.len();
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP 头部太长"));
        }
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            let detail = if buf.is_empty() { "读取 HTTP 头部前连接已关闭" } else { "读取 HTTP 头部中途连接已关闭" };
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, detail));
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// 解析好的请求头。
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    headers: Vec<(String, String)>,
}

/// 解析好的响应头。
#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    headers: Vec<(String, String)>,
}

fn collect_headers(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers.iter().map(|header| (header.name.to_ascii_lowercase(), String::from_utf8_lossy(header.value).trim().to_owned())).collect()
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
}

fn invalid(detail: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

impl RequestHead {
    /// # Errors
    ///
    /// 不是一个完整、合法的 HTTP/1.1 请求头。
    pub fn parse(head: &[u8]) -> io::Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(head) {
            Ok(httparse::Status::Complete(_)) => Ok(Self {
                method: request.method.unwrap_or_default().to_owned(),
                path: request.path.unwrap_or_default().to_owned(),
                headers: collect_headers(request.headers),
            }),
            Ok(httparse::Status::Partial) => Err(invalid("请求头不完整".to_owned())),
            Err(err) => Err(invalid(format!("无法解析请求头：{err}"))),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// `Connection`、`Upgrade` 这类逗号分隔的头里有没有 `token`（不分大小写）。
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.header(name).is_some_and(|value| value.split(',').any(|item| item.trim().eq_ignore_ascii_case(token)))
    }
}

impl ResponseHead {
    /// # Errors
    ///
    /// 不是一个完整、合法的 HTTP/1.1 响应头。
    pub fn parse(head: &[u8]) -> io::Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(head) {
            Ok(httparse::Status::Complete(_)) => Ok(Self {
                status: response.code.unwrap_or_default(),
                reason: response.reason.unwrap_or_default().to_owned(),
                headers: collect_headers(response.headers),
            }),
            Ok(httparse::Status::Partial) => Err(invalid("响应头不完整".to_owned())),
            Err(err) => Err(invalid(format!("无法解析响应头：{err}"))),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn head_ends_at_the_blank_line_and_the_rest_stays_in_the_buffer() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nX-A: 1\r\n\r\nbody".to_vec();
        // 一次只给一个字节，空行一定跨在几次读之间。
        let mut reader = tokio_test_reader(&wire);
        let mut buf = Vec::new();
        let len = read_head(&mut reader, &mut buf).await.unwrap();
        let head = ResponseHead::parse(&buf[..len]).unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.header("content-type"), Some("text/event-stream"));
        assert_eq!(head.header("x-a"), Some("1"));
        let mut rest = buf[len..].to_vec();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"body");
    }

    #[tokio::test]
    async fn eof_inside_the_head_is_unexpected_eof() {
        let mut reader: &[u8] = b"HTTP/1.1 200 OK\r\n";
        let err = read_head(&mut reader, &mut Vec::new()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn request_tokens_are_case_insensitive_and_comma_separated() {
        let head =
            RequestHead::parse(b"GET /v1/realtime HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\n").unwrap();
        assert_eq!((head.method.as_str(), head.path.as_str()), ("GET", "/v1/realtime"));
        assert!(head.has_token("connection", "upgrade"));
        assert!(head.has_token("upgrade", "websocket"));
        assert!(!head.has_token("connection", "close"));
    }

    /// 每次读只给一个字节的读取器。
    fn tokio_test_reader(bytes: &[u8]) -> impl AsyncRead + Unpin + '_ {
        struct OneByte<'a>(&'a [u8]);
        impl AsyncRead for OneByte<'_> {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                if let Some((&first, rest)) = self.0.split_first() {
                    buf.put_slice(&[first]);
                    self.0 = rest;
                }
                std::task::Poll::Ready(Ok(()))
            }
        }
        OneByte(bytes)
    }
}
