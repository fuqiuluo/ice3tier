//! 一个只够本机用的 HTTP：服务端回答 `GET`，客户端发一个 `GET`。
//!
//! 节点在回环地址上开两个小接口：给 Prometheus 抓的 `/metrics`，和给 `i3t status`、`i3t routes`、`i3t ping` 问的本机状态接口。
//! 它们都只有"一个不带请求体的 GET（参数在查询串里），回一段文本"这一种用法，所以不值得为此让节点程序带上一个完整的 HTTP 库：
//! 每条连接只处理一个请求，回完就关。

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 请求头最长这么多字节。正常的一个 GET 只有一两百字节。
const MAX_REQUEST_HEAD: usize = 8 * 1024;
/// 客户端收的应答最长这么多字节。
const MAX_RESPONSE: u64 = 16 * 1024 * 1024;
/// 一条连接从接受到回完最多这么久。回环上正常只要几毫秒；这个时限只是不让不说话的连接一直占着。
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// 已接收请求中服务端所需的字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) method: String,
    /// 路径，不带查询串。
    pub(crate) path: String,
    /// `?` 后面的查询串，原样；没有时是空的。
    pub(crate) query: String,
    /// `Authorization: Bearer <令牌>` 里的令牌。
    pub(crate) bearer: Option<String>,
}

/// 要回的应答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) content_type: &'static str,
    pub(crate) body: String,
}

impl Response {
    pub(crate) fn ok(content_type: &'static str, body: String) -> Self {
        Self { status: 200, content_type, body }
    }

    pub(crate) fn error(status: u16, message: &str) -> Self {
        Self { status, content_type: "text/plain; charset=utf-8", body: format!("{message}\n") }
    }

    fn encode(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "Error",
        };
        format!(
            "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.status,
            self.content_type,
            self.body.len(),
            self.body
        )
        .into_bytes()
    }
}

/// 在 `listener` 上回答请求，直到这个 future 被丢弃。每个请求交给 `respond`，只有 `GET` 会交过去。
pub(crate) async fn serve<F, Fut>(listener: TcpListener, respond: F)
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send,
{
    let respond = Arc::new(respond);
    loop {
        let (stream, from) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%error, "本机接口接受连接出错");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let respond = Arc::clone(&respond);
        tokio::spawn(async move {
            match tokio::time::timeout(EXCHANGE_TIMEOUT, exchange(stream, respond.as_ref())).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::debug!(%from, "本机接口上的一个请求没有处理完：{error:#}"),
                Err(_) => tracing::debug!(%from, "本机接口上的一条连接超时了"),
            }
        });
    }
}

async fn exchange<F, Fut>(mut stream: TcpStream, respond: &F) -> anyhow::Result<()>
where
    F: Fn(Request) -> Fut,
    Fut: Future<Output = Response>,
{
    let response = match read_request(&mut stream).await? {
        Some(request) if request.method == "GET" => respond(request).await,
        Some(_) => Response::error(405, "这个接口只支持 GET"),
        None => Response::error(400, "不是一个 HTTP 请求"),
    };
    stream.write_all(&response.encode()).await.context("写应答")?;
    stream.shutdown().await.context("关闭连接")
}

/// 读出请求头。读到的不是 HTTP 请求时返回 `None`。
async fn read_request(stream: &mut TcpStream) -> anyhow::Result<Option<Request>> {
    let mut head = Vec::new();
    let mut chunk = [0; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await.context("读请求")?;
        if read == 0 || head.len() + read > MAX_REQUEST_HEAD {
            return Ok(None);
        }
        head.extend_from_slice(&chunk[..read]);
    }
    Ok(parse_request(&String::from_utf8_lossy(&head)))
}

fn parse_request(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, version) = (first.next()?, first.next()?, first.next()?);
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return None;
    }
    let bearer = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization").then(|| value.trim().strip_prefix("Bearer ")).flatten()
    });
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Some(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        bearer: bearer.map(|token| token.trim().to_owned()),
    })
}

/// 向 `addr` 发一个 `GET`，返回应答体。
///
/// # Errors
///
/// 连接失败、应答不是有效的 HTTP 响应，或状态码非 200（此时错误中包含应答体作为对端返回的原因）。
pub(crate) async fn get(addr: SocketAddr, path: &str, bearer: Option<&str>) -> anyhow::Result<String> {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await.with_context(|| format!("连接 {addr}"))?;
        let authorization = bearer.map(|token| format!("Authorization: Bearer {token}\r\n")).unwrap_or_default();
        let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{authorization}Connection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.context("发请求")?;
        let mut response = Vec::new();
        stream.take(MAX_RESPONSE).read_to_end(&mut response).await.context("读应答")?;
        anyhow::Ok(response)
    };
    let response = tokio::time::timeout(EXCHANGE_TIMEOUT, exchange).await.with_context(|| format!("等待 {addr} 应答超时"))??;
    let text = String::from_utf8(response).context("应答不是文本")?;
    let (head, body) = text.split_once("\r\n\r\n").context("应答不是 HTTP")?;
    let status = head.split(' ').nth(1).and_then(|code| code.parse::<u16>().ok()).context("应答不是 HTTP")?;
    ensure!(head.starts_with("HTTP/1."), "应答不是 HTTP");
    if status != 200 {
        bail!("{}（状态码 {status}）", body.trim());
    }
    Ok(body.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, |request: Request| async move {
            match (request.path.as_str(), request.bearer.as_deref()) {
                ("/open", _) => Response::ok("text/plain; charset=utf-8", "公开的\n".to_owned()),
                ("/secret", Some("s3cret")) => Response::ok("application/json", "{\"ok\":true}".to_owned()),
                ("/secret", _) => Response::error(401, "要带令牌"),
                _ => Response::error(404, "没有这个路径"),
            }
        }));
        addr
    }

    #[tokio::test]
    async fn a_get_round_trips_with_and_without_a_token() {
        let addr = server().await;
        assert_eq!(get(addr, "/open", None).await.unwrap(), "公开的\n");
        assert_eq!(get(addr, "/open?x=1", None).await.unwrap(), "公开的\n", "查询串不算在路径里");
        assert_eq!(get(addr, "/secret", Some("s3cret")).await.unwrap(), "{\"ok\":true}");
        let refused = get(addr, "/secret", Some("wrong")).await.unwrap_err();
        assert!(format!("{refused:#}").contains("要带令牌") && format!("{refused:#}").contains("401"), "{refused:#}");
        assert!(format!("{:#}", get(addr, "/secret", None).await.unwrap_err()).contains("401"));
        assert!(format!("{:#}", get(addr, "/nowhere", None).await.unwrap_err()).contains("没有这个路径"));
    }

    #[tokio::test]
    async fn anything_but_a_get_is_turned_away() {
        let addr = server().await;
        let send = |raw: &'static str| async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(raw.as_bytes()).await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        };
        assert!(send("POST /open HTTP/1.1\r\nHost: x\r\n\r\n").await.starts_with("HTTP/1.1 405 "));
        assert!(send("hello\r\n\r\n").await.starts_with("HTTP/1.1 400 "));
        assert!(send("GET /open HTTP/1.1\r\nHost: x\r\n\r\n").await.starts_with("HTTP/1.1 200 OK\r\n"));
        let nobody: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(get(nobody, "/open", None).await.is_err());
    }

    #[test]
    fn requests_are_parsed_leniently_enough_for_curl_and_prometheus() {
        let head =
            "GET /metrics?format=text HTTP/1.1\r\nHost: 127.0.0.1:20333\r\nUser-Agent: curl/8\r\nauthorization:  Bearer  abc \r\n\r\n";
        let request = parse_request(head).unwrap();
        assert_eq!(
            request,
            Request { method: "GET".into(), path: "/metrics".into(), query: "format=text".into(), bearer: Some("abc".into()) }
        );
        assert_eq!(parse_request("GET /x HTTP/1.0\r\n\r\n").unwrap().bearer, None);
        assert!(parse_request("GET x HTTP/1.1\r\n\r\n").is_none() && parse_request("\r\n\r\n").is_none());
    }
}
