//! 模拟的 LLM API：HTTPS 和明文 HTTP 各一个端口，SSE 端点和 WebSocket 端点。每个请求怎么回答由请求自己说（见 [`crate::wire`]）。
//!
//! | 方法和路径 | 作用 |
//! |---|---|
//! | `POST /v1/chat/completions` | SSE：读完请求体、核对提示词，回响应头，按请求里的参数思考、发事件、结束 |
//! | `GET /v1/realtime` | WebSocket 会话 |
//! | `GET /health` | 回 `ok`，用来确认经代理能到这里 |
//!
//! 每个连接只服务一个请求（`Connection: close`）：经代理入口时一个请求就是一条新的流，这正是要测的。

mod sse;
mod ws;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context;
use clap::Args as ClapArgs;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::http::{RequestHead, read_head};
use crate::net::TcpSocket;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// HTTPS 的监听地址；写 off 不开
    #[arg(long, default_value = "0.0.0.0:443")]
    https: String,
    /// 明文 HTTP 的监听地址；写 off 不开
    #[arg(long, default_value = "0.0.0.0:80")]
    http: String,
    /// 测试 CA 所在的目录：没有就生成，负载端用里面的 ca.pem
    #[arg(long)]
    cert_dir: PathBuf,
    /// 证书里写的名字（域名或 IP），可以写多次。负载端连的地址或者 --sni 必须在里面
    #[arg(long = "name", default_values_t = ["localhost".to_owned(), "127.0.0.1".to_owned(), "api.llmgw.test".to_owned()])]
    names: Vec<String>,
}

/// 计数器，定期打一行，退出时再打一行。
#[derive(Default)]
struct Counters {
    connections: AtomicU64,
    open: AtomicU64,
    sse_active: AtomicU64,
    ws_active: AtomicU64,
    requests: AtomicU64,
    events: AtomicU64,
    aborted: AtomicU64,
    stalled: AtomicU64,
    bad: AtomicU64,
    gone: AtomicU64,
}

impl Counters {
    fn line(&self, events_per_s: u64) -> String {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        format!(
            "上游：连接 {}（累计 {}），SSE 进行中 {}，WebSocket 进行中 {}，事件 {events_per_s}/s（累计 {}），请求 {}，中途重置 {}，停住 {}，坏请求 {}，客户端先断 {}",
            get(&self.open),
            get(&self.connections),
            get(&self.sse_active),
            get(&self.ws_active),
            get(&self.events),
            get(&self.requests),
            get(&self.aborted),
            get(&self.stalled),
            get(&self.bad),
            get(&self.gone),
        )
    }
}

/// 计数器加一，丢掉时减一。
struct Gauge<'a>(&'a AtomicU64);

impl<'a> Gauge<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for Gauge<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// # Errors
///
/// 端口绑定失败或证书目录读写失败。
pub async fn run(args: Args) -> anyhow::Result<()> {
    let tls = TlsAcceptor::from(crate::tls::server_config(&args.cert_dir, &args.names)?);
    let counters = Arc::new(Counters::default());
    let mut listeners = Vec::new();
    for (bind, secure) in [(&args.https, true), (&args.http, false)] {
        if bind == "off" {
            continue;
        }
        let addr: SocketAddr = bind.parse().with_context(|| format!("监听地址 {bind:?} 不对"))?;
        let listener = TcpListener::bind(addr).await.with_context(|| format!("监听 {addr}"))?;
        tracing::info!(%addr, tls = secure, "上游开始监听");
        listeners.push(tokio::spawn(accept_loop(listener, secure.then(|| tls.clone()), counters.clone())));
    }
    anyhow::ensure!(!listeners.is_empty(), "--https 和 --http 至少要开一个");
    // 打印一行"已就绪"，测试脚本等的就是它。
    eprintln!("上游已就绪，CA 证书：{}", args.cert_dir.join("ca.pem").display());

    let mut tick = tokio::time::interval(Duration::from_secs(10));
    let mut last_events = 0;
    let mut last_line = String::new();
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let events = counters.events.load(Ordering::Relaxed);
                let line = counters.line((events - last_events) / 10);
                last_events = events;
                if line != last_line {
                    eprintln!("{line}");
                    last_line = line;
                }
            }
            _ = shutdown_signal() => break,
        }
    }
    eprintln!("{}", counters.line(0));
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn accept_loop(listener: TcpListener, tls: Option<TlsAcceptor>, counters: Arc<Counters>) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // 文件描述符用完之类的：等一下再接，不退出。
                tracing::warn!(%err, "接受连接失败");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let tls = tls.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            counters.connections.fetch_add(1, Ordering::Relaxed);
            let _open = Gauge::new(&counters.open);
            if let Err(err) = tcp.set_nodelay(true) {
                tracing::debug!(%err, "启用 TCP_NODELAY 失败");
            }
            let served = match tls {
                Some(tls) => match tokio::time::timeout(HEAD_TIMEOUT, tls.accept(tcp)).await {
                    Ok(Ok(stream)) => serve(stream, &counters).await,
                    Ok(Err(err)) => Err(anyhow::Error::new(err).context("TLS 握手")),
                    Err(_) => Err(anyhow::anyhow!("TLS 握手超时")),
                },
                None => serve(tcp, &counters).await,
            };
            if let Err(err) = served {
                tracing::debug!(%peer, "连接结束：{err:#}");
            }
        });
    }
}

/// 等请求头最多等多久。请求体可能很大、路上可能很慢，不受它限制。
const HEAD_TIMEOUT: Duration = Duration::from_secs(60);

async fn serve<S>(mut stream: S, counters: &Counters) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpSocket,
{
    let mut buf = Vec::new();
    let head_len = tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut stream, &mut buf)).await.context("等请求头超时")??;
    let head = RequestHead::parse(&buf[..head_len])?;
    let rest = buf.split_off(head_len);
    counters.requests.fetch_add(1, Ordering::Relaxed);
    match (head.method.as_str(), head.path.as_str()) {
        ("POST", "/v1/chat/completions") => sse::serve(stream, &head, rest, counters).await,
        ("GET", "/v1/realtime") => ws::serve(stream, &head, rest, counters).await,
        ("GET", "/health") => respond(&mut stream, 200, "ok").await,
        _ => {
            counters.bad.fetch_add(1, Ordering::Relaxed);
            respond(&mut stream, 404, "没有这个端点").await
        }
    }
}

/// 回一个简单的响应然后正常关闭。
async fn respond<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, body: &str) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

/// 停住：不再发任何东西，也不回应，直到对面关闭连接。读到的字节直接丢掉。
async fn hold_until_closed<S: AsyncRead + Unpin>(stream: &mut S) {
    use tokio::io::AsyncReadExt;
    let mut sink = [0_u8; 4096];
    while let Ok(1..) = stream.read(&mut sink).await {}
}
