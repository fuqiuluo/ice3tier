//! SSE 端点：一个请求一段流式回答。

use std::fmt::Write as _;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use super::{Counters, Gauge, hold_until_closed, respond};
use crate::http::RequestHead;
use crate::net::{TcpSocket, reset_on_close};
use crate::wire::{Answer, Chain, End, Fnv, SseRequest, filler, hex, now_ns, parse_hex};
use crate::{chunked, sse};

/// 请求体最多多大。真实的提示词到 1 MB 左右。
const MAX_BODY: usize = 64 * 1024 * 1024;
/// 读取请求体的超时时间：即使在低速链路上上传 1 MB 也远短于此值。
const BODY_TIMEOUT: Duration = Duration::from_secs(600);
/// 一次写最多攒多少事件。速率是 0（发得越快越好）或者落后于计划时，几个事件合成一次写。
const MAX_WRITE: usize = 16 * 1024;

pub(super) async fn serve<S>(mut stream: S, head: &RequestHead, mut body: Vec<u8>, counters: &Counters) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpSocket,
{
    let Some(len) = head.header("content-length").and_then(|value| value.parse::<usize>().ok()).filter(|&len| len <= MAX_BODY) else {
        counters.bad.fetch_add(1, Ordering::Relaxed);
        return respond(&mut stream, 400, "缺少有效的 Content-Length 请求头（最大 64 MB）").await;
    };
    if body.len() < len {
        let have = body.len();
        body.resize(len, 0);
        tokio::time::timeout(BODY_TIMEOUT, stream.read_exact(&mut body[have..])).await.context("读请求体超时")?.context("读请求体")?;
    }
    body.truncate(len);
    let received_ns = now_ns();
    let request: SseRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(err) => {
            counters.bad.fetch_add(1, Ordering::Relaxed);
            return respond(&mut stream, 400, &format!("无法解析请求体 JSON：{err}")).await;
        }
    };
    drop(body);
    if parse_hex(&request.prompt_hash) != Some(Fnv::of(request.prompt.as_bytes())) {
        counters.bad.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(stream = %request.stream, bytes = request.prompt.len(), "提示词与哈希不匹配：请求体可能已损坏");
        return respond(&mut stream, 400, "提示词与 prompt_hash 不匹配：请求体可能已损坏").await;
    }

    let _active = Gauge::new(&counters.sse_active);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\
         Connection: close\r\nx-llmgw-received-ns: {received_ns}\r\nx-llmgw-prompt-bytes: {}\r\n\r\n",
        request.prompt.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    let answer = &request.answer;
    if let Err(err) = think(&mut stream, answer).await {
        counters.gone.fetch_add(1, Ordering::Relaxed);
        return Err(err.context("思考期间写保活注释"));
    }
    let mut chain = Chain::new();
    let limit = match answer.end {
        End::Done => answer.tokens,
        End::Abort | End::Stall => answer.end_after.min(answer.tokens),
    };
    if let Err(err) = send_events(&mut stream, answer, &mut chain, limit, counters).await {
        counters.gone.fetch_add(1, Ordering::Relaxed);
        return Err(err.context("写事件"));
    }

    match answer.end {
        End::Done => {
            let mut text = String::new();
            let end = format!(r#"{{"count":{},"h":"{}"}}"#, chain.count(), hex(chain.hash()));
            sse::write_event(&mut text, Some("end"), None, &end);
            sse::write_event(&mut text, None, None, "[DONE]");
            let mut wire = Vec::with_capacity(text.len() + 16);
            chunked::encode(&mut wire, text.as_bytes());
            wire.extend_from_slice(chunked::LAST_CHUNK);
            stream.write_all(&wire).await?;
            stream.shutdown().await?;
        }
        End::Abort => {
            counters.aborted.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(stream = %request.stream, events = chain.count(), "按请求中途重置连接");
            reset_on_close(stream.tcp()).await?;
        }
        End::Stall => {
            counters.stalled.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(stream = %request.stream, events = chain.count(), "按请求停住，等对面关闭");
            hold_until_closed(&mut stream).await;
        }
    }
    Ok(())
}

/// 思考：完全静默，或者每隔一段时间发一个保活注释。
async fn think<S: AsyncWrite + Unpin>(stream: &mut S, answer: &Answer) -> anyhow::Result<()> {
    let until = Instant::now() + Duration::from_millis(answer.think_ms);
    if answer.keepalive_ms == 0 {
        tokio::time::sleep_until(until).await;
        return Ok(());
    }
    let every = Duration::from_millis(answer.keepalive_ms);
    let mut text = String::new();
    sse::write_comment(&mut text, "keep-alive");
    let mut wire = Vec::new();
    chunked::encode(&mut wire, text.as_bytes());
    loop {
        let next = (Instant::now() + every).min(until);
        tokio::time::sleep_until(next).await;
        if next >= until {
            return Ok(());
        }
        stream.write_all(&wire).await?;
        stream.flush().await?;
    }
}

/// 按计划发前 `limit` 个事件。每个事件写出之前盖章，时间是真正交给连接的那一刻。
async fn send_events<S: AsyncWrite + Unpin>(
    stream: &mut S,
    answer: &Answer,
    chain: &mut Chain,
    limit: u32,
    counters: &Counters,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let event_bytes = usize::try_from(answer.event_bytes).context("event_bytes 太大")?;
    let mut index = 0;
    let mut text = String::new();
    let mut wire = Vec::new();
    while index < limit {
        tokio::time::sleep_until(start + answer.due_after_start(index)).await;
        let now = Instant::now();
        text.clear();
        let mut batch = 0;
        while index < limit && text.len() < MAX_WRITE && start + answer.due_after_start(index) <= now {
            let payload = filler(u64::from(index), event_bytes);
            let stamp = chain.seal(now_ns(), payload.as_bytes());
            let mut data = String::with_capacity(payload.len() + 80);
            write!(data, r#"{{"seq":{},"t":{},"h":"{}","delta":"{payload}"}}"#, stamp.seq, stamp.t_ns, hex(stamp.hash))
                .expect("写 String 不会失败");
            sse::write_event(&mut text, None, Some(stamp.seq), &data);
            index += 1;
            batch += 1;
        }
        wire.clear();
        chunked::encode(&mut wire, text.as_bytes());
        stream.write_all(&wire).await?;
        stream.flush().await?;
        counters.events.fetch_add(batch, Ordering::Relaxed);
    }
    Ok(())
}
