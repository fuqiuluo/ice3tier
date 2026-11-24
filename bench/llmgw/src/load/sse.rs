//! 一条 SSE 流：发请求（带提示词），读响应头，按事件验顺序、完整性和哈希，判断它是怎么结束的。

use std::borrow::Cow;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use super::client::{Conn, Run, StreamEnd, Tally, open};
use super::scenario::{GroupSpec, Outcome};
use crate::http::{ResponseHead, read_head};
use crate::wire::{Chain, End, Fnv, SseRequest, Stamp, hex, now_ns, parse_hex, prompt};
use crate::{chunked, sse};

#[derive(Deserialize)]
struct TokenEvent<'a> {
    seq: u64,
    t: u64,
    #[serde(borrow)]
    h: Cow<'a, str>,
    #[serde(borrow)]
    delta: Cow<'a, str>,
}

#[derive(Deserialize)]
struct EndEvent<'a> {
    count: u64,
    #[serde(borrow)]
    h: Cow<'a, str>,
}

/// 响应体的解析：分块编码、SSE、事件的验证。和读写分开，好单独测。
pub struct Body {
    decoder: chunked::Decoder,
    parser: sse::Parser,
    chain: Chain,
    plain: Vec<u8>,
    items: Vec<sse::Item>,
    /// 上游的 end 事件报的事件数，已经和收到的核对过。
    end_seen: bool,
    done_seen: bool,
    expected_tokens: u64,
    /// 这一批里新收到的事件。
    pub fresh: Vec<Stamp>,
    pub keepalives: u64,
}

impl Body {
    pub fn new(expected_tokens: u32) -> Self {
        Self {
            decoder: chunked::Decoder::new(),
            parser: sse::Parser::new(),
            chain: Chain::new(),
            plain: Vec::new(),
            items: Vec::new(),
            end_seen: false,
            done_seen: false,
            expected_tokens: u64::from(expected_tokens),
            fresh: Vec::new(),
            keepalives: 0,
        }
    }

    pub fn events(&self) -> u64 {
        self.chain.count()
    }

    /// 收到了终止事件，分块编码也正常结束了。
    pub fn is_complete(&self) -> bool {
        self.done_seen && self.decoder.is_done()
    }

    /// 喂一批从连接上读到的字节。新收到的事件放在 `fresh` 里（调用者负责清空）。
    ///
    /// # Errors
    ///
    /// 内容不对：编码坏了、事件乱序或者被改过、end 事件报的数和收到的不一样。错误是给人看的说明。
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.plain.clear();
        self.decoder.feed(bytes, &mut self.plain).map_err(|err| format!("分块编码：{err}"))?;
        self.items.clear();
        self.parser.feed(&self.plain, &mut self.items);
        for item in std::mem::take(&mut self.items) {
            match item {
                sse::Item::Comment(_) => self.keepalives += 1,
                sse::Item::Event(event) => self.on_event(&event)?,
            }
        }
        Ok(())
    }

    fn on_event(&mut self, event: &sse::Event) -> Result<(), String> {
        if self.done_seen {
            return Err("[DONE] 之后还有事件".to_owned());
        }
        if event.data == "[DONE]" {
            if !self.end_seen {
                return Err(format!("收到 {} 个事件之后来了 [DONE]，前面没有 end 事件", self.chain.count()));
            }
            self.done_seen = true;
            return Ok(());
        }
        if event.name.as_deref() == Some("end") {
            let end: EndEvent<'_> = serde_json::from_str(&event.data).map_err(|err| format!("无法解析 end 事件：{err}"))?;
            if end.count != self.chain.count() || parse_hex(&end.h) != Some(self.chain.hash()) {
                return Err(format!(
                    "上游说发了 {} 个事件（哈希 {}），收到并验过的是 {} 个（哈希 {}）",
                    end.count,
                    end.h,
                    self.chain.count(),
                    hex(self.chain.hash())
                ));
            }
            if end.count != self.expected_tokens {
                return Err(format!("上游正常结束时只发了 {} 个事件，请求的是 {} 个", end.count, self.expected_tokens));
            }
            self.end_seen = true;
            return Ok(());
        }
        let token: TokenEvent<'_> =
            serde_json::from_str(&event.data).map_err(|err| format!("无法解析事件：{err}；内容 {:?}", truncate(&event.data)))?;
        let stamp = Stamp { seq: token.seq, t_ns: token.t, hash: parse_hex(&token.h).unwrap_or_default() };
        self.chain.check(stamp, token.delta.as_bytes()).map_err(|err| err.to_string())?;
        self.fresh.push(stamp);
        Ok(())
    }
}

fn truncate(text: &str) -> String {
    text.chars().take(120).collect()
}

/// 跑一条 SSE 流，返回它是怎么结束的。测量记在 `tally` 里。
pub async fn run(run: &Run, group: usize, spec: &GroupSpec, stream_no: u64, id: &str, tally: &mut Tally) -> StreamEnd {
    let begin = Instant::now();
    let mut conn = match open(run, tally).await {
        Ok(conn) => conn,
        Err(end) => return end,
    };
    let prompt = prompt(stream_no, spec.prompt_bytes.for_stream(stream_no));
    let request = SseRequest { stream: id.to_owned(), answer: spec.answer(), prompt_hash: hex(Fnv::of(prompt.as_bytes())), prompt };
    let body = serde_json::to_vec(&request).expect("请求总能编成 JSON");
    drop(request);
    let mut wire = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        run.target.authority,
        body.len()
    )
    .into_bytes();
    wire.extend_from_slice(&body);
    drop(body);
    let sent_wall = now_ns();
    let written = tokio::select! {
        written = async { conn.write_all(&wire).await?; conn.flush().await } => written,
        () = tokio::time::sleep_until(run.deadline) => return StreamEnd::new(Outcome::Timeout, "到时限时请求还没有发完"),
    };
    if let Err(err) = written {
        return StreamEnd::broken(&err, "发请求");
    }
    let sent = Instant::now();
    tally.bytes_up += u64::try_from(wire.len()).unwrap_or(u64::MAX);
    drop(wire);

    let mut buf = Vec::with_capacity(16 * 1024);
    let head_len = tokio::select! {
        head = read_head(&mut conn, &mut buf) => match head {
            Ok(len) => len,
            Err(err) => return StreamEnd::broken(&err, "读响应头"),
        },
        () = tokio::time::sleep_until(run.deadline) => return StreamEnd::new(Outcome::Timeout, "到时限时还没有收到响应头"),
    };
    tally.first_byte = Some(begin.elapsed());
    let head = match ResponseHead::parse(&buf[..head_len]) {
        Ok(head) => head,
        Err(err) => return StreamEnd::new(Outcome::Error, format!("响应头：{err}")),
    };
    if head.status != 200 {
        return refused(&mut conn, &head, buf.split_off(head_len)).await;
    }
    if let Some(received) = head.header("x-llmgw-received-ns").and_then(|value| value.parse::<u64>().ok()) {
        tally.upload = Some(Duration::from_nanos(received.saturating_sub(sent_wall)));
    }
    let leftover = buf.split_off(head_len);
    read_events(run, group, spec, &mut conn, leftover, sent, tally).await
}

/// 上游回了 200 以外的状态：读一点正文当作说明。
async fn refused(conn: &mut Conn, head: &ResponseHead, mut body: Vec<u8>) -> StreamEnd {
    let mut chunk = [0_u8; 2048];
    if let Ok(Ok(read)) = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut chunk)).await {
        body.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&body).into_owned();
    let outcome = if text.contains("损坏") { Outcome::Corrupt } else { Outcome::HttpError };
    StreamEnd::new(outcome, format!("HTTP {} {}：{}", head.status, head.reason, truncate(&text)))
}

async fn read_events(
    run: &Run,
    group: usize,
    spec: &GroupSpec,
    conn: &mut Conn,
    leftover: Vec<u8>,
    sent: Instant,
    tally: &mut Tally,
) -> StreamEnd {
    let mut body = Body::new(spec.tokens);
    let stall_point = (spec.end == End::Stall).then_some(u64::from(spec.end_after));
    let hold = Duration::from_secs_f64(spec.hold_s);
    // 在第 0 个事件之后停住的，从收到响应头就开始算。
    let mut hold_until: Option<Instant> = (stall_point == Some(0)).then(|| Instant::now() + hold);
    let mut buf = vec![0_u8; 16 * 1024];
    let mut pending = leftover;
    loop {
        if !pending.is_empty() {
            let recv = Instant::now();
            let recv_wall = now_ns();
            tally.bytes_down += u64::try_from(pending.len()).unwrap_or(u64::MAX);
            if let Err(detail) = body.feed(&pending) {
                return StreamEnd::new(Outcome::Corrupt, detail);
            }
            pending.clear();
            for stamp in body.fresh.drain(..) {
                if stamp.seq == 0 {
                    tally.ttft.push(recv.saturating_duration_since(sent));
                    tally.first_token_lag.push(Duration::from_nanos(recv_wall.saturating_sub(stamp.t_ns)));
                }
                tally.event(run, group, recv, recv_wall, stamp.t_ns);
            }
            tally.keepalives = body.keepalives;
            if body.is_complete() {
                return StreamEnd::new(Outcome::Complete, "");
            }
            if let Some(point) = stall_point {
                if body.events() > point {
                    return StreamEnd::new(
                        Outcome::Corrupt,
                        format!("上游应该在第 {point} 个事件之后停住，却收到了第 {} 个", body.events()),
                    );
                }
                if body.events() == point && hold_until.is_none() {
                    hold_until = Some(Instant::now() + hold);
                }
            }
        }
        let wake = hold_until.map_or(run.deadline, |hold| hold.min(run.deadline));
        let read = tokio::select! {
            read = conn.read(&mut buf) => read,
            () = tokio::time::sleep_until(wake) => {
                return if hold_until.is_some_and(|hold| hold <= Instant::now()) {
                    StreamEnd::new(Outcome::Stalled, "")
                } else {
                    StreamEnd::new(Outcome::Timeout, format!("到时限时收到了 {} 个事件", body.events()))
                };
            }
        };
        match read {
            Ok(0) => {
                let detail =
                    format!("收到 {} 个事件之后连接正常关闭了（FIN），没有终止事件；这样的截断在 TCP 层看起来像正常结束", body.events());
                return StreamEnd::new(Outcome::Truncated, detail);
            }
            Ok(read) => pending.extend_from_slice(&buf[..read]),
            Err(err) => return StreamEnd::broken(&err, &format!("收到 {} 个事件之后", body.events())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 按上游的写法组一段响应体。
    fn wire(tokens: u64, end: bool) -> Vec<u8> {
        let mut chain = Chain::new();
        let mut text = String::new();
        sse::write_comment(&mut text, "keep-alive");
        for seq in 0..tokens {
            let delta = crate::wire::filler(seq, 12);
            let stamp = chain.seal(1000 + seq, delta.as_bytes());
            let data = format!(r#"{{"seq":{},"t":{},"h":"{}","delta":"{delta}"}}"#, stamp.seq, stamp.t_ns, hex(stamp.hash));
            sse::write_event(&mut text, None, Some(seq), &data);
        }
        if end {
            sse::write_event(&mut text, Some("end"), None, &format!(r#"{{"count":{tokens},"h":"{}"}}"#, hex(chain.hash())));
            sse::write_event(&mut text, None, None, "[DONE]");
        }
        let mut out = Vec::new();
        chunked::encode(&mut out, text.as_bytes());
        if end {
            out.extend_from_slice(chunked::LAST_CHUNK);
        }
        out
    }

    #[test]
    fn a_whole_answer_fed_in_small_pieces_is_complete() {
        let mut body = Body::new(20);
        let mut seen = 0;
        for piece in wire(20, true).chunks(7) {
            body.feed(piece).unwrap();
            seen += body.fresh.drain(..).count();
        }
        assert_eq!(seen, 20);
        assert_eq!(body.keepalives, 1);
        assert!(body.is_complete());
    }

    #[test]
    fn an_answer_cut_short_is_not_complete() {
        let mut body = Body::new(20);
        body.feed(&wire(5, false)).unwrap();
        assert_eq!(body.events(), 5);
        assert!(!body.is_complete());
    }

    #[test]
    fn a_normal_end_with_fewer_events_than_requested_is_corrupt() {
        let mut body = Body::new(20);
        let err = body.feed(&wire(5, true)).unwrap_err();
        assert!(err.contains("请求的是 20"), "{err}");
    }

    #[test]
    fn a_changed_byte_inside_an_event_is_corrupt() {
        let mut bytes = wire(3, true);
        let at = bytes.windows(5).position(|window| window == b"quick").unwrap();
        bytes[at] = b'Q';
        let err = Body::new(3).feed(&bytes).unwrap_err();
        assert!(err.contains("累积哈希"), "{err}");
    }

    #[test]
    fn a_dropped_event_is_corrupt() {
        let text = String::from_utf8(wire(3, false)).unwrap();
        // 去掉第二个事件（id: 1 那一块）。
        let start = text.find("id: 1\n").unwrap();
        let end = text[start..].find("\n\n").unwrap() + start + 2;
        let without = format!("{}{}", &text[..start], &text[end..]);
        // 去掉了内容，块长度也要跟着改：重新按块编码。
        let inner = without.split_once("\r\n").unwrap().1.trim_end_matches("\r\n");
        let mut bytes = Vec::new();
        chunked::encode(&mut bytes, inner.as_bytes());
        let err = Body::new(3).feed(&bytes).unwrap_err();
        assert!(err.contains("第 1 个"), "{err}");
    }
}
