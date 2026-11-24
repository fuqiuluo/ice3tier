//! WebSocket 端点：一个会话里多轮问答，像实时类的 API。
//!
//! 客户端先发 `session` 说明会话怎么进行，之后每发一条 `turn` 开始一轮：上游思考、按节拍发事件（文本或二进制帧）、
//! 发 `turn_done`。回答进行中客户端可以插进 `note` 和二进制帧，上游逐条验；客户端发 `sync` 时上游报出验过的计数。
//! 上游按 `server_ping_ms` 定期 ping 客户端。

use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, bail};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;

use super::{Counters, Gauge, hold_until_closed, respond};
use crate::http::RequestHead;
use crate::net::{TcpSocket, reset_on_close};
use crate::wire::{Chain, End, Fnv, Session, Stamp, WsText, binary_frame, filler, hex, now_ns, parse_binary_frame, parse_hex};

/// 等客户端说明会话最多等多久。
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);
/// 速率是 0 时一次最多连发多少个事件再 flush。
const MAX_BATCH: u32 = 64;

pub(super) async fn serve<S>(mut stream: S, head: &RequestHead, rest: Vec<u8>, counters: &Counters) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpSocket,
{
    let key = head.header("sec-websocket-key").filter(|_| head.has_token("upgrade", "websocket"));
    let Some(key) = key else {
        counters.bad.fetch_add(1, Ordering::Relaxed);
        return respond(&mut stream, 400, "要 WebSocket 升级请求").await;
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        derive_accept_key(key.as_bytes())
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    let mut ws = WebSocketStream::from_partially_read(stream, rest, Role::Server, None).await;

    let first = tokio::time::timeout(SESSION_TIMEOUT, ws.next()).await.context("等会话说明超时")?;
    let session = match first {
        Some(Ok(Message::Text(text))) => match serde_json::from_str::<WsText>(&text) {
            Ok(WsText::Session(session)) => session,
            Ok(_) | Err(_) => {
                counters.bad.fetch_add(1, Ordering::Relaxed);
                let detail = format!("第一条消息应该是 session：{}", text.chars().take(200).collect::<String>());
                send_error(&mut ws, &detail).await;
                bail!(detail);
            }
        },
        other => bail!("第一条消息应该是 session 文本消息，收到的是 {other:?}"),
    };
    let _active = Gauge::new(&counters.ws_active);
    let mut state = SessionState::new(session);
    match state.run(&mut ws, counters).await? {
        Ending::Closed => {
            // 关闭握手之后由服务端先断开；TLS 的话先发 close_notify，客户端才分得清这是正常关闭。
            ws.get_mut().shutdown().await?;
            Ok(())
        }
        Ending::Abort => {
            counters.aborted.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(stream = %state.session.stream, events = state.events.count(), "按请求中途重置连接");
            reset_on_close(ws.get_ref().tcp()).await?;
            Ok(())
        }
        Ending::Stall => {
            counters.stalled.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(stream = %state.session.stream, events = state.events.count(), "按请求停住，等对面关闭");
            hold_until_closed(ws.get_mut()).await;
            Ok(())
        }
    }
}

async fn send_error<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>, detail: &str) {
    let text = serde_json::to_string(&WsText::Error { detail: detail.to_owned() }).expect("消息总能编成 JSON");
    // 告诉客户端为什么之后就关；发不出去也没有别的办法了。
    let _ = ws.send(Message::text(text)).await;
    let _ = ws.close(None).await;
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    /// 等客户端开始下一轮。
    Idle,
    Thinking {
        turn: u32,
        until: Instant,
    },
    Streaming {
        turn: u32,
        start: Instant,
        index: u32,
    },
}

enum Ending {
    Closed,
    Abort,
    Stall,
}

struct SessionState {
    session: Session,
    /// 上游发出的事件，整个会话一条链（文本和二进制两种形式共用）。
    events: Chain,
    notes: Chain,
    client_binary: Chain,
    pongs: u64,
    phase: Phase,
}

/// 很远的将来：没有定时任务时 select 里的那个分支用它。
fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86_400)
}

impl SessionState {
    fn new(session: Session) -> Self {
        Self { session, events: Chain::new(), notes: Chain::new(), client_binary: Chain::new(), pongs: 0, phase: Phase::Idle }
    }

    /// 发到第几个事件时按 `end` 出事、出什么事；`done` 时永远不会。
    fn trouble(&self) -> Option<(u64, Ending)> {
        let at = u64::from(self.session.answer.end_after);
        match self.session.answer.end {
            End::Done => None,
            End::Abort => Some((at, Ending::Abort)),
            End::Stall => Some((at, Ending::Stall)),
        }
    }

    /// 已经发够了出事的事件数时，返回该怎么出事。
    fn due_trouble(&self) -> Option<Ending> {
        self.trouble().filter(|(at, _)| *at == self.events.count()).map(|(_, ending)| ending)
    }

    async fn run<S>(&mut self, ws: &mut WebSocketStream<S>, counters: &Counters) -> anyhow::Result<Ending>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let ping_every = (self.session.server_ping_ms > 0).then(|| Duration::from_millis(self.session.server_ping_ms));
        let mut next_ping = ping_every.map_or_else(far_future, |every| Instant::now() + every);
        loop {
            let wake = match self.phase {
                Phase::Idle => far_future(),
                Phase::Thinking { until, .. } => until,
                Phase::Streaming { start, index, .. } => start + self.session.answer.due_after_start(index),
            };
            tokio::select! {
                message = ws.next() => match message {
                    None => return Ok(Ending::Closed),
                    Some(Err(err)) => return Err(anyhow::Error::new(err).context("读客户端的消息")),
                    // 客户端要关闭：库会自动回关闭帧，之后不能再发任何东西，ping 和没发完的事件都停掉，等流结束。
                    Some(Ok(Message::Close(_))) => {
                        next_ping = far_future();
                        self.phase = Phase::Idle;
                    }
                    Some(Ok(message)) => {
                        match self.on_message(message) {
                            Ok(None) => {}
                            Ok(Some(reply)) => ws.send(Message::text(reply)).await?,
                            Err(detail) => {
                                counters.bad.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(stream = %self.session.stream, "{detail}");
                                send_error(ws, &detail).await;
                                bail!(detail);
                            }
                        }
                    }
                },
                _ = tokio::time::sleep_until(wake) => {
                    if let Some(ending) = self.on_timer(ws, counters).await? {
                        return Ok(ending);
                    }
                }
                _ = tokio::time::sleep_until(next_ping) => {
                    ws.send(Message::Ping(now_ns().to_le_bytes().to_vec().into())).await?;
                    next_ping = ping_every.map_or_else(far_future, |every| Instant::now() + every);
                }
            }
        }
    }

    /// 处理客户端发送的一条消息。返回需立即回复客户端的文本；校验失败时返回原因并终止会话。
    fn on_message(&mut self, message: Message) -> Result<Option<String>, String> {
        match message {
            Message::Text(text) => match serde_json::from_str::<WsText>(&text) {
                Ok(WsText::Turn { turn, prompt_hash, prompt }) => {
                    if !matches!(self.phase, Phase::Idle) {
                        return Err(format!("第 {turn} 轮开始的时候上一轮还没有完"));
                    }
                    if parse_hex(&prompt_hash) != Some(Fnv::of(prompt.as_bytes())) {
                        return Err(format!("第 {turn} 轮提示词（{} 字节）与哈希不匹配：消息可能已损坏", prompt.len()));
                    }
                    let until = Instant::now() + Duration::from_millis(self.session.answer.think_ms);
                    self.phase = Phase::Thinking { turn, until };
                    Ok(None)
                }
                Ok(WsText::Note { seq, t, h, text }) => {
                    let stamp = Stamp { seq, t_ns: t, hash: parse_hex(&h).unwrap_or_default() };
                    self.notes.check(stamp, text.as_bytes()).map_err(|err| format!("客户端的消息：{err}"))?;
                    Ok(None)
                }
                Ok(WsText::Sync) => {
                    let synced = WsText::Synced {
                        notes: self.notes.count(),
                        notes_hash: hex(self.notes.hash()),
                        binary: self.client_binary.count(),
                        binary_hash: hex(self.client_binary.hash()),
                        pongs: self.pongs,
                    };
                    Ok(Some(serde_json::to_string(&synced).expect("消息总能编成 JSON")))
                }
                Ok(other) => Err(format!("收到意外的客户端消息类型：{other:?}")),
                Err(err) => Err(format!("无法解析客户端消息 JSON：{err}")),
            },
            Message::Binary(frame) => {
                let (stamp, payload) =
                    parse_binary_frame(&frame).ok_or_else(|| format!("客户端的二进制帧只有 {} 字节，比头还短", frame.len()))?;
                self.client_binary.check(stamp, payload).map_err(|err| format!("客户端的二进制帧：{err}")).map(|()| None)
            }
            Message::Pong(_) => {
                self.pongs += 1;
                Ok(None)
            }
            // ping 由底层库自动回复 pong；close 已在 `run` 中处理，不会到达此处。
            Message::Ping(_) | Message::Close(_) | Message::Frame(_) => Ok(None),
        }
    }

    /// 定时器到了：思考结束开始发，或者到了该发下一批事件的时候。返回 `Some` 表示按请求出事。
    async fn on_timer<S>(&mut self, ws: &mut WebSocketStream<S>, counters: &Counters) -> anyhow::Result<Option<Ending>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (turn, start, mut index) = match self.phase {
            Phase::Idle => return Ok(None),
            Phase::Thinking { turn, .. } => {
                self.phase = Phase::Streaming { turn, start: Instant::now(), index: 0 };
                return Ok(None);
            }
            Phase::Streaming { turn, start, index } => (turn, start, index),
        };
        let answer = &self.session.answer;
        let event_bytes = usize::try_from(answer.event_bytes).context("event_bytes 太大")?;
        let now = Instant::now();
        let mut batch = 0;
        while index < answer.tokens && batch < MAX_BATCH && start + answer.due_after_start(index) <= now {
            if let Some(ending) = self.due_trouble() {
                ws.flush().await?;
                return Ok(Some(ending));
            }
            let message = if self.session.binary {
                Message::binary(binary_frame(&mut self.events, event_bytes))
            } else {
                let delta = filler(self.events.count(), event_bytes);
                let stamp = self.events.seal(now_ns(), delta.as_bytes());
                let text = WsText::Delta { turn, seq: stamp.seq, t: stamp.t_ns, h: hex(stamp.hash), delta };
                Message::text(serde_json::to_string(&text).expect("消息总能编成 JSON"))
            };
            ws.feed(message).await?;
            index += 1;
            batch += 1;
        }
        ws.flush().await?;
        counters.events.fetch_add(u64::from(batch), Ordering::Relaxed);
        if let Some(ending) = self.due_trouble() {
            return Ok(Some(ending));
        }
        if index < answer.tokens {
            self.phase = Phase::Streaming { turn, start, index };
            return Ok(None);
        }
        let done = WsText::TurnDone { turn, events: u64::from(index) };
        ws.send(Message::text(serde_json::to_string(&done).expect("消息总能编成 JSON"))).await?;
        self.phase = Phase::Idle;
        Ok(None)
    }
}
