//! 一个 WebSocket 会话：多轮问答，回答进行中插进消息和二进制帧，两边互相 ping，两轮之间空闲。
//! 协议见 [`crate::upstream`] 的 WebSocket 端点。

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::{Error as WsError, Message, error::ProtocolError};

use super::client::{Conn, Run, StreamEnd, Tally, open};
use super::scenario::{GroupSpec, Outcome};
use crate::http::{ResponseHead, read_head};
use crate::wire::{Chain, End, Fnv, Session, Stamp, WsText, binary_frame, filler, hex, now_ns, parse_binary_frame, parse_hex, prompt};

pub async fn run(run: &Run, group: usize, spec: &GroupSpec, stream_no: u64, id: &str, tally: &mut Tally) -> StreamEnd {
    let begin = Instant::now();
    let mut conn = match open(run, tally).await {
        Ok(conn) => conn,
        Err(end) => return end,
    };
    let key = generate_key();
    let request = format!(
        "GET /v1/realtime HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        run.target.authority
    );
    let written = tokio::select! {
        written = async { conn.write_all(request.as_bytes()).await?; conn.flush().await } => written,
        () = tokio::time::sleep_until(run.deadline) => return StreamEnd::new(Outcome::Timeout, "到时限时升级请求还没有发完"),
    };
    if let Err(err) = written {
        return StreamEnd::broken(&err, "发升级请求");
    }
    let mut buf = Vec::new();
    let head_len = tokio::select! {
        head = read_head(&mut conn, &mut buf) => match head {
            Ok(len) => len,
            Err(err) => return StreamEnd::broken(&err, "读升级的回答"),
        },
        () = tokio::time::sleep_until(run.deadline) => return StreamEnd::new(Outcome::Timeout, "到时限时还没有收到升级的回答"),
    };
    tally.first_byte = Some(begin.elapsed());
    let head = match ResponseHead::parse(&buf[..head_len]) {
        Ok(head) => head,
        Err(err) => return StreamEnd::new(Outcome::Error, format!("升级的回答：{err}")),
    };
    let accept = derive_accept_key(key.as_bytes());
    if head.status != 101 || head.header("sec-websocket-accept") != Some(accept.as_str()) {
        return StreamEnd::new(Outcome::HttpError, format!("WebSocket 升级失败：HTTP {} {}", head.status, head.reason));
    }
    let leftover = buf.split_off(head_len);
    let ws = WebSocketStream::from_partially_read(conn, leftover, Role::Client, None).await;
    let mut session = ClientSession::new(run, group, spec, stream_no, tally);
    session.run(ws, id).await
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    /// 一轮的请求已经发出，在收这一轮的事件。
    Answering { sent: Instant, received: u32, notes: u32 },
    /// 这一轮的事件收齐了，发了 sync，等上游报数。
    Syncing,
    /// 两轮之间。
    Idle { until: Instant },
    /// 上游按要求停住了，拿着它到这个时刻。
    Holding { until: Instant },
    /// 发了关闭帧，等上游回关闭帧、连接结束。
    Closing,
}

struct ClientSession<'a> {
    run: &'a Run,
    group: usize,
    spec: &'a GroupSpec,
    stream_no: u64,
    tally: &'a mut Tally,
    /// 上游的事件，整个会话一条链。
    events: Chain,
    notes: Chain,
    binary: Chain,
    turn: u32,
    phase: Phase,
    next_ping: Option<Instant>,
    next_binary: Option<Instant>,
}

/// 一条会话结束了：负载端判定的结果。用 `?` 从各个处理函数里一路返回。
type Flow<T = ()> = Result<T, StreamEnd>;

impl<'a> ClientSession<'a> {
    fn new(run: &'a Run, group: usize, spec: &'a GroupSpec, stream_no: u64, tally: &'a mut Tally) -> Self {
        Self {
            run,
            group,
            spec,
            stream_no,
            tally,
            events: Chain::new(),
            notes: Chain::new(),
            binary: Chain::new(),
            turn: 0,
            phase: Phase::Syncing,
            next_ping: None,
            next_binary: None,
        }
    }

    async fn run(&mut self, mut ws: WebSocketStream<Conn>, id: &str) -> StreamEnd {
        match self.drive(&mut ws, id).await {
            Ok(()) => StreamEnd::new(Outcome::Complete, ""),
            Err(end) => end,
        }
    }

    async fn drive(&mut self, ws: &mut WebSocketStream<Conn>, id: &str) -> Flow {
        let session = Session {
            stream: id.to_owned(),
            answer: self.spec.answer(),
            binary: self.spec.binary,
            server_ping_ms: self.spec.server_ping_ms,
        };
        self.send_text(ws, &WsText::Session(session)).await?;
        if self.spec.client_ping_ms > 0 {
            self.next_ping = Some(Instant::now() + Duration::from_millis(self.spec.client_ping_ms));
        }
        self.start_turn(ws).await?;
        loop {
            let phase_timer = match self.phase {
                Phase::Idle { until } | Phase::Holding { until } => Some(until),
                Phase::Answering { .. } | Phase::Syncing | Phase::Closing => None,
            };
            let wake = [phase_timer, self.next_ping, self.next_binary].into_iter().flatten().fold(self.run.deadline, Instant::min);
            tokio::select! {
                message = ws.next() => match message {
                    None => return self.ended_without_error(),
                    Some(Err(err)) => return Err(self.ws_error(&err)),
                    Some(Ok(message)) => {
                        if self.on_message(ws, message).await? {
                            return Ok(());
                        }
                    }
                },
                () = tokio::time::sleep_until(wake) => self.on_timer(ws).await?,
            }
        }
    }

    fn ended_without_error(&self) -> Flow {
        match self.phase {
            Phase::Closing => Ok(()),
            _ => Err(StreamEnd::new(Outcome::Truncated, format!("收到 {} 个事件之后会话结束了，没有关闭握手", self.events.count()))),
        }
    }

    fn ws_error(&self, err: &WsError) -> StreamEnd {
        let context = format!("收到 {} 个事件之后", self.events.count());
        match err {
            WsError::Io(io) => StreamEnd::broken(io, &context),
            WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
                StreamEnd::new(Outcome::Truncated, format!("{context}连接正常关闭了（FIN），没有 WebSocket 的关闭握手"))
            }
            WsError::ConnectionClosed | WsError::AlreadyClosed if matches!(self.phase, Phase::Closing) => {
                StreamEnd::new(Outcome::Complete, "")
            }
            other => StreamEnd::new(Outcome::Error, format!("{context}：{other}")),
        }
    }

    async fn send(&mut self, ws: &mut WebSocketStream<Conn>, message: Message) -> Flow {
        self.tally.bytes_up += u64::try_from(message.len()).unwrap_or(u64::MAX);
        ws.send(message).await.map_err(|err| self.ws_error(&err))
    }

    async fn send_text(&mut self, ws: &mut WebSocketStream<Conn>, text: &WsText) -> Flow {
        let json = serde_json::to_string(text).expect("消息总能编成 JSON");
        self.send(ws, Message::text(json)).await
    }

    async fn start_turn(&mut self, ws: &mut WebSocketStream<Conn>) -> Flow {
        let prompt_bytes = self.spec.prompt_bytes.for_stream(self.stream_no * 1000 + u64::from(self.turn));
        let prompt = prompt(self.stream_no * 1000 + u64::from(self.turn), prompt_bytes);
        let turn = WsText::Turn { turn: self.turn, prompt_hash: hex(Fnv::of(prompt.as_bytes())), prompt };
        self.send_text(ws, &turn).await?;
        self.tally.new_answer();
        self.phase = Phase::Answering { sent: Instant::now(), received: 0, notes: 0 };
        if self.spec.client_binary_ms > 0 {
            self.next_binary = Some(Instant::now() + Duration::from_millis(self.spec.client_binary_ms));
        }
        Ok(())
    }

    fn corrupt(&self, detail: impl Into<String>) -> StreamEnd {
        StreamEnd::new(Outcome::Corrupt, format!("第 {} 轮：{}", self.turn, detail.into()))
    }

    /// 处理上游的一条消息。返回 `true` 表示会话正常结束了。
    async fn on_message(&mut self, ws: &mut WebSocketStream<Conn>, message: Message) -> Flow<bool> {
        self.tally.bytes_down += u64::try_from(message.len()).unwrap_or(u64::MAX);
        match message {
            Message::Text(text) => {
                let parsed: WsText = serde_json::from_str(&text).map_err(|err| self.corrupt(format!("无法解析上游消息：{err}")))?;
                self.on_text(ws, parsed).await?;
            }
            Message::Binary(frame) => {
                let (stamp, payload) = parse_binary_frame(&frame).ok_or_else(|| self.corrupt("二进制帧比头还短"))?;
                self.on_event(ws, stamp, payload).await?;
            }
            Message::Pong(payload) => {
                if let Ok(bytes) = <[u8; 8]>::try_from(&payload[..]) {
                    let sent = Duration::from_micros(u64::from_le_bytes(bytes));
                    self.tally.ping(Instant::now().saturating_duration_since(self.run.start).saturating_sub(sent));
                }
            }
            // 上游的 ping 由库自动回 pong。
            Message::Ping(_) | Message::Frame(_) => {}
            Message::Close(_) => {
                // 关闭握手完成，会话就算正常结束了；之后 TCP 怎么断不再要紧（按 RFC 6455 由服务端先断）。
                return match self.phase {
                    Phase::Closing => Ok(true),
                    _ => Err(StreamEnd::new(
                        Outcome::Truncated,
                        format!("收到 {} 个事件之后上游发来关闭帧，回答还没完", self.events.count()),
                    )),
                };
            }
        }
        Ok(false)
    }

    async fn on_text(&mut self, ws: &mut WebSocketStream<Conn>, text: WsText) -> Flow {
        match text {
            WsText::Delta { turn, seq, t, h, delta } => {
                if turn != self.turn {
                    return Err(self.corrupt(format!("收到了第 {turn} 轮的事件")));
                }
                let stamp = Stamp { seq, t_ns: t, hash: parse_hex(&h).unwrap_or_default() };
                self.on_event(ws, stamp, delta.as_bytes()).await
            }
            WsText::TurnDone { turn, events } => {
                let Phase::Answering { received, .. } = self.phase else {
                    return Err(self.corrupt("不在回答中却收到了 turn_done"));
                };
                if turn != self.turn || events != u64::from(self.spec.tokens) || received != self.spec.tokens {
                    return Err(self.corrupt(format!(
                        "turn_done 说第 {turn} 轮发了 {events} 个事件，这一轮请求 {} 个、收到 {received} 个",
                        self.spec.tokens
                    )));
                }
                self.next_binary = None;
                self.phase = Phase::Syncing;
                self.send_text(ws, &WsText::Sync).await
            }
            WsText::Synced { notes, notes_hash, binary, binary_hash, pongs: _ } => {
                if !matches!(self.phase, Phase::Syncing) {
                    return Err(self.corrupt("没有发 sync 却收到了 synced"));
                }
                let notes_ok = notes == self.notes.count() && parse_hex(&notes_hash) == Some(self.notes.hash());
                let binary_ok = binary == self.binary.count() && parse_hex(&binary_hash) == Some(self.binary.hash());
                if !(notes_ok && binary_ok) {
                    return Err(self.corrupt(format!(
                        "上游验过的客户端消息 {notes} 条、二进制帧 {binary} 个，发出的是 {} 条、{} 个（或者累积哈希不同）",
                        self.notes.count(),
                        self.binary.count()
                    )));
                }
                self.turn += 1;
                if self.turn < self.spec.turns {
                    self.phase = Phase::Idle { until: Instant::now() + Duration::from_millis(self.spec.idle_ms) };
                    return Ok(());
                }
                // 发了关闭帧之后什么都不能再发，ping 和二进制帧的定时器都停掉。
                self.phase = Phase::Closing;
                self.next_ping = None;
                self.next_binary = None;
                ws.close(None).await.map_err(|err| self.ws_error(&err))
            }
            WsText::Error { detail } => Err(self.corrupt(format!("上游说：{detail}"))),
            other => Err(self.corrupt(format!("上游不该发这种消息：{other:?}"))),
        }
    }

    /// 上游的一个事件（文本或者二进制帧）。
    async fn on_event(&mut self, ws: &mut WebSocketStream<Conn>, stamp: Stamp, payload: &[u8]) -> Flow {
        let Phase::Answering { sent, received, notes } = self.phase else {
            return Err(self.corrupt(format!("不在回答中却收到了第 {} 个事件", stamp.seq)));
        };
        self.events.check(stamp, payload).map_err(|err| self.corrupt(err.to_string()))?;
        let recv = Instant::now();
        let recv_wall = now_ns();
        if received == 0 {
            self.tally.ttft.push(recv.saturating_duration_since(sent));
            self.tally.first_token_lag.push(Duration::from_nanos(recv_wall.saturating_sub(stamp.t_ns)));
        }
        self.tally.event(self.run, self.group, recv, recv_wall, stamp.t_ns);
        let received = received + 1;
        self.phase = Phase::Answering { sent, received, notes };
        if self.spec.end == End::Stall && self.events.count() == u64::from(self.spec.end_after) {
            self.next_binary = None;
            self.phase = Phase::Holding { until: Instant::now() + Duration::from_secs_f64(self.spec.hold_s) };
            return Ok(());
        }
        // 第 k 条插话在这一轮收到 (k+1)/(n+1) 的事件时发出，均匀地落在回答中间。
        let due = u64::from(notes + 1) * u64::from(self.spec.tokens) / u64::from(self.spec.client_msgs + 1);
        if notes < self.spec.client_msgs && u64::from(received) >= due {
            let text = filler(self.notes.count(), 64);
            let stamp = self.notes.seal(now_ns(), text.as_bytes());
            self.phase = Phase::Answering { sent, received, notes: notes + 1 };
            self.send_text(ws, &WsText::Note { seq: stamp.seq, t: stamp.t_ns, h: hex(stamp.hash), text }).await?;
        }
        Ok(())
    }

    async fn on_timer(&mut self, ws: &mut WebSocketStream<Conn>) -> Flow {
        let now = Instant::now();
        if now >= self.run.deadline {
            return Err(StreamEnd::new(Outcome::Timeout, format!("到时限时在第 {} 轮，收到了 {} 个事件", self.turn, self.events.count())));
        }
        if self.next_ping.is_some_and(|at| at <= now) {
            let stamp = u64::try_from(now.saturating_duration_since(self.run.start).as_micros()).unwrap_or(u64::MAX);
            self.send(ws, Message::Ping(stamp.to_le_bytes().to_vec().into())).await?;
            self.next_ping = Some(now + Duration::from_millis(self.spec.client_ping_ms));
        }
        if let Some(at) = self.next_binary
            && at <= now
        {
            let bytes = usize::try_from(self.spec.client_binary_bytes).expect("u32 放得进 usize");
            let frame = binary_frame(&mut self.binary, bytes);
            self.send(ws, Message::binary(frame)).await?;
            // 按计划的节拍排下一个，不按实际发出的时刻，免得一次发得慢就把节拍整体推后。
            self.next_binary = Some(at + Duration::from_millis(self.spec.client_binary_ms));
        }
        match self.phase {
            Phase::Idle { until } if until <= now => self.start_turn(ws).await,
            Phase::Holding { until } if until <= now => Err(StreamEnd::new(Outcome::Stalled, "")),
            Phase::Idle { .. } | Phase::Holding { .. } | Phase::Answering { .. } | Phase::Syncing | Phase::Closing => Ok(()),
        }
    }
}
