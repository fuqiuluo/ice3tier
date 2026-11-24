//! 每条流共用的部分：运行的上下文、建连（代理和 TLS）、一条流的计时和逐事件的测量、流结束时记账。

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::ServerName;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::scenario::{GroupSpec, Outcome, Scenario};
use super::stats::{Dist, StallSpan};
use crate::net::Broken;
use crate::proxy::{Proxy, ProxyError};

/// 上游在哪里、怎么连。
pub struct Target {
    pub host: String,
    pub port: u16,
    /// `Host` 头里写的东西。
    pub authority: String,
    pub tls: Option<(TlsConnector, ServerName<'static>)>,
}

/// 运行中随时在变的计数，进度行和峰值用它。
#[derive(Default)]
pub struct Live {
    pub active: AtomicU64,
    pub started: AtomicU64,
    pub finished: AtomicU64,
    pub events: AtomicU64,
}

/// 一组流的测量结果。流结束时（和每攒够一批样本时）并进来。
#[derive(Default)]
pub struct GroupStats {
    pub connect: Dist,
    pub tls: Dist,
    pub first_byte: Dist,
    pub upload: Dist,
    pub ttft: Dist,
    pub first_token_lag: Dist,
    pub gap: Dist,
    pub gap_excess: Dist,
    pub event_delay: Dist,
    pub ping_rtt: Dist,
    pub ended_at: Dist,
    pub stalls: u64,
    pub events: u64,
    pub keepalives: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub outcomes: BTreeMap<Outcome, u64>,
    pub passed: u64,
    pub failed: u64,
    pub failures: Vec<Failure>,
}

/// 一条没有按期望结束的流。报告里每组最多列这么多条：再多也只是重复。
pub const MAX_FAILURES: usize = 40;

#[derive(Clone, Debug, Serialize)]
pub struct Failure {
    pub stream: String,
    pub expected: Outcome,
    pub outcome: Outcome,
    pub detail: String,
    pub events: u64,
    /// 从运行开始算，秒。
    pub started_s: f64,
    pub ended_s: f64,
    /// 结束时的墙上时钟（Unix 毫秒），用来对照节点日志里同一时刻发生了什么。
    pub ended_unix_ms: u64,
}

/// 一次运行的上下文，所有流共享。
pub struct Run {
    pub scenario: Scenario,
    pub proxy: Proxy,
    pub target: Target,
    pub start: Instant,
    pub deadline: Instant,
    pub stall: Duration,
    pub live: Live,
    pub groups: Vec<Mutex<GroupStats>>,
    pub stalls: Mutex<Vec<StallSpan>>,
}

/// 卡顿的记录最多留这么多条，够算出停顿的规律，又不会在很差的链路上把内存吃掉。
const MAX_STALL_SPANS: usize = 200_000;

impl Run {
    fn since_start_us(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.start).as_micros()).unwrap_or(u64::MAX)
    }
}

/// 一条流结束的样子和原因。
#[derive(Debug)]
pub struct StreamEnd {
    pub outcome: Outcome,
    pub detail: String,
}

impl StreamEnd {
    pub fn new(outcome: Outcome, detail: impl Into<String>) -> Self {
        Self { outcome, detail: detail.into() }
    }

    /// 读写出错时按连接是怎么断的归类。
    pub fn broken(err: &io::Error, context: &str) -> Self {
        let outcome = match Broken::from(err) {
            Broken::Reset => Outcome::Reset,
            Broken::Eof => Outcome::Truncated,
            Broken::Other => Outcome::Error,
        };
        Self::new(outcome, format!("{context}：{err}"))
    }
}

/// 明文或者 TLS 的连接，读写时不用区分。
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// 一条流里逐事件的测量，攒一批再并进组里，免得每个事件都抢一次锁。
pub struct Tally {
    pub stream: u32,
    pub connect: Option<Duration>,
    pub tls: Option<Duration>,
    pub first_byte: Option<Duration>,
    pub upload: Option<Duration>,
    pub ttft: Vec<Duration>,
    pub first_token_lag: Vec<Duration>,
    pub events: u64,
    pub keepalives: u64,
    pub stalls: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    gap: Vec<u64>,
    excess: Vec<u64>,
    delay: Vec<u64>,
    ping_rtt: Vec<u64>,
    spans: Vec<StallSpan>,
    /// 上一个事件收到的时刻和上游写它的时刻。新的一段回答开始时清掉，段与段之间的空闲不算间隔。
    last: Option<(Instant, u64)>,
}

/// 攒够这么多样本就并一次。
const FLUSH_AT: usize = 512;

impl Tally {
    pub fn new(stream: u32) -> Self {
        Self {
            stream,
            connect: None,
            tls: None,
            first_byte: None,
            upload: None,
            ttft: Vec::new(),
            first_token_lag: Vec::new(),
            events: 0,
            keepalives: 0,
            stalls: 0,
            bytes_up: 0,
            bytes_down: 0,
            gap: Vec::new(),
            excess: Vec::new(),
            delay: Vec::new(),
            ping_rtt: Vec::new(),
            spans: Vec::new(),
            last: None,
        }
    }

    /// 新的一段回答开始了（WebSocket 的下一轮）。
    pub fn new_answer(&mut self) {
        self.last = None;
    }

    /// 收到一个事件：`recv` 是读到它的时刻，`recv_wall` 是同一时刻的墙上时钟，`t_ns` 是上游写它的时刻。
    pub fn event(&mut self, run: &Run, group: usize, recv: Instant, recv_wall: u64, t_ns: u64) {
        self.events += 1;
        self.delay.push(recv_wall.saturating_sub(t_ns) / 1000);
        if let Some((last_recv, last_t)) = self.last {
            let gap = recv.saturating_duration_since(last_recv);
            let paced = Duration::from_nanos(t_ns.saturating_sub(last_t));
            let excess = gap.saturating_sub(paced);
            self.gap.push(u64::try_from(gap.as_micros()).unwrap_or(u64::MAX));
            self.excess.push(u64::try_from(excess.as_micros()).unwrap_or(u64::MAX));
            if excess > run.stall {
                self.stalls += 1;
                let end_us = run.since_start_us(recv);
                let start_us = end_us.saturating_sub(u64::try_from(excess.as_micros()).unwrap_or(u64::MAX));
                self.spans.push(StallSpan { start_us, end_us, stream: self.stream });
            }
        }
        self.last = Some((recv, t_ns));
        run.live.events.fetch_add(1, Ordering::Relaxed);
        if self.delay.len() >= FLUSH_AT {
            self.flush(run, group);
        }
    }

    pub fn ping(&mut self, rtt: Duration) {
        self.ping_rtt.push(u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX));
    }

    /// 把攒着的逐事件样本并进组里。
    pub fn flush(&mut self, run: &Run, group: usize) {
        let mut stats = run.groups[group].lock().expect("组统计的锁不会中毒：持锁时不会 panic");
        for &us in &self.gap {
            stats.gap.record_us(us);
        }
        for &us in &self.excess {
            stats.gap_excess.record_us(us);
        }
        for &us in &self.delay {
            stats.event_delay.record_us(us);
        }
        for &us in &self.ping_rtt {
            stats.ping_rtt.record_us(us);
        }
        drop(stats);
        self.gap.clear();
        self.excess.clear();
        self.delay.clear();
        self.ping_rtt.clear();
        if !self.spans.is_empty() {
            let mut spans = run.stalls.lock().expect("卡顿记录的锁不会中毒：持锁时不会 panic");
            let room = MAX_STALL_SPANS.saturating_sub(spans.len());
            spans.extend(self.spans.drain(..).take(room));
        }
    }
}

/// 建一条到上游的连接：经代理（或者直连），需要时做 TLS 握手。计时记在 `tally` 里。
pub async fn open(run: &Run, tally: &mut Tally) -> Result<Conn, StreamEnd> {
    let begin = Instant::now();
    let tcp = run.proxy.connect(&run.target.host, run.target.port).await.map_err(|err| match err {
        ProxyError::Refused(detail) => StreamEnd::new(Outcome::ProxyRefused, detail),
        ProxyError::Connect(err) => StreamEnd::new(Outcome::ConnectFailed, format!("连接失败：{err}")),
        ProxyError::Io(err) => StreamEnd::new(Outcome::ConnectFailed, format!("和代理握手时出错：{err}")),
    })?;
    tally.connect = Some(begin.elapsed());
    let Some((connector, name)) = &run.target.tls else {
        return Ok(Conn::Plain(tcp));
    };
    let handshake = Instant::now();
    let tls = connector.connect(name.clone(), tcp).await.map_err(|err| StreamEnd::new(Outcome::TlsFailed, format!("TLS 握手：{err}")))?;
    tally.tls = Some(handshake.elapsed());
    Ok(Conn::Tls(Box::new(tls)))
}

/// 流结束：按期望判定，把这条流的测量并进组里。
pub fn finish(run: &Run, group: usize, spec: &GroupSpec, id: String, started: Instant, end: StreamEnd, mut tally: Tally) {
    tally.flush(run, group);
    let now = Instant::now();
    let expected = spec.expected();
    let mut stats = run.groups[group].lock().expect("组统计的锁不会中毒：持锁时不会 panic");
    let stats = &mut *stats;
    for (dist, value) in [
        (&mut stats.connect, tally.connect),
        (&mut stats.tls, tally.tls),
        (&mut stats.first_byte, tally.first_byte),
        (&mut stats.upload, tally.upload),
    ] {
        if let Some(value) = value {
            dist.record(value);
        }
    }
    for &value in &tally.ttft {
        stats.ttft.record(value);
    }
    for &value in &tally.first_token_lag {
        stats.first_token_lag.record(value);
    }
    stats.ended_at.record(now.saturating_duration_since(run.start));
    stats.stalls += tally.stalls;
    stats.events += tally.events;
    stats.keepalives += tally.keepalives;
    stats.bytes_up += tally.bytes_up;
    stats.bytes_down += tally.bytes_down;
    *stats.outcomes.entry(end.outcome).or_default() += 1;
    if end.outcome == expected {
        stats.passed += 1;
        return;
    }
    stats.failed += 1;
    if stats.failures.len() < MAX_FAILURES {
        let seconds = |at: Instant| at.saturating_duration_since(run.start).as_secs_f64();
        let unix_ms = crate::wire::now_ns() / 1_000_000;
        stats.failures.push(Failure {
            stream: id,
            expected,
            outcome: end.outcome,
            detail: end.detail,
            events: tally.events,
            started_s: seconds(started),
            ended_s: seconds(now),
            ended_unix_ms: unix_ms,
        });
    }
}
