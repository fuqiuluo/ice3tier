//! 负载：在一条双向字节流上跑的几种请求，以及客户端一侧的驱动。与用什么传输无关。
//!
//! 所有请求都不依赖"对方关闭写方向"，因为 KCP 没有半关闭。
//! 大流量测试按时间截止而不是等数据传完：慢链路上发送方的缓冲里可能积着几十秒的数据，
//! 等它传完测的就不是这段时间的吞吐了。

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use clap::ValueEnum;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinSet;

use crate::stats::{LatencyRecorder, LatencySummary, now_ns};
use crate::transport::Connector;

const REQUEST_LEN: usize = 40;
const CHUNK_LEN: usize = 64 * 1024;
const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
/// 回显和 token 消息的开头 8 字节是发送时刻。
const STAMP_LEN: usize = 8;

static ZEROS: [u8; CHUNK_LEN] = [0; CHUNK_LEN];

pub struct Duplex {
    pub rd: Pin<Box<dyn AsyncRead + Send>>,
    pub wr: Pin<Box<dyn AsyncWrite + Send>>,
}

/// 一次 LLM 流式请求的流量模型：先上传请求体，等待首 token 延迟后，按固定间隔接收一系列小消息。
#[derive(Clone, Copy, Debug)]
pub struct LlmShape {
    pub body_len: u64,
    /// 服务端收完请求体之后等多久才发第一个 token。
    pub ttft_ms: u32,
    pub tokens: u32,
    pub interval_ms: u32,
    pub token_size: u32,
    /// 发完这么多个 token 之后静默一次；0 表示不静默。
    pub silent_after: u32,
    pub silent_ms: u32,
}

#[derive(Clone, Copy, Debug)]
enum Request {
    /// 客户端一直写。服务端从收到第一个字节起计时，到点回一份收据。
    Upload {
        secs: u32,
        warmup_secs: u32,
    },
    /// 服务端一直写，客户端读到自己的截止时间为止。
    Download,
    Echo {
        msg_size: u32,
    },
    Llm(LlmShape),
}

impl Request {
    fn encode(self) -> [u8; REQUEST_LEN] {
        let pair = |hi: u32, lo: u32| (u64::from(hi) << 32) | u64::from(lo);
        let (op, words): (u8, [u64; 4]) = match self {
            Self::Upload { secs, warmup_secs } => (1, [u64::from(secs), u64::from(warmup_secs), 0, 0]),
            Self::Download => (2, [0; 4]),
            Self::Echo { msg_size } => (3, [u64::from(msg_size), 0, 0, 0]),
            Self::Llm(shape) => (
                4,
                [
                    shape.body_len,
                    pair(shape.ttft_ms, shape.tokens),
                    pair(shape.interval_ms, shape.token_size),
                    pair(shape.silent_after, shape.silent_ms),
                ],
            ),
        };
        let mut out = [0; REQUEST_LEN];
        out[0] = op;
        for (slot, word) in out[8..].as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *slot = word.to_be_bytes();
        }
        out
    }

    fn decode(raw: &[u8; REQUEST_LEN]) -> anyhow::Result<Self> {
        let word = |index: usize| {
            let start = 8 + index * 8;
            u64::from_be_bytes(raw[start..start + 8].try_into().expect("切片长度固定为 8"))
        };
        // 高 32 位和低 32 位各装一个 u32，拆开时截断正是想要的。
        #[expect(clippy::cast_possible_truncation, reason = "故意取 u64 的高低各 32 位")]
        let halves = |index: usize| ((word(index) >> 32) as u32, word(index) as u32);
        let narrow = |index: usize| u32::try_from(word(index)).context("请求里的数值超出 u32");
        Ok(match raw[0] {
            1 => Self::Upload { secs: narrow(0)?, warmup_secs: narrow(1)? },
            2 => Self::Download,
            3 => Self::Echo { msg_size: narrow(0)? },
            4 => {
                let ((ttft_ms, tokens), (interval_ms, token_size), (silent_after, silent_ms)) = (halves(1), halves(2), halves(3));
                Self::Llm(LlmShape { body_len: word(0), ttft_ms, tokens, interval_ms, token_size, silent_after, silent_ms })
            }
            other => bail!("未知的请求类型 {other}"),
        })
    }
}

fn stamp(message: &mut [u8]) {
    message[..STAMP_LEN].copy_from_slice(&now_ns().to_be_bytes());
}

fn stamp_age_ns(message: &[u8]) -> u64 {
    let sent = u64::from_be_bytes(message[..STAMP_LEN].try_into().expect("切片长度固定为 8"));
    now_ns().saturating_sub(sent)
}

fn message_len(requested: u32) -> usize {
    (requested as usize).max(STAMP_LEN)
}

/// 服务端：处理一条流上的一个请求。
pub async fn serve(mut stream: Duplex) -> anyhow::Result<()> {
    let mut raw = [0; REQUEST_LEN];
    stream.rd.read_exact(&mut raw).await?;
    match Request::decode(&raw)? {
        Request::Upload { secs, warmup_secs } => serve_upload(&mut stream, secs, warmup_secs).await,
        Request::Download => serve_download(&mut stream).await,
        Request::Echo { msg_size } => serve_echo(&mut stream, msg_size).await,
        Request::Llm(shape) => serve_llm(&mut stream, shape).await,
    }
}

async fn serve_upload(stream: &mut Duplex, secs: u32, warmup_secs: u32) -> anyhow::Result<()> {
    let mut sink = vec![0; CHUNK_LEN];
    let first = stream.rd.read(&mut sink).await?;
    if first == 0 {
        return Ok(());
    }
    let started = Instant::now();
    let warm_at = started + Duration::from_secs(u64::from(warmup_secs));
    let end_at = started + Duration::from_secs(u64::from(secs));
    let mut total = first as u64;
    let mut at_warmup = None;
    loop {
        let now = Instant::now();
        if at_warmup.is_none() && now >= warm_at {
            at_warmup = Some(total);
        }
        if now >= end_at {
            break;
        }
        match tokio::time::timeout_at(end_at.into(), stream.rd.read(&mut sink)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(got)) => total += got as u64,
            Ok(Err(err)) => return Err(err.into()),
        }
    }
    let steady = total - at_warmup.unwrap_or(total);
    for value in [total, steady, duration_ns(started.elapsed())] {
        stream.wr.write_u64(value).await?;
    }
    stream.wr.flush().await?;
    // 客户端收到收据后会断开；在那之前把它还在发的数据读掉，免得它被流控卡住。
    while matches!(stream.rd.read(&mut sink).await, Ok(got) if got > 0) {}
    Ok(())
}

async fn serve_download(stream: &mut Duplex) -> anyhow::Result<()> {
    // 没有客户端会测这么久；只是防止对端消失后这里永远写下去。
    let give_up = Instant::now() + Duration::from_secs(900);
    while Instant::now() < give_up {
        stream.wr.write_all(&ZEROS).await?;
    }
    Ok(())
}

async fn serve_echo(stream: &mut Duplex, msg_size: u32) -> anyhow::Result<()> {
    let mut message = vec![0; message_len(msg_size)];
    // 对方停止发送后读会失败，那就是正常结束。
    while stream.rd.read_exact(&mut message).await.is_ok() {
        stream.wr.write_all(&message).await?;
        stream.wr.flush().await?;
    }
    Ok(())
}

async fn serve_llm(stream: &mut Duplex, shape: LlmShape) -> anyhow::Result<()> {
    let mut body = (&mut stream.rd).take(shape.body_len);
    let received = tokio::io::copy(&mut body, &mut tokio::io::sink()).await?;
    if received != shape.body_len {
        bail!("请求体只收到 {received} / {} 字节", shape.body_len);
    }
    tokio::time::sleep(Duration::from_millis(u64::from(shape.ttft_ms))).await;

    let mut token = vec![0; message_len(shape.token_size)];
    for index in 0..shape.tokens {
        if shape.silent_after > 0 && index == shape.silent_after {
            tokio::time::sleep(Duration::from_millis(u64::from(shape.silent_ms))).await;
        }
        stamp(&mut token);
        stream.wr.write_all(&token).await?;
        stream.wr.flush().await?;
        tokio::time::sleep(Duration::from_millis(u64::from(shape.interval_ms))).await;
    }
    stream.wr.shutdown().await?;
    Ok(())
}

async fn send_request(stream: &mut Duplex, request: Request) -> anyhow::Result<()> {
    stream.wr.write_all(&request.encode()).await?;
    stream.wr.flush().await?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Up,
    Down,
}

#[derive(Clone, Copy, Debug)]
pub struct BulkOpts {
    pub streams: usize,
    pub secs: u32,
    /// 算稳态吞吐时跳过开头这么多秒。
    pub warmup_secs: u32,
    pub direction: Direction,
    pub keep_series: bool,
}

#[derive(Debug, Serialize)]
pub struct BulkReport {
    direction: Direction,
    streams: usize,
    bytes: u64,
    /// 跳过预热之后的平均值。下行在客户端量，上行在服务端量。
    mbps: f64,
    /// 下行时，传输开始之后最长的一段"一个字节都没收到"的时间。
    longest_stall_ms: u64,
    /// 每 100ms 一个点的吞吐，只在要求时输出。
    #[serde(skip_serializing_if = "Option::is_none")]
    series_mbps: Option<Vec<f64>>,
}

pub async fn run_bulk(connector: &Connector, opts: BulkOpts) -> anyhow::Result<BulkReport> {
    match opts.direction {
        Direction::Down => run_download(connector, opts).await,
        Direction::Up => run_upload(connector, opts).await,
    }
}

async fn run_download(connector: &Connector, opts: BulkOpts) -> anyhow::Result<BulkReport> {
    let received = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let sampler = tokio::spawn(sample_counter(Arc::clone(&received), Arc::clone(&done)));
    let deadline = Instant::now() + Duration::from_secs(u64::from(opts.secs));

    let mut tasks = JoinSet::new();
    for _ in 0..opts.streams {
        let mut stream = connector.open().await?;
        let received = Arc::clone(&received);
        tasks.spawn(async move {
            send_request(&mut stream, Request::Download).await?;
            let mut sink = vec![0; CHUNK_LEN];
            loop {
                // 数据一直读得到时，下面的 timeout 永远先看到"读好了"，轮不到它检查时间，
                // 所以截止时间要自己再看一次。
                if Instant::now() >= deadline {
                    return anyhow::Ok(());
                }
                match tokio::time::timeout_at(deadline.into(), stream.rd.read(&mut sink)).await {
                    Err(_deadline_reached) => return anyhow::Ok(()),
                    Ok(Ok(0)) => bail!("服务端提前关闭了下载的流"),
                    Ok(Ok(got)) => received.fetch_add(got as u64, Ordering::Relaxed),
                    Ok(Err(err)) => return Err(err.into()),
                };
            }
        });
    }
    let outcome = join_all(tasks).await;
    done.store(true, Ordering::Relaxed);
    let samples = sampler.await.context("采样任务异常退出")?;
    outcome?;

    let series = Series::new(&samples);
    Ok(BulkReport {
        direction: Direction::Down,
        streams: opts.streams,
        bytes: received.load(Ordering::Relaxed),
        mbps: series.mean_mbps(opts.warmup_secs, opts.secs),
        longest_stall_ms: series.longest_stall_ms(),
        series_mbps: opts.keep_series.then(|| series.mbps()),
    })
}

async fn run_upload(connector: &Connector, opts: BulkOpts) -> anyhow::Result<BulkReport> {
    struct Receipt {
        total: u64,
        steady: u64,
    }

    let request = Request::Upload { secs: opts.secs, warmup_secs: opts.warmup_secs };
    let mut tasks = JoinSet::new();
    for _ in 0..opts.streams {
        let mut stream = connector.open().await?;
        tasks.spawn(async move {
            send_request(&mut stream, request).await?;
            let Duplex { mut rd, mut wr } = stream;
            let keep_writing = async {
                loop {
                    wr.write_all(&ZEROS).await?;
                }
            };
            let receipt = async {
                let total = rd.read_u64().await?;
                let steady = rd.read_u64().await?;
                let _elapsed_ns = rd.read_u64().await?;
                anyhow::Ok(Receipt { total, steady })
            };
            tokio::select! {
                receipt = receipt => receipt,
                failed = keep_writing => failed,
            }
        });
    }
    let mut receipts = Vec::with_capacity(opts.streams);
    while let Some(joined) = tasks.join_next().await {
        receipts.push(joined.context("上传任务异常退出")??);
    }

    let steady: u64 = receipts.iter().map(|receipt| receipt.steady).sum();
    let steady_secs = f64::from(opts.secs.saturating_sub(opts.warmup_secs).max(1));
    Ok(BulkReport {
        direction: Direction::Up,
        streams: opts.streams,
        bytes: receipts.iter().map(|receipt| receipt.total).sum(),
        mbps: steady as f64 * 8.0 / 1e6 / steady_secs,
        longest_stall_ms: 0,
        series_mbps: None,
    })
}

async fn join_all(mut tasks: JoinSet<anyhow::Result<()>>) -> anyhow::Result<()> {
    while let Some(joined) = tasks.join_next().await {
        joined.context("负载任务异常退出")??;
    }
    Ok(())
}

/// 每 100ms 记一次累计字节数，直到 `done` 置位。
async fn sample_counter(counter: Arc<AtomicU64>, done: Arc<AtomicBool>) -> Vec<u64> {
    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut samples = Vec::new();
    while !done.load(Ordering::Relaxed) {
        ticker.tick().await;
        samples.push(counter.load(Ordering::Relaxed));
    }
    samples
}

/// 累计字节数的采样序列，相邻两点相隔 100ms。
struct Series<'a> {
    cumulative: &'a [u64],
}

impl<'a> Series<'a> {
    const PER_SEC: usize = 10;

    fn new(cumulative: &'a [u64]) -> Self {
        Self { cumulative }
    }

    fn deltas(&self) -> impl Iterator<Item = u64> + '_ {
        self.cumulative.windows(2).map(|pair| pair[1] - pair[0])
    }

    fn mbps(&self) -> Vec<f64> {
        self.deltas().map(|bytes| bytes as f64 * 8.0 / 1e6 * Self::PER_SEC as f64).collect()
    }

    /// 第 `from_secs` 秒到第 `to_secs` 秒之间的平均吞吐。
    fn mean_mbps(&self, from_secs: u32, to_secs: u32) -> f64 {
        let Some(last_index) = self.cumulative.len().checked_sub(1) else { return 0.0 };
        let from = (from_secs as usize * Self::PER_SEC).min(last_index);
        let to = (to_secs as usize * Self::PER_SEC).min(last_index);
        if to <= from {
            return 0.0;
        }
        let bytes = self.cumulative[to] - self.cumulative[from];
        bytes as f64 * 8.0 / 1e6 / ((to - from) as f64 / Self::PER_SEC as f64)
    }

    /// 第一个字节到达之后、最后一个字节到达之前，最长的一段没有任何数据的时间。
    fn longest_stall_ms(&self) -> u64 {
        let deltas: Vec<u64> = self.deltas().collect();
        let Some(start) = deltas.iter().position(|&d| d > 0) else { return 0 };
        let end = deltas.iter().rposition(|&d| d > 0).unwrap_or(start);
        let (mut longest, mut current) = (0u64, 0u64);
        for &delta in &deltas[start..=end] {
            current = if delta == 0 { current + 1 } else { 0 };
            longest = longest.max(current);
        }
        longest * u64::try_from(SAMPLE_INTERVAL.as_millis()).unwrap_or(100)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EchoOpts {
    pub secs: u32,
    pub interval_ms: u32,
    pub msg_size: u32,
}

#[derive(Debug, Serialize)]
pub struct EchoReport {
    sent: u64,
    received: u64,
    /// 小消息一去一回的时间。
    rtt_ms: LatencySummary,
}

/// 按固定节拍发小消息，对端原样送回，量往返时间。模拟按键这类交互流量。
pub async fn run_echo(connector: &Connector, opts: EchoOpts) -> anyhow::Result<EchoReport> {
    let Duplex { mut rd, mut wr } = {
        let mut stream = connector.open().await?;
        send_request(&mut stream, Request::Echo { msg_size: opts.msg_size }).await?;
        stream
    };
    let len = message_len(opts.msg_size);
    let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
    let reader = tokio::spawn(async move {
        let mut recorder = LatencyRecorder::new();
        let mut message = vec![0; len];
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                read = rd.read_exact(&mut message) => {
                    if read.is_err() {
                        break;
                    }
                    recorder.record_ns(stamp_age_ns(&message));
                }
            }
        }
        recorder
    });

    let mut message = vec![0; len];
    let mut ticker = tokio::time::interval(Duration::from_millis(u64::from(opts.interval_ms.max(1))));
    let deadline = Instant::now() + Duration::from_secs(u64::from(opts.secs));
    let mut sent = 0u64;
    while Instant::now() < deadline {
        ticker.tick().await;
        stamp(&mut message);
        wr.write_all(&message).await?;
        wr.flush().await?;
        sent += 1;
    }
    // 给最后几条回显留出返回的时间，然后不再等。
    tokio::time::sleep(Duration::from_secs(2)).await;
    // 读取任务如果已经因为流断开而退出，发送会失败，这没有关系。
    stop.send(()).ok();
    let rtt_ms = reader.await.context("回显的读取任务异常退出")?.summary();
    Ok(EchoReport { sent, received: rtt_ms.count, rtt_ms })
}

/// 开一条流，发一条小消息，等它回来。返回从开流到收到回显的纳秒数。
pub async fn first_echo_ns(connector: &Connector) -> anyhow::Result<u64> {
    const MSG_SIZE: u32 = 64;
    let started = Instant::now();
    let mut stream = connector.open().await?;
    send_request(&mut stream, Request::Echo { msg_size: MSG_SIZE }).await?;
    let mut message = vec![0; message_len(MSG_SIZE)];
    stamp(&mut message);
    stream.wr.write_all(&message).await?;
    stream.wr.flush().await?;
    stream.rd.read_exact(&mut message).await.context("没有等到回显")?;
    Ok(duration_ns(started.elapsed()))
}

#[derive(Clone, Copy, Debug)]
pub struct LlmOpts {
    pub concurrency: usize,
    pub requests: usize,
    pub body_min: u64,
    pub body_max: u64,
    pub ttft_ms: u32,
    pub tokens: u32,
    pub interval_ms: u32,
    pub token_size: u32,
    /// 每隔这么多个请求有一个中途静默；0 表示都不静默。
    pub silent_every: usize,
    pub silent_after: u32,
    pub silent_ms: u32,
}

#[derive(Debug, Default, Serialize)]
pub struct LlmReport {
    ok: u64,
    failed: u64,
    silent_ok: u64,
    silent_failed: u64,
    wall_secs: f64,
    /// 从打开流到请求体全部写进传输层。
    upload_ms: LatencySummary,
    /// 从写完请求体到收到第一个 token，再扣掉服务端故意等待的时间。
    first_token_overhead_ms: LatencySummary,
    /// 每个 token 从服务端发出到客户端收到。只在两端共用时钟（本机测试）时有意义。
    token_delay_ms: LatencySummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_error: Option<String>,
}

/// 所有并发共用一份统计。延迟直方图每个有一百多 KB，每个并发各持有一份的话，
/// 几千个并发时测到的就是测试工具自己的内存了。
#[derive(Default)]
struct LlmTally {
    ok: u64,
    failed: u64,
    silent_ok: u64,
    silent_failed: u64,
    upload: LatencyRecorder,
    first_token: LatencyRecorder,
    token_delay: LatencyRecorder,
    first_error: Option<String>,
}

/// 一个请求跑下来量到的时间，请求结束时再并入总的统计。
#[derive(Default)]
struct RequestSamples {
    upload_ns: Option<u64>,
    first_token_ns: Option<u64>,
    token_delays_ns: Vec<u64>,
}

impl LlmTally {
    fn record(&mut self, silent: bool, outcome: anyhow::Result<()>, samples: &RequestSamples) {
        if let Some(ns) = samples.upload_ns {
            self.upload.record_ns(ns);
        }
        if let Some(ns) = samples.first_token_ns {
            self.first_token.record_ns(ns);
        }
        for &ns in &samples.token_delays_ns {
            self.token_delay.record_ns(ns);
        }
        match (outcome, silent) {
            (Ok(()), true) => self.silent_ok += 1,
            (Ok(()), false) => self.ok += 1,
            (Err(err), silent) => {
                if silent {
                    self.silent_failed += 1;
                } else {
                    self.failed += 1;
                }
                self.first_error.get_or_insert_with(|| format!("{err:#}"));
            }
        }
    }
}

/// 并发跑一批 LLM 形状的请求，全部在 `connector` 给出的连接上。
pub async fn run_llm(connector: &Arc<Connector>, opts: LlmOpts) -> anyhow::Result<LlmReport> {
    let next = Arc::new(AtomicUsize::new(0));
    let tally = Arc::new(Mutex::new(LlmTally::default()));
    let started = Instant::now();
    let mut workers = JoinSet::new();
    for _ in 0..opts.concurrency.max(1) {
        let (connector, next, tally) = (Arc::clone(connector), Arc::clone(&next), Arc::clone(&tally));
        workers.spawn(async move {
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= opts.requests {
                    return;
                }
                let silent = opts.silent_every > 0 && index % opts.silent_every == 0;
                let shape = LlmShape {
                    body_len: body_len_for(index, opts.body_min, opts.body_max),
                    ttft_ms: opts.ttft_ms,
                    tokens: opts.tokens,
                    interval_ms: opts.interval_ms,
                    token_size: opts.token_size,
                    silent_after: if silent { opts.silent_after } else { 0 },
                    silent_ms: opts.silent_ms,
                };
                let mut samples = RequestSamples::default();
                let outcome = one_llm_request(&connector, shape, &mut samples).await;
                tally.lock().expect("llm tally mutex poisoned").record(silent, outcome, &samples);
            }
        });
    }
    while let Some(joined) = workers.join_next().await {
        joined.context("LLM 负载任务异常退出")?;
    }
    let total = tally.lock().expect("llm tally mutex poisoned");
    Ok(LlmReport {
        ok: total.ok,
        failed: total.failed,
        silent_ok: total.silent_ok,
        silent_failed: total.silent_failed,
        wall_secs: started.elapsed().as_secs_f64(),
        upload_ms: total.upload.summary(),
        first_token_overhead_ms: total.first_token.summary(),
        token_delay_ms: total.token_delay.summary(),
        first_error: total.first_error.clone(),
    })
}

async fn one_llm_request(connector: &Connector, shape: LlmShape, samples: &mut RequestSamples) -> anyhow::Result<()> {
    let opened = Instant::now();
    let mut stream = connector.open().await?;
    send_request(&mut stream, Request::Llm(shape)).await?;
    let mut left = shape.body_len;
    while left > 0 {
        let piece = usize::try_from(left).map_or(CHUNK_LEN, |l| l.min(CHUNK_LEN));
        stream.wr.write_all(&ZEROS[..piece]).await?;
        left -= piece as u64;
    }
    stream.wr.flush().await?;
    let body_done = Instant::now();
    samples.upload_ns = Some(duration_ns(body_done - opened));

    let mut token = vec![0; message_len(shape.token_size)];
    samples.token_delays_ns.reserve(shape.tokens as usize);
    for index in 0..shape.tokens {
        stream.rd.read_exact(&mut token).await.with_context(|| format!("第 {index} 个 token 没收到"))?;
        if index == 0 {
            let waited = body_done.elapsed().saturating_sub(Duration::from_millis(u64::from(shape.ttft_ms)));
            samples.first_token_ns = Some(duration_ns(waited));
        }
        samples.token_delays_ns.push(stamp_age_ns(&token));
    }
    Ok(())
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// 第 `index` 个请求的请求体长度：在上下限之间，同样的参数每次跑出来都一样。
fn body_len_for(index: usize, min: u64, max: u64) -> u64 {
    if max <= min {
        return min;
    }
    // splitmix64 的一轮，足够把序号打散。
    let mut x = (index as u64).wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    min + (x ^ (x >> 31)) % (max - min + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llm_request_round_trips() {
        let shape = LlmShape {
            body_len: 1_048_576,
            ttft_ms: 800,
            tokens: 200,
            interval_ms: 30,
            token_size: 64,
            silent_after: 50,
            silent_ms: 120_000,
        };
        let Request::Llm(back) = Request::decode(&Request::Llm(shape).encode()).unwrap() else {
            panic!("解码出来的不是 LLM 请求");
        };
        assert_eq!(
            (back.body_len, back.ttft_ms, back.tokens, back.interval_ms),
            (shape.body_len, shape.ttft_ms, shape.tokens, shape.interval_ms)
        );
        assert_eq!((back.token_size, back.silent_after, back.silent_ms), (shape.token_size, shape.silent_after, shape.silent_ms));
    }

    #[test]
    fn series_reports_steady_rate_and_stall() {
        // 每 100ms 收 125000 字节 = 10 Mbit/s；中间有 300ms 没有数据。
        let mut cumulative = vec![0u64];
        for step in 0..30 {
            let stalled = (10..13).contains(&step);
            cumulative.push(cumulative.last().unwrap() + if stalled { 0 } else { 125_000 });
        }
        let series = Series::new(&cumulative);
        assert_eq!(series.longest_stall_ms(), 300);
        assert!((series.mean_mbps(2, 3) - 10.0).abs() < 1e-9);
    }

    #[test]
    fn body_len_stays_in_range_and_is_deterministic() {
        for index in 0..1000 {
            let len = body_len_for(index, 30_000, 1_000_000);
            assert!((30_000..=1_000_000).contains(&len));
            assert_eq!(len, body_len_for(index, 30_000, 1_000_000));
        }
    }
}
