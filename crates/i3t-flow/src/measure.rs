//! 测量流：主动测试量吞吐用的流。格式见 [`i3t_proto::flow::OpenMeasure`]。
//!
//! - 发起方用 [`measure`] 开一条测量流，量一个方向：[`MeasureMode::Sink`] 是自己发、对端收（上行），
//!   [`MeasureMode::Source`] 是对端发、自己收（下行）。要用共用的连接开（不经 ice3proxy）：量的是那条连接现在走的路。
//! - 接受方从 [`crate::serve`] 拿到 [`MeasureRequest`]（[`crate::Handler::handle_measure`]），先自己决定接不接（测试编号、时间窗、
//!   本机的开关），接的话调用 [`MeasureRequest::serve`]。接受方的上限（[`MeasureLimits`]）由它自己定，不管发起方要多少：
//!   字节数和时长到了就停，另有一个总的时限，发起方不发数据、不读数据都占不住它。
//! - 数据是全零的块。连接本身是加密的，量到的就是真实负载的吞吐。
//! - 速率计算排除起始预热阶段（[`WARM_UP`]）：连接启动初期速率仍在爬升，若计入该阶段，
//!   先测路径的结果会明显偏低，即使两条测试走的是同一路径。总字节数与总耗时仍按完整传输统计。

use std::time::{Duration, Instant};

use i3t_conn::{Connector, Priority, RecvStream, SendStream, StreamCode};
use i3t_proto::NodeId;
use i3t_proto::flow::{MeasureEnd, MeasureMode, MeasureSteady, MeasureSummary, OpenMeasure, Reason, Reply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time;

use crate::{FlowError, header};

/// 一次读写的块有多大。
const CHUNK: usize = 64 * 1024;
/// 测量结束后等待对端收尾（接收模式下接受方写回的汇总数据）的最长时间。
const SUMMARY_WAIT: Duration = Duration::from_secs(5);
/// 除了时长上限，接受方另外给流留的余量：建流、慢启动之前的空档、收尾。过了这个总时限一律重置。
const GRACE: Duration = Duration::from_secs(3);
/// 一次搬运开头多大一部分算起步：字节上限或者时长上限的四分之一，先到为止。
/// 往返 150 毫秒的路上爬到 100 Mbit/s 大约要 1 秒、4 MB，20 MB、5 秒的上限下四分之一正好盖住。
pub const WARM_UP: u32 = 4;

/// 接受方自己的上限。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasureLimits {
    pub bytes: u64,
    pub duration: Duration,
}

impl MeasureLimits {
    /// 发起方要的和接受方自己的上限里小的那个。
    #[must_use]
    pub fn within(self, open: &OpenMeasure) -> Self {
        Self { bytes: self.bytes.min(open.bytes), duration: self.duration.min(Duration::from_millis(u64::from(open.millis))) }
    }
}

/// 一个方向搬了多少。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {
    pub bytes: u64,
    /// 从第一个字节到最后一个字节。
    pub elapsed: Duration,
    pub end: MeasureEnd,
    /// 剔除起始预热阶段后的稳态统计。若传输在预热阶段内结束，或对端为不上报该字段的旧版本，则为 `None`。
    pub steady: Option<Steady>,
}

/// 单次传输剔除起始预热阶段后的接收字节数与耗时。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Steady {
    pub bytes: u64,
    pub elapsed: Duration,
}

impl Measured {
    /// 吞吐速率（bit/s）：存在稳态统计时按稳态段计算，否则按整次传输计算。耗时不足 1 毫秒时无法计算，返回 `None`。
    #[must_use]
    pub fn bits_per_second(&self) -> Option<f64> {
        let (bytes, elapsed) = self.steady.map_or((self.bytes, self.elapsed), |steady| (steady.bytes, steady.elapsed));
        let seconds = elapsed.as_secs_f64();
        // 单次测量最多几十 MB，通常在 u32 范围内；若超出则饱和到最大值，结果只会偏低。
        let bits = f64::from(u32::try_from(bytes).unwrap_or(u32::MAX)) * 8.0;
        (seconds >= 0.001).then(|| bits / seconds)
    }
}

/// 收的一侧数一次搬运：一共多少、从第一个字节起多久，以及起步在哪里结束。
#[derive(Debug)]
struct Meter {
    limits: MeasureLimits,
    bytes: u64,
    first: Option<Instant>,
    last: Instant,
    /// 起步结束的时刻，和那时已经收到多少。
    warmed: Option<(Instant, u64)>,
}

impl Meter {
    fn new(limits: MeasureLimits, now: Instant) -> Self {
        Self { limits, bytes: 0, first: None, last: now, warmed: None }
    }

    /// 在 `now` 收到了 `read` 个字节。
    fn record(&mut self, read: usize, now: Instant) {
        let first = *self.first.get_or_insert(now);
        self.last = now;
        self.bytes = self.bytes.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let warm =
            self.bytes >= self.limits.bytes / u64::from(WARM_UP) || now.saturating_duration_since(first) >= self.limits.duration / WARM_UP;
        if self.warmed.is_none() && warm {
            self.warmed = Some((now, self.bytes));
        }
    }

    /// 从第一个字节算起过了多久；还没有收到字节时是 `None`。
    fn since_first(&self) -> Option<Duration> {
        self.first.map(|first| first.elapsed())
    }

    fn measured(&self, end: MeasureEnd) -> Measured {
        let elapsed = self.first.map_or(Duration::ZERO, |first| self.last.saturating_duration_since(first));
        // 预热结束后若未再收到任何字节（传输过短），则不产生稳态统计。
        let steady = self
            .warmed
            .filter(|(_, before)| self.bytes > *before)
            .map(|(at, before)| Steady { bytes: self.bytes - before, elapsed: self.last.saturating_duration_since(at) });
        Measured { bytes: self.bytes, elapsed, end, steady }
    }
}

/// 对端开过来的一条测量流，OPEN 已经读出来了。
pub struct MeasureRequest<S, R> {
    pub(crate) peer: NodeId,
    pub(crate) open: OpenMeasure,
    pub(crate) send: S,
    pub(crate) recv: R,
}

impl<S, R> std::fmt::Debug for MeasureRequest<S, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeasureRequest").field("peer", &self.peer).field("open", &self.open).finish_non_exhaustive()
    }
}

impl<S: SendStream, R: RecvStream> MeasureRequest<S, R> {
    /// 开这条流的节点，来自连接的握手。
    #[must_use]
    pub const fn peer(&self) -> NodeId {
        self.peer
    }

    #[must_use]
    pub const fn open(&self) -> &OpenMeasure {
        &self.open
    }

    /// 不接受：回这个拒绝，结束这条流。
    pub async fn refuse(mut self, reply: &Reply) {
        crate::acceptor::refuse(self.peer, &mut self.send, &mut self.recv, reply).await;
    }

    /// 接受，按 `limits`（和发起方要的里小的那个）搬运，直到结束。返回这个方向搬了多少。
    ///
    /// 不管发起方怎么做，这个函数最多占用"时长上限加几秒"：到时候流被重置。
    pub async fn serve(mut self, limits: MeasureLimits) -> Measured {
        let limits = limits.within(&self.open);
        let deadline = limits.duration + GRACE;
        let mut reply = Vec::with_capacity(Reply::MAX_LEN);
        Reply::ok().encode(&mut reply);
        // 测量流让着这条连接上别的流：吞吐测的是"别的流用剩下的"，测试期间不该把别人的交互挤慢。
        self.send.set_priority(Priority::Low);
        let mode = self.open.mode;
        let work = async {
            self.send.write_all(&reply).await?;
            match mode {
                MeasureMode::Sink => sink(&mut self.send, &mut self.recv, limits).await,
                MeasureMode::Source => {
                    self.recv.stop(StreamCode(Reason::Cancelled.to_wire()));
                    source(&mut self.send, limits).await
                }
            }
        };
        let outcome = time::timeout(deadline, work).await;
        match outcome {
            Ok(Ok(measured)) => measured,
            failed => {
                let code = StreamCode(Reason::Cancelled.to_wire());
                self.send.reset(code);
                self.recv.stop(code);
                if let Ok(Err(error)) = failed {
                    tracing::debug!(peer = %self.peer, %error, "测量流中途断开");
                }
                Measured { bytes: 0, elapsed: Duration::ZERO, end: MeasureEnd::Time, steady: None }
            }
        }
    }
}

/// "收"：读到发起方结束、字节数或者时长到了为止，然后写回收了多少。
async fn sink(send: &mut impl SendStream, recv: &mut impl RecvStream, limits: MeasureLimits) -> std::io::Result<Measured> {
    let mut buf = vec![0; CHUNK];
    let started = Instant::now();
    let mut meter = Meter::new(limits, started);
    let end = loop {
        // 发起方迟迟不发第一个字节时也按时长算：从接受这条流算起。
        let wait = limits.duration.saturating_sub(meter.since_first().unwrap_or_else(|| started.elapsed()));
        // 数据一直读得到时等待不会超时，所以每一轮都先看一眼时间。
        if wait.is_zero() {
            break MeasureEnd::Time;
        }
        match time::timeout(wait, recv.read(&mut buf)).await {
            Err(_) => break MeasureEnd::Time,
            Ok(Ok(0)) => break MeasureEnd::Finished,
            Ok(Ok(read)) => {
                meter.record(read, Instant::now());
                if meter.bytes >= limits.bytes {
                    break MeasureEnd::Bytes;
                }
            }
            Ok(Err(error)) => return Err(error),
        }
    };
    if end != MeasureEnd::Finished {
        // 到了上限：叫发起方别再发了。
        recv.stop(StreamCode(Reason::Cancelled.to_wire()));
    }
    let measured = meter.measured(end);
    let steady = measured.steady.map(|steady| MeasureSteady { bytes: steady.bytes, millis: millis(steady.elapsed) });
    let mut summary = Vec::with_capacity(MeasureSummary::MAX_LEN);
    MeasureSummary { bytes: measured.bytes, millis: millis(measured.elapsed), end, steady }.encode(&mut summary);
    send.write_all(&summary).await?;
    send.shutdown().await?;
    Ok(measured)
}

fn millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

/// "发"：写到字节数或者时长到了为止，然后正常结束。
async fn source(send: &mut impl SendStream, limits: MeasureLimits) -> std::io::Result<Measured> {
    let chunk = vec![0; CHUNK];
    let started = Instant::now();
    let mut bytes = 0u64;
    let end = loop {
        if bytes >= limits.bytes {
            break MeasureEnd::Bytes;
        }
        let left = limits.duration.saturating_sub(started.elapsed());
        // 写一直写得进去时等待不会超时，所以每一轮都先看一眼时间。
        if left.is_zero() {
            break MeasureEnd::Time;
        }
        let size = usize::try_from(limits.bytes - bytes).unwrap_or(CHUNK).min(CHUNK);
        match time::timeout(left, send.write_all(&chunk[..size])).await {
            Err(_) => break MeasureEnd::Time,
            Ok(Ok(())) => bytes += u64::try_from(size).unwrap_or(u64::MAX),
            Ok(Err(error)) => return Err(error),
        }
    };
    send.shutdown().await?;
    // 发送方无法获知对端各字节的到达时刻，稳态阶段由接收方自行统计。
    Ok(Measured { bytes, elapsed: started.elapsed(), end, steady: None })
}

/// 到 `peer` 开一条测量流，按 `open` 量一个方向，返回量到的结果。
///
/// 上行（[`MeasureMode::Sink`]）的结果是对端说它收到的；下行（[`MeasureMode::Source`]）的结果是本端自己收到的。
/// 本端这边也守着 `open` 里的上限，外面再套一个总的时限，对端不配合也不会一直等下去。
///
/// # Errors
///
/// 开流失败、对端拒绝（[`FlowError::Refused`]），或传输中途出错、超时。
pub async fn measure<C: Connector>(connector: &C, peer: NodeId, open: &OpenMeasure) -> Result<Measured, FlowError> {
    let (mut send, mut recv) = connector.open(peer).await?;
    send.set_priority(Priority::Low);
    let mut head = Vec::with_capacity(OpenMeasure::MAX_LEN);
    open.encode(&mut head);
    send.write_all(&head).await.map_err(FlowError::Write)?;
    let limit = Duration::from_millis(u64::from(open.millis)) + GRACE + SUMMARY_WAIT;
    let run = async {
        let reply = header::read_reply(&mut recv).await?;
        if !reply.status.is_ok() {
            return Err(FlowError::Refused(reply));
        }
        match open.mode {
            MeasureMode::Sink => upload(&mut send, &mut recv, open).await,
            MeasureMode::Source => {
                // 下行时本端不发数据。对端接受时叫停了这个方向，这里的结束可能失败，那也没有关系。
                let _ended = send.shutdown().await;
                download(&mut recv, open).await
            }
        }
    };
    match time::timeout(limit, run).await {
        Ok(Ok(measured)) => Ok(measured),
        Ok(Err(error)) => {
            abandon(&mut send, &mut recv);
            Err(error)
        }
        Err(_) => {
            abandon(&mut send, &mut recv);
            Err(FlowError::Deadline(limit))
        }
    }
}

fn abandon(send: &mut impl SendStream, recv: &mut impl RecvStream) {
    let code = StreamCode(Reason::Cancelled.to_wire());
    send.reset(code);
    recv.stop(code);
}

/// 上行测量：持续写入直至达到上限或被对端中止，随后读取对端写回的汇总信息。
async fn upload(send: &mut impl SendStream, recv: &mut impl RecvStream, open: &OpenMeasure) -> Result<Measured, FlowError> {
    let chunk = vec![0; CHUNK];
    let started = Instant::now();
    let duration = Duration::from_millis(u64::from(open.millis));
    let mut written = 0u64;
    while written < open.bytes && started.elapsed() < duration {
        let size = usize::try_from(open.bytes - written).unwrap_or(CHUNK).min(CHUNK);
        let left = duration.saturating_sub(started.elapsed());
        match time::timeout(left, send.write_all(&chunk[..size])).await {
            Ok(Ok(())) => written += u64::try_from(size).unwrap_or(u64::MAX),
            // 对端达到上限中止了写入，或本地超时，均转去读取对端写回的汇总信息。
            Ok(Err(_)) | Err(_) => break,
        }
    }
    // 对端叫停之后这里的结束可能失败，那也没有关系：它已经不读了。
    let _ended = send.shutdown().await;
    let summary = time::timeout(SUMMARY_WAIT, read_summary(recv)).await.map_err(|_| FlowError::Deadline(SUMMARY_WAIT))??;
    Ok(Measured {
        bytes: summary.bytes,
        elapsed: Duration::from_millis(u64::from(summary.millis)),
        end: summary.end,
        steady: summary.steady.map(|steady| Steady { bytes: steady.bytes, elapsed: Duration::from_millis(u64::from(steady.millis)) }),
    })
}

/// 读取对端写回的汇总信息：前部固定字段必然存在；后部稳态统计字段较早版本不写入，流会在此处结束。
async fn read_summary(recv: &mut impl RecvStream) -> Result<MeasureSummary, FlowError> {
    let mut head = [0; MeasureSummary::LEN];
    recv.read_exact(&mut head).await.map_err(|error| match error.kind() {
        std::io::ErrorKind::UnexpectedEof => FlowError::Truncated,
        _ => FlowError::Read(error),
    })?;
    let summary = MeasureSummary::from_bytes(&head).ok_or(FlowError::Truncated)?;
    let mut tail = [0; MeasureSteady::LEN];
    let steady = match recv.read_exact(&mut tail).await {
        Ok(_) => Some(MeasureSteady::from_bytes(&tail)),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => None,
        Err(error) => return Err(FlowError::Read(error)),
    };
    Ok(MeasureSummary { steady, ..summary })
}

/// 下行：读到对端结束、字节数够了，或者从第一个字节算起时长到了为止，自己数。
///
/// 时长按收到的一侧算：对端写进发送缓冲就算写完了，它停笔的时候缓冲里还有一截在路上，按它的时钟停会把那一截也算进来。
async fn download(recv: &mut impl RecvStream, open: &OpenMeasure) -> Result<Measured, FlowError> {
    let mut buf = vec![0; CHUNK];
    let limits = MeasureLimits { bytes: open.bytes, duration: Duration::from_millis(u64::from(open.millis)) };
    let mut meter = Meter::new(limits, Instant::now());
    let end = loop {
        let left = meter.since_first().map_or(limits.duration + GRACE, |since| limits.duration.saturating_sub(since));
        if left.is_zero() {
            break MeasureEnd::Time;
        }
        match time::timeout(left, recv.read(&mut buf)).await {
            Err(_) => break MeasureEnd::Time,
            // 对端结束了：字节数没够的话，是它那边的时长上限先到了。
            Ok(Ok(0)) => break if meter.bytes >= limits.bytes { MeasureEnd::Bytes } else { MeasureEnd::Time },
            Ok(Ok(read)) => {
                meter.record(read, Instant::now());
                if meter.bytes >= limits.bytes {
                    break MeasureEnd::Bytes;
                }
            }
            Ok(Err(error)) => return Err(FlowError::Read(error)),
        }
    };
    if end == MeasureEnd::Time {
        // 时长到了，后面还在路上的不要了。
        recv.stop(StreamCode(Reason::Cancelled.to_wire()));
    }
    Ok(meter.measured(end))
}

#[cfg(test)]
mod tests {
    use i3t_conn::Acceptor;
    use i3t_proto::NodeId;

    use super::*;
    use crate::memory::MemoryMesh;

    /// 对端写回 `wire` 然后结束，这一端读到的是什么。
    async fn summary_read_from(wire: &[u8]) -> Result<MeasureSummary, FlowError> {
        let mesh = MemoryMesh::new();
        let (connector, _) = mesh.join(NodeId::new(1).expect("1 is a valid node id"));
        let (_, acceptor) = mesh.join(NodeId::new(2).expect("2 is a valid node id"));
        let (_near_send, mut near_recv) = connector.open(NodeId::new(2).expect("2 is a valid node id")).await.expect("open");
        let mut far = acceptor.accept().await.expect("accept");
        far.send.write_all(wire).await.expect("write");
        far.send.shutdown().await.expect("finish");
        read_summary(&mut near_recv).await
    }

    #[tokio::test]
    async fn a_summary_from_an_older_peer_without_the_steady_part_is_still_read() {
        let plain = MeasureSummary { bytes: 20_000_000, millis: 2500, end: MeasureEnd::Bytes, steady: None };
        let mut old = Vec::new();
        plain.encode(&mut old);
        assert_eq!(summary_read_from(&old).await.expect("the fixed part alone is a whole summary"), plain);

        let full = MeasureSummary { steady: Some(MeasureSteady { bytes: 15_000_000, millis: 1200 }), ..plain };
        let mut new = Vec::new();
        full.encode(&mut new);
        assert_eq!(summary_read_from(&new).await.expect("with the steady part"), full);

        assert!(matches!(summary_read_from(&old[..5]).await, Err(FlowError::Truncated)), "固定的那一段不全就是坏的");
    }

    const LIMITS: MeasureLimits = MeasureLimits { bytes: 4000, duration: Duration::from_secs(4) };

    fn at(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    #[test]
    fn the_rate_leaves_out_the_first_quarter_of_the_bytes() {
        let start = Instant::now();
        let mut meter = Meter::new(LIMITS, start);
        // 起步很慢：前 1000 个字节用了 800 毫秒，之后每 100 毫秒 1000 个。
        meter.record(500, at(start, 0));
        meter.record(500, at(start, 800));
        meter.record(1000, at(start, 900));
        meter.record(1000, at(start, 1000));
        meter.record(1000, at(start, 1100));
        let measured = meter.measured(MeasureEnd::Bytes);
        assert_eq!((measured.bytes, measured.elapsed), (4000, Duration::from_millis(1100)), "字节数和用时是整次搬运的");
        assert_eq!(measured.steady, Some(Steady { bytes: 3000, elapsed: Duration::from_millis(300) }));
        assert_eq!(measured.bits_per_second(), Some(80_000.0), "速率按起步之后的那一段算");
    }

    #[test]
    fn on_a_slow_path_the_warm_up_ends_after_a_quarter_of_the_time() {
        let start = Instant::now();
        let mut meter = Meter::new(LIMITS, start);
        for step in 0..=40 {
            meter.record(10, at(start, step * 100));
        }
        let measured = meter.measured(MeasureEnd::Time);
        // 四分之一的时长是 1 秒：第 1000 毫秒那一次读到的还算起步，之后的 30 次算数。
        assert_eq!(measured.steady, Some(Steady { bytes: 300, elapsed: Duration::from_secs(3) }));
    }

    #[test]
    fn a_transfer_that_ends_inside_the_warm_up_is_reported_whole() {
        let start = Instant::now();
        let mut meter = Meter::new(LIMITS, start);
        meter.record(300, at(start, 0));
        meter.record(300, at(start, 100));
        let short = meter.measured(MeasureEnd::Finished);
        assert_eq!((short.bytes, short.steady), (600, None));
        assert_eq!(short.bits_per_second(), Some(48_000.0), "没有起步之后的那一段，就按整次搬运算");

        // 起步刚好在最后一次读到时结束：之后没有字节，也没有那一段。
        meter.record(400, at(start, 200));
        assert_eq!(meter.measured(MeasureEnd::Finished).steady, None);
        let nothing = Meter::new(LIMITS, start).measured(MeasureEnd::Time);
        assert_eq!((nothing.bytes, nothing.elapsed, nothing.steady), (0, Duration::ZERO, None));
    }
}
