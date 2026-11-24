//! 送达速率的采样：对端这段时间里实际收下了多少字节、用了多久。
//!
//! 做法是 BBR 草案里的送达速率估计：每个包发出时记下当时"已送达的字节数"和几个时刻，它被确认时，
//! 用这期间新送达的字节数除以经过的时间。时间取"发送侧经过的"和"确认侧经过的"里较长的一个，
//! 这样确认成堆到达（确认侧的时间被压短）不会把速率算高。
//!
//! QUIC 库的接口不给包号：发送时只知道"这一批包在 `now` 发出"，确认时只知道那个包的发送时刻。
//! 同一批包的发送时刻相同、发送时的快照也相同，所以这里按发送时刻记录，一批一条，效果和逐包记录一样。

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// 比"最近被确认的那一批"更早的记录留几条。乱序到达的确认还会用到它们；更早的包要么已经确认，
/// 否则即将被判定丢失，不会再收到确认。未命中发送记录仅导致跳过单个速率样本。
const KEPT_BEHIND: usize = 8;
/// 记录数的硬上限。正常情况下记录数不超过在途的批数；这个上限只防一直没有确认回来时无限增长。
const MAX_RECORDS: usize = 1 << 16;

/// 一批包发出时的快照。
#[derive(Debug, Clone, Copy)]
struct SendRecord {
    sent_time: Instant,
    /// 发出时已经送达的字节数。
    delivered: u64,
    /// 发出时，最近一次确认到达的时刻。
    delivered_time: Instant,
    /// 发出时，最近被确认的那个包是什么时候发的。从它到这一批之间发出的数据，就是这一批被确认时刚好送达的那些。
    first_sent_time: Instant,
    /// 发出时应用是不是没有填满连接。是的话，这一批量出来的速率反映的是应用，不是路径。
    app_limited: bool,
}

/// 正在处理的这一批确认。
#[derive(Debug, Clone, Copy, Default)]
struct Batch {
    acked: u64,
    /// 这一批确认的包里最晚发出的那个的发送时刻。
    newest_sent: Option<Instant>,
    /// 这一批确认的包里，找得到记录的、最晚发出的那个的快照。
    newest: Option<SendRecord>,
}

/// 一批确认处理完之后得到的东西。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AckSample {
    /// 这一批新确认的字节数。
    pub(super) acked: u64,
    /// 这一批里最晚发出的那个包的发送时刻。
    pub(super) sent: Instant,
    /// 往返时间：那个包从发出到被确认用了多久。含对端攒确认的时间。
    pub(super) rtt: Duration,
    /// 送达速率（字节/秒）。采样区间过短或未找到对应发送记录时为 `None`。
    pub(super) rate: Option<u64>,
    /// 这个样本是在应用没有填满连接的时候量的，只能用来抬高带宽估计，不能用来拉低。
    pub(super) app_limited: bool,
    /// 这一批确认是否走完了一轮：上一轮开始之后才发出的包被确认了，并且这一轮够长了。
    pub(super) round_ended: bool,
}

#[derive(Debug, Clone)]
pub(super) struct Sampler {
    delivered: u64,
    delivered_time: Instant,
    first_sent_time: Instant,
    /// 已送达的字节数超过这个值之前，发出的包都算应用受限。
    app_limited_until: Option<u64>,
    /// 没有在途的包。下一次发送时采样区间从头算起，不把空闲的时间算进去。
    idle: bool,
    /// 按发送时刻递增。
    records: VecDeque<SendRecord>,
    round: u64,
    /// 发送时"已送达的字节数"达到这个值的包被确认，就算走完了一轮。
    next_round_delivered: u64,
    round_start: Instant,
    /// 一轮至少这么长。
    min_round: Duration,
    batch: Batch,
}

impl Sampler {
    /// `min_round` 是一轮最短多长。往返时间只有几十微秒的路径上，按"在途的数据换了一遍"算的一轮只有零点几毫秒，
    /// 比操作系统调度的抖动还短：进程被挂起几毫秒，按轮数算的滤波器里就只剩下挂起前后的那几个样本了。
    pub(super) fn new(now: Instant, min_round: Duration) -> Self {
        Self {
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            app_limited_until: None,
            idle: true,
            records: VecDeque::new(),
            round: 0,
            next_round_delivered: 0,
            round_start: now,
            min_round,
            batch: Batch::default(),
        }
    }

    /// 已经走完了多少轮。一轮大约是一个往返时间，不短于构造时给的下限。
    pub(super) fn round(&self) -> u64 {
        self.round
    }

    pub(super) fn on_sent(&mut self, now: Instant) {
        if self.idle {
            self.idle = false;
            self.first_sent_time = now;
            self.delivered_time = now;
        }
        // QUIC 库一次唤醒里会用同一个时刻连发好几批，它们之间不会处理确认，快照相同，记一条就够。
        if self.records.back().is_some_and(|last| last.sent_time >= now) {
            return;
        }
        if self.records.len() == MAX_RECORDS {
            self.records.pop_front();
        }
        self.records.push_back(SendRecord {
            sent_time: now,
            delivered: self.delivered,
            delivered_time: self.delivered_time,
            first_sent_time: self.first_sent_time,
            app_limited: self.app_limited_until.is_some(),
        });
    }

    /// 一个在 `sent` 发出的包被确认了。
    pub(super) fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64) {
        self.delivered += bytes;
        self.delivered_time = now;
        self.batch.acked += bytes;
        // 同一批次发出的包具有相同的发送时刻与快照，无需重复查找；早于已处理最新发送时刻的包也可直接跳过。
        if self.batch.newest_sent.is_some_and(|newest| sent <= newest) {
            return;
        }
        self.batch.newest_sent = Some(sent);
        if let Ok(index) = self.records.binary_search_by(|record| record.sent_time.cmp(&sent)) {
            self.batch.newest = Some(self.records[index]);
            self.records.drain(..index.saturating_sub(KEPT_BEHIND));
        }
    }

    /// 从现在起发出的包算应用受限，直到眼下在途的数据都送达为止。
    pub(super) fn mark_app_limited(&mut self, in_flight: u64) {
        self.app_limited_until = Some(self.delivered + in_flight);
    }

    /// 一批确认处理完了。这一批里没有新确认的包时返回 `None`。
    ///
    /// `app_limited` 是这批确认到来之前发送方是不是没有数据可发；`min_rtt` 是眼下的往返时间下限，
    /// 比它还短的采样区间量不准，不出速率。
    pub(super) fn finish(&mut self, now: Instant, in_flight: u64, app_limited: bool, min_rtt: Option<Duration>) -> Option<AckSample> {
        let batch = std::mem::take(&mut self.batch);
        if in_flight == 0 {
            self.idle = true;
        }
        if self.app_limited_until.is_some_and(|until| self.delivered > until) {
            self.app_limited_until = None;
        }
        if app_limited {
            self.mark_app_limited(in_flight);
        }

        let newest_sent = batch.newest_sent?;
        let mut sample = AckSample {
            acked: batch.acked,
            sent: newest_sent,
            rtt: now.saturating_duration_since(newest_sent),
            rate: None,
            app_limited,
            round_ended: false,
        };
        let Some(record) = batch.newest else { return Some(sample) };

        self.first_sent_time = record.sent_time;
        sample.app_limited |= record.app_limited;
        let send_elapsed = record.sent_time.saturating_duration_since(record.first_sent_time);
        let ack_elapsed = now.saturating_duration_since(record.delivered_time);
        let interval = send_elapsed.max(ack_elapsed);
        if !interval.is_zero() && min_rtt.is_none_or(|min_rtt| interval >= min_rtt) {
            sample.rate = Some(super::bytes_per_sec(self.delivered - record.delivered, interval));
        }
        if record.delivered >= self.next_round_delivered && now.saturating_duration_since(self.round_start) >= self.min_round {
            self.next_round_delivered = self.delivered;
            self.round_start = now;
            self.round += 1;
            sample.round_ended = true;
        }
        Some(sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// 每毫秒发一个 1000 字节的包，往返 50ms，对端每个包都立即确认。跑 `packets` 个包，返回每次确认的样本。
    fn steady_flow(sampler: &mut Sampler, start: Instant, packets: u32) -> Vec<AckSample> {
        let rtt = 50 * MS;
        let mut samples = Vec::new();
        for tick in 0..packets + 50 {
            let now = start + tick * MS;
            if tick >= 50 {
                let sent = now - rtt;
                sampler.on_ack(now, sent, 1000);
                let in_flight = u64::from((packets.min(tick + 1)).saturating_sub(tick - 49)) * 1000;
                samples.extend(sampler.finish(now, in_flight, false, Some(rtt)));
            }
            if tick < packets {
                sampler.on_sent(now);
            }
        }
        samples
    }

    #[test]
    fn steady_flow_measures_the_sending_rate() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        let samples = steady_flow(&mut sampler, start, 400);
        // 1000 字节每毫秒 = 1MB/s。前 50 个样本的采样区间里包含启动时的空档，速率偏低；之后稳定。
        let steady: Vec<u64> = samples[60..300].iter().filter_map(|sample| sample.rate).collect();
        assert!(!steady.is_empty());
        for rate in steady {
            assert!((990_000..=1_010_000).contains(&rate), "速率 {rate}");
        }
        assert!(samples.iter().all(|sample| sample.rtt == 50 * MS));
        assert!(samples.iter().all(|sample| !sample.app_limited));
    }

    #[test]
    fn a_round_ends_when_a_packet_sent_after_the_previous_round_began_is_acked() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        let samples = steady_flow(&mut sampler, start, 400);
        let ends: Vec<usize> = samples.iter().enumerate().filter(|(_, sample)| sample.round_ended).map(|(index, _)| index).collect();
        // 第一个确认结束第一轮；之后每隔一个往返时间（50 个包）结束一轮。
        assert_eq!(ends[0], 0);
        for pair in ends.windows(2) {
            assert!((49..=51).contains(&(pair[1] - pair[0])), "相邻两轮隔了 {} 个确认", pair[1] - pair[0]);
        }
        assert_eq!(sampler.round(), u64::try_from(ends.len()).unwrap());
    }

    #[test]
    fn a_round_is_never_shorter_than_the_configured_minimum() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, 120 * MS);
        let samples = steady_flow(&mut sampler, start, 400);
        let ends: Vec<usize> = samples.iter().enumerate().filter(|(_, sample)| sample.round_ended).map(|(index, _)| index).collect();
        // 往返 50ms，按"换了一遍"算每 50 个确认一轮；下限是 120ms，所以要等到第 120 个确认之后。
        for pair in ends.windows(2) {
            assert!((120..=121).contains(&(pair[1] - pair[0])), "相邻两轮隔了 {} 个确认", pair[1] - pair[0]);
        }
        assert!(ends.len() >= 2);
    }

    #[test]
    fn compressed_acks_do_not_inflate_the_rate() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        // 每毫秒一个包，往返 50ms，发到第 150 个包为止。
        for tick in 0..150 {
            let now = start + tick * MS;
            if tick >= 50 {
                sampler.on_ack(now, now - 50 * MS, 1000);
                sampler.finish(now, 50_000, false, Some(50 * MS));
            }
            sampler.on_sent(now);
        }
        // 这时在途 50 个包，是 50ms 里匀速发出去的。它们的确认挤在一起，10ms 之后同时到达。
        let now = start + 159 * MS;
        for tick in 100..150 {
            sampler.on_ack(now, start + tick * MS, 1000);
        }
        let sample = sampler.finish(now, 0, false, Some(50 * MS)).unwrap();
        // 只看确认侧是 10ms 里到了 50000 字节，即 5MB/s。采样区间取较长的发送侧，得到的是实际的发送速率。
        assert_eq!(sample.rate, Some(1_000_000));
        assert_eq!(sample.acked, 50_000);
    }

    #[test]
    fn samples_shorter_than_the_min_rtt_carry_no_rate() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        sampler.on_sent(start);
        sampler.on_ack(start + 10 * MS, start, 1000);
        let sample = sampler.finish(start + 10 * MS, 0, false, Some(50 * MS)).unwrap();
        assert_eq!(sample.rate, None);
        assert_eq!(sample.rtt, 10 * MS);
    }

    #[test]
    fn packets_sent_while_app_limited_are_marked_until_the_pipe_is_refilled() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        // 应用只有两个包可发，发完就没有数据了。
        sampler.on_sent(start);
        sampler.on_ack(start + 50 * MS, start, 2000);
        let first = sampler.finish(start + 50 * MS, 0, true, None).unwrap();
        assert!(first.app_limited);

        // 之后应用有了很多数据。空闲之后发出的第一批还带着标记：它出发时管道是空的。
        sampler.on_sent(start + 100 * MS);
        sampler.on_sent(start + 101 * MS);
        sampler.on_ack(start + 150 * MS, start + 100 * MS, 1000);
        let second = sampler.finish(start + 150 * MS, 1000, false, Some(50 * MS)).unwrap();
        assert!(second.app_limited, "空闲后发出的第一批");

        // 标记在这之后清掉，之后发出的包量出来的是路径。
        sampler.on_sent(start + 151 * MS);
        sampler.on_ack(start + 201 * MS, start + 151 * MS, 1000);
        let third = sampler.finish(start + 201 * MS, 0, false, Some(50 * MS)).unwrap();
        assert!(!third.app_limited);
    }

    #[test]
    fn idle_time_is_not_counted_into_the_next_sample() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        sampler.on_sent(start);
        sampler.on_ack(start + 50 * MS, start, 1000);
        sampler.finish(start + 50 * MS, 0, false, None).unwrap();

        // 空闲 10 秒之后，1ms 之内发出 10 个包，50ms 后一起确认。
        let resume = start + Duration::from_secs(10);
        sampler.on_sent(resume);
        sampler.on_ack(resume + 50 * MS, resume, 10_000);
        let sample = sampler.finish(resume + 50 * MS, 0, false, Some(50 * MS)).unwrap();
        // 10000 字节 / 50ms = 200KB/s。把空闲的 10 秒算进去的话会是 1KB/s。
        assert_eq!(sample.rate, Some(200_000));
    }

    #[test]
    fn batches_sent_at_the_same_instant_share_one_record() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        sampler.on_sent(start);
        sampler.on_sent(start);
        sampler.on_sent(start);
        assert_eq!(sampler.records.len(), 1);
    }

    #[test]
    fn acks_without_a_send_record_still_count_as_delivered() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        // 探测路径最大包长的包不经过"已发送"的通知，但会被确认。
        sampler.on_ack(start + 50 * MS, start, 1400);
        let sample = sampler.finish(start + 50 * MS, 0, false, None).unwrap();
        assert_eq!((sample.acked, sample.rate, sample.round_ended), (1400, None, false));
        assert_eq!(sampler.delivered, 1400);
    }

    #[test]
    fn a_batch_with_nothing_newly_acked_yields_no_sample() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        assert_eq!(sampler.finish(start, 0, false, None), None);
    }

    #[test]
    fn old_records_are_dropped_as_acks_advance() {
        let start = Instant::now();
        let mut sampler = Sampler::new(start, Duration::ZERO);
        steady_flow(&mut sampler, start, 400);
        assert!(sampler.records.len() <= KEPT_BEHIND + 1, "留下了 {} 条", sampler.records.len());
    }
}
