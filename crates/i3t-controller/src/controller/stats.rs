//! 给界面画图的低分辨率时间序列。
//!
//! 数都来自 controller 本来就收到的东西：节点每 10 秒的上报（流量、活跃流、挂靠的 relay、出口的计数）和谁在线。
//! 攒在内存里，每 5 分钟写一个点；整点时把上一个小时的 5 分钟的点平均成一个 1 小时的点。
//!
//! | 分辨率 | 保留 | 每条序列的点 |
//! |---|---|---|
//! | 5 分钟 | 24 小时 | 288 |
//! | 1 小时 | 7 天 | 168 |
//!
//! 序列是固定的一小组（[`Series`]）：每个网络 4 条，每个节点 3 条，每个 relay 1 条，每个出口 2 条。1000 个节点
//! （其中 100 个 relay、100 个出口）大约 3300 条序列，最多 150 万行，数据库里约 46 MB（按这个表结构量过）。点都存在同一个数据库里，
//! controller 重启之后还在，备份数据库时也带着它们；过了保留期的整点时删掉。数据库暂时写不进去时，过完了的段留在内存里
//! 隔一会儿再写，最多留到 5 分钟的点的保留期；能写了之后一次写一个小时的。
//!
//! 速率从累计的计数算：两次上报之间涨了多少除以隔了多久。节点重启（[`Report::run`] 变了）或者计数变小了，
//! 这一段不算：算出来不是负数就是一个从零开始的大数。两次上报隔得太久（节点断开过）也不算，增量不知道落在哪一段里。

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use i3t_model::admin::stats::{Series, SeriesQuery, SeriesView};
use i3t_model::admin::{NetworkId, Timestamp};
use i3t_model::control::Report;
use i3t_model::netmap::Attachment;
use i3t_proto::NodeId;

use super::{Controller, Inner};
use crate::error::{Error, InField};
use crate::store::{NodeRecord, StatPoint};

/// 细的一档：多少秒一个点，留多久。
pub(crate) const FINE_STEP: u32 = 300;
const FINE_KEEP: u64 = 24 * 60 * 60;
/// 粗的一档。
pub(crate) const COARSE_STEP: u32 = 3600;
const COARSE_KEEP: u64 = 7 * 24 * 60 * 60;
/// 一次最多读多少个点：7 天的 5 分钟的点。
const MAX_POINTS: u64 = 2016;
/// 在线的节点数、挂靠在 relay 上的节点数多久数一次。一段 5 分钟里数 5 次，平均下来就是这一段的值。
const SAMPLE_EVERY: Duration = Duration::from_secs(60);
/// 同一个计数两次上报隔了超过这么久，中间的增量不算（节点每 10 秒报一次）。
const MAX_GAP: Duration = Duration::from_secs(60);
/// 过完了的段没写成功时，隔多久再试。
const WRITE_RETRY: Duration = Duration::from_secs(60);

/// 一段里攒着的数。
#[derive(Debug, Clone, Copy)]
enum Acc {
    /// 个数：每次看到的值相加，最后除以次数。
    Gauge { sum: f64, count: u32 },
    /// 速率：增量相加，时间相加，最后相除。
    Rate { bytes: u64, secs: f64 },
}

impl Acc {
    fn value(self) -> Option<f64> {
        match self {
            Self::Gauge { sum, count } => (count > 0).then(|| sum / f64::from(count)),
            Self::Rate { bytes, secs } => (secs > 0.0).then(|| precise(bytes) / secs),
        }
    }
}

/// 字节数换成浮点数。一段里的增量超过 2^53（8 PB）才会差一点，画图用不着那么准；标准库没有不丢精度的转换。
fn precise(bytes: u64) -> f64 {
    bytes as f64
}

/// 一个累计的计数上一次报的值。
#[derive(Debug, Clone, Copy)]
struct Counter {
    run: u64,
    value: u64,
    at: Instant,
}

type Key = (NetworkId, Series, Option<NodeId>);

/// 攒着还没写进存储的数。
#[derive(Debug, Default)]
pub(crate) struct Collector {
    /// 正在攒的那一段的开始；还没开始攒时是 `None`。
    bucket: Option<Timestamp>,
    acc: BTreeMap<Key, Acc>,
    /// 过完了、还没写下的段：每段的开始和它的点。写成功了才清掉；写不进去（数据库暂时出错）就留着下次再写。
    unwritten: BTreeMap<Timestamp, Vec<StatPoint>>,
    /// 上次没写成功：这个时刻之前不再试，免得数据库出错时每次叫都试一遍、报一遍错。过完了的段都写下了（或者丢了）时是 `None`。
    write_after: Option<Instant>,
    counters: BTreeMap<(NodeId, Series), Counter>,
    /// 每个节点最近一次报的挂靠的 relay，和存下来的是同一份（核对过、去掉了重复的）。数 relay 上挂着几个在线节点要用。
    attached: BTreeMap<NodeId, (NetworkId, Vec<NodeId>)>,
    next_sample: Option<Instant>,
}

impl Collector {
    fn gauge(&mut self, key: Key, value: f64) {
        let entry = self.acc.entry(key).or_insert(Acc::Gauge { sum: 0.0, count: 0 });
        if let Acc::Gauge { sum, count } = entry {
            *sum += value;
            *count += 1;
        }
    }

    /// 一个累计的计数报上来了：和上一次比，涨了多少记进这一段的速率。
    fn counter(&mut self, key: Key, run: u64, value: u64, now: Instant) {
        let (_, series, Some(node)) = key else { return };
        let previous = self.counters.insert((node, series), Counter { run, value, at: now });
        let Some(previous) = previous else { return };
        if previous.run != run || value < previous.value {
            tracing::debug!(%node, series = %series, "计数从头开始了（节点重启过），这一段不算速率");
            return;
        }
        let gap = now.saturating_duration_since(previous.at);
        if gap.is_zero() || gap > MAX_GAP {
            return;
        }
        let entry = self.acc.entry(key).or_insert(Acc::Rate { bytes: 0, secs: 0.0 });
        if let Acc::Rate { bytes, secs } = entry {
            *bytes = bytes.saturating_add(value - previous.value);
            *secs += gap.as_secs_f64();
        }
    }

    /// 这一段攒下的点，加上从节点的点算出来的网络的合计。之后从空的开始攒下一段。
    fn take_points(&mut self, at: Timestamp) -> Vec<StatPoint> {
        let acc = std::mem::take(&mut self.acc);
        let mut totals: BTreeMap<(NetworkId, Series), f64> = BTreeMap::new();
        let mut points = Vec::with_capacity(acc.len());
        for ((network, series, node), entry) in acc {
            let Some(value) = entry.value() else { continue };
            let total = match series {
                Series::NodeTx => Some(Series::Tx),
                Series::NodeRx => Some(Series::Rx),
                Series::NodeFlows => Some(Series::Flows),
                Series::Online | Series::Flows | Series::Tx | Series::Rx | Series::RelayAttached | Series::ExitTx | Series::ExitRx => None,
            };
            if let Some(total) = total {
                *totals.entry((network, total)).or_default() += value;
            }
            points.push(StatPoint { network, series, node, at, value });
        }
        // 正好留出合计的地方：数据库写不进去时这些点要在内存里留很久，不让它翻倍长出空位。
        points.reserve_exact(totals.len());
        points.extend(totals.into_iter().map(|((network, series), value)| StatPoint { network, series, node: None, at, value }));
        points
    }

    fn forget(&mut self, node: NodeId) {
        self.counters.retain(|(counted, _), _| *counted != node);
        self.attached.remove(&node);
    }

    /// 写不进去时，早于 5 分钟的点的保留期的段不再留着：写下去也马上会被清掉。数据库一直写不进去时，内存里最多留这么久的。
    /// 只在写失败之后丢：写得进去的话照样写下、汇总它所在的小时，再清掉（主机睡了一天多、时钟往前跳了，刚过完的那一段就是这样）。
    fn let_go_of_expired(&mut self) {
        let Some(now_bucket) = self.bucket else { return };
        let kept = self.unwritten.split_off(&now_bucket.saturating_sub(FINE_KEEP));
        let expired = std::mem::replace(&mut self.unwritten, kept);
        if let Some(first) = expired.keys().next() {
            tracing::warn!(from = first, segments = expired.len(), "时间序列有几段一直没能写下，过了保留期，不要了");
        }
        if self.unwritten.is_empty() {
            self.write_after = None;
        }
    }
}

impl Controller {
    /// 一条序列在一段时间里的点（`GET …/stats`）。
    ///
    /// # Errors
    ///
    /// 没有这个网络或者节点；节点的序列没有写节点，网络的序列写了节点；时间范围或者步长不对；读存储失败。
    pub fn series(&self, network: NetworkId, query: &SeriesQuery) -> Result<SeriesView, Error> {
        let inner = self.lock();
        let network = inner.require_network(network)?;
        let node = match (query.series.per_node(), query.node) {
            (true, Some(id)) => Some(inner.require_node(network.id, id).in_field("node")?.to_ref()),
            (true, None) => return Err(Error::invalid_field("node", "required", format!("序列 {} 要写是哪个节点", query.series))),
            (false, Some(_)) => return Err(Error::invalid_field("node", "not_allowed", format!("序列 {} 是整个网络的", query.series))),
            (false, None) => None,
        };
        let now = inner.clock.now();
        let to = query.to.unwrap_or(now);
        let from = query.from.unwrap_or_else(|| to.saturating_sub(FINE_KEEP));
        if from > to {
            return Err(Error::invalid_field("from", "out_of_range", "开始的时间不能晚于结束的时间"));
        }
        let step = match query.step {
            Some(step @ (FINE_STEP | COARSE_STEP)) => step,
            Some(_) => return Err(Error::invalid_field("step", "out_of_range", format!("步长只能是 {FINE_STEP} 或 {COARSE_STEP} 秒"))),
            // 开始的时间比细的一档的保留期早不到一段，也用细的一档。客户端按它自己的钟算"24 小时之前"（命令行默认就查这么久），
            // 算完还要先查别的，请求到这里时这里的钟已经过了零点几秒到几秒，两边的钟也可能差一点：严格地比，同一条命令时而
            // 得到 5 分钟一个的点，时而得到 1 小时一个。早出来的不到一段，最多让最早那个点落在已经清掉的一段里，是空的。
            None if from >= now.saturating_sub(FINE_KEEP + u64::from(FINE_STEP)) => FINE_STEP,
            None => COARSE_STEP,
        };
        let span = u64::from(step);
        let first = from - from % span;
        // 只到最后一段过完了的：正在攒的那一段还没有点，画出来会是一个假的断口。
        let last_complete = (now - now % span).saturating_sub(span);
        let last = (to - to % span).min(last_complete);
        if last >= first && (last - first) / span >= MAX_POINTS {
            return Err(Error::invalid_field(
                "from",
                "too_many",
                format!("一次最多读 {MAX_POINTS} 个点，把时间范围缩短或者用大一些的步长"),
            ));
        }
        let stored: BTreeMap<Timestamp, f64> =
            inner.store.stats(network.id, query.series, query.node, step, (first, last))?.into_iter().collect();
        let points = if last >= first {
            (0..=(last - first) / span).map(|index| first + index * span).map(|at| (at, stored.get(&at).copied())).collect()
        } else {
            Vec::new()
        };
        Ok(SeriesView { series: query.series, node, unit: query.series.unit(), step, from: first, to: last.max(first), points })
    }
}

impl Inner {
    /// 一个节点的上报里给时间序列用的数，挂靠的 relay 除外（见 [`Self::stats_attached`]）。
    pub(super) fn stats_reported(&mut self, node: &NodeRecord, report: &Report) {
        let now = Instant::now();
        let (network, id) = (node.network, Some(node.id));
        let stats = &mut self.stats;
        stats.counter((network, Series::NodeTx, id), report.run, report.tx_bytes, now);
        stats.counter((network, Series::NodeRx, id), report.run, report.rx_bytes, now);
        stats.gauge((network, Series::NodeFlows, id), f64::from(report.flows));
        if let Some(exit) = report.exit.as_deref().filter(|_| node.exit.is_some()) {
            stats.counter((network, Series::ExitTx, id), report.run, exit.bytes_to_target, now);
            stats.counter((network, Series::ExitRx, id), report.run, exit.bytes_from_target, now);
        }
    }

    /// 一个节点最近一次报的挂靠的 relay。`attached` 是核对过、去掉了重复的那一份，和存下来的是同一份。
    pub(super) fn stats_attached(&mut self, node: &NodeRecord, attached: &[Attachment]) {
        self.stats.attached.insert(node.id, (node.network, attached.iter().map(|attachment| attachment.relay).collect()));
    }

    /// 节点删掉了：它的计数不用再记着。已经写下的点留到过了保留期。
    pub(super) fn stats_forget(&mut self, node: NodeId) {
        self.stats.forget(node);
    }

    /// 到点了就数一次、写一个点、整点时汇总和清理。返回下一次要叫它的时刻。
    pub(super) fn stats_tick(&mut self, now: Instant, wall: Timestamp) -> Result<Instant, Error> {
        let span = u64::from(FINE_STEP);
        let bucket = wall - wall % span;
        // 先把过完了的那一段收起来，再数、再写。收起来不碰存储，存储出错也不会让新的数混进上一段。
        match self.stats.bucket {
            Some(current) if current < bucket => {
                self.stats.bucket = Some(bucket);
                let points = self.stats.take_points(current);
                self.stats.unwritten.insert(current, points);
            }
            Some(_) => {}
            None => self.stats.bucket = Some(bucket),
        }
        if self.stats.next_sample.is_none_or(|at| at <= now) {
            self.stats.next_sample = Some(now + SAMPLE_EVERY);
            self.sample()?;
        }
        if !self.stats.unwritten.is_empty() && self.stats.write_after.is_none_or(|at| at <= now) {
            self.stats.write_after = Some(now + WRITE_RETRY);
            if let Err(err) = self.write_oldest_hour() {
                self.stats.let_go_of_expired();
                return Err(err);
            }
            self.stats.write_after = None;
        }
        let boundary = now + Duration::from_secs(bucket + span - wall);
        // 还有没写下的段时：上次没写成功的话到点再试；不然是攒了好几个小时（数据库很久没写进去），马上再来写下一个小时，
        // 这中间锁让出去。都写下了（或者过了保留期丢了）就不用为它回来。
        let write = (!self.stats.unwritten.is_empty()).then(|| self.stats.write_after.unwrap_or(now));
        Ok([self.stats.next_sample, write].into_iter().flatten().fold(boundary, Instant::min))
    }

    /// 数一次在线的节点和每个 relay 上挂着的在线节点。
    fn sample(&mut self) -> Result<(), Error> {
        let mut online: BTreeMap<NetworkId, u32> = self.store.networks()?.into_iter().map(|network| (network.id, 0)).collect();
        for live in self.live.values() {
            *online.entry(live.network).or_default() += 1;
        }
        let mut attached: BTreeMap<(NetworkId, NodeId), u32> =
            self.store.relay_nodes()?.into_iter().map(|(network, relay)| ((network, relay), 0)).collect();
        for (node, (network, relays)) in &self.stats.attached {
            if !self.live.contains_key(node) {
                continue;
            }
            for relay in relays {
                if let Some(count) = attached.get_mut(&(*network, *relay)) {
                    *count += 1;
                }
            }
        }
        for (network, count) in online {
            self.stats.gauge((network, Series::Online, None), f64::from(count));
        }
        for ((network, relay), count) in attached {
            self.stats.gauge((network, Series::RelayAttached, Some(relay)), f64::from(count));
        }
        Ok(())
    }

    /// 写下过完了的段里最早的那个小时的；这个小时过完了的话，顺带汇总它。过完了的小时都写下了，再清掉过了保留期的点。
    /// 都在一个事务里：提交了才从内存里清掉，没提交就原样留着下次再写。一次只写一个小时，
    /// 数据库很久没写进去、攒了很多段时，不在一个事务里拿着锁写上十几秒。
    fn write_oldest_hour(&mut self) -> Result<(), Error> {
        let (Some(now_bucket), Some(&oldest)) = (self.stats.bucket, self.stats.unwritten.keys().next()) else { return Ok(()) };
        let hour = u64::from(COARSE_STEP);
        let this_hour = oldest - oldest % hour;
        let next_hour = this_hour + hour;
        let current_hour = now_bucket - now_bucket % hour;
        let hour_over = next_hour <= current_hour;
        let unwritten = &self.stats.unwritten;
        // 后面还有过完了的小时没写下（攒了一天左右，一次写一个小时）的话先不清：写下一个小时时还要再汇总一次这个小时，
        // 它的 5 分钟的点清掉了一部分的话，就拿剩下的那些算错了，换掉这次算对了的。也省得每写一个小时就把整张表扫两遍。
        let prune = hour_over && unwritten.range(next_hour..current_hour).next().is_none();
        let written = self.store.atomically(|store| {
            // 这几段里删掉了的网络，它的点不写：存储里没有它了（外键也不让写）。
            let networks: BTreeSet<NetworkId> = store.networks()?.into_iter().map(|network| network.id).collect();
            let points: Vec<StatPoint> = unwritten
                .range(..next_hour)
                .flat_map(|(_, points)| points)
                .filter(|point| networks.contains(&point.network))
                .copied()
                .collect();
            store.insert_stats(FINE_STEP, &points)?;
            if hour_over {
                // 这个小时，和再上一个（controller 正好在整点前后重启过的话那一个还没有汇总）。重复汇总只是换成同样的值：
                // 清理要等到过完了的小时都写下，那之前它们的 5 分钟的点都还在。
                store.roll_up_stats(FINE_STEP, COARSE_STEP, this_hour)?;
                store.roll_up_stats(FINE_STEP, COARSE_STEP, this_hour.saturating_sub(hour))?;
            }
            if prune {
                store.prune_stats(FINE_STEP, now_bucket.saturating_sub(FINE_KEEP))?;
                store.prune_stats(COARSE_STEP, now_bucket.saturating_sub(COARSE_KEEP))?;
            }
            Ok::<_, Error>(points.len())
        })?;
        let segments = unwritten.range(..next_hour).count();
        tracing::debug!(hour = this_hour, segments, points = written, hour_over, prune, "写下了时间序列过完了的段");
        self.stats.unwritten = self.stats.unwritten.split_off(&next_hour);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::testing::Lab;

    const NET: NetworkId = NetworkId(1);

    fn node(raw: u32) -> Option<NodeId> {
        NodeId::new(raw)
    }

    #[test]
    fn a_rate_is_the_increase_over_the_time_it_took_and_a_restart_or_a_drop_is_skipped() {
        let mut collector = Collector::default();
        let start = Instant::now();
        let key = (NET, Series::NodeTx, node(3));
        collector.counter(key, 7, 1_000, start);
        collector.counter(key, 7, 11_000, start + Duration::from_secs(10));
        collector.counter(key, 8, 50, start + Duration::from_secs(20));
        collector.counter(key, 8, 10, start + Duration::from_secs(30));
        collector.counter(key, 8, 1_010, start + Duration::from_secs(40));
        collector.counter(key, 8, 99_999_999, start + Duration::from_secs(400));
        let points = collector.take_points(600);
        let rate = points.iter().find(|point| point.series == Series::NodeTx).unwrap().value;
        assert!((rate - 550.0).abs() < 1e-9, "两段：10000 字节 10 秒、1000 字节 10 秒；重启、变小和隔太久的都不算：{rate}");
        assert!(points.iter().all(|point| point.value >= 0.0));
    }

    #[test]
    fn points_of_a_network_deleted_during_the_bucket_are_dropped_and_the_rest_written() {
        let lab = Lab::new();
        let kept = lab.network("home");
        let gone = lab.network("lab");
        let now = Instant::now();
        let wall = lab.controller.lock().clock.now();
        // 一个小时的第一段：下一段还在同一个小时里，不汇总。
        let bucket = wall - wall % u64::from(COARSE_STEP);
        lab.controller.lock().stats_tick(now, bucket).unwrap();
        lab.controller.delete_network(gone.id).unwrap();
        lab.controller.lock().stats_tick(now, bucket + u64::from(FINE_STEP)).unwrap();
        let inner = lab.controller.lock();
        assert_eq!(inner.store.stats(kept.id, Series::Online, None, FINE_STEP, (bucket, bucket)).unwrap(), [(bucket, 0.0)]);
        assert_eq!(inner.store.stats_count().unwrap(), 1);
    }

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn a_segment_the_store_would_not_take_is_written_once_it_takes_writes_again() {
        let mut lab = Lab::new();
        let network = lab.network("home");
        let _a = lab.join(network.id, &[]);
        let start = Instant::now();
        let wall = lab.controller.lock().clock.now();
        // 一个小时的最后一段：没写下的这一段跨过了整点，补写时还要汇总这个小时。
        let hour_start = wall - wall % u64::from(COARSE_STEP);
        let ended = hour_start + u64::from(COARSE_STEP - FINE_STEP);
        let next = hour_start + u64::from(COARSE_STEP);
        let tick = |lab: &Lab, after: Duration, wall| lab.controller.lock().stats_tick(start + after, wall);
        tick(&lab, Duration::ZERO, ended).unwrap();
        // 这一段数过了；再来一个节点，下一段数到的是两个。
        let _b = lab.join(network.id, &[]);

        lab.controller.lock().store.set_read_only(true);
        assert!(tick(&lab, Duration::ZERO, next).is_err());
        assert!(tick(&lab, MINUTE, next + 60).is_err(), "隔一会儿再试，还是写不进去；这次数到的两个节点算下一段的");
        lab.controller.lock().store.set_read_only(false);
        tick(&lab, 2 * MINUTE, next + 120).unwrap();

        let online = |step, at| lab.controller.lock().store.stats(network.id, Series::Online, None, step, (at, at)).unwrap();
        assert_eq!(online(FINE_STEP, ended), [(ended, 1.0)], "能写了之后补上那一段");
        assert_eq!(online(COARSE_STEP, hour_start), [(hour_start, 1.0)], "也汇总了它所在的小时");
        tick(&lab, 2 * MINUTE, next + u64::from(FINE_STEP)).unwrap();
        assert_eq!(online(FINE_STEP, ended), [(ended, 1.0)], "补上的不再变");
        assert_eq!(online(FINE_STEP, next), [(next, 2.0)], "下一段只有它自己数到的");
    }

    #[test]
    fn segments_left_unwritten_past_the_fine_retention_are_let_go() {
        let lab = Lab::new();
        lab.network("home");
        let start = Instant::now();
        let mut inner = lab.controller.lock();
        let wall = inner.clock.now();
        let step = u64::from(FINE_STEP);
        let first = wall - wall % step;
        inner.stats_tick(start, first).unwrap();
        inner.store.set_read_only(true);
        assert!(inner.stats_tick(start, first + step).is_err());
        assert!(inner.stats_tick(start + MINUTE, first + FINE_KEEP + step).is_err());
        assert_eq!(inner.stats.unwritten.keys().copied().collect::<Vec<_>>(), [first + step], "早于 24 小时的那一段不再留着");
    }

    #[test]
    fn a_segment_closed_more_than_a_day_late_still_counts_towards_its_hour() {
        // 主机睡了一天多（或者时钟往前跳了）：刚过完的那一段已经过了 5 分钟的点的保留期，它的小时还是要汇总。
        let lab = Lab::new();
        let network = lab.network("home");
        let start = Instant::now();
        let mut inner = lab.controller.lock();
        let wall = inner.clock.now();
        let hour_start = wall - wall % u64::from(COARSE_STEP);
        inner.stats_tick(start, hour_start).unwrap();
        inner.stats_tick(start, hour_start + u64::from(FINE_STEP) + FINE_KEEP).unwrap();
        let hourly = inner.store.stats(network.id, Series::Online, None, COARSE_STEP, (hour_start, hour_start)).unwrap();
        assert_eq!(hourly, [(hour_start, 0.0)]);
        assert!(inner.stats.unwritten.is_empty());
    }

    #[test]
    fn a_backlog_is_written_an_hour_at_a_time_coming_straight_back_for_the_next() {
        let lab = Lab::new();
        let network = lab.network("home");
        let start = Instant::now();
        let mut inner = lab.controller.lock();
        let wall = inner.clock.now();
        let fine = u64::from(FINE_STEP);
        let h0 = wall - wall % u64::from(COARSE_STEP);
        let h1 = h0 + u64::from(COARSE_STEP);
        // h0 的最后一段和 h1 的第一段都没写进去，各数到过一次。
        inner.stats_tick(start, h1 - fine).unwrap();
        inner.store.set_read_only(true);
        assert!(inner.stats_tick(start + MINUTE, h1).is_err());
        assert!(inner.stats_tick(start + 2 * MINUTE, h1 + fine).is_err());
        inner.store.set_read_only(false);

        let now = start + 3 * MINUTE;
        assert_eq!(inner.stats_tick(now, h1 + fine).unwrap(), now, "写了 h0 的，马上再来");
        assert_eq!(inner.stats.unwritten.keys().copied().collect::<Vec<_>>(), [h1]);
        let online =
            |inner: &crate::controller::Inner, step, at| inner.store.stats(network.id, Series::Online, None, step, (at, at)).unwrap();
        assert_eq!(online(&inner, COARSE_STEP, h0), [(h0, 0.0)], "h0 过完了，写下时汇总");
        assert!(inner.stats_tick(now, h1 + fine).unwrap() > now, "都写完了，不用马上再来");
        assert!(inner.stats.unwritten.is_empty());
        assert_eq!(online(&inner, FINE_STEP, h1), [(h1, 0.0)]);
        assert!(online(&inner, COARSE_STEP, h1).is_empty(), "h1 还没过完，不汇总");
    }

    #[test]
    fn a_failed_write_is_not_tried_again_before_the_retry_is_due() {
        let lab = Lab::new();
        lab.network("home");
        let start = Instant::now();
        let mut inner = lab.controller.lock();
        let wall = inner.clock.now();
        let fine = u64::from(FINE_STEP);
        let next = wall - wall % fine + fine;
        let secs = Duration::from_secs;
        inner.stats_tick(start, next - 30).unwrap();
        inner.store.set_read_only(true);
        assert!(inner.stats_tick(start + secs(30), next).is_err());
        assert_eq!(
            inner.stats_tick(start + secs(70), next + 40).unwrap(),
            start + secs(30) + WRITE_RETRY,
            "隔了不到一分钟：数照样数，不再试着写、也不报错，到点再来"
        );
        assert_eq!(inner.stats.unwritten.keys().copied().collect::<Vec<_>>(), [next - fine]);
        assert!(inner.stats_tick(start + secs(30) + WRITE_RETRY, next + 60).is_err(), "到点了再试");
    }

    #[test]
    fn letting_go_of_every_unwritten_segment_leaves_nothing_to_come_back_for() {
        // 主机睡了一天多，醒来时数据库正好写不进去：刚过完的那一段过了保留期，丢了之后没有要写的了，不能一直说马上回来。
        let lab = Lab::new();
        lab.network("home");
        let start = Instant::now();
        let mut inner = lab.controller.lock();
        let wall = inner.clock.now();
        let fine = u64::from(FINE_STEP);
        let first = wall - wall % fine;
        inner.stats_tick(start, first).unwrap();
        inner.store.set_read_only(true);
        let late = first + fine + FINE_KEEP;
        assert!(inner.stats_tick(start, late).is_err());
        assert!(inner.stats.unwritten.is_empty());
        let now = start + WRITE_RETRY;
        assert!(inner.stats_tick(now, late + 60).unwrap() > now);
    }

    #[test]
    fn a_day_long_backlog_written_an_hour_at_a_time_keeps_each_hour_s_roll_up() {
        // 写不进去了一天左右，在不是整点的时候恢复：最早那个小时的前半个小时的点早就写下了，已经过了保留期。
        // 写第二个小时时要再汇总一次第一个小时，那时它前半个小时的点还得在。
        let lab = Lab::new();
        let network = lab.network("home");
        let start = Instant::now();
        let mut inner = lab.controller.lock();
        let wall = inner.clock.now();
        let fine = u64::from(FINE_STEP);
        let h0 = wall - wall % u64::from(COARSE_STEP);
        let half = h0 + 6 * fine;
        // 前半个小时在线的有 10 个，故障之前写下了；后半个小时一个都没有，没写进去。
        let before: Vec<StatPoint> = (0..6)
            .map(|index| StatPoint { network: network.id, series: Series::Online, node: None, at: h0 + index * fine, value: 10.0 })
            .collect();
        inner.store.insert_stats(FINE_STEP, &before).unwrap();
        inner.stats_tick(start, half).unwrap();
        inner.store.set_read_only(true);
        let back = half + FINE_KEEP;
        let mut now = start;
        for at in (half + fine..back).step_by(usize::try_from(fine).unwrap()) {
            now += Duration::from_secs(fine);
            assert!(inner.stats_tick(now, at).is_err());
        }
        inner.store.set_read_only(false);
        now += Duration::from_secs(fine);

        let online = |inner: &Inner, step, range| inner.store.stats(network.id, Series::Online, None, step, range).unwrap();
        assert_eq!(inner.stats_tick(now, back).unwrap(), now, "写了 h0 的，马上再来");
        assert_eq!(online(&inner, COARSE_STEP, (h0, h0)), [(h0, 5.0)]);
        assert_eq!(inner.stats_tick(now, back).unwrap(), now, "写了 h1 的，马上再来");
        assert_eq!(online(&inner, COARSE_STEP, (h0, h0)), [(h0, 5.0)], "写 h1 时又汇总了一次 h0，前半个小时的点还在");
        assert_eq!(online(&inner, FINE_STEP, (h0, half - fine)).len(), 6, "过完了的小时还没都写下，先不清");
        for _ in 0..30 {
            if inner.stats.unwritten.is_empty() {
                break;
            }
            inner.stats_tick(now, back).unwrap();
        }
        assert!(inner.stats.unwritten.is_empty());
        assert_eq!(online(&inner, COARSE_STEP, (h0, h0)), [(h0, 5.0)]);
        assert!(online(&inner, FINE_STEP, (h0, half - fine)).is_empty(), "都写下了，过了保留期的清掉");
        assert_eq!(online(&inner, FINE_STEP, (half, back - fine)).len(), 288, "没过保留期的一段不少");
    }

    #[test]
    fn a_network_deleted_while_the_store_would_not_take_writes_does_not_hold_up_the_rest() {
        let lab = Lab::new();
        let kept = lab.network("home");
        let gone = lab.network("lab");
        let start = Instant::now();
        let fine = u64::from(FINE_STEP);
        let wall = lab.controller.lock().clock.now();
        let h1 = wall - wall % u64::from(COARSE_STEP) + u64::from(COARSE_STEP);
        let tick = |after: Duration, wall| lab.controller.lock().stats_tick(start + after, wall);
        // 两个网络都数到了：上一个小时的最后一段和这个小时的第一段都没写进去。
        tick(Duration::ZERO, h1 - fine).unwrap();
        lab.controller.lock().store.set_read_only(true);
        assert!(tick(MINUTE, h1).is_err());
        assert!(tick(2 * MINUTE, h1 + fine).is_err());
        lab.controller.lock().store.set_read_only(false);
        // 等着再试的这一会儿里删了一个网络。
        lab.controller.delete_network(gone.id).unwrap();

        assert_eq!(tick(3 * MINUTE, h1 + fine).unwrap(), start + 3 * MINUTE, "写了上一个小时的，马上再来");
        tick(3 * MINUTE, h1 + fine).unwrap();
        let inner = lab.controller.lock();
        assert!(inner.stats.unwritten.is_empty());
        let online = |step, range| inner.store.stats(kept.id, Series::Online, None, step, range).unwrap();
        assert_eq!(online(FINE_STEP, (h1 - fine, h1)), [(h1 - fine, 0.0), (h1, 0.0)]);
        assert_eq!(online(COARSE_STEP, (h1 - u64::from(COARSE_STEP), h1)), [(h1 - u64::from(COARSE_STEP), 0.0)]);
        assert_eq!(inner.store.stats_count().unwrap(), 3, "删了的网络的点没写");
    }

    #[test]
    fn the_segment_moves_on_when_other_background_work_fails_first() {
        // 数据库写不进去时，清理过期令牌这些排在前面的后台工作先出错。时间序列照样要切段，不然这期间上报的数都算进上一段。
        let lab = Lab::new();
        lab.network("home");
        let start = Instant::now();
        let mut inner = lab.controller.lock();
        let wall = inner.clock.now();
        let fine = u64::from(FINE_STEP);
        let first = wall - wall % fine;
        inner.tick(start, first).unwrap();
        inner.store.set_read_only(true);
        assert!(inner.tick(start + MINUTE, first + fine).is_err());
        assert_eq!(inner.stats.bucket, Some(first + fine));
        assert_eq!(inner.stats.unwritten.keys().copied().collect::<Vec<_>>(), [first]);
        let second = Duration::from_secs(1);
        assert!(inner.tick(start + MINUTE + second, first + fine + 1).is_ok(), "清理和写时间序列都还没到再试的时候，一秒之后不再报错");
    }

    #[test]
    fn a_range_that_starts_a_moment_before_the_fine_retention_still_gets_fine_points() {
        // 命令行按它自己的钟算"24 小时之前"，再查一两样别的，请求到这里时这里的钟已经过了一两秒：同一条命令不能因为
        // 这一两秒，时而得到 5 分钟一个的点，时而得到 1 小时一个（Windows 上冒烟测试就这样时不时失败过）。
        let lab = crate::controller::testing::Lab::new();
        let network = lab.network("home");
        let now = lab.controller.lock().clock.now();
        let step = |from| {
            let query = SeriesQuery { series: Series::Online, node: None, from: Some(from), to: None, step: None };
            lab.controller.series(network.id, &query).unwrap().step
        };
        assert_eq!(step(now - FINE_KEEP), FINE_STEP);
        assert_eq!(step(now - FINE_KEEP - 2), FINE_STEP, "早了两秒还是同一档");
        assert_eq!(step(now - FINE_KEEP - u64::from(FINE_STEP) - 2), COARSE_STEP, "早了一段以上，要的是更久的历史");
    }

    #[test]
    fn gauges_are_averaged_and_node_series_add_up_to_the_network() {
        let mut collector = Collector::default();
        let now = Instant::now();
        collector.gauge((NET, Series::NodeFlows, node(3)), 2.0);
        collector.gauge((NET, Series::NodeFlows, node(3)), 4.0);
        collector.gauge((NET, Series::NodeFlows, node(4)), 1.0);
        collector.counter((NET, Series::NodeRx, node(4)), 1, 0, now);
        collector.counter((NET, Series::NodeRx, node(4)), 1, 600, now + Duration::from_secs(6));
        let points = collector.take_points(900);
        let value = |series, node| points.iter().find(|point| point.series == series && point.node == node).map(|point| point.value);
        assert_eq!(value(Series::NodeFlows, self::node(3)), Some(3.0));
        assert_eq!(value(Series::Flows, None), Some(4.0));
        assert_eq!(value(Series::Rx, None), Some(100.0));
        assert_eq!(value(Series::Tx, None), None, "没有数的序列没有点，图上是断开的");
        assert!(collector.take_points(1200).is_empty(), "写过之后从空的开始");
    }
}
