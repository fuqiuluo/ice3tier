//! 出口上的约束：配额与账期、建连预算。
//!
//! 它们只管出口替别人搬运的互联网和局域网目标的流量，也就是"经这个出口出去"的那些。访问本节点自己的服务、
//! 下发给本节点的端口转发是组网内部的流量，不受这些约束，也不算进配额。
//!
//! | 约束 | 设置 | 做法 |
//! |---|---|---|
//! | 配额 | `quota_bytes`、`quota_reset_day` | 本账期两个方向相加的字节数。用完之后新的请求被拒绝，正在搬运的流在超出的那一刻被断开 |
//! | 建连预算 | `connects_per_minute` | 每个（发起节点，目标）一个令牌桶：可以一下子用完一分钟的额度，之后按每分钟这么多恢复 |
//!
//! 出口没有带宽上限：搬运多快只看两端和路上。relay 的带宽上限是另一回事，在 relay 那边（`i3t-relay`）。
//!
//! 账期按 UTC 计算：每月 `quota_reset_day` 日 0 点开启新账期。未配置配额时仍会统计本账期用量，
//! 以便中途启用配额时，本账期已消耗的流量计入统计。
//!
//! 配额用量需跨重启持久化：[`QuotaState`] 由装配层定期保存，启动时通过 [`crate::Exit::with_quota_state`] 恢复。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use i3t_flow::{Direction, Meter};
use i3t_model::netmap::ExitRole;
use i3t_proto::NodeId;
use i3t_proto::flow::Reason;
use tokio::time::Instant;

/// 建连预算最多记这么多个（发起节点，目标）。满了先清掉额度已经回满的，那些和没有记录一样。
const MAX_BUDGETS: usize = 4096;
const SECS_PER_DAY: u64 = 24 * 60 * 60;

/// 配额要跨重启保留的那一部分。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuotaState {
    /// 这份用量属于哪个账期：账期开始的时刻，Unix 秒。
    pub period_start: u64,
    pub used_bytes: u64,
}

/// 一个账期：从 `start` 起，到 `end` 为止（不含），Unix 秒。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Period {
    pub start: u64,
    pub end: u64,
}

impl Period {
    /// `now` 所在的账期：每个月 `reset_day` 号（UTC）0 点开始。`reset_day` 超出 1～28 时按最近的一端算。
    #[must_use]
    pub fn containing(now: u64, reset_day: u8) -> Self {
        let day = i64::from(reset_day.clamp(1, 28));
        let today = i64::try_from(now / SECS_PER_DAY).expect("u64 的秒数除以一天的秒数放得进 i64");
        let (year, month, mday) = civil_from_days(today);
        let (start_year, start_month) = if mday >= day { (year, month) } else { previous_month(year, month) };
        let (end_year, end_month) = next_month(start_year, start_month);
        let at = |year, month| u64::try_from(days_from_civil(year, month, day)).map_or(0, |days| days * SECS_PER_DAY);
        Self { start: at(start_year, start_month), end: at(end_year, end_month) }
    }
}

const fn previous_month(year: i64, month: i64) -> (i64, i64) {
    if month == 1 { (year - 1, 12) } else { (year, month - 1) }
}

const fn next_month(year: i64, month: i64) -> (i64, i64) {
    if month == 12 { (year + 1, 1) } else { (year, month + 1) }
}

/// 公历日期（年、月 1～12、日 1～31）到 1970-01-01 起的天数。Howard Hinnant 的 `days_from_civil`。
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// [`days_from_civil`] 反过来。
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 { month_from_march + 3 } else { month_from_march - 9 };
    let year = year_of_era + era * 400;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// 配额的账本。
#[derive(Debug, Clone)]
pub(crate) struct Quota {
    limit: Option<u64>,
    reset_day: u8,
    period: Option<Period>,
    used: u64,
}

impl Quota {
    fn restored(state: QuotaState) -> Self {
        // 账期边界要等知道 reset_day 之后才算得出来；先把用量和它所属的账期记下，第一次结算时对一下。
        let period = (state.period_start != 0).then_some(Period { start: state.period_start, end: state.period_start });
        Self { limit: None, reset_day: 1, period, used: state.used_bytes }
    }

    fn configure(&mut self, limit: Option<u64>, reset_day: u8) {
        if (self.limit, self.reset_day) != (limit, reset_day) {
            tracing::info!(?limit, reset_day, "出口配额配置已变更");
        }
        self.limit = limit;
        self.reset_day = reset_day;
    }

    /// 走到 `now` 所在的账期。换了账期（包括改了每月的起始日）时用量从零算。
    fn roll(&mut self, now: u64) -> Period {
        let current = Period::containing(now, self.reset_day);
        if self.period.is_none_or(|period| period.start != current.start) {
            if self.used > 0 {
                tracing::info!(used = self.used, start = current.start, "出口进入新账期，用量计数已归零");
            }
            self.used = 0;
        }
        self.period = Some(current);
        current
    }

    /// 本账期的用量是不是已经到了配额。
    fn exhausted(&mut self, now: u64) -> bool {
        self.roll(now);
        self.limit.is_some_and(|limit| self.used >= limit)
    }

    /// 记录 `bytes` 字节流量。计入后若超出配额则返回 `false`，表示该段数据不应继续发送。
    fn charge(&mut self, bytes: u64, now: u64) -> bool {
        self.roll(now);
        self.used = self.used.saturating_add(bytes);
        self.limit.is_none_or(|limit| self.used <= limit)
    }

    fn state(&self) -> QuotaState {
        QuotaState { period_start: self.period.map_or(0, |period| period.start), used_bytes: self.used }
    }

    fn usage(&mut self, now: u64) -> Option<QuotaUsage> {
        let period = self.roll(now);
        let limit = self.limit?;
        Some(QuotaUsage { limit_bytes: limit, used_bytes: self.used, period })
    }
}

/// 配了配额时本账期用到了哪里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaUsage {
    pub limit_bytes: u64,
    pub used_bytes: u64,
    pub period: Period,
}

/// 建连预算：每个（发起节点，目标）一个令牌桶，单位是"一次建连"。
#[derive(Debug, Default)]
struct ConnectBudget {
    per_minute: Option<u32>,
    buckets: HashMap<(NodeId, String), (f64, Instant)>,
}

impl ConnectBudget {
    fn configure(&mut self, per_minute: Option<u32>) {
        if self.per_minute != per_minute {
            tracing::info!(?per_minute, "出口建连预算配置已变更");
            self.per_minute = per_minute;
            self.buckets.clear();
        }
    }

    /// `peer` 现在能不能再向 `target` 建一条连接。能的话算它用掉一次。
    fn admit(&mut self, peer: NodeId, target: &str, now: Instant) -> bool {
        let Some(per_minute) = self.per_minute else { return true };
        let capacity = f64::from(per_minute);
        let per_sec = capacity / 60.0;
        let refilled = |(tokens, at): (f64, Instant)| (tokens + now.saturating_duration_since(at).as_secs_f64() * per_sec).min(capacity);
        if self.buckets.len() >= MAX_BUDGETS {
            self.buckets.retain(|_, bucket| refilled(*bucket) < capacity);
        }
        let entry = self.buckets.entry((peer, target.to_owned())).or_insert((capacity, now));
        let tokens = refilled(*entry);
        if tokens < 1.0 {
            *entry = (tokens, now);
            return false;
        }
        *entry = (tokens - 1.0, now);
        true
    }
}

/// 出口上的全部约束。各个流共用，所以每一项各有一把锁；锁里只做几次算术。
#[derive(Debug)]
pub(crate) struct Limits {
    quota: Mutex<Quota>,
    budget: Mutex<ConnectBudget>,
}

impl Limits {
    pub(crate) fn new(quota: QuotaState) -> Self {
        Self { quota: Mutex::new(Quota::restored(quota)), budget: Mutex::default() }
    }

    /// 按出口当前的设置调整。设置没变时什么都不做；不是出口时建连预算不限。
    pub(crate) fn configure(&self, role: Option<&ExitRole>) {
        let (limit, reset_day) = role.map_or((None, 1), |role| (role.quota_bytes, role.quota_reset_day));
        self.quota.lock().expect("quota mutex poisoned").configure(limit, reset_day);
        self.budget.lock().expect("connect budget mutex poisoned").configure(role.and_then(|role| role.connects_per_minute));
    }

    /// 本账期的配额是不是已经用完了。
    pub(crate) fn quota_exhausted(&self) -> bool {
        self.quota.lock().expect("quota mutex poisoned").exhausted(wall_clock())
    }

    /// `peer` 现在能不能再向 `target` 建一条连接。
    pub(crate) fn admit_connect(&self, peer: NodeId, target: &str) -> bool {
        self.budget.lock().expect("connect budget mutex poisoned").admit(peer, target, Instant::now())
    }

    /// 一个数据报能不能送出去：记下它的字节数之后配额没有超出。
    pub(crate) fn admit_datagram(&self, len: usize) -> bool {
        // usize 不会比 u64 宽，这里不会截断。
        self.quota.lock().expect("quota mutex poisoned").charge(len as u64, wall_clock())
    }

    pub(crate) fn quota_state(&self) -> QuotaState {
        self.quota.lock().expect("quota mutex poisoned").state()
    }

    pub(crate) fn quota_usage(&self) -> Option<QuotaUsage> {
        self.quota.lock().expect("quota mutex poisoned").usage(wall_clock())
    }

    /// 一段流的数据：记配额。超出配额时返回 `Err`，这段数据不再送出去。
    fn charge_stream(&self, len: usize) -> Result<(), Reason> {
        // usize 不会比 u64 宽，这里不会截断。
        if !self.quota.lock().expect("quota mutex poisoned").charge(len as u64, wall_clock()) {
            tracing::info!("出口本账期流量配额已耗尽，正在断开当前流");
            return Err(Reason::LimitReached);
        }
        Ok(())
    }
}

/// 搬运出口流量时用的关卡：两个方向都记配额。
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExitMeter<'a> {
    pub(crate) limits: &'a Limits,
}

impl Meter for ExitMeter<'_> {
    async fn pass(&self, _direction: Direction, len: usize) -> Result<(), Reason> {
        self.limits.charge_stream(len)
    }
}

/// 现在的 Unix 秒。系统时钟拨到 1970 年之前时当作 0：只影响账期的划分。
fn wall_clock() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// 2026-11-16 00:00:00 UTC。
    const NOV_16: u64 = 1_794_787_200;

    fn date(year: i64, month: i64, day: i64) -> u64 {
        u64::try_from(days_from_civil(year, month, day)).unwrap() * SECS_PER_DAY
    }

    #[test]
    fn civil_dates_round_trip_across_leap_years_and_eras() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(date(2026, 11, 16), NOV_16);
        for days in [-1, 0, 59, 60, 365, 10_957, 11_016, 20_000, 30_000, 2_932_896] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days, "{days} → {year}-{month}-{day}");
        }
        assert_eq!(civil_from_days(days_from_civil(2024, 2, 29)), (2024, 2, 29));
        assert_eq!(civil_from_days(days_from_civil(2024, 2, 29) + 1), (2024, 3, 1));
    }

    #[test]
    fn a_period_runs_from_the_reset_day_to_the_same_day_of_the_next_month() {
        assert_eq!(Period::containing(NOV_16 + 3600, 1), Period { start: date(2026, 11, 1), end: date(2026, 12, 1) });
        assert_eq!(Period::containing(NOV_16, 16), Period { start: NOV_16, end: date(2026, 12, 16) }, "当天 0 点正好是新账期");
        assert_eq!(Period::containing(NOV_16 - 1, 16), Period { start: date(2026, 10, 16), end: NOV_16 }, "前一秒还在上一个账期");
        assert_eq!(Period::containing(date(2026, 12, 31), 28), Period { start: date(2026, 12, 28), end: date(2027, 1, 28) });
        assert_eq!(Period::containing(date(2027, 1, 3), 28), Period { start: date(2026, 12, 28), end: date(2027, 1, 28) }, "跨年");
        assert_eq!(Period::containing(NOV_16, 0), Period::containing(NOV_16, 1), "超出范围的起始日按最近的一端算");
        assert_eq!(Period::containing(NOV_16, 31), Period::containing(NOV_16, 28));
    }

    #[test]
    fn the_quota_runs_out_and_comes_back_at_the_period_boundary() {
        let mut quota = Quota::restored(QuotaState::default());
        quota.configure(Some(1000), 16);
        let before = NOV_16 - 10;
        assert!(quota.charge(600, before));
        assert!(!quota.exhausted(before));
        assert!(!quota.charge(500, before), "记上之后超过了配额");
        assert!(quota.exhausted(before));
        assert_eq!(quota.usage(before).unwrap().used_bytes, 1100);

        assert!(!quota.exhausted(NOV_16), "到了起始日 0 点，新的账期从零算");
        assert_eq!(quota.state(), QuotaState { period_start: NOV_16, used_bytes: 0 });
        assert!(quota.charge(999, NOV_16 + 5));
        assert_eq!(
            quota.usage(NOV_16 + 5),
            Some(QuotaUsage { limit_bytes: 1000, used_bytes: 999, period: Period { start: NOV_16, end: date(2026, 12, 16) } })
        );
    }

    #[test]
    fn usage_is_kept_across_a_restart_within_the_period_and_dropped_after_it() {
        let mut quota = Quota::restored(QuotaState::default());
        quota.configure(Some(1000), 1);
        assert!(quota.charge(700, NOV_16));
        let saved = quota.state();
        assert_eq!(saved, QuotaState { period_start: date(2026, 11, 1), used_bytes: 700 });

        let mut restarted = Quota::restored(saved);
        restarted.configure(Some(1000), 1);
        assert!(restarted.charge(200, NOV_16 + 60));
        assert_eq!(restarted.state().used_bytes, 900, "重启之前的用量还在");
        assert!(!restarted.charge(200, NOV_16 + 61), "再记就超过配额了");

        let mut next_month = Quota::restored(saved);
        next_month.configure(Some(1000), 1);
        assert!(!next_month.exhausted(date(2026, 12, 2)));
        assert_eq!(next_month.state(), QuotaState { period_start: date(2026, 12, 1), used_bytes: 0 }, "重启时已经是下一个账期了");
    }

    #[test]
    fn without_a_quota_usage_is_still_counted_but_never_refused() {
        let mut quota = Quota::restored(QuotaState::default());
        assert!(quota.charge(u64::MAX / 2, NOV_16) && quota.charge(u64::MAX / 2, NOV_16) && quota.charge(10, NOV_16));
        assert!(!quota.exhausted(NOV_16));
        assert_eq!(quota.usage(NOV_16), None, "没有配额就没有配额的用量可报");
        quota.configure(Some(1), 1);
        assert!(quota.exhausted(NOV_16), "中途配上配额时，本账期已经用掉的也算数");
    }

    #[tokio::test]
    async fn the_meter_stops_a_stream_once_the_quota_is_spent() {
        let limits = Limits::new(QuotaState::default());
        limits.configure(Some(&ExitRole { quota_bytes: Some(40_000), ..ExitRole::default() }));
        let meter = ExitMeter { limits: &limits };
        assert!(meter.pass(Direction::FromTcp, 16_384).await.is_ok());
        assert!(meter.pass(Direction::FromFlow, 16_384).await.is_ok());
        assert_eq!(meter.pass(Direction::FromTcp, 16_384).await, Err(Reason::LimitReached));
        assert!(limits.quota_exhausted());
        assert!(!limits.admit_datagram(10), "配额用完之后数据报也不放");
    }

    #[test]
    fn the_connect_budget_allows_a_burst_then_refills_per_minute_for_each_peer_and_target() {
        let mut budget = ConnectBudget::default();
        let (a, b) = (NodeId::new(1).unwrap(), NodeId::new(2).unwrap());
        let start = Instant::now();
        assert!((0..100).all(|_| budget.admit(a, "api.example.com:443", start)), "没有配预算时不限");

        budget.configure(Some(6));
        assert!((0..6).all(|_| budget.admit(a, "api.example.com:443", start)), "一下子用完一分钟的额度");
        assert!(!budget.admit(a, "api.example.com:443", start));
        assert!(budget.admit(a, "other.example.com:443", start), "别的目标各算各的");
        assert!(budget.admit(b, "api.example.com:443", start), "别的发起节点各算各的");
        assert!(!budget.admit(a, "api.example.com:443", start + Duration::from_secs(9)), "每 10 秒恢复一次");
        assert!(budget.admit(a, "api.example.com:443", start + Duration::from_secs(10)));
        assert!(!budget.admit(a, "api.example.com:443", start + Duration::from_secs(11)));
    }
}
