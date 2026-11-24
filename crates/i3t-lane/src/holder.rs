//! 接受方一侧：拨号方停在本节点的空闲 lane，本节点要往它开流时从这里取。
//!
//! # 规矩
//!
//! - 驻留的 lane 仅在拨号方控制 lane 存活时使用。控制 lane 断开后立即关闭所有驻留 lane：拨号方大概率已变更地址或重启，
//!   旧 lane 通常已失效且不会收到重置。控制 lane 静默超过两个保活周期即暂停取用（断开判定为三个周期）：
//!   拨号方可能已感知异常并切换 epoch 重拨，此时取出的大概率是已失效的 lane。
//! - 新的控制 lane 带着新的 epoch 来了，不是这个 epoch 的空闲 lane 立刻关掉（家宽重拨之后旧的 lane 不会有任何动静）。
//!   不是当前 epoch 的停车请求不收。
//! - 空闲 lane 仅由本节点关闭（包括多余的逐条回收、旧 epoch 以及对端通知排空的 lane）。拨号方从不主动关闭已驻留的空闲 lane，
//!   因此双方不会在同一条 lane 上产生竞态：本节点刚取出的 lane 不会被拨号方同时关闭。
//! - 补拨由本节点要：本节点确切知道自己手上还有几条空闲的，拨号方要过半个往返才知道哪条被取走了。
//!   每个维护周期（以及有人开始等的时候），缺多少就在控制 lane 上请对方拨多少（POOL 里的 `extra`）：
//!   目标值 + 等待数 − 当前空闲数 − 已请求但尚未到达的数量。已请求数量在 [`REQUEST_TTL`] 内未到达则不再计入（大概率拨号失败），待下一周期重新请求。
//! - 池空时取的一方登记等待，最多等 [`LaneConfig::claim_wait`]。等不到就返回 [`OpenLaneError::PoolDry`]，调用方改走共用的连接。

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use i3t_proto::NodeId;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{self, Instant, MissedTickBehavior};

use crate::demand::{Demand, MAX_IDLE_TARGET};
use crate::endpoint::{Inner, LaneConfig};
use crate::error::{LaneError, OpenLaneError};
use crate::frame::Frame;
use crate::lane::Lane;
use crate::status::Book;

/// 突发时一次最多请对方额外补拨多少条。
pub(crate) const MAX_BURST: usize = 512;
/// 一个拨号方停在本节点的空闲 lane 最多这么多条，再来的直接关掉。
pub(crate) const MAX_IDLE: usize = MAX_IDLE_TARGET + MAX_BURST;

/// 池的维护间隔：更新速率估计、调整目标、关多余的。
const TICK: Duration = Duration::from_millis(100);
/// 多余的空闲 lane 每隔多久关一批。
const TRIM_EVERY: Duration = Duration::from_secs(1);
/// 已请求对端补拨的 lane 计入在途状态的时长。正常补拨耗时两三个往返，超时未到达通常意味着拨号失败。
const REQUEST_TTL: Duration = Duration::from_secs(3);

/// 一个拨号方在本节点的停车场。
#[derive(Default)]
pub(crate) struct Holder {
    control: Option<Control>,
    idle: VecDeque<Lane>,
    waiters: VecDeque<oneshot::Sender<Lane>>,
    demand: Option<Demand>,
    /// 已经请对方补拨、还没到的：请的时刻，和还差几条。
    requested: VecDeque<(Instant, usize)>,
    /// 对端已在当前控制 lane 上发送排空（GoAway）通知。
    going_away: bool,
    /// 上一次在控制 lane 上听到对方的时刻。
    heard: Option<Instant>,
    next_generation: u64,
}

struct Control {
    epoch: u64,
    generation: u64,
    commands: mpsc::UnboundedSender<Command>,
}

enum Command {
    /// 有人取走了一条，或者在等：看要不要请对方补拨。
    Want,
    /// 来了新的控制 lane，或者不再为这个对端开 lane 了：这一条停掉。
    Replace,
    /// 本节点进入排空状态：通知对端。
    GoAway,
}

impl Holder {
    /// 检查当前是否可从池中取出 lane：控制 lane 存活、近期收到过对端消息且对端未通知排空。
    pub(crate) fn available(&self, ping_interval: Duration) -> bool {
        self.control.is_some() && !self.going_away && !self.silent(ping_interval)
    }

    /// 控制 lane 上超过两个保活周期没有听到对方。
    fn silent(&self, ping_interval: Duration) -> bool {
        self.heard.is_some_and(|heard| heard.elapsed() > ping_interval * 2)
    }

    pub(crate) fn idle(&self) -> usize {
        self.idle.len()
    }

    /// 不再为这个对端开 lane：停掉控制 lane，空闲的全部关掉，等着的立刻失败。
    pub(crate) fn close(&mut self) {
        if let Some(control) = self.control.take() {
            // 守控制 lane 的任务已经自己结束（lane 断了）时没有人收：要它停的也就是这个。
            let _ = control.commands.send(Command::Replace);
        }
        self.idle.clear();
        self.waiters.clear();
    }

    pub(crate) fn go_away(&self) {
        if let Some(control) = &self.control {
            // 若维护控制 lane 的任务已结束（lane 已断开），无需再通知对端，可忽略发送失败。
            let _ = control.commands.send(Command::GoAway);
        }
    }

    /// 请过、还在路上的条数。
    fn outstanding(&self) -> usize {
        self.requested.iter().map(|(_, count)| count).sum()
    }

    /// 停过来了一条：在路上的少一条。
    fn arrived(&mut self) {
        if let Some((_, count)) = self.requested.front_mut() {
            *count -= 1;
            if *count == 0 {
                self.requested.pop_front();
            }
        }
    }

    /// 现在要请对方再拨几条，并记下来。
    fn shortfall(&mut self, target: usize, now: Instant) -> usize {
        self.requested.retain(|(at, _)| now.saturating_duration_since(*at) < REQUEST_TTL);
        let waiting = self.waiters.iter().filter(|waiter| !waiter.is_closed()).count();
        let have = self.idle.len() + self.outstanding();
        let more = (target + waiting).saturating_sub(have).min(MAX_BURST).min(MAX_IDLE.saturating_sub(have));
        if more > 0 {
            self.requested.push_back((now, more));
        }
        more
    }
}

/// 从 `peer` 停在本节点的 lane 里取一条。
pub(crate) async fn claim(inner: &Arc<Inner>, peer: NodeId, membership: &watch::Receiver<()>, book: &Book) -> Result<Lane, OpenLaneError> {
    let waiter = {
        let mut peers = inner.lock_peers();
        let holder = &mut peers.get_mut(&peer).filter(|entry| entry.matches(membership)).ok_or(OpenLaneError::NotEnabled(peer))?.holder;
        let silent = holder.silent(inner.config.ping_interval);
        let Some(control) = holder.control.as_ref().filter(|_| !silent) else {
            book.bump(|tally| &tally.claims_failed);
            return Err(OpenLaneError::NoControl(peer));
        };
        if holder.going_away {
            book.bump(|tally| &tally.claims_failed);
            return Err(OpenLaneError::GoingAway(peer));
        }
        book.bump(|tally| &tally.claims);
        holder.demand.get_or_insert_with(|| Demand::new(Instant::now().into_std())).record();
        // 每取走一条都让控制 lane 算一下要不要补：不等下一个维护周期，取得快的时候池才不会在两个周期之间被抽干。
        // 控制 lane 按"还在路上的"去重，连着来的几次只会请一次。
        let _ = control.commands.send(Command::Want);
        // 最新停进来的先用；最老的留给关多余的时候关。死了的在这里被看出来就扔掉。
        while let Some(lane) = holder.idle.pop_back() {
            if lane.is_usable() {
                return Ok(lane);
            }
            tracing::debug!(%peer, "丢弃已由对端关闭的空闲 lane");
        }
        let (sender, receiver) = oneshot::channel();
        holder.waiters.push_back(sender);
        receiver
    };
    book.bump(|tally| &tally.claims_waited);
    let started = Instant::now();
    let outcome = time::timeout(inner.config.claim_wait, waiter).await;
    let waited = started.elapsed();
    book.add(|tally| &tally.claim_wait_micros, usize::try_from(waited.as_micros()).unwrap_or(usize::MAX));
    match outcome {
        Ok(Ok(lane)) => Ok(lane),
        Ok(Err(_)) => {
            book.bump(|tally| &tally.claims_failed);
            Err(OpenLaneError::NoControl(peer))
        }
        Err(_) => {
            book.bump(|tally| &tally.claims_failed);
            inner.log_dry_pool(peer, waited);
            Err(OpenLaneError::PoolDry { peer, waited })
        }
    }
}

/// 拨号方拨来了一条控制 lane。
pub(crate) fn control_arrived(inner: &Arc<Inner>, mut lane: Lane) {
    let peer = lane.peer;
    lane.sealed.allow_unknown_frames();
    let (commands, receiver) = mpsc::unbounded_channel();
    let generation = {
        let mut peers = inner.lock_peers();
        let Some(entry) = peers.get_mut(&peer).filter(|entry| entry.matches(&lane.membership)) else {
            drop(peers);
            return inner.refuse(peer, &lane.membership, "对端 lane 授权已失效");
        };
        let holder = &mut entry.holder;
        if let Some(old) = holder.control.take() {
            // 旧的那条的任务已经自己结束（lane 断了）时没有人收：要它停的也就是这个。
            let _ = old.commands.send(Command::Replace);
        }
        let before = holder.idle.len();
        holder.idle.retain(|idle| idle.epoch == lane.epoch);
        if holder.idle.len() < before {
            tracing::info!(%peer, dropped = before - holder.idle.len(), "对端已切换 epoch（可能重启或变更地址），关闭旧的空闲 lane");
        }
        holder.going_away = false;
        holder.heard = Some(Instant::now());
        holder.requested.clear();
        holder.next_generation += 1;
        let generation = holder.next_generation;
        holder.control = Some(Control { epoch: lane.epoch, generation, commands });
        generation
    };
    tracing::info!(%peer, "对端控制 lane 已建立，可使用其驻留 lane 开流");
    tokio::spawn(serve_control(Arc::clone(inner), lane, generation, receiver));
}

/// 拨号方停过来一条 lane。
pub(crate) fn parked_arrived(inner: &Arc<Inner>, lane: Lane) {
    let peer = lane.peer;
    let mut peers = inner.lock_peers();
    let Some(entry) = peers.get_mut(&peer).filter(|entry| entry.matches(&lane.membership)) else {
        drop(peers);
        return inner.refuse(peer, &lane.membership, "对端 lane 授权已失效");
    };
    let holder = &mut entry.holder;
    let refusal = match &holder.control {
        None => Some("控制 lane 未建立"),
        Some(control) if control.epoch != lane.epoch => Some("epoch 与当前控制 lane 不匹配"),
        Some(_) if holder.going_away => Some("对端正在排空"),
        Some(_) if holder.idle.len() >= MAX_IDLE => Some("空闲驻留 lane 数量已达上限"),
        Some(_) => None,
    };
    if let Some(reason) = refusal {
        drop(peers);
        return inner.refuse(peer, &lane.membership, reason);
    }
    holder.arrived();
    let mut lane = lane;
    while let Some(waiter) = holder.waiters.pop_front() {
        match waiter.send(lane) {
            Ok(()) => return,
            // 那一个已经等不及走了。
            Err(back) => lane = back,
        }
    }
    holder.idle.push_back(lane);
}

/// 服务一条控制 lane，直到它断开、被新的替换，或者本节点关闭。
async fn serve_control(inner: Arc<Inner>, mut lane: Lane, generation: u64, mut commands: mpsc::UnboundedReceiver<Command>) {
    let peer = lane.peer;
    let mut removed = lane.membership.clone();
    let pool = Pool::new(&inner, peer, lane.membership.clone(), generation);
    let reason = tokio::select! {
        _ = removed.changed() => return,
        result = pool.run(&inner, &mut lane, &mut commands) => match result {
            Ok(reason) => reason.to_owned(),
            Err(error) => error.to_string(),
        },
    };
    let mut peers = inner.lock_peers();
    if let Some(entry) = peers.get_mut(&peer)
        && entry.matches(&removed)
        && entry.holder.control.as_ref().is_some_and(|control| control.generation == generation)
    {
        entry.holder.control = None;
        let dropped = entry.holder.idle.len();
        entry.holder.idle.clear();
        // 等着的随之失败（发送端被丢弃），调用方改走共用的连接。
        entry.holder.waiters.clear();
        drop(peers);
        tracing::info!(%peer, dropped, %reason, "对端控制 lane 已断开，关闭其所有空闲驻留 lane，新流回退至共用连接");
    }
}

/// 控制 lane 上这一侧的状态：目标、往返时间、保活。
struct Pool {
    peer: NodeId,
    membership: watch::Receiver<()>,
    generation: u64,
    config: LaneConfig,
    /// 上一次告诉对方的目标。
    announced: Option<u16>,
    trimmed_at: Instant,
    /// 控制 lane 上测到的往返时间。
    rtt: Option<Duration>,
    ping: Option<(u64, Instant)>,
    heard: Instant,
}

/// 一个事件。从 `select!` 里拿出来再处理，处理时才能再借用 lane 去写。
enum Event {
    Frame(Result<Option<Frame>, LaneError>),
    Command(Option<Command>),
    Tick,
    Ping,
    Shutdown,
}

impl Pool {
    fn new(inner: &Inner, peer: NodeId, membership: watch::Receiver<()>, generation: u64) -> Self {
        let now = Instant::now();
        Self {
            peer,
            membership,
            generation,
            config: inner.config.clone(),
            announced: None,
            trimmed_at: now,
            rtt: None,
            ping: None,
            heard: now,
        }
    }

    fn is_current(&self, entry: &crate::endpoint::Peer) -> bool {
        entry.matches(&self.membership) && entry.holder.control.as_ref().is_some_and(|control| control.generation == self.generation)
    }

    async fn run(
        mut self,
        inner: &Arc<Inner>,
        lane: &mut Lane,
        commands: &mut mpsc::UnboundedReceiver<Command>,
    ) -> Result<&'static str, LaneError> {
        let mut shutdown = inner.shutdown.clone();
        let mut tick = time::interval(TICK);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut ping = time::interval(self.config.ping_interval);
        ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // 第一个 POOL 也告诉对方：它的控制 lane 被接受了，可以开始停 lane 过来。
        self.request(inner, lane, true).await?;
        // 本节点在排空时对方（重启过的、换了地址的）新拨来控制 lane：马上告诉它，它才不会在这里开流。
        if inner.is_going_away() {
            lane.send(&Frame::GoAway).await?;
        }
        loop {
            let event = tokio::select! {
                _ = shutdown.changed() => Event::Shutdown,
                command = commands.recv() => Event::Command(command),
                frame = lane.read_frame() => Event::Frame(frame),
                _ = tick.tick() => Event::Tick,
                _ = ping.tick() => Event::Ping,
            };
            match event {
                Event::Shutdown | Event::Command(None | Some(Command::Replace)) => return Ok("本节点主动关闭当前控制 lane"),
                Event::Command(Some(Command::GoAway)) => lane.send(&Frame::GoAway).await?,
                Event::Command(Some(Command::Want)) => self.request(inner, lane, false).await?,
                Event::Frame(frame) => {
                    self.heard = Instant::now();
                    if let Some(entry) = inner.lock_peers().get_mut(&self.peer).filter(|entry| self.is_current(entry)) {
                        entry.holder.heard = Some(self.heard);
                    }
                    match frame? {
                        None => return Ok("对端关闭了控制 lane"),
                        Some(Frame::Ping(nonce)) => lane.send(&Frame::Pong(nonce)).await?,
                        Some(Frame::Pong(nonce)) => {
                            if let Some((sent, at)) = self.ping
                                && sent == nonce
                            {
                                self.rtt = Some(at.elapsed());
                                self.ping = None;
                            }
                        }
                        Some(Frame::GoAway) => self.peer_going_away(inner),
                        Some(Frame::Unknown(_)) => {}
                        Some(_) => return Err(LaneError::Protocol("控制 lane 收到非预期帧")),
                    }
                }
                Event::Ping => {
                    let nonce = inner.random_u64();
                    self.ping = Some((nonce, Instant::now()));
                    lane.send(&Frame::Ping(nonce)).await?;
                }
                Event::Tick => {
                    if self.heard.elapsed() > self.config.ping_interval * 3 {
                        return Ok("连续三个保活周期未收到对端响应");
                    }
                    self.maintain(inner);
                    self.request(inner, lane, false).await?;
                }
            }
        }
    }

    /// 每个维护周期：更新速率，关多余的空闲 lane。
    fn maintain(&mut self, inner: &Inner) {
        let now = Instant::now();
        let refill = self.refill();
        let mut peers = inner.lock_peers();
        let Some(entry) = peers.get_mut(&self.peer).filter(|entry| self.is_current(entry)) else { return };
        let min_idle = if entry.dials() { 0 } else { self.config.min_idle };
        let holder = &mut entry.holder;
        let demand = holder.demand.get_or_insert_with(|| Demand::new(now.into_std()));
        demand.update(now.into_std());
        let target = demand.target(refill, min_idle);
        let excess = holder.idle.len().saturating_sub(target);
        if excess > 0 && now.saturating_duration_since(self.trimmed_at) >= TRIM_EVERY {
            // 逐步关：每次关多出来的十分之一，至少一条，最老的先关。
            holder.idle.drain(..(excess / 10).max(1));
            self.trimmed_at = now;
        }
    }

    /// 缺多少就请对方拨多少；目标变了也告诉它（它据此显示状况）。`always` 时不缺也发。
    async fn request(&mut self, inner: &Inner, lane: &mut Lane, always: bool) -> Result<(), LaneError> {
        let refill = self.refill();
        let (target, extra) = {
            let mut peers = inner.lock_peers();
            let Some(entry) = peers.get_mut(&self.peer).filter(|entry| self.is_current(entry)) else { return Ok(()) };
            let min_idle = if entry.dials() { 0 } else { self.config.min_idle };
            let holder = &mut entry.holder;
            if holder.going_away {
                return Ok(());
            }
            let target = holder.demand.as_ref().map_or(min_idle.min(MAX_IDLE_TARGET), |demand| demand.target(refill, min_idle));
            (target, holder.shortfall(target, Instant::now()))
        };
        let idle = u16::try_from(target).expect("目标不超过 64");
        if extra == 0 && self.announced == Some(idle) && !always {
            return Ok(());
        }
        self.announced = Some(idle);
        let extra = u16::try_from(extra).expect("一次补拨不超过 512");
        lane.send(&Frame::Pool { idle, extra }).await
    }

    /// 取走一条到补上一条要多久：通知对方、它连过来、握手，约三个往返。还没测出往返时按 100 毫秒算。
    fn refill(&self) -> Duration {
        self.rtt.unwrap_or(Duration::from_millis(100)) * 3 + Duration::from_millis(5)
    }

    fn peer_going_away(&self, inner: &Inner) {
        let mut peers = inner.lock_peers();
        if let Some(entry) = peers.get_mut(&self.peer).filter(|entry| self.is_current(entry)) {
            entry.holder.going_away = true;
            entry.holder.idle.clear();
            entry.holder.waiters.clear();
        }
        drop(peers);
        tracing::info!(peer = %self.peer, "对端已通知进入排空状态，不再在其 lane 上开启新流");
    }
}
