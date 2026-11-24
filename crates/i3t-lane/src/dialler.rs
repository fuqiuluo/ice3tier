//! 拨号方一侧：为一个对端维持控制 lane、停在它那里的 lane，和自己开流用的几条热 lane。
//!
//! - 先拨控制 lane，等对方在上面回第一个 POOL：这才说明对方认了本节点（TLS 1.3 里客户端的握手先于服务端校验它的证书完成，
//!   被拒绝的拨号方在握手那一刻还不知道）。控制 lane 不在时，本节点不在任何 lane 上往这个对端开流，调用方改走共用的连接。
//! - 停多少条由对方说了算：它在 POOL 里说再拨几条就拨几条（它确切知道手上还有几条）。
//! - 自己开流用的热 lane 由本节点自己定：和接受方的池同一个估计（新流的速率 × 补一条要多久），补一条的时间是测到的拨号时间。
//!   预热池耗尽后才按需现拨。本节点首次向该对端开流前不预备（首条流按需拨号），避免仅为对端驻留 lane 的拨号方浪费连接。
//! - 停过去的 lane 每条有一个任务守着：对方在上面开流（OPENING）就把它交给本节点的接受队列；
//!   对方关掉它（多余的、旧 epoch 的）或者它死了，这个任务就结束。
//! - 每次拨号各自完成、立刻投入使用，不按批等：一次慢的拨号（SYN 重传）不拖住别的。
//!   同时在拨的最多 [`MAX_CONCURRENT_DIALS`] 条，多出来的排着，有空位再拨。
//! - 拨号失败就停一段时间再拨，时间逐次加倍，最长 [`MAX_BACKOFF`]；停着的这段时间里别的失败不再加倍：
//!   对方重启时几十条同时失败，只算一次。
//! - 控制 lane 断开后切换新的 epoch 重新拨号。旧 epoch 下的驻留 lane 失效，由对端在收到新控制 lane 时关闭；
//!   在那之前对方要是在其中一条上开了流，照样服务。

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use i3t_proto::NodeId;
use rustls::ClientConfig;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinSet;
use tokio::time::{self, Instant, MissedTickBehavior};

use crate::demand::{Demand, MAX_IDLE_TARGET};
use crate::endpoint::Inner;
use crate::error::LaneError;
use crate::frame::{Frame, Mode, Purpose};
use crate::holder::MAX_BURST;
use crate::lane::{self, Dial, Lane};

/// 同时最多在拨多少条。对方按来源限制没握手完的连接（见 `admission`），这个数要比它的上限小。
pub(crate) const MAX_CONCURRENT_DIALS: usize = 128;
/// 一次拨号（连接加握手）最长多久。
const DIAL_DEADLINE: Duration = Duration::from_secs(10);
const FIRST_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// 维护间隔：检查保活，补不够的。
const TICK: Duration = Duration::from_millis(100);

/// 拨号方为一个对端保留的东西，放在对端的表项里，开流时直接取。
pub(crate) struct DialSide {
    pub(crate) addrs: Vec<SocketAddr>,
    pub(crate) config: Arc<ClientConfig>,
    /// 留给自己开流的热 lane。
    pub(crate) warm: VecDeque<Lane>,
    /// 对方在控制 lane 上说了要走：不再在它那里开新的流。
    pub(crate) peer_going_away: bool,
    /// 到对方的控制 lane 在，并且对方回过 POOL（认了本节点）。
    pub(crate) control_up: bool,
    /// 停在对方那里、按本节点所知还空闲的条数（给状况用）。
    pub(crate) parked: usize,
    /// 本节点自己往对方开流的速率，热 lane 的条数跟着它走。第一次开流时才有。
    pub(crate) own: Option<Demand>,
    /// 拨一条 lane（连上加握手）平均要多久。
    pub(crate) dial_time: Option<Duration>,
    /// 上一次关多余的热 lane 的时刻。
    pub(crate) trimmed: Option<std::time::Instant>,
    /// 叫醒维护任务。每次启动维护任务时用新的 Notify，旧任务不能再改这个表项。
    pub(crate) wake: Arc<Notify>,
    pub(crate) task: tokio::task::AbortHandle,
    /// 上一次连上的地址，下一次先试它。
    pub(crate) last_good: Option<SocketAddr>,
}

impl DialSide {
    /// 停掉维护任务（连同控制 lane 和在拨的），换一个新的 epoch 从控制 lane 重新拨。手上的热 lane 不要了。
    pub(crate) fn redial(&mut self, inner: &Arc<Inner>, peer: NodeId) {
        self.task.abort();
        self.warm.clear();
        self.last_good = None;
        self.control_up = false;
        self.parked = 0;
        self.wake = Arc::new(Notify::new());
        self.task = tokio::spawn(run(Arc::clone(inner), peer, Arc::clone(&self.wake))).abort_handle();
    }

    pub(crate) fn matches(&self, generation: &Arc<Notify>) -> bool {
        Arc::ptr_eq(&self.wake, generation)
    }

    pub(crate) fn addrs_in_order(&self) -> Vec<SocketAddr> {
        let mut addrs = self.addrs.clone();
        if let Some(good) = self.last_good
            && let Some(position) = addrs.iter().position(|&addr| addr == good)
        {
            addrs[..=position].rotate_right(1);
        }
        addrs
    }
}

impl Drop for DialSide {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// 拨号任务、守 lane 的任务报回来的事。
enum Event {
    /// 一条停过去的 lane 拨好了（或者没拨成）。
    Parked { epoch: u64, ok: bool },
    /// 停过去的一条不再空闲：对方在上面开了流，或者它被关掉了。
    ParkedGone { epoch: u64 },
    /// 一条热 lane 拨好了（或者没拨成）。
    Own { ok: bool },
}

/// 为 `peer` 跑维护任务，直到本节点关闭或者不再拨它（任务被取消）。
pub(crate) async fn run(inner: Arc<Inner>, peer: NodeId, wake: Arc<Notify>) {
    let (events, mut receiver) = mpsc::unbounded_channel();
    let mut state = Dialler::new(&inner, peer, wake, events);
    // 维护任务撤销时，拨号和守着停车 lane 的任务也随 JoinSet 一起被撤销。
    let mut tasks = JoinSet::new();
    let mut shutdown = inner.shutdown.clone();
    let mut tick = time::interval(TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        // 重连期间不会进入下面的 select，也要回收已经结束的子任务。
        while tasks.try_join_next().is_some() {}
        if state.control.is_none() && !state.connect_control(&inner).await {
            let pause = state.paused_until.saturating_duration_since(Instant::now()).max(FIRST_BACKOFF);
            tokio::select! {
                _ = shutdown.changed() => return,
                () = time::sleep(pause) => continue,
            }
        }
        state.top_up(&inner, &mut tasks);
        let control = state.control.as_mut().expect("上面刚确认过控制 lane 在");
        let step = tokio::select! {
            _ = shutdown.changed() => return,
            frame = control.read_frame() => Step::Frame(frame),
            event = receiver.recv() => Step::Event(event),
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
            () = state.generation.notified() => Step::Wake,
            _ = tick.tick() => Step::Tick,
        };
        if let Err(reason) = state.handle(&inner, step).await {
            state.lose_control(&inner, &reason);
        }
        inner.set_parked(peer, &state.generation, state.parked_idle);
    }
}

enum Step {
    Frame(Result<Option<Frame>, LaneError>),
    Event(Option<Event>),
    Wake,
    Tick,
}

struct Dialler {
    peer: NodeId,
    generation: Arc<Notify>,
    events: mpsc::UnboundedSender<Event>,
    epoch: u64,
    control: Option<Lane>,
    /// 对方要拨、还没开始拨的条数。
    pending: usize,
    /// 当前 epoch 停在对方那里、按本节点所知还空闲的条数。
    parked_idle: usize,
    dialling_parked: usize,
    dialling_own: usize,
    backoff: Duration,
    paused_until: Instant,
    heard: Instant,
    ping_sent: Instant,
    /// 本节点排空时，GOAWAY 已经在这条控制 lane 上发过了。
    goaway_sent: bool,
}

impl Dialler {
    fn new(inner: &Inner, peer: NodeId, generation: Arc<Notify>, events: mpsc::UnboundedSender<Event>) -> Self {
        let now = Instant::now();
        Self {
            peer,
            generation,
            events,
            epoch: inner.random_u64(),
            control: None,
            pending: 0,
            parked_idle: 0,
            dialling_parked: 0,
            dialling_own: 0,
            backoff: FIRST_BACKOFF,
            paused_until: now,
            heard: now,
            ping_sent: now,
            goaway_sent: false,
        }
    }

    fn paused(&self) -> bool {
        Instant::now() < self.paused_until
    }

    /// 拨号失败后进入退避等待；若已处于退避期则不再加倍，将同一批并发失败合并为一次。
    fn failed(&mut self) {
        if self.paused() {
            return;
        }
        self.paused_until = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    fn succeeded(&mut self) {
        self.backoff = FIRST_BACKOFF;
    }

    /// 拨控制 lane。成功返回 `true`。
    async fn connect_control(&mut self, inner: &Arc<Inner>) -> bool {
        if self.paused() || inner.is_going_away() {
            return false;
        }
        let Some(plan) = inner.dial_plan(self.peer, &self.generation) else { return false };
        let dial = Dial {
            addrs: &plan.addrs,
            config: plan.config,
            peer: self.peer,
            membership: plan.membership,
            purpose: Purpose::Control,
            epoch: self.epoch,
            deadline: Instant::now() + DIAL_DEADLINE,
        };
        let started = Instant::now();
        let dialled = {
            let _dialling = plan.book.enter(|tally| &tally.dialling);
            lane::dial(dial).await
        };
        if dialled.is_ok() {
            inner.note_dial_time(self.peer, &self.generation, started.elapsed());
        }
        let confirmed = match dialled {
            Ok((mut lane, addr)) => {
                lane.sealed.allow_unknown_frames();
                let first = async {
                    lane.flush().await?;
                    lane.read_frame().await
                };
                match time::timeout_at(Instant::now() + DIAL_DEADLINE, first).await {
                    Ok(Ok(Some(Frame::Pool { extra, .. }))) => Ok((lane, addr, extra)),
                    Ok(Ok(_)) => Err(LaneError::Protocol("对端在控制 lane 上发送的首帧不是 POOL")),
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(LaneError::Deadline(DIAL_DEADLINE)),
                }
            }
            Err(error) => Err(error),
        };
        match confirmed {
            Ok((lane, addr, extra)) => {
                inner.remember_good(self.peer, &self.generation, addr);
                self.succeeded();
                let now = Instant::now();
                (self.heard, self.ping_sent) = (now, now);
                self.control = Some(lane);
                self.goaway_sent = false;
                self.add_pending(usize::from(extra));
                inner.set_control_up(self.peer, &self.generation, true);
                tracing::info!(peer = %self.peer, %addr, "到对端的控制 lane 已建立");
                true
            }
            Err(error) => {
                plan.book.bump(|tally| &tally.dial_failures);
                tracing::debug!(peer = %self.peer, %error, "拨号建立控制 lane 失败（对端拒绝或未识别本节点时也会出现该错误）");
                self.failed();
                false
            }
        }
    }

    /// 对方要再拨 `extra` 条。停着的、在拨的、要拨的合起来不超过上限。
    fn add_pending(&mut self, extra: usize) {
        let room = (MAX_IDLE_TARGET + MAX_BURST).saturating_sub(self.parked_idle + self.dialling_parked + self.pending);
        self.pending += extra.min(room);
    }

    /// 控制 lane 断开：切换新的 epoch，旧的驻留 lane 失效，并重新拨号。
    fn lose_control(&mut self, inner: &Inner, reason: &str) {
        self.control = None;
        self.epoch = inner.random_u64();
        self.pending = 0;
        self.parked_idle = 0;
        inner.set_control_up(self.peer, &self.generation, false);
        tracing::info!(peer = %self.peer, %reason, "到对端的控制 lane 已断开，切换新 epoch 重新拨号");
    }

    async fn handle(&mut self, inner: &Arc<Inner>, step: Step) -> Result<(), String> {
        match step {
            Step::Frame(frame) => {
                self.heard = Instant::now();
                let frame = frame.map_err(|error| error.to_string())?.ok_or("对端关闭了控制 lane")?;
                let control = self.control.as_mut().expect("控制 lane 在时才会读到它的帧");
                match frame {
                    Frame::Pool { extra, .. } => self.add_pending(usize::from(extra)),
                    Frame::Ping(nonce) => control.send(&Frame::Pong(nonce)).await.map_err(|error| error.to_string())?,
                    Frame::Pong(_) | Frame::Unknown(_) => {}
                    Frame::GoAway => inner.peer_going_away(self.peer, &self.generation),
                    _ => return Err("控制 lane 收到非预期帧".to_owned()),
                }
            }
            Step::Event(event) => match event.expect("发送端一直在这里，接收不会结束") {
                Event::Parked { epoch, ok } => {
                    self.dialling_parked -= 1;
                    if ok {
                        self.succeeded();
                        if epoch == self.epoch {
                            self.parked_idle += 1;
                        }
                    } else {
                        self.failed();
                    }
                }
                Event::ParkedGone { epoch } => {
                    if epoch == self.epoch {
                        self.parked_idle = self.parked_idle.saturating_sub(1);
                    }
                }
                Event::Own { ok } => {
                    self.dialling_own -= 1;
                    if ok { self.succeeded() } else { self.failed() }
                }
            },
            Step::Wake => {}
            Step::Tick => {
                let interval = inner.config.ping_interval;
                if self.heard.elapsed() > interval * 3 {
                    return Err("连续三个保活周期未收到对端响应".to_owned());
                }
                let control = self.control.as_mut().expect("同上");
                if self.ping_sent.elapsed() >= interval {
                    self.ping_sent = Instant::now();
                    control.send(&Frame::Ping(inner.random_u64())).await.map_err(|error| error.to_string())?;
                }
                if inner.is_going_away() && !self.goaway_sent {
                    self.goaway_sent = true;
                    control.send(&Frame::GoAway).await.map_err(|error| error.to_string())?;
                }
            }
        }
        Ok(())
    }

    /// 拨对方要的、补不够的热 lane。
    fn top_up(&mut self, inner: &Arc<Inner>, tasks: &mut JoinSet<()>) {
        if self.paused() || inner.is_going_away() || self.control.is_none() {
            return;
        }
        let Some((warm, peer_going_away)) = inner.warm_state(self.peer, &self.generation) else { return };
        if peer_going_away {
            return;
        }
        let slots = MAX_CONCURRENT_DIALS.saturating_sub(self.dialling_parked + self.dialling_own);
        let parked = self.pending.min(slots);
        for _ in 0..parked {
            self.pending -= 1;
            self.dialling_parked += 1;
            tasks.spawn(park(Arc::clone(inner), self.peer, Arc::clone(&self.generation), self.epoch, self.events.clone()));
        }
        let slots = MAX_CONCURRENT_DIALS.saturating_sub(self.dialling_parked + self.dialling_own);
        let ready = inner.size_ready(self.peer, &self.generation).unwrap_or(0);
        let own = ready.saturating_sub(warm + self.dialling_own).min(slots);
        for _ in 0..own {
            self.dialling_own += 1;
            tasks.spawn(warm_up(Arc::clone(inner), self.peer, Arc::clone(&self.generation), self.epoch, self.events.clone()));
        }
    }
}

/// 拨一条停在对方那里的 lane，然后守着它：对方在上面开流就交给接受队列。
async fn park(inner: Arc<Inner>, peer: NodeId, generation: Arc<Notify>, epoch: u64, events: mpsc::UnboundedSender<Event>) {
    // 以下事件上报给该对端的维护任务；若任务已结束（节点关闭或不再拨号该对端），发送失败可安全忽略。
    let Some(mut lane) = dial_one(&inner, peer, &generation, Purpose::Parked, epoch).await else {
        let _ = events.send(Event::Parked { epoch, ok: false });
        return;
    };
    if let Err(error) = lane.flush().await {
        tracing::debug!(%peer, %error, "驻留 lane 刚建立即断开");
        let _ = events.send(Event::Parked { epoch, ok: false });
        return;
    }
    let _ = events.send(Event::Parked { epoch, ok: true });
    let mut shutdown = inner.shutdown.clone();
    let opening = tokio::select! {
        _ = shutdown.changed() => return,
        opening = await_opening(&mut lane) => opening,
    };
    let _ = events.send(Event::ParkedGone { epoch });
    match opening {
        Ok(Some(opening)) => inner.deliver(lane, &opening, Some(&generation)),
        Ok(None) => {}
        Err(error) => tracing::debug!(%peer, %error, "驻留 lane 已关闭"),
    }
}

/// 拨一条热 lane，放进对端表项里给自己开流时取。
async fn warm_up(inner: Arc<Inner>, peer: NodeId, generation: Arc<Notify>, epoch: u64, events: mpsc::UnboundedSender<Event>) {
    let lane = match dial_one(&inner, peer, &generation, Purpose::Own, epoch).await {
        Some(mut lane) => match lane.flush().await {
            Ok(()) => Some(lane),
            Err(error) => {
                tracing::debug!(%peer, %error, "预热 lane 刚建立即断开");
                None
            }
        },
        None => None,
    };
    let ok = lane.is_some();
    if let Some(lane) = lane {
        inner.add_warm(lane, &generation);
    }
    // 若该对端的维护任务已结束（节点关闭或不再拨号该对端），发送失败可安全忽略。
    let _ = events.send(Event::Own { ok });
}

async fn dial_one(inner: &Arc<Inner>, peer: NodeId, generation: &Arc<Notify>, purpose: Purpose, epoch: u64) -> Option<Lane> {
    let plan = inner.dial_plan(peer, generation)?;
    let dial = Dial {
        addrs: &plan.addrs,
        config: plan.config,
        peer,
        membership: plan.membership,
        purpose,
        epoch,
        deadline: Instant::now() + DIAL_DEADLINE,
    };
    let started = Instant::now();
    let dialled = {
        let _dialling = plan.book.enter(|tally| &tally.dialling);
        lane::dial(dial).await
    };
    match dialled {
        Ok((lane, addr)) => {
            inner.remember_good(peer, generation, addr);
            inner.note_dial_time(peer, generation, started.elapsed());
            Some(lane)
        }
        Err(error) => {
            plan.book.bump(|tally| &tally.dial_failures);
            tracing::debug!(%peer, ?purpose, %error, "拨号建立 lane 失败");
            None
        }
    }
}

/// 开流请求：对方在一条 lane 上发来的 OPENING。
pub(crate) struct Opening {
    pub(crate) mode: Mode,
    pub(crate) header: bytes::Bytes,
}

/// 等对方在 `lane` 上开流。对方关掉它时返回 `Ok(None)`。
///
/// # Errors
///
/// lane 出错，或者对方发来的第一个帧不是 OPENING、[`Mode::Early`] 的 OPENING 后面同一条记录里还有东西。
pub(crate) async fn await_opening(lane: &mut Lane) -> Result<Option<Opening>, LaneError> {
    match lane.read_frame().await {
        Ok(Some(Frame::Opening { mode, header })) => {
            if mode == Mode::Early && !lane.sealed.at_record_boundary() {
                return Err(LaneError::Protocol("passthrough 模式的 OPENING 帧后同一 TLS 记录内存在多余数据"));
            }
            Ok(Some(Opening { mode, header }))
        }
        Ok(Some(_)) => Err(LaneError::Protocol("空闲 lane 收到的首帧不是 OPENING")),
        Ok(None) | Err(LaneError::Closed) => Ok(None),
        Err(error) => Err(error),
    }
}
