//! 节点一侧的中转会话：握手、保活、测延迟。帧的格式见 [`i3t_proto::session`]。
//!
//! 一台不做 I/O 的状态机，UDP 和 TCP 上各用一份：外面告诉它时间和 relay 发来了什么，它回答该发什么、会话还在不在。
//! 签名在外面做：它只说"该发 AUTH 了"，OK 的签名由外面验过才交进来。
//!
//! relay 的 ERROR 没有签名，伪造来源地址的人也能冒充 relay 发。所以它只在回显对得上时才算数（格式见
//! [`i3t_proto::session`]）：说本节点没有会话的，要回显一个还在等回答的保活 PING 的随机数；说别的路走不通的，
//! 要回显这个会话握手时的随机数。说没有会话、回显又对不上的（relay 回答中转帧时只能这样）只是个提示：马上发一个 PING 去问。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use i3t_proto::session::{Accepted, Challenge, Cookie, Echo, Nonce, Pong};

use crate::estimate::{Estimate, Quality, Train};
use crate::timing::{HANDSHAKE_RETRY, HANDSHAKE_TRIES, MAX_TIMEOUTS, PROBE_INTERVAL, Rtt, SILENCE, TCP_HANDSHAKE_STEP};

/// 回显对不上的"没有会话"最多这么频繁地引出一个核实用的 PING。真的 relay 给中转帧回错误帧本来就是一秒一个；
/// 伪造的再多，本节点也只是每秒多发一个 PING。
const NO_SESSION_CHECK_GAP: Duration = Duration::from_secs(1);

/// 要外面去发的帧。节点编号和签名由外面填。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Send {
    Init { nonce: Nonce },
    Auth { nonce: Nonce, cookie: Cookie },
    Ping { nonce: Nonce },
}

/// 会话的状态变了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    /// 握手成功。`observed` 是 relay 看到的本节点地址。
    Up { observed: SocketAddr },
    /// 会话没了，或者握手失败。
    Down { reason: &'static str },
    /// 收到了 CHALLENGE，但握手被要求停在这里（见 [`Session::start`] 的 `hold`）。
    Held,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Step {
    pub(crate) send: Option<Send>,
    pub(crate) event: Option<Event>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    AwaitChallenge {
        nonce: Nonce,
        sent: Instant,
        tries: u8,
        hold: bool,
    },
    /// 有 cookie 了，等外面说可以继续。
    Held {
        nonce: Nonce,
        cookie: Cookie,
    },
    AwaitOk {
        nonce: Nonce,
        cookie: Cookie,
        sent: Instant,
        tries: u8,
    },
    Up {
        /// 握手时的随机数。relay 回给会话主人的错误帧回显它。
        nonce: Nonce,
        last_ping: Instant,
        awaiting: Option<(Nonce, Instant)>,
        missed: u8,
    },
}

/// 到一个 relay、走一种传输（UDP 或 TCP）的中转会话。
#[derive(Debug)]
pub(crate) struct Session {
    state: State,
    /// 这一段链路的延迟、抖动和丢包。保活和探测包列的结果都记在这里。
    estimate: Estimate,
    train: Train,
    /// 这段链路是不是在正在评估的候选路径上：是的话定期发探测包列。
    training: bool,
    /// 保活的间隔。挂靠的 relay 是 5 秒，relay 和 relay 之间是 2 秒。
    interval: Duration,
    /// 上一次因为一个核对不了的"没有会话"提前发 PING 的时刻。
    checked: Option<Instant>,
    /// 这个会话走在 TCP 里：帧不会丢，只会迟到，所以握手不重发、每一步等得更久。
    reliable: bool,
}

impl Session {
    /// 走 UDP 的会话。
    pub(crate) const fn new() -> Self {
        Self {
            state: State::Idle,
            estimate: Estimate::new(),
            train: Train::new(),
            training: false,
            interval: PROBE_INTERVAL,
            checked: None,
            reliable: false,
        }
    }

    /// 走在 TCP 里的会话。`estimate` 是同一段链路上一个会话留下的测量值，接着用（见 [`measured`](Self::measured)）。
    pub(crate) const fn over_tcp(estimate: Estimate) -> Self {
        Self { state: State::Idle, estimate, train: Train::new(), training: false, interval: PROBE_INTERVAL, checked: None, reliable: true }
    }

    /// 这段链路上测到的全部结果。会话没了之后链路还是那一段，留给下一个会话接着用。
    pub(crate) const fn measured(&self) -> &Estimate {
        &self.estimate
    }

    pub(crate) const fn set_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }

    pub(crate) const fn set_training(&mut self, training: bool) {
        self.training = training;
    }

    pub(crate) const fn is_up(&self) -> bool {
        matches!(self.state, State::Up { .. })
    }

    /// 没有在握手，也没有会话。
    pub(crate) const fn is_idle(&self) -> bool {
        matches!(self.state, State::Idle)
    }

    /// 会话可疑：有保活没有得到回答。
    pub(crate) const fn in_doubt(&self) -> bool {
        matches!(self.state, State::Up { missed: 1.., .. })
    }

    pub(crate) const fn rtt(&self) -> Option<Rtt> {
        self.estimate.rtt()
    }

    /// 这段链路现在的估计；没有测到过或者过期了是 `None`。走在 TCP 里的会话按 TCP 的算法（[`Estimate::over_tcp`]）。
    pub(crate) fn quality(&self, now: Instant) -> Option<Quality> {
        if self.reliable { self.estimate.over_tcp(now) } else { self.estimate.quality(now) }
    }

    /// 开始握手，返回要发的 INIT。
    ///
    /// `hold` 为真时拿到 cookie 就停下，等 [`release`](Self::release)：TCP 和 UDP 同时试的时候，TCP 这边先走到这一步
    /// 证明连得上，但不发 AUTH。因为 relay 上一个节点只有一个会话，后握手的顶掉先握手的，TCP 抢先的话包就会走 TCP。
    pub(crate) fn start(&mut self, now: Instant, hold: bool) -> Send {
        let nonce: Nonce = i3t_underlay::random_bytes();
        self.state = State::AwaitChallenge { nonce, sent: now, tries: 1, hold };
        Send::Init { nonce }
    }

    /// 停在 cookie 那一步的握手可以继续了。返回要发的 AUTH；不在那一步时返回 `None`。
    pub(crate) fn release(&mut self, now: Instant) -> Option<Send> {
        let State::Held { nonce, cookie } = self.state else { return None };
        self.state = State::AwaitOk { nonce, cookie, sent: now, tries: 1 };
        Some(Send::Auth { nonce, cookie })
    }

    /// 放弃：不再握手，也不再保活。relay 那边的会话会自己过期。
    pub(crate) fn stop(&mut self) {
        self.state = State::Idle;
        self.train.clear();
    }

    pub(crate) fn on_challenge(&mut self, challenge: &Challenge, now: Instant) -> Step {
        let State::AwaitChallenge { nonce, sent, tries, hold } = self.state else { return Step::default() };
        if challenge.nonce != nonce {
            return Step::default();
        }
        // 握手的第一个往返顺便当一个延迟样本。重发过的话分不清这是在回答哪一个 INIT，就不取样。
        if tries == 1 {
            self.estimate.sample(now.saturating_duration_since(sent), now);
        }
        if hold {
            self.state = State::Held { nonce, cookie: challenge.cookie };
            return Step { send: None, event: Some(Event::Held) };
        }
        self.state = State::AwaitOk { nonce, cookie: challenge.cookie, sent: now, tries: 1 };
        Step { send: Some(Send::Auth { nonce, cookie: challenge.cookie }), event: None }
    }

    /// 这个 OK 是不是在回答本会话发出去的 AUTH。是的话外面要先验它的签名，再交给 [`on_ok`](Self::on_ok)。
    pub(crate) fn expects_ok(&self, ok: &Accepted) -> bool {
        matches!(self.state, State::AwaitOk { nonce, .. } if nonce == ok.nonce)
    }

    /// 签名已经验过的 OK。
    pub(crate) fn on_ok(&mut self, ok: &Accepted, now: Instant) -> Step {
        let State::AwaitOk { nonce, sent, tries, .. } = self.state else { return Step::default() };
        if nonce != ok.nonce {
            return Step::default();
        }
        // 握手的第二个往返同样可以当延迟样本，重发过就不取。
        if tries == 1 {
            self.estimate.sample(now.saturating_duration_since(sent), now);
        }
        // 两步都重发过的话还不知道延迟：不等保活间隔，马上量一次。
        let last_ping = if self.rtt().is_some() { now } else { now.checked_sub(self.interval).unwrap_or(now) };
        self.state = State::Up { nonce, last_ping, awaiting: None, missed: 0 };
        Step { send: None, event: Some(Event::Up { observed: ok.observed }) }
    }

    /// PONG。返回 relay 看到的本节点地址；随机数对不上时返回 `None`。
    pub(crate) fn on_pong(&mut self, pong: &Pong, now: Instant) -> Option<SocketAddr> {
        let State::Up { nonce: session, last_ping, awaiting, .. } = self.state else { return None };
        match awaiting {
            Some((nonce, sent)) if pong.nonce == nonce => {
                self.estimate.sample(now.saturating_duration_since(sent), now);
                self.state = State::Up { nonce: session, last_ping, awaiting: None, missed: 0 };
                Some(pong.observed)
            }
            // 不是在回答保活，那就看是不是探测包列里的一个。
            Some(_) | None => self.train.on_reply(&pong.nonce, now, &mut self.estimate).then_some(pong.observed),
        }
    }

    /// 这是不是会话握手时的随机数：relay 回给会话主人的错误帧回显它，回显对得上才是这个 relay 说的。
    pub(crate) fn is_session_echo(&self, echo: &Echo) -> bool {
        matches!(self.state, State::Up { nonce, .. } if nonce == *echo)
    }

    /// relay 说本节点在它那里没有会话，错误帧回显的是 `echo`。
    ///
    /// 回显的是一个还在等回答（或者刚超时）的保活 PING 的随机数：这是 relay 对那个 PING 的回答，会话确实没了。
    /// 别的回显核对不了，只当作提示：马上发一个 PING 去问，relay 怎么回答它才算数。
    pub(crate) fn on_no_session(&mut self, echo: &Echo, now: Instant) -> Step {
        let State::Up { nonce, last_ping, awaiting, missed } = self.state else { return Step::default() };
        if awaiting.is_some_and(|(pinged, _)| pinged == *echo) || self.train.expects(echo) {
            return self.fail("relay 说本节点没有会话");
        }
        if awaiting.is_some() || self.checked.is_some_and(|at| now.saturating_duration_since(at) < NO_SESSION_CHECK_GAP) {
            return Step::default();
        }
        self.checked = Some(now);
        let ping: Nonce = i3t_underlay::random_bytes();
        self.state = State::Up { nonce, last_ping: last_ping.max(now), awaiting: Some((ping, now)), missed };
        Step { send: Some(Send::Ping { nonce: ping }), event: None }
    }

    /// 推进定时器。`urgent`：有包正经这个 relay 发出去，却有一阵没有从它收到任何东西了。
    pub(crate) fn poll(&mut self, now: Instant, urgent: bool) -> Step {
        match self.state {
            State::Idle | State::Held { .. } => Step::default(),
            State::AwaitChallenge { nonce, sent, tries, hold } => match self.retry(sent, tries, now) {
                Retry::Wait => Step::default(),
                Retry::Again => {
                    self.state = State::AwaitChallenge { nonce, sent: now, tries: tries + 1, hold };
                    Step { send: Some(Send::Init { nonce }), event: None }
                }
                Retry::GiveUp => self.fail("握手没有回应"),
            },
            State::AwaitOk { nonce, cookie, sent, tries } => match self.retry(sent, tries, now) {
                Retry::Wait => Step::default(),
                Retry::Again => {
                    self.state = State::AwaitOk { nonce, cookie, sent: now, tries: tries + 1 };
                    Step { send: Some(Send::Auth { nonce, cookie }), event: None }
                }
                Retry::GiveUp => self.fail("握手的最后一步没有回应"),
            },
            State::Up { nonce, last_ping, awaiting, missed } => self.keep_alive(now, urgent, nonce, last_ping, awaiting, missed),
        }
    }

    fn keep_alive(
        &mut self,
        now: Instant,
        urgent: bool,
        session: Nonce,
        last_ping: Instant,
        awaiting: Option<(Nonce, Instant)>,
        missed: u8,
    ) -> Step {
        let since_ping = now.saturating_duration_since(last_ping);
        let timeout = self.rtt().map_or(crate::timing::PROBE_TIMEOUT_MAX, Rtt::probe_timeout);
        let (due, missed) = match awaiting {
            Some((_, sent)) if now.saturating_duration_since(sent) < timeout => (false, missed),
            // 超时之后不等下一个保活间隔，立刻再问。它的回答要是迟到了（走 TCP 时常见：TCP 在重传），照样记下延迟。
            Some((nonce, sent)) => {
                self.estimate.lost();
                self.train.overdue(nonce, sent);
                (true, missed + 1)
            }
            None => (since_ping >= self.interval || (urgent && since_ping >= SILENCE), missed),
        };
        if missed >= MAX_TIMEOUTS {
            // 走在 TCP 里的：最早那个没有回答的探测等了多久就是这一次停顿至少多长，它的回答再也不会来了（见 `crate::estimate`）。
            if let Some(sent) = self.train.oldest_overdue().filter(|_| self.reliable) {
                self.estimate.stalled(now.saturating_duration_since(sent), now);
            }
            return self.fail("保活连续没有回应");
        }
        if !due {
            // 不到发保活的时候：探测包列该发的话发一个。它的回答只用来估丢包，不影响会话还在不在的判断。
            let probe = self.train.poll(now, self.training, timeout, &mut self.estimate);
            return Step { send: probe.map(|nonce| Send::Ping { nonce }), event: None };
        }
        let nonce: Nonce = i3t_underlay::random_bytes();
        self.state = State::Up { nonce: session, last_ping: now, awaiting: Some((nonce, now)), missed };
        Step { send: Some(Send::Ping { nonce }), event: None }
    }

    /// 握手的一步发出去之后该怎么办。走 UDP 的隔一会儿重发，发够了次数放弃；走 TCP 的只等，等得更久。
    fn retry(&self, sent: Instant, tries: u8, now: Instant) -> Retry {
        let waited = now.saturating_duration_since(sent);
        if self.reliable {
            return if waited < TCP_HANDSHAKE_STEP { Retry::Wait } else { Retry::GiveUp };
        }
        if waited < HANDSHAKE_RETRY {
            Retry::Wait
        } else if tries < HANDSHAKE_TRIES {
            Retry::Again
        } else {
            Retry::GiveUp
        }
    }

    fn fail(&mut self, reason: &'static str) -> Step {
        self.state = State::Idle;
        self.train.clear();
        Step { send: None, event: Some(Event::Down { reason }) }
    }
}

enum Retry {
    Wait,
    Again,
    GiveUp,
}

#[cfg(test)]
mod tests {
    use i3t_proto::session::{COOKIE_LEN, SIGNATURE_LEN};

    use super::*;

    const MS: Duration = Duration::from_millis(1);
    const COOKIE: Cookie = [7; COOKIE_LEN];

    fn observed() -> SocketAddr {
        "203.0.113.7:4000".parse().unwrap()
    }

    fn ok(nonce: Nonce) -> Accepted {
        Accepted { nonce, valid_for: 30, observed: observed(), signature: [0; SIGNATURE_LEN] }
    }

    /// 握手成功的会话，返回它和成功的时刻。
    fn established() -> (Session, Instant) {
        let start = Instant::now();
        let mut session = Session::new();
        let Send::Init { nonce } = session.start(start, false) else { panic!("握手从 INIT 开始") };
        session.on_challenge(&Challenge { nonce, cookie: COOKIE }, start + 20 * MS);
        let up = start + 40 * MS;
        assert_eq!(session.on_ok(&ok(nonce), up).event, Some(Event::Up { observed: observed() }));
        (session, up)
    }

    #[test]
    fn the_handshake_goes_init_challenge_auth_ok() {
        let start = Instant::now();
        let mut session = Session::new();
        assert!(session.is_idle());
        let Send::Init { nonce } = session.start(start, false) else { panic!("握手从 INIT 开始") };
        assert!(!session.is_idle() && !session.is_up());

        assert_eq!(
            session.on_challenge(&Challenge { nonce: [0; 8], cookie: COOKIE }, start + 10 * MS),
            Step::default(),
            "随机数不对的 CHALLENGE 不理"
        );
        let step = session.on_challenge(&Challenge { nonce, cookie: COOKIE }, start + 20 * MS);
        assert_eq!(step, Step { send: Some(Send::Auth { nonce, cookie: COOKIE }), event: None });
        assert_eq!(session.rtt().map(Rtt::get), Some(20 * MS), "握手的第一个往返就是一个延迟样本");

        assert!(!session.expects_ok(&ok([0; 8])));
        assert_eq!(session.on_ok(&ok([0; 8]), start + 30 * MS), Step::default());
        assert!(session.expects_ok(&ok(nonce)));
        assert_eq!(session.on_ok(&ok(nonce), start + 40 * MS), Step { send: None, event: Some(Event::Up { observed: observed() }) });
        assert!(session.is_up() && !session.in_doubt());
        assert_eq!(session.on_ok(&ok(nonce), start + 50 * MS), Step::default(), "同一个 OK 不算两次");
    }

    #[test]
    fn each_handshake_step_is_retried_and_then_given_up() {
        let start = Instant::now();
        let mut session = Session::new();
        let Send::Init { nonce } = session.start(start, false) else { panic!("握手从 INIT 开始") };
        assert_eq!(session.poll(start + HANDSHAKE_RETRY - MS, false), Step::default());
        let mut now = start;
        for _ in 1..HANDSHAKE_TRIES {
            now += HANDSHAKE_RETRY;
            assert_eq!(session.poll(now, false).send, Some(Send::Init { nonce }), "重发用同一个随机数，哪个 CHALLENGE 回来都对得上");
        }
        now += HANDSHAKE_RETRY;
        assert_eq!(session.poll(now, false).event, Some(Event::Down { reason: "握手没有回应" }));
        assert!(session.is_idle());

        // 第二步同样。
        let Send::Init { nonce } = session.start(now, false) else { panic!("握手从 INIT 开始") };
        session.on_challenge(&Challenge { nonce, cookie: COOKIE }, now);
        for _ in 1..HANDSHAKE_TRIES {
            now += HANDSHAKE_RETRY;
            assert_eq!(session.poll(now, false).send, Some(Send::Auth { nonce, cookie: COOKIE }));
        }
        now += HANDSHAKE_RETRY;
        assert!(matches!(session.poll(now, false).event, Some(Event::Down { .. })));
    }

    #[test]
    fn a_retransmitted_init_does_not_yield_a_misleading_rtt_sample() {
        let start = Instant::now();
        let mut session = Session::new();
        let Send::Init { nonce } = session.start(start, false) else { panic!("握手从 INIT 开始") };
        session.poll(start + HANDSHAKE_RETRY, false);
        // 这个 CHALLENGE 可能是回答第一个 INIT 的，也可能是第二个的，算不出往返时间。
        let step = session.on_challenge(&Challenge { nonce, cookie: COOKIE }, start + HANDSHAKE_RETRY + 30 * MS);
        assert!(step.send.is_some(), "握手照常继续");
        assert_eq!(session.rtt(), None);

        // 第二步也重发了：握手完成时还是不知道延迟，所以马上发一个保活去量。
        let resent = start + 2 * HANDSHAKE_RETRY + 30 * MS;
        assert!(matches!(session.poll(resent, false).send, Some(Send::Auth { .. })));
        assert!(session.on_ok(&ok(nonce), resent + 10 * MS).event.is_some());
        assert_eq!(session.rtt(), None);
        let Some(Send::Ping { nonce }) = session.poll(resent + 11 * MS, false).send else { panic!("应该马上量一次延迟") };
        session.on_pong(&Pong { nonce, observed: observed() }, resent + 31 * MS);
        assert_eq!(session.rtt().map(Rtt::get), Some(20 * MS));
    }

    #[test]
    fn a_held_handshake_stops_at_the_cookie_until_released() {
        let start = Instant::now();
        let mut session = Session::new();
        let Send::Init { nonce } = session.start(start, true) else { panic!("握手从 INIT 开始") };
        let step = session.on_challenge(&Challenge { nonce, cookie: COOKIE }, start + 20 * MS);
        assert_eq!(step, Step { send: None, event: Some(Event::Held) });
        assert!(!session.is_idle() && !session.is_up());
        assert_eq!(session.poll(start + Duration::from_secs(60), false), Step::default(), "停着的时候什么都不发，也不超时");

        assert_eq!(session.release(start + Duration::from_secs(61)), Some(Send::Auth { nonce, cookie: COOKIE }));
        assert_eq!(session.release(start + Duration::from_secs(61)), None);
        assert!(session.on_ok(&ok(nonce), start + Duration::from_secs(61) + 20 * MS).event.is_some());
    }

    #[test]
    fn the_session_is_pinged_every_five_seconds_and_pong_updates_rtt_and_observed_address() {
        let (mut session, up) = established();
        assert_eq!(session.poll(up + PROBE_INTERVAL - MS, false), Step::default());
        let Some(Send::Ping { nonce }) = session.poll(up + PROBE_INTERVAL, false).send else { panic!("该发保活了") };

        let moved: SocketAddr = "203.0.113.7:4001".parse().unwrap();
        assert_eq!(session.on_pong(&Pong { nonce: [0; 8], observed: moved }, up + PROBE_INTERVAL + 5 * MS), None, "随机数不对");
        assert_eq!(session.on_pong(&Pong { nonce, observed: moved }, up + PROBE_INTERVAL + 60 * MS), Some(moved));
        assert_eq!(session.on_pong(&Pong { nonce, observed: moved }, up + PROBE_INTERVAL + 70 * MS), None, "同一个 PONG 不算两次");
        assert_eq!(session.rtt().map(Rtt::get), Some(25 * MS), "握手的两个往返都是 20ms，再加上一个 60ms 的样本");
    }

    #[test]
    fn three_unanswered_pings_take_the_session_down() {
        let (mut session, up) = established();
        let timeout = session.rtt().unwrap().probe_timeout();
        let mut now = up + PROBE_INTERVAL;
        assert!(session.poll(now, false).send.is_some());
        for _ in 1..MAX_TIMEOUTS {
            now += timeout;
            let step = session.poll(now, false);
            assert!(matches!(step, Step { send: Some(Send::Ping { .. }), event: None }), "超时之后立刻再问：{step:?}");
            assert!(session.in_doubt());
        }
        now += timeout;
        assert_eq!(session.poll(now, false).event, Some(Event::Down { reason: "保活连续没有回应" }));
        assert!(session.is_idle());
    }

    #[test]
    fn an_answer_clears_the_missed_count() {
        let (mut session, up) = established();
        let timeout = session.rtt().unwrap().probe_timeout();
        session.poll(up + PROBE_INTERVAL, false);
        let Some(Send::Ping { nonce }) = session.poll(up + PROBE_INTERVAL + timeout, false).send else { panic!("该重发保活了") };
        assert!(session.in_doubt());
        assert!(session.on_pong(&Pong { nonce, observed: observed() }, up + PROBE_INTERVAL + timeout + 5 * MS).is_some());
        assert!(session.is_up() && !session.in_doubt());
    }

    #[test]
    fn silence_while_traffic_flows_brings_the_next_ping_forward() {
        let (mut session, up) = established();
        assert_eq!(session.poll(up + SILENCE - MS, true), Step::default());
        assert!(matches!(session.poll(up + SILENCE, true).send, Some(Send::Ping { .. })));
    }

    #[test]
    fn a_refusal_that_answers_a_keepalive_ends_the_session_so_that_it_can_be_rebuilt() {
        let (mut session, up) = established();
        let Some(Send::Ping { nonce }) = session.poll(up + PROBE_INTERVAL, false).send else { panic!("该发保活了") };
        assert_eq!(
            session.on_no_session(&nonce, up + PROBE_INTERVAL + 10 * MS).event,
            Some(Event::Down { reason: "relay 说本节点没有会话" })
        );
        assert!(session.is_idle());
        assert_eq!(session.on_no_session(&nonce, up + PROBE_INTERVAL + 20 * MS), Step::default(), "没有会话时这种帧没有意义");
    }

    #[test]
    fn a_refusal_that_echoes_nothing_this_node_sent_only_makes_it_ask_the_relay() {
        let (mut session, up) = established();
        // 伪造来源地址的人冒充 relay 说本节点没有会话：会话不拆，只是马上发一个 PING 去问。
        let at = up + Duration::from_secs(1);
        let step = session.on_no_session(&[0xee; 8], at);
        let Some(Send::Ping { nonce }) = step.send else { panic!("应该马上发一个 PING 去问：{step:?}") };
        assert!(session.is_up() && step.event.is_none());
        // 再多伪造的也不会让它多发：问的那个还在等回答，或者一秒之内问过。
        assert_eq!(session.on_no_session(&[0xef; 8], at + 10 * MS), Step::default());
        session.on_pong(&Pong { nonce, observed: observed() }, at + 20 * MS);
        assert!(session.is_up(), "relay 照常回答了：是伪造的");
        assert_eq!(session.on_no_session(&[0xef; 8], at + 30 * MS), Step::default(), "一秒之内问过了");
        assert!(session.on_no_session(&[0xef; 8], at + NO_SESSION_CHECK_GAP).send.is_some());

        // 会话握手的随机数是另一回事：它不是在回答保活，不能用来拆会话。
        let (mut session, up) = established();
        let State::Up { nonce: session_nonce, .. } = session.state else { panic!("会话已经建好了") };
        assert!(session.is_session_echo(&session_nonce) && !session.is_session_echo(&[0; 8]));
        assert!(session.on_no_session(&session_nonce, up + MS).send.is_some());
        assert!(session.is_up());
    }

    #[test]
    fn a_backbone_session_is_pinged_every_two_seconds() {
        let (mut session, up) = established();
        session.set_interval(crate::timing::BACKBONE_PROBE_INTERVAL);
        assert_eq!(session.poll(up + Duration::from_secs(2) - MS, false), Step::default());
        assert!(matches!(session.poll(up + Duration::from_secs(2), false).send, Some(Send::Ping { .. })));
    }

    #[test]
    fn a_probe_train_measures_loss_without_disturbing_the_keepalive() {
        let (mut session, up) = established();
        session.set_training(true);
        let mut pings = Vec::new();
        // 两秒里每 50ms 推进一步：探测包列发出 10 个，每三个回答两个。
        for step in 1..40u32 {
            let now = up + 50 * MS * step;
            if let Some(Send::Ping { nonce }) = session.poll(now, false).send {
                pings.push(nonce);
                if pings.len() % 3 != 0 {
                    assert_eq!(session.on_pong(&Pong { nonce, observed: observed() }, now + 20 * MS), Some(observed()));
                }
            }
        }
        assert_eq!(pings.len(), 10, "一组 10 个，发完就停到下一组");
        assert!(session.is_up() && !session.in_doubt(), "探测包列丢了回答不算保活超时");
        let quality = session.quality(up + Duration::from_secs(3)).unwrap();
        assert_eq!((quality.lost, quality.probes), (3, 12), "握手的两个样本，加上 10 个探测里丢的 3 个");

        // 不在候选路径上的会话不发探测包列。
        let (mut idle, up) = established();
        assert!((1..40u32).all(|step| idle.poll(up + 50 * MS * step, false).send.is_none()));
    }

    #[test]
    fn keepalive_timeouts_count_as_loss_and_the_estimate_expires() {
        let (mut session, up) = established();
        let timeout = session.rtt().unwrap().probe_timeout();
        session.poll(up + PROBE_INTERVAL, false);
        let Some(Send::Ping { nonce }) = session.poll(up + PROBE_INTERVAL + timeout, false).send else { panic!("该重发保活了") };
        session.on_pong(&Pong { nonce, observed: observed() }, up + PROBE_INTERVAL + timeout + 5 * MS);
        for _ in 0..7 {
            session.estimate.sample(20 * MS, up + PROBE_INTERVAL + timeout + 5 * MS);
        }
        let quality = session.quality(up + PROBE_INTERVAL + timeout + 6 * MS).unwrap();
        assert_eq!((quality.lost, quality.probes), (1, 11));
        assert_eq!(session.quality(up + PROBE_INTERVAL + timeout + crate::timing::ESTIMATE_TTL + 6 * MS), None, "过期作废");
    }

    /// 一条 TCP 的中转腿：每个探测都会被回答（TCP 不丢包），但 `stalls` 为真时每三个里有一个要等一次重传，迟到 900ms。
    /// 跑一分钟，返回这段链路按代价公式（`crate::cost`）算出来的代价。
    fn leg_cost(stalls: bool) -> f64 {
        let (mut session, up) = established();
        session.set_training(true);
        let mut answers: Vec<(Instant, Nonce)> = Vec::new();
        let mut sent = 0u32;
        for step in 1..1200u32 {
            let now = up + 50 * MS * step;
            for (at, nonce) in answers.extract_if(.., |(at, _)| *at <= now) {
                session.on_pong(&Pong { nonce, observed: observed() }, at);
            }
            if let Some(Send::Ping { nonce }) = session.poll(now, false).send {
                sent += 1;
                let delay = if stalls && sent.is_multiple_of(3) { 900 * MS } else { 20 * MS };
                answers.push((now + delay, nonce));
            }
            assert!(session.is_up(), "停顿不到连续三次保活超时，会话一直在");
        }
        let quality = session.quality(up + Duration::from_secs(60)).unwrap();
        crate::cost::path_cost(&[quality.segment()], 0, 0.0)
    }

    #[test]
    fn a_tcp_leg_that_keeps_stalling_costs_far_more_than_a_smooth_one() {
        let (smooth, stalling) = (leg_cost(false), leg_cost(true));
        assert!((19.0..25.0).contains(&smooth), "顺畅的那条差不多就是它的延迟：{smooth}");
        // 一个只看平滑延迟的比较会觉得两条差不多；停顿让抖动、延迟和丢包一起涨，代价差出好几倍。
        assert!(stalling > 5.0 * smooth, "顺畅 {smooth:.1}ms，停顿 {stalling:.1}ms");
    }

    #[test]
    fn a_tcp_session_dropped_for_silence_counts_how_long_it_stalled_in_its_delay() {
        let start = Instant::now();
        let mut session = Session::over_tcp(Estimate::new());
        let Send::Init { nonce } = session.start(start, false) else { panic!("握手从 INIT 开始") };
        session.on_challenge(&Challenge { nonce, cookie: COOKIE }, start + 250 * MS);
        let up = start + 500 * MS;
        assert!(session.on_ok(&ok(nonce), up).event.is_some());
        assert_eq!(session.quality(up).map(|quality| quality.rtt), Some(250 * MS), "握手的两个往返");

        // 之后这条 TCP 卡死了：保活一个也没有回答，三次超时之后会话拆掉。
        let (mut now, mut first_ping) = (up, None);
        let reason = loop {
            now += 50 * MS;
            assert!(now < up + Duration::from_secs(30), "保活没有回答，会话早该断了");
            let step = session.poll(now, false);
            if matches!(step.send, Some(Send::Ping { .. })) {
                first_ping.get_or_insert(now);
            }
            if let Some(Event::Down { reason }) = step.event {
                break reason;
            }
        };
        assert_eq!(reason, "保活连续没有回应");
        let stall = now.saturating_duration_since(first_ping.unwrap());
        assert!(stall >= Duration::from_secs(3), "三次超时，每次 1 秒（延迟的 4 倍）：{stall:?}");
        // 这一次停顿按它至少有多长算进平均：重连之后这条 TCP 不会只剩握手那两个漂亮的样本。
        let quality = session.quality(now).unwrap();
        assert_eq!(quality.rtt, (250 * MS * 2 + stall) / 3);
        assert_eq!((quality.jitter, quality.lost), (Duration::ZERO, 0));
    }

    #[test]
    fn a_udp_session_dropped_for_silence_does_not_turn_the_silence_into_delay() {
        let (mut session, up) = established();
        let mut now = up;
        while session.is_up() {
            now += 50 * MS;
            session.poll(now, false);
        }
        // UDP 上没有回答的保活照旧记成丢失（丢包率要攒够样本才报），不记成一个长延迟的样本。
        assert_eq!(session.quality(now).map(|quality| quality.rtt), Some(20 * MS));
        assert_eq!(session.measured().over_tcp(now).map(|quality| quality.rtt), Some(20 * MS));
    }

    #[test]
    fn stopping_makes_the_session_forget_everything_but_its_rtt() {
        let (mut session, up) = established();
        session.stop();
        assert!(session.is_idle());
        assert_eq!(session.poll(up + Duration::from_secs(60), true), Step::default());
        assert!(session.rtt().is_some());
    }
}
