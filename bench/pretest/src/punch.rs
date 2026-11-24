//! UDP 打洞的最小工具，只能在真实的 NAT 后面测。
//!
//! 一台有公网端口的机器跑汇合点，两台 NAT 后面的机器各跑一个节点、用同一个会话名。
//! 汇合点只做两件事：告诉每个节点它自己的公网地址，以及对端的公网地址。之后两个节点
//! 用各自同一个端口互相发探测包，双向都通了就算打洞成功。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::stats::{LatencyRecorder, LatencySummary, now_ns};

const REGISTER_INTERVAL: Duration = Duration::from_millis(200);
const PROBE_INTERVAL: Duration = Duration::from_millis(50);
const PING_INTERVAL: Duration = Duration::from_millis(100);
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);
/// 汇合点忘掉一个节点之前，容忍它多久没有再登记。
const STALE_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Message {
    /// 节点 → 汇合点：我在这个会话里。`nonce` 用来区分同一个会话里的两个节点。
    Register {
        session: String,
        nonce: u64,
    },
    /// 汇合点 → 节点：你的公网地址；对端已经到了的话带上它的公网地址。
    Registered {
        you: SocketAddr,
        peer: Option<SocketAddr>,
    },
    /// 节点 → 汇合点的任意端口：只问自己的公网地址。
    WhoAmI,
    YouAre {
        you: SocketAddr,
    },
    Probe {
        nonce: u64,
    },
    ProbeAck {
        nonce: u64,
    },
    Ping {
        seq: u32,
        sent_ns: u64,
    },
    Pong {
        seq: u32,
        sent_ns: u64,
    },
}

impl Message {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("消息里只有字符串、整数和地址，序列化不会失败")
    }

    fn decode(datagram: &[u8]) -> Option<Self> {
        serde_json::from_slice(datagram).ok()
    }
}

async fn send(socket: &UdpSocket, message: &Message, to: SocketAddr) -> std::io::Result<()> {
    socket.send_to(&message.encode(), to).await.map(|_sent| ())
}

/// 汇合点。`alt` 是第二个端口，节点用它看自己的映射端口是否随目的地变化。
pub async fn run_rendezvous(listen: SocketAddr, alt: Option<SocketAddr>) -> anyhow::Result<()> {
    let main = UdpSocket::bind(listen).await.with_context(|| format!("绑定 UDP {listen}"))?;
    let alt = match alt {
        Some(alt) => Some(UdpSocket::bind(alt).await.with_context(|| format!("绑定 UDP {alt}"))?),
        None => None,
    };
    serve_rendezvous(main, alt).await
}

/// 在已经绑好的套接字上当汇合点。`alt` 是只回答"你是谁"的第二个地址。
async fn serve_rendezvous(main: UdpSocket, alt: Option<UdpSocket>) -> anyhow::Result<()> {
    if let Some(socket) = alt {
        tokio::spawn(answer_who_am_i(socket));
    }

    struct Member {
        nonce: u64,
        addr: SocketAddr,
        seen: Instant,
    }
    let mut sessions: HashMap<String, Vec<Member>> = HashMap::new();
    let mut buf = [0; 2048];
    loop {
        let (len, from) = main.recv_from(&mut buf).await?;
        match Message::decode(&buf[..len]) {
            Some(Message::Register { session, nonce }) => {
                let members = sessions.entry(session).or_default();
                members.retain(|member| member.seen.elapsed() < STALE_AFTER);
                match members.iter().position(|member| member.nonce == nonce) {
                    Some(index) => (members[index].addr, members[index].seen) = (from, Instant::now()),
                    None if members.len() < 2 => members.push(Member { nonce, addr: from, seen: Instant::now() }),
                    // 一个会话只配对两个节点，多出来的不理。
                    None => continue,
                }
                let peer = members.iter().find(|member| member.nonce != nonce).map(|member| member.addr);
                send(&main, &Message::Registered { you: from, peer }, from).await?;
            }
            Some(Message::WhoAmI) => send(&main, &Message::YouAre { you: from }, from).await?,
            Some(
                Message::Registered { .. }
                | Message::YouAre { .. }
                | Message::Probe { .. }
                | Message::ProbeAck { .. }
                | Message::Ping { .. }
                | Message::Pong { .. },
            )
            | None => {}
        }
        sessions.retain(|_, members| !members.is_empty());
    }
}

async fn answer_who_am_i(socket: UdpSocket) {
    let mut buf = [0; 256];
    while let Ok((len, from)) = socket.recv_from(&mut buf).await {
        if matches!(Message::decode(&buf[..len]), Some(Message::WhoAmI)) {
            // 回不出去就算了，节点会重问。
            send(&socket, &Message::YouAre { you: from }, from).await.ok();
        }
    }
}

pub struct PeerOpts {
    pub rendezvous: SocketAddr,
    pub alt: Option<SocketAddr>,
    pub session: String,
    pub bind: SocketAddr,
    pub tries: u32,
    /// 等对端出现在汇合点的最长时间。
    pub wait_secs: u32,
    /// 拿到对端地址之后，探测多久还不通就算失败。
    pub punch_secs: u32,
    pub pings: u32,
}

#[derive(Debug, Default, Serialize)]
pub struct Attempt {
    index: u32,
    /// 汇合点看到的本节点地址。
    mapped: Option<SocketAddr>,
    /// 汇合点第二个端口观测到的地址与第一个不同：映射随目的地变化，此类 NAT 通常无法打洞。
    mapping_varies: Option<bool>,
    peer_announced: Option<SocketAddr>,
    /// 实际收到对端探测包的来源地址。和汇合点通告的不一样，说明对端的映射随目的地变化。
    peer_actual: Option<SocketAddr>,
    success: bool,
    /// 从拿到对端地址到双向都通。
    punch_ms: Option<f64>,
    rtt_ms: Option<LatencySummary>,
    ping_loss_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PunchReport {
    role: &'static str,
    session: String,
    attempts: u32,
    succeeded: u32,
    tries: Vec<Attempt>,
}

pub async fn run_peer(opts: PeerOpts) -> anyhow::Result<PunchReport> {
    let mut tries = Vec::new();
    for index in 0..opts.tries {
        let mut attempt = Attempt { index, ..Attempt::default() };
        if let Err(err) = one_attempt(&opts, &mut attempt).await {
            attempt.note = Some(format!("{err:#}"));
        }
        eprintln!(
            "第 {} 次：{}{}",
            index + 1,
            if attempt.success { "成功" } else { "失败" },
            attempt.punch_ms.map(|ms| format!("，{ms:.0}ms")).unwrap_or_default()
        );
        tries.push(attempt);
    }
    Ok(PunchReport {
        role: "punch",
        session: opts.session,
        attempts: opts.tries,
        succeeded: u32::try_from(tries.iter().filter(|attempt| attempt.success).count()).unwrap_or(u32::MAX),
        tries,
    })
}

async fn one_attempt(opts: &PeerOpts, attempt: &mut Attempt) -> anyhow::Result<()> {
    // 每次用一个新 socket：端口不固定时，NAT 上会是一条新的映射。
    let socket = UdpSocket::bind(opts.bind).await.with_context(|| format!("绑定 UDP {}", opts.bind))?;
    let nonce = now_ns() ^ u64::from(std::process::id()).rotate_left(32);
    let session = format!("{}#{}", opts.session, attempt.index);
    let mut buf = [0; 2048];

    let peer = wait_for_peer(&socket, opts, &session, nonce, attempt, &mut buf).await?;
    if let Some(alt) = opts.alt {
        attempt.mapping_varies = match ask_who_am_i(&socket, alt, &mut buf).await {
            Some(seen_by_alt) => attempt.mapped.map(|mapped| mapped != seen_by_alt),
            None => None,
        };
    }

    let Some((peer, elapsed)) = punch(&socket, peer, nonce, Duration::from_secs(u64::from(opts.punch_secs)), &mut buf).await? else {
        return Ok(());
    };
    attempt.success = true;
    attempt.peer_actual = Some(peer);
    attempt.punch_ms = Some(elapsed.as_secs_f64() * 1000.0);

    let (rtt, lost) = ping(&socket, peer, opts.pings, &mut buf).await?;
    attempt.rtt_ms = Some(rtt);
    attempt.ping_loss_pct = Some(if opts.pings == 0 { 0.0 } else { f64::from(lost) * 100.0 / f64::from(opts.pings) });
    Ok(())
}

/// 反复向汇合点登记，直到它告诉我们对端的地址。
async fn wait_for_peer(
    socket: &UdpSocket,
    opts: &PeerOpts,
    session: &str,
    nonce: u64,
    attempt: &mut Attempt,
    buf: &mut [u8],
) -> anyhow::Result<SocketAddr> {
    let register = Message::Register { session: session.to_owned(), nonce };
    let deadline = Instant::now() + Duration::from_secs(u64::from(opts.wait_secs));
    while Instant::now() < deadline {
        send(socket, &register, opts.rendezvous).await?;
        let Ok(received) = timeout(REGISTER_INTERVAL, socket.recv_from(buf)).await else { continue };
        let (len, _from) = received?;
        if let Some(Message::Registered { you, peer }) = Message::decode(&buf[..len]) {
            attempt.mapped = Some(you);
            if let Some(peer) = peer {
                attempt.peer_announced = Some(peer);
                return Ok(peer);
            }
        }
    }
    anyhow::bail!("等了 {} 秒，对端没有出现在汇合点", opts.wait_secs)
}

async fn ask_who_am_i(socket: &UdpSocket, alt: SocketAddr, buf: &mut [u8]) -> Option<SocketAddr> {
    for _ in 0..5 {
        send(socket, &Message::WhoAmI, alt).await.ok()?;
        let deadline = Instant::now() + REGISTER_INTERVAL;
        while let Ok(Ok((len, from))) = timeout(deadline.saturating_duration_since(Instant::now()), socket.recv_from(buf)).await {
            if from == alt
                && let Some(Message::YouAre { you }) = Message::decode(&buf[..len])
            {
                return Some(you);
            }
        }
    }
    None
}

/// 向对端发探测包，同时回应对端的探测。收到对端对我们探测的确认，说明两个方向都通了。
///
/// 返回对端实际的地址和打通用的时间；到时间还没通返回 `None`。
async fn punch(
    socket: &UdpSocket,
    announced: SocketAddr,
    nonce: u64,
    limit: Duration,
    buf: &mut [u8],
) -> anyhow::Result<Option<(SocketAddr, Duration)>> {
    let started = Instant::now();
    let mut peer = announced;
    let mut ticker = tokio::time::interval(PROBE_INTERVAL);
    while started.elapsed() < limit {
        tokio::select! {
            _ = ticker.tick() => send(socket, &Message::Probe { nonce }, peer).await?,
            received = socket.recv_from(buf) => {
                let (len, from) = received?;
                match Message::decode(&buf[..len]) {
                    Some(Message::Probe { nonce: theirs }) => {
                        // 对端的 NAT 可能给这条路换了一个端口，以实际收到的来源为准。
                        peer = from;
                        send(socket, &Message::ProbeAck { nonce: theirs }, from).await?;
                    }
                    Some(Message::ProbeAck { nonce: echoed }) if echoed == nonce => {
                        // 额外持续回应一段时间，确保对端也能收到确认，否则对端会判定失败。
                        linger(socket, nonce, from, buf).await?;
                        return Ok(Some((from, started.elapsed())));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(None)
}

async fn linger(socket: &UdpSocket, nonce: u64, peer: SocketAddr, buf: &mut [u8]) -> anyhow::Result<()> {
    let until = Instant::now() + Duration::from_millis(500);
    send(socket, &Message::Probe { nonce }, peer).await?;
    while let Ok(received) = timeout(until.saturating_duration_since(Instant::now()), socket.recv_from(buf)).await {
        let (len, from) = received?;
        if let Some(Message::Probe { nonce: theirs }) = Message::decode(&buf[..len]) {
            send(socket, &Message::ProbeAck { nonce: theirs }, from).await?;
        }
    }
    Ok(())
}

/// 在打通的洞上量往返时间和丢包。返回延迟分布和没有收到回应的次数。
async fn ping(socket: &UdpSocket, peer: SocketAddr, count: u32, buf: &mut [u8]) -> anyhow::Result<(LatencySummary, u32)> {
    let mut recorder = LatencyRecorder::new();
    let mut answered = 0;
    let mut ticker = tokio::time::interval(PING_INTERVAL);
    let mut sent = 0;
    let mut last_send = Instant::now();
    while sent < count || last_send.elapsed() < REPLY_TIMEOUT && answered < count {
        tokio::select! {
            _ = ticker.tick(), if sent < count => {
                send(socket, &Message::Ping { seq: sent, sent_ns: now_ns() }, peer).await?;
                sent += 1;
                last_send = Instant::now();
            }
            received = timeout(REPLY_TIMEOUT, socket.recv_from(buf)) => {
                let Ok(received) = received else { break };
                let (len, from) = received?;
                match Message::decode(&buf[..len]) {
                    Some(Message::Ping { seq, sent_ns }) => send(socket, &Message::Pong { seq, sent_ns }, from).await?,
                    Some(Message::Pong { sent_ns, .. }) => {
                        recorder.record_ns(now_ns().saturating_sub(sent_ns));
                        answered += 1;
                    }
                    Some(Message::Probe { nonce }) => send(socket, &Message::ProbeAck { nonce }, from).await?,
                    _ => {}
                }
            }
        }
    }
    Ok((recorder.summary(), count.saturating_sub(answered)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        let message = Message::Registered { you: "203.0.113.5:40000".parse().unwrap(), peer: None };
        let Some(Message::Registered { you, peer }) = Message::decode(&message.encode()) else {
            panic!("解码出来的不是 Registered");
        };
        assert_eq!((you.port(), peer), (40000, None));
        assert!(Message::decode(b"not json").is_none());
    }

    /// 两个节点都在本机，没有 NAT：只验证汇合、探测、确认这套流程能走通。
    #[tokio::test]
    async fn two_local_peers_find_each_other() {
        // 端口让系统挑，先绑好再开始：写死端口的话，机器上别的程序（或者同时跑着的另一份测试）占着就失败，
        // 等一会儿再开始也不保证汇合点已经在听。
        let (main, second) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (rendezvous, alt) = (main.local_addr().unwrap(), second.local_addr().unwrap());
        tokio::spawn(serve_rendezvous(main, Some(second)));

        let peer = || PeerOpts {
            rendezvous,
            alt: Some(alt),
            session: "unit".to_owned(),
            bind: "127.0.0.1:0".parse().unwrap(),
            tries: 1,
            wait_secs: 5,
            punch_secs: 5,
            pings: 10,
        };
        let (first, second) = tokio::join!(run_peer(peer()), run_peer(peer()));
        let mut losses = Vec::new();
        for report in [first.unwrap(), second.unwrap()] {
            assert_eq!(report.succeeded, 1, "本机两个节点应该能互相打通：{report:?}");
            let attempt = &report.tries[0];
            assert_eq!(attempt.mapping_varies, Some(false));
            losses.push(attempt.ping_loss_pct.expect("打通了就量过丢包"));
        }
        // 回环上不丢包，但两边进出 ping 的阶段不在同一刻：先开始的一方头几个 ping 到的时候，另一方还在打洞的收尾里，
        // 不回答 ping；机器忙的时候这个错开有几十到几百毫秒。先开始的一方因此等满回答的时限，这期间照样回答对方，
        // 所以至少有一方一个不丢，另一方只丢开头的几个。两边各自都要收到回答：洞是两个方向都通的。
        assert!(losses.iter().all(|&loss| loss < 100.0), "两边都应该收到过回答：{losses:?}");
        assert!(losses.contains(&0.0), "至少有一方一个都不丢：{losses:?}");
    }
}
