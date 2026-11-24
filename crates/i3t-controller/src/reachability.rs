//! 启用 relay 时从 controller 这边试连它的地址（地址是 controller 找出来的，见 `crate::node_addresses`）。
//!
//! 探测结果仅供参考，不会阻止启用 relay，也不代表 relay 故障：relay 的可用性取决于各节点自身到它的连通性。
//! controller 与其他节点处于不同网络位置，controller 可达不代表其他节点可达，反之亦然（例如 relay 仅在特定局域网内可达，而 controller 不在该局域网中）。
//!
//! - UDP：向那个地址发一次地址查询（`i3t_proto::addr`），收到带着同一个随机数的应答就算通。节点的 UDP 端口总在回答地址查询，
//!   不用等它把 relay 开起来。
//! - TCP：建连成功后立即关闭。relay 的 TCP 监听在节点收到新 netmap 后才启动，因此在超时时限内定期重试。

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use i3t_model::admin::{ReachCause, Reachability, Transport};
use i3t_proto::addr::{Query, Reply};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time;

/// 每个地址最多试这么久。
pub(crate) const CHECK_TIMEOUT: Duration = Duration::from_secs(3);
/// UDP 的查询每隔这么久重发一次：一个包丢了不能就算不通。
const UDP_RESEND: Duration = Duration::from_millis(500);
/// TCP 连接失败后的重试间隔：节点可能尚未开启监听。
const TCP_RETRY: Duration = Duration::from_millis(200);

/// 同时试 `udp` 和 `tcp` 里的每个地址，每个地址一项结果，顺序和给的一样（先 UDP 后 TCP）。最多等 [`CHECK_TIMEOUT`] 多一点。
pub(crate) async fn check(udp: &[SocketAddr], tcp: &[SocketAddr]) -> Vec<Reachability> {
    let udp = udp.iter().map(|&addr| (Transport::Udp, addr, tokio::spawn(check_udp(addr))));
    let tcp = tcp.iter().map(|&addr| (Transport::Tcp, addr, tokio::spawn(check_tcp(addr))));
    let checks: Vec<_> = udp.chain(tcp).collect();
    let mut results = Vec::with_capacity(checks.len());
    // 它们是同时在跑的，挨个等的总时间也就是最慢的那一个。
    for (protocol, addr, check) in checks {
        let unfinished = |error| failed(protocol, addr, format!("探测任务未完成：{error}"), ReachCause::Local);
        results.push(check.await.unwrap_or_else(unfinished));
    }
    results
}

async fn check_udp(addr: SocketAddr) -> Reachability {
    let started = Instant::now();
    let outcome = time::timeout(CHECK_TIMEOUT, ask_address(addr)).await;
    let rtt = started.elapsed();
    match outcome {
        Ok(Ok(())) => reached(Transport::Udp, addr, rtt),
        Ok(Err((error, cause))) => failed(Transport::Udp, addr, error, cause),
        Err(_) => failed(Transport::Udp, addr, format!("{} 秒内未收到地址查询应答", CHECK_TIMEOUT.as_secs()), ReachCause::Timeout),
    }
}

/// 向 `addr` 发送地址查询，直至收到匹配的应答。
async fn ask_address(addr: SocketAddr) -> Result<(), (String, ReachCause)> {
    let bind: SocketAddr = if addr.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
    let socket = UdpSocket::bind(bind).await.map_err(|error| (format!("绑定 UDP 端口失败：{error}"), ReachCause::Local))?;
    let mut nonce = [0; 8];
    SystemRandom::new().fill(&mut nonce).map_err(|_| ("系统的随机数源不可用".to_owned(), ReachCause::Local))?;
    let query = Query { nonce }.to_bytes();
    let mut buf = [0; 64];
    loop {
        socket.send_to(&query, addr).await.map_err(|error| (format!("发送地址查询失败：{error}"), cause_of(&error)))?;
        let deadline = time::sleep(UDP_RESEND);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut deadline => break,
                received = socket.recv_from(&mut buf) => {
                    // 部分系统会在此处上报 ICMP「端口不可达」错误：忽略并继续等待，直至超时才判定不可达。
                    let Ok((len, from)) = received else { continue };
                    if from == addr && Reply::parse(&buf[..len]).is_some_and(|reply| reply.nonce == nonce) {
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn check_tcp(addr: SocketAddr) -> Reachability {
    // 记录最近一次连接失败的原因，超时后用于说明不可达原因。不在超时后再做短超时重试：Windows 上被拒绝的连接
    // 通常需要约两秒才会返回拒绝错误，短超时探测只会得到「超时」。
    let mut last_error = None;
    let attempt = async {
        loop {
            let tried = Instant::now();
            match TcpStream::connect(addr).await {
                Ok(_stream) => return tried.elapsed(),
                Err(error) => {
                    last_error = Some(error);
                    time::sleep(TCP_RETRY).await;
                }
            }
        }
    };
    let outcome = time::timeout(CHECK_TIMEOUT, attempt).await;
    match outcome {
        Ok(rtt) => reached(Transport::Tcp, addr, rtt),
        // 一次失败都没有等到：连接一直没有回音。
        Err(_) => match last_error {
            Some(error) => failed(Transport::Tcp, addr, error.to_string(), cause_of(&error)),
            None => failed(Transport::Tcp, addr, "连接超时".to_owned(), ReachCause::Timeout),
        },
    }
}

fn reached(protocol: Transport, addr: SocketAddr, rtt: Duration) -> Reachability {
    let rtt_ms = u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX);
    Reachability { protocol, addr, reachable: true, rtt_ms: Some(rtt_ms), error: None, cause: None }
}

fn failed(protocol: Transport, addr: SocketAddr, error: String, cause: ReachCause) -> Reachability {
    tracing::info!(?protocol, %addr, %error, "controller 无法连接该 relay 地址。探测结果仅反映 controller 到该地址的连通性。");
    Reachability { protocol, addr, reachable: false, rtt_ms: None, error: Some(error), cause: Some(cause) }
}

/// 系统给的连接错误归到哪一类。
fn cause_of(error: &io::Error) -> ReachCause {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => ReachCause::Refused,
        io::ErrorKind::TimedOut => ReachCause::Timeout,
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => ReachCause::Unreachable,
        _ => ReachCause::Other,
    }
}
