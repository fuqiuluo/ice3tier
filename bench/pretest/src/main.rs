//! 实现前测试用的最小工具。一个二进制，四个角色：relay、服务端、客户端、TCP 中间跳。
//!
//! 客户端跑完一种负载后在标准输出打一行 JSON；relay 和服务端在收到 SIGINT / SIGTERM 时打一行自己的统计。

mod path;
mod punch;
mod quic;
mod relay;
mod stats;
mod transport;
mod wire;
mod workload;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use quinn::Endpoint;
use serde::Serialize;

use crate::path::{PathConfig, PathCounters, PathSocket, Route};
use crate::quic::{Cipher, Congestion, QuicOpts, QuicStats};
use crate::relay::RelayConfig;
use crate::stats::{LatencyRecorder, LatencySummary, ProcessUsage};
use crate::transport::{Connector, KcpMode, KcpOpts};
use crate::wire::NodeId;
use crate::workload::{BulkOpts, BulkReport, Direction, EchoOpts, EchoReport, LlmOpts, LlmReport};

#[derive(Parser)]
#[command(about = "ice3tier 实现前测试工具")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 只转发包的 relay
    Relay(RelayArgs),
    /// 服务端：接受连接，按请求收发数据
    Serve(ServeArgs),
    /// 客户端：跑一种负载，输出一行 JSON
    Run(RunArgs),
    /// 两条 TCP 之间搬数据的中间跳，作为"每一段各自重传"的对照组
    Hop {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        upstream: SocketAddr,
    },
    /// UDP 打洞测试，只能在真实的 NAT 后面跑
    Punch {
        #[command(subcommand)]
        role: PunchRole,
    },
}

#[derive(Subcommand)]
enum PunchRole {
    /// 汇合点：跑在有公网端口的机器上
    Rendezvous {
        #[arg(long)]
        listen: SocketAddr,
        /// 第二个端口，节点用它判断自己的映射端口是否随目的地变化
        #[arg(long)]
        alt: Option<SocketAddr>,
    },
    /// 节点：跑在 NAT 后面。两台机器用同一个会话名，各跑一个
    Peer(PunchPeerArgs),
}

#[derive(Args)]
struct PunchPeerArgs {
    /// 汇合点的地址
    #[arg(long)]
    rendezvous: SocketAddr,
    /// 汇合点的第二个端口
    #[arg(long)]
    alt: Option<SocketAddr>,
    /// 两端约定的名字
    #[arg(long)]
    session: String,
    /// 本地 UDP 地址。端口写 0 时每次尝试换一个端口
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
    /// 尝试多少次，用来统计成功率
    #[arg(long, default_value_t = 10)]
    tries: u32,
    /// 等对端出现在汇合点的最长时间
    #[arg(long, default_value_t = 60)]
    wait_secs: u32,
    /// 拿到对端地址之后探测多久还不通就算失败
    #[arg(long, default_value_t = 10)]
    punch_secs: u32,
    /// 打通之后发多少个 ping 量往返时间
    #[arg(long, default_value_t = 50)]
    pings: u32,
}

#[derive(Args)]
struct RelayArgs {
    #[arg(long)]
    udp: SocketAddr,
    /// 供无法使用 UDP 的节点接入的 TCP 端口
    #[arg(long)]
    tcp: Option<SocketAddr>,
    /// 目的节点不在本 relay 上时转给谁，写成 `节点编号=地址`，可以给多个
    #[arg(long = "route")]
    routes: Vec<StaticRoute>,
    #[arg(long, default_value_t = 1024)]
    tcp_queue: usize,
}

#[derive(Clone, Copy, Debug)]
struct StaticRoute {
    node: NodeId,
    next: SocketAddr,
}

impl FromStr for StaticRoute {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (node, next) = s.split_once('=').context("静态路由要写成 `节点编号=地址`")?;
        Ok(Self { node: node.parse()?, next: next.parse().with_context(|| format!("地址不对：{next}"))? })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum TransportKind {
    Quic,
    Tcp,
    Kcp,
}

/// 只对 QUIC 有意义：包走哪条路。
#[derive(Args)]
struct PathArgs {
    /// 本节点的编号
    #[arg(long, default_value = "1")]
    id: NodeId,
    /// 对端节点的编号
    #[arg(long, default_value = "2")]
    peer: NodeId,
    /// 对端直连用的物理地址。客户端用 --connect 给；服务端不给的话从收到的第一个直连包里学
    #[arg(long)]
    direct: Option<SocketAddr>,
    /// relay 的 UDP 地址
    #[arg(long)]
    relay: Option<SocketAddr>,
    /// relay 的 TCP 地址；给了就会连上去
    #[arg(long)]
    relay_tcp: Option<SocketAddr>,
    /// 一开始走哪条路
    #[arg(long, value_enum, default_value_t = Route::Direct)]
    route: Route,
    /// 中途换路，写成 `秒数:路径`，逗号分隔，例如 `5:direct,10:relay`
    #[arg(long = "switch", value_delimiter = ',')]
    switches: Vec<SwitchAt>,
    /// TCP 中转的发送队列最多排多少个包
    #[arg(long, default_value_t = 1024)]
    tcp_queue: usize,
}

#[derive(Clone, Copy, Debug)]
struct SwitchAt {
    at: Duration,
    route: Route,
}

impl FromStr for SwitchAt {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (secs, route) = s.split_once(':').context("换路要写成 `秒数:路径`")?;
        let secs: f64 = secs.parse().with_context(|| format!("秒数不对：{secs}"))?;
        let route = Route::from_str(route, true).map_err(|err| anyhow::anyhow!("路径不对：{err}"))?;
        Ok(Self { at: Duration::try_from_secs_f64(secs).context("秒数不能是负数")?, route })
    }
}

#[derive(Args)]
struct QuicArgs {
    /// 拥塞控制
    #[arg(long = "cc", value_enum, default_value_t = Congestion::Cubic)]
    congestion: Congestion,
    /// 每条流的接收窗口，MB。超过 2 左右时，重度丢包下一条流的空洞可能超过 QUIC 库的上限，
    /// 整条连接会被判为内部错误
    #[arg(long, default_value_t = 2)]
    window_mb: u32,
    /// 空闲超时，秒；0 表示不设
    #[arg(long, default_value_t = 30)]
    idle_secs: u32,
    /// 不用内核的 UDP 分段卸载。经过 netem 的测试要关掉，否则一次"丢包"丢的是一整批
    #[arg(long)]
    no_gso: bool,
    #[arg(long, value_enum, default_value_t = Cipher::Aes128)]
    cipher: Cipher,
    /// 本端愿意接收的最大 UDP 包长；0 表示用 QUIC 库的默认值（约 64KB）
    #[arg(long, default_value_t = 0)]
    max_udp_payload: u16,
    /// 对端最多能同时开多少条流。每条允许的流都要预先占一点内存
    #[arg(long, default_value_t = 16_384)]
    max_streams: u32,
}

impl QuicArgs {
    fn opts(&self) -> QuicOpts {
        QuicOpts {
            congestion: self.congestion,
            window_mb: self.window_mb,
            idle_secs: self.idle_secs,
            segmentation_offload: !self.no_gso,
            cipher: self.cipher,
            max_udp_payload: self.max_udp_payload,
            max_streams: self.max_streams,
        }
    }
}

#[derive(Args)]
struct KcpArgs {
    #[arg(long, value_enum, default_value_t = KcpMode::Fast)]
    kcp_mode: KcpMode,
    /// KCP 的收发窗口，单位是包
    #[arg(long, default_value_t = 1024)]
    kcp_window: u16,
}

impl KcpArgs {
    fn opts(&self) -> KcpOpts {
        KcpOpts { mode: self.kcp_mode, window: self.kcp_window }
    }
}

#[derive(Args)]
struct ServeArgs {
    #[arg(value_enum)]
    transport: TransportKind,
    #[arg(long)]
    listen: SocketAddr,
    #[command(flatten)]
    path: PathArgs,
    #[command(flatten)]
    quic: QuicArgs,
    #[command(flatten)]
    kcp: KcpArgs,
}

#[derive(Args)]
struct RunArgs {
    #[arg(value_enum)]
    transport: TransportKind,
    /// 服务端的地址。QUIC 只走 relay 时可以不给
    #[arg(long)]
    connect: Option<SocketAddr>,
    /// QUIC 的本地 UDP 地址
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
    #[command(flatten)]
    path: PathArgs,
    #[command(flatten)]
    quic: QuicArgs,
    #[command(flatten)]
    kcp: KcpArgs,
    #[command(flatten)]
    load: LoadArgs,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
enum Workload {
    /// 大流量上传或下载
    Bulk,
    /// 按节拍收发小消息，量往返延迟
    Echo,
    /// 大流量和小消息同时跑
    Mixed,
    /// 一批 LLM 形状的流式请求
    Llm,
    /// 反复新建连接，量第一次访问的耗时
    Setup,
}

#[derive(Args)]
struct LoadArgs {
    #[arg(long, value_enum, default_value_t = Workload::Bulk)]
    workload: Workload,
    #[arg(long, default_value_t = 10)]
    secs: u32,
    /// 算稳态吞吐时跳过开头几秒
    #[arg(long, default_value_t = 3)]
    warmup: u32,
    #[arg(long, default_value_t = 1)]
    streams: usize,
    #[arg(long = "dir", value_enum, default_value_t = Direction::Down)]
    direction: Direction,
    /// 输出每 100ms 一个点的吞吐序列
    #[arg(long)]
    series: bool,
    /// 小消息的发送间隔
    #[arg(long, default_value_t = 20)]
    interval_ms: u32,
    #[arg(long, default_value_t = 100)]
    msg_size: u32,
    /// mixed 负载里，小消息另开一条 QUIC 连接，不和大流量共用
    #[arg(long)]
    split: bool,
    /// setup 负载重复多少轮
    #[arg(long, default_value_t = 20)]
    rounds: u32,
    #[command(flatten)]
    llm: LlmArgs,
}

#[derive(Args)]
struct LlmArgs {
    /// 同时在途的请求数
    #[arg(long, default_value_t = 100)]
    concurrency: usize,
    /// 总共发多少个请求
    #[arg(long, default_value_t = 500)]
    requests: usize,
    #[arg(long, default_value_t = 30_000)]
    body_min: u64,
    #[arg(long, default_value_t = 1_000_000)]
    body_max: u64,
    /// 服务端收完请求体之后等多久才发第一个 token
    #[arg(long, default_value_t = 800)]
    ttft_ms: u32,
    #[arg(long, default_value_t = 200)]
    tokens: u32,
    #[arg(long, default_value_t = 30)]
    token_interval_ms: u32,
    #[arg(long, default_value_t = 80)]
    token_size: u32,
    /// 每隔这么多个请求有一个中途静默；0 表示都不静默
    #[arg(long, default_value_t = 0)]
    silent_every: usize,
    /// 静默的请求在发完多少个 token 之后开始静默
    #[arg(long, default_value_t = 20)]
    silent_after: u32,
    #[arg(long, default_value_t = 60_000)]
    silent_ms: u32,
}

impl LoadArgs {
    fn bulk(&self) -> BulkOpts {
        BulkOpts {
            streams: self.streams,
            secs: self.secs,
            // 预热不能占满整段时间，否则没有可以算稳态吞吐的窗口。
            warmup_secs: self.warmup.min(self.secs.saturating_sub(1)),
            direction: self.direction,
            keep_series: self.series,
        }
    }

    fn echo(&self) -> EchoOpts {
        EchoOpts { secs: self.secs, interval_ms: self.interval_ms, msg_size: self.msg_size }
    }

    fn llm(&self) -> LlmOpts {
        let llm = &self.llm;
        LlmOpts {
            concurrency: llm.concurrency,
            requests: llm.requests,
            body_min: llm.body_min,
            body_max: llm.body_max,
            ttft_ms: llm.ttft_ms,
            tokens: llm.tokens,
            interval_ms: llm.token_interval_ms,
            token_size: llm.token_size,
            silent_every: llm.silent_every,
            silent_after: llm.silent_after,
            silent_ms: llm.silent_ms,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "workload", rename_all = "lowercase")]
enum Outcome {
    Bulk { bulk: BulkReport },
    Echo { echo: EchoReport },
    Mixed { bulk: BulkReport, echo: EchoReport },
    Llm { llm: LlmReport },
    Setup { setup: SetupReport },
}

#[derive(Serialize)]
struct SetupReport {
    rounds: u32,
    /// 从发起新连接到在它上面收到第一条回显。
    new_connection_ms: LatencySummary,
    /// 在已经建好的连接上新开一条流，到收到第一条回显。只有 QUIC 有这一项。
    #[serde(skip_serializing_if = "Option::is_none")]
    new_stream_ms: Option<LatencySummary>,
}

#[derive(Serialize)]
struct RunReport {
    role: &'static str,
    transport: TransportKind,
    #[serde(flatten)]
    outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    quic: Option<QuicStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<PathCounters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<ProcessUsage>,
}

#[derive(Serialize)]
struct ServerReport {
    role: &'static str,
    transport: TransportKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<PathCounters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<ProcessUsage>,
}

/// 往标准输出打一行 JSON。测试脚本按行收集。
pub fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(line) => println!("{line}"),
        Err(err) => eprintln!("统计结果序列化失败：{err}"),
    }
}

/// 等到进程被要求退出。
#[cfg(unix)]
pub async fn wait_for_shutdown() -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    Ok(())
}

/// 等到进程被要求退出（Ctrl-C）。
#[cfg(not(unix))]
pub async fn wait_for_shutdown() -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Relay(args) => {
            let report = relay::run(RelayConfig {
                udp: args.udp,
                tcp: args.tcp,
                routes: args.routes.iter().map(|route| (route.node, route.next)).collect(),
                tcp_queue: args.tcp_queue,
            })
            .await?;
            print_json(&report);
        }
        Command::Serve(args) => serve(args).await?,
        Command::Run(args) => run(args).await?,
        Command::Hop { listen, upstream } => {
            tokio::select! {
                result = transport::run_tcp_hop(listen, upstream) => result?,
                result = wait_for_shutdown() => result?,
            }
            print_json(&ServerReport { role: "hop", transport: TransportKind::Tcp, path: None, usage: ProcessUsage::of_this_process() });
        }
        Command::Punch { role: PunchRole::Rendezvous { listen, alt } } => {
            tokio::select! {
                result = punch::run_rendezvous(listen, alt) => result?,
                result = wait_for_shutdown() => result?,
            }
        }
        Command::Punch { role: PunchRole::Peer(args) } => {
            let report = punch::run_peer(punch::PeerOpts {
                rendezvous: args.rendezvous,
                alt: args.alt,
                session: args.session,
                bind: args.bind,
                tries: args.tries,
                wait_secs: args.wait_secs,
                punch_secs: args.punch_secs,
                pings: args.pings,
            })
            .await?;
            print_json(&report);
        }
    }
    Ok(())
}

async fn bind_path(args: &PathArgs, bind: SocketAddr, direct: Option<SocketAddr>) -> anyhow::Result<Arc<PathSocket>> {
    PathSocket::bind(PathConfig {
        local: args.id,
        peer: args.peer,
        bind,
        direct: direct.or(args.direct),
        relay_udp: args.relay,
        relay_tcp: args.relay_tcp,
        initial: args.route,
        tcp_queue: args.tcp_queue,
    })
    .await
}

/// 从调用这一刻起，按给定的时间表换路。
fn schedule_switches(socket: Arc<PathSocket>, switches: Vec<SwitchAt>) {
    if switches.is_empty() {
        return;
    }
    let started = Instant::now();
    tokio::spawn(async move {
        for switch in switches {
            tokio::time::sleep_until((started + switch.at).into()).await;
            socket.set_route(switch.route);
        }
    });
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let mut path_socket = None;
    match args.transport {
        TransportKind::Quic => {
            let socket = bind_path(&args.path, args.listen, None).await?;
            let endpoint = quic::server_endpoint(Arc::clone(&socket), args.quic.opts())?;
            let (switch_socket, switches) = (Arc::clone(&socket), args.path.switches.clone());
            // 换路的时间表从第一条连接到来时开始计，和客户端那边大致对齐。
            tokio::spawn(transport::serve_quic(endpoint, move || schedule_switches(switch_socket, switches)));
            path_socket = Some(socket);
        }
        TransportKind::Tcp => {
            tokio::spawn(transport::serve_tcp(args.listen));
        }
        TransportKind::Kcp => {
            tokio::spawn(transport::serve_kcp(args.listen, args.kcp.opts().config()));
        }
    }
    wait_for_shutdown().await?;
    print_json(&ServerReport {
        role: "server",
        transport: args.transport,
        path: path_socket.map(|socket| socket.counters()),
        usage: ProcessUsage::of_this_process(),
    });
    Ok(())
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    let report = match args.transport {
        TransportKind::Quic => run_quic(&args).await?,
        TransportKind::Tcp => {
            let addr = args.connect.context("TCP 要用 --connect 给出服务端地址")?;
            run_per_stream(&args, Connector::Tcp(addr)).await?
        }
        TransportKind::Kcp => {
            let addr = args.connect.context("KCP 要用 --connect 给出服务端地址")?;
            run_per_stream(&args, Connector::Kcp { config: args.kcp.opts().config(), addr }).await?
        }
    };
    print_json(&report);
    Ok(())
}

/// TCP 和 KCP：每条流就是一条新连接，没有"连接"这一层可以复用。
async fn run_per_stream(args: &RunArgs, connector: Connector) -> anyhow::Result<RunReport> {
    let connector = Arc::new(connector);
    let load = &args.load;
    let outcome = match load.workload {
        Workload::Bulk => Outcome::Bulk { bulk: workload::run_bulk(&connector, load.bulk()).await? },
        Workload::Echo => Outcome::Echo { echo: workload::run_echo(&connector, load.echo()).await? },
        Workload::Mixed => {
            let (bulk, echo) = tokio::join!(workload::run_bulk(&connector, load.bulk()), workload::run_echo(&connector, load.echo()));
            Outcome::Mixed { bulk: bulk?, echo: echo? }
        }
        Workload::Llm => Outcome::Llm { llm: workload::run_llm(&connector, load.llm()).await? },
        Workload::Setup => {
            let mut new_connection = LatencyRecorder::new();
            for _ in 0..load.rounds {
                new_connection.record_ns(workload::first_echo_ns(&connector).await?);
            }
            Outcome::Setup { setup: SetupReport { rounds: load.rounds, new_connection_ms: new_connection.summary(), new_stream_ms: None } }
        }
    };
    Ok(RunReport { role: "client", transport: args.transport, outcome, quic: None, path: None, usage: ProcessUsage::of_this_process() })
}

async fn connect_quic(endpoint: &Endpoint, peer: NodeId) -> anyhow::Result<quinn::Connection> {
    endpoint.connect(peer.virtual_addr(), "pretest")?.await.context("QUIC 握手失败")
}

async fn run_quic(args: &RunArgs) -> anyhow::Result<RunReport> {
    let socket = bind_path(&args.path, args.bind, args.connect).await?;
    let endpoint = quic::client_endpoint(Arc::clone(&socket), args.quic.opts())?;
    let peer = args.path.peer;
    let load = &args.load;

    if load.workload == Workload::Setup {
        let setup = measure_quic_setup(&endpoint, peer, load.rounds).await?;
        endpoint.wait_idle().await;
        return Ok(RunReport {
            role: "client",
            transport: args.transport,
            outcome: Outcome::Setup { setup },
            quic: None,
            path: Some(socket.counters()),
            usage: ProcessUsage::of_this_process(),
        });
    }

    let connection = connect_quic(&endpoint, peer).await?;
    schedule_switches(Arc::clone(&socket), args.path.switches.clone());
    let connector = Arc::new(Connector::Quic(connection.clone()));
    let outcome = match load.workload {
        Workload::Bulk => Outcome::Bulk { bulk: workload::run_bulk(&connector, load.bulk()).await? },
        Workload::Echo => Outcome::Echo { echo: workload::run_echo(&connector, load.echo()).await? },
        Workload::Mixed => {
            let echo_connector =
                if load.split { Arc::new(Connector::Quic(connect_quic(&endpoint, peer).await?)) } else { Arc::clone(&connector) };
            let (bulk, echo) = tokio::join!(workload::run_bulk(&connector, load.bulk()), workload::run_echo(&echo_connector, load.echo()));
            Outcome::Mixed { bulk: bulk?, echo: echo? }
        }
        Workload::Llm => Outcome::Llm { llm: workload::run_llm(&connector, load.llm()).await? },
        Workload::Setup => bail!("setup 负载已在前序分支处理，不应到达此处"),
    };

    let stats = connection.stats();
    endpoint.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(RunReport {
        role: "client",
        transport: args.transport,
        outcome,
        quic: Some(stats.into()),
        path: Some(socket.counters()),
        usage: ProcessUsage::of_this_process(),
    })
}

async fn measure_quic_setup(endpoint: &Endpoint, peer: NodeId, rounds: u32) -> anyhow::Result<SetupReport> {
    let mut new_connection = LatencyRecorder::new();
    let mut new_stream = LatencyRecorder::new();
    for _ in 0..rounds {
        let started = Instant::now();
        let connection = connect_quic(endpoint, peer).await?;
        let connector = Connector::Quic(connection.clone());
        let first_echo = workload::first_echo_ns(&connector).await?;
        let handshake_and_echo = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        // first_echo 仅包含握手后的阶段；总时长才代表"第一次访问"的耗时。
        new_connection.record_ns(handshake_and_echo.max(first_echo));
        new_stream.record_ns(workload::first_echo_ns(&connector).await?);
        connection.close(0u32.into(), b"round done");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(SetupReport { rounds, new_connection_ms: new_connection.summary(), new_stream_ms: Some(new_stream.summary()) })
}
