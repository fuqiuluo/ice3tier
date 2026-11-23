//! 处理别的节点开过来的流和数据报上下文。

use std::collections::HashMap;
use std::future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use i3t_access::{ForwardHealth, NoRoutes, OwnListener, RouteAtStart, SharedRoutes, TargetCause, proxy_header};
use i3t_conn::contract::{DatagramSender, Datagrams};
use i3t_conn::{Connector, Endpoint, RecvStream, SendStream};
use i3t_flow::datagram::{self, Opener, OutboundSocket};
use i3t_flow::{Carriage, End, Flow, FlowError, Handler, Request, Screening};
use i3t_model::Netmap;
use i3t_model::netmap::{Forward, ForwardProtocol, ForwardTarget, Peer};
use i3t_proto::flow::{Open, Reason, Reply, Status, Target};
use i3t_proto::{NodeId, PublicKey};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::datagrams::{ContextLimit, IDLE_TIMEOUT, MAX_CONTEXTS_PER_PEER, Session};
use crate::grant::Grant;
use crate::limits::{ExitMeter, Limits, QuotaState};
use crate::outbound::{Asker, Outbound};
use crate::stats::{Counters, ExitStats};
use crate::system::{Os, System};

/// 一个发起节点同时能有多少条流在本节点上被处理（还在读 OPEN 的、连着目标在搬运的、数据报上下文都算）。
///
/// 每条流在出口上占一个任务、两块搬运的缓冲区，连到目标的还占一个文件描述符。没有这个上限，
/// 一个被允许访问本节点的节点可以开上万条流、每条都连到一个不说话的目标，把文件描述符耗尽，整个节点跟着用不了。
///
/// 取 16384，和一条连接上并发流的上限一样。它要装得下这个产品最重的正当用法：一个网关把几千个长时间挂着的请求
/// 经同一个出口发出去（实测 2000 个并发请求时，取 1024 会让将近一半的请求被拒绝）。同一个对端最多有两条连接，
/// 所以它仍然是一个真的上限。节点启动时会把能打开的文件数抬到系统允许的最大值，这么多条流不会把它用完。
pub(crate) const MAX_STREAMS_PER_PEER: usize = 16_384;

/// 同一个发起节点因为流太多被拒绝时，多久最多记一行 info。每条被拒绝的流另有一行 debug。
const BUSY_LOG_EVERY: Duration = Duration::from_secs(60);

/// 一个节点接受流的那一侧。
///
/// 对端开过来的每条流在读 OPEN 之前先筛一遍（[`Handler::screen`]）：
///
/// - 访问规则不允许发起节点访问本节点：两个方向立刻重置，原因码是 [`Reason::AccessRevoked`]，它发来的东西一个字节也不读。
///   发起方把这当作 [`Status::AccessDenied`] 的拒绝。
/// - 发起节点在本节点上同时开着的流到了 [`MAX_STREAMS_PER_PEER`]：不读 OPEN，回 [`Status::TooManyStreams`]。
///
/// 通过的流读出 OPEN，再按这个顺序检查，不通过就用对应的状态拒绝：
///
/// 1. 访问规则：发起节点在当前的 netmap 里必须被允许访问本节点。发起节点是谁来自连接的握手，这里不信任入口的判断。
/// 2. 节点正在排空（[`Exit::set_draining`]）时一律拒绝，状态是 [`Status::Draining`]：调用方据此换一个出口。
///    这一步排在访问规则之后，不能访问本节点的节点看不出它在排空。
/// 3. 按目标的种类查本节点的能力和策略：
///    - 互联网：本节点启用了出口，端口在允许的范围里；配额没有用完，发起节点对这个目标的建连预算没有用完；
///      解析出来的地址按地址族挑过之后，每个都过出站策略；
///    - 局域网：本节点启用了出口并打开了局域网开关，配额和建连预算同上，地址在本机网卡直连的网段里；
///    - 本节点的端口：只用本机的非回环地址去连，程序自己的监听（代理、端口转发、名字服务）占着的地址不连。
///      那个端口上有监听在虚拟 IP 或者全部地址上的端口转发时，按那条转发处理（来源白名单按发起节点的虚拟 IP 查）：
///      目标是本节点就去连它指向的地址，目标是别的节点就到那个节点开一条流，把两条流接起来；
///    - 端口转发：必须是下发给本节点、并且由发起节点监听的那一条。不需要本节点是出口。
/// 4. 连上目标之后回成功，开始搬运。发起节点更换公钥、失去访问权限，或者放行这条流的能力被收回（出口、局域网开关、
///    端口转发，见 `grant` 模块）时，正在搬运的流被重置，原因码是 [`Reason::AccessRevoked`]。
///
/// 出口流量（互联网和局域网目标）搬运时算进配额，配额用完时正在搬运的流被断开（见 [`crate::limits`]）。
///
/// UDP 应用的数据走数据报上下文。建立上下文时只查访问规则、排空和上下文的个数（每个对端最多 128 个）；
/// 目标写在每个数据报里，所以第 3 步的检查落在每个目标第一次出现的时候，规则和流的完全一样，
/// 只是端口转发要的是 UDP 的那一条；监听在虚拟 IP 上、目标是别的节点的 UDP 转发，由本节点到目标节点另开一个上下文接力。
/// 没通过的数据报被丢掉并计数，UDP 没有地方回错误。
/// 出口流量的数据报同样算进配额，配额用完时丢掉。上下文没有报文往来 60 秒就回收。
///
/// 把它交给 [`i3t_flow::serve`] 就开始工作。`C` 是本节点到别的节点开流和数据报上下文用的，只有监听在虚拟 IP 上、
/// 目标是别的节点的端口转发要用；UDP 的这种转发还要 [`with_opener`](Self::with_opener) 交进来的那个开上下文的。
pub struct Exit<S = Os, C: Datagrams = Endpoint> {
    netmap: watch::Receiver<Arc<Netmap>>,
    outbound: Outbound<S>,
    connector: Arc<C>,
    /// 接力 UDP 端口转发时到目标节点开数据报上下文用的，和入口共用同一个。
    opener: Option<Arc<Opener<C>>>,
    counters: Counters,
    contexts: ContextLimit,
    limits: Limits,
    /// 正在排空时有值：给发起方看的说明。
    draining: Mutex<Option<String>>,
    datagram_idle_timeout: Duration,
    /// 每个发起节点上一次因为流太多被拒绝而记 info 的时刻。
    busy_logged: Mutex<HashMap<NodeId, Instant>>,
    /// 监听在本节点虚拟 IP 上的端口转发连不连得上目标，和入口记的是同一份（[`with_forward_health`](Self::with_forward_health)）。
    forward_health: ForwardHealth,
    /// 到各个对端现在走哪条路，写进每条流结束时的摘要（[`with_routes`](Self::with_routes)）。
    routes: SharedRoutes,
}

impl<S, C: Datagrams> std::fmt::Debug for Exit<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exit").field("counters", &self.counters).finish_non_exhaustive()
    }
}

/// 一个通过了检查的建流请求接下来怎么搬。
enum Admitted<S, R> {
    /// 连上了一个 TCP 目标。`exit_traffic` 为真时这是出口流量，要记配额。
    Target { stream: TcpStream, exit_traffic: bool },
    /// 到端口转发的目标节点开好了一条流，要和发起方的流接起来。
    Onward(Flow<S, R>),
}

impl<S: System, C: Connector + Datagrams> Exit<S, C> {
    #[must_use]
    pub fn new(netmap: watch::Receiver<Arc<Netmap>>, outbound: Outbound<S>, connector: Arc<C>) -> Self {
        Self {
            netmap,
            outbound,
            connector,
            opener: None,
            counters: Counters::default(),
            contexts: ContextLimit::default(),
            limits: Limits::new(QuotaState::default()),
            draining: Mutex::new(None),
            datagram_idle_timeout: IDLE_TIMEOUT,
            busy_logged: Mutex::default(),
            forward_health: ForwardHealth::default(),
            routes: Arc::new(NoRoutes),
        }
    }

    /// 到各个对端现在走哪条路从哪里问：每条流结束时的摘要里写它（和入口用同一个）。不设时摘要里的路是"不知道"。
    #[must_use]
    pub fn with_routes(mut self, routes: SharedRoutes) -> Self {
        self.routes = routes;
        self
    }

    /// 监听在本节点虚拟 IP 上的端口转发的流在目标那里成没成，记到哪里。装配时交进入口的那一份
    /// （`i3t_access::Access::forward_health`），上报里就有这些转发的"目标连不上"。不设时记在一份没有人看的里面。
    #[must_use]
    pub fn with_forward_health(mut self, health: ForwardHealth) -> Self {
        self.forward_health = health;
        self
    }

    /// 数据报上下文没有报文往来多久之后回收。默认 60 秒；测试里调短，不用真的等一分钟。
    #[must_use]
    pub fn with_datagram_idle_timeout(mut self, timeout: Duration) -> Self {
        self.datagram_idle_timeout = timeout;
        self
    }

    /// 接力 UDP 端口转发（监听在本节点虚拟 IP 上、目标是别的节点）时开数据报上下文用的。要和入口共用同一个
    /// （`i3t_access::Access::datagram_opener`）：对端发回来的数据报只由一个分发。不设时这种转发上的报文被丢掉。
    #[must_use]
    pub fn with_opener(mut self, opener: Arc<Opener<C>>) -> Self {
        self.opener = Some(opener);
        self
    }

    /// 接着上一次运行记下的配额用量往下记。装配层在启动时交进来；账期已经换了的话自动从零算。
    #[must_use]
    pub fn with_quota_state(mut self, state: QuotaState) -> Self {
        self.limits = Limits::new(state);
        self
    }

    /// 现在的配额用量，装配层定期存下来，下次启动时交回 [`with_quota_state`](Self::with_quota_state)。
    #[must_use]
    pub fn quota_state(&self) -> QuotaState {
        self.limits.quota_state()
    }

    /// 开始或者结束排空。`Some(说明)` 时新的流和数据报上下文一律被拒绝，状态是 [`Status::Draining`]，
    /// 说明原样给发起方；手上的流不受影响。
    pub fn set_draining(&self, draining: Option<String>) {
        *self.draining.lock().expect("draining mutex poisoned") = draining;
    }

    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.lock().expect("draining mutex poisoned").is_some()
    }

    /// 到现在为止的计数，加上配额用到了哪里。
    #[must_use]
    pub fn stats(&self) -> ExitStats {
        self.limits.configure(self.netmap.borrow().me.exit.as_ref());
        ExitStats { quota: self.limits.quota_usage(), draining: self.is_draining(), ..self.counters.snapshot() }
    }

    /// 排空期间给发起方的拒绝。
    fn drain_refusal(&self) -> Option<Reply> {
        let detail = self.draining.lock().expect("draining mutex poisoned").clone()?;
        self.counters.drained();
        Some(Reply::new(Status::Draining, detail))
    }

    /// 检查一个建流请求，通过的话连上它的目标，并返回放行凭据和本次判断使用的发起节点公钥。
    async fn admit(&self, netmap: &Netmap, peer: NodeId, open: &Open) -> Result<(Admitted<C::Send, C::Recv>, Grant, PublicKey), Reply> {
        let Some(initiator) = netmap.peer(peer).filter(|initiator| initiator.inbound) else {
            return Err(Reply::new(Status::AccessDenied, "访问规则不允许发起节点访问这个节点"));
        };
        if let Some(reply) = self.drain_refusal() {
            return Err(reply);
        }
        let exit_traffic = |stream| Admitted::Target { stream, exit_traffic: true };
        let local = |stream| Admitted::Target { stream, exit_traffic: false };
        let admitted = match &open.target {
            Target::Internet { host, port } => {
                self.exit_admission(netmap, peer, &format!("{host}:{port}"))?;
                let stream = self.outbound.internet(netmap, host, *port, Asker::Peer(peer)).await?;
                Ok((exit_traffic(stream), Grant::Internet { port: *port }))
            }
            Target::Lan { addr } => {
                self.exit_admission(netmap, peer, &addr.to_string())?;
                let stream = self.outbound.lan(netmap, *addr).await?;
                Ok((exit_traffic(stream), Grant::Lan))
            }
            Target::Node { port } => match forward_at_node_port(netmap, *port, ForwardProtocol::Tcp, &self.outbound.own_listeners()) {
                Some(forward) if forward.target != netmap.me.id => {
                    let flow = self.onward(netmap, initiator, forward, open).await?;
                    let grant = Grant::VirtualForward { id: forward.id, bind: forward.bind, target: forward.target, addr: None };
                    Ok((Admitted::Onward(flow), grant))
                }
                Some(forward) => {
                    let entry = virtual_forward_target(netmap, initiator, forward)?;
                    let connected = self.outbound.forward(entry.addr).await;
                    self.forward_health.record(forward.id, connected.as_ref().map(drop).map_err(|reply| forward_cause(reply.status)));
                    let stream = present(connected?, &entry, initiator).await?;
                    let grant =
                        Grant::VirtualForward { id: forward.id, bind: forward.bind, target: forward.target, addr: Some(entry.addr) };
                    Ok((local(stream), grant))
                }
                None => Ok((local(self.outbound.node_port(*port).await?), Grant::NodeService)),
            },
            Target::Forward { id } => {
                let listed = netmap
                    .me
                    .forward_targets
                    .iter()
                    .find(|entry| entry.id == *id && entry.listener == peer && entry.protocol == ForwardProtocol::Tcp);
                match listed {
                    Some(entry) => {
                        let stream = self.outbound.forward(entry.addr).await?;
                        let stream = present(stream, entry, initiator).await?;
                        Ok((local(stream), Grant::Forward { id: *id, addr: entry.addr }))
                    }
                    None => Err(Reply::new(Status::UnknownForward, "没有下发给这个节点、由发起节点监听的这条 TCP 端口转发")),
                }
            }
        };
        admitted.map(|(admitted, grant)| (admitted, grant, initiator.key))
    }

    /// 发起节点同时开着的流太多，拒绝它的又一条。info 日志每个节点每分钟最多一行，被拒绝的流本身只记 debug：
    /// 不然一个节点不停地开流就能刷屏。
    fn refuse_busy(&self, peer: NodeId) -> Screening {
        self.counters.turned_away(Status::TooManyStreams);
        let now = Instant::now();
        let first_in_a_while = {
            let mut logged = self.busy_logged.lock().expect("busy log mutex poisoned");
            logged.retain(|_, at| now.saturating_duration_since(*at) < BUSY_LOG_EVERY);
            let first = !logged.contains_key(&peer);
            if first {
                logged.insert(peer, now);
            }
            first
        };
        if first_in_a_while {
            tracing::info!(%peer, limit = MAX_STREAMS_PER_PEER, "发起节点在本节点上同时开着的流到了上限，新的流被拒绝（{BUSY_LOG_EVERY:?} 之内不再为它记这一行）");
        } else {
            tracing::debug!(%peer, "拒绝了一条流：发起节点同时开着的流到了上限");
        }
        Screening::Refuse(Reply::new(
            Status::TooManyStreams,
            format!("发起节点在这个节点上同时开着的流到了上限（{MAX_STREAMS_PER_PEER} 条），等手上的流结束一些再开"),
        ))
    }

    /// 出口流量在连目标之前的两项检查：配额，和建连预算。本节点不是出口时不查，留给出站那一步去拒绝。
    fn exit_admission(&self, netmap: &Netmap, peer: NodeId, target: &str) -> Result<(), Reply> {
        let Some(role) = &netmap.me.exit else { return Ok(()) };
        if self.limits.quota_exhausted() {
            let used =
                self.limits.quota_usage().map(|usage| format!("（本账期已用 {} 字节，配额 {} 字节）", usage.used_bytes, usage.limit_bytes));
            return Err(Reply::new(Status::QuotaExhausted, format!("出口本账期的流量配额已经用完{}", used.unwrap_or_default())));
        }
        if !self.limits.admit_connect(peer, target) {
            let per_minute = role.connects_per_minute.unwrap_or_default();
            return Err(Reply::new(
                Status::RateLimited,
                format!("发起节点向这个目标建连太频繁，超过了出口的建连预算（每分钟 {per_minute} 次）"),
            ));
        }
        Ok(())
    }

    /// 对组网里的节点开着（监听在本节点的虚拟 IP 或者全部地址上）、目标是别的节点的端口转发：替发起节点到目标节点开一条流。
    ///
    /// 访问规则查两段：发起节点要能访问本节点（已经查过），本节点要能访问目标节点（目标节点自己还会按转发的编号再查一遍）。
    /// 往目标节点去的这一段和别的端口转发一样只走共用的连接，不走 ice3proxy。
    async fn onward(&self, netmap: &Netmap, initiator: &Peer, forward: &Forward, open: &Open) -> Result<Flow<C::Send, C::Recv>, Reply> {
        check_allow_list(initiator, forward)?;
        if !netmap.peer(forward.target).is_some_and(|target| target.outbound) {
            return Err(Reply::new(Status::UnknownForward, "这条端口转发的目标节点不在本节点的 netmap 里，或者访问规则不允许本节点访问它"));
        }
        let request = Open { target: Target::Forward { id: forward.id }, class: open.class, origin: open.origin.clone() };
        let opened = async { i3t_flow::open(&*self.connector, forward.target, &request, b"", Carriage::Shared).await?.established().await };
        let (outcome, result) = match opened.await {
            Ok(flow) => (Ok(()), Ok(flow)),
            // 目标节点的拒绝原样转给发起节点：连接被拒绝、转发没有下发等，对方都该知道得和直接访问一样准确。
            Err(FlowError::Refused(reply)) => (Err(forward_cause(reply.status)), Err(reply)),
            Err(error) => (
                Err(TargetCause::NodeUnreachable),
                Err(Reply::new(Status::Unreachable, format!("到端口转发的目标节点 {} 建流失败：{error}", forward.target))),
            ),
        };
        self.forward_health.record(forward.id, outcome);
        result
    }
}

impl<S: System, C: Connector + Datagrams> Handler for Exit<S, C> {
    fn screen(&self, peer: NodeId, in_progress: usize) -> Screening {
        if !self.netmap.borrow().peer(peer).is_some_and(|initiator| initiator.inbound) {
            self.counters.turned_away(Status::AccessDenied);
            // 每条流一行，不记成 info：不然一个不被允许的节点不停地开流就能刷屏。
            tracing::debug!(%peer, "重置了一条流：访问规则不允许发起节点访问本节点，没有读它发来的任何东西");
            return Screening::Reset(Reason::AccessRevoked);
        }
        if in_progress >= MAX_STREAMS_PER_PEER {
            return self.refuse_busy(peer);
        }
        Screening::Admit
    }

    async fn handle<Snd: SendStream, Rcv: RecvStream>(&self, request: Request<Snd, Rcv>) {
        let _active = self.counters.begin();
        let peer = request.peer();
        let route = RouteAtStart::now(&*self.routes, peer);
        let (class, kind) = (request.open().class, request.open().target.kind());
        // 先记下"已经看过"的版本再判断，之后的变化才不会漏掉。
        let mut netmap_changes = self.netmap.clone();
        let netmap = Arc::clone(&netmap_changes.borrow_and_update());
        self.limits.configure(netmap.me.exit.as_ref());

        let (admitted, grant, key) = match self.admit(&netmap, peer, request.open()).await {
            Ok(admitted) => admitted,
            Err(reply) => {
                self.counters.failed(reply.status);
                tracing::info!(%peer, ?class, kind, status = ?reply.status, detail = %reply.detail, "拒绝了一个建流请求");
                return request.refuse(&reply).await;
            }
        };
        // 连目标的这段时间里 netmap 可能已经变了：放行时看的那一版之后的每一次变化都要核对。
        let revoked = async move { withdrawn(&mut netmap_changes, peer, key, grant).await };
        match admitted {
            Admitted::Target { stream, exit_traffic } => {
                let flow = match request.accept().await {
                    Ok(flow) => flow,
                    Err(error) => return tracing::info!(%peer, ?class, kind, ?error, "目标已经连上，但发起方放弃了这条流"),
                };
                let summary = if exit_traffic {
                    flow.relay_metered(stream, revoked, &ExitMeter { limits: &self.limits }).await
                } else {
                    flow.relay(stream, revoked).await
                };
                self.counters.finished(&summary);
                let route = route.ended(&*self.routes);
                let netmap = Arc::clone(&self.netmap.borrow());
                tracing::info!(
                    %peer,
                    ?class,
                    kind,
                    to_target = summary.from_flow.bytes,
                    from_target = summary.from_tcp.bytes,
                    first_byte_ms = summary.from_tcp.first_byte.map(|elapsed| elapsed.as_millis()),
                    end = ?summary.end,
                    route_start = %route.start_label(&netmap),
                    route_end = %route.end_label(&netmap),
                    route_changed = route.changed,
                    "流结束"
                );
            }
            Admitted::Onward(onward) => {
                let flow = match request.accept().await {
                    Ok(flow) => flow,
                    Err(error) => {
                        onward.abort(Reason::Cancelled);
                        return tracing::info!(%peer, ?class, ?error, "到端口转发的目标节点的流已经开好，但发起方放弃了这条流");
                    }
                };
                let spliced = flow.splice(onward, revoked).await;
                self.counters.spliced(spliced.near_to_far, spliced.far_to_near, matches!(spliced.end, End::Clean));
                let route = route.ended(&*self.routes);
                let netmap = Arc::clone(&self.netmap.borrow());
                tracing::info!(
                    %peer,
                    ?class,
                    to_target = spliced.near_to_far,
                    from_target = spliced.far_to_near,
                    end = ?spliced.end,
                    route_start = %route.start_label(&netmap),
                    route_end = %route.end_label(&netmap),
                    route_changed = route.changed,
                    "接力到端口转发目标节点的流结束"
                );
            }
        }
    }

    async fn handle_datagrams<Snd: SendStream, Rcv: RecvStream, T: DatagramSender>(&self, request: datagram::Request<Snd, Rcv, T>) {
        let _active = self.counters.begin();
        let peer = request.peer();
        let (class, origin) = (request.open().class, request.open().origin.clone());
        // 先记下"已经看过"的版本再判断，之后的变化才不会漏掉。
        let mut netmap_changes = self.netmap.clone();
        let allowed = netmap_changes.borrow_and_update().peer(peer).is_some_and(|initiator| initiator.inbound);
        self.limits.configure(netmap_changes.borrow().me.exit.as_ref());

        // 名额和端口占到上下文结束。
        let admitted = if !allowed {
            Err(Reply::new(Status::AccessDenied, "访问规则不允许发起节点访问这个节点"))
        } else if let Some(reply) = self.drain_refusal() {
            Err(reply)
        } else {
            match self.contexts.acquire(peer) {
                Some(slot) => OutboundSocket::bind()
                    .map(|socket| (slot, socket))
                    .map_err(|error| Reply::new(Status::InternalError, format!("绑不出 UDP 端口：{error}"))),
                None => Err(Reply::new(Status::PolicyDenied, format!("发起节点开着的数据报上下文到了上限（{MAX_CONTEXTS_PER_PEER} 个）"))),
            }
        };
        let (_slot, socket) = match admitted {
            Ok(admitted) => admitted,
            Err(reply) => {
                self.counters.failed(reply.status);
                tracing::info!(%peer, ?class, status = ?reply.status, detail = %reply.detail, "拒绝了一个数据报上下文");
                return request.refuse(&reply).await;
            }
        };
        let context = match request.accept().await {
            Ok(context) => context,
            Err(error) => return tracing::info!(%peer, ?class, ?error, "数据报上下文没有建成"),
        };
        tracing::debug!(%peer, ?class, "数据报上下文建立");

        let session = Session {
            outbound: &self.outbound,
            netmap: netmap_changes,
            counters: &self.counters,
            limits: &self.limits,
            opener: self.opener.as_deref(),
            peer,
            class,
            origin,
            socket,
            idle_timeout: self.datagram_idle_timeout,
        };
        let (end, tally) = session.run(context).await;
        if end.is_abnormal() {
            self.counters.aborted();
        }
        tracing::info!(
            %peer,
            ?class,
            to_target = tally.to_target,
            from_target = tally.from_target,
            refused = tally.refused,
            ?end,
            "数据报上下文结束"
        );
    }
}

/// 等到 `peer` 换了公钥，或者 netmap 不再允许它凭 `grant` 放行的这条流。
async fn withdrawn(netmap: &mut watch::Receiver<Arc<Netmap>>, peer: NodeId, key: PublicKey, grant: Grant) -> Reason {
    loop {
        if netmap.changed().await.is_err() {
            // 发送端没了说明节点在关闭，不是权限变了。流留给连接的关闭去结束。
            return future::pending().await;
        }
        let current = Arc::clone(&netmap.borrow_and_update());
        if let Some(why) = grant.withdrawn(&current, peer, ForwardProtocol::Tcp, Some(key)) {
            tracing::info!(%peer, ?grant, why, "重置一条已经建立的流：它不再被允许");
            return Reason::AccessRevoked;
        }
    }
}

/// 端口转发的目标给的失败状态是哪一种原因。
fn forward_cause(status: Status) -> TargetCause {
    TargetCause::of(status).unwrap_or(TargetCause::Other)
}

/// 别的节点访问本节点的 `port` 端口时，接住它的那条端口转发：监听在本节点的虚拟 IP 上，或者监听在全部地址上
/// （`0.0.0.0`、`[::]`）的。经虚拟网卡来的连接连到的是入口在操作系统里的监听；经流来的在这里接住，
/// 发起节点是谁看连接的握手，来源白名单按它的虚拟 IP 查。
///
/// 监听在全部地址上的也要在这里接：把它当成本机的服务从本机去连的话，那个监听看到的来源是本机自己的地址，
/// 只让局域网里的机器用的白名单就拦不住别的节点了。监听在别的某一个地址上的转发不是给组网里的节点用的，不在这里
/// （出口也不去连它，见 [`Outbound::with_own_listeners`]）。
///
/// 端口写 0 的转发实际监听在哪个端口从 `listeners` 里找。两种都有时用虚拟 IP 上的那一条。
pub(crate) fn forward_at_node_port<'n>(
    netmap: &'n Netmap,
    port: u16,
    protocol: ForwardProtocol,
    listeners: &[OwnListener],
) -> Option<&'n Forward> {
    let at_port = |forward: &Forward| match forward.bind.port() {
        0 => listeners
            .iter()
            .any(|listener| listener.forward == Some(forward.id) && listener.protocol == protocol && listener.local.port() == port),
        written => written == port,
    };
    let candidates = || netmap.me.forwards.iter().filter(|forward| forward.protocol == protocol && at_port(forward));
    let own = IpAddr::V4(netmap.me.virtual_ip);
    candidates()
        .find(|forward| forward.bind.ip().to_canonical() == own)
        .or_else(|| candidates().find(|forward| forward.bind.ip().is_unspecified()))
}

/// `bind` 上的监听是不是对组网里的节点开着的：本节点的虚拟 IP，或者全部地址（见 [`forward_at_node_port`]）。
pub(crate) fn faces_the_mesh(netmap: &Netmap, bind: SocketAddr) -> bool {
    bind.ip().is_unspecified() || bind.ip().to_canonical() == IpAddr::V4(netmap.me.virtual_ip)
}

/// 对组网里的节点开着的端口转发的来源白名单，按发起节点的虚拟 IP 查。
pub(crate) fn check_allow_list(initiator: &Peer, forward: &Forward) -> Result<(), Reply> {
    let from = IpAddr::V4(initiator.virtual_ip);
    if forward.allow_from.is_empty() || forward.allow_from.iter().any(|net| net.contains(&from)) {
        Ok(())
    } else {
        Err(Reply::new(Status::PolicyDenied, "发起节点不在这条端口转发的来源白名单里"))
    }
}

/// 对组网里的节点开着、目标是本节点自己的端口转发的目标一侧：最后要连的地址，和要不要发 PROXY protocol 的头。
///
/// 目标是别的节点的不走这里，由出口接力（[`Exit`] 的文档）。
pub(crate) fn virtual_forward_target(netmap: &Netmap, initiator: &Peer, forward: &Forward) -> Result<ForwardTarget, Reply> {
    check_allow_list(initiator, forward)?;
    if forward.target != netmap.me.id {
        return Err(Reply::new(Status::UnknownForward, "这条端口转发的目标是别的节点"));
    }
    netmap
        .me
        .forward_targets
        .iter()
        .find(|entry| entry.id == forward.id && entry.listener == netmap.me.id && entry.protocol == forward.protocol)
        .copied()
        .ok_or_else(|| Reply::new(Status::UnknownForward, "这条端口转发的目标地址没有下发给这个节点"))
}

/// 端口转发要求的话，先给刚连上的目标发 PROXY protocol 的头（[`i3t_access::proxy_header`]）。
///
/// 头里的来源是 `initiator` 的虚拟 IP：它来自连接的握手认出的发起节点在 netmap 里的条目，建流请求里写的什么都不算。
async fn present(mut stream: TcpStream, entry: &ForwardTarget, initiator: &Peer) -> Result<TcpStream, Reply> {
    let Some(version) = entry.proxy_protocol else { return Ok(stream) };
    let written = async {
        let (local, peer) = (stream.local_addr()?, stream.peer_addr()?);
        let header = proxy_header::encode(version, SocketAddr::new(initiator.virtual_ip.into(), local.port()), peer);
        stream.write_all(&header).await
    };
    match written.await {
        Ok(()) => {
            tracing::debug!(forward = entry.id, ?version, initiator = %initiator.virtual_ip, "给端口转发的目标发了 PROXY protocol 的头");
            Ok(stream)
        }
        Err(error) => Err(Reply::new(Status::ConnectionRefused, format!("目标在收到 PROXY protocol 的头之前断开了：{error}"))),
    }
}
