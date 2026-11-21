//! 一个数据报上下文在出口这一侧的一生。
//!
//! 一个上下文就是出口上的一个 UDP 端口。发起节点发来的每个数据报带着它要去的目标，都从这个端口发出去，
//! 所以不同的目标看到的来源端口是同一个（与目的地址无关的映射）；目标发回来的报文带着来源送回发起节点。
//!
//! 每个目标第一次出现时按和流一样的规则检查一遍（出口有没有启用、端口、解析之后的地址、局域网开关、端口转发有没有下发），
//! 结果记一分钟：通过的直接发，没通过的直接丢。netmap 一变，记着的结果全部作废；
//! 放行它们的能力被收回了的（出口、局域网开关、端口转发，见 `grant` 模块）当场作废，从它们回来的报文也不再收。
//! 检查是在上下文自己的任务里做的：目标是一个还没解析过的域名时，这个上下文后面的报文要等它解析完，
//! 等的时候排在上下文的队列里，队列满了丢新来的。别的上下文不受影响。
//!
//! 回来的报文只收"往它发过报文的地址"发来的：别的地址发到这个端口上的东西和发起节点没有关系，不替它们转。
//!
//! 上下文没有报文往来超过 [`IDLE_TIMEOUT`] 就回收，发起方下次要用时再开。
//!
//! 监听在本节点虚拟 IP 上、目标是别的节点的 UDP 端口转发要接力：目标第一次出现时，本节点到转发的目标节点开一个自己的
//! 数据报上下文（访问规则两段都要允许），之后发往这个端口的报文都从那个上下文转过去，回来的报文报成从这个端口来的。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use i3t_conn::contract::{DatagramSender, Datagrams};
use i3t_conn::{Connector, RecvStream, SendStream};
use i3t_flow::datagram::{Context, ContextEnd, ContextSender, Opener, OutboundSocket, Received};
use i3t_model::Netmap;
use i3t_model::netmap::ForwardProtocol;
use i3t_proto::NodeId;
use i3t_proto::flow::{Class, Host, Origin, Reason, Reply, Status, Target};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time;

use crate::grant::Grant;
use crate::handler::{check_allow_list, forward_on_virtual_ip, virtual_forward_target};
use crate::limits::Limits;
use crate::outbound::{Asker, Outbound};
use crate::stats::Counters;
use crate::system::System;

/// 上下文没有报文往来多久之后回收。
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 一个对端同时能开多少个上下文。每个上下文占一个 UDP 端口（一个文件描述符）、一块接收缓冲和一个队列，
/// 所以要有上限：对端再怎么开，占掉的也就是这么多。
///
/// 对端的入口按"每个客户端地址一个上下文"开 UDP 端口转发的会话，一条对外开放的转发最多开
/// `i3t_access` 里每条转发的会话上限（64）这么多。这里取它的两倍：一条转发被人占满时，
/// 那个节点经本节点的别的 UDP（SOCKS5 的 UDP 关联、别的转发）还有一半的名额，不会跟着用不了。
pub(crate) const MAX_CONTEXTS_PER_PEER: usize = 128;

/// 一个上下文最多记多少个目标的检查结果。满了就全部清掉重新记，和域名解析的缓存一个做法。
const MAX_DESTINATIONS: usize = 256;

/// 一个目标的检查结果用多久。域名隔这么久重新解析一次，被拒绝的目标隔这么久再检查一次。
const VERDICT_TTL: Duration = Duration::from_secs(60);

/// 一个 UDP 报文最长这么多，收的缓冲区按它开。
const MAX_UDP_PAYLOAD: usize = 65_535;

/// 接力的上下文送回来、等着交给发起节点的报文最多排这么多个。
const ONWARD_BACKLOG: usize = 64;

/// 每个对端开着多少个上下文。
#[derive(Debug, Default)]
pub(crate) struct ContextLimit {
    open: Mutex<HashMap<NodeId, usize>>,
}

impl ContextLimit {
    /// 给 `peer` 再记一个上下文。它已经到了上限时返回 `None`。返回的守卫被丢弃时这一个不再算数。
    pub(crate) fn acquire(&self, peer: NodeId) -> Option<ContextSlot<'_>> {
        let mut open = self.open.lock().expect("context limit mutex poisoned");
        let count = open.entry(peer).or_insert(0);
        if *count >= MAX_CONTEXTS_PER_PEER {
            return None;
        }
        *count += 1;
        Some(ContextSlot { limit: self, peer })
    }
}

/// 一个开着的上下文占着的名额。
#[derive(Debug)]
pub(crate) struct ContextSlot<'a> {
    limit: &'a ContextLimit,
    peer: NodeId,
}

impl Drop for ContextSlot<'_> {
    fn drop(&mut self) {
        let mut open = self.limit.open.lock().expect("context limit mutex poisoned");
        if let Some(count) = open.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.peer);
            }
        }
    }
}

/// 一个目标检查之后的结论。
#[derive(Debug, Clone, Copy)]
enum Outcome {
    /// 可以发，报文实际发到 `real`。`exit_traffic` 为真时这是出口流量（互联网或局域网目标），要记配额。
    Allowed {
        real: SocketAddr,
        exit_traffic: bool,
        grant: Grant,
    },
    /// 监听在本节点虚拟 IP 上、目标是 `node` 的 UDP 端口转发：经本节点到 `node` 的上下文接力。
    Onward {
        forward: u32,
        node: NodeId,
        grant: Grant,
    },
    Refused,
}

impl Outcome {
    /// 放行凭的是什么；没有放行时是 `None`。
    const fn grant(&self) -> Option<&Grant> {
        match self {
            Self::Allowed { grant, .. } | Self::Onward { grant, .. } => Some(grant),
            Self::Refused => None,
        }
    }
}

/// 往它发过报文的一个地址：从它回来的报文报成什么来源，那是不是出口流量，以及当初凭什么放行的。
#[derive(Debug, Clone)]
struct Source {
    target: Target,
    exit_traffic: bool,
    grant: Grant,
}

#[derive(Debug)]
struct Verdict {
    outcome: Outcome,
    expires: Instant,
}

/// 一个上下文记着的目标：检查的结论，以及哪些地址发回来的报文可以收。
#[derive(Debug, Default)]
struct Destinations {
    /// 这些结论是按哪一版 netmap 得出的。
    netmap_version: u64,
    verdicts: HashMap<Target, Verdict>,
    /// 往它发过报文的地址，以及从它回来的报文报成什么来源。
    sources: HashMap<SocketAddr, Source>,
}

impl Destinations {
    /// netmap 换了一版：出口的能力、端口、访问关系都可能变了，之前的结论全部作废。
    fn follow(&mut self, netmap: &Netmap) {
        if self.netmap_version != netmap.version {
            self.netmap_version = netmap.version;
            self.verdicts.clear();
            self.sources.clear();
        }
    }

    fn verdict(&self, target: &Target, now: Instant) -> Option<Outcome> {
        self.verdicts.get(target).filter(|verdict| verdict.expires > now).map(|verdict| verdict.outcome)
    }

    fn remember(&mut self, target: Target, outcome: Outcome, now: Instant) {
        if self.verdicts.len() >= MAX_DESTINATIONS && !self.verdicts.contains_key(&target) {
            self.verdicts.clear();
            self.sources.clear();
        }
        self.verdicts.insert(target, Verdict { outcome, expires: now + VERDICT_TTL });
    }

    /// 按新的 netmap 去掉放行凭据已经不成立的结论和来源：发往它们的报文下次重新检查（会被拒绝），
    /// 从它们回来的报文不再送回发起节点。返回去掉了几项。
    fn withdraw(&mut self, netmap: &Netmap, peer: NodeId) -> usize {
        let holds = |grant: &Grant| grant.withdrawn(netmap, peer, ForwardProtocol::Udp, None).is_none();
        let before = self.verdicts.len() + self.sources.len();
        self.verdicts.retain(|_, verdict| verdict.outcome.grant().is_none_or(holds));
        self.sources.retain(|_, source| holds(&source.grant));
        before - self.verdicts.len() - self.sources.len()
    }
}

/// 一个上下文里来往了多少报文。
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Tally {
    pub to_target: u64,
    pub from_target: u64,
    /// 没有通过检查、被丢掉的。
    pub refused: u64,
}

/// 一个上下文是怎么结束的。
#[derive(Debug)]
pub(crate) enum Ended {
    /// 没有报文往来超过了时限，出口这一侧回收了它。
    Idle,
    /// 发起方结束了它，或者连接断了。
    Peer(ContextEnd),
    /// 访问规则不再允许发起节点访问本节点。
    Revoked,
}

/// 一个开着的上下文。
pub(crate) struct Session<'a, S, C: Datagrams> {
    pub outbound: &'a Outbound<S>,
    pub netmap: watch::Receiver<Arc<Netmap>>,
    pub counters: &'a Counters,
    pub limits: &'a Limits,
    /// 接力 UDP 端口转发时到目标节点开上下文用的；没有时这种转发上的报文被拒绝。
    pub opener: Option<&'a Opener<C>>,
    pub peer: NodeId,
    /// 发起方的上下文的等级和来源说明，接力时原样带过去。
    pub class: Class,
    pub origin: Origin,
    pub socket: OutboundSocket,
    pub idle_timeout: Duration,
}

/// 到一个端口转发的目标节点的接力上下文。它的任务把回来的报文放进会话的队列；丢掉它，任务就正常关掉上下文
/// （目标节点看到的是正常结束，不算异常）。
struct OnwardLeg<T> {
    /// 回来的报文报成从哪里来：开它时发起节点发往的那个虚拟 IP 上的端口。
    source: Target,
    /// 当初凭哪条端口转发放行的。它不成立了，这个接力上下文就关掉。
    grant: Grant,
    sender: ContextSender<T>,
    task: JoinHandle<()>,
    /// 丢掉它就是叫任务关掉上下文。
    _stop: oneshot::Sender<()>,
}

/// 接力回来的一个报文：报成从哪里来（发起节点当初发往的那个虚拟 IP 上的端口），和内容。
type Returned = (Target, Bytes);

impl<S: System, C: Connector + Datagrams> Session<'_, S, C> {
    /// 在上下文和它的 UDP 端口之间搬运报文，直到上下文结束。返回时上下文和端口都已经关掉。
    pub(crate) async fn run<Snd: SendStream, Rcv: RecvStream, T: DatagramSender>(
        self,
        mut context: Context<Snd, Rcv, T>,
    ) -> (Ended, Tally) {
        let mut revocations = self.netmap.clone();
        let sender = context.sender();
        let mut destinations = Destinations::default();
        let mut tally = Tally::default();
        let mut buf = vec![0; MAX_UDP_PAYLOAD];
        let mut legs: HashMap<u32, OnwardLeg<C::Sender>> = HashMap::new();
        let (returns, mut returned) = mpsc::channel::<Returned>(ONWARD_BACKLOG);
        let idle = time::sleep(self.idle_timeout);
        tokio::pin!(idle);
        let mut following = true;
        loop {
            let forwarded = tokio::select! {
                biased;
                changed = revocations.changed(), if following => {
                    match changed {
                        // 发送端没了说明节点在关闭，不是权限变了。上下文留给连接的关闭去结束。
                        Err(_) => following = false,
                        Ok(()) => {
                            let netmap = Arc::clone(&revocations.borrow_and_update());
                            if !netmap.peer(self.peer).is_some_and(|initiator| initiator.inbound) {
                                tracing::info!(peer = %self.peer, "访问规则不再允许这个节点访问本节点，重置它的数据报上下文");
                                context.abort(Reason::AccessRevoked);
                                return (Ended::Revoked, tally);
                            }
                            self.withdraw(&netmap, &mut destinations, &mut legs);
                        }
                    }
                    false
                }
                received = context.recv() => match received {
                    Ok(datagram) => self.send_to_target(&datagram, &mut destinations, &mut tally, Onward { legs: &mut legs, returns: &returns }).await,
                    Err(end) => return (Ended::Peer(end), tally),
                },
                Some((source, payload)) = returned.recv() => match sender.send(&source, &payload).await {
                    Ok(()) => {
                        tally.from_target += 1;
                        self.counters.datagram_from_target(payload.len());
                        true
                    }
                    Err(error) => {
                        tracing::debug!(peer = %self.peer, %error, "接力回来的一个报文没有送回发起节点");
                        false
                    }
                },
                received = self.socket.recv_from(&mut buf) => match received {
                    Ok((len, from)) => self.return_from_target(from, &buf[..len], &sender, &destinations, &mut tally).await,
                    Err(error) => {
                        // 有的系统把上一次发送引起的"端口不可达"报在这里。它不影响这个端口继续用。
                        tracing::debug!(peer = %self.peer, %error, "数据报上下文的 UDP 端口收报文时出错");
                        false
                    }
                },
                () = &mut idle => {
                    context.close().await;
                    return (Ended::Idle, tally);
                }
            };
            // 只有真的搬过去了的报文才算往来：一直被拒绝的上下文照样到时回收。
            if forwarded {
                idle.as_mut().reset(time::Instant::now() + self.idle_timeout);
            }
        }
    }

    /// netmap 变了：放行凭据不再成立的目标当场作废，接力到端口转发目标节点的上下文跟着关掉。
    fn withdraw(&self, netmap: &Netmap, destinations: &mut Destinations, legs: &mut HashMap<u32, OnwardLeg<C::Sender>>) {
        let legs_before = legs.len();
        legs.retain(|_, leg| leg.grant.withdrawn(netmap, self.peer, ForwardProtocol::Udp, None).is_none());
        let removed = destinations.withdraw(netmap, self.peer) + (legs_before - legs.len());
        if removed > 0 {
            tracing::info!(peer = %self.peer, removed, "放行数据报目标的能力被收回了：这些目标两个方向的报文都不再转发");
        }
    }

    /// 把发起节点发来的一个报文发往它的目标。返回有没有发出去。
    async fn send_to_target(&self, datagram: &Received, destinations: &mut Destinations, tally: &mut Tally, onward: Onward<'_, C>) -> bool {
        let netmap = Arc::clone(&self.netmap.borrow());
        destinations.follow(&netmap);
        let now = Instant::now();
        let outcome = match destinations.verdict(&datagram.target, now) {
            Some(outcome) => outcome,
            None => {
                let outcome = match self.check(&netmap, &datagram.target).await {
                    Ok(Checked::Address(Destination { addr, source, exit_traffic, grant })) => {
                        let real = self.outbound.udp_route(addr);
                        destinations.sources.insert(real, Source { target: source, exit_traffic, grant });
                        Outcome::Allowed { real, exit_traffic, grant }
                    }
                    Ok(Checked::Onward { forward, node, grant }) => Outcome::Onward { forward, node, grant },
                    Err(reply) => {
                        self.counters.failed(reply.status);
                        tracing::info!(
                            peer = %self.peer,
                            kind = datagram.target.kind(),
                            status = ?reply.status,
                            detail = %reply.detail,
                            "拒绝了发往一个目标的数据报；{VERDICT_TTL:?} 之内发往它的都直接丢掉"
                        );
                        Outcome::Refused
                    }
                };
                destinations.remember(datagram.target.clone(), outcome, now);
                outcome
            }
        };
        let (real, exit_traffic) = match outcome {
            Outcome::Allowed { real, exit_traffic, .. } => (real, exit_traffic),
            Outcome::Onward { forward, node, grant } => return self.relay_onward(datagram, (forward, node, grant), tally, onward).await,
            Outcome::Refused => {
                tally.refused += 1;
                self.counters.datagram_refused();
                return false;
            }
        };
        if exit_traffic && !self.limits.admit_datagram(datagram.payload.len()) {
            self.counters.datagram_limited();
            tracing::trace!(peer = %self.peer, "丢掉一个发往目标的数据报：出口的配额用完了");
            return false;
        }
        match self.socket.send_to(&datagram.payload, real).await {
            Ok(()) => {
                tally.to_target += 1;
                self.counters.datagram_to_target(datagram.payload.len());
                true
            }
            Err(error) => {
                tracing::debug!(peer = %self.peer, kind = datagram.target.kind(), %error, "一个数据报没有发出去");
                false
            }
        }
    }

    /// 把 UDP 端口上收到的一个报文送回发起节点。返回有没有送出去。
    async fn return_from_target<T: DatagramSender>(
        &self,
        from: SocketAddr,
        payload: &[u8],
        sender: &ContextSender<T>,
        destinations: &Destinations,
        tally: &mut Tally,
    ) -> bool {
        let Some(source) = destinations.sources.get(&from) else {
            tracing::trace!(peer = %self.peer, "丢掉 UDP 端口上收到的一个报文：没有往它的来源发过报文");
            return false;
        };
        if source.exit_traffic && !self.limits.admit_datagram(payload.len()) {
            self.counters.datagram_limited();
            tracing::trace!(peer = %self.peer, "丢掉目标发回来的一个数据报：出口的配额用完了");
            return false;
        }
        match sender.send(&source.target, payload).await {
            Ok(()) => {
                tally.from_target += 1;
                self.counters.datagram_from_target(payload.len());
                true
            }
            Err(error) => {
                tracing::debug!(peer = %self.peer, %error, "目标发回来的一个报文没有送回发起节点");
                false
            }
        }
    }

    /// 经接力上下文把报文转给端口转发的目标节点。上下文还没有（或者已经结束了）就新开一个；开不成时这个报文丢掉。
    async fn relay_onward(&self, datagram: &Received, via: (u32, NodeId, Grant), tally: &mut Tally, onward: Onward<'_, C>) -> bool {
        let Onward { legs, returns } = onward;
        let (forward, node, grant) = via;
        // 转发改了监听的端口（编号没变）时，回来的报文要报新的来源，所以也重开。
        if legs.get(&forward).is_none_or(|leg| leg.task.is_finished() || leg.source != datagram.target || leg.grant != grant) {
            let Some(opener) = self.opener else { return false };
            // 开上下文要等目标节点答应；这期间这个会话后面的报文排在它自己的队列里。
            let mut context = match opener.open(node, self.class, self.origin.clone()).await {
                Ok(context) => context,
                Err(error) => {
                    tracing::info!(peer = %self.peer, %node, forward, ?error, "到端口转发的目标节点开数据报上下文失败，这个报文丢掉");
                    legs.remove(&forward);
                    return false;
                }
            };
            tracing::debug!(peer = %self.peer, %node, forward, "接力 UDP 端口转发的上下文建立");
            let (source, returns) = (datagram.target.clone(), returns.clone());
            let sender = context.sender();
            let (stop, mut stopped) = oneshot::channel::<()>();
            let task = tokio::spawn({
                let source = source.clone();
                async move {
                    loop {
                        tokio::select! {
                            received = context.recv() => match received {
                                Ok(received) => {
                                    if returns.send((source.clone(), received.payload)).await.is_err() {
                                        return context.close().await;
                                    }
                                }
                                Err(_) => return,
                            },
                            _ = &mut stopped => return context.close().await,
                        }
                    }
                }
            });
            legs.insert(forward, OnwardLeg { source, grant, sender, task, _stop: stop });
        }
        let Some(leg) = legs.get(&forward) else { return false };
        match leg.sender.send(&Target::Forward { id: forward }, &datagram.payload).await {
            Ok(()) => {
                tally.to_target += 1;
                self.counters.datagram_to_target(datagram.payload.len());
                true
            }
            Err(error) => {
                tracing::debug!(peer = %self.peer, %node, forward, %error, "一个报文没有转给端口转发的目标节点，下一个报文重新开上下文");
                legs.remove(&forward);
                false
            }
        }
    }

    /// 检查一个目标。访问规则、本节点的能力和出站策略都和流的一样。
    async fn check(&self, netmap: &Netmap, target: &Target) -> Result<Checked, Reply> {
        let Some(initiator) = netmap.peer(self.peer).filter(|initiator| initiator.inbound) else {
            return Err(Reply::new(Status::AccessDenied, "访问规则不允许发起节点访问这个节点"));
        };
        let (addr, grant) = match target {
            Target::Internet { host, port } => {
                let addr = self.outbound.udp_internet(netmap, host, *port, Asker::Peer(self.peer)).await?;
                // 目标写的是域名时，回来的报文报的是解析出来的地址。
                let source = Target::Internet { host: Host::Ip(addr.ip()), port: addr.port() };
                return Ok(Checked::Address(Destination { addr, source, exit_traffic: true, grant: Grant::Internet { port: *port } }));
            }
            Target::Lan { addr } => {
                let addr = self.outbound.lan_target(netmap, *addr)?;
                return Ok(Checked::Address(Destination { addr, source: target.clone(), exit_traffic: true, grant: Grant::Lan }));
            }
            Target::Node { port } => match forward_on_virtual_ip(netmap, *port, ForwardProtocol::Udp) {
                Some(forward) if forward.target != netmap.me.id => {
                    // 访问规则两段：发起节点能访问本节点（上面查过），本节点能访问目标节点。目标节点还会按编号再查一遍。
                    check_allow_list(initiator, forward)?;
                    if !netmap.peer(forward.target).is_some_and(|target| target.outbound) {
                        return Err(Reply::new(
                            Status::UnknownForward,
                            "这条端口转发的目标节点不在本节点的 netmap 里，或者访问规则不允许本节点访问它",
                        ));
                    }
                    let grant = Grant::VirtualForward { port: *port, id: forward.id, target: forward.target, addr: None };
                    return Ok(Checked::Onward { forward: forward.id, node: forward.target, grant });
                }
                Some(forward) => {
                    let addr = virtual_forward_target(netmap, initiator, forward)?.addr;
                    self.outbound.not_overlay(addr)?;
                    (addr, Grant::VirtualForward { port: *port, id: forward.id, target: forward.target, addr: Some(addr) })
                }
                None => (self.outbound.udp_node(*port)?, Grant::NodeService),
            },
            Target::Forward { id } => {
                let listed = netmap
                    .me
                    .forward_targets
                    .iter()
                    .find(|entry| entry.id == *id && entry.listener == self.peer && entry.protocol == ForwardProtocol::Udp);
                match listed {
                    Some(entry) => {
                        self.outbound.not_overlay(entry.addr)?;
                        (entry.addr, Grant::Forward { id: *id, addr: entry.addr })
                    }
                    None => return Err(Reply::new(Status::UnknownForward, "没有下发给这个节点、由发起节点监听的这条 UDP 端口转发")),
                }
            }
        };
        Ok(Checked::Address(Destination { addr, source: target.clone(), exit_traffic: false, grant }))
    }
}

/// 发送时要用到的接力上下文：已经开着的，和回来的报文排的队。
struct Onward<'a, C: Datagrams> {
    legs: &'a mut HashMap<u32, OnwardLeg<C::Sender>>,
    returns: &'a mpsc::Sender<Returned>,
}

/// 一个目标检查之后去哪里。
enum Checked {
    Address(Destination),
    Onward { forward: u32, node: NodeId, grant: Grant },
}

/// 一个通过了检查的目标。
struct Destination {
    /// 报文发往的地址（经过 [`System::udp_route`] 之前的）。
    addr: SocketAddr,
    /// 从它回来的报文带给发起节点的来源。
    source: Target,
    /// 这是出口流量（互联网或局域网目标）。
    exit_traffic: bool,
    grant: Grant,
}

impl Ended {
    /// 发起方结束上下文时带的原因码里，[`Reason::Cancelled`] 之外的才值得当成异常记下来。
    pub(crate) fn is_abnormal(&self) -> bool {
        match self {
            Self::Idle | Self::Peer(ContextEnd::Finished) => false,
            Self::Revoked => true,
            Self::Peer(ContextEnd::Aborted(aborted)) => aborted.code().0 != Reason::Cancelled.to_wire(),
            // `ContextEnd` 以后可能有新的结束方式；不认识的按异常算。
            Self::Peer(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    #[test]
    fn a_peer_may_hold_a_bounded_number_of_contexts_and_gets_slots_back_when_they_end() {
        let limit = ContextLimit::default();
        let mut slots: Vec<_> = (0..MAX_CONTEXTS_PER_PEER).map(|_| limit.acquire(node(1)).expect("还没到上限")).collect();
        assert!(limit.acquire(node(1)).is_none(), "到了上限");
        assert!(limit.acquire(node(2)).is_some(), "别的对端各算各的");

        slots.pop();
        assert!(limit.acquire(node(1)).is_some(), "结束一个就空出一个");
        drop(slots);
        assert!(limit.open.lock().unwrap().is_empty(), "没有上下文的对端不留记录");
    }

    #[test]
    fn verdicts_expire_and_are_forgotten_when_the_netmap_changes_or_the_table_is_full() {
        let target = |port| Target::Node { port };
        let real: SocketAddr = "192.168.77.5:53".parse().unwrap();
        let mut destinations = Destinations::default();
        let now = Instant::now();

        let allowed = Outcome::Allowed { real, exit_traffic: false, grant: Grant::NodeService };
        let source = || Source { target: target(53), exit_traffic: false, grant: Grant::NodeService };
        destinations.remember(target(53), allowed, now);
        destinations.remember(target(54), Outcome::Refused, now);
        destinations.sources.insert(real, source());
        assert!(matches!(destinations.verdict(&target(53), now), Some(Outcome::Allowed { real: addr, .. }) if addr == real));
        assert!(matches!(destinations.verdict(&target(54), now + VERDICT_TTL - Duration::from_millis(1)), Some(Outcome::Refused)));
        assert!(destinations.verdict(&target(54), now + VERDICT_TTL).is_none(), "过了时限要重新检查");
        assert!(destinations.verdict(&target(55), now).is_none());

        // 表满了：全部清掉，只留新来的。
        for port in 100..100 + u16::try_from(MAX_DESTINATIONS).unwrap() {
            destinations.remember(target(port), Outcome::Refused, now);
        }
        assert!(destinations.verdicts.len() <= MAX_DESTINATIONS);
        assert!(destinations.verdict(&target(53), now).is_none() && destinations.sources.is_empty());

        // netmap 换了一版：结论和可以收的来源都作废。
        destinations.remember(target(53), allowed, now);
        destinations.sources.insert(real, source());
        let mut netmap = netmap();
        destinations.follow(&netmap);
        assert!(destinations.verdicts.is_empty() && destinations.sources.is_empty());
        destinations.remember(target(53), allowed, now);
        destinations.follow(&netmap);
        assert_eq!(destinations.verdicts.len(), 1, "同一版 netmap 不清");
        netmap.version += 1;
        destinations.follow(&netmap);
        assert!(destinations.verdicts.is_empty());
    }

    /// 一份最小的 netmap，只用到它的版本号。
    fn netmap() -> Netmap {
        use i3t_model::netmap::{LocalNode, Network};
        Netmap {
            version: 7,
            network: Network {
                name: "home".into(),
                domain: "home.i3t".into(),
                cidr: "10.66.0.0/16".parse().unwrap(),
                routing: Default::default(),
                max_relay_hops: 2,
                reach: Default::default(),
                class: None,
                ack_eliciting_threshold: 3,
                max_ack_delay_ms: 2,
            },
            me: LocalNode {
                id: node(2),
                name: "gw".into(),
                virtual_ip: [10, 66, 0, 2].into(),
                routing: None,
                reach: None,
                dial_out_only: false,
                relay: None,
                exit: None,
                proxies: Vec::new(),
                forwards: Vec::new(),
                forward_targets: Vec::new(),
                pinned_relays: Vec::new(),
                profile: None,
                shared_relays: Vec::new(),
            },
            peers: Vec::new(),
            relays: Vec::new(),
            relay_clients: Vec::new(),
            no_vnet: Vec::new(),
        }
    }
}
