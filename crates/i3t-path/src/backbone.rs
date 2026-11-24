//! relay 和 relay 之间走 TCP 的骨干连接。
//!
//! 骨干上的一条连接是两个会话：本节点在对方 relay 上的，对方在本节点 relay 上的。UDP 通的时候两个会话各走各的 UDP，和以前一样。
//! 当两个 relay 之间的 UDP 存在单向不通时，双方会话复用**同一条** TCP 连接：一方主动拨号（路径层到 relay 的 TCP，[`crate::tcp`]）
//! 并按常规建立自身会话；另一方的 relay 接受连接并识别出拨号方为 netmap 中的 relay 后通知本地路径层（[`BackboneInbox`]），
//! 路径层随即可在同一条 TCP 上反向建立会话。因此一对 relay 间至多维持一条 TCP 连接，即使无法被直连的一方主动拨出亦可互通。
//!
//! 拨号方选择、切换至 TCP 及回切至 UDP 的规则见 [`crate::relays`] 中 `RelayLink` 的骨干逻辑。回切 UDP 需要双方双向可达证据
//! 在接收方汇合：对端经 UDP 发来的 AUTH 证明其 UDP 可达本节点，本节点近期经 UDP 收到其响应证明反向亦可达。
//! 路径层把走着 TCP 的那几段和这样的证据记在 [`Gates`] 里，relay 验过一个经 UDP 来的 AUTH 之后问它（[`BackboneInbox::admits_udp`]）。
//!
//! 帧在两头怎么分：
//!
//! | 收到的 | 拨号的一头（路径层读这条 TCP） | 接进来的一头（relay 读这条 TCP） |
//! |---|---|---|
//! | 会话的请求（INIT、AUTH、PING） | 交给本节点的 relay（[`crate::LocalRelay::handle_leg_frame`]） | relay 自己处理 |
//! | 会话的应答、错误帧、矩阵行 | 路径层自己处理 | 交给路径层（这里） |
//! | 发给本节点的包 | 交给连接层 | relay 交给连接层 |
//! | 要往下转的包 | 交给本节点的 relay | relay 自己转 |

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use i3t_proto::session::{Frame, Refused};
use i3t_proto::{Datagram, NodeId};
use i3t_underlay::tcp_leg::FrameSender;
use tokio::sync::mpsc;

use crate::control::Ctrl;
use crate::tcp::TcpEvent;

/// 本节点的 relay 把别的 relay 拨进来的 TCP 上属于路径层的事交到这里（见模块文档），也在这里问骨干走着 TCP 的那几段的情况。
///
/// 由 [`crate::Paths::backbone_inbox`] 给出，装配的一方交给本节点的 relay。它只拿着控制任务的队列和 [`Gates`]，
/// 不让 relay 和路径层互相拿着对方不放。队列满了的时候丢掉：交过来的都是有重试的握手、保活和矩阵行。
#[derive(Debug, Clone)]
pub struct BackboneInbox {
    pub(crate) ctrl: mpsc::Sender<Ctrl>,
    pub(crate) gates: Arc<Gates>,
}

/// relay 接进来的一条骨干 TCP 上发生的事。
#[derive(Debug)]
pub(crate) enum Accepted {
    /// 那个 relay 在这条 TCP 上和本节点的 relay 建好了会话：路径层可以在同一条 TCP 上反过来建自己的会话。
    Opened {
        addr: SocketAddr,
        sender: FrameSender,
    },
    Event(TcpEvent),
    Closed,
}

impl BackboneInbox {
    /// relay `relay` 在本节点的 relay 接进来的第 `conn` 条 TCP 上建好了会话。`sender` 往这条 TCP 里写，`addr` 是它的对端地址。
    pub fn opened(&self, relay: NodeId, conn: u64, addr: SocketAddr, sender: FrameSender) {
        self.send(relay, Ctrl::Accepted { relay, conn, event: Accepted::Opened { addr, sender } });
    }

    /// 这条 TCP 上来了一帧会话的应答、错误帧或者矩阵行（是不是这几种由这里看）。返回它是不是归路径层的。
    pub fn frame(&self, relay: NodeId, conn: u64, frame: Bytes) -> bool {
        let event = match Datagram::parse(&frame) {
            Ok(Datagram::Session(session)) if !session.is_request() => match (session, Refused::echo(&frame)) {
                (Frame::Error(refused), Some(echo)) => TcpEvent::Refusal(refused, echo),
                (session, _) => TcpEvent::Frame(session),
            },
            Ok(Datagram::Row(_)) => TcpEvent::Row(frame),
            _ => return false,
        };
        self.send(relay, Ctrl::Accepted { relay, conn, event: Accepted::Event(event) });
        true
    }

    /// 这条 TCP 断了。
    pub fn closed(&self, relay: NodeId, conn: u64) {
        self.send(relay, Ctrl::Accepted { relay, conn, event: Accepted::Closed });
    }

    /// relay `relay` 经 UDP 发来的 AUTH（cookie、限速、签名都已经核对过）能不能把它在本节点的 relay 上的会话搬到 UDP 上。
    ///
    /// 当对应骨干链路使用 TCP 时，仅在本节点近期经 UDP 收到过对端响应（响应本节点 INIT）或本节点至对端的 UDP 会话已就绪时才允许迁移：
    /// 若仅一端会话迁回 UDP 而另一端仍在 TCP，该段将无法转发任何流量；若仅单向 UDP 可达，链路会持续中断
    /// （详见 `crate::relays` 的骨干部分）。其余情况均允许迁移。拒绝时 relay 不建立会话、不回应，并调用 [`knocked`](Self::knocked)。
    ///
    /// # Panics
    ///
    /// 路径层的控制任务 panic 过（锁中毒）。
    #[must_use]
    pub fn admits_udp(&self, relay: NodeId, now: Instant) -> bool {
        self.gates.admits(relay, now)
    }

    /// 来自 `relay` 的 UDP AUTH 被 [`admits_udp`](Self::admits_udp) 拦截，说明对端 UDP 可达本节点。
    /// 路径层将立即主动发起一次 UDP 探测（受最小间隔限制）；若本节点 UDP 也可达对端，其下一次 AUTH 即可顺利迁移。
    pub fn knocked(&self, relay: NodeId) {
        self.send(relay, Ctrl::Knock { relay });
    }

    fn send(&self, relay: NodeId, message: Ctrl) {
        if self.ctrl.try_send(message).is_err() {
            tracing::debug!(%relay, "骨干事件入队失败，已丢弃");
        }
    }
}

/// 骨干上走着 TCP 的一段，本节点的 relay 让不让对方经 UDP 把会话搬过来（见 [`BackboneInbox::admits_udp`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// 近期已确认本节点 UDP 可达对端，在该时刻之前允许迁移。
    OpenUntil(Instant),
    /// 尚未确认本节点 UDP 可达对端，暂不允许迁移。
    Closed,
}

impl Gate {
    pub(crate) fn admits(self, now: Instant) -> bool {
        match self {
            Self::OpenUntil(until) => now < until,
            Self::Closed => false,
        }
    }
}

/// 骨干上走着 TCP 的那几段和它们的 [`Gate`]，按对方 relay 的编号。不在里面的都让，和以前一样。
///
/// 控制任务在每一轮和每次处理 relay 的应答之后写（只在变了的时候），本节点的 relay 验过一个经 UDP 来的 AUTH 之后读：
/// 两边都只是查一下或者换一张表，锁不跨过任何别的事。
#[derive(Debug, Default)]
pub(crate) struct Gates(Mutex<HashMap<NodeId, Gate>>);

impl Gates {
    fn admits(&self, relay: NodeId, now: Instant) -> bool {
        self.0.lock().expect("backbone gates mutex poisoned").get(&relay).is_none_or(|gate| gate.admits(now))
    }

    pub(crate) fn set(&self, gates: HashMap<NodeId, Gate>) {
        *self.0.lock().expect("backbone gates mutex poisoned") = gates;
    }
}
