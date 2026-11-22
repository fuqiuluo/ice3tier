//! relay 上的会话表：哪个节点现在挂在哪个地址（或者哪条 TCP）上。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use i3t_proto::session::Nonce;
use i3t_proto::{NodeId, PublicKey};
use i3t_underlay::tcp_leg::FrameSender;

/// 会话多久收不到 PING 就删掉。节点每 5 秒发一次，中间丢几个也够不着这个数。
pub(crate) const SESSION_TTL: Duration = Duration::from_secs(30);

/// 一个数据报是从哪里到 relay 的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    Udp(SocketAddr),
    Tcp(TcpConn),
}

/// 一条 TCP 是哪一条。两种编号各数各的，所以分开：撞了号的话，一条连接上来的帧会被当成另一条上的会话发的。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TcpConn {
    /// relay 接进来的，号是 relay 编的。
    Accepted(u64),
    /// 本节点的路径层拨向另一个 relay 的，号是路径层编的。那个 relay 在这条 TCP 上反过来和本节点建的会话绑在它上面（骨干，见 `crate::relay`）。
    Dialled(u64),
}

/// 会话绑定在什么上面，也就是发给这个节点的包往哪里送。
#[derive(Debug, Clone)]
pub(crate) enum Binding {
    Udp(SocketAddr),
    Tcp { conn: TcpConn, sender: FrameSender },
}

impl Binding {
    fn is(&self, origin: Origin) -> bool {
        match (self, origin) {
            (Self::Udp(bound), Origin::Udp(from)) => *bound == from,
            (Self::Tcp { conn, .. }, Origin::Tcp(from)) => *conn == from,
            (Self::Udp(_), Origin::Tcp(_)) | (Self::Tcp { .. }, Origin::Udp(_)) => false,
        }
    }
}

#[derive(Debug)]
struct Session {
    /// 握手时验过签名的那把公钥。netmap 里这个节点的公钥换了，这个会话就不算数了。
    key: PublicKey,
    binding: Binding,
    /// 节点握手时给的随机数（AUTH 里的那个）。只有 relay 和收得到发往会话地址的包的节点知道它，
    /// 发给会话主人的 ERROR 回显它，节点靠它认出 ERROR 确实是这个 relay 发的。
    nonce: Nonce,
    /// 这个节点的上一个会话是断掉的，这个会话是之后重新建的：它建立的时刻。头一次建立的会话是 `None`。
    reopened: Option<Instant>,
    expires: Instant,
}

/// 会话表。一个节点最多一个会话：新的握手成功就顶掉旧的，所以节点从 TCP 换回 UDP 只要在 UDP 上再握一次手。
#[derive(Debug, Default)]
pub(crate) struct Sessions {
    by_node: HashMap<NodeId, Session>,
    /// 会话断过（TCP 断开，或者过期）的节点。它们下一次建立的会话算"重新建的"。
    broke: HashSet<NodeId>,
}

impl Sessions {
    /// 握手成功：给 `node` 建会话，或者把它已有的会话改绑到新的来源上。`key` 是验过这次握手的签名的公钥，`nonce` 是这次握手里节点给的随机数。
    pub(crate) fn open(&mut self, node: NodeId, key: PublicKey, binding: Binding, nonce: Nonce, now: Instant) {
        let previous = self.by_node.get(&node);
        let reopened = match (previous.filter(|session| session.expires > now), &binding) {
            // 走着 TCP 的节点发现 UDP 通了，在 UDP 上再握一次手：会话没有断，只是换了个地方。
            (Some(Session { binding: Binding::Tcp { .. }, reopened, .. }), Binding::Udp(_)) => *reopened,
            // 别的情况下，节点重新握手是因为它认为原来的会话没了（保活没有回应，或者它重启了）。
            _ if previous.is_some() || self.broke.remove(&node) => Some(now),
            _ => None,
        };
        self.by_node.insert(node, Session { key, binding, nonce, reopened, expires: now + SESSION_TTL });
    }

    /// `node` 现在的会话如果是上一个会话断掉之后重新建的，返回它建立的时刻。
    /// 没有会话，或者这是它头一次建立的会话，返回 `None`。
    pub(crate) fn reopened(&self, node: NodeId, now: Instant) -> Option<Instant> {
        self.live(node, now).and_then(|session| session.reopened)
    }

    /// `node` 有没有会话，并且就是绑定在 `origin` 上的。转发之前靠它核对来源：
    /// 来源节点是别人的会话，或者数据报不是从会话绑定的地方来的，都不算。
    pub(crate) fn owned_by(&self, node: NodeId, origin: Origin, now: Instant) -> bool {
        self.live(node, now).is_some_and(|session| session.binding.is(origin))
    }

    /// `node` 的会话就是绑定在 `origin` 上时，返回它握手时给的随机数（[`owned_by`](Self::owned_by) 为真的那些情况）。
    pub(crate) fn owned_nonce(&self, node: NodeId, origin: Origin, now: Instant) -> Option<Nonce> {
        self.live(node, now).filter(|session| session.binding.is(origin)).map(|session| session.nonce)
    }

    /// 发给 `node` 的包往哪里送。没有会话或者会话过期了返回 `None`。
    pub(crate) fn binding(&self, node: NodeId, now: Instant) -> Option<&Binding> {
        self.live(node, now).map(|session| &session.binding)
    }

    /// 收到 PING：会话是绑定在 `origin` 上的就续期，返回 `true`。
    pub(crate) fn refresh(&mut self, node: NodeId, origin: Origin, now: Instant) -> bool {
        match self.by_node.get_mut(&node) {
            Some(session) if session.expires > now && session.binding.is(origin) => {
                session.expires = now + SESSION_TTL;
                true
            }
            _ => false,
        }
    }

    /// 一条 TCP 断了：绑定在它上面的会话跟着没有。节点这期间已经换到别处的会话不受影响。
    pub(crate) fn close_tcp(&mut self, conn: TcpConn) -> Vec<NodeId> {
        let removed = self.remove_where(|_, session| session.binding.is(Origin::Tcp(conn)));
        self.broke.extend(&removed);
        removed
    }

    /// 删掉过期的会话，返回是哪些节点的。
    pub(crate) fn sweep(&mut self, now: Instant) -> Vec<NodeId> {
        let removed = self.remove_where(|_, session| session.expires <= now);
        self.broke.extend(&removed);
        removed
    }

    /// 删掉不再被允许的节点的会话（节点被吊销、从网络里删除，或者换了公钥：会话是旧公钥的主人建的），返回是哪些节点的。
    /// `key_of` 给出一个节点现在被允许用的公钥，不被允许的是 `None`。
    pub(crate) fn retain_clients(&mut self, key_of: impl Fn(NodeId) -> Option<PublicKey>) -> Vec<NodeId> {
        self.broke.retain(|node| key_of(*node).is_some());
        self.remove_where(|node, session| key_of(node) != Some(session.key))
    }

    /// 现在所有会话绑定的地方。给全体会话发通知时用。
    pub(crate) fn bindings(&self, now: Instant) -> Vec<Binding> {
        self.by_node.values().filter(|session| session.expires > now).map(|session| session.binding.clone()).collect()
    }

    pub(crate) fn clear(&mut self) {
        self.by_node.clear();
        self.broke.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.by_node.len()
    }

    fn live(&self, node: NodeId, now: Instant) -> Option<&Session> {
        self.by_node.get(&node).filter(|session| session.expires > now)
    }

    fn remove_where(&mut self, doomed: impl Fn(NodeId, &Session) -> bool) -> Vec<NodeId> {
        let removed: Vec<NodeId> = self.by_node.iter().filter(|&(&node, session)| doomed(node, session)).map(|(&node, _)| node).collect();
        for node in &removed {
            self.by_node.remove(node);
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use i3t_underlay::tcp_leg;

    use super::*;

    const NONCE: Nonce = [7; 8];
    const KEY: PublicKey = PublicKey::from_bytes([1; PublicKey::LEN]);

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn udp(port: u16) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], port))
    }

    fn tcp(conn: u64) -> Binding {
        Binding::Tcp { conn: TcpConn::Accepted(conn), sender: tcp_leg::frame_queue().0 }
    }

    fn accepted(conn: u64) -> Origin {
        Origin::Tcp(TcpConn::Accepted(conn))
    }

    #[test]
    fn a_session_belongs_only_to_the_address_it_was_opened_from() {
        let now = Instant::now();
        let mut sessions = Sessions::default();
        sessions.open(node(1), KEY, Binding::Udp(udp(4000)), NONCE, now);
        assert!(sessions.owned_by(node(1), Origin::Udp(udp(4000)), now));
        assert!(!sessions.owned_by(node(1), Origin::Udp(udp(4001)), now), "别的地址冒充不了");
        assert!(!sessions.owned_by(node(1), accepted(1), now));
        assert!(!sessions.owned_by(node(2), Origin::Udp(udp(4000)), now), "同一个地址也不能冒充别的节点");
        assert_eq!(sessions.owned_nonce(node(1), Origin::Udp(udp(4000)), now), Some(NONCE));
        assert_eq!(sessions.owned_nonce(node(1), Origin::Udp(udp(4001)), now), None, "握手的随机数只告诉会话的主人");
    }

    #[test]
    fn a_session_expires_without_keepalive_and_ping_extends_it() {
        let start = Instant::now();
        let mut sessions = Sessions::default();
        sessions.open(node(1), KEY, Binding::Udp(udp(4000)), NONCE, start);

        let later = start + SESSION_TTL - Duration::from_secs(1);
        assert!(sessions.refresh(node(1), Origin::Udp(udp(4000)), later));
        assert!(!sessions.refresh(node(1), Origin::Udp(udp(4001)), later), "别的地址来的 PING 不续期");
        assert!(sessions.binding(node(1), start + SESSION_TTL).is_some(), "续过期了");

        let expired = later + SESSION_TTL;
        assert!(sessions.binding(node(1), expired).is_none());
        assert!(!sessions.owned_by(node(1), Origin::Udp(udp(4000)), expired));
        assert!(!sessions.refresh(node(1), Origin::Udp(udp(4000)), expired), "过期之后要重新握手");
        assert_eq!(sessions.sweep(expired), [node(1)]);
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn a_new_handshake_rebinds_the_session() {
        let now = Instant::now();
        let mut sessions = Sessions::default();
        sessions.open(node(1), KEY, tcp(7), NONCE, now);
        assert!(sessions.owned_by(node(1), accepted(7), now));
        sessions.open(node(1), KEY, Binding::Udp(udp(4000)), NONCE, now);
        assert!(!sessions.owned_by(node(1), accepted(7), now));
        assert!(matches!(sessions.binding(node(1), now), Some(Binding::Udp(_))));
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn only_a_session_rebuilt_after_a_break_counts_as_reopened() {
        let start = Instant::now();
        let mut sessions = Sessions::default();
        sessions.open(node(1), KEY, tcp(7), NONCE, start);
        assert_eq!(sessions.reopened(node(1), start), None, "头一次建立");

        // 节点认为原来的会话没了，在一条新的 TCP 上重新握手：这是断过。
        let later = start + Duration::from_secs(20);
        sessions.open(node(1), KEY, tcp(8), NONCE, later);
        assert_eq!(sessions.reopened(node(1), later), Some(later));
        // 保活不改变这个时刻。
        assert!(sessions.refresh(node(1), accepted(8), later + Duration::from_secs(5)));
        assert_eq!(sessions.reopened(node(1), later + Duration::from_secs(5)), Some(later));
        // 从 TCP 换到 UDP 不是断：还是原来那个时刻。
        sessions.open(node(1), KEY, Binding::Udp(udp(4000)), NONCE, later + Duration::from_secs(10));
        assert_eq!(sessions.reopened(node(1), later + Duration::from_secs(10)), Some(later));
        assert_eq!(sessions.reopened(node(2), later), None, "没有会话");
    }

    #[test]
    fn a_session_opened_after_the_last_one_was_closed_or_expired_counts_as_reopened() {
        let start = Instant::now();
        let mut sessions = Sessions::default();
        sessions.open(node(1), KEY, tcp(7), NONCE, start);
        sessions.open(node(2), KEY, Binding::Udp(udp(4000)), NONCE, start);
        sessions.open(node(3), KEY, Binding::Udp(udp(4001)), NONCE, start);
        assert_eq!(sessions.close_tcp(TcpConn::Accepted(7)), [node(1)]);
        let expired = start + SESSION_TTL;
        assert_eq!(sessions.sweep(expired).len(), 2);

        sessions.open(node(1), KEY, tcp(9), NONCE, expired);
        sessions.open(node(2), KEY, Binding::Udp(udp(4000)), NONCE, expired);
        assert_eq!(sessions.reopened(node(1), expired), Some(expired));
        assert_eq!(sessions.reopened(node(2), expired), Some(expired));
        // 被从网络里拿掉的节点不留记录：以后再加回来是全新的。
        sessions.retain_clients(|node| (node != self::node(3)).then_some(KEY));
        sessions.open(node(3), KEY, Binding::Udp(udp(4001)), NONCE, expired);
        assert_eq!(sessions.reopened(node(3), expired), None);
    }

    #[test]
    fn closing_a_tcp_connection_removes_only_sessions_still_bound_to_it() {
        let now = Instant::now();
        let mut sessions = Sessions::default();
        sessions.open(node(1), KEY, tcp(7), NONCE, now);
        sessions.open(node(2), KEY, tcp(8), NONCE, now);
        sessions.open(node(3), KEY, tcp(9), NONCE, now);
        // 节点 3 已经换回了 UDP，它原来那条 TCP 断开不该影响它。
        sessions.open(node(3), KEY, Binding::Udp(udp(4000)), NONCE, now);
        assert_eq!(sessions.close_tcp(TcpConn::Accepted(7)), [node(1)]);
        assert_eq!(sessions.close_tcp(TcpConn::Accepted(9)), []);
        assert!(sessions.binding(node(2), now).is_some() && sessions.binding(node(3), now).is_some());
    }

    #[test]
    fn every_live_binding_is_listed_for_notifications() {
        let now = Instant::now();
        let mut sessions = Sessions::default();
        sessions.open(node(1), KEY, Binding::Udp(udp(4000)), NONCE, now);
        sessions.open(node(2), KEY, tcp(7), NONCE, now);
        assert_eq!(sessions.bindings(now).len(), 2);
        assert!(sessions.bindings(now + SESSION_TTL).is_empty(), "过期的会话不再通知");
    }

    #[test]
    fn sessions_of_removed_clients_are_dropped() {
        let now = Instant::now();
        let mut sessions = Sessions::default();
        sessions.open(node(1), KEY, Binding::Udp(udp(4000)), NONCE, now);
        sessions.open(node(2), KEY, Binding::Udp(udp(4001)), NONCE, now);
        assert_eq!(sessions.retain_clients(|id| (id == node(2)).then_some(KEY)), [node(1)]);
        assert!(sessions.binding(node(1), now).is_none() && sessions.binding(node(2), now).is_some());
        sessions.clear();
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn a_session_is_dropped_when_its_node_is_given_another_key() {
        const NEW_KEY: PublicKey = PublicKey::from_bytes([2; PublicKey::LEN]);
        let now = Instant::now();
        let mut sessions = Sessions::default();
        sessions.open(node(1), KEY, Binding::Udp(udp(4000)), NONCE, now);
        sessions.open(node(2), KEY, Binding::Udp(udp(4001)), NONCE, now);
        // 节点 1 还在名单里，公钥换了：会话是旧公钥的主人建的。
        let key_of = |id| Some(if id == node(1) { NEW_KEY } else { KEY });
        assert_eq!(sessions.retain_clients(key_of), [node(1)]);
        assert!(!sessions.refresh(node(1), Origin::Udp(udp(4000)), now), "保活续不了一个已经不算数的会话");
        assert!(sessions.binding(node(2), now).is_some(), "公钥没有变的不受影响");

        // 新公钥的主人握手建的是全新的会话，之后名单不变它就留着。
        sessions.open(node(1), NEW_KEY, Binding::Udp(udp(4002)), NONCE, now);
        assert_eq!(sessions.reopened(node(1), now), None);
        assert_eq!(sessions.retain_clients(key_of), []);
        assert!(sessions.owned_by(node(1), Origin::Udp(udp(4002)), now));
    }
}
