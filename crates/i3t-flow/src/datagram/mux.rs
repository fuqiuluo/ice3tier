//! 把连接层收到的数据报分给各个上下文。
//!
//! 连接层交上来的是"某个对端发来的一帧"。这里解析帧头，把分片拼回去，按（对端，上下文号）找到上下文，
//! 把内容放进它的队列。每个上下文的队列有上限（个数和字节数都有），满了就丢新来的：
//! 取的一方慢了，不能让别的上下文跟着等，也不能让内存跟着涨。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use bytes::Bytes;
use i3t_conn::contract::{Datagram, Datagrams};
use i3t_proto::NodeId;
use i3t_proto::flow::{DatagramHeader, Recipient};
use tokio::sync::mpsc;

use super::reassembly::Reassembler;

/// 一个上下文里收到了、还没有被取走的数据报最多排多少个。
const CONTEXT_BACKLOG: usize = 256;

/// 这些数据报加起来最多多少字节。一个数据报可以有 64KB，只限个数的话一个没人取的上下文能占住十几 MB。
const CONTEXT_BACKLOG_BYTES: usize = 512 * 1024;

type Key = (NodeId, u32);

/// 一个上下文的队列往里放的那一头。
#[derive(Clone)]
struct Queue {
    sender: mpsc::Sender<Bytes>,
    /// 队列里现在排着多少字节。取的一头每取走一个就减掉。
    queued: Arc<AtomicUsize>,
}

impl Queue {
    /// 放得下就放进去，返回放进去了没有。
    fn offer(&self, body: Bytes) -> bool {
        let len = body.len();
        if self.queued.fetch_add(len, Ordering::AcqRel) + len <= CONTEXT_BACKLOG_BYTES && self.sender.try_send(body).is_ok() {
            return true;
        }
        self.queued.fetch_sub(len, Ordering::AcqRel);
        false
    }
}

/// 一个节点上，上下文的某一侧（发起方那些，或者接受方那些）的全部上下文。
pub(crate) struct Mux {
    /// 这里的上下文是哪一侧的：只处理发给这一侧的数据报。
    side: Recipient,
    state: Mutex<State>,
    /// 发起方挑上下文号用。
    next_context: AtomicU32,
}

#[derive(Default)]
struct State {
    contexts: HashMap<Key, Queue>,
    /// 每个对端一份，只在它有拼到一半的报文时存在。
    reassembly: HashMap<NodeId, Reassembler>,
}

impl Mux {
    pub(crate) fn new(side: Recipient) -> Arc<Self> {
        Arc::new(Self { side, state: Mutex::default(), next_context: AtomicU32::new(0) })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("datagram mux mutex poisoned")
    }

    /// 登记对端给定了号的一个上下文（接受方用）。这个号在和它的上下文里已经在用时返回 `None`。
    pub(crate) fn register(self: &Arc<Self>, peer: NodeId, context: u32) -> Option<Registration> {
        let (sender, incoming) = mpsc::channel(CONTEXT_BACKLOG);
        let queued = Arc::new(AtomicUsize::new(0));
        let mut state = self.state();
        if state.contexts.contains_key(&(peer, context)) {
            return None;
        }
        state.contexts.insert((peer, context), Queue { sender, queued: Arc::clone(&queued) });
        Some(Registration { mux: Arc::clone(self), peer, context, incoming, queued })
    }

    /// 挑一个到 `peer` 还没在用的上下文号并登记（发起方用）。
    pub(crate) fn allocate(self: &Arc<Self>, peer: NodeId) -> Registration {
        loop {
            // 上下文号单调递增，回绕后若与活跃上下文冲突则继续尝试下一个。
            let context = self.next_context.fetch_add(1, Ordering::Relaxed);
            if let Some(registration) = self.register(peer, context) {
                return registration;
            }
        }
    }

    /// 一直从连接层取发给这一侧的数据报并分发，直到连接层关闭。
    pub(crate) async fn pump<D: Datagrams>(&self, transport: &D) {
        while let Some(datagram) = transport.recv_datagram(self.side).await {
            self.dispatch(datagram, Instant::now());
        }
    }

    /// 处理对端发来的一帧。无法解析、找不到对应上下文或队列已满时直接丢弃（数据报允许丢包）。
    pub(crate) fn dispatch(&self, datagram: Datagram, now: Instant) {
        let Datagram { peer, payload } = datagram;
        let (header, rest) = match DatagramHeader::decode(&payload) {
            Ok((header, rest)) if header.recipient == self.side => (header, rest),
            Ok(_) => return tracing::trace!(%peer, "丢弃数据报：目标侧与当前侧不匹配"),
            Err(error) => return tracing::trace!(%peer, %error, "丢弃数据报：帧格式无效"),
        };
        let content = payload.slice(payload.len() - rest.len()..);

        let mut state = self.state();
        // 先看有没有这个上下文再拼片：不给不存在的上下文号占内存。
        let Some(queue) = state.contexts.get(&(peer, header.context)).cloned() else {
            return tracing::trace!(%peer, context = header.context, "丢弃数据报：找不到对应的上下文");
        };
        let body = match header.fragment {
            None => content,
            Some(fragment) => {
                let reassembler = state.reassembly.entry(peer).or_default();
                let complete = reassembler.push(header.context, fragment, content, now);
                if reassembler.is_empty() {
                    state.reassembly.remove(&peer);
                }
                let Some(body) = complete else { return };
                body
            }
        };
        drop(state);
        if !queue.offer(body) {
            tracing::trace!(%peer, context = header.context, "丢弃数据报：上下文接收队列已满");
        }
    }

    fn unregister(&self, peer: NodeId, context: u32) {
        let mut state = self.state();
        state.contexts.remove(&(peer, context));
        if let Some(reassembler) = state.reassembly.get_mut(&peer) {
            reassembler.forget(context);
            if reassembler.is_empty() {
                state.reassembly.remove(&peer);
            }
        }
    }

    #[cfg(test)]
    fn reassembling_peers(&self) -> usize {
        self.state().reassembly.len()
    }
}

/// 一个登记着的上下文。丢弃时注销：之后发给这个号的数据报没有人收，号可以再用。
pub(crate) struct Registration {
    mux: Arc<Mux>,
    peer: NodeId,
    context: u32,
    incoming: mpsc::Receiver<Bytes>,
    queued: Arc<AtomicUsize>,
}

impl Registration {
    pub(crate) fn context(&self) -> u32 {
        self.context
    }

    /// 等对端发来的下一个数据报的内容（目标加载荷），已经拼好。可以放在 `select!` 里：被取消时不会丢。
    pub(crate) async fn recv(&mut self) -> Option<Bytes> {
        let body = self.incoming.recv().await?;
        self.queued.fetch_sub(body.len(), Ordering::AcqRel);
        Some(body)
    }

    /// 队列里已经有的话取一个。
    #[cfg(test)]
    fn try_recv(&mut self) -> Option<Bytes> {
        let body = self.incoming.try_recv().ok()?;
        self.queued.fetch_sub(body.len(), Ordering::AcqRel);
        Some(body)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.mux.unregister(self.peer, self.context);
    }
}

#[cfg(test)]
mod tests {
    use i3t_proto::flow::Frames;

    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn frames(recipient: Recipient, context: u32, message: u16, body: &[u8], max_len: usize) -> Vec<Bytes> {
        Frames::split(recipient, context, message, body, max_len).unwrap().map(Bytes::from).collect()
    }

    fn deliver(mux: &Mux, peer: u32, frame: &Bytes) {
        mux.dispatch(Datagram { peer: node(peer), payload: frame.clone() }, Instant::now());
    }

    #[test]
    fn a_datagram_goes_to_the_context_of_that_peer_with_that_number_and_nowhere_else() {
        let mux = Mux::new(Recipient::Acceptor);
        let mut from_1 = mux.register(node(1), 7).unwrap();
        let mut from_2 = mux.register(node(2), 7).unwrap();
        let mut other = mux.register(node(1), 8).unwrap();

        deliver(&mux, 1, &frames(Recipient::Acceptor, 7, 0, b"for (1, 7)", 1200)[0]);
        deliver(&mux, 2, &frames(Recipient::Acceptor, 7, 0, b"for (2, 7)", 1200)[0]);
        assert_eq!(from_1.try_recv().unwrap(), &b"for (1, 7)"[..]);
        assert_eq!(from_2.try_recv().unwrap(), &b"for (2, 7)"[..]);
        assert!(from_1.try_recv().is_none() && other.try_recv().is_none());

        // 没有的上下文、给另一侧的、不合格式的：都不会到任何人手里。
        deliver(&mux, 3, &frames(Recipient::Acceptor, 7, 0, b"unknown peer", 1200)[0]);
        deliver(&mux, 1, &frames(Recipient::Acceptor, 9, 0, b"unknown context", 1200)[0]);
        deliver(&mux, 1, &frames(Recipient::Initiator, 7, 0, b"other side", 1200)[0]);
        deliver(&mux, 1, &Bytes::from_static(&[0x00, 0, 0]));
        deliver(&mux, 1, &Bytes::from_static(&[0x80, 0, 0, 0, 7, 1]));
        for registration in [&mut from_1, &mut from_2, &mut other] {
            assert!(registration.try_recv().is_none());
        }
    }

    #[test]
    fn fragments_are_reassembled_before_they_reach_the_context() {
        let mux = Mux::new(Recipient::Initiator);
        let mut context = mux.register(node(1), 7).unwrap();
        let body: Vec<u8> = (0..=u8::MAX).cycle().take(5000).collect();
        let cut = frames(Recipient::Initiator, 7, 3, &body, 1200);
        assert_eq!(cut.len(), 5);
        for frame in cut.iter().rev() {
            assert!(context.try_recv().is_none(), "片没到齐之前什么都不交出去");
            deliver(&mux, 1, frame);
        }
        assert_eq!(context.try_recv().unwrap(), &body[..]);
        assert_eq!(mux.reassembling_peers(), 0);
    }

    #[test]
    fn fragments_for_a_context_that_does_not_exist_take_no_memory() {
        let mux = Mux::new(Recipient::Acceptor);
        let cut = frames(Recipient::Acceptor, 7, 3, &[0; 5000], 1200);
        deliver(&mux, 1, &cut[0]);
        assert_eq!(mux.reassembling_peers(), 0);

        // 上下文结束时，它拼到一半的报文跟着扔掉。
        let context = mux.register(node(1), 7).unwrap();
        deliver(&mux, 1, &cut[0]);
        assert_eq!(mux.reassembling_peers(), 1);
        drop(context);
        assert_eq!(mux.reassembling_peers(), 0);
    }

    #[test]
    fn a_context_that_is_not_drained_drops_new_datagrams_at_its_bound() {
        let mux = Mux::new(Recipient::Acceptor);
        let mut slow = mux.register(node(1), 1).unwrap();
        let mut quick = mux.register(node(1), 2).unwrap();
        for index in 0..2 * u32::try_from(CONTEXT_BACKLOG).unwrap() {
            deliver(&mux, 1, &frames(Recipient::Acceptor, 1, 0, &index.to_be_bytes(), 1200)[0]);
        }
        // 别的上下文不受影响。
        deliver(&mux, 1, &frames(Recipient::Acceptor, 2, 0, b"still delivered", 1200)[0]);
        assert_eq!(quick.try_recv().unwrap(), &b"still delivered"[..]);

        let mut queued = Vec::new();
        while let Some(body) = slow.try_recv() {
            queued.push(u32::from_be_bytes(body[..].try_into().unwrap()));
        }
        assert_eq!(queued, (0..u32::try_from(CONTEXT_BACKLOG).unwrap()).collect::<Vec<_>>(), "留下的是先到的那些");
    }

    #[test]
    fn a_context_that_is_not_drained_holds_a_bounded_number_of_bytes() {
        let mux = Mux::new(Recipient::Acceptor);
        let mut slow = mux.register(node(1), 1).unwrap();
        // 走单向流来的数据报可以有 64KB。个数还远没到上限，字节数先到了。
        let large = frames(Recipient::Acceptor, 1, 0, &vec![7; 60_000], usize::MAX).remove(0);
        for _ in 0..20 {
            deliver(&mux, 1, &large);
        }
        let queued = |slow: &Registration| slow.queued.load(Ordering::Relaxed);
        assert_eq!(queued(&slow), 8 * 60_000, "只留下放得进半兆字节的那 8 个");

        // 取走一个，就又放得下一个。
        assert_eq!(slow.try_recv().unwrap().len(), 60_000);
        deliver(&mux, 1, &large);
        deliver(&mux, 1, &large);
        assert_eq!(queued(&slow), 8 * 60_000);
        let mut drained = 0;
        while slow.try_recv().is_some() {
            drained += 1;
        }
        assert_eq!((drained, queued(&slow)), (8, 0));
    }

    #[test]
    fn a_context_number_is_unique_per_peer_while_it_is_open_and_free_again_afterwards() {
        let mux = Mux::new(Recipient::Acceptor);
        let first = mux.register(node(1), 7).unwrap();
        assert!(mux.register(node(1), 7).is_none(), "同一个对端的同一个号不能登记两次");
        assert!(mux.register(node(2), 7).is_some(), "不同的对端各有各的号");
        drop(first);
        assert!(mux.register(node(1), 7).is_some());

        // 发起方自己挑号：跳过还开着的。
        let mux = Mux::new(Recipient::Initiator);
        let taken = mux.register(node(1), 1).unwrap();
        let allocated: Vec<Registration> = (0..3).map(|_| mux.allocate(node(1))).collect();
        assert_eq!(allocated.iter().map(Registration::context).collect::<Vec<_>>(), [0, 2, 3]);
        drop(taken);
    }
}
