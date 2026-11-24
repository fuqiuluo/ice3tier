//! 逐包访问控制过滤。
//!
//! controller 定义的访问规则为“a 可访问 b”，对应回程流量默认放行；在 netmap 中体现为每个对端的 `inbound` 标志
//! （是否允许其访问本节点），与建立连接流时查询的权限一致。若不允许对端访问本节点，则仅放行本节点主动发起会话的回包：
//!
//! - TCP：丢弃新建连接的首个握手包（带 SYN 且不带 ACK），放行其余 TCP 包（其余包无法建立新连接，内核对不存在的连接仅回复 RST）。
//!   同时丢弃被分片或头部不完整的 TCP 包（无法可靠判断标志位）；
//! - ICMP：丢弃 Echo 请求（ping），放行应答与差错报文（不可达、超时、参数问题）。若差错报文引用的原始包为 UDP，
//!   则该会话必须存在于下方回包跟踪表中，防止对端伪造端口向本机无关 UDP 套接字注入错误；
//! - UDP：仅当本节点近期曾从对应本机端口向该对端地址和端口发送过数据包时才放行（由有界表 [`Replies`] 跟踪）；
//! - IP 分片包：先收集齐所有分片（[`crate::fragments`]），再以首片调用本模块判定；单独的后续分片直接丢弃；
//! - 其他协议：一律丢弃（无法区分是否为回包）。
//!
//! ICMP 差错报文所引用原包的源/目的地址校验适用于所有对端（无论是否允许入站），在 [`crate::engine`] 中统一执行。
//!
//! 当规则双向均允许时（新建网络默认 `all <-> all`），不记录也不查询回包表。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::ipv4::{Conversation, Ipv4, UDP};

/// UDP 回包跟踪表的最大条目数。表满时先清理过期条目，仍满则淘汰最旧条目（最坏情况仅影响最早会话的回包）。
/// 单条仅占数十字节，整表内存上限约 100–200 KB。
pub const MAX_REPLIES: usize = 4096;

/// 本节点向某目标地址与端口发送 UDP 包后，允许接收其回包的有效窗口。与 UDP 端口转发的会话空闲超时保持一致。
pub const REPLY_WINDOW: Duration = Duration::from_secs(60);

/// 入站数据包的访问控制判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// 对端无权访问本节点，而该数据包用于发起新会话（或无法确认其属于已有会话的回包）。
    NewConversation,
}

/// 本节点近期发往无入站权限对端的 UDP 会话标识：（对端 IP，对端端口，本机端口）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Flow {
    peer: Ipv4Addr,
    peer_port: u16,
    local_port: u16,
}

/// UDP 回包会话跟踪表。
#[derive(Debug, Default)]
pub struct Replies {
    flows: HashMap<Flow, Instant>,
}

impl Replies {
    /// 记录本机发往无入站权限对端的出站数据包（仅跟踪 UDP）。
    pub fn sent(&mut self, packet: &Ipv4<'_>, now: Instant) {
        let Conversation::Udp { source, destination } = packet.conversation() else { return };
        let flow = Flow { peer: packet.destination(), peer_port: destination, local_port: source };
        if !self.flows.contains_key(&flow) && self.flows.len() >= MAX_REPLIES {
            self.make_room(now);
        }
        self.flows.insert(flow, now);
    }

    /// 判定无入站权限对端发来的数据包是否允许放行。对于 IP 分片包，应传入其首片。
    #[must_use]
    pub fn admit(&self, packet: &Ipv4<'_>, now: Instant) -> Verdict {
        let pass = match packet.conversation() {
            Conversation::TcpOngoing => true,
            Conversation::IcmpAnswer if packet.is_icmp_error() => packet.quoted().is_some_and(|quoted| self.quotes_ours(&quoted, now)),
            Conversation::IcmpAnswer => true,
            Conversation::TcpOpen | Conversation::IcmpRequest | Conversation::LaterFragment | Conversation::Other => false,
            Conversation::Udp { source, destination } => {
                self.expects(Flow { peer: packet.source(), peer_port: source, local_port: destination }, now)
            }
        };
        if pass { Verdict::Pass } else { Verdict::NewConversation }
    }

    /// 检查 ICMP 差错报文引用的原始出站包：UDP 需命中回包跟踪表（无法读取端口的拒绝），其余协议交由内核校验（如 TCP 序号校验）。
    fn quotes_ours(&self, quoted: &Ipv4<'_>, now: Instant) -> bool {
        if quoted.protocol() != UDP {
            return true;
        }
        match quoted.conversation() {
            Conversation::Udp { source, destination } => {
                self.expects(Flow { peer: quoted.destination(), peer_port: destination, local_port: source }, now)
            }
            _ => false,
        }
    }

    fn expects(&self, flow: Flow, now: Instant) -> bool {
        self.flows.get(&flow).is_some_and(|sent| now.saturating_duration_since(*sent) < REPLY_WINDOW)
    }

    /// 返回当前表中的条目数（包含尚未清理的过期条目）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    fn make_room(&mut self, now: Instant) {
        self.flows.retain(|_, sent| now.saturating_duration_since(*sent) < REPLY_WINDOW);
        if self.flows.len() >= MAX_REPLIES
            && let Some(oldest) = self.flows.iter().min_by_key(|(_, sent)| **sent).map(|(flow, _)| *flow)
        {
            self.flows.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::testing::{icmp, icmp_error, refragment, tcp, udp};

    const ME: [u8; 4] = [10, 66, 0, 1];
    const PEER: [u8; 4] = [10, 66, 0, 2];

    fn verdict(replies: &Replies, bytes: &[u8], now: Instant) -> Verdict {
        replies.admit(&Ipv4::parse(bytes).unwrap(), now)
    }

    #[test]
    fn a_peer_that_may_not_reach_us_cannot_open_anything_but_its_answers_pass() {
        let replies = Replies::default();
        let now = Instant::now();
        assert_eq!(verdict(&replies, &tcp(PEER, ME, (40000, 22), 0x02), now), Verdict::NewConversation, "SYN");
        assert_eq!(verdict(&replies, &tcp(PEER, ME, (22, 40000), 0x12), now), Verdict::Pass, "回给本机的 SYN-ACK");
        assert_eq!(verdict(&replies, &tcp(PEER, ME, (22, 40000), 0x10), now), Verdict::Pass);
        assert_eq!(verdict(&replies, &icmp(PEER, ME, 8), now), Verdict::NewConversation, "ping 的请求");
        assert_eq!(verdict(&replies, &icmp(PEER, ME, 0), now), Verdict::Pass, "ping 的回答");
        let syn = tcp(ME, PEER, (40000, 22), 0x02);
        assert_eq!(verdict(&replies, &icmp_error(PEER, ME, 3, 3, &syn[..28]), now), Verdict::Pass, "不可达");
        assert_eq!(verdict(&replies, &icmp(PEER, ME, 3), now), Verdict::NewConversation, "没有带回原包的不可达");
        assert_eq!(verdict(&replies, &udp(PEER, ME, (53, 5000), b"x"), now), Verdict::NewConversation, "没有先例的 UDP");
        let gre = crate::ipv4::testing::packet(47, PEER, ME, b"x");
        assert_eq!(verdict(&replies, &gre, now), Verdict::NewConversation, "看不出是不是回包的协议");
    }

    #[test]
    fn a_later_fragment_alone_and_a_cut_tcp_segment_do_not_pass() {
        let replies = Replies::default();
        let now = Instant::now();
        let later = refragment(udp(PEER, ME, (53, 5000), b"rest of it"), 4, 8, false);
        assert_eq!(verdict(&replies, &later, now), Verdict::NewConversation, "只有后面的片，判断不了");
        let gre_later = refragment(crate::ipv4::testing::packet(47, PEER, ME, b"x"), 5, 8, true);
        assert_eq!(verdict(&replies, &gre_later, now), Verdict::NewConversation);
        let cut_ack = refragment(tcp(PEER, ME, (22, 40000), 0x10), 6, 0, true);
        assert_eq!(verdict(&replies, &cut_ack, now), Verdict::NewConversation, "切开的 TCP 看不准标志");
    }

    #[test]
    fn an_icmp_error_about_udp_passes_only_for_a_conversation_we_started() {
        let mut replies = Replies::default();
        let now = Instant::now();
        let query = udp(ME, PEER, (5000, 53), b"query");
        let error = |quoted: &[u8]| icmp_error(PEER, ME, 3, 3, quoted);
        assert_eq!(verdict(&replies, &error(&query[..28]), now), Verdict::NewConversation, "本节点没发过");
        replies.sent(&Ipv4::parse(&query).unwrap(), now);
        assert_eq!(verdict(&replies, &error(&query[..28]), now), Verdict::Pass, "端口不可达：说的是本节点刚发的");
        let other_port = udp(ME, PEER, (5001, 53), b"query");
        assert_eq!(verdict(&replies, &error(&other_port[..28]), now), Verdict::NewConversation, "本机别的端口");
        assert_eq!(verdict(&replies, &error(&query[..20]), now), Verdict::NewConversation, "看不到端口");
        assert_eq!(verdict(&replies, &error(&query[..12]), now), Verdict::NewConversation, "带回来的头都不完整");
        let later = refragment(query.clone(), 1, 8, false);
        assert_eq!(verdict(&replies, &error(&later[..28]), now), Verdict::NewConversation, "说的是后面的一片，没有端口");
        let syn = tcp(ME, PEER, (40000, 22), 0x02);
        assert_eq!(verdict(&replies, &error(&syn[..28]), now), Verdict::Pass, "TCP 的由内核按序号核对");
    }

    #[test]
    fn udp_answers_pass_only_from_the_address_and_port_we_sent_to_and_only_for_a_while() {
        let mut replies = Replies::default();
        let now = Instant::now();
        replies.sent(&Ipv4::parse(&udp(ME, PEER, (5000, 53), b"query")).unwrap(), now);
        assert_eq!(replies.len(), 1);
        assert_eq!(verdict(&replies, &udp(PEER, ME, (53, 5000), b"answer"), now), Verdict::Pass);
        assert_eq!(verdict(&replies, &udp(PEER, ME, (54, 5000), b"x"), now), Verdict::NewConversation, "别的端口");
        assert_eq!(verdict(&replies, &udp(PEER, ME, (53, 5001), b"x"), now), Verdict::NewConversation, "本机别的端口");
        assert_eq!(verdict(&replies, &udp([10, 66, 0, 3], ME, (53, 5000), b"x"), now), Verdict::NewConversation, "别的对端");
        assert_eq!(verdict(&replies, &udp(PEER, ME, (53, 5000), b"late"), now + REPLY_WINDOW), Verdict::NewConversation, "过期了");
        replies.sent(&Ipv4::parse(&tcp(ME, PEER, (40000, 22), 0x02)).unwrap(), now);
        assert_eq!(replies.len(), 1, "TCP 不用记");
    }

    #[test]
    fn the_table_never_grows_past_its_limit_and_drops_the_stale_then_the_oldest() {
        let mut replies = Replies::default();
        let start = Instant::now();
        let port = |n: usize| u16::try_from(n % 60000 + 1).unwrap();
        for n in 0..MAX_REPLIES {
            let at = start + Duration::from_millis(u64::try_from(n).unwrap());
            replies.sent(&Ipv4::parse(&udp(ME, PEER, (port(n), 53), b"")).unwrap(), at);
        }
        assert_eq!(replies.len(), MAX_REPLIES);
        let later = start + Duration::from_secs(30);
        replies.sent(&Ipv4::parse(&udp(ME, PEER, (61000, 53), b"")).unwrap(), later);
        assert_eq!(replies.len(), MAX_REPLIES, "满了扔一条最旧的");
        assert_eq!(verdict(&replies, &udp(PEER, ME, (53, port(0)), b""), later), Verdict::NewConversation, "最旧的那条没了");
        assert_eq!(verdict(&replies, &udp(PEER, ME, (53, port(1)), b""), later), Verdict::Pass);
        let much_later = start + REPLY_WINDOW + Duration::from_secs(6);
        replies.sent(&Ipv4::parse(&udp(ME, PEER, (62000, 53), b"")).unwrap(), much_later);
        assert_eq!(replies.len(), 2, "满了的时候先扔过期的：只剩刚才和这一条");
    }
}
