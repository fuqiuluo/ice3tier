//! 地址查询发起方：向一组服务器查询其观察到的本节点地址。格式见 [`i3t_proto::addr`]。
//!
//! 这里不碰 socket 的接收：应答和别的数据报一样从那个唯一的 UDP 端口进来，由收包的一方认出是地址查询的应答之后
//! 交给 [`AddrQuery::handle_reply`]。

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use i3t_proto::addr::{Query, Reply};

use crate::port::UdpPort;

/// 一个服务器多久问一次。NAT 上的映射通常能保持 30 秒以上，这个间隔顺带给它保活。
const QUERY_INTERVAL: Duration = Duration::from_secs(25);
/// 还没有得到过回答的服务器问得勤一些，尽快拿到第一个反射地址。
const RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// 回答的有效期。过期的估计不能一直沿用。
const OBSERVATION_TTL: Duration = Duration::from_secs(120);

/// 某个服务器看到的本节点地址。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// 回答的服务器。
    pub observer: SocketAddr,
    /// 它看到的本节点地址。
    pub observed: SocketAddr,
    pub at: Instant,
}

#[derive(Debug)]
struct Server {
    addr: SocketAddr,
    /// 最近一次查询的随机数。仅接受携带相同随机数的应答，防止路径外伪造。
    pending: Option<[u8; 8]>,
    last_sent: Option<Instant>,
    observation: Option<Observation>,
}

/// 地址查询的状态：问过谁、谁回答了什么。
#[derive(Debug)]
pub struct AddrQuery {
    servers: Vec<Server>,
}

impl AddrQuery {
    #[must_use]
    pub fn new(servers: impl IntoIterator<Item = SocketAddr>) -> Self {
        let mut seen = HashSet::new();
        let servers = servers
            .into_iter()
            .filter(|&addr| seen.insert(addr))
            .map(|addr| Server { addr, pending: None, last_sent: None, observation: None })
            .collect();
        Self { servers }
    }

    /// 向到达查询间隔的服务器发送查询请求。需定时调用，重试与刷新间隔由内部控制。
    pub fn poll(&mut self, port: &UdpPort, now: Instant) {
        for server in &mut self.servers {
            let fresh = server.observation.is_some_and(|observation| now.duration_since(observation.at) < OBSERVATION_TTL);
            let interval = if fresh { QUERY_INTERVAL } else { RETRY_INTERVAL };
            if server.last_sent.is_some_and(|sent| now.duration_since(sent) < interval) {
                continue;
            }
            let nonce = crate::random_bytes();
            server.pending = Some(nonce);
            server.last_sent = Some(now);
            port.send_datagram(&Query { nonce }.to_bytes(), server.addr);
        }
    }

    /// 处理一个应答。若来源不在已查询服务器列表中，或随机数与最近一次查询不匹配，则返回 `None` 并忽略该应答。
    pub fn handle_reply(&mut self, from: SocketAddr, reply: &Reply, now: Instant) -> Option<Observation> {
        let server = self.servers.iter_mut().find(|server| server.addr == from)?;
        if server.pending != Some(reply.nonce) {
            return None;
        }
        server.pending = None;
        let observation = Observation { observer: from, observed: reply.observed, at: now };
        server.observation = Some(observation);
        Some(observation)
    }

    /// 还没有过期的回答。
    pub fn observations(&self, now: Instant) -> impl Iterator<Item = Observation> + '_ {
        self.servers
            .iter()
            .filter_map(|server| server.observation)
            .filter(move |observation| now.duration_since(observation.at) < OBSERVATION_TTL)
    }
}

/// 回答一个地址查询：把看到的来源地址告诉对方。回答的一方不记任何状态，应答不比查询大。
#[must_use]
pub fn answer(query: &Query, from: SocketAddr) -> Vec<u8> {
    Reply { nonce: query.nonce, observed: from }.to_bytes()
}

#[cfg(test)]
mod tests {
    use std::io::IoSliceMut;

    use i3t_proto::Datagram;

    use super::*;
    use crate::port::RecvMeta;

    async fn receive_one(port: &UdpPort) -> (SocketAddr, Vec<u8>) {
        let mut storage = vec![0u8; 2048 * port.gro_segments()];
        let mut metas = [RecvMeta::default(); 1];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let count = tokio::time::timeout(Duration::from_secs(5), port.recv(&mut bufs, &mut metas)).await.expect("等数据报超时").unwrap();
        assert_eq!(count, 1);
        (metas[0].addr, bufs[0][..metas[0].len.min(metas[0].stride)].to_vec())
    }

    #[tokio::test]
    async fn a_query_is_answered_with_the_address_the_server_saw() {
        let client = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut query = AddrQuery::new([server.local_addr()]);
        let now = Instant::now();
        query.poll(&client, now);

        let (from, datagram) = receive_one(&server).await;
        let Ok(Datagram::AddrQuery(received)) = Datagram::parse(&datagram) else { panic!("不是地址查询：{datagram:?}") };
        let reply = answer(&received, from);
        assert!(reply.len() <= datagram.len(), "应答不能比查询大");
        server.send_datagram(&reply, from);

        let (from, datagram) = receive_one(&client).await;
        let Ok(Datagram::AddrReply(reply)) = Datagram::parse(&datagram) else { panic!("不是应答：{datagram:?}") };
        let observation = query.handle_reply(from, &reply, now).expect("应答应该对得上");
        assert_eq!(observation.observed, client.local_addr());
        assert_eq!(query.observations(now).collect::<Vec<_>>(), [observation]);
    }

    #[tokio::test]
    async fn replies_from_strangers_or_with_a_wrong_nonce_are_ignored() {
        let client = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let stranger: SocketAddr = "127.0.0.1:10".parse().unwrap();
        let mut query = AddrQuery::new([server]);
        let now = Instant::now();
        query.poll(&client, now);
        let nonce = query.servers[0].pending.unwrap();
        let observed = "203.0.113.7:1234".parse().unwrap();

        assert_eq!(query.handle_reply(stranger, &Reply { nonce, observed }, now), None);
        assert_eq!(query.handle_reply(server, &Reply { nonce: [0; 8], observed }, now), None);
        assert!(query.handle_reply(server, &Reply { nonce, observed }, now).is_some());
        assert_eq!(query.handle_reply(server, &Reply { nonce, observed }, now), None, "同一个应答不能用两次");
    }

    #[tokio::test]
    async fn servers_are_asked_again_after_the_interval_and_old_answers_expire() {
        let client = UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut query = AddrQuery::new([server, server]);
        assert_eq!(query.servers.len(), 1, "重复的服务器只算一个");
        let start = Instant::now();
        query.poll(&client, start);
        let first = query.servers[0].pending.unwrap();
        query.poll(&client, start + Duration::from_millis(500));
        assert_eq!(query.servers[0].pending, Some(first), "间隔没到不重发");
        query.poll(&client, start + RETRY_INTERVAL);
        let second = query.servers[0].pending.unwrap();
        assert_ne!(second, first);

        let observed = "203.0.113.7:1234".parse().unwrap();
        query.handle_reply(server, &Reply { nonce: second, observed }, start + RETRY_INTERVAL).unwrap();
        assert_eq!(query.observations(start + RETRY_INTERVAL + OBSERVATION_TTL).count(), 0);
    }
}
