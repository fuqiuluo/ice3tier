//! CHALLENGE 里的 cookie：relay 不记状态地证明"对方确实收得到发往这个地址的包"。
//!
//! cookie 是用一把只有本进程知道的密钥，对"来源地址 + 节点编号 + 时间片"算出来的消息认证码。
//! relay 发出去之后什么都不记；AUTH 把它带回来时重算一遍，对得上就说明对方收到过发往这个地址的 CHALLENGE。
//! 伪造来源地址的一方无法收到 CHALLENGE，因而无法提供有效 cookie，relay 不会为其执行签名验证。

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use i3t_proto::NodeId;
use i3t_proto::session::{COOKIE_LEN, Cookie};
use ring::hmac;

/// 时间片的长度。cookie 在发出它的时间片和下一个时间片里有效，所以有效期在一到两个时间片之间：
/// 握手只要两个往返，这足够了；被人截获之后能重放的时间也就这么长（而且只能从同一个地址重放）。
const SLICE: Duration = Duration::from_secs(8);

/// 地址 16 字节（IPv4 写成映射地址）、端口 2 字节、节点编号 4 字节、时间片 8 字节。
const MESSAGE_LEN: usize = 16 + 2 + NodeId::WIRE_LEN + 8;

/// 发 cookie、验 cookie 的一方。密钥在创建时随机生成，进程重启之后以前发的 cookie 全部作废。
pub(crate) struct CookieJar {
    key: hmac::Key,
    /// 时间片从这里起算。用单调时钟，系统时间被调整不影响它。
    epoch: Instant,
}

impl CookieJar {
    pub(crate) fn new(now: Instant) -> Self {
        let secret: [u8; 32] = i3t_underlay::random_bytes();
        Self { key: hmac::Key::new(hmac::HMAC_SHA256, &secret), epoch: now }
    }

    pub(crate) fn issue(&self, from: SocketAddr, node: NodeId, now: Instant) -> Cookie {
        self.compute(from, node, self.slice(now))
    }

    /// `cookie` 是不是本进程在当前或者上一个时间片里发给 `from` 上的 `node` 的。
    pub(crate) fn verify(&self, cookie: &Cookie, from: SocketAddr, node: NodeId, now: Instant) -> bool {
        let slice = self.slice(now);
        let previous = slice.checked_sub(1).map(|previous| self.compute(from, node, previous));
        constant_time_eq(cookie, &self.compute(from, node, slice)) | previous.is_some_and(|previous| constant_time_eq(cookie, &previous))
    }

    fn slice(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs() / SLICE.as_secs()
    }

    fn compute(&self, from: SocketAddr, node: NodeId, slice: u64) -> Cookie {
        let ip = match from.ip() {
            IpAddr::V4(ip) => ip.to_ipv6_mapped(),
            IpAddr::V6(ip) => ip,
        };
        let mut message = [0; MESSAGE_LEN];
        message[..16].copy_from_slice(&ip.octets());
        message[16..18].copy_from_slice(&from.port().to_be_bytes());
        message[18..22].copy_from_slice(&node.to_be_bytes());
        message[22..].copy_from_slice(&slice.to_be_bytes());
        let tag = hmac::sign(&self.key, &message);
        *tag.as_ref().first_chunk::<COOKIE_LEN>().expect("HMAC-SHA256 输出长度为 32 字节，大于 cookie 长度")
    }
}

/// 比较所花的时间不随"前几个字节相同"变化，不给人逐字节试出 cookie 的机会。
fn constant_time_eq(a: &Cookie, b: &Cookie) -> bool {
    a.iter().zip(b).fold(0, |difference, (x, y)| difference | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_cookie_is_bound_to_address_port_and_node() {
        let now = Instant::now();
        let jar = CookieJar::new(now);
        let cookie = jar.issue(addr("203.0.113.7:4000"), node(5), now);
        assert!(jar.verify(&cookie, addr("203.0.113.7:4000"), node(5), now));
        assert!(!jar.verify(&cookie, addr("203.0.113.8:4000"), node(5), now));
        assert!(!jar.verify(&cookie, addr("203.0.113.7:4001"), node(5), now));
        assert!(!jar.verify(&cookie, addr("203.0.113.7:4000"), node(6), now));
        assert!(!jar.verify(&[0; COOKIE_LEN], addr("203.0.113.7:4000"), node(5), now));
    }

    #[test]
    fn a_cookie_survives_into_the_next_time_slice_but_not_beyond() {
        let start = Instant::now();
        let jar = CookieJar::new(start);
        let from = addr("[2001:db8::1]:4000");
        let issued = start + SLICE - Duration::from_millis(1);
        let cookie = jar.issue(from, node(5), issued);
        assert!(jar.verify(&cookie, from, node(5), issued + Duration::from_millis(2)), "刚跨过时间片的边界");
        assert!(jar.verify(&cookie, from, node(5), start + 2 * SLICE - Duration::from_millis(1)));
        assert!(!jar.verify(&cookie, from, node(5), start + 2 * SLICE));
    }

    #[test]
    fn cookies_from_another_process_are_worthless() {
        let now = Instant::now();
        let (jar, other) = (CookieJar::new(now), CookieJar::new(now));
        let from = addr("203.0.113.7:4000");
        assert!(!jar.verify(&other.issue(from, node(5), now), from, node(5), now));
    }
}
