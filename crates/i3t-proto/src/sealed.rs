//! 封好的网络包：虚拟网卡的 IP 包不进 QUIC，单独加密之后直接走路径层。
//!
//! 一对节点之间的连接握手完成之后，两端各自从这次握手里导出同样的一组密钥。之后虚拟网卡的每个网络包帧
//! （[`crate::flow::PacketHeader`] 连同后面的 IP 包）用它单独加密，装成下面这样一个数据报，和连接包走同一条路：
//! 直连时它就是整个数据报，经 relay 时前面加上中转头。
//!
//! ```text
//! 0      1          5          13                          最后 16 字节
//! +------+----------+----------+---------------------------+----------+
//! | 0x11 | 连接标识 | 序号     | 密文（网络包帧）          | 校验     |
//! +------+----------+----------+---------------------------+----------+
//! ```
//!
//! - 连接标识：密钥是哪一条连接的。它和密钥一起从握手里导出，两端算出来的一样。
//! - 序号：这条连接在这个方向上发的第几个，从 0 起，每发一个加 1。它也是加密时的随机数，同一把密钥下不能重复；
//!   收的一方靠它丢掉重放的包。
//! - 头的 13 个字节不加密，但是算在校验里，改了就对不上。
//!
//! 这样的包丢了就丢了：没有确认，没有重传，也不受连接的拥塞控制管。这些都是包里面的协议（两端内核的 TCP 等）自己的事。
//!
//! 这里只有格式。用哪种算法、密钥怎么导出、重放怎么判断，是连接层的事。

/// 封好的网络包的首字节。
pub const KIND_SEALED: u8 = 0x11;

/// 封好的网络包开头不加密的部分。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SealedHeader {
    /// 密钥是哪一条连接的。
    pub session: u32,
    /// 这个方向上的第几个包。
    pub counter: u64,
}

impl SealedHeader {
    /// 头占的字节数：类型 1 字节，连接标识 4 字节，序号 8 字节。
    pub const LEN: usize = 1 + 4 + 8;
    /// 末尾的校验占的字节数。
    pub const TAG_LEN: usize = 16;
    /// 一个网络包帧封好之后多出来的字节数。
    pub const OVERHEAD: usize = Self::LEN + Self::TAG_LEN;

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        bytes[0] = KIND_SEALED;
        bytes[1..5].copy_from_slice(&self.session.to_be_bytes());
        bytes[5..].copy_from_slice(&self.counter.to_be_bytes());
        bytes
    }

    /// 一个数据报是不是长度说得通的封好的网络包：首字节对，装得下头、校验和至少一个字节的内容。只做算术，不看内容。
    #[must_use]
    pub fn is_complete(datagram: &[u8]) -> bool {
        datagram.first() == Some(&KIND_SEALED) && datagram.len() > Self::OVERHEAD
    }

    /// 取出头。`packet` 不是封好的网络包（[`is_complete`](Self::is_complete) 为假）时返回 `None`。
    ///
    /// 头后面到末尾是密文连同校验，从第 [`LEN`](Self::LEN) 个字节起。
    #[must_use]
    pub fn parse(packet: &[u8]) -> Option<Self> {
        if !Self::is_complete(packet) {
            return None;
        }
        let (session, rest) = packet[1..].split_first_chunk::<4>()?;
        let (counter, _) = rest.split_first_chunk::<8>()?;
        Some(Self { session: u32::from_be_bytes(*session), counter: u64::from_be_bytes(*counter) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(header: SealedHeader, body_and_tag: usize) -> Vec<u8> {
        let mut packet = header.to_bytes().to_vec();
        packet.resize(SealedHeader::LEN + body_and_tag, 0xab);
        packet
    }

    #[test]
    fn the_header_round_trips_and_is_big_endian() {
        let header = SealedHeader { session: 0x0102_0304, counter: 0x0506_0708_090a_0b0c };
        assert_eq!(header.to_bytes(), [0x11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(SealedHeader::parse(&sealed(header, SealedHeader::TAG_LEN + 1)), Some(header));
    }

    #[test]
    fn a_packet_needs_the_header_the_tag_and_at_least_one_byte() {
        let header = SealedHeader { session: 1, counter: 0 };
        let shortest = sealed(header, SealedHeader::TAG_LEN + 1);
        assert!(SealedHeader::is_complete(&shortest));
        assert_eq!(shortest.len(), SealedHeader::OVERHEAD + 1);
        for len in 0..shortest.len() {
            assert_eq!(SealedHeader::parse(&shortest[..len]), None, "{len} 字节装不下头、校验和内容");
        }
    }

    #[test]
    fn other_first_bytes_are_not_sealed_packets() {
        let mut packet = sealed(SealedHeader { session: 1, counter: 2 }, 64);
        for first in [0x00, 0x01, 0x10, 0x12, 0x40, 0x51, 0xff] {
            packet[0] = first;
            assert_eq!(SealedHeader::parse(&packet), None, "首字节 {first:#04x}");
        }
    }
}
