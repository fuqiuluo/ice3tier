//! 局域网发现的信标。
//!
//! 节点定期向本地网段的一个组播地址发信标，同一个网络里的对端收到之后，把"信标的来源 IP + 信标里的端口"
//! 当作这个对端的一个直连候选地址。候选地址照样要用带签名的探测验证过才会用（[`crate::probe`]），
//! 所以信标本身不需要签名：伪造一个信标最多让收的一方多发几个探测包。
//!
//! ```text
//! 0x69 0x33 0x74 0x01 | 端口 2 | 盐 8 | 标签 16                      30 字节
//! ```
//!
//! 开头四个字节是固定的标记和版本。端口是发信标的节点收包用的那个 UDP 端口（大端）。
//!
//! 标签是 `HMAC-SHA256(密钥 = 发信标的节点的公钥, 消息 = 盐 ‖ 端口)` 的前 16 个字节，由调用方来算
//! （这个 crate 不依赖密码学库），要算的消息由 [`Beacon::tag_message`] 给出。盐每个信标换一次。
//!
//! 因此信标中不含固定标识：未知公钥者无法识别发送方，也无法将前后两个信标关联至同一主机；
//! 知道公钥的人（同一个网络里、netmap 里有它的对端）拿自己知道的每一把公钥各算一遍，对上了就认出来了。
//! 信标不带节点名、网络名、虚拟地址，泄露的不比一把公钥本来就泄露的多。

/// 信标开头的标记（"i3t"）和版本号。
const MAGIC: [u8; 4] = [0x69, 0x33, 0x74, 0x01];

pub const SALT_LEN: usize = 8;
pub const TAG_LEN: usize = 16;

/// 一个局域网信标。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beacon {
    /// 发信标的节点收包用的 UDP 端口。
    pub port: u16,
    pub salt: [u8; SALT_LEN],
    /// 见模块文档。
    pub tag: [u8; TAG_LEN],
}

impl Beacon {
    pub const LEN: usize = MAGIC.len() + 2 + SALT_LEN + TAG_LEN;

    /// 算标签时要认证的消息：盐后面跟着端口。
    #[must_use]
    pub fn tag_message(salt: &[u8; SALT_LEN], port: u16) -> [u8; SALT_LEN + 2] {
        let mut message = [0; SALT_LEN + 2];
        message[..SALT_LEN].copy_from_slice(salt);
        message[SALT_LEN..].copy_from_slice(&port.to_be_bytes());
        message
    }

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        let (magic, rest) = bytes.split_at_mut(MAGIC.len());
        magic.copy_from_slice(&MAGIC);
        rest[..2].copy_from_slice(&self.port.to_be_bytes());
        rest[2..2 + SALT_LEN].copy_from_slice(&self.salt);
        rest[2 + SALT_LEN..].copy_from_slice(&self.tag);
        bytes
    }

    /// 不是一个信标（标记或者版本不对、长度不对、端口是 0）时返回 `None`。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let bytes: &[u8; Self::LEN] = datagram.try_into().ok()?;
        let (magic, rest) = bytes.split_first_chunk::<{ MAGIC.len() }>()?;
        let (&port, rest) = rest.split_first_chunk::<2>()?;
        let (&salt, tag) = rest.split_first_chunk::<SALT_LEN>()?;
        let port = u16::from_be_bytes(port);
        (*magic == MAGIC && port != 0).then_some(Self { port, salt, tag: *tag.first_chunk::<TAG_LEN>()? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon() -> Beacon {
        Beacon { port: 20330, salt: [1, 2, 3, 4, 5, 6, 7, 8], tag: [0xa5; TAG_LEN] }
    }

    #[test]
    fn a_beacon_has_the_documented_layout_and_round_trips() {
        let bytes = beacon().to_bytes();
        assert_eq!(bytes.len(), 30);
        assert_eq!(&bytes[..6], [0x69, 0x33, 0x74, 0x01, 0x4f, 0x6a]);
        assert_eq!(&bytes[6..14], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[14..], [0xa5; TAG_LEN]);
        assert_eq!(Beacon::parse(&bytes), Some(beacon()));
    }

    #[test]
    fn the_tag_covers_the_salt_and_the_port() {
        let message = Beacon::tag_message(&[1, 2, 3, 4, 5, 6, 7, 8], 20330);
        assert_eq!(message, [1, 2, 3, 4, 5, 6, 7, 8, 0x4f, 0x6a]);
        assert_ne!(message, Beacon::tag_message(&[1, 2, 3, 4, 5, 6, 7, 8], 20331));
        assert_ne!(message, Beacon::tag_message(&[9, 2, 3, 4, 5, 6, 7, 8], 20330));
    }

    #[test]
    fn anything_that_is_not_exactly_a_beacon_is_ignored() {
        let bytes = beacon().to_bytes();
        assert_eq!(Beacon::parse(&bytes[..29]), None);
        assert_eq!(Beacon::parse(&[&bytes[..], &[0]].concat()), None);
        assert_eq!(Beacon::parse(&[]), None);
        let mut other_version = bytes;
        other_version[3] = 2;
        assert_eq!(Beacon::parse(&other_version), None, "别的版本");
        let mut zero_port = bytes;
        zero_port[4..6].fill(0);
        assert_eq!(Beacon::parse(&zero_port), None, "端口是 0 的没法用");
        // 同一个组播地址上别的程序发的东西。
        assert_eq!(Beacon::parse(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255"), None);
    }
}
