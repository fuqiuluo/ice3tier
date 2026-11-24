//! 骨干矩阵的一行：一个 relay 到其他各个 relay 的延迟、抖动和丢包，加上它自己的状态。
//!
//! 相互可达的 relay 两两保持中转会话并互测链路质量。每个 relay 对自身测得的行数据签名后发送给其上的全部会话节点
//! （含其他 relay）；relay 收到其他 relay 的行后原样转发给自身会话。因此矩阵无需经由 controller 即可送达各节点，
//! 且每一行仅能由其所属 relay 签发，中间 relay 无法篡改他人的行。
//!
//! 同一种帧也是 relay 的通知：relay 过载或者即将下线时，立刻发一行状态变了的。
//!
//! ```text
//! ROW  0x0e | 行的主人 4 | 序号 8 | 状态 1 | 负载 1 | 条数 1 | 条数 × ( relay 4 | 延迟 2 | 抖动 1 | 丢包 1 ) | 签名 64
//! ```
//!
//! 整数都是大端。
//!
//! - **序号**：主人每发一行加大一次（用的是毫秒时间戳，重启之后也不会变小）。收的一方只留每个主人序号最大的那一行，
//!   因此重放旧行无法覆盖新行。
//! - **状态**：见 [`RelayState`]。
//! - **负载**：转发带宽占用了上限的百分之几，超过 255 记 255；没有设上限的 relay 填 0。
//! - **延迟**：毫秒。`0xffff` 表示发起方无法连通该 relay；行中未列出的 relay 同样视为不可达。
//! - **抖动**：毫秒，超过 255 记 255。
//! - **丢包**：单位是 0.5%，200 就是全丢。
//!
//! # 签的是什么
//!
//! 签名由调用方用 `i3t_crypto::NodeKey::sign(用途, 消息)` 来算：用途是 [`Row::PURPOSE`]，消息是帧里签名之前的全部字节
//! （[`Row::signed_part`]）。签名包含所属 relay 编号与序号，因此无法冒充其他 relay，也无法篡改新旧顺序。
//!
//! # 对没有认证过的来源
//!
//! 这种帧只由 relay 主动发给已经建了会话的地址，没有人能用一个请求把它引出来。收的一方只认从自己有会话的 relay 来的，
//! 序号不比手上的新就直接丢掉，之后才去验签名。

use std::time::Duration;

use crate::node::NodeId;
use crate::session::SIGNATURE_LEN;

pub const KIND_ROW: u8 = 0x0e;

/// 一行里最多列多少个 relay。个人用的网络里 relay 是个位数；这个上限让一行始终装得进一个不分片的数据报。
pub const MAX_LINKS: usize = 64;

/// 类型、主人、序号、状态、负载、条数。
const HEAD_LEN: usize = 1 + NodeId::WIRE_LEN + 8 + 3;
/// relay 编号、延迟、抖动、丢包。
const LINK_LEN: usize = NodeId::WIRE_LEN + 2 + 1 + 1;
const UNREACHABLE: u16 = u16::MAX;
/// 丢包这个字节的满刻度：200 个 0.5%。
const LOSS_FULL_SCALE: u8 = 200;

/// relay 现在能不能接新的转发。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayState {
    /// 正常。
    #[default]
    Serving,
    /// 转发的流量到了带宽上限。节点应该改走别的 relay，不用等延迟涨上去再发现。
    Overloaded,
    /// 即将下线（升级、关机、被停用）。节点应该立刻把路径和挂靠换到别处。
    Draining,
}

impl RelayState {
    const fn code(self) -> u8 {
        match self {
            Self::Serving => 0,
            Self::Overloaded => 1,
            Self::Draining => 2,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Serving),
            1 => Some(Self::Overloaded),
            2 => Some(Self::Draining),
            _ => None,
        }
    }
}

/// 一段骨干链路测出来的质量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkQuality {
    /// 往返延迟，毫秒。最大 65534。
    pub rtt_ms: u16,
    /// 抖动，毫秒。
    pub jitter_ms: u8,
    /// 丢包率，单位 0.5%，最大 200。
    pub loss_half_percent: u8,
}

impl LinkQuality {
    /// 把测量值换成线上的刻度，超出范围的取边界值。丢包率是 `probes` 个探测里丢了 `lost` 个。
    #[must_use]
    pub fn from_measured(rtt: Duration, jitter: Duration, lost: usize, probes: usize) -> Self {
        let millis = |value: Duration| (value.as_micros() + 500) / 1000;
        let loss = (lost.min(probes) * usize::from(LOSS_FULL_SCALE) + probes / 2).checked_div(probes).unwrap_or(0);
        Self {
            // 不到 1 毫秒的延迟记 1，免得和"没有测到"混淆。
            rtt_ms: u16::try_from(millis(rtt)).unwrap_or(u16::MAX).clamp(1, UNREACHABLE - 1),
            jitter_ms: u8::try_from(millis(jitter)).unwrap_or(u8::MAX),
            loss_half_percent: u8::try_from(loss).unwrap_or(LOSS_FULL_SCALE),
        }
    }

    /// 丢包率，0 到 1 之间。
    #[must_use]
    pub fn loss(self) -> f64 {
        f64::from(self.loss_half_percent.min(LOSS_FULL_SCALE)) / f64::from(LOSS_FULL_SCALE)
    }
}

/// 行里的一条：主人到某个 relay 的链路。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub relay: NodeId,
    /// `None` 表示所属 relay 无法连通该目标。
    pub quality: Option<LinkQuality>,
}

/// 骨干矩阵的一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// 这一行是哪个 relay 测的、签的。
    pub origin: NodeId,
    pub seq: u64,
    pub state: RelayState,
    /// 带宽占用的百分比，见模块文档。
    pub load_percent: u8,
    pub links: Vec<Link>,
}

impl Row {
    /// 签名的用途标签。
    pub const PURPOSE: &str = "backbone-row";
    /// 帧最长多少字节。
    pub const MAX_LEN: usize = HEAD_LEN + MAX_LINKS * LINK_LEN + SIGNATURE_LEN;

    /// 帧里签名之前的部分，也就是要签的消息。超过 [`MAX_LINKS`] 条的链路不写进去。
    #[must_use]
    pub fn to_unsigned_bytes(&self) -> Vec<u8> {
        let links = &self.links[..self.links.len().min(MAX_LINKS)];
        let mut bytes = Vec::with_capacity(HEAD_LEN + links.len() * LINK_LEN + SIGNATURE_LEN);
        bytes.push(KIND_ROW);
        bytes.extend_from_slice(&self.origin.to_be_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.push(self.state.code());
        bytes.push(self.load_percent);
        bytes.push(u8::try_from(links.len()).expect("链路数不超过 MAX_LINKS，装得进一个字节"));
        for link in links {
            bytes.extend_from_slice(&link.relay.to_be_bytes());
            let (rtt, jitter, loss) = match link.quality {
                Some(quality) => (quality.rtt_ms.min(UNREACHABLE - 1), quality.jitter_ms, quality.loss_half_percent.min(LOSS_FULL_SCALE)),
                None => (UNREACHABLE, 0, 0),
            };
            bytes.extend_from_slice(&rtt.to_be_bytes());
            bytes.push(jitter);
            bytes.push(loss);
        }
        bytes
    }

    /// 完整的帧：[`to_unsigned_bytes`](Self::to_unsigned_bytes) 后面跟上主人对它的签名。
    #[must_use]
    pub fn to_bytes(&self, signature: &[u8; SIGNATURE_LEN]) -> Vec<u8> {
        let mut bytes = self.to_unsigned_bytes();
        bytes.extend_from_slice(signature);
        bytes
    }

    /// 首字节是 [`KIND_ROW`] 的数据报是不是一个长度对得上的行帧。只做算术，不看内容。
    #[must_use]
    pub fn is_complete(datagram: &[u8]) -> bool {
        datagram.get(HEAD_LEN - 1).is_some_and(|&count| {
            usize::from(count) <= MAX_LINKS && datagram.len() == HEAD_LEN + usize::from(count) * LINK_LEN + SIGNATURE_LEN
        })
    }

    /// 帧中参与验签的字节区间。帧不完整时返回 `None`。
    #[must_use]
    pub fn signed_part(datagram: &[u8]) -> Option<&[u8]> {
        Self::is_complete(datagram).then(|| &datagram[..datagram.len() - SIGNATURE_LEN])
    }

    /// 只取出主人和序号。收的一方先用它判断这一行是不是比手上的新，是才值得解析全部内容、验签名。
    #[must_use]
    pub fn peek(datagram: &[u8]) -> Option<(NodeId, u64)> {
        let (&[KIND_ROW], rest) = datagram.split_first_chunk::<1>()? else { return None };
        let (&origin, rest) = rest.split_first_chunk::<{ NodeId::WIRE_LEN }>()?;
        let (&seq, _) = rest.split_first_chunk::<8>()?;
        Some((NodeId::from_be_bytes(origin)?, u64::from_be_bytes(seq)))
    }

    /// 解析一帧，返回行的内容和签名。只看格式，签名由收的一方去验。
    ///
    /// 帧不完整、状态码未知、包含为 0 的节点编号、包含自身或重复列出同一 relay 时返回 `None`。
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Option<(Self, [u8; SIGNATURE_LEN])> {
        if !Self::is_complete(datagram) {
            return None;
        }
        let (origin, seq) = Self::peek(datagram)?;
        let (body, signature) = datagram.split_last_chunk::<SIGNATURE_LEN>()?;
        let (head, list) = body.split_at_checked(HEAD_LEN)?;
        let &[.., state, load_percent, _count] = head else { return None };
        let mut links = Vec::with_capacity(list.len() / LINK_LEN);
        for &[r0, r1, r2, r3, hi, lo, jitter_ms, loss_half_percent] in list.as_chunks::<LINK_LEN>().0 {
            let relay = NodeId::from_be_bytes([r0, r1, r2, r3])?;
            if relay == origin || links.iter().any(|link: &Link| link.relay == relay) || loss_half_percent > LOSS_FULL_SCALE {
                return None;
            }
            let quality = match u16::from_be_bytes([hi, lo]) {
                UNREACHABLE => None,
                rtt_ms => Some(LinkQuality { rtt_ms, jitter_ms, loss_half_percent }),
            };
            links.push(Link { relay, quality });
        }
        Some((Self { origin, seq, state: RelayState::from_code(state)?, load_percent, links }, *signature))
    }
}

const _: () = {
    // 最长的一行加上 UDP 和 IPv6 的头也装得进最小的 IPv6 链路（1280），不会被分片。
    assert!(Row::MAX_LEN + 48 <= 1280);
    assert!(MAX_LINKS <= u8::MAX as usize);
};

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNATURE: [u8; SIGNATURE_LEN] = [0x5a; SIGNATURE_LEN];

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    fn row() -> Row {
        Row {
            origin: node(0x0a0b_0c0d),
            seq: 0x0102_0304_0506_0708,
            state: RelayState::Overloaded,
            load_percent: 93,
            links: vec![
                Link { relay: node(7), quality: Some(LinkQuality { rtt_ms: 140, jitter_ms: 3, loss_half_percent: 1 }) },
                Link { relay: node(8), quality: None },
            ],
        }
    }

    #[test]
    fn a_row_has_the_documented_layout_and_round_trips() {
        let bytes = row().to_bytes(&SIGNATURE);
        assert_eq!(&bytes[..16], [0x0e, 0x0a, 0x0b, 0x0c, 0x0d, 1, 2, 3, 4, 5, 6, 7, 8, 1, 93, 2]);
        assert_eq!(&bytes[16..24], [0, 0, 0, 7, 0, 140, 3, 1]);
        assert_eq!(&bytes[24..32], [0, 0, 0, 8, 0xff, 0xff, 0, 0], "连不上的 relay 延迟写成 0xffff");
        assert_eq!(&bytes[32..], SIGNATURE);
        assert!(Row::is_complete(&bytes));
        assert_eq!(Row::peek(&bytes), Some((node(0x0a0b_0c0d), 0x0102_0304_0506_0708)));
        assert_eq!(Row::signed_part(&bytes), Some(&bytes[..32]));
        assert_eq!(Row::signed_part(&bytes), Some(&row().to_unsigned_bytes()[..]));
        assert_eq!(Row::parse(&bytes), Some((row(), SIGNATURE)));
    }

    #[test]
    fn a_row_without_links_is_a_bare_notice() {
        let notice = Row { state: RelayState::Draining, links: Vec::new(), ..row() };
        let bytes = notice.to_bytes(&SIGNATURE);
        assert_eq!(bytes.len(), 16 + SIGNATURE_LEN);
        assert_eq!(Row::parse(&bytes), Some((notice, SIGNATURE)));
    }

    #[test]
    fn frames_whose_length_does_not_match_the_link_count_are_rejected() {
        let bytes = row().to_bytes(&SIGNATURE);
        assert!(!Row::is_complete(&bytes[..bytes.len() - 1]));
        assert!(!Row::is_complete(&[&bytes[..], &[0]].concat()));
        assert!(!Row::is_complete(&bytes[..10]));
        assert!(!Row::is_complete(&[]));
        let mut wrong_count = bytes.clone();
        wrong_count[15] = 3;
        assert!(!Row::is_complete(&wrong_count));
        assert_eq!(Row::parse(&wrong_count), None);
        assert_eq!(Row::signed_part(&wrong_count), None);
        let mut too_many = vec![0x0e; HEAD_LEN + 65 * LINK_LEN + SIGNATURE_LEN];
        too_many[15] = 65;
        assert!(!Row::is_complete(&too_many), "条数超过上限");
    }

    #[test]
    fn hostile_contents_are_rejected() {
        let tamper = |edit: fn(&mut Vec<u8>)| {
            let mut bytes = row().to_bytes(&SIGNATURE);
            edit(&mut bytes);
            Row::parse(&bytes)
        };
        assert_eq!(tamper(|bytes| bytes[13] = 9), None, "不认识的状态");
        assert_eq!(tamper(|bytes| bytes[1..5].fill(0)), None, "主人的编号是 0");
        assert_eq!(tamper(|bytes| bytes[16..20].fill(0)), None, "链路里的编号是 0");
        assert_eq!(tamper(|bytes| bytes[24..28].copy_from_slice(&[0, 0, 0, 7])), None, "同一个 relay 列了两次");
        assert_eq!(tamper(|bytes| bytes[16..20].copy_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d])), None, "主人把自己列了进去");
        assert_eq!(tamper(|bytes| bytes[23] = 201), None, "丢包超过满刻度");
        assert_eq!(tamper(|bytes| bytes[0] = 0x0d).map(|(row, _)| row.origin), None, "别的类型");
    }

    #[test]
    fn links_beyond_the_limit_are_left_out() {
        let links = (1..=100).map(|id| Link { relay: node(id), quality: None }).collect();
        let bytes = Row { origin: node(1000), links, ..row() }.to_bytes(&SIGNATURE);
        assert_eq!(bytes.len(), Row::MAX_LEN);
        let (parsed, _) = Row::parse(&bytes).unwrap();
        assert_eq!(parsed.links.len(), MAX_LINKS);
    }

    #[test]
    fn measurements_are_rounded_and_clamped_to_the_wire_scale() {
        let quality = LinkQuality::from_measured(Duration::from_micros(139_600), Duration::from_micros(2_400), 1, 250);
        assert_eq!(quality, LinkQuality { rtt_ms: 140, jitter_ms: 2, loss_half_percent: 1 });
        assert!((quality.loss() - 0.005).abs() < 1e-9);

        let extreme = LinkQuality::from_measured(Duration::from_secs(1000), Duration::from_secs(1000), 70, 10);
        assert_eq!(extreme, LinkQuality { rtt_ms: 65534, jitter_ms: 255, loss_half_percent: 200 });
        assert!((extreme.loss() - 1.0).abs() < 1e-9);

        let tiny = LinkQuality::from_measured(Duration::from_micros(200), Duration::ZERO, 0, 0);
        assert_eq!(tiny, LinkQuality { rtt_ms: 1, jitter_ms: 0, loss_half_percent: 0 }, "不到 1 毫秒的延迟记 1；没有探测过就没有丢包");
    }
}
