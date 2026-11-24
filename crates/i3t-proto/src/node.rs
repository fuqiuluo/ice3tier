//! 节点编号。

use std::fmt;
use std::num::{NonZeroU32, ParseIntError};
use std::str::FromStr;

/// 节点在一个网络里的编号。
///
/// controller 在节点注册时分配，从 1 开始，网络内唯一。它只在协议内部使用：中转头靠它指明包要去哪个节点。
/// 使用者看到的是虚拟 IP 和名字。0 不是合法的编号，留给"没有"这个含义，所以解析时会被拒绝。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(NonZeroU32);

impl NodeId {
    /// 编码之后占的字节数。
    pub const WIRE_LEN: usize = 4;

    /// `raw` 为 0 时返回 `None`。
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// 线上的编码：4 字节大端。
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; Self::WIRE_LEN] {
        self.0.get().to_be_bytes()
    }

    /// 全 0 时返回 `None`。
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; Self::WIRE_LEN]) -> Option<Self> {
        Self::new(u32::from_be_bytes(bytes))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.0)
    }
}

impl From<NodeId> for u32 {
    fn from(id: NodeId) -> Self {
        id.get()
    }
}

/// 把一个整数当作节点编号时出的错。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidNodeId {
    #[error("节点编号不能为 0")]
    Zero,
    #[error("节点编号不是 1 到 4294967295 之间的整数：{0}")]
    NotANumber(#[from] ParseIntError),
}

impl TryFrom<u32> for NodeId {
    type Error = InvalidNodeId;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        Self::new(raw).ok_or(InvalidNodeId::Zero)
    }
}

impl FromStr for NodeId {
    type Err = InvalidNodeId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.parse::<u32>()?)
    }
}

impl serde::Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.get())
    }
}

impl<'de> serde::Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <u32 as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_rejected_everywhere() {
        assert_eq!(NodeId::new(0), None);
        assert_eq!(NodeId::from_be_bytes([0; 4]), None);
        assert_eq!(NodeId::try_from(0), Err(InvalidNodeId::Zero));
        assert_eq!("0".parse::<NodeId>(), Err(InvalidNodeId::Zero));
    }

    #[test]
    fn wire_encoding_is_big_endian_and_round_trips() {
        let id = NodeId::new(0x0102_0304).unwrap();
        assert_eq!(id.to_be_bytes(), [1, 2, 3, 4]);
        assert_eq!(NodeId::from_be_bytes([1, 2, 3, 4]), Some(id));
    }

    #[test]
    fn text_form_round_trips() {
        let id: NodeId = "258".parse().unwrap();
        assert_eq!(id.get(), 258);
        assert_eq!(id.to_string(), "258");
        assert_eq!(format!("{id:?}"), "NodeId(258)");
        assert!(matches!("abc".parse::<NodeId>(), Err(InvalidNodeId::NotANumber(_))));
        assert!(matches!("4294967296".parse::<NodeId>(), Err(InvalidNodeId::NotANumber(_))));
    }

    #[test]
    fn json_form_is_a_plain_number() {
        let id = NodeId::new(7).unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), "7");
        assert_eq!(serde_json::from_str::<NodeId>("7").unwrap(), id);
        assert!(serde_json::from_str::<NodeId>("0").is_err());
    }
}
