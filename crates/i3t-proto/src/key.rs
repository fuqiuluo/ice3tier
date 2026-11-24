//! 节点公钥。

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// 节点的 Ed25519 公钥，节点身份的根。
///
/// 文本形式是不带填充的 base64url，43 个字符，可以直接放进 URL、JSON 和命令行。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; Self::LEN]);

impl PublicKey {
    pub const LEN: usize = 32;

    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// 日志里只需要认得出是哪一把，所以只打前 8 个字符。
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = URL_SAFE_NO_PAD.encode(self.0);
        write!(f, "PublicKey({}…)", &text[..8])
    }
}

/// 一段文本不是合法的公钥。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error("公钥不是有效的 base64url：{0}")]
    Encoding(#[from] base64::DecodeError),
    #[error("公钥长度应为 {expected} 字节，解码后实际为 {actual} 字节", expected = PublicKey::LEN)]
    Length { actual: usize },
}

impl FromStr for PublicKey {
    type Err = InvalidPublicKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD.decode(s)?;
        let bytes: [u8; Self::LEN] = bytes.try_into().map_err(|rest: Vec<u8>| InvalidPublicKey::Length { actual: rest.len() })?;
        Ok(Self(bytes))
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_round_trips() {
        let key = PublicKey::from_bytes([0xab; 32]);
        let text = key.to_string();
        assert_eq!(text.len(), 43);
        assert_eq!(text.parse::<PublicKey>(), Ok(key));
        assert_eq!(format!("{key:?}"), format!("PublicKey({}…)", &text[..8]));
    }

    #[test]
    fn wrong_length_and_bad_characters_are_rejected() {
        assert_eq!("AAAA".parse::<PublicKey>(), Err(InvalidPublicKey::Length { actual: 3 }));
        assert!(matches!("not base64!".parse::<PublicKey>(), Err(InvalidPublicKey::Encoding(_))));
    }

    #[test]
    fn json_form_is_the_text_form() {
        let key = PublicKey::from_bytes([7; 32]);
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, format!("\"{key}\""));
        assert_eq!(serde_json::from_str::<PublicKey>(&json).unwrap(), key);
    }
}
