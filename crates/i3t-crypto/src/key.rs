//! 节点密钥与签名。

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use i3t_proto::PublicKey;
use ring::hkdf;
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

const PEM_HEADER: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_FOOTER: &str = "-----END PRIVATE KEY-----";
const PEM_LINE_LEN: usize = 64;

/// 所有签名共用的前缀，后面跟用途标签。同一把密钥在不同场合签出来的东西因此不能互相冒充。
const SIGNATURE_PREFIX: &[u8] = b"i3t-signature-v1";
/// 从私钥派生别的密钥时用的盐，和签名的前缀是两回事。
const DERIVE_SALT: &[u8] = b"i3t-derived-secret-v1";

/// [`NodeKey::derive_secret`] 给出的密钥的长度。
pub const DERIVED_SECRET_LEN: usize = 32;

/// 让 HKDF 输出 [`DERIVED_SECRET_LEN`] 字节。
struct DerivedLen;

impl hkdf::KeyType for DerivedLen {
    fn len(&self) -> usize {
        DERIVED_SECRET_LEN
    }
}

/// 节点的 Ed25519 私钥。私钥不离开节点，除了写进本机的密钥文件之外不导出。
pub struct NodeKey {
    pair: Ed25519KeyPair,
    pkcs8: Box<[u8]>,
}

impl NodeKey {
    /// # Errors
    ///
    /// 系统的随机数源不可用。
    pub fn generate() -> Result<Self, KeyError> {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| KeyError::Random)?;
        Self::from_pkcs8_der(document.as_ref())
    }

    /// # Errors
    ///
    /// `der` 不是一把 Ed25519 私钥的 PKCS#8 编码。
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, KeyError> {
        // 别的工具生成的 PKCS#8 可能不带公钥部分，所以用宽松的那个解析函数。
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der).map_err(|_| KeyError::NotEd25519Pkcs8)?;
        Ok(Self { pair, pkcs8: der.into() })
    }

    /// 从密钥文件的内容读出私钥。
    ///
    /// # Errors
    ///
    /// 不是 `PRIVATE KEY` 的 PEM，或者里面不是 Ed25519 私钥。
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        let body = pem.trim().strip_prefix(PEM_HEADER).and_then(|rest| rest.strip_suffix(PEM_FOOTER)).ok_or(KeyError::NotPem)?;
        let base64: String = body.split_whitespace().collect();
        let der = STANDARD.decode(base64).map_err(|_| KeyError::NotPem)?;
        Self::from_pkcs8_der(&der)
    }

    /// 密钥文件的内容：PKCS#8 的 PEM。写文件时由调用方把权限设成只有属主可读。
    #[must_use]
    pub fn to_pem(&self) -> String {
        let base64 = STANDARD.encode(&self.pkcs8);
        let mut pem = String::with_capacity(base64.len() + base64.len() / PEM_LINE_LEN + PEM_HEADER.len() + PEM_FOOTER.len() + 4);
        pem.push_str(PEM_HEADER);
        pem.push('\n');
        // base64 的输出是 ASCII，按字节切不会切坏字符。
        for line in base64.as_bytes().chunks(PEM_LINE_LEN) {
            pem.extend(line.iter().map(|&byte| char::from(byte)));
            pem.push('\n');
        }
        pem.push_str(PEM_FOOTER);
        pem.push('\n');
        pem
    }

    #[must_use]
    pub fn public(&self) -> PublicKey {
        let bytes: [u8; PublicKey::LEN] = self.pair.public_key().as_ref().try_into().expect("Ed25519 公钥固定是 32 字节，这是算法的定义");
        PublicKey::from_bytes(bytes)
    }

    /// 给 `message` 签名。`purpose` 说明这个签名用在哪里（例如 `"relay-session"`），验证时必须给出同一个标签。
    #[must_use]
    pub fn sign(&self, purpose: &str, message: &[u8]) -> Signature {
        let signature = self.pair.sign(&signed_bytes(purpose, message));
        let bytes: [u8; Signature::LEN] = signature.as_ref().try_into().expect("Ed25519 签名固定是 64 字节，这是算法的定义");
        Signature(bytes)
    }

    /// 原样给 `message` 签名，不加前缀和用途标签：签名的格式由别的规范定死时用（JWT 的 `EdDSA`，RFC 8037）。
    ///
    /// 只给专门做这一件事的密钥用。同一把密钥又拿去 [`sign`](Self::sign) 的话，这里签出来的东西没有用途标签隔着，
    /// 所以节点密钥和 controller 的密钥都不这样用。
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        let signature = self.pair.sign(message);
        let bytes: [u8; Signature::LEN] = signature.as_ref().try_into().expect("Ed25519 签名固定是 64 字节，这是算法的定义");
        Signature(bytes)
    }

    /// 从私钥派生一把对称密钥。同一把私钥、同一个 `purpose` 每次得到的都一样，不同的 `purpose` 互不相干，
    /// 知道其中一把也推不出私钥和别的。
    ///
    /// 给那些"重启之后还得是同一把"的密钥用：没有它就得另存一个文件，丢了、和私钥不配套了都是麻烦。
    #[must_use]
    pub fn derive_secret(&self, purpose: &str) -> [u8; DERIVED_SECRET_LEN] {
        let mut secret = [0; DERIVED_SECRET_LEN];
        hkdf::Salt::new(hkdf::HKDF_SHA256, DERIVE_SALT)
            .extract(&self.pkcs8)
            .expand(&[purpose.as_bytes()], DerivedLen)
            .and_then(|key| key.fill(&mut secret))
            .expect("HKDF-SHA256 输出 32 字节总是可以的：上限是 255 个哈希长度");
        secret
    }

    pub(crate) fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }
}

/// 私钥不能出现在日志里。
impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeKey").field("public", &self.public()).finish_non_exhaustive()
    }
}

/// 一个 Ed25519 签名。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; Self::LEN]);

impl Signature {
    pub const LEN: usize = 64;

    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({:02x}{:02x}{:02x}{:02x}…)", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// 验证 `signature` 是 `key` 的主人以 `purpose` 这个用途对 `message` 签的。
///
/// # Errors
///
/// 签名不对：消息被改过、用途标签不同，或者不是这把密钥签的。
pub fn verify(key: &PublicKey, purpose: &str, message: &[u8], signature: &Signature) -> Result<(), BadSignature> {
    UnparsedPublicKey::new(&ED25519, key.as_bytes()).verify(&signed_bytes(purpose, message), signature.as_bytes()).map_err(|_| BadSignature)
}

/// 验证 `signature` 是 `key` 的主人原样对 `message` 签的（[`NodeKey::sign_raw`]）。
///
/// # Errors
///
/// 签名不对：消息被改过，或者不是这把密钥签的。
pub fn verify_raw(key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), BadSignature> {
    UnparsedPublicKey::new(&ED25519, key.as_bytes()).verify(message, signature.as_bytes()).map_err(|_| BadSignature)
}

/// 真正被签名的字节：固定前缀、用途标签的长度和内容、消息。标签带长度，所以"标签 + 消息"的拼接没有歧义。
fn signed_bytes(purpose: &str, message: &[u8]) -> Vec<u8> {
    let purpose_len = u8::try_from(purpose.len()).expect("用途标签是代码里写死的短字符串，不会超过 255 字节");
    let mut bytes = Vec::with_capacity(SIGNATURE_PREFIX.len() + 1 + purpose.len() + message.len());
    bytes.extend_from_slice(SIGNATURE_PREFIX);
    bytes.push(purpose_len);
    bytes.extend_from_slice(purpose.as_bytes());
    bytes.extend_from_slice(message);
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("系统的随机数源不可用")]
    Random,
    #[error("不是 PRIVATE KEY 类型的 PEM")]
    NotPem,
    #[error("不是 Ed25519 私钥的 PKCS#8 编码")]
    NotEd25519Pkcs8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("签名验证不通过")]
pub struct BadSignature;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_verifies_only_with_the_same_key_purpose_and_message() {
        let key = NodeKey::generate().unwrap();
        let other = NodeKey::generate().unwrap();
        let signature = key.sign("probe", b"hello");
        assert_eq!(verify(&key.public(), "probe", b"hello", &signature), Ok(()));
        assert_eq!(verify(&other.public(), "probe", b"hello", &signature), Err(BadSignature));
        assert_eq!(verify(&key.public(), "relay-session", b"hello", &signature), Err(BadSignature));
        assert_eq!(verify(&key.public(), "probe", b"hello!", &signature), Err(BadSignature));
    }

    #[test]
    fn a_raw_signature_verifies_only_as_raw_with_the_same_key_and_message() {
        let key = NodeKey::generate().unwrap();
        let other = NodeKey::generate().unwrap();
        let signature = key.sign_raw(b"header.payload");
        assert_eq!(verify_raw(&key.public(), b"header.payload", &signature), Ok(()));
        assert_eq!(verify_raw(&other.public(), b"header.payload", &signature), Err(BadSignature));
        assert_eq!(verify_raw(&key.public(), b"header.payloae", &signature), Err(BadSignature));
        // 带用途的签名和原样的签名互不相认。
        assert_eq!(verify(&key.public(), "jwt", b"header.payload", &signature), Err(BadSignature));
        assert_eq!(verify_raw(&key.public(), b"header.payload", &key.sign("jwt", b"header.payload")), Err(BadSignature));
    }

    #[test]
    fn purpose_and_message_cannot_be_shifted_into_each_other() {
        let key = NodeKey::generate().unwrap();
        let signature = key.sign("ab", b"c");
        assert_eq!(verify(&key.public(), "a", b"bc", &signature), Err(BadSignature));
    }

    #[test]
    fn key_file_round_trips() {
        let key = NodeKey::generate().unwrap();
        let pem = key.to_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n") && pem.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(pem.lines().all(|line| line.len() <= PEM_LINE_LEN));
        let restored = NodeKey::from_pem(&pem).unwrap();
        assert_eq!(restored.public(), key.public());
        assert_eq!(verify(&key.public(), "x", b"m", &restored.sign("x", b"m")), Ok(()));
    }

    #[test]
    fn garbage_is_not_a_key() {
        assert_eq!(NodeKey::from_pem("hello").unwrap_err(), KeyError::NotPem);
        assert_eq!(NodeKey::from_pem(&format!("{PEM_HEADER}\n!!!\n{PEM_FOOTER}\n")).unwrap_err(), KeyError::NotPem);
        assert_eq!(NodeKey::from_pem(&format!("{PEM_HEADER}\nAAAA\n{PEM_FOOTER}\n")).unwrap_err(), KeyError::NotEd25519Pkcs8);
    }

    #[test]
    fn debug_output_does_not_contain_the_private_key() {
        let key = NodeKey::generate().unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("PublicKey("), "{debug}");
        assert!(!debug.contains("pkcs8"), "{debug}");
    }

    #[test]
    fn derived_secrets_are_stable_per_purpose_and_differ_between_purposes_and_keys() {
        let key = NodeKey::generate().unwrap();
        let reloaded = NodeKey::from_pem(&key.to_pem()).unwrap();
        assert_eq!(key.derive_secret("a"), reloaded.derive_secret("a"), "同一把私钥重新读进来，派生出的还是同一把");
        assert_ne!(key.derive_secret("a"), key.derive_secret("b"));
        assert_ne!(key.derive_secret("a"), NodeKey::generate().unwrap().derive_secret("a"));
    }
}
