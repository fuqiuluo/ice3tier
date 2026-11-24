//! 发布清单签名信任链：受信任公钥配置、清单签名与验签。

use i3t_crypto::{NodeKey, Signature};
use i3t_model::update::{Manifest, ManifestSignature, SignedManifest};
use i3t_proto::PublicKey;

use crate::error::ManifestError;

/// 清单签名的用途标签（domain separation）。即使发布私钥用于其他用途的签名，也无法冒充发布清单，反之亦然。
pub const MANIFEST_PURPOSE: &str = "release-manifest";

/// 项目内置的发布公钥。轮换密钥时应先加入新公钥发布过渡版本，待节点全部升级后再移除旧公钥。
const PROJECT_KEYS: [[u8; PublicKey::LEN]; 1] = [decode_key("kWB8NBoJtLGX7mZwXgMSZ1C8RkUDpkdOphusy_JhEk0")];

/// 编译时通过环境变量 `I3T_RELEASE_EXTRA_KEY` 额外注入的发布公钥（base64url）。
/// 供测试或自行构建发布时使用：无项目私钥时可编译信任自有公钥。
/// 环境变量格式错误会在编译期直接报错，不会静默失效。
const EXTRA_KEY: Option<[u8; PublicKey::LEN]> = match option_env!("I3T_RELEASE_EXTRA_KEY") {
    Some(text) if !text.is_empty() => Some(decode_key(text)),
    _ => None,
};

/// 在编译期解码单个公钥：43 字符无填充 base64url，对应 32 字节原始公钥。
///
/// 未使用 `base64` crate 是为了在 `const fn` 中完成解码，使配置错误的公钥在编译期即被发现，而非运行时才导致更新失败。
///
/// # Panics
///
/// `text` 不是合法公钥时触发 panic；由于仅在编译期求值，表现为编译错误。
const fn decode_key(text: &str) -> [u8; PublicKey::LEN] {
    let text = text.as_bytes();
    assert!(text.len() == 43, "发布公钥必须是 43 字符的无填充 base64url 编码（32 字节）");
    let mut key = [0; PublicKey::LEN];
    let mut written = 0;
    let mut bits: u32 = 0;
    let mut pending_bits = 0;
    let mut index = 0;
    while index < text.len() {
        let sextet = match text[index] {
            letter @ b'A'..=b'Z' => letter - b'A',
            letter @ b'a'..=b'z' => letter - b'a' + 26,
            digit @ b'0'..=b'9' => digit - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("发布公钥包含非法的 base64url 字符"),
        };
        // 仅保留尚未输出的低位比特，避免左移溢出。此处使用 `as` 做无损拓宽（常量函数中暂不可用 `From`）。
        bits = ((bits << 6) | sextet as u32) & 0x3fff;
        pending_bits += 6;
        if pending_bits >= 8 {
            pending_bits -= 8;
            key[written] = (bits >> pending_bits).to_le_bytes()[0];
            written += 1;
        }
        index += 1;
    }
    assert!(bits & 0b11 == 0, "发布公钥末尾字符的剩余 2 位填充必须为 0");
    key
}

/// 节点信任的发布公钥集合。
///
/// 节点程序仅使用 [`TrustedKeys::compiled_in`]：公钥在编译期固化，运行时无法通过任何配置、命令或 controller 消息新增或替换。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKeys {
    keys: Vec<PublicKey>,
}

impl TrustedKeys {
    /// 返回编译内置的受信任公钥：包含项目发布公钥，以及编译时通过 `I3T_RELEASE_EXTRA_KEY` 指定的额外公钥（如有）。
    #[must_use]
    pub fn compiled_in() -> Self {
        Self { keys: PROJECT_KEYS.iter().chain(&EXTRA_KEY).copied().map(PublicKey::from_bytes).collect() }
    }

    pub fn iter(&self) -> impl Iterator<Item = &PublicKey> {
        self.keys.iter()
    }

    /// 先校验签名，通过后再解析清单内容。未经签名验证的字节不会被反序列化。
    ///
    /// # Errors
    ///
    /// 签名与任一受信任公钥均不匹配，或签名有效但内容无法解析为合法清单时返回错误。
    pub fn verify(&self, signed: &SignedManifest) -> Result<Manifest, ManifestError> {
        let signature = Signature::from_bytes(*signed.signature.as_bytes());
        let text = signed.manifest.as_bytes();
        if !self.keys.iter().any(|key| i3t_crypto::verify(key, MANIFEST_PURPOSE, text, &signature).is_ok()) {
            return Err(ManifestError::BadSignature);
        }
        serde_json::from_slice(text).map_err(ManifestError::Malformed)
    }
}

/// 构造仅信任单把公钥的集合。供发布工具校验刚生成的清单使用，节点程序不走该路径。
impl From<PublicKey> for TrustedKeys {
    fn from(key: PublicKey) -> Self {
        Self { keys: vec![key] }
    }
}

/// 对发布清单原文签名。签名后的 `manifest` 字节内容不得再做任何修改。
#[must_use]
pub fn sign_manifest(key: &NodeKey, manifest: String) -> SignedManifest {
    let signature = key.sign(MANIFEST_PURPOSE, manifest.as_bytes());
    SignedManifest { manifest, signature: ManifestSignature::from_bytes(*signature.as_bytes()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_time_key_decoding_agrees_with_the_runtime_parser() {
        for text in [
            "kWB8NBoJtLGX7mZwXgMSZ1C8RkUDpkdOphusy_JhEk0",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-8",
        ] {
            assert_eq!(PublicKey::from_bytes(decode_key(text)), text.parse::<PublicKey>().unwrap(), "{text}");
        }
    }

    #[test]
    fn the_project_key_is_always_trusted() {
        let project: PublicKey = "kWB8NBoJtLGX7mZwXgMSZ1C8RkUDpkdOphusy_JhEk0".parse().unwrap();
        let keys = TrustedKeys::compiled_in();
        assert_eq!(keys.iter().next(), Some(&project));
        // 另外那一把只在编译时指定了才有。
        assert_eq!(keys.iter().count(), 1 + usize::from(EXTRA_KEY.is_some()));
    }

    #[test]
    fn a_manifest_signed_by_a_stranger_is_not_trusted_by_the_compiled_in_keys() {
        let stranger = NodeKey::generate().unwrap();
        let signed = sign_manifest(&stranger, "{}".to_owned());
        assert!(matches!(TrustedKeys::compiled_in().verify(&signed), Err(ManifestError::BadSignature)));
    }

    #[test]
    fn any_one_of_several_trusted_keys_is_enough() {
        // 换钥匙的过渡期里程序同时认新旧两把。
        let (current, next, stranger) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        let keys = TrustedKeys { keys: vec![current.public(), next.public()] };
        let text = r#"{ "version": "0.3.0", "min_controller": "0.1.0", "published": 1, "artifacts": {} }"#;
        for key in [&current, &next] {
            assert_eq!(keys.verify(&sign_manifest(key, text.to_owned())).unwrap().version.to_string(), "0.3.0");
        }
        assert!(matches!(keys.verify(&sign_manifest(&stranger, text.to_owned())), Err(ManifestError::BadSignature)));
    }
}
