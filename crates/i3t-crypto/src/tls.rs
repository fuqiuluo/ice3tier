//! 按公钥互相认证的 TLS 1.3 配置。
//!
//! 每个节点用自己的节点密钥自签一张证书。校验对端时不看证书链、有效期和名字，只做两件事：
//!
//! 1. 提取证书中的公钥，与期望公钥比对（拨号方），或询问调用方是否信任该公钥（接受方）；
//! 2. 验证握手签名，证明对端确实持有这把公钥对应的私钥。
//!
//! 所以证书只是公钥的容器，信任来自 netmap 里登记的公钥。

use std::sync::Arc;

use i3t_proto::PublicKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};

use crate::key::NodeKey;

/// Ed25519 公钥的 SubjectPublicKeyInfo 编码里，公钥本身之前的固定部分（RFC 8410）。
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// 证书里的名字。校验时不看它，只是证书格式要求有一个。
const CERT_NAME: &str = "i3t";

/// 拨出一方的配置：只接受公钥是 `expected` 的对端，并向对端出示自己的证书。
///
/// # Errors
///
/// 用节点密钥签证书失败。
pub fn client_config(key: &NodeKey, expected: PublicKey, alpn: &[u8]) -> Result<ClientConfig, TlsError> {
    client_config_with(&Identity::new(key)?, expected, alpn)
}

/// 和 [`client_config`] 一样，只是用已经签好的 [`Identity`]，不再签一次证书。
///
/// # Errors
///
/// TLS 库不接受这份配置（不会发生在 [`Identity::new`] 签出来的证书上）。
pub fn client_config_with(identity: &Identity, expected: PublicKey, alpn: &[u8]) -> Result<ClientConfig, TlsError> {
    client_config_for(identity, expected, alpn, Cipher::detect())
}

fn client_config_for(identity: &Identity, expected: PublicKey, alpn: &[u8], cipher: Cipher) -> Result<ClientConfig, TlsError> {
    let provider = provider(cipher);
    let verifier = PinnedServer { expected, algorithms: provider.signature_verification_algorithms };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![identity.certificate.clone()], identity.private_key.clone_key())?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// 接受方配置：对端必须出示证书，由 `is_allowed` 决定是否信任其公钥。
///
/// `is_allowed` 在每次握手时调用，所以它可以去查会变的东西（例如当前的 netmap）。
/// 握手完成之后用 [`peer_key`] 取出对端的公钥，就知道连进来的是谁。
///
/// # Errors
///
/// 用节点密钥签证书失败。
pub fn server_config(
    key: &NodeKey,
    is_allowed: impl Fn(&PublicKey) -> bool + Send + Sync + 'static,
    alpn: &[u8],
) -> Result<ServerConfig, TlsError> {
    server_config_with(&Identity::new(key)?, is_allowed, alpn)
}

/// 和 [`server_config`] 一样，只是用已经签好的 [`Identity`]，不再签一次证书。
///
/// # Errors
///
/// TLS 库不接受这份配置（不会发生在 [`Identity::new`] 签出来的证书上）。
pub fn server_config_with(
    identity: &Identity,
    is_allowed: impl Fn(&PublicKey) -> bool + Send + Sync + 'static,
    alpn: &[u8],
) -> Result<ServerConfig, TlsError> {
    server_config_for(identity, Box::new(is_allowed), alpn, Cipher::detect())
}

fn server_config_for(identity: &Identity, is_allowed: Box<IsAllowed>, alpn: &[u8], cipher: Cipher) -> Result<ServerConfig, TlsError> {
    let provider = provider(cipher);
    let verifier = AllowedClients { is_allowed, algorithms: provider.signature_verification_algorithms };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(vec![identity.certificate.clone()], identity.private_key.clone_key())?;
    config.alpn_protocols = vec![alpn.to_vec()];
    // 没有 AES 指令的一方要 ChaCha20：做服务端时按自己的顺序挑；有 AES 指令时照客户端的顺序，客户端没有 AES 指令就会把 ChaCha20 排在前面。
    // 两边谁缺 AES 指令，这条连接就用 ChaCha20。
    config.ignore_client_order = cipher == Cipher::ChaCha20;
    Ok(config)
}

/// 用节点密钥自签的证书，连同私钥：本节点在 TLS 里出示的身份。
///
/// 签一次可以给任意多份配置用。一个节点要给每个对端各做一份客户端配置（每份钉住一把不同的公钥）时，
/// 不必每份都重新签一张证书。
pub struct Identity {
    certificate: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
}

impl Identity {
    /// # Errors
    ///
    /// 用节点密钥签证书失败。
    pub fn new(key: &NodeKey) -> Result<Self, TlsError> {
        let (certificate, private_key) = identity(key)?;
        Ok(Self { certificate, private_key })
    }
}

/// 私钥不能出现在日志里。
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").finish_non_exhaustive()
    }
}

/// 取出对端证书里的 Ed25519 公钥。`end_entity` 是握手时对端出示的第一张证书。
///
/// # Errors
///
/// 对端证书解析失败，或无法从证书中提取 Ed25519 公钥。
pub fn peer_key(end_entity: &CertificateDer<'_>) -> Result<PublicKey, TlsError> {
    let certificate = ParsedCertificate::try_from(end_entity).map_err(|_| TlsError::BadCertificate)?;
    let spki = certificate.subject_public_key_info();
    let key = spki.strip_prefix(&ED25519_SPKI_PREFIX).ok_or(TlsError::NotEd25519)?;
    let key: [u8; PublicKey::LEN] = key.try_into().map_err(|_| TlsError::NotEd25519)?;
    Ok(PublicKey::from_bytes(key))
}

/// 优先用哪一种加密。
///
/// CPU 支持硬件 AES 指令时，AES-GCM 开销更低：本机实验环境（含 AES 与向量指令的 x86）下，满速传输每 GB 消耗 0.67 秒 CPU，
/// ChaCha20-Poly1305 为 1.02 秒，吞吐也低三分之一。缺乏硬件 AES 指令的 CPU（如部分 ARM 设备）上，AES-GCM 需软件计算，ChaCha20 性能明显更高；
/// 该差异无法在本机直接测量，属于此类 CPU 上的通行做法，因此按 CPU 能力选择，不分性能档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cipher {
    AesGcm,
    ChaCha20,
}

impl Cipher {
    /// 这台机器该优先哪一种。查一次，之后都用这个结论。
    fn detect() -> Self {
        static DETECTED: std::sync::LazyLock<Cipher> =
            std::sync::LazyLock::new(|| if aes_in_hardware() { Cipher::AesGcm } else { Cipher::ChaCha20 });
        *DETECTED
    }
}

/// CPU 有没有 AES 指令和配套的无进位乘法（GCM 要用）。
fn aes_in_hardware() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes") && std::arch::is_aarch64_feature_detected!("pmull")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// TLS 1.3 的三个套件都留着，只排先后。AES-128-GCM 一定要在：QUIC 的 Initial 包用它。
///
/// 两种 AES 里 AES-128-GCM 在前，主要是握手快。握手里的密钥派生和摘要用套件配的哈希：AES-128-GCM 配 SHA-256，AES-256-GCM 配 SHA-384，
/// 常见 CPU 上 SHA-384 比 SHA-256 慢得多（ring 在 x86 上只给 SHA-256 用了专门指令）。本机实验环境里（Intel 大小核）一次双向认证的握手，
/// 大核上快约 8%，小核上快约一倍。数据面差得不多：单看加解密，AES-128 少四轮，1360 字节的包快 13%～25%，满速传输每 GB 的 CPU 只省百分之几。
/// 密钥交换 X25519 与节点密钥 Ed25519 均为 128 位安全强度，AES-256 额外提供的强度无实际收益。
/// 旧版本将 AES-256-GCM 排在首位：两端均支持这三个套件，握手可正常完成；支持硬件 AES 指令的服务端遵循客户端偏好顺序，因此旧版本接入时仍协商为 AES-256。
fn provider(cipher: Cipher) -> Arc<CryptoProvider> {
    use rustls::crypto::ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256};
    let mut provider = ring::default_provider();
    provider.cipher_suites = match cipher {
        Cipher::AesGcm => vec![TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256],
        Cipher::ChaCha20 => vec![TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384],
    };
    Arc::new(provider)
}

/// 用节点密钥自签一张证书，连同私钥一起交给 TLS。
fn identity(key: &NodeKey) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), TlsError> {
    let pkcs8 = PrivatePkcs8KeyDer::from(key.pkcs8_der().to_vec());
    let signer = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)?;
    let certificate = rcgen::CertificateParams::new(vec![CERT_NAME.to_owned()])?.self_signed(&signer)?;
    Ok((certificate.der().clone(), PrivateKeyDer::Pkcs8(pkcs8)))
}

fn key_of(end_entity: &CertificateDer<'_>) -> Result<PublicKey, rustls::Error> {
    peer_key(end_entity).map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))
}

fn rejected() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

/// 握手签名只接受 Ed25519：对端的密钥只可能是这一种。
fn schemes() -> Vec<SignatureScheme> {
    vec![SignatureScheme::ED25519]
}

#[derive(Debug)]
struct PinnedServer {
    expected: PublicKey,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if key_of(end_entity)? == self.expected { Ok(ServerCertVerified::assertion()) } else { Err(rejected()) }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}

/// 接受方校验对端公钥是否受信任的回调。
type IsAllowed = dyn Fn(&PublicKey) -> bool + Send + Sync;

struct AllowedClients {
    is_allowed: Box<IsAllowed>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for AllowedClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllowedClients").finish_non_exhaustive()
    }
}

impl ClientCertVerifier for AllowedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if (self.is_allowed)(&key_of(end_entity)?) { Ok(ClientCertVerified::assertion()) } else { Err(rejected()) }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("使用节点密钥签发证书失败：{0}")]
    Certificate(#[from] rcgen::Error),
    #[error("TLS 配置无效：{0}")]
    Config(#[from] rustls::Error),
    #[error("对端证书解析失败")]
    BadCertificate,
    #[error("对端证书中的公钥不是 Ed25519")]
    NotEd25519,
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use rustls::{ClientConnection, ServerConnection};

    use super::*;

    const ALPN: &[u8] = b"test/1";

    /// 在内存里把一次握手跑完，返回两边各自看到的结果。
    fn handshake(
        client: ClientConfig,
        server: ServerConfig,
    ) -> (Result<ClientConnection, rustls::Error>, Result<ServerConnection, rustls::Error>) {
        let name = ServerName::try_from(CERT_NAME).unwrap();
        let mut client = ClientConnection::new(Arc::new(client), name).unwrap();
        let mut server = ServerConnection::new(Arc::new(server)).unwrap();
        let (mut client_error, mut server_error) = (None, None);
        for _ in 0..10 {
            let mut to_server = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut to_server).unwrap();
            }
            if !to_server.is_empty() && server_error.is_none() {
                server.read_tls(&mut to_server.as_slice()).unwrap();
                server_error = server.process_new_packets().err();
            }
            let mut to_client = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut to_client).unwrap();
            }
            if !to_client.is_empty() && client_error.is_none() {
                client.read_tls(&mut to_client.as_slice()).unwrap();
                client_error = client.process_new_packets().err();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        (client_error.map_or(Ok(client), Err), server_error.map_or(Ok(server), Err))
    }

    #[test]
    fn both_sides_learn_the_peer_key_and_can_exchange_data() {
        let (alice, bob) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        let alice_public = alice.public();
        let client = client_config(&alice, bob.public(), ALPN).unwrap();
        let server = server_config(&bob, move |key| *key == alice_public, ALPN).unwrap();
        let (client, server) = handshake(client, server);
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        assert_eq!(peer_key(&client.peer_certificates().unwrap()[0]).unwrap(), bob.public());
        assert_eq!(peer_key(&server.peer_certificates().unwrap()[0]).unwrap(), alice.public());
        assert_eq!(client.alpn_protocol(), Some(ALPN));
        assert_eq!(client.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));

        client.writer().write_all(b"ping").unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut received = [0; 4];
        server.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, b"ping");
    }

    #[test]
    fn the_side_without_aes_instructions_gets_chacha20_whichever_side_it_is() {
        let (alice, bob) = (Identity::new(&NodeKey::generate().unwrap()).unwrap(), Identity::new(&NodeKey::generate().unwrap()).unwrap());
        let bob_public = bob.certificate.clone();
        let bob_key = peer_key(&bob_public).unwrap();
        let negotiated = |client: Cipher, server: Cipher| {
            let client = client_config_for(&alice, bob_key, ALPN, client).unwrap();
            let server = server_config_for(&bob, Box::new(|_| true), ALPN, server).unwrap();
            let (client, server) = handshake(client, server);
            let (client, server) = (client.unwrap(), server.unwrap());
            let suite = client.negotiated_cipher_suite().unwrap().suite();
            assert_eq!(Some(suite), server.negotiated_cipher_suite().map(|suite| suite.suite()));
            suite
        };
        use rustls::CipherSuite::{TLS13_AES_128_GCM_SHA256 as AES, TLS13_CHACHA20_POLY1305_SHA256 as CHACHA};
        assert_eq!(negotiated(Cipher::AesGcm, Cipher::AesGcm), AES);
        assert_eq!(negotiated(Cipher::ChaCha20, Cipher::AesGcm), CHACHA, "客户端缺 AES 指令");
        assert_eq!(negotiated(Cipher::AesGcm, Cipher::ChaCha20), CHACHA, "服务端缺 AES 指令");
        assert_eq!(negotiated(Cipher::ChaCha20, Cipher::ChaCha20), CHACHA);
    }

    #[test]
    fn client_refuses_a_server_with_another_key() {
        let (alice, bob, mallory) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        let client = client_config(&alice, bob.public(), ALPN).unwrap();
        let server = server_config(&mallory, |_| true, ALPN).unwrap();
        let (client, _server) = handshake(client, server);
        assert!(matches!(client, Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))));
    }

    #[test]
    fn server_refuses_a_client_it_does_not_know() {
        let (alice, bob) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        let client = client_config(&alice, bob.public(), ALPN).unwrap();
        let server = server_config(&bob, |_| false, ALPN).unwrap();
        let (_client, server) = handshake(client, server);
        assert!(matches!(server, Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))));
    }

    #[test]
    fn one_identity_serves_configs_pinned_to_different_peers() {
        let (alice, bob, carol) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        let identity = Identity::new(&alice).unwrap();
        let alice_public = alice.public();
        for peer in [&bob, &carol] {
            let client = client_config_with(&identity, peer.public(), ALPN).unwrap();
            let server = server_config(peer, move |key| *key == alice_public, ALPN).unwrap();
            let (client, server) = handshake(client, server);
            assert_eq!(peer_key(&client.unwrap().peer_certificates().unwrap()[0]).unwrap(), peer.public());
            assert_eq!(peer_key(&server.unwrap().peer_certificates().unwrap()[0]).unwrap(), alice.public());
        }
        assert!(!format!("{identity:?}").contains("private"), "Debug 不能带出私钥");
    }

    #[test]
    fn a_certificate_with_another_kind_of_key_is_not_accepted() {
        let other = rcgen::generate_simple_self_signed(vec!["x".to_owned()]).unwrap();
        assert!(matches!(peer_key(other.cert.der()), Err(TlsError::NotEd25519)));
        assert!(matches!(peer_key(&CertificateDer::from(vec![1, 2, 3])), Err(TlsError::BadCertificate)));
    }
}
