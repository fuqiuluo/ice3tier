//! 测试用的证书：上游自己生成一个 CA，用它签自己的证书；负载端只信任这个 CA。
//!
//! CA 的证书和私钥写在一个目录里（`ca.pem`、`ca-key.pem`）。目录里已经有了就沿用，
//! 这样上游重启之后，已经拷到负载端机器上的 `ca.pem` 照样能用。

use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca-key.pem";
const ALPN: &[u8] = b"http/1.1";

/// CA 参数。沿用已有 CA 时必须保持相同的主体名，以确保签发证书的颁发者一致。
fn ca_params() -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new()).context("CA 的证书参数")?;
    params.distinguished_name.push(DnType::CommonName, "i3t-llmgw test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    Ok(params)
}

/// 读出目录里的 CA，没有就生成一个写进去。
fn load_or_create_ca(dir: &Path) -> anyhow::Result<Issuer<'static, KeyPair>> {
    let (cert_path, key_path) = (dir.join(CA_CERT), dir.join(CA_KEY));
    if cert_path.exists() && key_path.exists() {
        let pem = fs::read_to_string(&key_path).with_context(|| format!("读 {}", key_path.display()))?;
        let key = KeyPair::from_pem(&pem).with_context(|| format!("{} 不是一把私钥", key_path.display()))?;
        tracing::info!(dir = %dir.display(), "沿用目录里已有的测试 CA");
        return Ok(Issuer::new(ca_params()?, key));
    }
    fs::create_dir_all(dir).with_context(|| format!("创建目录 {}", dir.display()))?;
    let key = KeyPair::generate().context("生成 CA 的私钥")?;
    let params = ca_params()?;
    let cert = params.self_signed(&key).context("给 CA 自签证书")?;
    fs::write(&key_path, key.serialize_pem()).with_context(|| format!("写 {}", key_path.display()))?;
    fs::write(&cert_path, cert.pem()).with_context(|| format!("写 {}", cert_path.display()))?;
    tracing::info!(cert = %cert_path.display(), "生成了新的测试 CA，负载端要信任这个文件");
    Ok(Issuer::new(params, key))
}

/// 上游的 TLS 配置：证书由目录里的 CA 签发，覆盖 `names` 里的每个域名和 IP 地址。
///
/// # Errors
///
/// 目录读写失败，或者某个名字不能放进证书。
pub fn server_config(dir: &Path, names: &[String]) -> anyhow::Result<Arc<ServerConfig>> {
    let ca = load_or_create_ca(dir)?;
    let mut params = CertificateParams::new(names.to_vec()).context("上游证书里的名字")?;
    params.distinguished_name.push(DnType::CommonName, "i3t-llmgw upstream");
    let key = KeyPair::generate().context("生成上游证书的私钥")?;
    let cert = params.signed_by(&key, &ca).context("用测试 CA 签上游的证书")?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut config =
        ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.der().clone()], key).context("组装上游的 TLS 配置")?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// 负载端的 TLS 配置：只信任 `ca_file` 这一个 CA。
///
/// # Errors
///
/// 无法读取文件或文件中不包含有效证书。
pub fn client_config(ca_file: &Path) -> anyhow::Result<Arc<ClientConfig>> {
    let ca = CertificateDer::from_pem_file(ca_file).with_context(|| format!("读 CA 证书 {}", ca_file.display()))?;
    let mut roots = RootCertStore::empty();
    roots.add(ca).with_context(|| format!("{} 不能当作根证书", ca_file.display()))?;
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    /// 生成的 CA 签出来的证书客户端认；上游重启沿用同一个 CA 之后，旧的 ca.pem 照样认。
    #[tokio::test]
    async fn clients_trusting_ca_pem_accept_the_upstream_even_after_a_restart() {
        let dir = std::env::temp_dir().join(format!("i3t-llmgw-tls-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let names = vec!["api.llmgw.test".to_owned(), "127.0.0.1".to_owned()];
        let first = server_config(&dir, &names).unwrap();
        let client = client_config(&dir.join(CA_CERT)).unwrap();
        let second = server_config(&dir, &names).unwrap();
        for server in [first, second] {
            for name in ["api.llmgw.test", "127.0.0.1"] {
                handshake(server.clone(), client.clone(), name).await;
            }
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    async fn handshake(server: Arc<ServerConfig>, client: Arc<ClientConfig>, name: &'static str) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(server).accept(tcp).await.unwrap();
            tls.write_all(b"ok").await.unwrap();
            tls.shutdown().await.unwrap();
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from(name).unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(client).connect(server_name, tcp).await.unwrap();
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"ok");
        accept.await.unwrap();
    }
}
