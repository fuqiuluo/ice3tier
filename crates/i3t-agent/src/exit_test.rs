//! 出口测试的节点一侧（`i3tctl exit test`）：controller 让这个出口按它的出站策略试着连一个目标，
//! 节点做完把结果送回去。连目标之前的检查、解析和连接在出口模块（`i3t_exit::Outbound::probe`），这里加上 TLS 握手和节点自己的规矩。
//!
//! 节点自己的规矩，不依赖 controller：同时只做一个，两次之间至少隔 [`MIN_INTERVAL`]，每一步有时限（解析、连接、握手各 5 秒），
//! 目标只能是出口的策略允许别人连的（不是出口的节点什么都不连）。所以拿到管理令牌的人也不能用它扫描：每分钟最多 30 个目标，
//! 而且都是这个出口本来就替别人连的那些地址和端口。
//!
//! TLS 握手只看能不能完成、要多久，不检查证书（节点没有带证书的信任库）：这一步不说网站是不是真的，也不发任何数据。

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use i3t_exit::{Outbound, PROBE_STEP};
use i3t_model::control::exit_test::{ExitTestCause, ExitTestResult, ExitVia, TlsStep};
use i3t_proto::flow::Host;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

/// 两次出口测试之间至少隔多久。
const MIN_INTERVAL: Duration = Duration::from_secs(2);

/// 做 TLS 握手的端口。
const TLS_PORT: u16 = 443;

/// 一次出口测试的回答：controller 编的号，和结果。
pub(crate) type Answer = (u64, ExitTestResult);

/// 收 controller 的出口测试，一次做一个，结果放进 `answers`。
pub(crate) struct ExitTests {
    outbound: Outbound,
    answers: mpsc::Sender<Answer>,
    /// 正在做的那一个开始的时刻，和上一个开始的时刻。
    gate: Mutex<Gate>,
}

#[derive(Debug, Default)]
struct Gate {
    running: bool,
    last_start: Option<Instant>,
}

impl Gate {
    /// 能开始一个新的就占上，返回 `true`。
    fn enter(&mut self, now: Instant) -> bool {
        let rested = self.last_start.is_none_or(|last| now.saturating_duration_since(last) >= MIN_INTERVAL);
        if self.running || !rested {
            return false;
        }
        (self.running, self.last_start) = (true, Some(now));
        true
    }
}

impl ExitTests {
    pub(crate) fn new(outbound: Outbound, answers: mpsc::Sender<Answer>) -> Self {
        Self { outbound, answers, gate: Mutex::default() }
    }

    /// controller 要测 `host:port`。在长连接的任务里调用，不等：测试在自己的任务里做。
    pub(crate) fn order(self: &Arc<Self>, request: u64, host: String, port: u16) {
        if !self.gate.lock().expect("exit test gate mutex poisoned").enter(Instant::now()) {
            tracing::info!(request, "已拒绝出口测试：已有测试正在执行，或距上次测试不足 {MIN_INTERVAL:?}");
            return self.answer(request, refused(ExitTestCause::Busy));
        }
        let running = Running(Arc::clone(self));
        tokio::spawn(async move {
            let result = running.0.run(&host, port).await;
            running.0.answer(request, result);
        });
    }

    async fn run(&self, host: &str, port: u16) -> ExitTestResult {
        let Ok(target) = host.parse::<Host>() else {
            tracing::info!(host, "无法解析出口测试目标");
            return refused(ExitTestCause::BadTarget);
        };
        let probe = self.outbound.probe(&target, port).await;
        let mut result = probe.result;
        if let (TLS_PORT, Some(stream)) = (port, probe.stream) {
            result.tls = Some(handshake(stream, host).await);
        }
        tracing::info!(
            %target,
            port,
            via = ?result.via,
            refused = ?result.refused,
            resolve = ?result.resolve.as_ref().map(|step| (step.ms, step.cause)),
            connect = ?result.connect.as_ref().map(|step| (step.ms, step.address, step.cause)),
            tls = ?result.tls.as_ref().map(|step| (step.ms, step.cause)),
            "出口测试完成"
        );
        result
    }

    fn answer(&self, request: u64, result: ExitTestResult) {
        if self.answers.try_send((request, result)).is_err() {
            tracing::debug!(request, "无法发送出口测试结果（长连接通道已满或已关闭），已丢弃");
        }
    }
}

/// 正在做的那一个占着门，结束（或者它的任务意外中止）时放开。
struct Running(Arc<ExitTests>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.gate.lock().expect("exit test gate mutex poisoned").running = false;
    }
}

/// 未执行探测即拒绝测试。
fn refused(cause: ExitTestCause) -> ExitTestResult {
    ExitTestResult { via: ExitVia::Direct, refused: Some(cause), resolve: None, connect: None, tls: None }
}

/// 在连好的 `stream` 上做一次 TLS 握手（名字是 `host`），做完就关。
async fn handshake(stream: TcpStream, host: &str) -> TlsStep {
    let started = Instant::now();
    let cause = match ServerName::try_from(host.to_owned()) {
        Ok(name) => {
            let connector = TlsConnector::from(Arc::new(client_config()));
            match tokio::time::timeout(PROBE_STEP, connector.connect(name, stream)).await {
                Ok(Ok(_tls)) => None,
                Ok(Err(error)) => Some(tls_cause(&error)),
                Err(_) => Some(ExitTestCause::Timeout),
            }
        }
        Err(_) => Some(ExitTestCause::BadTarget),
    };
    TlsStep { ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX), cause }
}

/// 握手失败是哪一种。rustls 的错误包在 `io::Error` 里。
fn tls_cause(error: &std::io::Error) -> ExitTestCause {
    if matches!(error.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset) {
        return ExitTestCause::Closed;
    }
    match error.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::AlertReceived(_)) => ExitTestCause::Alert,
        _ => ExitTestCause::Other,
    }
}

/// 不检查证书、只验握手签名的客户端配置：TLS 1.2 和 1.3，常见的套件。
fn client_config() -> ClientConfig {
    let provider = Arc::new(ring::default_provider());
    let verifier = AnyCertificate { algorithms: provider.signature_verification_algorithms };
    match ClientConfig::builder_with_provider(Arc::clone(&provider)).with_safe_default_protocol_versions() {
        Ok(builder) => builder.dangerous().with_custom_certificate_verifier(Arc::new(verifier)).with_no_client_auth(),
        // ring 的默认套件一定支持默认的协议版本；万一不行就只用 TLS 1.3。
        Err(_) => ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring 支持 TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth(),
    }
}

/// 接受任意证书，仅校验握手签名（证明对端持有证书对应私钥）。仅用于出口测试：此步骤仅测量握手过程，不验证站点身份。
#[derive(Debug)]
struct AnyCertificate {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_test_at_a_time_and_at_most_one_every_two_seconds() {
        let mut gate = Gate::default();
        let start = Instant::now();
        assert!(gate.enter(start));
        assert!(!gate.enter(start + Duration::from_secs(5)), "上一个还在做");
        gate.running = false;
        assert!(!gate.enter(start + Duration::from_secs(1)), "刚做过");
        assert!(gate.enter(start + MIN_INTERVAL));
    }

    #[tokio::test]
    async fn a_handshake_with_a_server_that_is_not_tls_fails_with_a_cause() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // 收到 ClientHello 就关：握手完成之前对方走了。
            let mut buf = [0; 64];
            let _ = stream.readable().await;
            let _ = stream.try_read(&mut buf);
        });
        let step = handshake(TcpStream::connect(addr).await.unwrap(), "example.com").await;
        assert_eq!(step.cause, Some(ExitTestCause::Closed), "{step:?}");
    }
}
