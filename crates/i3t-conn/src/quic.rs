//! QUIC 的参数。数值有的是设计时定的，有的是实测的结论。

use std::sync::Arc;
use std::time::Duration;

use i3t_crypto::NodeKey;
use i3t_crypto::tls::{self, TlsError};
use i3t_model::netmap::{DEFAULT_ACK_ELICITING_THRESHOLD, DEFAULT_MAX_ACK_DELAY_MS, Network};
use i3t_path::Paths;
use i3t_proto::{MAX_CONN_PACKET_LEN, PublicKey};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{AckFrequencyConfig, ClientConfig, EndpointConfig, IdleTimeout, MtuDiscoveryConfig, ServerConfig, TransportConfig, VarInt};
use quinn_proto::HashedConnectionIdGenerator;

use crate::congestion::Algorithm;
use crate::tuning::Tuning;

/// 节点之间的连接在 TLS 握手里声明的协议名。
pub(crate) const ALPN: &[u8] = b"i3t/1";
/// TLS 要一个服务器名字。校验只看公钥，这个名字没有人看。
pub(crate) const SERVER_NAME: &str = "i3t";

/// 保活间隔。NAT 上的 UDP 映射通常 30 秒以上才回收。
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// 空闲超时。所有的路都断了的时候，连接在这段时间里等路恢复，上面的流不断。
const IDLE_TIMEOUT_MS: u32 = 30_000;
/// 对端最多能同时开多少条流。QUIC 库按这个数预先占内存（每条约 105 字节，16384 条是每条连接 13MB 左右）。
const MAX_STREAMS: u32 = 16_384;
// 每条流的接收窗口和连接的收发窗口跟着性能档位走，见 [`Tuning`]。
//
// 连接的发送窗口（一条连接上所有的流加起来，写进去了、对端还没有确认的数据）决定了流的优先级管不管用：
// 优先级排的是已经写进连接的数据，这个窗口满着的时候，高优先级的流也要先等别的流腾出位置才写得进去，和它们是一样的先后。
// 一条不停写的流最多压住一个流窗口（2MB）的数据，QUIC 库默认的 10MB 五条这样的流就满了；默认取 64MB，同时有 32 条流压满才会到。
// 实测（回环上每秒约一千个包的慢路，小消息的往返时间）：24 条流压满时高优先级 20～30ms、低优先级 64ms；64 条流压满、
// 超过了这个窗口时，高优先级的也要一百到几百毫秒。量的办法在 `tests/priority.rs` 里。
//
// 连接的接收窗口（对端发过来了、本端的上层还没有读走的数据）在 QUIC 库里默认不限。不限的话，netmap 里的任何一个对端
// 都能开满流、每条流压满 2MB 却不让本端读得动（比如在流的开头留一个空洞），把本端的内存吃光：16384 条流 × 2MB 是 32GB。
// 有了上限，一条连接最多压住这么多。和发送窗口取一样的数：守规矩的对端本来就不会让没确认的数据超过它。
/// 对端最多能同时开多少条单向流。单向流用来送打洞信令和要求可靠送达的数据报，每个数据报一条，读完就关。
/// 这个数也是对端一次能压过来多少个这样的数据报：本端来不及收时，对端开不出新的流，就在那里等。
const UNI_STREAMS: u32 = 256;
/// 收到了、上层还没有取走的数据报最多攒多少字节，超过了丢最旧的。上层取得很快，这只是给突发留的余量。
const DATAGRAM_RECV_BUFFER: usize = 256 * 1024;
/// 等着发出去的数据报最多攒多少字节，超过了丢最旧的：这些是不保证送达的数据，攒久了也就过期了。
/// 要装得下一个切成片的最大的 UDP 报文（64KB 多一点）。
const DATAGRAM_SEND_BUFFER: usize = 256 * 1024;

/// 请对端怎样确认本端发的包（QUIC 的确认频率扩展）。网络的设置，从 netmap 里读；取值的理由见
/// [`DEFAULT_ACK_ELICITING_THRESHOLD`] 和 [`DEFAULT_MAX_ACK_DELAY_MS`]。
///
/// 这是本端对对端的请求，连接一建立就发过去：本端的设置决定对端怎样确认本端发的包，反方向看对端的设置。
/// 对端的程序比这项设置旧也照办（QUIC 库一直认这个请求），只是它自己不提，本端确认它的包还是老样子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AckFrequency {
    /// 对端攒到多于这么多个包才单独发一个确认包；这期间它有别的包要发，确认就搭在里面。
    pub(crate) eliciting_threshold: u32,
    /// 没攒够时，对端最多等这么久就发确认。QUIC 库把它收在 1 毫秒和"往返时间、25 毫秒里大的那个"之间。
    pub(crate) max_delay: Duration,
}

impl Default for AckFrequency {
    fn default() -> Self {
        Self { eliciting_threshold: DEFAULT_ACK_ELICITING_THRESHOLD, max_delay: Duration::from_millis(DEFAULT_MAX_ACK_DELAY_MS.into()) }
    }
}

impl From<&Network> for AckFrequency {
    fn from(network: &Network) -> Self {
        Self { eliciting_threshold: network.ack_eliciting_threshold, max_delay: Duration::from_millis(network.max_ack_delay_ms.into()) }
    }
}

/// 一条连接的传输参数：档位定的窗口、这条连接用的拥塞控制（节点对的设置，见 [`Algorithm`]）和网络的确认设置。
pub(crate) fn transport(tuning: &Tuning, algorithm: Algorithm, ack: AckFrequency) -> Arc<TransportConfig> {
    // 两条路（直连、经 relay）对连接报同一个最大包长，探测出来的大包换了路也发得出去。
    let mut mtu = MtuDiscoveryConfig::default();
    mtu.upper_bound(MAX_CONN_PACKET_LEN);

    let mut ack_frequency = AckFrequencyConfig::default();
    ack_frequency.ack_eliciting_threshold(VarInt::from_u32(ack.eliciting_threshold)).max_ack_delay(Some(ack.max_delay));

    let mut transport = TransportConfig::default();
    transport
        .ack_frequency_config(Some(ack_frequency))
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(UNI_STREAMS))
        .stream_receive_window(VarInt::from_u32(tuning.effective_stream_window()))
        .receive_window(VarInt::from_u32(tuning.connection_window))
        .send_window(u64::from(tuning.connection_window))
        .keep_alive_interval(Some(KEEP_ALIVE))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(IDLE_TIMEOUT_MS))))
        .mtu_discovery_config(Some(mtu))
        // 默认用自己写的 BBR；库自带的那份不能用（窄带宽上多发一倍流量，带宽估计只升不降）。
        // 节点对可以设成 Cubic；没有设置时环境变量 I3T_CONGESTION=cubic 也可以换回 Cubic，做对比测试时用。
        .congestion_controller_factory(algorithm.factory())
        .datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUFFER))
        .datagram_send_buffer_size(DATAGRAM_SEND_BUFFER);
    Arc::new(transport)
}

/// 派生"无状态重置"密钥和连接编号密钥时的用途标签。
const RESET_KEY_PURPOSE: &str = "i3t-conn stateless reset";
const CID_KEY_PURPOSE: &str = "i3t-conn connection id";

/// 端点的参数。`key` 是本节点的私钥，从它派生两把重启之后不变的密钥：
///
/// - 连接编号里带一个校验值，不是本节点发出去的编号一眼就能认出来丢掉；
/// - 收到"编号是本节点发的、连接却不认识"的包时，回一个无状态重置，对端凭它立刻知道这条连接没了。
///
/// QUIC 库默认每次启动随机生成这两把密钥。那样节点崩溃重启之后，对端手上的旧连接发来的包在新进程看来编号不合法，
/// 直接丢掉、什么都不回，对端要等空闲超时（30 秒）才发现，这期间它开的新流全都没有回音。
/// 从私钥派生之后，新进程认得旧编号，回的重置对端也认，重启之后一两个往返就恢复。
pub(crate) fn endpoint(key: &NodeKey) -> Result<EndpointConfig, QuicConfigError> {
    let reset_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key.derive_secret(RESET_KEY_PURPOSE));
    let mut config = EndpointConfig::new(Arc::new(reset_key));
    let cid_key = u64::from_le_bytes(*key.derive_secret(CID_KEY_PURPOSE).first_chunk().expect("派生出来的密钥是 32 字节，取得出前 8 个"));
    config.cid_generator(move || Box::new(HashedConnectionIdGenerator::from_key(cid_key)));
    // 端口上靠"QUIC 包的首字节一定带 0x40 这一位"把连接包和路径层的帧分开，所以这一位不能被随机化。
    config.grease_quic_bit(false);
    // QUIC 库按"这个值 × 一次合并接收的包数 × 批量大小"分配接收缓冲，默认值下是一百多 MB。
    // 这个端口上最长的数据报就是带着中转头的连接包。
    let max_datagram = u16::try_from(Paths::max_datagram_len()).map_err(|_| QuicConfigError::DatagramLen)?;
    config.max_udp_payload_size(max_datagram).map_err(|_| QuicConfigError::DatagramLen)?;
    Ok(config)
}

/// 接受连接一方的配置。`is_allowed` 决定认不认对端的公钥，每次握手都会问。
pub(crate) fn server(
    key: &NodeKey,
    is_allowed: impl Fn(&PublicKey) -> bool + Send + Sync + 'static,
) -> Result<ServerConfig, QuicConfigError> {
    let crypto = QuicServerConfig::try_from(tls::server_config(key, is_allowed, ALPN)?).map_err(|_| QuicConfigError::CipherSuite)?;
    let mut server = ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(transport(&Tuning::default(), Algorithm::from_env(), AckFrequency::default()));
    // 对端在 QUIC 库眼里的地址是固定的虚拟地址，不会变。
    server.migration(false);
    Ok(server)
}

/// 拨出一方的配置：只接受公钥是 `expected` 的对端。
pub(crate) fn client(key: &NodeKey, expected: PublicKey, transport: Arc<TransportConfig>) -> Result<ClientConfig, QuicConfigError> {
    let crypto = QuicClientConfig::try_from(tls::client_config(key, expected, ALPN)?).map_err(|_| QuicConfigError::CipherSuite)?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    client.transport_config(transport);
    Ok(client)
}

/// QUIC 的配置建不出来。都是不该发生的事，发生了说明程序或者密钥有问题。
#[derive(Debug, thiserror::Error)]
pub enum QuicConfigError {
    #[error("建不出 TLS 配置")]
    Tls(#[from] TlsError),
    #[error("TLS 配置里没有 QUIC 需要的加密套件")]
    CipherSuite,
    #[error("最大数据报长度不在 QUIC 允许的范围里")]
    DatagramLen,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use bytes::Bytes;

    use super::*;

    /// 拨过去的一端按 `ack` 请对端确认，一个一个地送 `count` 个数据报（每个都等对面收到），返回它收到了多少个确认。
    ///
    /// 对面的传输参数是 QUIC 库默认的，自己不提确认的要求：比这项设置旧的节点就是这样。
    async fn acks_received(ack: AckFrequency, count: usize) -> u64 {
        let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let (near, far) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        let crypto = QuicServerConfig::try_from(tls::server_config(&far, |_| true, ALPN).unwrap()).unwrap();
        let listener = quinn::Endpoint::server(ServerConfig::with_crypto(Arc::new(crypto)), loopback).unwrap();
        let dialer = quinn::Endpoint::client(loopback).unwrap();
        let config = client(&near, far.public(), transport(&Tuning::default(), Algorithm::Bbr, ack)).unwrap();

        let dialing = dialer.connect_with(config, listener.local_addr().unwrap(), SERVER_NAME).unwrap();
        let (ours, theirs) = tokio::join!(dialing, async { listener.accept().await.unwrap().await });
        let (ours, theirs) = (ours.unwrap(), theirs.unwrap());
        for _ in 0..count {
            ours.send_datagram(Bytes::from_static(b"one way")).unwrap();
            theirs.read_datagram().await.unwrap();
        }
        ours.stats().frame_rx.acks
    }

    #[tokio::test]
    async fn a_peer_that_asks_for_nothing_itself_still_acknowledges_as_seldom_as_it_is_asked_to() {
        const PACKETS: usize = 300;
        // 等待时间取最长的，测的就只是阈值：包一个接一个地到，攒够之前等不满这么久。
        let asking = |eliciting_threshold| AckFrequency { eliciting_threshold, max_delay: Duration::from_millis(25) };
        let often = acks_received(asking(1), PACKETS).await;
        let seldom = acks_received(asking(10), PACKETS).await;
        assert!(often >= 100, "阈值 1 是每两个包一个确认，{PACKETS} 个包应该有一百多个：{often}");
        assert!(seldom * 2 < often, "阈值 10 是十来个包一个确认：阈值 1 时 {often} 个，现在 {seldom} 个");
    }
}
