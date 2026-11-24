//! 一条握手完成的 lane，以及怎么拨出去、怎么接进来。
//!
//! 握手不用现成的异步 TLS 包装：它们会从 socket 读尽可能多的字节交给 TLS 库，而 lane 上紧跟在握手之后的
//! 可能就是原始字节（拨号方当场拨的 lane，HELLO、OPENING 和用户的第一批原始字节在同一批里到）。
//! 所以握手也走 [`Sealed`] 的"一次一条记录"。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, BytesMut};
use i3t_crypto::tls::{self, Identity, TlsError};
use i3t_proto::{NodeId, PublicKey};
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::server::NoServerSessionStorage;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Instant, timeout_at};

use crate::error::LaneError;
use crate::frame::{Frame, Purpose};
use crate::sealed::{Next, Sealed, complete_record};
use crate::socket;

/// lane 的 ALPN，也是它的版本。和节点之间的 QUIC（`i3t/1`）、节点到 controller（`i3t-ctl/1`）分开，一种连接的握手不能冒充另一种。
///
/// 从 `i3t-lane/2` 起，passthrough 的流上发起方的方向也要等接受方的 SWITCH 才离开 TLS（见 crate 文档）。
pub const ALPN: &[u8] = b"i3t-lane/2";

/// 上一协议版本。仍保持兼容，可与未升级节点正常建立连接并开流，但本端发起的流一律采用 sealed 模式：
/// 旧版接受方不支持等待 SWITCH，其 passthrough 仅支持发起方在 OPENING 后立即离开 TLS（[`Mode::Early`]），本端不再使用该模式。
///
/// [`Mode::Early`]: crate::frame::Mode::Early
pub(crate) const ALPN_V1: &[u8] = b"i3t-lane/1";

/// 一条 lane 握手时谈定的版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Version {
    /// `i3t-lane/1`：对端是没升级的节点。
    V1,
    /// `i3t-lane/2`。
    V2,
}

impl Version {
    /// 握手完成之后看谈定的 ALPN。两边都认 `/2` 时服务端选它（它排在前面）；谈不出 `/2` 的都按 `/1` 算。
    fn of(connection: &Connection) -> Self {
        if connection.alpn_protocol() == Some(ALPN) { Self::V2 } else { Self::V1 }
    }
}

/// 两边都提供、服务端按这个顺序挑：新的在前。
fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![ALPN.to_vec(), ALPN_V1.to_vec()]
}

/// 一次从 socket 读多少。
const READ_CHUNK: usize = 16 * 1024;

/// 拨号方的 TLS 配置：钉住对端的公钥，不做会话恢复（每条 lane 都是完整的握手，见 crate 文档里的握手开销）。
///
/// # Errors
///
/// TLS 库不接受这份配置。
pub(crate) fn client_config(identity: &Identity, expected: PublicKey) -> Result<Arc<ClientConfig>, TlsError> {
    let mut config = tls::client_config_with(identity, expected, ALPN)?;
    config.alpn_protocols = alpn_protocols();
    config.resumption = Resumption::disabled();
    // 名字不参与校验（只认公钥），也就不必在明文的 ClientHello 里带一个。
    config.enable_sni = false;
    Ok(Arc::new(config))
}

/// 接受方的 TLS 配置：由 `is_allowed` 决定是否信任对端公钥；不签发会话票据，也不缓存会话。
///
/// # Errors
///
/// TLS 库不接受这份配置。
pub(crate) fn server_config(
    identity: &Identity,
    is_allowed: impl Fn(&PublicKey) -> bool + Send + Sync + 'static,
) -> Result<Arc<ServerConfig>, TlsError> {
    let mut config = tls::server_config_with(identity, is_allowed, ALPN)?;
    config.alpn_protocols = alpn_protocols();
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// 一条握手完成、HELLO 已经发出（拨号方）或者已经读到（接受方）的 lane。
pub(crate) struct Lane {
    pub(crate) socket: Arc<TcpStream>,
    pub(crate) sealed: Sealed,
    /// 待发的密文。
    pub(crate) out: BytesMut,
    pub(crate) peer: NodeId,
    pub(crate) membership: watch::Receiver<()>,
    pub(crate) purpose: Purpose,
    pub(crate) epoch: u64,
    pub(crate) version: Version,
}

impl Lane {
    /// 读取下一帧；收到对端 close_notify 时返回 `None`。支持取消安全：已读取但未凑齐整帧的字节会保留在缓冲中，供下次继续读取。
    ///
    /// # Errors
    ///
    /// 连接断开（没有 close_notify 的 FIN 也算）、出错，或者对端发来的东西不合法。
    pub(crate) async fn read_frame(&mut self) -> Result<Option<Frame>, LaneError> {
        loop {
            match self.sealed.next_frame()? {
                Next::Frame(frame) => return Ok(Some(frame)),
                Next::Closed => return Ok(None),
                Next::More => {
                    self.sealed.shrink();
                    read_more(&self.socket, &mut self.sealed.inbound).await?;
                }
            }
        }
    }

    /// 把一个帧排进待发的密文，不写。
    pub(crate) fn queue(&mut self, frame: &Frame) {
        self.sealed.seal_frame(frame);
        self.sealed.take_output(&mut self.out);
    }

    /// 把待发的密文写完。
    ///
    /// # Errors
    ///
    /// 连接断开或出错。
    pub(crate) async fn flush(&mut self) -> Result<(), LaneError> {
        write_all(&self.socket, &mut self.out).await
    }

    pub(crate) async fn send(&mut self, frame: &Frame) -> Result<(), LaneError> {
        self.queue(frame);
        self.flush().await
    }

    /// 空闲在池里的 lane 拿出来用之前问一下：对端没有关掉它，也没有在上面发不该发的东西。
    ///
    /// 非阻塞检查。此处无法检测尚未感知失效的半开连接，依赖开流阶段较短的 `TCP_USER_TIMEOUT` 发现（见 [`socket`]）。
    pub(crate) fn is_usable(&self) -> bool {
        if !self.sealed.inbound.is_empty() || !self.sealed.at_record_boundary() {
            return false;
        }
        let mut probe = [0; 1];
        matches!(self.socket.try_read(&mut probe), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    }
}

/// 从 socket 再读一些字节到 `buf` 末尾。
///
/// # Errors
///
/// 对端关了连接（[`LaneError::Closed`]）或者出错。
pub(crate) async fn read_more(socket: &TcpStream, buf: &mut BytesMut) -> Result<(), LaneError> {
    loop {
        socket.readable().await.map_err(LaneError::Io)?;
        buf.reserve(READ_CHUNK);
        match socket.try_read_buf(buf) {
            Ok(0) => return Err(LaneError::Closed),
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(LaneError::Io(error)),
        }
    }
}

/// 把 `out` 全部写出去，写一点扔掉一点：被取消时剩下的还在 `out` 里。
///
/// # Errors
///
/// 连接断开或出错。
pub(crate) async fn write_all(socket: &TcpStream, out: &mut BytesMut) -> Result<(), LaneError> {
    while !out.is_empty() {
        socket.writable().await.map_err(LaneError::Io)?;
        match socket.try_write(out) {
            Ok(written) => out.advance(written),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(LaneError::Io(error)),
        }
    }
    Ok(())
}

/// 跑完 TLS 握手：发 TLS 要发的，收一条记录处理一条，直到握手完成。
async fn handshake(socket: &TcpStream, sealed: &mut Sealed, out: &mut BytesMut) -> Result<(), LaneError> {
    loop {
        sealed.take_output(out);
        write_all(socket, out).await?;
        if !sealed.is_handshaking() {
            return Ok(());
        }
        match sealed.feed_record() {
            Ok(true) => {}
            Ok(false) => read_more(socket, &mut sealed.inbound).await?,
            Err(error) => {
                // TLS 库可能排了一个告警，告诉对端为什么不握了。尽力发出去，不等。
                sealed.take_output(out);
                let _ = socket.try_write(out);
                return Err(error);
            }
        }
    }
}

/// 拨号的参数。
pub(crate) struct Dial<'a> {
    pub(crate) addrs: &'a [SocketAddr],
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) peer: NodeId,
    pub(crate) membership: watch::Receiver<()>,
    pub(crate) purpose: Purpose,
    pub(crate) epoch: u64,
    pub(crate) deadline: Instant,
}

/// 拨一条 lane：连上、握手、把 HELLO 排进待发的密文。HELLO 不在这里写出去，调用方可以让后面的帧和它一起走。
///
/// 对端为 relay 时可能存在多个候选地址（由 controller 发现），并非全部可达。与路径层连接 relay TCP 中转一致
/// （[`i3t_path::connect_first`]）：按序错峰并发建连，采用最先连通的地址，避免无响应地址阻塞后续地址。
/// 返回用的是哪一个，下一次先试它。
///
/// # Errors
///
/// 所有地址均无法连通、握手失败（含对端公钥不匹配），或超过 `deadline`。
pub(crate) async fn dial(dial: Dial<'_>) -> Result<(Lane, SocketAddr), LaneError> {
    let Dial { addrs, config, peer, membership, purpose, epoch, deadline } = dial;
    if addrs.is_empty() {
        return Err(LaneError::Protocol("缺少可拨号的候选地址"));
    }
    let (socket, addr) = match timeout_at(deadline, i3t_path::connect_first(addrs)).await {
        Ok(Ok(connected)) => connected,
        Ok(Err(error)) => return Err(LaneError::Io(error)),
        Err(_) => return Err(LaneError::Deadline(deadline.saturating_duration_since(Instant::now()))),
    };
    match timeout_at(deadline, establish(socket, config, peer, membership, purpose, epoch)).await {
        Ok(Ok(lane)) => Ok((lane, addr)),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(LaneError::Deadline(deadline.saturating_duration_since(Instant::now()))),
    }
}

async fn establish(
    socket: TcpStream,
    config: Arc<ClientConfig>,
    peer: NodeId,
    membership: watch::Receiver<()>,
    purpose: Purpose,
    epoch: u64,
) -> Result<Lane, LaneError> {
    socket::configure(&socket).map_err(LaneError::Io)?;
    let name = ServerName::try_from("i3t").expect("固定的名字是合法的 DNS 名字");
    let connection = ClientConnection::new(config, name).map_err(LaneError::Tls)?;
    let mut sealed = Sealed::new(Connection::Client(connection), BytesMut::new());
    let mut out = BytesMut::new();
    handshake(&socket, &mut sealed, &mut out).await?;
    sealed.shrink();
    let version = Version::of(sealed.connection());
    let mut lane = Lane { socket: Arc::new(socket), sealed, out, peer, membership, purpose, epoch, version };
    lane.queue(&Frame::Hello { purpose, epoch });
    Ok(lane)
}

/// 接受一条拨进来的 lane：握手、认出对端、读 HELLO。
///
/// `prefix` 是调用方为了分辨协议已经从 socket 读走的字节。`resolve` 把握手认过的公钥换成节点编号；
/// 握手完成至此处之间该公钥可能已被移除，若无法映射回节点则视为不受信任。
///
/// 时限都是从接受连接时算起的绝对时刻，来多少字节都不延长：`first_record` 之内要收到一条完整的记录（ClientHello），
/// `deadline` 之内要握手完成并读到 HELLO。
///
/// # Errors
///
/// 超时、不是 TLS、握手失败（包括对端的公钥不被认可）、HELLO 不对。
pub(crate) async fn accept(
    socket: TcpStream,
    prefix: BytesMut,
    config: Arc<ServerConfig>,
    resolve: impl Fn(&PublicKey) -> Option<(NodeId, watch::Receiver<()>)>,
    first_record: Instant,
    deadline: Instant,
) -> Result<Lane, LaneError> {
    socket::configure(&socket).map_err(LaneError::Io)?;
    let connection = ServerConnection::new(config).map_err(LaneError::Tls)?;
    let mut sealed = Sealed::new(Connection::Server(connection), prefix);
    let hello_arrived = async {
        while complete_record(&sealed.inbound)?.is_none() {
            read_more(&socket, &mut sealed.inbound).await?;
        }
        Ok::<_, LaneError>(())
    };
    let waited = first_record.saturating_duration_since(Instant::now());
    timeout_at(first_record.min(deadline), hello_arrived).await.map_err(|_| LaneError::Deadline(waited))??;

    let rest = async {
        let mut out = BytesMut::new();
        handshake(&socket, &mut sealed, &mut out).await?;
        let key = sealed
            .connection()
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(LaneError::Protocol("对端未提供证书"))
            .and_then(|certificate| tls::peer_key(certificate).map_err(|_| LaneError::Protocol("无法从对端证书提取有效的 Ed25519 公钥")))?;
        let (peer, membership) = resolve(&key)
            .ok_or(LaneError::Tls(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)))?;
        let mut removed = membership.clone();
        let version = Version::of(sealed.connection());
        let mut lane = Lane { socket: Arc::new(socket), sealed, out, peer, membership, purpose: Purpose::Control, epoch: 0, version };
        let hello = tokio::select! {
            biased;
            _ = removed.changed() => return Err(LaneError::Closed),
            result = lane.read_frame() => result?,
        };
        match hello {
            Some(Frame::Hello { purpose, epoch }) => {
                lane.purpose = purpose;
                lane.epoch = epoch;
                // 这条 lane 可能要在池里空等很久：握手用过的读缓冲还回去。
                lane.sealed.shrink();
                Ok(lane)
            }
            _ => Err(LaneError::Protocol("lane 收到的首帧不是 HELLO")),
        }
    };
    let total = deadline.saturating_duration_since(Instant::now());
    timeout_at(deadline, rest).await.map_err(|_| LaneError::Deadline(total))?
}
