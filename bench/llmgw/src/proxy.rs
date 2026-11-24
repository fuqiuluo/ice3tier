//! 负载端到上游的第一段链路：直连或经 ice3tier 代理（SOCKS5、HTTP CONNECT）。出口选择由代理决定，
//! URL 中的用户名和密码用于代理认证（回环地址上无需认证的代理可省略）。

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 代理的用户名和密码。
#[derive(Clone, PartialEq, Eq)]
pub struct Auth {
    pub user: String,
    pub password: String,
}

// 密码可能是接入凭据，不打出来。
impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Auth").field("user", &self.user).finish_non_exhaustive()
    }
}

/// 怎么到达上游。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proxy {
    /// 不经代理，作为对照。
    Direct,
    Socks5 {
        server: String,
        auth: Option<Auth>,
    },
    Http {
        server: String,
        auth: Option<Auth>,
    },
}

impl FromStr for Proxy {
    type Err = String;

    /// `direct`、`socks5://[用户名[:密码]@]主机:端口`（`socks5h://` 相同：目标总是原样交给代理）、
    /// `http://[用户名[:密码]@]主机:端口`。
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "direct" {
            return Ok(Self::Direct);
        }
        let (scheme, rest) =
            text.split_once("://").ok_or_else(|| format!("代理地址 {text:?} 缺少 scheme，例如 socks5://用户名:密码@127.0.0.1:1080"))?;
        let rest = rest.trim_end_matches('/');
        // 用户名里可能有点号，没有 @；主机部分在最后一个 @ 之后。
        let (userinfo, server) = match rest.rsplit_once('@') {
            Some((userinfo, server)) => (Some(userinfo), server),
            None => (None, rest),
        };
        if server.rsplit_once(':').is_none_or(|(_, port)| port.parse::<u16>().is_err()) {
            return Err(format!("代理地址 {text:?} 里没有端口"));
        }
        let auth = userinfo.map(|userinfo| match userinfo.split_once(':') {
            Some((user, password)) => Auth { user: user.to_owned(), password: password.to_owned() },
            None => Auth { user: userinfo.to_owned(), password: String::new() },
        });
        let server = server.to_owned();
        match scheme {
            "socks5" | "socks5h" => Ok(Self::Socks5 { server, auth }),
            "http" => Ok(Self::Http { server, auth }),
            other => Err(format!("不支持的代理类型 {other:?}：只支持 socks5 和 http（CONNECT）")),
        }
    }
}

impl fmt::Display for Proxy {
    /// 不带密码的写法，用在报告里。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (scheme, server, auth) = match self {
            Self::Direct => return f.write_str("direct"),
            Self::Socks5 { server, auth } => ("socks5", server, auth),
            Self::Http { server, auth } => ("http", server, auth),
        };
        match auth {
            Some(auth) => write!(f, "{scheme}://{}@{server}", auth.user),
            None => write!(f, "{scheme}://{server}"),
        }
    }
}

/// 建立隧道失败。细分错误类型以便在结果中区分"无法连接代理"、"代理拒绝"和"握手过程出错"。
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("连接失败")]
    Connect(#[source] io::Error),
    #[error("代理拒绝：{0}")]
    Refused(String),
    #[error("和代理握手时出错")]
    Io(#[from] io::Error),
}

/// `host:port`，IPv6 地址加方括号。
pub fn authority(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("[{ip}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

impl Proxy {
    /// 建一条到 `host:port` 的 TCP 隧道。返回时隧道已经可以收发上游的字节。
    ///
    /// # Errors
    ///
    /// 见 [`ProxyError`]。
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, ProxyError> {
        let server = match self {
            Self::Direct => authority(host, port),
            Self::Socks5 { server, .. } | Self::Http { server, .. } => server.clone(),
        };
        let mut stream = TcpStream::connect(&server).await.map_err(ProxyError::Connect)?;
        // 网关发的是小块的请求和消息，不能让 Nagle 攒着。
        stream.set_nodelay(true).map_err(ProxyError::Connect)?;
        match self {
            Self::Direct => {}
            Self::Socks5 { auth, .. } => socks5_handshake(&mut stream, auth.as_ref(), host, port).await?,
            Self::Http { auth, .. } => http_connect(&mut stream, auth.as_ref(), host, port).await?,
        }
        Ok(stream)
    }
}

/// RFC 1928 的 CONNECT，有用户名时用 RFC 1929 的用户名密码认证。
async fn socks5_handshake(stream: &mut TcpStream, auth: Option<&Auth>, host: &str, port: u16) -> Result<(), ProxyError> {
    let method = if auth.is_some() { 0x02 } else { 0x00 };
    stream.write_all(&[0x05, 0x01, method]).await?;
    let mut choice = [0_u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice != [0x05, method] {
        return Err(ProxyError::Refused(format!("代理没有选我们提供的认证方式（回答 {choice:02x?}）")));
    }
    if let Some(auth) = auth {
        let user = u8::try_from(auth.user.len()).map_err(|_| ProxyError::Refused("用户名超过 255 字节".into()))?;
        let password = u8::try_from(auth.password.len()).map_err(|_| ProxyError::Refused("密码超过 255 字节".into()))?;
        let mut message = vec![0x01, user];
        message.extend_from_slice(auth.user.as_bytes());
        message.push(password);
        message.extend_from_slice(auth.password.as_bytes());
        stream.write_all(&message).await?;
        let mut status = [0_u8; 2];
        stream.read_exact(&mut status).await?;
        if status[1] != 0 {
            return Err(ProxyError::Refused(format!("用户名 {:?} 认证失败（状态 {}）", auth.user, status[1])));
        }
    }
    stream.write_all(&socks5_request(host, port)?).await?;
    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(ProxyError::Refused(socks5_reply_text(reply[1]).to_owned()));
    }
    // 回答里绑定的地址没有用，但要读掉，后面才是上游的字节。
    let address_len = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        other => return Err(ProxyError::Refused(format!("代理响应包含未知的地址类型：{other}"))),
    };
    let mut rest = vec![0_u8; address_len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

fn socks5_request(host: &str, port: u16) -> Result<Vec<u8>, ProxyError> {
    let mut request = vec![0x05, 0x01, 0x00];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let len = u8::try_from(host.len()).map_err(|_| ProxyError::Refused("域名超过 255 字节".into()))?;
            request.push(0x03);
            request.push(len);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

fn socks5_reply_text(code: u8) -> &'static str {
    match code {
        0x01 => "一般性失败（01）",
        0x02 => "规则不允许（02）",
        0x03 => "网络不可达（03）",
        0x04 => "主机不可达（04）",
        0x05 => "连接被拒绝（05）",
        0x06 => "TTL 过期（06）",
        0x07 => "不支持的命令（07）",
        0x08 => "不支持的地址类型（08）",
        _ => "未知错误码",
    }
}

/// HTTP CONNECT。用户名密码放在 `Proxy-Authorization: Basic` 里。
async fn http_connect(stream: &mut TcpStream, auth: Option<&Auth>, host: &str, port: u16) -> Result<(), ProxyError> {
    let target = authority(host, port);
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(auth) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", auth.user, auth.password));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    // 一个字节一个字节地读到空行：多读一个字节就是上游的了，而这里没有地方放它。头部只有几十个字节。
    let mut head = Vec::with_capacity(128);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err(ProxyError::Refused("代理的回答头部太长".into()));
        }
        head.push(stream.read_u8().await?);
    }
    let response = crate::http::ResponseHead::parse(&head)?;
    if !(200..300).contains(&response.status) {
        return Err(ProxyError::Refused(format!("HTTP {} {}", response.status, response.reason)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn proxy_urls_parse_with_dotted_user_names_and_display_without_passwords() {
        let socks: Proxy = "socks5h://u-1a2b.3c@127.0.0.1:1080".parse().unwrap();
        assert_eq!(
            socks,
            Proxy::Socks5 { server: "127.0.0.1:1080".into(), auth: Some(Auth { user: "u-1a2b.3c".into(), password: String::new() }) }
        );
        let http: Proxy = "http://gateway:secret@gw:3128/".parse().unwrap();
        assert_eq!(http, Proxy::Http { server: "gw:3128".into(), auth: Some(Auth { user: "gateway".into(), password: "secret".into() }) });
        assert_eq!(http.to_string(), "http://gateway@gw:3128");
        assert_eq!("socks5://127.0.0.1:1080".parse::<Proxy>().unwrap(), Proxy::Socks5 { server: "127.0.0.1:1080".into(), auth: None });
        assert_eq!("direct".parse::<Proxy>().unwrap(), Proxy::Direct);
        assert!("socks4://a:1".parse::<Proxy>().is_err());
        assert!("socks5://127.0.0.1".parse::<Proxy>().is_err());
    }

    #[test]
    fn socks5_requests_name_the_target_by_its_address_type() {
        assert_eq!(socks5_request("11.0.0.6", 443).unwrap(), vec![5, 1, 0, 1, 11, 0, 0, 6, 1, 187]);
        assert_eq!(socks5_request("api", 80).unwrap(), vec![5, 1, 0, 3, 3, b'a', b'p', b'i', 0, 80]);
        assert_eq!(socks5_request("::1", 80).unwrap()[3], 4);
        assert_eq!(authority("::1", 443), "[::1]:443");
    }

    /// 一个假的 SOCKS5 代理：检查握手的每一步，回答成功，然后回显隧道里的字节。
    #[tokio::test]
    async fn socks5_handshake_with_user_name_then_tunnel_carries_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            conn.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            conn.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0_u8; 7];
            conn.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth, [1, 3, b'g', b'w', b'1', 1, b'p']);
            conn.write_all(&[1, 0]).await.unwrap();
            let mut request = [0_u8; 10];
            conn.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 1, 11, 0, 0, 6, 1, 187]);
            // 回答里用域名形式的绑定地址，客户端要按长度读掉它。
            conn.write_all(&[5, 0, 0, 3, 2, b'h', b'i', 0, 1]).await.unwrap();
            let mut ping = [0_u8; 4];
            conn.read_exact(&mut ping).await.unwrap();
            conn.write_all(&ping).await.unwrap();
        });
        let proxy: Proxy = format!("socks5://gw1:p@{addr}").parse().unwrap();
        let mut tunnel = proxy.connect("11.0.0.6", 443).await.unwrap();
        tunnel.write_all(b"ping").await.unwrap();
        let mut echo = [0_u8; 4];
        tunnel.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_failure_codes_and_http_errors_are_refusals() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            conn.read_exact(&mut greeting).await.unwrap();
            conn.write_all(&[5, 0]).await.unwrap();
            let mut request = [0_u8; 10];
            conn.read_exact(&mut request).await.unwrap();
            conn.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();

            let (mut conn, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(conn.read_u8().await.unwrap());
            }
            let text = String::from_utf8(head).unwrap();
            assert!(text.starts_with("CONNECT 11.0.0.6:443 HTTP/1.1\r\n"), "{text}");
            // "ex1:" 的 base64。
            assert!(text.contains("Proxy-Authorization: Basic ZXgxOg==\r\n"), "{text}");
            conn.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await.unwrap();
        });
        let socks: Proxy = format!("socks5://{addr}").parse().unwrap();
        let err = socks.connect("11.0.0.6", 443).await.unwrap_err();
        assert!(matches!(&err, ProxyError::Refused(text) if text.contains("05")), "{err}");
        let http: Proxy = format!("http://ex1@{addr}").parse().unwrap();
        let err = http.connect("11.0.0.6", 443).await.unwrap_err();
        assert!(matches!(&err, ProxyError::Refused(text) if text.contains("407")), "{err}");
        server.await.unwrap();
    }
}
