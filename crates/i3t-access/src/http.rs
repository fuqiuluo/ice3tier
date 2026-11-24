//! HTTP 代理的请求和应答。只有解析和编码，不碰 socket。
//!
//! 两种请求：
//!
//! - `CONNECT 主机:端口 HTTP/1.x`：隧道。请求头里只看 `Proxy-Authorization: Basic`，别的跳过。
//! - 完整地址的请求（`GET http://主机[:端口]/路径 HTTP/1.x`，任何方法）：明文 HTTP 的转发代理。用户名和密码和 `CONNECT`
//!   一样来自 `Proxy-Authorization`，去往 URL 里的主机和端口（不写是 80）。入口把请求头改写好（[`Forward::head`]）随 OPEN 发出，
//!   之后只搬这个请求的请求体（[`body`]）。
//!
//! 转发时请求头怎么改：请求行换成只有路径的写法；`Host` 换成 URL 里的；逐跳的头（`Connection`、`Keep-Alive`、`TE`、`Upgrade`，
//! 以及 `Connection` 里点名的）和全部 `Proxy-*` 都不往前传；最后加上 `Connection: close`。一条流只承载一个请求：
//! 目标回完应答就关连接，入口随之关掉客户端的连接，客户端在同一条连接上排在后面的请求不会被发出去。
//!
//! 能让入口和目标对请求的边界理解不一致的写法一律回 400：`Content-Length` 和 `Transfer-Encoding` 同时出现、任何一个出现两次、
//! `Content-Length` 不是纯数字、`Connection` 点名了决定边界的头、HTTP/1.0 的请求带 `Transfer-Encoding`。
//! `Transfer-Encoding` 只认 `chunked`，别的编码回 501；`https://` 的地址回 501（那要用 `CONNECT`）。

mod body;

use std::net::{IpAddr, Ipv6Addr};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use i3t_proto::flow::Host;

pub(crate) use self::body::{Body, BodyFraming};
use crate::message::{Parsed, Password, ProxyAuth};

/// 请求行与请求头的总长度上限（字节）。读取到此上限仍未遇到空行则拒绝请求，防止客户端迫使读取方无限缓存数据。
///
/// 明文 HTTP 的请求带着网站的 Cookie，常见的服务器收 8 KB 的一行、几十 KB 的整个请求头，所以取 32 KB。
pub(crate) const MAX_HEAD_LEN: usize = 32 * 1024;

const HEAD_END: &[u8] = b"\r\n\r\n";

/// 明文 HTTP 不写端口时的端口。
const HTTP_PORT: u16 = 80;

/// 请求不被接受的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HttpError {
    #[error("请求不合法：{0}")]
    Malformed(&'static str),
    #[error("请求头超过了 {MAX_HEAD_LEN} 字节")]
    TooLarge,
    #[error("不支持：{0}")]
    NotImplemented(&'static str),
}

impl HttpError {
    /// 出这个错时回给客户端的应答。
    pub(crate) const fn response(self) -> Response {
        match self {
            Self::Malformed(_) => Response::BadRequest,
            Self::TooLarge => Response::HeaderTooLarge,
            Self::NotImplemented(_) => Response::NotImplemented,
        }
    }
}

/// 客户端发来的一个代理请求。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Request {
    Connect(Connect),
    Forward(Forward),
}

/// 客户端的 CONNECT 请求。
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Connect {
    pub host: Host,
    pub port: u16,
    /// `Proxy-Authorization: Basic` 里的用户名和密码；没有带，或者用的不是 Basic 时是 `None`。
    pub auth: Option<ProxyAuth>,
}

/// 一个要转发给目标的明文 HTTP 请求。
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Forward {
    pub host: Host,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
    /// 改写好、要发给目标的请求行和请求头，以空行结尾。
    pub head: Vec<u8>,
    pub body: Body,
}

impl Request {
    /// 解析从连接上读到的字节。请求头还没有读完（没有见到空行）时返回 `None`。
    ///
    /// 返回的长度包含结尾的空行，它后面的字节是隧道里的数据，或者是请求体。
    pub(crate) fn parse(buf: &[u8]) -> Result<Option<Parsed<Self>>, HttpError> {
        let window = &buf[..buf.len().min(MAX_HEAD_LEN)];
        let Some(end) = window.windows(HEAD_END.len()).position(|bytes| bytes == HEAD_END) else {
            return if buf.len() >= MAX_HEAD_LEN { Err(HttpError::TooLarge) } else { Ok(None) };
        };
        let head = str::from_utf8(&buf[..end]).map_err(|_| HttpError::Malformed("请求头不是 UTF-8"))?;
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default();
        // 控制字符（落单的 CR、LF、NUL 也在内）一律不收：有的服务器把它们当空白或者行尾，入口和目标对请求行、
        // 请求头的切分就可能不一样。请求头的值里可以有制表符，请求行里不可以。
        if has_control(request_line, Tab::Refused) || lines.clone().any(|line| has_control(line, Tab::Allowed)) {
            return Err(HttpError::Malformed("请求头里有控制字符"));
        }

        let mut parts = request_line.split(' ');
        let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(HttpError::Malformed("请求行不是「方法 目标 版本」"));
        };
        if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
            return Err(HttpError::Malformed("不是 HTTP/1.x"));
        }
        if !is_token(method) {
            return Err(HttpError::Malformed("方法不合法"));
        }
        let fields = lines.map(Field::parse).collect::<Result<Vec<Field<'_>>, HttpError>>()?;
        let request = if method == "CONNECT" {
            let (host, port) = parse_authority(target, None).map_err(|_| HttpError::Malformed("CONNECT 的目标不是「主机:端口」"))?;
            Self::Connect(Connect { host, port, auth: authorization(&fields)? })
        } else {
            Self::Forward(Forward::new(method, target, version, &fields)?)
        };
        Ok(Some(Parsed { value: request, len: end + HEAD_END.len() }))
    }
}

/// 制表符算不算控制字符。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Allowed,
    Refused,
}

/// 这一行里有没有控制字符（0x00～0x1F 和 0x7F）。
fn has_control(line: &str, tab: Tab) -> bool {
    line.bytes().any(|byte| byte.is_ascii_control() && !(tab == Tab::Allowed && byte == b'\t'))
}

/// 请求头里的一行。
struct Field<'a> {
    name: &'a str,
    /// 去掉了首尾空白的值。
    value: &'a str,
    /// 原样的一整行。
    line: &'a str,
}

impl<'a> Field<'a> {
    fn parse(line: &'a str) -> Result<Self, HttpError> {
        let (name, value) = line.split_once(':').ok_or(HttpError::Malformed("请求头缺少冒号"))?;
        // 名字里不能有空白：续行（以空白开头的行）和「名字 :」都在这里被拒绝。
        if !is_token(name) {
            return Err(HttpError::Malformed("请求头的名字不合法"));
        }
        Ok(Self { name, value: value.trim_matches([' ', '\t']), line })
    }

    fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

/// `Proxy-Authorization` 里的 Basic 认证。出现两次是坏请求：两处理解不一样就能骗过其中一处。
fn authorization(fields: &[Field<'_>]) -> Result<Option<ProxyAuth>, HttpError> {
    let mut found = fields.iter().filter(|field| field.is("proxy-authorization"));
    let Some(field) = found.next() else { return Ok(None) };
    if found.next().is_some() {
        return Err(HttpError::Malformed("Proxy-Authorization 出现了两次"));
    }
    parse_basic(field.value)
}

/// 不往目标传的头：逐跳的，和代理自己的（`Proxy-Authorization` 里是用户名和密码）。`Host` 换成 URL 里的。
fn dropped(field: &Field<'_>) -> bool {
    ["connection", "keep-alive", "te", "upgrade", "host"].iter().any(|name| field.is(name))
        || field.name.get(..6).is_some_and(|prefix| prefix.eq_ignore_ascii_case("proxy-"))
}

impl Forward {
    fn new(method: &str, target: &str, version: &str, fields: &[Field<'_>]) -> Result<Self, HttpError> {
        let url = AbsoluteUrl::parse(target)?;
        let auth = authorization(fields)?;

        let mut length = None;
        let mut chunked = false;
        for field in fields {
            if field.is("content-length") {
                if length.is_some() {
                    return Err(HttpError::Malformed("Content-Length 出现了不止一次"));
                }
                length = Some(parse_length(field.value)?);
            } else if field.is("transfer-encoding") {
                if chunked {
                    return Err(HttpError::Malformed("Transfer-Encoding 出现了不止一次"));
                }
                if !field.value.eq_ignore_ascii_case("chunked") {
                    return Err(HttpError::NotImplemented("Transfer-Encoding 只支持 chunked"));
                }
                chunked = true;
            }
        }
        let body = match (length, chunked) {
            (Some(_), true) => return Err(HttpError::Malformed("Content-Length 和 Transfer-Encoding 同时出现")),
            (None, true) if version == "HTTP/1.0" => return Err(HttpError::Malformed("HTTP/1.0 的请求不能用 Transfer-Encoding")),
            (None, true) => Body::Chunked,
            (Some(length), false) => Body::Length(length),
            (None, false) => Body::Empty,
        };

        // `Connection`（和老式的 `Proxy-Connection`）里点名的头也是逐跳的。点名决定请求边界的头是坏请求：
        // 去掉它们，目标看到的边界就和入口算的不一样了。
        let named: Vec<&str> = fields
            .iter()
            .filter(|field| field.is("connection") || field.is("proxy-connection"))
            .flat_map(|field| field.value.split(','))
            .map(|token| token.trim_matches([' ', '\t']))
            .filter(|token| !token.is_empty())
            .collect();
        if named.iter().any(|token| ["content-length", "transfer-encoding", "host"].iter().any(|name| token.eq_ignore_ascii_case(name))) {
            return Err(HttpError::Malformed("Connection 里点名了决定请求边界的头"));
        }

        let mut head = format!("{method} {} {version}\r\nHost: {}\r\n", url.path, url.authority);
        for field in fields.iter().filter(|field| !dropped(field) && !named.iter().any(|token| field.is(token))) {
            head.push_str(field.line);
            head.push_str("\r\n");
        }
        head.push_str("Connection: close\r\n\r\n");
        Ok(Self { host: url.host, port: url.port, auth, head: head.into_bytes(), body })
    }
}

/// 完整地址里转发要用的部分。
struct AbsoluteUrl<'a> {
    host: Host,
    port: u16,
    /// `主机[:端口]`，原样，写进 `Host`。
    authority: &'a str,
    /// 路径和查询串，以 `/` 开头。
    path: String,
}

impl<'a> AbsoluteUrl<'a> {
    fn parse(target: &'a str) -> Result<Self, HttpError> {
        let Some((scheme, rest)) = target.split_once("://") else {
            return Err(HttpError::Malformed("请求目标不是以 http:// 开头的完整地址（当前端口为代理而非源站）"));
        };
        if scheme.eq_ignore_ascii_case("https") {
            return Err(HttpError::NotImplemented("https:// 的地址要用 CONNECT"));
        }
        if !scheme.eq_ignore_ascii_case("http") {
            return Err(HttpError::Malformed("只转发 http:// 的地址"));
        }
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(split);
        if authority.contains('@') {
            return Err(HttpError::Malformed("地址里不能带用户名"));
        }
        let (host, port) = parse_authority(authority, Some(HTTP_PORT)).map_err(|_| HttpError::Malformed("地址中的主机或端口无效"))?;
        let path = if path.starts_with('/') { path.to_owned() } else { format!("/{path}") };
        Ok(Self { host, port, authority, path })
    }
}

/// `Content-Length` 的值：只能是十进制数字，不能有符号、空白或者逗号分隔的几个值。
fn parse_length(value: &str) -> Result<u64, HttpError> {
    const BAD: HttpError = HttpError::Malformed("Content-Length 不是一个十进制数");
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BAD);
    }
    value.parse().map_err(|_| BAD)
}

/// RFC 9110 的 token：方法和请求头的名字只能由这些字符组成。
fn is_token(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// `主机:端口`，IPv6 地址要写在方括号里。`default_port` 是 `None` 时必须写端口。
fn parse_authority(text: &str, default_port: Option<u16>) -> Result<(Host, u16), ()> {
    let (host, port) = match text.strip_prefix('[') {
        Some(rest) => {
            let (address, after) = rest.split_once(']').ok_or(())?;
            let port = match after {
                "" => None,
                after => Some(after.strip_prefix(':').ok_or(())?),
            };
            (Host::Ip(IpAddr::V6(address.parse::<Ipv6Addr>().map_err(drop)?)), port)
        }
        None => {
            let (host, port) = match text.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (text, None),
            };
            // 不带方括号的冒号只能是端口前面那一个，所以这里出现 IPv6 地址说明写错了。
            let host = host.parse::<Host>().ok().filter(|host| !matches!(host, Host::Ip(IpAddr::V6(_)))).ok_or(())?;
            (host, port)
        }
    };
    let port = match port {
        // `u16` 的解析接受前面的加号，这里不接受。
        Some(port) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => port.parse::<u16>().map_err(drop)?,
        Some(_) => return Err(()),
        None => default_port.ok_or(())?,
    };
    if port == 0 {
        return Err(());
    }
    Ok((host, port))
}

/// `Basic <base64(用户名:密码)>`。用的不是 Basic 时当作没有带认证。
///
/// 按第一个冒号切分，所以用户名里不能有冒号（controller 不收这样的用户名）。
fn parse_basic(value: &str) -> Result<Option<ProxyAuth>, HttpError> {
    let Some((scheme, token)) = value.split_once(' ') else { return Ok(None) };
    if !scheme.eq_ignore_ascii_case("basic") {
        return Ok(None);
    }
    let decoded = STANDARD.decode(token.trim_matches(' ')).map_err(|_| HttpError::Malformed("Basic 认证不是合法的 base64"))?;
    let (username, password) = match decoded.iter().position(|&byte| byte == b':') {
        Some(colon) => (&decoded[..colon], &decoded[colon + 1..]),
        None => (&decoded[..], &[][..]),
    };
    let username = str::from_utf8(username).map_err(|_| HttpError::Malformed("用户名不是 UTF-8"))?.to_owned();
    Ok(Some(ProxyAuth { username, password: Password::new(password) }))
}

/// 代理回给客户端的应答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Response {
    /// 隧道已经建好，之后的字节原样转发。
    Established,
    BadRequest,
    ProxyAuthenticationRequired,
    Forbidden,
    TooManyRequests,
    HeaderTooLarge,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    /// 节点正在排空：返回 503 并提示客户端稍后重试。
    Draining,
    GatewayTimeout,
}

/// 一个失败的应答：没有正文，发完就关连接。`$extra` 是额外的响应头，每个以 `\r\n` 结尾。
macro_rules! failure {
    ($status:literal $(, $extra:literal)?) => {
        concat!("HTTP/1.1 ", $status, "\r\n", $($extra,)? "Content-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()
    };
}

impl Response {
    pub(crate) const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Established => b"HTTP/1.1 200 Connection established\r\n\r\n",
            Self::BadRequest => failure!("400 Bad Request"),
            Self::ProxyAuthenticationRequired => {
                failure!("407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"i3t\"\r\n")
            }
            Self::Forbidden => failure!("403 Forbidden"),
            Self::TooManyRequests => failure!("429 Too Many Requests"),
            Self::HeaderTooLarge => failure!("431 Request Header Fields Too Large"),
            Self::NotImplemented => failure!("501 Not Implemented"),
            Self::BadGateway => failure!("502 Bad Gateway"),
            Self::ServiceUnavailable => failure!("503 Service Unavailable"),
            Self::Draining => failure!("503 Service Unavailable", "Retry-After: 60\r\n"),
            Self::GatewayTimeout => failure!("504 Gateway Timeout"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Option<Parsed<Request>>, HttpError> {
        Request::parse(text.as_bytes())
    }

    fn connect(text: &str) -> Connect {
        match parse(text).unwrap().unwrap().value {
            Request::Connect(connect) => connect,
            Request::Forward(forward) => panic!("不是 CONNECT：{forward:?}"),
        }
    }

    fn forward(text: &str) -> Forward {
        match parse(text).unwrap().unwrap().value {
            Request::Forward(forward) => forward,
            Request::Connect(connect) => panic!("不是转发：{connect:?}"),
        }
    }

    fn head(text: &str) -> String {
        String::from_utf8(forward(text).head).unwrap()
    }

    fn basic(credentials: &[u8]) -> String {
        format!("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", STANDARD.encode(credentials))
    }

    #[test]
    fn connect_with_a_domain_target_is_parsed() {
        let text = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: curl/8.0\r\n\r\n";
        let parsed = parse(text).unwrap().unwrap();
        assert_eq!(parsed.len, text.len());
        assert_eq!(parsed.value, Request::Connect(Connect { host: "example.com".parse().unwrap(), port: 443, auth: None }));
    }

    #[test]
    fn connect_accepts_ipv4_and_bracketed_ipv6_targets() {
        assert_eq!(connect("CONNECT 10.66.0.5:22 HTTP/1.0\r\n\r\n").host, Host::Ip("10.66.0.5".parse().unwrap()));
        let v6 = connect("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n");
        assert_eq!((v6.host, v6.port), (Host::Ip("2001:db8::1".parse().unwrap()), 8443));
    }

    #[test]
    fn bytes_after_the_blank_line_belong_to_the_tunnel() {
        let head = "CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        let parsed = Request::parse(format!("{head}\x16\x03\x01early hello\r\n\r\n").as_bytes()).unwrap().unwrap();
        assert_eq!(parsed.len, head.len());
    }

    #[test]
    fn every_strict_prefix_of_a_request_is_incomplete() {
        let text = basic(b"nas-01:token");
        for len in 0..text.len() {
            assert_eq!(parse(&text[..len]), Ok(None), "前 {len} 字节");
        }
    }

    #[test]
    fn basic_authorization_is_split_at_the_first_colon() {
        let auth = connect(&basic(b"10.66.0.5+c-i:to:ken")).auth.unwrap();
        assert_eq!(auth.username, "10.66.0.5+c-i");
        assert_eq!(auth.password.as_bytes(), b"to:ken");

        let no_password = connect(&basic(b"nas-01")).auth.unwrap();
        assert_eq!((no_password.username.as_str(), no_password.password.as_bytes()), ("nas-01", &[][..]));

        let no_username = connect(&basic(b":token")).auth.unwrap();
        assert_eq!((no_username.username.as_str(), no_username.password.as_bytes()), ("", &b"token"[..]));
    }

    #[test]
    fn header_name_and_scheme_are_case_insensitive() {
        let text = format!("CONNECT example.com:443 HTTP/1.1\r\nproxy-AUTHORIZATION:\tbASIC {} \r\n\r\n", STANDARD.encode("u:p"));
        assert_eq!(connect(&text).auth.unwrap().username, "u");
    }

    #[test]
    fn other_authorization_schemes_count_as_no_credentials() {
        let text = "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer abc.def\r\n\r\n";
        assert_eq!(connect(text).auth, None);
        let text = "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic\r\n\r\n";
        assert_eq!(connect(text).auth, None);
    }

    #[test]
    fn an_absolute_url_is_forwarded_with_a_rewritten_head() {
        let text = format!(
            "POST http://Example.com/upload?x=1 HTTP/1.1\r\nHost: evil.example\r\nUser-Agent: curl/8\r\nProxy-Authorization: Basic {}\r\n\
             Proxy-Connection: Keep-Alive\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\nKeep-Alive: 300\r\nTE: trailers\r\nUpgrade: h2c\r\n\
             Content-Length: 5\r\nExpect: 100-continue\r\n\r\nhello",
            STANDARD.encode("gw:token")
        );
        let parsed = parse(&text).unwrap().unwrap();
        assert_eq!(&text[parsed.len..], "hello", "请求体不算在请求头里");
        let Request::Forward(forward) = parsed.value else { panic!("应该是转发") };
        assert_eq!((forward.host, forward.port), ("Example.com".parse().unwrap(), 80));
        assert_eq!(forward.auth.unwrap().username, "gw");
        assert_eq!(forward.body, Body::Length(5));
        assert_eq!(
            String::from_utf8(forward.head).unwrap(),
            "POST /upload?x=1 HTTP/1.1\r\nHost: Example.com\r\nUser-Agent: curl/8\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\
             Connection: close\r\n\r\n"
        );
    }

    #[test]
    fn the_url_decides_host_port_and_path() {
        let cases = [
            ("GET http://example.com HTTP/1.0\r\n\r\n", "example.com", 80, "GET / HTTP/1.0\r\nHost: example.com\r\n"),
            ("GET HTTP://example.com:8080?q HTTP/1.1\r\n\r\n", "example.com", 8080, "GET /?q HTTP/1.1\r\nHost: example.com:8080\r\n"),
            ("DELETE http://10.0.0.1:81/a/b HTTP/1.1\r\n\r\n", "10.0.0.1", 81, "DELETE /a/b HTTP/1.1\r\nHost: 10.0.0.1:81\r\n"),
            ("GET http://[2001:db8::1]/ HTTP/1.1\r\n\r\n", "2001:db8::1", 80, "GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\n"),
            ("GET http://[2001:db8::1]:8443/x HTTP/1.1\r\n\r\n", "2001:db8::1", 8443, "GET /x HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n"),
        ];
        for (text, host, port, start) in cases {
            let parsed = forward(text);
            assert_eq!((parsed.host, parsed.port), (host.parse().unwrap(), port), "{text:?}");
            let head = String::from_utf8(parsed.head).unwrap();
            assert!(head.starts_with(start) && head.ends_with("Connection: close\r\n\r\n"), "{text:?} → {head:?}");
            assert_eq!(parsed.body, Body::Empty);
        }
    }

    #[test]
    fn a_chunked_body_is_passed_on_as_chunked() {
        let text = "PUT http://example.com/ HTTP/1.1\r\nTransfer-Encoding: Chunked\r\nTrailer: X-Sum\r\n\r\n";
        let chunked = forward(text);
        assert_eq!(chunked.body, Body::Chunked);
        assert!(String::from_utf8(chunked.head).unwrap().contains("\r\nTransfer-Encoding: Chunked\r\nTrailer: X-Sum\r\n"));
        assert!(head("GET http://example.com/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n").contains("Content-Length: 0\r\n"));
        assert_eq!(forward("GET http://example.com/ HTTP/1.1\r\nContent-Length: 007\r\n\r\n").body, Body::Length(7));
    }

    #[test]
    fn every_proxy_header_and_every_hop_by_hop_header_stays_behind() {
        let text = "GET http://example.com/ HTTP/1.1\r\nPROXY-AUTHORIZATION: Basic Og==\r\nProxy-Foo: bar\r\nconnection: X-A,  x-b\r\n\
                    X-A: 1\r\nx-B: 2\r\nX-C: 3\r\nKEEP-ALIVE: 1\r\n\r\n";
        assert_eq!(head(text), "GET / HTTP/1.1\r\nHost: example.com\r\nX-C: 3\r\nConnection: close\r\n\r\n");
    }

    #[test]
    fn request_smuggling_shapes_are_bad_requests() {
        let cases = [
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: +5\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length:\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://example.com/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nConnection: Content-Length\r\nContent-Length: 5\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nConnection: close, transfer-encoding\r\n\r\n",
            "GET http://example.com/ HTTP/1.1\r\nProxy-Connection: Host\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length : 5\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\n Content-Length: 5\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nX: a\nContent-Length: 5\r\n\r\n",
            // 控制字符：有的服务器把它们当空白或者行尾。
            "GET http://example.com/a\tHTTP/1.1\tX HTTP/1.1\r\n\r\n",
            "GET http://example.com/\x0b HTTP/1.1\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nX: a\x0cContent-Length: 5\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nX: a\rContent-Length: 5\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nX: a\0b\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nX: a\x7fb\r\n\r\n",
        ];
        for text in cases {
            assert!(matches!(parse(text), Err(HttpError::Malformed(_))), "{text:?} → {:?}", parse(text));
        }
    }

    #[test]
    fn a_tab_inside_a_header_value_is_kept() {
        assert!(head("GET http://example.com/ HTTP/1.1\r\nX-Note: a\tb\r\n\r\n").contains("X-Note: a\tb\r\n"));
    }

    #[test]
    fn what_the_proxy_does_not_do_is_said_so() {
        let cases = [
            "POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n",
            "GET https://example.com/ HTTP/1.1\r\n\r\n",
        ];
        for text in cases {
            assert!(matches!(parse(text), Err(HttpError::NotImplemented(_))), "{text:?} → {:?}", parse(text));
        }
        assert_eq!(HttpError::NotImplemented("").response(), Response::NotImplemented);
    }

    #[test]
    fn requests_that_are_not_for_a_proxy_or_name_a_bad_target_are_bad_requests() {
        let cases = [
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "OPTIONS * HTTP/1.1\r\n\r\n",
            "GET ftp://example.com/ HTTP/1.1\r\n\r\n",
            "GET http://user:pass@example.com/ HTTP/1.1\r\n\r\n",
            "GET http:///path HTTP/1.1\r\n\r\n",
            "GET http://example.com:0/ HTTP/1.1\r\n\r\n",
            "GET http://example.com:/ HTTP/1.1\r\n\r\n",
            "GET http://example.com:+80/ HTTP/1.1\r\n\r\n",
            "GET http://2001:db8::1/ HTTP/1.1\r\n\r\n",
            "GET http://[2001:db8::1/ HTTP/1.1\r\n\r\n",
            "GET http://[2001:db8::1]x/ HTTP/1.1\r\n\r\n",
            "GET http://exa_mple!.com/ HTTP/1.1\r\n\r\n",
            "G(ET http://example.com/ HTTP/1.1\r\n\r\n",
        ];
        for text in cases {
            assert!(matches!(parse(text), Err(HttpError::Malformed(_))), "{text:?} → {:?}", parse(text));
        }
    }

    #[test]
    fn malformed_requests_are_rejected() {
        let cases = [
            "CONNECT example.com:443\r\n\r\n",
            "CONNECT  example.com:443 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1 extra\r\n\r\n",
            "CONNECT example.com:443 HTTP/2.0\r\n\r\n",
            "CONNECT example.com:443 http/1.1\r\n\r\n",
            "CONNECT example.com HTTP/1.1\r\n\r\n",
            "CONNECT example.com:0 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:+443 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:65536 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:44a HTTP/1.1\r\n\r\n",
            "CONNECT :443 HTTP/1.1\r\n\r\n",
            "CONNECT exa mple.com:443 HTTP/1.1\r\n\r\n",
            "CONNECT 2001:db8::1:443 HTTP/1.1\r\n\r\n",
            "CONNECT [example.com]:443 HTTP/1.1\r\n\r\n",
            "CONNECT [2001:db8::1:443 HTTP/1.1\r\n\r\n",
            "CONNECT [2001:db8::1] HTTP/1.1\r\n\r\n",
            "CONNECT http://example.com:443/ HTTP/1.1\r\n\r\n",
            "(CONNECT) example.com:443 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nno colon here\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nHost : example.com\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nHost: a\r\n folded: b\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nHost: a\nX: b\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nHost: a\0b\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic !!!not-base64!!!\r\n\r\n",
            "\r\n\r\n",
        ];
        for text in cases {
            assert!(matches!(parse(text), Err(HttpError::Malformed(_))), "{text:?} → {:?}", parse(text));
        }
        assert_eq!(Request::parse(b"CONNECT \xff\xfe:443 HTTP/1.1\r\n\r\n"), Err(HttpError::Malformed("请求头不是 UTF-8")));
        assert_eq!(HttpError::Malformed("").response(), Response::BadRequest);
    }

    #[test]
    fn duplicate_authorization_headers_are_rejected() {
        let credentials = STANDARD.encode("u:p");
        for start in ["CONNECT example.com:443", "GET http://example.com/"] {
            let text =
                format!("{start} HTTP/1.1\r\nProxy-Authorization: Basic {credentials}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n");
            assert!(matches!(parse(&text), Err(HttpError::Malformed(_))), "{start}");
        }
    }

    #[test]
    fn a_username_that_is_not_utf8_is_rejected() {
        assert!(matches!(parse(&basic(b"\xff\xfe:token")), Err(HttpError::Malformed(_))));
    }

    #[test]
    fn a_head_that_never_ends_is_cut_off_at_the_limit() {
        let mut flood = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        while flood.len() < MAX_HEAD_LEN - 1 {
            flood.extend_from_slice(b"X-Padding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
            flood.truncate(MAX_HEAD_LEN - 1);
        }
        assert_eq!(Request::parse(&flood), Ok(None));
        flood.push(b'a');
        assert_eq!(Request::parse(&flood), Err(HttpError::TooLarge));
        // 空行落在上限之外也不算数。
        flood.extend_from_slice(b"\r\n\r\n");
        assert_eq!(Request::parse(&flood), Err(HttpError::TooLarge));
        assert_eq!(HttpError::TooLarge.response(), Response::HeaderTooLarge);
    }

    #[test]
    fn responses_are_complete_http_messages() {
        assert_eq!(Response::Established.as_bytes(), b"HTTP/1.1 200 Connection established\r\n\r\n");
        let unauthorized = str::from_utf8(Response::ProxyAuthenticationRequired.as_bytes()).unwrap();
        assert!(unauthorized.starts_with("HTTP/1.1 407 "));
        assert!(unauthorized.contains("\r\nProxy-Authenticate: Basic realm=\"i3t\"\r\n"));

        let failures = [
            (Response::BadRequest, "400"),
            (Response::ProxyAuthenticationRequired, "407"),
            (Response::Forbidden, "403"),
            (Response::TooManyRequests, "429"),
            (Response::HeaderTooLarge, "431"),
            (Response::NotImplemented, "501"),
            (Response::BadGateway, "502"),
            (Response::ServiceUnavailable, "503"),
            (Response::GatewayTimeout, "504"),
        ];
        for (response, status) in failures {
            let text = str::from_utf8(response.as_bytes()).unwrap();
            assert!(text.starts_with(&format!("HTTP/1.1 {status} ")), "{text}");
            assert!(text.ends_with("\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), "{text}");
        }
    }
}
