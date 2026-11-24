//! 经上游 SOCKS5 代理去连目标。
//!
//! 出口可以配置一个本机的 SOCKS5 代理（`upstream_socks5`），把流交给它去连，而不是自己直接连。
//! 此处实现 SOCKS5 客户端侧，仅执行无认证 CONNECT，且目标一律使用解析后的 IP 地址：域名已在出口完成解析并通过出站策略校验，
//! 交域名给上游的话它会再解析一次，结果可能和检查过的不一样。

use std::net::{IpAddr, SocketAddr};

use i3t_proto::flow::{Reply, Status};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VERSION: u8 = 0x05;
const METHOD_NONE: u8 = 0x00;
const COMMAND_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// 在一条已经连到上游代理的连接上，请它去连 `target`。成功之后这条连接就是到目标的通道。
///
/// 将问候与连接请求合并在单次写入中发送，不等待上游回复问候，可减少一次往返；若上游不支持无认证方式，首个应答会立即体现。
///
/// # Errors
///
/// 上游按 SOCKS5 的应答码拒绝时，翻译成对应的状态（目标拒绝连接、不可达等）；上游本身不对劲时是 [`Status::InternalError`]。
pub(crate) async fn connect(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), target: SocketAddr) -> Result<(), Reply> {
    let broken = |what: &str| Reply::new(Status::InternalError, format!("上游代理{what}"));

    let mut request = vec![VERSION, 1, METHOD_NONE, VERSION, COMMAND_CONNECT, 0x00];
    match target.ip().to_canonical() {
        IpAddr::V4(ip) => {
            request.push(ATYP_V4);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(ATYP_V6);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.map_err(|_| broken("断开了连接"))?;

    let mut selection = [0; 2];
    stream.read_exact(&mut selection).await.map_err(|_| broken("断开了连接"))?;
    if selection != [VERSION, METHOD_NONE] {
        return Err(broken("拒绝无认证连接，或协议不是 SOCKS5"));
    }

    let mut head = [0; 4];
    stream.read_exact(&mut head).await.map_err(|_| broken("断开了连接"))?;
    let [version, code, _reserved, address_type] = head;
    if version != VERSION {
        return Err(broken("的应答不是 SOCKS5"));
    }
    // 应答后紧跟上游绑定地址，此处无需使用，但必须读取完毕，其后即为目标数据流。
    let bound_len = match address_type {
        ATYP_V4 => 4 + 2,
        ATYP_V6 => 16 + 2,
        ATYP_DOMAIN => usize::from(stream.read_u8().await.map_err(|_| broken("断开了连接"))?) + 2,
        _ => return Err(broken("的应答包含不支持的地址类型")),
    };
    let mut bound = [0; u8::MAX as usize + 2];
    stream.read_exact(&mut bound[..bound_len]).await.map_err(|_| broken("断开了连接"))?;

    let status = match code {
        0x00 => return Ok(()),
        0x02 => Status::PolicyDenied,
        0x03 | 0x04 => Status::Unreachable,
        0x05 => Status::ConnectionRefused,
        0x06 => Status::TimedOut,
        _ => Status::InternalError,
    };
    Err(Reply::new(status, format!("上游代理的应答码是 {code:#04x}")))
}

#[cfg(test)]
mod tests {
    use tokio::io::DuplexStream;

    use super::*;

    /// 扮演上游代理：读走客户端一次写来的全部请求，回 `answer`，再回一点"目标的数据"。
    async fn upstream(mut far: DuplexStream, expected_request: Vec<u8>, answer: Vec<u8>) {
        let mut request = vec![0; expected_request.len()];
        far.read_exact(&mut request).await.unwrap();
        assert_eq!(request, expected_request);
        far.write_all(&answer).await.unwrap();
        far.write_all(b"banner").await.unwrap();
    }

    fn answer(code: u8, bound: &[u8]) -> Vec<u8> {
        [&[5, 0, 5, code, 0][..], bound].concat()
    }

    const BOUND_V4: [u8; 7] = [1, 10, 0, 0, 1, 0x1f, 0x90];

    #[tokio::test]
    async fn greeting_and_request_go_out_together_and_the_tunnel_starts_right_after_the_reply() {
        let (mut near, far) = tokio::io::duplex(1024);
        let expected = vec![5, 1, 0, 5, 1, 0, 1, 93, 184, 216, 34, 0x01, 0xbb];
        let proxy = tokio::spawn(upstream(far, expected, answer(0, &BOUND_V4)));
        connect(&mut near, "93.184.216.34:443".parse().unwrap()).await.unwrap();
        let mut banner = [0; 6];
        near.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"banner", "应答后面绑定的地址要读干净，不能混进目标的数据");
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_targets_and_every_form_of_bound_address_are_handled() {
        let target: SocketAddr = "[2606:4700::1111]:80".parse().unwrap();
        let IpAddr::V6(ip) = target.ip() else { unreachable!() };
        let expected = [&[5, 1, 0, 5, 1, 0, 4][..], &ip.octets(), &[0, 80]].concat();
        let bound_v6 = [&[4][..], &[0; 16], &[0, 0]].concat();
        let bound_domain = [&[3, 5][..], b"proxy", &[0, 0]].concat();
        for bound in [bound_v6, bound_domain] {
            let (mut near, far) = tokio::io::duplex(1024);
            let proxy = tokio::spawn(upstream(far, expected.clone(), answer(0, &bound)));
            connect(&mut near, target).await.unwrap();
            let mut banner = [0; 6];
            near.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"banner");
            proxy.await.unwrap();
        }
    }

    #[tokio::test]
    async fn reply_codes_of_the_upstream_keep_their_attribution() {
        let cases = [
            (0x05, Status::ConnectionRefused),
            (0x03, Status::Unreachable),
            (0x04, Status::Unreachable),
            (0x06, Status::TimedOut),
            (0x02, Status::PolicyDenied),
            (0x01, Status::InternalError),
            (0x07, Status::InternalError),
        ];
        for (code, status) in cases {
            let (mut near, far) = tokio::io::duplex(1024);
            let expected = vec![5, 1, 0, 5, 1, 0, 1, 93, 184, 216, 34, 0, 80];
            let proxy = tokio::spawn(upstream(far, expected, answer(code, &BOUND_V4)));
            let reply = connect(&mut near, "93.184.216.34:80".parse().unwrap()).await.unwrap_err();
            assert_eq!(reply.status, status, "应答码 {code:#04x}");
            proxy.await.unwrap();
        }
    }

    #[tokio::test]
    async fn an_upstream_that_misbehaves_is_a_failure_of_the_exit() {
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let answers: [&[u8]; 5] = [
            // 要求认证
            &[5, 2],
            // 没有可用的方法
            &[5, 0xff],
            // 根本不是 SOCKS5
            b"HTTP/1.1 400 Bad Request\r\n\r\n",
            // 应答里的地址类型不认识
            &[5, 0, 5, 0, 0, 9, 0, 0],
            // 应答到一半就断了
            &[5, 0, 5, 0],
        ];
        for bytes in answers {
            let (mut near, mut far) = tokio::io::duplex(1024);
            far.write_all(bytes).await.unwrap();
            far.shutdown().await.unwrap();
            let reply = connect(&mut near, target).await.unwrap_err();
            assert_eq!(reply.status, Status::InternalError, "{bytes:02x?}");
        }
    }
}
