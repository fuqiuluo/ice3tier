//! 一个代理端口上的设置：controller 下发的代理（netmap 里的 `me.proxies`），或者本机配置文件里的组网入口（[`LocalEntry`]）。

use std::net::SocketAddr;

use i3t_flow::Carriage;
use i3t_model::netmap::{ListenerProtocol, Proxy, Verifier};
use i3t_proto::NodeId;
use i3t_proto::flow::Class;
use subtle::ConstantTimeEq;

use crate::message::ProxyAuth;

/// 本机配置文件定义的组网入口（`config.toml` 的 `[proxy]`）：无需认证，不经出口节点，仅可访问组网内的节点。
///
/// 该入口仅供本机程序使用，配置文件仅接受回环地址。若绑定地址非回环地址，则与未配置凭据的非回环代理一样拒绝所有请求。
/// 该入口不由 controller 下发，不支持 ice3proxy 选项，其流仅通过共用连接传输。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEntry {
    /// 上报和日志里的名字（`local-socks5`、`local-http`）。
    pub name: String,
    pub bind: SocketAddr,
    pub protocol: ListenerProtocol,
}

/// 一条连接进来时用到的设置，按它进来那一刻的 netmap 取。
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry {
    pub protocol: ListenerProtocol,
    /// 不在组网里的目标经哪个节点出去；本机的组网入口没有，这样的目标一律拒绝。
    pub exit: Option<NodeId>,
    pub gate: Gate,
    pub class: Option<Class>,
    pub optimistic: Option<bool>,
    /// 这个端口上的 TCP 流能不能走 ice3proxy：只有选了它的代理（[`Proxy::lane`]）能。
    pub carriage: Carriage,
}

impl Entry {
    pub(crate) fn proxy(proxy: &Proxy) -> Self {
        Self {
            protocol: proxy.protocol,
            exit: Some(proxy.exit),
            gate: Gate::of(proxy.bind, proxy.auth),
            class: proxy.class,
            optimistic: proxy.optimistic,
            carriage: if proxy.lane { Carriage::Lane } else { Carriage::Shared },
        }
    }

    pub(crate) fn local(entry: &LocalEntry) -> Self {
        Self {
            protocol: entry.protocol,
            exit: None,
            gate: Gate::of(entry.bind, None),
            class: None,
            optimistic: None,
            carriage: Carriage::Shared,
        }
    }
}

/// 谁能用这个端口。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// 回环地址上、没有设用户名和密码：本机的程序都能用，客户端给了用户名和密码也不看。
    Open,
    /// 要对上用户名和密码。
    Verify(Verifier),
    /// 绑定在非回环地址且未配置用户名和密码：拒绝所有请求。controller 不会下发此类代理，仅静态模式 netmap 可能出现。
    Closed,
}

impl Gate {
    /// 不在回环地址上的端口一定要认证，不管 netmap 里怎么写：能连到它的不只是本机的程序。
    fn of(bind: SocketAddr, auth: Option<Verifier>) -> Self {
        match auth {
            Some(verifier) => Self::Verify(verifier),
            None if bind.ip().is_loopback() => Self::Open,
            None => Self::Closed,
        }
    }

    /// 客户端必须给用户名和密码。
    pub(crate) const fn needs_password(self) -> bool {
        !matches!(self, Self::Open)
    }

    /// 客户端给的认证（没有给时是 `None`）让不让它用。比较是常量时间的。
    pub(crate) fn admits(self, auth: Option<&ProxyAuth>) -> bool {
        match (self, auth) {
            (Self::Open, _) => true,
            (Self::Verify(verifier), Some(auth)) => {
                let presented = verifier.hash_of(auth.username.as_bytes(), auth.password.as_bytes());
                bool::from(presented.ct_eq(&verifier.hash.0))
            }
            (Self::Verify(_), None) | (Self::Closed, _) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Password;

    fn auth(username: &str, password: &str) -> ProxyAuth {
        ProxyAuth { username: username.into(), password: Password::new(password.as_bytes()) }
    }

    #[test]
    fn a_loopback_port_without_credentials_admits_anyone_and_ignores_what_they_send() {
        let gate = Gate::of("127.0.0.1:1080".parse().unwrap(), None);
        assert_eq!(gate, Gate::Open);
        assert!(!gate.needs_password());
        assert!(gate.admits(None) && gate.admits(Some(&auth("anyone", "anything"))));
        assert_eq!(Gate::of("[::1]:1080".parse().unwrap(), None), Gate::Open);
    }

    #[test]
    fn a_configured_user_name_and_password_must_both_match() {
        let verifier = Verifier::derive([3; 16], b"alice", b"s3cret");
        for bind in ["127.0.0.1:1080", "0.0.0.0:1080"] {
            let gate = Gate::of(bind.parse().unwrap(), Some(verifier));
            assert!(gate.needs_password());
            assert!(gate.admits(Some(&auth("alice", "s3cret"))));
            for (username, password) in [("alice", "wrong"), ("bob", "s3cret"), ("alice", ""), ("", "")] {
                assert!(!gate.admits(Some(&auth(username, password))), "{username}:{password}");
            }
            assert!(!gate.admits(None), "没有给认证");
        }
    }

    #[test]
    fn a_port_off_loopback_without_credentials_admits_nobody() {
        let gate = Gate::of("192.168.1.5:1080".parse().unwrap(), None);
        assert_eq!(gate, Gate::Closed);
        assert!(gate.needs_password());
        assert!(!gate.admits(None) && !gate.admits(Some(&auth("", ""))));
    }
}
