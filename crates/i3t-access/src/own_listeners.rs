//! 本节点的程序自己在监听的地址。
//!
//! 别的节点要访问本节点的一个端口（或者出口所在局域网里的一个地址）时，出口用本机的地址去连。连到的要是这个程序自己的监听，
//! 那条连接的来源就是本机自己的地址：监听按来源做的检查（来源白名单、只收本机和对端的虚拟 IP、只答本机的查询）
//! 看到的是本机，而不是真正来访问的那个节点。所以这些地址出口不去连，这里就是它查的那张表。
//!
//! 入口往里登记它的代理、组网入口和端口转发，装配层登记程序里别处的监听（虚拟网卡的名字服务）。

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use i3t_model::netmap::ForwardProtocol;

/// 本节点的程序自己在监听的一个地址。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnListener {
    /// TCP 的监听还是 UDP 的端口。
    pub protocol: ForwardProtocol,
    /// 实际绑定的地址：配置端口为 0 时，此处为系统分配的端口。
    pub local: SocketAddr,
    /// 是端口转发的监听时，它的编号。
    pub forward: Option<u32>,
}

impl OwnListener {
    /// 发往本机的地址 `addr` 的连接（`protocol` 是 UDP 时是报文）是不是落在这个监听上。
    /// IPv4 映射的 IPv6 地址按里面的 IPv4 地址算。
    ///
    /// `addr` 要是本机的地址，这由调用方保证：监听在全部地址上的，哪个地址上的这个端口都算它的，拿别的机器的地址来问也会说"是"。
    /// `[::]` 在有的系统上不收 IPv4 的，这里也按收算，宁可少连一个地址，不把来源洗成本机。
    #[must_use]
    pub fn receives(&self, protocol: ForwardProtocol, addr: SocketAddr) -> bool {
        let wanted = addr.ip().to_canonical();
        let covers = match self.local.ip().to_canonical() {
            IpAddr::V4(ip) if ip.is_unspecified() => wanted.is_ipv4(),
            IpAddr::V6(ip) if ip.is_unspecified() => true,
            ip => ip == wanted,
        };
        self.protocol == protocol && self.local.port() == addr.port() && covers
    }
}

/// 本节点的程序自己现在在监听的全部地址。克隆出来的是同一份。
#[derive(Debug, Clone, Default)]
pub struct OwnListeners {
    shared: Arc<Shared>,
}

#[derive(Debug, Default)]
struct Shared {
    /// 每次登记或撤销 TCP 监听时递增：用于判断先前缓存的查询结果是否仍然有效。
    tcp_generation: AtomicU64,
    /// 同上，UDP 的。
    udp_generation: AtomicU64,
    next_claim: AtomicU64,
    held: Mutex<Vec<Held>>,
}

impl Shared {
    const fn generation(&self, protocol: ForwardProtocol) -> &AtomicU64 {
        match protocol {
            ForwardProtocol::Tcp => &self.tcp_generation,
            ForwardProtocol::Udp => &self.udp_generation,
        }
    }
}

#[derive(Debug)]
struct Held {
    claim: u64,
    listener: OwnListener,
}

impl OwnListeners {
    /// 登记一个监听，返回的凭据丢掉时撤销。
    ///
    /// 必须在监听器可接收流量前完成登记，避免出现“已开始接收但出口尚不知情”的时间窗口：TCP 监听在绑定之后、开始 listen 之前登记
    /// （此间隙内不会接受连接）；UDP 端口一经绑定即可收包，需在绑定后立即登记。绑定失败后会定期重试的监听仅在绑定成功后登记：
    /// 否则每次重试都登记再撤销，会将其他程序占用的端口误判为本程序监听，并导致版本号无谓递增。仅尝试绑定一次、不重试的监听，
    /// 可在绑定前登记，绑定失败时释放凭据即可。撤销登记须在监听器彻底关闭之后进行。
    #[must_use = "凭据一丢掉，登记就撤销了"]
    pub fn claim(&self, listener: OwnListener) -> Claim {
        let claim = self.shared.next_claim.fetch_add(1, Ordering::Relaxed);
        self.held().push(Held { claim, listener });
        // 先改表再改版本号：读到新版本号的一定读得到新的表。
        self.shared.generation(listener.protocol).fetch_add(1, Ordering::SeqCst);
        Claim { listeners: self.clone(), claim, protocol: listener.protocol }
    }

    /// `protocol` 这一种监听每次登记、撤销之后都不一样。记着"某个地址可以连"这类结论的地方，看到它变了就重新查。
    /// 两种协议各算各的：TCP 的监听变了，和 UDP 的报文发到哪里没有关系。
    #[must_use]
    pub fn generation(&self, protocol: ForwardProtocol) -> u64 {
        self.shared.generation(protocol).load(Ordering::SeqCst)
    }

    /// 发往本机的地址 `addr` 的连接（`protocol` 是 UDP 时是报文）是不是落在程序自己的某个监听上。
    /// `addr` 要是本机的地址（[`OwnListener::receives`]）。
    #[must_use]
    pub fn receives(&self, protocol: ForwardProtocol, addr: SocketAddr) -> bool {
        self.held().iter().any(|held| held.listener.receives(protocol, addr))
    }

    /// 编号是 `forward` 的端口转发是不是正监听在 `port` 这个端口上。端口写 0 的转发挑了哪个端口，只有这里知道。
    #[must_use]
    pub fn forward_listens_on(&self, forward: u32, protocol: ForwardProtocol, port: u16) -> bool {
        self.held().iter().any(|held| {
            let listener = held.listener;
            listener.forward == Some(forward) && listener.protocol == protocol && listener.local.port() == port
        })
    }

    fn held(&self) -> MutexGuard<'_, Vec<Held>> {
        self.shared.held.lock().expect("own listeners mutex poisoned")
    }
}

/// 一个登记着的监听。丢掉它就撤销登记。
#[derive(Debug)]
pub struct Claim {
    listeners: OwnListeners,
    claim: u64,
    protocol: ForwardProtocol,
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.listeners.held().retain(|held| held.claim != self.claim);
        self.listeners.shared.generation(self.protocol).fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: ForwardProtocol = ForwardProtocol::Tcp;
    const UDP: ForwardProtocol = ForwardProtocol::Udp;

    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn listener(local: &str) -> OwnListener {
        OwnListener { protocol: TCP, local: at(local), forward: None }
    }

    #[test]
    fn a_listener_takes_what_is_sent_to_its_own_address_and_port_or_to_any_address_when_bound_to_all() {
        let tcp = |listener: OwnListener, addr: &str| listener.receives(TCP, at(addr));

        let on_lan = listener("192.168.1.5:8080");
        assert!(tcp(on_lan, "192.168.1.5:8080") && tcp(on_lan, "[::ffff:192.168.1.5]:8080"));
        assert!(!tcp(on_lan, "10.66.0.1:8080") && !tcp(on_lan, "192.168.1.5:8081") && !tcp(on_lan, "[2001:db8::5]:8080"));
        assert!(!on_lan.receives(UDP, at("192.168.1.5:8080")), "UDP 的同一个端口是另一回事");
        assert!(tcp(listener("[::ffff:192.168.1.5]:8080"), "192.168.1.5:8080"), "监听写成映射地址的也一样");

        // 全部 IPv4 地址，两种写法。
        for all_v4 in [listener("0.0.0.0:8080"), listener("[::ffff:0.0.0.0]:8080")] {
            assert!(tcp(all_v4, "192.168.1.5:8080") && tcp(all_v4, "10.66.0.1:8080"), "{all_v4:?}");
            assert!(!tcp(all_v4, "[2001:db8::5]:8080") && !tcp(all_v4, "192.168.1.5:8081"), "{all_v4:?}");
        }

        let all = listener("[::]:8080");
        assert!(tcp(all, "[2001:db8::5]:8080") && tcp(all, "192.168.1.5:8080"));
        assert!(!tcp(all, "192.168.1.5:8081"));
    }

    #[test]
    fn a_claim_holds_until_it_is_dropped_and_moves_the_generation_of_its_own_protocol() {
        let listeners = OwnListeners::default();
        let start = (listeners.generation(TCP), listeners.generation(UDP));
        assert!(!listeners.receives(TCP, at("192.168.1.5:8080")));

        let proxy = listeners.claim(listener("192.168.1.5:8080"));
        assert_ne!(listeners.generation(TCP), start.0);
        assert_eq!(listeners.generation(UDP), start.1, "TCP 的监听变了，UDP 的版本不动");

        let forward = listeners.clone().claim(OwnListener { protocol: UDP, local: at("0.0.0.0:40123"), forward: Some(7) });
        assert!(listeners.receives(TCP, at("192.168.1.5:8080")) && listeners.receives(UDP, at("10.66.0.1:40123")));
        assert!(listeners.forward_listens_on(7, UDP, 40123));
        assert!(!listeners.forward_listens_on(7, TCP, 40123) && !listeners.forward_listens_on(8, UDP, 40123));
        assert!(!listeners.forward_listens_on(7, UDP, 40124));
        let claimed = (listeners.generation(TCP), listeners.generation(UDP));
        assert_ne!(claimed.1, start.1);

        drop(proxy);
        assert!(!listeners.receives(TCP, at("192.168.1.5:8080")), "撤销的只是丢掉的那一个");
        assert!(listeners.receives(UDP, at("10.66.0.1:40123")));
        assert_ne!(listeners.generation(TCP), claimed.0);
        assert_eq!(listeners.generation(UDP), claimed.1);
        drop(forward);
        assert!(!listeners.forward_listens_on(7, UDP, 40123));
        assert_ne!(listeners.generation(UDP), claimed.1);
    }
}
