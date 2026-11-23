//! 把 controller 的几个入口装在一起跑：节点协议（TCP）、地址查询（同一个端口号的 UDP）、管理 API，和后台任务。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

use crate::controller::Controller;
use crate::error::{Error, error_chain};
use crate::webui::WebUi;
use crate::{addr_server, admin, admin_server, node_server};

/// 后台工作出错之后多久再试。
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// 多久查一次发布源。
const RELEASE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// [`Server::bind`] 要的东西。
#[derive(Debug, Clone)]
pub struct ServeOptions {
    /// 节点协议的监听地址。TCP 和 UDP 用同一个地址和端口。
    pub node_listen: SocketAddr,
    /// 管理 API 的监听地址。默认应该只绑回环地址。
    pub admin_listen: SocketAddr,
    /// WebUI 的静态文件从哪里来，挂在管理 API 同一个端口的 `/` 上。
    pub webui: WebUi,
    /// 要不要做和外面打交道的后台工作：定时查发布源、取节点的更新包、解析对外地址里的域名（见 `resolve_public_host`）。
    /// 正常运行时是要的；测试里关掉，免得测试去连项目的发布源、结果随测试机器的域名解析而变。
    /// 关掉之后管理 API 的"立即检查"仍然可以用，只是查到的包没有人去取。
    pub follow_releases: bool,
}

/// 已经绑好端口、还没开始服务的 controller。
pub struct Server {
    controller: Arc<Controller>,
    tls: Arc<rustls::ServerConfig>,
    node_tcp: TcpListener,
    node_udp: UdpSocket,
    admin: TcpListener,
    webui: WebUi,
    follow_releases: bool,
}

impl Server {
    /// 绑定全部端口。端口写 0 时由系统挑，挑到的地址用 [`Server::node_addr`] 和 [`Server::admin_addr`] 查。
    ///
    /// # Errors
    ///
    /// 有端口绑不上，或者准备 TLS 配置失败。
    pub async fn bind(controller: Arc<Controller>, options: ServeOptions) -> Result<Self, Error> {
        let tls = Arc::new(controller.tls_config()?);
        let (node_tcp, node_udp) = bind_node(options.node_listen, UdpSocket::bind).await?;
        let admin =
            i3t_underlay::tcp_mss::listen(options.admin_listen).map_err(|source| Error::Bind { address: options.admin_listen, source })?;
        Ok(Self { controller, tls, node_tcp, node_udp, admin, webui: options.webui, follow_releases: options.follow_releases })
    }

    /// 节点协议实际监听的地址。
    ///
    /// # Errors
    ///
    /// 系统查不出这个 socket 的地址。
    pub fn node_addr(&self) -> Result<SocketAddr, Error> {
        self.node_tcp.local_addr().map_err(Error::Socket)
    }

    /// 管理 API 实际监听的地址。
    ///
    /// # Errors
    ///
    /// 系统查不出这个 socket 的地址。
    pub fn admin_addr(&self) -> Result<SocketAddr, Error> {
        self.admin.local_addr().map_err(Error::Socket)
    }

    /// 开始服务，直到 `shutdown` 完成。之后不再接受新的连接和请求，等手上的收尾再返回：
    /// 在线的节点被记为离线，它们会自己重连。
    ///
    /// # Errors
    ///
    /// 现在不会出错：接受连接失败只记日志、过一会儿再接。留着 `Result` 是为了以后启动时还要做的事。
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<(), Error> {
        let (stop, stopped) = watch::channel(false);
        tokio::spawn(async move {
            shutdown.await;
            // 没有人在等也无所谓：那说明各个任务已经自己结束了。
            let _ = stop.send(true);
        });

        let nodes = tokio::spawn(node_server::serve(Arc::clone(&self.controller), self.tls, self.node_tcp, stopped.clone()));
        let addresses = tokio::spawn(addr_server::serve(self.node_udp, stopped.clone()));
        let maintenance = tokio::spawn(maintain(Arc::clone(&self.controller), stopped.clone()));
        let releases = self.follow_releases.then(|| tokio::spawn(follow_releases(Arc::clone(&self.controller), stopped.clone())));
        let host = (self.follow_releases && self.controller.public_host_name().is_some())
            .then(|| tokio::spawn(resolve_public_host(Arc::clone(&self.controller))));
        let router = admin::router(Arc::clone(&self.controller), &self.webui);
        admin_server::serve(self.admin, router, stopped.clone()).await;

        // 管理 API 停了：正常情况是收到了关闭的信号，这时等节点的连接收尾（把在线的节点记为离线）。
        // 关闭的信号要是没来（发送端没了），别的任务还在等一个不会来的信号，直接结束它们。
        addresses.abort();
        maintenance.abort();
        if let Some(host) = host {
            host.abort();
        }
        if let Some(releases) = releases {
            // 正在取的包取到一半就丢下：没有核对过的文件用的是另外的名字，下次从头取。
            releases.abort();
        }
        if *stopped.borrow() {
            if let Err(err) = nodes.await {
                tracing::error!("节点协议的服务异常结束：{err}");
            }
        } else {
            nodes.abort();
        }
        Ok(())
    }
}

/// 端口写 0 时最多挑几次端口，两种挑法（见 [`bind_node`]）各占一半。几次之内总能挑到 TCP 和 UDP 都用得了的。
const NODE_PORT_TRIES: usize = 16;

/// 绑节点协议的 TCP 和同一个端口号的 UDP（节点按"和节点协议同一个端口号"去找地址查询）。`bind_udp` 平时是
/// `UdpSocket::bind`。
///
/// 端口写 0 时由系统挑。系统给一种协议挑端口的时候不看另一种：挑给 TCP 的端口号，UDP 上可能正被别的程序占着；
/// Windows 上还可能落在系统给 UDP 保留、不让绑的一段里（`netsh int ipv4 show excludedportrange protocol=udp`），
/// 而且接着挑给 TCP 的端口号是挨着的，会一连几十个都落在这一段里。所以两种挑法轮着来：系统给 TCP 挑、去绑同号的
/// UDP；系统给 UDP 挑、去听同号的 TCP。系统给哪种协议挑，就躲开了那种协议用不了的端口，轮着来不会一直卡在同一段上。
/// 挑过而没用上的先拿着，免得系统又挑回它。端口写明了的不换，照实报错。
async fn bind_node<F, Fut>(listen: SocketAddr, mut bind_udp: F) -> Result<(TcpListener, UdpSocket), Error>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<UdpSocket>>,
{
    let failed = |source| Error::Bind { address: listen, source };
    let (mut spare_tcp, mut spare_udp) = (Vec::new(), Vec::new());
    loop {
        let tries = spare_tcp.len() + spare_udp.len();
        let (addr, source) = if tries % 2 == 0 {
            let tcp = i3t_underlay::tcp_mss::listen(listen).map_err(failed)?;
            let addr = tcp.local_addr().map_err(failed)?;
            match bind_udp(addr).await {
                Ok(udp) => return Ok((tcp, udp)),
                Err(source) => {
                    spare_tcp.push(tcp);
                    (addr, source)
                }
            }
        } else {
            let udp = bind_udp(listen).await.map_err(failed)?;
            let addr = udp.local_addr().map_err(failed)?;
            match i3t_underlay::tcp_mss::listen(addr) {
                Ok(tcp) => return Ok((tcp, udp)),
                Err(source) => {
                    spare_udp.push(udp);
                    (addr, source)
                }
            }
        };
        if listen.port() != 0 || !port_unusable(&source) || tries + 1 >= NODE_PORT_TRIES {
            return Err(Error::Bind { address: addr, source });
        }
        tracing::debug!(%addr, error = %source, "系统给一种协议挑的端口号，另一种协议上用不了，另挑一个");
    }
}

/// 绑不上是不是因为这个端口号用不了（换一个端口号就可能绑得上）。别的程序占着时一般报"地址已被占用"；Windows 上端口在
/// 系统保留的一段里、或者被别的账户的程序独占着时，报的是"没有权限"（10013）。
fn port_unusable(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied)
}

/// 后台任务：到点做延后的下发，不再等迟迟不确认的节点，清理过期的东西。
async fn maintain(controller: Arc<Controller>, mut shutdown: watch::Receiver<bool>) {
    loop {
        let next = match blocking(&controller, Controller::tick).await {
            Ok(next) => next.map(tokio::time::Instant::from_std),
            Err(err) => {
                tracing::error!("后台工作出错，稍后再试：{}", error_chain(&err));
                Some(tokio::time::Instant::now() + RETRY_DELAY)
            }
        };
        let until_next = async {
            match next {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = until_next => {}
            () = controller.wait_for_work() => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// 后台任务：controller 对外地址里的主机是域名时，定期解析它，告诉 controller 它是哪个 IP（走回环连过来的节点，
/// 别的机器要靠这个 IP 找到它）。回环地址不算：controller 自己的机器上的 `/etc/hosts` 常把本机的名字指向回环。
async fn resolve_public_host(controller: Arc<Controller>) {
    let Some(host) = controller.public_host_name() else { return };
    let address = controller.public_addr().to_owned();
    loop {
        let found = match tokio::net::lookup_host(address.as_str()).await {
            Ok(found) => found.map(|resolved| resolved.ip().to_canonical()).find(|ip| !ip.is_loopback() && !ip.is_unspecified()),
            Err(error) => {
                tracing::debug!(%host, %error, "解析不了 controller 对外地址里的主机");
                None
            }
        };
        if let Some(ip) = found
            && let Err(err) = blocking(&controller, move |controller| controller.set_public_host(Some(ip))).await
        {
            tracing::error!("记下 controller 对外地址的 IP 时出错：{}", error_chain(&err));
        }
        tokio::time::sleep(PUBLIC_HOST_REFRESH).await;
    }
}

/// 多久重新解析一次 controller 对外地址里的主机。
const PUBLIC_HOST_REFRESH: Duration = Duration::from_secs(10 * 60);

/// 后台任务：每小时查一次发布源，设置变了就提前查；有节点要用的包就去取。
///
/// 查和取都要走网络，在阻塞线程上做，期间不拿 controller 的锁。失败了只记日志：原因在管理 API 里看得到，下一轮再试。
/// 两件事各走各的：发布源连不上时一次查询要等到超时，不能因此耽误取别的包（管理员可能刚把发布源改到了连得上的地方）。
async fn follow_releases(controller: Arc<Controller>, mut shutdown: watch::Receiver<bool>) {
    let checks = async {
        let mut next_check = tokio::time::Instant::now();
        loop {
            if tokio::time::Instant::now() >= next_check || blocking(&controller, Controller::release_check_requested).await {
                if let Err(err) = blocking(&controller, Controller::check_release).await {
                    tracing::error!("记录查发布源的结果时出错：{}", error_chain(&err));
                }
                next_check = tokio::time::Instant::now() + RELEASE_CHECK_INTERVAL;
            }
            tokio::select! {
                () = tokio::time::sleep_until(next_check) => {}
                () = controller.wait_for_check_request() => {}
            }
        }
    };
    let fetches = async {
        loop {
            if let Err(err) = blocking(&controller, Controller::fetch_packages).await {
                tracing::error!("记录取包的结果时出错：{}", error_chain(&err));
            }
            controller.wait_for_wanted_packages().await;
        }
    };
    tokio::select! {
        () = checks => {}
        () = fetches => {}
        _ = shutdown.changed() => {}
    }
}

/// 在阻塞线程池里调用 controller 的同步方法。
///
/// 这些方法里有数据库读写，重算一个大网络也要花时间，直接在异步任务里调用会卡住运行时的工作线程。
pub(crate) async fn blocking<T: Send + 'static>(controller: &Arc<Controller>, call: impl FnOnce(&Controller) -> T + Send + 'static) -> T {
    let controller = Arc::clone(controller);
    match tokio::task::spawn_blocking(move || call(&controller)).await {
        Ok(value) => value,
        Err(err) => match err.try_into_panic() {
            // controller 里的 panic 是 bug，照原样传出去，不把它变成一个普通的错误。
            Ok(panic) => std::panic::resume_unwind(panic),
            // 运行时正在关闭，这个任务自己也马上会被丢弃。
            Err(_) => std::future::pending().await,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_node_port_left_to_the_system_moves_on_when_the_udp_of_the_same_number_is_taken() {
        // 系统挑的第一个端口号上，UDP 正好被别的程序占着。这里自己去占；占不上就是真有别的程序占着它（它什么时候放开不归这里管）。
        let mut first = None;
        let bound = bind_node("127.0.0.1:0".parse().unwrap(), |addr| {
            if first.is_none() {
                first = Some((addr, std::net::UdpSocket::bind(addr).ok()));
            }
            UdpSocket::bind(addr)
        })
        .await;
        let (tcp, udp) = bound.unwrap();
        let (tcp, udp) = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
        assert_eq!(tcp, udp, "TCP 和 UDP 在同一个端口号上");
        let (taken, squatter) = first.expect("至少试过一个端口");
        if squatter.is_some() {
            assert_ne!(udp, taken, "另挑了一个端口");
        }
    }

    #[tokio::test]
    async fn a_node_port_left_to_the_system_is_found_when_every_number_picked_for_tcp_is_refused_on_udp() {
        // Windows 上系统接连挑给 TCP 的端口号可以全落在给 UDP 保留的一段里，同号的 UDP 一个都绑不上，报的是"没有权限"。
        let mut refused = Vec::new();
        let bound = bind_node("127.0.0.1:0".parse().unwrap(), |addr| {
            let reserved = addr.port() != 0;
            if reserved {
                refused.push(addr);
            }
            async move { if reserved { Err(io::ErrorKind::PermissionDenied.into()) } else { UdpSocket::bind(addr).await } }
        })
        .await;
        let (tcp, udp) = bound.unwrap();
        let (tcp, udp) = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
        assert_eq!(tcp, udp, "TCP 和 UDP 在同一个端口号上");
        assert!(!refused.is_empty() && !refused.contains(&udp), "用的是系统给 UDP 挑的端口，不是被拒绝的 {refused:?}");
    }

    #[tokio::test]
    async fn picking_a_node_port_stops_after_a_fixed_number_of_tries() {
        // 两种挑法都不成：给 TCP 挑的端口号 UDP 上一律被拒绝；给 UDP 挑的端口号，同号的 TCP 都被这里先占上。
        let mut squatters = Vec::new();
        let mut calls = 0;
        let bound = bind_node("127.0.0.1:0".parse().unwrap(), |addr| {
            calls += 1;
            let udp = if addr.port() == 0 {
                let (udp, tcp) = (0..100).find_map(|_| udp_port_with_its_tcp_taken()).expect("占得上一个 UDP 和 TCP 都空着的端口");
                squatters.push(tcp);
                UdpSocket::from_std(udp)
            } else {
                Err(io::ErrorKind::PermissionDenied.into())
            };
            std::future::ready(udp)
        })
        .await;
        assert!(matches!(&bound, Err(Error::Bind { address, .. }) if address.port() != 0), "{:?}", bound.err());
        assert_eq!(calls, NODE_PORT_TRIES, "挑够次数就照实报错，不会一直挑下去");
    }

    /// 系统挑的一个 UDP 端口，同号的 TCP 也占上；TCP 占不上时是 `None`。
    fn udp_port_with_its_tcp_taken() -> Option<(std::net::UdpSocket, std::net::TcpListener)> {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let tcp = std::net::TcpListener::bind(udp.local_addr().unwrap()).ok()?;
        Some((udp, tcp))
    }

    #[tokio::test]
    async fn a_node_port_written_out_is_not_changed_when_its_udp_is_taken() {
        let squatter = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let taken = squatter.local_addr().unwrap();
        let bound = bind_node(taken, UdpSocket::bind).await;
        assert!(matches!(&bound, Err(Error::Bind { address, .. }) if *address == taken), "{:?}", bound.err());
    }
}
