//! 把 controller 的几个入口装在一起跑：节点协议（TCP）、地址查询（同一个端口号的 UDP）、管理 API，和后台任务。

use std::io;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

use crate::controller::{Controller, TickFailed};
use crate::error::{Error, error_chain};
use crate::gate::Throttle;
use crate::webui::WebUi;
use crate::{addr_server, admin, admin_server, node_server};

/// 后台工作一直出错时，多久最多打一轮它的错误。
const TICK_ERROR_LOG_EVERY: Duration = Duration::from_secs(60);

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
    /// 端口绑定失败，或准备 TLS 配置失败。
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
    /// 无法获取该 socket 的本地监听地址。
    pub fn node_addr(&self) -> Result<SocketAddr, Error> {
        self.node_tcp.local_addr().map_err(Error::Socket)
    }

    /// 管理 API 实际监听的地址。
    ///
    /// # Errors
    ///
    /// 无法获取该 socket 的本地监听地址。
    pub fn admin_addr(&self) -> Result<SocketAddr, Error> {
        self.admin.local_addr().map_err(Error::Socket)
    }

    /// 开始服务，直到 `shutdown` 完成。之后不再接受新的连接和请求，等手上的收尾再返回：
    /// 在线的节点被记为离线，它们会自己重连。
    ///
    /// # Errors
    ///
    /// 当前实现不会返回错误：接受连接失败时仅记录日志并延迟重试。保留 `Result` 返回类型以便后续扩展启动期检查。
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

/// 端口指定为 0 时的最大选口次数：包含首次由系统分配，以及不可用后的手动重试次数。
const NODE_PORT_TRIES: usize = 16;

/// 自己挑端口时用的范围：留给临时用途的动态端口，Windows 的系统也在这里面挑。
const DYNAMIC_PORTS: RangeInclusive<u16> = 49152..=65535;

/// 绑节点协议的 TCP 和同一个端口号的 UDP（节点按"和节点协议同一个端口号"去找地址查询）。`bind_udp` 平时是
/// `UdpSocket::bind`。
///
/// 端口指定为 0 时先由系统为 TCP 分配一个端口。系统分配时不会检查 UDP，同号 UDP 端口可能不可用：可能正被其他进程占用，或落入 Windows
/// 的 UDP 排除端口段（`netsh int ipv4 show excludedportrange protocol=udp`，绑定时报权限错误）。此类排除段
/// 会由 Windows 在运行时动态划出，可能连续覆盖系统顺序分配给 TCP 的数百个端口，导致重复让系统分配持续命中同一排除段。
/// 因此当系统分配的端口不可用时，改为在动态端口范围内随机挑选，避免连续碰撞同一排除段。若端口已显式指定则不更换，直接返回绑定错误。
async fn bind_node<F, Fut>(listen: SocketAddr, mut bind_udp: F) -> Result<(TcpListener, UdpSocket), Error>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<UdpSocket>>,
{
    let mut wanted = listen;
    let mut tries = 0;
    loop {
        tries += 1;
        let (addr, source) = match i3t_underlay::tcp_mss::listen(wanted).and_then(|tcp| Ok((tcp.local_addr()?, tcp))) {
            Ok((addr, tcp)) => match bind_udp(addr).await {
                Ok(udp) => return Ok((tcp, udp)),
                Err(source) => (addr, source),
            },
            Err(source) => (wanted, source),
        };
        if listen.port() != 0 || !port_unusable(&source) || tries >= NODE_PORT_TRIES {
            return Err(Error::Bind { address: addr, source });
        }
        tracing::debug!(%addr, error = %source, "该端口无法同时绑定 TCP 和 UDP，重新选择端口");
        wanted = SocketAddr::new(listen.ip(), any_dynamic_port()?);
    }
}

/// 判断绑定失败是否由当前端口不可用导致（更换端口可能成功）。端口被其他进程占用时报 `AddrInUse`；Windows 上端口落入
/// 系统保留段时报 `PermissionDenied`（错误码 10013）。
fn port_unusable(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied)
}

/// 动态端口的范围里随便一个端口号。
fn any_dynamic_port() -> Result<u16, Error> {
    let mut random = [0; 2];
    SystemRandom::new().fill(&mut random).map_err(|_| Error::Random)?;
    let count = DYNAMIC_PORTS.end() - DYNAMIC_PORTS.start() + 1;
    Ok(DYNAMIC_PORTS.start() + u16::from_ne_bytes(random) % count)
}

/// 后台任务：到点做延后的下发，不再等迟迟不确认的节点，清理过期的东西。
async fn maintain(controller: Arc<Controller>, mut shutdown: watch::Receiver<bool>) {
    let errors = Throttle::new(TICK_ERROR_LOG_EVERY);
    loop {
        let next = match blocking(&controller, Controller::tick).await {
            Ok(next) => next,
            Err(failed) => {
                log_failure(&errors, &failed);
                Some(failed.next)
            }
        };
        let until_next = async {
            match next {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
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

/// 后台的一轮出的错，打进日志。一直出错的时候（比如数据库停了）后台每秒都要再试，每一轮都打的话日志很快就被刷满：
/// 每 [`TICK_ERROR_LOG_EVERY`] 最多打一轮，说出这期间省掉了几轮，省掉的打在 debug 里。
///
/// 中间某轮未出错时仍保持限流：当整个数据库不可用时后台任务会进入退避，退避期间不访问数据库因此不会报错，
/// 不能据此视为已恢复。
fn log_failure(errors: &Throttle, failed: &TickFailed) {
    let suppressed = errors.allow();
    for err in &failed.errors {
        match suppressed {
            Some(suppressed) => tracing::error!(suppressed, "后台工作出错，稍后再试：{}", error_chain(err)),
            None => tracing::debug!("后台工作出错，稍后再试：{}", error_chain(err)),
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
                tracing::debug!(%host, %error, "无法解析 controller 对外地址中的主机名");
                None
            }
        };
        if let Some(ip) = found
            && let Err(err) = blocking(&controller, move |controller| controller.set_public_host(Some(ip))).await
        {
            tracing::error!("保存 controller 对外地址解析的 IP 失败：{}", error_chain(&err));
        }
        tokio::time::sleep(PUBLIC_HOST_REFRESH).await;
    }
}

/// 多久重新解析一次 controller 对外地址里的主机。
const PUBLIC_HOST_REFRESH: Duration = Duration::from_secs(10 * 60);

/// 后台任务：每小时查一次发布源，设置变了就提前查；有节点要用的包就去取。
///
/// 查和取都要走网络，在阻塞线程上做，期间不拿 controller 的锁。失败了只记日志：原因在管理 API 里看得到，下一轮再试。
/// 两项任务彼此独立：发布源不可达时单次检查需等待超时，不能因此阻塞更新包下载（管理员可能已将发布源修改为可达地址）。
async fn follow_releases(controller: Arc<Controller>, mut shutdown: watch::Receiver<bool>) {
    let checks = async {
        let mut next_check = tokio::time::Instant::now();
        loop {
            if tokio::time::Instant::now() >= next_check || blocking(&controller, Controller::release_check_requested).await {
                if let Err(err) = blocking(&controller, Controller::check_release).await {
                    tracing::error!("记录发布源检查结果失败：{}", error_chain(&err));
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
                tracing::error!("记录更新包获取结果失败：{}", error_chain(&err));
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
    use crate::controller::testing::logged;

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
    async fn a_node_port_left_to_the_system_moves_on_when_udp_refuses_the_number_the_way_windows_does() {
        // Windows 上端口在给 UDP 保留的一段里时报的是"没有权限"，而且一段里挨着的端口号都这样：这里头三个不同的端口号
        // 都拒绝，之后再挑到它们也一样拒绝。
        let mut refused = Vec::new();
        let bound = bind_node("127.0.0.1:0".parse().unwrap(), |addr| {
            let seen = refused.contains(&addr);
            let refuse = seen || refused.len() < 3;
            if refuse && !seen {
                refused.push(addr);
            }
            async move { if refuse { Err(io::ErrorKind::PermissionDenied.into()) } else { UdpSocket::bind(addr).await } }
        })
        .await;
        let (tcp, udp) = bound.unwrap();
        let (tcp, udp) = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
        assert_eq!(tcp, udp, "TCP 和 UDP 在同一个端口号上");
        assert_eq!(refused.len(), 3, "三个端口号都被拒绝之后才挑到的");
        assert!(!refused.contains(&udp), "用的不是被拒绝的端口：{refused:?}");
        assert!(refused[1..].iter().all(|addr| DYNAMIC_PORTS.contains(&addr.port())), "自己挑的在动态端口的范围里：{refused:?}");
    }

    #[tokio::test]
    async fn picking_a_node_port_stops_after_a_fixed_number_of_tries() {
        let mut calls = 0;
        let bound = bind_node("127.0.0.1:0".parse().unwrap(), |_| {
            calls += 1;
            std::future::ready(Err(io::ErrorKind::PermissionDenied.into()))
        })
        .await;
        assert!(matches!(&bound, Err(Error::Bind { address, .. }) if address.port() != 0), "{:?}", bound.err());
        // 自己挑的端口号 TCP 上正好被占着的那几次走不到 UDP，所以可以少于上限，不会多。
        assert!((2..=NODE_PORT_TRIES).contains(&calls), "挑够次数就照实报错，不会一直挑下去：挑了 {calls} 次");
    }

    #[tokio::test]
    async fn a_node_port_written_out_is_tried_once_whatever_the_refusal() {
        for refusal in [io::ErrorKind::AddrInUse, io::ErrorKind::PermissionDenied] {
            // 占着这个端口号的 UDP，别的测试就不会挑到它；它的 TCP 一般空着。
            let squatter = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let written = squatter.local_addr().unwrap();
            let mut calls = 0;
            let bound = bind_node(written, |_| {
                calls += 1;
                std::future::ready(Err(refusal.into()))
            })
            .await;
            assert!(matches!(&bound, Err(Error::Bind { address, .. }) if *address == written), "{:?}", bound.err());
            assert!(calls <= 1, "写明的端口不换，{refusal:?} 也只试一次：试了 {calls} 次");
        }
    }

    #[test]
    fn ports_picked_here_stay_in_the_dynamic_range() {
        let picked: Vec<u16> = (0..1000).map(|_| any_dynamic_port().unwrap()).collect();
        assert!(picked.iter().all(|port| DYNAMIC_PORTS.contains(port)), "{picked:?}");
        assert!(picked.iter().any(|port| *port != picked[0]), "不是每次都挑同一个");
    }

    #[tokio::test]
    async fn a_node_port_written_out_is_not_changed_when_its_udp_is_taken() {
        let squatter = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let taken = squatter.local_addr().unwrap();
        let bound = bind_node(taken, UdpSocket::bind).await;
        assert!(matches!(&bound, Err(Error::Bind { address, .. }) if *address == taken), "{:?}", bound.err());
    }

    fn failed(errors: usize) -> TickFailed {
        let errors = (0..errors).map(|_| Error::NotFound(crate::error::Entity::Network)).collect();
        TickFailed { errors, next: std::time::Instant::now() }
    }

    #[test]
    fn background_work_that_keeps_failing_is_logged_once_a_while_with_every_error_of_that_round() {
        let errors = Throttle::new(Duration::from_secs(3600));
        let lines = logged(|| {
            log_failure(&errors, &failed(2));
            log_failure(&errors, &failed(1));
            log_failure(&errors, &failed(2));
        });
        let shown: Vec<_> = lines.iter().filter(|line| line.contains("ERROR")).collect();
        assert_eq!(shown.len(), 2, "第一轮的两个错都打，接着的两轮不打：{lines:#?}");
        assert!(shown.iter().all(|line| line.contains("suppressed=0")), "{lines:#?}");

        // 过了限着的时间就再打，说出中间省掉了几轮。
        let window = Duration::from_secs(1);
        let errors = Throttle::new(window);
        let lines = logged(|| {
            log_failure(&errors, &failed(1));
            log_failure(&errors, &failed(1));
            log_failure(&errors, &failed(1));
            std::thread::sleep(window);
            log_failure(&errors, &failed(1));
        });
        let shown: Vec<_> = lines.iter().filter(|line| line.contains("ERROR")).collect();
        assert_eq!(shown.len(), 2, "{lines:#?}");
        assert!(shown[0].contains("suppressed=0") && shown[1].contains("suppressed=2"), "{lines:#?}");
    }
}
