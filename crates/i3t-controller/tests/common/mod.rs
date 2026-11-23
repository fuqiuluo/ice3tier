//! 集成测试共用的东西：一个跑在本机随机端口上的 controller，和一个用真的 TLS 连它的节点。

// 每个测试文件各自编译这个模块，各用其中的一部分。
#![allow(dead_code, reason = "不同的测试文件用到的辅助函数不一样")]
// clippy.toml 里的 allow-unwrap-in-tests 只认 `#[test]` 函数本身，认不出这里的辅助函数。
#![allow(clippy::unwrap_used, reason = "整个文件都是测试代码，出错就该直接失败")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use i3t_controller::frame::{read_frame, write_frame};
use i3t_controller::store::Store;
use i3t_controller::webui::WebUi;
use i3t_controller::{ALPN, Controller, ServeOptions, Server, Timing};
use i3t_crypto::{NodeKey, tls};
use i3t_model::Netmap;
use i3t_model::admin::{CreateEnrollToken, CreateGroup, CreateNetwork, GroupId, Network, NetworkId, UpdateSettings};
use i3t_model::control::{Declared, EnrollToken, Hello, MAX_FRAME_LEN, PROTOCOL_REVISION, SelfUpdate, ToController, ToNode};
use i3t_model::update::{Artifact, LATEST_DIR, MANIFEST_FILE, Manifest, NODE_PROGRAM, Platform, SIGNATURE_FILE, Sha256, Version};
use i3t_proto::{NodeId, PublicKey};
use i3t_update::{TrustedKeys, sign_manifest};
use rustls::pki_types::ServerName;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// 等一条消息最多等这么久。本机上正常只要几毫秒，放宽是为了在很忙的机器上不误报。
pub const PATIENCE: Duration = Duration::from_secs(5);

/// 测试里把各种等待都调短。
pub fn fast_timing() -> Timing {
    Timing { ack_coalesce: Duration::from_millis(5), report_coalesce: Duration::from_millis(20), ..Timing::default() }
}

/// 一个正在本机跑着的 controller。丢弃它就停止。
pub struct Running {
    pub controller: Arc<Controller>,
    pub node_addr: SocketAddr,
    pub admin_addr: SocketAddr,
    pub admin_token: String,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Running {
    pub async fn start(timing: Timing) -> Self {
        Self::start_with(timing, WebUi::NotIncluded).await
    }

    pub async fn start_with(timing: Timing, webui: WebUi) -> Self {
        let store = Store::temporary();
        let controller = Controller::new(store, NodeKey::generate().unwrap(), "ctl.example.com:20331".to_owned(), timing).unwrap();
        Self::serve(controller, webui).await
    }

    /// 把一个已经建好的 controller 跑起来。后台不查发布源：测试不该去连项目的发布源。
    pub async fn serve(controller: Controller, webui: WebUi) -> Self {
        let admin_token = controller.issue_admin_token().unwrap();
        let controller = Arc::new(controller);
        let options = ServeOptions {
            node_listen: "127.0.0.1:0".parse().unwrap(),
            admin_listen: "127.0.0.1:0".parse().unwrap(),
            webui,
            follow_releases: false,
        };
        let server = Server::bind(Arc::clone(&controller), options).await.unwrap();
        let (node_addr, admin_addr) = (server.node_addr().unwrap(), server.admin_addr().unwrap());
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            server
                .run(async {
                    stopped.await.ok();
                })
                .await
                .unwrap();
        });
        Self { controller, node_addr, admin_addr, admin_token, stop: Some(stop), task }
    }

    pub fn network(&self, name: &str) -> Network {
        self.controller.create_network(&CreateNetwork { name: name.to_owned(), ..CreateNetwork::default() }).unwrap()
    }

    /// 叫 `name` 的分组（不分大小写），没有就建一个。`all` 是内置的 `All`。
    pub fn group(&self, network: NetworkId, name: &str) -> GroupId {
        let existing = self.controller.groups(network).unwrap().into_iter().find(|group| group.name.eq_ignore_ascii_case(name));
        existing.map_or_else(|| self.controller.create_group(network, &CreateGroup { name: name.to_owned() }).unwrap().id, |group| group.id)
    }

    /// 生成一个注册令牌（用它加入的节点在这些分组里，没有的先建出来），返回里面的一次性密钥。
    pub fn secret(&self, network: NetworkId, groups: &[&str]) -> String {
        let groups = groups.iter().map(|name| self.group(network, name)).collect();
        let request = CreateEnrollToken { groups, ..CreateEnrollToken::default() };
        let created = self.controller.create_token(network, &request).unwrap();
        let token: EnrollToken = created.token.parse().unwrap();
        assert_eq!(token.key, self.controller.public_key());
        token.secret
    }

    /// 一个新节点加入网络并保持连接。它的第一份 netmap 已经收下并确认。
    pub async fn join(&self, network: NetworkId, groups: &[&str]) -> Node {
        let secret = self.secret(network, groups);
        let mut node = Node::new();
        node.enroll(self, &secret).await.expect("注册应该成功");
        node
    }

    /// 停止服务并等它收尾。
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send(()).ok();
        }
        timeout(PATIENCE, &mut self.task).await.expect("controller 应该在限定时间内停下").unwrap();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// 最初那一版节点的自我介绍：不报主机名，不懂更新。
pub fn hello(declared: Declared) -> Hello {
    Hello { version: "0.1.0".to_owned(), platform: "linux-x86_64".to_owned(), declared, port: 20330, ..Hello::default() }
}

/// 现在这一版节点的自我介绍：懂更新和路由查询，能自己更新，正在运行 `version`。
pub fn modern_hello(version: &str, declared: Declared) -> Hello {
    Hello { version: version.to_owned(), protocol: PROTOCOL_REVISION, self_update: Some(SelfUpdate::ABLE), ..hello(declared) }
}

/// 一个照 `i3t_controller::release` 里的布局摆的发布源目录，和签它的那把钥匙。
pub struct Publisher {
    pub key: NodeKey,
    pub root: tempfile::TempDir,
}

impl Publisher {
    pub fn new() -> Self {
        Self { key: NodeKey::generate().unwrap(), root: tempfile::tempdir().unwrap() }
    }

    pub fn source(&self) -> String {
        self.root.path().to_str().unwrap().to_owned()
    }

    pub fn keys(&self) -> TrustedKeys {
        TrustedKeys::from(self.key.public())
    }

    /// 发布 `version`：放好各个平台的程序，签清单，再把清单放到"最新"的位置上。
    pub fn publish(&self, version: &str, programs: &[(&str, &[u8])]) {
        self.publish_with_floor(version, None, programs);
    }

    /// 同 [`Publisher::publish`]，清单里写上安全下限 `floor`（有的话）。
    pub fn publish_with_floor(&self, version: &str, floor: Option<&str>, programs: &[(&str, &[u8])]) {
        let version: Version = version.parse().unwrap();
        let mut artifacts = std::collections::BTreeMap::new();
        for (platform, content) in programs {
            let file = platform.parse::<Platform>().unwrap().program_file(NODE_PROGRAM);
            let path = self.root.path().join(version.release_dir()).join(&file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            let hash: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, content).as_ref().try_into().unwrap();
            let artifact = Artifact { file, size: u64::try_from(content.len()).unwrap(), sha256: Sha256::from_bytes(hash) };
            artifacts.insert((*platform).to_owned(), artifact);
        }
        let manifest = Manifest {
            version,
            min_controller: "0.0.0".parse().unwrap(),
            published: 1_763_200_000,
            artifacts,
            security_floor: floor.map(|floor| floor.parse().unwrap()),
            files: std::collections::BTreeMap::new(),
        };
        let signed = sign_manifest(&self.key, serde_json::to_string_pretty(&manifest).unwrap());
        let latest = self.root.path().join(LATEST_DIR);
        std::fs::create_dir_all(&latest).unwrap();
        std::fs::write(latest.join(MANIFEST_FILE), &signed.manifest).unwrap();
        std::fs::write(latest.join(SIGNATURE_FILE), format!("{}\n", signed.signature)).unwrap();
    }

    /// 一个认这把钥匙、发布源指向这个目录的 controller。包缓存在 `cache` 里。
    pub fn controller(&self, timing: Timing, cache: &std::path::Path) -> Controller {
        let store = Store::temporary();
        let controller = Controller::new(store, NodeKey::generate().unwrap(), "ctl.example.com:20331".to_owned(), timing)
            .unwrap()
            .with_release_keys(self.keys())
            .unwrap()
            .with_release_cache(cache.to_owned())
            // 测试里发布的版本号是写死的，controller 的版本也固定下来，不随这个包的版本号变。
            .with_version("0.1.0".parse().unwrap());
        controller.set_update_settings(&UpdateSettings { source: Some(Some(self.source())), ..UpdateSettings::default() }).unwrap();
        controller
    }
}

/// 一个测试用的节点：真的密钥，真的 TLS，手动收发消息。
pub struct Node {
    pub key: NodeKey,
    pub declared: Declared,
    /// 有值时它是现在这一版的节点，正在运行这个版本；没有值时是最初那一版，不懂更新和路由查询。
    pub modern: Option<&'static str>,
    link: Option<Link>,
    /// 最近收到的 netmap。
    pub netmap: Option<Netmap>,
}

pub struct Link {
    reader: ReadHalf<TlsStream<TcpStream>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
}

impl Link {
    /// 用 `key` 连上 controller，校验对方的公钥是 `controller_key`。
    pub async fn open(addr: SocketAddr, key: &NodeKey, controller_key: PublicKey) -> std::io::Result<Self> {
        let config = tls::client_config(key, controller_key, ALPN).unwrap();
        let tcp = TcpStream::connect(addr).await?;
        let stream = TlsConnector::from(Arc::new(config)).connect(ServerName::try_from("i3t").unwrap(), tcp).await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self { reader, writer })
    }

    pub async fn send(&mut self, message: &ToController) {
        write_frame(&mut self.writer, message).await.unwrap();
    }

    /// 原样写一段字节，用来发 controller 不认识的帧。
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        use tokio::io::AsyncWriteExt;
        self.writer.write_all(bytes).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    /// 等下一条消息。连接被对方关闭时返回 `None`。
    pub async fn recv(&mut self) -> Option<ToNode> {
        timeout(PATIENCE, read_frame(&mut self.reader, MAX_FRAME_LEN)).await.expect("等 controller 的消息超时").unwrap_or(None)
    }

    /// 在 `within` 之内有没有消息来。
    pub async fn recv_within(&mut self, within: Duration) -> Option<ToNode> {
        timeout(within, read_frame(&mut self.reader, MAX_FRAME_LEN)).await.ok().and_then(|frame| frame.unwrap_or(None))
    }
}

impl Node {
    pub fn new() -> Self {
        Self::with_key(NodeKey::generate().unwrap())
    }

    pub fn with_key(key: NodeKey) -> Self {
        Self { key, declared: Declared::default(), modern: None, link: None, netmap: None }
    }

    pub fn id(&self) -> NodeId {
        self.netmap().me.id
    }

    pub fn hello(&self) -> Hello {
        match self.modern {
            Some(version) => modern_hello(version, self.declared),
            None => hello(self.declared),
        }
    }

    pub fn netmap(&self) -> &Netmap {
        self.netmap.as_ref().expect("节点应该已经收到过 netmap")
    }

    pub fn link(&mut self) -> &mut Link {
        self.link.as_mut().expect("节点应该连着")
    }

    /// 用一次性密钥注册。成功时收下并确认第一份 netmap；被拒绝时返回拒绝的原因。
    pub async fn enroll(&mut self, running: &Running, secret: &str) -> Result<(), String> {
        let first = ToController::Enroll { token: secret.to_owned(), hello: self.hello() };
        self.open(running, first).await
    }

    /// 已经注册过的节点重新连上来。
    pub async fn connect(&mut self, running: &Running) -> Result<(), String> {
        self.open(running, ToController::Hello(self.hello())).await
    }

    async fn open(&mut self, running: &Running, first: ToController) -> Result<(), String> {
        let mut link = Link::open(running.node_addr, &self.key, running.controller.public_key()).await.unwrap();
        link.send(&first).await;
        match link.recv().await {
            Some(ToNode::Snapshot(netmap)) => {
                link.send(&ToController::Ack { version: netmap.version }).await;
                self.netmap = Some(*netmap);
                self.link = Some(link);
                Ok(())
            }
            Some(ToNode::Rejected { reason, .. }) => {
                assert!(link.recv().await.is_none(), "拒绝之后 controller 应该关闭连接");
                Err(reason)
            }
            other => panic!("报到之后的第一条消息应该是 snapshot 或者 rejected，收到的是 {other:?}"),
        }
    }

    pub async fn send(&mut self, message: ToController) {
        self.link().send(&message).await;
    }

    /// 等下一条不是心跳的消息；是 netmap 的话收下并确认。
    pub async fn next(&mut self) -> Option<ToNode> {
        loop {
            let message = self.link().recv().await?;
            match &message {
                ToNode::Heartbeat => continue,
                ToNode::Snapshot(netmap) => {
                    self.netmap = Some((**netmap).clone());
                    let version = netmap.version;
                    self.send(ToController::Ack { version }).await;
                }
                ToNode::Signal { .. }
                | ToNode::Revoked
                | ToNode::Rejected { .. }
                | ToNode::Update { .. }
                | ToNode::UpdateCancel
                | ToNode::PackageChunk { .. }
                | ToNode::PackageUnavailable { .. }
                | ToNode::RouteQuery { .. }
                | ToNode::TryLater { .. }
                | ToNode::BackboneQuery { .. }
                | ToNode::Test(_)
                | ToNode::TestEnd { .. }
                | ToNode::ExitTest { .. } => {}
            }
            return Some(message);
        }
    }

    /// 一直收 netmap，直到手上的那一份满足条件。
    pub async fn until(&mut self, what: &str, satisfied: impl Fn(&Netmap) -> bool) {
        let waiting = async {
            while !satisfied(self.netmap()) {
                match self.next().await {
                    Some(_) => {}
                    None => panic!("还没等到「{what}」连接就断了"),
                }
            }
        };
        if timeout(PATIENCE, waiting).await.is_err() {
            panic!("没有等到「{what}」；手上的 netmap：{:#?}", self.netmap());
        }
    }

    /// 在 `within` 之内没有新的 netmap 或别的消息来（心跳不算）。
    pub async fn stays_quiet(&mut self, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.link().recv_within(left).await {
                Some(ToNode::Heartbeat) => continue,
                Some(_) => return false,
                None => return true,
            }
        }
    }

    pub fn disconnect(&mut self) {
        self.link = None;
    }
}

/// 让这些节点把发给它们的 netmap 都收下并确认，直到一轮下来谁也没有新消息。
///
/// 访问关系的变更要等对端确认才走下一步，所以测试里只盯着一个节点、别的节点不读消息的话，变更会停在半路。
pub async fn settle(nodes: &mut [&mut Node]) {
    let quiet = Duration::from_millis(100);
    loop {
        let mut active = false;
        for node in nodes.iter_mut() {
            while let Some(message) = node.link().recv_within(quiet).await {
                if let ToNode::Snapshot(netmap) = message {
                    let version = netmap.version;
                    node.netmap = Some(*netmap);
                    node.send(ToController::Ack { version }).await;
                    active = true;
                }
            }
        }
        if !active {
            return;
        }
    }
}

/// 反复查一个条件，直到它成立。给"controller 那边过一会儿才看得到"的状态用。
pub async fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "没有等到「{what}」");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
