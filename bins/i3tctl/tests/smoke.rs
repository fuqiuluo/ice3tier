//! 冒烟测试：在测试进程里跑一个 controller，再把编出来的 `i3tctl` 当成外部程序去操作它。

// clippy.toml 里的 allow-unwrap-in-tests 只认 `#[test]` 函数本身，认不出集成测试里的辅助函数。
#![allow(clippy::unwrap_used, reason = "整个文件都是测试代码，出错就该直接失败")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Output;
use std::sync::Arc;

use i3t_controller::store::Store;
use i3t_controller::webui::WebUi;
use i3t_controller::{Admitted, Controller, ServeOptions, Server, Timing};
use i3t_crypto::NodeKey;
use i3t_model::control::{Declared, EnrollToken, Hello, PROTOCOL_REVISION, Report, Route, RouteEntry, SelfUpdate, ToController, ToNode};
use i3t_model::update::{Artifact, FailureKind, LATEST_DIR, MANIFEST_FILE, Manifest, SIGNATURE_FILE, Sha256, UpdateCause, UpdateStatus};
use i3t_proto::PublicKey;
use i3t_update::{TrustedKeys, sign_manifest};
use serde_json::{Value, json};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

struct Fixture {
    controller: Arc<Controller>,
    admin: SocketAddr,
    token: String,
    _stop: oneshot::Sender<()>,
}

/// 一个假装在线的节点。收件箱要留着，丢了 controller 会当它断线。
struct Member {
    session: Admitted,
    _inbox: mpsc::Receiver<ToNode>,
}

const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

impl Fixture {
    async fn start() -> Self {
        let store = Store::open_in_memory().unwrap();
        let controller =
            Controller::new(store, NodeKey::generate().unwrap(), "ctl.example.com:20331".to_owned(), Timing::default()).unwrap();
        Self::serve(controller).await
    }

    async fn serve(controller: Controller) -> Self {
        let token = controller.issue_admin_token().unwrap();
        let controller = Arc::new(controller);
        // 后台不查发布源：测试不该去连项目的发布源。命令行的"立即检查"照样可以用。
        let options = ServeOptions {
            node_listen: "127.0.0.1:0".parse().unwrap(),
            admin_listen: "127.0.0.1:0".parse().unwrap(),
            webui: WebUi::NotIncluded,
            follow_releases: false,
        };
        let server = Server::bind(Arc::clone(&controller), options).await.unwrap();
        let admin = server.admin_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(server.run(async {
            stopped.await.ok();
        }));
        Self { controller, admin, token, _stop: stop }
    }

    /// 说中文的 `i3tctl`：这里的断言照着中文的输出写。
    fn command(&self) -> Command {
        self.command_in("zh-CN")
    }

    fn command_in(&self, lang: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_i3tctl"));
        // 测试所在的环境里可能设着这些变量，不能让它们混进来。
        command.env_remove("I3T_ADMIN_URL").env_remove("I3T_ADMIN_TOKEN").env_remove("I3T_NETWORK").env("I3T_LANG", lang);
        command
    }

    async fn run(&self, args: &[&str]) -> Output {
        let url = format!("http://{}", self.admin);
        self.command().args(["--url", &url, "--token", &self.token]).args(args).output().await.unwrap()
    }

    /// 同一条命令用英文跑一遍：成功，输出里（标准输出和标准错误）一个汉字都没有。返回标准输出。
    async fn english(&self, args: &[&str]) -> String {
        let url = format!("http://{}", self.admin);
        let output = self.command_in("en").args(["--url", &url, "--token", &self.token]).args(args).output().await.unwrap();
        let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
        assert!(output.status.success(), "i3tctl {args:?} 应该成功\nstdout: {stdout}\nstderr: {stderr}");
        for said in [&stdout, &stderr] {
            assert!(!i3t_lang::cli::has_chinese(said), "i3tctl {args:?} 的英文输出里有中文：\n{said}");
        }
        stdout
    }

    /// 一行里同时有这几段文字。表格和"名字 值"的列宽随语言变，所以不比空格。
    fn has_line(output: &str, parts: &[&str]) -> bool {
        output.lines().any(|line| parts.iter().all(|part| line.contains(part)))
    }

    /// 期望成功，返回标准输出。
    async fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args).await;
        let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
        assert!(output.status.success(), "i3tctl {args:?} 应该成功\nstdout: {stdout}\nstderr: {stderr}");
        stdout
    }

    /// 期望失败，返回标准错误。
    async fn fails(&self, args: &[&str]) -> String {
        let output = self.run(args).await;
        assert!(!output.status.success(), "i3tctl {args:?} 应该失败，输出：{}", text(&output.stdout));
        assert!(output.stdout.is_empty(), "失败时标准输出应该是空的：{}", text(&output.stdout));
        text(&output.stderr)
    }

    async fn json(&self, args: &[&str]) -> Value {
        let mut with_flag = vec!["--json"];
        with_flag.extend_from_slice(args);
        let stdout = self.ok(&with_flag).await;
        serde_json::from_str(&stdout).unwrap_or_else(|err| panic!("i3tctl --json {args:?} 的输出不是 JSON：{err}\n{stdout}"))
    }

    /// 用 `i3tctl token create` 生成的令牌让一个节点加入。它是最初那一版的节点：不报主机名，不懂更新。
    async fn join(&self, seed: u8, declared: Declared) -> Member {
        let hello = Hello { version: "0.1.0".to_owned(), platform: "linux-x86_64".to_owned(), declared, port: 20330, ..Hello::default() };
        self.join_as(seed, &hello).await
    }

    async fn join_as(&self, seed: u8, hello: &Hello) -> Member {
        let created = self.json(&["token", "create", "--expires", "10m"]).await;
        let token: EnrollToken = created["token"].as_str().unwrap().parse().unwrap();
        let (outbox, inbox) = mpsc::channel(64);
        let session = self.controller.enroll(PublicKey::from_bytes([seed; PublicKey::LEN]), &token.secret, hello, REMOTE, outbox).unwrap();
        Member { session, _inbox: inbox }
    }

    fn report(&self, member: &Member, report: Report) {
        self.controller.handle(member.session, REMOTE, ToController::Report(Box::new(report))).unwrap();
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn the_command_line_drives_a_running_controller() {
    let fixture = Fixture::start().await;

    // 连接与认证。
    let status = fixture.ok(&["status"]).await;
    assert!(status.contains("ctl.example.com:20331"), "{status}");
    let url = format!("http://{}", fixture.admin);
    let wrong = fixture.command().args(["--url", &url, "--token", "wrong", "status"]).output().await.unwrap();
    assert!(!wrong.status.success());
    assert!(text(&wrong.stderr).contains("unauthorized"), "{}", text(&wrong.stderr));
    let missing = fixture.command().args(["--url", &url, "status"]).output().await.unwrap();
    assert!(!missing.status.success() && text(&missing.stderr).contains("I3T_ADMIN_TOKEN"), "{}", text(&missing.stderr));
    let unreachable = fixture.command().args(["--url", "http://127.0.0.1:1", "--token", "x", "status"]).output().await.unwrap();
    assert!(!unreachable.status.success() && text(&unreachable.stderr).contains("连不上"), "{}", text(&unreachable.stderr));

    // 网络。
    assert!(fixture.fails(&["node", "list"]).await.contains("network create"), "还没有网络时要告诉人怎么办");
    let created = fixture.ok(&["network", "create", "home"]).await;
    assert!(created.contains("home.i3t") && created.contains("10.66.0.0/16"), "{created}");
    let listed = fixture.ok(&["network", "list"]).await;
    assert!(listed.lines().next().unwrap().starts_with("编号  名字") && listed.contains("home"), "{listed}");
    let networks = fixture.json(&["network", "list"]).await;
    assert_eq!(networks.as_array().unwrap().len(), 1);
    assert_eq!(networks[0]["name"], "home");
    fixture.ok(&["network", "set", "--routing", "lowest-cost", "--max-relay-hops", "3"]).await;
    assert_eq!(fixture.json(&["network", "show"]).await["routing"], "lowest_cost");
    let shown = fixture.json(&["network", "show"]).await;
    assert_eq!((&shown["ack_eliciting_threshold"], &shown["max_ack_delay_ms"]), (&3.into(), &2.into()), "默认值");
    let set = fixture.ok(&["network", "set", "--ack-eliciting-threshold", "4", "--max-ack-delay-ms", "5"]).await;
    assert!(set.contains("4（默认 3）") && set.contains("5 ms（默认 2 ms）"), "改过的设置后面写着默认值：{set}");
    assert!(set.contains("lowest_cost（默认 direct_first）") && !set.contains("any（默认"), "没改过的不写：{set}");
    let shown = fixture.json(&["network", "show"]).await;
    assert_eq!((&shown["ack_eliciting_threshold"], &shown["max_ack_delay_ms"]), (&4.into(), &5.into()));
    let refused = fixture.fails(&["network", "set", "--max-ack-delay-ms", "26"]).await;
    assert!(refused.contains("1 到 25"), "{refused}");
    assert_eq!(shown["bundle_small_packets"], true, "合并小包默认开着");
    let set = fixture.ok(&["network", "set", "--bundle-small-packets", "off"]).await;
    assert!(set.contains("合并小包") && set.contains("关（默认 开）"), "关掉之后写着默认值：{set}");
    assert_eq!(fixture.json(&["network", "show"]).await["bundle_small_packets"], false);
    assert_eq!((&shown["vnet_offload"], &shown["vnet_mtu"]), (&true.into(), &1280.into()), "虚拟网卡的两项默认开着、1280");
    let set = fixture.ok(&["network", "set", "--vnet-offload", "off", "--vnet-mtu", "1400"]).await;
    assert!(set.contains("虚拟网卡分段卸载") && set.contains("1400（默认 1280）"), "改过的写着默认值：{set}");
    let shown = fixture.json(&["network", "show"]).await;
    assert_eq!((&shown["vnet_offload"], &shown["vnet_mtu"]), (&false.into(), &1400.into()));
    let refused = fixture.fails(&["network", "set", "--vnet-mtu", "1501"]).await;
    assert!(refused.contains("576 到 1500"), "{refused}");

    // 分组。
    assert!(fixture.ok(&["group", "list"]).await.contains("All（内置）"));
    for name in ["servers", "laptops", "home"] {
        assert!(fixture.ok(&["group", "create", name]).await.contains(name));
    }
    assert!(fixture.fails(&["group", "create", "SERVERS"]).await.contains("name_taken"));
    let missing = fixture.fails(&["token", "create", "--group", "servers", "--group", "printers"]).await;
    assert!(missing.contains("没有分组 printers"), "说出不存在的那一个：{missing}");

    // 注册令牌和节点。
    let token = fixture.ok(&["token", "create", "--group", "servers", "--ip", "10.66.0.50"]).await;
    assert!(token.lines().any(|line| line.trim().starts_with("i3t-")), "{token}");
    let tokens = fixture.json(&["token", "list"]).await;
    assert_eq!(tokens[0]["groups"][0]["name"], "servers");
    assert!(fixture.ok(&["token", "list"]).await.contains("servers"));
    fixture.ok(&["token", "delete", &tokens[0]["id"].to_string()]).await;

    let _plain = fixture.join(1, Declared::default()).await;
    let _capable = fixture.join(2, Declared { exit: true, relay: true, relay_address: None }).await;
    let nodes = fixture.ok(&["node", "list"]).await;
    assert!(nodes.contains("10.66.0.1") && nodes.contains("10.66.0.2") && nodes.contains("在线"), "{nodes}");
    // 节点可以用编号、虚拟 IP 或名字指代。
    fixture.ok(&["node", "rename", "1", "laptop"]).await;
    fixture.ok(&["node", "rename", "10.66.0.2", "nas-01"]).await;
    fixture.ok(&["node", "groups", "laptop", "laptops"]).await;
    fixture.ok(&["node", "groups", "nas-01", "Servers", "home"]).await;
    let detail = fixture.ok(&["node", "show", "nas-01"]).await;
    assert!(detail.contains("nas-01.home.i3t") && detail.contains("home、servers"), "{detail}");
    assert!(fixture.fails(&["node", "groups", "laptop", "nope"]).await.contains("nope"));
    let group = fixture.ok(&["group", "add", "home", "laptop", "nas-01"]).await;
    assert!(Fixture::has_line(&group, &["节点", "laptop、nas-01"]), "{group}");
    fixture.ok(&["group", "remove", "home", "laptop"]).await;
    assert_eq!(fixture.json(&["group", "show", "home"]).await["nodes"].as_array().unwrap().len(), 1);
    assert!(fixture.fails(&["group", "add", "all", "laptop"]).await.contains("All"), "All 的成员改不了");
    assert_eq!(fixture.json(&["node", "show", "laptop"]).await["virtual_ip"], "10.66.0.1");
    assert!(fixture.fails(&["node", "show", "nobody"]).await.contains("nobody"));
    fixture.ok(&["node", "set", "laptop", "--dial-out-only", "on", "--reach", "direct-only"]).await;
    let laptop = fixture.json(&["node", "show", "laptop"]).await;
    assert_eq!((laptop["dial_out_only"].clone(), laptop["reach"].clone()), (Value::Bool(true), Value::from("direct_only")));
    fixture.ok(&["node", "set", "laptop", "--reach", "default"]).await;
    assert!(fixture.json(&["node", "show", "laptop"]).await["reach"].is_null());

    // 没声明的能力启用不了，错误里有要在节点上执行的命令。
    let refused = fixture.fails(&["relay", "enable", "laptop"]).await;
    assert!(refused.contains("i3t set can-relay on") && refused.contains("not_declared"), "{refused}");
    assert!(fixture.fails(&["exit", "enable", "laptop"]).await.contains("i3t set can-exit on"));
    assert!(fixture.fails(&["relay", "enable", "nas-01", "--udp", "203.0.113.7:20330"]).await.contains("--udp"), "地址不再由人填");
    fixture.ok(&["relay", "enable", "nas-01"]).await;
    fixture.ok(&["exit", "enable", "nas-01", "--ports", "any", "--lan"]).await;
    assert!(fixture.fails(&["exit", "enable", "nas-01", "--bandwidth", "50"]).await.contains("--bandwidth"), "出口没有带宽上限");
    let exits = fixture.ok(&["exit", "list"]).await;
    assert!(exits.contains("nas-01") && !exits.contains("带宽"), "{exits}");
    let nas = fixture.json(&["node", "show", "nas-01"]).await;
    let found = &nas["relay"]["addresses"][0];
    assert_eq!(found["source"], "observed", "{nas}");
    let shown = fixture.ok(&["node", "show", "nas-01"]).await;
    assert!(shown.contains(&format!("{}（controller 看到的）", found["address"].as_str().unwrap())), "{shown}");
    assert!(nas["exit"]["ports"].is_null() && nas["exit"]["lan"] == true);
    fixture.ok(&["node", "set", "laptop", "--pin", "nas-01"]).await;
    assert!(fixture.ok(&["node", "list"]).await.contains("中继、出口"));
    let overview = fixture.ok(&["overview"]).await;
    assert!(Fixture::has_line(&overview, &["中继", "1"]) && overview.contains("laptop"), "{overview}");
    let reachability = fixture.ok(&["relay", "enable", "nas-01", "--bandwidth", "100"]).await;
    let address = found["address"].as_str().unwrap();
    assert!(reachability.contains("从 controller 试连") && Fixture::has_line(&reachability, &["udp", address]), "{reachability}");
    fixture.ok(&["exit", "disable", "nas-01"]).await;

    // 时间序列：还没有数据的段是空的。
    let online = fixture.ok(&["stats", "online", "--since", "1h"]).await;
    assert!(online.lines().count() > 10 && online.lines().nth(1).is_some_and(|line| line.trim_end().ends_with(i3t_lang::NONE)), "{online}");
    let flows = fixture.json(&["stats", "node_flows", "--node", "laptop"]).await;
    assert_eq!((flows["step"].clone(), flows["node"]["name"].clone()), (Value::from(300), Value::from("laptop")));
    assert!(fixture.fails(&["stats", "node_flows"]).await.contains("node"), "节点的序列要写节点");
    assert!(fixture.fails(&["stats", "nodes"]).await.contains("online"), "写错了序列的名字，说可以写哪些");

    // 规则和访问关系。
    let rules = fixture.json(&["rule", "list"]).await;
    fixture.ok(&["rule", "disable", &rules[0]["id"].to_string()]).await;
    let added = fixture.json(&["rule", "add", "laptops", "servers", "--one-way", "--name", "ssh"]).await;
    assert_eq!(added["direction"], "one_way");
    let listed = fixture.ok(&["rule", "list"]).await;
    assert!(listed.contains("laptops  ->   servers  是    ssh") && listed.contains("All      <->  All      否"), "{listed}");
    assert!(fixture.fails(&["rule", "add", "laptops", "ghosts"]).await.contains("没有分组 ghosts"));
    let renamed = fixture.ok(&["group", "rename", "servers", "boxes"]).await;
    assert!(Fixture::has_line(&renamed, &["规则", "#", "laptops -> boxes"]), "改名之后规则跟着走：{renamed}");
    fixture.ok(&["group", "rename", "boxes", "servers"]).await;
    let spare = fixture.json(&["group", "create", "spare"]).await;
    fixture.ok(&["rule", "add", "spare", "all"]).await;
    let deleted = fixture.ok(&["group", "delete", &spare["id"].to_string()]).await;
    assert!(deleted.contains("分组 spare 已删除") && deleted.contains("1 条规则"), "按编号也能指代分组：{deleted}");
    assert!(fixture.ok(&["access", "check", "laptop", "nas-01"]).await.contains("可以访问"));
    assert!(fixture.ok(&["access", "check", "nas-01", "laptop"]).await.contains("不能访问"));
    assert_eq!(fixture.json(&["access", "check", "laptop", "nas-01"]).await["allowed"], true);
    assert!(fixture.ok(&["access", "graph"]).await.contains("laptops"));
    assert!(fixture.ok(&["node", "access", "nas-01"]).await.contains("可被访问"));

    // 代理、端口转发、节点对。
    let refused = fixture.fails(&["proxy", "add", "laptop", "192.168.1.5:1080", "nas-01"]).await;
    assert!(refused.contains("exit_not_enabled") && refused.contains("没有启用出口"), "出口停用着：{refused}");
    fixture.ok(&["exit", "enable", "nas-01"]).await;
    let proxy = fixture.json(&["proxy", "add", "laptop", "192.168.1.5:1080", "nas-01", "--allow-from", "192.168.1.0/24"]).await;
    let password = proxy["password"].as_str().unwrap().to_owned();
    assert!(proxy["username"].as_str().unwrap().starts_with("u-") && password.len() == 32, "{proxy}");
    let proxy_id = proxy["id"].to_string();
    let shown = fixture.ok(&["proxy", "show", &proxy_id]).await;
    assert!(shown.contains(&password) && shown.contains("socks5h://u-") && shown.contains("192.168.1.0/24"), "{shown}");
    assert!(Fixture::has_line(&shown, &["监听节点", "laptop"]) && Fixture::has_line(&shown, &["出口", "nas-01"]), "节点写名字：{shown}");
    let proxies = fixture.ok(&["proxy", "list", "--node", "laptop"]).await;
    // 监听的节点和出口写的是名字，不是 #1、#2。
    assert!(Fixture::has_line(&proxies, &["laptop", "192.168.1.5:1080", "nas-01", "laptop-1080"]) && !proxies.contains("#2"), "{proxies}");
    // ice3proxy 是代理的选项：不在终端上、没写 --ice3proxy 时不问，不走；之后可以打开，详情说它起不起作用。
    assert_eq!((&proxy["lane"], &proxy["lane_effect"]), (&json!(false), &Value::Null), "{proxy}");
    let chosen = fixture.json(&["proxy", "set", &proxy_id, "--ice3proxy", "on"]).await;
    // 这两个假装的节点说的是最初那一版节点协议，不懂 ice3proxy。
    assert_eq!((&chosen["lane"], &chosen["lane_effect"]["blocked"][0]["reason"]), (&json!(true), &json!("node_too_old")), "{chosen}");
    let shown = fixture.ok(&["proxy", "show", &proxy_id]).await;
    assert!(Fixture::has_line(&shown, &["ice3proxy", "是", "未生效"]) && Fixture::has_line(&shown, &["laptop 的版本太旧"]), "{shown}");
    assert!(Fixture::has_line(&fixture.ok(&["proxy", "list"]).await, &["laptop-1080", "未生效"]));
    let second = fixture.json(&["proxy", "add", "laptop", "127.0.0.1:1090", "nas-01", "--ice3proxy"]).await;
    assert_eq!(second["lane"], true, "写了 --ice3proxy 就走");
    fixture.ok(&["--json", "proxy", "delete", &second["id"].to_string()]).await;
    let paused = fixture.json(&["proxy", "set", &proxy_id, "--enabled", "off", "--name", "lan"]).await;
    assert_eq!((&paused["status"]["code"], &paused["name"]), (&json!("disabled"), &json!("lan")));
    assert!(fixture.fails(&["proxy", "set", &proxy_id, "--exit", "laptop"]).await.contains("exit_is_node"));
    let refused = fixture.fails(&["forward", "add", "laptop", "127.0.0.1:8080", "nas-01", "192.168.1.10:80"]).await;
    assert!(refused.contains("forward_target_off") && refused.contains("--forward-target on"), "{refused}");
    fixture.ok(&["node", "set", "nas-01", "--forward-target", "on"]).await;
    assert!(Fixture::has_line(&fixture.ok(&["node", "show", "nas-01"]).await, &["转发目标", "是"]));
    assert!(fixture.ok(&["node", "list"]).await.contains("中继、出口、转发目标"), "代理要出口，nas-01 又启用成了出口");
    let forward = fixture.json(&["forward", "add", "laptop", "127.0.0.1:8080", "nas-01", "192.168.1.10:80", "--name", "web"]).await;
    assert_eq!(forward["status"], "active");
    let forward_id = forward["id"].to_string();
    assert_eq!(fixture.json(&["forward", "disable", &forward_id]).await["status"], "disabled");
    assert_eq!(fixture.json(&["forward", "enable", &forward_id]).await["enabled"], true);
    assert!(fixture.ok(&["forward", "list"]).await.contains("#2 192.168.1.10:80"));
    // 没有设置的一对也看得到：各项都是默认值。ice3proxy 不在节点对上了。
    let unset = fixture.json(&["pair", "show", "nas-01", "laptop"]).await;
    assert_eq!(unset, json!({ "a": 1, "b": 2, "keep_alive": false, "congestion": null, "stored": false }), "{unset}");
    assert!(Fixture::has_line(&fixture.ok(&["pair", "show", "laptop", "nas-01"]).await, &["#1 ↔ #2", "默认"]));
    assert!(Fixture::has_line(&fixture.ok(&["pair", "list"]).await, &["#1", "#2", "默认"]), "没有设置的一对也在列表里，是默认");
    fixture.ok(&["pair", "set", "nas-01", "laptop", "--keep-alive", "on"]).await;
    assert!(Fixture::has_line(&fixture.ok(&["pair", "list"]).await, &["#1", "#2", "是", "默认"]));
    let pairs = fixture.json(&["pair", "list"]).await;
    assert_eq!(pairs, json!([{ "a": 1, "b": 2, "keep_alive": true, "congestion": null, "stored": true }]));
    assert!(fixture.fails(&["pair", "set", "nas-01", "laptop", "--lane", "always"]).await.contains("--lane"), "节点对上没有 ice3proxy 了");
    assert!(fixture.fails(&["pair", "set", "nas-01", "laptop"]).await.contains("--keep-alive"), "至少要改一项");

    // 地址、令牌和网络也可以从环境变量来。
    let mut from_env = fixture.command();
    from_env.env("I3T_ADMIN_URL", &url).env("I3T_ADMIN_TOKEN", &fixture.token).env("I3T_NETWORK", "home");
    let output = from_env.args(["node", "routes", "laptop"]).output().await.unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(fixture.fails(&["--network", "nowhere", "node", "list"]).await.contains("nowhere"));

    // 删除。--json 时没有应答体的操作什么都不输出。
    fixture.ok(&["pair", "unset", "laptop", "nas-01"]).await;
    assert_eq!(fixture.json(&["pair", "show", "laptop", "nas-01"]).await["stored"], json!(false), "去掉之后回到默认");
    fixture.ok(&["forward", "delete", &forward_id]).await;
    assert_eq!(fixture.ok(&["--json", "proxy", "delete", &proxy_id]).await, "");
    assert!(fixture.ok(&["node", "delete", "laptop"]).await.contains("节点 laptop 已删除"));
    assert_eq!(fixture.json(&["node", "list"]).await.as_array().unwrap().len(), 1);
    assert!(fixture.fails(&["network", "delete", "home"]).await.contains("network_not_empty"));
    let log = fixture.ok(&["log", "--limit", "5"]).await;
    assert!(log.contains("node.delete") && log.contains("删除节点 laptop") && log.lines().count() == 6, "{log}");

    // 同样的东西用英文看：按代码和参数写，没有一个汉字（controller 的原话是中文的，不能漏出来）。
    for args in [
        &["status"][..],
        &["overview"],
        &["network", "list"],
        &["network", "show"],
        &["node", "list"],
        &["node", "show", "nas-01"],
        &["rule", "list"],
        &["group", "list"],
        &["group", "show", "servers"],
        &["token", "list", "--all"],
        &["access", "graph"],
        &["proxy", "list"],
        &["proxy", "add", "--help"],
        &["forward", "list"],
        &["pair", "list"],
        &["log", "--limit", "100"],
        &["--help"],
        &["node", "set", "--help"],
    ] {
        fixture.english(args).await;
    }
    let english_log = fixture.english(&["log", "--limit", "100"]).await;
    assert!(english_log.contains("Node laptop deleted") && english_log.contains("Network home created"), "{english_log}");
    assert!(english_log.contains("Group servers renamed to boxes") && english_log.contains("Group spare deleted"), "{english_log}");
    let english_group = fixture.english(&["group", "create", "lab"]).await;
    assert!(english_group.starts_with("lab #"), "{english_group}");
    let url = format!("http://{}", fixture.admin);
    let unknown = fixture
        .command_in("en")
        .args(["--url", &url, "--token", &fixture.token, "node", "groups", "nas-01", "nope"])
        .output()
        .await
        .unwrap();
    let said = text(&unknown.stderr);
    assert!(!unknown.status.success() && said.contains("No group nope") && !i3t_lang::cli::has_chinese(&said), "{said}");
    let url = format!("http://{}", fixture.admin);
    let refused =
        fixture.command_in("en").args(["--url", &url, "--token", &fixture.token, "network", "delete", "home"]).output().await.unwrap();
    let said = text(&refused.stderr);
    assert!(!refused.status.success() && !i3t_lang::cli::has_chinese(&said) && said.contains("network_not_empty"), "{said}");
}

/// 在 `root` 里摆一个发布源（布局见 `i3t_controller::release`）：`version` 的 Linux 节点程序，清单用 `key` 签，
/// 写上安全下限 `security_floor`（有的话）。
fn publish(root: &std::path::Path, key: &NodeKey, version: &str, security_floor: Option<&str>, program: &[u8]) {
    let version: i3t_model::update::Version = version.parse().unwrap();
    let file = "i3t-linux-x86_64".to_owned();
    let release = root.join(version.release_dir());
    std::fs::create_dir_all(&release).unwrap();
    std::fs::write(release.join(&file), program).unwrap();
    let hash: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, program).as_ref().try_into().unwrap();
    let artifact = Artifact { file, size: u64::try_from(program.len()).unwrap(), sha256: Sha256::from_bytes(hash) };
    let manifest = Manifest {
        version,
        min_controller: "0.0.0".parse().unwrap(),
        published: 1_763_200_000,
        artifacts: [("linux-x86_64".to_owned(), artifact)].into(),
        security_floor: security_floor.map(|floor| floor.parse().unwrap()),
    };
    let signed = sign_manifest(key, serde_json::to_string(&manifest).unwrap());
    let latest = root.join(LATEST_DIR);
    std::fs::create_dir_all(&latest).unwrap();
    std::fs::write(latest.join(MANIFEST_FILE), &signed.manifest).unwrap();
    std::fs::write(latest.join(SIGNATURE_FILE), signed.signature.to_string()).unwrap();
}

#[tokio::test]
async fn updates_routes_and_paths_can_be_driven_from_the_command_line() {
    let (source, cache) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let release_key = NodeKey::generate().unwrap();
    let controller = Controller::new(
        Store::open_in_memory().unwrap(),
        NodeKey::generate().unwrap(),
        "ctl.example.com:20331".to_owned(),
        Timing::default(),
    )
    .unwrap()
    .with_release_keys(TrustedKeys::from(release_key.public()))
    .unwrap()
    .with_release_cache(cache.path().to_owned())
    // 下面发布的版本号是写死的，controller 的版本也固定下来，不随这个包的版本号变。
    .with_version("0.1.0".parse().unwrap());
    let fixture = Fixture::serve(controller).await;
    fixture.ok(&["network", "create", "home"]).await;

    // 设置。
    let shown = fixture.ok(&["update", "show"]).await;
    assert!(
        shown.contains("自动更新    开") && shown.contains("github.com") && shown.contains("（默认）") && shown.contains("还没有查到"),
        "{shown}"
    );
    let source_dir = source.path().to_str().unwrap();
    let set = fixture.json(&["update", "set", "--auto", "off", "--source", source_dir]).await;
    assert_eq!(
        (set["auto_update"].clone(), set["source"].clone(), set["source_is_default"].clone()),
        (false.into(), source_dir.into(), false.into())
    );
    assert!(fixture.fails(&["update", "set", "--source", "not/absolute"]).await.contains("invalid_request"));

    // 查发布源：先是什么都没有，然后有了一个版本。
    let empty = fixture.ok(&["update", "check"]).await;
    assert!(empty.contains("检查失败") && empty.contains("还没有查到"), "{empty}");
    publish(source.path(), &release_key, "0.2.0", Some("0.2.0"), b"the new program");
    let checked = fixture.ok(&["update", "check"]).await;
    assert!(Fixture::has_line(&checked, &["最新版本", "0.2.0"]) && Fixture::has_line(&checked, &["linux-x86_64", "不需要"]), "{checked}");
    assert!(Fixture::has_line(&checked, &["安全", "低于 0.2.0 的版本有已知的安全问题"]), "{checked}");
    assert_eq!(fixture.json(&["update", "show"]).await["release"]["security_floor"], "0.2.0");
    assert!(checked.contains("controller 也有新版本 0.2.0"), "{checked}");
    assert!(Fixture::has_line(&fixture.ok(&["status"]).await, &["新版本", "0.2.0"]));
    fixture.english(&["update", "show"]).await;

    // 一个懂更新的节点（主机名变成了它的名字），一个最初那一版的。
    let modern = Hello {
        version: "0.1.0".to_owned(),
        platform: "linux-x86_64".to_owned(),
        port: 20330,
        hostname: "Laptop.lan".to_owned(),
        protocol: PROTOCOL_REVISION,
        self_update: Some(SelfUpdate::ABLE),
        ..Hello::default()
    };
    let laptop = fixture.join_as(1, &modern).await;
    let ancient = fixture.join(2, Declared::default()).await;
    fixture.report(&laptop, Report { update: Some(UpdateStatus::Idle), ..Report::default() });
    let nodes = fixture.ok(&["update", "nodes"]).await;
    let row = |name: &str| nodes.lines().find(|line| line.contains(name)).unwrap_or_else(|| panic!("{nodes}")).to_owned();
    assert!(
        row("laptop").contains("0.2.0") && row("laptop").contains("是") && row("laptop").contains("有新版本 0.2.0（安全更新）"),
        "{nodes}"
    );
    assert!(row("node-2").contains("版本太旧") && row("node-2").contains("开"), "{nodes}");
    let detail = fixture.ok(&["node", "show", "laptop"]).await;
    assert!(
        Fixture::has_line(&detail, &["主机名", "Laptop.lan"]) && Fixture::has_line(&detail, &["更新", "有新版本 0.2.0（安全更新）"]),
        "{detail}"
    );
    assert!(Fixture::has_line(&detail, &["自动更新", "开"]), "{detail}");
    let off = fixture.json(&["node", "set", "laptop", "--auto-update", "off"]).await;
    assert_eq!((off["auto_update"].clone(), off["update"]["security"].clone()), (false.into(), true.into()));
    assert!(Fixture::has_line(&fixture.ok(&["node", "show", "laptop"]).await, &["自动更新", "关"]));
    let english = fixture.english(&["node", "show", "laptop"]).await;
    assert!(
        english.contains("0.2.0 available (security update)") && Fixture::has_line(&english, &["Automatic updates", "off"]),
        "{english}"
    );
    assert!(fixture.english(&["update", "show"]).await.contains("versions below 0.2.0 have a known security problem"));
    fixture.english(&["update", "nodes"]).await;

    // 强制更新：包还没有取回来时先排着；取回来之后指令发出去。
    assert!(fixture.fails(&["update", "node", "node-2"]).await.contains("cannot_self_update"));
    let queued = fixture.ok(&["update", "node", "laptop", "--drain"]).await;
    assert!(queued.contains("等待下载包"), "{queued}");
    let controller = Arc::clone(&fixture.controller);
    tokio::task::spawn_blocking(move || controller.fetch_packages().unwrap()).await.unwrap();
    let update = fixture.json(&["update", "node", "laptop", "--drain"]).await;
    assert_eq!(update["ordered"], serde_json::json!({ "version": "0.2.0", "timing": "after_drain" }));
    let all = fixture.ok(&["update", "all"]).await;
    assert!(Fixture::has_line(&all, &["已下发", "laptop"]) && Fixture::has_line(&all, &["跳过 node-2", "版本太旧"]), "{all}");
    fixture.report(&laptop, Report { update: Some(UpdateStatus::Draining { version: "0.2.0".parse().unwrap() }), ..Report::default() });
    assert!(fixture.ok(&["update", "nodes"]).await.contains("正在排空"));

    // 节点说这个版本不能用：自动更新暂停，看过之后继续。
    let failed = UpdateStatus::Failed {
        version: Some("0.2.0".parse().unwrap()),
        kind: FailureKind::VersionRejected,
        reason: "自检没有通过".into(),
        cause: Some(UpdateCause::SelfCheck { exit_code: Some(1), output: "config.toml unreadable".into() }),
    };
    fixture.report(&laptop, Report { update: Some(failed), ..Report::default() });
    let paused = fixture.ok(&["update", "show"]).await;
    assert!(paused.contains("0.2.0 已暂停：laptop") && paused.contains("i3tctl update resume 0.2.0"), "{paused}");
    assert!(paused.contains("自检没有通过（退出码 1）：config.toml unreadable"), "按原因的代码写：{paused}");
    assert!(fixture.ok(&["update", "nodes"]).await.contains("不再自动重试"));
    let english = fixture.english(&["update", "show"]).await;
    assert!(english.contains("Self-check failed (exit code 1): config.toml unreadable"), "{english}");
    fixture.english(&["update", "nodes"]).await;
    fixture.english(&["log"]).await;
    assert!(fixture.json(&["update", "resume", "0.2.0"]).await["paused"].as_array().unwrap().is_empty());
    assert!(fixture.fails(&["update", "resume", "0.2.0"]).await.contains("not_found"));
    assert!(fixture.fails(&["update", "resume", "latest"]).await.contains("版本号"));

    // 路由矩阵和两个节点之间的路径。
    let route =
        RouteEntry { peer: ancient.session.node, route: Route::Direct { addr: "203.0.113.9:20330".parse().unwrap() }, rtt_ms: Some(7) };
    fixture.report(
        &ancient,
        Report { routes: vec![RouteEntry { peer: laptop.session.node, ..route.clone() }], routes_full: true, ..Report::default() },
    );
    let matrix = fixture.ok(&["routes"]).await;
    assert!(matrix.lines().next().unwrap().starts_with("从") && matrix.contains("node-2  laptop  直连 203.0.113.9:20330  7"), "{matrix}");
    assert!(matrix.contains("没有上报过的节点：laptop"), "{matrix}");
    fixture.english(&["routes"]).await;
    assert_eq!(fixture.json(&["routes"]).await["entries"][0]["stale"], false);
    // laptop 懂路由查询但不会回答（它只是个收件箱），等几秒之后退回到上报的数据；它没有上报过。
    let path = fixture.ok(&["path", "laptop", "node-2"]).await;
    assert!(Fixture::has_line(&path, &["laptop → node-2", "没有数据"]), "{path}");
    assert!(
        path.contains("node-2 → laptop  直连 203.0.113.9:20330  7") && Fixture::has_line(&path, &["node-2 → laptop", "上报"]),
        "{path}"
    );
    assert!(path.contains("用的是它的上报"), "{path}");
    fixture.english(&["path", "laptop", "node-2"]).await;
    assert_eq!(fixture.json(&["path", "node-2", "laptop"]).await["forward"]["source"], "report");
    assert!(fixture.fails(&["path", "laptop", "laptop"]).await.contains("invalid_request"));
    assert!(fixture.ok(&["backbone"]).await.contains("还没有中继"));
    assert_eq!(fixture.json(&["backbone"]).await["relays"], serde_json::json!([]));
}

#[tokio::test]
async fn active_tests_and_the_matrix_are_run_and_shown_from_the_command_line() {
    use i3t_model::control::DirectKind;
    use i3t_model::control::TestReport;
    use i3t_model::control::diag::{DirectSide, TestRole};

    let fixture = Fixture::start().await;
    fixture.ok(&["network", "create", "home"]).await;
    let modern = Hello {
        version: "0.2.0".to_owned(),
        protocol: PROTOCOL_REVISION,
        throughput_tests: true,
        self_update: Some(SelfUpdate::ABLE),
        ..Hello::default()
    };
    let laptop = fixture.join_as(11, &modern).await;
    let nas = fixture.join_as(12, &modern).await;
    let _old = fixture.join(13, Declared::default()).await;
    fixture.ok(&["node", "rename", "1", "laptop"]).await;
    fixture.ok(&["node", "rename", "2", "nas"]).await;
    fixture.ok(&["node", "rename", "3", "old"]).await;

    let started = fixture.json(&["test", "laptop", "nas", "--only", "direct,route", "--no-wait"]).await;
    assert_eq!((started["state"].as_str(), started["request"]["items"].clone()), (Some("running"), serde_json::json!(["direct", "route"])));
    let id = started["id"].as_u64().unwrap();
    let side = DirectSide { ok: true, kind: Some(DirectKind::Punched), elapsed_ms: Some(640), ..DirectSide::default() };
    for (member, role) in [(&laptop, TestRole::Initiator), (&nas, TestRole::Responder)] {
        let report = TestReport { test: id, role: Some(role), last: true, direct: Some(side.clone()), ..TestReport::default() };
        fixture.controller.handle(member.session, REMOTE, ToController::TestReport(Box::new(report))).unwrap();
    }
    let shown = fixture.ok(&["tests", "show", &id.to_string()]).await;
    assert!(shown.contains(&format!("测试 #{id}  laptop → nas  完成")) && shown.contains("直连：是（打洞、640 ms）"), "{shown}");
    assert!(shown.contains("laptop：连上了") && shown.contains("nas：连上了"), "{shown}");
    let english = fixture.english(&["tests", "show", &id.to_string()]).await;
    assert!(english.contains("Direct: yes (hole punched, 640 ms)"), "{english}");
    let listed = fixture.ok(&["tests", "list", "nas", "laptop"]).await;
    assert!(listed.starts_with("编号  A") && Fixture::has_line(&listed, &[&id.to_string(), "laptop  nas"]), "{listed}");
    assert!(fixture.fails(&["test", "laptop", "nas"]).await.contains("too_soon"), "同一对刚测过");
    assert!(fixture.fails(&["tests", "cancel", &id.to_string()]).await.contains("busy"));

    // 版本太旧的节点：测试立刻失败，说是哪个节点。等结果的这一种也马上返回。
    let refused = fixture.ok(&["test", "laptop", "old"]).await;
    assert!(refused.contains("没有做成：old：版本太旧，不支持主动测试"), "{refused}");

    // 全网矩阵：开始（不等）、看、取消。
    let run = fixture.json(&["tests", "matrix", "--no-wait"]).await;
    assert_eq!((run["total"].as_u64(), run["state"].as_str()), (Some(3), Some("running")));
    let matrix = fixture.ok(&["tests", "matrix", "--show"]).await;
    assert!(matrix.starts_with("全网矩阵 #1  进行中") && matrix.contains("old：版本太旧"), "{matrix}");
    fixture.english(&["tests", "matrix", "--show"]).await;
    let cancelled = fixture.ok(&["tests", "matrix", "--cancel"]).await;
    assert!(cancelled.starts_with("全网矩阵 #1  已取消"), "{cancelled}");
}
