//! 两个真的路径层（同一台机器的回环地址上）之间的主动测试：直连尝试、探测包列、选路的结论、固定路。

#![allow(clippy::unwrap_used, reason = "整个文件都是测试代码，出错就该直接失败")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use i3t_crypto::NodeKey;
use i3t_model::Netmap;
use i3t_model::control::Route;
use i3t_path::diag::DirectFailure;
use i3t_path::{ChoiceReason, HopSource, PathConfig, Paths, Side, TestPath, TestSpec, TrainSpec};
use i3t_proto::NodeId;
use i3t_underlay::UdpPort;
use tokio::sync::watch;

struct Node {
    id: NodeId,
    paths: Paths,
    _netmap: watch::Sender<Arc<Netmap>>,
}

fn node(raw: u32) -> NodeId {
    NodeId::new(raw).unwrap()
}

/// 两个节点 1 和 2，各自的 netmap 里有对方和对方的地址。`reach_b` 是节点 2 的路径限制。
fn pair(reach_b: &str) -> (Node, Node) {
    let keys = [Arc::new(NodeKey::generate().unwrap()), Arc::new(NodeKey::generate().unwrap())];
    let ports = [UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap(), UdpPort::bind("127.0.0.1:0".parse().unwrap()).unwrap()];
    let addrs: Vec<SocketAddr> = ports.iter().map(UdpPort::local_addr).collect();
    let mut nodes = Vec::new();
    for ((index, key), port) in keys.iter().enumerate().zip(ports) {
        let (me, other) = (index, 1 - index);
        let (me_id, other_id) = (u32::try_from(me + 1).unwrap(), u32::try_from(other + 1).unwrap());
        let reach = if me == 1 { reach_b } else { "any" };
        let netmap: Netmap = serde_json::from_value(serde_json::json!({
            "version": 1,
            "network": { "name": "test", "domain": "test.i3t", "cidr": "10.66.0.0/16" },
            "me": { "id": me_id, "name": format!("n{me_id}"), "virtual_ip": format!("10.66.0.{me_id}"), "reach": reach },
            "peers": [{
                "id": other_id, "key": keys[other].public(), "name": format!("n{other_id}"), "virtual_ip": format!("10.66.0.{other_id}"),
                "inbound": true, "outbound": true, "endpoints": [addrs[other]],
            }],
        }))
        .unwrap();
        let (sender, receiver) = watch::channel(Arc::new(netmap));
        let paths = Paths::new(PathConfig { key: Arc::clone(key), port: Arc::new(port), netmap: receiver, addr_servers: Vec::new() });
        nodes.push(Node { id: node(me_id), paths, _netmap: sender });
    }
    let b = nodes.pop().unwrap();
    let a = nodes.pop().unwrap();
    (a, b)
}

/// 路径层的收包要有人一直在调用（平时是连接层）。测试里起一个任务不停地收，收到的连接包扔掉。
async fn pump(paths: &Paths) {
    let mut storage = vec![0u8; 64 * 1024];
    let mut metas = [i3t_path::PacketMeta { peer: node(1), len: 0, stride: 0, ecn: None }; 1];
    loop {
        let mut bufs = [std::io::IoSliceMut::new(&mut storage)];
        let received = std::future::poll_fn(|cx| paths.poll_recv(cx, &mut bufs, &mut metas)).await;
        if received.is_err() {
            return;
        }
    }
}

fn spec(test: u64, peer: NodeId) -> TestSpec {
    TestSpec { test, peer, side: Side::Lead, window: Duration::from_secs(30), max_probes: 100, relays: Vec::new() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_test_finds_the_path_measures_every_probe_and_needs_the_peer_to_have_the_same_test_open() {
    let (a, b) = pair("any");
    let run = async {
        let attempt = a.paths.attempt_direct(b.id, Side::Lead, Duration::from_secs(5)).await;
        assert!(attempt.ok && !attempt.already && attempt.kind.is_some(), "{attempt:?}");
        assert!(attempt.elapsed.is_some_and(|elapsed| elapsed < Duration::from_secs(5)), "{attempt:?}");
        let again = a.paths.attempt_direct(b.id, Side::Lead, Duration::from_secs(5)).await;
        assert!(again.ok && again.already, "已经有的直连当场回答：{again:?}");

        let train = |count| TrainSpec { test: 7, peer: b.id, path: TestPath::Direct, count, interval: Duration::from_millis(10) };
        let _a_window = a.paths.open_test(spec(7, b.id));
        let unanswered = a.paths.train(train(5)).await.unwrap();
        assert_eq!(unanswered.summary().answered, 0, "对端没有打开这个测试，一个都不回答");

        let _b_window = b.paths.open_test(spec(7, a.id));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let report = a.paths.train(train(20)).await.unwrap();
        let summary = report.summary();
        assert_eq!((summary.sent, summary.answered, summary.loss_permille), (20, 20, 0), "{report:?}");
        assert_eq!((report.peer_received, report.same_path), (Some(20), 20));
        // 平均值可以高于 p95：20 个样本里只要有一个很慢的，就能把平均值抬到第 19 个之上。
        assert!(summary.min_us <= summary.avg_us && summary.min_us <= summary.p95_us, "{summary:?}");
        assert!(summary.avg_us.is_some_and(|avg| avg < 50_000), "回环上的往返不到 50ms：{summary:?}");
        assert!(report.peer_addr.is_some());

        let decision = a.paths.decide(b.id).await.unwrap();
        assert_eq!(decision.direct_first.reason, ChoiceReason::Direct);
        assert!(matches!(decision.direct_first.route, Route::Direct { .. }));
        assert!(matches!(decision.lowest_cost.route, Route::Direct { .. }), "唯一的候选就是直连：{decision:?}");
        assert_eq!((decision.default_relay, decision.cheapest_relay), (None, None), "没有 relay");
        let hops = a.paths.hops(b.id, TestPath::Direct).await;
        assert_eq!(hops.len(), 1);
        assert_eq!((hops[0].from, hops[0].to, hops[0].source), (a.id, b.id, HopSource::Measured));

        drop(_b_window);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let closed = a.paths.train(train(5)).await.unwrap();
        assert_eq!(closed.summary().answered, 0, "对端关掉了这个测试");
    };
    tokio::select! {
        () = run => {}
        () = pump(&a.paths) => panic!("收包停了"),
        () = pump(&b.paths) => panic!("收包停了"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_only_node_takes_no_part_in_a_direct_test() {
    let (a, b) = pair("relay_only");
    let run = async {
        let refused = b.paths.attempt_direct(a.id, Side::Lead, Duration::from_secs(1)).await;
        assert_eq!((refused.ok, refused.failure), (false, Some(DirectFailure::RelayOnly)));
        let tried = a.paths.attempt_direct(b.id, Side::Lead, Duration::from_secs(2)).await;
        assert!(!tried.ok, "只经 relay 的节点不回答直连的探测：{tried:?}");
        let _a_window = a.paths.open_test(spec(9, b.id));
        let _b_window = b.paths.open_test(spec(9, a.id));
        let train = TrainSpec { test: 9, peer: b.id, path: TestPath::Direct, count: 5, interval: Duration::from_millis(10) };
        assert!(a.paths.train(train).await.is_err(), "没有直连可以测");
    };
    tokio::select! {
        () = run => {}
        () = pump(&a.paths) => panic!("收包停了"),
        () = pump(&b.paths) => panic!("收包停了"),
    }
}
