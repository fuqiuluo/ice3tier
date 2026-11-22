//! 管理 API 的测试：请求直接交给路由，不经过网络端口。

// clippy.toml 里的 allow-unwrap-in-tests 只认 `#[test]` 函数本身，认不出集成测试里的辅助函数。
#![allow(clippy::unwrap_used, reason = "整个文件都是测试代码，出错就该直接失败")]

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use i3t_controller::store::Store;
use i3t_controller::webui::{Asset, WebUi};
use i3t_controller::{Admitted, Controller, Timing, admin};
use i3t_crypto::NodeKey;
use i3t_model::admin as model;
use i3t_model::control::{
    BackboneLink, BackboneRow, BindCause, Declared, DirectKind, EnrollToken, Hello, ListenState, ListenTraffic, PathCandidate, PathDetail,
    PathSegment, ProxyReport, RelayState, Report, Route, RouteAnswer, RouteCause, RouteEntry, RouteKind, SelfUpdate, ToController, ToNode,
};
use i3t_model::netmap::{LaneMode, RoutingMode};
use i3t_model::update::{FailureKind, UpdateCause, UpdateStatus, UpdateTiming};
use i3t_proto::{NodeId, PublicKey};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tower::ServiceExt;

use crate::common::{Publisher, modern_hello};

const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

struct Api {
    router: Router,
    controller: Arc<Controller>,
    token: String,
    next_key: u8,
}

/// 一个假装在线的节点。收件箱要留着，丢了 controller 会当它断线。
struct Member {
    id: NodeId,
    key: PublicKey,
    session: Admitted,
    inbox: mpsc::Receiver<ToNode>,
}

impl Member {
    /// 等 controller 发来的下一条查询（路由的、骨干矩阵的、出口测试），跳过别的消息。
    async fn next_query(&mut self) -> ToNode {
        loop {
            let message = tokio::time::timeout(common::PATIENCE, self.inbox.recv()).await.unwrap().unwrap();
            if matches!(message, ToNode::RouteQuery { .. } | ToNode::BackboneQuery { .. } | ToNode::ExitTest { .. }) {
                return message;
            }
        }
    }
}

impl Api {
    fn new() -> Self {
        Self::with_webui(&WebUi::NotIncluded)
    }

    fn with_webui(webui: &WebUi) -> Self {
        let store = Store::open_in_memory().unwrap();
        let controller =
            Controller::new(store, NodeKey::generate().unwrap(), "ctl.example.com:20331".to_owned(), Timing::default()).unwrap();
        Self::around(controller, webui)
    }

    fn around(controller: Controller, webui: &WebUi) -> Self {
        let token = controller.issue_admin_token().unwrap();
        let controller = Arc::new(controller);
        Self { router: admin::router(Arc::clone(&controller), webui), controller, token, next_key: 0 }
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (parts.status, parts.headers, bytes.to_vec())
    }

    fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Request<Body> {
        let builder =
            Request::builder().method(method).uri(format!("/api/v1{path}")).header(header::AUTHORIZATION, format!("Bearer {}", self.token));
        match body {
            Some(body) => builder.header(header::CONTENT_TYPE, "application/json").body(Body::from(body.to_string())).unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    /// 带着管理令牌发一个请求，返回状态码和 JSON 应答体（没有应答体时是 `null`）。
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let (status, _, bytes) = self.send(self.request(method, path, body.as_ref())).await;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("应答体不是 JSON：{}", String::from_utf8_lossy(&bytes)))
        };
        (status, value)
    }

    /// 期望成功，并把应答体读成 `T`。
    async fn ok<T: DeserializeOwned>(&self, method: Method, path: &str, body: Option<Value>) -> T {
        let (status, value) = self.call(method.clone(), path, body).await;
        assert!(status.is_success(), "{method} {path} 应该成功，实际是 {status}：{value}");
        serde_json::from_value(value.clone()).unwrap_or_else(|err| panic!("{method} {path} 的应答不符合模型：{err}\n{value}"))
    }

    /// 期望失败，返回错误码和说明。
    async fn fails(&self, method: Method, path: &str, body: Option<Value>, expected: StatusCode) -> model::ApiError {
        let (status, value) = self.call(method.clone(), path, body).await;
        assert_eq!(status, expected, "{method} {path}：{value}");
        let body: model::ErrorBody =
            serde_json::from_value(value.clone()).unwrap_or_else(|err| panic!("错误的应答不符合统一格式：{err}\n{value}"));
        assert!(!body.error.message.is_empty());
        body.error
    }

    async fn network(&self, name: &str) -> model::Network {
        self.ok(Method::POST, "/networks", Some(json!({ "name": name }))).await
    }

    /// 经 API 找叫 `name` 的分组（不分大小写），没有就建一个。`all` 是内置的 `All`。
    async fn group(&self, network: model::NetworkId, name: &str) -> model::GroupId {
        let path = format!("/networks/{network}/groups");
        let groups: Vec<model::Group> = self.ok(Method::GET, &path, None).await;
        match groups.into_iter().find(|group| group.name.eq_ignore_ascii_case(name)) {
            Some(group) => group.id,
            None => self.ok::<model::Group>(Method::POST, &path, Some(json!({ "name": name }))).await.id,
        }
    }

    /// 经 API 生成注册令牌，再让一个节点用它加入并保持在线。
    async fn join(&mut self, network: model::NetworkId, declared: Declared) -> Member {
        self.join_as(network, &hello(declared)).await
    }

    /// 同上，节点带着指定的自我介绍。懂更新的节点顺带做第一次上报：controller 等它到了才会给节点下发更新指令。
    async fn join_as(&mut self, network: model::NetworkId, hello: &Hello) -> Member {
        let created: model::CreatedEnrollToken = self.ok(Method::POST, &format!("/networks/{network}/tokens"), Some(json!({}))).await;
        let secret = created.token.parse::<EnrollToken>().unwrap().secret;
        self.next_key += 1;
        let key = PublicKey::from_bytes([self.next_key; PublicKey::LEN]);
        let (outbox, inbox) = mpsc::channel(64);
        let session = self.controller.enroll(key, &secret, hello, REMOTE, outbox).unwrap();
        if hello.protocol > 0 {
            let report = Report { update: Some(UpdateStatus::Idle), ..Report::default() };
            self.controller.handle(session, REMOTE, ToController::Report(Box::new(report))).unwrap();
        }
        Member { id: session.node, key, session, inbox }
    }
}

fn hello(declared: Declared) -> Hello {
    Hello { version: "0.1.0".to_owned(), platform: "linux-x86_64".to_owned(), declared, port: 20330, ..Hello::default() }
}

const CAN_DO_ALL: Declared = Declared { exit: true, relay: true, relay_address: None };

#[tokio::test]
async fn requests_without_the_admin_token_are_refused() {
    let api = Api::new();
    let paths = ["/api/v1/status", "/api/v1/networks", "/api/v1/networks/1/nodes", "/api/v1/no-such-endpoint"];
    let attempts: [Option<String>; 5] = [
        None,
        Some("Bearer wrong-token".to_owned()),
        Some(format!("Basic {}", api.token)),
        Some(api.token.clone()),
        Some("Bearer ".to_owned()),
    ];
    for path in paths {
        for attempt in &attempts {
            let mut builder = Request::builder().uri(path);
            if let Some(value) = attempt {
                builder = builder.header(header::AUTHORIZATION, value);
            }
            let (status, headers, bytes) = api.send(builder.body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} {attempt:?}");
            assert_eq!(headers.get(header::WWW_AUTHENTICATE).unwrap(), "Bearer");
            let body: model::ErrorBody = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body.error.code, model::ErrorCode::Unauthorized);
        }
    }
    // 改动类的请求同样被挡住，什么都没发生。
    let request = Request::builder().method(Method::POST).uri("/api/v1/networks").header(header::CONTENT_TYPE, "application/json");
    let (status, _, _) = api.send(request.body(Body::from(json!({ "name": "home" }).to_string())).unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(api.controller.networks().unwrap().is_empty());

    let status: model::Status = api.ok(Method::GET, "/status", None).await;
    assert_eq!(
        (status.controller_key, status.public_addr.as_str(), status.networks),
        (api.controller.public_key(), "ctl.example.com:20331", 0)
    );

    // 换了令牌之后旧的立刻失效。
    let fresh = api.controller.issue_admin_token().unwrap();
    api.fails(Method::GET, "/status", None, StatusCode::UNAUTHORIZED).await;
    let renewed = Api { token: fresh, router: api.router.clone(), controller: Arc::clone(&api.controller), next_key: 0 };
    renewed.ok::<model::Status>(Method::GET, "/status", None).await;
}

#[tokio::test]
async fn networks_can_be_created_listed_changed_and_deleted() {
    let api = Api::new();
    let home = api.network("home").await;
    assert_eq!((home.name.as_str(), home.domain.as_str(), home.nodes), ("home", "home.i3t", 0));
    assert_eq!(home.cidr, "10.66.0.0/16".parse().unwrap());
    assert_eq!((home.ack_eliciting_threshold, home.max_ack_delay_ms, home.bundle_small_packets), (3, 2, true), "没写的设置用默认值");
    let defaults = home.defaults.clone().expect("controller 报出各项设置的默认值");
    assert_eq!(
        (home.routing, home.max_relay_hops, home.reach, home.class, home.ack_eliciting_threshold, home.max_ack_delay_ms),
        (
            defaults.routing,
            defaults.max_relay_hops,
            defaults.reach,
            defaults.class,
            defaults.ack_eliciting_threshold,
            defaults.max_ack_delay_ms
        ),
        "新建的网络每一项都是默认值"
    );
    let explicit = json!({
        "name": "lab", "cidr": "10.99.3.4/24", "routing": "lowest_cost", "max_relay_hops": 3, "reach": "direct_only",
        "ack_eliciting_threshold": 4, "max_ack_delay_ms": 5, "bundle_small_packets": false
    });
    let lab: model::Network = api.ok(Method::POST, "/networks", Some(explicit)).await;
    assert_eq!(lab.cidr, "10.99.3.0/24".parse().unwrap());
    assert_eq!((lab.max_relay_hops, serde_json::to_value(lab.routing).unwrap()), (3, json!("lowest_cost")));
    assert_eq!((lab.ack_eliciting_threshold, lab.max_ack_delay_ms, lab.bundle_small_packets), (4, 5, false));

    let listed: Vec<model::Network> = api.ok(Method::GET, "/networks", None).await;
    assert_eq!(listed, vec![home.clone(), lab.clone()]);
    let shown: model::Network = api.ok(Method::GET, &format!("/networks/{}", lab.id), None).await;
    assert_eq!(shown, lab);

    let changed: model::Network =
        api.ok(Method::PATCH, &format!("/networks/{}", lab.id), Some(json!({ "reach": "any", "cidr": "10.99.0.0/16" }))).await;
    assert_eq!((changed.cidr, serde_json::to_value(changed.reach).unwrap()), ("10.99.0.0/16".parse().unwrap(), json!("any")));
    assert_eq!(changed.max_relay_hops, 3, "没写的字段不变");
    let quieter: model::Network =
        api.ok(Method::PATCH, &format!("/networks/{}", lab.id), Some(json!({ "ack_eliciting_threshold": 20 }))).await;
    assert_eq!((quieter.ack_eliciting_threshold, quieter.max_ack_delay_ms), (20, 5));
    assert!(!quieter.bundle_small_packets, "没提到的设置不变");
    let bundling: model::Network =
        api.ok(Method::PATCH, &format!("/networks/{}", lab.id), Some(json!({ "bundle_small_packets": true }))).await;
    assert!(bundling.bundle_small_packets);
    assert_eq!(bundling.ack_eliciting_threshold, 20);
    assert_eq!(quieter.defaults, Some(defaults), "默认值不跟着网络的设置变");

    let overlap = api.fails(Method::POST, "/networks", Some(json!({ "name": "x", "cidr": "10.66.1.0/24" })), StatusCode::CONFLICT).await;
    assert_eq!(overlap.code, model::ErrorCode::RangeOverlaps);
    let taken = api.fails(Method::POST, "/networks", Some(json!({ "name": "home" })), StatusCode::CONFLICT).await;
    assert_eq!(taken.code, model::ErrorCode::NameTaken);
    let invalid = api.fails(Method::POST, "/networks", Some(json!({ "name": "Not Valid" })), StatusCode::BAD_REQUEST).await;
    assert_eq!(invalid.code, model::ErrorCode::InvalidRequest);
    let hops =
        api.fails(Method::PATCH, &format!("/networks/{}", lab.id), Some(json!({ "max_relay_hops": 9 })), StatusCode::BAD_REQUEST).await;
    assert_eq!(hops.code, model::ErrorCode::InvalidRequest);

    let (status, body) = api.call(Method::DELETE, &format!("/networks/{}", lab.id), None).await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, Value::Null));
    api.fails(Method::GET, &format!("/networks/{}", lab.id), None, StatusCode::NOT_FOUND).await;
    api.fails(Method::DELETE, &format!("/networks/{}", lab.id), None, StatusCode::NOT_FOUND).await;
}

#[tokio::test]
async fn enrolment_tokens_show_their_text_only_once() {
    let api = Api::new();
    let network = api.network("home").await;
    let path = format!("/networks/{}/tokens", network.id);
    let servers = api.group(network.id, "Servers").await;
    let request = json!({ "expires_in_secs": 600, "groups": [servers], "virtual_ip": "10.66.0.9" });
    let (status, created) = api.call(Method::POST, &path, Some(request)).await;
    assert_eq!(status, StatusCode::CREATED);
    let text = created["token"].as_str().unwrap();
    let token: EnrollToken = text.parse().unwrap();
    assert_eq!((token.controller.as_str(), token.key), ("ctl.example.com:20331", api.controller.public_key()));
    assert_eq!(created["groups"], json!([{ "id": servers, "name": "Servers", "builtin": false }]));
    assert_eq!(created["virtual_ip"], json!("10.66.0.9"));
    assert_eq!(created["expires_at"].as_u64().unwrap() - created["created_at"].as_u64().unwrap(), 600);

    let (_, listed) = api.call(Method::GET, &path, None).await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["id"], created["id"]);
    assert!(listed[0].get("token").is_none(), "令牌文本只在创建的应答里出现");
    assert!(!listed.to_string().contains(&token.secret));

    let unknown_node = api.fails(Method::POST, &path, Some(json!({ "successor_of": 99 })), StatusCode::NOT_FOUND).await;
    assert_eq!(unknown_node.code, model::ErrorCode::NotFound);
    let unknown_group = api.fails(Method::POST, &path, Some(json!({ "groups": [servers, 99] })), StatusCode::NOT_FOUND).await;
    assert_eq!((unknown_group.what.as_deref(), unknown_group.field.as_deref()), (Some("group"), Some("groups[1]")));
    let (status, _) = api.call(Method::DELETE, &format!("{path}/{}", created["id"]), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let listed: Vec<model::EnrollTokenInfo> = api.ok(Method::GET, &path, None).await;
    assert!(listed.is_empty());
}

#[tokio::test]
async fn a_node_can_be_inspected_changed_and_deleted() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let base = format!("/networks/{}/nodes", network.id);
    let node = api.join(network.id, Declared::default()).await;
    let relay = api.join(network.id, CAN_DO_ALL).await;
    let path = format!("{base}/{}", node.id);

    let listed: Vec<model::Node> = api.ok(Method::GET, &base, None).await;
    assert_eq!(listed.iter().map(|node| node.id).collect::<Vec<_>>(), vec![node.id, relay.id]);
    // 节点只是用令牌注册过（这条连接是注册的那一条），还没有带着 Hello 连上来过：没有"最近在线"。
    assert!(listed[0].online && listed[0].last_seen_at.is_none());
    assert_eq!((listed[0].key, listed[0].virtual_ip), (node.key, "10.66.0.1".parse::<Ipv4Addr>().unwrap()));
    assert_eq!(listed[0].fqdn, format!("{}.home.i3t", listed[0].name));
    assert_eq!((listed[0].netmap_version, listed[0].sent_version, listed[0].acked_version), (2, 2, 0));

    let report = Report {
        endpoints: vec!["192.168.1.5:20330".parse().unwrap()],
        flows: 2,
        tx_bytes: 10,
        rx_bytes: 20,
        routes: vec![RouteEntry { peer: relay.id, route: Route::Relay { relays: vec![relay.id] }, rtt_ms: Some(30) }],
        ..Report::default()
    };
    api.controller.handle(node.session, REMOTE, ToController::Report(Box::new(report))).unwrap();
    let detail: model::NodeDetail = api.ok(Method::GET, &path, None).await;
    assert_eq!(detail.node.id, node.id);
    assert_eq!(detail.endpoints, vec!["192.168.1.5:20330".parse().unwrap()]);
    assert_eq!(detail.observed_endpoint, Some("198.51.100.7:20330".parse().unwrap()));
    assert_eq!((detail.flows, detail.tx_bytes, detail.rx_bytes), (2, 10, 20));
    let (_, raw) = api.call(Method::GET, &path, None).await;
    assert!(raw["name"].is_string() && raw["endpoints"].is_array(), "详情里列表的字段和上报的字段在同一层：{raw}");
    let table: model::RouteTable = api.ok(Method::GET, &format!("{path}/routes"), None).await;
    assert!(table.online);
    assert_eq!((table.routes[0].peer.id, table.routes[0].rtt_ms), (relay.id, Some(30)));
    assert_eq!(serde_json::to_value(&table.routes[0].route).unwrap(), json!({ "via": "relay", "relays": [relay.id] }));

    // 改名、改分组、开关；null 表示清掉覆盖值。
    let (laptops, all) = (api.group(network.id, "laptops").await, api.group(network.id, "all").await);
    let patch =
        json!({ "name": "Laptop", "groups": [laptops, all], "dial_out_only": true, "routing": "lowest_cost", "reach": "relay_only" });
    let changed: model::Node = api.ok(Method::PATCH, &path, Some(patch)).await;
    assert_eq!((changed.name.as_str(), changed.fqdn.as_str()), ("laptop", "laptop.home.i3t"));
    assert_eq!(
        serde_json::to_value(&changed.groups).unwrap(),
        json!([{ "id": laptops, "name": "laptops", "builtin": false }]),
        "All 不列出"
    );
    assert!(changed.dial_out_only && changed.routing.is_some() && changed.reach.is_some());
    let cleared: model::Node = api.ok(Method::PATCH, &path, Some(json!({ "routing": null }))).await;
    assert!(cleared.routing.is_none() && cleared.reach.is_some() && cleared.name == "laptop");
    let moved: model::Node = api.ok(Method::PATCH, &path, Some(json!({ "virtual_ip": "10.66.9.9" }))).await;
    assert_eq!(moved.virtual_ip, "10.66.9.9".parse::<Ipv4Addr>().unwrap());

    let taken = api.fails(Method::PATCH, &path, Some(json!({ "virtual_ip": "10.66.0.2" })), StatusCode::CONFLICT).await;
    assert_eq!(taken.code, model::ErrorCode::AddressTaken);
    let outside = api.fails(Method::PATCH, &path, Some(json!({ "virtual_ip": "10.67.0.1" })), StatusCode::BAD_REQUEST).await;
    assert_eq!(outside.code, model::ErrorCode::AddressOutOfRange);

    // 没声明的能力启用不了，错误里写着要在节点上执行的命令。
    let refused = api.fails(Method::PUT, &format!("{path}/exit"), Some(json!({})), StatusCode::CONFLICT).await;
    assert_eq!(refused.code, model::ErrorCode::NotDeclared);
    assert!(refused.message.contains("i3t set can-exit on") && refused.message.contains("laptop"), "{}", refused.message);
    let refused =
        api.fails(Method::PUT, &format!("{path}/relay"), Some(json!({ "udp": ["203.0.113.7:20330"] })), StatusCode::CONFLICT).await;
    assert!(refused.message.contains("i3t set can-relay on"), "{}", refused.message);

    let relay_path = format!("{base}/{}", relay.id);
    let zero = api.fails(Method::PUT, &format!("{relay_path}/relay"), Some(json!({ "bandwidth_mbps": 0 })), StatusCode::BAD_REQUEST).await;
    assert_eq!(
        (zero.code, zero.what.as_deref(), zero.field.as_deref()),
        (model::ErrorCode::InvalidRequest, Some("zero"), Some("bandwidth_mbps"))
    );
    // 早先的请求体照收，填的地址和区域没有作用：地址是 controller 找出来的。
    let settings = json!({ "udp": ["203.0.113.7:20330"], "tcp": ["203.0.113.7:20330"], "region": "hk", "bandwidth_mbps": 200 });
    let enabled: model::Node = api.ok(Method::PUT, &format!("{relay_path}/relay"), Some(settings)).await;
    assert_eq!(
        serde_json::to_value(enabled.relay.unwrap()).unwrap(),
        json!({
            "addresses": [{ "address": "198.51.100.7:20330", "source": "observed" }], "bandwidth_mbps": 200,
            "reach": { "reached": 0, "unreached": 0, "unknown": 1 }, "users": null
        })
    );
    let plain: model::Node = api.ok(Method::PUT, &format!("{relay_path}/relay"), Some(json!({}))).await;
    assert_eq!(plain.relay.unwrap().bandwidth_mbps, None, "{{}} 就是不限带宽地启用");
    // 出口没有带宽上限：早先的界面还会发的 bandwidth_mbps 照收（连 0 也是），没有作用，应答里没有它。
    let exit: model::Node = api.ok(Method::PUT, &format!("{relay_path}/exit"), Some(json!({ "lan": true, "bandwidth_mbps": 0 }))).await;
    assert_eq!(
        serde_json::to_value(exit.exit.unwrap()).unwrap(),
        json!({
            "ports": null, "lan": true, "upstream_socks5": null,
            // 后来加的出口设置，没写的取默认值。端口默认不限。
            "quota_bytes": null, "quota_reset_day": 1, "family": "any", "connects_per_minute": null, "class": null, "optimistic": null
        })
    );
    let pinned: model::Node = api.ok(Method::PATCH, &path, Some(json!({ "pinned_relays": [relay.id] }))).await;
    assert_eq!(pinned.pinned_relays, vec![relay.id]);
    let profiled: Value = api.ok(Method::PATCH, &path, Some(json!({ "profile": "high_throughput" }))).await;
    assert_eq!(profiled["profile"], json!("high_throughput"));
    let unprofiled: Value = api.ok(Method::PATCH, &path, Some(json!({ "profile": null }))).await;
    assert_eq!(unprofiled["profile"], Value::Null);
    let bad = api.fails(Method::PATCH, &path, Some(json!({ "profile": "turbo" })), StatusCode::BAD_REQUEST).await;
    assert_eq!(bad.field.as_deref(), Some("profile"));
    let disabled: model::Node = api.ok(Method::DELETE, &format!("{relay_path}/exit"), None).await;
    assert!(disabled.exit.is_none() && disabled.relay.is_some());
    let disabled: model::Node = api.ok(Method::DELETE, &format!("{relay_path}/relay"), None).await;
    assert!(disabled.relay.is_none());

    let access: model::NodeAccess = api.ok(Method::GET, &format!("{path}/access"), None).await;
    assert_eq!(access.can_reach.iter().map(|edge| edge.node.id).collect::<Vec<_>>(), vec![relay.id]);
    assert_eq!(access.reachable_by[0].rules.len(), 1);

    // 继任：在线的节点不能被继任。
    let online = api.fails(Method::POST, &format!("{path}/succeed"), Some(json!({ "predecessor": relay.id })), StatusCode::CONFLICT).await;
    assert_eq!(online.code, model::ErrorCode::PredecessorOnline);
    api.controller.disconnect(relay.session);
    let successor: model::Node = api.ok(Method::POST, &format!("{path}/succeed"), Some(json!({ "predecessor": relay.id }))).await;
    assert_eq!((successor.id, successor.virtual_ip), (node.id, "10.66.0.2".parse::<Ipv4Addr>().unwrap()));
    api.fails(Method::GET, &relay_path, None, StatusCode::NOT_FOUND).await;

    let (status, body) = api.call(Method::DELETE, &path, None).await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, Value::Null));
    api.fails(Method::GET, &path, None, StatusCode::NOT_FOUND).await;
    api.fails(Method::DELETE, &path, None, StatusCode::NOT_FOUND).await;
    let listed: Vec<model::Node> = api.ok(Method::GET, &base, None).await;
    assert!(listed.is_empty());
}

#[tokio::test]
async fn rules_and_the_access_views_follow_each_other() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let base = format!("/networks/{}", network.id);
    let laptop = api.join(network.id, Declared::default()).await;
    let server = api.join(network.id, Declared::default()).await;
    let loner = api.join(network.id, Declared::default()).await;
    let (laptops, servers, all) =
        (api.group(network.id, "Laptops").await, api.group(network.id, "servers").await, api.group(network.id, "all").await);
    for (member, group) in [(&laptop, laptops), (&server, servers)] {
        api.ok::<model::Node>(Method::PATCH, &format!("{base}/nodes/{}", member.id), Some(json!({ "groups": [group] }))).await;
    }

    let rules: Vec<model::Rule> = api.ok(Method::GET, &format!("{base}/rules"), None).await;
    assert_eq!(rules.len(), 1);
    let builtin = json!({ "id": all, "name": "All", "builtin": true });
    assert_eq!(
        serde_json::to_value(&rules[0]).unwrap(),
        json!({ "id": rules[0].id, "name": "default", "src": builtin, "dst": builtin, "direction": "both", "enabled": true })
    );
    let default_rule = format!("{base}/rules/{}", rules[0].id);
    let disabled: model::Rule = api.ok(Method::PATCH, &default_rule, Some(json!({ "enabled": false }))).await;
    assert!(!disabled.enabled && disabled.src.id == all);

    let (status, created) = api
        .call(
            Method::POST,
            &format!("{base}/rules"),
            Some(json!({ "src": laptops, "dst": servers, "direction": "one_way", "name": "ssh" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        (created["src"].clone(), created["direction"].clone(), created["enabled"].clone()),
        (json!({ "id": laptops, "name": "Laptops", "builtin": false }), json!("one_way"), json!(true))
    );
    let rule_id = created["id"].as_u64().unwrap();
    let by_name =
        api.fails(Method::POST, &format!("{base}/rules"), Some(json!({ "src": "laptops", "dst": servers })), StatusCode::BAD_REQUEST).await;
    assert_eq!((by_name.code, by_name.what.as_deref()), (model::ErrorCode::InvalidRequest, Some("data")), "分组按编号引用");
    let missing =
        api.fails(Method::POST, &format!("{base}/rules"), Some(json!({ "src": laptops, "dst": 99 })), StatusCode::NOT_FOUND).await;
    assert_eq!((missing.what.as_deref(), missing.field.as_deref()), (Some("group"), Some("dst")));

    let check = |from: NodeId, to: NodeId| format!("{base}/access/check?from={from}&to={to}");
    let allowed: model::AccessCheck = api.ok(Method::GET, &check(laptop.id, server.id), None).await;
    assert!(allowed.allowed);
    assert_eq!(allowed.rules.iter().map(|rule| u64::from(rule.id)).collect::<Vec<_>>(), vec![rule_id]);
    assert_eq!((allowed.from.id, allowed.to.id), (laptop.id, server.id));
    let denied: model::AccessCheck = api.ok(Method::GET, &check(server.id, laptop.id), None).await;
    assert!(!denied.allowed && denied.rules.is_empty());
    api.fails(Method::GET, &check(laptop.id, NodeId::new(99).unwrap()), None, StatusCode::NOT_FOUND).await;
    api.fails(Method::GET, &format!("{base}/access/check?from={}", laptop.id), None, StatusCode::BAD_REQUEST).await;

    let graph: model::AccessGraph = api.ok(Method::GET, &format!("{base}/access/graph"), None).await;
    let members = |name: &str| {
        graph.groups.iter().find(|group| group.name == name).map(|group| group.nodes.iter().map(|node| node.id).collect::<Vec<_>>())
    };
    assert_eq!(graph.groups.iter().map(|group| group.name.as_str()).collect::<Vec<_>>(), vec!["All", "Laptops", "servers"]);
    assert_eq!(members("All"), Some(vec![laptop.id, server.id, loner.id]));
    assert_eq!(members("Laptops"), Some(vec![laptop.id]));
    assert_eq!(graph.rules.len(), 2, "停用的规则也在图里（画成虚线）");
    assert_eq!(graph.unconnected.iter().map(|node| node.id).collect::<Vec<_>>(), vec![loner.id]);
    assert!(!graph.unacknowledged.is_empty(), "这些节点从来没有确认过 netmap");

    let view: model::NodeAccess = api.ok(Method::GET, &format!("{base}/nodes/{}/access", server.id), None).await;
    assert!(view.can_reach.is_empty() && !view.acknowledged);
    assert_eq!(view.reachable_by.len(), 1);
    assert_eq!((view.reachable_by[0].node.id, view.reachable_by[0].rules.clone()), (laptop.id, vec![u32::try_from(rule_id).unwrap()]));

    let widened: model::Rule = api.ok(Method::PATCH, &format!("{base}/rules/{rule_id}"), Some(json!({ "direction": "both" }))).await;
    assert_eq!(serde_json::to_value(widened.direction).unwrap(), json!("both"));
    let now_allowed: model::AccessCheck = api.ok(Method::GET, &check(server.id, laptop.id), None).await;
    assert!(now_allowed.allowed);
    let (status, _) = api.call(Method::DELETE, &format!("{base}/rules/{rule_id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    api.fails(Method::PATCH, &format!("{base}/rules/{rule_id}"), Some(json!({})), StatusCode::NOT_FOUND).await;
    let gone: model::AccessCheck = api.ok(Method::GET, &check(laptop.id, server.id), None).await;
    assert!(!gone.allowed);
}

#[tokio::test]
async fn proxies_forwards_and_pairs_round_trip() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let base = format!("/networks/{}", network.id);
    let gateway = api.join(network.id, Declared::default()).await;
    // 端口转发的目标不用声明什么：管理员打开它的开关。
    let target = api.join(network.id, Declared::default()).await;
    let (_, raw) = api.call(Method::GET, &format!("{base}/nodes/{}", target.id), None).await;
    assert_eq!((raw["forward_target"].clone(), raw["declared"].get("forward")), (json!(false), None), "新节点的开关关着，声明里没有它");
    let switched: model::Node =
        api.ok(Method::PATCH, &format!("{base}/nodes/{}", target.id), Some(json!({ "forward_target": true }))).await;
    assert!(switched.forward_target);

    // 代理：经 exit 出去。不在回环上、不写名字和用户名密码时 controller 取名字、生成一对。
    let exit = api.join(network.id, CAN_DO_ALL).await;
    api.ok::<model::Node>(Method::PUT, &format!("{base}/nodes/{}/exit", exit.id), Some(json!({}))).await;
    let gateway_name = raw_name(&api, &base, gateway.id).await;
    let request = json!({ "node": gateway.id, "bind": "192.168.1.5:1080", "exit": exit.id, "allow_from": ["192.168.1.0/24"] });
    let (status, created) = api.call(Method::POST, &format!("{base}/proxies"), Some(request)).await;
    assert_eq!(status, StatusCode::CREATED);
    let proxy_id = created["id"].as_u64().unwrap();
    let (username, password) = (created["username"].as_str().unwrap().to_owned(), created["password"].as_str().unwrap().to_owned());
    assert!(username.starts_with("u-") && password.len() == 32, "{username} {password}");
    assert_eq!(
        created,
        json!({
            "id": proxy_id, "name": format!("{gateway_name}-1080"), "node": gateway.id, "bind": "192.168.1.5:1080", "protocol": "mixed",
            "exit": exit.id, "username": username, "password": password, "enabled": true, "allow_from": ["192.168.1.0/24"],
            "class": null, "optimistic": null, "lane": false, "status": { "code": "pending" }, "lane_effect": null, "lanes": [],
            "connections": 0, "bytes_up": 0, "bytes_down": 0
        }),
        "节点在线、还没有报；没写 lane 就是不走 ice3proxy"
    );
    let shown: Value = api.ok(Method::GET, &format!("{base}/proxies/{proxy_id}"), None).await;
    assert_eq!(shown["password"], json!(password), "密码查得回来");
    let local = json!({ "node": target.id, "name": "local", "bind": "127.0.0.1:1080", "exit": exit.id, "protocol": "http", "lane": true });
    let local: model::Proxy = api.ok(Method::POST, &format!("{base}/proxies"), Some(local)).await;
    assert_eq!((local.username.as_str(), local.password.as_str()), ("", ""), "回环上的可以不认证");
    // 选了 ice3proxy：两头的 netmap 里这一对是 always，代理的视图说它起不起作用（这两个节点都没有启用 relay，说的是最初那一版节点协议）。
    assert!(local.lane);
    let too_old = |node| model::LaneBlock::NodeTooOld { node };
    assert_eq!(local.lane_effect.map(|effect| effect.blocked), Some(vec![model::LaneBlock::NoRelay, too_old(target.id), too_old(exit.id)]));
    let lane_between = |a: NodeId, b| api.controller.netmap_of(a).unwrap().unwrap().peer(b).unwrap().lane;
    assert_eq!((lane_between(target.id, exit.id), lane_between(exit.id, target.id)), (LaneMode::Always, LaneMode::Always));
    assert_eq!(lane_between(gateway.id, exit.id), LaneMode::Off, "没选 ice3proxy 的代理那一对没有");
    let unchosen: model::Proxy = api.ok(Method::PATCH, &format!("{base}/proxies/{}", local.id), Some(json!({ "lane": false }))).await;
    assert_eq!((unchosen.lane, unchosen.lane_effect, lane_between(target.id, exit.id)), (false, None, LaneMode::Off));
    let all: Vec<model::Proxy> = api.ok(Method::GET, &format!("{base}/proxies"), None).await;
    assert_eq!(all.len(), 2);
    let on_gateway: Vec<model::Proxy> = api.ok(Method::GET, &format!("{base}/proxies?node={}", gateway.id), None).await;
    assert_eq!(on_gateway.iter().map(|proxy| u64::from(proxy.id)).collect::<Vec<_>>(), vec![proxy_id]);
    let netmap = api.controller.netmap_of(gateway.id).unwrap().unwrap();
    assert!(netmap.me.proxies[0].auth.is_some() && !serde_json::to_string(&netmap).unwrap().contains(&password));
    let exits: Vec<model::ExitView> = api.ok(Method::GET, &format!("{base}/exits"), None).await;
    let through = exits[0].proxies.iter().map(|proxy| u64::from(proxy.id)).collect::<Vec<_>>();
    assert_eq!(through, [proxy_id, u64::from(local.id)], "出口的视图列出经它出去的代理");

    // 出错时说是哪一项。
    let refusals = [
        (
            json!({ "node": gateway.id, "bind": "127.0.0.1:2000", "exit": exit.id, "username": "u" }),
            StatusCode::BAD_REQUEST,
            "credentials_incomplete",
            "password",
        ),
        (
            json!({ "node": gateway.id, "bind": "127.0.0.1:2000", "exit": exit.id, "password": "p" }),
            StatusCode::BAD_REQUEST,
            "credentials_incomplete",
            "username",
        ),
        (json!({ "node": gateway.id, "bind": "127.0.0.1:2000", "exit": gateway.id }), StatusCode::BAD_REQUEST, "exit_is_node", "exit"),
        (json!({ "node": gateway.id, "bind": "127.0.0.1:2000", "exit": target.id }), StatusCode::CONFLICT, "exit_not_enabled", "exit"),
        (json!({ "node": gateway.id, "bind": "192.168.1.5:1080", "exit": exit.id }), StatusCode::CONFLICT, "conflict", "bind"),
    ];
    for (request, status, code, field) in refusals {
        let (got, body) = api.call(Method::POST, &format!("{base}/proxies"), Some(request.clone())).await;
        assert_eq!((got, &body["error"]["code"], &body["error"]["field"]), (status, &json!(code), &json!(field)), "{request}");
    }
    let no_exit = api
        .fails(
            Method::POST,
            &format!("{base}/proxies"),
            Some(json!({ "node": gateway.id, "bind": "127.0.0.1:2000" })),
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert_eq!((no_exit.what.as_deref(), no_exit.field.as_deref()), (Some("data"), Some("exit")), "出口必填");

    // 只改写了的字段；只写 enabled 也行。
    let patched: model::Proxy =
        api.ok(Method::PATCH, &format!("{base}/proxies/{proxy_id}"), Some(json!({ "name": "lan", "bind": "192.168.1.5:1081" }))).await;
    assert_eq!((patched.name.as_str(), patched.bind.port(), patched.password.as_str()), ("lan", 1081, password.as_str()));
    let paused: Value = api.ok(Method::PATCH, &format!("{base}/proxies/{proxy_id}"), Some(json!({ "enabled": false }))).await;
    assert_eq!((paused["enabled"].clone(), paused["status"].clone()), (json!(false), json!({ "code": "disabled" })));
    assert!(api.controller.netmap_of(gateway.id).unwrap().unwrap().me.proxies.is_empty(), "停用的不下发");
    for gone in ["listeners", "credentials"] {
        let error = api.fails(Method::GET, &format!("{base}/{gone}"), None, StatusCode::NOT_FOUND).await;
        assert_eq!(error.what.as_deref(), Some("endpoint"), "{gone} 去掉了，不是别名");
    }

    let forward = json!({
        "name": "web", "protocol": "tcp", "listen_node": gateway.id, "bind": "127.0.0.1:8080",
        "target_node": target.id, "target_addr": "192.168.1.10:80", "allow_from": [], "enabled": true
    });
    let (status, created_forward) = api.call(Method::POST, &format!("{base}/forwards"), Some(forward.clone())).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created_forward["status"], json!("active"));
    let forward_id = created_forward["id"].as_u64().unwrap();
    let switched_off = json!({ "protocol": "udp", "listen_node": target.id, "bind": "127.0.0.1:5353", "target_node": gateway.id, "target_addr": "127.0.0.1:53" });
    let (status, refused) = api.call(Method::POST, &format!("{base}/forwards"), Some(switched_off)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        (refused["error"]["code"].clone(), refused["error"]["what"].clone(), refused["error"]["field"].clone()),
        (json!("forward_target_off"), json!(null), json!("target_node"))
    );
    let message = refused["error"]["message"].as_str().unwrap();
    assert!(message.contains("--forward-target on"), "{message}");
    // 关掉开关：转发留着、还是启用的，状态说明它不生效；再打开就回来。
    let target_path = format!("{base}/nodes/{}", target.id);
    api.ok::<model::Node>(Method::PATCH, &target_path, Some(json!({ "forward_target": false }))).await;
    let (_, listed) = api.call(Method::GET, &format!("{base}/forwards"), None).await;
    assert_eq!((listed[0]["enabled"].clone(), listed[0]["status"].clone()), (json!(true), json!("forward_target_off")));
    api.ok::<model::Node>(Method::PATCH, &target_path, Some(json!({ "forward_target": true }))).await;
    let (_, listed) = api.call(Method::GET, &format!("{base}/forwards"), None).await;
    assert_eq!(listed[0]["status"], json!("active"));
    let mut paused = forward.clone();
    paused["enabled"] = json!(false);
    let replaced: model::Forward = api.ok(Method::PUT, &format!("{base}/forwards/{forward_id}"), Some(paused)).await;
    assert_eq!(serde_json::to_value(replaced.status).unwrap(), json!("disabled"));
    api.controller.disconnect(target.session);
    api.ok::<model::Forward>(Method::PUT, &format!("{base}/forwards/{forward_id}"), Some(forward)).await;
    let listed: Vec<model::Forward> = api.ok(Method::GET, &format!("{base}/forwards"), None).await;
    assert_eq!(serde_json::to_value(listed[0].status).unwrap(), json!("target_offline"));

    let pair_path = format!("{base}/pairs/{}/{}", target.id, gateway.id);
    // 没有设置的一对也查得到：各项是默认值，`stored` 是 false。
    let (status, unset) = api.call(Method::GET, &pair_path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        unset,
        json!({ "a": gateway.id, "b": target.id, "keep_alive": false, "congestion": null, "stored": false }),
        "没有 ice3proxy 的东西了"
    );
    api.fails(Method::GET, &format!("{base}/pairs/{0}/{0}", gateway.id), None, StatusCode::BAD_REQUEST).await;
    let pair: model::PairSetting = api.ok(Method::PUT, &pair_path, Some(json!({ "keep_alive": true }))).await;
    assert_eq!((pair.a, pair.b, pair.keep_alive), (gateway.id, target.id, true), "编号小的在前");
    // 列表里是网络里的每一对：存着设置的只有刚写的那一对，别的是默认值。
    let (_, listed) = api.call(Method::GET, &format!("{base}/pairs"), None).await;
    let nodes: Vec<model::Node> = api.ok(Method::GET, &format!("{base}/nodes"), None).await;
    let listed = listed.as_array().unwrap();
    assert_eq!(listed.len(), nodes.len() * (nodes.len() - 1) / 2);
    let (stored, defaults): (Vec<&Value>, Vec<&Value>) = listed.iter().partition(|pair| pair["stored"] == json!(true));
    assert_eq!(stored, [&json!({ "a": pair.a, "b": pair.b, "keep_alive": true, "congestion": null, "stored": true })]);
    assert!(defaults.iter().all(|pair| pair["keep_alive"] == json!(false) && pair["congestion"].is_null()), "{defaults:?}");
    // 旧的客户端还写 ice3proxy 的设置：不报错，什么都不改。
    for old in [json!({ "lane": "always" }), json!({ "lane": "sometimes" })] {
        let view: Value = api.ok(Method::PUT, &pair_path, Some(old.clone())).await;
        assert_eq!(view, json!({ "a": gateway.id, "b": target.id, "keep_alive": true, "congestion": null, "stored": true }), "{old}");
    }
    assert_eq!(lane_between(gateway.id, target.id), LaneMode::Off);
    let bad = api.fails(Method::PUT, &pair_path, Some(json!({ "congestion": "reno" })), StatusCode::BAD_REQUEST).await;
    assert_eq!(bad.code, model::ErrorCode::InvalidRequest);
    let same = api
        .fails(Method::PUT, &format!("{base}/pairs/{0}/{0}", gateway.id), Some(json!({ "keep_alive": true })), StatusCode::BAD_REQUEST)
        .await;
    assert_eq!(same.code, model::ErrorCode::InvalidRequest);

    for path in [pair_path.clone(), format!("{base}/forwards/{forward_id}"), format!("{base}/proxies/{proxy_id}")] {
        let (status, body) = api.call(Method::DELETE, &path, None).await;
        assert_eq!((status, body), (StatusCode::NO_CONTENT, Value::Null), "{path}");
        api.fails(Method::DELETE, &path, None, StatusCode::NOT_FOUND).await;
    }
    let (_, back) = api.call(Method::GET, &pair_path, None).await;
    assert_eq!(back["stored"], json!(false), "去掉设置之后回到默认");
}

/// 节点现在的名字。
async fn raw_name(api: &Api, base: &str, node: NodeId) -> String {
    let (_, raw) = api.call(Method::GET, &format!("{base}/nodes/{node}"), None).await;
    raw["name"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn the_overview_counts_things_and_the_log_records_changes() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let base = format!("/networks/{}", network.id);
    let a = api.join(network.id, CAN_DO_ALL).await;
    let b = api.join(network.id, Declared::default()).await;
    api.ok::<model::Node>(Method::PUT, &format!("{base}/nodes/{}/relay", a.id), Some(json!({ "udp": ["203.0.113.7:20330"] }))).await;
    api.call(Method::POST, &format!("{base}/tokens"), Some(json!({}))).await;
    let report = Report { routes: vec![RouteEntry { peer: a.id, route: Route::None, rtt_ms: None }], ..Report::default() };
    api.controller.handle(b.session, REMOTE, ToController::Report(Box::new(report))).unwrap();

    let overview: model::Overview = api.ok(Method::GET, &format!("{base}/overview"), None).await;
    assert_eq!(
        (overview.nodes, overview.online, overview.relays, overview.exits, overview.rules, overview.pending_tokens),
        (2, 2, 1, 0, 1, 1)
    );
    assert_eq!(overview.online_nodes.iter().map(|node| node.id).collect::<Vec<_>>(), vec![a.id, b.id]);
    assert_eq!(overview.unreachable_pairs.iter().map(|pair| (pair.a.id, pair.b.id)).collect::<Vec<_>>(), vec![(a.id, b.id)]);
    api.fails(Method::GET, "/networks/99/overview", None, StatusCode::NOT_FOUND).await;

    let log: Vec<model::LogEntry> = api.ok(Method::GET, "/log", None).await;
    let actions: Vec<&str> = log.iter().map(|entry| entry.action.as_str()).collect();
    assert_eq!(actions[..2], ["token.create", "node.relay.enable"], "新的在前：{actions:?}");
    assert!(actions.contains(&"network.create") && actions.contains(&"node.enroll") && actions.contains(&"admin.token"));
    let limited: Vec<model::LogEntry> = api.ok(Method::GET, "/log?limit=2", None).await;
    assert_eq!(limited.len(), 2);
    assert!(limited[0].id > limited[1].id);
}

#[tokio::test]
async fn every_error_has_the_same_shape() {
    let api = Api::new();
    let network = api.network("home").await;

    let not_json =
        Request::builder().method(Method::POST).uri("/api/v1/networks").header(header::AUTHORIZATION, format!("Bearer {}", api.token));
    let (status, _, bytes) =
        api.send(not_json.header(header::CONTENT_TYPE, "application/json").body(Body::from("{ not json")).unwrap()).await;
    let body: model::ErrorBody = serde_json::from_slice(&bytes).unwrap();
    assert_eq!((status, body.error.code), (StatusCode::BAD_REQUEST, model::ErrorCode::InvalidRequest));

    let no_content_type =
        Request::builder().method(Method::POST).uri("/api/v1/networks").header(header::AUTHORIZATION, format!("Bearer {}", api.token));
    let (status, _, bytes) = api.send(no_content_type.body(Body::from(json!({ "name": "x" }).to_string())).unwrap()).await;
    let body: model::ErrorBody = serde_json::from_slice(&bytes).unwrap();
    assert_eq!((status, body.error.code), (StatusCode::BAD_REQUEST, model::ErrorCode::InvalidRequest));

    let wrong_type = api.fails(Method::POST, "/networks", Some(json!({ "name": 5 })), StatusCode::BAD_REQUEST).await;
    assert_eq!(wrong_type.code, model::ErrorCode::InvalidRequest);
    let missing_field =
        api.fails(Method::POST, &format!("/networks/{}/rules", network.id), Some(json!({ "src": "a" })), StatusCode::BAD_REQUEST).await;
    assert_eq!(missing_field.code, model::ErrorCode::InvalidRequest);
    let bad_id = api.fails(Method::GET, "/networks/home", None, StatusCode::BAD_REQUEST).await;
    assert_eq!(bad_id.code, model::ErrorCode::InvalidRequest);
    let zero_node = api.fails(Method::GET, &format!("/networks/{}/nodes/0", network.id), None, StatusCode::BAD_REQUEST).await;
    assert_eq!(zero_node.code, model::ErrorCode::InvalidRequest);
    let bad_query = api.fails(Method::GET, "/log?limit=many", None, StatusCode::BAD_REQUEST).await;
    assert_eq!(bad_query.code, model::ErrorCode::InvalidRequest);

    let unknown = api.fails(Method::GET, "/no-such-endpoint", None, StatusCode::NOT_FOUND).await;
    assert_eq!(unknown.code, model::ErrorCode::NotFound);
    let wrong_method = api.fails(Method::DELETE, "/networks", None, StatusCode::METHOD_NOT_ALLOWED).await;
    assert_eq!(wrong_method.code, model::ErrorCode::InvalidRequest);
    let missing = api.fails(Method::GET, &format!("/networks/{}/nodes/42", network.id), None, StatusCode::NOT_FOUND).await;
    assert_eq!(missing.code, model::ErrorCode::NotFound);
}

#[tokio::test]
async fn a_build_without_the_web_ui_explains_itself_instead_of_serving_404s() {
    let api = Api::new();
    let get = |path: &str| Request::builder().uri(path).body(Body::empty()).unwrap();
    for path in ["/", "/networks/1/nodes"] {
        let (status, headers, bytes) = api.send(get(path)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap().starts_with("text/html"));
        let page = String::from_utf8(bytes).unwrap();
        assert!(page.contains("没有带 WebUI") && page.contains("--static-dir"), "{page}");
    }
    // API 不受影响：照样要令牌，不存在的接口照样是统一格式的 404。
    let (status, _, _) = api.send(get("/api/v1/status")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let unknown = api.fails(Method::GET, "/no-such-endpoint", None, StatusCode::NOT_FOUND).await;
    assert_eq!(unknown.code, model::ErrorCode::NotFound);
}

#[tokio::test]
async fn the_embedded_web_ui_is_served_from_memory() {
    static ASSETS: &[Asset] = &[
        Asset { path: "index.html", bytes: b"<html>embedded</html>" },
        Asset { path: "assets/index-3f2a.js", bytes: b"console.log('ui')" },
        Asset { path: "favicon.svg", bytes: b"<svg/>" },
    ];
    let api = Api::with_webui(&WebUi::Embedded(ASSETS));
    let get = |path: &str| Request::builder().uri(path).body(Body::empty()).unwrap();
    let header_of = |headers: &axum::http::HeaderMap, name| headers.get(name).unwrap().to_str().unwrap().to_owned();

    let (status, headers, bytes) = api.send(get("/")).await;
    assert_eq!((status, bytes.as_slice()), (StatusCode::OK, b"<html>embedded</html>".as_slice()));
    assert!(header_of(&headers, header::CONTENT_TYPE).starts_with("text/html"));
    assert_eq!(header_of(&headers, header::CACHE_CONTROL), "no-cache", "index.html 每次都要问，这样换了版本马上看得到");

    let (status, headers, bytes) = api.send(get("/assets/index-3f2a.js")).await;
    assert_eq!((status, bytes.as_slice()), (StatusCode::OK, b"console.log('ui')".as_slice()));
    assert!(header_of(&headers, header::CONTENT_TYPE).starts_with("text/javascript"));
    assert!(header_of(&headers, header::CACHE_CONTROL).contains("immutable"), "名字里带哈希的文件可以一直缓存");
    let (_, headers, _) = api.send(get("/favicon.svg")).await;
    assert_eq!(header_of(&headers, header::CONTENT_TYPE), "image/svg+xml");

    // 前端自己的路由：不是文件的路径回 index.html。
    let (status, _, bytes) = api.send(get("/networks/1/nodes")).await;
    assert_eq!((status, bytes.as_slice()), (StatusCode::OK, b"<html>embedded</html>".as_slice()));
    let (status, _, _) = api.send(get("/api/v1/status")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "/api/v1 不会落到静态文件上");

    // 打进去的文件里没有 index.html，等于没有带。
    static BROKEN: &[Asset] = &[Asset { path: "assets/x.js", bytes: b"" }];
    let (status, _, bytes) = Api::with_webui(&WebUi::Embedded(BROKEN)).send(get("/")).await;
    assert!(status == StatusCode::OK && String::from_utf8(bytes).unwrap().contains("没有带 WebUI"));
}

#[tokio::test]
async fn metrics_need_no_token_and_name_no_node() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let _member = api.join(network.id, Declared::default()).await;
    let (status, headers, bytes) = api.send(Request::builder().uri("/metrics").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap().starts_with("text/plain; version=0.0.4"));
    let text = String::from_utf8(bytes).unwrap();
    for line in [
        "i3t_controller_nodes 1\n",
        "i3t_controller_nodes_online 1\n",
        "i3t_controller_networks 1\n",
        "# TYPE i3t_controller_snapshots_sent_total counter\n",
    ] {
        assert!(text.contains(line), "应该有 {line:?}：\n{text}");
    }
    assert!(text.contains("i3t_controller_snapshots_sent_total 1\n"), "{text}");
    assert!(!text.contains("node-1") && !text.contains("10.66."), "指标里不该有节点的名字和地址：\n{text}");
}

#[tokio::test]
async fn update_settings_checks_and_forced_updates_work_over_the_api() {
    let publisher = Publisher::new();
    let cache = tempfile::tempdir().unwrap();
    let mut api = Api::around(publisher.controller(Timing::default(), cache.path()), &WebUi::NotIncluded);
    let network = api.network("home").await;

    let overview: model::UpdateOverview = api.ok(Method::GET, "/update", None).await;
    assert!(overview.auto_update && !overview.source_is_default && overview.release.is_none() && overview.checked_at.is_none());
    assert_eq!(overview.source, publisher.source());
    let (_, raw) = api.call(Method::GET, "/update", None).await;
    for field in
        ["auto_update", "source", "source_is_default", "controller_version", "release", "checked_at", "check_error", "paused", "nodes"]
    {
        assert!(raw.get(field).is_some(), "应答里的字段总是全的，缺了 {field}：{raw}");
    }

    // 还没有发布：查不到是写在应答里的，不是请求失败。
    let checked: model::UpdateOverview = api.ok(Method::POST, "/update/check", Some(json!({}))).await;
    assert!(checked.release.is_none() && checked.check_error.is_some() && checked.checked_at.is_some());

    publisher.publish("0.2.0", &[("linux-x86_64", b"the new program")]);
    let checked: model::UpdateOverview = api.ok(Method::POST, "/update/check", Some(json!({}))).await;
    let release = checked.release.unwrap();
    assert_eq!((release.version.to_string().as_str(), release.packages.len(), checked.check_error), ("0.2.0", 1, None));
    assert_eq!(release.packages[0].state, model::PackageState::NotNeeded);
    let status: model::Status = api.ok(Method::GET, "/status", None).await;
    assert_eq!(status.newer_version.map(|version| version.to_string()), Some("0.2.0".to_owned()), "controller 自己也有新版本");

    let off: model::UpdateOverview = api.ok(Method::PATCH, "/update", Some(json!({ "auto_update": false }))).await;
    assert!(!off.auto_update && off.source == publisher.source(), "没写的字段不动");
    let bad = api.fails(Method::PATCH, "/update", Some(json!({ "source": "relative/dir" })), StatusCode::BAD_REQUEST).await;
    assert_eq!(bad.code, model::ErrorCode::InvalidRequest);

    // 节点的更新情况在节点列表、节点详情和单独的接口里都有。
    let member = api.join_as(network.id, &modern_hello("0.1.0", Declared::default())).await;
    let ancient = api.join(network.id, Declared::default()).await;
    let update_path = |node: NodeId| format!("/networks/{}/nodes/{node}/update", network.id);
    let nodes: Vec<model::Node> = api.ok(Method::GET, &format!("/networks/{}/nodes", network.id), None).await;
    assert!(nodes.iter().all(|node| node.update.available.as_ref().is_some_and(|version| version.to_string() == "0.2.0")));
    let update: model::NodeUpdate = api.ok(Method::GET, &update_path(member.id), None).await;
    assert_eq!((update.self_update, update.ordered, update.status), (Some(SelfUpdate::ABLE), None, UpdateStatus::Idle));
    let (_, raw) = api.call(Method::GET, &format!("/networks/{}/nodes/{}", network.id, member.id), None).await;
    assert_eq!(raw["update"]["self_update"], json!({ "able": true, "blocker": null }));
    assert_eq!(raw["update"]["status"], json!({ "state": "idle" }));
    assert_eq!(raw["hostname"], json!(""));

    // 强制更新：时机只能是 now 或 after_drain；不能自己更新的、不在线的各有各的错误码。
    let idle = api.fails(Method::POST, &update_path(member.id), Some(json!({ "timing": "idle" })), StatusCode::BAD_REQUEST).await;
    assert_eq!(idle.code, model::ErrorCode::InvalidRequest);
    let unable = api.fails(Method::POST, &update_path(ancient.id), Some(json!({ "timing": "now" })), StatusCode::CONFLICT).await;
    assert_eq!(unable.code, model::ErrorCode::CannotSelfUpdate);
    let forced: model::NodeUpdate = api.ok(Method::POST, &update_path(member.id), Some(json!({ "timing": "after_drain" }))).await;
    assert_eq!(forced.waiting, Some(model::UpdateWait::Package), "包还没有取回来：先排着");
    let controller = Arc::clone(&api.controller);
    tokio::task::spawn_blocking(move || controller.fetch_packages().unwrap()).await.unwrap();
    let update: model::NodeUpdate = api.ok(Method::GET, &update_path(member.id), None).await;
    assert_eq!(update.ordered.map(|order| order.timing), Some(UpdateTiming::AfterDrain));
    let all: model::ForcedUpdates = api.ok(Method::POST, "/update/force", Some(json!({ "timing": "now" }))).await;
    assert_eq!((all.ordered.len(), all.queued.len(), all.skipped.len()), (1, 0, 1));
    assert!(all.skipped[0].node.id == ancient.id && all.skipped[0].reason.contains("不能自己更新"));
    assert_eq!(all.skipped[0].cause, Some(model::SkipCause::TooOld), "原话旁边有原因的代码");

    // 节点说这个版本不能用：暂停出现在总览里，继续之后消失；没有暂停的版本继续不了。
    let failed = UpdateStatus::Failed {
        version: Some("0.2.0".parse().unwrap()),
        kind: FailureKind::VersionRejected,
        reason: "自检没有通过".into(),
        cause: Some(UpdateCause::SelfCheck { exit_code: Some(2), output: "读不了 config.toml".into() }),
    };
    api.controller
        .handle(member.session, REMOTE, ToController::Report(Box::new(Report { update: Some(failed), ..Report::default() })))
        .unwrap();
    let paused: model::UpdateOverview = api.ok(Method::GET, "/update", None).await;
    assert_eq!((paused.paused.len(), paused.nodes.failed, paused.nodes.manual), (1, 1, 1));
    let (_, raw) = api.call(Method::GET, "/update", None).await;
    assert_eq!(raw["paused"][0]["version"], json!("0.2.0"));
    assert_eq!(raw["paused"][0]["node"]["id"], json!(member.id.get()));
    assert_eq!(raw["paused"][0]["reason"], json!("自检没有通过"));
    assert_eq!(raw["paused"][0]["cause"], json!({ "code": "self_check", "exit_code": 2, "output": "读不了 config.toml" }));
    let resumed: model::UpdateOverview = api.ok(Method::POST, "/update/resume", Some(json!({ "version": "0.2.0" }))).await;
    assert!(resumed.paused.is_empty());
    let nothing = api.fails(Method::POST, "/update/resume", Some(json!({ "version": "0.2.0" })), StatusCode::NOT_FOUND).await;
    assert_eq!(nothing.code, model::ErrorCode::NotFound);

    api.controller.disconnect(member.session);
    let offline = api.fails(Method::POST, &update_path(member.id), Some(json!({ "timing": "now" })), StatusCode::CONFLICT).await;
    assert_eq!(offline.code, model::ErrorCode::NodeOffline);
    let current = api.join_as(network.id, &modern_hello("0.2.0", Declared::default())).await;
    let none = api.fails(Method::POST, &update_path(current.id), Some(json!({ "timing": "now" })), StatusCode::CONFLICT).await;
    assert_eq!((none.code, none.what.as_deref()), (model::ErrorCode::NoUpdate, Some("up_to_date")));

    let reset: model::UpdateOverview = api.ok(Method::PATCH, "/update", Some(json!({ "source": null }))).await;
    assert!(reset.source_is_default && reset.source.starts_with("https://github.com/"));
    let log: Vec<model::LogEntry> = api.ok(Method::GET, "/log", None).await;
    for action in ["update.settings", "update.release", "update.force", "update.force_all", "update.pause", "update.resume"] {
        assert!(log.iter().any(|entry| entry.action == action), "操作记录里应该有 {action}");
    }
    let pause = log.iter().find(|entry| entry.action == "update.pause").unwrap();
    assert_eq!((&pause.params["node"], &pause.params["version"]), (&json!(member.id.get()), &json!("0.2.0")));
    assert_eq!(pause.params["cause"]["code"], json!("self_check"));
    let force = log.iter().find(|entry| entry.action == "update.force").unwrap();
    assert_eq!(force.params["timing"], json!("after_drain"));
}

#[tokio::test]
async fn a_node_can_be_kept_off_automatic_updates_and_a_security_floor_is_shown_over_the_api() {
    let publisher = Publisher::new();
    let cache = tempfile::tempdir().unwrap();
    let mut api = Api::around(publisher.controller(Timing::default(), cache.path()), &WebUi::NotIncluded);
    let network = api.network("home").await;
    let old = api.join_as(network.id, &modern_hello("0.1.0", Declared::default())).await;
    let current = api.join_as(network.id, &modern_hello("0.2.0", Declared::default())).await;
    let node_path = |node: NodeId| format!("/networks/{}/nodes/{node}", network.id);

    let (_, raw) = api.call(Method::GET, &node_path(old.id), None).await;
    assert_eq!((raw["auto_update"].clone(), raw["update"]["security"].clone()), (json!(true), json!(false)), "新节点开着，还没有发布");

    publisher.publish_with_floor("0.2.0", Some("0.2.0"), &[("linux-x86_64", b"the fixed program")]);
    let _: model::UpdateOverview = api.ok(Method::POST, "/update/check", Some(json!({}))).await;
    let (_, overview) = api.call(Method::GET, "/update", None).await;
    assert_eq!(overview["release"]["security_floor"], json!("0.2.0"));
    let (_, nodes) = api.call(Method::GET, &format!("/networks/{}/nodes", network.id), None).await;
    let security: Vec<_> = nodes.as_array().unwrap().iter().map(|node| (node["id"].clone(), node["update"]["security"].clone())).collect();
    assert_eq!(security, [(json!(old.id.get()), json!(true)), (json!(current.id.get()), json!(false))]);
    let (_, update) = api.call(Method::GET, &format!("{}/update", node_path(old.id)), None).await;
    assert_eq!(update["security"], json!(true));

    let changed: model::Node = api.ok(Method::PATCH, &node_path(old.id), Some(json!({ "auto_update": false }))).await;
    assert!(!changed.auto_update && changed.update.security, "开关只管自动更新，安全更新照旧标着");
    let (_, raw) = api.call(Method::GET, &node_path(old.id), None).await;
    assert_eq!(raw["auto_update"], json!(false));
    let log: Vec<model::LogEntry> = api.ok(Method::GET, "/log", None).await;
    let entry = log.iter().find(|entry| entry.action == "node.update").unwrap();
    assert_eq!(entry.params["changes"], json!({ "auto_update": false }));
    assert!(entry.detail.contains("自动更新 关"), "{}", entry.detail);
    let untouched: model::Node = api.ok(Method::PATCH, &node_path(old.id), Some(json!({ "name": "nas" }))).await;
    assert!(!untouched.auto_update, "没写的开关不动");

    // 下一个发布不再写下限：谁都不标。
    publisher.publish("0.3.0", &[("linux-x86_64", b"a later program")]);
    let checked: model::UpdateOverview = api.ok(Method::POST, "/update/check", Some(json!({}))).await;
    assert_eq!(checked.release.unwrap().security_floor, None);
    let (_, overview) = api.call(Method::GET, "/update", None).await;
    assert_eq!(overview["release"]["security_floor"], json!(null), "字段总是在，没有下限时是 null");
    let update: model::NodeUpdate = api.ok(Method::GET, &format!("{}/update", node_path(old.id)), None).await;
    assert!(!update.security);
}

#[tokio::test]
async fn the_route_matrix_and_the_path_between_two_nodes_are_served() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let a = api.join(network.id, Declared::default()).await;
    let b = api.join(network.id, Declared::default()).await;
    let routes = vec![RouteEntry { peer: b.id, route: Route::Relay { relays: vec![b.id] }, rtt_ms: Some(25) }];
    api.controller
        .handle(a.session, REMOTE, ToController::Report(Box::new(Report { routes, routes_full: true, ..Report::default() })))
        .unwrap();

    let (_, raw) = api.call(Method::GET, &format!("/networks/{}/routes", network.id), None).await;
    assert_eq!(raw["nodes"][0], json!({ "id": a.id.get(), "name": "node-1", "virtual_ip": "10.66.0.1", "online": true }));
    let entry = &raw["entries"][0];
    assert_eq!(
        (&entry["from"], &entry["to"], &entry["rtt_ms"], &entry["stale"]),
        (&json!(a.id.get()), &json!(b.id.get()), &json!(25), &json!(false))
    );
    assert_eq!(entry["route"], json!({ "via": "relay", "relays": [b.id.get()] }));
    assert!(entry["age_secs"].as_u64().is_some_and(|age| age <= 2));
    let matrix: model::RouteMatrix = api.ok(Method::GET, &format!("/networks/{}/routes", network.id), None).await;
    assert_eq!((matrix.nodes.len(), matrix.entries.len()), (2, 1));

    // 这两个节点是最初那一版的，问不了，两个方向都退回到上报的数据。
    let path = format!("/networks/{}/path?from={}&to={}", network.id, a.id, b.id);
    let view: model::PathView = api.ok(Method::GET, &path, None).await;
    assert_eq!((view.forward.from.id, view.forward.to.id, view.forward.source), (a.id, b.id, model::PathSource::Report));
    assert_eq!((view.forward.rtt_ms, view.forward.route.clone()), (Some(25), Some(Route::Relay { relays: vec![b.id] })));
    assert_eq!((view.reverse.from.id, view.reverse.source, view.reverse.route.clone()), (b.id, model::PathSource::None, None));
    let (_, raw) = api.call(Method::GET, &path, None).await;
    assert_eq!(
        raw["reverse"],
        json!({
            "from": { "id": b.id.get(), "name": "node-2", "virtual_ip": "10.66.0.2" },
            "to": { "id": a.id.get(), "name": "node-1", "virtual_ip": "10.66.0.1" },
            "source": "none", "route": null, "rtt_ms": null, "age_secs": null, "since": null,
            "direct": null, "relay_leg": null, "mode": null, "reason": null, "cause": null, "candidates": null,
            "connection_rtt_ms": null, "switches": []
        })
    );

    let same =
        api.fails(Method::GET, &format!("/networks/{}/path?from={}&to={}", network.id, a.id, a.id), None, StatusCode::BAD_REQUEST).await;
    assert_eq!(same.code, model::ErrorCode::InvalidRequest);
    assert_eq!((same.what.as_deref(), same.field.as_deref()), (Some("same_node"), Some("to")));
    let missing = api.fails(Method::GET, &format!("/networks/{}/path?from={}&to=99", network.id, a.id), None, StatusCode::NOT_FOUND).await;
    assert_eq!((missing.code, missing.what.as_deref()), (model::ErrorCode::NotFound, Some("node")));
    let no_query = api.fails(Method::GET, &format!("/networks/{}/path", network.id), None, StatusCode::BAD_REQUEST).await;
    assert_eq!(no_query.code, model::ErrorCode::InvalidRequest);
    assert_eq!((no_query.what.as_deref(), no_query.field.as_deref()), (Some("query"), Some("from")));
    api.fails(Method::GET, "/networks/99/routes", None, StatusCode::NOT_FOUND).await;
}

#[tokio::test]
async fn vague_errors_say_what_was_wrong_and_which_field() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let bad_json =
        api.fails(Method::POST, "/networks", Some(json!({ "name": "lab", "routing": "fastest" })), StatusCode::BAD_REQUEST).await;
    assert_eq!((bad_json.what.as_deref(), bad_json.field.as_deref()), (Some("data"), Some("routing")));
    let no_name = api.fails(Method::POST, "/networks", Some(json!({})), StatusCode::BAD_REQUEST).await;
    assert_eq!((no_name.what.as_deref(), no_name.field.as_deref()), (Some("data"), Some("name")));
    let bad_name = api.fails(Method::POST, "/networks", Some(json!({ "name": "123" })), StatusCode::BAD_REQUEST).await;
    assert_eq!((bad_name.what.as_deref(), bad_name.field.as_deref()), (Some("all_digits"), Some("name")));
    let hops = json!({ "max_relay_hops": 9 });
    let hops = api.fails(Method::PATCH, &format!("/networks/{}", network.id), Some(hops), StatusCode::BAD_REQUEST).await;
    assert_eq!((hops.what.as_deref(), hops.field.as_deref()), (Some("out_of_range"), Some("max_relay_hops")));
    for (field, value) in
        [("ack_eliciting_threshold", 0), ("ack_eliciting_threshold", 101), ("max_ack_delay_ms", 0), ("max_ack_delay_ms", 26)]
    {
        let refused =
            api.fails(Method::PATCH, &format!("/networks/{}", network.id), Some(json!({ field: value })), StatusCode::BAD_REQUEST).await;
        assert_eq!((refused.what.as_deref(), refused.field.as_deref()), (Some("out_of_range"), Some(field)), "{field} = {value}");
    }
    let path = api.fails(Method::GET, "/networks/x/nodes", None, StatusCode::BAD_REQUEST).await;
    assert_eq!((path.what.as_deref(), path.field.as_deref()), (Some("path"), Some("network")));
    let endpoint = api.fails(Method::GET, "/nowhere", None, StatusCode::NOT_FOUND).await;
    assert_eq!(endpoint.what.as_deref(), Some("endpoint"));
    let rule = api.fails(Method::DELETE, &format!("/networks/{}/rules/99", network.id), None, StatusCode::NOT_FOUND).await;
    assert_eq!((rule.what.as_deref(), rule.field), (Some("rule"), None));

    let node = api.join(network.id, Declared::default()).await;
    let gw = api.join(network.id, CAN_DO_ALL).await;
    api.ok::<model::Node>(Method::PUT, &format!("/networks/{}/nodes/{}/exit", network.id, gw.id), Some(json!({}))).await;
    let proxy = json!({ "node": node.id.get(), "name": "a", "bind": "127.0.0.1:1080", "exit": gw.id });
    let _: model::Proxy = api.ok(Method::POST, &format!("/networks/{}/proxies", network.id), Some(proxy.clone())).await;
    let twin = json!({ "node": node.id.get(), "name": "b", "bind": "127.0.0.1:1080", "exit": gw.id });
    let clash = api.fails(Method::POST, &format!("/networks/{}/proxies", network.id), Some(twin), StatusCode::CONFLICT).await;
    assert_eq!((clash.code, clash.what.as_deref(), clash.field.as_deref()), (model::ErrorCode::Conflict, Some("proxy"), Some("bind")));
    let exit = json!({ "node": node.id.get(), "name": "c", "bind": "127.0.0.1:1081", "exit": 99 });
    let exit = api.fails(Method::POST, &format!("/networks/{}/proxies", network.id), Some(exit), StatusCode::NOT_FOUND).await;
    assert_eq!((exit.what.as_deref(), exit.field.as_deref()), (Some("node"), Some("exit")));
}

#[tokio::test]
async fn path_candidates_route_details_and_the_backbone_are_served() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let modern = modern_hello("0.2.0", Declared::default());
    let mut relay = api.join_as(network.id, &Hello { declared: CAN_DO_ALL, ..modern.clone() }).await;
    let mut a = api.join_as(network.id, &modern).await;
    let mut b = api.join_as(network.id, &modern).await;
    let settings = model::RelaySettings::default();
    api.controller.enable_relay(network.id, relay.id, settings).unwrap();
    let direct = Route::Direct { addr: "198.51.100.9:20330".parse().unwrap() };
    let report = Report {
        routes: vec![RouteEntry { peer: b.id, route: direct.clone(), rtt_ms: Some(12) }],
        route_kinds: vec![RouteKind { peer: b.id, direct: Some(DirectKind::Lan), relay_leg: None, direct_status: None, alternative: None }],
        routes_full: true,
        ..Report::default()
    };
    api.controller.handle(a.session, REMOTE, ToController::Report(Box::new(report))).unwrap();

    // 路由表和矩阵里有直连的类型。
    let (_, table) = api.call(Method::GET, &format!("/networks/{}/nodes/{}/routes", network.id, a.id), None).await;
    assert_eq!((&table["routes"][0]["direct"], &table["routes"][0]["relay_leg"]), (&json!("lan"), &json!(null)));
    let (_, matrix) = api.call(Method::GET, &format!("/networks/{}/routes", network.id), None).await;
    assert_eq!(matrix["entries"][0]["direct"], json!("lan"));

    // 路径：a 现答，带着候选路径；b 只答路，不带细节（像旧版本的节点那样）。
    let request = api.request(Method::GET, &format!("/networks/{}/path?from={}&to={}", network.id, a.id, b.id), None);
    let asking = tokio::spawn(api.router.clone().oneshot(request));
    let ToNode::RouteQuery { request: to_a, .. } = a.next_query().await else { panic!("a 应该被问到路由") };
    let ToNode::RouteQuery { request: to_b, .. } = b.next_query().await else { panic!("b 应该被问到路由") };
    let segment = PathSegment { from: a.id, to: b.id, rtt_us: 12_400, jitter_us: 300, loss_permille: 1 };
    let detail = PathDetail {
        mode: Some(RoutingMode::DirectFirst),
        direct: Some(DirectKind::Lan),
        relay_leg: None,
        reason: "直连可用".to_owned(),
        cause: Some(RouteCause::DirectVerified),
        candidates: vec![PathCandidate { route: direct.clone(), cost_us: 13_600, legs: vec![segment], load_percent: 0, current: true }],
    };
    let answer = RouteAnswer {
        peer: b.id,
        route: Some(direct.clone()),
        rtt_ms: Some(12),
        since: None,
        detail: Some(detail),
        connection_rtt_ms: None,
    };
    api.controller.handle(a.session, REMOTE, ToController::RouteAnswer { request: to_a, answer }).unwrap();
    let plain = RouteAnswer { peer: a.id, route: Some(Route::None), rtt_ms: None, since: None, detail: None, connection_rtt_ms: None };
    api.controller.handle(b.session, REMOTE, ToController::RouteAnswer { request: to_b, answer: plain }).unwrap();
    let response = asking.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let view: Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    let forward = &view["forward"];
    assert_eq!((&forward["mode"], &forward["direct"], &forward["reason"]), (&json!("direct_first"), &json!("lan"), &json!("直连可用")));
    assert_eq!(forward["cause"], json!({ "code": "direct_verified" }));
    assert_eq!(
        forward["candidates"],
        json!([{
            "route": { "via": "direct", "addr": "198.51.100.9:20330" }, "cost_us": 13_600, "load_percent": 0, "current": true,
            "legs": [{ "from": a.id.get(), "to": b.id.get(), "rtt_us": 12_400, "jitter_us": 300, "loss_permille": 1 }]
        }])
    );
    let reverse = &view["reverse"];
    assert_eq!(
        (&reverse["source"], &reverse["mode"], &reverse["candidates"]),
        (&json!("query"), &json!(null), &json!(null)),
        "不说细节的节点：不知道"
    );

    // 骨干矩阵：问在线的节点，relay 的那一行从挂靠它的节点来。
    let request = api.request(Method::GET, &format!("/networks/{}/backbone", network.id), None);
    let asking = tokio::spawn(api.router.clone().oneshot(request));
    let row = BackboneRow {
        relay: relay.id,
        state: RelayState::Draining,
        load_percent: 40,
        age_ms: 900,
        links: vec![BackboneLink { to: relay.id, rtt_ms: None, jitter_ms: 0, loss_permille: 1000 }],
    };
    for (member, rows) in [(&mut relay, Vec::new()), (&mut a, vec![row]), (&mut b, Vec::new())] {
        let ToNode::BackboneQuery { request } = member.next_query().await else { panic!("应该被问到骨干矩阵") };
        api.controller.handle(member.session, REMOTE, ToController::BackboneAnswer { request, rows }).unwrap();
    }
    let response = asking.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let view: Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(
        view["relays"],
        json!([{
            "relay": { "id": relay.id.get(), "name": "node-1", "virtual_ip": "10.66.0.1" }, "online": true, "state": "draining",
            "load_percent": 40, "age_ms": 900, "reported_by": a.id.get(),
            "links": [{ "to": relay.id.get(), "rtt_ms": null, "jitter_ms": 0, "loss_permille": 1000 }],
            "reach": { "reached": 0, "unreached": 0, "unknown": 2 }
        }])
    );
    assert_eq!(view["answered"].as_array().map(Vec::len), Some(3));
    api.fails(Method::GET, "/networks/99/backbone", None, StatusCode::NOT_FOUND).await;
}

#[tokio::test]
async fn a_new_node_is_named_after_its_hostname_in_the_api() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let member = api.join_as(network.id, &Hello { hostname: "Office-PC.corp.example".to_owned(), ..hello(Declared::default()) }).await;
    let node: model::NodeDetail = api.ok(Method::GET, &format!("/networks/{}/nodes/{}", network.id, member.id), None).await;
    assert_eq!(
        (node.node.name.as_str(), node.node.fqdn.as_str(), node.node.hostname.as_str()),
        ("office-pc", "office-pc.home.i3t", "Office-PC.corp.example")
    );
}

#[tokio::test]
async fn the_static_directory_is_served_at_the_root_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<html>ice3tier</html>").unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    std::fs::write(dir.path().join("assets/app.js"), "console.log('ui')").unwrap();
    let api = Api::with_webui(&WebUi::Dir(dir.path().to_owned()));
    let get = |path: &str| Request::builder().uri(path).body(Body::empty()).unwrap();

    let (status, headers, bytes) = api.send(get("/")).await;
    assert_eq!((status, bytes.as_slice()), (StatusCode::OK, b"<html>ice3tier</html>".as_slice()));
    assert!(headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap().starts_with("text/html"));
    let (status, _, bytes) = api.send(get("/assets/app.js")).await;
    assert_eq!((status, bytes.as_slice()), (StatusCode::OK, b"console.log('ui')".as_slice()));
    // 前端自己的路由：不是文件的路径回 index.html。
    let (status, _, bytes) = api.send(get("/networks/1/nodes")).await;
    assert_eq!((status, bytes.as_slice()), (StatusCode::OK, b"<html>ice3tier</html>".as_slice()));

    // 静态文件不需要令牌，API 照样需要。
    let (status, _, _) = api.send(get("/api/v1/status")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    api.ok::<model::Status>(Method::GET, "/status", None).await;
    let unknown = api.fails(Method::GET, "/no-such-endpoint", None, StatusCode::NOT_FOUND).await;
    assert_eq!(unknown.code, model::ErrorCode::NotFound, "/api/v1 下面不存在的路径不会落到静态文件上");
}

/// 一个假的节点 UDP 端口：回答地址查询；和同一个端口号上的 TCP 监听。
///
/// 系统挑 UDP 端口的时候不看 TCP：同一个端口号的 TCP 可能正被别的程序用着（同一台机器上并行跑的测试一直在开连接），
/// 那就另挑一个。
async fn answering_relay() -> std::net::SocketAddr {
    use i3t_proto::addr::{Query, Reply};
    let mut tries = 0;
    let (udp, tcp, addr) = loop {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        match tokio::net::TcpListener::bind(addr).await {
            Ok(tcp) => break (udp, tcp, addr),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse && tries < 16 => tries += 1,
            Err(error) => panic!("{addr} 上的 TCP 绑不上：{error}"),
        }
    };
    tokio::spawn(async move {
        let mut buf = [0; 64];
        while let Ok((len, from)) = udp.recv_from(&mut buf).await {
            if let Some(query) = Query::parse(&buf[..len]) {
                let _ = udp.send_to(&Reply { nonce: query.nonce, observed: from }.to_bytes(), from).await;
            }
        }
    });
    tokio::spawn(async move { while tcp.accept().await.is_ok() {} });
    addr
}

#[tokio::test]
async fn enabling_a_relay_answers_with_a_reachability_check_that_only_advises() {
    let api = Api::new();
    let network = api.network("home").await;
    let good = answering_relay().await;
    // relay 和 controller 在同一台机器上：controller 看到的是回环地址加上它自报的端口，那里有程序在回答；
    // 它报的网卡地址 127.0.0.2 上同一个端口没有程序在听。
    let created: model::CreatedEnrollToken = api.ok(Method::POST, &format!("/networks/{}/tokens", network.id), Some(json!({}))).await;
    let secret = created.token.parse::<EnrollToken>().unwrap().secret;
    let (outbox, _inbox) = mpsc::channel(64);
    let hello = Hello { port: good.port(), ..hello(CAN_DO_ALL) };
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let relay = api.controller.enroll(PublicKey::from_bytes([77; PublicKey::LEN]), &secret, &hello, loopback, outbox).unwrap();
    let local = Report { local_addresses: Some(vec!["127.0.0.2".parse().unwrap()].into()), ..Report::default() };
    api.controller.handle(relay, loopback, ToController::Report(Box::new(local))).unwrap();
    let closed = std::net::SocketAddr::new("127.0.0.2".parse().unwrap(), good.port());
    let path = format!("/networks/{}/nodes/{}/relay", network.id, relay.node);
    let enabled: model::RelayEnabled = api.ok(Method::PUT, &path, Some(json!({}))).await;
    assert!(enabled.node.relay.is_some(), "连不上的地址不挡着启用");
    let summary: Vec<(model::Transport, std::net::SocketAddr, bool)> =
        enabled.reachability.iter().map(|check| (check.protocol, check.addr, check.reachable)).collect();
    assert_eq!(
        summary,
        [
            (model::Transport::Udp, good, true),
            (model::Transport::Udp, closed, false),
            (model::Transport::Tcp, good, true),
            (model::Transport::Tcp, closed, false)
        ]
    );
    assert!(enabled.reachability[0].rtt_ms.is_some() && enabled.reachability[1].error.is_some());
    assert_eq!(enabled.reachability[0].cause, None);
    assert_eq!(enabled.reachability[1].cause, Some(model::ReachCause::Timeout), "UDP 的地址查询没有回答");
    // 127.0.0.2 在 Linux 和 Windows 上是本机的回环地址，端口上没有程序在听，连接被拒绝（Windows 上要两秒左右才报出来）。
    // macOS 的回环网卡上只有 127.0.0.1，发往 127.0.0.2 的连接没有回音，等到超时。
    let closed_tcp = if cfg!(target_os = "macos") { model::ReachCause::Timeout } else { model::ReachCause::Refused };
    assert_eq!(enabled.reachability[3].cause, Some(closed_tcp), "TCP 端口上没有程序在听");
}

#[tokio::test]
async fn a_proxy_shows_what_its_node_reports_and_why_it_cannot_work_although_it_listens() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let base = format!("/networks/{}", network.id);
    let gateway = api.join(network.id, Declared::default()).await;
    let exit = api.join(network.id, CAN_DO_ALL).await;
    api.ok::<model::Node>(Method::PUT, &format!("{base}/nodes/{}/exit", exit.id), Some(json!({}))).await;
    let request = json!({ "node": gateway.id, "bind": "0.0.0.0:3128", "exit": exit.id, "protocol": "http" });
    let created: model::Proxy = api.ok(Method::POST, &format!("{base}/proxies"), Some(request)).await;
    let path = format!("{base}/proxies/{}", created.id);

    let local = "0.0.0.0:3128".parse().unwrap();
    let traffic = ListenTraffic { connections: 2, bytes_up: 10, bytes_down: 20 };
    let state = |state| Report { run: 5, proxies: vec![ProxyReport { id: created.id, bind: local, state, traffic }], ..Report::default() };
    api.controller.handle(gateway.session, REMOTE, ToController::Report(Box::new(state(ListenState::Listening { local })))).unwrap();
    let shown: Value = api.ok(Method::GET, &path, None).await;
    assert_eq!(
        (shown["status"].clone(), shown["connections"].clone(), shown["bytes_down"].clone()),
        (json!({ "code": "listening", "local": "0.0.0.0:3128" }), json!(2), json!(20))
    );
    let in_use = ListenState::PortInUse { detail: "Address already in use".into(), cause: Some(BindCause::AddressInUse) };
    api.controller.handle(gateway.session, REMOTE, ToController::Report(Box::new(state(in_use)))).unwrap();
    let shown: Value = api.ok(Method::GET, &path, None).await;
    assert_eq!(
        shown["status"],
        json!({ "code": "port_in_use", "detail": "Address already in use", "cause": { "code": "address_in_use" } })
    );

    // 在监听，出口却用不了：出口离线、出口停用、规则不让访问出口。
    api.controller.handle(gateway.session, REMOTE, ToController::Report(Box::new(state(ListenState::Listening { local })))).unwrap();
    api.controller.disconnect(exit.session);
    let shown: Value = api.ok(Method::GET, &path, None).await;
    assert_eq!(shown["status"], json!({ "code": "exit_offline", "local": "0.0.0.0:3128" }));
    api.ok::<model::Node>(Method::DELETE, &format!("{base}/nodes/{}/exit", exit.id), None).await;
    let shown: Value = api.ok(Method::GET, &path, None).await;
    assert_eq!(shown["status"]["code"], json!("exit_disabled"), "出口停用之后代理留着、照样下发");
    assert_eq!(api.controller.netmap_of(gateway.id).unwrap().unwrap().me.proxies.len(), 1);
    let renamed: Value = api.ok(Method::PATCH, &path, Some(json!({ "name": "lan" }))).await;
    assert_eq!(renamed["name"], json!("lan"), "只改名字不因为出口停用了而被拦住");
    api.ok::<Value>(Method::PATCH, &path, Some(json!({ "enabled": false }))).await;
    let refused = api.fails(Method::PATCH, &path, Some(json!({ "enabled": true })), StatusCode::CONFLICT).await;
    assert_eq!((refused.code, refused.field.as_deref()), (model::ErrorCode::ExitNotEnabled, Some("exit")), "再启用要出口是启用着的");

    // 出口回来了，规则却不让访问它：启用不了；启用着的代理状态说明为什么。
    api.ok::<model::Node>(Method::PUT, &format!("{base}/nodes/{}/exit", exit.id), Some(json!({}))).await;
    api.ok::<Value>(Method::PATCH, &path, Some(json!({ "enabled": true }))).await;
    let rules: Vec<model::Rule> = api.ok(Method::GET, &format!("{base}/rules"), None).await;
    api.call(Method::DELETE, &format!("{base}/rules/{}", rules[0].id), None).await;
    let shown: Value = api.ok(Method::GET, &path, None).await;
    assert_eq!(shown["status"], json!({ "code": "access_denied", "local": "0.0.0.0:3128" }));
    let check: Value = api.ok(Method::GET, &format!("{base}/access/check?from={}&to={}", gateway.id, exit.id), None).await;
    assert_eq!(check["allowed"], json!(false), "界面保存之前可以先问规则");
    api.ok::<Value>(Method::PATCH, &path, Some(json!({ "enabled": false }))).await;
    let refused = api.fails(Method::PATCH, &path, Some(json!({ "enabled": true })), StatusCode::CONFLICT).await;
    assert_eq!((refused.code, refused.field.as_deref()), (model::ErrorCode::AccessDenied, Some("exit")));
}

#[tokio::test]
async fn tokens_can_be_listed_with_the_used_and_expired_ones_and_carry_a_prefix() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let path = format!("/networks/{}/tokens", network.id);
    let pending: model::CreatedEnrollToken = api.ok(Method::POST, &path, Some(json!({}))).await;
    assert!(pending.token.starts_with(&pending.info.prefix));
    let member = api.join(network.id, Declared::default()).await;

    let only_pending: Vec<model::EnrollTokenInfo> = api.ok(Method::GET, &path, None).await;
    assert_eq!(only_pending.iter().map(|token| token.id).collect::<Vec<_>>(), [pending.info.id]);
    let all: Vec<model::EnrollTokenInfo> = api.ok(Method::GET, &format!("{path}?all=true"), None).await;
    assert_eq!(all.len(), 2);
    let used = all.iter().find(|token| token.id != pending.info.id).unwrap();
    assert_eq!((used.state, used.used_by.as_ref().map(|node| node.id)), (model::TokenState::Used, Some(member.id)));
}

#[tokio::test]
async fn the_log_pages_filters_and_names_what_each_entry_is_about() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let a = api.join(network.id, Declared::default()).await;
    let b = api.join(network.id, Declared::default()).await;
    api.ok::<model::Node>(Method::PATCH, &format!("/networks/{}/nodes/{}", network.id, a.id), Some(json!({ "name": "renamed" }))).await;

    let about_a: Vec<model::LogEntry> = api.ok(Method::GET, &format!("/log?ref=node:{}", a.id), None).await;
    assert_eq!(about_a.iter().map(|entry| entry.action.as_str()).collect::<Vec<_>>(), ["node.update", "node.enroll"]);
    assert!(about_a.iter().all(|entry| entry.refs.contains(&model::LogRef::node(a.id))));
    let nodes_only: Vec<model::LogEntry> = api.ok(Method::GET, "/log?action=node", None).await;
    assert!(nodes_only.iter().all(|entry| entry.action.starts_with("node.")));
    assert_eq!(nodes_only.len(), 3);
    let first_page: Vec<model::LogEntry> = api.ok(Method::GET, &format!("/log?limit=2&network={}", network.id), None).await;
    let next_page: Vec<model::LogEntry> =
        api.ok(Method::GET, &format!("/log?limit=2&network={}&before={}", network.id, first_page[1].id), None).await;
    assert!(next_page.iter().all(|entry| entry.id < first_page[1].id));
    assert!(next_page.iter().all(|entry| entry.network == Some(network.id)));
    let bad = api.fails(Method::GET, "/log?ref=planet:1", None, StatusCode::BAD_REQUEST).await;
    assert!(bad.message.contains("ref"), "{}", bad.message);
    let _ = b;
}

#[tokio::test]
async fn status_overview_node_list_routes_and_groups_carry_what_the_web_ui_asked_for() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let base = format!("/networks/{}", network.id);
    let relay = api.join(network.id, CAN_DO_ALL).await;
    let member = api.join(network.id, Declared::default()).await;

    let status: Value = api.ok(Method::GET, "/status", None).await;
    assert!(status.get("data_dir").is_some_and(Value::is_null), "内存里的 controller 没有数据目录：{status}");

    let attached = vec![i3t_model::netmap::Attachment { relay: relay.id, rtt_ms: 9, shared: false }];
    let routes = vec![RouteEntry { peer: relay.id, route: Route::Relay { relays: vec![relay.id] }, rtt_ms: Some(9) }];
    let report =
        Report { flows: 4, tx_bytes: 10, rx_bytes: 20, attached: attached.clone(), routes, routes_full: true, ..Report::default() };
    api.controller.handle(member.session, REMOTE, ToController::Report(Box::new(report))).unwrap();

    let nodes: Vec<model::Node> = api.ok(Method::GET, &format!("{base}/nodes"), None).await;
    assert_eq!(nodes.iter().find(|node| node.id == member.id).unwrap().attached, attached);
    let overview: model::Overview = api.ok(Method::GET, &format!("{base}/overview"), None).await;
    assert_eq!((overview.flows, overview.tx_bytes, overview.rx_bytes), (4, 10, 20));
    let table: model::RouteTable = api.ok(Method::GET, &format!("{base}/nodes/{}/routes", member.id), None).await;
    assert!(table.routes[0].age_secs <= 1 && table.routes[0].since_secs <= 1);

    let laptops = api.group(network.id, "laptops").await;
    api.ok::<model::Node>(Method::PATCH, &format!("{base}/nodes/{}", member.id), Some(json!({ "groups": [laptops] }))).await;
    api.ok::<model::Group>(Method::PATCH, &format!("{base}/groups/{laptops}"), Some(json!({ "name": "phones" }))).await;
    let node: model::NodeDetail = api.ok(Method::GET, &format!("{base}/nodes/{}", member.id), None).await;
    assert_eq!(serde_json::to_value(&node.node.groups).unwrap(), json!([{ "id": laptops, "name": "phones", "builtin": false }]));
    let (_, raw) = api.call(Method::GET, &format!("{base}/nodes/{}", member.id), None).await;
    assert!(raw.get("tags").is_none(), "标签没有了，也没有别名：{raw}");
    let gone =
        api.fails(Method::POST, &format!("{base}/tags/rename"), Some(json!({ "from": "a", "to": "b" })), StatusCode::NOT_FOUND).await;
    assert_eq!(gone.what.as_deref(), Some("endpoint"));

    let class: model::Network = api.ok(Method::PATCH, &base, Some(json!({ "class": "interactive" }))).await;
    assert_eq!(class.class, Some(i3t_proto::flow::Class::Interactive));
}

#[tokio::test]
async fn exits_and_listen_status_are_served_from_what_the_nodes_report() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let base = format!("/networks/{}", network.id);
    let exit = api.join(network.id, CAN_DO_ALL).await;
    let laptop = api.join(network.id, Declared::default()).await;
    api.ok::<model::Node>(Method::PUT, &format!("{base}/nodes/{}/exit", exit.id), Some(json!({ "quota_bytes": 5000, "family": "ipv4" })))
        .await;
    api.ok::<model::Node>(Method::PATCH, &format!("{base}/nodes/{}", exit.id), Some(json!({ "forward_target": true }))).await;
    let forward = json!({ "protocol": "tcp", "listen_node": laptop.id, "bind": "127.0.0.1:0", "target_node": exit.id, "target_addr": "127.0.0.1:22" });
    let created: model::Forward = api.ok(Method::POST, &format!("{base}/forwards"), Some(forward)).await;
    assert_eq!(created.bind.port(), 0, "端口写 0 由节点挑");

    let exit_report = i3t_model::control::ExitReport { total: 3, refused: 1, ..Default::default() };
    api.controller
        .handle(
            exit.session,
            REMOTE,
            ToController::Report(Box::new(Report { run: 1, exit: Some(Box::new(exit_report)), ..Report::default() })),
        )
        .unwrap();
    let forwards = vec![i3t_model::control::ForwardReport {
        id: created.id,
        bind: "127.0.0.1:0".parse().unwrap(),
        protocol: i3t_model::netmap::ForwardProtocol::Tcp,
        state: i3t_model::control::ListenState::Listening { local: "127.0.0.1:43210".parse().unwrap() },
        traffic: i3t_model::control::ListenTraffic::default(),
        target_failure: Some(i3t_model::control::TargetFailureReport { cause: i3t_model::control::TargetCause::Refused, secs_ago: 0 }),
    }];
    api.controller
        .handle(laptop.session, REMOTE, ToController::Report(Box::new(Report { run: 2, forwards, ..Report::default() })))
        .unwrap();

    let exits: Vec<model::ExitView> = api.ok(Method::GET, &format!("{base}/exits"), None).await;
    assert_eq!(exits.len(), 1);
    assert_eq!((exits[0].settings.quota_bytes, exits[0].usage.as_ref().map(|usage| usage.total)), (Some(5000), Some(3)));
    let one: model::ExitView = api.ok(Method::GET, &format!("{base}/exits/{}", exit.id), None).await;
    assert_eq!(one.node.id, exit.id);
    api.fails(Method::GET, &format!("{base}/exits/{}", laptop.id), None, StatusCode::NOT_FOUND).await;

    let listed: Value = api.ok(Method::GET, &format!("{base}/forwards"), None).await;
    assert_eq!(listed[0]["listen"]["state"], json!("listening"));
    assert_eq!(listed[0]["listen"]["local"], json!("127.0.0.1:43210"));
    assert_eq!(listed[0]["target_failure"]["cause"], json!({ "code": "refused" }));
    assert!(listed[0]["target_failure"]["at"].as_u64().is_some_and(|at| at > 1_700_000_000), "{}", listed[0]["target_failure"]);
    let on_node: model::NodeListeners = api.ok(Method::GET, &format!("{base}/nodes/{}/listeners", laptop.id), None).await;
    assert_eq!(on_node.forwards.len(), 1);
    assert_eq!(on_node.forwards[0].id, created.id);
}

/// 等 controller 发来的下一个测试指令，跳过别的消息。
async fn next_order(member: &mut Member) -> i3t_model::control::TestOrder {
    loop {
        let message = tokio::time::timeout(common::PATIENCE, member.inbox.recv()).await.unwrap().unwrap();
        if let ToNode::Test(order) = message {
            return *order;
        }
    }
}

#[tokio::test]
async fn an_active_test_is_started_followed_listed_and_cancelled_over_the_api() {
    use i3t_model::admin::diag::{MatrixRun, TestView};
    use i3t_model::control::TestReport;
    use i3t_model::control::diag::{DirectSide, TestRole};

    let mut api = Api::new();
    let network = api.network("home").await.id;
    let modern = Hello { throughput_tests: true, ..modern_hello("0.2.0", Declared::default()) };
    let mut a = api.join_as(network, &modern).await;
    let mut b = api.join_as(network, &modern).await;
    let mut old = api.join(network, Declared::default()).await;
    let tests = format!("/networks/{network}/tests");

    let (status, started) = api.call(Method::POST, &tests, Some(json!({ "a": a.id, "b": b.id, "items": ["direct"] }))).await;
    assert_eq!(status, StatusCode::CREATED, "{started}");
    assert_eq!((started["state"].as_str(), started["direct"]["state"].as_str()), (Some("running"), Some("pending")));
    assert_eq!(started["direct_quality"], Value::Null, "没有要的项是 null");
    let id = started["id"].as_u64().unwrap();
    let (order_a, order_b) = (next_order(&mut a).await, next_order(&mut b).await);
    assert_eq!((order_a.test, order_a.role, order_b.role), (id, TestRole::Initiator, TestRole::Responder));

    let busy = api.fails(Method::POST, &tests, Some(json!({ "a": b.id, "b": a.id })), StatusCode::CONFLICT).await;
    assert_eq!(busy.code, model::ErrorCode::Busy);
    let side = DirectSide { ok: true, kind: Some(DirectKind::Reachable), elapsed_ms: Some(30), ..DirectSide::default() };
    let report = |role, last| TestReport { test: id, role: Some(role), last, direct: Some(side.clone()), ..TestReport::default() };
    api.controller.handle(a.session, REMOTE, ToController::TestReport(Box::new(report(TestRole::Initiator, true)))).unwrap();
    api.controller.handle(b.session, REMOTE, ToController::TestReport(Box::new(report(TestRole::Responder, true)))).unwrap();
    let done: TestView = api.ok(Method::GET, &format!("{tests}/{id}"), None).await;
    let direct = done.direct.unwrap();
    assert_eq!((serde_json::to_value(done.state).unwrap(), direct.ok, direct.elapsed_ms), (json!("done"), true, Some(30)));
    let (_, raw) = api.call(Method::GET, &format!("{tests}/{id}"), None).await;
    assert_eq!(raw["direct"]["kind"], "reachable");
    assert_eq!(raw["direct"]["sides"][1]["node"], json!(b.id), "两端各自看到的，节点编号和那一端的字段在同一层");

    let soon = api.fails(Method::POST, &tests, Some(json!({ "a": a.id, "b": b.id })), StatusCode::CONFLICT).await;
    assert_eq!(soon.code, model::ErrorCode::TooSoon);
    let finished = api.fails(Method::POST, &format!("{tests}/{id}/cancel"), None, StatusCode::CONFLICT).await;
    assert_eq!(finished.code, model::ErrorCode::Busy);
    let listed: Vec<TestView> = api.ok(Method::GET, &format!("{tests}?a={}&b={}", b.id, a.id), None).await;
    assert_eq!(listed.iter().map(|view| view.id).collect::<Vec<_>>(), [id]);
    api.fails(Method::GET, &format!("{tests}?a={}", a.id), None, StatusCode::BAD_REQUEST).await;
    api.fails(Method::GET, &format!("{tests}/999"), None, StatusCode::NOT_FOUND).await;
    let invalid = api.fails(Method::POST, &tests, Some(json!({ "a": a.id, "b": a.id })), StatusCode::BAD_REQUEST).await;
    assert_eq!(invalid.code, model::ErrorCode::InvalidRequest);

    // 版本太旧的节点：测试建起来、立刻失败，并且说是哪个节点。
    let (status, refused) = api.call(Method::POST, &tests, Some(json!({ "a": a.id, "b": old.id }))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!((refused["state"].as_str(), refused["error"]["code"].as_str()), (Some("failed"), Some("not_supported")));
    assert_eq!(refused["error"]["node"], json!(old.id));
    assert!(old.inbox.try_recv().is_err() || !matches!(old.inbox.try_recv(), Ok(ToNode::Test(_))));

    // 全网矩阵：开始、看、取消。`tests/matrix` 不会被当成编号。
    let matrix_path = format!("{tests}/matrix");
    api.fails(Method::GET, &matrix_path, None, StatusCode::NOT_FOUND).await;
    let (status, run) = api.call(Method::POST, &matrix_path, None).await;
    assert_eq!(status, StatusCode::CREATED, "{run}");
    let run: MatrixRun = serde_json::from_value(run).unwrap();
    assert_eq!((run.total, run.nodes.len()), (3, 3));
    let shown: MatrixRun = api.ok(Method::GET, &matrix_path, None).await;
    assert_eq!(shown.id, run.id);
    let cancelled: MatrixRun = api.ok(Method::POST, &format!("{matrix_path}/cancel"), None).await;
    assert_eq!(serde_json::to_value(cancelled.state).unwrap(), json!("cancelled"));
    let log: Vec<model::LogEntry> = api.ok(Method::GET, &format!("/log?network={network}&action=test"), None).await;
    let actions: Vec<&str> = log.iter().map(|entry| entry.action.as_str()).collect();
    assert!(actions.contains(&"test.start") && actions.contains(&"test.matrix") && actions.contains(&"test.matrix.cancel"), "{actions:?}");
}

#[tokio::test]
async fn groups_are_listed_created_read_renamed_changed_and_deleted_through_the_router() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let base = format!("/networks/{}/groups", network.id);
    let a = api.join(network.id, Declared::default()).await;
    let b = api.join(network.id, Declared::default()).await;

    let listed: Vec<model::Group> = api.ok(Method::GET, &base, None).await;
    assert_eq!(listed.len(), 1);
    let all = listed[0].id;
    let (_, raw) = api.call(Method::GET, &base, None).await;
    assert_eq!(raw[0]["name"], "All");
    assert_eq!((raw[0]["builtin"].clone(), raw[0]["nodes"].as_array().unwrap().len()), (json!(true), 2));
    assert_eq!(raw[0]["rules"][0]["name"], "default");

    let (status, created) = api.call(Method::POST, &base, Some(json!({ "name": "Servers" }))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created, json!({ "id": created["id"], "name": "Servers", "builtin": false, "nodes": [], "rules": [] }));
    let servers: model::GroupId = serde_json::from_value(created["id"].clone()).unwrap();
    let path = format!("{base}/{servers}");

    let taken = api.fails(Method::POST, &base, Some(json!({ "name": "servers" })), StatusCode::CONFLICT).await;
    assert_eq!((taken.code, taken.what.as_deref(), taken.field.as_deref()), (model::ErrorCode::NameTaken, Some("group"), Some("name")));
    let bad = api.fails(Method::POST, &base, Some(json!({ "name": "a/b" })), StatusCode::BAD_REQUEST).await;
    assert_eq!((bad.what.as_deref(), bad.field.as_deref()), (Some("malformed"), Some("name")));
    let long = api.fails(Method::POST, &base, Some(json!({ "name": "x".repeat(33) })), StatusCode::BAD_REQUEST).await;
    assert_eq!(long.what.as_deref(), Some("too_long"));

    // 一个一个地加入、移出，和批量的。
    let one: model::Group = api.ok(Method::PUT, &format!("{path}/nodes/{}", a.id), Some(json!({}))).await;
    assert_eq!(one.nodes.iter().map(|node| node.id).collect::<Vec<_>>(), vec![a.id]);
    let batch: model::Group = api.ok(Method::PATCH, &format!("{path}/nodes"), Some(json!({ "add": [b.id], "remove": [a.id] }))).await;
    assert_eq!(batch.nodes.iter().map(|node| node.id).collect::<Vec<_>>(), vec![b.id]);
    let unknown = api.fails(Method::PATCH, &format!("{path}/nodes"), Some(json!({ "add": [a.id, 99] })), StatusCode::NOT_FOUND).await;
    assert_eq!((unknown.what.as_deref(), unknown.field.as_deref()), (Some("node"), Some("add[1]")));
    let removed: model::Group = api.ok(Method::DELETE, &format!("{path}/nodes/{}", b.id), None).await;
    assert!(removed.nodes.is_empty());
    let again: model::Group = api.ok(Method::PUT, &format!("{path}/nodes/{}", b.id), Some(json!({}))).await;
    assert_eq!(again.nodes.len(), 1);
    api.fails(Method::PUT, &format!("{path}/nodes/99"), Some(json!({})), StatusCode::NOT_FOUND).await;

    let builtin = api.fails(Method::PUT, &format!("{base}/{all}/nodes/{}", a.id), Some(json!({})), StatusCode::BAD_REQUEST).await;
    assert_eq!((builtin.what.as_deref(), builtin.field.as_deref()), (Some("builtin"), Some("group")));
    api.fails(Method::PATCH, &format!("{base}/{all}"), Some(json!({ "name": "Everyone" })), StatusCode::BAD_REQUEST).await;
    api.fails(Method::DELETE, &format!("{base}/{all}"), None, StatusCode::BAD_REQUEST).await;

    let rule: model::Rule =
        api.ok(Method::POST, &format!("/networks/{}/rules", network.id), Some(json!({ "src": all, "dst": servers, "name": "ssh" }))).await;
    let renamed: model::Group = api.ok(Method::PATCH, &path, Some(json!({ "name": "boxes" }))).await;
    assert_eq!((renamed.name.as_str(), renamed.rules.len()), ("boxes", 1));
    assert_eq!(renamed.rules[0].dst.name, "boxes", "规则里看到的是新名字");
    let read: model::Group = api.ok(Method::GET, &path, None).await;
    assert_eq!(read, renamed);

    let (status, deleted) = api.call(Method::DELETE, &path, None).await;
    assert_eq!(status, StatusCode::OK, "删除的应答说删掉了什么");
    assert_eq!(deleted["id"], json!(servers));
    assert_eq!(deleted["name"], "boxes");
    assert_eq!(deleted["nodes"][0]["id"], json!(b.id));
    assert_eq!(deleted["rules"][0]["id"], json!(rule.id));
    assert_eq!(deleted["tokens"], json!([]));
    let missing = api.fails(Method::GET, &path, None, StatusCode::NOT_FOUND).await;
    assert_eq!((missing.what.as_deref(), missing.field), (Some("group"), None));
    assert!(missing.message.contains(&format!("#{servers}")), "{}", missing.message);
    let rules: Vec<model::Rule> = api.ok(Method::GET, &format!("/networks/{}/rules", network.id), None).await;
    assert_eq!(rules.len(), 1, "用到它的规则一起删掉了");

    let other = api.network("lab").await;
    api.fails(Method::GET, &format!("/networks/{}/groups/{all}", other.id), None, StatusCode::NOT_FOUND).await;
    let path_error = api.fails(Method::GET, &format!("{base}/x"), None, StatusCode::BAD_REQUEST).await;
    assert_eq!(path_error.field.as_deref(), Some("group"));
    let actions: Vec<model::LogEntry> = api.ok(Method::GET, "/log?action=group", None).await;
    let actions: Vec<&str> = actions.iter().rev().map(|entry| entry.action.as_str()).collect();
    assert_eq!(
        actions,
        ["group.create", "group.members", "group.members", "group.members", "group.members", "group.rename", "group.delete"]
    );
    let by_ref: Vec<model::LogEntry> = api.ok(Method::GET, &format!("/log?ref=group:{servers}"), None).await;
    assert_eq!(by_ref.len(), 7);
}

#[tokio::test]
async fn an_exit_is_asked_to_test_a_target_and_its_answer_is_passed_on() {
    use i3t_model::control::exit_test::{ConnectStep, ExitTestCause, ExitTestResult, ExitVia};

    let mut api = Api::new();
    let network = api.network("home").await;
    let base = format!("/networks/{}", network.id);
    let mut exit = api.join_as(network.id, &modern_hello("0.2.0", CAN_DO_ALL)).await;
    let laptop = api.join(network.id, Declared::default()).await;
    let old = api.join(network.id, CAN_DO_ALL).await;
    for node in [exit.id, old.id] {
        api.ok::<model::Node>(Method::PUT, &format!("{base}/nodes/{node}/exit"), Some(json!({}))).await;
    }
    let unanswered: Value = api.ok(Method::POST, &format!("{base}/exits/{}/test", old.id), Some(json!({ "target": "example.com" }))).await;
    assert_eq!((&unanswered["answered"], &unanswered["result"]), (&json!(false), &json!(null)), "最初那一版的节点不会被问");

    let not_exit = api
        .fails(Method::POST, &format!("{base}/exits/{}/test", laptop.id), Some(json!({ "target": "example.com" })), StatusCode::NOT_FOUND)
        .await;
    assert_eq!(not_exit.what.as_deref(), Some("exit"));
    let malformed = api
        .fails(Method::POST, &format!("{base}/exits/{}/test", exit.id), Some(json!({ "target": "exa mple.com" })), StatusCode::BAD_REQUEST)
        .await;
    assert_eq!((malformed.what.as_deref(), malformed.field.as_deref()), (Some("malformed"), Some("target")));

    let request = api.request(Method::POST, &format!("{base}/exits/{}/test", exit.id), Some(&json!({ "target": "example.com:8443" })));
    let asking = tokio::spawn(api.router.clone().oneshot(request));
    let ToNode::ExitTest { request, host, port } = exit.next_query().await else { panic!("出口应该被问到") };
    assert_eq!((host.as_str(), port), ("example.com", 8443));
    let result = ExitTestResult {
        via: ExitVia::Direct,
        refused: None,
        resolve: None,
        connect: Some(ConnectStep { ms: 30, address: None, cause: Some(ExitTestCause::Refused) }),
        tls: None,
    };
    api.controller.handle(exit.session, REMOTE, ToController::ExitTestAnswer { request, result: Box::new(result) }).unwrap();
    let response = asking.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let view: Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!((&view["target"], &view["answered"]), (&json!("example.com:8443"), &json!(true)));
    assert_eq!(view["node"]["id"], json!(exit.id.get()));
    assert_eq!(view["result"]["connect"], json!({ "ms": 30, "address": null, "cause": { "code": "refused" } }));
}

#[tokio::test]
async fn a_series_is_read_with_a_query_string_and_gaps_come_back_as_null() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let a = api.join(network.id, Declared::default()).await;
    let path = format!("/networks/{}/stats", network.id);
    let (status, view) = api.call(Method::GET, &format!("{path}?series=online"), None).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(
        (view["series"].clone(), view["node"].clone(), view["unit"].clone(), view["step"].clone()),
        (json!("online"), Value::Null, json!("count"), json!(300))
    );
    let points = view["points"].as_array().unwrap();
    assert_eq!(points.len(), 288);
    assert!(points.iter().all(|point| point[1].is_null() && point[0].is_u64()), "还没有数据：每一段都在，值是 null");

    let node: Value = api.ok(Method::GET, &format!("{path}?series=node_tx&node={}&step=3600", a.id), None).await;
    assert_eq!(
        (node["node"]["id"].clone(), node["unit"].clone(), node["step"].clone()),
        (json!(a.id), json!("bytes_per_second"), json!(3600))
    );

    let missing = api.fails(Method::GET, &format!("{path}?series=node_tx"), None, StatusCode::BAD_REQUEST).await;
    assert_eq!((missing.what.as_deref(), missing.field.as_deref()), (Some("required"), Some("node")));
    let unknown = api.fails(Method::GET, &format!("{path}?series=everything"), None, StatusCode::BAD_REQUEST).await;
    assert_eq!(unknown.what.as_deref(), Some("query"));
    api.fails(Method::GET, &format!("{path}?series=node_tx&node=999"), None, StatusCode::NOT_FOUND).await;
}

#[tokio::test]
async fn a_node_whose_interface_is_inside_the_range_carries_a_warning() {
    let mut api = Api::new();
    let network = api.network("home").await;
    let a = api.join(network.id, Declared::default()).await;
    let local =
        Report { local_addresses: Some(vec!["10.66.5.5".parse().unwrap(), "192.168.1.9".parse().unwrap()].into()), ..Report::default() };
    api.controller.handle(a.session, REMOTE, ToController::Report(Box::new(local))).unwrap();
    let node: Value = api.ok(Method::GET, &format!("/networks/{}/nodes/{}", network.id, a.id), None).await;
    assert_eq!(node["warnings"], json!([{ "code": "range_overlap", "address": "10.66.5.5" }]));
    let overview: Value = api.ok(Method::GET, &format!("/networks/{}/overview", network.id), None).await;
    assert_eq!(overview["warnings"][0]["code"], json!("range_overlap"));
    assert_eq!(overview["warnings"][0]["node"]["id"], json!(a.id));
}
