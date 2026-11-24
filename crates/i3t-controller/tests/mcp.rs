//! MCP 端点的测试：请求直接交给路由，不经过网络端口。
//!
//! 握手的那一代协议和无状态的那一代都测；令牌的权限决定看得到、调得了哪些工具；只限一个网络的令牌碰不到别的网络；
//! 不算数的令牌（没带、撤销了、过期了、改过的、别处签的、管理令牌）一律 401。JWT 本身验得过验不过的细节
//! （签名、`alg`、`aud`）在 `controller/mcp.rs` 的单元测试里，那里拿得到签名的密钥。

// clippy.toml 里的 allow-unwrap-in-tests 只认 `#[test]` 函数本身，认不出集成测试里的辅助函数。
#![allow(clippy::unwrap_used, reason = "整个文件都是测试代码，出错就该直接失败")]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use i3t_controller::store::Store;
use i3t_controller::webui::WebUi;
use i3t_controller::{Controller, Timing, admin};
use i3t_crypto::NodeKey;
use i3t_model::admin::mcp::{CreateMcpToken, CreatedMcpToken, McpScope, McpTokenInfo, McpTokenState};
use i3t_model::admin::{self as model, NetworkId};
use i3t_model::control::{Declared, EnrollToken, Hello};
use i3t_proto::{NodeId, PublicKey};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tower::ServiceExt;

const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const ENDPOINT: &str = "/api/v1/mcp";
const MODERN: &str = "2026-07-28";
const LEGACY: &str = "2025-06-18";
const CAN_DO_ALL: Declared = Declared { exit: true, relay: true, relay_address: None };

/// 一个开着 MCP 端点的 controller。
struct Server {
    router: Router,
    controller: Arc<Controller>,
    admin_token: String,
    next_key: u8,
    /// 加入之后保持在线的节点的收件箱：丢了 controller 会当它们断线。
    inboxes: Vec<mpsc::Receiver<i3t_model::control::ToNode>>,
}

/// 一次应答：状态码、头，和读成 JSON 的应答体（没有应答体时是 `null`）。
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Answer {
    /// 成功的 JSON-RPC 应答里的结果。
    fn result(&self) -> &Value {
        assert_eq!(self.status, StatusCode::OK, "{}", self.body);
        assert!(self.body.get("error").is_none(), "{}", self.body);
        &self.body["result"]
    }

    /// JSON-RPC 错误的编号。
    fn error_code(&self) -> i64 {
        self.body["error"]["code"].as_i64().unwrap_or_else(|| panic!("不是一个 JSON-RPC 错误：{}", self.body))
    }

    fn challenge(&self) -> &str {
        self.headers.get(header::WWW_AUTHENTICATE).expect("要有 WWW-Authenticate").to_str().unwrap()
    }
}

/// 工具的结果：成了的是工具给的 JSON，没成的是管理 API 那样的错误。
#[derive(Debug)]
enum Outcome {
    Done(Value),
    Failed(model::ApiError),
}

impl Outcome {
    #[track_caller]
    fn done(self) -> Value {
        match self {
            Self::Done(value) => value,
            Self::Failed(error) => panic!("工具应该成功：{error:?}"),
        }
    }

    #[track_caller]
    fn failed(self) -> model::ApiError {
        match self {
            Self::Failed(error) => error,
            Self::Done(value) => panic!("工具应该失败：{value}"),
        }
    }
}

impl Server {
    fn new() -> Self {
        let store = Store::temporary();
        let controller =
            Controller::new(store, NodeKey::generate().unwrap(), "ctl.example.com:20331".to_owned(), Timing::default()).unwrap();
        let admin_token = controller.issue_admin_token().unwrap();
        let controller = Arc::new(controller);
        let router = admin::router(Arc::clone(&controller), &WebUi::NotIncluded);
        Self { router, controller, admin_token, next_key: 0, inboxes: Vec::new() }
    }

    fn network(&self, name: &str) -> NetworkId {
        self.controller.create_network(&model::CreateNetwork { name: name.to_owned(), ..model::CreateNetwork::default() }).unwrap().id
    }

    /// 签一个令牌。
    fn issue(&self, scopes: &[McpScope], network: Option<NetworkId>) -> CreatedMcpToken {
        let request = CreateMcpToken { name: "claude-code".to_owned(), scopes: scopes.to_vec(), network, expires_in_secs: 3600 };
        self.controller.create_mcp_token(&request).unwrap()
    }

    fn jwt(&self, scopes: &[McpScope], network: Option<NetworkId>) -> String {
        self.issue(scopes, network).token
    }

    /// 一个节点用 `secret` 加入并保持在线。
    fn enroll(&mut self, secret: &str, declared: Declared) -> NodeId {
        self.next_key += 1;
        let key = PublicKey::from_bytes([self.next_key; PublicKey::LEN]);
        let (outbox, inbox) = mpsc::channel(64);
        let hello = Hello { version: "0.1.0".to_owned(), platform: "linux-x86_64".to_owned(), declared, port: 20330, ..Hello::default() };
        let session = self.controller.enroll(key, secret, &hello, REMOTE, outbox).unwrap();
        self.inboxes.push(inbox);
        session.node
    }

    /// 一个节点加入 `network` 并保持在线。
    fn join(&mut self, network: NetworkId, declared: Declared) -> NodeId {
        let created = self.controller.create_token(network, &model::CreateEnrollToken::default()).unwrap();
        let secret = created.token.parse::<EnrollToken>().unwrap().secret;
        self.enroll(&secret, declared)
    }

    async fn send(&self, request: Request<Body>) -> Answer {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("应答体不是 JSON：{}", String::from_utf8_lossy(&bytes)))
        };
        Answer { status: parts.status, headers: parts.headers, body }
    }

    /// 发一个 JSON-RPC 消息，头照 `headers` 写。
    async fn post(&self, jwt: Option<&str>, headers: &[(&str, &str)], message: &Value) -> Answer {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(ENDPOINT)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(jwt) = jwt {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {jwt}"));
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        self.send(builder.body(Body::from(message.to_string())).unwrap()).await
    }

    /// 握手的那一代的一个请求：握手之后的请求带着定下来的版本。
    async fn legacy(&self, jwt: &str, method: &str, params: Value) -> Answer {
        let message = json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params });
        let headers: &[(&str, &str)] = if method == "initialize" { &[] } else { &[("MCP-Protocol-Version", LEGACY)] };
        self.post(Some(jwt), headers, &message).await
    }

    /// 无状态的那一代的一个请求：版本和客户端的能力在 `_meta` 里，头和请求体对得上。
    async fn modern(&self, jwt: &str, method: &str, mut params: Value) -> Answer {
        params["_meta"] = modern_meta();
        let name = params.get("name").and_then(Value::as_str).map(str::to_owned);
        let mut headers = vec![("MCP-Protocol-Version", MODERN), ("Mcp-Method", method)];
        if let Some(name) = &name {
            headers.push(("Mcp-Name", name));
        }
        self.post(Some(jwt), &headers, &json!({ "jsonrpc": "2.0", "id": "r-1", "method": method, "params": params })).await
    }

    /// 调一个工具（用握手的那一代），期望协议上是成功的，返回工具的结果。
    async fn tool(&self, jwt: &str, name: &str, arguments: Value) -> Outcome {
        let answer = self.legacy(jwt, "tools/call", json!({ "name": name, "arguments": arguments })).await;
        outcome(answer.result())
    }

    /// 这个令牌看得到的工具的名字，按列出来的顺序。
    async fn tool_names(&self, jwt: &str) -> Vec<String> {
        let answer = self.legacy(jwt, "tools/list", json!({})).await;
        answer.result()["tools"].as_array().unwrap().iter().map(|tool| tool["name"].as_str().unwrap().to_owned()).collect()
    }
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientInfo": { "name": "test-client", "version": "1.0.0" },
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

/// 把 `tools/call` 的结果读成工具的结果。
fn outcome(result: &Value) -> Outcome {
    let content = result["content"].as_array().unwrap_or_else(|| panic!("工具的结果要有 content：{result}"));
    assert_eq!((content.len(), &content[0]["type"]), (1, &json!("text")), "{result}");
    let text = content[0]["text"].as_str().unwrap();
    let value: Value = serde_json::from_str(text).unwrap_or_else(|_| panic!("工具给的文字要是 JSON：{text}"));
    if result["isError"] == json!(true) { Outcome::Failed(serde_json::from_value(value).unwrap()) } else { Outcome::Done(value) }
}

/// 每项权限该有的工具。工具表改了这里要跟着改：一个工具落在哪项权限下面是这个功能的要点，不该悄悄变。
fn expected_tools() -> BTreeMap<McpScope, Vec<&'static str>> {
    BTreeMap::from([
        (
            McpScope::Read,
            vec![
                "status",
                "network_list",
                "network_show",
                "overview",
                "node_list",
                "node_show",
                "node_routes",
                "node_access",
                "node_listeners",
                "node_update_status",
                "group_list",
                "group_show",
                "rule_list",
                "access_check",
                "access_graph",
                "proxy_list",
                "proxy_show",
                "forward_list",
                "pair_list",
                "pair_show",
                "exit_list",
                "exit_show",
                "route_matrix",
                "path_show",
                "backbone_show",
                "stats_series",
                "test_list",
                "test_show",
                "matrix_show",
                "update_status",
                "log",
            ],
        ),
        (McpScope::NodesEnroll, vec!["enroll_token_list", "enroll_token_create", "enroll_token_status", "enroll_token_delete"]),
        (
            McpScope::NodesWrite,
            vec!["node_update", "node_delete", "node_succeed", "relay_enable", "relay_disable", "exit_enable", "exit_disable"],
        ),
        (
            McpScope::ConfigWrite,
            vec![
                "group_create",
                "group_rename",
                "group_members_change",
                "group_delete",
                "rule_create",
                "rule_update",
                "rule_delete",
                "proxy_create",
                "proxy_update",
                "proxy_delete",
                "forward_create",
                "forward_replace",
                "forward_delete",
                "pair_set",
                "pair_reset",
            ],
        ),
        (McpScope::TestsRun, vec!["test_start", "test_cancel", "matrix_start", "matrix_cancel", "exit_test"]),
        (McpScope::UpdatesWrite, vec!["update_settings_set", "update_check", "update_resume", "update_force_all", "node_force_update"]),
        (McpScope::NetworksWrite, vec!["network_create", "network_update", "network_delete"]),
    ])
}

/// 管整个 controller 的工具：只限一个网络的令牌看不到。
const GLOBAL_TOOLS: [&str; 2] = ["status", "update_status"];

#[tokio::test]
async fn a_client_that_shakes_hands_first_is_answered_in_the_version_it_asked_for() {
    let server = Server::new();
    let jwt = server.jwt(&[McpScope::Read], None);

    for (asked, answered) in [("2025-03-26", "2025-03-26"), (LEGACY, LEGACY), ("2025-11-25", "2025-11-25"), ("2024-11-05", "2025-11-25")] {
        let params = json!({ "protocolVersion": asked, "capabilities": {}, "clientInfo": { "name": "test", "version": "1" } });
        let answer = server.legacy(&jwt, "initialize", params).await;
        let result = answer.result();
        assert_eq!(result["protocolVersion"], answered, "要的是 {asked}");
        assert_eq!(result["capabilities"], json!({ "tools": {} }));
        assert_eq!(
            (&result["serverInfo"]["name"], &result["serverInfo"]["version"]),
            (&json!("ice3tier"), &json!(env!("CARGO_PKG_VERSION")))
        );
        assert!(result["instructions"].as_str().unwrap().contains("enroll_token_create"));
        assert!(result.get("resultType").is_none(), "握手的那一代的结果里没有新一代才有的字段：{result}");
        assert_eq!((&answer.body["jsonrpc"], &answer.body["id"]), (&json!("2.0"), &json!(7)));
        assert!(answer.headers.get("mcp-session-id").is_none(), "没有会话");
    }

    // 通知收下，没有应答体。
    let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let answer = server.post(Some(&jwt), &[("MCP-Protocol-Version", LEGACY)], &initialized).await;
    assert_eq!((answer.status, &answer.body), (StatusCode::ACCEPTED, &Value::Null));

    assert_eq!(server.legacy(&jwt, "ping", json!({})).await.result(), &json!({}));
    let listed = server.legacy(&jwt, "tools/list", json!({})).await;
    assert_eq!(listed.result()["tools"].as_array().unwrap().len(), expected_tools()[&McpScope::Read].len());
    assert!(listed.result().get("ttlMs").is_none() && listed.result().get("nextCursor").is_none());
    // 2025-03-26 的客户端不带版本的头。
    let no_header = server.post(Some(&jwt), &[], &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await;
    assert_eq!(no_header.result()["tools"].as_array().unwrap().len(), expected_tools()[&McpScope::Read].len());
    let called = server.legacy(&jwt, "tools/call", json!({ "name": "status", "arguments": {} })).await;
    assert_eq!(called.result()["isError"], json!(false));
    assert_eq!(outcome(called.result()).done()["public_addr"], "ctl.example.com:20331");

    // 不认识的方法是一个普通的 JSON-RPC 错误：有的客户端不看能力就来问别的列表。
    for method in ["resources/list", "prompts/list", "server/discover", "no/such"] {
        let answer = server.legacy(&jwt, method, json!({})).await;
        assert_eq!((answer.status, answer.error_code(), &answer.body["id"]), (StatusCode::OK, -32601, &json!(7)), "{method}");
    }
    // 握手之后带的版本得是认得的。
    let message = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let unknown = server.post(Some(&jwt), &[("MCP-Protocol-Version", "1999-01-01")], &message).await;
    assert_eq!((unknown.status, unknown.error_code()), (StatusCode::BAD_REQUEST, -32022));
    assert_eq!(unknown.body["error"]["data"]["requested"], "1999-01-01");
    assert_eq!(unknown.body["error"]["data"]["supported"], json!([MODERN, "2025-11-25", "2025-06-18", "2025-03-26"]));
}

#[tokio::test]
async fn the_endpoint_takes_one_json_rpc_message_per_post_and_nothing_else() {
    let server = Server::new();
    let jwt = server.jwt(&[McpScope::Read], None);

    // 没有可以订阅的流，也没有可以结束的会话。
    for method in [Method::GET, Method::DELETE, Method::PUT] {
        let request = Request::builder().method(method.clone()).uri(ENDPOINT).header(header::AUTHORIZATION, format!("Bearer {jwt}"));
        let answer = server.send(request.body(Body::empty()).unwrap()).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(answer.headers.get(header::ALLOW).unwrap(), "POST");
    }

    let raw = |body: &'static str| {
        let request = Request::builder().method(Method::POST).uri(ENDPOINT).header(header::AUTHORIZATION, format!("Bearer {jwt}"));
        server.send(request.body(Body::from(body)).unwrap())
    };
    let not_json = raw("{ not json").await;
    assert_eq!((not_json.status, not_json.error_code()), (StatusCode::BAD_REQUEST, -32700));
    let batch = raw(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#).await;
    assert_eq!((batch.status, batch.error_code()), (StatusCode::BAD_REQUEST, -32600), "不收成批的");
    let nothing = raw(r#"{"jsonrpc":"2.0"}"#).await;
    assert_eq!((nothing.status, nothing.error_code()), (StatusCode::BAD_REQUEST, -32600));
    let null_id = raw(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).await;
    assert_eq!((null_id.status, null_id.error_code()), (StatusCode::BAD_REQUEST, -32600));
    let bad_params = raw(r#"{"jsonrpc":"2.0","id":3,"method":"ping","params":[1]}"#).await;
    assert_eq!((bad_params.status, bad_params.error_code(), &bad_params.body["id"]), (StatusCode::BAD_REQUEST, -32602, &json!(3)));
    // 客户端发来的应答没有人等，收下不理。
    assert_eq!(raw(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).await.status, StatusCode::ACCEPTED);

    // 调工具时协议上的错：没写名字、参数不是对象、没有这个工具、带着这里从没给过的游标。
    for params in [json!({}), json!({ "name": "status", "arguments": [] }), json!({ "name": "no_such_tool" })] {
        let answer = server.legacy(&jwt, "tools/call", params.clone()).await;
        assert_eq!((answer.status, answer.error_code()), (StatusCode::OK, -32602), "{params}");
    }
    assert_eq!(server.legacy(&jwt, "tools/list", json!({ "cursor": "next" })).await.error_code(), -32602);

    // 浏览器里别的网站的页面发来的请求带着 Origin：不是同一个来源的不答。同一个来源的照常。
    let message = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let foreign = server.post(Some(&jwt), &[("Host", "127.0.0.1:20332"), ("Origin", "https://evil.example.com")], &message).await;
    assert_eq!((foreign.status, foreign.error_code()), (StatusCode::FORBIDDEN, 403));
    let same = server.post(Some(&jwt), &[("Host", "127.0.0.1:20332"), ("Origin", "http://127.0.0.1:20332")], &message).await;
    assert_eq!(same.result(), &json!({}));
}

#[tokio::test]
async fn a_stateless_client_is_answered_request_by_request_with_what_the_new_revision_requires() {
    let server = Server::new();
    let jwt = server.jwt(&[McpScope::Read], None);
    let server_info = json!({ "name": "ice3tier", "title": "ice3tier controller", "version": env!("CARGO_PKG_VERSION") });
    let meta = json!({ "io.modelcontextprotocol/serverInfo": server_info });

    let discovered = server.modern(&jwt, "server/discover", json!({})).await;
    let result = discovered.result();
    assert_eq!(result["supportedVersions"], json!([MODERN]));
    assert_eq!((&result["capabilities"], &result["resultType"], &result["_meta"]), (&json!({ "tools": {} }), &json!("complete"), &meta));
    assert_eq!((&result["ttlMs"], &result["cacheScope"]), (&json!(300_000), &json!("public")));
    assert!(result["instructions"].as_str().is_some());
    assert_eq!(discovered.body["id"], "r-1");

    let listed = server.modern(&jwt, "tools/list", json!({})).await;
    let result = listed.result();
    assert_eq!((&result["resultType"], &result["_meta"]), (&json!("complete"), &meta));
    assert_eq!((&result["ttlMs"], &result["cacheScope"]), (&json!(300_000), &json!("private")), "工具表随令牌的权限变，不能公用地缓存");
    assert_eq!(result["tools"].as_array().unwrap().len(), expected_tools()[&McpScope::Read].len());

    let called = server.modern(&jwt, "tools/call", json!({ "name": "status", "arguments": {} })).await;
    assert_eq!((&called.result()["resultType"], &called.result()["isError"]), (&json!("complete"), &json!(false)));
    assert_eq!(outcome(called.result()).done()["networks"], 0);

    // 头和请求体对不上、或者少了头，一律 400 和 HeaderMismatch。
    let request = |method: &str, name: Option<&str>| {
        let mut params = json!({ "_meta": modern_meta() });
        if let Some(name) = name {
            params["name"] = json!(name);
            params["arguments"] = json!({});
        }
        json!({ "jsonrpc": "2.0", "id": 5, "method": method, "params": params })
    };
    let list = request("tools/list", None);
    let call = request("tools/call", Some("status"));
    let mismatches: [(&Value, &[(&str, &str)]); 7] = [
        (&list, &[("Mcp-Method", "tools/list")]),
        (&list, &[("MCP-Protocol-Version", "2025-06-18"), ("Mcp-Method", "tools/list")]),
        (&list, &[("MCP-Protocol-Version", MODERN)]),
        (&list, &[("MCP-Protocol-Version", MODERN), ("Mcp-Method", "tools/call")]),
        (&call, &[("MCP-Protocol-Version", MODERN), ("Mcp-Method", "tools/call")]),
        (&call, &[("MCP-Protocol-Version", MODERN), ("Mcp-Method", "tools/call"), ("Mcp-Name", "node_list")]),
        (&call, &[("MCP-Protocol-Version", MODERN), ("Mcp-Method", "tools/call"), ("Mcp-Name", "=?base64?!!!?=")]),
    ];
    for (message, headers) in mismatches {
        let answer = server.post(Some(&jwt), headers, message).await;
        assert_eq!((answer.status, answer.error_code(), &answer.body["id"]), (StatusCode::BAD_REQUEST, -32020, &json!(5)), "{headers:?}");
    }
    // 头说是新的一代，请求体里却没有版本。
    let bare = json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" });
    let answer = server.post(Some(&jwt), &[("MCP-Protocol-Version", MODERN), ("Mcp-Method", "tools/list")], &bare).await;
    assert_eq!((answer.status, answer.error_code()), (StatusCode::BAD_REQUEST, -32020));
    // 名字不是纯 ASCII 时头里写成 base64；头的名字不分大小写。
    let encoded = format!("=?base64?{}?=", STANDARD.encode("status"));
    let headers = [("mcp-protocol-version", MODERN), ("MCP-METHOD", "tools/call"), ("mcp-name", encoded.as_str())];
    assert_eq!(server.post(Some(&jwt), &headers, &call).await.result()["isError"], json!(false));

    // 不认得的版本：说出认得的那些，客户端挑一个再来。
    let mut future = request("tools/list", None);
    future["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2030-01-01");
    let answer = server.post(Some(&jwt), &[("MCP-Protocol-Version", "2030-01-01"), ("Mcp-Method", "tools/list")], &future).await;
    assert_eq!((answer.status, answer.error_code()), (StatusCode::BAD_REQUEST, -32022));
    assert_eq!(
        answer.body["error"]["data"],
        json!({ "supported": [MODERN, "2025-11-25", "2025-06-18", "2025-03-26"], "requested": "2030-01-01" })
    );
    // 少了必须有的 `_meta` 字段。
    let mut incomplete = request("tools/list", None);
    incomplete["params"]["_meta"].as_object_mut().unwrap().remove("io.modelcontextprotocol/clientCapabilities");
    let answer = server.post(Some(&jwt), &[("MCP-Protocol-Version", MODERN), ("Mcp-Method", "tools/list")], &incomplete).await;
    assert_eq!((answer.status, answer.error_code()), (StatusCode::BAD_REQUEST, -32602));
    // 新的一代里没有握手和 ping：不认识的方法是 404。
    for method in ["initialize", "ping", "resources/list"] {
        let answer = server.modern(&jwt, method, json!({})).await;
        assert_eq!((answer.status, answer.error_code(), &answer.body["id"]), (StatusCode::NOT_FOUND, -32601, &json!("r-1")), "{method}");
    }
}

#[tokio::test]
async fn only_an_mcp_token_opens_the_endpoint_and_it_opens_nothing_else() {
    let server = Server::new();
    let created = server.issue(&McpScope::ALL, None);
    let jwt = created.token.clone();
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    assert_eq!(server.post(Some(&jwt), &[], &ping).await.result(), &json!({}));

    // 没带令牌：401，不说哪里错了。
    let missing = server.post(None, &[], &ping).await;
    assert_eq!((missing.status, missing.error_code()), (StatusCode::UNAUTHORIZED, 401));
    assert_eq!(missing.challenge(), r#"Bearer realm="i3t-mcp""#, "没带令牌时只说要什么，不说错在哪");

    // 不算数的令牌：管理令牌、乱写的、改过内容的、去掉签名的、别的 controller 签的。应答都一个样。
    let parts: Vec<&str> = jwt.split('.').collect();
    let mut claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    claims["sub"] = json!("someone-else");
    let tampered = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(claims.to_string()), parts[2]);
    let unsigned = format!("{}.{}.", URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#), parts[1]);
    let elsewhere = Server::new().jwt(&McpScope::ALL, None);
    for (what, token) in [
        ("管理令牌", server.admin_token.as_str()),
        ("乱写的", "not-a-jwt"),
        ("改过内容的", &tampered),
        ("alg: none", &unsigned),
        ("别的 controller 签的", &elsewhere),
    ] {
        let refused = server.post(Some(token), &[], &ping).await;
        assert_eq!((refused.status, refused.error_code()), (StatusCode::UNAUTHORIZED, 401), "{what}");
        assert!(refused.challenge().contains(r#"error="invalid_token""#), "{what}: {}", refused.challenge());
        assert!(!refused.body.to_string().contains(token) && !refused.challenge().contains(token), "{what}：应答里没有令牌");
    }
    // `Authorization` 得是 Bearer。
    let request = Request::builder().method(Method::POST).uri(ENDPOINT).header(header::AUTHORIZATION, format!("Basic {jwt}"));
    assert_eq!(server.send(request.body(Body::from(ping.to_string())).unwrap()).await.status, StatusCode::UNAUTHORIZED);

    // MCP 令牌在管理 API 的别的路径上没有用：看不了，更不能给自己签发、列出、撤销令牌。
    let wanted = json!({ "name": "more", "scopes": ["networks:write"], "expires_in_secs": 60 });
    let admin_paths = [
        (Method::GET, "/api/v1/status".to_owned(), None),
        (Method::GET, "/api/v1/networks".to_owned(), None),
        (Method::GET, "/api/v1/mcp/tokens".to_owned(), None),
        (Method::POST, "/api/v1/mcp/tokens".to_owned(), Some(wanted.clone())),
        (Method::POST, format!("/api/v1/mcp/tokens/{}/revoke", created.info.id), None),
    ];
    for (method, path, body) in &admin_paths {
        let request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
            .header(header::CONTENT_TYPE, "application/json");
        let body = body.as_ref().map_or_else(Body::empty, |body| Body::from(body.to_string()));
        let answer = server.send(request.body(body).unwrap()).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(answer.body["error"]["code"], "unauthorized");
    }
    assert_eq!(server.controller.mcp_tokens().unwrap().len(), 1, "一个都没多签");
    assert_eq!(server.controller.mcp_tokens().unwrap()[0].state, McpTokenState::Active, "也没有被撤销");
    // 工具里也没有管令牌的。
    let names = server.tool_names(&jwt).await;
    assert!(!names.iter().any(|name| name.contains("mcp") || name.contains("admin")), "{names:?}");

    // 管理令牌经管理 API 签发、列出、撤销；撤销之后的下一次调用就被拒绝。
    let admin = |method: Method, path: &str, body: Option<Value>| {
        let request = Request::builder()
            .method(method)
            .uri(format!("/api/v1{path}"))
            .header(header::AUTHORIZATION, format!("Bearer {}", server.admin_token))
            .header(header::CONTENT_TYPE, "application/json");
        server.send(request.body(body.map_or_else(Body::empty, |body| Body::from(body.to_string()))).unwrap())
    };
    let issued = admin(Method::POST, "/mcp/tokens", Some(json!({ "name": "codex", "scopes": ["read"], "expires_in_secs": 600 }))).await;
    assert_eq!(issued.status, StatusCode::CREATED, "{}", issued.body);
    let issued: CreatedMcpToken = serde_json::from_value(issued.body).unwrap();
    assert_eq!(server.post(Some(&issued.token), &[], &ping).await.result(), &json!({}));
    let listed = admin(Method::GET, "/mcp/tokens", None).await;
    assert!(!listed.body.to_string().contains(&issued.token) && !listed.body.to_string().contains(&jwt), "列表里没有 JWT");
    let listed: Vec<McpTokenInfo> = serde_json::from_value(listed.body).unwrap();
    assert_eq!(listed.iter().map(|token| token.name.as_str()).collect::<Vec<_>>(), ["claude-code", "codex"]);
    let revoked = admin(Method::POST, &format!("/mcp/tokens/{}/revoke", issued.info.id), None).await;
    assert_eq!((revoked.status, &revoked.body["state"]), (StatusCode::OK, &json!("revoked")));
    let refused = server.post(Some(&issued.token), &[], &ping).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "撤销之后的下一次调用");
    assert_eq!(server.post(Some(&jwt), &[], &ping).await.result(), &json!({}), "别的令牌照常");
    assert_eq!(admin(Method::POST, "/mcp/tokens/999/revoke", None).await.status, StatusCode::NOT_FOUND);
    // 请求不对的不签。
    for (body, field) in [
        (json!({ "name": "x", "scopes": ["read"] }), "expires_in_secs"),
        (json!({ "name": "x", "scopes": [], "expires_in_secs": 60 }), "scopes"),
        (json!({ "name": "x", "scopes": ["read"], "expires_in_secs": 91 * 24 * 60 * 60 }), "expires_in_secs"),
        (json!({ "name": "x", "scopes": ["read", "root"], "expires_in_secs": 60 }), "scopes"),
    ] {
        let refused = admin(Method::POST, "/mcp/tokens", Some(body.clone())).await;
        assert_eq!((refused.status, &refused.body["error"]["field"]), (StatusCode::BAD_REQUEST, &json!(field)), "{body}");
    }

    // 过期的也一样：签一个一秒钟的，过一秒多就不认了。
    let brief = CreateMcpToken { name: "brief".to_owned(), scopes: vec![McpScope::Read], network: None, expires_in_secs: 1 };
    let brief = server.controller.create_mcp_token(&brief).unwrap().token;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let expired = server.post(Some(&brief), &[], &ping).await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
    assert!(expired.challenge().contains(r#"error="invalid_token""#));
}

#[tokio::test]
async fn the_tools_a_token_sees_and_may_call_are_the_ones_its_scopes_allow() {
    let server = Server::new();
    let home = server.network("home");
    let expected = expected_tools();
    let everything = server.jwt(&McpScope::ALL, None);
    let all_names = server.tool_names(&everything).await;
    assert_eq!(all_names, expected.values().flatten().copied().collect::<Vec<_>>(), "全部权限：全部工具，顺序固定");
    assert_eq!(all_names.iter().collect::<BTreeSet<_>>().len(), all_names.len(), "名字不重复");

    for (scope, names) in &expected {
        let jwt = server.jwt(&[*scope], None);
        assert_eq!(&server.tool_names(&jwt).await, names, "{scope}");
        // 列表里没有的工具调了是 403，说出要哪项权限。挑别的每项权限的第一个工具来试。
        for (other, other_names) in expected.iter().filter(|(other, _)| *other != scope) {
            let answer = server.legacy(&jwt, "tools/call", json!({ "name": other_names[0], "arguments": { "network": home } })).await;
            assert_eq!(
                (answer.status, answer.error_code(), &answer.body["id"]),
                (StatusCode::FORBIDDEN, 403, &json!(7)),
                "{scope} 调 {}",
                other_names[0]
            );
            let challenge = answer.challenge();
            assert!(
                challenge.contains(r#"error="insufficient_scope""#) && challenge.contains(&format!(r#"scope="{other}""#)),
                "{challenge}"
            );
            assert_eq!(answer.body["error"]["data"], json!({ "error": "insufficient_scope", "scope": other }));
        }
    }
    // 没有权限的调用什么都没有做成。
    let read_only = server.jwt(&[McpScope::Read], None);
    let refused = server
        .legacy(&read_only, "tools/call", json!({ "name": "group_create", "arguments": { "network": home, "name": "servers" } }))
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let refused = server.modern(&read_only, "tools/call", json!({ "name": "network_delete", "arguments": { "network": home } })).await;
    assert_eq!((refused.status, refused.error_code()), (StatusCode::FORBIDDEN, 403), "新的一代也一样");
    assert!(refused.challenge().contains(r#"scope="networks:write""#));
    assert_eq!(server.controller.groups(home).unwrap().len(), 1, "只有内置的 All");
    assert_eq!(server.controller.networks().unwrap().len(), 1);

    // 每个工具写明了它会做什么：只读的、会删东西的、再调一次没有区别的。参数是一个不收多余字段的对象。
    let listed = server.legacy(&everything, "tools/list", json!({})).await;
    let tools = listed.result()["tools"].as_array().unwrap().clone();
    let hints = |name: &str| {
        let tool = tools.iter().find(|tool| tool["name"] == name).unwrap_or_else(|| panic!("没有 {name}"));
        let hint = |hint: &str| tool["annotations"].get(hint).and_then(Value::as_bool);
        (hint("readOnlyHint"), hint("destructiveHint"), hint("idempotentHint"), hint("openWorldHint"))
    };
    for tool in &tools {
        let name = tool["name"].as_str().unwrap();
        assert!(name.len() <= 64 && name.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'), "{name}");
        assert!(tool["title"].as_str().is_some_and(|title| !title.is_empty()), "{name}");
        assert!(tool["description"].as_str().is_some_and(|text| text.len() > 20 && text.is_ascii()), "{name}");
        let schema = &tool["inputSchema"];
        assert_eq!((&schema["type"], &schema["additionalProperties"]), (&json!("object"), &json!(false)), "{name}");
        let properties = schema["properties"].as_object().unwrap();
        for required in schema["required"].as_array().unwrap() {
            assert!(properties.contains_key(required.as_str().unwrap()), "{name} 要求的 {required} 不在参数里");
        }
        for (property, schema) in properties {
            assert!(schema["description"].as_str().is_some_and(|text| !text.is_empty()), "{name}.{property} 要有说明");
        }
        let read_only = tool["annotations"]["readOnlyHint"] == json!(true);
        let is_read_tool = expected[&McpScope::Read].contains(&name);
        let reads_under_another_scope = ["enroll_token_list", "enroll_token_status", "exit_test"].contains(&name);
        assert_eq!(read_only, is_read_tool || reads_under_another_scope, "{name}");
        if name.ends_with("_delete") {
            assert_eq!(hints(name), (Some(false), Some(true), Some(true), Some(false)), "{name}：删除要先问人");
        }
        if name.ends_with("_create") || name.ends_with("_start") {
            assert_eq!(hints(name), (Some(false), Some(false), Some(false), Some(false)), "{name}：新增，再调一次会再多一个");
        }
    }
    assert_eq!(hints("node_list"), (Some(true), None, None, Some(false)));
    assert_eq!(hints("node_update"), (Some(false), Some(false), Some(true), Some(false)));
    assert_eq!(hints("node_succeed"), (Some(false), Some(true), Some(true), Some(false)), "被继任的节点会被删掉");
    assert_eq!(hints("relay_disable"), (Some(false), Some(true), Some(true), Some(false)));
    assert_eq!(hints("pair_reset"), (Some(false), Some(true), Some(true), Some(false)));
    assert_eq!(hints("update_force_all"), (Some(false), Some(true), Some(false), Some(false)), "节点会重启");
    assert_eq!(hints("exit_test"), (Some(true), None, None, Some(true)), "去连互联网上的目标");
    assert_eq!(hints("update_check"), (Some(false), Some(false), Some(true), Some(true)), "去问发布源");
}

#[tokio::test]
async fn a_token_limited_to_a_network_sees_and_changes_only_that_network() {
    let mut server = Server::new();
    let (home, lab) = (server.network("home"), server.network("lab"));
    let (ours, theirs) = (server.join(home, Declared::default()), server.join(lab, Declared::default()));
    let their_group = server.controller.create_group(lab, &model::CreateGroup { name: "theirs".to_owned() }).unwrap().id;
    // 一条和哪个网络都无关的记录。
    server.controller.set_update_settings(&model::UpdateSettings { auto_update: Some(false), ..model::UpdateSettings::default() }).unwrap();
    let local: Vec<McpScope> = McpScope::ALL.into_iter().filter(|scope| !scope.is_global()).collect();
    let jwt = server.jwt(&local, Some(home));

    // 管整个 controller 的工具它看不到，调了是 403。
    let names = server.tool_names(&jwt).await;
    let expected: Vec<&str> =
        local.iter().flat_map(|scope| expected_tools()[scope].clone()).filter(|name| !GLOBAL_TOOLS.contains(name)).collect();
    assert_eq!(names, expected);
    for global in GLOBAL_TOOLS {
        let answer = server.legacy(&jwt, "tools/call", json!({ "name": global, "arguments": {} })).await;
        assert_eq!((answer.status, answer.error_code()), (StatusCode::FORBIDDEN, 403), "{global}");
        assert!(answer.body["error"]["message"].as_str().unwrap().contains("limited to one network"), "{}", answer.body);
    }
    // 管整个 controller 的权限也签不给它。
    for global in [McpScope::NetworksWrite, McpScope::UpdatesWrite] {
        let request = CreateMcpToken { name: "x".to_owned(), scopes: vec![global], network: Some(home), expires_in_secs: 60 };
        assert_eq!(server.controller.create_mcp_token(&request).unwrap_err().field(), Some("scopes"));
    }

    // 自己的网络照常。
    let networks = server.tool(&jwt, "network_list", json!({})).await.done();
    assert_eq!(networks.as_array().unwrap().iter().map(|network| &network["name"]).collect::<Vec<_>>(), [&json!("home")]);
    assert_eq!(server.tool(&jwt, "network_list", json!({ "network": lab })).await.done(), json!([]));
    let nodes = server.tool(&jwt, "node_list", json!({ "network": home })).await.done();
    assert_eq!(nodes.as_array().unwrap().iter().map(|node| &node["id"]).collect::<Vec<_>>(), [&json!(ours)]);
    let created = server.tool(&jwt, "group_create", json!({ "network": home, "name": "servers" })).await.done();

    // 别的网络对它等于不存在：看不了，改不了。
    let other_network = |error: model::ApiError| {
        assert_eq!(
            (error.code, error.what.as_deref(), error.field.as_deref()),
            (model::ErrorCode::NotFound, Some("network"), Some("network"))
        );
    };
    for (tool, arguments) in [
        ("network_show", json!({ "network": lab })),
        ("node_list", json!({ "network": lab })),
        ("node_show", json!({ "network": lab, "node": theirs })),
        ("group_create", json!({ "network": lab, "name": "mine" })),
        ("group_delete", json!({ "network": lab, "group": their_group })),
        ("node_delete", json!({ "network": lab, "node": theirs })),
        ("enroll_token_create", json!({ "network": lab })),
        ("test_start", json!({ "network": lab, "a": theirs, "b": theirs })),
        ("path_show", json!({ "network": lab, "from": theirs, "to": theirs })),
        ("network_show", json!({ "network": 999 })),
    ] {
        other_network(server.tool(&jwt, tool, arguments).await.failed());
    }
    // 拿自己的网络当幌子去指别的网络里的东西也不行。
    for (tool, arguments, what) in [
        ("node_show", json!({ "network": home, "node": theirs }), "node"),
        ("node_delete", json!({ "network": home, "node": theirs }), "node"),
        ("group_show", json!({ "network": home, "group": their_group }), "group"),
        ("group_members_change", json!({ "network": home, "group": created["id"], "add": [theirs] }), "node"),
        ("enroll_token_create", json!({ "network": home, "groups": [their_group] }), "group"),
    ] {
        let error = server.tool(&jwt, tool, arguments).await.failed();
        assert_eq!((error.code, error.what.as_deref()), (model::ErrorCode::NotFound, Some(what)), "{tool}");
    }
    assert_eq!(server.controller.nodes(lab).unwrap().len(), 1);
    assert_eq!(server.controller.groups(lab).unwrap().len(), 2, "别的网络里什么都没变");
    assert!(server.controller.tokens(lab, true).unwrap().len() == 1, "只有它自己的节点加入时用的那一个");

    // 操作记录里它只看得到自己这个网络的。
    let log = server.tool(&jwt, "log", json!({})).await.done();
    let log = log.as_array().unwrap();
    assert!(!log.is_empty() && log.iter().all(|entry| entry["network"] == json!(home)), "{log:?}");
    assert_eq!(server.tool(&jwt, "log", json!({ "network": lab })).await.done(), json!([]));
    let unlimited = server.jwt(&[McpScope::Read], None);
    let everything = server.tool(&unlimited, "log", json!({})).await.done();
    let networks: BTreeSet<String> = everything.as_array().unwrap().iter().map(|entry| entry["network"].to_string()).collect();
    assert_eq!(networks, BTreeSet::from([home.to_string(), lab.to_string(), "null".to_owned()]), "不限网络的令牌都看得到");
    let only_lab = server.tool(&unlimited, "log", json!({ "network": lab, "action": "group" })).await.done();
    assert_eq!(only_lab.as_array().unwrap().len(), 1);

    // 网络删掉之后，只限它的令牌跟着没有了。
    server.controller.delete_node(home, ours).unwrap();
    server.controller.delete_network(home).unwrap();
    let gone = server.legacy(&jwt, "tools/list", json!({})).await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn adding_a_node_goes_from_a_token_with_install_commands_to_a_node_seen_online() {
    let mut server = Server::new();
    let home = server.network("home");
    let servers = server.controller.create_group(home, &model::CreateGroup { name: "servers".to_owned() }).unwrap().id;
    let created = server.issue(&[McpScope::NodesEnroll], Some(home));
    let jwt = created.token.clone();

    // 建注册令牌的工具一起给出两种系统上的安装命令。
    let token =
        server.tool(&jwt, "enroll_token_create", json!({ "network": home, "groups": [servers], "expires_in_secs": 600 })).await.done();
    let text = token["token"].as_str().unwrap().to_owned();
    assert!(text.starts_with("i3t-"), "{text}");
    assert_eq!(
        token["install"]["linux_macos"],
        format!("curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --token {text}")
    );
    assert_eq!(
        token["install"]["windows_powershell_as_administrator"],
        format!("$env:I3T_TOKEN = '{text}'; irm https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.ps1 | iex")
    );
    assert_eq!((&token["groups"][0]["name"], &token["state"]), (&json!("servers"), &json!("pending")));
    let id = token["id"].as_u64().unwrap();

    // 还没有节点用它。
    let pending = server.tool(&jwt, "enroll_token_status", json!({ "network": home, "token": id })).await.done();
    assert_eq!((&pending["joined"], &pending["online"], &pending["node"]), (&json!(false), &json!(false), &Value::Null));
    // 令牌是秘密：只在建它的那一次出现，列表和状态里只有开头的一小段。
    let listed = server.tool(&jwt, "enroll_token_list", json!({ "network": home })).await.done();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert!(!listed.to_string().contains(&text) && !pending.to_string().contains(&text));
    assert!(text.starts_with(listed[0]["prefix"].as_str().unwrap()));

    // 机器上执行了安装命令：节点加入，工具看得到是哪个节点、在不在线。
    let secret = text.parse::<EnrollToken>().unwrap().secret;
    let node = server.enroll(&secret, Declared::default());
    let joined = server.tool(&jwt, "enroll_token_status", json!({ "network": home, "token": id })).await.done();
    assert_eq!((&joined["joined"], &joined["online"], &joined["node"]["id"]), (&json!(true), &json!(true), &json!(node)));
    assert_eq!(joined["node"]["groups"][0]["name"], "servers");
    assert_eq!(joined["token"]["state"], "used");
    assert_eq!(server.tool(&jwt, "enroll_token_list", json!({ "network": home })).await.done(), json!([]), "用掉的不在还能用的里面");
    let missing = server.tool(&jwt, "enroll_token_status", json!({ "network": home, "token": id + 50 })).await.failed();
    assert_eq!((missing.code, missing.what.as_deref()), (model::ErrorCode::NotFound, Some("token")));

    // 没用掉的可以收回。
    let spare = server.tool(&jwt, "enroll_token_create", json!({ "network": home })).await.done();
    assert_eq!(
        server.tool(&jwt, "enroll_token_delete", json!({ "network": home, "token": spare["id"] })).await.done(),
        json!({ "ok": true })
    );

    // 操作记录里记着这些是哪个令牌做的；节点加入是节点引起的，管理员做的也不带。
    let entries = server.controller.oplog(10).unwrap();
    let who = |action: &str| {
        let entry = entries.iter().find(|entry| entry.action == action).unwrap_or_else(|| panic!("没有 {action} 的记录"));
        entry.actor.as_ref().map(|actor| (actor.kind, actor.name.clone(), actor.jti.clone()))
    };
    let this_token = Some((model::ActorKind::Mcp, "claude-code".to_owned(), created.info.jti.clone()));
    assert_eq!(who(model::action::TOKEN_CREATE), this_token);
    assert_eq!(who(model::action::TOKEN_DELETE), this_token);
    assert_eq!(who(model::action::NODE_ENROLL), None);
    assert_eq!(who(model::action::GROUP_CREATE), None);
    assert_eq!(who(model::action::MCP_TOKEN_CREATE), None);
    for entry in &entries {
        let written = format!("{} {}", entry.detail, Value::Object(entry.params.clone()));
        assert!(!written.contains(&text) && !written.contains(&secret) && !written.contains(&jwt), "{written}");
    }
    // 经 MCP 看操作记录时也看得到是谁做的。
    let reader = server.jwt(&[McpScope::Read], Some(home));
    let log = server.tool(&reader, "log", json!({ "action": "token.create" })).await.done();
    assert_eq!(log[0]["actor"], json!({ "kind": "mcp", "name": "claude-code", "jti": created.info.jti }));
    // 只有 read 的令牌建不了注册令牌。
    let refused = server.legacy(&reader, "tools/call", json!({ "name": "enroll_token_create", "arguments": { "network": home } })).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn what_a_tool_cannot_do_comes_back_as_an_error_the_model_can_read_and_fix() {
    let mut server = Server::new();
    let home = server.network("home");
    let node = server.join(home, Declared::default());
    let jwt = server.jwt(&[McpScope::Read, McpScope::ConfigWrite, McpScope::NodesWrite], None);
    let failed = |error: model::ApiError| (error.code, error.what, error.field);
    let invalid = |what: &str, field: &str| (model::ErrorCode::InvalidRequest, Some(what.to_owned()), Some(field.to_owned()));

    // 参数的毛病：少了、写错了名字、类型不对。
    assert_eq!(failed(server.tool(&jwt, "node_show", json!({ "network": home })).await.failed()), invalid("missing", "node"));
    assert_eq!(failed(server.tool(&jwt, "node_list", json!({})).await.failed()), invalid("missing", "network"));
    let typo = server.tool(&jwt, "node_update", json!({ "network": home, "node": node, "nmae": "nas" })).await.failed();
    assert_eq!(failed(typo), invalid("not_allowed", "nmae"), "写错的参数不会被悄悄忽略");
    assert_eq!(
        failed(server.tool(&jwt, "node_show", json!({ "network": home, "node": "nas" })).await.failed()),
        invalid("malformed", "node")
    );
    let bad_enum = server.tool(&jwt, "node_update", json!({ "network": home, "node": node, "routing": "fastest" })).await.failed();
    assert_eq!((bad_enum.code, bad_enum.what.as_deref()), (model::ErrorCode::InvalidRequest, Some("malformed")));
    let missing_body = server.tool(&jwt, "rule_create", json!({ "network": home, "src": 1 })).await.failed();
    assert_eq!(failed(missing_body), invalid("malformed", "dst"));

    // controller 说办不成的：和管理 API 的错误是同一种。
    let not_found = server.tool(&jwt, "node_show", json!({ "network": home, "node": 999 })).await.failed();
    assert_eq!((not_found.code, not_found.what.as_deref()), (model::ErrorCode::NotFound, Some("node")));
    assert_eq!(not_found.message, "没有这个节点");
    server.tool(&jwt, "group_create", json!({ "network": home, "name": "servers" })).await.done();
    let taken = server.tool(&jwt, "group_create", json!({ "network": home, "name": "Servers" })).await.failed();
    assert_eq!((taken.code, taken.what.as_deref()), (model::ErrorCode::NameTaken, Some("group")));
    let undeclared = server.tool(&jwt, "relay_enable", json!({ "network": home, "node": node })).await.failed();
    assert_eq!((undeclared.code, undeclared.what.as_deref()), (model::ErrorCode::NotDeclared, Some("relay")));
    assert!(undeclared.message.contains("i3t set can-relay on"), "{}", undeclared.message);

    // 新的一代协议里也是工具的结果，不是协议的错误。
    let answer = server.modern(&jwt, "tools/call", json!({ "name": "node_show", "arguments": { "network": home, "node": 999 } })).await;
    assert_eq!(
        (answer.status, &answer.result()["isError"], &answer.result()["resultType"]),
        (StatusCode::OK, &json!(true), &json!("complete"))
    );
}

#[tokio::test]
async fn no_tool_gives_away_the_admin_token_a_jwt_an_enrollment_secret_or_a_password_it_should_not() {
    let mut server = Server::new();
    let home = server.network("home");
    let gateway = server.join(home, Declared::default());
    let exit = server.join(home, CAN_DO_ALL);
    server.controller.enable_exit(home, exit, i3t_model::netmap::ExitRole::default()).unwrap();
    let proxy = model::CreateProxy {
        node: gateway,
        name: String::new(),
        bind: "192.168.1.5:1080".parse().unwrap(),
        exit,
        protocol: i3t_model::netmap::ListenerProtocol::default(),
        username: "alice".to_owned(),
        password: "correct-horse-battery".to_owned(),
        enabled: true,
        allow_from: Vec::new(),
        class: None,
        optimistic: None,
        lane: false,
    };
    let proxy = server.controller.create_proxy(home, proxy).unwrap();
    let pending = server.controller.create_token(home, &model::CreateEnrollToken::default()).unwrap();
    let enroll_secret = pending.token.parse::<EnrollToken>().unwrap().secret;
    let other_jwt = server.jwt(&McpScope::ALL, None);
    let reader = server.jwt(&[McpScope::Read, McpScope::NodesEnroll], None);

    // 把只读的工具都调一遍，每个都得成功，结果里一样秘密都没有。
    let arguments = |name: &str| match name {
        "status" | "update_status" | "network_list" | "log" => json!({}),
        "node_show" | "node_routes" | "node_access" | "node_listeners" | "node_update_status" => {
            json!({ "network": home, "node": gateway })
        }
        "exit_show" => json!({ "network": home, "node": exit }),
        "group_show" => json!({ "network": home, "group": server.controller.groups(home).unwrap()[0].id }),
        "access_check" | "path_show" => json!({ "network": home, "from": gateway, "to": exit }),
        "pair_show" => json!({ "network": home, "a": gateway, "b": exit }),
        "proxy_show" => json!({ "network": home, "proxy": proxy.id }),
        "stats_series" => json!({ "network": home, "series": "online" }),
        "enroll_token_list" => json!({ "network": home, "all": true }),
        "enroll_token_status" => json!({ "network": home, "token": pending.info.id }),
        _ => json!({ "network": home }),
    };
    let mut names = expected_tools()[&McpScope::Read].clone();
    names.extend(["enroll_token_list", "enroll_token_status"]);
    let secrets = [
        ("管理令牌", server.admin_token.as_str()),
        ("别的 JWT", other_jwt.as_str()),
        ("自己的 JWT", reader.as_str()),
        ("注册令牌", pending.token.as_str()),
        ("注册令牌里的密钥", enroll_secret.as_str()),
        ("代理的密码", "correct-horse-battery"),
    ];
    for name in names {
        // 没有做过测试、没有跑过矩阵时这两个是"没有这个东西"，别的都该成功。
        let outcome = server.tool(&reader, name, arguments(name)).await;
        let written = match (name, outcome) {
            ("test_show" | "matrix_show", Outcome::Failed(error)) => serde_json::to_string(&error).unwrap(),
            (_, outcome) => outcome.done().to_string(),
        };
        for (what, secret) in secrets {
            assert!(!written.contains(secret), "{name} 的结果里有{what}：{written}");
        }
    }
    // 代理的用户名看得到，密码换成了一句说明，嵌在出口的视图里的也是；有 config:write 的令牌本来就能改它，看得到原文。
    let exits = server.tool(&reader, "exit_list", json!({ "network": home })).await.done();
    assert_eq!(exits[0]["proxies"][0]["password"], "(hidden: needs the config:write scope)");
    let shown = server.tool(&reader, "proxy_show", json!({ "network": home, "proxy": proxy.id })).await.done();
    assert_eq!((&shown["username"], &shown["password"]), (&json!("alice"), &json!("(hidden: needs the config:write scope)")));
    let listed = server.tool(&reader, "proxy_list", json!({ "network": home, "node": gateway })).await.done();
    assert_eq!(listed[0]["password"], "(hidden: needs the config:write scope)");
    let writer = server.jwt(&[McpScope::Read, McpScope::ConfigWrite], None);
    let shown = server.tool(&writer, "proxy_show", json!({ "network": home, "proxy": proxy.id })).await.done();
    assert_eq!(shown["password"], "correct-horse-battery");
    assert_eq!(server.tool(&writer, "proxy_list", json!({ "network": home })).await.done()[0]["password"], "correct-horse-battery");
    // 不认证的代理没有密码可藏。
    let open = model::CreateProxy {
        node: gateway,
        name: "local".to_owned(),
        bind: "127.0.0.1:1080".parse().unwrap(),
        exit,
        protocol: i3t_model::netmap::ListenerProtocol::default(),
        username: String::new(),
        password: String::new(),
        enabled: true,
        allow_from: Vec::new(),
        class: None,
        optimistic: None,
        lane: false,
    };
    let open = server.controller.create_proxy(home, open).unwrap();
    assert_eq!(server.tool(&reader, "proxy_show", json!({ "network": home, "proxy": open.id })).await.done()["password"], "");
}

#[tokio::test]
async fn every_change_the_admin_api_can_make_can_be_made_through_a_tool_with_the_right_scope() {
    let mut server = Server::new();
    let jwt = server.jwt(&McpScope::ALL, None);

    // networks:write
    let network = server.tool(&jwt, "network_create", json!({ "name": "home", "cidr": "10.77.0.0/16", "max_relay_hops": 3 })).await.done();
    let home = NetworkId(u32::try_from(network["id"].as_u64().unwrap()).unwrap());
    assert_eq!((&network["cidr"], &network["max_relay_hops"]), (&json!("10.77.0.0/16"), &json!(3)));
    let network = server
        .tool(&jwt, "network_update", json!({ "network": home, "routing": "lowest_cost", "class": "bulk", "vnet_mtu": 1400 }))
        .await
        .done();
    assert_eq!((&network["routing"], &network["class"], &network["vnet_mtu"]), (&json!("lowest_cost"), &json!("bulk"), &json!(1400)));
    let network = server.tool(&jwt, "network_update", json!({ "network": home, "class": null })).await.done();
    assert_eq!(network["class"], Value::Null, "null 是清掉这项设置");

    let (a, b) = (server.join(home, Declared::default()), server.join(home, Declared::default()));
    let capable = server.join(home, CAN_DO_ALL);

    // nodes:write
    let node = server
        .tool(&jwt, "node_update", json!({ "network": home, "node": a, "name": "nas", "forward_target": true, "profile": "low_footprint" }))
        .await
        .done();
    assert_eq!((&node["name"], &node["forward_target"], &node["profile"]), (&json!("nas"), &json!(true), &json!("low_footprint")));
    let node = server.tool(&jwt, "node_update", json!({ "network": home, "node": a, "profile": null })).await.done();
    assert_eq!((&node["name"], &node["profile"]), (&json!("nas"), &Value::Null));
    let relay = server.tool(&jwt, "relay_enable", json!({ "network": home, "node": capable, "bandwidth_mbps": 100 })).await.done();
    assert_eq!((&relay["id"], &relay["relay"]["bandwidth_mbps"]), (&json!(capable), &json!(100)));
    assert!(relay["reachability"].is_array(), "{relay}");
    let exit = server
        .tool(&jwt, "exit_enable", json!({ "network": home, "node": capable, "ports": [443, 80], "lan": true, "family": "ipv4" }))
        .await
        .done();
    assert_eq!((&exit["exit"]["ports"], &exit["exit"]["lan"], &exit["exit"]["family"]), (&json!([80, 443]), &json!(true), &json!("ipv4")));

    // config:write
    let group = server.tool(&jwt, "group_create", json!({ "network": home, "name": "servers" })).await.done();
    let group_id = group["id"].clone();
    let group = server.tool(&jwt, "group_rename", json!({ "network": home, "group": group_id, "name": "boxes" })).await.done();
    assert_eq!(group["name"], "boxes");
    let group = server.tool(&jwt, "group_members_change", json!({ "network": home, "group": group_id, "add": [a, b] })).await.done();
    assert_eq!(group["nodes"].as_array().unwrap().len(), 2);
    let group = server.tool(&jwt, "group_members_change", json!({ "network": home, "group": group_id, "remove": [b] })).await.done();
    assert_eq!(group["nodes"].as_array().unwrap().len(), 1);
    let all = server.controller.groups(home).unwrap().into_iter().find(|group| group.builtin).unwrap().id;
    let rule = server
        .tool(&jwt, "rule_create", json!({ "network": home, "src": group_id, "dst": all, "direction": "one_way", "name": "boxes out" }))
        .await
        .done();
    assert_eq!((&rule["direction"], &rule["enabled"]), (&json!("one_way"), &json!(true)));
    let rule = server.tool(&jwt, "rule_update", json!({ "network": home, "rule": rule["id"], "enabled": false })).await.done();
    assert_eq!((&rule["enabled"], &rule["name"]), (&json!(false), &json!("boxes out")));
    let proxy = server
        .tool(&jwt, "proxy_create", json!({ "network": home, "node": a, "bind": "127.0.0.1:1080", "exit": capable, "protocol": "socks5" }))
        .await
        .done();
    assert_eq!((&proxy["protocol"], &proxy["exit"]), (&json!("socks5"), &json!(capable)));
    let proxy = server
        .tool(&jwt, "proxy_update", json!({ "network": home, "proxy": proxy["id"], "name": "out", "class": "interactive" }))
        .await
        .done();
    assert_eq!((&proxy["name"], &proxy["class"], &proxy["protocol"]), (&json!("out"), &json!("interactive"), &json!("socks5")));
    let wanted = json!({ "network": home, "protocol": "tcp", "listen_node": b, "bind": "127.0.0.1:8080", "target_node": a, "target_addr": "127.0.0.1:80" });
    let forward = server.tool(&jwt, "forward_create", wanted.clone()).await.done();
    assert_eq!((&forward["listen_node"], &forward["target_node"]), (&json!(b), &json!(a)));
    let mut replaced = wanted;
    replaced["forward"] = forward["id"].clone();
    replaced["bind"] = json!("127.0.0.1:8081");
    replaced["proxy_protocol"] = json!("v2");
    let forward = server.tool(&jwt, "forward_replace", replaced).await.done();
    assert_eq!((&forward["bind"], &forward["proxy_protocol"]), (&json!("127.0.0.1:8081"), &json!("v2")));
    let pair =
        server.tool(&jwt, "pair_set", json!({ "network": home, "a": a, "b": b, "keep_alive": true, "congestion": "cubic" })).await.done();
    assert_eq!((&pair["keep_alive"], &pair["congestion"]), (&json!(true), &json!("cubic")));
    assert_eq!(server.tool(&jwt, "pair_reset", json!({ "network": home, "a": a, "b": b })).await.done(), json!({ "ok": true }));
    assert_eq!(server.tool(&jwt, "pair_show", json!({ "network": home, "a": a, "b": b })).await.done()["keep_alive"], false);

    // tests:run。最初那一版协议的节点不懂主动测试，测试马上就有了结果；这里要看的只是请求走得通。
    let test = server.tool(&jwt, "test_start", json!({ "network": home, "a": a, "b": b, "items": ["direct"] })).await.done();
    let shown = server.tool(&jwt, "test_show", json!({ "network": home, "test": test["id"] })).await.done();
    assert_eq!(shown["id"], test["id"]);
    assert_eq!(
        server.tool(&jwt, "test_list", json!({ "network": home, "a": b, "b": a, "limit": 5 })).await.done().as_array().unwrap().len(),
        1
    );
    let cancelled = server.tool(&jwt, "test_cancel", json!({ "network": home, "test": test["id"] })).await;
    assert!(
        matches!(&cancelled, Outcome::Done(_)) || matches!(&cancelled, Outcome::Failed(error) if error.code == model::ErrorCode::Busy),
        "{cancelled:?}"
    );
    let same_node = server.tool(&jwt, "test_start", json!({ "network": home, "a": a, "b": a })).await.failed();
    assert_eq!(same_node.code, model::ErrorCode::InvalidRequest);
    let matrix = server.tool(&jwt, "matrix_start", json!({ "network": home })).await;
    if let Outcome::Done(matrix) = matrix {
        assert_eq!(server.tool(&jwt, "matrix_show", json!({ "network": home })).await.done()["id"], matrix["id"]);
        let _ = server.tool(&jwt, "matrix_cancel", json!({ "network": home })).await;
    }
    let tested = server.tool(&jwt, "exit_test", json!({ "network": home, "node": capable, "target": "example.com" })).await.done();
    assert_eq!((&tested["target"], &tested["answered"]), (&json!("example.com:443"), &json!(false)), "最初那一版的节点不懂这个查询");

    // updates:write。发布源指到一个没有东西的目录：查得到"没有"，不去连项目的发布源。
    let nowhere = tempfile::tempdir().unwrap();
    let settings = server.tool(&jwt, "update_settings_set", json!({ "auto_update": false, "source": nowhere.path() })).await.done();
    assert_eq!((&settings["auto_update"], &settings["source"]), (&json!(false), &json!(nowhere.path())));
    assert!(server.tool(&jwt, "update_check", json!({})).await.done()["release"].is_null());
    let not_paused = server.tool(&jwt, "update_resume", json!({ "version": "0.9.9" })).await.failed();
    assert_eq!((not_paused.code, not_paused.what.as_deref()), (model::ErrorCode::NotFound, Some("paused_version")));
    assert_eq!(server.tool(&jwt, "update_resume", json!({ "version": "not a version" })).await.failed().field.as_deref(), Some("version"));
    let forced = server.tool(&jwt, "update_force_all", json!({ "timing": "after_drain" })).await.done();
    assert_eq!(forced["skipped"].as_array().unwrap().len(), 3, "没有查到发布，三个节点都跳过：{forced}");
    let one = server.tool(&jwt, "node_force_update", json!({ "network": home, "node": a, "timing": "now" })).await.failed();
    assert!(matches!(one.code, model::ErrorCode::NoUpdate | model::ErrorCode::CannotSelfUpdate), "{one:?}");
    assert_eq!(
        server.tool(&jwt, "node_force_update", json!({ "network": home, "node": a, "timing": "idle?" })).await.failed().field.as_deref(),
        Some("timing")
    );

    // 删：都写明了是会删东西的工具。
    for (tool, arguments) in [
        ("forward_delete", json!({ "network": home, "forward": forward["id"] })),
        ("proxy_delete", json!({ "network": home, "proxy": proxy["id"] })),
        ("rule_delete", json!({ "network": home, "rule": rule["id"] })),
    ] {
        assert_eq!(server.tool(&jwt, tool, arguments).await.done(), json!({ "ok": true }), "{tool}");
    }
    let deleted = server.tool(&jwt, "group_delete", json!({ "network": home, "group": group_id })).await.done();
    assert_eq!((&deleted["name"], deleted["nodes"].as_array().unwrap().len()), (&json!("boxes"), 1));
    assert!(server.tool(&jwt, "exit_disable", json!({ "network": home, "node": capable })).await.done()["exit"].is_null());
    assert!(server.tool(&jwt, "relay_disable", json!({ "network": home, "node": capable })).await.done()["relay"].is_null());

    // 继任：原来的节点下线之后，新加入的节点接手它的名字，原来的被删掉。
    server.inboxes.remove(0);
    let sessions = server.controller.nodes(home).unwrap();
    assert!(sessions.iter().any(|node| node.id == a));
    let fresh = server.join(home, Declared::default());
    let online = server.tool(&jwt, "node_succeed", json!({ "network": home, "node": fresh, "predecessor": b })).await.failed();
    assert_eq!(online.code, model::ErrorCode::PredecessorOnline, "还在线的不能被继任");
    for node in [fresh, b, capable] {
        assert_eq!(server.tool(&jwt, "node_delete", json!({ "network": home, "node": node })).await.done(), json!({ "ok": true }));
    }
    let not_empty = server.tool(&jwt, "network_delete", json!({ "network": home })).await.failed();
    assert_eq!(not_empty.code, model::ErrorCode::NetworkNotEmpty);
    server.tool(&jwt, "node_delete", json!({ "network": home, "node": a })).await.done();
    assert_eq!(server.tool(&jwt, "network_delete", json!({ "network": home })).await.done(), json!({ "ok": true }));
    assert!(server.controller.networks().unwrap().is_empty());

    // 每一步改动都记在这个令牌头上。
    let entries = server.controller.oplog(200).unwrap();
    let by_token = entries.iter().filter(|entry| entry.actor.as_ref().is_some_and(|actor| actor.name == "claude-code")).count();
    assert!(by_token >= 25, "经 MCP 做的改动都带着是谁做的：{by_token} / {}", entries.len());
    let unattributed: Vec<&str> = entries.iter().filter(|entry| entry.actor.is_none()).map(|entry| entry.action.as_str()).collect();
    assert!(
        unattributed.iter().all(|action| matches!(*action, "mcp.token.create" | "node.enroll" | "token.create" | "admin.token")),
        "{unattributed:?}"
    );
}

#[tokio::test]
async fn a_jwt_is_never_written_to_the_log_whether_it_is_accepted_or_refused() {
    let server = Server::new();
    let home = server.network("home");
    let jwt = server.jwt(&[McpScope::Read], None);
    let parts: Vec<&str> = jwt.split('.').collect();
    let tampered = format!("{}.{}.{}", parts[0], parts[1], "A".repeat(parts[2].len()));

    let file = tempfile::NamedTempFile::new().unwrap();
    let writer = std::sync::Mutex::new(file.reopen().unwrap());
    let subscriber =
        tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).without_time().with_ansi(false).with_writer(writer).finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    assert_eq!(server.post(None, &[], &ping).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(server.post(Some(&tampered), &[], &ping).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(server.post(Some(&server.admin_token), &[], &ping).await.status, StatusCode::UNAUTHORIZED);
    server.tool(&jwt, "node_list", json!({ "network": home })).await.done();
    server.tool(&jwt, "node_show", json!({ "network": home, "node": 9 })).await.failed();
    let forbidden = server.legacy(&jwt, "tools/call", json!({ "name": "node_delete", "arguments": { "network": home, "node": 9 } })).await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    drop(guard);

    let log = std::fs::read_to_string(file.path()).unwrap();
    assert_eq!(log.matches("拒绝 MCP 请求").count(), 4, "三次没过令牌这一关，一次权限不够，都记了：\n{log}");
    assert!(log.contains("签名不对") && log.contains("不是一个 JWT") && log.contains("needs the scope nodes:write"), "{log}");
    // 被拒绝的调用记着是哪个令牌（名字和 jti），不是令牌本身。
    let jti = server.controller.mcp_tokens().unwrap().remove(0).jti;
    assert!(log.contains("claude-code") && log.contains(&jti), "{log}");
    for secret in [jwt.as_str(), parts[1], parts[2], tampered.as_str(), server.admin_token.as_str()] {
        assert!(!log.contains(secret), "日志里有令牌：\n{log}");
    }
}
