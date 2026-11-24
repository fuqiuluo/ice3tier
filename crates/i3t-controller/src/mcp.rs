//! controller 自带的 MCP（Model Context Protocol）Server：AI Agent 带着管理员签的 JWT 连上来，查看网络、做管理操作。
//!
//! 端点挂在管理 API 的监听上（`/api/v1/mcp`），走 MCP 的 Streamable HTTP：每个 JSON-RPC 请求是一次 POST，
//! 应答是一个 JSON。没有会话，也没有服务端主动发的消息，所以 GET 和 DELETE 是 405。连接数和读请求头的时限
//! 就是管理 API 的（[`crate::admin_server`]）。
//!
//! 工具（[`tools`]）直接调 [`Controller`] 上的方法，和管理 API 的处理函数调的是同一批，不经 HTTP 绕一圈。
//!
//! # 认谁
//!
//! 只认 MCP 令牌（[`Controller::mcp_grant`]），管理令牌在这里没有用；反过来管理 API 的别的路径也不认 MCP 令牌。
//! 没带令牌、令牌不算数是 401；令牌的权限够不着要调的工具是 403，`WWW-Authenticate` 里写着 `insufficient_scope`
//! 和需要的权限（RFC 6750，MCP 的授权规范照它来）。先验令牌，验过了才去读请求体。
//!
//! # 说哪一版协议
//!
//! MCP 在 2026-07-28 这一版改成了无状态的：没有 `initialize` 握手，每个请求在 `_meta` 里自带协议版本，
//! 多了 `server/discover`，HTTP 头要和请求体对得上。更早的版本先握手。两种客户端都有，所以两种都答：
//! 请求的 `_meta` 里带着协议版本的按新的规矩，不带的按握手的那几版。两边都不要这里记任何状态。

mod tools;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequest, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, post};
use axum::{Json, body::Bytes};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use i3t_model::admin::mcp::McpScope;
use serde_json::{Map, Value, json};

use crate::controller::{Controller, McpGrant};

/// `serverInfo` 里的名字。
const SERVER_NAME: &str = "ice3tier";
/// 无状态的那一代协议里认的版本，新的在前。
const MODERN_VERSIONS: [&str; 1] = ["2026-07-28"];
/// 先握手的那一代协议里认的版本，新的在前。更早的 2024-11-05 用的是另一种传输（HTTP+SSE），不支持。
const LEGACY_VERSIONS: [&str; 3] = ["2025-11-25", "2025-06-18", "2025-03-26"];
/// 握手的那一代里，请求没带 `MCP-Protocol-Version` 头时当它是哪一版（规范这样定的：2025-03-26 还没有这个头）。
const LEGACY_DEFAULT: &str = "2025-03-26";

const VERSION_HEADER: &str = "mcp-protocol-version";
const METHOD_HEADER: &str = "mcp-method";
const NAME_HEADER: &str = "mcp-name";

const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// 工具表多久之内不用重新取，毫秒。它只随令牌的权限和 controller 的版本变。
const LIST_TTL_MS: u64 = 5 * 60 * 1000;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
/// 2026-07-28 定的两个：HTTP 头和请求体对不上，和不支持的协议版本。
const HEADER_MISMATCH: i64 = -32020;
const UNSUPPORTED_VERSION: i64 = -32022;
/// 令牌的事不是 JSON-RPC 的事，规范没有给它们编号：HTTP 的状态码已经说明了，错误体里的编号照着状态码写。
const UNAUTHORIZED: i64 = 401;
const FORBIDDEN: i64 = 403;

/// 给模型看的说明：这个 Server 是什么，东西怎么指代，添加节点怎么走。
const INSTRUCTIONS: &str = "\
This server manages an ice3tier overlay network through its controller. \
Networks, nodes, groups, rules, proxies and forwards are referred to by numeric id: list them first (network_list, node_list, group_list, ...) and pass the ids. \
Only the tools your token's scopes allow are listed. A token limited to one network sees and changes only that network. \
To add a machine: call enroll_token_create (optionally with group ids), run the returned install command on that machine, \
then call enroll_token_status until the node is listed as joined and online. An enrollment token is a secret and works once. \
Error results carry a machine-readable `code`; their `message` is in Chinese. Timestamps are Unix seconds. \
Changes made through this server are recorded in the controller's operation log under your token's name.";

type App = Arc<Controller>;

/// MCP 端点的路由。别的方法（GET、DELETE）是 405：没有可以订阅的流，也没有可以结束的会话。
pub(crate) fn endpoint() -> MethodRouter<App> {
    post(serve)
}

/// 请求用的是哪一代协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Era {
    /// 2026-07-28 起：无状态，每个请求自带版本。
    Modern,
    /// 2025-11-25 和更早：先 `initialize`。
    Legacy,
}

/// 一个不成功的应答：HTTP 状态码，加上一个 JSON-RPC 的错误。在堆上：它比成功时的结果大得多，出错又是少数。
type Refused = Box<Refusal>;

struct Refusal {
    status: StatusCode,
    /// 请求的 `id`；读不出来（或者还没读请求体）时没有。
    id: Option<Value>,
    code: i64,
    message: String,
    data: Option<Value>,
    /// `WWW-Authenticate` 头的值。
    challenge: Option<String>,
}

impl Refusal {
    fn new(status: StatusCode, code: i64, message: impl Into<String>) -> Refused {
        Box::new(Self { status, id: None, code, message: message.into(), data: None, challenge: None })
    }

    /// 请求本身不对，400。
    fn bad(code: i64, message: impl Into<String>) -> Refused {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    /// 请求读懂了、只是这一次办不了的 JSON-RPC 错误：HTTP 上是 200，错误在应答体里。
    fn rpc(code: i64, message: impl Into<String>) -> Refused {
        Self::new(StatusCode::OK, code, message)
    }

    fn with_id(mut self: Refused, id: &Value) -> Refused {
        self.id = Some(id.clone());
        self
    }

    fn with_data(mut self: Refused, data: Value) -> Refused {
        self.data = Some(data);
        self
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let mut error = json!({ "code": self.code, "message": self.message });
        if let Some(data) = self.data {
            error["data"] = data;
        }
        let mut body = json!({ "jsonrpc": "2.0", "error": error });
        if let Some(id) = self.id {
            body["id"] = id;
        }
        let mut response = (self.status, Json(body)).into_response();
        // 头的值里只有 ASCII（见 `challenge`），放不进去的话宁可不带这个头。
        if let Some(challenge) = self.challenge.and_then(|challenge| HeaderValue::from_str(&challenge).ok()) {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, challenge);
        }
        response
    }
}

async fn serve(State(app): State<App>, request: Request) -> Response {
    let remote = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0);
    let headers = request.headers().clone();
    if let Err(refusal) = check_origin(&headers) {
        tracing::warn!(?remote, "拒绝 MCP 请求：Origin 头和请求的主机不是同一个来源");
        return refusal.into_response();
    }
    let grant = match authenticate(&app, &headers) {
        Ok(grant) => grant,
        Err((reason, refusal)) => {
            tracing::warn!(?remote, reason, "拒绝 MCP 请求");
            return refusal.into_response();
        }
    };
    // 令牌验过了才读请求体，和管理 API 一样最多 2 MB。
    let body = match Bytes::from_request(request, &()).await {
        Ok(body) => body,
        Err(rejection) => return Refusal::new(rejection.status(), INVALID_REQUEST, rejection.body_text()).into_response(),
    };
    match answer(&app, &grant, &headers, &body).await {
        Ok(response) => response,
        Err(refusal) => {
            if refusal.status == StatusCode::FORBIDDEN {
                tracing::warn!(?remote, token = %grant.name, jti = %grant.jti, reason = %refusal.message, "拒绝 MCP 请求");
            }
            refusal.into_response()
        }
    }
}

/// 规范要求看 `Origin`：浏览器里别的网站的页面发来的请求带着它。带了就必须和请求的主机是同一个来源；
/// 不是浏览器的客户端（Claude Code 这一类）不带，不管。
fn check_origin(headers: &HeaderMap) -> Result<(), Refused> {
    let Some(origin) = headers.get(header::ORIGIN) else { return Ok(()) };
    let host = headers.get(header::HOST).and_then(|host| host.to_str().ok());
    let same = origin
        .to_str()
        .ok()
        .and_then(|origin| origin.split_once("://"))
        .zip(host)
        .is_some_and(|((scheme, authority), host)| matches!(scheme, "http" | "https") && authority.eq_ignore_ascii_case(host));
    if same { Ok(()) } else { Err(Refusal::new(StatusCode::FORBIDDEN, FORBIDDEN, "Origin not allowed")) }
}

/// `WWW-Authenticate` 头的值。`error` 是哪里不对和一句说明（只能有 ASCII，不能有引号和反斜杠）；
/// 请求根本没带令牌时没有它：RFC 6750 说这时不给错误信息，只说要 Bearer。
fn challenge(error: Option<(&str, &str)>, scope: Option<McpScope>) -> String {
    let mut value = "Bearer realm=\"i3t-mcp\"".to_owned();
    if let Some((error, _)) = error {
        value.push_str(&format!(", error=\"{error}\""));
    }
    if let Some(scope) = scope {
        value.push_str(&format!(", scope=\"{scope}\""));
    }
    if let Some((_, description)) = error {
        value.push_str(&format!(", error_description=\"{description}\""));
    }
    value
}

/// 请求带的 MCP 令牌说的话。不算数时是给日志的原因和 401。
fn authenticate(app: &Controller, headers: &HeaderMap) -> Result<McpGrant, (String, Refused)> {
    let presented =
        headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()).and_then(|value| value.strip_prefix("Bearer "));
    let (reason, error, description) = match presented {
        Some(token) => match app.mcp_grant(token.trim()) {
            Ok(grant) => return Ok(grant),
            // 应答里不说是哪一种不算数：过期的、撤销的、伪造的一个样。细的在日志里。
            Err(refusal) => (format!("MCP 令牌不算数：{refusal}"), Some("invalid_token"), "The MCP token is invalid, expired or revoked"),
        },
        None => ("请求未携带 MCP 令牌".to_owned(), None, "An MCP token is required: Authorization: Bearer <JWT>"),
    };
    let mut refusal = Refusal::new(StatusCode::UNAUTHORIZED, UNAUTHORIZED, description);
    refusal.challenge = Some(challenge(error.map(|error| (error, description)), None));
    Err((reason, refusal))
}

/// 一个头的值。有、但是不是能看的 ASCII 时也算没有。
fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok()).map(str::trim)
}

/// `Mcp-Name` 头的值，解开过的：不是纯 ASCII 的名字写成 `=?base64?…?=`。
fn decoded_name(raw: &str) -> Option<String> {
    match raw.strip_prefix("=?base64?").and_then(|rest| rest.strip_suffix("?=")) {
        Some(encoded) => String::from_utf8(STANDARD.decode(encoded).ok()?).ok(),
        None => Some(raw.to_owned()),
    }
}

/// 读请求体，照它说的协议办，给出应答。
async fn answer(app: &App, grant: &McpGrant, headers: &HeaderMap, body: &[u8]) -> Result<Response, Refused> {
    let message: Value = serde_json::from_slice(body).map_err(|_| Refusal::bad(PARSE_ERROR, "The request body is not JSON"))?;
    // 一次只收一个消息：成批的请求只在 2025-03-26 那一版里有，后来去掉了。
    let Value::Object(message) = message else {
        return Err(Refusal::bad(INVALID_REQUEST, "The request body must be a single JSON-RPC message"));
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        // 没有方法的是应答。这里从不向客户端发请求，所以没有什么应答可收；照规范收下，不理它。
        let is_response = message.contains_key("result") || message.contains_key("error");
        return if is_response {
            Ok(StatusCode::ACCEPTED.into_response())
        } else {
            Err(Refusal::bad(INVALID_REQUEST, "Not a JSON-RPC message"))
        };
    };
    let Some(id) = message.get("id") else {
        // 通知（`notifications/initialized`、`notifications/cancelled`）：收下，没有应答体。
        return Ok(StatusCode::ACCEPTED.into_response());
    };
    if !(id.is_string() || id.is_number()) {
        return Err(Refusal::bad(INVALID_REQUEST, "The request id must be a string or a number"));
    }
    let empty = Map::new();
    let params = match message.get("params") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(params)) => params,
        Some(_) => return Err(Refusal::bad(INVALID_PARAMS, "params must be an object").with_id(id)),
    };
    let era = negotiate(headers, method, params).map_err(|refusal| refusal.with_id(id))?;
    let result = dispatch(app, grant, era, method, params).await.map_err(|refusal| refusal.with_id(id))?;
    Ok(Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response())
}

fn unsupported_version(requested: &str) -> Refused {
    let supported: Vec<&str> = MODERN_VERSIONS.iter().chain(&LEGACY_VERSIONS).copied().collect();
    Refusal::bad(UNSUPPORTED_VERSION, "Unsupported protocol version").with_data(json!({ "supported": supported, "requested": requested }))
}

/// 这个请求说的是哪一代协议，说的版本这里认不认，头和请求体对不对得上。
fn negotiate(headers: &HeaderMap, method: &str, params: &Map<String, Value>) -> Result<Era, Refused> {
    let meta = params.get("_meta").and_then(Value::as_object);
    let header = header_text(headers, VERSION_HEADER);
    let Some(declared) = meta.and_then(|meta| meta.get(META_VERSION)) else {
        // 握手的那一代。握手本身还没有定下版本，不看头；之后的请求带的头得是认得的版本。
        return match header {
            _ if method == "initialize" => Ok(Era::Legacy),
            None => Ok(Era::Legacy),
            Some(version) if LEGACY_VERSIONS.contains(&version) => Ok(Era::Legacy),
            Some(version) if MODERN_VERSIONS.contains(&version) => Err(Refusal::bad(
                HEADER_MISMATCH,
                format!("Header mismatch: MCP-Protocol-Version is {version} but _meta carries no {META_VERSION}"),
            )),
            Some(version) => Err(unsupported_version(version)),
        };
    };
    let Some(declared) = declared.as_str() else {
        return Err(Refusal::bad(INVALID_PARAMS, format!("{META_VERSION} must be a string")));
    };
    match header {
        Some(header) if header == declared => {}
        Some(header) => {
            let message = format!("Header mismatch: MCP-Protocol-Version header value '{header}' does not match body value '{declared}'");
            return Err(Refusal::bad(HEADER_MISMATCH, message));
        }
        None => return Err(Refusal::bad(HEADER_MISMATCH, "Header mismatch: the MCP-Protocol-Version header is missing")),
    }
    if !MODERN_VERSIONS.contains(&declared) {
        return Err(unsupported_version(declared));
    }
    match header_text(headers, METHOD_HEADER) {
        Some(header) if header == method => {}
        Some(header) => {
            let message = format!("Header mismatch: Mcp-Method header value '{header}' does not match body value '{method}'");
            return Err(Refusal::bad(HEADER_MISMATCH, message));
        }
        None => return Err(Refusal::bad(HEADER_MISMATCH, "Header mismatch: the Mcp-Method header is missing")),
    }
    if method == "tools/call" {
        let name = params.get("name").and_then(Value::as_str).unwrap_or_default();
        match header_text(headers, NAME_HEADER).map(decoded_name) {
            Some(Some(header)) if header == name => {}
            Some(_) => {
                return Err(Refusal::bad(HEADER_MISMATCH, "Header mismatch: the Mcp-Name header does not match the tool name in the body"));
            }
            None => return Err(Refusal::bad(HEADER_MISMATCH, "Header mismatch: the Mcp-Name header is missing")),
        }
    }
    if !meta.is_some_and(|meta| meta.get(META_CLIENT_CAPABILITIES).is_some_and(Value::is_object)) {
        return Err(Refusal::bad(INVALID_PARAMS, format!("_meta must carry {META_CLIENT_CAPABILITIES}")));
    }
    Ok(Era::Modern)
}

fn server_info() -> Value {
    json!({ "name": SERVER_NAME, "title": "ice3tier controller", "version": env!("CARGO_PKG_VERSION") })
}

/// 把结果写成这一代协议要的样子：新的一代每个结果都带 `resultType` 和 Server 是谁。
fn finish(era: Era, mut result: Value) -> Value {
    if era == Era::Modern {
        result["resultType"] = json!("complete");
        result["_meta"] = json!({ META_SERVER_INFO: server_info() });
    }
    result
}

async fn dispatch(app: &App, grant: &McpGrant, era: Era, method: &str, params: &Map<String, Value>) -> Result<Value, Refused> {
    let capabilities = json!({ "tools": {} });
    let result = match (era, method) {
        (Era::Legacy, "initialize") => {
            // 客户端要的版本认得就用它，不认得就给这一代里最新的，由客户端决定接不接着说。
            let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(LEGACY_DEFAULT);
            let version = LEGACY_VERSIONS.iter().find(|version| **version == requested).unwrap_or(&LEGACY_VERSIONS[0]);
            json!({ "protocolVersion": version, "capabilities": capabilities, "serverInfo": server_info(), "instructions": INSTRUCTIONS })
        }
        (Era::Legacy, "ping") => json!({}),
        (Era::Modern, "server/discover") => {
            // 谁来问都是这一份，所以可以公用地缓存；工具表不一样，它随令牌的权限变。
            json!({
                "supportedVersions": MODERN_VERSIONS,
                "capabilities": capabilities,
                "instructions": INSTRUCTIONS,
                "ttlMs": LIST_TTL_MS,
                "cacheScope": "public",
            })
        }
        (_, "tools/list") => {
            // 工具一页就列完了，从不给下一页的游标，所以带着游标来的都是不认得的游标。
            if params.get("cursor").is_some_and(|cursor| !cursor.is_null()) {
                return Err(Refusal::rpc(INVALID_PARAMS, "Unknown cursor"));
            }
            let mut result = json!({ "tools": tools::listed(grant) });
            if era == Era::Modern {
                result["ttlMs"] = json!(LIST_TTL_MS);
                result["cacheScope"] = json!("private");
            }
            result
        }
        (_, "tools/call") => call(app, grant, params).await?,
        // 新的一代规定不认识的方法是 404；握手的那一代里是一个普通的 JSON-RPC 错误（有的客户端不看能力就来问
        // `resources/list`、`prompts/list`，404 会被它们当成连接出了问题）。
        (Era::Modern, _) => return Err(Refusal::new(StatusCode::NOT_FOUND, METHOD_NOT_FOUND, format!("Method not found: {method}"))),
        (Era::Legacy, _) => return Err(Refusal::rpc(METHOD_NOT_FOUND, format!("Method not found: {method}"))),
    };
    Ok(finish(era, result))
}

/// `tools/call`：找到工具，核对令牌的权限，调它，把结果（成了的和没成的）写成工具的结果。
async fn call(app: &App, grant: &McpGrant, params: &Map<String, Value>) -> Result<Value, Refused> {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return Err(Refusal::rpc(INVALID_PARAMS, "tools/call needs the name of a tool"));
    };
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(arguments)) => arguments.clone(),
        Some(_) => return Err(Refusal::rpc(INVALID_PARAMS, "arguments must be an object")),
    };
    let Some(tool) = tools::find(name) else {
        return Err(Refusal::rpc(INVALID_PARAMS, format!("Unknown tool: {name}")));
    };
    if let Err(denied) = tool.permits(grant) {
        let description = match denied {
            tools::Denied::Scope => format!("The tool {name} needs the scope {}", tool.scope),
            tools::Denied::Limited => format!("The tool {name} acts on the whole controller; this token is limited to one network"),
        };
        let mut refusal = Refusal::new(StatusCode::FORBIDDEN, FORBIDDEN, description.clone());
        refusal.data = Some(json!({ "error": "insufficient_scope", "scope": tool.scope }));
        refusal.challenge = Some(challenge(Some(("insufficient_scope", &description)), Some(tool.scope)));
        return Err(refusal);
    }
    tracing::debug!(tool = name, token = %grant.name, jti = %grant.jti, "MCP 调用工具");
    // 工具自己办不成的事（没有这个节点、名字被占了）是工具的结果，不是协议的错误：模型看得到，能自己改了再试。
    Ok(match tool.run(app, grant, arguments).await {
        Ok(value) => json!({ "content": [{ "type": "text", "text": value.to_string() }], "isError": false }),
        Err(error) => {
            let (_status, error) = crate::admin::api_error(&error);
            let text = serde_json::to_string(&error).unwrap_or_else(|_| error.message.clone());
            json!({ "content": [{ "type": "text", "text": text }], "isError": true })
        }
    })
}
