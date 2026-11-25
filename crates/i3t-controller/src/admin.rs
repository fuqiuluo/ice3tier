//! 管理 API：HTTP + JSON，WebUI 和命令行都走它。
//!
//! 数据结构在 `i3t_model::admin`。
//! 这里每个处理函数只做三件事：取出路径和请求体，调用 [`Controller`] 上对应的方法，把结果写成 JSON。
//!
//! `/api/v1` 下面的请求都要带管理令牌（`Authorization: Bearer <令牌>`）。只有一个管理员，没有角色。
//! 不要令牌的只有两样：WebUI 的静态文件（[`WebUi`]），和 `/metrics`。后者只有合计的数，没有节点的名字和地址，
//! 这样抓指标的程序不用拿着能改一切的管理令牌。`/metrics` 同一时刻只计算一次（见 [`Metrics`]）。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::RawPathParams;
use axum::extract::path::ErrorKind;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use i3t_model::admin::diag::{CreateTest, TestQuery};
use i3t_model::admin::stats::SeriesQuery;
use i3t_model::admin::{
    API_PREFIX, ApiError, CreateEnrollToken, CreateGroup, CreateNetwork, CreateProxy, CreateRule, ErrorBody, ErrorCode, ExitTestInput,
    ForceUpdate, ForwardInput, GroupId, GroupMembers, LogRef, NetworkId, PairInput, RelayEnabled, RelaySettings, ResumeUpdate, Succeed,
    UpdateGroup, UpdateNetwork, UpdateNode, UpdateProxy, UpdateRule, UpdateSettings,
};
use i3t_model::netmap::ExitRole;
use i3t_proto::NodeId;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Semaphore;

use crate::controller::Controller;
use crate::error::{Error, error_chain};
use crate::reachability;
use crate::server::blocking;
use crate::store::LogFilter;
use crate::webui::WebUi;

/// 操作记录一次最多取多少条，和不写 `limit` 时取多少条。
const MAX_LOG_LIMIT: u32 = 1000;
const DEFAULT_LOG_LIMIT: u32 = 100;

type App = Arc<Controller>;
type Reply = Result<Response, Failure>;

/// 管理 API 的全部路由，加上 `/metrics`。别的路径交给 `webui`。
pub fn router(controller: Arc<Controller>, webui: &WebUi) -> Router {
    let network = "/networks/{network}";
    let api = Router::new()
        .route("/status", get(status))
        .route("/log", get(log))
        .route("/update", get(show_update).patch(set_update))
        .route("/update/check", post(check_update))
        .route("/update/resume", post(resume_update))
        .route("/update/force", post(force_update_all))
        .route("/networks", get(list_networks).post(create_network))
        .route(network, get(show_network).patch(update_network).delete(delete_network))
        .route(&format!("{network}/overview"), get(overview))
        .route(&format!("{network}/nodes"), get(list_nodes))
        .route(&format!("{network}/nodes/{{node}}"), get(show_node).patch(update_node).delete(delete_node))
        .route(&format!("{network}/nodes/{{node}}/relay"), put(enable_relay).delete(disable_relay))
        .route(&format!("{network}/nodes/{{node}}/exit"), put(enable_exit).delete(disable_exit))
        .route(&format!("{network}/nodes/{{node}}/succeed"), post(succeed))
        .route(&format!("{network}/nodes/{{node}}/routes"), get(routes))
        .route(&format!("{network}/nodes/{{node}}/access"), get(node_access))
        .route(&format!("{network}/nodes/{{node}}/update"), get(show_node_update).post(force_node_update))
        .route(&format!("{network}/nodes/{{node}}/listeners"), get(node_listeners))
        .route(&format!("{network}/exits"), get(list_exits))
        .route(&format!("{network}/exits/{{node}}"), get(show_exit))
        .route(&format!("{network}/exits/{{node}}/test"), post(test_exit))
        .route(&format!("{network}/routes"), get(route_matrix))
        .route(&format!("{network}/path"), get(path))
        .route(&format!("{network}/backbone"), get(backbone))
        .route(&format!("{network}/stats"), get(series))
        .route(&format!("{network}/tests"), get(list_tests).post(start_test))
        .route(&format!("{network}/tests/matrix"), get(show_matrix).post(start_matrix))
        .route(&format!("{network}/tests/matrix/cancel"), post(cancel_matrix))
        .route(&format!("{network}/tests/{{id}}"), get(show_test))
        .route(&format!("{network}/tests/{{id}}/cancel"), post(cancel_test))
        .route(&format!("{network}/groups"), get(list_groups).post(create_group))
        .route(&format!("{network}/groups/{{group}}"), get(show_group).patch(update_group).delete(delete_group))
        .route(&format!("{network}/groups/{{group}}/nodes"), axum::routing::patch(change_members))
        .route(&format!("{network}/groups/{{group}}/nodes/{{node}}"), put(add_member).delete(remove_member))
        .route(&format!("{network}/tokens"), get(list_tokens).post(create_token))
        .route(&format!("{network}/tokens/{{id}}"), axum::routing::delete(delete_token))
        .route(&format!("{network}/rules"), get(list_rules).post(create_rule))
        .route(&format!("{network}/rules/{{id}}"), axum::routing::patch(update_rule).delete(delete_rule))
        .route(&format!("{network}/proxies"), get(list_proxies).post(create_proxy))
        .route(&format!("{network}/proxies/{{id}}"), get(show_proxy).patch(update_proxy).delete(delete_proxy))
        .route(&format!("{network}/forwards"), get(list_forwards).post(create_forward))
        .route(&format!("{network}/forwards/{{id}}"), put(replace_forward).delete(delete_forward))
        .route(&format!("{network}/pairs"), get(list_pairs))
        .route(&format!("{network}/pairs/{{a}}/{{b}}"), get(get_pair).put(set_pair).delete(delete_pair))
        .route(&format!("{network}/access/graph"), get(access_graph))
        .route(&format!("{network}/access/check"), get(access_check))
        .fallback(no_such_endpoint)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(Arc::clone(&controller), require_admin))
        .with_state(Arc::clone(&controller));

    let metrics_state = Metrics { controller, turn: Arc::new(Semaphore::new(1)) };
    let router = Router::new().route("/metrics", get(metrics)).with_state(metrics_state).nest(API_PREFIX, api);
    webui.attach(router)
}

/// 出错时的应答：HTTP 状态码加上统一格式的 JSON。
struct Failure {
    status: StatusCode,
    code: ErrorCode,
    message: String,
    what: Option<String>,
    field: Option<String>,
}

impl Failure {
    fn new(status: StatusCode, code: ErrorCode, what: Option<&str>, message: String) -> Self {
        Self { status, code, message, what: what.map(str::to_owned), field: None }
    }

    /// 请求本身不合法。`what` 是哪里不对：`body`、`query`、`path`。
    fn bad_request(what: &str, field: Option<String>, message: String) -> Self {
        Self { field, ..Self::new(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, Some(what), message) }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        let code = error.code();
        let status = match code {
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::InvalidRequest | ErrorCode::AddressOutOfRange | ErrorCode::ExitIsNode | ErrorCode::CredentialsIncomplete => {
                StatusCode::BAD_REQUEST
            }
            ErrorCode::NameTaken
            | ErrorCode::NameCoolingDown
            | ErrorCode::AddressTaken
            | ErrorCode::AddressCoolingDown
            | ErrorCode::RangeOverlaps
            | ErrorCode::RangeExhausted
            | ErrorCode::RangeNotSuperset
            | ErrorCode::NetworkNotEmpty
            | ErrorCode::NotDeclared
            | ErrorCode::ForwardTargetOff
            | ErrorCode::PredecessorOnline
            | ErrorCode::Conflict
            | ErrorCode::NodeOffline
            | ErrorCode::CannotSelfUpdate
            | ErrorCode::NoUpdate
            | ErrorCode::TooSoon
            | ErrorCode::Busy
            | ErrorCode::ExitNotEnabled
            | ErrorCode::AccessDenied => StatusCode::CONFLICT,
            // `ErrorCode` 以后可能加新的值；这里没有专门对应的一律按内部错误报。
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!("管理请求失败：{}", error_chain(&error));
            // 内部错误的细节只进日志，不发给调用方；只说是哪个环节。
            let message = "controller 内部错误，详情请查看 controller 日志".to_owned();
            return Self::new(status, ErrorCode::Internal, error.what().as_deref(), message);
        }
        tracing::info!(?code, reason = %error, "拒绝管理请求");
        Self { status, code, message: error.to_string(), what: error.what(), field: error.field().map(str::to_owned) }
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let body = ErrorBody { error: ApiError { code: self.code, message: self.message, what: self.what, field: self.field } };
        let mut response = (self.status, Json(body)).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, header::HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// 每个请求都要带对的管理令牌。
async fn require_admin(State(controller): State<App>, request: Request, next: Next) -> Response {
    let presented =
        request.headers().get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()).and_then(|value| value.strip_prefix("Bearer "));
    let (what, reason) = match presented {
        Some(token) if controller.is_admin_token(token.trim()) => return next.run(request).await,
        Some(_) => ("wrong", "管理令牌不正确"),
        None => ("missing", "请求未携带管理令牌（Authorization: Bearer <令牌>）"),
    };
    let remote = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0);
    tracing::warn!(?remote, path = %request.uri().path(), reason, "拒绝管理请求");
    Failure::new(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, Some(what), reason.to_owned()).into_response()
}

async fn no_such_endpoint() -> Failure {
    Failure::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, Some("endpoint"), "接口不存在".to_owned())
}

async fn method_not_allowed() -> Failure {
    Failure::new(StatusCode::METHOD_NOT_ALLOWED, ErrorCode::InvalidRequest, Some("method"), "该接口不支持当前请求方法".to_owned())
}

/// 路径参数。解析失败时按统一格式返回错误。
struct Path<T>(T);

impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for Path<T> {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(value)) => Ok(Self(value)),
            Err(PathRejection::FailedToDeserializePathParams(error)) => {
                // 路径参数的名字：axum 在按名字解析时直接给出；按位置（元组）或者只有一个参数时，从原始的参数表里按位置取。
                let names = RawPathParams::from_request_parts(parts, state).await.ok();
                let nth = |index: usize| names.as_ref().and_then(|names| names.iter().nth(index)).map(|(key, _)| key.to_owned());
                let field = match error.kind() {
                    ErrorKind::ParseErrorAtKey { key, .. } | ErrorKind::InvalidUtf8InPathParam { key } => Some(key.clone()),
                    ErrorKind::ParseErrorAtIndex { index, .. } => nth(*index),
                    ErrorKind::ParseError { .. } if names.as_ref().is_some_and(|names| names.iter().count() == 1) => nth(0),
                    _ => None,
                };
                Err(Failure::bad_request("path", field, format!("路径中的编号无效：{}", error.body_text())))
            }
            Err(rejection) => Err(Failure::bad_request("path", None, rejection.body_text())),
        }
    }
}

/// 查询串里的参数。
struct Query<T>(T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for Query<T> {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(value)) => Ok(Self(value)),
            Err(rejection @ QueryRejection::FailedToDeserializeQueryString(_)) => {
                let text = rejection.body_text();
                Err(Failure::bad_request("query", named_field(&text), format!("查询参数无效：{text}")))
            }
            Err(rejection) => Err(Failure::bad_request("query", None, rejection.body_text())),
        }
    }
}

/// JSON 请求体。
struct Body<T>(T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Body<T> {
    type Rejection = Failure;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                let text = rejection.body_text();
                let (what, field, said) = match &rejection {
                    JsonRejection::MissingJsonContentType(_) => {
                        ("content_type", None, "请求体必须为 JSON（Content-Type: application/json）")
                    }
                    JsonRejection::JsonSyntaxError(_) => ("syntax", None, "请求体不是合法的 JSON"),
                    JsonRejection::JsonDataError(_) => ("data", data_field(&text), "请求体字段无效"),
                    _ => ("body", None, "无法读取请求体"),
                };
                Err(Failure::bad_request(what, field, format!("{said}：{text}")))
            }
        }
    }
}

/// JSON 请求体里出问题的字段。axum 的说法是"Failed to deserialize the JSON body into the target type: <路径>: <原因>"，
/// 路径是 serde 走到出错处的字段（`exit.ports[2]` 这样），取它的第一段；缺字段时路径是空的，字段名在原因里（`` missing field `name` ``）。
fn data_field(text: &str) -> Option<String> {
    let detail = text.split_once("target type: ").map_or(text, |(_, rest)| rest);
    let path = detail.split_once(": ").map(|(path, _)| path).filter(|path| !path.contains(' '));
    match path {
        Some(path) => path.split(['.', '[']).next().filter(|first| !first.is_empty()).map(str::to_owned),
        None => named_field(detail),
    }
}

/// serde 的说法里用反引号括起来的字段名：`` missing field `from` ``。
fn named_field(text: &str) -> Option<String> {
    let (_, rest) = text.split_once("field `")?;
    rest.split_once('`').map(|(name, _)| name.to_owned())
}

/// 调用 controller，把结果写成 JSON 应答。
async fn respond<T: Serialize + Send + 'static>(
    controller: &App,
    status: StatusCode,
    call: impl FnOnce(&Controller) -> Result<T, Error> + Send + 'static,
) -> Reply {
    let value = blocking(controller, call).await?;
    Ok((status, Json(value)).into_response())
}

async fn ok<T: Serialize + Send + 'static>(controller: &App, call: impl FnOnce(&Controller) -> Result<T, Error> + Send + 'static) -> Reply {
    respond(controller, StatusCode::OK, call).await
}

async fn created<T: Serialize + Send + 'static>(
    controller: &App,
    call: impl FnOnce(&Controller) -> Result<T, Error> + Send + 'static,
) -> Reply {
    respond(controller, StatusCode::CREATED, call).await
}

/// 删除成功没有应答体。
async fn deleted(controller: &App, call: impl FnOnce(&Controller) -> Result<(), Error> + Send + 'static) -> Reply {
    blocking(controller, call).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
struct LogQuery {
    limit: Option<u32>,
    before: Option<u64>,
    network: Option<NetworkId>,
    action: Option<String>,
    /// `node:3` 这样的写法。
    #[serde(rename = "ref")]
    reference: Option<String>,
}

#[derive(Deserialize)]
struct TokenQuery {
    #[serde(default)]
    all: bool,
}

#[derive(Deserialize)]
struct ProxyQuery {
    node: Option<NodeId>,
}

#[derive(Deserialize)]
struct CheckQuery {
    from: NodeId,
    to: NodeId,
}

/// Prometheus 的文本格式。
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// `/metrics` 用的状态：controller，和同一时刻只允许一次计算的名额。
///
/// `/metrics` 不要令牌，计算要在阻塞线程池里拿 controller 的锁、读存储。交给阻塞线程池的任务不会随连接断开而取消：
/// 不加限制的话，客户端发出请求后立即断开，就能让排队的计算无限累积、占满阻塞线程池，节点的报到、上报和管理请求都排在后面。
/// 名额在连接上异步等待，连接断开即随之放弃；拿到之后随计算一起交给阻塞线程池，计算完成才归还。
#[derive(Clone)]
struct Metrics {
    controller: App,
    turn: Arc<Semaphore>,
}

async fn metrics(State(metrics): State<Metrics>) -> Reply {
    let turn = Arc::clone(&metrics.turn).acquire_owned().await.expect("名额从不关闭");
    let text = blocking(&metrics.controller, move |controller| {
        let _turn = turn;
        controller.metrics()
    })
    .await?;
    Ok(([(header::CONTENT_TYPE, METRICS_CONTENT_TYPE)], text).into_response())
}

async fn show_update(State(app): State<App>) -> Reply {
    ok(&app, Controller::update_overview).await
}

async fn set_update(State(app): State<App>, Body(request): Body<UpdateSettings>) -> Reply {
    ok(&app, move |controller| controller.set_update_settings(&request)).await
}

/// 查发布源要走网络，可能要等几十秒；它在阻塞线程上跑，不占着运行时。
async fn check_update(State(app): State<App>) -> Reply {
    ok(&app, Controller::check_release).await
}

async fn resume_update(State(app): State<App>, Body(request): Body<ResumeUpdate>) -> Reply {
    ok(&app, move |controller| controller.resume_update(&request.version)).await
}

async fn force_update_all(State(app): State<App>, Body(request): Body<ForceUpdate>) -> Reply {
    ok(&app, move |controller| controller.force_update_all(request.timing)).await
}

async fn show_node_update(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.node_update(network, node)).await
}

async fn force_node_update(
    State(app): State<App>,
    Path((network, node)): Path<(NetworkId, NodeId)>,
    Body(request): Body<ForceUpdate>,
) -> Reply {
    ok(&app, move |controller| controller.force_update(network, node, request.timing)).await
}

async fn route_matrix(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.route_matrix(network)).await
}

async fn path(State(app): State<App>, Path(network): Path<NetworkId>, Query(query): Query<CheckQuery>) -> Reply {
    let view = app.path(network, query.from, query.to).await?;
    Ok(Json(view).into_response())
}

async fn backbone(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    let view = app.backbone(network).await?;
    Ok(Json(view).into_response())
}

async fn start_test(State(app): State<App>, Path(network): Path<NetworkId>, Body(request): Body<CreateTest>) -> Reply {
    created(&app, move |controller| controller.start_test(network, &request)).await
}

async fn list_tests(State(app): State<App>, Path(network): Path<NetworkId>, Query(query): Query<TestQuery>) -> Reply {
    ok(&app, move |controller| controller.tests(network, &query)).await
}

async fn show_test(State(app): State<App>, Path((network, id)): Path<(NetworkId, u64)>) -> Reply {
    ok(&app, move |controller| controller.test(network, id)).await
}

async fn cancel_test(State(app): State<App>, Path((network, id)): Path<(NetworkId, u64)>) -> Reply {
    ok(&app, move |controller| controller.cancel_test(network, id)).await
}

async fn start_matrix(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    created(&app, move |controller| controller.start_matrix(network)).await
}

async fn show_matrix(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.matrix(network)).await
}

async fn cancel_matrix(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.cancel_matrix(network)).await
}

async fn status(State(app): State<App>) -> Reply {
    ok(&app, Controller::status).await
}

async fn log(State(app): State<App>, Query(query): Query<LogQuery>) -> Reply {
    let reference = match query.reference.as_deref().map(str::parse::<LogRef>).transpose() {
        Ok(reference) => reference,
        Err(error) => return Err(Failure::bad_request("query", Some("ref".to_owned()), format!("查询参数 ref 无效：{error}"))),
    };
    let filter = LogFilter {
        limit: query.limit.unwrap_or(DEFAULT_LOG_LIMIT).min(MAX_LOG_LIMIT),
        before: query.before,
        network: query.network,
        action: query.action.filter(|action| !action.is_empty()),
        reference,
    };
    ok(&app, move |controller| controller.oplog_filtered(&filter)).await
}

async fn node_listeners(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.node_listeners(network, node)).await
}

async fn list_exits(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.exits(network)).await
}

async fn show_exit(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.exit(network, node)).await
}

async fn test_exit(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>, Body(input): Body<ExitTestInput>) -> Reply {
    let view = app.exit_test(network, node, input).await?;
    Ok(Json(view).into_response())
}

async fn list_groups(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.groups(network)).await
}

async fn create_group(State(app): State<App>, Path(network): Path<NetworkId>, Body(request): Body<CreateGroup>) -> Reply {
    created(&app, move |controller| controller.create_group(network, &request)).await
}

async fn show_group(State(app): State<App>, Path((network, group)): Path<(NetworkId, GroupId)>) -> Reply {
    ok(&app, move |controller| controller.group(network, group)).await
}

async fn update_group(
    State(app): State<App>,
    Path((network, group)): Path<(NetworkId, GroupId)>,
    Body(request): Body<UpdateGroup>,
) -> Reply {
    ok(&app, move |controller| controller.update_group(network, group, &request)).await
}

/// 删除分组的应答说删掉了什么，所以是 200 和一个应答体，不是别的删除那样的 204。
async fn delete_group(State(app): State<App>, Path((network, group)): Path<(NetworkId, GroupId)>) -> Reply {
    ok(&app, move |controller| controller.delete_group(network, group)).await
}

async fn change_members(
    State(app): State<App>,
    Path((network, group)): Path<(NetworkId, GroupId)>,
    Body(request): Body<GroupMembers>,
) -> Reply {
    ok(&app, move |controller| controller.change_members(network, group, &request)).await
}

async fn add_member(State(app): State<App>, Path((network, group, node)): Path<(NetworkId, GroupId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.add_member(network, group, node)).await
}

async fn remove_member(State(app): State<App>, Path((network, group, node)): Path<(NetworkId, GroupId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.remove_member(network, group, node)).await
}

async fn list_networks(State(app): State<App>) -> Reply {
    ok(&app, Controller::networks).await
}

async fn create_network(State(app): State<App>, Body(request): Body<CreateNetwork>) -> Reply {
    created(&app, move |controller| controller.create_network(&request)).await
}

async fn show_network(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.network(network)).await
}

async fn update_network(State(app): State<App>, Path(network): Path<NetworkId>, Body(request): Body<UpdateNetwork>) -> Reply {
    ok(&app, move |controller| controller.update_network(network, &request)).await
}

async fn delete_network(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    deleted(&app, move |controller| controller.delete_network(network)).await
}

async fn overview(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.overview(network)).await
}

async fn list_nodes(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.nodes(network)).await
}

async fn show_node(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.node(network, node)).await
}

async fn update_node(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>, Body(request): Body<UpdateNode>) -> Reply {
    ok(&app, move |controller| controller.update_node(network, node, &request)).await
}

async fn delete_node(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>) -> Reply {
    deleted(&app, move |controller| controller.delete_node(network, node)).await
}

/// 启用后从 controller 侧探测 relay 地址的连通性，并将结果与节点信息一并返回给调用方。探测结果仅供参考，仅反映 controller 到该地址的连通性。
async fn enable_relay(
    State(app): State<App>,
    Path((network, node)): Path<(NetworkId, NodeId)>,
    Body(settings): Body<RelaySettings>,
) -> Reply {
    let node = blocking(&app, move |controller| controller.enable_relay(network, node, settings)).await?;
    let addresses: Vec<SocketAddr> = node.relay.iter().flat_map(|relay| &relay.addresses).map(|entry| entry.address).collect();
    let reachability = reachability::check(&addresses, &addresses).await;
    Ok(Json(RelayEnabled { node, reachability }).into_response())
}

async fn series(State(app): State<App>, Path(network): Path<NetworkId>, Query(query): Query<SeriesQuery>) -> Reply {
    ok(&app, move |controller| controller.series(network, &query)).await
}

async fn disable_relay(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.disable_relay(network, node)).await
}

async fn enable_exit(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>, Body(settings): Body<ExitRole>) -> Reply {
    ok(&app, move |controller| controller.enable_exit(network, node, settings)).await
}

async fn disable_exit(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.disable_exit(network, node)).await
}

async fn succeed(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>, Body(request): Body<Succeed>) -> Reply {
    ok(&app, move |controller| controller.succeed(network, node, request.predecessor)).await
}

async fn routes(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.routes(network, node)).await
}

async fn node_access(State(app): State<App>, Path((network, node)): Path<(NetworkId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.node_access(network, node)).await
}

async fn list_tokens(State(app): State<App>, Path(network): Path<NetworkId>, Query(query): Query<TokenQuery>) -> Reply {
    ok(&app, move |controller| controller.tokens(network, query.all)).await
}

async fn create_token(State(app): State<App>, Path(network): Path<NetworkId>, Body(request): Body<CreateEnrollToken>) -> Reply {
    created(&app, move |controller| controller.create_token(network, &request)).await
}

async fn delete_token(State(app): State<App>, Path((network, id)): Path<(NetworkId, u32)>) -> Reply {
    deleted(&app, move |controller| controller.delete_token(network, id)).await
}

async fn list_rules(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.rules(network)).await
}

async fn create_rule(State(app): State<App>, Path(network): Path<NetworkId>, Body(request): Body<CreateRule>) -> Reply {
    created(&app, move |controller| controller.create_rule(network, &request)).await
}

async fn update_rule(State(app): State<App>, Path((network, id)): Path<(NetworkId, u32)>, Body(request): Body<UpdateRule>) -> Reply {
    ok(&app, move |controller| controller.update_rule(network, id, &request)).await
}

async fn delete_rule(State(app): State<App>, Path((network, id)): Path<(NetworkId, u32)>) -> Reply {
    deleted(&app, move |controller| controller.delete_rule(network, id)).await
}

async fn list_proxies(State(app): State<App>, Path(network): Path<NetworkId>, Query(query): Query<ProxyQuery>) -> Reply {
    ok(&app, move |controller| controller.proxies(network, query.node)).await
}

async fn create_proxy(State(app): State<App>, Path(network): Path<NetworkId>, Body(input): Body<CreateProxy>) -> Reply {
    created(&app, move |controller| controller.create_proxy(network, input)).await
}

async fn show_proxy(State(app): State<App>, Path((network, id)): Path<(NetworkId, u32)>) -> Reply {
    ok(&app, move |controller| controller.proxy(network, id)).await
}

async fn update_proxy(State(app): State<App>, Path((network, id)): Path<(NetworkId, u32)>, Body(input): Body<UpdateProxy>) -> Reply {
    ok(&app, move |controller| controller.update_proxy(network, id, input)).await
}

async fn delete_proxy(State(app): State<App>, Path((network, id)): Path<(NetworkId, u32)>) -> Reply {
    deleted(&app, move |controller| controller.delete_proxy(network, id)).await
}

async fn list_forwards(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.forwards(network)).await
}

async fn create_forward(State(app): State<App>, Path(network): Path<NetworkId>, Body(input): Body<ForwardInput>) -> Reply {
    created(&app, move |controller| controller.create_forward(network, input)).await
}

async fn replace_forward(State(app): State<App>, Path((network, id)): Path<(NetworkId, u32)>, Body(input): Body<ForwardInput>) -> Reply {
    ok(&app, move |controller| controller.replace_forward(network, id, input)).await
}

async fn delete_forward(State(app): State<App>, Path((network, id)): Path<(NetworkId, u32)>) -> Reply {
    deleted(&app, move |controller| controller.delete_forward(network, id)).await
}

async fn list_pairs(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.pairs(network)).await
}

async fn get_pair(State(app): State<App>, Path((network, a, b)): Path<(NetworkId, NodeId, NodeId)>) -> Reply {
    ok(&app, move |controller| controller.pair(network, a, b)).await
}

async fn set_pair(State(app): State<App>, Path((network, a, b)): Path<(NetworkId, NodeId, NodeId)>, Body(input): Body<PairInput>) -> Reply {
    ok(&app, move |controller| controller.set_pair(network, a, b, input)).await
}

async fn delete_pair(State(app): State<App>, Path((network, a, b)): Path<(NetworkId, NodeId, NodeId)>) -> Reply {
    deleted(&app, move |controller| controller.delete_pair(network, a, b)).await
}

async fn access_graph(State(app): State<App>, Path(network): Path<NetworkId>) -> Reply {
    ok(&app, move |controller| controller.access_graph(network)).await
}

async fn access_check(State(app): State<App>, Path(network): Path<NetworkId>, Query(query): Query<CheckQuery>) -> Reply {
    ok(&app, move |controller| controller.access_check(network, query.from, query.to)).await
}
