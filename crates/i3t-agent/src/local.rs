//! 节点在本机开的两个小接口，都只绑回环地址：
//!
//! - **指标**：`http://<配置里的地址>/metrics`，Prometheus 的文本格式，不带认证。里面只有计数和对端的名字，
//!   没有密钥、令牌和目标地址。地址在 `config.toml` 的 `[metrics]` 里，写 `"off"` 就不开。
//! - **本机状态**：`i3t status` 和 `i3t routes` 向正在运行的节点问现在的状态，`i3t ping` 让它量到另一个节点的往返
//!   （`/ping?peer=…&count=…`）。它在一个系统挑的回环端口上，每个请求都要带令牌。
//!
//! 本机状态接口采用“回环端口 + 随机令牌”设计：本机任意用户均可连接回环地址，仅靠绑定回环无法隔离其他用户。
//! 因此节点每次启动时生成随机令牌，与端口一并写入状态目录中的 `local.json`。状态目录仅属主可访问
//! （节点私钥也存于此处），因此只有有权读取私钥的用户（运行节点的用户与 root）才能查询状态。
//! 未使用 Unix 域套接字，是为了让 Linux、Windows、macOS 复用同一套实现。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::http::{self, Request, Response};
use crate::metrics;
use crate::ping::{self, PingReport};
use crate::runtime::Runtime;
use crate::state::{LocalEndpoint, StateDir};
use crate::status::LiveStatus;

const STATUS_PATH: &str = "/status";
const PING_PATH: &str = "/ping";
const METRICS_PATH: &str = "/metrics";
/// Prometheus 的文本格式。
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// 开着的本机接口。丢弃它就关掉，并删掉 `local.json`。
pub(crate) struct LocalServers {
    state: StateDir,
    tasks: Vec<JoinHandle<()>>,
}

impl LocalServers {
    /// 启动本机状态接口，以及（若配置未关闭）指标接口。
    ///
    /// 两个接口均非节点运行所必需：启动失败仅记录日志，节点继续运行。
    pub(crate) async fn start(runtime: &Arc<Runtime>, state: &StateDir, metrics_at: Option<SocketAddr>) -> Self {
        let mut tasks = Vec::new();
        match start_status(runtime, state).await {
            Ok(task) => tasks.push(task),
            Err(error) => tracing::warn!("本机状态接口启动失败，i3t status 和 i3t routes 将无法查询运行状态：{error:#}"),
        }
        if let Some(addr) = metrics_at {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!(%addr, "指标接口已启动：http://{addr}{METRICS_PATH}");
                    let runtime = Arc::clone(runtime);
                    tasks.push(tokio::spawn(http::serve(listener, move |request| {
                        let response = respond_metrics(&runtime, &request);
                        async move { response }
                    })));
                }
                Err(error) => {
                    tracing::warn!(%addr, %error, "指标接口启动失败（如端口已被占用，可在 config.toml 的 [metrics] 中更换地址或设为 \"off\"）")
                }
            }
        }
        Self { state: state.clone(), tasks }
    }
}

impl Drop for LocalServers {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        if let Err(error) = self.state.remove_local() {
            tracing::debug!("删除本机状态接口记录失败：{error:#}");
        }
    }
}

async fn start_status(runtime: &Arc<Runtime>, state: &StateDir) -> anyhow::Result<JoinHandle<()>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.context("在回环地址上绑定一个端口")?;
    let addr = listener.local_addr().context("查询绑定到的端口")?;
    let token: String = rand::random::<[u8; 24]>().iter().map(|byte| format!("{byte:02x}")).collect();
    state.save_local(&LocalEndpoint { addr, token: token.clone() })?;
    let runtime = Arc::clone(runtime);
    let token: Arc<str> = token.into();
    Ok(tokio::spawn(http::serve(listener, move |request| {
        let (runtime, token) = (Arc::clone(&runtime), Arc::clone(&token));
        async move { respond_status(&runtime, &token, &request).await }
    })))
}

async fn respond_status(runtime: &Runtime, token: &str, request: &Request) -> Response {
    if !request.bearer.as_deref().is_some_and(|presented| same(presented, token)) {
        tracing::warn!(path = %request.path, "已拒绝本机状态接口请求：缺少令牌或令牌无效");
        return Response::error(401, "需要提供状态目录中 local.json 记录的令牌");
    }
    let body = match request.path.as_str() {
        STATUS_PATH => serde_json::to_string(&LiveStatus::of(runtime)),
        PING_PATH => {
            let Some((peer, count)) = ping_query(&request.query) else {
                return Response::error(400, "参数错误：需要 peer=<节点>，可选 count=<次数>");
            };
            serde_json::to_string(&ping::ping(runtime, &peer, count).await)
        }
        _ => return Response::error(404, "未找到请求的路径"),
    };
    match body {
        Ok(body) => Response::ok("application/json", body),
        Err(error) => Response::error(500, &format!("响应序列化为 JSON 失败：{error}")),
    }
}

/// `/ping` 的查询串：`peer=<节点>&count=<次数>`。节点只能是名字、全名或者虚拟 IP 用到的字符，不用解码。
fn ping_query(query: &str) -> Option<(String, u32)> {
    let mut peer = None;
    let mut count = ping::DEFAULT_COUNT;
    for pair in query.split('&') {
        match pair.split_once('=')? {
            ("peer", value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)) => {
                peer = Some(value.to_owned());
            }
            ("count", value) => count = value.parse().ok()?,
            _ => return None,
        }
    }
    Some((peer?, count))
}

fn respond_metrics(runtime: &Runtime, request: &Request) -> Response {
    match request.path.as_str() {
        METRICS_PATH => Response::ok(METRICS_CONTENT_TYPE, metrics::render(runtime)),
        _ => Response::error(404, "指标在 /metrics"),
    }
}

/// 比较两个令牌，花的时间不随第一个不同的位置变化。
fn same(presented: &str, expected: &str) -> bool {
    presented.len() == expected.len() && presented.bytes().zip(expected.bytes()).fold(0, |diff, (a, b)| diff | (a ^ b)) == 0
}

/// 让正在运行的节点在到 `peer` 的连接上量 `count` 个往返（`i3t ping`）。没有节点在运行时返回 `None`。
///
/// # Errors
///
/// 无法读取 `local.json`、节点返回无法解析的应答，或 `peer` 包含节点名与地址中不允许的字符。
pub async fn ping(state: &StateDir, peer: &str, count: u32) -> anyhow::Result<Option<PingReport>> {
    let Some(local) = state.local()? else { return Ok(None) };
    if peer.is_empty() || !peer.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)) {
        return Err(anyhow!((crate::texts::texts().bad_peer)(peer)));
    }
    let path = format!("{PING_PATH}?peer={peer}&count={count}");
    let body = match http::get(local.addr, &path, Some(&local.token)).await {
        Ok(body) => body,
        Err(error) if refused(&error) => return Ok(None),
        Err(error) => return Err(anyhow!((crate::texts::texts().query_running)(&format!("{error:#}")))),
    };
    serde_json::from_str(&body).map(Some).context(crate::texts::texts().status_unreadable)
}

/// 记录文件仍存在但端口无法连接：通常是节点被异常终止，未能清理记录。
fn refused(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused))
}

/// 查询正在运行节点的状态。无节点运行时返回 `None`。
///
/// # Errors
///
/// 无法读取 `local.json`，或节点正在运行但返回了无法解析的应答。
pub async fn query(state: &StateDir) -> anyhow::Result<Option<LiveStatus>> {
    let Some(local) = state.local()? else { return Ok(None) };
    let body = match http::get(local.addr, STATUS_PATH, Some(&local.token)).await {
        Ok(body) => body,
        Err(error) => {
            return if refused(&error) { Ok(None) } else { Err(anyhow!((crate::texts::texts().query_running)(&format!("{error:#}")))) };
        }
    };
    serde_json::from_str(&body).map(Some).context(crate::texts::texts().status_unreadable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_must_match_exactly() {
        assert!(same("abc123", "abc123"));
        assert!(!same("abc124", "abc123") && !same("abc12", "abc123") && !same("", "abc123"));
    }

    #[tokio::test]
    async fn no_record_or_a_stale_record_means_no_node_is_running() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path()).unwrap();
        assert_eq!(query(&state).await.unwrap(), None);
        // 被杀掉的节点留下的记录：端口上已经没有人了。
        let gone = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        state.save_local(&LocalEndpoint { addr: gone, token: "t".to_owned() }).unwrap();
        assert_eq!(query(&state).await.unwrap(), None);
    }
}
