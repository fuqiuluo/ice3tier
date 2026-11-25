//! 管理 API 的 HTTP 服务端：接受连接，把请求交给 [`crate::admin::router`]。
//!
//! 不用 `axum::serve`，因为它既不能给读请求头设时限，也不限制连接数。管理 API 默认只听回环地址，但管理员可以把它
//! 放到别的地址上，那时任何人都能连上来。不带令牌的请求马上就被拒绝；不要令牌的 `/metrics` 同一时刻只计算一次，
//! 不随请求数累积（见 `admin::Metrics`）。能占着资源不放的因此只有连接本身，所以：
//!
//! - 连接按来源地址记账，满了挤掉最老的，不拒绝新来的（[`crate::gate`]）；
//! - 请求头要在 [`HEADER_TIMEOUT`] 之内读完。连接空着等下一个请求时也在计时，所以不发请求的连接会被关掉；
//! - 请求体由 axum 的 `Json` 限制在 2 MB 以内，并且要先过了令牌的检查才会去读。

use std::net::SocketAddr;
use std::pin::pin;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tower::ServiceExt;

use crate::gate::{Gate, Limits, Pass, Throttle};

/// 每个来源最多 32 条连接，全部最多 128 条。浏览器对一个地址最多开六条左右，`i3tctl` 一次一条；
/// 管理 API 在回环地址上时所有本机程序都是同一个来源。
const LIMITS: Limits = Limits { per_source: 32, total: 128 };
/// 请求头要在这么久之内读完，空闲的连接也在这么久之后关掉。
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// 关闭时最多等手上的请求答完这么久。
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// 接受连接失败的日志多久最多记一条。
const ACCEPT_ERROR_LOG_EVERY: Duration = Duration::from_secs(10);

/// 在 `listener` 上服务管理 API，直到 `shutdown` 变化。之后不再接新的连接，手上的请求答完（最多等 [`SHUTDOWN_GRACE`]）再返回。
pub(crate) async fn serve(listener: TcpListener, router: Router, mut shutdown: watch::Receiver<bool>) {
    let gate = Gate::new("管理 API 的连接", LIMITS);
    let accept_errors = Throttle::new(ACCEPT_ERROR_LOG_EVERY);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = i3t_underlay::tcp_mss::accept(&listener) => match accepted {
                Ok((stream, remote)) => {
                    let pass = gate.admit(remote.ip());
                    connections.spawn(serve_connection(stream, remote, router.clone(), pass, shutdown.clone()));
                }
                Err(err) => {
                    // 通常由文件描述符耗尽导致。短暂休眠后再继续接受连接，避免空转。
                    if let Some(suppressed) = accept_errors.allow() {
                        tracing::warn!(suppressed, "管理 API 接受连接失败：{err}");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            _ = shutdown.changed() => break,
        }
    }
    drop(listener);
    // 每条连接自己也在看 shutdown：答完手上的请求就关。
    if timeout(SHUTDOWN_GRACE, async { while connections.join_next().await.is_some() {} }).await.is_err() {
        tracing::warn!("部分管理 API 连接未在 {SHUTDOWN_GRACE:?} 内结束，放弃等待");
    }
}

async fn serve_connection(stream: TcpStream, remote: SocketAddr, router: Router, mut pass: Pass, mut shutdown: watch::Receiver<bool>) {
    let service = service_fn(move |mut request: hyper::Request<Incoming>| {
        // 处理函数里按来源地址记日志。
        request.extensions_mut().insert(ConnectInfo(remote));
        router.clone().oneshot(request)
    });
    let mut connection = pin!(
        http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT).serve_connection(TokioIo::new(stream), service)
    );
    let mut closing = false;
    loop {
        tokio::select! {
            outcome = connection.as_mut() => {
                if let Err(err) = outcome {
                    tracing::debug!(%remote, "管理 API 的连接出错结束：{err}");
                }
                return;
            }
            () = pass.evicted() => {
                tracing::debug!(%remote, "管理 API 连接数已达上限，当前连接被淘汰");
                return;
            }
            _ = shutdown.changed(), if !closing => {
                closing = true;
                connection.as_mut().graceful_shutdown();
            }
        }
    }
}
