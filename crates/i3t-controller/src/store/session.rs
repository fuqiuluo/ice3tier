//! 和 PostgreSQL 的一条连接，同步地用。
//!
//! `tokio-postgres` 把一条连接拆成两半：发请求的 `Client`，和读写套接字的 `Connection`。后一半要有人一直驱动，
//! 这里给它一条自己的线程和一个只有这一条线程的运行时。前一半的每个请求只是往后一半的队列里放消息、等回音，
//! 用不到运行时，所以 [`wait`] 就在调用方的线程上等。
//!
//! 这样 [`Store`](super::Store) 的方法在哪里调用都行：普通线程、`spawn_blocking` 的线程，或者异步任务里
//! （和读写本地文件一样，会占住那条线程一小会儿）。
//!
//! 所有等待均有超时限制：建连超时（包括端口已连上但对端无响应）上限为 [`connect_limit`]，单条语句等待响应的上限为
//! [`RESPONSE_TIMEOUT`]。调用方持有 controller 锁进行等待，若无超时限制，无响应的数据库会导致整个 controller 阻塞。
//!
//! 丢弃 [`Session`] 即关闭连接：`Client` 释放后，`Connection` 向数据库发送终止消息并结束，驱动线程随之退出。
//! 即使仍有请求尚未收到响应也可关闭连接，只是不再继续等待该响应（见 [`drive`]）。

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tokio_postgres::error::Severity;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Config, NoTls, Row, Statement};

use super::StoreError;

/// 一条语句的参数，按 `$1`、`$2` 的顺序。
pub(super) type Params<'a> = &'a [&'a (dyn ToSql + Sync)];

/// 单条语句发出后等待响应的超时上限。常规语句耗时在毫秒级，等锁也有更短的独立超时
/// （[`LOCK_TIMEOUT`](super::LOCK_TIMEOUT)）；等待至此时长只可能是数据库或中间网络无响应。
/// 超时后视为该连接已失效，后续将建立新连接替换。
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// 连接串未指定超时时，连接单个地址的默认超时时长。
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 等待驱动线程交回连接时在 [`connect_limit`] 基础上额外预留的余量：正常情况下驱动线程会在超时到达时自行报告连接失败。
const HANDOVER_MARGIN: Duration = Duration::from_secs(5);

/// [`Session`] 被丢弃后，连接向数据库发送终止消息并优雅关闭的最长等待时间。正常情况下可瞬间完成。
const GOODBYE: Duration = Duration::from_secs(1);

/// 整个建连流程的总超时上限：包含地址解析、建连与认证。`tokio-postgres` 自带的 `connect_timeout` 仅覆盖端口连接
/// 阶段，对端接受连接却无响应时会持续阻塞。连接串中指定了几个主机便分配几份配额；主机可通过主机名（`host`）、
/// IP 地址（`hostaddr`）或两者同时指定，主机数取两者中的较大值。
pub(super) fn connect_limit(config: &Config) -> Duration {
    let each = config.get_connect_timeout().copied().unwrap_or(CONNECT_TIMEOUT);
    let hosts = config.get_hosts().len().max(config.get_hostaddrs().len());
    each.saturating_mul(u32::try_from(hosts).unwrap_or(u32::MAX).max(1))
}

pub(super) struct Session {
    client: Client,
    /// 准备好的语句，按 SQL 的文字找：同一句话从第二次起只要一次往返。
    /// 这里的 SQL 都是代码里写死的，句数有限，所以不用淘汰。
    statements: RefCell<HashMap<String, Statement>>,
    /// 这条连接不能再用了：数据库说它结束了，读写它出了错，或者等回答等过了头。
    /// `Client` 自己要等驱动线程退出才知道连接断了，中间那一小会儿发出去的请求只会白白失败。
    broken: Cell<bool>,
    response_timeout: Cell<Duration>,
    /// 不往里放东西：这一头和 `Session` 一起没了，驱动线程由此知道这条连接没人用了（见 [`drive`]）。
    _in_use: oneshot::Sender<Infallible>,
}

impl Session {
    /// 连接数据库。连接失败、认证失败等错误均在此处返回。
    pub(super) fn connect(config: &Config) -> Result<Self, StoreError> {
        let limit = connect_limit(config);
        let (sender, receiver) = mpsc::channel();
        let (in_use, dropped) = oneshot::channel();
        let config = config.clone();
        let drive = move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = sender.send(Err(StoreError::Driver(error)));
                    return;
                }
            };
            runtime.block_on(async move {
                // 到了期限就丢掉这次建连：套接字随之关掉，这条线程退出。
                match tokio::time::timeout(limit, config.connect(NoTls)).await {
                    Ok(Ok((client, connection))) => {
                        // 等的人已经不在了的话，`client` 随着这次发送失败被丢掉，连接不用留。
                        if sender.send(Ok(client)).is_err() {
                            return;
                        }
                        drive(connection, dropped).await;
                    }
                    Ok(Err(error)) => {
                        let _ = sender.send(Err(StoreError::Connect(error)));
                    }
                    Err(_) => {
                        let _ = sender.send(Err(StoreError::ConnectTimedOut(limit)));
                    }
                }
            });
        };
        thread::Builder::new().name("i3t-postgres".to_owned()).spawn(drive).map_err(StoreError::Driver)?;
        let client = match receiver.recv_timeout(limit.saturating_add(HANDOVER_MARGIN)) {
            Ok(client) => client?,
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(StoreError::ConnectTimedOut(limit)),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(StoreError::Driver(io::Error::other("数据库驱动线程异常退出，未返回连接结果")));
            }
        };
        Ok(Self {
            client,
            statements: RefCell::default(),
            broken: Cell::new(false),
            response_timeout: Cell::new(RESPONSE_TIMEOUT),
            _in_use: in_use,
        })
    }

    /// 连接已经不能用了：之后的请求都会失败，要换一条新的。
    pub(super) fn is_closed(&self) -> bool {
        self.broken.get() || self.client.is_closed()
    }

    /// 测试用：等回答只等这么久。
    #[cfg(test)]
    pub(super) fn set_response_timeout(&self, timeout: Duration) {
        self.response_timeout.set(timeout);
    }

    /// 等一个请求的回答。等过了头、或者这次失败说明连接完了，就记下这条连接不能再用。
    fn finish<T>(&self, request: impl Future<Output = Result<T, tokio_postgres::Error>>) -> Result<T, StoreError> {
        // 已经知道连接不在了：不发，这一次确定没有做。
        if self.is_closed() {
            self.broken.set(true);
            return Err(StoreError::Disconnected);
        }
        let limit = self.response_timeout.get();
        match wait(request, limit) {
            Some(Ok(value)) => Ok(value),
            Some(Err(error)) => {
                if ends_connection(&error) {
                    self.broken.set(true);
                }
                Err(StoreError::Postgres(error))
            }
            // 请求中途放弃等待，该连接上的协议状态已无法同步，只能新建连接替换。
            None => {
                self.broken.set(true);
                Err(StoreError::Unresponsive(limit))
            }
        }
    }

    fn statement(&self, sql: &str) -> Result<Statement, StoreError> {
        if let Some(statement) = self.statements.borrow().get(sql) {
            return Ok(statement.clone());
        }
        let statement = self.finish(self.client.prepare(sql))?;
        self.statements.borrow_mut().insert(sql.to_owned(), statement.clone());
        Ok(statement)
    }

    /// 执行一条语句，返回它改了几行。
    pub(super) fn execute(&self, sql: &str, params: Params<'_>) -> Result<u64, StoreError> {
        let statement = self.statement(sql)?;
        self.finish(self.client.execute(&statement, params))
    }

    pub(super) fn query(&self, sql: &str, params: Params<'_>) -> Result<Vec<Row>, StoreError> {
        let statement = self.statement(sql)?;
        self.finish(self.client.query(&statement, params))
    }

    /// 最多一行的查询。
    pub(super) fn query_opt(&self, sql: &str, params: Params<'_>) -> Result<Option<Row>, StoreError> {
        let statement = self.statement(sql)?;
        self.finish(self.client.query_opt(&statement, params))
    }

    /// 正好一行的查询。
    pub(super) fn query_one(&self, sql: &str, params: Params<'_>) -> Result<Row, StoreError> {
        let statement = self.statement(sql)?;
        self.finish(self.client.query_one(&statement, params))
    }

    /// 不带参数地执行一段 SQL，可以是用分号隔开的好几条。
    pub(super) fn batch(&self, sql: &str) -> Result<(), StoreError> {
        self.finish(self.client.batch_execute(sql))
    }

    /// 等别的连接放开锁最多等多久，过了就让那条语句失败。
    pub(super) fn set_lock_timeout(&self, timeout: Duration) -> Result<(), StoreError> {
        self.batch(&format!("SET lock_timeout = {}", timeout.as_millis().max(1)))
    }
}

/// 照看一条连接（读写它的套接字），到它结束为止。
///
/// 正常情况下，当 `Client` 被丢弃后，连接会向数据库发送终止消息并自行结束；但若仍有请求未收到响应，连接会持续等待。
/// 若数据库无响应（[`Session`] 正是因此被丢弃），连接将长期保持套接字打开，数据库侧未完成的事务及其持有的锁也会随之滞留。
/// 因此在 `Session` 被丢弃后仅额外等待 [`GOODBYE`]，超时即丢弃连接以关闭套接字，促使数据库感知对端断开。
async fn drive(connection: impl Future<Output = Result<(), tokio_postgres::Error>>, dropped: oneshot::Receiver<Infallible>) {
    let mut connection = pin!(connection);
    let ended = tokio::select! {
        ended = &mut connection => Some(ended),
        // 那一头不放东西，这里等到的只会是它没了。
        _ = dropped => tokio::time::timeout(GOODBYE, &mut connection).await.ok(),
    };
    match ended {
        Some(Ok(())) => {}
        Some(Err(error)) => tracing::warn!(%error, "数据库连接已断开"),
        None => tracing::warn!("数据库长期无响应，放弃等待并关闭连接"),
    }
}

/// 这次失败之后连接是不是完了：已经断了，读写套接字出了错，或者数据库说了 FATAL（它说完就会关掉这条连接）。
fn ends_connection(error: &tokio_postgres::Error) -> bool {
    error.is_closed()
        || std::error::Error::source(error).is_some_and(|source| source.is::<io::Error>())
        || error.as_db_error().and_then(|error| error.parsed_severity()).is_some_and(|it| matches!(it, Severity::Fatal | Severity::Panic))
}

/// 在当前线程上等一个不需要运行时的 future：没有结果就睡，被叫醒了再问。等了 `limit` 还没有结果时返回 `None`。
fn wait<F: Future>(future: F, limit: Duration) -> Option<F::Output> {
    struct Unpark(Thread);

    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    let deadline = Instant::now() + limit;
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return Some(output);
        }
        let left = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())?;
        // `park_timeout` 可以无故返回，也可能是别处留下的一次叫醒：所以每次醒来都回去再问一遍。
        thread::park_timeout(left);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread::JoinHandle;

    use super::*;

    /// "再见"这条消息。
    const TERMINATE: &[u8] = b"X\0\0\0\x04";

    /// 只会打招呼的"数据库"：连接建得起来，之后发什么都不答。
    /// 返回的线程读到对面关了连接才结束，交出打完招呼之后收到的全部字节。
    fn server_that_only_greets() -> (Config, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = Config::new();
        config.host("127.0.0.1").port(listener.local_addr().unwrap().port()).user("i3t").dbname("i3t");
        let serve = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut chunk = [0; 1024];
            assert!(stream.read(&mut chunk).unwrap() > 0, "启动消息");
            // "认证通过"，"可以发语句了"。
            stream.write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I").unwrap();
            let mut received = Vec::new();
            while let Ok(read @ 1..) = stream.read(&mut chunk) {
                received.extend_from_slice(&chunk[..read]);
            }
            received
        });
        (config, serve)
    }

    #[test]
    fn dropping_an_idle_connection_says_goodbye() {
        let (config, server) = server_that_only_greets();
        drop(Session::connect(&config).unwrap());
        assert_eq!(server.join().unwrap(), TERMINATE);
    }

    #[test]
    fn dropping_a_connection_closes_it_even_when_a_statement_was_never_answered() {
        let (config, server) = server_that_only_greets();
        let session = Session::connect(&config).unwrap();
        session.set_response_timeout(Duration::from_millis(100));
        assert!(matches!(session.batch("SELECT 1"), Err(StoreError::Unresponsive(_))));
        assert!(session.is_closed());

        // 那个回答永远不会来，连接自己会一直等它。丢掉之后不能接着等：套接字得关上，对面才知道这边走了。
        let dropped = Instant::now();
        drop(session);
        while !server.is_finished() {
            assert!(dropped.elapsed() < Duration::from_secs(10), "连接还开着");
            thread::sleep(Duration::from_millis(20));
        }
        let received = server.join().unwrap();
        assert!(!received.is_empty() && !received.ends_with(TERMINATE), "语句发出去了，再见来不及说：{received:?}");
    }
}
