//! 和 PostgreSQL 的一条连接，同步地用。
//!
//! `tokio-postgres` 把一条连接拆成两半：发请求的 `Client`，和读写套接字的 `Connection`。后一半要有人一直驱动，
//! 这里给它一条自己的线程和一个只有这一条线程的运行时。前一半的每个请求只是往后一半的队列里放消息、等回音，
//! 用不到运行时，所以 [`wait`] 就在调用方的线程上等。
//!
//! 这样 [`Store`](super::Store) 的方法在哪里调用都行：普通线程、`spawn_blocking` 的线程，或者异步任务里
//! （和读写本地文件一样，会占住那条线程一小会儿）。
//!
//! 等都有期限：连不上（包括连上了端口、对面却不答话）等到 [`connect_limit`]，一条语句等回答等到
//! [`RESPONSE_TIMEOUT`]。调用方是拿着 controller 的锁在等的，没有期限的话，一个不答话的数据库就能把它卡死。
//!
//! 丢掉 [`Session`] 就是关连接：`Client` 没了，`Connection` 随之结束，那条线程跟着退出。

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::{Duration, Instant};

use tokio_postgres::error::Severity;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Config, NoTls, Row, Statement};

use super::StoreError;

/// 一条语句的参数，按 `$1`、`$2` 的顺序。
pub(super) type Params<'a> = &'a [&'a (dyn ToSql + Sync)];

/// 一条语句发出去之后等回答最多等这么久。平时的语句都是毫秒级的，等锁也有它自己更短的期限
/// （[`LOCK_TIMEOUT`](super::LOCK_TIMEOUT)）：等到这么久只会是数据库或者中间的网络不答话了。
/// 过了就当这条连接坏了，换一条新的。
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// 连接串里没有写超时的话，连一个地址最多等这么久。
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 等驱动线程交回连接比 [`connect_limit`] 多等的一点：正常情况下它自己会在期限到时说没连上。
const HANDOVER_MARGIN: Duration = Duration::from_secs(5);

/// 整个建连最多花多久：找地址、连上、认证，都算在里面。`tokio-postgres` 自己的 `connect_timeout` 只管连上端口
/// 那一步，对面接了连接却不答话时它一直等。连接串里写了几个主机就给几份。
pub(super) fn connect_limit(config: &Config) -> Duration {
    let each = config.get_connect_timeout().copied().unwrap_or(CONNECT_TIMEOUT);
    let hosts = u32::try_from(config.get_hosts().len()).unwrap_or(u32::MAX).max(1);
    each.saturating_mul(hosts)
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
}

impl Session {
    /// 连上数据库。连不上、密码不对之类的错在这里报出来。
    pub(super) fn connect(config: &Config) -> Result<Self, StoreError> {
        let limit = connect_limit(config);
        let (sender, receiver) = mpsc::channel();
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
                        if let Err(error) = connection.await {
                            tracing::warn!(%error, "和数据库的连接断了");
                        }
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
                return Err(StoreError::Driver(io::Error::other("照看数据库连接的线程没有回音就退出了")));
            }
        };
        Ok(Self { client, statements: RefCell::default(), broken: Cell::new(false), response_timeout: Cell::new(RESPONSE_TIMEOUT) })
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
            // 请求发到一半就不等了，这条连接上的对话已经对不上：只能换一条。
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
