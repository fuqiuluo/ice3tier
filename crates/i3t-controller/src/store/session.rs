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
//! 丢掉 [`Session`] 就是关连接：`Client` 没了，`Connection` 向数据库说完再见就结束，那条线程跟着退出。
//! 有请求还没等到回答时也关得掉，只是不再等那个回答（见 [`drive`]）。

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

/// 一条语句发出去之后等回答最多等这么久。平时的语句都是毫秒级的，等锁也有它自己更短的期限
/// （[`LOCK_TIMEOUT`](super::LOCK_TIMEOUT)）：等到这么久只会是数据库或者中间的网络不答话了。
/// 过了就当这条连接坏了，换一条新的。
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// 连接串里没有写超时的话，连一个地址最多等这么久。
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 等驱动线程交回连接比 [`connect_limit`] 多等的一点：正常情况下它自己会在期限到时说没连上。
const HANDOVER_MARGIN: Duration = Duration::from_secs(5);

/// [`Session`] 被丢掉之后，连接向数据库说再见最多给这么久。平时那是一眨眼的事。
const GOODBYE: Duration = Duration::from_secs(1);

/// 整个建连最多花多久：找地址、连上、认证，都算在里面。`tokio-postgres` 自己的 `connect_timeout` 只管连上端口
/// 那一步，对面接了连接却不答话时它一直等。连接串里写了几个主机就给几份；主机可以写名字（`host`）、
/// 写地址（`hostaddr`）或者两样都写，个数是多的那一样。
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
    /// 连上数据库。连不上、密码不对之类的错在这里报出来。
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
                return Err(StoreError::Driver(io::Error::other("照看数据库连接的线程没有回音就退出了")));
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

/// 照看一条连接（读写它的套接字），到它结束为止。
///
/// 平时它是这样结束的：`Client` 被丢掉，连接向数据库说完再见，自己结束。但只要还有请求没等到回答，连接就接着等；
/// 数据库不答话（[`Session`] 正是因为这个才被丢掉的），它会一直等下去，套接字开着，数据库那边没做完的事务和它的锁也都留着。
/// 所以 `Session` 没了之后只再给它 [`GOODBYE`] 这么久，过了就把连接丢掉：套接字随之关上，数据库由此知道对面走了。
async fn drive(connection: impl Future<Output = Result<(), tokio_postgres::Error>>, dropped: oneshot::Receiver<Infallible>) {
    let mut connection = pin!(connection);
    let ended = tokio::select! {
        ended = &mut connection => Some(ended),
        // 那一头不放东西，这里等到的只会是它没了。
        _ = dropped => tokio::time::timeout(GOODBYE, &mut connection).await.ok(),
    };
    match ended {
        Some(Ok(())) => {}
        Some(Err(error)) => tracing::warn!(%error, "和数据库的连接断了"),
        None => tracing::warn!("数据库一直不回答，不等它了：直接关掉这条连接"),
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
