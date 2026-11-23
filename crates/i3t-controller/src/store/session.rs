//! 和 PostgreSQL 的一条连接，同步地用。
//!
//! `tokio-postgres` 把一条连接拆成两半：发请求的 `Client`，和读写套接字的 `Connection`。后一半要有人一直驱动，
//! 这里给它一条自己的线程和一个只有这一条线程的运行时。前一半的每个请求只是往后一半的队列里放消息、等回音，
//! 用不到运行时，所以 [`wait`] 就在调用方的线程上等。
//!
//! 这样 [`Store`](super::Store) 的方法在哪里调用都行：普通线程、`spawn_blocking` 的线程，或者异步任务里
//! （和读写本地文件一样，会占住那条线程一小会儿）。
//!
//! 丢掉 [`Session`] 就是关连接：`Client` 没了，`Connection` 随之结束，那条线程跟着退出。

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Duration;

use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Config, NoTls, Row, Statement};

use super::StoreError;

/// 一条语句的参数，按 `$1`、`$2` 的顺序。
pub(super) type Params<'a> = &'a [&'a (dyn ToSql + Sync)];

/// 别的连接占着一张表或者一行的锁时（有人在库里开着事务改数据、锁了表），一条语句最多等这么久，过了就失败。
/// PostgreSQL 默认一直等下去，而等的时候 controller 的锁是拿着的：没有这个期限，一把忘了放的锁就能把 controller 卡死。
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct Session {
    client: Client,
    /// 准备好的语句，按 SQL 的文字找：同一句话从第二次起只要一次往返。
    /// 这里的 SQL 都是代码里写死的，句数有限，所以不用淘汰。
    statements: RefCell<HashMap<String, Statement>>,
}

impl Session {
    /// 连上数据库。连不上、密码不对之类的错在这里报出来。
    pub(super) fn connect(config: &Config) -> Result<Self, StoreError> {
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
                match config.connect(NoTls).await {
                    Ok((client, connection)) => {
                        // 等的人已经不在了的话，`client` 随着这次发送失败被丢掉，连接不用留。
                        if sender.send(Ok(client)).is_err() {
                            return;
                        }
                        if let Err(error) = connection.await {
                            tracing::warn!(%error, "和数据库的连接断了");
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(StoreError::Connect(error)));
                    }
                }
            });
        };
        thread::Builder::new().name("i3t-postgres".to_owned()).spawn(drive).map_err(StoreError::Driver)?;
        let client = receiver.recv().map_err(|_| StoreError::Driver(io::Error::other("照看数据库连接的线程没有回音就退出了")))??;
        let session = Self { client, statements: RefCell::default() };
        session.set_lock_timeout(LOCK_TIMEOUT).map_err(StoreError::Connect)?;
        Ok(session)
    }

    /// 等别的连接放开锁最多等多久，过了就让那条语句失败（见 [`LOCK_TIMEOUT`]）。
    pub(super) fn set_lock_timeout(&self, timeout: Duration) -> Result<(), tokio_postgres::Error> {
        self.batch(&format!("SET lock_timeout = {}", timeout.as_millis()))
    }

    /// 连接已经断了：之后的请求都会失败，要换一条新的。
    pub(super) fn is_closed(&self) -> bool {
        self.client.is_closed()
    }

    fn statement(&self, sql: &str) -> Result<Statement, tokio_postgres::Error> {
        if let Some(statement) = self.statements.borrow().get(sql) {
            return Ok(statement.clone());
        }
        let statement = wait(self.client.prepare(sql))?;
        self.statements.borrow_mut().insert(sql.to_owned(), statement.clone());
        Ok(statement)
    }

    /// 执行一条语句，返回它改了几行。
    pub(super) fn execute(&self, sql: &str, params: Params<'_>) -> Result<u64, tokio_postgres::Error> {
        let statement = self.statement(sql)?;
        wait(self.client.execute(&statement, params))
    }

    pub(super) fn query(&self, sql: &str, params: Params<'_>) -> Result<Vec<Row>, tokio_postgres::Error> {
        let statement = self.statement(sql)?;
        wait(self.client.query(&statement, params))
    }

    /// 最多一行的查询。
    pub(super) fn query_opt(&self, sql: &str, params: Params<'_>) -> Result<Option<Row>, tokio_postgres::Error> {
        let statement = self.statement(sql)?;
        wait(self.client.query_opt(&statement, params))
    }

    /// 正好一行的查询。
    pub(super) fn query_one(&self, sql: &str, params: Params<'_>) -> Result<Row, tokio_postgres::Error> {
        let statement = self.statement(sql)?;
        wait(self.client.query_one(&statement, params))
    }

    /// 不带参数地执行一段 SQL，可以是用分号隔开的好几条。
    pub(super) fn batch(&self, sql: &str) -> Result<(), tokio_postgres::Error> {
        wait(self.client.batch_execute(sql))
    }
}

/// 在当前线程上等一个不需要运行时的 future：没有结果就睡，被叫醒了再问。
fn wait<F: Future>(future: F) -> F::Output {
    struct Unpark(Thread);

    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        // `park` 可以无故返回，也可能是别处留下的一次叫醒：所以每次醒来都回去再问一遍。
        thread::park();
    }
}
