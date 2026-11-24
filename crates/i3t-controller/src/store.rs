//! 存储：一个 PostgreSQL 数据库。
//!
//! 别的模块只通过 [`Store`] 上的方法读写，看不到 SQL，所以以后要换存储只需要重写这个模块。
//! 这里不检查业务规则（名字合不合法、能力有没有声明），那是 [`crate::Controller`] 的事；
//! 表上的唯一约束和外键只是最后一道保险。
//!
//! 一个 [`Store`] 是一条连接，方法是同步的：发出一条语句，等到结果才返回（见 [`session`]）。
//! 表建在连接的 `search_path` 里排在最前面的那个 schema 里，默认就是 `public`；一个数据库给一个 controller 用。
//!
//! # 等多久
//!
//! 调用方是拿着 controller 的锁调用这里的，所以每一种等都有期限：
//!
//! - 断线后的重连在后台进行（见下文「连接断了」），调用方最多等待 [`RECONNECT_WAIT`]，上一次重连失败后最多等待 [`RETRY_WAIT`]。
//!   建连本身受总超时限制（包括已连通端口但对端无响应）；刚重连失败后会在冷却期内跳过重连，期间读写立即失败
//!   （[`StoreError::Disconnected`]）。
//! - 一条语句等回答有期限，过了就当这条连接坏了。启动时执行的表结构迁移期限更长（[`MIGRATION_TIMEOUT`]）。
//! - 其他连接持有锁时（例如外部事务正在修改同一行或锁表），单条语句最多等待 [`LOCK_TIMEOUT`]。刚触发锁超时后，在随后的同等
//!   时长内不再等待：涉及被锁资源的语句立即失败，未受影响的资源仍正常写入。长期不释放的锁因此最多占用 controller 一半的等待时间，
//!   且不会阻塞其他行的操作。
//!
//! # 连接断了
//!
//! 连接断了（数据库重启、网络闪断）时，下一次读写会开始建立新连接。建连连同初始设置都在驱动线程上进行，不占用调用方：
//! 调用方（持有 controller 锁）只在建连开始后的一小段时间内等待结果（[`RECONNECT_WAIT`]，上一次重连失败后为 [`RETRY_WAIT`]），
//! 数据库可达时通常在此期间完成，读写照常进行；
//! 超出这段时间仍未连上则返回 [`StoreError::Reconnecting`]，建连继续在后台进行，此后的读写立即失败，直到建连有了结果。
//! 若在持锁期间同步等待建连（多主机时可达数十秒），会冻结整个 controller，使所有节点连接因长时间无法处理而被判定离线。
//! 断的那一刻正在做的读写报错。
//! 若断开发生在事务中，事务不会生效且数据库侧会自动回滚，仅有一种情况结果不确定：连接断在发出提交指令之后、收到响应之前。
//! 此时数据库可能已提交也可能未提交，此处返回 [`StoreError::CommitUnknown`]，调用方不可按未执行处理。
//! 最终提交结果可在后续查明：提交前已记录事务编号，待连接恢复后可向数据库查询确认（[`Store::settle_commits`]）。

mod codec;
mod cooldown;
#[cfg(test)]
pub(crate) mod fixtures;
mod forward;
mod group;
mod mcp;
mod network;
mod node;
mod oplog;
mod pair;
mod proxy;
mod rule;
mod schema;
#[cfg(any(test, feature = "testing"))]
mod scratch;
mod session;
mod stats;
mod switch;
mod test;
mod token;

use std::cell::{Cell, RefCell};
use std::fmt;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Config, Row};

pub use cooldown::CooldownKind;
pub use forward::ForwardRecord;
pub use group::{BUILTIN_GROUP, GroupRecord, folded};
pub use mcp::{McpTokenRecord, NewMcpToken, mcp_token_at};
pub use network::{NetworkRecord, NewNetwork};
pub use node::{NetmapState, NewNode, NodeRecord, ReachRecord};
pub use oplog::LogFilter;
pub(crate) use oplog::acting_as;
pub use pair::PairOptions;
pub use proxy::ProxyRecord;
#[cfg(any(test, feature = "testing"))]
pub use scratch::{Scratch, TEST_DATABASE_ENV};
pub use stats::StatPoint;
pub use switch::NewSwitch;
pub use test::KEEP_PER_PAIR;
pub use token::{NewToken, RETENTION_SECS, TokenRecord, is_pending, token_at};

use codec::{Int, Read};
use session::{CONNECT_TIMEOUT, Connecting, Params, Session, lock_timeout_sql};

/// SHA-256 的长度。令牌和 netmap 的摘要都是它。
pub const DIGEST_LEN: usize = 32;

/// 别的连接占着一张表或者一行的锁时，一条语句最多等这么久，过了就失败。PostgreSQL 默认一直等下去。
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// 刚等满过一次锁之后，"不等"的那段时间里用的期限：被占着的语句马上失败。不能是 0，0 是"一直等"。
const NO_LOCK_WAIT: Duration = Duration::from_millis(1);

/// 重连失败后的最小、最大退避间隔。具体时长取决于本次建连耗时：立即被拒绝的可较快重试，耗时触达超时的则退避更久，
/// 避免在数据库不可达期间反复建连。
const RECONNECT_PAUSE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(30));

/// 原本可用的连接断开后，一次后台重连开始后调用方合计最多等待多久。数据库可达时重连通常在毫秒级完成，此期间内完成则
/// 调用方无感知；超出后调用方立即返回，不再等待。调用方持有 controller 锁等待，因此需远短于节点的存活期限。
pub const RECONNECT_WAIT: Duration = Duration::from_secs(2);

/// 上一次重连失败后再次重连时，调用方合计最多等待多久。数据库此前就连不上，这一次多半也连不上，不值得持锁久等；
/// 数据库已经恢复时，重连通常也在此期间内完成。
pub const RETRY_WAIT: Duration = Duration::from_millis(500);

/// 连接串里没有另外写的话，连接闲着这么久就发 TCP 保活，发出去的数据这么久没人确认就当连接断了。
/// 数据库在别的机器上、中间的网络悄悄断掉时，靠它才不会一直等一个不会来的回答。
const DEAD_PEER_TIMEOUT: Duration = Duration::from_secs(30);

/// 连接串里没有另外写的话，保活的探测隔这么久发一次，连着这么多次没有回音就当连接断了：
/// 闲着的连接断了之后一分钟里发现，不靠系统的默认（Linux 上十几分钟）。
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_RETRIES: u32 = 3;

/// `tokio-postgres` 自己的保活间隔。连接串里没有改它的话，这里换成 [`DEAD_PEER_TIMEOUT`]。
const LIBRARY_KEEPALIVE_IDLE: Duration = Duration::from_secs(2 * 60 * 60);

/// 连到哪个 PostgreSQL 数据库。从连接串来，两种写法都认：
/// `postgres://用户:密码@主机:端口/库名`，或者 `host=… user=… dbname=…`（主机可以是放 Unix 套接字的目录）。
///
/// 不支持 TLS：数据库要和 controller 在同一台机器或者一个可信的内网里。连接串要求 TLS（`sslmode=require`）时
/// 不收，而不是悄悄不加密地连。
#[derive(Clone)]
pub struct Database(Config);

impl FromStr for Database {
    type Err = StoreError;

    fn from_str(text: &str) -> Result<Self, StoreError> {
        // 解析的错误里会带着连接串的片段（拼错了 `postgres://` 时是整个连接串，连密码在内），所以不留它的原话。
        let mut config: Config = text.trim().parse().map_err(|_| StoreError::BadConnectionString)?;
        // 空的连接串解析得过去，要到连的时候才说没有主机。主机可以只写地址（`hostaddr=…`）。
        if config.get_hosts().is_empty() && config.get_hostaddrs().is_empty() {
            return Err(StoreError::BadConnectionString);
        }
        if config.get_ssl_mode() == SslMode::Require {
            return Err(StoreError::TlsUnsupported);
        }
        if config.get_application_name().is_none() {
            config.application_name("i3t-controller");
        }
        if config.get_connect_timeout().is_none() {
            config.connect_timeout(CONNECT_TIMEOUT);
        }
        if config.get_keepalives_idle() == LIBRARY_KEEPALIVE_IDLE {
            config.keepalives_idle(DEAD_PEER_TIMEOUT);
        }
        if config.get_keepalives_interval().is_none() {
            config.keepalives_interval(KEEPALIVE_INTERVAL);
        }
        if config.get_keepalives_retries().is_none() {
            config.keepalives_retries(KEEPALIVE_RETRIES);
        }
        if config.get_tcp_user_timeout().is_none() {
            config.tcp_user_timeout(DEAD_PEER_TIMEOUT);
        }
        Ok(Self(config))
    }
}

/// 不带密码。
impl fmt::Debug for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database")
            .field("hosts", &self.0.get_hosts())
            .field("hostaddrs", &self.0.get_hostaddrs())
            .field("ports", &self.0.get_ports())
            .field("user", &self.0.get_user())
            .field("dbname", &self.0.get_dbname())
            .finish_non_exhaustive()
    }
}

/// 去问结果不明的提交（[`StoreError::CommitUnknown`]）后来怎么样了，问到的。没有这样的提交时两样都是 `false`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Settled {
    /// 这一次问出了结果的提交里有算了数的：数据库里已经是改过的样子。
    pub(crate) committed: bool,
    /// 还有数据库那边没做完的：还记着它们，过一会儿再问。
    pub(crate) pending: bool,
}

/// 事务进行到哪了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transaction {
    None,
    Open,
    /// 里面有一条语句失败了：PostgreSQL 从这时起拒绝这个事务里的一切，提交也只会变成撤销。
    Failed,
}

pub struct Store {
    database: Database,
    /// 当前活跃的连接。一旦检测到失效便立即丢弃并置空，而非等到下次建连才替换：丢弃会关闭套接字，促使数据库侧尽快回滚
    /// 未完成事务并释放持有的锁；若保留失效连接，在该 `Store` 空闲或持续无法重连期间，这些锁将被长期占用。
    session: RefCell<Option<Session>>,
    /// 正在后台进行的重连（见 [`Store::reconnect_if_closed`]），以及调用方为它合计最多等待多久。
    connecting: RefCell<Option<(Connecting, Duration)>>,
    transaction: Cell<Transaction>,
    /// 等锁平时肯等多久。
    lock_patience: Cell<Duration>,
    /// 刚等满过一次锁：到这个时刻之前不再等。
    impatient_until: Cell<Option<Instant>>,
    /// 连接上现在设的是不是"不等锁"。
    impatient: Cell<bool>,
    /// 刚试过没连上：到这个时刻之前不再去连。
    reconnect_after: Cell<Option<Instant>>,
    /// 提交发出去了、回答没有回来的事务的编号（[`StoreError::CommitUnknown`]）：还不知道它们后来算没算数。
    unsettled: RefCell<Vec<String>>,
    /// 出了上面这样的事务时叫醒谁，见 [`Store::wake_on_unsettled_commit`]。
    unsettled_wake: Option<Arc<Notify>>,
    /// 测试用：有几条语句是把等锁的期限等满了才失败的。
    #[cfg(test)]
    lock_waits: Cell<usize>,
    /// 测试用的数据库：和这个 `Store` 一起丢掉。写在 `session` 后面，先关连接再删。
    #[cfg(any(test, feature = "testing"))]
    scratch: Option<Scratch>,
}

impl Store {
    /// 连接数据库并将表结构迁移至当前版本；若为空库则初始化建表。
    ///
    /// # Errors
    ///
    /// 无法连接数据库，或数据库中的表结构由更新版本的程序创建。
    pub fn open(database: &Database) -> Result<Self, StoreError> {
        Self::prepare(database, schema::MIGRATIONS, Missing::Create)
    }

    /// 与 [`Store::open`] 相同，但当库中尚不存在 controller 数据表时不自动建表，而是返回 [`StoreError::Empty`]。
    ///
    /// # Errors
    ///
    /// 无法连接数据库、库为空，或库中的表结构由更新版本的程序创建。
    pub fn open_existing(database: &Database) -> Result<Self, StoreError> {
        Self::prepare(database, schema::MIGRATIONS, Missing::Refuse)
    }

    /// 一个空的数据库，只给这个 `Store` 用，丢掉时删除。测试用，要一个测试用的 PostgreSQL（见 [`Scratch`]）。
    ///
    /// # Panics
    ///
    /// 没有测试用的 PostgreSQL。
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn temporary() -> Self {
        let scratch = Scratch::new();
        let mut store = Self::open(&scratch.database()).expect("在测试用的数据库里建表");
        store.scratch = Some(scratch);
        store
    }

    fn prepare(database: &Database, migrations: &[&str], missing: Missing) -> Result<Self, StoreError> {
        let session = Session::connect(&database.0)?;
        session.set_lock_timeout(LOCK_TIMEOUT)?;
        migrate(&session, migrations, missing)?;
        Ok(Self {
            database: database.clone(),
            session: RefCell::new(Some(session)),
            connecting: RefCell::new(None),
            transaction: Cell::new(Transaction::None),
            lock_patience: Cell::new(LOCK_TIMEOUT),
            impatient_until: Cell::new(None),
            impatient: Cell::new(false),
            reconnect_after: Cell::new(None),
            unsettled: RefCell::default(),
            unsettled_wake: None,
            #[cfg(test)]
            lock_waits: Cell::new(0),
            #[cfg(any(test, feature = "testing"))]
            scratch: None,
        })
    }

    /// 表结构现在是第几版，也就是已经执行过几条迁移。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        self.query_one("SELECT version FROM schema_version", &[], |row| Ok(row.try_get::<_, Int<u32>>(0)?.0))
    }

    /// 把 `f` 里的读写放进一个事务：`f` 返回错误时全部撤销。
    ///
    /// 事务中某条语句失败后，该事务即不可再用（PostgreSQL 语义）：`f` 应将该错误向上返回。
    /// 若 `f` 吞掉错误并正常返回，此处返回 [`StoreError::Aborted`] 并回滚整个事务。
    ///
    /// 要求 `&mut self` 是为了在编译期避免事务嵌套。
    ///
    /// # Errors
    ///
    /// `f` 返回的错误，或开启、提交事务时的数据库错误。若提交请求已发出但未收到响应，则返回
    /// [`StoreError::CommitUnknown`]：此时无法立即确认该事务是否已提交。
    pub fn atomically<T, E: From<StoreError>>(&mut self, f: impl FnOnce(&Self) -> Result<T, E>) -> Result<T, E> {
        self.run(|session| session.batch("BEGIN"))?;
        self.transaction.set(Transaction::Open);
        let open = OpenTransaction(self);
        // `f` 出错或者恐慌时 `open` 在这里被丢弃，丢弃即撤销。
        let value = f(self)?;
        open.commit()?;
        Ok(value)
    }

    /// 有事务的提交结果不明时叫醒 `wake`：得有人回头来问它后来算没算数（[`Store::settle_commits`]），
    /// 而那一刻的调用方多半只是带着错误返回了。
    pub(crate) fn wake_on_unsettled_commit(&mut self, wake: Arc<Notify>) {
        self.unsettled_wake = Some(wake);
    }

    /// 向数据库查询先前提交结果未明的事务最终状态。已确定结果的事务会从记录中移除；数据库侧仍在执行中的保留至下次查询。
    ///
    /// # Errors
    ///
    /// 读取数据库失败。此时本次已查到的结果均不生效，所有待查事务保持原样，供后续重新查询。
    pub(crate) fn settle_commits(&self) -> Result<Settled, StoreError> {
        let transactions = self.unsettled.borrow().clone();
        let mut settled = Settled::default();
        let mut pending = Vec::new();
        for transaction in &transactions {
            let asked = self.query_one("SELECT pg_xact_status($1::text::xid8)", &[transaction], |row| row.try_get::<_, Option<String>>(0));
            let status = match asked {
                Ok(status) => status,
                // 数据库说这个编号它还没有用到：库换成了另一份。只有这一种错是"答不上来"；别的（数据库正在关、
                // 语句被取消、连接满了）是这一次没问成，事务可能还在做，不能就此忘了它。
                Err(StoreError::Postgres(error)) if error.code() == Some(&SqlState::INVALID_PARAMETER_VALUE) => None,
                Err(error) => return Err(error),
            };
            match status.as_deref() {
                Some("in progress") => pending.push(transaction),
                Some("aborted") => {}
                // 答不上来的（换了库，或者是太久以前的事务）：当它算了数，多核对一次没有坏处。
                Some(_) | None => settled.committed = true,
            }
        }
        settled.pending = !pending.is_empty();
        // 只去掉这一次问出了结果的：问的时候不在事务里，不会有新的加进来，可是不靠这个。
        self.unsettled.borrow_mut().retain(|transaction| pending.contains(&transaction) || !transactions.contains(transaction));
        Ok(settled)
    }

    /// 测试用：有没有提交的结果还不知道。
    #[cfg(test)]
    pub(crate) fn has_unsettled_commits(&self) -> bool {
        !self.unsettled.borrow().is_empty()
    }

    /// 测试用：让数据库只能读，或者恢复成能写，模拟数据库暂时写不进去。
    #[cfg(test)]
    pub(crate) fn set_read_only(&self, read_only: bool) {
        let value = if read_only { "on" } else { "off" };
        self.run(|session| session.batch(&format!("SET default_transaction_read_only = {value}"))).unwrap();
    }

    /// 测试用：等别的连接放开锁只等这么久，不等满平时的期限。刚等满过一次的那段"不等"也从头算。
    #[cfg(test)]
    pub(crate) fn set_lock_timeout(&self, timeout: Duration) {
        self.lock_patience.set(timeout);
        self.impatient_until.set(None);
        self.impatient.set(false);
        self.on_session(|session| session.set_lock_timeout(timeout)).unwrap();
    }

    /// 测试用：到现在为止有几条语句是把等锁的期限等满了才失败的。每一条都是拿着 controller 的锁白等的一段时间；
    /// "不等"的那段时间里马上失败的不算。
    #[cfg(test)]
    pub(crate) fn lock_waits(&self) -> usize {
        self.lock_waits.get()
    }

    /// 测试用：现在这条连接上，一条语句等回答只等这么久。
    #[cfg(test)]
    pub(crate) fn set_response_timeout(&self, timeout: Duration) {
        self.session.borrow().as_ref().expect("连接还在").set_response_timeout(timeout);
    }

    /// 测试用：数据库那边照看现在这条连接的进程。
    #[cfg(test)]
    pub(crate) fn backend(&self) -> i32 {
        self.query_one("SELECT pg_backend_pid()", &[], |row| row.try_get(0)).unwrap()
    }

    /// 测试用：直接执行几条 SQL。
    #[cfg(test)]
    pub(crate) fn execute_batch(&self, sql: &str) {
        self.run(|session| session.batch(sql)).unwrap();
    }

    /// 测试用：从现在起 `on`（比如 `INSERT ON tests`）报错，模拟一串写里只有前面的写进去了。
    /// `when` 是只让哪些行报错的条件，可以用 `OLD` 和 `NEW`；没有就是每一行。用 [`Store::unblock`] 撤掉。
    #[cfg(test)]
    pub(crate) fn block(&self, name: &str, on: &str, when: Option<&str>) {
        let when = when.map(|condition| format!("WHEN ({condition})")).unwrap_or_default();
        self.execute_batch(&format!(
            "CREATE OR REPLACE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '测试不让写（%）', TG_NAME; END $$;
             CREATE TRIGGER {name} BEFORE {on} FOR EACH ROW {when} EXECUTE FUNCTION refuse();"
        ));
    }

    /// 测试用：撤掉 [`Store::block`] 在 `table` 上装的 `name`。
    #[cfg(test)]
    pub(crate) fn unblock(&self, name: &str, table: &str) {
        self.execute_batch(&format!("DROP TRIGGER {name} ON {table}"));
    }

    /// 读一项全局设置（管理令牌的哈希之类）。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.query_opt("SELECT value FROM meta WHERE key = $1", &[&key], |row| row.try_get(0))
    }

    /// # Errors
    ///
    /// 写数据库失败。
    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.execute(
            "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            &[&key, &value],
        )?;
        Ok(())
    }

    /// 记下一项只定一次的全局设置：已经有了就不动它。返回现在记着的值，是自己刚写的，或者别人先写的那个。
    /// 几个进程同时来也只有一个写得上。
    ///
    /// # Errors
    ///
    /// 读写数据库失败。
    pub fn set_meta_once(&self, key: &str, value: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.execute("INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING", &[&key, &value])?;
        // 分成两句：别人先写的那一行可能是在上一句开始之后才提交的，同一句里看不见它。
        self.query_one("SELECT value FROM meta WHERE key = $1", &[&key], |row| row.try_get(0))
    }

    /// 在连接上做一件事。事务外面先看连接还在不在、等锁的期限对不对；事务里面不动这两样：
    /// 新连接上没有那个事务，期限在事务里改了也会跟着事务一起撤销。
    fn run<T>(&self, f: impl FnOnce(&Session) -> Result<T, StoreError>) -> Result<T, StoreError> {
        if self.transaction.get() == Transaction::None {
            self.reconnect_if_closed()?;
            self.settle_lock_timeout()?;
        }
        let result = self.on_session(f);
        if let Err(error) = &result {
            if self.transaction.get() == Transaction::Open {
                self.transaction.set(Transaction::Failed);
            }
            // 等满了一次：接下来同样长的一段时间里不再等。"不等"的时候失败的不算等过，不把这段时间往后推。
            if error.is_lock_timeout() && !self.impatient.get() {
                self.impatient_until.set(Some(Instant::now() + self.lock_patience.get()));
                #[cfg(test)]
                self.lock_waits.set(self.lock_waits.get() + 1);
            }
        }
        result
    }

    /// 在现在这条连接上做一件事，没有连接就是 [`StoreError::Disconnected`]。做完连接不能用了的话马上丢掉它。
    fn on_session<T>(&self, f: impl FnOnce(&Session) -> Result<T, StoreError>) -> Result<T, StoreError> {
        let mut current = self.session.borrow_mut();
        let Some(session) = current.as_ref() else {
            return Err(StoreError::Disconnected);
        };
        let result = f(session);
        if session.is_closed() {
            *current = None;
        }
        result
    }

    /// 若当前无可用连接则建立新连接。建连在驱动线程上进行，调用方只在建连开始后的一小段时间内等待（[`RECONNECT_WAIT`]，
    /// 上一次重连失败后为 [`RETRY_WAIT`]）：期间连上则照常返回；仍未连上则返回 [`StoreError::Reconnecting`]，建连继续进行，
    /// 由之后的调用接收结果。近期重连失败后的退避窗口内不发起建连，直接返回 [`StoreError::Disconnected`]。
    fn reconnect_if_closed(&self) -> Result<(), StoreError> {
        // 收到的结果已经过时时重新开始一次：失败发生在较早之前、退避期已过，或者连上之后无人来取、连接在等待期间已断开。
        for _ in 0..2 {
            {
                let mut current = self.session.borrow_mut();
                if current.as_ref().is_some_and(|session| !session.is_closed()) {
                    return Ok(());
                }
                // 闲着的时候断的，现在才看见。
                *current = None;
            }
            let mut connecting = self.connecting.borrow_mut();
            let (attempt, patience) = match connecting.as_mut() {
                Some(reconnect) => reconnect,
                None => {
                    let retry = match self.reconnect_after.get() {
                        Some(after) if Instant::now() < after => return Err(StoreError::Disconnected),
                        Some(_) => true,
                        None => false,
                    };
                    match Session::start(&self.database.0, Some(lock_timeout_sql(self.lock_patience.get()))) {
                        Ok(attempt) => connecting.insert((attempt, if retry { RETRY_WAIT } else { RECONNECT_WAIT })),
                        Err(error) => {
                            self.reconnect_after.set(Some(Instant::now() + RECONNECT_PAUSE.0));
                            return Err(error);
                        }
                    }
                }
            };
            // 同一次建连，所有调用方合计只等这么久：后来的调用方在建连仍未完成时不再等待。
            let left = (attempt.started() + *patience).saturating_duration_since(Instant::now());
            let Some((outcome, finished)) = attempt.wait(left) else { return Err(StoreError::Reconnecting) };
            let took = finished.saturating_duration_since(attempt.started());
            *connecting = None;
            match outcome {
                Ok(session) if !session.is_closed() => {
                    *self.session.borrow_mut() = Some(session);
                    self.reconnect_after.set(None);
                    self.impatient.set(false);
                    tracing::info!("已重新连接数据库");
                    return Ok(());
                }
                Ok(_) => {}
                Err(error) => {
                    let after = finished + took.clamp(RECONNECT_PAUSE.0, RECONNECT_PAUSE.1);
                    self.reconnect_after.set(Some(after));
                    if Instant::now() < after {
                        return Err(error);
                    }
                }
            }
        }
        // 重新开始的那一次连上之后也马上断了：数据库那边一连上就断开。同样退避，不让每次读写都去连。
        self.reconnect_after.set(Some(Instant::now() + RECONNECT_PAUSE.0));
        Err(StoreError::Disconnected)
    }

    /// 让连接上等锁的期限和现在该有的一致：刚等满过一次的那段时间里是"不等"，过了就恢复。
    fn settle_lock_timeout(&self) -> Result<(), StoreError> {
        let impatient = self.impatient_until.get().is_some_and(|until| Instant::now() < until);
        if impatient != self.impatient.get() {
            let timeout = if impatient { NO_LOCK_WAIT } else { self.lock_patience.get() };
            self.on_session(|session| session.set_lock_timeout(timeout))?;
            self.impatient.set(impatient);
        }
        Ok(())
    }

    /// 执行一条语句，返回它改了几行。
    fn execute(&self, sql: &str, params: Params<'_>) -> Result<usize, StoreError> {
        let changed = self.run(|session| session.execute(sql, params))?;
        Ok(usize::try_from(changed).unwrap_or(usize::MAX))
    }

    fn query<T>(&self, sql: &str, params: Params<'_>, read: impl FnMut(&Row) -> Read<T>) -> Result<Vec<T>, StoreError> {
        self.query_into(sql, params, read)
    }

    /// 和 [`Store::query`] 一样，结果收进调用方要的容器。
    fn query_into<T, C: FromIterator<T>>(&self, sql: &str, params: Params<'_>, read: impl FnMut(&Row) -> Read<T>) -> Result<C, StoreError> {
        let rows = self.run(|session| session.query(sql, params))?;
        Ok(rows.iter().map(read).collect::<Read<C>>()?)
    }

    /// 最多一行的查询：按主键或者唯一的列找。
    fn query_opt<T>(&self, sql: &str, params: Params<'_>, read: impl FnOnce(&Row) -> Read<T>) -> Result<Option<T>, StoreError> {
        let row = self.run(|session| session.query_opt(sql, params))?;
        Ok(row.as_ref().map(read).transpose()?)
    }

    /// 正好一行的查询：聚合，或者带 `RETURNING` 的插入。
    fn query_one<T>(&self, sql: &str, params: Params<'_>, read: impl FnOnce(&Row) -> Read<T>) -> Result<T, StoreError> {
        let row = self.run(|session| session.query_one(sql, params))?;
        Ok(read(&row)?)
    }

    /// 插入一行，返回数据库分给它的编号。`sql` 要以 `RETURNING id` 结尾。
    fn insert(&self, sql: &str, params: Params<'_>) -> Result<u32, StoreError> {
        self.query_one(sql, params, |row| Ok(row.try_get::<_, Int<u32>>(0)?.0))
    }
}

/// 开着的事务。提交之前丢掉就是撤销。
struct OpenTransaction<'a>(&'a Store);

impl OpenTransaction<'_> {
    fn commit(self) -> Result<(), StoreError> {
        if self.0.transaction.get() == Transaction::Failed {
            return Err(StoreError::Aborted);
        }
        // 先记下这个事务的编号：提交的回答要是回不来，过后凭它问得出事务算了数没有。什么都没改过的事务没有编号。
        let transaction: Option<String> =
            self.0.run(|session| Ok(session.query_one("SELECT pg_current_xact_id_if_assigned()::text", &[])?.try_get(0)?))?;
        match self.0.on_session(|session| session.batch("COMMIT")) {
            Ok(()) => {
                self.0.transaction.set(Transaction::None);
                Ok(())
            }
            // 数据库答了话、说提交不了：事务没有算数。连接早就不能用、提交根本没发出去的也是。
            Err(error @ (StoreError::Disconnected | StoreError::Postgres(_))) if !error.left_unanswered() => Err(error),
            // 发出去了，回答没有回来：数据库那边可能已经提交了。
            Err(error) => {
                self.0.transaction.set(Transaction::None);
                // 什么都没改过的事务算不算数都一样，没有要过后去问的。
                if let Some(transaction) = transaction {
                    self.0.unsettled.borrow_mut().push(transaction);
                    if let Some(wake) = &self.0.unsettled_wake {
                        wake.notify_one();
                    }
                }
                Err(StoreError::CommitUnknown(Box::new(error)))
            }
        }
    }
}

impl Drop for OpenTransaction<'_> {
    fn drop(&mut self) {
        if self.0.transaction.replace(Transaction::None) != Transaction::None {
            // 撤销不了只会是连接断了或者已经被丢掉了，那样数据库自己会撤销这个事务。
            let _ = self.0.on_session(|session| session.batch("ROLLBACK"));
        }
    }
}

/// 执行一条迁移时等待响应的上限。迁移仅在启动时执行，此时没有调用方持有 controller 锁等待；在已有数据的库上
/// 建索引、改表需要扫描整张表，库较大或磁盘较慢时可能超过单条语句平常的期限（见 [`session`]）。
const MIGRATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// 库里还没有 controller 的表时怎么办。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Missing {
    Create,
    Refuse,
}

/// 把表结构升到 `migrations` 的最后一条。每条迁移连同版本号的更新在一个事务里：PostgreSQL 的建表、改表也能撤销，
/// 所以失败的迁移不留下半张表。
///
/// 事务一开始先拿一把按 schema 算的咨询锁：两个进程同时在一个空库上启动时，后到的等前一个建完，再看到已经是新版本。
fn migrate(session: &Session, migrations: &[&str], missing: Missing) -> Result<(), StoreError> {
    let supported = u32::try_from(migrations.len()).expect("迁移是代码里写死的一个短列表，条数远小于 u32 的上限");
    loop {
        session.batch("BEGIN")?;
        let step = migrate_one(session, migrations, supported, missing);
        let done = match step {
            Ok(done) => session.batch("COMMIT").map(|()| done),
            Err(error) => Err(error),
        };
        match done {
            Ok(Some(version)) => tracing::info!(version, "数据库表结构已升级"),
            Ok(None) => return Ok(()),
            Err(error) => {
                // 回滚失败只可能是连接已断开，此时数据库侧已自动回滚该事务。
                let _ = session.batch("ROLLBACK");
                return Err(error);
            }
        }
    }
}

/// 在已经开始的事务里执行下一条还没执行的迁移，返回升到了第几版；已经是最新的话返回 `None`。
///
/// 表建在 `search_path` 里排在最前面的那个 schema 里（`current_schema()`），认版本号也只认那一个里的：
/// 排在后面的 schema 里就算有一张同名的表（别的程序的，或者另一个 controller 的），也不是这里的。
fn migrate_one(session: &Session, migrations: &[&str], supported: u32, missing: Missing) -> Result<Option<u32>, StoreError> {
    let schema: Option<String> = session.query_one("SELECT current_schema()::text", &[])?.try_get(0)?;
    let Some(schema) = schema else { return Err(StoreError::NoSchema) };
    session.execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&schema])?;
    let exists: bool =
        session.query_one("SELECT to_regclass(format('%I.schema_version', $1::text)) IS NOT NULL", &[&schema])?.try_get(0)?;
    if !exists {
        if missing == Missing::Refuse {
            return Err(StoreError::Empty);
        }
        session.batch("CREATE TABLE schema_version (version BIGINT NOT NULL); INSERT INTO schema_version (version) VALUES (0);")?;
    }
    // 上面确认了（或者刚建了）排在最前面的 schema 里有这张表，不写 schema 的名字找到的就是它。
    let found = session.query_one("SELECT version FROM schema_version", &[])?.try_get::<_, Int<u32>>(0)?.0;
    if found > supported {
        return Err(StoreError::NewerSchema { found, supported });
    }
    if found == supported {
        return Ok(None);
    }
    if found == 0 && missing == Missing::Refuse {
        return Err(StoreError::Empty);
    }
    let index = usize::try_from(found).expect("found 小于迁移的条数，条数本来就是 usize");
    tracing::info!(version = found + 1, "正在升级数据库表结构");
    session.batch_within(migrations[index], MIGRATION_TIMEOUT)?;
    session.execute("UPDATE schema_version SET version = $1", &[&Int(found + 1)])?;
    Ok(Some(found + 1))
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// 无法解析连接串，或连接串中缺少主机信息。不附带解析器的原始错误信息，避免暴露连接串片段及密码。
    #[error("数据库连接串格式无效：应为 postgres://用户:密码@主机/库名")]
    BadConnectionString,
    #[error("连接串要求启用 TLS（sslmode=require），但当前不支持数据库 TLS 连接：请将数据库部署在同机或可信内网中")]
    TlsUnsupported,
    #[error("无法连接数据库")]
    Connect(#[source] tokio_postgres::Error),
    #[error("连接数据库超时（已等待 {} 秒，含已建立 TCP 连接但对端无响应的情况）", .0.as_secs())]
    ConnectTimedOut(Duration),
    /// 连接已断开且近期重连失败：将在短暂间隔后再次尝试重连，期间的读写请求直接返回此错误。
    #[error("数据库连接已断开且近期重连失败，请稍后重试")]
    Disconnected,
    /// 连接已断开，重连正在后台进行且未在调用方可等待的时间（[`RECONNECT_WAIT`]、[`RETRY_WAIT`]）内完成：
    /// 期间的读写请求直接返回此错误。
    #[error("数据库连接已断开，正在重新连接，请稍后重试")]
    Reconnecting,
    #[error("无法启动数据库连接驱动线程")]
    Driver(#[source] io::Error),
    #[error("数据库操作失败")]
    Postgres(#[from] tokio_postgres::Error),
    #[error("数据库在 {} 秒内无响应", .0.as_secs())]
    Unresponsive(Duration),
    #[error("事务中存在失败的操作，整个事务未提交")]
    Aborted,
    /// 提交请求已发送但未收到响应：数据库侧可能已提交，也可能未提交。后续可通过 [`Store::settle_commits`] 查询最终状态。
    #[error("提交事务后未收到数据库响应，无法确认变更是否生效")]
    CommitUnknown(#[source] Box<StoreError>),
    #[error("search_path 中不存在有效的 schema，无法创建数据表")]
    NoSchema,
    #[error("数据库中缺少 controller 的数据表")]
    Empty,
    #[error("数据库由更新版本的程序创建（当前表结构版本为 {found}，本程序最高支持到第 {supported} 版）")]
    NewerSchema { found: u32, supported: u32 },
}

impl StoreError {
    /// 判断此次失败是否属于整个数据库级别的故障：无法连接、连接断开、无响应，或数据库处于只读、关闭中、空间不足等状态。
    /// 此类情况下立即重试其他写入也会得到相同结果。
    ///
    /// 其他失败仅与单条语句有关，其他行仍可正常写入（例如约束冲突、触发器拒绝、值类型不匹配、语句被取消等）。
    /// 等待锁超时（[`StoreError::is_lock_timeout`]）同样归为此类：被锁定的可能仅为单行。
    #[must_use]
    pub fn is_database_wide(&self) -> bool {
        match self {
            Self::Connect(_)
            | Self::ConnectTimedOut(_)
            | Self::Disconnected
            | Self::Reconnecting
            | Self::Driver(_)
            | Self::Unresponsive(_)
            | Self::CommitUnknown(_) => true,
            Self::Postgres(error) => match error.code() {
                // 数据库答了话，说了是哪一类：连接出错（08）、资源不够（53，盘满、连接数满）、系统出错（58），
                // 正在关闭或者被管理员断开（57P01 到 57P05；57014 是只取消了这一条语句，不算），再加上只读。
                Some(code) => {
                    matches!(code.code().get(..2), Some("08" | "53" | "58"))
                        || matches!(code.code(), "57P01" | "57P02" | "57P03" | "57P04" | "57P05")
                        || *code == SqlState::READ_ONLY_SQL_TRANSACTION
                }
                None => self.left_unanswered(),
            },
            Self::BadConnectionString | Self::TlsUnsupported | Self::Aborted | Self::NoSchema | Self::Empty | Self::NewerSchema { .. } => {
                false
            }
        }
    }

    /// 判断此次失败是否为等待其他连接释放锁超时。被锁定的可能是整张表，也可能仅为单行：
    /// 其他行大概率仍可正常写入，因此不应据此跳过其余操作。
    #[must_use]
    pub fn is_lock_timeout(&self) -> bool {
        matches!(self, Self::Postgres(error) if error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE))
    }

    /// 请求已发送但数据库未响应：连接断开、套接字读写出错或等待超时。参数或结果类型转换失败不属此类，仅与当前语句有关。
    fn left_unanswered(&self) -> bool {
        match self {
            Self::Unresponsive(_) => true,
            Self::Postgres(error) => {
                error.code().is_none()
                    && (error.is_closed() || std::error::Error::source(error).is_some_and(|source| source.is::<io::Error>()))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    const FIRST: &str = "CREATE TABLE a (x BIGINT NOT NULL);";
    const SECOND: &str = "CREATE TABLE b (y TEXT NOT NULL); ALTER TABLE a ADD COLUMN z BIGINT NOT NULL DEFAULT 7;";

    fn number(store: &Store, sql: &str) -> i64 {
        store.query_one(sql, &[], |row| row.try_get(0)).unwrap()
    }

    #[test]
    fn only_failures_of_the_whole_database_count_as_database_wide() {
        let scratch = Scratch::new();
        let store = Store::open(&scratch.database()).unwrap();
        store.set_meta("k", b"v").unwrap();

        store.set_read_only(true);
        assert!(store.set_meta("k", b"w").unwrap_err().is_database_wide(), "只读");
        store.set_read_only(false);

        store.block("no_meta", "UPDATE ON meta", None);
        assert!(!store.set_meta("k", b"w").unwrap_err().is_database_wide(), "只是这一条语句被拦下了");
        store.unblock("no_meta", "meta");
        let no_value = store.execute("INSERT INTO meta (key) VALUES ('no value')", &[]).unwrap_err();
        assert!(!no_value.is_database_wide(), "约束不让写：{no_value:?}");
        let wrong_type = store.query_one("SELECT value FROM meta WHERE key = 'k'", &[], |row| row.try_get::<_, i64>(0)).unwrap_err();
        assert!(!wrong_type.is_database_wide(), "读出来的值不是要的类型：{wrong_type:?}");
        assert!(!StoreError::NewerSchema { found: 2, supported: 1 }.is_database_wide());
        assert!(!StoreError::Aborted.is_database_wide());

        // 别的连接锁着这张表：等到期限就失败。被占着的也可能只是一行，所以不算整个数据库的事，另有一个说法。
        let other = Store::open(&scratch.database()).unwrap();
        other.execute_batch("BEGIN; LOCK TABLE meta IN EXCLUSIVE MODE");
        store.set_lock_timeout(Duration::from_millis(50));
        let locked = store.set_meta("k", b"w").unwrap_err();
        assert!(locked.is_lock_timeout() && !locked.is_database_wide(), "等锁超时：{locked:?}");
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()), "读不用等这把锁");
        other.execute_batch("ROLLBACK");
        store.set_meta("k", b"x").unwrap();

        // 只是这一条语句被取消了（这里是它自己超时），别的照常。
        store.execute_batch("SET statement_timeout = 20");
        let cancelled = store.execute("SELECT pg_sleep(5)", &[]).unwrap_err();
        assert!(!cancelled.is_database_wide() && !cancelled.is_lock_timeout(), "{cancelled:?}");
        store.execute_batch("SET statement_timeout = 0");
        store.set_meta("k", b"y").unwrap();

        // 数据库把连接掐了；之后连不上。
        let terminated = store.execute("SELECT pg_terminate_backend(pg_backend_pid())", &[]).unwrap_err();
        assert!(terminated.is_database_wide(), "{terminated:?}");
        let nowhere: Database = "postgres://i3t@127.0.0.1:1/i3t".parse().unwrap();
        assert!(Store::open(&nowhere).err().expect("这个端口上没有数据库").is_database_wide());
        assert!(StoreError::Disconnected.is_database_wide() && StoreError::Unresponsive(Duration::ZERO).is_database_wide());
    }

    #[test]
    fn after_one_full_wait_for_a_lock_locked_rows_fail_at_once_and_other_rows_are_written() {
        let scratch = Scratch::new();
        let store = Store::open(&scratch.database()).unwrap();
        store.set_meta("locked", b"1").unwrap();
        store.set_meta("free", b"1").unwrap();
        let other = Store::open(&scratch.database()).unwrap();
        other.execute_batch("BEGIN; UPDATE meta SET value = '\\x02' WHERE key = 'locked'");

        let patience = Duration::from_millis(300);
        store.set_lock_timeout(patience);
        let started = Instant::now();
        assert!(store.set_meta("locked", b"3").unwrap_err().is_lock_timeout());
        assert!(started.elapsed() >= patience, "头一次把期限等满");
        assert_eq!(store.lock_waits(), 1);

        // 刚等满过一次：同一行再写马上失败，不再等；没被占着的行照常写。
        let started = Instant::now();
        assert!(store.set_meta("locked", b"3").unwrap_err().is_lock_timeout());
        assert!(store.set_meta("locked", b"3").unwrap_err().is_lock_timeout());
        store.set_meta("free", b"2").unwrap();
        assert!(started.elapsed() < patience, "这三次加起来也没有等满一次：{:?}", started.elapsed());
        assert_eq!(store.lock_waits(), 1, "马上失败的不算等过");
        assert_eq!(store.meta("free").unwrap().as_deref(), Some(b"2".as_slice()));

        // 过了这一段，又肯等一次。
        std::thread::sleep(patience);
        assert!(store.set_meta("locked", b"3").unwrap_err().is_lock_timeout());
        assert_eq!(store.lock_waits(), 2);

        // 锁放开了：就算还在"不等"的那一段里，也写得进去。
        other.execute_batch("ROLLBACK");
        store.set_meta("locked", b"3").unwrap();
    }

    #[test]
    fn a_lock_wait_inside_a_transaction_fails_the_transaction_and_the_next_one_does_not_wait() {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.database()).unwrap();
        store.set_meta("locked", b"1").unwrap();
        let other = Store::open(&scratch.database()).unwrap();
        other.execute_batch("BEGIN; UPDATE meta SET value = '\\x02' WHERE key = 'locked'");
        let patience = Duration::from_millis(300);
        store.set_lock_timeout(patience);

        let waited: Result<(), StoreError> = store.atomically(|store| {
            store.set_meta("free", b"1")?;
            store.set_meta("locked", b"3")
        });
        assert!(waited.unwrap_err().is_lock_timeout());
        assert_eq!(store.meta("free").unwrap(), None, "整个事务撤销了");

        let started = Instant::now();
        let again: Result<(), StoreError> = store.atomically(|store| store.set_meta("locked", b"3"));
        assert!(again.unwrap_err().is_lock_timeout());
        assert!(started.elapsed() < patience, "{:?}", started.elapsed());
        assert_eq!(store.lock_waits(), 1);
        other.execute_batch("ROLLBACK");
    }

    /// 接了连接、之后一个字节都不回的"数据库"。
    fn silent_server() -> (std::net::TcpListener, Database) {
        silent_server_with(1)
    }

    /// 同 [`silent_server`]，连接串里的建连超时是 `connect_timeout` 秒。
    fn silent_server_with(connect_timeout: u32) -> (std::net::TcpListener, Database) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let database = format!("postgres://i3t@127.0.0.1:{port}/i3t?connect_timeout={connect_timeout}").parse().unwrap();
        (listener, database)
    }

    #[test]
    fn a_server_that_accepts_and_never_answers_is_given_up_on() {
        let (listener, database) = silent_server();
        let held = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));
        let started = Instant::now();
        let error = Store::open(&database).err().expect("它不会答话");
        assert!(matches!(error, StoreError::ConnectTimedOut(limit) if limit == Duration::from_secs(1)), "{error:?}");
        assert!(error.is_database_wide());
        assert!(started.elapsed() < Duration::from_secs(5), "到了期限就放弃：{:?}", started.elapsed());
        drop(held.join().unwrap());
    }

    #[test]
    fn a_statement_that_gets_no_answer_in_time_fails_and_the_connection_is_replaced() {
        let store = Store::temporary();
        store.set_meta("k", b"v").unwrap();
        store.set_response_timeout(Duration::from_millis(100));
        let started = Instant::now();
        let error = store.execute("SELECT pg_sleep(30)", &[]).unwrap_err();
        assert!(matches!(error, StoreError::Unresponsive(_)) && error.is_database_wide(), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()), "下一次读写换了一条新连接");
    }

    #[test]
    fn a_connection_that_stopped_answering_is_dropped_at_once_and_its_transaction_lets_go_of_its_locks() {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.database()).unwrap();
        store.set_meta("k", b"v").unwrap();
        let other = Store::open(&scratch.database()).unwrap();
        let backend = number(&store, "SELECT pg_backend_pid()::bigint");
        let still_there = format!("SELECT COUNT(*) FROM pg_stat_activity WHERE pid = {backend}");
        assert_eq!(number(&other, &still_there), 1);

        // 事务里先占住一行，接着的一条语句在期限里等不到回答。
        store.set_response_timeout(Duration::from_millis(200));
        let outcome: Result<(), StoreError> = store.atomically(|store| {
            store.set_meta("k", b"w")?;
            store.execute("SELECT pg_sleep(2)", &[]).map(|_| ())
        });
        assert!(matches!(outcome.unwrap_err(), StoreError::Unresponsive(_)));
        assert!(store.session.borrow().is_none(), "不能用的连接当场就丢掉");

        // 之后没有人再用这个 `Store`，也就没有人去重新连。数据库那边照样发现对面走了：那条连接结束，事务撤销，锁放开。
        let deadline = Instant::now() + Duration::from_secs(20);
        while number(&other, &still_there) != 0 {
            assert!(Instant::now() < deadline, "那条连接还留在数据库那边，占着它的锁");
            std::thread::sleep(Duration::from_millis(50));
        }
        other.set_lock_timeout(Duration::from_millis(500));
        other.set_meta("k", b"x").unwrap();
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"x".as_slice()), "再用的时候连一条新的");
    }

    #[test]
    fn after_a_failed_reconnect_the_next_calls_fail_at_once_until_the_pause_is_over() {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.database()).unwrap();
        store.set_meta("k", b"v").unwrap();
        // 连接断了，数据库又搬去了一个不答话的地方：重新连要等满期限。
        let (listener, nowhere) = silent_server();
        let real = std::mem::replace(&mut store.database, nowhere);
        assert!(store.execute("SELECT pg_terminate_backend(pg_backend_pid())", &[]).is_err());

        let started = Instant::now();
        assert!(matches!(store.meta("k"), Err(StoreError::ConnectTimedOut(_))));
        let first = started.elapsed();
        assert!(first >= Duration::from_secs(1), "{first:?}");

        // 刚试过：这一会儿里不再去连，马上说连不上，不是每一次都等满期限。
        let started = Instant::now();
        for _ in 0..5 {
            assert!(matches!(store.meta("k"), Err(StoreError::Disconnected)));
        }
        assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());

        // 过了这一会儿、数据库也回来了：照常。
        store.database = real;
        std::thread::sleep(first);
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()));
        drop(listener);
    }

    /// 连接断了，重连去的 `nowhere` 一直给不出结果；调用方只等一小会儿，之后的调用不再等。
    /// 然后 `hang_up` 让那边挂断、数据库回到原处，`Store` 自己连回去。
    fn reconnecting_in_the_background(nowhere: Database, hang_up: impl FnOnce()) {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.database()).unwrap();
        store.set_meta("k", b"v").unwrap();
        let real = std::mem::replace(&mut store.database, nowhere);
        assert!(store.execute("SELECT pg_terminate_backend(pg_backend_pid())", &[]).is_err());

        let started = Instant::now();
        let error = store.meta("k").unwrap_err();
        assert!(matches!(error, StoreError::Reconnecting) && error.is_database_wide(), "{error:?}");
        assert!(started.elapsed() < RECONNECT_WAIT + Duration::from_secs(1), "只等一小会儿：{:?}", started.elapsed());

        // 建连仍在后台进行：之后的读写立即失败，不再等它。
        let started = Instant::now();
        for _ in 0..5 {
            assert!(matches!(store.meta("k"), Err(StoreError::Reconnecting)));
        }
        assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());

        // 那边挂断，这次建连失败；退避之后连上已经回来的数据库。
        store.database = real;
        hang_up();
        let deadline = Instant::now() + Duration::from_secs(20);
        let value = loop {
            match store.meta("k") {
                Ok(value) => break value,
                Err(error) => assert!(error.is_database_wide() && Instant::now() < deadline, "应当重新连上：{error:?}"),
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(value.as_deref(), Some(b"v".as_slice()));
    }

    #[test]
    fn a_reconnect_stuck_on_connecting_goes_on_in_the_background() {
        // 端口连得上，之后一个字节都不回：建连要到连接串里的期限（30 秒）才放弃。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let nowhere = format!("postgres://i3t@127.0.0.1:{port}/i3t?connect_timeout=30").parse().unwrap();
        let held = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));
        reconnecting_in_the_background(nowhere, || drop(held.join().unwrap()));
    }

    #[test]
    fn a_reconnect_stuck_on_its_first_statement_goes_on_in_the_background() {
        use std::io::{Read as _, Write as _};

        // 连接建得起来、打完招呼之后什么都不回：新连接上设置等锁期限的语句等不到响应。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let nowhere = format!("postgres://i3t@127.0.0.1:{port}/i3t").parse().unwrap();
        let (hang_up, hung_up) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut chunk = [0; 1024];
            assert!(stream.read(&mut chunk).unwrap() > 0, "启动消息");
            // "认证通过"，"可以发语句了"。
            stream.write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I").unwrap();
            let _ = hung_up.recv();
        });
        reconnecting_in_the_background(nowhere, move || {
            hang_up.send(()).unwrap();
            server.join().unwrap();
        });
    }

    #[test]
    fn after_a_failed_reconnect_the_next_attempt_holds_up_the_caller_for_less_time() {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.database()).unwrap();
        let (listener, nowhere) = silent_server();
        store.database = nowhere;
        assert!(store.execute("SELECT pg_terminate_backend(pg_backend_pid())", &[]).is_err());

        // 原本可用的连接断了：等这一次建连的结果（1 秒超时）。
        let started = Instant::now();
        assert!(matches!(store.meta("k"), Err(StoreError::ConnectTimedOut(_))));
        let first = started.elapsed();

        // 退避过后再试，这一次建连要 30 秒才放弃：数据库此前就连不上，只等 `RETRY_WAIT`，明显短于原本可用的连接断开时的等待。
        let (_held, slower) = silent_server_with(30);
        store.database = slower;
        std::thread::sleep(first);
        let started = Instant::now();
        assert!(matches!(store.meta("k"), Err(StoreError::Reconnecting)));
        let waited = started.elapsed();
        assert!(waited < RECONNECT_WAIT, "{waited:?}");
        drop(listener);
    }

    #[test]
    fn a_connection_that_closed_before_anyone_picked_it_up_is_not_used() {
        use std::io::{Read as _, Write as _};

        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.database()).unwrap();
        store.set_meta("k", b"v").unwrap();
        // 连接建得起来，初始设置迟迟没有响应：调用方等不到，先走了。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let slow = format!("postgres://i3t@127.0.0.1:{port}/i3t").parse().unwrap();
        let real = std::mem::replace(&mut store.database, slow);
        let (next, step) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut chunk = [0; 1024];
            assert!(stream.read(&mut chunk).unwrap() > 0, "启动消息");
            // "认证通过"，"可以发语句了"。
            stream.write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I").unwrap();
            assert!(stream.read(&mut chunk).unwrap() > 0, "初始设置");
            step.recv().unwrap();
            // 设置完成："SET"，"可以发语句了"。
            stream.write_all(b"C\0\0\0\x08SET\0Z\0\0\0\x05I").unwrap();
            // 之后关闭连接。
            step.recv().unwrap();
        });
        assert!(store.execute("SELECT pg_terminate_backend(pg_backend_pid())", &[]).is_err());
        assert!(matches!(store.meta("k"), Err(StoreError::Reconnecting)));

        // 设置完成，连接交了出来，却在无人来取的这段时间里断了。
        next.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        next.send(()).unwrap();
        server.join().unwrap();
        std::thread::sleep(Duration::from_millis(300));

        // 下一次读写不用这条已经断了的连接，重新连接（数据库已回到原处）。
        store.database = real;
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()));
    }

    #[test]
    fn a_commit_that_gets_no_answer_is_reported_as_unknown_not_as_rolled_back() {
        let mut store = Store::temporary();
        // 提交要做的事（推迟到提交时才触发）要做上一阵：提交发出去了，在期限里等不到回答。
        store.execute_batch(
            "CREATE FUNCTION stall() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1.5); RETURN NULL; END $$;
             CREATE CONSTRAINT TRIGGER stall AFTER INSERT OR UPDATE ON meta DEFERRABLE INITIALLY DEFERRED
                 FOR EACH ROW EXECUTE FUNCTION stall();",
        );
        store.set_response_timeout(Duration::from_millis(200));
        let wake = Arc::new(Notify::new());
        store.wake_on_unsettled_commit(Arc::clone(&wake));
        let started = Instant::now();
        let outcome: Result<(), StoreError> = store.atomically(|store| store.set_meta("k", b"v"));
        let error = outcome.unwrap_err();
        assert!(matches!(error, StoreError::CommitUnknown(_)) && error.is_database_wide(), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        // 得有人回头来问它后来怎么样了：记着它，并且叫醒了要来问的人。
        assert!(store.has_unsettled_commits());
        let mut woken = std::pin::pin!(wake.notified());
        assert!(woken.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())).is_ready());

        // 数据库那边其实还在做，做完就提交了：这次改动是算数的。调用方要是把这个错当成"没有做"，就错了。
        // 问得出来：数据库那边做完之前是"还没做完"，然后是"算了数"。
        let deadline = Instant::now() + Duration::from_secs(20);
        let answer = loop {
            let answer = store.settle_commits().unwrap();
            if !answer.pending {
                break answer;
            }
            assert!(!answer.committed, "还没做完的不算有了结果");
            assert!(Instant::now() < deadline, "数据库那边应该提交了");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(answer, Settled { committed: true, pending: false });
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()));
        assert!(!store.has_unsettled_commits(), "问出了结果就不再记着");
    }

    #[test]
    fn what_became_of_a_transaction_is_asked_by_its_number() {
        let scratch = Scratch::new();
        let (store, other) = (Store::open(&scratch.database()).unwrap(), Store::open(&scratch.database()).unwrap());
        const NOTHING: Settled = Settled { committed: false, pending: false };
        assert_eq!(store.settle_commits().unwrap(), NOTHING);
        let number = |store: &Store| store.query_one("SELECT pg_current_xact_id()::text", &[], |row| row.try_get::<_, String>(0)).unwrap();

        // 撤销了的。
        other.execute_batch("BEGIN");
        store.unsettled.borrow_mut().push(number(&other));
        other.execute_batch("ROLLBACK");
        assert_eq!(store.settle_commits().unwrap(), NOTHING, "没算数，等于什么都没发生");
        assert!(!store.has_unsettled_commits());

        // 还没做完的过后再问，这期间一直记着；做完了、算了数的。
        other.execute_batch("BEGIN");
        store.unsettled.borrow_mut().push(number(&other));
        assert_eq!(store.settle_commits().unwrap(), Settled { committed: false, pending: true });
        assert!(store.has_unsettled_commits());
        other.execute_batch("COMMIT");
        assert_eq!(store.settle_commits().unwrap(), Settled { committed: true, pending: false });
        assert_eq!(store.settle_commits().unwrap(), NOTHING);

        // 几个一起问：没做完的那个不耽误已经算了数的那个有结果，它自己留着下次再问。
        let third = Store::open(&scratch.database()).unwrap();
        other.execute_batch("BEGIN");
        third.execute_batch("BEGIN");
        let (still_running, done) = (number(&other), number(&third));
        third.execute_batch("COMMIT");
        store.unsettled.borrow_mut().extend([still_running.clone(), done]);
        assert_eq!(store.settle_commits().unwrap(), Settled { committed: true, pending: true });
        assert_eq!(*store.unsettled.borrow(), [still_running]);
        other.execute_batch("ROLLBACK");
        assert_eq!(store.settle_commits().unwrap(), NOTHING);

        // 数据库答不上来的编号（库换成了另一份的话，它在那里还没有用到）：当它算了数，多核对一次没有坏处。
        store.unsettled.borrow_mut().push(u64::MAX.to_string());
        assert_eq!(store.settle_commits().unwrap(), Settled { committed: true, pending: false });
        assert!(!store.has_unsettled_commits());
    }

    #[test]
    fn a_question_that_could_not_be_asked_does_not_make_the_transaction_forgotten() {
        // 问的那一下数据库出了别的错（这里是语句被取消；数据库正在关、连接满了也一样）：不是"这个编号查不到"。
        // 事务可能还在做，就此当它算了数、不再记着它的话，提前核对读到的是旧的样子，之后也不会再核对。
        // 把 pg_catalog 排在后面，就能用自己的一个同名函数顶替那个内置的来出这个错。
        let scratch = Scratch::new();
        let store = Store::open(&scratch.database_with_path(&[scratch.schema(), "pg_catalog"])).unwrap();
        store.execute_batch(
            "CREATE FUNCTION pg_xact_status(xid8) RETURNS text LANGUAGE plpgsql AS $$ BEGIN
                 RAISE EXCEPTION '语句被取消了' USING ERRCODE = 'query_canceled';
             END $$;",
        );
        store.execute_batch("BEGIN");
        let running = store.query_one("SELECT pg_current_xact_id()::text", &[], |row| row.try_get::<_, String>(0)).unwrap();
        store.unsettled.borrow_mut().push(running.clone());
        store.execute_batch("COMMIT");

        let error = store.settle_commits().unwrap_err();
        assert!(matches!(&error, StoreError::Postgres(error) if error.code() == Some(&SqlState::QUERY_CANCELED)), "{error:?}");
        assert_eq!(*store.unsettled.borrow(), [running], "还记着它");
        store.execute_batch("DROP FUNCTION pg_xact_status(xid8)");
        assert_eq!(store.settle_commits().unwrap(), Settled { committed: true, pending: false });
    }

    #[test]
    fn a_commit_the_database_refuses_is_a_plain_failure() {
        let mut store = Store::temporary();
        store.execute_batch(
            "CREATE TABLE parent (id BIGINT PRIMARY KEY);
             CREATE TABLE child (parent BIGINT REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);",
        );
        // 外键推迟到提交时才查：提交被数据库拒绝，它答了话，事务确定没有算数。
        let outcome: Result<(), StoreError> = store.atomically(|store| store.execute("INSERT INTO child VALUES (1)", &[]).map(|_| ()));
        let error = outcome.unwrap_err();
        assert!(matches!(error, StoreError::Postgres(_)) && !error.is_database_wide(), "{error:?}");
        assert_eq!(store.query_one("SELECT COUNT(*) FROM child", &[], |row| row.try_get::<_, i64>(0)).unwrap(), 0);
        store.atomically(|store| store.set_meta("k", b"v")).unwrap();
    }

    #[test]
    fn the_tables_and_their_version_belong_to_the_first_schema_of_the_search_path() {
        // search_path 里有两个 schema：前一个是空的，后一个里有别人的一张 schema_version。
        let mine = Scratch::new();
        let theirs = Scratch::new();
        let admin = Store::prepare(&theirs.database(), &[], Missing::Create).unwrap();
        admin.execute("UPDATE schema_version SET version = 99", &[]).unwrap();
        let both = mine.database_with_path(&[mine.schema(), theirs.schema()]);

        assert!(matches!(Store::open_existing(&both), Err(StoreError::Empty)), "前一个 schema 里没有表：不认后一个里的");
        let store = Store::open(&both).unwrap();
        assert_eq!(store.schema_version().unwrap(), u32::try_from(schema::MIGRATIONS.len()).unwrap());
        store.set_meta("k", b"v").unwrap();
        assert_eq!(number(&admin, "SELECT version FROM schema_version"), 99, "别人的版本号没有被改");
        let only_mine = Store::open(&mine.database()).unwrap();
        assert_eq!(only_mine.meta("k").unwrap().as_deref(), Some(b"v".as_slice()), "表建在前一个 schema 里");
    }

    #[test]
    fn a_search_path_without_any_existing_schema_is_refused() {
        let scratch = Scratch::new();
        let nowhere = scratch.database_with_path(&["no_such_schema_anywhere"]);
        assert!(matches!(Store::open(&nowhere), Err(StoreError::NoSchema)));
    }

    #[test]
    fn an_empty_database_is_migrated_to_the_current_schema() {
        let scratch = Scratch::new();
        let store = Store::open(&scratch.database()).unwrap();
        assert_eq!(store.schema_version().unwrap(), u32::try_from(schema::MIGRATIONS.len()).unwrap());
        assert!(store.networks().unwrap().is_empty());
    }

    #[test]
    fn reopening_keeps_the_data_and_does_not_migrate_again() {
        let scratch = Scratch::new();
        {
            let store = Store::open(&scratch.database()).unwrap();
            store.set_meta("k", b"v").unwrap();
        }
        let store = Store::open(&scratch.database()).unwrap();
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()));
        assert_eq!(store.meta("missing").unwrap(), None);
    }

    #[test]
    fn an_empty_database_is_left_alone_when_asked_not_to_create() {
        let scratch = Scratch::new();
        assert!(matches!(Store::open_existing(&scratch.database()), Err(StoreError::Empty)));
        let admin = Store::prepare(&scratch.database(), &[], Missing::Create).unwrap();
        assert_eq!(
            number(&admin, "SELECT COUNT(*) FROM pg_tables WHERE schemaname = current_schema() AND tablename <> 'schema_version'"),
            0
        );
        drop(admin);

        // 只有版本号那张表、一条迁移也没执行过的库，也算空的。
        assert!(matches!(Store::open_existing(&scratch.database()), Err(StoreError::Empty)));
        drop(Store::open(&scratch.database()).unwrap());
        assert!(Store::open_existing(&scratch.database()).is_ok());
    }

    #[test]
    fn a_later_migration_is_applied_on_top_of_existing_data() {
        let scratch = Scratch::new();
        {
            let store = Store::prepare(&scratch.database(), &[FIRST], Missing::Create).unwrap();
            assert_eq!(store.schema_version().unwrap(), 1);
            store.execute("INSERT INTO a (x) VALUES (1)", &[]).unwrap();
        }
        let store = Store::prepare(&scratch.database(), &[FIRST, SECOND], Missing::Create).unwrap();
        assert_eq!(store.schema_version().unwrap(), 2);
        let row: (i64, i64) = store.query_one("SELECT x, z FROM a", &[], |row| Ok((row.try_get(0)?, row.try_get(1)?))).unwrap();
        assert_eq!(row, (1, 7));
        store.execute("INSERT INTO b (y) VALUES ('new table')", &[]).unwrap();
    }

    #[test]
    fn a_migration_may_take_longer_than_an_ordinary_statement() {
        // 在已有数据的库上建索引要扫描整张表：迁移不受平常的期限约束，迁移之后的语句仍受约束。
        let scratch = Scratch::new();
        let session = Session::connect(&scratch.database().0).unwrap();
        session.set_response_timeout(Duration::from_millis(500));
        let slow = "SELECT pg_sleep(1.5); CREATE TABLE c (q BIGINT);";
        migrate(&session, &[FIRST, slow], Missing::Create).unwrap();
        assert!(matches!(session.batch("SELECT pg_sleep(1.5)"), Err(StoreError::Unresponsive(_))));
        let store = Store::prepare(&scratch.database(), &[FIRST, slow], Missing::Create).unwrap();
        assert_eq!(store.schema_version().unwrap(), 2);
    }

    #[test]
    fn a_database_from_a_newer_program_is_refused() {
        let scratch = Scratch::new();
        drop(Store::prepare(&scratch.database(), &[FIRST, SECOND], Missing::Create).unwrap());
        let result = Store::prepare(&scratch.database(), &[FIRST], Missing::Create);
        assert!(matches!(result, Err(StoreError::NewerSchema { found: 2, supported: 1 })));
    }

    #[test]
    fn a_failed_migration_leaves_the_previous_version_in_place() {
        let scratch = Scratch::new();
        drop(Store::prepare(&scratch.database(), &[FIRST], Missing::Create).unwrap());
        let broken = "CREATE TABLE c (q BIGINT); CREATE TABLE a (dup BIGINT);";
        assert!(matches!(Store::prepare(&scratch.database(), &[FIRST, broken], Missing::Create), Err(StoreError::Postgres(_))));
        let store = Store::prepare(&scratch.database(), &[FIRST], Missing::Create).unwrap();
        assert_eq!(store.schema_version().unwrap(), 1);
        assert!(store.execute("INSERT INTO c (q) VALUES (1)", &[]).is_err(), "失败的迁移不应该留下半张表");
    }

    #[test]
    fn two_programs_starting_on_an_empty_database_both_end_up_with_one_schema() {
        let scratch = Scratch::new();
        let database = scratch.database();
        let versions: Vec<u32> = std::thread::scope(|scope| {
            let starts: Vec<_> = (0..4).map(|_| scope.spawn(|| Store::open(&database).unwrap().schema_version().unwrap())).collect();
            starts.into_iter().map(|start| start.join().unwrap()).collect()
        });
        assert_eq!(versions, [u32::try_from(schema::MIGRATIONS.len()).unwrap(); 4]);
    }

    #[test]
    fn a_failed_transaction_is_rolled_back_as_a_whole() {
        let mut store = Store::temporary();
        let result: Result<(), StoreError> = store.atomically(|store| {
            store.set_meta("a", b"1")?;
            Err(StoreError::NewerSchema { found: 0, supported: 0 })
        });
        assert!(result.is_err());
        assert_eq!(store.meta("a").unwrap(), None);

        store.atomically(|store| store.set_meta("a", b"2")).unwrap();
        assert_eq!(store.meta("a").unwrap().as_deref(), Some(b"2".as_slice()));
    }

    #[test]
    fn a_transaction_with_a_swallowed_failure_is_not_reported_as_committed() {
        let mut store = Store::temporary();
        let result: Result<(), StoreError> = store.atomically(|store| {
            store.set_meta("a", b"1")?;
            assert!(store.execute("INSERT INTO meta (key) VALUES ('no value')", &[]).is_err());
            Ok(())
        });
        assert!(matches!(result, Err(StoreError::Aborted)));
        assert_eq!(store.meta("a").unwrap(), None, "PostgreSQL 把整个事务撤销了，不能当成提交了");
        store.set_meta("a", b"2").unwrap();
    }

    #[test]
    fn a_panic_inside_a_transaction_rolls_it_back() {
        let mut store = Store::temporary();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), StoreError> = store.atomically(|store| {
                store.set_meta("a", b"1")?;
                panic!("半路出事");
            });
        }));
        assert!(outcome.is_err());
        assert_eq!(store.meta("a").unwrap(), None);
        store.atomically(|store| store.set_meta("a", b"2")).unwrap();
    }

    #[test]
    fn a_dropped_connection_is_replaced_on_the_very_next_use() {
        let store = Store::temporary();
        store.set_meta("k", b"v").unwrap();
        // 让数据库把这条连接掐掉：这一句自己拿不到回答。数据库说了连接到此为止，不用等驱动线程发现套接字关了。
        assert!(store.execute("SELECT pg_terminate_backend(pg_backend_pid())", &[]).unwrap_err().is_database_wide());
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()), "紧接着的读写就换了一条新连接");
    }

    #[test]
    fn a_connection_lost_inside_a_transaction_fails_it_and_the_store_recovers() {
        let mut store = Store::temporary();
        let result: Result<(), StoreError> = store.atomically(|store| {
            store.set_meta("a", b"1")?;
            let _ = store.execute("SELECT pg_terminate_backend(pg_backend_pid())", &[]);
            store.set_meta("b", b"2")
        });
        assert!(result.is_err());
        assert_eq!((store.meta("a").unwrap(), store.meta("b").unwrap()), (None, None));
        store.atomically(|store| store.set_meta("a", b"3")).unwrap();
        assert_eq!(store.meta("a").unwrap().as_deref(), Some(b"3".as_slice()));
    }

    #[test]
    fn the_store_works_from_inside_an_async_task() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let store = Store::temporary();
            store.set_meta("k", b"v").unwrap();
            assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()));
        });
    }

    #[test]
    fn the_connection_string_is_read_in_both_forms_and_its_password_is_not_printed() {
        let url: Database = "postgres://i3t:s3cret@db.example:5433/controller".parse().unwrap();
        let pairs: Database = "host=/var/run/postgresql user=i3t password=s3cret dbname=controller".parse().unwrap();
        for database in [&url, &pairs] {
            let printed = format!("{database:?}");
            assert!(printed.contains("controller") && !printed.contains("s3cret"), "{printed}");
        }
        assert_eq!(url.0.get_connect_timeout(), Some(&CONNECT_TIMEOUT));
        assert_eq!(
            (url.0.get_keepalives_idle(), url.0.get_keepalives_interval(), url.0.get_keepalives_retries()),
            (DEAD_PEER_TIMEOUT, Some(KEEPALIVE_INTERVAL), Some(KEEPALIVE_RETRIES))
        );
        let own: Database =
            "postgres://db.example/x?connect_timeout=3&keepalives_idle=600&keepalives_interval=7&keepalives_retries=9".parse().unwrap();
        assert_eq!(own.0.get_connect_timeout(), Some(&Duration::from_secs(3)), "连接串里写了的照它的");
        assert_eq!(own.0.get_keepalives_idle(), Duration::from_secs(600));
        assert_eq!((own.0.get_keepalives_interval(), own.0.get_keepalives_retries()), (Some(Duration::from_secs(7)), Some(9)));
    }

    #[test]
    fn a_connection_string_that_cannot_be_read_is_refused_without_repeating_it() {
        // 拼错了 postgres://：解析器把整个连接串当成一个不认识的选项，原话里有密码。
        // 密码没有加引号、里面有空格和等号：同样会被原样说出来。
        for bad in [
            "postgre://i3t:s3cret@db.example/controller?x=1",
            "postgres://i3t:s3cret@db.example:notaport/controller",
            "host=db.example user=i3t password=s3cret word=more dbname=controller",
            "host=db.example user=i3t password=s3cret extra",
        ] {
            let error = bad.parse::<Database>().expect_err(bad);
            assert!(matches!(error, StoreError::BadConnectionString), "{bad}");
            let mut said = format!("{error} {error:?}");
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                said.push_str(&format!(" {cause} {cause:?}"));
                source = cause.source();
            }
            assert!(!said.contains("s3cret") && !said.contains("db.example"), "{said}");
        }
        // 空的、只有空白的、没有主机的：现在就说，不等到连的时候。
        for empty in ["", "  \n", "user=i3t dbname=controller"] {
            assert!(matches!(empty.parse::<Database>(), Err(StoreError::BadConnectionString)), "{empty:?}");
        }
        assert!("  postgres://i3t@db.example/controller\n".parse::<Database>().is_ok(), "前后的空白和换行不碍事");
    }

    #[test]
    fn a_setting_that_is_set_once_keeps_the_first_value() {
        let scratch = Scratch::new();
        let (first, second) = (Store::open(&scratch.database()).unwrap(), Store::open(&scratch.database()).unwrap());
        assert_eq!(first.set_meta_once("owner", b"first").unwrap(), b"first");
        assert_eq!(second.set_meta_once("owner", b"second").unwrap(), b"first", "后来的写不上，读到的是先写的");
        assert_eq!(first.meta("owner").unwrap().as_deref(), Some(b"first".as_slice()));

        // 先来的还没提交时后来的等着它；它提交了，后来的读到的是它写的，不是空的。
        first.execute_batch("BEGIN; INSERT INTO meta (key, value) VALUES ('race', 'early')");
        let late = std::thread::spawn(move || second.set_meta_once("race", b"late").unwrap());
        std::thread::sleep(Duration::from_millis(300));
        first.execute_batch("COMMIT");
        assert_eq!(late.join().unwrap(), b"early");
    }

    #[test]
    fn a_host_written_only_as_an_address_is_a_host() {
        // 只写 `hostaddr`、不写 `host`：不是"没有主机"，照样去连。
        let database: Database = "hostaddr=127.0.0.1 port=1 user=i3t password=s3cret dbname=controller".parse().expect("只写了地址");
        let printed = format!("{database:?}");
        assert!(printed.contains("127.0.0.1") && !printed.contains("s3cret"), "{printed}");
        let error = Store::open(&database).err().expect("这个端口上没有数据库");
        assert!(matches!(error, StoreError::Connect(_)), "去连了，而不是说连接串读不懂：{error:?}");

        // 建连的期限按主机的个数给：写名字、写地址都算。
        let limit = |text: &str| session::connect_limit(&text.parse::<Database>().unwrap().0);
        assert_eq!(limit("hostaddr=192.0.2.1,192.0.2.2 user=i3t connect_timeout=3"), Duration::from_secs(6));
        assert_eq!(limit("host=a.example,b.example,c.example user=i3t connect_timeout=3"), Duration::from_secs(9));
        assert_eq!(limit("host=a.example,b.example hostaddr=192.0.2.1,192.0.2.2 user=i3t connect_timeout=3"), Duration::from_secs(6));
    }

    #[test]
    fn a_connection_string_that_asks_for_tls_is_refused_instead_of_connecting_in_the_clear() {
        for wants_tls in ["postgres://i3t@db.example/controller?sslmode=require", "host=db.example user=i3t sslmode=require"] {
            assert!(matches!(wants_tls.parse::<Database>(), Err(StoreError::TlsUnsupported)), "{wants_tls}");
        }
        for fine in ["postgres://i3t@db.example/controller?sslmode=disable", "postgres://i3t@db.example/controller?sslmode=prefer"] {
            assert!(fine.parse::<Database>().is_ok(), "{fine}");
        }
    }
}
