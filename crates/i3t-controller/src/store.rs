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
//! - 连不上（包括连上了端口、对面却不答话）有总的期限；刚试过没连上的话，过一小会儿才再去连，这期间的读写马上失败
//!   （[`StoreError::Disconnected`]），不是每一次都把期限等满。
//! - 一条语句等回答有期限，过了就当这条连接坏了。
//! - 别的连接占着锁时（有人在库里开着事务改同一行、锁了表）最多等 [`LOCK_TIMEOUT`]。刚等满过一次的话，接下来同样长的
//!   一段时间里不再等：被占着的马上失败，没被占着的照常写。一把一直不放的锁因此最多让 controller 有一半的时间在等，
//!   而且挡不住别的行。
//!
//! # 连接断了
//!
//! 连接断了（数据库重启、网络闪断）时，下一次读写会换一条新的连接再做。断的那一刻正在做的读写报错。
//! 它要是在事务里，事务不算数，数据库那边已经撤销了，只有一种情况说不准：断在"提交"发出去之后、回答回来之前。
//! 那时数据库可能已经提交了，也可能没有，这里报 [`StoreError::CommitUnknown`]，调用方不能当成"没有做"。

mod codec;
mod cooldown;
#[cfg(test)]
pub(crate) mod fixtures;
mod forward;
mod group;
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
use std::time::{Duration, Instant};

use tokio_postgres::config::SslMode;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Config, Row};

pub use cooldown::CooldownKind;
pub use forward::ForwardRecord;
pub use group::{BUILTIN_GROUP, GroupRecord, folded};
pub use network::{NetworkRecord, NewNetwork};
pub use node::{NetmapState, NewNode, NodeRecord, ReachRecord};
pub use oplog::LogFilter;
pub use pair::PairOptions;
pub use proxy::ProxyRecord;
#[cfg(any(test, feature = "testing"))]
pub use scratch::{Scratch, TEST_DATABASE_ENV};
pub use stats::StatPoint;
pub use switch::NewSwitch;
pub use test::KEEP_PER_PAIR;
pub use token::{NewToken, RETENTION_SECS, TokenRecord, is_pending, token_at};

use codec::{Int, Read};
use session::{CONNECT_TIMEOUT, Params, Session};

/// SHA-256 的长度。令牌和 netmap 的摘要都是它。
pub const DIGEST_LEN: usize = 32;

/// 别的连接占着一张表或者一行的锁时，一条语句最多等这么久，过了就失败。PostgreSQL 默认一直等下去。
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// 刚等满过一次锁之后，"不等"的那段时间里用的期限：被占着的语句马上失败。不能是 0，0 是"一直等"。
const NO_LOCK_WAIT: Duration = Duration::from_millis(1);

/// 没连上之后至少、至多隔多久再去连。隔多久看那一次花了多久：马上被拒绝的可以很快再试，等满了期限的要多隔一会儿，
/// 不然连不上的那段时间里 controller 就一直卡在"连"上。
const RECONNECT_PAUSE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(30));

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
        // 空的连接串解析得过去，要到连的时候才说没有主机。
        if config.get_hosts().is_empty() {
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
            .field("ports", &self.0.get_ports())
            .field("user", &self.0.get_user())
            .field("dbname", &self.0.get_dbname())
            .finish_non_exhaustive()
    }
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
    /// 现在用着的连接。发现它不能用了就马上丢掉、留空，不等到下一次连上才换：丢掉就是关套接字，数据库那边由此撤销
    /// 它没做完的事务、放开它的锁。留着的话，这个 `Store` 闲着或者一直连不上的那段时间里，那些锁就一直占着。
    session: RefCell<Option<Session>>,
    transaction: Cell<Transaction>,
    /// 等锁平时肯等多久。
    lock_patience: Cell<Duration>,
    /// 刚等满过一次锁：到这个时刻之前不再等。
    impatient_until: Cell<Option<Instant>>,
    /// 连接上现在设的是不是"不等锁"。
    impatient: Cell<bool>,
    /// 刚试过没连上：到这个时刻之前不再去连。
    reconnect_after: Cell<Option<Instant>>,
    /// 测试用：有几条语句是把等锁的期限等满了才失败的。
    #[cfg(test)]
    lock_waits: Cell<usize>,
    /// 测试用的数据库：和这个 `Store` 一起丢掉。写在 `session` 后面，先关连接再删。
    #[cfg(any(test, feature = "testing"))]
    scratch: Option<Scratch>,
}

impl Store {
    /// 连上数据库，并把表结构升到当前版本；库是空的就从头建。
    ///
    /// # Errors
    ///
    /// 连不上，或者库里的表是更新版本的程序建的。
    pub fn open(database: &Database) -> Result<Self, StoreError> {
        Self::prepare(database, schema::MIGRATIONS, Missing::Create)
    }

    /// 和 [`Store::open`] 一样，只是库里还没有 controller 的表时不建，报 [`StoreError::Empty`]。
    ///
    /// # Errors
    ///
    /// 连不上，库是空的，或者库里的表是更新版本的程序建的。
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
            transaction: Cell::new(Transaction::None),
            lock_patience: Cell::new(LOCK_TIMEOUT),
            impatient_until: Cell::new(None),
            impatient: Cell::new(false),
            reconnect_after: Cell::new(None),
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
    /// 事务里的一条语句失败之后，这个事务就不能再用了（PostgreSQL 的规矩）：`f` 应该把那个错误传出来。
    /// 它要是把错误吞了、照常返回，这里报 [`StoreError::Aborted`]，同样全部撤销。
    ///
    /// 要 `&mut self` 是为了让编译器保证事务不会嵌套。
    ///
    /// # Errors
    ///
    /// `f` 返回的错误，或者开始、提交事务时数据库出的错。提交发出去了、回答没有回来时是
    /// [`StoreError::CommitUnknown`]：这一种说不准事务算不算数。
    pub fn atomically<T, E: From<StoreError>>(&mut self, f: impl FnOnce(&Self) -> Result<T, E>) -> Result<T, E> {
        self.run(|session| session.batch("BEGIN"))?;
        self.transaction.set(Transaction::Open);
        let open = OpenTransaction(self);
        // `f` 出错或者恐慌时 `open` 在这里被丢弃，丢弃即撤销。
        let value = f(self)?;
        open.commit()?;
        Ok(value)
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

    /// 没有能用的连接的话连一条新的。刚试过没连上的那一小会儿里不去连，直接说连不上。
    fn reconnect_if_closed(&self) -> Result<(), StoreError> {
        {
            let mut current = self.session.borrow_mut();
            if current.as_ref().is_some_and(|session| !session.is_closed()) {
                return Ok(());
            }
            // 闲着的时候断的，现在才看见。
            *current = None;
        }
        if self.reconnect_after.get().is_some_and(|after| Instant::now() < after) {
            return Err(StoreError::Disconnected);
        }
        let started = Instant::now();
        let connected = Session::connect(&self.database.0).and_then(|session| {
            session.set_lock_timeout(self.lock_patience.get())?;
            Ok(session)
        });
        match connected {
            Ok(session) => {
                *self.session.borrow_mut() = Some(session);
                self.reconnect_after.set(None);
                self.impatient.set(false);
                tracing::info!("重新连上了数据库");
                Ok(())
            }
            Err(error) => {
                let pause = started.elapsed().clamp(RECONNECT_PAUSE.0, RECONNECT_PAUSE.1);
                self.reconnect_after.set(Some(Instant::now() + pause));
                Err(error)
            }
        }
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
            Ok(Some(version)) => tracing::info!(version, "数据库的表结构已升级"),
            Ok(None) => return Ok(()),
            Err(error) => {
                // 撤销不了只会是连接断了，那样数据库已经自己撤销了。
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
    session.batch(migrations[index])?;
    session.execute("UPDATE schema_version SET version = $1", &[&Int(found + 1)])?;
    Ok(Some(found + 1))
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// 连接串读不懂，或者里面没有主机。不带解析器的原话：那里面会有连接串的片段，连密码在内。
    #[error("数据库的连接串写得不对：要写成 postgres://用户:密码@主机/库名")]
    BadConnectionString,
    #[error("连接串要求 TLS（sslmode=require），这个程序连数据库不支持 TLS：数据库要在同一台机器上或者可信的内网里")]
    TlsUnsupported,
    #[error("连不上数据库")]
    Connect(#[source] tokio_postgres::Error),
    #[error("连数据库等了 {} 秒没有连上（连上了端口、对面一直不答话也算）", .0.as_secs())]
    ConnectTimedOut(Duration),
    /// 连接断着，刚试过重新连、没连上：过一小会儿才再去连，这期间的读写直接是这个错。
    #[error("和数据库的连接断了，刚试过没连上，过一会儿再试")]
    Disconnected,
    #[error("起不了照看数据库连接的线程")]
    Driver(#[source] io::Error),
    #[error("数据库操作失败")]
    Postgres(#[from] tokio_postgres::Error),
    #[error("数据库 {} 秒没有回答", .0.as_secs())]
    Unresponsive(Duration),
    #[error("事务里有一步失败了，整个事务没有提交")]
    Aborted,
    /// 提交发出去了，回答没有回来：数据库那边可能已经提交了，也可能没有。
    #[error("提交之后没有等到数据库的回答，不知道这次改动算不算数")]
    CommitUnknown(#[source] Box<StoreError>),
    #[error("search_path 里没有一个存在的 schema，表没有地方建")]
    NoSchema,
    #[error("数据库里没有 controller 的表")]
    Empty,
    #[error("数据库是更新版本的程序写的（表结构第 {found} 版，这个程序只认识到第 {supported} 版）")]
    NewerSchema { found: u32, supported: u32 },
}

impl StoreError {
    /// 这次失败是不是整个数据库的事：连不上、连接断了、不答话，数据库只读、正在关闭、没有空间。
    /// 这时换一行写、马上再写一次都是一样的结果。
    ///
    /// 别的失败只和那一条语句有关，别的行照样写得进去：约束、触发器、读出来的值不对、语句被取消之类。
    /// 等锁等到了期限（[`StoreError::is_lock_timeout`]）也在这一边：被占着的可能只是这一行。
    #[must_use]
    pub fn is_database_wide(&self) -> bool {
        match self {
            Self::Connect(_)
            | Self::ConnectTimedOut(_)
            | Self::Disconnected
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

    /// 这次失败是不是等别的连接放开锁等到了期限。被占着的可能是一整张表，也可能只是这一行：
    /// 别的行多半照样写得进去，所以不该因为它就不去试别的。
    #[must_use]
    pub fn is_lock_timeout(&self) -> bool {
        matches!(self, Self::Postgres(error) if error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE))
    }

    /// 请求发出去了，数据库没有答话：连接断了、读写它出了错，或者等过了头。参数、结果转换不了的不算，那是这一条语句的事。
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
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let database = format!("postgres://i3t@127.0.0.1:{port}/i3t?connect_timeout=1").parse().unwrap();
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
        let started = Instant::now();
        let outcome: Result<(), StoreError> = store.atomically(|store| store.set_meta("k", b"v"));
        let error = outcome.unwrap_err();
        assert!(matches!(error, StoreError::CommitUnknown(_)) && error.is_database_wide(), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());

        // 数据库那边其实还在做，做完就提交了：这次改动是算数的。调用方要是把这个错当成"没有做"，就错了。
        let deadline = Instant::now() + Duration::from_secs(20);
        while store.meta("k").unwrap().is_none() {
            assert!(Instant::now() < deadline, "数据库那边应该提交了");
            std::thread::sleep(Duration::from_millis(50));
        }
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
    fn a_connection_string_that_asks_for_tls_is_refused_instead_of_connecting_in_the_clear() {
        for wants_tls in ["postgres://i3t@db.example/controller?sslmode=require", "host=db.example user=i3t sslmode=require"] {
            assert!(matches!(wants_tls.parse::<Database>(), Err(StoreError::TlsUnsupported)), "{wants_tls}");
        }
        for fine in ["postgres://i3t@db.example/controller?sslmode=disable", "postgres://i3t@db.example/controller?sslmode=prefer"] {
            assert!(fine.parse::<Database>().is_ok(), "{fine}");
        }
    }
}
