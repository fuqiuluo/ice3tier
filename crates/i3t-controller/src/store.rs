//! 存储：一个 PostgreSQL 数据库。
//!
//! 别的模块只通过 [`Store`] 上的方法读写，看不到 SQL，所以以后要换存储只需要重写这个模块。
//! 这里不检查业务规则（名字合不合法、能力有没有声明），那是 [`crate::Controller`] 的事；
//! 表上的唯一约束和外键只是最后一道保险。
//!
//! 一个 [`Store`] 是一条连接，方法是同步的：发出一条语句，等到结果才返回（见 [`session`]）。
//! 表建在连接的 `search_path` 指的 schema 里，默认就是 `public`；一个数据库给一个 controller 用。
//!
//! 连接断了（数据库重启、网络闪断）时，下一次读写会重新连上再做。断的那一刻正在做的读写报错；
//! 它要是在事务里，整个事务不算数，数据库那边已经撤销了。

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
use std::time::Duration;

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
use session::{Params, Session};

/// SHA-256 的长度。令牌和 netmap 的摘要都是它。
pub const DIGEST_LEN: usize = 32;

/// 连接串里没有写超时的话，连不上时最多等这么久。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 连接串里没有另外写的话，连接闲着这么久就发 TCP 保活，发出去的数据这么久没人确认就当连接断了。
/// 数据库在别的机器上、中间的网络悄悄断掉时，靠它才不会一直等一个不会来的回答。
const DEAD_PEER_TIMEOUT: Duration = Duration::from_secs(30);

/// `tokio-postgres` 自己的保活间隔。连接串里没有改它的话，这里换成 [`DEAD_PEER_TIMEOUT`]。
const LIBRARY_KEEPALIVE_IDLE: Duration = Duration::from_secs(2 * 60 * 60);

/// 连到哪个 PostgreSQL 数据库。从连接串来，两种写法都认：
/// `postgres://用户:密码@主机:端口/库名`，或者 `host=… user=… dbname=…`（主机可以是放 Unix 套接字的目录）。
///
/// 不支持 TLS：数据库要和 controller 在同一台机器或者一个可信的内网里。
#[derive(Clone)]
pub struct Database(Config);

impl FromStr for Database {
    type Err = StoreError;

    fn from_str(text: &str) -> Result<Self, StoreError> {
        let mut config: Config = text.parse().map_err(StoreError::BadConnectionString)?;
        if config.get_application_name().is_none() {
            config.application_name("i3t-controller");
        }
        if config.get_connect_timeout().is_none() {
            config.connect_timeout(CONNECT_TIMEOUT);
        }
        if config.get_keepalives_idle() == LIBRARY_KEEPALIVE_IDLE {
            config.keepalives_idle(DEAD_PEER_TIMEOUT);
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
    session: RefCell<Session>,
    transaction: Cell<Transaction>,
    /// 测试用：有几条语句是等锁等到超时才失败的。
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
        migrate(&session, migrations, missing)?;
        Ok(Self {
            database: database.clone(),
            session: RefCell::new(session),
            transaction: Cell::new(Transaction::None),
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
    /// `f` 返回的错误，或者开始、提交事务时数据库出的错。
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
        self.session.borrow().batch(&format!("SET default_transaction_read_only = {value}")).unwrap();
    }

    /// 测试用：等别的连接放开锁只等这么久，不等满平时的期限。
    #[cfg(test)]
    pub(crate) fn set_lock_timeout(&self, timeout: Duration) {
        self.session.borrow().set_lock_timeout(timeout).unwrap();
    }

    /// 测试用：到现在为止有几条语句是等锁等到超时才失败的。每一条都是拿着 controller 的锁白等的一段时间。
    #[cfg(test)]
    pub(crate) fn lock_waits(&self) -> usize {
        self.lock_waits.get()
    }

    /// 测试用：直接执行几条 SQL。
    #[cfg(test)]
    pub(crate) fn execute_batch(&self, sql: &str) {
        self.session.borrow().batch(sql).unwrap();
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

    /// 在连接上做一件事。连接已经断了的话先换一条新的；事务开着时不换，新连接上没有那个事务。
    fn run<T>(&self, f: impl FnOnce(&Session) -> Result<T, tokio_postgres::Error>) -> Result<T, StoreError> {
        if self.transaction.get() == Transaction::None && self.session.borrow().is_closed() {
            let session = Session::connect(&self.database.0)?;
            *self.session.borrow_mut() = session;
            tracing::info!("重新连上了数据库");
        }
        let result = f(&self.session.borrow());
        if result.is_err() && self.transaction.get() == Transaction::Open {
            self.transaction.set(Transaction::Failed);
        }
        #[cfg(test)]
        if result.as_ref().is_err_and(|error| error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE)) {
            self.lock_waits.set(self.lock_waits.get() + 1);
        }
        Ok(result?)
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
        self.0.session.borrow().batch("COMMIT")?;
        self.0.transaction.set(Transaction::None);
        Ok(())
    }
}

impl Drop for OpenTransaction<'_> {
    fn drop(&mut self) {
        if self.0.transaction.replace(Transaction::None) != Transaction::None {
            // 撤销不了只会是连接断了，那样数据库已经自己撤销了这个事务。
            let _ = self.0.session.borrow().batch("ROLLBACK");
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
            Ok(done) => session.batch("COMMIT").map(|()| done).map_err(StoreError::from),
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
fn migrate_one(session: &Session, migrations: &[&str], supported: u32, missing: Missing) -> Result<Option<u32>, StoreError> {
    session.batch("SELECT pg_advisory_xact_lock(hashtext(current_schema()))")?;
    let exists: bool = session.query_one("SELECT to_regclass('schema_version') IS NOT NULL", &[])?.try_get(0)?;
    if !exists {
        if missing == Missing::Refuse {
            return Err(StoreError::Empty);
        }
        session.batch("CREATE TABLE schema_version (version BIGINT NOT NULL); INSERT INTO schema_version (version) VALUES (0);")?;
    }
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
    #[error("数据库的连接串写得不对")]
    BadConnectionString(#[source] tokio_postgres::Error),
    #[error("连不上数据库")]
    Connect(#[source] tokio_postgres::Error),
    #[error("起不了照看数据库连接的线程")]
    Driver(#[source] io::Error),
    #[error("数据库操作失败")]
    Postgres(#[from] tokio_postgres::Error),
    #[error("事务里有一步失败了，整个事务没有提交")]
    Aborted,
    #[error("数据库里没有 controller 的表")]
    Empty,
    #[error("数据库是更新版本的程序写的（表结构第 {found} 版，这个程序只认识到第 {supported} 版）")]
    NewerSchema { found: u32, supported: u32 },
}

impl StoreError {
    /// 这次失败是不是整个数据库的事：连不上、连接断了，数据库只读、正在关闭、没有空间，或者等别的连接放开锁等到了超时。
    /// 这时换一行写、马上再写一次都是一样的结果，而且"等锁"的每一次都要先等满期限才失败。
    ///
    /// 别的失败只和那一条语句有关，别的行照样写得进去：约束、触发器、读出来的值不对之类。
    #[must_use]
    pub fn is_database_wide(&self) -> bool {
        match self {
            Self::Connect(_) | Self::Driver(_) => true,
            Self::Postgres(error) => match error.code() {
                // 数据库答了话，说了是哪一类：连接出错（08）、资源不够（53，盘满、连接数满）、被管理员中断或者正在关闭（57）、
                // 系统出错（58），再加上只读和等锁超时这两个。
                Some(code) => {
                    matches!(code.code().get(..2), Some("08" | "53" | "57" | "58"))
                        || *code == SqlState::READ_ONLY_SQL_TRANSACTION
                        || *code == SqlState::LOCK_NOT_AVAILABLE
                }
                // 没有答话：连接已经断了，或者读写它的时候出了错。参数、结果转换不了的不算，那是这一条语句的事。
                None => error.is_closed() || std::error::Error::source(error).is_some_and(|source| source.is::<io::Error>()),
            },
            Self::BadConnectionString(_) | Self::Aborted | Self::Empty | Self::NewerSchema { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
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

        // 别的连接锁着这张表：等到期限就失败，换一行写也一样。
        let other = Store::open(&scratch.database()).unwrap();
        other.execute_batch("BEGIN; LOCK TABLE meta IN EXCLUSIVE MODE");
        store.set_lock_timeout(Duration::from_millis(50));
        assert_eq!(store.lock_waits(), 0);
        assert!(store.set_meta("k", b"w").unwrap_err().is_database_wide(), "等锁超时");
        assert_eq!(store.lock_waits(), 1);
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()), "读不用等这把锁");
        other.execute_batch("ROLLBACK");
        store.set_meta("k", b"x").unwrap();

        // 数据库把连接掐了；之后连不上。
        let terminated = store.execute("SELECT pg_terminate_backend(pg_backend_pid())", &[]).unwrap_err();
        assert!(terminated.is_database_wide(), "{terminated:?}");
        let nowhere: Database = "postgres://i3t@127.0.0.1:1/i3t".parse().unwrap();
        assert!(Store::open(&nowhere).err().expect("这个端口上没有数据库").is_database_wide());
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
    fn a_dropped_connection_is_replaced_on_the_next_use() {
        let store = Store::temporary();
        store.set_meta("k", b"v").unwrap();
        // 让数据库把这条连接掐掉：这一句自己拿不到回答。
        assert!(store.execute("SELECT pg_terminate_backend(pg_backend_pid())", &[]).is_err());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !store.session.borrow().is_closed() {
            assert!(std::time::Instant::now() < deadline, "连接应该已经断了");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()), "下一次读写换了一条新连接");
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
        let own: Database = "postgres://db.example/x?connect_timeout=3&keepalives_idle=600".parse().unwrap();
        assert_eq!(own.0.get_connect_timeout(), Some(&Duration::from_secs(3)), "连接串里写了的照它的");
        assert_eq!(own.0.get_keepalives_idle(), Duration::from_secs(600));
        assert!(matches!("postgres://db.example:notaport/x".parse::<Database>(), Err(StoreError::BadConnectionString(_))));
    }
}
