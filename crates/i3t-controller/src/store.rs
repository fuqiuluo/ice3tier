//! 存储：一个 SQLite 文件。
//!
//! 别的模块只通过 [`Store`] 上的方法读写，看不到 SQL，所以以后要换存储只需要重写这个模块。
//! 这里不检查业务规则（名字合不合法、能力有没有声明），那是 [`crate::Controller`] 的事；
//! 表上的唯一约束和外键只是最后一道保险。
//!
//! 数据库是 WAL 模式：提交先写进旁边的 `-wal` 文件，过一阵才写回主文件。所以 controller 开着的时候拷贝主文件
//! 得不到完整的数据，备份要用 [`Store::snapshot`]。

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
mod stats;
mod switch;
mod test;
mod token;

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

pub use cooldown::CooldownKind;
pub use forward::ForwardRecord;
pub use group::{BUILTIN_GROUP, GroupRecord, folded};
pub use network::{NetworkRecord, NewNetwork};
pub use node::{NetmapState, NewNode, NodeRecord, ReachRecord};
pub use oplog::LogFilter;
pub use pair::PairOptions;
pub use proxy::ProxyRecord;
pub use stats::StatPoint;
pub use switch::NewSwitch;
pub use test::KEEP_PER_PAIR;
pub use token::{NewToken, RETENTION_SECS, TokenRecord, is_pending, token_at};

/// SHA-256 的长度。令牌和 netmap 的摘要都是它。
pub const DIGEST_LEN: usize = 32;

/// 做快照时最多等别的连接多久。WAL 模式下读不挡写，只有对方正在重建 WAL 的索引这类很短的时刻要等。
const SNAPSHOT_BUSY_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Store {
    conn: Connection,
}

impl Store {
    /// 打开数据库文件，不存在就新建，并把表结构升到当前版本。
    ///
    /// # Errors
    ///
    /// 文件打不开、不是 SQLite 数据库，或者它是更新版本的程序写的。
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::prepare(Connection::open(path)?, schema::MIGRATIONS)
    }

    /// 把数据库文件 `database` 的一份一致的快照写到 `to`。`to` 要么还不存在，要么是一个空文件。
    ///
    /// 用的是 SQLite 的 `VACUUM INTO`：在一个读事务里把整个数据库写成一个新文件。读事务看到的是它开始那一刻已经提交的
    /// 全部内容，包括还在 `-wal` 里、没有写回主文件的提交；之后的提交一条也不混进来。WAL 模式下读不挡写，
    /// 同时开着这个数据库的 controller（同一个进程或者别的进程）照常读写。
    ///
    /// 只读打开，不迁移：快照不改原来的数据库，哪个版本的程序写的都原样照抄，表结构的版本号也在里面。
    /// 在快照上 [`Store::open`] 时照常迁移。controller 停着时，SQLite 会在原来的数据库旁边建出空的 `-wal` 和 `-shm`
    /// （只读也要用它们）；留着不碍事，controller 启动时照常用。
    ///
    /// # Errors
    ///
    /// `database` 打不开或者不是 SQLite 数据库，`to` 写不了或者已经有内容。
    pub fn snapshot(database: &Path, to: &Path) -> Result<(), StoreError> {
        let conn = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        conn.busy_timeout(SNAPSHOT_BUSY_TIMEOUT)?;
        // SQLite 的文件名是 UTF-8。rusqlite 在 Windows 上对不是 UTF-8 的路径也是这样拒绝的。
        let target = to.to_str().ok_or_else(|| rusqlite::Error::InvalidPath(to.to_owned()))?;
        conn.execute("VACUUM INTO ?1", [target])?;
        Ok(())
    }

    /// 只在内存里的数据库，进程结束就没了。测试用。
    ///
    /// # Errors
    ///
    /// SQLite 初始化失败。
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::prepare(Connection::open_in_memory()?, schema::MIGRATIONS)
    }

    fn prepare(mut conn: Connection, migrations: &[&str]) -> Result<Self, StoreError> {
        // WAL 加 NORMAL：每次提交不必等刷盘，断电最多丢最后几次提交，文件不会坏。
        // controller 的数据丢了最后一两次修改可以重做，换来的是上报密集时不卡在磁盘上。
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        migrate(&mut conn, migrations)?;
        Ok(Self { conn })
    }

    /// 表结构现在是第几版，也就是已经执行过几条迁移。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        Ok(self.conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    /// 把 `f` 里的读写放进一个事务：`f` 返回错误时全部撤销。
    ///
    /// 要 `&mut self` 是为了让编译器保证事务不会嵌套。
    ///
    /// # Errors
    ///
    /// `f` 返回的错误，或者开始、提交事务时数据库出的错。
    pub fn atomically<T, E: From<StoreError>>(&mut self, f: impl FnOnce(&Self) -> Result<T, E>) -> Result<T, E> {
        let transaction = self.conn.unchecked_transaction().map_err(StoreError::from)?;
        // `f` 出错时 `transaction` 在这里被丢弃，丢弃即回滚。
        let value = f(self)?;
        transaction.commit().map_err(StoreError::from)?;
        Ok(value)
    }

    /// 测试用：让数据库只能读，或者恢复成能写，模拟磁盘暂时写不进去。
    #[cfg(test)]
    pub(crate) fn set_read_only(&self, read_only: bool) {
        self.conn.pragma_update(None, "query_only", read_only).unwrap();
    }

    /// 测试用：别的连接占着写锁时不等，这一次写直接算失败，并且叫一下 `seen`。
    /// 模拟"数据库正忙"而不用真的等满超时，也数得出等了几次。
    #[cfg(test)]
    pub(crate) fn fail_when_busy(&mut self, mut seen: impl FnMut() + Send + 'static) {
        let give_up = move |_| {
            seen();
            false
        };
        self.conn.busy_handler(Some(give_up)).unwrap();
    }

    /// 测试用：直接执行几条 SQL，比如装一个让某张表写不进去的触发器，模拟一串写里只有前面的写进去了。
    #[cfg(test)]
    pub(crate) fn execute_batch(&self, sql: &str) {
        self.conn.execute_batch(sql).unwrap();
    }

    /// 读一项全局设置（管理令牌的哈希之类）。
    ///
    /// # Errors
    ///
    /// 读数据库失败。
    pub fn meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| row.get(0)).optional()?)
    }

    /// # Errors
    ///
    /// 写数据库失败。
    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

fn migrate(conn: &mut Connection, migrations: &[&str]) -> Result<(), StoreError> {
    let found: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let supported = u32::try_from(migrations.len()).expect("迁移是代码里写死的一个短列表，条数远小于 u32 的上限");
    if found > supported {
        return Err(StoreError::NewerSchema { found, supported });
    }
    for version in found..supported {
        let index = usize::try_from(version).expect("version 小于迁移的条数，条数本来就是 usize");
        let transaction = conn.transaction()?;
        transaction.execute_batch(migrations[index])?;
        transaction.pragma_update(None, "user_version", version + 1)?;
        transaction.commit()?;
        tracing::info!(version = version + 1, "数据库的表结构已升级");
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("数据库操作失败")]
    Sqlite(#[from] rusqlite::Error),
    #[error("数据库是更新版本的程序写的（表结构第 {found} 版，这个程序只认识到第 {supported} 版）")]
    NewerSchema { found: u32, supported: u32 },
}

impl StoreError {
    /// 这次失败是不是整个数据库的事：别的进程占着写锁、数据库只读、盘满、读写文件出错。
    /// 这时换一行写、马上再写一次都是一样的结果，而且"占着写锁"的每一次都要先等满超时才失败。
    ///
    /// 别的失败（约束、触发器之类）只和那一条语句有关，别的行照样写得进去。
    #[must_use]
    pub fn is_database_wide(&self) -> bool {
        use rusqlite::ErrorCode::{DatabaseBusy, DatabaseLocked, DiskFull, ReadOnly, SystemIoFailure};
        match self {
            Self::Sqlite(err) => {
                matches!(err.sqlite_error_code(), Some(DatabaseBusy | DatabaseLocked | DiskFull | ReadOnly | SystemIoFailure))
            }
            Self::NewerSchema { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: &str = "CREATE TABLE a (x INTEGER NOT NULL);";
    const SECOND: &str = "CREATE TABLE b (y TEXT NOT NULL); ALTER TABLE a ADD COLUMN z INTEGER NOT NULL DEFAULT 7;";

    #[test]
    fn only_failures_of_the_whole_database_count_as_database_wide() {
        let store = Store::open_in_memory().unwrap();
        store.set_meta("k", b"v").unwrap();

        store.set_read_only(true);
        assert!(store.set_meta("k", b"w").unwrap_err().is_database_wide(), "只读");
        store.set_read_only(false);

        store.execute_batch("CREATE TRIGGER no_meta BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'no'); END;");
        assert!(!store.set_meta("k", b"w").unwrap_err().is_database_wide(), "只是这一条语句被拦下了");
        assert!(!StoreError::NewerSchema { found: 2, supported: 1 }.is_database_wide());
    }

    #[test]
    fn an_empty_file_is_migrated_to_the_current_schema() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("controller.db")).unwrap();
        assert_eq!(store.schema_version().unwrap(), u32::try_from(schema::MIGRATIONS.len()).unwrap());
        assert!(store.networks().unwrap().is_empty());
    }

    #[test]
    fn reopening_keeps_the_data_and_does_not_migrate_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("controller.db");
        {
            let store = Store::open(&path).unwrap();
            store.set_meta("k", b"v").unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.meta("k").unwrap().as_deref(), Some(b"v".as_slice()));
        assert_eq!(store.meta("missing").unwrap(), None);
    }

    #[test]
    fn a_later_migration_is_applied_on_top_of_existing_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.db");
        {
            let store = Store::prepare(Connection::open(&path).unwrap(), &[FIRST]).unwrap();
            assert_eq!(store.schema_version().unwrap(), 1);
            store.conn.execute("INSERT INTO a (x) VALUES (1)", []).unwrap();
        }
        let store = Store::prepare(Connection::open(&path).unwrap(), &[FIRST, SECOND]).unwrap();
        assert_eq!(store.schema_version().unwrap(), 2);
        let row: (i64, i64) = store.conn.query_row("SELECT x, z FROM a", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!(row, (1, 7));
        store.conn.execute("INSERT INTO b (y) VALUES ('new table')", []).unwrap();
    }

    #[test]
    fn a_database_from_a_newer_program_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.db");
        drop(Store::prepare(Connection::open(&path).unwrap(), &[FIRST, SECOND]).unwrap());
        let result = Store::prepare(Connection::open(&path).unwrap(), &[FIRST]);
        assert!(matches!(result, Err(StoreError::NewerSchema { found: 2, supported: 1 })));
    }

    #[test]
    fn a_failed_migration_leaves_the_previous_version_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.db");
        drop(Store::prepare(Connection::open(&path).unwrap(), &[FIRST]).unwrap());
        let broken = "CREATE TABLE c (q INTEGER); CREATE TABLE a (dup INTEGER);";
        assert!(matches!(Store::prepare(Connection::open(&path).unwrap(), &[FIRST, broken]), Err(StoreError::Sqlite(_))));
        let store = Store::prepare(Connection::open(&path).unwrap(), &[FIRST]).unwrap();
        assert_eq!(store.schema_version().unwrap(), 1);
        assert!(store.conn.execute("INSERT INTO c (q) VALUES (1)", []).is_err(), "失败的迁移不应该留下半张表");
    }

    #[test]
    fn a_failed_transaction_is_rolled_back_as_a_whole() {
        let mut store = Store::open_in_memory().unwrap();
        let result: Result<(), StoreError> = store.atomically(|store| {
            store.set_meta("a", b"1")?;
            Err(StoreError::NewerSchema { found: 0, supported: 0 })
        });
        assert!(result.is_err());
        assert_eq!(store.meta("a").unwrap(), None);

        store.atomically(|store| store.set_meta("a", b"2")).unwrap();
        assert_eq!(store.meta("a").unwrap().as_deref(), Some(b"2".as_slice()));
    }
}
