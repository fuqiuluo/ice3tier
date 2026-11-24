//! 测试用的空数据库。
//!
//! 测试要一个真的 PostgreSQL，在哪里由环境变量 [`TEST_DATABASE_ENV`] 说：一个连接串，里面的用户要能在那个库里建 schema。
//! 每个 [`Scratch`] 在那个库里建一个名字不重样的 schema，给出去的连接把 `search_path` 指着它，
//! 所以并行的测试互不相干。丢掉时连同里面的表一起删。

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_postgres::Config;

use super::Database;
use super::session::Session;

/// 测试用的 PostgreSQL 的连接串放在这个环境变量里。
pub const TEST_DATABASE_ENV: &str = "I3T_TEST_DATABASE_URL";

const HOW_TO: &str = "这些测试需要一个 PostgreSQL 实例。可启动一个临时实例，并将连接串写入环境变量，例如：\n\n    \
    docker run -d --rm -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:5432:5432 postgres:17\n    \
    export I3T_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres\n";

/// 连接测试服务器的超时上限。大量测试并发建连时响应较慢（Windows 上每条连接需启动独立进程，在 CI 环境中排队时间可能超过
/// 默认的 10 秒），但这并非连接失败；真正无法连接时多等待一段时间也无妨。
const CONNECT_PATIENCE: Duration = Duration::from_secs(60);

/// 同一个进程里的第几个。
static NEXT: AtomicU32 = AtomicU32::new(0);

/// 一个空的数据库：测试服务器上的一个 schema。在它上面可以先后（或者同时）打开好几个 [`Store`](super::Store)，
/// 就像一个 controller 重启、或者另一个进程连同一个库。
pub struct Scratch {
    server: Config,
    schema: String,
}

impl Scratch {
    /// # Panics
    ///
    /// 环境变量 [`TEST_DATABASE_ENV`] 未设置或格式无效，或无法连接数据库及创建 schema。
    #[must_use]
    pub fn new() -> Self {
        let url = std::env::var(TEST_DATABASE_ENV).unwrap_or_else(|_| panic!("未设置环境变量 {TEST_DATABASE_ENV}。{HOW_TO}"));
        let Database(mut server) = url.parse().unwrap_or_else(|error| panic!("环境变量 {TEST_DATABASE_ENV} 格式无效：{error:?}"));
        server.connect_timeout(CONNECT_PATIENCE);
        // 进程号加序号在单机上不会重复；再附加纳秒时间戳，多机共用同一测试服务器时也不会冲突。
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.subsec_nanos());
        let schema = format!("i3t_test_{}_{}_{nanos:08x}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let session =
            Session::connect(&server).unwrap_or_else(|error| panic!("无法连接 {TEST_DATABASE_ENV} 指定的数据库：{error:?}\n{HOW_TO}"));
        session.batch(&format!("CREATE SCHEMA {schema}")).unwrap_or_else(|error| panic!("无法创建测试用 schema：{error:?}"));
        Self { server, schema }
    }

    /// 这个空数据库的 schema 的名字。
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// 连到这个空数据库的写法。
    #[must_use]
    pub fn database(&self) -> Database {
        self.database_with_path(&[&self.schema])
    }

    /// 连到同一个服务器，`search_path` 依次是这几个 schema。
    #[must_use]
    pub fn database_with_path(&self, schemas: &[&str]) -> Database {
        let mut config = self.server.clone();
        let search_path = format!("-c search_path={}", schemas.join(","));
        let options = match config.get_options() {
            Some(options) => format!("{options} {search_path}"),
            None => search_path,
        };
        config.options(options);
        Database(config)
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // 清理失败（例如测试服务器已关闭）可忽略：该服务器仅用于临时测试。
        if let Ok(session) = Session::connect(&self.server) {
            let _ = session.batch(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema));
        }
    }
}
