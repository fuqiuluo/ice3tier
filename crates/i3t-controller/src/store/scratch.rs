//! 测试用的空数据库。
//!
//! 测试要一个真的 PostgreSQL，在哪里由环境变量 [`TEST_DATABASE_ENV`] 说：一个连接串，里面的用户要能在那个库里建 schema。
//! 每个 [`Scratch`] 在那个库里建一个名字不重样的 schema，给出去的连接把 `search_path` 指着它，
//! 所以并行的测试互不相干。丢掉时连同里面的表一起删。

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio_postgres::Config;

use super::Database;
use super::session::Session;

/// 测试用的 PostgreSQL 的连接串放在这个环境变量里。
pub const TEST_DATABASE_ENV: &str = "I3T_TEST_DATABASE_URL";

const HOW_TO: &str = "这些测试要一个 PostgreSQL。起一个用完就扔的，再把连接串放进环境变量，比如：\n\n    \
    docker run -d --rm -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:5432:5432 postgres:17\n    \
    export I3T_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres\n";

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
    /// 环境变量 [`TEST_DATABASE_ENV`] 没有设、写得不对，或者连不上、建不了 schema。
    #[must_use]
    pub fn new() -> Self {
        let url = std::env::var(TEST_DATABASE_ENV).unwrap_or_else(|_| panic!("没有设 {TEST_DATABASE_ENV}。{HOW_TO}"));
        let Database(server) = url.parse().unwrap_or_else(|error| panic!("{TEST_DATABASE_ENV} 写得不对：{error:?}"));
        // 进程号加序号在一台机器上不重样；再加上时刻，几台机器共用一个测试服务器时也不撞。
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.subsec_nanos());
        let schema = format!("i3t_test_{}_{}_{nanos:08x}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let session =
            Session::connect(&server).unwrap_or_else(|error| panic!("连不上 {TEST_DATABASE_ENV} 说的数据库：{error:?}\n{HOW_TO}"));
        session.batch(&format!("CREATE SCHEMA {schema}")).unwrap_or_else(|error| panic!("建不了测试用的 schema：{error:?}"));
        Self { server, schema }
    }

    /// 连到这个空数据库的写法。
    #[must_use]
    pub fn database(&self) -> Database {
        let mut config = self.server.clone();
        let search_path = format!("-c search_path={}", self.schema);
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
        // 删不掉（服务器已经没了）也不要紧：那是个用完就扔的服务器。
        if let Ok(session) = Session::connect(&self.server) {
            let _ = session.batch(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema));
        }
    }
}
