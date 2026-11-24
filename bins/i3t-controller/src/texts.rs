//! `i3t-controller` 的文字目录：帮助、管理令牌、启动时的错误，两种语言各一份。少写一项编译不过。

use i3t_controller::store::StoreError;
use i3t_lang::Lang;

#[derive(Debug)]
pub struct Texts {
    pub about: &'static str,
    pub data_dir: &'static str,
    pub database_url: &'static str,
    pub public_addr: &'static str,
    pub listen: &'static str,
    pub admin_listen: &'static str,
    pub static_dir: &'static str,
    pub reset_admin_token: &'static str,
    pub tcp_mss: &'static str,
    pub bad_mss: fn(u16, u16) -> String,
    pub dir: &'static str,
    pub url: &'static str,
    pub bytes: &'static str,
    pub host_port: &'static str,
    pub address: &'static str,
    pub start_runtime: &'static str,
    pub no_index_html: fn(&str) -> String,
    pub open_data_dir: fn(&str) -> String,
    pub bad_version: &'static str,
    pub reset_token: &'static str,
    pub admin_token: &'static str,
    pub admin_token_note: &'static str,
    pub bind: &'static str,
    pub run_failed: &'static str,
    pub not_data_dir: fn(&str, &str) -> String,
    pub bad_public_addr: fn(&str) -> String,
    pub io: fn(&str) -> String,
    pub key_file: fn(&str) -> String,
    pub key_mismatch: fn(&str) -> String,
    pub key_missing: fn(&str) -> String,
    pub key_generation: &'static str,
    pub no_database_url: fn(&str) -> String,
    pub read_database_url: &'static str,
    pub bad_database_url: &'static str,
    pub database_tls: &'static str,
    pub connect_database: &'static str,
    pub connect_timed_out: fn(u64) -> String,
    pub no_schema: &'static str,
    pub empty_database: &'static str,
    pub database: &'static str,
    pub newer_database: fn(u32, u32) -> String,
    pub tls: &'static str,
    pub bind_address: fn(&str) -> String,
    pub socket: &'static str,
    pub random: &'static str,
    pub internal: &'static str,
}

pub fn texts() -> &'static Texts {
    texts_in(i3t_lang::current())
}

pub const fn texts_in(lang: Lang) -> &'static Texts {
    match lang {
        Lang::ZhCn => &ZH,
        Lang::English => &EN,
    }
}

static ZH: Texts = Texts {
    about: "ice3tier controller：节点协议、管理 API 和 WebUI",
    data_dir: "数据目录：controller 的密钥和更新包的缓存。第一次启动时创建",
    database_url: "PostgreSQL 连接串，例如 postgres://用户:密码@主机/库名。网络、节点和配置均存储于此库中。未指定时读取数据目录中的 database.url",
    public_addr: "节点连接 controller 的对外地址，会写入每个注册令牌。主机部分可为域名",
    listen: "节点协议的监听地址（TCP；同端口的 UDP 用于响应地址探测）",
    admin_listen: "管理 API 和 WebUI 的监听地址。远程管理用 SSH 端口转发",
    static_dir: "从该目录加载 WebUI 静态文件，替代内置资源",
    reset_admin_token: "重新生成管理令牌后退出，旧令牌将失效。需在 controller 停止状态下执行",
    tcp_mss: "TCP 通告的最大分段长度（MSS）。当路径丢弃大包且不返回 ICMP 时，发送大分段会导致连接卡顿；设为 0 表示使用系统默认值",
    bad_mss: |low, high| format!("必须为 0，或介于 {low} 与 {high} 之间"),
    dir: "目录",
    url: "连接串",
    bytes: "字节",
    host_port: "主机:端口",
    address: "地址",
    start_runtime: "启动运行时",
    no_index_html: |dir| format!("静态文件目录 {dir} 里没有 index.html"),
    open_data_dir: |dir| format!("打开数据目录 {dir} 和数据库"),
    bad_version: "这个程序的版本号不合法",
    reset_token: "重新生成管理令牌",
    admin_token: "管理令牌（只显示这一次）：",
    admin_token_note: "i3tctl 和 WebUI 使用此令牌登录。如遗失，请先停止 controller，再使用 --reset-admin-token 重新生成。",
    bind: "绑定端口",
    run_failed: "controller 运行出错",
    not_data_dir: |dir, missing| format!("{dir} 中缺少 {missing}，不是有效的 controller 数据目录"),
    bad_public_addr: |address| format!("--public-addr 格式应为 主机:端口（如 ctl.example.com:20331），收到无效值 {address:?}"),
    io: |path| format!("读写 {path} 失败"),
    key_file: |path| format!("无法解析 controller 的密钥文件 {path}"),
    key_mismatch: |path| format!("{path} 与当前数据库中的 controller 身份不匹配：数据目录与数据库不一致"),
    key_missing: |path| format!("数据库中已存在 controller 数据，但缺少密钥文件 {path}：请还原备份的 controller.key"),
    key_generation: "生成 controller 的密钥失败",
    no_database_url: |path| format!("未指定数据库连接：请提供 --database-url（或环境变量 I3T_DATABASE_URL），或将连接串写入 {path}"),
    read_database_url: "读取数据库连接串",
    bad_database_url: "数据库连接串格式无效：应为 postgres://用户:密码@主机/库名",
    database_tls: "连接串要求启用 TLS（sslmode=require），但当前不支持数据库 TLS 连接：请将数据库部署在同机或可信内网中",
    connect_database: "无法连接数据库",
    connect_timed_out: |seconds| format!("连接数据库超时（已等待 {seconds} 秒）"),
    no_schema: "search_path 中无可用 schema，无法创建数据表",
    empty_database: "数据库中缺少 controller 数据表：连接串未指向已初始化的 controller 数据库",
    database: "数据库出错",
    newer_database: |found, supported| format!("数据库结构版本过高（当前为第 {found} 版，本程序最高支持第 {supported} 版）"),
    tls: "准备 TLS 失败",
    bind_address: |address| format!("绑定 {address} 失败"),
    socket: "网络端口出错",
    random: "系统的随机数源不可用",
    internal: "内部出错",
};

static EN: Texts = Texts {
    about: "ice3tier controller: node protocol, admin API and WebUI",
    data_dir: "Data directory: the controller key and the cache of update packages. Created on first start",
    database_url: "PostgreSQL connection string, e.g. postgres://USER:PASSWORD@HOST/DBNAME. Networks, nodes and settings are stored in this database. When not given, read from database.url in the data directory",
    public_addr: "Address nodes use to reach the controller, written into every enrollment token. The host may be a domain name",
    listen: "Node protocol listen address (TCP; UDP on the same port answers address queries)",
    admin_listen: "Admin API and WebUI listen address. For remote admin use SSH port forwarding",
    static_dir: "Serve the WebUI from this directory instead of the built-in one",
    reset_admin_token: "Issue a new admin token and exit; the old one stops working. Run while the controller is stopped",
    tcp_mss: "Maximum segment size TCP advertises. On paths that drop large packets without sending ICMP, connections stall at the first large segment; 0 uses the system's",
    bad_mss: |low, high| format!("must be 0, or between {low} and {high}"),
    dir: "DIR",
    url: "URL",
    bytes: "BYTES",
    host_port: "HOST:PORT",
    address: "ADDR",
    start_runtime: "Starting the runtime",
    no_index_html: |dir| format!("No index.html in the static directory {dir}"),
    open_data_dir: |dir| format!("Opening the data directory {dir} and the database"),
    bad_version: "This program's version is invalid",
    reset_token: "Issuing a new admin token",
    admin_token: "Admin token (shown only once):",
    admin_token_note: "i3tctl and the WebUI sign in with it. If lost, stop the controller and run it with --reset-admin-token.",
    bind: "Binding ports",
    run_failed: "Controller failed",
    not_data_dir: |dir, missing| format!("{dir} has no {missing}; it isn't a controller data directory"),
    bad_public_addr: |address| format!("--public-addr takes HOST:PORT, e.g. ctl.example.com:20331, not {address:?}"),
    io: |path| format!("Couldn't read or write {path}"),
    key_file: |path| format!("Controller key file {path} unreadable"),
    key_mismatch: |path| {
        format!("{path} is not the key of this database's controller: the data directory and the database don't belong together")
    },
    key_missing: |path| {
        format!(
            "The database holds an existing controller's data, but its key {path} is missing: put the controller.key from the backup back"
        )
    },
    key_generation: "Generating the controller key failed",
    no_database_url: |path| {
        format!("No database given: pass --database-url (or set I3T_DATABASE_URL), or write the connection string into {path}")
    },
    read_database_url: "Reading the database connection string",
    bad_database_url: "Not a valid connection string: write it as postgres://USER:PASSWORD@HOST/DBNAME",
    database_tls: "The connection string asks for TLS (sslmode=require), which this program doesn't support for the database: keep the database on the same machine or a trusted private network",
    connect_database: "Couldn't connect to the database",
    connect_timed_out: |seconds| format!("No connection to the database after {seconds} s"),
    no_schema: "None of the schemas in the search_path exists, so there is nowhere to create the tables",
    empty_database: "The database has no controller tables: the connection string doesn't point at this controller's database",
    database: "Database error",
    newer_database: |found, supported| {
        format!("The database was written by a newer version (schema {found}; this program knows up to {supported})")
    },
    tls: "Preparing TLS failed",
    bind_address: |address| format!("Couldn't bind {address}"),
    socket: "Network socket error",
    random: "System random source unavailable",
    internal: "Internal error",
};

/// 启动时的错误写成一行：这个程序自己加的说明按语言写，controller 库的错误按种类换成这种语言，系统的原话照抄。
pub fn describe(error: &anyhow::Error) -> String {
    let t = texts();
    i3t_lang::current().chain(error.chain().map(|cause| {
        if let Some(error) = cause.downcast_ref::<i3t_controller::Error>() {
            return controller_error(error, t);
        }
        if let Some(store) = cause.downcast_ref::<StoreError>() {
            return store_error(store, t);
        }
        cause.to_string()
    }))
}

fn controller_error(error: &i3t_controller::Error, t: &Texts) -> String {
    use i3t_controller::Error;
    match error {
        Error::Io { path, .. } => (t.io)(&path.display().to_string()),
        Error::Key { path, .. } => (t.key_file)(&path.display().to_string()),
        Error::KeyMismatch { path } => (t.key_mismatch)(&path.display().to_string()),
        Error::KeyMissing { path } => (t.key_missing)(&path.display().to_string()),
        Error::KeyGeneration(_) => t.key_generation.to_owned(),
        Error::Store(store) => store_error(store, t),
        Error::Tls(_) => t.tls.to_owned(),
        Error::Bind { address, .. } => (t.bind_address)(&address.to_string()),
        Error::Socket(_) => t.socket.to_owned(),
        Error::NotDataDir { dir, missing } => (t.not_data_dir)(&dir.display().to_string(), missing),
        Error::Random => t.random.to_owned(),
        // 启动时不会遇到的种类（管理请求的错误）：只说内部出错，细节在日志里。
        _ => t.internal.to_owned(),
    }
}

fn store_error(error: &StoreError, t: &Texts) -> String {
    match error {
        StoreError::BadConnectionString => t.bad_database_url.to_owned(),
        StoreError::TlsUnsupported => t.database_tls.to_owned(),
        StoreError::Connect(_) | StoreError::Disconnected => t.connect_database.to_owned(),
        StoreError::ConnectTimedOut(limit) => (t.connect_timed_out)(limit.as_secs()),
        StoreError::NoSchema => t.no_schema.to_owned(),
        StoreError::Empty => t.empty_database.to_owned(),
        StoreError::NewerSchema { found, supported } => (t.newer_database)(*found, *supported),
        // 以后的版本新加的种类：说是数据库出错，细节在后面的来源里。
        _ => t.database.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use i3t_lang::cli::{CLAP_ENGLISH, all_help, has_chinese, try_parse_from};

    use super::*;

    const DATABASE: &str = "postgres://i3t:secret@127.0.0.1/i3t";

    #[test]
    fn the_help_is_written_in_each_language_without_the_other() {
        for lang in Lang::ALL {
            i3t_lang::cli::localize(crate::command(lang), lang).debug_assert();
        }
        for (path, help) in all_help(crate::command(Lang::English), Lang::English) {
            assert!(!has_chinese(&help), "{path}：\n{help}");
        }
        for (path, help) in all_help(crate::command(Lang::ZhCn), Lang::ZhCn) {
            for english in CLAP_ENGLISH {
                assert!(!help.contains(english), "{path} 的中文帮助里有 {english}：\n{help}");
            }
        }
        let args = ["i3t-controller", "--data-dir", "/tmp/x", "--database-url", DATABASE, "--public-addr", "ctl:20331"].map(OsString::from);
        assert!(try_parse_from::<crate::Args>(crate::command(Lang::English), Lang::English, args).is_ok());
    }

    #[test]
    fn the_database_comes_from_the_option_or_from_a_file_in_the_data_dir_and_its_password_never_shows() {
        let parse = |args: &[&str]| {
            let args = ["i3t-controller", "--data-dir", "/var/lib/x", "--public-addr", "ctl:20331"].iter().chain(args).map(OsString::from);
            try_parse_from::<crate::Args>(crate::command(Lang::English), Lang::English, args).unwrap()
        };
        let dir = tempfile::tempdir().unwrap();
        let given = parse(&["--database-url", DATABASE]).database_url;
        assert!(crate::database(dir.path(), given.as_deref()).is_ok());

        // 没有给、数据目录里也没有那个文件：说两种给法，带上文件的位置。
        let said = describe(&crate::database(dir.path(), None).unwrap_err());
        assert!(said.contains("--database-url") && said.contains("database.url"), "{said}");

        // 安装脚本写的文件，末尾带换行。空的环境变量当作没有给。
        std::fs::write(dir.path().join("database.url"), format!("{DATABASE}\n")).unwrap();
        assert!(crate::database(dir.path(), None).is_ok());
        assert!(crate::database(dir.path(), Some("")).is_ok());

        // 读不懂的连接串：只说要怎么写，不把它打出来，一个片段都不带。拼错了 postgres:// 的那一种，
        // 解析器的原话里是整个连接串；密码没加引号、里面有空格的那一种，原话里是密码的后半截。
        for bad in [
            "postgres://i3t:s3cret@db-host:notaport/i3t",
            "postgre://i3t:s3cret@db-host/i3t?x=1",
            "host=db-host user=i3t password=s3cret tail dbname=i3t",
        ] {
            for given in [parse(&["--database-url", bad]).database_url, None] {
                std::fs::write(dir.path().join("database.url"), bad).unwrap();
                let said = describe(&crate::database(dir.path(), given.as_deref()).unwrap_err());
                assert!(said.contains(EN.bad_database_url) || said.contains(ZH.bad_database_url), "{said}");
                for piece in ["s3cret", "db-host", "notaport", "tail", "postgre:"] {
                    assert!(!said.contains(piece), "{bad}：{said}");
                }
            }
        }

        // 空的 database.url 等于没有说；要 TLS 的不收，并且说为什么。
        std::fs::write(dir.path().join("database.url"), " \n").unwrap();
        let said = describe(&crate::database(dir.path(), None).unwrap_err());
        assert!(said.contains("--database-url") && said.contains("database.url"), "{said}");
        let said = describe(&crate::database(dir.path(), Some("postgres://i3t:s3cret@db-host/i3t?sslmode=require")).unwrap_err());
        assert!(said.contains("TLS") && !said.contains("s3cret"), "{said}");
    }

    #[test]
    fn a_new_admin_token_needs_only_the_data_dir_and_the_database() {
        let parse = |args: &[&str]| {
            let args = ["i3t-controller", "--data-dir", "/var/lib/x", "--database-url", DATABASE].iter().chain(args).map(OsString::from);
            try_parse_from::<crate::Args>(crate::command(Lang::English), Lang::English, args)
        };
        assert!(parse(&["--reset-admin-token"]).unwrap().reset_admin_token);
        assert!(parse(&[]).is_err(), "运行时要 --public-addr");
        assert!(parse(&["--public-addr", "ctl:20331", "--reset-admin-token"]).is_ok(), "原来带着 --public-addr 的写法照样能用");
    }

    #[test]
    fn refusals_to_issue_an_admin_token_are_written_in_the_language() {
        let error = anyhow::Error::new(i3t_controller::Error::Store(StoreError::Empty)).context(EN.reset_token);
        let said = describe(&error);
        if i3t_lang::current() == Lang::English {
            assert_eq!(said, format!("Issuing a new admin token: {}", EN.empty_database));
        }
        let error = i3t_controller::Error::NotDataDir { dir: "/tmp".into(), missing: "controller.key" };
        assert!(controller_error(&error, &ZH).contains("controller.key"));
        assert!(!has_chinese(&controller_error(&error, &EN)));
    }

    #[test]
    fn startup_errors_from_the_library_are_written_in_the_language() {
        let error = anyhow::Error::new(i3t_controller::Error::Bind {
            address: "127.0.0.1:20332".parse().unwrap(),
            source: std::io::Error::from(std::io::ErrorKind::AddrInUse),
        })
        .context((EN.open_data_dir)("/var/lib/i3t-controller"));
        let said = describe(&error);
        if i3t_lang::current() == Lang::English {
            assert!(!has_chinese(&said), "{said}");
        }
        assert!(said.contains("127.0.0.1:20332"), "{said}");
    }
}
