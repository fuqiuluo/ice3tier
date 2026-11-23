//! ice3tier 的 controller：节点协议、管理 API 和内嵌的 WebUI，一个进程。
//!
//! 这里只做装配：读参数，打开数据目录和数据库，绑端口，等退出信号。逻辑都在 `i3t-controller` 这个库里。
//! 终端上的文字（帮助、管理令牌、启动时的错误）跟着系统的语言，日志不翻译。
//!
//! 除了运行，还有一种做完就退出的用法：`--reset-admin-token`。它不需要 `--public-addr`，也不起运行时。

mod texts;

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{CommandFactory, Parser};
use i3t_controller::store::Database;
use i3t_controller::webui::{Asset, WebUi};
use i3t_controller::{Controller, ServeOptions, Server};
use i3t_lang::Lang;
use tracing_subscriber::EnvFilter;

/// 构建时打进来的 WebUI：`web/dist` 里的全部文件。构建的时候没有 `web/dist` 的话是空的（见 `build.rs`）。
static WEBUI: &[Asset] = include!(concat!(env!("OUT_DIR"), "/webui_assets.rs"));

/// 日志级别用这个环境变量调，写法和 `RUST_LOG` 相同，例如 `I3T_LOG=debug`。
const LOG_ENV: &str = "I3T_LOG";

// 帮助的文字在文字目录里（`texts`），由 `command` 按语言装上去，所以这里不写文档注释：clap 会把它们当成说明。
#[derive(Parser)]
#[command(name = "i3t-controller", version)]
struct Args {
    #[arg(long, env = "I3T_DATA_DIR")]
    data_dir: PathBuf,

    /// 连接串里有密码：帮助里不显示环境变量的值，也不交给 clap 解析（它报错时会把值原样打出来），由 [`database`] 来读。
    #[arg(long, env = "I3T_DATABASE_URL", hide_env_values = true)]
    database_url: String,

    #[arg(long, env = "I3T_PUBLIC_ADDR", required_unless_present = "reset_admin_token")]
    public_addr: Option<String>,

    #[arg(long, default_value = "0.0.0.0:20331")]
    listen: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:20332")]
    admin_listen: SocketAddr,

    #[arg(long)]
    static_dir: Option<PathBuf>,

    #[arg(long)]
    reset_admin_token: bool,

    #[arg(long, default_value_t = i3t_underlay::tcp_mss::DEFAULT, value_parser = parse_mss)]
    tcp_mss: u16,
}

/// `--tcp-mss`：0（用系统的），或者 [`i3t_underlay::tcp_mss::RANGE`] 之内。
fn parse_mss(text: &str) -> Result<u16, String> {
    let range = i3t_underlay::tcp_mss::RANGE;
    match text.parse::<u16>() {
        Ok(mss) if mss == 0 || range.contains(&mss) => Ok(mss),
        _ => Err((texts::texts().bad_mss)(*range.start(), *range.end())),
    }
}

/// 命令行的定义，帮助按 `lang` 写。
fn command(lang: Lang) -> clap::Command {
    let t = texts::texts_in(lang);
    Args::command()
        .about(t.about)
        .mut_arg("data_dir", |arg| arg.help(t.data_dir).value_name(t.dir))
        .mut_arg("database_url", |arg| arg.help(t.database_url).value_name(t.url))
        .mut_arg("public_addr", |arg| arg.help(t.public_addr).value_name(t.host_port))
        .mut_arg("listen", |arg| arg.help(t.listen).value_name(t.address))
        .mut_arg("admin_listen", |arg| arg.help(t.admin_listen).value_name(t.address))
        .mut_arg("static_dir", |arg| arg.help(t.static_dir).value_name(t.dir))
        .mut_arg("reset_admin_token", |arg| arg.help(t.reset_admin_token))
        .mut_arg("tcp_mss", |arg| arg.help(t.tcp_mss).value_name(t.bytes))
}

fn main() -> ExitCode {
    let lang = i3t_lang::set(Lang::detect());
    let args: Args = i3t_lang::cli::parse(command(lang), lang);
    let outcome = if args.reset_admin_token {
        reset_admin_token(&args)
    } else {
        match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime.block_on(serve(args)),
            Err(error) => {
                eprintln!("i3t-controller: {}", lang.labelled(texts::texts().start_runtime, &error.to_string()));
                return ExitCode::FAILURE;
            }
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("i3t-controller: {}", texts::describe(&error));
            ExitCode::FAILURE
        }
    }
}

/// 日志写到标准错误。`default` 是没有设 [`LOG_ENV`] 时的级别。
fn init_logging(default: &str) {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new(default));
    // 输出到文件或者日志服务时不带颜色的控制符。
    tracing_subscriber::fmt().with_env_filter(filter).with_ansi(std::io::stderr().is_terminal()).with_writer(std::io::stderr).init();
}

/// 读连接串。读不懂时只说哪里不对，不把连接串打出来：里面有密码。
fn database(url: &str) -> anyhow::Result<Database> {
    url.parse().map_err(|error| anyhow::Error::new(error).context(texts::texts().read_database_url))
}

/// 重新生成管理令牌，打在标准输出上。不需要对外地址，也不会在写错的目录或者空的库里建出一个新的 controller。
fn reset_admin_token(args: &Args) -> anyhow::Result<()> {
    init_logging("warn");
    let database = database(&args.database_url)?;
    let token = Controller::reset_admin_token(&args.data_dir, &database).context(texts::texts().reset_token)?;
    print_admin_token(&token);
    Ok(())
}

/// 令牌只在这里出现一次，直接写到标准输出，不进日志。
fn print_admin_token(token: &str) {
    let t = texts::texts();
    println!("{}\n\n    {token}\n", t.admin_token);
    println!("{}", t.admin_token_note);
}

async fn serve(args: Args) -> anyhow::Result<()> {
    let t = texts::texts();
    init_logging("info");
    abort_on_panic();
    let public_addr = args.public_addr.expect("clap 保证：运行时 --public-addr 是必须写的");
    check_public_addr(&public_addr)?;
    // 在监听之前：节点连进来的控制连接和管理 API 都按它通告 MSS（见 `i3t_underlay::tcp_mss`）。
    i3t_underlay::tcp_mss::set(args.tcp_mss);
    if let Some(dir) = &args.static_dir {
        // 目录写错了的话 WebUI 只会全是 404，不如启动时就说。
        if !dir.join("index.html").is_file() {
            bail!((t.no_index_html)(&dir.display().to_string()));
        }
    }

    let database = database(&args.database_url)?;
    let opened = Controller::open(&args.data_dir, &database, public_addr.clone())
        .with_context(|| (t.open_data_dir)(&args.data_dir.display().to_string()))?;
    // 发布清单里的"需要的 controller 最低版本"是和可执行文件的版本比的。
    let version = env!("CARGO_PKG_VERSION").parse().context(t.bad_version)?;
    let controller = opened.controller.with_version(version);
    if let Some(token) = opened.admin_token {
        print_admin_token(&token);
    }

    let webui = match args.static_dir {
        Some(dir) => WebUi::Dir(dir),
        None if WEBUI.is_empty() => WebUi::NotIncluded,
        None => WebUi::Embedded(WEBUI),
    };
    let webui_from = match &webui {
        WebUi::Dir(_) => "指定的目录",
        WebUi::Embedded(_) => "程序自带",
        WebUi::NotIncluded => "这次构建没有带",
    };
    let options = ServeOptions { node_listen: args.listen, admin_listen: args.admin_listen, webui, follow_releases: true };
    let server = Server::bind(Arc::new(controller), options).await.context(t.bind)?;
    tracing::info!(
        nodes = %server.node_addr().context(t.bind)?,
        admin = %server.admin_addr().context(t.bind)?,
        public = %public_addr,
        webui = webui_from,
        "controller 已启动"
    );
    if !args.admin_listen.ip().is_loopback() {
        tracing::warn!(admin = %args.admin_listen, "管理 API 没有绑在回环地址上：它是明文 HTTP，管理令牌会在网络上明文传输");
    }
    server.run(shutdown_signal()).await.context(t.run_failed)?;
    tracing::info!("controller 已停止");
    Ok(())
}

/// 等 Ctrl-C；在 Unix 上也等 SIGTERM（systemd 和容器停服务时发的是它）。
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!("监听 Ctrl-C 失败：{err}");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!("监听 SIGTERM 失败：{err}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!("收到退出信号，正在停止");
}

/// 注册令牌里的地址写错了，节点拿着令牌也连不上，而且要到那时才发现。所以启动时先看一眼它的样子对不对。
fn check_public_addr(address: &str) -> anyhow::Result<()> {
    let well_formed =
        address.rsplit_once(':').is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0));
    if !well_formed {
        bail!((texts::texts().bad_public_addr)(address));
    }
    Ok(())
}

/// 任何线程 panic 都让整个进程退出。
///
/// controller 的状态在一把锁后面，持锁的线程 panic 之后这把锁就中毒了，之后每个请求都会失败，
/// 进程却还活着、端口还开着。让它直接退出，由 systemd 之类的拉起来，比留着一个什么都做不了的进程好。
fn abort_on_panic() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::abort();
    }));
}
