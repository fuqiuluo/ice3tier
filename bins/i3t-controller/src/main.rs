//! ice3tier 的 controller：节点协议、管理 API 和内嵌的 WebUI，一个进程。
//!
//! 这里只做装配：读参数，打开数据目录和数据库，绑端口，等退出信号。逻辑都在 `i3t-controller` 这个库里。
//! 终端上的文字（帮助、管理令牌、启动时的错误）跟着系统的语言，日志不翻译。
//!
//! 除常驻运行外，还支持一次性执行的 `--reset-admin-token` 模式，无需 `--public-addr`，也不启动异步运行时。

mod texts;

use std::io::{self, IsTerminal};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// 数据库的连接串也可以放在数据目录里的这个文件里，`--database-url` 和环境变量都没有给时读它。
/// 安装脚本把连接串写在这里（只有 controller 的用户读得了），所以只凭数据目录就能启动、就能重新生成管理令牌。
const DATABASE_URL_FILE: &str = "database.url";

/// 服务停止后关闭运行时，等待阻塞线程上未完成调用的最长时间。
///
/// 从发布源检查版本、下载更新包的调用可能持续数分钟，若一直等待，停服会超出 Docker Compose（默认 10 秒）或 systemd 的
/// 期限而被强制终止。数据库读写通常在此期限内完成。超过期限后进程直接退出：未提交的事务由数据库撤销，下载未完成的文件
/// 使用临时名称，下次重新下载。管理 API 与节点连接的收尾在此之前另有期限（目前各 3 秒，同时开始），停服合计约 6 秒。
const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

// 帮助的文字在文字目录里（`texts`），由 `command` 按语言装上去，所以这里不写文档注释：clap 会把它们当成说明。
#[derive(Parser)]
#[command(name = "i3t-controller", version)]
struct Args {
    #[arg(long, env = "I3T_DATA_DIR")]
    data_dir: PathBuf,

    /// 连接串里有密码：帮助里不显示环境变量的值，也不交给 clap 解析（它报错时会把值原样打出来），由 [`database`] 来读。
    #[arg(long, env = "I3T_DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,

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
        match block_on(serve(args), RUNTIME_SHUTDOWN_GRACE) {
            Ok(stopped) => {
                if stopped.abandoned_blocking {
                    tracing::warn!("停服时仍有阻塞调用（如发布源检查、更新包下载）在 {RUNTIME_SHUTDOWN_GRACE:?} 内未完成，已放弃等待");
                }
                // 在运行时关闭之后输出：关闭期间残留的阻塞调用仍可能输出日志。
                if stopped.output.is_ok() {
                    tracing::info!("controller 已停止");
                }
                stopped.output
            }
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

/// [`block_on`] 的结果。
struct Stopped<T> {
    output: T,
    /// 关闭运行时达到期限时仍有阻塞调用未完成，已放弃等待。
    abandoned_blocking: bool,
}

/// 在新建的多线程运行时上运行 `future` 直至完成，再关闭运行时，最多等待 `grace`。
///
/// # Errors
///
/// 无法创建运行时。
fn block_on<F: Future>(future: F, grace: Duration) -> io::Result<Stopped<F::Output>> {
    let runtime = tokio::runtime::Runtime::new()?;
    let output = runtime.block_on(future);
    let closing = Instant::now();
    // 直接 drop 运行时会无限期等待全部阻塞调用结束。
    runtime.shutdown_timeout(grace);
    // tokio 不返回是否超时，因此按耗时判断。阻塞调用恰好在期限到达时结束的情况也记为放弃，概率极小。
    Ok(Stopped { output, abandoned_blocking: closing.elapsed() >= grace })
}

/// 日志写到标准错误。`default` 是没有设 [`LOG_ENV`] 时的级别。
fn init_logging(default: &str) {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new(default));
    // 输出到文件或者日志服务时不带颜色的控制符。
    tracing_subscriber::fmt().with_env_filter(filter).with_ansi(std::io::stderr().is_terminal()).with_writer(std::io::stderr).init();
}

/// 解析数据库连接配置：优先使用 `--database-url`（或对应环境变量），未提供时读取数据目录中的 [`DATABASE_URL_FILE`]。
/// 解析失败时仅报告错误原因而不输出连接串，避免泄露密码。
fn database(data_dir: &Path, given: Option<&str>) -> anyhow::Result<Database> {
    let t = texts::texts();
    // 空的环境变量当作没有给。
    let text = match given.map(str::trim).filter(|url| !url.is_empty()) {
        Some(url) => url.to_owned(),
        None => {
            let path = data_dir.join(DATABASE_URL_FILE);
            match std::fs::read_to_string(&path) {
                // 一个空文件等于没有说：现在就讲，不等到连的时候才说没有主机。
                Ok(text) if text.trim().is_empty() => bail!((t.no_database_url)(&path.display().to_string())),
                Ok(text) => text.trim().to_owned(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => bail!((t.no_database_url)(&path.display().to_string())),
                Err(error) => return Err(anyhow::Error::new(error).context((t.io)(&path.display().to_string()))),
            }
        }
    };
    text.parse().map_err(|error| anyhow::Error::new(error).context(t.read_database_url))
}

/// 重新生成管理令牌，打在标准输出上。不需要对外地址，也不会在写错的目录或者空的库里建出一个新的 controller。
fn reset_admin_token(args: &Args) -> anyhow::Result<()> {
    init_logging("warn");
    let database = database(&args.data_dir, args.database_url.as_deref())?;
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

    let database = database(&args.data_dir, args.database_url.as_deref())?;
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
    server.run(shutdown_signal()).await.context(t.run_failed)
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

/// 若注册令牌中的对外地址格式有误，节点将无法连接且需到注册时才会暴露，因此启动时先做基本格式校验。
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
/// controller 的共享状态由互斥锁保护，若持锁线程发生 panic 会导致锁中毒，后续请求均会失败，
/// 但进程仍存活且继续占用端口。直接中止进程交由 systemd 等服务管理器拉起，优于保留无法提供服务的进程。
fn abort_on_panic() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::abort();
    }));
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;

    use tokio::sync::oneshot;

    use super::*;

    /// 测试用的期限：足以让短调用完成，又不使测试久等。
    const GRACE: Duration = Duration::from_millis(500);

    /// 在运行时上启动一个阻塞调用，等它开始执行后即返回，不等待其结束（与停服时被取消的后台任务一致）。
    /// 未开始执行的阻塞调用在运行时关闭时会被直接丢弃，所以必须等它开始。
    async fn start_blocking(call: impl FnOnce() + Send + 'static) {
        let (started, wait_started) = oneshot::channel();
        drop(tokio::task::spawn_blocking(move || {
            // 发送失败说明等待方已不在，无需处理。
            let _ = started.send(());
            call();
        }));
        wait_started.await.expect("阻塞调用在开始执行前被丢弃");
    }

    #[test]
    fn stopping_waits_for_short_blocking_calls() {
        let finished = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&finished);
        let call = move || {
            std::thread::sleep(Duration::from_millis(100));
            flag.store(true, Ordering::SeqCst);
        };
        let stopped = block_on(start_blocking(call), GRACE).unwrap();
        assert!(finished.load(Ordering::SeqCst), "关闭运行时未等待 100 毫秒的阻塞调用完成");
        assert!(!stopped.abandoned_blocking, "阻塞调用已在期限 {GRACE:?} 内完成，却记为放弃等待");
    }

    #[test]
    fn stopping_gives_up_on_long_blocking_calls() {
        let (release, wait_release) = mpsc::channel::<()>();
        let (done, wait_done) = mpsc::channel();
        let call = move || {
            // 关闭运行时之后由测试放行。最多阻塞 20 秒：关闭运行时若一直等待，测试以失败结束，不会一直挂起。
            let _ = wait_release.recv_timeout(Duration::from_secs(20));
            // 发送失败说明测试已结束，无需处理。
            let _ = done.send(());
        };
        let started = Instant::now();
        let stopped = block_on(start_blocking(call), GRACE).unwrap();
        let elapsed = started.elapsed();
        drop(release);
        assert!(elapsed < GRACE + Duration::from_secs(5), "关闭运行时等待了 {elapsed:?}，超出期限 {GRACE:?}");
        assert!(stopped.abandoned_blocking, "阻塞调用在期限 {GRACE:?} 内未完成，却未记为放弃等待");
        // 放行后阻塞线程随即结束，不留到测试进程退出。
        wait_done.recv_timeout(Duration::from_secs(5)).expect("放行后阻塞调用未在 5 秒内结束");
    }
}
