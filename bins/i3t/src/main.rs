//! `i3t`：ice3tier 的节点程序。
//!
//! 终端上的文字跟着系统的语言（见 `i3t_lang`），日志不翻译。

mod network;
#[cfg(windows)]
mod service;
mod show;
mod texts;
#[cfg(target_os = "linux")]
mod tune;

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{CommandFactory, Parser, Subcommand};
use i3t_agent::config::{Change, Config, InvalidConfig, Setting};
use i3t_agent::join::{JoinOptions, join};
use i3t_agent::node::{self, Outcome, Source, StopError};
use i3t_agent::program::Program;
use i3t_agent::state::StateDir;
use i3t_agent::{NO_RESTART_EXIT_CODE, RESTART_EXIT_CODE, Version, local, selfcheck};
use i3t_lang::Lang;
use i3t_lang::table::Fields;
use i3t_update::SelfCheckFailure;

use crate::texts::texts;

/// 这个程序的版本号：报给 controller 的、`i3t --version` 显示的、更新时和发布清单比的都是它。
///
/// 它就是这个包在 `Cargo.toml` 里的版本号。唯一的例外是编译时设了环境变量 `I3T_TEST_VERSION`：
/// 端到端测试要有"同一份代码、版本号不同"的两个程序才能把更新跑一遍，用它编出第二个。
/// 发布不用它：发布流水线会核对标签和 `Cargo.toml`，清单上的版本号和程序自己报的对不上时，节点的自检也不会放行。
//noinspection ALL
const VERSION: &str = match option_env!("I3T_TEST_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

// 帮助的文字在文字目录里（`texts`），由 `command` 按语言装上去，所以这里不写文档注释：clap 会把它们当成说明。
#[derive(Parser)]
#[command(name = "i3t", version = VERSION)]
struct Cli {
    #[arg(long, global = true, env = "I3T_STATE_DIR")]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Join {
        #[arg(long)]
        can_exit: bool,
        #[arg(long)]
        can_relay: bool,
        // 以前的声明，照收、不起作用：端口转发的目标由管理员打开。
        #[arg(long, hide = true)]
        can_forward: bool,
    },
    Run {
        #[arg(long)]
        r#static: Option<PathBuf>,
        // Windows 的服务控制管理器启动服务时带着它（见 `service`），不是给人用的。
        #[cfg(windows)]
        #[arg(long, hide = true)]
        service: bool,
    },
    // Windows 上把节点登记成系统服务、注销它。安装脚本用。
    #[cfg(windows)]
    #[command(hide = true)]
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    Set {
        #[arg(value_parser = parse_setting)]
        setting: Setting,
        value: String,
    },
    Status,
    Routes,
    Ping {
        node: String,
        #[arg(long, default_value_t = i3t_agent::ping::DEFAULT_COUNT, value_parser = clap::value_parser!(u32).range(1..=i64::from(i3t_agent::ping::MAX_COUNT)))]
        count: u32,
    },
    Key,
    Tune {
        #[arg(long)]
        apply: bool,
    },
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    Hosts {
        #[arg(long)]
        apply: bool,
        #[arg(long, conflicts_with = "apply")]
        remove: bool,
    },
    SelfCheck,
}

#[derive(Subcommand)]
enum NetworkCommand {
    Status,
    Cleanup,
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceCommand {
    Install,
    Uninstall,
}

/// `i3t hosts` 做什么：打印那一段、写进 hosts 文件（`--apply`）、从里面去掉（`--remove`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostsAction {
    Print,
    Apply,
    Remove,
}

/// `i3t set` 的设置项。解析的错误由节点的文字目录按语言写。
fn parse_setting(text: &str) -> Result<Setting, String> {
    text.parse().map_err(|error: anyhow::Error| error.to_string())
}

/// 命令行的定义，帮助按 `lang` 写。
fn command(lang: Lang) -> clap::Command {
    let (h, v) = (&texts::texts_in(lang).help, &texts::texts_in(lang).values);
    Cli::command()
        .about(h.about)
        .mut_arg("state_dir", |arg| arg.help(h.state_dir).value_name(v.dir))
        .mut_subcommand("join", |sub| {
            sub.about(h.join).mut_arg("can_exit", |arg| arg.help(h.can_exit)).mut_arg("can_relay", |arg| arg.help(h.can_relay))
        })
        .mut_subcommand("run", |sub| sub.about(h.run).mut_arg("static", |arg| arg.help(h.run_static).value_name(v.file)))
        .mut_subcommand("set", |sub| {
            sub.about(h.set)
                .mut_arg("setting", |arg| arg.value_name("can-exit|can-relay|relay-address|throughput-tests|profile|network|firewall|mtu"))
                .mut_arg("value", |arg| arg.value_name("on|off|low-footprint|balanced|high-throughput|IP:PORT|576-1500"))
        })
        .mut_subcommand("status", |sub| sub.about(h.status))
        .mut_subcommand("routes", |sub| sub.about(h.routes))
        .mut_subcommand("ping", |sub| {
            sub.about(h.ping)
                .mut_arg("node", |arg| arg.help(h.ping_node).value_name(v.node))
                .mut_arg("count", |arg| arg.help(h.ping_count).value_name(v.count))
        })
        .mut_subcommand("key", |sub| sub.about(h.key))
        .mut_subcommand("tune", |sub| sub.about(h.tune).mut_arg("apply", |arg| arg.help(h.tune_apply)))
        .mut_subcommand("network", |sub| {
            sub.about(h.network)
                .mut_subcommand("status", |sub| sub.about(h.network_status))
                .mut_subcommand("cleanup", |sub| sub.about(h.network_cleanup))
        })
        .mut_subcommand("hosts", |sub| {
            sub.about(h.hosts).mut_arg("apply", |arg| arg.help(h.hosts_apply)).mut_arg("remove", |arg| arg.help(h.hosts_remove))
        })
        .mut_subcommand("self-check", |sub| sub.about(h.self_check))
}

fn main() -> ExitCode {
    let lang = i3t_lang::set(Lang::detect());
    match run(i3t_lang::cli::parse(command(lang), lang)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("i3t: {}", lang.chain(error.chain()));
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    // 清理残留规则不需要状态目录，免得状态目录打不开时 systemd 的 ExecStopPost 也跟着失败。
    if matches!(cli.command, Command::Network { command: NetworkCommand::Cleanup }) {
        network::cleanup()?;
        return Ok(ExitCode::SUCCESS);
    }
    // 登记和注销服务也不碰状态目录：它由安装脚本建，访问控制也是脚本设的。
    #[cfg(windows)]
    if let Command::Service { command } = &cli.command {
        change_service(command)?;
        return Ok(ExitCode::SUCCESS);
    }
    let t = &texts().ui;
    let version: Version = VERSION.parse().context(t.bad_version)?;
    let state = StateDir::open(match cli.state_dir {
        Some(dir) => dir,
        None => default_state_dir()?,
    })?;
    match cli.command {
        Command::Join { can_exit, can_relay, can_forward } => {
            let mut token = String::new();
            std::io::stdin().read_to_string(&mut token).context(t.read_token)?;
            if can_forward {
                println!("{}", t.forward_by_admin);
            }
            let options = JoinOptions { can_exit, can_relay };
            let program = Program::detect(version)?;
            let netmap = current_thread()?.block_on(join(&state, &token, options, &program))?;
            println!("{}", (t.joined)(&netmap.network.name));
            let mut fields = Fields::new(2);
            fields.add(t.node, netmap.me.name.clone());
            fields.add(t.fqdn, format!("{}.{}", netmap.me.name, netmap.network.domain));
            fields.add(t.virtual_ip, netmap.me.virtual_ip.to_string());
            fields.add(t.config_file, state.config_path().display().to_string());
            fields.print();
            // 安装脚本装的 `i3t` 包装脚本在加入之后自己重启系统服务，这时不该再叫人去 `i3t run`。
            match std::env::var("I3T_SERVICE") {
                Ok(service) if !service.is_empty() => println!("{}", (t.start_service)(&service)),
                _ => {
                    // Windows 上装成了系统服务、加入的又是服务的那个状态目录：直接把服务启动起来。
                    #[cfg(windows)]
                    if runs_as_service(&state) {
                        println!("{}", (t.start_service)(service::NAME));
                        service::restart().context(texts().service.needs_admin)?;
                        return Ok(ExitCode::SUCCESS);
                    }
                    println!("{}", t.start_with_run);
                }
            }
        }
        #[cfg(windows)]
        Command::Run { r#static, service: true } => return run_as_service(state, version, r#static),
        Command::Run { r#static, .. } => {
            #[cfg(windows)]
            if runs_as_service(&state) {
                bail!((texts().service.run_is_service)(service::NAME));
            }
            match run_node(&state, &version, r#static, &LogTo::Stderr, shutdown_signal()) {
                Ok(Outcome::Stopped) => {}
                // 程序文件换过了：请看护程序（systemd 之类）把进程重新拉起来。
                Ok(Outcome::Restart) => return Ok(ExitCode::from(RESTART_EXIT_CODE)),
                Err(error) if is_unrecoverable(&error) => {
                    eprintln!("i3t: {}", i3t_lang::current().chain(error.chain()));
                    return Ok(ExitCode::from(NO_RESTART_EXIT_CODE));
                }
                Err(error) => return Err(error),
            }
        }
        Command::Set { setting, value } => {
            let change = setting.change(&value)?;
            if let Change::CanForward(_) = change {
                println!("{}", t.forward_by_admin);
                return Ok(ExitCode::SUCCESS);
            }
            Config::set(&state.config_path(), change)?;
            println!("{}", (t.setting_set)(&setting.to_string(), &change.to_string()));
            match change {
                Change::Declare(_, true) => println!("{}", t.declare_hint),
                Change::Profile(profile) => {
                    // 读不出上次的 netmap 只是少一句提示。
                    let chosen = state.netmap().ok().flatten().and_then(|netmap| netmap.me.profile);
                    if let Some(chosen) = chosen.filter(|chosen| *chosen != profile) {
                        println!("{}", (t.profile_chosen)(chosen.spelling()));
                    }
                }
                Change::Network(false) | Change::Firewall(false) => {
                    // 问的时候出错也当它在运行：只有确实没有节点在运行，才去拆上次留下的东西。
                    let running = current_thread()?.block_on(local::query(&state)).map_or(true, |live| live.is_some());
                    network::after_switch_off(running);
                }
                Change::Declare(_, false)
                | Change::CanForward(_)
                | Change::RelayAddress(_)
                | Change::ThroughputTests(_)
                | Change::Network(true)
                | Change::Firewall(true)
                | Change::Mtu(_) => {}
            }
        }
        Command::Status => {
            show::local(&state)?;
            match current_thread()?.block_on(local::query(&state))? {
                Some(live) => show::status(&live),
                None => println!("\n{}", t.not_running),
            }
        }
        Command::Routes => match current_thread()?.block_on(local::query(&state))? {
            Some(live) => show::routes(&live),
            None => bail!(t.routes_not_running),
        },
        Command::Ping { node, count } => match current_thread()?.block_on(local::ping(&state, &node, count))? {
            Some(report) => {
                if !show::ping(&node, &report) {
                    return Ok(ExitCode::FAILURE);
                }
            }
            None => bail!(t.routes_not_running),
        },
        Command::Key => println!("{}", state.key_or_generate()?.public()),
        Command::Tune { apply } => {
            let config = Config::load(&state.config_path())?;
            tune(config.port, apply)?;
        }
        Command::Network { command: NetworkCommand::Status } => {
            let live = current_thread()?.block_on(local::query(&state))?;
            network::status(&state, live.as_ref());
        }
        Command::Network { command: NetworkCommand::Cleanup } => unreachable!("Cleanup 已在打开状态目录之前处理"),
        #[cfg(windows)]
        Command::Service { .. } => unreachable!("Service 已在打开状态目录之前处理"),
        Command::Hosts { apply, remove } => {
            let action = match (apply, remove) {
                (true, _) => HostsAction::Apply,
                (false, true) => HostsAction::Remove,
                (false, false) => HostsAction::Print,
            };
            network::hosts(&state, action)?;
        }
        Command::SelfCheck => {
            // 不初始化日志：调用它的旧程序把标准错误的最后一段当作失败的原因报给 controller，那里只该有原因本身。
            if let Err(failure) = current_thread()?.block_on(selfcheck::self_check(&state, &version)) {
                eprintln!("{}", self_check_failure(&failure));
                return Ok(ExitCode::FAILURE);
            }
            println!("{}", (t.self_check_passed)(&version.to_string()));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// 启动并运行节点，直到 `shutdown` 完成，或者节点自己要求重新启动。日志写到 `log`。
fn run_node(
    state: &StateDir,
    version: &Version,
    r#static: Option<PathBuf>,
    log: &LogTo,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<Outcome> {
    let t = &texts().ui;
    let config = Config::load(&state.config_path())?;
    init_logging(config.log.level.as_str(), log);
    #[cfg(unix)]
    raise_open_file_limit();
    // 程序文件在哪里要趁早查：更新换过文件之后，系统报出来的就不是原来的位置了。
    let program = Program::detect(version.clone())?;
    let source = r#static.map_or(Source::Controller, Source::Static);
    let threads = node::starting_performance(state, &source)?.threads;
    let runtime = runtime(threads).context(t.start_runtime)?;
    runtime.block_on(node::run(state.clone(), source, program, threads, shutdown))
}

/// 这个状态目录里的节点是不是由系统服务运行的：服务登记着，目录就是服务用的那一个。
#[cfg(windows)]
fn runs_as_service(state: &StateDir) -> bool {
    let same = |a: &std::path::Path, b: &std::path::Path| matches!((a.canonicalize(), b.canonicalize()), (Ok(a), Ok(b)) if a == b);
    system_state_dir().is_some_and(|system| same(&system, state.path())) && service::is_installed()
}

/// 服务控制管理器启动的节点：日志写进状态目录里的文件（服务没有终端），停止的通知来自 SCM。
#[cfg(windows)]
fn run_as_service(state: StateDir, version: Version, r#static: Option<PathBuf>) -> anyhow::Result<ExitCode> {
    let log = state.path().join(SERVICE_LOG);
    let job = move |stop: service::Stop| match run_node(&state, &version, r#static, &LogTo::File(log.clone()), stop) {
        Ok(Outcome::Stopped) => 0,
        Ok(Outcome::Restart) => u32::from(RESTART_EXIT_CODE),
        Err(error) => {
            // 出错可能早于日志初始化（配置文件读不了），所以直接写进日志文件。
            append_line(&log, &format!("i3t: {}", i3t_lang::current().chain(error.chain())));
            // 重启也救不了的以 0 停止，服务控制管理器不再拉；别的它过一会儿重新启动。
            if is_unrecoverable(&error) { 0 } else { 1 }
        }
    };
    service::dispatch(job).context(texts().service.not_started_by_system)?;
    Ok(ExitCode::SUCCESS)
}

/// `i3t service install`、`i3t service uninstall`。
#[cfg(windows)]
fn change_service(command: &ServiceCommand) -> anyhow::Result<()> {
    let t = &texts().service;
    match command {
        ServiceCommand::Install => {
            let program = std::env::current_exe().context(t.needs_admin)?;
            service::install(&program).context(t.needs_admin)?;
            println!("{}", (t.installed)(service::NAME));
        }
        ServiceCommand::Uninstall => {
            service::uninstall().context(t.needs_admin)?;
            println!("{}", (t.uninstalled)(service::NAME));
        }
    }
    Ok(())
}

/// 这条错误重启也救不了：`i3t run` 应以 [`NO_RESTART_EXIT_CODE`]（78 / `EX_CONFIG`）退出，让 systemd 停止自动重启。
fn is_unrecoverable(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<InvalidConfig>() || cause.is::<StopError>())
}

/// 自检没有通过的原因，按这个程序的语言写。它会被旧程序收下、报给 controller。
fn self_check_failure(failure: &SelfCheckFailure) -> String {
    let t = &texts().ui;
    match failure {
        SelfCheckFailure::WrongVersion { expected, running } => (t.wrong_version)(&running.to_string(), expected),
        SelfCheckFailure::State(reason) => (t.state_unreadable)(reason),
        SelfCheckFailure::Handshake(reason) => (t.handshake_failed)(reason),
        SelfCheckFailure::HandshakeTimeout => (t.handshake_timeout)(i3t_update::self_check::HANDSHAKE_TIMEOUT.as_secs()),
    }
}

#[cfg(target_os = "linux")]
fn tune(port: u16, apply: bool) -> anyhow::Result<()> {
    tune::run(port, apply)
}

#[cfg(not(target_os = "linux"))]
fn tune(_port: u16, _apply: bool) -> anyhow::Result<()> {
    bail!(texts().ui.tune_linux_only)
}

/// `i3t run` 的运行时：一个工作线程时是单线程的运行时，多个时是多线程的（线程数由性能档位定，见 `i3t_agent::performance`）。
///
/// 同时让 glibc 的分配器尽快把空出来的内存还给系统。本机实验环境里空闲的节点因此少占约 1.4MB，满速搬运的 CPU 量不出差别。
fn runtime(threads: usize) -> std::io::Result<tokio::runtime::Runtime> {
    return_memory_promptly();
    if threads <= 1 {
        return tokio::runtime::Builder::new_current_thread().enable_all().build();
    }
    tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_all().build()
}

/// glibc 默认会把释放的内存留在进程里，大块的阈值还会随用量往上调，一次大流量之后常驻内存就降不下来。
/// 把两个阈值固定在 128KB：大于它的分配直接向系统要、用完就还，堆顶空出这么多就还。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn return_memory_promptly() {
    const THRESHOLD: libc::c_int = 128 * 1024;
    for (option, name) in [(libc::M_TRIM_THRESHOLD, "M_TRIM_THRESHOLD"), (libc::M_MMAP_THRESHOLD, "M_MMAP_THRESHOLD")] {
        // SAFETY: `mallopt` 只改分配器的参数，不碰任何调用方的内存；两个参数都是 glibc 认识的选项，值在它允许的范围里。
        // 这时还没有别的线程。
        if unsafe { libc::mallopt(option, THRESHOLD) } == 0 {
            tracing::warn!(option = name, "glibc 不接受这个分配器参数");
        }
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn return_memory_promptly() {}

/// 只做一两次网络往返的子命令用的运行时。
fn current_thread() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().context(texts().ui.start_runtime)
}

/// 节点的日志写到哪里。
enum LogTo {
    /// 标准错误：终端，或者 systemd、launchd 替它收着。
    Stderr,
    /// 一个文件。Windows 的服务没有终端，也没有人替它收标准错误。
    #[cfg(windows)]
    File(PathBuf),
}

/// Windows 上作为服务运行时的日志文件，在状态目录里。
#[cfg(windows)]
const SERVICE_LOG: &str = "i3t.log";

/// 日志文件超过这么大，下次启动时改名留作上一份（`i3t.log.old`），重新开始写。
#[cfg(windows)]
const SERVICE_LOG_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// 初始化日志。级别来自配置文件，可以用环境变量 `I3T_LOG` 临时覆盖（写法同 `RUST_LOG`，可以按模块设）。
fn init_logging(level: &str, to: &LogTo) {
    let filter = std::env::var("I3T_LOG").unwrap_or_else(|_| level.to_owned());
    let filter = tracing_subscriber::EnvFilter::try_new(&filter).unwrap_or_else(|err| {
        eprintln!("{}", (texts().ui.bad_log_env)(&filter, &err.to_string(), level));
        tracing_subscriber::EnvFilter::new(level)
    });
    let logs = tracing_subscriber::fmt().with_env_filter(filter);
    match to {
        // 输出到文件或者日志服务时不带颜色的控制符。
        LogTo::Stderr => logs.with_ansi(std::io::stderr().is_terminal()).with_writer(std::io::stderr).init(),
        #[cfg(windows)]
        LogTo::File(path) => match open_log(path) {
            Ok(file) => logs.with_ansi(false).with_writer(std::sync::Mutex::new(file)).init(),
            // 日志文件打不开不该让节点起不来。
            Err(_) => logs.with_ansi(false).with_writer(std::io::sink).init(),
        },
    }
}

/// 打开日志文件接着写；已经太大的先改名留作上一份。
#[cfg(windows)]
fn open_log(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    if std::fs::metadata(path).is_ok_and(|file| file.len() > SERVICE_LOG_MAX_BYTES) {
        // 改不了名就接着往原来的文件里写。
        let _kept = std::fs::rename(path, path.with_extension("log.old"));
    }
    std::fs::OpenOptions::new().create(true).append(true).open(path)
}

/// 往日志文件里添一行。写不进去就算了：这已经是报错的最后一条路。
#[cfg(windows)]
fn append_line(path: &std::path::Path, line: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _written = writeln!(file, "{line}");
    }
}

/// 把能同时打开的文件数的软上限抬到硬上限。
///
/// 经过本节点的每条流在入口或者出口上占一个文件描述符（客户端的连接、到目标的连接），每个数据报上下文占一个 UDP 端口。
/// 直接在终端里执行 `i3t run` 时软上限常常只有 1024，一千来条流就会让整个节点打不开新的连接。
/// 硬上限是系统允许这个用户自己抬到的数，抬上去不需要特权。装成系统服务时单元文件里另外设了 `LimitNOFILE`，这里只是兜底。
/// macOS 的硬上限常常写着"不限"，实际能抬到的是 `kern.maxfilesperproc`，`rlimit` 会按它取。
#[cfg(unix)]
fn raise_open_file_limit() {
    match rlimit::increase_nofile_limit(u64::MAX) {
        Ok(limit) => tracing::info!(limit, "能同时打开的文件数的上限"),
        Err(error) => tracing::warn!(%error, "无法抬高能同时打开的文件数的上限，流多时可能打不开新的连接"),
    }
}

/// 收到 Ctrl-C，或者（Unix 上）收到 SIGTERM 时完成。
async fn shutdown_signal() {
    let interrupt = interrupted(tokio::signal::ctrl_c());
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    () = interrupt => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(err) => {
                tracing::warn!("装不上 SIGTERM 的处理（{err}），只响应 Ctrl-C");
                interrupt.await;
            }
        }
    }
    #[cfg(not(unix))]
    interrupt.await;
}

/// 等 Ctrl-C（`ctrl_c` 是 [`tokio::signal::ctrl_c`] 的结果）。
///
/// 处理装不上时它立刻以错误结束；把这当作收到了信号，节点一启动就会停下，日志里还什么都没有。
/// 所以记下原因，然后一直等：Unix 上 SIGTERM 照样能让节点停下。
async fn interrupted(ctrl_c: impl Future<Output = std::io::Result<()>>) {
    if let Err(error) = ctrl_c.await {
        tracing::error!(%error, "装不上 Ctrl-C 的处理，Ctrl-C 停不了节点");
        std::future::pending::<()>().await;
    }
}

/// 装成系统服务时的状态目录：Unix 上是 `/var/lib/i3t`，Windows 上是 `%ProgramData%\i3t`。安装脚本建它。
fn system_state_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("ProgramData").filter(|value| !value.is_empty()).map(|base| PathBuf::from(base).join("i3t"))
    } else {
        Some(PathBuf::from("/var/lib/i3t"))
    }
}

/// 没有用 `--state-dir` 指定时状态目录放在哪里。
///
/// 装成系统服务时安装脚本会建好系统的那一个（[`system_state_dir`]），存在就用它；否则放在当前用户自己的目录里。
fn default_state_dir() -> anyhow::Result<PathBuf> {
    if let Some(system) = system_state_dir().filter(|system| system.is_dir()) {
        return Ok(system);
    }
    let from_env = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    let dir = if cfg!(windows) {
        from_env("LOCALAPPDATA").map(|base| base.join("i3t"))
    } else if cfg!(target_os = "macos") {
        from_env("HOME").map(|home| home.join("Library/Application Support/i3t"))
    } else {
        from_env("XDG_STATE_HOME").map(|base| base.join("i3t")).or_else(|| from_env("HOME").map(|home| home.join(".local/state/i3t")))
    };
    match dir {
        Some(dir) => Ok(dir),
        None => bail!(texts().ui.no_state_dir),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use i3t_lang::cli::{CLAP_ENGLISH, all_help, has_chinese, try_parse_from};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_ctrl_c_handler_that_cannot_be_installed_does_not_stop_the_node() {
        let hour = std::time::Duration::from_secs(3600);
        let not_installed = async { Err(std::io::Error::other("没有信号处理")) };
        assert!(tokio::time::timeout(hour, interrupted(not_installed)).await.is_err(), "装不上处理不等于收到了 Ctrl-C");
        tokio::time::timeout(hour, interrupted(async { Ok(()) })).await.expect("收到 Ctrl-C 就停");
    }

    #[test]
    fn the_help_of_every_command_is_written_in_each_language_without_the_other() {
        for lang in Lang::ALL {
            i3t_lang::cli::localize(command(lang), lang).debug_assert();
        }
        for (path, help) in all_help(command(Lang::English), Lang::English) {
            assert!(!has_chinese(&help), "{path} 的英文帮助里有中文：\n{help}");
        }
        for (path, help) in all_help(command(Lang::ZhCn), Lang::ZhCn) {
            for english in CLAP_ENGLISH {
                assert!(!help.contains(english), "{path} 的中文帮助里有 {english}：\n{help}");
            }
            assert!(has_chinese(&help), "{path}：\n{help}");
        }
    }

    #[test]
    fn commands_parse_and_a_wrong_setting_is_refused() {
        let parse = |args: &[&str]| try_parse_from::<Cli>(command(Lang::English), Lang::English, args.iter().map(OsString::from));
        assert!(matches!(parse(&["i3t", "set", "can-exit", "on"]).unwrap().command, Command::Set { setting: Setting::Declare(_), .. }));
        assert!(matches!(
            parse(&["i3t", "set", "profile", "low-footprint"]).unwrap().command,
            Command::Set { setting: Setting::Profile, .. }
        ));
        assert!(parse(&["i3t", "set", "can-fly", "on"]).is_err());
        assert!(parse(&["i3t", "connect", "nas", "22"]).is_err(), "i3t connect 去掉了：有虚拟网卡，直接连虚拟 IP");
        assert!(matches!(parse(&["i3t", "set", "network", "off"]).unwrap().command, Command::Set { setting: Setting::Network, .. }));
        assert!(matches!(parse(&["i3t", "set", "firewall", "off"]).unwrap().command, Command::Set { setting: Setting::Firewall, .. }));
        assert!(matches!(parse(&["i3t", "set", "mtu", "1400"]).unwrap().command, Command::Set { setting: Setting::Mtu, .. }));
        assert!(parse(&["i3t", "set", "intercept", "on"]).is_err(), "透明访问的开关没有了");
        assert!(matches!(parse(&["i3t", "network", "status"]).unwrap().command, Command::Network { command: NetworkCommand::Status }));
        assert!(matches!(parse(&["i3t", "network", "cleanup"]).unwrap().command, Command::Network { command: NetworkCommand::Cleanup }));
        assert!(matches!(parse(&["i3t", "hosts", "--apply"]).unwrap().command, Command::Hosts { apply: true, remove: false }));
        assert!(matches!(parse(&["i3t", "hosts", "--remove"]).unwrap().command, Command::Hosts { apply: false, remove: true }));
        assert!(parse(&["i3t", "hosts", "--apply", "--remove"]).is_err(), "写进去和去掉只能选一个");
    }

    #[test]
    fn permanent_run_errors_are_marked_unrecoverable_and_transient_errors_are_not() {
        for stop in [StopError::NotJoined, StopError::Revoked, StopError::Rejected] {
            let err = anyhow::Error::from(stop).context("外层上下文");
            assert!(is_unrecoverable(&err), "{stop:?} 应该判为重启也救不了");
        }
        let dir = tempfile::tempdir().unwrap();
        let bad_config = dir.path().join("config.toml");
        std::fs::write(&bad_config, "port = 0\n").unwrap();
        assert!(is_unrecoverable(&Config::load(&bad_config).unwrap_err()), "配置文件有错应该判为重启也救不了");

        let transient = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::AddrInUse)).context("绑定端口 20330");
        assert!(!is_unrecoverable(&transient), "临时性绑定失败应该继续允许重启");
    }

    #[cfg(unix)]
    #[test]
    fn the_soft_open_file_limit_is_raised_as_far_as_the_hard_limit_allows() {
        use rlimit::Resource;

        let (_, hard) = Resource::NOFILE.get().unwrap();
        let low = hard.min(256);
        Resource::NOFILE.set(low, hard).unwrap();

        raise_open_file_limit();

        let (soft, still_hard) = Resource::NOFILE.get().unwrap();
        assert_eq!(still_hard, hard, "硬上限不动");
        if cfg!(target_os = "linux") {
            assert_eq!(soft, hard);
        } else {
            assert!(soft > low || low == hard, "软上限应该抬上去了：{low} -> {soft}（硬上限 {hard}）");
        }
    }
}
