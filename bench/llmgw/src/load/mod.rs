//! 负载端：扮演 LLM 网关，按场景文件经代理入口向上游发流，验证每一条，测量，出报告。

mod client;
mod report;
mod scenario;
mod sse;
mod stats;
mod watch;
mod ws;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Args as ClapArgs;
use rustls::pki_types::ServerName;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use self::client::{GroupStats, Live, Run, Tally, Target, finish};
use self::report::{GroupReport, Report};
use self::scenario::{Kind, Scenario};
use self::stats::Episodes;
use self::watch::WatchSpec;
use crate::proxy::Proxy;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// 场景文件（TOML）
    #[arg(long)]
    scenario: PathBuf,
    /// 上游：https://主机[:端口] 或 http://主机[:端口]
    #[arg(long)]
    target: String,
    /// 代理：socks5://出口@127.0.0.1:1080、http://出口:密码@127.0.0.1:1081，或者 direct（不经代理，作为对照）
    #[arg(long, default_value = "direct")]
    proxy: Proxy,
    /// 上游的 CA 证书（上游 --cert-dir 里的 ca.pem）。https 时必须有
    #[arg(long)]
    ca: Option<PathBuf>,
    /// TLS 握手时用的服务器名，默认是 --target 里的主机
    #[arg(long)]
    sni: Option<String>,
    /// 结果写成 JSON 放在这里
    #[arg(long)]
    out: Option<PathBuf>,
    /// 采样这个进程的 CPU 和内存：名字=pid 或者 名字=state:节点的状态目录。可以写多次
    #[arg(long = "watch")]
    watch: Vec<WatchSpec>,
    /// 写进报告的说明，比如"丢包 1%"
    #[arg(long, default_value = "")]
    label: String,
    /// 不打进度行
    #[arg(long)]
    quiet: bool,
}

/// 解析 `--target`。
fn target(text: &str, ca: Option<&PathBuf>, sni: Option<&str>) -> anyhow::Result<Target> {
    let (scheme, rest) = text.split_once("://").context("--target 要写成 https://主机[:端口]")?;
    let rest = rest.trim_end_matches('/');
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        other => bail!("--target 的 scheme 只能是 https 或 http，不是 {other}"),
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && port.parse::<u16>().is_ok() => {
            (host.trim_matches(['[', ']']).to_owned(), port.parse()?)
        }
        _ => (rest.trim_matches(['[', ']']).to_owned(), default_port),
    };
    let authority = crate::proxy::authority(&host, port);
    let tls = match scheme {
        "https" => {
            let ca = ca.context("https 的上游要用 --ca 指定它的 CA 证书")?;
            let connector = TlsConnector::from(crate::tls::client_config(ca)?);
            let name =
                ServerName::try_from(sni.unwrap_or(&host).to_owned()).context("--sni 或者 --target 里的主机不能当作 TLS 的服务器名")?;
            Some((connector, name))
        }
        _ => None,
    };
    Ok(Target { host, port, authority, tls })
}

/// # Errors
///
/// 参数或者场景文件不对。流的失败不算错误，写在报告里，退出码是 1。
pub async fn run(args: Args) -> anyhow::Result<bool> {
    let scenario = Scenario::load(&args.scenario)?;
    let target = target(&args.target, args.ca.as_ref(), args.sni.as_deref())?;
    raise_open_files(&scenario);

    let start = Instant::now();
    let started_unix_ms = crate::wire::now_ns() / 1_000_000;
    let loadavg_start = watch::loadavg();
    let groups = scenario.groups.iter().map(|_| Mutex::new(GroupStats::default())).collect();
    let run = Arc::new(Run {
        deadline: start + Duration::from_secs_f64(scenario.duration_s),
        stall: Duration::from_millis(scenario.stall_ms),
        scenario,
        proxy: args.proxy.clone(),
        target,
        start,
        live: Live::default(),
        groups,
        stalls: Mutex::new(Vec::new()),
    });

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let watcher = tokio::spawn(watch::sample(args.watch.clone(), stop_rx.clone()));
    let progress = tokio::spawn(progress(run.clone(), stop_rx, args.quiet));

    let schedule = run.scenario.schedule();
    let total = schedule.len();
    let mut tasks = JoinSet::new();
    for (stream_no, (at, group, index)) in schedule.into_iter().enumerate() {
        let run = run.clone();
        let stream_no = u32::try_from(stream_no).context("流太多了")?;
        tasks.spawn(async move {
            tokio::time::sleep_until(run.start + at).await;
            one_stream(&run, group, index, stream_no).await;
        });
    }
    while let Some(joined) = tasks.join_next().await {
        joined.context("一条流的任务 panic 了")?;
    }
    let elapsed = start.elapsed();
    stop_tx.send_replace(true);
    let processes = watcher.await.context("采样任务 panic 了")?;
    let (peak_active, peak_events) = progress.await.context("进度任务 panic 了")?;

    let groups: Vec<GroupReport> = run
        .scenario
        .groups
        .iter()
        .zip(&run.groups)
        .map(|(spec, stats)| GroupReport::new(spec, &stats.lock().expect("组统计的锁不会中毒：持锁时不会 panic")))
        .collect();
    let spans = std::mem::take(&mut *run.stalls.lock().expect("卡顿记录的锁不会中毒：持锁时不会 panic"));
    let own = watch::own_usage();
    let events = run.live.events.load(Ordering::Relaxed);
    let report = Report {
        scenario: run.scenario.name.clone(),
        label: args.label.clone(),
        proxy: args.proxy.to_string(),
        target: args.target.clone(),
        started_unix_ms,
        elapsed_s: elapsed.as_secs_f64(),
        stall_ms: run.scenario.stall_ms,
        passed: groups.iter().all(|group| group.failed == 0),
        streams: u64::try_from(total).unwrap_or(u64::MAX),
        peak_active,
        peak_events_per_s: peak_events,
        events_per_s: events as f64 / elapsed.as_secs_f64().max(1e-3),
        stall_episodes: Episodes::from_spans(spans),
        groups,
        processes,
        load_cpu_s: own.map(|(cpu, _)| cpu),
        load_rss_peak_mb: own.map(|(_, rss)| rss),
        loadavg_start,
        loadavg_end: watch::loadavg(),
        cores: std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
    };
    print!("{}", report.table());
    if let Some(out) = &args.out {
        let json = serde_json::to_vec_pretty(&report).context("报告编成 JSON")?;
        std::fs::write(out, json).with_context(|| format!("写 {}", out.display()))?;
    }
    Ok(report.passed)
}

async fn one_stream(run: &Run, group: usize, index: usize, stream_no: u32) {
    let spec = &run.scenario.groups[group];
    let id = format!("{}-{index}", spec.name);
    let started = Instant::now();
    run.live.started.fetch_add(1, Ordering::Relaxed);
    run.live.active.fetch_add(1, Ordering::Relaxed);
    let mut tally = Tally::new(stream_no);
    let end = match spec.kind {
        Kind::Sse => sse::run(run, group, spec, u64::from(stream_no), &id, &mut tally).await,
        Kind::Ws => ws::run(run, group, spec, u64::from(stream_no), &id, &mut tally).await,
    };
    run.live.active.fetch_sub(1, Ordering::Relaxed);
    run.live.finished.fetch_add(1, Ordering::Relaxed);
    finish(run, group, spec, id, started, end, tally);
}

/// 每秒看一次在线流数和事件速率，记下峰值；不安静时每 5 秒打一行进度。返回 (在线峰值, 每秒事件峰值)。
async fn progress(run: Arc<Run>, mut stop: tokio::sync::watch::Receiver<bool>, quiet: bool) -> (u64, u64) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let (mut peak_active, mut peak_events, mut last_events, mut seconds) = (0, 0, 0, 0_u64);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return (peak_active, peak_events),
        }
        let active = run.live.active.load(Ordering::Relaxed);
        let events = run.live.events.load(Ordering::Relaxed);
        peak_active = peak_active.max(active);
        peak_events = peak_events.max(events - last_events);
        if !quiet && seconds % 5 == 0 && seconds > 0 {
            eprintln!(
                "  {:>4}s  在线 {active}，已开始 {}，已结束 {}，事件 {}/s",
                seconds,
                run.live.started.load(Ordering::Relaxed),
                run.live.finished.load(Ordering::Relaxed),
                events - last_events
            );
        }
        last_events = events;
        seconds += 1;
    }
}

/// 几千条流要几千个文件描述符（经代理时每条一个，直连对照时上游在本机的话再多一倍）。把软上限提到硬上限。
fn raise_open_files(scenario: &Scenario) {
    let streams: usize = scenario.groups.iter().map(|group| group.count).sum();
    let wanted = u64::try_from(streams * 2 + 256).unwrap_or(u64::MAX);
    match rlimit::increase_nofile_limit(wanted) {
        Ok(limit) if limit < wanted => eprintln!("警告：打开文件数上限仅能提高至 {limit}，{streams} 条流可能不足；请使用 ulimit -n 调高"),
        Ok(_) => {}
        Err(err) => eprintln!("警告：无法提高打开文件数上限（{err}），{streams} 条流可能不足"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_parse_with_default_ports_and_bracketed_ipv6() {
        let plain = target("http://11.0.0.6", None, None).unwrap();
        assert_eq!((plain.host.as_str(), plain.port, plain.authority.as_str()), ("11.0.0.6", 80, "11.0.0.6:80"));
        assert!(plain.tls.is_none());
        let v6 = target("http://[::1]:8080/", None, None).unwrap();
        assert_eq!((v6.host.as_str(), v6.port, v6.authority.as_str()), ("::1", 8080, "[::1]:8080"));
        assert!(target("https://api:443", None, None).is_err(), "https 没有 --ca 不行");
        assert!(target("ftp://api", None, None).is_err());
    }
}
