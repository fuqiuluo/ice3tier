//! 运行期间对几个进程（入口、出口节点）的 CPU 时间和常驻内存采样，报告这次负载在它们身上花了多少。
//!
//! 进程可以按 pid 指定，也可以按节点的状态目录指定：命令行里带着这个目录的进程就是它。按目录指定时，
//! 进程中途重启了（pid 变了）也跟得上，CPU 时间按各个进程分段累加。只支持 Linux（读 `/proc`）。

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::watch;

/// `--watch` 的一项：`名字=pid` 或者 `名字=state:目录`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchSpec {
    pub name: String,
    pub target: WatchTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchTarget {
    Pid(u32),
    StateDir(PathBuf),
}

impl FromStr for WatchSpec {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (name, target) = text.split_once('=').ok_or_else(|| format!("{text:?} 应该写成 名字=pid 或者 名字=state:目录"))?;
        let target = match target.strip_prefix("state:") {
            Some(dir) => WatchTarget::StateDir(PathBuf::from(dir)),
            None => WatchTarget::Pid(target.strip_prefix("pid:").unwrap_or(target).parse().map_err(|_| format!("{target:?} 不是 pid"))?),
        };
        Ok(Self { name: name.to_owned(), target })
    }
}

/// 一个进程在这次运行期间的花费。
#[derive(Clone, Debug, Default, Serialize)]
pub struct Usage {
    pub name: String,
    /// 这段时间里用掉的 CPU 秒数（用户态加内核态）。
    pub cpu_s: f64,
    /// 平均占用了多少个核的百分比（100 是一个核满载）。
    pub cpu_pct: f64,
    pub rss_peak_mb: f64,
    pub rss_end_mb: f64,
    /// 采到过的不同 pid 的个数，大于 1 说明中途重启过。
    pub pids: usize,
    /// 有多少次采样没有找到进程。
    pub missing: u64,
}

/// 采样间隔。
const EVERY: Duration = Duration::from_millis(500);

/// 在后台采样，直到 `stop` 变成 `true`，然后返回每个进程的结果。
pub async fn sample(specs: Vec<WatchSpec>, mut stop: watch::Receiver<bool>) -> Vec<Usage> {
    let started = tokio::time::Instant::now();
    let mut trackers: Vec<Tracker> = specs.into_iter().map(Tracker::new).collect();
    let mut tick = tokio::time::interval(EVERY);
    loop {
        for tracker in &mut trackers {
            tracker.sample();
        }
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => break,
        }
    }
    for tracker in &mut trackers {
        tracker.sample();
    }
    let elapsed = started.elapsed().as_secs_f64().max(1e-3);
    trackers.into_iter().map(|tracker| tracker.finish(elapsed)).collect()
}

struct Tracker {
    spec: WatchSpec,
    /// 现在跟着的进程和它上一次采到的 CPU 时间。
    current: Option<(u32, f64)>,
    first: bool,
    usage: Usage,
    seen: Vec<u32>,
}

impl Tracker {
    fn new(spec: WatchSpec) -> Self {
        let usage = Usage { name: spec.name.clone(), ..Usage::default() };
        Self { spec, current: None, first: true, usage, seen: Vec::new() }
    }

    fn sample(&mut self) {
        let first = std::mem::replace(&mut self.first, false);
        let Some(pid) = self.find() else {
            self.usage.missing += 1;
            self.current = None;
            return;
        };
        let Some(Proc { cpu_s, rss_mb }) = Proc::read(pid) else {
            self.usage.missing += 1;
            self.current = None;
            return;
        };
        match self.current {
            Some((same, last)) if same == pid => self.usage.cpu_s += (cpu_s - last).max(0.0),
            // 运行开始时已经在跑的进程只算之后的；运行中途出现的（重启）从它启动算起。
            _ if first => {}
            _ => self.usage.cpu_s += cpu_s,
        }
        self.current = Some((pid, cpu_s));
        if !self.seen.contains(&pid) {
            self.seen.push(pid);
        }
        self.usage.rss_peak_mb = self.usage.rss_peak_mb.max(rss_mb);
        self.usage.rss_end_mb = rss_mb;
    }

    fn find(&self) -> Option<u32> {
        match &self.spec.target {
            WatchTarget::Pid(pid) => Some(*pid),
            WatchTarget::StateDir(dir) => find_by_argument(&dir.to_string_lossy()),
        }
    }

    fn finish(mut self, elapsed_s: f64) -> Usage {
        self.usage.cpu_pct = self.usage.cpu_s / elapsed_s * 100.0;
        self.usage.pids = self.seen.len();
        self.usage
    }
}

/// 从 `/proc` 读到的一个进程的状态。
struct Proc {
    cpu_s: f64,
    rss_mb: f64,
}

impl Proc {
    #[cfg(target_os = "linux")]
    fn read(pid: u32) -> Option<Self> {
        // `/proc/<pid>/stat` 里的时间单位是 1/100 秒（USER_HZ，Linux 上固定是 100）。
        const TICKS_PER_SEC: f64 = 100.0;
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // 第 2 个字段是带括号的进程名，里面可能有空格，所以从最后一个 ')' 之后开始数。
        let (_, rest) = stat.rsplit_once(')')?;
        let mut fields = rest.split_whitespace().skip(11);
        let user: f64 = fields.next()?.parse().ok()?;
        let system: f64 = fields.next()?.parse().ok()?;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let rss_kb: f64 = status.lines().find_map(|line| line.strip_prefix("VmRSS:"))?.split_whitespace().next()?.parse().ok()?;
        Some(Self { cpu_s: (user + system) / TICKS_PER_SEC, rss_mb: rss_kb / 1024.0 })
    }

    #[cfg(not(target_os = "linux"))]
    fn read(_pid: u32) -> Option<Self> {
        None
    }
}

/// 当前进程累计的 CPU 时间和内存峰值；无法读取时返回 `None`。
pub fn own_usage() -> Option<(f64, f64)> {
    let pid = std::process::id();
    let cpu = Proc::read(pid)?.cpu_s;
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let peak_kb: f64 = status.lines().find_map(|line| line.strip_prefix("VmHWM:"))?.split_whitespace().next()?.parse().ok()?;
    Some((cpu, peak_kb / 1024.0))
}

/// 命令行参数里有 `needle` 的那个进程（不算本进程）。有几个时取 pid 最小的，也就是最早启动的那个。
fn find_by_argument(needle: &str) -> Option<u32> {
    let own = std::process::id();
    std::fs::read_dir("/proc")
        .ok()?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| pid != own)
        .filter(|&pid| {
            std::fs::read(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|cmdline| cmdline.split(|&byte| byte == 0).any(|arg| arg == needle.as_bytes()))
        })
        .filter(|&pid| is_program(pid))
        .min()
}

/// 跳过 `ip netns exec` 这类包在外面的启动器：它们的命令行里也有那个目录，但本身不干活。
fn is_program(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|comm| !matches!(comm.trim(), "ip" | "unshare" | "sudo" | "timeout"))
}

/// 机器的 1 分钟平均负载，用来说明测量时机器有多忙。
pub fn loadavg() -> Option<f64> {
    std::fs::read_to_string("/proc/loadavg").ok()?.split_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_specs_name_a_pid_or_a_state_directory() {
        assert_eq!("entry=123".parse::<WatchSpec>().unwrap(), WatchSpec { name: "entry".into(), target: WatchTarget::Pid(123) });
        assert_eq!("exit=pid:7".parse::<WatchSpec>().unwrap().target, WatchTarget::Pid(7));
        assert_eq!("exit=state:/tmp/x".parse::<WatchSpec>().unwrap().target, WatchTarget::StateDir("/tmp/x".into()));
        assert!("entry".parse::<WatchSpec>().is_err());
        assert!("entry=abc".parse::<WatchSpec>().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_can_be_read_from_proc() {
        let me = Proc::read(std::process::id()).unwrap();
        assert!(me.rss_mb > 0.0);
        assert!(own_usage().is_some());
        assert!(loadavg().is_some());
    }
}
