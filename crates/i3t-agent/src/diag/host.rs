//! 测试项 `host`：测试期间这台机器、节点这个进程和它到对端的那条连接的状况。
//!
//! 不为它多发一个包、多等一秒：CPU 在测试开着的这段时间里每秒看一次，别的在测试做完时读一遍。
//! 主机与进程指标从 `/proc` 读取，因此仅在 Linux 平台可用；读取失败的指标各自为 `None`，连接相关指标在所有平台均可用。

use std::fs;
use std::time::Duration;

use i3t_conn::{ConnectionReport, Endpoint};
use i3t_model::control::Route;
use i3t_model::control::diag::{CpuUse, HostConnections, HostMemory, HostProcess, HostReport, HostSystem, PeerConnection};
use i3t_proto::NodeId;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::Diag;

/// 多久看一次 CPU。
const SAMPLE: Duration = Duration::from_secs(1);
/// 测试不到一秒就做完时，等头一秒的 CPU 量完最多等这么久。
const FIRST_SAMPLE_WAIT: Duration = Duration::from_secs(2);

/// 一个测试期间的观察：开始时记下到对端的连接的计数、开始每秒看一次 CPU，做完时出报告。
pub(super) struct Watch {
    sampler: JoinHandle<()>,
    cpu: watch::Receiver<CpuSeen>,
    /// 测试开始时到对端的连接（有的话）。
    before: Option<ConnectionReport>,
}

impl Watch {
    pub(super) fn start(endpoint: &Endpoint, peer: NodeId) -> Self {
        let (seen, cpu) = watch::channel(CpuSeen::default());
        Self { sampler: tokio::spawn(sample(seen)), cpu, before: endpoint.connection_report(peer) }
    }

    /// 测试做完了：这一端的报告。
    pub(super) async fn finish(mut self, diag: &Diag, peer: NodeId) -> HostReport {
        // 仅包含该测试项的测试可能不足一秒即完成，因此等待首秒采样结束；不支持 CPU 采集的平台采样任务已退出，此处会立即返回。
        if tokio::time::timeout(FIRST_SAMPLE_WAIT, self.cpu.wait_for(|seen| seen.first.is_some())).await.is_err() {
            tracing::debug!(%peer, "主动测试：等待首秒 CPU 采样超时");
        }
        self.sampler.abort();
        let seen = *self.cpu.borrow();
        let status = read("/proc/self/status");
        HostReport {
            system: Some(system()),
            cpu: seen.first,
            cpu_peak: seen.peak,
            load_x100: read("/proc/loadavg").as_deref().and_then(load_x100),
            memory: memory(read("/proc/meminfo").as_deref(), status.as_deref()),
            process: Some(HostProcess {
                uptime_secs: diag.started.elapsed().as_secs(),
                threads: status.as_deref().and_then(|status| field(status, "Threads:")).and_then(|threads| threads.parse().ok()),
            }),
            connections: Some(connections(diag)),
            to_peer: to_peer(&diag.endpoint, peer, self.before.as_ref()),
        }
    }
}

/// 测试期间见过的 CPU 占用。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CpuSeen {
    /// 头一秒。
    first: Option<CpuUse>,
    /// 最忙的一秒，两个数各取各的最大值。
    peak: Option<CpuUse>,
}

impl CpuSeen {
    fn add(&mut self, used: CpuUse) {
        self.first.get_or_insert(used);
        let peak = self.peak.get_or_insert(used);
        peak.system_percent = peak.system_percent.max(used.system_percent);
        peak.process_percent = peak.process_percent.max(used.process_percent);
    }
}

/// 每秒采样一次 CPU，直至任务被中止。无法读取（非 Linux 平台）时直接退出，接收端可通过发送端关闭感知无需继续等待。
async fn sample(seen: watch::Sender<CpuSeen>) {
    let Some(mut last) = CpuTimes::read() else { return };
    let mut tick = tokio::time::interval(SAMPLE);
    tick.tick().await;
    loop {
        tick.tick().await;
        let Some(now) = CpuTimes::read() else { return };
        if let Some(used) = now.since(last) {
            seen.send_modify(|seen| seen.add(used));
        }
        last = now;
    }
}

/// 某一时刻累计的 CPU 时间，单位是内核的时钟滴答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTimes {
    /// 整台机器所有的核加起来：一共过去了多少，其中不空闲的有多少。
    total: u64,
    busy: u64,
    /// 节点这个进程用掉的（用户态加内核态，所有线程）。
    process: u64,
    /// 机器有几个核在算（`/proc/stat` 里 `cpuN` 的行数）。
    cores: u64,
}

impl CpuTimes {
    fn read() -> Option<Self> {
        Self::parse(&read("/proc/stat")?, &read("/proc/self/stat")?)
    }

    /// `stat` 是 `/proc/stat`，`own` 是 `/proc/self/stat`。
    fn parse(stat: &str, own: &str) -> Option<Self> {
        let mut lines = stat.lines();
        // 第一行是所有核的合计：user nice system idle iowait irq softirq steal（后面的 guest 已经算在 user 里）。
        let times: Vec<u64> =
            lines.next()?.strip_prefix("cpu ")?.split_ascii_whitespace().take(8).map_while(|field| field.parse().ok()).collect();
        let [_, _, _, idle, iowait, ..] = times[..] else { return None };
        let total: u64 = times.iter().sum();
        let cores = lines.take_while(|line| line.starts_with("cpu")).count();
        // 进程名可以带空格和括号，从最后一个右括号往后数：状态是第 1 个，utime、stime 是第 12、13 个。
        let mut fields = own.rsplit_once(')')?.1.split_ascii_whitespace().skip(11);
        let (utime, stime): (u64, u64) = (fields.next()?.parse().ok()?, fields.next()?.parse().ok()?);
        Some(Self { total, busy: total.saturating_sub(idle + iowait), process: utime + stime, cores: u64::try_from(cores).ok()?.max(1) })
    }

    /// 计算自 `earlier` 至今的 CPU 使用率。若两次采样间隔过短导致时间未推进，则返回 `None`。
    fn since(self, earlier: Self) -> Option<CpuUse> {
        let total = self.total.checked_sub(earlier.total).filter(|&total| total > 0)?;
        let percent = |part: u64| u32::try_from(part.saturating_mul(100) / total).unwrap_or(u32::MAX);
        Some(CpuUse {
            system_percent: percent(self.busy.saturating_sub(earlier.busy)).min(100),
            // 该时间段内每个核心累计 total / cores 个时钟滴答，进程占用按单核折算。
            process_percent: percent(self.process.saturating_sub(earlier.process).saturating_mul(self.cores)),
        })
    }
}

fn read(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

/// `名字: 值 [单位]` 这种一行一项的文件里，`name`（带着冒号）那一项的值。
fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| line.strip_prefix(name)).and_then(|rest| rest.split_ascii_whitespace().next())
}

/// 同上，值的单位是 kB 的那些项，换成字节。
fn field_bytes(text: &str, name: &str) -> Option<u64> {
    field(text, name)?.parse::<u64>().ok()?.checked_mul(1024)
}

fn system() -> HostSystem {
    let os_release = read("/etc/os-release");
    let pretty = os_release.as_deref().and_then(|text| text.lines().find_map(|line| line.strip_prefix("PRETTY_NAME=")));
    let cpu_info = read("/proc/cpuinfo");
    let model =
        cpu_info.as_deref().and_then(|text| text.lines().find(|line| line.starts_with("model name"))).and_then(|line| line.split_once(':'));
    HostSystem {
        os: Some(pretty.map_or(std::env::consts::OS, |name| name.trim_matches('"')).to_owned()),
        kernel: read("/proc/sys/kernel/osrelease").map(|release| release.trim().to_owned()),
        arch: std::env::consts::ARCH.to_owned(),
        cpu_model: model.map(|(_, name)| name.trim().to_owned()),
        cores: std::thread::available_parallelism().ok().and_then(|cores| u32::try_from(cores.get()).ok()).unwrap_or(1),
        uptime_secs: read("/proc/uptime").as_deref().and_then(whole_seconds),
    }
}

/// `/proc/uptime` 的第一个数（带小数的秒）的整数部分。
fn whole_seconds(uptime: &str) -> Option<u64> {
    uptime.split_ascii_whitespace().next()?.split('.').next()?.parse().ok()
}

/// `/proc/loadavg` 开头的三个平均负载，乘 100。
fn load_x100(loadavg: &str) -> Option<[u32; 3]> {
    let mut loads = loadavg.split_ascii_whitespace().map(hundredths);
    Some([loads.next()??, loads.next()??, loads.next()??])
}

/// `"1.25"` 读成 125。内核写的总是两位小数；少了的位按 0 算。
fn hundredths(decimal: &str) -> Option<u32> {
    let (whole, fraction) = decimal.split_once('.').unwrap_or((decimal, ""));
    let fraction: u32 = format!("{fraction:0<2}").get(..2)?.parse().ok()?;
    whole.parse::<u32>().ok()?.checked_mul(100)?.checked_add(fraction)
}

/// `meminfo` 是 `/proc/meminfo`，`status` 是 `/proc/self/status`。
fn memory(meminfo: Option<&str>, status: Option<&str>) -> Option<HostMemory> {
    Some(HostMemory {
        total_bytes: field_bytes(meminfo?, "MemTotal:")?,
        available_bytes: field_bytes(meminfo?, "MemAvailable:")?,
        process_rss_bytes: field_bytes(status?, "VmRSS:")?,
    })
}

fn connections(diag: &Diag) -> HostConnections {
    let count = |count: u64| u32::try_from(count).unwrap_or(u32::MAX);
    let endpoint = &diag.endpoint;
    let peers = endpoint.peer_use();
    let lanes = diag.lanes.as_ref().map(|lanes| lanes.status());
    HostConnections {
        peers: u32::try_from(peers.len()).unwrap_or(u32::MAX),
        relays: u32::try_from(endpoint.attached().len()).unwrap_or(u32::MAX),
        relay_clients: diag.netmap.borrow().me.relay.is_some().then(|| count(endpoint.relay_counters().sessions)),
        streams: peers.iter().map(|peer| peer.flows).fold(0, u32::saturating_add),
        lanes_in_use: lanes.as_ref().map_or(0, |lanes| count(lanes.total.in_use)),
        lanes_idle: lanes
            .as_ref()
            .map_or(0, |lanes| count(lanes.peers.iter().map(|peer| peer.idle + peer.ready + peer.parked_at_peer).sum())),
    }
}

/// 这一端到对端的那条连接。计数是测试期间增加的：`before` 是测试开始时的同一条连接；
/// 开始时还没有连接、或者中间换了一条时，就是现在这条从建立起的。
fn to_peer(endpoint: &Endpoint, peer: NodeId, before: Option<&ConnectionReport>) -> Option<PeerConnection> {
    let micros = |duration: Duration| u32::try_from(duration.as_micros()).unwrap_or(u32::MAX);
    let now = endpoint.connection_report(peer)?;
    let counters = match before.filter(|before| before.established == now.established) {
        Some(before) => now.counters.since(before.counters),
        None => now.counters,
    };
    Some(PeerConnection {
        route: endpoint.path_report(peer).map_or(Route::None, |report| report.route),
        rtt_us: micros(now.rtt),
        min_rtt_us: Some(micros(now.min_rtt)),
        cwnd_bytes: now.cwnd_bytes,
        mtu: u32::from(now.mtu),
        congestion: now.congestion.to_string(),
        sent_packets: counters.sent_packets,
        lost_packets: counters.lost_packets,
        lost_bytes: counters.lost_bytes,
        congestion_events: counters.congestion_events,
        bytes_sent: counters.bytes_sent,
        bytes_received: counters.bytes_received,
        age_secs: now.established.elapsed().as_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两个核的机器：合计一行，再每个核一行。
    fn stat(user: u64, idle: u64) -> String {
        format!("cpu  {user} 0 0 {idle} 0 0 0 0 0 0\ncpu0 1 0 0 1 0 0 0 0 0 0\ncpu1 1 0 0 1 0 0 0 0 0 0\nintr 5\n")
    }

    /// `/proc/self/stat`：进程名里带空格和括号，utime、stime 是第 14、15 项。
    fn own(utime: u64, stime: u64) -> String {
        format!("4242 (i3t (run) x) S 1 4242 4242 0 -1 4194560 100 0 0 0 {utime} {stime} 0 0 20 0 6 0 1000 1 1")
    }

    #[test]
    fn cpu_use_is_the_share_of_the_machine_and_of_one_core_for_the_process() {
        let earlier = CpuTimes::parse(&stat(1000, 9000), &own(50, 10)).unwrap();
        assert_eq!(earlier, CpuTimes { total: 10_000, busy: 1000, process: 60, cores: 2 });
        // 一秒之后：两个核各走了 100 个滴答，一共 200；其中 60 个不空闲；进程用了 90 个，也就是一个核的九成。
        let now = CpuTimes::parse(&stat(1060, 9140), &own(120, 30)).unwrap();
        assert_eq!(now.since(earlier), Some(CpuUse { system_percent: 30, process_percent: 90 }));
        // 两个线程都跑满：按一个核算是 200。
        let both = CpuTimes::parse(&stat(1200, 9000), &own(250, 10)).unwrap();
        assert_eq!(both.since(earlier), Some(CpuUse { system_percent: 100, process_percent: 200 }));
        assert_eq!(earlier.since(earlier), None, "时间没有往前走");
    }

    #[test]
    fn what_cannot_be_parsed_is_none_instead_of_a_wrong_number() {
        assert_eq!(CpuTimes::parse("garbage", &own(1, 1)), None);
        assert_eq!(CpuTimes::parse(&stat(1, 1), "4242 no closing paren"), None);
        assert_eq!(CpuTimes::parse(&stat(1, 1), "4242 (i3t) S 1 2"), None);
        assert_eq!(load_x100("0.35 nonsense"), None);
        assert_eq!(memory(Some("MemTotal: 10 kB\n"), Some("VmRSS: 1 kB\n")), None, "少一样就整个没有");
    }

    #[test]
    fn the_busiest_second_keeps_each_figure_s_own_maximum() {
        let mut seen = CpuSeen::default();
        seen.add(CpuUse { system_percent: 10, process_percent: 3 });
        seen.add(CpuUse { system_percent: 80, process_percent: 20 });
        seen.add(CpuUse { system_percent: 40, process_percent: 97 });
        assert_eq!(seen.first, Some(CpuUse { system_percent: 10, process_percent: 3 }));
        assert_eq!(seen.peak, Some(CpuUse { system_percent: 80, process_percent: 97 }));
    }

    #[test]
    fn proc_files_are_read_as_whole_numbers() {
        assert_eq!(load_x100("0.35 1.07 12.5 2/345 6789\n"), Some([35, 107, 1250]));
        assert_eq!(hundredths("3"), Some(300));
        assert_eq!(whole_seconds("4123456.78 8000000.12\n"), Some(4_123_456));
        let meminfo = "MemTotal:        1017840 kB\nMemFree:          100000 kB\nMemAvailable:     598020 kB\n";
        let status = "Name:\ti3t\nVmRSS:\t   27648 kB\nThreads:\t6\n";
        assert_eq!(
            memory(Some(meminfo), Some(status)),
            Some(HostMemory { total_bytes: 1_017_840 * 1024, available_bytes: 598_020 * 1024, process_rss_bytes: 27_648 * 1024 })
        );
        assert_eq!(field(status, "Threads:"), Some("6"));
    }
}
