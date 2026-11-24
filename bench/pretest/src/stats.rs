//! 测量用的小工具：时间戳、进程 CPU 时间、延迟分布的汇总。

use std::time::{SystemTime, UNIX_EPOCH};

use hdrhistogram::Histogram;
use serde::Serialize;

/// 墙上时钟的纳秒数。同一台机器上的各个网络命名空间共用一个时钟，
/// 所以本机测试里可以直接用它算单向延迟；跨机器时只能用往返。
pub fn now_ns() -> u64 {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    u64::try_from(since_epoch.as_nanos()).unwrap_or(u64::MAX)
}

/// 本进程到现在为止用掉的资源。
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ProcessUsage {
    pub user_s: f64,
    pub sys_s: f64,
    /// 常驻内存的峰值。
    pub peak_rss_mb: f64,
}

impl ProcessUsage {
    /// 当前进程（所有线程）消耗的 CPU 时间和内存峰值。无法读取时返回 `None`，报告中将省略该项。
    pub fn of_this_process() -> Option<Self> {
        match platform::usage() {
            Ok(usage) => Some(usage),
            Err(err) => {
                eprintln!("无法读取当前进程的资源占用：{err:#}");
                None
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use anyhow::Context;

    use super::ProcessUsage;

    /// 读 `/proc` 而不是调 `getrusage`，免得为几个数字写 unsafe。
    pub fn usage() -> anyhow::Result<ProcessUsage> {
        // `/proc/self/stat` 里的时间单位固定是 1/100 秒。
        const TICKS_PER_SEC: f64 = 100.0;
        let stat = std::fs::read_to_string("/proc/self/stat").context("读 /proc/self/stat")?;
        // 第 2 个字段是带括号的进程名，里面可能有空格，所以从最后一个 ')' 之后开始数。
        let after_name = stat.rsplit_once(')').map(|(_, rest)| rest).context("/proc/self/stat 格式不对")?;
        let mut fields = after_name.split_whitespace().skip(11);
        let mut ticks = || -> anyhow::Result<f64> {
            let field = fields.next().context("/proc/self/stat 字段不够")?;
            Ok(field.parse::<f64>()? / TICKS_PER_SEC)
        };
        Ok(ProcessUsage { user_s: ticks()?, sys_s: ticks()?, peak_rss_mb: peak_rss_mb()? })
    }

    fn peak_rss_mb() -> anyhow::Result<f64> {
        let status = std::fs::read_to_string("/proc/self/status").context("读 /proc/self/status")?;
        let kb = status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|rest| rest.split_whitespace().next())
            .context("/proc/self/status 里没有 VmHWM")?;
        Ok(kb.parse::<f64>()? / 1024.0)
    }
}

#[cfg(windows)]
mod platform {
    use std::io;

    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    use super::ProcessUsage;

    /// FILETIME 的单位是 100 纳秒。
    fn seconds(time: FILETIME) -> f64 {
        let ticks = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        ticks as f64 / 1e7
    }

    pub fn usage() -> anyhow::Result<ProcessUsage> {
        const ZERO: FILETIME = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut exited, mut kernel, mut user) = (ZERO, ZERO, ZERO, ZERO);
        // SAFETY: GetCurrentProcess 返回的是永远有效的伪句柄；四个指针都指向本函数栈上的 FILETIME。
        let ok = unsafe { GetProcessTimes(GetCurrentProcess(), &mut created, &mut exited, &mut kernel, &mut user) };
        if ok == 0 {
            return Err(io::Error::last_os_error().into());
        }

        // SAFETY: PROCESS_MEMORY_COUNTERS 只含整数字段，全零是合法的取值。
        let mut memory: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        let size = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS>()).expect("结构体只有几十字节");
        memory.cb = size;
        // SAFETY: 句柄同上；指针指向栈上的结构体，size 是它的真实大小。
        let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut memory, size) };
        if ok == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(ProcessUsage {
            user_s: seconds(user),
            sys_s: seconds(kernel),
            peak_rss_mb: memory.PeakWorkingSetSize as f64 / (1024.0 * 1024.0),
        })
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::ProcessUsage;

    pub fn usage() -> anyhow::Result<ProcessUsage> {
        anyhow::bail!("这个平台上还没有实现")
    }
}

/// 延迟样本的收集器，内部单位是微秒。
pub struct LatencyRecorder {
    hist: Histogram<u64>,
}

impl LatencyRecorder {
    pub fn new() -> Self {
        // 3 位有效数字；上限 1 小时，足够装下"静默几分钟"的间隔。
        let hist = Histogram::new_with_bounds(1, 3_600_000_000, 3).expect("直方图的上下界是常量，一定合法");
        Self { hist }
    }

    pub fn record_ns(&mut self, ns: u64) {
        self.hist.saturating_record((ns / 1000).max(1));
    }

    pub fn summary(&self) -> LatencySummary {
        let ms = |us: u64| us as f64 / 1000.0;
        LatencySummary {
            count: self.hist.len(),
            min_ms: ms(self.hist.min()),
            p50_ms: ms(self.hist.value_at_quantile(0.50)),
            p95_ms: ms(self.hist.value_at_quantile(0.95)),
            p99_ms: ms(self.hist.value_at_quantile(0.99)),
            max_ms: ms(self.hist.max()),
            mean_ms: self.hist.mean() / 1000.0,
            stddev_ms: self.hist.stdev() / 1000.0,
        }
    }
}

impl Default for LatencyRecorder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct LatencySummary {
    pub count: u64,
    pub min_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    /// 标准差，当作抖动的度量。
    pub stddev_ms: f64,
}
