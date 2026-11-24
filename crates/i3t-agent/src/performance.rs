//! 性能档位：三个预设加上本机配置文件里逐项的覆盖，落实成一份设置 [`Performance`]。
//!
//! 每一项、每个值都是量出来的（本机实验环境，release 程序）。
//! 未测出显著差异的参数不纳入档位，保留为各 crate 内部常量。
//!
//! | 项（配置文件里的键） | low-footprint | balanced | high-throughput |
//! |---|---|---|---|
//! | 工作线程 `threads` | 1 | 2 | 4 |
//! | 每条流每个方向的搬运缓冲 `stream_buffer_kb` | 4 | 16 | 16 |
//! | 每条流的接收窗口 `stream_window_kb` | 1024 | 2048 | 2048 |
//! | 连接的收发窗口 `connection_window_mb` | 16 | 64 | 64 |
//! | 没有流之后多久关闭连接 `idle_close_secs`（0 是不关） | 60 | 300 | 0 |
//! | 定期把空着的内存还给系统 `return_memory` | 是 | 否 | 否 |
//!
//! - 线程：一条连接的包、它上面的流都在一个任务里或者互相唤醒，多一个工作线程就多一份跨核的唤醒和锁的争用。
//!   只有一个对端在忙时一个线程最快也最省（满速 10 Gbit/s、每 GB 0.7 秒 CPU；两个线程 7 Gbit/s、1.2 秒；四个 4.3 Gbit/s、2.2 秒），
//!   几个对端同时在忙时线程多才有用（四个对端经同一个出口：一个线程合计 9 Gbit/s，两个 15，四个 23，全部 14 个核也是 23）。
//!   档位不知道会有几个对端同时在忙，所以低占用取 1、默认取 2、高速度取 4；都不超过机器的核数。只有一个对端在忙的机器
//!   和纯粹的 relay（转发在一个任务里做完）用 `threads = 1` 最快。
//! - 搬运缓冲和窗口只影响内存的上限：2000 条开着的流，4KB 的缓冲比 16KB 少约 45MB；往不读数据的目标上传的 16 条流，
//!   1MB / 16MB 的窗口让出口压住的数据从 39MB 降到 18MB。代价是满速时每 GB 多两成 CPU，单条流的吞吐不超过"流窗口 ÷ 往返时间"。
//! - 空闲回收：一条空着的连接大约占 1.3MB 到 2.6MB，低占用早一点关；高速度不关，常用的对端开新流不用重新握手。
//! - 归还内存：见 [`crate::memory`]。
//!
//! 档位从哪里来：controller 给这个节点选了的话用它，否则用本机配置文件里的 `profile`（默认 balanced）。
//! 本机配置文件里单独写了的项总是盖过档位，因为它说的是这台机器自己的事。
//!
//! 什么时候生效：工作线程数在进程启动时定，换了档位要重启才变（上报里的 `restart_pending`）；别的项立刻生效，
//! 窗口对之后建立的连接生效，缓冲对之后开始的流生效。

use std::time::Duration;

use i3t_conn::{MAX_STREAM_WINDOW, Tuning};
use i3t_model::control::PerformanceReport;
use i3t_model::netmap::Profile;

use crate::config::PerformanceConfig;

/// 一个档位的预设值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Preset {
    threads: usize,
    stream_buffer_kb: u32,
    stream_window_kb: u32,
    connection_window_mb: u32,
    idle_close_secs: u64,
    return_memory: bool,
}

impl Preset {
    const fn of(profile: Profile) -> Self {
        match profile {
            Profile::LowFootprint => Self {
                threads: 1,
                stream_buffer_kb: 4,
                stream_window_kb: 1024,
                connection_window_mb: 16,
                idle_close_secs: 60,
                return_memory: true,
            },
            Profile::Balanced => Self {
                threads: 2,
                stream_buffer_kb: 16,
                stream_window_kb: 2048,
                connection_window_mb: 64,
                idle_close_secs: 300,
                return_memory: false,
            },
            Profile::HighThroughput => Self {
                threads: 4,
                stream_buffer_kb: 16,
                stream_window_kb: 2048,
                connection_window_mb: 64,
                idle_close_secs: 0,
                return_memory: false,
            },
        }
    }
}

/// 一个档位落实下来的全部设置：各个 crate 的数都从这里取。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Performance {
    pub profile: Profile,
    /// 运行时的工作线程数。1 是单线程的运行时。
    pub threads: usize,
    /// 每条流每个方向的搬运缓冲，字节。
    pub stream_buffer: usize,
    /// 连接层的设置。
    pub tuning: Tuning,
    /// 定期把分配器空着的内存还给系统。
    pub return_memory: bool,
    /// 本机配置文件单独改了的项（配置文件里的键名）。
    pub overrides: Vec<&'static str>,
}

impl Performance {
    /// 按档位和本机的覆盖算出全部设置。`chosen` 是管理员给这个节点选的档位（netmap 里的），没有选时用本机配置文件里的。
    #[must_use]
    pub fn resolve(chosen: Option<Profile>, local: &PerformanceConfig) -> Self {
        Self::resolve_on(chosen, local, cores())
    }

    fn resolve_on(chosen: Option<Profile>, local: &PerformanceConfig, cores: usize) -> Self {
        let profile = chosen.unwrap_or(local.profile);
        let preset = Preset::of(profile);
        let mut picked = Picked::default();
        let threads = picked.pick("threads", local.threads, u32::try_from(preset.threads.min(cores)).unwrap_or(1));
        let stream_buffer_kb = picked.pick("stream_buffer_kb", local.stream_buffer_kb, preset.stream_buffer_kb);
        let stream_window_kb = picked.pick("stream_window_kb", local.stream_window_kb, preset.stream_window_kb);
        let window_mb = picked.pick("connection_window_mb", local.connection_window_mb, preset.connection_window_mb);
        let idle_close_secs = picked.pick("idle_close_secs", local.idle_close_secs, preset.idle_close_secs);
        let return_memory = picked.pick("return_memory", local.return_memory, preset.return_memory);
        // 配置文件读进来时已经核对过范围（见 `PerformanceConfig`），这里的换算不会越界；越界了也只是取上限。
        let bytes = |amount: u32, unit: u32| amount.saturating_mul(unit);
        Self {
            profile,
            threads: usize::try_from(threads).unwrap_or(1).max(1),
            stream_buffer: usize::try_from(bytes(stream_buffer_kb, 1024)).unwrap_or(usize::MAX),
            tuning: Tuning {
                stream_window: bytes(stream_window_kb, 1024).min(MAX_STREAM_WINDOW),
                connection_window: bytes(window_mb, 1024 * 1024),
                idle_close: (idle_close_secs > 0).then(|| Duration::from_secs(idle_close_secs)),
            },
            return_memory,
            overrides: picked.keys,
        }
    }

    /// 报给 controller 的样子。`running_threads` 是这个进程启动时实际建的工作线程数。
    #[must_use]
    pub fn report(&self, running_threads: usize) -> PerformanceReport {
        PerformanceReport {
            profile: self.profile,
            threads: u32::try_from(running_threads).unwrap_or(u32::MAX),
            restart_pending: self.threads != running_threads,
            overrides: self.overrides.iter().map(|key| (*key).to_owned()).collect(),
        }
    }
}

/// 逐项取值：本机配置文件写了就用它（并且记下这一项被改过），没写就用档位的。
#[derive(Debug, Default)]
struct Picked {
    keys: Vec<&'static str>,
}

impl Picked {
    fn pick<T>(&mut self, key: &'static str, local: Option<T>, preset: T) -> T {
        if local.is_some() {
            self.keys.push(key);
        }
        local.unwrap_or(preset)
    }
}

/// 这台机器能用的核数。查不到时当作一个。
fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(text: &str) -> PerformanceConfig {
        crate::config::Config::parse(text).unwrap().performance
    }

    #[test]
    fn each_profile_has_its_own_values_and_threads_never_exceed_the_cores() {
        let low = Performance::resolve_on(Some(Profile::LowFootprint), &PerformanceConfig::default(), 8);
        assert_eq!((low.threads, low.stream_buffer, low.return_memory), (1, 4096, true));
        assert_eq!(low.tuning, Tuning { stream_window: 1 << 20, connection_window: 16 << 20, idle_close: Some(Duration::from_secs(60)) });
        let balanced = Performance::resolve_on(None, &PerformanceConfig::default(), 8);
        assert_eq!((balanced.profile, balanced.threads, balanced.stream_buffer), (Profile::Balanced, 2, 16 * 1024));
        assert_eq!(balanced.tuning, Tuning::default(), "默认档位就是今天的连接设置");
        let high = Performance::resolve_on(Some(Profile::HighThroughput), &PerformanceConfig::default(), 8);
        assert_eq!((high.threads, high.tuning.idle_close, high.return_memory), (4, None, false));
        let small_machine = Performance::resolve_on(Some(Profile::HighThroughput), &PerformanceConfig::default(), 2);
        assert_eq!(small_machine.threads, 2);
        assert!(low.overrides.is_empty() && balanced.overrides.is_empty() && high.overrides.is_empty());
    }

    #[test]
    fn the_controller_picks_the_profile_and_local_items_still_win() {
        let config = local("[performance]\nprofile = \"low-footprint\"\nthreads = 3\nidle_close_secs = 0\nreturn_memory = false\n");
        let alone = Performance::resolve_on(None, &config, 8);
        assert_eq!((alone.profile, alone.threads, alone.stream_buffer, alone.return_memory), (Profile::LowFootprint, 3, 4096, false));
        let chosen = Performance::resolve_on(Some(Profile::HighThroughput), &config, 8);
        assert_eq!(chosen.profile, Profile::HighThroughput, "管理员选的档位盖过本机的 profile");
        assert_eq!((chosen.threads, chosen.tuning.idle_close), (3, None), "本机单独写的项盖过档位");
        assert_eq!(chosen.overrides, ["threads", "idle_close_secs", "return_memory"]);
        assert_eq!(chosen.stream_buffer, 16 * 1024);
    }

    #[test]
    fn a_report_says_when_the_threads_need_a_restart() {
        let performance = Performance::resolve_on(Some(Profile::LowFootprint), &PerformanceConfig::default(), 8);
        let settled = performance.report(1);
        assert_eq!((settled.profile, settled.threads, settled.restart_pending), (Profile::LowFootprint, 1, false));
        assert!(performance.report(2).restart_pending, "跑着 2 个线程、档位要 1 个");
    }
}
