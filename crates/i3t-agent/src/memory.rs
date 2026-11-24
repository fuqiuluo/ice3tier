//! 把分配器手上空着的内存还给系统（低占用档位的一项，见 [`crate::performance`]）。
//!
//! glibc 释放的内存通常会保留在进程堆中以供后续分配，一次大流量过后常驻内存可能长期维持高位。启用该项后，
//! 每隔 [`PERIOD`] 让分配器把整页空着的内存还回去（`malloc_trim`）。本机实验环境里，空闲的入口因此再少 2.4MB 左右、
//! 出口 1.3MB、relay 1MB。忙的时候还回去的页马上又要重新要，所以只在低占用档位打开。只在用 glibc 的 Linux 上有。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// 多久还一次。空闲的节点几乎没有新的分配，一分钟一次足够。
const PERIOD: Duration = Duration::from_secs(60);

static RETURNING: AtomicBool = AtomicBool::new(false);

/// 打开或者关上定期归还（档位换了就跟着换）。
pub(crate) fn set_returning(on: bool) {
    RETURNING.store(on, Ordering::Relaxed);
}

/// 一直运行：打开着的时候每隔 [`PERIOD`] 归还一次。
pub(crate) async fn give_back() {
    let mut tick = tokio::time::interval(PERIOD);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if RETURNING.load(Ordering::Relaxed) {
            trim();
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn trim() {
    // SAFETY: `malloc_trim` 只整理 glibc 分配器自己的空闲块，不动任何还在用的内存；参数 0 是"不在堆顶留余量"。
    // 它内部有锁，任何线程随时都可以调用。
    let returned = unsafe { libc::malloc_trim(0) };
    tracing::trace!(returned, "把空着的内存还给系统");
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn trim() {}
