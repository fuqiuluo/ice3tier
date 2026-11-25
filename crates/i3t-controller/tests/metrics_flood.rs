//! 不要令牌的 `/metrics`：客户端发出请求后立即断开，计算不会在阻塞线程池里累积。
//!
//! 按进程的线程数判断，所以单独一个测试程序：同一个程序里别的测试同时运行时会干扰计数。线程数从 `/proc` 读取，只在 Linux 上运行。

#![cfg(target_os = "linux")]
// clippy.toml 里的 allow-unwrap-in-tests 只认 `#[test]` 函数本身，无法识别这里的辅助函数。
#![allow(clippy::unwrap_used, reason = "整个文件都是测试代码，出错就该直接失败")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Running, fast_timing};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::oneshot;

/// 这个进程现在有几条线程。
fn threads() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find_map(|line| line.strip_prefix("Threads:")).expect("/proc/self/status 里有线程数");
    line.trim().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_requests_from_clients_that_hang_up_do_not_pile_up_in_the_blocking_pool() {
    /// 发出请求后断开的客户端个数。
    const CLIENTS: usize = 40;
    let running = Running::start(fast_timing()).await;

    // controller 卡在锁上：每一次 /metrics 的计算都要等它。若不加限制，每个已经交给阻塞线程池的计算各占用一条阻塞线程等待。
    let controller = Arc::clone(&running.controller);
    let (held, holding) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let stuck = tokio::task::spawn_blocking(move || {
        let _stalled = controller.stall();
        held.send(()).unwrap();
        released.recv().unwrap();
    });
    holding.await.unwrap();

    let before = threads();
    // 客户端逐个发出请求、等它开始处理，再断开。名额若不随计算一起交给阻塞线程池，断开时名额即被归还，下一个请求又能交出一次计算。
    for _ in 0..CLIENTS {
        let mut stream = TcpStream::connect(running.admin_addr).await.unwrap();
        stream.write_all(b"GET /metrics HTTP/1.1\r\nhost: controller\r\n\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(stream);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let grown = threads().saturating_sub(before);

    release.send(()).unwrap();
    stuck.await.unwrap();
    assert!(grown < 10, "{CLIENTS} 个发出请求后即断开的客户端使阻塞线程增加了 {grown} 条：同一时刻应当只有一次计算");

    // 放开之后照常回答。
    let answered = metrics_status_line(&running).await;
    assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
    running.shutdown().await;
}

/// 不带令牌请求一次 /metrics，返回应答的第一行。
async fn metrics_status_line(running: &Running) -> String {
    use tokio::io::AsyncReadExt;

    let mut stream = TcpStream::connect(running.admin_addr).await.unwrap();
    stream.write_all(b"GET /metrics HTTP/1.1\r\nhost: controller\r\nconnection: close\r\n\r\n").await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(common::PATIENCE, stream.read_to_end(&mut answer)).await.unwrap().unwrap();
    String::from_utf8_lossy(&answer).lines().next().unwrap_or_default().to_owned()
}
