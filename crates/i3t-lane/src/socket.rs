//! lane 的 socket 选项，以及"立刻重置"。
//!
//! | 选项 | 值 | 为什么 |
//! |---|---|---|
//! | `TCP_NODELAY` | 开 | 流式的小块响应要立刻走 |
//! | 内核保活 | 静默 25 秒开始，间隔 10 秒，3 次 | lane 穿过家用路由器，静默久了映射会被悄悄回收；探测也让死掉的 lane 在一分钟左右被发现 |
//! | `TCP_USER_TIMEOUT`（Linux） | 空闲 90 秒；开流之后、对端第一次回话之前 15 秒；流里 120 秒 | 已发出的数据这么久没有被确认就判连接已死 |
//! | `TCP_RTO_MAX_MS`（Linux 6.15 起） | 2 秒 | 断网之后路一通，最多 2 秒就重传，不用等加倍了的重传定时器（见 `i3t_underlay::tcp_recovery`） |
//! | `TCP_NOTSENT_LOWAT`（Linux） | 128 KB | 内核里还没发出去的数据有上限，内存跟着有上限 |
//!
//! 流没有空闲时限：一个模型可以想好几分钟不说话。

use std::io;
use std::time::Duration;

use i3t_underlay::tcp_recovery::Recovery;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

const KEEPALIVE_IDLE: Duration = Duration::from_secs(25);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_PROBES: u32 = 3;

/// 空闲的 lane（池里的、控制 lane）的 `TCP_USER_TIMEOUT`。
pub(crate) const IDLE_USER_TIMEOUT: Duration = Duration::from_secs(90);
/// 开流之后、对端第一次回话之前的 `TCP_USER_TIMEOUT`。
///
/// 预先拨好的 lane 可能已经死了而本端还不知道（对端家宽重拨，旧地址上的连接不会收到重置）。
/// 活着的 lane 一个往返之内就确认开流的数据，这里给 15 秒，丢包重传几次也够；死了的 lane 不用等上 90 秒才失败。
pub(crate) const OPENING_USER_TIMEOUT: Duration = Duration::from_secs(15);
/// 流里的 `TCP_USER_TIMEOUT`。
pub(crate) const STREAM_USER_TIMEOUT: Duration = Duration::from_secs(120);

/// 内核里还没发出去的数据的上限。
const NOTSENT_LOWAT: u32 = 128 * 1024;

/// 给一条刚建立的 lane 设上选项（见模块文档）。
///
/// # Errors
///
/// 系统不让设。
pub(crate) fn configure(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let socket = SockRef::from(stream);
    let keepalive = TcpKeepalive::new().with_time(KEEPALIVE_IDLE).with_interval(KEEPALIVE_INTERVAL);
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "windows", target_os = "freebsd"))]
    let keepalive = keepalive.with_retries(KEEPALIVE_PROBES);
    socket.set_tcp_keepalive(&keepalive)?;
    // 重传上限总是和放弃时限一起设；内核没有上限这个选项时照旧只设放弃时限。之后各阶段只换放弃时限，上限留着。
    if !Recovery::giving_up_after(IDLE_USER_TIMEOUT).apply(stream) {
        set_user_timeout(stream, IDLE_USER_TIMEOUT);
    }
    limit_unsent(&socket)
}

/// 设置 `TCP_USER_TIMEOUT`。仅 Linux 与 Android 支持；设置失败仅导致失效连接检测变慢，因此不返回错误。
pub(crate) fn set_user_timeout(stream: &TcpStream, timeout: Duration) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Err(error) = SockRef::from(stream).set_tcp_user_timeout(Some(timeout)) {
        tracing::debug!(%error, "设置 TCP_USER_TIMEOUT 失败");
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = (stream, timeout);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn limit_unsent(socket: &SockRef<'_>) -> io::Result<()> {
    socket.set_tcp_notsent_lowat(NOTSENT_LOWAT)
}

/// 别的系统没有这个选项。发送缓冲由系统自己调，不去缩它：lane 上跑的是单条流，缩了只会限制吞吐。
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn limit_unsent(_socket: &SockRef<'_>) -> io::Result<()> {
    let _ = NOTSENT_LOWAT;
    Ok(())
}

/// 关闭时发 RST 而不是 FIN。流一开始就这样设，只有两个方向都正常结束了才改回去：
/// 中途出错、任务被取消、进程退出，对端看到的都是重置，被截断的数据不会看起来像正常结束。
pub(crate) fn rst_on_close(stream: &TcpStream) {
    if let Err(error) = stream.set_zero_linger() {
        tracing::warn!(%error, "设置 SO_LINGER 失败，lane 中途断开时对端可能视为正常关闭");
    }
}

/// 两个方向都正常结束了：关闭时按正常的 FIN 走。本端写的一半要已经用 [`finish_write`] 关掉。
pub(crate) fn graceful_close(stream: &TcpStream) {
    if let Err(error) = i3t_underlay::tcp_reset::graceful_close(stream) {
        tracing::debug!(%error, "禁用 SO_LINGER 失败，关闭 lane 时可能发送 RST");
    }
}

/// 现在就重置连接，不等最后一个持有者把它关掉。
///
/// 原始字节的方向上，重置是告诉对端"异常结束"的唯一办法，越早越好。Linux 上对 TCP socket 做一次
/// "连接到 AF_UNSPEC"就是断开：内核立刻发 RST，之后这个 socket 上的读写都出错。别的系统上只能等它被关闭
/// （[`rst_on_close`] 保证那时发的是 RST）。
pub(crate) fn reset_now(stream: &TcpStream) {
    rst_on_close(stream);
    #[cfg(target_os = "linux")]
    if let Err(error) = rustix::net::connect_unspec(stream) {
        tracing::debug!(%error, "立即重置 lane 失败，将在连接关闭时发送 RST");
    }
}

/// 关掉写的一半（发 FIN），关闭时照样发 RST：异常结束之后用。
pub(crate) fn shutdown_write(stream: &TcpStream) -> io::Result<()> {
    SockRef::from(stream).shutdown(std::net::Shutdown::Write)
}

/// 正常结束写的一半（发 FIN）。macOS 上要赶在两个方向都关了之前改回正常关闭，见 `i3t_underlay::tcp_reset::shutdown_write`。
pub(crate) fn finish_write(stream: &TcpStream) -> io::Result<()> {
    i3t_underlay::tcp_reset::shutdown_write(stream)
}
