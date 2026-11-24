//! 断网之后让节点之间的 TCP 尽快恢复。
//!
//! 一条 TCP 遇到一段完全不通（丢包的跨境链路上 15 到 30 秒并不少见），内核每重传一次就把重传定时器加倍，
//! 路通了之后要等下一次重传才发现：平均要再等断开时长的一半。给定时器设一个上限（`TCP_RTO_MAX_MS`，Linux 6.15 起），
//! 路通之后最多过一个上限就恢复。
//!
//! 只设上限会出事：内核是按重传的次数放弃连接的（`tcp_retries2`），上限低了次数很快用完。本机实验里上限 1 秒的连接
//! 在 20 秒的断开里死了，2 秒的在 40 秒里死了。所以上限永远和一个明确的放弃时限（`TCP_USER_TIMEOUT`）一起设：
//! 有了它内核按时间放弃，不再数次数。两项要么都设上，要么都不设（内核没有上限这个选项时就和以前一样）。
//!
//! 放弃时限由用的人按自己那一层的规矩定：TCP 不能先于上面那一层把连接判死，也不该在上面那一层已经换掉它之后还留着它。
//!
//! 只在 Linux 上有。别的系统上什么都不做。

use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsFd;

/// 重传定时器的上限。
///
/// 取 2 秒，不取 1 秒。断开 20 秒、40 秒之后，lane 在两种上限下都是两秒之内恢复（本机实验环境，`tests/e2e/test_recovery.py`）。
/// 上限低于这条路本来要的重传时间时（往返长、抖得厉害的跨境链路上常常过 1 秒），内核会在确认还在路上的时候就超时重传、
/// 把发送窗口收到最小。往返 600ms、抖动 120ms、丢包 0.5% 的路上下载两次 5MB：1 秒的上限超时重传 4 次和 15 次，2 秒 7 次和 4 次，
/// 不设 2 次和 6 次。样本少、起伏大，但方向是上限越低误判越多；多等一秒的恢复换这一份余量。
pub const RTO_MAX: Duration = Duration::from_secs(2);

/// 测试用的开关：环境变量 `I3T_TEST_TCP_RECOVERY=off` 时 [`Recovery::apply`] 什么都不设，用来和设了的情形对比。
#[cfg(any(target_os = "linux", target_os = "android"))]
const TEST_SWITCH: &str = "I3T_TEST_TCP_RECOVERY";

/// 一条 TCP 的重传上限和放弃时限，一起设。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    /// 重传定时器最长多久。内核只接受 1 秒到 120 秒。
    pub rto_max: Duration,
    /// 发出去的数据这么久没有得到确认，就放弃这条连接。
    pub give_up: Duration,
}

impl Recovery {
    /// 上限取 [`RTO_MAX`]，放弃时限取 `give_up`。
    #[must_use]
    pub const fn giving_up_after(give_up: Duration) -> Self {
        Self { rto_max: RTO_MAX, give_up }
    }

    /// 设到一条 TCP 上。返回两项是不是都设上了。
    ///
    /// 先设置放弃时限，再设置重传上限；若无法设置重传上限（内核不支持该选项），则清除放弃时限，使连接保持原默认行为。
    /// 设置失败不视为错误，仅意味着断网后的恢复速度较慢。
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn apply(self, socket: &impl AsFd) -> bool {
        if switched_off() {
            return false;
        }
        let sock = socket2::SockRef::from(socket);
        if let Err(error) = sock.set_tcp_user_timeout(Some(self.give_up)) {
            tracing::debug!(%error, "设置 TCP_USER_TIMEOUT 失败，跳过重传超时上限设置");
            return false;
        }
        match linux::set_rto_max(socket.as_fd(), self.rto_max) {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(%error, "无法设置 TCP 重传超时上限，接下来尝试清除 TCP_USER_TIMEOUT");
                if let Err(error) = sock.set_tcp_user_timeout(None) {
                    tracing::debug!(%error, "无法清除 TCP_USER_TIMEOUT 设置");
                }
                false
            }
        }
    }

    /// 别的系统上没有这两个选项的组合，什么都不设。
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn apply<S>(self, _socket: &S) -> bool {
        false
    }
}

/// 这个内核能不能给 TCP 的重传定时器设上限（Linux 6.15 起）。拿一个不连接的 TCP socket 试一下。
#[must_use]
pub fn rto_cap_supported() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let Ok(socket) = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP)) else {
            return false;
        };
        linux::set_rto_max(socket.as_fd(), RTO_MAX).is_ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        false
    }
}

/// 测试用的开关有没有关掉这两项。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn switched_off() -> bool {
    static OFF: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| std::env::var(TEST_SWITCH).is_ok_and(|value| value == "off"));
    *OFF
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::time::Duration;

    /// `linux/tcp.h` 里的 `TCP_RTO_MAX_MS`。libc 还没有收这个常量。
    const TCP_RTO_MAX_MS: libc::c_int = 44;

    /// 设 `TCP_RTO_MAX_MS`。socket2 和 rustix 都还没有这个选项，只能直接调 `setsockopt`。
    pub(super) fn set_rto_max(socket: BorrowedFd<'_>, cap: Duration) -> io::Result<()> {
        let millis = libc::c_int::try_from(cap.as_millis()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let len = libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("c_int 字节长度应可转换为 socklen_t");
        // SAFETY: `socket` 是有效的借用文件描述符；指针指向栈上的 `c_int`，长度即为其字节长度，内核只读不写，
        // 调用结束后不再使用该指针。内核不支持该选项时会返回错误，不会越界访问内存。
        let result = unsafe { libc::setsockopt(socket.as_raw_fd(), libc::IPPROTO_TCP, TCP_RTO_MAX_MS, (&raw const millis).cast(), len) };
        if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::os::fd::AsRawFd;

    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    fn rto_max_of(stream: &TcpStream) -> Option<u32> {
        let mut value: libc::c_int = 0;
        let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("一个 int 的长度装得进 socklen_t");
        // SAFETY: 测试里读一个 int 大小的选项，指针和长度都指向栈上的 `value`。
        let result = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::IPPROTO_TCP, 44, (&raw mut value).cast(), &raw mut len) };
        (result == 0).then(|| u32::try_from(value).expect("内核给的上限不是负数"))
    }

    #[tokio::test]
    async fn both_options_are_set_together_or_neither_is() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let recovery = Recovery::giving_up_after(Duration::from_secs(30));
        let applied = recovery.apply(&stream);
        let user_timeout = socket2::SockRef::from(&stream).tcp_user_timeout().unwrap();
        assert_eq!(applied, rto_cap_supported(), "内核支持时应设置成功，不支持时应返回 false");
        if applied {
            assert_eq!(user_timeout, Some(Duration::from_secs(30)));
            assert_eq!(rto_max_of(&stream), Some(2000));
        } else {
            assert_eq!(user_timeout, None, "重传上限设置失败时应同步清除 TCP_USER_TIMEOUT");
        }
    }
}
