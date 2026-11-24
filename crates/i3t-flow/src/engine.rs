//! 在两条 TCP 之间搬字节：Linux 上用 `splice(2)` 在内核里搬，别处（以及要比较时）在用户态拷贝。
//!
//! 跑在 ice3proxy 上、不再加密的流（[`i3t_conn::RawRead`]、[`i3t_conn::RawWrite`]）底下就是一条普通的 TCP，
//! 和另一头（入口的客户端连接、出口到目标的连接）一样。两条 TCP 之间的搬运不需要把字节读进程序：
//!
//! - 每个方向：来源 → 管道 → 目标，非阻塞，由 tokio 的可读可写事件驱动。
//! - 只在目标可写时才从来源拉：目标写不动时数据留在来源的接收缓冲里，由 TCP 的流量控制把压力传回去，
//!   程序里不积压。
//! - 管道是池化的，每个 256 KB（比默认的 64 KB 系统调用少，每 GB 的 CPU 更低）；只在有字节在路上时占着，
//!   一条静默的流不占管道，只占它的两个 socket。
//! - 系统调用用 rustix 的安全封装，这里没有 `unsafe`。
//!
//! 结束语义与流契约一致：来源读到 EOF 时向目标发送 FIN（仅关闭写半部，另一方向继续）；任一端出错时，
//! 调用方把两头都重置，绝不能用 FIN 结束，否则被截断的数据看起来像正常结束。

use std::convert::Infallible;
use std::future::Future;
use std::io;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::net::TcpStream;

/// 只增不减的计数。
#[derive(Debug, Default)]
struct Counter(AtomicU64);

impl Counter {
    fn add(&self, n: usize) {
        // usize 不会比 u64 宽，这里不会截断。
        self.0.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// 两条 TCP 上的关闭方式。
mod socket {
    use tokio::net::TcpStream;

    /// 关闭时发 RST 而不是 FIN。
    pub(super) fn rst_on_close(stream: &TcpStream) {
        if let Err(error) = stream.set_zero_linger() {
            tracing::warn!(%error, "设置 SO_LINGER 失败，转发中断时对端可能视为正常关闭");
        }
    }

    /// 两个方向都正常结束了：关闭时按正常的 FIN 走。
    pub(super) fn graceful_close(stream: &TcpStream) {
        if let Err(error) = i3t_underlay::tcp_reset::graceful_close(stream) {
            tracing::debug!(%error, "禁用 SO_LINGER 失败，关闭连接时可能发送 RST");
        }
    }

    /// 现在就重置连接，不等最后一个持有者把它关掉。Linux 上"连接到 AF_UNSPEC"就是断开：内核立刻发 RST。
    /// 别的系统上只能等它被关闭（那时发的是 RST，见 [`rst_on_close`]）。
    pub(super) fn reset_now(stream: &TcpStream) {
        rst_on_close(stream);
        #[cfg(target_os = "linux")]
        if let Err(error) = rustix::net::connect_unspec(stream) {
            tracing::debug!(%error, "立即重置连接失败，将在连接关闭时发送 RST");
        }
    }

    /// 关掉写的一半（发 FIN）：这个方向正常结束了。macOS 上要赶在两个方向都关了之前改回正常关闭，见
    /// `i3t_underlay::tcp_reset::shutdown_write`。
    pub(super) fn shutdown_write(stream: &TcpStream) -> std::io::Result<()> {
        i3t_underlay::tcp_reset::shutdown_write(stream)
    }
}

/// 用户态拷贝时一次最多读多少。缓冲只在有数据时才分配，写完就还回去，静默的流不占。
const COPY_CHUNK: usize = 64 * 1024;

/// 搬每一段数据之前要过的关：计数、限速，或者叫停。
pub trait Gate: Send {
    /// 叫停时带出来的东西，原样交给调用方。
    type Stop: Send;

    /// `len` 字节刚从来源读出来（在管道或者缓冲里），还没写给目标。返回之前可以等（限速）。
    fn pass(&mut self, len: usize) -> impl Future<Output = Result<(), Self::Stop>> + Send;
}

/// 什么都不管的关。
#[derive(Debug, Clone, Copy, Default)]
pub struct Open;

impl Gate for Open {
    type Stop = Infallible;

    async fn pass(&mut self, _len: usize) -> Result<(), Infallible> {
        Ok(())
    }
}

/// 一个方向的搬运停在哪里。
#[derive(Debug, thiserror::Error)]
pub enum PumpError<S> {
    /// 读来源出错（对方重置了连接、保活超时）。
    #[error("读取来源数据失败")]
    Read(#[source] io::Error),
    /// 写目标出错，或者给目标发 FIN 出错。
    #[error("写入目标数据失败")]
    Write(#[source] io::Error),
    /// 关卡叫停了。
    #[error("转发被中止")]
    Stopped(S),
}

/// 一次双向搬运的结果。
#[derive(Debug)]
pub struct Relayed {
    pub a_to_b: u64,
    pub b_to_a: u64,
    /// `None`：两个方向都正常结束；否则是先出错的那个方向的错误，两头都已经重置。
    pub error: Option<PumpError<Infallible>>,
}

/// 搬运的引擎和它的管道池。一个节点共用一个。
#[derive(Debug)]
pub struct Splicer {
    #[cfg(target_os = "linux")]
    pipes: Option<linux::Pipes>,
    spliced: Counter,
    copied: Counter,
}

impl Default for Splicer {
    fn default() -> Self {
        Self::new()
    }
}

impl Splicer {
    /// Linux 上用 `splice(2)`，别处用户态拷贝。
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            pipes: Some(linux::Pipes::default()),
            spliced: Counter::default(),
            copied: Counter::default(),
        }
    }

    /// 一律用户态拷贝。用来比较，或者在 splice 不可用的环境里。
    #[must_use]
    pub fn copying() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            pipes: None,
            spliced: Counter::default(),
            copied: Counter::default(),
        }
    }

    /// 用 splice 搬了多少字节。
    #[must_use]
    pub fn spliced_bytes(&self) -> u64 {
        self.spliced.get()
    }

    /// 在用户态拷贝了多少字节（包括先写出去的 `prefix`）。
    #[must_use]
    pub fn copied_bytes(&self) -> u64 {
        self.copied.get()
    }

    /// 现在池里空着的管道有几个。
    #[must_use]
    pub fn idle_pipes(&self) -> usize {
        #[cfg(target_os = "linux")]
        if let Some(pipes) = &self.pipes {
            return pipes.idle();
        }
        0
    }

    /// 从 `from` 搬到 `to`，直到 `from` 读到 EOF（然后给 `to` 发 FIN），或者出错、被叫停。
    ///
    /// 先把 `prefix` 写给 `to`：它是已经从 `from` 那边读进程序、还没写出去的字节（见 [`i3t_conn::RawRead`]、[`i3t_conn::RawWrite`]）。
    /// `moved` 随着搬运增加，被取消时也是准的。出错时这里不重置任何一头，由调用方决定（两头都要重置）。
    ///
    /// # Errors
    ///
    /// 读 `from`、写 `to` 出错，或者 `gate` 叫停。
    pub async fn pump<G: Gate>(
        &self,
        from: &TcpStream,
        to: &TcpStream,
        prefix: Bytes,
        gate: &mut G,
        moved: &mut u64,
    ) -> Result<(), PumpError<G::Stop>> {
        if !prefix.is_empty() {
            gate.pass(prefix.len()).await.map_err(PumpError::Stopped)?;
            write_all(to, &prefix).await.map_err(PumpError::Write)?;
            self.copied.add(prefix.len());
            *moved += u64::try_from(prefix.len()).unwrap_or(u64::MAX);
        }
        #[cfg(target_os = "linux")]
        if let Some(pipes) = &self.pipes {
            return linux::pump(pipes, from, to, gate, moved, &self.spliced).await;
        }
        copy(from, to, gate, moved, &self.copied).await
    }

    /// 双向搬运，直到两个方向都结束，或者有一个方向出错。`to_a`、`to_b` 是先写给 `a`、`b` 的字节。
    ///
    /// 开始时把两头都设成"关闭时发 RST"。两个方向都正常结束时改回正常关闭（macOS 上在各自发 FIN 时就改了，见
    /// `i3t_underlay::tcp_reset`）；有一个方向出错时两头立刻重置。
    pub async fn relay(&self, a: &TcpStream, to_a: Bytes, b: &TcpStream, to_b: Bytes) -> Relayed {
        socket::rst_on_close(a);
        socket::rst_on_close(b);
        let (mut a_to_b, mut b_to_a) = (0, 0);
        let (mut forward_gate, mut backward_gate) = (Open, Open);
        let error = {
            let forward = self.pump(a, b, to_b, &mut forward_gate, &mut a_to_b);
            let backward = self.pump(b, a, to_a, &mut backward_gate, &mut b_to_a);
            tokio::pin!(forward, backward);
            let (mut forward_done, mut backward_done) = (false, false);
            loop {
                let outcome = tokio::select! {
                    outcome = &mut forward, if !forward_done => {
                        forward_done = true;
                        outcome
                    }
                    outcome = &mut backward, if !backward_done => {
                        backward_done = true;
                        outcome
                    }
                };
                if let Err(error) = outcome {
                    break Some(error);
                }
                if forward_done && backward_done {
                    break None;
                }
            }
        };
        if error.is_some() {
            socket::reset_now(a);
            socket::reset_now(b);
        } else {
            socket::graceful_close(a);
            socket::graceful_close(b);
        }
        Relayed { a_to_b, b_to_a, error }
    }
}

/// 把 `bytes` 全部写给 `to`。
async fn write_all(to: &TcpStream, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        to.writable().await?;
        match to.try_write(bytes) {
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// 用户态拷贝的一个方向。
async fn copy<G: Gate>(
    from: &TcpStream,
    to: &TcpStream,
    gate: &mut G,
    moved: &mut u64,
    copied: &Counter,
) -> Result<(), PumpError<G::Stop>> {
    loop {
        to.writable().await.map_err(PumpError::Write)?;
        from.readable().await.map_err(PumpError::Read)?;
        let mut chunk = Vec::with_capacity(COPY_CHUNK);
        match from.try_read_buf(&mut chunk) {
            Ok(0) => return socket::shutdown_write(to).map_err(PumpError::Write),
            Ok(len) => {
                gate.pass(len).await.map_err(PumpError::Stopped)?;
                write_all(to, &chunk).await.map_err(PumpError::Write)?;
                copied.add(len);
                *moved += u64::try_from(len).unwrap_or(u64::MAX);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(PumpError::Read(error)),
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::OwnedFd;

    use rustix::pipe::{PipeFlags, SpliceFlags};
    use tokio::io::Interest;
    use tokio::net::TcpStream;

    use super::{Counter, Gate, Mutex, PumpError, socket};

    /// 管道的容量。
    const PIPE_SIZE: usize = 256 * 1024;
    /// 池里最多留多少个空管道，多出来的关掉。
    const MAX_IDLE_PIPES: usize = 64;

    #[derive(Debug)]
    struct Pipe {
        read: OwnedFd,
        write: OwnedFd,
        size: usize,
    }

    impl Pipe {
        fn new() -> io::Result<Self> {
            let (read, write) = rustix::pipe::pipe_with(PipeFlags::NONBLOCK | PipeFlags::CLOEXEC)?;
            // 非 root 用户受管道总容量上限（`fs.pipe-user-pages-soft`）限制，超出上限时无法调大容量，退回系统默认大小仍可继续转发，仅吞吐略低。
            let size = match rustix::pipe::fcntl_setpipe_size(&write, PIPE_SIZE) {
                Ok(size) => size,
                Err(error) => {
                    tracing::debug!(%error, "设置管道容量为 256 KB 失败，改用系统默认大小");
                    rustix::pipe::fcntl_getpipe_size(&write)?
                }
            };
            Ok(Self { read, write, size })
        }
    }

    #[derive(Debug, Default)]
    pub(super) struct Pipes {
        idle: Mutex<Vec<Pipe>>,
    }

    impl Pipes {
        fn take(&self) -> io::Result<Pipe> {
            match self.idle.lock().expect("pipe pool mutex poisoned").pop() {
                Some(pipe) => Ok(pipe),
                None => Pipe::new(),
            }
        }

        /// 还回一个空管道。里面还有字节的不能还：下一个用它的会把别人的字节写出去。
        fn give_back(&self, pipe: Pipe) {
            let mut idle = self.idle.lock().expect("pipe pool mutex poisoned");
            if idle.len() < MAX_IDLE_PIPES {
                idle.push(pipe);
            }
        }

        pub(super) fn idle(&self) -> usize {
            self.idle.lock().expect("pipe pool mutex poisoned").len()
        }
    }

    pub(super) async fn pump<G: Gate>(
        pipes: &Pipes,
        from: &TcpStream,
        to: &TcpStream,
        gate: &mut G,
        moved: &mut u64,
        spliced: &Counter,
    ) -> Result<(), PumpError<G::Stop>> {
        let flags = SpliceFlags::MOVE | SpliceFlags::NONBLOCK;
        loop {
            to.writable().await.map_err(PumpError::Write)?;
            from.readable().await.map_err(PumpError::Read)?;
            let pipe = pipes.take().map_err(PumpError::Read)?;
            let pulled = from.try_io(Interest::READABLE, || Ok(rustix::pipe::splice(from, None, &pipe.write, None, pipe.size, flags)?));
            let mut in_pipe = match pulled {
                Ok(0) => {
                    pipes.give_back(pipe);
                    return socket::shutdown_write(to).map_err(PumpError::Write);
                }
                Ok(len) => len,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    pipes.give_back(pipe);
                    continue;
                }
                Err(error) => return Err(PumpError::Read(error)),
            };
            // 叫停或者出错时管道里还有字节：直接丢掉这个管道，不还回池里。
            gate.pass(in_pipe).await.map_err(PumpError::Stopped)?;
            while in_pipe > 0 {
                to.writable().await.map_err(PumpError::Write)?;
                let pushed = to.try_io(Interest::WRITABLE, || Ok(rustix::pipe::splice(&pipe.read, None, to, None, in_pipe, flags)?));
                match pushed {
                    Ok(len) => {
                        in_pipe -= len;
                        spliced.add(len);
                        *moved += u64::try_from(len).unwrap_or(u64::MAX);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(PumpError::Write(error)),
                }
            }
            pipes.give_back(pipe);
        }
    }
}
