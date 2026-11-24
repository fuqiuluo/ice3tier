//! 流的两个方向，按 [`crate::contract`] 的语义包装 QUIC 库的流。

use std::future::Future;
use std::io;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Instant;

use quinn::{ReadError, VarInt, WriteError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::contract::{self, Priority, StreamAborted, StreamCode};

/// 发送方向没有 `shutdown` 就被丢弃时，带给对端的原因码。
///
/// 契约规定这种情况等同于重置（被截断的数据不能表现成正常结束），但没有规定用哪个码。
/// 取最大值，尽量不和上层自己定义的码撞上。
pub const DROPPED_STREAM_CODE: StreamCode = StreamCode(u32::MAX);

fn code_of(code: VarInt) -> StreamCode {
    // 本项目的两端只会发 32 位以内的码；别的实现发来更大的就压到最大值。
    StreamCode(u32::try_from(code.into_inner()).unwrap_or(u32::MAX))
}

/// 契约里的优先级在 QUIC 库里的数值：数值大的先发，新开的流是 0。
const fn quic_priority(priority: Priority) -> i32 {
    match priority {
        Priority::Low => -1,
        Priority::Normal => 0,
        Priority::High => 1,
    }
}

/// 一条连接上现在开着多少条流，以及最近一次变成零是什么时候。连接靠它判断自己是不是空闲。
#[derive(Debug)]
pub(crate) struct StreamCount {
    open: AtomicUsize,
    idle_since: Mutex<Instant>,
}

impl StreamCount {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self { open: AtomicUsize::new(0), idle_since: Mutex::new(Instant::now()) })
    }

    /// 现在开着的流（两半里至少还有一半没有放下的）。
    pub(crate) fn open(&self) -> usize {
        self.open.load(Ordering::Acquire)
    }

    /// 没有流的话，从什么时候起没有的。
    pub(crate) fn idle_since(&self) -> Option<Instant> {
        (self.open.load(Ordering::Acquire) == 0).then(|| *self.idle_since.lock().expect("stream count mutex poisoned"))
    }

    fn enter(self: &Arc<Self>) -> StreamGuard {
        self.open.fetch_add(1, Ordering::AcqRel);
        StreamGuard(Arc::clone(self))
    }
}

/// 一条流活着（两个方向里至少还有一个没放下）的时候占着的计数。
#[derive(Debug)]
struct StreamGuard(Arc<StreamCount>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let mut idle_since = self.0.idle_since.lock().expect("stream count mutex poisoned");
        if self.0.open.fetch_sub(1, Ordering::AcqRel) == 1 {
            *idle_since = Instant::now();
        }
    }
}

/// 把 QUIC 库的一对流包装成契约里的两个方向。
pub(crate) fn wrap(send: quinn::SendStream, recv: quinn::RecvStream, count: &Arc<StreamCount>) -> (SendHalf, RecvHalf) {
    // 两个方向共用一个计数：流的两半都放下了，这条流才不算开着。
    let open = Arc::new(count.enter());
    (SendHalf { inner: send, ended: false, _open: Arc::clone(&open) }, RecvHalf { inner: recv, _open: open })
}

/// 一条流的发送方向。
///
/// 正常结束用 `AsyncWriteExt::shutdown`；[`reset`](contract::SendStream::reset) 或者没有 `shutdown` 就丢弃都是异常结束，
/// 对端的读会出错。对端叫停之后，写和 `shutdown` 返回的错误里能取出 [`StreamAborted::Stopped`]。
#[derive(Debug)]
pub struct SendHalf {
    inner: quinn::SendStream,
    /// 已经正常结束或者重置过了，丢弃时不用再做什么。
    ended: bool,
    _open: Arc<StreamGuard>,
}

impl AsyncWrite for SendHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        quinn::SendStream::poll_write(Pin::new(&mut this.inner), cx, buf).map_err(write_error)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 写进去的数据由连接自己发送和重传，没有要冲刷的缓冲。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Ok(()));
        }
        // 对端已经叫停，或者连接已经断了的话，之前写的数据它不一定收到了，不能当作正常结束。
        match pin!(this.inner.stopped()).poll(cx) {
            Poll::Ready(Ok(Some(code))) => return Poll::Ready(Err(StreamAborted::Stopped(code_of(code)).into())),
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("连接已断开：{error}"))));
            }
            Poll::Ready(Ok(None)) | Poll::Pending => {}
        }
        this.ended = true;
        // 失败只有一种可能：这个方向已经结束或者重置过了，那就没有什么要做的。
        let _already_closed = this.inner.finish();
        Poll::Ready(Ok(()))
    }
}

impl contract::SendStream for SendHalf {
    fn reset(&mut self, code: StreamCode) {
        if self.ended {
            return;
        }
        self.ended = true;
        // 失败说明这个方向已经关掉了（连接断了也算），没有什么可重置的。
        let _already_closed = self.inner.reset(VarInt::from_u32(code.0));
    }

    fn set_priority(&mut self, priority: Priority) {
        // 失败说明这个方向已经关掉了，那它排在哪里都无所谓。
        let _already_closed = self.inner.set_priority(quic_priority(priority));
    }
}

impl Drop for SendHalf {
    fn drop(&mut self) {
        contract::SendStream::reset(self, DROPPED_STREAM_CODE);
    }
}

/// 一条流的接收方向。
///
/// 读到 0 字节是对端正常结束；对端重置之后，读返回的错误里能取出 [`StreamAborted::Reset`]。
/// 没读完就丢弃等同于用原因码 0 叫停。
#[derive(Debug)]
pub struct RecvHalf {
    inner: quinn::RecvStream,
    _open: Arc<StreamGuard>,
}

impl AsyncRead for RecvHalf {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.inner.poll_read_buf(cx, buf)).map_err(read_error)?;
        Poll::Ready(Ok(()))
    }
}

impl contract::RecvStream for RecvHalf {
    fn stop(&mut self, code: StreamCode) {
        // 失败说明这个方向已经结束了，没有什么可叫停的。
        let _already_closed = self.inner.stop(VarInt::from_u32(code.0));
    }
}

/// 错误里只带文字，不带 QUIC 库的类型：它们不出这个 crate。
fn write_error(error: WriteError) -> io::Error {
    match error {
        WriteError::Stopped(code) => StreamAborted::Stopped(code_of(code)).into(),
        WriteError::ConnectionLost(reason) => io::Error::new(io::ErrorKind::ConnectionAborted, format!("连接已断开：{reason}")),
        WriteError::ClosedStream => io::Error::new(io::ErrorKind::NotConnected, "当前发送方向已关闭或重置"),
        WriteError::ZeroRttRejected => io::Error::other("对端拒绝了提前发送的数据"),
    }
}

fn read_error(error: ReadError) -> io::Error {
    match error {
        ReadError::Reset(code) => StreamAborted::Reset(code_of(code)).into(),
        ReadError::ConnectionLost(reason) => io::Error::new(io::ErrorKind::ConnectionAborted, format!("连接已断开：{reason}")),
        ReadError::ClosedStream => io::Error::new(io::ErrorKind::NotConnected, "当前接收方向已中止"),
        ReadError::IllegalOrderedRead => io::Error::other("流的读取方式前后不一致"),
        ReadError::ZeroRttRejected => io::Error::other("对端拒绝了提前发送的数据"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aborts_keep_their_code_through_the_error_mapping() {
        let stopped = write_error(WriteError::Stopped(VarInt::from_u32(7)));
        assert_eq!(StreamAborted::of(&stopped), Some(StreamAborted::Stopped(StreamCode(7))));
        let reset = read_error(ReadError::Reset(VarInt::from_u32(9)));
        assert_eq!(StreamAborted::of(&reset), Some(StreamAborted::Reset(StreamCode(9))));
        let huge = read_error(ReadError::Reset(VarInt::MAX));
        assert_eq!(StreamAborted::of(&huge), Some(StreamAborted::Reset(StreamCode(u32::MAX))));
        assert_eq!(StreamAborted::of(&write_error(WriteError::ClosedStream)), None);
    }

    #[test]
    fn a_higher_priority_is_a_larger_number_and_normal_is_what_new_streams_have() {
        assert!(quic_priority(Priority::High) > quic_priority(Priority::Normal));
        assert!(quic_priority(Priority::Normal) > quic_priority(Priority::Low));
        assert_eq!(quic_priority(Priority::default()), 0);
    }

    #[test]
    fn a_connection_is_idle_only_while_no_stream_half_is_alive() {
        let count = StreamCount::new();
        let created = count.idle_since().expect("刚建好的连接没有流");
        let first = count.enter();
        let second = count.enter();
        assert_eq!(count.idle_since(), None);
        drop(first);
        assert_eq!(count.idle_since(), None, "还有一个方向开着");
        drop(second);
        assert!(count.idle_since().expect("流都关了") >= created);
    }
}
