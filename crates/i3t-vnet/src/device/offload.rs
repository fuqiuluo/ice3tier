//! Linux：网卡和内核之间一次交接一大块（TUN 的 `IFF_VNET_HDR` 和分段卸载）。
//!
//! 不开它，本机的内核把 TCP 的数据切成一个个不超过 MTU 的包才交给网卡，对端来的包也得一个一个地写回去：每个包一次系统调用，
//! 内核里收和发的路每个包走一遍。开了之后两个方向都可以一次一大块（最长 64 KB），前面带一个 10 字节的头，说它该怎么切：
//!
//! - 读：内核给的是还没切的一大块，校验和也没算完。按头里说的切成不超过 MTU 的包、补上校验和，再一个一个地交出去
//!   （[`Segmented::recv`]）：引擎看到的和不开时一样。
//! - 写：一批里同一条 TCP 流（或者同一对 UDP 端口）首尾相接的包先合成一个大的再写（[`Segmented::send_many`]），
//!   内核收一次；单独的一个包前面补一个全零的头，意思是"就是一个普通的包"（[`send_plain`]）。
//!
//! 切和合的算法是 `tun-rs` 的。头不出这个模块：开了这个模式，读出来的和写进去的前面都必须有它，少了的话内核会把
//! IP 包的头 10 个字节当成它。

use std::io::{self, IoSlice};
use std::ops::Range;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tun_rs::{AsyncDevice, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use super::Unwritten;
use crate::MTU_RANGE;

/// 内核一次给的最多这么长：头，加一个 IPv4 的包能有的最大长度。
const RAW_LEN: usize = VIRTIO_NET_HDR_LEN + u16::MAX as usize;

/// 一大块最多切成多少个包。分段长度不小于 512 字节时够用，而网卡的 MTU 最小 576（[`MTU_RANGE`]），内核按它定的
/// TCP 分段长度不小于 524。程序自己把分段长度设得更小、切出来比这还多的那一块丢掉（[`Segmented::try_recv`]），
/// 它的 TCP 会重发，拥塞窗口小了之后内核给的块也就小了。
const SEGMENTS: usize = IDEAL_BATCH_SIZE;

/// 一次最多拿多少个包去合。对端来的包引擎一批取 64 帧；内核收的一大块在默认的 MTU 下是 53 个包。
const MERGE_BATCH: usize = 64;

/// 合包用的每一格留多大的地方：合好的一大块连头都装得下。合的时候后面的包接到前面那一格的末尾，`tun-rs` 不给格子扩容
/// （地方不够就不合），所以每一格都要事先留够。只是留着：没写到的那些页不占内存。
const BLOCK_CAPACITY: usize = 2 * VIRTIO_NET_HDR_LEN + u16::MAX as usize;

/// 开了分段卸载的网卡：切好了还没交出去的包，和合包用的东西。
pub(super) struct Segmented {
    /// 内核给不给 UDP 的大块（Linux 6.2 起）。只用来说明状态：读和写的时候 `tun-rs` 自己知道。
    pub(super) udp: bool,
    reading: Mutex<Reading>,
    /// 只有搬进来的包的那一个任务用，锁着等写完也不挡别人。
    writing: tokio::sync::Mutex<Writing>,
    /// 写的时候还合不合：内核拒绝过一次合好的包之后不再合。
    merging: AtomicBool,
}

struct Reading {
    /// 从内核读来的原样：头和一大块。
    raw: Box<[u8]>,
    /// 切出来的包，一个一格；每格装得下 MTU 允许的最大值。
    segments: Vec<Vec<u8>>,
    lens: Vec<usize>,
    /// `segments` 里还没交出去的。
    pending: Range<usize>,
}

struct Writing {
    table: GROTable,
    /// 要写的包，一个一格（最多 [`MERGE_BATCH`] 格，每格 [`BLOCK_CAPACITY`]），前面留着头的位置。
    buffers: Vec<Vec<u8>>,
}

impl Segmented {
    pub(super) fn new(udp: bool) -> Self {
        let segment = usize::from(*MTU_RANGE.end());
        Self {
            udp,
            reading: Mutex::new(Reading {
                raw: vec![0; RAW_LEN].into_boxed_slice(),
                segments: vec![vec![0; segment]; SEGMENTS],
                lens: vec![0; SEGMENTS],
                pending: 0..0,
            }),
            writing: tokio::sync::Mutex::new(Writing { table: GROTable::new(), buffers: Vec::new() }),
            merging: AtomicBool::new(true),
        }
    }

    /// 下一个本机发出的包：切好了还没交出去的先交，没有了才等内核的下一块。
    pub(super) async fn recv(&self, device: &AsyncDevice, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(read) = self.try_recv(device, buf) {
                return read;
            }
            device.readable().await?;
        }
    }

    /// 现在就有的话给一个包，不等。
    ///
    /// 内核给的一块切不了时（切出来的包比 [`SEGMENTS`] 多，或者比格子长：有人把网卡的 MTU 改到了 1500 以上）是一个
    /// `InvalidData` 的错误，那一块丢掉了，网卡还在；系统给的错误原样返回。
    pub(super) fn try_recv(&self, device: &AsyncDevice, buf: &mut [u8]) -> Option<io::Result<usize>> {
        let mut reading = self.reading.lock().expect("virtual adapter read state mutex poisoned");
        loop {
            if let Some(len) = reading.take(buf) {
                return Some(Ok(len));
            }
            let Reading { raw, segments, lens, pending } = &mut *reading;
            match device.try_recv_multiple(raw, segments, lens, 0) {
                Ok(count) => *pending = 0..count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return None,
                Err(error) if error.raw_os_error().is_some() => return Some(Err(error)),
                Err(error) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, error))),
            }
        }
    }

    /// 把一批包按顺序交给内核：每 [`MERGE_BATCH`] 个里能合的先合。
    pub(super) async fn send_many(&self, device: &AsyncDevice, packets: &[Bytes]) -> Result<(), Unwritten> {
        let mut lost = None;
        for batch in packets.chunks(MERGE_BATCH) {
            match self.send_merged(device, batch).await {
                Some(Ok(())) => {}
                Some(Err(error)) => Unwritten::add(&mut lost, batch.len(), batch.iter().map(Bytes::len).sum(), error),
                None => {
                    for packet in batch {
                        if let Err(error) = send_plain(device, packet).await {
                            Unwritten::add(&mut lost, 1, packet.len(), error);
                        }
                    }
                }
            }
        }
        lost.map_or(Ok(()), Err)
    }

    /// 把几个包合了再写。`None` 是没合：只有一个包，已经不合了，或者这一次合不成，调用方照一个一个地写。
    ///
    /// 内核不收合好的包（`EINVAL`）时这块网卡从此不再合，这几个也回去一个一个地写；其中已经写进去的那几个大的
    /// 因此会重复一遍（TCP 不在乎，UDP 的程序会多收到几个一样的包），只有这一次。别的错误是网卡写不了了，
    /// 这几个都算没写进去。
    async fn send_merged(&self, device: &AsyncDevice, packets: &[Bytes]) -> Option<io::Result<()>> {
        if packets.len() < 2 || !self.merging.load(Ordering::Relaxed) {
            return None;
        }
        let mut writing = self.writing.lock().await;
        let Writing { table, buffers } = &mut *writing;
        if buffers.len() < packets.len() {
            buffers.resize_with(packets.len(), || Vec::with_capacity(BLOCK_CAPACITY));
        }
        let buffers = &mut buffers[..packets.len()];
        for (buffer, packet) in buffers.iter_mut().zip(packets) {
            buffer.clear();
            buffer.resize(VIRTIO_NET_HDR_LEN, 0);
            buffer.extend_from_slice(packet);
        }
        let error = match device.send_multiple(table, buffers, VIRTIO_NET_HDR_LEN).await {
            Ok(_) => return Some(Ok(())),
            Err(error) => error,
        };
        match error.raw_os_error() {
            // 不是系统给的错误：合的那一步就没成，还什么都没写。
            None => {
                tracing::debug!(%error, packets = packets.len(), "这几个包合不起来，一个一个地写进网卡");
                None
            }
            Some(libc::EINVAL) => {
                self.merging.store(false, Ordering::Relaxed);
                tracing::warn!(%error, "内核不收合起来的包：这块虚拟网卡往后一个一个地写");
                None
            }
            Some(_) => Some(Err(error)),
        }
    }
}

impl Reading {
    /// 交出一个切好的包；没有了是 `None`。`buf` 比包短的话只给前面的，和直接读网卡时一样。
    fn take(&mut self, buf: &mut [u8]) -> Option<usize> {
        let index = self.pending.next()?;
        let len = self.lens[index].min(buf.len());
        buf[..len].copy_from_slice(&self.segments[index][..len]);
        Some(len)
    }
}

/// 把一个包原样写进开了分段卸载的网卡：前面补一个全零的头。
pub(super) async fn send_plain(device: &AsyncDevice, packet: &[u8]) -> io::Result<()> {
    const PLAIN: [u8; VIRTIO_NET_HDR_LEN] = [0; VIRTIO_NET_HDR_LEN];
    device.send_vectored(&[IoSlice::new(&PLAIN), IoSlice::new(packet)]).await.map(drop)
}

#[cfg(test)]
mod tests;
