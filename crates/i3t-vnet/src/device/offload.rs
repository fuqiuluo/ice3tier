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

use bytes::Bytes;
use tun_rs::{AsyncDevice, GROTable, VIRTIO_NET_HDR_LEN};

use super::Unwritten;
use crate::MTU_RANGE;
use crate::ipv4::{Ipv4, TCP};

/// 内核一次给的最多这么长：头，加一个 IPv4 的包能有的最大长度。
const RAW_LEN: usize = VIRTIO_NET_HDR_LEN + u16::MAX as usize;

/// 一大块最多切成多少个包：分段长度不小于 256 字节时够用。网卡的 MTU 最小 576（[`MTU_RANGE`]），内核按它定的 TCP 分段长度
/// 是 536，带着时间戳 524，再带上几个 SACK 块 496，路径 MTU 被压到内核肯认的最小值（552）时还要再小几十，都在里面。
/// 程序自己把分段长度设得更小、切出来比这还多的那一块丢掉（[`Segmented::try_recv`]）：它的 TCP 会重发，拥塞窗口小了之后
/// 内核给的块也就小了，等窗口长回来又会丢一次。
const SEGMENTS: usize = 256;

/// 内核收一块合在一起的 UDP 时最多认多少段（它的 `UDP_MAX_SEGMENTS`）：6.9 之前是 64，之后是 128。多了那一次写就是 `EINVAL`。
const KERNEL_UDP_SEGMENTS: usize = 64;

/// 一次最多拿多少个包去合。对端来的包引擎一批取 64 帧；内核收的一大块在默认的 MTU 下是 53 个包。
///
/// 不能比 [`KERNEL_UDP_SEGMENTS`] 大。`tun-rs` 合 UDP 时不数段数，同一对端口的包有多少合多少，而对端合在一帧里发来的小包
/// 一批可以有几百个：是这里一次只给它这么多，合出来的才不超过内核认的段数。超了内核拒绝那一次写，这块网卡往后就不合 UDP 了。
const MERGE_BATCH: usize = 64;
const _: () = assert!(MERGE_BATCH <= KERNEL_UDP_SEGMENTS, "一次拿去合的包不能比内核认的 UDP 段数多");

/// 合包用的每一格留多大的地方：合好的一大块连头都装得下。合的时候后面的包接到前面那一格的末尾，`tun-rs` 不给格子扩容
/// （地方不够就不合），所以每一格都要事先留够。
///
/// 没写到的页不占内存，写到过的就一直占着：哪一格都可能排在一条流的最前面、被接成一大块，跑久了 [`MERGE_BATCH`] 格
/// 都写满过，一共四兆多，网卡在就留着（不合了的时候才放掉，见 [`Merger`]）。
const BLOCK_CAPACITY: usize = 2 * VIRTIO_NET_HDR_LEN + u16::MAX as usize;

/// 开了分段卸载的网卡：切好了还没交出去的包，和合包用的东西。
pub(super) struct Segmented {
    /// 内核给不给 UDP 的大块（Linux 6.2 起）。读和写的时候 `tun-rs` 自己知道；这里用来说明状态，和决定被内核拒绝之后怎么退。
    pub(super) udp: bool,
    reading: Mutex<Reading>,
    /// 只有搬进来的包的那一个任务用，锁着等写完也不挡别人。
    writing: tokio::sync::Mutex<Writing>,
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
    merging: Merging,
    /// 第一次有包要合的时候才有，不合了就没有。
    merger: Option<Merger>,
}

/// 合包用的东西。都不小，所以用得着才建：`tun-rs` 的表一建出来就按最多的流数把地方分配好（近两兆，空着的也一样），
/// 格子见 [`BLOCK_CAPACITY`]。
struct Merger {
    table: GROTable,
    /// 要写的包，一个一格（最多 [`MERGE_BATCH`] 格），前面留着头的位置。
    buffers: Vec<Vec<u8>>,
}

/// 写的时候合哪些。只往少里变：内核拒绝过的，这块网卡不再试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Merging {
    /// 内核给哪些大块就合哪些。
    All,
    /// 只合 TCP。内核对 UDP 的大块查得多（段数、校验和的位置），被拒绝的多半是它，所以先只停它：省下来的主要在 TCP 上。
    TcpOnly,
    /// 不合了。
    Off,
}

impl Merging {
    /// 内核拒绝了一次合好的包之后合哪些。`udp` 是这块网卡合不合 UDP。
    const fn after_refusal(self, udp: bool) -> Self {
        match self {
            Self::All if udp => Self::TcpOnly,
            Self::All | Self::TcpOnly | Self::Off => Self::Off,
        }
    }

    /// 挨着的两个包能不能放在一起拿去合。只合 TCP 的时候，别的包把一批隔成几段，各段照原来的顺序写。
    fn joins(self, earlier: &[u8], later: &[u8]) -> bool {
        match self {
            Self::All => true,
            Self::TcpOnly => is_tcp(earlier) && is_tcp(later),
            Self::Off => false,
        }
    }
}

fn is_tcp(packet: &[u8]) -> bool {
    Ipv4::parse(packet).is_ok_and(|ip| ip.protocol() == TCP)
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
            writing: tokio::sync::Mutex::new(Writing { merging: Merging::All, merger: None }),
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
        let mut writing = self.writing.lock().await;
        let mut lost = None;
        for batch in packets.chunks(MERGE_BATCH) {
            let merging = writing.merging;
            for run in batch.chunk_by(|earlier, later| merging.joins(earlier, later)) {
                match writing.send_merged(device, self.udp, run).await {
                    Some(Ok(())) => {}
                    Some(Err(error)) => Unwritten::add(&mut lost, run.len(), run.iter().map(Bytes::len).sum(), error),
                    None => {
                        for packet in run {
                            if let Err(error) = send_plain(device, packet).await {
                                Unwritten::add(&mut lost, 1, packet.len(), error);
                            }
                        }
                    }
                }
            }
        }
        lost.map_or(Ok(()), Err)
    }
}

impl Writing {
    /// 把几个包合了再写。`None` 是没合：只有一个包，不合了，或者这一次合不成，调用方照一个一个地写。
    ///
    /// 内核不收合好的包（`EINVAL`）时往后少合一样（[`Merging::after_refusal`]），这几个也回去一个一个地写；其中已经
    /// 写进去的那几个大的因此会重复一遍（TCP 不在乎，UDP 的程序会多收到几个一样的包），一块网卡最多两次。
    ///
    /// 别的错误是网卡写不了了。`tun-rs` 只说最后一个错误、不说哪几个写进去了，所以这几个都算没写进去：只是一时写不进
    /// 其中一块的话（内存紧），丢掉的包会多数、收到的会少数。
    async fn send_merged(&mut self, device: &AsyncDevice, udp: bool, packets: &[Bytes]) -> Option<io::Result<()>> {
        if packets.len() < 2 || self.merging == Merging::Off {
            return None;
        }
        let Merger { table, buffers } = self.merger.get_or_insert_with(|| Merger { table: GROTable::new(), buffers: Vec::new() });
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
                self.refused(udp);
                if self.merging == Merging::TcpOnly {
                    tracing::warn!(%error, "内核不收合起来的包：这块虚拟网卡往后只合 TCP 的");
                } else {
                    tracing::warn!(%error, "内核不收合起来的包：这块虚拟网卡往后一个一个地写");
                }
                None
            }
            Some(_) => Some(Err(error)),
        }
    }

    /// 内核拒绝了一次合好的包：往后少合一样；不合了的话，合包用的东西整个放掉。
    fn refused(&mut self, udp: bool) {
        self.merging = self.merging.after_refusal(udp);
        if self.merging == Merging::Off {
            self.merger = None;
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
