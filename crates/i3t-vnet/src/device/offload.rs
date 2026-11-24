//! Linux 分段卸载：在虚拟网卡与内核之间以大块缓冲批量收发数据（TUN 的 `IFF_VNET_HDR` 与 GSO/GRO）。
//!
//! 未启用时，本机内核会将 TCP 数据拆分为不超过 MTU 的独立数据包交付网卡，入站包也需逐包写回：每个包触发一次系统调用
//! 并完整走一遍内核收发路径。启用后，收发双向均可以大块形式交接（最大 64 KB），并在头部附加 10 字节的 `virtio_net_hdr` 描述分段参数：
//!
//! - 读取：内核交付未拆分的聚合大块且校验和未补全。本模块依据头部信息拆分为不超过 MTU 的标准包、补齐校验和后再逐包向上交付
//!   （[`Segmented::recv`]），对转发引擎完全透明。
//! - 写入：将同一批中属于同一 TCP 流或同一 UDP 端口对的连续数据包先聚合为大块再写入（[`Segmented::send_many`]），减少内核处理次数；
//!   单包写入时则在头部填充全零的 `virtio_net_hdr` 表示普通数据包（[`send_plain`]）。
//!
//! 拆分与聚合算法由 `tun-rs` 实现，头部仅在本模块内部处理：启用该模式后，读写数据均必须携带该头部，否则内核会将 IP 头前 10 字节误解析为控制头。

use std::io::{self, IoSlice};
use std::ops::Range;
use std::sync::Mutex;

use bytes::Bytes;
use tun_rs::{AsyncDevice, GROTable, VIRTIO_NET_HDR_LEN};

use super::Unwritten;
use crate::MTU_RANGE;
use crate::ipv4::{Ipv4, TCP};

/// 内核单次交付数据的最大长度：virtio-net 头部加上最大 IPv4 包长度。
const RAW_LEN: usize = VIRTIO_NET_HDR_LEN + u16::MAX as usize;

/// 单个聚合大块最多可拆分的包数量：分段长度不小于 256 字节时均足够。虚拟网卡最小 MTU 为 576（[`MTU_RANGE`]），
/// 对应 TCP MSS 为 536（含时间戳为 524，含 SACK 块为 496），即使路径 MTU 降至内核下限 552 仍在此范围内。
/// 若应用显式设置极小 MSS 导致拆出包数超出此上限，该数据块将被丢弃（[`Segmented::try_recv`]），由 TCP 重传并随拥塞窗口收缩自然恢复。
const SEGMENTS: usize = 256;

/// 内核单次接收 UDP 聚合包支持的最大分段数（`UDP_MAX_SEGMENTS`）：Linux 6.9 前为 64，6.9 起为 128；超出将返回 `EINVAL`。
const KERNEL_UDP_SEGMENTS: usize = 64;

/// 单次参与聚合的最大包数量。转发引擎每批读取 64 帧，而默认 MTU 下 64 KB 大块约包含 53 个包。
///
/// 该值不得超过 [`KERNEL_UDP_SEGMENTS`]。`tun-rs` 聚合 UDP 时不限制分段数，而对端聚合帧展开后一批可能包含数百个小包；
/// 在此处限制单批数量可避免触发内核 `EINVAL` 进而导致该网卡停用 UDP 聚合。
const MERGE_BATCH: usize = 64;
const _: () = assert!(MERGE_BATCH <= KERNEL_UDP_SEGMENTS, "单次聚合批量不得超过内核允许的 UDP 最大分段数");

/// 聚合缓冲区单槽容量：需完整容纳聚合后的最大数据块及头部。`tun-rs` 聚合时不会自动扩容（容量不足时跳过聚合），
/// 因此每个槽位必须预先分配充足容量。
///
/// 未触及的页面不会占用物理内存；但任意槽位都可能成为流的首包被拼接至最大长度，长时间运行后 [`MERGE_BATCH`] 个槽位
/// 合计约占用 4 MB 内存并随网卡存活（仅在完全停用聚合后释放，见 [`Merger`]）。
const BLOCK_CAPACITY: usize = 2 * VIRTIO_NET_HDR_LEN + u16::MAX as usize;

/// 启用分段卸载的虚拟网卡状态：维护拆分后的待消费队列及入站聚合器。
pub(super) struct Segmented {
    /// 内核是否支持 UDP 分段卸载（Linux 6.2 及以上）。底层收发由 `tun-rs` 感知；该字段用于状态上报及决定写入遭拒时的降级策略。
    pub(super) udp: bool,
    reading: Mutex<Reading>,
    /// 仅由入站转发任务独占使用，持锁等待异步写入不会阻塞其他任务。
    writing: tokio::sync::Mutex<Writing>,
}

struct Reading {
    /// 从内核直接读取的原始缓冲（含头部与聚合大块）。
    raw: Box<[u8]>,
    /// 拆分后的数据包槽位，每个槽位足以容纳允许的最大 MTU。
    segments: Vec<Vec<u8>>,
    lens: Vec<usize>,
    /// `segments` 中尚未交付给上层的有效索引范围。
    pending: Range<usize>,
}

struct Writing {
    merging: Merging,
    /// 仅在首次需要聚合时延迟初始化，完全停用聚合后释放。
    merger: Option<Merger>,
}

/// 数据包聚合状态。内存开销较大，因此按需创建：`tun-rs` 的 GRO 表在初始化时即按最大流数预分配近 2 MB 空间，
/// 缓冲区容量详见 [`BLOCK_CAPACITY`]。
struct Merger {
    table: GROTable,
    /// 待聚合数据包缓冲区，每包一槽（最多 [`MERGE_BATCH`] 槽），头部预留 virtio-net 控制头空间。
    buffers: Vec<Vec<u8>>,
}

/// 入站写入时的聚合策略。仅单向降级：被内核拒绝过的聚合类型在同一虚拟网卡生命周期内不再重试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Merging {
    /// 对内核支持的所有协议启用聚合。
    All,
    /// 仅聚合 TCP 数据包。内核对 UDP 聚合块的校验较严格（如分段数、校验和偏移），写入遭拒通常源于 UDP，
    /// 因此优先停用 UDP 聚合，保留主要收益所在的 TCP 聚合。
    TcpOnly,
    /// 完全停用聚合，改为逐包写入。
    Off,
}

impl Merging {
    /// 计算内核拒绝聚合包后的降级策略。`udp` 表示该网卡是否启用了 UDP 分段卸载。
    const fn after_refusal(self, udp: bool) -> Self {
        match self {
            Self::All if udp => Self::TcpOnly,
            Self::All | Self::TcpOnly | Self::Off => Self::Off,
        }
    }

    /// 判断相邻两个数据包能否归入同一聚合批次。仅聚合 TCP 时，非 TCP 包会将批次切分为多段并严格保持原有顺序写入。
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

    /// 读取下一个本机发出的数据包：优先交付已拆分缓存的包，缓存为空时再等待内核交付下一大块。
    pub(super) async fn recv(&self, device: &AsyncDevice, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(read) = self.try_recv(device, buf) {
                return read;
            }
            device.readable().await?;
        }
    }

    /// 非阻塞读取一个数据包，无就绪数据时返回 `None`。
    ///
    /// 若内核交付的大块无法拆分（如拆出段数超过 [`SEGMENTS`]，或单包超过槽位容量，例如外部将网卡 MTU 改为大于 1500），
    /// 返回 `InvalidData` 错误并丢弃该数据块，虚拟网卡本身保持可用；底层系统错误则原样返回。
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

    /// 按顺序将一批数据包提交内核：每 [`MERGE_BATCH`] 个为一组，对满足条件的数据包先执行聚合。
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
    /// 尝试将多个数据包聚合后写入内核。返回 `None` 表示未执行聚合发送（仅单包、已停用聚合、聚合阶段失败或内核拒绝聚合），
    /// 调用方应回退为逐包写入。
    ///
    /// 内核返回 `EINVAL` 拒绝聚合包时，按 [`Merging::after_refusal`] 降级策略并回退逐包写入；该批次中此前已写入的大块
    /// 可能被重复投递一次（TCP 会自动去重，UDP 应用可能收到重复报文），每块网卡整个生命周期内最多触发两次。
    ///
    /// 其他系统错误表示写入虚拟网卡失败。由于 `tun-rs` 仅返回最后一个错误而不报告已成功写入的包数，本批次全部计为未写入；
    /// 若仅为短暂资源紧张导致部分失败，丢包计数可能偏高、接收计数可能偏低。
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
            // 非操作系统错误：聚合阶段即失败，尚未向内核写入任何数据。
            None => {
                tracing::debug!(%error, packets = packets.len(), "数据包聚合失败，改为逐包写入虚拟网卡");
                None
            }
            Some(libc::EINVAL) => {
                self.refused(udp);
                if self.merging == Merging::TcpOnly {
                    tracing::warn!(%error, "UDP 聚合包写入失败，虚拟网卡后续仅聚合 TCP 数据包");
                } else {
                    tracing::warn!(%error, "聚合包写入失败，虚拟网卡停用聚合并改为逐包写入");
                }
                None
            }
            Some(_) => Some(Err(error)),
        }
    }

    /// 内核拒绝聚合包后降级聚合策略；完全停用时释放聚合表与缓冲区。
    fn refused(&mut self, udp: bool) {
        self.merging = self.merging.after_refusal(udp);
        if self.merging == Merging::Off {
            self.merger = None;
        }
    }
}

impl Reading {
    /// 取出一个已拆分的数据包；队列为空时返回 `None`。若 `buf` 长度小于数据包则截断拷贝，与直接读取网卡行为一致。
    fn take(&mut self, buf: &mut [u8]) -> Option<usize> {
        let index = self.pending.next()?;
        let len = self.lens[index].min(buf.len());
        buf[..len].copy_from_slice(&self.segments[index][..len]);
        Some(len)
    }
}

/// 将单个普通数据包写入启用分段卸载的虚拟网卡：在头部附加全零的 virtio-net 控制头。
pub(super) async fn send_plain(device: &AsyncDevice, packet: &[u8]) -> io::Result<()> {
    const PLAIN: [u8; VIRTIO_NET_HDR_LEN] = [0; VIRTIO_NET_HDR_LEN];
    device.send_vectored(&[IoSlice::new(&PLAIN), IoSlice::new(packet)]).await.map(drop)
}

#[cfg(test)]
mod tests;
