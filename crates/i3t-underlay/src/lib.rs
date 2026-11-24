//! 可达层。
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`port`] | 节点唯一的 UDP 端口：绑定、批量收发 |
//! | [`ifaddr`] | 本机网卡地址，用作局域网候选端点 |
//! | [`addr_query`] | 反射地址查询：向服务器询问其观察到的本机地址 |
//! | [`tcp_leg`] | TCP 中继连接封装：限制积压的写入与逐帧读取，节点与 relay 共用 |
//! | [`tcp_recovery`] | 节点间 TCP 断网后快速恢复：同时配置重传上限与放弃时限 |
//! | [`tcp_mss`] | 为出站与入站 TCP 连接通告较低的 MSS，规避路径 MTU 黑洞 |
//! | [`tcp_reset`] | 异常关闭 TCP 连接（关闭时发送 RST 并确保对端接收）以及此类连接的正常关闭流程 |
//! | [`lan`] | 局域网发现：组播信标 |
//! | [`portmap`] | 自动端口映射：PCP、NAT-PMP、UPnP-IGD |

pub mod addr_query;
pub mod ifaddr;
pub mod lan;
pub mod port;
pub mod portmap;
pub mod tcp_leg;
pub mod tcp_mss;
pub mod tcp_recovery;
pub mod tcp_reset;

pub use addr_query::{AddrQuery, Observation};
pub use port::{BATCH_SIZE, Direction, Ecn, PacketFilter, RecvMeta, Transmit, UdpPort};

use ring::rand::{SecureRandom, SystemRandom};

/// 取 `N` 个随机字节，用作各种帧里的随机数。
///
/// # Panics
///
/// 操作系统的随机数源不可用。此时进程无法安全完成握手，且无可用的回退方案。
#[must_use]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    SystemRandom::new().fill(&mut bytes).expect("操作系统随机数源不可用，进程无法安全运行");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_differ_between_calls() {
        assert_ne!(random_bytes::<16>(), random_bytes::<16>());
    }
}
