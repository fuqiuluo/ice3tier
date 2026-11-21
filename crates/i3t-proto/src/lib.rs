//! ice3tier 的线上格式。
//!
//! 这里只有格式：字节怎么排、怎么编码和解析。不做 I/O，不依赖运行时，所以 relay、节点和测试都可以直接用。
//!
//! | 模块 | 内容 |
//! |---|---|
//! | [`node`] | 节点编号 |
//! | [`key`] | 节点公钥 |
//! | [`datagram`] | 一个端口上收到的 UDP 数据报怎么分类；经 relay 转发时加在包前面的中转头 |
//! | [`session`] | 节点和 relay 之间的中转会话 |
//! | [`probe`] | 节点之间的探测 |
//! | [`addr`] | 地址查询 |
//! | [`backbone`] | relay 之间的骨干延迟矩阵，以及 relay 的过载和下线通知 |
//! | [`beacon`] | 局域网发现的信标 |
//! | [`flow`] | 建流请求与应答 |
//! | [`sealed`] | 虚拟网卡的 IP 包不进 QUIC、单独加密之后的格式 |
//! | [`tcp_frame`] | UDP 用不了的节点把同样的包装进一条 TCP 时的分帧 |

pub mod addr;
pub mod backbone;
pub mod beacon;
pub mod datagram;
pub mod flow;
pub mod key;
pub mod node;
pub mod probe;
pub mod sealed;
pub mod session;
pub mod tcp_frame;

pub use datagram::{Datagram, DatagramError, MAX_CONN_PACKET_LEN, RelayHeader};
pub use key::PublicKey;
pub use node::NodeId;
