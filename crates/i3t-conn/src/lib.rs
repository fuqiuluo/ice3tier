//! 连接层：一对节点之间一条端到端的连接。
//!
//! [`contract`] 是这一层对上层的全部承诺：到某个节点开一条流，接受对端开过来的流，流可以正常结束也可以被重置。
//! 上层（`i3t-flow` 及以上）只依赖这些 trait，看不到 QUIC 库的任何类型。
//!
//! [`Endpoint`] 是这些 trait 的实现：QUIC 跑在路径层上，每个对端一个固定的虚拟地址，
//! 所以包走直连还是经 relay、什么时候换路，连接和上面的流都不知道。
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use i3t_conn::{Acceptor, Connector, Endpoint, EndpointConfig};
//! # use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! # async fn example(key: Arc<i3t_crypto::NodeKey>, netmap: tokio::sync::watch::Receiver<Arc<i3t_model::Netmap>>, peer: i3t_proto::NodeId)
//! # -> Result<(), Box<dyn std::error::Error>> {
//! let endpoint = Endpoint::bind(EndpointConfig { key, bind: "0.0.0.0:20330".parse()?, netmap, addr_servers: Vec::new() })?;
//!
//! // 到对端开一条流：没有连接时先建，包走哪条路由路径层决定。
//! let (mut send, mut recv) = endpoint.open(peer).await?;
//! send.write_all(b"hello").await?;
//! send.shutdown().await?;
//! let mut reply = Vec::new();
//! recv.read_to_end(&mut reply).await?;
//!
//! // 接受对端开过来的流。
//! while let Some(incoming) = endpoint.accept().await {
//!     println!("节点 {} 开过来一条流", incoming.peer);
//! }
//! # Ok(())
//! # }
//! ```

mod congestion;
pub mod contract;
mod endpoint;
mod manager;
mod quic;
mod sealed;
mod socket;
mod stream;
mod tuning;

pub use contract::{
    Acceptor, Connector, Datagram, DatagramSendError, DatagramSender, Datagrams, Incoming, OpenError, PacketSender, Packets, Payload,
    Priority, RawRead, RawWrite, RecvStream, SendStream, StreamAborted, StreamCode,
};
pub use endpoint::{Endpoint, EndpointConfig, EndpointError, UdpSeen};
pub use i3t_path::diag::{self, MAX_PIN, MAX_TEST_PROBES, MAX_TEST_WINDOW};
pub use i3t_path::{
    BackboneLink, BackboneRow, CandidateReport, ChoiceReason, DirectAttempt, DirectFailure, DirectFailureCause, DirectKind, DirectState,
    DirectStatus, HopReport, HopSource, LatencySummary, LegReport, ModeChoice, PathReport, RelayLeg, RouteChange, RouteDecision, RoutePin,
    Side, TestGuard, TestPath, TestSpec, TrainError, TrainReport, TrainSpec,
};
pub use i3t_relay::{DropReason, RelayCounters, TcpHandoff};
pub use i3t_underlay::{Direction, PacketFilter};
pub use manager::{ConnectionCounters, ConnectionReport, DIAL_TIMEOUT, DatagramHandle};
pub use quic::QuicConfigError;
pub use sealed::PacketTransport;
pub use stream::{DROPPED_STREAM_CODE, RecvHalf, SendHalf};
pub use tuning::{MAX_STREAM_WINDOW, Tuning};
