//! ice3proxy（lane）：一对节点之间，每条用户连接独占一条 TCP，而不是共用连接里的一条流。
//!
//! 哪一对之间备着它、什么时候拨由调用方定（[`Lanes::set_peers`] 里给了地址就拨，拿掉地址就放手）；节点里跟着 netmap，
//! 只有选了 ice3proxy 的代理的那一对备着。用的时候，两个节点里能连上对方节点端口的那一个（"拨号方"）向对方拨 lane；
//! 每条 lane 是一条按两边节点公钥双向认证的 TLS 1.3 连接，承载正好一条流，用完就关，不复用。
//! 流之间互不影响（一个丢包只耽误它自己），本来就是 TLS 的用户数据可以不再加密、由内核直接搬（Linux 上是 splice）。
//! 代价是每条流一条 TCP 穿过拨号方的路由器、要预先拨好一批，以及流不能换路。
//!
//! # 谁拨、谁用
//!
//! | lane | 谁拨 | 谁开流 | 什么时候拨 |
//! |---|---|---|---|
//! | 控制 lane | 拨号方 | 不承载流 | 拨着的时候一直保持一条 |
//! | 停车的 lane | 拨号方 | 接受方 | 按接受方的要求预先拨好，停在接受方那里 |
//! | 自己的 lane | 拨号方 | 拨号方 | 留几条热的，用完了当场拨 |
//!
//! 用途在拨号时（HELLO）就定了，两边永远不会争用同一条 lane。两个节点都能连上对方时，各自用自己拨的 lane。
//! 接受方的监听就是节点端口上 relay 的 TCP 监听：它按开头的字节（[`is_lane`]）把 lane 交给 [`Lanes::accept_tcp`]。
//!
//! # 线上格式
//!
//! lane 是 TCP 上的 TLS 1.3，ALPN 是 [`ALPN`]（`i3t-lane/2`）。双方用节点密钥自签的证书互相认证，按 netmap 里的公钥比对，
//! 未知或已吊销的公钥会在握手阶段被拒绝。不签发会话票据，也不支持会话恢复。
//!
//! 两边都还提供上一个版本 `i3t-lane/1`，服务端先挑 `/2`：和没升级的节点之间谈定 `/1`，照样拨、照样开流，
//! 只是本端发起的流一律 sealed（`/1` 的 passthrough 让发起方在 OPENING 之后马上离开 TLS，见下面的负载方式 1）。
//!
//! TLS 里面是一串帧，多字节整数都是大端：
//!
//! ```text
//! +------+------------+======+
//! | 类型 | 长度（2）  | 内容 |
//! +------+------------+======+
//!
//! 类型   名字     方向            内容                               长度
//! 0x01   HELLO    拨号方 → 接受方  用途（1）| epoch（8）              9
//!                                  用途：0 控制，1 停车，2 自己的
//! 0x02   POOL     接受方 → 拨号方  空闲目标（2）| 额外补拨（2）       4      只在控制 lane 上
//! 0x03   PING     双方             随机数（8）                        8      只在控制 lane 上
//! 0x04   PONG     双方             PING 里的随机数（8）               8      只在控制 lane 上
//! 0x05   GOAWAY   双方             无                                 0      只在控制 lane 上
//! 0x10   OPENING  发起方           负载方式（1）| 流的头              1～32769
//!                                  负载方式：0 sealed，1 passthrough（只有 /1 的发起方发），
//!                                  2 passthrough、两边都等 SWITCH（/2）
//! 0x11   DATA     双方             流的数据                           1～16381
//! 0x12   SWITCH   双方             无                                 0
//! 0x13   ABORT    双方             原因码（4）                        4
//! 0x14   STOP     双方             原因码（4）                        4
//! ```
//!
//! - 每条 lane 上拨号方的第一个帧是 HELLO，紧跟在它的 TLS Finished 后面，不多一个往返。
//!   epoch 是一个随机数，拨号方每次启动、地址变了、控制 lane 断了之后换一个。
//! - 控制 lane 上接受方的第一个帧是 POOL；拨号方收到它才算控制 lane 建立（TLS 1.3 里客户端的握手先于服务端校验它的证书完成，
//!   这个 POOL 是"认了你"的确认）。之后接受方每当缺 lane（被取走了、死了、请过的没到）或者目标变了就再发：
//!   空闲目标是它想平时停着几条（拨号方只用来显示），额外补拨是要拨号方现在再拨的条数，拨号方照数去拨。
//!   双方每隔 [`LaneConfig::ping_interval`] 发送一次 PING，连续三个周期未收到对端响应即判定控制 lane 断开。未知帧类型将被跳过（载荷最长 1024 字节）。
//! - 拨号方只在控制 lane 建立着的时候在 lane 上开流（包括它自己的流）；控制 lane 断了，它换一个新的 epoch 重拨，
//!   接受方随之关掉旧 epoch 的空闲 lane。
//! - 一条流：发起方发 OPENING（流层的 OPEN 连同首批数据），接受方回流层的 REPLY 和数据。
//!   - sealed：之后两个方向都是 DATA 帧。一个方向的正常结束是 TLS 的 close_notify 加 FIN；没有 close_notify 的 FIN 是截断，算异常结束。
//!   - passthrough（负载方式 2）：每个方向在自己的 SWITCH 所在的 TLS 记录之后离开 TLS，原样传用户的字节（用户的 TLS 记录）；
//!     之后 FIN 是正常结束，RST 是异常结束。接受方先发：它看到目标回了 TLS 1.3 的 ServerHello、确认后面的握手都由用户的
//!     TLS 加密了的时候。发起方收到之后回一个，在那之前它的方向一直是 sealed。接受方不发时两个方向都一直是 sealed：
//!     目标回 HelloRetryRequest、用 TLS 1.2 或者根本不是 TLS 时，客户端接下来的字节（第二个 ClientHello、客户端证书）
//!     不会明文出现在 lane 上。SWITCH 只能在 passthrough 的流上；发起方的 SWITCH 只能是回应，在接受方的之前到是协议错误。
//!   - 负载方式 1（`/1` 的 passthrough）：发起方的方向在 OPENING 所在的记录之后就离开 TLS，只有接受方发 SWITCH。
//!     本端不再发它，只为没升级的发起方收它。
//!   - OPENING（负载方式 1 时）和 SWITCH 都必须是它所在记录里的最后一个帧。
//!   - ABORT：发的一方异常结束了这条流，之后 RST。STOP：发的一方不再读了，请对方停止发送。两者都只能在还在 TLS 里的方向上发。
//!   - 承载流的 lane 上收到其他类型或未知类型的帧均视为协议错误，并重置该 lane。
//!
//! 和 relay 的 TCP 中转共用端口时靠第一个字节区分：lane 以 TLS 握手记录开头（`0x16`），TCP 中转以很短的帧长度开头（高字节是 `0x00`）。
//!
//! # 和流层的对接
//!
//! [`Lanes`] 实现连接层的 [`i3t_conn::Connector`] 和 [`i3t_conn::Acceptor`]，流的两个方向 [`LaneSend`]、[`LaneRecv`]
//! 实现 [`i3t_conn::SendStream`]、[`i3t_conn::RecvStream`]。流层头写完时调 [`i3t_conn::SendStream::end_header`]
//! 说这条流的负载要不要再加密；搬运之前用 [`i3t_conn::SendStream::take_raw`]、[`i3t_conn::RecvStream::wait_raw`]
//! 拿到原始的 socket，交给流层的搬运引擎（`i3t_flow::engine`）。
//!
//! 节点里用的是 [`LaneConnector`] 和 [`LaneAcceptor`]：把共用的连接和 lane 装成一个连接层，要求走 ice3proxy 的流（`open_tcp`）
//! 对端间预备有可用 lane 时走 lane，获取失败时静默回退到共用连接；其余流与数据报一律走共用连接。

mod admission;
mod demand;
mod dialler;
mod endpoint;
mod error;
mod frame;
mod holder;
mod lane;
mod mixed;
mod sealed;
mod socket;
mod status;
mod stream;
#[cfg(feature = "test-util")]
pub mod testing;

pub use endpoint::{LaneConfig, LanePeer, Lanes, NoDatagrams, is_lane};
pub use error::{LaneError, OpenLaneError};
pub use frame::FrameError;
pub use i3t_conn::{Payload, RawRead, RawWrite};
pub use lane::ALPN;
pub use mixed::{Choose, EitherRecv, EitherSend, LaneAcceptor, LaneConnector};
pub use status::{HandshakeFailures, LaneCounts, LaneStatus, PeerLaneStatus};
pub use stream::{LaneRecv, LaneSend};
