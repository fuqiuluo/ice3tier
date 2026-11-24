//! 判定不可用 UDP 的节点：对应管理接口中节点的 `no_udp` 字段以及其他节点 netmap 中该对端的 `no_udp` 标志。
//!
//! 用途：`udp_fallback` 仅在路径上缺少 UDP 时启用 ice3proxy，但节点只能观测到自身到对端或首跳中继的传输方式。
//! 当普通节点经支持 UDP 的中继转发至不可用 UDP 的中继时，节点自身这一段走 UDP，无法感知后半段为 TCP；由 controller 统一判定并通知对端。
//! 当前 controller 不再下发 `udp_fallback`（ice3proxy 已作为代理选项按需常开），netmap 中的 `no_udp` 仅对仍按该模式运行的旧节点生效；
//! 管理接口中的 `no_udp` 仍供管理员参考。
//!
//! - 判定依据来自节点上报的 relay 连通性及传输协议（[`relay_reach::without_udp`]）。仅在有节点上报变化后，
//!   于后台任务下一轮重算该网络。
//! - 依据持续成立满 [`Timing::no_udp_settle`](super::Timing) 才正式生效：支持 UDP 的节点也可能短暂退回 TCP（到 relay 的会话先尝试 UDP
//!   1 秒，握手未成功则临时改用 TCP，30 秒后重试 UDP）。稳定期内不改动任何 netmap，避免短时波动导致
//!   对端 netmap 反复重算。一旦依据不再成立则立即取消判定：节点侧的按需拨号自身带有保持时间，不会因此立即断开重拨。
//! - controller 启动时，持久化记录中已满足依据的节点直接生效：重启前通常已处于该状态，避免对端 netmap 先移除后恢复。
//! - 判定状态发生切换时，重算网络中与其存在访问关系的对端节点的 netmap，并与上报触发的重算合并节流。

use std::collections::BTreeSet;
use std::collections::btree_map::Entry;
use std::time::Instant;

use i3t_model::admin::NetworkId;
use i3t_proto::NodeId;

use super::{Failures, Inner};
use crate::error::Error;
use crate::netmap::NodeFacts;
use crate::relay_reach;
use crate::store::NodeRecord;

/// 一个证据成立着的节点。
#[derive(Debug, Clone, Copy)]
pub(crate) struct NoUdp {
    network: NetworkId,
    /// 证据从什么时候起一直成立。
    since: Instant,
    /// 判定是否已生效（已写入其对端的 netmap）。
    settled: bool,
}

impl NodeFacts for Inner {
    fn has_no_udp(&self, node: NodeId) -> bool {
        self.no_udp(node)
    }
}

impl Inner {
    /// 判断 `node` 是否已被判定为不可用 UDP。
    pub(crate) fn no_udp(&self, node: NodeId) -> bool {
        self.no_udp.get(&node).is_some_and(|entry| entry.settled)
    }

    /// 启动初始化：对持久化记录中已满足依据的节点直接生效。
    pub(crate) fn load_no_udp<'a>(&mut self, nodes: impl IntoIterator<Item = &'a NodeRecord> + Clone, now: Instant) {
        let without = relay_reach::without_udp(nodes.clone());
        for node in nodes.into_iter().filter(|node| without.contains(&node.id)) {
            self.no_udp.insert(node.id, NoUdp { network: node.network, since: now, settled: true });
        }
    }

    /// 后台轮询：重算上报记录有变更的网络，使满稳定期的判定生效，并将状态变更通知对端。返回下一个待生效时刻。
    ///
    /// 存储读取错误记录到 `failures`。读取失败的网络留待下一轮重试，其余网络正常计算并通知对端；
    /// 读取失败网络中的节点本轮不生效，也不计算其唤醒时刻，因为在成功读取前无法确认其上报状态是否已变化。
    pub(crate) fn no_udp_tick(&mut self, now: Instant, failures: &mut Failures) -> Option<Instant> {
        let mut changed: Vec<(NetworkId, NodeId)> = Vec::new();
        let mut unread = BTreeSet::new();
        while let Some(network) = self.no_udp_dirty.pop_first() {
            let nodes = match self.store.nodes(network) {
                Ok(nodes) => nodes,
                // 单个网络读取失败不阻塞其他网络：否则前面已计算出的变更无人通知（已移出 `no_udp_dirty`），
                // 若该网络持续失败，排在后面的网络也将长期得不到处理。
                //
                // 若整个数据库不可读，则跳过剩余网络并保留在 `no_udp_dirty` 中：连接无响应时每次读取都会等待完整超时，
                // 且此过程持有 controller 锁。
                Err(error) => {
                    unread.insert(network);
                    let database_wide = error.is_database_wide();
                    failures.keep(Err::<(), Error>(error.into()));
                    if database_wide {
                        break;
                    }
                    continue;
                }
            };
            let without: BTreeSet<NodeId> = relay_reach::without_udp(&nodes);
            for node in &nodes {
                match self.no_udp.entry(node.id) {
                    Entry::Vacant(slot) if without.contains(&node.id) => {
                        tracing::debug!(node = %node.id, "节点所有可达 relay 均未通过 UDP 连通，等待稳定期后再判定其不可用 UDP");
                        slot.insert(NoUdp { network, since: now, settled: false });
                    }
                    Entry::Occupied(slot) if !without.contains(&node.id) => {
                        if slot.remove().settled {
                            tracing::info!(node = %node.id, "节点已恢复经 UDP 连通 relay，取消其不可用 UDP 的判定");
                            changed.push((network, node.id));
                        }
                    }
                    Entry::Vacant(_) | Entry::Occupied(_) => {}
                }
            }
            // 删掉了的节点不再记着。
            let present: BTreeSet<NodeId> = nodes.iter().map(|node| node.id).collect();
            self.no_udp.retain(|id, entry| entry.network != network || present.contains(id));
        }
        // 循环结束之后才放回去，不然同一轮里又会把它取出来。
        self.no_udp_dirty.append(&mut unread);
        let settle = self.timing.no_udp_settle;
        let unread = &self.no_udp_dirty;
        for (id, entry) in self.no_udp.iter_mut().filter(|(_, entry)| !unread.contains(&entry.network)) {
            if !entry.settled && now.saturating_duration_since(entry.since) >= settle {
                entry.settled = true;
                tracing::info!(node = %id, ?settle, "节点在稳定期内所有可达 relay 均仅通过 TCP 连通，判定其不可用 UDP");
                changed.push((entry.network, *id));
            }
        }
        for (network, node) in changed {
            let holders = self.holders_of(node);
            self.defer_report(network, holders);
        }
        // 读取失败的网络留待后续读取成功后再计算：本轮已有错误记录，后台任务会自动安排重试。
        let unread = &self.no_udp_dirty;
        self.no_udp.values().filter(|entry| !entry.settled && !unread.contains(&entry.network)).map(|entry| entry.since + settle).min()
    }
}
