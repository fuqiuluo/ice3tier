//! controller 的指标，Prometheus 的文本格式。
//!
//! 只有合计的数，没有按节点分的标签：这个接口不要管理令牌（见 `crate::admin`），所以不能从它看出网络里有谁。

use i3t_metrics::Exposition;

use super::{Controller, count};
use crate::error::Error;

/// 启动以来的累计数。都在 controller 的那把锁里改，所以用普通的整数。
#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub(crate) snapshots_sent: u64,
    pub(crate) orders_sent: u64,
    pub(crate) orders_cancelled: u64,
    pub(crate) version_failures: u64,
    pub(crate) release_checks: u64,
    pub(crate) release_check_failures: u64,
    pub(crate) package_bytes: u64,
    pub(crate) route_queries: u64,
}

impl Controller {
    /// 当前的指标，可以直接作为 `/metrics` 的应答。
    ///
    /// # Errors
    ///
    /// 读存储失败。
    pub fn metrics(&self) -> Result<String, Error> {
        let inner = self.lock();
        let overview = inner.update_overview()?;
        let counters = &inner.counters;
        let mut out = Exposition::new();
        out.gauge("i3t_controller_info", "controller 版本", &[("version", &overview.controller_version.to_string())], 1.0);
        out.gauge("i3t_controller_networks", "网络数量", &[], f64::from(count(inner.store.networks()?.len())));
        out.gauge("i3t_controller_nodes", "已注册节点数量", &[], f64::from(inner.store.node_count(None)?));
        out.gauge("i3t_controller_nodes_online", "当前在线节点数量", &[], f64::from(count(inner.live.len())));
        out.counter("i3t_controller_snapshots_sent_total", "启动以来下发给节点的 netmap 份数", &[], counters.snapshots_sent);
        out.counter("i3t_controller_route_queries_total", "启动以来发送给节点的路由查询次数", &[], counters.route_queries);

        out.gauge("i3t_controller_update_auto", "自动更新开关（1 表示开启，0 表示关闭）", &[], f64::from(u8::from(overview.auto_update)));
        let release = overview.release.as_ref().map(|release| release.version.to_string());
        if let Some(version) = &release {
            out.gauge("i3t_controller_update_release_info", "已知的最新正式版", &[("version", version)], 1.0);
        }
        out.gauge("i3t_controller_update_paused_versions", "已暂停自动更新的版本数量", &[], f64::from(count(overview.paused.len())));
        let nodes = overview.nodes;
        let by_state = [
            ("updating", nodes.updating),
            ("failed", nodes.failed),
            ("manual", nodes.manual),
            ("outdated", nodes.outdated),
            ("up_to_date", nodes.up_to_date),
        ];
        for (state, nodes) in by_state {
            out.gauge("i3t_controller_update_nodes", "按更新状态统计的节点数量", &[("state", state)], f64::from(nodes));
        }
        out.counter("i3t_controller_update_orders_total", "启动以来下发的更新指令数", &[], counters.orders_sent);
        out.counter("i3t_controller_update_cancels_total", "启动以来撤回的更新指令数", &[], counters.orders_cancelled);
        out.counter(
            "i3t_controller_update_version_failures_total",
            "启动以来节点上报的归因于版本的更新失败次数",
            &[],
            counters.version_failures,
        );
        out.counter("i3t_controller_release_checks_total", "启动以来检查发布源的次数", &[], counters.release_checks);
        out.counter("i3t_controller_release_check_failures_total", "启动以来检查发布源失败的次数", &[], counters.release_check_failures);
        out.counter("i3t_controller_package_bytes_sent_total", "启动以来发送给节点的更新包字节数", &[], counters.package_bytes);
        Ok(out.finish())
    }
}
