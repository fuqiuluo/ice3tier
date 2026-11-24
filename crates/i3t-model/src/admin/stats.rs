//! 管理 API 里的时间序列：controller 为界面的图表留着的一份低分辨率的数。
//!
//! 只有一小组固定的序列，都是 controller 本来就收到的东西：网络里在线的节点数、活跃流、流量；每个节点的流量和活跃流；
//! 每个 relay 上挂靠着的节点数；每个出口替别人收发的流量。长期的、细的数据交给节点自己暴露的指标和外部的 Prometheus。

use std::fmt;
use std::str::FromStr;

use i3t_proto::NodeId;
use serde::{Deserialize, Serialize};

use super::{NodeRef, Timestamp};

/// 一条序列。网络的序列不带节点；节点、relay、出口的序列要指明是哪个节点。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Series {
    /// 网络里在线的节点数。
    Online,
    /// 网络里各个节点上报的活跃流之和。一条流两端各报一次。
    Flows,
    /// 网络里各个节点经流发出的速率之和。
    Tx,
    /// 网络里各个节点经流收到的速率之和。
    Rx,
    /// 一个节点经它的流发出的速率（入口一侧客户端发出的，出口一侧发往目标的）。
    NodeTx,
    /// 一个节点经它的流收到的速率。
    NodeRx,
    /// 一个节点上正在进行的流。
    NodeFlows,
    /// 挂靠在一个 relay 上的在线节点数。
    RelayAttached,
    /// 一个出口替别人发往目标的速率。
    ExitTx,
    /// 一个出口替别人从目标收到的速率。
    ExitRx,
}

impl Series {
    pub const ALL: [Self; 10] = [
        Self::Online,
        Self::Flows,
        Self::Tx,
        Self::Rx,
        Self::NodeTx,
        Self::NodeRx,
        Self::NodeFlows,
        Self::RelayAttached,
        Self::ExitTx,
        Self::ExitRx,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Flows => "flows",
            Self::Tx => "tx",
            Self::Rx => "rx",
            Self::NodeTx => "node_tx",
            Self::NodeRx => "node_rx",
            Self::NodeFlows => "node_flows",
            Self::RelayAttached => "relay_attached",
            Self::ExitTx => "exit_tx",
            Self::ExitRx => "exit_rx",
        }
    }

    /// 这条序列是不是某一个节点的（要带 `node`）。
    #[must_use]
    pub const fn per_node(self) -> bool {
        match self {
            Self::Online | Self::Flows | Self::Tx | Self::Rx => false,
            Self::NodeTx | Self::NodeRx | Self::NodeFlows | Self::RelayAttached | Self::ExitTx | Self::ExitRx => true,
        }
    }

    #[must_use]
    pub const fn unit(self) -> Unit {
        match self {
            Self::Online | Self::Flows | Self::NodeFlows | Self::RelayAttached => Unit::Count,
            Self::Tx | Self::Rx | Self::NodeTx | Self::NodeRx | Self::ExitTx | Self::ExitRx => Unit::BytesPerSecond,
        }
    }
}

impl fmt::Display for Series {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Series {
    type Err = UnknownSeries;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.into_iter().find(|series| series.as_str() == s).ok_or_else(|| UnknownSeries(s.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("未知的序列 {0:?}")]
pub struct UnknownSeries(pub String);

/// 序列里的值是什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    /// 数量（节点数、流数）。每个时间桶的值为该时间段内的平均值，因此可能带有小数。
    Count,
    /// 字节每秒。每个时间桶的值为该时间段内节点在线期间的平均速率。
    BytesPerSecond,
}

/// 读一条序列（`GET …/stats` 的查询参数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeriesQuery {
    pub series: Series,
    /// 节点、relay、出口的序列要写；网络的序列不能写。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
    /// 时间范围的开始，Unix 秒；省略时是 `to` 之前 24 小时。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Timestamp>,
    /// 时间范围的结束，Unix 秒；省略时是现在。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Timestamp>,
    /// 点的间隔，秒：300 或 3600。省略时范围的开始还在 300 秒那一档的保留期里（或者早不到 300 秒：客户端的钟、
    /// 请求路上花的时间）就用 300，否则用 3600。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<u32>,
}

/// 一条序列在一段时间里的点，可以直接交给图表。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SeriesView {
    pub series: Series,
    /// 节点的序列是这个节点；网络的序列是 `null`。
    pub node: Option<NodeRef>,
    pub unit: Unit,
    /// 两个点之间隔几秒。
    pub step: u32,
    /// 第一个点和最后一个点的时间（都按 `step` 对齐）。
    pub from: Timestamp,
    pub to: Timestamp,
    /// `[时间, 值]`。时间为该时间桶的起始时间，覆盖从 `from` 到 `to` 的每个时间桶；无数据的区间（节点离线、controller 未运行
    /// 或已超出保留期）其值为 `null`，在图表中显示为断开。尚未结束的当前时间桶不包含在内。
    pub points: Vec<(Timestamp, Option<f64>)>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn series_names_round_trip_through_text_and_json() {
        for series in Series::ALL {
            assert_eq!(series.as_str().parse::<Series>().unwrap(), series);
            assert_eq!(serde_json::to_value(series).unwrap(), json!(series.as_str()));
        }
        assert!("nodes".parse::<Series>().is_err());
    }

    #[test]
    fn a_view_writes_gaps_as_null() {
        let view = SeriesView {
            series: Series::Online,
            node: None,
            unit: Unit::Count,
            step: 300,
            from: 600,
            to: 900,
            points: vec![(600, Some(2.5)), (900, None)],
        };
        let value = serde_json::to_value(&view).unwrap();
        assert_eq!(value["points"], json!([[600, 2.5], [900, null]]));
        assert_eq!(value["unit"], json!("count"));
    }
}
