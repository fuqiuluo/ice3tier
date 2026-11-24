//! 出口测试（`i3tctl exit test`，路径诊断里的"一个出口节点加一个目标"）在节点协议里的样子：
//!
//! ```text
//! controller → 出口节点   ExitTest { 编号, 主机, 端口 }
//! 出口节点 → controller   ExitTestAnswer { 编号, 结果 }
//! ```
//!
//! 出口节点按它替别人连这个目标时的同一套规矩做：不是出口、端口不允许、解析出来的地址不能连，都在 [`ExitTestResult::refused`] 里
//! 说出原因，和别人经它访问时被拒绝的原因一样。管理 API 的结果也是这几个结构，数都带着单位写在名字里（毫秒）。

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::netmap::IpFamily;

/// 出口节点做完一次测试的结果。没有做到的步骤是 `None`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitTestResult {
    /// 经什么连目标：自己直接连，还是出口配的上游 SOCKS5 代理。
    pub via: ExitVia,
    /// 出口节点不做这次测试（另一个测试在做），或者按出口的策略不替别人连这个目标的原因。有值时后面的步骤只做到被拒绝的那一步。
    #[serde(default)]
    pub refused: Option<ExitTestCause>,
    /// 解析域名。目标本来就是地址时是 `None`。
    #[serde(default)]
    pub resolve: Option<ResolveStep>,
    /// 连目标。
    #[serde(default)]
    pub connect: Option<ConnectStep>,
    /// 端口是 443 时，连上之后做一次 TLS 握手。
    #[serde(default)]
    pub tls: Option<TlsStep>,
}

/// 出口经什么连目标。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitVia {
    Direct,
    /// 出口配的上游 SOCKS5 代理（`ExitRole::upstream_socks5`）。
    Upstream,
    #[serde(other)]
    Unknown,
}

/// 解析域名这一步。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveStep {
    /// 用了多久，失败时是到失败为止。
    pub ms: u32,
    /// 解析出来的地址，最多 8 个，按解析器给的顺序。
    #[serde(default)]
    pub addresses: Vec<IpAddr>,
    /// 出口只连哪一种地址（出口的设置）：解析出来的地址里只有这一种会去连。
    pub family: IpFamily,
    /// 失败的原因；成功是 `None`。
    #[serde(default)]
    pub cause: Option<ExitTestCause>,
}

/// 连目标这一步。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectStep {
    pub ms: u32,
    /// 连上的那个地址；都没有连上时是 `None`。
    #[serde(default)]
    pub address: Option<SocketAddr>,
    #[serde(default)]
    pub cause: Option<ExitTestCause>,
}

/// TLS 握手这一步。只看握手能不能完成、要多久，不检查证书：这一步不说网站是不是真的。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsStep {
    pub ms: u32,
    #[serde(default)]
    pub cause: Option<ExitTestCause>,
}

/// 出口测试中某一步骤失败的原因码，供界面按当前语言展示。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ExitTestCause {
    /// 出口节点上另一个测试正在做，或者刚做过（每 2 秒最多一个）。
    Busy,
    /// 出口节点无法解析该目标。
    BadTarget,
    /// 这个节点没有启用出口。
    NotEnabled,
    /// 目标是局域网的地址，出口没有打开"允许访问本机局域网"。
    LanNotEnabled,
    /// 互联网目标的端口不在出口允许的范围里。
    PortNotAllowed { port: u16 },
    /// 出口只连一种地址，解析出来的地址里没有这一种（或者目标就是另一种地址）。
    FamilyUnavailable { family: IpFamily },
    /// 出口不替别人连这个地址：私有、回环这类地址，覆盖网的地址，本机网卡所在网段的，节点自己的。
    AddressNotAllowed { address: IpAddr },
    /// 局域网目标不在出口的网卡直连的网段里（或者是回环、链路本地这类不算局域网的地址）。
    NotOnLan { address: IpAddr },
    /// 域名不存在，或者没有地址记录。
    NameNotFound,
    /// 解析器出错。
    ResolverFailed,
    /// 超时（解析、连接或者握手，看是哪一步）。
    Timeout,
    /// 目标拒绝了连接。
    Refused,
    /// 目标所在的网络或主机不可达。
    Unreachable,
    /// 无法连接出口的上游代理。
    UpstreamFailed,
    /// TLS 握手完成前对端关闭了连接。
    Closed,
    /// TLS 握手时对端返回告警（例如不识别该服务器名称）。
    Alert,
    /// 其他原因，详见出口节点日志。
    Other,
    /// 较新版本节点上报的未知原因。
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_result_has_a_stable_json_shape_and_reads_new_codes_as_unknown() {
        let result = ExitTestResult {
            via: ExitVia::Direct,
            refused: None,
            resolve: Some(ResolveStep { ms: 12, addresses: vec!["93.184.216.34".parse().unwrap()], family: IpFamily::Any, cause: None }),
            connect: Some(ConnectStep { ms: 30, address: Some("93.184.216.34:443".parse().unwrap()), cause: None }),
            tls: Some(TlsStep { ms: 61, cause: Some(ExitTestCause::Alert) }),
        };
        let wire = serde_json::to_value(&result).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({
                "via": "direct", "refused": null,
                "resolve": { "ms": 12, "addresses": ["93.184.216.34"], "family": "any", "cause": null },
                "connect": { "ms": 30, "address": "93.184.216.34:443", "cause": null },
                "tls": { "ms": 61, "cause": { "code": "alert" } }
            })
        );
        assert_eq!(serde_json::from_value::<ExitTestResult>(wire).unwrap(), result);
        let refused = serde_json::to_value(ExitTestCause::PortNotAllowed { port: 8080 }).unwrap();
        assert_eq!(refused, serde_json::json!({ "code": "port_not_allowed", "port": 8080 }));
        let newer: ExitTestCause = serde_json::from_value(serde_json::json!({ "code": "later", "x": 1 })).unwrap();
        assert_eq!(newer, ExitTestCause::Unknown);
    }
}
