//! 旧版透明访问模式（0.1.7 至 0.1.25，Linux）遗留系统配置的检测与清理：虚拟网卡已取代该模式，节点异常终止时残留的规则需在此清理。
//!
//! 这些残留不仅多余，其中的 nftables 表还会将发往虚拟网段的连接重定向至无人监听的端口并拒绝其余流量，
//! 导致虚拟网卡无法正常通信。本模块沿用原有识别特征，仅操作可明确归属于旧版透明访问的配置项：
//!
//! | 配置项 | 识别依据 |
//! |---|---|
//! | nftables 表 `ip i3t` | 表名（虚拟网卡使用的表名均带有数字编号） |
//! | 策略路由 `2033: fwmark 0x20000000/0x20000000 lookup 2033 proto 203` | 优先级 2033 且 `proto 203` |
//! | 路由表 2033 中的路由 | `proto 203` |
//! | dummy 虚拟接口 `i3t0` | 接口类型为 `dummy` 且别名为 `ice3tier` |

use serde_json::Value;

use crate::machine::{CommandError, Machine, Program};
use crate::plan::linux;
use crate::survey::has_table;

const TABLE: &str = "i3t";
const RULE_PRIORITY: u64 = 2033;
const ROUTE_TABLE: &str = "2033";
const PROTO: &str = "203";
const LINK: &str = "i3t0";
const LINK_ALIAS: &str = "ice3tier";

/// 探测到的旧版透明访问遗留项汇总。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Leftover {
    pub table: bool,
    /// 匹配旧版透明访问特征的策略路由规则条数。
    pub rules: usize,
    pub routes: bool,
    pub link: bool,
}

impl Leftover {
    /// 判断是否未检测到任何旧版遗留配置。
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.table && self.rules == 0 && !self.routes && !self.link
    }

    /// 将检测到的遗留项格式化为系统级名称列表（面向用户展示，不做本地化翻译）。
    #[must_use]
    pub fn items(&self) -> Vec<&'static str> {
        [(self.table, "table ip i3t"), (self.rules > 0, "ip rule 2033"), (self.routes, "ip route table 2033"), (self.link, "dummy i3t0")]
            .into_iter()
            .filter_map(|(found, item)| found.then_some(item))
            .collect()
    }

    /// 扫描当前系统中的旧版透明访问遗留配置（Linux）。
    ///
    /// # Errors
    ///
    /// 执行系统命令失败或无法解析命令输出时返回错误。
    pub fn find(machine: &mut impl Machine) -> Result<Self, CommandError> {
        let table = has_table(&machine.run(Program::Nft, &linux::list_tables(), None)?, TABLE)?;
        let rules = rules(&machine.run(Program::Ip, &args(&["-j", "rule", "show"]), None)?)?;
        let routes = match machine.run(Program::Ip, &args(&["-j", "route", "show", "table", ROUTE_TABLE]), None) {
            Ok(json) => listing(&json)?.iter().any(|route| text(route.get("protocol")).as_deref() == Some(PROTO)),
            Err(error) if error.says("does not exist") => false,
            Err(error) => return Err(error),
        };
        let link = match machine.run(Program::Ip, &args(&["-j", "-d", "link", "show", "dev", LINK]), None) {
            Ok(json) => listing(&json)?.first().is_some_and(|link| {
                link.get("linkinfo").and_then(|info| text(info.get("info_kind"))).as_deref() == Some("dummy")
                    && text(link.get("ifalias")).as_deref() == Some(LINK_ALIAS)
            }),
            Err(error) if error.says("does not exist") => false,
            Err(error) => return Err(error),
        };
        Ok(Self { table, rules, routes, link })
    }

    /// 依次清理已检测到的遗留配置项。各项独立执行，返回首个发生的错误。
    ///
    /// # Errors
    ///
    /// 任一配置项清理失败时返回首个错误，其余配置项仍会继续尝试清理。
    pub fn remove(&self, machine: &mut impl Machine) -> Result<(), CommandError> {
        let mut first = None;
        let mut keep = |result: Result<String, CommandError>| {
            if let Err(error) = result {
                first.get_or_insert(error);
            }
        };
        if self.table {
            keep(machine.run(Program::Nft, &args(&["-f", "-"]), Some(&linux::remove_table_script(TABLE))));
        }
        let rule = args(&["rule", "del", "priority", "2033", "fwmark", "0x20000000/0x20000000", "lookup", ROUTE_TABLE, "proto", PROTO]);
        for _ in 0..self.rules {
            keep(machine.run(Program::Ip, &rule, None));
        }
        if self.routes {
            keep(machine.run(Program::Ip, &args(&["route", "flush", "table", ROUTE_TABLE, "proto", PROTO]), None));
        }
        if self.link {
            keep(machine.run(Program::Ip, &args(&["link", "del", LINK]), None));
        }
        first.map_or(Ok(()), Err)
    }
}

/// 统计 `ip -j rule show` 输出中属于旧版透明访问的策略路由规则条数。
fn rules(json: &str) -> Result<usize, CommandError> {
    let rules = listing(json)?;
    Ok(rules
        .iter()
        .filter(|rule| rule.get("priority").and_then(Value::as_u64) == Some(RULE_PRIORITY))
        .filter(|rule| text(rule.get("protocol")).as_deref() == Some(PROTO))
        .count())
}

/// 解析 `ip -j` 输出的 JSON 数组。空输出视为空列表；无法解析的内容返回错误，而非视为无条目。
fn listing(json: &str) -> Result<Vec<Value>, CommandError> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(json)
        .map_err(|error| CommandError::Io { program: Program::Ip, detail: format!("无法解析 ip 命令输出：{error}") })
}

/// 提取 `ip -j` 字段值（不同版本可能将编号序列化为字符串或整数）。
fn text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一台按命令应答的假机器，记下执行过的命令。
    struct Fake {
        answers: Vec<(&'static str, Result<String, CommandError>)>,
        log: Vec<String>,
    }

    impl Machine for Fake {
        fn run(&mut self, program: Program, args: &[String], _input: Option<&str>) -> Result<String, CommandError> {
            let line = format!("{program} {}", args.join(" "));
            self.log.push(line.clone());
            match self.answers.iter().position(|(prefix, _)| line.starts_with(prefix)) {
                Some(at) => self.answers.remove(at).1,
                None => Ok(String::new()),
            }
        }
    }

    fn failed(detail: &str) -> CommandError {
        CommandError::Failed { program: Program::Ip, status: Some(1), detail: detail.into() }
    }

    // 以前的透明访问装好之后，iproute2 6.17 和 nftables 1.1.6 真的输出（截取）。
    const RULES: &str = r#"[{"priority":0,"src":"all","table":"local"},{"priority":2033,"src":"all","fwmark":"0x20000000","fwmask":"0x20000000","table":"2033","protocol":"203"},{"priority":2033,"src":"all","fwmark":"0x1","table":"7"}]"#;
    const ROUTES: &str = r#"[{"type":"local","dst":"default","dev":"lo","protocol":"203","scope":"host","flags":[]}]"#;
    const LINK_JSON: &str = r#"[{"ifindex":2,"ifname":"i3t0","ifalias":"ice3tier","linkinfo":{"info_kind":"dummy"}}]"#;

    #[test]
    fn every_piece_the_old_transparent_access_left_is_found_and_removed() {
        let mut fake = Fake {
            answers: vec![
                ("nft -j list tables ip", Ok(r#"{"nftables": [{"table": {"family": "ip", "name": "i3t"}}]}"#.into())),
                ("ip -j rule show", Ok(RULES.into())),
                ("ip -j route show table 2033", Ok(ROUTES.into())),
                ("ip -j -d link show dev i3t0", Ok(LINK_JSON.into())),
            ],
            log: Vec::new(),
        };
        let found = Leftover::find(&mut fake).unwrap();
        assert_eq!(found, Leftover { table: true, rules: 1, routes: true, link: true });
        assert_eq!(found.items(), ["table ip i3t", "ip rule 2033", "ip route table 2033", "dummy i3t0"]);
        fake.log.clear();
        found.remove(&mut fake).unwrap();
        assert_eq!(
            fake.log,
            [
                "nft -f -",
                "ip rule del priority 2033 fwmark 0x20000000/0x20000000 lookup 2033 proto 203",
                "ip route flush table 2033 proto 203",
                "ip link del i3t0"
            ]
        );
    }

    #[test]
    fn a_clean_machine_and_someone_elses_things_are_left_alone() {
        let mut fake = Fake {
            answers: vec![
                ("nft -j list tables ip", Ok(r#"{"nftables": [{"table": {"family": "ip", "name": "filter"}}]}"#.into())),
                ("ip -j rule show", Ok(r#"[{"priority":2033,"src":"all","table":"7"}]"#.into())),
                ("ip -j route show table 2033", Err(failed("Error: ipv4: FIB table does not exist."))),
                ("ip -j -d link show dev i3t0", Ok(r#"[{"ifname":"i3t0","linkinfo":{"info_kind":"tun"}}]"#.into())),
            ],
            log: Vec::new(),
        };
        let found = Leftover::find(&mut fake).unwrap();
        assert!(found.is_empty(), "{found:?}：同名的 TUN 是虚拟网卡自己的，同优先级没有 proto 203 的规则是别人的");
    }

    #[test]
    fn an_unreadable_answer_is_an_error() {
        let mut fake = Fake { answers: vec![("nft -j list tables ip", Ok("garbage".into()))], log: Vec::new() };
        assert!(Leftover::find(&mut fake).is_err());
    }
}
