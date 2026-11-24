//! 探测系统中当前存在的、归属于虚拟网卡的自有防火墙配置。
//!
//! 安装前先探测，用于识别并替换异常崩溃遗留的规则，避免产生重复项；`i3t network status` 也依赖此结果。
//! Linux 解析 `nft -j` 的 JSON 与 `iptables -S` 的文本输出，Windows 解析 PowerShell 统计的规则数；非自有规则一律忽略。

use ipnet::Ipv4Net;
use serde_json::Value;

use crate::device::Platform;
use crate::machine::{CommandError, Machine, Program};
use crate::plan::{linux, windows};
use crate::{COMMENT, is_device_name};

/// 系统防火墙现状探测结果。各项独立查询，单项读取失败（如普通用户无权读取规则或内核无 `raw` 表）不影响其余项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Survey {
    /// 自有防伪造 nftables 表列表（Linux 启用 `nft` 时安装，表名即网卡名），按字典序排列。
    pub tables: Result<Vec<String>, CommandError>,
    /// 自有入站放行规则列表，按链中顺序排列。
    pub accept: Result<Vec<AcceptRule>, CommandError>,
    /// 自有 `raw` 表 `PREROUTING` 链防伪造规则列表（Linux 无 `nft` 时安装），按链中顺序排列。
    pub guard_rules: Result<Vec<GuardRule>, CommandError>,
}

/// 单条自有入站放行规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptRule {
    /// 规则关联的虚拟网卡名称。
    pub device: String,
    /// Linux：在 `INPUT` 链中的位置序号（从 1 开始）；Windows 不区分顺序，固定为 1。
    pub position: usize,
}

/// 单条自有防伪造规则（Linux `raw` 表 `PREROUTING` 链）。每块网卡对应两条：按源网段（`-s`）与按目的地址（`-d`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardRule {
    /// 规则关联的虚拟网卡名称（来自 `! -i <网卡>`）。
    pub device: String,
    /// 在 `PREROUTING` 链中的位置序号（从 1 开始）。
    pub position: usize,
    /// 拦截的源网段（`-s`）。缺失或无法解析时为 `None`；此类自有规则会在安装时按需替换。
    pub range: Option<Ipv4Net>,
    /// 拦截的目的地址（`-d`，即本节点虚拟 IP `/32`）。
    pub destination: Option<Ipv4Net>,
    /// `iptables -S` 输出行去掉 `-A PREROUTING ` 后的原文，删除时原样回传（[`linux::delete_guard`]）。
    pub rule: String,
}

impl Survey {
    /// 在目标平台 `platform` 上执行一次完整探测。`device` 用于 Windows 构造规则名（Linux 按自有注释全局扫描）。
    pub fn take(machine: &mut impl Machine, platform: Platform, device: &str) -> Self {
        match platform {
            Platform::Linux => {
                let tables = machine.run(Program::Nft, &linux::list_tables(), None).and_then(|json| parse_tables(&json));
                let accept = machine.run(Program::Iptables, &linux::list_input(), None).map(|text| parse_input(&text));
                let guard_rules =
                    machine.run(Program::Iptables, &linux::list_raw_prerouting(), None).map(|text| parse_raw_prerouting(&text));
                Self { tables, accept, guard_rules }
            }
            Platform::Windows => {
                let accept =
                    machine.run(Program::PowerShell, &windows::invocation(&windows::count_script(device)), None).and_then(|text| {
                        let count = text.trim().parse::<usize>().map_err(|_| CommandError::Io {
                            program: Program::PowerShell,
                            detail: format!("无法解析防火墙规则计数输出：{}", text.trim()),
                        })?;
                        Ok((0..count).map(|_| AcceptRule { device: device.to_owned(), position: 1 }).collect())
                    });
                Self { tables: Ok(Vec::new()), accept, guard_rules: Ok(Vec::new()) }
            }
            Platform::MacOs | Platform::Other => Self { tables: Ok(Vec::new()), accept: Ok(Vec::new()), guard_rules: Ok(Vec::new()) },
        }
    }

    /// 判断是否探测到至少一项自有防火墙配置。读取失败的项不计入。
    #[must_use]
    pub fn found_any(&self) -> bool {
        self.counts().into_iter().any(|count| count.is_some_and(|count| count > 0))
    }

    /// 判断所有自有防火墙配置是否均已清空。读取失败的项不视为“无残留”。
    ///
    /// 若错误表明对应程序或表本身不存在（[`CommandError::means_absent`]），则该项按 0 计：未安装 `nft` 不会创建自有表，
    /// 未安装 `iptables` 或内核无 `raw` 表则不会存在相应规则。若安装表后再卸载 `nft`，虽表仍存于内核但主机已无工具可删除
    /// （卸载流程同样视为已清空），且其仅拦截伪造虚拟 IP 的入站包，系统重启后即自动清除。
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.counts().into_iter().all(|count| count == Some(0))
    }

    /// 汇总三类配置的自有条目数量。读取失败为 `None`，程序或表不存在时为 `Some(0)`。
    fn counts(&self) -> [Option<usize>; 3] {
        [count(&self.tables), count(&self.accept), count(&self.guard_rules)]
    }
}

fn count<T>(item: &Result<Vec<T>, CommandError>) -> Option<usize> {
    match item {
        Ok(found) => Some(found.len()),
        Err(error) => error.means_absent().then_some(0),
    }
}

/// 从 `nft -j list tables ip` 输出中提取自有表名（匹配虚拟网卡命名规则）。旧版透明访问表 `i3t`（无数字编号）不在此列，见 [`crate::legacy`]。
fn parse_tables(json: &str) -> Result<Vec<String>, CommandError> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| CommandError::Io { program: Program::Nft, detail: format!("无法解析 nft 命令输出：{error}") })?;
    let objects = value.get("nftables").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let mut names: Vec<String> = objects
        .iter()
        .filter_map(|object| object.get("table")?.get("name")?.as_str())
        .filter(|name| is_device_name(name))
        .map(str::to_owned)
        .collect();
    names.sort();
    Ok(names)
}

/// 检查 `nft -j list tables ip` 输出中是否存在指定名称 `name` 的表。
pub(crate) fn has_table(json: &str, name: &str) -> Result<bool, CommandError> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| CommandError::Io { program: Program::Nft, detail: format!("无法解析 nft 命令输出：{error}") })?;
    let objects = value.get("nftables").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    Ok(objects.iter().any(|object| object.get("table").and_then(|table| table.get("name")).and_then(Value::as_str) == Some(name)))
}

/// 从 `iptables -S INPUT` 输出中筛选自有放行规则：以 `-A INPUT` 开头、注释为 [`COMMENT`]、动作为 `ACCEPT` 且接口符合虚拟网卡命名。
fn parse_input(text: &str) -> Vec<AcceptRule> {
    Listed::all(text, "INPUT")
        .filter(|rule| rule.is_ours("ACCEPT"))
        .filter_map(|rule| {
            let device = rule.after("-i").filter(|device| is_device_name(device))?;
            Some(AcceptRule { device: device.to_owned(), position: rule.position })
        })
        .collect()
}

/// 从 `iptables -t raw -S PREROUTING` 输出中筛选自有防伪造规则：以 `-A PREROUTING` 开头、注释为 [`COMMENT`]、动作为 `DROP`
/// 且匹配 `! -i <虚拟网卡>`。不限定源网段，确保网段变更后遗留的旧规则仍可被识别清理。
fn parse_raw_prerouting(text: &str) -> Vec<GuardRule> {
    Listed::all(text, "PREROUTING")
        .filter(|rule| rule.is_ours("DROP"))
        .filter_map(|rule| {
            let device = rule.after_negated("-i").filter(|device| is_device_name(device))?;
            let range = rule.after("-s").and_then(|source| source.parse().ok());
            let destination = rule.after("-d").and_then(|destination| destination.parse().ok());
            Some(GuardRule { device: device.to_owned(), position: rule.position, range, destination, rule: rule.text.to_owned() })
        })
        .collect()
}

/// 解析后的单条 `iptables -S <链>` 规则。
struct Listed<'a> {
    /// 在链中的 1-based 序号。
    position: usize,
    /// 原始行去掉 `-A <链> ` 后的文本。
    text: &'a str,
    /// 去除引号并拆分后的参数词列表（[`linux::split_listed`]），确保带空格的注释作为单个完整词精确匹配。
    words: Vec<String>,
}

impl<'a> Listed<'a> {
    /// 按序遍历 `iptables -S <chain>` 输出中的规则行；默认策略行（`-P`）不计入位置序号。
    fn all(output: &'a str, chain: &str) -> impl Iterator<Item = Self> {
        let prefix = format!("-A {chain} ");
        output.lines().filter_map(move |line| line.strip_prefix(prefix.as_str())).enumerate().map(|(index, text)| Self {
            position: index + 1,
            text,
            words: linux::split_listed(text),
        })
    }

    /// 返回紧跟在 `flag` 后的参数值。
    fn after(&self, flag: &str) -> Option<&str> {
        self.words.windows(2).find(|pair| pair[0] == flag).map(|pair| pair[1].as_str())
    }

    /// 返回紧跟在 `! <flag>` 后的参数值（例如 `! -i i3t0` 中的 `i3t0`）。
    fn after_negated(&self, flag: &str) -> Option<&str> {
        self.words.windows(3).find(|three| three[0] == "!" && three[1] == flag).map(|three| three[2].as_str())
    }

    /// 判断注释是否为 [`COMMENT`] 且跳转目标匹配 `target`。
    fn is_ours(&self, target: &str) -> bool {
        self.after("--comment") == Some(COMMENT) && self.after("-j") == Some(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // nftables 1.1.6 在一个网络命名空间里真的输出（另有一张 ufw 的表、一张以前的透明访问的表）。
    const TABLES: &str = r#"{"nftables": [{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}, {"table": {"family": "ip", "name": "filter", "handle": 1}}, {"table": {"family": "ip", "name": "i3t0", "handle": 2}}, {"table": {"family": "ip", "name": "i3t", "handle": 3}}]}"#;
    // iptables 1.8.11（nf_tables 后端）的 -S INPUT：ufw 风格的规则夹着自己的。
    const INPUT: &str = "-P INPUT DROP\n-A INPUT -i i3t0 -m comment --comment ice3tier -j ACCEPT\n-A INPUT -j ufw-before-input\n\
                         -A INPUT -i i3t1 -m comment --comment ice3tier -j ACCEPT\n-A INPUT -i eth0 -m comment --comment ice3tier -j ACCEPT\n\
                         -A INPUT -i i3t0 -m comment --comment \"someone else\" -j ACCEPT\n-A INPUT -i i3t0 -m comment --comment ice3tier -j DROP\n";

    #[test]
    fn our_tables_are_the_ones_named_like_our_devices() {
        assert_eq!(parse_tables(TABLES).unwrap(), ["i3t0"]);
        assert!(has_table(TABLES, "i3t").unwrap());
        assert!(!has_table(TABLES, "i3t9").unwrap());
        assert!(parse_tables(r#"{"nftables": []}"#).unwrap().is_empty());
        assert!(parse_tables("not json").is_err(), "读不懂的是错误，不是没有");
    }

    #[test]
    fn our_input_rules_carry_our_comment_accept_and_a_device_of_ours_and_keep_their_position() {
        assert_eq!(
            parse_input(INPUT),
            [AcceptRule { device: "i3t0".into(), position: 1 }, AcceptRule { device: "i3t1".into(), position: 3 }]
        );
        assert!(parse_input("-P INPUT ACCEPT\n").is_empty());
    }

    // -t raw -S PREROUTING：Docker 的、别人的、注释带引号的规则夹着自己的三条（i3t0 的两条，i3t1 那条是地址段变了之前、
    // 还没有按目的的那条时的）。按 iptables 1.8 写规则的次序（-s、-d、! -i、各个 -m、-j）写的。
    const RAW: &str = "-P PREROUTING ACCEPT\n\
                       -A PREROUTING -d 172.17.0.2/32 ! -i docker0 -j DROP\n\
                       -A PREROUTING -s 10.66.0.0/16 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP\n\
                       -A PREROUTING -d 10.66.0.1/32 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP\n\
                       -A PREROUTING -p udp -m udp --dport 53 -j CT --notrack\n\
                       -A PREROUTING -s 10.66.0.0/16 ! -i i3t0 -m comment --comment \"ice3tier \\\"old\\\"\" -j DROP\n\
                       -A PREROUTING -s 10.99.0.0/16 ! -i i3t1 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP\n\
                       -A PREROUTING -s 10.66.0.0/16 -i i3t0 -m comment --comment ice3tier -j DROP\n\
                       -A PREROUTING -s 10.66.0.0/16 ! -i eth0 -m comment --comment ice3tier -j DROP\n\
                       -A PREROUTING -s 10.66.0.0/16 ! -i i3t2 -m comment --comment ice3tier -j ACCEPT\n";

    #[test]
    fn our_raw_rules_carry_our_comment_drop_and_not_a_device_of_ours_and_keep_their_position_range_and_spelling() {
        let rule = |device: &str, position, range: &str, text: &str| GuardRule {
            device: device.into(),
            position,
            range: Some(range.parse().unwrap()),
            destination: None,
            rule: text.into(),
        };
        let to_us = "-d 10.66.0.1/32 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP";
        assert_eq!(
            parse_raw_prerouting(RAW),
            [
                rule(
                    "i3t0",
                    2,
                    "10.66.0.0/16",
                    "-s 10.66.0.0/16 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP"
                ),
                GuardRule { range: None, destination: Some("10.66.0.1/32".parse().unwrap()), ..rule("i3t0", 3, "0.0.0.0/0", to_us) },
                rule(
                    "i3t1",
                    6,
                    "10.99.0.0/16",
                    "-s 10.99.0.0/16 ! -i i3t1 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP"
                ),
            ],
            "注释带引号的那条（ice3tier \"old\"）不是自己的；-i（没有 !）、eth0、ACCEPT 的也不是"
        );
        assert!(parse_raw_prerouting("-P PREROUTING ACCEPT\n").is_empty());
        let without_source = parse_raw_prerouting("-A PREROUTING ! -i i3t0 -m comment --comment ice3tier -j DROP\n");
        assert_eq!(without_source.len(), 1, "没有地址段的也是自己的：装的时候换掉");
        assert_eq!((without_source[0].range, without_source[0].destination), (None, None));
    }

    #[derive(Default)]
    struct Answers(Vec<(Program, Result<String, CommandError>)>);

    impl Machine for Answers {
        fn run(&mut self, program: Program, _args: &[String], _input: Option<&str>) -> Result<String, CommandError> {
            let at = self.0.iter().position(|(wanted, _)| *wanted == program).expect("每个程序都给了回答");
            self.0.remove(at).1
        }
    }

    fn refused(detail: &str) -> Result<String, CommandError> {
        Err(CommandError::Failed { program: Program::Iptables, status: Some(4), detail: detail.into() })
    }

    #[test]
    fn a_survey_reads_each_item_on_its_own_and_unreadable_items_are_not_taken_for_none() {
        // iptables 先读 INPUT，再读 raw 的 PREROUTING。
        let mut machine = Answers(vec![
            (Program::Nft, Ok(TABLES.to_owned())),
            (Program::Iptables, refused("Permission denied")),
            (Program::Iptables, Ok(RAW.to_owned())),
        ]);
        let survey = Survey::take(&mut machine, Platform::Linux, "i3t0");
        assert_eq!(survey.tables.as_deref(), Ok(&["i3t0".to_owned()][..]));
        assert!(survey.accept.is_err());
        assert_eq!(survey.guard_rules.as_ref().map(Vec::len), Ok(3));
        assert!(survey.found_any() && !survey.is_clean());

        let no_raw_table = "iptables v1.8.9 (legacy): can't initialize iptables table `raw': Table does not exist (do you need to insmod?)";
        let mut machine = Answers(vec![
            (Program::Nft, Ok(r#"{"nftables": []}"#.into())),
            (Program::Iptables, Ok(INPUT.to_owned())),
            (Program::Iptables, refused(no_raw_table)),
        ]);
        let survey = Survey::take(&mut machine, Platform::Linux, "i3t0");
        assert!(survey.guard_rules.is_err(), "raw 表读不了是这一项的错误");
        assert_eq!(survey.accept.map(|rules| rules.len()), Ok(2), "不妨碍别的项");

        let mut machine = Answers(vec![
            (Program::Nft, Ok(r#"{"nftables": []}"#.into())),
            (Program::Iptables, Ok("-P INPUT ACCEPT\n".into())),
            (Program::Iptables, refused("Permission denied (you must be root)")),
        ]);
        assert!(!Survey::take(&mut machine, Platform::Linux, "i3t0").is_clean(), "读不了的项不算没有");

        let mut windows = Answers(vec![(Program::PowerShell, Ok("0\r\n".into()))]);
        assert!(Survey::take(&mut windows, Platform::Windows, "i3t0").is_clean(), "数出来是 0：没有这条规则");
        let mut windows = Answers(vec![(Program::PowerShell, Ok("1\r\n".into()))]);
        assert_eq!(Survey::take(&mut windows, Platform::Windows, "i3t0").accept.unwrap().len(), 1);
        let mut windows = Answers(vec![(Program::PowerShell, Ok("WARNING: something\r\n".into()))]);
        assert!(Survey::take(&mut windows, Platform::Windows, "i3t0").accept.is_err(), "看不懂的输出不当作没有");
        assert!(Survey::take(&mut Answers::default(), Platform::MacOs, "utun7").is_clean(), "macOS 上什么都不加，也什么都不读");
    }

    #[test]
    fn a_missing_program_or_table_means_none_of_its_kind_is_there() {
        let missing = |program| Err(CommandError::Missing(program));
        let tables = || Ok(r#"{"nftables": []}"#.to_owned());
        let input = || Ok("-P INPUT ACCEPT\n".to_owned());
        let raw = || Ok("-P PREROUTING ACCEPT\n".to_owned());
        let no_raw_table = || refused("can't initialize iptables table `raw': Table does not exist (do you need to insmod?)");
        let iptables = Program::Iptables;
        let machines = [
            vec![(Program::Nft, missing(Program::Nft)), (iptables, input()), (iptables, raw())],
            vec![(Program::Nft, tables()), (iptables, missing(iptables)), (iptables, missing(iptables))],
            vec![(Program::Nft, missing(Program::Nft)), (iptables, missing(iptables)), (iptables, missing(iptables))],
            vec![(Program::Nft, tables()), (iptables, input()), (iptables, no_raw_table())],
        ];
        for answers in machines {
            let survey = Survey::take(&mut Answers(answers), Platform::Linux, "i3t0");
            assert!(survey.is_clean() && !survey.found_any(), "{survey:?}");
        }
        let mut machine = Answers(vec![(Program::Nft, missing(Program::Nft)), (iptables, input()), (iptables, Ok(RAW.into()))]);
        let survey = Survey::take(&mut machine, Platform::Linux, "i3t0");
        assert!(survey.found_any() && !survey.is_clean(), "没有 nft 时 raw 表里的规则照样算");
    }
}
