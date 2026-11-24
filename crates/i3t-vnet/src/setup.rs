//! 防火墙规则的安装、卸载与异常遗留项清理；并在 Linux 上将虚拟网络域名配置至 systemd-resolved。
//!
//! 设计原则：
//!
//! - 规则独立安装：单条规则失败（如内核不支持或权限不足）不影响另一条规则及虚拟网卡本身，并在状态中明确记录原因（[`RuleState::Failed`]）。
//! - 零额外依赖：Linux 防伪造规则优先使用 `nft`（nftables 表），不可用时自动回退至 `iptables` `raw` 表，仅当二者均不可用时失败；
//!   入站放行规则在无 `iptables` 时标记为无需安装（[`RuleState::NotNeeded`]），不视为失败。
//! - 幂等无重复：Linux nftables 表通过单次事务整表替换；`INPUT` 链放行规则始终唯一且位于第 1 条，`raw` 表防伪造规则始终为第 1、2 条，
//!   若存在残留、网段变化、顺序偏移或旧版单条规则则全部清除后重建；成功安装 nftables 表后会自动清理此前遗留的 `raw` 表规则。
//!   Windows 规则在同一脚本内按名称先删后建。
//! - 严格限定自有范围（见 [`crate::plan`]）：清理时各项独立执行，单项失败不阻断其余项；对应程序或内核表不存在时视为无残留，
//!   不作为失败返回（[`CommandError::means_absent`]）。
//! - 孤立遗留清理：异常崩溃遗留且对应虚拟网卡已不存在（无运行中节点使用）的规则，会在下次启动时自动清除（[`remove_leftovers`]）。

use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use i3t_model::control::{Firewall, NameService, RuleState, VnetCause};
use ipnet::Ipv4Net;

use crate::device::Platform;
use crate::machine::{CommandError, Machine, Program};
use crate::plan::{Plan, linux, windows};
use crate::survey::{AcceptRule, GuardRule, Survey};

/// 将外部命令错误转换为上报状态用的结构化原因。
#[must_use]
pub fn cause(error: CommandError) -> VnetCause {
    match error {
        CommandError::Missing(program) => VnetCause::ProgramMissing { program: program.name().to_owned() },
        CommandError::Failed { program, detail, .. } | CommandError::Io { program, detail } => {
            VnetCause::CommandFailed { program: program.name().to_owned(), detail }
        }
    }
}

fn state(result: Result<(), CommandError>) -> RuleState {
    match result {
        Ok(()) => RuleState::On,
        Err(error) => RuleState::Failed { cause: cause(error) },
    }
}

/// 按 `plan` 在目标平台 `platform` 上安装防火墙规则（仅在防火墙开关启用时调用）。
pub fn install_firewall(machine: &mut impl Machine, platform: Platform, plan: &Plan) -> Firewall {
    match platform {
        Platform::Linux => {
            let survey = Survey::take(machine, platform, &plan.device);
            let guard = match machine.run(Program::Nft, &args(&["-f", "-"]), Some(&linux::guard_script(&plan.device, plan.own, plan.cidr)))
            {
                Ok(_) => {
                    // nftables 表已生效：清理此前无 nft 时添加的 raw 表防伪造规则。若无法读取 raw 表（如缺少 iptables、
                    // 内核无 raw 表模块或权限不足）则跳过；即便清理失败也不影响已生效的 nftables 表。
                    if let Ok(found) = &survey.guard_rules {
                        for rule in found.iter().filter(|rule| rule.device == plan.device) {
                            let _stale = delete_guard_rule(machine, rule);
                        }
                    }
                    Ok(())
                }
                Err(CommandError::Missing(Program::Nft)) => install_raw_guard(machine, plan, survey.guard_rules),
                Err(error) => Err(error),
            };
            let accept = match survey.accept {
                Err(CommandError::Missing(Program::Iptables)) => RuleState::NotNeeded,
                found => state(found.and_then(|rules| install_accept(machine, &plan.device, &rules))),
            };
            Firewall { accept, guard: state(guard) }
        }
        Platform::Windows => {
            let script = windows::install_script(&plan.device, plan.own, plan.cidr);
            let accept = machine.run(Program::PowerShell, &windows::invocation(&script), None).map(drop);
            Firewall { accept: state(accept), guard: RuleState::Unsupported }
        }
        Platform::MacOs | Platform::Other => Firewall { accept: RuleState::Unsupported, guard: RuleState::Unsupported },
    }
}

/// 卸载指定虚拟网卡 `device` 关联的防火墙规则（包括放行规则、nftables 防伪造表及可能遗留的 `raw` 表规则），返回首个错误（通常为权限不足）。
///
/// # Errors
///
/// 若任一规则查询或删除失败则返回首个错误，其余规则仍会继续清理。对应程序或表不存在时视为无残留，不返回错误。
pub fn remove_firewall(machine: &mut impl Machine, platform: Platform, device: &str) -> Result<(), CommandError> {
    match platform {
        Platform::Linux => {
            let survey = Survey::take(machine, platform, device);
            let tables = remove_each(survey.tables, |table| table == device, |table| remove_table(machine, table));
            let accept = remove_each(survey.accept, |rule| rule.device == device, |_| delete_accept(machine, device));
            let guards = remove_each(survey.guard_rules, |rule| rule.device == device, |rule| delete_guard_rule(machine, rule));
            tables.and(accept).and(guards).map(drop)
        }
        Platform::Windows => delete_windows_rule(machine, device),
        Platform::MacOs | Platform::Other => Ok(()),
    }
}

/// 清理异常崩溃遗留的孤立防火墙规则：Linux 清理对应虚拟网卡已不在 `present` 列表中的规则（仍在运行的网卡规则保持不变）；
/// Windows 网卡名固定，当 `present` 不包含该网卡时清理其同名规则。返回实际清理的条目数。
///
/// # Errors
///
/// 查询或删除失败时返回错误（Linux 上其余项仍会继续清理）。对应程序或表不存在时视为无残留，不返回错误。
pub fn remove_leftovers(machine: &mut impl Machine, platform: Platform, present: &[String]) -> Result<usize, CommandError> {
    match platform {
        Platform::Linux => {
            let survey = Survey::take(machine, platform, "");
            let orphan = |device: &str| !present.iter().any(|name| name == device);
            let tables = remove_each(survey.tables, |table| orphan(table), |table| remove_table(machine, table));
            let accept = remove_each(survey.accept, |rule| orphan(&rule.device), |rule| delete_accept(machine, &rule.device));
            let guards = remove_each(survey.guard_rules, |rule| orphan(&rule.device), |rule| delete_guard_rule(machine, rule));
            Ok(tables? + accept? + guards?)
        }
        Platform::Windows => {
            let device = crate::device::WINDOWS_NAME;
            if present.iter().any(|name| name == device) {
                return Ok(0);
            }
            let found = Survey::take(machine, platform, device).accept?.len();
            if found > 0 {
                delete_windows_rule(machine, device)?;
            }
            Ok(found)
        }
        Platform::MacOs | Platform::Other => Ok(0),
    }
}

/// 确保 Linux `INPUT` 链仅存在一条自有放行规则且位于第 1 位；若存在重复或位置偏移则先全部删除再插入首条。
fn install_accept(machine: &mut impl Machine, device: &str, found: &[AcceptRule]) -> Result<(), CommandError> {
    let ours: Vec<usize> = found.iter().filter(|rule| rule.device == device).map(|rule| rule.position).collect();
    if ours == [1] {
        return Ok(());
    }
    for _ in &ours {
        delete_accept(machine, device)?;
    }
    machine.run(Program::Iptables, &linux::insert_accept(device), None).map(drop)
}

/// 无 `nft` 时的防伪造规则安装：确保 `raw` 表 `PREROUTING` 链第 1、2 条严格匹配当前网卡、网段与虚拟 IP
/// （源地址规则在前，目的地址规则在后）；否则先清理该网卡的所有旧规则再重新插入。
/// `found` 为预先探测的当前链规则。
///
/// 当 `nft` 与 `iptables` 均缺失时报告缺少 `nft`（首选方案为 nftables）。
fn install_raw_guard(machine: &mut impl Machine, plan: &Plan, found: Result<Vec<GuardRule>, CommandError>) -> Result<(), CommandError> {
    let found = found.map_err(|error| match error {
        CommandError::Missing(_) => CommandError::Missing(Program::Nft),
        other => other,
    })?;
    let ours: Vec<&GuardRule> = found.iter().filter(|rule| rule.device == plan.device).collect();
    let (range, own) = (Some(plan.cidr.trunc()), Some(Ipv4Net::from(plan.own)));
    if let [spoofed, to_us] = ours.as_slice()
        && (spoofed.position, spoofed.range, spoofed.destination) == (1, range, None)
        && (to_us.position, to_us.range, to_us.destination) == (2, None, own)
    {
        return Ok(());
    }
    for rule in ours {
        delete_guard_rule(machine, rule)?;
    }
    for insert in linux::insert_guards(&plan.device, plan.own, plan.cidr) {
        machine.run(Program::Iptables, &insert, None)?;
    }
    Ok(())
}

/// 对探测结果中满足 `pick` 条件的每一项调用 `remove` 清理，返回清理数量。若目标程序或表不存在则视为 0 项。
fn remove_each<T>(
    found: Result<Vec<T>, CommandError>,
    pick: impl Fn(&T) -> bool,
    mut remove: impl FnMut(&T) -> Result<(), CommandError>,
) -> Result<usize, CommandError> {
    let found = match found {
        Err(error) if error.means_absent() => Vec::new(),
        found => found?,
    };
    found.iter().filter(|thing| pick(thing)).try_fold(0, |removed, thing| remove(thing).map(|()| removed + 1))
}

/// 删除指定的 Linux nftables 表。
fn remove_table(machine: &mut impl Machine, name: &str) -> Result<(), CommandError> {
    machine.run(Program::Nft, &args(&["-f", "-"]), Some(&linux::remove_table_script(name))).map(drop)
}

/// 删除 Linux `INPUT` 链中的自有放行规则；规则已不存在时不视为错误。
fn delete_accept(machine: &mut impl Machine, device: &str) -> Result<(), CommandError> {
    delete_iptables_rule(machine, &linux::delete_accept(device))
}

/// 按探测到的原样规则删除 Linux `raw` 表防伪造规则；规则已不存在时不视为错误。
fn delete_guard_rule(machine: &mut impl Machine, rule: &GuardRule) -> Result<(), CommandError> {
    delete_iptables_rule(machine, &linux::delete_guard(&rule.rule))
}

/// 删除单条 iptables 规则；若规则已被提前移除则忽略对应错误。
fn delete_iptables_rule(machine: &mut impl Machine, args: &[String]) -> Result<(), CommandError> {
    match machine.run(Program::Iptables, args, None) {
        Err(error) if !error.says("does a matching rule exist") && !error.says("bad rule") => Err(error),
        Ok(_) | Err(_) => Ok(()),
    }
}

/// 删除 Windows 上对应网卡的防火墙规则；规则不存在时不视为错误（由脚本保证）。
fn delete_windows_rule(machine: &mut impl Machine, device: &str) -> Result<(), CommandError> {
    machine.run(Program::PowerShell, &windows::invocation(&windows::remove_script(device)), None).map(drop)
}

/// systemd-resolved 感知新建虚拟网卡需要短暂延迟，期间会返回 "not known"；此处为最大重试次数与间隔。
const LINK_KNOWN_TRIES: u32 = 20;
const LINK_KNOWN_PAUSE: Duration = Duration::from_millis(100);

/// Linux：配置 systemd-resolved 将 `domain` 下的 DNS 查询经虚拟网卡 `device` 路由至本节点名称服务 `server`：
/// 明确关闭该网卡的默认 DNS 路由，其他域名继续沿用系统原有解析器。
///
/// 该配置仅存于内存，不修改磁盘文件，虚拟网卡销毁后自动清除。系统无可用 systemd-resolved 时返回 [`NameService::NoResolver`]，
/// 用户可改用 `i3t hosts`。
pub fn configure_resolver(machine: &mut impl Machine, device: &str, domain: &str, server: Ipv4Addr) -> NameService {
    // 按序配置路由域、禁用默认路由，最后再指定 DNS 服务器：确保生效瞬间该接口仅承接目标域名的查询。
    let steps = [
        args(&["domain", device, &format!("~{domain}")]),
        args(&["default-route", device, "false"]),
        args(&["dns", device, &server.to_string()]),
    ];
    for step in &steps {
        let mut tries = 0;
        loop {
            match machine.run(Program::Resolvectl, step, None) {
                Ok(_) => break,
                Err(error) if error.says("not known") && tries < LINK_KNOWN_TRIES => {
                    tries += 1;
                    thread::sleep(LINK_KNOWN_PAUSE);
                }
                Err(error) if resolver_absent(&error) => return NameService::NoResolver,
                Err(error) => {
                    // 回滚已完成的部分配置：较旧版本 systemd-resolved 不支持 default-route，可能将该网卡误设为默认 DNS 路由。
                    let _undone = machine.run(Program::Resolvectl, &args(&["revert", device]), None);
                    return NameService::Failed { cause: cause(error) };
                }
            }
        }
    }
    NameService::Resolved
}

/// 判断错误是否表明系统未运行或未安装 systemd-resolved（而非权限拒绝等配置失败）。
fn resolver_absent(error: &CommandError) -> bool {
    matches!(error, CommandError::Missing(_))
        || ["connect to bus", "not found", "could not activate", "no such file", "not running", "connection refused"]
            .iter()
            .any(|needle| error.says(needle))
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

#[cfg(test)]
pub(crate) mod fake {
    //! 一台假的机器：按收到的命令改自己的防火墙，读的时候按真的程序的样子回答。
    use std::collections::BTreeSet;

    use super::*;

    #[derive(Debug, Default)]
    pub(crate) struct Fake {
        /// `ip` 族里的表名。
        pub(crate) tables: BTreeSet<String>,
        /// INPUT 链，按先后：每条是 `iptables -S` 去掉 `-A INPUT ` 的样子。
        pub(crate) input: Vec<String>,
        /// `raw` 表的 PREROUTING 链，按先后：每条是 `iptables -S` 去掉 `-A PREROUTING ` 的样子。
        pub(crate) raw: Vec<String>,
        /// Windows 防火墙里的规则名。
        pub(crate) windows: Vec<String>,
        pub(crate) resolver: Vec<String>,
        /// 没有这个程序。
        pub(crate) missing: Vec<Program>,
        /// 没有权限：写的命令一律失败。
        pub(crate) unprivileged: bool,
        /// 内核里没有 `raw` 表（老的 xtables 后端、没有这个模块）：碰它的命令一律失败。
        pub(crate) no_raw_table: bool,
        pub(crate) no_resolver: bool,
        pub(crate) log: Vec<String>,
    }

    fn failed(program: Program, status: i32, detail: &str) -> CommandError {
        CommandError::Failed { program, status: Some(status), detail: detail.to_owned() }
    }

    /// `iptables -S` 写出来的样子：`-s`、`-d` 排在 `! -i` 前面，不管插的时候怎么写。删的时候也按这个样子比，和真的一样不看次序。
    fn as_listed(rule: &str) -> String {
        let words: Vec<&str> = rule.split(' ').collect();
        match words.as_slice() {
            ["!", "-i", device, flag @ ("-s" | "-d"), range, rest @ ..] => {
                [&[*flag, *range, "!", "-i", *device][..], rest].concat().join(" ")
            }
            _ => rule.to_owned(),
        }
    }

    impl Fake {
        /// iptables 的两条链：INPUT，和 `raw` 表的 PREROUTING。读、插在第一条、按写全了的规则删。
        fn iptables(&mut self, line: &str) -> Result<String, CommandError> {
            let (name, chain, command) = match line.strip_prefix("-w 5 -t raw ") {
                Some(_) if self.no_raw_table => {
                    let detail =
                        "iptables v1.8.9 (legacy): can't initialize iptables table `raw': Table does not exist (do you need to insmod?)";
                    return Err(failed(Program::Iptables, 3, detail));
                }
                Some(command) => ("PREROUTING", &mut self.raw, command),
                None => ("INPUT", &mut self.input, line.strip_prefix("-w 5 ").expect("总是等 xtables 的锁")),
            };
            if command == format!("-S {name}") {
                let listed = chain.iter().map(|rule| format!("-A {name} {rule}"));
                return Ok(std::iter::once(format!("-P {name} ACCEPT")).chain(listed).collect::<Vec<_>>().join("\n"));
            }
            if let Some((position, rule)) = command.strip_prefix(&format!("-I {name} ")).and_then(|rest| rest.split_once(' ')) {
                let position: usize = position.parse().expect("插在第几条");
                assert!(position <= chain.len() + 1, "iptables 不让插在链的末尾之后：{line}");
                chain.insert(position - 1, as_listed(rule));
                return Ok(String::new());
            }
            let rule = as_listed(command.strip_prefix(&format!("-D {name} ")).expect("只会读、插和删"));
            match chain.iter().position(|existing| *existing == rule) {
                Some(at) => {
                    chain.remove(at);
                    Ok(String::new())
                }
                None => Err(failed(Program::Iptables, 1, "iptables: Bad rule (does a matching rule exist in that chain?).")),
            }
        }
    }

    impl Machine for Fake {
        fn run(&mut self, program: Program, args: &[String], input: Option<&str>) -> Result<String, CommandError> {
            let line = args.join(" ");
            self.log.push(format!("{program} {line}"));
            if self.missing.contains(&program) {
                return Err(CommandError::Missing(program));
            }
            let reads = line.starts_with("-j list") || line.contains(" -S ") || line.contains("$rules.Count");
            if self.unprivileged && !reads {
                return Err(failed(program, 1, "Operation not permitted"));
            }
            match program {
                Program::Nft if line == "-j list tables ip" => {
                    let tables: Vec<String> =
                        self.tables.iter().map(|name| format!(r#"{{"table": {{"family": "ip", "name": "{name}"}}}}"#)).collect();
                    Ok(format!(r#"{{"nftables": [{}]}}"#, tables.join(", ")))
                }
                Program::Nft if line == "-f -" => {
                    let script = input.unwrap_or_default();
                    let name = script.lines().next().and_then(|first| first.strip_prefix("table ip ")).expect("脚本先保证有表");
                    assert!(script.contains(&format!("delete table ip {name}\n")), "整张表在一个事务里换：{script}");
                    if script.lines().count() > 2 {
                        self.tables.insert(name.to_owned());
                    } else {
                        self.tables.remove(name);
                    }
                    Ok(String::new())
                }
                Program::Iptables => self.iptables(&line),
                Program::PowerShell => {
                    let name = line.split("-Name '").nth(1).and_then(|rest| rest.split('\'').next()).unwrap_or_default().to_owned();
                    if line.contains("$rules.Count") {
                        return Ok(format!("{}\r\n", self.windows.iter().filter(|existing| **existing == name).count()));
                    }
                    assert!(line.contains("Remove-NetFirewallRule"), "装之前先删同名的：{line}");
                    self.windows.retain(|existing| *existing != name);
                    if line.contains("New-NetFirewallRule") {
                        self.windows.push(name);
                    }
                    Ok(String::new())
                }
                Program::Resolvectl if self.no_resolver => {
                    Err(failed(program, 1, "Failed to set DNS configuration: Unit dbus-org.freedesktop.resolve1.service not found."))
                }
                Program::Resolvectl => {
                    self.resolver.push(line);
                    Ok(String::new())
                }
                other => panic!("假机器不认识这条命令：{other} {line}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::Fake;
    use super::*;

    fn plan(device: &str) -> Plan {
        Plan { device: device.into(), own: Ipv4Addr::new(10, 66, 0, 1), cidr: "10.66.0.0/16".parse().unwrap() }
    }

    const OURS: &str = "-i i3t0 -m comment --comment ice3tier -j ACCEPT";
    /// 没有 nft 时防冒充的那条，`iptables -S` 写出来的样子。
    const GUARD: &str = "-s 10.66.0.0/16 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP";
    /// 防冒充的第二条：目的是本机的地址。
    const TO_US: &str = "-d 10.66.0.1/32 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP";
    const GUARD_I3T1: &str = "-s 10.66.0.0/16 ! -i i3t1 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP";
    const TO_US_I3T1: &str = "-d 10.66.0.1/32 ! -i i3t1 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP";
    /// Docker 在 raw 表里加的那种规则：别人的，不动。
    const DOCKER: &str = "-d 172.17.0.2/32 ! -i docker0 -j DROP";

    #[test]
    fn on_linux_both_rules_go_in_and_come_out_and_nothing_else_is_touched() {
        let mut fake = Fake { input: vec!["-j ufw-before-input".into()], tables: ["filter".to_owned()].into(), ..Fake::default() };
        let firewall = install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(firewall, Firewall { accept: RuleState::On, guard: RuleState::On });
        assert_eq!(fake.input, [OURS, "-j ufw-before-input"], "放行的那条插在最前面");
        assert!(fake.tables.contains("i3t0"));
        remove_firewall(&mut fake, Platform::Linux, "i3t0").unwrap();
        assert_eq!(fake.input, ["-j ufw-before-input"]);
        assert_eq!(fake.tables.iter().collect::<Vec<_>>(), ["filter"], "别人的表不动");
    }

    #[test]
    fn a_leftover_after_a_crash_is_replaced_not_duplicated() {
        let mut fake = Fake::default();
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        // 进程被杀掉，什么都没拆；别的程序之后在最前面插了一条。重启之后再装。
        fake.input.insert(0, "-s 192.0.2.9/32 -j DROP".into());
        let firewall = install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(firewall.accept, RuleState::On);
        assert_eq!(fake.input, [OURS, "-s 192.0.2.9/32 -j DROP"], "还是一条，又回到最前面");
        assert_eq!(fake.tables.len(), 1);
        // 已经在最前面的不动。
        fake.log.clear();
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert!(
            !fake.log.iter().any(|line| line.starts_with("iptables -w 5 -I") || line.starts_with("iptables -w 5 -D")),
            "{:?}",
            fake.log
        );
        // 两份（更早的版本被杀掉两次）也收成一份。
        fake.input.push(OURS.into());
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(fake.input.iter().filter(|rule| *rule == OURS).count(), 1);
    }

    #[test]
    fn leftovers_whose_device_is_gone_are_removed_and_a_running_nodes_are_not() {
        let mut fake = Fake::default();
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        install_firewall(&mut fake, Platform::Linux, &plan("i3t1"));
        // 还没有 nft 时 i3t0 加的那条 raw 规则也留着。
        fake.raw.push(GUARD.into());
        assert_eq!(remove_leftovers(&mut fake, Platform::Linux, &["i3t1".into()]).unwrap(), 3, "i3t0 的表、放行和 raw 规则");
        assert_eq!(fake.input, ["-i i3t1 -m comment --comment ice3tier -j ACCEPT"]);
        assert_eq!(fake.tables.iter().collect::<Vec<_>>(), ["i3t1"]);
        assert!(fake.raw.is_empty());
        assert_eq!(remove_leftovers(&mut fake, Platform::Linux, &["i3t1".into()]).unwrap(), 0);

        // 没有 nft 的机器：防冒充是 raw 规则，在的网卡的不动。
        let mut fake = Fake { missing: vec![Program::Nft], raw: vec![DOCKER.into()], ..Fake::default() };
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        install_firewall(&mut fake, Platform::Linux, &plan("i3t1"));
        assert_eq!(remove_leftovers(&mut fake, Platform::Linux, &["i3t1".into()]).unwrap(), 3, "i3t0 的放行和两条 raw 规则");
        assert_eq!(fake.raw, [GUARD_I3T1, TO_US_I3T1, DOCKER]);
        assert_eq!(fake.input, ["-i i3t1 -m comment --comment ice3tier -j ACCEPT"]);
        assert_eq!(remove_leftovers(&mut fake, Platform::Linux, &[]).unwrap(), 3);
        assert_eq!(fake.raw, [DOCKER], "别人的规则不动");
    }

    #[test]
    fn without_iptables_the_accept_rule_is_not_needed_and_the_guard_goes_in_with_nft() {
        let mut fake = Fake { missing: vec![Program::Iptables], ..Fake::default() };
        let firewall = install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(firewall, Firewall { accept: RuleState::NotNeeded, guard: RuleState::On });
        assert!(fake.tables.contains("i3t0"));
        let tried: Vec<&String> = fake.log.iter().filter(|line| line.starts_with("iptables ")).collect();
        assert!(!tried.is_empty() && tried.iter().all(|line| line.contains(" -S ")), "iptables 只读过一下，发现没有：{tried:?}");

        // 别的失败（没有权限）还是失败。
        let mut fake = Fake { unprivileged: true, ..Fake::default() };
        let firewall = install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert!(matches!(firewall.guard, RuleState::Failed { cause: VnetCause::CommandFailed { .. } }));
        assert!(matches!(firewall.accept, RuleState::Failed { cause: VnetCause::CommandFailed { .. } }));
        let mut fake = Fake { unprivileged: true, missing: vec![Program::Nft], ..Fake::default() };
        let firewall = install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert!(
            matches!(firewall.guard, RuleState::Failed { cause: VnetCause::CommandFailed { ref program, .. } } if program == "iptables")
        );
        assert!(
            remove_firewall(&mut Fake { unprivileged: true, input: vec![OURS.into()], ..Fake::default() }, Platform::Linux, "i3t0")
                .is_err()
        );
        assert!(
            remove_firewall(&mut Fake { unprivileged: true, raw: vec![GUARD.into()], ..Fake::default() }, Platform::Linux, "i3t0").is_err()
        );
    }

    #[test]
    fn without_nft_the_guard_is_two_rules_first_in_raw_prerouting() {
        let mut fake = Fake { missing: vec![Program::Nft], raw: vec![DOCKER.into()], ..Fake::default() };
        let firewall = install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(firewall, Firewall { accept: RuleState::On, guard: RuleState::On });
        assert_eq!(fake.raw, [GUARD, TO_US, DOCKER], "插在最前面，按来源的在前");
        for insert in linux::insert_guards("i3t0", plan("i3t0").own, plan("i3t0").cidr) {
            let inserted = format!("iptables {}", insert.join(" "));
            assert!(fake.log.contains(&inserted), "{:?}", fake.log);
        }

        // 再装一遍：已经在最前面、地址段对的不动。
        fake.log.clear();
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(fake.raw, [GUARD, TO_US, DOCKER]);
        assert!(!fake.log.iter().any(|line| line.contains(" -I ") || line.contains(" -D ")), "{:?}", fake.log);

        // 被别人挤到了后面：回到最前面，还是两条。
        fake.raw.insert(0, "-s 192.0.2.9/32 -j DROP".into());
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(fake.raw, [GUARD, TO_US, "-s 192.0.2.9/32 -j DROP", DOCKER]);
        fake.raw.insert(1, "-s 192.0.2.9/32 -j DROP".into());
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(fake.raw, [GUARD, TO_US, "-s 192.0.2.9/32 -j DROP", "-s 192.0.2.9/32 -j DROP", DOCKER], "两条中间插进了别的");
        fake.raw.drain(2..3);
        fake.raw.swap(0, 1);
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(fake.raw, [GUARD, TO_US, "-s 192.0.2.9/32 -j DROP", DOCKER], "次序反了");

        // 两份（更早的版本被杀掉两次）收成一份。
        fake.raw.push(GUARD.into());
        fake.raw.push(TO_US.into());
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(fake.raw, [GUARD, TO_US, "-s 192.0.2.9/32 -j DROP", DOCKER]);

        // 拆：只拆自己的。
        remove_firewall(&mut fake, Platform::Linux, "i3t0").unwrap();
        assert_eq!(fake.raw, ["-s 192.0.2.9/32 -j DROP", DOCKER]);
        assert!(fake.input.is_empty());
    }

    #[test]
    fn without_nft_a_changed_virtual_ip_replaces_the_rule_for_it() {
        let mut fake = Fake { missing: vec![Program::Nft], ..Fake::default() };
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        let renumbered = Plan { own: Ipv4Addr::new(10, 66, 0, 9), ..plan("i3t0") };
        assert_eq!(install_firewall(&mut fake, Platform::Linux, &renumbered).guard, RuleState::On);
        assert_eq!(fake.raw, [GUARD, "-d 10.66.0.9/32 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP"]);
    }

    #[test]
    fn without_nft_the_single_rule_of_an_earlier_version_gets_its_second_rule() {
        let mut fake = Fake { missing: vec![Program::Nft], raw: vec![GUARD.into(), DOCKER.into()], ..Fake::default() };
        assert_eq!(install_firewall(&mut fake, Platform::Linux, &plan("i3t0")).guard, RuleState::On);
        assert_eq!(fake.raw, [GUARD, TO_US, DOCKER]);
    }

    #[test]
    fn without_nft_a_changed_range_replaces_the_raw_rule_and_other_adapters_keep_theirs() {
        let mut fake = Fake { missing: vec![Program::Nft], ..Fake::default() };
        install_firewall(&mut fake, Platform::Linux, &plan("i3t1"));
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        let moved = Plan { own: Ipv4Addr::new(10, 77, 0, 1), cidr: "10.77.0.0/16".parse().unwrap(), ..plan("i3t0") };
        let firewall = install_firewall(&mut fake, Platform::Linux, &moved);
        assert_eq!(firewall.guard, RuleState::On);
        assert_eq!(
            fake.raw,
            [
                "-s 10.77.0.0/16 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP",
                "-d 10.77.0.1/32 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP",
                GUARD_I3T1,
                TO_US_I3T1
            ],
            "旧地址段的两条换掉了，i3t1 的不动"
        );
    }

    #[test]
    fn once_nft_is_there_the_table_takes_over_from_the_raw_rule_left_from_before() {
        let mut fake = Fake { raw: vec![GUARD.into(), TO_US.into(), GUARD_I3T1.into(), DOCKER.into()], ..Fake::default() };
        let firewall = install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(firewall, Firewall { accept: RuleState::On, guard: RuleState::On });
        assert!(fake.tables.contains("i3t0"));
        assert_eq!(fake.raw, [GUARD_I3T1, DOCKER], "只拆这块网卡的");

        // raw 表读不了、拆不掉：表照样算装上了。
        let mut fake = Fake { no_raw_table: true, ..Fake::default() };
        assert_eq!(install_firewall(&mut fake, Platform::Linux, &plan("i3t0")), Firewall { accept: RuleState::On, guard: RuleState::On });
        assert!(!fake.log.iter().any(|line| line.contains(" -t raw -D ")), "读不出来就不删：{:?}", fake.log);
    }

    #[test]
    fn with_neither_program_the_guard_fails_for_want_of_nft_and_the_accept_rule_is_not_needed() {
        let mut fake = Fake { missing: vec![Program::Nft, Program::Iptables], ..Fake::default() };
        assert_eq!(
            install_firewall(&mut fake, Platform::Linux, &plan("i3t0")),
            Firewall {
                accept: RuleState::NotNeeded,
                guard: RuleState::Failed { cause: VnetCause::ProgramMissing { program: "nft".into() } }
            }
        );
        remove_firewall(&mut fake, Platform::Linux, "i3t0").unwrap();
        assert_eq!(remove_leftovers(&mut fake, Platform::Linux, &[]).unwrap(), 0);
    }

    #[test]
    fn removing_where_a_program_or_the_raw_table_is_missing_succeeds_and_removes_what_is_there() {
        let mut fake = Fake { missing: vec![Program::Nft], ..Fake::default() };
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        remove_firewall(&mut fake, Platform::Linux, "i3t0").unwrap();
        assert!(fake.raw.is_empty() && fake.input.is_empty());

        let mut fake = Fake { missing: vec![Program::Iptables], ..Fake::default() };
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        remove_firewall(&mut fake, Platform::Linux, "i3t0").unwrap();
        assert!(fake.tables.is_empty());

        let mut fake = Fake { no_raw_table: true, ..Fake::default() };
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        remove_firewall(&mut fake, Platform::Linux, "i3t0").unwrap();
        assert!(fake.tables.is_empty() && fake.input.is_empty());
        install_firewall(&mut fake, Platform::Linux, &plan("i3t0"));
        assert_eq!(remove_leftovers(&mut fake, Platform::Linux, &[]).unwrap(), 2, "表和放行的那条");
    }

    #[test]
    fn on_windows_one_named_rule_on_our_adapter_admits_the_range_and_the_guard_is_left_to_the_strong_host_model() {
        let mut fake = Fake { windows: vec!["ice3tier-i3t0".into()], ..Fake::default() };
        let firewall = install_firewall(&mut fake, Platform::Windows, &plan("i3t0"));
        assert_eq!(firewall, Firewall { accept: RuleState::On, guard: RuleState::Unsupported });
        assert_eq!(fake.windows, ["ice3tier-i3t0"], "留下的那条先删掉，不会多一条");
        assert!(
            fake.log.iter().any(|line| line.contains("-InterfaceAlias 'i3t0' -LocalAddress 10.66.0.1 -RemoteAddress 10.66.0.0/16")),
            "{:?}",
            fake.log
        );
        assert_eq!(remove_leftovers(&mut fake, Platform::Windows, &["i3t0".into()]).unwrap(), 0, "网卡在：不是留下的");
        assert_eq!(remove_leftovers(&mut fake, Platform::Windows, &[]).unwrap(), 1);
        assert!(fake.windows.is_empty());
        remove_firewall(&mut fake, Platform::Windows, "i3t0").unwrap();
        let mut fake = Fake { unprivileged: true, ..Fake::default() };
        let firewall = install_firewall(&mut fake, Platform::Windows, &plan("i3t0"));
        assert!(matches!(firewall.accept, RuleState::Failed { cause: VnetCause::CommandFailed { .. } }), "{firewall:?}");
    }

    #[test]
    fn on_macos_nothing_is_added() {
        let mut fake = Fake::default();
        assert_eq!(
            install_firewall(&mut fake, Platform::MacOs, &plan("utun7")),
            Firewall { accept: RuleState::Unsupported, guard: RuleState::Unsupported }
        );
        assert!(fake.log.is_empty());
    }

    #[test]
    fn the_resolver_gets_a_routing_domain_on_our_link_and_is_never_the_default_route() {
        let mut fake = Fake::default();
        assert_eq!(configure_resolver(&mut fake, "i3t0", "home.i3t", [10, 66, 0, 1].into()), NameService::Resolved);
        assert_eq!(fake.resolver, ["domain i3t0 ~home.i3t", "default-route i3t0 false", "dns i3t0 10.66.0.1"], "服务器最后才给");
        let mut fake = Fake { no_resolver: true, ..Fake::default() };
        assert_eq!(configure_resolver(&mut fake, "i3t0", "home.i3t", [10, 66, 0, 1].into()), NameService::NoResolver);
        let mut fake = Fake { missing: vec![Program::Resolvectl], ..Fake::default() };
        assert_eq!(configure_resolver(&mut fake, "i3t0", "home.i3t", [10, 66, 0, 1].into()), NameService::NoResolver);
    }
}
