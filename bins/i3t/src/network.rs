//! 虚拟网卡在本机的几个命令：`i3t network status`、`i3t network cleanup`、`i3t set network|firewall off` 之后的清理、`i3t hosts`。
//!
//! 虚拟网卡的创建与移除由运行中的节点负责（`i3t_agent::vnet`）；本模块仅查询系统当前状态，并在节点未运行时清理残留防火墙规则。
//! `i3t hosts --apply` 写入 hosts 文件的条目区块不会随虚拟网卡一并移除，需由管理员显式运行 `i3t hosts --remove` 移除。

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, bail};
use i3t_agent::state::StateDir;
use i3t_agent::status::LiveStatus;
use i3t_agent::vnet::{devices, names_of, present_devices};
use i3t_lang::table::Fields;
use i3t_model::control::{VnetCause, VnetState};
use i3t_vnet::device::Platform;
use i3t_vnet::machine::{Machine, Shell, missing_privilege};
use i3t_vnet::names::{hosts_block, remove_hosts_block, replace_hosts_block};
use i3t_vnet::{CommandError, Program, Survey, legacy, setup};

use crate::HostsAction;
use crate::texts::texts;

/// 这台机器的 hosts 文件。
fn hosts_file() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        root.join(r"System32\drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

/// `i3t network cleanup`：清理节点崩溃或被强制终止后残留的防火墙规则（及旧版透明访问残留项）。
///
/// 在跑的节点程序的网卡还存在，它的规则不动。systemd 单元的 `ExecStopPost` 也会调用它。
pub(crate) fn cleanup() -> anyhow::Result<()> {
    let t = &texts().network;
    if let Some(missing) = missing_privilege() {
        bail!((t.cleanup_no_privilege)(missing));
    }
    let removed = cleanup_with(&mut Shell, Platform::CURRENT, &present_devices()).context(t.leftover_remove_failed)?;
    if removed == 0 {
        println!("{}", t.cleanup_nothing);
    } else {
        println!("{}", (t.leftover_removed)(removed));
    }
    Ok(())
}

/// 在 `machine` 上清理不属于 `present` 的孤立规则及旧版透明访问残留项，返回已清理的条目数。
fn cleanup_with(machine: &mut impl Machine, platform: Platform, present: &[String]) -> Result<usize, CommandError> {
    let mut first_error = None;
    let mut removed = match setup::remove_leftovers(machine, platform, present) {
        Ok(count) => count,
        Err(error) => {
            first_error = Some(error);
            0
        }
    };
    if platform == Platform::Linux {
        match legacy::Leftover::find(machine) {
            Ok(found) if !found.is_empty() => match found.remove(machine) {
                Ok(()) => removed += found.items().len(),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            },
            Ok(_) => {}
            // 没有 nft 或 ip 的机器上本来就没有过透明访问，不当作清理失败。
            Err(error) if error.means_absent() => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(removed),
    }
}

/// 在 `i3t set network off` 或 `i3t set firewall off` 写入配置后执行：若节点未运行，立即清理残留规则。
/// 若节点正在运行，则由其在停止时或下次启动检测到开关关闭时清理。
pub(crate) fn after_switch_off(running: bool) {
    if running || missing_privilege().is_some() {
        return;
    }
    let t = &texts().network;
    // 本节点没在运行，可这台机器上可能还跑着进别的网络的节点程序：它们的网卡在，规则不拆。
    match setup::remove_leftovers(&mut Shell, Platform::CURRENT, &present_devices()) {
        Ok(0) => {}
        Ok(count) => println!("{}", (t.leftover_removed)(count)),
        Err(_) => println!("{}", t.leftover_remove_failed),
    }
    if Platform::CURRENT == Platform::Linux
        && let Ok(found) = legacy::Leftover::find(&mut Shell)
        && !found.is_empty()
        && found.remove(&mut Shell).is_err()
    {
        println!("{}", t.leftover_remove_failed);
    }
    names_left_behind();
}

/// 检测到 `i3t hosts --apply` 写入的完整区块时，提示移除命令。读取 `hosts` 文件失败时跳过检查。
fn names_left_behind() {
    let path = hosts_file();
    if fs::read_to_string(&path).is_ok_and(|hosts| remove_hosts_block(&hosts).is_some()) {
        println!("{}", (texts().network.hosts_left)(&path.display().to_string()));
    }
}

/// `i3t network status` 显示运行中节点报告的虚拟网卡状态，以及在本机检测到的相关资源。
pub(crate) fn status(state: &StateDir, live: Option<&LiveStatus>) {
    let t = &texts().network;
    let lang = i3t_lang::current();
    if let Some(report) = live.and_then(|live| live.vnet.as_ref()) {
        println!("{}", lang.labelled(texts().ui.vnet, &crate::show::vnet_line(report)));
    }
    let mut fields = Fields::new(2);
    let cidr = state.netmap().ok().flatten().map(|netmap| netmap.network.cidr);
    let found_devices = devices(cidr);
    for (name, address) in &found_devices {
        fields.add(t.device, format!("{name} {address}"));
    }
    let platform = Platform::CURRENT;
    let survey = Survey::take(&mut Shell, platform, i3t_vnet::device::WINDOWS_NAME);
    // 防冒充：有 nft 时是 nftables 的表，没有时是 raw 表 PREROUTING 链里的规则。
    if let Ok(tables) = &survey.tables {
        for table in tables {
            fields.add(t.guard_rule, format!("table ip {table}"));
        }
    }
    if let Ok(rules) = &survey.guard_rules {
        for rule in rules {
            let matched = match (rule.range, rule.destination) {
                (Some(range), _) => format!("! -i {} -s {range}", rule.device),
                (None, Some(own)) => format!("! -i {} -d {own}", rule.device),
                (None, None) => format!("! -i {}", rule.device),
            };
            fields.add(t.guard_rule, (t.guard_at)(rule.position, &matched));
        }
    }
    let guard_note = guard_note(&survey);
    // 列出读取失败的检查项及原因。缺少工具时，说明规则无需安装或指出需要安装的工具。
    let noted = guard_note.is_some() || survey.accept.is_err();
    if let Some(note) = guard_note {
        fields.add(t.guard_rule, note);
    }
    match &survey.accept {
        Ok(rules) => {
            for rule in rules {
                fields.add(t.accept_rule, (t.accept_at)(&rule.device, rule.position));
            }
        }
        // 未安装 iptables 时不存在 ufw 等经其注入的 INPUT 链规则需要前置放行，因此节点无需添加此规则，并非添加失败。
        Err(CommandError::Missing(Program::Iptables)) => fields.add(t.accept_rule, t.accept_not_needed),
        Err(error) => fields.add(t.accept_rule, unreadable(error)),
    }
    let legacy = (platform == Platform::Linux).then(|| legacy::Leftover::find(&mut Shell).ok()).flatten().filter(|found| !found.is_empty());
    if let Some(found) = legacy {
        fields.add(t.legacy, lang.list(found.items()));
    }
    let found = !found_devices.is_empty() || survey.found_any() || legacy.is_some();
    if found || noted {
        fields.print();
    } else {
        println!("{}", t.nothing_installed);
    }
    if live.is_none() && survey.found_any() {
        println!("{}", t.leftover);
    }
    let installed = live.and_then(|live| live.vnet.as_ref()).is_some_and(|report| matches!(report.state, VnetState::Installed { .. }));
    if !installed {
        names_left_behind();
    }
}

/// 防冒充检查项除已安装的 nftables 表与 raw 规则外的补充说明。
///
/// 存在 nft 时防冒充规则位于对应的 nftables 表中，raw 表仅可能含迁移前残留项，因此 raw 表不可读时无需提示。
/// 无 nft 时回退检查 raw 表规则：若 nft 与 iptables 均缺失则提示缺少 nft（与节点状态保持一致）；若 raw 表无对应规则或内核无 raw 表则说明均未安装。
fn guard_note(survey: &Survey) -> Option<String> {
    let t = &texts().network;
    match (&survey.tables, &survey.guard_rules) {
        (Ok(_), _) => None,
        (Err(nft @ CommandError::Missing(Program::Nft)), Err(CommandError::Missing(Program::Iptables))) => Some(unreadable(nft)),
        (Err(CommandError::Missing(Program::Nft)), Ok(rules)) => rules.is_empty().then(|| t.guard_none.to_owned()),
        (Err(CommandError::Missing(Program::Nft)), Err(error)) if error.means_absent() => Some(t.guard_none.to_owned()),
        (Err(CommandError::Missing(Program::Nft)), Err(error)) | (Err(error), _) => Some(unreadable(error)),
    }
}

/// 格式化检查项读取失败时的提示文本。若系统未安装对应工具则直接说明工具缺失，不归因于权限不足。
fn unreadable(error: &CommandError) -> String {
    match error {
        CommandError::Missing(_) => said(error),
        CommandError::Failed { .. } | CommandError::Io { .. } => (texts().network.unreadable)(&said(error)),
    }
}

fn said(error: &CommandError) -> String {
    match error {
        CommandError::Missing(program) => {
            (i3t_lang::current().codes().vnet_cause)(&VnetCause::ProgramMissing { program: program.name().to_owned() })
        }
        CommandError::Failed { detail, .. } | CommandError::Io { detail, .. } => detail.clone(),
    }
}

/// 根据最近保存的 `netmap` 生成 hosts 条目区块。应用时替换完整的旧区块或追加新区块，移除时仅处理完整区块。
pub(crate) fn hosts(state: &StateDir, action: HostsAction) -> anyhow::Result<()> {
    let t = &texts().network;
    let path = hosts_file();
    let shown = path.display().to_string();
    let command = if action == HostsAction::Remove { "i3t hosts --remove" } else { "i3t hosts --apply" };
    let failed = || (t.hosts_write_failed)(&shown, command);
    if action == HostsAction::Remove {
        let existing = fs::read_to_string(&path).with_context(failed)?;
        match remove_hosts_block(&existing) {
            Some(rest) => {
                fs::write(&path, rest).with_context(failed)?;
                println!("{}", (t.hosts_removed)(&shown));
            }
            None => println!("{}", (t.hosts_no_block)(&shown)),
        }
        return Ok(());
    }
    let netmap = state.netmap()?.context(texts().ui.not_joined)?;
    let names = names_of(&netmap);
    let block = hosts_block(&names);
    if action == HostsAction::Print {
        print!("{block}");
        return Ok(());
    }
    let existing = fs::read_to_string(&path).with_context(failed)?;
    fs::write(&path, replace_hosts_block(&existing, &block)).with_context(failed)?;
    println!("{}", (t.hosts_written)(names.len(), &shown));
    Ok(())
}

#[cfg(test)]
mod tests {
    use i3t_vnet::survey::GuardRule;

    use super::*;

    fn survey(tables: Result<Vec<String>, CommandError>, guard_rules: Result<Vec<GuardRule>, CommandError>) -> Survey {
        Survey { tables, accept: Ok(Vec::new()), guard_rules }
    }

    #[test]
    fn the_guard_line_says_neither_is_there_only_without_nft_and_without_a_raw_rule() {
        let t = &texts().network;
        let no_nft = || Err(CommandError::Missing(Program::Nft));
        let refused = |detail: &str| CommandError::Failed { program: Program::Iptables, status: Some(3), detail: detail.into() };
        let no_raw_table = || refused("iptables v1.8.9 (legacy): can't initialize iptables table `raw': Table does not exist");
        let rule = GuardRule {
            device: "i3t0".into(),
            position: 1,
            range: Some("10.66.0.0/16".parse().unwrap()),
            destination: None,
            rule: String::new(),
        };

        assert_eq!(guard_note(&survey(Ok(Vec::new()), Err(no_raw_table()))), None, "有 nft：防冒充是表，raw 表读不了不用说");
        assert_eq!(guard_note(&survey(no_nft(), Ok(Vec::new()))).as_deref(), Some(t.guard_none));
        assert_eq!(guard_note(&survey(no_nft(), Err(no_raw_table()))).as_deref(), Some(t.guard_none));
        assert_eq!(guard_note(&survey(no_nft(), Ok(vec![rule]))), None, "规则那一行已经说了");
        assert_eq!(
            guard_note(&survey(no_nft(), Err(CommandError::Missing(Program::Iptables)))),
            Some(unreadable(&CommandError::Missing(Program::Nft))),
            "两个都没有：说缺 nft"
        );
        let denied = refused("iptables v1.8.9 (legacy): can't initialize iptables table `raw': Permission denied (you must be root)");
        assert_eq!(guard_note(&survey(no_nft(), Err(denied.clone()))), Some(unreadable(&denied)));
    }

    #[test]
    fn cleanup_removes_orphaned_rules_and_keeps_running_adapters_untouched() {
        struct FakeMachine {
            answers: Vec<(Program, &'static str, Result<String, CommandError>)>,
            log: Vec<String>,
        }

        impl Machine for FakeMachine {
            fn run(&mut self, program: Program, args: &[String], _input: Option<&str>) -> Result<String, CommandError> {
                let line = format!("{program} {}", args.join(" "));
                self.log.push(line.clone());
                match self.answers.iter().position(|(p, prefix, _)| *p == program && line.starts_with(prefix)) {
                    Some(at) => self.answers.remove(at).2,
                    None => Ok(String::new()),
                }
            }
        }

        let mut machine = FakeMachine {
            answers: vec![
                // remove_leftovers 的 Survey::take
                (Program::Nft, "nft -j list tables ip", Ok(r#"{"nftables": [{"table": {"family": "ip", "name": "i3t0"}}, {"table": {"family": "ip", "name": "i3t1"}}]}"#.into())),
                (Program::Iptables, "iptables -w 5 -S INPUT", Ok("-P INPUT ACCEPT\n-A INPUT -i i3t0 -m comment --comment ice3tier -j ACCEPT\n-A INPUT -i i3t1 -m comment --comment ice3tier -j ACCEPT\n".into())),
                (Program::Iptables, "iptables -w 5 -t raw -S PREROUTING", Ok("-P PREROUTING ACCEPT\n".into())),
                // legacy::Leftover::find
                (Program::Nft, "nft -j list tables ip", Ok(r#"{"nftables": []}"#.into())),
                (Program::Ip, "ip -j rule show", Ok("[]".into())),
                (Program::Ip, "ip -j route show table 2033", Err(CommandError::Failed { program: Program::Ip, status: Some(2), detail: "Error: ipv4: FIB table does not exist.".into() })),
                (Program::Ip, "ip -j -d link show dev i3t0", Err(CommandError::Failed { program: Program::Ip, status: Some(1), detail: "Device \"i3t0\" does not exist.".into() })),
            ],
            log: Vec::new(),
        };

        let removed = cleanup_with(&mut machine, Platform::Linux, &["i3t1".into()]).unwrap();
        assert_eq!(removed, 2, "只拆掉不在的 i3t0 的表和 INPUT 规则");
        assert!(machine.log.iter().any(|cmd| cmd.contains("-D INPUT -i i3t0")), "i3t0 的放行规则应该被删：{:?}", machine.log);
        assert!(!machine.log.iter().any(|cmd| cmd.contains("i3t1")), "在跑的 i3t1 不该被动：{:?}", machine.log);
    }

    #[test]
    fn cleanup_succeeds_on_linux_without_nft_binary() {
        struct MissingNft;

        impl Machine for MissingNft {
            fn run(&mut self, program: Program, args: &[String], _input: Option<&str>) -> Result<String, CommandError> {
                match program {
                    Program::Nft => Err(CommandError::Missing(Program::Nft)),
                    Program::Iptables if args.contains(&"-S".to_owned()) => Ok("-P INPUT ACCEPT\n".into()),
                    _ => Ok(String::new()),
                }
            }
        }

        assert_eq!(cleanup_with(&mut MissingNft, Platform::Linux, &[]).unwrap(), 0, "没有 nft 时不应因为查不到旧表而报错");
    }
}
