//! `i3t tune`：检查会影响节点表现的内核参数，按要求把它们改过来。只支持 Linux。
//!
//! 不加参数时只看不改：列出每一项现在的值、建议的值和原因。加 `--apply` 时把建议的值写进内核（立刻生效），
//! 并记到 `/etc/sysctl.d/` 下的一个文件里，重启之后还在。只往"更宽"的方向改：已经比建议值大的数不动。
//! 只有一处往回改：以前的版本打开过的路径 MTU 黑洞探测（见 [`survey`]）。

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::texts::texts;

/// `--apply` 把改过的参数记在这里。
const PERSIST_FILE: &str = "/etc/sysctl.d/90-i3t.conf";
/// 节点给自己的 UDP 端口申请的缓冲区大小（`i3t-underlay` 里的 `SOCKET_BUFFER_BYTES`）。
const UDP_BUFFER_BYTES: u64 = 4 * 1024 * 1024;
/// 路径 MTU 黑洞探测的开关。0 是关，1 是发现黑洞之后才探，2 是一直探。
const MTU_PROBING: &str = "net.ipv4.tcp_mtu_probing";
/// 探测开着时，内核把一条 TCP 的分段最小减到多少字节。
const MTU_PROBE_FLOOR: &str = "net.ipv4.tcp_mtu_probe_floor";
/// 探测开着时分段下限至少要这么大。内核默认 48 字节；1024 是探测的起点（`tcp_base_mss`）的默认值，
/// 也就是发现黑洞之后减一次就到底，不再一路减半。
const MTU_PROBE_FLOOR_BYTES: u64 = 1024;

/// `--apply` 以前记下的参数：名字到值。
type Recorded = BTreeMap<String, String>;

/// 读写内核参数的地方。真的是 `/proc/sys`，测试里是一张表。
pub(crate) trait Sysctl {
    /// 参数现在的值；这个内核没有这个参数时是 `None`。
    fn read(&self, key: &str) -> Option<String>;

    fn write(&mut self, key: &str, value: &str) -> io::Result<()>;
}

/// `/proc/sys` 下的内核参数：`net.core.rmem_max` 就是文件 `/proc/sys/net/core/rmem_max`。
pub(crate) struct ProcSys;

impl ProcSys {
    fn path(key: &str) -> PathBuf {
        Path::new("/proc/sys").join(key.replace('.', "/"))
    }
}

impl Sysctl for ProcSys {
    fn read(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(Self::path(key)).ok().map(|value| value.trim().to_owned())
    }

    fn write(&mut self, key: &str, value: &str) -> io::Result<()> {
        std::fs::write(Self::path(key), value)
    }
}

/// 一个参数应该是什么样。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    /// 数值不小于这个数。
    AtLeast(u64),
    /// 就是这个值。
    Exactly(&'static str),
    /// 端口列表里有这个端口。列表的写法是逗号分隔，每一项是一个端口或者 `起-止`。
    IncludesPort(u16),
}

impl Want {
    /// 现在的值是 `current` 时该改成什么；已经符合就是 `None`。
    fn change(self, current: &str) -> Option<String> {
        match self {
            Self::AtLeast(least) => {
                let now: u64 = current.split_whitespace().next()?.parse().ok()?;
                (now < least).then(|| least.to_string())
            }
            Self::Exactly(value) => (current != value).then(|| value.to_owned()),
            Self::IncludesPort(port) => {
                let listed = current.split(',').filter_map(port_range).any(|(from, to)| (from..=to).contains(&port));
                (!listed).then(|| if current.is_empty() { port.to_string() } else { format!("{current},{port}") })
            }
        }
    }
}

/// 把 `8080` 或者 `8000-8100` 读成一段端口。
fn port_range(item: &str) -> Option<(u16, u16)> {
    let item = item.trim();
    match item.split_once('-') {
        Some((from, to)) => Some((from.trim().parse().ok()?, to.trim().parse().ok()?)),
        None => item.parse().ok().map(|port| (port, port)),
    }
}

/// 对一个参数的结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Fine,
    /// 建议改成这个值。
    Change(String),
    /// 不适用，原因写给人看。
    Skipped(&'static str),
}

/// 一个参数检查下来的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    pub(crate) key: &'static str,
    pub(crate) current: Option<String>,
    pub(crate) verdict: Verdict,
    pub(crate) why: &'static str,
}

/// 检查一遍。`port` 是节点的端口（配置文件里的 `port`），`recorded` 是 `--apply` 以前记下的参数。
///
/// 路径 MTU 黑洞探测（[`MTU_PROBING`]）不再建议打开。它开着时，一条 TCP 大约 3 秒没有进展之后，每一次重传超时都被内核
/// 当成黑洞的迹象：分段先降到 1024 字节，再每超时一次减半，一直减到 [`MTU_PROBE_FLOOR`]（默认 48），之后要靠探测一点点
/// 加回去，丢了一个探测包上限还要再降。丢包重的线路上这等于把连接掐住：本机实验里（往返 250 毫秒，一个方向丢 30%，
/// 经 ice3proxy 来回传 256 KB，90 秒为限）关着时 12 次传完 9 次，开着 12 次传完 3 次，下限提到 1024 是 7 次。
/// 节点自己的 TCP 已经压低了分段（`i3t_underlay::tcp_mss`），躲黑洞不靠这一项。所以：
///
/// - 关着：不提它。
/// - 开着，并且是以前的版本的 `--apply` 打开的：改回 0。那时只在原来是 0 时才改成 1 并记下来，
///   因此记录值为 1 且当前值也为 1 时可确认属于本程序之前的修改，回退为 0 不会影响管理员配置。
/// - 开着，别的情形（管理员自己开的，或者设成了 2）：留着，只要求分段的下限不低于 [`MTU_PROBE_FLOOR_BYTES`]。
pub(crate) fn survey(sysctl: &impl Sysctl, port: u16, recorded: &Recorded) -> Vec<Finding> {
    let t = &texts().linux;
    let check = |key: &'static str, want: Want, why: &'static str| {
        let current = sysctl.read(key);
        let verdict = match &current {
            None => Verdict::Skipped(t.tune_missing),
            Some(current) => want.change(current).map_or(Verdict::Fine, Verdict::Change),
        };
        Finding { key, current, verdict, why }
    };
    let mut findings = vec![
        check("net.core.rmem_max", Want::AtLeast(UDP_BUFFER_BYTES), t.tune_rmem),
        check("net.core.wmem_max", Want::AtLeast(UDP_BUFFER_BYTES), t.tune_wmem),
        check("net.ipv4.tcp_slow_start_after_idle", Want::Exactly("0"), t.tune_slow_start),
        check("net.ipv4.tcp_tw_reuse", Want::Exactly("1"), t.tune_tw_reuse),
    ];

    let probing = sysctl.read(MTU_PROBING);
    let switched_on_by_us = probing.as_deref() == Some("1") && recorded.get(MTU_PROBING).is_some_and(|value| value == "1");
    if switched_on_by_us {
        findings.push(check(MTU_PROBING, Want::Exactly("0"), t.tune_mtu_probing));
    } else if probing.is_some_and(|value| value != "0") {
        findings.push(check(MTU_PROBE_FLOOR, Want::AtLeast(MTU_PROBE_FLOOR_BYTES), t.tune_mtu_probe_floor));
    }

    let mut congestion = check("net.ipv4.tcp_congestion_control", Want::Exactly("bbr"), t.tune_bbr);
    let available = sysctl.read("net.ipv4.tcp_available_congestion_control").unwrap_or_default();
    if matches!(congestion.verdict, Verdict::Change(_)) && !available.split_whitespace().any(|name| name == "bbr") {
        congestion.verdict = Verdict::Skipped(t.tune_no_bbr);
    }
    findings.push(congestion);

    let mut reserved = check("net.ipv4.ip_local_reserved_ports", Want::IncludesPort(port), t.tune_reserved);
    let in_ephemeral_range = sysctl.read("net.ipv4.ip_local_port_range").and_then(|range| {
        let mut bounds = range.split_whitespace().map(str::parse::<u16>);
        Some((bounds.next()?.ok()?..=bounds.next()?.ok()?).contains(&port))
    });
    if matches!(reserved.verdict, Verdict::Change(_)) && in_ephemeral_range != Some(true) {
        reserved.verdict = Verdict::Fine;
    }
    findings.push(reserved);
    findings
}

/// 把建议的值写进内核。返回改了哪些参数、改成了什么。
///
/// # Errors
/// 写入内核参数失败时停止处理并返回错误，已生效的修改不会回滚。常见原因是缺少 root 权限。
pub(crate) fn apply(sysctl: &mut impl Sysctl, findings: &[Finding]) -> anyhow::Result<Vec<(&'static str, String)>> {
    let mut changed = Vec::new();
    for finding in findings {
        if let Verdict::Change(value) = &finding.verdict {
            sysctl.write(finding.key, value).with_context(|| (texts().linux.tune_write_failed)(finding.key))?;
            changed.push((finding.key, value.clone()));
        }
    }
    Ok(changed)
}

/// 读出记着改过的参数的那个文件里的每一项。`existing` 是文件的内容。
fn recorded(existing: &str) -> Recorded {
    existing
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

/// 记下改过的参数，让它们重启之后还在。`existing` 是这个文件原来的内容：以前记过的参数保留，同名的换成新值。
fn persisted(existing: &str, changed: &[(&'static str, String)]) -> String {
    let mut settings = recorded(existing);
    for (key, value) in changed {
        settings.insert((*key).to_owned(), value.clone());
    }
    let mut text = format!("# {}\n", texts().linux.tune_file_header);
    for (key, value) in settings {
        text.push_str(&format!("{key} = {value}\n"));
    }
    text
}

/// 记着改过的参数的那个文件现在的内容。还没有这个文件时是空的。
///
/// # Errors
/// 文件存在但无法读取（如权限不足、非 UTF-8 文本或路径为目录）。此时不能视为空文件，否则后续写入会覆盖先前记录的参数。
fn read_persisted(path: &Path) -> anyhow::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error).with_context(|| (texts().linux.tune_read_failed)(&path.display().to_string())),
    }
}

/// `i3t tune` 的全部：检查，打印，按要求修改。
pub(crate) fn run(port: u16, apply_changes: bool) -> anyhow::Result<()> {
    let t = &texts().linux;
    let mut sysctl = ProcSys;
    let kernel = sysctl.read("kernel.osrelease").unwrap_or_else(|| i3t_lang::NONE.to_owned());
    println!("{}", (t.tune_title)(&kernel));
    // 持久化记录文件无法读取时，检查阶段按无历史记录处理（最多遗漏一条回退建议）；真正执行写入时再返回该错误。
    let existing = read_persisted(Path::new(PERSIST_FILE));
    let findings = survey(&sysctl, port, &existing.as_deref().map(recorded).unwrap_or_default());
    let mut table = i3t_lang::table::Table::new(&t.tune_header).indented(2);
    for finding in &findings {
        let current = finding.current.clone().unwrap_or_else(|| i3t_lang::NONE.to_owned());
        let (verdict, suggested, note) = match &finding.verdict {
            Verdict::Fine => (t.tune_fine, i3t_lang::NONE.to_owned(), String::new()),
            Verdict::Change(value) => (t.tune_change, value.clone(), finding.why.to_owned()),
            Verdict::Skipped(reason) => (t.tune_skipped, i3t_lang::NONE.to_owned(), (*reason).to_owned()),
        };
        table.row(vec![verdict.to_owned(), finding.key.to_owned(), current, suggested, note]);
    }
    table.print();
    print_open_file_limit();
    print_rto_cap(i3t_underlay::tcp_recovery::rto_cap_supported());

    let wanted = findings.iter().filter(|finding| matches!(finding.verdict, Verdict::Change(_))).count();
    if wanted == 0 {
        println!("\n{}", t.tune_nothing);
        return Ok(());
    }
    if !apply_changes {
        println!("\n{}", (t.tune_wanted)(wanted, PERSIST_FILE));
        return Ok(());
    }
    // 若无法读取既有持久化记录，则中止修改，避免修改内核参数后覆盖丢失先前记录。
    let existing = existing?;
    let changed = apply(&mut sysctl, &findings)?;
    std::fs::write(PERSIST_FILE, persisted(&existing, &changed)).with_context(|| (t.tune_persist_failed)(PERSIST_FILE))?;
    println!("\n{}", (t.tune_changed)(changed.len(), PERSIST_FILE));
    Ok(())
}

/// 内核能不能给 TCP 的重传定时器设上限。节点自己在 lane 和 TCP 中转的 socket 上设，不用改内核参数，这里只报告。
fn print_rto_cap(supported: bool) {
    let t = &texts().linux;
    println!("{}", if supported { t.tune_rto_cap } else { t.tune_no_rto_cap });
}

/// 能同时打开的文件数。它不是内核参数，这里只报告：`i3t run` 启动时自己会把软上限抬到硬上限。
fn print_open_file_limit() {
    let t = &texts().linux;
    match rlimit::Resource::NOFILE.get() {
        Ok((soft, hard)) => {
            println!("\n{}", (t.tune_files)(soft, hard));
            if hard < 65_536 {
                println!("{}", t.tune_files_low);
            }
        }
        Err(error) => println!("\n{}", (t.tune_files_unknown)(&error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// 一张表当内核。`read_only` 的参数写不进去，像没有 root 权限时那样。
    #[derive(Default)]
    struct Table {
        values: HashMap<&'static str, String>,
        read_only: bool,
    }

    impl Table {
        fn with(values: &[(&'static str, &str)]) -> Self {
            Self { values: values.iter().map(|&(key, value)| (key, value.to_owned())).collect(), read_only: false }
        }
    }

    impl Sysctl for Table {
        fn read(&self, key: &str) -> Option<String> {
            self.values.get(key).cloned()
        }

        fn write(&mut self, key: &str, value: &str) -> io::Result<()> {
            if self.read_only {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let slot = self.values.iter_mut().find(|(known, _)| **known == key).ok_or(io::ErrorKind::NotFound)?;
            *slot.1 = value.to_owned();
            Ok(())
        }
    }

    /// 一台没有调过的机器上常见的值。
    fn stock() -> Table {
        Table::with(&[
            ("net.core.rmem_max", "212992"),
            ("net.core.wmem_max", "212992"),
            ("net.ipv4.tcp_slow_start_after_idle", "1"),
            ("net.ipv4.tcp_tw_reuse", "2"),
            ("net.ipv4.tcp_mtu_probing", "0"),
            ("net.ipv4.tcp_congestion_control", "cubic"),
            ("net.ipv4.tcp_available_congestion_control", "reno cubic bbr"),
            ("net.ipv4.ip_local_reserved_ports", ""),
            ("net.ipv4.ip_local_port_range", "32768\t60999"),
        ])
    }

    fn verdict_of<'a>(findings: &'a [Finding], key: &str) -> &'a Verdict {
        &findings.iter().find(|finding| finding.key == key).unwrap_or_else(|| panic!("应该检查了 {key}")).verdict
    }

    fn mentions(findings: &[Finding], key: &str) -> bool {
        findings.iter().any(|finding| finding.key == key)
    }

    /// 这台机器上 `--apply` 还没有记过什么。
    fn nothing() -> Recorded {
        Recorded::new()
    }

    #[test]
    fn an_untuned_machine_gets_the_five_changes() {
        let findings = survey(&stock(), 20330, &nothing());
        assert_eq!(verdict_of(&findings, "net.core.rmem_max"), &Verdict::Change("4194304".to_owned()));
        assert_eq!(verdict_of(&findings, "net.core.wmem_max"), &Verdict::Change("4194304".to_owned()));
        assert_eq!(verdict_of(&findings, "net.ipv4.tcp_slow_start_after_idle"), &Verdict::Change("0".to_owned()));
        assert_eq!(verdict_of(&findings, "net.ipv4.tcp_tw_reuse"), &Verdict::Change("1".to_owned()), "默认的 2 只对回环生效");
        assert_eq!(verdict_of(&findings, "net.ipv4.tcp_congestion_control"), &Verdict::Change("bbr".to_owned()));
        assert!(!mentions(&findings, MTU_PROBING) && !mentions(&findings, MTU_PROBE_FLOOR), "黑洞探测关着就不提它");
        assert_eq!(verdict_of(&findings, "net.ipv4.ip_local_reserved_ports"), &Verdict::Fine, "20330 不在随机端口的范围里，不用保留");
    }

    #[test]
    fn values_that_are_already_wide_enough_are_left_alone() {
        let mut machine = stock();
        machine.values.insert("net.core.rmem_max", "16777216".to_owned());
        let findings = survey(&machine, 20330, &nothing());
        assert_eq!(verdict_of(&findings, "net.core.rmem_max"), &Verdict::Fine, "只往大里改，不把已经更大的数改小");
    }

    #[test]
    fn mtu_probing_switched_on_by_an_earlier_apply_is_switched_off_again() {
        let mut machine = stock();
        machine.values.insert(MTU_PROBING, "1".to_owned());
        machine.values.insert(MTU_PROBE_FLOOR, "48".to_owned());
        let earlier = recorded("# 以前的版本写的\nnet.core.rmem_max = 4194304\nnet.ipv4.tcp_mtu_probing = 1\n");
        let findings = survey(&machine, 20330, &earlier);
        assert_eq!(verdict_of(&findings, MTU_PROBING), &Verdict::Change("0".to_owned()));
        assert!(!mentions(&findings, MTU_PROBE_FLOOR), "探测要关了，下限就不用管");

        let changed = apply(&mut machine, &findings).unwrap();
        let text = persisted("net.ipv4.tcp_mtu_probing = 1\n", &changed);
        assert!(text.contains("net.ipv4.tcp_mtu_probing = 0\n"), "{text}");
        let again = survey(&machine, 20330, &recorded(&text));
        assert!(!mentions(&again, MTU_PROBING) && !mentions(&again, MTU_PROBE_FLOOR));
    }

    #[test]
    fn mtu_probing_someone_else_switched_on_stays_and_gets_a_higher_floor() {
        let mut machine = stock();
        machine.values.insert(MTU_PROBING, "1".to_owned());
        machine.values.insert(MTU_PROBE_FLOOR, "48".to_owned());
        let findings = survey(&machine, 20330, &nothing());
        assert!(!mentions(&findings, MTU_PROBING), "没有记过，是管理员自己开的：不动");
        assert_eq!(verdict_of(&findings, MTU_PROBE_FLOOR), &Verdict::Change("1024".to_owned()));

        machine.values.insert(MTU_PROBE_FLOOR, "1200".to_owned());
        assert_eq!(verdict_of(&survey(&machine, 20330, &nothing()), MTU_PROBE_FLOOR), &Verdict::Fine, "已经更高的下限不改小");

        // 记过 1，但现在是 2：后来有人改过，不再是本程序的改动。
        machine.values.insert(MTU_PROBING, "2".to_owned());
        machine.values.insert(MTU_PROBE_FLOOR, "48".to_owned());
        let findings = survey(&machine, 20330, &recorded("net.ipv4.tcp_mtu_probing = 1\n"));
        assert!(!mentions(&findings, MTU_PROBING));
        assert_eq!(verdict_of(&findings, MTU_PROBE_FLOOR), &Verdict::Change("1024".to_owned()));
    }

    #[test]
    fn a_kernel_without_the_probe_floor_says_so() {
        let mut machine = stock();
        machine.values.insert(MTU_PROBING, "1".to_owned());
        let findings = survey(&machine, 20330, &nothing());
        assert!(matches!(verdict_of(&findings, MTU_PROBE_FLOOR), Verdict::Skipped(_)), "Linux 5.4 之前没有这个参数");
    }

    #[test]
    fn bbr_is_only_suggested_when_the_kernel_has_it() {
        let mut machine = stock();
        machine.values.insert("net.ipv4.tcp_available_congestion_control", "reno cubic".to_owned());
        let findings = survey(&machine, 20330, &nothing());
        assert!(
            matches!(verdict_of(&findings, "net.ipv4.tcp_congestion_control"), Verdict::Skipped(reason) if reason.contains("modprobe tcp_bbr"))
        );
    }

    #[test]
    fn a_node_port_inside_the_ephemeral_range_is_reserved() {
        let findings = survey(&stock(), 40000, &nothing());
        assert_eq!(verdict_of(&findings, "net.ipv4.ip_local_reserved_ports"), &Verdict::Change("40000".to_owned()));

        let mut machine = stock();
        machine.values.insert("net.ipv4.ip_local_reserved_ports", "8080,39000-41000".to_owned());
        assert_eq!(
            verdict_of(&survey(&machine, 40000, &nothing()), "net.ipv4.ip_local_reserved_ports"),
            &Verdict::Fine,
            "已经在一段保留的范围里"
        );
        machine.values.insert("net.ipv4.ip_local_reserved_ports", "8080".to_owned());
        let appended = Verdict::Change("8080,40000".to_owned());
        assert_eq!(verdict_of(&survey(&machine, 40000, &nothing()), "net.ipv4.ip_local_reserved_ports"), &appended, "原来保留的端口留着");
    }

    #[test]
    fn a_parameter_the_kernel_lacks_is_reported_not_guessed() {
        let mut machine = stock();
        machine.values.remove("net.ipv4.tcp_slow_start_after_idle");
        let findings = survey(&machine, 20330, &nothing());
        assert!(matches!(verdict_of(&findings, "net.ipv4.tcp_slow_start_after_idle"), Verdict::Skipped(_)));
    }

    #[test]
    fn applying_writes_every_suggested_value_and_a_second_survey_is_clean() {
        let mut machine = stock();
        let findings = survey(&machine, 40000, &nothing());
        let changed = apply(&mut machine, &findings).unwrap();
        assert_eq!(changed.len(), 6);
        assert!(survey(&machine, 40000, &nothing()).iter().all(|finding| finding.verdict == Verdict::Fine));
    }

    #[test]
    fn without_permission_applying_fails_and_says_how_to_run_it() {
        let mut machine = stock();
        machine.read_only = true;
        let findings = survey(&machine, 20330, &nothing());
        let error = apply(&mut machine, &findings).unwrap_err();
        assert!(format!("{error:#}").contains("sudo i3t tune --apply"));
    }

    #[test]
    fn the_persisted_file_keeps_earlier_entries_and_replaces_changed_ones() {
        let existing = "# 旧的说明\nnet.core.rmem_max = 1048576\nnet.ipv4.tcp_slow_start_after_idle = 0\n";
        let text = persisted(existing, &[("net.core.rmem_max", "4194304".to_owned()), ("net.core.wmem_max", "4194304".to_owned())]);
        let lines: Vec<&str> = text.lines().skip(1).collect();
        assert_eq!(lines, ["net.core.rmem_max = 4194304", "net.core.wmem_max = 4194304", "net.ipv4.tcp_slow_start_after_idle = 0"]);
        assert!(text.starts_with('#'));
    }

    #[test]
    fn only_a_missing_persisted_file_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_persisted(&dir.path().join("90-i3t.conf")).unwrap(), "", "还没有记过");
        let file = dir.path().join("written.conf");
        std::fs::write(&file, "net.core.rmem_max = 4194304\n").unwrap();
        assert_eq!(read_persisted(&file).unwrap(), "net.core.rmem_max = 4194304\n");
        // 读不了的文件不能当作空的：不然接着写进去的会把以前记下的参数整个盖掉。
        let error = read_persisted(dir.path()).unwrap_err();
        assert!(format!("{error:#}").contains(&dir.path().display().to_string()), "{error:#}");
        std::fs::write(&file, [0xff, 0xfe, b'\n']).unwrap();
        assert!(read_persisted(&file).is_err(), "不是文本");
    }

    #[test]
    fn port_lists_are_read_with_ranges_and_spaces() {
        assert_eq!(port_range("8080"), Some((8080, 8080)));
        assert_eq!(port_range(" 8000 - 8100 "), Some((8000, 8100)));
        assert_eq!(port_range("x"), None);
    }
}
