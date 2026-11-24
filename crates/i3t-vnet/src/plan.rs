//! 生成各平台待安装的防火墙规则参数与脚本。本模块仅构造命令文本而不调用系统接口，因此所有平台的规则均可在任意机器上逐字单元测试。
//!
//! | 平台 | 入站放行规则（`accept`） | 防虚拟 IP 伪造规则（`guard`） |
//! |---|---|---|
//! | Linux | `iptables -I INPUT 1 -i <网卡> -m comment --comment ice3tier -j ACCEPT`：插入 `INPUT` 链首条，确保 ufw 等默认拒绝入站的防火墙不会拦截其他节点流量。系统无 `iptables` 时跳过（无对应 `INPUT` 链规则需要前置） | 存在 `nft` 时创建 nftables 表 `ip <网卡名>`：对非本虚拟网卡且非回环接口进入的数据包，丢弃源地址位于虚拟网段或目的地址为本节点虚拟 IP 的流量。无 `nft` 但有 `iptables` 时，在 `raw` 表 `PREROUTING` 链前两条插入 `! -i <网卡> -s <地址段> -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP` 与 `! -i <网卡> -d <虚拟 IP>/32 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP`，语义等效 |
//! | Windows | Windows 防火墙入站规则 `ice3tier-<网卡>`：限定仅作用于该虚拟网卡，放行目的为本节点虚拟 IP、来源位于虚拟网段的入站流量（新建网卡默认归入“公用”网络，默认拦截全部入站） | 不添加：Windows（Vista 起）默认采用强主机模型，发往虚拟 IP 的流量仅在绑定该地址的网卡上接收，从物理网卡进入的会被内核丢弃；且上方入站规则已限定接口。若管理员手动开启物理网卡 `weakhostreceive` 或转发，仅前项防护减弱，后项仍生效 |
//! | macOS | 不添加：本程序不修改包过滤配置（pf），macOS 默认不启用 pf 且不拦截入站流量 | 不添加：macOS 默认（`net.inet.ip.check_interface = 1`，混合模型）对 utun 等隧道接口按强主机模型收包，从物理网卡进入且目的为虚拟 IP 的流量会被丢弃；仅在开启转发（如“互联网共享”）退回弱主机模型时失去该防护 |
//!
//! 所有自有规则均具备明确标识：Linux 使用注释 [`COMMENT`] 配合 `-i <网卡>`（放行）或 `! -i <网卡>`（防伪造），nftables 表名即网卡名；
//! Windows 使用固定命名规则（分组为 [`COMMENT`]）。
//!
//! Linux 防伪造规则后半部分（目的为本节点虚拟 IP）的原因：Linux 默认采用“弱主机模型”收包，发往本机任意地址的包无论从哪块网卡进入均可被接收。
//! 若不拦截，同局域网主机或上游路由器可使用真实源地址将目的为虚拟 IP 的包路由至本机，从而直接访问仅监听在虚拟 IP 上的服务与端口转发，
//! 绕过访问控制且不受 `rp_filter` 拦截。此处仅拦截目的为本节点虚拟 IP 的流量而不拦截整个网段，确保经本机转发的流量（例如 Docker 容器经本机访问其他节点，
//! 出站时伪装为本节点虚拟 IP）保持正常。由于虚拟网段中本机仅拥有这一个地址（其他接口存在重叠地址时会拒绝启用，见 [`crate::overlap`]），
//! 且虚拟 IP 变更时会重装规则，因此直接匹配该 IP 而不依赖 nftables `fib` 查表（精简内核可能缺少 `fib` 模块导致整张表加载失败）。
//! 由此带来的限制是 Docker 桥接网络容器无法直接访问宿主机自身的虚拟 IP（流量来自 `docker0`，无法与局域网外部流量区分）；
//! 若需访问，可使用 `--network host` 或访问宿主机在网桥上的地址。

use std::fmt::Write;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::COMMENT;

/// Linux 平台防火墙规则生成。
pub mod linux {
    use super::{COMMENT, Ipv4Addr, Ipv4Net, Write, args};

    /// `iptables` 等待 xtables 锁的最长秒数（旧版 xtables 后端可能存在并发修改；nftables 后端无需锁）。
    const LOCK_WAIT: &str = "5";

    /// 生成防伪造 nftables 表的原子替换脚本。旧表（含异常崩溃遗留表）在同一事务中先声明、再删除并重建；
    /// 若中途失败则内核配置保持不变。链挂载在 `prerouting` 最前端（`raw` 优先级，位于连接跟踪之前），同时覆盖转发流量。
    ///
    /// 对既不来自本虚拟网卡也不来自回环接口的数据包，丢弃源地址位于虚拟网段 `cidr` 的包（防伪造其他节点），
    /// 以及目的地址为本节点虚拟 IP `own` 的包（应对弱主机模型，详见模块文档）；不影响经本机转发至其他节点的流量。
    #[must_use]
    pub fn guard_script(device: &str, own: Ipv4Addr, cidr: Ipv4Net) -> String {
        let mut script = format!("table ip {device}\ndelete table ip {device}\ntable ip {device} {{\n");
        let _ = write!(
            script,
            "\tchain guard {{\n\
             \t\ttype filter hook prerouting priority raw; policy accept;\n\
             \t\tiifname \"{device}\" return\n\
             \t\tiifname \"lo\" return\n\
             \t\tip saddr {cidr} drop\n\
             \t\tip daddr {own} drop\n\
             \t}}\n\
             }}\n"
        );
        script
    }

    /// 生成删除指定表的 nftables 脚本。先声明空表再删除，确保表不存在时也不会报错。
    #[must_use]
    pub fn remove_table_script(name: &str) -> String {
        format!("table ip {name}\ndelete table ip {name}\n")
    }

    /// 构造入站放行规则参数（对应 `iptables -S` 输出去掉 `-A INPUT` 后的部分）。
    fn rule(device: &str) -> Vec<String> {
        args(&["-i", device, "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"])
    }

    /// 插入至 `INPUT` 链首条的 `iptables` 参数。
    #[must_use]
    pub fn insert_accept(device: &str) -> Vec<String> {
        [args(&["-w", LOCK_WAIT, "-I", "INPUT", "1"]), rule(device)].concat()
    }

    /// 按完整匹配条件删除自有放行规则的 `iptables` 参数。
    #[must_use]
    pub fn delete_accept(device: &str) -> Vec<String> {
        [args(&["-w", LOCK_WAIT, "-D", "INPUT"]), rule(device)].concat()
    }

    /// 列出 `INPUT` 链规则的参数。
    #[must_use]
    pub fn list_input() -> Vec<String> {
        args(&["-w", LOCK_WAIT, "-S", "INPUT"])
    }

    /// 列出 `ip` 地址族所有表的 `nft` 参数。
    #[must_use]
    pub fn list_tables() -> Vec<String> {
        args(&["-j", "list", "tables", "ip"])
    }

    /// 无 `nft` 时的防伪造规则：两条 `iptables` 规则均作用于非 `device` 接口入站流量，
    /// 分别丢弃源地址位于 `cidr` 与目的地址为 `own` 的数据包。规则位于 `raw` 表 `PREROUTING` 链（连接跟踪之前），同时覆盖转发流量。
    ///
    /// 单条 `iptables` 规则仅支持匹配单个网卡，无法像 nftables 那样单独放行 `lo`；但本机应用访问本节点虚拟 IP 时流量走回环接口，
    /// 源地址位于网段内且目的为虚拟 IP，不应丢弃。通过 `-m addrtype ! --src-type LOCAL` 排除本机源地址流量即可放行回环访问，
    /// 而从外部接口伪造本机源地址的数据包会由内核默认丢弃（martian，`accept_local` 默认关闭）。
    ///
    /// 为保证与 `iptables -S` 读回格式一致，网段使用规范网络地址，单地址显式携带 `/32`。
    fn guard_rules(device: &str, own: Ipv4Addr, cidr: Ipv4Net) -> [Vec<String>; 2] {
        let not_local = args(&["-m", "addrtype", "!", "--src-type", "LOCAL", "-m", "comment", "--comment", COMMENT, "-j", "DROP"]);
        let spoofed = [args(&["!", "-i", device, "-s", &cidr.trunc().to_string()]), not_local.clone()].concat();
        let to_us = [args(&["!", "-i", device, "-d", &Ipv4Net::from(own).to_string()]), not_local].concat();
        [spoofed, to_us]
    }

    /// 生成插入 `raw` 表 `PREROUTING` 链第 1、2 条的防伪造规则参数（按源地址拦截规则在前，需按顺序执行）。
    #[must_use]
    pub fn insert_guards(device: &str, own: Ipv4Addr, cidr: Ipv4Net) -> [Vec<String>; 2] {
        let insert = |position: &str| args(&["-w", LOCK_WAIT, "-t", "raw", "-I", "PREROUTING", position]);
        let [spoofed, to_us] = guard_rules(device, own, cidr);
        [[insert("1"), spoofed].concat(), [insert("2"), to_us].concat()]
    }

    /// 生成删除单条防伪造规则的参数：`listed` 为 `iptables -S` 输出行去掉 `-A PREROUTING` 后的原文。
    /// 按原样回传删除可兼容历史网段与旧格式规则，不受 `iptables` 输出参数顺序与 [`insert_guards`] 差异的影响。
    #[must_use]
    pub fn delete_guard(listed: &str) -> Vec<String> {
        [args(&["-w", LOCK_WAIT, "-t", "raw", "-D", "PREROUTING"]), split_listed(listed)].concat()
    }

    /// 列出 `raw` 表 `PREROUTING` 链规则的参数。
    #[must_use]
    pub fn list_raw_prerouting() -> Vec<String> {
        args(&["-w", LOCK_WAIT, "-t", "raw", "-S", "PREROUTING"])
    }

    /// 将 `iptables -S` 输出的单条规则拆分为参数列表。参数以空白分隔，含空白或引号的值（如注释）由双引号包裹，
    /// 内部的 `"`、`\`、`'` 按 `iptables-save` 规则以 `\` 转义；解析结果去除外层引号，可直接作为进程参数使用。
    #[must_use]
    pub fn split_listed(listed: &str) -> Vec<String> {
        let mut words = Vec::new();
        // 当前正在拼接的参数。空双引号 `""` 也代表一个有效的空字符串参数，因此用 `Option` 区分是否存在参数。
        let mut word: Option<String> = None;
        let mut quoted = false;
        let mut chars = listed.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    quoted = !quoted;
                    word.get_or_insert_default();
                }
                '\\' if quoted => word.get_or_insert_default().extend(chars.next()),
                c if c.is_whitespace() && !quoted => words.extend(word.take()),
                c => word.get_or_insert_default().push(c),
            }
        }
        words.extend(word);
        words
    }
}

/// Windows 平台防火墙规则生成：通过 PowerShell `NetSecurity` 模块（Windows 8 起内置）管理入站规则。
///
/// 未使用 `netsh advfirewall` 的原因：其仅支持按接口类型（有线、无线、拨号）过滤而无法限定到特定适配器；
/// `New-NetFirewallRule -InterfaceAlias` 可精确限定在虚拟网卡上，避免放行从其他网卡伪造虚拟 IP 进入的流量。
pub mod windows {
    use super::{COMMENT, Ipv4Addr, Ipv4Net, args};

    /// 生成规则名称（`-Name`，Windows 防火墙唯一标识）及显示名：`ice3tier-i3t0`（分组为 [`COMMENT`]）。
    #[must_use]
    pub fn rule_name(device: &str) -> String {
        format!("{COMMENT}-{device}")
    }

    /// 构造执行 PowerShell 脚本的参数列表。脚本不得包含双引号，以确保作为单个参数传递给 PowerShell。
    /// 通过 `$ErrorActionPreference = 'Stop'` 确保出错时立即中止并以非零状态退出，错误信息输出至标准错误。
    #[must_use]
    pub fn invocation(script: &str) -> Vec<String> {
        debug_assert!(!script.contains('"'), "PowerShell 脚本中不得包含双引号：{script}");
        let mut parts = args(&["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]);
        parts.push(format!("$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; {script}"));
        parts
    }

    /// 生成安装入站放行规则的脚本：先清理可能残留的同名规则再新建。仅放行经 `device` 进入、目的为 `own`、
    /// 来源属于 `cidr` 的任意协议流量，覆盖所有网络配置文件（新建网卡默认归入“公用”网络，默认拦截入站）。
    #[must_use]
    pub fn install_script(device: &str, own: Ipv4Addr, cidr: Ipv4Net) -> String {
        let name = rule_name(device);
        format!(
            "{remove}; New-NetFirewallRule -Name '{name}' -DisplayName '{name}' -Group '{COMMENT}' -Direction Inbound -Action Allow \
             -Protocol Any -InterfaceAlias '{device}' -LocalAddress {own} -RemoteAddress {cidr} -Profile Any | Out-Null",
            remove = remove_script(device)
        )
    }

    /// 生成删除同名防火墙规则的脚本；规则不存在时不视为错误。
    #[must_use]
    pub fn remove_script(device: &str) -> String {
        format!("Get-NetFirewallRule -Name '{}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule", rule_name(device))
    }

    /// 生成统计同名防火墙规则数量的脚本（输出 `0` 或 `1`）；除 `ObjectNotFound` 外的错误（如防火墙服务未运行）仍会抛出异常。
    #[must_use]
    pub fn count_script(device: &str) -> String {
        format!(
            "$rules = @(Get-NetFirewallRule -Name '{}' -ErrorAction SilentlyContinue -ErrorVariable failures); \
             $other = @($failures | Where-Object {{ $_.CategoryInfo.Category -ne 'ObjectNotFound' }}); \
             if ($other.Count -gt 0) {{ throw $other[0] }}; $rules.Count",
            rule_name(device)
        )
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// 虚拟网卡防火墙配置计划：包含设备创建后的实际名称、本节点虚拟 IP 及网络网段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// 虚拟网卡实际名称。
    pub device: String,
    /// 本节点虚拟 IP。
    pub own: Ipv4Addr,
    /// 虚拟网络网段。
    pub cidr: Ipv4Net,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_linux_guard_replaces_its_whole_table_in_one_transaction() {
        let script = linux::guard_script("i3t0", Ipv4Addr::new(10, 66, 0, 1), "10.66.0.0/16".parse().unwrap());
        assert_eq!(
            script,
            "table ip i3t0\ndelete table ip i3t0\ntable ip i3t0 {\n\tchain guard {\n\t\ttype filter hook prerouting priority raw; policy accept;\n\
             \t\tiifname \"i3t0\" return\n\t\tiifname \"lo\" return\n\t\tip saddr 10.66.0.0/16 drop\n\
             \t\tip daddr 10.66.0.1 drop\n\t}\n}\n"
        );
        assert_eq!(linux::remove_table_script("i3t1"), "table ip i3t1\ndelete table ip i3t1\n");
    }

    #[test]
    fn the_linux_accept_rule_is_inserted_first_and_deleted_by_its_full_spelling() {
        assert_eq!(linux::insert_accept("i3t0").join(" "), "-w 5 -I INPUT 1 -i i3t0 -m comment --comment ice3tier -j ACCEPT");
        assert_eq!(linux::delete_accept("i3t0").join(" "), "-w 5 -D INPUT -i i3t0 -m comment --comment ice3tier -j ACCEPT");
        assert_eq!(linux::list_input().join(" "), "-w 5 -S INPUT");
        assert_eq!(linux::list_tables().join(" "), "-j list tables ip");
    }

    #[test]
    fn without_nft_the_linux_guard_is_the_first_two_rules_in_raw_prerouting_and_is_deleted_as_listed() {
        let cidr = "10.66.0.0/16".parse().unwrap();
        let [spoofed, to_us] = linux::insert_guards("i3t0", Ipv4Addr::new(10, 66, 0, 1), cidr);
        assert_eq!(
            spoofed.join(" "),
            "-w 5 -t raw -I PREROUTING 1 ! -i i3t0 -s 10.66.0.0/16 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP"
        );
        assert_eq!(
            to_us.join(" "),
            "-w 5 -t raw -I PREROUTING 2 ! -i i3t0 -d 10.66.0.1/32 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP"
        );
        assert_eq!(linux::list_raw_prerouting().join(" "), "-w 5 -t raw -S PREROUTING");
        let listed = "-s 10.66.0.0/16 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP";
        assert_eq!(
            linux::delete_guard(listed).join(" "),
            "-w 5 -t raw -D PREROUTING -s 10.66.0.0/16 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP"
        );
        let [spoofed, to_us] = linux::insert_guards("i3t0", Ipv4Addr::new(10, 66, 3, 4), "10.66.3.4/16".parse().unwrap());
        assert!(spoofed.join(" ").contains(" -s 10.66.0.0/16 "), "写的是网络地址，和 iptables 读回来的一样");
        assert!(to_us.join(" ").contains(" -d 10.66.3.4/32 "), "单个地址带 /32，和 iptables 读回来的一样");
    }

    #[test]
    fn a_listed_rule_splits_back_into_arguments_and_a_quoted_value_is_one_argument() {
        assert_eq!(
            linux::split_listed(r#"-s 10.0.0.0/8 -m comment --comment "a \"b\" \\c" -j  DROP"#),
            ["-s", "10.0.0.0/8", "-m", "comment", "--comment", r#"a "b" \c"#, "-j", "DROP"]
        );
        assert_eq!(linux::split_listed(r#"--comment "" -j ACCEPT"#), ["--comment", "", "-j", "ACCEPT"]);
        assert!(linux::split_listed("  ").is_empty());
    }

    #[test]
    fn the_windows_rule_is_scoped_to_our_adapter_and_known_by_its_name() {
        let install = windows::install_script("i3t0", Ipv4Addr::new(10, 66, 0, 5), "10.66.0.0/16".parse().unwrap());
        assert_eq!(
            install,
            "Get-NetFirewallRule -Name 'ice3tier-i3t0' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             New-NetFirewallRule -Name 'ice3tier-i3t0' -DisplayName 'ice3tier-i3t0' -Group 'ice3tier' -Direction Inbound -Action Allow \
             -Protocol Any -InterfaceAlias 'i3t0' -LocalAddress 10.66.0.5 -RemoteAddress 10.66.0.0/16 -Profile Any | Out-Null"
        );
        let call = windows::invocation(&install);
        assert_eq!(call[..5].join(" "), "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command");
        assert_eq!(call.len(), 6, "脚本是一个参数");
        assert!(call[5].starts_with("$ErrorActionPreference = 'Stop'; "), "出错就停下、以 1 退出：{}", call[5]);
        for script in [install, windows::remove_script("i3t0"), windows::count_script("i3t0")] {
            assert!(!script.contains('"'), "没有双引号，整个脚本是一个参数：{script}");
            assert!(script.contains("-Name 'ice3tier-i3t0'"), "{script}");
        }
        assert!(windows::count_script("i3t0").contains("ObjectNotFound"), "只有“没有这条规则”当作 0");
    }
}
