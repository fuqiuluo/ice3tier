//! 名称解析：将 `<节点名>.<网络域名>` 解析为对应节点的虚拟 IP。
//!
//! 提供两种使用方式，数据均来源于节点当前的网络视图（netmap 中本节点可访问的对端及自身）：
//!
//! - **内置 DNS 服务**（[`Names::answer`]）：仅响应本网络域名的权威 DNS 应答器，监听在本节点虚拟 IP 的 53 端口，
//!   由 systemd-resolved 仅将本网络域名的查询路由至此。其他域名一律返回 `REFUSED`，不充当主机通用递归解析器。
//! - **hosts 区块管理**（[`hosts_block`]、[`replace_hosts_block`]、[`remove_hosts_block`]）：在无 systemd-resolved 的主机上，
//!   由 `i3t hosts` 生成或写入带起止标记的 `/etc/hosts` 条目区块；重复写入仅更新该区块，`i3t hosts --remove` 仅移除该区块。
//!
//! 仅支持完整域名（如 `nas.home.i3t`），不解析短主机名（如 `nas`），避免与局域网内同名主机冲突。

use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::Ipv4Addr;
use std::ops::Range;

/// DNS 应答记录的 TTL（秒）。节点名称与拓扑可能动态变更，因此保持较短值。
const TTL_SECS: u32 = 30;

/// DNS 记录类型与查询类常量。
const TYPE_A: u16 = 1;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

/// DNS 响应码（RFC 1035 §4.1.1）。
const NOERROR: u8 = 0;
const FORMERR: u8 = 1;
const NXDOMAIN: u8 = 3;
const NOTIMP: u8 = 4;
const REFUSED: u8 = 5;

/// 单个虚拟网络内的域名及节点地址映射表。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Names {
    /// 规范化后的网络域名（小写，无末尾点号）。
    domain: String,
    /// 小写节点名到虚拟 IP 的有序映射。
    nodes: BTreeMap<String, Ipv4Addr>,
}

impl Names {
    /// 使用网络域名 `domain`（如 `home.i3t`）及 `(节点名, 虚拟 IP)` 列表构造映射表；名称不区分大小写。
    #[must_use]
    pub fn new(domain: &str, nodes: impl IntoIterator<Item = (String, Ipv4Addr)>) -> Self {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        Self { domain, nodes: nodes.into_iter().map(|(name, ip)| (name.to_ascii_lowercase(), ip)).collect() }
    }

    /// 返回当前表中的节点名称数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// 按完整域名（如 `nas.home.i3t`，可带末尾点号、不区分大小写）查询虚拟 IP；不属于本网络或未找到时返回 `None`。
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<Ipv4Addr> {
        let short = self.short(name)?;
        self.nodes.get(&short).copied()
    }

    /// 提取完整域名中的单级节点名标签。域名不归属当前网络，或包含多级子域（如 `a.b.home.i3t`）时返回 `None`。
    fn short(&self, name: &str) -> Option<String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let short = name.strip_suffix(&self.domain)?.strip_suffix('.')?;
        (!short.is_empty() && !short.contains('.')).then(|| short.to_owned())
    }

    /// 判断 `name` 是否位于当前网络域名范围内（含网络域名本身）。
    fn covers(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        name == self.domain || name.strip_suffix(&self.domain).is_some_and(|rest| rest.ends_with('.'))
    }

    /// 处理单个 DNS 查询报文（UDP 负载）。报文无法解析或非查询类型（如响应报文）时返回 `None`（静默忽略）。
    ///
    /// - 属于当前网络域名且存在对应节点：返回 A 记录；查询其他记录类型（如 AAAA）时返回 `NOERROR` 空应答。
    /// - 属于当前网络域名但不存在对应节点：返回 `NXDOMAIN`。
    /// - 域外名称：返回 `REFUSED`。
    #[must_use]
    pub fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let header = query.get(..12)?;
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let is_response = flags & 0x8000 != 0;
        if is_response {
            return None;
        }
        let opcode = (flags >> 11) & 0xf;
        let questions = u16::from_be_bytes([header[4], header[5]]);
        let parsed = (questions == 1).then(|| question(&query[12..])).flatten();
        let Some(Question { name, kind, class, len }) = parsed else {
            return Some(reply(query, flags, FORMERR, &[], None));
        };
        let echoed = &query[12..12 + len];
        if opcode != 0 {
            return Some(reply(query, flags, NOTIMP, echoed, None));
        }
        if !self.covers(&name) {
            return Some(reply(query, flags, REFUSED, echoed, None));
        }
        let address = self.lookup(&name);
        // 域名本身视为存在（但无 A 记录）；域名下未匹配到节点的其他名称均返回 NXDOMAIN。
        let code = if address.is_some() || name_is_domain(&name, &self.domain) { NOERROR } else { NXDOMAIN };
        let record = address.filter(|_| class == CLASS_IN && (kind == TYPE_A || kind == TYPE_ANY));
        Some(reply(query, flags, code, echoed, record))
    }
}

fn name_is_domain(name: &str, domain: &str) -> bool {
    name.trim_end_matches('.').eq_ignore_ascii_case(domain)
}

struct Question {
    name: String,
    kind: u16,
    class: u16,
    /// Question 段在报文中所占的字节长度。
    len: usize,
}

/// 解析 DNS Question 段（域名标签序列、记录类型与查询类；Question 中不应出现压缩指针）。
fn question(bytes: &[u8]) -> Option<Question> {
    let mut at = 0;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = usize::from(*bytes.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        // 高两位非零表示压缩指针（0xc0）或未定义标签类型（0x40、0x80），在 Question 中均非法。
        if len > 63 {
            return None;
        }
        let label = bytes.get(at..at + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        at += len;
    }
    let fixed = bytes.get(at..at + 4)?;
    Some(Question {
        name: labels.join("."),
        kind: u16::from_be_bytes([fixed[0], fixed[1]]),
        class: u16::from_be_bytes([fixed[2], fixed[3]]),
        len: at + 4,
    })
}

/// 构造 DNS 响应报文：复制事务 ID、操作码与 RD 标志，置 QR 与 AA（权威应答）位、清 RA 位，并原样回显 `question`。
fn reply(query: &[u8], flags: u16, code: u8, question: &[u8], address: Option<Ipv4Addr>) -> Vec<u8> {
    let flags = 0x8000 | (flags & 0x7800) | 0x0400 | (flags & 0x0100) | u16::from(code);
    let mut out = Vec::with_capacity(12 + question.len() + 16);
    out.extend_from_slice(&query[..2]);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&u16::from(!question.is_empty()).to_be_bytes());
    out.extend_from_slice(&u16::from(address.is_some()).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(question);
    if let Some(address) = address {
        // Answer 名称使用压缩指针指向 Question 起始位置（偏移 12）。
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL_SECS.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&address.octets());
    }
    out
}

/// `/etc/hosts` 中由本程序管理的条目区块起止标记。
pub const HOSTS_BEGIN: &str = "# BEGIN ice3tier (i3t hosts)";
pub const HOSTS_END: &str = "# END ice3tier";

/// `/etc/hosts` 条目名称必须仅含合法主机名字符，防止异常或被篡改的 `netmap.json` 注入换行、空白或注释。
fn is_safe_hosts_label(label: &str) -> bool {
    !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_safe_hosts_domain(domain: &str) -> bool {
    !domain.is_empty() && domain.split('.').all(is_safe_hosts_label)
}

/// 生成带起止标记的 `/etc/hosts` 条目区块：每行格式为 `<虚拟 IP>\t<完整域名>`，按节点名升序排列。
#[must_use]
pub fn hosts_block(names: &Names) -> String {
    let mut block = format!("{HOSTS_BEGIN}\n");
    if is_safe_hosts_domain(&names.domain) {
        for (name, ip) in &names.nodes {
            if is_safe_hosts_label(name) {
                let _ = writeln!(block, "{ip}\t{name}.{}", names.domain);
            }
        }
    }
    block.push_str(HOSTS_END);
    block.push('\n');
    block
}

/// 查找 `hosts` 中由起止标记界定的条目区块字节范围（从起始标记行首至结束标记行末换行符之后）。
/// 缺少结束标记时返回 `None`，表示未找到完整的条目区块。
fn hosts_block_span(hosts: &str) -> Option<Range<usize>> {
    let mut lines = hosts.split_inclusive('\n').scan(0, |offset, line| {
        let start = *offset;
        *offset += line.len();
        Some((start..*offset, line.trim_end()))
    });
    let begin = lines.find(|(_, line)| *line == HOSTS_BEGIN)?.0.start;
    let end = lines.find(|(_, line)| *line == HOSTS_END)?.0.end;
    Some(begin..end)
}

/// 仅替换 `hosts` 中有完整起止标记的条目区块。未找到完整区块时，在文件末尾追加 `block`。
#[must_use]
pub fn replace_hosts_block(hosts: &str, block: &str) -> String {
    match hosts_block_span(hosts) {
        Some(span) => [&hosts[..span.start], block, &hosts[span.end..]].concat(),
        None if hosts.is_empty() || hosts.ends_with('\n') => [hosts, block].concat(),
        None => [hosts, "\n", block].concat(),
    }
}

/// 仅移除 `hosts` 中有完整起止标记的条目区块。未找到完整区块时返回 `None`。
#[must_use]
pub fn remove_hosts_block(hosts: &str) -> Option<String> {
    let span = hosts_block_span(hosts)?;
    Some([&hosts[..span.start], &hosts[span.end..]].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Names {
        Names::new("Home.i3t.", [("nas".to_owned(), [10, 66, 0, 5].into()), ("Laptop".to_owned(), [10, 66, 0, 2].into())])
    }

    /// 一个 DNS 查询：编号 0x1d3f，要求递归，问 `name` 的 `kind` 类记录。
    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut bytes = vec![0x1d, 0x3f, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            bytes.push(u8::try_from(label.len()).unwrap());
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes
    }

    fn code(answer: &[u8]) -> u8 {
        answer[3] & 0x0f
    }

    fn answers(answer: &[u8]) -> u16 {
        u16::from_be_bytes([answer[6], answer[7]])
    }

    #[test]
    fn a_node_name_is_answered_with_its_virtual_ip() {
        let q = query("NAS.home.i3t", TYPE_A);
        let a = names().answer(&q).unwrap();
        assert_eq!(&a[..2], &q[..2], "编号照抄");
        assert_eq!(a[2] & 0x80, 0x80, "是应答");
        assert_eq!(a[2] & 0x04, 0x04, "权威");
        assert_eq!(a[2] & 0x01, 0x01, "要求递归照抄");
        assert_eq!(a[3] & 0x80, 0, "不说可以递归");
        assert_eq!((code(&a), answers(&a)), (NOERROR, 1));
        assert_eq!(&a[12..q.len()], &q[12..], "问题原样带回");
        assert_eq!(&a[a.len() - 4..], &[10, 66, 0, 5]);
        assert_eq!(u32::from_be_bytes(a[a.len() - 10..a.len() - 6].try_into().unwrap()), TTL_SECS);
    }

    #[test]
    fn other_types_unknown_nodes_and_foreign_names_get_the_right_codes() {
        let a = names().answer(&query("nas.home.i3t", 28)).unwrap();
        assert_eq!((code(&a), answers(&a)), (NOERROR, 0), "AAAA：名字在，没有这种记录");
        let a = names().answer(&query("ghost.home.i3t", TYPE_A)).unwrap();
        assert_eq!((code(&a), answers(&a)), (NXDOMAIN, 0));
        let a = names().answer(&query("a.nas.home.i3t", TYPE_A)).unwrap();
        assert_eq!(code(&a), NXDOMAIN, "节点名只有一段");
        let a = names().answer(&query("home.i3t", TYPE_A)).unwrap();
        assert_eq!((code(&a), answers(&a)), (NOERROR, 0), "域名本身存在，没有地址");
        let a = names().answer(&query("example.com", TYPE_A)).unwrap();
        assert_eq!((code(&a), answers(&a)), (REFUSED, 0), "不是这台机器的解析器");
        let a = names().answer(&query("nothome.i3t", TYPE_A)).unwrap();
        assert_eq!(code(&a), REFUSED, "后缀要按整段比");
    }

    #[test]
    fn malformed_queries_and_responses_are_not_answered_as_lookups() {
        assert_eq!(names().answer(&[0; 5]), None);
        let mut response = query("nas.home.i3t", TYPE_A);
        response[2] |= 0x80;
        assert_eq!(names().answer(&response), None, "别人的应答不回");
        let truncated = &query("nas.home.i3t", TYPE_A)[..20];
        assert_eq!(code(&names().answer(truncated).unwrap()), FORMERR);
        let mut notify = query("nas.home.i3t", TYPE_A);
        notify[2] |= 4 << 3;
        assert_eq!(code(&names().answer(&notify).unwrap()), NOTIMP);
    }

    #[test]
    fn lookups_need_the_full_name() {
        assert_eq!(names().lookup("nas.home.i3t."), Some([10, 66, 0, 5].into()));
        assert_eq!(names().lookup("laptop.HOME.i3t"), Some([10, 66, 0, 2].into()));
        assert_eq!(names().lookup("nas"), None, "短名字可能是局域网里的另一台机器");
    }

    #[test]
    fn the_hosts_block_lists_full_names_and_replaces_only_itself() {
        let block = hosts_block(&names());
        assert_eq!(block, format!("{HOSTS_BEGIN}\n10.66.0.2\tlaptop.home.i3t\n10.66.0.5\tnas.home.i3t\n{HOSTS_END}\n"));
        let original = "127.0.0.1 localhost\n::1 localhost\n";
        let first = replace_hosts_block(original, &block);
        assert_eq!(first, format!("{original}{block}"));
        let changed = hosts_block(&Names::new("home.i3t", [("nas".to_owned(), [10, 66, 0, 9].into())]));
        let with_more = format!("{first}192.168.1.1 router\n");
        let second = replace_hosts_block(&with_more, &changed);
        assert_eq!(second, format!("{original}{changed}192.168.1.1 router\n"), "只换那一段，后面别人的行留着");
        assert_eq!(replace_hosts_block(&second, &changed), second, "再写一次不变");
        assert_eq!(replace_hosts_block("127.0.0.1 localhost", &block), format!("127.0.0.1 localhost\n{block}"), "最后一行没有换行符");
    }

    #[test]
    fn hosts_block_drops_entries_with_control_or_whitespace_characters() {
        let poisoned = Names::new(
            "home.i3t",
            [
                ("nas".to_owned(), [10, 66, 0, 5].into()),
                ("evil\n127.0.0.1 bank.example".to_owned(), [10, 66, 0, 6].into()),
                ("bad name".to_owned(), [10, 66, 0, 7].into()),
            ],
        );
        let block = hosts_block(&poisoned);
        assert_eq!(block, format!("{HOSTS_BEGIN}\n10.66.0.5\tnas.home.i3t\n{HOSTS_END}\n"));

        let bad_domain = Names::new("home.i3t\n127.0.0.1 evil.com", [("nas".to_owned(), [10, 66, 0, 5].into())]);
        assert_eq!(hosts_block(&bad_domain), format!("{HOSTS_BEGIN}\n{HOSTS_END}\n"));
    }

    #[test]
    fn removing_the_hosts_block_leaves_every_other_byte_as_it_was() {
        let block = hosts_block(&names());
        // 别人的行：Windows 的换行、行尾的空白、没有结尾换行符的最后一行。
        let (before, after) = ("127.0.0.1 localhost\r\n# keep  \n\n", "192.168.1.1 router\t# no newline");
        let hosts = format!("{before}{block}{after}");
        assert_eq!(remove_hosts_block(&hosts).as_deref(), Some(format!("{before}{after}").as_str()));
        assert_eq!(remove_hosts_block(before), None, "没有那一段：不动");
        let unfinished = format!("{before}{HOSTS_BEGIN}\n10.66.0.5\tnas.home.i3t\n");
        assert_eq!(remove_hosts_block(&unfinished), None, "没有结尾标记：不知道到哪里为止，不动");
        let replaced = replace_hosts_block(&hosts, &block);
        assert_eq!(replaced, hosts, "换成同样的一段：一个字节也不变");
    }
}
