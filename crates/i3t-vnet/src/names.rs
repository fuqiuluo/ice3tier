//! 名字：`<节点>.<网络的域名>` 解析成节点的虚拟 IP。
//!
//! 两种用法，答的都是节点现在看到的网络（netmap 里本节点能访问的对端，加上自己）：
//!
//! - **名字服务**（[`Names::answer`]）：一个只认网络自己的域名的 DNS 应答者，听在本节点虚拟 IP 的 53 端口上，
//!   systemd-resolved 只把这个域名下的查询发给它。域名之外的名字一律回 REFUSED：它不是这台机器的解析器。
//! - **hosts 文件**（[`hosts_block`]、[`replace_hosts_block`]、[`remove_hosts_block`]）：没有 systemd-resolved 的机器用
//!   `i3t hosts` 打印或者写进 `/etc/hosts` 的一段，前后有标记，再写一次只换这一段，`i3t hosts --remove` 只去掉这一段。
//!
//! 只有全名（`nas.home.i3t`）；短名字（`nas`）可能是局域网里的另一台机器，不去抢。

use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::Ipv4Addr;
use std::ops::Range;

/// 回答里的 TTL。名字可以改、对端可以增减，所以不长。
const TTL_SECS: u32 = 30;

/// DNS 的记录类型和类。
const TYPE_A: u16 = 1;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

/// 应答码（RFC 1035 §4.1.1）。
const NOERROR: u8 = 0;
const FORMERR: u8 = 1;
const NXDOMAIN: u8 = 3;
const NOTIMP: u8 = 4;
const REFUSED: u8 = 5;

/// 一个网络里的名字：域名，和域名下每个节点的地址。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Names {
    /// 小写，没有结尾的点。
    domain: String,
    /// 节点名（小写）到虚拟 IP。
    nodes: BTreeMap<String, Ipv4Addr>,
}

impl Names {
    /// `domain` 是网络的域名（`home.i3t`），`nodes` 是（节点名，虚拟 IP）。名字不分大小写。
    #[must_use]
    pub fn new(domain: &str, nodes: impl IntoIterator<Item = (String, Ipv4Addr)>) -> Self {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        Self { domain, nodes: nodes.into_iter().map(|(name, ip)| (name.to_ascii_lowercase(), ip)).collect() }
    }

    /// 有几个名字。
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// 全名（`nas.home.i3t`，可以带结尾的点，不分大小写）对应的地址。不是这个网络里的名字时是 `None`。
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<Ipv4Addr> {
        let short = self.short(name)?;
        self.nodes.get(&short).copied()
    }

    /// 全名里节点名那一段。名字不在这个域名下，或者节点名不是一段（`a.b.home.i3t`）时是 `None`。
    fn short(&self, name: &str) -> Option<String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let short = name.strip_suffix(&self.domain)?.strip_suffix('.')?;
        (!short.is_empty() && !short.contains('.')).then(|| short.to_owned())
    }

    /// 名字在这个域名下（包括域名本身）。
    fn covers(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        name == self.domain || name.strip_suffix(&self.domain).is_some_and(|rest| rest.ends_with('.'))
    }

    /// 回答一个 DNS 查询（UDP 报文的内容）。读不懂、不像一个查询的报文返回 `None`：不回答，像没收到一样。
    ///
    /// - 网络的域名下、有这个节点：A 记录；问别的类型（AAAA 之类）时没有记录（NOERROR，空的回答）。
    /// - 网络的域名下、没有这个节点：NXDOMAIN。
    /// - 别的名字：REFUSED。
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
        // 域名本身存在（只是没有地址）；域名下别的名字都是没有这个节点。
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
    /// 问题部分在报文里占多少字节。
    len: usize,
}

/// 读问题部分：名字（一串标签，问题里不会有压缩指针）、类型、类。
fn question(bytes: &[u8]) -> Option<Question> {
    let mut at = 0;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = usize::from(*bytes.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        // 0xc0 开头的是压缩指针，问题里不该出现；0x40、0x80 是没有定义的标签类型。
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

/// 写应答：编号、操作码和"要求递归"照抄，标上"是应答""权威"，不说"可以递归"。`question` 原样带回去。
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
        // 名字用指针指回问题里的那个（偏移 12）。
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL_SECS.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&address.octets());
    }
    out
}

/// `/etc/hosts` 里那一段的开头和结尾。
pub const HOSTS_BEGIN: &str = "# BEGIN ice3tier (i3t hosts)";
pub const HOSTS_END: &str = "# END ice3tier";

/// `/etc/hosts` 里的一段名字必须只含合法主机名字符，防止异常或被篡改的 `netmap.json` 注入换行、空白或注释。
fn is_safe_hosts_label(label: &str) -> bool {
    !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_safe_hosts_domain(domain: &str) -> bool {
    !domain.is_empty() && domain.split('.').all(is_safe_hosts_label)
}

/// `/etc/hosts` 的一段：每个节点一行，`<虚拟 IP>\t<全名>`，按名字排。前后带标记。
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

/// 上次写的那一段在 `hosts` 里占的字节：从开头标记那一行的行首，到结尾标记那一行的换行符之后。
/// 有开头没有结尾的不算：不知道它到哪里为止，就一个字也不动。
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

/// 把 `hosts`（`/etc/hosts` 原来的内容）里上次写的那一段换成 `block`；没有的话加在最后。别的字节一个也不动。
#[must_use]
pub fn replace_hosts_block(hosts: &str, block: &str) -> String {
    match hosts_block_span(hosts) {
        Some(span) => [&hosts[..span.start], block, &hosts[span.end..]].concat(),
        None if hosts.is_empty() || hosts.ends_with('\n') => [hosts, block].concat(),
        None => [hosts, "\n", block].concat(),
    }
}

/// `hosts` 里去掉上次写的那一段之后的样子，别的字节一个也不动；没有那一段时是 `None`。
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
