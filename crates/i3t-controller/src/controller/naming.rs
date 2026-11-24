//! 名字的写法。

use crate::error::Error;

const MAX_LABEL_LEN: usize = 63;
const MAX_GROUP_NAME_LEN: usize = 32;
const MAX_TITLE_LEN: usize = 64;

/// 网络和节点的名字：会出现在 `<节点>.<网络>.i3t` 里，所以按域名的一段来要求。返回小写的形式。
///
/// 不能全是数字：命令行里节点既可以用编号也可以用名字指代，全是数字的名字分不清是哪一种。
pub(super) fn label(what: &str, raw: &str) -> Result<String, Error> {
    let name = raw.trim().to_ascii_lowercase();
    let well_formed = !name.is_empty()
        && name.len() <= MAX_LABEL_LEN
        && name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !well_formed {
        return Err(Error::invalid(
            "malformed",
            format!("{what}的名字 {raw:?} 不合法：只能用字母、数字和连字符，不能以连字符开头或结尾，最长 {MAX_LABEL_LEN} 个字符"),
        ));
    }
    if name.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::invalid("all_digits", format!("{what}的名字 {raw:?} 不合法：不能全是数字")));
    }
    Ok(name)
}

/// 从节点上报的主机名中提取合法的节点名称；无法提取时返回 `None`，节点将命名为 `node-<编号>`。
///
/// 只取第一段（`nas.lan` 取 `nas`），大写转小写，名字里不能有的字符换成连字符。
/// 结果留出加序号的余地：同一个网络里重名时调用方在后面加 `-2`、`-3`。
/// `localhost` 不算名字：很多没有设过主机名的机器都叫这个。
pub(super) fn from_hostname(hostname: &str) -> Option<String> {
    let first = hostname.trim().split('.').next().unwrap_or_default().to_ascii_lowercase();
    let mapped: String = first.chars().map(|ch| if ch.is_ascii_lowercase() || ch.is_ascii_digit() { ch } else { '-' }).collect();
    let mut name = mapped.split('-').filter(|part| !part.is_empty()).collect::<Vec<_>>().join("-");
    name.truncate(MAX_LABEL_LEN - UNIQUE_SUFFIX_ROOM);
    let name = name.trim_end_matches('-');
    (name != "localhost").then(|| label("节点", name).ok()).flatten()
}

/// `name` 是不是按编号起的默认名字的写法（`node-<数字>`）。
///
/// 这个写法不能按主机名分给节点：以后编号恰好是那个数字的节点，默认名字会和它撞上。
pub(super) fn is_default_node_name(name: &str) -> bool {
    name.strip_prefix("node-").is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
}

/// 给重名的节点加序号（`-2` 起）最多占几个字符。
const UNIQUE_SUFFIX_ROOM: usize = 5;

/// 分组的名字：1 到 32 个字符，字母（任何文字的）、数字、连字符、下划线。首尾的空白去掉，大小写保留。
///
/// 字符按 Unicode 的标量值数，字母和数字按 Unicode 的属性认（`char::is_alphanumeric`），所以中文、带变音的字母都可以。
/// 允许纯数字分组名：API 请求中按分组编号引用，命令行仅在按名称未匹配到时才将其视为编号。
pub(super) fn group_name(raw: &str) -> Result<String, Error> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(Error::invalid("empty", "分组的名字不能是空的"));
    }
    if name.chars().count() > MAX_GROUP_NAME_LEN {
        return Err(Error::invalid("too_long", format!("分组的名字 {raw:?} 太长：最长 {MAX_GROUP_NAME_LEN} 个字符")));
    }
    if !name.chars().all(|ch| ch.is_alphanumeric() || ch == '-' || ch == '_') {
        return Err(Error::invalid("malformed", format!("分组的名字 {raw:?} 不合法：只能用字母、数字、连字符和下划线")));
    }
    Ok(name.to_owned())
}

/// 规则、凭据、监听器、端口转发的名字：给人看的一小段文字。`required` 为真时不能是空的。
pub(super) fn title(what: &str, raw: &str, required: bool) -> Result<String, Error> {
    let title = raw.trim();
    if required && title.is_empty() {
        return Err(Error::invalid("empty", format!("{what}的名字不能是空的")));
    }
    if title.chars().count() > MAX_TITLE_LEN || title.chars().any(char::is_control) {
        return Err(Error::invalid("malformed", format!("{what}的名字不合法：最长 {MAX_TITLE_LEN} 个字符，不能有控制字符")));
    }
    Ok(title.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_lowercased_dns_labels() {
        assert_eq!(label("节点", " NAS-01 ").unwrap(), "nas-01");
        for bad in ["", "-a", "a-", "a.b", "a b", "名字", "123", &"a".repeat(64)] {
            assert!(label("节点", bad).is_err(), "{bad}");
        }
        assert!(label("节点", &"a".repeat(63)).is_ok());
        assert!(label("节点", "7zip").is_ok());
    }

    #[test]
    fn hostnames_become_node_names_when_they_can() {
        let cases = [
            ("nas-01", Some("nas-01")),
            ("NAS-01.lan.example.com", Some("nas-01")),
            ("Bob's MacBook Pro", Some("bob-s-macbook-pro")),
            ("my_server", Some("my-server")),
            ("--edge--", Some("edge")),
            ("服务器", None),
            ("", None),
            ("  ", None),
            ("1234", None),
            ("localhost", None),
            ("localhost.localdomain", None),
        ];
        for (hostname, expected) in cases {
            assert_eq!(from_hostname(hostname).as_deref(), expected, "{hostname:?}");
        }
        let long = from_hostname(&"a".repeat(200)).unwrap();
        assert_eq!(long.len(), MAX_LABEL_LEN - UNIQUE_SUFFIX_ROOM);
        assert!(label("节点", &format!("{long}-9999")).is_ok(), "加了序号也要是合法的名字");
        assert_eq!(from_hostname(&format!("{}-b", "a".repeat(MAX_LABEL_LEN - UNIQUE_SUFFIX_ROOM - 1))).unwrap().len(), 57);
    }

    #[test]
    fn the_default_name_pattern_is_recognised() {
        assert!(is_default_node_name("node-7") && is_default_node_name("node-123"));
        assert!(
            !is_default_node_name("node-")
                && !is_default_node_name("node-7a")
                && !is_default_node_name("node")
                && !is_default_node_name("nas-7")
        );
    }

    #[test]
    fn group_names_keep_their_case_and_allow_letters_of_any_script() {
        for good in ["Servers", "home_lab", "家里", "Café-2", "2025", "a", &"字".repeat(32)] {
            assert_eq!(group_name(&format!(" {good} ")).unwrap(), good, "{good}");
        }
        let what = |raw: &str| group_name(raw).unwrap_err().what();
        assert_eq!(what("  ").as_deref(), Some("empty"));
        assert_eq!(what(&"a".repeat(33)).as_deref(), Some("too_long"));
        for bad in ["a b", "a.b", "a/b", "a\nb", "😀"] {
            assert_eq!(what(bad).as_deref(), Some("malformed"), "{bad}");
        }
    }

    #[test]
    fn titles_are_trimmed_and_bounded() {
        assert_eq!(title("规则", "  laptops → servers ", false).unwrap(), "laptops → servers");
        assert_eq!(title("规则", "", false).unwrap(), "");
        assert!(title("凭据", "  ", true).is_err());
        assert!(title("规则", "a\nb", false).is_err());
        assert!(title("规则", &"规".repeat(65), false).is_err());
    }
}
