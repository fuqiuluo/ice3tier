//! 命令行程序说哪种语言。
//!
//! 三个程序（`i3t`、`i3tctl`、`i3t-controller`）在终端上写给人看的东西都有简体中文和英文两份，跟着系统的语言走：
//!
//! 1. 环境变量 `I3T_LANG`（`zh-CN` 或 `en`）说了算；
//! 2. 否则按惯常的顺序看 `LC_ALL`、`LC_MESSAGES`、`LANG`，第一个不是空的那个；
//! 3. 都没有时问操作系统：Windows 上是用户的区域设置（`GetUserDefaultLocaleName`），macOS 上是
//!    `defaults read -g AppleLocale`（终端里通常设着 `LANG`，走不到这一步）；
//! 4. 以 `zh` 开头的是简体中文，别的一律是英文。
//!
//! 每个程序有自己的文字目录：一个结构体，两种语言各一份，少写一项编译不过。这个 crate 只管挑语言、按语言写数和时间
//! （[`Lang`] 上的方法）、对齐表格（[`table`]），以及命令行解析库自己的那部分文字（[`cli`]）。
//!
//! 日志（`tracing`）不在这里：它们照旧是中文，给维护的人看。

pub mod cli;
pub mod codes;
mod format;
pub mod table;

use std::sync::OnceLock;

pub use format::{NONE, optional};

/// 一种语言。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    /// 简体中文。
    ZhCn,
    English,
}

/// 指定语言的环境变量。
pub const LANG_ENV: &str = "I3T_LANG";

/// 系统的语言设置，按这个顺序看第一个不是空的。
const LOCALE_ENV: [&str; 3] = ["LC_ALL", "LC_MESSAGES", "LANG"];

impl Lang {
    /// 全部语言，测试逐个检查用。
    pub const ALL: [Self; 2] = [Self::ZhCn, Self::English];

    /// BCP 47 的写法，和 WebUI 用的一样。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZhCn => "zh-CN",
            Self::English => "en",
        }
    }

    /// 一个语言标记（`zh_CN.UTF-8`、`zh-Hans`、`en_US`、`C`……）对应的语言：以 `zh` 开头的是简体中文，别的是英文。
    #[must_use]
    pub fn from_tag(tag: &str) -> Self {
        if tag.trim().get(..2).is_some_and(|prefix| prefix.eq_ignore_ascii_case("zh")) { Self::ZhCn } else { Self::English }
    }

    /// 按环境变量和系统的设置挑语言，规矩见模块文档。
    #[must_use]
    pub fn detect() -> Self {
        Self::detect_from(|name| std::env::var(name).ok(), system_locale)
    }

    /// [`detect`](Self::detect) 的全部逻辑，环境变量和系统的设置从参数来，测试用。
    fn detect_from(var: impl Fn(&str) -> Option<String>, system: impl FnOnce() -> Option<String>) -> Self {
        let set = |name: &str| var(name).filter(|value| !value.trim().is_empty());
        set(LANG_ENV)
            .or_else(|| LOCALE_ENV.iter().find_map(|name| set(name)))
            .or_else(system)
            .map_or(Self::English, |tag| Self::from_tag(&tag))
    }
}

static CURRENT: OnceLock<Lang> = OnceLock::new();

/// 这个进程说的语言。程序启动时用 [`set`] 定下来；没有定的话第一次问的时候按 [`Lang::detect`] 挑。
pub fn current() -> Lang {
    *CURRENT.get_or_init(Lang::detect)
}

/// 定下这个进程说的语言。只有第一次有效：之后再定什么都不变，返回已经定下的那一种。
pub fn set(lang: Lang) -> Lang {
    *CURRENT.get_or_init(|| lang)
}

/// 操作系统的语言设置；无法获取时返回 `None`。
#[cfg(windows)]
fn system_locale() -> Option<String> {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    // Windows 的头文件里 LOCALE_NAME_MAX_LENGTH 是 85，含结尾的 0。
    let mut buffer = [0u16; 85];
    let capacity = i32::try_from(buffer.len()).expect("85 放得进 i32");
    // SAFETY: 传入一块可写缓冲区及其长度（UTF-16 码元数）。函数最多写入该长度并返回写入的码元数（含结尾的 0），
    // 失败时返回 0。缓冲区在调用期间保持有效，调用后仅读取返回值指示的有效区间。
    let written = unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), capacity) };
    let len = usize::try_from(written).ok()?.checked_sub(1)?;
    String::from_utf16(buffer.get(..len)?).ok()
}

/// 操作系统的语言设置；无法获取时返回 `None`。
///
/// macOS 的终端一般设着 `LANG`，走到这里的多是从图形界面或者 launchd 启动的。读系统的偏好不想为此引一个绑定库，
/// 所以问一下 `defaults`：只在环境变量都没有时问，一次，十来毫秒。
#[cfg(target_os = "macos")]
fn system_locale() -> Option<String> {
    let output = std::process::Command::new("defaults").args(["read", "-g", "AppleLocale"]).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned()).filter(|tag| !tag.is_empty())
}

/// 操作系统的语言设置；别的系统都看环境变量，这里没有别的来源。
#[cfg(not(any(windows, target_os = "macos")))]
const fn system_locale() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn detect(vars: &[(&str, &str)], system: Option<&str>) -> Lang {
        let vars: HashMap<String, String> = vars.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect();
        Lang::detect_from(|name| vars.get(name).cloned(), || system.map(str::to_owned))
    }

    #[test]
    fn the_override_wins_over_the_locale() {
        assert_eq!(detect(&[("I3T_LANG", "en"), ("LC_ALL", "zh_CN.UTF-8")], None), Lang::English);
        assert_eq!(detect(&[("I3T_LANG", "zh-CN"), ("LANG", "en_US.UTF-8")], None), Lang::ZhCn);
        assert_eq!(detect(&[("I3T_LANG", "fr"), ("LANG", "zh_CN.UTF-8")], None), Lang::English, "不认识的语言写英文");
        assert_eq!(detect(&[("I3T_LANG", " "), ("LANG", "zh_CN.UTF-8")], None), Lang::ZhCn, "空的不算写了");
    }

    #[test]
    fn the_locale_variables_are_read_in_the_usual_order() {
        let all = [("LC_ALL", "zh_CN.UTF-8"), ("LC_MESSAGES", "en_US.UTF-8"), ("LANG", "en_US.UTF-8")];
        assert_eq!(detect(&all, None), Lang::ZhCn, "LC_ALL 在最前面");
        assert_eq!(detect(&[("LC_MESSAGES", "zh_TW.UTF-8"), ("LANG", "en_US.UTF-8")], None), Lang::ZhCn);
        assert_eq!(detect(&[("LC_MESSAGES", "en_GB.UTF-8"), ("LANG", "zh_CN.UTF-8")], None), Lang::English);
        assert_eq!(detect(&[("LC_ALL", ""), ("LANG", "zh_CN.GB18030")], None), Lang::ZhCn, "空的跳过");
        assert_eq!(detect(&[("LANG", "C")], Some("zh-CN")), Lang::English, "C 也是写了，不再问系统");
        assert_eq!(detect(&[("LANG", "POSIX")], None), Lang::English);
    }

    #[test]
    fn without_variables_the_system_is_asked_and_english_is_the_fallback() {
        assert_eq!(detect(&[], Some("zh-CN")), Lang::ZhCn);
        assert_eq!(detect(&[], Some("zh_Hans_CN")), Lang::ZhCn);
        assert_eq!(detect(&[], Some("en-US")), Lang::English);
        assert_eq!(detect(&[], None), Lang::English);
    }

    #[test]
    fn tags_starting_with_zh_are_chinese() {
        for tag in ["zh", "zh-CN", "ZH_cn", "zh_SG.UTF-8", "zh-Hant"] {
            assert_eq!(Lang::from_tag(tag), Lang::ZhCn, "{tag}");
        }
        for tag in ["", "z", "en", "de_DE", "C.UTF-8", "ja_JP"] {
            assert_eq!(Lang::from_tag(tag), Lang::English, "{tag}");
        }
        assert_eq!(Lang::ALL.map(Lang::code), ["zh-CN", "en"]);
    }
}
