//! 命令行解析库（clap）自己的那部分文字：帮助里的"用法""选项""命令"这些标题、`--help` 和 `--version` 的说明、
//! 默认值和环境变量的写法，以及解析出错时的那几句话。
//!
//! 各个程序先把自己的说明（命令、参数、值的名字）写到 `Command` 上，再交给 [`localize`] 换掉剩下的英文；
//! 使用 [`parse`] 解析命令行，出错时按目标语言输出提示。clap 无法识别的极少数错误（见 [`render_error`]）沿用其默认英文提示。

use std::ffi::OsString;
use std::fmt::Write as _;

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Arg, ArgAction, Command, FromArgMatches};

use crate::Lang;

/// 命令行解析库的文字，一种语言一份。
#[derive(Debug)]
pub struct ClapTexts {
    /// 帮助开头那一行的标题，带冒号：`用法:`、`Usage:`。clap 给小节标题加的是半角冒号（`命令:`），中文也跟着用半角，免得混着。
    pub usage: &'static str,
    /// 没有选项名的参数那一节的标题（clap 自己会在后面加冒号）。
    pub arguments: &'static str,
    pub options: &'static str,
    /// 每个子命令都能用的选项（`--url` 这类）那一节的标题。
    pub global_options: &'static str,
    pub commands: &'static str,
    /// 用法里代表子命令的占位：`命令`、`COMMAND`。
    pub command: &'static str,
    /// 用法里代表选项的占位：`[选项]`、`[OPTIONS]`。
    pub options_usage: &'static str,
    pub help: &'static str,
    pub version: &'static str,
    pub default: fn(&str) -> String,
    pub env: fn(&str) -> String,
    pub error: &'static str,
    pub unknown_argument: fn(&str) -> String,
    pub unknown_command: fn(&str) -> String,
    pub did_you_mean: fn(&str) -> String,
    pub tip: fn(&str) -> String,
    pub missing_value: fn(&str) -> String,
    pub invalid_value: fn(&str, &str) -> String,
    pub possible_values: fn(&str) -> String,
    pub missing_arguments: fn(&str) -> String,
    pub missing_command: fn(&str) -> String,
    pub conflict: fn(&str, &str) -> String,
    pub repeated: fn(&str) -> String,
    pub value_count: fn(&str) -> String,
    pub no_equals: fn(&str) -> String,
    pub not_utf8: &'static str,
    pub more: fn(&str) -> String,
}

pub static ZH: ClapTexts = ClapTexts {
    usage: "用法:",
    arguments: "参数",
    options: "选项",
    global_options: "全局选项",
    commands: "命令",
    command: "命令",
    options_usage: "[选项]",
    help: "显示帮助",
    version: "显示版本",
    default: |value| format!("默认 {value}"),
    env: |name| format!("环境变量 {name}"),
    error: "错误:",
    unknown_argument: |arg| format!("未知参数 {arg}"),
    unknown_command: |name| format!("未知命令 {name}"),
    did_you_mean: |candidate| format!("是否要输入 {candidate}？"),
    tip: |tip| format!("提示：{tip}"),
    missing_value: |arg| format!("{arg} 缺少参数值"),
    invalid_value: |arg, value| format!("{arg} 的值 {value} 无效"),
    possible_values: |values| format!("可选值：{values}"),
    missing_arguments: |args| format!("缺少 {args}"),
    missing_command: |name| format!("{name} 缺少子命令"),
    conflict: |arg, other| format!("{arg} 与 {other} 不能同时使用"),
    repeated: |arg| format!("{arg} 不能重复指定"),
    value_count: |arg| format!("{arg} 的参数值数量不正确"),
    no_equals: |arg| format!("{arg} 需使用等号指定值：{arg}=…"),
    not_utf8: "参数不是有效的 UTF-8",
    more: |help| format!("更多信息见 {help}"),
};

pub static EN: ClapTexts = ClapTexts {
    usage: "Usage:",
    arguments: "Arguments",
    options: "Options",
    global_options: "Global options",
    commands: "Commands",
    command: "COMMAND",
    options_usage: "[OPTIONS]",
    help: "Show help",
    version: "Show version",
    default: |value| format!("default: {value}"),
    env: |name| format!("env: {name}"),
    error: "error:",
    unknown_argument: |arg| format!("unexpected argument '{arg}'"),
    unknown_command: |name| format!("unknown command '{name}'"),
    did_you_mean: |candidate| format!("did you mean '{candidate}'?"),
    tip: |tip| format!("tip: {tip}"),
    missing_value: |arg| format!("'{arg}' needs a value"),
    invalid_value: |arg, value| format!("invalid value '{value}' for '{arg}'"),
    possible_values: |values| format!("possible values: {values}"),
    missing_arguments: |args| format!("missing {args}"),
    missing_command: |name| format!("'{name}' needs a subcommand"),
    conflict: |arg, other| format!("'{arg}' cannot be used with '{other}'"),
    repeated: |arg| format!("'{arg}' can be given only once"),
    value_count: |arg| format!("wrong number of values for '{arg}'"),
    no_equals: |arg| format!("'{arg}' takes its value after an equals sign: {arg}=…"),
    not_utf8: "an argument is not valid UTF-8",
    more: |help| format!("For more, see '{help}'."),
};

impl Lang {
    /// 命令行解析库在这种语言里的文字。
    #[must_use]
    pub const fn clap(self) -> &'static ClapTexts {
        match self {
            Self::ZhCn => &ZH,
            Self::English => &EN,
        }
    }
}

/// 帮助和版本的开关的名字。各个程序用 clap 自动生成的那两个开关的话，说明是英文的，所以换成自己加的。
const HELP: &str = "help";
const VERSION: &str = "version";

/// 把 `command` 和它的全部子命令里 clap 自己的文字换成 `lang`：标题、用法、`--help`、`--version`、默认值和环境变量的写法。
///
/// 调用方先写好自己的说明（命令和参数的 `about`、`help`，值的名字）。参数的默认值、环境变量由这里接在说明后面，
/// 可选的值（`ValueEnum`）不由 clap 列出：调用方在说明里自己写。`help` 子命令去掉了，[`rewrite_help`] 把它改写成 `--help`。
#[must_use]
pub fn localize(command: Command, lang: Lang) -> Command {
    let name = command.get_name().to_owned();
    let has_version = command.get_version().is_some();
    let command = localize_at(command, lang, &name);
    if has_version {
        let texts = lang.clap();
        command
            .disable_version_flag(true)
            .arg(Arg::new(VERSION).short('V').long("version").action(ArgAction::Version).help(texts.version).help_heading(texts.options))
    } else {
        command
    }
}

fn localize_at(command: Command, lang: Lang, path: &str) -> Command {
    let texts = lang.clap();
    let mut position = 0;
    let mut command = command
        .disable_help_flag(true)
        .disable_help_subcommand(true)
        .arg(Arg::new(HELP).short('h').long("help").action(ArgAction::Help).help(texts.help))
        .mut_args(|arg| {
            let arg = localize_arg(arg, texts);
            // 位置参数在帮助里按它们在命令行上的顺序列：clap 默认按名字的字母序排它们，`<源> <目的>` 会列成先目的后源。
            if arg.is_positional() {
                position += 1;
                arg.display_order(position)
            } else {
                arg
            }
        })
        .subcommand_help_heading(texts.commands)
        .subcommand_value_name(texts.command)
        .help_template(format!("{{before-help}}{{about-with-newline}}\n{} {{usage}}\n\n{{all-args}}{{after-help}}", texts.usage));
    let usage = usage(&command, path, texts);
    command = command.override_usage(usage);
    let names: Vec<String> = command.get_subcommands().map(|sub| sub.get_name().to_owned()).collect();
    for name in names {
        let sub_path = format!("{path} {name}");
        command = command.mut_subcommand(&name, |sub| localize_at(sub, lang, &sub_path));
    }
    command
}

fn localize_arg(arg: Arg, texts: &ClapTexts) -> Arg {
    let heading = if arg.is_positional() {
        texts.arguments
    } else if arg.is_global_set() {
        texts.global_options
    } else {
        texts.options
    };
    if !arg.get_action().takes_values() {
        return arg.help_heading(heading);
    }
    let mut notes = Vec::new();
    let defaults: Vec<String> = arg.get_default_values().iter().map(|value| value.to_string_lossy().into_owned()).collect();
    if !arg.is_hide_default_value_set() && defaults.iter().any(|value| !value.is_empty()) {
        notes.push((texts.default)(&defaults.join(",")));
    }
    if let Some(name) = arg.get_env().filter(|_| !arg.is_hide_env_set()) {
        notes.push((texts.env)(&name.to_string_lossy()));
    }
    let help = arg.get_help().map(ToString::to_string).unwrap_or_default();
    let help = match (help.is_empty(), notes.is_empty()) {
        (_, true) => help,
        (true, false) => format!("[{}]", notes.join("; ")),
        (false, false) => format!("{help} [{}]", notes.join("; ")),
    };
    arg.help(help).help_heading(heading).hide_default_value(true).hide_env(true).hide_possible_values(true)
}

/// 帮助和报错里的用法：`i3tctl node rename [选项] <节点> <名字>`。clap 自己生成的用法里有英文的占位，所以自己写。
fn usage(command: &Command, path: &str, texts: &ClapTexts) -> String {
    let mut parts = vec![path.to_owned(), texts.options_usage.to_owned()];
    let value_name = |arg: &Arg| {
        arg.get_value_names().and_then(|names| names.first()).map_or_else(|| arg.get_id().as_str().to_uppercase(), ToString::to_string)
    };
    for arg in command.get_arguments().filter(|arg| !arg.is_positional() && arg.is_required_set()) {
        if let Some(long) = arg.get_long() {
            parts.push(format!("--{long} <{}>", value_name(arg)));
        }
    }
    for arg in command.get_positionals().filter(|arg| !arg.is_hide_set()) {
        let many = if arg.get_num_args().is_some_and(|count| count.max_values() > 1) { "..." } else { "" };
        let name = value_name(arg);
        parts.push(if arg.is_required_set() { format!("<{name}>{many}") } else { format!("[{name}]{many}") });
    }
    if command.has_subcommands() {
        let name = texts.command;
        parts.push(if command.is_subcommand_required_set() { format!("<{name}>") } else { format!("[{name}]") });
    }
    parts.join(" ")
}

/// `程序 help a b` 改写成 `程序 a b --help`：help 子命令是 clap 生成的，它的说明是英文的，所以去掉了，这样写照样能用。
#[must_use]
pub fn rewrite_help(mut args: Vec<OsString>) -> Vec<OsString> {
    if args.get(1).is_some_and(|arg| arg == "help") {
        args.remove(1);
        args.push(OsString::from("--help"));
    }
    args
}

/// 解析这个进程的命令行：改写 `help`，按 `lang` 写帮助和报错。要显示帮助或版本、或者命令行有错时，写出来之后退出进程。
pub fn parse<T: FromArgMatches>(command: Command, lang: Lang) -> T {
    try_parse_from(command, lang, std::env::args_os()).unwrap_or_else(|error| exit(&error, lang))
}

/// [`parse`] 去掉退出的那一步，测试用。
///
/// # Errors
///
/// 命令行不对，或者要显示帮助、版本（clap 的约定：这两种也是"错误"）。
pub fn try_parse_from<T: FromArgMatches>(command: Command, lang: Lang, args: impl IntoIterator<Item = OsString>) -> Result<T, clap::Error> {
    let matches = localize(command, lang).try_get_matches_from(rewrite_help(args.into_iter().collect()))?;
    T::from_arg_matches(&matches)
}

/// 把一个解析的结果写出来并退出：帮助和版本写到标准输出，别的写到标准错误。
pub fn exit(error: &clap::Error, lang: Lang) -> ! {
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => error.exit(),
        _ => {
            eprint!("{}", render_error(error, lang));
            std::process::exit(error.exit_code());
        }
    }
}

/// 一个命令行解析的错误写成 `lang` 的样子：哪里不对、怎么写才对、用法，和去哪里看更多。
///
/// clap 提供上下文详情（参数名、参数值、可选值）的错误均按目标语言输出；无此类详情的极少数错误（如 I/O、格式化错误等与命令行无关的错误）
/// 则沿用 clap 默认英文输出。
#[must_use]
pub fn render_error(error: &clap::Error, lang: Lang) -> String {
    let texts = lang.clap();
    let text = |kind| match error.get(kind) {
        Some(ContextValue::String(value)) => Some(value.clone()),
        Some(ContextValue::Strings(values)) => Some(lang.list(values)),
        Some(ContextValue::StyledStr(value)) => Some(value.to_string()),
        Some(ContextValue::StyledStrs(values)) => Some(lang.list(values)),
        Some(ContextValue::Number(value)) => Some(value.to_string()),
        Some(ContextValue::Bool(value)) => Some(value.to_string()),
        Some(ContextValue::None | _) | None => None,
    };
    let arg = text(ContextKind::InvalidArg).unwrap_or_default();
    let value = text(ContextKind::InvalidValue).unwrap_or_default();
    let said = match error.kind() {
        ErrorKind::UnknownArgument => Some((texts.unknown_argument)(&arg)),
        ErrorKind::InvalidSubcommand => text(ContextKind::InvalidSubcommand).map(|name| (texts.unknown_command)(&name)),
        ErrorKind::InvalidValue if value.is_empty() => Some((texts.missing_value)(&arg)),
        ErrorKind::InvalidValue => {
            let mut said = (texts.invalid_value)(&arg, &value);
            if let Some(values) = text(ContextKind::ValidValue) {
                let _ = write!(said, "\n  {}", (texts.possible_values)(&values));
            }
            Some(said)
        }
        ErrorKind::ValueValidation => {
            let said = (texts.invalid_value)(&arg, &value);
            Some(match std::error::Error::source(error) {
                Some(source) => lang.labelled(&said, &source.to_string()),
                None => said,
            })
        }
        ErrorKind::MissingRequiredArgument => text(ContextKind::InvalidArg).map(|args| (texts.missing_arguments)(&args)),
        ErrorKind::MissingSubcommand => text(ContextKind::InvalidSubcommand).map(|name| (texts.missing_command)(&name)),
        ErrorKind::ArgumentConflict => match (text(ContextKind::InvalidArg), text(ContextKind::PriorArg)) {
            (Some(arg), Some(prior)) if arg == prior => Some((texts.repeated)(&arg)),
            (Some(arg), Some(prior)) => Some((texts.conflict)(&arg, &prior)),
            _ => None,
        },
        ErrorKind::TooManyValues | ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => Some((texts.value_count)(&arg)),
        ErrorKind::NoEquals => Some((texts.no_equals)(&arg)),
        ErrorKind::InvalidUtf8 => Some(texts.not_utf8.to_owned()),
        // 和命令行本身无关的几种（I/O、格式化），以及以后的版本新加的：照 clap 自己的写法。
        _ => None,
    };
    let Some(said) = said else { return error.render().to_string() };
    let mut out = format!("{} {said}\n", texts.error);
    for kind in [ContextKind::SuggestedArg, ContextKind::SuggestedSubcommand, ContextKind::SuggestedValue] {
        if let Some(candidate) = text(kind) {
            let _ = writeln!(out, "\n  {}", (texts.tip)(&(texts.did_you_mean)(&candidate)));
        }
    }
    if let Some(usage) = text(ContextKind::Usage) {
        let usage = usage.trim();
        let usage = usage.strip_prefix(texts.usage).or_else(|| usage.strip_prefix("Usage:")).unwrap_or(usage).trim();
        let _ = writeln!(out, "\n{} {usage}", texts.usage);
        let command = usage.split(" [").next().unwrap_or(usage);
        let _ = writeln!(out, "\n{}", (texts.more)(&format!("{command} --help")));
    }
    out
}

/// 一段文字里有没有汉字。测试用来检查英文的文字里没有漏掉的中文。
#[must_use]
pub fn has_chinese(text: &str) -> bool {
    text.chars().any(|ch| matches!(ch, '\u{3000}'..='\u{303f}' | '\u{3400}'..='\u{9fff}' | '\u{ff00}'..='\u{ffef}'))
}

/// 英文里一个数后面直接跟着复数名词、而这个数是 1 的地方（`1 nodes`）：返回那两个词。测试拿 1 去调文字目录里带数的函数，
/// 用它检查英文没有写成这个样子；要么用中性的写法（`nodes: 1`、`nodes 1`），要么分单复数。
///
/// 仅匹配独立的 `1`（前面可带括号），不匹配 `v1`、`#1`、`1.5`、`1/2` 中的 `1`；后续词须全为字母且以 `s` 结尾，
/// 单位 `ms` 和几个以 `s` 结尾的动词（`1 is …`）不算。
#[must_use]
pub fn plural_after_one(text: &str) -> Option<String> {
    const NOT_PLURAL: [&str; 5] = ["ms", "is", "was", "has", "does"];
    let words: Vec<&str> = text.split_whitespace().collect();
    words.windows(2).find_map(|pair| {
        let number = pair[0].trim_start_matches(['(', '[', '（']);
        let noun = pair[1].trim_end_matches(|ch: char| !ch.is_ascii_alphabetic());
        let plural =
            noun.len() > 1 && noun.ends_with('s') && noun.chars().all(|ch| ch.is_ascii_alphabetic()) && !NOT_PLURAL.contains(&noun);
        (number == "1" && plural).then(|| format!("{} {}", pair[0], pair[1]))
    })
}

/// clap 自己的英文在帮助里可能留下的词。测试用来检查中文的帮助里没有漏掉它们。
pub const CLAP_ENGLISH: [&str; 10] =
    ["Usage", "Options", "Arguments", "Commands", "Print help", "Print version", "[default:", "[env:", "possible values", "Global"];

/// 一个命令和它的全部子命令的帮助，按语言写好的，测试用：每一条是（命令的路径，帮助的全文）。
#[must_use]
pub fn all_help(command: Command, lang: Lang) -> Vec<(String, String)> {
    fn walk(command: &mut Command, path: &str, out: &mut Vec<(String, String)>) {
        out.push((path.to_owned(), command.render_long_help().to_string()));
        let names: Vec<String> = command.get_subcommands().map(|sub| sub.get_name().to_owned()).collect();
        for name in names {
            if let Some(sub) = command.find_subcommand_mut(&name) {
                walk(sub, &format!("{path} {name}"), out);
            }
        }
    }
    let mut command = localize(command, lang);
    command.build();
    let mut out = Vec::new();
    let path = command.get_name().to_owned();
    walk(&mut command, &path, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use clap::{Parser, Subcommand};

    use super::*;

    #[test]
    fn a_plural_noun_after_a_lone_one_is_caught_and_neutral_forms_pass() {
        assert_eq!(plural_after_one("v3, 1 peers, 0 relays").as_deref(), Some("1 peers,"));
        assert_eq!(plural_after_one("Lowest cost of (1 candidates)").as_deref(), Some("(1 candidates)"));
        for fine in [
            "peers 1, relays 0",
            "nodes: 1",
            "1 peer",
            "1 ms",
            "#1 deleted",
            "v1 is out",
            "1.5 seconds",
            "1/1 pairs",
            "1 B",
            "table 1 is used",
        ] {
            assert_eq!(plural_after_one(fine), None, "{fine}");
        }
    }

    // 一个小的命令行，覆盖各种参数的写法。说明不用文档注释写：那会成为它的中文说明。
    #[derive(Parser, Debug)]
    #[command(name = "demo", version = "1.2.3")]
    struct Demo {
        #[arg(long, env = "DEMO_URL", default_value = "http://x", global = true)]
        url: String,
        #[command(subcommand)]
        command: Sub,
    }

    #[derive(Subcommand, Debug)]
    enum Sub {
        Rename {
            node: String,
            name: String,
            #[arg(long)]
            force: bool,
        },
        Set {
            #[arg(long, value_parser = ["on", "off"])]
            mode: String,
            #[arg(long, value_parser = |text: &str| text.parse::<u8>().map_err(|_| "要写 0 到 255 的数".to_owned()))]
            level: Option<u8>,
        },
    }

    fn command(lang: Lang) -> Command {
        let about = match lang {
            Lang::ZhCn => ("改名", "节点", "名字"),
            Lang::English => ("Rename", "NODE", "NAME"),
        };
        <Demo as clap::CommandFactory>::command().mut_subcommand("rename", |sub| {
            sub.about(about.0).mut_arg("node", |arg| arg.value_name(about.1)).mut_arg("name", |arg| arg.value_name(about.2))
        })
    }

    fn parse(lang: Lang, args: &[&str]) -> Result<Demo, clap::Error> {
        try_parse_from(command(lang), lang, args.iter().map(OsString::from))
    }

    #[test]
    fn the_help_has_no_english_left_in_chinese_and_no_chinese_in_english() {
        for (path, help) in all_help(command(Lang::ZhCn), Lang::ZhCn) {
            for english in CLAP_ENGLISH {
                assert!(!help.contains(english), "{path} 的中文帮助里有 {english}：\n{help}");
            }
            assert!(help.contains("用法: ") && help.contains("显示帮助"), "{path}：\n{help}");
        }
        for (path, help) in all_help(command(Lang::English), Lang::English) {
            assert!(!has_chinese(&help), "{path} 的英文帮助里有中文：\n{help}");
        }
        let help = all_help(command(Lang::ZhCn), Lang::ZhCn);
        let rename = &help.iter().find(|(path, _)| path == "demo rename").unwrap().1;
        assert!(rename.contains("用法: demo rename [选项] <节点> <名字>"), "{rename}");
        assert!(help[0].1.contains("默认 http://x") && help[0].1.contains("环境变量 DEMO_URL"), "{}", help[0].1);
    }

    #[test]
    fn errors_are_written_in_the_language_with_usage_and_where_to_look() {
        let error = parse(Lang::ZhCn, &["demo", "rename", "a"]).unwrap_err();
        let text = render_error(&error, Lang::ZhCn);
        assert!(text.starts_with("错误: 缺少 <名字>") && text.contains("用法: demo rename"), "{text}");
        assert!(text.contains("更多信息见 demo rename --help"), "{text}");

        let error = parse(Lang::English, &["demo", "set", "--mode", "maybe"]).unwrap_err();
        let text = render_error(&error, Lang::English);
        assert!(text.contains("invalid value 'maybe' for '--mode") && text.contains("possible values: on, off"), "{text}");

        let error = parse(Lang::ZhCn, &["demo", "set", "--mode", "on", "--level", "x"]).unwrap_err();
        let text = render_error(&error, Lang::ZhCn);
        assert!(text.contains("的值 x 无效") && text.contains("要写 0 到 255 的数"), "{text}");

        let error = parse(Lang::ZhCn, &["demo", "renam"]).unwrap_err();
        let text = render_error(&error, Lang::ZhCn);
        assert!(text.contains("未知命令 renam") && text.contains("是否要输入 rename？"), "{text}");
        assert!(!has_chinese(&render_error(&parse(Lang::English, &["demo", "renam"]).unwrap_err(), Lang::English)));
        for lang in Lang::ALL {
            for args in [&["demo", "--bogus"][..], &["demo"], &["demo", "rename", "a", "b", "c"]] {
                let text = render_error(&parse(lang, args).unwrap_err(), lang);
                assert_eq!(has_chinese(&text), lang == Lang::ZhCn, "{args:?}：{text}");
            }
        }
    }

    #[test]
    fn help_as_a_command_shows_the_help_of_what_follows() {
        let error = parse(Lang::English, &["demo", "help", "rename"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        assert!(error.to_string().contains("Rename"), "{error}");
        assert_eq!(parse(Lang::English, &["demo", "--version"]).unwrap_err().kind(), ErrorKind::DisplayVersion);
        let parsed = parse(Lang::ZhCn, &["demo", "rename", "a", "b", "--url", "http://y"]).unwrap();
        assert!(matches!(parsed.command, Sub::Rename { .. }) && parsed.url == "http://y");
    }
}
