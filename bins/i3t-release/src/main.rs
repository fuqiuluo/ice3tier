//! `i3t-release`：发布时用的工具。生成发布签名密钥，为一个发布目录生成清单并签名，核对一个发布目录。
//!
//! 发布目录是平铺的，里面的东西原样上传到 GitHub Release，镜像也照这个样子放：
//!
//! ```text
//! i3t-linux-x86_64            各个平台的节点程序，名字是 i3t-<平台>，Windows 上加 .exe
//! i3t-windows-x86_64.exe
//! i3t-windows-x86_64.zip      Windows 节点安装包（含 wintun.dll）
//! i3t-controller-linux-x86_64 controller 与命令行工具
//! i3tctl-linux-x86_64
//! …
//! manifest.json               清单：版本号，节点程序（artifacts）与其余发布产物（files）的大小和 SHA-256，修了安全问题时还有安全下限
//! manifest.json.sig           清单的签名
//! ```
//!
//! 节点自动更新只看 `artifacts`（节点程序）；安装脚本同时核对 `artifacts` 与 `files` 里的所有发布产物。
//!
//! 终端上的文字跟着系统的语言（见 `i3t_lang`，可以用 `I3T_LANG` 指定）。标准输出上 `keygen` 只有公钥那一行，给脚本接。

mod texts;

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail, ensure};
use clap::{CommandFactory, Parser, Subcommand};
use i3t_crypto::NodeKey;
use i3t_lang::Lang;
use i3t_model::update::{Artifact, MANIFEST_FILE, Manifest, NODE_PROGRAM, Platform, SIGNATURE_FILE, SignedManifest, Version};
use i3t_proto::PublicKey;
use i3t_update::{FileDigest, TrustedKeys, sign_manifest};

use crate::texts::texts;

// 帮助的文字在文字目录里（`texts`），由 `command` 按语言装上去，所以这里不写文档注释：clap 会把它们当成说明。
#[derive(Parser)]
#[command(name = "i3t-release", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    Manifest {
        #[arg(long)]
        version: Version,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "0.0.0")]
        min_controller: Version,
        #[arg(long)]
        security_floor: Option<Version>,
    },
    Verify {
        #[arg(long)]
        dir: PathBuf,
        // base64url 的字符里有 `-`，公钥可能以它开头，不能被当成另一个选项。
        #[arg(long, allow_hyphen_values = true)]
        key: Option<PublicKey>,
    },
}

/// 命令行的定义，帮助按 `lang` 写。
fn command(lang: Lang) -> clap::Command {
    let (h, v) = (&texts::texts_in(lang).help, &texts::texts_in(lang).values);
    Cli::command()
        .about(h.about)
        .mut_subcommand("keygen", |sub| sub.about(h.keygen).mut_arg("out", |arg| arg.help(h.keygen_out).value_name(v.file)))
        .mut_subcommand("manifest", |sub| {
            sub.about(h.manifest)
                .mut_arg("version", |arg| arg.help(h.manifest_version).value_name(v.version))
                .mut_arg("dir", |arg| arg.help(h.manifest_dir).value_name(v.dir))
                .mut_arg("key", |arg| arg.help(h.manifest_key).value_name(v.file))
                .mut_arg("min_controller", |arg| arg.help(h.min_controller).value_name(v.version))
                .mut_arg("security_floor", |arg| arg.help(h.security_floor).value_name(v.version))
        })
        .mut_subcommand("verify", |sub| {
            sub.about(h.verify)
                .mut_arg("dir", |arg| arg.help(h.verify_dir).value_name(v.dir))
                .mut_arg("key", |arg| arg.help(h.verify_key).value_name(v.key))
        })
}

fn main() -> ExitCode {
    let lang = i3t_lang::set(Lang::detect());
    let cli: Cli = i3t_lang::cli::parse(command(lang), lang);
    let result = match cli.command {
        Command::Keygen { out } => keygen(&out),
        Command::Manifest { version, dir, key, min_controller, security_floor } => {
            manifest(version, min_controller, security_floor, &dir, &key)
        }
        Command::Verify { dir, key } => verify(&dir, key),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("i3t-release: {}", lang.chain(error.chain()));
            ExitCode::FAILURE
        }
    }
}

fn keygen(out: &Path) -> anyhow::Result<()> {
    let t = &texts().ui;
    let shown = out.display().to_string();
    let key = NodeKey::generate().context(t.generate_key)?;
    let mut file = create_private(out).with_context(|| (t.create_key_file)(&shown))?;
    file.write_all(key.to_pem().as_bytes()).and_then(|()| file.sync_all()).with_context(|| (t.write)(&shown))?;
    // 标准输出上只有公钥，方便脚本接；给人看的话走标准错误。
    println!("{}", key.public());
    eprintln!("{}", (t.key_written)(&shown));
    Ok(())
}

/// 新建一个只有属主可读写的文件。文件已经存在时失败：签名密钥不能被不小心盖掉。
#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

// Windows 上文件的访问控制继承自所在的目录，所以要把密钥放在只有自己能进的目录里。
#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// `security_floor` 是这次发布写的安全下限；它不能比这次发布的版本新，否则这一版自己也算有安全问题。
fn manifest(version: Version, min_controller: Version, security_floor: Option<Version>, dir: &Path, key_file: &Path) -> anyhow::Result<()> {
    let t = &texts().ui;
    if let Some(floor) = &security_floor {
        ensure!(*floor <= version, (t.floor_above_version)(&floor.to_string(), &version.to_string()));
    }
    let shown = key_file.display().to_string();
    let pem = fs::read_to_string(key_file).with_context(|| (t.read_key)(&shown))?;
    let key = NodeKey::from_pem(&pem).with_context(|| (t.parse_key)(&shown))?;
    let (manifest_path, signature_path) = (dir.join(MANIFEST_FILE), dir.join(SIGNATURE_FILE));
    for path in [&manifest_path, &signature_path] {
        ensure!(!path.exists(), (t.already_signed)(&path.display().to_string()));
    }

    let (artifacts, files) = collect_release_files(dir)?;
    ensure!(!artifacts.is_empty(), (t.no_programs)(&dir.display().to_string(), NODE_PROGRAM));
    let published = SystemTime::now().duration_since(UNIX_EPOCH).context(t.clock_before_1970)?.as_secs();
    let manifest = Manifest { version, min_controller, published, artifacts, security_floor, files };
    let text = serde_json::to_string_pretty(&manifest).context(t.encode_manifest)? + "\n";
    let signed = sign_manifest(&key, text);

    write_new(&manifest_path, signed.manifest.as_bytes())?;
    write_new(&signature_path, format!("{}\n", signed.signature).as_bytes())?;

    println!("{}", (t.signed)(&manifest.version.to_string(), release_kind(&manifest), &key.public().to_string()));
    print_security_floor(&manifest);
    for (platform, artifact) in &manifest.artifacts {
        println!("{}", (t.artifact)(platform, &artifact.file, artifact.size, &artifact.sha256.to_string()));
    }
    for (name, artifact) in &manifest.files {
        println!("{}", (t.artifact)("file", name, artifact.size, &artifact.sha256.to_string()));
    }
    println!("{}", (t.written)(&manifest_path.display().to_string(), &signature_path.display().to_string()));
    if !TrustedKeys::compiled_in().iter().any(|trusted| *trusted == key.public()) {
        eprintln!("{}", t.untrusted_key);
    }
    Ok(())
}

/// 节点程序之外、需要收入 `manifest.files` 的可执行程序前缀。
const EXTRA_PROGRAMS: [&str; 2] = ["i3t-controller", "i3tctl"];

/// 目录里的发布产物：节点程序放进 `artifacts`（以平台名为键），controller、命令行工具与 Windows 压缩包放进 `files`（以文件名为键）。
fn collect_release_files(dir: &Path) -> anyhow::Result<(BTreeMap<String, Artifact>, BTreeMap<String, Artifact>)> {
    let t = &texts().ui;
    let read_dir = || (t.read_dir)(&dir.display().to_string());
    let mut artifacts = BTreeMap::new();
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(dir).with_context(read_dir)? {
        let entry = entry.with_context(read_dir)?;
        let Some(file) = entry.file_name().to_str().map(str::to_owned) else { continue };
        let platform = node_program_platform(&file);
        let is_extra = platform.is_none() && is_extra_release_file(&file);
        if platform.is_none() && !is_extra {
            continue;
        }
        let path = entry.path();
        let shown = path.display().to_string();
        ensure!(path.is_file(), (t.not_a_file)(&shown));
        let digest = FileDigest::of_file(&path).with_context(|| (t.read)(&shown))?;
        ensure!(digest.size > 0, (t.empty_file)(&shown));
        let artifact = Artifact { file: file.clone(), size: digest.size, sha256: digest.sha256 };
        if let Some(platform) = platform {
            artifacts.insert(platform.to_string(), artifact);
        } else {
            files.insert(file, artifact);
        }
    }
    Ok((artifacts, files))
}

/// 一个文件名是不是某个平台的节点程序；是的话是哪个平台。
///
/// 反向校验文件名，以排除 `i3t-linux-x86_64.exe`、`i3t-windows-x86_64` 等与目标平台命名规范不符的名称。
fn node_program_platform(file: &str) -> Option<Platform> {
    let rest = file.strip_prefix(NODE_PROGRAM)?.strip_prefix('-')?;
    let platform: Platform = rest.strip_suffix(".exe").unwrap_or(rest).parse().ok()?;
    (platform.program_file(NODE_PROGRAM) == file).then_some(platform)
}

/// 一个文件名是不是节点程序之外的发布产物：`i3t-controller-<平台>[.exe]`、`i3tctl-<平台>[.exe]` 或 Windows 安装包 `i3t-windows-<架构>.zip`。
fn is_extra_release_file(file: &str) -> bool {
    for program in EXTRA_PROGRAMS {
        if let Some(rest) = file.strip_prefix(program).and_then(|s| s.strip_prefix('-'))
            && let Ok(platform) = rest.strip_suffix(".exe").unwrap_or(rest).parse::<Platform>()
            && platform.program_file(program) == file
        {
            return true;
        }
    }
    if let Some(rest) = file.strip_prefix(NODE_PROGRAM).and_then(|s| s.strip_prefix('-')).and_then(|s| s.strip_suffix(".zip"))
        && let Ok(platform) = rest.parse::<Platform>()
        && platform.as_str().starts_with("windows-")
    {
        return true;
    }
    false
}

/// 新建并写入。文件已经存在时失败。
fn write_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let write = || -> io::Result<()> {
        let mut file = File::create_new(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    };
    write().with_context(|| (texts().ui.write)(&path.display().to_string()))
}

fn release_kind(manifest: &Manifest) -> &'static str {
    let t = &texts().ui;
    if manifest.is_prerelease() { t.prerelease } else { t.release }
}

fn print_security_floor(manifest: &Manifest) {
    if let Some(floor) = &manifest.security_floor {
        println!("{}", (texts().ui.security_floor)(&floor.to_string()));
    }
}

fn verify(dir: &Path, key: Option<PublicKey>) -> anyhow::Result<()> {
    let (t, lang) = (&texts().ui, i3t_lang::current());
    let read = |name: &str| fs::read_to_string(dir.join(name)).with_context(|| (t.read)(&dir.join(name).display().to_string()));
    let signed =
        SignedManifest::from_files(read(MANIFEST_FILE)?, &read(SIGNATURE_FILE)?).with_context(|| (t.parse_signature)(SIGNATURE_FILE))?;
    let keys = key.map_or_else(TrustedKeys::compiled_in, TrustedKeys::from);
    let manifest = keys.verify(&signed).with_context(|| (t.check_signature)(MANIFEST_FILE, &lang.list(keys.iter())))?;
    println!("{}", (t.verified)(&manifest.version.to_string(), release_kind(&manifest), &manifest.min_controller.to_string()));
    print_security_floor(&manifest);

    let mut mismatched = 0;
    for (platform, artifact) in &manifest.artifacts {
        match check_file(dir, artifact) {
            Ok(()) => println!("{}", (t.file_ok)(platform, &artifact.file)),
            Err(error) => {
                println!("{}", (t.file_bad)(platform, &artifact.file, &lang.chain(error.chain())));
                mismatched += 1;
            }
        }
    }
    for (key, artifact) in &manifest.files {
        let result = if key != &artifact.file {
            Err(anyhow::anyhow!((t.key_file_mismatch)(key, &artifact.file)))
        } else {
            check_file(dir, artifact)
        };
        match result {
            Ok(()) => println!("{}", (t.file_ok)("file", &artifact.file)),
            Err(error) => {
                println!("{}", (t.file_bad)("file", key, &lang.chain(error.chain())));
                mismatched += 1;
            }
        }
    }
    ensure!(mismatched == 0, (t.mismatched)(mismatched));
    println!("{}", (t.all_match)(manifest.artifacts.len() + manifest.files.len()));
    Ok(())
}

fn check_file(dir: &Path, artifact: &Artifact) -> anyhow::Result<()> {
    let t = &texts().ui;
    // 清单是签过名的，但文件名要拿去拼路径，还是只认不带目录的名字。
    ensure!(Path::new(&artifact.file).file_name().is_some_and(|name| name == artifact.file.as_str()), t.directory_in_name);
    let digest = FileDigest::of_file(&dir.join(&artifact.file)).context(t.unreadable)?;
    if digest.size != artifact.size {
        bail!((t.size_differs)(digest.size, artifact.size));
    }
    ensure!(digest.sha256 == artifact.sha256, (t.sha256_differs)(&digest.sha256.to_string(), &artifact.sha256.to_string()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use i3t_lang::cli::{CLAP_ENGLISH, all_help, has_chinese, plural_after_one, try_parse_from};

    use super::*;

    #[test]
    fn only_node_programs_named_for_a_platform_are_recognised() {
        let platform = |file: &str| node_program_platform(file).map(|platform| platform.to_string());
        assert_eq!(platform("i3t-linux-x86_64").as_deref(), Some("linux-x86_64"));
        assert_eq!(platform("i3t-linux-aarch64").as_deref(), Some("linux-aarch64"));
        assert_eq!(platform("i3t-macos-aarch64").as_deref(), Some("macos-aarch64"));
        assert_eq!(platform("i3t-windows-x86_64.exe").as_deref(), Some("windows-x86_64"));
        let others = [
            "i3t",
            "i3t-",
            "i3t-linux",
            "i3t-controller-linux-x86_64",
            "i3tctl-linux-x86_64",
            "i3t-linux-x86_64.exe",
            "i3t-windows-x86_64",
            "i3t-linux-x86_64.sha256",
            "i3t-linux-x86_64.old",
            "manifest.json",
            "manifest.json.sig",
            "I3T-linux-x86_64",
        ];
        for file in others {
            assert_eq!(platform(file), None, "{file} 不应该被当成节点程序");
        }
    }

    #[test]
    fn the_help_of_every_command_is_written_in_each_language_without_the_other() {
        for lang in Lang::ALL {
            i3t_lang::cli::localize(command(lang), lang).debug_assert();
        }
        for (path, help) in all_help(command(Lang::English), Lang::English) {
            assert!(!has_chinese(&help), "{path} 的英文帮助里有中文：\n{help}");
        }
        for (path, help) in all_help(command(Lang::ZhCn), Lang::ZhCn) {
            for english in CLAP_ENGLISH {
                assert!(!help.contains(english), "{path} 的中文帮助里有 {english}：\n{help}");
            }
            assert!(has_chinese(&help), "{path}：\n{help}");
        }
    }

    #[test]
    fn extra_release_files_cover_controller_cli_and_windows_zip_only() {
        for expected in [
            "i3t-controller-linux-x86_64",
            "i3t-controller-linux-aarch64",
            "i3t-controller-macos-aarch64",
            "i3t-controller-windows-x86_64.exe",
            "i3tctl-linux-x86_64",
            "i3tctl-macos-x86_64",
            "i3tctl-windows-x86_64.exe",
            "i3t-windows-x86_64.zip",
            "i3t-windows-aarch64.zip",
        ] {
            assert!(is_extra_release_file(expected), "{expected} 应该收入 manifest.files");
            assert_eq!(node_program_platform(expected), None, "{expected} 不应该同时进入 artifacts");
        }
        for ignored in [
            "i3t-linux-x86_64",
            "i3t-windows-x86_64.exe",
            "i3t-linux-x86_64.zip",
            "i3t-controller-linux-x86_64.exe",
            "i3t-controller-windows-x86_64",
            "i3tctl-linux-x86_64.exe",
            "i3tctl-windows-x86_64",
            "i3t-windows-x86_64.zip.sig",
            "manifest.json",
            "manifest.json.sig",
            "README.txt",
        ] {
            assert!(!is_extra_release_file(ignored), "{ignored} 不应该进入 manifest.files");
        }
    }

    #[test]
    fn the_english_texts_have_no_chinese_and_read_right_for_one() {
        let ui = &texts::texts_in(Lang::English).ui;
        let said = [
            (ui.key_written)("release.key"),
            (ui.no_programs)("dist", NODE_PROGRAM),
            (ui.signed)("0.3.0", ui.release, "KEY"),
            (ui.artifact)("linux-x86_64", "i3t-linux-x86_64", 1, "ab"),
            (ui.check_signature)(MANIFEST_FILE, "KEY"),
            (ui.verified)("0.3.0", ui.prerelease, "0.2.0"),
            (ui.file_bad)("linux-x86_64", "i3t-linux-x86_64", ui.unreadable),
            (ui.mismatched)(1),
            (ui.all_match)(1),
            (ui.size_differs)(1, 1),
            (ui.security_floor)("0.3.0"),
            (ui.floor_above_version)("0.4.0", "0.3.0"),
            (ui.key_file_mismatch)("a", "b"),
            ui.untrusted_key.to_owned(),
        ];
        for text in said {
            assert!(!has_chinese(&text), "{text}");
            assert_eq!(plural_after_one(&text), None, "{text}");
        }
    }

    #[test]
    fn the_security_floor_is_optional_and_must_be_a_version() {
        let args = |extra: &[&str]| {
            let base = ["i3t-release", "manifest", "--version", "0.3.0", "--dir", "dist", "--key", "release.key"];
            base.iter().chain(extra).map(|arg| OsString::from(*arg)).collect::<Vec<_>>()
        };
        let floor = |extra: &[&str]| {
            let cli: Cli = try_parse_from(command(Lang::English), Lang::English, args(extra)).unwrap();
            let Command::Manifest { security_floor, .. } = cli.command else { panic!("应该解析成 manifest") };
            security_floor.map(|floor| floor.to_string())
        };
        assert_eq!(floor(&[]), None, "不写就没有下限");
        assert_eq!(floor(&["--security-floor", "0.2.5"]).as_deref(), Some("0.2.5"));
        assert!(try_parse_from::<Cli>(command(Lang::English), Lang::English, args(&["--security-floor", "x"])).is_err());
    }

    #[test]
    fn a_public_key_starting_with_a_hyphen_is_still_a_value() {
        let key = format!("-{}", "A".repeat(42));
        let args = ["i3t-release", "verify", "--dir", "dist", "--key", &key].map(OsString::from);
        let cli: Cli = try_parse_from(command(Lang::English), Lang::English, args).unwrap();
        let Command::Verify { key: Some(parsed), .. } = cli.command else { panic!("应该解析成 verify") };
        assert_eq!(parsed.to_string(), key);
    }
}
