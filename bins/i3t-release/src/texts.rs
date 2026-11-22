//! `i3t-release` 的文字目录：帮助、结果和报错，两种语言各一份。少写一项、参数不对都编译不过。

use i3t_lang::Lang;

#[derive(Debug)]
pub struct Texts {
    pub help: Help,
    pub values: Values,
    pub ui: Ui,
}

pub fn texts() -> &'static Texts {
    texts_in(i3t_lang::current())
}

pub const fn texts_in(lang: Lang) -> &'static Texts {
    match lang {
        Lang::ZhCn => &ZH,
        Lang::English => &EN,
    }
}

#[derive(Debug)]
pub struct Help {
    pub about: &'static str,
    pub keygen: &'static str,
    pub keygen_out: &'static str,
    pub manifest: &'static str,
    pub manifest_version: &'static str,
    pub manifest_dir: &'static str,
    pub manifest_key: &'static str,
    pub min_controller: &'static str,
    pub security_floor: &'static str,
    pub verify: &'static str,
    pub verify_dir: &'static str,
    pub verify_key: &'static str,
}

#[derive(Debug)]
pub struct Values {
    pub file: &'static str,
    pub version: &'static str,
    pub dir: &'static str,
    pub key: &'static str,
}

#[derive(Debug)]
pub struct Ui {
    pub generate_key: &'static str,
    pub create_key_file: fn(&str) -> String,
    pub write: fn(&str) -> String,
    pub read: fn(&str) -> String,
    pub read_dir: fn(&str) -> String,
    /// `keygen` 之后，标准错误上：私钥写到了哪个文件，上面那一行公钥怎么用。
    pub key_written: fn(&str) -> String,
    pub read_key: fn(&str) -> String,
    pub parse_key: fn(&str) -> String,
    pub already_signed: fn(&str) -> String,
    /// 目录里没有节点程序：目录，节点程序的名字（`i3t`）。
    pub no_programs: fn(&str, &str) -> String,
    pub not_a_file: fn(&str) -> String,
    pub empty_file: fn(&str) -> String,
    pub clock_before_1970: &'static str,
    pub encode_manifest: &'static str,
    /// 签好了：版本，正式版还是预发布版，签名用的公钥。
    pub signed: fn(&str, &str, &str) -> String,
    /// 清单里的一个文件：平台，文件名，字节数，SHA-256。
    pub artifact: fn(&str, &str, u64, &str) -> String,
    pub written: fn(&str, &str) -> String,
    pub untrusted_key: &'static str,
    pub release: &'static str,
    pub prerelease: &'static str,
    pub parse_signature: fn(&str) -> String,
    /// 核对签名失败：清单文件，认的公钥。
    pub check_signature: fn(&str, &str) -> String,
    /// 签名正确：版本，正式版还是预发布版，需要的 controller 最低版本。
    pub verified: fn(&str, &str, &str) -> String,
    /// 清单写了安全下限：那个版本。
    pub security_floor: fn(&str) -> String,
    /// 安全下限比这次发布的版本新：下限，这次的版本。
    pub floor_above_version: fn(&str, &str) -> String,
    pub file_ok: fn(&str, &str) -> String,
    /// 一个文件和清单对不上：平台，文件名，哪里不对。
    pub file_bad: fn(&str, &str, &str) -> String,
    pub mismatched: fn(usize) -> String,
    pub all_match: fn(usize) -> String,
    pub directory_in_name: &'static str,
    pub key_file_mismatch: fn(&str, &str) -> String,
    pub unreadable: &'static str,
    pub size_differs: fn(u64, u64) -> String,
    pub sha256_differs: fn(&str, &str) -> String,
}

static ZH: Texts = Texts {
    help: Help {
        about: "ice3tier 的发布工具",
        keygen: "生成一把新的发布签名密钥，写进文件（只有属主可读），并打印它的公钥",
        keygen_out: "私钥写到哪个文件。已经存在的文件不会被覆盖",
        manifest: "为发布目录里的节点程序生成 manifest.json 并签名，得到 manifest.json.sig",
        manifest_version: "这次发布的版本号，例如 0.3.0；预发布版写成 0.3.0-rc.1",
        manifest_dir: "发布目录。里面的节点程序要叫 i3t-<平台>，例如 i3t-linux-x86_64、i3t-windows-x86_64.exe",
        manifest_key: "发布签名密钥的文件（keygen 生成的那个）",
        min_controller: "这个版本的节点需要的 controller 最低版本。比它旧的 controller 不会下发这个版本",
        security_floor: "安全下限：最低的没有已知安全问题的版本，比它旧的节点标为有安全更新。默认没有；写了就每一版都带上",
        verify: "核对一个发布目录：清单的签名，以及清单里每个文件的大小和 SHA-256",
        verify_dir: "发布目录",
        verify_key: "只认这一把公钥（base64url）。不给的话用编译在本程序里的发布公钥，和节点认的一样",
    },
    values: Values { file: "文件", version: "版本号", dir: "目录", key: "公钥" },
    ui: Ui {
        generate_key: "生成密钥",
        create_key_file: |path| format!("创建 {path}（已经存在的文件不会被覆盖）"),
        write: |path| format!("写 {path}"),
        read: |path| format!("读 {path}"),
        read_dir: |dir| format!("读目录 {dir}"),
        key_written: |path| {
            format!(
                "私钥已经写到 {path}。上面这一行是公钥：节点只认编译在程序里的公钥，\n\
                 所以要么把它加进 i3t-update 的公钥列表，要么编译时设 I3T_RELEASE_EXTRA_KEY=<公钥>。"
            )
        },
        read_key: |path| format!("读签名密钥 {path}"),
        parse_key: |path| format!("解析签名密钥 {path}"),
        already_signed: |path| format!("{path} 已经存在。签过名的清单不覆盖；确实要重做的话先把它删掉"),
        no_programs: |dir, program| {
            format!("{dir} 里没有节点程序。它们应该叫 {program}-<平台>，例如 {program}-linux-x86_64、{program}-windows-x86_64.exe")
        },
        not_a_file: |path| format!("{path} 不是一个普通文件"),
        empty_file: |path| format!("{path} 是空的"),
        clock_before_1970: "系统时钟早于 1970 年",
        encode_manifest: "生成清单",
        signed: |version, kind, key| format!("版本 {version}（{kind}），签名用的公钥 {key}"),
        artifact: |platform, file, size, sha256| format!("  {platform:<16} {file}  {size} 字节  {sha256}"),
        written: |manifest, signature| format!("已写出 {manifest} 和 {signature}"),
        untrusted_key: "注意：这把钥匙不在本程序编译进去的发布公钥里。同样编译出来的节点不会认这份清单。",
        release: "正式版",
        prerelease: "预发布版",
        parse_signature: |file| format!("解析 {file}"),
        check_signature: |file, keys| format!("核对 {file} 的签名（认的公钥：{keys}）"),
        verified: |version, kind, min| format!("版本 {version}（{kind}），需要 controller {min} 或更新，签名正确"),
        security_floor: |floor| format!("安全下限 {floor}：比它旧的版本有已知的安全问题"),
        floor_above_version: |floor, version| format!("安全下限 {floor} 比这次发布的版本 {version} 还新"),
        file_ok: |platform, file| format!("  通过  {platform:<16} {file}"),
        file_bad: |platform, file, error| format!("  不符  {platform:<16} {file}：{error}"),
        mismatched: |count| format!("清单里有 {count} 个文件和目录里的对不上"),
        all_match: |count| format!("清单里的 {count} 个文件都核对无误"),
        directory_in_name: "文件名里不应该有目录",
        key_file_mismatch: |key, file| format!("键名是 {key}，文件名却是 {file}"),
        unreadable: "读不了",
        size_differs: |size, listed| format!("大小是 {size} 字节，清单上是 {listed} 字节"),
        sha256_differs: |sha256, listed| format!("SHA-256 是 {sha256}，清单上是 {listed}"),
    },
};

static EN: Texts = Texts {
    help: Help {
        about: "ice3tier release tool",
        keygen: "Generate a new release signing key, write it to a file readable only by its owner, and print its public key",
        keygen_out: "File for the private key. An existing file is never overwritten",
        manifest: "Write manifest.json for the node programs in a release directory and sign it into manifest.json.sig",
        manifest_version: "Version of this release, e.g. 0.3.0; a pre-release is written 0.3.0-rc.1",
        manifest_dir: "Release directory. Node programs in it are named i3t-<PLATFORM>, e.g. i3t-linux-x86_64, i3t-windows-x86_64.exe",
        manifest_key: "File of the release signing key (the one keygen wrote)",
        min_controller: "Oldest controller version the nodes of this release need. Older controllers don't offer it",
        security_floor: "Security floor: the lowest version without a known security problem; older nodes are marked as having a security update. None by default; once set, carry it in every release",
        verify: "Check a release directory: the manifest's signature, and the size and SHA-256 of every file in it",
        verify_dir: "Release directory",
        verify_key: "Accept only this public key (base64url). Without it, the release keys compiled into this program, as nodes do",
    },
    values: Values { file: "FILE", version: "VERSION", dir: "DIR", key: "KEY" },
    ui: Ui {
        generate_key: "Generating the key",
        create_key_file: |path| format!("Creating {path} (an existing file is never overwritten)"),
        write: |path| format!("Writing {path}"),
        read: |path| format!("Reading {path}"),
        read_dir: |dir| format!("Reading directory {dir}"),
        key_written: |path| {
            format!(
                "Private key written to {path}. The line above is the public key: nodes trust only keys compiled into them,\n\
                 so add it to the key list in i3t-update, or build with I3T_RELEASE_EXTRA_KEY=<KEY>."
            )
        },
        read_key: |path| format!("Reading the signing key {path}"),
        parse_key: |path| format!("Parsing the signing key {path}"),
        already_signed: |path| format!("{path} already exists. A signed manifest is never overwritten; delete it first to redo it"),
        no_programs: |dir, program| {
            format!(
                "No node programs in {dir}. They are named {program}-<PLATFORM>, e.g. {program}-linux-x86_64, {program}-windows-x86_64.exe"
            )
        },
        not_a_file: |path| format!("{path} is not a regular file"),
        empty_file: |path| format!("{path} is empty"),
        clock_before_1970: "The system clock is before 1970",
        encode_manifest: "Writing the manifest",
        signed: |version, kind, key| format!("Version {version} ({kind}), signed with public key {key}"),
        artifact: |platform, file, size, sha256| format!("  {platform:<16} {file}  {size} B  {sha256}"),
        written: |manifest, signature| format!("Wrote {manifest} and {signature}"),
        untrusted_key: "Note: this key is not among the release keys compiled into this program. Nodes built the same way won't accept this manifest.",
        release: "release",
        prerelease: "pre-release",
        parse_signature: |file| format!("Parsing {file}"),
        check_signature: |file, keys| format!("Checking the signature of {file} (trusted keys: {keys})"),
        verified: |version, kind, min| format!("Version {version} ({kind}), needs controller {min} or newer, signature valid"),
        security_floor: |floor| format!("Security floor {floor}: older versions have a known security problem"),
        floor_above_version: |floor, version| format!("The security floor {floor} is newer than this release {version}"),
        file_ok: |platform, file| format!("  ok        {platform:<16} {file}"),
        file_bad: |platform, file, error| format!("  mismatch  {platform:<16} {file}: {error}"),
        mismatched: |count| format!("Files that don't match the manifest: {count}"),
        all_match: |count| format!("Every file in the manifest matches (files: {count})"),
        directory_in_name: "The file name must not contain a directory",
        key_file_mismatch: |key, file| format!("key is {key}, but file name is {file}"),
        unreadable: "Can't read it",
        size_differs: |size, listed| format!("size is {size} B, the manifest says {listed} B"),
        sha256_differs: |sha256, listed| format!("SHA-256 is {sha256}, the manifest says {listed}"),
    },
};
