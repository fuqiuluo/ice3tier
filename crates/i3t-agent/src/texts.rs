//! 节点程序在终端上说的、出自这个 crate 的话：配置文件的模板，和交互的命令（`i3t join`、`i3t status`、`i3t set`、
//! `i3t self-check`）出错时的说明。两种语言各一份，按进程的语言（`i3t_lang::current`）取。
//!
//! 运行中的节点写进日志的话不在这里：日志照旧是中文。所以这里只放交互的命令走到的地方；`i3t run` 和交互的命令共用、
//! 出了错会进日志的地方（状态目录里文件的读写、长连接）保持原样。

use std::path::Path;

use i3t_lang::Lang;

/// 一种语言的文字。
#[derive(Debug)]
pub(crate) struct Texts {
    /// 第一次写出来的配置文件，注释是这种语言的。里面的值就是默认值。
    pub(crate) template: &'static str,
    pub(crate) read_config: fn(&Path) -> String,
    pub(crate) config_error: fn(&Path) -> String,
    pub(crate) write_config: fn(&Path) -> String,
    pub(crate) create_config: fn(&Path) -> String,
    pub(crate) port_zero: &'static str,
    pub(crate) proxy_not_loopback: fn(&str, &str) -> String,
    pub(crate) metrics_not_loopback: fn(&str) -> String,
    pub(crate) same_proxy_address: fn(&str) -> String,
    pub(crate) unknown_setting: fn(&str) -> String,
    pub(crate) not_a_switch: fn(&str) -> String,
    pub(crate) unknown_profile: fn(&str) -> String,
    pub(crate) bad_relay_address: fn(&str) -> String,
    pub(crate) bad_mtu: fn(&str) -> String,
    pub(crate) performance_range: fn(&str, u64, u64) -> String,
    pub(crate) not_an_address: fn(&str) -> String,
    pub(crate) create_state_dir: fn(&Path) -> String,
    pub(crate) restrict_state_dir: fn(&Path) -> String,
    /// Windows 上已有的状态目录（或里面的一项）不能用：属主（SID）不可信。
    #[cfg(windows)]
    pub(crate) untrusted_owner: fn(&str) -> String,
    /// Windows 上已有的状态目录（或里面的一项）不能用：这个账户（SID）能写或者能改权限。
    #[cfg(windows)]
    pub(crate) untrusted_writer: fn(&str) -> String,
    /// Windows 上已有的状态目录（或里面的一项）不能用：没有访问控制列表。
    #[cfg(windows)]
    pub(crate) no_dacl: &'static str,
    pub(crate) parse_key: fn(&Path) -> String,
    pub(crate) read_key: fn(&Path) -> String,
    pub(crate) generate_key: &'static str,
    pub(crate) find_program: &'static str,
    pub(crate) not_a_token: &'static str,
    pub(crate) not_joined: &'static str,
    pub(crate) enroll_timeout: &'static str,
    pub(crate) enroll_rejected: fn(&str) -> String,
    pub(crate) enroll_try_later: fn(&str) -> String,
    pub(crate) enroll_unexpected: fn(&str) -> String,
    pub(crate) enroll_closed: &'static str,
    pub(crate) connect: Connect,
    pub(crate) probe_close: &'static str,
    pub(crate) probe_refused: &'static str,
    pub(crate) query_running: fn(&str) -> String,
    pub(crate) status_unreadable: &'static str,
    /// `i3t ping` 的节点写得不对。
    pub(crate) bad_peer: fn(&str) -> String,
}

/// 连 controller 时每一步出错的说明。`i3t run` 的长连接用中文的这一份（它出错只进日志），交互的命令用当前语言的。
#[derive(Debug)]
pub(crate) struct Connect {
    pub(crate) tls_config: &'static str,
    pub(crate) server_name: &'static str,
    pub(crate) tcp: fn(&str) -> String,
    pub(crate) nodelay: &'static str,
    pub(crate) handshake: &'static str,
    pub(crate) timeout: fn(&str) -> String,
}

/// 这个进程的语言的文字。
pub(crate) fn texts() -> &'static Texts {
    texts_in(i3t_lang::current())
}

pub(crate) const fn texts_in(lang: Lang) -> &'static Texts {
    match lang {
        Lang::ZhCn => &ZH,
        Lang::English => &EN,
    }
}

static ZH: Texts = Texts {
    template: TEMPLATE_ZH,
    read_config: |path| format!("读取配置文件 {}", path.display()),
    config_error: |path| format!("配置文件 {} 存在错误", path.display()),
    write_config: |path| format!("写入配置文件 {}", path.display()),
    create_config: |path| format!("创建配置文件 {}", path.display()),
    port_zero: "port 不能为 0：其他节点需要通过固定端口访问本节点",
    proxy_not_loopback: |name, addr| {
        format!(
            "{name} = \"{addr}\" 不是回环地址：本机组网入口仅允许绑定 127.0.0.1 或 [::1]。面向其他机器、经出口转发的代理请在 WebUI 的代理中配置。"
        )
    },
    metrics_not_loopback: |addr| format!("metrics.listen = \"{addr}\" 不是回环地址：指标接口无认证保护，仅允许绑定 127.0.0.1 或 [::1]。"),
    same_proxy_address: |addr| format!("proxy.socks5 与 proxy.http 不能使用相同地址 {addr}"),
    unknown_setting: |other| {
        format!("未知设置项 {other}：支持 can-exit、can-relay、relay-address、throughput-tests、profile、network、firewall、mtu、offload")
    },
    not_a_switch: |other| format!("\"{other}\" 不是有效的开关值：请填写 on 或 off"),
    unknown_profile: |other| format!("未知性能档位 \"{other}\"：支持 low-footprint、balanced、high-throughput"),
    bad_relay_address: |text| {
        format!("\"{text}\" 不是有效的中继地址：请填写其他节点可达的“地址:端口”（如 \"203.0.113.9:40330\"）或 \"off\"")
    },
    bad_mtu: |text| format!("无效的虚拟网卡 MTU \"{text}\"：请填写 576 至 1500 之间的字节数（默认 1280）"),
    performance_range: |key, low, high| format!("performance.{key} 必须在 {low} 至 {high} 之间"),
    not_an_address: |text| format!("\"{text}\" 不是有效地址：请填写“地址:端口”（如 \"127.0.0.1:1080\"）或 \"off\""),
    create_state_dir: |path| format!("创建状态目录 {}", path.display()),
    restrict_state_dir: |path| format!("设置状态目录 {} 权限", path.display()),
    #[cfg(windows)]
    untrusted_owner: |sid| {
        format!("属主为 {sid}，不是 SYSTEM、Administrators 或当前用户，可能是其他用户预先创建的：请检查后将其删除，再重新运行")
    },
    #[cfg(windows)]
    untrusted_writer: |sid| format!("{sid} 可以写入或修改其权限，其中的内容可能已被改动：请检查后撤销该账户的权限或将其删除，再重新运行"),
    #[cfg(windows)]
    no_dacl: "没有访问控制列表，所有用户都可以写入，其中的内容可能已被改动：请检查后为其设置权限或将其删除，再重新运行",
    parse_key: |path| format!("无法解析私钥文件 {}", path.display()),
    read_key: |path| format!("读取私钥文件 {}", path.display()),
    generate_key: "生成节点私钥",
    find_program: "无法定位当前运行的可执行文件路径",
    not_a_token: "无效的注册令牌：令牌以 i3t- 开头，可在 WebUI 的“添加节点”中生成",
    not_joined: "尚未加入网络",
    enroll_timeout: "等待 controller 响应注册请求超时",
    enroll_rejected: |reason| format!("controller 拒绝了注册请求：{reason}"),
    enroll_try_later: |reason| format!("controller 暂时无法处理注册请求，令牌未被消耗，请稍后重试：{reason}"),
    enroll_unexpected: |kind| format!("收到 controller 的意外响应：{kind}"),
    enroll_closed: "controller 未响应即关闭了连接",
    connect: CONNECT_ZH,
    probe_close: "关闭连接",
    probe_refused: "controller 拒绝了握手",
    query_running: |error| format!("查询运行中节点状态失败：{error}"),
    status_unreadable: "无法解析运行中节点返回的状态数据",
    bad_peer: |peer| format!("{peer:?} 不是有效的节点名称或虚拟 IP"),
};

/// 中文的连接说明。长连接的日志一直用这一份。
pub(crate) const CONNECT_ZH: Connect = Connect {
    tls_config: "准备 TLS 配置",
    server_name: "构造 TLS 服务器名",
    tcp: |address| format!("连接 controller {address}"),
    nodelay: "设置 TCP_NODELAY",
    handshake: "与 controller 的 TLS 握手",
    timeout: |address| format!("连接 controller {address} 超时"),
};

static EN: Texts = Texts {
    template: TEMPLATE_EN,
    read_config: |path| format!("Reading the configuration file {}", path.display()),
    config_error: |path| format!("Error in the configuration file {}", path.display()),
    write_config: |path| format!("Writing the configuration file {}", path.display()),
    create_config: |path| format!("Creating the configuration file {}", path.display()),
    port_zero: "port can't be 0: other nodes find this one at a fixed port",
    proxy_not_loopback: |name, addr| {
        format!(
            "{name} = \"{addr}\" isn't a loopback address: the local mesh entries take 127.0.0.1 or [::1]. \
             Proxies for other machines, leaving through an exit, are set up under Proxies in the WebUI."
        )
    },
    metrics_not_loopback: |addr| {
        format!("metrics.listen = \"{addr}\" isn't a loopback address: the metrics endpoint has no authentication.")
    },
    same_proxy_address: |addr| format!("proxy.socks5 and proxy.http can't share the address {addr}"),
    unknown_setting: |other| {
        format!(
            "No setting {other}: possible values: can-exit, can-relay, relay-address, throughput-tests, profile, network, firewall, mtu, offload"
        )
    },
    not_a_switch: |other| format!("\"{other}\" isn't a switch value: write on or off"),
    unknown_profile: |other| format!("No profile \"{other}\": possible values: low-footprint, balanced, high-throughput"),
    bad_relay_address: |text| {
        format!("\"{text}\" can't be a relay address: write an address:port other nodes can reach, e.g. \"203.0.113.9:40330\", or \"off\"")
    },
    bad_mtu: |text| format!("The virtual adapter's MTU can't be \"{text}\": write a number of bytes from 576 to 1500 (default 1280)"),
    performance_range: |key, low, high| format!("performance.{key} must be between {low} and {high}"),
    not_an_address: |text| format!("\"{text}\" isn't an address: write \"127.0.0.1:1080\" (address:port) or \"off\""),
    create_state_dir: |path| format!("Creating the state directory {}", path.display()),
    restrict_state_dir: |path| format!("Restricting the state directory {}", path.display()),
    #[cfg(windows)]
    untrusted_owner: |sid| {
        format!(
            "it is owned by {sid}, not by SYSTEM, Administrators or the current user, so another user may have created it: check it, delete it and run again"
        )
    },
    #[cfg(windows)]
    untrusted_writer: |sid| {
        format!(
            "{sid} may write to it or change its permissions, so what is inside may have been altered: check it, take that account's access away or delete it, and run again"
        )
    },
    #[cfg(windows)]
    no_dacl: "it has no access control list, so every user may write to it and what is inside may have been altered: check it, give it permissions or delete it, and run again",
    parse_key: |path| format!("Private key file {} unreadable", path.display()),
    read_key: |path| format!("Reading the private key file {}", path.display()),
    generate_key: "Generating the node key",
    find_program: "Can't find the running program file",
    not_a_token: "Not an enrollment token: tokens start with i3t- and come from \"Add node\" in the WebUI",
    not_joined: "Not joined to a network yet",
    enroll_timeout: "The controller didn't answer the enrollment in time",
    enroll_rejected: |reason| format!("The controller rejected the enrollment: {reason}"),
    enroll_try_later: |reason| format!("The controller can't enroll right now; the token is still unused. Try again later: {reason}"),
    enroll_unexpected: |kind| format!("Unexpected answer from the controller: {kind}"),
    enroll_closed: "The controller closed the connection without answering",
    connect: Connect {
        tls_config: "Preparing TLS",
        server_name: "Preparing the TLS server name",
        tcp: |address| format!("Connecting to the controller at {address}"),
        nodelay: "Setting TCP_NODELAY",
        handshake: "TLS handshake with the controller",
        timeout: |address| format!("Connecting to the controller at {address} timed out"),
    },
    probe_close: "Closing the connection",
    probe_refused: "The controller refused the handshake",
    query_running: |error| format!("Couldn't ask the running node: {error}"),
    status_unreadable: "The running node's status is unreadable",
    bad_peer: |peer| format!("{peer:?} isn't a node name or virtual IP"),
};

const TEMPLATE_ZH: &str = r#"# ice3tier 节点配置文件。修改后重启 i3t 生效，`i3t set …` 也会修改此文件。

# 节点的 UDP 端口。启用为中继的节点同时在相同端口号监听 TCP。
port = 20330

# 本机声明可承担的角色。声明本身不启用任何角色，需由管理员在 WebUI 中启用；未声明的角色无法启用。
[declare]
# 出口：其他节点的流量经本机网络出站。
exit = false
# 中继：为其他节点转发流量。能够访问该端口的节点即可使用本节点作为中继。
relay = false
# 中继的额外外部地址：仅在机房或路由器将另一 IP 的端口映射到本机时需要填写，例如：
# relay_address = "203.0.113.9:40330"
# 也可执行 i3t set relay-address 203.0.113.9:40330。其余地址由 controller 自动发现。

# 本机组网入口：供本机程序访问组网内节点（仅通往节点，不经出口，无认证）。默认关闭：
# 启用虚拟网卡时可直接访问虚拟 IP，仅在无法安装虚拟网卡的机器上需要使用。如需开启请填写回环地址，例如 socks5 = "127.0.0.1:1080"。
# 本机入口的流仅经共用连接传输，不使用 ice3proxy。经出口出站的代理（及其 ice3proxy 选项）请在 WebUI 的代理中配置。
[proxy]
socks5 = "off"
http = "off"

# 本机指标接口（Prometheus）：http://<地址>/metrics。仅允许绑定回环地址，不需要时填写 "off"。
[metrics]
listen = "127.0.0.1:20333"

# 管理员发起的主动测试。
[tests]
# 接受吞吐测试：单方向上限为 5 秒或 20 MB。按流量计费的机器可设为 false（i3t set throughput-tests off）。
throughput = true

# 性能档位：low-footprint（单核、数百 MB 内存机器）、balanced、high-throughput（多对端、大流量场景）。
# 若 controller 为本节点指定了档位，则以 controller 配置为准。i3t set profile <档位> 会修改此行。
[performance]
profile = "balanced"
# 下列参数未填写时使用档位默认值；填写后将覆盖档位配置（无论档位由本机还是 controller 指定）。
# threads = 2               # 工作线程数。仅单对端活跃或纯中继节点设为 1 性能最佳；修改后需重启
# stream_buffer_kb = 16     # 每条流单方向的传输缓冲大小
# stream_window_kb = 2048   # 每条流的接收窗口大小，最大 2048
# connection_window_mb = 64 # 单条连接收发方向各自允许积压的数据上限
# idle_close_secs = 300     # 无活跃流后关闭空闲连接的等待时长，0 表示不自动关闭
# return_memory = false     # 每分钟将空闲堆内存归还操作系统

# 虚拟网卡：本机程序可直接通过虚拟 IP 或 <名称>.<网络域名> 访问其他节点，如同局域网。节点停止时自动清理。
# 需要 root 权限（Linux 下具备 CAP_NET_ADMIN 即可）；Windows 下需以管理员身份运行且程序同目录需有 wintun.dll。初始化失败时代理和端口转发仍可用。
# 执行 i3t set network off 可关闭，执行 i3t network status 可查看已安装状态。
[network]
enabled = true
# 防火墙：放行经虚拟网卡入站的流量，丢弃经其他网卡入站但源地址属于虚拟地址段的流量（Linux），放行虚拟地址段（Windows）。
# 设为 false（i3t set firewall off）时程序不修改任何防火墙规则，虚拟网卡流量由本机防火墙自行管理。
firewall = true
# 虚拟网卡 MTU（字节，576 至 1500；i3t set mtu 1280）。设为 1280 表示跟随网络默认值（由管理员在 controller 上配置）；
# 设为其他值时仅对本机虚拟网卡生效，其他节点配置不同也可互通。
# 通常无需修改：大于 1280 可能导致数据包分片并降低性能；仅在底层链路 MTU 极小时调小。
mtu = 1280
# Linux：启用虚拟网卡与内核之间的分片卸载（GSO/GRO），高吞吐场景可降低 CPU 占用；内核不支持时自动回退。
# 通常无需修改：若经虚拟网卡传输出现卡顿或数据异常，可设为 false（i3t set offload off）排查。
# 若管理员在 controller 上关闭了网络级分片卸载，此处开启也不会生效。
offload = true

[log]
# 日志级别：error、warn、info、debug、trace。
level = "info"
"#;

const TEMPLATE_EN: &str = r#"# ice3tier node configuration. Restart i3t after editing. `i3t set …` edits this file too.

# The node's UDP port. A node enabled as a relay also listens on TCP at the same port number.
port = 20330

# What this machine declares it can do. Declaring enables nothing: an admin enables it in the WebUI,
# and only declared roles can be enabled.
[declare]
# Exit: other nodes' traffic leaves through this machine's network.
exit = false
# Relay: forward for other nodes. A relay serves whoever can reach its port.
relay = false
# Another address of the relay. Only needed when a provider or router maps a port on another IP to this machine, e.g.:
# relay_address = "203.0.113.9:40330"
# Or run: i3t set relay-address 203.0.113.9:40330. The controller finds the other addresses itself.

# Local mesh entries: programs on this machine reach the nodes of the network through them (nodes only, no exit,
# no authentication). Off by default: with the virtual network programs connect to virtual IPs directly, so only
# machines that cannot have the adapter need one. To turn one on write a loopback address,
# e.g. socks5 = "127.0.0.1:1080". They always use the shared connection, never ice3proxy. Proxies that leave
# through an exit (and their ice3proxy option) are set up under Proxies in the WebUI.
[proxy]
socks5 = "off"
http = "off"

# Local metrics endpoint (Prometheus): http://<address>/metrics. Loopback only. "off" turns it off.
[metrics]
listen = "127.0.0.1:20333"

# Active tests started by the admin.
[tests]
# Accept throughput tests: up to 5 s or 20 MB each way. Metered machines can set false (i3t set throughput-tests off).
throughput = true

# Performance profile: low-footprint (one core, a few hundred MB of memory), balanced, high-throughput (many peers, heavy traffic).
# A profile chosen for this node on the controller applies instead. i3t set profile <profile> edits this line.
[performance]
profile = "balanced"
# Each item below defaults to the profile's value; set here, it overrides the profile, whoever chose it.
# threads = 2               # Worker threads. 1 is fastest with one busy peer or on a pure relay. Needs a restart
# stream_buffer_kb = 16     # Copy buffer per stream and direction
# stream_window_kb = 2048   # Receive window per stream, at most 2048
# connection_window_mb = 64 # Most data one connection holds, each way
# idle_close_secs = 300     # Close a connection this long after its last stream; 0 never
# return_memory = false     # Give unused memory back to the system every minute

# Virtual network adapter: programs here reach other nodes by virtual IP or <name>.<network domain>, like a LAN.
# Removed when the node stops. Needs root (CAP_NET_ADMIN on Linux); on Windows run as administrator with wintun.dll next to
# the program. Proxies and port forwards work without it. i3t set network off turns it off; i3t network status lists what is installed.
[network]
enabled = true
# Firewall: accept what arrives on the adapter and drop packets claiming the virtual range from other interfaces (Linux),
# accept the virtual range (Windows). false (i3t set firewall off) makes the program touch no rules at all.
firewall = true
# The adapter's MTU (bytes, 576 to 1500; i3t set mtu 1280). 1280 follows the network's default (set by the admin on
# the controller); any other value is used as written, for this machine's adapter only: other nodes may differ.
# Rarely worth changing: above 1280 most packets go as two pieces and get slower; go lower only on lines with very small packets.
mtu = 1280
# Linux: the adapter and the kernel exchange large blocks instead of single packets, which saves CPU under load; the
# program falls back by itself where the kernel refuses. Rarely worth changing: write false (i3t set offload off) to see
# whether it is the cause when transfers over the adapter stall or arrive damaged. Where the admin turned this off for
# the network on the controller, it stays off whatever is written here.
offload = true

[log]
# Log level: error, warn, info, debug, trace.
level = "info"
"#;

#[cfg(test)]
mod tests {
    use i3t_lang::cli::has_chinese;

    use super::*;
    use crate::config::Config;

    #[test]
    fn the_configuration_template_reads_the_same_in_both_languages() {
        for lang in Lang::ALL {
            assert_eq!(Config::parse(texts_in(lang).template).unwrap(), Config::default(), "{lang:?} 的模板里的值就是默认值");
        }
        assert!(!has_chinese(EN.template), "英文的模板里有中文");
        assert!(has_chinese(ZH.template));
        // 两份模板的配置项一行一行对得上，只有注释不同。
        fn settings(template: &str) -> Vec<&str> {
            template.lines().filter(|line| !line.starts_with('#') && !line.is_empty()).collect()
        }
        assert_eq!(settings(ZH.template), settings(EN.template));
    }

    #[test]
    fn english_messages_have_no_chinese() {
        let path = Path::new("/var/lib/i3t/config.toml");
        let english = [
            (EN.read_config)(path),
            (EN.config_error)(path),
            (EN.proxy_not_loopback)("proxy.http", "0.0.0.0:1081"),
            (EN.metrics_not_loopback)("0.0.0.0:1"),
            (EN.unknown_setting)("x"),
            (EN.bad_mtu)("x"),
            (EN.enroll_rejected)("x"),
            (EN.connect.tcp)("ctl:1"),
            EN.not_a_token.to_owned(),
            EN.port_zero.to_owned(),
        ];
        for text in english {
            assert!(!has_chinese(&text), "{text}");
        }
    }
}
