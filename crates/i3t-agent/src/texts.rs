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
    read_config: |path| format!("读配置文件 {}", path.display()),
    config_error: |path| format!("配置文件 {} 有错", path.display()),
    write_config: |path| format!("写配置文件 {}", path.display()),
    create_config: |path| format!("创建配置文件 {}", path.display()),
    port_zero: "port 不能是 0：别的节点要按固定的端口找它",
    proxy_not_loopback: |name, addr| {
        format!(
            "{name} = \"{addr}\" 不是回环地址：本机的组网入口只能写 127.0.0.1 或 [::1]。给别的机器用的、经出口出去的代理在 WebUI 的代理里配置。"
        )
    },
    metrics_not_loopback: |addr| format!("metrics.listen = \"{addr}\" 不是回环地址：指标接口没有认证，只能写 127.0.0.1 或 [::1]。"),
    same_proxy_address: |addr| format!("proxy.socks5 和 proxy.http 不能用同一个地址 {addr}"),
    unknown_setting: |other| {
        format!("没有设置项 {other}：可以写 can-exit、can-relay、relay-address、throughput-tests、profile、network、firewall、mtu、offload")
    },
    not_a_switch: |other| format!("\"{other}\" 不是开关的值：写 on 或 off"),
    unknown_profile: |other| format!("没有档位 \"{other}\"：可以写 low-footprint、balanced、high-throughput"),
    bad_relay_address: |text| {
        format!("\"{text}\" 不能作为中继地址：写别的节点连得上的“地址:端口”，比如 \"203.0.113.9:40330\"，或者 \"off\"")
    },
    bad_mtu: |text| format!("虚拟网卡的 MTU 不能是 \"{text}\"：写 576 到 1500 之间的字节数（默认 1280）"),
    performance_range: |key, low, high| format!("performance.{key} 要在 {low} 到 {high} 之间"),
    not_an_address: |text| format!("\"{text}\" 不是地址：写成 \"127.0.0.1:1080\" 这样的“地址:端口”，或者 \"off\""),
    create_state_dir: |path| format!("创建状态目录 {}", path.display()),
    restrict_state_dir: |path| format!("收紧状态目录 {} 的权限", path.display()),
    parse_key: |path| format!("私钥文件 {} 读不懂", path.display()),
    read_key: |path| format!("读私钥文件 {}", path.display()),
    generate_key: "生成节点私钥",
    find_program: "找不到正在运行的程序文件",
    not_a_token: "这不是注册令牌：令牌以 i3t- 开头，在 WebUI 的“添加节点”里生成",
    not_joined: "还没有加入网络",
    enroll_timeout: "controller 没有按时回答注册请求",
    enroll_rejected: |reason| format!("controller 拒绝了注册：{reason}"),
    enroll_try_later: |reason| format!("controller 暂时处理不了注册，令牌没有用掉，稍后再试：{reason}"),
    enroll_unexpected: |kind| format!("controller 的回答不对：{kind}"),
    enroll_closed: "controller 没有回答就关闭了连接",
    connect: CONNECT_ZH,
    probe_close: "关闭连接",
    probe_refused: "controller 拒绝了握手",
    query_running: |error| format!("问不到正在运行的节点：{error}"),
    status_unreadable: "正在运行的节点给的状态读不懂",
    bad_peer: |peer| format!("{peer:?} 不是节点名或者虚拟 IP"),
};

/// 中文的连接说明。长连接的日志一直用这一份。
pub(crate) const CONNECT_ZH: Connect = Connect {
    tls_config: "准备 TLS 配置",
    server_name: "构造 TLS 服务器名",
    tcp: |address| format!("连接 controller {address}"),
    nodelay: "设置 TCP_NODELAY",
    handshake: "和 controller 的 TLS 握手",
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

const TEMPLATE_ZH: &str = r#"# ice3tier 节点的配置。改完重启 i3t 生效。`i3t set …` 改的也是这个文件。

# 节点的 UDP 端口。启用为中继的节点在同一个端口号上还监听 TCP。
port = 20330

# 这台机器声明可以承担什么。声明本身不启用任何东西：要管理员在 WebUI 上启用；没有声明的启用不了。
[declare]
# 出口：别的节点的流量从这台机器的网络出去。
exit = false
# 中继：为别的节点转发。别的节点连得上它的端口就行，谁连得上它，它就是谁的中继。
relay = false
# 中继的另一个地址，只有机房或路由器把另一个 IP 上的端口映射到这台机器时才要写，比如：
# relay_address = "203.0.113.9:40330"
# 也可以执行 i3t set relay-address 203.0.113.9:40330。别的地址由 controller 自己找出来。

# 本机的组网入口：这台机器上的程序经它访问组网里的节点（只到节点，不经出口，不认证）。默认不开：
# 有虚拟网卡时直接连虚拟 IP 就行，装不了网卡的机器才用得上。要开就写回环上的地址，比如 socks5 = "127.0.0.1:1080"。
# 它们的流只走共用的连接，不走 ice3proxy。经出口出去的代理（和它的 ice3proxy 选项）在 WebUI 的代理里配置。
[proxy]
socks5 = "off"
http = "off"

# 本机的指标接口（Prometheus）：http://<地址>/metrics。只能绑回环地址。不需要的写 "off"。
[metrics]
listen = "127.0.0.1:20333"

# 管理员发起的主动测试。
[tests]
# 接受吞吐测试：每个方向最多 5 秒或 20 MB。按流量计费的机器可以写 false（i3t set throughput-tests off）。
throughput = true

# 性能档位：low-footprint（一个核、几百 MB 内存的机器）、balanced、high-throughput（对端多、流量大）。
# controller 给这个节点选了档位时以它为准。i3t set profile <档位> 改的是这一行。
[performance]
profile = "balanced"
# 下面各项不写就用档位的值；写了就盖过档位，不管档位是谁选的。
# threads = 2               # 工作线程。只有一个对端在忙的机器、纯粹的中继写 1 最快。改了要重启
# stream_buffer_kb = 16     # 每条流每个方向的搬运缓冲
# stream_window_kb = 2048   # 每条流的接收窗口，最大 2048
# connection_window_mb = 64 # 一条连接上收、发各自最多压住多少数据
# idle_close_secs = 300     # 没有流之后多久关闭连接，0 是不关
# return_memory = false     # 每分钟把空着的内存还给系统

# 虚拟网卡：本机的程序直接用虚拟 IP 或者 <名字>.<网络的域名> 访问别的节点，像一个局域网。节点停下时拆掉。
# 要 root（Linux 上 CAP_NET_ADMIN 就够）；Windows 上要以管理员运行，程序旁边要有 wintun.dll。装不上时代理和端口转发照常。
# i3t set network off 关掉它，i3t network status 列出装了什么。
[network]
enabled = true
# 防火墙：放行从虚拟网卡进来的、丢掉从别的网卡进来却自称来自虚拟地址段的（Linux），放行虚拟地址段（Windows）。
# 写 false（i3t set firewall off）程序就一条规则也不碰，从虚拟网卡进来的由这台机器自己的防火墙管。
firewall = true
# 网卡的 MTU（字节，576 到 1500；i3t set mtu 1280）。只管这台机器的网卡，别的节点设得不一样也通。
# 一般不用动：比 1280 大，包多半要切成两片发，反而慢；底下的线路包长特别小时才值得调小。
mtu = 1280
# Linux：网卡和内核之间一次交接一大块数据，不是一个个的包，流量大时省 CPU；内核不给时程序自己退回去。
# 一般不用动：经网卡的传输卡住或者内容不对时，写 false（i3t set offload off）看是不是它。
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
# The adapter's MTU (bytes, 576 to 1500; i3t set mtu 1280). It is this machine's adapter only: other nodes may differ.
# Rarely worth changing: above 1280 most packets go as two pieces and get slower; go lower only on lines with very small packets.
mtu = 1280
# Linux: the adapter and the kernel exchange large blocks instead of single packets, which saves CPU under load; the
# program falls back by itself where the kernel refuses. Rarely worth changing: write false (i3t set offload off) to see
# whether it is the cause when transfers over the adapter stall or arrive damaged.
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
