//! `i3t` 的文字目录：帮助、状态、提示、报错，两种语言各一份。少写一项、参数不对都编译不过。
//! 控制面的代码（更新的进度、换路的原因）的写法在 `i3t_lang::codes`，和 `i3tctl` 共用；配置文件的模板在 `i3t-agent` 里。

use i3t_lang::Lang;

#[derive(Debug)]
pub struct Texts {
    pub help: Help,
    pub values: Values,
    pub ui: Ui,
    pub network: Net,
    #[cfg(target_os = "linux")]
    pub linux: Linux,
    #[cfg(windows)]
    pub service: Service,
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
    pub state_dir: &'static str,
    pub join: &'static str,
    pub can_exit: &'static str,
    pub can_relay: &'static str,
    pub run: &'static str,
    pub run_static: &'static str,
    pub set: &'static str,
    pub status: &'static str,
    pub routes: &'static str,
    pub ping: &'static str,
    pub ping_node: &'static str,
    pub ping_count: &'static str,
    pub key: &'static str,
    pub tune: &'static str,
    pub tune_apply: &'static str,
    pub network: &'static str,
    pub network_status: &'static str,
    pub network_cleanup: &'static str,
    pub hosts: &'static str,
    pub hosts_apply: &'static str,
    pub hosts_remove: &'static str,
    pub self_check: &'static str,
}

#[derive(Debug)]
pub struct Values {
    pub dir: &'static str,
    pub file: &'static str,
    pub node: &'static str,
    pub count: &'static str,
}

#[derive(Debug)]
pub struct Ui {
    pub none: &'static str,
    pub unknown: &'static str,
    /// 一句话的句号：`。`、`.`。
    pub period: &'static str,
    pub bad_version: &'static str,
    pub read_token: &'static str,
    pub joined: fn(&str) -> String,
    pub node: &'static str,
    pub fqdn: &'static str,
    pub virtual_ip: &'static str,
    pub config_file: &'static str,
    pub start_with_run: &'static str,
    /// 装成系统服务时（安装脚本的 `i3t` 包装脚本设 `I3T_SERVICE`）加入之后说的话：服务的名字。包装脚本接着重启它。
    pub start_service: fn(&str) -> String,
    pub start_runtime: &'static str,
    pub setting_set: fn(&str, &str) -> String,
    pub declare_hint: &'static str,
    /// `can-forward` 照收、不起作用时说的话。
    pub forward_by_admin: &'static str,
    /// `i3t set profile` 之后：controller 给这个节点选了别的档位，配置文件里的这一项现在不起作用。
    pub profile_chosen: fn(&str) -> String,
    pub not_running: &'static str,
    pub routes_not_running: &'static str,
    /// `i3t ping` 的结果：发了几个、回来几个、最短、平均、最长（毫秒，已经写好）。
    pub ping_summary: fn(u32, u32, &str, &str, &str) -> String,
    pub ping_all_lost: fn(u32) -> String,
    /// 开始和结束时的路不一样：开始时的、结束时的。
    pub ping_route_changed: fn(&str, &str) -> String,
    pub ping_unknown_node: fn(&str) -> String,
    pub ping_myself: &'static str,
    pub ping_not_allowed: fn(&str) -> String,
    pub ping_refused: fn(&str) -> String,
    pub ping_unreachable: fn(&str) -> String,
    /// 连接没有及时建起来：慢的路上建连接要几秒，不一定是它不在线。
    pub ping_connect_timeout: fn(&str) -> String,
    pub ping_unsupported: fn(&str) -> String,
    pub ping_busy: &'static str,
    pub ping_unknown: fn(&str) -> String,
    pub self_check_passed: fn(&str) -> String,
    pub wrong_version: fn(&str, &str) -> String,
    pub state_unreadable: fn(&str) -> String,
    pub handshake_failed: fn(&str) -> String,
    pub handshake_timeout: fn(u64) -> String,
    // `i3t tune` 只在 Linux 上做事，这句话只有别的系统上的程序用得到。
    #[cfg_attr(target_os = "linux", expect(dead_code, reason = "只在 Linux 以外的系统上说"))]
    pub tune_linux_only: &'static str,
    pub bad_log_env: fn(&str, &str, &str) -> String,
    // 只有 Windows 的服务把日志写进文件，这句话只有那里用得到。参数是环境变量的值和默认的上限（MiB）。
    #[cfg_attr(not(windows), expect(dead_code, reason = "只在 Windows 上说"))]
    pub bad_log_size_env: fn(&str, u64) -> String,
    pub no_state_dir: &'static str,

    pub state_dir: &'static str,
    pub port: &'static str,
    pub declared: &'static str,
    pub exit: &'static str,
    pub relay: &'static str,
    pub relay_address: &'static str,
    pub not_joined: &'static str,
    pub network: &'static str,
    pub netmap: fn(u64, usize, usize) -> String,
    pub running: fn(&str, &str) -> String,
    pub link_static: &'static str,
    pub link_online: &'static str,
    pub link_offline: &'static str,
    pub link_revoked: &'static str,
    pub link_rejected: &'static str,
    pub netmap_version: fn(u64) -> String,
    pub flows: &'static str,
    pub endpoints: &'static str,
    pub nat: &'static str,
    pub mapping_varies: &'static str,
    pub attached: &'static str,
    pub relay_counts: fn(u64, u64, &str, u64) -> String,
    pub update: &'static str,
    pub state: &'static str,
    pub draining: &'static str,
    pub quota: &'static str,
    pub listeners: &'static str,
    pub listeners_header: [&'static str; 5],
    pub listening: &'static str,
    pub listening_on: fn(&str) -> String,
    pub on_virtual_ip: &'static str,
    pub not_bound: &'static str,
    pub lanes: &'static str,
    pub lanes_header: [&'static str; 9],
    pub dial: &'static str,
    pub accept: &'static str,
    pub up: &'static str,
    pub down: &'static str,
    pub handshake_failures: fn(u64, u64, u64, u64, u64, u64) -> String,
    pub routes: &'static str,
    pub routes_header: [&'static str; 6],
    pub no_peers: &'static str,
    pub update_record_unreadable: &'static str,
    pub profile: &'static str,
    /// 在用的档位和工作线程数。
    pub profile_running: fn(&str, u32) -> String,
    pub restart_pending: &'static str,
    pub cannot_self_update: &'static str,

    /// 虚拟网卡那一行的名字。
    pub vnet: &'static str,
    /// 虚拟网卡收发了多少包和字节：发出的包，收进的包，流量，丢掉的包。
    pub vnet_traffic: fn(u64, u64, &str, u64) -> String,
}

/// `i3t network status`、`i3t hosts`，和 `i3t set network|firewall off` 之后说的话。
#[derive(Debug)]
pub struct Net {
    pub device: &'static str,
    pub guard_rule: &'static str,
    /// 一条 raw 表 PREROUTING 链里的防冒充规则：第几条，规则管的是什么（`! -i i3t0 -s 10.66.0.0/16`）。
    pub guard_at: fn(usize, &str) -> String,
    /// 没有 nft，raw 表里也没有防冒充的规则。
    pub guard_none: &'static str,
    pub accept_rule: &'static str,
    /// 一条 INPUT 规则：网卡，第几条。
    pub accept_at: fn(&str, usize) -> String,
    /// 没有 iptables 的机器上不加放行的那条。
    pub accept_not_needed: &'static str,
    pub legacy: &'static str,
    pub unreadable: fn(&str) -> String,
    pub nothing_installed: &'static str,
    pub leftover: &'static str,
    pub leftover_removed: fn(usize) -> String,
    pub leftover_remove_failed: &'static str,
    pub cleanup_nothing: &'static str,
    pub cleanup_no_privilege: fn(&str) -> String,
    pub hosts_written: fn(usize, &str) -> String,
    /// 写 hosts 文件失败：文件，要用管理员权限再执行的命令。
    pub hosts_write_failed: fn(&str, &str) -> String,
    pub hosts_removed: fn(&str) -> String,
    pub hosts_no_block: fn(&str) -> String,
    /// 虚拟网卡没装着，hosts 文件里还有 `i3t hosts --apply` 写的名字。
    pub hosts_left: fn(&str) -> String,
}

/// Windows 上装成系统服务之后说的话。参数都是服务的名字。
#[cfg(windows)]
#[derive(Debug)]
pub struct Service {
    pub installed: fn(&str) -> String,
    pub uninstalled: fn(&str) -> String,
    /// 在终端里执行 `i3t run`，而这个节点是由系统服务运行的。
    pub run_is_service: fn(&str) -> String,
    pub needs_admin: &'static str,
    /// `i3t run --service` 不是服务控制管理器启动的。
    pub not_started_by_system: &'static str,
}

/// `i3t tune` 说的话。这个命令只在 Linux 上做事，别的平台上只说一句只有 Linux 有（[`Ui::tune_linux_only`]），
/// 这些文字也就只在 Linux 上编进去。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Linux {
    pub tune_title: fn(&str) -> String,
    pub tune_header: [&'static str; 5],
    pub tune_fine: &'static str,
    pub tune_change: &'static str,
    pub tune_skipped: &'static str,
    pub tune_missing: &'static str,
    pub tune_rmem: &'static str,
    pub tune_wmem: &'static str,
    pub tune_slow_start: &'static str,
    pub tune_tw_reuse: &'static str,
    pub tune_mtu_probing: &'static str,
    pub tune_mtu_probe_floor: &'static str,
    pub tune_bbr: &'static str,
    pub tune_no_bbr: &'static str,
    pub tune_reserved: &'static str,
    pub tune_write_failed: fn(&str) -> String,
    pub tune_file_header: &'static str,
    pub tune_nothing: &'static str,
    pub tune_wanted: fn(usize, &str) -> String,
    pub tune_read_failed: fn(&str) -> String,
    pub tune_persist_failed: fn(&str) -> String,
    pub tune_changed: fn(usize, &str) -> String,
    pub tune_files: fn(u64, u64) -> String,
    pub tune_files_low: &'static str,
    pub tune_files_unknown: fn(&str) -> String,
    pub tune_rto_cap: &'static str,
    pub tune_no_rto_cap: &'static str,
}

static ZH: Texts = Texts {
    help: Help {
        about: "ice3tier 节点",
        state_dir: "状态目录：密钥、配置文件和缓存",
        join: "用注册令牌加入网络。令牌从标准输入读：echo <令牌> | i3t join",
        can_exit: "声明可以作为出口",
        can_relay: "声明可以作为中继（要有别的节点连得上的端口）",
        run: "运行节点",
        run_static: "测试用：从这个 JSON 文件读 netmap，不连 controller",
        set: "修改本机的声明、开关、性能档位和虚拟网卡的 MTU，重启 i3t 后生效",
        status: "节点状态",
        routes: "到各个对端的路由",
        ping: "在到另一个节点的连接上量往返（不是 ICMP），看走的是哪条路",
        ping_node: "节点名、全名或者虚拟 IP",
        ping_count: "量几个往返，1 到 10",
        key: "节点公钥（没有时生成）",
        tune: "检查影响节点的内核参数（Linux），只看不改",
        tune_apply: "写入建议的值并持久化，要 root",
        network: "虚拟网卡",
        network_status: "虚拟网卡的状态，和它在系统里装了什么",
        network_cleanup: "拆掉上次崩溃留下的虚拟网卡防火墙规则（在跑的网卡不动）",
        hosts: "网络里的名字写成 hosts 文件的几行（给没有 systemd-resolved 的机器）",
        hosts_apply: "写进 hosts 文件，只换上次写的那一段，要 root 或管理员",
        hosts_remove: "从 hosts 文件去掉写进去的那一段，要 root 或管理员",
        self_check: "自检：读配置和状态，和 controller 握手",
    },
    values: Values { dir: "目录", file: "文件", node: "节点", count: "次数" },
    ui: Ui {
        none: "没有",
        unknown: "未知",
        period: "。",
        bad_version: "这个程序的版本号不合法",
        read_token: "从标准输入读注册令牌",
        joined: |network| format!("已加入网络 {network}"),
        node: "节点",
        fqdn: "域名",
        virtual_ip: "虚拟 IP",
        config_file: "配置文件",
        start_with_run: "启动：i3t run",
        start_service: |service| format!("启动服务 {service}…"),
        start_runtime: "启动运行时",
        setting_set: |setting, state| format!("{setting} 已设为 {state}，重启 i3t 后生效"),
        declare_hint: "声明本身不启用任何东西：要管理员在 WebUI 上启用。",
        forward_by_admin: "端口转发的目标不用在本机声明：由管理员打开（i3tctl node set <节点> --forward-target on）。这一项没有改动。",
        profile_chosen: |profile| format!("controller 给这个节点选了 {profile}，以它为准。"),
        not_running: "节点没有在运行（上面是本机的配置）",
        routes_not_running: "节点没有在运行：先 i3t run",
        ping_summary: |sent, received, min, avg, max| {
            format!("{sent} 个往返，回来 {received} 个，丢 {}：最短 {min}，平均 {avg}，最长 {max}", sent.saturating_sub(received))
        },
        ping_all_lost: |sent| format!("{sent} 个往返都没有回来"),
        ping_route_changed: |start, end| format!("{start} → {end}"),
        ping_unknown_node: |node| format!("本节点的配置里没有 {node}：没有这个节点，或者访问规则没有把它和本节点连起来"),
        ping_myself: "这是本节点自己",
        ping_not_allowed: |node| format!("访问规则不允许本节点访问 {node}（只允许它访问本节点）"),
        ping_refused: |node| format!("{node} 拒绝了：它那边的访问规则不允许本节点访问它"),
        ping_unreachable: |node| format!("连不上 {node}：它不在线，或者没有路"),
        ping_connect_timeout: |node| format!("到 {node} 的连接没有及时建起来，稍后再试"),
        ping_unsupported: |node| format!("{node} 的版本太旧，不回答 ping"),
        ping_busy: "本节点上另一个 ping 正在做，稍后再试",
        ping_unknown: |node| format!("{node}：节点给了一个这个版本不认识的结论"),
        self_check_passed: |version| format!("自检通过：i3t {version}"),
        wrong_version: |running, expected| format!("这个程序是 {running}，清单上是 {expected}"),
        state_unreadable: |reason| format!("读不了配置和状态：{reason}"),
        handshake_failed: |reason| format!("和 controller 握手失败：{reason}"),
        handshake_timeout: |secs| format!("{secs} 秒内没有和 controller 握手成功"),
        tune_linux_only: "i3t tune 只支持 Linux",
        bad_log_env: |filter, error, level| format!("I3T_LOG 的值 {filter:?} 不对（{error}），用配置文件里的 {level}"),
        bad_log_size_env: |size, default| {
            format!("I3T_LOG_MAX_SIZE 的值 {size:?} 不对（要字节数，可以带 K、M、G，比如 64M），用默认的 {default} MiB")
        },
        no_state_dir: "找不到放状态目录的位置：用 --state-dir 指定",

        state_dir: "状态目录",
        port: "端口",
        declared: "声明",
        exit: "出口",
        relay: "中继",
        relay_address: "中继地址",
        not_joined: "还没有加入网络：在 WebUI 的“添加节点”里生成注册令牌，然后 echo <令牌> | i3t join",
        network: "网络",
        netmap: |version, peers, relays| format!("第 {version} 版，{peers} 个对端，{relays} 个中继"),
        running: |version, uptime| format!("正在运行 i3t {version}，已运行 {uptime}"),
        link_static: "静态模式，不连 controller",
        link_online: "已连接",
        link_offline: "未连接，按手上的配置运行，正在重连",
        link_revoked: "已被吊销",
        link_rejected: "不被接受，要重新加入网络",
        netmap_version: |version| format!("第 {version} 版"),
        flows: "流",
        endpoints: "候选端点",
        nat: "NAT",
        mapping_varies: "端口映射随对端变化，打不了洞",
        attached: "挂靠",
        relay_counts: |sessions, packets, bytes, dropped| format!("{sessions} 个会话，转发 {packets} 个包（{bytes}），丢弃 {dropped} 个"),
        update: "更新",
        state: "状态",
        draining: "正在排空：不接新的流",
        quota: "流量配额",
        listeners: "监听",
        listeners_header: ["名字", "监听地址", "连接", "流量", "状态"],
        listening: "监听中",
        listening_on: |local| format!("监听在 {local}"),
        on_virtual_ip: "在虚拟 IP 上",
        not_bound: "没有绑上",
        lanes: "ice3proxy（只承载 TCP 流；共用的连接照常在，它的路见路由）",
        lanes_header: ["对端", "角色", "控制连接", "空闲", "使用中", "取用（等待）", "回退", "拨号失败", "流量"],
        dial: "拨号",
        accept: "被拨",
        up: "在",
        down: "不在",
        handshake_failures: |total, deadline, unknown_key, tls, protocol, busy| {
            format!("拨进来没握手成功 {total} 次：超时 {deadline}，不认识的公钥 {unknown_key}，TLS {tls}，协议 {protocol}，太多 {busy}")
        },
        routes: "路由",
        routes_header: ["对端", "虚拟 IP", "路", "延迟 ms", "直连", "换上"],
        no_peers: "没有对端：配置里没有和它有访问关系的节点",
        update_record_unreadable: "更新的记录读不了",
        profile: "性能档位",
        profile_running: |profile, threads| format!("{profile}，{threads} 个工作线程"),
        restart_pending: "重启后才全部生效",
        cannot_self_update: "不能自己更新",

        vnet: "虚拟网卡",
        vnet_traffic: |sent, received, traffic, dropped| format!("发 {sent} 包，收 {received} 包，{traffic}，丢 {dropped} 包"),
    },
    network: Net {
        device: "网卡",
        guard_rule: "防冒充的规则",
        guard_at: |position, rule| format!("raw PREROUTING 的第 {position} 条，{rule}"),
        guard_none: "没有：没有 nft，raw PREROUTING 里也没有",
        accept_rule: "放行的规则",
        accept_at: |device, position| format!("-i {device}，INPUT 的第 {position} 条"),
        accept_not_needed: "不需要：这台机器上没有 iptables",
        legacy: "以前的透明访问留下的",
        unreadable: |error| format!("读不了（要 root）：{error}"),
        nothing_installed: "系统里没有虚拟网卡装的东西",
        leftover: "节点没在运行，这些是上次留下的：下次启动时换掉，i3t network cleanup 现在就拆掉",
        leftover_removed: |count| format!("拆掉了上次留下的 {count} 条规则"),
        leftover_remove_failed: "上次留下的规则拆不掉（要 root 或管理员）",
        cleanup_nothing: "系统里没有虚拟网卡留下的规则",
        cleanup_no_privilege: |missing| format!("没有清理防火墙规则的权限（缺 {missing}）"),
        hosts_written: |count, path| format!("{path} 里写了 {count} 个名字"),
        hosts_write_failed: |path, command| format!("写 {path}：要 root 或管理员，sudo {command}"),
        hosts_removed: |path| format!("从 {path} 去掉了 i3t hosts 写的那一段"),
        hosts_no_block: |path| format!("{path} 里没有 i3t hosts 写的那一段"),
        hosts_left: |path| format!("{path} 里还有 i3t hosts --apply 写的名字，虚拟网卡没装时它们不通：i3t hosts --remove 去掉"),
    },
    #[cfg(windows)]
    service: Service {
        installed: |name| format!("已登记系统服务 {name}，开机自动启动"),
        uninstalled: |name| format!("已注销系统服务 {name}"),
        run_is_service: |name| format!("节点已装成系统服务，由它运行：Start-Service {name}"),
        needs_admin: "操作系统服务失败（要以管理员身份运行）",
        not_started_by_system: "--service 只在由 Windows 的服务管理器启动时使用",
    },
    #[cfg(target_os = "linux")]
    linux: Linux {
        tune_title: |kernel| format!("内核参数（Linux {kernel}）"),
        tune_header: ["结论", "参数", "现在", "建议", "原因"],
        tune_fine: "正常",
        tune_change: "建议修改",
        tune_skipped: "没有检查",
        tune_missing: "内核没有这个参数",
        tune_rmem: "UDP 接收缓冲的上限：节点申请 4 MB，默认值常常只有 200 KB，突发的包会被丢掉",
        tune_wmem: "UDP 发送缓冲的上限，同上",
        tune_slow_start: "经过节点的 TCP 连接空闲之后不收回发送窗口，流式应答停顿之后不用重新慢启动",
        tune_tw_reuse: "开了 ice3proxy 时连接用完就关，TIME_WAIT 会占满本地端口；1 让拨出的连接复用它们",
        tune_mtu_probing: "以前的 i3t tune 打开的。丢包的线路上，内核把连续几次重传超时当成路径 MTU 黑洞，每次把 TCP 的分段减半（最小 48 字节），很难加回去，传输变慢甚至中断。节点自己的 TCP 已经压低了 MSS，不靠它",
        tune_mtu_probe_floor: "路径 MTU 黑洞探测开着（tcp_mtu_probing 不是 0）：丢包的线路上，内核把连续几次重传超时当成黑洞，每次把 TCP 的分段减半，减到这个下限。默认的 48 字节让连接几乎传不动",
        tune_bbr: "经过节点的 TCP 连接在有丢包的链路上用 BBR 快得多（节点之间的 QUIC 不受影响）",
        tune_no_bbr: "内核没有加载 bbr：先 modprobe tcp_bbr，再运行 i3t tune",
        tune_reserved: "节点的端口在随机分配的出站端口范围里，重启时可能被别的程序占用",
        tune_write_failed: |key| format!("写 {key} 失败：要 root，sudo i3t tune --apply"),
        tune_file_header: "由 i3t tune --apply 写入，原因见 i3t tune 的输出。",
        tune_nothing: "没有要改的",
        tune_wanted: |count, file| format!("{count} 项建议修改。sudo i3t tune --apply：立即生效，并写进 {file}"),
        tune_read_failed: |file| format!("读不了 {file}，什么都没改"),
        tune_persist_failed: |file| format!("已经生效，但写 {file} 失败，重启后会恢复"),
        tune_changed: |count, file| format!("改了 {count} 项，已生效，已写进 {file}"),
        tune_files: |soft, hard| format!("能同时打开的文件数：软上限 {soft}，硬上限 {hard}。i3t run 启动时会把软上限抬到硬上限"),
        tune_files_low: "硬上限偏低，流多的出口和中继可能不够用：系统服务的 LimitNOFILE 管它。",
        tune_files_unknown: |error| format!("能同时打开的文件数：读不到（{error}）"),
        tune_rto_cap: "TCP 重传上限：支持。ice3proxy 和 TCP 中转断网之后，路一通最多 2 秒就恢复",
        tune_no_rto_cap: "TCP 重传上限：这个内核不支持（Linux 6.15 起才有）。ice3proxy 和 TCP 中转断网之后恢复得慢，最多要再等断开时长的一半",
    },
};

static EN: Texts = Texts {
    help: Help {
        about: "ice3tier node",
        state_dir: "State directory: key, configuration and cache",
        join: "Join a network with an enrollment token read from stdin: echo <TOKEN> | i3t join",
        can_exit: "Declare it can be an exit",
        can_relay: "Declare it can be a relay (needs a port other nodes can reach)",
        run: "Run the node",
        run_static: "For tests: read the netmap from this JSON file instead of the controller",
        set: "Change local declarations, switches, the performance profile and the virtual adapter's MTU; restart i3t to apply",
        status: "Node status",
        routes: "Routes to peers",
        ping: "Measure round trips over the connection to another node (not ICMP) and show its route",
        ping_node: "Node name, full name or virtual IP",
        ping_count: "How many round trips, 1 to 10",
        key: "Node public key (generated if missing)",
        tune: "Check kernel parameters that affect the node (Linux); read-only",
        tune_apply: "Apply and persist the suggested values; needs root",
        network: "Virtual network adapter",
        network_status: "Virtual adapter state and what it installed in the system",
        network_cleanup: "Remove leftover virtual adapter firewall rules from an earlier run (running adapters are untouched)",
        hosts: "Names in the network as hosts-file lines (for machines without systemd-resolved)",
        hosts_apply: "Write them into the hosts file, replacing only the block written last time; needs root or administrator",
        hosts_remove: "Remove that block from the hosts file; needs root or administrator",
        self_check: "Self-check: read configuration and state, handshake with the controller",
    },
    values: Values { dir: "DIR", file: "FILE", node: "NODE", count: "COUNT" },
    ui: Ui {
        none: "None",
        unknown: "unknown",
        period: ".",
        bad_version: "This program's version is invalid",
        read_token: "Reading the enrollment token from stdin",
        joined: |network| format!("Joined network {network}"),
        node: "Node",
        fqdn: "DNS name",
        virtual_ip: "Virtual IP",
        config_file: "Configuration",
        start_with_run: "Start it: i3t run",
        start_service: |service| format!("Starting service {service}…"),
        start_runtime: "Starting the runtime",
        setting_set: |setting, state| format!("{setting} set to {state}; restart i3t to apply"),
        declare_hint: "Declaring enables nothing: an admin enables it in the WebUI.",
        forward_by_admin: "A port forward target isn't declared here: an admin switches it on (i3tctl node set <node> --forward-target on). Nothing changed.",
        profile_chosen: |profile| format!("The controller chose {profile} for this node; that one applies."),
        not_running: "Node not running (above: local configuration)",
        routes_not_running: "Node not running: start it with i3t run",
        ping_summary: |sent, received, min, avg, max| {
            format!("{sent} round trips, {received} back, {} lost: min {min}, avg {avg}, max {max}", sent.saturating_sub(received))
        },
        ping_all_lost: |sent| format!("None of {sent} round trips came back"),
        ping_route_changed: |start, end| format!("{start} → {end}"),
        ping_unknown_node: |node| format!("{node} isn't in this node's configuration: no such node, or no access rule connects them"),
        ping_myself: "That is this node",
        ping_not_allowed: |node| format!("Access rules don't allow this node to reach {node} (only the other way)"),
        ping_refused: |node| format!("{node} refused: its access rules don't allow this node"),
        ping_unreachable: |node| format!("Can't reach {node}: offline, or no path"),
        ping_connect_timeout: |node| format!("The connection to {node} didn't come up in time; try again"),
        ping_unsupported: |node| format!("{node} is too old to answer pings"),
        ping_busy: "Another ping is running on this node; try again shortly",
        ping_unknown: |node| format!("{node}: the node gave an answer this version doesn't know"),
        self_check_passed: |version| format!("Self-check passed: i3t {version}"),
        wrong_version: |running, expected| format!("This program is {running}, the manifest says {expected}"),
        state_unreadable: |reason| format!("Can't read configuration and state: {reason}"),
        handshake_failed: |reason| format!("Handshake with the controller failed: {reason}"),
        handshake_timeout: |secs| format!("No handshake with the controller within {secs} s"),
        tune_linux_only: "i3t tune supports Linux only",
        bad_log_env: |filter, error, level| format!("I3T_LOG value {filter:?} is invalid ({error}); using {level} from the configuration"),
        bad_log_size_env: |size, default| {
            format!(
                "I3T_LOG_MAX_SIZE value {size:?} is invalid (a number of bytes, optionally with K, M or G, such as 64M); using the default, {default} MiB"
            )
        },
        no_state_dir: "No place for the state directory: give one with --state-dir",

        state_dir: "State directory",
        port: "Port",
        declared: "Declared",
        exit: "exit",
        relay: "relay",
        relay_address: "Relay address",
        not_joined: "Not joined yet: create an enrollment token under \"Add node\" in the WebUI, then echo <TOKEN> | i3t join",
        network: "Network",
        netmap: |version, peers, relays| format!("v{version}, peers {peers}, relays {relays}"),
        running: |version, uptime| format!("Running i3t {version}, up {uptime}"),
        link_static: "static mode, no controller",
        link_online: "connected",
        link_offline: "disconnected; running on the last settings, reconnecting",
        link_revoked: "revoked",
        link_rejected: "rejected; join again",
        netmap_version: |version| format!("v{version}"),
        flows: "Flows",
        endpoints: "Endpoints",
        nat: "NAT",
        mapping_varies: "Port mapping varies by peer; no hole punching",
        attached: "Attached",
        relay_counts: |sessions, packets, bytes, dropped| {
            format!("sessions {sessions}, packets forwarded {packets} ({bytes}), dropped {dropped}")
        },
        update: "Update",
        state: "State",
        draining: "Draining: no new flows",
        quota: "Traffic quota",
        listeners: "Listeners",
        listeners_header: ["NAME", "LISTEN", "CONNECTIONS", "TRAFFIC", "STATE"],
        listening: "listening",
        listening_on: |local| format!("Listening on {local}"),
        on_virtual_ip: "On the virtual IP",
        not_bound: "Not bound",
        lanes: "ice3proxy (TCP flows only; the shared connection stays, its route is under Routes)",
        lanes_header: ["PEER", "ROLE", "CONTROL", "IDLE", "IN-USE", "CLAIMS (WAITED)", "FALLBACKS", "DIAL-FAILURES", "TRAFFIC"],
        dial: "dials",
        accept: "dialled",
        up: "up",
        down: "down",
        handshake_failures: |total, deadline, unknown_key, tls, protocol, busy| {
            format!(
                "Incoming handshakes failed: {total} (timeout {deadline}, unknown key {unknown_key}, TLS {tls}, protocol {protocol}, too many {busy})"
            )
        },
        routes: "Routes",
        routes_header: ["PEER", "VIRTUAL-IP", "ROUTE", "RTT-MS", "DIRECT", "SINCE"],
        no_peers: "No peers: no node in the configuration can reach this one",
        update_record_unreadable: "Update record unreadable",
        profile: "Profile",
        profile_running: |profile, threads| format!("{profile}, worker threads: {threads}"),
        restart_pending: "fully applies after a restart",
        cannot_self_update: "Can't update itself",

        vnet: "Virtual network",
        vnet_traffic: |sent, received, traffic, dropped| format!("packets sent {sent}, received {received}, {traffic}, dropped {dropped}"),
    },
    network: Net {
        device: "Adapter",
        guard_rule: "Anti-spoofing rule",
        guard_at: |position, rule| format!("raw PREROUTING rule {position}, {rule}"),
        guard_none: "none: no nft, and none in raw PREROUTING",
        accept_rule: "Accept rule",
        accept_at: |device, position| format!("-i {device}, INPUT rule {position}"),
        accept_not_needed: "not needed: this machine has no iptables",
        legacy: "Left by the old transparent access",
        unreadable: |error| format!("unreadable (needs root): {error}"),
        nothing_installed: "Nothing from the virtual adapter in the system",
        leftover: "Node not running; these are left from the last run: the next start replaces them, i3t network cleanup removes them now",
        leftover_removed: |count| format!("Removed rules left from the last run: {count}"),
        leftover_remove_failed: "Can't remove rules left from the last run (needs root or administrator)",
        cleanup_nothing: "No leftover virtual adapter rules to remove",
        cleanup_no_privilege: |missing| format!("No privilege to remove firewall rules (missing {missing})"),
        hosts_written: |count, path| format!("Names written to {path}: {count}"),
        hosts_write_failed: |path, command| format!("Writing {path}: needs root or administrator, sudo {command}"),
        hosts_removed: |path| format!("Removed the i3t hosts block from {path}"),
        hosts_no_block: |path| format!("No i3t hosts block in {path}"),
        hosts_left: |path| {
            format!("{path} still has names from i3t hosts --apply, which don't work without the virtual adapter: i3t hosts --remove")
        },
    },
    #[cfg(windows)]
    service: Service {
        installed: |name| format!("Registered system service {name}; it starts at boot"),
        uninstalled: |name| format!("Removed system service {name}"),
        run_is_service: |name| format!("The node is installed as a system service, which runs it: Start-Service {name}"),
        needs_admin: "Changing the system service failed (run as administrator)",
        not_started_by_system: "--service is only for the Windows service manager",
    },
    #[cfg(target_os = "linux")]
    linux: Linux {
        tune_title: |kernel| format!("Kernel parameters (Linux {kernel})"),
        tune_header: ["VERDICT", "PARAMETER", "CURRENT", "SUGGESTED", "REASON"],
        tune_fine: "ok",
        tune_change: "change",
        tune_skipped: "skipped",
        tune_missing: "not in this kernel",
        tune_rmem: "UDP receive buffer cap: the node asks for 4 MB, defaults are often 200 KB and bursts get dropped",
        tune_wmem: "UDP send buffer cap, same as above",
        tune_slow_start: "TCP connections through the node keep their window after idling; streamed replies don't restart slowly",
        tune_tw_reuse: "With ice3proxy each connection closes after use and TIME_WAIT fills local ports; 1 lets outgoing ones reuse them",
        tune_mtu_probing: "Switched on by an earlier i3t tune. On lossy lines the kernel takes repeated retransmission timeouts for a path-MTU black hole and halves the TCP segment size each time (down to 48 bytes); it rarely grows back, so transfers crawl or break. The node's own TCP already uses a lower MSS and doesn't need it",
        tune_mtu_probe_floor: "Path-MTU black hole probing is on (tcp_mtu_probing isn't 0): on lossy lines the kernel takes repeated retransmission timeouts for a black hole and halves the TCP segment size each time, down to this floor. At the default of 48 bytes a connection barely moves",
        tune_bbr: "TCP connections through the node are much faster with BBR on lossy links (QUIC between nodes is unaffected)",
        tune_no_bbr: "bbr isn't loaded: run modprobe tcp_bbr, then i3t tune again",
        tune_reserved: "The node's port is inside the ephemeral range; another program may take it during a restart",
        tune_write_failed: |key| format!("Writing {key} failed: needs root, sudo i3t tune --apply"),
        tune_file_header: "Written by i3t tune --apply; see i3t tune for the reasons.",
        tune_nothing: "Nothing to change",
        tune_wanted: |count, file| format!("Changes suggested: {count}. sudo i3t tune --apply applies them now and writes {file}"),
        tune_read_failed: |file| format!("Couldn't read {file}; nothing changed"),
        tune_persist_failed: |file| format!("Applied, but writing {file} failed; a reboot reverts them"),
        tune_changed: |count, file| format!("Changed {count}, applied and written to {file}"),
        tune_files: |soft, hard| {
            format!("Open files: soft limit {soft}, hard limit {hard}. i3t run raises the soft limit to the hard limit")
        },
        tune_files_low: "The hard limit is low for busy exits and relays: LimitNOFILE in the service sets it.",
        tune_files_unknown: |error| format!("Open files: unknown ({error})"),
        tune_rto_cap: "TCP retransmission cap: supported. ice3proxy and TCP relay legs resume within 2 s once a blackout ends",
        tune_no_rto_cap: "TCP retransmission cap: not supported by this kernel (Linux 6.15+). After a blackout, ice3proxy and TCP relay legs \
                          resume late, up to half the blackout's length",
    },
};

#[cfg(test)]
mod tests {
    use i3t_lang::cli::plural_after_one;

    use super::*;

    #[test]
    fn english_counts_read_right_for_one() {
        let ui = &EN.ui;
        let said = [
            (ui.netmap)(1, 1, 1),
            (ui.relay_counts)(1, 1, "1 B", 1),
            (ui.handshake_failures)(1, 1, 1, 1, 1, 1),
            (ui.profile_running)("balanced", 1),
            (ui.vnet_traffic)(1, 1, "↑ 1 B  ↓ 1 B", 1),
            (EN.network.hosts_written)(1, "/etc/hosts"),
            (EN.network.leftover_removed)(1),
            (ui.handshake_timeout)(1),
        ];
        for text in said {
            assert_eq!(plural_after_one(&text), None, "{text}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn english_counts_of_the_linux_commands_read_right_for_one() {
        let linux = &EN.linux;
        let said = [
            (linux.tune_wanted)(1, "/etc/sysctl.d/90-i3t.conf"),
            (linux.tune_changed)(1, "/etc/sysctl.d/90-i3t.conf"),
            (linux.tune_files)(1, 1),
        ];
        for text in said {
            assert_eq!(plural_after_one(&text), None, "{text}");
        }
    }
}
