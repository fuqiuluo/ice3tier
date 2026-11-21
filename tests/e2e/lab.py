"""本机的端到端测试环境：用网络命名空间搭一个小"互联网"。

不需要 root。测试进程先用 `unshare -Urnm` 进入自己的用户命名空间（见 `enter`），之后的命名空间、网卡、NAT 规则
都只存在于这个进程树里，进程退出就全部消失。

拓扑的样子：

    公网主机 ─┐
    公网主机 ─┼─ core（路由器，相当于互联网）
    NAT 路由器 ┘        │
       └─ 内网主机      └─ 每条线可以加延迟、丢包、限速

- `Lab.host(name)`：一台有公网地址的主机。
- `Lab.nat(name, kind)`：一个 NAT 路由器，`kind` 决定它的行为；`Nat.host(name)` 是它后面的一台内网主机。
- 主机上用 `Host.run` / `Host.spawn` 执行命令。

需要系统里有 ip、tc、nft。
"""

from __future__ import annotations

import dataclasses
import enum
import ipaddress
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator, Sequence

IN_LAB_ENV = "I3T_E2E_LAB"


def enter() -> None:
    """不在测试用的命名空间里时，换进去重新执行自己。在脚本最开头调用。"""
    if os.environ.get(IN_LAB_ENV) == "1":
        return
    env = {**os.environ, IN_LAB_ENV: "1"}
    os.execvpe("unshare", ["unshare", "-Urnm", sys.executable, *sys.argv], env)


def sh(*cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


class NatKind(enum.Enum):
    """NAT 路由器的行为。"""

    # 同一个内网地址和端口，不管发往哪里，映射出来的公网端口都一样；只放行自己发过包的对端回来的包。
    # 家用路由器大多是这种，两边都是这种时可以打洞。
    CONE = "cone"
    # 每个目的地址映射到不同的随机端口。对端猜不到端口，打不了洞。
    SYMMETRIC = "symmetric"


@dataclasses.dataclass(frozen=True)
class Shape:
    """一条线上的网络条件，两个方向相同。`rtt_ms` 是往返延迟。"""

    rtt_ms: float = 0
    loss_pct: float = 0
    rate_mbit: float = 0

    def netem_args(self) -> list[str]:
        args = ["delay", f"{self.rtt_ms / 2:g}ms"]
        if self.loss_pct:
            args += ["loss", f"{self.loss_pct:g}%"]
        if self.rate_mbit:
            packets_per_sec = self.rate_mbit * 1e6 / (1500 * 8)
            # 队列里同时装着"还在延迟中的包"和"等带宽的包"，给后者留 100ms 的量。
            limit = int(packets_per_sec * (self.rtt_ms / 2000 + 0.1)) + 50
            args += ["rate", f"{self.rate_mbit:g}mbit", "limit", str(limit)]
        return args


class Host:
    """一个网络命名空间里的一台"机器"。"""

    def __init__(self, lab: "Lab", name: str, ip: str) -> None:
        self.lab = lab
        self.name = name
        self.ip = ip
        self._procs: list[subprocess.Popen] = []

    def cmd(self, *args: str) -> list[str]:
        return ["ip", "netns", "exec", self.name, *args]

    def run(self, *args: str, check: bool = True, input: str | None = None, timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run(self.cmd(*args), check=check, capture_output=True, text=True, input=input, timeout=timeout)

    def spawn(self, *args: str, log: Path | None = None, env: dict[str, str] | None = None) -> subprocess.Popen:
        """在后台启动一个进程，实验环境关闭时会被停掉。"""
        out = log.open("w") if log else subprocess.DEVNULL
        proc = subprocess.Popen(self.cmd(*args), stdout=out, stderr=subprocess.STDOUT, env={**os.environ, **(env or {})})
        self._procs.append(proc)
        return proc

    def stop(self, proc: subprocess.Popen, sig: int = signal.SIGTERM, wait: float = 5) -> None:
        if proc.poll() is None:
            proc.send_signal(sig)
            try:
                proc.wait(timeout=wait)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if proc in self._procs:
            self._procs.remove(proc)

    def stop_all(self) -> None:
        for proc in list(self._procs):
            self.stop(proc)

    def shape(self, shape: Shape | None) -> None:
        """改这台主机上联那条线的网络条件。`None` 表示去掉所有限制。"""
        self.lab.shape(self.name, "up0", shape)

    def block_udp(self, blocked: bool = True, except_with: "Host | None" = None) -> None:
        """模拟一个用不了 UDP 的网络：这台主机发出和收到的 UDP 全部丢掉。回环和节点的虚拟网卡除外：
        用不了 UDP 的是外面的网络，经虚拟网卡走的 UDP 在外面看是节点之间的连接（这时经 TCP 中转）。

        `except_with`：和这一台主机之间的 UDP 照常通。真实的例子是一个机房的 UDP 到大多数地方都不通，到个别对端却打得通。"""
        self.run("nft", "delete", "table", "inet", "noudp", check=False)
        if blocked:
            spared_out = f"ip daddr {except_with.ip} accept" if except_with else ""
            spared_in = f"ip saddr {except_with.ip} accept" if except_with else ""
            rules = f"""
table inet noudp {{
    chain out {{
        type filter hook output priority filter;
        {spared_out}
        oifname "i3t*" accept
        oifname != "lo" meta l4proto udp drop
    }}
    chain in {{
        type filter hook input priority filter;
        {spared_in}
        iifname "i3t*" accept
        iifname != "lo" meta l4proto udp drop
    }}
}}
"""
            self.run("nft", "-f", "-", input=rules)


class Nat(Host):
    """一个 NAT 路由器。它自己也是一台主机（公网一侧的地址是 `ip`）。"""

    def __init__(self, lab: "Lab", name: str, ip: str, kind: NatKind, lan: ipaddress.IPv4Network) -> None:
        super().__init__(lab, name, ip)
        self.kind = kind
        self.lan = lan
        self._next_host = 10

    def host(self, name: str) -> Host:
        """在这个 NAT 后面加一台内网主机。同一个 NAT 后面的主机在同一个局域网里。"""
        ip = str(self.lan.network_address + self._next_host)
        self._next_host += 1
        self.lab._add_namespace(name)
        # 每台内网主机一对 veth，路由器这一头都挂在网桥 lan0 上。
        port = f"l-{name}"[:15]
        sh("ip", "link", "add", "up0", "netns", name, "type", "veth", "peer", "name", port, "netns", self.name)
        sh("ip", "-n", self.name, "link", "set", port, "master", "lan0")
        sh("ip", "-n", self.name, "link", "set", port, "up")
        sh("ip", "-n", name, "addr", "add", f"{ip}/{self.lan.prefixlen}", "dev", "up0")
        sh("ip", "-n", name, "link", "set", "up0", "up")
        sh("ip", "-n", name, "route", "add", "default", "via", str(self.lan.network_address + 1))
        host = Host(self.lab, name, ip)
        self.lab.hosts[name] = host
        return host

    def forward_port(self, proto: str, port: int, to: Host) -> None:
        """在路由器上做一条端口转发：公网一侧的 `port` 转给内网主机 `to` 的同一个端口。"""
        self.run("nft", "add", "rule", "ip", "nat", "pre", "iifname", "up0", proto, "dport", str(port), "dnat", "to", f"{to.ip}:{port}")


class Lab:
    """一个小"互联网"。用完调用 `close`，或者用 `with`。"""

    def __init__(self) -> None:
        # /run/netns 归 root 所有，所以在自己的挂载命名空间里换一个空的 /run。
        sh("mount", "-t", "tmpfs", "tmpfs", "/run")
        os.mkdir("/run/netns")
        self.hosts: dict[str, Host] = {}
        self._next_public = 1
        self._next_lan = 1
        self._add_namespace("core")
        sh("ip", "netns", "exec", "core", "sysctl", "-qw", "net.ipv4.ip_forward=1")

    def __enter__(self) -> "Lab":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        for host in self.hosts.values():
            host.stop_all()

    def _add_namespace(self, name: str) -> None:
        sh("ip", "netns", "add", name)
        sh("ip", "-n", name, "link", "set", "lo", "up")

    def _attach_public(self, name: str) -> str:
        """给命名空间 `name` 一条到 core 的线和一个公网地址，返回这个地址。"""
        index = self._next_public
        self._next_public += 1
        # 每台公网主机一个 /30：core 一侧 .1，主机一侧 .2。
        # 地址必须是普通的公网单播地址：出口的出站策略不放行文档、基准测试这类保留地址段。
        # 这些地址只存在于测试自己的命名空间里，不会和真实的互联网混在一起。
        base = ipaddress.IPv4Address("11.0.0.0") + 4 * index
        core_ip, host_ip = str(base + 1), str(base + 2)
        port = f"c-{name}"[:15]
        sh("ip", "link", "add", "up0", "netns", name, "type", "veth", "peer", "name", port, "netns", "core")
        sh("ip", "-n", "core", "addr", "add", f"{core_ip}/30", "dev", port)
        sh("ip", "-n", "core", "link", "set", port, "up")
        sh("ip", "-n", name, "addr", "add", f"{host_ip}/30", "dev", "up0")
        sh("ip", "-n", name, "link", "set", "up0", "up")
        sh("ip", "-n", name, "route", "add", "default", "via", core_ip)
        return host_ip

    def host(self, name: str) -> Host:
        """一台有公网地址的主机。"""
        self._add_namespace(name)
        host = Host(self, name, self._attach_public(name))
        self.hosts[name] = host
        return host

    def nat(self, name: str, kind: NatKind = NatKind.CONE) -> Nat:
        """一个 NAT 路由器，后面是一个局域网。"""
        self._add_namespace(name)
        public_ip = self._attach_public(name)
        lan = ipaddress.IPv4Network(f"192.168.{self._next_lan}.0/24")
        self._next_lan += 1
        sh("ip", "-n", name, "link", "add", "lan0", "type", "bridge")
        sh("ip", "-n", name, "addr", "add", f"{lan.network_address + 1}/{lan.prefixlen}", "dev", "lan0")
        sh("ip", "-n", name, "link", "set", "lan0", "up")
        sh("ip", "netns", "exec", name, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        # Linux 默认的地址伪装会尽量保留源端口，同一个内网端口发往不同目的地时映射相同，相当于 CONE。
        # 加上 random 之后每条流各取一个随机端口，相当于 SYMMETRIC。
        masquerade = "masquerade random" if kind is NatKind.SYMMETRIC else "masquerade"
        rules = f"""
table ip nat {{
    chain pre {{
        type nat hook prerouting priority dstnat;
    }}
    chain post {{
        type nat hook postrouting priority srcnat;
        oifname "up0" {masquerade}
    }}
}}
table ip filter {{
    chain forward {{
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "lan0" accept
        ct status dnat accept
    }}
    chain input {{
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iifname != "up0" accept
        icmp type echo-request accept
    }}
}}
"""
        # 两条链的默认动作都是丢弃：没有对应连接记录的包不许从公网进到内网，也不许进到路由器自己。
        # 后一条不能省。路由器要是收下了一个没人要的包，内核会给它记一条连接；之后内网主机往同一个对端发包时，
        # 原来的端口已经被这条记录占着，映射只好换一个端口，对端就对不上了。真实的家用路由器也是直接丢。
        loaded = subprocess.run(["ip", "netns", "exec", name, "nft", "-f", "-"], input=rules, capture_output=True, text=True)
        if loaded.returncode != 0:
            raise RuntimeError(f"给 {name} 装 NAT 规则失败：{loaded.stderr.strip()}")
        nat = Nat(self, name, public_ip, kind, lan)
        self.hosts[name] = nat
        return nat

    def shape(self, ns: str, dev: str, shape: Shape | None) -> None:
        sh("tc", "-n", ns, "qdisc", "del", "dev", dev, "root", check=False)
        peer = f"c-{ns}"[:15]
        in_core = sh("ip", "-n", "core", "link", "show", peer, check=False).returncode == 0
        if in_core:
            sh("tc", "-n", "core", "qdisc", "del", "dev", peer, "root", check=False)
        if shape is None or shape == Shape():
            return
        sh("tc", "-n", ns, "qdisc", "add", "dev", dev, "root", "netem", *shape.netem_args())
        if in_core:
            sh("tc", "-n", "core", "qdisc", "add", "dev", peer, "root", "netem", *shape.netem_args())


def wait_until(condition, timeout: float = 15, interval: float = 0.2, what: str = "条件") -> None:
    """反复检查直到 `condition()` 为真；超时就抛出异常，说明在等什么。"""
    deadline = time.monotonic() + timeout
    while True:
        if condition():
            return
        if time.monotonic() > deadline:
            raise TimeoutError(f"等了 {timeout:g} 秒，{what} 还没有满足")
        time.sleep(interval)


def chunks(items: Sequence, size: int) -> Iterator[Sequence]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def private_link(lab: Lab, host: Host, name: str, network: str) -> Host:
    """给 `host` 加一块连着一台新机器 `name` 的网卡，像一个只有这两台机器的内网：`network` 里的第一个地址在 `host` 上，
    第二个在新机器上。这个网段和"互联网"无关，可以和覆盖网的地址段重叠（透明访问的重叠检查要用）。"""
    net = ipaddress.IPv4Network(network)
    ours, theirs = net.network_address + 1, net.network_address + 2
    lab._add_namespace(name)
    port = f"p-{name}"[:15]
    sh("ip", "link", "add", port, "netns", host.name, "type", "veth", "peer", "name", "up0", "netns", name)
    sh("ip", "-n", host.name, "addr", "add", f"{ours}/{net.prefixlen}", "dev", port)
    sh("ip", "-n", host.name, "link", "set", port, "up")
    sh("ip", "-n", name, "addr", "add", f"{theirs}/{net.prefixlen}", "dev", "up0")
    sh("ip", "-n", name, "link", "set", "up0", "up")
    other = Host(lab, name, str(theirs))
    lab.hosts[name] = other
    return other


def forward_port_as(nat: Nat, public_port: int, to: Host, port: int) -> None:
    """在路由器上把公网一侧的 `public_port`（UDP 和 TCP）转给内网主机 `to` 的 `port`。和 `Nat.forward_port` 不同，
    两个端口号可以不一样：像机房在另一个端口上映射进来的那种。"""
    for proto in ("udp", "tcp"):
        nat.run("nft", "add", "rule", "ip", "nat", "pre", "iifname", "up0", proto, "dport", str(public_port), "dnat", "to", f"{to.ip}:{port}")


def drop_inbound_udp(host: Host) -> None:
    """这台主机收不到外面来的 UDP（回环除外），发得出去。像一个只放行 TCP 进来的机房。"""
    rules = """
table inet noudpin {
    chain in {
        type filter hook input priority filter;
        iifname != "lo" meta l4proto udp drop
    }
}
"""
    host.run("nft", "-f", "-", input=rules)


def isolate(host: Host, *others: Host) -> None:
    """`host` 和 `others` 之间什么都不通（所有协议、两个方向）：在 `host` 上丢掉发往和来自它们地址的包。可以调用几次，越加越多。
    内网主机的对面要写它所在的 NAT（外面看到的是 NAT 的地址）。"""
    cut = host.__dict__.setdefault("_isolated", set())
    cut.update(other.ip for other in others)
    addresses = ", ".join(sorted(cut))
    host.run("nft", "delete", "table", "inet", "isolate", check=False)
    rules = f"""
table inet isolate {{
    chain out {{
        type filter hook output priority filter;
        ip daddr {{ {addresses} }} drop
    }}
    chain in {{
        type filter hook input priority filter;
        ip saddr {{ {addresses} }} drop
    }}
}}
"""
    host.run("nft", "-f", "-", input=rules)
