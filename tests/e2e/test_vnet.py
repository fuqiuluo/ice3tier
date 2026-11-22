#!/usr/bin/env python3
"""虚拟网卡：每个节点一块，本机的程序用虚拟 IP 访问别的节点，IP 包作为连接上的数据报在节点之间走。

    python3 tests/e2e/test_vnet.py [场景名...]

实验环境的命名空间里没有特权，但在自己的用户和网络命名空间里 TUN 网卡、地址、路由和防火墙规则都建得了，节点就在这里装上、拆掉。
客户端都是不改的程序（ping、curl、dig、Python 的套接字），不经任何代理。

- basics：ping（第一个不丢）、TCP 的客户端和服务按虚拟 IP 和按名字、服务看到的来源是对端的虚拟 IP、50MB 完整、UDP、
  不是节点的地址当场"主机不可达"、没开的端口当场"连接被拒绝"、大的 ping 照通、不许分片的大包得到正确的"太大"、
  状态命令、节点停下之后系统和装之前一样。
- rules：访问规则只允许 a 访问 b：a 发起的照常（TCP、ping、UDP 的问答，比 MTU 大、切成了片的也通），b 发起的连不上；
  对端发来的新会话在本节点被丢掉。
- relay：两个节点之间不通，经 relay：ping 和 20MB。
- tcp_relay：一端用不了 UDP，连接经 relay 的 TCP 中转：ping 和 20MB。
- tcp_relay_flood：同上，那一端的线路只有 2 Mbit/s：两个方向各灌 20 Mbit/s 的 UDP 时，到 relay 的那条 TCP 不被当作断了，
  灌完之后两秒之内 ping 又通。
- nat：两端都在 NAT 后面：ping 和 20MB。
- bundling：直连的两个节点之间一串很密的小包合起来发，线上的包数只有几分之一，一个不丢；网络的开关关着时一个包一个包地发。
- offload：网卡和内核之间一大块一大块地交接（Linux 的分段卸载）：一条 TCP 流在两头的虚拟网卡上只有几分之一的包数，内容一个字节不差；
  内核切的、程序一个个发的 UDP 包都按原样到；一头 `i3t set offload off` 之后那一头一个包一个包地交接，两头照样通。
- firewall：开关开着时，默认拒绝入站的防火墙（iptables 的 INPUT 策略是 DROP）也让别的节点进来；从真网卡来、冒充虚拟 IP 的包被丢掉。
  开关关着时 `nft list ruleset` 和 `iptables-save` 装之前、装着、拆之后都一样，冒充的包照样进来（防火墙由这台机器自己管）。
- privilege：没有 CAP_NET_ADMIN、没有 /dev/net/tun：不装，状态说为什么，代理照常。
- overlap：本机在一个和地址段重叠的网络里：不装，说出和谁重叠，那个网络照常。appears：装着的时候才重叠：拆掉；重叠没了再装上。
- leftover：kill -9 之后网卡没了、规则留着；再启动换掉而不是多一份；节点没运行时 `i3t set network off` 拆掉；关着启动什么都不装。
- restart：经虚拟网卡的 TCP 会话开着时重启节点程序，会话不断。
- forward：监听在本节点虚拟 IP 上的端口转发（目标是本节点的回环服务、目标是另一个节点）经网卡可达；经流照旧可达。
- lan：Linux 的弱主机模型。局域网里的机器用它自己的地址、把虚拟 IP 指到 a（`rp_filter` 开着）：连不上 a 虚拟 IP 上的服务和端口转发，
  UDP 也进不来；像 Docker 那样接在 a 后面、经 a 伪装出去的"容器"访问别的节点照常，连不了 a 自己的虚拟 IP。防火墙开关关着时，
  虚拟 IP 上的服务由这台机器自己管（进得来），端口转发自己不收从别的网卡来的连接。lan_iptables：同 lan，a 找不到 nft，
  防冒充是 raw 表里的两条 iptables 规则（读回来的写法和程序认的一样，停下之后拆干净）。
- hostile：b 不能访问 a，它在自己的机器上用原始套接字经虚拟网卡往 a 发拼不齐的 IP 分片（还有切开的 TCP、凑得齐但后一片带着
  内核会先扔掉的坏选项的）和伪造的 ICMP"需要分片"
  （说的是 a 发往别处的包）：a 的内核拼片缓存不被占用，a 到别处的路径 MTU 不被改成 552；b 的内核回给 a 的真的"端口不可达"照常。
- managed：由 controller 管理：状态在节点详情里；一个节点关着网卡，别的节点发给它的包当场"不可达"；`i3t hosts`。
- legacy：配置文件里的 `[intercept]` 不让节点起不来；以前的透明访问留下的规则和网卡被拆掉，网卡照常装上。
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab as lablib  # noqa: E402
from harness import (  # noqa: E402
    TICKER_DIRECT, Checks, Controller, Node, add_node_config, binary, current_route, dial, firewall_rules, private_hosts_file,
    send_checked, settled_snapshot, snapshot_difference, start_digest_server, start_ticker, start_udp_echo, start_whoami,
    system_snapshot, tail, udp_dial, use_nameserver, vnet_dropped, vnet_ready, without_empty_filter,
)
from lab import Lab, NatKind, Shape, isolate, private_link, wait_until  # noqa: E402

# 当场失败的（ICMP 不可达、RST）不到一秒。
FAST = 1.0
MB = 1_000_000


def i3t(node: Node, *args: str) -> subprocess.CompletedProcess:
    return node.host.run(binary("i3t"), "--state-dir", str(node.state), *args, check=False)


def ping(node: Node, address: str, *args: str, count: int = 3) -> subprocess.CompletedProcess:
    return node.host.run("ping", "-c", str(count), "-W", "2", "-i", "0.2", *args, address, check=False)


def received(done: subprocess.CompletedProcess) -> int:
    found = re.search(r"(\d+) received", done.stdout)
    return int(found.group(1)) if found else 0


def installed(t: Checks, *nodes: Node) -> bool:
    ok = True
    for node in nodes:
        ok &= t.check(f"{node.name} 的虚拟网卡装好了", vnet_ready(node) == "installed", tail(node.read_log()))
    return ok


def comparable(snapshot: dict[str, str]) -> dict[str, str]:
    """系统快照里去掉 iptables 插第一条规则时建的、删掉规则之后空着留下的 `ip filter` 表（见 `without_empty_filter`）。"""
    return {**snapshot, "nft": without_empty_filter(snapshot["nft"])}


def pair(lab: Lab, work: Path) -> tuple[Node, Node]:
    a, b = Node(lab.host("a"), work, 1), Node(lab.host("b"), work, 2)
    return a, b


def start_pair(a: Node, b: Node, **peer_options) -> None:
    a.start_static(a.netmap(peers=[b.as_peer(**peer_options)]))
    b.start_static(b.netmap(peers=[a.as_peer(**peer_options)]))


def basics(lab: Lab, work: Path, t: Checks) -> None:
    """两个公网节点直连。"""
    a, b = pair(lab, work)
    before = settled_snapshot(a.host)
    start_whoami(b.host, 8080)
    start_digest_server(b.host, 9000)
    start_udp_echo(b.host, 5353)
    start_pair(a, b)
    if not installed(t, a, b):
        return
    first = ping(a, b.virtual_ip, count=1)
    t.check("第一个 ping 就通（连接建起来的那一会儿它排着，没有丢）", received(first) == 1, first.stdout + first.stderr)
    pings = ping(a, b.virtual_ip, count=5)
    t.check("ping 对端的虚拟 IP：对端的内核回答", received(pings) == 5, pings.stdout)
    back = ping(b, a.virtual_ip, count=2)
    t.check("反方向也通", received(back) == 2, back.stdout)
    own = ping(a, a.virtual_ip, count=1)
    t.check("ping 自己的虚拟 IP：本机回答", received(own) == 1, own.stdout)

    seen = a.host.run("curl", "-sS", "--max-time", "10", f"http://{b.virtual_ip}:8080/", check=False)
    t.check("按虚拟 IP：curl 不配代理连到 b 上的服务", seen.returncode == 0, seen.stderr.strip())
    t.check("b 上的服务看到的来源是 a 的虚拟 IP", seen.stdout == a.virtual_ip, f"看到 {seen.stdout!r}")
    use_nameserver(a.virtual_ip)
    answer = a.host.run("dig", "+short", "+time=2", "+tries=1", f"@{a.virtual_ip}", "b.lab.i3t", check=False).stdout.strip()
    t.check("名字服务：b.lab.i3t 是 b 的虚拟 IP", answer == b.virtual_ip, answer)
    refused = a.host.run("dig", "+time=2", "+tries=1", f"@{a.virtual_ip}", "example.com", check=False).stdout
    t.check("名字服务只答网络自己的域名，别的名字回 REFUSED", "status: REFUSED" in refused, refused[-300:])
    from_peer = b.host.run("dig", "+time=2", "+tries=1", f"@{a.virtual_ip}", "b.lab.i3t", check=False)
    t.check("名字服务不回答别的节点来的查询", "status: NOERROR" not in from_peer.stdout, from_peer.stdout[-300:])
    by_name = a.host.run("curl", "-sS", "--max-time", "10", "http://b.lab.i3t:8080/", check=False)
    t.check("按名字：curl http://b.lab.i3t:8080/ 不配代理也能用", by_name.stdout == a.virtual_ip, f"{by_name.stdout!r} {by_name.stderr.strip()}")

    big = send_checked(a.host, b.virtual_ip, 9000, 50 * MB)
    t.check("TCP 发 50MB：一个字节不差", big.get("ok") is True, str(big))
    t.check("TCP 的分段长度按网卡的 MTU（1280）定，应用不用管", 0 < big.get("mss", 0) <= 1240, str(big))
    echoed = udp_dial(a.host, b.virtual_ip, 5353, b"ping")
    t.check("UDP：报文到了 b 上的服务，它看到的来源是 a 的虚拟 IP",
            bytes.fromhex(echoed.get("data", "")).startswith(a.virtual_ip.encode()), str(echoed))
    t.check("UDP：回答的来源是 b 的虚拟 IP 和那个端口", echoed.get("source") == f"{b.virtual_ip}:5353", str(echoed))

    nobody = dial(a.host, "10.66.0.9", 8080, limit=5)
    t.check("不是节点的地址：当场\"主机不可达\"，不是等超时", nobody.get("error") == "OSError" and nobody["seconds"] < FAST, str(nobody))
    unreachable = ping(a, "10.66.0.9", count=1)
    t.check("ping 不是节点的地址：当场说不可达", "Unreachable" in unreachable.stdout, unreachable.stdout)
    closed = dial(a.host, b.virtual_ip, 8999, limit=5)
    t.check("对端没开的端口：对端的内核当场拒绝", closed.get("error") == "ConnectionRefusedError" and closed["seconds"] < FAST, str(closed))
    large = ping(a, b.virtual_ip, "-s", "4000", count=2)
    t.check("比 MTU 大的 ping（4000 字节）照通：本机的内核切开，对端拼回去", received(large) == 2, large.stdout + large.stderr)
    dont = a.host.run("ping", "-c", "1", "-W", "2", "-M", "do", "-s", "1300", b.virtual_ip, check=False)
    said = dont.stdout + dont.stderr
    t.check("不许分片的大包：本机的内核当场说太大（MTU 1280），不是没有回音", "mtu=1280" in said or "Message too long" in said, said)
    t.check("i3t ping 照常", i3t(a, "ping", "b", "--count", "2").returncode == 0)

    status = i3t(a, "network", "status").stdout
    t.check("i3t network status 列出装了什么",
            all(part in status for part in ("装着", "i3t0 10.66.0.1/16", "table ip i3t0", "-i i3t0，INPUT 的第 1 条", "放行开着")), status)
    overall = i3t(a, "status").stdout
    t.check("i3t status 里有虚拟网卡的状态和计数", "虚拟网卡" in overall and "装着" in overall and "发 " in overall, overall[-600:])

    a.stop()
    after = system_snapshot(a.host)
    t.check("节点停下之后，网卡、地址、路由和规则和装之前一样", comparable(after) == comparable(before), snapshot_difference(before, after))
    gone = ping(b, a.virtual_ip, count=1)
    t.check("拆掉之后不再通", received(gone) == 0)
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log()), sep="\n  ---\n")


def rules(lab: Lab, work: Path, t: Checks) -> None:
    """访问规则只允许 a 访问 b（a -> b）。c 自以为可以访问 a（它的 netmap 和 a 的对不上），a 照样只放回包。"""
    a, b, c = Node(lab.host("a"), work, 1), Node(lab.host("b"), work, 2), Node(lab.host("c"), work, 3)
    for host in (a.host, b.host):
        start_whoami(host, 8080)
        start_udp_echo(host, 5353)
    a.start_static(a.netmap(peers=[b.as_peer(inbound=False), c.as_peer(inbound=False)]))
    b.start_static(b.netmap(peers=[a.as_peer(outbound=False)]))
    c.start_static(c.netmap(peers=[a.as_peer()]))
    if not installed(t, a, b, c):
        return
    t.check("a 发起的 ping 通", received(ping(a, b.virtual_ip)) == 3)
    seen = a.host.run("curl", "-sS", "--max-time", "10", f"http://{b.virtual_ip}:8080/", check=False)
    t.check("a 发起的 TCP 通", seen.stdout == a.virtual_ip, f"{seen.stdout!r} {seen.stderr.strip()}")
    echoed = udp_dial(a.host, b.virtual_ip, 5353, b"query")
    t.check("a 发起的 UDP 问答通（回答靠本节点记下的会话进来）", echoed.get("source") == f"{b.virtual_ip}:5353", str(echoed))
    # 比 MTU 大的：两个方向都被内核切成片，b 那边攒齐了才交给内核，a 这边按第一片认出是回答。
    large = udp_dial(a.host, b.virtual_ip, 5353, b"q" * 4000)
    answer = bytes.fromhex(large.get("data", ""))
    t.check("a 发起的 UDP 问答，比 MTU 大（切成了片）也通", answer == a.virtual_ip.encode() + b"|" + b"q" * 4000, str(large)[:300])
    t.check("a 发起的大 ping（切成了片）通", received(ping(a, b.virtual_ip, "-s", "3000", count=2)) == 2)

    syn = dial(b.host, a.virtual_ip, 8080, limit=5)
    t.check("b 发起的 TCP：b 自己当场拒绝（被管理员禁止）", syn.get("error") == "OSError" and syn["seconds"] < FAST, str(syn))
    t.check("b 发起的 ping 不通", received(ping(b, a.virtual_ip, count=1)) == 0)
    dropped = vnet_dropped(a, "not_allowed")
    unasked = udp_dial(b.host, a.virtual_ip, 5353, b"unasked", tries=2)
    t.check("b 发起的 UDP 不通", "data" not in unasked, str(unasked))
    sneaky = dial(c.host, a.virtual_ip, 8080, limit=3)
    t.check("c 以为可以访问 a：它的 TCP 握手在 a 那里被丢掉，连不上", "connected" not in sneaky, str(sneaky))
    t.check("a 数到了被丢掉的新会话", vnet_dropped(a, "not_allowed") >= dropped + 2, str(vnet_dropped(a, "not_allowed")))
    t.check("a 发起的照常，不受影响", received(ping(a, c.virtual_ip, count=1)) == 1)
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log()), sep="\n  ---\n")


def carried(t: Checks, a: Node, b: Node, what: str, size: int = 20 * MB) -> None:
    """a 和 b 之间：ping 和一次核对过的传输。"""
    start_digest_server(b.host, 9000)
    pings = ping(a, b.virtual_ip, count=3)
    t.check(f"{what}：ping 通", received(pings) >= 2, pings.stdout + pings.stderr)
    sent = send_checked(a.host, b.virtual_ip, 9000, size, timeout=240)
    t.check(f"{what}：TCP 发 {size // MB}MB 一个字节不差", sent.get("ok") is True, str(sent))
    print(f"  {what}：{size // MB}MB 用了 {sent.get('seconds')} 秒，路是 {current_route(a, b)}")


# 往一个地址按固定的速率发 UDP，不管对面收不收。参数：目的地址、Mbit/s、秒。
UDP_FLOOD = r'''
import socket, sys, time
target, mbit, seconds = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = bytes(1200)
gap = len(payload) * 8 / (mbit * 1e6)
start, sent = time.monotonic(), 0
while (now := time.monotonic() - start) < seconds:
    while sent < now / gap:
        try:
            sock.sendto(payload, (target, 9))
        except OSError:
            pass
        sent += 1
    time.sleep(0.001)
'''


def survives_flood(t: Checks, sender: Node, target: Node, leg: Node, what: str) -> None:
    """`sender` 经虚拟网卡往 `target` 灌一条比线路宽十倍的 UDP 流：`leg` 到 relay 的那条 TCP 不能因此被当作断了。

    经 relay 的路上网络包是连接的数据报，量有连接的拥塞控制管着。要是不进连接、单独封好了就发（直连时是这样），
    没有人管量的包会把这条 TCP 灌满：到 relay 的保活等不到回答，连续三次那条 TCP 就被拆掉重连，每六七秒一次；
    不拆的话里面的东西也要晚几秒才到。"""
    mark = len(leg.read_log())
    sender.host.run(sys.executable, "-c", UDP_FLOOD, target.virtual_ip, "20", "20")
    during = leg.read_log()[mark:]
    t.check(f"{what}：到 relay 的 TCP 没有被当作断了", "TCP 中转不可用" not in during,
            tail("\n".join(line for line in during.splitlines() if " INFO " in line), 6))


def relayed_pair(lab: Lab, work: Path, *, a_host, b_host) -> tuple[Node, Node, Node]:
    r = Node(lab.host("r"), work, 9, declare=("relay",))
    a, b = Node(a_host, work, 1), Node(b_host, work, 2)
    r.start_static(r.netmap(me={"relay": {}}, relays=[r.as_relay()], relay_clients=[a, b, r]))
    a.start_static(a.netmap(peers=[b.as_peer(attached=[(r, 5)])], relays=[r.as_relay()]))
    b.start_static(b.netmap(peers=[a.as_peer(attached=[(r, 5)])], relays=[r.as_relay()]))
    return a, b, r


def relay(lab: Lab, work: Path, t: Checks) -> None:
    """a 和 b 之间什么都不通，经 relay。"""
    a_host, b_host = lab.host("a"), lab.host("b")
    isolate(a_host, b_host)
    isolate(b_host, a_host)
    a, b, _ = relayed_pair(lab, work, a_host=a_host, b_host=b_host)
    if installed(t, a, b):
        carried(t, a, b, "经 relay")
        t.check("走的确实是 relay", current_route(a, b).startswith("经 relay"), current_route(a, b))
    if t.failures:
        print(tail(a.read_log(), 20), tail(b.read_log()), sep="\n  ---\n")


def tcp_relay(lab: Lab, work: Path, t: Checks) -> None:
    """b 用不了 UDP：它到 relay 的那一段是 TCP，连接在那一段装进 TCP，包照样是连接上的数据报。"""
    a_host, b_host = lab.host("a"), lab.host("b")
    b_host.block_udp()
    a, b, _ = relayed_pair(lab, work, a_host=a_host, b_host=b_host)
    if installed(t, a, b):
        wait_until(lambda: "经 TCP" in b.read_log() or "TCP" in b.read_log(), timeout=20, what="b 经 TCP 挂上 relay")
        carried(t, a, b, "经 TCP 中转")
    if t.failures:
        print(tail(a.read_log(), 20), tail(b.read_log()), sep="\n  ---\n")


def tcp_relay_flood(lab: Lab, work: Path, t: Checks) -> None:
    """b 用不了 UDP，线路只有 2 Mbit/s：经虚拟网卡灌一条宽十倍的 UDP 流，它到 relay 的那条 TCP 不被当作断了。"""
    a_host, b_host = lab.host("a"), lab.host("b")
    b_host.block_udp()
    # 从一开始就限着。先跑满再限的话，连接的拥塞控制还记着原来的带宽，限下来的头几秒照那个数发，那是另一回事。
    b_host.shape(Shape(rtt_ms=20, rate_mbit=2))
    a, b, _ = relayed_pair(lab, work, a_host=a_host, b_host=b_host)
    if installed(t, a, b):
        wait_until(lambda: "中转会话建立（TCP）" in b.read_log(), timeout=20, what="b 经 TCP 挂上 relay")
        t.check("灌之前 ping 通", received(ping(b, a.virtual_ip, count=3)) >= 2)
        survives_flood(t, b, a, b, "b 往外灌（它自己到 relay 的那条 TCP）")
        survives_flood(t, a, b, b, "a 往 b 灌（relay 发给 b 的那条 TCP）")
        b_host.shape(None)
        # 线路上排着的东西要一点时间走完。没有人管量的包灌过的话要好几秒，这里只给两秒。
        deadline = time.monotonic() + 2
        while not (back := received(ping(b, a.virtual_ip, "-W", "1", count=1)) == 1) and time.monotonic() < deadline:
            pass
        t.check("灌完之后两秒之内 ping 又通", back)
    if t.failures:
        print(tail(a.read_log(), 20), tail(b.read_log()), sep="\n  ---\n")


# 一个接一个地发小的 UDP 包（IP 包 48 字节）。参数：目的地址、个数、每秒几个。
SMALL_PACKETS = r'''
import socket, sys, time
target, count, rate = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
start, sent = time.monotonic(), 0
while sent < count:
    due = min(count, int((time.monotonic() - start) * rate) + 1)
    while sent < due:
        sock.sendto(bytes(20), (target, 9))
        sent += 1
    time.sleep(0.0002)
'''


def device_counter(node: Node, device: str, name: str) -> int:
    return int(node.host.run("sh", "-c", f"cat /sys/class/net/{device}/statistics/{name}").stdout.split()[0])


def small_packets(a: Node, b: Node, count: int) -> tuple[int, int]:
    """a 往 b 的虚拟 IP 发 `count` 个小 UDP 包，每秒四千个。返回（a 的真网卡因此发出去多少个包，b 的节点写进虚拟网卡多少个）。"""
    ping(a, b.virtual_ip, count=2)
    time.sleep(0.5)
    before = device_counter(a, "up0", "tx_packets"), device_counter(b, "i3t*", "rx_packets")
    a.host.run(sys.executable, "-c", SMALL_PACKETS, b.virtual_ip, str(count), "4000")
    time.sleep(0.5)
    return device_counter(a, "up0", "tx_packets") - before[0], device_counter(b, "i3t*", "rx_packets") - before[1]


def bundling(lab: Lab, work: Path, t: Checks) -> None:
    """直连的两个节点之间一串很密的小包：合起来发，线上的包数少得多；网络的开关关着时一个包一个包地发。"""
    a, b = pair(lab, work)
    # 真网卡上关掉分段卸载：不关的话内核把一次交下去的几个包记成一个，数不出线上到底走了几个。
    offload = a.host.run("ethtool", "-K", "up0", "tx-udp-segmentation", "off", "gso", "off", check=False)
    if offload.returncode != 0:
        print(f"  跳过：这台机器上关不掉分段卸载，数不了线上的包（{offload.stderr.strip() or '没有 ethtool'}）")
        return
    count = 2000
    start_pair(a, b)
    if installed(t, a, b):
        wait_until(lambda: current_route(a, b).startswith("直连"), timeout=20, what="a 到 b 直连")
        on_wire, delivered = small_packets(a, b, count)
        print(f"  开关开着：{count} 个小包，线上 {on_wire} 个包，对面收到 {delivered} 个")
        t.check("合起来发：一个不丢", delivered >= count, f"对面的虚拟网卡收到 {delivered} 个")
        t.check("合起来发：线上的包不到小包数的一半", on_wire < count // 2, f"线上 {on_wire} 个")
        idle = ping(a, b.virtual_ip, count=5)
        t.check("稀的包照旧：ping 不丢", received(idle) == 5, idle.stdout)

    # 同一对节点换一份开关关着的 netmap 重新起来。
    for node in (a, b):
        node.stop()
    off = lambda netmap: {**netmap, "network": {**netmap["network"], "bundle_small_packets": False}}  # noqa: E731
    a.start_static(off(a.netmap(peers=[b.as_peer()])))
    b.start_static(off(b.netmap(peers=[a.as_peer()])))
    if installed(t, a, b):
        wait_until(lambda: current_route(a, b).startswith("直连"), timeout=20, what="a 到 b 直连")
        on_wire, delivered = small_packets(a, b, count)
        print(f"  开关关着：{count} 个小包，线上 {on_wire} 个包，对面收到 {delivered} 个")
        t.check("开关关着：一个包一个包地发", on_wire >= count, f"线上 {on_wire} 个")
        t.check("开关关着：一个不丢", delivered >= count, f"对面的虚拟网卡收到 {delivered} 个")
    if t.failures:
        print(tail(a.read_log(), 20), tail(b.read_log()), sep="\n  ---\n")


# 往一个地址发一串 1000 字节的 UDP 包，每个包里全是它的序号。前 `blocks` 个一次交给内核、让它切（UDP_SEGMENT）：
# 内核给虚拟网卡 UDP 的大块时，到网卡上的是没切的一大块。内核不肯这样发时一个一个地发，结果里说明。后 `singles` 个一个一个地发。
UDP_BLOCKS = r'''
import json, socket, sys
target, port, blocks, singles = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
UDP_SEGMENT, SIZE = 103, 1000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((target, port))
packets = [bytes([index]) * SIZE for index in range(blocks + singles)]
refused = None
try:
    sock.setsockopt(socket.IPPROTO_UDP, UDP_SEGMENT, SIZE)
    sock.send(b"".join(packets[:blocks]))
except OSError as error:
    refused = str(error)
sock.setsockopt(socket.IPPROTO_UDP, UDP_SEGMENT, 0)
for packet in packets[0 if refused else blocks:]:
    sock.send(packet)
print(json.dumps({"refused": refused}))
'''

# 收上面那一串：每个包的序号、长度、内容是不是全是序号，写进一个文件。收够了，或者三秒没有新的，就结束。
UDP_SERIES_SINK = r'''
import json, socket, sys
port, expected, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
sock.settimeout(30)
seen = []
try:
    while len(seen) < expected:
        data = sock.recv(65535)
        sock.settimeout(3)
        seen.append([data[0], len(data), data == bytes([data[0]]) * len(data)])
except socket.timeout:
    pass
with open(out, "w") as result:
    json.dump(seen, result)
'''


def offload_of(node: Node) -> str:
    """节点的日志里，它的虚拟网卡和内核之间谈下来的交接办法：off、tcp 或者 tcp+udp。"""
    found = re.search(r"虚拟网卡建好了.*?offload=(\S+)", re.sub(r"\x1b\[[0-9;]*m", "", node.read_log()))
    return found.group(1) if found else "?"


def stream_counted(t: Checks, sender: Node, receiver: Node, what: str, size: int = 20 * MB) -> tuple[int, int]:
    """`sender` 经虚拟网卡给 `receiver` 发一条核对过的 TCP 流。返回（`sender` 的内核交给它的网卡几次，`receiver` 的节点往网卡里写了几次）。"""
    before = device_counter(sender, "i3t*", "tx_packets"), device_counter(receiver, "i3t*", "rx_packets")
    sent = send_checked(sender.host, receiver.virtual_ip, 9000, size, timeout=240)
    t.check(f"{what}：TCP 发 {size // MB}MB 一个字节不差", sent.get("ok") is True, str(sent))
    counted = device_counter(sender, "i3t*", "tx_packets") - before[0], device_counter(receiver, "i3t*", "rx_packets") - before[1]
    print(f"  {what}：{size // MB}MB 用了 {sent.get('seconds')} 秒，{sender.name} 的网卡读了 {counted[0]} 次，{receiver.name} 的网卡写了 {counted[1]} 次")
    return counted


def udp_series(t: Checks, sender: Node, receiver: Node, work: Path, what: str, *, port: int, blocks: int = 20, singles: int = 60) -> None:
    """`sender` 给 `receiver` 发一串 UDP 包（见 `UDP_BLOCKS`）：个数、顺序、每个包的内容都不变。"""
    out = work / f"udp-{port}.json"
    sink = receiver.host.spawn(sys.executable, "-c", UDP_SERIES_SINK, str(port), str(blocks + singles), str(out))
    wait_until(lambda: f":{port} " in receiver.host.run("ss", "-lnu").stdout, what=f"{receiver.name} 上收 UDP 的程序启动")
    done = sender.host.run(sys.executable, "-c", UDP_BLOCKS, receiver.virtual_ip, str(port), str(blocks), str(singles), check=False)
    said = json.loads(done.stdout) if done.stdout.strip() else {"refused": done.stderr.strip()[-200:]}
    sink.wait(timeout=45)
    seen = json.loads(out.read_text())
    intact = all(length == 1000 and whole for _, length, whole in seen)
    t.check(f"{what}：{blocks + singles} 个 UDP 包一个不少、顺序不变、内容不变",
            [index for index, _, _ in seen] == list(range(blocks + singles)) and intact, f"收到 {len(seen)} 个：{[index for index, _, _ in seen][:40]}")
    if offload_of(sender) != "off":
        t.check(f"{what}：程序一次交给内核、让它切的一大块 UDP 也发得出去", said.get("refused") is None, str(said))


def offload(lab: Lab, work: Path, t: Checks) -> None:
    """直连的两个节点：先都照默认的一大块一大块地交接，再让 a 关掉。"""
    a, b = pair(lab, work)
    for node in (a, b):
        start_digest_server(node.host, 9000)
    start_pair(a, b)
    if not installed(t, a, b):
        return
    wait_until(lambda: current_route(a, b).startswith("直连"), timeout=20, what="a 到 b 直连")
    kinds = offload_of(a), offload_of(b)
    t.check("默认开着：两头的内核都给大块", all(kind in ("tcp", "tcp+udp") for kind in kinds), str(kinds))
    print(f"  交接办法：a {kinds[0]}，b {kinds[1]}")
    # 一个包一个包地交接的话，20MB 至少是这么多个满长的包。
    one_by_one = 20 * MB // 1240
    for sender, receiver in ((a, b), (b, a)):
        read, written = stream_counted(t, sender, receiver, f"{sender.name} → {receiver.name}")
        t.check(f"{sender.name} → {receiver.name}：内核交给 {sender.name} 的网卡的次数不到包数的四分之一", read < one_by_one // 4, f"{read} 次")
        t.check(f"{sender.name} → {receiver.name}：{receiver.name} 往网卡里写的次数不到包数的一半", written < one_by_one // 2, f"{written} 次")
    udp_series(t, a, b, work, "a → b", port=5400)
    idle = ping(a, b.virtual_ip, count=5)
    t.check("稀的包照旧：ping 不丢", received(idle) == 5, idle.stdout)
    unreachable = ping(a, "10.66.0.9", count=1)
    t.check("回给本机程序的\"不可达\"照样写得进网卡", "Unreachable" in unreachable.stdout, unreachable.stdout)

    # a 关掉，b 不动：两头不一样也通。
    a.stop()
    done = i3t(a, "set", "offload", "off")
    t.check("i3t set offload off：写下了", done.returncode == 0 and "offload" in done.stdout, done.stdout + done.stderr)
    a.start_static(a.netmap(peers=[b.as_peer()]))
    if not installed(t, a):
        return
    t.check("a 关掉之后一个包一个包地交接，b 照旧", (offload_of(a), offload_of(b)) == ("off", kinds[1]), f"{offload_of(a)} {offload_of(b)}")
    read, _ = stream_counted(t, a, b, "a（关着）→ b")
    t.check("a（关着）→ b：内核一个包一个包地交给 a 的网卡", read >= one_by_one, f"{read} 次")
    _, written = stream_counted(t, b, a, "b → a（关着）")
    t.check("b → a（关着）：a 一个包一个包地往网卡里写", written >= one_by_one, f"{written} 次")
    udp_series(t, a, b, work, "a（关着）→ b", port=5401)
    udp_series(t, b, a, work, "b → a（关着）", port=5402)
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log()), sep="\n  ---\n")


def nat(lab: Lab, work: Path, t: Checks) -> None:
    """两端都在 NAT 后面，另有一个公网上的 relay。"""
    a_host, b_host = lab.nat("nat-a", NatKind.CONE).host("a"), lab.nat("nat-b", NatKind.CONE).host("b")
    a, b, _ = relayed_pair(lab, work, a_host=a_host, b_host=b_host)
    if installed(t, a, b):
        carried(t, a, b, "两端都在 NAT 后面")
    if t.failures:
        print(tail(a.read_log(), 20), tail(b.read_log()), sep="\n  ---\n")


# 收到一个 UDP 报文就把来源写一行进文件。参数：端口、文件。
UDP_SINK = r"""
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", int(sys.argv[1])))
while True:
    data, peer = s.recvfrom(2048)
    with open(sys.argv[2], "a") as out:
        out.write(peer[0] + "\n")
"""

# 从一个指定的来源地址发一个 UDP 报文。参数：来源、目的、端口。
UDP_FROM = r"""
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.sendto(b"hello", (sys.argv[2], int(sys.argv[3])))
"""


def spoof_reaches(a: Node, lan, sink: Path, source: str) -> bool:
    """局域网里的那台机器以 `source` 为来源发一个 UDP 报文给 a 在那个局域网里的地址，a 上的服务收到了没有。"""
    before = sink.read_text() if sink.exists() else ""
    lan.run(sys.executable, "-c", UDP_FROM, source, "192.168.77.1", "7777")
    time.sleep(0.5)
    after = sink.read_text() if sink.exists() else ""
    return after.count(source) > before.count(source)


def firewall(lab: Lab, work: Path, t: Checks) -> None:
    """开关开着：默认拒绝入站的 INPUT 也让别的节点进来，冒充虚拟 IP 的包被丢掉。开关关着：规则一条也不碰。"""
    a, b = pair(lab, work)
    lan = private_link(lab, a.host, "lan", "192.168.77.0/24")
    # 冒充的包要真的走到 a：a 不按来源查回去的路（很多发行版的默认是宽松的），局域网那台机器另有一个地址段里的地址。
    for key in ("all", "default", "p-lan"):
        a.host.run("sysctl", "-qw", f"net.ipv4.conf.{key}.rp_filter=0")
    lan.run("ip", "addr", "add", "10.66.0.2/32", "dev", "up0")
    sink = work / "sink"
    a.host.spawn(sys.executable, "-c", UDP_SINK, "7777", str(sink))
    start_whoami(a.host, 8080)
    # 像 ufw 那样的默认拒绝：只放行回包、回环、节点自己的 UDP 端口和那个局域网（冒充的包就从那里来）。
    for rule in (["-P", "INPUT", "DROP"], ["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                 ["-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                 ["-A", "INPUT", "-p", "udp", "--dport", "20330", "-j", "ACCEPT"], ["-A", "INPUT", "-i", "p-lan", "-j", "ACCEPT"]):
        a.host.run("iptables", *rule)
    start_pair(a, b)
    if installed(t, a, b):
        seen = b.host.run("curl", "-sS", "--max-time", "10", f"http://{a.virtual_ip}:8080/", check=False)
        t.check("INPUT 默认拒绝，别的节点经虚拟网卡照样进得来", seen.stdout == b.virtual_ip, f"{seen.stdout!r} {seen.stderr.strip()}")
        t.check("局域网里来的正常的包照样进来（对照）", spoof_reaches(a, lan, sink, "192.168.77.2"))
        t.check("从真网卡来、冒充虚拟 IP 的包被丢掉", not spoof_reaches(a, lan, sink, "10.66.0.2"), sink.read_text() if sink.exists() else "")
    a.stop()
    b.stop()

    add_node_config(a, "[network]\nfirewall = false\n")
    before = firewall_rules(a.host)
    a.log.write_text("")
    b.log.write_text("")
    start_pair(a, b)
    if installed(t, a):
        t.check("开关关着：装着的时候规则和装之前一样", firewall_rules(a.host) == before, json.dumps(firewall_rules(a.host))[-500:])
        t.check("开关关着：冒充的包不归程序管，照样进来", spoof_reaches(a, lan, sink, "10.66.0.2"))
        own = ping(b, a.virtual_ip, count=1)
        t.check("开关关着：INPUT 的默认拒绝挡住了别的节点（由这台机器自己的防火墙管）", received(own) == 0, own.stdout)
        status = i3t(a, "network", "status").stdout
        t.check("i3t network status 不列规则", "table ip" not in status and "INPUT" not in status, status)
    a.stop()
    t.check("开关关着：拆之后规则和装之前一样", firewall_rules(a.host) == before)
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log()), sep="\n  ---\n")


def privilege(lab: Lab, work: Path, t: Checks) -> None:
    """没有 CAP_NET_ADMIN 的节点、看不到 /dev/net/tun 的节点：不装，说为什么，经本机入口访问照常。"""
    a, b = pair(lab, work)
    start_whoami(b.host, 8080)
    b.start_static(b.netmap(peers=[a.as_peer()]))
    before = settled_snapshot(a.host)
    path = a.state / "static-netmap.json"
    path.write_text(json.dumps(a.netmap(peers=[b.as_peer()])))
    a.proc = a.host.spawn("setpriv", "--bounding-set=-net_admin", "--inh-caps=-net_admin", binary("i3t"), "--state-dir", str(a.state),
                          "run", "--static", str(path), log=a.log)
    t.check("没有 CAP_NET_ADMIN：不装", vnet_ready(a) == "failed", tail(a.read_log()))
    t.check("状态说缺 CAP_NET_ADMIN", "缺 CAP_NET_ADMIN" in i3t(a, "status").stdout, i3t(a, "status").stdout[-500:])
    proxied = a.curl(f"http://{b.virtual_ip}:8080/")
    t.check("经本机入口访问 b 照常", proxied.stdout == b.host.ip, f"{proxied.stdout!r} {proxied.stderr.strip()}")
    t.check("系统里什么都没动", comparable(system_snapshot(a.host)) == comparable(before), snapshot_difference(before, system_snapshot(a.host)))
    a.stop()

    a.log.write_text("")
    a.proc = a.host.spawn("unshare", "-m", "sh", "-c", f"mount -t tmpfs tmpfs /dev/net && exec {binary('i3t')} --state-dir {a.state} "
                          f"run --static {path}", log=a.log)
    t.check("没有 /dev/net/tun：不装", vnet_ready(a) == "failed", tail(a.read_log()))
    status = i3t(a, "status").stdout
    t.check("状态说打不开建网卡用的设备", "打不开建网卡用的设备" in status, status[-500:])
    proxied = a.curl(f"http://{b.virtual_ip}:8080/")
    t.check("经本机入口访问 b 照常", proxied.stdout == b.host.ip, f"{proxied.stdout!r} {proxied.stderr.strip()}")
    if t.failures:
        print(tail(a.read_log(), 30))


def overlap(lab: Lab, work: Path, t: Checks) -> None:
    """a 自己就在一个和地址段重叠的内网里（10.66.200.0/24）：什么都不装，说清楚为什么，别的照常。"""
    a, b = pair(lab, work)
    lan = private_link(lab, a.host, "lan", "10.66.200.0/24")
    start_whoami(lan, 8080)
    start_whoami(b.host, 8080)
    before = settled_snapshot(a.host)
    start_pair(a, b)
    t.check("地址段和本机的一个真实网络重叠：不装", vnet_ready(a) == "failed", tail(a.read_log()))
    after = system_snapshot(a.host)
    t.check("网卡、路由和规则一样也没动", comparable(after) == comparable(before), snapshot_difference(before, after))
    status = i3t(a, "status").stdout
    t.check("i3t status 说出和谁重叠", "网络的地址段和本机的 10.66.200.1/24 dev p-lan 重叠" in status, status[-500:])
    real = a.host.run("curl", "-sS", "--max-time", "10", "http://10.66.200.2:8080/", check=False)
    t.check("发往那个真实网络的流量照常", real.stdout == "10.66.200.1", f"{real.stdout!r} {real.stderr.strip()}")
    proxied = a.curl(f"http://{b.virtual_ip}:8080/")
    t.check("节点别的功能照常：经本机入口访问 b", proxied.stdout == b.host.ip, f"{proxied.stdout!r} {proxied.stderr.strip()}")
    if t.failures:
        print(tail(a.read_log(), 30))


def appears(lab: Lab, work: Path, t: Checks) -> None:
    """装着的时候，另一块网卡上多了一个地址段里的地址（DHCP 换了地址、VPN 连上）：当场拆掉；地址去掉之后再装上。"""
    a, b = pair(lab, work)
    lan = private_link(lab, a.host, "lan", "192.168.77.0/24")
    start_whoami(lan, 8080)
    start_pair(a, b)
    if not installed(t, a, b):
        return

    def device() -> bool:
        return " i3t0:" in a.host.run("ip", "-o", "link", "show").stdout

    a.host.run("ip", "addr", "add", "10.66.200.1/24", "dev", "p-lan")
    lan.run("ip", "addr", "add", "10.66.200.2/24", "dev", "up0")
    started = time.monotonic()
    wait_until(lambda: not device(), timeout=20, what="a 拆掉虚拟网卡")
    t.check("多了一个地址段里的地址：几秒之内拆掉", time.monotonic() - started < 10)
    t.check("日志说出为什么拆", "重叠了，虚拟网卡当场拆掉" in a.read_log(), tail(a.read_log()))
    t.check("规则也拆了", "table ip i3t0" not in a.host.run("nft", "list", "ruleset").stdout)
    real = a.host.run("curl", "-sS", "--max-time", "10", "http://10.66.200.2:8080/", check=False)
    t.check("那个网络照常通", real.stdout == "10.66.200.1", f"{real.stdout!r} {real.stderr.strip()}")

    a.host.run("ip", "addr", "del", "10.66.200.1/24", "dev", "p-lan")
    started = time.monotonic()
    wait_until(device, timeout=20, what="a 再装上虚拟网卡")
    t.check("地址去掉之后几秒之内再装上", time.monotonic() - started < 10)
    wait_until(lambda: received(ping(a, b.virtual_ip, count=1)) == 1, timeout=10, what="再装上之后 ping 通")
    if t.failures:
        print(tail(a.read_log(), 30))


def leftover(lab: Lab, work: Path, t: Checks) -> None:
    """节点被杀掉：网卡随进程没了，规则留着；下次启动换掉；节点没运行时关掉就拆掉；关着启动什么都不装。"""
    a, b = pair(lab, work)
    before = settled_snapshot(a.host)
    netmap = a.netmap(peers=[b.as_peer()])
    b.start_static(b.netmap(peers=[a.as_peer()]))
    a.start_static(netmap)
    installed(t, a)

    a.host.stop(a.proc, signal.SIGKILL)
    a.proc = None
    left = system_snapshot(a.host)
    t.check("被杀掉：网卡和它的地址、路由跟着没了", " i3t0:" not in left["links"] and "10.66.0.0/16" not in left["routes"], left["links"])
    t.check("被杀掉：规则留着", "table ip i3t0" in left["nft"] and "ice3tier" in firewall_rules(a.host)["iptables"], left["nft"])
    t.check("i3t network status 说这些是上次留下的", "上次留下的" in i3t(a, "network", "status").stdout)

    a.log.write_text("")
    a.start_static(netmap)
    installed(t, a)
    rules_now = firewall_rules(a.host)
    counts = (rules_now["nft"].count("table ip i3t0"), rules_now["iptables"].count("--comment ice3tier"))
    t.check("再启动：换掉而不是多一份（一张表、一条规则）", counts == (1, 1), str(counts))
    t.check("换掉之后照常可用", received(ping(a, b.virtual_ip, count=1)) == 1)

    a.host.stop(a.proc, signal.SIGKILL)
    a.proc = None
    switched = i3t(a, "set", "network", "off")
    t.check("节点没运行时 i3t set network off 拆掉留下的", "拆掉了上次留下的" in switched.stdout, switched.stdout + switched.stderr)
    after = system_snapshot(a.host)
    t.check("拆掉之后和装之前一样", comparable(after) == comparable(before), snapshot_difference(before, after))
    a.log.write_text("")
    a.start_static(netmap)
    time.sleep(1.5)
    t.check("关着启动：什么都不装", comparable(system_snapshot(a.host)) == comparable(before), snapshot_difference(before, system_snapshot(a.host)))
    t.check("关着：状态说关着", "关着" in i3t(a, "status").stdout)
    if t.failures:
        print(tail(a.read_log(), 30))


def restart(lab: Lab, work: Path, t: Checks) -> None:
    """a 经虚拟网卡连着 b 上一个一直在发消息的服务；中途重启 a 的节点程序：TCP 的状态在两端的操作系统里，会话不断。"""
    a, b = pair(lab, work)
    start_ticker(b.host, 9000)
    start_pair(a, b)
    if not installed(t, a, b):
        return
    seconds = 25
    client = subprocess.Popen(a.host.cmd(sys.executable, "-c", TICKER_DIRECT, b.virtual_ip, "9000", str(seconds)),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(5)
    a.stop()
    a.log.write_text("")
    a.start_static(a.netmap(peers=[b.as_peer()]))
    installed(t, a)
    out, err = client.communicate(timeout=seconds + 30)
    result = json.loads(out) if out.strip() else {"ended": err.strip()[-300:], "gaps": [], "bytes": 0}
    t.check("重启之后会话没有断，消息接着来", result["ended"] is None and result["bytes"] > 64 * 100 * (seconds - 15), str(result))
    t.check("中间的停顿不长", max(result["gaps"] or [0]) < 8, str(result["gaps"]))
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log()), sep="\n  ---\n")


def mtu(lab: Lab, work: Path, t: Checks) -> None:
    """a 把网卡的 MTU 设成允许的最大值 1500（`i3t set mtu`），b 用默认的 1280：两头设得不一样也通，满长的包也送得到。"""
    a, b = pair(lab, work)
    for bad in ("575", "1501", "big"):
        refused = i3t(a, "set", "mtu", bad)
        t.check(f"i3t set mtu {bad}：不收，说得出范围", refused.returncode != 0 and "576" in refused.stderr and "1500" in refused.stderr,
                refused.stdout + refused.stderr)
    done = i3t(a, "set", "mtu", "1500")
    t.check("i3t set mtu 1500：写下了", done.returncode == 0 and "1500" in done.stdout, done.stdout + done.stderr)
    start_pair(a, b)
    if not installed(t, a, b):
        return

    def link_mtu(node: Node) -> int | None:
        found = re.search(r"mtu (\d+)", node.host.run("ip", "-o", "link", "show", "i3t0", check=False).stdout)
        return int(found.group(1)) if found else None

    t.check("a 的网卡是 1500，b 的是默认的 1280", (link_mtu(a), link_mtu(b)) == (1500, 1280), f"{link_mtu(a)} {link_mtu(b)}")
    status = i3t(a, "network", "status").stdout
    t.check("a 的状态里写着 MTU 1500", "MTU 1500" in status, status)
    # 1472 字节的数据加 28 字节的头正好 1500：a 这边不许分片地发出去，连接上一个数据报装不下，切成两片；
    # b 的网卡只有 1280，照样收得下，回答由 b 的内核切开发回来。
    full = ping(a, b.virtual_ip, "-M", "do", "-s", "1472")
    t.check("a 发满 1500 字节、不许分片的 ping：b 收得到，回得来", received(full) == 3, full.stdout + full.stderr)
    over = ping(a, b.virtual_ip, "-M", "do", "-s", "1473", count=1)
    t.check("再大一个字节：a 自己的内核就说太大，不发", received(over) == 0, over.stdout + over.stderr)
    back = ping(b, a.virtual_ip, "-M", "do", "-s", "1252")
    t.check("b 发满 1280 字节的 ping：通", received(back) == 3, back.stdout + back.stderr)
    carried(t, a, b, "两头 MTU 不一样（1500 → 1280）")
    carried(t, b, a, "两头 MTU 不一样（1280 → 1500）")
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log()), sep="\n  ---\n")


def forward(lab: Lab, work: Path, t: Checks) -> None:
    """a 的虚拟 IP 上两条端口转发：8080 转给 a 自己回环上的服务，8082 转给 b 回环上的服务。b 经虚拟网卡连它们。"""
    a, b = pair(lab, work)
    start_whoami(a.host, 18080, bind="127.0.0.1")
    start_whoami(b.host, 18082, bind="127.0.0.1")
    to_self = {"id": 7, "protocol": "tcp", "bind": f"{a.virtual_ip}:8080", "target": a.id}
    to_b = {"id": 8, "protocol": "tcp", "bind": f"{a.virtual_ip}:8082", "target": b.id}
    a.start_static(a.netmap(peers=[b.as_peer()], me={
        "forwards": [to_self, to_b],
        "forward_targets": [{"id": 7, "protocol": "tcp", "addr": "127.0.0.1:18080", "listener": a.id}],
    }))
    b.start_static(b.netmap(peers=[a.as_peer()], me={
        "forward_targets": [{"id": 8, "protocol": "tcp", "addr": "127.0.0.1:18082", "listener": a.id}],
    }))
    if not installed(t, a, b):
        return
    here = b.host.run("curl", "-sS", "--max-time", "10", f"http://{a.virtual_ip}:8080/", check=False)
    t.check("经虚拟网卡连 a 的虚拟 IP 上的转发，到 a 回环上的服务", here.stdout == "127.0.0.1", f"{here.stdout!r} {here.stderr.strip()}")
    there = b.host.run("curl", "-sS", "--max-time", "10", f"http://{a.virtual_ip}:8082/", check=False)
    t.check("目标是另一个节点的转发：经虚拟网卡进来，经流到目标", there.stdout == "127.0.0.1", f"{there.stdout!r} {there.stderr.strip()}")
    streamed = b.curl(f"http://{a.virtual_ip}:8080/")
    t.check("经流（本机入口）照旧到得了", streamed.stdout == "127.0.0.1", f"{streamed.stdout!r} {streamed.stderr.strip()}")
    listed = a.host.run("ss", "-lnt").stdout
    t.check("转发在虚拟 IP 上真的监听着", f"{a.virtual_ip}:8080" in listed, listed)
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log()), sep="\n  ---\n")


def lan_reaches(a: Node, lan, sink: Path, destination: str) -> bool:
    """局域网里的那台机器用它自己的地址（192.168.77.2）发一个 UDP 报文给 `destination` 的 7777 端口，a 上监听 0.0.0.0 的服务收到了没有。"""
    before = sink.read_text().count("192.168.77.2") if sink.exists() else 0
    lan.run(sys.executable, "-c", UDP_FROM, "192.168.77.2", destination, "7777")
    time.sleep(0.5)
    return (sink.read_text().count("192.168.77.2") if sink.exists() else 0) > before


def fetch(host, url: str, *extra: str) -> subprocess.CompletedProcess:
    return host.run("curl", "-sS", "--max-time", "3", *extra, url, check=False)


@contextlib.contextmanager
def nft_hidden(work: Path) -> Iterator[None]:
    """这一段时间里谁都找不到 nft：每个找得到的 nft 上盖一个不能执行的空文件。盖在实验环境自己的挂载命名空间里，不碰真的系统。"""
    blank = work / "not-nft"
    blank.write_text("")
    places = os.environ["PATH"].split(":") + ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
    covered = sorted({os.path.realpath(Path(place) / "nft") for place in places if (Path(place) / "nft").exists()})
    for path in covered:
        lablib.sh("mount", "--bind", str(blank), path)
    try:
        yield
    finally:
        for path in covered:
            lablib.sh("umount", path, check=False)


def lan(lab: Lab, work: Path, t: Checks, *, nft: bool = True) -> None:
    """局域网里的机器和接在 a 后面的"容器"都把虚拟 IP 指到 a：连不上 a 的虚拟 IP；容器经 a 访问别的节点照常。"""
    a, b = pair(lab, work)
    lan = private_link(lab, a.host, "lan", "192.168.77.0/24")
    lan.run("ip", "route", "add", "10.66.0.0/16", "via", "192.168.77.1", "src", "192.168.77.2")
    # 按来源查回去的路开着：局域网那台机器的地址本来就从那块网卡回得去，挡不住它。
    for key in ("all", "default", "p-lan"):
        a.host.run("sysctl", "-qw", f"net.ipv4.conf.{key}.rp_filter=1")
    # 像 Docker 的 docker0：a 转发、出虚拟网卡时伪装成 a 的虚拟 IP。
    box = private_link(lab, a.host, "box", "172.30.0.0/24")
    box.run("ip", "route", "add", "10.66.0.0/16", "via", "172.30.0.1")
    a.host.run("sysctl", "-qw", "net.ipv4.ip_forward=1")
    a.host.run("nft", "-f", "-", input="table ip box {\n chain post {\n type nat hook postrouting priority srcnat;\n"
                                       ' oifname "i3t0" ip saddr 172.30.0.0/24 masquerade\n }\n}\n')
    sink = work / "sink"
    a.host.spawn(sys.executable, "-c", UDP_SINK, "7777", str(sink))
    start_whoami(a.host, 18080, bind="127.0.0.1")
    start_whoami(b.host, 8080)
    to_self = {"id": 7, "protocol": "tcp", "bind": f"{a.virtual_ip}:8080", "target": a.id}
    with contextlib.nullcontext() if nft else nft_hidden(work):
        lan_checks(a, b, lan, box, sink, to_self, t, nft=nft)


def lan_checks(a: Node, b: Node, lan, box, sink: Path, to_self: dict, t: Checks, *, nft: bool) -> None:
    """[`lan`] 的节点部分：启动、核对；开关关上再来一遍。"""
    def start() -> bool:
        a.start_static(a.netmap(peers=[b.as_peer()], me={
            "forwards": [to_self], "forward_targets": [{"id": 7, "protocol": "tcp", "addr": "127.0.0.1:18080", "listener": a.id}],
        }))
        b.start_static(b.netmap(peers=[a.as_peer()]))
        if not installed(t, a, b):
            return False
        if f"{a.virtual_ip}:8081 " not in a.host.run("ss", "-lnt").stdout:
            start_whoami(a.host, 8081, bind=a.virtual_ip)
        return True

    if start():
        seen = fetch(b.host, f"http://{a.virtual_ip}:8081/")
        t.check("别的节点经虚拟网卡连 a 的虚拟 IP 上的服务（对照）", seen.stdout == b.virtual_ip, f"{seen.stdout!r} {seen.stderr.strip()}")
        seen = fetch(b.host, f"http://{a.virtual_ip}:8080/")
        t.check("别的节点经虚拟网卡连 a 的虚拟 IP 上的端口转发（对照）", seen.stdout == "127.0.0.1", f"{seen.stdout!r} {seen.stderr.strip()}")
        t.check("局域网里的机器发给 a 在局域网里的地址的 UDP 照常（对照）", lan_reaches(a, lan, sink, "192.168.77.1"))
        seen = fetch(lan, f"http://{a.virtual_ip}:8081/", "--interface", "192.168.77.2")
        t.check("局域网里的机器用自己的地址连不上 a 的虚拟 IP 上的服务", seen.returncode != 0, f"{seen.stdout!r}")
        seen = fetch(lan, f"http://{a.virtual_ip}:8080/", "--interface", "192.168.77.2")
        t.check("  ……也连不上 a 的虚拟 IP 上的端口转发", seen.returncode != 0, f"{seen.stdout!r}")
        t.check("  ……UDP 也进不来", not lan_reaches(a, lan, sink, a.virtual_ip))
        seen = fetch(box, f"http://{b.virtual_ip}:8080/")
        t.check("接在 a 后面的容器经 a 访问别的节点照常（伪装成 a 的虚拟 IP）", seen.stdout == a.virtual_ip, f"{seen.stdout!r} {seen.stderr.strip()}")
        seen = fetch(box, f"http://{a.virtual_ip}:8081/")
        t.check("接在 a 后面的容器连不了 a 自己的虚拟 IP（和局域网里的机器分不开）", seen.returncode != 0, f"{seen.stdout!r}")
        if nft:
            dropped = a.host.run("nft", "list", "table", "ip", "i3t0").stdout
            t.check("丢掉它们的是防冒充的表里按目的的那条", re.search(rf"ip daddr {re.escape(a.virtual_ip)} drop$", dropped, re.M) is not None,
                    dropped)
        else:
            raw = a.host.run("iptables", "-t", "raw", "-S", "PREROUTING").stdout
            ours = [line for line in raw.splitlines() if "ice3tier" in line]
            t.check("没有 nft：丢掉它们的是 raw 表 PREROUTING 的前两条，按来源的在前、按目的的在后", ours == raw.splitlines()[1:3] == [
                "-A PREROUTING -s 10.66.0.0/16 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP",
                "-A PREROUTING -d 10.66.0.1/32 ! -i i3t0 -m addrtype ! --src-type LOCAL -m comment --comment ice3tier -j DROP",
            ], raw)
            status = i3t(a, "network", "status").stdout
            t.check("  ……i3t network status 列出这两条", "-s 10.66.0.0/16" in status and "-d 10.66.0.1/32" in status, status)
    a.stop()
    b.stop()
    if not nft:
        raw = a.host.run("iptables", "-t", "raw", "-S", "PREROUTING").stdout
        t.check("  ……停下之后拆干净了", "ice3tier" not in raw, raw)

    add_node_config(a, "[network]\nfirewall = false\n")
    if start():
        seen = fetch(lan, f"http://{a.virtual_ip}:8081/", "--interface", "192.168.77.2")
        t.check("开关关着：虚拟 IP 上别的服务由这台机器自己管，内核照样收", seen.stdout == "192.168.77.2", f"{seen.stdout!r} {seen.stderr.strip()}")
        seen = fetch(lan, f"http://{a.virtual_ip}:8080/", "--interface", "192.168.77.2")
        t.check("  ……虚拟 IP 上的端口转发自己不收从别的网卡来的连接", seen.stdout != "127.0.0.1", f"{seen.stdout!r} {seen.stderr.strip()}")
        t.check("  ……节点记下了为什么", "来源既不是本机，也不是可以访问本节点的节点" in a.read_log(), tail(a.read_log()))
        seen = fetch(b.host, f"http://{a.virtual_ip}:8080/")
        t.check("  ……别的节点照常", seen.stdout == "127.0.0.1", f"{seen.stdout!r} {seen.stderr.strip()}")
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log()), sep="\n  ---\n")


def lan_iptables(lab: Lab, work: Path, t: Checks) -> None:
    """同 lan，节点 a 找不到 nft：防冒充是 raw 表里的两条 iptables 规则。"""
    lan(lab, work, t, nft=False)


# 从标准输入读一行一个十六进制的 IPv4 包（头自己写好），用原始套接字原样发出去。打印发了几个。
INJECT = r"""
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sent = 0
for line in sys.stdin:
    packet = bytes.fromhex(line.strip())
    try:
        s.sendto(packet, (socket.inet_ntoa(packet[16:20]), 0))
        sent += 1
    except OSError:
        pass
print(sent)
"""

# 连上一个 UDP 端口发一个报文，打印收到了什么：对端回了"端口不可达"时是 ConnectionRefusedError。参数：地址、端口。
UDP_REFUSED = r"""
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.connect((sys.argv[1], int(sys.argv[2])))
for _ in range(3):
    s.send(b"anyone?")
    try:
        s.recv(100)
        print("answered")
        break
    except socket.timeout:
        continue
    except OSError as error:
        print(type(error).__name__)
        break
"""


def internet_checksum(data: bytes) -> int:
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4_packet(source: str, destination: str, protocol: int, payload: bytes, *, ident: int = 0x4242, offset: int = 0,
                more: bool = False, options: bytes = b"") -> bytes:
    """一个 IPv4 包，头 20 字节加上 `options`（4 的倍数）。`offset` 是片在原包里的字节偏移（8 的倍数），`more` 是 MF。"""
    flags = (0x2000 if more else 0) | (offset // 8)
    header = struct.pack("!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0, 20 + len(options) + len(payload), ident, flags, 64,
                         protocol, 0, socket.inet_aton(source), socket.inet_aton(destination)) + options
    return header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:] + payload


def icmp_message(kind: int, code: int, rest: bytes, data: bytes) -> bytes:
    body = struct.pack("!BBH", kind, code, 0) + rest + data
    return body[:2] + struct.pack("!H", internet_checksum(body)) + body[4:]


def inject(host, packets: list[bytes]) -> int:
    done = host.run(sys.executable, "-c", INJECT, input="".join(packet.hex() + "\n" for packet in packets))
    return int(done.stdout.strip() or 0)


def reassembly_cache(host) -> tuple[int, int]:
    """内核拼片缓存（这个网络命名空间的）：正在拼的包有几个，占多少字节。"""
    found = re.search(r"FRAG: inuse (\d+) memory (\d+)", host.run("cat", "/proc/net/sockstat").stdout)
    return (int(found.group(1)), int(found.group(2))) if found else (-1, -1)


def hostile(lab: Lab, work: Path, t: Checks) -> None:
    """b 不能访问 a，往 a 发拼不齐的片和伪造的 ICMP 差错报文：a 的内核不受影响，真的差错报文照常。"""
    a, b = pair(lab, work)
    a.start_static(a.netmap(peers=[b.as_peer(inbound=False)]))
    b.start_static(b.netmap(peers=[a.as_peer(outbound=False)]))
    if not installed(t, a, b):
        return
    t.check("a 发起的 ping 通（连接建好了）", received(ping(a, b.virtual_ip, count=2)) == 2)
    refused = a.host.run(sys.executable, "-c", UDP_REFUSED, b.virtual_ip, "9", check=False)
    t.check("a 连 b 上没开的 UDP 端口：b 的内核回的“端口不可达”照常进来", refused.stdout.strip() == "ConnectionRefusedError",
            refused.stdout + refused.stderr)

    before = reassembly_cache(a.host)
    packets = []
    for ident in range(1, 1201):
        # 后面的片，第一片永远不来；任何协议都行（GRE）。
        packets.append(ipv4_packet(b.virtual_ip, a.virtual_ip, 47, b"g" * 64, ident=ident, offset=1480, more=True))
        # 第一片（ping 的回答，"回包"），后面的永远不来。
        echo_reply = icmp_message(0, 0, struct.pack("!HH", 7, ident), b"r" * 48)
        packets.append(ipv4_packet(b.virtual_ip, a.virtual_ip, 1, echo_reply, ident=ident, more=True))
        # RFC 1858：16 个字节的 TCP 第一片，标志是 ACK。
        segment = struct.pack("!HHIIBB", 40000, 22, 1, 1, 0x50, 0x10) + b"\0\0"
        packets.append(ipv4_packet(b.virtual_ip, a.virtual_ip, 6, segment, ident=ident, more=True))
    sent = inject(b.host, packets)
    time.sleep(1.5)
    after = reassembly_cache(a.host)
    t.check(f"b 发了 {sent} 个拼不齐的片：a 的内核拼片缓存里一个也没有", sent > 0 and after == before == (0, 0), f"之前 {before}，之后 {after}")

    # 两片凑得齐，可后一片带着不合规矩的选项（记录路由，长度写 0）：内核在拼片之前就扔掉它，前一片要是交给了内核就留在缓存里。
    pairs = []
    for ident in range(2001, 3201):
        echo_reply = icmp_message(0, 0, struct.pack("!HH", 7, ident), b"")
        pairs.append(ipv4_packet(b.virtual_ip, a.virtual_ip, 1, echo_reply, ident=ident, more=True))
        pairs.append(ipv4_packet(b.virtual_ip, a.virtual_ip, 1, b"p" * 8, ident=ident, offset=8, options=bytes([7, 0, 0, 0])))
    sent = inject(b.host, pairs)
    time.sleep(1.5)
    after = reassembly_cache(a.host)
    t.check(f"b 发了 {sent // 2} 对后一片带坏选项的片：a 的内核拼片缓存里也一个都没有", sent > 0 and after == (0, 0), f"之后 {after}")

    # 伪造的"需要分片，下一跳 MTU 552"，说的是 a 从它 53 端口（名字服务）发往别处的一个 UDP 包。
    targets = ("203.0.113.5", "10.66.0.9")
    forged = []
    for target in targets:
        quoted = ipv4_packet(a.virtual_ip, target, 17, struct.pack("!HHHH", 53, 5353, 16, 0) + b"q" * 8)
        forged.append(ipv4_packet(b.virtual_ip, a.virtual_ip, 1, icmp_message(3, 4, struct.pack("!HH", 0, 552), quoted[:28])))
    inject(b.host, forged)
    time.sleep(1)
    for target in targets:
        route = a.host.run("ip", "route", "get", target, check=False).stdout
        t.check(f"伪造的“需要分片”没有把 a 到 {target} 的路径 MTU 改成 552", "mtu 552" not in route, route.strip())
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log()), sep="\n  ---\n")


def managed(lab: Lab, work: Path, t: Checks) -> None:
    """由 controller 管理：状态在节点详情里；c 关着网卡，别的节点知道，发给它的包当场"不可达"；i3t hosts 写出名字。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab", "--cidr", "10.66.0.0/16")
    a, b, c = Node(lab.host("a"), work), Node(lab.host("b"), work), Node(lab.host("c"), work)
    add_node_config(c, "[network]\nenabled = false\n")
    for node in (a, b, c):
        node.join(controller)
    installed(t, a, b)

    def detail(node: Node) -> dict:
        return controller.ctl("node", "show", str(node.id))

    wait_until(lambda: (detail(a).get("vnet") or {}).get("state") == "installed", timeout=30, what="a 把虚拟网卡的状态报给 controller")
    reported = detail(a)["vnet"]
    t.check("节点详情：a 的网卡装着，防火墙两条都开着",
            reported.get("device") == "i3t0" and reported.get("firewall") == {"accept": {"state": "on"}, "guard": {"state": "on"}}, str(reported))
    wait_until(lambda: (detail(c).get("vnet") or {}).get("state") == "off", timeout=30, what="c 报虚拟网卡关着")
    shown = controller.host.run(binary("i3tctl"), "--token", controller.token, "node", "show", str(a.id), check=False).stdout
    t.check("i3tctl node show 写出虚拟网卡的状态", "虚拟网卡" in shown and "装着" in shown, shown[-500:])

    wait_until(lambda: received(ping(a, b.virtual_ip, count=1)) == 1, timeout=20, what="a ping 通 b")
    wait_until(lambda: "Unreachable" in ping(a, c.virtual_ip, count=1).stdout, timeout=30, what="a 知道 c 没有网卡")
    started = time.monotonic()
    to_c = dial(a.host, c.virtual_ip, 22, limit=5)
    t.check("发给没有网卡的节点：当场\"主机不可达\"", to_c.get("error") == "OSError" and time.monotonic() - started < FAST, str(to_c))

    printed = i3t(a, "hosts").stdout
    t.check("i3t hosts 写出网络里的名字", f"{b.virtual_ip}\tb.lab.i3t" in printed and f"{a.virtual_ip}\ta.lab.i3t" in printed, printed)
    hosts = private_hosts_file()
    original = hosts.read_text()
    written = i3t(a, "hosts", "--apply")
    t.check("i3t hosts --apply 写进 /etc/hosts，原来的行留着",
            written.returncode == 0 and hosts.read_text().startswith(original) and "b.lab.i3t" in hosts.read_text(), written.stderr)
    resolved = a.host.run("getent", "hosts", "b.lab.i3t", check=False).stdout
    t.check("靠 hosts 文件按名字找到 b", resolved.startswith(b.virtual_ip), resolved)
    removed = i3t(a, "hosts", "--remove")
    t.check("i3t hosts --remove 只去掉那一段", removed.returncode == 0 and hosts.read_text() == original, removed.stdout + removed.stderr)
    if t.failures:
        print(tail(a.read_log(), 30), tail(controller.log.read_text(errors="replace")), sep="\n  ---\n")


# 以前的透明访问装好之后、进程被杀掉时留在系统里的东西（它的表的样子、策略路由、dummy 网卡），用来确认新版本会拆掉它们。
OLD_TABLE = """
table ip i3t {
    chain refuse {
        type filter hook output priority filter; policy accept;
        ip daddr 10.66.0.0/16 ip daddr != 10.66.0.1 reject with icmp type admin-prohibited
    }
}
"""


def legacy(lab: Lab, work: Path, t: Checks) -> None:
    """配置文件里写着 [intercept]，系统里留着以前的透明访问的表、规则、路由和 dummy 网卡 i3t0。"""
    a, b = pair(lab, work)
    add_node_config(a, "[intercept]\nenabled = true\n")
    a.host.run("nft", "-f", "-", input=OLD_TABLE)
    a.host.run("ip", "rule", "add", "priority", "2033", "fwmark", "0x20000000/0x20000000", "lookup", "2033", "proto", "203")
    a.host.run("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "2033", "proto", "203")
    a.host.run("ip", "link", "add", "i3t0", "type", "dummy")
    a.host.run("ip", "link", "set", "i3t0", "alias", "ice3tier", "up")
    start_pair(a, b)
    t.check("[intercept] 不让节点起不来，记一行", "这一节已经不起作用" in a.read_log(), tail(a.read_log()))
    if installed(t, a, b):
        left = system_snapshot(a.host)
        t.check("以前的表、规则、路由都拆掉了", "table ip i3t {" not in left["nft"] and "2033" not in left["rules"] + left["routes"],
                snapshot_difference(left, left))
        t.check("以前的 dummy 网卡拆掉了，虚拟网卡用上了 i3t0", "dummy" not in a.host.run("ip", "-d", "link", "show", "i3t0").stdout)
        t.check("ping 通", received(ping(a, b.virtual_ip, count=2)) == 2)
    if t.failures:
        print(tail(a.read_log(), 30))


SCENARIOS = {
    "basics": basics, "rules": rules, "relay": relay, "tcp_relay": tcp_relay, "tcp_relay_flood": tcp_relay_flood, "nat": nat, "bundling": bundling, "firewall": firewall, "privilege": privilege,
    "overlap": overlap, "appears": appears, "leftover": leftover, "restart": restart, "mtu": mtu, "forward": forward,
    "offload": offload,
    "lan": lan, "lan_iptables": lan_iptables, "hostile": hostile, "managed": managed, "legacy": legacy,
}


def main() -> int:
    lablib.enter()
    names = sys.argv[1:] or list(SCENARIOS)
    t = Checks()
    for name in names:
        print(f"== {name}：{(SCENARIOS[name].__doc__ or '').strip()}", flush=True)
        with tempfile.TemporaryDirectory(prefix=f"i3t-e2e-{name}-") as work, Lab() as lab:
            try:
                SCENARIOS[name](lab, Path(work), t)
            except Exception as err:  # noqa: BLE001 - 一个场景出错不影响后面的场景
                t.check(f"{name} 没有跑完", False, repr(err))
        time.sleep(0.3)
    return t.summary()


if __name__ == "__main__":
    sys.exit(main())
