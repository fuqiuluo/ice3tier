#!/usr/bin/env python3
"""由 controller 管理的端到端测试：节点用注册令牌加入，配置全部由 controller 下发。

    python3 tests/e2e/test_managed.py [场景名...]
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab as lablib  # noqa: E402
from harness import (Checks, Controller, Node, RestoredController, add_node_config, binary, blob_digest, blob_file,  # noqa: E402
                     controller_data, create_groups, ctl_wait, eventually_value, fetch, shape_between, start_blob_server,
                     start_whoami, tail)
from lab import Lab, NatKind, wait_until  # noqa: E402


def reaches(node: Node, url: str, via: Node, expect: str, timeout: float = 20) -> bool:
    """反复尝试，直到经 `via` 访问 `url` 得到 `expect`，或者超时。配置下发和建连都要一点时间。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if node.curl(url, via=via, timeout=6).stdout == expect:
            return True
        time.sleep(0.5)
    return False


def blocked(node: Node, url: str, via: Node, timeout: float = 15) -> bool:
    """反复尝试，直到经 `via` 访问 `url` 失败，或者超时。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if node.curl(url, via=via, timeout=6).returncode != 0:
            return True
        time.sleep(0.5)
    return False


def join_and_exit(lab: Lab, work: Path, t: Checks) -> None:
    """两个公网节点加入网络；启用出口；访问规则收紧和放开；删除节点。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab", "--cidr", "10.66.0.0/16")
    a, b = Node(lab.host("a"), work), Node(lab.host("b"), work, declare=("exit",))
    create_groups(controller, "laptop", "server")
    a.join(controller, "laptop")
    b.join(controller, "server")
    t.check("加入之后得到虚拟 IP 和名字", (a.virtual_ip, b.virtual_ip) == ("10.66.0.1", "10.66.0.2"), f"{a.virtual_ip} {b.virtual_ip}")
    wait_until(lambda: all(controller.node(node)["online"] for node in (a, b)), what="两个节点上线")

    url = f"http://{web.ip}/"
    refused = controller.ctl("proxy", "add", str(a.id), "127.0.0.1:11000", str(b.id), check=False)
    t.check("出口没启用时建不了经 b 出去的代理", refused.returncode != 0 and "exit_not_enabled" in refused.stderr, refused.stderr.strip())
    refused = controller.ctl("exit", "enable", str(a.id), check=False)
    t.check("没有声明的节点启用不了出口，并且提示要执行的命令", refused.returncode != 0 and "i3t set can-exit on" in refused.stderr,
            refused.stderr.strip())
    refused = controller.ctl("proxy", "add", str(a.id), "127.0.0.1:11000", str(a.id), check=False)
    t.check("出口不能是监听的节点自己", refused.returncode != 0 and "exit_is_node" in refused.stderr, refused.stderr.strip())
    controller.ctl("exit", "enable", str(b.id))
    proxy = controller.add_proxy(a, b)
    t.check("建好代理之后，不用重启节点就能经 b 出去", reaches(a, url, b, b.host.ip))
    shown = controller.wait_proxy(proxy["id"])
    t.check("代理的状态是在监听", shown["status"] == {"code": "listening", "local": f"127.0.0.1:{a.proxies[b.id].port}"}, str(shown["status"]))
    exits = controller.ctl("exit", "list")
    t.check("出口的视图列出经它出去的代理", [entry["id"] for entry in exits[0]["proxies"]] == [proxy["id"]], str(exits[0]["proxies"]))

    rules = controller.ctl("rule", "list")
    controller.ctl("rule", "delete", str(rules[0]["id"]))
    t.check("删掉 All <-> All 之后互相不可达", blocked(a, url, b))
    t.check("代理留着，状态说访问规则不让它访问出口", controller.proxy(proxy["id"])["status"]["code"] == "access_denied",
            str(controller.proxy(proxy["id"])["status"]))
    controller.ctl("rule", "add", "laptop", "server", "--one-way")
    t.check("加上 laptop -> server 之后 a 又能用 b", reaches(a, url, b, b.host.ip))
    b.stop()
    offline = controller.wait_proxy(proxy["id"], "exit_offline", timeout=60)
    t.check("出口离线时代理的状态说出口离线", offline["status"]["code"] == "exit_offline", str(offline["status"]))
    b.start()

    controller.ctl("node", "delete", str(a.id))
    wait_until(lambda: a.proc.poll() is not None, timeout=20, what="被删除的节点自己退出")
    t.check("被删除的节点说明了原因", "吊销" in a.read_log(), tail(a.read_log(), 5))
    if t.failures:
        print(tail(a.read_log()), tail(b.read_log()), tail(controller.log.read_text(errors="replace")), sep="\n  ---\n")


def enable_relay(lab: Lab, work: Path, t: Checks) -> None:
    """两个节点都在对称型 NAT 后面，没有 relay 时不可达；在 controller 上启用 relay 之后自动经它转发。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    r = Node(lab.host("r"), work, declare=("relay",))
    a = Node(lab.nat("nat-a", NatKind.SYMMETRIC).host("a"), work)
    b = Node(lab.nat("nat-b", NatKind.SYMMETRIC).host("b"), work, declare=("exit",))
    for node in (r, a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    url, expect = f"http://{web.ip}/", lab.hosts["nat-b"].ip

    t.check("没有 relay 时这对节点不可达", a.curl(url, via=b, timeout=10).returncode != 0)
    controller.ctl("relay", "enable", str(r.id))
    t.check("启用 relay 之后，不用重启节点就能经它到达", reaches(a, url, b, expect, timeout=30))
    def route_to_b() -> dict:
        routes = controller.ctl("node", "routes", str(a.id))["routes"]
        return next((route["route"] for route in routes if route["peer"]["id"] == b.id), {})

    try:
        wait_until(lambda: route_to_b().get("via") == "relay", timeout=15, what="a 上报经 relay 的路由")
    except TimeoutError:
        pass
    t.check("a 上报的路由显示经 relay", route_to_b() == {"via": "relay", "relays": [r.id]}, str(route_to_b()))
    pinged = a.host.run(binary("i3t"), "--state-dir", str(a.state), "ping", b.name, check=False, timeout=20)
    t.check("i3t ping 写 relay 的名字，不写编号", pinged.returncode == 0 and f"经 {r.name}" in pinged.stdout and f"#{r.id}" not in pinged.stdout,
            f"{pinged.stdout!r} {pinged.stderr.strip()}")
    if t.failures:
        print(tail(a.read_log(), 25), tail(b.read_log(), 25), tail(r.read_log(), 25), sep="\n  ---\n")


def route_of(controller: Controller, node: Node, peer: Node) -> dict:
    """`node` 最近上报的、到 `peer` 的路。"""
    routes = controller.ctl("node", "routes", str(node.id))["routes"]
    return next((route["route"] for route in routes if route["peer"]["id"] == peer.id), {})


def direct_status_of(controller: Controller, node: Node, peer: Node) -> dict:
    """`node` 最近上报的、到 `peer` 的直连在哪一步；还没有报过时是空的。"""
    routes = controller.ctl("node", "routes", str(node.id))["routes"]
    return next((route.get("direct_status") or {} for route in routes if route["peer"]["id"] == peer.id), {})


def wait_route(controller: Controller, node: Node, peer: Node, via: str, timeout: float = 30) -> dict:
    try:
        wait_until(lambda: route_of(controller, node, peer).get("via") == via, timeout=timeout, what=f"{node.name} 到 {peer.name} 的路变成 {via}")
    except TimeoutError:
        pass
    return route_of(controller, node, peer)


def slow_download(node: Node, url: str, via: Node, megabytes: int, rate: str = "1M"):
    """在后台开始一次限速下载，返回进程。限速是为了让它持续几十秒，中间好换路。"""
    import subprocess
    size = megabytes * 1_000_000
    cmd = node.host.cmd("curl", "-sS", "--max-time", "120", "--limit-rate", rate, "-o", "/dev/null", "-w", "%{size_download}",
                        "-x", node.entry(via).url("socks5h"), f"{url}bytes/{size}")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True), size


def finished_intact(download, size: int, timeout: float = 120) -> tuple[bool, str]:
    out, err = download.communicate(timeout=timeout)
    return out == str(size), f"下载了 {out!r}，应该是 {size}；{err.strip()}"


def hole_punch(lab: Lab, work: Path, t: Checks) -> None:
    """两个节点各在一个普通 NAT 后面，没有 relay：经 controller 交换地址，打洞直连。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a = Node(lab.nat("nat-a", NatKind.CONE).host("a"), work)
    b = Node(lab.nat("nat-b", NatKind.CONE).host("b"), work, declare=("exit",))
    for node in (a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    url, expect = f"http://{web.ip}/", lab.hosts["nat-b"].ip

    t.check("没有 relay，靠打洞也能到达", reaches(a, url, b, expect, timeout=40))
    route = wait_route(controller, a, b, "direct")
    t.check("a 上报的路由是直连，地址是 b 所在 NAT 的公网地址", route.get("via") == "direct" and route.get("addr", "").startswith(expect + ":"), str(route))
    download, size = slow_download(a, url, b, 5, rate="5M")
    ok, detail = finished_intact(download, size)
    t.check("打洞出来的直连上下载 5MB", ok, detail)
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log(), 30), sep="\n  ---\n")


def relay_then_direct(lab: Lab, work: Path, t: Checks) -> None:
    """有 relay 时第一次访问不用等打洞；直连打通之后换过去，正在进行的下载不断。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    r = Node(lab.host("r"), work, declare=("relay",))
    a = Node(lab.nat("nat-a", NatKind.CONE).host("a"), work)
    b = Node(lab.nat("nat-b", NatKind.CONE).host("b"), work, declare=("exit",))
    # 这里看的是对端多的网络（多过 32 个）：直连等第一次用到才试。小网络里不等流量就试，见 direct_without_traffic。
    for node in (a, b):
        node.env = {"I3T_TEST_EAGER_DIRECT_PEERS": "0"}
    for node in (r, a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    controller.ctl("relay", "enable", str(r.id))
    url, expect = f"http://{web.ip}/", lab.hosts["nat-b"].ip
    wait_until(lambda: all(controller.ctl("node", "show", str(node.id))["attached"] for node in (a, b)), timeout=20, what="两个节点挂靠上 relay")
    # 两个节点还没有说过话：直连一次也没有试过，路由表这样说，而不是看起来像"直连失败了"。
    untried = eventually_value(lambda: direct_status_of(controller, a, b), lambda status: bool(status), timeout=20)
    t.check("没有说过话的两个节点：直连是 not_tried", untried.get("state") == "not_tried" and untried.get("attempted_at") is None, str(untried))
    table = controller.host.run(binary("i3tctl"), "--token", controller.token, "node", "routes", str(a.id), check=False).stdout
    t.check("命令行的路由表上写着直连未尝试", "未尝试" in table, table)

    started = time.monotonic()
    download, size = slow_download(a, url, b, 30)
    wait_until(lambda: "和对端的连接建立" in a.read_log() or download.poll() is not None, timeout=15, what="a 和 b 建立连接")
    t.check("第一次访问在 3 秒内就连上了（先经 relay，不等打洞）", time.monotonic() - started < 3 and download.poll() is None,
            f"用了 {time.monotonic() - started:.1f} 秒")
    route = wait_route(controller, a, b, "direct", timeout=75)
    switched_during_download = download.poll() is None
    t.check("之后换到了直连", route.get("via") == "direct", str(route))
    verified = direct_status_of(controller, a, b)
    t.check("直连是 verified，带着最近一次尝试的时间", verified.get("state") == "verified" and verified.get("attempted_at"), str(verified))
    t.check("换路发生在下载进行当中", switched_during_download)
    ok, detail = finished_intact(download, size)
    t.check("换路没有打断下载，字节数对得上", ok, detail)
    if t.failures:
        print(tail(a.read_log(), 40), tail(b.read_log(), 25), sep="\n  ---\n")


def tcp_relay(lab: Lab, work: Path, t: Checks) -> None:
    """a 所在的网络用不了 UDP：它用 TCP 连 relay，b 照常用 UDP。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    r = Node(lab.host("r"), work, declare=("relay",))
    a = Node(lab.nat("nat-a", NatKind.CONE).host("a"), work)
    b = Node(lab.nat("nat-b", NatKind.CONE).host("b"), work, declare=("exit",))
    a.host.block_udp()
    for node in (r, a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    controller.ctl("relay", "enable", str(r.id))
    url, expect = f"http://{web.ip}/", lab.hosts["nat-b"].ip

    t.check("UDP 用不了的节点经 TCP 中转也能到达", reaches(a, url, b, expect, timeout=40))
    t.check("a 用的是 TCP 中转", "中转会话建立（TCP）" in a.read_log(), tail(a.read_log(), 8))
    t.check("b 用的是 UDP 中转", "中转会话建立（UDP）" in b.read_log(), tail(b.read_log(), 8))
    download, size = slow_download(a, url, b, 10, rate="5M")
    ok, detail = finished_intact(download, size)
    t.check("经 TCP 中转下载 10MB", ok, detail)

    a.host.block_udp(False)
    route = wait_route(controller, a, b, "direct", timeout=90)
    t.check("UDP 恢复之后改走直连", route.get("via") == "direct", str(route))
    if t.failures:
        print(tail(a.read_log(), 40), tail(r.read_log(), 20), sep="\n  ---\n")


def relay_failover(lab: Lab, work: Path, t: Checks) -> None:
    """正在用的 relay 下线：连接换到另一个 relay，正在进行的下载不断。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    r1, r2 = Node(lab.host("r1"), work, declare=("relay",)), Node(lab.host("r2"), work, declare=("relay",))
    a = Node(lab.nat("nat-a", NatKind.SYMMETRIC).host("a"), work)
    b = Node(lab.nat("nat-b", NatKind.SYMMETRIC).host("b"), work, declare=("exit",))
    for node in (r1, r2, a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    for relay in (r1, r2):
        controller.ctl("relay", "enable", str(relay.id))
    url, expect = f"http://{web.ip}/", lab.hosts["nat-b"].ip
    t.check("经 relay 到达", reaches(a, url, b, expect, timeout=40))

    download, size = slow_download(a, url, b, 30)
    time.sleep(5)
    used = wait_route(controller, a, b, "relay", timeout=15).get("relays", [None])[0]
    victim = r1 if used == r1.id else r2
    victim.stop()
    survivor = r2 if victim is r1 else r1
    ok, detail = finished_intact(download, size)
    t.check(f"下载途中停掉正在用的 relay（{victim.name}），下载没有断", ok, detail)
    route = wait_route(controller, a, b, "relay", timeout=20)
    t.check(f"之后的路改经 {survivor.name}", route.get("relays") == [survivor.id], f"{route}，原先经 {used}")
    if t.failures:
        print(tail(a.read_log(), 40), tail(b.read_log(), 25), sep="\n  ---\n")


def relay_record(controller: Controller, relay: Node) -> dict:
    """controller 眼里这个 relay 的 `relay` 一项：它的地址（找出来的）和设置。"""
    return controller.ctl("node", "show", str(relay.id))["relay"] or {}


def attached_to(controller: Controller, node: Node) -> list[int]:
    return [entry["relay"] for entry in controller.ctl("node", "show", str(node.id))["attached"]]


def relay_without_udp(lab: Lab, work: Path, t: Checks) -> None:
    """relay 所在的机器收不到 UDP：没有人说它只能用 TCP，节点自己改用 TCP 连它，照常经它到达。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    r = Node(lab.host("r"), work, declare=("relay",))
    lablib.drop_inbound_udp(r.host)
    a = Node(lab.nat("nat-a", NatKind.SYMMETRIC).host("a"), work)
    b = Node(lab.nat("nat-b", NatKind.SYMMETRIC).host("b"), work, declare=("exit",))
    for node in (r, a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    enabled = controller.ctl("relay", "enable", str(r.id))
    addresses = [entry["address"] for entry in enabled["relay"]["addresses"]]
    t.check("启用时不填地址，controller 找出了 relay 的地址", addresses[:1] == [r.endpoint], str(enabled["relay"]))
    udp = [check for check in enabled["reachability"] if check["protocol"] == "udp"]
    t.check("controller 试连 UDP 不通也照样启用", bool(udp) and not udp[0]["reachable"] and enabled["relay"] is not None, str(enabled["reachability"]))
    url, expect = f"http://{web.ip}/", lab.hosts["nat-b"].ip
    t.check("经这个 relay 到达", reaches(a, url, b, expect, timeout=40))
    t.check("a 自己改用了 TCP 连它", "中转会话建立（TCP）" in a.read_log(), tail(a.read_log(), 8))
    if t.failures:
        print(tail(a.read_log(), 30), tail(r.read_log(), 20), sep="\n  ---\n")


def relay_on_declared_address(lab: Lab, work: Path, t: Checks) -> None:
    """relay 在 NAT 后面，路由器只在另一个端口上映射进来：它看到的地址和网卡上的地址都连不上，节点上声明的那个连得上。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    nat_r = lab.nat("nat-r", NatKind.CONE)
    r = Node(nat_r.host("r"), work, declare=("relay",))
    lablib.forward_port_as(nat_r, 40330, r.host, 20330)
    declared = f"{nat_r.ip}:40330"
    said = r.host.run(binary("i3t"), "--state-dir", str(r.state), "set", "relay-address", declared, check=False)
    t.check("i3t set relay-address 写进配置", said.returncode == 0 and declared in said.stdout, said.stderr.strip())
    a = Node(lab.nat("nat-a", NatKind.SYMMETRIC).host("a"), work)
    b = Node(lab.nat("nat-b", NatKind.SYMMETRIC).host("b"), work, declare=("exit",))
    for node in (r, a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    enabled_at = time.monotonic()
    controller.ctl("relay", "enable", str(r.id))
    relay = relay_record(controller, r)
    listed = [(entry["address"], entry["source"]) for entry in relay.get("addresses", [])]
    t.check("声明的地址排在最前，后面是 controller 看到的和网卡上的",
            listed[:3] == [(declared, "declared"), (f"{nat_r.ip}:20330", "observed"), (f"{r.host.ip}:20330", "local")], str(listed))
    try:
        wait_until(lambda: r.id in attached_to(controller, a), timeout=20, what="a 挂靠上 relay")
    except TimeoutError:
        pass
    took = time.monotonic() - enabled_at
    t.check("前两个地址连不上，也很快挂靠上（不挨个等）", r.id in attached_to(controller, a) and took < 15, f"用了 {took:.1f} 秒")
    t.check("用的是声明的地址", f"via={declared}" in a.read_log(), tail(a.read_log(), 8))
    url, expect = f"http://{web.ip}/", lab.hosts["nat-b"].ip
    t.check("经它到达", reaches(a, url, b, expect, timeout=30))
    if t.failures:
        print(tail(a.read_log(), 30), tail(r.read_log(), 20), sep="\n  ---\n")


def relay_in_a_lan(lab: Lab, work: Path, t: Checks) -> None:
    """relay 在一个局域网里，外面连不进来：同一个局域网里的节点靠它网卡上的地址用它，外面的节点用不了，也没有谁说它坏了。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    lan = lab.nat("nat-l", NatKind.CONE)
    r = Node(lan.host("r"), work, declare=("relay",))
    inside = Node(lan.host("inside"), work)
    outside = Node(lab.nat("nat-o", NatKind.SYMMETRIC).host("outside"), work)
    for node in (r, inside, outside):
        node.join(controller)
    enabled_at = time.monotonic()
    controller.ctl("relay", "enable", str(r.id))
    listed = [(entry["address"], entry["source"]) for entry in relay_record(controller, r).get("addresses", [])]
    t.check("relay 的地址：controller 看到的是局域网的出口，网卡上的是内网地址",
            listed == [(f"{lan.ip}:20330", "observed"), (f"{r.host.ip}:20330", "local")], str(listed))
    try:
        wait_until(lambda: r.id in attached_to(controller, inside), timeout=20, what="局域网里的节点挂靠上 relay")
    except TimeoutError:
        pass
    took = time.monotonic() - enabled_at
    t.check("同一个局域网里的节点经内网地址用上了它", r.id in attached_to(controller, inside) and f"via={r.host.ip}:20330" in inside.read_log(),
            tail(inside.read_log(), 8))
    t.check("排在前面的地址连不上，也很快挂靠上（不挨个等）", took < 15, f"用了 {took:.1f} 秒")
    time.sleep(8)
    t.check("外面的节点连不上它，也就不用它", r.id not in attached_to(controller, outside), str(attached_to(controller, outside)))
    shown = controller.ctl("node", "show", str(r.id))
    t.check("它照样是启用着的 relay，没有提醒", shown["relay"] is not None and shown["warnings"] == [], str(shown["warnings"]))
    if t.failures:
        print(tail(inside.read_log(), 30), tail(outside.read_log(), 20), sep="\n  ---\n")


def relay_for_half(lab: Lab, work: Path, t: Checks) -> None:
    """两个中继只有家里（一个局域网里）的节点连得上，离家里的节点最近；第三个谁都连得上。外面的节点照样经两边共同的那个到达
    家里的节点，中继列表上如实写着谁连得上谁，只有部分节点连得上的中继不算毛病。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    home = lab.nat("nat-h", NatKind.CONE)
    near = [Node(home.host(name), work, declare=("relay",)) for name in ("rh1", "rh2")]
    a = Node(home.host("a"), work, declare=("exit",))
    everyone = Node(lab.host("rall"), work, declare=("relay",))
    everyone.host.shape(lablib.Shape(rtt_ms=40))
    b = Node(lab.nat("nat-b", NatKind.SYMMETRIC).host("b"), work)
    for node in (*near, a, everyone, b):
        node.join(controller)
    for relay in (*near, everyone):
        controller.ctl("relay", "enable", str(relay.id))
    controller.ctl("exit", "enable", str(a.id))
    controller.add_proxy(b, a)
    url, expect = f"http://{web.ip}/", home.ip

    def attached(node: Node) -> list[tuple[int, bool]]:
        return sorted((entry["relay"], entry.get("shared", False)) for entry in controller.node(node)["attached"])

    try:
        wait_until(lambda: (everyone.id, True) in attached(a), timeout=60, what="a 另外挂上两边都连得上的中继")
    except TimeoutError:
        pass
    own = sorted(relay.id for relay in near)
    t.check("a 自己挑的是家里那两个，另外挂上了两边都连得上的那个", attached(a) == [*[(id, False) for id in own], (everyone.id, True)],
            str(attached(a)))
    t.check("外面的节点经共同的中继用上家里的出口", reaches(b, url, a, expect, timeout=60))
    # a 挂上共同的中继之前，这一对可能先走过一串中继（默认模式没有共同的中继时的退路），有了共同的中继就换到它上面；
    # 路由表是节点隔一会儿报一次的，所以等这条路出现，而不是看到第一条经中继的路就断言。
    shared = {"via": "relay", "relays": [everyone.id]}
    route = eventually_value(lambda: route_of(controller, b, a), lambda found: found == shared, timeout=40, interval=1)
    t.check("b 到 a 经两边都连得上的中继", route == shared, str(route))

    def reach_of(relay: Node) -> dict:
        listed = {entry["id"]: entry for entry in controller.ctl("relay", "list")}
        return (listed.get(relay.id, {}).get("relay") or {}).get("reach", {})

    try:
        wait_until(lambda: reach_of(near[0]).get("unknown") == 0, timeout=60, what="每个在线的节点都报了试 rh1 的结果")
    except TimeoutError:
        pass
    # rall 也连得上 rh1：rh1 自己连着 rall，家里的路由器放行 rall 回来的包。外面的 b 连不上。
    reach = reach_of(near[0])
    t.check("中继列表：家里的节点连得上 rh1，外面的 b 连不上", reach.get("reached", 0) >= 2 and reach.get("unreached") == 1, str(reach))
    shown = controller.ctl("node", "show", str(near[0].id))
    outcomes = {entry["node"]["id"]: entry["outcome"] for entry in shown["reached_by"] or []}
    t.check("节点详情写着谁连不上它", outcomes.get(b.id) == "unreached" and outcomes.get(a.id) in ("udp", "tcp"), str(outcomes))
    t.check("只有部分节点连得上的中继没有提醒", shown["warnings"] == [] and controller.ctl("overview")["warnings"] == [], str(shown["warnings"]))
    listed = controller.host.run(binary("i3tctl"), "--token", controller.token, "relay", "list", check=False).stdout
    counts = f"{reach.get('reached')}/{reach.get('unreached')}/{reach.get('unknown')}"
    t.check("i3tctl relay list 列出各个中继连得上的节点数", near[0].name in listed and counts in listed, listed)
    t.check("a 的出口地址是家里的公网地址", controller.node(a)["egress_ip"] == home.ip, str(controller.node(a)["egress_ip"]))
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log(), 30), tail(controller.log.read_text(errors="replace"), 10), sep="\n  ---\n")


def backbone_rows(controller: Controller) -> dict[int, dict[int, int | None]]:
    """controller 问来的骨干矩阵：每个 relay 到别的 relay 的延迟（毫秒，连不上是 None）。"""
    return {row["relay"]["id"]: {link["to"]: link["rtt_ms"] for link in row["links"]} for row in controller.ctl("backbone")["relays"]}


def chain_through_relay_without_udp(lab: Lab, work: Path, t: Checks) -> None:
    """三个中继，中间那个的机房挡掉了 UDP：它和另外两个之间的骨干走 TCP，经它的一串中继两个方向各传 1 MB。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab", "--routing", "lowest-cost", "--max-relay-hops", "3")
    r1, r2, r3 = (Node(lab.host(name), work, declare=("relay",)) for name in ("r1", "r2", "r3"))
    a, d = Node(lab.host("a"), work), Node(lab.host("d"), work)
    r2.host.block_udp()
    # a 只够得着 r1，d 只够得着 r3，r1 和 r3 之间什么都不通：a 到 d 只有 r1 → r2 → r3 这一串。
    lablib.isolate(a.host, r2.host, r3.host, d.host)
    lablib.isolate(d.host, r1.host, r2.host)
    lablib.isolate(r1.host, r3.host)
    start_blob_server(d.host, work)
    for node in (r1, r2, r3, a, d):
        node.join(controller)
    enabled = time.monotonic()
    for relay in (r1, r2, r3):
        controller.ctl("relay", "enable", str(relay.id))

    def linked() -> bool:
        rows = backbone_rows(controller)
        return all(rows.get(x.id, {}).get(y.id) is not None for x, y in ((r1, r2), (r2, r1), (r2, r3), (r3, r2)))

    try:
        wait_until(linked, timeout=60, interval=1, what="r2 和 r1、r3 之间的骨干")
    except TimeoutError:
        pass
    rows = backbone_rows(controller)
    t.check("没有 UDP 的 r2 和 r1、r3 之间的骨干通了，延迟有数", linked(), str(rows))
    t.check("r1 和 r3 之间照实是连不上", rows.get(r1.id, {}).get(r3.id) is None, str(rows))
    r2_log = r2.read_log().splitlines()
    over_tcp = [peer.name for peer in (r1, r3)
                if any("中转会话建立" in line and f"node={peer.id} " in line and 'via="TCP"' in line for line in r2_log)]
    t.check("r1、r3 在 r2 上的会话走 TCP", over_tcp == [r1.name, r3.name], "\n".join(r2_log[-12:]))
    megabyte = 1 << 20
    download = eventually_value(lambda: fetch(a, f"http://{d.virtual_ip}/blob/{megabyte}", via=None, timeout=30),
                                lambda done: done[0] == 0, timeout=90, interval=2)
    took = time.monotonic() - enabled
    t.check(f"经 r1 → r2 → r3 下载 1 MB，内容完整（启用中继之后 {took:.1f} 秒）", download[:2] == (0, blob_digest(megabyte)), str(download))
    upload = fetch(a, f"http://{d.virtual_ip}/digest", via=None, upload=blob_file(a, megabyte), timeout=60)
    t.check("反方向上传 1 MB，内容完整", upload[:2] == (0, blob_digest(megabyte)), str(upload))
    # 路由表是节点上报的，晚一点才到。
    forward, backward = wait_route(controller, a, d, "relay"), wait_route(controller, d, a, "relay")
    t.check("a 到 d 经三个中继", forward == {"via": "relay", "relays": [r1.id, r2.id, r3.id]}, str(forward))
    t.check("d 到 a 倒过来经同样三个", backward == {"via": "relay", "relays": [r3.id, r2.id, r1.id]}, str(backward))
    print(f"   计时：启用中继到第一次 1 MB 下载完成 {took:.1f} 秒", flush=True)
    if t.failures:
        print(tail(r1.read_log(), 25), tail(r2.read_log(), 40), tail(a.read_log(), 25), sep="\n  ---\n")


def tcp_only_relay_prices_its_own_relay(lab: Lab, work: Path, t: Checks) -> None:
    """没有 UDP 的中继 s（延迟优先）：经它自己的中继到对端的那条路按量到的算。对端 a 是中继时，这条路和经 a 的那条是同一条 TCP，
    代价一样；对端 y 不是中继、也没有把 s 列进挂靠表时，s 经 y 的会话自己去量，不再是两三毫秒。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    s = Node(lab.host("s"), work, declare=("relay",))
    a, r = (Node(lab.host(name), work, declare=("relay",)) for name in ("a", "r"))
    y = Node(lab.host("y"), work)
    # y 离 r、a 近，挂靠的是它们两个；s 离谁都是 100 ms 以上，只经 TCP，线上丢 3% 的包。
    for one, other, rtt, loss in ((s, a, 100, 3), (s, r, 110, 3), (s, y, 120, 3), (a, r, 30, 0), (a, y, 20, 0), (r, y, 2, 0)):
        shape_between(one.host, other.host, lablib.Shape(rtt_ms=rtt, loss_pct=loss))
    s.host.block_udp()
    for node in (a, r, y, s):
        node.join(controller)
    for relay in (a, r, s):
        controller.ctl("relay", "enable", str(relay.id))
    controller.ctl("node", "set", str(s.id), "--routing", "lowest-cost")

    def candidates(peer: Node) -> dict[tuple, dict]:
        # 有流量的对端 s 才为它选路、探测；y 也因此在 s 的中继上建会话（s 自己是中继，y 经它到 s）。
        s.host.run(binary("i3t"), "--state-dir", str(s.state), "ping", peer.name, "--count", "1", check=False, timeout=20)
        forward = controller.ctl("path", str(s.id), str(peer.id)).get("forward") or {}
        return {tuple(entry["route"].get("relays") or ()): entry for entry in forward.get("candidates") or []}

    own = (s.id,)
    to_y = eventually_value(lambda: candidates(y), lambda found: own in found and found[own]["cost_us"] < 1_000_000, timeout=90, interval=3)
    cost = to_y.get(own, {}).get("cost_us", 0) / 1000
    t.check(f"经 s 自己的中继到 y：量到了（{cost:.0f} ms），不是两三毫秒，也不是没量到时的 1.5 秒", 100 < cost < 1000, str(to_y.get(own)))
    to_a = eventually_value(lambda: candidates(a), lambda found: own in found and (a.id,) in found, timeout=60, interval=3)
    costs = [to_a.get(path, {}).get("cost_us", 0) / 1000 for path in (own, (a.id,))]
    t.check(f"到中继 a：经 s 自己的中继和经 a 的中继是同一条 TCP，代价一样（{costs[0]:.0f} / {costs[1]:.0f} ms）",
            costs[0] > 50 and abs(costs[0] - costs[1]) < 1, str(to_a))
    result = ctl_wait(controller, "test", s.name, y.name, "--via", s.name)
    hops = next((entry.get("hops") or [] for entry in result.get("relay_quality") or [] if (entry.get("route") or {}).get("relays") == [s.id]), [])
    t.check("主动测试里这一段写着是 s 自己量的", [(hop["from"], hop["to"], hop["source"]) for hop in hops] == [(s.id, y.id, "measured")], str(hops))
    if t.failures:
        print(tail(s.read_log(), 30), tail(y.read_log(), 15), sep="\n  ---\n")


def idle_pair_without_direct_keeps_its_route(lab: Lab, work: Path, t: Checks) -> None:
    """没有 UDP 的中继 s 和普通节点 y 之间没有流量，直连永远打不通。小网络里两边每分钟会不等流量地再试一次直连；
    这种尝试不该让 y 以为 s 有流量：不然 y 每分钟为它建一次到 s 的中继的会话、把路换过去，45 秒后会话回收、路又换走。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    s = Node(lab.host("s"), work, declare=("relay",))
    a, r = (Node(lab.host(name), work, declare=("relay",)) for name in ("a", "r"))
    y = Node(lab.host("y"), work)
    # y 挂靠的是离它近的 a 和 r；s 远，y 不挂靠它，到 s 的中继的会话只在 s 有流量时才临时建。
    for one, other, rtt in ((s, a, 100), (s, r, 110), (s, y, 120), (a, r, 30), (a, y, 20), (r, y, 2)):
        shape_between(one.host, other.host, lablib.Shape(rtt_ms=rtt))
    s.host.block_udp()
    for node in (a, r, y, s):
        node.join(controller)
    for relay in (a, r, s):
        controller.ctl("relay", "enable", str(relay.id))
    eventually_value(lambda: controller.ctl("node", "list"), lambda nodes: all(node.get("online") for node in nodes), timeout=40)

    def changes() -> list[str]:
        return [line for line in y.read_log().splitlines() if "到对端的路变了" in line and f"peer={s.id} " in line]

    # 头半分钟里路怎么定下来的不管；之后两分多钟（两轮不等流量的尝试）里，到 s 的路不该再变。
    time.sleep(30)
    settled = len(changes())
    time.sleep(140)
    later = changes()[settled:]
    t.check(f"y 到 s 的路在没有流量的两分多钟里没有变（变了 {len(later)} 次）", not later, "\n".join(later[-6:]))
    sessions = [line for line in s.read_log().splitlines() if "中转会话建立" in line and f"node={y.id} " in line]
    t.check(f"y 没有每分钟到 s 的中继上建一次会话（{len(sessions)} 次）", len(sessions) <= 1, "\n".join(sessions[-6:]))
    if t.failures:
        print(tail(y.read_log(), 20), tail(s.read_log(), 10), sep="\n  ---\n")


def two_islands(lab: Lab, work: Path, t: Checks) -> None:
    """家里的节点只连得上家里的中继 H（局域网地址），外面的节点只连得上公网的中继 P，H 和 P 连得上：默认模式下外面的节点经
    P → H 用家里节点上的服务，路由表说出为什么；两边都连得上的中继出现之后，这一对换到它上面。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    home = lab.nat("nat-h", NatKind.CONE)
    h = Node(home.host("rh"), work, declare=("relay",))
    a = Node(home.host("a"), work)
    p = Node(lab.host("rp"), work, declare=("relay",))
    s = Node(lab.host("rs"), work, declare=("relay",))
    o = Node(lab.host("o"), work)
    lablib.isolate(a.host, p.host)
    lablib.isolate(o.host, home)
    start_whoami(a.host, 8080)
    started = time.monotonic()
    for node in (h, a, p, s, o):
        node.join(controller)
    for relay in (h, p):
        controller.ctl("relay", "enable", str(relay.id))
    url = f"http://{a.virtual_ip}:8080/"
    served = eventually_value(lambda: o.curl(url, timeout=8), lambda done: done.returncode == 0 and done.stdout, timeout=90, interval=2)
    took = time.monotonic() - started
    t.check(f"外面的节点用上了家里节点上的服务（{took:.1f} 秒）", served.returncode == 0 and bool(served.stdout), served.stderr.strip())
    route = wait_route(controller, o, a, "relay", timeout=10)
    t.check("o 到 a 经 P → H", route == {"via": "relay", "relays": [p.id, h.id]}, str(route))
    # a 的路是它自己报给 controller 的（十秒一次）：服务一通就问的话，这一份常常还没到。
    back = wait_route(controller, a, o, "relay", timeout=15)
    t.check("a 到 o 经 H → P", back == {"via": "relay", "relays": [h.id, p.id]}, str(back))
    path = controller.ctl("path", str(o.id), str(a.id))
    cause = (path.get("forward") or {}).get("cause") or {}
    t.check("路径的原因：没有两端都用得上的中继", cause.get("code") == "no_shared_relay", str(path.get("forward", {}).get("reason")))
    shown = controller.host.run(binary("i3tctl"), "--token", controller.token, "path", str(o.id), str(a.id), check=False).stdout
    t.check("i3tctl path 写着为什么经一串中继（中继写的是名字）", "没有两端均可用的中继" in shown and f"{p.name} → {h.name}" in shown, shown)
    print(f"   计时：节点加入到外面的节点用上家里的服务 {took:.1f} 秒", flush=True)

    # 一个两边都连得上的中继出现了：这一对少绕路，换到它上面。
    controller.ctl("relay", "enable", str(s.id))
    route = {}
    try:
        wait_until(lambda: route_of(controller, o, a) == {"via": "relay", "relays": [s.id]}, timeout=60, interval=1,
                   what="o 到 a 换到两边都连得上的中继")
    except TimeoutError:
        pass
    route = route_of(controller, o, a)
    t.check("两边都连得上的中继出现之后，o 到 a 只经它一个", route == {"via": "relay", "relays": [s.id]}, str(route))
    path = controller.ctl("path", str(o.id), str(a.id))
    cause = (path.get("forward") or {}).get("cause") or {}
    t.check("换过去的原因是少绕了路", cause == {"code": "relay_changed", "hint": "shortcut", "previous": [p.id, h.id]}, str(cause))
    t.check("服务照常能用", o.curl(url, timeout=8).returncode == 0)
    if t.failures:
        print(tail(o.read_log(), 30), tail(a.read_log(), 20), tail(h.read_log(), 20), tail(p.read_log(), 20), sep="\n  ---\n")


def direct_without_traffic(lab: Lab, work: Path, t: Checks) -> None:
    """对端不多的两个节点不等流量就试直连：两台公网机器上线之后很快就在路由表上是直连，它们之间一条流也没有；
    对端多过上限的网络照旧等第一次用到（这里用测试的开关把上限压到 0）。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a, b = Node(lab.host("a"), work), Node(lab.host("b"), work)
    started = time.monotonic()
    for node in (a, b):
        node.join(controller)
    try:
        wait_until(lambda: all(route_of(controller, x, y).get("via") == "direct" for x, y in ((a, b), (b, a))), timeout=30,
                   interval=0.5, what="两个节点之间的直连")
    except TimeoutError:
        pass
    took = time.monotonic() - started
    statuses = (direct_status_of(controller, a, b), direct_status_of(controller, b, a))
    t.check(f"两边的路由表上都是直连、已验证（加入之后 {took:.1f} 秒）",
            all(status.get("state") == "verified" for status in statuses) and route_of(controller, a, b).get("via") == "direct", str(statuses))
    flows = [entry.get("flows") for entry in controller.ctl("node", "routes", str(a.id))["routes"]]
    t.check("它们之间没有连接，也就没有流", flows == [None] and "和对端的连接建立" not in a.read_log() + b.read_log(), str(flows))
    print(f"   计时：加入到两边都显示直连 {took:.1f} 秒", flush=True)

    # 另一个网络（另一个 controller），两个节点的上限压到 0。
    (work / "over").mkdir()
    other = Controller(lab.host("ctl2"), work / "over")
    other.ctl("network", "create", "lab")
    c, e = Node(lab.host("c"), work / "over"), Node(lab.host("e"), work / "over")
    for node in (c, e):
        node.env = {"I3T_TEST_EAGER_DIRECT_PEERS": "0"}
        node.join(other)
    try:
        wait_until(lambda: bool(direct_status_of(other, c, e)), timeout=20, what="c 上报到 e 的路")
    except TimeoutError:
        pass
    time.sleep(8)
    status = direct_status_of(other, c, e)
    t.check("对端多过上限：不试，路由表上是未尝试", status.get("state") == "not_tried" and route_of(other, c, e).get("via") == "none",
            f"{status} {route_of(other, c, e)}")
    if t.failures:
        print(tail(a.read_log(), 25), tail(b.read_log(), 15), sep="\n  ---\n")


def idle_held_offline(lab: Lab, work: Path, t: Checks) -> None:
    """没有 relay、controller 又停了：空闲的连接不回收（关掉就建不回来）；controller 回来之后照常回收。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a = Node(lab.nat("nat-a", NatKind.CONE).host("a"), work)
    b = Node(lab.nat("nat-b", NatKind.CONE).host("b"), work, declare=("exit",))
    for node in (a, b):
        add_node_config(node, "[performance]\nidle_close_secs = 3\n")
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    url, expect = f"http://{web.ip}/", lab.hosts["nat-b"].ip
    closed, held = "和对端的连接结束", "暂不回收空闲连接"

    t.check("打洞直连，a 经 b 访问", reaches(a, url, b, expect, timeout=40))
    try:
        wait_until(lambda: closed in a.read_log(), timeout=15, what="空闲的连接被回收")
    except TimeoutError:
        pass
    t.check("controller 在线时，空闲 3 秒的连接照常回收", closed in a.read_log(), tail(a.read_log(), 8))

    mark = len(a.read_log())
    t.check("又建起一条连接", reaches(a, url, b, expect, timeout=20))
    controller.host.stop(controller.proc)
    try:
        wait_until(lambda: "和 controller 的连接断了" in a.read_log()[mark:], timeout=15, what="a 发现 controller 不在了")
    except TimeoutError:
        pass
    time.sleep(8)
    since = a.read_log()[mark:]
    t.check("controller 停了、没有 relay：空闲的连接留着，并且说明了原因", closed not in since and held in since, tail(since, 8))
    t.check("留着的连接照常能用", a.curl(url, via=b, timeout=6).stdout == expect)

    RestoredController(controller.host, work, controller_data(controller), controller.token, controller.database)
    try:
        wait_until(lambda: closed in a.read_log()[mark:], timeout=60, what="controller 回来之后回收")
    except TimeoutError:
        pass
    t.check("controller 回来之后照常回收", closed in a.read_log()[mark:], tail(a.read_log()[mark:], 8))
    if t.failures:
        print(tail(a.read_log(), 30), tail(b.read_log(), 20), sep="\n  ---\n")


def range_overlap_warning(lab: Lab, work: Path, t: Checks) -> None:
    """节点所在的一个真实网络落在网络的地址段里：节点上和总览里有一条提醒，什么都不拦。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab", "--cidr", "10.66.0.0/16")
    a = Node(lab.host("a"), work)
    lablib.private_link(lab, a.host, "a-lan", "10.66.200.0/24")
    a.join(controller)
    warning = {"code": "range_overlap", "address": "10.66.200.1"}
    try:
        wait_until(lambda: controller.node(a)["warnings"] == [warning], timeout=30, what="节点上的提醒")
    except TimeoutError:
        pass
    t.check("节点上有地址段重叠的提醒", controller.node(a)["warnings"] == [warning], str(controller.node(a)["warnings"]))
    overview = controller.ctl("overview")
    t.check("总览里也有", [(entry["node"]["id"], entry["code"]) for entry in overview["warnings"]] == [(a.id, "range_overlap")],
            str(overview["warnings"]))
    shown = controller.host.run(binary("i3tctl"), "--token", controller.token, "node", "show", str(a.id), check=False).stdout
    t.check("i3tctl node show 写出了这条提醒", "网卡地址 10.66.200.1 在网络的地址段里" in shown, shown)
    t.check("节点照常在线", controller.node(a)["online"])


SCENARIOS = {
    "join_and_exit": join_and_exit,
    "enable_relay": enable_relay,
    "hole_punch": hole_punch,
    "relay_then_direct": relay_then_direct,
    "tcp_relay": tcp_relay,
    "relay_failover": relay_failover,
    "relay_without_udp": relay_without_udp,
    "relay_on_declared_address": relay_on_declared_address,
    "relay_in_a_lan": relay_in_a_lan,
    "range_overlap_warning": range_overlap_warning,
    "relay_for_half": relay_for_half,
    "idle_held_offline": idle_held_offline,
    "chain_through_relay_without_udp": chain_through_relay_without_udp,
    "two_islands": two_islands,
    "tcp_only_relay_prices_its_own_relay": tcp_only_relay_prices_its_own_relay,
    "idle_pair_without_direct_keeps_its_route": idle_pair_without_direct_keeps_its_route,
    "direct_without_traffic": direct_without_traffic,
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
