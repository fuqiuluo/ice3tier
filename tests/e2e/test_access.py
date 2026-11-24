#!/usr/bin/env python3
"""接入方式的端到端测试：节点上的服务、端口转发、出口背后的局域网、对外开放的代理，以及分组决定谁能访问谁。

    python3 tests/e2e/test_access.py [场景名...]
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab as lablib  # noqa: E402
from harness import (  # noqa: E402
    Checks, Controller, Node, Proxy, binary, blob_digest, blob_file, create_groups, eventually_value, group_names, hold_port, plain_http,
    start_blob_server, start_header_echo, start_proxy_protocol_echo, start_whoami, tail,
)
from lab import Lab, NatKind, wait_until  # noqa: E402


def socks(node: Node, url: str, via: Node | None = None, timeout: float = 8):
    """从 `node` 所在的机器经 SOCKS5 访问 `url`：经它上面经 `via` 出去的代理，`via` 是 `None` 时经本机的组网入口。"""
    return node.curl(url, via=via, timeout=timeout)


def eventually(action, ok, timeout: float = 25):
    """反复执行 `action`，直到 `ok(结果)` 为真或者超时；返回最后一次的结果。配置下发和建连都要一点时间。"""
    deadline = time.monotonic() + timeout
    while True:
        result = action()
        if ok(result) or time.monotonic() > deadline:
            return result
        time.sleep(0.5)


def node_service(lab: Lab, work: Path, t: Checks) -> None:
    """访问另一个节点上的服务：目标写它的虚拟 IP 或名字，不需要它是出口；只监听回环地址的服务到不了。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a, b = Node(lab.host("a"), work), Node(lab.host("b"), work)
    for node in (a, b):
        node.join(controller)
    start_whoami(b.host, 8080)
    start_whoami(b.host, 8081, bind="127.0.0.1")

    seen = eventually(lambda: socks(a, f"http://{b.virtual_ip}:8080/"), lambda r: r.returncode == 0)
    t.check("用虚拟 IP 访问 b 上的服务", seen.returncode == 0, seen.stderr.strip())
    t.check("服务看到的来源是 b 自己的非回环地址，不是 127.0.0.1", seen.stdout == b.host.ip, f"看到 {seen.stdout!r}")
    by_name = socks(a, "http://b.lab.i3t:8080/")
    t.check("用全名 b.lab.i3t 访问", by_name.stdout == b.host.ip, by_name.stderr.strip())
    loopback_only = socks(a, f"http://{b.virtual_ip}:8081/")
    t.check("只监听 127.0.0.1 的服务到不了", loopback_only.returncode != 0)
    as_exit = controller.ctl("proxy", "add", str(a.id), "127.0.0.1:11000", str(b.id), check=False)
    t.check("b 没有启用出口，建不了经它出去的代理", as_exit.returncode != 0 and "exit_not_enabled" in as_exit.stderr, as_exit.stderr.strip())
    outside = socks(a, "http://11.0.0.2/")
    t.check("组网入口到不了网络之外", outside.returncode != 0, outside.stdout)

    if t.failures:
        print(tail(a.read_log()), tail(b.read_log()), sep="\n  ---\n")


def port_forward(lab: Lab, work: Path, t: Checks) -> None:
    """端口转发：把目标节点回环上的服务转发到监听节点的本地端口，以及转发到目标节点的虚拟 IP 上。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a, c, d = Node(lab.host("a"), work), Node(lab.host("c"), work), Node(lab.host("d"), work)
    for node in (a, c, d):
        node.join(controller)
    controller.forward_target(c)
    for node in (c, d):
        start_whoami(node.host, 8081, bind="127.0.0.1")

    refused = controller.ctl("forward", "add", str(a.id), "127.0.0.1:9001", str(d.id), "127.0.0.1:8081", check=False)
    t.check("目标节点的开关关着时配不了转发，并且提示怎么打开", refused.returncode != 0 and "--forward-target on" in refused.stderr,
            refused.stderr.strip())

    controller.ctl("forward", "add", str(a.id), "127.0.0.1:9000", str(c.id), "127.0.0.1:8081")
    local = lambda: a.host.run("curl", "-sS", "--max-time", "6", "http://127.0.0.1:9000/", check=False)  # noqa: E731
    seen = eventually(local, lambda r: r.returncode == 0)
    t.check("a 的本地端口通到了 c 回环上的服务", seen.stdout == "127.0.0.1", f"{seen.stdout!r} {seen.stderr.strip()}")

    controller.ctl("forward", "add", str(c.id), f"{c.virtual_ip}:9100", str(c.id), "127.0.0.1:8081")
    seen = eventually(lambda: socks(a, f"http://{c.virtual_ip}:9100/"), lambda r: r.returncode == 0)
    t.check("监听在 c 的虚拟 IP 上的转发，组网里的节点可以访问", seen.stdout == "127.0.0.1", f"{seen.stdout!r} {seen.stderr.strip()}")
    # c 的虚拟网卡装着（默认打开）：这个端口也在操作系统里听着，只听虚拟 IP，经网卡来的连接也到得了；别的地址上没有它。
    listening = [line.split()[3] for line in c.host.run("ss", "-lnt").stdout.splitlines()[1:] if line.split()[3].endswith(":9100")]
    t.check("它在 c 的操作系统里只听虚拟 IP", listening == [f"{c.virtual_ip}:9100"], str(listening))
    other = socks(a, f"http://{c.virtual_ip}:8081/")
    t.check("没有配转发的回环端口仍然到不了", other.returncode != 0)

    forwards = controller.ctl("forward", "list")
    controller.ctl("forward", "delete", str(forwards[0]["id"]))
    gone = eventually(local, lambda r: r.returncode != 0)
    t.check("删掉转发之后本地端口不再可用", gone.returncode != 0)
    if t.failures:
        print(tail(a.read_log()), tail(c.read_log()), sep="\n  ---\n")


def forward_switch(lab: Lab, work: Path, t: Checks) -> None:
    """端口转发的目标由管理员打开：节点不用声明（旧配置里的 forward = true 照收、不起作用）；关掉开关，转发留着、不生效；再打开就回来。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    # c 的配置文件还是以前的写法，声明了 forward：照样读得进来，什么也不决定。
    a, c = Node(lab.host("a"), work), Node(lab.host("c"), work, declare=("forward",))
    for node in (a, c):
        node.join(controller)
    start_whoami(c.host, 8081, bind="127.0.0.1")
    seen = controller.node(c)
    t.check("新节点的开关关着，声明里没有 forward", seen["forward_target"] is False and "forward" not in seen["declared"], str(seen))
    old_set = c.host.run(binary("i3t"), "--state-dir", str(c.state), "set", "can-forward", "on", check=False)
    t.check("i3t set can-forward 照收，说明由管理员打开，配置文件不变",
            old_set.returncode == 0 and "--forward-target on" in old_set.stdout and "forward = true" in (c.state / "config.toml").read_text(),
            f"{old_set.stdout!r} {old_set.stderr.strip()}")
    refused = controller.ctl("forward", "add", str(a.id), "127.0.0.1:9000", str(c.id), "127.0.0.1:8081", check=False)
    t.check("开关关着：配不了转发，错误码是 forward_target_off", refused.returncode != 0 and "forward_target_off" in refused.stderr,
            refused.stderr.strip())

    controller.forward_target(c)
    created = controller.ctl("forward", "add", str(a.id), "127.0.0.1:9000", str(c.id), "127.0.0.1:8081")
    local = lambda: a.host.run("curl", "-sS", "--max-time", "6", "http://127.0.0.1:9000/", check=False)  # noqa: E731
    status = lambda: next(entry for entry in controller.ctl("forward", "list") if entry["id"] == created["id"])  # noqa: E731
    seen = eventually(local, lambda r: r.returncode == 0)
    t.check("打开开关之后转发通到 c 回环上的服务", seen.stdout == "127.0.0.1", f"{seen.stdout!r} {seen.stderr.strip()}")

    controller.forward_target(c, on=False)
    parked = status()
    t.check("关掉开关：转发还在、还是启用的，状态说明不生效",
            parked["enabled"] is True and parked["status"] == "forward_target_off", str(parked))
    gone = eventually(lambda: a.host.run("ss", "-lnt").stdout, lambda out: ":9000 " not in out)
    t.check("关掉开关：a 不再监听转发的端口", ":9000 " not in gone)
    t.check("关掉开关：连不上了", local().returncode != 0)
    text = controller.host.run(binary("i3tctl"), "--token", controller.token, "forward", "list", check=False).stdout
    t.check("命令行的列表里写成一句话", "目标节点未开启转发" in text, text)

    controller.forward_target(c)
    back = eventually(local, lambda r: r.returncode == 0)
    t.check("再打开：转发回来了", back.stdout == "127.0.0.1" and status()["status"] == "active", f"{back.stdout!r} {back.stderr.strip()}")
    if t.failures:
        print(tail(a.read_log()), tail(c.read_log()), sep="\n  ---\n")


def lan_behind_exit(lab: Lab, work: Path, t: Checks) -> None:
    """经出口访问它所在的局域网：要出口打开"允许访问本机局域网"这个开关。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    home = lab.nat("home", NatKind.CONE)
    printer = home.host("printer")
    start_whoami(printer, 80)
    a, b = Node(lab.host("a"), work), Node(home.host("gw"), work, declare=("exit",))
    for node in (a, b):
        node.join(controller)
    url = f"http://{printer.ip}/"

    controller.ctl("exit", "enable", str(b.id))
    wait_until(lambda: controller.node(b)["exit"] is not None, what="出口启用")
    controller.add_proxy(a, b)
    # 等出口的配置到了两个节点上，否则"到不了"可能只是因为配置还没到。
    wait_until(lambda: "出口" in b.read_log() or controller.node(b)["acked_version"] == controller.node(b)["netmap_version"], what="出口的配置下发")
    t.check("没开局域网开关时到不了出口背后的局域网", socks(a, url, via=b).returncode != 0)
    controller.ctl("exit", "enable", str(b.id), "--lan")
    seen = eventually(lambda: socks(a, url, via=b), lambda r: r.returncode == 0)
    t.check("打开开关之后可以访问，局域网里的机器看到的来源是出口在局域网里的地址", seen.stdout == b.host.ip, f"{seen.stdout!r} {seen.stderr.strip()}")
    t.check("组网入口不经出口，到不了出口背后的局域网", socks(a, url).returncode != 0)
    if t.failures:
        print(tail(a.read_log()), tail(b.read_log()), sep="\n  ---\n")


def public_proxy(lab: Lab, work: Path, t: Checks) -> None:
    """对外开放的代理：认它自己的用户名和密码（没写时 controller 生成一对），一个端口上 SOCKS5 和 HTTP 都说；
    换一对密码之后旧的不能用了；端口被别的程序占着时状态说出来。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    gw, ex = Node(lab.host("gw"), work), Node(lab.host("ex"), work, declare=("exit",))
    for node in (gw, ex):
        node.join(controller)
    controller.ctl("exit", "enable", str(ex.id))
    outsider = lab.host("outsider")
    created = controller.add_proxy(gw, ex, bind="0.0.0.0", port=3128)
    url = f"http://{web.ip}/"
    t.check("不在回环上、没写用户名密码：controller 生成了一对", created["username"].startswith("u-") and len(created["password"]) == 32,
            str(created))

    def through(proxy: Proxy, scheme: str = "http"):
        flags = ("-p",) if scheme == "http" else ()
        return outsider.run("curl", "-sS", "--max-time", "8", *flags, "-x", proxy.url(scheme), "-o", "/dev/null",
                            "-w", "%{http_connect} %{http_code}", url, check=False)

    right = Proxy(gw.host.ip, 3128, created["username"], created["password"])
    t.check("HTTP 不带用户名密码：407", through(Proxy(gw.host.ip, 3128)).stdout.startswith("407"), through(Proxy(gw.host.ip, 3128)).stdout)
    wrong = Proxy(gw.host.ip, 3128, created["username"], "wrong")
    t.check("HTTP 密码不对：407", through(wrong).stdout.startswith("407"), through(wrong).stdout)
    good = eventually(lambda: through(right), lambda r: r.stdout == "200 200")
    t.check("HTTP 用户名密码对：经代理的出口访问成功", good.stdout == "200 200", f"{good.stdout!r} {good.stderr.strip()}")
    socks5 = outsider.run("curl", "-sS", "--max-time", "8", "-x", right.url("socks5h"), url, check=False)
    t.check("同一个端口上的 SOCKS5：目标看到的来源是出口的地址", socks5.stdout == ex.host.ip, f"{socks5.stdout!r} {socks5.stderr.strip()}")
    refused = outsider.run("curl", "-sS", "--max-time", "8", "-x", wrong.url("socks5h"), url, check=False)
    t.check("SOCKS5 密码不对：认证不过", refused.returncode != 0 and refused.stdout == "", f"{refused.stdout!r}")
    anonymous = outsider.run("curl", "-sS", "--max-time", "8", "-x", Proxy(gw.host.ip, 3128).url("socks5h"), url, check=False)
    t.check("SOCKS5 不给用户名密码：没有可用的认证方法", anonymous.returncode != 0 and anonymous.stdout == "", f"{anonymous.stdout!r}")

    # 管理员自己定一对，旧的就不能用了。
    controller.ctl("proxy", "set", str(created["id"]), "--username", "alice", "--password", "s3cret")
    alice = Proxy(gw.host.ip, 3128, "alice", "s3cret")
    switched = eventually(lambda: through(alice), lambda r: r.stdout == "200 200")
    t.check("改成管理员定的用户名密码：新的能用", switched.stdout == "200 200", switched.stdout)
    t.check("旧的不能用了", through(right).stdout.startswith("407"), through(right).stdout)
    shown = controller.proxy(created["id"])
    t.check("管理员再看得到密码", (shown["username"], shown["password"]) == ("alice", "s3cret"), str(shown))

    hold_port(gw.host, 3999)
    busy = controller.add_proxy(gw, ex, port=3999, wait=False, default=False)
    seen = controller.wait_proxy(busy["id"], "port_in_use")
    t.check("端口被别的程序占着：状态是 port_in_use，带着系统的原话", seen["status"]["code"] == "port_in_use" and seen["status"].get("detail"),
            str(seen["status"]))
    if t.failures:
        print(tail(gw.read_log()), tail(ex.read_log()), sep="\n  ---\n")


def groups(lab: Lab, work: Path, t: Checks) -> None:
    """分组决定访问：加入分组就得到规则给它的访问，移出时正在进行的连接断开；删掉分组连同它的规则和访问；
    令牌预设分组；命令行上写了不存在的分组被拒绝，并且说出是哪一个。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    create_groups(controller, "admins", "servers")
    for rule in controller.ctl("rule", "list"):
        controller.ctl("rule", "delete", str(rule["id"]))
    controller.ctl("rule", "add", "admins", "servers", "--one-way", "--name", "admin")
    a, b, c = Node(lab.host("a"), work), Node(lab.host("b"), work), Node(lab.host("c"), work)
    a.join(controller)
    b.join(controller, "servers")
    c.join(controller)
    t.check("令牌预设的分组：b 一加入就在 servers 里", group_names(controller, b) == ["servers"], str(group_names(controller, b)))
    for node in (a, b, c):
        start_whoami(node.host, 8080)
    to_b = f"http://{b.virtual_ip}:8080/"
    t.check("a 不在 admins 里时到不了 b", socks(a, to_b).returncode != 0)

    unknown = controller.ctl("group", "add", "nope", str(a.id), check=False)
    t.check("命令行上写了不存在的分组被拒绝，说出是哪一个", unknown.returncode != 0 and "nope" in unknown.stderr, unknown.stderr.strip())
    unknown = controller.ctl("node", "groups", str(a.id), "admins", "ghosts", check=False)
    t.check("一串分组里有一个不存在也被拒绝，说出是哪一个", unknown.returncode != 0 and "ghosts" in unknown.stderr, unknown.stderr.strip())
    t.check("被拒绝的请求什么也没改", group_names(controller, a) == [], str(group_names(controller, a)))

    controller.ctl("group", "add", "admins", str(a.id))
    seen = eventually(lambda: socks(a, to_b), lambda r: r.returncode == 0)
    t.check("a 加入 admins 之后可以访问 b", seen.stdout == b.host.ip, f"{seen.stdout!r} {seen.stderr.strip()}")
    t.check("规则是单向的：b 还是访问不了 a", socks(b, f"http://{a.virtual_ip}:8080/").returncode != 0)
    t.check("c 不在 admins 里，照旧到不了 b", socks(c, to_b).returncode != 0)
    t.check("a 也没有因此能访问 c", socks(a, f"http://{c.virtual_ip}:8080/").returncode != 0)

    # 一次限速的下载，持续三十秒左右；下载途中把 a 移出 admins。
    size = 30_000_000
    download = subprocess.Popen(
        a.host.cmd("curl", "-sS", "--max-time", "90", "--limit-rate", "1M", "-o", "/dev/null", "-w", "%{size_download}",
                   "-x", "socks5h://127.0.0.1:1080", f"{to_b}bytes/{size}"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(3)
    t.check("下载开始了", download.poll() is None)
    controller.ctl("group", "remove", "admins", str(a.id))
    try:
        out, err = download.communicate(timeout=20)
        ended = out != str(size)
        detail = f"下载了 {out!r}；{err.strip()}"
    except subprocess.TimeoutExpired:
        download.kill()
        ended, detail = False, "移出之后 20 秒连接还在"
    t.check("a 移出 admins 之后，正在进行的连接断开", ended, detail)
    gone = eventually(lambda: socks(a, to_b), lambda r: r.returncode != 0)
    t.check("之后也连不上了", gone.returncode != 0)

    controller.ctl("group", "add", "admins", str(a.id))
    back = eventually(lambda: socks(a, to_b), lambda r: r.returncode == 0)
    t.check("重新加入之后又能访问", back.returncode == 0, back.stderr.strip())
    deleted = controller.ctl("group", "delete", "admins")
    t.check("删掉分组的应答说出删掉了哪条规则和哪些成员",
            [rule["name"] for rule in deleted["rules"]] == ["admin"] and [node["id"] for node in deleted["nodes"]] == [a.id], str(deleted))
    t.check("用到它的规则没了", controller.ctl("rule", "list") == [])
    t.check("a 不再在任何分组里", group_names(controller, a) == [], str(group_names(controller, a)))
    after = eventually(lambda: socks(a, to_b), lambda r: r.returncode != 0)
    t.check("删掉分组之后 a 到不了 b", after.returncode != 0)
    if t.failures:
        print(tail(a.read_log()), tail(b.read_log()), tail(controller.log.read_text(errors="replace")), sep="\n  ---\n")


def plain_http_proxy(lab: Lab, work: Path, t: Checks) -> None:
    """代理转发明文 HTTP（不用 CONNECT）：经代理的出口出去，代理自己的头不到目标，请求体完整，
    大的下载完整，出口的端口白名单按 URL 里的端口查，出口停用了的代理被拒绝。"""
    web, echo = lab.host("web"), lab.host("echo")
    start_blob_server(web, work)
    start_whoami(web, 8080)
    start_header_echo(echo)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a, ex, b = Node(lab.host("a"), work), Node(lab.host("ex"), work, declare=("exit",)), Node(lab.host("b"), work, declare=("exit",))
    for node in (a, ex, b):
        node.join(controller)
    # 出口默认不限端口；这里写明只放行 80 和 443，测端口白名单按 URL 里的端口查。
    controller.ctl("exit", "enable", str(ex.id), "--ports", "80,443")
    controller.add_proxy(a, ex)
    controller.ctl("exit", "enable", str(b.id))
    via_b = controller.add_proxy(a, b)

    small = eventually(lambda: plain_http(a, f"http://{web.ip}/blob/1000", via=ex), lambda r: r[0] == "200")
    t.check("curl -x http://代理 http://… 经代理的出口取回", small[0] == "200", f"{small}")
    headers = plain_http(a, f"http://{echo.ip}/path?q=1", via=ex, extra=("-H", "X-Test: kept"))
    seen = headers[1].lower()
    t.check("目标收到的请求行只有路径", headers[1].startswith("GET /path?q=1 HTTP/1.1"), headers[1][:200])
    t.check("Proxy-Authorization 和逐跳的头没有到目标，别的头都在，Host 是 URL 里的",
            "proxy-" not in seen and "keep-alive" not in seen and "x-test: kept" in seen and f"host: {echo.ip}" in seen
            and "connection: close" in seen, headers[1])

    big = 30_000_000
    code, digest, error = plain_http(a, f"http://{web.ip}/blob/{big}", via=ex, timeout=120)
    t.check("30 MB 的下载完整", code == "200" and digest == blob_digest(big), f"{code} {error}")
    upload = blob_file(a, 3_000_000)
    code, body, error = plain_http(a, f"http://{web.ip}/digest", via=ex, extra=("--data-binary", f"@{upload}"))
    t.check("3 MB 的 POST（curl 先发 Expect: 100-continue）完整到达", code == "200" and body == blob_digest(3_000_000), f"{code} {body!r} {error}")
    code, body, error = plain_http(a, f"http://{web.ip}/digest", via=ex,
                                   extra=("--data-binary", "hello", "-H", "Transfer-Encoding: chunked", "-H", "Expect:"))
    t.check("chunked 的请求体原样转给目标（这个服务只认 Content-Length，所以读到的是空的）", code == "200", f"{code} {body!r} {error}")

    whoami = plain_http(a, f"http://{web.ip}:8080/", via=ex)
    t.check("出口只放行 80 和 443，URL 里写 8080 被拒绝：403", whoami[0] == "403", f"{whoami}")
    first = eventually(lambda: plain_http(a, f"http://{web.ip}/blob/10", via=b), lambda r: r[0] == "200")
    t.check("经 b 出去的代理先是好的", first[0] == "200", f"{first}")
    controller.ctl("exit", "disable", str(b.id))
    refused = eventually(lambda: plain_http(a, f"http://{web.ip}/blob/10", via=b), lambda r: r[0] == "403")
    t.check("b 停用了出口：代理还在监听，请求得到 403", refused[0] == "403", f"{refused}")
    status = controller.wait_proxy(via_b["id"], "exit_disabled")["status"]
    t.check("代理的状态说出口没有启用", status["code"] == "exit_disabled", str(status))
    proxy_env = a.host.run("env", f"http_proxy={a.entry(ex).url('http')}", "curl", "-sS", "--max-time", "20", "-o", "/dev/null",
                           "-w", "%{http_code}", f"http://{web.ip}/blob/10", check=False)
    t.check("http_proxy 环境变量指向代理就能用", proxy_env.stdout == "200", f"{proxy_env.stdout!r} {proxy_env.stderr.strip()}")
    if t.failures:
        print(tail(a.read_log()), tail(ex.read_log()), sep="\n  ---\n")


def forward_target(lab: Lab, work: Path, t: Checks) -> None:
    """端口转发说出目标连不上：原因和时间，直到有一条连接成功；命令行的列表里写成一句话。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a, c = Node(lab.host("a"), work), Node(lab.host("c"), work)
    for node in (a, c):
        node.join(controller)
    controller.forward_target(c)
    controller.ctl("forward", "add", str(a.id), "127.0.0.1:9000", str(c.id), "127.0.0.1:8090")
    local = lambda: a.host.run("curl", "-sS", "--max-time", "6", "http://127.0.0.1:9000/", check=False)  # noqa: E731
    failure = lambda: controller.ctl("forward", "list")[0]["target_failure"]  # noqa: E731

    wait_until(lambda: ":9000 " in a.host.run("ss", "-lnt").stdout, timeout=20, what="a 开始监听转发的端口")
    t.check("c 的 8090 上没有服务：a 上的连接被重置", local().returncode != 0)
    seen = eventually(lambda: (local(), failure())[1], lambda found: found is not None, timeout=30)
    t.check("转发报出目标拒绝连接，带着时间", seen is not None and seen["cause"] == {"code": "refused"} and seen["at"] > 1_700_000_000, str(seen))
    text = controller.host.run(binary("i3tctl"), "--token", controller.token, "forward", "list", check=False).stdout
    t.check("命令行的列表里写成一句话", "目标拒绝连接" in text, text)

    start_whoami(c.host, 8090, bind="127.0.0.1")
    through = eventually(local, lambda r: r.returncode == 0)
    t.check("服务起来之后连接成功", through.stdout == "127.0.0.1", f"{through.stdout!r} {through.stderr.strip()}")
    cleared = eventually(failure, lambda found: found is None, timeout=30)
    t.check("有一条连接成功之后记录清掉", cleared is None, str(cleared))
    if t.failures:
        print(tail(a.read_log()), tail(c.read_log()), sep="\n  ---\n")


def proxy_protocol(lab: Lab, work: Path, t: Checks) -> None:
    """端口转发可以给目标发 PROXY protocol 的头（v1、v2）：认它的服务看到的是发起节点的虚拟 IP，而不是 127.0.0.1；
    UDP 的转发不能设。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a, c = Node(lab.host("a"), work), Node(lab.host("c"), work)
    for node in (a, c):
        node.join(controller)
    controller.forward_target(c)
    start_proxy_protocol_echo(c.host, 8095)
    controller.ctl("forward", "add", str(a.id), "127.0.0.1:9001", str(c.id), "127.0.0.1:8095", "--proxy-protocol", "v1")
    controller.ctl("forward", "add", str(a.id), "127.0.0.1:9002", str(c.id), "127.0.0.1:8095", "--proxy-protocol", "v2")
    controller.ctl("forward", "add", str(a.id), "127.0.0.1:9003", str(c.id), "127.0.0.1:8095")
    get = lambda port: a.host.run("curl", "-sS", "--max-time", "6", f"http://127.0.0.1:{port}/", check=False)  # noqa: E731

    for port, version in [(9001, "v1"), (9002, "v2")]:
        seen = eventually(lambda: get(port), lambda r: r.returncode == 0)
        t.check(f"PROXY protocol {version}：服务看到 a 的虚拟 IP", seen.stdout == a.virtual_ip, f"{seen.stdout!r} {seen.stderr.strip()}")
    plain = eventually(lambda: get(9003), lambda r: r.returncode == 0)
    t.check("没有设的转发不发头", plain.stdout == "no proxy header", f"{plain.stdout!r} {plain.stderr.strip()}")
    t.check("转发的设置里有这一项", [f["proxy_protocol"] for f in controller.ctl("forward", "list")] == ["v1", "v2", None])
    udp = controller.ctl("forward", "add", str(a.id), "127.0.0.1:9004", str(c.id), "127.0.0.1:8095", "--udp", "--proxy-protocol", "v1",
                         check=False)
    t.check("UDP 的转发不能设", udp.returncode != 0 and "PROXY protocol" in udp.stderr, udp.stderr.strip())
    if t.failures:
        print(tail(a.read_log()), tail(c.read_log()), sep="\n  ---\n")


def exit_optimistic(lab: Lab, work: Path, t: Checks) -> None:
    """出口可以关掉乐观回复：经它的连接等它的应答，客户端拿到"连接被拒绝"而不是连上之后被重置；代理自己的设置排在前面。"""
    web = lab.host("web")
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a, ex = Node(lab.host("a"), work), Node(lab.host("ex"), work, declare=("exit",))
    for node in (a, ex):
        node.join(controller)
    controller.ctl("exit", "enable", str(ex.id))
    controller.add_proxy(a, ex)
    # web 的 443 上没有服务：出口连过去被拒绝。
    closed = f"http://{web.ip}:443/"
    default = eventually(lambda: socks(a, closed, via=ex), lambda r: "reset" in r.stderr.lower())
    t.check("默认：先说连上了，之后被重置", default.returncode == 56 and "reset" in default.stderr.lower(), f"{default.returncode} {default.stderr.strip()}")
    controller.ctl("exit", "enable", str(ex.id), "--optimistic", "off")
    careful = eventually(lambda: socks(a, closed, via=ex), lambda r: r.returncode == 97)
    t.check("出口关掉乐观回复：客户端拿到 SOCKS5 的连接被拒绝", careful.returncode == 97, f"{careful.returncode} {careful.stderr.strip()}")
    t.check("出口的设置里有这一项", controller.node(ex)["exit"]["optimistic"] is False, str(controller.node(ex)["exit"]))
    controller.add_proxy(a, ex, "--optimistic", "on", port=1090, default=False)
    seen = eventually(lambda: a.curl(closed, through=Proxy("127.0.0.1", 1090), timeout=8), lambda r: r.returncode == 56)
    t.check("代理打开了乐观回复，以代理为准", seen.returncode == 56, f"{seen.returncode} {seen.stderr.strip()}")
    if t.failures:
        print(tail(a.read_log()), tail(ex.read_log()), sep="\n  ---\n")


def exit_test(lab: Lab, work: Path, t: Checks) -> None:
    """i3tctl exit test：出口按它自己的策略试着连一个目标，说出解析、连接、TLS 握手各花多久、经什么出去；
    它不替别人连的目标被拒绝，原因和别人经它访问时一样；出口节点一次只做一个。"""
    web = lab.host("web")
    start_blob_server(web, work)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    a, ex = Node(lab.host("a"), work), Node(lab.host("ex"), work, declare=("exit",))
    for node in (a, ex):
        node.join(controller)
    controller.ctl("exit", "enable", str(ex.id))
    test = lambda target: controller.ctl("exit", "test", ex.name, target)  # noqa: E731

    seen = eventually_value(lambda: test(f"{web.ip}:443"), lambda view: (view["result"] or {}).get("tls") is not None, timeout=30)
    result = seen["result"] or {}
    t.check("回答了：经直接连，连上了，TLS 握手完成", seen["answered"] and result["via"] == "direct" and result["refused"] is None
            and result["connect"]["address"] == f"{web.ip}:443" and result["connect"]["cause"] is None and result["tls"]["cause"] is None,
            str(seen))
    t.check("写成地址的目标不用解析", result.get("resolve") is None, str(result))
    time.sleep(2.1)
    seen = test("localhost:443")["result"]
    t.check("域名解析出来是回环地址：解析这一步有地址，出口不连，原因是地址不允许",
            seen["resolve"] is not None and "127.0.0.1" in seen["resolve"]["addresses"] and seen["refused"]["code"] == "address_not_allowed"
            and seen["connect"] is None, str(seen))
    busy = test(f"{web.ip}:80")["result"]
    t.check("两秒之内再测：出口节点说忙", busy["refused"] == {"code": "busy"}, str(busy))
    time.sleep(2.1)
    closed = test(f"{web.ip}:9")["result"]
    t.check("目标端口没有服务：连接被拒绝；不是 443 不做握手", closed["connect"]["cause"] == {"code": "refused"} and closed["tls"] is None,
            str(closed))
    time.sleep(2.1)
    lan = test("192.168.1.10:80")["result"]
    t.check("局域网的地址：出口没有打开局域网访问", lan["refused"] == {"code": "lan_not_enabled"}, str(lan))

    controller.ctl("exit", "enable", str(ex.id), "--ports", "443")
    time.sleep(2.1)
    port = eventually_value(lambda: test(f"{web.ip}:80")["result"], lambda result: result["refused"] is not None, timeout=20)
    t.check("出口只放行 443：测 80 被拒绝，说出端口", port["refused"] == {"code": "port_not_allowed", "port": 80}, str(port))
    time.sleep(2.1)
    said = lambda target: controller.host.run(binary("i3tctl"), "--token", controller.token, "exit", "test", ex.name, target,  # noqa: E731
                                              check=False).stdout
    text = said(f"{web.ip}:80")
    t.check("命令行写成一句话", "端口 80 不在出口允许的范围里" in text, text)
    text = said(f"{web.ip}:443")
    t.check("命令行：出口忙时单独一句，不放在“出口不连”下面", "ex 正忙" in text and "出口不连" not in text, text)
    time.sleep(2.1)
    text = said(f"{web.ip}:443")
    t.check("命令行：不到 1 毫秒的写成 <1 ms，不写 0 ms", "连接" in text and " 0 ms" not in text, text)
    not_exit = controller.ctl("exit", "test", a.name, f"{web.ip}:443", check=False)
    t.check("不是出口的节点不能测", not_exit.returncode != 0, not_exit.stderr.strip())
    if t.failures:
        print(tail(ex.read_log()), tail(controller.log.read_text(errors="replace")), sep="\n  ---\n")


def ping(lab: Lab, work: Path, t: Checks) -> None:
    """i3t ping：在到另一个节点的连接上量往返，说出走的路；不认识的节点、访问规则不允许、对端离线各有一句明白话。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab")
    create_groups(controller, "ops", "boxes")
    a, b, c = Node(lab.host("a"), work), Node(lab.host("b"), work), Node(lab.host("c"), work)
    a.join(controller, "ops")
    b.join(controller, "ops")
    c.join(controller, "boxes")
    for rule in controller.ctl("rule", "list"):
        controller.ctl("rule", "delete", str(rule["id"]))
    controller.ctl("rule", "add", "ops", "ops")
    controller.ctl("rule", "add", "boxes", "ops", "--one-way")
    run = lambda *args: a.host.run(binary("i3t"), "--state-dir", str(a.state), "ping", *args, check=False, timeout=20)  # noqa: E731

    seen = eventually(lambda: run(b.name), lambda r: r.returncode == 0 and "直连" in r.stdout)
    t.check("ping b：5 个往返都回来了，走的是直连", seen.returncode == 0 and "5 个往返，回来 5 个" in seen.stdout and "直连" in seen.stdout,
            f"{seen.stdout!r} {seen.stderr.strip()}")
    print(seen.stdout.rstrip(), flush=True)
    route = seen.stdout.splitlines()[0].partition("  ")[2] if seen.stdout else ""
    start, arrow, end = route.partition(" → ")
    t.check("路没变就不写成 开始 → 结束", not arrow or start != end, route)
    by_ip = run(b.virtual_ip, "--count", "2")
    t.check("用虚拟 IP、只量 2 个", by_ip.returncode == 0 and "2 个往返" in by_ip.stdout, f"{by_ip.stdout!r} {by_ip.stderr.strip()}")
    unknown = run("nobody")
    t.check("不认识的节点：说出来，失败退出", unknown.returncode != 0 and "没有 nobody" in unknown.stderr, unknown.stderr.strip())
    one_way = eventually(lambda: run(c.name), lambda r: "不允许" in r.stderr)
    t.check("只有 c 能访问 a：a ping c 说访问规则不允许", one_way.returncode != 0 and "访问规则不允许本节点访问 c" in one_way.stderr,
            one_way.stderr.strip())
    t.check("ping 自己说是自己", "本节点自己" in run(a.name).stderr)
    b.stop()
    gone = run(b.name)
    t.check("b 停了：说连不上，或者连接没有及时建起来", gone.returncode != 0
            and ("无法连接节点 b" in gone.stderr or "建立连接超时" in gone.stderr or "都没有回来" in gone.stdout),
            f"{gone.stdout!r} {gone.stderr.strip()}")
    if t.failures:
        print(tail(a.read_log()), tail(b.read_log()), sep="\n  ---\n")


SCENARIOS = {
    "node_service": node_service,
    "port_forward": port_forward,
    "forward_switch": forward_switch,
    "lan_behind_exit": lan_behind_exit,
    "public_proxy": public_proxy,
    "groups": groups,
    "plain_http_proxy": plain_http_proxy,
    "forward_target": forward_target,
    "proxy_protocol": proxy_protocol,
    "exit_optimistic": exit_optimistic,
    "exit_test": exit_test,
    "ping": ping,
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
