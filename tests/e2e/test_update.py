#!/usr/bin/env python3
"""节点自己更新的端到端测试：真的进程，真的替换程序文件，真的重启。

    python3 tests/e2e/test_update.py [场景名...]

这个脚本自己编译它要用的程序，不用 `target/release` 里现成的，因为更新要有三样平时没有的东西：

- 一把测试用的发布签名钥匙。节点和 controller 只认编译在程序里的发布公钥，所以用
  `I3T_RELEASE_EXTRA_KEY=<公钥>` 编译，让它们多认这一把。
- "同一份代码、版本号更高"的第二个节点程序。版本号来自 `bins/i3t/Cargo.toml`，测试不去改它，
  而是用 `I3T_TEST_VERSION=<版本号>` 再编一次 `i3t`（见 `bins/i3t/src/main.rs` 里的说明）。
- 一个发布源。这里是一个本机目录，布局照 `i3t_controller::release`，清单用 `i3t-release` 签。

编译放在自己的 target 目录里（默认 `target/e2e-update`，环境变量 `I3T_E2E_TARGET` 可以改），
免得不同的编译时环境变量把别处的缓存来回冲掉。已经编好的不会重编。

节点由一个小的看护脚本拉起来，代替 systemd：进程以 75（"请重启我"）退出就马上重新启动；
别的退出码也重启（相当于单元文件里的 `Restart=always`），这样才测得出"新程序连着崩了几次之后换回旧的"。
"""

from __future__ import annotations

import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BUILD = Path(os.environ.get("I3T_E2E_TARGET", REPO / "target" / "e2e-update")).resolve()
# 编好的程序放在这里：old/ 是现在的版本（三个程序），new/ 是版本号更高的那个节点程序。
STAGE = BUILD / "stage"
os.environ["I3T_BIN_DIR"] = str(STAGE / "old")

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab as lablib  # noqa: E402
from harness import Checks, Controller, Node, binary, start_whoami, tail  # noqa: E402
from lab import Host, Lab, Shape, wait_until  # noqa: E402

RESTART_EXIT_CODE = 75
PLATFORM = f"{sys.platform}-{platform.machine()}"
ARTIFACT = f"i3t-{PLATFORM}"

# 看护脚本：把节点拉起来，记下它的进程号，退出之后按退出码决定要不要再拉。
SUPERVISOR = r"""
while :; do
    "$PROGRAM" --state-dir "$STATE" run >>"$LOG" 2>&1 &
    echo $! >"$PIDFILE"
    wait $!
    code=$?
    echo "看护：节点进程退出，退出码 $code" >>"$LOG"
    if [ "$code" -ne 75 ]; then sleep 0.3; fi
done
"""


def cargo(*args: str, env: dict[str, str] | None = None) -> None:
    command = ["cargo", "build", "--release", *args]
    print("编译：" + " ".join(f"{name}={value}" for name, value in (env or {}).items()) + " " + " ".join(command), flush=True)
    subprocess.run(command, cwd=REPO, check=True, env={**os.environ, "CARGO_TARGET_DIR": str(BUILD), **(env or {})})


def next_version(version: str, bump: int = 1) -> str:
    major, minor, patch = version.split(".")
    return f"{major}.{minor}.{int(patch) + bump}"


def version_of(program: Path) -> str:
    return subprocess.run([str(program), "--version"], check=True, capture_output=True, text=True).stdout.split()[-1]


def build() -> None:
    """编出测试要用的全部程序。要在进入实验环境之前做：那里面的"root"不该去动 target 目录。"""
    done = STAGE / "done"
    sources = [path for top in ("crates", "bins") for path in (REPO / top).rglob("*") if path.suffix in (".rs", ".toml")]
    newest = max(path.stat().st_mtime for path in [*sources, REPO / "Cargo.lock"])
    if done.exists() and done.stat().st_mtime >= newest:
        return
    STAGE.mkdir(parents=True, exist_ok=True)
    release = BUILD / "release"

    # 签名钥匙只生成一次：公钥是编译时的输入，换了钥匙就要把依赖它的东西全部重编。
    cargo("-p", "i3t-release")
    shutil.copy2(release / "i3t-release", STAGE / "i3t-release")
    key, public = STAGE / "release.key", STAGE / "release.pub"
    if not (key.exists() and public.exists()):
        key.unlink(missing_ok=True)
        generated = subprocess.run([str(STAGE / "i3t-release"), "keygen", "--out", str(key)], check=True, capture_output=True, text=True)
        public.write_text(generated.stdout.strip())
    trust = {"I3T_RELEASE_EXTRA_KEY": public.read_text().strip()}

    cargo("-p", "i3t", "-p", "i3t-controller-bin", "-p", "i3tctl", env=trust)
    (STAGE / "old").mkdir(exist_ok=True)
    for name in ("i3t", "i3t-controller", "i3tctl"):
        shutil.copy2(release / name, STAGE / "old" / name)
    old = version_of(STAGE / "old" / "i3t")

    cargo("-p", "i3t", env={**trust, "I3T_TEST_VERSION": next_version(old)})
    (STAGE / "new").mkdir(exist_ok=True)
    shutil.copy2(release / "i3t", STAGE / "new" / "i3t")
    if version_of(STAGE / "new" / "i3t") != next_version(old):
        raise RuntimeError("第二个节点程序的版本号没有变，I3T_TEST_VERSION 没有生效")
    done.write_text(f"{old} {next_version(old)}\n")


class Release:
    """一个本机目录里的发布源，布局见 `i3t_controller::release`。"""

    def __init__(self, work: Path) -> None:
        self.root = work / "releases"
        (self.root / "latest" / "download").mkdir(parents=True)

    def publish(self, version: str, program: Path, *, security_floor: str | None = None) -> None:
        """发布 `version`：节点程序是 `program`，清单写上安全下限 `security_floor`（有的话）。
        先放好这个版本的文件，再把清单放到"最新"的位置上。"""
        directory = self.root / "download" / f"v{version}"
        directory.mkdir(parents=True)
        shutil.copy2(program, directory / ARTIFACT)
        floor = ["--security-floor", security_floor] if security_floor else []
        signed = subprocess.run(
            [str(STAGE / "i3t-release"), "manifest", "--version", version, "--dir", str(directory), "--key", str(STAGE / "release.key"),
             *floor],
            capture_output=True, text=True)
        if signed.returncode != 0:
            raise RuntimeError(f"签发布清单失败：{signed.stderr.strip()}")
        for name in ("manifest.json", "manifest.json.sig"):
            shutil.copy2(directory / name, self.root / "latest" / "download" / name)


# 正在运行的节点。一个场景不管怎么结束，都要把它们连同看护脚本一起停掉。
RUNNING: list["SupervisedNode"] = []


class SupervisedNode(Node):
    """一个由看护脚本拉起来的节点。它有自己的一份程序文件：更新换的就是这一份。"""

    def __init__(self, host: Host, work: Path, *, declare: tuple[str, ...] = ()) -> None:
        super().__init__(host, work, declare=declare)
        self.program = work / f"{host.name}-bin" / "i3t"
        self.program.parent.mkdir()
        shutil.copy2(STAGE / "old" / "i3t", self.program)
        self.pidfile = work / f"{host.name}.pid"

    def start(self) -> None:
        env = {**os.environ, "PROGRAM": str(self.program), "STATE": str(self.state), "LOG": str(self.log), "PIDFILE": str(self.pidfile)}
        # 自己一个进程组：停的时候把看护脚本和节点一起停掉。
        self.proc = subprocess.Popen(self.host.cmd("sh", "-c", SUPERVISOR), env=env, start_new_session=True)
        RUNNING.append(self)
        wait_until(lambda: "节点启动" in self.read_log(), what=f"{self.name} 启动")

    def stop(self) -> None:
        if self.proc is None:
            return
        # 看护脚本收到 SIGTERM 会立刻退出，但它的子进程 i3t 还在做优雅停机、可能继续往工作目录写状态文件；
        # 必须等到整个进程组清空，否则外层 TemporaryDirectory 删目录时会撞出 ENOTEMPTY。
        pgid = self.proc.pid
        for sig, timeout in ((signal.SIGTERM, 5.0), (signal.SIGKILL, 2.0)):
            try:
                os.killpg(pgid, sig)
            except ProcessLookupError:
                break
            if self.proc.poll() is None:
                try:
                    self.proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    continue
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    os.killpg(pgid, 0)
                except ProcessLookupError:
                    self.proc = None
                    return
                time.sleep(0.05)
        self.proc = None

    def pid(self) -> int:
        return int(self.pidfile.read_text())

    def kill(self) -> None:
        """杀掉节点进程，像它自己崩了一样。看护脚本会把它重新拉起来。"""
        os.kill(self.pid(), signal.SIGKILL)

    def installed_version(self) -> str:
        """磁盘上这个节点的程序文件现在是哪个版本。"""
        return version_of(self.program)

    def count(self, text: str) -> int:
        return self.read_log().count(text)

    def i3t(self, *args: str) -> subprocess.CompletedProcess:
        return self.host.run(str(self.program), "--state-dir", str(self.state), *args, check=False)

    def block_controller(self, controller: Controller, blocked: bool = True) -> None:
        """这台机器连不上 controller（别的流量不受影响）：连接被直接拒绝。"""
        self.host.run("nft", "delete", "table", "inet", "noctl", check=False)
        if blocked:
            rules = f"""
table inet noctl {{
    chain out {{
        type filter hook output priority filter;
        ip daddr {controller.host.ip} tcp dport 20331 reject with tcp reset
    }}
}}
"""
            self.host.run("nft", "-f", "-", input=rules)


def setup(lab: Lab, work: Path, *, auto: bool) -> tuple[Controller, Release, Host]:
    """一个 controller，发布源指向一个本机目录，再加一台普通的网站。"""
    web = lab.host("web")
    start_whoami(web)
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab", "--cidr", "10.66.0.0/16")
    release = Release(work)
    controller.ctl("update", "set", "--auto", "on" if auto else "off", "--source", str(release.root))
    return controller, release, web


def update_of(controller: Controller, node: Node) -> dict:
    return controller.node(node)["update"]


def state_of(controller: Controller, node: Node) -> str:
    return update_of(controller, node)["status"]["state"]


def wait_version(controller: Controller, node: Node, version: str, timeout: float = 90) -> bool:
    """等到 controller 看到这个节点在线，并且正在运行 `version`。"""
    def arrived() -> bool:
        seen = controller.node(node)
        return seen["online"] and seen["version"] == version
    try:
        wait_until(arrived, timeout=timeout, interval=0.5, what=f"{node.name} 以 {version} 上线")
    except TimeoutError:
        return False
    return True


def waited(condition, timeout: float, what: str) -> bool:
    try:
        wait_until(condition, timeout=timeout, interval=0.5, what=what)
    except TimeoutError:
        return False
    return True


def slow_download(node: Node, url: str, via: Node, megabytes: int, rate: str = "1M"):
    """在后台开始一次限速下载，返回进程和应该下到的字节数。限速是为了让它持续几十秒。"""
    size = megabytes * 1_000_000
    cmd = node.host.cmd("curl", "-sS", "--max-time", "180", "--limit-rate", rate, "-o", "/dev/null", "-w", "%{size_download}",
                        "-x", node.entry(via).url("socks5h"), f"{url}bytes/{size}")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True), size


def finished_intact(download, size: int, timeout: float = 180) -> tuple[bool, str]:
    out, err = download.communicate(timeout=timeout)
    return out == str(size), f"下载了 {out!r}，应该是 {size}；{err.strip()}"


def reaches(node: Node, url: str, via: Node, expect: str, timeout: float = 30) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if node.curl(url, via=via, timeout=6).stdout == expect:
            return True
        time.sleep(0.5)
    return False


def versions() -> tuple[str, str]:
    old = version_of(STAGE / "old" / "i3t")
    return old, next_version(old)


def forced_update(lab: Lab, work: Path, t: Checks) -> None:
    """自动更新关着：管理员让一个节点立即更新，它自己换程序、重启、以新版本上线；别的节点照常工作，不受影响。"""
    old, new = versions()
    controller, release, web = setup(lab, work, auto=False)
    a, b, c = (SupervisedNode(lab.host(name), work, declare=("exit",) if name == "b" else ()) for name in "abc")
    for node in (a, b, c):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    for node in (a, c):
        controller.add_proxy(node, b)
    url = f"http://{web.ip}/"
    t.check("更新之前 a 经 b 出得去", reaches(a, url, b, b.host.ip))
    seen = controller.node(a)["update"]
    t.check("节点报了自己能自己更新", seen["self_update"] == {"able": True, "blocker": None}, str(seen))
    t.check("没有发布时不提示有新版本", seen["available"] is None, str(seen))

    release.publish(new, STAGE / "new" / "i3t")
    checked = controller.ctl("update", "check")
    t.check("controller 查到了新版本", (checked["release"] or {}).get("version") == new and checked["check_error"] is None, str(checked))
    time.sleep(3)
    t.check("自动更新关着：只提示有新版本，谁也不动",
            all(update_of(controller, node)["available"] == new and update_of(controller, node)["ordered"] is None for node in (a, b, c))
            and a.count("controller 要求更新") == 0)

    # c 经 b 的下载贯穿 a 的整个更新过程。
    download, size = slow_download(c, url, b, 25)
    time.sleep(2)
    controller.ctl("update", "node", str(a.id))
    t.check("a 以新版本重新上线", wait_version(controller, a, new), f"controller 看到的是 {controller.node(a)['version']}")
    t.check("a 的程序文件换成了新版本", a.installed_version() == new, a.installed_version())
    t.check("a 是自己以“请重启我”的退出码退出、被看护脚本拉起来的", f"退出码 {RESTART_EXIT_CODE}" in a.read_log(), tail(a.read_log(), 6))
    t.check("新程序连上 controller 之后更新被确认", waited(lambda: "更新成功：新版本连上了 controller" in a.read_log(), 15, "确认"),
            tail(a.read_log(), 8))
    t.check("确认之后备份的旧程序被删掉", waited(lambda: sorted(p.name for p in a.program.parent.iterdir()) == ["i3t"], 10, "清理"),
            str(sorted(p.name for p in a.program.parent.iterdir())))
    t.check("controller 看到 a 没有新版本可更了", update_of(controller, a)["available"] is None, str(update_of(controller, a)))
    t.check("b 和 c 没有被动过：还是旧版本，进程也没有重启",
            all(controller.node(node)["version"] == old and node.count("节点启动") == 1 for node in (b, c)))
    ok, detail = finished_intact(download, size)
    t.check("a 更新期间，c 经 b 的下载没有受影响", ok, detail)
    t.check("新版本的 a 和旧版本的 b 照样互通", reaches(a, url, b, b.host.ip))

    live = a.i3t("status").stdout
    t.check("i3t status 显示运行中的状态", f"正在运行 i3t {new}" in live and "已连接" in live and "local-socks5" in live, live[-600:])
    routes = a.i3t("routes")
    t.check("i3t routes 列出到对端的路", routes.returncode == 0 and "对端" in routes.stdout and " b " in routes.stdout, routes.stdout + routes.stderr)
    metrics = a.host.run("curl", "-sS", "--max-time", "5", "http://127.0.0.1:20333/metrics", check=False).stdout
    t.check("节点的 /metrics 有版本、连接状态和路由",
            f'i3t_info{{version="{new}"}} 1' in metrics and "i3t_controller_link_up 1" in metrics and 'i3t_peer_route{peer="b"' in metrics,
            metrics[:400])
    check = a.i3t("self-check")
    t.check("手动运行自检通过，而且不打扰正在运行的节点",
            check.returncode == 0 and controller.node(a)["online"] and a.count("节点启动") == 2, check.stdout + check.stderr)
    path = controller.ctl("path", str(a.id), str(b.id))
    t.check("i3tctl path 问到了两个方向的路（新版本的节点现答，旧程序一样会答）",
            path["forward"]["source"] == "query" and path["reverse"]["source"] == "query" and path["forward"]["route"]["via"] != "none",
            str(path))
    if t.failures:
        print(tail(a.read_log(), 40), tail(controller.log.read_text(errors="replace"), 30), sep="\n  ---\n")


def idle_waits_for_flows(lab: Lab, work: Path, t: Checks) -> None:
    """自动更新：新程序准备好之后等节点上没有活跃的流才换。下载进行期间不动，下载结束之后才更新。"""
    old, new = versions()
    controller, release, web = setup(lab, work, auto=True)
    a, b = SupervisedNode(lab.host("a"), work), SupervisedNode(lab.host("b"), work, declare=("exit",))
    for node in (a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    url = f"http://{web.ip}/"
    t.check("a 经 b 出得去", reaches(a, url, b, b.host.ip))

    # 这次下载的起点在 a、终点在 b：两个节点上都有活跃的流。
    download, size = slow_download(a, url, b, 40)
    time.sleep(2)
    release.publish(new, STAGE / "new" / "i3t")
    controller.ctl("update", "check")
    both_waiting = waited(lambda: all(state_of(controller, node) == "waiting_for_idle" for node in (a, b)), 30, "两个节点等待空闲")
    t.check("两个节点都取了包、过了自检，然后停在“等待空闲”", both_waiting,
            f"a: {update_of(controller, a)['status']}，b: {update_of(controller, b)['status']}")
    t.check("下发的时机是“空闲时”", update_of(controller, a)["ordered"] == {"version": new, "timing": "idle"}, str(update_of(controller, a)))
    time.sleep(5)
    still_running = download.poll() is None
    t.check("下载还在进行的时候，两个节点都没有换程序、没有重启",
            still_running and all(node.installed_version() == old and node.count("节点启动") == 1 for node in (a, b)),
            f"下载还在进行：{still_running}")
    ok, detail = finished_intact(download, size)
    t.check("下载完整地结束了，没有被更新打断", ok, detail)
    t.check("流结束之后 a 更新到新版本", wait_version(controller, a, new), controller.node(a)["version"])
    t.check("流结束之后 b 也更新到新版本", wait_version(controller, b, new), controller.node(b)["version"])
    t.check("更新之后照样互通", reaches(a, url, b, b.host.ip))
    if t.failures:
        print(tail(a.read_log(), 40), tail(b.read_log(), 30), sep="\n  ---\n")


def rollback_pauses_rollout(lab: Lab, work: Path, t: Checks) -> None:
    """新版本换上去之后连不上 controller：节点启动几次都没被确认，自己换回旧程序；回来报告之后，这个版本的自动更新被暂停。"""
    old, new = versions()
    controller, release, web = setup(lab, work, auto=True)
    a, b = SupervisedNode(lab.host("a"), work), SupervisedNode(lab.host("b"), work, declare=("exit",))
    for node in (a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    url = f"http://{web.ip}/"
    t.check("a 经 b 出得去", reaches(a, url, b, b.host.ip))

    # 用一次下载把 a 按在“等待空闲”上：这时新程序已经过了自检，只差换上去。
    download, _size = slow_download(a, url, b, 100)
    time.sleep(2)
    release.publish(new, STAGE / "new" / "i3t")
    controller.ctl("update", "check")
    t.check("a 的新程序过了自检，在等空闲", waited(lambda: state_of(controller, a) == "waiting_for_idle", 30, "a 等待空闲"),
            str(update_of(controller, a)["status"]))
    # 从这时起 a 连不上 controller：对新程序来说，就是"这个版本在这台机器上连不上 controller"。
    a.block_controller(controller)
    download.kill()
    download.wait()

    started = waited(lambda: a.count("这是刚换上来的新版本") >= 1, 40, "a 的新程序启动")
    t.check("流没了之后 a 换上新程序并重启", started and a.installed_version() == new, tail(a.read_log(), 8))
    t.check("旧程序留作备份", (a.program.parent / "i3t.old").exists() or len(list(a.program.parent.iterdir())) > 1,
            str(sorted(p.name for p in a.program.parent.iterdir())))
    # 新程序一直连不上 controller。让它像连着崩溃一样重启：第 4 次启动时它应该自己换回旧程序。
    for attempt in (1, 2, 3):
        wait_until(lambda: a.count("这是刚换上来的新版本") >= attempt, timeout=20, what=f"a 的新程序第 {attempt} 次启动")
        time.sleep(1)
        a.kill()
    rolled_back = waited(lambda: "已经换回旧程序" in a.read_log(), 30, "a 换回旧程序")
    t.check("启动 3 次都没连上 controller 之后，a 自己换回了旧程序", rolled_back and a.installed_version() == old, tail(a.read_log(), 10))
    t.check("换回之后以“请重启我”退出，旧程序重新启动",
            waited(lambda: a.read_log().rstrip().count(f"退出码 {RESTART_EXIT_CODE}") >= 2, 15, "a 以旧程序重启"), tail(a.read_log(), 6))

    a.block_controller(controller, False)
    t.check("a 以旧版本重新上线", wait_version(controller, a, old), controller.node(a)["version"])
    reported = waited(lambda: (update_of(controller, a)["failure"] or {}).get("version") == new, 20, "a 报告失败")
    failure = update_of(controller, a)["failure"] or {}
    t.check("a 把失败报给了 controller，归因于版本", reported and failure.get("kind") == "version_rejected", str(update_of(controller, a)))
    overview = controller.ctl("update", "show")
    t.check("这个版本的自动更新被暂停了", [paused["version"] for paused in overview["paused"]] == [new], str(overview["paused"]))
    t.check("b 没有连不上的问题，它在暂停之前已经更新成功", wait_version(controller, b, new), controller.node(b)["version"])

    # 暂停期间新加入的节点不会被更新；失败过的 a 也不会再被要求装这个版本。
    c = SupervisedNode(lab.host("c"), work)
    c.join(controller)
    time.sleep(8)
    t.check("暂停期间，新加入的旧版本节点不会被更新",
            controller.node(c)["version"] == old and update_of(controller, c)["ordered"] is None and c.count("controller 要求更新") == 0,
            str(update_of(controller, c)))
    orders_to_a = a.count("controller 要求更新")
    controller.ctl("update", "resume", new)
    t.check("管理员继续之后，c 更新到新版本", wait_version(controller, c, new), controller.node(c)["version"])
    t.check("失败过的 a 留在旧版本，没有再被要求更新",
            controller.node(a)["version"] == old and a.count("controller 要求更新") == orders_to_a, str(update_of(controller, a)))
    t.check("a 回到旧版本之后照常工作", reaches(a, url, b, b.host.ip))
    if t.failures:
        print(tail(a.read_log(), 60), tail(controller.log.read_text(errors="replace"), 30), sep="\n  ---\n")


def broken_release_is_stopped_by_self_check(lab: Lab, work: Path, t: Checks) -> None:
    """发布出去的程序在这台机器上根本跑不了：自检不通过，节点不换程序、不重启，报告失败，自动更新被暂停。"""
    old, _new = versions()
    broken = next_version(old, 7)
    controller, release, web = setup(lab, work, auto=True)
    a, b = SupervisedNode(lab.host("a"), work), SupervisedNode(lab.host("b"), work, declare=("exit",))
    for node in (a, b):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    url = f"http://{web.ip}/"

    program = work / "broken-i3t"
    program.write_text("#!/bin/sh\necho '这个程序在这台机器上跑不了：缺一个库' >&2\nexit 127\n")
    program.chmod(0o755)
    release.publish(broken, program)
    controller.ctl("update", "check")
    paused = waited(lambda: controller.ctl("update", "show")["paused"], 40, "版本被暂停")
    overview = controller.ctl("update", "show")
    t.check("自检不通过的版本被暂停", paused and overview["paused"][0]["version"] == broken, str(overview["paused"]))
    t.check("失败的原因带着新程序自己说的话", "缺一个库" in (overview["paused"] or [{}])[0].get("reason", ""), str(overview["paused"]))
    time.sleep(3)
    t.check("两个节点都没有换程序，也没有重启",
            all(node.installed_version() == old and node.count("节点启动") == 1 and controller.node(node)["online"] for node in (a, b)))
    t.check("程序旁边没有留下没换上去的新程序", sorted(p.name for p in a.program.parent.iterdir()) == ["i3t"],
            str(sorted(p.name for p in a.program.parent.iterdir())))
    t.check("节点照常工作", reaches(a, url, b, b.host.ip))
    if t.failures:
        print(tail(a.read_log(), 40), tail(controller.log.read_text(errors="replace"), 30), sep="\n  ---\n")


def drain_then_update(lab: Lab, work: Path, t: Checks) -> None:
    """排空后更新：出口不再接新的流，手上的流跑完之后才换程序重启；排空期间新的请求被明确地拒绝。"""
    old, new = versions()
    controller, release, web = setup(lab, work, auto=False)
    a, b, c = (SupervisedNode(lab.host(name), work, declare=("exit",) if name == "b" else ()) for name in "abc")
    for node in (a, b, c):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    for node in (a, c):
        controller.add_proxy(node, b)
    start_whoami(c.host, 8080)
    on_c = f"http://{c.virtual_ip}:8080/"
    url = f"http://{web.ip}/"
    t.check("a 和 c 都能经 b 出去", reaches(a, url, b, b.host.ip) and reaches(c, url, b, b.host.ip))
    release.publish(new, STAGE / "new" / "i3t")
    controller.ctl("update", "check")

    # a 经 b 的这次下载是 b 手上的流：排空要等它跑完。
    download, size = slow_download(a, url, b, 25)
    time.sleep(2)
    controller.ctl("update", "node", str(b.id), "--drain")
    draining = waited(lambda: state_of(controller, b) == "draining", 30, "b 进入排空")
    t.check("b 准备好新程序之后进入排空，没有马上重启", draining and b.installed_version() == old and b.count("节点启动") == 1,
            str(update_of(controller, b)["status"]))
    t.check("下发的时机是“排空后”", update_of(controller, b)["ordered"] == {"version": new, "timing": "after_drain"}, str(update_of(controller, b)))

    refused = c.curl(url, via=b, timeout=8)
    t.check("排空期间别的节点经 b 的新请求被拒绝", refused.returncode != 0 and refused.stdout != b.host.ip, f"{refused.stdout!r} {refused.stderr.strip()}")
    t.check("b 记下了拒绝的原因", "节点正在排空" in b.read_log(), tail(b.read_log(), 6))
    local = b.curl(on_c, timeout=5)
    t.check("排空期间 b 自己的组网入口也拒绝新的请求", local.returncode != 0, f"{local.stdout!r} {local.stderr.strip()}")
    t.check("i3t status 说明节点正在排空", "正在排空" in b.i3t("status").stdout, b.i3t("status").stdout[-400:])
    t.check("手上的流还在跑，b 还没有重启", download.poll() is None and b.count("节点启动") == 1)

    ok, detail = finished_intact(download, size)
    t.check("排空开始之前就在跑的下载完整地结束了", ok, detail)
    t.check("流跑完之后 b 更新到新版本", wait_version(controller, b, new), controller.node(b)["version"])
    t.check("重启之后 b 重新接受新的流", reaches(c, url, b, b.host.ip) and b.curl(on_c, timeout=8).stdout == c.host.ip)
    if t.failures:
        print(tail(b.read_log(), 50), tail(c.read_log(), 20), sep="\n  ---\n")


def download_resumes_after_link_loss(lab: Lab, work: Path, t: Checks) -> None:
    """取包取到一半，和 controller 的连接断了：连接恢复之后从断点接着取，不从头来，更新照样完成。"""
    old, new = versions()
    controller, release, _web = setup(lab, work, auto=False)
    a = SupervisedNode(lab.host("a"), work)
    a.join(controller)
    # 把 a 的线路压慢，包要取十几秒，中间才来得及断一次。
    a.host.shape(Shape(rate_mbit=12))
    release.publish(new, STAGE / "new" / "i3t")
    controller.ctl("update", "check")
    size = (STAGE / "new" / "i3t").stat().st_size

    def sent() -> int:
        """controller 一共发出去多少字节的包。"""
        metrics = controller.host.run("curl", "-sS", "--max-time", "5", "http://127.0.0.1:20332/metrics", check=False).stdout
        line = next((line for line in metrics.splitlines() if line.startswith("i3t_controller_package_bytes_sent_total ")), "x 0")
        return int(line.split()[1])

    controller.ctl("update", "node", str(a.id))

    def received() -> int:
        status = update_of(controller, a)["status"]
        return status.get("received", 0) if status["state"] == "downloading" else 0

    partly = waited(lambda: received() > size // 4, 60, "a 取了四分之一")
    before = received()
    t.check("a 正在一段一段地取包", partly and before < size, f"取了 {before} / {size}")
    a.block_controller(controller)
    interrupted = waited(lambda: "取包被打断" in a.read_log(), 30, "a 发现取包被打断")
    t.check("连接断了之后 a 知道取包被打断，等着重试", interrupted, tail(a.read_log(), 6))
    time.sleep(3)
    t.check("断着的时候 a 没有放弃这次更新，也没有重启", a.count("节点启动") == 1 and "更新没有成功" not in a.read_log(), tail(a.read_log(), 6))
    a.block_controller(controller, False)
    a.host.shape(None)

    t.check("连接恢复之后 a 取完了包，更新到新版本", wait_version(controller, a, new, timeout=120), controller.node(a)["version"])
    total = sent()
    t.check("包是从断点接着取的，没有从头再来", size <= total < size + size // 4, f"controller 一共发了 {total} 字节，包有 {size} 字节")
    t.check("controller 重连之后重发的同一条指令没有打断正在做的更新", a.count("开始准备新版本") == 1, tail(a.read_log(), 12))
    if t.failures:
        print(tail(a.read_log(), 60), tail(controller.log.read_text(errors="replace"), 30), sep="\n  ---\n")


def ctl_text(controller: Controller, *args: str) -> str:
    """i3tctl 给人看的输出（不加 --json），语言是测试定下的中文。"""
    return controller.host.run(binary("i3tctl"), "--token", controller.token, *args).stdout


def node_switch_and_security_floor(lab: Lab, work: Path, t: Checks) -> None:
    """按节点关掉自动更新：关着的节点不被自动更新，关掉时撤回还没换上去的那次，"立即更新"照样管用；
    发布写了安全下限，比它旧的节点被标出来，只是告诉人。"""
    old, new = versions()
    controller, release, web = setup(lab, work, auto=True)
    a, b, c = (SupervisedNode(lab.host(name), work, declare=("exit",) if name == "b" else ()) for name in "abc")
    for node in (a, b, c):
        node.join(controller)
    controller.ctl("exit", "enable", str(b.id))
    controller.add_proxy(a, b)
    kept = controller.ctl("node", "set", str(c.id), "--auto-update", "off")
    t.check("新节点的自动更新开着，c 的被关掉了", controller.node(a)["auto_update"] is True and kept["auto_update"] is False, str(kept))
    url = f"http://{web.ip}/"
    t.check("a 经 b 出得去", reaches(a, url, b, b.host.ip))

    # a 经 b 的下载让 a 和 b 都停在“等待空闲”上：新程序准备好了，还没换上去。
    download, size = slow_download(a, url, b, 30)
    time.sleep(2)
    release.publish(new, STAGE / "new" / "i3t", security_floor=new)
    checked = controller.ctl("update", "check")
    t.check("controller 读到了清单里的安全下限", (checked["release"] or {}).get("security_floor") == new, str(checked["release"]))
    t.check("比下限旧的节点都标着有安全更新",
            all(update_of(controller, node)["security"] is True for node in (a, b, c)), str([update_of(controller, n) for n in (a, b, c)]))
    both_waiting = waited(lambda: all(state_of(controller, node) == "waiting_for_idle" for node in (a, b)), 30, "a 和 b 等待空闲")
    t.check("开着的 a 和 b 取了包、过了自检，在等空闲", both_waiting, f"a: {update_of(controller, a)['status']}，b: {update_of(controller, b)['status']}")
    t.check("开关关着的 c 没有收到自动更新，只标出有新版本",
            update_of(controller, c)["ordered"] is None and update_of(controller, c)["available"] == new and c.count("controller 要求更新") == 0,
            str(update_of(controller, c)))

    controller.ctl("node", "set", str(a.id), "--auto-update", "off")
    withdrawn = waited(lambda: "controller 撤回了更新的要求" in a.read_log() and state_of(controller, a) == "idle", 15, "a 的更新被撤回")
    t.check("关掉 a 的开关：还没换上去的自动更新被撤回", withdrawn and update_of(controller, a)["ordered"] is None,
            f"{update_of(controller, a)}\n{tail(a.read_log(), 6)}")
    t.check("b 不受影响，还在等空闲", state_of(controller, b) == "waiting_for_idle", str(update_of(controller, b)["status"]))

    ok, detail = finished_intact(download, size)
    t.check("下载完整地结束了", ok, detail)
    t.check("流结束之后 b 更新到新版本", wait_version(controller, b, new), controller.node(b)["version"])
    t.check("更新到下限那一版的 b 不再标着有安全更新", update_of(controller, b)["security"] is False, str(update_of(controller, b)))
    time.sleep(5)
    t.check("开关关着的 a 和 c 没有换程序，也没有重启",
            all(node.installed_version() == old and node.count("节点启动") == 1 for node in (a, c)),
            f"a: {a.installed_version()}，c: {c.installed_version()}")

    overview = ctl_text(controller, "update", "show")
    t.check("i3tctl update show 写明了安全下限", f"低于 {new} 的版本有已知的安全问题" in overview, overview)
    shown = ctl_text(controller, "node", "show", str(c.id))
    t.check("i3tctl node show 写明了安全更新和关着的自动更新",
            f"有新版本 {new}（安全更新）" in shown and any("自动更新" in line and "关" in line for line in shown.splitlines()), shown)

    controller.ctl("node", "set", str(c.id), "--auto-update", "on")
    t.check("打开 c 的开关之后它自动更新到新版本", wait_version(controller, c, new), controller.node(c)["version"])
    controller.ctl("update", "node", str(a.id))
    t.check("开关关着的 a 由管理员点了“立即更新”，照样更新", wait_version(controller, a, new), controller.node(a)["version"])
    t.check("更新之后照样互通", reaches(a, url, b, b.host.ip))
    if t.failures:
        print(tail(a.read_log(), 40), tail(controller.log.read_text(errors="replace"), 30), sep="\n  ---\n")


SCENARIOS = {
    "forced_update": forced_update,
    "idle_waits_for_flows": idle_waits_for_flows,
    "drain_then_update": drain_then_update,
    "download_resumes_after_link_loss": download_resumes_after_link_loss,
    "rollback_pauses_rollout": rollback_pauses_rollout,
    "broken_release_is_stopped_by_self_check": broken_release_is_stopped_by_self_check,
    "node_switch_and_security_floor": node_switch_and_security_floor,
}


def main() -> int:
    if os.environ.get(lablib.IN_LAB_ENV) != "1":
        build()
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
            finally:
                while RUNNING:
                    RUNNING.pop().stop()
        time.sleep(0.3)
    return t.summary()


if __name__ == "__main__":
    sys.exit(main())
