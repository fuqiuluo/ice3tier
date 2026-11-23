#!/usr/bin/env python3
"""controller 的备份与恢复，照部署文档里写的做：运行中用 pg_dump 备份数据库、拷贝密钥，停掉，
把备份恢复进一个新的库，带着密钥启动，原来的节点自己连回来。

    python3 tests/e2e/test_backup.py [场景名...]
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab as lablib  # noqa: E402
from harness import (  # noqa: E402
    Checks, Controller, Node, RestoredController, controller_data, create_groups, dump_database, restore_database,
    start_whoami, tail,
)
from lab import Lab, wait_until  # noqa: E402


def socks(node: Node, url: str, timeout: float = 8):
    """从 `node` 所在的机器经它的本机 SOCKS5 入口访问 `url`。"""
    return node.host.run("curl", "-sS", "--max-time", str(timeout), "-x", "socks5h://127.0.0.1:1080", url, check=False, timeout=timeout + 5)


def reaches(node: Node, peer: Node, timeout: float = 30) -> bool:
    """反复尝试，直到 `node` 经覆盖网访问到 `peer` 上的服务（它回答 `peer` 的地址），或者超时。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if socks(node, f"http://{peer.virtual_ip}:8080/").stdout == peer.host.ip:
            return True
        time.sleep(0.5)
    return False


def blocked(node: Node, peer: Node, timeout: float = 20) -> bool:
    """反复尝试，直到 `node` 访问不到 `peer` 上的服务，或者超时。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if socks(node, f"http://{peer.virtual_ip}:8080/", timeout=4).returncode != 0:
            return True
        time.sleep(0.5)
    return False


def waited(condition, timeout: float, what: str) -> bool:
    try:
        wait_until(condition, timeout=timeout, interval=0.5, what=what)
    except TimeoutError:
        return False
    return True


def backup_and_restore(lab: Lab, work: Path, t: Checks) -> None:
    """两个节点在线时备份；之后加入第三个节点、建一个分组；停掉 controller，在备份上以同一个地址启动。"""
    controller = Controller(lab.host("ctl"), work)
    controller.ctl("network", "create", "lab", "--cidr", "10.66.0.0/16")
    create_groups(controller, "laptop")
    a, b, c = Node(lab.host("a"), work), Node(lab.host("b"), work), Node(lab.host("c"), work)
    a.join(controller, "laptop")
    b.join(controller)
    for node in (a, b):
        start_whoami(node.host, 8080)
    wait_until(lambda: all(controller.node(node)["online"] for node in (a, b)), what="a 和 b 上线")
    t.check("备份之前 a 和 b 互相访问得到", reaches(a, b) and reaches(b, a))

    # 备份是两样东西：数据库的一份转储，和数据目录里的密钥。
    backup = work / "backup"
    backup.mkdir()
    done = dump_database(controller.database, backup / "controller.dump")
    t.check("controller 运行中 pg_dump 成功", done.returncode == 0, done.stderr.strip())
    shutil.copy2(controller_data(controller) / "controller.key", backup / "controller.key")
    t.check("密钥只有属主可读，拷贝出来的也是", (backup / "controller.key").stat().st_mode & 0o777 == 0o600)

    # 备份之后的改动。
    create_groups(controller, "later")
    c.join(controller)
    wait_until(lambda: controller.node(c)["online"], what="c 上线")

    # 恢复：转储进一个新的空库，密钥放进一个新的数据目录。
    controller.host.stop(controller.proc)
    data = work / "restored"
    data.mkdir()
    shutil.copy2(backup / "controller.key", data / "controller.key")
    restored = RestoredController(controller.host, work, data, controller.token, restore_database(backup / "controller.dump"))
    t.check("备份时的管理令牌照常能用", restored.ctl("status", check=False).returncode == 0)
    t.check("a 和 b 自己连回了恢复的 controller",
            waited(lambda: all(restored.node(node)["online"] for node in (a, b)), 60, "a 和 b 重新上线"))
    t.check("a 和 b 一直在运行，没有重启", a.proc.poll() is None and b.proc.poll() is None
            and a.read_log().count("节点启动") == 1 and b.read_log().count("节点启动") == 1)
    t.check("恢复之后 a 和 b 互相访问得到", reaches(a, b) and reaches(b, a))
    for rule in restored.ctl("rule", "list"):
        restored.ctl("rule", "delete", str(rule["id"]))
    t.check("恢复的 controller 删掉 All <-> All 之后，a 访问不到 b：配置由它下发", blocked(a, b))

    names = sorted(node["name"] for node in restored.ctl("node", "list"))
    t.check("备份之后加入的 c 不在节点列表里", names == ["a", "b"], str(names))
    groups = [group["name"] for group in restored.ctl("group", "list")]
    t.check("备份之后建的分组不在，之前的在", "later" not in groups and "laptop" in groups, str(groups))
    stopped = waited(lambda: c.proc.poll() is not None, 90, "c 退出")
    t.check("c 被当成不认识的节点拒绝，不再重连，进程退出并说明要重新加入",
            stopped and "不认这个节点" in c.read_log() and "i3t join" in c.read_log(), tail(c.read_log(), 5))
    t.check("controller 的日志里有拒绝的原因", "这把公钥没有注册" in restored.log.read_text(errors="replace"))
    if t.failures:
        print(tail(a.read_log()), tail(c.read_log()), tail(restored.log.read_text(errors="replace")), sep="\n  ---\n")


SCENARIOS = {
    "backup_and_restore": backup_and_restore,
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
