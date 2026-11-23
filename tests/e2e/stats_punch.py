#!/usr/bin/env python3
"""打洞的统计：对实验环境搭得出的每一对网络位置重复建立直连，数成功率和耗时。

    python3 tests/e2e/stats_punch.py [--reps N] [--out 目录] [--pairs 组合,...] [--variants 条件,...]
    python3 tests/e2e/stats_punch.py --table 目录        # 只按已有的原始数据重新出表

不是通过 / 失败的测试，不在任何测试套件里。

一次尝试：新搭一个实验环境，起一个 controller，节点 a、b（和条件要求的 relay）用注册令牌加入。等两个节点都在线
（有 relay 时还要都挂上了它；"controller 停了"的条件下再把 controller 停掉），a 经本机的 SOCKS5 入口反复访问 b 上的
一个 HTTP 服务（`Target::Node`），直到 a 到 b 的路换成直连，或者过了 `WINDOW` 秒。记下：

- 直连有没有建起来；
- 耗时：从发出第一个请求（就是看到两个节点都在线的那一刻）到 a 的日志里"到对端的路变了 … path=直连"那一行；
- 是哪一种直连（`i3tctl path` 现问 a 和 b：lan、ipv6、reachable、punched），两个方向各一个；
- 第一个请求成没成、用了多久（没有 relay 时它要等直连）。

每台公网主机和每个 NAT 路由器到"互联网"的那条线上都加 `--rtt-ms`（默认 20 ms）的往返延迟，所以 a 到 b 的往返是它的两倍，
到 controller 和 relay 也一样远；同一个局域网里的两台机器之间没有延迟。不加延迟时实验环境里一切都在一毫秒之内完成，耗时说明不了什么。

每次尝试是一个单独的子进程，在自己的用户和网络命名空间里，结束时命名空间整个消失，互不影响。一次只跑一个。
原始的每一行追加到输出目录的 rows.jsonl（中途停下可以接着跑，已有的不重跑），跑完写 rows.csv 和 table.md，并打印那张表。

实验环境的 NAT 是 Linux 的 nftables 做的（见 lab.py），不是家用路由器：普通 NAT 的映射不随目的地址变、过滤按连接跟踪，
对称型 NAT 每条流一个随机端口；没有 UPnP / NAT-PMP / PCP，没有映射超时的差别，没有丢包和抖动，延迟只有上面那一个固定值。

程序从 `I3T_BIN_DIR`（默认 target/release）取，见 harness.py。
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime
import json
import math
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab as lablib  # noqa: E402

# 网络位置：节点在哪里。
PLACE_TEXT = {
    "public": "公网",
    "cone": "普通 NAT",
    "symmetric": "对称型 NAT",
    "forwarded": "普通 NAT + 端口转发",
    "lan": "同一个局域网",
}

# 一对节点的网络位置，a 在前，a 是发起访问的一方。不对称的组合两个方向都有：谁先发起，走的是不同的路。
PAIRS = {
    "public-public": ("public", "public"),
    "public-cone": ("public", "cone"),
    "cone-public": ("cone", "public"),
    "public-symmetric": ("public", "symmetric"),
    "symmetric-public": ("symmetric", "public"),
    "cone-cone": ("cone", "cone"),
    "cone-symmetric": ("cone", "symmetric"),
    "symmetric-cone": ("symmetric", "cone"),
    "symmetric-symmetric": ("symmetric", "symmetric"),
    "forwarded-symmetric": ("forwarded", "symmetric"),
    "symmetric-forwarded": ("symmetric", "forwarded"),
    "lan": ("lan", "lan"),
}

# 条件：信令和第一个请求走哪里。
VARIANTS = {
    "none": "没有 relay（信令只经 controller，第一个请求等直连）",
    "relay": "有两边共用的 relay（第一个请求先经 relay，信令经 controller 也经连接）",
    "relay-no-ctl": "有 relay，开始之前 controller 停了（信令只能经连接）",
}
# 第三种条件只对要交换信令才打得通的组合有意义；别的组合里直连的地址本来就在 netmap 里。
NO_CONTROLLER_PAIRS = ("cone-cone", "cone-symmetric", "symmetric-cone", "symmetric-symmetric")

# 等直连等多久。打洞失败之后按 1、1、2、4、4、8… 秒退避重试，20 秒里有五六轮；实验环境的 NAT 行为是确定的，
# 前几轮都不成的，后面也不会成。
WINDOW = 20.0
# 一次尝试最多多久（含搭环境），超过就当它卡住了，整组进程杀掉。
TRIAL_TIMEOUT = 180

ROUTE_LINE = re.compile(r"^(\S+)\s+INFO\b.*到对端的路变了 peer=(\d+) path=(\S+)(?: (\S+))?")


@dataclasses.dataclass
class Row:
    pair: str
    variant: str
    rep: int
    place_a: str
    place_b: str
    # 每条上联线的往返延迟，毫秒。
    rtt_ms: float = 0
    direct: bool = False
    # 从第一个请求到 a 的路换成直连，秒；没有建起来时是 None。
    direct_s: float | None = None
    # b 到 a 的路换成直连，同一个起点。
    direct_back_s: float | None = None
    # `i3tctl path` 报的直连种类，a → b 和 b → a。
    kind: str | None = None
    kind_back: str | None = None
    addr: str | None = None
    # a 到 b 的第一条路：relay、direct，或者一直没有路（None）。
    first_route: str | None = None
    first_ok: bool | None = None
    first_s: float | None = None
    requests: int = 0
    setup_s: float | None = None
    error: str | None = None


def expected(pair: str, variant: str) -> str:
    """这一对应该怎么连。"""
    a, b = PAIRS[pair]
    if a == "lan":
        return "直连（lan）"
    if {"public", "forwarded"} & {a, b}:
        return "直连"
    if a == b == "cone":
        return "直连（打洞）"
    return "经 relay" if variant != "none" else "不可达"


def log_time(stamp: str) -> float:
    """节点日志行首的时间（tracing 的默认格式，UTC）转成和 `time.time()` 同一个时钟的秒数。"""
    return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def routes(node, peer) -> list[tuple[float, str, str | None]]:
    """`node` 的日志里到 `peer` 的每一次换路：(时间, 直连 / 经 / 没有路, 直连的地址)。"""
    found = []
    for line in node.read_log().splitlines():
        match = ROUTE_LINE.match(line)
        if match and int(match.group(2)) == peer.id:
            kind = {"直连": "direct", "经": "relay"}.get(match.group(3), "none")
            found.append((log_time(match.group(1)), kind, match.group(4) if kind == "direct" else None))
    return found


def first_direct(node, peer) -> tuple[float, str | None] | None:
    return next(((at, addr) for at, kind, addr in routes(node, peer) if kind == "direct"), None)


def place(lab, name: str, where: str):
    """一台在 `where` 的主机，和它连到"互联网"的那台机器（它自己，或者它前面的 NAT 路由器）。"""
    if where == "public":
        host = lab.host(name)
        return host, host
    nat = lab.nat(f"nat-{name}", lablib.NatKind.SYMMETRIC if where == "symmetric" else lablib.NatKind.CONE)
    host = nat.host(name)
    if where == "forwarded":
        nat.forward_port("udp", 20330, host)
    return host, nat


def trial(pair: str, variant: str, rep: int, rtt_ms: float, work: Path) -> Row:
    """在当前（已经进了实验用的命名空间的）进程里做一次尝试。"""
    from harness import Controller, Node, RestoredController, controller_data, start_whoami

    place_a, place_b = PAIRS[pair]
    row = Row(pair, variant, rep, place_a, place_b, rtt_ms)
    started = time.monotonic()
    with lablib.Lab() as lab:
        ctl_host = lab.host("ctl")
        if place_a == "lan":
            nat = lab.nat("nat-ab", lablib.NatKind.CONE)
            (host_a, host_b), uplinks = (nat.host("a"), nat.host("b")), [nat]
        else:
            (host_a, uplink_a), (host_b, uplink_b) = place(lab, "a", place_a), place(lab, "b", place_b)
            uplinks = [uplink_a, uplink_b]
        relay_host = lab.host("r") if variant != "none" else None
        for uplink in [ctl_host, *uplinks, *([relay_host] if relay_host else [])]:
            uplink.shape(lablib.Shape(rtt_ms=rtt_ms))
        controller = Controller(ctl_host, work)
        controller.ctl("network", "create", "lab")
        start_whoami(host_b)
        relay = None
        if relay_host is not None:
            relay = Node(relay_host, work, declare=("relay",))
            relay.join(controller)
            controller.ctl("relay", "enable", str(relay.id))
        a, b = Node(host_a, work), Node(host_b, work)
        a.join(controller)
        b.join(controller)

        def ready() -> bool:
            shown = [controller.ctl("node", "show", str(node.id)) for node in (a, b)]
            return all(node["online"] for node in shown) and (relay is None or all(node["attached"] for node in shown))

        lablib.wait_until(ready, timeout=30, what="两个节点都在线" + ("并且挂上了 relay" if relay else ""))
        if variant == "relay-no-ctl":
            # 两边的地址要先报给 controller、写进对方的 netmap，之后 controller 才可以走。
            lablib.wait_until(lambda: all(controller.ctl("node", "show", str(node.id))["endpoints"] for node in (a, b)),
                              timeout=20, what="两个节点都报了自己的地址")
            time.sleep(1.0)
            controller.host.stop(controller.proc)
        row.setup_s = round(time.monotonic() - started, 2)

        url = f"http://{b.virtual_ip}/"
        begin = time.time()
        while first_direct(a, b) is None and time.time() < begin + WINDOW:
            sent = time.time()
            done = a.host.run("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "6",
                              "-x", "socks5h://127.0.0.1:1080", url, check=False, timeout=15)
            row.requests += 1
            if row.first_ok is None:
                row.first_ok, row.first_s = done.stdout == "200", round(time.time() - sent, 3)
            time.sleep(0.25)

        seen = routes(a, b)
        row.first_route = seen[0][1] if seen else None
        found = first_direct(a, b)
        if found:
            row.direct, row.direct_s, row.addr = True, round(found[0] - begin, 3), found[1]
            back = first_direct(b, a)
            row.direct_back_s = round(back[0] - begin, 3) if back else None
            if variant == "relay-no-ctl":
                # 种类只有现问节点才知道：把 controller 在同一份数据上重新起来，等两个节点重新连上。
                controller = RestoredController(controller.host, work, controller_data(controller), controller.token, controller.database)
                lablib.wait_until(lambda: all(controller.ctl("node", "show", str(node.id))["online"] for node in (a, b)),
                                  timeout=40, what="两个节点重新连上 controller")
            path = controller.ctl("path", str(a.id), str(b.id))
            row.kind = (path.get("forward") or {}).get("direct")
            row.kind_back = (path.get("reverse") or {}).get("direct")
    return row


def run_trial(args) -> int:
    """子进程：进命名空间，做一次尝试，最后一行打印 `ROW <json>`。"""
    lablib.enter()
    pair, variant, rep = args.trial[0], args.trial[1], int(args.trial[2])
    rtt_ms = args.rtt_ms
    keep = Path(args.keep) if args.keep else None
    # 节点的状态目录和日志放在输出目录下面（跑完就删），不散在系统的临时目录里。
    work_root = keep.parent / "work" if keep else None
    if work_root:
        work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{pair}-{variant}-{rep}-", dir=work_root) as work:
        try:
            row = trial(pair, variant, rep, rtt_ms, Path(work))
        except Exception as error:  # noqa: BLE001 - 出错也要交回一行，带着原因
            row = Row(pair, variant, rep, *PAIRS[pair], rtt_ms, error=repr(error)[:500])
        # 出错的、和预期不一样的，把各个程序的日志留下来看。
        surprising = row.direct != expected(pair, variant).startswith("直连")
        if keep is not None and (row.error or surprising):
            target = keep / f"{pair}-{variant}-{rep}"
            target.mkdir(parents=True, exist_ok=True)
            for log in Path(work).glob("*.log"):
                shutil.copy(log, target / log.name)
    print("ROW " + json.dumps(dataclasses.asdict(row), ensure_ascii=False), flush=True)
    return 0


def spawn_trial(pair: str, variant: str, rep: int, rtt_ms: float, keep: Path) -> Row:
    """在一个新的会话里跑一次尝试：卡住时连同它起的所有进程一起杀掉。"""
    cmd = [sys.executable, str(Path(__file__).resolve()), "--trial", pair, variant, str(rep), "--rtt-ms", str(rtt_ms), "--keep", str(keep)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=TRIAL_TIMEOUT)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return Row(pair, variant, rep, *PAIRS[pair], rtt_ms, error=f"超过 {TRIAL_TIMEOUT} 秒没有结束")
    for line in reversed(out.splitlines()):
        if line.startswith("ROW "):
            return Row(**json.loads(line[4:]))
    return Row(pair, variant, rep, *PAIRS[pair], rtt_ms, error=f"子进程没有交回结果（退出码 {proc.returncode}）：{err.strip()[-300:]}")


def load(out: Path) -> list[Row]:
    path = out / "rows.jsonl"
    if not path.exists():
        return []
    return [Row(**json.loads(line)) for line in path.read_text().splitlines() if line.strip()]


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """成功率的 95% 置信区间（Wilson）。次数少的时候比正态近似靠谱。"""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, centre - spread), min(1.0, centre + spread))


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))
    return ordered[index]


def table(rows: list[Row]) -> str:
    cells: dict[tuple[str, str, float], list[Row]] = {}
    for row in rows:
        cells.setdefault((row.pair, row.variant, row.rtt_ms), []).append(row)
    lines = [
        "| a | b | 条件 | 预期 | 次数 | 直连 | 成功率（95% 区间） | 耗时 中位 / p90 / 最大（秒） | 直连的种类 a→b / b→a | 第一个请求成功 | 出错 |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    order = {name: index for index, name in enumerate(PAIRS)}
    variants = {name: index for index, name in enumerate(VARIANTS)}
    for (pair, variant, rtt_ms), group in sorted(cells.items(), key=lambda item: (item[0][2], variants[item[0][1]], order[item[0][0]])):
        ran = [row for row in group if not row.error]
        direct = [row for row in ran if row.direct]
        low, high = wilson(len(direct), len(ran))
        times = [row.direct_s for row in direct if row.direct_s is not None]
        timing = f"{statistics.median(times):.2f} / {percentile(times, 0.9):.2f} / {max(times):.2f}" if times else "—"
        kinds: dict[str, int] = {}
        for row in direct:
            key = f"{row.kind or '?'} / {row.kind_back or '?'}"
            kinds[key] = kinds.get(key, 0) + 1
        kind_text = "、".join(f"{key} ×{count}" for key, count in sorted(kinds.items(), key=lambda item: -item[1])) or "—"
        first = sum(1 for row in ran if row.first_ok)
        rate = f"{len(direct) / len(ran):.0%}（{low:.0%}–{high:.0%}）" if ran else "—"
        a, b = PAIRS[pair]
        lines.append(f"| {PLACE_TEXT[a]} | {PLACE_TEXT[b]} | {variant}，{rtt_ms:g} ms | {expected(pair, variant)} | {len(ran)} | {len(direct)} | {rate} | "
                     f"{timing} | {kind_text} | {first}/{len(ran)} | {len(group) - len(ran)} |")
    return "\n".join(lines)


def write_outputs(out: Path, rows: list[Row]) -> str:
    fields = [field.name for field in dataclasses.fields(Row)]
    with (out / "rows.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(dataclasses.asdict(row) for row in rows)
    text = table(rows)
    (out / "table.md").write_text(text + "\n")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reps", type=int, default=20, help="预期能直连的格子每格重复几次（默认 20）")
    parser.add_argument("--reps-without", type=int, default=10,
                        help="预期不能直连的格子每格重复几次（默认 10；每次都要等满 WINDOW 秒）")
    parser.add_argument("--rtt-ms", type=float, default=20, help="每条上联线的往返延迟，毫秒（默认 20）")
    parser.add_argument("--out", help="原始数据和表写在哪里（默认新建一个临时目录）")
    parser.add_argument("--pairs", help="只跑这些组合，逗号分隔：" + ", ".join(PAIRS))
    parser.add_argument("--variants", help="只跑这些条件，逗号分隔：" + ", ".join(VARIANTS))
    parser.add_argument("--table", metavar="目录", help="不跑，只按这个目录里的 rows.jsonl 出表")
    parser.add_argument("--trial", nargs=3, metavar=("组合", "条件", "序号"), help=argparse.SUPPRESS)
    parser.add_argument("--keep", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.trial:
        return run_trial(args)
    if args.table:
        print(write_outputs(Path(args.table), load(Path(args.table))))
        return 0

    out = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix="i3t-punch-stats-"))
    out.mkdir(parents=True, exist_ok=True)
    pairs = args.pairs.split(",") if args.pairs else list(PAIRS)
    variants = args.variants.split(",") if args.variants else list(VARIANTS)
    cells = [(pair, variant) for variant in variants for pair in pairs if variant != "relay-no-ctl" or pair in NO_CONTROLLER_PAIRS]
    reps = {cell: args.reps if expected(*cell).startswith("直连") else args.reps_without for cell in cells}
    rows = load(out)
    done = {(row.pair, row.variant, row.rep) for row in rows}
    # 一轮一轮地跑，每轮每格一次：中途停下时各格的次数差不多。
    todo = [(pair, variant, rep) for rep in range(max(reps.values())) for pair, variant in cells
            if rep < reps[(pair, variant)] and (pair, variant, rep) not in done]
    print(f"输出在 {out}；{len(cells)} 格，上联线往返 {args.rtt_ms:g} ms，还要跑 {len(todo)} 次", flush=True)
    started = time.monotonic()
    with (out / "rows.jsonl").open("a") as log:
        for index, (pair, variant, rep) in enumerate(todo, start=1):
            row = spawn_trial(pair, variant, rep, args.rtt_ms, out / "kept")
            rows.append(row)
            log.write(json.dumps(dataclasses.asdict(row), ensure_ascii=False) + "\n")
            log.flush()
            outcome = row.error or (f"直连 {row.direct_s:.2f}s {row.kind}/{row.kind_back}" if row.direct else f"没有直连（第一条路 {row.first_route}）")
            print(f"[{index}/{len(todo)} {time.monotonic() - started:.0f}s] {pair} {variant} #{rep}：{outcome}", flush=True)
            # 上一次的进程要退干净，命名空间才会消失。
            time.sleep(0.3)
    print(f"用了 {time.monotonic() - started:.0f} 秒\n")
    print(write_outputs(out, rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
