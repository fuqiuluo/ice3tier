"""在实验环境里启动 ice3tier 的程序，以及测试里反复用到的几样东西。"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

from lab import Host, wait_until

REPO = Path(__file__).resolve().parents[2]
BIN_DIR = Path(os.environ.get("I3T_BIN_DIR", REPO / "target" / "release"))
# 程序在终端上说的话跟着系统的语言。测试读其中的一些（多数用 --json），按中文写的，所以这里定下来：测试启动的程序都继承它。
os.environ["I3T_LANG"] = "zh-CN"
NETWORK = {"name": "lab", "domain": "lab.i3t", "cidr": "10.66.0.0/16"}

# 节点本机配置文件里的组网入口（`[proxy]`）：只通到组网里的节点，不认证、没有出口。节点默认不开，测试里的节点默认开着
# （`Node(local_entry=False)` 不开），访问组网里的节点就经它。
LOCAL_SOCKS5 = 1080
LOCAL_HTTP = 1081
# 经出口出去的代理：在节点 A 上监听、经出口节点 B 出去。没有写端口时监听在 PROXY_PORT_BASE + B 的编号上。
PROXY_PORT_BASE = 11000


@dataclass
class Proxy:
    """客户端眼里的一个代理：连哪里，用户名和密码（不认证时是空的）。组网入口也是这样一个。"""
    host: str
    port: int
    username: str = ""
    password: str = ""

    def url(self, scheme: str) -> str:
        """`socks5h://用户名:密码@127.0.0.1:11002` 这样的写法。"""
        login = f"{self.username}:{self.password}@" if self.username or self.password else ""
        return f"{scheme}://{login}{self.host}:{self.port}"

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


def verifier(username: str, password: str) -> dict:
    """静态 netmap 里代理的 `auth`：SHA-256(盐 ‖ SHA-256(用户名) ‖ 密码)，和 `i3t_model::netmap::Verifier` 一样。"""
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + hashlib.sha256(username.encode()).digest() + password.encode()).hexdigest()
    return {"salt": salt.hex(), "hash": digest}

# 一个只回答"你是从哪个地址连过来的"的 HTTP 服务。用它确认流量是从哪个节点的出口出去的。
WHOAMI = r"""
import http.server, socketserver, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode()
        if self.path.startswith("/bytes/"):
            body = b"x" * int(self.path.rsplit("/", 1)[1])
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
Server((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
"""


def binary(name: str) -> str:
    path = BIN_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"找不到 {path}。先构建：cargo build --release，或者用环境变量 I3T_BIN_DIR 指到可执行文件所在的目录")
    return str(path)


def scratch_database(name: str = "e2e") -> str:
    """测试用的 PostgreSQL 上的一个新的空库，返回连到它的连接串。

    服务器在哪里由环境变量 `I3T_TEST_DATABASE_URL` 说，见 `scripts/test-postgres.sh`。要是经 Unix 套接字连的那一种：
    实验环境里的主机各有各的网络命名空间，连不到本机的端口，文件系统却是同一个。
    """
    done = subprocess.run([str(REPO / "scripts" / "test-postgres.sh"), "database", name], capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"建不了测试用的数据库：{done.stderr.strip()}")
    return done.stdout.strip()


def start_controller(host: Host, data: Path, database: str, address: str, out: Path, log: Path) -> subprocess.Popen:
    """在 `host` 上启动 controller，等它说已启动。管理令牌打在标准输出上，日志在标准错误上，分开收。"""
    proc = subprocess.Popen(
        host.cmd(binary("i3t-controller"), "--data-dir", str(data), "--database-url", database, "--public-addr", address),
        stdout=out.open("w"), stderr=log.open("w"))
    host._procs.append(proc)
    wait_until(lambda: "已启动" in log.read_text(errors="replace") or proc.poll() is not None, what="controller 启动")
    if proc.poll() is not None:
        raise RuntimeError(f"controller 启动失败：\n{log.read_text(errors='replace')[-2000:]}")
    return proc


def start_whoami(host: Host, port: int = 80, bind: str = "0.0.0.0") -> None:
    host.spawn(sys.executable, "-c", WHOAMI, bind, str(port))
    wait_until(lambda: f":{port} " in host.run("ss", "-lnt").stdout, what=f"{host.name} 上的 HTTP 服务启动")


class Controller:
    """实验环境里的 controller，以及操作它的命令行。"""

    def __init__(self, host: Host, work: Path) -> None:
        self.host = host
        self.log = work / "controller.log"
        self.out = work / "controller.out"
        self.address = f"{host.ip}:20331"
        # 网络、节点和设置在这个库里；数据目录里只有 controller 的密钥和更新包的缓存。
        self.database = scratch_database()
        self.proc = start_controller(host, work / "controller", self.database, self.address, self.out, self.log)
        tokens = [line.strip() for line in self.out.read_text().splitlines() if line.startswith("    ")]
        if len(tokens) != 1:
            raise RuntimeError(f"没有在 controller 的输出里找到管理令牌：{self.out.read_text()!r}")
        self.token = tokens[0]

    def ctl(self, *args: str, check: bool = True) -> object:
        """执行一条 i3tctl 命令，返回管理 API 的 JSON。`check=False` 时出错不抛异常，返回完成的进程。"""
        done = self.host.run(binary("i3tctl"), "--token", self.token, "--json", *args, check=False)
        if not check:
            return done
        if done.returncode != 0:
            raise RuntimeError(f"i3tctl {' '.join(args)} 失败：{done.stderr.strip() or done.stdout.strip()}")
        return json.loads(done.stdout) if done.stdout.strip() else None

    def enroll_token(self, *groups: str) -> str:
        """一个注册令牌，用它加入的节点在这些分组里。分组要已经有了，见 `create_groups`。"""
        created = self.ctl("token", "create", *[arg for group in groups for arg in ("--group", group)])
        return created["token"]

    def node(self, node: "Node") -> dict:
        """controller 眼里这个节点现在的样子。"""
        return next(entry for entry in self.ctl("node", "list") if entry["key"] == node.key)

    def forward_target(self, node: "Node", on: bool = True) -> None:
        """管理员打开（或者关掉）节点"可以作为端口转发的目标"的开关。节点自己不声明它。"""
        self.ctl("node", "set", str(node.id), "--forward-target", "on" if on else "off")

    def add_proxy(self, node: "Node", exit: "Node", *args: str, port: int | None = None, bind: str = "127.0.0.1",
                  username: str = "", password: str = "", wait: bool = True, default: bool = True) -> dict:
        """经 controller 在 `node` 上建一个经 `exit` 出去的代理（`i3tctl proxy add`），之后 `node.curl(via=exit)` 这些就走它。
        `args` 是另外的选项（`--protocol socks5` 之类）。`wait` 时等到节点上这个端口开始监听（不等节点上报：它每 10 秒报一次，
        要看状态用 `wait_proxy`）。`default` 是假时不把它当作经 `exit` 出去的那一个（`curl(via=exit)` 不走它）。返回代理的 JSON。"""
        port = port or PROXY_PORT_BASE + exit.id
        login = [*(["--username", username] if username else []), *(["--password", password] if password else [])]
        created = self.ctl("proxy", "add", str(node.id), f"{bind}:{port}", str(exit.id), *login, *args)
        host = "127.0.0.1" if bind in ("127.0.0.1", "0.0.0.0") else bind
        if default:
            node.proxies[exit.id] = Proxy(host, port, created["username"], created["password"])
        if wait:
            wait_until(lambda: f":{port} " in node.host.run("ss", "-lnt").stdout, what=f"{node.name} 上的代理 {bind}:{port} 开始监听")
        return created

    def proxy(self, proxy_id: int) -> dict:
        return self.ctl("proxy", "show", str(proxy_id))

    def wait_proxy(self, proxy_id: int, code: str = "listening", timeout: float = 60) -> dict:
        """等代理的状态变成 `code`（节点每 10 秒上报一次），返回那时的代理。"""
        wait_until(lambda: self.proxy(proxy_id)["status"]["code"] == code, timeout=timeout,
                   what=f"代理 #{proxy_id} 的状态变成 {code}（现在是 {self.proxy(proxy_id)['status']}）")
        return self.proxy(proxy_id)


class Node:
    """实验环境里的一个 ice3tier 节点。"""

    def __init__(self, host: Host, work: Path, node_id: int = 0, *, declare: tuple[str, ...] = (), local_entry: bool = True) -> None:
        self.host = host
        self.id = node_id
        self.name = host.name
        self.virtual_ip = f"10.66.0.{node_id}"
        self.state = work / host.name
        self.state.mkdir(parents=True, exist_ok=True)
        self.log = work / f"{host.name}.log"
        self.proc: subprocess.Popen | None = None
        # 启动节点时另外给的环境变量（测试用的开关）。
        self.env: dict[str, str] = {}
        declared = "\n".join(f"{name} = true" for name in declare)
        entries = f"[proxy]\nsocks5 = \"127.0.0.1:{LOCAL_SOCKS5}\"\nhttp = \"127.0.0.1:{LOCAL_HTTP}\"\n" if local_entry else ""
        (self.state / "config.toml").write_text(f"port = 20330\n[declare]\n{declared}\n{entries}[log]\nlevel = \"debug\"\n")
        # 这个节点上经出口出去的代理，按出口的编号：`proxy_to`（静态的 netmap）或者 `Controller.add_proxy` 记进来。
        self.proxies: dict[int, Proxy] = {}
        self.key = host.run(binary("i3t"), "--state-dir", str(self.state), "key").stdout.strip()

    @property
    def endpoint(self) -> str:
        return f"{self.host.ip}:20330"

    def as_peer(self, *, endpoints: bool = True, attached: list[tuple["Node", int]] = (), exit: bool = False,
                inbound: bool = True, outbound: bool = True) -> dict:
        """别的节点的 netmap 里，这个节点长什么样。"""
        peer = {"id": self.id, "key": self.key, "name": self.name, "virtual_ip": self.virtual_ip,
                "inbound": inbound, "outbound": outbound,
                "endpoints": [self.endpoint] if endpoints else [],
                "attached": [{"relay": relay.id, "rtt_ms": rtt} for relay, rtt in attached]}
        if exit:
            peer["exit"] = {}
        return peer

    def as_relay(self) -> dict:
        return {"id": self.id, "key": self.key, "name": self.name, "udp": [self.endpoint], "tcp": [self.endpoint]}

    def proxy_to(self, exit: "Node", *, port: int | None = None, bind: str = "127.0.0.1", protocol: str = "mixed",
                 username: str = "", password: str = "", default: bool = True, **settings) -> dict:
        """静态 netmap 里的一个代理：在这个节点上监听、经 `exit` 出去（放进 `netmap(proxies=…)`）。`default` 时之后
        `curl(via=exit)` 这些就走它。写了用户名和密码时 netmap 里只有它们的校验值。
        `settings` 是代理的别的设置（`class`、`optimistic`、`allow_from`）。"""
        port = port or PROXY_PORT_BASE + exit.id
        entry = {"id": port, "name": f"via-{exit.name}", "bind": f"{bind}:{port}", "protocol": protocol, "exit": exit.id, **settings}
        if username or password:
            entry["auth"] = verifier(username, password)
        host = "127.0.0.1" if bind in ("127.0.0.1", "0.0.0.0") else bind
        if default:
            self.proxies[exit.id] = Proxy(host, port, username, password)
        return entry

    def entry(self, via: "Node | None", protocol: str = "socks5") -> Proxy:
        """客户端从这个节点出去时连的代理：经 `via` 出去的那个，`via` 是 `None` 时是本机的组网入口（只到组网里的节点）。"""
        if via is None:
            return Proxy("127.0.0.1", LOCAL_SOCKS5 if protocol == "socks5" else LOCAL_HTTP)
        if via.id not in self.proxies:
            raise KeyError(f"{self.name} 上没有经 {via.name} 出去的代理：先 proxy_to 或者 Controller.add_proxy")
        return self.proxies[via.id]

    def netmap(self, *, peers: list[dict] = (), relays: list[dict] = (), me: dict | None = None,
               relay_clients: list["Node"] = (), proxies: list[dict] = (), version: int = 1) -> dict:
        own = {"proxies": list(proxies)} if proxies else {}
        return {"version": version, "network": NETWORK,
                "me": {"id": self.id, "name": self.name, "virtual_ip": self.virtual_ip, **own, **(me or {})},
                "peers": list(peers), "relays": list(relays),
                "relay_clients": [{"id": node.id, "key": node.key} for node in relay_clients]}

    def start_static(self, netmap: dict) -> None:
        path = self.state / "static-netmap.json"
        path.write_text(json.dumps(netmap, indent=1))
        self.proc = self.host.spawn(binary("i3t"), "--state-dir", str(self.state), "run", "--static", str(path), log=self.log,
                                    env=self.env)
        wait_until(lambda: "节点启动" in self.read_log() or self.proc.poll() is not None, what=f"{self.name} 启动")
        if self.proc.poll() is not None:
            raise RuntimeError(f"{self.name} 启动失败：\n{self.read_log()[-2000:]}")

    def join(self, controller: Controller, *groups: str, name: bool = True) -> None:
        """用一个新的注册令牌加入网络（一加入就在 `groups` 里），然后启动。加入之后把节点名改成主机名，方便看日志和写用户名。"""
        token = controller.enroll_token(*groups)
        done = self.host.run(binary("i3t"), "--state-dir", str(self.state), "join", input=token, check=False)
        if done.returncode != 0:
            raise RuntimeError(f"{self.name} 加入失败：{done.stderr.strip()}")
        seen = controller.node(self)
        self.id, self.virtual_ip = seen["id"], seen["virtual_ip"]
        if name:
            controller.ctl("node", "rename", str(self.id), self.name)
        self.start()

    def start(self) -> None:
        self.proc = self.host.spawn(binary("i3t"), "--state-dir", str(self.state), "run", log=self.log, env=self.env)
        wait_until(lambda: "节点启动" in self.read_log() or self.proc.poll() is not None, what=f"{self.name} 启动")
        if self.proc.poll() is not None:
            raise RuntimeError(f"{self.name} 启动失败：\n{self.read_log()[-2000:]}")

    def stop(self) -> None:
        if self.proc is not None:
            self.host.stop(self.proc)
            self.proc = None

    def read_log(self) -> str:
        return self.log.read_text(errors="replace") if self.log.exists() else ""

    def curl(self, url: str, *, via: "Node | None" = None, proxy: str = "socks5", timeout: float = 20,
             extra: tuple[str, ...] = (), through: Proxy | None = None) -> subprocess.CompletedProcess:
        """从这个节点所在的机器上访问 `url`：经这个节点上经 `via` 出去的代理，`via` 是 `None` 时经本机的组网入口。
        `through` 直接给出要连的代理（测认证时用）。`proxy` 是说哪种协议：`socks5` 或者 `http`（CONNECT）。"""
        target = through or self.entry(via, proxy)
        if proxy == "socks5":
            proxy_args = ["-x", target.url("socks5h")]
        else:
            # -p 让 curl 对明文 HTTP 也走 CONNECT 的隧道（不用 -p 的明文转发见 plain_http）。
            proxy_args = ["-p", "-x", target.url("http")]
        return self.host.run("curl", "-sS", "--max-time", str(timeout), *proxy_args, *extra, url, check=False, timeout=timeout + 5)


class Checks:
    """收集一个测试脚本里各项检查的结果。"""

    def __init__(self) -> None:
        self.failures: list[str] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        print(f"{'通过' if ok else '失败'}  {name}{'：' + detail if detail and not ok else ''}", flush=True)
        if not ok:
            self.failures.append(name)
        return ok

    def summary(self) -> int:
        print("全部通过" if not self.failures else f"{len(self.failures)} 项失败：" + "；".join(self.failures))
        return 1 if self.failures else 0


def tail(text: str, lines: int = 15) -> str:
    return textwrap.indent("\n".join(text.splitlines()[-lines:]), "    ")


# 下面是选路场景（test_routing.py）用的：按"哪两台主机之间"加网络条件，从节点的日志里读它现在走哪条路。

def shape_between(a: Host, b: Host, shape=None) -> None:
    """只给 `a` 和 `b` 之间的包加网络条件，两台主机的别的流量不受影响。`shape` 是 `lab.Shape`，`None` 表示去掉。

    `Host.shape` 管的是一台主机的整条上联线，做不出"直连差、绕 relay 好"的拓扑；这里按目的地址分流，
    两个方向各在发出的一侧加一半的延迟和各自的丢包。
    """
    for host, peer in ((a, b), (b, a)):
        shapes = host.__dict__.setdefault("_pair_shapes", {})
        if shape is None:
            shapes.pop(peer.ip, None)
        else:
            shapes[peer.ip] = shape
        host.run("tc", "qdisc", "del", "dev", "up0", "root", check=False)
        if not shapes:
            continue
        # 第一条带（1:1）走没有限制的流量，之后每个对端一条带，带下面挂一个 netem。
        host.run("tc", "qdisc", "add", "dev", "up0", "root", "handle", "1:", "prio", "bands", str(max(2, len(shapes) + 1)),
                 "priomap", *["0"] * 16)
        for band, (ip, pair_shape) in enumerate(shapes.items(), start=2):
            host.run("tc", "qdisc", "add", "dev", "up0", "parent", f"1:{band:x}", "handle", f"{band:x}0:", "netem",
                     *pair_shape.netem_args())
            host.run("tc", "filter", "add", "dev", "up0", "parent", "1:", "protocol", "ip", "prio", "1", "u32",
                     "match", "ip", "dst", f"{ip}/32", "flowid", f"1:{band:x}")


def route_changes(node: "Node", peer: "Node") -> list[tuple[str, str]]:
    """`node` 的日志里到 `peer` 的每一次换路：(换成了哪条路, 原因)，按发生的顺序。

    静态模式下没有 controller 可问，路径层每次换路都记一条带原因的日志，这里读的就是它。
    路写成"直连 1.2.3.4:20330"、"经 relay 8 → 9"或者"没有路"。
    """
    import re
    pattern = re.compile(rf"到对端的路变了 peer={peer.id} path=(.*?) reason=\"(.*?)\"\s*$")
    return [match.groups() for line in node.read_log().splitlines() if (match := pattern.search(line))]


def current_route(node: "Node", peer: "Node") -> str:
    """`node` 到 `peer` 现在走的路；还没有过路时是"没有路"。"""
    changes = route_changes(node, peer)
    return changes[-1][0] if changes else "没有路"


# 下面是 UDP 的场景（test_udp.py）用的。

# 一个 UDP 回显服务：把收到的报文发回去，前面加上"它看到的来源地址"和一个竖线。用它确认 UDP 是从哪个节点的出口出去的。
UDP_ECHO = r"""
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sys.argv[1], int(sys.argv[2])))
while True:
    data, peer = sock.recvfrom(65535)
    sock.sendto(peer[0].encode() + b"|" + data, peer)
"""

# 一个最小的 SOCKS5 UDP 客户端：做 UDP ASSOCIATE，经中继端口发一个报文，打印回来的报文（JSON）；等不到就打印 null。
# 参数：代理地址、代理端口、用户名、密码（都空时不认证）、目标、目标端口、载荷（十六进制）、最多发几次。
# 第一个报文要等两个节点之间建好连接才出得去，所以每隔一秒半重发一次，直到有回音。
SOCKS5_UDP = r"""
import json, socket, struct, sys
proxy_host, proxy_port, user, password, target, port, payload, tries = sys.argv[1:9]
control = socket.create_connection((proxy_host, int(proxy_port)), timeout=10)
if user or password:
    control.sendall(b"\x05\x01\x02")
    assert control.recv(2) == b"\x05\x02", "代理应该选中用户名密码认证"
    control.sendall(bytes([1, len(user)]) + user.encode() + bytes([len(password)]) + password.encode())
    assert control.recv(2) == b"\x01\x00", "认证应该通过"
else:
    control.sendall(b"\x05\x01\x00")
    assert control.recv(2) == b"\x05\x00", "代理应该选中不认证"
control.sendall(b"\x05\x03\x00\x01" + bytes(6))
reply = b""
while len(reply) < 10:
    reply += control.recv(10 - len(reply))
assert reply[:4] == b"\x05\x00\x00\x01", reply
relay = (socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0])
try:
    address = b"\x01" + socket.inet_aton(target)
except OSError:
    address = b"\x03" + bytes([len(target)]) + target.encode()
packet = b"\x00\x00\x00" + address + struct.pack("!H", int(port)) + bytes.fromhex(payload)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(1.5)
answer = None
for _ in range(int(tries)):
    udp.sendto(packet, relay)
    try:
        data, sender = udp.recvfrom(65535)
    except socket.timeout:
        continue
    assert sender == relay and data[:4] == b"\x00\x00\x00\x01", (sender, data[:10])
    answer = {"source": socket.inet_ntoa(data[4:8]), "port": struct.unpack("!H", data[8:10])[0], "data": data[10:].hex()}
    break
print(json.dumps(answer))
"""

# 一个普通的 UDP 客户端：往一个地址发一个报文，打印回来的报文（十六进制）；等不到就什么都不打印。
# 参数：地址、端口、载荷（十六进制）、最多发几次。
UDP_CLIENT = r"""
import socket, sys
address, port, payload, tries = sys.argv[1:5]
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(1.5)
for _ in range(int(tries)):
    udp.sendto(bytes.fromhex(payload), (address, int(port)))
    try:
        data, _ = udp.recvfrom(65535)
    except socket.timeout:
        continue
    print(data.hex())
    break
"""

# 没有 dnsmasq 的机器上顶替它的 DNS 服务：不管问什么名字，都用同一条 A 记录回答。参数：监听地址、端口、要回答的地址。
DNS_STUB = r"""
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sys.argv[1], int(sys.argv[2])))
while True:
    query, peer = sock.recvfrom(2048)
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(sys.argv[3])
    sock.sendto(query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + query[12:] + answer, peer)
"""


def _wait_udp_listening(host: Host, port: int, what: str) -> None:
    wait_until(lambda: f":{port} " in host.run("ss", "-lnu").stdout, what=what)


def start_udp_echo(host: Host, port: int, bind: str = "0.0.0.0") -> None:
    host.spawn(sys.executable, "-c", UDP_ECHO, bind, str(port))
    _wait_udp_listening(host, port, f"{host.name} 上的 UDP 回显服务启动")


def start_dns(host: Host, bind: str, port: int, name: str, address: str) -> str:
    """在 `host` 上起一个 DNS 服务，`name` 解析成 `address`。有 dnsmasq 就用它，没有就用一个替身。返回用的是哪个。"""
    import shutil

    if shutil.which("dnsmasq"):
        # -d：留在前台，也不切换用户（测试用的用户命名空间里只有 root 这一个用户，切不了）。
        host.spawn("dnsmasq", "-d", "--conf-file=/dev/null", "--no-resolv", "--no-hosts", "--bind-interfaces",
                   f"--listen-address={bind}", f"--port={port}", f"--address=/{name}/{address}")
        server = "dnsmasq"
    else:
        host.spawn(sys.executable, "-c", DNS_STUB, bind, str(port), address)
        server = "替身"
    _wait_udp_listening(host, port, f"{host.name} 上的 DNS 服务启动")
    return server


def socks5_udp(node: Node, target: str, port: int, payload: bytes, *, via: Node | None = None, through: Proxy | None = None,
               tries: int = 10) -> dict | None:
    """从 `node` 所在的机器经它上面经 `via` 出去的代理（`via` 是 `None` 时经组网入口；`through` 直接给出代理）
    发一个 UDP 报文给 `target:port`，返回回来的报文：来源地址、端口和数据。"""
    proxy = through or node.entry(via)
    done = node.host.run(sys.executable, "-c", SOCKS5_UDP, proxy.host, str(proxy.port), proxy.username, proxy.password, target, str(port),
                         payload.hex(), str(tries), check=False, timeout=tries * 2 + 15)
    if done.returncode != 0:
        raise RuntimeError(f"SOCKS5 UDP 客户端出错：{done.stderr.strip()[-500:]}")
    answer = json.loads(done.stdout)
    if answer is not None:
        answer["data"] = bytes.fromhex(answer["data"])
    return answer


def udp_exchange(host: Host, address: str, port: int, payload: bytes, *, tries: int = 10) -> bytes | None:
    """从 `host` 上往 `address:port` 发一个 UDP 报文，返回回来的报文；等不到返回 `None`。"""
    done = host.run(sys.executable, "-c", UDP_CLIENT, address, str(port), payload.hex(), str(tries), check=False, timeout=tries * 2 + 15)
    return bytes.fromhex(done.stdout.strip()) if done.stdout.strip() else None


def dns_query(name: str, query_id: int = 0x1d3f) -> bytes:
    """一个查 `name` 的 A 记录的 DNS 请求。"""
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.rstrip(".").split("."))
    return query_id.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x00\x01\x00\x01"


def dns_a_records(response: bytes, query: bytes) -> list[str]:
    """从 DNS 应答里取出 A 记录的地址。应答对不上 `query`（编号、问题）时抛出异常。"""
    import socket

    if response[:2] != query[:2] or not response[2] & 0x80 or response[12:len(query)] != query[12:]:
        raise ValueError(f"这不是对那个请求的应答：{response[:len(query)].hex()}")
    count, at, addresses = int.from_bytes(response[6:8], "big"), len(query), []
    for _ in range(count):
        # 名字要么是一个 2 字节的指针，要么是一串标签；这里的应答里都是指针。
        at += 2 if response[at] & 0xc0 == 0xc0 else response.index(b"\x00", at) - at + 1
        kind, length = int.from_bytes(response[at:at + 2], "big"), int.from_bytes(response[at + 8:at + 10], "big")
        if kind == 1 and length == 4:
            addresses.append(socket.inet_ntoa(response[at + 10:at + 14]))
        at += 10 + length
    return addresses


# 下面是限额与用量的场景（test_limits.py）用的。

def eventually_value(action, ok, timeout: float = 30, interval: float = 0.5):
    """反复执行 `action`，直到 `ok(结果)` 为真或者超时；返回最后一次的结果。节点每 10 秒上报一次，等上报的东西要用它。"""
    deadline = time.monotonic() + timeout
    while True:
        result = action()
        if ok(result) or time.monotonic() > deadline:
            return result
        time.sleep(interval)


def timed_download(node: Node, url: str, *, via: Node | None = None, through: Proxy | None = None, timeout: float = 60):
    """从 `node` 所在的机器经它上面经 `via` 出去的代理（或者 `through` 这个代理）下载 `url`，
    返回 (curl 的退出码, 下载的字节数, 用了多少秒)。"""
    proxy = through or node.entry(via)
    done = node.host.run("curl", "-sS", "--max-time", str(timeout), "-x", proxy.url("socks5h"), "-o", "/dev/null",
                         "-w", "%{size_download} %{time_total}", url, check=False, timeout=timeout + 5)
    size, seconds = (done.stdout.split() + ["0", "0"])[:2]
    return done.returncode, int(float(size)), float(seconds)


def hold_port(host: Host, port: int) -> None:
    """在 `host` 上占住一个 TCP 端口（别的程序在监听它），直到实验环境关闭。"""
    code = "import socket, time\ns = socket.socket()\ns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n" \
           f"s.bind(('127.0.0.1', {port}))\ns.listen()\ntime.sleep(3600)\n"
    host.spawn(sys.executable, "-c", code)
    wait_until(lambda: f"127.0.0.1:{port} " in host.run("ss", "-lnt").stdout, what=f"{host.name} 上的 {port} 端口被占住")


# 下面是 ice3proxy（lane）的场景（test_lane.py）用的。

# 一个按路径决定怎么回答的 HTTP 服务，同时听明文和 TLS。数据是按长度做种子的伪随机字节，测试那边算得出它的摘要，
# 收到的字节一个不差才对得上。参数：监听地址、明文端口、TLS 端口、证书、私钥。
#   GET  /blob/<n>         n 字节
#   POST /digest           回答请求体的 SHA-256（十六进制）
#   GET  /reset/<n>        说有 10n 字节，发出 n 字节之后用 RST 断开（上游在回答中途出了事）
#   GET  /slow/<s>/<n>     n 字节：先发一半，静默 s 秒，再发另一半
BLOB_SERVER = r"""
import hashlib, http.server, random, socket, socketserver, ssl, struct, sys, threading, time
def blob(n):
    return random.Random(n).randbytes(n)
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def answer(self, length):
        self.send_response(200)
        self.send_header("Content-Length", str(length))
        self.end_headers()
    def do_GET(self):
        parts = self.path.strip("/").split("/")
        if parts[0] == "blob":
            body = blob(int(parts[1]))
            self.answer(len(body))
            self.wfile.write(body)
        elif parts[0] == "reset":
            n = int(parts[1])
            self.answer(10 * n)
            self.wfile.write(blob(n))
            self.wfile.flush()
            time.sleep(0.5)
            # 不发 TLS 的 close_notify，也不发 FIN：直接 RST。
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            self.connection.close()
            self.close_connection = True
        elif parts[0] == "slow":
            seconds, n = float(parts[1]), int(parts[2])
            body = blob(n)
            self.answer(n)
            self.wfile.write(body[:n // 2])
            self.wfile.flush()
            time.sleep(seconds)
            self.wfile.write(body[n // 2:])
        else:
            self.send_error(404)
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        digest = hashlib.sha256()
        while length > 0:
            chunk = self.rfile.read(min(length, 1 << 16))
            if not chunk:
                break
            digest.update(chunk)
            length -= len(chunk)
        body = digest.hexdigest().encode()
        self.answer(len(body))
        self.wfile.write(body)
    def log_message(self, *args):
        pass
class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 1024
bind, plain, secure, cert, key = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
tls = Server((bind, secure), Handler)
tls.socket = context.wrap_socket(tls.socket, server_side=True)
threading.Thread(target=tls.serve_forever, daemon=True).start()
Server((bind, plain), Handler).serve_forever()
"""


def blob_digest(size: int) -> str:
    """`BLOB_SERVER` 的 /blob/<size> 回答的字节的 SHA-256。"""
    import hashlib
    import random

    return hashlib.sha256(random.Random(size).randbytes(size)).hexdigest()


def start_blob_server(host: Host, work: Path) -> Path:
    """在 `host` 上起 `BLOB_SERVER`，明文在 80、TLS 在 443。返回给客户端用的证书。"""
    cert, key = work / f"{host.name}-cert.pem", work / f"{host.name}-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                    "-subj", f"/CN={host.ip}", "-addext", f"subjectAltName=IP:{host.ip}", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    host.spawn(sys.executable, "-c", BLOB_SERVER, "0.0.0.0", "80", "443", str(cert), str(key))
    wait_until(lambda: ":443 " in host.run("ss", "-lnt").stdout and ":80 " in host.run("ss", "-lnt").stdout,
               what=f"{host.name} 上的数据服务启动")
    return cert


def fetch(node: Node, url: str, *, via: Node | None, cert: Path | None = None, proxy: str = "socks5", timeout: float = 60,
          upload: Path | None = None) -> tuple[int, str, str]:
    """从 `node` 所在的机器经它上面经 `via` 出去的代理（`via` 是 `None` 时经组网入口）取 `url`，
    返回 (curl 的退出码, 应答体, curl 的错误输出)。

    应答体比 1KB 长、或者不是文本时换成它的 SHA-256（十六进制）。`upload` 是要 POST 上去的文件。
    """
    entry = node.entry(via, proxy)
    proxy_args = f"-x {entry.url('socks5h')}" if proxy == "socks5" else f"-p -x {entry.url('http')}"
    tls = f"--cacert {cert}" if cert else ""
    body = f"--data-binary @{upload} -H 'Content-Type: application/octet-stream'" if upload else ""
    answer = node.state / "answer"
    script = (f"curl -sS --max-time {timeout} {proxy_args} {tls} {body} -o {answer} '{url}'; code=$?; "
              f"if [ $(stat -c %s {answer} 2>/dev/null || echo 0) -le 1024 ] && iconv -f utf-8 -t utf-8 {answer} >/dev/null 2>&1; "
              f"then cat {answer}; elif [ -e {answer} ]; then sha256sum {answer} | cut -d' ' -f1; fi; rm -f {answer}; echo $code >&2")
    done = node.host.run("bash", "-c", script, check=False, timeout=timeout + 10)
    lines = done.stderr.strip().splitlines()
    code = int(lines[-1]) if lines and lines[-1].isdigit() else -1
    return code, done.stdout.strip(), "\n".join(lines[:-1])


def blob_file(node: Node, size: int) -> Path:
    """`node` 的状态目录里一个内容和 /blob/<size> 一样的文件，上传用。"""
    import random

    path = node.state / f"blob-{size}"
    if not path.exists():
        path.write_bytes(random.Random(size).randbytes(size))
    return path


def node_metrics(node: Node) -> str:
    """节点本机的 /metrics。"""
    return node.host.run("curl", "-sS", "--max-time", "5", "http://127.0.0.1:20333/metrics", check=False).stdout


def metric(text: str, name: str, **labels: str) -> float:
    """`text`（Prometheus 文本）里名字是 `name`、标签都对得上的样本之和。"""
    import re

    total = 0.0
    pattern = re.compile(rf"^{re.escape(name)}(\{{(.*?)\}})? (\S+)$")
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        found = dict(re.findall(r'(\w+)="([^"]*)"', match.group(2) or ""))
        if all(found.get(key) == value for key, value in labels.items()):
            total += float(match.group(3))
    return total


LANE_COUNTERS = ("claims", "claims_waited", "claims_failed", "fallbacks", "dial_failures", "refused")


def lane_counts(node: Node, peer: Node | None = None) -> dict[str, float]:
    """`node` 上和 `peer`（不写时是全部对端）之间的 ice3proxy 的计数和水位，读自它的 /metrics。"""
    text = node_metrics(node)
    labels = {"peer": peer.name} if peer else {}
    counts = {name: metric(text, f"i3t_lane_{name}_total", **labels) for name in LANE_COUNTERS}
    counts["claim_wait_ms"] = metric(text, "i3t_lane_claim_wait_milliseconds_total", **labels)
    counts["in_use"] = metric(text, "i3t_lane_in_use", **labels)
    counts["dialling"] = metric(text, "i3t_lane_dialling", **labels)
    counts["control_up"] = metric(text, "i3t_lane_control_up", **labels)
    for pool in ("parked_here", "ready", "parked_at_peer"):
        counts[pool] = metric(text, "i3t_lane_idle", pool=pool, **labels)
    for mode in ("sealed", "passthrough", "spliced"):
        counts[f"{mode}_bytes"] = metric(text, "i3t_lane_bytes_total", mode=mode, **labels)
    counts["carried_bytes"] = counts["sealed_bytes"] + counts["passthrough_bytes"] + counts["spliced_bytes"]
    for reason in ("deadline", "unknown_key", "tls", "protocol", "busy"):
        counts[f"handshake_{reason}"] = metric(text, "i3t_lane_handshake_failures_total", reason=reason)
    return counts


def lane_line(node: Node, peer: Node | None = None) -> str:
    """一行给人看的 ice3proxy 计数。"""
    c = lane_counts(node, peer)
    return (f"{node.name}：控制 {c['control_up']:.0f}，空闲 {c['parked_here']:.0f}/{c['ready']:.0f}/{c['parked_at_peer']:.0f}，"
            f"在用 {c['in_use']:.0f}，取用 {c['claims']:.0f}（等过 {c['claims_waited']:.0f}，共 {c['claim_wait_ms']:.0f}ms，"
            f"没取到 {c['claims_failed']:.0f}），改走共用 {c['fallbacks']:.0f}，拨号失败 {c['dial_failures']:.0f}，拒绝 {c['refused']:.0f}，"
            f"字节 加密 {c['sealed_bytes'] / 1e6:.1f}MB / 程序搬 {c['passthrough_bytes'] / 1e6:.1f}MB / 内核搬 {c['spliced_bytes'] / 1e6:.1f}MB")


def lane_peer(node: Node, *, lane: str, **options) -> dict:
    """别的节点的 netmap 里打开了 ice3proxy 的 `node`。"""
    return {**node.as_peer(**options), "lane": lane}


def set_nat_timeouts(nat: Host, udp_s: int, tcp_s: int) -> None:
    """把 NAT 回收 UDP 和 TCP 映射的时间调短，像家用路由器那样。"""
    nat.run("sysctl", "-qw", f"net.netfilter.nf_conntrack_udp_timeout={udp_s}", f"net.netfilter.nf_conntrack_udp_timeout_stream={udp_s}",
            f"net.netfilter.nf_conntrack_tcp_timeout_established={tcp_s}")


def block_tcp_port(host: Host, port: int, blocked: bool = True) -> None:
    """`host` 不接受别人连它的 TCP 端口 `port`（直接丢掉，像防火墙那样），别的流量不受影响。"""
    host.run("nft", "delete", "table", "inet", "notcp", check=False)
    if blocked:
        rules = f"""
table inet notcp {{
    chain in {{
        type filter hook input priority filter;
        iifname != "lo" tcp dport {port} drop
    }}
}}
"""
        host.run("nft", "-f", "-", input=rules)


# 下面是主动测试（test_probe.py）用的。

def ctl_wait(controller: Controller, *args: str, timeout: float = 300) -> object:
    """执行一条要等一阵的 i3tctl 命令（主动测试会等到结果出来），返回管理 API 的 JSON。"""
    done = controller.host.run(binary("i3tctl"), "--token", controller.token, "--json", *args, check=False, timeout=timeout)
    if done.returncode != 0:
        raise RuntimeError(f"i3tctl {' '.join(args)} 失败：{done.stderr.strip() or done.stdout.strip()}")
    return json.loads(done.stdout)


def active_test(controller: Controller, a: Node, b: Node, *options: str, timeout: float = 300) -> dict:
    """在 `a` 和 `b` 之间做一次主动测试（`i3tctl test`），等它做完，返回结果。"""
    return ctl_wait(controller, "test", a.name, b.name, *options, timeout=timeout)


def forward_route(controller: Controller, a: Node, b: Node) -> dict:
    """controller 现问 `a`：到 `b` 现在走哪条路。"""
    return controller.ctl("path", str(a.id), str(b.id))["forward"].get("route") or {}


def add_node_config(node: Node, text: str) -> None:
    """在节点的配置文件末尾加几行。要在节点启动之前。"""
    with (node.state / "config.toml").open("a") as config:
        config.write(text)


def create_groups(controller: Controller, *names: str) -> None:
    """在当前的网络里建这些分组，已经有的跳过。节点、注册令牌和规则只能引用已有的分组。"""
    existing = {group["name"].lower() for group in controller.ctl("group", "list")}
    for name in names:
        if name.lower() not in existing:
            controller.ctl("group", "create", name)


def group_names(controller: Controller, node: Node) -> list[str]:
    """controller 眼里这个节点所在的分组（不含 All）。"""
    return [group["name"] for group in controller.node(node)["groups"]]


# 下面是断网之后恢复的场景（test_recovery.py）用的。

# 一个每 10 毫秒发一个 64 字节小消息的 TCP 服务，一直发到客户端断开。参数：监听地址、端口。
TICKER = r"""
import socket, sys, threading, time
def serve(conn):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        while True:
            conn.sendall(b"t" * 64)
            time.sleep(0.01)
    except OSError:
        pass
    finally:
        conn.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(64)
while True:
    conn, _ = s.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
"""

# 经一个不认证的 SOCKS5 代理连 TICKER，收 `seconds` 秒，打印 JSON：超过 0.5 秒的停顿（每一段的起止，单调时钟），
# 收到的字节数，流是不是提前断了。参数：代理的端口（在 127.0.0.1 上）、目标地址、端口、秒数。
TICKER_CLIENT = r"""
import json, socket, struct, sys, time
proxy_port, target, port, seconds = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
s = socket.create_connection(("127.0.0.1", proxy_port), timeout=30)
s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target) + struct.pack("!H", port))
reply = b""
while len(reply) < 10:
    reply += s.recv(10 - len(reply))
assert reply[1] == 0, reply
end = time.monotonic() + seconds
s.settimeout(0.5)
last, gaps, total, ended = time.monotonic(), [], 0, None
while time.monotonic() < end:
    try:
        data = s.recv(65536)
    except socket.timeout:
        continue
    except OSError as error:
        ended = repr(error)
        break
    if not data:
        ended = "eof"
        break
    now = time.monotonic()
    if now - last > 0.5:
        gaps.append([last, now])
    last, total = now, total + len(data)
print(json.dumps({"gaps": gaps, "bytes": total, "ended": ended, "last": last}))
"""


def start_ticker(host: Host, port: int = 80) -> None:
    host.spawn(sys.executable, "-c", TICKER, "0.0.0.0", str(port))
    wait_until(lambda: f":{port} " in host.run("ss", "-lnt").stdout, what=f"{host.name} 上的 ticker 服务启动")


def blackout_between(a: Host, b: Host, base, on: bool) -> None:
    """`a` 和 `b` 之间的包全部丢掉（netem 100% 丢包，`on`），或者恢复成 `base`（`lab.Shape`，可以是 `None`）。别的流量不受影响。"""
    import dataclasses

    from lab import Shape

    shape = dataclasses.replace(base or Shape(), loss_pct=100) if on else base
    shape_between(a, b, shape)


def rto_cap_supported() -> bool:
    """这个内核能不能给 TCP 的重传定时器设上限（Linux 6.15 起，和 sysctl tcp_rto_max_ms 同时出现）。"""
    return Path("/proc/sys/net/ipv4/tcp_rto_max_ms").exists()


# 下面是虚拟网卡（test_vnet.py）用的。

def system_snapshot(host: Host) -> dict[str, str]:
    """一台主机的包过滤规则、路由规则、全部路由表、网卡和地址。虚拟网卡拆掉之后要和装之前一模一样。"""
    return {
        "nft": host.run("nft", "list", "ruleset").stdout,
        "rules": host.run("ip", "rule", "show").stdout,
        "routes": host.run("ip", "route", "show", "table", "all").stdout,
        "links": host.run("ip", "-o", "link", "show").stdout,
        "addresses": host.run("ip", "-o", "addr", "show").stdout,
    }


def settled_snapshot(host: Host, timeout: float = 10) -> dict[str, str]:
    """一台刚建好的主机的快照，等它不再变了再取：内核在网卡起来一两秒之后才加上 IPv6 链路本地的地址（先是 tentative）和路由。"""
    deadline = time.monotonic() + timeout
    previous = system_snapshot(host)
    while time.monotonic() < deadline:
        time.sleep(0.5)
        current = system_snapshot(host)
        if current == previous and "fe80::" in current["routes"] and "tentative" not in current["addresses"]:
            return current
        previous = current
    return previous


def snapshot_difference(before: dict[str, str], after: dict[str, str]) -> str:
    """两份快照不一样的地方，给失败的检查看；一样时是空的。"""
    import difflib

    parts = []
    for key in before:
        if before[key] != after[key]:
            diff = difflib.unified_diff(before[key].splitlines(), after[key].splitlines(), lineterm="", n=0)
            parts.append(f"[{key}] " + " | ".join(line for line in diff if line[:1] in "+-" and line[:3] not in ("+++", "---")))
    return "；".join(parts)


def use_nameserver(address: str) -> None:
    """让实验环境里的程序（glibc 的解析器）把查询发给 `address`，像一台机器上的系统解析器把网络的域名转给节点那样。

    /etc/resolv.conf 在这台机器上通常指向 /run 下面 systemd-resolved 的文件；实验环境的 /run 是自己的一块 tmpfs，
    就写那里。不是那样的话，在自己的挂载命名空间里把一个文件绑到 /etc/resolv.conf 上。
    """
    resolv = Path("/etc/resolv.conf")
    text = f"nameserver {address}\noptions timeout:2 attempts:1\n"
    target = resolv.resolve()
    if str(target).startswith("/run/"):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return
    local = Path("/run/i3t-e2e-resolv.conf")
    local.write_text(text)
    subprocess.run(["mount", "--bind", str(local), "/etc/resolv.conf"], check=True)


def private_hosts_file() -> Path:
    """在自己的挂载命名空间里给 /etc/hosts 换一份可以写的副本，返回它。`i3t hosts --apply` 写的就是它。"""
    copy = Path("/run/i3t-e2e-hosts")
    copy.write_text(Path("/etc/hosts").read_text())
    subprocess.run(["mount", "--bind", str(copy), "/etc/hosts"], check=True)
    return copy


# 不经代理直接连一个地址：连上要多久、读到了什么、怎么失败的。参数：地址、端口、要发的文字、时限。打印 JSON。
DIAL = r"""
import json, socket, sys, time
host, port, send, limit = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
start = time.monotonic()
result = {}
try:
    s = socket.create_connection((host, port), timeout=limit)
    result["connected"] = round(time.monotonic() - start, 3)
    result["local"] = s.getsockname()[0]
    if send:
        s.sendall(send.encode())
    data = b""
    while len(data) < 65536:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    result["data"] = data.decode(errors="replace")
except OSError as error:
    result["error"] = type(error).__name__
result["seconds"] = round(time.monotonic() - start, 3)
print(json.dumps(result))
"""


def dial(host: Host, address: str, port: int, send: str = "", limit: float = 10) -> dict:
    """从 `host` 上不经代理直接连 `address:port`（虚拟网卡装着时经它），见 `DIAL`。"""
    done = host.run(sys.executable, "-c", DIAL, address, str(port), send, str(limit), check=False, timeout=limit + 15)
    return json.loads(done.stdout) if done.stdout.strip() else {"error": done.stderr.strip()[-300:]}


# 一个先说话的服务（像 SSH）：连上就发一行横幅，然后关掉。参数：监听地址、端口、横幅。
BANNER = r"""
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(64)
while True:
    conn, peer = s.accept()
    conn.sendall((sys.argv[3] + " " + peer[0] + "\r\n").encode())
    conn.close()
"""


def start_banner(host: Host, port: int, banner: str) -> None:
    host.spawn(sys.executable, "-c", BANNER, "0.0.0.0", str(port), banner)
    wait_until(lambda: f":{port} " in host.run("ss", "-lnt").stdout, what=f"{host.name} 上的横幅服务启动")


# 不经代理发一个 UDP 报文、收回答：回答的内容（十六进制）和它的来源。参数：地址、端口、载荷（十六进制）、最多发几次。
UDP_DIAL = r"""
import json, socket, sys, time
address, port, payload, tries = sys.argv[1], int(sys.argv[2]), bytes.fromhex(sys.argv[3]), int(sys.argv[4])
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(1.5)
result = {}
start = time.monotonic()
for _ in range(tries):
    try:
        udp.sendto(payload, (address, port))
    except OSError as error:
        result["error"] = type(error).__name__
        break
    try:
        data, source = udp.recvfrom(65535)
    except socket.timeout:
        continue
    except OSError as error:
        result["error"] = type(error).__name__
        break
    result["data"], result["source"] = data.hex(), f"{source[0]}:{source[1]}"
    break
result["seconds"] = round(time.monotonic() - start, 3)
print(json.dumps(result))
"""


def udp_dial(host: Host, address: str, port: int, payload: bytes, tries: int = 6) -> dict:
    done = host.run(sys.executable, "-c", UDP_DIAL, address, str(port), payload.hex(), str(tries), check=False, timeout=tries * 2 + 15)
    return json.loads(done.stdout) if done.stdout.strip() else {"error": done.stderr.strip()[-300:]}


# 不经代理直接连 TICKER，收 `seconds` 秒，打印 JSON：超过 0.5 秒的停顿、收到的字节数、流是不是提前断了。参数：地址、端口、秒数。
TICKER_DIRECT = r"""
import json, socket, sys, time
target, port, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.create_connection((target, port), timeout=10)
end = time.monotonic() + seconds
s.settimeout(0.5)
last, gaps, total, ended = time.monotonic(), [], 0, None
while time.monotonic() < end:
    try:
        data = s.recv(65536)
    except socket.timeout:
        continue
    except OSError as error:
        ended = repr(error)
        break
    if not data:
        ended = "eof"
        break
    now = time.monotonic()
    if now - last > 0.5:
        gaps.append(round(now - last, 2))
    last, total = now, total + len(data)
print(json.dumps({"gaps": gaps, "bytes": total, "ended": ended}))
"""


# 数发往覆盖网的地址段、真的从 up0 出去了的包：一张只计数的表，挂在 postrouting 的最后。经虚拟网卡走的包不从 up0 出去。
LEAK_WATCH = """
table ip leakwatch {
    chain post {
        type filter hook postrouting priority 300; policy accept;
        oifname "up0" ip daddr 10.66.0.0/16 counter
    }
}
"""


def watch_leaks(host: Host, on: bool = True) -> None:
    """在 `host` 上装上（或者去掉）`LEAK_WATCH`。"""
    host.run("nft", "delete", "table", "ip", "leakwatch", check=False)
    if on:
        host.run("nft", "-f", "-", input=LEAK_WATCH)


def leaked(host: Host) -> int:
    """`LEAK_WATCH` 数到的包。"""
    import re

    text = host.run("nft", "list", "table", "ip", "leakwatch").stdout
    found = re.search(r"counter packets (\d+)", text)
    return int(found.group(1)) if found else -1


# 下面是 controller 重启、备份与恢复的场景用的。

def controller_data(controller: Controller) -> Path:
    """`Controller` 启动时用的数据目录。"""
    return controller.out.parent / "controller"


def dump_database(database: str, to: Path) -> subprocess.CompletedProcess:
    """把 controller 的库备份成一个文件（`pg_dump`），部署文档里写的就是这样做。controller 开着也可以。"""
    return subprocess.run(["pg_dump", "--format=custom", "--file", str(to), database], capture_output=True, text=True)


def restore_database(dump: Path) -> str:
    """把 `dump_database` 写的文件恢复进一个新的空库（`pg_restore`），返回连到它的连接串。"""
    database = scratch_database("e2e_restored")
    done = subprocess.run(["pg_restore", "--no-owner", "--exit-on-error", "--dbname", database, str(dump)],
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"pg_restore 失败：{done.stderr.strip()}")
    return database


class RestoredController(Controller):
    """在已有的数据目录和库上启动的 controller（重启，或者从备份恢复），地址和原来的一样。

    管理令牌是原来的那个（库里有它的哈希），启动时不再打出来，所以由调用方给。
    """

    def __init__(self, host: Host, work: Path, data: Path, token: str, database: str) -> None:
        self.host = host
        self.log = work / "restored.log"
        self.out = work / "restored.out"
        self.address = f"{host.ip}:20331"
        self.database = database
        self.proc = start_controller(host, data, database, self.address, self.out, self.log)
        self.token = token


# 一个把请求头原样作为正文回给客户端的 HTTP 服务：看代理往目标传了哪些头。
HEADER_ECHO = r"""
import http.server, socketserver, sys
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = (self.requestline + "\n" + str(self.headers)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
Server((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
"""


def start_header_echo(host: Host, port: int = 80) -> None:
    host.spawn(sys.executable, "-c", HEADER_ECHO, "0.0.0.0", str(port))
    wait_until(lambda: f":{port} " in host.run("ss", "-lnt").stdout, what=f"{host.name} 上的请求头回显服务启动")


def plain_http(node: Node, url: str, *, via: Node | None = None, through: Proxy | None = None, extra: tuple[str, ...] = (),
               timeout: float = 60) -> tuple[str, str, str]:
    """从 `node` 所在的机器经它上面经 `via` 出去的代理（`via` 是 `None` 时经组网入口的 HTTP 那一个；`through` 直接给出代理）
    以明文 HTTP 代理的方式取 `url`（不用 CONNECT）。返回 (状态码, 应答体或者它的 SHA-256, curl 的错误输出)：应答体比 4KB 长时换成摘要。"""
    proxy = through or node.entry(via, "http")
    answer = node.state / "plain-answer"
    done = node.host.run("curl", "-sS", "--max-time", str(timeout), "-x", proxy.url("http"), *extra, "-o", str(answer),
                         "-w", "%{http_code}", url, check=False, timeout=timeout + 5)
    body = ""
    if answer.exists():
        data = answer.read_bytes()
        import hashlib

        body = hashlib.sha256(data).hexdigest() if len(data) > 4096 else data.decode(errors="replace")
        answer.unlink()
    return done.stdout.strip(), body, done.stderr.strip()


# 一个认 PROXY protocol（v1 和 v2）的小服务：读出头里的来源地址，读掉一个 HTTP 请求头，把那个地址作为应答的正文回过去。
# 头不对时回 "no proxy header"。参数：监听地址、端口。
PROXY_PROTOCOL_ECHO = r"""
import ipaddress, socket, socketserver, struct, sys
class Handler(socketserver.BaseRequestHandler):
    def read(self, n):
        data = b""
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data
    def handle(self):
        first = self.read(12)
        source = "no proxy header"
        if first.startswith(b"PROXY "):
            line = first
            while not line.endswith(b"\r\n"):
                line += self.read(1)
            source = line.decode().split()[2]
        elif first == b"\r\n\r\n\x00\r\nQUIT\n":
            ver_cmd, family, length = struct.unpack("!BBH", self.read(4))
            body = self.read(length)
            source = str(ipaddress.ip_address(body[:4] if family == 0x11 else body[:16]))
        rest = b""
        while b"\r\n\r\n" not in rest:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            rest += chunk
        answer = source.encode()
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(answer), answer))
class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
Server((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
"""


def start_proxy_protocol_echo(host: Host, port: int, bind: str = "127.0.0.1") -> None:
    host.spawn(sys.executable, "-c", PROXY_PROTOCOL_ECHO, bind, str(port))
    wait_until(lambda: f":{port} " in host.run("ss", "-lnt").stdout, what=f"{host.name} 上认 PROXY protocol 的服务启动")


def flow_routes(node: Node) -> list[tuple[str, str, str]]:
    """`node` 的日志里每条流结束时的摘要写的路：(开始时, 结束时, 中间换没换过)，按出现的顺序。"""
    import re

    pattern = re.compile(r"route_start=(.+?) route_end=(.+?) route_changed=(true|false)")
    return [match.groups() for line in node.read_log().splitlines() if "流结束" in line for match in [pattern.search(line)] if match]


# 下面是虚拟网卡（test_vnet.py）的另外几样。

def vnet_ready(node: Node, timeout: float = 15) -> str:
    """等节点的虚拟网卡有了结果，返回 "installed" 或者 "failed"。"""
    def outcome() -> str | None:
        log = node.read_log()
        if "虚拟网卡装好了" in log:
            return "installed"
        if "虚拟网卡装不上" in log:
            return "failed"
        return None
    wait_until(lambda: outcome() is not None, timeout=timeout, what=f"{node.name} 的虚拟网卡有了结果")
    return outcome() or "failed"


def vnet_dropped(node: Node, reason: str) -> float:
    """节点的虚拟网卡按原因丢掉的包（/metrics 的 i3t_vnet_dropped_total）。"""
    return metric(node_metrics(node), "i3t_vnet_dropped_total", reason=reason)


def firewall_rules(host: Host) -> dict[str, str]:
    """一台主机的包过滤规则：`nft list ruleset` 和 `iptables-save`，去掉写着时间的注释行和会跟着流量变的计数。"""
    import re

    saved = host.run("iptables-save", check=False).stdout
    saved = "\n".join(re.sub(r"\[\d+:\d+\]", "[-]", line) for line in saved.splitlines() if not line.startswith("#"))
    ruleset = re.sub(r"counter packets \d+ bytes \d+", "counter", host.run("nft", "list", "ruleset").stdout)
    return {"nft": ruleset, "iptables": saved}


def without_empty_filter(ruleset: str) -> str:
    """`nft list ruleset` 去掉一张只剩空的内置 INPUT 链（策略 accept）的 `ip filter` 表：iptables 插第一条规则时建的，
    删掉规则之后它留着，什么都不做。"""
    import re

    empty = re.compile(r"table ip filter \{\n\tchain INPUT \{\n\t\ttype filter hook input priority filter; policy accept;\n\t\}\n\}\n?")
    return empty.sub("", ruleset)


# 一个收发都核对的 TCP 传输：客户端连上之后发 n 字节（按 n 做种子的伪随机），服务端收齐之后回它们的 SHA-256。
# 服务参数：监听地址、端口。客户端参数：地址、端口、字节数；打印 JSON：摘要对不对、用了多少秒。
DIGEST_SERVER = r"""
import hashlib, socket, sys, threading
def serve(conn):
    with conn:
        size = int.from_bytes(conn.recv(8, socket.MSG_WAITALL), "big")
        digest, left = hashlib.sha256(), size
        while left:
            chunk = conn.recv(min(left, 1 << 16))
            if not chunk:
                return
            digest.update(chunk)
            left -= len(chunk)
        conn.sendall(digest.hexdigest().encode())
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(64)
while True:
    conn, _ = s.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
"""

DIGEST_CLIENT = r"""
import hashlib, json, random, socket, sys, time
address, port, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
data = random.Random(size).randbytes(size)
start = time.monotonic()
s = socket.create_connection((address, port), timeout=30)
s.sendall(size.to_bytes(8, "big") + data)
answer = s.recv(64).decode()
took = time.monotonic() - start
print(json.dumps({"ok": answer == hashlib.sha256(data).hexdigest(), "seconds": round(took, 3),
                  "mss": s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)}))
"""


def start_digest_server(host: Host, port: int) -> None:
    host.spawn(sys.executable, "-c", DIGEST_SERVER, "0.0.0.0", str(port))
    wait_until(lambda: f":{port} " in host.run("ss", "-lnt").stdout, what=f"{host.name} 上的核对服务启动")


def send_checked(host: Host, address: str, port: int, size: int, timeout: float = 120) -> dict:
    """从 `host` 不经代理把 `size` 字节发到 `address:port` 上的 `DIGEST_SERVER`，见 `DIGEST_CLIENT`。"""
    done = host.run(sys.executable, "-c", DIGEST_CLIENT, address, str(port), str(size), check=False, timeout=timeout)
    return json.loads(done.stdout) if done.stdout.strip() else {"ok": False, "error": done.stderr.strip()[-300:]}
