#!/usr/bin/env bash
# 虚拟网卡的名字经一个真的 systemd-resolved 走。两个容器接在一个 --internal 的 Docker 网络上（不通外面）：
#
# - a：以 systemd 为 1 号进程（--privileged），开着 systemd-resolved；跑 controller（和它的 PostgreSQL）、节点 a，
#   节点 a 的虚拟网卡默认装上；
# - b：只跑节点 b 和一个 HTTP 服务（8080 端口，回答它看到的来源地址），有 CAP_NET_ADMIN 和 /dev/net/tun，也装上虚拟网卡。
#   b 在 Docker 的名字服务里另有一个名字
#   web.example.test，用来确认网络的域名之外的名字照旧经容器原来的解析器。
#
#   tests/platform/resolved/run.sh <有 i3t、i3t-controller、i3tctl（Linux 版）的目录> <结果目录> [root|service|service-polkit]
#
# root（默认）：节点 a 以 root 在前台跑。service：节点 a 装成 deploy/systemd 里的系统服务（i3t 用户、沙箱设置、
# 虚拟网卡要的那几项能力），看 systemd-resolved 认不认这样一个进程的设置。service-polkit：同 service，另外给 polkit
# 一条规则，允许 i3t 用户做那几个动作（改网卡的 DNS、路由域、默认路线，撤销）。
# 镜像的基础可以换：I3T_RESOLVED_BASE=ubuntu:24.04（默认 debian:trixie）。
# 结果目录里：summary.txt（每项 PASS 或 FAIL 和原因），resolvectl、i3t、journalctl 的输出。
set -uo pipefail
# 节点的命令经 docker exec -i 拿标准输入（注册令牌）；别的命令不该读到调用者的终端。
exec < /dev/null

bin=$(realpath "${1:?用法：run.sh <程序目录> <结果目录> [root|service]}")
out=$(realpath -m "${2:?缺结果目录}")
variant=${3:-root}
here=$(dirname "$(realpath "$0")")
repo=$(realpath "$here/../../..")
base=${I3T_RESOLVED_BASE:-debian:trixie}
image=${I3T_RESOLVED_IMAGE:-i3t-platform-resolved:${base//[:\/]/-}}
net=i3t-platform-resolved
a=i3t-resolved-a
b=i3t-resolved-b
case $variant in root | service | service-polkit) ;; *) echo "不认识的方式：$variant" >&2; exit 2 ;; esac

mkdir -p "$out"
summary=$out/summary.txt
: > "$summary"
record() { # 结果 名字 [原因]
    local line="$1  $2"
    [ -n "${3:-}" ] && line="$line: $(printf '%s' "$3" | tr '\n' ' ' | cut -c1-600)"
    echo "$line" | tee -a "$summary"
}
check() { # 名字 原因（失败时执行的一段 shell） 命令…
    local name=$1 why=$2; shift 2
    if "$@"; then record PASS "$name"; else record FAIL "$name" "$(eval "$why" 2>&1)"; fi
}
wait_for() { # 秒数 命令…
    local deadline=$((SECONDS + $1)); shift
    until "$@"; do [ $SECONDS -ge $deadline ] && return 1; sleep 0.5; done
}
ina() { docker exec "$a" "$@"; }
inb() { docker exec "$b" "$@"; }
save() { # 文件名 容器 命令…：输出（连同标准错误）存进结果目录
    local file=$1 where=$2; shift 2
    docker exec "$where" "$@" > "$out/$file" 2>&1
}
cleanup() {
    docker rm -f "$a" "$b" > /dev/null 2>&1
    docker network rm "$net" > /dev/null 2>&1
}
trap cleanup EXIT

docker build -q --build-arg "BASE=$base" -t "$image" "$here" > /dev/null || { echo "镜像建不出来" >&2; exit 1; }
cleanup
docker network create --internal "$net" > /dev/null
docker run -d --name "$a" --hostname a --privileged --cgroupns=private --network "$net" \
    --tmpfs /run --tmpfs /run/lock -v "$bin:/programs:ro" -v "$repo/deploy/systemd:/deploy:ro" "$image" > /dev/null
docker run -d --name "$b" --hostname b --network "$net" --network-alias web.example.test --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$bin:/programs:ro" "$image" sleep infinity > /dev/null
ip_a=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$a")
ip_b=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$b")
echo "base=$base variant=$variant a=$ip_a b=$ip_b" > "$out/environment.txt"

check "systemd is running in a and systemd-resolved is active" 'ina systemctl is-system-running; ina systemctl status systemd-resolved' \
    wait_for 60 bash -c "docker exec $a systemctl is-active -q systemd-resolved"
ina systemctl --version | head -1 >> "$out/environment.txt"
ina sh -c 'nft --version; ip -V; iptables --version' >> "$out/environment.txt" 2>&1
ina resolvectl log-level debug
# systemd-resolved 报 active 时系统总线可能还没起来，那时 resolvectl 连不上：等它答得出来再记"之前"的样子。
wait_for 30 bash -c "docker exec $a resolvectl status > /dev/null 2>&1"
save resolvectl-before.txt "$a" resolvectl status
save resolv-conf.txt "$a" sh -c 'cat /etc/resolv.conf; grep hosts /etc/nsswitch.conf'

# controller 的数据库：镜像里装着的 PostgreSQL，systemd 已经把它起来了。给 controller 建一个用户和一个库。
check "postgresql is running in a" 'ina systemctl status "postgresql*" --no-pager' \
    wait_for 60 bash -c "docker exec $a runuser -u postgres -- pg_isready -q"
ina runuser -u postgres -- psql -q -v ON_ERROR_STOP=1 -c "CREATE ROLE i3t LOGIN PASSWORD 'i3t'" -c "CREATE DATABASE i3t OWNER i3t" \
    > "$out/postgres-setup.txt" 2>&1

# controller 和节点
ina sh -c "I3T_LANG=en I3T_DATABASE_URL=postgres://i3t:i3t@127.0.0.1/i3t \
    setsid /programs/i3t-controller --data-dir /srv/controller --public-addr $ip_a:20331 --listen 0.0.0.0:20331 \
    > /srv/controller.out 2> /srv/controller.log < /dev/null &"
check "controller starts in a" 'ina tail -5 /srv/controller.log' wait_for 30 bash -c "docker exec $a grep -q 'controller 已启动' /srv/controller.log"
token=$(ina sed -n 's/^    \([A-Za-z0-9_-]\{20,\}\)$/\1/p' /srv/controller.out | head -1)
ctl() { ina env I3T_LANG=en /programs/i3tctl --token "$token" "$@"; }
ctl network create lab --cidr 10.66.0.0/16 > "$out/network-create.txt" 2>&1
enroll() { ctl --json token create | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["token"])'; }

if [ "$variant" = service-polkit ]; then
    docker exec -i "$a" sh -c 'cat > /etc/polkit-1/rules.d/50-i3t-resolved.rules' < "$repo/deploy/polkit/50-i3t-resolved.rules"
fi
if [ "$variant" != root ]; then
    state=/var/lib/i3t
    ina sh -c 'useradd --system --home-dir /var/lib/i3t --shell /usr/sbin/nologin i3t && install -d -o i3t -g i3t -m 0700 /var/lib/i3t /var/lib/i3t/bin \
        && install -o i3t -g i3t -m 0755 /programs/i3t /var/lib/i3t/bin/i3t \
        && install -D -m 0644 /deploy/i3t.service /etc/systemd/system/i3t.service'
    nodea() { docker exec -i "$a" runuser -u i3t -- env I3T_LANG=en I3T_STATE_DIR=$state /var/lib/i3t/bin/i3t "$@"; }
else
    state=/srv/node-a
    nodea() { docker exec -i "$a" env I3T_LANG=en /programs/i3t --state-dir $state "$@"; }
fi
nodeb() { docker exec -i "$b" env I3T_LANG=en /programs/i3t --state-dir /srv/node-b "$@"; }
join() { enroll | "$1" join > "$out/join-$2.txt" 2>&1; }
check "node a joins" 'cat "$out/join-a.txt"' join nodea a
check "node b joins" 'cat "$out/join-b.txt"' join nodeb b
network_switch() { nodea set network "$1" > "$out/set-network-$1.txt" 2>&1; }

start_a() {
    if [ "$variant" != root ]; then ina systemctl daemon-reload && ina systemctl start i3t
    else ina sh -c "I3T_LANG=en setsid /programs/i3t --state-dir $state run > /srv/node-a.log 2>&1 < /dev/null &"; fi
}
log_a() { if [ "$variant" != root ]; then ina journalctl -u i3t --no-pager -o cat; else ina cat /srv/node-a.log; fi; }
stop_a() {
    if [ "$variant" != root ]; then ina systemctl stop i3t
    else ina pkill -INT -f "i3t --state-dir $state run"; wait_for 15 bash -c "! docker exec $a pgrep -f 'i3t --state-dir $state run' > /dev/null"; fi
}
inb sh -c "python3 -I -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (\"b sees %s\" % self.client_address[0]).encode()
        self.send_response(200); self.send_header(\"Content-Length\", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer((\"0.0.0.0\", 8080), H).serve_forever()
' > /dev/null 2>&1 < /dev/null &"
inb sh -c "I3T_LANG=en setsid /programs/i3t --state-dir /srv/node-b run > /srv/node-b.log 2>&1 < /dev/null &"
start_a
online() { [ "$(ctl --json node list 2>/dev/null | python3 -I -c 'import json,sys; print(sum(1 for n in json.load(sys.stdin) if n["online"]))')" = 2 ]; }
check "both nodes online" 'ctl node list' wait_for 60 online
vnet_installed() { log_a | grep -q '虚拟网卡装好了'; }
check "node a: the virtual adapter is installed" 'log_a | tail -5' wait_for 30 vnet_installed
ctl node list > "$out/node-list.txt" 2>&1
name_b=$(ctl --json node list | python3 -I -c 'import json,sys; print(next(n["fqdn"] for n in json.load(sys.stdin) if n["virtual_ip"] == "10.66.0.2"))')
vip_b=10.66.0.2
echo "peer name: $name_b" >> "$out/environment.txt"

# 装着时
nodea network status > "$out/network-status-on.txt" 2>&1
nodea status > "$out/status-a-on.txt" 2>&1
sleep 11 # 节点每 10 秒报一次状态
ctl --json node show 1 > "$out/node-show-a.json" 2>&1
check "controller sees names served through systemd-resolved" 'cat "$out/node-show-a.json" | head -c 600' \
    bash -c "python3 -I -c 'import json,sys; n=json.load(open(sys.argv[1])); print(n.get(\"vnet\")); sys.exit(0 if (n.get(\"vnet\") or {}).get(\"names\", {}).get(\"state\") == \"resolved\" else 1)' '$out/node-show-a.json' > '$out/node-show-a-vnet.txt'"
save resolvectl-on.txt "$a" resolvectl status
save resolvectl-on-link.txt "$a" resolvectl status i3t0
check "resolvectl status i3t0: DNS server is a's virtual IP, routing domain ~lab.i3t, not a default route" 'cat "$out/resolvectl-on-link.txt"' \
    bash -c "grep -q 'DNS Servers: 10.66.0.1' '$out/resolvectl-on-link.txt' && grep -q 'DNS Domain: ~lab.i3t' '$out/resolvectl-on-link.txt' \
        && grep -qE 'Default Route: no|-DefaultRoute' '$out/resolvectl-on-link.txt'"
save resolvectl-query-peer.txt "$a" resolvectl query "$name_b"
check "resolvectl query $name_b gives $vip_b" 'cat "$out/resolvectl-query-peer.txt"' grep -q "$name_b: $vip_b" "$out/resolvectl-query-peer.txt"
check "  ... answered on link i3t0" 'cat "$out/resolvectl-query-peer.txt"' grep -q "link: i3t0" "$out/resolvectl-query-peer.txt"
save getent-peer.txt "$a" getent hosts "$name_b"
check "getent hosts $name_b (nss-resolve) gives $vip_b" 'cat "$out/getent-peer.txt"' grep -q "^$vip_b " "$out/getent-peer.txt"
save curl-peer-name.txt "$a" env -u http_proxy -u https_proxy -u all_proxy curl -sS --noproxy '*' --max-time 10 "http://$name_b:8080/"
check "curl http://$name_b:8080/ with no proxy reaches the server on b, which sees a's virtual IP" 'cat "$out/curl-peer-name.txt"' \
    grep -q '^b sees 10.66.0.1$' "$out/curl-peer-name.txt"
save resolvectl-query-other.txt "$a" resolvectl query web.example.test
check "a name outside the domain (web.example.test) still resolves through the container's resolver" 'cat "$out/resolvectl-query-other.txt"' \
    grep -q "web.example.test: $ip_b" "$out/resolvectl-query-other.txt"
save curl-other.txt "$a" curl -sS --max-time 10 http://web.example.test:8080/
check "curl http://web.example.test:8080/ goes the normal way (b sees a's container address)" 'cat "$out/curl-other.txt"' \
    grep -q "^b sees $ip_a$" "$out/curl-other.txt"
save resolvectl-query-unknown.txt "$a" resolvectl query nobody.lab.i3t
check "an unknown name in the domain is NXDOMAIN from the node" 'cat "$out/resolvectl-query-unknown.txt"' \
    grep -qiE 'not found|NXDOMAIN|does not exist' "$out/resolvectl-query-unknown.txt"

# 关掉：停下节点（拆掉 i3t0，systemd-resolved 跟着忘掉它上面的设置），关上开关，再启动
stop_a
check "i3t set network off (node stopped)" 'cat "$out/set-network-off.txt"' network_switch off
save resolvectl-after-stop.txt "$a" resolvectl status
start_a
a_running() { nodea status 2>&1 | grep -q 'Running i3t'; }
check "node a runs again with the virtual adapter off" 'log_a | tail -3' wait_for 30 a_running
sleep 2
nodea network status > "$out/network-status-off.txt" 2>&1
save resolvectl-off.txt "$a" resolvectl status
check "resolvectl status after switching off is the same as before" 'diff "$out/resolvectl-before.txt" "$out/resolvectl-off.txt"' \
    diff -q "$out/resolvectl-before.txt" "$out/resolvectl-off.txt"
save resolvectl-query-peer-off.txt "$a" resolvectl query "$name_b"
check "resolvectl query $name_b no longer answers" 'cat "$out/resolvectl-query-peer-off.txt"' \
    bash -c "! grep -q '$vip_b' '$out/resolvectl-query-peer-off.txt'"
check "no i3t0 link left" 'ina ip -o link' bash -c "! docker exec $a ip link show i3t0 > /dev/null 2>&1"

log_a > "$out/node-a.log" 2>&1
inb cat /srv/node-b.log > "$out/node-b.log" 2>&1
ina cat /srv/controller.log > "$out/controller.log" 2>&1
ina journalctl -u systemd-resolved --no-pager -o short-precise > "$out/journal-resolved.txt" 2>&1
grep -E 'i3t0|SetLink|Revert|Bus|bus|polkit|denied|Access' "$out/journal-resolved.txt" > "$out/journal-resolved-i3t0.txt"
passed=$(grep -c '^PASS' "$summary")
failed=$(grep -c '^FAIL' "$summary")
echo "== $base $variant: $passed passed, $failed failed" | tee -a "$summary"
[ "$failed" = 0 ]
