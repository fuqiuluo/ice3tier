#!/usr/bin/env bash
# 在一个容器里把三个程序走一遍：版本和帮助、controller（数据库是容器里起的一个 PostgreSQL）、建网络和注册令牌、
# 两个节点加入并上线、一个当出口、
# 另一个上经它出去的代理（SOCKS5、HTTP CONNECT、明文 HTTP 转发），状态命令，正常停下，再在同样的目录上启动一次。
#
#   smoke.sh wine   <有 i3t.exe、i3t-controller.exe、i3tctl.exe 的目录> <结果目录>
#   smoke.sh native <有 i3t、i3t-controller、i3tctl 的目录>             <结果目录>
#
# native 是对照：同一个脚本跑 Linux 版，两边的差别才算 Windows（Wine）上的问题。由 run.sh 在容器里调用；
# 出口的"局域网"是容器的 eth0（run.sh 把容器接在一个不通外面的 Docker 网络上）；没有 eth0 时（--network none）
# 脚本自己建一块 dummy 网卡（要 CAP_NET_ADMIN）。
# 结果目录里：summary.txt（每项 PASS 或 FAIL 和原因），每个程序的输出和日志。
set -u

mode=${1:?用法：smoke.sh wine|native <程序目录> <结果目录>}
bin=${2:?缺程序目录}
out=${3:?缺结果目录}
mkdir -p "$out"
summary=$out/summary.txt
: > "$summary"
: > "$out/curl.txt"
export I3T_LANG=en

HTTP_PORT=18080
PROXY_PORT=11002
CONTROLLER=127.0.0.1:20331
ADMIN=127.0.0.1:20332

case $mode in
    wine)
        exe=.exe
        # Windows 的路径，和它在 Linux 这边对应的地方。
        winpath() { printf 'C:\\i3t\\%s' "$1"; }
        hostpath() { printf '%s/drive_c/i3t/%s' "$WINEPREFIX" "$1"; }
        default_dir=$WINEPREFIX/drive_c/users/$(id -un)/AppData/Local/i3t
        wineboot --init > "$out/wineboot.txt" 2>&1
        ;;
    native)
        exe=
        winpath() { printf '/work/%s' "$1"; }
        hostpath() { winpath "$1"; }
        default_dir=$HOME/.local/state/i3t
        ;;
    *) echo "不认识的方式：$mode" >&2; exit 2 ;;
esac
# Wine 下 wine 一路 exec 到那个 Windows 程序，进程号不变，所以后台启动的进程号就是程序自己的。
run_program() { local name=$1; shift; if [ "$mode" = wine ]; then wine "$bin/$name$exe" "$@"; else "$bin/$name" "$@"; fi; }

record() { # 结果 名字 [原因]
    local line="$1  $2"
    [ -n "${3:-}" ] && line="$line: $(printf '%s' "$3" | tr '\n' ' ' | cut -c1-500)"
    echo "$line" | tee -a "$summary"
}
# check 名字 原因 命令…：命令成功就是 PASS。原因是一段 shell，失败时才执行，它的输出写进 summary。
check() {
    local name=$1 why=$2; shift 2
    if "$@"; then record PASS "$name"; else record FAIL "$name" "$(eval "$why" 2>&1)"; fi
}
# expect 名字 输出文件 正则 命令…：命令的输出写进文件，退出码是 0、输出里有那个正则（空的话不查）就是 PASS。
expect() {
    local name=$1 file=$2 want=$3; shift 3
    "$@" > "$file" 2>&1
    local code=$?
    if [ "$code" = 0 ] && { [ -z "$want" ] || grep -qE "$want" "$file"; }; then record PASS "$name"
    else record FAIL "$name" "exit $code: $(cat "$file")"; fi
}
# 每隔半秒试一次命令，直到成功或者超过秒数。
wait_for() {
    local seconds=$1; shift
    local deadline=$((SECONDS + seconds))
    until "$@"; do
        [ $SECONDS -ge $deadline ] && return 1
        sleep 0.5
    done
}
listening() { ss -lnt | grep -q " $1 "; }
json() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
alive() { kill -0 "$1" 2>/dev/null; }

start_bg() { # 日志名 程序 参数…；`$started` 是程序自己的进程号（子 shell 用 exec 换成它，信号才到得了程序）
    local log=$1 name=$2; shift 2
    if [ "$mode" = wine ]; then (exec wine "$bin/$name$exe" "$@") > "$out/$log.out" 2> "$out/$log.log" &
    else (exec "$bin/$name" "$@") > "$out/$log.out" 2> "$out/$log.log" & fi
    started=$!
}
# Ctrl-C（SIGINT；Wine 把它交给程序的控制台处理函数）停下一个程序，最多等 15 秒。返回它的退出码，没停下是 124。
stop_bg() {
    local pid=$1
    kill -INT "$pid" 2>/dev/null
    local deadline=$((SECONDS + 15))
    while alive "$pid"; do
        if [ $SECONDS -ge $deadline ]; then kill -KILL "$pid"; wait "$pid" 2>/dev/null; return 124; fi
        sleep 0.2
    done
    wait "$pid"
}

echo "mode=$mode kernel=$(uname -r)" > "$out/environment.txt"
[ "$mode" = wine ] && wine --version >> "$out/environment.txt"

# 出口要连的"局域网"上的 HTTP 服务：回答请求的路径和它看到的来源地址。
LAN_IP=$(ip -4 -o addr show dev eth0 2>/dev/null | awk '{print $4}' | head -1)
if [ -n "$LAN_IP" ]; then
    LAN_IP=${LAN_IP%/*}
    echo "lan=eth0 $LAN_IP" >> "$out/environment.txt"
else
    LAN_IP=192.168.77.1
    ip link add lan0 type dummy && ip addr add "$LAN_IP/24" dev lan0 && ip link set lan0 up
    echo "lan=dummy lan0 $LAN_IP" >> "$out/environment.txt"
fi
python3 -I -c '
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("hello from %s via %s" % (self.path, self.client_address[0])).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), H).serve_forever()
' "$LAN_IP" "$HTTP_PORT" &
wait_for 10 listening "$LAN_IP:$HTTP_PORT" || record FAIL "test HTTP server" "did not start"

# 1. 版本和帮助
for program in i3t i3t-controller i3tctl; do
    expect "$program --version" "$out/$program-version.txt" "^$program [0-9]+\.[0-9]+\.[0-9]+" run_program "$program" --version
    expect "$program --help" "$out/$program-help.txt" '^Usage:' run_program "$program" --help
done
expect "i3t key without --state-dir" "$out/default-key.txt" '^[A-Za-z0-9_-]{43}$' run_program i3t key
check "  ... writes the key into the platform's default directory ($default_dir)" 'ls -la "$default_dir"' test -s "$default_dir/node.key"

# controller 的数据库：在容器里起一个测试用的 PostgreSQL，在上面建一个空库。经回环的端口连：Windows 版的程序不认 Unix 套接字。
# 连接串放在环境变量里，Wine 里的程序照样读得到；第 7 步在同一个库上再启动一次。
postgres=$(sh /test-postgres.sh start 2> "$out/postgres.txt" | sed -n 's/^I3T_TEST_DATABASE_TCP_URL=//p')
I3T_DATABASE_URL=$(I3T_TEST_DATABASE_URL=$postgres sh /test-postgres.sh database smoke 2>> "$out/postgres.txt")
export I3T_DATABASE_URL
check "a PostgreSQL for the controller is running" 'cat "$out/postgres.txt"' test -n "$I3T_DATABASE_URL"

ctl() { run_program i3tctl --url "http://$ADMIN" --token "$TOKEN" "$@"; }
start_controller() { # 日志名
    start_bg "$1" i3t-controller --data-dir "$(winpath controller)" --public-addr "$CONTROLLER" --listen "$CONTROLLER" --admin-listen "$ADMIN"
    controller_pid=$started
    wait_for 60 bash -c "grep -q 'controller 已启动' '$out/$1.log' || ! kill -0 $controller_pid 2>/dev/null"
    alive "$controller_pid" && grep -q 'controller 已启动' "$out/$1.log"
}
start_node() { # 名字 第几次启动
    start_bg "node-$1-$2" i3t --state-dir "$(winpath "$1")" run
    eval "pid_$1=$started"
}
online() { [ "$(ctl --json node list 2>/dev/null | json 'sum(1 for n in d if n["online"])')" = 2 ]; }
proxy_listening() { [ "$(ctl --json proxy list 2>/dev/null | json 'd[0]["status"]["code"]')" = listening ]; }
via_proxy() { # 名字 curl 的代理参数…：经代理访问那个 HTTP 服务，回答要对
    local name=$1; shift
    local got
    got=$(curl -sS --max-time 20 "$@" "http://$LAN_IP:$HTTP_PORT/$name" 2>&1)
    echo "$name: $got" >> "$out/curl.txt"
    [ "$got" = "hello from /$name via $LAN_IP" ]
}
proxy_round() { # 第几轮
    check "SOCKS5 through the proxy on node a, out through exit b ($1)" 'tail -1 "$out/curl.txt"' \
        via_proxy "socks5-$1" -x "socks5h://127.0.0.1:$PROXY_PORT"
    check "HTTP CONNECT on the same mixed port ($1)" 'tail -1 "$out/curl.txt"' via_proxy "connect-$1" -p -x "http://127.0.0.1:$PROXY_PORT"
    check "plain HTTP forwarding on the same mixed port ($1)" 'tail -1 "$out/curl.txt"' via_proxy "forward-$1" -x "http://127.0.0.1:$PROXY_PORT"
}
nodes_running() { # 第几轮
    for node in a b; do
        eval "pid=\$pid_$node"
        check "node $node is running ($1)" "tail -3 '$out/node-$node-$2.log'" alive "$pid"
    done
}
stop_all() { # 第几轮 日志的编号
    for node in a b; do
        eval "pid=\$pid_$node"
        stop_bg "$pid"
        code=$?
        check "node $node stops on Ctrl-C with exit code 0 ($1; got $code)" "tail -3 '$out/node-$node-$2.log'" test "$code" = 0
    done
    stop_bg "$controller_pid"
    code=$?
    check "controller stops on Ctrl-C with exit code 0 ($1; got $code)" "tail -3 '$out/controller-$2.log'" \
        bash -c "[ $code = 0 ] && grep -q 'controller 已停止' '$out/controller-$2.log'"
}

# 2. controller，网络，注册令牌
check "controller starts on loopback with a fresh data directory" 'tail -5 "$out/controller-1.log"' start_controller controller-1
TOKEN=$(sed -n 's/^    \([A-Za-z0-9_-]\{20,\}\)$/\1/p' "$out/controller-1.out" | head -1)
check "controller prints an admin token on first start" 'cat "$out/controller-1.out"' test -n "$TOKEN"
check "the WebUI is built in (not the notice page)" 'curl -sS "http://$ADMIN/" | head -c 300' \
    bash -c "curl -sS 'http://$ADMIN/' | grep -q '<div id=\"root\"'"
expect "i3tctl network create lab" "$out/network-create.txt" '' ctl network create lab --cidr 10.66.0.0/16
for node in a b; do
    ctl --json token create > "$out/token-$node.json" 2> "$out/token-$node.err"
    eval "enroll_$node=\$(json 'd[\"token\"]' < '$out/token-$node.json' 2>/dev/null)"
done
check "i3tctl token create (two tokens)" 'cat "$out/token-a.err" "$out/token-b.err"' test -n "$enroll_a" -a -n "$enroll_b"

# 3. 两个节点：各自的状态目录和端口，b 声明可以当出口
for node in a b; do
    mkdir -p "$(hostpath "$node")"
    case $node in a) port=20341 ;; b) port=20351 ;; esac
    printf 'port = %s\n[metrics]\nlisten = "127.0.0.1:%s"\n[log]\nlevel = "debug"\n' "$port" "$((port + 2))" > "$(hostpath "$node")/config.toml"
done
expect "node a joins" "$out/join-a.txt" '' run_program i3t --state-dir "$(winpath a)" join <<< "$enroll_a"
expect "node b joins, declaring it can be an exit" "$out/join-b.txt" '' run_program i3t --state-dir "$(winpath b)" join --can-exit <<< "$enroll_b"
start_node a 1
start_node b 1
check "both nodes come online" 'ctl node list; tail -2 "$out/node-a-1.log"' wait_for 90 online
nodes_running first 1
ids=$(ctl --json node list | json '" ".join(str(n["id"]) for n in sorted(d, key=lambda n: n["id"]))')
id_a=${ids%% *}
id_b=${ids##* }
ctl node rename "$id_a" a > /dev/null 2>&1
ctl node rename "$id_b" b > /dev/null 2>&1

# 4. 出口和代理
expect "i3tctl exit enable b --lan" "$out/exit-enable.txt" '' ctl exit enable b --lan
expect "i3tctl proxy add a 127.0.0.1:$PROXY_PORT b" "$out/proxy-add.txt" '' ctl proxy add a "127.0.0.1:$PROXY_PORT" b
check "the proxy listens on node a" 'ss -lnt' wait_for 60 listening "127.0.0.1:$PROXY_PORT"
proxy_round first

# 5. 状态命令
check "i3tctl proxy list reports the proxy as listening" 'ctl proxy list' wait_for 40 proxy_listening
expect "i3tctl node list: a and b online, b an exit" "$out/node-list.txt" '^2 +b +10\.66\.0\.2 +online +exit' ctl node list
expect "i3tctl proxy list" "$out/proxy-list.txt" "127\.0\.0\.1:$PROXY_PORT +mixed" ctl proxy list
expect "i3tctl exit list" "$out/exit-list.txt" '' ctl exit list
expect "i3t status on a: running, controller connected, the listener" "$out/status-a.txt" "controller +connected" \
    run_program i3t --state-dir "$(winpath a)" status
check "  ... and the route to b" 'cat "$out/status-a.txt"' grep -qE '^ +b +10\.66\.0\.2 +direct' "$out/status-a.txt"
# 虚拟网卡默认打开。Wine 里装不上（Wintun 在 Wine 下不能用，测试里也没有放 wintun.dll），容器里没有 /dev/net/tun：
# 节点照常运行，状态里说为什么没装。
check "  ... and why the virtual adapter isn't installed" 'grep -i "virtual" "$out/status-a.txt"' \
    grep -qE 'Virtual network +not installed: .+' "$out/status-a.txt"
expect "i3t status on b" "$out/status-b.txt" "controller +connected" run_program i3t --state-dir "$(winpath b)" status
expect "i3t routes on a" "$out/routes-a.txt" 'b .*direct' run_program i3t --state-dir "$(winpath a)" routes
expect "i3t ping b from a" "$out/ping-a.txt" '5 back, 0 lost' run_program i3t --state-dir "$(winpath a)" ping b
check "metrics endpoint of node a" 'curl -sS --max-time 5 http://127.0.0.1:20343/metrics | head -3' \
    bash -c "curl -sS --max-time 5 http://127.0.0.1:20343/metrics | grep -q '^i3t_'"
expect "i3t self-check on a" "$out/self-check-a.txt" '' run_program i3t --state-dir "$(winpath a)" self-check

# 6. 正常停下
stop_all first 1
for dir in controller a b; do ls -la "$(hostpath "$dir")" > "$out/files-$dir-after-stop.txt" 2>&1; done
check "node a removed its local.json on stop" 'cat "$out/files-a-after-stop.txt"' test ! -e "$(hostpath a)/local.json"
check "node a's cached netmap (written by replacing the file) is the latest one" 'head -c 300 "$(hostpath a)/netmap.json"' \
    bash -c "python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))[\"version\"] > 1 else 1)' '$(hostpath a)/netmap.json'"
check "both nodes are in the controller's database after a clean stop" 'psql "$I3T_DATABASE_URL" -Atc "select id, name from nodes"' \
    bash -c "[ \"\$(psql '$I3T_DATABASE_URL' -Atc 'select count(*) from nodes')\" = 2 ]"

# 7. 同样的目录上再启动一次
check "controller starts again on the same data directory" 'tail -5 "$out/controller-2.log"' start_controller controller-2
expect "the admin token from the first start still works" "$out/status-controller.txt" '' ctl status
start_node a 2
start_node b 2
check "both nodes come online again" 'ctl node list; tail -2 "$out/node-a-2.log"' wait_for 90 online
nodes_running second 2
check "the proxy listens again" 'ss -lnt' wait_for 60 listening "127.0.0.1:$PROXY_PORT"
proxy_round second
stop_all second 2

for dir in controller a b; do ls -la "$(hostpath "$dir")" > "$out/files-$dir-end.txt" 2>&1; done
[ "$mode" = wine ] && wineserver -k 2>/dev/null
passed=$(grep -c '^PASS' "$summary")
failed=$(grep -c '^FAIL' "$summary")
echo "== $mode: $passed passed, $failed failed" | tee -a "$summary"
[ "$failed" = 0 ]
