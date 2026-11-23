#!/bin/sh
# 照 deploy/docker/compose.yaml 把 controller 和它的 PostgreSQL 起来，把部署文档里写的几件事真的做一遍：
# 第一次启动打出管理令牌，管理 API 和 i3tctl 能用，数据库不听网络，数据库重启之后 controller 自己连回去，
# 重新生成管理令牌，备份（pg_dump 加密钥，两个文件都只有自己可读），在一套全新的卷上恢复；
# 忘了把密钥放回来时 controller 不肯启动。最后把容器和卷都删掉。
#
# 用的是本机已经有的镜像 ghcr.io/fuqiuluo/ice3tier-controller:latest，先建出来：
#   docker build -f deploy/docker/Dockerfile -t ghcr.io/fuqiuluo/ice3tier-controller:latest .
#   scripts/test-compose.sh
#
# 环境变量：
#   I3T_COMPOSE_EXTRA   另一份 compose 文件，叠在上面（换端口、换 PostgreSQL 的镜像）
#   I3T_COMPOSE_ADMIN   宿主机上管理 API 的地址，默认 127.0.0.1:20332
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
project="i3t-compose-test-$$"
work=$(mktemp -d)
admin=${I3T_COMPOSE_ADMIN:-127.0.0.1:20332}
export I3T_PUBLIC_ADDR=127.0.0.1:20331

compose() {
    if [ -n "${I3T_COMPOSE_EXTRA:-}" ]; then
        docker compose -p "$project" -f "$repo/deploy/docker/compose.yaml" -f "$I3T_COMPOSE_EXTRA" "$@"
    else
        docker compose -p "$project" -f "$repo/deploy/docker/compose.yaml" "$@"
    fi
}

# 一条本该马上失败的命令，万一没有失败（那就是在一直运行）也不让它卡住整个脚本：到点把它的容器停掉。
compose_run_briefly() { # 输出写到哪里 run 的参数…
    out=$1
    shift
    compose run --name "$project-brief" -T "$@" >"$out" 2>&1 &
    pid=$!
    i=0
    while kill -0 "$pid" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 60 ]; then
            docker rm -f "$project-brief" >/dev/null 2>&1 || true
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        sleep 1
    done
    code=0
    wait "$pid" || code=$?
    docker rm -f "$project-brief" >/dev/null 2>&1 || true
    return "$code"
}

step() {
    printf '\n=== %s\n' "$*"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

finish() {
    status=$?
    if [ "$status" -ne 0 ]; then
        printf '\n--- failed; the containers say:\n'
        # 令牌只在第一次启动的输出里：别把它留在 CI 的日志里。
        compose logs --tail 60 2>&1 | sed 's/^\(.*|     \)[A-Za-z0-9_-]\{43\}$/\1<admin token>/' || true
    fi
    compose down --volumes --timeout 5 >/dev/null 2>&1 || true
    rm -rf "$work"
    exit "$status"
}
trap finish EXIT

# i3tctl 在 controller 的容器里，连的是容器自己的管理端口。
ctl() {
    compose exec -T controller i3tctl --token "$token" "$@"
}

wait_for() { # 说明 命令…：最多等 60 秒
    what=$1
    shift
    i=0
    until "$@" >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 60 ] || fail "$what"
        sleep 1
    done
}

has_home() {
    ctl --json network list | grep -q '"name": "home"'
}

first_token() {
    compose logs controller 2>/dev/null | sed -n 's/^.*|     \([A-Za-z0-9_-]\{43\}\)$/\1/p' | head -n 1
}

# 每一轮都重新去看日志：写成 `wait_for … test -n "$(first_token)"` 的话，那个 $(…) 在等之前就算完了，
# 令牌晚一点打出来，等多少轮看的都是那一次的空结果。
has_token() {
    [ -n "$(first_token)" ]
}

step "the address is required"
if I3T_PUBLIC_ADDR='' compose config --quiet 2>"$work/config.err"; then
    fail "compose accepted an empty I3T_PUBLIC_ADDR"
fi
grep -q I3T_PUBLIC_ADDR "$work/config.err" || fail "the refusal does not name I3T_PUBLIC_ADDR: $(cat "$work/config.err")"

step "up: the database first, then the controller"
compose up --detach
wait_for "the controller printed no admin token" has_token
token=$(first_token)
wait_for "the admin API did not answer inside the container" ctl status

step "the admin API is published on this machine's loopback, and serves the WebUI"
answer=$(curl -fsS --max-time 10 -H "Authorization: Bearer $token" "http://$admin/api/v1/status") || fail "no answer on $admin"
printf '%s' "$answer" | grep -q '"public_addr":"127.0.0.1:20331"' || fail "unexpected status: $answer"
curl -fsS --max-time 10 "http://$admin/" | grep -q '<div id="root">' || fail "the image has no WebUI in it"
key=$(printf '%s' "$answer" | sed -n 's/.*"controller_key":"\([^"]*\)".*/\1/p')
ctl network create home >/dev/null

step "the database is not on the network: only on the socket the two containers share"
compose exec -T postgres pg_isready --username i3t --dbname i3t >/dev/null || fail "the database does not answer on its socket"
if compose exec -T postgres pg_isready --host 127.0.0.1 --username i3t --dbname i3t >/dev/null 2>&1; then
    fail "the database listens on TCP"
fi

step "the database restarts under the controller"
compose restart postgres
wait_for "the controller did not come back after the database restarted" has_home

step "a new admin token"
compose stop controller
token=$(compose run --rm -T controller --reset-admin-token 2>/dev/null | sed -n 's/^    \([A-Za-z0-9_-]\{43\}\)$/\1/p')
[ -n "$token" ] || fail "--reset-admin-token printed no token"
compose start controller
wait_for "the new admin token does not work" ctl status

step "the health check does not pass on the server the image runs while it sets up an empty volume"
# 那个临时的服务器听的是同一个套接字，pg_isready 分不出来。这里照样起一个不是 1 号进程的服务器，拿 compose 文件里的
# 检查去问它：不能过。不然 `up --wait postgres` 会提前放行，接着的恢复会被临时服务器的退出打断。
health=$(compose config --format json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["services"]["postgres"]["healthcheck"]["test"][1].replace("$$", "$"))')
image=$(compose config --format json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["services"]["postgres"]["image"])')
# shellcheck disable=SC2016
docker run --rm --user postgres --entrypoint sh "$image" -c '
    initdb -D /tmp/data -U i3t >/dev/null 2>&1 || exit 3
    pg_ctl -D /tmp/data -o "-c listen_addresses=" -w start >/dev/null 2>&1 || exit 3
    pg_isready --username i3t --dbname i3t >/dev/null || exit 3
    if sh -c "$1" >/dev/null 2>&1; then exit 4; fi
' sh "$health" || fail "the health check passed on a server that is not the container's main process (or the probe could not run): $health"
compose exec -T postgres sh -c "$health" >/dev/null || fail "the health check does not pass on the real server: $health"
# docker 的守护进程可以设成默认给每个容器加一个 init 当 1 号进程（dockerd --init）。那样正式的服务器也不是 1 号进程，
# 和上面那个一样永远不过：compose 文件里得写明这个服务不要 init。
init=$(compose config --format json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["services"]["postgres"].get("init"))')
[ "$init" = False ] || fail "the postgres service does not say init: false (it says: $init)"

step "back up: the database and the key"
mkdir "$work/backup"
chmod 755 "$work/backup"
# 上一次备份留下的、谁都读得了的两个文件：新的不能沿用它们的权限。
: > "$work/backup/controller.dump"
: > "$work/backup/controller.key"
chmod 644 "$work/backup/controller.dump" "$work/backup/controller.key"
# 文档里的写法：两个文件在 umask 077 下重新写出来，有一步不成就停。转储里有代理的密码，密钥就是 controller 的身份。
(
    cd "$work/backup"
    set -e
    umask 077
    rm -f controller.dump controller.key
    compose exec -T postgres pg_dump --username i3t --format custom i3t > controller.dump
    compose exec -T controller cat /data/controller.key > controller.key
)
[ -s "$work/backup/controller.dump" ] && [ -s "$work/backup/controller.key" ] || fail "the backup is empty"
for file in controller.dump controller.key; do
    mode=$(stat -c '%a' "$work/backup/$file" 2>/dev/null || stat -f '%Lp' "$work/backup/$file")
    [ "$mode" = 600 ] || fail "$file is readable by others (mode $mode)"
done

step "restore on new volumes"
compose down --volumes --timeout 5
compose up --detach --wait postgres
compose exec -T postgres pg_restore --username i3t --dbname i3t --no-owner < "$work/backup/controller.dump"

# 忘了把密钥放回来：controller 不生成新的（节点认的是原来那一把），说缺密钥，不启动。
if compose_run_briefly "$work/no-key.out" controller; then
    fail "the controller started on a restored database without its key"
fi
grep -q 'controller.key' "$work/no-key.out" || fail "the refusal does not name the key: $(cat "$work/no-key.out")"

compose run --rm -T --entrypoint sh controller -c 'umask 077; cat > /data/controller.key' < "$work/backup/controller.key"
compose up --detach
wait_for "the restored controller does not answer with the token from the backup" ctl status
[ -z "$(first_token)" ] || fail "the restored controller issued a new admin token: it started as a new controller"
restored=$(ctl --json status)
printf '%s' "$restored" | grep -q "\"controller_key\": \"$key\"" || fail "the restored controller has another key: $restored"
has_home || fail "the network is not in the restored controller"

step "ok"
