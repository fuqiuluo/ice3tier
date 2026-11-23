#!/bin/sh
# 照 deploy/docker/compose.yaml 把 controller 和它的 PostgreSQL 起来，把部署文档里写的几件事真的做一遍：
# 第一次启动打出管理令牌，管理 API 和 i3tctl 能用，数据库重启之后 controller 自己连回去，重新生成管理令牌，
# 备份（pg_dump 加密钥），在一套全新的卷上恢复。最后把容器和卷都删掉。
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

step "the address is required"
if I3T_PUBLIC_ADDR='' compose config --quiet 2>"$work/config.err"; then
    fail "compose accepted an empty I3T_PUBLIC_ADDR"
fi
grep -q I3T_PUBLIC_ADDR "$work/config.err" || fail "the refusal does not name I3T_PUBLIC_ADDR: $(cat "$work/config.err")"

step "up: the database first, then the controller"
compose up --detach
wait_for "the controller printed no admin token" test -n "$(first_token)"
token=$(first_token)
wait_for "the admin API did not answer inside the container" ctl status

step "the admin API is published on this machine's loopback, and serves the WebUI"
answer=$(curl -fsS --max-time 10 -H "Authorization: Bearer $token" "http://$admin/api/v1/status") || fail "no answer on $admin"
printf '%s' "$answer" | grep -q '"public_addr":"127.0.0.1:20331"' || fail "unexpected status: $answer"
curl -fsS --max-time 10 "http://$admin/" | grep -q '<div id="root">' || fail "the image has no WebUI in it"
key=$(printf '%s' "$answer" | sed -n 's/.*"controller_key":"\([^"]*\)".*/\1/p')
ctl network create home >/dev/null

step "the database restarts under the controller"
compose restart postgres
wait_for "the controller did not come back after the database restarted" has_home

step "a new admin token"
compose stop controller
token=$(compose run --rm -T controller --reset-admin-token 2>/dev/null | sed -n 's/^    \([A-Za-z0-9_-]\{43\}\)$/\1/p')
[ -n "$token" ] || fail "--reset-admin-token printed no token"
compose start controller
wait_for "the new admin token does not work" ctl status

step "back up: the database and the key"
compose exec -T postgres pg_dump --username i3t --format custom i3t > "$work/controller.dump"
compose exec -T controller cat /data/controller.key > "$work/controller.key"
[ -s "$work/controller.dump" ] && [ -s "$work/controller.key" ] || fail "the backup is empty"

step "restore on new volumes"
compose down --volumes --timeout 5
compose up --detach --wait postgres
compose exec -T postgres pg_restore --username i3t --dbname i3t --no-owner < "$work/controller.dump"
compose run --rm -T --entrypoint sh controller -c 'umask 077; cat > /data/controller.key' < "$work/controller.key"
compose up --detach
wait_for "the restored controller does not answer with the token from the backup" ctl status
[ -z "$(first_token)" ] || fail "the restored controller issued a new admin token: it started as a new controller"
restored=$(ctl --json status)
printf '%s' "$restored" | grep -q "\"controller_key\": \"$key\"" || fail "the restored controller has another key: $restored"
has_home || fail "the network is not in the restored controller"

step "ok"
