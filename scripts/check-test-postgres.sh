#!/bin/sh
# scripts/test-postgres.sh 自己的检查，走的是"只有 docker"的那条路（I3T_TEST_POSTGRES_VIA=docker：不用本机装着的
# PostgreSQL，连 psql 也用容器里的）：start、database、stop 都走得通，目录写成相对路径也行；
# 不是它建的目录它不用、也不删。用自己的容器名和端口，不碰正在用的测试服务器。
#
#   scripts/check-test-postgres.sh
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
script="$repo/scripts/test-postgres.sh"
work=$(mktemp -d)
export I3T_TEST_POSTGRES_VIA=docker
export I3T_TEST_POSTGRES_CONTAINER=i3t-test-postgres-check
export I3T_TEST_POSTGRES_PORT=${I3T_TEST_POSTGRES_PORT:-54331}

step() {
    printf '\n=== %s\n' "$*"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

finish() {
    status=$?
    docker rm -f "$I3T_TEST_POSTGRES_CONTAINER" >/dev/null 2>&1 || true
    # 容器里的用户建的套接字自己删不掉：留给脚本的 stop；到这里还在的话借容器删。
    rm -rf "$work" 2>/dev/null || docker run --rm -v "$(dirname "$work"):/parent" --entrypoint rm \
        "${I3T_TEST_POSTGRES_IMAGE:-postgres:17}" -rf "/parent/$(basename "$work")" >/dev/null 2>&1 || true
    exit "$status"
}
trap finish EXIT

in_container() {
    docker exec "$I3T_TEST_POSTGRES_CONTAINER" psql -U postgres -h 127.0.0.1 -p "$I3T_TEST_POSTGRES_PORT" -d postgres -Atc "$1"
}

step "start, with the directory given as a relative path"
cd "$work"
export I3T_TEST_POSTGRES_DIR=pg
started=$(sh "$script" start)
printf '%s\n' "$started"
url=$(printf '%s\n' "$started" | sed -n 's/^I3T_TEST_DATABASE_URL=//p')
tcp=$(printf '%s\n' "$started" | sed -n 's/^I3T_TEST_DATABASE_TCP_URL=//p')
[ -n "$url" ] && [ -n "$tcp" ] || fail "start did not print both connection strings"
case "$url" in
    *"$(printf '%s' "$work/pg" | sed 's|/|%2F|g')"*) ;;
    *) fail "the socket URL does not carry the absolute directory: $url" ;;
esac
[ -S "$work/pg/.s.PGSQL.$I3T_TEST_POSTGRES_PORT" ] || fail "no socket in $work/pg"
[ "$(sh "$script" start)" = "$started" ] || fail "a second start printed something else"

step "database: created through the container, the URL is the host's"
for server in "$url" "$tcp"; do
    made=$(I3T_TEST_DATABASE_URL=$server sh "$script" database probe) || fail "database failed against $server"
    case "$made" in
        "${server%/*}"/probe_*) ;;
        *) fail "unexpected connection string: $made" ;;
    esac
    [ "$(in_container "select count(*) from pg_database where datname = '${made##*/}'")" = 1 ] || fail "${made##*/} was not created"
done

step "stop removes the directory it made"
sh "$script" stop
[ ! -e "$work/pg" ] || fail "$work/pg is still there"
[ -z "$(docker ps -aq --filter "name=^${I3T_TEST_POSTGRES_CONTAINER}\$")" ] || fail "the container is still there"

step "a directory with something in it is neither used nor deleted"
mkdir "$work/precious"
echo keep > "$work/precious/file"
export I3T_TEST_POSTGRES_DIR="$work/precious"
if sh "$script" start >"$work/start.out" 2>&1; then
    fail "start used a directory that is not its own"
fi
if sh "$script" stop >"$work/stop.out" 2>&1; then
    fail "stop accepted a directory that is not its own"
fi
[ "$(cat "$work/precious/file")" = keep ] || fail "the directory was touched"

step "ok"
