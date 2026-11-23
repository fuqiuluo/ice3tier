#!/bin/sh
# 测试用的 PostgreSQL：controller 的测试都要一个真的数据库，连接串放在环境变量 I3T_TEST_DATABASE_URL 里。
#
#   scripts/test-postgres.sh start            起一个用完就扔的服务器，打印 I3T_TEST_DATABASE_URL=… 这样的两行
#   scripts/test-postgres.sh stop             停掉它，删掉它的数据
#   scripts/test-postgres.sh database NAME    在 I3T_TEST_DATABASE_URL 说的服务器上新建一个空库，打印连到它的连接串
#
# 本机上：
#   export $(scripts/test-postgres.sh start)
#   cargo test --workspace
# CI 里：
#   scripts/test-postgres.sh start >> "$GITHUB_ENV"
#
# 服务器谁连都不用密码，只听本机，不落盘（fsync 关着）。数据放在 I3T_TEST_POSTGRES_DIR 里，
# 默认是临时目录下的 i3t-test-postgres。它同时听两处，打印出来的两个连接串各指一处：
#   I3T_TEST_DATABASE_URL      Unix 上是数据目录旁边的套接字（网络命名空间里的测试也连得上），Windows 上是下面那个端口
#   I3T_TEST_DATABASE_TCP_URL  127.0.0.1 上的端口 I3T_TEST_POSTGRES_PORT（默认 54329）
#
# 用系统里装着的 PostgreSQL（initdb 和 pg_ctl）；找不到又有 docker 时用 postgres 的官方镜像。
set -eu

DIR=${I3T_TEST_POSTGRES_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/i3t-test-postgres}
PORT=${I3T_TEST_POSTGRES_PORT:-54329}
CONTAINER=i3t-test-postgres
IMAGE=${I3T_TEST_POSTGRES_IMAGE:-postgres:17}
# 测试一个接一个地建库、删库，不在乎断电：不等落盘，快得多。
SETTINGS="-c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=300"

die() {
    echo "test-postgres.sh: $*" >&2
    exit 1
}

windows() {
    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*) return 0 ;;
        *) return 1 ;;
    esac
}

# PostgreSQL 的程序在哪个目录。发行版多半不把 initdb、pg_ctl 放进 PATH，几个常见的位置都看一遍，版本高的优先。
bin_dir() {
    found=""
    for candidate in \
        /usr/local/opt/postgresql@*/bin /opt/homebrew/opt/postgresql@*/bin \
        /usr/pgsql-*/bin /usr/lib/postgresql/*/bin \
        "$(pg_config --bindir 2>/dev/null || true)" \
        "$(dirname "$(command -v pg_ctl 2>/dev/null || echo /nonexistent/pg_ctl)")" \
        "${PGBIN:-}"; do
        if [ -n "$candidate" ] && { [ -x "$candidate/initdb" ] || [ -x "$candidate/initdb.exe" ]; }; then
            found=$candidate
        fi
    done
    [ -n "$found" ] && printf '%s\n' "$found"
}

# PostgreSQL 不肯以 root 运行（容器里常是 root）：那时换成 postgres 用户来执行。
as_server_user() {
    if [ "$(id -u)" = 0 ]; then
        su -s /bin/sh postgres -c "$1"
    else
        sh -c "$1"
    fi
}

# 删掉数据目录。用 docker 起过的话，里面的套接字归容器里的 postgres 用户，目录也被它改成了只有属主能删：
# 自己删不掉时借一个容器来删。
remove_dir() {
    if rm -rf "$DIR" 2>/dev/null; then
        return 0
    fi
    if command -v docker >/dev/null 2>&1; then
        docker run --rm -v "$(dirname "$DIR"):/parent" --entrypoint rm "$IMAGE" -rf "/parent/$(basename "$DIR")" >/dev/null 2>&1 || true
    fi
    [ ! -e "$DIR" ] || die "删不掉 $DIR"
}

# 套接字所在的目录写进连接串时，斜杠要写成 %2F。
socket_host() {
    printf '%s' "$DIR" | sed 's|/|%2F|g'
}

print_urls() {
    tcp="postgres://postgres@127.0.0.1:${PORT}/postgres"
    if windows; then
        echo "I3T_TEST_DATABASE_URL=$tcp"
    else
        echo "I3T_TEST_DATABASE_URL=postgres://postgres@$(socket_host):${PORT}/postgres"
    fi
    echo "I3T_TEST_DATABASE_TCP_URL=$tcp"
}

start_native() {
    bin=$1
    data="$DIR/data"
    if [ -f "$data/PG_VERSION" ] && as_server_user "'$bin/pg_ctl' -D '$data' status" >/dev/null 2>&1; then
        return 0
    fi
    remove_dir
    mkdir -p "$DIR"
    if [ "$(id -u)" = 0 ]; then
        id postgres >/dev/null 2>&1 || die "以 root 运行时要有 postgres 这个用户"
        chown postgres "$DIR"
    fi
    if windows; then
        listen="-c listen_addresses=127.0.0.1"
    else
        listen="-c listen_addresses=127.0.0.1 -c unix_socket_directories='$DIR'"
    fi
    as_server_user "'$bin/initdb' -D '$data' -U postgres -A trust -E UTF8 --no-locale --no-sync" >"$DIR/initdb.log" 2>&1 \
        || die "initdb 失败：$(cat "$DIR/initdb.log")"
    as_server_user "'$bin/pg_ctl' -D '$data' -l '$DIR/server.log' -o \"-p $PORT $listen $SETTINGS\" -w start" >"$DIR/start.log" 2>&1 \
        || die "服务器没起来：$(cat "$DIR/start.log" "$DIR/server.log" 2>/dev/null)"
}

start_docker() {
    # 已经起着、套接字也在这个目录里的话就用它；目录对不上（上次用的是别的目录）就重新起。
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" = true ] && [ -S "$DIR/.s.PGSQL.$PORT" ]; then
        return 0
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    remove_dir
    mkdir -p "$DIR"
    # 容器里的 postgres 用户要能在这个目录里建套接字。
    chmod 777 "$DIR"
    # shellcheck disable=SC2086
    docker run -d --name "$CONTAINER" --tmpfs /var/lib/postgresql -e POSTGRES_HOST_AUTH_METHOD=trust \
        -p "127.0.0.1:${PORT}:${PORT}" -v "$DIR:/var/run/postgresql" "$IMAGE" -p "$PORT" $SETTINGS >/dev/null \
        || die "docker 起不了 $IMAGE"
    tries=0
    # 镜像第一次启动时先在里面初始化、重启一次：等到端口上真的答话。
    until docker exec "$CONTAINER" psql -U postgres -h 127.0.0.1 -p "$PORT" -qAtc 'select 1' >/dev/null 2>&1; do
        tries=$((tries + 1))
        [ "$tries" -lt 120 ] || die "容器里的服务器没起来：$(docker logs --tail 20 "$CONTAINER" 2>&1)"
        sleep 0.5
    done
}

start() {
    if bin=$(bin_dir); then
        start_native "$bin"
    elif command -v docker >/dev/null 2>&1; then
        start_docker
    else
        die "找不到 PostgreSQL（initdb、pg_ctl），也没有 docker。装一个 PostgreSQL，或者自己起一个服务器、把连接串放进 I3T_TEST_DATABASE_URL"
    fi
    print_urls
}

stop() {
    if bin=$(bin_dir) && [ -f "$DIR/data/PG_VERSION" ]; then
        as_server_user "'$bin/pg_ctl' -D '$DIR/data' -m immediate -w stop" >/dev/null 2>&1 || true
    fi
    if command -v docker >/dev/null 2>&1; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
    remove_dir
}

# 找一个能用的 psql：PATH 里的，PostgreSQL 的程序目录里的，或者容器里的。
run_psql() {
    if command -v psql >/dev/null 2>&1; then
        psql "$@"
    elif bin=$(bin_dir); then
        "$bin/psql" "$@"
    elif [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" = true ]; then
        docker exec "$CONTAINER" psql "$@"
    else
        die "找不到 psql"
    fi
}

database() {
    name=${1:?用法：test-postgres.sh database NAME}
    url=${I3T_TEST_DATABASE_URL:?没有设 I3T_TEST_DATABASE_URL：先 export \$(scripts/test-postgres.sh start)}
    case "$url" in
        postgres://*/* | postgresql://*/*) ;;
        *) die "I3T_TEST_DATABASE_URL 要写成 postgres://用户@主机/库名，不带参数" ;;
    esac
    # 名字后面加上进程号和时刻：同一个服务器上反复跑、几个测试同时跑都不撞。
    fresh="${name}_$$_$(date +%s)"
    run_psql "$url" -q -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$fresh\"" >/dev/null
    printf '%s\n' "${url%/*}/$fresh"
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    database) database "${2:-}" ;;
    *) die "用法：test-postgres.sh start | stop | database NAME" ;;
esac
