# 在 Wine 里跑 Windows 版的三个程序（smoke.sh）。只有 64 位的 Wine：程序是 x86_64-pc-windows-gnu 的。
# 客户端（curl）和 HTTP 服务（python3）是 Linux 的程序，经回环连 Windows 版节点开的端口。
# controller 的数据库是容器里的 PostgreSQL（Linux 的），Windows 版的 controller 经回环连它。
FROM debian:trixie
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        wine wine64 ca-certificates curl python3 procps iproute2 postgresql \
    && rm -rf /var/lib/apt/lists/*
# 不装 Mono 和 Gecko（没有界面的程序用不着），不弹窗口。
ENV WINEDLLOVERRIDES="mscoree,mshtml=" WINEDEBUG=-all WINEPREFIX=/wine
