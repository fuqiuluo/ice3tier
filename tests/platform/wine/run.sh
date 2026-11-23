#!/usr/bin/env bash
# 在 Docker 容器里跑 smoke.sh：Windows 版的程序在 Wine 里跑，或者 Linux 版的程序直接跑（对照）。
#
#   tests/platform/wine/run.sh wine   <有 i3t.exe 等的目录> <结果目录>
#   tests/platform/wine/run.sh native <有 i3t 等的目录>     <结果目录>
#
# Windows 版这样编（controller 要带上 WebUI 的话先在 web/ 里构建）：
#   cargo zigbuild --profile dist --locked --target x86_64-pc-windows-gnu -p i3t -p i3t-controller-bin -p i3tctl
# 容器接在一个 --internal 的 Docker 网络上：有一块真的网卡（eth0），但是不通外面，controller 启动时查不到发布源，
# 别的流量也出不去。I3T_WINE_NET=none 时不给网卡（--network none），smoke.sh 自己建一块 dummy 网卡当局域网。
set -euo pipefail

mode=${1:?用法：run.sh wine|native <程序目录> <结果目录>}
bin=$(realpath "${2:?缺程序目录}")
out=$(realpath -m "${3:?缺结果目录}")
here=$(dirname "$(realpath "$0")")
repo=$(realpath "$here/../../..")
image=${I3T_WINE_IMAGE:-i3t-platform-wine}

docker build -q -t "$image" "$here" > /dev/null
mkdir -p "$out"
net=${I3T_WINE_NET:-internal}
if [ "$net" = internal ]; then
    net=i3t-platform-wine-$$
    docker network create --internal "$net" > /dev/null
    trap 'docker network rm "$net" > /dev/null' EXIT
fi
status=0
# 容器里是 root：写出来的结果最后改回调用者的。
docker run --rm --network "$net" --cap-add NET_ADMIN \
    -v "$bin:/programs:ro" -v "$here/smoke.sh:/smoke.sh:ro" -v "$repo/scripts/test-postgres.sh:/test-postgres.sh:ro" -v "$out:/out" \
    "$image" bash -c "bash /smoke.sh $mode /programs /out; code=\$?; chown -R $(id -u):$(id -g) /out; exit \$code" || status=$?
exit $status
