#!/usr/bin/env bash
# 构建能在较旧的 Linux 发行版上运行的可执行文件（要求 glibc 2.28 及以上，约等于 2018 年之后的系统）。
#
# 需要先安装 zig 与 cargo-zigbuild。发布使用的版本与摘要见 scripts/zigbuild-requirements.txt：
#   pip install --require-hashes --only-binary=:all: --no-deps -r scripts/zigbuild-requirements.txt
#
#   scripts/build-linux.sh [x86_64|aarch64]
#
# 产物在 target/dist/<目标>/dist/ 下：i3t、i3t-controller、i3tctl。用的是发布档位 `dist`（见根目录的 Cargo.toml）。
set -euo pipefail

arch=${1:-x86_64}
case $arch in
    x86_64 | aarch64) ;;
    *) echo "不支持的架构：$arch（可以写 x86_64 或 aarch64）" >&2; exit 1 ;;
esac

command -v cargo-zigbuild >/dev/null || { echo "未找到 cargo-zigbuild。安装命令：pip install --require-hashes --only-binary=:all: --no-deps -r scripts/zigbuild-requirements.txt" >&2; exit 1; }

cd "$(dirname "$0")/.."
target="$arch-unknown-linux-gnu"
rustup target add "$target" >/dev/null
CARGO_TARGET_DIR=target/dist cargo zigbuild --profile dist --locked --target "$target.2.28" -p i3t -p i3t-controller-bin -p i3tctl
ls -l "target/dist/$target/dist/"{i3t,i3t-controller,i3tctl}
