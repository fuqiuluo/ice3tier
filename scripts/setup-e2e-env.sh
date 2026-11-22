#!/bin/sh
# 在 Linux CI runner（如 ubuntu-latest）上准备 tests/e2e/ 所需的网络命名空间环境：
# 安装缺少的网络工具、预加载内核模块（用户命名空间内无法按需自动加载模块）、放宽 Ubuntu 24.04 对非特权
# user namespace 的 AppArmor 限制，并跑一遍 check_lab.py 确认实验环境本身正常。
#
# 用法：scripts/setup-e2e-env.sh
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)

need_pkg=""
check_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        need_pkg="$need_pkg $2"
    fi
}

check_tool nft nftables
check_tool iptables iptables
check_tool dnsmasq dnsmasq-base
check_tool dig bind9-dnsutils
check_tool ethtool ethtool

apt_updated=0
apt_install() {
    if [ "$apt_updated" -eq 0 ]; then
        sudo apt-get update -qq
        apt_updated=1
    fi
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@"
}

if [ -n "$need_pkg" ]; then
    echo "==> installing e2e tools:$need_pkg"
    # shellcheck disable=SC2086
    apt_install $need_pkg
fi

# tc netem 在部分云内核（如 Azure）里拆在 linux-modules-extra 中，按需补装。
if ! sudo modprobe sch_netem 2>/dev/null; then
    echo "==> installing linux-modules-extra-$(uname -r) for sch_netem"
    apt_install "linux-modules-extra-$(uname -r)" || true
    sudo modprobe sch_netem
fi

# tests/e2e/lab.py 通过 unshare -Urnm 进入独立命名空间，在其中内核不会自动 modprobe，
# 所以先在宿主机命名空间把 NAT、防火墙和 TUN 需要的模块加载进来。
for mod in \
    tun bridge veth \
    nf_tables nft_ct nft_nat nft_chain_nat nft_masq nft_compat nf_conntrack \
    ip_tables iptable_filter iptable_raw xt_conntrack xt_comment xt_state; do
    sudo modprobe "$mod" 2>/dev/null || true
done

if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
    sudo sysctl -qw kernel.apparmor_restrict_unprivileged_userns=0
fi

echo "==> verifying e2e lab environment"
python3 "$repo/tests/e2e/check_lab.py"
