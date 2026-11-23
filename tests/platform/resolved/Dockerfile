# 虚拟网卡的名字经真的 systemd-resolved 走（run.sh）。容器 a 以 systemd 为 1 号进程、开着 systemd-resolved；
# 容器 b 用同一个镜像，只跑一个节点和一个 HTTP 服务，不起 systemd。装着 polkit：systemd-resolved 按它决定一个不是 root 的
# 进程能不能改一块网卡的 DNS（run.sh 的 service、service-polkit 两种方式看的就是这个）。
# 还装着 PostgreSQL：controller 的数据库。装的时候建好了一个集群，容器 a 的 systemd 把它起来。
#
# 名字解析：Docker 把它自己的 /etc/resolv.conf（127.0.0.11）挂进容器，所以程序经 nss-resolve（libnss-resolve 在
# /etc/nsswitch.conf 的 hosts 一行里加上 resolve）问 systemd-resolved；systemd-resolved 读到那个 resolv.conf，
# 把 127.0.0.11 当成别的名字的服务器。这和装了 nss-resolve 的桌面发行版走的是同一条路。
ARG BASE=debian:trixie
FROM ${BASE}
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv systemd-resolved libnss-resolve dbus polkitd nftables iptables iproute2 \
        curl python3 procps bind9-dnsutils ca-certificates postgresql \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl enable systemd-resolved
# 容器里用不着、起不来或者会去改网络的单元。
RUN systemctl mask getty.target console-getty.service systemd-firstboot.service systemd-networkd.service \
        systemd-networkd.socket systemd-networkd-wait-online.service systemd-timesyncd.service
ENV container=docker
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
