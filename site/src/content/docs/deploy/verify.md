---
title: 检查
description: 确认节点连上了 controller，节点之间互相能通。
---

在任意一个节点上：

```sh
sudo i3t status              # controller 已连接，以及到每个节点的路由
sudo i3t ping <节点>         # 到另一个节点的往返
ping <虚拟 IP>               # 经虚拟网卡
ssh <节点>.<网络>.i3t        # 按名字，比如 nas.home.i3t
```

## 名字

有 `systemd-resolved` 的 Linux 上名字直接能用。别的机器上把名字写进 hosts 文件，或者直接用虚拟 IP：

```sh
sudo i3t hosts --apply
```

## 之后

之后的事都在 Web 界面或 `i3tctl` 里做：出口和代理、端口转发、分组和访问规则。

哪里不对的话，见 [常见问题](../../reference/troubleshooting/)。
