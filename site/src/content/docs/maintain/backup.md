---
title: 备份和恢复
description: 备份 controller 的数据，在原来的或新的服务器上恢复。
---

## 备份

备份不用停 controller：

```sh
sudo /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller \
  --backup-to /root/i3t-controller-backup
```

目标要是一个新的或者空的目录。备份里有全部的网络、节点和设置，以及管理令牌和 controller 的密钥。

:::caution
不要只拷贝 `controller.db`：最近的改动可能还在它旁边的文件里。
:::

## 恢复

在原来的服务器上，或者在一台按 [安装 controller](../../deploy/controller/) 装好的新服务器上：

```sh
sudo systemctl stop i3t-controller
sudo mv /var/lib/i3t-controller /var/lib/i3t-controller.old
sudo cp -a /root/i3t-controller-backup /var/lib/i3t-controller
sudo chown -R i3t-controller: /var/lib/i3t-controller
sudo systemctl start i3t-controller
```

只要公网地址仍然指向 controller，节点会自己连回来。备份之后才加入的节点要用新的令牌重新加入。
