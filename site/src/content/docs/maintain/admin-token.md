---
title: 管理令牌丢了
description: 重置管理令牌。
---

在服务器上。用 Docker 装的：

```sh
docker compose stop controller
docker compose run --rm controller --reset-admin-token
docker compose start controller
```

用安装脚本装的：

```sh
sudo systemctl stop i3t-controller
sudo -u i3t-controller /usr/local/bin/i3t-controller \
  --data-dir /var/lib/i3t-controller --reset-admin-token
sudo systemctl start i3t-controller
```

它会打印一个新的令牌，原来的作废。

安装时没有看到管理令牌的话，它还在服务的日志里：

```sh
docker compose logs controller                  # Docker
sudo journalctl -u i3t-controller --no-pager    # 安装脚本
```
