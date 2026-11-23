---
title: 备份和恢复
description: 备份 controller 的数据，在原来的或新的服务器上恢复。
---

## 备份

备份是两个文件：数据库的转储，和 controller 的密钥 `controller.key`。备份不用停 controller。

用 Docker 装的：

```sh
docker compose exec -T postgres pg_dump --username i3t --format custom i3t > controller.dump
docker compose exec -T controller cat /data/controller.key > controller.key
chmod 600 controller.key
```

用安装脚本装的：

```sh
sudo sh -c 'pg_dump --format custom --file controller.dump "$(cat /var/lib/i3t-controller/database.url)"'
sudo cp /var/lib/i3t-controller/controller.key controller.key
```

转储里有全部的网络、节点和设置，以及管理令牌。

:::caution
两个文件缺一不可：节点认的是这把密钥，数据库里记着在它名下加入的节点。
:::

## 恢复

恢复在一台新的服务器上做，公网地址和原来的一样。

用 Docker 的话：

```sh
curl -fsSLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/docker/compose.yaml
echo 'I3T_PUBLIC_ADDR=<公网地址>:20331' > .env
docker compose up -d --wait postgres
docker compose exec -T postgres pg_restore --username i3t --dbname i3t --no-owner < controller.dump
docker compose run --rm -T --entrypoint sh controller -c 'umask 077; cat > /data/controller.key' < controller.key
docker compose up -d
```

在原来的服务器上恢复的话，前两行换成 `docker compose down --volumes`：它会删掉现有的数据库和密钥。

用安装脚本的话，先按 [安装 controller](../../deploy/controller/) 建一个空的数据库，然后：

```sh
pg_restore --no-owner --dbname postgres://i3t:<密码>@127.0.0.1/i3t controller.dump
# 先装上但不启动，把密钥放好，再启动
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh |
  sh -s -- --controller --database-url postgres://i3t:<密码>@127.0.0.1/i3t
sudo install -o i3t-controller -g i3t-controller -m 600 controller.key \
  /var/lib/i3t-controller/controller.key
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh |
  sh -s -- --controller --public-addr <公网地址>:20331
```

在原来的服务器上恢复的话：先停服务（`sudo systemctl stop i3t-controller`），把库删掉、重新建一个空的，执行上面 `pg_restore` 和 `sudo install` 那两条，再启动服务。

备份时的管理令牌照样能用。只要公网地址仍然指向 controller，节点会自己连回来。备份之后才加入的节点要用新的令牌重新加入。
