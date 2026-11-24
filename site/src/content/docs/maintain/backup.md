---
title: 备份和恢复
description: 备份 controller 的数据，在原来的或新的服务器上恢复。
---

## 备份

备份是两个文件：数据库的转储，和 controller 的密钥 `controller.key`。备份不用停 controller。

用 Docker 装的：

```sh
(umask 077; tmp=$(mktemp -d ./controller.backup.XXXXXX) || exit
 trap 'rm -rf "$tmp"' EXIT; trap 'exit 1' HUP INT TERM
 docker compose exec -T postgres pg_dump --username i3t --format custom i3t > "$tmp/controller.dump" &&
 docker compose exec -T controller cat /data/controller.key > "$tmp/controller.key" &&
 [ -s "$tmp/controller.dump" ] && [ -s "$tmp/controller.key" ] &&
 mv -f "$tmp/controller.dump" "$tmp/controller.key" .)
```

用安装脚本装的：

```sh
(umask 077; tmp=$(mktemp -d ./controller.backup.XXXXXX) || exit
 trap 'rm -rf "$tmp"' EXIT; trap 'exit 1' HUP INT TERM
 sudo -u i3t-controller sh -c 'url=$(cat /var/lib/i3t-controller/database.url) && [ -n "$url" ] && exec pg_dump --format custom --dbname="$url"' > "$tmp/controller.dump" &&
 sudo -u i3t-controller cat /var/lib/i3t-controller/controller.key > "$tmp/controller.key" &&
 [ -s "$tmp/controller.dump" ] && [ -s "$tmp/controller.key" ] &&
 mv -f "$tmp/controller.dump" "$tmp/controller.key" .)
```

转储里有全部的网络、节点和设置，以及管理令牌。两个文件都是秘密：转储里有代理的密码，密钥就是 controller 的身份。上面的命令把它们重新写出来，只有你自己可读，保存时也别放宽。中途失败时，上一次的备份保持原样。用安装脚本装的，数据目录归服务的用户 `i3t-controller`，备份和恢复都以它的身份读写里面的文件，不用 root：那里的文件可能被换成了链接，root 会跟着它读写别处。

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
sudo -u i3t-controller sh -c 'umask 077; rm -f "$1" && cat > "$1"' sh /var/lib/i3t-controller/controller.key < controller.key
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh |
  sh -s -- --controller --public-addr <公网地址>:20331
```

在原来的服务器上恢复的话：先停服务（`sudo systemctl stop i3t-controller`），把库删掉、重新建一个空的，执行上面 `pg_restore` 和 `sudo -u i3t-controller` 那两条，再启动服务。

按这份说明以前的版本做的备份归 root，你自己读不了：先 `sudo chown "$(id -un)" controller.dump controller.key`。

密钥要在 controller 启动之前放好：库已经是某个 controller 的了，没有它的密钥 controller 不启动，也不会生成一把新的。

备份时的管理令牌照样能用。只要公网地址仍然指向 controller，节点会自己连回来。备份之后才加入的节点要用新的令牌重新加入。
