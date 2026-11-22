---
title: 常见问题
description: 常见的现象和处理办法。
---

## `i3t join` 连不上 controller

确认这台机器连得上 controller 的 TCP 20331，以及安装 controller 时 `--public-addr` 写的是节点能用的地址。

## 注册令牌无效：不存在、已经用过或者已经过期

一个令牌只能用一次，新建一个。

## 节点一直不在线

看它的日志：

```sh
sudo journalctl -u i3t -n 50   # Linux
cat /var/log/i3t.log           # macOS
```

## 两个节点都在线，互相却不通

它们之间没有直连的路，也没有两边都连得上的中继，见 [配置中继](../../deploy/relay/)。`sudo i3t status` 里有到每个节点的路由。

## 开着 firewalld，别的节点连不到这台机器

```sh
sudo firewall-cmd --permanent --zone=trusted --add-interface=i3t0
sudo firewall-cmd --reload
```

## 名字解析不了

```sh
sudo i3t hosts --apply
```

或者直接用虚拟 IP。

## 安装时没有看到管理令牌

```sh
sudo journalctl -u i3t-controller --no-pager
```
