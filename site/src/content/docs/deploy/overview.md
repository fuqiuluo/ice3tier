---
title: 开始之前
description: 要部署什么、机器要满足什么、要放行哪些端口。
---

照着这一组页面，可以从零搭起一个能用的网络。请按顺序做：**先部署 controller**，因为节点要拿 controller 发的注册令牌才能加入。

1. [安装 controller](../controller/)
2. [添加节点](../nodes/)
3. [配置中继](../relay/)
4. [检查](../verify/)

## 要部署什么

| 组成 | 放在哪里 | 数量 |
| --- | --- | --- |
| controller（`i3t-controller`）和 `i3tctl` | 一台各个节点都连得上的 Linux 机器，通常是有公网地址的服务器 | 一个 |
| 节点（`i3t`） | 每一台要组网的机器 | 每台一个 |
| 中继 | 一个别的节点连得上的节点 | 至少一个 |

## 机器

- **放 controller 的机器**：Linux（x86_64 或 aarch64），有 systemd，有一个各个节点都连得上的 IP 或域名。
- **节点的机器**：Linux（x86_64、aarch64）、macOS（Apple 芯片、Intel）或 Windows（x86_64）。
- 每台机器上要有 root 或 `sudo`。
- 安装脚本从 GitHub 下载。机器连不上 GitHub 的话，见 [连不上 GitHub 时](../../reference/other-install/#连不上-github-时)。

## 端口

要在防火墙或安全组里放行的端口：

| 机器 | 端口 | 对谁开放 | 用途 |
| --- | --- | --- | --- |
| controller | TCP 20331、UDP 20331 | 所有节点 | 节点连 controller |
| controller | TCP 20332 | 不开放 | Web 界面和管理 API，只监听 `127.0.0.1`，不要对外放行 |
| 中继节点 | UDP 20330、TCP 20330 | 别的节点 | 中继转发 |
| 别的节点 | 不需要 | | 放行 UDP 20330 有助于别的节点直连过来 |
