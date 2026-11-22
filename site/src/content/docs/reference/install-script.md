---
title: 安装脚本
description: 安装脚本的选项，以及它建的文件。
---

## 选项

Linux 和 macOS 用 `install.sh`：

| 选项 | 含义 |
| --- | --- |
| `--controller` | 安装 controller 和 `i3tctl`，不装节点 |
| `--public-addr <主机:端口>` | controller：节点连它用的地址；同时启动服务 |
| `--token <令牌>` | 节点：加入并启动。也可以用环境变量 `I3T_TOKEN` |
| `--can-relay`、`--can-exit` | 节点：加入时声明可以作为中继、出口 |
| `--no-vnet` | 节点：不要虚拟网卡 |
| `--no-polkit` | 节点：不装 `systemd-resolved` 的 polkit 规则 |
| `--version <标签>` | 安装指定的版本，不装最新的 |
| `--release-base <地址>` | 从目录结构和 GitHub Releases 相同的镜像下载 |
| `--from <目录>` | 用本地目录里的程序安装，不下载 |
| `--uninstall`、`--purge` | 删掉服务和程序；加 `--purge` 连状态和设置一起删 |

Windows 用 `install.ps1`，选项写成环境变量，只对这一次执行有效：

| 环境变量 | 含义 |
| --- | --- |
| `I3T_TOKEN` | 加入并启动 |
| `I3T_CAN_RELAY=1`、`I3T_CAN_EXIT=1` | 加入时声明可以作为中继、出口 |
| `I3T_VERSION` | 安装指定的版本，不装最新的 |
| `I3T_RELEASE_BASE` | 从目录结构和 GitHub Releases 相同的镜像下载 |
| `I3T_FROM` | 用本地目录里的 `i3t.exe` 和 `wintun.dll` 安装，不下载 |
| `I3T_UNINSTALL=1`、`I3T_PURGE=1` | 删掉服务和程序；加 `I3T_PURGE` 连密钥和设置一起删 |

## 文件

`install.sh` 建的文件：

| 内容 | 位置 |
| --- | --- |
| controller 的数据 | `/var/lib/i3t-controller` |
| controller 的设置 | `/etc/i3t/controller.env`（`I3T_PUBLIC_ADDR`、`I3T_CONTROLLER_ARGS`） |
| controller 和命令行程序 | `/usr/local/bin/i3t-controller`、`/usr/local/bin/i3tctl` |
| 节点的状态和设置 | `/var/lib/i3t`（设置在 `config.toml` 里） |
| 节点程序 | `/var/lib/i3t/bin/i3t`，经 `/usr/local/bin` 里的 `i3t` 命令执行 |
| 服务 | `i3t-controller.service` 和 `i3t.service`；macOS 上是 launchd 守护进程 `com.github.fuqiuluo.ice3tier` |
