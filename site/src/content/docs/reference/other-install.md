---
title: 其他安装方式
description: 连不上 GitHub 时怎么装、手动下载、从源码构建。
---

## 连不上 GitHub 时

在一台连得上 GitHub 的电脑上，下载脚本和目标机器所在平台的程序（文件名见 [手动下载](#手动下载)）：

```sh
curl -fLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh
curl -fLO https://github.com/fuqiuluo/ice3tier/releases/latest/download/i3t-linux-x86_64
```

把它们拷到目标机器的同一个目录里，从这个目录安装：

```sh
sh install.sh --from . --token <注册令牌>
```

装 controller 的话，下载 `i3t-controller-<平台>` 和 `i3tctl-<平台>`，执行：

```sh
sh install.sh --from . --controller --public-addr <公网地址>:20331
```

有和 GitHub Releases 目录结构相同的镜像的话，改用 `--release-base <地址>`。

节点的更新是从 controller 取的，所以之后只有 controller 需要一个连得上的发布源：

```sh
i3tctl update set --source <地址或目录>
```

## 手动下载

从 [最新的发布](https://github.com/fuqiuluo/ice3tier/releases/latest) 下载对应平台的程序。每个平台有三个文件：节点 `i3t-<平台>`、controller `i3t-controller-<平台>`、命令行 `i3tctl-<平台>`。

| 平台 | 文件名里的 `<平台>` |
| --- | --- |
| Linux x86_64 | `linux-x86_64` |
| Linux aarch64 | `linux-aarch64` |
| Windows x86_64 | `windows-x86_64`，节点是 `.zip`，另外两个是 `.exe` |
| macOS（Apple 芯片） | `macos-aarch64` |
| macOS（Intel） | `macos-x86_64` |

不用安装脚本、直接运行的话，顺序相同：

```sh
i3t-controller --data-dir /var/lib/i3t-controller --public-addr <公网地址>:20331
echo <注册令牌> | i3t join
i3t run
```

systemd 单元和 polkit 规则文件在 [`deploy/systemd`](https://github.com/fuqiuluo/ice3tier/tree/main/deploy/systemd) 与 [`deploy/polkit`](https://github.com/fuqiuluo/ice3tier/tree/main/deploy/polkit)。

直接运行时，虚拟网卡需要：

| 平台 | 需要 |
| --- | --- |
| Linux | `CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_NET_BIND_SERVICE`（`deploy/systemd/i3t.service` 里已授予）；非 root 配合 `systemd-resolved` 解析名字另装 `deploy/polkit/50-i3t-resolved.rules` |
| Windows | 以管理员运行；`i3t.exe` 旁边要有 `wintun.dll`（发布的 zip 里带着） |
| macOS | 以 root 运行 |

## 从源码构建

需要 Rust 1.91 或更新的版本；Web 界面要 Node.js 22 和 pnpm。

```sh
git clone https://github.com/fuqiuluo/ice3tier.git
cd ice3tier
(cd web && pnpm install && pnpm build)   # controller 会把 Web 界面编进去
cargo build --release
```

程序在 `target/release/` 下。
