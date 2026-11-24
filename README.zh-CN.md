<div align="center">

<img src="web/public/favicon.svg" alt="ice3tier" width="96" />

# ice3tier

**自己托管的组网工具，把你自己的机器连成一个网。**

[![CI](https://github.com/fuqiuluo/ice3tier/actions/workflows/ci.yml/badge.svg)](https://github.com/fuqiuluo/ice3tier/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/fuqiuluo/ice3tier?include_prereleases)](https://github.com/fuqiuluo/ice3tier/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#许可证)
[![Rust](https://img.shields.io/badge/rust-1.91%2B-orange)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](#平台支持)

[English](README.md) | 简体中文

</div>

ice3tier 把你自己的机器连成一个私有网络。每个节点有一块虚拟网卡和一个虚拟 IP，能直连就直连，连不通就经你自己的中继转发。整个网络由一个带 Web 界面的 controller 管理。

> [!NOTE]
> 项目还在活跃开发中，版本之间接口和协议都可能变。

## 功能

- **虚拟网络**：每个节点默认装一块虚拟网卡、分到一个虚拟 IP，本机的程序按 IP 或名字访问别的节点，比如 `ssh nas.home.i3t`。
- **能直连就直连**：同一个局域网、有开放的端口或者打洞成功时直连；不行就经中继转发，UDP 不通时走 TCP。中继只转发加密的数据。
- **出口代理**：在一个节点上开 SOCKS5 / HTTP 代理，流量从另一个节点的网络出去。代理可以设用户名和密码、打开 ice3proxy；出口可以设流量配额。
- **端口转发**：把一个节点上的端口转发到另一个节点，或者它所在局域网里的服务。
- **按分组的访问控制**：规则只有一种：分组 A 里的节点可以访问分组 B 里的节点。
- **集中管理**：一个 controller，带 Web 界面和命令行，可以同时管多个互相隔离的网络。
- **交给 AI Agent**：controller 自带 MCP Server。签一个带权限的令牌，Claude Code、Codex 这类 Agent 就能查看网络、添加节点、改分组和规则，见 [部署指南](docs/deployment.zh-CN.md#让-ai-agent-管理网络mcp)。
- **签名的自动更新**：节点自己取新版本、验签、安装、重启，新版本起不来就退回旧的。

## 工作原理

```
                 ┌──────────────────────────────┐
                 │          controller          │   Web 界面 · 管理 API · i3tctl
                 └──────────────┬───────────────┘
                                │ 配置和成员
             ┌──────────────────┼──────────────────┐
             ▼                  ▼                  ▼
        ┌─────────┐        ┌─────────┐        ┌─────────┐
        │  节点 A │◀══════▶│  中继   │◀══════▶│  节点 B │
        └─────────┘        └─────────┘        └─────────┘
             ▲                                     ▲
             └═════════════════ 直连 ══════════════┘
```

- 每一对节点之间只有一条端到端加密的 QUIC 连接；在中继和直连之间切换时，上面的连接不断。
- 节点之间、节点和 controller 之间按 Ed25519 公钥互相认证。
- controller 只负责下发配置；它不在线时，已经在线的节点照常工作。

## 快速上手

先部署 controller，再装节点：节点要拿 controller 发的令牌才能加入。每一步的细节，以及端口、Windows、升级和备份，见 [部署指南](docs/deployment.zh-CN.md)。

**1. 安装 controller**，放在一台各个节点都连得上的 Linux 服务器上，放行 TCP 和 UDP 的 20331 端口。用 Docker 的话，连它存数据用的 PostgreSQL 一起启动：

```sh
curl -fsSLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/docker/compose.yaml
echo 'I3T_PUBLIC_ADDR=<公网地址>:20331' > .env
docker compose up -d
docker compose logs controller   # 管理令牌只在第一次启动时打印一次
```

自己有 PostgreSQL（16 或更新）的话，也可以装成 systemd 服务，脚本会打印一次管理令牌：

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --public-addr <公网地址>:20331 --database-url postgres://<用户>:<密码>@<主机>/<库名>
```

登录 Web 界面和 `i3tctl` 都用这个令牌。Web 界面只监听 `127.0.0.1:20332`，从别的机器打开要用 SSH 转发端口：

```sh
ssh -L 20332:127.0.0.1:20332 <controller 所在的机器>
```

**2. 建网络，新建注册令牌。** 在 Web 界面里新建网络，点「添加节点」，新建一个令牌。用命令行的话，在服务器上：

```sh
export I3T_ADMIN_TOKEN=<管理令牌>
i3tctl network create home
i3tctl token create   # 每台机器用一个
```

用 Docker 装的话，`i3tctl` 在 controller 的容器里：`docker compose exec controller i3tctl --token <管理令牌> network create home`。

**3. 在每台机器上安装节点。** Linux 和 macOS：

```sh
# 可以当中继或出口的，加 --can-relay 或 --can-exit
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --token <注册令牌>
sudo i3t status
```

它把节点装成系统服务、加入网络并启动：Linux 上是以专用系统用户运行的 systemd 服务，macOS 上是 launchd 守护进程。Windows 见 [部署指南](docs/deployment.zh-CN.md#第-3-步添加节点)。

**4. 启用中继和出口，建代理和端口转发。** 在 Web 界面里做，或者用命令行。连不通的节点之间要经中继转发，所以至少启用一个，通常就放在 controller 那台服务器上：

```sh
i3tctl relay enable <节点>
i3tctl exit enable <节点>
i3tctl proxy add <监听的节点> 127.0.0.1:1080 <出口节点>
curl -x socks5h://127.0.0.1:1080 https://example.com
```

## 其他安装方式

### 手动下载

从 [最新的发布](https://github.com/fuqiuluo/ice3tier/releases/latest) 下载对应平台的程序：

| 平台                  | 节点                     | controller                          | 命令行                      |
| --------------------- | ------------------------ | ----------------------------------- | --------------------------- |
| Linux x86_64          | `i3t-linux-x86_64`       | `i3t-controller-linux-x86_64`       | `i3tctl-linux-x86_64`       |
| Linux aarch64         | `i3t-linux-aarch64`      | `i3t-controller-linux-aarch64`      | `i3tctl-linux-aarch64`      |
| Windows x86_64        | `i3t-windows-x86_64.zip` | `i3t-controller-windows-x86_64.exe` | `i3tctl-windows-x86_64.exe` |
| macOS（Apple 芯片）   | `i3t-macos-aarch64`      | `i3t-controller-macos-aarch64`      | `i3tctl-macos-aarch64`      |
| macOS（Intel）        | `i3t-macos-x86_64`       | `i3t-controller-macos-x86_64`       | `i3tctl-macos-x86_64`       |

不用安装脚本、直接运行的话，顺序相同：

```sh
i3t-controller --data-dir /var/lib/i3t-controller --database-url postgres://<用户>:<密码>@<主机>/<库名> --public-addr <公网地址>:20331
echo <注册令牌> | i3t join
i3t run
```

连接串里有数据库的密码。不想把它写在命令行上的话，放进环境变量 `I3T_DATABASE_URL`，或者写进数据目录里名叫 `database.url` 的文件。

systemd 单元和 polkit 规则文件在 [`deploy/systemd`](deploy/systemd) 与 [`deploy/polkit`](deploy/polkit)。

### 从源码构建

需要 Rust 1.91 或更新的版本；Web 界面要 Node.js 22 和 pnpm。

```sh
git clone https://github.com/fuqiuluo/ice3tier.git
cd ice3tier
(cd web && pnpm install && pnpm build)   # controller 会把 Web 界面编进去
cargo build --release
```

程序在 `target/release/` 下。controller 的 Docker 镜像用 [`deploy/docker/Dockerfile`](deploy/docker/Dockerfile) 构建。

## 平台支持

| 平台    | 架构                | 虚拟网卡需要                                              |
| ------- | ------------------- | --------------------------------------------------------- |
| Linux   | x86_64、aarch64     | `CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_NET_BIND_SERVICE`（[`deploy/systemd/i3t.service`](deploy/systemd/i3t.service) 里已授予）；非 root 配合 `systemd-resolved` 解析名字另装 [`deploy/polkit/50-i3t-resolved.rules`](deploy/polkit/50-i3t-resolved.rules) |
| Windows | x86_64              | 以管理员运行；`i3t.exe` 旁边要有 `wintun.dll`（发布的 zip 里带着） |
| macOS   | Apple 芯片、Intel   | 以 root 运行                                              |

## 开发

controller 的测试要一个 PostgreSQL。`scripts/test-postgres.sh start` 起一个用完就扔的（用系统里装着的 PostgreSQL，或者 Docker），并打印要导出的环境变量：

```sh
export $(scripts/test-postgres.sh start)
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Web 界面见 [`web/README.md`](web/README.md)，每一版的变化见 [CHANGELOG.md](CHANGELOG.md)。

## 参与贡献

欢迎提交问题和 Pull Request。提 Pull Request 之前，请确认 `cargo fmt --check`、`cargo clippy` 和 `cargo test --workspace` 都通过；改了 Web 界面的话，在 `web/` 里跑 `pnpm lint` 和 `pnpm test`。

## 许可证

以下两种许可任选其一：

- Apache License 2.0（[LICENSE-APACHE](LICENSE-APACHE)）
- MIT 许可证（[LICENSE-MIT](LICENSE-MIT)）

除非你明确声明，你有意提交、要合入本项目的任何贡献（按 Apache-2.0 许可的定义），都按上面的双许可发布，不附加别的条款或条件。
