# 部署指南

[English](deployment.md) | 简体中文

照着这份指南，可以从零搭起一个能用的网络。请按顺序做：**先部署 controller**，因为节点要拿 controller 发的注册令牌才能加入。

1. [安装 controller](#第-1-步安装-controller)
2. [打开 Web 界面，新建网络](#第-2-步打开-web-界面新建网络)
3. [添加节点](#第-3-步添加节点)
4. [配置中继](#第-4-步配置中继)
5. [检查](#第-5-步检查)

## 要部署什么

| 组成                                    | 放在哪里                                           | 数量       |
| --------------------------------------- | -------------------------------------------------- | ---------- |
| controller（`i3t-controller`）和 `i3tctl` | 一台各个节点都连得上的 Linux 机器，通常是有公网地址的服务器 | 一个       |
| PostgreSQL 数据库                       | 和 controller 放在一起，它的数据存在里面           | 一个       |
| 节点（`i3t`）                           | 每一台要组网的机器                                 | 每台一个   |
| 中继                                    | 一个别的节点连得上的节点     | 至少一个   |

## 开始之前

- **放 controller 的机器**：Linux（x86_64 或 aarch64），有一个各个节点都连得上的 IP 或域名。要么装了 Docker（带 `docker compose`），要么有 systemd 和一个 PostgreSQL 数据库（16 或更新的版本）。
- **节点的机器**：Linux（x86_64、aarch64）、macOS（Apple 芯片、Intel）或 Windows（x86_64）。
- 每台机器上要有 root 或 `sudo`。
- 安装脚本从 GitHub 下载。机器连不上 GitHub 的话，见 [连不上 GitHub 时](#连不上-github-时)。

要在防火墙或安全组里放行的端口：

| 机器       | 端口                 | 对谁开放 | 用途                                                 |
| ---------- | -------------------- | -------- | ---------------------------------------------------- |
| controller | TCP 20331、UDP 20331 | 所有节点 | 节点连 controller                                    |
| controller | TCP 20332            | 不开放   | Web 界面和管理 API，只监听 `127.0.0.1`，不要对外放行 |
| 中继节点   | UDP 20330、TCP 20330 | 别的节点 | 中继转发                                             |
| 别的节点   | 不需要               |          | 放行 UDP 20330 有助于别的节点直连过来                |

## 第 1 步：安装 controller

controller 把网络、节点和所有设置都存在 PostgreSQL 数据库里。有两种装法：用 Docker，自带 PostgreSQL；或者用安装脚本，PostgreSQL 自己准备。

两种装法里，`<公网地址>` 都是节点连这台机器用的 IP 或域名。它会写进每一个注册令牌，所以要选一个不会变的。用域名的话，以后可以把 controller 搬到别的机器上。

**用 Docker。** 在服务器上：

```sh
curl -fsSLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/docker/compose.yaml
echo 'I3T_PUBLIC_ADDR=<公网地址>:20331' > .env
docker compose up -d
docker compose logs controller   # 管理令牌只在第一次启动时打印一次
```

它把 controller 和它用的 PostgreSQL 一起启动。这份指南后面的 `docker compose` 命令都在这个目录里执行。设置写在 `compose.yaml` 旁边的 `.env` 文件里：

| 设置              | 含义                                                 |
| ----------------- | ---------------------------------------------------- |
| `I3T_PUBLIC_ADDR` | 必填：节点连它用的地址                               |
| `I3T_VERSION`     | 要运行的版本，不带 `v`，比如 `0.1.35`。默认 `latest` |

镜像是 `ghcr.io/fuqiuluo/ice3tier-controller`（linux amd64 和 arm64），里面有 `i3t-controller` 和 `i3tctl`。TCP 和 UDP 的 20331 发布在所有地址上，Web 界面的 20332 端口只发布在服务器的 `127.0.0.1` 上。数据库没有密码要设，也不听网络：它只听一个 Unix 套接字，套接字在只有这两个容器挂着的卷里。数据在两个命名卷里：`postgres` 是数据库，`controller` 是 controller 的密钥和更新包的缓存。第三个卷 `postgres-socket` 里只有那个套接字。

**用安装脚本。** 脚本不装 PostgreSQL：要先有一个数据库，16 或更新的版本。在同一台机器上建一个的话，Debian 或 Ubuntu 上：

```sh
sudo apt-get install -y postgresql
sudo -u postgres psql -c "CREATE ROLE i3t LOGIN PASSWORD '<密码>'" -c "CREATE DATABASE i3t OWNER i3t"
```

它的连接串是 `postgres://i3t:<密码>@127.0.0.1/i3t`。然后安装 controller：

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --public-addr <公网地址>:20331 --database-url postgres://<用户>:<密码>@<主机>/<库名>
```

脚本把 `i3t-controller` 和 `i3tctl` 装到 `/usr/local/bin`，建好 systemd 服务 `i3t-controller`（专用的系统用户，开机自启）并启动它。连接串写进 `/var/lib/i3t-controller/database.url`，只有这个服务的用户可读。到数据库的连接不加密：数据库要放在同一台机器上，或者可信的内网里。

两种装法都在第一次启动时打印管理令牌：在 `docker compose logs controller` 里，或者在脚本的最后。

```
管理令牌（只显示这一次）：

    <管理令牌>
```

**把令牌存好。** Web 界面和 `i3tctl` 都用它登录，之后不会再显示。丢了的话见 [管理令牌丢了](#管理令牌丢了)。

查看服务状态：

```sh
docker compose ps                  # Docker
systemctl status i3t-controller    # 安装脚本
```

## 第 2 步：打开 Web 界面，新建网络

Web 界面只监听服务器的 `127.0.0.1:20332`，而且是明文 HTTP，从外面打不开。在你自己的电脑上用 SSH 转发端口：

```sh
ssh -L 20332:127.0.0.1:20332 <用户>@<服务器>
```

保持这个会话不断，打开 <http://127.0.0.1:20332>，用管理令牌登录，新建一个网络，比如 `home`。

用命令行的话，在服务器上：

```sh
export I3T_ADMIN_TOKEN=<管理令牌>
i3tctl network create home
```

用 Docker 装的话，`i3tctl` 在 controller 的容器里。这份指南里的 `i3tctl` 命令都这样写：

```sh
docker compose exec controller i3tctl --token <管理令牌> network create home
```

## 第 3 步：添加节点

每台机器用自己的注册令牌加入。一个令牌只能用一次，默认 24 小时后过期。

**新建令牌。** 在 Web 界面里点「添加节点」，点「新建令牌」，再点「仅复制令牌」。用命令行的话：

```sh
i3tctl token create
```

**安装并加入。** 在要加入的机器上（Linux 或 macOS）：

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --token <注册令牌>
```

它把节点装成系统服务、加入网络并启动，开机自启：Linux 上是以专用系统用户运行的 systemd 服务 `i3t`，macOS 上是 launchd 守护进程。

在这台机器上检查：

```sh
sudo i3t status
```

`controller` 一行应该是「已连接」，Web 界面里这个节点显示在线。每台机器用一个新的令牌，重复这一步。

别的情况：

- **安装时没有带令牌。** 之后再加入，加入后服务会自动启动：

  ```sh
  echo <注册令牌> | sudo i3t join
  ```

- **Windows。** 以管理员身份打开 PowerShell，执行：

  ```powershell
  $env:I3T_TOKEN = '<注册令牌>'; irm https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.ps1 | iex
  ```

  节点装成系统服务 `i3t`：在后台运行，开机自动启动。不带令牌也可以装，之后用 `echo <注册令牌> | i3t join` 加入，加入后服务会自动启动。`i3t status` 查看状态；卸载是 `$env:I3T_UNINSTALL = '1'; irm … | iex`。

- **没有 systemd 的 Linux。** 脚本只装 `/usr/local/bin/i3t`。用 `echo <注册令牌> | sudo i3t join` 加入，再用你的 init 系统让 `sudo i3t run` 一直运行。

## 第 4 步：配置中继

两个节点能直连就直连：在同一个局域网里、有开放的端口，或者打洞成功。连不通时经中继转发。**没有中继的话，这样的一对节点之间就是不通的。** 中继通常就放在跑 controller 的那台服务器上。

1. 按第 3 步在服务器上也装一个节点，并声明它可以作为中继：

   ```sh
   curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --token <注册令牌> --can-relay
   ```

   已经加入的节点：

   ```sh
   sudo i3t set can-relay on
   sudo systemctl restart i3t   # macOS：sudo launchctl kickstart -k system/com.github.fuqiuluo.ice3tier
   ```

2. 在服务器上放行 UDP 20330 和 TCP 20330。

3. 启用中继：在 Web 界面的节点页打开中继开关，或者执行：

   ```sh
   i3tctl relay enable <节点>
   ```

   它会列出这个节点的各个地址，以及 controller 连不连得上。

声明和启用缺一不可：机器自己声明可以作为中继，管理员再把它打开。中继的地址是自动找出来的。只有机房或路由器把另一个 IP 上的端口映射到这台机器时才需要写明，写完重启节点：

```sh
sudo i3t set relay-address <IP>:<端口>
```

## 第 5 步：检查

在任意一个节点上：

```sh
sudo i3t status              # controller 已连接，以及到每个节点的路由
sudo i3t ping <节点>         # 到另一个节点的往返
ping <虚拟 IP>               # 经虚拟网卡
ssh <节点>.<网络>.i3t        # 按名字，比如 nas.home.i3t
```

有 `systemd-resolved` 的 Linux 上名字直接能用。别的机器上用 `sudo i3t hosts --apply` 把名字写进 hosts 文件，或者直接用虚拟 IP。

之后的事都在 Web 界面或 `i3tctl` 里做：出口和代理、端口转发、分组和访问规则。

## 维护

### 升级

- **节点自己更新。** controller 取来带签名的新版本交给节点，节点验签、安装、重启。`i3tctl update show` 查看状态。要手动升级一个节点，在它上面再执行一次安装脚本，已有的加入信息会保留。
- **controller 要手动升级。** 在服务器上执行，数据和设置都保留：

  ```sh
  # Docker
  docker compose pull && docker compose up -d

  # 安装脚本：再执行一次
  curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller
  ```

- **从 0.1.34 或更早的版本升级。** controller 现在要 PostgreSQL，原来的数据不会带过来：它从空的开始。网络要重新建，每个节点要用新的注册令牌重新加入。原来的 `controller.db` 留在原处，不再读它。用安装脚本的话，这一次要像 [第 1 步](#第-1-步安装-controller) 那样带上 `--database-url`，以后升级不用再带。管理令牌也是新的，脚本最后会把它打印出来。

每一版要升级哪些部分，见 [CHANGELOG.md](../CHANGELOG.md)。

### 备份和恢复

备份是两个文件：数据库的转储，和 controller 的密钥 `controller.key`。备份不用停 controller：

```sh
# Docker
(umask 077; tmp=$(mktemp -d ./controller.backup.XXXXXX) || exit
 trap 'rm -rf "$tmp"' EXIT; trap 'exit 1' HUP INT TERM
 docker compose exec -T postgres pg_dump --username i3t --format custom i3t > "$tmp/controller.dump" &&
 docker compose exec -T controller cat /data/controller.key > "$tmp/controller.key" &&
 [ -s "$tmp/controller.dump" ] && [ -s "$tmp/controller.key" ] &&
 mv -f "$tmp/controller.dump" "$tmp/controller.key" .)

# 安装脚本
(umask 077; tmp=$(mktemp -d ./controller.backup.XXXXXX) || exit
 trap 'rm -rf "$tmp"' EXIT; trap 'exit 1' HUP INT TERM
 sudo -u i3t-controller sh -c 'url=$(cat /var/lib/i3t-controller/database.url) && [ -n "$url" ] && exec pg_dump --format custom --dbname="$url"' > "$tmp/controller.dump" &&
 sudo -u i3t-controller cat /var/lib/i3t-controller/controller.key > "$tmp/controller.key" &&
 [ -s "$tmp/controller.dump" ] && [ -s "$tmp/controller.key" ] &&
 mv -f "$tmp/controller.dump" "$tmp/controller.key" .)
```

转储里有全部的网络、节点和设置，以及管理令牌。两个文件都是秘密：转储里有代理的密码，密钥就是 controller 的身份。上面的命令把它们重新写出来，只有你自己可读，保存时也别放宽。中途失败时，上一次的备份保持原样。用安装脚本装的，数据目录归服务的用户 `i3t-controller`，备份和恢复都以它的身份读写里面的文件，不用 root：那里的文件可能被换成了链接，root 会跟着它读写别处。两个文件缺一不可：节点认的是这把密钥，数据库里记着在它名下加入的节点。

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

用安装脚本的话，先按第 1 步建一个空的数据库，然后：

```sh
pg_restore --no-owner --dbname postgres://i3t:<密码>@127.0.0.1/i3t controller.dump
# 先装上但不启动，把密钥放好，再启动
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --database-url postgres://i3t:<密码>@127.0.0.1/i3t
sudo -u i3t-controller sh -c 'umask 077; rm -f "$1" && cat > "$1"' sh /var/lib/i3t-controller/controller.key < controller.key
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --public-addr <公网地址>:20331
```

在原来的服务器上恢复的话：先停服务（`sudo systemctl stop i3t-controller`），把库删掉、重新建一个空的，执行上面 `pg_restore` 和 `sudo -u i3t-controller` 那两条，再启动服务。

按这份说明以前的版本做的备份归 root，你自己读不了：先 `sudo chown "$(id -un)" controller.dump controller.key`。

密钥要在 controller 启动之前放好：库已经是某个 controller 的了，没有它的密钥 controller 不启动，也不会生成一把新的。

备份时的管理令牌照样能用。只要公网地址仍然指向 controller，节点会自己连回来。备份之后才加入的节点要用新的令牌重新加入。

签过 [MCP 令牌](#让-ai-agent-管理网络mcp) 的话，数据目录里还有一把签它们的密钥 `mcp.key`。想让它们在恢复之后接着能用，把它和 `controller.key` 一起备份、一起放回去：上面的命令里 `controller.key` 的那一行照样再写一行 `mcp.key`。没有它也能恢复：controller 生成一把新的，原来签出去的 MCP 令牌全部作废，重新签发就行。

### 管理令牌丢了

```sh
# Docker
docker compose stop controller
docker compose run --rm controller --reset-admin-token
docker compose start controller

# 安装脚本
sudo systemctl stop i3t-controller
sudo -u i3t-controller /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller --reset-admin-token
sudo systemctl start i3t-controller
```

它会打印一个新的令牌，原来的作废。

### 让 AI Agent 管理网络（MCP）

controller 自己就是一个 MCP Server。Claude Code、Codex、Cursor 这类 AI Agent 连上来以后，能查看网络，也能做管理操作：对它说「把这台机器加进 home 网络，放进 servers 分组」，它自己去建注册令牌、给出安装命令、确认节点上线。它能做什么，由你签给它的令牌决定。

**签一个 MCP 令牌。** 在 Web 界面的「设置 → MCP」里签，或者在服务器上执行（用 Docker 装的，前面加 `docker compose exec controller`）：

```sh
i3tctl mcp token create --name claude-code --scope read,nodes:enroll --expires-in 30d
```

令牌只显示这一次。`--name` 是给谁用的，它做的每一处改动都记着这个名字。有效期必须写，最长 90 天。加上 `--network <网络>`，它就只能看到和操作这一个网络。`--scope` 是权限，只给用得着的：

| 权限             | 能做的                                                                                                   |
| ---------------- | -------------------------------------------------------------------------------------------------------- |
| `read`           | 只读：状态、网络、节点、路由和路径、出口、访问检查、测试结果、统计、操作记录，以及分组、规则、代理、端口转发、节点对的设置 |
| `nodes:enroll`   | 添加节点：建、列、删注册令牌，查一个注册令牌加入了哪个节点、在不在线                                     |
| `nodes:write`    | 改节点、删节点、继任、开关中继和出口                                                                     |
| `config:write`   | 分组和成员、访问规则、代理、端口转发、节点对的设置                                                       |
| `tests:run`      | 发起和取消测试                                                                                           |
| `updates:write`  | 更新设置、检查更新、强制更新。管的是整个 controller，不能给只限一个网络的令牌                            |
| `networks:write` | 建、改、删网络。管的是整个 controller，不能给只限一个网络的令牌                                          |

没有 `config:write` 的令牌看不到代理的密码。

**配进客户端。** MCP 端点是管理 API 地址上的 `/api/v1/mcp`，令牌放在请求头 `Authorization: Bearer <MCP 令牌>` 里：

```sh
# Claude Code
claude mcp add --transport http ice3tier http://127.0.0.1:20332/api/v1/mcp --header "Authorization: Bearer <MCP 令牌>"

# Codex：令牌从环境变量里读
export I3T_MCP_TOKEN=<MCP 令牌>
codex mcp add ice3tier --url http://127.0.0.1:20332/api/v1/mcp --bearer-token-env-var I3T_MCP_TOKEN
```

别的客户端在它的 MCP 配置里填这个地址和这个请求头。比如 Cursor 的 `mcp.json`：

```json
{
  "mcpServers": {
    "ice3tier": {
      "url": "http://127.0.0.1:20332/api/v1/mcp",
      "headers": { "Authorization": "Bearer <MCP 令牌>" }
    }
  }
}
```

MCP 端点和 Web 界面在同一个地址上：只监听服务器的 `127.0.0.1:20332`，明文 HTTP。Agent 在别的机器上时，和打开 Web 界面一样先用 SSH 转发端口，地址照旧写 `127.0.0.1`。用 `--admin-listen` 把管理 API 放到别的地址上，MCP 端点也跟着暴露出去。

**查看和撤销。**

```sh
i3tctl mcp token list
i3tctl mcp token revoke <编号>   # 它的下一次调用就被拒绝
i3tctl log                        # 经 MCP 做的改动后面注明是哪个令牌做的
```

还要知道的：

- MCP 令牌只在 MCP 端点上有用，不能当管理令牌用。签发、列出、撤销令牌只能用管理令牌，Agent 自己做不了，也就没法给自己加权限。
- 删节点、删规则这类工具都标明了会删东西（MCP 的 `destructiveHint`），客户端可以据此在执行之前先问你。让 Agent 改东西的时候，自己看一眼它要调什么，别把会删东西的工具设成自动放行。
- 签令牌的是数据目录里的 `mcp.key`，不是 `controller.key`。要让签出去的令牌全部作废：停 controller，删掉 `mcp.key`，再启动。它会生成一把新的，原来签的令牌都不再认，列表里标成已撤销。
- 认的 MCP 协议版本是 2025-03-26、2025-06-18、2025-11-25 和 2026-07-28，传输是 Streamable HTTP。不做 OAuth：令牌由你签好、配进客户端。

### 卸载

```sh
# 节点。加 --purge 连它的身份和设置一起删
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --uninstall

# controller，用 Docker 装的。加 --volumes 连数据库和 controller 的密钥一起删
docker compose down

# controller，用安装脚本装的。加 --purge 连它的密钥和设置一起删
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --uninstall --controller
```

安装脚本不会动 PostgreSQL 数据库，加不加 `--purge` 都一样。想删的话自己删。

卸载节点之后，在 Web 界面里把它删掉，或者执行 `i3tctl node delete <节点>`。

## 连不上 GitHub 时

在一台连得上 GitHub 的电脑上，下载脚本和目标机器所在平台的程序（文件名见 [README](../README.zh-CN.md#手动下载)）：

```sh
curl -fLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh
curl -fLO https://github.com/fuqiuluo/ice3tier/releases/latest/download/i3t-linux-x86_64
```

把它们拷到目标机器的同一个目录里，从这个目录安装：

```sh
sh install.sh --from . --token <注册令牌>
```

装 controller 的话，下载 `i3t-controller-<平台>` 和 `i3tctl-<平台>`，执行 `sh install.sh --from . --controller --public-addr <公网地址>:20331 --database-url postgres://<用户>:<密码>@<主机>/<库名>`。

有和 GitHub Releases 目录结构相同的镜像的话，改用 `--release-base <地址>`。节点的更新是从 controller 取的，所以之后只有 controller 需要一个连得上的发布源，用 `i3tctl update set --source <地址或目录>` 修改。

## 常见问题

| 现象                                                   | 怎么办                                                                                              |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| `i3t join` 连不上 controller                           | 确认这台机器连得上 controller 的 TCP 20331，以及 `--public-addr` 写的是节点能用的地址               |
| `注册令牌无效：不存在、已经用过或者已经过期`           | 一个令牌只能用一次，新建一个                                                                        |
| 节点一直不在线                                         | 看它的日志：Linux 上 `sudo journalctl -u i3t -n 50`，macOS 上 `/var/log/i3t.log`                    |
| 两个节点都在线，互相却不通                             | 它们之间没有直连的路，也没有两边都连得上的中继，见 [第 4 步](#第-4-步配置中继)。`sudo i3t status` 里有到每个节点的路由 |
| 开着 firewalld，别的节点连不到这台机器                 | `sudo firewall-cmd --permanent --zone=trusted --add-interface=i3t0 && sudo firewall-cmd --reload`   |
| 名字解析不了                                           | `sudo i3t hosts --apply`，或者直接用虚拟 IP                                                         |
| 安装时没有看到管理令牌                                 | `sudo journalctl -u i3t-controller --no-pager`；用 Docker 装的是 `docker compose logs controller`   |
| 安装脚本要求给 `--database-url`                        | controller 要一个 PostgreSQL 数据库，见 [第 1 步](#第-1-步安装-controller)                          |
| controller 连不上数据库                                | 确认 PostgreSQL 在运行，以及 `/var/lib/i3t-controller/database.url` 里的连接串是对的                |

## 参考

安装脚本建的文件：

| 内容                    | 位置                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------ |
| controller 的数据       | `/var/lib/i3t-controller`（`controller.key`、`mcp.key`、`database.url`、更新包的缓存） |
| controller 的设置       | `/etc/i3t/controller.env`（`I3T_PUBLIC_ADDR`、`I3T_CONTROLLER_ARGS`）                |
| controller 和命令行程序 | `/usr/local/bin/i3t-controller`、`/usr/local/bin/i3tctl`                             |
| 节点的状态和设置        | `/var/lib/i3t`（设置在 `config.toml` 里）                                            |
| 节点程序                | `/var/lib/i3t/bin/i3t`，经 `/usr/local/bin` 里的 `i3t` 命令执行                      |
| 服务                    | `i3t-controller.service` 和 `i3t.service`；macOS 上是 launchd 守护进程 `com.github.fuqiuluo.ice3tier` |

安装脚本的选项：

| 选项                        | 含义                                                   |
| --------------------------- | ------------------------------------------------------ |
| `--controller`              | 安装 controller 和 `i3tctl`，不装节点                  |
| `--public-addr <主机:端口>` | controller：节点连它用的地址；同时启动服务             |
| `--database-url <连接串>`   | controller：用的数据库。也可以用 `I3T_DATABASE_URL`    |
| `--token <令牌>`            | 节点：加入并启动。也可以用环境变量 `I3T_TOKEN`         |
| `--can-relay`、`--can-exit` | 节点：加入时声明可以作为中继、出口                     |
| `--no-vnet`                 | 节点：不要虚拟网卡                                     |
| `--no-polkit`               | 节点：不装 `systemd-resolved` 的 polkit 规则           |
| `--version <标签>`          | 安装指定的版本，不装最新的                             |
| `--release-base <地址>`     | 从目录结构和 GitHub Releases 相同的镜像下载            |
| `--from <目录>`             | 用本地目录里的程序安装，不下载                         |
| `--uninstall`、`--purge`    | 删掉服务和程序；加 `--purge` 连状态和设置一起删        |

controller 的数据目录里是它的密钥 `controller.key`、签 MCP 令牌的密钥 `mcp.key` 和更新包的缓存；网络、节点和设置都在数据库里。数据库的连接串写成 `postgres://用户:密码@主机[:端口]/库名`，也可以写成 `host=… user=… dbname=…` 的形式。`i3t-controller` 先看选项 `--database-url`，再看环境变量 `I3T_DATABASE_URL`，最后读数据目录里只有一行的 `database.url` 文件。连接串里有密码，所以最好用环境变量或者文件，不要写在命令行上。
