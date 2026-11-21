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
| 节点（`i3t`）                           | 每一台要组网的机器                                 | 每台一个   |
| 中继                                    | 一个别的节点连得上的节点     | 至少一个   |

## 开始之前

- **放 controller 的机器**：Linux（x86_64 或 aarch64），有 systemd，有一个各个节点都连得上的 IP 或域名。
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

在服务器上：

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --public-addr <公网地址>:20331
```

`<公网地址>` 是节点连这台机器用的 IP 或域名。它会写进每一个注册令牌，所以要选一个不会变的。用域名的话，以后可以把 controller 搬到别的机器上。

脚本把 `i3t-controller` 和 `i3tctl` 装到 `/usr/local/bin`，建好 systemd 服务 `i3t-controller`（专用的系统用户，开机自启）并启动它，最后打印管理令牌：

```
管理令牌（只显示这一次）：

    <管理令牌>
```

**把令牌存好。** Web 界面和 `i3tctl` 都用它登录，之后不会再显示。丢了的话见 [管理令牌丢了](#管理令牌丢了)。

查看服务状态：

```sh
systemctl status i3t-controller
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
- **controller 要手动升级。** 在服务器上再执行一次脚本，数据和设置都保留：

  ```sh
  curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller
  ```

每一版要升级哪些部分，见 [CHANGELOG.md](../CHANGELOG.md)。

### 备份和恢复

备份不用停 controller：

```sh
sudo /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller --backup-to /root/i3t-controller-backup
```

目标要是一个新的或者空的目录。备份里有全部的网络、节点和设置，以及管理令牌和 controller 的密钥。不要只拷贝 `controller.db`：最近的改动可能还在它旁边的文件里。

恢复，在原来的服务器上，或者在一台按第 1 步装好 controller 的新服务器上：

```sh
sudo systemctl stop i3t-controller
sudo mv /var/lib/i3t-controller /var/lib/i3t-controller.old
sudo cp -a /root/i3t-controller-backup /var/lib/i3t-controller
sudo chown -R i3t-controller: /var/lib/i3t-controller
sudo systemctl start i3t-controller
```

只要公网地址仍然指向 controller，节点会自己连回来。备份之后才加入的节点要用新的令牌重新加入。

### 管理令牌丢了

```sh
sudo systemctl stop i3t-controller
sudo -u i3t-controller /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller --reset-admin-token
sudo systemctl start i3t-controller
```

它会打印一个新的令牌，原来的作废。

### 卸载

```sh
# 节点。加 --purge 连它的身份和设置一起删
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --uninstall

# controller。加 --purge 连它的数据和配置一起删
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --uninstall --controller
```

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

装 controller 的话，下载 `i3t-controller-<平台>` 和 `i3tctl-<平台>`，执行 `sh install.sh --from . --controller --public-addr <公网地址>:20331`。

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
| 安装时没有看到管理令牌                                 | `sudo journalctl -u i3t-controller --no-pager`                                                      |

## 参考

安装脚本建的文件：

| 内容                    | 位置                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------ |
| controller 的数据       | `/var/lib/i3t-controller`                                                            |
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
| `--token <令牌>`            | 节点：加入并启动。也可以用环境变量 `I3T_TOKEN`         |
| `--can-relay`、`--can-exit` | 节点：加入时声明可以作为中继、出口                     |
| `--no-vnet`                 | 节点：不要虚拟网卡                                     |
| `--no-polkit`               | 节点：不装 `systemd-resolved` 的 polkit 规则           |
| `--version <标签>`          | 安装指定的版本，不装最新的                             |
| `--release-base <地址>`     | 从目录结构和 GitHub Releases 相同的镜像下载            |
| `--from <目录>`             | 用本地目录里的程序安装，不下载                         |
| `--uninstall`、`--purge`    | 删掉服务和程序；加 `--purge` 连状态和设置一起删        |
