---
title: 升级
description: 节点自己更新，controller 手动升级。
---

## 节点

节点自己更新。controller 取来带签名的新版本交给节点，节点验签、安装、重启；新版本起不来就退回旧的。

查看状态：

```sh
i3tctl update show
```

要手动升级一个节点，在它上面再执行一次安装脚本，已有的加入信息会保留。

## controller

controller 要手动升级，数据和设置都保留。

用 Docker 装的：

```sh
docker compose pull && docker compose up -d
```

用安装脚本装的，在服务器上再执行一次脚本：

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh |
  sh -s -- --controller
```

每一版要升级哪些部分，见 [CHANGELOG](https://github.com/fuqiuluo/ice3tier/blob/main/CHANGELOG.md)。

## 从 0.1.34 或更早的版本升级

controller 现在要 PostgreSQL，原来的数据不会带过来：它从空的开始。网络要重新建，每个节点要用新的注册令牌重新加入。原来的 `controller.db` 留在原处，不再读它。

用安装脚本升级的话，这一次要像 [安装 controller](../../deploy/controller/) 那样带上 `--database-url`，以后升级不用再带。管理令牌也是新的，脚本最后会把它打印出来。
