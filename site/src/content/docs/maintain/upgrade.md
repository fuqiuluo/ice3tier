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

controller 要手动升级。在服务器上再执行一次脚本，数据和设置都保留：

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh |
  sh -s -- --controller
```

每一版要升级哪些部分，见 [CHANGELOG](https://github.com/fuqiuluo/ice3tier/blob/main/CHANGELOG.md)。
