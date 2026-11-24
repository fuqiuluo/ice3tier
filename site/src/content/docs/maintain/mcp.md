---
title: 让 AI Agent 管理网络（MCP）
description: controller 自带 MCP Server：签一个带权限的令牌，让 Claude Code 这类 AI Agent 查看和管理网络。
---

controller 自己就是一个 MCP Server。Claude Code、Codex、Cursor 这类 AI Agent 连上来以后，能查看网络，也能做管理操作：对它说「把这台机器加进 home 网络，放进 servers 分组」，它自己去建注册令牌、给出安装命令、确认节点上线。它能做什么，由你签给它的令牌决定。

## 签一个 MCP 令牌

在 Web 界面的「设置 → MCP」里签，或者在服务器上执行（用 Docker 装的，前面加 `docker compose exec controller`）：

```sh
i3tctl mcp token create --name claude-code --scope read,nodes:enroll --expires-in 30d
```

令牌只显示这一次。`--name` 是给谁用的，它做的每一处改动都记着这个名字。有效期必须写，最长 90 天。加上 `--network <网络>`，它就只能看到和操作这一个网络。`--scope` 是权限，只给用得着的：

| 权限 | 能做的 |
| --- | --- |
| `read` | 只读：状态、网络、节点、路由和路径、出口、访问检查、测试结果、统计、操作记录，以及分组、规则、代理、端口转发、节点对的设置 |
| `nodes:enroll` | 添加节点：建、列、删注册令牌，查一个注册令牌加入了哪个节点、在不在线 |
| `nodes:write` | 改节点、删节点、继任、开关中继和出口 |
| `config:write` | 分组和成员、访问规则、代理、端口转发、节点对的设置 |
| `tests:run` | 发起和取消测试 |
| `updates:write` | 更新设置、检查更新、强制更新。管的是整个 controller，不能给只限一个网络的令牌 |
| `networks:write` | 建、改、删网络。管的是整个 controller，不能给只限一个网络的令牌 |

没有 `config:write` 的令牌看不到代理的密码。

## 配进客户端

MCP 端点是管理 API 地址上的 `/api/v1/mcp`，令牌放在请求头 `Authorization: Bearer <MCP 令牌>` 里：

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

MCP 端点和 Web 界面在同一个地址上：只监听服务器的 `127.0.0.1:20332`，明文 HTTP。Agent 在别的机器上时，和 [打开 Web 界面](../../deploy/controller/) 一样先用 SSH 转发端口，地址照旧写 `127.0.0.1`。用 `--admin-listen` 把管理 API 放到别的地址上，MCP 端点也跟着暴露出去。

## 查看和撤销

```sh
i3tctl mcp token list
i3tctl mcp token revoke <编号>   # 它的下一次调用就被拒绝
i3tctl log                        # 经 MCP 做的改动后面注明是哪个令牌做的
```

## 还要知道的

- MCP 令牌只在 MCP 端点上有用，不能当管理令牌用。签发、列出、撤销令牌只能用管理令牌，Agent 自己做不了，也就没法给自己加权限。
- 删节点、删规则这类工具都标明了会删东西（MCP 的 `destructiveHint`），客户端可以据此在执行之前先问你。让 Agent 改东西的时候，自己看一眼它要调什么，别把会删东西的工具设成自动放行。
- 签令牌的是数据目录里的 `mcp.key`，不是 `controller.key`。备份时把它一起带上，见 [备份和恢复](../backup/)。要让签出去的令牌全部作废：停 controller，删掉 `mcp.key`，再启动。它会生成一把新的，原来签的令牌都不再认，列表里标成已撤销。
- 认的 MCP 协议版本是 2025-03-26、2025-06-18、2025-11-25 和 2026-07-28，传输是 Streamable HTTP。不做 OAuth：令牌由你签好、配进客户端。
