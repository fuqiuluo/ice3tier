---
title: Let an AI agent manage the network (MCP)
description: The controller is an MCP server. Issue a scoped token and let an AI agent such as Claude Code look at and manage the network.
---

The controller is itself an MCP server. An AI agent such as Claude Code, Codex or Cursor that connects to it can look at the network and manage it: tell it "add this machine to the home network, in the servers group", and it creates the enrollment token, gives the install command and checks that the node came online. What it may do is decided by the token you issue for it.

## Issue an MCP token

In the web interface under "Settings → MCP", or on the server (with Docker, put `docker compose exec controller` in front):

```sh
i3tctl mcp token create --name claude-code --scope read,nodes:enroll --expires-in 30d
```

The token is shown only once. `--name` says who it is for; every change it makes is recorded under that name. A lifetime is required, at most 90 days. With `--network <NETWORK>` it sees and changes only that network. `--scope` lists what it may do; give only what is needed:

| Scope | Allows |
| --- | --- |
| `read` | Read-only: status, networks, nodes, routes and paths, exits, access checks, test results, statistics, the operation log, and the settings of groups, rules, proxies, port forwards and node pairs |
| `nodes:enroll` | Add nodes: create, list and delete enrollment tokens; see which node joined with one and whether it is online |
| `nodes:write` | Change and delete nodes, successors, switch relays and exits on and off |
| `config:write` | Groups and members, access rules, proxies, port forwards, node-pair settings |
| `tests:run` | Start and cancel tests |
| `updates:write` | Update settings, check for updates, force updates. Acts on the whole controller: not for a token limited to one network |
| `networks:write` | Create, change and delete networks. Acts on the whole controller: not for a token limited to one network |

A token without `config:write` does not see proxy passwords.

## Give it to the client

The MCP endpoint is `/api/v1/mcp` on the admin API address; the token goes in the header `Authorization: Bearer <MCP TOKEN>`:

```sh
# Claude Code
claude mcp add --transport http ice3tier http://127.0.0.1:20332/api/v1/mcp --header "Authorization: Bearer <MCP TOKEN>"

# Codex: the token is read from an environment variable
export I3T_MCP_TOKEN=<MCP TOKEN>
codex mcp add ice3tier --url http://127.0.0.1:20332/api/v1/mcp --bearer-token-env-var I3T_MCP_TOKEN
```

Other clients take the same address and header in their MCP configuration. For example Cursor's `mcp.json`:

```json
{
  "mcpServers": {
    "ice3tier": {
      "url": "http://127.0.0.1:20332/api/v1/mcp",
      "headers": { "Authorization": "Bearer <MCP TOKEN>" }
    }
  }
}
```

The MCP endpoint is on the same address as the web interface: it listens only on the server's `127.0.0.1:20332`, in plain HTTP. When the agent runs on another machine, forward the port over SSH as you do for [the web interface](../../deploy/controller/), and keep `127.0.0.1` in the address. If you move the admin API to another address with `--admin-listen`, the MCP endpoint is exposed there too.

## List and revoke

```sh
i3tctl mcp token list
i3tctl mcp token revoke <ID>   # its next call is refused
i3tctl log                     # changes made through MCP name the token that made them
```

## Also worth knowing

- An MCP token works only on the MCP endpoint; it is not an admin token. Issuing, listing and revoking tokens takes the admin token, so an agent cannot do it and cannot give itself more rights.
- Tools that delete things, such as deleting a node or a rule, are marked as destructive (MCP's `destructiveHint`), so that the client can ask you before running them. When you let an agent change things, look at what it is about to call, and do not set the destructive tools to run without asking.
- Tokens are signed with `mcp.key` in the data directory, not with `controller.key`. Take it along when you back up, see [Backup and restore](../backup/). To void every token issued so far: stop the controller, delete `mcp.key`, start it again. It generates a new key; the earlier tokens are no longer accepted and are listed as revoked.
- The MCP protocol revisions served are 2025-03-26, 2025-06-18, 2025-11-25 and 2026-07-28, over Streamable HTTP. There is no OAuth: you issue the token and put it in the client.
