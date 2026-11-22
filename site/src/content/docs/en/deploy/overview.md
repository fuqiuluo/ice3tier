---
title: Before you start
description: What you deploy, what the machines need and which ports to open.
---

These pages take you from nothing to a working network. Follow them in order: **the controller comes first**, because a node can only join with an enrollment token that the controller issues.

1. [Install the controller](../controller/)
2. [Add nodes](../nodes/)
3. [Set up a relay](../relay/)
4. [Check that it works](../verify/)

## What you deploy

| Part | Where | How many |
| --- | --- | --- |
| Controller (`i3t-controller`) and `i3tctl` | A Linux machine every node can reach, usually a server with a public address | One |
| Node (`i3t`) | Every machine you want in the network | One per machine |
| Relay | A node that other nodes can reach | At least one |

## Machines

- **Controller machine**: Linux (x86_64 or aarch64) with systemd, and an IP address or domain name that every node can reach.
- **Node machines**: Linux (x86_64, aarch64), macOS (Apple silicon, Intel) or Windows (x86_64).
- Root or `sudo` on each machine.
- The install script downloads from GitHub. If a machine cannot reach it, see [Without access to GitHub](../../reference/other-install/#without-access-to-github).

## Ports

Ports to open in the firewall or security group:

| Machine | Port | Open to | Used for |
| --- | --- | --- | --- |
| Controller | TCP 20331, UDP 20331 | All nodes | Nodes connect to the controller |
| Controller | TCP 20332 | Nobody | Web UI and admin API. Listens on `127.0.0.1` only; keep it closed |
| Relay node | UDP 20330, TCP 20330 | Other nodes | Relaying |
| Other nodes | None required | | Opening UDP 20330 helps other nodes connect directly |
