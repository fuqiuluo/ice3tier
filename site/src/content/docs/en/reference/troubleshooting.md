---
title: Troubleshooting
description: Common symptoms and what to do.
---

## `i3t join` cannot reach the controller

Check that the machine reaches the controller on TCP 20331, and that the `--public-addr` given when installing the controller is an address nodes can use.

## Invalid enrollment token: unknown, used or expired

A token works once. Create a new one.

## The node stays offline

Read its log:

```sh
sudo journalctl -u i3t -n 50   # Linux
cat /var/log/i3t.log           # macOS
```

## Two nodes are online but cannot reach each other

They have no direct path and no relay both can reach: see [Set up a relay](../../deploy/relay/). `sudo i3t status` shows the route to each node.

## With firewalld, other nodes cannot reach this machine

```sh
sudo firewall-cmd --permanent --zone=trusted --add-interface=i3t0
sudo firewall-cmd --reload
```

## Names do not resolve

```sh
sudo i3t hosts --apply
```

Or use the virtual IP.

## The admin token did not show up during install

```sh
sudo journalctl -u i3t-controller --no-pager
```
