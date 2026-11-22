---
title: Check that it works
description: Confirm that nodes reach the controller and each other.
---

On any node:

```sh
sudo i3t status              # controller connected, and the route to every other node
sudo i3t ping <node>         # round trips to another node
ping <virtual-ip>            # through the virtual network adapter
ssh <node>.<network>.i3t     # by name, for example nas.home.i3t
```

## Names

Names work out of the box on Linux with `systemd-resolved`. Elsewhere, write them into the hosts file, or use the virtual IP:

```sh
sudo i3t hosts --apply
```

## From here on

Everything else is done in the web UI or with `i3tctl`: exits and proxies, port forwards, groups and access rules.

If something is off, see [Troubleshooting](../../reference/troubleshooting/).
