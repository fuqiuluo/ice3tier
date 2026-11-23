---
title: Install script
description: The install script's options and the files it creates.
---

## Options

Linux and macOS use `install.sh`:

| Option | Meaning |
| --- | --- |
| `--controller` | Install the controller and `i3tctl` instead of the node |
| `--public-addr <host:port>` | Controller: the address nodes use; also starts the service |
| `--database-url <url>` | Controller: the PostgreSQL database it keeps its data in. `I3T_DATABASE_URL` works too |
| `--token <token>` | Node: join and start. `I3T_TOKEN` works too |
| `--can-relay`, `--can-exit` | Node: declare when joining that it may be a relay or an exit |
| `--no-vnet` | Node: no virtual network adapter |
| `--no-polkit` | Node: do not install the `systemd-resolved` polkit rule |
| `--version <tag>` | Install this release instead of the latest |
| `--release-base <url>` | Download from a mirror laid out like GitHub Releases |
| `--from <dir>` | Install programs from a local directory instead of downloading |
| `--uninstall`, `--purge` | Remove the service and programs; with `--purge` also state and settings |

Windows uses `install.ps1`. Options are environment variables and apply to one run only:

| Environment variable | Meaning |
| --- | --- |
| `I3T_TOKEN` | Join and start |
| `I3T_CAN_RELAY=1`, `I3T_CAN_EXIT=1` | Declare when joining that the node may be a relay or an exit |
| `I3T_VERSION` | Install this release instead of the latest |
| `I3T_RELEASE_BASE` | Download from a mirror laid out like GitHub Releases |
| `I3T_FROM` | Install `i3t.exe` and `wintun.dll` from a local directory instead of downloading |
| `I3T_UNINSTALL=1`, `I3T_PURGE=1` | Remove the service and the program; with `I3T_PURGE` also the key and settings |

## Files

Files `install.sh` creates:

| What | Where |
| --- | --- |
| Controller data | `/var/lib/i3t-controller` (`controller.key`, `database.url`, update cache) |
| Controller settings | `/etc/i3t/controller.env` (`I3T_PUBLIC_ADDR`, `I3T_CONTROLLER_ARGS`) |
| Controller and command line programs | `/usr/local/bin/i3t-controller`, `/usr/local/bin/i3tctl` |
| Node state and settings | `/var/lib/i3t` (settings in `config.toml`) |
| Node program | `/var/lib/i3t/bin/i3t`, run through the `i3t` command in `/usr/local/bin` |
| Services | `i3t-controller.service` and `i3t.service`; on macOS the launchd daemon `com.github.fuqiuluo.ice3tier` |
