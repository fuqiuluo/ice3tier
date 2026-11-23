---
title: Other ways to install
description: Installing without access to GitHub, prebuilt binaries and building from source.
---

## Without access to GitHub

Download the script and the programs for the machine's platform on a computer that can reach GitHub (file names are listed under [Prebuilt binaries](#prebuilt-binaries)):

```sh
curl -fLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh
curl -fLO https://github.com/fuqiuluo/ice3tier/releases/latest/download/i3t-linux-x86_64
```

Copy them into one directory on the machine and install from there:

```sh
sh install.sh --from . --token <enrollment-token>
```

For the controller, download `i3t-controller-<platform>` and `i3tctl-<platform>` and run:

```sh
sh install.sh --from . --controller --public-addr <public-address>:20331 \
  --database-url postgres://<user>:<password>@<host>/<database>
```

If you have a mirror laid out like GitHub Releases, pass `--release-base <url>` instead.

Nodes get their updates from the controller, so later on only the controller needs a release source it can reach:

```sh
i3tctl update set --source <url-or-directory>
```

## Prebuilt binaries

Download the programs for your platform from the [latest release](https://github.com/fuqiuluo/ice3tier/releases/latest). Each platform has three files: the node `i3t-<platform>`, the controller `i3t-controller-<platform>` and the CLI `i3tctl-<platform>`.

| Platform | `<platform>` in the file name |
| --- | --- |
| Linux x86_64 | `linux-x86_64` |
| Linux aarch64 | `linux-aarch64` |
| Windows x86_64 | `windows-x86_64`; the node is a `.zip`, the other two are `.exe` |
| macOS (Apple silicon) | `macos-aarch64` |
| macOS (Intel) | `macos-x86_64` |

Run them without the install script, in the same order:

```sh
i3t-controller --data-dir /var/lib/i3t-controller \
  --database-url postgres://<user>:<password>@<host>/<database> --public-addr <public-address>:20331
echo <enrollment-token> | i3t join
i3t run
```

The controller's data directory holds its key `controller.key` and the cache of update packages; networks, nodes and settings are in a PostgreSQL database, version 16 or newer. The connection string has the form `postgres://USER:PASSWORD@HOST[:PORT]/DBNAME`; the `host=… user=… dbname=…` form works too. `i3t-controller` takes it from the option `--database-url`, then from the environment variable `I3T_DATABASE_URL`, then from a one-line file `database.url` in the data directory. It contains the password, so prefer the environment variable or the file over the command line. The connection to the database is not encrypted: keep the database on the same machine or on a trusted private network.

Raw systemd units and the polkit rule are in [`deploy/systemd`](https://github.com/fuqiuluo/ice3tier/tree/main/deploy/systemd) and [`deploy/polkit`](https://github.com/fuqiuluo/ice3tier/tree/main/deploy/polkit).

Run this way, the virtual network adapter needs:

| Platform | Needs |
| --- | --- |
| Linux | `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE` (granted by `deploy/systemd/i3t.service`); `deploy/polkit/50-i3t-resolved.rules` for non-root `systemd-resolved` DNS |
| Windows | Run as administrator; `wintun.dll` next to `i3t.exe` (in the release zip) |
| macOS | Run as root |

## Build from source

Requires Rust 1.91 or newer, and Node.js 22 with pnpm for the web UI.

```sh
git clone https://github.com/fuqiuluo/ice3tier.git
cd ice3tier
(cd web && pnpm install && pnpm build)   # the controller embeds the web UI
cargo build --release
```

The programs are in `target/release/`. The controller's Docker image is built from [`deploy/docker/Dockerfile`](https://github.com/fuqiuluo/ice3tier/blob/main/deploy/docker/Dockerfile).
