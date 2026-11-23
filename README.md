<div align="center">

<img src="web/public/favicon.svg" alt="ice3tier" width="96" />

# ice3tier

**A self-hosted mesh network for your own machines.**

[![CI](https://github.com/fuqiuluo/ice3tier/actions/workflows/ci.yml/badge.svg)](https://github.com/fuqiuluo/ice3tier/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/fuqiuluo/ice3tier?include_prereleases)](https://github.com/fuqiuluo/ice3tier/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Rust](https://img.shields.io/badge/rust-1.91%2B-orange)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](#platform-support)

English | [简体中文](README.zh-CN.md)

</div>

ice3tier connects the machines you own into one private network. Every node gets a virtual network adapter and a virtual IP. Nodes talk to each other directly whenever they can, and through your own relays when they cannot. One controller with a web UI manages the network.

> [!NOTE]
> ice3tier is under active development. Its APIs and protocols may still change between releases.

## Features

- **Virtual network.** Each node gets a virtual adapter and IP by default. Programs reach other nodes by IP or by name, for example `ssh nas.home.i3t`.
- **Direct when possible.** Nodes connect directly on the same LAN, through an open port, or by hole punching. Otherwise traffic goes through a relay, over TCP when UDP is blocked. Relays forward encrypted data only.
- **Exit proxies.** Open a SOCKS5/HTTP proxy on one node and send its traffic out through another node's network. Proxies support credentials and the optional ice3proxy transport; exits can have traffic quotas.
- **Port forwarding.** Forward a port on one node to a service on another node or on that node's LAN.
- **Group-based access control.** One kind of rule: nodes in group A may reach nodes in group B.
- **Central management.** One controller with a web UI and a CLI. Run several isolated networks side by side.
- **Signed self-updates.** Nodes fetch, verify, install and restart into new releases, and roll back if the new version fails to start.

## How it works

```
                 ┌──────────────────────────────┐
                 │          controller          │   web UI · admin API · i3tctl
                 └──────────────┬───────────────┘
                                │ configuration and membership
             ┌──────────────────┼──────────────────┐
             ▼                  ▼                  ▼
        ┌─────────┐        ┌─────────┐        ┌─────────┐
        │  node A │◀══════▶│  relay  │◀══════▶│  node B │
        └─────────┘        └─────────┘        └─────────┘
             ▲                                     ▲
             └════════════ direct path ════════════┘
```

- Each pair of nodes shares a single end-to-end encrypted QUIC connection. Switching between the relay and a direct path does not break the connections on top of it.
- Nodes authenticate each other and the controller by their Ed25519 public keys.
- The controller only distributes configuration. Nodes that are already online keep working while it is down.

## Quick start

Deploy the controller first, then the nodes: a node joins with a token that the controller issues. The [deployment guide](docs/deployment.md) covers every step in detail, with ports, Windows, upgrades and backups.

**1. Install the controller** on a Linux server that every node can reach, with TCP and UDP port 20331 open. With Docker, this starts it together with the PostgreSQL database it keeps its data in:

```sh
curl -fsSLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/docker/compose.yaml
echo 'I3T_PUBLIC_ADDR=<public-address>:20331' > .env
docker compose up -d
docker compose logs controller   # the admin token is printed once, on the first start
```

Or, with a PostgreSQL (16 or newer) of your own, install it as a systemd service; the script prints the admin token once:

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --public-addr <public-address>:20331 --database-url postgres://<user>:<password>@<host>/<database>
```

Use the token to sign in to the web UI and `i3tctl`. The web UI listens on `127.0.0.1:20332` only. To open it from another machine, forward the port over SSH:

```sh
ssh -L 20332:127.0.0.1:20332 <controller-host>
```

**2. Create a network and an enrollment token.** In the web UI, create a network, then click **Add node** and create a token. With the CLI, on the server:

```sh
export I3T_ADMIN_TOKEN=<admin-token>
i3tctl network create home
i3tctl token create   # one token per machine
```

With Docker, `i3tctl` is inside the controller's container: `docker compose exec controller i3tctl --token <admin-token> network create home`.

**3. Install a node on each machine.** On Linux and macOS:

```sh
# add --can-relay or --can-exit if the machine may serve as one
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --token <enrollment-token>
sudo i3t status
```

This installs the node as a service, joins the network and starts it: a systemd unit under its own system user on Linux, a launchd daemon on macOS. For Windows, see the [deployment guide](docs/deployment.md#step-3-add-nodes).

**4. Enable relays and exits, then add proxies and port forwards** in the web UI, or with the CLI. Nodes that cannot connect directly talk through a relay, so enable at least one, usually on the controller's server:

```sh
i3tctl relay enable <node>
i3tctl exit enable <node>
i3tctl proxy add <listening-node> 127.0.0.1:1080 <exit-node>
curl -x socks5h://127.0.0.1:1080 https://example.com
```

## Other ways to install

### Prebuilt binaries

Download the programs for your platform from the [latest release](https://github.com/fuqiuluo/ice3tier/releases/latest):

| Platform              | Node                    | Controller                         | CLI                        |
| --------------------- | ----------------------- | ---------------------------------- | -------------------------- |
| Linux x86_64          | `i3t-linux-x86_64`      | `i3t-controller-linux-x86_64`      | `i3tctl-linux-x86_64`      |
| Linux aarch64         | `i3t-linux-aarch64`     | `i3t-controller-linux-aarch64`     | `i3tctl-linux-aarch64`     |
| Windows x86_64        | `i3t-windows-x86_64.zip` | `i3t-controller-windows-x86_64.exe` | `i3tctl-windows-x86_64.exe` |
| macOS (Apple silicon) | `i3t-macos-aarch64`     | `i3t-controller-macos-aarch64`     | `i3tctl-macos-aarch64`     |
| macOS (Intel)         | `i3t-macos-x86_64`      | `i3t-controller-macos-x86_64`      | `i3tctl-macos-x86_64`      |

Run them without the install script, in the same order:

```sh
i3t-controller --data-dir /var/lib/i3t-controller --database-url postgres://<user>:<password>@<host>/<database> --public-addr <public-address>:20331
echo <enrollment-token> | i3t join
i3t run
```

The connection string contains the database password. To keep it off the command line, set the environment variable `I3T_DATABASE_URL`, or write it into a file named `database.url` in the data directory.

Raw systemd units and the polkit rule are in [`deploy/systemd`](deploy/systemd) and [`deploy/polkit`](deploy/polkit).

### Build from source

Requires Rust 1.91 or newer, and Node.js 22 with pnpm for the web UI.

```sh
git clone https://github.com/fuqiuluo/ice3tier.git
cd ice3tier
(cd web && pnpm install && pnpm build)   # the controller embeds the web UI
cargo build --release
```

The programs are in `target/release/`. The controller's Docker image is built from [`deploy/docker/Dockerfile`](deploy/docker/Dockerfile).

## Platform support

| Platform | Architectures       | Virtual network needs                                                 |
| -------- | ------------------- | --------------------------------------------------------------------- |
| Linux    | x86_64, aarch64     | `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE` (granted by [`deploy/systemd/i3t.service`](deploy/systemd/i3t.service)); [`deploy/polkit/50-i3t-resolved.rules`](deploy/polkit/50-i3t-resolved.rules) for non-root `systemd-resolved` DNS |
| Windows  | x86_64              | Run as administrator; `wintun.dll` next to `i3t.exe` (in the release zip) |
| macOS    | Apple silicon, Intel | Run as root                                                          |

## Development

The controller's tests need a PostgreSQL. `scripts/test-postgres.sh start` starts a throwaway one, from an installed PostgreSQL or with Docker, and prints the variables to export:

```sh
export $(scripts/test-postgres.sh start)
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

See [`web/README.md`](web/README.md) for the web UI and [CHANGELOG.md](CHANGELOG.md) for release notes.

## Contributing

Bug reports and pull requests are welcome. Before opening a pull request, please make sure `cargo fmt --check`, `cargo clippy` and `cargo test --workspace` pass, and run `pnpm lint` and `pnpm test` in `web/` if you touched the web UI.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
