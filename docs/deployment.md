# Deployment guide

English | [简体中文](deployment.zh-CN.md)

This guide takes you from nothing to a working network. Follow the steps in order: **the controller comes first**, because a node can only join with an enrollment token that the controller issues.

1. [Install the controller](#step-1-install-the-controller)
2. [Open the web UI and create a network](#step-2-open-the-web-ui-and-create-a-network)
3. [Add nodes](#step-3-add-nodes)
4. [Set up a relay](#step-4-set-up-a-relay)
5. [Check that it works](#step-5-check-that-it-works)

## What you deploy

| Part                                         | Where                                                                    | How many        |
| -------------------------------------------- | ------------------------------------------------------------------------ | --------------- |
| Controller (`i3t-controller`) and `i3tctl`   | A Linux machine every node can reach, usually a server with a public address | One             |
| Node (`i3t`)                                 | Every machine you want in the network                                    | One per machine |
| Relay                                        | A node that other nodes can reach                                        | At least one    |

## Before you start

- **Controller machine**: Linux (x86_64 or aarch64) with systemd, and an IP address or domain name that every node can reach.
- **Node machines**: Linux (x86_64, aarch64), macOS (Apple silicon, Intel) or Windows (x86_64).
- Root or `sudo` on each machine.
- The install script downloads from GitHub. If a machine cannot reach it, see [Without access to GitHub](#without-access-to-github).

Ports to open in the firewall or security group:

| Machine     | Port                 | Open to     | Used for                                                    |
| ----------- | -------------------- | ----------- | ----------------------------------------------------------- |
| Controller  | TCP 20331, UDP 20331 | All nodes   | Nodes connect to the controller                             |
| Controller  | TCP 20332            | Nobody      | Web UI and admin API. Listens on `127.0.0.1` only; keep it closed |
| Relay node  | UDP 20330, TCP 20330 | Other nodes | Relaying                                                    |
| Other nodes | None required        |             | Opening UDP 20330 helps other nodes connect directly        |

## Step 1. Install the controller

On the server:

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --public-addr <public-address>:20331
```

`<public-address>` is the IP address or domain name nodes use to reach this machine. It is written into every enrollment token, so choose one that will not change. With a domain name you can move the controller to another machine later.

The script installs `i3t-controller` and `i3tctl` into `/usr/local/bin`, creates the systemd service `i3t-controller` (its own system user, started at boot) and starts it. At the end it prints the admin token:

```
Admin token (shown only once):

    <admin-token>
```

**Save the token.** The web UI and `i3tctl` sign in with it, and it is not shown again. If you lose it, see [Lost admin token](#lost-admin-token).

Check the service:

```sh
systemctl status i3t-controller
```

## Step 2. Open the web UI and create a network

The web UI listens on `127.0.0.1:20332` of the server and speaks plain HTTP, so it cannot be opened from outside. Forward the port over SSH from your own computer:

```sh
ssh -L 20332:127.0.0.1:20332 <user>@<server>
```

Keep that session open, open <http://127.0.0.1:20332>, sign in with the admin token and create a network, for example `home`.

With the command line instead, on the server:

```sh
export I3T_ADMIN_TOKEN=<admin-token>
i3tctl network create home
```

## Step 3. Add nodes

Each machine joins with its own enrollment token. A token works once and expires after 24 hours unless you choose otherwise.

**Create a token.** In the web UI open **Add node**, click **Create token**, then **Copy token only**. With the command line:

```sh
i3tctl token create
```

**Install and join.** On the machine, Linux or macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --token <enrollment-token>
```

This installs the node as a service, joins the network and starts the node. The service starts at boot: a systemd unit `i3t` under its own system user on Linux, a launchd daemon on macOS.

Check on the machine:

```sh
sudo i3t status
```

The `controller` line should say `connected`, and the node shows as online in the web UI. Repeat with a new token for every machine.

Other cases:

- **Installed without a token.** Join afterwards, which also starts the service:

  ```sh
  echo <enrollment-token> | sudo i3t join
  ```

- **Windows.** In a PowerShell window opened as administrator:

  ```powershell
  $env:I3T_TOKEN = '<enrollment-token>'; irm https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.ps1 | iex
  ```

  The node is installed as the system service `i3t`: it runs in the background and starts at boot. You can also install without a token and join later with `echo <enrollment-token> | i3t join`, which starts the service. `i3t status` shows its state; to uninstall, `$env:I3T_UNINSTALL = '1'; irm … | iex`.

- **Linux without systemd.** The script installs `/usr/local/bin/i3t` only. Join with `echo <enrollment-token> | sudo i3t join` and keep `sudo i3t run` running with your init system.

## Step 4. Set up a relay

Two nodes connect directly when they can: on the same LAN, through an open port, or by hole punching. When they cannot, they talk through a relay. **Without a relay, such a pair has no connection.** The server that runs the controller is usually the right place for one.

1. Install a node on the server as in step 3, and declare that it may relay:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --token <enrollment-token> --can-relay
   ```

   For a node that has already joined:

   ```sh
   sudo i3t set can-relay on
   sudo systemctl restart i3t   # macOS: sudo launchctl kickstart -k system/com.github.fuqiuluo.ice3tier
   ```

2. Open UDP 20330 and TCP 20330 on the server.

3. Enable the relay: turn on the relay switch on the node's page in the web UI, or run:

   ```sh
   i3tctl relay enable <node>
   ```

   The command lists the node's addresses and whether the controller can reach each of them.

Declaring and enabling are both needed: the machine says it may relay, and the admin turns it on. Relay addresses are found automatically. Only when a provider or router maps a port on another IP address to the machine do you have to name it, then restart the node:

```sh
sudo i3t set relay-address <ip>:<port>
```

## Step 5. Check that it works

On any node:

```sh
sudo i3t status              # controller connected, and the route to every other node
sudo i3t ping <node>         # round trips to another node
ping <virtual-ip>            # through the virtual network adapter
ssh <node>.<network>.i3t     # by name, for example nas.home.i3t
```

Names work out of the box on Linux with `systemd-resolved`. Elsewhere, `sudo i3t hosts --apply` writes them into the hosts file, or use the virtual IP.

From here on everything is done in the web UI or with `i3tctl`: exits and proxies, port forwards, groups and access rules.

## Maintenance

### Upgrading

- **Nodes update themselves.** The controller fetches signed releases and passes them to the nodes, which verify, install and restart. `i3tctl update show` shows the state. To upgrade a node by hand, run the install script on it again; it keeps its enrollment.
- **The controller is upgraded by hand.** Run the script again on the server. Data and settings are kept:

  ```sh
  curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller
  ```

[CHANGELOG.md](../CHANGELOG.md) says which parts each release asks you to upgrade.

### Backup and restore

Back up while the controller runs:

```sh
sudo /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller --backup-to /root/i3t-controller-backup
```

The target must be a new or empty directory. The backup holds all networks, nodes and settings, the admin token and the controller's key. Do not copy `controller.db` by itself: recent changes may still be in the files next to it.

Restore, on the same server or on a new one where the controller has been installed as in step 1:

```sh
sudo systemctl stop i3t-controller
sudo mv /var/lib/i3t-controller /var/lib/i3t-controller.old
sudo cp -a /root/i3t-controller-backup /var/lib/i3t-controller
sudo chown -R i3t-controller: /var/lib/i3t-controller
sudo systemctl start i3t-controller
```

Nodes reconnect by themselves as long as the public address still leads to the controller. Nodes that joined after the backup was made have to join again with a new token.

### Lost admin token

```sh
sudo systemctl stop i3t-controller
sudo -u i3t-controller /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller --reset-admin-token
sudo systemctl start i3t-controller
```

It prints a new token; the old one stops working.

### Uninstalling

```sh
# Node. Add --purge to delete its identity and settings as well
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --uninstall

# Controller. Add --purge to delete its data and configuration as well
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --uninstall --controller
```

After uninstalling a node, delete it in the web UI or with `i3tctl node delete <node>`.

## Without access to GitHub

Download the script and the programs for the machine's platform on a computer that can reach GitHub (file names are listed in the [README](../README.md#prebuilt-binaries)):

```sh
curl -fLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh
curl -fLO https://github.com/fuqiuluo/ice3tier/releases/latest/download/i3t-linux-x86_64
```

Copy them into one directory on the machine and install from there:

```sh
sh install.sh --from . --token <enrollment-token>
```

For the controller, download `i3t-controller-<platform>` and `i3tctl-<platform>` and run `sh install.sh --from . --controller --public-addr <public-address>:20331`.

If you have a mirror laid out like GitHub Releases, pass `--release-base <url>` instead. Nodes get their updates from the controller, so later on only the controller needs a release source it can reach; `i3tctl update set --source <url-or-directory>` changes it.

## Troubleshooting

| Symptom                                               | What to do                                                                                                                                          |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `i3t join` cannot reach the controller                | Check that the machine reaches the controller on TCP 20331, and that `--public-addr` is an address nodes can use                                    |
| `Invalid enrollment token: unknown, used or expired`  | A token works once. Create a new one                                                                                                                |
| The node stays offline                                | Read its log: `sudo journalctl -u i3t -n 50` on Linux, `/var/log/i3t.log` on macOS                                                                  |
| Two nodes are online but cannot reach each other      | They have no direct path and no relay both can reach: see [step 4](#step-4-set-up-a-relay). `sudo i3t status` shows the route to each node          |
| With firewalld, other nodes cannot reach this machine | `sudo firewall-cmd --permanent --zone=trusted --add-interface=i3t0 && sudo firewall-cmd --reload`                                                   |
| Names do not resolve                                  | `sudo i3t hosts --apply`, or use the virtual IP                                                                                                     |
| The admin token did not show up during install        | `sudo journalctl -u i3t-controller --no-pager`                                                                                                      |

## Reference

Files the install script creates:

| What                                 | Where                                                                        |
| ------------------------------------ | ---------------------------------------------------------------------------- |
| Controller data                      | `/var/lib/i3t-controller`                                                    |
| Controller settings                  | `/etc/i3t/controller.env` (`I3T_PUBLIC_ADDR`, `I3T_CONTROLLER_ARGS`)         |
| Controller and command line programs | `/usr/local/bin/i3t-controller`, `/usr/local/bin/i3tctl`                     |
| Node state and settings              | `/var/lib/i3t` (settings in `config.toml`)                                   |
| Node program                         | `/var/lib/i3t/bin/i3t`, run through the `i3t` command in `/usr/local/bin`    |
| Services                             | `i3t-controller.service` and `i3t.service`; on macOS the launchd daemon `com.github.fuqiuluo.ice3tier` |

Install script options:

| Option                      | Meaning                                                                    |
| --------------------------- | -------------------------------------------------------------------------- |
| `--controller`              | Install the controller and `i3tctl` instead of the node                    |
| `--public-addr <host:port>` | Controller: the address nodes use; also starts the service                 |
| `--token <token>`           | Node: join and start. `I3T_TOKEN` works too                                |
| `--can-relay`, `--can-exit` | Node: declare when joining that it may be a relay or an exit               |
| `--no-vnet`                 | Node: no virtual network adapter                                           |
| `--no-polkit`               | Node: do not install the `systemd-resolved` polkit rule                    |
| `--version <tag>`           | Install this release instead of the latest                                 |
| `--release-base <url>`      | Download from a mirror laid out like GitHub Releases                       |
| `--from <dir>`              | Install programs from a local directory instead of downloading             |
| `--uninstall`, `--purge`    | Remove the service and programs; with `--purge` also state and settings    |
