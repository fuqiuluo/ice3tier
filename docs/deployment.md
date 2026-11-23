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
| PostgreSQL database                          | Next to the controller, which keeps its data in it                       | One             |
| Node (`i3t`)                                 | Every machine you want in the network                                    | One per machine |
| Relay                                        | A node that other nodes can reach                                        | At least one    |

## Before you start

- **Controller machine**: Linux (x86_64 or aarch64), and an IP address or domain name that every node can reach. Either Docker with `docker compose`, or systemd and a PostgreSQL database, version 16 or newer.
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

The controller keeps networks, nodes and all settings in a PostgreSQL database. There are two ways to install it: with Docker, which brings its own PostgreSQL, or with the install script and a PostgreSQL of your own.

In both, `<public-address>` is the IP address or domain name nodes use to reach this machine. It is written into every enrollment token, so choose one that will not change. With a domain name you can move the controller to another machine later.

**With Docker.** On the server:

```sh
curl -fsSLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/docker/compose.yaml
echo 'I3T_PUBLIC_ADDR=<public-address>:20331' > .env
docker compose up -d
docker compose logs controller   # the admin token is printed once, on the first start
```

This starts the controller together with its PostgreSQL. Run the later `docker compose` commands of this guide in the same directory. The settings are in the `.env` file next to `compose.yaml`:

| Setting                 | Meaning                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------- |
| `I3T_PUBLIC_ADDR`       | Required: the address nodes use                                                                      |
| `I3T_VERSION`           | Version to run, without `v`, for example `0.1.35`. Default `latest`                                  |
| `I3T_POSTGRES_PASSWORD` | Database password, default `i3t`. The database port is not published; only the controller reaches it |

The image is `ghcr.io/fuqiuluo/ice3tier-controller` (linux amd64 and arm64), with `i3t-controller` and `i3tctl` in it. TCP and UDP 20331 are published on all addresses, the web UI's port 20332 only on `127.0.0.1` of the server. The data is in two named volumes: `postgres` holds the database, `controller` the controller's key and the cache of update packages.

**With the install script.** The script does not install PostgreSQL: you need a database, version 16 or newer. To create one on the same machine, on Debian or Ubuntu:

```sh
sudo apt-get install -y postgresql
sudo -u postgres psql -c "CREATE ROLE i3t LOGIN PASSWORD '<password>'" -c "CREATE DATABASE i3t OWNER i3t"
```

Its connection string is `postgres://i3t:<password>@127.0.0.1/i3t`. Then install the controller:

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --public-addr <public-address>:20331 --database-url postgres://<user>:<password>@<host>/<database>
```

The script installs `i3t-controller` and `i3tctl` into `/usr/local/bin`, creates the systemd service `i3t-controller` (its own system user, started at boot) and starts it. It writes the connection string to `/var/lib/i3t-controller/database.url`, readable only by the service's user. The connection to the database is not encrypted: keep the database on the same machine or on a trusted private network.

Either way, the first start prints the admin token: in `docker compose logs controller`, or at the end of the script.

```
Admin token (shown only once):

    <admin-token>
```

**Save the token.** The web UI and `i3tctl` sign in with it, and it is not shown again. If you lose it, see [Lost admin token](#lost-admin-token).

Check the service:

```sh
docker compose ps                  # Docker
systemctl status i3t-controller    # install script
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

With Docker, `i3tctl` is inside the controller's container. Write every `i3tctl` command of this guide like this:

```sh
docker compose exec controller i3tctl --token <admin-token> network create home
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
- **The controller is upgraded by hand.** On the server; data and settings are kept:

  ```sh
  # Docker
  docker compose pull && docker compose up -d

  # Install script: run it again
  curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller
  ```

- **From 0.1.34 or older.** The controller now needs PostgreSQL, and the old data is not carried over: it starts empty. Create the networks again; every node has to join again with a new enrollment token. The old `controller.db` stays where it is and is no longer read. With the install script, pass `--database-url` as in [step 1](#step-1-install-the-controller) this once; later upgrades need nothing extra. The admin token is new as well: the script prints it at the end.

[CHANGELOG.md](../CHANGELOG.md) says which parts each release asks you to upgrade.

### Backup and restore

A backup is two files: a dump of the database, and the controller's key `controller.key`. Back up while the controller runs:

```sh
# Docker
docker compose exec -T postgres pg_dump --username i3t --format custom i3t > controller.dump
docker compose exec -T controller cat /data/controller.key > controller.key
chmod 600 controller.key

# Install script
sudo sh -c 'pg_dump --format custom --file controller.dump "$(cat /var/lib/i3t-controller/database.url)"'
sudo cp /var/lib/i3t-controller/controller.key controller.key
```

The dump holds all networks, nodes and settings and the admin token. Both files are needed: nodes trust this key, and the database lists the nodes enrolled under it.

Restore on a new server, with the same public address as before.

With Docker:

```sh
curl -fsSLO https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/docker/compose.yaml
echo 'I3T_PUBLIC_ADDR=<public-address>:20331' > .env
docker compose up -d --wait postgres
docker compose exec -T postgres pg_restore --username i3t --dbname i3t --no-owner < controller.dump
docker compose run --rm -T --entrypoint sh controller -c 'umask 077; cat > /data/controller.key' < controller.key
docker compose up -d
```

To restore on the same server, run `docker compose down --volumes` in place of the first two lines: it deletes the database and the key that are there.

With the install script, first create an empty database as in step 1, then:

```sh
pg_restore --no-owner --dbname postgres://i3t:<password>@127.0.0.1/i3t controller.dump
# install without starting, put the key in place, then start
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --database-url postgres://i3t:<password>@127.0.0.1/i3t
sudo install -o i3t-controller -g i3t-controller -m 600 controller.key /var/lib/i3t-controller/controller.key
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --public-addr <public-address>:20331
```

To restore on the same server: stop the service (`sudo systemctl stop i3t-controller`), drop the database and create it again empty, run the `pg_restore` and `sudo install` lines above, then start the service.

The admin token from the time of the backup keeps working. Nodes reconnect by themselves as long as the public address still leads to the controller. Nodes that joined after the backup was made have to join again with a new token.

### Lost admin token

```sh
# Docker
docker compose stop controller
docker compose run --rm controller --reset-admin-token
docker compose start controller

# Install script
sudo systemctl stop i3t-controller
sudo -u i3t-controller /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller --reset-admin-token
sudo systemctl start i3t-controller
```

It prints a new token; the old one stops working.

### Uninstalling

```sh
# Node. Add --purge to delete its identity and settings as well
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --uninstall

# Controller, with Docker. Add --volumes to delete the database and the controller's key as well
docker compose down

# Controller, with the install script. Add --purge to delete its key and settings as well
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --uninstall --controller
```

The install script never touches the PostgreSQL database, with or without `--purge`. Drop it yourself if you want it gone.

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

For the controller, download `i3t-controller-<platform>` and `i3tctl-<platform>` and run `sh install.sh --from . --controller --public-addr <public-address>:20331 --database-url postgres://<user>:<password>@<host>/<database>`.

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
| The admin token did not show up during install        | `sudo journalctl -u i3t-controller --no-pager`; with Docker, `docker compose logs controller`                                                       |
| The install script asks for `--database-url`          | The controller needs a PostgreSQL database: see [step 1](#step-1-install-the-controller)                                                            |
| The controller cannot connect to the database         | Check that PostgreSQL is running and that the connection string in `/var/lib/i3t-controller/database.url` is right                                  |

## Reference

Files the install script creates:

| What                                 | Where                                                                        |
| ------------------------------------ | ---------------------------------------------------------------------------- |
| Controller data                      | `/var/lib/i3t-controller` (`controller.key`, `database.url`, update cache)   |
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
| `--database-url <url>`      | Controller: its PostgreSQL database. `I3T_DATABASE_URL` works too          |
| `--token <token>`           | Node: join and start. `I3T_TOKEN` works too                                |
| `--can-relay`, `--can-exit` | Node: declare when joining that it may be a relay or an exit               |
| `--no-vnet`                 | Node: no virtual network adapter                                           |
| `--no-polkit`               | Node: do not install the `systemd-resolved` polkit rule                    |
| `--version <tag>`           | Install this release instead of the latest                                 |
| `--release-base <url>`      | Download from a mirror laid out like GitHub Releases                       |
| `--from <dir>`              | Install programs from a local directory instead of downloading             |
| `--uninstall`, `--purge`    | Remove the service and programs; with `--purge` also state and settings    |

The controller's data directory holds its key `controller.key` and the cache of update packages; networks, nodes and settings are in the database. The database connection string has the form `postgres://USER:PASSWORD@HOST[:PORT]/DBNAME`; the `host=… user=… dbname=…` form works too. `i3t-controller` takes it from the option `--database-url`, then from the environment variable `I3T_DATABASE_URL`, then from a one-line file `database.url` in the data directory. It contains the password, so prefer the environment variable or the file over the command line.
