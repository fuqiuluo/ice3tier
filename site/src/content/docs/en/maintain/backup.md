---
title: Backup and restore
description: Back up the controller's data and restore it on the same server or a new one.
---

## Backup

A backup is two files: a dump of the database, and the controller's key `controller.key`. Back up while the controller runs.

With Docker:

```sh
(umask 077
 docker compose exec -T postgres pg_dump --username i3t --format custom i3t > controller.dump
 docker compose exec -T controller cat /data/controller.key > controller.key)
```

With the install script:

```sh
sudo sh -c 'umask 077; pg_dump --format custom --file controller.dump "$(cat /var/lib/i3t-controller/database.url)"'
sudo cp /var/lib/i3t-controller/controller.key controller.key
```

The dump holds all networks, nodes and settings and the admin token. Both files are secrets: the dump has the proxy passwords in it, and the key is the controller's identity. The commands above write them readable by their owner only; keep them that way.

:::caution
Both files are needed: nodes trust this key, and the database lists the nodes enrolled under it.
:::

## Restore

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

With the install script, first create an empty database as in [Install the controller](../../deploy/controller/), then:

```sh
pg_restore --no-owner --dbname postgres://i3t:<password>@127.0.0.1/i3t controller.dump
# install without starting, put the key in place, then start
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh |
  sh -s -- --controller --database-url postgres://i3t:<password>@127.0.0.1/i3t
sudo install -o i3t-controller -g i3t-controller -m 600 controller.key \
  /var/lib/i3t-controller/controller.key
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh |
  sh -s -- --controller --public-addr <public-address>:20331
```

To restore on the same server: stop the service (`sudo systemctl stop i3t-controller`), drop the database and create it again empty, run the `pg_restore` and `sudo install` lines above, then start the service.

Put the key in place before the controller starts: on a database that already belongs to a controller, it refuses to start without that controller's key rather than make a new one.

The admin token from the time of the backup keeps working. Nodes reconnect by themselves as long as the public address still leads to the controller. Nodes that joined after the backup was made have to join again with a new token.
