---
title: Upgrading
description: Nodes update themselves. The controller is upgraded by hand.
---

## Nodes

Nodes update themselves. The controller fetches signed releases and passes them to the nodes, which verify, install and restart, and roll back if the new version fails to start.

Show the state:

```sh
i3tctl update show
```

To upgrade a node by hand, run the install script on it again; it keeps its enrollment.

## Controller

The controller is upgraded by hand. Data and settings are kept.

With Docker:

```sh
docker compose pull && docker compose up -d
```

With the install script, run it again on the server:

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh |
  sh -s -- --controller
```

The [CHANGELOG](https://github.com/fuqiuluo/ice3tier/blob/main/CHANGELOG.md) says which parts each release asks you to upgrade.

## From 0.1.34 or older

The controller now needs PostgreSQL, and the old data is not carried over: it starts empty. Create the networks again; every node has to join again with a new enrollment token. The old `controller.db` stays where it is and is no longer read.

With the install script, pass `--database-url` as in [Install the controller](../../deploy/controller/) this once; later upgrades need nothing extra. The admin token is new as well: the script prints it at the end.
