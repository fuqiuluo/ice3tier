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

The controller is upgraded by hand. Run the script again on the server. Data and settings are kept:

```sh
curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh |
  sh -s -- --controller
```

The [CHANGELOG](https://github.com/fuqiuluo/ice3tier/blob/main/CHANGELOG.md) says which parts each release asks you to upgrade.
