---
title: Backup and restore
description: Back up the controller's data and restore it on the same server or a new one.
---

## Backup

Back up while the controller runs:

```sh
sudo /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller \
  --backup-to /root/i3t-controller-backup
```

The target must be a new or empty directory. The backup holds all networks, nodes and settings, the admin token and the controller's key.

:::caution
Do not copy `controller.db` by itself: recent changes may still be in the files next to it.
:::

## Restore

On the same server, or on a new one where the controller has been installed as in [Install the controller](../../deploy/controller/):

```sh
sudo systemctl stop i3t-controller
sudo mv /var/lib/i3t-controller /var/lib/i3t-controller.old
sudo cp -a /root/i3t-controller-backup /var/lib/i3t-controller
sudo chown -R i3t-controller: /var/lib/i3t-controller
sudo systemctl start i3t-controller
```

Nodes reconnect by themselves as long as the public address still leads to the controller. Nodes that joined after the backup was made have to join again with a new token.
