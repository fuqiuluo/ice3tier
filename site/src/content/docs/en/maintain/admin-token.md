---
title: Lost admin token
description: Reset the admin token.
---

On the server:

```sh
sudo systemctl stop i3t-controller
sudo -u i3t-controller /usr/local/bin/i3t-controller \
  --data-dir /var/lib/i3t-controller --reset-admin-token
sudo systemctl start i3t-controller
```

It prints a new token; the old one stops working.

If the admin token did not show up during install, it is still in the service's log:

```sh
sudo journalctl -u i3t-controller --no-pager
```
