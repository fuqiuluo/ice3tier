---
title: Default MTU of the virtual adapter
description: What the virtual adapter's MTU is, where the default comes from and when to change it.
sidebar:
  order: 3
---

How many bytes an IP packet on a node's virtual adapter may have.

| Setting | Default | Range | Where |
| --- | --- | --- | --- |
| Default MTU | 1280 bytes | 576 – 1500 | Network → Virtual adapter |

With the command line:

```sh
i3tctl network set --vnet-mtu 1400
```

Nodes reinstall their virtual adapter as soon as they get the setting. No restart is needed.

A machine can set its own; restart the node afterwards:

```sh
sudo i3t set mtu 1200
```

A machine with a value of its own does not follow the network's default. Set it back to 1280 and it follows the network again.

## How it works

Applications need not care about the MTU: the kernels at both ends use it to decide how much data each TCP packet carries, and a larger packet is cut up by the kernel, or the sender is told it is too big.

An IP packet on the virtual adapter travels between nodes as one datagram on their connection. How much a datagram holds depends on the line underneath: a little over 1100 bytes when a connection has just been set up, and a little over 1300 once path MTU discovery has finished. A packet that does not fit is sent as two pieces and put together again at the other end.

A 1280-byte packet fits whole once discovery has finished. That is where the default comes from.

## Choosing

- The default of 1280 suits nearly every line. Leave it.
- **Higher** (up to 1500): each packet carries a little more. But above 1300 or so every full packet goes as two pieces, the number of packets on the wire doubles, and things get slower.
- **Lower**: only worth it where the line underneath carries very small packets and 1280-byte packets are always cut in two. At 1100 or so nothing is cut any more, at the price of a tenth less data per packet.

Two nodes may use different values: TCP goes by the smaller one.
