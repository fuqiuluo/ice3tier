---
title: Bundle small packets
description: What bundling small packets is, how it works, what turning it on buys and what it costs.
sidebar:
  order: 1
---

On a direct route, small packets going to the same node at the same moment leave in one packet.

| Setting | Default | Where |
| --- | --- | --- |
| Bundle small packets | On | Network → Virtual adapter |

With the command line:

```sh
i3tctl network set --bundle-small-packets off
```

Nodes apply it as soon as they get the setting. No reconnect is needed.

## How it works

The return direction of a download is all small packets: TCP acknowledgements of fifty-odd bytes, one for every two data packets. Sent one by one, they are half as many packets as the data.

Some lines limit packets per second in one direction. The small packets use the budget up first: the download stalls there, and other packets in that direction, such as ping, are dropped with them.

Twenty or so acknowledgements fit into one packet. Sent together, the packets on the way back shrink to a fraction.

Only small packets (up to 256 bytes) are bundled. Whether they wait depends on how thick they come:

- **At hand together**: small packets read from the virtual adapter in the same round leave in one packet at the end of the round, with no delay.
- **Sparse** (more than 2 ms after the last one, such as ping or a game's packets): sent at once, as without bundling.
- **Thick** (such as the acknowledgements of a running download): they wait until a packet is full, or for a millisecond or two, and then leave.

Large packets neither wait nor get bundled. A large packet for the same node sends the waiting small ones first, so the order is kept.

## When it applies

- The two nodes are connected directly. Nothing is bundled through a relay.
- Both ends run a version that understands bundled packets. With an older version on one end, packets go one by one as before.

Waiting a millisecond or two needs a timer. Where timers are much coarser (Windows ticks every 15 ms or so by default), a wait that keeps running late switches the waiting off for a while, and only packets that are at hand together are bundled.

## Why turn it on

- **Far fewer packets on the way back.** A download's acknowledgements shrink to a fraction.
- **Much faster on a line that limits packets per second.** Small packets no longer use the budget up, the download does not stall, and other packets in that direction are not dropped with them.

## What it costs

When small packets come thick, each may wait a millisecond or two. Sparse ones never wait.

## What to pick

It is on by default. Leave it. To compare, or when tracking down a problem, turn it off and measure again.

It bundles small packets of the virtual adapter. Proxies and port forwards travel inside QUIC; for the packets on their way back, see [QUIC ACK frequency](../ack-frequency/).
