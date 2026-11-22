---
title: Segmentation offload
description: What segmentation offload on the virtual adapter is, how it works, what turning it on buys and when to turn it off.
sidebar:
  order: 2
---

On Linux nodes, the virtual adapter and the kernel exchange large blocks of data instead of single packets.

| Setting | Default | Where |
| --- | --- | --- |
| Segmentation offload | On | Network → Virtual adapter |

With the command line:

```sh
i3tctl network set --vnet-offload off
```

Nodes reinstall their virtual adapter as soon as they get the setting. No restart is needed.

A machine can turn it off for itself; restart the node afterwards:

```sh
sudo i3t set offload off
```

It is used only where both the network's switch and the machine's are on.

## How it works

When a program sends through the virtual adapter, the kernel first cuts the data into packets no larger than the MTU and hands them to the node one by one. Packets from a peer are written back to the kernel one by one as well. That is one system call per packet, and one pass through the kernel's send or receive path per packet.

With the switch on, both directions move in blocks:

- **Sending**: the kernel hands the node a block of up to 64 KB as it is, and the node cuts it into packets and completes their checksums. At the default MTU a block is about fifty packets.
- **Receiving**: packets that arrived together and follow one another on the same connection are merged into one block and given to the kernel in one go.

The packets on the wire are the same as without it. The peer cannot tell, so the two ends need not agree.

## When it applies

- Linux only. On Windows and macOS the switch changes nothing.
- It depends on the kernel. Blocks for TCP exist in every version; blocks for UDP need Linux 6.2 or newer, and an older kernel gets the TCP part only. Where the kernel refuses, the node falls back to single packets by itself.
- Packets have to come thick enough. On a slow line or with little traffic a batch holds one packet, and there is nothing to merge.

## What it buys

- **Paths limited by CPU get much faster.** On a LAN, inside one data centre or on a weak CPU, the same traffic takes far less CPU and throughput can double.
- Where the line is the limit (home broadband, long-distance lines), throughput and latency stay as they are.

## Cost

- The merge buffers take a few megabytes of memory. They are allocated when there is something to merge.
- While one flow fills a very fast line, more data waits inside the nodes than without it, and other packets on that path, such as ping, get a few milliseconds slower.

## Choosing

It is on by default. Leave it. When transfers over the virtual adapter stall or arrive damaged, turn it off and try again to see whether it is the cause.
