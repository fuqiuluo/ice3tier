-- 节点的虚拟网卡的两项设置，按网络定、下发给节点：和内核之间是不是一大块一大块地交接（Linux 的分段卸载），和默认的 MTU。
-- 已有的网络取默认值：开着，1280。
ALTER TABLE networks ADD COLUMN vnet_offload INTEGER NOT NULL DEFAULT 1;
ALTER TABLE networks ADD COLUMN vnet_mtu INTEGER NOT NULL DEFAULT 1280;
