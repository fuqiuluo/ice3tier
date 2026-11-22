-- 节点之间直连时把同一时刻要发的几个小网络包合成一个包发：网络的一项开关，下发给节点。
-- 已有的网络取默认值：开着。
ALTER TABLE networks ADD COLUMN bundle_small_packets INTEGER NOT NULL DEFAULT 1;
