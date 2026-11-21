-- 节点之间的连接请对端少发确认包：网络的两项设置，下发给节点，建连接时用。
-- 已有的网络取默认值：攒到多于 10 个包才单独发确认，没攒够时最多等 2 毫秒。
ALTER TABLE networks ADD COLUMN ack_eliciting_threshold INTEGER NOT NULL DEFAULT 10;
ALTER TABLE networks ADD COLUMN max_ack_delay_ms INTEGER NOT NULL DEFAULT 2;
