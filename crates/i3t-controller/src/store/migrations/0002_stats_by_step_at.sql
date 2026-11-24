-- 时间序列按步长与时间查找数据点的索引。整点汇总（Store::roll_up_stats）与过期清理（Store::prune_stats）
-- 仅按 step 与 at 筛选，无法利用以 network_id、series、node_id 开头的主键，只能顺序扫描全表，
-- 而这两项操作在 controller 持锁期间执行。
--
-- 每个 (step, at) 对应的行数等于序列数（1000 个节点时约 3300），B 树去重后索引很小（此时约 11 MB，主键约 135 MB）。
-- 索引不包含 value 列：覆盖写入同一分段时仅更新 value，仍可进行 HOT 更新而无需改写索引。

CREATE INDEX stats_by_step_at ON stats(step, at);
