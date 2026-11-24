//! 全网矩阵：对网络里所有的节点对做直连能力和延迟测试，分批进行，同时最多 [`CONCURRENCY`] 个。
//! 矩阵不包含吞吐测试。每对节点对应一次常规主动测试（可在历史记录中查询），矩阵仅维护其进度与摘要。
//!
//! 节点不在线、版本太旧、访问规则没有连通的节点对不测，格子里写明原因。同一对节点刚单独测过的，等它过了间隔再测。
//! 矩阵只在内存里：controller 重启之后没有了，每一对的结果还在各自的测试里。

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use i3t_model::admin::diag::{CellState, ItemState, MatrixCell, MatrixRun, MatrixState, TestItem, TestRequest, TestState, TestView};
use i3t_model::admin::{LogRef, NetworkId, RefKind, action};
use i3t_proto::NodeId;
use serde_json::json;

use super::{MIN_INTERVAL, STORE_RETRY, pair};
use crate::controller::{Controller, Inner, count};
use crate::error::{Entity, Error};
use crate::store::{NetworkRecord, NodeRecord};

/// 同时最多跑几个测试。一个节点同时出现在几对里也不会超过节点自己的上限（8 个）。
pub(crate) const CONCURRENCY: usize = 4;
/// 两次矩阵至少隔多久开始。
const MATRIX_INTERVAL: Duration = Duration::from_secs(60);

/// 一次矩阵。
pub(crate) struct Matrix {
    run: MatrixRun,
    started: Instant,
    /// 还没开始的节点对，按顺序。
    pending: Vec<(NodeId, NodeId)>,
    /// 正在进行的测试及其节点对，包含已得出结果但尚未持久化的测试：需待全部结果落盘后矩阵才视为结束。
    running: BTreeMap<u64, (NodeId, NodeId)>,
    /// 管理员取消了，还有测试没有收尾：不再开始新的；测试都收尾了才算取消完，这之前不能开始下一次。
    cancelling: bool,
    /// 开始下一对时存储出错了：这个时刻之前不再排。
    retry_at: Option<Instant>,
    /// 调度重入保护标记：启动某对节点时若发生节点掉线并触发其他测试结束，不从回调重入调度，而是由外层循环继续调度。
    scheduling: bool,
}

impl Matrix {
    pub(crate) fn is_finished(&self) -> bool {
        self.run.state != MatrixState::Running
    }

    fn cell_mut(&mut self, a: NodeId, b: NodeId) -> Option<&mut MatrixCell> {
        self.run.cells.iter_mut().find(|cell| (cell.a, cell.b) == pair(a, b))
    }

    fn count_finished(&mut self) {
        let finished = self.run.cells.iter().filter(|cell| !matches!(cell.state, CellState::Pending | CellState::Running)).count();
        self.run.finished = count(finished);
    }

    /// 现在可以排：没有在排，也没有在等存储出错之后再试的时刻。
    fn may_schedule(&self, now: Instant) -> bool {
        !self.is_finished() && !self.cancelling && !self.scheduling && self.retry_at.is_none_or(|at| at <= now)
    }

    /// 测试用：当作这次矩阵开始以来已经过了两次矩阵之间的间隔。
    #[cfg(test)]
    pub(super) fn interval_passed(&mut self) {
        if let Some(started) = self.started.checked_sub(MATRIX_INTERVAL) {
            self.started = started;
        }
    }
}

impl Controller {
    /// 开始一次全网矩阵。
    ///
    /// # Errors
    ///
    /// 没有这个网络；这个网络正在跑一次矩阵（`busy`），或者上一次刚开始不久（`too_soon`）。
    pub fn start_matrix(&self, network: NetworkId) -> Result<MatrixRun, Error> {
        let mut inner = self.lock();
        let record = inner.require_network(network)?;
        if let Some(matrix) = inner.diag.matrices.get(&network) {
            if matrix.cancelling {
                return Err(Error::Busy("该网络的全网矩阵正在取消，仍有测试结果等待持久化，请稍后再试".to_owned()));
            }
            if !matrix.is_finished() {
                return Err(Error::Busy("该网络正在执行全网矩阵，请等待其完成或先将其取消".to_owned()));
            }
            let wait = MATRIX_INTERVAL.saturating_sub(matrix.started.elapsed());
            if !wait.is_zero() {
                return Err(Error::TooSoon(format!("距离上一次全网矩阵启动间隔过短，请 {} 秒后再试", wait.as_secs().max(1))));
            }
        }
        let nodes = inner.store.nodes(network)?;
        inner.diag.next_matrix += 1;
        let id = inner.diag.next_matrix;
        let mut cells = Vec::new();
        let mut pending = Vec::new();
        for (index, a) in nodes.iter().enumerate() {
            for b in &nodes[index + 1..] {
                let blocker = inner.test_blocker(a, b);
                let state = if blocker.is_some() { CellState::Skipped } else { CellState::Pending };
                if blocker.is_none() {
                    pending.push((a.id, b.id));
                }
                cells.push(MatrixCell {
                    a: a.id,
                    b: b.id,
                    state,
                    test: None,
                    direct_ok: None,
                    direct_kind: None,
                    direct_elapsed_ms: None,
                    route: None,
                    latency: None,
                    problem: blocker,
                });
            }
        }
        let run = MatrixRun {
            id,
            network,
            state: MatrixState::Running,
            started_at: inner.clock.now(),
            finished_at: None,
            concurrency: count(CONCURRENCY),
            total: count(cells.len()),
            finished: 0,
            nodes: nodes.iter().map(NodeRecord::to_ref).collect(),
            cells,
        };
        let detail = format!("开始全网矩阵：{} 个节点，{} 对，其中 {} 对要测", nodes.len(), run.total, pending.len());
        let params = json!({ "matrix": id, "nodes": nodes.len(), "pairs": run.total, "testing": pending.len() });
        let refs = [LogRef::new(RefKind::Network, network.0)];
        // 操作记录与顺带的清理操作在同一事务中执行：写入失败时状态保持不变，可重试。
        inner.store.atomically(|store| store.log_refs(run.started_at, Some(network), action::TEST_MATRIX, &detail, &refs, params))?;
        tracing::info!(network = %network, matrix = id, pairs = run.total, testing = pending.len(), "开始全网矩阵");
        let mut matrix = Matrix {
            run,
            started: Instant::now(),
            pending,
            running: BTreeMap::new(),
            cancelling: false,
            retry_at: None,
            scheduling: false,
        };
        matrix.count_finished();
        inner.diag.matrices.insert(network, matrix);
        inner.schedule_matrix(&record, Instant::now());
        let run = inner.matrix_run(network)?;
        self.wake_if_needed(&inner);
        Ok(run)
    }

    /// 这个网络最近一次全网矩阵。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者 controller 这次启动以来还没有跑过矩阵。
    pub fn matrix(&self, network: NetworkId) -> Result<MatrixRun, Error> {
        let inner = self.lock();
        inner.require_network(network)?;
        inner.matrix_run(network)
    }

    /// 取消进行中的全网矩阵：取消运行中的测试，不再调度尚未开始的节点对。
    ///
    /// 全部测试完成收尾后矩阵才视为取消完成。若有测试结果持久化失败，其状态已固定为已取消，由后台任务继续重试持久化，全部持久化后矩阵才结束取消；
    /// 在此期间可再次调用取消接口，但不能启动新的全网矩阵。
    ///
    /// # Errors
    ///
    /// 没有这个网络、没有矩阵（`not_found`），或者它已经结束了（`busy`）；读写存储失败。
    pub fn cancel_matrix(&self, network: NetworkId) -> Result<MatrixRun, Error> {
        let mut inner = self.lock();
        inner.require_network(network)?;
        let Some(matrix) = inner.diag.matrices.get(&network) else { return Err(Error::NotFound(Entity::Matrix)) };
        if matrix.is_finished() {
            return Err(Error::Busy("全网矩阵已经结束了".to_owned()));
        }
        // 已经在取消的是再取消一次：操作记过了，只是接着收尾。
        if !matrix.cancelling {
            let (id, at) = (matrix.run.id, inner.clock.now());
            let refs = [LogRef::new(RefKind::Network, network.0)];
            let params = json!({ "matrix": id });
            // 操作记录与顺带的清理操作在同一事务中执行：写入失败时状态保持不变，可重试。
            inner
                .store
                .atomically(|store| store.log_refs(at, Some(network), action::TEST_MATRIX_CANCEL, "取消了全网矩阵", &refs, params))?;
            tracing::info!(network = %network, "取消全网矩阵");
            if let Some(matrix) = inner.diag.matrices.get_mut(&network) {
                // 先标成在取消：下面结束各个测试时不会再开始新的。
                matrix.cancelling = true;
                for &(a, b) in &std::mem::take(&mut matrix.pending) {
                    if let Some(cell) = matrix.cell_mut(a, b) {
                        cell.state = CellState::Cancelled;
                    }
                }
                matrix.count_finished();
            }
        }
        let tests: Vec<u64> = inner.diag.matrices.get(&network).map(|matrix| matrix.running.keys().copied().collect()).unwrap_or_default();
        // 先将所有测试结果固定为已取消（已定型的保持不变），再逐个持久化：持久化后会向节点发送终止消息，若节点因此断线，
        // 其参与的其他测试虽按断线收尾，但已固定的结果仍保持为已取消。
        for &test in &tests {
            inner.fix_outcome(test, true);
        }
        // 单个测试持久化失败不阻塞其余测试；失败项留待后台任务继续持久化。
        let mut failed = None;
        for test in tests {
            // 前面结束的测试给节点发结束时，节点可能掉线，连带结束了这一个。
            if !inner.diag.running.contains_key(&test) {
                continue;
            }
            if let Err(error) = inner.finish_test(test, true) {
                tracing::warn!(test, "取消主动测试时存储出错，稍后再试：{error}");
                failed.get_or_insert(error);
            }
        }
        // 一个测试都没有在跑时，上面不会有测试结束来带着它收尾。
        inner.finish_matrix_if_done(network);
        self.wake_if_needed(&inner);
        match failed {
            Some(error) => Err(error),
            None => inner.matrix_run(network),
        }
    }
}

impl Inner {
    fn matrix_run(&self, network: NetworkId) -> Result<MatrixRun, Error> {
        self.diag.matrices.get(&network).map(|matrix| matrix.run.clone()).ok_or(Error::NotFound(Entity::Matrix))
    }

    /// 有空位就开始矩阵里排着的节点对。刚单独测过的对先跳过，等它过了间隔。一个网络出错不耽误别的网络。
    pub(super) fn schedule_matrices(&mut self, now: Instant) {
        let networks: Vec<NetworkId> =
            self.diag.matrices.iter().filter(|(_, matrix)| matrix.may_schedule(now)).map(|(network, _)| *network).collect();
        for network in networks {
            self.schedule_network_matrix(network, now);
        }
    }

    /// 排一个网络的矩阵。
    fn schedule_network_matrix(&mut self, network: NetworkId, now: Instant) {
        if !self.diag.matrices.get(&network).is_some_and(|matrix| matrix.may_schedule(now)) {
            return;
        }
        match self.store.network(network) {
            Ok(Some(record)) => self.schedule_matrix(&record, now),
            Ok(None) => {}
            Err(error) => self.retry_matrix_later(network, now, &error.into()),
        }
    }

    /// 有空位就开始排着的节点对。存储出错时记下日志，隔 [`STORE_RETRY`] 再排；正在排的时候不重入。
    fn schedule_matrix(&mut self, network: &NetworkRecord, now: Instant) {
        let Some(matrix) = self.diag.matrices.get_mut(&network.id).filter(|matrix| matrix.may_schedule(now)) else { return };
        matrix.scheduling = true;
        let scheduled = self.try_schedule_matrix(network, now);
        if let Some(matrix) = self.diag.matrices.get_mut(&network.id) {
            matrix.scheduling = false;
            if scheduled.is_ok() {
                matrix.retry_at = None;
            }
        }
        if let Err(error) = scheduled {
            self.retry_matrix_later(network.id, now, &error);
        }
    }

    fn retry_matrix_later(&mut self, network: NetworkId, now: Instant, error: &Error) {
        tracing::warn!(network = %network, "全网矩阵启动下一对测试失败，{} 秒后重试：{error}", STORE_RETRY.as_secs());
        if let Some(matrix) = self.diag.matrices.get_mut(&network) {
            matrix.retry_at = Some(now + STORE_RETRY);
        }
    }

    /// 出错时待测队列保持不变：仅当该节点对已启动（或确认无需测试）时才将其移出队列。
    ///
    /// 无法启动的节点对移至队尾并结束本轮调度：下一轮优先尝试其余节点对，避免单对持续失败阻塞队列；
    /// 当整个存储不可写时，每轮也仅额外尝试一次，不会遍历重试全部待测节点对。
    fn try_schedule_matrix(&mut self, network: &NetworkRecord, now: Instant) -> Result<(), Error> {
        loop {
            let Some(matrix) = self.diag.matrices.get(&network.id).filter(|matrix| !matrix.is_finished()) else { return Ok(()) };
            if matrix.running.len() >= CONCURRENCY {
                return Ok(());
            }
            let busy = |a: NodeId, b: NodeId| {
                let key = pair(a, b);
                self.diag.running.values().any(|running| pair(running.base.a.id, running.base.b.id) == key)
                    || self.diag.last.get(&key).is_some_and(|(started, _)| now.saturating_duration_since(*started) < MIN_INTERVAL)
            };
            let Some(&(a, b)) = matrix.pending.iter().find(|&&(a, b)| !busy(a, b)) else {
                self.finish_matrix_if_done(network.id);
                return Ok(());
            };
            let matrix_id = matrix.run.id;
            let view = match self.start_pair(network, matrix_id, a, b) {
                Ok(Some(view)) => view,
                Ok(None) => {
                    // 节点在矩阵开始之后被删掉了。
                    if let Some(matrix) = self.diag.matrices.get_mut(&network.id) {
                        matrix.pending.retain(|&queued| queued != (a, b));
                        if let Some(cell) = matrix.cell_mut(a, b) {
                            cell.state = CellState::Skipped;
                        }
                        matrix.count_finished();
                    }
                    continue;
                }
                Err(error) => {
                    if let Some(matrix) = self.diag.matrices.get_mut(&network.id) {
                        matrix.pending.retain(|&queued| queued != (a, b));
                        matrix.pending.push((a, b));
                    }
                    return Err(error);
                }
            };
            // 仍在进行中的测试（包括结果已定型但尚未持久化的）记入矩阵并显示为测试中，待持久化后再填入最终结果。
            let shown = self.diag.running.get(&view.id).map(|running| running.view(false));
            if let Some(matrix) = self.diag.matrices.get_mut(&network.id) {
                // 按值拿掉，不靠找它时的位置：开始一对时节点可能掉线、别的测试随之结束，不去假设这中间 `pending` 没被动过。
                matrix.pending.retain(|&queued| queued != (a, b));
                if shown.is_some() {
                    matrix.running.insert(view.id, (a, b));
                }
                if let Some(cell) = matrix.cell_mut(a, b) {
                    fill_cell(cell, shown.as_ref().unwrap_or(&view));
                }
                matrix.count_finished();
            }
        }
    }

    /// 开始矩阵里的一对。两个节点有一个已经被删掉时返回 `None`。出错时什么都没有变。
    fn start_pair(&mut self, network: &NetworkRecord, matrix: u64, a: NodeId, b: NodeId) -> Result<Option<TestView>, Error> {
        let (Some(a), Some(b)) = (self.store.node(a)?, self.store.node(b)?) else { return Ok(None) };
        // 矩阵只测直连能力和延迟：有直连时量直连，没有时量默认会经的 relay。不量吞吐，不算选路。
        let request = TestRequest {
            items: vec![TestItem::Direct, TestItem::DirectQuality, TestItem::RelayQuality],
            throughput: false,
            via: Vec::new(),
        };
        self.begin_test(network, &a, &b, request, Some(matrix)).map(Some)
    }

    /// 矩阵里的一个测试结束了：记下摘要，空出来的位置给排着的。
    pub(super) fn matrix_test_finished(&mut self, network: NetworkId, matrix: u64, view: &TestView) {
        let Some(state) = self.diag.matrices.get_mut(&network).filter(|state| state.run.id == matrix) else { return };
        state.running.remove(&view.id);
        if let Some(cell) = state.cell_mut(view.a.id, view.b.id) {
            fill_cell(cell, view);
        }
        state.count_finished();
        // 最后一个测试持久化完成后矩阵即结束（处于取消中则标记为已取消），无需等待后续读取存储。
        self.finish_matrix_if_done(network);
        // 调度后续节点对；若此次调度失败不影响已完成项，待测队列保持不变，由后台任务稍后重试。
        self.schedule_network_matrix(network, Instant::now());
    }

    fn finish_matrix_if_done(&mut self, network: NetworkId) {
        let now = self.clock.now();
        let Some(matrix) = self.diag.matrices.get_mut(&network) else { return };
        if matrix.is_finished() || !matrix.pending.is_empty() || !matrix.running.is_empty() {
            return;
        }
        matrix.run.state = if matrix.cancelling { MatrixState::Cancelled } else { MatrixState::Done };
        matrix.cancelling = false;
        matrix.run.finished_at = Some(now);
        matrix.count_finished();
        tracing::info!(network = %network, matrix = matrix.run.id, state = ?matrix.run.state, "全网矩阵已结束");
    }

    /// 矩阵里有排着的节点对时，什么时候再来看：在等间隔过去的隔一秒，开始不了的到再试的时刻。
    pub(super) fn matrix_wake(&self, now: Instant) -> Option<Instant> {
        let soon = now + Duration::from_secs(1);
        self.diag
            .matrices
            .values()
            .filter(|matrix| !matrix.is_finished() && !matrix.pending.is_empty())
            .map(|matrix| matrix.retry_at.map_or(soon, |at| at.max(soon)))
            .min()
    }
}

/// 一个测试的摘要写进矩阵的格子：能不能直连，延迟测在哪条路径上（有直连时是直连，否则是默认会经的 relay）。
fn fill_cell(cell: &mut MatrixCell, view: &TestView) {
    cell.test = Some(view.id);
    cell.state = match view.state {
        TestState::Running => CellState::Running,
        TestState::Done => CellState::Done,
        TestState::Failed => CellState::Failed,
        TestState::Cancelled => CellState::Cancelled,
        TestState::Unknown => CellState::Unknown,
    };
    if let Some(direct) = &view.direct {
        cell.direct_ok = (direct.state == ItemState::Done).then_some(direct.ok);
        cell.direct_kind = direct.kind;
        cell.direct_elapsed_ms = direct.elapsed_ms;
    }
    let measured =
        view.direct_quality.iter().chain(&view.relay_quality).find(|path| path.state == ItemState::Done && path.latency.is_some());
    cell.route = measured.and_then(|path| path.route.clone());
    cell.latency = measured.and_then(|path| path.latency);
    cell.problem = view.error.clone().or_else(|| {
        let direct = view.direct.as_ref().and_then(|direct| direct.problem.clone());
        if measured.is_some() { direct } else { direct.or_else(|| view.relay_quality.iter().find_map(|path| path.problem.clone())) }
    });
}
