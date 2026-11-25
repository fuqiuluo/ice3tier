//! 提交发出去了、回答没有回来（[`StoreError::CommitUnknown`]）：操作当时只能报错，可是数据库里后来可能已经是改过的样子。
//! controller 过后要把结果问出来，算了数的话把当时没做的事补上：重算 netmap、断开被删的节点、换管理令牌。
//!
//! 主动测试和全网矩阵不等待查明提交结果：当场按已提交处理，正常执行提交之后的步骤，本次调用随后不再写入存储。

use std::time::{Duration, Instant};

use i3t_model::admin::diag::{CellState, CreateTest, MatrixRun, MatrixState, TestQuery, TestState};
use i3t_model::admin::{NetworkId, action};
use i3t_model::control::diag::TestRole;
use i3t_model::control::{Declared, TestReport, ToController};

use super::super::Controller;
use super::super::diag::{MIN_INTERVAL, STORE_RETRY};
use super::super::testing::{Lab, Member, REMOTE, modern_hello};
use super::is_woken;
use crate::error::Error;
use crate::store::{Database, Scratch, Store, StoreError};

const ADDR: &str = "ctl.example.com:20331";

/// 卡着提交的那把锁在它手上。放开（或者丢掉）之后，卡着的提交这就做完。
struct Stalled(Store);

impl Stalled {
    fn release(self) {
        self.0.execute_batch("SELECT pg_advisory_unlock(1, hashtext(current_schema()))");
    }
}

/// `table` 上有 `change`（比如 `DELETE`）的事务，提交卡住不动，直到交回来的这个东西被放开：
/// 推迟到提交时才跑的触发器去等一把锁，锁在它手上。不靠睡多久，机器再慢也是同一个先后。
fn stall_commits(database: &Database, change: &str, table: &str) -> Stalled {
    let holder = Store::open(database).unwrap();
    holder.execute_batch(&format!(
        "CREATE FUNCTION stall() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
             PERFORM set_config('lock_timeout', '0', true);
             PERFORM pg_advisory_xact_lock(1, hashtext(current_schema()));
             RETURN NULL;
         END $$;
         CREATE CONSTRAINT TRIGGER stall AFTER {change} ON {table} DEFERRABLE INITIALLY DEFERRED
             FOR EACH ROW EXECUTE FUNCTION stall();
         SELECT pg_advisory_lock(1, hashtext(current_schema()));"
    ));
    Stalled(holder)
}

/// 从现在起 controller 等回答只等这么一会儿：卡住的提交等不到，平常的语句（哪怕机器很慢）等得到。
/// 换了新连接之后恢复平时的期限。
fn be_impatient(lab: &Lab) {
    be_impatient_for(lab, Duration::from_secs(2));
}

/// 与 [`be_impatient`] 相同，等待响应的期限为 `timeout`。
fn be_impatient_for(lab: &Lab, timeout: Duration) {
    lab.controller.lock().store.set_response_timeout(timeout);
}

/// 提交没等到回答之后，存储暂停一小段才重连（见 `Store::went_unanswered`）。等它过去：之后的读写照常连得上数据库，
/// 那次提交在数据库那边仍然卡着。
fn after_the_reconnect_pause() {
    std::thread::sleep(crate::store::RECONNECT_PAUSE.0);
}

fn is_unknown(error: &Error) -> bool {
    matches!(error, Error::Store(StoreError::CommitUnknown(_)))
}

/// 做后台工作，做到结果不明的提交有了结果、该补的都补上了为止。
fn tick_until_settled(lab: &Lab) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // 数据库那边还没做完时这里什么都不会发生，也可能带着别的错误回来：都只是再等一等。
        let _ = lab.controller.tick();
        let inner = lab.controller.lock();
        if !inner.store.has_unsettled_commits() && !inner.out_of_step {
            return;
        }
        drop(inner);
        assert!(Instant::now() < deadline, "结果不明的提交一直没有问出结果");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 仅查明结果未知的提交并据此补齐，不执行后台的其他工作：进行中的测试不会被后台任务写入并结束。
fn settle_only(lab: &Lab) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut inner = lab.controller.lock();
        // 退避期间与数据库尚未完成提交时不会有结果，也可能返回其他错误：均继续等待。
        let _ = inner.settle_commits(Instant::now());
        if !inner.store.has_unsettled_commits() && !inner.out_of_step {
            return;
        }
        drop(inner);
        assert!(Instant::now() < deadline, "结果未知的提交始终未能查明");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 一个网络，里面两个互相看得见的节点。
fn two_members(database: &Database, dir: &std::path::Path) -> (Lab, NetworkId, Member, Member) {
    let mut lab = Lab::around(Controller::open(dir, database, ADDR.to_owned()).unwrap().controller);
    let network = lab.network("home").id;
    let (mut a, mut b) = (lab.join(network, &[]), lab.join(network, &[]));
    lab.settle(&mut [&mut a, &mut b]);
    assert!(a.netmap().peer(b.id).is_some() && b.netmap().peer(a.id).is_some());
    (lab, network, a, b)
}

#[test]
fn a_rule_deleted_by_a_commit_whose_answer_was_lost_is_still_taken_away_from_the_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, mut a, mut b) = two_members(&database, dir.path());
    let rule = lab.controller.rules(network).unwrap().remove(0);

    let stalled = stall_commits(&database, "DELETE", "rules");
    be_impatient(&lab);
    // 前面节点加入时叫过后台任务，那一次还留着：先用掉，下面看到的才是这一次叫的。
    is_woken(&lab);
    let error = lab.controller.delete_rule(network, rule.id).unwrap_err();
    assert!(is_unknown(&error), "{error:?}");
    assert!(is_woken(&lab), "得有人回头来问结果：调用方只是带着错误返回了");
    assert_eq!(a.receive() + b.receive(), 0, "当时不知道删没删成，什么都没发");

    // 数据库那边其实删成了。问出来之后，两个节点照样互相看不见。
    stalled.release();
    tick_until_settled(&lab);
    lab.settle(&mut [&mut a, &mut b]);
    assert!(lab.controller.rules(network).unwrap().is_empty());
    assert!(a.netmap().peers.is_empty() && b.netmap().peers.is_empty(), "规则撤掉了，节点也跟着撤掉了");
    // 管理员再删一次只会听到"没有这条规则"，该撤的不靠这一次。
    assert!(matches!(lab.controller.delete_rule(network, rule.id), Err(Error::NotFound(_))));
}

#[test]
fn a_node_deleted_by_a_commit_whose_answer_was_lost_is_still_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, mut a, mut b) = two_members(&database, dir.path());

    let stalled = stall_commits(&database, "DELETE", "nodes");
    be_impatient(&lab);
    let error = lab.controller.delete_node(network, b.id).unwrap_err();
    assert!(is_unknown(&error), "{error:?}");
    b.receive();
    assert!(!b.revoked && !b.is_closed(), "当时不知道删没删成，它还连着");

    stalled.release();
    tick_until_settled(&lab);
    lab.settle(&mut [&mut a]);
    b.receive();
    assert!(b.revoked && b.is_closed(), "数据库里已经没有它了：公钥吊销，连接断开");
    assert!(a.netmap().peers.is_empty(), "别的节点的 netmap 里也没有它了");
    assert!(!lab.controller.lock().sync.contains_key(&b.id));
}

#[test]
fn an_admin_token_changed_by_a_commit_whose_answer_was_lost_is_the_one_in_force() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let opened = Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap();
    let old = opened.admin_token.unwrap();
    let lab = Lab::around(opened.controller);

    let stalled = stall_commits(&database, "INSERT OR UPDATE", "meta");
    be_impatient(&lab);
    let error = lab.controller.issue_admin_token().unwrap_err();
    assert!(is_unknown(&error), "{error:?}");
    assert!(lab.controller.is_admin_token(&old), "当时不知道换没换成，还认原来的");

    // 数据库里记的已经是新的那个了。内存里跟着它：不然现在认的是一个，重启之后认的是另一个。
    stalled.release();
    tick_until_settled(&lab);
    assert!(!lab.controller.is_admin_token(&old));
    drop(lab);
    let reopened = Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap();
    assert!(reopened.admin_token.is_none() && !reopened.controller.is_admin_token(&old), "重启之后也是这样");
}

#[test]
fn a_commit_whose_answer_was_lost_and_that_did_not_count_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, mut a, mut b) = two_members(&database, dir.path());
    let rule = lab.controller.rules(network).unwrap().remove(0);

    // 提交做到一半，数据库那边把这条连接掐了：事务没有算数。这边只知道回答没有回来。
    // 掐的时候提交还卡着（锁没有放），所以一定是没做完就被掐了。
    let stalled = stall_commits(&database, "DELETE", "rules");
    let backend = lab.controller.lock().store.backend();
    be_impatient(&lab);
    let sent = a.snapshots.len() + b.snapshots.len();
    let error = lab.controller.delete_rule(network, rule.id).unwrap_err();
    assert!(is_unknown(&error), "{error:?}");
    stalled.0.execute_batch(&format!("SELECT pg_terminate_backend({backend})"));
    stalled.release();

    tick_until_settled(&lab);
    lab.settle(&mut [&mut a, &mut b]);
    assert_eq!(lab.controller.rules(network).unwrap().len(), 1, "规则还在");
    assert!(a.netmap().peer(b.id).is_some() && b.netmap().peer(a.id).is_some(), "节点照旧互相看得见");
    assert_eq!(a.snapshots.len() + b.snapshots.len(), sent, "没有因此多发一份 netmap");
}

/// 一个网络，其中有 `count` 个支持主动测试的节点。
fn testers(database: &Database, dir: &std::path::Path, count: usize) -> (Lab, NetworkId, Vec<Member>) {
    let mut lab = Lab::around(Controller::open(dir, database, ADDR.to_owned()).unwrap().controller);
    let network = lab.network("home").id;
    let mut members: Vec<Member> = (0..count).map(|_| lab.join_as(network, &modern_hello("0.2.0"))).collect();
    lab.settle(&mut members.iter_mut().collect::<Vec<_>>());
    (lab, network, members)
}

/// 一个网络，其中有两个支持主动测试的节点。
fn two_testers(database: &Database, dir: &std::path::Path) -> (Lab, NetworkId, Member, Member) {
    let (lab, network, mut members) = testers(database, dir, 2);
    let b = members.pop().unwrap();
    let a = members.pop().unwrap();
    (lab, network, a, b)
}

fn test_between(a: &Member, b: &Member) -> CreateTest {
    CreateTest { a: a.id, b: b.id, items: None, throughput: false, via: Vec::new() }
}

/// `member` 上报其在测试 `test` 中的最后一份结果。忽略处理时返回的错误：结果无法写入存储时会返回错误。
fn report_last(lab: &Lab, member: &Member, test: u64, role: TestRole) {
    let report = TestReport { test, role: Some(role), last: true, ..TestReport::default() };
    let _ = lab.controller.handle(member.session, REMOTE, ToController::TestReport(Box::new(report)));
}

/// 测试 `test` 的两端（位于 `members` 中）各上报最后一份结果，发起方先上报。
fn both_report_last(lab: &Lab, network: NetworkId, test: u64, members: &[&Member]) {
    let view = lab.controller.test(network, test).unwrap();
    let member = |id| members.iter().copied().find(|member| member.id == id).unwrap();
    report_last(lab, member(view.a.id), test, TestRole::Initiator);
    report_last(lab, member(view.b.id), test, TestRole::Responder);
}

/// 矩阵中 `x` 与 `y` 对应的单元格。
fn cell(run: &MatrixRun, x: &Member, y: &Member) -> (CellState, Option<u64>) {
    let cell = run.cells.iter().find(|cell| [cell.a, cell.b] == [x.id, y.id] || [cell.a, cell.b] == [y.id, x.id]).unwrap();
    (cell.state, cell.test)
}

/// 提交结果未知且尚未查明的事务数量。
fn unsettled_commits(lab: &Lab) -> usize {
    lab.controller.lock().store.unsettled_commits()
}

/// 已过矩阵再次调度的时刻（[`STORE_RETRY`] 之后），尚未超过任何测试的时间窗：执行后台任务中处理测试的部分。
fn matrix_retry_due(lab: &Lab) {
    lab.controller.lock().tests_tick(Instant::now() + STORE_RETRY + Duration::from_secs(1));
}

/// 已超过所有测试的时间窗及结果重试持久化的时刻：执行后台任务中处理测试的部分。
fn tests_overdue(lab: &Lab) {
    lab.controller.lock().tests_tick(Instant::now() + Duration::from_secs(600));
}

/// 操作记录中 `action` 的条数。
fn logged(lab: &Lab, action: &str) -> usize {
    lab.controller.oplog(100).unwrap().into_iter().filter(|entry| entry.action == action).count()
}

/// 取消测试的提交未收到响应之后的后续情况。
#[derive(Debug, Clone, Copy)]
enum AfterCancel {
    /// 两端仍上报了最终结果。
    Reports,
    /// 两端均未再上报，测试已超过时间窗。
    TimesOut,
    /// 接受方离线。
    NodeGone,
    /// 管理员未看到结果，再次取消。
    CancelAgain,
}

#[test]
fn a_test_cancel_whose_answer_was_lost_stays_a_cancel_whatever_happens_next() {
    for next in [AfterCancel::Reports, AfterCancel::TimesOut, AfterCancel::NodeGone, AfterCancel::CancelAgain] {
        let dir = tempfile::tempdir().unwrap();
        let scratch = Scratch::new();
        let database = scratch.database();
        let (lab, network, mut a, mut b) = two_testers(&database, dir.path());
        let test = lab.controller.start_test(network, &test_between(&a, &b)).unwrap().id;

        let stalled = stall_commits(&database, "UPDATE", "tests");
        be_impatient(&lab);
        let cancelled = lab.controller.cancel_test(network, test).expect("提交未收到响应：按已提交处理，正常返回");
        assert!(lab.controller.lock().store.has_unsettled_commits(), "{next:?}：取消的提交确实未收到响应");
        after_the_reconnect_pause();
        assert_eq!(cancelled.state, TestState::Cancelled);
        // 提交仍处于阻塞状态，数据库侧尚未完成。
        match next {
            AfterCancel::Reports => both_report_last(&lab, network, test, &[&a, &b]),
            AfterCancel::TimesOut => tests_overdue(&lab),
            AfterCancel::NodeGone => lab.controller.disconnect(b.session),
            AfterCancel::CancelAgain => {
                let again = lab.controller.cancel_test(network, test);
                assert!(matches!(again, Err(Error::Busy(_))), "{next:?}：查明提交结果之前不写入该测试的记录：{again:?}");
            }
        }
        assert_eq!(lab.controller.test(network, test).unwrap(), cancelled, "{next:?}：取消结果已确定，不因此改变");
        assert_eq!(lab.controller.lock().store.lock_waits(), 0, "{next:?}：该行被阻塞的提交锁定，未持有 controller 锁等待该锁");

        stalled.release();
        if matches!(next, AfterCancel::CancelAgain) {
            // 仅查明提交结果，不运行后台任务：测试仍在进行中，再次取消走继续持久化的路径。
            settle_only(&lab);
            let again = lab.controller.cancel_test(network, test).unwrap();
            assert_eq!(again, cancelled, "再次取消仅持久化已确定的结果，结束时刻不变");
        } else {
            tick_until_settled(&lab);
        }
        tests_overdue(&lab);
        let stored = Store::open(&database).unwrap().test(network, test).unwrap().unwrap();
        assert_eq!((stored.state, stored.finished_at), (TestState::Cancelled, cancelled.finished_at), "{next:?}：持久化的是该次取消");
        assert_eq!(lab.controller.test(network, test).unwrap(), stored, "{next:?}");
        assert_eq!(logged(&lab, action::TEST_CANCEL), 1, "{next:?}：取消仅记录一次");
        a.receive();
        b.receive();
        assert!(a.test_ends.contains(&test), "{next:?}：发起方被告知结束");
        if !matches!(next, AfterCancel::NodeGone) {
            assert!(b.test_ends.contains(&test), "{next:?}：接受方被告知结束");
        }
        assert!(matches!(lab.controller.cancel_test(network, test), Err(Error::Busy(_))), "{next:?}：测试已结束");
        assert_eq!(logged(&lab, action::TEST_CANCEL), 1, "{next:?}");
    }
}

#[test]
fn a_test_whose_creation_answer_was_lost_runs_and_its_result_is_stored_in_its_own_row() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, mut a, mut b) = two_testers(&database, dir.path());

    let stalled = stall_commits(&database, "INSERT", "tests");
    be_impatient(&lab);
    let started = lab.controller.start_test(network, &test_between(&a, &b)).expect("提交未收到响应：按已提交处理，正常开始");
    assert!(lab.controller.lock().store.has_unsettled_commits(), "创建测试记录的提交确实未收到响应");
    after_the_reconnect_pause();
    assert_eq!(started.state, TestState::Running);
    a.receive();
    b.receive();
    assert_eq!((a.tests.len(), b.tests.len()), (1, 1), "两端均已收到指令");
    assert!(matches!(lab.controller.start_test(network, &test_between(&a, &b)), Err(Error::Busy(_))), "该节点对正在测试中");
    // 两端在提交仍处于阻塞状态时即已上报完毕：该行在数据库侧尚未创建，此时写入不会生效。
    both_report_last(&lab, network, started.id, &[&a, &b]);
    assert_eq!(lab.controller.test(network, started.id).unwrap().state, TestState::Done, "结果已确定");

    stalled.release();
    tick_until_settled(&lab);
    tests_overdue(&lab);
    let listed: Vec<(u64, TestState)> =
        lab.controller.tests(network, &TestQuery::default()).unwrap().iter().map(|view| (view.id, view.state)).collect();
    assert_eq!(listed, [(started.id, TestState::Done)], "仅此一行，持久化的是两端上报的结果，而非\"controller 已重启\"");
    assert_eq!(logged(&lab, action::TEST_START), 1);
    a.receive();
    b.receive();
    assert!(a.test_ends.contains(&started.id) && b.test_ends.contains(&started.id), "两端被告知结束");
}

#[test]
fn a_matrix_pair_whose_creation_answer_was_lost_is_tested_once() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, a, b) = two_testers(&database, dir.path());

    let stalled = stall_commits(&database, "INSERT", "tests");
    be_impatient(&lab);
    let run = lab.controller.start_matrix(network).unwrap();
    assert!(lab.controller.lock().store.has_unsettled_commits(), "创建测试记录的提交确实未收到响应");
    after_the_reconnect_pause();
    assert_eq!(run.cells[0].state, CellState::Running, "该节点对正常开始，不重新排队：{:?}", run.cells);
    let test = run.cells[0].test.unwrap();

    stalled.release();
    tick_until_settled(&lab);
    both_report_last(&lab, network, test, &[&a, &b]);
    tests_overdue(&lab);
    let run = lab.controller.matrix(network).unwrap();
    assert_eq!((run.state, run.finished, run.cells[0].state), (MatrixState::Done, 1, CellState::Done));
    let listed: Vec<(u64, TestState)> =
        lab.controller.tests(network, &TestQuery::default()).unwrap().iter().map(|view| (view.id, view.state)).collect();
    assert_eq!(listed, [(test, TestState::Done)], "该节点对仅测试一次");
    assert_eq!(logged(&lab, action::TEST_START), 1);
}

#[test]
fn a_test_whose_creation_answer_is_still_unknown_is_cancelled_only_once_the_answer_is_known() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, a, b) = two_testers(&database, dir.path());

    let stalled = stall_commits(&database, "INSERT", "tests");
    be_impatient(&lab);
    let started = lab.controller.start_test(network, &test_between(&a, &b)).expect("提交未收到响应：按已提交处理，正常开始");
    assert_eq!(unsettled_commits(&lab), 1, "创建测试记录的提交确实未收到响应");
    after_the_reconnect_pause();
    // 该行在数据库侧可能尚未创建：此时写入的取消不会生效，测试却会随之结束。
    let refused = lab.controller.cancel_test(network, started.id);
    assert!(matches!(refused, Err(Error::Busy(_))), "查明提交结果之前不写入该测试的记录：{refused:?}");
    assert_eq!(lab.controller.test(network, started.id).unwrap().state, TestState::Running, "状态未发生变化");

    stalled.release();
    tick_until_settled(&lab);
    assert_eq!(logged(&lab, action::TEST_CANCEL), 0, "被拒绝的取消未写入操作记录");
    let cancelled = lab.controller.cancel_test(network, started.id).expect("查明提交结果之后正常取消");
    assert_eq!(cancelled.state, TestState::Cancelled);
    let stored = Store::open(&database).unwrap().test(network, started.id).unwrap().unwrap();
    assert_eq!((stored.state, stored.finished_at), (TestState::Cancelled, cancelled.finished_at), "持久化的是本次取消");
    assert_eq!(logged(&lab, action::TEST_CANCEL), 1);
}

#[test]
fn a_matrix_round_stops_at_a_pair_whose_creation_answer_was_lost() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, members) = testers(&database, dir.path(), 3);

    let stalled = stall_commits(&database, "INSERT", "tests");
    // 等待期限长于 STORE_RETRY：再次调度的时刻须从提交返回时算起，而非从本轮调度开始时算起。
    be_impatient_for(&lab, STORE_RETRY + Duration::from_secs(1));
    let run = lab.controller.start_matrix(network).unwrap();
    // 该节点对仍视为已开始，不重新排队。提交可能仍阻塞在数据库中，本轮不再开始其余节点对：每开始一对均需持锁等待一次完整的响应超时。
    assert_eq!(unsettled_commits(&lab), 1, "开始一对后即结束本轮调度");
    let started: Vec<_> =
        run.cells.iter().filter(|cell| cell.state == CellState::Running).map(|cell| (cell.a, cell.b, cell.test)).collect();
    let pending = run.cells.iter().filter(|cell| cell.state == CellState::Pending).count();
    assert_eq!((started.len(), pending), (1, 2), "{:?}", run.cells);
    // 退避已结束，再次调度的时刻尚未到达。
    lab.controller.lock().tests_tick(Instant::now() + Duration::from_secs(2));
    assert_eq!(unsettled_commits(&lab), 1, "再次调度的时刻从提交返回时算起");

    stalled.release();
    tick_until_settled(&lab);
    matrix_retry_due(&lab);
    let run = lab.controller.matrix(network).unwrap();
    assert!(run.cells.iter().all(|cell| cell.state == CellState::Running), "其余节点对在 STORE_RETRY 之后开始：{:?}", run.cells);
    assert!(run.cells.iter().any(|cell| (cell.a, cell.b, cell.test) == started[0]), "已开始的节点对未重新排队");
    let members: Vec<&Member> = members.iter().collect();
    for cell in &run.cells {
        both_report_last(&lab, network, cell.test.unwrap(), &members);
    }
    let run = lab.controller.matrix(network).unwrap();
    assert_eq!((run.state, run.finished), (MatrixState::Done, 3), "{:?}", run.cells);
    assert_eq!(lab.controller.tests(network, &TestQuery::default()).unwrap().len(), 3, "每个节点对仅测试一次");
    assert_eq!(logged(&lab, action::TEST_START), 3);
}

#[test]
fn a_matrix_round_also_stops_at_a_pair_that_ends_at_once_when_its_creation_answer_was_lost() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, members) = testers(&database, dir.path(), 3);
    let [a, b, d] = [&members[0], &members[1], &members[2]];
    // 与 d 相关的两对刚单独测试过：矩阵开始时排队等待间隔结束。
    for x in [a, b] {
        let test = lab.controller.start_test(network, &test_between(x, d)).unwrap().id;
        both_report_last(&lab, network, test, &[x, d]);
    }
    let run = lab.controller.start_matrix(network).unwrap();
    assert_eq!([cell(&run, a, b).0, cell(&run, a, d).0, cell(&run, b, d).0], [CellState::Running, CellState::Pending, CellState::Pending]);
    // d 离线：与其相关的两对在开始时即结束，不下发指令，插入的记录即包含最终结果。
    lab.controller.disconnect(d.session);

    let stalled = stall_commits(&database, "INSERT", "tests");
    be_impatient(&lab);
    // 已超过两次测试之间的间隔，尚未超过 a 与 b 之间测试的时间窗。
    lab.controller.lock().tests_tick(Instant::now() + MIN_INTERVAL + Duration::from_secs(1));
    assert_eq!(unsettled_commits(&lab), 1, "结束一对后即结束本轮调度，未继续写入下一对");
    after_the_reconnect_pause();
    let run = lab.controller.matrix(network).unwrap();
    let mut ends = [cell(&run, a, d).0, cell(&run, b, d).0];
    ends.sort_unstable_by_key(|state| *state == CellState::Pending);
    assert_eq!(ends, [CellState::Failed, CellState::Pending], "{:?}", run.cells);

    stalled.release();
    tick_until_settled(&lab);
    // 已超过再次调度的时刻与另一对的测试间隔。
    lab.controller.lock().tests_tick(Instant::now() + MIN_INTERVAL + Duration::from_secs(1));
    let test = cell(&lab.controller.matrix(network).unwrap(), a, b).1.unwrap();
    both_report_last(&lab, network, test, &[a, b]);
    let run = lab.controller.matrix(network).unwrap();
    assert_eq!((run.state, run.finished), (MatrixState::Done, 3), "{:?}", run.cells);
    assert_eq!([cell(&run, a, b).0, cell(&run, a, d).0, cell(&run, b, d).0], [CellState::Done, CellState::Failed, CellState::Failed]);
    assert_eq!(lab.controller.tests(network, &TestQuery::default()).unwrap().len(), 5, "单独测试两次，矩阵中每个节点对各一次");
    assert_eq!(logged(&lab, action::TEST_START), 5);
}

#[test]
fn a_matrix_cancel_whose_answer_was_lost_cancels_the_matrix_and_is_logged_once() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, _members) = testers(&database, dir.path(), 3);
    let run = lab.controller.start_matrix(network).unwrap();
    let tests: Vec<u64> = run.cells.iter().filter_map(|cell| cell.test).collect();
    assert_eq!(tests.len(), 3, "三对均在测试中：{:?}", run.cells);

    let stalled = stall_commits(&database, "INSERT", "oplog");
    be_impatient(&lab);
    let run = lab.controller.cancel_matrix(network).expect("提交未收到响应：按已提交处理，正常取消");
    assert_eq!(unsettled_commits(&lab), 1, "记录取消的提交确实未收到响应");
    after_the_reconnect_pause();
    // 提交可能仍阻塞在数据库中：各测试的结果已确定为取消，本次不写入（每次写入均需持有 controller 锁等待一次完整的响应超时），
    // 交由后台任务处理。
    let elsewhere = Store::open(&database).unwrap();
    for &test in &tests {
        assert_eq!(lab.controller.test(network, test).unwrap().state, TestState::Cancelled, "取消结果已确定");
        assert_eq!(elsewhere.test(network, test).unwrap().unwrap().state, TestState::Running, "本次未写入");
    }
    assert_eq!(run.state, MatrixState::Running, "测试结果持久化之前矩阵仍在取消中：{:?}", run.cells);
    assert!(matches!(lab.controller.start_matrix(network), Err(Error::Busy(_))), "取消完成之前不能开始下一次矩阵");

    stalled.release();
    tick_until_settled(&lab);
    // 后台任务在 STORE_RETRY 之后写入，不等待各测试的时间窗结束。
    matrix_retry_due(&lab);
    let run = lab.controller.matrix(network).unwrap();
    assert_eq!(run.state, MatrixState::Cancelled);
    assert!(run.cells.iter().all(|cell| cell.state == CellState::Cancelled), "{:?}", run.cells);
    for &test in &tests {
        assert_eq!(elsewhere.test(network, test).unwrap().unwrap().state, TestState::Cancelled);
    }
    assert!(matches!(lab.controller.cancel_matrix(network), Err(Error::Busy(_))), "矩阵已取消完成");
    assert_eq!(logged(&lab, action::TEST_MATRIX_CANCEL), 1, "取消仅记录一次");
}

#[test]
fn a_matrix_whose_start_answer_was_lost_starts_its_pairs_later_and_tests_each_once() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, members) = testers(&database, dir.path(), 3);

    // 开始一对时也会向该表写入操作记录，其提交同样会阻塞。
    let stalled = stall_commits(&database, "INSERT", "oplog");
    be_impatient(&lab);
    let run = lab.controller.start_matrix(network).expect("提交未收到响应：按已提交处理，正常开始");
    // 提交可能仍阻塞在数据库中：本次不开始节点对，每开始一对均需持有 controller 锁等待一次完整的响应超时。
    assert_eq!(unsettled_commits(&lab), 1, "仅有记录矩阵开始的那次提交结果未知");
    assert_eq!(run.state, MatrixState::Running);
    assert!(run.cells.iter().all(|cell| cell.state == CellState::Pending), "{:?}", run.cells);

    stalled.release();
    tick_until_settled(&lab);
    matrix_retry_due(&lab);
    let run = lab.controller.matrix(network).unwrap();
    assert!(run.cells.iter().all(|cell| cell.state == CellState::Running), "由后台任务在 STORE_RETRY 之后开始：{:?}", run.cells);
    let members: Vec<&Member> = members.iter().collect();
    for cell in &run.cells {
        both_report_last(&lab, network, cell.test.unwrap(), &members);
    }
    let run = lab.controller.matrix(network).unwrap();
    assert_eq!((run.state, run.finished), (MatrixState::Done, 3), "{:?}", run.cells);
    assert_eq!(lab.controller.tests(network, &TestQuery::default()).unwrap().len(), 3, "每个节点对仅测试一次");
    assert_eq!(logged(&lab, action::TEST_START), 3);
    assert_eq!(logged(&lab, action::TEST_MATRIX), 1);
}

#[test]
fn a_matrix_whose_start_answer_was_lost_is_there_as_its_log_entry_says() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let mut lab = Lab::around(Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap().controller);
    let network = lab.network("home").id;
    // 一个节点离线：唯一的一对无需测试，矩阵开始即完成，不再写入数据库。
    let mut online = lab.join_as(network, &modern_hello("0.2.0"));
    lab.join_offline(network, &[], Declared::default());
    lab.settle(&mut [&mut online]);

    let stalled = stall_commits(&database, "INSERT", "oplog");
    be_impatient(&lab);
    let run = lab.controller.start_matrix(network).expect("提交未收到响应：按已提交处理，正常开始");
    assert!(lab.controller.lock().store.has_unsettled_commits(), "记录开始的提交确实未收到响应");

    stalled.release();
    tick_until_settled(&lab);
    assert_eq!(logged(&lab, action::TEST_MATRIX), 1);
    assert_eq!(lab.controller.matrix(network).unwrap(), run, "操作记录中记为已开始的矩阵确实存在");
}

#[test]
fn a_lost_commit_while_scheduling_one_matrix_holds_back_the_other_matrices_for_the_round() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let mut lab = Lab::around(Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap().controller);
    let mut networks = Vec::new();
    for name in ["home", "work"] {
        let network = lab.network(name).id;
        let mut members: Vec<Member> = (0..2).map(|_| lab.join_as(network, &modern_hello("0.2.0"))).collect();
        lab.settle(&mut members.iter_mut().collect::<Vec<_>>());
        // 该节点对刚单独测试过：矩阵开始时排队等待间隔结束。
        let test = lab.controller.start_test(network, &test_between(&members[0], &members[1])).unwrap().id;
        both_report_last(&lab, network, test, &[&members[0], &members[1]]);
        assert_eq!(lab.controller.start_matrix(network).unwrap().cells[0].state, CellState::Pending);
        networks.push((network, members));
    }

    let stalled = stall_commits(&database, "INSERT", "tests");
    be_impatient(&lab);
    {
        let mut inner = lab.controller.lock();
        inner.intervals_passed();
        inner.tests_tick(Instant::now());
    }
    // 先调度的矩阵开始一对时提交未收到响应，随即开始退避：本轮不再调度另一个网络的矩阵。
    assert_eq!(unsettled_commits(&lab), 1, "本轮仅开始了一对");
    after_the_reconnect_pause();
    let mut states: Vec<CellState> = networks.iter().map(|(network, _)| lab.controller.matrix(*network).unwrap().cells[0].state).collect();
    states.sort_unstable_by_key(|state| *state == CellState::Pending);
    assert_eq!(states, [CellState::Running, CellState::Pending]);

    stalled.release();
    tick_until_settled(&lab);
    matrix_retry_due(&lab);
    for (network, _) in &networks {
        assert_eq!(lab.controller.matrix(*network).unwrap().cells[0].state, CellState::Running, "退避结束后正常调度");
    }
}

#[test]
fn a_lost_commit_while_a_node_s_tests_end_leaves_its_other_results_to_the_background() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, members) = testers(&database, dir.path(), 3);
    let [x, y, z] = [&members[0], &members[1], &members[2]];
    // y 与 z 刚单独测试过：矩阵开始时该节点对排队等待间隔结束。
    let test = lab.controller.start_test(network, &test_between(y, z)).unwrap().id;
    both_report_last(&lab, network, test, &[y, z]);
    let run = lab.controller.start_matrix(network).unwrap();
    assert_eq!([cell(&run, x, y).0, cell(&run, x, z).0, cell(&run, y, z).0], [CellState::Running, CellState::Running, CellState::Pending]);
    let ended = [cell(&run, x, y).1.unwrap(), cell(&run, x, z).1.unwrap()];

    let stalled = stall_commits(&database, "INSERT", "tests");
    be_impatient(&lab);
    lab.controller.lock().intervals_passed();
    // x 离线：先写入的测试结束后，矩阵开始 y 与 z 组成的节点对，其提交未收到响应并开始退避。
    lab.controller.disconnect(x.session);
    assert_eq!(unsettled_commits(&lab), 1, "y 与 z 组成的节点对已开始");
    after_the_reconnect_pause();
    let elsewhere = Store::open(&database).unwrap();
    let mut stored: Vec<TestState> = ended.iter().map(|&test| elsewhere.test(network, test).unwrap().unwrap().state).collect();
    stored.sort_unstable_by_key(|state| *state == TestState::Running);
    assert!(stored[0] != TestState::Running && stored[1] == TestState::Running, "另一个测试的结果本次未写入：{stored:?}");
    for test in ended {
        assert_ne!(lab.controller.test(network, test).unwrap().state, TestState::Running, "两个测试的结果均已确定");
    }

    stalled.release();
    tick_until_settled(&lab);
    matrix_retry_due(&lab);
    for test in ended {
        assert_ne!(elsewhere.test(network, test).unwrap().unwrap().state, TestState::Running, "后台任务写入了其余结果");
    }
}

#[test]
fn a_test_whose_order_cannot_be_delivered_after_a_lost_commit_writes_no_other_result() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (mut lab, network, mut members) = testers(&database, dir.path(), 3);
    let mut c = members.pop().unwrap();
    let b = members.pop().unwrap();
    let mut a = members.pop().unwrap();
    // b 以已注册节点的身份重新连接：其连接断开时 controller 会记录最近在线的时间。
    lab.controller.disconnect(b.session);
    let mut b = lab.connect_as(b.key, &modern_hello("0.2.0")).unwrap();
    lab.settle(&mut [&mut a, &mut b, &mut c]);
    let other = lab.controller.start_test(network, &test_between(&c, &b)).unwrap().id;
    // b 的连接已断开，controller 尚未察觉：向它下发指令时失败，它随之被记为离线。
    let b_id = b.id;
    drop(b);

    // 记录最近在线的时间所需的时长超过退避期：若在退避期内仍写入，退避将在写入其他测试的结果之前结束。
    let slow = Store::open(&database).unwrap();
    slow.execute_batch(
        "CREATE FUNCTION slow() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1.5); RETURN NEW; END $$;
         CREATE TRIGGER slow BEFORE UPDATE ON nodes FOR EACH ROW EXECUTE FUNCTION slow();",
    );
    let stalled = stall_commits(&database, "INSERT", "tests");
    be_impatient(&lab);
    let request = CreateTest { a: a.id, b: b_id, items: None, throughput: false, via: Vec::new() };
    let started = lab.controller.start_test(network, &request).expect("提交未收到响应：按已提交处理，正常返回");
    assert_eq!(unsettled_commits(&lab), 1, "创建测试记录的提交未收到响应");
    after_the_reconnect_pause();
    assert_ne!(started.state, TestState::Running, "指令无法下发的测试在此结束");
    // 提交可能仍阻塞在数据库中：b 参与的另一个测试的结果已经确定，本次不写入。
    let elsewhere = Store::open(&database).unwrap();
    assert_eq!(elsewhere.test(network, other).unwrap().unwrap().state, TestState::Running, "本次未写入另一个测试的结果");
    assert_ne!(lab.controller.test(network, other).unwrap().state, TestState::Running, "另一个测试的结果已经确定");

    // 被阻塞的事务持有 nodes 表上的锁（外键检查），提交完成后才能撤销该触发器。
    stalled.release();
    slow.execute_batch("DROP TRIGGER slow ON nodes");
    tick_until_settled(&lab);
    matrix_retry_due(&lab);
    assert_ne!(elsewhere.test(network, other).unwrap().unwrap().state, TestState::Running, "后台任务写入了另一个测试的结果");
    assert_eq!(elsewhere.test(network, started.id).unwrap().unwrap().state, started.state, "新测试的结果写入了其自身的记录");
}

#[test]
fn a_matrix_is_not_scheduled_while_backing_off_and_its_network_is_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let (lab, network, a, b) = two_testers(&database, dir.path());
    // 该节点对刚单独测试过：矩阵开始时排队等待间隔结束。
    let test = lab.controller.start_test(network, &test_between(&a, &b)).unwrap().id;
    both_report_last(&lab, network, test, &[&a, &b]);
    assert_eq!(lab.controller.start_matrix(network).unwrap().cells[0].state, CellState::Pending);

    // 另一个连接锁定 networks 表：读取网络信息须等待该锁。
    let holder = Store::open(&database).unwrap();
    holder.execute_batch("BEGIN; LOCK TABLE networks IN ACCESS EXCLUSIVE MODE");
    {
        let mut inner = lab.controller.lock();
        inner.store.set_lock_timeout(Duration::from_millis(300));
        inner.intervals_passed();
        inner.back_off();
        inner.tests_tick(Instant::now());
        assert_eq!(inner.store.lock_waits(), 0, "退避期内不调度矩阵，也不读取其网络信息");
    }
    holder.execute_batch("ROLLBACK");
    assert_eq!(lab.controller.matrix(network).unwrap().cells[0].state, CellState::Pending, "退避期内未开始节点对");
}
