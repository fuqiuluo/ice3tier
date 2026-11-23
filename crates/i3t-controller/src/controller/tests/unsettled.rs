//! 提交发出去了、回答没有回来（[`StoreError::CommitUnknown`]）：操作当时只能报错，可是数据库里后来可能已经是改过的样子。
//! controller 过后要把结果问出来，算了数的话把当时没做的事补上：重算 netmap、断开被删的节点、换管理令牌。

use std::time::{Duration, Instant};

use super::super::Controller;
use super::super::testing::{Lab, Member};
use super::is_woken;
use crate::error::Error;
use crate::store::{Database, Scratch, Store, StoreError};

const ADDR: &str = "ctl.example.com:20331";

/// 提交要做上多久。比 controller 肯等的（[`be_impatient`]）长得多，所以它等不到回答；又不长，测试等得起它做完。
const STALL: Duration = Duration::from_secs(1);

/// `table` 上有 `change`（比如 `DELETE`）的事务，提交要做上 `stall` 这么久：推迟到提交时才跑的触发器里睡一觉。
fn stall_commits(database: &Database, change: &str, table: &str, stall: Duration) {
    let seconds = stall.as_secs_f64();
    Store::open(database).unwrap().execute_batch(&format!(
        "CREATE FUNCTION stall() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep({seconds}); RETURN NULL; END $$;
         CREATE CONSTRAINT TRIGGER stall AFTER {change} ON {table} DEFERRABLE INITIALLY DEFERRED
             FOR EACH ROW EXECUTE FUNCTION stall();"
    ));
}

/// 从现在起 controller 等回答只等很短的一下，上面那样的提交等不到。换了新连接之后恢复平时的期限。
fn be_impatient(lab: &Lab) {
    lab.controller.lock().store.set_response_timeout(Duration::from_millis(200));
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

/// 一个网络，里面两个互相看得见的节点。
fn two_members(database: &Database, dir: &std::path::Path) -> (Lab, i3t_model::admin::NetworkId, Member, Member) {
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

    stall_commits(&database, "DELETE", "rules", STALL);
    be_impatient(&lab);
    let error = lab.controller.delete_rule(network, rule.id).unwrap_err();
    assert!(is_unknown(&error), "{error:?}");
    assert!(is_woken(&lab), "得有人回头来问结果：调用方只是带着错误返回了");
    assert_eq!(a.receive() + b.receive(), 0, "当时不知道删没删成，什么都没发");

    // 数据库那边其实删成了。问出来之后，两个节点照样互相看不见。
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

    stall_commits(&database, "DELETE", "nodes", STALL);
    be_impatient(&lab);
    let error = lab.controller.delete_node(network, b.id).unwrap_err();
    assert!(is_unknown(&error), "{error:?}");
    b.receive();
    assert!(!b.revoked && !b.is_closed(), "当时不知道删没删成，它还连着");

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

    stall_commits(&database, "INSERT OR UPDATE", "meta", STALL);
    be_impatient(&lab);
    let error = lab.controller.issue_admin_token().unwrap_err();
    assert!(is_unknown(&error), "{error:?}");
    assert!(lab.controller.is_admin_token(&old), "当时不知道换没换成，还认原来的");

    // 数据库里记的已经是新的那个了。内存里跟着它：不然现在认的是一个，重启之后认的是另一个。
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
    // 掐它用的连接事先开好，提交又要做上一分钟：不管机器多慢，掐的时候它一定还没做完。掐了它就停，测试不用等这一分钟。
    stall_commits(&database, "DELETE", "rules", Duration::from_secs(60));
    let killer = Store::open(&database).unwrap();
    let backend = lab.controller.lock().store.backend();
    be_impatient(&lab);
    let sent = a.snapshots.len() + b.snapshots.len();
    let error = lab.controller.delete_rule(network, rule.id).unwrap_err();
    assert!(is_unknown(&error), "{error:?}");
    killer.execute_batch(&format!("SELECT pg_terminate_backend({backend})"));

    tick_until_settled(&lab);
    lab.settle(&mut [&mut a, &mut b]);
    assert_eq!(lab.controller.rules(network).unwrap().len(), 1, "规则还在");
    assert!(a.netmap().peer(b.id).is_some() && b.netmap().peer(a.id).is_some(), "节点照旧互相看得见");
    assert_eq!(a.snapshots.len() + b.snapshots.len(), sent, "没有因此多发一份 netmap");
}
