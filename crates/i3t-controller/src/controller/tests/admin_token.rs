//! 重新生成管理令牌（`i3t-controller --reset-admin-token`）：只要数据目录和数据库，不要对外地址，
//! 也不在写错的目录或者空的库里建出新的 controller。

use std::fs;
use std::path::Path;

use i3t_model::admin::{CreateNetwork, action};

use crate::controller::{Controller, KEY_FILE};
use crate::error::Error;
use crate::store::{Database, Scratch, Store, StoreError};

const ADDR: &str = "ctl.example.com:20331";

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    names
}

#[test]
fn a_new_admin_token_needs_only_the_data_dir_and_the_database_and_leaves_everything_else_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let data = dir.path().join("data");
    let opened = Controller::open(&data, &database, ADDR.to_owned()).unwrap();
    let old = opened.admin_token.unwrap();
    let controller_key = opened.controller.public_key();
    let home = opened.controller.create_network(&CreateNetwork { name: "home".to_owned(), ..CreateNetwork::default() }).unwrap();
    drop(opened.controller);

    let fresh = Controller::reset_admin_token(&data, &database).unwrap();
    assert_ne!(fresh, old);

    let reopened = Controller::open(&data, &database, "other.example.com:1".to_owned()).unwrap();
    assert!(reopened.admin_token.is_none(), "令牌已经有了，打开时不再生成");
    let controller = reopened.controller;
    assert!(controller.is_admin_token(&fresh), "新的令牌能用");
    assert!(!controller.is_admin_token(&old), "原来的作废");
    assert_eq!(controller.public_key(), controller_key, "密钥没动");
    assert_eq!(controller.networks().unwrap().iter().map(|network| network.id).collect::<Vec<_>>(), [home.id]);
    let latest = &controller.oplog(1).unwrap()[0];
    assert_eq!(latest.action, action::ADMIN_TOKEN, "记了一条操作");
    assert!(!latest.detail.contains(&fresh) && !latest.params.values().any(|value| value.to_string().contains(&fresh)), "记录里没有令牌");
}

#[test]
fn a_place_that_is_not_a_data_dir_gets_no_admin_token_and_nothing_is_created_there() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();

    let missing = dir.path().join("typo");
    let refused = Controller::reset_admin_token(&missing, &database).unwrap_err();
    assert!(matches!(&refused, Error::NotDataDir { dir, missing: KEY_FILE } if *dir == missing), "{refused:?}");
    assert!(!missing.exists(), "写错的目录不建出来");

    let empty = dir.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let refused = Controller::reset_admin_token(&empty, &database).unwrap_err();
    assert!(matches!(refused, Error::NotDataDir { missing: KEY_FILE, .. }), "{refused:?}");
    assert!(listing(&empty).is_empty(), "不生成密钥");
    assert!(matches!(Store::open_existing(&database), Err(StoreError::Empty)), "也不在库里建表");
}

#[test]
fn an_empty_database_gets_no_admin_token_and_no_tables() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let data = dir.path().join("data");
    drop(Controller::open(&data, &scratch.database(), ADDR.to_owned()).unwrap());

    // 密钥是对的，连到的却是另一个空的库（连接串里的库名写错了）：不在那里建出一个空的 controller。
    let elsewhere = Scratch::new();
    let refused = Controller::reset_admin_token(&data, &elsewhere.database()).unwrap_err();
    assert!(matches!(refused, Error::Store(StoreError::Empty)), "{refused:?}");
    assert!(matches!(Store::open_existing(&elsewhere.database()), Err(StoreError::Empty)), "没有建表");
    assert_eq!(listing(&data), [KEY_FILE]);
}

#[test]
fn an_unreadable_key_or_an_unreachable_database_is_refused_and_the_token_stays() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let data = dir.path().join("data");
    let opened = Controller::open(&data, &database, ADDR.to_owned()).unwrap();
    let old = opened.admin_token.unwrap();
    drop(opened.controller);

    // 密钥读不懂的 controller 启动不了：不换令牌，现在就说。
    let key = fs::read(data.join(KEY_FILE)).unwrap();
    fs::write(data.join(KEY_FILE), "这不是密钥").unwrap();
    let refused = Controller::reset_admin_token(&data, &database).unwrap_err();
    assert!(matches!(&refused, Error::Key { path, .. } if *path == data.join(KEY_FILE)), "{refused:?}");
    fs::write(data.join(KEY_FILE), key).unwrap();

    // 这个端口上没有数据库。
    let nowhere: Database = "postgres://i3t@127.0.0.1:1/i3t".parse().unwrap();
    let refused = Controller::reset_admin_token(&data, &nowhere).unwrap_err();
    assert!(matches!(refused, Error::Store(StoreError::Connect(_))), "{refused:?}");

    let reopened = Controller::open(&data, &database, ADDR.to_owned()).unwrap();
    assert!(reopened.controller.is_admin_token(&old), "原来的令牌还能用");
}

#[test]
fn a_data_dir_and_a_database_of_different_controllers_are_not_put_together() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (Scratch::new(), Scratch::new());
    let (data_a, data_b) = (dir.path().join("a"), dir.path().join("b"));
    let token_a = Controller::open(&data_a, &a.database(), ADDR.to_owned()).unwrap().admin_token.unwrap();
    drop(Controller::open(&data_b, &b.database(), ADDR.to_owned()).unwrap());

    // 拿着 b 的数据目录连 a 的库：不开，也不换掉 a 的管理令牌。
    let refused = Controller::open(&data_b, &a.database(), ADDR.to_owned()).err().expect("密钥对不上");
    assert!(matches!(&refused, Error::KeyMismatch { path } if *path == data_b.join(KEY_FILE)), "{refused:?}");
    let refused = Controller::reset_admin_token(&data_b, &a.database()).unwrap_err();
    assert!(matches!(refused, Error::KeyMismatch { .. }), "{refused:?}");

    let reopened = Controller::open(&data_a, &a.database(), ADDR.to_owned()).unwrap();
    assert!(reopened.admin_token.is_none() && reopened.controller.is_admin_token(&token_a), "a 的令牌没有动");
}

#[test]
fn two_controllers_that_reach_an_empty_database_at_the_same_moment_do_not_both_get_it() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    // 另一个数据目录的 controller 抢先了一步：这一个读的时候库里还没有记公钥，等它去记时那一个的已经在了。
    // 用一个触发器把"那一个的"在这一刻塞进去。
    let theirs = [7u8; 32];
    Store::open(&database).unwrap().execute_batch(&format!(
        "CREATE FUNCTION come_first() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
             INSERT INTO meta (key, value) VALUES ('controller_key', '\\x{}');
             RETURN NEW;
         END $$;
         CREATE TRIGGER come_first BEFORE INSERT ON meta FOR EACH ROW
             WHEN (NEW.key = 'controller_key' AND pg_trigger_depth() = 0) EXECUTE FUNCTION come_first();",
        "07".repeat(theirs.len())
    ));

    let data = dir.path().join("late");
    let refused = Controller::open(&data, &database, ADDR.to_owned()).err().expect("库已经是另一个 controller 的了");
    assert!(matches!(&refused, Error::KeyMismatch { path } if *path == data.join(KEY_FILE)), "{refused:?}");
    let store = Store::open(&database).unwrap();
    assert_eq!(store.meta("controller_key").unwrap().as_deref(), Some(theirs.as_slice()), "先记上的那一把没有被盖掉");
    assert_eq!(store.meta("admin_token_hash").unwrap(), None, "没开成的这一个也没有在别人的库里生成管理令牌");
}

#[test]
fn a_database_that_already_has_a_controller_is_not_given_a_new_key() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let data = dir.path().join("data");
    let opened = Controller::open(&data, &database, ADDR.to_owned()).unwrap();
    let (key, token) = (opened.controller.public_key(), opened.admin_token.unwrap());
    drop(opened.controller);

    // 恢复时忘了把密钥放回来，或者数据目录丢了：节点认的是原来那一把，生成一把新的只会让它们都连不回来。
    let fresh = dir.path().join("fresh");
    let refused = Controller::open(&fresh, &database, ADDR.to_owned()).err().expect("没有密钥");
    assert!(matches!(&refused, Error::KeyMissing { path } if *path == fresh.join(KEY_FILE)), "{refused:?}");
    assert!(listing(&fresh).is_empty(), "没有生成新的密钥");

    // 把密钥放回来就照常。
    fs::copy(data.join(KEY_FILE), fresh.join(KEY_FILE)).unwrap();
    let restored = Controller::open(&fresh, &database, ADDR.to_owned()).unwrap();
    assert!(restored.admin_token.is_none() && restored.controller.is_admin_token(&token));
    assert_eq!(restored.controller.public_key(), key);
}

#[test]
fn a_first_start_that_cannot_reach_the_database_leaves_no_key_behind() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let nowhere: Database = "postgres://i3t@127.0.0.1:1/i3t".parse().unwrap();
    let refused = Controller::open(&data, &nowhere, ADDR.to_owned()).err().expect("这个端口上没有数据库");
    assert!(matches!(refused, Error::Store(StoreError::Connect(_))), "{refused:?}");
    assert!(listing(&data).is_empty(), "没连上数据库：不留下一把密钥");

    // 数据库好了之后的这一次才是第一次启动：生成密钥，给出管理令牌。
    let scratch = Scratch::new();
    let opened = Controller::open(&data, &scratch.database(), ADDR.to_owned()).unwrap();
    assert!(opened.admin_token.is_some());
    assert_eq!(listing(&data), [KEY_FILE]);
}

#[test]
fn a_new_admin_token_that_cannot_be_logged_leaves_the_old_one_in_force() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let data = dir.path().join("data");
    let opened = Controller::open(&data, &database, ADDR.to_owned()).unwrap();
    let old = opened.admin_token.unwrap();
    drop(opened.controller);

    // 操作记录写不进去：换令牌和记这一条是一起的，一样没做成就都不算。
    let other = Store::open(&database).unwrap();
    other.block("no_log", "INSERT ON oplog", None);
    assert!(matches!(Controller::reset_admin_token(&data, &database), Err(Error::Store(_))));
    let reopened = Controller::open(&data, &database, ADDR.to_owned()).unwrap();
    assert!(reopened.admin_token.is_none() && reopened.controller.is_admin_token(&old), "原来的令牌照旧有效");
    assert!(reopened.controller.issue_admin_token().is_err());
    assert!(reopened.controller.is_admin_token(&old));
    drop(reopened);

    other.unblock("no_log", "oplog");
    let fresh = Controller::reset_admin_token(&data, &database).unwrap();
    let reopened = Controller::open(&data, &database, ADDR.to_owned()).unwrap();
    assert!(reopened.controller.is_admin_token(&fresh) && !reopened.controller.is_admin_token(&old));
}
