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
