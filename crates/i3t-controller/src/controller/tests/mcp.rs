//! MCP 令牌的签发、列出、撤销和过期，换签名密钥，以及经 MCP 做的操作在操作记录里记着是谁做的。
//! JWT 本身验得过验不过的测试和验证的代码在一起（`controller/mcp.rs`）。

use std::collections::BTreeSet;
use std::fs;

use i3t_model::admin::mcp::{CreateMcpToken, MAX_LIFETIME_SECS, McpScope, McpTokenState};
use i3t_model::admin::{ActorKind, CreateGroup, ErrorCode, LogActor, NetworkId, action};

use super::super::mcp::MCP_KEY_FILE;
use super::super::testing::Lab;
use super::super::{Controller, McpRefusal};
use crate::error::Error;
use crate::store::{RETENTION_SECS, Scratch, acting_as};

const ADDR: &str = "ctl.example.com:20331";
const HOUR: u64 = 60 * 60;

fn request(name: &str, scopes: &[McpScope], network: Option<NetworkId>) -> CreateMcpToken {
    CreateMcpToken { name: name.to_owned(), scopes: scopes.to_vec(), network, expires_in_secs: HOUR }
}

/// 最近的操作记录里各条的操作名，新的在前。
fn actions(controller: &Controller) -> Vec<String> {
    controller.oplog(20).unwrap().into_iter().map(|entry| entry.action).collect()
}

#[test]
fn an_issued_token_says_who_it_is_for_and_what_it_may_do_and_its_text_is_kept_nowhere() {
    let lab = Lab::new();
    let home = lab.network("home").id;
    let asked = request("  claude-code ", &[McpScope::NodesEnroll, McpScope::Read, McpScope::Read], Some(home));
    let created = lab.controller.create_mcp_token(&asked).unwrap();
    let info = &created.info;
    assert_eq!((info.name.as_str(), info.network, info.state), ("claude-code", Some(home), McpTokenState::Active));
    assert_eq!(info.scopes, [McpScope::Read, McpScope::NodesEnroll], "去掉重复，按固定的顺序");
    assert_eq!((info.expires_at, info.revoked_at), (info.created_at + HOUR, None));
    assert_eq!(lab.controller.mcp_tokens().unwrap(), std::slice::from_ref(info));

    let grant = lab.controller.mcp_grant(&created.token).unwrap();
    assert_eq!((grant.name.as_str(), grant.jti.as_str(), grant.network), ("claude-code", info.jti.as_str(), Some(home)));
    assert_eq!(grant.scopes, BTreeSet::from([McpScope::Read, McpScope::NodesEnroll]));
    assert_eq!(grant.actor(), LogActor { kind: ActorKind::Mcp, name: "claude-code".to_owned(), jti: info.jti.clone() });

    // 两个令牌可以同名，jti 各是各的。
    let second = lab.controller.create_mcp_token(&request("claude-code", &[McpScope::Read], None)).unwrap();
    assert_ne!(second.info.jti, info.jti);
    assert_eq!(lab.controller.mcp_grant(&second.token).unwrap().network, None);

    let entry = lab.controller.oplog(20).unwrap().into_iter().find(|entry| entry.params["token"] == info.id).unwrap();
    assert_eq!((entry.action.as_str(), entry.network, &entry.actor), (action::MCP_TOKEN_CREATE, Some(home), &None));
    assert_eq!(entry.params["jti"], info.jti.as_str());
    assert_eq!(entry.params["scopes"], serde_json::json!(["read", "nodes:enroll"]));
    for entry in lab.controller.oplog(20).unwrap() {
        let text = format!("{} {}", entry.detail, serde_json::Value::Object(entry.params));
        assert!(!text.contains(&created.token) && !text.contains(&second.token), "记录里没有 JWT：{text}");
        let signature = created.token.rsplit('.').next().unwrap();
        assert!(!text.contains(signature), "{text}");
    }
}

#[test]
fn a_request_for_a_token_says_which_field_is_wrong() {
    let lab = Lab::new();
    let home = lab.network("home").id;
    let refused = |request: CreateMcpToken| {
        let error = lab.controller.create_mcp_token(&request).unwrap_err();
        (error.code(), error.what(), error.field().map(str::to_owned))
    };
    let invalid = |what: &str, field: &str| (ErrorCode::InvalidRequest, Some(what.to_owned()), Some(field.to_owned()));
    let read = [McpScope::Read];

    assert_eq!(refused(request(" ", &read, None)), invalid("empty", "name"));
    assert_eq!(refused(request(&"x".repeat(65), &read, None)), invalid("malformed", "name"));
    assert_eq!(refused(request("a\nb", &read, None)), invalid("malformed", "name"));
    assert_eq!(refused(request("x", &[], None)), invalid("empty", "scopes"));
    assert_eq!(refused(request("x", &[McpScope::Read, McpScope::Unknown], None)), invalid("malformed", "scopes"));
    // 管整个 controller 的权限不能签给只限一个网络的令牌；不限网络的可以。
    for global in [McpScope::NetworksWrite, McpScope::UpdatesWrite] {
        assert_eq!(refused(request("x", &[McpScope::Read, global], Some(home))), invalid("not_allowed", "scopes"));
        lab.controller.create_mcp_token(&request("x", &[global], None)).unwrap();
    }
    assert_eq!(
        refused(request("x", &read, Some(NetworkId(home.0 + 1)))),
        (ErrorCode::NotFound, Some("network".to_owned()), Some("network".to_owned()))
    );
    // 过期时间必须有，而且有上限。
    for secs in [0, MAX_LIFETIME_SECS + 1, u64::MAX] {
        assert_eq!(
            refused(CreateMcpToken { expires_in_secs: secs, ..request("x", &read, None) }),
            invalid("out_of_range", "expires_in_secs")
        );
    }
    lab.controller.create_mcp_token(&CreateMcpToken { expires_in_secs: MAX_LIFETIME_SECS, ..request("x", &read, None) }).unwrap();
    assert_eq!(lab.controller.mcp_tokens().unwrap().len(), 3, "被拒绝的一个都没有记下来");
}

#[test]
fn a_token_stops_counting_the_moment_it_is_revoked_or_expires() {
    let lab = Lab::new();
    let kept = lab.controller.create_mcp_token(&request("kept", &[McpScope::Read], None)).unwrap();
    let revoked = lab.controller.create_mcp_token(&request("revoked", &[McpScope::Read], None)).unwrap();

    let info = lab.controller.revoke_mcp_token(revoked.info.id).unwrap();
    assert_eq!((info.state, info.revoked_at.is_some()), (McpTokenState::Revoked, true));
    assert_eq!(lab.controller.mcp_grant(&revoked.token).unwrap_err(), McpRefusal::Revoked, "下一次调用就被拒绝");
    assert!(lab.controller.mcp_grant(&kept.token).is_ok(), "别的令牌不受影响");

    // 再撤销一次什么也不做：时间是头一次的，操作只记了一条。
    lab.controller.advance_clock(60);
    assert_eq!(lab.controller.revoke_mcp_token(revoked.info.id).unwrap().revoked_at, info.revoked_at);
    assert_eq!(actions(&lab.controller).iter().filter(|action| *action == action::MCP_TOKEN_REVOKE).count(), 1);
    let missing = lab.controller.revoke_mcp_token(revoked.info.id + 100).unwrap_err();
    assert_eq!((missing.code(), missing.what().as_deref()), (ErrorCode::NotFound, Some("mcp_token")));

    lab.controller.advance_clock(HOUR - 61);
    assert!(lab.controller.mcp_grant(&kept.token).is_ok(), "还差一秒");
    lab.controller.advance_clock(1);
    assert_eq!(lab.controller.mcp_grant(&kept.token).unwrap_err(), McpRefusal::Expired);
    let states: Vec<_> = lab.controller.mcp_tokens().unwrap().into_iter().map(|token| token.state).collect();
    assert_eq!(states, [McpTokenState::Expired, McpTokenState::Revoked], "撤销了的过期之后还是算撤销");

    // 过期的留一阵给人看，之后后台清掉。
    lab.controller.advance_clock(RETENTION_SECS - 1);
    lab.controller.tick().unwrap();
    assert_eq!(lab.controller.mcp_tokens().unwrap().len(), 2);
    lab.controller.advance_clock(120);
    // 清理一分钟一次，刚做过的那一轮不算。
    lab.controller.lock().last_purge = None;
    lab.controller.tick().unwrap();
    assert!(lab.controller.mcp_tokens().unwrap().is_empty());
}

#[test]
fn the_tokens_limited_to_a_network_go_with_it() {
    let lab = Lab::new();
    let (home, lab_net) = (lab.network("home").id, lab.network("lab").id);
    let bound = lab.controller.create_mcp_token(&request("bound", &[McpScope::Read], Some(home))).unwrap();
    let elsewhere = lab.controller.create_mcp_token(&request("elsewhere", &[McpScope::Read], Some(lab_net))).unwrap();
    let free = lab.controller.create_mcp_token(&request("free", &[McpScope::Read], None)).unwrap();

    lab.controller.delete_network(home).unwrap();
    assert_eq!(lab.controller.mcp_grant(&bound.token).unwrap_err(), McpRefusal::Unlisted);
    assert!(lab.controller.mcp_grant(&elsewhere.token).is_ok() && lab.controller.mcp_grant(&free.token).is_ok());
    let left: Vec<_> = lab.controller.mcp_tokens().unwrap().into_iter().map(|token| token.name).collect();
    assert_eq!(left, ["elsewhere", "free"]);
}

#[test]
fn tokens_outlive_a_restart_and_a_new_signing_key_revokes_them_all() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let opened = Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap();
    let key_file = dir.path().join(MCP_KEY_FILE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&key_file).unwrap().permissions().mode() & 0o777, 0o600, "只有属主可读写");
    }
    let key = fs::read(&key_file).unwrap();
    assert_ne!(key, fs::read(dir.path().join("controller.key")).unwrap(), "不是 controller 的那一把");
    let live = opened.controller.create_mcp_token(&request("live", &[McpScope::Read], None)).unwrap();
    let gone = opened.controller.create_mcp_token(&request("gone", &[McpScope::Read], None)).unwrap();
    opened.controller.revoke_mcp_token(gone.info.id).unwrap();
    drop(opened);

    // 重启：密钥还是那一把，签过的照旧，撤销了的还是撤销的。
    let reopened = Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap().controller;
    assert_eq!(fs::read(&key_file).unwrap(), key);
    assert_eq!(reopened.mcp_grant(&live.token).unwrap().name, "live");
    assert_eq!(reopened.mcp_grant(&gone.token).unwrap_err(), McpRefusal::Revoked);
    assert!(!actions(&reopened).contains(&action::MCP_KEY_ROTATE.to_owned()));
    drop(reopened);

    // 换密钥：删掉文件再启动。原来签的全部作废，列表里也标成撤销，记了一条操作。
    fs::remove_file(&key_file).unwrap();
    let rotated = Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap().controller;
    assert_ne!(fs::read(&key_file).unwrap(), key, "生成了新的一把");
    assert_eq!(rotated.mcp_grant(&live.token).unwrap_err(), McpRefusal::BadSignature);
    let tokens = rotated.mcp_tokens().unwrap();
    assert!(tokens.iter().all(|token| token.state == McpTokenState::Revoked), "{tokens:?}");
    let rotation = rotated.oplog(1).unwrap().remove(0);
    assert_eq!((rotation.action.as_str(), &rotation.params["revoked"]), (action::MCP_KEY_ROTATE, &serde_json::json!(1)));
    let fresh = rotated.create_mcp_token(&request("fresh", &[McpScope::Read], None)).unwrap();
    assert_eq!(rotated.mcp_grant(&fresh.token).unwrap().name, "fresh");
    drop(rotated);

    // 之后的重启不再有事。
    let again = Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap().controller;
    assert_eq!(again.mcp_grant(&fresh.token).unwrap().name, "fresh");
    assert_eq!(actions(&again).iter().filter(|action| *action == action::MCP_KEY_ROTATE).count(), 1);
}

#[test]
fn a_key_file_that_cannot_be_read_stops_the_start_instead_of_being_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = Scratch::new();
    let database = scratch.database();
    let opened = Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap();
    let live = opened.controller.create_mcp_token(&request("live", &[McpScope::Read], None)).unwrap();
    drop(opened);

    let key_file = dir.path().join(MCP_KEY_FILE);
    let key = fs::read(&key_file).unwrap();
    fs::write(&key_file, "这不是密钥").unwrap();
    let refused = Controller::open(dir.path(), &database, ADDR.to_owned()).err().expect("密钥读不懂");
    assert!(matches!(&refused, Error::Key { path, .. } if *path == key_file), "{refused:?}");
    assert_eq!(fs::read_to_string(&key_file).unwrap(), "这不是密钥", "不悄悄换成一把新的");

    // 放回来就照常，令牌一个没丢。
    fs::write(&key_file, key).unwrap();
    let restored = Controller::open(dir.path(), &database, ADDR.to_owned()).unwrap().controller;
    assert_eq!(restored.mcp_grant(&live.token).unwrap().name, "live");
}

#[test]
fn what_is_done_while_acting_as_a_token_is_logged_with_it_and_the_rest_is_not() {
    let lab = Lab::new();
    let home = lab.network("home").id;
    let created = lab.controller.create_mcp_token(&request("claude-code", &[McpScope::ConfigWrite], Some(home))).unwrap();
    let grant = lab.controller.mcp_grant(&created.token).unwrap();

    let by_token = acting_as(grant.actor(), || lab.controller.create_group(home, &CreateGroup { name: "servers".to_owned() })).unwrap();
    let by_admin = lab.controller.create_group(home, &CreateGroup { name: "laptops".to_owned() }).unwrap();
    // 失败的操作不留记录，也不把"是谁"留在这个线程上。
    assert!(acting_as(grant.actor(), || lab.controller.create_group(home, &CreateGroup { name: "servers".to_owned() })).is_err());
    lab.controller.delete_group(home, by_admin.id).unwrap();

    let entries = lab.controller.oplog(3).unwrap();
    let who: Vec<_> = entries.iter().map(|entry| (entry.action.as_str(), entry.actor.as_ref().map(|actor| actor.jti.as_str()))).collect();
    assert_eq!(who, [(action::GROUP_DELETE, None), (action::GROUP_CREATE, None), (action::GROUP_CREATE, Some(created.info.jti.as_str()))]);
    assert_eq!(entries[2].actor, Some(grant.actor()));
    assert_eq!(entries[2].params["group"], by_token.id.0);
}
