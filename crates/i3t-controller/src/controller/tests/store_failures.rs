//! 存储暂时读写不了的时候，改了一半的不留下，改完了的不丢下后面该做的事：要重算的照样重算，该发的更新指令照样发。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use i3t_model::admin::{CreateEnrollToken, CreateRule, Direction, NetworkId, RelaySettings, UpdateNode};
use i3t_model::control::{Declared, Hello, ToNode};
use i3t_proto::NodeId;
use tokio::sync::mpsc;

use super::super::testing::{CAN_DO_ALL, Lab, Member, hello};
use super::ordering::{block_column_of, report_endpoints, two_unconnected};
use super::{is_woken, relations};

/// 让存储里 `nodes` 表的这一列写不进去，模拟这一列暂时写不进去；别的写照常。
fn block(lab: &Lab, column: &str) {
    lab.controller.lock().store.block(&format!("no_{column}"), &format!("UPDATE OF {column} ON nodes"), None);
}

fn unblock(lab: &Lab, column: &str) {
    lab.controller.lock().store.unblock(&format!("no_{column}"), "nodes");
}

/// 让这张表读不出来（改个名字），模拟数据库暂时读不了；`restore` 改回来。
fn hide(lab: &Lab, table: &str) {
    lab.controller.lock().store.execute_batch(&format!("ALTER TABLE {table} RENAME TO {table}_away;"));
}

fn restore(lab: &Lab, table: &str) {
    lab.controller.lock().store.execute_batch(&format!("ALTER TABLE {table}_away RENAME TO {table};"));
}

#[test]
fn a_rule_change_whose_affected_nodes_cannot_be_read_is_not_left_half_done() {
    let mut lab = Lab::new();
    let (network, mut source, mut destination) = two_unconnected(&mut lab);
    let (src, dst) = (lab.group(network, "src"), lab.group(network, "dst"));
    let request = CreateRule { name: String::new(), src, dst, direction: Direction::OneWay, enabled: true };

    // 规则写得进去，要重算哪些节点却读不出来：规则也不留下，不然它已经生效了却没人去重算。
    hide(&lab, "nodes");
    assert!(lab.controller.create_rule(network, &request).is_err());
    restore(&lab, "nodes");
    assert!(lab.controller.rules(network).unwrap().is_empty());

    lab.controller.create_rule(network, &request).unwrap();
    lab.settle(&mut [&mut source, &mut destination]);
    assert_eq!(relations(source.netmap()), vec![(destination.id, false, true)]);
}

#[test]
fn switching_a_forward_target_whose_forwards_cannot_be_read_is_not_left_half_done() {
    let mut lab = Lab::new();
    let network = lab.network("home").id;
    let target = lab.join(network, &[]);
    let request = UpdateNode { forward_target: Some(true), ..UpdateNode::default() };

    hide(&lab, "forwards");
    assert!(lab.controller.update_node(network, target.id, &request).is_err());
    restore(&lab, "forwards");
    assert!(!lab.controller.node(network, target.id).unwrap().node.forward_target, "要重算的读不出来，开关也不留下");
}

/// 一个启用了的 relay 和一个用着它的节点；relay 已经下线，等着重新连上来。
fn relay_gone_offline(lab: &mut Lab) -> (NetworkId, Member, Member) {
    let network = lab.network("home").id;
    let mut relay = lab.join_with(network, &[], CAN_DO_ALL);
    let mut client = lab.join(network, &[]);
    lab.controller.enable_relay(network, relay.id, RelaySettings::default()).unwrap();
    lab.settle(&mut [&mut relay, &mut client]);
    assert_eq!(client.netmap().relays.len(), 1);
    lab.controller.disconnect(relay.session);
    lab.settle(&mut [&mut client]);
    (network, relay, client)
}

#[test]
fn a_withdrawn_relay_whose_new_address_cannot_be_saved_is_not_left_half_done() {
    let mut lab = Lab::new();
    let (network, relay, mut client) = relay_gone_offline(&mut lab);

    // 重新连上来时不再声明 relay，端口也换了。地址写不进去：撤回也不留下，不然 relay 关了，却没人告诉用着它的节点。
    block(&lab, "observed");
    let moved = Hello { port: 20444, ..hello(Declared::default()) };
    assert!(lab.connect_as(relay.key, &moved).is_err());
    assert!(lab.controller.node(network, relay.id).unwrap().node.relay.is_some());

    unblock(&lab, "observed");
    lab.connect_as(relay.key, &moved).unwrap();
    lab.settle(&mut [&mut client]);
    assert!(client.netmap().relays.is_empty());
}

#[test]
fn a_node_whose_last_seen_time_cannot_be_recorded_still_comes_online() {
    let mut lab = Lab::new();
    let (_, relay, mut client) = relay_gone_offline(&mut lab);

    // 只是"最近在线"记不下来：它照样上线，撤回的 relay 照样告诉用着它的节点。
    block(&lab, "last_seen_at");
    lab.connect(relay.key, Declared::default()).expect("节点应该能上线");
    lab.settle(&mut [&mut client]);
    assert!(client.netmap().relays.is_empty());
}

#[test]
fn a_public_host_that_could_not_be_applied_to_every_node_is_applied_again() {
    let mut lab = Lab::new();
    let network = lab.network("home").id;
    let secret = lab.secret(network, &CreateEnrollToken::default());
    let key = lab.fresh_key();
    let (outbox, _inbox) = mpsc::channel(64);
    let session = lab.controller.enroll(key, &secret, &hello(CAN_DO_ALL), IpAddr::V4(Ipv4Addr::LOCALHOST), outbox).unwrap();
    let observed = || lab.controller.node(network, session.node).unwrap().observed_endpoint;
    let public: IpAddr = "203.0.113.1".parse().unwrap();

    block(&lab, "observed");
    assert!(lab.controller.set_public_host(Some(public)).is_err());
    unblock(&lab, "observed");
    // 后台任务过一会儿又解析出同一个 IP：上次没改完，这次要接着改，不能当作"没变"。
    lab.controller.set_public_host(Some(public)).unwrap();
    assert_eq!(observed(), Some(SocketAddr::new(public, 20330)));
}

/// 一个和 controller 在同一台机器上、走回环连上来的节点。收件箱要留着：丢了的话它的连接就算断了。
fn looped_node(lab: &mut Lab, network: NetworkId) -> (NodeId, mpsc::Receiver<ToNode>) {
    let secret = lab.secret(network, &CreateEnrollToken::default());
    let key = lab.fresh_key();
    let (outbox, inbox) = mpsc::channel(64);
    let session = lab.controller.enroll(key, &secret, &hello(CAN_DO_ALL), IpAddr::V4(Ipv4Addr::LOCALHOST), outbox).unwrap();
    (session.node, inbox)
}

#[test]
fn a_public_host_applied_to_only_some_nodes_leaves_none_of_them_behind_whichever_ip_comes_next() {
    let mut lab = Lab::new();
    let network = lab.network("home").id;
    let (a, _a) = looped_node(&mut lab, network);
    let (b, _b) = looped_node(&mut lab, network);
    // 节点按编号的顺序改：后改的那个写不进去时，先改的那个已经改过了。
    let (first, second) = (a.min(b), a.max(b));
    let hosts = || {
        let host = |node| lab.controller.node(network, node).unwrap().observed_endpoint.map(|endpoint| endpoint.ip());
        (host(first), host(second))
    };
    let (old, new): (IpAddr, IpAddr) = ("203.0.113.1".parse().unwrap(), "203.0.113.2".parse().unwrap());
    lab.controller.set_public_host(Some(old)).unwrap();

    block_column_of(&lab, "observed", second);
    assert!(lab.controller.set_public_host(Some(new)).is_err());
    unblock(&lab, "observed");
    assert_eq!(hosts(), (Some(old), Some(old)), "要么都改，要么都不改");

    // 下次解析又回到了旧的 IP（DNS 抖了一下）：和记着的一样，什么都不用做，也不能有节点停在新的 IP 上。
    lab.controller.set_public_host(Some(old)).unwrap();
    assert_eq!(hosts(), (Some(old), Some(old)));
    lab.controller.set_public_host(Some(new)).unwrap();
    assert_eq!(hosts(), (Some(new), Some(new)));
}

#[test]
fn a_database_that_takes_no_writes_is_tried_once_by_the_background_work_and_then_left_alone_for_a_while() {
    let mut lab = Lab::new();
    // 整个数据库写不进去（这里是变成了只读；连不上、盘满了也一样）。只是某一行、某张表被别的连接占着是另一回事：
    // 那种时候等多久由存储自己限着，见 `ordering` 里等锁的那几个测试。
    let read_only = |lab: &Lab, on: bool| lab.controller.lock().store.set_read_only(on);
    let network = lab.network("home").id;
    let (mut reporter, mut peer) = (lab.join(network, &[]), lab.join(network, &[]));
    lab.settle(&mut [&mut reporter, &mut peer]);
    // 对端的 netmap 要变（要写存储），过期的记录也到了该清的时候。
    report_endpoints(&lab, &reporter, "203.0.113.9:1");
    lab.controller.lock().last_purge = None;
    // 做一遍后台工作，时间算作 `after` 之后：过了退避的那一会儿，或者就是现在。
    let work = |lab: &Lab, after: Duration| {
        let mut inner = lab.controller.lock();
        let wall = inner.clock.now();
        inner.tick_work(Instant::now() + after, wall)
    };
    let past_back_off = Duration::from_secs(2);

    // 重算撞上了：这一轮不再接着去清理，那只会再撞一次。
    read_only(&lab, true);
    assert!(work(&lab, past_back_off).is_err());
    assert!(lab.controller.lock().last_purge.is_none(), "清理没做，下次接着做");
    // 重算排上重试时叫醒了后台任务，它马上又来一轮：还在退避，什么都不去写，也就不出错。
    assert!(is_woken(&lab));
    work(&lab, Duration::ZERO).unwrap();
    assert!(lab.controller.lock().last_purge.is_none());

    read_only(&lab, false);
    work(&lab, past_back_off).unwrap();
    assert!(lab.controller.lock().last_purge.is_some());
    assert_eq!(peer.receive(), 1, "写得进去之后补发");

    // 没有要重算的，是清理先撞上了：一样退避，紧接着的一轮不再去撞（去撞的话这一轮会带着错误回来）。
    read_only(&lab, true);
    lab.controller.lock().last_purge = None;
    assert!(work(&lab, past_back_off).is_err());
    work(&lab, Duration::ZERO).unwrap();
    read_only(&lab, false);
}

#[test]
fn background_work_goes_on_after_a_refresh_fails() {
    let mut lab = Lab::new();
    let network = lab.network("home").id;
    let a = lab.join(network, &[]);
    {
        let mut inner = lab.controller.lock();
        inner.defer(network, [a.id], Duration::ZERO);
        inner.updates.next_rollout = Some(Instant::now());
    }
    hide(&lab, "pair_settings");
    assert!(lab.controller.tick().is_err());
    restore(&lab, "pair_settings");
    assert_eq!(lab.controller.lock().updates.next_rollout, None, "重算出了错，到点的更新照样做了");
}

#[test]
fn an_update_rollout_that_could_not_read_the_store_is_tried_again() {
    let mut lab = Lab::new();
    let network = lab.network("home").id;
    lab.join(network, &[]);
    hide(&lab, "nodes");
    let mut inner = lab.controller.lock();
    assert!(inner.roll_out().is_err());
    assert!(inner.updates.next_rollout.is_some(), "没做完，过一会儿再做");
    drop(inner);
    restore(&lab, "nodes");
}
