//! 不读写存储的节点消息（见 `switchboard`）：controller 的锁被占用时照常处理，其余消息等待锁；连接被顶替、发送队列已满时的处理。

use std::sync::mpsc;
use std::time::Duration;

use i3t_model::control::exit_test::ExitVia;
use i3t_model::control::{ExitTestResult, RouteAnswer, Signal, ToController};
use i3t_proto::NodeId;

use super::super::testing::{Lab, REMOTE, modern_hello};
use super::super::{Controller, Waits};

fn punch() -> Signal {
    Signal::PunchRequest { endpoints: vec!["203.0.113.1:20330".parse().unwrap()] }
}

/// 取一段 controller 没有缓存的更新包。
fn package_request(request: u64) -> ToController {
    ToController::PackageRequest {
        request,
        version: "0.9.0".parse().unwrap(),
        platform: "linux-x86_64".parse().unwrap(),
        offset: 0,
        len: 1,
    }
}

/// 每一种节点消息各一条。信令发给 `to`。
fn every_message(to: NodeId) -> Vec<ToController> {
    let answer = RouteAnswer { peer: to, route: None, rtt_ms: None, since: None, detail: None, connection_rtt_ms: None };
    let result = ExitTestResult { via: ExitVia::Direct, refused: None, resolve: None, connect: None, tls: None };
    vec![
        package_request(1),
        ToController::RouteAnswer { request: 1, answer },
        ToController::BackboneAnswer { request: 2, rows: Vec::new() },
        ToController::ExitTestAnswer { request: 3, result: Box::new(result) },
        ToController::Signal { to, signal: punch() },
        ToController::Heartbeat,
        ToController::Enroll { token: "unused".to_owned(), hello: modern_hello("0.2.0") },
        ToController::TestReport(Box::default()),
        ToController::Report(Box::default()),
        ToController::Ack { version: 0 },
        ToController::Hello(modern_hello("0.2.0")),
    ]
}

#[test]
fn only_messages_that_use_the_store_wait_while_the_controller_lock_is_held() {
    let mut lab = Lab::new();
    let network = lab.network("home").id;
    let mut a = lab.join_as(network, &modern_hello("0.2.0"));
    let mut b = lab.join_as(network, &modern_hello("0.2.0"));
    lab.settle(&mut [&mut a, &mut b]);
    let (controller, session) = (&lab.controller, a.session);

    // 锁被占用，例如一次操作正在等待无响应的数据库。`Controller::waits` 说不等存储的消息照常处理完，其余的等锁。
    std::thread::scope(|scope| {
        let held = controller.lock();
        let mut waiting = Vec::new();
        for (index, message) in every_message(b.id).into_iter().enumerate() {
            let waits = Controller::waits(&message);
            let (done, finished) = mpsc::channel();
            let worker = scope.spawn(move || {
                let _outcome = controller.handle(session, REMOTE, message);
                done.send(()).expect("测试线程一直在等这个结果");
            });
            if waits == Waits::Store {
                assert!(finished.recv_timeout(Duration::from_millis(300)).is_err(), "第 {index} 条消息应当等锁");
                waiting.push((worker, finished));
            } else {
                finished.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| panic!("第 {index} 条消息（{waits:?}）不应等锁"));
                worker.join().unwrap();
            }
        }
        drop(held);
        for (worker, finished) in waiting {
            worker.join().unwrap();
            finished.recv().unwrap();
        }
    });
    b.receive();
    assert_eq!(b.signals, [(a.id, punch())], "锁被占用期间信令照常转发");
    a.receive();
    assert!(matches!(a.chunks.as_slice(), [(1, Err(_))]), "取包照常回复：{:?}", a.chunks);
}

#[test]
fn quick_messages_on_a_replaced_connection_are_ignored() {
    let mut lab = Lab::new();
    let network = lab.network("home").id;
    let mut a = lab.join_as(network, &modern_hello("0.2.0"));
    let mut b = lab.join_as(network, &modern_hello("0.2.0"));
    lab.settle(&mut [&mut a, &mut b]);
    let old = a.session;
    let mut again = lab.connect_as(a.key, &modern_hello("0.2.0")).unwrap();
    lab.settle(&mut [&mut again, &mut b]);

    lab.controller.handle(old, REMOTE, ToController::Signal { to: b.id, signal: punch() }).unwrap();
    lab.controller.handle(old, REMOTE, package_request(5)).unwrap();
    b.receive();
    again.receive();
    assert!(b.signals.is_empty(), "旧连接上的信令不转发");
    assert!(again.chunks.is_empty(), "旧连接上的取包请求不回复：{:?}", again.chunks);

    lab.controller.handle(again.session, REMOTE, ToController::Signal { to: b.id, signal: punch() }).unwrap();
    b.receive();
    assert_eq!(b.signals, [(a.id, punch())], "新连接上照常");
}

#[test]
fn a_node_that_does_not_read_its_package_replies_is_disconnected() {
    let mut lab = Lab::new();
    let network = lab.network("home").id;
    // 节点从不读取发送队列：回复积满后无法放入，连接被去掉，后台任务将其记为离线。
    let member = lab.join_as(network, &modern_hello("0.2.0"));
    for request in 0..100 {
        lab.controller.handle(member.session, REMOTE, package_request(request)).unwrap();
    }
    assert!(!lab.controller.lock().switchboard().is_current(member.session), "发送队列已满，连接已去掉");
    assert!(lab.controller.lock().is_online(member.id), "此时只有持有 controller 锁的一方能把它记为离线");
    let _next = lab.controller.tick();
    assert!(!lab.controller.node(network, member.id).unwrap().node.online, "后台任务把它记为离线");
}
