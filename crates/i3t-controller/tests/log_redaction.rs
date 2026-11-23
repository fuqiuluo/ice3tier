//! 日志级别开到 debug（`I3T_LOG=debug`）时，数据库的驱动会经 `log` 把每条语句的参数打出来。
//! 代理的密码是原样存的，不能跟着出现在日志里。
//!
//! 这个文件自己是一个测试程序：它要装一个全局的日志接收器，不能和别的测试混在一个进程里。

use std::sync::Mutex;

use i3t_controller::store::{NewNetwork, NewNode, ProxyRecord, Store};
use i3t_model::control::Declared;
use i3t_model::netmap::{ListenerProtocol, Reach, RoutingMode, Verifier};
use i3t_proto::PublicKey;

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// 把每一条日志的正文收起来。
struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        if let Ok(mut lines) = LINES.lock() {
            lines.push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

#[test]
fn a_proxy_password_never_shows_up_in_debug_logs() {
    log::set_logger(&Capture).unwrap();
    log::set_max_level(log::LevelFilter::Debug);

    let store = Store::temporary();
    let network = store
        .insert_network(&NewNetwork {
            name: "home".to_owned(),
            cidr: "10.66.0.0/16".parse().unwrap(),
            routing: RoutingMode::DirectFirst,
            max_relay_hops: 2,
            reach: Reach::Any,
            created_at: 1_000,
            class: None,
            ack_eliciting_threshold: 3,
            max_ack_delay_ms: 2,
            bundle_small_packets: true,
            vnet_offload: true,
            vnet_mtu: 1280,
        })
        .unwrap();
    let node = store
        .insert_node(&NewNode {
            network,
            key: PublicKey::from_bytes([7; PublicKey::LEN]),
            name: Some("gateway".to_owned()),
            virtual_ip: "10.66.0.7".parse().unwrap(),
            groups: Default::default(),
            declared: Declared::default(),
            platform: "linux-x86_64".to_owned(),
            version: "0.1.0".to_owned(),
            created_at: 1_000,
            enrolled_with: None,
        })
        .unwrap();

    let mut proxy = ProxyRecord {
        id: 0,
        node,
        name: "visible-proxy-name".to_owned(),
        bind: "127.0.0.1:11002".parse().unwrap(),
        protocol: ListenerProtocol::Socks5,
        exit: None,
        username: "visible-user".to_owned(),
        password: "s3cret-first-password".to_owned(),
        salt: [9; Verifier::SALT_LEN],
        enabled: false,
        allow_from: Vec::new(),
        class: None,
        optimistic: None,
        lane: false,
    };
    proxy.id = store.insert_proxy(&proxy).unwrap();
    proxy.password = "s3cret-second-password".to_owned();
    store.update_proxy(&proxy).unwrap();
    assert_eq!(store.proxy(network, proxy.id).unwrap().unwrap().password, "s3cret-second-password", "存进去的是原文");

    let lines = LINES.lock().unwrap().join("\n");
    assert!(lines.contains("executing statement"), "驱动确实在往日志里打参数，这个测试才有意义：\n{lines}");
    assert!(lines.contains("visible-proxy-name") && lines.contains("visible-user"), "别的参数照常打出来：\n{lines}");
    assert!(!lines.contains("s3cret"), "密码出现在了日志里：\n{lines}");
}
