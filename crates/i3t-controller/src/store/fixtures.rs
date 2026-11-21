//! 测试里反复用到的数据。

use i3t_model::admin::NetworkId;
use i3t_model::control::Declared;
use i3t_model::netmap::{Reach, RoutingMode};
use i3t_proto::{NodeId, PublicKey};

use super::{NetmapState, NewNetwork, NewNode, NodeRecord, Store};

pub(crate) fn home() -> NewNetwork {
    NewNetwork {
        name: "home".to_owned(),
        cidr: "10.66.0.0/16".parse().unwrap(),
        routing: RoutingMode::DirectFirst,
        max_relay_hops: 2,
        reach: Reach::Any,
        created_at: 1_000,
        class: None,
        ack_eliciting_threshold: 3,
        max_ack_delay_ms: 2,
    }
}

pub(crate) fn key(seed: u8) -> PublicKey {
    PublicKey::from_bytes([seed; PublicKey::LEN])
}

/// 第 `seed` 个节点：公钥和虚拟 IP 都由 `seed` 决定，所以不同的 `seed` 不会撞。
pub(crate) fn new_node(network: NetworkId, seed: u8) -> NewNode {
    NewNode {
        network,
        key: key(seed),
        name: None,
        virtual_ip: [10, 66, 0, seed].into(),
        groups: Default::default(),
        declared: Declared::default(),
        platform: "linux-x86_64".to_owned(),
        version: "0.1.0".to_owned(),
        created_at: 1_000,
        enrolled_with: None,
    }
}

/// 一个网络加 `count` 个节点。
pub(crate) fn store_with_nodes(count: u8) -> (Store, NetworkId, Vec<NodeId>) {
    let store = Store::open_in_memory().unwrap();
    let network = store.insert_network(&home()).unwrap();
    let nodes = (1..=count).map(|seed| store.insert_node(&new_node(network, seed)).unwrap()).collect();
    (store, network, nodes)
}

/// 第 `seed` 个节点的记录，不经过存储：只用来测按记录算东西的函数。别的字段按需要改。
pub(crate) fn record(seed: u8) -> NodeRecord {
    NodeRecord {
        id: NodeId::new(u32::from(seed)).unwrap(),
        network: NetworkId(1),
        key: key(seed),
        name: format!("node-{seed}"),
        virtual_ip: [10, 66, 0, seed].into(),
        groups: Default::default(),
        declared: Declared::default(),
        forward_target: false,
        relay: None,
        exit: None,
        dial_out_only: false,
        routing: None,
        reach: None,
        pinned_relays: Vec::new(),
        profile: None,
        auto_update: true,
        endpoints: Vec::new(),
        local_addresses: None,
        observed: None,
        attached: Vec::new(),
        relay_reach: Vec::new(),
        platform: String::new(),
        version: String::new(),
        hostname: String::new(),
        self_update: None,
        update_failure: None,
        created_at: 0,
        last_seen_at: None,
        netmap: NetmapState::default(),
        enrolled_with: None,
    }
}
