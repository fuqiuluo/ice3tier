//! 端口转发的增删改，和每条转发现在的状态。

use std::net::IpAddr;

use i3t_model::admin::{Forward, ForwardInput, ForwardStatus, LogRef, NetworkId, RefKind, action};
use i3t_model::netmap::ForwardProtocol;
use serde_json::{Value, json};

use super::nodes::{is_connectable, require_node};
use super::{Controller, Inner, Seeds, naming};
use crate::access::AccessMap;
use crate::error::{Entity, Error, InField};
use crate::netmap::{NetworkView, Undialable};
use crate::node_addresses::canonical;
use crate::store::{ForwardRecord, Store};

impl Controller {
    /// 一个网络的全部端口转发和它们现在的状态。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn forwards(&self, network: NetworkId) -> Result<Vec<Forward>, Error> {
        let inner = self.lock();
        let view = NetworkView::load(&inner.store, network)?.ok_or(Error::NotFound(Entity::Network))?;
        let access = view.access();
        Ok(view.forwards.iter().map(|record| inner.forward_view(&view, &access, record)).collect())
    }

    /// # Errors
    ///
    /// 两个节点不都在这个网络里；要启用而目标节点的开关（可以作为端口转发的目标）关着；
    /// 地址不合法；监听节点上同一个地址已经有一条同协议的转发。
    pub fn create_forward(&self, network: NetworkId, input: ForwardInput) -> Result<Forward, Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let record = inner.store.atomically(|store| {
            let config = check(store, network, None, input)?;
            let id = store.insert_forward(network, &config)?;
            store.log_refs(
                now,
                Some(network),
                action::FORWARD_CREATE,
                &describe(id, &config),
                &refs(id, &config),
                params(store, id, &config)?,
            )?;
            Ok::<_, Error>(ForwardRecord { id, config })
        })?;
        inner.refresh(network, Seeds::of([record.config.listen_node, record.config.target_node]), None)?;
        self.wake_if_needed(&inner);
        inner.forward_status(network, &record)
    }

    /// 整个替换一条转发。启用和停用也走这里。
    ///
    /// # Errors
    ///
    /// 这个网络里没有这条转发；其余同 [`Controller::create_forward`]。
    pub fn replace_forward(&self, network: NetworkId, id: u32, input: ForwardInput) -> Result<Forward, Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let (before, record) = inner.store.atomically(|store| {
            let before = store.forward(network, id)?.ok_or(Error::NotFound(Entity::Forward))?;
            let config = check(store, network, Some(&before), input)?;
            store.update_forward(id, &config)?;
            store.log_refs(
                now,
                Some(network),
                action::FORWARD_UPDATE,
                &describe(id, &config),
                &refs(id, &config),
                params(store, id, &config)?,
            )?;
            Ok::<_, Error>((before, ForwardRecord { id, config }))
        })?;
        let ends = [before.config.listen_node, before.config.target_node, record.config.listen_node, record.config.target_node];
        inner.refresh(network, Seeds::of(ends), None)?;
        self.wake_if_needed(&inner);
        inner.forward_status(network, &record)
    }

    /// # Errors
    ///
    /// 这个网络里没有这条转发。
    pub fn delete_forward(&self, network: NetworkId, id: u32) -> Result<(), Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let record = inner.store.atomically(|store| {
            let record = store.forward(network, id)?.ok_or(Error::NotFound(Entity::Forward))?;
            let params = params(store, id, &record.config)?;
            store.delete_forward(id)?;
            store.log_refs(now, Some(network), action::FORWARD_DELETE, &describe(id, &record.config), &refs(id, &record.config), params)?;
            Ok::<_, Error>(record)
        })?;
        inner.refresh(network, Seeds::of([record.config.listen_node, record.config.target_node]), None)?;
        self.wake_if_needed(&inner);
        Ok(())
    }
}

impl Inner {
    fn forward_status(&self, network: NetworkId, record: &ForwardRecord) -> Result<Forward, Error> {
        let view = NetworkView::load(&self.store, network)?.ok_or(Error::NotFound(Entity::Network))?;
        Ok(self.forward_view(&view, &view.access(), record))
    }

    fn forward_view(&self, view: &NetworkView, access: &AccessMap<'_>, record: &ForwardRecord) -> Forward {
        let config = &record.config;
        let switched_on = view.nodes.get(&config.target_node).is_some_and(|target| target.forward_target);
        // 停用是这条转发自己的设置，排在目标的开关前面：开关打开之后它也不会生效。
        let status = if !config.enabled {
            ForwardStatus::Disabled
        } else if !switched_on {
            ForwardStatus::ForwardTargetOff
        } else if Undialable::of(view.network.cidr, config.target_addr).is_some() {
            ForwardStatus::TargetNotAllowed
        } else if !view.forward_is_deliverable(access, record) {
            ForwardStatus::AccessDenied
        } else if !self.is_online(config.listen_node) {
            ForwardStatus::ListenerOffline
        } else if !self.is_online(config.target_node) {
            ForwardStatus::TargetOffline
        } else {
            ForwardStatus::Active
        };
        Forward {
            id: record.id,
            name: config.name.clone(),
            protocol: config.protocol,
            listen_node: config.listen_node,
            bind: config.bind,
            target_node: config.target_node,
            target_addr: config.target_addr,
            allow_from: config.allow_from.clone(),
            enabled: config.enabled,
            status,
            class: config.class,
            listen: self.forward_listen_status(config.listen_node, record.id),
            target_failure: self.forward_target_failure(config.listen_node, record.id),
            proxy_protocol: config.proxy_protocol,
        }
    }
}

/// 检查一条转发的配置。`replacing` 是正在被替换的那一条，查冲突时不和它自己比。
fn check(store: &Store, network: NetworkId, replacing: Option<&ForwardRecord>, mut config: ForwardInput) -> Result<ForwardInput, Error> {
    config.name = naming::title("端口转发", &config.name, false).in_field("name")?;
    // 同一个地址只存一种写法：IPv4 映射的 IPv6 地址存成它里面的 IPv4 地址，后面的比较和节点上的判断才对得上。
    (config.bind, config.target_addr) = (canonical(config.bind), canonical(config.target_addr));
    let listener = require_node(store, network, config.listen_node).in_field("listen_node")?;
    let target = require_node(store, network, config.target_node).in_field("target_node")?;
    // 目标节点的开关要打开：一台机器的回环和局域网经转发对外，要管理员对这台机器明确地点过头。
    // 拦的是"新启用"：本来就启用着、指向同一个节点的转发在开关关着时照样能改，它留着，开关打开就生效（见 `forward_view`）。
    let already_enabled = replacing.is_some_and(|before| before.config.enabled && before.config.target_node == config.target_node);
    if config.enabled && !already_enabled && !target.forward_target {
        return Err(Error::ForwardTargetOff(target.name).in_field("target_node"));
    }
    // 端口填 0 表示由监听节点自动分配空闲端口（确定后重启保持不变，实际端口以节点上报为准）。
    // 虚拟 IP 上的转发不占操作系统的端口，没有"空闲的端口"可挑，要写明。
    if config.bind.port() == 0 && config.bind.ip() == IpAddr::V4(listener.virtual_ip) {
        return Err(Error::invalid_field("bind", "zero_port", "监听在虚拟 IP 上的端口转发必须显式指定端口，不能为 0"));
    }
    // PROXY protocol 的头是给 TCP 的服务读的：v1 没有 UDP 的写法，v2 的要加在每个报文前面，认它的 UDP 服务几乎没有。
    if config.proxy_protocol.is_some() && config.protocol == ForwardProtocol::Udp {
        return Err(Error::invalid_field("proxy_protocol", "tcp_only", "PROXY protocol 仅适用于 TCP 端口转发"));
    }
    if !is_connectable(&config.target_addr) {
        return Err(Error::invalid_field(
            "target_addr",
            "not_connectable",
            format!("目标地址 {} 不是有效的可连接地址", config.target_addr),
        ));
    }
    // 拒绝目标节点不会连接的地址（节点侧同样会校验）：允许配置也只会产生不可用的转发。仅对启用状态校验（停用项不下发），
    // 以便历史遗留配置可原地停用，重新启用时仍受此校验限制。
    let cidr = store.network(network)?.ok_or(Error::NotFound(Entity::Network))?.cidr;
    if let Some(undialable) = Undialable::of(cidr, config.target_addr).filter(|_| config.enabled) {
        let (what, message) = match undialable {
            Undialable::CloudMetadata => {
                ("cloud_metadata", format!("目标地址 {} 为云平台实例元数据地址，禁止作为端口转发目标", config.target_addr))
            }
            Undialable::Overlay => (
                "overlay_address",
                format!(
                    "目标地址 {} 位于网络虚拟地址段 {cidr} 内：此处应填写目标节点本地可直连的地址（回环或所在局域网地址）",
                    config.target_addr
                ),
            ),
        };
        return Err(Error::invalid_field("target_addr", what, message));
    }
    // 端口写 0 的各挑各的端口，不算冲突。
    let clash = store.forwards(network)?.into_iter().find(|other| {
        Some(other.id) != replacing.map(|before| before.id)
            && other.config.listen_node == config.listen_node
            && other.config.protocol == config.protocol
            && canonical(other.config.bind) == config.bind
            && config.bind.port() != 0
    });
    match clash {
        Some(other) => Err(Error::Conflict {
            with: Entity::Forward,
            message: format!("监听节点上的转发 #{} 已经监听在 {}", other.id, other.config.bind),
        }
        .in_field("bind")),
        None => Ok(config),
    }
}

/// 操作记录里一条转发说到的东西：它自己和两端的节点。
fn refs(id: u32, config: &ForwardInput) -> [LogRef; 3] {
    [LogRef::new(RefKind::Forward, id), LogRef::node(config.listen_node), LogRef::node(config.target_node)]
}

/// 操作记录里一条转发的参数：两端的节点带着当时的名字。
fn params(store: &Store, id: u32, config: &ForwardInput) -> Result<Value, Error> {
    let name = |node| Ok::<_, Error>(store.node(node)?.map(|node| node.name));
    Ok(json!({
        "forward": id,
        "forward_name": config.name,
        "protocol": config.protocol,
        "listen_node": config.listen_node,
        "listen_node_name": name(config.listen_node)?,
        "bind": config.bind,
        "target_node": config.target_node,
        "target_node_name": name(config.target_node)?,
        "target_addr": config.target_addr,
        "enabled": config.enabled,
    }))
}

fn describe(id: u32, config: &ForwardInput) -> String {
    let state = if config.enabled { "启用" } else { "停用" };
    format!(
        "转发 #{id}：节点 #{} 的 {} → 节点 #{} 的 {}（{state}）",
        config.listen_node, config.bind, config.target_node, config.target_addr
    )
}
