//! 网络的增删改查。

use i3t_model::admin::{
    ACK_ELICITING_THRESHOLD, CreateNetwork, Direction, GroupRef, LogRef, MAX_ACK_DELAY_MS, Network, NetworkDefaults, NetworkId, RefKind,
    Rule, UpdateNetwork, action,
};
use i3t_model::netmap::VNET_MTU;
use ipnet::Ipv4Net;
use serde_json::json;

use super::{Controller, Inner, Seeds, address, naming};
use crate::error::{Entity, Error, InField};
use crate::store::{BUILTIN_GROUP, NetworkRecord, NewNetwork};

/// 一条路径最多经过几个 relay：协议允许的范围。
const MAX_RELAY_HOPS: std::ops::RangeInclusive<u8> = 1..=4;

impl Controller {
    /// # Errors
    ///
    /// 读存储失败。
    pub fn networks(&self) -> Result<Vec<Network>, Error> {
        let inner = self.lock();
        inner.store.networks()?.iter().map(|record| inner.network_view(record)).collect()
    }

    /// # Errors
    ///
    /// 没有这个网络，或者读存储失败。
    pub fn network(&self, id: NetworkId) -> Result<Network, Error> {
        let inner = self.lock();
        inner.network_view(&inner.require_network(id)?)
    }

    /// 新建一个网络。它自带内置分组 `All` 和一条 `All <-> All` 规则，所以装好就能互通。
    ///
    /// # Errors
    ///
    /// 名字不合法或者已经有了；地址段和别的网络重叠；没指定地址段而默认的都被占了。
    pub fn create_network(&self, request: &CreateNetwork) -> Result<Network, Error> {
        let name = naming::label("网络", &request.name).in_field("name")?;
        let defaults = NetworkDefaults::default();
        let max_relay_hops = check_max_relay_hops(request.max_relay_hops.unwrap_or(defaults.max_relay_hops))?;
        let ack_eliciting_threshold =
            check_ack_eliciting_threshold(request.ack_eliciting_threshold.unwrap_or(defaults.ack_eliciting_threshold))?;
        let max_ack_delay_ms = check_max_ack_delay_ms(request.max_ack_delay_ms.unwrap_or(defaults.max_ack_delay_ms))?;
        let vnet_mtu = check_vnet_mtu(request.vnet_mtu.unwrap_or(defaults.vnet_mtu))?;
        let mut inner = self.lock();
        let now = inner.clock.now();
        let id = inner.store.atomically(|store| {
            let existing = store.networks()?;
            if existing.iter().any(|network| network.name == name) {
                return Err(Error::NameTaken(name.clone()));
            }
            let cidr = match request.cidr {
                Some(cidr) => address::normalize(cidr).in_field("cidr")?,
                None => {
                    let taken: Vec<Ipv4Net> = existing.iter().map(|network| network.cidr).collect();
                    address::default_range(&taken)
                        .ok_or_else(|| Error::invalid_field("cidr", "no_default", "默认的地址段都被占用了，请用 cidr 指定一个"))?
                }
            };
            check_no_overlap(&existing, None, cidr).in_field("cidr")?;
            let id = store.insert_network(&NewNetwork {
                name: name.clone(),
                cidr,
                routing: request.routing.unwrap_or(defaults.routing),
                max_relay_hops,
                reach: request.reach.unwrap_or(defaults.reach),
                created_at: now,
                class: request.class.or(defaults.class),
                ack_eliciting_threshold,
                max_ack_delay_ms,
                bundle_small_packets: request.bundle_small_packets.unwrap_or(defaults.bundle_small_packets),
                vnet_offload: request.vnet_offload.unwrap_or(defaults.vnet_offload),
                vnet_mtu,
            })?;
            let all = store.builtin_group(id)?.ok_or(Error::NotFound(Entity::Group))?;
            let all = GroupRef { id: all, name: BUILTIN_GROUP.to_owned(), builtin: true };
            let default_rule =
                Rule { id: 0, name: "default".to_owned(), src: all.clone(), dst: all, direction: Direction::Both, enabled: true };
            store.insert_rule(id, &default_rule)?;
            let refs = [LogRef::new(RefKind::Network, id.0)];
            let params = json!({ "network": id, "network_name": name, "cidr": cidr });
            store.log_refs(now, Some(id), action::NETWORK_CREATE, &format!("新建网络 {name}，地址段 {cidr}"), &refs, params)?;
            Ok(id)
        })?;
        tracing::info!(network = %id, %name, "新建网络");
        inner.network_view(&inner.require_network(id)?)
    }

    /// 改网络的设置，并把新的设置发给网络里的节点。
    ///
    /// # Errors
    ///
    /// 没有这个网络；地址段和别的网络重叠；网络里已经有节点而新的地址段不包含原来的。
    pub fn update_network(&self, id: NetworkId, request: &UpdateNetwork) -> Result<Network, Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        let updated = inner.store.atomically(|store| {
            let mut network = store.network(id)?.ok_or(Error::NotFound(Entity::Network))?;
            if let Some(cidr) = request.cidr {
                let cidr = address::normalize(cidr).in_field("cidr")?;
                check_no_overlap(&store.networks()?, Some(id), cidr).in_field("cidr")?;
                if store.node_count(Some(id))? > 0 && !cidr.contains(&network.cidr) {
                    return Err(Error::RangeNotSuperset(network.cidr).in_field("cidr"));
                }
                network.cidr = cidr;
            }
            if let Some(max_relay_hops) = request.max_relay_hops {
                network.max_relay_hops = check_max_relay_hops(max_relay_hops)?;
            }
            if let Some(threshold) = request.ack_eliciting_threshold {
                network.ack_eliciting_threshold = check_ack_eliciting_threshold(threshold)?;
            }
            if let Some(delay) = request.max_ack_delay_ms {
                network.max_ack_delay_ms = check_max_ack_delay_ms(delay)?;
            }
            if let Some(bundle) = request.bundle_small_packets {
                network.bundle_small_packets = bundle;
            }
            if let Some(mtu) = request.vnet_mtu {
                network.vnet_mtu = check_vnet_mtu(mtu)?;
            }
            network.vnet_offload = request.vnet_offload.unwrap_or(network.vnet_offload);
            network.routing = request.routing.unwrap_or(network.routing);
            network.reach = request.reach.unwrap_or(network.reach);
            network.class = request.class.unwrap_or(network.class);
            store.update_network(&network)?;
            let refs = [LogRef::new(RefKind::Network, id.0)];
            let params = json!({
                "network": id,
                "network_name": network.name,
                "cidr": network.cidr,
                "routing": network.routing,
                "max_relay_hops": network.max_relay_hops,
                "reach": network.reach,
                "class": network.class,
                "ack_eliciting_threshold": network.ack_eliciting_threshold,
                "max_ack_delay_ms": network.max_ack_delay_ms,
                "bundle_small_packets": network.bundle_small_packets,
                "vnet_offload": network.vnet_offload,
                "vnet_mtu": network.vnet_mtu,
            });
            store.log_refs(now, Some(id), action::NETWORK_UPDATE, &format!("修改网络 {} 的设置", network.name), &refs, params)?;
            Ok::<_, Error>(network)
        })?;
        inner.refresh(id, Seeds::All, None)?;
        self.wake_if_needed(&inner);
        inner.network_view(&updated)
    }

    /// 删掉一个空的网络，连同它的分组、规则、凭据、注册令牌和只限它的 MCP 令牌。
    ///
    /// # Errors
    ///
    /// 没有这个网络，或者里面还有节点。
    pub fn delete_network(&self, id: NetworkId) -> Result<(), Error> {
        let mut inner = self.lock();
        let now = inner.clock.now();
        inner.store.atomically(|store| {
            let network = store.network(id)?.ok_or(Error::NotFound(Entity::Network))?;
            if store.node_count(Some(id))? > 0 {
                return Err(Error::NetworkNotEmpty(network.name));
            }
            store.delete_network(id)?;
            let params = json!({ "network": id, "network_name": network.name });
            let refs = [LogRef::new(RefKind::Network, id.0)];
            store.log_refs(now, None, action::NETWORK_DELETE, &format!("删除网络 {}", network.name), &refs, params)?;
            tracing::info!(network = %id, name = %network.name, "删除网络");
            Ok(())
        })?;
        inner.mcp.forget_network(id);
        Ok(())
    }
}

impl Inner {
    fn network_view(&self, record: &NetworkRecord) -> Result<Network, Error> {
        Ok(Network {
            id: record.id,
            name: record.name.clone(),
            domain: record.domain(),
            cidr: record.cidr,
            routing: record.routing,
            max_relay_hops: record.max_relay_hops,
            reach: record.reach,
            created_at: record.created_at,
            nodes: self.store.node_count(Some(record.id))?,
            class: record.class,
            ack_eliciting_threshold: record.ack_eliciting_threshold,
            max_ack_delay_ms: record.max_ack_delay_ms,
            bundle_small_packets: record.bundle_small_packets,
            vnet_offload: record.vnet_offload,
            vnet_mtu: record.vnet_mtu,
            defaults: Some(NetworkDefaults::default()),
        })
    }
}

fn check_max_relay_hops(hops: u8) -> Result<u8, Error> {
    if MAX_RELAY_HOPS.contains(&hops) {
        Ok(hops)
    } else {
        Err(Error::invalid_field(
            "max_relay_hops",
            "out_of_range",
            format!("最大中转级数要在 {} 到 {} 之间", MAX_RELAY_HOPS.start(), MAX_RELAY_HOPS.end()),
        ))
    }
}

fn check_ack_eliciting_threshold(threshold: u32) -> Result<u32, Error> {
    if ACK_ELICITING_THRESHOLD.contains(&threshold) {
        Ok(threshold)
    } else {
        Err(Error::invalid_field(
            "ack_eliciting_threshold",
            "out_of_range",
            format!("确认阈值要在 {} 到 {} 之间", ACK_ELICITING_THRESHOLD.start(), ACK_ELICITING_THRESHOLD.end()),
        ))
    }
}

fn check_max_ack_delay_ms(delay: u32) -> Result<u32, Error> {
    if MAX_ACK_DELAY_MS.contains(&delay) {
        Ok(delay)
    } else {
        Err(Error::invalid_field(
            "max_ack_delay_ms",
            "out_of_range",
            format!("确认的最长等待要在 {} 到 {} 毫秒之间", MAX_ACK_DELAY_MS.start(), MAX_ACK_DELAY_MS.end()),
        ))
    }
}

fn check_vnet_mtu(mtu: u16) -> Result<u16, Error> {
    if VNET_MTU.contains(&mtu) {
        Ok(mtu)
    } else {
        Err(Error::invalid_field(
            "vnet_mtu",
            "out_of_range",
            format!("虚拟网卡的 MTU 要在 {} 到 {} 字节之间", VNET_MTU.start(), VNET_MTU.end()),
        ))
    }
}

/// 各个网络的地址段不能重叠：一个虚拟 IP 在整个 controller 里只对应一个节点。
fn check_no_overlap(existing: &[NetworkRecord], except: Option<NetworkId>, cidr: Ipv4Net) -> Result<(), Error> {
    match existing.iter().find(|network| Some(network.id) != except && address::overlaps(network.cidr, cidr)) {
        Some(other) => Err(Error::RangeOverlaps { cidr, other: other.name.clone(), other_cidr: other.cidr }),
        None => Ok(()),
    }
}
