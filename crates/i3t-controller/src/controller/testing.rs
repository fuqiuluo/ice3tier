//! 测试用的小实验室：一个开在临时数据库上的 controller，加上几个假装成节点的收件箱。
//!
//! 这里的"节点"不走 TLS，直接调用节点协议在 controller 一侧的入口，所以测的是规则和下发，不是连接本身。

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use i3t_crypto::NodeKey;
use i3t_model::Netmap;
use i3t_model::admin::{CreateEnrollToken, CreateGroup, CreateNetwork, CreateProxy, GroupId, Network, NetworkId, UpdateNode};
use i3t_model::control::{Declared, EnrollToken, Hello, PROTOCOL_REVISION, Report, SelfUpdate, Signal, TestOrder, ToController, ToNode};
use i3t_model::update::{SignedManifest, UpdateStatus, UpdateTiming};
use i3t_proto::{NodeId, PublicKey};
use tokio::sync::mpsc;

use super::{Admitted, Controller, Timing};
use crate::store::Store;

pub(crate) const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

pub(crate) struct Lab {
    pub(crate) controller: Controller,
    next_key: u8,
}

/// 一个假装在线的节点：它的连接，和从 controller 收到的东西。
pub(crate) struct Member {
    pub(crate) id: NodeId,
    pub(crate) key: PublicKey,
    pub(crate) session: Admitted,
    inbox: mpsc::Receiver<ToNode>,
    /// 收到的每一份 netmap，按先后。
    pub(crate) snapshots: Vec<Netmap>,
    pub(crate) signals: Vec<(NodeId, Signal)>,
    pub(crate) revoked: bool,
    /// 收到的更新指令，按先后。
    pub(crate) orders: Vec<(SignedManifest, UpdateTiming)>,
    /// 收到了几次撤回。
    pub(crate) cancels: usize,
    /// 对取包请求的回答：编号，和数据或者给不了的原因。
    pub(crate) chunks: Vec<(u64, Result<Vec<u8>, String>)>,
    /// 收到的路由查询：编号和问的对端。
    pub(crate) queries: Vec<(u64, NodeId)>,
    /// 收到的骨干矩阵查询的编号。
    pub(crate) backbone_queries: Vec<u64>,
    /// 收到的出口测试：编号、主机、端口。
    pub(crate) exit_tests: Vec<(u64, String, u16)>,
    /// 收到的主动测试的指令，和"测试结束"的编号。
    pub(crate) tests: Vec<TestOrder>,
    pub(crate) test_ends: Vec<u64>,
    /// 还没确认的版本。测试要自己控制确认的时机时用。
    unacked: Option<u64>,
}

impl Lab {
    /// 延后的下发不等待：`settle` 一调就做完。
    pub(crate) fn new() -> Self {
        Self::with_timing(Timing { ack_coalesce: Duration::ZERO, report_coalesce: Duration::ZERO, ..Timing::default() })
    }

    pub(crate) fn with_timing(timing: Timing) -> Self {
        let store = Store::temporary();
        let controller = Controller::new(store, NodeKey::generate().unwrap(), "ctl.example.com:20331".to_owned(), timing).unwrap();
        Self { controller, next_key: 0 }
    }

    /// 用一个已经建好的 controller（比如开在磁盘上的）。
    pub(crate) fn around(controller: Controller) -> Self {
        Self { controller, next_key: 100 }
    }

    pub(crate) fn network(&self, name: &str) -> Network {
        self.controller.create_network(&CreateNetwork { name: name.to_owned(), ..CreateNetwork::default() }).unwrap()
    }

    pub(crate) fn fresh_key(&mut self) -> PublicKey {
        self.next_key += 1;
        PublicKey::from_bytes([self.next_key; PublicKey::LEN])
    }

    /// 生成一个注册令牌，返回里面的一次性密钥。
    pub(crate) fn secret(&self, network: NetworkId, request: &CreateEnrollToken) -> String {
        let created = self.controller.create_token(network, request).unwrap();
        created.token.parse::<EnrollToken>().unwrap().secret
    }

    /// 叫 `name` 的分组（不分大小写），没有就建一个。`all` 是内置的 `All`。
    pub(crate) fn group(&self, network: NetworkId, name: &str) -> GroupId {
        let existing = self.controller.groups(network).unwrap().into_iter().find(|group| group.name.eq_ignore_ascii_case(name));
        existing.map_or_else(|| self.controller.create_group(network, &CreateGroup { name: name.to_owned() }).unwrap().id, |group| group.id)
    }

    /// 一个节点带着这些分组（按名字，没有的先建出来）和声明加入网络，并且保持在线。它的第一份 netmap 已经收下但还没确认。
    pub(crate) fn join_with(&mut self, network: NetworkId, groups: &[&str], declared: Declared) -> Member {
        let groups = groups.iter().map(|name| self.group(network, name)).collect();
        let request = CreateEnrollToken { groups, ..CreateEnrollToken::default() };
        let secret = self.secret(network, &request);
        let key = self.fresh_key();
        self.enroll(key, &secret, declared).expect("注册应该成功")
    }

    /// 管理员打开节点"可以作为端口转发的目标"的开关。
    pub(crate) fn switch_on_forward_target(&self, network: NetworkId, node: NodeId) {
        let request = UpdateNode { forward_target: Some(true), ..UpdateNode::default() };
        self.controller.update_node(network, node, &request).expect("打开开关应该成功");
    }

    pub(crate) fn join(&mut self, network: NetworkId, groups: &[&str]) -> Member {
        self.join_with(network, groups, Declared::default())
    }

    /// 加入网络之后马上下线。不在线的节点不用等它确认，所以它的 netmap 立刻就是最终的样子。
    pub(crate) fn join_offline(&mut self, network: NetworkId, groups: &[&str], declared: Declared) -> NodeId {
        let member = self.join_with(network, groups, declared);
        self.controller.disconnect(member.session);
        self.settle(&mut []);
        member.id
    }

    pub(crate) fn enroll(&mut self, key: PublicKey, secret: &str, declared: Declared) -> Result<Member, crate::Rejection> {
        self.enroll_as(key, secret, &hello(declared))
    }

    /// 带着指定的自我介绍注册。
    pub(crate) fn enroll_as(&mut self, key: PublicKey, secret: &str, hello: &Hello) -> Result<Member, crate::Rejection> {
        let (outbox, inbox) = mpsc::channel(64);
        let session = self.controller.enroll(key, secret, hello, REMOTE, outbox)?;
        Ok(Member::new(key, session, inbox))
    }

    /// 一个节点带着指定的自我介绍加入网络，并且保持在线。
    pub(crate) fn join_as(&mut self, network: NetworkId, hello: &Hello) -> Member {
        let secret = self.secret(network, &CreateEnrollToken::default());
        let key = self.fresh_key();
        self.enroll_as(key, &secret, hello).expect("注册应该成功")
    }

    /// 已经注册过的节点重新连上来。
    pub(crate) fn connect(&mut self, key: PublicKey, declared: Declared) -> Result<Member, crate::Rejection> {
        self.connect_as(key, &hello(declared))
    }

    /// 已经注册过的节点带着指定的自我介绍重新连上来。
    pub(crate) fn connect_as(&mut self, key: PublicKey, hello: &Hello) -> Result<Member, crate::Rejection> {
        let (outbox, inbox) = mpsc::channel(64);
        let session = self.controller.hello(key, hello, REMOTE, outbox)?;
        Ok(Member::new(key, session, inbox))
    }

    /// 让一切走到头：每个节点收下并确认发给它的东西，controller 做完延后的下发，直到谁也没有新动作。
    pub(crate) fn settle(&self, members: &mut [&mut Member]) {
        for _ in 0..50 {
            let received: usize = members.iter_mut().map(|member| member.receive_and_ack(&self.controller)).sum();
            self.controller.tick().unwrap();
            let pending: usize = members.iter_mut().map(|member| member.receive()).sum();
            let next_due = self.controller.lock().dirty.values().map(|deferred| deferred.due).min();
            match next_due {
                // 还有排着的下发没到时间：等到那时再看。
                Some(due) => std::thread::sleep(due.saturating_duration_since(Instant::now())),
                None if received == 0 && pending == 0 => return,
                None => {}
            }
        }
        panic!("50 轮之后还在变化：下发没有收敛");
    }

    pub(crate) fn netmap(&self, node: NodeId) -> Netmap {
        self.controller.netmap_of(node).unwrap().expect("节点应该存在")
    }
}

impl Member {
    fn new(key: PublicKey, session: Admitted, inbox: mpsc::Receiver<ToNode>) -> Self {
        let mut member = Self {
            id: session.node,
            key,
            session,
            inbox,
            snapshots: Vec::new(),
            signals: Vec::new(),
            revoked: false,
            orders: Vec::new(),
            cancels: 0,
            chunks: Vec::new(),
            queries: Vec::new(),
            backbone_queries: Vec::new(),
            exit_tests: Vec::new(),
            tests: Vec::new(),
            test_ends: Vec::new(),
            unacked: None,
        };
        member.receive();
        assert_eq!(member.snapshots.len(), 1, "报到之后 controller 应该先发来一份 netmap");
        member
    }

    /// 收下队列里的东西但不确认。返回收到了几条。
    pub(crate) fn receive(&mut self) -> usize {
        let mut received = 0;
        while let Ok(message) = self.inbox.try_recv() {
            received += 1;
            match message {
                ToNode::Snapshot(netmap) => {
                    self.unacked = Some(netmap.version);
                    self.snapshots.push(*netmap);
                }
                ToNode::Signal { from, signal } => self.signals.push((from, signal)),
                ToNode::Revoked => self.revoked = true,
                ToNode::Rejected { reason, .. } => panic!("已经报到的连接上不应该收到 rejected：{reason}"),
                ToNode::Heartbeat => {}
                ToNode::Update { manifest, timing } => self.orders.push((manifest, timing)),
                ToNode::UpdateCancel => self.cancels += 1,
                ToNode::PackageChunk { request, data } => self.chunks.push((request, Ok(data))),
                ToNode::PackageUnavailable { request, reason } => self.chunks.push((request, Err(reason))),
                ToNode::RouteQuery { request, peer } => self.queries.push((request, peer)),
                ToNode::BackboneQuery { request } => self.backbone_queries.push(request),
                ToNode::Test(order) => self.tests.push(*order),
                ToNode::TestEnd { test } => self.test_ends.push(test),
                ToNode::ExitTest { request, host, port } => self.exit_tests.push((request, host, port)),
                ToNode::TryLater { reason } => panic!("已经报到的连接上不应该收到 try_later：{reason}"),
            }
        }
        received
    }

    pub(crate) fn send(&self, controller: &Controller, message: ToController) {
        controller.handle(self.session, REMOTE, message).unwrap();
    }

    /// 上报一次，带着这个更新进度。
    pub(crate) fn report_update(&self, controller: &Controller, status: UpdateStatus) {
        self.send(controller, ToController::Report(Box::new(Report { update: Some(status), ..Report::default() })));
    }

    /// 确认收到的最新一份 netmap。
    pub(crate) fn ack(&mut self, controller: &Controller) {
        if let Some(version) = self.unacked.take() {
            controller.handle(self.session, REMOTE, ToController::Ack { version }).unwrap();
        }
    }

    pub(crate) fn receive_and_ack(&mut self, controller: &Controller) -> usize {
        let received = self.receive();
        let acked = usize::from(self.unacked.is_some());
        self.ack(controller);
        received + acked
    }

    /// 手上最新的 netmap。
    pub(crate) fn netmap(&self) -> &Netmap {
        self.snapshots.last().expect("节点应该已经收到过 netmap")
    }

    /// 连接是不是被 controller 关掉了（发送队列的另一头没了）。
    pub(crate) fn is_closed(&mut self) -> bool {
        matches!(self.inbox.try_recv(), Err(mpsc::error::TryRecvError::Disconnected))
    }
}

/// 最初那一版节点的自我介绍：不报主机名，不懂更新。
pub(crate) fn hello(declared: Declared) -> Hello {
    Hello { version: "0.1.0".to_owned(), platform: "linux-x86_64".to_owned(), declared, port: 20330, ..Hello::default() }
}

/// 现在这一版节点的自我介绍：懂更新，能自己更新。
pub(crate) fn modern_hello(version: &str) -> Hello {
    Hello {
        version: version.to_owned(),
        protocol: PROTOCOL_REVISION,
        self_update: Some(SelfUpdate::ABLE),
        throughput_tests: true,
        ..hello(Declared::default())
    }
}

pub(crate) const CAN_DO_ALL: Declared = Declared { exit: true, relay: true, relay_address: None };

/// 新建一个代理的请求：在 `node` 的 `bind` 上监听，经 `exit` 出去，其余取默认（`mixed`、启用、不写名字和用户名密码）。
pub(crate) fn proxy(node: NodeId, bind: &str, exit: NodeId) -> CreateProxy {
    CreateProxy {
        node,
        name: String::new(),
        bind: bind.parse().expect("测试写的地址"),
        exit,
        protocol: Default::default(),
        username: String::new(),
        password: String::new(),
        enabled: true,
        allow_from: Vec::new(),
        class: None,
        optimistic: None,
        lane: false,
    }
}
