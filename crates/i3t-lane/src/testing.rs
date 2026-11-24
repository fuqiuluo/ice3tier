//! 给上层 crate 的测试用：同一批测试分别跑在共用的连接上和 lane 上。
//!
//! - [`LaneMesh`]：测试里的每个节点在回环上有一个真的 [`Lanes`]，互相都能拨，控制 lane 建好了才交出去。
//! - [`on_both_transports!`](crate::on_both_transports)：把一个测试展开成 `shared` 和 `lanes` 两个，
//!   测试里用 [`transport`] 知道这一次跑在哪种传输上；lane 的那一个结束时检查 lane 真的承载了数据、没有一条流改走共用的连接。

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use i3t_crypto::NodeKey;
use i3t_proto::{NodeId, PublicKey};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::endpoint::{LaneConfig, LanePeer, Lanes};
use crate::mixed::Choose;

/// 一个测试跑在哪种传输上。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// 只用共用的连接（例如内存里的连接层）。
    Shared,
    /// 承载 TCP 连接的流走 lane。
    Lanes,
}

tokio::task_local! {
    static CURRENT: Run;
}

#[derive(Clone)]
struct Run {
    transport: Transport,
    meshes: Arc<Mutex<Vec<LaneMesh>>>,
}

/// 这个测试跑在哪种传输上。不在 [`run`] 里面时是 [`Transport::Shared`]。
#[must_use]
pub fn transport() -> Transport {
    CURRENT.try_with(|run| run.transport).unwrap_or(Transport::Shared)
}

/// 在 `transport` 上跑 `test`。跑在 lane 上时，结束之后检查 lane 真的承载了数据、没有流改走共用的连接。
///
/// # Panics
///
/// 跑在 lane 上、但没有任何字节经过 lane，或者有流改走了共用的连接。
pub async fn run(transport: Transport, test: impl Future<Output = ()>) {
    let run = Run { transport, meshes: Arc::default() };
    CURRENT.scope(run.clone(), test).await;
    if transport == Transport::Lanes {
        let meshes = run.meshes.lock().expect("lane meshes mutex poisoned").clone();
        let (mut carried, mut fallbacks) = (0, 0);
        for mesh in &meshes {
            for lanes in mesh.lanes() {
                let total = lanes.status().total;
                carried += total.sealed_bytes + total.passthrough_bytes + total.spliced_bytes;
                fallbacks += total.fallbacks;
            }
        }
        assert!(carried > 0, "这个测试跑在 lane 上，但没有任何字节经过 lane");
        assert_eq!(fallbacks, 0, "存在无法开启 lane 而回退至共用连接的流");
    }
}

/// 把一个异步测试展开成两个：`<名字>::shared` 和 `<名字>::lanes`。测试体里不要再写 `#[tokio::test]`。
#[macro_export]
macro_rules! on_both_transports {
    ($(#[$meta:meta])* async fn $name:ident() $body:block) => {
        mod $name {
            #[allow(unused_imports, reason = "测试体用的名字在外面一层")]
            use super::*;

            $(#[$meta])*
            #[tokio::test]
            async fn shared() {
                $crate::testing::run($crate::testing::Transport::Shared, async $body).await
            }

            $(#[$meta])*
            #[tokio::test]
            async fn lanes() {
                $crate::testing::run($crate::testing::Transport::Lanes, async $body).await
            }
        }
    };
}

/// 测试里的一组节点的 lane。克隆出来的是同一组。
#[derive(Clone)]
pub struct LaneMesh {
    enabled: bool,
    nodes: Arc<Mutex<Vec<Member>>>,
}

#[derive(Clone)]
struct Member {
    id: NodeId,
    key: PublicKey,
    addr: std::net::SocketAddr,
    lanes: Arc<Lanes>,
    _listener: Arc<AbortOnDrop>,
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl LaneMesh {
    /// 按当前测试的传输（[`transport`]）建一组：跑在共用的连接上时，lane 建出来但不用。
    #[must_use]
    pub fn for_current_test() -> Self {
        let mesh = Self { enabled: transport() == Transport::Lanes, nodes: Arc::default() };
        // 跑在 [`run`] 里面时登记下来，结束时检查。
        let _ = CURRENT.try_with(|run| run.meshes.lock().expect("lane meshes mutex poisoned").push(mesh.clone()));
        mesh
    }

    /// 这一组用不用 lane。
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// 给 `LaneConnector` 的选择：用 lane 的话所有对端都走 lane。
    #[must_use]
    pub fn choose(&self) -> Choose {
        let enabled = self.enabled;
        Arc::new(move |_| enabled)
    }

    /// 加入一个节点：在回环上听，和已经在的节点互相登记（互相都拨）。用 lane 的话等控制 lane 都建好了才返回。
    ///
    /// # Panics
    ///
    /// 回环地址监听失败，或 10 秒内未能建立控制 lane。
    pub async fn join(&self, id: NodeId) -> Arc<Lanes> {
        let key = NodeKey::generate().expect("系统的随机数源可用");
        let config = LaneConfig { min_idle: 2, ..LaneConfig::default() };
        let lanes = Arc::new(Lanes::new(&key, config).expect("使用节点密钥签发证书成功"));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("回环地址监听成功");
        let addr = listener.local_addr().expect("刚绑的监听有地址");
        let serving = Arc::clone(&lanes);
        let task = tokio::spawn(async move { serving.serve(listener).await });
        let member = Member { id, key: key.public(), addr, lanes: Arc::clone(&lanes), _listener: Arc::new(AbortOnDrop(task)) };
        let members = {
            let mut nodes = self.nodes.lock().expect("lane mesh mutex poisoned");
            nodes.retain(|node| node.id != id);
            nodes.push(member);
            nodes.clone()
        };
        if self.enabled {
            for member in &members {
                let peers = members.iter().filter(|other| other.id != member.id).map(|other| LanePeer {
                    id: other.id,
                    key: other.key,
                    dial: vec![other.addr],
                });
                member.lanes.set_peers(peers).expect("给对端做 TLS 配置");
            }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            for member in &members {
                for other in members.iter().filter(|other| other.id != member.id) {
                    while !member.lanes.can_open(other.id) {
                        assert!(tokio::time::Instant::now() < deadline, "节点 {} 到 {} 的控制 lane 10 秒没有建好", member.id, other.id);
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
            }
        }
        lanes
    }

    fn lanes(&self) -> Vec<Arc<Lanes>> {
        self.nodes.lock().expect("lane mesh mutex poisoned").iter().map(|member| Arc::clone(&member.lanes)).collect()
    }
}

impl std::fmt::Debug for LaneMesh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneMesh").field("enabled", &self.enabled).finish_non_exhaustive()
    }
}
