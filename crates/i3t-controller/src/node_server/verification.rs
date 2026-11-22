//! 已经读到首帧、正在核验成员资格的任务。核验提交到阻塞池之后，即使连接任务取消了也可能继续执行。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::controller::Controller;
use crate::gate::{Limits, Pass, Source};
use crate::server::blocking;

pub(super) struct Verifier {
    limits: Limits,
    active: Mutex<Active>,
}

#[derive(Default)]
struct Active {
    total: usize,
    by_source: HashMap<Source, usize>,
}

struct Permit {
    verifier: Arc<Verifier>,
    source: Source,
}

impl Verifier {
    pub(super) fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self { limits, active: Mutex::default() })
    }

    /// 满额时交还握手名额给调用方，方便它在原来的名额内通知节点重试。
    pub(super) async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        controller: &Arc<Controller>,
        handshake: Pass,
        check: impl FnOnce(&Controller) -> T + Send + 'static,
    ) -> Result<T, Pass> {
        let Some(permit) = self.reserve(handshake.source()) else { return Err(handshake) };
        drop(handshake);
        Ok(blocking(controller, move |controller| {
            // 从提交排队直到核验结束都占着名额，外层连接任务的存亡不影响它。
            let _permit = permit;
            check(controller)
        })
        .await)
    }

    fn reserve(self: &Arc<Self>, source: Source) -> Option<Permit> {
        let mut active = self.active.lock().expect("verification mutex poisoned");
        if active.total >= self.limits.total || active.by_source.get(&source).copied().unwrap_or(0) >= self.limits.per_source {
            return None;
        }
        *active.by_source.entry(source).or_default() += 1;
        active.total += 1;
        Some(Permit { verifier: Arc::clone(self), source })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut active = self.verifier.active.lock().expect("verification mutex poisoned");
        let count = active.by_source.get_mut(&self.source).expect("verification source is recorded");
        *count -= 1;
        if *count == 0 {
            active.by_source.remove(&self.source);
        }
        active.total -= 1;
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::task::{Context, Waker};
    use std::time::Duration;

    use i3t_crypto::{NodeKey, tls};
    use i3t_model::control::{MAX_FRAME_LEN, ToController, ToNode};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{oneshot, watch};
    use tokio::time::timeout;
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::controller::ALPN;
    use crate::controller::testing::{Lab, hello};
    use crate::frame::{read_frame, write_frame};
    use crate::gate::Gate;
    use crate::node_server::Connection;

    #[test]
    fn verification_counts_each_source_and_the_total_and_recovers_capacity() {
        let verifier = Verifier::new(Limits { per_source: 1, total: 2 });
        let source = |ip: &str| Source::from(ip.parse::<IpAddr>().unwrap());
        let ipv6 = verifier.reserve(source("2001:db8:1::1")).unwrap();
        assert!(verifier.reserve(source("2001:db8:1::2")).is_none(), "同一个 /64 共享名额");
        let ipv4 = verifier.reserve(source("192.0.2.1")).unwrap();
        assert!(verifier.reserve(source("192.0.2.2")).is_none(), "不同来源也受总量限制");
        drop(ipv6);
        assert!(verifier.reserve(source("::ffff:192.0.2.1")).is_none());
        assert!(verifier.reserve(source("192.0.2.2")).is_some());
        assert!(verifier.reserve(source("2001:db8:1::2")).is_some());
        drop(ipv4);
        assert!(verifier.active.lock().unwrap().by_source.is_empty());
    }

    #[test]
    fn queued_and_running_verifications_hold_their_slots_after_the_connection_is_cancelled() {
        let runtime = tokio::runtime::Builder::new_current_thread().max_blocking_threads(1).enable_all().build().unwrap();
        runtime.block_on(async {
            let controller = Arc::new(Lab::new().controller);
            let gate = Gate::new("握手", Limits { per_source: 1, total: 2 });
            let verifier = Verifier::new(Limits { per_source: 1, total: 2 });
            let a = IpAddr::from([192, 0, 2, 1]);
            let b = IpAddr::from([192, 0, 2, 2]);
            let c = IpAddr::from([192, 0, 2, 3]);
            let (started, running) = oneshot::channel();
            let (finish, resume) = oneshot::channel();
            let mut first = Box::pin(verifier.run(&controller, gate.admit(a), move |_| {
                started.send(()).unwrap();
                let _ = resume.blocking_recv();
            }));
            assert!(first.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            running.await.unwrap();
            drop(first);
            assert!(verifier.reserve(a.into()).is_none(), "取消连接不能挤掉正在执行的核验");

            // 唯一的阻塞线程还在做第一项核验，第二项提交以后一定在排队。
            let (done, checked) = oneshot::channel();
            let mut second = Box::pin(verifier.run(&controller, gate.admit(b), move |_| done.send(()).unwrap()));
            assert!(second.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            drop(second);
            assert!(verifier.reserve(b.into()).is_none(), "取消连接不能让已提交的核验脱离来源配额");
            assert!(verifier.reserve(c.into()).is_none(), "排队和执行中的核验合计占满全局配额");

            finish.send(()).unwrap();
            checked.await.unwrap();
            // 同一个工作线程再次接到任务时，上一个核验闭包已经退出。
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            let active = verifier.active.lock().unwrap();
            assert_eq!(active.total, 0);
            assert!(active.by_source.is_empty());
        });
    }

    #[tokio::test]
    async fn a_full_verifier_tells_both_hello_and_enroll_to_retry() {
        let controller = Arc::new(Lab::new().controller);
        let server_tls = Arc::new(controller.tls_config().unwrap());
        let key = NodeKey::generate().unwrap();
        let client_tls = TlsConnector::from(Arc::new(tls::client_config(&key, controller.public_key(), ALPN).unwrap()));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limits = Limits { per_source: 1, total: 1 };
        let gate = Gate::new("握手", limits);
        let verifier = Verifier::new(limits);
        let _occupied = verifier.reserve(addr.ip().into()).unwrap();
        let hello = hello(Default::default());
        for message in [ToController::Hello(hello.clone()), ToController::Enroll { token: "test".into(), hello }] {
            let server = async {
                let (stream, remote) = listener.accept().await.unwrap();
                let connection = Connection { controller: Arc::clone(&controller), remote, shutdown: watch::channel(false).1 };
                assert!(connection.establish(Arc::clone(&server_tls), stream, gate.admit(remote.ip()), &verifier).await.is_none());
            };
            let client = async {
                let stream = TcpStream::connect(addr).await.unwrap();
                let mut tls = client_tls.connect("i3t".try_into().unwrap(), stream).await.unwrap();
                write_frame(&mut tls, &message).await.unwrap();
                assert!(matches!(read_frame::<_, ToNode>(&mut tls, MAX_FRAME_LEN).await.unwrap(), Some(ToNode::TryLater { .. })));
                assert!(read_frame::<_, ToNode>(&mut tls, MAX_FRAME_LEN).await.unwrap().is_none());
            };
            timeout(Duration::from_secs(5), async { tokio::join!(server, client) }).await.expect("满额时应该立即答复");
        }
    }
}
