//! 已经读到首帧、正在核验成员资格的任务。核验提交到阻塞池之后，即使连接任务取消了也可能继续执行。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::controller::Controller;
use crate::error::Rejection;
use crate::gate::{LOG_EVERY, Limits, Pass, Source, Throttle};
use crate::server::blocking;

pub(crate) struct VerificationQuota {
    limits: Limits,
    active: Mutex<Active>,
    busy_log: Throttle,
}

#[derive(Default)]
struct Active {
    total: usize,
    by_source: HashMap<Source, usize>,
}

pub(super) struct Permit {
    quota: Arc<VerificationQuota>,
    source: Source,
}

pub(super) enum AdmissionError {
    Evicted,
    Busy(Pass),
    UnexpectedFirstMessage(Pass),
    Rejected(Rejection, Permit),
}

impl VerificationQuota {
    pub(crate) fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self { limits, active: Mutex::default(), busy_log: Throttle::new(LOG_EVERY) })
    }

    fn reserve(self: &Arc<Self>, source: Source) -> Option<Permit> {
        let mut active = self.active.lock().expect("verification mutex poisoned");
        let source_full = active.by_source.get(&source).copied().unwrap_or(0) >= self.limits.per_source;
        let global_full = active.total >= self.limits.total;
        if source_full || global_full {
            drop(active);
            if let Some(suppressed) = self.busy_log.allow() {
                tracing::warn!(%source, source_full, global_full, suppressed, "节点的成员资格核验名额已满");
            }
            return None;
        }
        *active.by_source.entry(source).or_default() += 1;
        active.total += 1;
        Some(Permit { quota: Arc::clone(self), source })
    }
}

impl Controller {
    /// 满额应答沿用握手名额，核验拒绝的应答沿用核验名额。
    pub(super) async fn verify_node<T: Send + 'static>(
        self: &Arc<Self>,
        handshake: Pass,
        check: impl FnOnce(&Controller) -> Result<T, Rejection> + Send + 'static,
    ) -> Result<T, AdmissionError> {
        let Some(permit) = self.verification_quota.reserve(handshake.source()) else { return Err(AdmissionError::Busy(handshake)) };
        if !handshake.finish() {
            return Err(AdmissionError::Evicted);
        }
        blocking(self, move |controller| {
            // 闭包持有名额。核验成功时归还，拒绝时随结果移交给负责写应答的任务。
            check(controller).map_err(|reason| AdmissionError::Rejected(reason, permit))
        })
        .await
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut active = self.quota.active.lock().expect("verification mutex poisoned");
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::task::{Context, Waker};
    use std::time::Duration;

    use i3t_crypto::{NodeKey, tls};
    use i3t_model::control::{MAX_FRAME_LEN, RejectCause, ToController, ToNode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{oneshot, watch};
    use tokio::time::{Instant, timeout};
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::controller::ALPN;
    use crate::controller::testing::{Lab, hello};
    use crate::frame::{read_frame, write_frame};
    use crate::gate::Gate;
    use crate::node_server::{ADMISSION_REPLY_TIMEOUT, serve};

    fn controller_with_limits(limits: Limits) -> Arc<Controller> {
        let mut controller = Lab::new().controller;
        controller.verification_quota = VerificationQuota::new(limits);
        Arc::new(controller)
    }

    #[test]
    fn verification_counts_each_source_and_the_total_and_recovers_capacity() {
        let quota = VerificationQuota::new(Limits { per_source: 1, total: 2 });
        let source = |ip: &str| Source::from(ip.parse::<IpAddr>().unwrap());
        let ipv6 = quota.reserve(source("2001:db8:1::1")).unwrap();
        assert!(quota.reserve(source("2001:db8:1::2")).is_none(), "同一个 /64 共享名额");
        let ipv4 = quota.reserve(source("192.0.2.1")).unwrap();
        assert!(quota.reserve(source("192.0.2.2")).is_none(), "不同来源也受总量限制");
        drop(ipv6);
        assert!(quota.reserve(source("::ffff:192.0.2.1")).is_none());
        assert!(quota.reserve(source("192.0.2.2")).is_some());
        assert!(quota.reserve(source("2001:db8:1::2")).is_some());
        drop(ipv4);
        assert!(quota.active.lock().unwrap().by_source.is_empty());
    }

    #[test]
    fn full_quota_warnings_distinguish_source_and_global_limits_and_are_throttled() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let subscriber = tracing_subscriber::fmt().without_time().with_ansi(false).with_writer(Mutex::new(log.reopen().unwrap())).finish();
        tracing::subscriber::with_default(subscriber, || {
            let a = Source::from(IpAddr::from([192, 0, 2, 1]));
            let b = Source::from(IpAddr::from([192, 0, 2, 2]));
            let per_source = VerificationQuota::new(Limits { per_source: 1, total: 2 });
            let global = VerificationQuota::new(Limits { per_source: 2, total: 1 });
            let _first = per_source.reserve(a).unwrap();
            let _second = global.reserve(a).unwrap();
            for _ in 0..2 {
                assert!(per_source.reserve(a).is_none());
                assert!(global.reserve(b).is_none());
            }
        });
        let log = std::fs::read_to_string(log.path()).unwrap();
        let warnings: Vec<_> = log.lines().filter(|line| line.contains("WARN")).collect();
        assert_eq!(warnings.len(), 2, "{log}");
        assert!(
            warnings[0].contains("source=192.0.2.1")
                && warnings[0].contains("source_full=true")
                && warnings[0].contains("global_full=false")
        );
        assert!(
            warnings[1].contains("source=192.0.2.2")
                && warnings[1].contains("source_full=false")
                && warnings[1].contains("global_full=true")
        );
        assert!(warnings.iter().all(|line| line.contains("suppressed=0")));
    }

    #[tokio::test]
    async fn only_the_current_handshake_can_start_verification() {
        let limits = Limits { per_source: 1, total: 1 };
        let controller = controller_with_limits(limits);
        let gate = Gate::new("握手", limits);
        let quota = &controller.verification_quota;
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let old = gate.admit(ip);
        let current = gate.admit(ip);
        // 即使首帧已经读完，连接任务也可能还没观察到淘汰通知。
        let stale = controller.verify_node(old, |_| -> Result<(), Rejection> { panic!("已经被淘汰的握手不应提交核验") }).await;
        assert!(matches!(stale, Err(AdmissionError::Evicted)));
        assert!(controller.verify_node(current, |_| Ok(())).await.is_ok());
        assert!(quota.reserve(ip.into()).is_some());
    }

    #[tokio::test]
    async fn a_stalled_rejection_keeps_its_slot_until_the_reply_finishes_or_is_cancelled() {
        let limits = Limits { per_source: 1, total: 1 };
        let controller = controller_with_limits(limits);
        let gate = Gate::new("握手", limits);
        let quota = &controller.verification_quota;
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        let (_shutdown, mut stopped) = watch::channel(false);
        for cancel in [true, false] {
            let error = controller.verify_node(gate.admit(remote.ip()), |_| Err::<(), _>(Rejection::UnknownKey)).await.err().unwrap();
            let (mut writer, mut reader) = tokio::io::duplex(1);
            let mut reply = Box::pin(error.reply(&mut writer, remote, Instant::now(), &mut stopped));
            assert!(reply.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            assert!(quota.reserve(remote.ip().into()).is_none(), "写端阻塞时尚未交还核验名额");
            if cancel {
                drop(reply);
            } else {
                let read = async {
                    assert!(matches!(read_frame::<_, ToNode>(&mut reader, MAX_FRAME_LEN).await.unwrap(), Some(ToNode::Rejected { .. })));
                };
                timeout(Duration::from_secs(5), async { tokio::join!(reply, read) }).await.unwrap();
            }
            assert!(quota.reserve(remote.ip().into()).is_some(), "连接收尾后名额应可复用");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_blocked_rejection_releases_its_permit_on_timeout_or_shutdown() {
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        let quota = VerificationQuota::new(Limits { per_source: 1, total: 1 });
        for stop in [false, true] {
            let permit = quota.reserve(remote.ip().into()).unwrap();
            let error = AdmissionError::Rejected(Rejection::UnknownKey, permit);
            let (mut writer, mut reader) = tokio::io::duplex(1);
            let (shutdown, mut stopped) = watch::channel(false);
            let started = Instant::now();
            let mut reply = Box::pin(error.reply(&mut writer, remote, started, &mut stopped));
            assert!(reply.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            if stop {
                shutdown.send(true).unwrap();
            }
            reply.await;
            let elapsed = started.elapsed();
            if stop {
                assert_eq!(elapsed, Duration::ZERO, "停机时不再等写超时");
            } else {
                assert!(elapsed >= ADMISSION_REPLY_TIMEOUT && elapsed < Duration::from_secs(3), "拒绝应答占用了 {elapsed:?}");
            }
            assert!(quota.reserve(remote.ip().into()).is_some());
            // 第一字节占满了缓冲。读走它后仍能写，说明不完整的应答没有再走优雅关闭。
            timeout(Duration::from_secs(1), async {
                reader.read_u8().await.unwrap();
                writer.write_u8(0).await.unwrap();
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_verification_can_still_send_try_later_after_the_handshake_deadline() {
        let deadline = Instant::now() + Duration::from_secs(10);
        tokio::time::advance(Duration::from_secs(11)).await;
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        let quota = VerificationQuota::new(Limits { per_source: 1, total: 1 });
        let error = AdmissionError::Rejected(Rejection::Internal, quota.reserve(remote.ip().into()).unwrap());
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let (_shutdown, mut stopped) = watch::channel(false);
        error.reply(&mut writer, remote, deadline, &mut stopped).await;
        timeout(Duration::from_secs(1), async {
            assert!(matches!(read_frame::<_, ToNode>(&mut reader, MAX_FRAME_LEN).await.unwrap(), Some(ToNode::TryLater { .. })));
            assert!(read_frame::<_, ToNode>(&mut reader, MAX_FRAME_LEN).await.unwrap().is_none());
        })
        .await
        .expect("核验返回后应写完整条应答并关闭写端");
    }

    #[tokio::test]
    async fn a_stalled_busy_reply_ends_on_handshake_eviction_or_deadline() {
        let limits = Limits { per_source: 1, total: 1 };
        let controller = controller_with_limits(limits);
        let gate = Gate::new("握手", limits);
        let quota = &controller.verification_quota;
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        let _checking = quota.reserve(remote.ip().into()).unwrap();
        let (_shutdown, mut stopped) = watch::channel(false);
        for evict in [true, false] {
            let error = controller.verify_node(gate.admit(remote.ip()), |_| Ok(())).await.err().unwrap();
            let (mut writer, _reader) = tokio::io::duplex(1);
            let deadline = if evict { Instant::now() + Duration::from_secs(60) } else { Instant::now() };
            let mut reply = Box::pin(error.reply(&mut writer, remote, deadline, &mut stopped));
            if evict {
                assert!(reply.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                let _next = gate.admit(remote.ip());
                assert!(reply.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_ready());
            } else {
                timeout(Duration::from_secs(5), reply).await.expect("握手时限应中止满额应答");
            }
        }
    }

    #[test]
    fn queued_and_running_verifications_hold_their_slots_after_the_connection_is_cancelled() {
        let runtime = tokio::runtime::Builder::new_current_thread().max_blocking_threads(1).enable_all().build().unwrap();
        runtime.block_on(async {
            let limits = Limits { per_source: 1, total: 2 };
            let controller = controller_with_limits(limits);
            let gate = Gate::new("握手", limits);
            let quota = &controller.verification_quota;
            let a = IpAddr::from([192, 0, 2, 1]);
            let b = IpAddr::from([192, 0, 2, 2]);
            let c = IpAddr::from([192, 0, 2, 3]);
            let (started, running) = oneshot::channel();
            let (finish, resume) = oneshot::channel();
            let mut first = Box::pin(controller.verify_node(gate.admit(a), move |_| {
                started.send(()).unwrap();
                let _ = resume.blocking_recv();
                Ok(())
            }));
            assert!(first.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            timeout(Duration::from_secs(5), running).await.expect("第一项核验应已开始").unwrap();
            drop(first);
            assert!(quota.reserve(a.into()).is_none(), "取消连接不能挤掉正在执行的核验");

            // 唯一的阻塞线程还在做第一项核验，第二项提交以后一定在排队。
            let (done, checked) = oneshot::channel();
            let mut second = Box::pin(controller.verify_node(gate.admit(b), move |_| {
                done.send(()).unwrap();
                Ok(())
            }));
            assert!(second.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            drop(second);
            assert!(quota.reserve(b.into()).is_none(), "取消连接不能让已提交的核验脱离来源配额");
            assert!(quota.reserve(c.into()).is_none(), "排队和执行中的核验合计占满全局配额");

            finish.send(()).unwrap();
            timeout(Duration::from_secs(5), checked).await.expect("工作线程空闲后应处理第二项核验").unwrap();
            // 同一个工作线程再次接到任务时，上一个核验闭包已经退出。
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            let active = quota.active.lock().unwrap();
            assert_eq!(active.total, 0);
            assert!(active.by_source.is_empty());
        });
    }

    async fn first_reply(controller: &Arc<Controller>, key: &NodeKey, message: ToController) -> ToNode {
        let server_tls = Arc::new(controller.tls_config().unwrap());
        let client_tls = TlsConnector::from(Arc::new(tls::client_config(key, controller.public_key(), ALPN).unwrap()));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, stopped) = watch::channel(false);
        let server = serve(Arc::clone(controller), server_tls, listener, stopped);
        let client = async {
            let stream = TcpStream::connect(addr).await.unwrap();
            let mut tls = client_tls.connect("i3t".try_into().unwrap(), stream).await.unwrap();
            write_frame(&mut tls, &message).await.unwrap();
            let reply = read_frame::<_, ToNode>(&mut tls, MAX_FRAME_LEN).await.unwrap().unwrap();
            if matches!(reply, ToNode::TryLater { .. } | ToNode::Rejected { .. }) {
                assert!(read_frame::<_, ToNode>(&mut tls, MAX_FRAME_LEN).await.unwrap().is_none());
            }
            shutdown.send(true).unwrap();
            reply
        };
        let ((), reply) = timeout(Duration::from_secs(5), async { tokio::join!(server, client) }).await.unwrap();
        reply
    }

    #[tokio::test]
    async fn listeners_on_one_controller_share_capacity_for_hello_and_enroll() {
        let controller = controller_with_limits(Limits { per_source: 1, total: 1 });
        let key = NodeKey::generate().unwrap();
        let occupied = controller.verification_quota.reserve(IpAddr::V4(Ipv4Addr::LOCALHOST).into()).unwrap();
        let request = |message| first_reply(&controller, &key, message);
        let hello = hello(Default::default());
        let (a, b) = tokio::join!(
            request(ToController::Hello(hello.clone())),
            request(ToController::Enroll { token: "test".into(), hello: hello.clone() })
        );
        assert!(matches!((a, b), (ToNode::TryLater { .. }, ToNode::TryLater { .. })));
        let invalid = request(ToController::Heartbeat).await;
        assert!(matches!(invalid, ToNode::Rejected { cause: Some(RejectCause::UnexpectedFirstMessage), .. }));
        drop(occupied);
        assert!(matches!(request(ToController::Hello(hello)).await, ToNode::Rejected { .. }), "名额归还后应恢复正常的公钥核验");
    }

    #[tokio::test]
    async fn a_node_can_enroll_while_another_source_is_at_its_limit() {
        let mut lab = Lab::new();
        let network = lab.network("home");
        let token = lab.secret(network.id, &Default::default());
        lab.controller.verification_quota = VerificationQuota::new(Limits { per_source: 1, total: 2 });
        let controller = Arc::new(lab.controller);
        let other_source = IpAddr::from([192, 0, 2, 1]).into();
        let _occupied = controller.verification_quota.reserve(other_source).unwrap();
        assert!(controller.verification_quota.reserve(other_source).is_none());

        let key = NodeKey::generate().unwrap();
        let reply = first_reply(&controller, &key, ToController::Enroll { token, hello: hello(Default::default()) }).await;
        assert!(matches!(reply, ToNode::Snapshot(_)));
    }
}
