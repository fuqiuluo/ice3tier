//! 加入网络：`i3t join` 做的事。

use anyhow::anyhow;
use i3t_model::Netmap;
use i3t_model::control::{EnrollToken, Hello, PROTOCOL_REVISION};

use crate::config::{Capability, Config};
use crate::control;
use crate::program::Program;
use crate::state::{ControllerInfo, StateDir};

/// 加入时在命令行上给出的本地声明。没有给的保持配置文件里原来的值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JoinOptions {
    pub can_exit: bool,
    pub can_relay: bool,
}

/// 用注册令牌加入网络，把结果存进状态目录，返回 controller 给的第一份 netmap。
///
/// 顺序是先写本地的东西（密钥、配置文件、声明），再去找 controller。注册成功之后才记下 controller 是谁，
/// 所以失败了可以原样重来；令牌是一次性的，注册成功之后再跑一遍会被 controller 拒绝。
///
/// # Errors
///
/// 令牌无效、状态目录不可写、无法连接 controller，或 controller 拒绝注册。
pub async fn join(state: &StateDir, token: &str, options: JoinOptions, program: &Program) -> anyhow::Result<Netmap> {
    // 令牌解析的细节（模型里的原话）对使用者没有用：说清楚它不是令牌、令牌从哪里来就够了。
    let token: EnrollToken = token.parse().map_err(|_| anyhow!(crate::texts::texts().not_a_token))?;
    let key = state.key_or_generate()?;

    let config_path = state.config_path();
    Config::write_template_if_missing(&config_path)?;
    let declared = [(Capability::Exit, options.can_exit), (Capability::Relay, options.can_relay)];
    for (capability, _) in declared.into_iter().filter(|&(_, on)| on) {
        Config::set_declared(&config_path, capability, true)?;
    }
    let config = Config::load(&config_path)?;

    let controller = ControllerInfo { address: token.controller.clone(), key: token.key };
    let netmap = control::enroll(&controller, &key, &token.secret, hello(&config, program)).await?;
    state.save_controller(&controller)?;
    state.save_netmap(&netmap)?;
    Ok(netmap)
}

/// 这个节点现在的自我介绍。
#[must_use]
pub fn hello(config: &Config, program: &Program) -> Hello {
    Hello {
        version: program.version.to_string(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        declared: config.declare.into(),
        port: config.port,
        hostname: hostname(),
        protocol: PROTOCOL_REVISION,
        self_update: Some(program.self_update()),
        throughput_tests: config.tests.throughput,
    }
}

/// 这台机器的主机名。controller 用它给新节点起名字；系统给的不是合法的文字时当作没有。
fn hostname() -> String {
    gethostname::gethostname().into_string().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use i3t_model::control::{SelfUpdate, ToController, ToNode};
    use i3t_model::update::{Platform, SelfUpdateBlocker, Version};

    use super::*;
    use crate::control::testing::{FakeController, expect, netmap};
    use crate::control::write_message;

    fn program() -> Program {
        Program { version: Version::new(0, 4, 2), path: "/opt/i3t/i3t".into(), blocker: None }
    }

    fn token_for(controller: &FakeController) -> String {
        EnrollToken { controller: controller.info.address.clone(), key: controller.info.key, secret: "s3cret".to_owned() }.to_string()
    }

    #[tokio::test]
    async fn join_enrolls_declares_and_persists() {
        let controller = FakeController::start().await;
        let token = token_for(&controller);
        let expected_controller = controller.info.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = controller.accept().await;
            let ToController::Enroll { token, hello } = expect(&mut stream).await else { panic!("第一条消息不是 enroll") };
            write_message(&mut stream, &ToNode::Snapshot(Box::new(netmap(1)))).await.unwrap();
            let _: ToController = expect(&mut stream).await;
            (token, hello)
        });

        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path()).unwrap();
        let options = JoinOptions { can_exit: true, ..JoinOptions::default() };
        let received = join(&state, &token, options, &program()).await.unwrap();
        let (secret, hello) = server.await.unwrap();

        assert_eq!(received.version, 1);
        assert_eq!(secret, "s3cret");
        assert!(hello.declared.exit && !hello.declared.relay);
        assert_eq!(hello.port, 20330);
        assert_eq!((hello.version.as_str(), hello.protocol, hello.self_update), ("0.4.2", PROTOCOL_REVISION, Some(SelfUpdate::ABLE)));
        assert_eq!(state.controller().unwrap(), Some(expected_controller));
        assert_eq!(state.netmap().unwrap().unwrap().version, 1);
        assert!(Config::load(&state.config_path()).unwrap().declare.exit);
    }

    #[test]
    fn hello_says_who_the_program_is_and_why_it_cannot_update_itself() {
        let blocked = Program { blocker: Some(SelfUpdateBlocker::ReadOnlyDir), ..program() };
        let hello = hello(&Config::default(), &blocked);
        assert_eq!(hello.self_update, Some(SelfUpdate { able: false, blocker: Some(SelfUpdateBlocker::ReadOnlyDir) }));
        assert_eq!(hello.platform, Platform::current().as_str(), "平台名和发布清单里的写法一致，controller 靠它挑包");
        assert_eq!(hello.hostname, gethostname::gethostname().to_string_lossy());
    }

    #[tokio::test]
    async fn a_refused_join_leaves_no_controller_behind() {
        let controller = FakeController::start().await;
        let token = token_for(&controller);
        tokio::spawn(async move {
            let (mut stream, _) = controller.accept().await;
            let _: ToController = expect(&mut stream).await;
            write_message(&mut stream, &ToNode::Rejected { reason: "令牌过期".into(), cause: None }).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path()).unwrap();
        let error = join(&state, &token, JoinOptions::default(), &program()).await.unwrap_err();
        assert!(format!("{error:#}").contains("令牌过期"));
        assert_eq!(state.controller().unwrap(), None);
        assert!(state.netmap().unwrap().is_none());
    }

    #[tokio::test]
    async fn text_that_is_not_a_token_is_explained() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path()).unwrap();
        let error = join(&state, "hello", JoinOptions::default(), &program()).await.unwrap_err();
        assert!(format!("{error:#}").contains("i3t-"));
    }
}
