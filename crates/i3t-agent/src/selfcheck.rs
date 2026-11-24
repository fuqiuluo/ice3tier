//! 新程序的自检：`i3t self-check` 做的事。约定见 `i3t_update::self_check`。
//!
//! 更新过程中，运行中的旧版本会将新版本程序放在同目录并执行该子命令，仅当退出码为 0 时才会执行替换。
//! 新版本需在本机验证三项条件：自身版本与清单一致；能够正常读取现有配置与状态；
//! 能与 controller 完成一次 TLS 握手。
//!
//! 此时旧版本仍在运行，因此自检仅读不写、不绑定节点端口，握手完成双向认证后即断开，不上报身份。

use anyhow::Context;
use i3t_crypto::NodeKey;
use i3t_model::update::Version;
use i3t_update::SelfCheckFailure;

use crate::config::Config;
use crate::control;
use crate::state::{ControllerInfo, StateDir};

/// 握手所需凭据：成功加载即可证明当前配置与状态均可被新版本正常解析。
struct Loaded {
    key: NodeKey,
    controller: ControllerInfo,
}

/// 自检。`running` 是这个程序自己的版本。
///
/// # Errors
///
/// 三件事里的哪一件没有做成。调用方把它写到标准错误，以非 0 退出。
pub async fn self_check(state: &StateDir, running: &Version) -> Result<(), SelfCheckFailure> {
    i3t_update::self_check(running, || load(state), async |loaded: Loaded| control::probe(&loaded.controller, &loaded.key).await).await
}

/// 把节点运行要读的东西都读一遍：配置文件、私钥、controller 的地址、最后一份 netmap。
fn load(state: &StateDir) -> anyhow::Result<Loaded> {
    let not_joined = crate::texts::texts().not_joined;
    Config::load(&state.config_path())?;
    let key = state.key()?.context(not_joined)?;
    let controller = state.controller()?.context(not_joined)?;
    state.netmap()?.context(not_joined)?;
    Ok(Loaded { key, controller })
}

#[cfg(test)]
mod tests {
    use i3t_model::control::ToController;

    use super::*;
    use crate::control::read_message;
    use crate::control::testing::{FakeController, netmap};

    fn joined(controller: &FakeController) -> (tempfile::TempDir, StateDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::open(dir.path()).unwrap();
        state.key_or_generate().unwrap();
        state.save_controller(&controller.info).unwrap();
        state.save_netmap(&netmap(3)).unwrap();
        (dir, state)
    }

    #[tokio::test]
    async fn a_joined_node_that_reaches_its_controller_passes_without_introducing_itself() {
        let controller = FakeController::start().await;
        let (_dir, state) = joined(&controller);
        let expected = state.key().unwrap().unwrap().public();
        let server = tokio::spawn(async move {
            let (mut stream, key) = controller.accept().await;
            assert_eq!(key, expected, "握手用的是节点自己的密钥");
            assert!(read_message::<_, ToController>(&mut stream).await.unwrap().is_none(), "自检不发 hello");
        });
        self_check(&state, &Version::new(0, 2, 0)).await.unwrap();
        server.await.unwrap();
        let names: Vec<_> = std::fs::read_dir(state.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(names.len(), 3, "自检不往状态目录里写东西：{names:?}");
    }

    #[tokio::test]
    async fn state_the_program_cannot_read_fails_the_check_before_any_connection() {
        let controller = FakeController::start().await;
        let (_dir, state) = joined(&controller);
        std::fs::write(state.config_path(), "port = \"not a number\"\n").unwrap();
        let failure = self_check(&state, &Version::new(0, 2, 0)).await.unwrap_err();
        assert!(matches!(&failure, SelfCheckFailure::State(reason) if reason.contains("config.toml")), "{failure}");

        let empty = tempfile::tempdir().unwrap();
        let failure = self_check(&StateDir::open(empty.path()).unwrap(), &Version::new(0, 2, 0)).await.unwrap_err();
        let not_joined = crate::texts::texts().not_joined;
        assert!(matches!(&failure, SelfCheckFailure::State(reason) if reason.contains(not_joined)), "{failure}");
    }

    #[tokio::test]
    async fn a_controller_that_cannot_be_reached_fails_the_check() {
        let controller = FakeController::start().await;
        let (_dir, state) = joined(&controller);
        drop(controller);
        let failure = self_check(&state, &Version::new(0, 2, 0)).await.unwrap_err();
        assert!(matches!(failure, SelfCheckFailure::Handshake(_)), "{failure}");
    }
}
