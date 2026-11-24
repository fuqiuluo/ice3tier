//! Windows 上作为系统服务运行：登记、注销、启动，以及和服务控制管理器（SCM）之间的往来。
//!
//! 安装脚本（`deploy/install.ps1`）用 `i3t service install` 把本程序登记成开机自动启动的服务，服务的命令行是
//! `i3t.exe run --service`，以 LocalSystem 运行。服务停下时退出码不是 0，SCM 过 [`RESTART_DELAY`] 把它重新拉起来，
//! 和 Linux 上 systemd 的 `Restart=always` 是一回事：节点自己更新之后"请重启我"的退出也走这条路。
//! 无法通过重启恢复的情况（尚未加入网络、配置错误、节点被吊销）以退出码 0 停止，使 SCM 不再自动重启。

use std::ffi::OsString;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

/// 服务的名字：`Start-Service i3t`、`sc query i3t` 用的就是它。
pub const NAME: &str = "i3t";
const DISPLAY_NAME: &str = "ice3tier node";
const DESCRIPTION: &str = "Keeps this machine connected to its ice3tier network.";

/// 服务失败之后过多久重新启动。和 systemd 单元里的 `RestartSec` 一样。
const RESTART_DELAY: Duration = Duration::from_secs(2);
/// 这么久没有再失败，SCM 记的失败次数清零。
const FAILURE_RESET: Duration = Duration::from_secs(24 * 60 * 60);
/// 停止服务时最多等多久。
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// 系统的错误码：没有这个服务、服务没有在运行、服务此刻不接受控制（正在启动或者停止）。
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: i32 = 1061;

/// SCM 要服务停下（或者系统要关机）时完成。
pub type Stop = Pin<Box<dyn Future<Output = ()>>>;

/// 服务要做的事：运行到 [`Stop`] 完成为止，返回服务的退出码。0 是正常停止，别的 SCM 会重新启动服务。
type Job = Box<dyn FnOnce(Stop) -> u32 + Send>;

/// 供 [`dispatch`] 传递给 [`service_main`] 的任务闭包。SCM 在独立线程中调用服务入口且不支持传参，因此通过全局变量中转。
static JOB: Mutex<Option<Job>> = Mutex::new(None);

/// 在 SCM 下面运行 `job`，等到服务停止才返回。
///
/// # Errors
///
/// 这个进程不是 SCM 启动的（在终端里执行了 `i3t run --service`）。
pub fn dispatch(job: impl FnOnce(Stop) -> u32 + Send + 'static) -> windows_service::Result<()> {
    *JOB.lock().expect("service job mutex poisoned") = Some(Box::new(job));
    service_dispatcher::start(NAME, ffi_service_main)
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    let Some(job) = JOB.lock().expect("service job mutex poisoned").take() else { return };
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // 收的一头没了，说明节点已经在收尾。
            let _already_stopping = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    // 注册控制处理器失败则无法向 SCM 上报状态，SCM 未收到"运行中"状态将判定启动失败。此时日志尚未初始化。
    let Ok(status) = service_control_handler::register(NAME, handler) else { return };
    report(status, ServiceState::Running, 0);
    let stop = Box::pin(async move {
        // 发的一头在上面的处理函数里，服务登记着就一直在；它要是没了，就不会再有通知，一直等。
        if stop_rx.recv().await.is_none() {
            std::future::pending::<()>().await;
        }
        report(status, ServiceState::StopPending, 0);
    });
    let exit_code = job(stop);
    report(status, ServiceState::Stopped, exit_code);
}

/// 把服务现在的状态报给 SCM。运行中才接受停止和关机的通知；正在停止时告诉它最多等多久。
fn report(status: ServiceStatusHandle, state: ServiceState, exit_code: u32) {
    let stopping = state == ServiceState::StopPending;
    let reported = status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: u32::from(stopping),
        wait_hint: if stopping { STOP_TIMEOUT } else { Duration::ZERO },
        process_id: None,
    });
    if let Err(error) = reported {
        tracing::warn!(%error, ?state, "向系统上报服务状态失败");
    }
}

fn manager(access: ServiceManagerAccess) -> windows_service::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | access)
}

/// `error` 是不是系统的这个错误码。
fn is_os_error(error: &windows_service::Error, code: i32) -> bool {
    matches!(error, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(code))
}

/// 打开登记着的服务；没有登记是 `None`。
fn open(access: ServiceAccess) -> windows_service::Result<Option<Service>> {
    match manager(ServiceManagerAccess::empty())?.open_service(NAME, access) {
        Ok(service) => Ok(Some(service)),
        Err(error) if is_os_error(&error, ERROR_SERVICE_DOES_NOT_EXIST) => Ok(None),
        Err(error) => Err(error),
    }
}

/// 查询服务是否已注册。查询失败时按未注册处理。
pub fn is_installed() -> bool {
    matches!(open(ServiceAccess::QUERY_STATUS), Ok(Some(_)))
}

/// 把 `program` 登记成开机自动启动的服务；已经登记过就改成现在的样子。不启动它。
///
/// # Errors
///
/// 没有管理员权限，或者 SCM 拒绝。
pub fn install(program: &Path) -> windows_service::Result<()> {
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: program.to_owned(),
        launch_arguments: vec!["run".into(), "--service".into()],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    };
    // 设置"失败之后重新启动"要有启动服务的权限。
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = match open(access)? {
        Some(service) => {
            service.change_config(&info)?;
            service
        }
        None => manager(ServiceManagerAccess::CREATE_SERVICE)?.create_service(&info, access)?,
    };
    // 失败的次数超过这里列的动作数时，SCM 一直重复最后一个，所以一个就够。
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction { action_type: ServiceActionType::Restart, delay: RESTART_DELAY }]),
    })?;
    // 服务自己报"已停止"但退出码不是 0，也算失败：节点更新之后就是这样请 SCM 重启它的。
    service.set_failure_actions_on_non_crash_failures(true)?;
    service.set_description(DESCRIPTION)
}

/// 停下并注销服务。没有登记过不算错。
///
/// # Errors
///
/// 没有管理员权限，或者 SCM 拒绝。
pub fn uninstall() -> windows_service::Result<()> {
    let Some(service) = open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)? else { return Ok(()) };
    stop(&service)?;
    service.delete()
}

/// 服务登记着的话把它（重新）启动。返回它登记着没有。
///
/// # Errors
///
/// 缺少管理员权限或服务启动失败。
pub fn restart() -> windows_service::Result<bool> {
    let Some(service) = open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START)? else { return Ok(false) };
    stop(&service)?;
    service.start::<OsString>(&[])?;
    Ok(true)
}

/// 要服务停下，等到它停了为止（最多 [`STOP_TIMEOUT`]）。本来就停着、正好自己停了都不算错。
fn stop(service: &Service) -> windows_service::Result<()> {
    if service.query_status()?.current_state != ServiceState::Stopped {
        match service.stop() {
            Ok(_) => {}
            Err(error) if is_os_error(&error, ERROR_SERVICE_NOT_ACTIVE) || is_os_error(&error, ERROR_SERVICE_CANNOT_ACCEPT_CTRL) => {}
            Err(error) => return Err(error),
        }
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    while service.query_status()?.current_state != ServiceState::Stopped && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
