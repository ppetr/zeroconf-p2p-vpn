//! Running the daemon as a Windows service (`zeroconf-p2p-vpn service run <config>`), started by
//! the Service Control Manager (SCM).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

/// The one name the daemon's service is registered under.
pub const SERVICE_NAME: &str = "zeroconf-p2p-vpn";

/// How long the SCM waits for a pending start or stop before it considers the service hung.
const PENDING_WAIT_HINT: Duration = Duration::from_secs(30);

static CONFIG_PATH: OnceLock<String> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Hands the process over to the SCM; returns once the service has stopped.
///
/// Fails when the process was not started by the SCM (e.g. run from a console).
pub fn run_dispatcher(config_path: &str) -> anyhow::Result<()> {
    CONFIG_PATH.set(config_path.to_owned()).ok();
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).context(
        "cannot connect to the service control manager; `service run` is meant to be started by it",
    )
}

/// Directory of the daemon's log files.
fn log_dir() -> PathBuf {
    let program_data = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
    PathBuf::from(program_data).join(SERVICE_NAME).join("logs")
}

fn init_file_logging() {
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(SERVICE_NAME)
        .filename_suffix("log")
        .max_log_files(14)
        .build(log_dir());
    match appender {
        Ok(appender) => crate::init_logging(appender, false),
        Err(_) => crate::init_logging(std::io::stderr, false),
    }
}

fn report(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    exit_code: ServiceExitCode,
) -> windows_service::Result<()> {
    let pending = matches!(state, ServiceState::StartPending | ServiceState::StopPending);
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: u32::from(pending),
        wait_hint: if pending { PENDING_WAIT_HINT } else { Duration::ZERO },
        process_id: None,
    })
}

fn service_main(_arguments: Vec<OsString>) {
    init_file_logging();
    let config_path = CONFIG_PATH.get().expect("set before the dispatcher starts");

    let shutdown = CancellationToken::new();
    let handle = match service_control_handler::register(SERVICE_NAME, {
        let shutdown = shutdown.clone();
        move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }) {
        Ok(handle) => handle,
        Err(err) => {
            error!(%err, "Cannot register the service control handler");
            return;
        }
    };
    let _ = report(&handle, ServiceState::StartPending, ServiceExitCode::NO_ERROR);

    let exit_code = match serve_until_stopped(&handle, config_path, shutdown) {
        Ok(()) => ServiceExitCode::NO_ERROR,
        Err(err) => {
            error!("Service failed: {err:#}");
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    if let Err(err) = report(&handle, ServiceState::Stopped, exit_code) {
        error!(%err, "Cannot report the service as stopped");
    }
}

/// Runs the daemon, reporting `Running` once it is set up and `StopPending` once shutdown begins.
fn serve_until_stopped(
    handle: &ServiceStatusHandle,
    config_path: &str,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    // Carries a failure to report `Running` out of `ready`, which cannot return it.
    let (ready_err_tx, mut ready_err_rx) = oneshot::channel::<anyhow::Error>();

    let result = runtime.block_on(async {
        tokio::spawn({
            let (handle, shutdown) = (*handle, shutdown.clone());
            async move {
                shutdown.cancelled().await;
                let _ = report(&handle, ServiceState::StopPending, ServiceExitCode::NO_ERROR);
            }
        });
        let ready = {
            let (handle, shutdown) = (*handle, shutdown.clone());
            move || {
                if let Err(err) = report(&handle, ServiceState::Running, ServiceExitCode::NO_ERROR)
                {
                    let _ = ready_err_tx.send(
                        anyhow::Error::new(err).context("cannot report the service as running"),
                    );
                    shutdown.cancel();
                }
            }
        };
        crate::serve(config_path, shutdown, ready).await
    });

    match ready_err_rx.try_recv() {
        Ok(ready_err) => {
            if let Err(err) = result {
                warn!("Daemon also failed while stopping: {err:#}");
            }
            Err(ready_err)
        }
        Err(_) => result,
    }
}

/// Runs a `service` subcommand: `run <config>` (started by the SCM).
pub fn command(args: &[&str]) -> anyhow::Result<()> {
    match args {
        ["run", config_path] => run_dispatcher(config_path),
        _ => anyhow::bail!("Usage: zeroconf-p2p-vpn service run <config-file-path>"),
    }
}
