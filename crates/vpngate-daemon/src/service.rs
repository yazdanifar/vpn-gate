//! The Windows service host: registers with the service control manager, runs the pipe daemon until a stop or system
//! shutdown, and reports its state. Installing the service (auto-start, restart on failure) is the MSI's job (U20).

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::{define_windows_service, service_dispatcher};

use crate::backend;
use crate::daemon::run_pipe_daemon;

pub const SERVICE_NAME: &str = "VPNGate";

define_windows_service!(ffi_service_main, service_main);

/// Hands the process to the service control manager. Returns when the service has stopped; fails when the process was
/// not started by the SCM.
pub fn run() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        println!("[service] {e}");
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let stop = Arc::new(Notify::new());
    let handler_stop = stop.clone();
    let handle: ServiceStatusHandle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // A permit is stored, so a stop that arrives before the daemon waits is not lost.
            handler_stop.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    handle.set_service_status(status(ServiceState::StartPending, ServiceControlAccept::empty(), 0))?;
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), 1))?;
            return Err(e.into());
        }
    };
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ))?;

    let result = runtime.block_on(run_pipe_daemon(backend::WINDOWS_PIPE_NAME.to_string(), None, None, async move {
        stop.notified().await
    }));

    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        u32::from(result.is_err()),
    ))?;
    Ok(result?)
}
