use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use anyhow::{Context, Result};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

use crate::native::{report_event, request_notification_stop, run_notification_loop};
use crate::{AlertPolicy, EventStore};

const SERVICE_NAME: &str = "PeripheralLedger";

define_windows_service!(service_entry, service_main);

pub fn dispatch() -> windows_service::Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, service_entry)
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run() {
        eprintln!("PeripheralLedger service failed: {error:#}");
    }
}

fn run() -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let notification_thread_id = Arc::new(AtomicU32::new(0));
    let stop_for_handler = Arc::clone(&stop);
    let thread_for_handler = Arc::clone(&notification_thread_id);
    let status = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop_for_handler.store(true, Ordering::SeqCst);
            let thread_id = thread_for_handler.load(Ordering::SeqCst);
            if thread_id != 0 {
                request_notification_stop(thread_id);
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    let database = data_path()?;
    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).context("create service data directory")?;
    }
    let mut store = EventStore::open(database)?;
    let policy = policy_from_environment();
    let (sender, receiver) = mpsc::channel();
    let id_for_thread = Arc::clone(&notification_thread_id);
    let notifier = std::thread::spawn(move || {
        let id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
        id_for_thread.store(id, Ordering::SeqCst);
        run_notification_loop(sender)
    });

    while !stop.load(Ordering::SeqCst) {
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(mut event) => {
                policy.evaluate(&mut event);
                report_event(&event);
                store.append(event)?;
                store.verify()?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let thread_id = notification_thread_id.load(Ordering::SeqCst);
    if thread_id != 0 {
        request_notification_stop(thread_id);
    }
    notifier
        .join()
        .map_err(|_| anyhow::anyhow!("notification thread panicked"))??;
    status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;
    Ok(())
}

fn data_path() -> Result<PathBuf> {
    let root = std::env::var_os("ProgramData").context("ProgramData is not defined")?;
    Ok(PathBuf::from(root)
        .join("PeripheralLedger")
        .join("events.db"))
}

fn policy_from_environment() -> AlertPolicy {
    let pairs = std::env::var("PERIPHERAL_LEDGER_DENY")
        .unwrap_or_default()
        .split(',')
        .filter_map(|pair| pair.split_once(':'))
        .map(|(vendor, product)| (vendor.trim().into(), product.trim().into()))
        .collect();
    AlertPolicy::new(pairs)
}
