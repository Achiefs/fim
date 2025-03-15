// Copyright (C) 2022, Achiefs.
// Parts of the code here is based on mullvad/windows-service-rs crate examples
// Crate link: https://github.com/mullvad/windows-service-rs

use notify::event::{Event, EventKind, EventAttributes};
use std::thread;
use tokio::runtime::Runtime;

use crate::monitor;
use crate::rotator;
use crate::init::init;
use crate::hashscanner;

use log::{error, info};
use std::{
    ffi::OsString,
    sync::mpsc,
    time::Duration,
    path::PathBuf,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher, Result,
};

const SERVICE_NAME: &str = "FimService";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// ----------------------------------------------------------------------------

pub fn run() -> Result<()> {
    // Register generated `ffi_service_main` with the system and start the service, blocking
    // this thread until the service is stopped.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

// ----------------------------------------------------------------------------

// Generate the windows service boilerplate.
// The boilerplate contains the low-level service entry function (ffi_service_main) that parses
// incoming service arguments into Vec<OsString> and passes them to user defined service
// entry (my_service_main).
define_windows_service!(ffi_service_main, my_service_main);

// ----------------------------------------------------------------------------

// Service entry function which is called on background thread by the system with service
// parameters. There is no stdout or stderr at this point so make sure to configure the log
// output to file if needed.
pub fn my_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("Run service failed, error: {}", e);
    }
}

// ----------------------------------------------------------------------------

pub fn run_service() -> Result<()> {
    // Create a channel to be able to poll a stop event from the service worker loop.
    let (tx, rx) = mpsc::channel();
    let signal_handler = tx.clone();

    // Define system service event handler that will be receiving service events.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // Notifies a service to report its current status information to the service
            // control manager. Always return NoError even if not implemented.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

            // Handle stop
            ServiceControl::Stop => {
                signal_handler.send(Ok(Event {
                    paths: vec![PathBuf::from("DISCONNECT")],
                    kind: EventKind::Any,
                    attrs: EventAttributes::new()
                })).unwrap();
                ServiceControlHandlerResult::NoError
            },

            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler.
    // The returned status handle should be used to report service status changes to the system.
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Tell the system that service is running
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let (cfg, ruleset) = init();
    let rotator_cfg = cfg.clone();
    let hashscanner_cfg = cfg.clone();

    match thread::Builder::new()
        .name("FIM_Rotator".to_string()).spawn(|| rotator::rotator(rotator_cfg)){
        Ok(_v) => info!("FIM rotator thread started."),
        Err(e) => error!("Could not start FIM rotator thread, error: {}", e)
    };

    if cfg.hashscanner_enabled {
        match thread::Builder::new()
        .name("FIM_HashScanner".to_string())
        .spawn(|| hashscanner::scan(hashscanner_cfg)){
            Ok(_v) => info!("FIM HashScanner thread started."),
            Err(e) => error!("Could not start FIM HashScanner thread, error: {}", e)
        };
    } else {
        info!("FIM HashScanner thread disabled, not running.")
    };

    let rt = Runtime::new().unwrap();
    rt.block_on(monitor::monitor(tx, rx, cfg, ruleset));

    // Tell the system that service has stopped.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

