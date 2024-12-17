// Copyright (C) 2021, Achiefs.

// To allow big structs like json on audit events
#![recursion_limit = "256"]

use std::sync::mpsc;
use std::thread;
use log::{error, info};
use crate::init::init;

// Utils functions
mod utils;
// Hashing functions
mod hash;
// Configuration load functions
mod appconfig;
// Ruleset load functions
mod ruleset;
// Index management functions
mod index;
// Single event data management
mod event;
mod monitorevent;
mod ruleevent;
// File reading continuously
mod logreader;
mod auditevent;
// Manage Windows service
#[cfg(target_os = "windows")]
mod service;
// Manage monitor methods
mod monitor;
// Manage integrations
mod integration;
mod launcher;
mod multiwatcher;
mod rotator;
mod init;
mod db;
mod scanner;

// ----------------------------------------------------------------------------

// Main function where the magic happens
#[cfg(not(windows))]
#[tokio::main]
async fn main() {
    let (cfg, ruleset) = init();

    let (tx, rx) = mpsc::channel();
    let rotator_cfg = cfg.clone();
    match thread::Builder::new()
        .name("FIM_Rotator".to_string()).spawn(|| rotator::rotator(rotator_cfg)){
        Ok(_v) => info!("FIM rotator thread started."),
        Err(e) => error!("Could not start FIM rotator thread, error: {}", e)
    };
    monitor::monitor(tx, rx, cfg, ruleset).await;
}

// ----------------------------------------------------------------------------

#[cfg(windows)]
#[tokio::main]
async fn main() -> windows_service::Result<()> {
    // To manage terminal parameters
    use std::env;
    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--foreground"|"-f" => {
                let (tx, rx) = mpsc::channel();
                let (cfg, ruleset) = init();
                let rotator_cfg = cfg.clone();
                match thread::Builder::new()
                    .name("FIM_Rotator".to_string())
                    .spawn(|| rotator::rotator(rotator_cfg)){
                        Ok(_v) => info!("FIM rotator thread started."),
                        Err(e) => error!("Could not start FIM rotator thread, error: {}", e)
                    };
                monitor::monitor(tx, rx, cfg, ruleset).await;
                Ok(())
            },
            _ => { service::run() }
        }
    }else{ service::run() }
}

// ----------------------------------------------------------------------------