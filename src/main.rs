// Copyright (C) 2021, Achiefs.

// To allow big structs like json on audit events
#![recursion_limit = "256"]

use std::sync::mpsc;
use std::thread;
use log::{error, info};
use crate::init::init;

mod utils;
mod hash;
mod config;
mod ruleset;
mod index;
mod logreader;
mod monitor;
mod integration;
mod launcher;
mod multiwatcher;
mod rotator;
mod init;
mod db;
mod dbfile;
mod hashscanner;
mod events;
#[cfg(target_os = "windows")]
mod service;

// ----------------------------------------------------------------------------

// Main function where the magic happens
#[cfg(not(windows))]
#[tokio::main]
async fn main() {
    let (cfg, ruleset) = init();

    let (tx, rx) = mpsc::channel();
    let rotator_cfg = cfg.clone();
    let hashscanner_cfg = cfg.clone();
    match thread::Builder::new()
        .name("FIM_Rotator".to_string()).spawn(|| rotator::rotator(rotator_cfg)){
        Ok(_v) => info!("FIM rotator thread started."),
        Err(e) => error!("Could not start FIM rotator thread, error: {}", e)
    };

    if cfg.hashscanner_enabled {
        match thread::Builder::new()
            .name("FIM_HashScanner".to_string()).spawn(|| hashscanner::scan(hashscanner_cfg)){
            Ok(_v) => info!("FIM HashScanner thread started."),
            Err(e) => error!("Could not start FIM HashScanner thread, error: {}", e)
        };
    } else {
        info!("FIM HashScanner thread disabled, not running.")
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
                let hashscanner_cfg = cfg.clone();
                match thread::Builder::new()
                    .name("FIM_Rotator".to_string())
                    .spawn(|| rotator::rotator(rotator_cfg)){
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
                monitor::monitor(tx, rx, cfg, ruleset).await;
                Ok(())
            },
            _ => { service::run() }
        }
    }else{ service::run() }
}

// ----------------------------------------------------------------------------