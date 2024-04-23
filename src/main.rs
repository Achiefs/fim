// Copyright (C) 2021, Achiefs.

// To allow big structs like json on audit events
#![recursion_limit = "256"]

use std::sync::mpsc;
use std::thread;
use log::{error, info};

// Utils functions
mod utils;
// Hashing functions
mod hash;
// Configuration load functions
mod config;
// Ruleset load functions
mod ruleset;
// Index management functions
mod index;
// Single event data management
mod event;
mod monitorevent;
mod monitorruleevent;
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

static mut GRULESET: Option<ruleset::Ruleset> = None;

// ----------------------------------------------------------------------------

fn init() -> config::Config {
    use std::path::Path;
    use simplelog::WriteLogger;
    use simplelog::Config;
    use std::fs;

    println!("[INFO] Achiefs File Integrity Monitoring software starting!");
    println!("[INFO] Reading config...");
    let cfg = config::Config::new(&utils::get_os(), None);
    unsafe{ 
        GRULESET = Some(ruleset::Ruleset::new(&utils::get_os(), None));
    };
    // Create folders to store logs based on config.yml
    fs::create_dir_all(
        Path::new( &cfg.clone().log_file
        ).parent().unwrap().to_str().unwrap()
    ).unwrap();

    // Create logger output to write generated logs.
    WriteLogger::init(
        cfg.clone().get_level_filter(),
        Config::default(),
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(cfg.clone().log_file)
            .expect("Unable to open log file")
    ).unwrap();

    println!("[INFO] Configuration successfully read, forwarding output to log file.");
    println!("[INFO] Log file: '{}'", cfg.clone().log_file);
    println!("[INFO] Log level: '{}'", cfg.clone().log_level);
    println!("[INFO] Ruleset successfully load.");
    
    log_panics::init();
    cfg
}

// ----------------------------------------------------------------------------

// Main function where the magic happens
#[cfg(not(windows))]
#[tokio::main]
async fn main() {
    let cfg = init();

    let (tx, rx) = mpsc::channel();
    match thread::Builder::new()
        .name("FIM_Rotator".to_string()).spawn(|| rotator::rotator(cfg)){
        Ok(_v) => info!("FIM rotator thread started."),
        Err(e) => error!("Could not start FIM rotator thread, error: {}", e)
    };
    monitor::monitor(tx, rx, cfg).await;
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
                let cfg = init();
                let rotator_cfg = cfg.clone();
                match thread::Builder::new()
                    .name("FIM_Rotator".to_string())
                    .spawn(|| rotator::rotator(rotator_cfg)){
                        Ok(_v) => info!("FIM rotator thread started."),
                        Err(e) => error!("Could not start FIM rotator thread, error: {}", e)
                    };
                monitor::monitor(tx, rx, cfg).await;
                Ok(())
            },
            _ => { service::run() }
        }
    }else{ service::run() }
}

// ----------------------------------------------------------------------------