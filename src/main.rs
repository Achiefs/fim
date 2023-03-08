// Copyright (C) 2021, Achiefs.

// To allow big structs like json on audit events
#![recursion_limit = "256"]


// To manage event channels
use std::sync::mpsc;

// Utils functions
mod utils;
// Hashing functions
mod hash;
// Configuration load functions
mod config;
// Index management functions
mod index;
// Single event data management
mod event;
// File reading continuously
mod logreader;
mod auditevent;
// Manage Windows service
#[cfg(target_os = "windows")]
mod service;
// Manage monitor methods
mod monitor;

static mut GCONFIG: Option<config::Config> = None;

// ----------------------------------------------------------------------------

fn init(){
    use std::path::Path;
    use simplelog::WriteLogger;
    use simplelog::Config;
    use std::fs;

    println!("Achiefs File Integrity Monitoring software starting!");
    println!("[INFO] Reading config...");
    unsafe{
        GCONFIG = Some(config::Config::new(&utils::get_os(), None));    

        // Create folders to store logs based on config.yml
        fs::create_dir_all(
            Path::new( &GCONFIG.clone().unwrap().log_file
            ).parent().unwrap().to_str().unwrap()
        ).unwrap();

        // Create logger output to write generated logs.
        WriteLogger::init(
            GCONFIG.clone().unwrap().get_level_filter(),
            Config::default(),
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open(GCONFIG.clone().unwrap().log_file)
                .expect("Unable to open log file")
        ).unwrap();

        println!("[INFO] Configuration successfully read, forwarding output to log file");
        println!("[INFO] Log file: '{}'", GCONFIG.clone().unwrap().log_file);
        println!("[INFO] Log level: '{}'", GCONFIG.clone().unwrap().log_level);
    };
    log_panics::init();
}

// ----------------------------------------------------------------------------

// Main function where the magic happens
#[cfg(not(windows))]
#[tokio::main]
async fn main() {
    init();

    let (tx, rx) = mpsc::channel();
    monitor::monitor(tx, rx).await;
}

// ----------------------------------------------------------------------------

#[cfg(windows)]
#[tokio::main]
async fn main() -> windows_service::Result<()> {
    init();

    // To manage terminal parameters
    use std::env;
    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--foreground"|"-f" => {
                let (tx, rx) = mpsc::channel();
                monitor::monitor(tx, rx).await;
                Ok(())
            },
            _ => { service::run() }
        }
    }else{ service::run() }
}

// ----------------------------------------------------------------------------