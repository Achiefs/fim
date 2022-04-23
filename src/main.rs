// Copyright (C) 2021, Achiefs.

// To read and write directories and files, env to get Operating system
use std::fs;
// To get file system changes
use notify::{RecommendedWatcher, Watcher, RecursiveMode};
use std::sync::mpsc::channel;
// To log the program process
use log::{info, error, debug};
use simplelog::{WriteLogger, Config};
// To manage paths
use std::path::Path;
// To manage date and time
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
// To manage unique event identifier
use uuid::Uuid;
// To use intersperse()
use itertools::Itertools;
// To get own process ID
use std::process;

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
use event::Event;
// Async calls management
use futures::executor::block_on;
use tokio;

// ----------------------------------------------------------------------------

// Main function where the magic happens
#[tokio::main]
async fn main() {
    println!("Achiefs File Integrity Monitoring software started!");
    println!("[INFO] Reading config...");
    let config = config::Config::new();
    println!("[INFO] Log file: {}", config.log_file);
    println!("[INFO] Log level: {}", config.log_level);

    // Create folders to store logs based on config.yml
    fs::create_dir_all(Path::new(&config.log_file).parent().unwrap().to_str().unwrap()).unwrap();

    // Create logger output to write generated logs.
    WriteLogger::init(
        config.get_level_filter(),
        Config::default(),
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(config.log_file.clone())
            .expect("Unable to open log file")
    ).unwrap();

    let destination = config.get_events_destination();
    let current_date = OffsetDateTime::now_utc();
    let index_name = format!("fim-{}-{}-{}", current_date.year(), current_date.month() as u8, current_date.day() );

    // Perform actions depending on destination
    match destination.as_str() {
        config::BOTH_MODE => {
            println!("[INFO] Events file: {}", config.events_file);
            fs::create_dir_all(Path::new(&config.events_file).parent().unwrap().to_str().unwrap()).unwrap();

            // On start create index (Include check if events won't be ingested by http)
            block_on(index::create_index( index_name.clone(), config.endpoint_address.clone(), config.endpoint_user.clone(), config.endpoint_pass.clone()) );
        },
        config::NETWORK_MODE => {
            // On start create index (Include check if events won't be ingested by http)
            block_on(index::create_index( index_name.clone(), config.endpoint_address.clone(), config.endpoint_user.clone(), config.endpoint_pass.clone()) );
        },
        _ => {
            println!("[INFO] Events file: {}", config.events_file);
            fs::create_dir_all(Path::new(&config.events_file).parent().unwrap().to_str().unwrap()).unwrap()
        }
    }

    // Iterating over monitor paths and set watcher on each folder to watch.
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new_raw(tx).unwrap();
    for m in config.monitor.clone() {
        let path = m["path"].as_str().unwrap();
        info!("Monitoring path: {}", path);
        match m["ignore"].as_vec() {
            Some(ig) => {
                let ignore_list_vec  = ig.iter().map(|e| { e.as_str().unwrap() });
                let ignore_list : String = Itertools::intersperse(ignore_list_vec, ", ").collect();
                info!("Ignoring files with: {} inside {}", ignore_list, path);
            },
            None => info!("Ignore for '{}' not set", path)
        };
        watcher.watch(path, RecursiveMode::Recursive).unwrap();
    }

    // Main loop, receive any produced event and write it into the events log.
    loop {
        match rx.recv() {
            Ok(raw_event) => {
                // Get the event path and filename
                debug!("Event registered: {:?}", raw_event);
                let event_path = Path::new(raw_event.path.as_ref().unwrap().to_str().unwrap());
                let event_parent_path = event_path.parent().unwrap().to_str().unwrap();
                let event_filename = event_path.file_name().unwrap();

                // Iterate over monitoring paths to match ignore string and ignore event or not
                let monitor_vector = config.monitor.clone().to_vec();
                let monitor_index = monitor_vector.iter().position(|it| {
                    let path = it["path"].as_str().unwrap();
                    let value = if path.ends_with('/') || path.ends_with('\\'){ utils::pop(path) }else{ path };
                    event_parent_path.contains(value)
                });
                let index = monitor_index.unwrap();

                if monitor_index.is_some() &&
                    match monitor_vector[index]["ignore"].as_vec() {
                        Some(igv) => ! igv.to_vec().iter().any(|ignore| event_filename.to_str().unwrap().contains(ignore.as_str().unwrap()) ),
                        None => true
                    }{

                    let current_timestamp = format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis());
                    let current_hostname = gethostname::gethostname().into_string().unwrap();
                    let yaml_labels = match config.monitor[index]["labels"].clone().into_vec() {
                        Some(lb) => lb,
                        None => Vec::new()
                    };
                    let current_labels = yaml_labels.to_vec().iter().map(|element| String::from(element.as_str().unwrap()) ).collect();
                    let operation = raw_event.op.unwrap().clone();
                    let path = raw_event.path.unwrap().clone();

                    let event = Event {
                        id: format!("{}", Uuid::new_v4()),
                        timestamp: current_timestamp,
                        hostname: current_hostname,
                        nodename: config.nodename.clone(),
                        version: String::from(config::VERSION),
                        operation: operation.clone(),
                        path: path.clone(),
                        labels: current_labels,
                        kind: event::get_kind(operation.clone()),
                        checksum: hash::get_checksum(path.to_str().unwrap().clone()),
                        pid: process::id(),
                        system: config.system.clone()
                    };

                    debug!("Event received: {:?}", event);
                    match destination.as_str() {
                        config::BOTH_MODE => {
                            event.log_event(config.events_file.clone());
                            block_on(event.send( index_name.clone(), config.endpoint_address.clone(), config.endpoint_user.clone(), config.endpoint_pass.clone()) );
                        },
                        config::NETWORK_MODE => {
                            block_on(event.send( index_name.clone(), config.endpoint_address.clone(), config.endpoint_user.clone(), config.endpoint_pass.clone()) );
                        },
                        _ => event.log_event(config.events_file.clone())
                    }
                }else{
                    debug!("Event ignored not stored in alerts");
                }
            },
            Err(e) => error!("Watch error: {:?}", e),
        }
    }
}
