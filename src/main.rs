// Copyright (C) 2021, Achiefs.

// To allow big structs like json on audit events
#![recursion_limit = "256"]

// To read and write directories and files
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
// To use intersperse()
use itertools::Itertools;
// To run commands
use std::process::Command;
// Event handling
use notify::op::Op;


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


// ----------------------------------------------------------------------------

fn setup_logger(config: config::Config){
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
            .open(config.log_file)
            .expect("Unable to open log file")
    ).unwrap();
}

// ----------------------------------------------------------------------------

fn setup_events(destination: &str, config: config::Config){
    // Perform actions depending on destination
    info!("Events destination selected: {}", destination);
    match destination {
        config::NETWORK_MODE => {
            debug!("Events folder not created in network mode");
        },
        _ => {
            info!("Events file: {}", config.events_file);
            fs::create_dir_all(Path::new(&config.events_file).parent().unwrap().to_str().unwrap()).unwrap()
        }
    }
}

// ----------------------------------------------------------------------------

async fn push_template(destination: &str, config: config::Config){
    // Perform actions depending on destination
    match destination {
        config::NETWORK_MODE|config::BOTH_MODE => {
            // On start push template (Include check if events won't be ingested by http)
            index::push_template(config.endpoint_address, config.endpoint_user, config.endpoint_pass, config.insecure).await;
        },
        _ => {
            debug!("Template not pushed in file mode");
        }
    }
}

// ----------------------------------------------------------------------------

// Main function where the magic happens
#[tokio::main]
async fn main() {
    println!("Achiefs File Integrity Monitoring software started!");
    println!("[INFO] Reading config...");
    let config = config::Config::new(&utils::get_os());
    println!("[INFO] Log file: {}", config.log_file);
    println!("[INFO] Log level: {}", config.log_level);

    setup_logger(config.clone());
    let destination = config.get_events_destination();
    setup_events(destination.as_str(), config.clone());

    // Check if we have to push index template
    push_template(destination.as_str(), config.clone()).await;

    // Iterating over monitor paths and set watcher on each folder to watch.
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new_raw(tx).unwrap();
    if ! config.monitor.is_empty() {
        for element in config.monitor.clone() {
            let path = element["path"].as_str().unwrap();
            info!("Monitoring path: {}", path);
            match element["ignore"].as_vec() {
                Some(ig) => {
                    let ignore_list_vec  = ig.iter().map(|e| { e.as_str().unwrap() });
                    let ignore_list : String = Itertools::intersperse(ignore_list_vec, ", ").collect();
                    info!("Ignoring files with: {} inside {}", ignore_list, path);
                },
                None => info!("Ignore for '{}' not set", path)
            };
            watcher.watch(path, RecursiveMode::Recursive).unwrap();
        }
    }
    let mut last_position = 0;
    if ! config.audit.is_empty() && utils::get_os() == "linux" && utils::check_auditd() {
        for element in config.audit.clone() {
            let path = element["path"].as_str().unwrap();
            match Command::new("/usr/sbin/auditctl")
                .args(["-w", path, "-k", "fim", "-p", "wax"])
                .output() {
                Ok(d) => debug!("Auditctl command info: {:?}", d),
                Err(e) => error!("Auditctl command error: {}", e)
            };
            info!("Monitoring audit path: {}", path);
            match element["ignore"].as_vec() {
                Some(ig) => {
                    let ignore_list_vec  = ig.iter().map(|e| { e.as_str().unwrap() });
                    let ignore_list : String = Itertools::intersperse(ignore_list_vec, ", ").collect();
                    info!("Ignoring files with: {} inside {}", ignore_list, path);
                },
                None => info!("Ignore for '{}' not set", path)
            };
        }
        // Detect if file is moved or renamed (rotation)
        watcher.watch(logreader::AUDIT_PATH, RecursiveMode::NonRecursive).unwrap();
        last_position = utils::get_file_end(logreader::AUDIT_LOG_PATH);
        // Remove auditd rules introduced by FIM
        let cconfig = config.clone();
        ctrlc::set_handler(move || {
            for element in &cconfig.audit {
                let path = element["path"].as_str().unwrap();
                match Command::new("/usr/sbin/auditctl")
                    .args(["-W", path, "-k", "fim", "-p", "wax"])
                    .output()
                    {
                        Ok(d) => debug!("Auditctl command info: {:?}", d),
                        Err(e) => error!("Auditctl command error: {}", e)
                    };
            }
            std::process::exit(0);
        }).expect("Error setting Ctrl-C handler");
    }

    // Main loop, receive any produced event and write it into the events log.
    loop {
        match rx.recv() {
            Ok(raw_event) => {
                // Get the event path and filename
                debug!("Event received: {:?}", raw_event);
                let plain_path = raw_event.path.as_ref().unwrap().to_str().unwrap();
                let event_path = Path::new(plain_path);
                let event_filename = event_path.file_name().unwrap();

                let current_date = OffsetDateTime::now_utc();
                let index_name = format!("fim-{}-{}-{}", current_date.year(), current_date.month() as u8, current_date.day() );
                let current_timestamp = format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis());
                let current_hostname = utils::get_hostname();
                let op = raw_event.op.unwrap();
                let path = raw_event.path.clone().unwrap();

                // Reset reading position due to log rotation
                if plain_path == logreader::AUDIT_LOG_PATH && op == Op::CHMOD {
                    last_position = 0;
                }

                // If the event comes from audit.log
                if plain_path == logreader::AUDIT_LOG_PATH {
                    // Getting events from audit.log
                    let mut events = Vec::new();
                    let (event, position) = logreader::read_log(String::from(logreader::AUDIT_LOG_PATH), config.clone(), last_position, 0);
                    if event.id != "0" { events.push(event); };
                    let mut ctr = 0;
                    last_position = position;
                    while last_position < utils::get_file_end(logreader::AUDIT_LOG_PATH) {
                        debug!("Reading events, iteration: {}", ctr);
                        ctr = ctr + 1;
                        let (evt, pos) = logreader::read_log(String::from(logreader::AUDIT_LOG_PATH), config.clone(), last_position, ctr);
                        if evt.id != "0" { events.push(evt); };
                        last_position = pos;
                    }
                    debug!("Events read from audit log, position: {}", last_position);

                    for audit_event in events {
                        if ! audit_event.is_empty() {
                            // Getting the position of event in config (match ignore and labels)
                            let index = config.get_index(audit_event.clone().path.as_str(),
                                audit_event.clone().cwd.as_str(),
                                config.audit.clone().to_vec());

                            if index != usize::MAX {
                                // If event contains ignored string ignore event
                                if ! config.match_ignore(index,
                                        audit_event.clone().file.as_str(),
                                        config.audit.clone()) {
                                    audit_event.process(destination.clone().as_str(), index_name.clone(), config.clone()).await;
                                }else{
                                    debug!("Event ignored not stored in alerts");
                                }
                            }else{
                                debug!("Event not monitored by FIM");
                            }
                        }
                        debug!("Event processed: {:?}", audit_event.clone());
                    }
                }else {
                    let index = config.get_index(event_path.to_str().unwrap(), "", config.monitor.clone().to_vec());
                    if index != usize::MAX {
                        let labels = config.get_labels(index, config.monitor.clone());
                        if ! config.match_ignore(index,
                            event_filename.to_str().unwrap(), config.monitor.clone()){
                            let event = event::Event {
                                id: utils::get_uuid(),
                                timestamp: current_timestamp,
                                hostname: current_hostname,
                                node: config.node.clone(),
                                version: String::from(config::VERSION),
                                op,
                                path: path.clone(),
                                labels,
                                operation: event::get_op(op),
                                checksum: hash::get_checksum( String::from(path.to_str().unwrap()) ),
                                fpid: utils::get_pid(),
                                system: config.system.clone()
                            };

                            debug!("Event processed: {:?}", event);
                            event.process(destination.clone().as_str(), index_name.clone(), config.clone()).await;
                        }else{
                            debug!("Event ignored not stored in alerts");
                        }
                    }
                }
            },
            Err(e) => error!("Watch error: {:?}", e)
        }
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::block_on;

    // ------------------------------------------------------------------------

    #[test]
    fn test_setup_logger() {
        let config = config::Config::new(&utils::get_os());
        fs::create_dir_all(&Path::new(&config.events_file).parent().unwrap()).unwrap();
        setup_logger(config.clone());
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_push_template() {
        let config = config::Config::new(&utils::get_os());
        fs::create_dir_all(Path::new(&config.log_file).parent().unwrap().to_str().unwrap()).unwrap();
        block_on(push_template("file", config.clone()));
        block_on(push_template("network", config.clone()));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_setup_events() {
        let config = config::Config::new(&utils::get_os());
        fs::create_dir_all(Path::new(&config.log_file).parent().unwrap().to_str().unwrap()).unwrap();
        setup_events("file", config.clone());
        setup_events("network", config.clone());
    }
}
