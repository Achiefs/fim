// Copyright (C) 2021, Achiefs.

// To read and write directories and files
use std::fs;
// To get file system changes
use notify::RecursiveMode;
use std::sync::mpsc;
// To log the program process
use log::{info, error, debug, warn};
// To manage paths
use std::path::Path;
// To manage date and time
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
// To use intersperse()
use itertools::Itertools;
// Event handling
use notify::event::{EventKind, AccessKind};


// Utils functions
use crate::utils;
// Hashing functions
use crate::hash;
// To get config constants
use crate::config;
// Index management functions
use crate::index;
// Single event data management
use crate::event;
// File reading continuously
use crate::logreader;
// integrations checker
use crate::launcher;
use crate::multiwatcher::MultiWatcher;

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

async fn push_template(destination: &str){
    // Perform actions depending on destination
    match destination {
        config::NETWORK_MODE|config::BOTH_MODE => {
            // On start push template (Include check if events won't be ingested by http)
            index::push_template().await;
        },
        _ => {
            debug!("Template not pushed in file mode");
        }
    }
}

// ----------------------------------------------------------------------------

fn clean_audit_rules(config: &config::Config){
    for element in config.audit.clone() {
        let path = element["path"].as_str().unwrap();
        let rule = utils::get_audit_rule_permissions(element["rule"].as_str());
        utils::run_auditctl(&["-W", path, "-k", "fim", "-p", &rule]);
    }
    std::process::exit(0);
}

// ----------------------------------------------------------------------------

// Function that monitorize files in loop
pub async fn monitor(tx: mpsc::Sender<Result<notify::Event, notify::Error>>,
    rx: mpsc::Receiver<Result<notify::Event, notify::Error>>){

    let config = unsafe { super::GCONFIG.clone().unwrap() };
    let destination = config.get_events_destination();
    setup_events(destination.as_str(), config.clone());

    // Check if we have to push index template
    push_template(destination.as_str()).await;

    let mut watcher = MultiWatcher::new(config.events_watcher.as_str(), tx);
    
    // Iterating over monitor paths and set watcher on each folder to watch.
    if ! config.monitor.is_empty() {
        for element in config.monitor.clone() {
            let path = element["path"].as_str().unwrap();
            info!("Monitoring path: {}", path);

            match element["ignore"].as_vec() {
                Some(ig) => {
                    let ignore_vec  = ig.iter().map(|e| e.as_str().unwrap() );
                    let ignore_list : String = Itertools::intersperse(ignore_vec, ", ").collect();
                    info!("Ignoring files with: {} inside {}", ignore_list, path);
                },
                None => debug!("Ignore for '{}' not set", path)
            };

            match element["allowed"].as_vec(){
                Some(allowed) => {
                    let allowed_vec = allowed.iter().map(|e| e.as_str().unwrap());
                    let allowed_list : String = Itertools::intersperse(allowed_vec, ", ").collect();
                    info!("Only files with '{}' will trigger event inside '{}'", allowed_list, path)
                },
                None => debug!("Monitoring all files under this path '{}'", path)
            }

            match watcher.watch(Path::new(path), RecursiveMode::Recursive) {
                Ok(_d) => debug!("Monitoring path: {}", path),
                Err(e) => warn!("Could not monitor given path '{}', description: {}", path, e)
            };
        }
    }
    let mut last_position = 0;
    if ! config.audit.is_empty() && utils::get_os() == "linux" && utils::check_auditd() {
        for element in config.audit.clone() {
            let path = element["path"].as_str().unwrap();
            let rule = utils::get_audit_rule_permissions(element["rule"].as_str());
            utils::run_auditctl(&["-w", path, "-k", "fim", "-p", &rule]);
            info!("Checking audit path: {}", path);

            match element["allowed"].as_vec() {
                Some(allowed) => {
                    let allowed_vec  = allowed.iter().map(|e| e.as_str().unwrap() );
                    let allowed_list : String = Itertools::intersperse(allowed_vec, ", ").collect();
                    info!("Only files with '{}' will trigger event inside '{}'", allowed_list, path)
                },
                None => debug!("Monitoring all files under this path '{}'", path)
            };

            match element["ignore"].as_vec() {
                Some(ig) => {
                    let ignore_list_vec  = ig.iter().map(|e| e.as_str().unwrap() );
                    let ignore_list : String = Itertools::intersperse(ignore_list_vec, ", ").collect();
                    info!("Ignoring files with: {} inside {}", ignore_list, path);
                },
                None => info!("Ignore for '{}' not set", path)
            };
        }
        // Detect if Audit file is moved or renamed (rotation)
        watcher.watch(Path::new(logreader::AUDIT_PATH), RecursiveMode::NonRecursive).unwrap();
        last_position = utils::get_file_end(logreader::AUDIT_LOG_PATH, 0);
       
        // Remove auditd rules introduced by FIM
        // Setting ctrl + C handler
        let cloned_config = config.clone();
        match ctrlc::set_handler(move || clean_audit_rules(&cloned_config)) {
            Ok(_v) => debug!("Handler Ctrl-C set and listening"),
            Err(e) => error!("Error setting Ctrl-C handler, the process will continue without signal handling, Error: '{}'", e)
        }
    }


    // Main loop, receive any produced event and write it into the events log.
    loop {
        for message in &rx {
            match message {
                Ok(event) => {
                    // Get the event path and filename
                    debug!("Event received: {:?}", event);

                    let plain_path: &str = match event.paths.len() {
                        0 => "UNKNOWN",
                        _ => event.paths[0].to_str().unwrap()
                    };
                    if plain_path == "DISCONNECT" {
                        info!("Received exit signal, exiting...");
                        break;
                    }

                    let event_path = Path::new(plain_path);
                    let event_filename = event_path.file_name().unwrap();

                    let current_date = OffsetDateTime::now_utc();
                    let index_name = format!("fim-{}-{}-{}", current_date.year(), current_date.month() as u8, current_date.day() );
                    let current_timestamp = format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis());
                    let kind: notify::EventKind = event.kind;
                    let path = event.paths[0].clone();

                    // Reset reading position due to log rotation
                    if plain_path == logreader::AUDIT_LOG_PATH && kind == EventKind::Access(AccessKind::Any) {
                        last_position = 0;
                    }

                    // If the event comes from audit.log
                    if plain_path == logreader::AUDIT_LOG_PATH {
                        // Getting events from audit.log
                        let mut events = Vec::new();
                        let (log_event, position) = logreader::read_log(String::from(logreader::AUDIT_LOG_PATH), config.clone(), last_position, 0);
                        if log_event.id != "0" { events.push(log_event); };
                        let mut ctr = 0;
                        last_position = position;
                        while last_position < utils::get_file_end(logreader::AUDIT_LOG_PATH, 0) {
                            debug!("Reading events, iteration: {}", ctr);
                            let original_position = last_position;
                            ctr += 1;
                            let (evt, pos) = logreader::read_log(String::from(logreader::AUDIT_LOG_PATH), config.clone(), last_position, ctr);
                            if evt.id != "0" {
                                events.push(evt);
                                ctr = 0;
                            };
                            last_position = pos;
                            if original_position == pos {
                                ctr = 0;
                            }
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
                                            config.audit.clone())  &&
                                        config.match_allowed(index,
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
                                event_filename.to_str().unwrap(), config.monitor.clone()) &&
                                config.match_allowed(index, event_filename.to_str().unwrap(), config.monitor.clone()) {
                                let event = event::Event {
                                    id: utils::get_uuid(),
                                    timestamp: current_timestamp,
                                    hostname: utils::get_hostname(),
                                    node: config.node.clone(),
                                    version: String::from(config::VERSION),
                                    kind,
                                    path: path.clone(),
                                    size: utils::get_file_size(path.clone().to_str().unwrap()),
                                    labels,
                                    operation: event::get_operation(kind),
                                    detailed_operation: event::get_detailed_operation(kind),
                                    checksum: hash::get_checksum( String::from(path.to_str().unwrap()), config.events_max_file_checksum ),
                                    fpid: utils::get_pid(),
                                    system: config.system.clone()
                                };

                                debug!("Event processed: {:?}", event);
                                event.process(destination.clone().as_str(), index_name.clone(), config.clone()).await;
                                launcher::check_integrations(event.clone(), config.clone());
                            }else{
                                debug!("Event ignored not stored in alerts");
                            }
                        }else{
                            debug!("Event not matched monitor");
                        }
                    }
                },
                Err(e) => {
                    error!("Watch for event failed, error: {:?}", e);
                }
            }
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
    fn test_push_template() {
        let config = config::Config::new(&utils::get_os(), None);
        fs::create_dir_all(Path::new(&config.log_file).parent().unwrap().to_str().unwrap()).unwrap();
        block_on(push_template("file"));
        block_on(push_template("network"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_setup_events() {
        let config = config::Config::new(&utils::get_os(), None);
        fs::create_dir_all(Path::new(&config.log_file).parent().unwrap().to_str().unwrap()).unwrap();
        setup_events("file", config.clone());
        setup_events("network", config.clone());
    }
}
