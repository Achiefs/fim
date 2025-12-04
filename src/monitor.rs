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
// To use intersperse()
use itertools::Itertools;
// Event handling
use notify::event::{EventKind, AccessKind};


// Utils functions
use crate::utils;
// Hashing functions
use crate::hash;
use crate::appconfig;
use crate::appconfig::*;
// Index management functions
use crate::index;
// Event data management
use crate::events;
use crate::events::Event;
use crate::events::MonitorEvent;
use crate::ruleset::*;
// File reading continuously
use crate::logreader;
// integrations checker
use crate::launcher;
use crate::multiwatcher::MultiWatcher;

// ----------------------------------------------------------------------------

fn setup_events(destination: &str, cfg: AppConfig){
    // Perform actions depending on destination
    info!("Events destination selected: {}", destination);
    match destination {
        appconfig::NETWORK_MODE => {
            debug!("Events folder not created in network mode");
        },
        _ => {
            info!("Events file: {}", cfg.events_file);
            fs::create_dir_all(Path::new(&cfg.events_file).parent().unwrap().to_str().unwrap()).unwrap()
        }
    }
}

// ----------------------------------------------------------------------------

async fn push_template(destination: &str, cfg: AppConfig){
    // Perform actions depending on destination
    match destination {
        appconfig::NETWORK_MODE|appconfig::BOTH_MODE => {
            // On start push template (Include check if events won't be ingested by http)
            index::push_template(cfg).await;
        },
        _ => {
            debug!("Template not pushed in file mode");
        }
    }
}

// ----------------------------------------------------------------------------

fn clean_audit_rules(cfg: &AppConfig){
    for element in cfg.audit.clone() {
        let path = element["path"].as_str().unwrap();
        let rule = utils::get_audit_rule_permissions(element["rule"].as_str());
        utils::run_auditctl(&["-W", path, "-k", "fim", "-p", &rule]);
    }
    std::process::exit(0);
}

// ----------------------------------------------------------------------------

// Function that monitorize files in loop
pub async fn monitor(
    tx: mpsc::Sender<Result<notify::Event, notify::Error>>,
    rx: mpsc::Receiver<Result<notify::Event, notify::Error>>, 
    cfg: AppConfig,
    ruleset: Ruleset){

    let destination = cfg.clone().get_events_destination();
    setup_events(destination.as_str(), cfg.clone());

    // Check if we have to push index template
    push_template(destination.as_str(), cfg.clone()).await;

    let mut watcher = MultiWatcher::new(cfg.clone().events_watcher.as_str(), tx);
    
    // Iterating over monitor paths and set watcher on each folder to watch.
    if ! cfg.clone().monitor.is_empty() {
        for element in cfg.clone().monitor {
            let path = element["path"].as_str().unwrap();
            info!("Monitoring path: {}", path);

            match element["ignore"].as_vec() {
                Some(ig) => {
                    let ignore_vec  = ig.iter().map(|e| e.as_str().unwrap() );
                    let ignore_list : String = Itertools::intersperse(ignore_vec, ", ").collect();
                    info!("Ignoring files with: '{}' inside '{}' path.", ignore_list, path);
                },
                None => debug!("Ignore for '{}' path not set.", path)
            };

            match element["exclude"].as_vec() {
                Some(ex) => {
                    let exclude_vec  = ex.iter().map(|e| e.as_str().unwrap() );
                    let exclude_list : String = Itertools::intersperse(exclude_vec, ", ").collect();
                    info!("Excluding folders: '{}' inside '{}' path.", exclude_list, path);
                },
                None => debug!("Exclude folders for '{}' path not set.", path)
            };

            match element["allowed"].as_vec(){
                Some(allowed) => {
                    let allowed_vec = allowed.iter().map(|e| e.as_str().unwrap());
                    let allowed_list : String = Itertools::intersperse(allowed_vec, ", ").collect();
                    info!("Only files with '{}' will trigger event inside '{}' path.", allowed_list, path)
                },
                None => debug!("Monitoring files under '{}' path.", path)
            }

            match watcher.watch(Path::new(path), RecursiveMode::Recursive) {
                Ok(_d) => debug!("Monitoring '{}' path.", path),
                Err(e) => warn!("Could not monitor given path '{}', description: {}", path, e)
            };
        }
    }
    let mut last_position = 0;
    if ! cfg.clone().audit.is_empty() && utils::get_os() == "linux" && utils::check_auditd() {
        for element in cfg.clone().audit {
            let path = element["path"].as_str().unwrap();
            let rule = utils::get_audit_rule_permissions(element["rule"].as_str());
            utils::run_auditctl(&["-w", path, "-k", "fim", "-p", &rule]);
            info!("Checking audit path: {}", path);

            match element["allowed"].as_vec() {
                Some(allowed) => {
                    let allowed_vec  = allowed.iter().map(|e| e.as_str().unwrap() );
                    let allowed_list : String = Itertools::intersperse(allowed_vec, ", ").collect();
                    info!("Only files with '{}' will trigger event inside '{}' path.", allowed_list, path)
                },
                None => debug!("Monitoring files under '{}' path.", path)
            };

            match element["exclude"].as_vec() {
                Some(ex) => {
                    let exclude_vec  = ex.iter().map(|e| e.as_str().unwrap() );
                    let exclude_list : String = Itertools::intersperse(exclude_vec, ", ").collect();
                    info!("Excluding folders: '{}' inside '{}' path.", exclude_list, path);
                },
                None => debug!("Exclude folders for '{}' path not set.", path)
            };

            match element["ignore"].as_vec() {
                Some(ig) => {
                    let ignore_list_vec  = ig.iter().map(|e| e.as_str().unwrap() );
                    let ignore_list : String = Itertools::intersperse(ignore_list_vec, ", ").collect();
                    info!("Ignoring files with: '{}' inside '{}' path", ignore_list, path);
                },
                None => info!("Ignore for '{}' pat not set", path)
            };
        }
        // Detect if Audit file is moved or renamed (rotation)
        watcher.watch(Path::new(logreader::AUDIT_PATH), RecursiveMode::NonRecursive).unwrap();
        last_position = utils::get_file_end(logreader::AUDIT_LOG_PATH, 0);
       
        // Remove auditd rules introduced by FIM
        // Setting ctrl + C handler
        let cloned_cfg = cfg.clone();
        match ctrlc::set_handler(move || clean_audit_rules(&cloned_cfg)) {
            Ok(_v) => debug!("Handler Ctrl-C set and listening"),
            Err(e) => error!("Error setting Ctrl-C handler, the process will continue without signal handling, Error: '{}'", e)
        }
    }


    // Main loop, receive any produced event and write it into the events log.
    'processor: loop {
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
                        break 'processor;
                    }

                    let event_path = Path::new(plain_path);
                    let event_filename = event_path.file_name().unwrap();
                    let current_timestamp = utils::get_current_time_millis();
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
                        let (log_event, position) = logreader::read_log(String::from(logreader::AUDIT_LOG_PATH), cfg.clone(), last_position, 0);
                        if log_event.get_audit_event().id != "0" { events.push(log_event); };
                        let mut ctr = 0;
                        last_position = position;
                        while last_position < utils::get_file_end(logreader::AUDIT_LOG_PATH, 0) {
                            debug!("Reading events, iteration: {}", ctr);
                            let original_position = last_position;
                            ctr += 1;
                            let (evt, pos) = logreader::read_log(String::from(logreader::AUDIT_LOG_PATH), cfg.clone(), last_position, ctr);
                            if evt.get_audit_event().id != "0" {
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
                            if ! audit_event.get_audit_event().is_empty() {
                                // Getting the position of event in config (match ignore and labels)
                                let index = cfg.get_index(audit_event.get_audit_event().path.as_str(),
                                    audit_event.get_audit_event().cwd.as_str(),
                                    cfg.clone().audit.to_vec());

                                if index != usize::MAX {
                                    // If event contains ignored string ignore event
                                    if ! cfg.match_ignore(index, audit_event.get_audit_event().file.as_str(), cfg.clone().audit)  &&
                                        ! cfg.match_exclude(index, audit_event.get_audit_event().path.as_str(), cfg.clone().audit) &&
                                        cfg.match_allowed(index, audit_event.get_audit_event().file.as_str(), cfg.clone().audit) {
                                        audit_event.process(cfg.clone(), ruleset.clone()).await;
                                    }else{
                                        debug!("Event ignored/excluded not stored in alerts");
                                    }
                                }else{
                                    debug!("Event not monitored by FIM");
                                }
                            }
                            debug!("Event processed: {:?}", audit_event.clone());
                        }
                    }else {
                        let index = cfg.get_index(event_path.to_str().unwrap(), "", cfg.clone().monitor.to_vec());
                        let parent = match event_path.is_dir() {
                            true => event_path.to_str().unwrap(),
                            false => event_path.parent().unwrap().to_str().unwrap()
                        };
                        if index != usize::MAX {
                            let labels = cfg.get_labels(index, cfg.clone().monitor);
                            if ! cfg.match_ignore(index, event_filename.to_str().unwrap(), cfg.clone().monitor) &&
                                ! cfg.match_exclude(index, parent, cfg.clone().monitor) &&
                                cfg.match_allowed(index, event_filename.to_str().unwrap(), cfg.clone().monitor) {
                                let event = Event::Monitor(MonitorEvent {
                                    id: utils::get_uuid(),
                                    timestamp: current_timestamp,
                                    hostname: utils::get_hostname(),
                                    node: cfg.clone().node,
                                    version: String::from(appconfig::VERSION),
                                    kind,
                                    path: path.clone(),
                                    size: utils::get_file_size(path.clone().to_str().unwrap()),
                                    labels,
                                    operation: events::get_operation(kind),
                                    detailed_operation: events::get_detailed_operation(kind),
                                    checksum: hash::get_checksum( String::from(path.to_str().unwrap()), cfg.clone().events_max_file_checksum, cfg.clone().checksum_algorithm),
                                    fpid: utils::get_pid(),
                                    system: cfg.clone().system
                                });

                                debug!("Event processed: {:?}", event);
                                event.process(cfg.clone(), ruleset.clone()).await;
                                launcher::check_integrations(event.clone(), cfg.clone());
                            }else{
                                debug!("Event ignored/excluded not stored in alerts");
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
        let cfg = AppConfig::new(&utils::get_os(), None);
        fs::create_dir_all(Path::new(&cfg.log_file).parent().unwrap().to_str().unwrap()).unwrap();
        block_on(push_template("file", cfg.clone()));
        block_on(push_template("network", cfg.clone()));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_setup_events() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        fs::create_dir_all(Path::new(&cfg.log_file).parent().unwrap().to_str().unwrap()).unwrap();
        setup_events("file", cfg.clone());
        setup_events("network", cfg.clone());
    }
}
