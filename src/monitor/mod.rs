// Copyright (C) 2021, Achiefs.

#[cfg(test)]
mod tests;

mod setup;

use std::fs;
use std::sync::mpsc;
use log::{info, error, debug};
use std::path::Path;
use notify::event::{EventKind, AccessKind};

use crate::hash;
use crate::config;
use crate::config::*;
use crate::index;
use crate::events;
use crate::events::Event;
use crate::events::MonitorEvent;
use crate::ruleset::*;
use crate::logreader;
use crate::launcher;
use crate::multiwatcher::MultiWatcher;
use crate::utils::{
    get_file_end, 
    get_current_time_millis, 
    get_uuid, 
    get_hostname, 
    get_file_size, 
    get_pid
};

fn setup_events(destination: &str, cfg: Config){
    // Perform actions depending on destination
    info!("Events destination selected: {}", destination);
    match destination {
        config::NETWORK_MODE => {
            debug!("Events folder not created in network mode");
        },
        _ => {
            info!("Events file: {}", cfg.events_file);
            fs::create_dir_all(Path::new(&cfg.events_file).parent().unwrap().to_str().unwrap()).unwrap()
        }
    }
}

// ----------------------------------------------------------------------------

async fn push_template(destination: &str, cfg: Config){
    // Perform actions depending on destination
    match destination {
        config::NETWORK_MODE|config::BOTH_MODE => {
            // On start push template (Include check if events won't be ingested by http)
            index::push_template(cfg).await;
        },
        _ => {
            debug!("Template not pushed in file mode");
        }
    }
}

// ----------------------------------------------------------------------------

// Function that monitorize files in loop
pub async fn monitor(
    tx: mpsc::Sender<Result<notify::Event, notify::Error>>,
    rx: mpsc::Receiver<Result<notify::Event, notify::Error>>, 
    cfg: Config,
    ruleset: Ruleset){

    let destination = cfg.clone().get_events_destination();
    setup_events(destination.as_str(), cfg.clone());

    // Check if we have to push index template
    push_template(destination.as_str(), cfg.clone()).await;

    let mut watcher = MultiWatcher::new(cfg.clone().events_watcher.as_str(), tx);
    setup::set_monitor_watchers(&mut watcher, &cfg);
    setup::set_audit_watchers(&mut watcher, &cfg);
    let mut last_position = get_file_end(logreader::AUDIT_LOG_PATH, 0);

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
                    let current_timestamp = get_current_time_millis();
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
                        while last_position < get_file_end(logreader::AUDIT_LOG_PATH, 0) {
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
                                    id: get_uuid(),
                                    timestamp: current_timestamp,
                                    hostname: get_hostname(),
                                    node: cfg.clone().node,
                                    version: String::from(config::VERSION),
                                    kind,
                                    path: path.clone(),
                                    size: get_file_size(path.clone().to_str().unwrap()),
                                    labels,
                                    operation: events::get_operation(kind),
                                    detailed_operation: events::get_detailed_operation(kind),
                                    checksum: hash::get_checksum( String::from(path.to_str().unwrap()), cfg.clone().events_max_file_checksum, cfg.clone().checksum_algorithm),
                                    fpid: get_pid(),
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