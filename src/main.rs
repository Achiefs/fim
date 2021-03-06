// To read and write files
use std::fs::OpenOptions;
// To get file system changes
use notify::{RecommendedWatcher, Watcher, RecursiveMode};
use std::sync::mpsc::channel;
// To log the program process
use log::*;
use simplelog::{WriteLogger, Config};

// To load configuration functions
mod config;
// To load events handling
mod events;

// Main function where the magic happens
fn main() {
    let config_path = "config.yml";
    let config = config::read_config(config_path);
    let paths = &config[0]["monitor"];
    //let delay:u64 = config[0]["watcher"]["delay"].as_i64().unwrap().try_into().unwrap();
    let log_file = &config[0]["log"]["output"]["file"].as_str().unwrap();
    let log_level = &config[0]["log"]["output"]["level"].as_str().unwrap();
    let events_file = &config[0]["log"]["events"]["file"].as_str().unwrap();
    let events_format = &config[0]["log"]["events"]["format"].as_str().unwrap();
    
    println!("Reading config...");
    println!("Config file: {}", config_path);
    println!("Log file: {}", log_file);
    println!("Events file: {}", events_file);
    println!("Log level: {}", log_level);

    // Create output log to write app logs.
    WriteLogger::init(
        config::get_log_level(log_level.to_string(), log_file.to_string()),
        Config::default(),
        OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(log_file)
            .expect("Unable to open log file")
    ).unwrap();
    
    // Iterating over monitor paths and set each watcher to watch.
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new_raw(tx).unwrap();
    for p in paths.as_vec().unwrap() {
        let path = p.as_str().unwrap();
        info!("Monitoring path: {}", path);
        watcher.watch(path, RecursiveMode::Recursive).unwrap();
    }

    // Main loop, receive any produced event and write into the events log.
    loop {
        match rx.recv() {
            Ok(event) => {
                debug!("Event registered: {:?}", event);
                events::log_event(events_file, event, events_format)
            },
            Err(e) => error!("Watch error: {:?}", e),
        }
    }
}
