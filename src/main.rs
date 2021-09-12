// To read and write files
use std::fs::OpenOptions;
// To get file system changes
use notify::{RecommendedWatcher, Watcher, RecursiveMode};
use std::sync::mpsc::channel;
// To log the program process
use log::*;
use simplelog::{WriteLogger, Config};
// To manage paths
//use std::path::Path;
mod monitor;
use monitor::Monitor;

// To load configuration functions
mod config;
// To load events handling
mod events;

// Main function where the magic happens
fn main() {
    println!("Reading config...");

    let config_path = "config.yml";
    let config = config::read_config(config_path);
    let monitor = &config[0]["monitor"];
    //println!("{}", monitor.as_str().unwrap());
    let log_file = &config[0]["log"]["output"]["file"].as_str().unwrap();
    let log_level = &config[0]["log"]["output"]["level"].as_str().unwrap();
    let events_file = &config[0]["log"]["events"]["file"].as_str().unwrap();
    let events_format = &config[0]["log"]["events"]["format"].as_str().unwrap();
    let ignores = &config[0]["ignore"];
    
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
    for m in monitor.as_vec().unwrap() {
        
        println!( "{}", &m["path"].as_str().unwrap() );
        println!( "{}", &m["ignore"].as_str().unwrap() );
        let mon = Monitor {
            path: String::from(m["path"].as_str().unwrap()),
            ignore: String::from(m["ignore"].as_str().unwrap())
        };
        
        info!("Monitoring path: {}", mon.path);
        info!("Ignoring files with: {}", mon.ignore);
        watcher.watch(mon.path, RecursiveMode::Recursive).unwrap();
    }

    // Main loop, receive any produced event and write into the events log.
    loop {
        match rx.recv() {
            Ok(event) => {
                debug!("Event registered: {:?}", event);
                /*for ignore in ignores.as_vec().unwrap() {
                    let ignore_path = Path::new(ignore.as_str().unwrap());
                    let ignore_parent_path = ignore_path.parent().unwrap().to_str().unwrap();
                    let event_path = Path::new(event.path.as_ref().unwrap().to_str().unwrap());
                    let event_parent_path = event_path.parent().unwrap().to_str().unwrap();
                    println!("Event path: {}", event_path.to_str().unwrap());
                    println!("Ignore path: {}", ignore_path.to_str().unwrap());
                    println!("Event parent path: {}", event_parent_path);
                    println!("Ignore parent path: {}", ignore_parent_path);

                    //if event_parent_path != ignore_parent_path

                    //match parent {
                    //    event.path => println!('EQUALS');
                    //}
                    //println!("Character: {}",  );
                }*/
                events::log_event(events_file, event, events_format)
            },
            Err(e) => error!("Watch error: {:?}", e),
        }
    }
}
