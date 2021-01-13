// To read and write files
use std::fs::OpenOptions;
use std::io::Write;
use std::io::{Error, ErrorKind};
use std::result::Result;
// To get file checksums
use crypto::digest::Digest;
use crypto::sha3::Sha3;
// To get file system changes
use notify::{RecommendedWatcher, Watcher, RecursiveMode, RawEvent};
use notify::op::Op;
use std::sync::mpsc::channel;
// To log the program process
use log::*;
use simplelog::{WriteLogger, Config};
// To get Date and Time
use chrono::Utc;
// To get own process ID
use std::process;
// To load configuration functions
mod config;


// To calculate file content hash in sha512 format (SHA3 implementation)
fn get_checksum(file: &str) -> Result<String, Error> {
    let mut hasher = Sha3::sha3_512();
    match std::fs::read_to_string(file) {
        Ok(data) => {
            hasher.input_str(&data);
            return Ok(hasher.result_str())
        },
        Err(e) => return Err(e),
    }
}

// To get Syslog format "Jan 01 01:01:01 HOSTNAME APPNAME[PID]:"
fn get_syslog_format() -> String {
    let datetime = Utc::now().format("%b %d %H:%M:%S");
    let hostname = gethostname::gethostname().into_string().unwrap();
    format!("{} {} FIM[{}]: ", datetime, hostname, process::id())
}

// Function to write the received events to file
fn log_event(file: &str, event: RawEvent){
    let mut log = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(file)
        .expect("Unable to open events log file.");

    let path = event.path.expect("Event path");
    let syslog_format = get_syslog_format();
    match event.op.unwrap() {
        Op::CREATE => {
            let checksum = get_checksum(path.to_str().unwrap()).unwrap();
            writeln!(log, "{}File '{}' created, checksum {}",
                syslog_format, path.to_str().unwrap(), checksum
            ).expect("Error writing event");
        }
        Op::WRITE => {
            let checksum = get_checksum(path.to_str().unwrap()).unwrap();
            writeln!(log, "{}File '{}' written, new checksum {}",
                syslog_format, path.to_str().unwrap(), checksum
            ).expect("Error writing event");
        }
        Op::RENAME => {
            let checksum = match get_checksum(path.to_str().unwrap()) {
                Ok(data) => data,
                Err(e) => {
                    match e.kind() {
                        ErrorKind::NotFound => println!("File Not found error ignoring..."),
                        _ => panic!("Not handled error on get_checksum function."),
                    };
                    String::from("IGNORED")
                }
            };
            writeln!(log, "{}File '{}' renamed, checksum {}", syslog_format,
                path.to_str().unwrap(), checksum).expect("Error writing event");
        }
        Op::REMOVE => writeln!(log, "{}File '{}' removed", syslog_format,
            path.to_str().unwrap()).expect("Error writing event"),
        Op::CHMOD => writeln!(log, "{}File '{}' permissions modified", syslog_format,
            path.to_str().unwrap()).expect("Error writing event"),
        Op::CLOSE_WRITE => writeln!(log, "{}File '{}' closed", syslog_format,
            path.to_str().unwrap()).expect("Error writing event"),
        Op::RESCAN => writeln!(log, "{}Directory '{}' need to be rescaned", syslog_format,
            path.to_str().unwrap()).expect("Error writing event"),
        _ => error!("Event Op not Handled"),
    }
}


// Main function where the magic happens
fn main() {
    let config_path = "config.yml";
    let config = config::read_config(config_path);
    let paths = &config[0]["monitor"];
    //let delay:u64 = config[0]["watcher"]["delay"].as_i64().unwrap().try_into().unwrap();
    let log_file = &config[0]["log"]["output"].as_str().unwrap();
    let events_file = &config[0]["log"]["events"].as_str().unwrap();
    let log_level = &config[0]["log"]["level"].as_str().unwrap();
    
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
                log_event(events_file, event)
            },
            Err(e) => error!("Watch error: {:?}", e),
        }
    }
}
