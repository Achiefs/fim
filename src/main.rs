// To read and write files
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::io::Write;
// To parse files in yaml format
use yaml_rust::yaml::{Yaml, YamlLoader};
// To get file checksums
//use crypto::digest::Digest;
//use crypto::sha3::Sha3;
// To get file system changes
use notify::{RecommendedWatcher, Watcher, RecursiveMode, RawEvent};
use notify::op::Op;
use std::sync::mpsc::channel;
// To log the program process
use log::*;
use simplelog::{WriteLogger, LevelFilter, Config};


// To read the configuration Yaml file
fn read_config(file: &str) -> Vec<Yaml> {
    let mut file = File::open(file).expect("Unable to open file");
    let mut contents = String::new();

    file.read_to_string(&mut contents)
        .expect("Unable to read file");
    YamlLoader::load_from_str(&contents).unwrap()
}


// To calculate file content hash in sha512 format (SHA3 implementation)
/*fn get_checksum(file: &str) -> String {
    let mut hasher = Sha3::sha3_512();
    let data = std::fs::read_to_string(file).unwrap();
    hasher.input_str(&data);
    hasher.result_str()
}*/

// Function to write the received events to file
fn log_event(file: &str, event: RawEvent){
    let mut log = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(file)
        .expect("Unable to open events log file.");

    let path = event.path.expect("Event path");
    match event.op.unwrap() {
        Op::CREATE => writeln!(log, "File '{}' created", path.to_str().unwrap()).expect("Error writing event"),
        Op::WRITE => writeln!(log, "File '{}' written", path.to_str().unwrap()).expect("Error writing event"),
        Op::REMOVE => writeln!(log, "File '{}' removed", path.to_str().unwrap()).expect("Error writing event"),
        Op::RENAME => writeln!(log, "File '{}' renamed", path.to_str().unwrap()).expect("Error writing event"),
        Op::CHMOD => writeln!(log, "File '{}' modified", path.to_str().unwrap()).expect("Error writing event"),
        Op::CLOSE_WRITE => writeln!(log, "File '{}' closed", path.to_str().unwrap()).expect("Error writing event"),
        Op::RESCAN => writeln!(log, "Directory '{}' need to be rescaned", path.to_str().unwrap()).expect("Error writing event"),
        _ => error!("Event Op not Handled"),
    }
}


// Main function where the magic happens
fn main() {
    let config_path = "src/config.yml";
    let config = read_config(config_path);
    let paths = &config[0]["monitor"];
    //let delay:u64 = config[0]["watcher"]["delay"].as_i64().unwrap().try_into().unwrap();
    let log_file = &config[0]["log"]["output"].as_str().unwrap();
    let events_file = &config[0]["log"]["events"].as_str().unwrap();
    
    // Create output log to write app logs.
    WriteLogger::init(
        LevelFilter::Debug,
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
