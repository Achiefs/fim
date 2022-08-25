// Copyright (C) 2022, Achiefs.

// Global constants definitions
pub const AUDIT_LOG_PATH: &str = "/var/log/audit/audit.log";

// To manage file reading
use std::io::{BufReader, SeekFrom};
use std::io::prelude::*;
use std::fs::File;
// To manage readed data into collection
use std::collections::HashMap;
// To log the program process
use log::{debug, error};

// Single event data management
use crate::auditevent::Event;
// To manage common functions
use crate::utils;
// To get configuration constants
use crate::config;

// Defined type to simplify syntax
type SHashMap = HashMap<String, String>;

// ----------------------------------------------------------------------------

// Read file to extract last data until the Audit ID changes
pub fn read_log(file: String, config: config::Config, position: u64) -> (Vec<Event>, u64) {
    let mut events: Vec<Event> = Vec::new();
    let log = File::open(file).unwrap();
    let end_position = utils::get_file_end(AUDIT_LOG_PATH);
    let mut buff = BufReader::new(log);
    match buff.seek(SeekFrom::Current(position as i64)) {
        Ok(p) => debug!("Seek audit log file, position: {}, end: {}", p, end_position),
        Err(e) => error!("{}", e)
    };

    // Read from last registered position until the end
    let mut data: Vec<HashMap<String, String>> = Vec::new();
    for result in buff.take(end_position-position).lines() {    
        let line = result.unwrap();
        if data.is_empty() {
            data.push(parse_audit_log(line.clone()));
        }else{
            let line_info = parse_audit_log(line.clone());
            if line_info["msg"] == data.last().unwrap()["msg"] {
                data.push(line_info);
            }
        }
        if data.last().unwrap()["type"] == "PROCTITLE" && data.first().unwrap()["type"] == "SYSCALL" {
            // Skip the event generation of events not monitored by FIM
            let (syscall, cwd, parent, path, proctitle) = extract_fields(data.clone());
            if config.path_in(parent["name"].as_str(), cwd["cwd"].as_str(), config.audit.clone().to_vec()) {
                events.push(Event::new_from(syscall, cwd, parent, path, proctitle, config.clone()));
                data = Vec::new();
            }
        }
    }
    (events, end_position)
}

// ----------------------------------------------------------------------------

pub fn extract_fields(data: Vec<HashMap<String, String>>) -> (SHashMap,
    SHashMap, SHashMap, SHashMap, SHashMap) {
    let syscall = data[0].clone()["syscall"].clone();
    if syscall == "266" || syscall == "86" {
        (data[0].clone(),
        data[1].clone(), 
        if data[3].clone()["type"] == "PATH" {
            data[3].clone()
        }else{ HashMap::new() },
        data[data.len()-2].clone(),
        data[data.len()-1].clone())
    }else{
        (data[0].clone(),
        data[1].clone(), 
        if data[2].clone()["type"] == "PATH" {
            data[2].clone()
        }else{ HashMap::new() },
        data[data.len()-2].clone(),
        data[data.len()-1].clone())
    }
}

// ----------------------------------------------------------------------------

pub fn parse_audit_log(log: String) -> HashMap<String, String> {
    let fields: Vec<&str> = log.split(' ').collect();
    let map: HashMap<String, String> = fields.iter()
        .map(|f| {
            let obj: Vec<&str> = f.split('=').collect();
            (String::from(obj[0]), String::from(obj[1]).replace('\"', ""))
        }).collect();
    map
}

// ----------------------------------------------------------------------------

/*#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::fs::File;
    use std::io::prelude::*;

    fn create_test_file(filename: String) {
        File::create(filename).unwrap().write_all(b"This is a test!").unwrap();
    }

    fn remove_test_file(filename: String) {
        fs::remove_file(filename).unwrap()
    }

    #[test]
    fn test_get_checksum_file() {
        let filename = String::from("test_get_checksum_file");
        create_test_file(filename.clone());
        assert_eq!(get_checksum(filename.clone()), String::from("46512636eeeb22dee0d60f3aba6473b1fb3258dc0c9ed6fbdbf26bed06df796bc70d4c1f6d50ca977b45f35b494e4bd9fb34e55a1576d6d9a3b5e1ab059953ee"));
        remove_test_file(filename.clone());
    }

    #[test]
    fn test_get_checksum_not_exists() {
        assert_ne!(get_checksum(String::from("not_exists")), String::from("This is a test"));
        assert_eq!(get_checksum(String::from("not_exists")), String::from("UNKNOWN"));
    }

    #[test]
    fn test_get_checksum_bad() {
        let filename = String::from("test_get_checksum_bad");
        create_test_file(filename.clone());
        assert_ne!(get_checksum(filename.clone()), String::from("This is a test"));
        remove_test_file(filename.clone());
    }
}*/
