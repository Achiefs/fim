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
                events.push(Event::from(syscall, cwd, parent, path, proctitle, config.clone()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_log() {

    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_extract_fields() {
        // Parent given check
        let mut data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("syscall"), String::from("100")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("PATH")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        let (a, b, c, d, e) = extract_fields(data);
        assert_eq!(a["syscall"], String::from("100"));
        assert_eq!(b["key"], String::from("expected"));
        assert_eq!(c["type"], String::from("PATH"));
        assert_eq!(d["key"], String::from("expected"));
        assert_eq!(e["key"], String::from("expected"));

        // Testing parent not given option
        data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("syscall"), String::from("100")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("NOT_PATH")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        let (a, b, c, d, e) = extract_fields(data);
        assert_eq!(a["syscall"], String::from("100"));
        assert_eq!(b["key"], String::from("expected"));
        assert_eq!(c, HashMap::new());
        assert_eq!(d["key"], String::from("expected"));
        assert_eq!(e["key"], String::from("expected"));

        // Testing specific syscall with parent given
        data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("syscall"), String::from("266")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("NOT_PATH")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("PATH")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        let (a, b, c, d, e) = extract_fields(data);
        assert_eq!(a["syscall"], String::from("266"));
        assert_eq!(b["key"], String::from("expected"));
        assert_eq!(c["type"], String::from("PATH"));
        assert_eq!(d["key"], String::from("expected"));
        assert_eq!(e["key"], String::from("expected"));

        // Testing specific syscall with parent not given
        data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("syscall"), String::from("266")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("NOT_PATH")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("NOT_PATHPATH")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        let (a, b, c, d, e) = extract_fields(data);
        assert_eq!(a["syscall"], String::from("266"));
        assert_eq!(b["key"], String::from("expected"));
        assert_eq!(c, HashMap::new());
        assert_eq!(d["key"], String::from("expected"));
        assert_eq!(e["key"], String::from("expected"));

    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_audit_log() {

    }
}
