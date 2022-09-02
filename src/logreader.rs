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
    let end_position = utils::get_file_end(&file);
    let log = File::open(file).unwrap();
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
    fields.iter()
        .map(|f| {
            let obj: Vec<&str> = f.split('=').collect();
            (String::from(obj[0]), String::from(obj[1]).replace('\"', ""))
        }).collect::<HashMap<String, String>>()
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_read_log() {
        let config = Config::new("linux");
        let (events, position) = read_log(String::from("test/unit/audit.log"),
            config, 0);
        let event = events[0].clone();

        assert_eq!(events.len(), 1);
        assert_eq!(event.id.len(), 36);
        assert_eq!(event.path, ".");
        assert_eq!(event.operation, "CREATE");
        assert_eq!(event.file, "sedTsutP7");
        assert_eq!(event.timestamp, "1659026449689");
        assert_eq!(event.proctitle, "736564002D6900737C68656C6C6F7C4849217C670066696C6531302E747874");
        assert_eq!(event.cap_fver, "0");
        assert_eq!(event.inode, "1972630");
        assert_eq!(event.cap_fp, "0");
        assert_eq!(event.cap_fe, "0");
        assert_eq!(event.item, "1");
        assert_eq!(event.cap_fi, "0");
        assert_eq!(event.dev, "08:02");
        assert_eq!(event.mode, "0100000");
        assert_eq!(event.cap_frootid, "0");
        assert_eq!(event.ouid, "0");
        assert_eq!(event.parent["rdev"], "00:00");
        assert_eq!(event.parent["cap_fi"], "0");
        assert_eq!(event.parent["item"], "0");
        assert_eq!(event.parent["type"], "PATH");
        assert_eq!(event.parent["inode"], "1966138");
        assert_eq!(event.parent["ouid"], "1000");
        assert_eq!(event.parent["msg"], "audit(1659026449.689:6434):");
        assert_eq!(event.parent["dev"], "08:02");
        assert_eq!(event.parent["cap_fver"], "0");
        assert_eq!(event.parent["nametype"], "PARENT");
        assert_eq!(event.parent["cap_frootid"], "0");
        assert_eq!(event.parent["mode"], "040755");
        assert_eq!(event.parent["ogid"], "0");
        assert_eq!(event.parent["cap_fe"], "0");
        assert_eq!(event.parent["cap_fp"], "0");
        assert_eq!(event.parent["name"], "./");
        assert_eq!(event.cwd, "/tmp/test");
        assert_eq!(event.syscall, "257");
        assert_eq!(event.ppid, "161880");
        assert_eq!(event.comm, "sed");
        assert_eq!(event.fsuid, "0");
        assert_eq!(event.pid, "161937");
        assert_eq!(event.a0, "ffffff9c");
        assert_eq!(event.a1, "556150ee3c00");
        assert_eq!(event.a2, "c2");
        assert_eq!(event.a3, "180");
        assert_eq!(event.arch, "c000003e");
        assert_eq!(event.auid, "1000");
        assert_eq!(event.items, "2");
        assert_eq!(event.gid, "0");
        assert_eq!(event.euid, "0");
        assert_eq!(event.sgid, "0");
        assert_eq!(event.uid, "0");
        assert_eq!(event.tty, "pts0");
        assert_eq!(event.success, "yes");
        assert_eq!(event.exit, "4");
        assert_eq!(event.ses, "807");
        assert_eq!(event.key, "fim");
        assert_eq!(event.suid, "0");
        assert_eq!(event.egid, "0");
        assert_eq!(event.fsgid, "0");
        assert_eq!(event.exe, "/usr/bin/sed");
        if utils::get_os() == "windows" {
            assert_eq!(position, 854);
        }else{
            assert_eq!(position, 850);
        }
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
        let audit_line = String::from("type=CWD msg=audit(1659026449.689:6434): cwd=\"/tmp/test\"");
        let map = parse_audit_log(audit_line);
        assert_eq!(map["type"], "CWD");
        assert_eq!(map["msg"], "audit(1659026449.689:6434):");
        assert_eq!(map["cwd"], "/tmp/test");
        assert_eq!(map.len(), 3);
    }
}
