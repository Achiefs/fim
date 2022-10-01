// Copyright (C) 2022, Achiefs.

// Global constants definitions
pub const AUDIT_PATH: &str = "/var/log/audit";
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
pub fn read_log(file: String, config: config::Config, position: u64, itx: u64) -> (Event, u64) {
    let mut event: Event = Event::new();
    let mut current_position = position;
    let end_position = utils::get_file_end(&file);
    let log = File::open(file).unwrap();
    let mut buff = BufReader::new(log);
    match buff.seek(SeekFrom::Current(position as i64)) {
        Ok(p) => debug!("Seek audit log file, position: {}, end: {}", p, end_position),
        Err(e) => error!("{}", e)
    };

    // Read from last registered position until we get event or the end
    let mut data: Vec<HashMap<String, String>> = Vec::new();
    let mut line = String::new();
    while current_position < end_position {
        let start_position = current_position;
        debug!("Reading start: {}", current_position);
        let bytes_read = match buff.read_line(&mut line){
            Ok(bytes) => {
                debug!("Read string: '{}', bytes read: {}", line, bytes);
                bytes as u64
            },
            Err(e) => {
                error!("Reading string line, position: {}, error: {}", current_position, e);
                0
            }
        };
        current_position = current_position + bytes_read;
        debug!("End read position: {}", current_position);
        if data.is_empty() {
            data.push(parse_audit_log(line.clone()));
            // It seems that doesn't exist a case where I read two lines with
            // The same MSG and both of them aren't part of event...
        }else{
            let line_info = parse_audit_log(line.clone());
            if line_info.contains_key("msg") &&
                data.last().unwrap().contains_key("msg") &&
                line_info["msg"] == data.last().unwrap()["msg"] {
                data.push(line_info);
            // If the timestamp is different then we get a complete event
            }else{
                current_position = start_position;
                break;
            }
        }
        line = String::new();
    }
    if !data.is_empty() {
        if data.last().unwrap().contains_key("type") &&
            data.first().unwrap().contains_key("type") &&
            data.last().unwrap()["type"] == "PROCTITLE" &&
            data.first().unwrap()["type"] == "SYSCALL" {
            let (syscall, cwd, proctitle, paths) = extract_fields(data.clone());
            let audit_vec = config.audit.clone().to_vec();

            // Skip the event generation of paths not monitored by FIM
            if paths.iter().any(|p| {
                config.path_in(p["name"].as_str(), cwd["cwd"].as_str(), audit_vec.clone()) ||
                config.path_in(cwd["cwd"].as_str(), "", audit_vec.clone())
            }) {
                event = Event::from(syscall, cwd, proctitle, paths, config.clone());
            }
        }else if data.iter().any(|line| {
            line["type"] == "SYSCALL" ||
            line["type"] == "CWD" ||
            line["type"] == "PATH" ||
            line["type"] == "PROCTITLE"
        }) {
            if itx < 3{
                current_position = position;
            }
        }
    }
    (event, current_position)
}

// ----------------------------------------------------------------------------

pub fn extract_fields(data: Vec<HashMap<String, String>>) -> (SHashMap,
    SHashMap, SHashMap, Vec<SHashMap>) {
    let mut paths: Vec<SHashMap> = Vec::new();
    let mut syscall = SHashMap::new();
    let mut cwd = SHashMap::from([ (String::from("cwd"), String::from("/UNKNOWN")) ]);
    let mut proctitle = SHashMap::new();

    data.iter().for_each(|v| {
        match v["type"].as_str() {
            "SYSCALL" => syscall = v.clone(),
            "PATH" => paths.push(v.clone()),
            "CWD" => cwd = v.clone(),
            "PROCTITLE" => proctitle = v.clone(),
            _ => error!("Unidentified Audit field")
        }
    });
    (syscall, cwd, proctitle, paths)
}

// ----------------------------------------------------------------------------

pub fn parse_audit_log(log: String) -> HashMap<String, String> {
    let fields: Vec<&str> = log.split(' ').collect();
    fields.iter()
        .map(|f| {
            let obj: Vec<&str> = f.split('=').collect();
            if obj.len() == 2 {
                (String::from(obj[0]), String::from(obj[1]).replace('\"', "").replace("\n", ""))
            }else{
                (String::from(obj[0]), String::from("UNKNOWN"))
            }
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
        let (event, position) = read_log(String::from("test/unit/audit.log"),
            config, 0, 0);

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
        /*assert_eq!(event.parent["rdev"], "00:00");
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
        assert_eq!(event.parent["name"], "./");*/
        assert_eq!(event.cwd, "/tmp");
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
            assert_eq!(position, 849);
        }else{
            assert_eq!(position, 845);
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_extract_fields() {
        // Parent given check
        /*let mut data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("syscall"), String::from("100")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("PATH")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        let (a, b, c, d) = extract_fields(data);
        assert_eq!(a["syscall"], String::from("100"));
        assert_eq!(b["key"], String::from("expected"));
        //assert_eq!(c["type"], String::from("PATH"));
        //assert_eq!(d["key"], String::from("expected"));
        //assert_eq!(e["key"], String::from("expected"));

        // Testing parent not given option
        data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("syscall"), String::from("100")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("NOT_PATH")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        let (a, b, c, d) = extract_fields(data);
        assert_eq!(a["syscall"], String::from("100"));
        assert_eq!(b["key"], String::from("expected"));
        //assert_eq!(c, HashMap::new());
        //assert_eq!(d["key"], String::from("expected"));
        //assert_eq!(e["key"], String::from("expected"));

        // Testing specific syscall with parent given
        data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("syscall"), String::from("266")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("NOT_PATH")) ]));
        //data.push(HashMap::from([ (String::from("type"), String::from("PATH")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        let (a, b, c, d) = extract_fields(data);
        assert_eq!(a["syscall"], String::from("266"));
        assert_eq!(b["key"], String::from("expected"));
        //assert_eq!(c["type"], String::from("PATH"));
        //assert_eq!(d["key"], String::from("expected"));
        //assert_eq!(e["key"], String::from("expected"));

        // Testing specific syscall with parent not given
        data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("syscall"), String::from("266")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("NOT_PATH")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("NOT_PATHPATH")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        data.push(HashMap::from([ (String::from("key"), String::from("expected")) ]));
        let (a, b, c, d) = extract_fields(data);
        assert_eq!(a["syscall"], String::from("266"));
        assert_eq!(b["key"], String::from("expected"));*/
        //assert_eq!(c, HashMap::new());
        //assert_eq!(d["key"], String::from("expected"));
        //assert_eq!(e["key"], String::from("expected"));

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
