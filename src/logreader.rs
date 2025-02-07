// Copyright (C) 2022, Achiefs.

// Global constants definitions
pub const AUDIT_PATH: &str = "/var/log/audit";
pub const AUDIT_LOG_PATH: &str = "/var/log/audit/audit.log";

// To manage file reading
use std::io::{BufReader, SeekFrom};
use std::io::prelude::*;
// To manage readed data into collection
use std::collections::HashMap;
// To log the program process
use log::{debug, error};

// Single event data management
use crate::auditevent::Event;
// To manage common functions
use crate::utils;
// To get configuration constants
use crate::appconfig::*;

// Defined type to simplify syntax
type SHashMap = HashMap<String, String>;

// ----------------------------------------------------------------------------

// Read file to extract last data until the Audit ID changes
pub fn read_log(file: String, cfg: AppConfig, position: u64, itx: u64) -> (Event, u64) {
    let mut event: Event = Event::new();
    let mut current_position = position;
    let log = utils::open_file(&file, 0);
    let mut buff = BufReader::new(log);
    match buff.seek(SeekFrom::Current(position as i64)) {
        Ok(p) => debug!("Seek audit log file, position: {}", p),
        Err(e) => error!("{}", e)
    };

    // Read from last registered position until we get event or the end
    let mut data: Vec<HashMap<String, String>> = Vec::new();
    let mut line = String::new();
    while current_position < utils::get_file_end(&file, 0) {
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
        current_position += bytes_read;
        debug!("End read position: {}\n", current_position);

        let line_info = parse_audit_log(line.clone());
        if line_info.contains_key("type") && (line_info["type"] == "SYSCALL" ||
            line_info["type"] == "CWD" ||
            line_info["type"] == "PATH" ||
            line_info["type"] == "PROCTITLE") {
            data.push(line_info.clone());
            if line_info.contains_key("type") &&
                line_info["type"] == "PROCTITLE" {
                debug!("PROCTITLE line detected, breaking loop. Data: {:?}", data);
                break;
            }
        }
        line = String::new();
    }
    if !data.is_empty() {
        let last = data.last().unwrap();
        let first = data.first().unwrap();
        if last.contains_key("type") &&
            first.contains_key("type") &&
            last["type"] == "PROCTITLE" &&
            first["type"] == "SYSCALL" {
            let (syscall, cwd, proctitle, paths) = extract_fields(data.clone());
            let audit_vec = cfg.audit.to_vec();

            // Skip the event generation of paths not monitored by FIM
            if paths.iter().any(|p| {
                let cwd_path = cwd["cwd"].as_str();
                cfg.path_in(p["name"].as_str(), cwd_path, audit_vec.clone()) ||
                cfg.path_in(cwd_path, "", audit_vec.clone())
            }) {
                event = Event::from(syscall, cwd, proctitle, paths, cfg.clone());
            }
        }else if data.iter().any(|line| {
            line["type"] == "SYSCALL" ||
            line["type"] == "CWD" ||
            line["type"] == "PATH" ||
            line["type"] == "PROCTITLE"
        }) && itx < 120 {
            current_position = position;
        }else{
            debug!("Audit log discarded, data: {:?}", data);
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
            "SYSCALL" => syscall.clone_from(v),
            "PATH" => paths.push(v.clone()),
            "CWD" => cwd.clone_from(v),
            "PROCTITLE" => proctitle.clone_from(v),
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
                (String::from(obj[0]), String::from(obj[1]).replace(['\"', '\n'], ""))
            }else{
                (String::from(obj[0]), String::from("UNKNOWN"))
            }
        }).collect::<HashMap<String, String>>()
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_log() {
        if utils::get_os() == "linux" {
            let cfg = AppConfig::new("linux", Some("test/system/audit_config.yml"));
            let (event, position) = read_log(String::from("test/unit/audit.log"),
                cfg, 0, 0);

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
            assert_eq!(event.paths[0]["item"], "0");
            assert_eq!(event.paths[0]["name"], "./");
            assert_eq!(event.paths[0]["inode"], "1966138");
            assert_eq!(event.paths[0]["dev"], "08:02");
            assert_eq!(event.paths[0]["mode"], "040755");
            assert_eq!(event.paths[0]["ouid"], "1000");
            assert_eq!(event.paths[0]["ogid"], "0");
            assert_eq!(event.paths[0]["rdev"], "00:00");
            assert_eq!(event.paths[0]["nametype"], "PARENT");
            assert_eq!(event.paths[0]["cap_fp"], "0");
            assert_eq!(event.paths[0]["cap_fi"], "0");
            assert_eq!(event.paths[0]["cap_fe"], "0");
            assert_eq!(event.paths[0]["cap_fver"], "0");
            assert_eq!(event.paths[0]["cap_frootid"], "0");
            assert_eq!(event.paths[1]["item"], "1");
            assert_eq!(event.paths[1]["name"], "./sedTsutP7");
            assert_eq!(event.paths[1]["inode"], "1972630");
            assert_eq!(event.paths[1]["dev"], "08:02");
            assert_eq!(event.paths[1]["mode"], "0100000");
            assert_eq!(event.paths[1]["ouid"], "0");
            assert_eq!(event.paths[1]["ogid"], "0");
            assert_eq!(event.paths[1]["rdev"], "00:00");
            assert_eq!(event.paths[1]["nametype"], "CREATE");
            assert_eq!(event.paths[1]["cap_fp"], "0");
            assert_eq!(event.paths[1]["cap_fi"], "0");
            assert_eq!(event.paths[1]["cap_fe"], "0");
            assert_eq!(event.paths[1]["cap_fver"], "0");
            assert_eq!(event.paths[1]["cap_frootid"], "0");
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
            assert_eq!(position, 850);
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_extract_fields() {
        let mut data = Vec::<HashMap<String, String>>::new();
        data.push(HashMap::from([ (String::from("type"), String::from("SYSCALL")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("CWD")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("PROCTITLE")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("PATH")),
            (String::from("nametype"), String::from("CREATE")) ]));
        data.push(HashMap::from([ (String::from("type"), String::from("PATH")),
            (String::from("nametype"), String::from("PARENT")) ]));
        let (a, b, c, vd) = extract_fields(data);
        assert_eq!(a["type"], String::from("SYSCALL"));
        assert_eq!(b["type"], String::from("CWD"));
        assert_eq!(c["type"], String::from("PROCTITLE"));
        assert_eq!(vd[0]["type"], String::from("PATH"));
        assert_eq!(vd[0]["nametype"], String::from("CREATE"));
        assert_eq!(vd[1]["type"], String::from("PATH"));
        assert_eq!(vd[1]["nametype"], String::from("PARENT"));
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
