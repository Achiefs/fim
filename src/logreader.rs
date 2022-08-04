// Copyright (C) 2022, Achiefs.

// Global constants definitions
pub const AUDIT_LOG_PATH: &str = "/var/log/audit/audit.log";

// To Read reversed order lines
use rev_lines::RevLines;
use std::io::BufReader;
use std::fs::File;
// To manage readed data into collection
use std::collections::HashMap;

// Single event data management
use crate::auditevent::Event;
// To manage common functions
use crate::utils;
// To get configuration constants
use crate::config;
// To manage checksums and conversions
use crate::hash;

// ----------------------------------------------------------------------------

// Read file to extract last data until the Audit ID changes
pub fn read_log(file: String, config: config::Config) -> Event {
    let log = File::open(file).unwrap();
    let rev_lines = RevLines::new(BufReader::new(log)).unwrap();

    let mut data: Vec<HashMap<String, String>> = Vec::new();
    for line in rev_lines {
        if data.is_empty() {
            data.push(parse_audit_log(line));
        }else{
            let line_info = parse_audit_log(line);
            if line_info["msg"] == data.last().unwrap()["msg"] {
                data.push(line_info);
            }else{ break; }
        }
    }
    if data.last().unwrap()["type"] == "SYSCALL" {
        let proctitle_data = data[0].clone();
        let path_data = data[1].clone();

        let parent_path_data = if data[data.len()-3].clone()["type"] == "PATH" {
            data[data.len()-3].clone()
        }else{
            HashMap::new()
        };
        let position = if parent_path_data.is_empty() { data.len()-3
        }else{ data.len()-2 };
        let cwd_data = data[position].clone();
        let syscall_data = data[position+1].clone();

        let command = if proctitle_data["proctitle"].contains("\"") {
            proctitle_data["proctitle"].clone()
        }else{
            hash::hex_to_ascii(proctitle_data["proctitle"].clone())
        };

        let clean_timestamp: String = String::from(proctitle_data["msg"].clone()
            .replace("audit(", "")
            .replace(".", "")
            .split(":").collect::<Vec<&str>>()[0]); // Getting the 13 digits timestamp

        let event_path = parent_path_data["name"].clone().replace('\"', "");
        let file = utils::get_filename_path(path_data["name"].clone().replace('\"', "").as_str());
        let index = config.get_index(event_path.as_str(), file.clone().as_str(), config.audit.clone().to_vec());
        let labels = config.get_labels(index);

        Event{
            id: utils::get_uuid(),
            proctitle: proctitle_data["proctitle"].clone(),
            command: command.replace('\"', ""),
            timestamp: clean_timestamp,
            hostname: utils::get_hostname(),
            node: config.node.clone(),
            version: String::from(config::VERSION),
            labels,
            operation: path_data["nametype"].clone(),
            path: event_path,
            file,
            checksum: hash::get_checksum(format!("{}/{}", parent_path_data["name"].clone(), path_data["name"].clone())),
            fpid: utils::get_pid(),
            system: utils::get_os(),


            ogid: path_data["ogid"].clone(),
            rdev: path_data["rdev"].clone(),
            cap_fver: path_data["cap_fver"].clone(),
            inode: path_data["inode"].clone(),
            cap_fp: path_data["cap_fp"].clone(),
            cap_fe: path_data["cap_fe"].clone(),
            item: path_data["item"].clone(),
            cap_fi: path_data["cap_fi"].clone(),
            dev: path_data["dev"].clone(),
            mode: path_data["mode"].clone(),
            cap_frootid: path_data["cap_frootid"].clone(),
            ouid: path_data["ouid"].clone(),

            parent: parent_path_data,
            cwd: cwd_data["cwd"].clone().replace('\"', ""),

            syscall: syscall_data["syscall"].clone(),
            ppid: syscall_data["ppid"].clone(),
            comm: syscall_data["comm"].clone().replace('\"', ""),
            fsuid: syscall_data["fsuid"].clone(),
            pid: syscall_data["pid"].clone(),
            a0: syscall_data["a0"].clone(),
            a1: syscall_data["a1"].clone(),
            a2: syscall_data["a2"].clone(),
            a3: syscall_data["a3"].clone(),
            arch: syscall_data["arch"].clone(),
            auid: syscall_data["auid"].clone(),
            items: syscall_data["items"].clone(),
            gid: syscall_data["gid"].clone(),
            euid: syscall_data["euid"].clone(),
            sgid: syscall_data["sgid"].clone(),
            uid: syscall_data["uid"].clone(),
            tty: syscall_data["tty"].clone(),
            success: syscall_data["success"].clone(),
            exit: syscall_data["exit"].clone(),
            ses: syscall_data["ses"].clone(),
            key: syscall_data["key"].clone().replace('\"', ""),
            suid: syscall_data["suid"].clone(),
            egid: syscall_data["egid"].clone(),
            fsgid: syscall_data["fsgid"].clone(),
            exe: syscall_data["exe"].clone().replace('\"', ""),
            source: String::from("audit")
        }
    }else{
        Event::new()
    }
}

// ----------------------------------------------------------------------------

pub fn parse_audit_log(log: String) -> HashMap<String, String> {
    let fields: Vec<&str> = log.split(' ').collect();
    let map: HashMap<String, String> = fields.iter()
        .map(|f| {
            let obj: Vec<&str> = f.split('=').collect();
            return (String::from(obj[0]), String::from(obj[1]));
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
