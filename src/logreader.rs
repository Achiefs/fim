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

// Read file to extract last data until the Audit ID changes
pub fn read_log(file: String) -> Event {
    let log = File::open(file).unwrap();
    let rev_lines = RevLines::new(BufReader::new(log)).unwrap();

    let mut data: Vec<HashMap<String, String>> = Vec::new();
    for line in rev_lines {
        data.push(parse_audit_log(line));

        if data.first().unwrap()["msg"] != data.last().unwrap()["msg"] { break; }
    }
    //println!("Audit Data: {:?}", data);
    if data.len() == 6 {
        let proctitle_data = data[0].clone();
        let path_data = data[1].clone();
        let parent_path_data = data[2].clone();
        let cwd_data = data[3].clone();
        let syscall_data = data[4].clone();

        Event{
            id: "0123456".to_string(),
            proctitle: proctitle_data["proctitle"].clone(),
            timestamp: proctitle_data["msg"].clone(),
            operation: path_data["nametype"].clone(),
            path: parent_path_data["name"].clone(),
            file: path_data["name"].clone(),
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
            
            parent_inode: parent_path_data["inode"].clone(),
            parent_cap_fe: parent_path_data["cap_fe"].clone(),
            parent_cap_frootid: parent_path_data["cap_frootid"].clone(),
            parent_ouid: parent_path_data["ouid"].clone(),
            parent_item: parent_path_data["item"].clone(),
            parent_cap_fver: parent_path_data["cap_fver"].clone(),
            parent_mode: parent_path_data["mode"].clone(),
            parent_rdev: parent_path_data["rdev"].clone(),
            parent_cap_fi: parent_path_data["cap_fi"].clone(),
            parent_cap_fp: parent_path_data["cap_fp"].clone(),
            parent_dev: parent_path_data["dev"].clone(),
            parent_ogid: parent_path_data["ogid"].clone(),
            cwd: cwd_data["cwd"].clone(),

            syscall: syscall_data["syscall"].clone(),
            ppid: syscall_data["ppid"].clone(),
            comm: syscall_data["comm"].clone(),
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
            key: syscall_data["key"].clone(),
            suid: syscall_data["suid"].clone(),
            egid: syscall_data["egid"].clone(),
            fsgid: syscall_data["fsgid"].clone(),
            exe: syscall_data["exe"].clone()
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
