// Copyright (C) 2022, Achiefs.

// Global constants definitions
pub const AUDIT_LOG_PATH: &str = "/var/log/audit/audit.log";

// ----
use rev_lines::RevLines;
use std::io::BufReader;
use std::fs::File;
use std::collections::HashMap;
// ----

/*pub struct Audit {
    pub log_type: String,
    pub msg: String
}*/

// Read file to extract last data
pub fn read_log(file: String) {
    let log = File::open(file).unwrap();
    let rev_lines = RevLines::new(BufReader::new(log)).unwrap();

    let mut count = 5;
    for line in rev_lines {
        parse_audit_log(line);
        count = count - 1;
        if count == 0 { break; }
    }
}

// ----------------------------------------------------------------------------

pub fn parse_audit_log(log: String) {
    let fields: Vec<&str> = log.split(' ').collect();
    let map: HashMap<String, String> = fields.iter()
        .map(|f| {
            let obj: Vec<&str> = f.split('=').collect();
            return (String::from(obj[0]), String::from(obj[1]));
        }).collect();
    println!("{:?}", map);
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
