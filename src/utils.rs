// Copyright (C) 2021, Achiefs.

// To manage unique event identifier
use uuid::Uuid;
// To get own process ID
use std::process;
// To get Operating system
use std::env;
// To use files IO operations.
use std::fs::File;
use std::io::{Read, SeekFrom};
use std::io::prelude::*;
// To get config constants
use crate::config;
// To manage paths
use std::path::Path;
// To run commands
use std::process::Command;
// To log the program process
use log::{warn, error, debug};
// To manage cmp order
use std::cmp::Ordering;

// ----------------------------------------------------------------------------

// Function to pop last char of a given String
pub fn pop(string: &str) -> &str {
    let mut chars = string.chars();
    chars.next_back();
    chars.as_str()
}

// ----------------------------------------------------------------------------

pub fn get_hostname() -> String {
    gethostname::gethostname().into_string().unwrap()
}

// ----------------------------------------------------------------------------

pub fn get_uuid() -> String {
    format!("{}", Uuid::new_v4())
}

// ----------------------------------------------------------------------------

pub fn get_pid() -> u32 {
    process::id()
}

// ----------------------------------------------------------------------------

pub fn get_os() -> String {
    env::consts::OS.to_string()
}

// ----------------------------------------------------------------------------

// Function to read file from begin to end
pub fn read_file(path: &str) -> String {
    let mut file = File::open(path).unwrap();
    let mut contents = String::new();

    file.read_to_string(&mut contents).unwrap();
    contents
}

// ----------------------------------------------------------------------------

// (Only supported in Linux) Function to get machine id of the host
pub fn get_machine_id() -> String {
    read_file(config::MACHINE_ID_PATH)
}

// ----------------------------------------------------------------------------

// Function to get file name of a given path
pub fn get_filename_path(path: &str) -> String {
    String::from(Path::new(path).file_name().unwrap().to_str().unwrap())
}

// ----------------------------------------------------------------------------

// Function to clean trailing slash of a path
pub fn clean_path(path: &str) -> String {
    String::from(if path.ends_with('/') || path.ends_with('\\'){ pop(path) }else{ path })
}

// ----------------------------------------------------------------------------

// Function to get the last byte of a given file
pub fn get_file_end(file: &str, itx: u64) -> u64 {
    if itx < 5 {
        match File::open(file) {
            Ok(mut d) => d.seek(SeekFrom::End(0)).unwrap(),
            Err(e) => {
                warn!("Cannot open file '{}', due to: {}, retrying...", file, e);
                get_file_end(file, itx + 1)
            }
        }
    }else{ 0 }
}

// ----------------------------------------------------------------------------

// Function to get the last byte of a given file
pub fn open_file(file: &str, itx: u64) -> File {
    if itx < 5 {
        match File::open(file) {
            Ok(d) => d,
            Err(e) => {
                warn!("Cannot open file '{}', due to: {}, retrying...", file, e);
                open_file(file, itx + 1)
            }
        }
    }else{
        panic!("Cannot open '{}'", file);
    }
}

// ----------------------------------------------------------------------------

pub fn check_auditd() -> bool {
    match Command::new("which")
        .arg("auditctl")
        .output()
        .expect("[ERROR] Failed to execute auditctl command check")
        .status
        .success() {
        true => {
            debug!("Auditctl command available");
            true
        },
        _ => {
            error!("Auditctl command unavailable");
            false
        }
    }
}

// ------------------------------------------------------------------------

// Returns if raw_path contains compare_path
pub fn match_path(raw_path: &str, compare_path: &str) -> bool {
    let pattern = if get_os() == "linux" { "/" }else{ "\\" };
    let mut raw_tokens: Vec<&str> = raw_path.split(pattern).collect();
    let mut compare_tokens: Vec<&str> = compare_path.split(pattern).collect();

    match raw_tokens.len().cmp(&compare_tokens.len()) {
        Ordering::Equal => {
            raw_tokens.iter().zip(compare_tokens.iter()).all(|(r,c)|
                clean_path(r) == clean_path(c))
        },
        Ordering::Greater => {
            // Removing file name from bottom
            raw_tokens.pop();
            raw_tokens.iter().zip(compare_tokens.iter()).all(|(r,c)|
                clean_path(r) == clean_path(c))
        },
        _ => {
            // Removing file name from bottom
            compare_tokens.pop();
            raw_tokens.iter().zip(compare_tokens.iter()).all(|(r,c)|
                clean_path(r) == clean_path(c))
        }
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pop() {
        assert_eq!(pop("test-"), "test");
        assert_eq!(pop("dir/"), "dir");
        assert_eq!(pop("dir@"), "dir");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_hostname() {
        // We will need to manage a better test
        assert_eq!(get_hostname(), gethostname::gethostname().into_string().unwrap());
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_uuid() {
        // 9bd52d8c-e162-4f4d-ab35-32206d6d1445
        let uuid = get_uuid();
        let uuid_vec: Vec<&str> = uuid.split("-").collect();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid_vec.len(), 5);
        assert_eq!(uuid_vec[0].len(), 8);
        assert_eq!(uuid_vec[1].len(), 4);
        assert_eq!(uuid_vec[2].len(), 4);
        assert_eq!(uuid_vec[3].len(), 4);
        assert_eq!(uuid_vec[4].len(), 12);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_pid() {
        assert_eq!(get_pid(), process::id());
        assert!(get_pid() > 0);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_os() {
        assert_eq!(get_os(), env::consts::OS.to_string());
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_read_file() {
        assert_eq!(read_file("pkg/deb/debian/compat"), "10");
        assert_ne!(read_file("LICENSE"), "10");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_machine_id() {
        if get_os() == "linux" {
            assert_eq!(get_machine_id().len(), 33);
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_filename_path() {
        if get_os() == "windows"{
            assert_eq!(get_filename_path("C:\\test\\file.txt"), "file.txt");
            assert_ne!(get_filename_path("C:\\test\\file.txt"), "none");
        }else{
            assert_eq!(get_filename_path("/test/file.txt"), "file.txt");
            assert_ne!(get_filename_path("/test/file.txt"), "none");
            assert_eq!(get_filename_path("/test/"), "test");
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic]
    fn test_get_filename_path_panic() {
        get_filename_path("/");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_clean_path() {
        assert_eq!(clean_path("/test/"), "/test");
        assert_eq!(clean_path("/test"), "/test");
        assert_eq!(clean_path("C:\\test\\"), "C:\\test");
        assert_eq!(clean_path("C:\\test"), "C:\\test");
        assert_eq!(clean_path("/"), "");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_file_end() {
        assert_ne!(get_file_end("LICENSE", 0), 100);
        // CRLF matter
        if get_os() == "windows"{
            assert_eq!(get_file_end("LICENSE", 0), 35823);
        }else{
            assert_eq!(get_file_end("LICENSE", 0), 35149);
        }

        assert_eq!(get_file_end("NotFound", 0), 0);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_open_file() {
        open_file("LICENSE", 0);
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic]
    fn test_open_file_panic() {
        open_file("NotFound", 0);
    }

    // ------------------------------------------------------------------------

    #[test]
    #[ignore]
    fn test_check_auditd() {
        if get_os() == "linux" {
            assert!(check_auditd());
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_match_path() {
        if get_os() == "linux" {
            assert!(match_path("/", "/"));
            assert!(match_path("/test", "/test"));
            assert!(match_path("/test/", "/test"));
            assert!(match_path("/test/tmp", "/test"));
            assert!(!match_path("/tmp/test", "/test"));
            assert!(!match_path("/tmp", "/test"));
        }
    }

}