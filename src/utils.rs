// Copyright (C) 2021, Achiefs.

// To manage unique event identifier
use uuid::Uuid;
// To get own process ID
use std::process;
// To get Operating system
use std::env;
// To use files IO operations.
use std::fs::{File, metadata};
use std::io::{Read, SeekFrom};
use std::io::prelude::*;
use crate::appconfig;
// To manage paths
use std::path::{Path, PathBuf};
// To run commands
use std::process::Command;
// To log the program process
use log::{warn, debug, error};
// To manage maps
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

#[cfg(test)]
mod test;

// ----------------------------------------------------------------------------

/// Function to pop last char of a given String
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

pub const fn get_os() -> &'static str {
    env::consts::OS
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
    read_file(appconfig::MACHINE_ID_PATH)
}

// ----------------------------------------------------------------------------

// Function to get file name of a given path
pub fn get_filename_path(path: &str) -> String {
    String::from(
        match Path::new(path).file_name() {
            Some(value) => value,
            None => {
                debug!("Cannot retrieve event file, event path is empty.");
                std::ffi::OsStr::new(path)
            }
        }.to_str().unwrap()
    )
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
            warn!("Auditctl command unavailable");
            false
        }
    }
}

// ------------------------------------------------------------------------

// Returns if raw_path contains compare_path
pub fn match_path(raw_path: &str, compare_path: &str) -> bool {
    let max_pops = 128;
    let mut pops = 0;
    let pattern = if get_os() == "linux" { "/" }else{ "\\" };
    let compare_path_clean = &clean_path(compare_path);
    let raw_path_clean = &clean_path(raw_path);

    let mut raw_tokens: Vec<&str>;
    let mut compare_tokens: Vec<&str>;

    match metadata(raw_path_clean) {
        Ok(md) => if md.is_file(){
            raw_tokens = raw_path_clean.split(pattern).collect();
            raw_tokens.pop();
        }else{
            raw_tokens = raw_path_clean.split(pattern).collect();
        }
        ,
        Err(e) => { 
            debug!("Cannot fetch metadata information of '{}', assuming not a file. Error: {}", raw_path_clean, e);
            raw_tokens = raw_path_clean.split(pattern).collect();
        }
    };
    match metadata(compare_path_clean) {
        Ok(md) => if md.is_file(){
            compare_tokens = compare_path_clean.split(pattern).collect();
            compare_tokens.pop();
        }else{
            compare_tokens = compare_path_clean.split(pattern).collect();
        },
        Err(e) => {
            debug!("Cannot fetch metadata information of '{}', assuming not a file. Error: {}", compare_path_clean, e);
            compare_tokens = compare_path_clean.split(pattern).collect();
        }
    };

    while raw_tokens.len() > compare_tokens.len() && pops < max_pops {
        raw_tokens.pop();
        pops += 1;
    }
    
    raw_tokens.iter().zip(compare_tokens.iter()).all(|(r,c)| {
        clean_path(r) == clean_path(c)
    })
}

// ----------------------------------------------------------------------------

#[cfg(not(tarpaulin_include))]
/// Get the current workdir for FIM, it returns a String with complete path.
pub fn get_current_dir() -> String {
    String::from(env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).to_str()
        .unwrap_or("."))
}

// ----------------------------------------------------------------------------

pub fn get_field(data: HashMap<String, String>, field_name: &str) -> String {
    let alternative = match field_name {
        "nametype" => "objtype",
        _ => field_name
    };
    match data.get(field_name) {
        Some(value) => String::from(value),
        None => {
            debug!("Cannot not fetch field name trying alternative");
            match data.get(alternative) {
                Some(alt) => String::from(alt),
                None => {
                    debug!("Cannot not fetch alternative. Using default");
                    String::from("UNKNOWN")
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------

pub fn get_file_size(filename: &str) -> u64 {
    match metadata(filename) {
        Ok(data) => data.len(),
        Err(e) => {
            debug!("Cannot retrieve file size, error: {}", e);
            0
        }
    }
}

// ----------------------------------------------------------------------------

pub fn get_audit_rule_permissions(value: Option<&str>) -> String {
    let mut rule: String = String::new();
    match value {
        Some(value) => {
            for c in value.chars(){
                match c {
                    'r'|'R' => rule.push('r'),
                    'w'|'W' => rule.push('w'),
                    'a'|'A' => rule.push('a'),
                    'x'|'X' => rule.push('x'),
                    _ => rule = String::from("wax")
                }
            }
            rule.clone()
        },
        None => String::from("wax")
    }
}

// ----------------------------------------------------------------------------

pub fn run_auditctl(args: &[&str]) {
    match Command::new("/usr/sbin/auditctl")
    .args(args)
    .output()
    {
        Ok(d) => debug!("Auditctl command info: {:?}", d),
        Err(e) => error!("Auditctl command error: {}", e)
    };
}

// ----------------------------------------------------------------------------

pub fn get_current_time_millis() -> String {
    format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("Time went backwards").as_millis())
}

// ----------------------------------------------------------------------------

pub fn get_fs_list(root: String) -> Vec<String> {
    let mut list = Vec::new();
    for result in WalkDir::new(root) {
        list.push(String::from(result.unwrap().path().to_str().unwrap()))
    }
    list
}

// ----------------------------------------------------------------------------

#[cfg(target_family = "unix")]
pub fn get_unix_permissions(file: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let metadata = Path::new(file).metadata().unwrap();
    format!("{:o}", metadata.permissions().mode()).parse::<u32>().unwrap()
}

// ----------------------------------------------------------------------------

#[cfg(target_family = "windows")]
pub fn get_unix_permissions(_v: &str) -> u32 {
    return 0
}

// ----------------------------------------------------------------------------