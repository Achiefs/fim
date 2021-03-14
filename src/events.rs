// To handle files
use std::fs::{OpenOptions, metadata};
use std::io::{Write, Error, ErrorKind};
// To get Date and Time
use chrono::Utc;
// To get own process ID
use std::process;
// Event handling
use notify::op::Op;
// To log the program process
use log::*;
use notify::RawEvent;
// To handle JSON objects
use json::JsonValue;

// To load hashing functions
mod hash;

// To get JSON object of common data.
fn get_common_message(format: &str) -> JsonValue {
    let hostname = gethostname::gethostname().into_string().unwrap();
    match format {
        "JSON" => {
            json::object![
                timestamp: format!("{}", Utc::now().format("%s")),
                hostname: hostname,
                app: "FIM",
                pid: process::id()
            ]
        },
        "SYSLOG" | _ => {
            json::object![
                timestamp: format!("{}", Utc::now().format("%b %d %H:%M:%S")),
                hostname: hostname,
                app: "FIM",
                pid: process::id()
            ]
        },
    }
}

// Function to write the received events to file
pub fn log_event(file: &str, event: RawEvent, format: &str){
    let mut log = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(file)
        .expect("Unable to open events log file.");

    let path = event.path.expect("Error getting event path");
    let clean_format: &str;
    match format {
        "json" | "JSON" | "j" | "J" | "Json" => clean_format = "JSON",
        "syslog" | "s" | "SYSLOG" | "S" | "Syslog" | _ => clean_format = "SYSLOG",
    }
    let mut obj = get_common_message(clean_format);
    let message = format!("{} {} {}[{}]:",
            obj["timestamp"], obj["hostname"], obj["app"], obj["pid"]);

    match event.op.unwrap() {
        Op::CREATE => {
            let md = metadata(&path).unwrap();
            let checksum = match md.is_file() {
                true => {
                    match hash::get_checksum(&path.to_str().unwrap()) {
                        Ok(data) => data,
                        Err(_e) => String::from("IGNORED")
                    }
                },
                false => String::from("IGNORED")
            };

            if clean_format == "JSON" {
                obj["kind"] = "CREATE".into();
                obj["file"] = path.to_str().unwrap().into();
                obj["checksum"] = checksum.into();
                writeln!(log, "{}", json::stringify(obj))
            } else {
                writeln!(log, "{} File '{}' created, checksum {}", message,
                    path.to_str().unwrap(), checksum)
            }
        }
        Op::WRITE => {
            let checksum = match hash::get_checksum(&path.to_str().unwrap()) {
                Ok(data) => data,
                Err(_e) => String::from("IGNORED")
            };

            if clean_format == "JSON" {
                obj["kind"] = "WRITE".into();
                obj["file"] = path.to_str().unwrap().into();
                obj["checksum"] = checksum.into();
                writeln!(log, "{}", json::stringify(obj))
            } else {
                writeln!(log, "{} File '{}' written, new checksum {}", message,
                    path.to_str().unwrap(), checksum)
            }
        }
        Op::RENAME => {
            let checksum = match metadata(&path) {
                Ok(md) => {
                    match md.is_file() {
                        true => {
                            match hash::get_checksum(&path.to_str().unwrap()) {
                                Ok(data) => data,
                                Err(e) => {
                                    match e.kind() {
                                        ErrorKind::NotFound => println!("File Not found error ignoring..."),
                                        _ => panic!("Not handled error on get_checksum function."),
                                    };
                                    String::from("IGNORED")
                                }
                            }
                        },
                        false => String::from("IGNORED")
                    }
                },
                Err(_e) => String::from("IGNORED")
            };
            if clean_format == "JSON" {
                obj["kind"] = "RENAME".into();
                obj["file"] = path.to_str().unwrap().into();
                obj["checksum"] = checksum.into();
                writeln!(log, "{}", json::stringify(obj))
            } else {
                writeln!(log, "{} File '{}' renamed, checksum {}", message,
                    path.to_str().unwrap(), checksum)
            }
        }
        Op::REMOVE => {
            if clean_format == "JSON" {
                obj["kind"] = "REMOVE".into();
                obj["file"] = path.to_str().unwrap().into();
                writeln!(log, "{}", json::stringify(obj))
            } else {
                writeln!(log, "{} File '{}' removed", message,
                    path.to_str().unwrap())
            }
        },
        Op::CHMOD => {
            if clean_format == "JSON" {
                obj["kind"] = "CHMOD".into();
                obj["file"] = path.to_str().unwrap().into();
                writeln!(log, "{}", json::stringify(obj))
            } else {
                writeln!(log, "{} File '{}' permissions modified", message,
                    path.to_str().unwrap())
            }
        },
        Op::CLOSE_WRITE => {
            if clean_format == "JSON" {
                obj["kind"] = "CLOSE_WRITE".into();
                obj["file"] = path.to_str().unwrap().into();
                writeln!(log, "{}", json::stringify(obj))
            } else {
                writeln!(log, "{} File '{}' closed", message,
                    path.to_str().unwrap())
            }
        },
        Op::RESCAN => {
            if clean_format == "JSON" {
                obj["kind"] = "RESCAN".into();
                obj["file"] = path.to_str().unwrap().into();
                writeln!(log, "{}", json::stringify(obj))
            } else {
                writeln!(log, "{} Directory '{}' need to be rescaned", message,
                    path.to_str().unwrap())
            }
        },
        _ => {
            let error_msg = "Event Op not Handled or do not exists";
            error!("{}", error_msg);
            Err(Error::new(ErrorKind::InvalidInput, error_msg))
        },
    }.expect("Error writing event")
}