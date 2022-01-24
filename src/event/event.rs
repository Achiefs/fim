// To implement Debug and fmt method
use std::fmt;
// To handle files
use std::fs::{OpenOptions, metadata};
use std::io::{Write, Error, ErrorKind};
// To get own process ID
use std::process;
// Event handling
use notify::op::Op;
// To log the program process
use log::*;
// To handle JSON objects
use json::JsonValue;
// To load hashing functions
use super::hash;
// To manage Pathbufs
use std::path::PathBuf;


pub struct Event {
    pub id: String,
    pub timestamp: String,
    pub hostname: String,
    pub nodename: String,
    pub version: String,
    pub path: PathBuf,
    pub operation: Op
}

impl Event {
    // To get JSON object of common data.
    fn get_common_message(&self, format: &str) -> JsonValue {
        match format {
            "JSON" => {
                json::object![
                    id: self.id.clone(),
                    timestamp: self.timestamp.clone(),
                    hostname: self.hostname.clone(),
                    node: self.nodename.clone(),
                    pid: process::id(),
                    version: self.version.clone()
                ]
            },
            "SYSLOG" | _ => {
                json::object![
                    timestamp: self.timestamp.clone(),
                    hostname: self.hostname.clone(),
                    node: self.nodename.clone(),
                    pid: process::id()
                ]
            },
        }
    }

    // ------------------------------------------------------------------------

    // Function to write the received events to file
    pub fn log_event(&self, file: &str, format: &str){
        let mut log = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(file)
            .expect("Unable to open events log file.");

        let clean_format: &str;
        match format {
            "json" | "JSON" | "j" | "J" | "Json" => clean_format = "JSON",
            "syslog" | "s" | "SYSLOG" | "S" | "Syslog" | _ => clean_format = "SYSLOG",
        }
        let mut obj = self.get_common_message(clean_format);
        let message = format!("{} {} {}[{}]:",
                obj["timestamp"], obj["hostname"], obj["node"], obj["pid"]);

        match self.operation {
            Op::CREATE => {
                let checksum = match metadata(&self.path){
                    Ok(metadata_struct) => {
                        match metadata_struct.is_file() {
                            true => {
                                match hash::get_checksum(&self.path.to_str().unwrap()) {
                                    Ok(data) => data,
                                    Err(_e) => String::from("IGNORED")
                                }
                            },
                            false => String::from("IGNORED")
                        }
                    },
                    Err(_e) => String::from("IGNORED")
                };

                if clean_format == "JSON" {
                    obj["kind"] = "CREATE".into();
                    obj["file"] = self.path.to_str().unwrap().into();
                    obj["checksum"] = checksum.into();
                    writeln!(log, "{}", json::stringify(obj))
                } else {
                    writeln!(log, "{} File '{}' created, checksum {}", message,
                        self.path.to_str().unwrap(), checksum)
                }
            }
            Op::WRITE => {
                let checksum = match hash::get_checksum(&self.path.to_str().unwrap()) {
                    Ok(data) => data,
                    Err(_e) => String::from("IGNORED")
                };

                if clean_format == "JSON" {
                    obj["kind"] = "WRITE".into();
                    obj["file"] = self.path.to_str().unwrap().into();
                    obj["checksum"] = checksum.into();
                    writeln!(log, "{}", json::stringify(obj))
                } else {
                    writeln!(log, "{} File '{}' written, new checksum {}", message,
                        self.path.to_str().unwrap(), checksum)
                }
            }
            Op::RENAME => {
                let checksum = match metadata(&self.path) {
                    Ok(md) => {
                        match md.is_file() {
                            true => {
                                match hash::get_checksum(&self.path.to_str().unwrap()) {
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
                    obj["file"] = self.path.to_str().unwrap().into();
                    obj["checksum"] = checksum.into();
                    writeln!(log, "{}", json::stringify(obj))
                } else {
                    writeln!(log, "{} File '{}' renamed, checksum {}", message,
                        self.path.to_str().unwrap(), checksum)
                }
            }
            Op::REMOVE => {
                if clean_format == "JSON" {
                    obj["kind"] = "REMOVE".into();
                    obj["file"] = self.path.to_str().unwrap().into();
                    writeln!(log, "{}", json::stringify(obj))
                } else {
                    writeln!(log, "{} File '{}' removed", message,
                        self.path.to_str().unwrap())
                }
            },
            Op::CHMOD => {
                if clean_format == "JSON" {
                    obj["kind"] = "CHMOD".into();
                    obj["file"] = self.path.to_str().unwrap().into();
                    writeln!(log, "{}", json::stringify(obj))
                } else {
                    writeln!(log, "{} File '{}' permissions modified", message,
                        self.path.to_str().unwrap())
                }
            },
            Op::CLOSE_WRITE => {
                if clean_format == "JSON" {
                    obj["kind"] = "CLOSE_WRITE".into();
                    obj["file"] = self.path.to_str().unwrap().into();
                    writeln!(log, "{}", json::stringify(obj))
                } else {
                    writeln!(log, "{} File '{}' closed", message,
                        self.path.to_str().unwrap())
                }
            },
            Op::RESCAN => {
                if clean_format == "JSON" {
                    obj["kind"] = "RESCAN".into();
                    obj["file"] = self.path.to_str().unwrap().into();
                    writeln!(log, "{}", json::stringify(obj))
                } else {
                    writeln!(log, "{} Directory '{}' need to be rescaned", message,
                        self.path.to_str().unwrap())
                }
            },
            _ => {
                let error_msg = "Event Op not Handled or do not exists";
                error!("{}", error_msg);
                Err(Error::new(ErrorKind::InvalidInput, error_msg))
            },
        }.expect("Error writing event")
    }
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        f.debug_tuple("")
          .field(&self.id)
          .field(&self.path)
          .field(&self.operation)
          .finish()
    }
}