// Copyright (C) 2021, Achiefs.

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
mod hash;
// To manage Pathbufs
use std::path::PathBuf;


pub struct Event {
    pub id: String,
    pub timestamp: String,
    pub hostname: String,
    pub nodename: String,
    pub version: String,
    pub path: PathBuf,
    pub operation: Op,
    pub labels: Vec<String>
}

impl Event {
    // To get JSON object of common data.
    fn get_common_message(&self, format: &str) -> JsonValue {
        match format {
            "SYSLOG" => {
                json::object![
                    timestamp: self.timestamp.clone(),
                    hostname: self.hostname.clone(),
                    node: self.nodename.clone(),
                    pid: process::id()
                ]
            },
            _ => {
                json::object![
                    id: self.id.clone(),
                    timestamp: self.timestamp.clone(),
                    hostname: self.hostname.clone(),
                    node: self.nodename.clone(),
                    pid: process::id(),
                    version: self.version.clone(),
                    labels: self.labels.clone()
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
            "syslog" | "s" | "SYSLOG" | "S" | "Syslog" => clean_format = "SYSLOG",
            _ => clean_format = "JSON",
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
                                match hash::get_checksum(self.path.to_str().unwrap()) {
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
                let checksum = match hash::get_checksum(self.path.to_str().unwrap()) {
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
                                match hash::get_checksum(self.path.to_str().unwrap()) {
                                    Ok(data) => data,
                                    Err(e) => {
                                        match e.kind() {
                                            ErrorKind::NotFound => debug!("File Not found error ignoring..."),
                                            ErrorKind::InvalidData => debug!("File data not valid ignoring..."),
                                            _ => {
                                                debug!("Error not handled: {:?}", e.kind());
                                                panic!("Not handled error on get_checksum function.")
                                            },
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

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::event::Event;
    use notify::op::Op;
    use std::path::PathBuf;
    use std::process;
    use std::fs;

    fn remove_test_file(filename: &str) {
        fs::remove_file(filename).unwrap()
    }

    fn create_test_event() -> Event {
        Event {
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            nodename: "FIM".to_string(),
            version: "x.x.x".to_string(),
            operation: Op::CREATE,
            path: PathBuf::new(),
            labels: Vec::new()
        }
    }

    #[test]
    fn test_create_event() {
        let evt = create_test_event();
        assert_eq!(evt.id, "Test_id".to_string());
        assert_eq!(evt.timestamp, "Timestamp".to_string());
        assert_eq!(evt.hostname, "Hostname".to_string());
        assert_eq!(evt.nodename, "FIM".to_string());
        assert_eq!(evt.version, "x.x.x".to_string());
        assert_eq!(evt.operation, Op::CREATE);
        assert_eq!(evt.path, PathBuf::new());
        assert_eq!(evt.labels, Vec::<String>::new());
    }

    #[test]
    fn test_get_common_message_syslog() {
        let evt = create_test_event();
        let expected_output = json::object![
            timestamp: evt.timestamp.clone(),
            hostname: evt.hostname.clone(),
            node: evt.nodename.clone(),
            pid: process::id(),
        ];
        assert_eq!(evt.get_common_message("SYSLOG"), expected_output);
    }

    #[test]
    fn test_get_common_message_json() {
        let evt = create_test_event();
        let expected_output = json::object![
            id: evt.id.clone(),
            timestamp: evt.timestamp.clone(),
            hostname: evt.hostname.clone(),
            node: evt.nodename.clone(),
            pid: process::id(),
            version: evt.version.clone(),
            labels: Vec::<String>::new()
        ];
        assert_eq!(evt.get_common_message("JSON"), expected_output);
    }

    #[test]
    fn test_get_common_message_default() {
        let evt = create_test_event();
        let expected_output = json::object![
            id: evt.id.clone(),
            timestamp: evt.timestamp.clone(),
            hostname: evt.hostname.clone(),
            node: evt.nodename.clone(),
            pid: process::id(),
            version: evt.version.clone(),
            labels: Vec::<String>::new()
        ];
        assert_eq!(evt.get_common_message("TEST"), expected_output);
        assert_eq!(evt.get_common_message(""), expected_output);
    }

    #[test]
    fn test_log_event_json() {
        let filename = "test_event.json";
        let evt = create_test_event();

        evt.log_event(filename, "JSON");
        let contents = fs::read_to_string(filename);
        let expected = format!("{{\"id\":\"Test_id\",\"timestamp\":\"Timestamp\",\"hostname\":\"Hostname\",\"node\":\"FIM\",\"pid\":{},\"version\":\"x.x.x\",\"labels\":[],\"kind\":\"CREATE\",\"file\":\"\",\"checksum\":\"IGNORED\"}}\n", process::id());
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename);
    }

    #[test]
    fn test_log_event_syslog() {
        let filename = "test_event.log";
        let evt = create_test_event();

        evt.log_event(filename, "SYSLOG");
        let contents = fs::read_to_string(filename);
        let expected = format!("Timestamp Hostname FIM[{}]: File '' created, checksum IGNORED\n", process::id());
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename);
    }
}