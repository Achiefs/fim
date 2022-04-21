// Copyright (C) 2021, Achiefs.

// To implement Debug and fmt method
use std::fmt;
// To handle files
use std::fs::OpenOptions;
use std::io::{Write, Error, ErrorKind};
// To get own process ID
use std::process;
// Event handling
use notify::op::Op;
// To log the program process
use log::*;
// To handle JSON objects
use serde_json::{json, to_string};
// To manage Pathbufs
use std::path::PathBuf;
// To manage HTTP requests
use reqwest::Client;

pub struct Event {
    pub id: String,
    pub timestamp: String,
    pub hostname: String,
    pub nodename: String,
    pub version: String,
    pub path: PathBuf,
    pub operation: Op,
    pub labels: Vec<String>,
    pub kind: String,
    pub checksum: String
}

impl Event {
    // Get formatted string with all required data
    fn format_json(&self, format: &str) -> String {
        match format {
            "SYSLOG" => {
                format!("{} {} {}[{}] File '{}' {}, checksum: {}",
                    self.timestamp.clone(),
                    self.hostname.clone(),
                    self.nodename.clone(),
                    process::id(),
                    self.path.clone().to_str().unwrap(),
                    self.kind.clone(),
                    self.checksum.clone())
            },
            _ => {
                let obj = json!({
                    "id": self.id.clone(),
                    "timestamp": self.timestamp.clone(),
                    "hostname": self.hostname.clone(),
                    "node": self.nodename.clone(),
                    "pid": process::id(),
                    "version": self.version.clone(),
                    "labels": self.labels.clone(),
                    "kind": self.kind.clone(),
                    "file": String::from(self.path.clone().to_str().unwrap()),
                    "checksum": self.checksum.clone()
                });
                format!("{}", to_string(&obj).unwrap())
            }
        }
    }

    // ------------------------------------------------------------------------

    // To get JSON object of common data.
/*    fn get_common_message(&self, format: &str) -> json::JsonValue {
        match format {
            "SYSLOG" => {
                json!({
                    "timestamp": self.timestamp.clone(),
                    "hostname": self.hostname.clone(),
                    "node": self.nodename.clone(),
                    "pid": process::id()
                })
            },
            _ => {
                json!({
                    "id": self.id.clone(),
                    "timestamp": self.timestamp.clone(),
                    "hostname": self.hostname.clone(),
                    "node": self.nodename.clone(),
                    "pid": process::id(),
                    "version": self.version.clone(),
                    "labels": self.labels.clone()
                })
            },
        }
    }
*/
    // ------------------------------------------------------------------------

    // Function to write the received events to file
    pub fn log_event(&self, file: &str, format: &str){
        let mut events_file = OpenOptions::new()
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

        match self.operation {
            Op::CREATE|Op::WRITE|Op::RENAME|Op::REMOVE|Op::CHMOD|Op::CLOSE_WRITE|Op::RESCAN => {
                writeln!(events_file, "{}", self.format_json(clean_format.clone()) )
            },
            _ => {
                let error_msg = "Event Op not Handled or do not exists";
                error!("{}", error_msg);
                Err(Error::new(ErrorKind::InvalidInput, error_msg))
            },
        }.expect("Error writing event")
    }

    // ------------------------------------------------------------------------

    // Function to send events through network
    // Include a way to pass credentials
    pub async fn send(&self, endpoint: String) {
        let data = json!({
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.nodename.clone(),
            "pid": process::id(),
            "version": self.version.clone(),
            "labels": self.labels.clone(),
            "kind": self.kind.clone(),
            "file": String::from(self.path.clone().to_str().unwrap()),
            "checksum": self.checksum.clone()
        });

        let request_url = format!("{}/fim-10-10-2022/_doc/{}", endpoint, self.id);
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build().unwrap();
        let response = client
            .post(request_url)
            .basic_auth("admin", Some("admin"))
            .json(&data)
            .send()
            .await;
        debug!("Event send Response: {:?}", response.unwrap().text().await);
    }
}

// ----------------------------------------------------------------------------

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

pub fn get_kind(operation: Op) -> String {
    match operation {
        Op::CREATE => { String::from("CREATE") },
        Op::WRITE => { String::from("WRITE") },
        Op::RENAME => { String::from("RENAME") },
        Op::REMOVE => { String::from("REMOVE") },
        Op::CHMOD => { String::from("CHMOD") },
        Op::CLOSE_WRITE => { String::from("CLOSE_WRITE") },
        Op::RESCAN => { String::from("RESCAN") },
        _ => { String::from("UNKNOW") }
    }
}

// ----------------------------------------------------------------------------

pub fn has_checksum(operation: Op) -> bool {
    match operation {
        Op::CREATE => { true },
        Op::WRITE => { true },
        Op::RENAME => { true },
        Op::REMOVE => { false },
        Op::CHMOD => { false },
        Op::CLOSE_WRITE => { false },
        Op::RESCAN => { false },
        _ => { false }
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