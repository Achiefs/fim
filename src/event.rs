// Copyright (C) 2021, Achiefs.

// To implement Debug and fmt method
use std::fmt;
// To handle files
use std::fs::OpenOptions;
use std::io::{Write, Error, ErrorKind};
// Event handling
use notify::op::Op;
// To log the program procedure
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
    pub checksum: String,
    pub pid: u32,
    pub system: String
}

impl Event {
    // Get formatted string with all required data
    fn format_json(&self) -> String {
        let obj = json!({
            "id": self.id.clone(),
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.nodename.clone(),
            "pid": self.pid.clone(),
            "version": self.version.clone(),
            "labels": self.labels.clone(),
            "kind": self.kind.clone(),
            "file": String::from(self.path.clone().to_str().unwrap()),
            "checksum": self.checksum.clone(),
            "system": self.system.clone()
        });
        to_string(&obj).unwrap()
    }

    // ------------------------------------------------------------------------

    // Function to write the received events to file
    pub fn log_event(&self, file: String){
        let mut events_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(file)
            .expect("Unable to open events log file.");

        match self.operation {
            Op::CREATE|Op::WRITE|Op::RENAME|Op::REMOVE|Op::CHMOD|Op::CLOSE_WRITE|Op::RESCAN => {
                writeln!(events_file, "{}", self.format_json() )
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
    pub async fn send(&self, index: String, address: String, user: String, pass: String) {
        let data = json!({
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.nodename.clone(),
            "pid": self.pid.clone(),
            "version": self.version.clone(),
            "labels": self.labels.clone(),
            "kind": self.kind.clone(),
            "file": String::from(self.path.clone().to_str().unwrap()),
            "checksum": self.checksum.clone(),
            "system": self.system.clone()
        });

        let request_url = format!("{}/{}/_doc/{}", address, index, self.id);
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build().unwrap();
        let response = client
            .post(request_url)
            .basic_auth(user, Some(pass))
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

#[cfg(test)]
mod tests {
    use crate::event::Event;
    use notify::op::Op;
    use std::path::PathBuf;
    //use serde_json::json;
    use std::fs;

    fn remove_test_file(filename: String) {
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
            labels: Vec::new(),
            kind: "TEST".to_string(),
            checksum: "UNKNOWN".to_string(),
            pid: 0,
            system: "test".to_string()
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

/*    #[test]
    fn test_get_common_message_syslog() {
        let evt = create_test_event();
        let expected_output = json!({
            "timestamp": evt.timestamp.clone(),
            "hostname": evt.hostname.clone(),
            "node": evt.nodename.clone(),
            "pid": evt.pid.clone(),
        });
        assert_eq!(evt.get_common_message("SYSLOG"), expected_output);
    }

    #[test]
    fn test_get_common_message_json() {
        let evt = create_test_event();
        let expected_output = json!({
            "id": evt.id.clone(),
            "timestamp": evt.timestamp.clone(),
            "hostname": evt.hostname.clone(),
            "node": evt.nodename.clone(),
            "pid": evt.pid.clone(),
            "version": evt.version.clone(),
            "labels": Vec::<String>::new()
        });
        assert_eq!(evt.get_common_message("JSON"), expected_output);
    }

    #[test]
    fn test_get_common_message_default() {
        let evt = create_test_event();
        let expected_output = json!({
            "id": evt.id.clone(),
            "timestamp": evt.timestamp.clone(),
            "hostname": evt.hostname.clone(),
            "node": evt.nodename.clone(),
            "pid": evt.pid.clone(),
            "version": evt.version.clone(),
            "labels": Vec::<String>::new()
        });
        assert_eq!(evt.get_common_message("TEST"), expected_output);
        assert_eq!(evt.get_common_message(""), expected_output);
    }*/

    #[test]
    fn test_log_event() {
        let filename = String::from("test_event.json");
        let evt = create_test_event();

        evt.log_event(filename.clone());
        let contents = fs::read_to_string(filename.clone());
        let expected = "{\"checksum\":\"UNKNOWN\",\"file\":\"\",\"hostname\":\"Hostname\",\"id\":\"Test_id\",\"kind\":\"TEST\",\"labels\":[],\"node\":\"FIM\",\"pid\":0,\"system\":\"test\",\"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}\n";
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename.clone());
    }
}