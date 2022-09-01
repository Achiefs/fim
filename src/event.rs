// Copyright (C) 2021, Achiefs.

// To implement Debug and fmt method
use std::fmt;
// To handle files
use std::fs::OpenOptions;
use std::io::Write;
//use std::io::{Write, Error, ErrorKind};
// Handle time intervals
use std::time::Duration;
// Event handling
use notify::op::Op;
// To log the program procedure
use log::*;
// To handle JSON objects
use serde_json::{json, to_string};
// To manage paths
use std::path::PathBuf;
// To manage HTTP requests
use reqwest::Client;

// To get configuration constants
use crate::config;

pub struct Event {
    pub id: String,
    pub timestamp: String,
    pub hostname: String,
    pub node: String,
    pub version: String,
    pub path: PathBuf,
    pub op: Op,
    pub labels: Vec<String>,
    pub operation: String,
    pub checksum: String,
    pub fpid: u32,
    pub system: String
}

impl Event {
    // Get formatted string with all required data
    fn format_json(&self) -> String {
        let obj = json!({
            "id": self.id.clone(),
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.node.clone(),
            "fpid": self.fpid.clone(),
            "version": self.version.clone(),
            "labels": self.labels.clone(),
            "operation": self.operation.clone(),
            "file": String::from(self.path.clone().to_str().unwrap()),
            "checksum": self.checksum.clone(),
            "system": self.system.clone()
        });
        to_string(&obj).unwrap()
    }

    // ------------------------------------------------------------------------

    // Function to write the received events to file
    pub fn log(&self, file: String){
        let mut events_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(file)
            .expect("(log) Unable to open events log file.");

        match self.op {
            Op::CREATE|Op::WRITE|Op::RENAME|Op::REMOVE|Op::CHMOD|Op::CLOSE_WRITE|Op::RESCAN => {
                match writeln!(events_file, "{}", self.format_json() ) {
                    Ok(_d) => debug!("Event log written"),
                    Err(e) => error!("Event could not be written, Err: [{}]", e)
                };
            },
            _ => {
                let error_msg = "Event Op not Handled or do not exists";
                error!("{}", error_msg);
            },
        };
    }

    // ------------------------------------------------------------------------

    // Function to send events through network
    pub async fn send(&self, index: String, address: String, user: String, pass: String, insecure: bool) {
        let data = json!({
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.node.clone(),
            "fpid": self.fpid.clone(),
            "version": self.version.clone(),
            "labels": self.labels.clone(),
            "operation": self.operation.clone(),
            "file": String::from(self.path.clone().to_str().unwrap()),
            "checksum": self.checksum.clone(),
            "system": self.system.clone()
        });

        let request_url = format!("{}/{}/_doc/{}", address, index, self.id);
        let client = Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(Duration::from_secs(30))
            .build().unwrap();
        match client
            .post(request_url)
            .basic_auth(user, Some(pass))
            .json(&data)
            .send()
            .await {
            Ok(response) => debug!("Response received: {:?}", response),
            Err(e) => debug!("Error on request: {:?}", e)
        };
    }

    // ------------------------------------------------------------------------

    // Function to manage event destination
    pub async fn process(&self, destination: &str, index_name: String, config: config::Config){
        match destination {
            config::BOTH_MODE => {
                self.log(config.events_file);
                self.send( index_name, config.endpoint_address, config.endpoint_user, config.endpoint_pass, config.insecure).await;
            },
            config::NETWORK_MODE => {
                self.send( index_name, config.endpoint_address, config.endpoint_user, config.endpoint_pass, config.insecure).await;
            },
            _ => self.log(config.events_file)
        }
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

pub fn get_op(operation: Op) -> String {
    match operation {
        Op::CREATE => { String::from("CREATE") },
        Op::WRITE => { String::from("WRITE") },
        Op::RENAME => { String::from("RENAME") },
        Op::REMOVE => { String::from("REMOVE") },
        Op::CHMOD => { String::from("CHMOD") },
        Op::CLOSE_WRITE => { String::from("CLOSE_WRITE") },
        Op::RESCAN => { String::from("RESCAN") },
        _ => { String::from("UNKNOWN") }
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use notify::op::Op;
    use std::path::PathBuf;
    use std::fs;

    // ------------------------------------------------------------------------

    fn remove_test_file(filename: String) {
        fs::remove_file(filename).unwrap()
    }

    fn create_test_event() -> Event {
        Event {
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            node: "FIM".to_string(),
            version: "x.x.x".to_string(),
            op: Op::CREATE,
            path: PathBuf::new(),
            labels: Vec::new(),
            operation: "TEST".to_string(),
            checksum: "UNKNOWN".to_string(),
            fpid: 0,
            system: "test".to_string()
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_create_event() {
        let evt = create_test_event();
        assert_eq!(evt.id, "Test_id".to_string());
        assert_eq!(evt.timestamp, "Timestamp".to_string());
        assert_eq!(evt.hostname, "Hostname".to_string());
        assert_eq!(evt.node, "FIM".to_string());
        assert_eq!(evt.version, "x.x.x".to_string());
        assert_eq!(evt.op, Op::CREATE);
        assert_eq!(evt.path, PathBuf::new());
        assert_eq!(evt.labels, Vec::<String>::new());
        assert_eq!(evt.operation, String::from("TEST"));
        assert_eq!(evt.fpid, 0);
        assert_eq!(evt.system, String::from("test"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send() {
        let evt = create_test_event();
        tokio_test::block_on( evt.send(
            String::from("test"), String::from("https://127.0.0.1:9200"),
            String::from("admin"), String::from("admin"), true) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_op(){
        assert_eq!(get_op(Op::CREATE), String::from("CREATE"));
        assert_eq!(get_op(Op::WRITE), String::from("WRITE"));
        assert_eq!(get_op(Op::RENAME), String::from("RENAME"));
        assert_eq!(get_op(Op::REMOVE), String::from("REMOVE"));
        assert_eq!(get_op(Op::CHMOD), String::from("CHMOD"));
        assert_eq!(get_op(Op::CLOSE_WRITE), String::from("CLOSE_WRITE"));
        assert_eq!(get_op(Op::RESCAN), String::from("RESCAN"));
        assert_eq!(get_op(Op::empty()), String::from("UNKNOWN"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_event_fmt(){
        let out = format!("{:?}", create_test_event());
        assert_eq!(out, "(\"Test_id\", \"\", \"TEST\")");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_format_json() {
        let expected = "{\"checksum\":\"UNKNOWN\",\"file\":\"\",\"fpid\":0,\
            \"hostname\":\"Hostname\",\"id\":\"Test_id\",\"labels\":[],\
            \"node\":\"FIM\",\"operation\":\"TEST\",\"system\":\"test\",\
            \"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}";
        assert_eq!(create_test_event().format_json(), expected);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_log() {
        let filename = String::from("test_event.json");
        let evt = create_test_event();

        evt.log(filename.clone());
        let contents = fs::read_to_string(filename.clone());
        let expected = "{\"checksum\":\"UNKNOWN\",\"file\":\"\",\"fpid\":0,\
            \"hostname\":\"Hostname\",\"id\":\"Test_id\",\"labels\":[],\
            \"node\":\"FIM\",\"operation\":\"TEST\",\"system\":\"test\",\
            \"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}\n";
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename.clone());
    }
}