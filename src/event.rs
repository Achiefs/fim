// Copyright (C) 2021, Achiefs.

// To implement Debug and fmt method
use std::fmt;
// To handle files
use std::fs::OpenOptions;
use std::io::Write;
// Handle time intervals
use std::time::Duration;
// Event handling
use notify::event::*;
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
    pub kind: EventKind,
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

        match writeln!(events_file, "{}", self.format_json() ) {
            Ok(_d) => debug!("Event log written"),
            Err(e) => error!("Event could not be written, Err: [{}]", e)
        }
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

pub fn get_kind(operation: EventKind) -> String {
    match operation {
        EventKind::Create(CreateKind::Any) => { String::from("CREATE") },
        EventKind::Modify(ModifyKind::Any) => { String::from("WRITE") },
        EventKind::Remove(RemoveKind::Any) => { String::from("REMOVE") },
        EventKind::Access(AccessKind::Any) => { String::from("ACCESS") },
        _ => { String::from("UNKNOWN") }
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::config::Config;
    use crate::utils;
    use std::path::PathBuf;
    use tokio_test::block_on;
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
            kind: EventKind::Create(CreateKind::Any),
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
        assert_eq!(evt.kind, EventKind::Create(CreateKind::Any) );
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
        block_on( evt.send(
            String::from("test"), String::from("https://127.0.0.1:9200"),
            String::from("admin"), String::from("admin"), true) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_kind(){
        assert_eq!(get_kind(EventKind::Create(CreateKind::Any)), String::from("CREATE"));
        assert_eq!(get_kind(EventKind::Modify(ModifyKind::Any)), String::from("WRITE"));
        assert_eq!(get_kind(EventKind::Remove(RemoveKind::Any)), String::from("REMOVE"));
        assert_eq!(get_kind(EventKind::Access(AccessKind::Any)), String::from("ACCESS"));
        assert_eq!(get_kind(EventKind::Any), String::from("UNKNOWN"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_process() {
        let config = Config::new(&utils::get_os());
        let event = create_test_event();

        block_on(event.process(config::NETWORK_MODE, String::from("test"), config.clone()));
        block_on(event.process(config::FILE_MODE, String::from("test2"), config.clone()));
        block_on(event.process(config::BOTH_MODE, String::from("test3"), config.clone()));
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