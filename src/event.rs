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
    pub kind: notify::EventKind,
    pub labels: Vec<String>,
    pub operation: String,
    pub detailed_operation: String,
    pub checksum: String,
    pub fpid: u32,
    pub system: String
}

impl Event {
    // Get formatted string with all required data
    pub fn format_json(&self) -> String {
        let obj = json!({
            "id": self.id.clone(),
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.node.clone(),
            "fpid": self.fpid.clone(),
            "version": self.version.clone(),
            "labels": self.labels.clone(),
            "operation": self.operation.clone(),
            "detailed_operation": self.detailed_operation.clone(),
            "file": String::from(self.path.clone().to_str().unwrap()),
            "checksum": self.checksum.clone(),
            "system": self.system.clone()
        });
        to_string(&obj).unwrap()
    }

    // ------------------------------------------------------------------------

    pub fn clone(&self) -> Self {
        Event {
            id: self.id.clone(),
            timestamp: self.timestamp.clone(),
            hostname: self.hostname.clone(),
            node: self.node.clone(),
            version: self.version.clone(),
            path: self.path.clone(),
            kind: self.kind,
            labels: self.labels.clone(),
            operation: self.operation.clone(),
            detailed_operation: self.detailed_operation.clone(),
            checksum: self.checksum.clone(),
            fpid: self.fpid,
            system: self.system.clone()
        }
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
    pub async fn send(&self, index: String) {
        let config = unsafe { super::GCONFIG.clone().unwrap() };
        // Splunk endpoint integration
        if config.endpoint_type == "Splunk" {
            let data = json!({
                "source": self.node.clone(),
                "sourcetype": "_json",
                "event": json!({
                    "timestamp": self.timestamp.clone(),
                    "hostname": self.hostname.clone(),
                    "node": self.node.clone(),
                    "fpid": self.fpid.clone(),
                    "version": self.version.clone(),
                    "labels": self.labels.clone(),
                    "operation": self.operation.clone(),
                    "detailed_operation": self.detailed_operation.clone(),
                    "file": String::from(self.path.clone().to_str().unwrap()),
                    "checksum": self.checksum.clone(),
                    "system": self.system.clone()
                }),
                "index": "fim_events"
            });
            debug!("Sending received event to Splunk integration, event: {}", data);
            let request_url = format!("{}/services/collector/event", config.endpoint_address);
            let client = Client::builder()
                .danger_accept_invalid_certs(config.insecure)
                .timeout(Duration::from_secs(30))
                .build().unwrap();
            match client
                .post(request_url)
                .header("Authorization", format!("Splunk {}", config.endpoint_token))
                .json(&data)
                .send()
                .await {
                    Ok(response) => debug!("Response received: {:?}",
                        response.text().await.unwrap()),
                    Err(e) => debug!("Error on request: {:?}", e)
            }
        // Elastic endpoint integration
        } else {
            let data = json!({
                "timestamp": self.timestamp.clone(),
                "hostname": self.hostname.clone(),
                "node": self.node.clone(),
                "fpid": self.fpid.clone(),
                "version": self.version.clone(),
                "labels": self.labels.clone(),
                "operation": self.operation.clone(),
                "detailed_operation": self.detailed_operation.clone(),
                "file": String::from(self.path.clone().to_str().unwrap()),
                "checksum": self.checksum.clone(),
                "system": self.system.clone()
            });
            let request_url = format!("{}/{}/_doc/{}", config.endpoint_address, index, self.id);
            let client = Client::builder()
                .danger_accept_invalid_certs(config.insecure)
                .timeout(Duration::from_secs(30))
                .build().unwrap();
            match client
                .post(request_url)
                .basic_auth(config.endpoint_user, Some(config.endpoint_pass))
                .json(&data)
                .send()
                .await {
                    Ok(response) => debug!("Response received: {:?}",
                        response.text().await.unwrap()),
                    Err(e) => debug!("Error on request: {:?}", e)
            }
        }

    }

    // ------------------------------------------------------------------------

    // Function to manage event destination
    pub async fn process(&self, destination: &str, index_name: String, config: config::Config){
        match destination {
            config::BOTH_MODE => {
                self.log(config.events_file);
                self.send(index_name).await;
            },
            config::NETWORK_MODE => {
                self.send(index_name).await;
            },
            _ => self.log(config.events_file)
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_string(&self, field: String) -> String {
        match field.as_str() {
            "path" => String::from(self.path.to_str().unwrap()),
            "hostname" => self.hostname.clone(),
            "node" => self.node.clone(),
            "version" => self.version.clone(),
            "operation" => self.operation.clone(),
            "detailed_operation" => self.detailed_operation.clone(),
            "checksum" => self.checksum.clone(),
            "system" => self.system.clone(),
            _ => "".to_string()
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
          .field(&self.detailed_operation)
          .finish()
    }
}

// ----------------------------------------------------------------------------

pub fn get_operation(event_kind: EventKind) -> String {
    let detailed_operation: String = get_detailed_operation(event_kind);
    if detailed_operation == "ANY" {
        String::from("ANY")
    }else if detailed_operation.contains("CREATE") {
        String::from("CREATE")
    }else if detailed_operation.contains("MODIFY") {
        String::from("WRITE")
    }else if detailed_operation.contains("REMOVE") {
        String::from("REMOVE")
    }else if detailed_operation.contains("ACCESS") {
        String::from("ACCESS")
    }else{
        String::from("OTHER")
    }
}

// ----------------------------------------------------------------------------

pub fn get_detailed_operation(event_kind: EventKind) -> String {
    match event_kind {
        EventKind::Any => { String::from("ANY") },

        EventKind::Create(CreateKind::Any) => { String::from("CREATE_ANY") },
        EventKind::Create(CreateKind::File) => { String::from("CREATE_FILE") },
        EventKind::Create(CreateKind::Folder) => { String::from("CREATE_FOLDER") },
        EventKind::Create(CreateKind::Other) => { String::from("CREATE_OTHER") },

        EventKind::Modify(ModifyKind::Any) => { String::from("MODIFY_ANY") },
        EventKind::Modify(ModifyKind::Data(DataChange::Any)) => { String::from("MODIFY_DATA_ANY") },
        EventKind::Modify(ModifyKind::Data(DataChange::Size)) => { String::from("MODIFY_DATA_SIZE") },
        EventKind::Modify(ModifyKind::Data(DataChange::Content)) => { String::from("MODIFY_DATA_CONTENT") },
        EventKind::Modify(ModifyKind::Data(DataChange::Other)) => { String::from("MODIFY_DATA_OTHER") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)) => { String::from("MODIFY_METADATA_ANY") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::AccessTime)) => { String::from("MODIFY_METADATA_ACCESSTIME") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)) => { String::from("MODIFY_METADATA_WRITETIME") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)) => { String::from("MODIFY_METADATA_PERMISSIONS") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Ownership)) => { String::from("MODIFY_METADATA_OWNERSHIP") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Extended)) => { String::from("MODIFY_METADATA_EXTENDED") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Other)) => { String::from("MODIFY_METADATA_OTHER") },
        EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => { String::from("MODIFY_RENAME_ANY") },
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => { String::from("MODIFY_RENAME_TO") },
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => { String::from("MODIFY_RENAME_FROM") },
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => { String::from("MODIFY_RENAME_BOTH") },
        EventKind::Modify(ModifyKind::Name(RenameMode::Other)) => { String::from("MODIFY_RENAME_OTHER") },
        EventKind::Modify(ModifyKind::Other) => { String::from("MODIFY_OTHER") },

        EventKind::Remove(RemoveKind::Any) => { String::from("REMOVE_ANY") },
        EventKind::Remove(RemoveKind::File) => { String::from("REMOVE_FILE") },
        EventKind::Remove(RemoveKind::Folder) => { String::from("REMOVE_FOLDER") },
        EventKind::Remove(RemoveKind::Other) => { String::from("REMOVE_OTHER") },

        EventKind::Access(AccessKind::Any) => { String::from("ACCESS_ANY") },
        EventKind::Access(AccessKind::Read) => { String::from("ACCESS_READ") },
        EventKind::Access(AccessKind::Open(AccessMode::Any)) => { String::from("ACCESS_OPEN_ANY") },
        EventKind::Access(AccessKind::Open(AccessMode::Execute)) => { String::from("ACCESS_OPEN_EXECUTE") },
        EventKind::Access(AccessKind::Open(AccessMode::Read)) => { String::from("ACCESS_OPEN_READ") },
        EventKind::Access(AccessKind::Open(AccessMode::Write)) => { String::from("ACCESS_OPEN_WRITE") },
        EventKind::Access(AccessKind::Open(AccessMode::Other)) => { String::from("ACCESS_OPEN_OTHER") },
        EventKind::Access(AccessKind::Close(AccessMode::Any)) => { String::from("ACCESS_CLOSE_ANY") },
        EventKind::Access(AccessKind::Close(AccessMode::Execute)) => { String::from("ACCESS_CLOSE_EXECUTE") },
        EventKind::Access(AccessKind::Close(AccessMode::Read)) => { String::from("ACCESS_CLOSE_READ") },
        EventKind::Access(AccessKind::Close(AccessMode::Write)) => { String::from("ACCESS_CLOSE_WRITE") },
        EventKind::Access(AccessKind::Close(AccessMode::Other)) => { String::from("ACCESS_CLOSE_OTHER") },
        EventKind::Access(AccessKind::Other) => { String::from("ACCESS_OTHER") },

        EventKind::Other => { String::from("OTHER") }
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

    //static mut GCONFIG: Option<config::Config> = None;

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
            operation: "CREATE".to_string(),
            detailed_operation: "CREATE_FILE".to_string(),
            checksum: "UNKNOWN".to_string(),
            fpid: 0,
            system: "test".to_string()
        }
    }

    fn initialize() {
        unsafe{
            super::super::GCONFIG = Some(config::Config::new(&utils::get_os(), None)); 
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_clone() {
        let event = create_test_event();
        let cloned = event.clone();
        assert_eq!(event.id, cloned.id);
        assert_eq!(event.timestamp, cloned.timestamp);
        assert_eq!(event.hostname, cloned.hostname);
        assert_eq!(event.node, cloned.node);
        assert_eq!(event.version, cloned.version);
        assert_eq!(event.path, cloned.path);
        assert_eq!(event.kind, cloned.kind);
        assert_eq!(event.labels, cloned.labels);
        assert_eq!(event.operation, cloned.operation);
        assert_eq!(event.detailed_operation, cloned.detailed_operation);
        assert_eq!(event.checksum, cloned.checksum);
        assert_eq!(event.fpid, cloned.fpid);
        assert_eq!(event.system, cloned.system);
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
        assert_eq!(evt.operation, String::from("CREATE"));
        assert_eq!(evt.detailed_operation, String::from("CREATE_FILE"));
        assert_eq!(evt.fpid, 0);
        assert_eq!(evt.system, String::from("test"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send() {
        initialize();
        let evt = create_test_event();
        block_on( evt.send(String::from("test")) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send_splunk() {
        initialize();
        let evt = create_test_event();
        unsafe {
            super::super::GCONFIG = Some(config::Config::new(&utils::get_os(), Some("test/unit/config/common/test_send_splunk.yml")));
        }
        block_on( evt.send(String::from("test")) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_operation(){
        assert_eq!(get_operation(EventKind::Create(CreateKind::Any)), String::from("CREATE"));
        assert_eq!(get_operation(EventKind::Modify(ModifyKind::Any)), String::from("WRITE"));
        assert_eq!(get_operation(EventKind::Remove(RemoveKind::Any)), String::from("REMOVE"));
        assert_eq!(get_operation(EventKind::Access(AccessKind::Any)), String::from("ACCESS"));
        assert_eq!(get_operation(EventKind::Other), String::from("OTHER"));
        assert_eq!(get_operation(EventKind::Any), String::from("ANY"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_detailed_operation(){
        assert_eq!(get_detailed_operation(EventKind::Any), String::from("ANY"));
        assert_eq!(get_detailed_operation(EventKind::Create(CreateKind::Any)),
            String::from("CREATE_ANY"));
        assert_eq!(get_detailed_operation(EventKind::Create(CreateKind::File)),
            String::from("CREATE_FILE"));
        assert_eq!(get_detailed_operation(EventKind::Create(CreateKind::Folder)),
            String::from("CREATE_FOLDER"));
        assert_eq!(get_detailed_operation(EventKind::Create(CreateKind::Other)),
            String::from("CREATE_OTHER"));

        assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Any)),
            String::from("MODIFY_ANY"));
        assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Data(DataChange::Any))),
            String::from("MODIFY_DATA_ANY"));
        assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Data(DataChange::Size))),
            String::from("MODIFY_DATA_SIZE"));
        assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Data(DataChange::Content))),
            String::from("MODIFY_DATA_CONTENT"));
        assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Data(DataChange::Other))),
            String::from("MODIFY_DATA_OTHER"));
        assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any))),
            String::from("MODIFY_METADATA_ANY"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Metadata(MetadataKind::AccessTime))),
            String::from("MODIFY_METADATA_ACCESSTIME"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Metadata(MetadataKind::WriteTime))),
            String::from("MODIFY_METADATA_WRITETIME"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Metadata(MetadataKind::Permissions))),
            String::from("MODIFY_METADATA_PERMISSIONS"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Metadata(MetadataKind::Ownership))),
            String::from("MODIFY_METADATA_OWNERSHIP"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Metadata(MetadataKind::Extended))),
            String::from("MODIFY_METADATA_EXTENDED"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Metadata(MetadataKind::Other))),
            String::from("MODIFY_METADATA_OTHER"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Name(RenameMode::Any))), String::from("MODIFY_RENAME_ANY"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Name(RenameMode::To))), String::from("MODIFY_RENAME_TO"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Name(RenameMode::From))), String::from("MODIFY_RENAME_FROM"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Name(RenameMode::Both))), String::from("MODIFY_RENAME_BOTH"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Name(RenameMode::Other))), String::from("MODIFY_RENAME_OTHER"));
        assert_eq!(get_detailed_operation(EventKind::Modify(
            ModifyKind::Other)), String::from("MODIFY_OTHER"));

        assert_eq!(get_detailed_operation(EventKind::Remove(
            RemoveKind::Any)), String::from("REMOVE_ANY"));
        assert_eq!(get_detailed_operation(EventKind::Remove(
            RemoveKind::File)), String::from("REMOVE_FILE"));
        assert_eq!(get_detailed_operation(EventKind::Remove(
            RemoveKind::Folder)), String::from("REMOVE_FOLDER"));
        assert_eq!(get_detailed_operation(EventKind::Remove(
            RemoveKind::Other)), String::from("REMOVE_OTHER"));

        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Any)), String::from("ACCESS_ANY"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Read)), String::from("ACCESS_READ"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Open(AccessMode::Any))), String::from("ACCESS_OPEN_ANY"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Open(AccessMode::Execute))), String::from("ACCESS_OPEN_EXECUTE"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Open(AccessMode::Read))), String::from("ACCESS_OPEN_READ"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Open(AccessMode::Write))), String::from("ACCESS_OPEN_WRITE"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Open(AccessMode::Other))), String::from("ACCESS_OPEN_OTHER"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Close(AccessMode::Any))), String::from("ACCESS_CLOSE_ANY"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Close(AccessMode::Execute))), String::from("ACCESS_CLOSE_EXECUTE"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Close(AccessMode::Read))), String::from("ACCESS_CLOSE_READ"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Close(AccessMode::Write))), String::from("ACCESS_CLOSE_WRITE"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Close(AccessMode::Other))), String::from("ACCESS_CLOSE_OTHER"));
        assert_eq!(get_detailed_operation(EventKind::Access(
            AccessKind::Other)), String::from("ACCESS_OTHER"));

        assert_eq!(get_detailed_operation(EventKind::Other), String::from("OTHER"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_process() {
        let config = Config::new(&utils::get_os(), None);
        let event = create_test_event();

        block_on(event.process(config::NETWORK_MODE, String::from("test"), config.clone()));
        block_on(event.process(config::FILE_MODE, String::from("test2"), config.clone()));
        block_on(event.process(config::BOTH_MODE, String::from("test3"), config.clone()));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_event_fmt(){
        let out = format!("{:?}", create_test_event());
        assert_eq!(out, "(\"Test_id\", \"\", \"CREATE\", \"CREATE_FILE\")");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_format_json() {
        let expected = "{\"checksum\":\"UNKNOWN\",\"detailed_operation\":\"CREATE_FILE\",\
            \"file\":\"\",\"fpid\":0,\
            \"hostname\":\"Hostname\",\"id\":\"Test_id\",\"labels\":[],\
            \"node\":\"FIM\",\"operation\":\"CREATE\",\"system\":\"test\",\
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
        let expected = "{\"checksum\":\"UNKNOWN\",\"detailed_operation\":\"CREATE_FILE\",\
            \"file\":\"\",\"fpid\":0,\
            \"hostname\":\"Hostname\",\"id\":\"Test_id\",\"labels\":[],\
            \"node\":\"FIM\",\"operation\":\"CREATE\",\
            \"system\":\"test\",\
            \"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}\n";
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename.clone());
    }
}