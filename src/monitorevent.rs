// Copyright (C) 2024, Achiefs.

use crate::event;
use crate::appconfig;
use crate::appconfig::*;
use crate::ruleset::*;

use event::Event;
use log::*;
use serde_json::{json, to_string};
use std::path::PathBuf;
use reqwest::Client;
use std::fs::OpenOptions;
use std::time::Duration;
use std::fmt;
use std::io::Write;


pub struct MonitorEvent {
  pub id: String,
  pub timestamp: String,
  pub hostname: String,
  pub node: String,
  pub version: String,
  pub path: PathBuf,
  pub size: u64,
  pub kind: notify::EventKind,
  pub labels: Vec<String>,
  pub operation: String,
  pub detailed_operation: String,
  pub checksum: String,
  pub fpid: u32,
  pub system: String
}



impl Event for MonitorEvent {
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
          "detailed_operation": self.detailed_operation.clone(),
          "file": String::from(self.path.clone().to_str().unwrap()),
          "file_size": self.size.clone(),
          "checksum": self.checksum.clone(),
          "system": self.system.clone()
      });
      to_string(&obj).unwrap()
  }

  // ------------------------------------------------------------------------

  fn clone(&self) -> Self {
      MonitorEvent {
          id: self.id.clone(),
          timestamp: self.timestamp.clone(),
          hostname: self.hostname.clone(),
          node: self.node.clone(),
          version: self.version.clone(),
          path: self.path.clone(),
          size: self.size,
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
  fn log(&self, file: String) {
      let mut events_file = OpenOptions::new()
          .create(true)
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
  async fn send(&self, cfg: AppConfig) {
        use time::OffsetDateTime;
        let current_date = OffsetDateTime::now_utc();
        let index = format!("fim-{}-{}-{}", current_date.year(), current_date.month() as u8, current_date.day() );
        
        // Splunk endpoint integration
        if cfg.endpoint_type == "Splunk" {
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
                    "file_size": self.size.clone(),
                    "checksum": self.checksum.clone(),
                    "system": self.system.clone()
                }),
                "index": "fim_events"
            });
            debug!("Sending received event to Splunk integration, event: {}", data);
            let request_url = format!("{}/services/collector/event", cfg.endpoint_address);
            let client = Client::builder()
                .danger_accept_invalid_certs(cfg.insecure)
                .timeout(Duration::from_secs(30))
                .build().unwrap();
            match client
                .post(request_url)
                .header("Authorization", format!("Splunk {}", cfg.endpoint_token))
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
                "file_size": self.size.clone(),
                "checksum": self.checksum.clone(),
                "system": self.system.clone()
            });
            let request_url = format!("{}/{}/_doc/{}", cfg.endpoint_address, index, self.id);
            let client = Client::builder()
                .danger_accept_invalid_certs(cfg.insecure)
                .timeout(Duration::from_secs(30))
                .build().unwrap();
            match client
                .post(request_url)
                .basic_auth(cfg.endpoint_user, Some(cfg.endpoint_pass))
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
    async fn process(&self, cfg: AppConfig, _ruleset: Ruleset) {
        _ruleset.match_rule(cfg.clone(), self.path.clone()).await;
        route(self, cfg).await;
    }

    // ------------------------------------------------------------------------

    fn get_string(&self, field: String) -> String {
        match field.as_str() {
            "path" => String::from(self.path.to_str().unwrap()),
            "file_size" => self.size.clone().to_string(),
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

impl fmt::Debug for MonitorEvent {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
      f.debug_tuple("")
        .field(&self.id)
        .field(&self.path)
        .field(&self.size)
        .field(&self.operation)
        .field(&self.detailed_operation)
        .finish()
  }
}

// ----------------------------------------------------------------------------

pub async fn route(event: &MonitorEvent, cfg: AppConfig) {
  match cfg.get_events_destination().as_str() {
      appconfig::BOTH_MODE => {
          event.log(cfg.get_events_file());
          event.send(cfg).await;
      },
      appconfig::NETWORK_MODE => {
          event.send(cfg).await;
      },
      _ => event.log(cfg.get_events_file())
  }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitorevent::MonitorEvent;
    use crate::event::*;
    use crate::utils;
    use std::path::PathBuf;
    use tokio_test::block_on;
    use std::fs;
    use notify::EventKind;
    use notify::event::{CreateKind, ModifyKind, RemoveKind, AccessKind, MetadataKind,
        DataChange, RenameMode, AccessMode};

    // ------------------------------------------------------------------------

    fn remove_test_file(filename: String) {
        fs::remove_file(filename).unwrap()
    }

    fn create_test_event() -> MonitorEvent {
        MonitorEvent {
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            node: "FIM".to_string(),
            version: "x.x.x".to_string(),
            kind: EventKind::Create(CreateKind::Any),
            path: PathBuf::new(),
            size: 0,
            labels: Vec::new(),
            operation: "CREATE".to_string(),
            detailed_operation: "CREATE_FILE".to_string(),
            checksum: "UNKNOWN".to_string(),
            fpid: 0,
            system: "test".to_string()
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
        assert_eq!(event.size, cloned.size);
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
        let evt = create_test_event();
        let cfg = AppConfig::new(&utils::get_os(), None);
        block_on( evt.send(cfg) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send_splunk() {
        let evt = create_test_event();
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/common/test_send_splunk.yml"));
        block_on( evt.send(cfg) );
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
        let event = create_test_event();
        let cfg = AppConfig::new(&utils::get_os(), None);
        let ruleset = Ruleset::new(&utils::get_os(), None);  

        block_on(event.process(cfg, ruleset));
        //block_on(event.process(appconfig::NETWORK_MODE, String::from("test"), cfg.clone()));
        //block_on(event.process(appconfig::FILE_MODE, String::from("test2"), cfg.clone()));
        //block_on(event.process(appconfig::BOTH_MODE, String::from("test3"), cfg.clone()));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_event_fmt(){
        let out = format!("{:?}", create_test_event());
        assert_eq!(out, "(\"Test_id\", \"\", 0, \"CREATE\", \"CREATE_FILE\")");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_format_json() {
        let expected = "{\"checksum\":\"UNKNOWN\",\"detailed_operation\":\"CREATE_FILE\",\
            \"file\":\"\",\"file_size\":0,\"fpid\":0,\
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
            \"file\":\"\",\"file_size\":0,\"fpid\":0,\
            \"hostname\":\"Hostname\",\"id\":\"Test_id\",\"labels\":[],\
            \"node\":\"FIM\",\"operation\":\"CREATE\",\
            \"system\":\"test\",\
            \"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}\n";
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename.clone());
    }
}