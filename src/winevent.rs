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

pub struct WinEvent {
    pub id: String,
    pub timestamp: String,
    pub hostname: String,
    pub node: String,
    pub version: String,
    pub path: PathBuf,
    pub size: u64,
    pub labels: Vec<String>,
    pub operations: Vec<String>,
    pub checksum: String,
    pub fpid: u32,
    pub system: String,

    pub subject_user_sid: String,
    pub subject_user_name: String,
    pub subject_domain_name: String,
    pub subject_logon_id: String,
    pub object_server: String,
    pub object_type: String,
    pub object_name: String,
    pub handle_id: String,
    pub transaction_id: String,
    pub access_list: Vec<String>,
    pub access_reason: String,
    pub access_mask: String,
    pub privilege_list: String,
    pub restricted_sid_count: String,
    pub process_id: String,
    pub process_name: String,
    pub resource_attributes: String
}



impl Event for WinEvent {
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
          "operations": self.operations.clone(),
          "file": String::from(self.path.clone().to_str().unwrap()),
          "file_size": self.size.clone(),
          "checksum": self.checksum.clone(),
          "system": self.system.clone(),

          "subject_user_sid": self.subject_user_sid.clone(),
          "subject_user_name": self.subject_user_name.clone(),
          "subject_domain_name": self.subject_domain_name.clone(),
          "subject_logon_id": self.subject_logon_id.clone(),
          "object_server": self.object_server.clone(),
          "object_type": self.object_type.clone(),
          "object_name": self.object_name.clone(),
          "handle_id": self.handle_id.clone(),
          "transaction_id": self.transaction_id.clone(),
          "access_list": self.access_list.clone(),
          "access_reason": self.access_reason.clone(),
          "access_mask": self.access_mask.clone(),
          "privilege_list": self.privilege_list.clone(),
          "restricted_sid_count": self.restricted_sid_count.clone(),
          "process_id": self.process_id.clone(),
          "process_name": self.process_name.clone(),
          "resource_attributes": self.resource_attributes.clone()
      });
      to_string(&obj).unwrap()
  }

  // ------------------------------------------------------------------------

  fn clone(&self) -> Self {
        WinEvent {
            id: self.id.clone(),
            timestamp: self.timestamp.clone(),
            hostname: self.hostname.clone(),
            node: self.node.clone(),
            version: self.version.clone(),
            path: self.path.clone(),
            size: self.size,
            labels: self.labels.clone(),
            operations: self.operations.clone(),
            checksum: self.checksum.clone(),
            fpid: self.fpid,
            system: self.system.clone(),

            subject_user_sid: self.subject_user_sid.clone(),
            subject_user_name: self.subject_user_name.clone(),
            subject_domain_name: self.subject_domain_name.clone(),
            subject_logon_id: self.subject_logon_id.clone(),
            object_server: self.object_server.clone(),
            object_type: self.object_type.clone(),
            object_name: self.object_name.clone(),
            handle_id: self.handle_id.clone(),
            transaction_id: self.transaction_id.clone(),
            access_list: self.access_list.clone(),
            access_reason: self.access_reason.clone(),
            access_mask: self.access_mask.clone(),
            privilege_list: self.privilege_list.clone(),
            restricted_sid_count: self.restricted_sid_count.clone(),
            process_id: self.process_id.clone(),
            process_name: self.process_name.clone(),
            resource_attributes: self.resource_attributes.clone(),
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
                    "operations": self.operations.clone(),
                    "file": String::from(self.path.clone().to_str().unwrap()),
                    "file_size": self.size.clone(),
                    "checksum": self.checksum.clone(),
                    "system": self.system.clone(),

                    "subject_user_sid": self.subject_user_sid.clone(),
                    "subject_user_name": self.subject_user_name.clone(),
                    "subject_domain_name": self.subject_domain_name.clone(),
                    "subject_logon_id": self.subject_logon_id.clone(),
                    "object_server": self.object_server.clone(),
                    "object_type": self.object_type.clone(),
                    "object_name": self.object_name.clone(),
                    "handle_id": self.handle_id.clone(),
                    "transaction_id": self.transaction_id.clone(),
                    "access_list": self.access_list.clone(),
                    "access_reason": self.access_reason.clone(),
                    "access_mask": self.access_mask.clone(),
                    "privilege_list": self.privilege_list.clone(),
                    "restricted_sid_count": self.restricted_sid_count.clone(),
                    "process_id": self.process_id.clone(),
                    "process_name": self.process_name.clone(),
                    "resource_attributes": self.resource_attributes.clone()
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
                "operations": self.operations.clone(),
                "file": String::from(self.path.clone().to_str().unwrap()),
                "file_size": self.size.clone(),
                "checksum": self.checksum.clone(),
                "system": self.system.clone(),

                "subject_user_sid": self.subject_user_sid.clone(),
                "subject_user_name": self.subject_user_name.clone(),
                "subject_domain_name": self.subject_domain_name.clone(),
                "subject_logon_id": self.subject_logon_id.clone(),
                "object_server": self.object_server.clone(),
                "object_type": self.object_type.clone(),
                "object_name": self.object_name.clone(),
                "handle_id": self.handle_id.clone(),
                "transaction_id": self.transaction_id.clone(),
                "access_list": self.access_list.clone(),
                "access_reason": self.access_reason.clone(),
                "access_mask": self.access_mask.clone(),
                "privilege_list": self.privilege_list.clone(),
                "restricted_sid_count": self.restricted_sid_count.clone(),
                "process_id": self.process_id.clone(),
                "process_name": self.process_name.clone(),
                "resource_attributes": self.resource_attributes.clone()
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
        //match filter(self, cfg.clone()){
        //    true => {
                route(self, cfg.clone()).await;
                _ruleset.match_rule(cfg, self.path.clone(), self.id.clone()).await;
        //    },
        //    false => debug!("Event discarded, not match monitoring path.")
        //}
    }

    // ------------------------------------------------------------------------

    fn get_string(&self, field: String) -> String {
        match field.as_str() {
            "file" => String::from(self.path.to_str().unwrap()),
            "file_size" => self.size.clone().to_string(),
            "hostname" => self.hostname.clone(),
            "node" => self.node.clone(),
            "version" => self.version.clone(),
            "operations" => self.operations.clone().iter().map(|x| x.to_string() + ",").collect(),
            "checksum" => self.checksum.clone(),
            "system" => self.system.clone(),

            "subject_user_sid" => self.subject_user_sid.clone(),
            "subject_user_name" => self.subject_user_name.clone(),
            "subject_domain_name" => self.subject_domain_name.clone(),
            "subject_logon_id" => self.subject_logon_id.clone(),
            "object_server" => self.object_server.clone(),
            "object_type" => self.object_type.clone(),
            "object_name" => self.object_name.clone(),
            "handle_id" => self.handle_id.clone(),
            "transaction_id" => self.transaction_id.clone(),
            "access_list" => self.access_list.clone().iter().map(|x| x.to_string() + ",").collect(),
            "access_reason" => self.access_reason.clone(),
            "access_mask" => self.access_mask.clone(),
            "privilege_list" => self.privilege_list.clone(),
            "restricted_sid_count" => self.restricted_sid_count.clone(),
            "process_id" => self.process_id.clone(),
            "process_name" => self.process_name.clone(),
            "resource_attributes" => self.resource_attributes.clone(),
            _ => "".to_string()
        }
    }
}

// ----------------------------------------------------------------------------

impl fmt::Debug for WinEvent {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
      f.debug_tuple("")
        .field(&self.id)
        .field(&self.path)
        .field(&self.size)
        .field(&self.operations)
        .field(&self.subject_user_sid)
        .field(&self.subject_user_name)
        .field(&self.subject_domain_name)
        .field(&self.subject_logon_id)
        .field(&self.object_server)
        .field(&self.object_type)
        .field(&self.object_name)
        .field(&self.handle_id)
        .field(&self.transaction_id)
        .field(&self.access_list)
        .field(&self.access_reason)
        .field(&self.access_mask)
        .field(&self.privilege_list)
        .field(&self.restricted_sid_count)
        .field(&self.process_id)
        .field(&self.process_name)
        .field(&self.resource_attributes)
        .finish()
  }
}

// ----------------------------------------------------------------------------

pub fn filter (event: &WinEvent, cfg: AppConfig) -> bool {
    let index = cfg.get_index(event.path.to_str().unwrap(), "", cfg.clone().monitor.to_vec());
    index != usize::MAX
}

// ----------------------------------------------------------------------------

pub async fn route(event: &WinEvent, cfg: AppConfig) {
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
    use crate::winevent::WinEvent;
    use crate::event::*;
    use crate::utils;
    use std::path::PathBuf;
    use tokio_test::block_on;
    use std::fs;

    // ------------------------------------------------------------------------

    fn remove_test_file(filename: String) {
        fs::remove_file(filename).unwrap()
    }

    fn create_test_event() -> WinEvent {
        WinEvent {
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            node: "FIM".to_string(),
            version: "x.x.x".to_string(),
            path: PathBuf::new(),
            size: 0,
            labels: Vec::new(),
            operations: Vec::new(),
            checksum: "UNKNOWN".to_string(),
            fpid: 0,
            system: "test".to_string(),

            subject_user_sid: "SubjecUserSid".to_string(),
            subject_user_name: "SubjectUserName".to_string(),
            subject_domain_name: "SubjectDomainName".to_string(),
            subject_logon_id: "SubjectLogonId".to_string(),
            object_server: "ObjectServer".to_string(),
            object_type: "ObjectType".to_string(),
            object_name: "ObjectName".to_string(),
            handle_id: "HandleId".to_string(),
            transaction_id: "TransactionId".to_string(),
            access_list: "AccessList".to_string(),
            access_reason: "AccessReason".to_string(),
            access_mask: "AccessMask".to_string(),
            privilege_list: "PrivilegeList".to_string(),
            restricted_sid_count: "RestrictedSidCount".to_string(),
            process_id: "ProcessId".to_string(),
            process_name: "ProcessName".to_string(),
            resource_attributes: "ResourceAttributes".to_string()
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
        assert_eq!(event.labels, cloned.labels);
        assert_eq!(event.operations, cloned.operations);
        assert_eq!(event.checksum, cloned.checksum);
        assert_eq!(event.fpid, cloned.fpid);
        assert_eq!(event.system, cloned.system);

        assert_eq!(event.subject_user_sid, cloned.subject_user_sid);
        assert_eq!(event.subject_user_name, cloned.subject_user_name);
        assert_eq!(event.subject_domain_name, cloned.subject_domain_name);
        assert_eq!(event.subject_logon_id, cloned.subject_logon_id);
        assert_eq!(event.object_server, cloned.object_server);
        assert_eq!(event.object_type, cloned.object_type);
        assert_eq!(event.object_name, cloned.object_name);
        assert_eq!(event.handle_id, cloned.handle_id);
        assert_eq!(event.transaction_id, cloned.transaction_id);
        assert_eq!(event.access_list, cloned.access_list);
        assert_eq!(event.access_reason, cloned.access_reason);
        assert_eq!(event.access_mask, cloned.access_mask);
        assert_eq!(event.privilege_list, cloned.privilege_list);
        assert_eq!(event.restricted_sid_count, cloned.restricted_sid_count);
        assert_eq!(event.process_id, cloned.process_id);
        assert_eq!(event.process_name, cloned.process_name);
        assert_eq!(event.resource_attributes, cloned.resource_attributes);
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
        assert_eq!(evt.path, PathBuf::new());
        assert_eq!(evt.labels, Vec::<String>::new());
        assert_eq!(evt.operations, Vec::new());
        assert_eq!(evt.fpid, 0);
        assert_eq!(evt.system, String::from("test"));

        assert_eq!(evt.subject_user_sid, String::from("SubjecUserSid"));
        assert_eq!(evt.subject_user_name, String::from("SubjectUserName"));
        assert_eq!(evt.subject_domain_name, String::from("SubjectDomainName"));
        assert_eq!(evt.subject_logon_id, String::from("SubjectLogonId"));
        assert_eq!(evt.object_server, String::from("ObjectServer"));
        assert_eq!(evt.object_type, String::from("ObjectType"));
        assert_eq!(evt.object_name, String::from("ObjectName"));
        assert_eq!(evt.handle_id, String::from("HandleId"));
        assert_eq!(evt.transaction_id, String::from("TransactionId"));
        assert_eq!(evt.access_list, Vec::new());
        assert_eq!(evt.access_reason, String::from("AccessReason"));
        assert_eq!(evt.access_mask, String::from("AccessMask"));
        assert_eq!(evt.privilege_list, String::from("PrivilegeList"));
        assert_eq!(evt.restricted_sid_count, String::from("RestrictedSidCount"));
        assert_eq!(evt.process_id, String::from("ProcessId"));
        assert_eq!(evt.process_name, String::from("ProcessName"));
        assert_eq!(evt.resource_attributes, String::from("ResourceAttributes"));
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
        let expected = "{\"checksum\":\"UNKNOWN\",\
            \"file\":\"\",\"file_size\":0,\"fpid\":0,\
            \"hostname\":\"Hostname\",\"id\":\"Test_id\",\"labels\":[],\
            \"node\":\"FIM\",\"operations\":\"CREATE\",\"system\":\"test\",\
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
        let expected = "{\"checksum\":\"UNKNOWN\",\
            \"file\":\"\",\"file_size\":0,\"fpid\":0,\
            \"hostname\":\"Hostname\",\"id\":\"Test_id\",\"labels\":[],\
            \"node\":\"FIM\",\"operations\":\"CREATE\",\
            \"system\":\"test\",\
            \"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}\n";
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename.clone());
    }
}