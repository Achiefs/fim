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
use std::io::Write;

pub struct RuleEvent {
    pub id: usize,
    pub rule: String,
    pub timestamp: String,
    pub hostname: String,
    pub version: String,
    pub path: PathBuf,
    pub fpid: u32,
    pub system: String,
    pub message: String,
    pub parent_id: String
}

// ----------------------------------------------------------------------------

impl Event for RuleEvent {
    // Get formatted string with all required data
    fn format_json(&self) -> String {
        let obj = json!({
            "id": self.id.clone(),
            "rule": self.rule.clone(),
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "fpid": self.fpid.clone(),
            "version": self.version.clone(),
            "system": self.system.clone(),
            "message": self.message.clone(),
            "parent_id": self.parent_id.clone()
        });
        to_string(&obj).unwrap()
    }

    // ------------------------------------------------------------------------

    fn clone(&self) -> Self {
        RuleEvent {
            id: self.id,
            rule: self.rule.clone(),
            timestamp: self.timestamp.clone(),
            hostname: self.hostname.clone(),
            version: self.version.clone(),
            path: self.path.clone(),
            fpid: self.fpid,
            system: self.system.clone(),
            message: self.message.clone(),
            parent_id: self.parent_id.clone()
        }
    }

    // ------------------------------------------------------------------------

    // Function to write the received events to file
    fn log(&self, cfg: AppConfig) {
        let file = cfg.events_lock.lock().unwrap();
        let mut events_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file.as_str())
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
                "source": "FIM_RULESET",
                "sourcetype": "_json",
                "event": json!({
                    "rule": self.rule.clone(),
                    "timestamp": self.timestamp.clone(),
                    "hostname": self.hostname.clone(),
                    "fpid": self.fpid.clone(),
                    "version": self.version.clone(),
                    "system": self.system.clone(),
                    "message": self.message.clone(),
                    "parent_id": self.parent_id.clone()
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
                "rule": self.rule.clone(),
                "timestamp": self.timestamp.clone(),
                "hostname": self.hostname.clone(),
                "fpid": self.fpid.clone(),
                "version": self.version.clone(),
                "system": self.system.clone(),
                "message": self.message.clone(),
                "parent_id": self.parent_id.clone()
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
        match cfg.get_events_destination().as_str() {
            appconfig::BOTH_MODE => {
                self.log(cfg.clone());
                self.send(cfg).await;
            },
            appconfig::NETWORK_MODE => {
                self.send(cfg).await;
            },
            _ => self.log(cfg.clone())
        }
    }

    // ------------------------------------------------------------------------

    fn get_string(&self, field: String) -> String {
        match field.as_str() {
            "rule" => self.rule.clone(),
            "path" => String::from(self.path.to_str().unwrap()),
            "hostname" => self.hostname.clone(),
            "version" => self.version.clone(),
            "system" => self.system.clone(),
            "message" => self.message.clone(),
            "parent_id" => self.parent_id.clone(),
            _ => "".to_string()
        }
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use std::path::PathBuf;
    use tokio_test::block_on;
    use std::fs;

    // ------------------------------------------------------------------------

    fn remove_test_file(filename: String) {
        fs::remove_file(filename).unwrap()
    }

    fn create_test_event() -> RuleEvent {
        RuleEvent {
            id: 0,
            rule: "\\.php$".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            version: "x.x.x".to_string(),
            path: PathBuf::new(),
            fpid: 0,
            system: "test".to_string(),
            message: "This is a message".to_string(),
            parent_id: "0000".to_string()
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
        assert_eq!(event.version, cloned.version);
        assert_eq!(event.path, cloned.path);
        assert_eq!(event.fpid, cloned.fpid);
        assert_eq!(event.system, cloned.system);
        assert_eq!(event.message, cloned.message);
        assert_eq!(event.parent_id, cloned.parent_id);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_new() {
        let evt = create_test_event();
        assert_eq!(evt.id, 0);
        assert_eq!(evt.timestamp, "Timestamp".to_string());
        assert_eq!(evt.hostname, "Hostname".to_string());
        assert_eq!(evt.version, "x.x.x".to_string());
        assert_eq!(evt.path, PathBuf::new());
        assert_eq!(evt.fpid, 0);
        assert_eq!(evt.system, String::from("test"));
        assert_eq!(evt.message, String::from("This is a message"));
        assert_eq!(evt.parent_id, String::from("0000"));
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
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_format_json() {
        let expected = "{\"fpid\":0,\"hostname\":\"Hostname\",\"id\":0,\"message\":\"This is a message\",\
        \"parent_id\":\"0000\",\"rule\":\"\\\\.php$\",\"system\":\"test\",\"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}";
        assert_eq!(create_test_event().format_json(), expected);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_log() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/common/test_log_ruleevent.yml"));
        let filename = String::from("test_ruleevent.json");
        let evt = create_test_event();

        evt.log(cfg.clone());
        let contents = fs::read_to_string(filename.clone());
        let expected = "{\"fpid\":0,\"hostname\":\"Hostname\",\"id\":0,\"message\":\"This is a message\",\
        \"parent_id\":\"0000\",\"rule\":\"\\\\.php$\",\"system\":\"test\",\"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}\n";
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename.clone());
    }
}