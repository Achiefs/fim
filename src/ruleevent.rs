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
//use std::fmt;
use std::io::Write;

pub struct RuleEvent {
    pub id: usize,
    pub rule: String,
    pub timestamp: String,
    pub hostname: String,
    pub node: String,
    pub version: String,
    pub path: PathBuf,
    pub fpid: u32,
    pub system: String,
    pub message: String
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

impl Event for RuleEvent {
    // Get formatted string with all required data
    fn format_json(&self) -> String {
        let obj = json!({
            "id": self.id.clone(),
            "rule": self.rule.clone(),
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.node.clone(),
            "fpid": self.fpid.clone(),
            "version": self.version.clone(),
            "system": self.system.clone(),
            "message": self.message.clone()
        });
        to_string(&obj).unwrap()
    }

    // ------------------------------------------------------------------------

    fn clone(&self) -> Self {
        RuleEvent {
            id: self.id.clone(),
            rule: self.rule.clone(),
            timestamp: self.timestamp.clone(),
            hostname: self.hostname.clone(),
            node: self.node.clone(),
            version: self.version.clone(),
            path: self.path.clone(),
            fpid: self.fpid,
            system: self.system.clone(),
            message: self.message.clone()
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
                    "rule": self.rule.clone(),
                    "timestamp": self.timestamp.clone(),
                    "hostname": self.hostname.clone(),
                    "node": self.node.clone(),
                    "fpid": self.fpid.clone(),
                    "version": self.version.clone(),
                    "system": self.system.clone(),
                    "message": self.message.clone()
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
                "node": self.node.clone(),
                "fpid": self.fpid.clone(),
                "version": self.version.clone(),
                "system": self.system.clone(),
                "message": self.message.clone()
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
                self.log(cfg.get_events_file());
                self.send(cfg).await;
            },
            appconfig::NETWORK_MODE => {
                self.send(cfg).await;
            },
            _ => self.log(cfg.get_events_file())
        }
    }

    // ------------------------------------------------------------------------

    fn get_string(&self, field: String) -> String {
        match field.as_str() {
            "rule" => self.rule.clone(),
            "path" => String::from(self.path.to_str().unwrap()),
            "hostname" => self.hostname.clone(),
            "node" => self.node.clone(),
            "version" => self.version.clone(),
            "system" => self.system.clone(),
            "message" => self.message.clone(),
            _ => "".to_string()
        }
    }
}