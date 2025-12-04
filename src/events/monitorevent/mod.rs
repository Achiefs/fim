// Copyright (C) 2024, Achiefs.

#[cfg(test)]
mod tests;

use crate::appconfig;
use crate::appconfig::*;
use crate::ruleset::*;

use log::*;
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
use reqwest::Client;
use std::fs::OpenOptions;
use std::time::Duration;
use std::io::Write;

#[derive(Clone, Serialize, Debug)]
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

impl MonitorEvent {

    // Get formatted string with all required data
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    // ------------------------------------------------------------------------

    // Function to write the received events to file
    pub fn log(&self, cfg: AppConfig) {
        let file = cfg.events_lock.lock().unwrap();
        let mut events_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file.as_str())
            .expect("(log) Unable to open events log file.");

        match writeln!(events_file, "{}", self.to_json() ) {
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
    pub async fn process(&self, cfg: AppConfig, _ruleset: Ruleset) {
        route(self, cfg.clone()).await;
        _ruleset.match_rule(cfg, self.path.clone(), self.id.clone()).await;
    }

    // ------------------------------------------------------------------------

    pub fn get_string(&self, field: String) -> String {
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

pub async fn route(event: &MonitorEvent, cfg: AppConfig) {
    match cfg.get_events_destination().as_str() {
        appconfig::BOTH_MODE => {
            event.log(cfg.clone());
            event.send(cfg).await;
        },
        appconfig::NETWORK_MODE => {
            event.send(cfg).await;
        },
        _ => event.log(cfg.clone())
    }
}