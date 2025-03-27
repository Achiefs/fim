// Copyright (C) 2024, Achiefs.

// Global constants definitions
pub const REMOVE: &str = "REMOVE";
pub const CREATE: &str = "CREATE";
pub const WRITE: &str = "WRITE";

use crate::appconfig;
use crate::appconfig::*;
use crate::dbfile::*;

use log::*;
use std::fs::OpenOptions;
use serde_json::{json, to_string};
use std::io::Write;
use reqwest::Client;
use std::time::Duration;

pub struct HashEvent {
    previous_dbfile: Option<DBFile>,
    dbfile: DBFile,
    operation: String,
}

#[cfg(test)]
mod test;

impl HashEvent {
    pub fn new(previous_dbfile: Option<DBFile>, dbfile: DBFile, operation: String) -> Self {
        HashEvent {
            previous_dbfile,
            dbfile,
            operation,
        }
    }

    // ------------------------------------------------------------------------

    fn log(&self, file: String) {
        let mut events_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file)
            .expect("(hashevent::log) Unable to open events log file.");

            match writeln!(events_file, "{}", self.format_json()) {
                Ok(_d) => debug!("Hash event log written"),
                Err(e) => error!("Hash event could not be written, Err: [{}]", e)
            };
    }

    // ------------------------------------------------------------------------

    async fn send(&self, cfg: AppConfig) {
        use time::OffsetDateTime;

        let event = self.get_json();
        let current_date = OffsetDateTime::now_utc();
        let index = format!("fim-{}-{}-{}", current_date.year(), current_date.month() as u8, current_date.day() );

        // Splunk endpoint integration
        if cfg.endpoint_type == "Splunk" {
            let data = json!({
                "source": cfg.node,
                "sourcetype": "_json",
                "event": event,
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
            let request_url = format!("{}/{}/_doc/{}", cfg.endpoint_address, index, self.dbfile.id);
            let client = Client::builder()
                .danger_accept_invalid_certs(cfg.insecure)
                .timeout(Duration::from_secs(30))
                .build().unwrap();
            match client
                .post(request_url)
                .basic_auth(cfg.endpoint_user, Some(cfg.endpoint_pass))
                .json(&event)
                .send()
                .await {
                    Ok(response) => debug!("Response received: {:?}",
                        response.text().await.unwrap()),
                    Err(e) => debug!("Error on request: {:?}", e)
            }
        }
    }

    // ------------------------------------------------------------------------

    pub async fn process(&self, cfg: AppConfig) {
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

    fn format_json(&self) -> String { to_string(&self.get_json()).unwrap() }

    // ------------------------------------------------------------------------

    fn get_json(&self) -> serde_json::Value {
        match &self.previous_dbfile {
            Some(data) => {
                json!({
                    "previous_dbfile.id": data.id.clone(),
                    "previous_dbfile.timestamp": data.timestamp.clone(),
                    "previous_dbfile.hash": data.hash.clone(),
                    "previous_dbfile.path": data.path.clone(),
                    "previous_dbfile.size": data.size.clone(),
                    "previous_dbfile.permissions": data.permissions.clone(),
                    "dbfile.id": self.dbfile.id.clone(),
                    "dbfile.timestamp": self.dbfile.timestamp.clone(),
                    "dbfile.hash": self.dbfile.hash.clone(),
                    "dbfile.path": self.dbfile.path.clone(),
                    "dbfile.size": self.dbfile.size.clone(),
                    "dbfile.permissions": self.dbfile.permissions.clone(),
                    "operation": self.operation.clone(),
                })
            },
            None => json!({
                "dbfile.id": self.dbfile.id.clone(),
                "dbfile.timestamp": self.dbfile.timestamp.clone(),
                "dbfile.hash": self.dbfile.hash.clone(),
                "dbfile.path": self.dbfile.path.clone(),
                "dbfile.size": self.dbfile.size.clone(),
                "dbfile.permissions": self.dbfile.permissions.clone(),
                "operation": self.operation.clone(),
            })
        }

    }
}