// Copyright (C) 2024, Achiefs.

#[cfg(test)]
mod tests;

pub const REMOVE: &str = "REMOVE";
pub const CREATE: &str = "CREATE";
pub const WRITE: &str = "WRITE";

use crate::appconfig;
use crate::appconfig::*;
use crate::dbfile::*;

use log::*;
use std::fs::OpenOptions;
use serde::Serialize;
use serde_json::json;
use std::io::Write;
use reqwest::Client;
use std::time::Duration;

#[derive(Clone, Serialize, Debug)]
pub struct HashEvent {
    previous_dbfile: Option<DBFile>,
    dbfile: DBFile,
    operation: String,
}

impl HashEvent {
    pub fn new(previous_dbfile: Option<DBFile>, dbfile: DBFile, operation: String) -> Self {
        HashEvent {
            previous_dbfile,
            dbfile,
            operation,
        }
    }

    // ------------------------------------------------------------------------

    pub fn log(&self, cfg: AppConfig) {
        let file = cfg.events_lock.lock().unwrap();
        let mut events_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file.as_str())
            .expect("(hashevent::log) Unable to open events log file.");

            match writeln!(events_file, "{}", self.to_json()) {
                Ok(_d) => debug!("Hash event log written"),
                Err(e) => error!("Hash event could not be written, Err: [{}]", e)
            };
    }

    // ------------------------------------------------------------------------

    async fn send(&self, cfg: AppConfig) {
        use time::OffsetDateTime;

        let event = self.to_json();
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

    pub fn to_json(&self) -> String { serde_json::to_string(self).unwrap() }
}