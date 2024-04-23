// Copyright (C) 2024, Achiefs.

use crate::event;
use crate::config;

use event::Event;
use log::*;
use serde_json::{json, to_string};
use std::path::PathBuf;
use reqwest::Client;
use std::fs::OpenOptions;
use std::time::Duration;
//use std::fmt;
use std::io::Write;

pub struct MonitorRuleEvent {
    pub id: String,
    pub cid: String,
    pub rule: String,
    pub timestamp: String,
    pub hostname: String,
    pub node: String,
    pub version: String,
    pub path: PathBuf,
    pub labels: Vec<String>,
    pub fpid: u32,
    pub system: String,
    pub message: String
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

impl Event for MonitorRuleEvent {
    // Get formatted string with all required data
    fn format_json(&self) -> String {
        let obj = json!({
            "id": self.id.clone(),
            "cid": self.cid.clone(),
            "rule": self.rule.clone(),
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.node.clone(),
            "fpid": self.fpid.clone(),
            "version": self.version.clone(),
            "labels": self.labels.clone(),
            "system": self.system.clone(),
            "message": self.message.clone()
        });
        to_string(&obj).unwrap()
    }

    // ------------------------------------------------------------------------

    fn clone(&self) -> Self {
        MonitorRuleEvent {
            id: self.id.clone(),
            cid: self.cid.clone(),
            rule: self.rule.clone(),
            timestamp: self.timestamp.clone(),
            hostname: self.hostname.clone(),
            node: self.node.clone(),
            version: self.version.clone(),
            path: self.path.clone(),
            labels: self.labels.clone(),
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
    async fn send(&self, cfg: config::Config) {
        use time::OffsetDateTime;
        let current_date = OffsetDateTime::now_utc();
        let index = format!("fim-{}-{}-{}", current_date.year(), current_date.month() as u8, current_date.day() );
        
        // Splunk endpoint integration
        if cfg.endpoint_type == "Splunk" {
            let data = json!({
                "source": self.node.clone(),
                "sourcetype": "_json",
                "event": json!({
                    "cid": self.cid.clone(),
                    "rule": self.rule.clone(),
                    "timestamp": self.timestamp.clone(),
                    "hostname": self.hostname.clone(),
                    "node": self.node.clone(),
                    "fpid": self.fpid.clone(),
                    "version": self.version.clone(),
                    "labels": self.labels.clone(),
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
                "cid": self.cid.clone(),
                "rule": self.rule.clone(),
                "timestamp": self.timestamp.clone(),
                "hostname": self.hostname.clone(),
                "node": self.node.clone(),
                "fpid": self.fpid.clone(),
                "version": self.version.clone(),
                "labels": self.labels.clone(),
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

    // -----------------------------------------------------------------------

    // ------------------------------------------------------------------------

    // Function to manage event destination
    async fn process(&self, cfg: config::Config) {
        use regex::Regex;

        let ruleset = unsafe { super::GRULESET.clone().unwrap() };

        let rule_index = ruleset.get_index(self.path.clone().to_str().unwrap(), "", ruleset.monitor.clone());
        let mut rule = ruleset.get_rule(rule_index, ruleset.monitor.clone());
        rule.push_str("{1}");
        let expression = Regex::new(&rule).unwrap();
        if expression.is_match(self.path.file_name().unwrap().to_str().unwrap()){
            //event_match...
        }

        route(self, cfg).await;

    }

    // ------------------------------------------------------------------------

    fn get_string(&self, field: String) -> String {
        match field.as_str() {
            "cid" => self.cid.clone(),
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


// ------------------------------------------------------------------------

/*pub async fn send_custom_event(message: String, ) {
    Event {

    }
}*/


pub async fn route(event: &MonitorRuleEvent, cfg: config::Config) {
  match cfg.get_events_destination().as_str() {
      config::BOTH_MODE => {
          event.log(cfg.get_events_file());
          event.send(cfg).await;
      },
      config::NETWORK_MODE => {
          event.send(cfg).await;
      },
      _ => event.log(cfg.get_events_file())
  }
}