// Copyright (C) 2022, Achiefs.

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests;

use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;
use log::*;
use serde::Serialize;
use serde_json::json;
use reqwest::Client;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::events::Event;
use crate::appconfig;
use crate::appconfig::*;
use crate::ruleset::*;
use crate::utils;
use crate::hash;

#[derive(Clone, Serialize, Debug, Default)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub hostname: String,
    pub node: String,
    pub version: String,
    pub path: String,
    pub file: String,
    pub size: u64,
    pub labels: Vec<String>,
    pub operation: String,
    pub checksum: String,
    pub fpid: u32,
    pub system: String,
    pub command: String,

    pub ogid: String,
    pub rdev: String,
    pub proctitle: String,
    pub cap_fver: String,
    pub inode: String,
    pub cap_fp: String,
    pub cap_fe: String,
    pub item: String,
    pub cap_fi: String,
    pub dev: String,
    pub mode: String,
    pub cap_frootid: String,
    pub ouid: String,
    pub paths: Vec<HashMap<String, String>>,
    pub cwd: String,
    pub syscall: String,
    pub ppid: String,
    pub comm: String,
    pub fsuid: String,
    pub pid: String,
    pub a0: String,
    pub a1: String,
    pub a2: String,
    pub a3: String,
    pub arch: String,
    pub auid: String,
    pub items: String,
    pub gid: String,
    pub euid: String,
    pub sgid: String,
    pub uid: String,
    pub tty: String,
    pub success: String,
    pub exit: String,
    pub ses: String,
    pub key: String,
    pub suid: String,
    pub egid: String,
    pub fsgid: String,
    pub exe: String,
    pub source: String,
}

impl AuditEvent {
    pub fn new() -> Self {
        let empty = String::from("0");
        AuditEvent{
            id: empty.clone(), timestamp: empty.clone(), hostname: empty.clone(),
            node: empty.clone(), version: empty.clone(), path: empty.clone(),
            file: empty.clone(), size: 0, labels: Vec::new(), operation: empty.clone(),
            checksum: empty.clone(), fpid: 0, system: empty.clone(),
            command: empty.clone(), ogid: empty.clone(), rdev: empty.clone(),
            proctitle: empty.clone(), cap_fver: empty.clone(),
            inode: empty.clone(), cap_fp: empty.clone(), cap_fe: empty.clone(),
            item: empty.clone(), cap_fi: empty.clone(), dev: empty.clone(),
            mode: empty.clone(), cap_frootid: empty.clone(), ouid: empty.clone(),
            paths: Vec::new(), cwd: empty.clone(), syscall: empty.clone(),
            ppid: empty.clone(), comm: empty.clone(), fsuid: empty.clone(),
            pid: empty.clone(), a0: empty.clone(), a1: empty.clone(),
            a2: empty.clone(), a3: empty.clone(), arch: empty.clone(),
            auid: empty.clone(), items: empty.clone(), gid: empty.clone(),
            euid: empty.clone(), sgid: empty.clone(), uid: empty.clone(),
            tty: empty.clone(), success: empty.clone(), exit: empty.clone(),
            ses: empty.clone(), key: empty.clone(), suid: empty.clone(),
            egid: empty.clone(), fsgid: empty.clone(), exe: empty.clone(),
            source: empty,
        }
    }

    // ------------------------------------------------------------------------

    pub fn from(syscall: HashMap<String, String>,
        cwd: HashMap<String, String>, proctitle: HashMap<String, String>,
        paths: Vec<HashMap<String, String>>,
        cfg: AppConfig) -> Event {

        let parent = get_parent(paths.clone(),  cwd["cwd"].as_str(), cfg.clone());
        let path = get_item_path(paths.clone(), cwd["cwd"].as_str(), cfg.clone());

        let command = if proctitle["proctitle"].contains('/') ||
            proctitle["proctitle"].contains("bash") {
            proctitle["proctitle"].clone()
        }else{
            hash::hex_to_ascii(proctitle["proctitle"].clone())
        };

        let clean_timestamp: String = String::from(proctitle["msg"].clone()
            .replace("audit(", "")
            .replace('.', "")
            .split(':').collect::<Vec<&str>>()[0]); // Getting the 13 digits timestamp

        let event_path = parent["name"].clone();
        let index = cfg.get_index(event_path.as_str(),
            cwd["cwd"].as_str(), cfg.audit.clone().to_vec());
        let labels = cfg.get_labels(index, cfg.audit.clone());

        Event::Audit(Box::new(AuditEvent{
            id: utils::get_uuid(),
            proctitle: proctitle["proctitle"].clone(),
            command,
            timestamp: clean_timestamp,
            hostname: utils::get_hostname(),
            node: cfg.node,
            version: String::from(appconfig::VERSION),
            labels,
            operation: utils::get_field(path.clone(), "nametype"),
            path: utils::clean_path(&event_path),
            file: utils::get_filename_path(path["name"].clone().as_str()),
            size: utils::get_file_size(path["name"].clone().as_str()),
            checksum: hash::get_checksum(
                format!("{}/{}", parent["name"].clone(), path["name"].clone()),
                cfg.events_max_file_checksum,
                cfg.checksum_algorithm),
            fpid: utils::get_pid(),
            system: String::from(utils::get_os()),


            ogid: get_field(path.clone(), "ogid"),
            rdev: get_field(path.clone(), "rdev"),
            cap_fver: get_field(path.clone(), "cap_fver"),
            inode: get_field(path.clone(), "inode"),
            cap_fp: get_field(path.clone(), "cap_fp"),
            cap_fe: get_field(path.clone(), "cap_fe"),
            item: get_field(path.clone(), "item"),
            cap_fi: get_field(path.clone(), "cap_fi"),
            dev: get_field(path.clone(), "dev"),
            mode: get_field(path.clone(), "mode"),
            cap_frootid: get_field(path.clone(), "cap_frootid"),
            ouid: get_field(path.clone(), "ouid"),

            paths,
            cwd: cwd["cwd"].clone(),

            syscall: syscall["syscall"].clone(),
            ppid: syscall["ppid"].clone(),
            comm: syscall["comm"].clone(),
            fsuid: syscall["fsuid"].clone(),
            pid: syscall["pid"].clone(),
            a0: syscall["a0"].clone(),
            a1: syscall["a1"].clone(),
            a2: syscall["a2"].clone(),
            a3: syscall["a3"].clone(),
            arch: syscall["arch"].clone(),
            auid: syscall["auid"].clone(),
            items: syscall["items"].clone(),
            gid: syscall["gid"].clone(),
            euid: syscall["euid"].clone(),
            sgid: syscall["sgid"].clone(),
            uid: syscall["uid"].clone(),
            tty: syscall["tty"].clone(),
            success: syscall["success"].clone(),
            exit: syscall["exit"].clone(),
            ses: syscall["ses"].clone(),
            key: syscall["key"].clone(),
            suid: syscall["suid"].clone(),
            egid: syscall["egid"].clone(),
            fsgid: syscall["fsgid"].clone(),
            exe: syscall["exe"].clone(),
            source: String::from("audit")
        }))
    }

    // ------------------------------------------------------------------------

    pub fn is_empty(&self) -> bool { self.path == *"" }

    // ------------------------------------------------------------------------

    // Get formatted string with all required data
    pub fn to_json(&self) -> String { serde_json::to_string(self).unwrap() }

    // ------------------------------------------------------------------------

    // Function to write the received events to file
    pub fn log(&self, cfg: AppConfig){
        let file = cfg.events_lock.lock().unwrap();
        let mut events_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file.as_str())
            .expect("(auditevent::log) Unable to open events log file.");

            match writeln!(events_file, "{}", self.to_json()) {
                Ok(_d) => debug!("Audit event log written"),
                Err(e) => error!("Audit event could not be written, Err: [{}]", e)
            };
    }

    // ------------------------------------------------------------------------

    // Function to send events through network
    pub async fn send(&self, cfg: AppConfig) {
        use time::OffsetDateTime;
        let current_date = OffsetDateTime::now_utc();
        let index = format!("fim-{}-{}-{}", current_date.year(), current_date.month() as u8, current_date.day() );
        let event = self.to_json();
        
        // Splunk endpoint integration
        if cfg.endpoint_type == "Splunk" {
            let data = json!({
                "source": self.node.clone(),
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
            let request_url = format!("{}/{}/_doc/{}", cfg.endpoint_address, index, self.id);
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

    // Function to manage event destination
    pub async fn process(&self, cfg: AppConfig, ruleset: Ruleset){
        route(self, cfg.clone()).await;
        let filepath = PathBuf::from(self.path.clone());
        ruleset.match_rule(cfg, filepath.join(self.file.clone()), self.id.clone()).await;
    }
}

// ----------------------------------------------------------------------------
fn get_field(map: HashMap<String, String>,field: &str) -> String {
    if map.contains_key(field) {
        map[field].clone()
    }else{
        String::from("UNKNOWN")
    }
}

// ----------------------------------------------------------------------------

pub fn get_parent(paths: Vec<HashMap<String, String>>, cwd: &str, cfg: AppConfig) -> HashMap<String, String> {
    match paths.iter().find(|p|{
        utils::get_field((*p).clone(), "nametype") == "PARENT" &&
        cfg.path_in(p["name"].as_str(), cwd, cfg.audit.clone())
    }){
        Some(p) => p.clone(),
        None => get_item_path(paths.clone(), cwd, cfg.clone())
    }
}

// ----------------------------------------------------------------------------

pub fn get_item_path(paths: Vec<HashMap<String, String>>, cwd: &str, cfg: AppConfig) -> HashMap<String, String> {
    match paths.iter().rfind(|p|{
        utils::get_field((*p).clone(), "nametype") != "PARENT" &&
        utils::get_field((*p).clone(), "nametype") != "UNKNOWN" &&
        cfg.path_in(p["name"].as_str(), cwd, cfg.audit.clone())
    }){
        Some(p) => p.clone(),
        None => get_parent(paths.clone(), cwd, cfg.clone())
    }
}

// ----------------------------------------------------------------------------

pub async fn route(event: &AuditEvent, cfg: AppConfig) {
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