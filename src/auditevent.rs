// Copyright (C) 2022, Achiefs.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;
use log::*;
use serde_json::{json, to_string};
use reqwest::Client;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::appconfig;
use crate::appconfig::*;
use crate::ruleset::*;
use crate::utils;
use crate::hash;

// ----------------------------------------------------------------------------

pub struct Event {
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

impl Event {
    pub fn new() -> Self {
        let empty = String::from("0");
        Event{
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
        cfg: AppConfig) -> Self {

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

        Event{
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
        }
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
            file: self.file.clone(),
            size: self.size,
            labels: self.labels.clone(),
            operation: self.operation.clone(),
            checksum: self.checksum.clone(),
            fpid: self.fpid,
            system: self.system.clone(),
            command: self.command.clone(),
            ogid: self.ogid.clone(),
            rdev: self.rdev.clone(),
            proctitle: self.proctitle.clone(),
            cap_fver: self.cap_fver.clone(),
            inode: self.inode.clone(),
            cap_fp: self.cap_fp.clone(),
            cap_fe: self.cap_fe.clone(),
            item: self.item.clone(),
            cap_fi: self.cap_fi.clone(),
            dev: self.dev.clone(),
            mode: self.mode.clone(),
            cap_frootid: self.cap_frootid.clone(),
            ouid: self.ouid.clone(),
            paths: self.paths.clone(),
            cwd: self.cwd.clone(),
            syscall: self.syscall.clone(),
            ppid: self.ppid.clone(),
            comm: self.comm.clone(),
            fsuid: self.fsuid.clone(),
            pid: self.pid.clone(),
            a0: self.a0.clone(),
            a1: self.a1.clone(),
            a2: self.a2.clone(),
            a3: self.a3.clone(),
            arch: self.arch.clone(),
            auid: self.auid.clone(),
            items: self.items.clone(),
            gid: self.gid.clone(),
            euid: self.euid.clone(),
            sgid: self.sgid.clone(),
            uid: self.uid.clone(),
            tty: self.tty.clone(),
            success: self.success.clone(),
            exit: self.exit.clone(),
            ses: self.ses.clone(),
            key: self.key.clone(),
            suid: self.suid.clone(),
            egid: self.egid.clone(),
            fsgid: self.fsgid.clone(),
            exe: self.exe.clone(),
            source: self.source.clone(),
        }
    }

    // ------------------------------------------------------------------------

    pub fn is_empty(&self) -> bool { self.path == *"" }

    // ------------------------------------------------------------------------

    fn get_json(&self) -> serde_json::Value {
        json!({
            "id": self.id.clone(),
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.node.clone(),
            "version": self.version.clone(),
            "path": self.path.clone(),
            "file": self.file.clone(),
            "file_size": self.size.clone(),
            "labels": self.labels.clone(),
            "operation": self.operation.clone(),
            "checksum": self.checksum.clone(),
            "fpid": self.fpid.clone(),
            "system": self.system.clone(),
            "command": self.command.clone(),

            "ogid": self.ogid.clone(),
            "rdev": self.rdev.clone(),
            "proctitle": self.proctitle.clone(),
            "cap_fver": self.cap_fver.clone(),
            "inode": self.inode.clone(),
            "cap_fp": self.cap_fp.clone(),
            "cap_fe": self.cap_fe.clone(),
            "item": self.item.clone(),
            "cap_fi": self.cap_fi.clone(),
            "dev": self.dev.clone(),
            "mode": self.mode.clone(),
            "cap_frootid": self.cap_frootid.clone(),
            "ouid": self.ouid.clone(),
            "paths": self.paths.clone(),
            "cwd": self.cwd.clone(),
            "syscall": self.syscall.clone(),
            "ppid": self.ppid.clone(),
            "comm": self.comm.clone(),
            "fsuid": self.fsuid.clone(),
            "pid": self.pid.clone(),
            "a0": self.a0.clone(),
            "a1": self.a1.clone(),
            "a2": self.a2.clone(),
            "a3": self.a3.clone(),
            "arch": self.arch.clone(),
            "auid": self.auid.clone(),
            "items": self.items.clone(),
            "gid": self.gid.clone(),
            "euid": self.euid.clone(),
            "sgid": self.sgid.clone(),
            "uid": self.uid.clone(),
            "tty": self.tty.clone(),
            "success": self.success.clone(),
            "exit": self.exit.clone(),
            "ses": self.ses.clone(),
            "key": self.key.clone(),
            "suid": self.suid.clone(),
            "egid": self.egid.clone(),
            "fsgid": self.fsgid.clone(),
            "exe": self.exe.clone(),
            "source": self.source.clone()
        })
    }

    // ------------------------------------------------------------------------

    // Get formatted string with all required data
    fn format_json(&self) -> String { to_string(&self.get_json()).unwrap() }

    // ------------------------------------------------------------------------

    // Function to write the received events to file
    pub fn log(&self, file: &str){
        let mut events_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file)
            .expect("(auditevent::log) Unable to open events log file.");

            match writeln!(events_file, "{}", self.format_json()) {
                Ok(_d) => debug!("Audit event log written"),
                Err(e) => error!("Audit event could not be written, Err: [{}]", e)
            };
    }

    // ------------------------------------------------------------------------

    // Function to send events through network
    pub async fn send(&self, index: String, cfg: AppConfig) {
        let event = self.get_json();
        
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
    pub async fn process(&self, destination: &str, index_name: String, cfg: AppConfig, ruleset: Ruleset){
        match destination {
            appconfig::BOTH_MODE => {
                self.log(&cfg.get_events_file());
                self.send(index_name, cfg.clone()).await;
            },
            appconfig::NETWORK_MODE => {
                self.send(index_name, cfg.clone()).await;
            },
            _ => self.log(&cfg.get_events_file())
        }
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

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        f.debug_struct("")
            .field("id", &self.id)
            .field("path", &self.path)
            .field("operation", &self.operation)
            .field("file", &self.file)
            .field("file_size", &self.size)
            .field("timestamp", &self.timestamp)
            .field("proctitle", &self.proctitle)
            .field("cap_fver", &self.cap_fver)
            .field("inode", &self.inode)
            .field("cap_fp", &self.cap_fp)
            .field("cap_fe", &self.cap_fe)
            .field("item", &self.item)
            .field("cap_fi", &self.cap_fi)
            .field("dev", &self.dev)
            .field("mode", &self.mode)
            .field("cap_frootid", &self.cap_frootid)
            .field("ouid", &self.ouid)
            .field("paths", &self.paths)
            .field("cwd", &self.cwd)
            .field("syscall", &self.syscall)
            .field("ppid", &self.ppid)
            .field("comm", &self.comm)
            .field("fsuid", &self.fsuid)
            .field("pid", &self.pid)
            .field("a0", &self.a0)
            .field("a1", &self.a1)
            .field("a2", &self.a2)
            .field("a3", &self.a3)
            .field("arch", &self.arch)
            .field("auid", &self.auid)
            .field("items", &self.items)
            .field("gid", &self.gid)
            .field("euid", &self.euid)
            .field("sgid", &self.sgid)
            .field("uid", &self.uid)
            .field("tty", &self.tty)
            .field("success", &self.success)
            .field("exit", &self.exit)
            .field("ses", &self.ses)
            .field("key", &self.key)
            .field("suid", &self.suid)
            .field("egid", &self.egid)
            .field("fsgid", &self.fsgid)
            .field("exe", &self.exe)
            .finish()
    }
}

// ----------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditevent::Event;
    use tokio_test::block_on;
    use std::fs;

    // ------------------------------------------------------------------------

    fn remove_test_file(filename: &str) {
        fs::remove_file(filename).unwrap()
    }

    fn create_empty_event() -> Event {
        Event {
            id: String::from(""), timestamp: String::from(""),
            hostname: String::from(""), node: String::from(""),
            version: String::from(""), path: String::from(""),
            file: String::from(""), size: 0, labels: Vec::new(),
            operation: String::from(""), checksum: String::from(""), fpid: 0,
            system: String::from(""), command: String::from(""),
            ogid: String::from(""), rdev: String::from(""),
            proctitle: String::from(""), cap_fver: String::from(""),
            inode: String::from(""), cap_fp: String::from(""),
            cap_fe: String::from(""), item: String::from(""),
            cap_fi: String::from(""), dev: String::from(""),
            mode: String::from(""), cap_frootid: String::from(""),
            ouid: String::from(""), paths: Vec::new(),
            cwd: String::from(""), syscall: String::from(""),
            ppid: String::from(""), comm: String::from(""),
            fsuid: String::from(""), pid: String::from(""),
            a0: String::from(""), a1: String::from(""),
            a2: String::from(""), a3: String::from(""),
            arch: String::from(""), auid: String::from(""),
            items: String::from(""), gid: String::from(""),
            euid: String::from(""), sgid: String::from(""),
            uid: String::from(""), tty: String::from(""),
            success: String::from(""), exit: String::from(""),
            ses: String::from(""), key: String::from(""),
            suid: String::from(""), egid: String::from(""),
            fsgid: String::from(""), exe: String::from(""),
            source: String::from("")
        }
    }

    fn create_test_event() -> Event {
        Event {
            id: String::from("ID"), timestamp: String::from("TIMESTAMP"),
            hostname: String::from("HOSTNAME"), node: String::from("NODE"),
            version: String::from("VERSION"), path: String::from("PATH"),
            file: String::from("FILE"), size: 0, labels: Vec::new(),
            operation: String::from("OPERATION"), checksum: String::from("CHECKSUM"),
            fpid: 0,
            system: String::from("SYSTEM"), command: String::from("COMMAND"),
            ogid: String::from("OGID"), rdev: String::from("RDEV"),
            proctitle: String::from("PROCTITLE"), cap_fver: String::from("CAP_FVER"),
            inode: String::from("INODE"), cap_fp: String::from("CAP_FP"),
            cap_fe: String::from("CAP_FE"), item: String::from("ITEM"),
            cap_fi: String::from("CAP_FI"), dev: String::from("DEV"),
            mode: String::from("MODE"), cap_frootid: String::from("CAP_FROOTID"),
            ouid: String::from("OUID"), paths: Vec::new(),
            cwd: String::from("CWD"), syscall: String::from("SYSCALL"),
            ppid: String::from("PPID"), comm: String::from("COMM"),
            fsuid: String::from("FSUID"), pid: String::from("PID"),
            a0: String::from("A0"), a1: String::from("A1"),
            a2: String::from("A2"), a3: String::from("A3"),
            arch: String::from("ARCH"), auid: String::from("AUID"),
            items: String::from("ITEMS"), gid: String::from("GID"),
            euid: String::from("EUID"), sgid: String::from("SGID"),
            uid: String::from("UID"), tty: String::from("TTY"),
            success: String::from("SUCCESS"), exit: String::from("EXIT"),
            ses: String::from("SES"), key: String::from("KEY"),
            suid: String::from("SUID"), egid: String::from("EGID"),
            fsgid: String::from("FSGID"), exe: String::from("EXE"),
            source: String::from("SOURCE")
        }
    }

    // ------------------------------------------------------------------------

    #[ignore] // Just for GH runner error (Passed on local)
    #[test]
    fn test_from() {
        if utils::get_os() == "linux" {
            let cfg = AppConfig::new(&utils::get_os(),
                Some("test/unit/config/linux/audit_from_test.yml"));
            let syscall = HashMap::<String, String>::from([
                (String::from("syscall"), String::from("syscall")),
                (String::from("ppid"), String::from("ppid")),
                (String::from("comm"), String::from("comm")),
                (String::from("fsuid"), String::from("fsuid")),
                (String::from("pid"), String::from("pid")),
                (String::from("a0"), String::from("a0")),
                (String::from("a1"), String::from("a1")),
                (String::from("a2"), String::from("a2")),
                (String::from("a3"), String::from("a3")),
                (String::from("arch"), String::from("arch")),
                (String::from("auid"), String::from("auid")),
                (String::from("items"), String::from("items")),
                (String::from("gid"), String::from("gid")),
                (String::from("euid"), String::from("euid")),
                (String::from("sgid"), String::from("sgid")),
                (String::from("uid"), String::from("uid")),
                (String::from("tty"), String::from("tty")),
                (String::from("success"), String::from("success")),
                (String::from("exit"), String::from("exit")),
                (String::from("ses"), String::from("ses")),
                (String::from("key"), String::from("key")),
                (String::from("suid"), String::from("suid")),
                (String::from("egid"), String::from("egid")),
                (String::from("fsgid"), String::from("fsgid")),
                (String::from("exe"), String::from("exe"))
            ]);

            let cwd = HashMap::<String, String>::from([
                (String::from("cwd"), String::from("cwd"))
            ]);

            /*let parent = HashMap::<String, String>::from([
                (String::from("name"), String::from("/tmp"))
            ]);*/

            let paths = Vec::from([
                HashMap::<String, String>::from([
                    (String::from("name"), String::from("/etc")),
                    (String::from("nametype"), String::from("PARENT"))
                ]),
                HashMap::<String, String>::from([
                    (String::from("nametype"), String::from("nametype")),
                    (String::from("name"), String::from("/tmp/test.txt")),
                    (String::from("ogid"), String::from("ogid")),
                    (String::from("rdev"), String::from("rdev")),
                    (String::from("cap_fver"), String::from("cap_fver")),
                    (String::from("inode"), String::from("inode")),
                    (String::from("cap_fp"), String::from("cap_fp")),
                    (String::from("cap_fe"), String::from("cap_fe")),
                    (String::from("item"), String::from("item")),
                    (String::from("cap_fi"), String::from("cap_fi")),
                    (String::from("dev"), String::from("dev")),
                    (String::from("mode"), String::from("mode")),
                    (String::from("cap_frootid"), String::from("cap_frootid")),
                    (String::from("ouid"), String::from("ouid")),

                ])
            ]);

            /*let path = HashMap::<String, String>::from([
                (String::from("nametype"), String::from("nametype")),
                (String::from("name"), String::from("name")),
                (String::from("ogid"), String::from("ogid")),
                (String::from("rdev"), String::from("rdev")),
                (String::from("cap_fver"), String::from("cap_fver")),
                (String::from("inode"), String::from("inode")),
                (String::from("cap_fp"), String::from("cap_fp")),
                (String::from("cap_fe"), String::from("cap_fe")),
                (String::from("item"), String::from("item")),
                (String::from("cap_fi"), String::from("cap_fi")),
                (String::from("dev"), String::from("dev")),
                (String::from("mode"), String::from("mode")),
                (String::from("cap_frootid"), String::from("cap_frootid")),
                (String::from("ouid"), String::from("ouid")),
            ]);*/

            let proctitle = HashMap::<String, String>::from([
                (String::from("proctitle"), String::from("736564002D6900737C68656C6C6F7C4849217C670066696C6531302E747874")),
                (String::from("msg"), String::from("audit(1659026449.689:6434)"))
            ]);

            let event = Event::from(syscall.clone(), cwd.clone(), proctitle, paths.clone(), cfg.clone());
            assert_eq!(String::from("1659026449689"), event.timestamp);
            assert_eq!(utils::get_hostname(), event.hostname);
            assert_eq!(String::from("FIM"), event.node);
            assert_eq!(String::from(appconfig::VERSION), event.version);
            assert_eq!(String::from("/tmp"), event.path);
            assert_eq!(String::from("test.txt"), event.file);
            assert_eq!(0, event.size);
            //assert_eq!(..., event.labels);
            //assert_eq!(..., event.parent);
            assert_eq!(String::from("nametype"), event.operation);
            assert_eq!(String::from("UNKNOWN"), event.checksum);
            assert_eq!(utils::get_pid(), event.fpid);
            assert_eq!(utils::get_os(), event.system);
            assert_eq!(String::from("sed -i s|hello|HI!|g file10.txt"), event.command);
            assert_eq!(String::from("ogid"), event.ogid);
            assert_eq!(String::from("rdev"), event.rdev);
            assert_eq!(String::from("736564002D6900737C68656C6C6F7C4849217C670066696C6531302E747874"), event.proctitle);
            assert_eq!(String::from("cap_fver"), event.cap_fver);
            assert_eq!(String::from("inode"), event.inode);
            assert_eq!(String::from("cap_fp"), event.cap_fp);
            assert_eq!(String::from("cap_fe"), event.cap_fe);
            assert_eq!(String::from("item"), event.item);
            assert_eq!(String::from("cap_fi"), event.cap_fi);
            assert_eq!(String::from("dev"), event.dev);
            assert_eq!(String::from("mode"), event.mode);
            assert_eq!(String::from("ouid"), event.ouid);
            assert_eq!(String::from("cwd"), event.cwd);
            assert_eq!(String::from("syscall"), event.syscall);
            assert_eq!(String::from("ppid"), event.ppid);
            assert_eq!(String::from("comm"), event.comm);
            assert_eq!(String::from("fsuid"), event.fsuid);
            assert_eq!(String::from("pid"), event.pid);
            assert_eq!(String::from("a0"), event.a0);
            assert_eq!(String::from("a1"), event.a1);
            assert_eq!(String::from("a2"), event.a2);
            assert_eq!(String::from("a3"), event.a3);
            assert_eq!(String::from("arch"), event.arch);
            assert_eq!(String::from("auid"), event.auid);
            assert_eq!(String::from("items"), event.items);
            assert_eq!(String::from("gid"), event.gid);
            assert_eq!(String::from("euid"), event.euid);
            assert_eq!(String::from("sgid"), event.sgid);
            assert_eq!(String::from("uid"), event.uid);
            assert_eq!(String::from("tty"), event.tty);
            assert_eq!(String::from("success"), event.success);
            assert_eq!(String::from("exit"), event.exit);
            assert_eq!(String::from("ses"), event.ses);
            assert_eq!(String::from("key"), event.key);
            assert_eq!(String::from("suid"), event.suid);
            assert_eq!(String::from("egid"), event.egid);
            assert_eq!(String::from("fsgid"), event.fsgid);
            assert_eq!(String::from("exe"), event.exe);
            assert_eq!(String::from("audit"), event.source);

            let proctitle = HashMap::<String, String>::from([
                (String::from("proctitle"), String::from("bash")),
                (String::from("msg"), String::from("audit(1659026449.689:6434)"))
            ]);
            let event = Event::from(syscall, cwd, proctitle, paths.clone(), cfg.clone());
            assert_eq!(String::from("bash"), event.proctitle);

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
        assert_eq!(event.file, cloned.file);
        assert_eq!(event.size, cloned.size);
        assert_eq!(event.labels, cloned.labels);
        assert_eq!(event.operation, cloned.operation);
        assert_eq!(event.checksum, cloned.checksum);
        assert_eq!(event.fpid, cloned.fpid);
        assert_eq!(event.system, cloned.system);
        assert_eq!(event.command, cloned.command);
        assert_eq!(event.ogid, cloned.ogid);
        assert_eq!(event.rdev, cloned.rdev);
        assert_eq!(event.proctitle, cloned.proctitle);
        assert_eq!(event.cap_fver, cloned.cap_fver);
        assert_eq!(event.inode, cloned.inode);
        assert_eq!(event.cap_fp, cloned.cap_fp);
        assert_eq!(event.cap_fe, cloned.cap_fe);
        assert_eq!(event.item, cloned.item);
        assert_eq!(event.cap_fi, cloned.cap_fi);
        assert_eq!(event.dev, cloned.dev);
        assert_eq!(event.mode, cloned.mode);
        assert_eq!(event.cap_frootid, cloned.cap_frootid);
        assert_eq!(event.ouid, cloned.ouid);
        assert_eq!(event.paths, cloned.paths);
        //assert_eq!(event.parent, cloned.parent);
        assert_eq!(event.cwd, cloned.cwd);
        assert_eq!(event.syscall, cloned.syscall);
        assert_eq!(event.ppid, cloned.ppid);
        assert_eq!(event.comm, cloned.comm);
        assert_eq!(event.fsuid, cloned.fsuid);
        assert_eq!(event.pid, cloned.pid);
        assert_eq!(event.a0, cloned.a0);
        assert_eq!(event.a1, cloned.a1);
        assert_eq!(event.a2, cloned.a2);
        assert_eq!(event.a3, cloned.a3);
        assert_eq!(event.arch, cloned.arch);
        assert_eq!(event.auid, cloned.auid);
        assert_eq!(event.items, cloned.items);
        assert_eq!(event.gid, cloned.gid);
        assert_eq!(event.euid, cloned.euid);
        assert_eq!(event.sgid, cloned.sgid);
        assert_eq!(event.uid, cloned.uid);
        assert_eq!(event.tty, cloned.tty);
        assert_eq!(event.success, cloned.success);
        assert_eq!(event.exit, cloned.exit);
        assert_eq!(event.ses, cloned.ses);
        assert_eq!(event.key, cloned.key);
        assert_eq!(event.suid, cloned.suid);
        assert_eq!(event.egid, cloned.egid);
        assert_eq!(event.fsgid, cloned.fsgid);
        assert_eq!(event.exe, cloned.exe);
        assert_eq!(event.source, cloned.source);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_is_empty() {
        let empty = create_empty_event();
        let event = create_test_event();
        assert_eq!(empty.is_empty(), true);
        assert_eq!(event.is_empty(), false);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_json(){
        let event = create_test_event().get_json();
        assert_eq!(event["id"], "ID");
        assert_eq!(event["timestamp"], "TIMESTAMP");
        assert_eq!(event["hostname"], "HOSTNAME");
        assert_eq!(event["node"], "NODE");
        assert_eq!(event["version"], "VERSION");
        assert_eq!(event["path"], "PATH");
        assert_eq!(event["file"], "FILE");
        assert_eq!(event["file_size"], 0);
        //assert_eq!(event["labels"], Vec::<String>::new());
        assert_eq!(event["operation"], "OPERATION");
        assert_eq!(event["checksum"], "CHECKSUM");
        assert_eq!(event["fpid"], 0 as i8);
        assert_eq!(event["system"], "SYSTEM");
        assert_eq!(event["command"], "COMMAND");
        assert_eq!(event["ogid"], "OGID");
        assert_eq!(event["rdev"], "RDEV");
        assert_eq!(event["proctitle"], "PROCTITLE");
        assert_eq!(event["cap_fver"], "CAP_FVER");
        assert_eq!(event["inode"], "INODE");
        assert_eq!(event["cap_fp"], "CAP_FP");
        assert_eq!(event["cap_fe"], "CAP_FE");
        assert_eq!(event["item"], "ITEM");
        assert_eq!(event["cap_fi"], "CAP_FI");
        assert_eq!(event["dev"], "DEV");
        assert_eq!(event["mode"], "MODE");
        assert_eq!(event["cap_frootid"], "CAP_FROOTID");
        assert_eq!(event["ouid"], "OUID");
        //assert_eq!(event["parent"], HashMap::new());
        assert_eq!(event["cwd"], "CWD");
        assert_eq!(event["syscall"], "SYSCALL");
        assert_eq!(event["ppid"], "PPID");
        assert_eq!(event["comm"], "COMM");
        assert_eq!(event["fsuid"], "FSUID");
        assert_eq!(event["pid"], "PID");
        assert_eq!(event["a0"], "A0");
        assert_eq!(event["a1"], "A1");
        assert_eq!(event["a2"], "A2");
        assert_eq!(event["a3"], "A3");
        assert_eq!(event["arch"], "ARCH");
        assert_eq!(event["auid"], "AUID");
        assert_eq!(event["items"], "ITEMS");
        assert_eq!(event["gid"], "GID");
        assert_eq!(event["euid"], "EUID");
        assert_eq!(event["sgid"], "SGID");
        assert_eq!(event["uid"], "UID");
        assert_eq!(event["tty"], "TTY");
        assert_eq!(event["success"], "SUCCESS");
        assert_eq!(event["exit"], "EXIT");
        assert_eq!(event["ses"], "SES");
        assert_eq!(event["key"], "KEY");
        assert_eq!(event["suid"], "SUID");
        assert_eq!(event["egid"], "EGID");
        assert_eq!(event["fsgid"], "FSGID");
        assert_eq!(event["exe"], "EXE");
        assert_eq!(event["source"], "SOURCE");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_format_json() {
        let json = create_test_event().format_json();
        let string = String::from("{\"a0\":\"A0\",\"a1\":\"A1\",\"a2\":\"A2\",\
            \"a3\":\"A3\",\"arch\":\"ARCH\",\"auid\":\"AUID\",\"cap_fe\":\"CAP_FE\",\
            \"cap_fi\":\"CAP_FI\",\"cap_fp\":\"CAP_FP\",\"cap_frootid\":\"CAP_FROOTID\",\
            \"cap_fver\":\"CAP_FVER\",\"checksum\":\"CHECKSUM\",\"comm\":\"COMM\",\
            \"command\":\"COMMAND\",\"cwd\":\"CWD\",\"dev\":\"DEV\",\"egid\":\"EGID\",\
            \"euid\":\"EUID\",\"exe\":\"EXE\",\"exit\":\"EXIT\",\"file\":\"FILE\",\
            \"file_size\":0,\"fpid\":0,\"fsgid\":\"FSGID\",\"fsuid\":\"FSUID\",\"gid\":\"GID\",\
            \"hostname\":\"HOSTNAME\",\"id\":\"ID\",\"inode\":\"INODE\",\
            \"item\":\"ITEM\",\"items\":\"ITEMS\",\"key\":\"KEY\",\"labels\":[],\
            \"mode\":\"MODE\",\"node\":\"NODE\",\"ogid\":\"OGID\",\
            \"operation\":\"OPERATION\",\"ouid\":\"OUID\",\"path\":\"PATH\",\
            \"paths\":[],\"pid\":\"PID\",\"ppid\":\"PPID\",\"proctitle\":\"PROCTITLE\",\
            \"rdev\":\"RDEV\",\"ses\":\"SES\",\"sgid\":\"SGID\",\"source\":\"SOURCE\",\
            \"success\":\"SUCCESS\",\"suid\":\"SUID\",\"syscall\":\"SYSCALL\",\
            \"system\":\"SYSTEM\",\"timestamp\":\"TIMESTAMP\",\"tty\":\"TTY\",\
            \"uid\":\"UID\",\"version\":\"VERSION\"}");
        assert_eq!(json, string);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_log() {
        let filename = "test_log.json";
        let event = create_test_event();
        event.log(filename);

        let expected = "{\"a0\":\"A0\",\"a1\":\"A1\",\"a2\":\"A2\",\"a3\":\"A3\",\
            \"arch\":\"ARCH\",\"auid\":\"AUID\",\"cap_fe\":\"CAP_FE\",\
            \"cap_fi\":\"CAP_FI\",\"cap_fp\":\"CAP_FP\",\
            \"cap_frootid\":\"CAP_FROOTID\",\"cap_fver\":\"CAP_FVER\",\
            \"checksum\":\"CHECKSUM\",\"comm\":\"COMM\",\"command\":\"COMMAND\",\
            \"cwd\":\"CWD\",\"dev\":\"DEV\",\"egid\":\"EGID\",\"euid\":\"EUID\",\
            \"exe\":\"EXE\",\"exit\":\"EXIT\",\"file\":\"FILE\",\"file_size\":0,\"fpid\":0,\
            \"fsgid\":\"FSGID\",\"fsuid\":\"FSUID\",\"gid\":\"GID\",\
            \"hostname\":\"HOSTNAME\",\"id\":\"ID\",\"inode\":\"INODE\",\
            \"item\":\"ITEM\",\"items\":\"ITEMS\",\"key\":\"KEY\",\"labels\":[],\
            \"mode\":\"MODE\",\"node\":\"NODE\",\"ogid\":\"OGID\",\
            \"operation\":\"OPERATION\",\"ouid\":\"OUID\",\"path\":\"PATH\",\
            \"paths\":[],\"pid\":\"PID\",\"ppid\":\"PPID\",\
            \"proctitle\":\"PROCTITLE\",\"rdev\":\"RDEV\",\"ses\":\"SES\",\
            \"sgid\":\"SGID\",\"source\":\"SOURCE\",\"success\":\"SUCCESS\",\
            \"suid\":\"SUID\",\"syscall\":\"SYSCALL\",\"system\":\"SYSTEM\",\
            \"timestamp\":\"TIMESTAMP\",\"tty\":\"TTY\",\"uid\":\"UID\",\
            \"version\":\"VERSION\"}\n";

        let log = utils::read_file(filename);
        assert_eq!(log, expected);

        remove_test_file(filename);
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic]
    fn test_log_panic() {
        create_empty_event().log("");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send() {
        let event = create_test_event();
        let cfg = AppConfig::new(&utils::get_os(), None);
        block_on( event.send(String::from("test"), cfg) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send_splunk() {
        let event = create_test_event();
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/common/test_send_splunk.yml"));
        block_on( event.send(String::from("test"), cfg) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_process() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        let ruleset = Ruleset::new(&utils::get_os(), None);  
        let event = create_test_event();

        block_on(event.process(appconfig::NETWORK_MODE, String::from("test"), cfg.clone(), ruleset.clone()));
        block_on(event.process(appconfig::FILE_MODE, String::from("test2"), cfg.clone(), ruleset.clone()));
        block_on(event.process(appconfig::BOTH_MODE, String::from("test3"), cfg.clone(), ruleset.clone()));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_event_fmt(){
        let out = format!("{:?}", create_test_event());
        let expected = " { id: \"ID\", path: \"PATH\", operation: \"OPERATION\", \
            file: \"FILE\", file_size: 0, timestamp: \"TIMESTAMP\", proctitle: \"PROCTITLE\", \
            cap_fver: \"CAP_FVER\", inode: \"INODE\", cap_fp: \"CAP_FP\", \
            cap_fe: \"CAP_FE\", item: \"ITEM\", cap_fi: \"CAP_FI\", dev: \"DEV\", \
            mode: \"MODE\", cap_frootid: \"CAP_FROOTID\", ouid: \"OUID\", paths: [], \
            cwd: \"CWD\", syscall: \"SYSCALL\", ppid: \"PPID\", comm: \"COMM\", \
            fsuid: \"FSUID\", pid: \"PID\", a0: \"A0\", a1: \"A1\", a2: \"A2\", \
            a3: \"A3\", arch: \"ARCH\", auid: \"AUID\", items: \"ITEMS\", \
            gid: \"GID\", euid: \"EUID\", sgid: \"SGID\", uid: \"UID\", \
            tty: \"TTY\", success: \"SUCCESS\", exit: \"EXIT\", ses: \"SES\", \
            key: \"KEY\", suid: \"SUID\", egid: \"EGID\", fsgid: \"FSGID\", exe: \"EXE\" }";

        assert_eq!(out, expected);
    }

}