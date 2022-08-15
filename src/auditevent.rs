// Copyright (C) 2021, Achiefs.

// To implement Debug and fmt method
use std::fmt;
// To handle files
use std::fs::OpenOptions;
use std::io::Write;
// Handle time intervals
//use std::time::Duration;
// To log the program procedure
use log::*;
// To handle JSON objects
use serde_json::{json, to_string};
// To manage paths
//use std::path::PathBuf;
// To manage HTTP requests
//use reqwest::Client;
// To use HashMap
use std::collections::HashMap;

// To get configuration constants
use crate::config;
// To manage common functions
use crate::utils;
// To manage checksums and conversions
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
    pub parent: HashMap<String, String>,
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
    pub fn new_from(syscall: HashMap<String, String>,
        cwd: HashMap<String, String>, parent: HashMap<String, String>, 
        path: HashMap<String, String>, proctitle: HashMap<String, String>,
        config: config::Config) -> Self {

        let command = if proctitle["proctitle"].contains('/') {
            proctitle["proctitle"].clone()
        }else{
            hash::hex_to_ascii(proctitle["proctitle"].clone())
        };

        let clean_timestamp: String = String::from(proctitle["msg"].clone()
            .replace("audit(", "")
            .replace(".", "")
            .split(':').collect::<Vec<&str>>()[0]); // Getting the 13 digits timestamp

        let event_path = parent["name"].clone();
        let index = config.get_index(event_path.as_str(),
            cwd["cwd"].as_str(), config.audit.clone().to_vec());
        let labels = config.get_labels(index, config.audit.clone());

        Event{
            id: utils::get_uuid(),
            proctitle: proctitle["proctitle"].clone(),
            command,
            timestamp: clean_timestamp,
            hostname: utils::get_hostname(),
            node: config.node,
            version: String::from(config::VERSION),
            labels,
            operation: path["nametype"].clone(),
            path: utils::clean_path(&event_path),
            file: utils::get_filename_path(path["name"].clone().as_str()),
            checksum: hash::get_checksum(format!("{}/{}",
                parent["name"].clone(), path["name"].clone())),
            fpid: utils::get_pid(),
            system: utils::get_os(),


            ogid: path["ogid"].clone(),
            rdev: path["rdev"].clone(),
            cap_fver: path["cap_fver"].clone(),
            inode: path["inode"].clone(),
            cap_fp: path["cap_fp"].clone(),
            cap_fe: path["cap_fe"].clone(),
            item: path["item"].clone(),
            cap_fi: path["cap_fi"].clone(),
            dev: path["dev"].clone(),
            mode: path["mode"].clone(),
            cap_frootid: path["cap_frootid"].clone(),
            ouid: path["ouid"].clone(),

            parent,
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
            parent: self.parent.clone(),
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

    pub fn is_empty(&self) -> bool {
        self.path == *""
    }

    // ------------------------------------------------------------------------

    // Get formatted string with all required data
    fn format_json(&self) -> String {
        let obj = json!({
            "id": self.id.clone(),
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.node.clone(),
            "version": self.version.clone(),
            "path": self.path.clone(),
            "file": self.file.clone(),
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
            "parent": self.parent.clone(),
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
        });
        to_string(&obj).unwrap()
    }

    // ------------------------------------------------------------------------

    // Function to write the received events to file
    pub fn log_event(&self, file: String){
        let mut events_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(file)
            .expect("(auditevent::log_event) Unable to open events log file.");

            match writeln!(events_file, "{}", self.format_json()) {
                Ok(_d) => debug!("Audit event log written"),
                Err(e) => error!("Audit event could not be written, Err: [{}]", e)
            };
    }

    // ------------------------------------------------------------------------

    // Function to send events through network
    /*pub async fn send(&self, index: String, address: String, user: String, pass: String, insecure: bool) {
        let data = json!({
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.node.clone(),
            "pid": self.pid.clone(),
            "version": self.version.clone(),
            "labels": self.labels.clone(),
            "operation": self.operation.clone(),
            "file": String::from(self.path.clone().to_str().unwrap()),
            "checksum": self.checksum.clone(),
            "system": self.system.clone()
        });

        let request_url = format!("{}/{}/_doc/{}", address, index, self.id);
        let client = Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(Duration::from_secs(30))
            .build().unwrap();
        match client
            .post(request_url)
            .basic_auth(user, Some(pass))
            .json(&data)
            .send()
            .await{
            Ok(response) => debug!("Response received: {:?}", response),
            Err(e) => debug!("Error on request: {:?}", e)
        };
    }*/
}

// ----------------------------------------------------------------------------

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        f.debug_struct("")
            .field("id", &self.id)
            .field("path", &self.path)
            .field("operation", &self.operation)
            .field("file", &self.file)
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
            .field("parent", &self.parent)
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

/*#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use notify::op::Op;
    use std::path::PathBuf;
    use std::fs;

    // ------------------------------------------------------------------------

    fn remove_test_file(filename: String) {
        fs::remove_file(filename).unwrap()
    }

    fn create_test_event() -> Event {
        Event {
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            node: "FIM".to_string(),
            version: "x.x.x".to_string(),
            op: Op::CREATE,
            path: PathBuf::new(),
            labels: Vec::new(),
            operation: "TEST".to_string(),
            checksum: "UNKNOWN".to_string(),
            pid: 0,
            system: "test".to_string()
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_create_event() {

    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send_event() {

    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_operation(){

    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_event_fmt(){

    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_format_json() {

    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_log_event() {

    }
}*/