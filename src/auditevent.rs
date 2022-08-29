// Copyright (C) 2021, Achiefs.

// To implement Debug and fmt method
use std::fmt;
// To handle files
use std::fs::OpenOptions;
use std::io::Write;
// Handle time intervals
use std::time::Duration;
// To log the program procedure
use log::*;
// To handle JSON objects
use serde_json::{json, to_string};
// To manage HTTP requests
use reqwest::Client;
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
    pub fn from(syscall: HashMap<String, String>,
        cwd: HashMap<String, String>, parent: HashMap<String, String>,
        path: HashMap<String, String>, proctitle: HashMap<String, String>,
        config: config::Config) -> Self {

        let command = if proctitle["proctitle"].contains('/') ||
            proctitle["proctitle"].contains("bash") {
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
        })
    }

    // ------------------------------------------------------------------------

    // Get formatted string with all required data
    fn format_json(&self) -> String { to_string(&self.get_json()).unwrap() }

    // ------------------------------------------------------------------------

    // Function to write the received events to file
    pub fn log(&self, file: String){
        let mut events_file = OpenOptions::new()
            .create(true)
            .write(true)
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
    pub async fn send(&self, index: String, address: String, user: String, pass: String, insecure: bool) {
        let data = self.get_json();

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
    }

    // ------------------------------------------------------------------------

    // Function to manage event destination
    pub async fn process(&self, destination: &str, index_name: String, config: config::Config){
        match destination {
            config::BOTH_MODE => {
                self.log(config.events_file);
                self.send( index_name, config.endpoint_address, config.endpoint_user, config.endpoint_pass, config.insecure).await;
            },
            config::NETWORK_MODE => {
                self.send( index_name, config.endpoint_address, config.endpoint_user, config.endpoint_pass, config.insecure).await;
            },
            _ => self.log(config.events_file)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditevent::Event;
    use crate::config::Config;
    use tokio_test::block_on;
    //use std::fs;

    // ------------------------------------------------------------------------

    /*fn remove_test_file(filename: String) {
        fs::remove_file(filename).unwrap()
    }*/

    fn create_empty_event() -> Event {
        Event {
            id: String::from(""), timestamp: String::from(""),
            hostname: String::from(""), node: String::from(""),
            version: String::from(""), path: String::from(""),
            file: String::from(""), labels: Vec::new(),
            operation: String::from(""), checksum: String::from(""), fpid: 0,
            system: String::from(""), command: String::from(""),
            ogid: String::from(""), rdev: String::from(""),
            proctitle: String::from(""), cap_fver: String::from(""),
            inode: String::from(""), cap_fp: String::from(""),
            cap_fe: String::from(""), item: String::from(""),
            cap_fi: String::from(""), dev: String::from(""),
            mode: String::from(""), cap_frootid: String::from(""),
            ouid: String::from(""), parent: HashMap::new(),
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
            file: String::from("FILE"), labels: Vec::new(),
            operation: String::from("OPERATION"), checksum: String::from("CHECKSUM"),
            fpid: 0,
            system: String::from("SYSTEM"), command: String::from("COMMAND"),
            ogid: String::from("OGID"), rdev: String::from("RDEV"),
            proctitle: String::from("PROCTITLE"), cap_fver: String::from("CAP_FVER"),
            inode: String::from("INODE"), cap_fp: String::from("CAP_FP"),
            cap_fe: String::from("CAP_FE"), item: String::from("ITEM"),
            cap_fi: String::from("CAP_FI"), dev: String::from("DEV"),
            mode: String::from("MODE"), cap_frootid: String::from("CAP_FROOTID"),
            ouid: String::from("OUID"), parent: HashMap::new(),
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

    //#[test]
    //fn test_from() {}

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
            \"cap_fi\":\"CAP_FI\",\"cap_fp\":\"CAP_FP\",\
            \"cap_frootid\":\"CAP_FROOTID\",\"cap_fver\":\"CAP_FVER\",\
            \"checksum\":\"CHECKSUM\",\"comm\":\"COMM\",\"command\":\"COMMAND\",\
            \"cwd\":\"CWD\",\"dev\":\"DEV\",\"egid\":\"EGID\",\"euid\":\"EUID\",\
            \"exe\":\"EXE\",\"exit\":\"EXIT\",\"file\":\"FILE\",\"fpid\":0,\
            \"fsgid\":\"FSGID\",\"fsuid\":\"FSUID\",\"gid\":\"GID\",\
            \"hostname\":\"HOSTNAME\",\"id\":\"ID\",\"inode\":\"INODE\",\
            \"item\":\"ITEM\",\"items\":\"ITEMS\",\"key\":\"KEY\",\"labels\":[],\
            \"mode\":\"MODE\",\"node\":\"NODE\",\"ogid\":\"OGID\",\
            \"operation\":\"OPERATION\",\"ouid\":\"OUID\",\"parent\":{},\
            \"path\":\"PATH\",\"pid\":\"PID\",\"ppid\":\"PPID\",\
            \"proctitle\":\"PROCTITLE\",\"rdev\":\"RDEV\",\"ses\":\"SES\",\
            \"sgid\":\"SGID\",\"source\":\"SOURCE\",\"success\":\"SUCCESS\",\
            \"suid\":\"SUID\",\"syscall\":\"SYSCALL\",\"system\":\"SYSTEM\",\
            \"timestamp\":\"TIMESTAMP\",\"tty\":\"TTY\",\"uid\":\"UID\",\
            \"version\":\"VERSION\"}");
        assert_eq!(json, string);
    }

    // ------------------------------------------------------------------------

    //#[test]
    //fn test_log() {}

    // ------------------------------------------------------------------------

    //#[test]
    //fn test_send() {   }

    // ------------------------------------------------------------------------

    #[test]
    fn test_process() {
        let config = Config::new(&utils::get_os());
        let event = create_test_event();

        block_on(event.process(config::NETWORK_MODE, String::from("test"), config.clone()));
        block_on(event.process(config::FILE_MODE, String::from("test2"), config.clone()));
        block_on(event.process(config::BOTH_MODE, String::from("test3"), config.clone()));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_event_fmt(){
        let out = format!("{:?}", create_test_event());
        let expected = " { id: \"ID\", path: \"PATH\", operation: \"OPERATION\", \
            file: \"FILE\", timestamp: \"TIMESTAMP\", proctitle: \"PROCTITLE\", \
            cap_fver: \"CAP_FVER\", inode: \"INODE\", cap_fp: \"CAP_FP\", \
            cap_fe: \"CAP_FE\", item: \"ITEM\", cap_fi: \"CAP_FI\", dev: \"DEV\", \
            mode: \"MODE\", cap_frootid: \"CAP_FROOTID\", ouid: \"OUID\", \
            parent: {}, cwd: \"CWD\", syscall: \"SYSCALL\", ppid: \"PPID\", \
            comm: \"COMM\", fsuid: \"FSUID\", pid: \"PID\", a0: \"A0\", \
            a1: \"A1\", a2: \"A2\", a3: \"A3\", arch: \"ARCH\", auid: \"AUID\", \
            items: \"ITEMS\", gid: \"GID\", euid: \"EUID\", sgid: \"SGID\", \
            uid: \"UID\", tty: \"TTY\", success: \"SUCCESS\", exit: \"EXIT\", \
            ses: \"SES\", key: \"KEY\", suid: \"SUID\", egid: \"EGID\", \
            fsgid: \"FSGID\", exe: \"EXE\" }";
        assert_eq!(out, expected);
    }

}