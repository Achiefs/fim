// Copyright (C) 2021, Achiefs.

// To implement Debug and fmt method
use std::fmt;
// To handle files
use std::fs::OpenOptions;
use std::io::{Write, Error, ErrorKind};
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

pub struct Event {
    pub id: String,
    pub timestamp: String,
    pub path: String,
    pub file: String,
    pub operation: String,
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
    pub parent_inode: String,
    pub parent_cap_fe: String,
    pub parent_cap_frootid: String,
    pub parent_ouid: String,
    pub parent_item: String,
    pub parent_cap_fver: String,
    pub parent_mode: String,
    pub parent_rdev: String,
    pub parent_cap_fi: String,
    pub parent_cap_fp: String,
    pub parent_dev: String,
    pub parent_ogid: String,
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
    pub exe: String
}

impl Event {
    pub fn new() -> Self {
        Event {
            id: String::from(""),
            timestamp: String::from(""),
            path: String::from(""),
            file: String::from(""),
            operation: String::from(""),
            ogid: String::from(""),
            rdev: String::from(""),

            proctitle: String::from(""),
            cap_fver: String::from(""),
            inode: String::from(""),
            cap_fp: String::from(""),
            cap_fe: String::from(""),
            item: String::from(""),
            cap_fi: String::from(""),
            dev: String::from(""),
            mode: String::from(""),
            cap_frootid: String::from(""),
            ouid: String::from(""),
            parent_inode: String::from(""),
            parent_cap_fe: String::from(""),
            parent_cap_frootid: String::from(""),
            parent_ouid: String::from(""),
            parent_item: String::from(""),
            parent_cap_fver: String::from(""),
            parent_mode: String::from(""),
            parent_rdev: String::from(""),
            parent_cap_fi: String::from(""),
            parent_cap_fp: String::from(""),
            parent_dev: String::from(""),
            parent_ogid: String::from(""),
            cwd: String::from(""),
            syscall: String::from(""),
            ppid: String::from(""),
            comm: String::from(""),
            fsuid: String::from(""),
            pid: String::from(""),
            a0: String::from(""),
            a1: String::from(""),
            a2: String::from(""),
            a3: String::from(""),
            arch: String::from(""),
            auid: String::from(""),
            items: String::from(""),
            gid: String::from(""),
            euid: String::from(""),
            sgid: String::from(""),
            uid: String::from(""),
            tty: String::from(""),
            success: String::from(""),
            exit: String::from(""),
            ses: String::from(""),
            key: String::from(""),
            suid: String::from(""),
            egid: String::from(""),
            fsgid: String::from(""),
            exe: String::from("")
        }
    }

    // Get formatted string with all required data
    fn format_json(&self) -> String {
        let obj = json!({
            "id": self.id.clone(),
            "timestamp": self.timestamp.clone(),
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
            .expect("(log_event) Unable to open events log file.");

        match self.operation.as_str() {
            "CREATE"|"WRITE"|"RENAME"|"REMOVE"|"CHMOD" => {
                writeln!(events_file, "{}", self.format_json() )
            },
            _ => {
                let error_msg = "Event Op not Handled or do not exists";
                error!("{}", error_msg);
                Err(Error::new(ErrorKind::InvalidInput, error_msg))
            },
        }.expect("(log_event) Error writing event")
    }

    // ------------------------------------------------------------------------

    // Function to send events through network
    /*pub async fn send(&self, index: String, address: String, user: String, pass: String, insecure: bool) {
        let data = json!({
            "timestamp": self.timestamp.clone(),
            "hostname": self.hostname.clone(),
            "node": self.nodename.clone(),
            "pid": self.pid.clone(),
            "version": self.version.clone(),
            "labels": self.labels.clone(),
            "kind": self.kind.clone(),
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
          .field("parent_inode", &self.parent_inode)
          .field("parent_cap_fe", &self.parent_cap_fe)
          .field("parent_cap_frootid", &self.parent_cap_frootid)
          .field("parent_ouid", &self.parent_ouid)
          .field("parent_item", &self.parent_item)
          .field("parent_cap_fver", &self.parent_cap_fver)
          .field("parent_mode", &self.parent_mode)
          .field("parent_rdev", &self.parent_rdev)
          .field("parent_cap_fi", &self.parent_cap_fi)
          .field("parent_cap_fp", &self.parent_cap_fp)
          .field("parent_dev", &self.parent_dev)
          .field("parent_ogid", &self.parent_ogid)
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
            nodename: "FIM".to_string(),
            version: "x.x.x".to_string(),
            operation: Op::CREATE,
            path: PathBuf::new(),
            labels: Vec::new(),
            kind: "TEST".to_string(),
            checksum: "UNKNOWN".to_string(),
            pid: 0,
            system: "test".to_string()
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_create_event() {
        let evt = create_test_event();
        assert_eq!(evt.id, "Test_id".to_string());
        assert_eq!(evt.timestamp, "Timestamp".to_string());
        assert_eq!(evt.hostname, "Hostname".to_string());
        assert_eq!(evt.nodename, "FIM".to_string());
        assert_eq!(evt.version, "x.x.x".to_string());
        assert_eq!(evt.operation, Op::CREATE);
        assert_eq!(evt.path, PathBuf::new());
        assert_eq!(evt.labels, Vec::<String>::new());
        assert_eq!(evt.kind, String::from("TEST"));
        assert_eq!(evt.pid, 0);
        assert_eq!(evt.system, String::from("test"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_send_event() {
        let evt = create_test_event();
        tokio_test::block_on( evt.send(
            String::from("test"), String::from("https://127.0.0.1:9200"),
            String::from("admin"), String::from("admin"), true) );
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_kind(){
        assert_eq!(get_kind(Op::CREATE), String::from("CREATE"));
        assert_eq!(get_kind(Op::WRITE), String::from("WRITE"));
        assert_eq!(get_kind(Op::RENAME), String::from("RENAME"));
        assert_eq!(get_kind(Op::REMOVE), String::from("REMOVE"));
        assert_eq!(get_kind(Op::CHMOD), String::from("CHMOD"));
        assert_eq!(get_kind(Op::CLOSE_WRITE), String::from("CLOSE_WRITE"));
        assert_eq!(get_kind(Op::RESCAN), String::from("RESCAN"));
        assert_eq!(get_kind(Op::empty()), String::from("UNKNOWN"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_event_fmt(){
        let out = format!("{:?}", create_test_event());
        assert_eq!(out, "(\"Test_id\", \"\", CREATE)");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_format_json() {
        let expected = "{\"checksum\":\"UNKNOWN\",\"file\":\"\",\"hostname\":\"Hostname\",\"id\":\"Test_id\",\"kind\":\"TEST\",\"labels\":[],\"node\":\"FIM\",\"pid\":0,\"system\":\"test\",\"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}";
        assert_eq!(create_test_event().format_json(), expected);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_log_event() {
        let filename = String::from("test_event.json");
        let evt = create_test_event();

        evt.log_event(filename.clone());
        let contents = fs::read_to_string(filename.clone());
        let expected = "{\"checksum\":\"UNKNOWN\",\"file\":\"\",\"hostname\":\"Hostname\",\"id\":\"Test_id\",\"kind\":\"TEST\",\"labels\":[],\"node\":\"FIM\",\"pid\":0,\"system\":\"test\",\"timestamp\":\"Timestamp\",\"version\":\"x.x.x\"}\n";
        assert_eq!(contents.unwrap(), expected);
        remove_test_file(filename.clone());
    }
}*/