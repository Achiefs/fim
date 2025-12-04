use super::*;
use crate::utils;
use std::path::PathBuf;
use tokio_test::block_on;
use std::fs;

// ------------------------------------------------------------------------

fn remove_test_file(filename: String) {
    fs::remove_file(filename).unwrap()
}

fn create_test_event() -> RuleEvent {
    RuleEvent {
        id: 0,
        rule: "\\.php$".to_string(),
        timestamp: "Timestamp".to_string(),
        hostname: "Hostname".to_string(),
        version: "x.x.x".to_string(),
        path: PathBuf::new(),
        fpid: 0,
        system: "test".to_string(),
        message: "This is a message".to_string(),
        parent_id: "0000".to_string()
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
    assert_eq!(event.version, cloned.version);
    assert_eq!(event.path, cloned.path);
    assert_eq!(event.fpid, cloned.fpid);
    assert_eq!(event.system, cloned.system);
    assert_eq!(event.message, cloned.message);
    assert_eq!(event.parent_id, cloned.parent_id);
}

// ------------------------------------------------------------------------

#[test]
fn test_new() {
    let evt = create_test_event();
    assert_eq!(evt.id, 0);
    assert_eq!(evt.timestamp, "Timestamp".to_string());
    assert_eq!(evt.hostname, "Hostname".to_string());
    assert_eq!(evt.version, "x.x.x".to_string());
    assert_eq!(evt.path, PathBuf::new());
    assert_eq!(evt.fpid, 0);
    assert_eq!(evt.system, String::from("test"));
    assert_eq!(evt.message, String::from("This is a message"));
    assert_eq!(evt.parent_id, String::from("0000"));
}

// ------------------------------------------------------------------------

#[test]
fn test_send() {
    let evt = create_test_event();
    let cfg = AppConfig::new(&utils::get_os(), None);
    block_on( evt.send(cfg) );
}

// ------------------------------------------------------------------------

#[test]
fn test_send_splunk() {
    let evt = create_test_event();
    let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/common/test_send_splunk.yml"));
    block_on( evt.send(cfg) );
}

// ------------------------------------------------------------------------

#[test]
fn test_process() {
    let event = create_test_event();
    let cfg = AppConfig::new(&utils::get_os(), None);

    block_on(event.process(cfg));
}

// ------------------------------------------------------------------------

#[test]
fn test_to_json() {
    let expected = "{\
        \"id\":0,\
        \"rule\":\"\\\\.php$\",\
        \"timestamp\":\"Timestamp\",\
        \"hostname\":\"Hostname\",\
        \"version\":\"x.x.x\",\
        \"path\":\"\",\
        \"fpid\":0,\
        \"system\":\"test\",\
        \"message\":\"This is a message\",\
        \"parent_id\":\"0000\"\
    }";
    assert_eq!(create_test_event().to_json(), expected);
}

// ------------------------------------------------------------------------

#[test]
fn test_log() {
    let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/common/test_log_ruleevent.yml"));
    let filename = String::from("test_ruleevent.json");
    let evt = create_test_event();

    evt.log(cfg.clone());
    let contents = fs::read_to_string(filename.clone());
    let expected = "{\
        \"id\":0,\
        \"rule\":\"\\\\.php$\",\
        \"timestamp\":\"Timestamp\",\
        \"hostname\":\"Hostname\",\
        \"version\":\"x.x.x\",\
        \"path\":\"\",\
        \"fpid\":0,\
        \"system\":\"test\",\
        \"message\":\"This is a message\",\
        \"parent_id\":\"0000\"\
    }\n";
    assert_eq!(contents.unwrap(), expected);
    remove_test_file(filename.clone());
}