use super::*;
use std::fs;

use crate::utils;

// ----------------------------------------------------------------------------

#[test]
/// Check new instance creation, the instance should match the given values
fn test_new() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let previous_dbfile = DBFile::new(cfg.clone(), "LICENSE", None);
    let dbfile = DBFile::new(cfg.clone(), "README.md", None);
    let event = HashEvent::new(Some(previous_dbfile.clone()), dbfile.clone(), String::from("NEW"));

    match event.previous_dbfile {
        Some(data) => {
            assert_eq!(data.id, previous_dbfile.id);
            assert_eq!(data.timestamp, previous_dbfile.timestamp);
            assert_eq!(data.hash, previous_dbfile.hash);
            assert_eq!(data.path, previous_dbfile.path);
            assert_eq!(data.size, previous_dbfile.size);
            assert_eq!(data.permissions, previous_dbfile.permissions);
        },
        None => assert!(false)
    }

    assert_eq!(event.dbfile.id, dbfile.id);
    assert_eq!(event.dbfile.timestamp, dbfile.timestamp);
    assert_eq!(event.dbfile.hash, dbfile.hash);
    assert_eq!(event.dbfile.path, dbfile.path);
    assert_eq!(event.dbfile.size, dbfile.size);
    assert_eq!(event.dbfile.permissions, dbfile.permissions);
    assert_eq!(event.operation, String::from("NEW"));
}

// ----------------------------------------------------------------------------

#[test]
/// Check the hashEvent JSON log write, it should match with expected one
fn test_log() {
    let filename = String::from("test_hashevent.json");
    let cfg = AppConfig::new(&utils::get_os(), None);
    let previous_dbfile = DBFile {
        id: String::from("PREVIOUS"),
        timestamp: String::from("TIMESTAMP"),
        hash: String::from("HASH"),
        path: String::from("PATH"),
        size: 123,
        permissions: 0
    };
    let dbfile = DBFile {
        id: String::from("CURRENT"),
        timestamp: String::from("TIMESTAMPC"),
        hash: String::from("HASHC"),
        path: String::from("PATHC"),
        size: 1234,
        permissions: 1
    };
    let event = HashEvent::new(Some(previous_dbfile.clone()), dbfile.clone(),
        String::from("NEW"));

    event.log(filename.clone());
    let contents = fs::read_to_string(filename.clone());
    let expected = "{\"dbfile.hash\":\"HASHC\",\"dbfile.id\":\"CURRENT\",\
        \"dbfile.path\":\"PATHC\",\"dbfile.permissions\":1,\"dbfile.size\":1234,\
        \"dbfile.timestamp\":\"TIMESTAMPC\",\"operation\":\"NEW\",\
        \"previous_dbfile.hash\":\"HASH\",\"previous_dbfile.id\":\"PREVIOUS\",\
        \"previous_dbfile.path\":\"PATH\",\"previous_dbfile.permissions\":0,\
        \"previous_dbfile.size\":123,\"previous_dbfile.timestamp\":\"TIMESTAMP\"}\n";
    assert_eq!(contents.unwrap(), expected);
    fs::remove_file(filename).unwrap();
}