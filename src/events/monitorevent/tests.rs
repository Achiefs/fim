use super::*;
use crate::events::MonitorEvent;
use crate::events::*;
use crate::utils;
use std::path::PathBuf;
use tokio_test::block_on;
use std::fs;
use notify::EventKind;
use notify::event::{CreateKind, ModifyKind, RemoveKind, AccessKind, MetadataKind,
    DataChange, RenameMode, AccessMode};

// ------------------------------------------------------------------------

fn remove_test_file(filename: String) {
    fs::remove_file(filename).unwrap()
}

fn create_test_event() -> MonitorEvent {
    MonitorEvent {
        id: "Test_id".to_string(),
        timestamp: "Timestamp".to_string(),
        hostname: "Hostname".to_string(),
        node: "FIM".to_string(),
        version: "x.x.x".to_string(),
        kind: EventKind::Create(CreateKind::Any),
        path: PathBuf::new(),
        size: 0,
        labels: Vec::new(),
        operation: "CREATE".to_string(),
        detailed_operation: "CREATE_FILE".to_string(),
        checksum: "UNKNOWN".to_string(),
        fpid: 0,
        system: "test".to_string()
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
    assert_eq!(event.size, cloned.size);
    assert_eq!(event.kind, cloned.kind);
    assert_eq!(event.labels, cloned.labels);
    assert_eq!(event.operation, cloned.operation);
    assert_eq!(event.detailed_operation, cloned.detailed_operation);
    assert_eq!(event.checksum, cloned.checksum);
    assert_eq!(event.fpid, cloned.fpid);
    assert_eq!(event.system, cloned.system);
}

// ------------------------------------------------------------------------

#[test]
fn test_create_event() {
    let evt = create_test_event();
    assert_eq!(evt.id, "Test_id".to_string());
    assert_eq!(evt.timestamp, "Timestamp".to_string());
    assert_eq!(evt.hostname, "Hostname".to_string());
    assert_eq!(evt.node, "FIM".to_string());
    assert_eq!(evt.version, "x.x.x".to_string());
    assert_eq!(evt.kind, EventKind::Create(CreateKind::Any) );
    assert_eq!(evt.path, PathBuf::new());
    assert_eq!(evt.labels, Vec::<String>::new());
    assert_eq!(evt.operation, String::from("CREATE"));
    assert_eq!(evt.detailed_operation, String::from("CREATE_FILE"));
    assert_eq!(evt.fpid, 0);
    assert_eq!(evt.system, String::from("test"));
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
fn test_get_operation(){
    assert_eq!(get_operation(EventKind::Create(CreateKind::Any)), String::from("CREATE"));
    assert_eq!(get_operation(EventKind::Modify(ModifyKind::Any)), String::from("WRITE"));
    assert_eq!(get_operation(EventKind::Remove(RemoveKind::Any)), String::from("REMOVE"));
    assert_eq!(get_operation(EventKind::Access(AccessKind::Any)), String::from("ACCESS"));
    assert_eq!(get_operation(EventKind::Other), String::from("OTHER"));
    assert_eq!(get_operation(EventKind::Any), String::from("ANY"));
}

// ------------------------------------------------------------------------

#[test]
fn test_get_detailed_operation(){
    assert_eq!(get_detailed_operation(EventKind::Any), String::from("ANY"));
    assert_eq!(get_detailed_operation(EventKind::Create(CreateKind::Any)),
        String::from("CREATE_ANY"));
    assert_eq!(get_detailed_operation(EventKind::Create(CreateKind::File)),
        String::from("CREATE_FILE"));
    assert_eq!(get_detailed_operation(EventKind::Create(CreateKind::Folder)),
        String::from("CREATE_FOLDER"));
    assert_eq!(get_detailed_operation(EventKind::Create(CreateKind::Other)),
        String::from("CREATE_OTHER"));

    assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Any)),
        String::from("MODIFY_ANY"));
    assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Data(DataChange::Any))),
        String::from("MODIFY_DATA_ANY"));
    assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Data(DataChange::Size))),
        String::from("MODIFY_DATA_SIZE"));
    assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Data(DataChange::Content))),
        String::from("MODIFY_DATA_CONTENT"));
    assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Data(DataChange::Other))),
        String::from("MODIFY_DATA_OTHER"));
    assert_eq!(get_detailed_operation(EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any))),
        String::from("MODIFY_METADATA_ANY"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Metadata(MetadataKind::AccessTime))),
        String::from("MODIFY_METADATA_ACCESSTIME"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Metadata(MetadataKind::WriteTime))),
        String::from("MODIFY_METADATA_WRITETIME"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Metadata(MetadataKind::Permissions))),
        String::from("MODIFY_METADATA_PERMISSIONS"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Metadata(MetadataKind::Ownership))),
        String::from("MODIFY_METADATA_OWNERSHIP"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Metadata(MetadataKind::Extended))),
        String::from("MODIFY_METADATA_EXTENDED"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Metadata(MetadataKind::Other))),
        String::from("MODIFY_METADATA_OTHER"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Name(RenameMode::Any))), String::from("MODIFY_RENAME_ANY"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Name(RenameMode::To))), String::from("MODIFY_RENAME_TO"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Name(RenameMode::From))), String::from("MODIFY_RENAME_FROM"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Name(RenameMode::Both))), String::from("MODIFY_RENAME_BOTH"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Name(RenameMode::Other))), String::from("MODIFY_RENAME_OTHER"));
    assert_eq!(get_detailed_operation(EventKind::Modify(
        ModifyKind::Other)), String::from("MODIFY_OTHER"));

    assert_eq!(get_detailed_operation(EventKind::Remove(
        RemoveKind::Any)), String::from("REMOVE_ANY"));
    assert_eq!(get_detailed_operation(EventKind::Remove(
        RemoveKind::File)), String::from("REMOVE_FILE"));
    assert_eq!(get_detailed_operation(EventKind::Remove(
        RemoveKind::Folder)), String::from("REMOVE_FOLDER"));
    assert_eq!(get_detailed_operation(EventKind::Remove(
        RemoveKind::Other)), String::from("REMOVE_OTHER"));

    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Any)), String::from("ACCESS_ANY"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Read)), String::from("ACCESS_READ"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Open(AccessMode::Any))), String::from("ACCESS_OPEN_ANY"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Open(AccessMode::Execute))), String::from("ACCESS_OPEN_EXECUTE"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Open(AccessMode::Read))), String::from("ACCESS_OPEN_READ"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Open(AccessMode::Write))), String::from("ACCESS_OPEN_WRITE"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Open(AccessMode::Other))), String::from("ACCESS_OPEN_OTHER"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Close(AccessMode::Any))), String::from("ACCESS_CLOSE_ANY"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Close(AccessMode::Execute))), String::from("ACCESS_CLOSE_EXECUTE"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Close(AccessMode::Read))), String::from("ACCESS_CLOSE_READ"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Close(AccessMode::Write))), String::from("ACCESS_CLOSE_WRITE"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Close(AccessMode::Other))), String::from("ACCESS_CLOSE_OTHER"));
    assert_eq!(get_detailed_operation(EventKind::Access(
        AccessKind::Other)), String::from("ACCESS_OTHER"));

    assert_eq!(get_detailed_operation(EventKind::Other), String::from("OTHER"));
}

// ------------------------------------------------------------------------

#[test]
fn test_process() {
    let event = create_test_event();
    let cfg = AppConfig::new(&utils::get_os(), None);
    let ruleset = Ruleset::new(&utils::get_os(), None);  

    block_on(event.process(cfg, ruleset));
    //block_on(event.process(appconfig::NETWORK_MODE, String::from("test"), cfg.clone()));
    //block_on(event.process(appconfig::FILE_MODE, String::from("test2"), cfg.clone()));
    //block_on(event.process(appconfig::BOTH_MODE, String::from("test3"), cfg.clone()));
}

// ------------------------------------------------------------------------

#[test]
fn test_to_json() {
    let expected = "{\
        \"id\":\"Test_id\",\
        \"timestamp\":\"Timestamp\",\
        \"hostname\":\"Hostname\",\
        \"node\":\"FIM\",\
        \"version\":\"x.x.x\",\
        \"path\":\"\",\
        \"size\":0,\
        \"kind\":{\
            \"create\":{\
                \"kind\":\"any\"\
            }\
        },\
        \"labels\":[],\
        \"operation\":\"CREATE\",\
        \"detailed_operation\":\"CREATE_FILE\",\
        \"checksum\":\"UNKNOWN\",\
        \"fpid\":0,\
        \"system\":\"test\"\
    }";
    assert_eq!(create_test_event().to_json(), expected);
}

// ------------------------------------------------------------------------

#[test]
fn test_log() {
    let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/common/test_log.yml"));
    let filename = String::from("test_log.json");
    let evt = create_test_event();

    evt.log(cfg.clone());
    let contents = fs::read_to_string(filename.clone());
    let expected = "{\
        \"id\":\"Test_id\",\
        \"timestamp\":\"Timestamp\",\
        \"hostname\":\"Hostname\",\
        \"node\":\"FIM\",\
        \"version\":\"x.x.x\",\
        \"path\":\"\",\
        \"size\":0,\
        \"kind\":{\
            \"create\":{\
                \"kind\":\"any\"\
            }\
        },\
        \"labels\":[],\
        \"operation\":\"CREATE\",\
        \"detailed_operation\":\"CREATE_FILE\",\
        \"checksum\":\"UNKNOWN\",\
        \"fpid\":0,\
        \"system\":\"test\"\
    }\n";
    assert_eq!(contents.unwrap(), expected);
    remove_test_file(filename.clone());
}