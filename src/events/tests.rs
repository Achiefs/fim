// Copyright (C) 2025, Achiefs.

use super::*;

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