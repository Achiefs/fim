#[cfg(test)]
mod tests;

pub mod monitorevent;
pub mod ruleevent;
pub mod hashevent;
pub mod auditevent;

use crate::appconfig::AppConfig;
use crate::ruleset::Ruleset;
use notify::event::*;
use std::fmt;

#[derive(Clone)]
pub enum Event {
    Monitor(MonitorEvent),
    Rule(RuleEvent),
    Hash(HashEvent),
    Audit(Box<AuditEvent>)
}

impl Event {
    pub fn to_json(&self) -> String {
        match self {
            Event::Monitor(event) => event.to_json(),
            Event::Rule(event) => event.to_json(),
            Event::Hash(event) => event.to_json(),
            Event::Audit(event) => event.to_json()
        }
    }

    pub fn get_monitor_event(&self) -> MonitorEvent {
        match self {
            Event::Monitor(event) => event.clone(),
            _ => panic!()
        }
    }

    pub fn get_audit_event(&self) -> AuditEvent {
        match self {
            Event::Audit(event) => *event.clone(),
            _ => panic!()
        }
    }

    pub fn get_rule_event(&self) -> RuleEvent {
        match self {
            Event::Rule(event) => event.clone(),
            _ => panic!()
        }
    }

    pub async fn process(&self, cfg: AppConfig, ruleset: Ruleset) {
        match self {
            Event::Monitor(event) => &event.process(cfg, ruleset).await,
            Event::Rule(event) => &event.process(cfg).await,
            Event::Hash(event) => &event.process(cfg).await,
            Event::Audit(event) => &event.process(cfg, ruleset).await
        };
    }
}

// ----------------------------------------------------------------------------

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        match self {
            Event::Monitor(event) => event.fmt(f),
            Event::Rule(event) => event.fmt(f),
            Event::Hash(event) => event.fmt(f),
            Event::Audit(event) => event.fmt(f)
        }
    }
}

// ----------------------------------------------------------------------------

pub fn get_operation(event_kind: EventKind) -> String {
    let detailed_operation: String = get_detailed_operation(event_kind);
    if detailed_operation == "ANY" {
        String::from("ANY")
    }else if detailed_operation.contains("CREATE") {
        String::from("CREATE")
    }else if detailed_operation.contains("MODIFY") {
        String::from("WRITE")
    }else if detailed_operation.contains("REMOVE") {
        String::from("REMOVE")
    }else if detailed_operation.contains("ACCESS") {
        String::from("ACCESS")
    }else{
        String::from("OTHER")
    }
}

// ----------------------------------------------------------------------------

pub fn get_detailed_operation(event_kind: EventKind) -> String {
    match event_kind {
        EventKind::Any => { String::from("ANY") },

        EventKind::Create(CreateKind::Any) => { String::from("CREATE_ANY") },
        EventKind::Create(CreateKind::File) => { String::from("CREATE_FILE") },
        EventKind::Create(CreateKind::Folder) => { String::from("CREATE_FOLDER") },
        EventKind::Create(CreateKind::Other) => { String::from("CREATE_OTHER") },

        EventKind::Modify(ModifyKind::Any) => { String::from("MODIFY_ANY") },
        EventKind::Modify(ModifyKind::Data(DataChange::Any)) => { String::from("MODIFY_DATA_ANY") },
        EventKind::Modify(ModifyKind::Data(DataChange::Size)) => { String::from("MODIFY_DATA_SIZE") },
        EventKind::Modify(ModifyKind::Data(DataChange::Content)) => { String::from("MODIFY_DATA_CONTENT") },
        EventKind::Modify(ModifyKind::Data(DataChange::Other)) => { String::from("MODIFY_DATA_OTHER") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)) => { String::from("MODIFY_METADATA_ANY") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::AccessTime)) => { String::from("MODIFY_METADATA_ACCESSTIME") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)) => { String::from("MODIFY_METADATA_WRITETIME") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)) => { String::from("MODIFY_METADATA_PERMISSIONS") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Ownership)) => { String::from("MODIFY_METADATA_OWNERSHIP") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Extended)) => { String::from("MODIFY_METADATA_EXTENDED") },
        EventKind::Modify(ModifyKind::Metadata(MetadataKind::Other)) => { String::from("MODIFY_METADATA_OTHER") },
        EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => { String::from("MODIFY_RENAME_ANY") },
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => { String::from("MODIFY_RENAME_TO") },
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => { String::from("MODIFY_RENAME_FROM") },
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => { String::from("MODIFY_RENAME_BOTH") },
        EventKind::Modify(ModifyKind::Name(RenameMode::Other)) => { String::from("MODIFY_RENAME_OTHER") },
        EventKind::Modify(ModifyKind::Other) => { String::from("MODIFY_OTHER") },

        EventKind::Remove(RemoveKind::Any) => { String::from("REMOVE_ANY") },
        EventKind::Remove(RemoveKind::File) => { String::from("REMOVE_FILE") },
        EventKind::Remove(RemoveKind::Folder) => { String::from("REMOVE_FOLDER") },
        EventKind::Remove(RemoveKind::Other) => { String::from("REMOVE_OTHER") },

        EventKind::Access(AccessKind::Any) => { String::from("ACCESS_ANY") },
        EventKind::Access(AccessKind::Read) => { String::from("ACCESS_READ") },
        EventKind::Access(AccessKind::Open(AccessMode::Any)) => { String::from("ACCESS_OPEN_ANY") },
        EventKind::Access(AccessKind::Open(AccessMode::Execute)) => { String::from("ACCESS_OPEN_EXECUTE") },
        EventKind::Access(AccessKind::Open(AccessMode::Read)) => { String::from("ACCESS_OPEN_READ") },
        EventKind::Access(AccessKind::Open(AccessMode::Write)) => { String::from("ACCESS_OPEN_WRITE") },
        EventKind::Access(AccessKind::Open(AccessMode::Other)) => { String::from("ACCESS_OPEN_OTHER") },
        EventKind::Access(AccessKind::Close(AccessMode::Any)) => { String::from("ACCESS_CLOSE_ANY") },
        EventKind::Access(AccessKind::Close(AccessMode::Execute)) => { String::from("ACCESS_CLOSE_EXECUTE") },
        EventKind::Access(AccessKind::Close(AccessMode::Read)) => { String::from("ACCESS_CLOSE_READ") },
        EventKind::Access(AccessKind::Close(AccessMode::Write)) => { String::from("ACCESS_CLOSE_WRITE") },
        EventKind::Access(AccessKind::Close(AccessMode::Other)) => { String::from("ACCESS_CLOSE_OTHER") },
        EventKind::Access(AccessKind::Other) => { String::from("ACCESS_OTHER") },

        EventKind::Other => { String::from("OTHER") }
    }
}

pub use monitorevent::MonitorEvent;
pub use ruleevent::RuleEvent;
pub use hashevent::HashEvent;
pub use auditevent::AuditEvent;