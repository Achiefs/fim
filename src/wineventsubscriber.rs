// Copyright (C) 2024, Achiefs.

use windows::core::*;
use windows::Win32::System::EventLog::*;
use windows::Win32::Foundation::*;
use minidom::Element;
use minidom::NSChoice;
use std::ffi::c_void;
use futures::executor::block_on;
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::PathBuf;

use crate::appconfig;
use crate::appconfig::*;
use crate::utils;
use crate::event;
use event::Event;
use crate::winevent::WinEvent;
use crate::ruleset::*;
use crate::hash;

use log::*;

// ---------------------------------------------------------------------------

// Unsafe variables, required to process the event callback.
static mut CONFIG: Option<AppConfig> = None;
static mut RULESET: Option<Ruleset> = None;

// ----------------------------------------------------------------------------

fn process_access_list(access_list: Vec<String>) -> Vec<String> {
    access_list.iter().map(|x| match x.as_str() {
        "%%4416" => String::from("ReadData/ListDirectory"),
        "%%4417" => String::from("WriteData/AddFile"),
        "%%4418" => String::from("AppendData/AddSubdirectory/CreatePipeInstance"),
        "%%4419" => String::from("ReadEA/Enumerate SubKeys"),
        "%%4420" => String::from("WriteEA"),
        "%%4421" => String::from("Execute/Traverse"),
        "%%4422" => String::from("DeleteChild"),
        "%%4423" => String::from("ReadAttributes"),
        "%%4424" => String::from("WriteAttributes"),
        "%%1537" => String::from("DELETE"),
        "%%1538" => String::from("READ_CONTROL"),
        "%%1539" => String::from("WRITE_DAC"),
        "%%1540" => String::from("WRITE_OWNER"),
        "%%1541" => String::from("SYNCHRONIZE"),
        "%%1542" => String::from("ACCESS_SYS_SEC"),
        _ => String::from("UNKNOWN")
    }).collect()
}

// ----------------------------------------------------------------------------

fn get_element_text(root: Element, attr: &str) -> String {
    let event_data = root.get_child("EventData", NSChoice::Any).unwrap();
    let element = event_data.children().find(|&x| x.attr("Name").unwrap() == attr);
    match element {
        Some(elem) => elem.text(),
        None => String::from("UNKNOWN")
    }
}

// ----------------------------------------------------------------------------

unsafe extern "system" fn print_event(_action: EVT_SUBSCRIBE_NOTIFY_ACTION, _usercontext: *const c_void, event: EVT_HANDLE) -> u32 {
    let buffer_used: *mut u32 = &mut 0;
    let property_count: *mut u32 = &mut 0;
    let mut buf = [0u8; 4096];
    let ptr = buf.as_mut_ptr() as *mut c_void;
    let cfg = CONFIG.clone().unwrap();

    match EvtRender(None, event, EvtRenderEventXml.0.try_into().unwrap(), 4096,
        Some(ptr), buffer_used, property_count){
            Ok(_) => debug!("Event rendered"),//(),
            Err(e) => error!("Could not render the received event, err: {}", e)
        }

    let num_bytes: usize = (*buffer_used).try_into().unwrap();
    let xml_event = std::slice::from_raw_parts(ptr as *mut u8, num_bytes).to_vec();
    let arr = String::from_utf8(xml_event).unwrap().replace("\0", "");
    let root: Element = arr.parse().unwrap();

    let timestamp = format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis());
    let path = PathBuf::from(get_element_text(root.clone(), "ObjectName"));
    let mut access_list_text = get_element_text(root.clone(), "AccessList");
    if access_list_text.ends_with("\n\t\t\t\t") { access_list_text.truncate(access_list_text.len()-5); }
    let access_list: Vec<String> = access_list_text.split("\n\t\t\t\t").map(|x| x.to_string()).collect();

    if path.to_str().unwrap() != "UNKNOWN" {
        let index = cfg.clone().get_index(path.to_str().unwrap(), "", cfg.clone().monitor.to_vec());
        let filename = path.file_name().unwrap();
        let parent = match path.is_dir() {
            true => path.to_str().unwrap(),
            false => path.parent().unwrap().to_str().unwrap()
        };

        if index != usize::MAX {

            if ! cfg.match_ignore(index, filename.to_str().unwrap(), cfg.clone().monitor) &&
            ! cfg.match_exclude(index, parent, cfg.clone().monitor) &&
            cfg.match_allowed(index, filename.to_str().unwrap(), cfg.clone().monitor){

                let labels = cfg.clone().get_labels(index, cfg.clone().monitor);
                let evt = WinEvent {
                    id: utils::get_uuid(),
                    timestamp,
                    hostname: utils::get_hostname(),
                    node: CONFIG.clone().unwrap().node,
                    version: String::from(appconfig::VERSION),
                    path: path.clone(),
                    size: utils::get_file_size(path.clone().to_str().unwrap()),
                    labels: labels,
                    operations: process_access_list(access_list.clone()),
                    checksum: hash::get_checksum( String::from(path.to_str().unwrap()), CONFIG.clone().unwrap().events_max_file_checksum ),
                    fpid: utils::get_pid(),
                    system: CONFIG.clone().unwrap().system,

                    subject_user_sid: get_element_text(root.clone(), "SubjectUserSid"),
                    subject_user_name: get_element_text(root.clone(), "SubjectUserName"),
                    subject_domain_name: get_element_text(root.clone(), "SubjectDomainName"),
                    subject_logon_id: get_element_text(root.clone(), "SubjectLogonId"),
                    object_server: get_element_text(root.clone(), "ObjectServer"),
                    object_type: get_element_text(root.clone(), "ObjectType"),
                    object_name: get_element_text(root.clone(), "ObjectName"),
                    handle_id: get_element_text(root.clone(), "HandleId"),
                    transaction_id: get_element_text(root.clone(), "TransactionId"),
                    access_list,
                    access_reason: get_element_text(root.clone(), "AccessReason"),
                    access_mask: get_element_text(root.clone(), "AccessMask"),
                    privilege_list: get_element_text(root.clone(), "PrivilegeList"),
                    restricted_sid_count: get_element_text(root.clone(), "RestrictedSidCount"),
                    process_id: get_element_text(root.clone(), "ProcessId"),
                    process_name: get_element_text(root.clone(), "ProcessName"),
                    resource_attributes: get_element_text(root.clone(), "ResourceAttributes")
                };

                block_on( evt.process(CONFIG.clone().unwrap(), RULESET.clone().unwrap()) );
            }
        }
    }

    return 0
}




pub fn subscribe_event_channel(cfg: AppConfig, ruleset: Ruleset) {
    unsafe {
        CONFIG = Some(cfg);
        RULESET = Some(ruleset);
        let callback: EVT_SUBSCRIBE_CALLBACK = Some(print_event);

        let subscribe_future_events = 1;

        // 9007199254740992 = 0x20000000000000 -> Audit Success
        // 327942 = 0x50006 -> Write/Add/Read/Extended attr
        // 0CCE921D-69AE-11D9-BED3-505054503030 -> File system selector
        // 4656 -> Handle to an object requested
        // 4663 -> Attempt made to access an object
        // 4658 -> Handle to an object closed
        // 4660 -> Object deleted
        // 4670 -> Permissions on an object were changed
        // 4661 -> Handle to an object was requested with intent to delete

        let query = w!("
            Event[ \
                System[band(Keywords, 9007199254740992)] and ( \
                    ( ( EventData/Data[@Name='ObjectType'] = 'File' or EventData/Data[@Name='ObjectType'] = 'Directory' )  and \
                        ( ( System/EventID = 4656 or System/EventID = 4663 ) and \
                            ( EventData[band(Data[@Name='AccessMask'], 327942)] ) ) \
                    ) or ( EventData/Data[@Name='SubcategoryGuid'] = '0CCE921D-69AE-11D9-BED3-505054503030' ) or \
                    ( System/EventID = 4658 ) or \
                    ( System/EventID = 4660 ) or \
                    ( System/EventID = 4670 ) or \
                    ( System/EventID = 4661 )
                ) \
            ]
        ");

        let _handle = EvtSubscribe( None, HANDLE::default(), w!("Security"),
            query, None, None, callback, subscribe_future_events);
    }
}