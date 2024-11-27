// Copyright (C) 2021, Achiefs.

// To read and write directories and files
use std::fs;
// To get file system changes
use notify::RecursiveMode;
use std::sync::mpsc;
// To log the program process
use log::{info, error, debug, warn};
// To manage paths
use std::path::Path;
// To manage date and time
use std::time::{SystemTime, UNIX_EPOCH};
//use std::ffi::c_void;
use time::OffsetDateTime;
// To use intersperse()
use itertools::Itertools;
// Event handling
use notify::event::{EventKind, AccessKind};


// Utils functions
use crate::utils;
// Hashing functions
use crate::hash;
use crate::appconfig;
use crate::appconfig::*;
// Index management functions
use crate::index;
// Event data management
use crate::event;
use event::Event;
use crate::monitorevent::MonitorEvent;
use crate::ruleset::*;
// File reading continuously
use crate::logreader;
// integrations checker
use crate::launcher;
use crate::multiwatcher::MultiWatcher;
use crate::wineventsubscriber;
use crate::winhandler::*;

// ----------------------------------------------------------------------------

fn setup_events(destination: &str, cfg: AppConfig){
    // Perform actions depending on destination
    info!("Events destination selected: {}", destination);
    match destination {
        appconfig::NETWORK_MODE => {
            debug!("Events folder not created in network mode");
        },
        _ => {
            info!("Events file: {}", cfg.events_file);
            fs::create_dir_all(Path::new(&cfg.events_file).parent().unwrap().to_str().unwrap()).unwrap()
        }
    }
}

// ----------------------------------------------------------------------------

async fn push_template(destination: &str, cfg: AppConfig){
    // Perform actions depending on destination
    match destination {
        appconfig::NETWORK_MODE|appconfig::BOTH_MODE => {
            // On start push template (Include check if events won't be ingested by http)
            index::push_template(cfg).await;
        },
        _ => {
            debug!("Template not pushed in file mode");
        }
    }
}

// ----------------------------------------------------------------------------

fn clean_audit_rules(cfg: &AppConfig){
    for element in cfg.audit.clone() {
        let path = element["path"].as_str().unwrap();
        let rule = utils::get_audit_rule_permissions(element["rule"].as_str());
        utils::run_auditctl(&["-W", path, "-k", "fim", "-p", &rule]);
    }
    std::process::exit(0);
}

// ----------------------------------------------------------------------------

// Function that monitorize files in loop
pub async fn monitor(
    tx: mpsc::Sender<core::result::Result<notify::Event, notify::Error>>,
    rx: mpsc::Receiver<core::result::Result<notify::Event, notify::Error>>,
    cfg: AppConfig,
    ruleset: Ruleset){

    let destination = cfg.clone().get_events_destination();
    setup_events(destination.as_str(), cfg.clone());

    // Check if we have to push index template
    push_template(destination.as_str(), cfg.clone()).await;

    let mut watcher = MultiWatcher::new(cfg.clone().events_watcher.as_str(), tx);

    // Iterating over monitor paths and set watcher on each folder to watch.
    if ! cfg.clone().monitor.is_empty() {
        for element in cfg.clone().monitor {
            let path = element["path"].as_str().unwrap();
            info!("Monitoring path: {}", path);

            match element["ignore"].as_vec() {
                Some(ig) => {
                    let ignore_vec  = ig.iter().map(|e| e.as_str().unwrap() );
                    let ignore_list : String = Itertools::intersperse(ignore_vec, ", ").collect();
                    info!("Ignoring files with: '{}' inside '{}' path.", ignore_list, path);
                },
                None => debug!("Ignore for '{}' path not set.", path)
            };

            match element["exclude"].as_vec() {
                Some(ex) => {
                    let exclude_vec  = ex.iter().map(|e| e.as_str().unwrap() );
                    let exclude_list : String = Itertools::intersperse(exclude_vec, ", ").collect();
                    info!("Excluding folders: '{}' inside '{}' path.", exclude_list, path);
                },
                None => debug!("Exclude folders for '{}' path not set.", path)
            };

            match element["allowed"].as_vec(){
                Some(allowed) => {
                    let allowed_vec = allowed.iter().map(|e| e.as_str().unwrap());
                    let allowed_list : String = Itertools::intersperse(allowed_vec, ", ").collect();
                    info!("Only files with '{}' will trigger event inside '{}' path.", allowed_list, path)
                },
                None => debug!("Monitoring files under '{}' path.", path)
            }

            if utils::get_os() != "windows" {
                match watcher.watch(Path::new(path), RecursiveMode::Recursive) {
                    Ok(_d) => debug!("Monitoring '{}' path.", path),
                    Err(e) => warn!("Could not monitor given path '{}', description: {}", path, e)
                };
            } else {


                use windows::core::{ PCWSTR, HSTRING, PWSTR };
                use windows::Win32::System::SystemServices::{
                    SECURITY_DESCRIPTOR_REVISION,
                    MAXDWORD
                };
                use windows::Win32::Security::{
                    PSID,
                    ACL_REVISION,
                    ACL_REVISION_DS,
                    ACL,
                    InitializeSecurityDescriptor,
                    InitializeAcl,
                    GetAce,
                    AddAce,
                    SYSTEM_AUDIT_OBJECT_ACE,
                    IsValidAcl,
                    ACE_HEADER,
                    SYSTEM_AUDIT_ACE,
                };
                use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
                use windows::Win32::Security::Authorization::BuildExplicitAccessWithNameW;
                use windows::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
                use windows::Win32::Security::Authorization::SET_AUDIT_FAILURE;
                use windows::Win32::Security::Authorization::SET_AUDIT_SUCCESS;
                use windows::Win32::Security::CONTAINER_INHERIT_ACE;
                use windows::Win32::Security::NO_INHERITANCE;
                use windows::Win32::Security::Authorization::TRUSTEE_W;
                use windows::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE;
                use windows::Win32::Security::Authorization::TRUSTEE_IS_SID;
                use windows::Win32::Security::Authorization::TRUSTEE_IS_NAME;
                use windows::Win32::Security::Authorization::TRUSTEE_IS_WELL_KNOWN_GROUP;
                use windows::Win32::Security::Authorization::GetExplicitEntriesFromAclW;
                use windows::Win32::Foundation::GENERIC_ALL;
                use windows::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;
                use windows::Win32::Security::Authorization::ACCESS_MODE;
                use windows::Win32::Security::Authorization::SetEntriesInAclW;
                use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
                use windows::Win32::Security::Authorization::SET_ACCESS;
                use windows::Win32::System::SystemServices::SYSTEM_AUDIT_ACE_TYPE;

                let mut sid = PSID::default();
                let mut raw_sidE = HSTRING::from("S-1-1-0\0"); // Everyone
                let raw_sid = HSTRING::from("Everyone\0"); // Everyone

                unsafe {
                    //let mut ptr = *(raw_sid.as_ptr());
                    //let array = raw_sid.as_wide();
                    //println!("Array: {:?}", array);
                    //let mut ptr = raw_sid.as_ptr() as *mut _;
                    let pwstr = PWSTR::from_raw(raw_sid.as_ptr() as *mut _);
                    //println!("PWSTR: {:?}", pwstr.to_string().unwrap());

                    enable_privilege();
                    let handle = get_handle(HSTRING::from("C:\\tmp2\\file.txt\0"));

                    // Convert the SID string to a PSID
                    let _result = ConvertStringSidToSidW(PCWSTR::from_raw(raw_sidE.as_ptr()), &mut sid);
                    let mut acl = get_sacl_security_info(handle);


                    use std::ffi::c_void;
                    println!("Getting ACL ACEs...");
                    for n in 0..acl.AceCount {
                        let mut pace: *mut c_void = std::ptr::null_mut();
                        GetAce(&acl, n as u32, &mut pace);

                        let ace_header: *mut ACE_HEADER = pace as *mut ACE_HEADER;
                        println!("{:?}", *ace_header);
                        acl.AclSize += (*ace_header).AceSize;
                    }




                    /*let mut explicit_access = EXPLICIT_ACCESS_W {
                        grfAccessPermissions: ACCESS_SYSTEM_SECURITY,
                        grfAccessMode: ACCESS_MODE(SET_AUDIT_SUCCESS.0 | SET_AUDIT_FAILURE.0),
                        grfInheritance: CONTAINER_INHERIT_ACE,
                        Trustee: TRUSTEE_W {
                            pMultipleTrustee: std::ptr::null_mut(),
                            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                            TrusteeForm: TRUSTEE_IS_NAME,
                            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                            ptstrName: pwstr,
                        },
                    };*/
                    //let explicit_access = &mut EXPLICIT_ACCESS_W::default();
                    //println!();
                    //println!("Explicit access: {:?}", explicit_access);
                    //println!();
                    /*BuildExplicitAccessWithNameW(
                        explicit_access,
                        pwstr,
                        ACCESS_SYSTEM_SECURITY,
                        ACCESS_MODE(SET_AUDIT_SUCCESS.0 | SET_AUDIT_FAILURE.0),
                        NO_INHERITANCE
                    );*/

                    let mut explicit_access_failure = EXPLICIT_ACCESS_W::default();
                    explicit_access_failure.grfAccessPermissions = GENERIC_ALL.0;
                    explicit_access_failure.grfAccessMode = SET_AUDIT_FAILURE;
                    explicit_access_failure.grfInheritance = NO_INHERITANCE;
                    explicit_access_failure.Trustee.pMultipleTrustee = std::ptr::null_mut();
                    explicit_access_failure.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
                    explicit_access_failure.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
                    explicit_access_failure.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
                    explicit_access_failure.Trustee.ptstrName = pwstr;
                    let mut explicit_access_success = EXPLICIT_ACCESS_W::default();
                    explicit_access_success.grfAccessPermissions = GENERIC_ALL.0;
                    explicit_access_success.grfAccessMode = SET_AUDIT_SUCCESS;
                    explicit_access_success.grfInheritance = NO_INHERITANCE;
                    explicit_access_success.Trustee.pMultipleTrustee = std::ptr::null_mut();
                    explicit_access_success.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
                    explicit_access_success.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
                    explicit_access_success.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
                    explicit_access_success.Trustee.ptstrName = pwstr;

                    let mut explicit_access_array = [explicit_access_failure, explicit_access_success];
                    //println!();
                    //println!("Explicit access: {:?}", explicit_access);
                    //println!("PWSTR text: {:?}", explicit_access.Trustee.ptstrName.to_string().unwrap());
                    //println!();

                    //let mut new_acl: *mut ACL = &mut ACL::default();
                    let mut new_acl: *mut [c_void; 65536] = &mut [const { std::mem::zeroed() }; 65536] as *mut _;
                    let mut tacl = new_acl as *mut ACL;
                    println!("The old ACL is: {:?}", acl);
                    //let array = &mut [*explicit_access];
                    //println!("Array: {:?}", array);
                    let result = SetEntriesInAclW(
                        Some(&explicit_access_array),
                        Some(&acl),
                        &mut tacl
                    );
                    println!("Result = {:?}", result);

                    println!("The new ACL is: {:?}", *tacl);
                    println!("Getting ACL ACEs...");
                    //let cacl = *tacl as *mut ACL;
                    for n in 0..(*tacl).AceCount {
                        let sacl = *tacl;
                        let mut pace: *mut c_void = std::ptr::null_mut();
                        GetAce(&sacl, n as u32, &mut pace);

                        let ace_header: *mut ACE_HEADER = pace as *mut ACE_HEADER;
                        println!("ACE_HEADER: {:?}", *ace_header);
                        //acl.AclSize += (*ace_header).AceSize;
                    }



                    //println!("Monitor PSI: {:?}", security_info);
                    //use std::ffi::c_void;
                    //let mut ace: [u8; 28] = [std::mem::zeroed(); 28];
                    //let ace_info: *mut *mut c_void = &mut &mut ace as *mut _ as *mut _;
                    //GetAce(&acl, 0, ace_info);
                    //let ptr_ace_struct = *ace_info as *mut SYSTEM_AUDIT_OBJECT_ACE;
                    //println!("ACE entry: {:?}", * ptr_ace_struct);

                    /*let ace = SYSTEM_AUDIT_OBJECT_ACE {
                        Header: ,
                        Mask: ,
                        Flags: ,
                        ObjectType: ,
                        InheritedObjectType: ,
                        SidStart: ,
                    };
                    AddAce(acl, acl.AclRevision, MAXDWORD, &ace, size_of::<ACE> as u32);*/

                    /*let mut iacl = ACL::default();
                    match InitializeAcl(&mut iacl, (size_of::<ACL>() as u32) * 100, ACL_REVISION_DS) {
                        Ok(_v) => println!("ACL initialized!"),
                        Err(e) => println!("Error initializing ACL, {:?}", e)
                    };
                    println!("Initialized ACL: {:?}", iacl);*/

                    // Initialize a new security descriptor
                    /*println!("Initializing Security Descriptor");
                    match InitializeSecurityDescriptor(security_info,
                        SECURITY_DESCRIPTOR_REVISION){
                        Ok(_v) => println!("Security Descriptor initialized."),
                        Err(_e) => println!("Error initializing security descriptor")
                    };

                    println!("Initialized SecDesc: {:?}", security_info);*/

                    //add_security_ace(new_acl, sid);
                    //set_security_info(handle, new_acl);
                    // disable_privilege();
                }

                //debug!("Monitoring windows '{}' audit path.", path);
            }
        }
    }
    let mut last_position = 0;
    if ! cfg.clone().audit.is_empty() && utils::get_os() == "linux" && utils::check_auditd() {
        for element in cfg.clone().audit {
            let path = element["path"].as_str().unwrap();
            let rule = utils::get_audit_rule_permissions(element["rule"].as_str());
            utils::run_auditctl(&["-w", path, "-k", "fim", "-p", &rule]);
            info!("Checking audit path: {}", path);

            match element["allowed"].as_vec() {
                Some(allowed) => {
                    let allowed_vec  = allowed.iter().map(|e| e.as_str().unwrap() );
                    let allowed_list : String = Itertools::intersperse(allowed_vec, ", ").collect();
                    info!("Only files with '{}' will trigger event inside '{}' path.", allowed_list, path)
                },
                None => debug!("Monitoring files under '{}' path.", path)
            };

            match element["exclude"].as_vec() {
                Some(ex) => {
                    let exclude_vec  = ex.iter().map(|e| e.as_str().unwrap() );
                    let exclude_list : String = Itertools::intersperse(exclude_vec, ", ").collect();
                    info!("Excluding folders: '{}' inside '{}' path.", exclude_list, path);
                },
                None => debug!("Exclude folders for '{}' path not set.", path)
            };

            match element["ignore"].as_vec() {
                Some(ig) => {
                    let ignore_list_vec  = ig.iter().map(|e| e.as_str().unwrap() );
                    let ignore_list : String = Itertools::intersperse(ignore_list_vec, ", ").collect();
                    info!("Ignoring files with: '{}' inside '{}' path", ignore_list, path);
                },
                None => info!("Ignore for '{}' pat not set", path)
            };
        }
        // Detect if Audit file is moved or renamed (rotation)
        watcher.watch(Path::new(logreader::AUDIT_PATH), RecursiveMode::NonRecursive).unwrap();
        last_position = utils::get_file_end(logreader::AUDIT_LOG_PATH, 0);

        // Remove auditd rules introduced by FIM
        // Setting ctrl + C handler
        let cloned_cfg = cfg.clone();
        match ctrlc::set_handler(move || clean_audit_rules(&cloned_cfg)) {
            Ok(_v) => debug!("Handler Ctrl-C set and listening"),
            Err(e) => error!("Error setting Ctrl-C handler, the process will continue without signal handling, Error: '{}'", e)
        }
    }


    // ----------------------------------------

    // Subscribing to windows event channel
    wineventsubscriber::subscribe_event_channel(cfg.clone(), ruleset.clone());

    // Main loop, receive any produced event and write it into the events log.
    loop {
        for message in &rx {
            match message {
                Ok(event) => {
                    // Get the event path and filename
                    debug!("Event received: {:?}", event);

                    let plain_path: &str = match event.paths.len() {
                        0 => "UNKNOWN",
                        _ => event.paths[0].to_str().unwrap()
                    };
                    if plain_path == "DISCONNECT" {
                        info!("Received exit signal, exiting...");
                        break;
                    }

                    let event_path = Path::new(plain_path);
                    let event_filename = event_path.file_name().unwrap();

                    let current_date = OffsetDateTime::now_utc();
                    let index_name = format!("fim-{}-{}-{}", current_date.year(), current_date.month() as u8, current_date.day() );
                    let current_timestamp = format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis());
                    let kind: notify::EventKind = event.kind;
                    let path = event.paths[0].clone();

                    // Reset reading position due to log rotation
                    if plain_path == logreader::AUDIT_LOG_PATH && kind == EventKind::Access(AccessKind::Any) {
                        last_position = 0;
                    }

                    // If the event comes from audit.log
                    if plain_path == logreader::AUDIT_LOG_PATH {
                        // Getting events from audit.log
                        let mut events = Vec::new();
                        let (log_event, position) = logreader::read_log(String::from(logreader::AUDIT_LOG_PATH), cfg.clone(), last_position, 0);
                        if log_event.id != "0" { events.push(log_event); };
                        let mut ctr = 0;
                        last_position = position;
                        while last_position < utils::get_file_end(logreader::AUDIT_LOG_PATH, 0) {
                            debug!("Reading events, iteration: {}", ctr);
                            let original_position = last_position;
                            ctr += 1;
                            let (evt, pos) = logreader::read_log(String::from(logreader::AUDIT_LOG_PATH), cfg.clone(), last_position, ctr);
                            if evt.id != "0" {
                                events.push(evt);
                                ctr = 0;
                            };
                            last_position = pos;
                            if original_position == pos {
                                ctr = 0;
                            }
                        }
                        debug!("Events read from audit log, position: {}", last_position);

                        for audit_event in events {
                            if ! audit_event.is_empty() {
                                // Getting the position of event in config (match ignore and labels)
                                let index = cfg.get_index(audit_event.clone().path.as_str(),
                                    audit_event.clone().cwd.as_str(),
                                    cfg.clone().audit.to_vec());

                                if index != usize::MAX {
                                    // If event contains ignored string ignore event
                                    if ! cfg.match_ignore(index, audit_event.clone().file.as_str(), cfg.clone().audit)  &&
                                        ! cfg.match_exclude(index, audit_event.clone().path.as_str(), cfg.clone().audit) &&
                                        cfg.match_allowed(index, audit_event.clone().file.as_str(), cfg.clone().audit) {
                                        audit_event.process(destination.clone().as_str(), index_name.clone(), cfg.clone(), ruleset.clone()).await;
                                    }else{
                                        debug!("Event ignored/excluded not stored in alerts");
                                    }
                                }else{
                                    debug!("Event not monitored by FIM");
                                }
                            }
                            debug!("Event processed: {:?}", audit_event.clone());
                        }
                    }else {
                        let index = cfg.get_index(event_path.to_str().unwrap(), "", cfg.clone().monitor.to_vec());
                        let parent = match event_path.is_dir() {
                            true => event_path.to_str().unwrap(),
                            false => event_path.parent().unwrap().to_str().unwrap()
                        };
                        if index != usize::MAX {
                            let labels = cfg.get_labels(index, cfg.clone().monitor);
                            if ! cfg.match_ignore(index, event_filename.to_str().unwrap(), cfg.clone().monitor) &&
                                ! cfg.match_exclude(index, parent, cfg.clone().monitor) &&
                                cfg.match_allowed(index, event_filename.to_str().unwrap(), cfg.clone().monitor) {
                                let event = MonitorEvent {
                                    id: utils::get_uuid(),
                                    timestamp: current_timestamp,
                                    hostname: utils::get_hostname(),
                                    node: cfg.clone().node,
                                    version: String::from(appconfig::VERSION),
                                    kind,
                                    path: path.clone(),
                                    size: utils::get_file_size(path.clone().to_str().unwrap()),
                                    labels,
                                    operation: event::get_operation(kind),
                                    detailed_operation: event::get_detailed_operation(kind),
                                    checksum: hash::get_checksum( String::from(path.to_str().unwrap()), cfg.clone().events_max_file_checksum ),
                                    fpid: utils::get_pid(),
                                    system: cfg.clone().system,
                                };

                                debug!("Event processed: {:?}", event);
                                //event.process(cfg.clone(), ruleset.clone()).await;
                                launcher::check_integrations(event.clone(), cfg.clone());
                            }else{
                                debug!("Event ignored/excluded not stored in alerts");
                            }
                        }else{
                            debug!("Event not matched monitor");
                        }
                    }
                },
                Err(e) => {
                    error!("Watch for event failed, error: {:?}", e);
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::block_on;

    // ------------------------------------------------------------------------

    #[test]
    fn test_push_template() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        fs::create_dir_all(Path::new(&cfg.log_file).parent().unwrap().to_str().unwrap()).unwrap();
        block_on(push_template("file", cfg.clone()));
        block_on(push_template("network", cfg.clone()));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_setup_events() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        fs::create_dir_all(Path::new(&cfg.log_file).parent().unwrap().to_str().unwrap()).unwrap();
        setup_events("file", cfg.clone());
        setup_events("network", cfg.clone());
    }
}
