// Copyright (C) 2025, Achiefs.

use log::{info, error, debug, warn};
use std::path::Path;
use notify::RecursiveMode;
use yaml_rust::Yaml;

use crate::logreader;
use crate::config::Config;
use crate::multiwatcher::MultiWatcher;
use crate::utils::{
    check_auditd,
    get_os,
    run_auditctl,
    get_audit_rule_permissions
};

fn clean_audit_rules(cfg: &Config){
    for element in cfg.audit.clone() {
        let path = element["path"].as_str().unwrap();
        let rule = get_audit_rule_permissions(element["rule"].as_str());
        run_auditctl(&["-W", path, "-k", "fim", "-p", &rule]);
    }
    std::process::exit(0);
}

// ----------------------------------------------------------------------------

fn print_validation(element: &Yaml, name: &str, path: &str) {
    match element[name].as_vec() {
        Some(e) => {
            info!("{} files with: '{}' inside '{}' path.", name,
                e.iter()
                .map(|e| e.as_str().unwrap())
                .collect::<Vec<_>>()
                .join(", "),
                path
            );
        },
        None => debug!("{} for '{}' path not set.", name, path)
    };
}

// ----------------------------------------------------------------------------

pub fn set_monitor_watchers(watcher: &mut MultiWatcher, cfg: &Config) {
    for element in &cfg.monitor {
        let path = element["path"].as_str().unwrap();
        print_validation(element, "ignore", path);
        print_validation(element, "exclude", path);
        print_validation(element, "allowed", path);

        match watcher.watch(Path::new(path), RecursiveMode::Recursive) {
            Ok(_d) => info!("Monitoring '{}' path.", path),
            Err(e) => warn!("Could not monitor given path '{}', description: {}", path, e)
        };
    }
}

// ----------------------------------------------------------------------------

pub fn set_audit_watchers(watcher: &mut MultiWatcher, cfg: &Config) {
    if get_os() == "linux" && check_auditd() {
        for element in &cfg.audit {
            let path = element["path"].as_str().unwrap();
            let rule = get_audit_rule_permissions(element["rule"].as_str());
            run_auditctl(&["-w", path, "-k", "fim", "-p", &rule]);
            info!("Checking audit path: {}", path);

            print_validation(element, "ignore", path);
            print_validation(element, "exclude", path);
            print_validation(element, "allowed", path);
        }
        // Detect if Audit file is moved or renamed (rotation)
        watcher.watch(Path::new(logreader::AUDIT_PATH), RecursiveMode::NonRecursive).unwrap();
       
        // Remove auditd rules introduced by FIM
        // Setting ctrl + C handler
        let cloned_cfg = cfg.clone();
        match ctrlc::set_handler(move || clean_audit_rules(&cloned_cfg)) {
            Ok(_v) => debug!("Handler Ctrl-C set and listening"),
            Err(e) => error!("Error setting Ctrl-C handler, the process will continue without signal handling, Error: '{}'", e)
        }
    }
}