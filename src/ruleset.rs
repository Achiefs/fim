// Copyright (C) 2024, Achiefs.

// Global definitions
const RULESET_MACOS_PATH: &str = "/Applications/FileMonitor.app/rules.yml";
const RULESET_LINUX_PATH: &str = "/etc/fim/rules.yml";
const RULESET_WINDOWS_PATH: &str = "C:\\Program Files\\File Integrity Monitor\\rules.yml";

use yaml_rust::yaml::{Yaml, YamlLoader};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::collections::HashMap;
use log::{debug, error};
use std::path::PathBuf;
use regex::Regex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::utils;
use crate::appconfig;
use crate::appconfig::*;
use crate::event;
use event::Event;
use crate::ruleevent::RuleEvent;

// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct Ruleset {
    pub rules: HashMap<usize, HashMap<String, String>>,
}

impl Ruleset {

    pub fn clone(&self) -> Self {
        Ruleset {
            rules: self.rules.clone()
        }
    }

    pub fn new(system: &str, path: Option<&str>) -> Self {
        println!("[INFO] Reading ruleset...");
        let rules_file = match path {
            Some(p) => String::from(p),
            None => get_ruleset_path(system)
        };
        println!("[INFO] Loading rules from: '{}'", rules_file);
        
        let yaml = read_ruleset(rules_file.clone());

        // Manage null value on rules
        let mut rules = HashMap::new();
        if !yaml.is_empty() {
            let vec_of_rules = match yaml[0]["rules"].as_vec() {
                Some(value) => value.to_vec(),
                None => {
                    println!("[INFO] No rules to load.");
                    Vec::new()
                }
            };
        
            let itr = vec_of_rules.iter();
            itr.for_each(|yml| {
                let mut map = HashMap::new();
                match yml["path"].as_str() {
                    Some(p) => map.insert(String::from("path"), String::from(p)),
                    None => panic!("[ERROR] Ruleset syntax error, attribute 'path' in rule not defined. \
                                        Required fields in rule are 'path', 'rule', 'message' and 'id'.")
                };
                match yml["rule"].as_str() {
                    Some(r) => map.insert(String::from("rule"), sanitize(r)),
                    None => panic!("[ERROR] Ruleset syntax error, attribute 'rule' in rule not defined. \
                                        Required fields in rule are 'path', 'rule', 'message' and 'id'.")
                };
                match yml["message"].as_str() {
                    Some(m) => map.insert(String::from("message"), String::from(m)),
                    None => panic!("[ERROR] Ruleset syntax error, attribute 'message' in rule not defined. \
                                        Required fields in rule are 'path', 'rule', 'message' and 'id'.")
                };

                let id = match yml["id"].as_i64() {
                    Some(value) => usize::try_from(value).unwrap(),
                    None => panic!("[ERROR] Ruleset syntax error, attribute 'id' in rule not defined. \
                    Required fields in rule are 'path', 'rule', 'message' and 'id'.")
                };
                rules.insert(id, map);
            });
            println!("[INFO] Ruleset successfully load.");
        }else{
            println!("[INFO] Ruleset empty, nothing to do.");
        }

        Ruleset { rules }
    }

    // ------------------------------------------------------------------------

    pub async fn match_rule(&self, cfg: AppConfig, filepath: PathBuf) -> (bool, usize) {
        let path = match filepath.parent() {
            Some(p) => p.to_str().unwrap(),
            None => {
                error!("(match_rule): Cannot retrieve event parent path.");
                ""
            }
        };
        let find = self.rules.iter().find(|map| {
            map.1.contains_key("path") && utils::match_path(map.1.get("path").unwrap(), path)
        });

        let (id, rule) = match find {
            Some(element) => (*element.0, element.1.get("rule").unwrap().clone()),
            None => {
                debug!("No rule matched");
                (usize::MAX, String::from(""))
            }
        };
        
        let expression = match Regex::new(&rule){
            Ok(exp) => exp,
            Err(e) => {
                error!("Cannot create regex rule: {}, Error: {}", rule, e);
                return (false, usize::MAX);
            },
        };

        let filename = match filepath.file_name() {
            Some(f) => f.to_str().unwrap(),
            None => {
                error!("(match_rule): Cannot retrieve event filename.");
                ""
            }
        };
        if id != usize::MAX {
            if expression.is_match(filename){
                debug!("Rule with ID: '{}', match event path: '{}'.", id, path);
                // Send rule event
                let event = RuleEvent {
                    id,
                    rule,
                    timestamp: format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis()),
                    hostname: utils::get_hostname(),
                    node: cfg.clone().node,
                    version: String::from(appconfig::VERSION),
                    path: filepath,
                    fpid: utils::get_pid(),
                    system: cfg.clone().system,
                    message: self.rules.get(&id).unwrap().get("message").unwrap().clone()
                };
                event.process(cfg, self.clone()).await;
                (true, id)
            } else { (false, usize::MAX) }
        } else { (false, usize::MAX) }
    }
}

// ----------------------------------------------------------------------------

pub fn sanitize(raw_rule: &str) -> String {
    let mut rule = String::from(raw_rule);
    rule.retain(|x| {!['\"', ':', '\'', '/', '|', '>', '<', '?'].contains(&x)});
    rule
}

// ----------------------------------------------------------------------------

pub fn read_ruleset(path: String) -> Vec<Yaml> {
    let mut file: File = File::open(path.clone())
        .unwrap_or_else(|_| panic!("(read_ruleset): Unable to open file '{}'", path));
    let mut contents: String = String::new();

    file.read_to_string(&mut contents)
        .unwrap_or_else(|_| panic!("(read_ruleset): Unable to read contents of file '{}'", path));
    YamlLoader::load_from_str(&contents).unwrap()
}


// ----------------------------------------------------------------------------

pub fn get_ruleset_path(system: &str) -> String {
    // Select directory where to load rules.yml it depends on system
    let current_dir: String = utils::get_current_dir();
    if system == "windows" {
        let default_path: String = format!("{}\\config\\{}\\rules.yml", current_dir, system);
        let relative_path: String = format!("{}\\..\\..\\config\\{}\\rules.yml", current_dir, system);
        if Path::new(default_path.as_str()).exists() {
            default_path
        }else if Path::new(&format!("{}\\rules.yml", current_dir)).exists() {
            format!("{}\\rules.yml", current_dir)
        }else if Path::new(relative_path.as_str()).exists() {
            relative_path
        }else{
            String::from(RULESET_WINDOWS_PATH)
        }
    }else{
        let default_path: String = format!("{}/config/{}/rules.yml", current_dir, system);
        let relative_path: String = format!("{}/../../config/{}/rules.yml", current_dir, system);
        if Path::new(default_path.as_str()).exists() {
            default_path
        }else if Path::new(&format!("{}/rules.yml", current_dir)).exists() {
            format!("{}/rules.yml", current_dir)
        }else if Path::new(relative_path.as_str()).exists() {
            relative_path
        }else if system == "macos" {
            String::from(RULESET_MACOS_PATH)
        }else{
            String::from(RULESET_LINUX_PATH)
        } 
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //use super::*;

    // ------------------------------------------------------------------------

    /*pub fn create_test_config(filter: &str, events_destination: &str) -> AppConfig {
        AppConfig {
            version: String::from(VERSION),
            path: String::from("test"),
            events_watcher: String::from("Recommended"),
            events_destination: String::from(events_destination),
            events_max_file_checksum: 64,
            events_max_file_size: 128,
            endpoint_type: String::from("Elastic"),
            endpoint_address: String::from("test"),
            endpoint_user: String::from("test"),
            endpoint_pass: String::from("test"),
            endpoint_token: String::from("test"),
            events_file: String::from("test"),
            monitor: Array::new(),
            audit: Array::new(),
            log_file: String::from("./test.log"),
            log_level: String::from(filter),
            log_max_file_size: 64,
            system: String::from("test"),
            insecure: true
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_clone() {
        let cfg = create_test_config("info", "");
        let cloned = cfg.clone();
        assert_eq!(cfg.version, cloned.version);
        assert_eq!(cfg.path, cloned.path);
        assert_eq!(cfg.events_destination, cloned.events_destination);
        assert_eq!(cfg.events_max_file_checksum, cloned.events_max_file_checksum);
        assert_eq!(cfg.events_max_file_size, cloned.events_max_file_size);
        assert_eq!(cfg.endpoint_type, cloned.endpoint_type);
        assert_eq!(cfg.endpoint_address, cloned.endpoint_address);
        assert_eq!(cfg.endpoint_user, cloned.endpoint_user);
        assert_eq!(cfg.endpoint_pass, cloned.endpoint_pass);
        assert_eq!(cfg.endpoint_token, cloned.endpoint_token);
        assert_eq!(cfg.events_file, cloned.events_file);
        assert_eq!(cfg.monitor, cloned.monitor);
        assert_eq!(cfg.audit, cloned.audit);
        assert_eq!(cfg.log_file, cloned.log_file);
        assert_eq!(cfg.log_level, cloned.log_level);
        assert_eq!(cfg.log_max_file_size, cloned.log_max_file_size);
        assert_eq!(cfg.system, cloned.system);
        assert_eq!(cfg.insecure, cloned.insecure);
    }*/

}
