// Copyright (C) 2024, Achiefs.

// Global definitions
const RULESET_MACOS_PATH: &str = "/Applications/FileMonitor.app/rules.yml";
const RULESET_LINUX_PATH: &str = "/etc/fim/rules.yml";
const RULESET_WINDOWS_PATH: &str = "C:\\Program Files\\File Integrity Monitor\\rules.yml";

use yaml_rust::yaml::{Yaml, YamlLoader, Array};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use crate::utils;

// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct Ruleset {
    pub path: String,
    pub monitor: Array,
    pub audit: Array,
    pub node: String,
    pub system: String
}

impl Ruleset {

    pub fn clone(&self) -> Self {
        Ruleset {
            path: self.path.clone(),
            monitor: self.monitor.clone(),
            audit: self.audit.clone(),
            node: self.node.clone(),
            system: self.system.clone()
        }
    }

    pub fn new(system: &str, ruleset_path: Option<&str>) -> Self {
        println!("[INFO] System detected '{}'", system);
        let cfg = match ruleset_path {
            Some(path) => String::from(path),
            None => get_ruleset_path(system)
        };
        println!("[INFO] Loading rules from: '{}'", cfg);
        let yaml = read_ruleset(cfg.clone());
        println!("{:?}", yaml.clone());

        // Manage null value on monitor value
        let monitor = match yaml[0]["monitor"].as_vec() {
            Some(value) => value.to_vec(),
            None => Vec::new()
        };

        // Manage null value on audit value
        let audit = match yaml[0]["audit"].as_vec() {
            Some(value) => {
                if utils::get_os() != "linux"{
                    panic!("Audit only supported in Linux systems.");
                }
                value.to_vec()
            },
            None => {
                if monitor.is_empty() {
                    panic!("Neither monitor or audit section found in rules.yml.");
                };
                Vec::new()
            }
        };

        // Manage null value on node value
        let node = match yaml[0]["node"].as_str() {
            Some(value) => String::from(value),
            None => {
                match system {
                    "linux" => match utils::get_machine_id().is_empty() {
                        true => utils::get_hostname(),
                        false => utils::get_machine_id()
                    },
                    "macos" => match utils::get_machine_id().is_empty(){
                        true => utils::get_hostname(),
                        false => utils::get_machine_id()
                    }
                    _ => {
                        println!("[WARN] node not found in rules.yml, using hostname.");
                        utils::get_hostname()
                    }
                }
            }
        };

        Ruleset {
            path: cfg,
            monitor,
            audit,
            node,
            system: String::from(system)
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_index(&self, raw_path: &str, cwd: &str, array: Array) -> usize {
        // Iterate over monitoring paths to match the given path
        match array.iter().position(|it| {
            if !cwd.is_empty() && (raw_path.starts_with("./") || raw_path == "." || !raw_path.contains('/')) {
                utils::match_path(cwd, it["path"].as_str().unwrap())
            }else{
                utils::match_path(raw_path, it["path"].as_str().unwrap())
            }
        }){
            Some(pos) => pos,
            None => usize::MAX
        }
    }

    // ------------------------------------------------------------------------

    pub fn clean_rule(raw_rule: String) -> String {
        let mut rule = raw_rule.clone();
        rule.retain(|x| {!['\"', ':', '\'', '/', '|', '>', '<', '?'].contains(&x)});
        rule
    }

    // ------------------------------------------------------------------------

    pub fn get_rule(&self, index: usize, array: Array) -> String {
        match array[index]["rule"].as_str() {
            Some(rule) => String::from(Ruleset::clean_rule(String::from(rule))),
            None => String::from("")
        }
    }
}

// ----------------------------------------------------------------------------

pub fn read_ruleset(path: String) -> Vec<Yaml> {
    let mut file: File = File::open(path.clone())
        .unwrap_or_else(|_| panic!("(read_ruleset): Unable to open file '{}'", path));
    let mut contents: String = String::new();

    file.read_to_string(&mut contents)
        .expect(&format!("(read_ruleset): Unable to read contents of file '{}'", path));
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
    use super::*;

    // ------------------------------------------------------------------------

    /*pub fn create_test_config(filter: &str, events_destination: &str) -> Config {
        Config {
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
            node: String::from("test"),
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
        let config = create_test_config("info", "");
        let cloned = config.clone();
        assert_eq!(config.version, cloned.version);
        assert_eq!(config.path, cloned.path);
        assert_eq!(config.events_destination, cloned.events_destination);
        assert_eq!(config.events_max_file_checksum, cloned.events_max_file_checksum);
        assert_eq!(config.events_max_file_size, cloned.events_max_file_size);
        assert_eq!(config.endpoint_type, cloned.endpoint_type);
        assert_eq!(config.endpoint_address, cloned.endpoint_address);
        assert_eq!(config.endpoint_user, cloned.endpoint_user);
        assert_eq!(config.endpoint_pass, cloned.endpoint_pass);
        assert_eq!(config.endpoint_token, cloned.endpoint_token);
        assert_eq!(config.events_file, cloned.events_file);
        assert_eq!(config.monitor, cloned.monitor);
        assert_eq!(config.audit, cloned.audit);
        assert_eq!(config.node, cloned.node);
        assert_eq!(config.log_file, cloned.log_file);
        assert_eq!(config.log_level, cloned.log_level);
        assert_eq!(config.log_max_file_size, cloned.log_max_file_size);
        assert_eq!(config.system, cloned.system);
        assert_eq!(config.insecure, cloned.insecure);
    }*/

}
