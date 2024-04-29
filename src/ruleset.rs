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

    pub async fn match_rule(&self, cfg: AppConfig, filepath: PathBuf, ruleid: String) -> (bool, usize) {
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
                    version: String::from(appconfig::VERSION),
                    path: filepath,
                    fpid: utils::get_pid(),
                    system: cfg.clone().system,
                    message: self.rules.get(&id).unwrap().get("message").unwrap().clone(),
                    parent_id: ruleid
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
    use super::*;
    use tokio_test::block_on;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_get_ruleset_path_unix() {
        let current_dir = utils::get_current_dir();
        let default_path_linux = format!("{}/config/linux/rules.yml", current_dir);
        let default_path_macos = format!("{}/config/macos/rules.yml", current_dir);
        assert_eq!(get_ruleset_path("linux"), default_path_linux);
        assert_eq!(get_ruleset_path("macos"), default_path_macos);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_ruleset_path_windows() {
        let current_dir = utils::get_current_dir();
        let default_path_windows = format!("{}\\config\\windows\\rules.yml", current_dir);
        assert_eq!(get_ruleset_path("windows"), default_path_windows);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_read_ruleset_unix() {
        let yaml = read_ruleset(String::from("config/linux/rules.yml"));

        assert_eq!(yaml[0]["rules"][0]["id"].as_i64().unwrap(), 1);
        assert_eq!(yaml[0]["rules"][0]["path"].as_str().unwrap(), "/etc");
        assert_eq!(yaml[0]["rules"][0]["rule"].as_str().unwrap(), "\\.sh$");
        assert_eq!(yaml[0]["rules"][0]["message"].as_str().unwrap(), "Shell script present in /etc folder.");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_read_ruleset_windows() {
        let yaml = read_ruleset(String::from("config/windows/rules.yml"));

        assert_eq!(yaml[0]["rules"][0]["id"].as_i64().unwrap(), 1);
        assert_eq!(yaml[0]["rules"][0]["path"].as_str().unwrap(), "C:\\");
        assert_eq!(yaml[0]["rules"][0]["rule"].as_str().unwrap(), "\\.ps1$");
        assert_eq!(yaml[0]["rules"][0]["message"].as_str().unwrap(), "Powershell script present in root directory.");
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "NotFound")]
    fn test_read_ruleset_panic() {
        read_ruleset(String::from("NotFound"));
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "ScanError")]
    fn test_read_ruleset_panic_not_config() {
        read_ruleset(String::from("README.md"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_sanitize() {
        assert_eq!("test", sanitize("test"));
        assert_eq!("test", sanitize("t\"est"));
        assert_eq!("C\\test", sanitize("C:\\test"));
        assert_eq!("test", sanitize("t\'est"));
        assert_eq!("test", sanitize("t/est"));
        assert_eq!("test", sanitize("t|est"));
        assert_eq!("test", sanitize("t>est"));
        assert_eq!("test", sanitize("t<est"));
        assert_eq!("test", sanitize("t?est"));
        assert_eq!("\\.php$", sanitize("\\.php$"));
        assert_ne!("\\.php", sanitize("\\.php$"));        
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_match_rule_unix() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        let ruleset = Ruleset::new(&utils::get_os(), None); 

        let (result, id) = block_on(ruleset.match_rule(cfg.clone(), PathBuf::from("/etc/file.sh"), String::from("0000")));
        assert_eq!(id, 1);
        assert_eq!(result, true);

        let (result, id) = block_on(ruleset.match_rule(cfg, PathBuf::from("/etc/file.php"), String::from("0000")));
        assert_eq!(id, usize::MAX);
        assert_eq!(result, false);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_match_rule_windows() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        let ruleset = Ruleset::new(&utils::get_os(), None); 

        let (result, id) = block_on(ruleset.match_rule(cfg.clone(), PathBuf::from("C:\\file.ps1"), String::from("0000")));
        assert_eq!(id, 1);
        assert_eq!(result, true);

        let (result, id) = block_on(ruleset.match_rule(cfg, PathBuf::from("C:\\file.php"), String::from("0000")));
        assert_eq!(id, usize::MAX);
        assert_eq!(result, false);
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_new_unix() {
        let ruleset = Ruleset::new(&utils::get_os(), None);
        let element = ruleset.rules.get(&1usize).unwrap();

        assert_eq!(element.get("path").unwrap(), "/etc");
        assert_eq!(element.get("rule").unwrap(), "\\.sh$");
        assert_eq!(element.get("message").unwrap(), "Shell script present in /etc folder.");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_windows() {
        let ruleset = Ruleset::new(&utils::get_os(), None);
        let element = ruleset.rules.get(&1usize).unwrap();
        assert_eq!(element.get("path").unwrap(), "C:\\");
        assert_eq!(element.get("rule").unwrap(), "\\.ps1$");
        assert_eq!(element.get("message").unwrap(), "Powershell script present in root directory.");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_clone() {
        let ruleset = Ruleset::new(&utils::get_os(), None);
        let cloned = ruleset.clone();
        let ruleset_values = ruleset.rules.get(&1usize).unwrap();
        let cloned_values = cloned.rules.get(&1usize).unwrap();

        assert_eq!(ruleset.rules.keys().next(), cloned.rules.keys().next());
        assert_eq!(ruleset_values, cloned_values);
        assert_eq!(ruleset_values.get("path").unwrap(), cloned_values.get("path").unwrap());
        assert_eq!(ruleset_values.get("rule").unwrap(), cloned_values.get("rule").unwrap());
        assert_eq!(ruleset_values.get("message").unwrap(), cloned_values.get("message").unwrap());
    }

}
