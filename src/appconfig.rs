// Copyright (C) 2021, Achiefs.

// Global constants definitions
pub const VERSION: &str = "0.6.0";
pub const NETWORK_MODE: &str = "NETWORK";
pub const FILE_MODE: &str = "FILE";
pub const BOTH_MODE: &str = "BOTH";
pub const MACHINE_ID_PATH: &str = "/etc/machine-id";
const CONFIG_MACOS_PATH: &str = "/Applications/FileMonitor.app/config.yml";
const CONFIG_LINUX_PATH: &str = "/etc/fim/config.yml";
const CONFIG_WINDOWS_PATH: &str = "C:\\Program Files\\File Integrity Monitor\\config.yml";

// Required dependencies
use yaml_rust::yaml::{Yaml, YamlLoader, Array};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use simplelog::LevelFilter;
use std::sync::{Arc, Mutex};
use log::error;

use crate::utils;
use crate::integration::Integration;
use crate::hash::ShaType;

// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppConfig {
    pub version: String,
    pub path: String,
    pub events_watcher: String,
    pub events_destination: String,
    pub events_max_file_checksum: usize,
    pub events_max_file_size: usize,
    pub checksum_algorithm: ShaType,
    pub endpoint_type: String,
    pub endpoint_address: String,
    pub endpoint_user: String,
    pub endpoint_pass: String,
    pub endpoint_token: String,
    pub events_file: String,
    pub monitor: Array,
    pub audit: Array,
    pub node: String,
    pub log_file: String,
    pub log_level: String,
    pub log_max_file_size: usize,
    pub system: String,
    pub insecure: bool,
    pub events_lock: Arc<Mutex<bool>>,
    pub log_lock: Arc<Mutex<bool>>,
    pub hashscanner_file: String,
    pub hashscanner_enabled: bool,
    pub hashscanner_interval: usize,
    pub hashscanner_algorithm: ShaType,
    pub engine: String
}

impl AppConfig {

    pub fn clone(&self) -> Self {
        AppConfig {
            version: self.version.clone(),
            path: self.path.clone(),
            events_watcher: self.events_watcher.clone(),
            events_destination: self.events_destination.clone(),
            events_max_file_checksum: self.events_max_file_checksum,
            events_max_file_size: self.events_max_file_size,
            checksum_algorithm: self.checksum_algorithm.clone(),
            endpoint_type: self.endpoint_type.clone(),
            endpoint_address: self.endpoint_address.clone(),
            endpoint_user: self.endpoint_user.clone(),
            endpoint_pass: self.endpoint_pass.clone(),
            endpoint_token: self.endpoint_token.clone(),
            events_file: self.events_file.clone(),
            monitor: self.monitor.clone(),
            audit: self.audit.clone(),
            node: self.node.clone(),
            log_file: self.log_file.clone(),
            log_level: self.log_level.clone(),
            log_max_file_size: self.log_max_file_size,
            system: self.system.clone(),
            insecure: self.insecure,
            events_lock: self.events_lock.clone(),
            log_lock: self.log_lock.clone(),
            hashscanner_file: self.hashscanner_file.clone(),
            hashscanner_enabled: self.hashscanner_enabled,
            hashscanner_interval: self.hashscanner_interval,
            hashscanner_algorithm: self.hashscanner_algorithm.clone(),
            engine: self.engine.clone()
        }
    }

    pub fn new(system: &str, config_path: Option<&str>) -> Self {
        println!("[INFO] System detected '{}'", system);
        let cfg = match config_path {
            Some(path) => String::from(path),
            None => get_config_path(system)
        };
        println!("[INFO] Loaded config from: '{}'", cfg);
        let yaml = read_config(cfg.clone());

        // Manage null value on events->destination value
        let events_destination = match yaml[0]["events"]["destination"].as_str() {
            Some(value) => String::from(value),
            None => {
                println!("[WARN] events->destination not found in config.yml, using 'file'.");
                String::from("file")
            }
        };

        // Manage value on events->watcher value
        let events_watcher = match yaml[0]["events"]["watcher"].as_str() {
            Some("poll"|"P"|"POLL"|"Poll") => String::from("Poll"),
            _ => String::from("Recommended")
        };

        // Manage null value on events->file value
        let events_file = match yaml[0]["events"]["file"].as_str() {
            Some(value) => String::from(value),
            None => {
                if events_destination != *"network" {
                    println!("[ERROR] events->file not found in config.yml.");
                    panic!("events->file not found in config.yml.");
                }else{
                    String::from("Not_defined")
                }
            }
        };

        // Manage null value on events->max_file_checksum value
        let events_max_file_checksum = match yaml[0]["events"]["max_file_checksum"].as_i64() {
            Some(value) => usize::try_from(value).unwrap(),
            None => 64
        };

        // Manage null value on events->max_file_size value
        let events_max_file_size = match yaml[0]["events"]["max_file_size"].as_i64() {
            Some(value) => usize::try_from(value).unwrap(),
            None => 128
        };

        // Temporal value
        let checksum_algorithm = match yaml[0]["events"]["checksum_algorithm"].as_str() {
            Some(value) => {
                match value {
                    "sha224"|"224"|"SHA224"|"Sha224" => ShaType::Sha224,
                    "sha256"|"256"|"SHA256"|"Sha256" => ShaType::Sha256,
                    "sha384"|"384"|"SHA384"|"Sha384" => ShaType::Sha384,
                    "sha512"|"512"|"SHA512"|"Sha512" => ShaType::Sha512,
                    "keccak224"|"K224"|"KECCAK224"|"Keccak224" => ShaType::Keccak224,
                    "keccak256"|"K256"|"KECCAK256"|"Keccak256" => ShaType::Keccak256,
                    "keccak384"|"K384"|"KECCAK384"|"Keccak384" => ShaType::Keccak384,
                    "keccak512"|"K512"|"KECCAK512"|"Keccak512" => ShaType::Keccak512,
                    _ => ShaType::Sha512
                }
            },
            None => ShaType::Sha256
        };

        let hashscanner_algorithm = match yaml[0]["hashscanner"]["algorithm"].as_str() {
            Some(value) => {
                match value {
                    "sha224"|"224"|"SHA224"|"Sha224" => ShaType::Sha224,
                    "sha256"|"256"|"SHA256"|"Sha256" => ShaType::Sha256,
                    "sha384"|"384"|"SHA384"|"Sha384" => ShaType::Sha384,
                    "sha512"|"512"|"SHA512"|"Sha512" => ShaType::Sha512,
                    "keccak224"|"K224"|"KECCAK224"|"Keccak224" => ShaType::Keccak224,
                    "keccak256"|"K256"|"KECCAK256"|"Keccak256" => ShaType::Keccak256,
                    "keccak384"|"K384"|"KECCAK384"|"Keccak384" => ShaType::Keccak384,
                    "keccak512"|"K512"|"KECCAK512"|"Keccak512" => ShaType::Keccak512,
                    _ => ShaType::Sha256
                }
            },
            None => ShaType::Sha256
        };

        // Manage null value on events->endpoint->insecure value
        let insecure = match yaml[0]["events"]["endpoint"]["insecure"].as_bool() {
            Some(value) => value,
            None => {
                if events_destination != *"file" {
                    println!("[WARN] events->endpoint->insecure not found in config.yml, using 'false'.");
                    false
                }else{ false }
            }
        };

        // Manage null value on events->endpoint->address value
        let endpoint_address = match yaml[0]["events"]["endpoint"]["address"].as_str() {
            Some(value) => String::from(value),
            None => {
                if events_destination != *"file" {
                    println!("[ERROR] events->endpoint->address not found in config.yml.");
                    panic!("events->endpoint->address not found in config.yml.");
                }else{
                    String::from("Not_defined")
                }
            }
        };

        // Manage null value on events->endpoint->credentials->token value
        let endpoint_token = match yaml[0]["events"]["endpoint"]["credentials"]["token"].as_str() {
            Some(value) => String::from(value),
            None => String::from("Not_defined")
        };

        // Manage null value on events->endpoint->credentials->user value
        let endpoint_user = match yaml[0]["events"]["endpoint"]["credentials"]["user"].as_str() {
            Some(value) => String::from(value),
            None => {
                if events_destination != *"file" && endpoint_token.is_empty() {
                    println!("[ERROR] events->endpoint->credentials->user not found in config.yml.");
                    panic!("events->endpoint->credentials->user not found in config.yml.");
                }else{
                    String::from("Not_defined")
                }
            }
        };

        // Manage null value on events->endpoint->credentials->password value
        let endpoint_pass = match yaml[0]["events"]["endpoint"]["credentials"]["password"].as_str() {
            Some(value) => String::from(value),
            None => {
                if events_destination != *"file" && endpoint_token.is_empty()  {
                    println!("[ERROR] events->endpoint->credentials->password not found in config.yml.");
                    panic!("events->endpoint->credentials->password not found in config.yml.");
                }else{
                    String::from("Not_defined")
                }
            }
        };

        let endpoint_type = if endpoint_token != "Not_defined" {
            String::from("Splunk")
        }else if endpoint_user != "Not_defined" && endpoint_pass != "Not_defined" {
            String::from("Elastic")
        }else{
            String::from("Not_defined")
        };

        if endpoint_token == "Not_defined" && (endpoint_user == "Not_defined" ||
            endpoint_pass == "Not_defined") && events_destination != *"file" {
            println!("[ERROR] events->endpoint->credentials->[token or user and password] not found in config.yml.");
            panic!("No endpoint credentials provided in config.yml.");
        }


        // Manage null value on monitor value
        let monitor = match yaml[0]["monitor"].as_vec() {
            Some(value) => value.to_vec(),
            None => Vec::new()
        };

        // Manage null value on audit value
        let mut engine = String::from("monitor");
        let audit = match yaml[0]["audit"].as_vec() {
            Some(value) => {
                if utils::get_os() != "linux" {
                    panic!("Audit only supported in Linux systems.");
                }
                engine = String::from("audit");
                value.to_vec()
            },
            None => {
                if monitor.is_empty() {
                    panic!("Neither monitor or audit section found in config.yml.");
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
                        println!("[WARN] node not found in config.yml, using hostname.");
                        utils::get_hostname()
                    }
                }
            }
        };

        // Manage null value on log->file value
        let log_file = match yaml[0]["log"]["file"].as_str() {
            Some(value) => String::from(value),
            None => {
                println!("[ERROR] log->file not found in config.yml.");
                panic!("log->file not found in config.yml.");
            }
        };

        // Manage null value on log->level value
        let log_level = match yaml[0]["log"]["level"].as_str() {
            Some(value) => String::from(value),
            None => {
                println!("[WARN] log->level not found in config.yml, using 'info'.");
                String::from("info")
            }
        };

        // Manage null value on log->max_file_size value
        let log_max_file_size = match yaml[0]["log"]["max_file_size"].as_i64() {
            Some(value) => usize::try_from(value).unwrap(),
            None => 64
        };

        // Manage null value on hashscanner->file value
        let hashscanner_file = match yaml[0]["hashscanner"]["file"].as_str() {
            Some(value) => String::from(value),
            None => {
                println!("[ERROR] hashscanner->file not found in config.yml.");
                panic!("hashscanner->file not found in config.yml.");
            }
        };

        let hashscanner_interval = match yaml[0]["hashscanner"]["interval"].as_i64() {
            Some(value) => {
                let interval = usize::try_from(value).unwrap();
                if interval >= 5 { interval * 60 }else{ 300 } // Minimum of five minutes 
            },
            None => 3600 // Default one hour
        };

        let hashscanner_enabled = yaml[0]["hashscanner"]["enabled"].as_bool().unwrap_or(true);

        AppConfig {
            version: String::from(VERSION),
            path: cfg,
            events_watcher,
            events_destination,
            events_max_file_checksum,
            events_max_file_size,
            checksum_algorithm,
            endpoint_type,
            endpoint_address,
            endpoint_user,
            endpoint_pass,
            endpoint_token,
            events_file,
            monitor,
            audit,
            node,
            log_file,
            log_level,
            log_max_file_size,
            system: String::from(system),
            insecure,
            events_lock: Arc::new(Mutex::new(false)),
            log_lock: Arc::new(Mutex::new(false)),
            hashscanner_file,
            hashscanner_enabled,
            hashscanner_interval,
            hashscanner_algorithm,
            engine
        }
    }

    // ------------------------------------------------------------------------

    // To process log level set on config file
    pub fn get_level_filter(&self) -> LevelFilter {
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_file.clone())
            .expect("(get_level_filter) Unable to open events log file.");

        match self.log_level.as_str() {
            "debug" | "Debug" | "DEBUG" | "D" | "d" => LevelFilter::Debug,
            "info" | "Info" | "INFO" | "I" | "i" => LevelFilter::Info,
            "error" | "Error" | "ERROR" | "E" | "e" => LevelFilter::Error,
            "warning" | "Warning" | "WARNING" | "W" | "w" | "warn" | "Warn" | "WARN" => LevelFilter::Warn,
            _ => {
                let msg = String::from("[ERROR] invalid log level from 'config.yml', using Info level.");
                println!("{}", msg);
                writeln!(log, "{}", msg).expect("[ERROR] cannot write in log file.");
                LevelFilter::Info
            }
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_events_destination(&self) -> String {
        match self.events_destination.clone().as_str() {
            "both" => String::from(BOTH_MODE),
            "network" => String::from(NETWORK_MODE),
            // Default option is to log into file
            _ => String::from(FILE_MODE)
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_index(&self, raw_path: &str, cwd: &str, array: Array) -> usize {
        // Iterate over monitoring paths to match ignore string and ignore event or not
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

    pub fn get_labels(&self, index: usize, array: Array) -> Vec<String> {
        array[index]["labels"].clone().into_vec().unwrap_or_default()
        .to_vec().iter().map(|element| String::from(element.as_str().unwrap()) ).collect()
    }

    // ------------------------------------------------------------------------

    pub fn match_ignore(&self, index: usize, filename: &str, array: Array) -> bool {
        match array[index]["ignore"].as_vec() {
            Some(igv) => igv.to_vec().iter().any(|ignore| filename.contains(ignore.as_str().unwrap()) ),
            None => false
        }
    }

    // ------------------------------------------------------------------------

    pub fn match_exclude(&self, index: usize, path: &str, array: Array) -> bool {
        match array[index]["exclude"].as_vec() {
            Some(igv) => igv.to_vec().iter().any(|exclude| path.contains(exclude.as_str().unwrap()) ),
            None => false
        }
    }

    // ------------------------------------------------------------------------

    pub fn match_allowed(&self, index: usize, filename: &str, array: Array) -> bool {
        match array[index]["allowed"].as_vec() {
            Some(allowed) => allowed.to_vec().iter().any(|allw| filename.contains(allw.as_str().unwrap())),
            None => true
        }
    }

    // ------------------------------------------------------------------------

    // Returns if a given path and filename is in the configuration paths
    pub fn path_in(&self, raw_path: &str, cwd: &str, vector: Vec<Yaml>) -> bool {
        // Iterate over monitoring paths to match ignore string and ignore event or not
        vector.iter().any(|it| {
            if raw_path.starts_with("./") || raw_path == "." || !raw_path.contains('/') {
                utils::match_path(cwd, it["path"].as_str().unwrap())
            }else{
                utils::match_path(raw_path, it["path"].as_str().unwrap())
            }
        })
    }

    // ------------------------------------------------------------------------

    pub fn get_integrations(&self, index: usize, array: Array) -> Vec<Integration> {
        let default = array[index]["integrations"].clone().into_vec();
        let data = default.unwrap_or_default();
        let mut integrations: Vec<Integration> = Vec::new();
        data.iter().for_each(|info|
            integrations.push(Integration::new(
                String::from(info["name"].as_str().unwrap()), 
                info["condition"]
                    .clone().into_vec().unwrap().iter().map(|element| 
                        String::from(element.as_str().unwrap()) ).collect(), 
                String::from(info["binary"].as_str().unwrap()), 
                String::from(info["script"].as_str().unwrap()), 
                String::from(info["parameters"].as_str().unwrap()) ))
        );
        integrations
    }

    // ------------------------------------------------------------------------

    pub fn get_lock_value(&self, lock: &Arc<Mutex<bool>>) -> bool {
        match Arc::into_inner(lock.into()) {
            None => {
                error!("Cannot retrieve events lock Arc value.");
                false
            },
            Some(mutex) => match mutex.lock() {
                Ok(guard) => *guard,
                Err(e) => {
                    error!("Cannot retrieve events lock Mutex value, err: {}.", e);
                    false
                }
            }
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_events_file(&self) -> String {
        match self.get_lock_value(&self.events_lock) {
            false => self.events_file.clone(),
            true => format!("{}.tmp", self.events_file.clone())
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_mutex(&self, lock: Arc<Mutex<bool>>) -> Mutex<bool> {
        match Arc::into_inner(lock.clone()) {
            None => {
                error!("Could not retrieve Mutex '{:?}'.", lock.clone());
                Mutex::new(false)
            },
            Some(mutex) => mutex
        }
    }

}

// ----------------------------------------------------------------------------

// To read the Yaml configuration file
pub fn read_config(path: String) -> Vec<Yaml> {
    let mut file: File = File::open(path.clone())
        .unwrap_or_else(|_| panic!("(read_config): Unable to open file '{}'", path));
    let mut contents: String = String::new();

    file.read_to_string(&mut contents)
        .expect("Unable to read file");
    YamlLoader::load_from_str(&contents).unwrap()
}

// ----------------------------------------------------------------------------

pub fn get_config_path(system: &str) -> String {
    // Select directory where to load config.yml it depends on system
    let current_dir: String = utils::get_current_dir();
    if system == "windows" {
        let default_path: String = format!("{}\\config\\{}\\config.yml", current_dir, system);
        let relative_path: String = format!("{}\\..\\..\\config\\{}\\config.yml", current_dir, system);
        if Path::new(default_path.as_str()).exists() {
            default_path
        }else if Path::new(&format!("{}\\config.yml", current_dir)).exists() {
            format!("{}\\config.yml", current_dir)
        }else if Path::new(relative_path.as_str()).exists() {
            relative_path
        }else{
            String::from(CONFIG_WINDOWS_PATH)
        }
    }else{
        let default_path: String = format!("{}/config/{}/config.yml", current_dir, system);
        let relative_path: String = format!("{}/../../config/{}/config.yml", current_dir, system);
        if Path::new(default_path.as_str()).exists() {
            default_path
        }else if Path::new(&format!("{}/config.yml", current_dir)).exists() {
            format!("{}/config.yml", current_dir)
        }else if Path::new(relative_path.as_str()).exists() {
            relative_path
        }else if system == "macos" {
            String::from(CONFIG_MACOS_PATH)
        }else{
            String::from(CONFIG_LINUX_PATH)
        } 
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------

    pub fn create_test_config(filter: &str, events_destination: &str) -> AppConfig {
        AppConfig {
            version: String::from(VERSION),
            path: String::from("test"),
            events_watcher: String::from("Recommended"),
            events_destination: String::from(events_destination),
            events_max_file_checksum: 64,
            events_max_file_size: 128,
            checksum_algorithm: ShaType::Sha512,
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
            insecure: true,
            events_lock: Arc::new(Mutex::new(false)),
            log_lock: Arc::new(Mutex::new(false)),
            hashscanner_file: String::from("test"),
            hashscanner_enabled: true,
            hashscanner_interval: 3600,
            hashscanner_algorithm: ShaType::Sha256,
            engine: String::from("monitor")
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
        assert_eq!(cfg.node, cloned.node);
        assert_eq!(cfg.log_file, cloned.log_file);
        assert_eq!(cfg.log_level, cloned.log_level);
        assert_eq!(cfg.log_max_file_size, cloned.log_max_file_size);
        assert_eq!(cfg.system, cloned.system);
        assert_eq!(cfg.insecure, cloned.insecure);
        assert_eq!(cfg.hashscanner_file, cloned.hashscanner_file);
        assert_eq!(cfg.hashscanner_enabled, cloned.hashscanner_enabled);
        assert_eq!(cfg.hashscanner_interval, cloned.hashscanner_interval);
        assert_eq!(cfg.hashscanner_algorithm, cloned.hashscanner_algorithm);
        assert_eq!(cfg.engine, cloned.engine);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows() {
        let dir = utils::get_current_dir();
        let disk = dir.get(0..1).unwrap();
        let cfg = AppConfig::new("windows", None);

        assert_eq!(cfg.version, String::from(VERSION));
        assert_eq!(cfg.events_destination, String::from("file"));
        assert_eq!(cfg.endpoint_address, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_type, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_user, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_pass, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_token, String::from("Not_defined"));
        assert_eq!(cfg.events_file, format!("{}:\\ProgramData\\fim\\events.json", disk) );
        // monitor
        // audit
        assert_eq!(cfg.node, String::from("FIM"));
        assert_eq!(cfg.log_file, format!("{}:\\ProgramData\\fim\\fim.log", disk) );
        assert_eq!(cfg.log_level, String::from("info"));
        assert_eq!(cfg.log_max_file_size, 64);
        assert_eq!(cfg.system, String::from("windows"));
        assert_eq!(cfg.insecure, false);
        assert_eq!(cfg.hashscanner_file, format!("{}:\\ProgramData\\fim\\fim.db", disk) );
        assert_eq!(cfg.hashscanner_enabled, true);
        assert_eq!(cfg.hashscanner_interval, 3600);
        assert_eq!(cfg.hashscanner_algorithm, ShaType::Sha256);
        assert_eq!(cfg.engine, String::from("monitor"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_destination() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_destination_none.yml"));
        assert_eq!(cfg.events_destination, String::from("file"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_hashscanner_file() {
        AppConfig::new("windows", Some("test/unit/config/windows/hashscanner_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_events_file() {
        AppConfig::new("windows", Some("test/unit/config/windows/events_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_destination_network() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_destination_network.yml"));
        assert_eq!(cfg.events_file, String::from("Not_defined"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_max_file_checksum() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_max_file_checksum.yml"));
        assert_eq!(cfg.events_max_file_checksum, 128);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_max_file_size() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_max_file_size.yml"));
        assert_eq!(cfg.events_max_file_size, 256);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_endpoint_insecure() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_endpoint_insecure.yml"));
        assert_eq!(cfg.insecure, true);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_endpoint_insecure_none() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_endpoint_insecure_none.yml"));
        assert_eq!(cfg.insecure, false);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_destination_network_address() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_destination_network_address.yml"));
        assert_eq!(cfg.endpoint_address, "0.0.0.0");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_events_destination_network_address_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/events_destination_network_address_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_credentials_user() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_user.yml"));
        assert_eq!(cfg.endpoint_user, "test_user");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_events_credentials_user_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_user_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_credentials_password() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_password.yml"));
        assert_eq!(cfg.endpoint_pass, "test_password");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_events_credentials_token() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_token.yml"));
        assert_eq!(cfg.endpoint_token, "test_token");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_events_credentials_password_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/events_credentials_password_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_monitor_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/monitor_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_node_none() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/node_none.yml"));
        assert_eq!(cfg.node, utils::get_hostname());
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_new_config_windows_log_file_none() {
        AppConfig::new("windows", Some("test/unit/config/windows/log_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_log_level_none() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/log_level_none.yml"));
        assert_eq!(cfg.log_level, "info");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_new_config_windows_log_max_file_size_none() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/log_max_file_size_none.yml"));
        assert_eq!(cfg.log_max_file_size, 64);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_destination() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_destination_none.yml"));
        assert_eq!(cfg.events_destination, String::from("file"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_hashscanner_file() {
        AppConfig::new("linux", Some("test/unit/config/linux/hashscanner_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_events_file() {
        AppConfig::new("linux", Some("test/unit/config/linux/events_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_destination_network() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_destination_network.yml"));
        assert_eq!(cfg.events_file, String::from("Not_defined"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_max_file_checksum() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_max_file_checksum.yml"));
        assert_eq!(cfg.events_max_file_checksum, 128);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_max_file_size() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_max_file_size.yml"));
        assert_eq!(cfg.events_max_file_size, 256);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_endpoint_insecure() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_endpoint_insecure.yml"));
        assert_eq!(cfg.insecure, true);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_endpoint_insecure_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_endpoint_insecure_none.yml"));
        assert_eq!(cfg.insecure, false);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_destination_network_address() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_destination_network_address.yml"));
        assert_eq!(cfg.endpoint_address, "0.0.0.0");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_events_destination_network_address_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/events_destination_network_address_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_credentials_user() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_user.yml"));
        assert_eq!(cfg.endpoint_user, "test_user");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_events_credentials_user_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_user_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_credentials_password() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_password.yml"));
        assert_eq!(cfg.endpoint_pass, "test_password");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_events_credentials_token() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_token.yml"));
        assert_eq!(cfg.endpoint_token, "test_token");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_events_credentials_password_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/events_credentials_password_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_monitor_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/monitor_none.yml"));
        assert_eq!(cfg.monitor, Vec::new());
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_audit_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/audit_none.yml"));
        assert_eq!(cfg.audit, Vec::new());
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_audit_and_monitor_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/audit_and_monitor_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_node_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/node_none.yml"));
        let machine_id = utils::get_machine_id();
        match machine_id.is_empty(){
            true => assert_eq!(cfg.node, utils::get_hostname()),
            false => assert_eq!(cfg.node, machine_id)
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic]
    fn test_new_config_linux_log_file_none() {
        AppConfig::new("linux", Some("test/unit/config/linux/log_file_none.yml"));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_log_level_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/log_level_none.yml"));
        assert_eq!(cfg.log_level, "info");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux_log_max_file_size_none() {
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/log_max_file_size_none.yml"));
        assert_eq!(cfg.log_max_file_size, 64);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_new_config_linux() {
        if utils::get_os() == "linux" {
            let cfg = AppConfig::new("linux", None);
            assert_eq!(cfg.version, String::from(VERSION));
            assert_eq!(cfg.events_destination, String::from("file"));
            assert_eq!(cfg.endpoint_type, String::from("Not_defined"));
            assert_eq!(cfg.endpoint_address, String::from("Not_defined"));
            assert_eq!(cfg.endpoint_user, String::from("Not_defined"));
            assert_eq!(cfg.endpoint_pass, String::from("Not_defined"));
            assert_eq!(cfg.endpoint_token, String::from("Not_defined"));
            assert_eq!(cfg.events_file, String::from("/var/lib/fim/events.json"));
            // monitor
            // audit
            assert_eq!(cfg.node, String::from("FIM"));
            assert_eq!(cfg.log_file, String::from("/var/log/fim/fim.log"));
            assert_eq!(cfg.log_level, String::from("info"));
            assert_eq!(cfg.log_max_file_size, 64);
            assert_eq!(cfg.system, String::from("linux"));
            assert_eq!(cfg.insecure, false);
            assert_eq!(cfg.hashscanner_file, String::from("/var/lib/fim/fim.db"));
            assert_eq!(cfg.hashscanner_enabled, true);
            assert_eq!(cfg.hashscanner_interval, 3600);
            assert_eq!(cfg.hashscanner_algorithm, ShaType::Sha256);
            assert_eq!(cfg.engine, String::from("monitor"));
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn test_new_config_macos() {
        let cfg = AppConfig::new("macos", None);
        assert_eq!(cfg.version, String::from(VERSION));
        assert_eq!(cfg.events_destination, String::from("file"));
        assert_eq!(cfg.endpoint_type, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_address, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_user, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_pass, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_token, String::from("Not_defined"));
        assert_eq!(cfg.events_file, String::from("/var/lib/fim/events.json"));
        // monitor
        // audit
        assert_eq!(cfg.node, String::from("FIM"));
        assert_eq!(cfg.log_file, String::from("/var/log/fim/fim.log"));
        assert_eq!(cfg.log_level, String::from("info"));
        assert_eq!(cfg.log_max_file_size, 64);
        assert_eq!(cfg.system, String::from("macos"));
        assert_eq!(cfg.insecure, false);
        assert_eq!(cfg.hashscanner_file, String::from("/var/lib/fim/fim.db"));
        assert_eq!(cfg.hashscanner_enabled, true);
        assert_eq!(cfg.hashscanner_interval, 3600);
        assert_eq!(cfg.hashscanner_algorithm, ShaType::Sha256);
        assert_eq!(cfg.engine, String::from("monitor"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_info() {
        let filter = LevelFilter::Info;
        assert_eq!(create_test_config("info", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Info", "").get_level_filter(), filter);
        assert_eq!(create_test_config("INFO", "").get_level_filter(), filter);
        assert_eq!(create_test_config("I", "").get_level_filter(), filter);
        assert_eq!(create_test_config("i", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_debug() {
        let filter = LevelFilter::Debug;
        assert_eq!(create_test_config("debug", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Debug", "").get_level_filter(), filter);
        assert_eq!(create_test_config("DEBUG", "").get_level_filter(), filter);
        assert_eq!(create_test_config("D", "").get_level_filter(), filter);
        assert_eq!(create_test_config("d", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_error() {
        let filter = LevelFilter::Error;
        assert_eq!(create_test_config("error", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Error", "").get_level_filter(), filter);
        assert_eq!(create_test_config("ERROR", "").get_level_filter(), filter);
        assert_eq!(create_test_config("E", "").get_level_filter(), filter);
        assert_eq!(create_test_config("e", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_warning() {
        let filter = LevelFilter::Warn;
        assert_eq!(create_test_config("warning", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Warning", "").get_level_filter(), filter);
        assert_eq!(create_test_config("WARNING", "").get_level_filter(), filter);
        assert_eq!(create_test_config("W", "").get_level_filter(), filter);
        assert_eq!(create_test_config("w", "").get_level_filter(), filter);
        assert_eq!(create_test_config("warn", "").get_level_filter(), filter);
        assert_eq!(create_test_config("Warn", "").get_level_filter(), filter);
        assert_eq!(create_test_config("WARN", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_level_filter_bad() {
        let filter = LevelFilter::Info;
        assert_eq!(create_test_config("bad", "").get_level_filter(), filter);
        assert_eq!(create_test_config("BAD", "").get_level_filter(), filter);
        assert_eq!(create_test_config("B", "").get_level_filter(), filter);
        assert_eq!(create_test_config("b", "").get_level_filter(), filter);
        assert_eq!(create_test_config("test", "").get_level_filter(), filter);
        assert_eq!(create_test_config("", "").get_level_filter(), filter);
        assert_eq!(create_test_config("_", "").get_level_filter(), filter);
        assert_eq!(create_test_config("?", "").get_level_filter(), filter);
        assert_eq!(create_test_config("=", "").get_level_filter(), filter);
        assert_eq!(create_test_config("/", "").get_level_filter(), filter);
        assert_eq!(create_test_config(".", "").get_level_filter(), filter);
        assert_eq!(create_test_config(":", "").get_level_filter(), filter);
        assert_eq!(create_test_config(";", "").get_level_filter(), filter);
        assert_eq!(create_test_config("!", "").get_level_filter(), filter);
        assert_eq!(create_test_config("''", "").get_level_filter(), filter);
        assert_eq!(create_test_config("[]", "").get_level_filter(), filter);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_events_destination() {
        assert_eq!(create_test_config("info", "both").get_events_destination(), String::from(BOTH_MODE));
        assert_eq!(create_test_config("info", "network").get_events_destination(), String::from(NETWORK_MODE));
        assert_eq!(create_test_config("info", "file").get_events_destination(), String::from(FILE_MODE));
        assert_eq!(create_test_config("info", "").get_events_destination(), String::from(FILE_MODE));
        assert_eq!(create_test_config("info", "?").get_events_destination(), String::from(FILE_MODE));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_read_config_unix() {
        let yaml = read_config(String::from("config/linux/config.yml"));

        assert_eq!(yaml[0]["node"].as_str().unwrap(), "FIM");
        assert_eq!(yaml[0]["events"]["destination"].as_str().unwrap(), "file");
        assert_eq!(yaml[0]["events"]["file"].as_str().unwrap(), "/var/lib/fim/events.json");

        assert_eq!(yaml[0]["monitor"][0]["path"].as_str().unwrap(), "/bin/");
        assert_eq!(yaml[0]["monitor"][1]["path"].as_str().unwrap(), "/usr/bin/");
        assert_eq!(yaml[0]["monitor"][1]["labels"][0].as_str().unwrap(), "usr/bin");
        assert_eq!(yaml[0]["monitor"][1]["labels"][1].as_str().unwrap(), "linux");
        assert_eq!(yaml[0]["monitor"][2]["path"].as_str().unwrap(), "/etc");
        assert_eq!(yaml[0]["monitor"][2]["labels"][0].as_str().unwrap(), "etc");
        assert_eq!(yaml[0]["monitor"][2]["labels"][1].as_str().unwrap(), "linux");

        assert_eq!(yaml[0]["log"]["file"].as_str().unwrap(), "/var/log/fim/fim.log");
        assert_eq!(yaml[0]["log"]["level"].as_str().unwrap(), "info");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_read_config_windows() {
        let dir = utils::get_current_dir();
        let disk = dir.get(0..1).unwrap();
        let yaml = read_config(String::from("config/windows/config.yml"));

        assert_eq!(yaml[0]["node"].as_str().unwrap(), "FIM");
        assert_eq!(yaml[0]["events"]["destination"].as_str().unwrap(), "file");
        assert_eq!(yaml[0]["events"]["file"].as_str().unwrap(), format!("{}:\\ProgramData\\fim\\events.json", disk) );

        assert_eq!(yaml[0]["monitor"][0]["path"].as_str().unwrap(), "C:\\Program Files\\");
        assert_eq!(yaml[0]["monitor"][0]["labels"][0].as_str().unwrap(), "Program Files");
        assert_eq!(yaml[0]["monitor"][0]["labels"][1].as_str().unwrap(), "windows");
        assert_eq!(yaml[0]["monitor"][1]["path"].as_str().unwrap(), "C:\\Users\\" );
        assert_eq!(yaml[0]["monitor"][1]["labels"][0].as_str().unwrap(), "Users");
        assert_eq!(yaml[0]["monitor"][1]["labels"][1].as_str().unwrap(), "windows");

        assert_eq!(yaml[0]["log"]["file"].as_str().unwrap(), format!("{}:\\ProgramData\\fim\\fim.log", disk) );
        assert_eq!(yaml[0]["log"]["level"].as_str().unwrap(), "info");
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "NotFound")]
    fn test_read_config_panic() {
        read_config(String::from("NotFound"));
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "ScanError")]
    fn test_read_config_panic_not_config() {
        read_config(String::from("README.md"));
    }

    // ------------------------------------------------------------------------

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_get_config_path_unix() {
        let current_dir = utils::get_current_dir();
        let default_path_linux = format!("{}/config/linux/config.yml", current_dir);
        let default_path_macos = format!("{}/config/macos/config.yml", current_dir);
        assert_eq!(get_config_path("linux"), default_path_linux);
        assert_eq!(get_config_path("macos"), default_path_macos);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_config_path_windows() {
        let current_dir = utils::get_current_dir();
        let default_path_windows = format!("{}\\config\\windows\\config.yml", current_dir);
        assert_eq!(get_config_path("windows"), default_path_windows);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_path_in_monitor() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        assert!(cfg.path_in("/bin/", "", cfg.monitor.clone()));
        assert!(cfg.path_in("/bin", "", cfg.monitor.clone()));
        assert!(cfg.path_in("/bin/test", "", cfg.monitor.clone()));
        assert!(!cfg.path_in("/test", "", cfg.monitor.clone()));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_path_in_audit() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_allowed.yml"));
        assert!(cfg.path_in("/tmp", "", cfg.audit.clone()));
        assert!(cfg.path_in("/tmp/", "", cfg.audit.clone()));
        assert!(cfg.path_in("./", "/tmp", cfg.audit.clone()));
        assert!(cfg.path_in("./", "/tmp/", cfg.audit.clone()));
        assert!(!cfg.path_in("./", "/test", cfg.audit.clone()));
        assert!(cfg.path_in("./", "/tmp/test", cfg.audit.clone()));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_index_monitor() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        assert_eq!(cfg.get_index("/bin/", "", cfg.monitor.clone()), 0);
        assert_eq!(cfg.get_index("./", "/bin", cfg.monitor.clone()), 0);
        assert_eq!(cfg.get_index("/usr/bin/", "", cfg.monitor.clone()), 1);
        assert_eq!(cfg.get_index("/etc", "", cfg.monitor.clone()), 2);
        assert_eq!(cfg.get_index("/test", "", cfg.monitor.clone()), usize::MAX);
        assert_eq!(cfg.get_index("./", "/test", cfg.monitor.clone()), usize::MAX);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_index_audit() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_allowed.yml"));
        assert_eq!(cfg.get_index("/tmp", "", cfg.audit.clone()), 0);
        assert_eq!(cfg.get_index("/test", "", cfg.audit.clone()), usize::MAX);
        assert_eq!(cfg.get_index("./", "/tmp", cfg.audit.clone()), 0);
        assert_eq!(cfg.get_index("./", "/test", cfg.audit.clone()), usize::MAX);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_labels() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        if utils::get_os() == "windows" {
            let labels = cfg.get_labels(0, cfg.monitor.clone());
            assert_eq!(labels[0], "Program Files");
            assert_eq!(labels[1], "windows");
        }else if utils::get_os() == "macos"{
            let labels = cfg.get_labels(2, cfg.monitor.clone());
            assert_eq!(labels[0], "usr/bin");
            assert_eq!(labels[1], "macos");
        }else{
            let labels = cfg.get_labels(1, cfg.monitor.clone());
            assert_eq!(labels[0], "usr/bin");
            assert_eq!(labels[1], "linux");
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_match_ignore_monitor() {
        let cfg = AppConfig::new(&utils::get_os(), None);
        assert!(cfg.match_ignore(3, "file.swp", cfg.monitor.clone()));
        assert!(!cfg.match_ignore(0, "file.txt", cfg.monitor.clone()));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_match_ignore_audit() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_exclude.yml"));
        assert!(cfg.match_ignore(0, "file.swp", cfg.audit.clone()));
        assert!(!cfg.match_ignore(0, "file.txt", cfg.audit.clone()));
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_match_exclude() {
        let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_exclude.yml"));
        assert!(cfg.match_exclude(0, "/tmp/test", cfg.audit.clone()));
        assert!(!cfg.match_exclude(0, "/tmp/another", cfg.audit.clone()));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_match_allowed() {
        if utils::get_os() == "windows" {
            let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/windows/monitor_allowed.yml"));
            assert!(!cfg.match_allowed(1, "file.swp", cfg.monitor.clone()));
            assert!(cfg.match_allowed(1, "file.txt", cfg.monitor.clone()));
        } else if utils::get_os() == "linux" {
            let cfg = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/monitor_allowed.yml"));
            assert!(!cfg.match_allowed(2, "file.swp", cfg.monitor.clone()));
            assert!(cfg.match_allowed(2, "file.txt", cfg.monitor.clone()));

            let cfg_audit = AppConfig::new(&utils::get_os(), Some("test/unit/config/linux/audit_allowed.yml"));
            assert!(!cfg_audit.match_allowed(0, "file.swp", cfg_audit.audit.clone()));
            assert!(cfg_audit.match_allowed(0, "file.txt", cfg_audit.audit.clone()));
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_integrations() {
        let os = utils::get_os();
        let cfg = AppConfig::new(&os,
            Some(format!("test/unit/config/{}/monitor_integration.yml", os)
                .as_str())
        );
        if os == "windows" {
            let integrations = cfg.get_integrations(2, cfg.monitor.clone());
            assert_eq!(integrations.len(), 1);
        }else if os == "macos"{
            let integrations = cfg.get_integrations(2, cfg.monitor.clone());
            assert_eq!(integrations.len(), 1);
        }else{
            let integrations_monitor = cfg.get_integrations(2, cfg.monitor.clone());
            assert_eq!(integrations_monitor.len(), 1);

            // Not implemented yet
            //let integrations_audit = cfg.get_integrations(2, cfg.audit.clone());
            //assert_eq!(integrations_audit.len(), 1);
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_new_config_watcher() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/events_watcher.yml"));
        assert_eq!(cfg.events_watcher, "Poll");
    }

}
