// Copyright (C) 2021, Achiefs.

#[cfg(test)]
mod tests;

pub const VERSION: &str = "0.7.0";
pub const NETWORK_MODE: &str = "NETWORK";
pub const FILE_MODE: &str = "FILE";
pub const BOTH_MODE: &str = "BOTH";
pub const MACHINE_ID_PATH: &str = "/etc/machine-id";
const CONFIG_MACOS_PATH: &str = "/Applications/FileMonitor.app/config.yml";
const CONFIG_LINUX_PATH: &str = "/etc/fim/config.yml";
const CONFIG_WINDOWS_PATH: &str = "C:\\Program Files\\File Integrity Monitor\\config.yml";

use yaml_rust::yaml::{Yaml, YamlLoader, Array};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use simplelog::LevelFilter;
use std::sync::{Arc, Mutex};

use crate::utils;
use crate::integration::Integration;
use crate::hash::ShaType;

#[derive(Clone)]
pub struct Config {
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
    pub events_lock: Arc<Mutex<String>>,
    pub log_lock: Arc<Mutex<String>>,
    pub hashscanner_file: String,
    pub hashscanner_enabled: bool,
    pub hashscanner_interval: usize,
    pub hashscanner_algorithm: ShaType,
    pub engine: String
}

impl Config {

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

        Config {
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
            events_file: events_file.clone(),
            monitor,
            audit,
            node,
            log_file: log_file.clone(),
            log_level,
            log_max_file_size,
            system: String::from(system),
            insecure,
            events_lock: Arc::new(Mutex::new(events_file)),
            log_lock: Arc::new(Mutex::new(log_file)),
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
            integrations.push(Integration {
                name: String::from(info["name"].as_str().unwrap()), 
                condition: info["condition"]
                    .clone().into_vec().unwrap().iter().map(|element| 
                        String::from(element.as_str().unwrap()) ).collect(), 
                binary: String::from(info["binary"].as_str().unwrap()), 
                script: String::from(info["script"].as_str().unwrap()), 
                parameters: String::from(info["parameters"].as_str().unwrap())
            })
        );
        integrations
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