// Copyright (C) 2021, Achiefs.

// Global constants definitions
pub const VERSION: &str = "0.2.2";
pub const NETWORK_MODE: &str = "NETWORK";
pub const FILE_MODE: &str = "FILE";
pub const BOTH_MODE: &str = "BOTH";
const CONFIG_LINUX_PATH: &str = "/etc/fim/config.yml";

// To parse files in yaml format
use yaml_rust::yaml::{Yaml, YamlLoader, Array};
// To use files IO operations.
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::io::Write;
// To manage paths
use std::path::Path;
use std::env;
// To set log filter level
use simplelog::LevelFilter;

// ----------------------------------------------------------------------------

pub struct Config {
    pub version: String,
    pub path: String,
    pub events_destination: String,
    pub endpoint_address: String,
    pub endpoint_user: String,
    pub endpoint_pass: String,
    pub events_file: String,
    pub monitor: Array,
    pub nodename: String,
    pub log_file: String,
    pub log_level: String,
    pub system: String
}

impl Config {

    pub fn new() -> Self {
        println!("[INFO] System detected {}", env::consts::OS);
        // Select directory where to load config.yml it depends on system
        let default_path = format!("./config/{}/config.yml", env::consts::OS);
        let config_path = match Path::new(default_path.as_str()).exists() {
            true => default_path.as_str(),
            false => CONFIG_LINUX_PATH
        };
        println!("[INFO] Loaded config from: {}", config_path);
        let yaml = read_config(config_path.clone());

        // Manage null value on events->destination value
        let events_destination = match yaml[0]["events"]["destination"].as_str() {
            Some(value) => String::from(value),
            None => {
                println!("[WARN] events->destination not found in config.yml, using 'file'.");
                String::from("file")
            }
        };

        // Manage null value on events->file value
        let events_file = match yaml[0]["events"]["file"].as_str() {
            Some(value) => String::from(value),
            None => {
                if events_destination != String::from("network") {
                    println!("[ERROR] events->file not found in config.yml.");
                    panic!("events->file not found in config.yml.");
                }else{
                    String::from("Not_used")
                }
            }
        };

        // Manage null value on events->endpoint->address value
        let endpoint_address = match yaml[0]["events"]["endpoint"]["address"].as_str() {
            Some(value) => String::from(value),
            None => {
                if events_destination != String::from("file") {
                    println!("[ERROR] events->endpoint->address not found in config.yml.");
                    panic!("events->endpoint->address not found in config.yml.");
                }else{
                    String::from("Not_used")
                }
            }
        };

        // Manage null value on events->endpoint->credentials->user value
        let endpoint_user = match yaml[0]["events"]["endpoint"]["credentials"]["user"].as_str() {
            Some(value) => String::from(value),
            None => {
                if events_destination != String::from("file") {
                    println!("[ERROR] events->endpoint->credentials->user not found in config.yml.");
                    panic!("events->endpoint->credentials->user not found in config.yml.");
                }else{
                    String::from("Not_used")
                }
            }
        };

        // Manage null value on events->endpoint->credentials->password value
        let endpoint_pass = match yaml[0]["events"]["endpoint"]["credentials"]["password"].as_str() {
            Some(value) => String::from(value),
            None => {
                if events_destination != String::from("file") {
                    println!("[ERROR] events->endpoint->credentials->password not found in config.yml.");
                    panic!("events->endpoint->credentials->password not found in config.yml.");
                }else{
                    String::from("Not_used")
                }
            }
        };

        // Manage null value on monitor value
        let monitor = match yaml[0]["monitor"].as_vec() {
            Some(value) => value.to_vec(),
            None => {
                println!("[ERROR] monitor not found in config.yml.");
                panic!("monitor not found in config.yml.");
            }
        };

        // Manage null value on nodename value
        let nodename = match yaml[0]["nodename"].as_str() {
            Some(value) => String::from(value),
            None => {
                println!("[WARN] nodename not found in config.yml, using 'FIM'.");
                String::from("FIM")
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

        Config {
            version: String::from(VERSION),
            path: String::from(config_path.clone()),
            events_destination: events_destination,
            endpoint_address: endpoint_address,
            endpoint_user: endpoint_user,
            endpoint_pass: endpoint_pass,
            events_file: events_file,
            monitor: monitor,
            nodename: nodename,
            log_file: log_file,
            log_level: log_level,
            system: String::from(env::consts::OS)
        }
    }

    // ------------------------------------------------------------------------

    // To process log level set on config file
    pub fn get_level_filter(&self) -> LevelFilter {
        let mut log = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(self.log_file.clone())
            .expect("Unable to open events log file.");

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

}

// ----------------------------------------------------------------------------

// To read the Yaml configuration file
pub fn read_config(path: &str) -> Vec<Yaml> {
    let mut file = File::open(path).expect("Unable to open file");
    let mut contents = String::new();

    file.read_to_string(&mut contents)
        .expect("Unable to read file");
    YamlLoader::load_from_str(&contents).unwrap()
}


// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn remove_test_file(filename: &str) {
        fs::remove_file(filename).unwrap()
    }

    #[test]
    fn test_get_level_filter() {
        let file = "info.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Info;
        assert_eq!(get_level_filter(String::from("info"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("Info"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("INFO"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("I"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("i"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    fn test_get_level_filter_debug() {
        let file = "debug.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Debug;
        assert_eq!(get_level_filter(String::from("debug"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("Debug"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("DEBUG"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("D"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("d"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    fn test_get_level_filter_error() {
        let file = "error.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Error;
        assert_eq!(get_level_filter(String::from("error"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("Error"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("ERROR"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("E"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("e"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    fn test_get_level_filter_warning() {
        let file = "warning.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Warn;
        assert_eq!(get_level_filter(String::from("warning"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("Warning"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("WARNING"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("W"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("w"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("warn"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("Warn"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("WARN"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    fn test_get_level_filter_bad() {
        let file = "bad.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Info;
        assert_eq!(get_level_filter(String::from("bad"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("BAD"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("B"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("b"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("test"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("anything"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from(""), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("_"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("?"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("="), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("/"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("."), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from(":"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from(";"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("!"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("''"), filename.clone()), filter);
        assert_eq!(get_level_filter(String::from("[]"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    #[should_panic(expected = "NotFound")]
    fn test_get_level_filter_panic_empty() {
        get_level_filter("".to_string(), "".to_string());
    }

    #[test]
    fn test_read_config() {
        read_config("config/linux/config.yml");
    }

    #[test]
    #[should_panic(expected = "NotFound")]
    fn test_read_config_panic() {
        read_config("not_found");
    }

    #[test]
    #[should_panic(expected = "ScanError")]
    fn test_read_config_panic_not_config() {
        read_config("README.md");
    }
}
