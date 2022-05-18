// Copyright (C) 2021, Achiefs.

// Global constants definitions
pub const VERSION: &str = "0.3.0";
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
    pub system: String,
    pub insecure: bool
}

impl Config {

    pub fn clone(&self) -> Self {
        Config {
            version: self.version.clone(),
            path: self.path.clone(),
            events_destination: self.events_destination.clone(),
            endpoint_address: self.endpoint_address.clone(),
            endpoint_user: self.endpoint_user.clone(),
            endpoint_pass: self.endpoint_pass.clone(),
            events_file: self.events_file.clone(),
            monitor: self.monitor.clone(),
            nodename: self.nodename.clone(),
            log_file: self.log_file.clone(),
            log_level: self.log_level.clone(),
            system: self.system.clone(),
            insecure: self.insecure
        }
    }

    pub fn new(system: &str) -> Self {
        println!("[INFO] System detected {}", system);
        let config_path = get_config_path(system);
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
                if events_destination != *"network" {
                    println!("[ERROR] events->file not found in config.yml.");
                    panic!("events->file not found in config.yml.");
                }else{
                    String::from("Not_used")
                }
            }
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
                    String::from("Not_used")
                }
            }
        };

        // Manage null value on events->endpoint->credentials->user value
        let endpoint_user = match yaml[0]["events"]["endpoint"]["credentials"]["user"].as_str() {
            Some(value) => String::from(value),
            None => {
                if events_destination != *"file" {
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
                if events_destination != *"file" {
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
            path: config_path,
            events_destination,
            endpoint_address,
            endpoint_user,
            endpoint_pass,
            events_file,
            monitor,
            nodename,
            log_file,
            log_level,
            system: String::from(system),
            insecure
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

}

// ----------------------------------------------------------------------------

// To read the Yaml configuration file
pub fn read_config(path: String) -> Vec<Yaml> {
    let mut file = File::open(path).expect("Unable to open file");
    let mut contents = String::new();

    file.read_to_string(&mut contents)
        .expect("Unable to read file");
    YamlLoader::load_from_str(&contents).unwrap()
}

// ----------------------------------------------------------------------------

pub fn get_config_path(system: &str) -> String {
    // Select directory where to load config.yml it depends on system
    let default_path = format!("./config/{}/config.yml", system);
    let relative_path = format!("./../../config/{}/config.yml", system);
    if Path::new(default_path.as_str()).exists() {
        default_path
    }else if Path::new("./config.yml").exists() {
        String::from("./config.yml")
    }else if Path::new(relative_path.as_str()).exists() {
        relative_path
    }else{
        String::from(CONFIG_LINUX_PATH)
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // To use files IO operations.
    use std::{fs, env};

    // ------------------------------------------------------------------------

    pub fn create_test_config(filter: &str, events_destination: &str) -> Config {
        Config {
            version: String::from(VERSION),
            path: String::from("test"),
            events_destination: String::from(events_destination),
            endpoint_address: String::from("test"),
            endpoint_user: String::from("test"),
            endpoint_pass: String::from("test"),
            events_file: String::from("test"),
            monitor: Array::new(),
            nodename: String::from("test"),
            log_file: String::from("./test.log"),
            log_level: String::from(filter),
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
        assert_eq!(config.endpoint_address, cloned.endpoint_address);
        assert_eq!(config.endpoint_user, cloned.endpoint_user);
        assert_eq!(config.endpoint_pass, cloned.endpoint_pass);
        assert_eq!(config.events_file, cloned.events_file);
        assert_eq!(config.monitor, cloned.monitor);
        assert_eq!(config.nodename, cloned.nodename);
        assert_eq!(config.log_file, cloned.log_file);
        assert_eq!(config.log_level, cloned.log_level);
        assert_eq!(config.system, cloned.system);
        assert_eq!(config.insecure, cloned.insecure);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_new_config_windows() {
        let default_path = format!("./config/{}/config.yml", "windows");
        let config = Config::new("windows");
        assert_eq!(config.version, String::from(VERSION));
        assert_eq!(config.path, default_path);
        assert_eq!(config.events_destination, String::from("file"));
        assert_eq!(config.endpoint_address, String::from("Not_used"));
        assert_eq!(config.endpoint_user, String::from("Not_used"));
        assert_eq!(config.endpoint_pass, String::from("Not_used"));
        assert_eq!(config.events_file, String::from("C:\\ProgramData\\fim\\events.json"));
        // monitor
        assert_eq!(config.nodename, String::from("FIM"));
        assert_eq!(config.log_file, String::from("C:\\ProgramData\\fim\\fim.log"));
        assert_eq!(config.log_level, String::from("info"));
        assert_eq!(config.system, String::from("windows"));
        assert_eq!(config.insecure, false);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_new_config_linux() {
        let default_path = format!("./config/{}/config.yml", "linux");
        let config = Config::new("linux");
        assert_eq!(config.version, String::from(VERSION));
        assert_eq!(config.path, default_path);
        assert_eq!(config.events_destination, String::from("file"));
        assert_eq!(config.endpoint_address, String::from("Not_used"));
        assert_eq!(config.endpoint_user, String::from("Not_used"));
        assert_eq!(config.endpoint_pass, String::from("Not_used"));
        assert_eq!(config.events_file, String::from("/var/lib/fim/events.json"));
        // monitor
        assert_eq!(config.nodename, String::from("FIM"));
        assert_eq!(config.log_file, String::from("/var/log/fim/fim.log"));
        assert_eq!(config.log_level, String::from("info"));
        assert_eq!(config.system, String::from("linux"));
        assert_eq!(config.insecure, false);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_new_config_macos() {
        let default_path = format!("./config/{}/config.yml", "macos");
        let config = Config::new("macos");
        assert_eq!(config.version, String::from(VERSION));
        assert_eq!(config.path, default_path);
        assert_eq!(config.events_destination, String::from("file"));
        assert_eq!(config.endpoint_address, String::from("Not_used"));
        assert_eq!(config.endpoint_user, String::from("Not_used"));
        assert_eq!(config.endpoint_pass, String::from("Not_used"));
        assert_eq!(config.events_file, String::from("/var/lib/fim/events.json"));
        // monitor
        assert_eq!(config.nodename, String::from("FIM"));
        assert_eq!(config.log_file, String::from("/var/log/fim/fim.log"));
        assert_eq!(config.log_level, String::from("info"));
        assert_eq!(config.system, String::from("macos"));
        assert_eq!(config.insecure, false);
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

        assert_eq!(yaml[0]["nodename"].as_str().unwrap(), "FIM");
        assert_eq!(yaml[0]["events"]["destination"].as_str().unwrap(), "file");
        assert_eq!(yaml[0]["events"]["file"].as_str().unwrap(), "/var/lib/fim/events.json");

        assert_eq!(yaml[0]["monitor"][0]["path"].as_str().unwrap(), "/tmp/");
        assert_eq!(yaml[0]["monitor"][1]["path"].as_str().unwrap(), "/bin/");
        assert_eq!(yaml[0]["monitor"][2]["path"].as_str().unwrap(), "/usr/bin/");
        assert_eq!(yaml[0]["monitor"][2]["labels"][0].as_str().unwrap(), "usr/bin");
        assert_eq!(yaml[0]["monitor"][2]["labels"][1].as_str().unwrap(), "linux");
        assert_eq!(yaml[0]["monitor"][3]["path"].as_str().unwrap(), "/etc");
        assert_eq!(yaml[0]["monitor"][3]["labels"][0].as_str().unwrap(), "etc");
        assert_eq!(yaml[0]["monitor"][3]["labels"][1].as_str().unwrap(), "linux");

        assert_eq!(yaml[0]["log"]["file"].as_str().unwrap(), "/var/log/fim/fim.log");
        assert_eq!(yaml[0]["log"]["level"].as_str().unwrap(), "info");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_read_config_windows() {
        let yaml = read_config(String::from("config/windows/config.yml"));

        assert_eq!(yaml[0]["nodename"].as_str().unwrap(), "FIM");
        assert_eq!(yaml[0]["events"]["destination"].as_str().unwrap(), "file");
        assert_eq!(yaml[0]["events"]["file"].as_str().unwrap(), "C:\\ProgramData\\fim\\events.json");

        assert_eq!(yaml[0]["monitor"][0]["path"].as_str().unwrap(), "C:\\Program Files\\");
        assert_eq!(yaml[0]["monitor"][0]["labels"][0].as_str().unwrap(), "Program Files");
        assert_eq!(yaml[0]["monitor"][0]["labels"][1].as_str().unwrap(), "windows");
        assert_eq!(yaml[0]["monitor"][1]["path"].as_str().unwrap(), "C:\\Users\\");
        assert_eq!(yaml[0]["monitor"][1]["labels"][0].as_str().unwrap(), "Users");
        assert_eq!(yaml[0]["monitor"][1]["labels"][1].as_str().unwrap(), "windows");

        assert_eq!(yaml[0]["log"]["file"].as_str().unwrap(), "C:\\ProgramData\\fim\\fim.log");
        assert_eq!(yaml[0]["log"]["level"].as_str().unwrap(), "info");
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "NotFound")]
    fn test_read_config_panic() {
        read_config(String::from("not_found"));
    }

    // ------------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "ScanError")]
    fn test_read_config_panic_not_config() {
        read_config(String::from("README.md"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_config_path() {
        let default_path_windows = "./config/windows/config.yml";
        let default_path_linux = "./config/linux/config.yml";
        let default_path_macos = "./config/macos/config.yml";
        assert_eq!(get_config_path("windows"), default_path_windows);
        assert_eq!(get_config_path("linux"), default_path_linux);
        assert_eq!(get_config_path("macos"), default_path_macos);

        let path = "./config.yml";
        fs::rename(default_path_windows, path).unwrap();
        assert_eq!(get_config_path("windows"), path);
        fs::rename(path, default_path_windows).unwrap();

        fs::rename(default_path_linux, path).unwrap();
        assert_eq!(get_config_path("linux"), path);
        fs::rename(path, default_path_linux).unwrap();

        fs::rename(default_path_macos, path).unwrap();
        assert_eq!(get_config_path("macos"), path);
        fs::rename(path, default_path_macos).unwrap();

        let relative_path_windows = "./../../config/windows";
        let relative_config_windows = "./../../config/windows/config.yml";
        let relative_path_linux = "./../../config/linux";
        let relative_config_linux = "./../../config/linux/config.yml";
        let relative_path_macos = "./../../config/macos";
        let relative_config_macos = "./../../config/macos/config.yml";

        fs::create_dir_all(relative_path_windows).unwrap();
        fs::rename(default_path_windows, relative_config_windows).unwrap();
        assert_eq!(get_config_path("windows"), relative_config_windows);
        fs::rename(relative_config_windows, default_path_windows).unwrap();

        fs::create_dir_all(relative_path_linux).unwrap();
        fs::rename(default_path_linux, relative_config_linux).unwrap();
        assert_eq!(get_config_path("linux"), relative_config_linux);
        fs::rename(relative_config_linux, default_path_linux).unwrap();

        fs::create_dir_all(relative_path_macos).unwrap();
        fs::rename(default_path_macos, relative_config_macos).unwrap();
        assert_eq!(get_config_path("macos"), relative_config_macos);
        fs::rename(relative_config_macos, default_path_macos).unwrap();

        fs::remove_dir_all("./../../config").unwrap();

        if env::consts::OS == "linux" {
            let linux_path = "/etc/fim";
            let config_linux = "/etc/fim/config.yml";
            fs::create_dir_all(linux_path).unwrap();
            fs::rename(default_path_linux, config_linux).unwrap();
            assert_eq!(get_config_path("linux"), config_linux);
            fs::rename(config_linux, default_path_linux).unwrap();
        }
    }
}
