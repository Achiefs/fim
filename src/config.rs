// Copyright (C) 2021, Achiefs.

// To parse files in yaml format
use yaml_rust::yaml::{Yaml, YamlLoader};
// To use files IO operations.
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::io::Write;
// To set log filter level
use simplelog::LevelFilter;

// To read the configuration Yaml file
pub fn read_config(file: &str) -> Vec<Yaml> {
    let mut file = File::open(file).expect("Unable to open file");
    let mut contents = String::new();

    file.read_to_string(&mut contents)
        .expect("Unable to read file");
    YamlLoader::load_from_str(&contents).unwrap()
}

// To process log level set on config file
pub fn get_log_level(level: String, log_file: String) -> LevelFilter {
    let mut log = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(log_file)
        .expect("Unable to open events log file.");

    match level.as_str() {
        "debug" | "Debug" | "DEBUG" | "D" | "d" => LevelFilter::Debug,
        "info" | "Info" | "INFO" | "I" | "i" => LevelFilter::Info,
        "error" | "Error" | "ERROR" | "E" | "e" => LevelFilter::Error,
        "warning" | "Warning" | "WARNING" | "W" | "w" | "warn" | "Warn" | "WARN" => LevelFilter::Warn,
        _ => {
            let msg = String::from("ERROR reading log level from 'config.yml', using Info by default");
            println!("{}", msg);
            writeln!(log, "{}", msg).expect("Error writing Error in log.");
            LevelFilter::Info
        }
    }
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
    fn test_get_log_level_info() {
        let file = "info.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Info;
        assert_eq!(get_log_level(String::from("info"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("Info"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("INFO"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("I"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("i"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    fn test_get_log_level_debug() {
        let file = "debug.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Debug;
        assert_eq!(get_log_level(String::from("debug"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("Debug"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("DEBUG"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("D"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("d"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    fn test_get_log_level_error() {
        let file = "error.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Error;
        assert_eq!(get_log_level(String::from("error"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("Error"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("ERROR"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("E"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("e"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    fn test_get_log_level_warning() {
        let file = "warning.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Warn;
        assert_eq!(get_log_level(String::from("warning"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("Warning"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("WARNING"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("W"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("w"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("warn"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("Warn"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("WARN"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    fn test_get_log_level_bad() {
        let file = "bad.txt";
        let filename = String::from(file);
        let filter = LevelFilter::Info;
        assert_eq!(get_log_level(String::from("bad"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("BAD"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("B"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("b"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("test"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("anything"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from(""), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("_"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("?"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("="), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("/"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("."), filename.clone()), filter);
        assert_eq!(get_log_level(String::from(":"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from(";"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("!"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("''"), filename.clone()), filter);
        assert_eq!(get_log_level(String::from("[]"), filename.clone()), filter);
        remove_test_file(file);
    }

    #[test]
    #[should_panic(expected = "NotFound")]
    fn test_get_log_level_panic_empty() {
        get_log_level("".to_string(), "".to_string());
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
