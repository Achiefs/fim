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
            let msg = String::from("ERROR reading log level from 'config.yml', using Debug by default");
            println!("{}", msg);
            writeln!(log, "{}", msg).expect("Error writing Error in log.");
            LevelFilter::Debug
        }
    }
}