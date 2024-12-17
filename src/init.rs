// Copyright (C) 2024, Achiefs.

use crate::ruleset::Ruleset;
use crate::appconfig::*;
use crate::utils;
use crate::db;


pub fn init() -> (AppConfig, Ruleset) {
    use std::path::Path;
    use simplelog::WriteLogger;
    use simplelog::Config;
    use std::fs;

    println!("[INFO] Achiefs File Integrity Monitoring software starting!");
    println!("[INFO] Reading config...");
    let cfg = AppConfig::new(utils::get_os(), None);

    // Create folders to store logs based on config.yml
    fs::create_dir_all(
        Path::new( &cfg.clone().log_file
        ).parent().unwrap().to_str().unwrap()
    ).unwrap();

    // Create logger output to write generated logs.
    WriteLogger::init(
        cfg.clone().get_level_filter(),
        Config::default(),
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(cfg.clone().log_file)
            .expect("Unable to open log file")
    ).unwrap();

    println!("[INFO] Configuration successfully read, forwarding output to log file.");
    println!("[INFO] Log file: '{}'", cfg.clone().log_file);
    println!("[INFO] Log level: '{}'", cfg.clone().log_level);

    let ruleset = Ruleset::new(utils::get_os(), None);

    let db = db::DB::new();
    db.create_table();
    println!("[INFO] Database created.");

    println!("[INFO] Any error from this point will be logged in the log file.");
    log_panics::init();
    (cfg, ruleset)
}