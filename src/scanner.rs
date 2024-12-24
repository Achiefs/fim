// Copyright (C) 2024, Achiefs.

use crate::db;
use crate::dbfile::*;
use crate::utils;
use crate::appconfig::AppConfig;
use crate::hashevent::HashEvent;

use walkdir::WalkDir;
use log::*;

// Temporal
use tokio::runtime::Runtime;

pub fn scan_path(cfg: AppConfig, root: String) {
    let db = db::DB::new();
    for res in WalkDir::new(root) {
        let entry = res.unwrap();
        let metadata = entry.metadata().unwrap();
        let path = entry.path();
        if metadata.clone().is_file(){


            let dbfile = DBFile::new(cfg.clone(), path.to_str().unwrap());
            db.insert_file(dbfile);
        }
    }
}

// ----------------------------------------------------------------------------

pub fn check_changes(cfg: AppConfig, root: String) {
    let db = db::DB::new();
    for res in WalkDir::new(root) {
        let entry = res.unwrap();
        let metadata = entry.metadata().unwrap();
        let path = entry.path();

        if metadata.clone().is_file(){
            let result = db.get_file_by_path(String::from(path.to_str().unwrap()));
            match result {
                Ok(dbfile) => {
                    let hash = dbfile.get_disk_hash(cfg.clone());
                    if dbfile.hash != hash {
                        debug!("The file '{}', has changed.", path.display());
                        db.update_file(
                            dbfile.clone(),
                            Some(utils::get_current_time_millis()),
                            Some(hash),
                            Some(metadata.len()));
                        let event = HashEvent::new(dbfile);
                        let rt = Runtime::new().unwrap();
                        rt.block_on(event.process(cfg.clone()));
                        // Trigger new event
                    }
                },
                Err(e) => {
                    if e.kind() == "DBFileNotFoundError" {
                        debug!("New file '{}' found in directory.", path.display());
                        let dbfile = DBFile::new(cfg.clone(), path.to_str().unwrap());
                        db.insert_file(dbfile);
                        // Trigger new event
                    } else {
                        error!("Could not get file '{}' databse information, Error: {:?}", path.display(), e)
                    }
                }
            };
        }
    }
}

// ----------------------------------------------------------------------------

pub fn first_scan(cfg: AppConfig, root: String) {
    let db = db::DB::new();
    if ! db.is_empty() {
        check_changes(cfg, root);
    } else {
        scan_path(cfg, root);
    }
}