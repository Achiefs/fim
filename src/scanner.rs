// Copyright (C) 2024, Achiefs.

use crate::db;
use crate::dbfile::*;
use crate::appconfig::AppConfig;
use crate::hashevent::HashEvent;
use crate::utils;

use walkdir::WalkDir;
use log::*;
use std::collections::HashSet;

pub fn scan_path(cfg: AppConfig, root: String) {
    let db = db::DB::new();
    for res in WalkDir::new(root) {
        let entry = res.unwrap();
        let metadata = entry.metadata().unwrap();
        let path = entry.path();
        if metadata.clone().is_file(){
            let dbfile = DBFile::new(cfg.clone(), path.to_str().unwrap(), None);
            db.insert_file(dbfile);
        }
    }
}

// ----------------------------------------------------------------------------

pub async fn check_path(cfg: AppConfig, root: String) {
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
                        let current_dbfile = db.update_file(cfg.clone(), dbfile.clone());
                        match current_dbfile {
                            Some(data) => {
                                let event = HashEvent::new(dbfile, data);
                                event.process(cfg.clone()).await;
                            },
                            None => warn!("Could not update file information in database, file: '{}'", path.display())
                        }
                    }
                },
                Err(e) => {
                    if e.kind() == "DBFileNotFoundError" {
                        debug!("New file '{}' found in directory.", path.display());
                        let dbfile = DBFile::new(cfg.clone(), path.to_str().unwrap(), None);
                        db.insert_file(dbfile);
                        // In this case we don't trigger an event due the watcher will trigger new file in monitoring path.
                    } else {
                        error!("Could not get file '{}' information from database, Error: {:?}", path.display(), e)
                    }
                }
            };
        }
    }
}

// ----------------------------------------------------------------------------

pub fn update_db(cfg: AppConfig, root: String) {
    let db = db::DB::new();

    let list = db.get_file_list(root.clone());
    let path_list = utils::get_path_file_list(root);

    //path_list.iter().filter()

    let path_set: HashSet<_> = path_list.iter().collect();
    let diff: Vec<_> = list.iter().filter(|item| !path_set.contains(&item.path)).collect();
    println!("DIFF: {:?}", diff);
}

// ----------------------------------------------------------------------------

pub async fn first_scan(cfg: AppConfig, root: String) {
    let db = db::DB::new();
    if db.is_empty() {
        scan_path(cfg, root);
    } else {
        check_path(cfg.clone(), root.clone()).await;
        update_db(cfg, root);
    }
}