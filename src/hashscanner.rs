// Copyright (C) 2024, Achiefs.

use crate::db;
use crate::dbfile::*;
use crate::appconfig::AppConfig;
use crate::hashevent;
use crate::hashevent::HashEvent;
use crate::utils;

use walkdir::WalkDir;
use log::*;
use std::collections::HashSet;
use std::time::Duration;
use std::thread;
use tokio::runtime::Runtime;

#[cfg(test)]
mod test;

// ----------------------------------------------------------------------------

pub fn scan_path(cfg: AppConfig, root: String) {
    let db = db::DB::new(&cfg.hashscanner_file);
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

/// This function iterate over the files on `root` directory
/// If hash or permissions of a file change it should trigger a HashEvent
/// Just in case the first scan after reboot or a hash change between scans
/// It also updates the DBFile definition in the DB
pub async fn check_path(cfg: AppConfig, root: String, first_scan: bool) {
    let db = db::DB::new(&cfg.hashscanner_file);
    for res in WalkDir::new(root) {
        let entry = res.unwrap();
        let metadata = entry.metadata().unwrap();
        let path = entry.path();

        if metadata.clone().is_file(){
            let result = db.get_file_by_path(String::from(path.to_str().unwrap()));
            match result {
                Ok(dbfile) => {
                    let hash = dbfile.get_file_hash(cfg.clone());
                    let permissions = utils::get_unix_permissions(&dbfile.path);
                    if dbfile.hash != hash {
                        debug!("The file '{}' checksum has changed.", path.display());
                        let current_dbfile = db.update_file(cfg.clone(), dbfile.clone());
                        match current_dbfile {
                            Some(data) => {
                                let event = HashEvent::new(Some(dbfile), data, String::from(hashevent::WRITE));
                                event.process(cfg.clone()).await;
                            },
                            None => warn!("Could not update file checksum information in database, file: '{}'", path.display())
                        }
                    } else if dbfile.permissions != permissions {
                        debug!("The file '{}' permissions have changed.", path.display());
                        let current_dbfile = db.update_file(cfg.clone(), dbfile.clone());
                        match current_dbfile {
                            Some(data) => {
                                let event = HashEvent::new(Some(dbfile), data, String::from(hashevent::WRITE));
                                event.process(cfg.clone()).await;
                            },
                            None => warn!("Could not update file permissions information in database, file: '{}'", path.display())
                        }
                    }
                },
                Err(e) => {
                    if e.kind() == "DBFileNotFoundError" {
                        debug!("New file '{}' found in directory.", path.display());
                        let dbfile = DBFile::new(cfg.clone(), path.to_str().unwrap(), None);
                        db.insert_file(dbfile.clone());
                        // Only trigger new file event in case it is a first scan else monitor will notify.
                        if first_scan {
                            let event = HashEvent::new(None, dbfile, String::from(hashevent::CREATE));
                            event.process(cfg.clone()).await;
                        }
                    } else {
                        error!("Could not get file '{}' information from database, Error: {:?}", path.display(), e)
                    }
                }
            };
        }
    }
}

// ----------------------------------------------------------------------------

/// This function update the DB in case files were removed from given path
/// In case changes were detected, it trigger hashEvents on first scan after reboot
pub async fn update_db(cfg: AppConfig, root: String, first_scan: bool) {
    let db = db::DB::new(&cfg.hashscanner_file);

    let db_list = db.get_file_list(root.clone());
    let path_list = utils::get_fs_list(root);

    let path_set: HashSet<_> = path_list.iter().collect();
    let diff: Vec<_> = db_list.iter().filter(|item| !path_set.contains(&item.path)).collect();

    for file in diff {
        let dbfile = DBFile {
            id: file.id.clone(),
            timestamp: file.timestamp.clone(),
            hash: file.hash.clone(),
            path: file.path.clone(),
            size: file.size,
            permissions: file.permissions
        };
        let result = db.delete_file(dbfile.clone());
        match result {
            Ok(_v) => {
                // Only trigger delete file event in case it is a first scan else monitor will notify.
                if first_scan {
                    let event = HashEvent::new(None, dbfile, String::from(hashevent::REMOVE));
                    event.process(cfg.clone()).await;
                }
                debug!("File {} deleted from databse", file.path)
            },
            Err(e) => error!("Could not delete file {} from database, error: {:?}", file.path, e)
        }
    }
}

// ----------------------------------------------------------------------------

#[cfg(not(tarpaulin_include))]
pub fn scan(cfg: AppConfig) {
    let db = db::DB::new(&cfg.hashscanner_file);
    let rt = Runtime::new().unwrap();
    let interval = cfg.clone().hashscanner_interval;
    let mut first_scan = true;
    debug!("Starting file scan to create hash database.");

    let config_paths = match cfg.clone().engine.as_str() {
        "audit" => cfg.clone().audit,
        _ => cfg.clone().monitor,
    };

    loop{

        for element in config_paths.clone() {
            let path = String::from(element["path"].as_str().unwrap());
            if db.is_empty() {
                scan_path(cfg.clone(), path.clone());
            } else {
                rt.block_on(check_path(cfg.clone(), path.clone(), first_scan));
                rt.block_on(update_db(cfg.clone(), path.clone(), first_scan));
                first_scan = false;
            }
            debug!("Path '{}' scanned all files are hashed in DB.", path.clone());
        }

        debug!("Sleeping HashScanner thread for {} minutes", interval.clone());
        thread::sleep(Duration::from_secs(interval.try_into().unwrap()));
    }

}