use walkdir::WalkDir;
use crate::db;
use crate::db::DBFile;
use crate::utils;
use crate::hash;
use crate::appconfig::AppConfig;
use sha2::{Digest, Sha256};

pub fn scan_path(cfg: AppConfig, root: String) {
    for res in WalkDir::new(root) {
        let entry = res.unwrap();
        let metadata = entry.metadata().unwrap();
        let path = entry.path();
        if metadata.clone().is_file(){
            let dbfile = DBFile {
                id: 0, // Not used for insert
                timestamp: utils::get_current_time_millis(),
                hash: hash::get_checksumv2( String::from(path.to_str().unwrap()), cfg.clone().events_max_file_checksum, Sha256::new()),
                path: String::from(entry.path().to_str().unwrap()),
                size: metadata.len()
            };
            let db = db::DB::new();
            db.insert_file(dbfile);
        }
    }
}