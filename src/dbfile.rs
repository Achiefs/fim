// Copyright (C) 2024, Achiefs.

use crate::utils;
use crate::hash;
use crate::appconfig::*;

//use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use rusqlite;
use std::os::unix::fs::PermissionsExt;

pub struct DBFileError {
    kind: String,
    message: String
}

pub struct DBFile {
    pub id: String,
    pub timestamp: String,
    pub hash: String,
    pub path: String,
    pub size: u64,
    pub permissions: Option<u32>
}

// ----------------------------------------------------------------------------

impl DBFileError {
    pub fn not_found_error() -> Self {
        DBFileError {
            kind: String::from("DBFileNotFoundError"),
            message: String::from("Could not find requested file in the database."),
        }
    }

    // ------------------------------------------------------------------------

    pub fn kind(&self) -> String {
        self.kind.clone()
    }
}

// ----------------------------------------------------------------------------

impl From<rusqlite::Error> for DBFileError {
    fn from(error: rusqlite::Error) -> Self {
        DBFileError {
            kind: String::from("RusqliteError"),
            message: error.to_string()
        }
    }
}

// ----------------------------------------------------------------------------

impl fmt::Debug for DBFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        f.debug_tuple("")
        .field(&self.kind)
        .field(&self.message)
        .finish()
    }
}

// ----------------------------------------------------------------------------

impl fmt::Debug for DBFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        f.debug_tuple("")
        .field(&self.id)
        .field(&self.timestamp)
        .field(&self.hash)
        .field(&self.path)
        .field(&self.size)
        .finish()
    }
}

// ----------------------------------------------------------------------------

impl fmt::Display for DBFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Oh no, something bad went down")
    }
}

// ----------------------------------------------------------------------------

impl DBFile {
    pub fn new(cfg: AppConfig, path: &str, id: Option<String>) -> Self {
        let metadata = Path::new(path).metadata().unwrap();
        let size = metadata.clone().len();
        let hash = hash::get_checksum(
            String::from(path), 
            cfg.clone().events_max_file_checksum,
            cfg.clone().hashscanner_algorithm);

        let target_id = match id {
            Some(data) => data,
            None => utils::get_uuid()
        };

        let permissions = match utils::get_os() {
            "windows" => None, // Not implemented
            _ => Some(format!("{:o}", metadata.permissions().mode()).parse::<u32>().unwrap())
        };

        DBFile {
            id: target_id,
            timestamp: utils::get_current_time_millis(),
            hash,
            path: String::from(path),
            size,
            permissions
        }
    }

    // ------------------------------------------------------------------------

    pub fn clone(&self) -> Self {
        DBFile {
            id: self.id.clone(),
            timestamp: self.timestamp.clone(),
            hash: self.hash.clone(),
            path: self.path.clone(),
            size: self.size,
            permissions: self.permissions.clone()
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_file_hash(&self, cfg: AppConfig) -> String {
        hash::get_checksum(
            String::from(&self.path),
            cfg.clone().events_max_file_checksum,
            cfg.clone().hashscanner_algorithm
        )
    }

    // ------------------------------------------------------------------------

    pub fn get_file_permissions(&self) -> u32 {
        let metadata = Path::new(&self.path).metadata().unwrap();
        match utils::get_os() {
            "windows" => 0, // Not implemented
            _ => format!("{:o}", metadata.permissions().mode()).parse::<u32>().unwrap()
        }
    }

}