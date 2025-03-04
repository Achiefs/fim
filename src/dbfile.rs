// Copyright (C) 2024, Achiefs.

use crate::utils;
use crate::hash;
use crate::appconfig::*;

use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use rusqlite;

pub struct DBFileError {
    kind: String,
    message: String
}

pub struct DBFile {
    pub id: String,
    pub timestamp: String,
    pub hash: String,
    pub path: String,
    pub size: u64
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
        let size = Path::new(path).metadata().unwrap().len();
        let hash = match cfg.clone().checksum_method.as_str() {
            "Partial" => hash::get_partial_checksum(
                String::from(path),
                Sha256::new()
            ),
            _ => hash::get_checksum(
                String::from(path),
                cfg.clone().events_max_file_checksum,
                Sha256::new())
        };

        let target_id = match id {
            Some(data) => data,
            None => utils::get_uuid()
        };

        DBFile {
            id: target_id,
            timestamp: utils::get_current_time_millis(),
            hash,
            path: String::from(path),
            size
        }
    }

    // ------------------------------------------------------------------------

    pub fn clone(&self) -> Self {
        DBFile {
            id: self.id.clone(),
            timestamp: self.timestamp.clone(),
            hash: self.hash.clone(),
            path: self.path.clone(),
            size: self.size
        }
    }

    // ------------------------------------------------------------------------

    pub fn get_file_hash(&self, cfg: AppConfig) -> String {
        match cfg.clone().checksum_method.as_str() {
            "Partial" => hash::get_partial_checksum(
                String::from(&self.path),
                Sha256::new()
            ),
            _ => hash::get_checksum(
                String::from(&self.path),
                cfg.clone().events_max_file_checksum, Sha256::new())//hash::get_hasher("Sha256"))
        }
    }
}