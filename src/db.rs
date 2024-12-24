// Copyright (C) 2024, Achiefs.

use crate::appconfig;
use crate::utils;
use crate::dbfile::*;

use rusqlite::{Connection, Error};
use rusqlite::Error::QueryReturnedNoRows;
use std::path::Path;
use log::*;


pub const DBNAME: &str = "fim.db";

pub struct DB {
    path: String
}

impl DB {
    pub fn new() -> DB {
        let mut config_folder = Path::new(&appconfig::get_config_path(utils::get_os()))
        .parent().unwrap().to_path_buf();
        config_folder.push(DBNAME);

        DB {
            path: String::from(config_folder.to_str().unwrap()),
        }
    }

    // ------------------------------------------------------------------------

    pub fn open(&self) -> Connection {
        match Connection::open(self.path.clone()) {
            Ok(database) => {
                debug!("Database connection opened ready to read/write");
                database
            }
            Err(e) => {
                error!("Database cannot be opened, Err: [{}]", e);
                info!("Please, check if {} is locked or in use.", DBNAME);
                panic!();
            }
        }
    }

    // ------------------------------------------------------------------------

    pub fn close(&self, connection: Connection) {
        match connection.close(){
            Ok(_) => debug!("DB connection closed successfully"),
            Err(e) => warn!("DB connection could not be closed, error: {:?}", e)
        };
    }

    // ------------------------------------------------------------------------

    pub fn exists(&self) -> bool {
        let mut config_folder = Path::new(&appconfig::get_config_path(utils::get_os()))
        .parent().unwrap().to_path_buf();
        config_folder.push(DBNAME);

        config_folder.exists()
    }

    // ------------------------------------------------------------------------

    pub fn is_empty(&self) -> bool {
        let connection = self.open();
        let result = connection.query_row("SELECT * FROM files LIMIT 1", [], |_row| Ok(0));
        self.close(connection);
        match result {
            Ok(_v) => false,
            Err(e) => {
                if e == QueryReturnedNoRows {
                    true
                } else {
                    error!("Could not check if the database is empty, Error: {}", e);
                    true
                }
            }
        }
    }

    // ------------------------------------------------------------------------

    pub fn create_table(&self) {
        let connection = self.open();
        let result = connection.execute(
            "CREATE TABLE IF NOT EXISTS files (
                dbid INTEGER PRIMARY KEY,
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                hash TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                size INTEGER,
                PRIMARY KEY(dbid, id) )",
            (),
        );
        match result {
            Ok(_v) => info!("Database successfully created."),
            Err(e) => error!("Error creating database, Error: '{}'", e)
        }
        self.close(connection);
    }

    // ------------------------------------------------------------------------

    pub fn insert_file(&self, file: DBFile) {
        let connection = self.open();
        let result = connection.execute(
            "INSERT INTO files (timestamp, hash, path, size) VALUES (?1, ?2, ?3, ?4)",
            (file.timestamp, file.hash, file.path, file.size)
        );
        match result {
            Ok(_) => debug!("Inserted new file in DB"),
            Err(e) => warn!("Could not insert file in DB (Probably duplicated path), error: {:?}", e)
        }
        self.close(connection);
    }

    // ------------------------------------------------------------------------

    pub fn get_file_by_path(&self, path: String) -> Result<DBFile, DBFileError> {
        let connection = self.open();
        let result = connection.query_row(
            "SELECT * FROM files WHERE path = ?1 LIMIT 1",
            [path.clone()],
            |row| Ok(DBFile {
                dbid: row.get(0).unwrap(),
                id: row.get(1).unwrap(),
                timestamp: row.get(2).unwrap(),
                hash: row.get(3).unwrap(),
                path: row.get(4).unwrap(),
                size: row.get(5).unwrap()
            })
        );

        let data = match result {
            Ok(d) => Ok(d),
            Err(e) => {
                match e {
                    Error::QueryReturnedNoRows => Err(DBFileError::not_found_error()),
                    _ => {
                        error!("Could not get file '{}' information in database, Error: {:?}", path, e);
                        Err(DBFileError::from(e))
                    }
                }
            }
        };

        self.close(connection);
        data
    }

    // ------------------------------------------------------------------------

    pub fn get_file_by_id(&self, dbid: u64) -> DBFile {
        let connection = self.open();
        let data = connection.query_row(
            "SELECT * FROM files WHERE dbid = ?1 LIMIT 1",
            [dbid],
            |row| Ok(DBFile {
                dbid: row.get(0).unwrap(),
                id: row.get(1).unwrap(),
                timestamp: row.get(2).unwrap(),
                hash: row.get(3).unwrap(),
                path: row.get(4).unwrap(),
                size: row.get(5).unwrap()
            })
        ).unwrap();

        self.close(connection);
        data
    }

    // ------------------------------------------------------------------------

    pub fn update_file(&self, dbfile: DBFile, timestamp: Option<String>, hash: Option<String>, size: Option<u64>) {
        let connection = self.open();

        let timestamp_str = match timestamp {
            Some(t) => format!("timestamp = '{}'", t),
            None => String::new()
        };
        let hash_str = match hash {
            Some(h) => format!("hash = '{}'", h),
            None => String::new()
        };
        let size_str = match size {
            Some(s) => format!("size = '{}'", s),
            None => String::new()
        };

        let query = format!("UPDATE files SET {}, {}, {} WHERE dbid = {}",
            timestamp_str, hash_str, size_str, dbfile.dbid);

        let mut statement = connection.prepare(&query).unwrap();
        let result = statement.execute([]);
        match result {
            Ok(_v) => debug!("File '{}', updated with new information.", dbfile.path),
            Err(e) => error!("Cannot update file '{}' information, Error: {:?}", dbfile.path, e)
        }

    }

    // ------------------------------------------------------------------------

    pub fn print(&self) {
        let connection = self.open();
        let mut query = connection.prepare(
            "SELECT * from files").unwrap();
        let files = query.query_map([], |row|{
            Ok(DBFile {
                dbid: row.get(0).unwrap(),
                id: row.get(1).unwrap(),
                timestamp: row.get(2).unwrap(),
                hash: row.get(3).unwrap(),
                path: row.get(4).unwrap(),
                size: row.get(5).unwrap(),
            })
        }).unwrap();

        for file in files {
            println!("{:?}", file.unwrap());
        }
    }
}