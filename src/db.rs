// Copyright (C) 2024, Achiefs.

use crate::dbfile::*;
use crate::appconfig::AppConfig;

use rusqlite::{Connection, Error, params};
use rusqlite::Error::QueryReturnedNoRows;
use log::*;

#[derive(Clone)]
pub struct DB {
    pub path: String
}

#[cfg(test)]
mod test;

// ----------------------------------------------------------------------------

impl DB {
    /// Create a new db object
    pub fn new(path: &str) -> DB {
        DB {
            path: String::from(path),
        }
    }

    // ------------------------------------------------------------------------

    /// Open a handle to the db
    pub fn open(&self) -> Connection {
        match Connection::open(self.path.clone()) {
            Ok(database) => {
                debug!("Database connection opened ready to read/write");
                database
            }
            Err(e) => {
                error!("Database cannot be opened, Err: [{}]", e);
                info!("Please, check if {} is locked or in use.", self.path);
                panic!();
            }
        }
    }

    // ------------------------------------------------------------------------

    /// Close the db handle
    pub fn close(&self, connection: Connection) {
        match connection.close(){
            Ok(_) => debug!("DB connection closed successfully"),
            Err(e) => warn!("DB connection could not be closed, error: {:?}", e)
        };
    }

    // ------------------------------------------------------------------------

    /// Check if current db is empty
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

    /// Create the `files` table where store all files information
    /// Defines files table schema
    pub fn create_table(&self) {
        let connection = self.open();
        let result = connection.execute(
            "CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                hash TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                size INTEGER,
                permissions INTEGER)",
            (),
        );
        match result {
            Ok(_v) => info!("Database successfully created."),
            Err(e) => error!("Error creating database, Error: '{}'", e)
        }
        self.close(connection);
    }

    // ------------------------------------------------------------------------

    /// Insert information of a given DBFile in db
    pub fn insert_file(&self, file: DBFile) {
        let connection = self.open();
        let result = connection.execute(
            "INSERT INTO files (id, timestamp, hash, path, size, permissions) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (file.id, file.timestamp, file.hash, file.path, file.size, file.permissions)
        );
        match result {
            Ok(_) => debug!("Inserted new file in DB"),
            Err(e) => warn!("Could not insert file in DB (Probably duplicated path), error: {:?}", e)
        }
        self.close(connection);
    }

    // ------------------------------------------------------------------------

    /// Retrieve the DBFile object from db, using the path of file
    pub fn get_file_by_path(&self, path: String) -> Result<DBFile, DBFileError> {
        let connection = self.open();
        let result = connection.query_row(
            "SELECT * FROM files WHERE path = ?1 LIMIT 1",
            [path.clone()],
            |row| Ok(DBFile {
                id: row.get(0).unwrap(),
                timestamp: row.get(1).unwrap(),
                hash: row.get(2).unwrap(),
                path: row.get(3).unwrap(),
                size: row.get(4).unwrap(),
                permissions: row.get(5).unwrap()
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

    /// Retrieve a list of files that match the given path
    pub fn get_file_list(&self, path: String) -> Vec<DBFile> {
        let connection = self.open();
        let mut list = Vec::new();
        let query = format!("SELECT * FROM files WHERE path LIKE '{}%'", path);
        let mut statement = connection.prepare_cached(&query).unwrap();
        let result = statement.query_map([], |row| {
            Ok(DBFile {
                id: row.get(0).unwrap(),
                timestamp: row.get(1).unwrap(),
                hash: row.get(2).unwrap(),
                path: row.get(3).unwrap(),
                size: row.get(4).unwrap(),
                permissions: row.get(5).unwrap()
            })
        });
        match result {
            Ok(mapped_rows) => {
                for file in mapped_rows {
                    list.push(file.unwrap())
                }
            },
            Err(e) => error!("Could not get database file list, error: {:?}", e)
        };
        list
    }

    // ------------------------------------------------------------------------

    /// Update db information of the given DBFile information
    pub fn update_file(&self, cfg: AppConfig, dbfile: DBFile) -> Option<DBFile>{
        let connection = self.open();
        let current_dbfile = DBFile::new(cfg, &dbfile.path, Some(dbfile.id));
        let query = "UPDATE files SET timestamp = ?1, hash = ?2, size = ?3, permissions = ?4 WHERE id = ?5";

        let mut statement = connection.prepare(query).unwrap();
        let result = statement.execute(params![
            current_dbfile.timestamp,
            current_dbfile.hash,
            current_dbfile.size,
            current_dbfile.permissions,
            current_dbfile.id]);
        match result {
            Ok(_v) => {
                debug!("File '{}', updated with new information.", dbfile.path);
                Some(current_dbfile)
            },
            Err(e) => {
                error!("Cannot update file '{}' information, Error: {:?}", dbfile.path, e);
                None
            }
        }
    }

    // ------------------------------------------------------------------------

    /// Delete information inside db related to the given DBFile
    pub fn delete_file(&self, dbfile: DBFile) -> Result<u8, DBFileError>{
        let connection = self.open();
        let mut statement = connection.prepare("DELETE FROM files WHERE id = ?1").unwrap();
        let result = statement.execute(params![dbfile.id]);
        match result {
            Ok(_v) => {
                debug!("File '{}', deleted from database.", dbfile.path);
                Ok(0)
            },
            Err(e) => {
                error!("Cannot delete file '{}' information, Error: {:?}", dbfile.path, e);
                Err(DBFileError::from(e))
            }
        }
    }
}