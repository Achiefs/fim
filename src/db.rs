use rusqlite::Connection;
use std::path::Path;
use crate::appconfig;
use crate::utils;
use log::*;
use std::fmt;

pub const DBNAME: &str = "fim.db";

pub struct DBFile {
    pub id: u64,
    pub timestamp: String,
    pub hash: String,
    pub path: String,
    pub size: u64
}

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

    pub fn create_table(&self) {
        let connection = self.open();
        let result = connection.execute(
            "CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                hash TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                size INTEGER)",
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

    pub fn get_file(&self, path: String) -> DBFile {
        let connection = self.open();
        let data = connection.query_row(
            "SELECT * FROM files WHERE path = ?1 LIMIT 1",
            [path],
            |row| Ok(DBFile {
                id: row.get(0).unwrap(),
                timestamp: row.get(1).unwrap(),
                hash: row.get(2).unwrap(),
                path: row.get(3).unwrap(),
                size: row.get(4).unwrap()
            })
        ).unwrap();

        self.close(connection);
        data
    }

    // ------------------------------------------------------------------------

    pub fn print(&self) {
        let connection = self.open();
        let mut query = connection.prepare(
            "SELECT * from files").unwrap();
        let files = query.query_map([], |row|{
            Ok(DBFile {
                id: row.get(0).unwrap(),
                timestamp: row.get(1).unwrap(),
                hash: row.get(2).unwrap(),
                path: row.get(3).unwrap(),
                size: row.get(4).unwrap(),
            })
        }).unwrap();

        for file in files {
            println!("{:?}", file.unwrap());
        }
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