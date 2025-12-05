use super::*;
use serial_test::serial;
use std::path::Path;

use crate::utils;

// ----------------------------------------------------------------------------

fn remove_db(path: &str) {
    use std::fs::remove_file;

    if Path::new(path).exists() {
        match remove_file(path){
            Ok(_v) => (),
            Err(e) => println!("Error deleting db, {}", e)
        };
    };
}

// ----------------------------------------------------------------------------

fn get_dbfile() -> DBFile {
    DBFile{
        id: String::from("ID"),
        timestamp: String::from("TIMESTAMP"),
        hash: String::from("HASH"),
        path: String::from("PATH"),
        size: 10,
        permissions: 0
    }
}

// ----------------------------------------------------------------------------

#[test]
#[serial]
/// Check new instance creation, the instance should match the expected DB path.
fn test_new() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let tdb = DB::new(&cfg.hashscanner_file);

    assert_eq!(tdb.path, cfg.hashscanner_file);
}

// ------------------------------------------------------------------------

#[test]
#[serial]
/// Check open of new DB changes, it should be 0
fn test_open() {
    let tdb = DB::new("fim.db");
    let connection = tdb.open();

    assert_eq!(connection.changes(), 0);
}

// ------------------------------------------------------------------------

#[test]
#[serial]
/// Check close of new DB, it should not panic
fn test_close() {
    let tdb = DB::new("fim.db");
    let connection = tdb.open();
    tdb.close(connection);
}

// ------------------------------------------------------------------------

#[test]
#[serial]
/// Check DB emptiness, it should be empty on first check and not empty in second
fn test_is_empty() {
    let db_path = "fim.db";
    let tdb = DB::new(db_path);
    
    remove_db(db_path);
    assert_eq!(tdb.is_empty(), true);
    tdb.create_table();
    tdb.insert_file(get_dbfile());
    assert_eq!(tdb.is_empty(), false);
}

// ------------------------------------------------------------------------

#[test]
#[serial]
/// Check DB table creation, pragma query should obtain first row of schema (id)
fn test_create_table() {
    let db_path = "fim.db";
    let tdb = DB::new(db_path);
    
    remove_db(db_path);
    tdb.create_table();

    let connection = tdb.open();
    let result = connection.query_row("SELECT * FROM pragma_table_info('files')",
        [],
        |row| {
            let data0: u32 = row.get(0).unwrap();
            let data1: String = row.get(1).unwrap();
            let data2: String = row.get(2).unwrap();
            assert_eq!(data0, 0);
            assert_eq!(data1, "id");
            assert_eq!(data2, "TEXT");
            Ok(())
        }
    );

    assert_eq!(result, Ok(()));
}

// ------------------------------------------------------------------------

#[test]
#[serial]
/// Check DB insertion, the data in DB should be the same as inserted object
fn test_insert_file() {
    let db_path = "fim.db";
    let tdb = DB::new(db_path);
    
    remove_db(db_path);
    tdb.create_table();
    tdb.insert_file(get_dbfile());

    let connection = tdb.open();
    let result = connection.query_row("SELECT * FROM files WHERE id = 'ID'",
        [],
        |row| {
            let data0: String = row.get(0).unwrap();
            let data1: String = row.get(1).unwrap();
            let data2: String = row.get(2).unwrap();
            let data3: String = row.get(3).unwrap();
            let data4: u32 = row.get(4).unwrap();
            let data5: u32 = row.get(5).unwrap();
            assert_eq!(data0, "ID");
            assert_eq!(data1, "TIMESTAMP");
            assert_eq!(data2, "HASH");
            assert_eq!(data3, "PATH");
            assert_eq!(data4, 10);
            assert_eq!(data5, 0);
            Ok(())
        }
    );

    assert_eq!(result, Ok(()));
}

// ------------------------------------------------------------------------

#[test]
#[serial]
/// Check dbfile retrieve from DB, the retrieved file should match fields with original
fn test_get_file_by_path() {
    let db_path = "fim.db";
    let tdb = DB::new(db_path);
    let original_dbfile = get_dbfile();
    
    remove_db(db_path);
    tdb.create_table();
    tdb.insert_file(original_dbfile.clone());

    let dbfile = tdb.get_file_by_path(String::from("PATH")).unwrap();
    assert_eq!(dbfile.id, original_dbfile.id);
    assert_eq!(dbfile.timestamp, original_dbfile.timestamp);
    assert_eq!(dbfile.hash, original_dbfile.hash);
    assert_eq!(dbfile.path, original_dbfile.path);
    assert_eq!(dbfile.size, original_dbfile.size);
    assert_eq!(dbfile.permissions, original_dbfile.permissions);
}

// ------------------------------------------------------------------------

#[test]
#[serial]
/// Check list retrieve of same main path files.
/// It should contains the list of files with matching attributes
fn test_get_file_list() {
    let db_path = "fim.db";
    let tdb = DB::new(db_path);
    let dbfile0 = DBFile{
        id: String::from("ID0"),
        timestamp: String::from("TIMESTAMP0"),
        hash: String::from("HASH0"),
        path: String::from("CUSTOM_PATH/0"),
        size: 100,
        permissions: 0
    };
    let dbfile1 = DBFile{
        id: String::from("ID1"),
        timestamp: String::from("TIMESTAMP1"),
        hash: String::from("HASH1"),
        path: String::from("CUSTOM_PATH/1"),
        size: 101,
        permissions: 1
    };
    
    remove_db(db_path);
    tdb.create_table();
    tdb.insert_file(dbfile0.clone());
    tdb.insert_file(dbfile1.clone());

    let list = tdb.get_file_list(String::from("CUSTOM_PATH"));
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, dbfile0.id);
    assert_eq!(list[0].timestamp, dbfile0.timestamp);
    assert_eq!(list[0].hash, dbfile0.hash);
    assert_eq!(list[0].path, dbfile0.path);
    assert_eq!(list[0].size, dbfile0.size);
    assert_eq!(list[0].permissions, dbfile0.permissions);

    assert_eq!(list[1].id, dbfile1.id);
    assert_eq!(list[1].timestamp, dbfile1.timestamp);
    assert_eq!(list[1].hash, dbfile1.hash);
    assert_eq!(list[1].path, dbfile1.path);
    assert_eq!(list[1].size, dbfile1.size);
    assert_eq!(list[1].permissions, dbfile1.permissions);
}

// ------------------------------------------------------------------------

#[test]
#[serial]
/// Check present DBFile update.
/// It should differ in calculated fields (timestamp, hash, size, permissions)
fn test_update_file() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let tdb = DB::new(&cfg.hashscanner_file);
    let original_dbfile = get_dbfile();
    let new_dbfile = DBFile {
        id: String::from("ID"),
        timestamp: String::from("CALCULATED"),
        hash: String::from("CALCULATED"),
        path: String::from("LICENSE"),
        size: 123,
        permissions: 321,
    };

    remove_db(&cfg.hashscanner_file);
    tdb.create_table();
    tdb.insert_file(original_dbfile.clone());
    let result = tdb.update_file(cfg, new_dbfile.clone());

    match result {
        Some(dbfile) => {
            assert_eq!(dbfile.id, new_dbfile.id);
            assert_ne!(dbfile.timestamp, new_dbfile.timestamp);
            assert_ne!(dbfile.hash, new_dbfile.hash);
            assert_eq!(dbfile.path, new_dbfile.path);
            assert_ne!(dbfile.size, new_dbfile.size);
            assert_ne!(dbfile.permissions, new_dbfile.permissions);
        },
        None => assert!(false)
    }
}

// ------------------------------------------------------------------------

#[test]
#[serial]
/// Check DBFile delete from DB, it should return QueryReturnedNoRows result on query
fn test_delete_file() {
    let db_path = "fim.db";
    let tdb = DB::new(db_path);
    let dbfile = get_dbfile();

    remove_db(db_path);
    tdb.create_table();
    tdb.insert_file(dbfile.clone());
    let delete_result = tdb.delete_file(dbfile.clone());
    match delete_result {
        Ok(_v) => (),
        Err(_e) => assert!(false)
    };

    let connection = tdb.open();
    let result = connection.query_row("SELECT * FROM files WHERE id = 'ID'",
        [],
        |row| {
            let data0: String = row.get(0).unwrap();
            let data1: String = row.get(1).unwrap();
            let data2: String = row.get(2).unwrap();
            let data3: String = row.get(3).unwrap();
            let data4: u32 = row.get(4).unwrap();
            let data5: u32 = row.get(5).unwrap();
            assert_eq!(data0, "ID");
            assert_eq!(data1, "TIMESTAMP");
            assert_eq!(data2, "HASH");
            assert_eq!(data3, "PATH");
            assert_eq!(data4, 10);
            assert_eq!(data5, 0);
            Ok(())
        }
    );

    assert_eq!(result, Err(QueryReturnedNoRows));
}