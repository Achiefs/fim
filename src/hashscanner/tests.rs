use super::*;
use std::fs::{create_dir_all, remove_dir_all, File};
use serial_test::serial;
use std::path::Path;
use std::io::Write;
use tokio_test::block_on;
use std::fs;

use crate::db::DB;

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

#[test]
#[serial]
#[cfg(target_family = "unix")]
/// Check dir scan result, DB should contains a DBFile definition with the given filepath
fn test_scan_path_unix() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let tdb = DB::new(&cfg.hashscanner_file);
    let scan_dir = String::from("./tmp/test_scan_path");
    let filepath = format!("{}/{}", scan_dir.clone(), "test_scan_path.txt");
    let _ = create_dir_all(scan_dir.clone());

    let _file = match File::create(&filepath) {
        Ok(file) => file,
        Err(e) => panic!("Could not create test file, error: '{}'", e)
    };

    remove_db(&cfg.hashscanner_file);
    tdb.create_table();
    scan_path(cfg.clone(), scan_dir.clone());

    let dbfile = tdb.get_file_by_path(filepath.clone()).unwrap();
    assert_eq!(dbfile.path, filepath);
    assert_eq!(dbfile.size, utils::get_file_size(&filepath));

    let _ = remove_dir_all(scan_dir);
}

// ----------------------------------------------------------------------------

#[test]
#[serial]
#[cfg(target_family = "unix")]
/// Check that modify a file is reflected in DB, it should modify the size and hash of DBFile
fn test_check_path() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let tdb = DB::new(&cfg.hashscanner_file);
    let scan_dir = String::from("./tmp/test_check_path");
    let filepath = format!("{}/{}", scan_dir.clone(), "test_check_path.txt");
    let _ = create_dir_all(scan_dir.clone());

    let mut _file = match File::create(&filepath) {
        Ok(file) => file,
        Err(e) => panic!("Could not create test file, error: '{}'", e)
    };

    remove_db(&cfg.hashscanner_file);
    tdb.create_table();
    scan_path(cfg.clone(), scan_dir.clone());
    let _result = writeln!(_file, "{}", "This is an additional line.");
    block_on(check_path(cfg.clone(), scan_dir.clone(), true));

    let dbfile = tdb.get_file_by_path(filepath.clone()).unwrap();
    assert_eq!(dbfile.path, filepath);
    assert_eq!(dbfile.size, utils::get_file_size(&filepath));

    let _ = remove_dir_all(scan_dir);
}

// ----------------------------------------------------------------------------

#[test]
#[serial]
#[cfg(target_family = "unix")]
#[should_panic(expected = "DBFileNotFoundError")]
/// Check file deletion of filesystem and DB, it should panic with DBFileNotFoundError
fn test_update_db() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let tdb = DB::new(&cfg.hashscanner_file);
    let scan_dir = String::from("./tmp/test_update_db");
    let filepath = format!("{}/{}", scan_dir.clone(), "test_update_db.txt");
    let filepath2 = format!("{}/{}", scan_dir.clone(), "test_update_db2.txt");
    let _ = create_dir_all(scan_dir.clone());

    let mut _file = match File::create(&filepath) {
        Ok(file) => file,
        Err(e) => panic!("Could not create test file, error: '{}'", e)
    };
    let mut _file2 = match File::create(&filepath2) {
        Ok(file) => file,
        Err(e) => panic!("Could not create test file, error: '{}'", e)
    };

    remove_db(&cfg.hashscanner_file);
    tdb.create_table();
    scan_path(cfg.clone(), scan_dir.clone());
    fs::remove_file(filepath.clone()).unwrap();
    block_on(update_db(cfg, scan_dir.clone(), true));

    let dbfile = tdb.get_file_by_path(filepath2.clone()).unwrap();
    assert_eq!(dbfile.path, filepath2);
    assert_eq!(dbfile.size, utils::get_file_size(&filepath2));
    let _ = remove_dir_all(scan_dir);

    // Panic line
    let _dbfile = tdb.get_file_by_path(filepath.clone()).unwrap();
}