use super::*;
use std::fs::{create_dir_all, remove_dir_all, File};
use serial_test::serial;
use std::path::Path;

use crate::db::DB;

// ----------------------------------------------------------------------------

fn remove_db() {
    use std::fs::remove_file;
    let tdb = DB::new();

    if Path::new(&tdb.clone().path).exists() {
        match remove_file(tdb.clone().path){
            Ok(_v) => (),
            Err(e) => println!("Error deleting db, {}", e)
        };
    };
}

// ----------------------------------------------------------------------------

#[test]
#[serial]
/// Check dir scan result, DB should contains a DBFile definition with the given filepath
fn test_scan_path() {
    let tdb = DB::new();
    let cfg = AppConfig::new(&utils::get_os(), None);
    let scan_dir = String::from("./tmp/test_scan_path");
    let filepath = format!("{}/{}", scan_dir.clone(), "test_scan_path.txt");
    let _ = create_dir_all(scan_dir.clone());

    let _file = match File::create(&filepath) {
        Ok(file) => file,
        Err(e) => panic!("Could not create test file, error: '{}'", e)
    };

    remove_db();
    tdb.create_table();
    scan_path(cfg.clone(), scan_dir.clone());

    let dbfile = tdb.get_file_by_path(filepath.clone()).unwrap();
    assert_eq!(dbfile.path, filepath);

    let _ = remove_dir_all(scan_dir);
}