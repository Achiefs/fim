use super::*;

// ----------------------------------------------------------------------------

#[test]
/// Check new instance attributes
fn test_new() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let dbfile_no_id = DBFile::new(cfg.clone(), "LICENSE", None);
    let dbfile = DBFile::new(cfg.clone(), "./LICENSE", Some(String::from("0")));

    assert_eq!(dbfile_no_id.timestamp.len(), 13);
    assert_eq!(dbfile_no_id.hash, dbfile_no_id.get_file_hash(cfg));
    assert_eq!(dbfile_no_id.path, "LICENSE");
    if cfg!(target_family = "unix") {
        assert_eq!(dbfile_no_id.size, 35149);
    } else {
        assert_eq!(dbfile_no_id.size, 35823);
    };
    assert_eq!(dbfile_no_id.permissions, utils::get_unix_permissions(&dbfile_no_id.path));

    assert_eq!(dbfile.id, String::from("0"));
    assert_eq!(dbfile.path, "./LICENSE");
    
}

// ------------------------------------------------------------------------

#[test]
/// Check each attributes of cloned object
fn test_clone() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let dbfile = DBFile::new(cfg.clone(), "LICENSE", None);
    let cloned = dbfile.clone();

    assert_eq!(dbfile.id, cloned.id);
    assert_eq!(dbfile.timestamp, cloned.timestamp);
    assert_eq!(dbfile.hash, cloned.hash);
    assert_eq!(dbfile.path, cloned.path);
    assert_eq!(dbfile.size, cloned.size);
    assert_eq!(dbfile.permissions, cloned.permissions);
}

// ------------------------------------------------------------------------

#[test]
/// Check match of file hashing function
fn test_get_file_hash() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let dbfile = DBFile::new(cfg.clone(), "LICENSE", None);
    let hash = dbfile.get_file_hash(cfg.clone());

    assert_eq!(dbfile.hash, hash);
}

// ------------------------------------------------------------------------

#[test]
/// Check the dbfile debug stdout formatter
fn test_fmt_debug() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let mut dbfile = DBFile::new(cfg.clone(), "LICENSE", None);
    dbfile.id = String::from("FIXED_ID");
    dbfile.timestamp = String::from("FIXED_TIMESTAMP");

    let out = format!("{:?}", dbfile);
    let expected = if cfg!(target_family = "unix") {
        "(\"FIXED_ID\", \"FIXED_TIMESTAMP\", \
        \"edb0016d9f8bafb54540da34f05a8d510de8114488f23916276bdead05509a53\", \
        \"LICENSE\", 35149, 100644)"
    } else {
        "(\"FIXED_ID\", \"FIXED_TIMESTAMP\", \
        \"209ba691a607610997f45be93529e6f582c1316a50a85af3ff257457a85d8f94\", \
        \"LICENSE\", 35823, 0)"
    };
    assert_eq!(out, expected);
}

// ------------------------------------------------------------------------

#[test]
/// Check the dbfile stdout formatter
fn test_fmt() {
    let cfg = AppConfig::new(&utils::get_os(), None);
    let mut dbfile = DBFile::new(cfg.clone(), "LICENSE", None);
    dbfile.id = String::from("FIXED_ID");
    dbfile.timestamp = String::from("FIXED_TIMESTAMP");

    let out = format!("{}", dbfile);
    let expected = if cfg!(target_family = "unix") {
        "DBFile(ID: FIXED_ID, TIMESTAMP: FIXED_TIMESTAMP, \
        HASH: edb0016d9f8bafb54540da34f05a8d510de8114488f23916276bdead05509a53, \
        PATH: LICENSE, SIZE: 35149, PERMISSIONS: 100644)"
    } else {
        "DBFile(ID: FIXED_ID, TIMESTAMP: FIXED_TIMESTAMP, \
        HASH: 209ba691a607610997f45be93529e6f582c1316a50a85af3ff257457a85d8f94, \
        PATH: LICENSE, SIZE: 35823, PERMISSIONS: 0)"
    };
    assert_eq!(out, expected);
}

// ------------------------------------------------------------------------

#[test]
/// Check if DBFileError is created as expected
fn test_dbfile_error_not_found_error() {
    let error = DBFileError::not_found_error();

    assert_eq!(error.kind, String::from("DBFileNotFoundError"));
    assert_eq!(error.message, String::from("Could not find requested file in the database."));
}

// ------------------------------------------------------------------------

#[test]
/// Check attribute kind clone
fn test_dbfile_error_kind() {
    let error = DBFileError::not_found_error();

    assert_eq!(error.kind(), error.kind);
}

// ------------------------------------------------------------------------

#[test]
/// Check DBFileError generation from rusqlite error
fn test_dbfile_error_from() {
    let error = DBFileError::from(rusqlite::Error::QueryReturnedNoRows);

    assert_eq!(error.kind, String::from("RusqliteError"));
    assert_eq!(error.message, "Query returned no rows");
}