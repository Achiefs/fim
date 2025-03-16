use super::*;

#[test]
/// Check new instance creation, the instance should match the expected DB path.
fn test_new() {
    let new_db = DB::new();
    let mut path = Path::new(&appconfig::get_config_path(utils::get_os())).parent().unwrap().to_path_buf();
    path.push(super::DBNAME);

    assert_eq!(new_db.path, path.to_str().unwrap());
}

// ------------------------------------------------------------------------

#[test]
/// Check open of new DB changes, it should be 0
fn test_open() {
    let tdb = DB::new();
    let connection = tdb.open();

    assert_eq!(connection.changes(), 0);
}

// ------------------------------------------------------------------------

#[test]
/// Check close of new DB, it should not panic
fn test_close() {
    let tdb = DB::new();
    let connection = tdb.open();
    tdb.close(connection);
}

// ------------------------------------------------------------------------

#[test]
/// Check DB emptiness, it should be empty on first check and not empty in second
fn test_is_empty() {
    use std::fs::remove_file;
    let tdb = DB::new();
    
    remove_file(tdb.clone().path).unwrap();
    assert_eq!(tdb.is_empty(), true);
    tdb.create_table();
    tdb.insert_file(DBFile{
        id: String::from("ID"),
        timestamp: String::from("TIMESTAMP"),
        hash: String::from("HASH"),
        path: String::from("PATH"),
        size: 10,
        permissions: 0
    });
    assert_eq!(tdb.is_empty(), false);
}

// ------------------------------------------------------------------------

#[test]
/// Check DB table creation, pragma query should obtain first row of schema (id)
fn test_create_table() {
    use std::fs::remove_file;
    let tdb = DB::new();
    
    remove_file(tdb.clone().path).unwrap();
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
/// 
fn test_insert_file() {
    use std::fs::remove_file;
    let tdb = DB::new();
    
    remove_file(tdb.clone().path).unwrap();
    tdb.create_table();
    tdb.insert_file(DBFile{
        id: String::from("ID"),
        timestamp: String::from("TIMESTAMP"),
        hash: String::from("HASH"),
        path: String::from("PATH"),
        size: 10,
        permissions: 0
    });

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