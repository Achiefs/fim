use super::*;
use std::{thread, time};

// ----------------------------------------------------------------------------

#[test]
fn test_pop() {
    assert_eq!(pop("test-"), "test");
    assert_eq!(pop("dir/"), "dir");
    assert_eq!(pop("dir@"), "dir");
}

// ------------------------------------------------------------------------

#[test]
fn test_get_hostname() {
    // We will need to manage a better test
    assert_eq!(get_hostname(), gethostname::gethostname().into_string().unwrap());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_uuid() {
    // 9bd52d8c-e162-4f4d-ab35-32206d6d1445
    let uuid = get_uuid();
    let uuid_vec: Vec<&str> = uuid.split("-").collect();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid_vec.len(), 5);
    assert_eq!(uuid_vec[0].len(), 8);
    assert_eq!(uuid_vec[1].len(), 4);
    assert_eq!(uuid_vec[2].len(), 4);
    assert_eq!(uuid_vec[3].len(), 4);
    assert_eq!(uuid_vec[4].len(), 12);
}

// ------------------------------------------------------------------------

#[test]
fn test_get_pid() {
    assert_eq!(get_pid(), process::id());
    assert!(get_pid() > 0);
}

// ------------------------------------------------------------------------

#[test]
fn test_get_os() {
    assert_eq!(get_os(), env::consts::OS.to_string());
}

// ------------------------------------------------------------------------

#[test]
fn test_read_file() {
    assert_eq!(read_file("pkg/deb/debian/compat"), "10");
    assert_ne!(read_file("LICENSE"), "10");
}

// ------------------------------------------------------------------------

#[test]
#[ignore]
fn test_get_machine_id() {
    if get_os() == "linux" {
        assert_eq!(get_machine_id().len(), 33);
    }
}

// ------------------------------------------------------------------------

#[test]
fn test_get_filename_path() {
    if get_os() == "windows"{
        assert_eq!(get_filename_path("C:\\test\\file.txt"), "file.txt");
        assert_ne!(get_filename_path("C:\\test\\file.txt"), "none");
    }else{
        assert_eq!(get_filename_path("/test/file.txt"), "file.txt");
        assert_ne!(get_filename_path("/test/file.txt"), "none");
        assert_eq!(get_filename_path("/test/"), "test");
    }
}

// ------------------------------------------------------------------------

#[test]
fn test_get_filename_path_empty() {
    assert_eq!(get_filename_path("/"), "/");
}

// ------------------------------------------------------------------------

#[test]
fn test_clean_path() {
    assert_eq!(clean_path("/test/"), "/test");
    assert_eq!(clean_path("/test"), "/test");
    assert_eq!(clean_path("C:\\test\\"), "C:\\test");
    assert_eq!(clean_path("C:\\test"), "C:\\test");
    assert_eq!(clean_path("/"), "");
}

// ------------------------------------------------------------------------

#[test]
fn test_get_file_end() {
    assert_ne!(get_file_end("LICENSE", 0), 100);
    // CRLF matter
    if get_os() == "windows"{
        assert_eq!(get_file_end("LICENSE", 0), 35823);
    }else{
        assert_eq!(get_file_end("LICENSE", 0), 35149);
    }

    assert_eq!(get_file_end("NotFound", 0), 0);
}

// ------------------------------------------------------------------------

#[test]
fn test_open_file() {
    open_file("LICENSE", 0);
}

// ------------------------------------------------------------------------

#[test]
#[should_panic]
fn test_open_file_panic() {
    open_file("NotFound", 0);
}

// ------------------------------------------------------------------------

#[test]
#[ignore]
fn test_check_auditd() {
    if get_os() == "linux" {
        assert!(check_auditd());
    }
}

// ------------------------------------------------------------------------

#[test]
fn test_match_path() {
    if get_os() == "linux" {
        assert!(match_path("/", "/"));
        assert!(match_path("/test", "/test"));
        assert!(match_path("/test/", "/test"));
        assert!(match_path("/test/tmp", "/test"));
        assert!(!match_path("/tmp/test", "/test"));
        assert!(!match_path("/tmp", "/test"));
    }
}

// ------------------------------------------------------------------------

#[test]
/// Check function return value of given key, it should match with array value
fn test_get_field() {
    let mut hm: HashMap<String, String> = HashMap::new();
    let value = String::from("Value");
    hm.insert(String::from("Key"), value.clone());
    let field = get_field(hm.clone(), "Key");
    assert_eq!(field, value);
    assert_eq!(get_field(hm, "Value"), String::from("UNKNOWN"))
}

// ------------------------------------------------------------------------

#[test]
/// Check size of file, it should return the size on disk of LICENSE file
fn test_get_file_size() {
    // CRLF matter
    if get_os() == "windows"{
        assert_eq!(get_file_size("LICENSE"), 35823);
    }else{
        assert_eq!(get_file_size("LICENSE"), 35149);
    }
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_get_audit_rule_permissions() {
    use crate::appconfig::*;
    let cfg = AppConfig::new(&get_os(), Some("test/unit/config/linux/audit_rule.yml"));
    assert_eq!(get_audit_rule_permissions(cfg.audit[0]["rule"].as_str()), "rwax");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_run_auditctl() {
    use crate::appconfig::*;
    let cfg = AppConfig::new(&get_os(), Some("test/unit/config/linux/audit_rule.yml"));
    let path = cfg.audit[0]["path"].as_str().unwrap();
    let rule = cfg.audit[0]["rule"].as_str().unwrap();
    run_auditctl(&["-w", path, "-k", "fim", "-p", rule]);

    match Command::new("/usr/sbin/auditctl")
    .args(["-l", "-k", "fim"])
    .output()
    {
        Ok(data) => assert_eq!(String::from_utf8(data.stdout).unwrap(), "-w /tmp -p rwxa -k fim\n"),
        Err(e) => {
            println!("{:?}", e);
            assert!(true)
        }
    };
}

// ------------------------------------------------------------------------

#[test]
/// Check the retrieve of current time in millis, it should return the time plus 10 ms
fn test_get_current_time_millis() {
    let millis = get_current_time_millis().parse::<u64>().unwrap();
    thread::sleep(time::Duration::from_millis(10));
    assert_ne!(millis, millis + 10);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
/// Check file list completion, it should return a list of 3 elements
fn test_get_fs_list() {
    let mut list = get_fs_list(String::from("test/stress"));
    list.sort();
    assert_eq!(list[0], String::from("test/stress"));
    assert_eq!(list[1], String::from("test/stress/monitor.sh"));
    assert_eq!(list[2], String::from("test/stress/stress.sh"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
/// Check file list completion, it should return a list of 3 elements
fn test_get_fs_list_windows() {
    let mut list = get_fs_list(String::from("test\\stress"));
    list.sort();
    assert_eq!(list[0], String::from("test\\stress"));
    assert_eq!(list[1], String::from("test\\stress\\monitor.sh"));
    assert_eq!(list[2], String::from("test\\stress\\stress.sh"));
}

// ------------------------------------------------------------------------

#[test]
/// Check file permissions, it should return the 644 standar permissions
fn test_get_unix_permissions() {
    if get_os() == "windows"{
        assert_eq!(get_unix_permissions("LICENSE"), 0);
    }else{
        assert_eq!(get_unix_permissions("LICENSE"), 100644);
    }
}