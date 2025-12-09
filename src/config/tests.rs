use super::*;

// ------------------------------------------------------------------------

pub fn create_test_config(filter: &str, events_destination: &str) -> Config {
    Config {
        events_watcher: String::from("Recommended"),
        events_destination: String::from(events_destination),
        events_max_file_checksum: 64,
        events_max_file_size: 128,
        checksum_algorithm: ShaType::Sha512,
        endpoint_type: String::from("Elastic"),
        endpoint_address: String::from("test"),
        endpoint_user: String::from("test"),
        endpoint_pass: String::from("test"),
        endpoint_token: String::from("test"),
        events_file: String::from("test"),
        monitor: Array::new(),
        audit: Array::new(),
        node: String::from("test"),
        log_file: String::from("./test.log"),
        log_level: String::from(filter),
        log_max_file_size: 64,
        system: String::from("test"),
        insecure: true,
        events_lock: Arc::new(Mutex::new(String::from("test"))),
        log_lock: Arc::new(Mutex::new(String::from("test"))),
        hashscanner_file: String::from("test"),
        hashscanner_enabled: true,
        hashscanner_interval: 3600,
        hashscanner_algorithm: ShaType::Sha256,
        engine: String::from("monitor")
    }
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows() {
    let dir = utils::get_current_dir();
    let disk = dir.get(0..1).unwrap();
    let cfg = Config::new("windows", None);

    assert_eq!(cfg.events_destination, String::from("file"));
    assert_eq!(cfg.endpoint_address, String::from("Not_defined"));
    assert_eq!(cfg.endpoint_type, String::from("Not_defined"));
    assert_eq!(cfg.endpoint_user, String::from("Not_defined"));
    assert_eq!(cfg.endpoint_pass, String::from("Not_defined"));
    assert_eq!(cfg.endpoint_token, String::from("Not_defined"));
    assert_eq!(cfg.events_file, format!("{}:\\ProgramData\\fim\\events.json", disk) );
    // monitor
    // audit
    assert_eq!(cfg.node, String::from("FIM"));
    assert_eq!(cfg.log_file, format!("{}:\\ProgramData\\fim\\fim.log", disk) );
    assert_eq!(cfg.log_level, String::from("info"));
    assert_eq!(cfg.log_max_file_size, 64);
    assert_eq!(cfg.system, String::from("windows"));
    assert_eq!(cfg.insecure, false);
    assert_eq!(cfg.hashscanner_file, format!("{}:\\ProgramData\\fim\\fim.db", disk) );
    assert_eq!(cfg.hashscanner_enabled, true);
    assert_eq!(cfg.hashscanner_interval, 3600);
    assert_eq!(cfg.hashscanner_algorithm, ShaType::Sha256);
    assert_eq!(cfg.engine, String::from("monitor"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_destination() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_destination_none.yml"));
    assert_eq!(cfg.events_destination, String::from("file"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[should_panic]
fn test_new_config_windows_hashscanner_file() {
    Config::new("windows", Some("test/unit/config/windows/hashscanner_file_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[should_panic]
fn test_new_config_windows_events_file() {
    Config::new("windows", Some("test/unit/config/windows/events_file_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_destination_network() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_destination_network.yml"));
    assert_eq!(cfg.events_file, String::from("Not_defined"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_max_file_checksum() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_max_file_checksum.yml"));
    assert_eq!(cfg.events_max_file_checksum, 128);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_max_file_size() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_max_file_size.yml"));
    assert_eq!(cfg.events_max_file_size, 256);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_endpoint_insecure() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_endpoint_insecure.yml"));
    assert_eq!(cfg.insecure, true);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_endpoint_insecure_none() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_endpoint_insecure_none.yml"));
    assert_eq!(cfg.insecure, false);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_destination_network_address() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_destination_network_address.yml"));
    assert_eq!(cfg.endpoint_address, "0.0.0.0");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[should_panic]
fn test_new_config_windows_events_destination_network_address_none() {
    Config::new("windows", Some("test/unit/config/windows/events_destination_network_address_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_credentials_user() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_credentials_user.yml"));
    assert_eq!(cfg.endpoint_user, "test_user");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[should_panic]
fn test_new_config_windows_events_credentials_user_none() {
    Config::new("windows", Some("test/unit/config/windows/events_credentials_user_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_credentials_password() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_credentials_password.yml"));
    assert_eq!(cfg.endpoint_pass, "test_password");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_events_credentials_token() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_credentials_token.yml"));
    assert_eq!(cfg.endpoint_token, "test_token");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[should_panic]
fn test_new_config_windows_events_credentials_password_none() {
    Config::new("windows", Some("test/unit/config/windows/events_credentials_password_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[should_panic]
fn test_new_config_windows_monitor_none() {
    Config::new("windows", Some("test/unit/config/windows/monitor_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_node_none() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/node_none.yml"));
    assert_eq!(cfg.node, utils::get_hostname());
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[should_panic]
fn test_new_config_windows_log_file_none() {
    Config::new("windows", Some("test/unit/config/windows/log_file_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_log_level_none() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/log_level_none.yml"));
    assert_eq!(cfg.log_level, "info");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_config_windows_log_max_file_size_none() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/log_max_file_size_none.yml"));
    assert_eq!(cfg.log_max_file_size, 64);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_destination() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_destination_none.yml"));
    assert_eq!(cfg.events_destination, String::from("file"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
#[should_panic]
fn test_new_config_linux_hashscanner_file() {
    Config::new("linux", Some("test/unit/config/linux/hashscanner_file_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
#[should_panic]
fn test_new_config_linux_events_file() {
    Config::new("linux", Some("test/unit/config/linux/events_file_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_destination_network() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_destination_network.yml"));
    assert_eq!(cfg.events_file, String::from("Not_defined"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_max_file_checksum() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_max_file_checksum.yml"));
    assert_eq!(cfg.events_max_file_checksum, 128);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_max_file_size() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_max_file_size.yml"));
    assert_eq!(cfg.events_max_file_size, 256);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_endpoint_insecure() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_endpoint_insecure.yml"));
    assert_eq!(cfg.insecure, true);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_endpoint_insecure_none() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_endpoint_insecure_none.yml"));
    assert_eq!(cfg.insecure, false);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_destination_network_address() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_destination_network_address.yml"));
    assert_eq!(cfg.endpoint_address, "0.0.0.0");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
#[should_panic]
fn test_new_config_linux_events_destination_network_address_none() {
    Config::new("linux", Some("test/unit/config/linux/events_destination_network_address_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_credentials_user() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_credentials_user.yml"));
    assert_eq!(cfg.endpoint_user, "test_user");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
#[should_panic]
fn test_new_config_linux_events_credentials_user_none() {
    Config::new("linux", Some("test/unit/config/linux/events_credentials_user_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_credentials_password() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_credentials_password.yml"));
    assert_eq!(cfg.endpoint_pass, "test_password");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_events_credentials_token() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/events_credentials_token.yml"));
    assert_eq!(cfg.endpoint_token, "test_token");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
#[should_panic]
fn test_new_config_linux_events_credentials_password_none() {
    Config::new("linux", Some("test/unit/config/linux/events_credentials_password_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_monitor_none() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/monitor_none.yml"));
    assert_eq!(cfg.monitor, Vec::new());
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_audit_none() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/audit_none.yml"));
    assert_eq!(cfg.audit, Vec::new());
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
#[should_panic]
fn test_new_config_linux_audit_and_monitor_none() {
    Config::new("linux", Some("test/unit/config/linux/audit_and_monitor_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_node_none() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/node_none.yml"));
    let machine_id = utils::get_machine_id();
    match machine_id.is_empty(){
        true => assert_eq!(cfg.node, utils::get_hostname()),
        false => assert_eq!(cfg.node, machine_id)
    }
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
#[should_panic]
fn test_new_config_linux_log_file_none() {
    Config::new("linux", Some("test/unit/config/linux/log_file_none.yml"));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_log_level_none() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/log_level_none.yml"));
    assert_eq!(cfg.log_level, "info");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux_log_max_file_size_none() {
    let cfg = Config::new("linux", Some("test/unit/config/linux/log_max_file_size_none.yml"));
    assert_eq!(cfg.log_max_file_size, 64);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_new_config_linux() {
    if utils::get_os() == "linux" {
        let cfg = Config::new("linux", None);
        assert_eq!(cfg.events_destination, String::from("file"));
        assert_eq!(cfg.endpoint_type, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_address, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_user, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_pass, String::from("Not_defined"));
        assert_eq!(cfg.endpoint_token, String::from("Not_defined"));
        assert_eq!(cfg.events_file, String::from("/var/lib/fim/events.json"));
        // monitor
        // audit
        assert_eq!(cfg.node, String::from("FIM"));
        assert_eq!(cfg.log_file, String::from("/var/log/fim/fim.log"));
        assert_eq!(cfg.log_level, String::from("info"));
        assert_eq!(cfg.log_max_file_size, 64);
        assert_eq!(cfg.system, String::from("linux"));
        assert_eq!(cfg.insecure, false);
        assert_eq!(cfg.hashscanner_file, String::from("/var/lib/fim/fim.db"));
        assert_eq!(cfg.hashscanner_enabled, true);
        assert_eq!(cfg.hashscanner_interval, 3600);
        assert_eq!(cfg.hashscanner_algorithm, ShaType::Sha256);
        assert_eq!(cfg.engine, String::from("monitor"));
    }
}

// ------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn test_new_config_macos() {
    let cfg = Config::new("macos", None);
    assert_eq!(cfg.events_destination, String::from("file"));
    assert_eq!(cfg.endpoint_type, String::from("Not_defined"));
    assert_eq!(cfg.endpoint_address, String::from("Not_defined"));
    assert_eq!(cfg.endpoint_user, String::from("Not_defined"));
    assert_eq!(cfg.endpoint_pass, String::from("Not_defined"));
    assert_eq!(cfg.endpoint_token, String::from("Not_defined"));
    assert_eq!(cfg.events_file, String::from("/var/lib/fim/events.json"));
    // monitor
    // audit
    assert_eq!(cfg.node, String::from("FIM"));
    assert_eq!(cfg.log_file, String::from("/var/log/fim/fim.log"));
    assert_eq!(cfg.log_level, String::from("info"));
    assert_eq!(cfg.log_max_file_size, 64);
    assert_eq!(cfg.system, String::from("macos"));
    assert_eq!(cfg.insecure, false);
    assert_eq!(cfg.hashscanner_file, String::from("/var/lib/fim/fim.db"));
    assert_eq!(cfg.hashscanner_enabled, true);
    assert_eq!(cfg.hashscanner_interval, 3600);
    assert_eq!(cfg.hashscanner_algorithm, ShaType::Sha256);
    assert_eq!(cfg.engine, String::from("monitor"));
}

// ------------------------------------------------------------------------

#[test]
fn test_get_level_filter_info() {
    let filter = LevelFilter::Info;
    assert_eq!(create_test_config("info", "").get_level_filter(), filter);
    assert_eq!(create_test_config("Info", "").get_level_filter(), filter);
    assert_eq!(create_test_config("INFO", "").get_level_filter(), filter);
    assert_eq!(create_test_config("I", "").get_level_filter(), filter);
    assert_eq!(create_test_config("i", "").get_level_filter(), filter);
}

// ------------------------------------------------------------------------

#[test]
fn test_get_level_filter_debug() {
    let filter = LevelFilter::Debug;
    assert_eq!(create_test_config("debug", "").get_level_filter(), filter);
    assert_eq!(create_test_config("Debug", "").get_level_filter(), filter);
    assert_eq!(create_test_config("DEBUG", "").get_level_filter(), filter);
    assert_eq!(create_test_config("D", "").get_level_filter(), filter);
    assert_eq!(create_test_config("d", "").get_level_filter(), filter);
}

// ------------------------------------------------------------------------

#[test]
fn test_get_level_filter_error() {
    let filter = LevelFilter::Error;
    assert_eq!(create_test_config("error", "").get_level_filter(), filter);
    assert_eq!(create_test_config("Error", "").get_level_filter(), filter);
    assert_eq!(create_test_config("ERROR", "").get_level_filter(), filter);
    assert_eq!(create_test_config("E", "").get_level_filter(), filter);
    assert_eq!(create_test_config("e", "").get_level_filter(), filter);
}

// ------------------------------------------------------------------------

#[test]
fn test_get_level_filter_warning() {
    let filter = LevelFilter::Warn;
    assert_eq!(create_test_config("warning", "").get_level_filter(), filter);
    assert_eq!(create_test_config("Warning", "").get_level_filter(), filter);
    assert_eq!(create_test_config("WARNING", "").get_level_filter(), filter);
    assert_eq!(create_test_config("W", "").get_level_filter(), filter);
    assert_eq!(create_test_config("w", "").get_level_filter(), filter);
    assert_eq!(create_test_config("warn", "").get_level_filter(), filter);
    assert_eq!(create_test_config("Warn", "").get_level_filter(), filter);
    assert_eq!(create_test_config("WARN", "").get_level_filter(), filter);
}

// ------------------------------------------------------------------------

#[test]
fn test_get_level_filter_bad() {
    let filter = LevelFilter::Info;
    assert_eq!(create_test_config("bad", "").get_level_filter(), filter);
    assert_eq!(create_test_config("BAD", "").get_level_filter(), filter);
    assert_eq!(create_test_config("B", "").get_level_filter(), filter);
    assert_eq!(create_test_config("b", "").get_level_filter(), filter);
    assert_eq!(create_test_config("test", "").get_level_filter(), filter);
    assert_eq!(create_test_config("", "").get_level_filter(), filter);
    assert_eq!(create_test_config("_", "").get_level_filter(), filter);
    assert_eq!(create_test_config("?", "").get_level_filter(), filter);
    assert_eq!(create_test_config("=", "").get_level_filter(), filter);
    assert_eq!(create_test_config("/", "").get_level_filter(), filter);
    assert_eq!(create_test_config(".", "").get_level_filter(), filter);
    assert_eq!(create_test_config(":", "").get_level_filter(), filter);
    assert_eq!(create_test_config(";", "").get_level_filter(), filter);
    assert_eq!(create_test_config("!", "").get_level_filter(), filter);
    assert_eq!(create_test_config("''", "").get_level_filter(), filter);
    assert_eq!(create_test_config("[]", "").get_level_filter(), filter);
}

// ------------------------------------------------------------------------

#[test]
fn test_get_events_destination() {
    assert_eq!(create_test_config("info", "both").get_events_destination(), String::from(BOTH_MODE));
    assert_eq!(create_test_config("info", "network").get_events_destination(), String::from(NETWORK_MODE));
    assert_eq!(create_test_config("info", "file").get_events_destination(), String::from(FILE_MODE));
    assert_eq!(create_test_config("info", "").get_events_destination(), String::from(FILE_MODE));
    assert_eq!(create_test_config("info", "?").get_events_destination(), String::from(FILE_MODE));
}

// ------------------------------------------------------------------------

#[test]
fn test_read_config_unix() {
    let yaml = read_config(String::from("config/linux/config.yml"));

    assert_eq!(yaml[0]["node"].as_str().unwrap(), "FIM");
    assert_eq!(yaml[0]["events"]["destination"].as_str().unwrap(), "file");
    assert_eq!(yaml[0]["events"]["file"].as_str().unwrap(), "/var/lib/fim/events.json");

    assert_eq!(yaml[0]["monitor"][0]["path"].as_str().unwrap(), "/bin/");
    assert_eq!(yaml[0]["monitor"][1]["path"].as_str().unwrap(), "/usr/bin/");
    assert_eq!(yaml[0]["monitor"][1]["labels"][0].as_str().unwrap(), "usr/bin");
    assert_eq!(yaml[0]["monitor"][1]["labels"][1].as_str().unwrap(), "linux");
    assert_eq!(yaml[0]["monitor"][2]["path"].as_str().unwrap(), "/etc");
    assert_eq!(yaml[0]["monitor"][2]["labels"][0].as_str().unwrap(), "etc");
    assert_eq!(yaml[0]["monitor"][2]["labels"][1].as_str().unwrap(), "linux");

    assert_eq!(yaml[0]["log"]["file"].as_str().unwrap(), "/var/log/fim/fim.log");
    assert_eq!(yaml[0]["log"]["level"].as_str().unwrap(), "info");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_read_config_windows() {
    let dir = utils::get_current_dir();
    let disk = dir.get(0..1).unwrap();
    let yaml = read_config(String::from("config/windows/config.yml"));

    assert_eq!(yaml[0]["node"].as_str().unwrap(), "FIM");
    assert_eq!(yaml[0]["events"]["destination"].as_str().unwrap(), "file");
    assert_eq!(yaml[0]["events"]["file"].as_str().unwrap(), format!("{}:\\ProgramData\\fim\\events.json", disk) );

    assert_eq!(yaml[0]["monitor"][0]["path"].as_str().unwrap(), "C:\\Program Files\\");
    assert_eq!(yaml[0]["monitor"][0]["labels"][0].as_str().unwrap(), "Program Files");
    assert_eq!(yaml[0]["monitor"][0]["labels"][1].as_str().unwrap(), "windows");
    assert_eq!(yaml[0]["monitor"][1]["path"].as_str().unwrap(), "C:\\Users\\" );
    assert_eq!(yaml[0]["monitor"][1]["labels"][0].as_str().unwrap(), "Users");
    assert_eq!(yaml[0]["monitor"][1]["labels"][1].as_str().unwrap(), "windows");

    assert_eq!(yaml[0]["log"]["file"].as_str().unwrap(), format!("{}:\\ProgramData\\fim\\fim.log", disk) );
    assert_eq!(yaml[0]["log"]["level"].as_str().unwrap(), "info");
}

// ------------------------------------------------------------------------

#[test]
#[should_panic(expected = "NotFound")]
fn test_read_config_panic() {
    read_config(String::from("NotFound"));
}

// ------------------------------------------------------------------------

#[test]
#[should_panic(expected = "ScanError")]
fn test_read_config_panic_not_config() {
    read_config(String::from("README.md"));
}

// ------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
#[test]
fn test_get_config_path_unix() {
    let current_dir = utils::get_current_dir();
    let default_path_linux = format!("{}/config/linux/config.yml", current_dir);
    let default_path_macos = format!("{}/config/macos/config.yml", current_dir);
    assert_eq!(get_config_path("linux"), default_path_linux);
    assert_eq!(get_config_path("macos"), default_path_macos);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_get_config_path_windows() {
    let current_dir = utils::get_current_dir();
    let default_path_windows = format!("{}\\config\\windows\\config.yml", current_dir);
    assert_eq!(get_config_path("windows"), default_path_windows);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_path_in_monitor() {
    let cfg = Config::new(&utils::get_os(), None);
    assert!(cfg.path_in("/bin/", "", cfg.monitor.clone()));
    assert!(cfg.path_in("/bin", "", cfg.monitor.clone()));
    assert!(cfg.path_in("/bin/test", "", cfg.monitor.clone()));
    assert!(!cfg.path_in("/test", "", cfg.monitor.clone()));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_path_in_audit() {
    let cfg = Config::new(&utils::get_os(), Some("test/unit/config/linux/audit_allowed.yml"));
    assert!(cfg.path_in("/tmp", "", cfg.audit.clone()));
    assert!(cfg.path_in("/tmp/", "", cfg.audit.clone()));
    assert!(cfg.path_in("./", "/tmp", cfg.audit.clone()));
    assert!(cfg.path_in("./", "/tmp/", cfg.audit.clone()));
    assert!(!cfg.path_in("./", "/test", cfg.audit.clone()));
    assert!(cfg.path_in("./", "/tmp/test", cfg.audit.clone()));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_get_index_monitor() {
    let cfg = Config::new(&utils::get_os(), None);
    assert_eq!(cfg.get_index("/bin/", "", cfg.monitor.clone()), 0);
    assert_eq!(cfg.get_index("./", "/bin", cfg.monitor.clone()), 0);
    assert_eq!(cfg.get_index("/usr/bin/", "", cfg.monitor.clone()), 1);
    assert_eq!(cfg.get_index("/etc", "", cfg.monitor.clone()), 2);
    assert_eq!(cfg.get_index("/test", "", cfg.monitor.clone()), usize::MAX);
    assert_eq!(cfg.get_index("./", "/test", cfg.monitor.clone()), usize::MAX);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_get_index_audit() {
    let cfg = Config::new(&utils::get_os(), Some("test/unit/config/linux/audit_allowed.yml"));
    assert_eq!(cfg.get_index("/tmp", "", cfg.audit.clone()), 0);
    assert_eq!(cfg.get_index("/test", "", cfg.audit.clone()), usize::MAX);
    assert_eq!(cfg.get_index("./", "/tmp", cfg.audit.clone()), 0);
    assert_eq!(cfg.get_index("./", "/test", cfg.audit.clone()), usize::MAX);
}

// ------------------------------------------------------------------------

#[test]
fn test_get_labels() {
    let cfg = Config::new(&utils::get_os(), None);
    if utils::get_os() == "windows" {
        let labels = cfg.get_labels(0, cfg.monitor.clone());
        assert_eq!(labels[0], "Program Files");
        assert_eq!(labels[1], "windows");
    }else if utils::get_os() == "macos"{
        let labels = cfg.get_labels(2, cfg.monitor.clone());
        assert_eq!(labels[0], "usr/bin");
        assert_eq!(labels[1], "macos");
    }else{
        let labels = cfg.get_labels(1, cfg.monitor.clone());
        assert_eq!(labels[0], "usr/bin");
        assert_eq!(labels[1], "linux");
    }
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_match_ignore_monitor() {
    let cfg = Config::new(&utils::get_os(), None);
    assert!(cfg.match_ignore(3, "file.swp", cfg.monitor.clone()));
    assert!(!cfg.match_ignore(0, "file.txt", cfg.monitor.clone()));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_match_ignore_audit() {
    let cfg = Config::new(&utils::get_os(), Some("test/unit/config/linux/audit_exclude.yml"));
    assert!(cfg.match_ignore(0, "file.swp", cfg.audit.clone()));
    assert!(!cfg.match_ignore(0, "file.txt", cfg.audit.clone()));
}

// ------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_match_exclude() {
    let cfg = Config::new(&utils::get_os(), Some("test/unit/config/linux/audit_exclude.yml"));
    assert!(cfg.match_exclude(0, "/tmp/test", cfg.audit.clone()));
    assert!(!cfg.match_exclude(0, "/tmp/another", cfg.audit.clone()));
}

// ------------------------------------------------------------------------

#[test]
fn test_match_allowed() {
    if utils::get_os() == "windows" {
        let cfg = Config::new(&utils::get_os(), Some("test/unit/config/windows/monitor_allowed.yml"));
        assert!(!cfg.match_allowed(1, "file.swp", cfg.monitor.clone()));
        assert!(cfg.match_allowed(1, "file.txt", cfg.monitor.clone()));
    } else if utils::get_os() == "linux" {
        let cfg = Config::new(&utils::get_os(), Some("test/unit/config/linux/monitor_allowed.yml"));
        assert!(!cfg.match_allowed(2, "file.swp", cfg.monitor.clone()));
        assert!(cfg.match_allowed(2, "file.txt", cfg.monitor.clone()));

        let cfg_audit = Config::new(&utils::get_os(), Some("test/unit/config/linux/audit_allowed.yml"));
        assert!(!cfg_audit.match_allowed(0, "file.swp", cfg_audit.audit.clone()));
        assert!(cfg_audit.match_allowed(0, "file.txt", cfg_audit.audit.clone()));
    }
}

// ------------------------------------------------------------------------

#[test]
fn test_get_integrations() {
    let os = utils::get_os();
    let cfg = Config::new(&os,
        Some(format!("test/unit/config/{}/monitor_integration.yml", os)
            .as_str())
    );
    if os == "windows" {
        let integrations = cfg.get_integrations(2, cfg.monitor.clone());
        assert_eq!(integrations.len(), 1);
    }else if os == "macos"{
        let integrations = cfg.get_integrations(2, cfg.monitor.clone());
        assert_eq!(integrations.len(), 1);
    }else{
        let integrations_monitor = cfg.get_integrations(2, cfg.monitor.clone());
        assert_eq!(integrations_monitor.len(), 1);

        // Not implemented yet
        //let integrations_audit = cfg.get_integrations(2, cfg.audit.clone());
        //assert_eq!(integrations_audit.len(), 1);
    }
}

// ------------------------------------------------------------------------

#[test]
fn test_new_config_watcher() {
    let cfg = Config::new("windows", Some("test/unit/config/windows/events_watcher.yml"));
    assert_eq!(cfg.events_watcher, "Poll");
}

// ------------------------------------------------------------------------

#[test]
fn test_checksum_algorithm() {
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/checksum_algorithm/sha224.yml")).checksum_algorithm,
        ShaType::Sha224
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/checksum_algorithm/sha256.yml")).checksum_algorithm,
        ShaType::Sha256
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/checksum_algorithm/sha384.yml")).checksum_algorithm,
        ShaType::Sha384
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/checksum_algorithm/sha512.yml")).checksum_algorithm,
        ShaType::Sha512
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/checksum_algorithm/keccak224.yml")).checksum_algorithm,
        ShaType::Keccak224
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/checksum_algorithm/keccak256.yml")).checksum_algorithm,
        ShaType::Keccak256
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/checksum_algorithm/keccak384.yml")).checksum_algorithm,
        ShaType::Keccak384
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/checksum_algorithm/keccak512.yml")).checksum_algorithm,
        ShaType::Keccak512
    );
}

// ------------------------------------------------------------------------

#[test]
fn test_hashscanner_algorithm() {
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/hashscanner_algorithm/sha224.yml")).hashscanner_algorithm,
        ShaType::Sha224
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/hashscanner_algorithm/sha256.yml")).hashscanner_algorithm,
        ShaType::Sha256
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/hashscanner_algorithm/sha384.yml")).hashscanner_algorithm,
        ShaType::Sha384
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/hashscanner_algorithm/sha512.yml")).hashscanner_algorithm,
        ShaType::Sha512
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/hashscanner_algorithm/keccak224.yml")).hashscanner_algorithm,
        ShaType::Keccak224
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/hashscanner_algorithm/keccak256.yml")).hashscanner_algorithm,
        ShaType::Keccak256
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/hashscanner_algorithm/keccak384.yml")).hashscanner_algorithm,
        ShaType::Keccak384
    );
    assert_eq!(
        Config::new("linux", 
            Some("test/unit/config/linux/hashscanner_algorithm/keccak512.yml")).hashscanner_algorithm,
        ShaType::Keccak512
    );
}