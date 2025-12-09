use super::*;
use tokio_test::block_on;

#[cfg(not(target_os = "windows"))]
#[test]
fn test_get_ruleset_path_unix() {
    let current_dir = utils::get_current_dir();
    let default_path_linux = format!("{}/config/linux/rules.yml", current_dir);
    let default_path_macos = format!("{}/config/macos/rules.yml", current_dir);
    assert_eq!(get_ruleset_path("linux"), default_path_linux);
    assert_eq!(get_ruleset_path("macos"), default_path_macos);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_get_ruleset_path_windows() {
    let current_dir = utils::get_current_dir();
    let default_path_windows = format!("{}\\config\\windows\\rules.yml", current_dir);
    assert_eq!(get_ruleset_path("windows"), default_path_windows);
}

// ------------------------------------------------------------------------

#[test]
fn test_read_ruleset_unix() {
    let yaml = read_ruleset(String::from("config/linux/rules.yml"));

    assert_eq!(yaml[0]["rules"][0]["id"].as_i64().unwrap(), 1);
    assert_eq!(yaml[0]["rules"][0]["path"].as_str().unwrap(), "/etc");
    assert_eq!(yaml[0]["rules"][0]["rule"].as_str().unwrap(), "\\.sh$");
    assert_eq!(yaml[0]["rules"][0]["message"].as_str().unwrap(), "Shell script present in /etc folder.");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_read_ruleset_windows() {
    let yaml = read_ruleset(String::from("config/windows/rules.yml"));

    assert_eq!(yaml[0]["rules"][0]["id"].as_i64().unwrap(), 1);
    assert_eq!(yaml[0]["rules"][0]["path"].as_str().unwrap(), "C:\\");
    assert_eq!(yaml[0]["rules"][0]["rule"].as_str().unwrap(), "\\.ps1$");
    assert_eq!(yaml[0]["rules"][0]["message"].as_str().unwrap(), "Powershell script present in root directory.");
}

// ------------------------------------------------------------------------

#[test]
#[should_panic(expected = "NotFound")]
fn test_read_ruleset_panic() {
    read_ruleset(String::from("NotFound"));
}

// ------------------------------------------------------------------------

#[test]
#[should_panic(expected = "ScanError")]
fn test_read_ruleset_panic_not_config() {
    read_ruleset(String::from("README.md"));
}

// ------------------------------------------------------------------------

#[test]
fn test_sanitize() {
    assert_eq!("test", sanitize("test"));
    assert_eq!("test", sanitize("t\"est"));
    assert_eq!("C\\test", sanitize("C:\\test"));
    assert_eq!("test", sanitize("t\'est"));
    assert_eq!("test", sanitize("t/est"));
    assert_eq!("test", sanitize("t|est"));
    assert_eq!("test", sanitize("t>est"));
    assert_eq!("test", sanitize("t<est"));
    assert_eq!("test", sanitize("t?est"));
    assert_eq!("\\.php$", sanitize("\\.php$"));
    assert_ne!("\\.php", sanitize("\\.php$"));        
}

// ------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
#[test]
fn test_match_rule_unix() {
    let cfg = Config::new(&utils::get_os(), None);
    let ruleset = Ruleset::new(&utils::get_os(), None); 

    let (result, id) = block_on(ruleset.match_rule(cfg.clone(), PathBuf::from("/etc/file.sh"), String::from("0000")));
    assert_eq!(id, 1);
    assert_eq!(result, true);

    let (result, id) = block_on(ruleset.match_rule(cfg, PathBuf::from("/etc/file.php"), String::from("0000")));
    assert_eq!(id, usize::MAX);
    assert_eq!(result, false);
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_match_rule_windows() {
    let cfg = Config::new(&utils::get_os(), None);
    let ruleset = Ruleset::new(&utils::get_os(), None); 

    let (result, id) = block_on(ruleset.match_rule(cfg.clone(), PathBuf::from("C:\\file.ps1"), String::from("0000")));
    assert_eq!(id, 1);
    assert_eq!(result, true);

    let (result, id) = block_on(ruleset.match_rule(cfg, PathBuf::from("C:\\file.php"), String::from("0000")));
    assert_eq!(id, usize::MAX);
    assert_eq!(result, false);
}

// ------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
#[test]
fn test_new_unix() {
    let ruleset = Ruleset::new(&utils::get_os(), None);
    let element = ruleset.rules.get(&1usize).unwrap();

    assert_eq!(element.get("path").unwrap(), "/etc");
    assert_eq!(element.get("rule").unwrap(), "\\.sh$");
    assert_eq!(element.get("message").unwrap(), "Shell script present in /etc folder.");
}

// ------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
fn test_new_windows() {
    let ruleset = Ruleset::new(&utils::get_os(), None);
    let element = ruleset.rules.get(&1usize).unwrap();
    assert_eq!(element.get("path").unwrap(), "C:\\");
    assert_eq!(element.get("rule").unwrap(), "\\.ps1$");
    assert_eq!(element.get("message").unwrap(), "Powershell script present in root directory.");
}

// ------------------------------------------------------------------------

#[test]
fn test_clone() {
    let ruleset = Ruleset::new(&utils::get_os(), None);
    let cloned = ruleset.clone();
    let ruleset_values = ruleset.rules.get(&1usize).unwrap();
    let cloned_values = cloned.rules.get(&1usize).unwrap();

    assert_eq!(ruleset.rules.keys().next(), cloned.rules.keys().next());
    assert_eq!(ruleset_values, cloned_values);
    assert_eq!(ruleset_values.get("path").unwrap(), cloned_values.get("path").unwrap());
    assert_eq!(ruleset_values.get("rule").unwrap(), cloned_values.get("rule").unwrap());
    assert_eq!(ruleset_values.get("message").unwrap(), cloned_values.get("message").unwrap());
}