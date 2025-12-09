use super::*;
use tokio_test::block_on;

use crate::utils::get_os;

// ------------------------------------------------------------------------

#[test]
fn test_push_template() {
    let cfg = Config::new(&get_os(), None);
    fs::create_dir_all(Path::new(&cfg.log_file).parent().unwrap().to_str().unwrap()).unwrap();
    block_on(push_template("file", cfg.clone()));
    block_on(push_template("network", cfg.clone()));
}

// ------------------------------------------------------------------------

#[test]
fn test_setup_events() {
    let cfg = Config::new(&get_os(), None);
    fs::create_dir_all(Path::new(&cfg.log_file).parent().unwrap().to_str().unwrap()).unwrap();
    setup_events("file", cfg.clone());
    setup_events("network", cfg.clone());
}