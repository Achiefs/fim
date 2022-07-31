// Copyright (C) 2021, Achiefs.

// To manage unique event identifier
use uuid::Uuid;
// To get own process ID
use std::process;
// To get Operating system
use std::env;
// To use files IO operations.
use std::fs::File;
use std::io::Read;
// To get config constants
use crate::config;

// ----------------------------------------------------------------------------

pub fn pop(value: &str) -> &str {
    let mut chars = value.chars();
    chars.next_back();
    chars.as_str()
}

// ----------------------------------------------------------------------------

pub fn get_hostname() -> String {
    gethostname::gethostname().into_string().unwrap()
}

// ----------------------------------------------------------------------------

pub fn get_uuid() -> String {
    format!("{}", Uuid::new_v4())
}

// ----------------------------------------------------------------------------

pub fn get_pid() -> u32 {
    process::id()
}

// ----------------------------------------------------------------------------

pub fn get_os() -> String {
    env::consts::OS.to_string()
}

// ----------------------------------------------------------------------------

pub fn read_file(path: String) -> String {
    let mut file = File::open(path.clone()).expect(
        format!("Unable to open file {}", path.clone()).as_str()
    );
    let mut contents = String::new();

    file.read_to_string(&mut contents).expect(
        format!("Unable to read file {}", path.clone()).as_str()
    );
    contents
}

// ----------------------------------------------------------------------------

// Only supported in Linux
pub fn get_machine_id() -> String {
    read_file(String::from(config::MACHINE_ID_PATH))
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pop() {
        assert_eq!(pop("test-"), "test");
        assert_eq!(pop("dir/"), "dir");
        assert_eq!(pop("dir@"), "dir");
    }

}