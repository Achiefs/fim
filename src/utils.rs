// Copyright (C) 2021, Achiefs.

// To manage unique event identifier
use uuid::Uuid;

pub fn pop(value: &str) -> &str {
    let mut chars = value.chars();
    chars.next_back();
    chars.as_str()
}

pub fn get_hostname() -> String {
    gethostname::gethostname().into_string().unwrap()
}

pub fn get_uuid() -> String {
    format!("{}", Uuid::new_v4())
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