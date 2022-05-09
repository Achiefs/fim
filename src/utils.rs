// Copyright (C) 2021, Achiefs.

pub fn pop(value: &str) -> &str {
    let mut chars = value.chars();
    chars.next_back();
    chars.as_str()
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