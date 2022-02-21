// Copyright (C) 2021, Achiefs.

// To get file checksums
use hex::encode;
use sha3::{Sha3_512, Digest};
use std::result::Result;
use std::io::Error;

// To calculate file content hash in sha512 format (SHA3 implementation)
pub fn get_checksum(file: &str) -> Result<String, Error> {
    let mut hasher = Sha3_512::new();
    match std::fs::read_to_string(file) {
        Ok(data) => {
            hasher.update(&data);
            let result = hasher.finalize().to_vec();
            let hash = encode(result);
            Ok(hash)
        },
        Err(e) => Err(e),
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::fs::File;
    use std::io::prelude::*;

    fn create_test_file(filename: &str) {
        File::create(filename).unwrap().write_all(b"This is a test!").unwrap();
    }

    fn remove_test_file(filename: &str) {
        fs::remove_file(filename).unwrap()
    }

    #[test]
    fn test_get_checksum_file() {
        let filename = "test_get_checksum_file";
        create_test_file(filename);
        assert_eq!(get_checksum(filename).unwrap(), "46512636eeeb22dee0d60f3aba6473b1fb3258dc0c9ed6fbdbf26bed06df796bc70d4c1f6d50ca977b45f35b494e4bd9fb34e55a1576d6d9a3b5e1ab059953ee");
        remove_test_file(filename);
    }

    #[test]
    #[should_panic(expected = "NotFound")]
    fn test_get_checksum_panic() {
        assert_ne!(get_checksum("not_exists").unwrap(), "This is a test");
    }

    #[test]
    fn test_get_checksum_bad() {
        let filename = "test_get_checksum_bad";
        create_test_file(filename);
        assert_ne!(get_checksum(filename).unwrap(), "This is a test");
        remove_test_file(filename);
    }
}
