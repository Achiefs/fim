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
            return Ok(hash)
        },
        Err(e) => return Err(e),
    }
}