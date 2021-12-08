// To get file checksums
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use std::result::Result;
use std::io::Error;

// To calculate file content hash in sha512 format (SHA3 implementation)
pub fn get_checksum(file: &str) -> Result<String, Error> {
    let mut hasher = Sha3::sha3_512();
    match std::fs::read_to_string(file) {
        Ok(data) => {
            hasher.input_str(&data);
            return Ok(hasher.result_str())
        },
        Err(e) => return Err(e),
    }
}