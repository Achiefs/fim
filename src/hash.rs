// Copyright (C) 2021, Achiefs.

// Constants definitions
const READ_CAPACITY: usize = 1024 * 1024 * 8; // Read file in chunks of 8MB

// To get file checksums
use hex::{encode, decode};
use sha3::{Sha3_512, Digest};
// To log the program process
use log::*;
// To manage hex to ascii conversion
use std::str;
// To manage files
use std::fs::File;
use std::path::Path;
// To read file content
use std::io::{BufRead, BufReader};

// To calculate file content hash in sha512 format (SHA3 implementation)
pub fn get_checksum(filename: String, read_limit: usize) -> String {
    let mut hasher = Sha3_512::new();
    let mut length = 1;
    let mut iteration = 0;
    let mut data_read = 0;
    
    if Path::new(&filename).is_file() { 
        debug!("Getting hash of file: {}", filename);
        match File::open(filename.clone()){
            Ok(file) => {
                let mut reader = BufReader::with_capacity(READ_CAPACITY, file);

                while length > 0 && data_read <= read_limit {
                    if iteration == 2 {
                        info!("Big file detected, the hash will take a while");
                    }
                    
                    length = {
                        let buffer = reader.fill_buf().unwrap();
                        hasher.update(buffer);
                        buffer.len()
                    };
                    reader.consume(length);
                    data_read += length / (1024 * 1024);
                    iteration += 1;
                };
                if data_read > read_limit {
                    info!("File '{}' checksum skipped. File size is above limit", filename);
                    String::from("UNKNOWN")
                }else{
                    encode(hasher.finalize())
                }
            },
            Err(e) => {
                debug!("Cannot open file to get checksum, error: {:?}", e);
                String::from("UNKNOWN")
            }
        }
    }else{
        debug!("Cannot produce checksum of a directory");
        String::from("UNKNOWN")
    }
}

// ----------------------------------------------------------------------------

pub fn hex_to_ascii(hex: String) -> String {
    debug!("HEX: {}", hex);
    let bytes = match decode(hex){
        Ok(d) => d,
        Err(e) => {
            debug!("Could not decode HEX data. Error: {}", e);
            Vec::new()
        }
    };
    String::from(str::from_utf8(&bytes).unwrap())
        .replace('\u{0000}', " ")
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    const MAX_FILE_READ: usize = 64;

    use super::*;
    use std::fs;
    use std::fs::File;
    use std::io::prelude::*;

    fn create_test_file(filename: String) {
        File::create(filename).unwrap().write_all(b"This is a test!").unwrap();
    }

    fn remove_test_file(filename: String) {
        fs::remove_file(filename).unwrap()
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_checksum_file() {
        let filename = String::from("test_get_checksum_file");
        create_test_file(filename.clone());
        assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ), String::from("46512636eeeb22dee0d60f3aba6473b1fb3258dc0c9ed6fbdbf26bed06df796bc70d4c1f6d50ca977b45f35b494e4bd9fb34e55a1576d6d9a3b5e1ab059953ee"));
        remove_test_file(filename.clone());
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_checksum_not_exists() {
        assert_ne!(get_checksum(String::from("not_exists"), MAX_FILE_READ), String::from("This is a test"));
        assert_eq!(get_checksum(String::from("not_exists"), MAX_FILE_READ), String::from("UNKNOWN"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_checksum_bad() {
        let filename = String::from("test_get_checksum_bad");
        create_test_file(filename.clone());
        assert_ne!(get_checksum(filename.clone(), MAX_FILE_READ), String::from("This is a test"));
        remove_test_file(filename.clone());
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_hex_to_ascii() {
        let ascii = hex_to_ascii(String::from("746F756368002F746D702F746573742F66696C65342E747874"));
        assert_eq!(ascii, "touch /tmp/test/file4.txt");
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_hex_to_ascii_bad() {
        assert_eq!(hex_to_ascii(String::from("ABC")), "");
    }

}
