// Copyright (C) 2021, Achiefs.

// Constants definitions
const READ_CAPACITY: usize = 1024 * 1024 * 8; // Read file in chunks of 8MB

// To get file checksums
use hex::{encode, decode};
//use sha3::{Digest, Sha3_256, Sha3_512, Sha3_224};
use sha3::{Digest, digest::DynDigest,
    Sha3_224, Sha3_256, Sha3_384, Sha3_512,
    Keccak224, Keccak256, Keccak384, Keccak512};
// To log the program process
use log::*;
// To manage hex to ascii conversion
use std::str;
// To manage files
use std::fs::File;
use std::path::Path;
// To read file content
use std::io::{BufRead, BufReader};

// ----------------------------------------------------------------------------

#[derive(PartialEq)]
#[derive(Clone)]
pub enum ShaType {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512
}

// To calculate file content hash
pub fn get_checksum(filename: String, read_limit: usize, algorithm: ShaType) -> String {
    let mut length = 1;
    let mut iteration = 0;
    let mut data_read = 0;
    let limit: usize = read_limit * 1024 * 1024;
    let mut hasher: Box<dyn DynDigest> = match algorithm {
        ShaType::Sha224 => Box::new(Sha3_224::new()),
        ShaType::Sha256 => Box::new(Sha3_256::new()),
        ShaType::Sha384 => Box::new(Sha3_384::new()),
        ShaType::Sha512 => Box::new(Sha3_512::new()),
        ShaType::Keccak224 => Box::new(Keccak224::new()),
        ShaType::Keccak256 => Box::new(Keccak256::new()),
        ShaType::Keccak384 => Box::new(Keccak384::new()),
        ShaType::Keccak512 => Box::new(Keccak512::new()),
    };
    
    if Path::new(&filename).is_file() { 
        debug!("Getting hash of file: {}", filename);
        match File::open(filename.clone()){
            Ok(file) => {
                let size: usize = file.metadata().unwrap().len() as usize;
                let mut reader = BufReader::with_capacity(READ_CAPACITY, file);

                if size > limit {
                    info!("File '{}' checksum skipped. File size is above limit.", filename);
                    String::from("UNKNOWN")
                }else{
                    while length > 0 && data_read <= limit {
                        if iteration == 2 {
                            debug!("Big file detected, the hash will take a while");
                        }
                        
                        length = {
                            match reader.fill_buf(){
                                Ok(buffer) =>{
                                    hasher.update(buffer);
                                    buffer.len()
                                },
                                Err(e) => {
                                    debug!("Cannot read file. Checksum set to 'UNKNOWN', error: {}", e);
                                    0
                                }
                            }
                        };
                        reader.consume(length);
                        data_read += length;
                        iteration += 1;
                    };
                    encode(hasher.finalize())
                }
            },
            Err(e) => {
                debug!("Cannot open file to get checksum, error: {:?}", e);
                String::from("UNKNOWN")
            }
        }
    }else{
        debug!("Cannot produce checksum of a removed file or directory.");
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
    use sha3::{Digest, Sha3_512};

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
        assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ, Sha3_512::new()), String::from("46512636eeeb22dee0d60f3aba6473b1fb3258dc0c9ed6fbdbf26bed06df796bc70d4c1f6d50ca977b45f35b494e4bd9fb34e55a1576d6d9a3b5e1ab059953ee"));
        remove_test_file(filename.clone());
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_checksum_not_exists() {
        assert_ne!(get_checksum(String::from("not_exists"), MAX_FILE_READ, Sha3_512::new()), String::from("This is a test"));
        assert_eq!(get_checksum(String::from("not_exists"), MAX_FILE_READ, Sha3_512::new()), String::from("UNKNOWN"));
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_get_checksum_bad() {
        let filename = String::from("test_get_checksum_bad");
        create_test_file(filename.clone());
        assert_ne!(get_checksum(filename.clone(), MAX_FILE_READ, Sha3_512::new()), String::from("This is a test"));
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
