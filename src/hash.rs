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

#[derive(Debug)]
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

#[cfg(test)]
mod test;

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
                    info!("File size is above limit. Getting file '{}' header/partial checksum.", filename);
                    get_partial_checksum(filename, algorithm)
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

/// Produce partial checksum of file, it read the first MB of the file
/// This method is targeted for big files where you cannot get checksum in a reasonable time.
pub fn get_partial_checksum(filename: String, algorithm: ShaType) -> String {
    let limit: usize = 1024 * 1024; // 1MB
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
                let metadata = file.metadata().unwrap();
                let mut reader = BufReader::with_capacity(limit, file);

                let length = {
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
                let hash_data: Vec<u8> = vec![metadata.len() as u8];
                hasher.update(&hash_data);
                encode(hasher.finalize())
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
