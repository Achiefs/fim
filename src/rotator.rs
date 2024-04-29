// Copyright (C) 2023, Achiefs.

use std::fs::{metadata, File, copy, read_to_string, remove_file, create_dir};
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use std::thread;
use log::{debug, error, info};
use std::sync::Mutex;

use crate::appconfig::*;
use crate::utils;

// ----------------------------------------------------------------------------

// Compress given file into zip.
#[cfg(windows)]
fn compress_zip_file(filepath: &str) -> Result<String, String> {
    use zip::write::FileOptions;
    use std::io::{BufReader, BufRead};
    let filename = Path::new(filepath).file_name().unwrap().to_str().unwrap();
    let zipfilename = format!("{}.zip", filepath);
    let path = Path::new(&zipfilename);
    let zipfile = File::create(path).unwrap();

    let mut zip = zip::ZipWriter::new(zipfile);
    match zip.start_file(filename, FileOptions::default()){
        Ok(_v) => {
            let file = File::open(filepath).unwrap();
            let reader = BufReader::new(file);

            let mut counter: u64 = 0;
            let mut broken = false;
            for line in reader.lines() {
                // Sleep during compression to avoid increase CPU load.
                if counter == 4096 {
                    thread::sleep(Duration::from_millis(500));
                    counter = 0;
                }
                match zip.write_all(line.unwrap().as_bytes()){
                    Ok(_v) => debug!("Line written into zip file from rotated file."),
                    Err(e) => {
                        error!("Error writting line to zip file, error: {}", e);
                        broken = true;
                        break;
                    }
                };
                counter += 1;
            }
            if ! broken {
                match zip.finish(){
                    Ok(_v) => debug!("File compressed successfully, result: {}", zipfilename),
                    Err(e) => error!("Error compressing rotated file, error:{}", e)
                };
            }
            Ok(format!("File {} compressed successfully.", filename))
        },
        Err(e) => {
            error!("Cannot create file inside zip file, error: {}", e);
            Err(format!("{}", e))
        }
    }
}

// ----------------------------------------------------------------------------

// Compress given file into tar.gz.
#[cfg(not(windows))]
fn compress_tgz_file(filepath: &str) -> Result<String, String> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let filename = Path::new(filepath).file_name().unwrap().to_str().unwrap();
    let parent_path = Path::new(filepath).parent().unwrap();
    let tarname = format!("{}/{}.tar.gz", parent_path.to_str().unwrap(), filename);
    let tgz = File::create(tarname).unwrap();
    let enc = GzEncoder::new(tgz, Compression::default());
    let mut tar = tar::Builder::new(enc);
    let mut file = File::open(filepath).unwrap();
    
    match tar.append_file(filename, &mut file){
        Ok(()) => Ok(format!("File {} compressed successfully.", filename)),
        Err(e) => {
            error!("Cannot not create tar.gz archive, error: {}", e);
            Err(format!("{}", e))
        }
    }
}

// ----------------------------------------------------------------------------

fn get_iteration(filepath: &str) -> u32{
    Path::new(filepath).read_dir().expect("read_dir call failed").count() as u32
}

// ----------------------------------------------------------------------------

fn rotate_file(filepath: &str, iteration: u32, lock: Mutex<bool>){
    info!("Rotating {} file...", filepath);
    *lock.lock().unwrap() = true;

    thread::sleep(Duration::new(15, 0));
    let path = Path::new(filepath);
    let mut parent_path = path.parent().unwrap().to_path_buf();
    parent_path.push(Path::new(path.file_name().unwrap()));

    let file_rotated = format!("{}.{}",
        parent_path.to_str().unwrap(), iteration);
    
    match copy(filepath, file_rotated.clone()){
        Ok(_v) => {
            debug!("File copied successfully.");
            match File::create(filepath){
                Ok(truncated_file) => {
                    debug!("File truncated successfully.");
                    let tmp_file = format!("{}.tmp", filepath);
                    let tmp_path = Path::new(&tmp_file);
                    if tmp_path.exists(){
                        let data = match read_to_string(tmp_file.clone()){
                            Ok(read_data) => read_data,
                            Err(_e) => {
                                debug!("No temporal data to copy.");
                                String::new()
                            }
                        };
                        match write!(&truncated_file, "{}", data){
                            Ok(_v) => debug!("Temporal file data written into destination file."),
                            Err(e) => error!("Cannot write temporal data to destination file skipping, error: {}", e)
                        };
                        match remove_file(tmp_file){
                            Ok(_v) => debug!("Temporal file removed successfully."),
                            Err(e) => info!("Cannot remove temporal file skipping, message: {}", e)
                        };
                    }
                },
                Err(e) => error!("Error truncating file, retrying on next iteration, error: {}", e)
            };
        },
        Err(e) => error!("File cannot be copied, retrying on next iteration, error: {}", e)
    };

    *lock.lock().unwrap() = false;
    info!("File {} rotated.", filepath);
    info!("Compressing rotated file {}", file_rotated);
    #[cfg(windows)]
    if utils::get_os() == "windows" {
        match compress_zip_file(&file_rotated){
            Ok(message) => {
                info!("{}", message);
                match remove_file(file_rotated.clone()) {
                    Ok(_v) => info!("File {} removed.", file_rotated),
                    Err(e) => error!("Cannot remove rotated file, error: {}", e)
                }
            },
            Err(e) => error!("Error compressing file, error: {}", e)
        };
    }
    #[cfg(not(windows))]
    if utils::get_os() != "windows" {
        match compress_tgz_file(&file_rotated){
            Ok(message) => {
                info!("{}", message);
                match remove_file(file_rotated.clone()) {
                    Ok(_v) => info!("File {} removed.", file_rotated),
                    Err(e) => error!("Cannot remove rotated file, error: {}", e)
                }
            },
            Err(e) => error!("Error compressing file, error: {}", e)
        };
    }
    
    
}

// ----------------------------------------------------------------------------

#[cfg(not(tarpaulin_include))]
pub fn rotator(cfg: AppConfig){
    loop{
        let log_size = if Path::new(cfg.clone().log_file.as_str()).exists() {
            metadata(cfg.clone().log_file).unwrap().len() as usize
        }else{ 0 };
            
        let events_size = if Path::new(cfg.clone().events_file.as_str()).exists() {
            metadata(cfg.clone().events_file).unwrap().len() as usize
        }else{ 0 };

        if events_size >= cfg.events_max_file_size * 1000000 {
            let events_path = Path::new(cfg.events_file.as_str());
            let mut parent_path = events_path.parent().unwrap().to_path_buf();
            parent_path.push("archive");

            if ! parent_path.exists(){
                match create_dir(parent_path.clone()){
                    Ok(_v) => debug!("Archive directory created successfully."),
                    Err(e) => error!("Cannot create archive directory, error: {}", e)
                };
            }

            rotate_file(
                cfg.clone().events_file.as_str(),
                get_iteration(parent_path.to_str().unwrap()), 
                cfg.clone().get_mutex(cfg.clone().events_lock));
        }

        if log_size >= cfg.log_max_file_size * 1000000 {
            let log_path = Path::new(cfg.log_file.as_str());
            let mut parent_path = log_path.parent().unwrap().to_path_buf();
            parent_path.push("archive");

            if ! parent_path.exists(){
                match create_dir(parent_path.clone()){
                    Ok(_v) => debug!("Archive directory created successfully."),
                    Err(e) => error!("Cannot create archive directory, error: {}", e)
                };
            }

            rotate_file(
                cfg.clone().log_file.as_str(),
                get_iteration(parent_path.to_str().unwrap()), 
                cfg.clone().get_mutex(cfg.clone().log_lock));
        }

        debug!("Sleeping rotator thread for 30 minutes");
        thread::sleep(Duration::from_secs(1800));
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{create_dir, remove_dir};
    use std::env;

    #[test]
    fn test_get_iteration() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("test_get_iteration");
        let test_path = current_path.to_str().unwrap();

        create_dir(test_path).unwrap();
        assert_eq!(get_iteration(test_path), 0);
        assert_ne!(get_iteration(test_path), 1);
        remove_dir(test_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_compress_zip_file() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE");
        let test_path = current_path.to_str().unwrap();
        let zip_path = format!("{}.zip", test_path);

        compress_zip_file(test_path).unwrap();
        assert_eq!(Path::new(&zip_path).exists(), true);
        remove_file(zip_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_compress_tgz_file() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE");
        let test_path = current_path.to_str().unwrap();
        let tgz_path = format!("{}.tar.gz", test_path);

        compress_tgz_file(test_path).unwrap();
        assert_eq!(Path::new(&tgz_path).exists(), true);
        remove_file(tgz_path).unwrap();
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_rotate_file() {
        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE");
        let license_path = current_path.to_str().unwrap();

        let mut current_path = env::current_dir().unwrap();
        current_path.push("LICENSE.bk");
        let copy_path = current_path.to_str().unwrap();

        copy(license_path, copy_path).unwrap();

        let lock = Mutex::new(false);
        let iteration = 0;
        let extension = if utils::get_os() == "windows" { "zip"
        }else{ "tar.gz" };
        let compressed_file = format!("{}.{}.{}", copy_path, iteration, extension);
        rotate_file(copy_path, iteration, lock);
        assert_eq!(metadata(copy_path).unwrap().len(), 0);
        assert_ne!(metadata(compressed_file.clone()).unwrap().len(), 0);
        remove_file(copy_path).unwrap();
        remove_file(compressed_file).unwrap();
    }

}