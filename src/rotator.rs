// Copyright (C) 2023, Achiefs.

use std::fs::{metadata, File, copy, read_to_string, remove_file, create_dir};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::thread;
use log::{debug, error, info};

use crate::config;

// ----------------------------------------------------------------------------

fn get_iteration(file: &str) -> u32{
    let mut iteration = 0;
    let mut path = Path::new(file).parent().unwrap().to_path_buf();
    path.push(Path::new("archive"));
    for entry in path.read_dir().expect("read_dir call failed").flatten() {
        let path = entry.path();
        let filename = Path::new(path.file_name().unwrap());
        let extension = filename.extension().unwrap();

        if extension.len() == 1 {
            let int_extension = extension.to_str().unwrap().parse::<u32>().unwrap();

            if int_extension == iteration {
                iteration += 1;
            }
        }
    }
    iteration
}

// ----------------------------------------------------------------------------

fn rotate_file(file: &str, iteration: u32, lock: &mut bool){
    info!("Rotating {} file...", file);
    *lock = true;
    thread::sleep(Duration::new(15, 0));
    let filepath = Path::new(file);
    let mut parent_path = filepath.parent().unwrap().to_path_buf();
    parent_path.push(Path::new("archive"));
    parent_path.push(Path::new(filepath.file_name().unwrap()));

    let file_rotated = format!("{}.{}",
        parent_path.to_str().unwrap(), iteration);

    if ! parent_path.parent().unwrap().exists(){
        match create_dir(parent_path.parent().unwrap()){
            Ok(_v) => debug!("Archive directory created successfully."),
            Err(e) => error!("Cannot create archive directory, error: {}", e)
        };
    }
    

    match copy(file, file_rotated){
        Ok(_v) => {
            debug!("File copied successfully.");
            match File::create(file){
                Ok(truncated_file) => {
                    debug!("File truncated successfully.");
                    let tmp_file = format!("{}.tmp", file);
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
                        Err(e) => error!("Cannot remove temporal file skipping, error: {}", e)
                    };
                },
                Err(e) => error!("Error truncating file, retrying on next iteration, error: {}", e)
            };
        },
        Err(e) => error!("File cannot be copied, retrying on next iteration, error: {}", e)
    };

    *lock = false;
    info!("File {} rotated.", file);
    

}

// ----------------------------------------------------------------------------

pub fn rotator(){
    let config = unsafe { super::GCONFIG.clone().unwrap() };
    let mut start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    loop{
        if (start_time + Duration::new(10, 0)).as_millis() < SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() {
            let log_size = metadata(config.clone().log_file).unwrap().len() as usize;
            let events_size = metadata(config.clone().events_file).unwrap().len() as usize;

            if events_size >= config.events_max_file_size * 1000000 {
                unsafe { rotate_file(config.clone().events_file.as_str(),
                    get_iteration(config.clone().events_file.as_str()), &mut config::TMP_EVENTS) };
            }

            if log_size >= config.log_max_file_size * 1000000 {
                unsafe { rotate_file(config.clone().log_file.as_str(),
                    get_iteration(config.clone().log_file.as_str()), &mut config::TMP_LOG) };
            }

            start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        }
    }
}

// ----------------------------------------------------------------------------

