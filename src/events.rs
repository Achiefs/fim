// To handle files
use std::fs::OpenOptions;
use std::io::{Write, ErrorKind};
// To get Date and Time
use chrono::Utc;
// To get own process ID
use std::process;
// Event handling
use notify::op::Op;
// To log the program process
use log::*;
use notify::RawEvent;

// To load hashing functions
mod hash;

// To get Syslog format "Jan 01 01:01:01 HOSTNAME APPNAME[PID]:"
fn get_syslog_format() -> String {
    let datetime = Utc::now().format("%b %d %H:%M:%S");
    let hostname = gethostname::gethostname().into_string().unwrap();
    format!("{} {} FIM[{}]: ", datetime, hostname, process::id())
}

// Function to write the received events to file
pub fn log_event(file: &str, event: RawEvent, format: &str){
    let mut log = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(file)
        .expect("Unable to open events log file.");

    let path = event.path.expect("Error getting event path");
    let msg;
    match format {
        "json" | "JSON" | "j" | "J" | "Json" => msg = "JSON".to_string(),
        "syslog" | "s" | "SYSLOG" | "S" | "Syslog" | _ => msg = get_syslog_format(),
    };
    match event.op.unwrap() {
        Op::CREATE => {
            let checksum = hash::get_checksum(path.to_str().unwrap()).unwrap();

            writeln!(log, "{}File '{}' created, checksum {}",
                msg, path.to_str().unwrap(), checksum
            ).expect("Error writing event");
        }
        Op::WRITE => {
            let checksum = hash::get_checksum(path.to_str().unwrap()).unwrap();
            writeln!(log, "{}File '{}' written, new checksum {}",
                msg, path.to_str().unwrap(), checksum
            ).expect("Error writing event");
        }
        Op::RENAME => {
            let checksum = match hash::get_checksum(path.to_str().unwrap()) {
                Ok(data) => data,
                Err(e) => {
                    match e.kind() {
                        ErrorKind::NotFound => println!("File Not found error ignoring..."),
                        _ => panic!("Not handled error on get_checksum function."),
                    };
                    String::from("IGNORED")
                }
            };
            writeln!(log, "{}File '{}' renamed, checksum {}", msg,
                path.to_str().unwrap(), checksum).expect("Error writing event");
        }
        Op::REMOVE => writeln!(log, "{}File '{}' removed", msg,
            path.to_str().unwrap()).expect("Error writing event"),
        Op::CHMOD => writeln!(log, "{}File '{}' permissions modified", msg,
            path.to_str().unwrap()).expect("Error writing event"),
        Op::CLOSE_WRITE => writeln!(log, "{}File '{}' closed", msg,
            path.to_str().unwrap()).expect("Error writing event"),
        Op::RESCAN => writeln!(log, "{}Directory '{}' need to be rescaned", msg,
            path.to_str().unwrap()).expect("Error writing event"),
        _ => error!("Event Op not Handled"),
    }
}