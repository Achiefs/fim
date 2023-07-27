// Copyright (C) 2023, Achiefs.

// To log the program process
//use log::{debug, error};

// To get configuration constants
use crate::config;
// Single event data management
use crate::event::Event;
// Manage integration launch
use crate::integration;
// To log the program process
use log::debug;

// ----------------------------------------------------------------------------

pub fn check_integrations(event: Event, config: config::Config) {
    let index = config.get_index(event.path.to_str().unwrap(), "", config.monitor.clone());
    if index != usize::MAX {
        let integrations = config.get_integrations(index, config.monitor.clone());
        let integration = integration::get_event_integration(event.clone(), integrations);
        match integration {
            Some(int) => int.launch(event.clone().format_json()),
            None => debug!("No integration match on this event")
        }
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::event::Event;
    use crate::config::*;
    use notify::event::*;
    use yaml_rust::yaml::Array;

    // ------------------------------------------------------------------------

    fn create_test_event() -> Event {
        Event {
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            node: "FIM".to_string(),
            version: "x.x.x".to_string(),
            kind: EventKind::Create(CreateKind::Any),
            path: PathBuf::new(),
            labels: Vec::new(),
            operation: "CREATE".to_string(),
            detailed_operation: "CREATE_FILE".to_string(),
            checksum: "UNKNOWN".to_string(),
            fpid: 0,
            system: "test".to_string()
        }
    }

    // ------------------------------------------------------------------------

    pub fn create_test_config(filter: &str, events_destination: &str) -> Config {
        Config {
            version: String::from(VERSION),
            path: String::from("test"),
            events_watcher: String::from("Recommended"),
            events_destination: String::from(events_destination),
            events_max_file_checksum: 64,
            endpoint_type: String::from("Not_defined"),
            endpoint_address: String::from("test"),
            endpoint_user: String::from("test"),
            endpoint_pass: String::from("test"),
            endpoint_token: String::from("test"),
            events_file: String::from("test"),
            monitor: Array::new(),
            audit: Array::new(),
            node: String::from("test"),
            log_file: String::from("./test.log"),
            log_level: String::from(filter),
            system: String::from("test"),
            insecure: true
        }
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_check_integrations() {
        let event = create_test_event();
        let config = create_test_config("info", "file");
        check_integrations(event, config);
    }

    // ------------------------------------------------------------------------

}
