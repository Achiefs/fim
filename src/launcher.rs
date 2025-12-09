// Copyright (C) 2023, Achiefs.

use crate::config::*;
use crate::events::Event;
use crate::integration;
use log::debug;

// ----------------------------------------------------------------------------

pub fn check_integrations(event: Event, cfg: Config) {
    let index = cfg.get_index(event.get_monitor_event().path.to_str().unwrap(), "", cfg.monitor.clone());
    if index != usize::MAX {
        let integrations = cfg.get_integrations(index, cfg.monitor.clone());
        let integration = integration::get_event_integration(event.get_monitor_event(), integrations);
        match integration {
            Some(int) => int.launch(event.to_json()),
            None => debug!("No integration match on this event")
        }
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::events::Event;
    use crate::events::MonitorEvent;
    use crate::config::Config;

    use std::path::PathBuf;
    use notify::event::*;

    // ------------------------------------------------------------------------

    fn create_test_event() -> MonitorEvent {
        MonitorEvent {
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            node: "FIM".to_string(),
            version: "x.x.x".to_string(),
            kind: EventKind::Create(CreateKind::Any),
            path: PathBuf::new(),
            size: 0,
            labels: Vec::new(),
            operation: "CREATE".to_string(),
            detailed_operation: "CREATE_FILE".to_string(),
            checksum: "UNKNOWN".to_string(),
            fpid: 0,
            system: "test".to_string()
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_integrations() {
        let event = create_test_event();
        let cfg = Config::new("windows", Some("test/unit/config/windows/monitor_integration.yml"));
        check_integrations(Event::Monitor(event), cfg);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_check_integrations_linux() {
        let event = create_test_event();
        let cfg = Config::new("linux", Some("test/unit/config/linux/monitor_integration.yml"));
        check_integrations(Event::Monitor(event), cfg);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn test_check_integrations_linux() {
        let event = create_test_event();
        let cfg = Config::new("macos", Some("test/unit/config/macos/monitor_integration.yml"));
        check_integrations(Event::Monitor(event), cfg);
    }

}
