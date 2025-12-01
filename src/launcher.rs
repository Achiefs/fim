// Copyright (C) 2023, Achiefs.

use crate::appconfig::*;
use crate::event::Event;
use crate::monitorevent::MonitorEvent;
use crate::integration;
use log::debug;

// ----------------------------------------------------------------------------

pub fn check_integrations(event: MonitorEvent, cfg: AppConfig) {
    let index = cfg.get_index(event.path.to_str().unwrap(), "", cfg.monitor.clone());
    if index != usize::MAX {
        let integrations = cfg.get_integrations(index, cfg.monitor.clone());
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

    use crate::monitorevent::MonitorEvent;
    use crate::appconfig::AppConfig;

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
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/monitor_integration.yml"));
        check_integrations(event, cfg);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_check_integrations_linux() {
        let event = create_test_event();
        let cfg = AppConfig::new("linux", Some("test/unit/config/linux/monitor_integration.yml"));
        check_integrations(event, cfg);
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn test_check_integrations_linux() {
        let event = create_test_event();
        let cfg = AppConfig::new("macos", Some("test/unit/config/macos/monitor_integration.yml"));
        check_integrations(event, cfg);
    }

}
