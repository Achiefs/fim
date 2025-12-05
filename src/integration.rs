// Copyright (C) 2023, Achiefs.

use log::{debug, warn};
use std::process::Command;

use crate::events::MonitorEvent;
use crate::utils;

#[derive(Clone, Debug, Default)]
pub struct Integration {
    pub name: String,
    pub condition: Vec<String>,
    pub binary: String,
    pub script: String,
    pub parameters: String
}

impl Integration {
    pub fn launch(&self, event: String) {
        let formatted_event = match utils::get_os() {
            "windows" => format!("'{}'", event),
            _ => event
        };
        let output = Command::new(self.binary.clone())
            .arg(self.script.clone())
            .arg(formatted_event)
            .arg(self.parameters.clone())
            .output()
            .expect("Failed to execute integration script");
        debug!("Integration script '{}' output: [{}]", self.name, String::from_utf8(output.stdout).unwrap());
        let stderr = String::from_utf8(output.stderr).unwrap();
        if !stderr.is_empty() { warn!("Integration error: '{}'", stderr) }
    }
}

// ----------------------------------------------------------------------------

pub fn get_event_integration(event: MonitorEvent, integrations: Vec<Integration>) -> Option<Integration> {
    let option = integrations.iter().find(|integration|
        match integration.condition[1].as_str() {
            "==" => event.get_string(integration.condition[0].clone()) == integration.condition[2],
            "!=" => event.get_string(integration.condition[0].clone()) != integration.condition[2],
            _ => false
        }
    );
    option.cloned()
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::*;
    use crate::appconfig::*;
    use std::path::PathBuf;
    use crate::events::MonitorEvent;

    #[cfg(target_os = "windows")]
    pub fn create_dummy_event_windows(path: &str, operation: &str) -> MonitorEvent {
        MonitorEvent{
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            node: "FIM".to_string(),
            version: "x.x.x".to_string(),
            kind: EventKind::Create(CreateKind::Any),
            path: PathBuf::from(format!("C:\\{}\\test.txt", path)),
            size: 0,
            labels: Vec::new(),
            operation: operation.to_string(),
            detailed_operation: "CREATE_FILE".to_string(),
            checksum: "UNKNOWN".to_string(),
            fpid: 0,
            system: "test".to_string()
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn create_dummy_event_unix(path: &str, operation: &str) -> MonitorEvent {
        MonitorEvent{
            id: "Test_id".to_string(),
            timestamp: "Timestamp".to_string(),
            hostname: "Hostname".to_string(),
            node: "FIM".to_string(),
            version: "x.x.x".to_string(),
            kind: EventKind::Create(CreateKind::Any),
            path: PathBuf::from(format!("/{}/test.txt", path)),
            size: 0,
            labels: Vec::new(),
            operation: operation.to_string(),
            detailed_operation: "CREATE_FILE".to_string(),
            checksum: "UNKNOWN".to_string(),
            fpid: 0,
            system: "test".to_string()
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_event_integration_windows() {
        let cfg = AppConfig::new("windows", Some("test/unit/config/windows/monitor_integration.yml"));

        let integrations = cfg.get_integrations(2, cfg.monitor.clone());
        let event = create_dummy_event_windows("tmp", "CREATE");
        let integration = get_event_integration(event, integrations.clone()).unwrap();

        assert_eq!(integration.name, "rmfile");
        assert_eq!(integration.condition[0], "operation");
        assert_eq!(integration.condition[1], "==");
        assert_eq!(integration.condition[2], "CREATE");
        assert_eq!(integration.binary, "powershell.exe");
        assert_eq!(integration.script, "C:\\tmp\\remover.ps1");
        assert_eq!(integration.parameters, "");

        let integrations2 = cfg.get_integrations(3, cfg.monitor.clone());
        let event2 = create_dummy_event_windows("tmp2", "MODIFY");
        let integration2 = get_event_integration(event2, integrations2.clone()).unwrap();

        assert_eq!(integration2.name, "rmfile2");
        assert_eq!(integration2.condition[0], "operation");
        assert_eq!(integration2.condition[1], "!=");
        assert_eq!(integration2.condition[2], "REMOVE");
        assert_eq!(integration2.binary, "powershell.exe");
        assert_eq!(integration2.script, "C:\\tmp\\remover.ps1");
        assert_eq!(integration2.parameters, "");
    }

    // ------------------------------------------------------------------------

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_get_event_integration_unix() {
        let os = utils::get_os();
        let cfg = AppConfig::new(&os, Some(format!("test/unit/config/{}/monitor_integration.yml", os).as_str()));

        let event = create_dummy_event_unix("etc", "CREATE");
        let integrations = cfg.get_integrations(2, cfg.monitor.clone());
        let integration = get_event_integration(event, integrations).unwrap();

        assert_eq!(integration.name, "rmfile");
        assert_eq!(integration.condition[0], "operation");
        assert_eq!(integration.condition[1], "==");
        assert_eq!(integration.condition[2], "CREATE");
        assert_eq!(integration.binary, "bash");
        assert_eq!(integration.script, "/tmp/remover.sh");
        assert_eq!(integration.parameters, "");

        let event2 = create_dummy_event_unix("etc2", "MODIFY");
        let integrations2 = cfg.get_integrations(3, cfg.monitor.clone());
        let integration2 = get_event_integration(event2, integrations2).unwrap();

        assert_eq!(integration2.name, "rmfile2");
        assert_eq!(integration2.condition[0], "operation");
        assert_eq!(integration2.condition[1], "!=");
        assert_eq!(integration2.condition[2], "REMOVE");
        assert_eq!(integration2.binary, "bash");
        assert_eq!(integration2.script, "/tmp/remover.sh");
        assert_eq!(integration2.parameters, "");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_launch_windows(){
        let integration = Integration {
            name: String::from("Name"),
            condition: [String::from("A"), String::from("B"), String::from("C")].to_vec(),
            binary: String::from("powershell.exe"),
            script: String::from("ls"),
            parameters: String::from("")
        };

        integration.launch(create_dummy_event_windows("tmp", "C").to_json());
    }

    // ------------------------------------------------------------------------

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_launch_unix(){
        let integration = Integration {
            name: String::from("Name"),
            condition: [String::from("A"), String::from("B"), String::from("C")].to_vec(),
            binary: String::from("bash"),
            script: String::from("ls"),
            parameters: String::from("")
        };

        integration.launch(create_dummy_event_unix("etc", "C").to_json());
    }

}
