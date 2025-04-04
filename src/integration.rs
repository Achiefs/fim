// Copyright (C) 2023, Achiefs.

// To implement Debug and fmt method
use std::fmt;
// To log the program process
use log::{debug, warn};
// To manage script execution
use std::process::Command;

// Single event data management
use crate::event::Event;
use crate::monitorevent::MonitorEvent;
use crate::utils;

// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct Integration {
    pub name: String,
    pub condition: Vec<String>,
    pub binary: String,
    pub script: String,
    pub parameters: String
}

// ----------------------------------------------------------------------------

impl Integration {

    pub fn clone(&self) -> Self {
        Integration {
            name: self.name.clone(),
            condition: self.condition.clone(),
            binary: self.binary.clone(),
            script: self.script.clone(),
            parameters: self.parameters.clone()
        }
    }

    // ------------------------------------------------------------------------

    pub fn new(name: String, condition: Vec<String>, binary: String, script: String, parameters: String) -> Self {
        Integration {
            name,
            condition,
            binary,
            script,
            parameters
        }
    }

    // ------------------------------------------------------------------------

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
        debug!("Integration output: [{}]", String::from_utf8(output.stdout).unwrap());
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
    option.map(|int| int.clone())
}

// ----------------------------------------------------------------------------

impl fmt::Debug for Integration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        f.debug_tuple("")
          .field(&self.name)
          .field(&self.condition)
          .field(&self.binary)
          .field(&self.script)
          .field(&self.parameters)
          .finish()
    }
}

// ----------------------------------------------------------------------------


#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::*;
    use crate::appconfig::*;
    use std::path::PathBuf;
    use crate::monitorevent::MonitorEvent;

    // ------------------------------------------------------------------------

    pub fn create_test_integration() -> Integration {
        Integration {
            name: String::from("Name"),
            condition: [String::from("A"), String::from("B"), String::from("C")].to_vec(),
            binary: String::from("Binary"),
            script: String::from("Script"),
            parameters: String::from("Parameters")
        }
    }

    // ------------------------------------------------------------------------

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

    #[test]
    fn test_clone() {
        let integration = create_test_integration();
        let cloned = integration.clone();
        assert_eq!(integration.name, cloned.name);
        assert_eq!(integration.condition, cloned.condition);
        assert_eq!(integration.binary, cloned.binary);
        assert_eq!(integration.script, cloned.script);
        assert_eq!(integration.parameters, cloned.parameters);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_new() {
        let integration = Integration::new(
            String::from("Name"),
            [String::from("A"), String::from("B"), String::from("C")].to_vec(),
            String::from("Binary"),
            String::from("Script"),
            String::from("Parameters")
        );
        assert_eq!(integration.name, "Name");
        assert_eq!(integration.condition[0], "A");
        assert_eq!(integration.condition[1], "B");
        assert_eq!(integration.condition[2], "C");
        assert_eq!(integration.binary, "Binary");
        assert_eq!(integration.script, "Script");
        assert_eq!(integration.parameters, "Parameters");
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

    #[test]
    fn test_integration_fmt(){
        let out = format!("{:?}", create_test_integration());
        assert_eq!(out,
            "(\"Name\", [\"A\", \"B\", \"C\"], \"Binary\", \"Script\", \"Parameters\")");
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

        integration.launch(create_dummy_event_windows("tmp", "C").format_json());
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

        integration.launch(create_dummy_event_unix("etc", "C").format_json());
    }

}
