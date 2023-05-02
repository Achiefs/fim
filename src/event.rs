// Copyright (C) 2021, Achiefs.

pub mod monitorevent;
//use monitorevent::MonitorEvent;
//use crate::event::monitorevent::MonitorEvent;
//use crate::monitorevent::MonitorEvent;


pub trait Event {
    fn format_json(&self) -> String;
    fn log(&self, file: &str);
    fn get_string(&self, field: String) -> String;
    //fn to_monitor(&self) -> MonitorEvent;
    //fn copy(&self) -> dyn Event;
}