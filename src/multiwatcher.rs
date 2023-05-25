use notify::{RecommendedWatcher, Watcher, Config as NConfig};
use notify::poll::PollWatcher;
use std::sync::mpsc;
use std::path::Path;
use notify::RecursiveMode;

// ----------------------------------------------------------------------------

pub struct MultiWatcher {
    pub poll_watcher: PollWatcher,
    pub recommended_watcher: RecommendedWatcher,
    pub kind: String
}

impl MultiWatcher {
    pub fn new(kind: &str, tx: mpsc::Sender<Result<notify::Event, notify::Error>>) -> Self {
        match kind {
            "Pool" => {
                let (_tx, _rx) = mpsc::channel();
                MultiWatcher {
                    poll_watcher: PollWatcher::new(tx, NConfig::default()).unwrap(),
                    recommended_watcher: RecommendedWatcher::new(_tx, NConfig::default()).unwrap(),
                    kind: String::from(kind)
                }
            }
            _ => {
                let (_tx, _rx) = mpsc::channel();
                MultiWatcher {
                    poll_watcher: PollWatcher::new(_tx, NConfig::default()).unwrap(),
                    recommended_watcher: RecommendedWatcher::new(tx, NConfig::default()).unwrap(),
                    kind: String::from(kind)
                }
            }
        }
    }

    // ------------------------------------------------------------------------

    pub fn watch(&mut self, path: &Path, mode: RecursiveMode) -> notify::Result<()> {
        if self.kind != "Pool" {
            self.recommended_watcher.watch(path, mode)
        }else{
            self.poll_watcher.watch(path, mode)
        }
    }
}