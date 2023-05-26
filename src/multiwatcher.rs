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

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------

    pub fn create() {
        
    }

    // ------------------------------------------------------------------------

    #[test]
    fn test_new() {
        let (_tx, _rx) = mpsc::channel();
        let watcher = MultiWatcher::new("Pool", _tx);
        assert_eq!(watcher.kind, "Pool");

        let (_tx2, _rx2) = mpsc::channel();
        let watcher2 = MultiWatcher::new("Recommended", _tx2);
        assert_eq!(watcher2.kind, "Recommended");
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn test_watch() {
        let (_tx, _rx) = mpsc::channel();
        let mut watcher = MultiWatcher::new("Recommended", _tx);
        match watcher.watch(Path::new("C:"), RecursiveMode::NonRecursive) {
            Ok(()) => (),
            _ => assert_eq!(1, 2)
        }
    }

    // ------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn test_watch() {
        let (_tx, _rx) = mpsc::channel();
        let mut watcher = MultiWatcher::new("Recommended", _tx);
        match watcher.watch(Path::new("/etc"), RecursiveMode::NonRecursive) {
            Ok(()) => (),
            _ => assert_eq!(1, 2)
        }
    }
}