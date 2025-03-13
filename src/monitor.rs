use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::collections::HashSet;


pub struct Monitor {
    path: PathBuf,
    tx: Sender<FileEvent>,
}

pub struct FileEvent {
    pub event: Event,
    pub timestamp: SystemTime,
}

impl Monitor {
    pub fn new(path: PathBuf, tx: Sender<FileEvent>) -> Self {
        Monitor { path, tx }
    }

    pub fn start(&self, stop_flag: Arc<AtomicBool>) {
        let (watcher_tx, watcher_rx) = std::sync::mpsc::channel();
        let mut watcher: RecommendedWatcher = Watcher::new(watcher_tx, notify::Config::default()).unwrap();
        watcher.watch(&self.path, RecursiveMode::Recursive).unwrap();
    
        let mut last_event_time = Instant::now();
        let mut event_set: HashSet<PathBuf> = HashSet::new();
    
        loop {
            // Aquí revisamos el stop_flag
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }

    
            match watcher_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Ok(event)) => {
                    let now = Instant::now();
                    if now.duration_since(last_event_time) > Duration::from_secs(1) {
                        event_set.clear();
                    }
                    last_event_time = now;
    
                    for path in &event.paths {
                        if !event_set.contains(path) {
                            event_set.insert(path.clone());
                            let file_event = FileEvent {
                                event: event.clone(),
                                timestamp: SystemTime::now(),
                            };
                            self.tx.send(file_event).unwrap();
                        }
                    }
                }
                Ok(Err(e)) => println!("watch error: {:?}", e),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Ignoramos timeouts y seguimos esperando eventos
                }
                Err(e) => println!("watch error: {:?}", e),
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::sync::mpsc;
    use tempfile::tempdir;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_monitor() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_path_buf();


        let (tx, rx) = mpsc::channel();

        // Create and start the monitor
        let monitor = Monitor::new(dir_path.clone(), tx);
        thread::spawn(move || {
            monitor.start(Arc::new(AtomicBool::new(false)));
        });

        // Add a small delay to ensure the monitor is ready
        thread::sleep(Duration::from_secs(1));

        // Create a file in the temporary directory to trigger an event
        let file_path = dir_path.join("test_file.txt");
        File::create(&file_path).unwrap();

        // Wait for the event to be received
        let file_event = rx.recv_timeout(Duration::from_secs(10)).expect("Did not receive event");

        // Check that the event is for the correct file
        assert!(file_event.event.paths.contains(&file_path));
    }
}