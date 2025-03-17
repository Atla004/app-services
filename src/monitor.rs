use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::collections::HashSet;
use crate::debug::debug_log; // added import

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
        debug_log("Monitor::start iniciado."); // added debug_log
        let (watcher_tx, watcher_rx) = std::sync::mpsc::channel();
        debug_log("Monitor::start iniciado.2"); // added debug_log
        let mut watcher: RecommendedWatcher = Watcher::new(watcher_tx, notify::Config::default()).unwrap();
        debug_log("Monitor::start iniciado.3"); // added debug_log
        match watcher.watch(&self.path, RecursiveMode::Recursive) {
            Ok(_) => {
                debug_log("Monitor::start: Carpeta original vigilada.");
            },
            Err(e) => {
                debug_log(&format!("Error al vigilar carpeta {:?}: {:?}. Intentando carpeta fallback.", self.path, e));
                let fallback_path = PathBuf::from("C:\\Temp");
                match watcher.watch(&fallback_path, RecursiveMode::Recursive) {
                    Ok(_) => {
                        debug_log(&format!("Monitor::start: Carpeta fallback {:?} vigilada.", fallback_path));
                    },
                    Err(e2) => {
                        debug_log(&format!("Error al vigilar carpeta fallback {:?}: {:?}", fallback_path, e2));
                        // Aquí podrías decidir abortar o seguir según tus necesidades.
                    }
                }
            }
        }
        debug_log("Monitor::start iniciado.4"); // added debug_log
    
        let mut last_event_time = Instant::now();
        debug_log("Monitor::start iniciado.5"); // added debug_log
        let mut event_set: HashSet<PathBuf> = HashSet::new();
        debug_log("entrando al loop del monitor");
    
        loop {
            if stop_flag.load(Ordering::SeqCst) {
                debug_log("Monitor::start finalizando por señal de stop."); // added debug_log
                break;
            }
            debug_log("Esperando evento del watcher. EN monitor"); // added debug_log
    
            match watcher_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Ok(event)) => {
                    debug_log("Evento recibido del watcher."); // added debug_log
                    let now = Instant::now();
                    if now.duration_since(last_event_time) > Duration::from_secs(1) {
                        event_set.clear();
                    }
                    last_event_time = now;
    
                    for path in &event.paths {
                        if !event_set.contains(path) {
                            event_set.insert(path.clone());
                            debug_log(&format!("Enviando FileEvent para: {:?}", path)); // added debug_log
                            let file_event = FileEvent {
                                event: event.clone(),
                                timestamp: SystemTime::now(),
                            };
                            self.tx.send(file_event).unwrap();
                        }
                    }
                }
                Ok(Err(e)) => {
                    println!("watch error: {:?}", e);
                    debug_log(&format!("Error en watcher: {:?}", e)); // added debug_log
                },
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Ignoramos timeouts y seguimos esperando eventos
                }
                Err(e) => {
                    println!("watch error: {:?}", e);
                    debug_log(&format!("Error en watcher (recv timeout): {:?}", e)); // added debug_log
                },
            }
        }
    }

}
