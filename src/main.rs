use std::env;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use chrono::{DateTime, Local};

mod monitor;
mod logger;
use monitor::Monitor;
use logger::Logger;

fn main() {
    let (tx, rx) = mpsc::channel();
    let user_profile = env::var("USERPROFILE").expect("Could not get USERPROFILE environment variable");
    let downloads_path = Path::new(&user_profile).join("Downloads"); 


    let log_path = Path::new("monitor_log.txt").to_path_buf();
    let logger = Logger::new(log_path).expect("Could not create log file");

    let monitor_handle = thread::spawn(move || {
        let monitor = Monitor::new(downloads_path, tx);
        monitor.start();
    });

    loop {
        match rx.recv() {
            Ok(event) => {
                let datetime: DateTime<Local> = event.timestamp.into();
                let log_message = format!(
                    "{} {:?}\nKind: {:?}\n",
                    datetime.format("%Y-%m-%d %H:%M:%S"),
                    event.event.paths,
                    event.event.kind
                );
                println!("{}", log_message);
                logger.add_log(&log_message).expect("Could not write to log file");
            },
            Err(_) => break,    
        }
    }
    monitor_handle.join().unwrap();
}