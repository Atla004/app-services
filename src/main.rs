use std::env;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use chrono::{DateTime, Local};

mod monitor;
mod logger;
mod ftp;
mod tcp;

use monitor::Monitor;
use logger::Logger;
use tcp::TcpClient;
use ftp::FtpClient;

const TCP_ADDRESS: &str = "127.0.0.1:7878";
const FTP_ADDRESS: &str = "127.0.0.1:21";
const FTP_USERNAME: &str = "test";
const FTP_PASSWORD: &str = "";


fn main() {
    // Configuración del monitor y logger (lo que ya tenías)
    let (tx, rx) = mpsc::channel();
    let user_profile = env::var("USERPROFILE").expect("Could not get USERPROFILE environment variable");
    let downloads_path = Path::new(&user_profile).join("Downloads"); 

    let log_path = Path::new("monitor_log.txt").to_path_buf();
    let logger = Logger::new(log_path.clone()).expect("Could not create log file");

    let monitor_handle = thread::spawn(move || {
        let monitor = Monitor::new(downloads_path, tx);
        monitor.start();
    });

    // Nuevo hilo para manejar la conexión TCP y actuar según el mensaje recibido.
    let log_path_str = log_path.to_str().unwrap().to_string();
    thread::spawn(move || {
        // Configura la dirección del servidor TCP (ajústala a tu entorno)
        let mut tcp_client = TcpClient::new(TCP_ADDRESS);
        if let Err(e) = tcp_client.connect() {
            eprintln!("Error conectando al servidor TCP: {}", e);
            panic!("No se pudo conectar al servidor TCP");
        }

        loop {
            match tcp_client.receive_message() {
                Ok(msg) => {
                    let trimmed = msg.trim();
                    if trimmed.eq_ignore_ascii_case("log") {
                        // Enviar el archivo de log por FTP
                        println!("Recibido 'log', enviando archivo de log...");
                        let ftp_client = FtpClient::new(FTP_ADDRESS, FTP_USERNAME, FTP_PASSWORD);
                        if let Err(e) = ftp_client.upload_file(&log_path_str, "monitor_log.txt") {
                            eprintln!("Error subiendo el log: {}", e);
                        } else {
                            println!("Archivo de log enviado.");
                        }
                    } else if trimmed.starts_with("Path:") {
                        // Extraer la ruta y enviar el archivo correspondiente por FTP.
                        if let Some(path_str) = trimmed.strip_prefix("Path:") {
                            let path_str = path_str.trim();
                            println!("Recibido 'Path: {}', enviando archivo...", path_str);
                            let ftp_client = FtpClient::new(FTP_ADDRESS, FTP_USERNAME, FTP_PASSWORD);
                            // Definimos el nombre remoto usando el nombre de archivo local
                            let remote_filename = std::path::Path::new(path_str)
                                .file_name()
                                .and_then(|os_str| os_str.to_str())
                                .unwrap_or("unknown_file");
                            if let Err(e) = ftp_client.upload_file(path_str, remote_filename) {
                                eprintln!("Error subiendo el archivo {}: {}", path_str, e);
                            } else {
                                println!("Archivo {} enviado.", path_str);
                            }
                        }
                    } else {
                        println!("Mensaje TCP recibido: {}", trimmed);
                    }
                },
                Err(e) => {
                    eprintln!("Error recibiendo mensaje TCP: {}", e);
                    break;
                }
            }
        }
        tcp_client.disconnect();
    });

    // Bucle principal para el monitor (lo que ya tenías)
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