
use std::{env, time::Duration};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use chrono::{DateTime, Local};

mod monitor;
mod logger;
mod ftp;
mod tcp;

use monitor::{FileEvent, Monitor};
use logger::Logger;
use tcp::TcpClient;
use ftp::FtpClient;

const TCP_ADDRESS: &str = "127.0.0.1:7878";
const FTP_ADDRESS: &str = "127.0.0.1:21";
const FTP_USERNAME: &str = "test";
const FTP_PASSWORD: &str = "";

enum TcpMessage {
    Log(String),
    Get(String),
    Other(String),//ls...
}

fn main() {
    let (tx, rx) = mpsc::channel();
    let (tx_tcp, rx_tcp) = mpsc::channel();
    let (tx_ftp, rx_ftp) = mpsc::channel();

    // ruta de descargas del usuario
    let user_profile = env::var("USERPROFILE").expect("Could not get USERPROFILE environment variable");
    let downloads_path = Path::new(&user_profile).join("Downloads"); 

    //inicializa el loger en un archivo monitor_log.txt en el directorio actual
    let log_path = Path::new("monitor_log.txt").to_path_buf();
    let logger = Logger::new(log_path.clone()).expect("Could not create log file");

    // Nuevo hilo para monitorear 
    let monitor_handle = thread::spawn(move || {
        let monitor = Monitor::new(downloads_path, tx);
        monitor.start();
    });

    // Nuevo hilo para recibir eventos del monitor y escribirlos en el log
    start_log_thread(rx, logger);

    

    let log_path_str = log_path.to_str().unwrap().to_string();

    
    let tcp_client = Arc::new(Mutex::new(TcpClient::new(TCP_ADDRESS)));

    // se conecta al servidor TCP por primera vez
    let mut tcp_is_connected = false;
    // Nuevo hilo para intentar conectarse al servidor TCP cuando se pierde la conexión
    {
        let tcp_client_clone = Arc::clone(&tcp_client);
        let tx_tcp_clone = tx_tcp.clone();
        thread::spawn(move || {
            loop {
                let mut tcp_client = tcp_client_clone.lock().unwrap();
                if !tcp_is_connected {
                    match tcp_client.connect() {
                        Ok(_) => {
                        tcp_is_connected = true;
                        tx_ftp.send(tcp_is_connected).unwrap();
                        println!("Conectado al servidor TCP.");
                    },
                    Err(e) => {
                        eprintln!("Error conectando al servidor TCP: {}. Reintentando en 10 minutos...", e);
                        std::thread::sleep(Duration::from_secs(5)); 
                    }
                }
                drop(tcp_client);
                if tcp_is_connected {
                    println!("TCP esta conectado hay que esperar a que se desconecte.");
                    match  rx_tcp.recv(){
                        Ok(reconnect) => {
                            println!("Recibido mensaje de reconexión. {}", reconnect);
                            tcp_is_connected = reconnect;
                        },
                        Err(_) => {
                            println!("Error recibiendo mensaje de reconexión.");
                            panic!("no se porque panic");
                        },
                        
                    }
                }else {
                    println!("TCP no esta conectado asi que se repite.");
                }
                println!("Reconectando al servidor TCP...");
                
            }
            }
        });
    }
    
    // Nuevo hilo para recibir mensajes del servidor TCP

    {
        let tcp_client_clone = Arc::clone(&tcp_client);
        let mut is_connected = tcp_is_connected;
        thread::spawn(move || {
            loop {

                if !is_connected {
                    println!("Esperando mensaje de reconexión FTP...");
                    rx_ftp.recv().unwrap();
                    is_connected = true;
                    println!("Conectado al servidor FTP.");
                } 

                let mut tcp_client = tcp_client_clone.lock().unwrap();
                println!("Esperando mensaje TCP...");
                match tcp_client.receive_message() {
                    Ok(msg) => {
                        let trimmed = msg.trim();
                    let message = if trimmed.eq_ignore_ascii_case("log") {
                        TcpMessage::Log(log_path_str.clone())
                    } else if trimmed.starts_with("Get:") {
                        TcpMessage::Get(trimmed.strip_prefix("Get:").unwrap().trim().to_string())
                    } else {
                        TcpMessage::Other(trimmed.to_string())
                    };
                    
                    if let Err(e) = process_tcp_message(message) {
                        tcp_client.send_message(&e).unwrap();

                    }
                    drop(tcp_client);
                },
                Err(e) => {
                    eprintln!("Error recibiendo mensaje TCP: {}", e);
                    if e.kind() == std::io::ErrorKind::ConnectionReset {
                        println!("Desconectado del servidor TCP asi que vamos a enviar un mensaje.");
                        is_connected = false;
                        tx_tcp.send(false).unwrap();
                    }
                }
            }
        }
    });
}
    



    monitor_handle.join().unwrap();
}

fn process_tcp_message(message: TcpMessage) -> Result<(), String> {
    match message {
        TcpMessage::Log(path_log) => {
            let ftp_client = FtpClient::new(FTP_ADDRESS, FTP_USERNAME, FTP_PASSWORD);
            if let Err(e) = ftp_client.upload_file(path_log, "monitor_log.txt") {
                eprintln!("Error enviando archivo de log: {}", e);
                Err(e.to_string())
            } else {
                println!("Archivo de log enviado.");
                Ok(())
            }
        },
        TcpMessage::Get(path_str) => {
            println!("Recibido 'Path: {}', enviando archivo...", path_str);
            let ftp_client = FtpClient::new(FTP_ADDRESS, FTP_USERNAME, FTP_PASSWORD);
            let remote_filename = std::path::Path::new(&path_str)
                .file_name()
                .and_then(|os_str| os_str.to_str())
                .unwrap_or("unknown_file");
            if let Err(e) = ftp_client.upload_file(&path_str, remote_filename) {
                eprintln!("Error subiendo el archivo {}: {}", path_str, e);
                Err(e.to_string())
            } else {

                println!("Archivo {} enviado.", path_str);
                Ok(())
            }
        },
        TcpMessage::Other(msg) => {
            println!("Recibido mensaje: {}", msg);
            Ok(())

        },
    }
}


fn start_log_thread(rx: mpsc::Receiver<FileEvent>, logger: Logger) {
    thread::spawn(move || {
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
    });
}