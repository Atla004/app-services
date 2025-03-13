use std::{
    env, io::Write, path::Path, sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex
    }, thread, time::Duration
};
use chrono::{DateTime, Local};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher
};

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
const FTP_PASSWORD: &str = "test";

// Define el handler del servicio.
define_windows_service!(ffi_service_main, my_service_main);

fn my_service_main(_arguments: Vec<std::ffi::OsString>) {
    
    // Creamos un flag compartido para indicar cuándo detener
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_handler = Arc::clone(&stop_flag);
    
    let status_handle = service_control_handler::register("VAS", move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                println!("Recibiendo señal de detención...");
                stop_flag_handler.store(true, Ordering::SeqCst);
            },
            _ => {}
        }
        ServiceControlHandlerResult::NoError
    }).unwrap();

    // Actualiza el estado a "Running".
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }).unwrap();

    // Llama a la lógica principal, pasando el flag de detención.
    main_logic(stop_flag);

    // Actualiza el estado a "Stopped" al finalizar.
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }).unwrap();
}

// Extrae la lógica que ya tienes en main() a una función separada.
fn main_logic(stop_flag: Arc<AtomicBool>) {
    let (tx, rx) = mpsc::channel::<FileEvent>();
    let (tx_tcp, rx_tcp) = mpsc::channel::<bool>();
    let (tx_ftp, rx_ftp) = mpsc::channel::<bool>();

    // Se intenta obtener la variable USERPROFILE o se usa una ruta alternativa
    let user_profile = env::var("USERPROFILE")
        .unwrap_or_else(|_| String::from("C:\\ProgramData\\VasService"));
    
    // Definir la ruta para los archivos (personalizada)
    let base_path = if let Ok(user_profile) = env::var("USERPROFILE") {
        // Queremos utilizar la carpeta "C:\Users\andre\Documents\Vas"
        Path::new(&user_profile).join("Documents").join("Vas")
    } else {
        // Ruta alternativa garantizada
        Path::new("C:\\ProgramData\\VasService").to_path_buf()
    };

    // Se crea la carpeta si no existe para garantizar permisos de escritura.
    if let Err(e) = std::fs::create_dir_all(&base_path) {
        eprintln!("Error creando la carpeta base {:?}: {}", base_path, e);
    } else {
        println!("Carpeta base asegurada: {:?}", base_path);
    }

    let log_path = base_path.join("monitor_log.txt");

    // Se crea el logger; en caso de no poderse escribir, se mostrará el error.
    let logger = Arc::new(Mutex::new(Logger::new(log_path.clone()).expect("...")));
    
    
    
    //Clientes
    let tcp_client = Arc::new(Mutex::new(TcpClient::new(TCP_ADDRESS)));


    // Thread monitor
    let downloads_path = Path::new(&user_profile).join("Downloads");
    let monitor_stop_flag = Arc::clone(&stop_flag);
    
    let monitor_thread = thread::spawn(move || {
        let monitor = Monitor::new(downloads_path, tx);
        monitor.start(monitor_stop_flag);
        println!("Finalizando thread de monitor.");
    });
    
    
    // Thread para procesar eventos del monitor
    let logger_stop_flag = Arc::clone(&stop_flag);
    let logger_clone = Arc::clone(&logger);
    let tcp_client_clone = Arc::clone(&tcp_client);

    let logger_thread = thread::spawn(move || {
        loop {
            if logger_stop_flag.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(event) = rx.recv() {
                let datetime: DateTime<Local> = event.timestamp.into();
                let log_message = format!(
                    "{} {:?}\nKind: {:?}\n",
                    datetime.format("%Y-%m-%d %H:%M:%S"),
                    event.event.paths,
                    event.event.kind
                );
                println!("{}", log_message);
                let logger = logger_clone.lock().unwrap();
                println!("Escribiendo en el log...");
                logger.add_log("hola23\n").expect("Could not write initial log message");
                logger.add_log(&log_message).expect("Could not write to log file");
                println!("Log actualizado.");
                tcp_client_clone.lock().unwrap().send_message("log se ha actualizado").unwrap();
                println!("Mensaje enviado al servidor TCP.");
                drop(logger);
            }
        }
        println!("Finalizando thread de log.");
    });
    
    let log_path_str = log_path.to_str().unwrap().to_string();
    let mut tcp_is_connected = false;
    
    let tcp_stop_flag = Arc::clone(&stop_flag);
    let tx_tcp_clone = tx_tcp.clone();
    let tcp_thread = {
        let tcp_client_clone = Arc::clone(&tcp_client);
        thread::spawn(move || {
            while !tcp_stop_flag.load(Ordering::SeqCst) {
                println!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                if !tcp_is_connected {
                    match tcp_client_clone.lock().unwrap().connect() {
                        Ok(_) => {
                            tcp_is_connected = true;
                            tx_ftp.send(tcp_is_connected).unwrap();
                            println!("Conectado al servidor TCP.");
                        },
                        Err(e) => {
                            eprintln!("Error conectando al servidor TCP: {}. Reintentando en 10 segundos...", e);
                            thread::sleep(Duration::from_secs(10));
                        }
                    }
                }
                if tcp_is_connected {
                    println!("TCP está conectado; esperando desconexión.");
                    match rx_tcp.recv() {
                        Ok(reconnect) => {
                            println!("Recibido mensaje de reconexión. {}", reconnect);
                            tcp_is_connected = reconnect;
                        },
                        Err(e) => {
                            eprintln!("Error recibiendo mensaje de reconexión: {}. Se intentará reconectar.", e);
                            tcp_is_connected = false;
                        },
                    }
                } else {
                    println!("TCP no está conectado, repitiendo.");
                }
                println!("Reconectando al servidor TCP...");
            }
            {

                let mut tcp_client = tcp_client_clone.lock().unwrap();
                tcp_client.disconnect();
            }
            println!("Finalizando thread TCP.");

        })
    };

    // Thread FTP
    let ftp_stop_flag = Arc::clone(&stop_flag);
    let logger_clone_tcp = Arc::clone(&logger);
    let ftp_thread = {
    let tcp_client_clone = Arc::clone(&tcp_client);
        thread::spawn(move || {
            let mut is_connected = tcp_is_connected;
            while !ftp_stop_flag.load(Ordering::SeqCst) {
                if !is_connected {
                    println!("Esperando mensaje de reconexión FTP...");
                    
                    match rx_ftp.recv() {
                        Ok(reconnect) => {
                            println!("Recibido mensaje de reconexión FTP. {}", reconnect);
                            is_connected = reconnect;
                        },
                        Err(e) => {
                            eprintln!("Error recibiendo mensaje de reconexión FTP: {}. Se intentará reconectar.", e);
                            is_connected = false;
                        },
                    }
                    println!("Conectado al servidor FTP.");
                } 
                

                println!("Esperando mensaje TCP...");
                match tcp_client_clone.lock().unwrap().receive_message() {
                    Ok(msg) => {
                        let trimmed = msg.trim();
                        tcp_client_clone.lock().unwrap().send_message(trimmed).unwrap();
                        let message = if trimmed.eq_ignore_ascii_case("log") {
                            let x =TcpMessage::Log(log_path_str.clone());
                            let logger = logger_clone_tcp.lock().unwrap();
                            logger.reset_log().unwrap();
                            drop(logger);
                            x
                        } else if trimmed.starts_with("Path:") {
                            TcpMessage::Path(trimmed.strip_prefix("Path:").unwrap().trim().to_string())
                        } else {
                            TcpMessage::Other(trimmed.to_string())
                        };
                        
                        if let Err(e) = process_tcp_message(message) {
                            tcp_client_clone.lock().unwrap().send_message(&e).unwrap();
                        }
                    },
                    Err(e) => {
                        eprintln!("Error recibiendo mensaje TCP: {}", e);
                        if e.kind() == std::io::ErrorKind::ConnectionReset {
                            println!("Desconectado del servidor TCP, enviando mensaje.");
                            is_connected = false;
                            if let Err(e) = tx_tcp_clone.send(false) {
                                eprintln!("No se pudo enviar mensaje a través del canal tx_tcp: {}", e);
                            }
                        }
                    }
                }
            }
            println!("Finalizando thread FTP.");
        })
    };

    let max_duration = 20; // Cambia este valor según lo que necesites
    let start_time = std::time::Instant::now();

    // Bucle en el thread principal: espera hasta que se active la señal de parada
    while !stop_flag.load(Ordering::SeqCst) {
        // Comprobamos tiempo transcurrido
        if start_time.elapsed().as_secs() >= max_duration {
            println!("Tiempo de prueba agotado, deteniendo el servicio.");
            stop_flag.store(true, Ordering::SeqCst);
            tx_tcp.send(false).unwrap();

        }
        thread::sleep(Duration::from_secs(1));

    }
    println!("Señal de detención recibida, finalizando main_logic.");

    let _ = monitor_thread.join();
    let _ = logger_thread.join();
    let _ = tcp_thread.join();
    let _ = ftp_thread.join();
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
        TcpMessage::Path(path_str) => {
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

enum TcpMessage {
    Log(String),
    Path(String),
    Other(String),
}

fn main() {
    if std::env::args().any(|arg| arg == "--console") {
        // Ejecuta la lógica principal en modo consola para depuración.
        main_logic(Arc::new(AtomicBool::new(false)));
    } else {
        // Inicia el servicio mediante el dispatcher de Windows.
        service_dispatcher::start("VAS", ffi_service_main).unwrap();
    }
}