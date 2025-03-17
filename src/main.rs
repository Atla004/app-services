use std::{
    env, path::Path, sync::{
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
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::service::{ServiceInfo, ServiceStartType, ServiceErrorControl, ServiceAccess};

mod monitor;
mod logger;
mod ftp;
mod tcp;

use monitor::{FileEvent, Monitor};
use logger::Logger;
use tcp::TcpClient;
use ftp::FtpClient;


mod debug;
use crate::debug::debug_log;



// Define el handler del servicio.
define_windows_service!(ffi_service_main, my_service_main);

fn my_service_main(_arguments: Vec<std::ffi::OsString>) {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_handler = Arc::clone(&stop_flag);
    debug_log("my_service_main iniciado.");
    
    let status_handle = match service_control_handler::register("VAS", move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                println!("Recibiendo señal de detención...");
                debug_log("Recibiendo señal de detención...");
                stop_flag_handler.store(true, Ordering::SeqCst);
            },
            _ => {}
        }
        ServiceControlHandlerResult::NoError
    }) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("Error al registrar el handler de control: {:?}", e);
            debug_log(&format!("Error al registrar el handler de control: {:?}", e)); // agregado
            return; // O maneja el error según convenga.
        }
    };

    // Actualiza el estado a "Running" inmediatamente
    if let Err(e) = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }) {
        eprintln!("Error al actualizar el estado del servicio: {:?}", e);
        debug_log(&format!("Error al actualizar el estado del servicio: {:?}", e)); // agregado
        return;
    }

    // Inicia la lógica principal en un hilo separado
    let stop_flag_clone = Arc::clone(&stop_flag);
    let main_thread = thread::spawn(move || {
        main_logic(stop_flag_clone);
        // Una vez finalizada la lógica, actualiza el estado a Stopped
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }).unwrap();
    });

    main_thread.join().unwrap();
}

// Extrae la lógica que ya tienes en main() a una función separada.
fn main_logic(stop_flag: Arc<AtomicBool>) {
    debug_log("main_logic iniciado.");
    let (tx, rx) = mpsc::channel::<FileEvent>();

    // Se intenta obtener la variable USERPROFILE o se usa una ruta alternativa
    let user_profile = String::from("C:\\Users\\ATS");
    debug_log( &format!("Ruta de usuario: {:?}", user_profile));
    
    // Definir la ruta para los archivos (personalizada)
    let base_path = Path::new("C:\\ProgramData\\VasService").to_path_buf();


    // Se crea la carpeta si no existe para garantizar permisos de escritura.
    if let Err(e) = std::fs::create_dir_all(&base_path) {
        eprintln!("Error creando la carpeta base {:?}: {}", base_path, e);
    } else {
        println!("Carpeta base asegurada: {:?}", base_path);
        debug_log(&format!("Carpeta base asegurada: {:?}", base_path));
    }
    

    let log_path = base_path.join("logger_principal.txt");
    let log_main_path = base_path.join("main_log.txt");
    let log_monitor_path = base_path.join("monitor_log.txt");
    let log_logger_path = base_path.join("logger_log.txt");
    let logger_normal_path = base_path.join("logger_normal.txt");


    // Se crea el logger; en caso de no poderse escribir, se mostrará el error.
    let logger_normal = Logger::new(logger_normal_path.clone()).expect("...");
    let logger = Arc::new(Mutex::new(Logger::new(log_path.clone()).expect("...")));
    let logger_main = Arc::new(Logger::new(log_main_path.clone()).expect("..."));
    let logger_monitor = Arc::new(Logger::new(log_monitor_path.clone()).expect("..."));
    let logger_logger = Arc::new(Logger::new(log_logger_path.clone()).expect("..."));

    
    

    // Thread monitor
    let downloads_path = Path::new(&user_profile).join("Downloads");
    let monitor_stop_flag = Arc::clone(&stop_flag);

    debug_log(" se va a imprimir los mensajes");

    logger_normal.add_log("main Thread comenzdo... apunto de entar en monitor thread_del looger normal").expect("Could not write log message");
    logger_main.add_log("main Thread comenzdo... apunto de entar en monitor thread").expect("Could not write log message");
    debug_log(" se imprimieron los mensajes");

    let monitor_thread = thread::spawn(move || {
        debug_log("Iniciando thread de monitor.");
        let monitor = Monitor::new(downloads_path, tx);
        let logger_monitor_clone = Arc::clone(&logger_monitor);
        logger_monitor_clone.add_log("monitor Thread comenzdo").expect("Could not write log message");

        
        monitor.start(monitor_stop_flag);
        logger_monitor_clone.add_log("monitor Thread finalizdo").expect("Could not write log message");

        println!("Finalizando thread de monitor.");
    });
    
    
    // Thread para procesar eventos del monitor
    let logger_stop_flag = Arc::clone(&stop_flag);
    let logger_clone = Arc::clone(&logger);

    logger_main.add_log("... apunto de entrar a logger_thread").expect("Could not write log message");
    debug_log(" apunto de entrar a logger_thread");

    

    let logger_thread = thread::spawn(move || {

        let logger_logger_clone = Arc::clone(&logger_logger);
        
        loop {
            debug_log(" esperando eventos del monitor");

            if logger_stop_flag.load(Ordering::SeqCst) {
                logger_logger_clone.add_log("logger Thread a finalizar").expect("Could not write log message");
                break;
            }
            if let Ok(event) = rx.recv() {
                debug_log("evento recibido del monitor y se  va a imprimir");
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
                logger_logger_clone.add_log("Escribiendo en el log...").expect("Could not write to log file");
                logger_logger_clone.add_log(&log_message).expect("Could not write to log file");
                logger.add_log(&log_message).expect("Could not write to log file");
                drop(logger);
                println!("Log actualizado.");
                logger_logger_clone.add_log("Log actualizado.").expect("Could not write to log file");
                println!("Mensaje enviado al servidor TCP.");
            }
        }
        logger_logger_clone.add_log("logger Thread finalizado").expect("Could not write log message");
        println!("Finalizando thread de log.");
    });
    
    let max_duration = 30; // Cambia este valor según lo que necesites
    let start_time = std::time::Instant::now();

    
    let logger_main_clone = Arc::clone(&logger_main);
    logger_main_clone.add_log("main Thread llegando al stop").expect("Could not write log message");

    
    while !stop_flag.load(Ordering::SeqCst) {
        // Comprobamos tiempo transcurrido
        logger_main_clone.add_log(&format!("ESTE ES PARA VER SI SE DETENIEN EL SERVICIO  y esto ES LO QUE FALTA PARA QUE SE DETENGA: {}",!stop_flag.load(Ordering::SeqCst),)).expect("Could not write log message");
        if start_time.elapsed().as_secs() >= max_duration {
            println!("Tiempo de prueba agotado, deteniendo el servicio.");
            stop_flag.store(true, Ordering::SeqCst);
        }
        thread::sleep(Duration::from_secs(1));

    }
    logger_main_clone.add_log("main Thread finalizado, Señal de detención recibida").expect("Could not write log message");
    println!("Señal de detención recibida, finalizando main_logic.");
    debug_log("Señal de detención recibida, finalizando main_logic.");

    let _ = monitor_thread.join();
    let _ = logger_thread.join();
    logger_main_clone.add_log("main Thread finalizado WUUUUUUUUUU").expect("Could not write log message");
    logger_normal.add_log("main Thread finnnnnn... apunto de entar en monitor thread_del looger normal").expect("Could not write log message");
}

// New function to install the service.
fn install_service() -> windows_service::Result<()> {
    use std::ffi::OsString;
    debug_log("Inicializando instalación del servicio."); // new debug_log
    let service_name = OsString::from("VAS");
    let service_display_name = OsString::from("Vas11");
    let current_exe = std::env::current_exe().expect("Failed to get current exe path");
    let service_binary_path = current_exe.to_str().unwrap();
    debug_log(&format!("Instalando servicio desde: {}", service_binary_path)); // new debug_log
    let service_info = ServiceInfo {
         name: service_name,
         display_name: service_display_name,
         service_type: ServiceType::OWN_PROCESS,
         start_type: ServiceStartType::AutoStart,
         error_control: ServiceErrorControl::Normal,
         executable_path: OsString::from(service_binary_path).into(),
         launch_arguments: vec![],
         dependencies: vec![],
         account_name: None,
         account_password: None,
    };
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    service_manager.create_service(&service_info, ServiceAccess::empty())?;
    println!("Servicio instalado correctamente.");
    debug_log("Servicio instalado correctamente."); // new debug_log
    Ok(())
}

// New function to uninstall the service.
fn uninstall_service() -> windows_service::Result<()> {
    use std::ffi::OsString;
    debug_log("Inicializando desinstalación del servicio."); // new debug_log
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let service = service_manager.open_service(OsString::from("VAS"), ServiceAccess::DELETE)?;
    service.delete()?;
    println!("Servicio desinstalado correctamente.");
    debug_log("Servicio desinstalado correctamente."); // new debug_log
    Ok(())
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

// Modified main() to handle "install" and "uninstall" arguments.
fn main() {
    debug_log("Inicio de ejecución del programa."); // new debug_log
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
         match args[1].as_str() {
             "install" => {
                if let Err(e) = install_service() {
                     eprintln!("Error instalando el servicio: {:?}", e);
                }
                return;
             },
             "uninstall" => {
                if let Err(e) = uninstall_service() {
                     eprintln!("Error desinstalando el servicio: {:?}", e);
                }
                return;
             },
             _ => {}
         }
    }
    // ...existing main code...
    if args.iter().any(|arg| arg == "--console") {
        debug_log("iniciado como consola");
        main_logic(Arc::new(AtomicBool::new(false)));
    } else {
        debug_log("iniciando servicio mediante service_dispatcher");
        if let Err(e) = service_dispatcher::start("VAS", ffi_service_main) {
            eprintln!("Error al iniciar el servicio: {:?}", e);
            debug_log(&format!("Error al iniciar el servicio: {:?}", e));
        }
    }
}