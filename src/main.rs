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

mod monitor;
mod logger;

use monitor::{FileEvent, Monitor};
use logger::Logger;

// Define el handler del servicio.
define_windows_service!(ffi_service_main, my_service_main);

fn my_service_main(_arguments: Vec<std::ffi::OsString>) {
    let base_path = if let Ok(user_profile) = env::var("USERPROFILE") {
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

    let matenme_path = base_path.join("matenme.txt");

    let logger_matenme = Arc::new(Logger::new(matenme_path.clone()).expect("..."));
    
    // Creamos un flag compartido para indicar cuándo detener
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_handler = Arc::clone(&stop_flag);
    
    let status_handle =match  service_control_handler::register("VAS", move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                println!("Recibiendo señal de detención...");
                stop_flag_handler.store(true, Ordering::SeqCst);
            },
            _ => {}
        }
        ServiceControlHandlerResult::NoError
    }) {
        Ok(handle) => handle,
        Err(e) => {
            logger_matenme.add_log( format!("Error al registrar el handler de control: {:?}", e).as_str()).expect("Could not write log message");
            eprintln!("Error al registrar el handler de control: {:?}", e);
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
    }){
        eprintln!("Error al actualizar el estado del servicio: {:?}", e);
        logger_matenme.add_log(format!("Error al actualizar el estado del servicio: {:?}", e).as_str()).expect("Could not write log message");
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
    let (tx, rx) = mpsc::channel::<FileEvent>();

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

    let log_path = base_path.join("logger_principal.txt");
    let log_main_path = base_path.join("main_log.txt");
    let log_monitor_path = base_path.join("monitor_log.txt");
    let log_logger_path = base_path.join("logger_log.txt");


    // Se crea el logger; en caso de no poderse escribir, se mostrará el error.
    let logger = Arc::new(Mutex::new(Logger::new(log_path.clone()).expect("...")));
    let logger_main = Arc::new(Logger::new(log_main_path.clone()).expect("..."));
    let logger_monitor = Arc::new(Logger::new(log_monitor_path.clone()).expect("..."));
    let logger_logger = Arc::new(Logger::new(log_logger_path.clone()).expect("..."));
    
    
    

    // Thread monitor
    let downloads_path = Path::new(&user_profile).join("Downloads");
    let monitor_stop_flag = Arc::clone(&stop_flag);
    
    let monitor_thread = thread::spawn(move || {
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

    let logger_thread = thread::spawn(move || {

        let logger_logger_clone = Arc::clone(&logger_logger);
        
        loop {

            if logger_stop_flag.load(Ordering::SeqCst) {
                logger_logger_clone.add_log("logger Thread a finalizar").expect("Could not write log message");
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
    
    let max_duration = 180; // Cambia este valor según lo que necesites
    let start_time = std::time::Instant::now();

    
    let logger_main_clone = Arc::clone(&logger_main);

    
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

    let _ = monitor_thread.join();
    let _ = logger_thread.join();
    logger_main_clone.add_log("main Thread finalizado WUUUUUUUUUU").expect("Could not write log message");
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