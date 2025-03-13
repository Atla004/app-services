use std::thread;
use std::time::Duration;

fn main() {
    // Se crea un hilo que imprime un contador
    let handle = thread::spawn(|| {
        for i in 0..5 {
            println!("Hilo: contador {}", i);
            thread::sleep(Duration::from_millis(500));
        }
    });

    // El hilo principal sigue haciendo otras tareas
    println!("Hilo principal: realizando tareas...");

    // join() espera a que el hilo creado termine su ejecución
    handle.join().expect("El hilo ha fallado");

    println!("Hilo principal: el hilo secundario ha finalizado.");
}
