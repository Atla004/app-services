use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

pub struct Logger {
    path: PathBuf,
}

impl Logger {
    // Crea un nuevo archivo de log
    pub fn new(path: PathBuf) -> io::Result<Self> {
        let file = File::create(&path)?;
        drop(file); 
        Ok(Logger { path })
    }

    // Agrega un nuevo log al archivo
    pub fn add_log(&self, log: &str) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", log)?;
        Ok(())
    }

    // Borra toda la información del archivo de log
    pub fn reset_log(&self) -> io::Result<()> {
        let file = File::create(&self.path)?;
        drop(file); // Cierra el archivo inmediatamente
        Ok(())
    }
}