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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_logger() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test_log.txt");

        // Crear un nuevo logger
        let logger = Logger::new(log_path.clone()).unwrap();

        // Agregar un log
        logger.add_log("This is a test log").unwrap();
        let content = fs::read_to_string(&log_path).unwrap();
        assert_eq!(content.trim(), "This is a test log");

        // Resetear el log
        logger.reset_log().unwrap();
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.is_empty());

        // Agregar otro log
        logger.add_log("Another test log").unwrap();
        let content = fs::read_to_string(&log_path).unwrap();
        assert_eq!(content.trim(), "Another test log");
    }


    #[test]
    #[ignore = "Crea un directorio 'temporal' con logs"]
    fn test_logger_in_temp_dir() {
        let temp_dir = PathBuf::from("./temporal");
        fs::create_dir_all(&temp_dir).unwrap();

        // Obtener la ruta del archivo de log en el directorio ./temporal/
        let log_path = temp_dir.join("test_log.txt");

        // Crear un nuevo logger
        let logger = Logger::new(log_path.clone()).unwrap();

        // Agregar un log
        logger.add_log("This is a test log in temp dir").unwrap();
        let content = fs::read_to_string(&log_path).unwrap();
        assert_eq!(content.trim(), "This is a test log in temp dir");

        // Resetear el log
        logger.reset_log().unwrap();
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.is_empty());

        // Agregar otro log
        logger.add_log("Another test log in temp dir").unwrap();
        let content = fs::read_to_string(&log_path).unwrap();
        assert_eq!(content.trim(), "Another test log in temp dir");
    }
}