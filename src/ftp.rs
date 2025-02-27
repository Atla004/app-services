use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::error::Error;
use ftp::FtpStream;

pub struct FtpClient {
    address: String,
    username: String,
    password: String,
}

impl FtpClient {
    pub fn new(address: &str, username: &str, password: &str) -> Self {
        FtpClient {
            address: address.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    // Sube un archivo al servidor FTP
    pub fn upload_file<P: AsRef<Path>>(&self, local_path: P, remote_filename: &str) -> Result<(), Box<dyn Error>> {
      println!("[DEBUG] Iniciando upload_file con local_path: {:?}", local_path.as_ref());

      // Conectar al servidor FTP
      println!("[DEBUG] Conectando a FTP: {}", &self.address);
        let mut ftp_stream = FtpStream::connect(&self.address)?;
      println!("[DEBUG] Conectado a FTP: {}", &self.address);

      ftp_stream.login(&self.username, &self.password)?;
      println!("[DEBUG] Autenticado como: {}", &self.username);

      // Leer el archivo local
      let mut file = File::open(&local_path)?;
      println!("[DEBUG] Archivo abierto: {:?}", local_path.as_ref());
      let mut buffer = Vec::new();
      file.read_to_end(&mut buffer)?;
      println!("[DEBUG] Archivo leído, tamaño: {} bytes", buffer.len());

      // Subir el archivo al servidor con el nombre remoto
      ftp_stream.put(remote_filename, &mut &buffer[..])?;
      println!("[DEBUG] Archivo subido como: {}", remote_filename);

      // Cerrar la conexión
      ftp_stream.quit()?;
      println!("[DEBUG] Conexión FTP cerrada.");

      Ok(())
  }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    #[ignore = "Requiere un servidor FTP en localhost 21 con usuario 'test' y contraseña 'test'"]
    fn test_upload_file() -> Result<(), Box<dyn Error>> {
        // Crear un archivo temporal con contenido de prueba.
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "contenido de prueba")?;
        let path = temp_file.path();
        
        // Instanciar FtpClient con parámetros para un servidor de prueba.
        let ftp_client = FtpClient::new("127.0.0.1:44444", "test", "test");
        
        // Intentar subir el archivo al servidor con nombre 'uploaded_test.txt'.
        ftp_client.upload_file(path, "uploaded_test.txt")?;
        
        Ok(())
    }
}