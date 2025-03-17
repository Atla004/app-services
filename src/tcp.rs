use std::net::TcpStream;
use std::io::{self, Read, Write};
use std::time::Duration;

pub struct TcpClient {
    address: String,
    stream: Option<TcpStream>,
}

impl TcpClient {
    /// Crea una nueva instancia del cliente con la dirección proporcionada.
    pub fn new(address: &str) -> Self {
        TcpClient {
            address: address.to_string(),
            stream: None,
        }
    }

    /// Conecta el cliente al servidor TCP.
    pub fn connect(&mut self) -> io::Result<()> {
        let stream = TcpStream::connect(&self.address)?;
        self.stream = Some(stream);
        println!("Conectado a {}", self.address);
        Ok(())
    }

    /// Envía un mensaje al servidor TCP.
    pub fn send_message(&mut self, message: &str) -> io::Result<()> {
        if let Some(ref mut stream) = self.stream {
            stream.write_all(message.as_bytes())?;
            println!("Mensaje enviado: {}", message);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No existe conexión establecida",
            ))
        }
    }

    /// Recibe un mensaje del servidor TCP.
    pub fn receive_message(&mut self) -> io::Result<String> {
        let mut buffer = [0; 512];
        if let Some(ref mut stream) = self.stream {
            // Se establece un timeout para la lectura: si no llegan datos en 5 segundos, se retorna un error.
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            match stream.read(&mut buffer) {
                Ok(n) => {
                    let message = String::from_utf8_lossy(&buffer[..n]).to_string();
                    println!("Mensaje recibido: {}", message);
                    Ok(message)
                },
                Err(e) => {
                    eprintln!("tipo de error: {}", e.kind());
                    if e.kind() == io::ErrorKind::TimedOut {
                        Err(io::Error::new(io::ErrorKind::TimedOut, "Error al recibir mensaje: Timeout"))
                    } else {
                        Err(io::Error::new(io::ErrorKind::NotConnected, "No existe conexión establecida"))
                    }
                }
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No existe conexión establecida",
            ))
        }
    }

    /// Desconecta (cierra) la conexión TCP.
    pub fn disconnect(&mut self) {
        if self.stream.is_some() {
            // Al usar take() se elimina el valor, cerrando la conexión
            self.stream.take();
        } else {
            println!("La conexión con {} ya estaba cerrada.", self.address);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_client() {
        let address = "127.0.0.1:7878";
        let mut client = TcpClient::new(address);

        let connect_result = client.connect();
        //no hay servidor  por lo que deberia fallar
        assert!(connect_result.is_err());
    }

    #[test]
    #[ignore = "Requiere un servidor TCP en 127.0.0.1:7878 que, al conectarse, envíe un mensaje."]
    fn test_tcp_client_receive() -> io::Result<()> {
        
        let address = "192.168.225.11:57833";
        let mut client = TcpClient::new(address);

        client.connect()?;

        let msg = client.receive_message()?;
        println!("Test: Mensaje recibido: {}", msg);
        let _ = client.receive_message()?;

        // Desconectarse.
        client.disconnect();

        Ok(())
    }
}