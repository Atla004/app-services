use std::net::TcpStream;
use std::io::{self, Read, Write};

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
            let n = stream.read(&mut buffer)?;
            let message = String::from_utf8_lossy(&buffer[..n]).to_string();
            println!("Mensaje recibido: {}", message);
            Ok(message)
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
            // Al usar take() se elimina el valor, cerrando la conexión.
            self.stream.take();
            println!("Desconectado de {}", self.address);
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
        
        let address = "127.0.0.1:7878";
        let mut client = TcpClient::new(address);

        client.connect()?;

        let msg = client.receive_message()?;
        println!("Test: Mensaje recibido: {}", msg);
        let msg2 = client.receive_message()?;

        // Desconectarse.
        client.disconnect();

        Ok(())
    }
}