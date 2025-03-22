use crate::logic::handle_message;
use crate::state::{init_client_data, remove_client_data};
use std::collections::HashMap;
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

pub struct Tcp {
    listener: TcpListener,
}

impl Tcp {
    pub fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:8080")?;
        Ok(Tcp { listener })
    }

    pub fn run(&self) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    thread::spawn(move || {
                        Self::handle_client(stream);
                    });
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                }
            }
        }
    }

    pub fn connect(&self, ip_addr: SocketAddrV4) {
        let mut stream = TcpStream::connect(ip_addr);

        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    Self::handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    fn handle_client(mut stream: TcpStream) {
        let socket_addr = stream.peer_addr().expect("Failed to get client address");

        init_client_data(socket_addr);

        let mut buffer = [0; 1024];
        loop {
            // TODO: Check for commands to send

            match stream.read(&mut buffer) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    println!("received from a client probably");
                    if let Err(e) = handle_message(socket_addr, &buffer[..n]) {
                        eprintln!("Error handling message: {}", e);
                    }
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        // No data available right now.
                        println!("No data available (WouldBlock)");
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    io::ErrorKind::Interrupted => {
                        // Operation was interrupted.  Handle appropriately (maybe retry).
                        println!("Read interrupted");
                    }
                    _ => {
                        // Other errors (connection reset, etc.) - handle as fatal.
                        eprintln!("Error reading from stream: {}", e);
                        break;
                    }
                },
            }
        }

        remove_client_data(socket_addr);
        println!("Client disconnected: {}", socket_addr);
    }
}
