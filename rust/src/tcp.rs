use crate::logic::handle_message;
use crate::state::{ClientData, ServerState};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use rsa::RsaPublicKey;

pub struct Tcp {
    listener: TcpListener,
    state: Arc<RwLock<ServerState>>,
}

impl Tcp {
    pub fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:8080")?;
        let state = Arc::new(RwLock::new(ServerState {
            clients: HashMap::new(),
        }));
        Ok(Tcp { listener, state })
    }

    pub fn run(&self) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let state_clone = Arc::clone(&self.state);
                    thread::spawn(move || {
                        Self::handle_client(stream, state_clone);
                    });
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                }
            }
        }
    }

    pub fn connect(&self, ip_addr: SocketAddrV4) {
        let state = Arc::clone(&self.state);
        let mut stream = TcpStream::connect(ip_addr);

        match stream {
            Ok(stream) => {
                let state_clone = Arc::clone(&self.state);
                thread::spawn(move || {
                    Self::handle_client(stream, state_clone);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    fn handle_client(mut stream: TcpStream, server_state: Arc<RwLock<ServerState>>) {
        let addr = stream.peer_addr().expect("Failed to get client address");

        // Exit if there's already a connection
        {
            let state = server_state.read().unwrap();
            if state.clients.contains_key(&addr) {
                eprintln!("duplicate connection {:?}", state.clients.get(&addr));
                return;
            }
        }

        let client_data = Arc::new(Mutex::new(ClientData {
            connections: 1,
            message_count: 0,
            rsa_public: None,
        }));

        // Add client data to the central map (write lock)
        {
            let mut state = server_state.write().unwrap();
            state.clients.insert(addr, Arc::clone(&client_data));
        }

        let mut buffer = [0; 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    println!("received from a client probably");
                    if let Err(e) = handle_message(&buffer[..n], &client_data) {
                        eprintln!("Error handling message: {}", e);
                    }
                }
                Err(e) => {
                    // eprintln!("Error reading from stream: {}: {}", addr, e);
                    break;
                }
            }
        }

        // Remove data from the central map (write lock) when disconnected
        {
            let mut state = server_state.write().unwrap();
            state.clients.remove(&addr);
        }
        println!("Client disconnected: {}", addr);
    }

    pub fn get_state(&self) -> Arc<RwLock<ServerState>> {
        Arc::clone(&self.state)
    }
}
