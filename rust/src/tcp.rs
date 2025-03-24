use log::info;
use prost::Message;

use crate::logic::{handle_message, sign_encrypt_message, unsign_decrypt_message};
use crate::pb;
use crate::state;
use std::io;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

pub struct TcpServer {
    listener: TcpListener,
}

impl TcpServer {
    pub fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("0.0.0.0:5200")?;
        Ok(TcpServer { listener })
    }

    pub fn run(&self) {
        // Incoming connections
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    state::init_client_data(stream.peer_addr().unwrap());
                    thread::spawn(move || {
                        handle_client(stream);
                    });
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                }
            }
        }
    }
}

pub fn connect(socket_addr: SocketAddr) {
    // Outgoing connections
    let stream = TcpStream::connect(socket_addr);
    state::init_client_data(socket_addr);

    match stream {
        Ok(stream) => {
            thread::spawn(move || {
                handle_client(stream);
            });
        }
        Err(e) => {
            eprintln!("Connection failed: {}", e);
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    stream.set_nonblocking(true).unwrap();

    let socket_addr = stream.peer_addr().expect("Failed to get client address");
    state::increment_client_connections(socket_addr);

    println!("\nClient connected: {}", socket_addr);
    println!(">> ");

    let mut use_client_encryption;

    let mut buffer = [0; 1024 * 1024];
    loop {
        use_client_encryption = state::get_client_encryption_modes(socket_addr);
        let mut wrapped_response = state::get_outgoing_message(socket_addr);

        if wrapped_response.is_none() {
            match stream.read(&mut buffer) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    log::info!("received message from a client {:?}", (&buffer[..n]));

                    let signed_message =
                        pb::SignedMessage::decode(&buffer[..n]).expect("NOT A PROTOBUF MESSAGE");

                    let wrapped_message = unsign_decrypt_message(
                        socket_addr,
                        &use_client_encryption,
                        &signed_message,
                    )
                    .unwrap();

                    wrapped_response = handle_message(socket_addr, wrapped_message);
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        log::debug!("No data available (WouldBlock)");
                        thread::sleep(std::time::Duration::from_millis(100));
                    }
                    io::ErrorKind::Interrupted => {
                        log::debug!("Read interrupted");
                    }
                    _ => {
                        eprintln!("Error reading from stream: {}", e);
                        break;
                    }
                },
            }
        }

        if wrapped_response.is_some() {
            let signed_message = sign_encrypt_message(
                socket_addr,
                &use_client_encryption,
                &wrapped_response.unwrap(),
            )
            .unwrap();
            stream
                .write_all(&signed_message.encode_to_vec())
                .expect("Error writing reply");
        }
    }

    state::remove_client_data(socket_addr);
    state::decrement_client_connections(socket_addr);
    println!("\nClient disconnected: {}", socket_addr);
    println!(">> ");
}
