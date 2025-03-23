use prost::Message;

use crate::logic::{handle_message, sign_encrypt_message, unsign_decrypt_message};
use crate::pb;
use crate::state::get_outgoing_message;
use std::io;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

pub struct Tcp {
    listener: TcpListener,
}

pub fn connect(ip_addr: SocketAddr) {
    let stream = TcpStream::connect(ip_addr);

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

impl Tcp {
    pub fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:5200")?;
        Ok(Tcp { listener })
    }

    pub fn run(&self) {
        for stream in self.listener.incoming() {
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
    }
}

fn handle_client(mut stream: TcpStream) {
    let socket_addr = stream.peer_addr().expect("Failed to get client address");
    let mut buffer = [0; 1024];

    loop {
        let mut wrapped_response = get_outgoing_message(socket_addr);
        if wrapped_response.is_none() {
            match stream.read(&mut buffer) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    println!("received message from a client {:?}", buffer);

                    let signed_message =
                        pb::SignedMessage::decode(&buffer[..n]).expect("NOT A PROTOBUF MESSAGE");

                    let wrapped_message =
                        unsign_decrypt_message(socket_addr, &signed_message).unwrap();

                    wrapped_response = handle_message(socket_addr, wrapped_message);
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        println!("No data available (WouldBlock)");
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    io::ErrorKind::Interrupted => {
                        println!("Read interrupted");
                    }
                    _ => {
                        eprintln!("Error reading from stream: {}", e);
                        break;
                    }
                },
            }
        }

        if wrapped_response.is_some() {
            let signed_message =
                sign_encrypt_message(socket_addr, &wrapped_response.unwrap()).unwrap();
            stream
                .write_all(&signed_message.encode_to_vec())
                .expect("Error writing reply");
        }
    }

    // state::remove_client_data(socket_addr);
    println!("Client disconnected: {}", socket_addr);
}
