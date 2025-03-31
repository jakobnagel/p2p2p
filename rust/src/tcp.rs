use prost::Message;

use crate::logic::{handle_message, sign_encrypt_message, unsign_decrypt_message};
use crate::pb;
use crate::state;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

pub struct TcpServer {
    listener: TcpListener,
}

impl TcpServer {
    pub fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("0.0.0.0:5200")?;
        listener.set_nonblocking(true)?;
        Ok(TcpServer { listener })
    }

    pub fn run(&self) {
        // Incoming connections
        loop {
            if state::SHUTDOWN.load(Ordering::SeqCst) {
                log::info!("TCP loop shutting down.");
                break;
            }
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    state::init_client_data(stream.peer_addr().unwrap());
                    let handle = thread::spawn(move || {
                        handle_client(stream);
                    });
                    let mut tcp_handles = state::TCP_HANDLES.lock().unwrap();
                    tcp_handles.push(handle);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
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
    log::info!("Initiating connection to {}", socket_addr);
    let stream = TcpStream::connect(socket_addr);
    state::init_client_data(socket_addr);

    match stream {
        Ok(stream) => {
            log::info!(
                "Connection to {} successful, handing off to handle_client()",
                socket_addr
            );

            let handle = thread::spawn(move || {
                handle_client(stream);
            });
            let mut tcp_handles = state::TCP_HANDLES.lock().unwrap();
            tcp_handles.push(handle);
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
        if state::SHUTDOWN.load(Ordering::SeqCst) {
            return;
        }

        use_client_encryption = state::get_client_encryption_modes(socket_addr);

        let mut wrapped_response = state::get_outgoing_message(socket_addr);
        if wrapped_response.is_some() {
            log::info!("[{}]: Found outgoing message", socket_addr);
        }

        if wrapped_response.is_none() {
            match stream.read(&mut buffer) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    log::info!(
                        "[{}]: Using RSA {}, Using AES {}",
                        socket_addr,
                        use_client_encryption.use_rsa,
                        use_client_encryption.use_aes
                    );

                    log::info!(
                        "[{}]: received message from a client of size {}",
                        socket_addr,
                        n
                    );

                    let signed_message =
                        pb::SignedMessage::decode(&buffer[..n]).expect("NOT A PROTOBUF MESSAGE");

                    log::info!(
                        "[{}]: decoded message into protobuf, passing to unsign_decrypt_message()",
                        socket_addr
                    );
                    let wrapped_message = unsign_decrypt_message(
                        socket_addr,
                        &use_client_encryption,
                        &signed_message,
                    )
                    .unwrap();

                    log::info!(
                        "[{}]: unwrapped message, passing to handle_message",
                        socket_addr
                    );

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
            log::info!("[{}]: Signing & encrypting outgoing message", socket_addr);
            let signed_message = sign_encrypt_message(
                socket_addr,
                &use_client_encryption,
                &wrapped_response.unwrap(),
            )
            .unwrap();
            log::info!("[{}]: Sending outgoing message", socket_addr);
            stream
                .write_all(&signed_message.encode_to_vec())
                .expect("Error writing reply");
            stream.flush().unwrap();
            log::info!("[{}]: Sent outgoing message", socket_addr);
        }
    }

    state::remove_client_data(socket_addr);
    state::decrement_client_connections(socket_addr);
    println!("\nClient disconnected: {}", socket_addr);
    println!(">> ");
}
