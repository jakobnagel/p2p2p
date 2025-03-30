#![warn(unused_extern_crates)]

mod logic;
mod mdns;
mod state;
mod tcp;

use num_traits::cast::ToPrimitive;
use rsa::traits::PublicKeyParts;
use rustyline::history::DefaultHistory;
use rustyline::Editor;
use state::get_rsa_key;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;

pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/p2p2p.rs"));
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    println!("Starting...");

    let password: String;
    match state::does_app_data_exist() {
        false => {
            println!("No previous data found");
            password = rpassword::prompt_password("Enter a new password: ").unwrap();
            log::info!("Password entered (length: {})", password.len());
        }
        true => {
            password = rpassword::prompt_password("Enter your existing password: ").unwrap();
            log::info!("Password entered (length: {})", password.len());
            match state::load_app_data_from_disk(&password) {
                Ok(_) => {}
                Err(e1) => {
                    if e1.kind() == std::io::ErrorKind::InvalidData {
                        println!("Wrong password");
                        std::process::exit(1);
                    }
                }
            }
        }
    }
    state::init_app_data();

    // mDNS
    let _mdns_handle = thread::spawn(move || {
        let mdns = mdns::Mdns::new().unwrap();
        mdns.run();
    });

    // TCP
    let _tcp_handle = thread::spawn(move || {
        let tcp = tcp::TcpServer::new().unwrap();
        tcp.run();
    });

    // Rustyline setup
    let mut rl: Editor<(), DefaultHistory> =
        Editor::new().expect("Unable to create rustyline editor");

    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }

    loop {
        let readline = rl.readline(">> ")?;
        rl.add_history_entry(readline.as_str())?;

        let parts: Vec<&str> = readline.split_whitespace().collect();

        match parts.get(0).map(|s| s.to_lowercase()).as_deref() {
            Some("help") => {
                println!("Available commands:");
                println!("  help - Show this help message");
            }
            Some("connect") => {
                if parts.len() >= 2 {
                    let socket_addr: Result<SocketAddr, _> = parts[1].parse();
                    match socket_addr {
                        Ok(socket_addr) => {
                            tcp::connect(socket_addr);
                            println!("Connected to {} successfully", socket_addr);

                            // Send Key Introduction
                            let rsa_public_key = state::get_rsa_key();
                            let dh_public_key = state::get_client_dh_public(socket_addr);
                            let wrapped_message = pb::WrappedMessage {
                                payload: Some(pb::wrapped_message::Payload::Introduction(
                                    pb::Introduction {
                                        rsa_public_key: {
                                            Some(pb::RsaPublicKey {
                                                e: rsa_public_key.e().to_u32().unwrap(),
                                                n: rsa_public_key.n().to_bytes_be(),
                                            })
                                        },
                                        diffe_hellman: Some(pb::DiffeHellman {
                                            dh_public_key: dh_public_key.to_bytes().to_vec(),
                                        }),
                                    },
                                )),
                            };
                            state::add_outgoing_message(socket_addr, wrapped_message);

                            // Send FileListRequest
                            let wrapped_message = pb::WrappedMessage {
                                payload: Some(pb::wrapped_message::Payload::FileListRequest(
                                    pb::FileListRequest {},
                                )),
                            };
                            state::add_outgoing_message(socket_addr, wrapped_message);
                        }
                        Err(e) => {
                            eprintln!("Invalid address: {:?}: {}", parts, e);
                            continue;
                        }
                    }
                } else {
                    state::print_clients();
                    println!("Usage: connect 192.168.0.1:5200");
                }
            }
            Some("listfiles") => {
                if parts.len() >= 2 {
                    let socket_addr: Result<SocketAddr, _> = parts[1].parse();
                    match socket_addr {
                        Ok(socket_addr) => {
                            // Send FileListRequest
                            let wrapped_message = pb::WrappedMessage {
                                payload: Some(pb::wrapped_message::Payload::FileListRequest(
                                    pb::FileListRequest {},
                                )),
                            };
                            state::add_outgoing_message(socket_addr, wrapped_message);

                            state::print_client_file_list(socket_addr);
                        }
                        Err(e) => {
                            eprintln!("Invalid address: {:?}: {}", parts, e);
                            continue;
                        }
                    }
                } else {
                    println!("Usage: listfiles 127.0.0.1:8080");
                }
            }
            Some("upload") => {
                if parts.len() >= 2 {
                    let socket_addr: Result<SocketAddr, _> = parts[1].parse();
                    match socket_addr {
                        Ok(addr) => {
                            if parts.len() >= 3 {
                                let file_name = parts[2].to_string();
                                let file_hash = match state::file_name_to_hash(&file_name) {
                                    Some(file_hash) => file_hash,
                                    None => {
                                        eprintln!("File not found");
                                        continue;
                                    }
                                };
                                let file = state::get_file_by_hash(&file_hash);
                                let wrapped_message = pb::WrappedMessage {
                                    payload: Some(pb::wrapped_message::Payload::FileUploadRequest(
                                        pb::FileUploadRequest {
                                            file_name: file.file_name,
                                            file_data: file.file_data.unwrap(),
                                        },
                                    )),
                                };
                                state::add_outgoing_message(addr, wrapped_message);
                            } else {
                                println!("Usage: upload 127.0.0.1:8080 file_name");
                            }
                        }
                        Err(e) => {
                            eprintln!("Invalid address: {:?}: {}", parts, e);
                            continue;
                        }
                    }
                } else {
                    state::print_clients();
                    println!("Usage: connect 127.0.0.1:8080");
                }
            }
            Some("download") => {
                if parts.len() >= 2 {
                    match parts[1].parse() {
                        Ok(socket_addr) => {
                            if parts.len() >= 3 {
                                let file_name = parts[2].to_string();

                                let wrapped_message = pb::WrappedMessage {
                                    payload: Some(
                                        pb::wrapped_message::Payload::FileDownloadRequest(
                                            pb::FileDownloadRequest { file_name },
                                        ),
                                    ),
                                };
                                state::add_outgoing_message(socket_addr, wrapped_message);
                            } else {
                                state::print_client_file_list(socket_addr);
                                println!("Usage: download 127.0.0.1:8080 file_name");
                            }
                        }
                        Err(e) => {
                            eprintln!("Invalid address: {:?}: {}", parts, e);
                            continue;
                        }
                    }
                } else {
                    println!("Usage: download 127.0.0.1:8080 file_name");
                }
            }
            Some("contact") => {
                if parts.len() >= 2 {
                    let socket_addr: Result<SocketAddr, _> = parts[1].parse();
                    match socket_addr {
                        Ok(socket_addr) => {
                            state::print_client_file_list(socket_addr);
                        }
                        Err(e) => {
                            eprintln!("Invalid address: {:?}: {}", parts, e);
                            continue;
                        }
                    }
                } else {
                    state::print_clients();
                    println!("Usage: contact 127.0.0.1:8080");
                }
            }
            Some("approve") => {
                if parts.len() >= 4 {
                    let socket_addr = SocketAddr::from_str(parts[1]).unwrap();
                    let file_direction = match parts[2] {
                        "upload" => state::FileDirection::UPLOAD,
                        "download" => state::FileDirection::DOWNLOAD,
                        _ => {
                            println!("Invalid file direction. Must be 'upload' or 'download'");
                            continue;
                        }
                    };
                    let file_name = parts[3].to_string();
                    let file_hash = match state::file_name_to_hash(&file_name) {
                        Some(file_hash) => file_hash,
                        None => {
                            eprintln!("File not found");
                            continue;
                        }
                    };
                    state::approve_transfer(socket_addr, file_direction, file_hash);
                    println!("Approved transfer");
                } else {
                    println!("Usage: approve <socket_addr> <upload|download> <file_hash>");
                }
            }
            Some("reject") => {
                if parts.len() >= 4 {
                    let socket_addr = SocketAddr::from_str(parts[1]).unwrap();
                    let file_direction = match parts[2] {
                        "upload" => state::FileDirection::UPLOAD,
                        "download" => state::FileDirection::DOWNLOAD,
                        _ => {
                            println!("Invalid file direction. Must be 'upload' or 'download'");
                            continue;
                        }
                    };
                    let file_name = parts[3].to_string();
                    let file_hash = match state::file_name_to_hash(&file_name) {
                        Some(file_hash) => file_hash,
                        None => {
                            eprintln!("File not found");
                            continue;
                        }
                    };
                    state::reject_transfer(socket_addr, file_direction, file_hash);
                    println!("Rejected transfer");
                } else {
                    println!("Usage: reject <socket_addr> <upload|download> <file_hash>");
                }
            }
            Some("ls") => {
                state::print_file_list();
            }
            Some("import") => {
                if parts.len() >= 2 {
                    let path = std::path::Path::new(parts[1]);
                    let file_hash = state::import_file(path).unwrap();
                    println!("Imported file with hash: {}", file_hash);
                } else {
                    println!("Usage: import <file_path>");
                }
            }
            Some("export") => {
                if parts.len() >= 3 {
                    let file_name = parts[1].to_string();
                    let file_hash = match state::file_name_to_hash(&file_name) {
                        Some(file_hash) => file_hash,
                        None => {
                            eprintln!("File not found");
                            continue;
                        }
                    };
                    let path = std::path::Path::new(parts[2]);

                    let file_path =
                        state::export_file(&file_hash, path).expect("error exporting file");
                    println!("Exported file to: {}", file_path);
                } else {
                    println!("Usage: export <file_name> <file_path>");
                }
            }
            Some("exit") => {
                break;
            }
            None => {}
            _ => {
                println!("Unknown command. Type 'help' for a list of commands.");
            }
        }
    }

    println!("Saving RSA private key to appdata.bin");
    println!("Saving files to filesystem.bin");
    state::save_app_data_to_disk(&password)?;
    rl.save_history("history.txt").unwrap();
    Ok(())
}
