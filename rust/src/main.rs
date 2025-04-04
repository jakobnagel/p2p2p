#![warn(unused_extern_crates)]

mod logic;
mod mdns;
mod state;
mod tcp;

use colored::*;
use num_traits::cast::ToPrimitive;
use rsa::traits::PublicKeyParts;
use rustyline::history::DefaultHistory;
use rustyline::Editor;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::Ordering;
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
    let mdns_handle = thread::spawn(move || {
        let mdns = mdns::Mdns::new().unwrap();
        mdns.run();
    });

    // TCP
    let tcp_handle = thread::spawn(move || {
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
        match rl.readline(">> ") {
            Ok(line) => {
                rl.add_history_entry(line.as_str())?;

                let parts: Vec<&str> = line.split_whitespace().collect();

                match parts.get(0).map(|s| s.to_lowercase()).as_deref() {
                    Some("help") => {
                        println!("Available commands:");
                        println!("  {} - Show this help message", "help".yellow().bold());
                        println!("  {} - List peers", "search".yellow().bold());
                        println!(
                            "  {} - Connect to a peer",
                            "connect <address> <nickname>".yellow().bold()
                        );
                        println!(
                            "  {} - Rename a peer",
                            "rename <old nickname> <new nickname>".yellow().bold()
                        );
                        println!(
                            "  {} - List files from a peer",
                            "listfiles <nickname>".yellow().bold()
                        );
                        println!(
                            "  {} - Upload a file to a peer",
                            "upload <nickname> <file_name>".yellow().bold()
                        );
                        println!(
                            "  {} - Download a file from a peer",
                            "download <nickname> <file_name>".yellow().bold()
                        );
                        println!(
                            "  {} - Approve a transfer",
                            "approve <nickname> <upload|download> <file_name>"
                                .yellow()
                                .bold()
                        );
                        println!(
                            "  {} - Reject a transfer",
                            "reject <nickname> <upload|download> <file_name>"
                                .yellow()
                                .bold()
                        );
                        println!("  {} - List local files", "ls".yellow().bold());
                        println!("  {} - Import a file", "import <file_path>".yellow().bold());
                        println!(
                            "  {} - Export a file",
                            "export <file_name> <file_path>".yellow().bold()
                        );
                        println!("  {} - Exit the program", "exit".yellow().bold());
                    }
                    Some("search") => {
                        state::print_clients();
                    }
                    Some("connect") => match parts.get(1..3) {
                        Some([socket_addr_str, nickname_str]) => {
                            let socket_addr = match SocketAddr::from_str(socket_addr_str) {
                                Ok(addr) => addr,
                                Err(e) => {
                                    eprintln!("Invalid address '{}': {}", socket_addr_str, e);
                                    continue;
                                }
                            };

                            let nickname = nickname_str.to_string();
                            state::init_client_data(socket_addr);
                            if state::set_client_nickname(socket_addr, nickname.clone()).is_err() {
                                println!("Nickname {} is already used", nickname);
                            }

                            // Open TCP connection
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
                            println!("Sent Hello to {}", socket_addr);

                            // Send FileListRequest
                            let wrapped_message = pb::WrappedMessage {
                                payload: Some(pb::wrapped_message::Payload::FileListRequest(
                                    pb::FileListRequest {},
                                )),
                            };
                            state::add_outgoing_message(socket_addr, wrapped_message);
                            println!("Sent FileList Request to {}", socket_addr);
                        }
                        _ => {
                            println!(
                                "Usage: {}",
                                "connect 256.256.256.256:5200 <nickname>".yellow().bold()
                            );
                        }
                    },
                    Some("rename") => match parts.get(1..3) {
                        Some([old_nickname_str, new_nickname_str]) => {
                            let old_nickname = old_nickname_str.to_string();
                            let new_nickname = new_nickname_str.to_string();

                            if state::change_client_nickname(
                                old_nickname.clone(),
                                new_nickname.clone(),
                            )
                            .is_err()
                            {
                                println!("Failed to rename {} to {}", old_nickname, new_nickname);
                                continue;
                            }
                            println!("Changed nickname of {} to {}", old_nickname, new_nickname);
                        }
                        _ => {
                            println!(
                                "Usage: {}",
                                "rename <old nickname> <new nickname>".yellow().bold()
                            );
                        }
                    },
                    Some("upload") => match parts.get(1..3) {
                        Some([nickname_str, file_name_str]) => {
                            let socket_addr = match state::get_socket_from_nickname(nickname_str) {
                                Some(socket_addr) => socket_addr,
                                None => {
                                    eprintln!("Unknown Nickname '{}'", nickname_str);
                                    continue;
                                }
                            };

                            let file_name = file_name_str.to_string();
                            let file_hash = match state::file_name_to_hash(&file_name) {
                                Some(hash) => hash,
                                None => {
                                    eprintln!("Local file '{}' not found.", file_name);
                                    state::print_file_list();
                                    continue;
                                }
                            };

                            let file = state::get_file_by_hash(&file_hash);

                            let file_data = match file.file_data {
                                Some(data) => data,
                                None => {
                                    eprintln!(
                                        "Error: Local file '{}' has no data associated with it.",
                                        file_name
                                    );
                                    continue;
                                }
                            };

                            let wrapped_message = pb::WrappedMessage {
                                payload: Some(pb::wrapped_message::Payload::FileUploadRequest(
                                    pb::FileUploadRequest {
                                        file_name: file.file_name,
                                        file_data,
                                    },
                                )),
                            };
                            state::add_outgoing_message(socket_addr, wrapped_message);
                            println!(
                                "Upload request for '{}' sent to {}.",
                                file_name_str, socket_addr
                            );
                        }
                        _ => {
                            println!("Usage: upload <nickname> file_name");
                        }
                    },
                    Some("download") => match parts.get(1..3) {
                        Some([nickname_str, file_name_str]) => {
                            let socket_addr = match state::get_socket_from_nickname(nickname_str) {
                                Some(socket_addr) => socket_addr,
                                None => {
                                    eprintln!("Unknown Nickname '{}'", nickname_str);
                                    continue;
                                }
                            };

                            let file_name = file_name_str.to_string();

                            let file_hash =
                                match state::remote_file_name_to_hash(socket_addr, &file_name) {
                                    Some(file_hash) => file_hash,
                                    _ => {
                                        eprintln!(
                                            "Can't find file {} in {}",
                                            file_name_str, socket_addr
                                        );
                                        continue;
                                    }
                                };

                            if !state::is_client_connected(socket_addr) {
                                let clients = state::find_clients_with_hash(&file_hash);

                                if clients.len() >= 1 {
                                    println!(
                                        "{} is offline, try {} or {:?}",
                                        socket_addr,
                                        format!("download {} {}", clients[0], file_name)
                                            .yellow()
                                            .bold(),
                                        clients
                                    );
                                } else {
                                    println!(
                                        "{} is offline, no other clients with the file found",
                                        socket_addr
                                    );
                                }
                                continue;
                            }

                            state::approve_transfer(
                                socket_addr,
                                state::FileDirection::DOWNLOAD,
                                file_name.clone(),
                                file_hash,
                            );

                            let wrapped_message = pb::WrappedMessage {
                                payload: Some(pb::wrapped_message::Payload::FileDownloadRequest(
                                    pb::FileDownloadRequest {
                                        file_name: file_name.clone(),
                                    },
                                )),
                            };
                            state::add_outgoing_message(socket_addr, wrapped_message);
                            println!(
                                "Download request for '{}' sent to {}.",
                                file_name, socket_addr
                            );
                        }
                        _ => {
                            println!(
                                "Usage: {}",
                                "download <nickname> <file_name>".yellow().bold()
                            );
                        }
                    },
                    Some("listfiles") => match parts.get(1..2) {
                        Some([nickname_str]) => {
                            let socket_addr = match state::get_socket_from_nickname(nickname_str) {
                                Some(socket_addr) => socket_addr,
                                None => {
                                    eprintln!("Unknown Nickname '{}'", nickname_str);
                                    continue;
                                }
                            };

                            if state::is_client_connected(socket_addr) {
                                println!("Status: Connected");
                            } else {
                                println!("Status: Offline");
                            }

                            let nickname = state::get_nickname_from_socket(socket_addr);
                            if nickname.is_some() {
                                println!("Nickname: {}", nickname.unwrap());
                            } else {
                                println!("Nickname: N/A")
                            }

                            let rsa_key = state::get_client_rsa_key(socket_addr);
                            if rsa_key.is_some() {
                                println!("RSA Key: Known");
                            } else {
                                println!("RSA Key: Unknown")
                            }

                            let wrapped_message = pb::WrappedMessage {
                                payload: Some(pb::wrapped_message::Payload::FileListRequest(
                                    pb::FileListRequest {},
                                )),
                            };
                            state::add_outgoing_message(socket_addr, wrapped_message);
                            std::thread::sleep(std::time::Duration::from_millis(100));

                            state::print_client_file_list(socket_addr);
                        }
                        _ => {
                            println!("\nUsage: {}", "listfiles <nickname>".yellow().bold());
                        }
                    },
                    Some("approve") => match parts.get(1..4) {
                        Some([nickname_str, file_direction_str, file_name_str]) => {
                            let socket_addr = match state::get_socket_from_nickname(nickname_str) {
                                Some(socket_addr) => socket_addr,
                                None => {
                                    eprintln!("Unknown Nickname '{}'", nickname_str);
                                    continue;
                                }
                            };
                            let file_direction = match *file_direction_str {
                                "upload" => state::FileDirection::UPLOAD,
                                "download" => state::FileDirection::DOWNLOAD,
                                _ => {
                                    eprintln!(
                                        "Invalid file direction. Must be 'upload' or 'download'"
                                    );
                                    continue;
                                }
                            };

                            let file_name = file_name_str.to_string();

                            let get_hash_function = match file_direction {
                                state::FileDirection::UPLOAD => state::get_pending_hash_from_name,
                                state::FileDirection::DOWNLOAD => state::file_name_to_hash,
                            };
                            let file_hash: String = match get_hash_function(&file_name) {
                                Some(hash) => hash,
                                None => {
                                    eprintln!(
                                        "File '{}' not found for direction: {}",
                                        file_name, file_direction
                                    );
                                    continue;
                                }
                            };

                            state::approve_transfer(
                                socket_addr,
                                file_direction,
                                file_name,
                                file_hash,
                            );
                            println!("Approved transfer");
                        }
                        _ => {
                            println!(
                                "Usage: {}",
                                "approve <nickname> <upload|download> <file_name>"
                                    .yellow()
                                    .bold()
                            );
                        }
                    },
                    Some("reject") => match parts.get(1..4) {
                        Some([nickname_str, file_direction_str, file_name_str]) => {
                            let socket_addr = match state::get_socket_from_nickname(nickname_str) {
                                Some(socket_addr) => socket_addr,
                                None => {
                                    eprintln!("Unknown Nickname '{}'", nickname_str);
                                    continue;
                                }
                            };
                            let file_direction = match *file_direction_str {
                                "upload" => state::FileDirection::UPLOAD,
                                "download" => state::FileDirection::DOWNLOAD,
                                _ => {
                                    eprintln!(
                                        "Invalid file direction. Must be 'upload' or 'download'"
                                    );
                                    continue;
                                }
                            };

                            let file_name = file_name_str.to_string();

                            let get_hash_function = match file_direction {
                                state::FileDirection::UPLOAD => state::get_pending_hash_from_name,
                                state::FileDirection::DOWNLOAD => state::file_name_to_hash,
                            };
                            let file_hash: String = match get_hash_function(&file_name) {
                                Some(hash) => hash,
                                None => {
                                    eprintln!(
                                        "File '{}' not found for direction: {}",
                                        file_name, file_direction
                                    );
                                    continue;
                                }
                            };

                            state::reject_transfer(
                                socket_addr,
                                file_direction,
                                file_name,
                                file_hash,
                            );
                            println!("Rejected transfer");
                        }
                        _ => {
                            println!(
                                "Usage: {}",
                                "reject <nickname> <upload|download> <file_name>"
                                    .yellow()
                                    .bold()
                            );
                        }
                    },
                    Some("ls") => {
                        state::print_file_list();
                    }
                    Some("import") => match parts.get(1..2) {
                        Some([path_str]) => {
                            let path = std::path::Path::new(path_str);
                            match state::import_file(path) {
                                Ok(file) => {
                                    println!(
                                        "Imported file with hash: {} {}",
                                        file.file_name, file.file_hash
                                    );
                                }
                                Err(e) => {
                                    eprintln!("Error importing file {}", e)
                                }
                            }
                        }
                        _ => {
                            println!("Usage: {}", "import <file_path>".yellow().bold());
                        }
                    },
                    Some("export") => match parts.get(1..3) {
                        Some([file_name, path_str]) => {
                            let file_hash = match state::file_name_to_hash(&file_name) {
                                Some(file_hash) => file_hash,
                                None => {
                                    eprintln!("File not found");
                                    continue;
                                }
                            };
                            let path = std::path::Path::new(path_str);
                            match state::export_file(&file_hash, path) {
                                Ok(exported_path) => {
                                    println!("Exported file to: {}", exported_path);
                                }
                                Err(e) => {
                                    eprintln!("Error exporting file '{}': {}", file_name, e);
                                }
                            }
                        }
                        _ => {
                            println!(
                                "Usage: {}",
                                "export <file_name> <file_path>".yellow().bold()
                            );
                        }
                    },
                    Some("exit") => {
                        state::SHUTDOWN.store(true, Ordering::SeqCst);
                        break;
                    }
                    None => {}
                    _ => {
                        println!("Unknown command. Type 'help' for a list of commands.");
                    }
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("(Ctrl+C), initiating shutdown...");
                state::SHUTDOWN.store(true, Ordering::SeqCst); // Set the flag
                break;
            }
            _ => {
                if state::SHUTDOWN.load(Ordering::SeqCst) {
                    println!("Shutdown initiated by Ctrl+C during input, exiting loop.");
                    break;
                }
            }
        }
    }
    log::info!("Sending shutdown signal");

    println!("Saving RSA private key to appdata.bin");
    println!("Saving files to filesystem.bin");
    state::save_app_data_to_disk(&password)?;
    rl.save_history("history.txt").unwrap();

    mdns_handle.join().unwrap();
    log::info!("mDNS stopped");

    tcp_handle.join().unwrap();
    log::info!("tcp server stopped");

    let mut tcp_handles = state::TCP_HANDLES.lock().unwrap();
    for handle in tcp_handles.drain(..) {
        handle.join().unwrap();
    }
    log::info!("tcp connections stopped");

    Ok(())
}
