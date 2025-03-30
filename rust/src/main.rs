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
                println!("  {} - Show this help message", "help".yellow().bold());
                println!(
                    "  {} - Connect to a peer",
                    "connect <address>".yellow().bold()
                );
                println!(
                    "  {} - List files from a peer",
                    "listfiles <address>".yellow().bold()
                );
                println!(
                    "  {} - Upload a file to a peer",
                    "upload <address> <file_name>".yellow().bold()
                );
                println!(
                    "  {} - Download a file from a peer",
                    "download <address> <file_name>".yellow().bold()
                );
                println!(
                    "  {} - Shows available peers or information about a specific peer",
                    "contact <address>".yellow().bold()
                );
                println!(
                    "  {} - Approve a transfer",
                    "approve <address> <upload|download> <file_name>"
                        .yellow()
                        .bold()
                );
                println!(
                    "  {} - Reject a transfer",
                    "reject <address> <upload|download> <file_name>"
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
            Some("connect") => match parts.get(1..2) {
                Some([socket_addr_str]) => {
                    let socket_addr = match SocketAddr::from_str(socket_addr_str) {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("Invalid address '{}': {}", socket_addr_str, e);
                            continue;
                        }
                    };

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
                    println!("Usage: {}", "connect 256.256.256.256:5200".yellow().bold());
                }
            },
            Some("upload") => match parts.get(1..3) {
                Some([socket_addr_str, file_name_str]) => {
                    let socket_addr = match SocketAddr::from_str(socket_addr_str) {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("Invalid address '{}': {}", socket_addr_str, e);
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
                    println!("Usage: upload 256.256.256.256:5200 file_name");
                }
            },
            Some("download") => match parts.get(1..3) {
                Some([socket_addr_str, file_name_str]) => {
                    let socket_addr = match SocketAddr::from_str(socket_addr_str) {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("Invalid address '{}': {}", socket_addr_str, e);
                            continue;
                        }
                    };

                    let file_name = file_name_str.to_string();
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
                        "download 256.256.256.256:5200 <file_name>".yellow().bold()
                    );
                }
            },
            Some("contact") => match parts.get(1..2) {
                Some([socket_addr_str]) => {
                    let socket_addr = match SocketAddr::from_str(socket_addr_str) {
                        Ok(socket_addr) => socket_addr,
                        Err(e) => {
                            eprintln!("Error parsing address {}", e);
                            continue;
                        }
                    };

                    if state::is_client_connected(socket_addr) {
                        println!("Status: Connected");
                    } else {
                        println!("Status: Offline");
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
                    state::print_client_file_list(socket_addr); // Won't be updated
                }
                _ => {
                    state::print_clients();

                    println!(
                        "\nUsage: {}",
                        "contact 256.256.256.256:5200".yellow().bold()
                    );
                }
            },
            Some("approve") => match parts.get(1..3) {
                Some([socket_addr_str, file_direction_str, file_name_str]) => {
                    let socket_addr = match SocketAddr::from_str(socket_addr_str) {
                        Ok(socket_addr) => socket_addr,
                        Err(e) => {
                            eprintln!("Error parsing address {}", e);
                            continue;
                        }
                    };
                    let file_direction = match *file_direction_str {
                        "upload" => state::FileDirection::UPLOAD,
                        "download" => state::FileDirection::DOWNLOAD,
                        _ => {
                            eprintln!("Invalid file direction. Must be 'upload' or 'download'");
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
                                "File '{}' not found for direction: {:?}",
                                file_name, file_direction
                            );
                            continue;
                        }
                    };

                    state::approve_transfer(socket_addr, file_direction, file_name, file_hash);
                    println!("Approved transfer");
                }
                _ => {
                    println!(
                        "Usage: {}",
                        "approve 256.256.256.256:5200 <upload|download> <file_name>"
                            .yellow()
                            .bold()
                    );
                }
            },
            Some("reject") => match parts.get(1..3) {
                Some([socket_addr_str, file_direction_str, file_name_str]) => {
                    let socket_addr = match SocketAddr::from_str(socket_addr_str) {
                        Ok(socket_addr) => socket_addr,
                        Err(e) => {
                            eprintln!("Error parsing address {}", e);
                            continue;
                        }
                    };
                    let file_direction = match *file_direction_str {
                        "upload" => state::FileDirection::UPLOAD,
                        "download" => state::FileDirection::DOWNLOAD,
                        _ => {
                            eprintln!("Invalid file direction. Must be 'upload' or 'download'");
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
                                "File '{}' not found for direction: {:?}",
                                file_name, file_direction
                            );
                            continue;
                        }
                    };

                    state::reject_transfer(socket_addr, file_direction, file_name, file_hash);
                    println!("Rejected transfer");
                }
                _ => {
                    println!(
                        "Usage: {}",
                        "reject 256.256.256.256:5200 <upload|download> <file_name>"
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
